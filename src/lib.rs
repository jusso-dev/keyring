//! Keyring: a plain-English web front end for Azure Key Vault.
//!
//! Every Azure call is made as the signed-in user. Nothing is stored.

pub(crate) mod age;
pub mod audit;
pub mod auth;
pub mod azure;
pub mod config;
pub mod dates;
pub mod description;
pub(crate) mod expiry;
pub(crate) mod generator;
pub(crate) mod health;
pub mod http;
pub mod notify;
pub mod owner;
pub mod password_policy;
pub(crate) mod pkcs12;
pub mod reason;
pub(crate) mod rotation;
pub mod routes;
pub mod secret;
pub(crate) mod secret_types;
pub mod serve;
pub mod telemetry;
pub mod x509;

use std::sync::Arc;

use axum::Router;

use crate::audit::sink::AuditSink;
use crate::auth::assertion::{Credential, ManagedIdentityTokens};
use crate::auth::cookies::CookieOptions;
use crate::auth::crypto::Sealer;
use crate::auth::oidc::Oidc;
use crate::auth::session::SessionStore;
use crate::azure::{AzureClient, TokenBroker};
use crate::config::Config;
use crate::notify::activity::{self as activity_notify, ActivityWatch};
use crate::notify::expiry::ExpiryHook;
use crate::notify::health::{self as health_notify, HealthWatch, SystemClock};
use crate::notify::sender::{self as notify_sender, Notifier};

/// Shared state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sessions: Arc<SessionStore>,
    pub oidc: Arc<Oidc>,
    /// Seals the short-lived login cookie (state, nonce and PKCE verifier).
    pub sealer: Arc<Sealer>,
    /// Seals flash cookies. A separate key from login cookies, so neither
    /// can be passed off as the other.
    pub flash_sealer: Arc<Sealer>,
    pub cookies: CookieOptions,
    pub azure: AzureClient,
    /// Limits for reading every vault. Always [`Limits::STANDARD`] outside
    /// tests.
    ///
    /// [`Limits::STANDARD`]: crate::azure::fanout::Limits::STANDARD
    pub fanout: azure::fanout::Limits,
    /// Sends Keyring's own audit events to Log Analytics, when set.
    pub audit_sink: Option<Arc<AuditSink>>,
    /// Sends email through Azure Communication Services, when set.
    pub notifier: Option<Arc<Notifier>>,
    /// The Event Grid webhook's state, when email is on with `expiry`.
    pub expiry_hook: Option<Arc<ExpiryHook>>,
    /// Emails the admins about Keyring's own health, with email on and
    /// `health` in `KEYRING_NOTIFY_TYPES`. Watches audit events as they
    /// are recorded. Its timer is started by `main`.
    pub health: Option<Arc<HealthWatch>>,
    /// One access request per person, vault and role an hour (#258).
    pub access_requests: Arc<notify::access::RequestLimit>,
    /// Emails about watched reads, deletes and bulk changes, and role use,
    /// with any of those types on. Watches audit events as they are
    /// recorded.
    pub activity: Option<Arc<ActivityWatch>>,
}

impl AppState {
    /// Build the state, panicking if the HTTP client can't be built. For
    /// tests; `main` uses [`AppState::try_new`] so start-up can report it.
    pub fn new(config: Config) -> Self {
        Self::try_new(config).expect("HTTP client settings are valid")
    }

    /// Build the state. Fails if the outbound HTTP client can't be built,
    /// for example because the TLS trust store can't be read. With the
    /// audit sink set, starts its sender task, so needs a Tokio runtime.
    pub fn try_new(config: Config) -> Result<Self, http::HttpError> {
        let http = http::client(config.outbound_https_only())?;
        // One managed identity token source, shared by the credential and
        // the audit sink, so each resource's token is cached once.
        let identity = config
            .managed_identity
            .as_ref()
            .map(ManagedIdentityTokens::for_identity)
            .transpose()?
            .map(Arc::new);
        let credential = Credential::with_identity(&config, identity.clone());
        let oidc = Oidc::new(&config, http.clone(), credential.clone());
        let broker = Arc::new(TokenBroker::new(&config, http.clone(), credential));
        // The sink writes with the managed identity only. Config refuses the
        // sink settings without one.
        let audit_sink = match (
            config.audit_ingestion_url(),
            &config.audit_sink,
            identity.clone(),
        ) {
            (Some(url), Some(settings), Some(identity)) => Some(AuditSink::start(
                url,
                settings.tuning,
                identity,
                http.clone(),
            )),
            _ => None,
        };
        // Email is sent as the managed identity only. Config refuses the
        // email settings without one.
        let notifier = match (config.notify_send_url(), &config.notify, identity) {
            (Some(send_url), Some(n), Some(identity)) => Some(Notifier::start(
                notify_sender::Settings {
                    send_url,
                    sender: n.sender.clone(),
                    admins: n.admins.clone(),
                    allowed_domains: n.allowed_domains.clone(),
                    types: n.types.clone(),
                    audit_recipients: n.audit_recipients,
                    per_hour: n.per_hour,
                    base_url: config.base_url.clone(),
                    tuning: n.tuning,
                },
                identity,
                http.clone(),
                audit_sink.clone(),
            )),
            _ => None,
        };
        // The webhook only exists with email on and `expiry` in the types.
        let expiry_hook = config
            .notify
            .as_ref()
            .filter(|n| n.types.contains(&crate::notify::NotifyType::Expiry))
            .map(|n| {
                Arc::new(ExpiryHook::new(
                    config.eventgrid_expect(),
                    n.eventgrid_subscriptions.clone(),
                    n.hook_tuning,
                    config.base_url.clone(),
                ))
            });
        let health = match (&notifier, &config.notify) {
            (Some(n), Some(c)) if n.is_on(notify::NotifyType::Health) => Some(HealthWatch::new(
                health_notify::Settings {
                    burst_threshold: c.burst_threshold,
                    secret_expires: config.client_secret_expires,
                    base_url: config.base_url.clone(),
                    tuning: c.health_tuning,
                },
                Arc::new(SystemClock),
                n.clone(),
                audit_sink.clone(),
            )),
            _ => None,
        };
        let azure = AzureClient::new(http, broker);
        let activity = match (&notifier, &config.notify) {
            (Some(n), Some(c))
                if [
                    notify::NotifyType::WatchedReads,
                    notify::NotifyType::Destructive,
                    notify::NotifyType::RoleUse,
                ]
                .into_iter()
                .any(|t| n.is_on(t)) =>
            {
                Some(ActivityWatch::new(
                    activity_notify::Settings {
                        base_url: config.base_url.clone(),
                        management_url: config.management_url.clone(),
                        owner_on_read: c.owner_on_read,
                        ticket: config.reason.ticket.clone(),
                        keyring_view: config.audit_workspace_id.is_some(),
                    },
                    Arc::new(SystemClock),
                    n.clone(),
                    azure.clone(),
                ))
            }
            _ => None,
        };
        let sessions = Arc::new(SessionStore::new(&config.session_secret));
        if let Some(sink) = &audit_sink {
            sessions.set_audit_sink(sink.clone());
        }
        Ok(Self {
            access_requests: Arc::new(notify::access::RequestLimit::default()),
            expiry_hook,
            health,
            activity,
            notifier,
            audit_sink,
            sessions,
            oidc: Arc::new(oidc),
            azure,
            fanout: azure::fanout::Limits::STANDARD,
            sealer: Arc::new(Sealer::new(&config.session_secret, "login")),
            flash_sealer: Arc::new(Sealer::new(&config.session_secret, "flash")),
            cookies: CookieOptions {
                secure: config.is_https(),
            },
            config: Arc::new(config),
        })
    }
}

impl AppState {
    /// What watches each request's audit events, if anything does.
    pub fn audit_observer(&self) -> Option<Arc<dyn audit::Observe>> {
        let mut all: Vec<Arc<dyn audit::Observe>> = Vec::new();
        if let Some(h) = &self.health {
            all.push(h.clone());
        }
        if let Some(a) = &self.activity {
            all.push(Arc::new(notify::activity::Observer(a.clone())));
        }
        match all.len() {
            0 => None,
            1 => all.pop(),
            _ => Some(Arc::new(audit::Fanout(all))),
        }
    }

    /// The on-behalf-of token broker.
    pub fn azure_broker(&self) -> &TokenBroker {
        self.azure.broker()
    }
}

/// Build the full application router.
pub fn app(state: AppState) -> Router {
    routes::router(state.clone()).with_state(state)
}
