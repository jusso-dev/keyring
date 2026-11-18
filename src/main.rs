use std::process::ExitCode;

use keyring::config::Config;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Keyring can't start: {err}");
            return ExitCode::FAILURE;
        }
    };

    keyring::telemetry::init(&config.log_level, config.log_format);
    keyring::telemetry::quiet_panics();

    for name in config.test_overrides() {
        tracing::warn!(
            variable = name,
            "a test-only override is set; tokens (people's, or Keyring's managed identity's) go to the host it names, not to Microsoft. Unset it outside the test suite"
        );
    }

    if config.uses_legacy_identity_setting() {
        tracing::warn!(
            "KEYRING_FEDERATED_IDENTITY_CLIENT_ID is deprecated and will be removed in a later release. Rename it to KEYRING_MANAGED_IDENTITY_CLIENT_ID"
        );
    }

    // Build everything that can fail before binding, so "keyring listening"
    // means Keyring really is ready.
    let listen = config.listen;
    let state = match keyring::AppState::try_new(config) {
        Ok(state) => state,
        Err(err) => {
            tracing::error!(error = %err, "could not set up the outbound HTTPS client; check SSL_CERT_FILE and the system trust store");
            return ExitCode::FAILURE;
        }
    };
    keyring::auth::session::spawn_sweeper(state.sessions.clone());
    if state.audit_sink.is_some() {
        tracing::info!("audit sink on: Keyring's audit events also go to Log Analytics");
    }
    if let Some(n) = &state.notifier {
        let types: Vec<&str> = state
            .config
            .notify
            .as_ref()
            .map(|c| c.types.iter().map(|t| t.as_str()).collect())
            .unwrap_or_default();
        if types.is_empty() {
            tracing::info!(
                "email on, but KEYRING_NOTIFY_TYPES turns no type on, so nothing is sent"
            );
        } else {
            tracing::info!(types = %types.join(","), admins = n.admins().len(), "email on: notices go through Azure Communication Services");
        }
    }
    if state
        .expiry_hook
        .as_ref()
        .is_some_and(|h| h.subscriptions.is_none())
    {
        tracing::warn!(
            "expiry notices are on, but KEYRING_EVENTGRID_SUBSCRIPTIONS is unset, so an expiry event from a Key Vault in any subscription is accepted. Set it to the subscription IDs whose vaults send events"
        );
    }
    if state.expiry_hook.is_some()
        && state
            .notifier
            .as_ref()
            .is_some_and(|n| n.admins().is_empty())
    {
        tracing::warn!(
            "expiry notices are on, but KEYRING_NOTIFY_ADMINS is empty: an expiry event is only emailed when the subscription's keyring-notify header names someone and KEYRING_NOTIFY_ALLOWED_DOMAINS is set"
        );
    }
    match (&state.health, state.config.client_secret_expires) {
        (Some(h), _) => {
            if state
                .notifier
                .as_ref()
                .is_some_and(|n| n.admins().is_empty())
            {
                tracing::warn!(
                    "health notices are on, but KEYRING_NOTIFY_ADMINS is empty, so none is sent"
                );
            }
            h.start();
        }
        (None, Some(_)) => tracing::warn!(
            "KEYRING_CLIENT_SECRET_EXPIRES is set, but nothing will email about it: turn on email with health in KEYRING_NOTIFY_TYPES"
        ),
        (None, None) => {}
    }
    let audit_sink = state.audit_sink.clone();
    let notifier = state.notifier.clone();
    let health = state.health.clone();

    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(addr = %listen, error = %err, "could not bind listen address");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %listen, "keyring listening");

    let app = keyring::app(state);
    let served = keyring::serve::serve(listener, app, shutdown_signal()).await;
    // After the last request: stop the health timer, then send queued
    // email, so its audit
    // events reach the sink, then the sink's own queue, each for up to ten
    // seconds.
    if let Some(h) = health {
        h.shutdown().await;
    }
    if let Some(n) = notifier {
        n.shutdown().await;
    }
    if let Some(sink) = audit_sink {
        sink.shutdown().await;
    }
    if let Err(err) = served {
        tracing::error!(error = %err, "server error");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Resolves on Ctrl-C or SIGTERM. If a handler can't be registered, that
/// one never resolves, so a failed registration can't shut the server down.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "could not listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}
