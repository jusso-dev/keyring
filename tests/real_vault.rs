//! Checks a few rows of the real-vault checklist against a real Key Vault,
//! and against the mock, and fails if the two disagree (plan 005).
//!
//! The real half only runs when asked for: every real-vault test is
//! `#[ignore]`, so `cargo test` never calls Azure. See
//! docs/real-vault-automation.md for how to run it.
//!
//! Each row has two tests:
//!
//! - `mock_<row>` runs the steps against the mock and checks the answer
//!   Key Vault really gave (from the checklist's record of runs). It is not
//!   ignored, so the scenario itself stays tested offline.
//! - `<row>` is ignored. It runs the same steps against the real vault, then
//!   against the mock, and asserts that both match the recorded answer and
//!   each other.
//!
//! The steps go through Keyring's own `azure::*Api` clients, so the code
//! that was checked is the code that ships. The vault token comes from a
//! file and is seeded into a test session. Keyring itself still has no way
//! to get an app-only token.

mod support;

use std::fmt::Debug;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use keyring::AppState;
use keyring::auth::session::{Session, User, UserId, UserTokens};
use keyring::azure::certs::{
    CertsApi, CreateCert, IssuerProps, KeyProps, Policy, SecretProps, X509Props,
};
use keyring::azure::keys::{CreateKey, KeysApi};
use keyring::azure::secrets::{API_VERSION, Attributes, SecretsApi, SetSecret, now_ts};
use keyring::azure::token::AccessToken;
use keyring::azure::vaults::is_valid_vault_name;
use keyring::azure::{AzureError, Resource};
use keyring::config::Config;
use keyring::secret::Secret;
use reqwest::Method;
use rsa::rand_core::{OsRng, RngCore};

// ---------------------------------------------------------------------
// Guard rails
// ---------------------------------------------------------------------

/// Throwaway vaults must be named this way, so the tests can't run against
/// a real vault by accident.
const TEST_VAULT_PREFIX: &str = "kr-test-";

/// A fixed dummy value for every secret the tests write. Never a real one.
const DUMMY_VALUE: &str = "kr-real-dummy-value";

/// The vault name from `KEYRING_REAL_VAULT`, or why it can't be used. Checked
/// before anything else, so a wrong name fails before any HTTP call.
fn check_vault_name(raw: Option<&str>) -> Result<String, String> {
    let name = raw
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .ok_or("KEYRING_REAL_VAULT is not set. Name a throwaway vault, for example kr-test-1")?;
    if !is_valid_vault_name(name) {
        return Err(format!("`{name}` isn't a valid Key Vault name"));
    }
    if !name.starts_with(TEST_VAULT_PREFIX) {
        return Err(format!(
            "`{name}` doesn't start with `{TEST_VAULT_PREFIX}`. These tests create and delete \
             items, so they only run against vaults named that way"
        ));
    }
    Ok(name.to_owned())
}

/// The token from the file's text. The error never repeats the text.
fn clean_token(raw: &str) -> Result<String, String> {
    let token = raw.trim();
    if token.is_empty() {
        return Err("the token file is empty".into());
    }
    if token.split_whitespace().count() != 1 {
        return Err("the token file should hold the token alone, on one line".into());
    }
    Ok(token.to_owned())
}

/// A name for something a test creates: `kr-real-` and 8 hex digits.
fn unique_name() -> String {
    format!("kr-real-{:08x}", OsRng.next_u32())
}

/// Key Vault's recovery levels that allow a purge all contain "Purgeable".
/// An unknown level counts as not purgeable.
fn is_purgeable(recovery_level: Option<&str>) -> bool {
    recovery_level.is_some_and(|l| l.contains("Purgeable"))
}

// ---------------------------------------------------------------------
// A session with a seeded token
// ---------------------------------------------------------------------

fn config(keyvault_test_url: Option<String>) -> Config {
    Config::from_lookup(move |k| {
        Some(match k {
            "ENTRA_TENANT_ID" => support::TENANT.to_owned(),
            "ENTRA_CLIENT_ID" => support::CLIENT_ID.to_owned(),
            "ENTRA_CLIENT_SECRET" => support::CLIENT_SECRET.to_owned(),
            "APP_BASE_URL" => "http://localhost:3000".to_owned(),
            "SESSION_SECRET" => "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            "KEYRING_TEST_KEYVAULT_URL" => keyvault_test_url.clone()?,
            _ => return None,
        })
    })
    .expect("test config")
}

/// Keyring's own Azure client and a session whose Key Vault token was handed
/// in. The user's own token is already expired and has no refresh token, so
/// a rejected token ends in "sign in again" with no call to Entra.
struct Harness {
    state: AppState,
    session: Arc<Session>,
    vault: String,
}

impl Harness {
    fn new(config: Config, vault: &str, token: &str) -> Self {
        let state = AppState::try_new(config).expect("HTTP client");
        let id = state.sessions.create(
            User {
                name: "Real vault test".into(),
                username: None,
                subject: UserId::from_sub("real-vault-test"),
            },
            UserTokens {
                access_token: Secret::new("not-a-token"),
                expires_at: SystemTime::UNIX_EPOCH,
                refresh_token: None,
            },
        );
        let session = state.sessions.get(&id).expect("session just created");
        session.azure_tokens.seed_token_for_tests(
            Resource::KeyVault,
            AccessToken::new(token, SystemTime::now() + Duration::from_secs(50 * 60)),
        );
        Self {
            state,
            session,
            vault: vault.to_owned(),
        }
    }

    fn vault_url(&self) -> String {
        self.state.config.vault_url(&self.vault)
    }

    fn secrets(&self) -> SecretsApi<'_> {
        SecretsApi {
            azure: &self.state.azure,
            session: &self.session,
            vault_url: self.vault_url(),
        }
    }

    fn keys(&self) -> KeysApi<'_> {
        KeysApi {
            azure: &self.state.azure,
            session: &self.session,
            vault_url: self.vault_url(),
        }
    }

    fn certs(&self) -> CertsApi<'_> {
        CertsApi {
            azure: &self.state.azure,
            session: &self.session,
            vault_url: self.vault_url(),
        }
    }
}

/// Stop on an Azure answer a step can't go on from. A token that stopped
/// working gets its own message, since it's the one thing the person running
/// this can fix.
fn fail(what: &str, e: AzureError) -> ! {
    match e {
        AzureError::Token(_) => {
            panic!("{what}: token expired, get a new one (docs/real-vault-automation.md)")
        }
        e => panic!("{what}: {e}"),
    }
}

/// Unwrap an Azure answer a step needs.
fn ok<T>(what: &str, r: Result<T, AzureError>) -> T {
    r.unwrap_or_else(|e| fail(what, e))
}

// ---------------------------------------------------------------------
// Pacing, polling and clean-up
// ---------------------------------------------------------------------

/// How often to poll, and for how long.
#[derive(Clone, Copy)]
struct Pace {
    every: Duration,
    up_to: Duration,
}

/// Try again while Azure answers one of `again_on`, until `pace.up_to` has
/// passed. Always tries at least once. Returns the last answer and how long
/// it took.
async fn retry<T>(
    pace: Pace,
    again_on: &[u16],
    mut f: impl AsyncFnMut() -> Result<T, AzureError>,
) -> (Result<T, AzureError>, Duration) {
    let start = Instant::now();
    loop {
        match f().await {
            Err(AzureError::Status { status, .. })
                if again_on.contains(&status) && start.elapsed() < pace.up_to =>
            {
                tokio::time::sleep(pace.every).await;
            }
            other => return (other, start.elapsed()),
        }
    }
}

enum Item {
    Secret(String),
    Key(String),
    Cert(String),
}

/// Deletes (and purges, where the vault allows it) what a test made. It does
/// this when dropped, so it runs when a test panics too. The work happens on
/// its own thread with its own client, since a drop can't await and the test's
/// runtime may be blocked.
struct Cleanup {
    config: Config,
    vault: String,
    token: String,
    pace: Pace,
    items: Mutex<Vec<Item>>,
}

impl Cleanup {
    /// Remember an item to clean up. Do this *before* creating it.
    fn track(&self, item: Item) {
        self.items
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(item);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let items = std::mem::take(self.items.get_mut().unwrap_or_else(PoisonError::into_inner));
        if items.is_empty() {
            return;
        }
        let (config, vault, token, pace) = (
            self.config.clone(),
            self.vault.clone(),
            self.token.clone(),
            self.pace,
        );
        // Never panic in here: this can run while another panic unwinds.
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async {
                let h = Harness::new(config, &vault, &token);
                for item in items {
                    clean_one(&h, pace, item).await;
                }
            });
        })
        .join();
    }
}

async fn clean_one(h: &Harness, pace: Pace, item: Item) {
    match item {
        Item::Secret(n) => {
            let api = h.secrets();
            delete_then_purge(
                "secret",
                &n,
                pace,
                api.delete(&n).await,
                async || {
                    api.get_deleted(&n)
                        .await
                        .map(|d| d.attributes.recovery_level)
                },
                async || api.purge(&n).await,
            )
            .await;
        }
        Item::Key(n) => {
            let api = h.keys();
            delete_then_purge(
                "key",
                &n,
                pace,
                api.delete(&n).await,
                async || {
                    api.get_deleted(&n)
                        .await
                        .map(|d| d.attributes.recovery_level)
                },
                async || api.purge(&n).await,
            )
            .await;
        }
        Item::Cert(n) => {
            let api = h.certs();
            delete_then_purge(
                "certificate",
                &n,
                pace,
                api.delete(&n).await,
                async || {
                    api.get_deleted(&n)
                        .await
                        .map(|d| d.attributes.recovery_level)
                },
                async || api.purge(&n).await,
            )
            .await;
        }
    }
}

/// After a delete, wait for the item to show as deleted, then purge it if
/// its recovery level allows. A failed delete (usually 404: the test
/// deleted it, or never made it) gets one look only. Only a 404 delete then a
/// 404 lookup counts as nothing left. Anything that may be left behind is said
/// on stderr, so it can be removed by hand.
async fn delete_then_purge(
    kind: &str,
    name: &str,
    pace: Pace,
    deleted: Result<(), AzureError>,
    level: impl AsyncFn() -> Result<Option<String>, AzureError>,
    purge: impl AsyncFn() -> Result<(), AzureError>,
) {
    let wait = if deleted.is_ok() {
        pace
    } else {
        Pace {
            up_to: Duration::ZERO,
            ..pace
        }
    };
    let delete_err = deleted.err();
    let (level, _) = retry(wait, &[404], async || level().await).await;
    let level = match level {
        Ok(level) => level,
        // A 404 after a 404 delete: never made, or already gone. Nothing left.
        Err(AzureError::Status { status: 404, .. })
            if matches!(&delete_err, Some(AzureError::Status { status: 404, .. })) =>
        {
            return;
        }
        // Anything else may have left the item behind, live or soft-deleted.
        Err(e) => {
            match &delete_err {
                Some(d) => eprintln!(
                    "cleanup: {kind} {name} may be left behind: delete failed ({d}), then the deleted lookup failed ({e})"
                ),
                None => eprintln!(
                    "cleanup: {kind} {name} may be left soft-deleted: deleted, but the deleted lookup failed ({e})"
                ),
            }
            return;
        }
    };
    if !is_purgeable(level.as_deref()) {
        eprintln!(
            "cleanup: {kind} {name} stays soft-deleted until retention ends (purge protection)"
        );
        return;
    }
    let (purged, _) = retry(pace, &[404, 409], async || purge().await).await;
    if let Err(e) = purged {
        eprintln!("cleanup: {kind} {name} left behind: {e}");
    }
}

// ---------------------------------------------------------------------
// The two places a row can run
// ---------------------------------------------------------------------

struct Target {
    h: Harness,
    cleanup: Cleanup,
    pace: Pace,
}

impl Target {
    fn new(config: Config, vault: &str, token: &str, pace: Pace) -> Self {
        Self {
            h: Harness::new(config.clone(), vault, token),
            cleanup: Cleanup {
                config,
                vault: vault.to_owned(),
                token: token.to_owned(),
                pace,
                items: Mutex::new(Vec::new()),
            },
            pace,
        }
    }

    /// The real vault named by `KEYRING_REAL_VAULT`, with the token in
    /// `KEYRING_REAL_TOKEN_FILE`. Panics, before any HTTP call, if the vault
    /// isn't a `kr-test-` one.
    fn real() -> Self {
        let vault = check_vault_name(std::env::var("KEYRING_REAL_VAULT").ok().as_deref())
            .unwrap_or_else(|e| panic!("{e}"));
        let path = std::env::var("KEYRING_REAL_TOKEN_FILE").unwrap_or_else(|_| {
            panic!("KEYRING_REAL_TOKEN_FILE is not set (docs/real-vault-automation.md)")
        });
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("can't read the token file: {}", e.kind()));
        let token = clean_token(&raw).unwrap_or_else(|e| panic!("{e}"));
        Self::new(
            config(None),
            &vault,
            &token,
            Pace {
                every: Duration::from_secs(1),
                up_to: Duration::from_secs(30),
            },
        )
    }

    /// The mock Key Vault. Same code path as the real one, with a made-up
    /// token the mock doesn't look at.
    fn mock(kv: &support::keyvault::MockKeyVault) -> Self {
        Self::new(
            config(Some(kv.url())),
            "kr-test-mock",
            "mock-token-not-a-secret",
            Pace {
                every: Duration::from_millis(20),
                up_to: Duration::from_secs(5),
            },
        )
    }

    fn secret_name(&self) -> String {
        let name = unique_name();
        self.cleanup.track(Item::Secret(name.clone()));
        name
    }
}

// ---------------------------------------------------------------------
// Row 1: Secrets, "Versions of a name that doesn't exist"
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Versions {
    /// 200 with an empty list.
    Empty200,
    NotFound404,
}

const ROW_VERSIONS: &str = "Secrets: Versions of a name that doesn't exist";
const EXPECT_VERSIONS: Versions = Versions::Empty200;

async fn versions_of_a_missing_name(t: &Target) -> Versions {
    let name = unique_name();
    match t.h.secrets().versions(&name).await {
        Ok(v) if v.is_empty() => Versions::Empty200,
        Ok(_) => panic!("a name made up just now already has versions"),
        Err(AzureError::Status { status: 404, .. }) => Versions::NotFound404,
        Err(e) => fail("list versions", e),
    }
}

// ---------------------------------------------------------------------
// Row 2: Secrets, "Clearing an expiry date"
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct Expiry {
    /// Key Vault answered the PATCH with 2xx.
    patch_accepted: bool,
    /// The expiry was still there afterwards.
    expiry_kept: bool,
}

const ROW_EXPIRY: &str = "Secrets: Clearing an expiry date";
const EXPECT_EXPIRY: Expiry = Expiry {
    patch_accepted: true,
    expiry_kept: true,
};

/// Keyring never sends `"exp": null` now, because Key Vault ignores it. This
/// row sends it on purpose, by hand, to see that Key Vault still does.
async fn clearing_an_expiry_date(t: &Target) -> Expiry {
    let name = t.secret_name();
    let api = t.h.secrets();
    let exp = now_ts() + 30 * 86_400;
    let made = ok(
        "set secret",
        api.set(
            &name,
            &SetSecret {
                value: Secret::new(DUMMY_VALUE),
                content_type: None,
                attributes: Attributes {
                    enabled: Some(true),
                    expires: Some(exp),
                    ..Attributes::default()
                },
                tags: None,
            },
        )
        .await,
    );
    let url = format!(
        "{}/secrets/{name}/{}?api-version={API_VERSION}",
        api.vault_url,
        made.version()
    );
    let patched =
        t.h.state
            .azure
            .send(
                &t.h.session,
                Resource::KeyVault,
                Method::PATCH,
                &url,
                Some(br#"{"attributes":{"exp":null}}"#.to_vec()),
            )
            .await;
    let patch_accepted = match patched {
        Ok(_) => true,
        Err(AzureError::Status { .. }) => false,
        Err(e) => fail("patch secret", e),
    };
    let versions = ok("list versions", api.versions(&name).await);
    let after = versions
        .iter()
        .find(|v| v.version() == made.version())
        .and_then(|v| v.attributes.expires);
    Expiry {
        patch_accepted,
        expiry_kept: after == Some(exp),
    }
}

// ---------------------------------------------------------------------
// Row 3: Secrets, "Recover then read"
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct Recover {
    /// The recover call itself answered 2xx.
    recover_answered: bool,
    /// The secret could be read again within the polling limit.
    readable_afterwards: bool,
}

const ROW_RECOVER: &str = "Secrets: Recover then read";
const EXPECT_RECOVER: Recover = Recover {
    recover_answered: true,
    readable_afterwards: true,
};

async fn recover_then_read(t: &Target) -> Recover {
    let name = t.secret_name();
    let api = t.h.secrets();
    ok("set secret", api.set(&name, &simple_secret()).await);
    ok("delete secret", api.delete(&name).await);
    // A delete takes a moment to show as deleted, and recover needs that.
    let (shown, _) = retry(t.pace, &[404], async || api.get_deleted(&name).await).await;
    ok("wait for the deleted secret to show", shown);
    // Key Vault can refuse a recover for a moment after the delete shows,
    // with 409 while the delete is still settling. Try again on that.
    let (recovered, _) = retry(t.pace, &[409], async || api.recover(&name).await).await;
    if let Err(e) = &recovered {
        eprintln!("recover then read: recover refused: {e}");
    }
    let recover_answered = recovered.is_ok();
    let (read, took) = retry(t.pace, &[404], async || api.get_value(&name, None).await).await;
    let readable_afterwards = read.is_ok();
    // Record how long the read took to work, for the checklist's Result column.
    eprintln!("recover then read: readable after {took:.1?}");
    Recover {
        recover_answered,
        readable_afterwards,
    }
}

fn simple_secret() -> SetSecret {
    SetSecret {
        value: Secret::new(DUMMY_VALUE),
        content_type: None,
        attributes: Attributes {
            enabled: Some(true),
            ..Attributes::default()
        },
        tags: None,
    }
}

// ---------------------------------------------------------------------
// Row 4: Secrets, "409 for a soft-deleted name"
// ---------------------------------------------------------------------

/// What both the mock and the real vault must agree on.
#[derive(Debug, PartialEq, Eq)]
struct Conflict {
    status: u16,
    detail: ConflictDetail,
}

/// The code and whether the message names the deleted state.
#[derive(Debug, PartialEq, Eq)]
struct ConflictDetail {
    code: Option<String>,
    message_names_deleted_state: bool,
}

const ROW_CONFLICT: &str = "Secrets: 409 for a soft-deleted name";
const EXPECT_CONFLICT_STATUS: u16 = 409;

/// What the first real run recorded: the inner code, and a message saying
/// "deleted but recoverable state".
fn expect_conflict_detail() -> ConflictDetail {
    ConflictDetail {
        code: Some("ObjectIsDeletedButRecoverable".into()),
        message_names_deleted_state: true,
    }
}

async fn conflict_for_a_soft_deleted_name(t: &Target) -> Conflict {
    let name = t.secret_name();
    let api = t.h.secrets();
    ok("set secret", api.set(&name, &simple_secret()).await);
    ok("delete secret", api.delete(&name).await);
    let (shown, _) = retry(t.pace, &[404], async || api.get_deleted(&name).await).await;
    ok("wait for the deleted secret to show", shown);
    match api.set(&name, &simple_secret()).await {
        Ok(_) => panic!("setting a soft-deleted name should be refused, but it worked"),
        Err(AzureError::Status {
            status,
            code,
            message,
        }) => Conflict {
            status,
            detail: ConflictDetail {
                code,
                message_names_deleted_state: message.is_some_and(|m| {
                    m.to_ascii_lowercase()
                        .contains("deleted but recoverable state")
                }),
            },
        },
        Err(e) => fail("set a soft-deleted name", e),
    }
}

// ---------------------------------------------------------------------
// Row 5: Keys, "HSM key on a Standard vault"
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    status: u16,
    code: Option<String>,
}

const ROW_HSM: &str = "Keys: HSM key on a Standard vault";

fn expect_hsm() -> Refusal {
    Refusal {
        status: 403,
        code: Some("HardwareKeysNotSupported".into()),
    }
}

async fn hsm_key_on_a_standard_vault(t: &Target) -> Refusal {
    let name = unique_name();
    // Tracked even though it should be refused: on a Premium vault it works.
    t.cleanup.track(Item::Key(name.clone()));
    let made =
        t.h.keys()
            .create(
                &name,
                &CreateKey {
                    kty: "RSA-HSM".into(),
                    key_size: Some(2048),
                    crv: None,
                    key_ops: vec!["sign".into(), "verify".into()],
                    attributes: Attributes {
                        enabled: Some(true),
                        ..Attributes::default()
                    },
                    tags: None,
                },
            )
            .await;
    match made {
        Ok(_) => panic!("an HSM key was created: is this a Premium vault? Use a Standard one"),
        Err(AzureError::Status { status, code, .. }) => Refusal { status, code },
        Err(e) => fail("create HSM key", e),
    }
}

// ---------------------------------------------------------------------
// Row 6: Certificates, "Self-signed create"
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct SelfSigned {
    /// `status` in the create reply.
    created: String,
    /// `status` once polling stopped.
    finished: String,
}

const ROW_SELF_SIGNED: &str = "Certificates: Self-signed create";

fn expect_self_signed() -> SelfSigned {
    SelfSigned {
        created: "inProgress".into(),
        finished: "completed".into(),
    }
}

async fn self_signed_create(t: &Target) -> SelfSigned {
    let name = unique_name();
    t.cleanup.track(Item::Cert(name.clone()));
    let api = t.h.certs();
    let body = CreateCert {
        policy: Policy {
            key_props: Some(KeyProps {
                exportable: Some(true),
                kty: Some("RSA".into()),
                key_size: Some(2048),
                crv: None,
                reuse_key: Some(false),
            }),
            secret_props: Some(SecretProps {
                content_type: Some("application/x-pkcs12".into()),
            }),
            x509_props: Some(X509Props {
                subject: Some("CN=kr-real.example.test".into()),
                sans: None,
                validity_months: Some(1),
                ekus: Vec::new(),
            }),
            lifetime_actions: Vec::new(),
            issuer: Some(IssuerProps {
                name: Some("Self".into()),
            }),
        },
        attributes: Attributes {
            enabled: Some(true),
            ..Attributes::default()
        },
        tags: None,
    };
    let op = ok("create certificate", api.create(&name, &body).await);
    let created = op.status.unwrap_or_default();
    let start = Instant::now();
    let finished = loop {
        let status = match ok("read pending", api.pending(&name).await) {
            Some(op) => op.status.unwrap_or_default(),
            // No pending record left: it's done if the certificate reads.
            None if api.get_cert(&name, None).await.is_ok() => "completed".into(),
            None => "inProgress".into(),
        };
        if status != "inProgress" || start.elapsed() >= t.pace.up_to {
            break status;
        }
        tokio::time::sleep(t.pace.every).await;
    };
    eprintln!(
        "self-signed create: {finished} after {:.1?}",
        start.elapsed()
    );
    SelfSigned { created, finished }
}

// ---------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------

/// The mock half: the steps run against the mock and give the recorded answer.
async fn mock_row<T: Debug + PartialEq>(
    row: &str,
    scenario: impl AsyncFn(&Target) -> T,
    expected: T,
) {
    let kv = support::keyvault::start().await;
    let mocked = scenario(&Target::mock(&kv)).await;
    assert_eq!(
        mocked, expected,
        "the mock (tests/support/) no longer gives the answer Key Vault gave for checklist row '{row}'"
    );
}

/// The real half: the steps run against the real vault, and the mock gives
/// the same answer.
async fn real_row<T: Debug + PartialEq>(
    row: &str,
    mock_file: &str,
    scenario: impl AsyncFn(&Target) -> T,
    expected: T,
) {
    let real = scenario(&Target::real()).await;
    let kv = support::keyvault::start().await;
    let mocked = scenario(&Target::mock(&kv)).await;
    assert_eq!(
        real, expected,
        "the real vault gave a different answer from the recorded run, checklist row '{row}'"
    );
    assert_eq!(
        real, mocked,
        "the mock and the real vault disagree on checklist row '{row}': fix {mock_file}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_versions_of_a_name_that_doesnt_exist() {
    mock_row(ROW_VERSIONS, versions_of_a_missing_name, EXPECT_VERSIONS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real kr-test- vault: docs/real-vault-automation.md"]
async fn real_versions_of_a_name_that_doesnt_exist() {
    real_row(
        ROW_VERSIONS,
        "tests/support/keyvault.rs (versions)",
        versions_of_a_missing_name,
        EXPECT_VERSIONS,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_clearing_an_expiry_date() {
    mock_row(ROW_EXPIRY, clearing_an_expiry_date, EXPECT_EXPIRY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real kr-test- vault: docs/real-vault-automation.md"]
async fn real_clearing_an_expiry_date() {
    real_row(
        ROW_EXPIRY,
        "tests/support/keyvault.rs (update)",
        clearing_an_expiry_date,
        EXPECT_EXPIRY,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_recover_then_read() {
    mock_row(ROW_RECOVER, recover_then_read, EXPECT_RECOVER).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real kr-test- vault: docs/real-vault-automation.md"]
async fn real_recover_then_read() {
    real_row(
        ROW_RECOVER,
        "tests/support/keyvault.rs (recover)",
        recover_then_read,
        EXPECT_RECOVER,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_409_for_a_soft_deleted_name() {
    let kv = support::keyvault::start().await;
    let mocked = conflict_for_a_soft_deleted_name(&Target::mock(&kv)).await;
    // Only the status is checked here. The mock's code and message differ
    // from the real ones (see the real test); that is a known difference.
    assert_eq!(
        mocked.status, EXPECT_CONFLICT_STATUS,
        "the mock (tests/support/keyvault.rs, set) no longer refuses a soft-deleted name, checklist row '{ROW_CONFLICT}'"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real kr-test- vault: docs/real-vault-automation.md"]
async fn real_409_for_a_soft_deleted_name() {
    let real = conflict_for_a_soft_deleted_name(&Target::real()).await;
    let kv = support::keyvault::start().await;
    let mocked = conflict_for_a_soft_deleted_name(&Target::mock(&kv)).await;
    assert_eq!(
        real.status, EXPECT_CONFLICT_STATUS,
        "the real vault didn't answer 409, checklist row '{ROW_CONFLICT}'"
    );
    assert_eq!(
        real.detail,
        expect_conflict_detail(),
        "the real vault's code or message changed, checklist row '{ROW_CONFLICT}'"
    );
    assert_eq!(
        real, mocked,
        "the mock and the real vault disagree on checklist row '{ROW_CONFLICT}': fix tests/support/keyvault.rs"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_hsm_key_on_a_standard_vault() {
    mock_row(ROW_HSM, hsm_key_on_a_standard_vault, expect_hsm()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real kr-test- vault (Standard tier): docs/real-vault-automation.md"]
async fn real_hsm_key_on_a_standard_vault() {
    real_row(
        ROW_HSM,
        "tests/support/keys.rs (create)",
        hsm_key_on_a_standard_vault,
        expect_hsm(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_self_signed_create() {
    mock_row(ROW_SELF_SIGNED, self_signed_create, expect_self_signed()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real kr-test- vault: docs/real-vault-automation.md"]
async fn real_self_signed_create() {
    real_row(
        ROW_SELF_SIGNED,
        "tests/support/certs.rs (create, settle)",
        self_signed_create,
        expect_self_signed(),
    )
    .await;
}

// ---------------------------------------------------------------------
// Tests of the harness itself (offline)
// ---------------------------------------------------------------------

#[test]
fn the_guard_accepts_only_kr_test_vaults() {
    assert_eq!(
        check_vault_name(Some("kr-test-1")).as_deref(),
        Ok("kr-test-1")
    );
    assert_eq!(
        check_vault_name(Some("  kr-test-abc  ")).as_deref(),
        Ok("kr-test-abc")
    );
    for (input, why) in [
        (None, "not set"),
        (Some(""), "empty"),
        (Some("   "), "blank"),
        (Some("prod-vault"), "not a test vault"),
        (Some("kr-testing"), "prefix needs the dash after test"),
        (Some("my-kr-test-vault"), "prefix must be at the start"),
        (Some("KR-TEST-1"), "prefix is lower case"),
        (Some("kr-test-"), "can't end in a dash"),
        (Some("kr-test--x"), "no double dash"),
        (Some("kr-test-abcdefghijklmnopqrs"), "over 24 characters"),
        (Some("kr-test-a/../b"), "not a vault name"),
    ] {
        assert!(check_vault_name(input).is_err(), "should refuse: {why}");
    }
}

#[test]
fn the_guard_says_what_to_do() {
    let unset = check_vault_name(None).unwrap_err();
    assert!(unset.contains("KEYRING_REAL_VAULT"), "{unset}");
    let wrong = check_vault_name(Some("prod-vault")).unwrap_err();
    assert!(wrong.contains("kr-test-"), "{wrong}");
}

#[test]
fn the_token_text_is_checked_without_being_repeated() {
    assert_eq!(clean_token("abc.def.ghi\n").as_deref(), Ok("abc.def.ghi"));
    assert!(clean_token("").is_err());
    assert!(clean_token(" \n ").is_err());
    let err = clean_token("secret-one secret-two").unwrap_err();
    assert!(!err.contains("secret-"), "{err}");
}

#[test]
fn item_names_are_kr_real_and_eight_hex_digits() {
    for _ in 0..50 {
        let n = unique_name();
        let hex = n.strip_prefix("kr-real-").expect("prefix");
        assert_eq!(hex.len(), 8, "{n}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{n}");
    }
    assert_ne!(unique_name(), unique_name());
}

#[test]
fn only_purgeable_recovery_levels_are_purged() {
    for level in [
        "Purgeable",
        "Recoverable+Purgeable",
        "CustomizedRecoverable+Purgeable",
    ] {
        assert!(is_purgeable(Some(level)), "{level}");
    }
    for level in [
        "Recoverable",
        "Recoverable+ProtectedSubscription",
        "CustomizedRecoverable",
        "CustomizedRecoverable+ProtectedSubscription",
    ] {
        assert!(!is_purgeable(Some(level)), "{level}");
    }
    assert!(!is_purgeable(None));
}

/// Nothing a test makes is left in the mock afterwards.
fn assert_mock_is_empty(kv: &support::keyvault::MockKeyVault) {
    let state = &kv.state;
    assert!(
        state.secrets.lock().unwrap().is_empty(),
        "live secrets left"
    );
    assert!(
        state.deleted.lock().unwrap().is_empty(),
        "soft-deleted secrets left"
    );
    // The mock leaves the managed key behind a certificate in place when the
    // certificate is deleted, so only keys a test made itself count here.
    assert!(
        state.keys.lock().unwrap().values().all(|k| k.managed),
        "keys left"
    );
    assert!(state.deleted_keys.lock().unwrap().is_empty());
    assert!(state.certs.lock().unwrap().is_empty(), "certificates left");
    assert!(state.deleted_certs.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_up_removes_what_the_rows_made() {
    let kv = support::keyvault::start().await;
    {
        let t = Target::mock(&kv);
        recover_then_read(&t).await;
        conflict_for_a_soft_deleted_name(&t).await;
        self_signed_create(&t).await;
        hsm_key_on_a_standard_vault(&t).await;
    }
    assert_mock_is_empty(&kv);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_up_runs_when_a_test_panics() {
    let kv = support::keyvault::start().await;
    let t = Target::mock(&kv);
    let task = tokio::spawn(async move {
        let name = t.secret_name();
        ok(
            "set secret",
            t.h.secrets().set(&name, &simple_secret()).await,
        );
        panic!("a step failed halfway");
    });
    assert!(task.await.expect_err("the task panics").is_panic());
    assert_mock_is_empty(&kv);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mock_halves_ask_only_the_mock() {
    // Every request of a mock row reaches the local mock, with the made-up
    // token. If a row ever went to Azure this would see nothing.
    let kv = support::keyvault::start().await;
    {
        let t = Target::mock(&kv);
        clearing_an_expiry_date(&t).await;
    }
    let log = kv.state.log.lock().unwrap();
    assert!(!log.is_empty());
    let bearers = kv.state.bearers.lock().unwrap();
    assert!(
        bearers
            .iter()
            .all(|b| b == "Bearer mock-token-not-a-secret"),
        "the seeded token should be the only one used"
    );
}
