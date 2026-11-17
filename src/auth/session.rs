//! Server-side sessions held in memory. The browser only gets a random ID.
//!
//! Nothing here is written to disk. Restarting Keyring signs everyone out.
//! Running more than one copy needs sticky sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::auth::crypto::{constant_time_eq, random_token};
use crate::auth::step_up::SignInFacts;
use crate::azure::token::TokenCache;
use crate::secret::Secret;

/// Sign out after this long without a request.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Sign out after this long regardless of activity.
pub const ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);

/// How long an uploaded file waits for confirmation.
pub const PENDING_UPLOAD_TTL: Duration = Duration::from_secs(10 * 60);

/// How often expired sessions and stale uploads are dropped.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How long a vault's list of names and properties is reused by search and
/// the expiry dashboard before Key Vault is asked again.
pub const LIST_TTL: Duration = Duration::from_secs(60);

/// How long the signed-in person's own permissions at a scope are reused
/// to grey out buttons before ARM is asked again. See
/// [`crate::routes::hints`].
pub const PERMISSIONS_TTL: Duration = Duration::from_secs(5 * 60);

/// The person's permissions at one scope, as last read. `None` means
/// "don't hint": an access policy vault, where they don't cover data
/// access. Memory only, dropped with the session.
struct CachedPermissions {
    read_at: Instant,
    perms: Option<Arc<crate::azure::authz::Permissions>>,
}

/// One vault's secrets, certificates and keys as last read: names and
/// properties only, never values. Memory only, dropped with the session.
struct CachedList {
    read_at: Instant,
    items: Arc<Vec<crate::expiry::Item>>,
}

/// A certificate file waiting to be imported. Never written anywhere.
pub struct PendingUpload {
    pub id: String,
    pub vault: String,
    pub name: String,
    /// `application/x-pkcs12` or `application/x-pem-file`.
    pub content_type: &'static str,
    /// Base64 PFX or PEM text.
    pub value: Secret,
    pub password: Option<Secret>,
    pub tags: std::collections::BTreeMap<String, String>,
    pub enabled: bool,
    pub exportable: bool,
    pub created: Instant,
}

impl std::fmt::Debug for PendingUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingUpload")
            .field("vault", &self.vault)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A file of secrets waiting to be imported. Values are [`Secret`]s, so
/// they are zeroised when this is dropped. Never written anywhere.
pub struct PendingImport {
    pub id: String,
    pub vault: String,
    pub rows: Vec<PendingSecret>,
    /// Rows the preview showed that won't be written, with why.
    pub skipped: Vec<SkippedSecret>,
    pub created: Instant,
}

/// A row of an import that won't be written. Never holds the value.
#[derive(Debug, Clone)]
pub struct SkippedSecret {
    pub original: String,
    pub name: String,
    pub reason: String,
    /// Its value didn't meet `KEYRING_PASSWORD_POLICY`, so the import
    /// writes a `password_policy` refusal event for it.
    pub policy: bool,
}

/// Where a [`PendingImport`] waits. `generation` goes up each time the
/// person forgets imports, so a preview that started before can tell.
#[derive(Default)]
struct ImportSlot {
    generation: u64,
    import: Option<PendingImport>,
}

/// One secret in a [`PendingImport`].
pub struct PendingSecret {
    /// The name as written in the file.
    pub original: String,
    /// The Key Vault name it becomes.
    pub name: String,
    pub value: Secret,
    pub content_type: Option<String>,
    pub expires: Option<i64>,
    pub tags: std::collections::BTreeMap<String, String>,
    /// The name already has a secret, so this adds a version.
    pub exists: bool,
}

impl std::fmt::Debug for PendingImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingImport")
            .field("vault", &self.vault)
            .field("rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}

/// Who is signed in, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub username: Option<String>,
    /// Who this is in the logs. See [`UserId`].
    pub subject: UserId,
}

/// The identity written on every log line about a person's action.
///
/// Entra's `sub` claim is pairwise: unique to this app registration and
/// found nowhere else. Admins match people by object ID (`oid`) and tenant
/// ID (`tid`), which Entra's sign-in logs and Key Vault's audit logs both
/// use, so those are shown when the ID token has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId {
    pub sub: String,
    pub oid: Option<String>,
    pub tid: Option<String>,
}

impl UserId {
    /// An identity with only the pairwise subject.
    pub fn from_sub(sub: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            oid: None,
            tid: None,
        }
    }
}

impl From<&str> for UserId {
    fn from(sub: &str) -> Self {
        Self::from_sub(sub)
    }
}

impl From<String> for UserId {
    fn from(sub: String) -> Self {
        Self::from_sub(sub)
    }
}

/// `oid:<object ID>,tid:<tenant ID>`, or `sub:<subject>` without them.
impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.oid, &self.tid) {
            (Some(oid), Some(tid)) => write!(f, "oid:{oid},tid:{tid}"),
            (Some(oid), None) => write!(f, "oid:{oid}"),
            _ => write!(f, "sub:{}", self.sub),
        }
    }
}

/// Tokens from sign-in. The access token is for Keyring's own API and is what
/// gets exchanged on behalf of the user for Azure tokens.
#[derive(Debug, Clone)]
pub struct UserTokens {
    pub access_token: Secret,
    pub expires_at: SystemTime,
    pub refresh_token: Option<Secret>,
}

/// One signed-in session.
pub struct Session {
    pub user: User,
    /// A keyed hash of the session ID, written on Keyring's audit events so
    /// one session's events join up without the log holding the cookie
    /// value. See [`SessionStore::new`].
    pub audit_ref: String,
    /// Per-session key for form tokens. Never sent to the browser; forms
    /// carry a token derived from it and the chosen vault.
    csrf: Secret,
    /// Tokens for Azure APIs, exchanged on behalf of this user.
    pub azure_tokens: TokenCache,
    /// Vault picked in the header. Lives only as long as the session.
    selected_vault: Mutex<Option<String>>,
    selected_vault_id: Mutex<Option<String>>,
    /// A conditional access challenge from a failed on-behalf-of exchange,
    /// sent with the next sign-in so Entra asks for what's missing.
    claims_challenge: Mutex<Option<String>>,
    /// `acrs` and `auth_time` from the verified ID token, for step-up. See
    /// [`crate::auth::step_up`].
    sign_in: Mutex<SignInFacts>,
    /// A certificate file between "preview" and "import". Memory only.
    pending_upload: Mutex<Option<PendingUpload>>,
    /// A secrets import between "preview" and "import". Memory only.
    pending_import: Mutex<ImportSlot>,
    /// Each vault's list, read in full, for [`LIST_TTL`]. See [`CachedList`].
    lists: Mutex<HashMap<String, CachedList>>,
    /// The person's own permissions by ARM scope (lower case), for
    /// [`PERMISSIONS_TTL`]. See [`CachedPermissions`].
    permissions: Mutex<HashMap<String, CachedPermissions>>,
    /// Goes up each time the permissions are dropped, so a read that
    /// started before can't put its stale answer back.
    permissions_generation: std::sync::atomic::AtomicU64,
    tokens: Mutex<UserTokens>,
    created: Instant,
    last_seen: Mutex<Instant>,
}

impl Session {
    pub fn tokens(&self) -> UserTokens {
        lock(&self.tokens).clone()
    }

    pub fn set_tokens(&self, tokens: UserTokens) {
        *lock(&self.tokens) = tokens;
    }

    pub fn selected_vault(&self) -> Option<String> {
        lock(&self.selected_vault).clone()
    }

    /// The chosen vault's ARM resource ID, if known.
    pub fn selected_vault_id(&self) -> Option<String> {
        lock(&self.selected_vault_id).clone()
    }

    /// Remember a claims challenge. Only JSON objects up to 4 KB are kept.
    pub fn set_claims_challenge(&self, claims: &str) {
        let ok = claims.len() <= 4096
            && serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(claims).is_ok();
        if ok {
            *lock(&self.claims_challenge) = Some(claims.to_owned());
        }
    }

    pub fn claims_challenge(&self) -> Option<String> {
        lock(&self.claims_challenge).clone()
    }

    /// How the person signed in, from the verified ID token.
    pub fn sign_in_facts(&self) -> SignInFacts {
        lock(&self.sign_in).clone()
    }

    /// Keep `acrs` and `auth_time` from the ID token. Set once, by the
    /// sign-in callback, and by tests.
    pub fn set_sign_in_facts(&self, facts: SignInFacts) {
        *lock(&self.sign_in) = facts;
    }

    /// Keep an uploaded certificate until the person confirms it.
    pub fn set_pending_upload(&self, upload: PendingUpload) {
        *lock(&self.pending_upload) = Some(upload);
    }

    /// Take the pending upload if it's for this ID and not too old. It's
    /// removed either way, so a file is only ever imported once.
    pub fn take_pending_upload(&self, id: &str) -> Option<PendingUpload> {
        let upload = lock(&self.pending_upload).take()?;
        (crate::auth::crypto::constant_time_eq(upload.id.as_bytes(), id.as_bytes())
            && upload.created.elapsed() < PENDING_UPLOAD_TTL)
            .then_some(upload)
    }

    /// The pending import slot's generation. A preview reads it before it
    /// starts and hands it to [`Self::set_pending_import`].
    pub fn pending_import_generation(&self) -> u64 {
        lock(&self.pending_import).generation
    }

    /// Keep a previewed import until the person confirms it, if nothing has
    /// forgotten imports since `generation` was read. Replaces (and so
    /// drops) any import already waiting. `false` if it was too late: the
    /// import is dropped, so a preview that finishes after "Start again"
    /// can't bring its secrets back.
    pub fn set_pending_import(&self, generation: u64, import: PendingImport) -> bool {
        let mut slot = lock(&self.pending_import);
        if slot.generation != generation {
            return false;
        }
        slot.import = Some(import);
        true
    }

    /// Take the pending import if it's for this ID and not too old. A
    /// matching one is removed, so a file is only ever imported once. A
    /// different ID, from an older preview, leaves a newer import waiting.
    /// An expired one is removed whatever the ID.
    pub fn take_pending_import(&self, id: &str) -> Option<PendingImport> {
        let mut slot = lock(&self.pending_import);
        let import = slot.import.as_ref()?;
        if import.created.elapsed() >= PENDING_UPLOAD_TTL {
            slot.import = None;
            return None;
        }
        if !crate::auth::crypto::constant_time_eq(import.id.as_bytes(), id.as_bytes()) {
            return None;
        }
        slot.import.take()
    }

    /// Drop any import waiting in this session, and any preview still
    /// running: one that finishes later isn't kept.
    pub fn forget_pending_import(&self) {
        let mut slot = lock(&self.pending_import);
        slot.generation = slot.generation.wrapping_add(1);
        slot.import = None;
    }

    /// Remember the chosen vault. The caller checks the name is valid.
    pub fn select_vault(&self, name: String) {
        *lock(&self.selected_vault) = Some(name);
        *lock(&self.selected_vault_id) = None;
    }

    /// Remember the chosen vault and its ARM ID together, holding the
    /// selection lock, so a request from another tab can't change the vault
    /// between the two and leave this ID filed under its name. Same lock
    /// order as [`Self::note_vault_used`]. The caller checks the name is valid.
    pub fn select_vault_with_id(&self, name: String, id: String) {
        let mut selected = lock(&self.selected_vault);
        *selected = Some(name);
        *lock(&self.selected_vault_id) = Some(id);
    }

    /// Note that a request used `name`, the vault in its address. The
    /// vault last used changes only if it is a different one, so the ARM ID
    /// kept for it isn't dropped by a request for the same vault. The
    /// caller checks the name is valid.
    pub fn note_vault_used(&self, name: &str) {
        let mut selected = lock(&self.selected_vault);
        if selected.as_deref() != Some(name) {
            *selected = Some(name.to_owned());
            *lock(&self.selected_vault_id) = None;
        }
    }

    /// The ARM ID kept for `vault`, if the vault last used is `vault`.
    /// Another tab may have moved on to a different vault since.
    pub fn vault_id_for(&self, vault: &str) -> Option<String> {
        let selected = lock(&self.selected_vault);
        if selected.as_deref() == Some(vault) {
            lock(&self.selected_vault_id).clone()
        } else {
            None
        }
    }

    /// Keep `id` as the ARM ID of `vault`, but only while `vault` is the
    /// one last used, so it can't be filed under another vault's name.
    pub fn set_vault_id_for(&self, vault: &str, id: String) {
        let selected = lock(&self.selected_vault);
        if selected.as_deref() == Some(vault) {
            *lock(&self.selected_vault_id) = Some(id);
        }
    }

    /// The list read from `vault` within the last [`LIST_TTL`], if any.
    pub(crate) fn cached_list(&self, vault: &str) -> Option<Arc<Vec<crate::expiry::Item>>> {
        self.cached_list_at(vault, Instant::now())
    }

    pub(crate) fn cached_list_at(
        &self,
        vault: &str,
        now: Instant,
    ) -> Option<Arc<Vec<crate::expiry::Item>>> {
        lock(&self.lists)
            .get(vault)
            .filter(|c| now.saturating_duration_since(c.read_at) < LIST_TTL)
            .map(|c| c.items.clone())
    }

    /// Keep a vault's list, read in full just now. Only names and
    /// properties: [`crate::expiry::Item`] has no field for a value.
    pub(crate) fn keep_list(&self, vault: &str, items: Vec<crate::expiry::Item>) {
        self.keep_list_at(vault, items, Instant::now());
    }

    pub(crate) fn keep_list_at(&self, vault: &str, items: Vec<crate::expiry::Item>, now: Instant) {
        lock(&self.lists).insert(
            vault.to_owned(),
            CachedList {
                read_at: now,
                items: Arc::new(items),
            },
        );
    }

    /// Forget the list kept for `vault`, because something in it is about
    /// to change.
    pub fn forget_list(&self, vault: &str) {
        lock(&self.lists).remove(vault);
    }

    /// The permissions read at `scope` within the last
    /// [`PERMISSIONS_TTL`]. The outer `None` is "not read"; the inner one is
    /// "read, and nothing to hint".
    pub(crate) fn cached_permissions_at(
        &self,
        scope: &str,
        now: Instant,
    ) -> Option<Option<Arc<crate::azure::authz::Permissions>>> {
        lock(&self.permissions)
            .get(&scope.to_ascii_lowercase())
            .filter(|c| now.saturating_duration_since(c.read_at) < PERMISSIONS_TTL)
            .map(|c| c.perms.clone())
    }

    /// Drop every permission read, after a role was turned on or off.
    pub(crate) fn forget_permissions(&self) {
        let mut kept = lock(&self.permissions);
        self.permissions_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        kept.clear();
    }

    /// Take this before reading permissions from Azure, and hand it to
    /// [`Self::keep_permissions_at`] with the answer.
    pub(crate) fn permissions_generation(&self) -> u64 {
        self.permissions_generation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Keep what was read at `scope`, unless the permissions were dropped
    /// since `generation` was taken: that read began before a role was
    /// turned on or off, so its answer may be out of date.
    pub(crate) fn keep_permissions_at(
        &self,
        scope: &str,
        perms: Option<Arc<crate::azure::authz::Permissions>>,
        now: Instant,
        generation: u64,
    ) {
        let mut kept = lock(&self.permissions);
        if generation != self.permissions_generation() {
            return;
        }
        kept.insert(
            scope.to_ascii_lowercase(),
            CachedPermissions {
                read_at: now,
                perms,
            },
        );
    }

    /// Drop permissions older than [`PERMISSIONS_TTL`].
    fn drop_stale_permissions(&self, now: Instant) {
        lock(&self.permissions)
            .retain(|_, c| now.saturating_duration_since(c.read_at) < PERMISSIONS_TTL);
    }

    /// Drop lists older than [`LIST_TTL`].
    fn drop_stale_lists(&self, now: Instant) {
        lock(&self.lists).retain(|_, c| now.saturating_duration_since(c.read_at) < LIST_TTL);
    }

    fn expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) >= ABSOLUTE_TIMEOUT
            || now.saturating_duration_since(*lock(&self.last_seen)) >= IDLE_TIMEOUT
    }

    /// Drop a pending upload or import nobody confirmed in time.
    fn drop_stale_upload(&self, now: Instant) {
        let mut slot = lock(&self.pending_upload);
        if slot
            .as_ref()
            .is_some_and(|u| now.saturating_duration_since(u.created) >= PENDING_UPLOAD_TTL)
        {
            *slot = None;
        }
        drop(slot);
        let mut slot = lock(&self.pending_import);
        if slot
            .import
            .as_ref()
            .is_some_and(|u| now.saturating_duration_since(u.created) >= PENDING_UPLOAD_TTL)
        {
            slot.import = None;
        }
    }

    /// The form token for `vault`, or for no vault. It is
    /// `<vault>.<HMAC-SHA256 of the vault, keyed with this session's secret>`,
    /// so a form says which vault it was rendered for and can't be forged.
    pub fn csrf_for(&self, vault: Option<&str>) -> String {
        let vault = vault.unwrap_or_default();
        format!("{vault}.{}", self.csrf_mac(vault))
    }

    /// The form token for the vault chosen now. Every form renders this.
    pub fn csrf_token(&self) -> String {
        self.csrf_for(self.selected_vault().as_deref())
    }

    fn csrf_mac(&self, vault: &str) -> String {
        use base64::Engine;
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.csrf.expose().as_bytes());
        let tag = ring::hmac::sign(&key, format!("keyring form v1\0{vault}").as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag.as_ref())
    }

    /// The vault a genuine form token was rendered for (empty for none).
    /// `None` if the token isn't one of this session's.
    fn csrf_vault<'a>(&self, presented: &'a str) -> Option<&'a str> {
        let (vault, mac) = presented.rsplit_once('.')?;
        constant_time_eq(self.csrf_mac(vault).as_bytes(), mac.as_bytes()).then_some(vault)
    }

    /// True when the form's token is this session's and was rendered for
    /// the vault chosen now. A form from before a vault switch in another
    /// tab is refused, so it can't act on the wrong vault.
    pub fn csrf_matches(&self, presented: &str) -> bool {
        let now = self.selected_vault().unwrap_or_default();
        self.csrf_matches_vault(presented, &now)
    }

    /// True when the form's token is this session's and was rendered for
    /// `vault`. Handlers pass the vault they are about to act on, read
    /// once, so a vault switch in another tab between reading it and
    /// checking the token can't pair one vault's form with another vault.
    pub fn csrf_matches_vault(&self, presented: &str, vault: &str) -> bool {
        self.csrf_vault(presented).is_some_and(|v| v == vault)
    }

    /// True when the form's token is this session's, whichever vault it
    /// was rendered for. Only for forms that don't act on a vault: signing
    /// out and switching vaults.
    pub fn csrf_matches_any(&self, presented: &str) -> bool {
        self.csrf_vault(presented).is_some()
    }

    /// When a genuine form was refused only because it was rendered for
    /// another vault, that vault. Used to explain the refusal.
    pub fn csrf_other_vault(&self, presented: &str) -> Option<String> {
        let now = self.selected_vault().unwrap_or_default();
        self.csrf_vault(presented)
            .filter(|v| !v.is_empty() && *v != now)
            .map(str::to_owned)
    }
}

/// Written by hand so the form key and tokens can never be printed.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user", &self.user)
            .field("selected_vault", &self.selected_vault())
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

/// Drop expired sessions, writing an audit event for each. Not tied to
/// the request in progress, if any, so no browser details.
fn drop_expired(
    map: &mut HashMap<String, Arc<Session>>,
    now: Instant,
    sink: Option<&crate::audit::sink::AuditSink>,
) {
    map.retain(|_, s| {
        let expired = s.expired_at(now);
        if expired {
            record_expired(s, sink);
        }
        !expired
    });
}

fn record_expired(session: &Session, sink: Option<&crate::audit::sink::AuditSink>) {
    use crate::audit::{Action, AuditEvent, Outcome, record};
    record(
        AuditEvent::new(Action::SessionExpired, Outcome::Success).by(session),
        sink,
    );
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock leaves plain data behind, so carry on.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// All live sessions, keyed by the random ID in the session cookie.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// Keys each session's [`Session::audit_ref`].
    audit_key: ring::hmac::Key,
    /// The audit sink, for session expiry events, when it is set.
    audit_sink: std::sync::OnceLock<Arc<crate::audit::sink::AuditSink>>,
}

/// A store whose audit key is random, so its session references join up
/// only within this process. For tests; Keyring uses [`SessionStore::new`].
impl Default for SessionStore {
    fn default() -> Self {
        Self::with_audit_key(random_token(32).as_bytes())
    }
}

/// Prints only how many sessions there are. The keys are live session IDs.
impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStore")
            .field("sessions", &self.len())
            .finish()
    }
}

/// Every [`SWEEP_INTERVAL`], drop expired sessions (with their tokens) and
/// uploads nobody confirmed. Without this they would stay in memory until
/// someone next signs in.
pub fn spawn_sweeper(store: Arc<SessionStore>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            store.sweep_at(Instant::now());
        }
    })
}

impl SessionStore {
    /// A store whose session references are keyed from `SESSION_SECRET`,
    /// so they stay the same across restarts of the same deployment.
    pub fn new(session_secret: &Secret) -> Self {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"keyring audit v1");
        let prk = salt.extract(session_secret.expose().as_bytes());
        let info = [b"session_ref".as_slice()];
        let okm = prk
            .expand(&info, ring::hmac::HMAC_SHA256)
            .expect("valid HKDF length");
        Self {
            sessions: Mutex::new(HashMap::new()),
            audit_key: ring::hmac::Key::from(okm),
            audit_sink: std::sync::OnceLock::new(),
        }
    }

    fn with_audit_key(key: &[u8]) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            audit_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
            audit_sink: std::sync::OnceLock::new(),
        }
    }

    /// Send session expiry events to the audit sink too. Set once, at
    /// start.
    pub fn set_audit_sink(&self, sink: Arc<crate::audit::sink::AuditSink>) {
        let _ = self.audit_sink.set(sink);
    }

    fn sink(&self) -> Option<&crate::audit::sink::AuditSink> {
        self.audit_sink.get().map(Arc::as_ref)
    }

    /// The audit reference for a session ID: the first 16 bytes of its
    /// HMAC, base64url.
    fn audit_ref(&self, id: &str) -> String {
        use base64::Engine;
        let tag = ring::hmac::sign(&self.audit_key, id.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tag.as_ref()[..16])
    }

    /// Start a new session and return its ID for the cookie.
    pub fn create(&self, user: User, tokens: UserTokens) -> String {
        self.create_at(user, tokens, Instant::now())
    }

    pub fn create_at(&self, user: User, tokens: UserTokens, now: Instant) -> String {
        let id = random_token(32);
        let session = Arc::new(Session {
            audit_ref: self.audit_ref(&id),
            user,
            csrf: Secret::new(random_token(32)),
            azure_tokens: TokenCache::default(),
            selected_vault: Mutex::new(None),
            selected_vault_id: Mutex::new(None),
            claims_challenge: Mutex::new(None),
            sign_in: Mutex::new(SignInFacts::default()),
            pending_upload: Mutex::new(None),
            pending_import: Mutex::new(ImportSlot::default()),
            lists: Mutex::new(HashMap::new()),
            permissions: Mutex::new(HashMap::new()),
            permissions_generation: std::sync::atomic::AtomicU64::new(0),
            tokens: Mutex::new(tokens),
            created: now,
            last_seen: Mutex::new(now),
        });
        let mut map = lock(&self.sessions);
        drop_expired(&mut map, now, self.sink());
        map.insert(id.clone(), session);
        id
    }

    /// Look up a live session and mark it as used.
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.get_at(id, Instant::now())
    }

    pub fn get_at(&self, id: &str, now: Instant) -> Option<Arc<Session>> {
        let mut map = lock(&self.sessions);
        let session = map.get(id)?.clone();
        if session.expired_at(now) {
            map.remove(id);
            // Found by the browser that holds it, so its details belong.
            use crate::audit::{Action, AuditEvent, Outcome, from_this_browser, record};
            record(
                from_this_browser(
                    AuditEvent::new(Action::SessionExpired, Outcome::Success).by(&session),
                ),
                self.sink(),
            );
            return None;
        }
        *lock(&session.last_seen) = now;
        Some(session)
    }

    /// Drop expired sessions, and pending uploads older than
    /// [`PENDING_UPLOAD_TTL`], vault lists older than [`LIST_TTL`] and
    /// permissions older than [`PERMISSIONS_TTL`] in
    /// the sessions that are left.
    pub fn sweep_at(&self, now: Instant) {
        let mut map = lock(&self.sessions);
        drop_expired(&mut map, now, self.sink());
        for s in map.values() {
            s.drop_stale_upload(now);
            s.drop_stale_lists(now);
            s.drop_stale_permissions(now);
        }
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        lock(&self.sessions).remove(id)
    }

    pub fn len(&self) -> usize {
        lock(&self.sessions).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn user() -> User {
        User {
            name: "Alex Example".into(),
            username: Some("alex@example.com".into()),
            subject: UserId {
                sub: "sub-1".into(),
                oid: Some("aaaaaaaa-0000-0000-0000-000000000001".into()),
                tid: Some("bbbbbbbb-0000-0000-0000-000000000002".into()),
            },
        }
    }

    pub(crate) fn tokens() -> UserTokens {
        UserTokens {
            access_token: Secret::new("access-token-value"),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            refresh_token: Some(Secret::new("refresh-token-value")),
        }
    }

    #[test]
    fn create_and_get() {
        let store = SessionStore::default();
        let id = store.create(user(), tokens());
        let s = store.get(&id).unwrap();
        assert_eq!(s.user.name, "Alex Example");
        assert!(store.get("nope").is_none());
        assert_ne!(id, s.csrf.expose());
    }

    #[test]
    fn idle_timeout_ends_session() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        assert!(store.get_at(&id, t0 + IDLE_TIMEOUT / 2).is_some());
        // Activity resets the idle clock.
        assert!(store.get_at(&id, t0 + IDLE_TIMEOUT).is_some());
        assert!(
            store
                .get_at(&id, t0 + IDLE_TIMEOUT * 2 + Duration::from_secs(1))
                .is_none()
        );
        assert!(store.is_empty());
    }

    #[test]
    fn absolute_timeout_ends_busy_session() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        let mut t = t0;
        while t < t0 + ABSOLUTE_TIMEOUT - Duration::from_secs(60) {
            t += Duration::from_secs(30 * 60);
            if t >= t0 + ABSOLUTE_TIMEOUT {
                break;
            }
            assert!(store.get_at(&id, t).is_some());
        }
        assert!(store.get_at(&id, t0 + ABSOLUTE_TIMEOUT).is_none());
    }

    #[test]
    fn expired_sessions_are_swept_on_create() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        store.create_at(user(), tokens(), t0);
        store.create_at(user(), tokens(), t0 + ABSOLUTE_TIMEOUT);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn sweep_drops_expired_sessions_without_a_sign_in() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        store.sweep_at(t0 + IDLE_TIMEOUT / 2);
        assert_eq!(store.len(), 1);
        store.sweep_at(t0 + IDLE_TIMEOUT);
        assert!(store.is_empty());
        assert!(store.get_at(&id, t0).is_none());
    }

    fn upload(created: Instant) -> PendingUpload {
        PendingUpload {
            id: "up-1".into(),
            vault: "kv-a".into(),
            name: "web".into(),
            content_type: "application/x-pkcs12",
            value: Secret::new("pfx"),
            password: Some(Secret::new("pw")),
            tags: Default::default(),
            enabled: true,
            exportable: false,
            created,
        }
    }

    #[test]
    fn sweep_drops_stale_uploads_from_live_sessions() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        let s = store.get_at(&id, t0).unwrap();
        s.set_pending_upload(upload(t0));
        store.sweep_at(t0 + PENDING_UPLOAD_TTL / 2);
        assert!(lock(&s.pending_upload).is_some());
        store.sweep_at(t0 + PENDING_UPLOAD_TTL);
        assert!(lock(&s.pending_upload).is_none());
        assert_eq!(store.len(), 1, "the session itself stays");
    }

    #[test]
    fn sweep_drops_stale_imports_and_take_is_once_only() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        let s = store.get_at(&id, t0).unwrap();
        let import = |created| PendingImport {
            id: "im-1".into(),
            vault: "kv-a".into(),
            rows: vec![PendingSecret {
                original: "DB_PASSWORD".into(),
                name: "DB-PASSWORD".into(),
                value: Secret::new("v"),
                content_type: None,
                expires: None,
                tags: Default::default(),
                exists: false,
            }],
            skipped: Vec::new(),
            created,
        };
        let g = s.pending_import_generation();
        assert!(s.set_pending_import(g, import(Instant::now())));
        assert!(s.take_pending_import("im-1").is_some());
        assert!(s.take_pending_import("im-1").is_none(), "only once");
        assert!(s.set_pending_import(g, import(t0)));
        store.sweep_at(t0 + PENDING_UPLOAD_TTL / 2);
        assert!(lock(&s.pending_import).import.is_some());
        store.sweep_at(t0 + PENDING_UPLOAD_TTL);
        assert!(lock(&s.pending_import).import.is_none());
        assert!(!format!("{:?}", import(t0)).contains("\"v\""));
    }

    fn pending(id: &str, created: Instant) -> PendingImport {
        PendingImport {
            id: id.into(),
            vault: "kv-a".into(),
            rows: Vec::new(),
            skipped: Vec::new(),
            created,
        }
    }

    #[test]
    fn a_stale_import_id_leaves_the_newer_import_waiting() {
        let store = SessionStore::default();
        let id = store.create(user(), tokens());
        let s = store.get(&id).unwrap();
        let g = s.pending_import_generation();
        assert!(s.set_pending_import(g, pending("im-a", Instant::now())));
        assert!(s.set_pending_import(g, pending("im-b", Instant::now())));
        assert!(s.take_pending_import("im-a").is_none(), "replaced by B");
        assert!(s.take_pending_import("wrong").is_none());
        assert!(s.take_pending_import("im-b").is_some(), "B still waits");
        assert!(s.take_pending_import("im-b").is_none(), "only once");
        // An expired import goes whatever the ID.
        let old = Instant::now()
            .checked_sub(PENDING_UPLOAD_TTL + Duration::from_secs(1))
            .unwrap();
        assert!(s.set_pending_import(g, pending("im-c", old)));
        assert!(s.take_pending_import("wrong").is_none());
        assert!(lock(&s.pending_import).import.is_none());
    }

    #[test]
    fn a_preview_that_finishes_after_forgetting_is_not_kept() {
        let store = SessionStore::default();
        let id = store.create(user(), tokens());
        let s = store.get(&id).unwrap();
        let before = s.pending_import_generation();
        s.forget_pending_import();
        assert!(!s.set_pending_import(before, pending("im-a", Instant::now())));
        assert!(s.take_pending_import("im-a").is_none());
        let now = s.pending_import_generation();
        assert!(s.set_pending_import(now, pending("im-b", Instant::now())));
        assert!(s.take_pending_import("im-b").is_some());
    }

    #[test]
    fn vault_lists_are_kept_for_a_minute_and_swept() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        let s = store.get_at(&id, t0).unwrap();
        s.keep_list_at("kv-a", Vec::new(), t0);
        s.keep_list_at("kv-b", Vec::new(), t0);
        assert!(s.cached_list_at("kv-a", t0 + LIST_TTL / 2).is_some());
        assert!(s.cached_list_at("kv-a", t0 + LIST_TTL).is_none());
        s.forget_list("kv-b");
        assert!(s.cached_list_at("kv-b", t0).is_none());
        store.sweep_at(t0 + LIST_TTL);
        assert!(lock(&s.lists).is_empty(), "stale lists are dropped");
    }

    #[test]
    fn a_read_begun_before_the_permissions_were_dropped_is_not_kept() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        let s = store.get_at(&id, t0).unwrap();
        let scope = "/subscriptions/s/vaults/kv";
        // A hints read starts, a role is turned on, then the read lands.
        let before = s.permissions_generation();
        s.forget_permissions();
        s.keep_permissions_at(scope, None, t0, before);
        assert!(
            s.cached_permissions_at(scope, t0).is_none(),
            "the stale answer was kept"
        );
        // A read begun after is kept as usual.
        s.keep_permissions_at(scope, None, t0, s.permissions_generation());
        assert!(s.cached_permissions_at(scope, t0).is_some());
    }

    #[test]
    fn permissions_are_kept_a_few_minutes_by_scope_and_swept() {
        let store = SessionStore::default();
        let t0 = Instant::now();
        let id = store.create_at(user(), tokens(), t0);
        let s = store.get_at(&id, t0).unwrap();
        let perms = Arc::new(crate::azure::authz::Permissions::default());
        let g = s.permissions_generation();
        s.keep_permissions_at("/subscriptions/S/vaults/KV", Some(perms), t0, g);
        s.keep_permissions_at("/subscriptions/s/vaults/policy", None, t0, g);
        assert!(
            s.cached_permissions_at("/subscriptions/s/vaults/kv", t0)
                .is_some_and(|p| p.is_some()),
            "scopes match without regard to case"
        );
        assert_eq!(
            s.cached_permissions_at("/subscriptions/s/vaults/policy", t0),
            Some(None),
            "nothing to hint, remembered as such"
        );
        assert!(
            s.cached_permissions_at("/subscriptions/s/vaults/other", t0)
                .is_none()
        );
        assert!(
            s.cached_permissions_at("/subscriptions/s/vaults/kv", t0 + PERMISSIONS_TTL)
                .is_none()
        );
        store.sweep_at(t0 + PERMISSIONS_TTL / 2);
        assert_eq!(lock(&s.permissions).len(), 2);
        store.sweep_at(t0 + PERMISSIONS_TTL);
        assert!(
            lock(&s.permissions).is_empty(),
            "stale permissions are dropped"
        );
    }

    #[test]
    fn csrf_token_is_bound_to_the_vault() {
        let store = SessionStore::default();
        let s = store.get(&store.create(user(), tokens())).unwrap();
        let none = s.csrf_token();
        assert!(s.csrf_matches(&none));
        assert!(!s.csrf_matches("wrong"));
        assert!(!s.csrf_matches(""));
        assert!(!s.csrf_matches(s.csrf.expose()));

        s.select_vault("kv-a".into());
        let a = s.csrf_token();
        assert!(a.starts_with("kv-a."));
        assert!(s.csrf_matches(&a));
        assert!(
            !s.csrf_matches(&none),
            "form from before a vault was chosen"
        );
        assert_eq!(s.csrf_other_vault(&a), None);

        s.select_vault("kv-b".into());
        assert!(!s.csrf_matches(&a), "form rendered for another vault");
        assert_eq!(s.csrf_other_vault(&a).as_deref(), Some("kv-a"));
        assert!(s.csrf_matches(&s.csrf_token()));

        // Sign-out and the vault switch accept any of this session's tokens.
        assert!(s.csrf_matches_any(&a) && s.csrf_matches_any(&none));
        // A token naming a vault but with another session's MAC is refused.
        let other = store.get(&store.create(user(), tokens())).unwrap();
        other.select_vault("kv-b".into());
        assert!(!s.csrf_matches_any(&other.csrf_token()));
        assert!(!s.csrf_matches_any("kv-b.forged"));
        assert_eq!(s.csrf_other_vault("kv-a.forged"), None);
    }

    #[test]
    fn csrf_is_checked_against_the_vault_the_handler_holds() {
        let store = SessionStore::default();
        let s = store.get(&store.create(user(), tokens())).unwrap();
        s.select_vault("kv-a".into());
        let a = s.csrf_token();
        // A handler read kv-a, then another tab switched to kv-b before
        // the token was checked. The check uses the handler's vault.
        s.select_vault("kv-b".into());
        assert!(s.csrf_matches_vault(&a, "kv-a"));
        assert!(!s.csrf_matches_vault(&a, "kv-b"));
        assert!(!s.csrf_matches_vault(&s.csrf_token(), "kv-a"));
    }

    #[test]
    fn a_vault_id_is_only_given_for_the_vault_it_was_kept_with() {
        let store = SessionStore::default();
        let s = store.get(&store.create(user(), tokens())).unwrap();
        s.select_vault_with_id("kv-a".into(), "/sub/a/kv-a".into());
        assert_eq!(s.vault_id_for("kv-a").as_deref(), Some("/sub/a/kv-a"));
        // Another tab moves on: kv-a's ID must not be given for kv-b.
        s.note_vault_used("kv-b");
        assert_eq!(s.vault_id_for("kv-b"), None);
        assert_eq!(s.vault_id_for("kv-a"), None);
        // Using the same vault again keeps its ID.
        s.select_vault_with_id("kv-a".into(), "/sub/a/kv-a".into());
        s.note_vault_used("kv-a");
        assert_eq!(s.vault_id_for("kv-a").as_deref(), Some("/sub/a/kv-a"));
    }

    #[test]
    fn user_id_prefers_object_and_tenant_ids() {
        assert_eq!(
            user().subject.to_string(),
            "oid:aaaaaaaa-0000-0000-0000-000000000001,tid:bbbbbbbb-0000-0000-0000-000000000002"
        );
        assert_eq!(UserId::from("pairwise").to_string(), "sub:pairwise");
    }

    #[test]
    fn debug_does_not_leak_tokens_ids_or_form_keys() {
        let store = SessionStore::default();
        let id = store.create(user(), tokens());
        let s = store.get(&id).unwrap();
        s.select_vault("kv-a".into());
        let out = format!("{s:?} {:?} {store:?}", s.tokens());
        assert!(!out.contains("access-token-value"));
        assert!(!out.contains("refresh-token-value"));
        assert!(!out.contains(s.csrf.expose()), "form key leaked: {out}");
        assert!(!out.contains(&s.csrf_token()), "form token leaked: {out}");
        assert!(!out.contains(&id), "session ID leaked: {out}");
    }
}
