//! Server-side sessions held in memory. The browser only gets a random ID.
//!
//! Nothing here is written to disk. Restarting Keyring signs everyone out.
//! Running more than one copy needs sticky sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::auth::crypto::random_token;
use crate::azure::token::TokenCache;
use crate::secret::Secret;

/// Sign out after this long without a request.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Sign out after this long regardless of activity.
pub const ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);

/// How long an uploaded file waits for confirmation.
pub const PENDING_UPLOAD_TTL: Duration = Duration::from_secs(10 * 60);

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

/// Who is signed in, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub username: Option<String>,
    pub subject: String,
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
#[derive(Debug)]
pub struct Session {
    pub user: User,
    /// Per-session token every form posts back, checked on the server.
    pub csrf: String,
    /// Tokens for Azure APIs, exchanged on behalf of this user.
    pub azure_tokens: TokenCache,
    /// Vault picked in the header. Lives only as long as the session.
    selected_vault: Mutex<Option<String>>,
    /// A certificate file between "preview" and "import". Memory only.
    pending_upload: Mutex<Option<PendingUpload>>,
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

    /// Remember the chosen vault. The caller checks the name is valid.
    pub fn select_vault(&self, name: String) {
        *lock(&self.selected_vault) = Some(name);
    }

    fn expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) >= ABSOLUTE_TIMEOUT
            || now.saturating_duration_since(*lock(&self.last_seen)) >= IDLE_TIMEOUT
    }

    /// True when the form's token matches this session's.
    pub fn csrf_matches(&self, presented: &str) -> bool {
        crate::auth::crypto::constant_time_eq(self.csrf.as_bytes(), presented.as_bytes())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock leaves plain data behind, so carry on.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// All live sessions, keyed by the random ID in the session cookie.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

impl SessionStore {
    /// Start a new session and return its ID for the cookie.
    pub fn create(&self, user: User, tokens: UserTokens) -> String {
        self.create_at(user, tokens, Instant::now())
    }

    pub fn create_at(&self, user: User, tokens: UserTokens, now: Instant) -> String {
        let id = random_token(32);
        let session = Arc::new(Session {
            user,
            csrf: random_token(32),
            azure_tokens: TokenCache::default(),
            selected_vault: Mutex::new(None),
            pending_upload: Mutex::new(None),
            tokens: Mutex::new(tokens),
            created: now,
            last_seen: Mutex::new(now),
        });
        let mut map = lock(&self.sessions);
        map.retain(|_, s| !s.expired_at(now));
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
            return None;
        }
        *lock(&session.last_seen) = now;
        Some(session)
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
            subject: "sub-1".into(),
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
        assert_ne!(id, s.csrf);
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
    fn csrf_check() {
        let store = SessionStore::default();
        let s = store.get(&store.create(user(), tokens())).unwrap();
        assert!(s.csrf_matches(&s.csrf.clone()));
        assert!(!s.csrf_matches("wrong"));
    }

    #[test]
    fn debug_does_not_leak_tokens() {
        let store = SessionStore::default();
        let s = store.get(&store.create(user(), tokens())).unwrap();
        let out = format!("{s:?} {:?}", s.tokens());
        assert!(!out.contains("access-token-value"));
        assert!(!out.contains("refresh-token-value"));
    }
}
