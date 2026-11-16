//! Read every vault the person can see, a few at a time.
//!
//! Each vault gets its own time limit, so one slow or throttled vault
//! doesn't hold up the rest, and the whole read has a deadline, well
//! inside the request limit, so the page always comes back with what it
//! found. Vaults that can't be read, or weren't reached in time, are
//! returned with the reason in plain words.
//!
//! The per-vault work is up to the caller: it is handed each vault's name
//! and returns whatever it read, plus a reason if some or all of the vault
//! couldn't be read.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::azure::AzureError;

/// Vaults read at the same time.
pub const CONCURRENCY: usize = 6;
/// Time limit for reading one vault.
pub const VAULT_TIMEOUT: Duration = Duration::from_secs(20);
/// Time limit for the whole read. Well under the 90 second request limit
/// in `routes::headers`, so there is time left to build the page.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// Why a vault over [`VAULT_TIMEOUT`] is missing.
pub(crate) const TOO_SLOW: &str = "Took too long to answer";
/// Why a vault not finished by [`DEADLINE`] is missing.
pub(crate) const OUT_OF_TIME: &str = "Not read in time. Keyring stops reading after a minute so it can show what it has. Pick this vault on its own to see it";
/// Why a vault whose read failed inside Keyring is missing.
pub(crate) const TASK_FAILED: &str = "Keyring hit a problem reading it";

/// A vault that couldn't be read, and why in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub vault: String,
    pub reason: String,
}

/// What came back from every vault.
pub struct Fanned<T> {
    /// Each vault that answered in time, with what was read from it, in
    /// the order they finished.
    pub read: Vec<(String, T)>,
    /// Vaults not read, or only partly read, sorted by name.
    pub skipped: Vec<Skipped>,
}

/// How many vaults at once, and how long each and all may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub concurrency: usize,
    pub vault_timeout: Duration,
    pub deadline: Duration,
}

impl Limits {
    /// [`CONCURRENCY`], [`VAULT_TIMEOUT`] and [`DEADLINE`]. Only tests use
    /// anything else.
    pub const STANDARD: Limits = Limits {
        concurrency: CONCURRENCY,
        vault_timeout: VAULT_TIMEOUT,
        deadline: DEADLINE,
    };
}

/// Plain words for why a vault couldn't be read. Never Azure's message.
pub fn reason(err: &AzureError) -> String {
    match err {
        AzureError::Status {
            status: 403, code, ..
        } if code
            .as_deref()
            .is_some_and(|c| c == "ForbiddenByFirewall" || c == "ForbiddenByConnection") =>
        {
            "Blocked by the vault's firewall".into()
        }
        AzureError::Status { status: 403, .. } => "You don't have a Key Vault role on it".into(),
        AzureError::Status { status: 429, .. } => {
            "Azure was throttling requests. Try again in a minute".into()
        }
        AzureError::Network(_) => {
            "Couldn't reach it. It may only be reachable on a private network".into()
        }
        AzureError::Token(_) => "Sign-in needs refreshing".into(),
        _ => "Azure returned an error".into(),
    }
}

/// Run `read` for each vault, [`CONCURRENCY`] at a time, each within
/// [`VAULT_TIMEOUT`], giving up on whatever is left at [`DEADLINE`].
///
/// `read` returns what it found and, if part or all of the vault couldn't
/// be read, the reason. A vault with a reason is listed in `skipped` and
/// what it did find is still kept.
pub async fn read_each<T, F, Fut>(vaults: impl IntoIterator<Item = String>, read: F) -> Fanned<T>
where
    T: Send + 'static,
    F: FnMut(String) -> Fut,
    Fut: Future<Output = (T, Option<String>)> + Send + 'static,
{
    read_each_within(vaults, read, Limits::STANDARD).await
}

pub(crate) async fn read_each_within<T, F, Fut>(
    vaults: impl IntoIterator<Item = String>,
    mut read: F,
    limits: Limits,
) -> Fanned<T>
where
    T: Send + 'static,
    F: FnMut(String) -> Fut,
    Fut: Future<Output = (T, Option<String>)> + Send + 'static,
{
    let deadline = tokio::time::Instant::now() + limits.deadline;
    let permits = Arc::new(Semaphore::new(limits.concurrency));
    let mut set = JoinSet::new();
    // Task ID to vault name, so a task that panics or runs out of time
    // can still be reported by name.
    let mut pending: HashMap<tokio::task::Id, String> = HashMap::new();
    for vault in vaults {
        let work = read(vault.clone());
        let permits = permits.clone();
        let handle = set.spawn(async move {
            let _permit = permits.acquire_owned().await;
            tokio::time::timeout(limits.vault_timeout, work).await
        });
        pending.insert(handle.id(), vault);
    }
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    loop {
        let done = match tokio::time::timeout_at(deadline, set.join_next_with_id()).await {
            Ok(Some(done)) => done,
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(unfinished = pending.len(), "vault reads ran out of time");
                set.abort_all();
                skipped.extend(pending.drain().map(|(_, vault)| Skipped {
                    vault,
                    reason: OUT_OF_TIME.into(),
                }));
                break;
            }
        };
        match done {
            Ok((id, result)) => {
                let Some(vault) = pending.remove(&id) else {
                    continue;
                };
                match result {
                    Ok((found, why)) => {
                        if let Some(reason) = why {
                            skipped.push(Skipped {
                                vault: vault.clone(),
                                reason,
                            });
                        }
                        out.push((vault, found));
                    }
                    Err(_) => skipped.push(Skipped {
                        vault,
                        reason: TOO_SLOW.into(),
                    }),
                }
            }
            Err(e) => {
                tracing::error!(error = ?e.to_string(), "vault read task failed");
                if let Some(vault) = pending.remove(&e.id()) {
                    skipped.push(Skipped {
                        vault,
                        reason: TASK_FAILED.into(),
                    });
                }
            }
        }
    }
    skipped.sort_by(|a, b| a.vault.cmp(&b.vault));
    Fanned { read: out, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn quick(deadline_ms: u64) -> Limits {
        Limits {
            concurrency: CONCURRENCY,
            vault_timeout: Duration::from_millis(200),
            deadline: Duration::from_millis(deadline_ms),
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn got(skipped: &[Skipped]) -> Vec<(&str, &str)> {
        skipped
            .iter()
            .map(|s| (s.vault.as_str(), s.reason.as_str()))
            .collect()
    }

    #[tokio::test]
    async fn a_slow_vault_is_skipped_and_the_rest_are_read() {
        let started = std::time::Instant::now();
        let out = read_each_within(
            names(&["kv-a", "kv-slow", "kv-b"]),
            |vault| async move {
                if vault == "kv-slow" {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                (vault.len(), None)
            },
            quick(5_000),
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "per-vault limit"
        );
        let mut read: Vec<&str> = out.read.iter().map(|(v, _)| v.as_str()).collect();
        read.sort();
        assert_eq!(read, ["kv-a", "kv-b"]);
        assert_eq!(got(&out.skipped), [("kv-slow", TOO_SLOW)]);
    }

    #[tokio::test]
    async fn a_forbidden_vault_is_listed_with_the_reason() {
        let forbidden = AzureError::Status {
            status: 403,
            code: Some("Forbidden".into()),
            message: None,
        };
        let why = reason(&forbidden);
        let out = read_each_within(
            names(&["kv-ok", "kv-locked"]),
            |vault| {
                let why = why.clone();
                async move {
                    if vault == "kv-locked" {
                        (Vec::new(), Some(why))
                    } else {
                        (vec![vault], None)
                    }
                }
            },
            quick(5_000),
        )
        .await;
        assert_eq!(
            got(&out.skipped),
            [("kv-locked", "You don't have a Key Vault role on it")]
        );
        let found: Vec<&String> = out.read.iter().flat_map(|(_, v)| v).collect();
        assert_eq!(found, ["kv-ok"]);
    }

    #[tokio::test]
    async fn the_total_deadline_stops_the_read_and_names_what_is_left() {
        // One at a time, each just under its own limit, so the deadline
        // comes first.
        let limits = Limits {
            concurrency: 1,
            vault_timeout: Duration::from_millis(500),
            deadline: Duration::from_millis(600),
        };
        let started = std::time::Instant::now();
        let out = read_each_within(
            names(&["kv-1", "kv-2", "kv-3"]),
            |_| async {
                tokio::time::sleep(Duration::from_millis(400)).await;
                ((), None)
            },
            limits,
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "stopped at the deadline"
        );
        assert_eq!(out.read.len(), 1);
        assert_eq!(out.skipped.len(), 2);
        assert!(out.skipped.iter().all(|s| s.reason == OUT_OF_TIME));
    }

    #[tokio::test]
    async fn a_panic_names_the_vault() {
        let out = read_each_within(
            names(&["kv-fine", "kv-broken"]),
            |vault| async move {
                if vault == "kv-broken" {
                    panic!("read failed inside the task");
                }
                ((), None)
            },
            quick(5_000),
        )
        .await;
        assert_eq!(out.read.len(), 1);
        assert_eq!(got(&out.skipped), [("kv-broken", TASK_FAILED)]);
    }

    #[tokio::test]
    async fn no_more_than_the_limit_run_at_once() {
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let vaults: Vec<String> = (0..20).map(|i| format!("kv-{i}")).collect();
        let out = read_each_within(
            vaults,
            |_| {
                let (running, most) = (running.clone(), most.clone());
                async move {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    running.fetch_sub(1, Ordering::SeqCst);
                    ((), None)
                }
            },
            quick(5_000),
        )
        .await;
        assert_eq!(out.read.len(), 20);
        assert!(out.skipped.is_empty());
        assert!(most.load(Ordering::SeqCst) <= CONCURRENCY);
    }
}
