//! Doing one thing to many items in one request: a secrets import, or a
//! bulk change of tags, expiry or enabled.
//!
//! Each item's work runs as the person, [`CONCURRENCY`] at a time, inside
//! [`ItemEvents::run`], so each item that reaches Key Vault gets its own
//! audit event. No new work starts after the start deadline, and Keyring
//! stops waiting at the stop deadline, well inside the request limit.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::audit::ItemEvents;

/// Items worked on at once.
pub(crate) const CONCURRENCY: usize = 4;
/// No new item starts after this long, so the page comes back well inside
/// the request limit.
pub(crate) const START_DEADLINE: Duration = Duration::from_secs(45);
/// Stop waiting for work still running after this long.
pub(crate) const STOP_DEADLINE: Duration = Duration::from_secs(70);

/// When work stops starting, and when Keyring stops waiting for it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadlines {
    pub start: Duration,
    pub stop: Duration,
}

impl Deadlines {
    pub(crate) const STANDARD: Self = Self {
        start: START_DEADLINE,
        stop: STOP_DEADLINE,
    };
}

/// How one item's work went.
#[derive(Debug)]
pub(crate) enum Ran<T, E> {
    /// The work finished, well or not.
    Done(Result<T, E>),
    /// Never started: no permit came free before the start deadline. No
    /// audit event, since nothing reached Key Vault.
    NotStarted,
    /// Started, but Keyring stopped waiting. Its event says `cancelled`.
    Unknown,
}

/// Run `work` on each `(name, item)`, [`CONCURRENCY`] at a time, and say how
/// each went, in the same order. Each item whose work began writes one
/// audit event through `events`, named by its `name`, which must be a
/// checked item name. A task cut off in flight writes `cancelled`
/// (see [`ItemEvents::run`]).
pub(crate) async fn run_each<I, F, Fut, T, E>(
    items: Vec<(String, I)>,
    events: ItemEvents,
    deadlines: Deadlines,
    work: F,
) -> Vec<Ran<T, E>>
where
    I: Send + 'static,
    F: Fn(I) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let started = tokio::time::Instant::now();
    let start_by = started + deadlines.start;
    let permits = Arc::new(Semaphore::new(CONCURRENCY));
    // Set just before an item's work begins, so an item whose task was cut
    // off before then is known not to have been sent.
    let began: Arc<Vec<AtomicBool>> =
        Arc::new((0..items.len()).map(|_| AtomicBool::new(false)).collect());
    let mut results: Vec<Option<Ran<T, E>>> = (0..items.len()).map(|_| None).collect();
    let mut set = JoinSet::new();
    for (i, (name, item)) in items.into_iter().enumerate() {
        let permits = permits.clone();
        let events = events.clone();
        let began = began.clone();
        let work = work.clone();
        set.spawn(async move {
            // Waiting for a permit stops at the start deadline too, so an
            // item queued behind slow work is reported as not sent.
            let Ok(Ok(_permit)) = tokio::time::timeout_at(start_by, permits.acquire_owned()).await
            else {
                return (i, Ran::NotStarted);
            };
            if tokio::time::Instant::now() >= start_by {
                return (i, Ran::NotStarted);
            }
            began[i].store(true, Ordering::SeqCst);
            (i, Ran::Done(events.run(&name, work(item)).await))
        });
    }
    let stop = started + deadlines.stop;
    loop {
        match tokio::time::timeout_at(stop, set.join_next()).await {
            Ok(Some(Ok((i, r)))) => results[i] = Some(r),
            // A task that panicked: its result depends on whether it began.
            Ok(Some(Err(_))) => {}
            Ok(None) => break,
            Err(_) => {
                // Dropping the tasks writes a `cancelled` event for each
                // item still in flight, and none for one not begun.
                set.abort_all();
                while let Some(done) = set.join_next().await {
                    if let Ok((i, r)) = done {
                        results[i] = Some(r);
                    }
                }
                break;
            }
        }
    }
    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| match r {
            Some(r) => r,
            None if began[i].load(Ordering::SeqCst) => Ran::Unknown,
            None => Ran::NotStarted,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Action;

    #[test]
    fn deadlines_sit_inside_the_request_limit() {
        assert!(START_DEADLINE < STOP_DEADLINE);
        assert!(STOP_DEADLINE + Duration::from_secs(15) <= crate::routes::headers::REQUEST_TIMEOUT);
    }

    // Each item's audit event comes from `ItemEvents::run` around its
    // work, so an item whose work was never called writes no event, and
    // one cut off in flight writes `cancelled` (tested in `audit`).
    #[tokio::test]
    async fn items_queued_past_the_start_deadline_are_not_sent_and_not_unknown() {
        let sent = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let items: Vec<(String, String)> = (0..10)
            .map(|i| (format!("s{i}"), format!("s{i}")))
            .collect();
        // Every task hangs, so the four permits are never given back.
        let calls = sent.clone();
        let results = run_each(
            items,
            ItemEvents::for_request(Action::SecretImport, None),
            Deadlines {
                start: Duration::from_millis(200),
                stop: Duration::from_millis(500),
            },
            move |name: String| {
                calls.lock().unwrap().push(name);
                async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok::<(), ()>(())
                }
            },
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), CONCURRENCY, "only four began");
        for (i, r) in results.iter().enumerate() {
            let name = format!("s{i}");
            match r {
                Ran::Unknown => assert!(sent.contains(&name), "{name}"),
                Ran::NotStarted => assert!(!sent.contains(&name), "{name}"),
                Ran::Done(_) => panic!("{name} can't have finished"),
            }
        }
        let unknown = results.iter().filter(|r| matches!(r, Ran::Unknown)).count();
        assert_eq!(unknown, CONCURRENCY);
    }

    #[tokio::test]
    async fn results_come_back_in_order() {
        let items: Vec<(String, usize)> = (0..6).map(|i| (format!("s{i}"), i)).collect();
        let results = run_each(
            items,
            ItemEvents::for_request(Action::SecretImport, None),
            Deadlines::STANDARD,
            |i: usize| async move { if i == 3 { Err(i) } else { Ok(i) } },
        )
        .await;
        let got: Vec<Result<usize, usize>> = results
            .into_iter()
            .map(|r| match r {
                Ran::Done(r) => r,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(got, [Ok(0), Ok(1), Ok(2), Err(3), Ok(4), Ok(5)]);
    }
}
