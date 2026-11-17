use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use crate::AppState;

/// Liveness probe. Does no work and calls nothing.
pub(super) async fn healthz() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], "ok")
}

/// The audit sink's state, for a probe or alert: `ok` or `degraded` and
/// counts since start, nothing else. No sign-in. 503 while degraded, so a
/// plain HTTP check can alert on it. Without the sink set, `off`.
pub(super) async fn audit(State(state): State<AppState>) -> impl IntoResponse {
    let (status, body) = match &state.audit_sink {
        None => (StatusCode::OK, "status=off\n".to_owned()),
        Some(sink) => {
            let h = sink.health();
            (
                if h.degraded {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                },
                format!(
                    "status={}\nqueued={}\nsent={}\ndropped_queue_full={}\ndropped_rejected={}\ndropped_at_shutdown={}\nfailed_attempts={}\n",
                    if h.degraded { "degraded" } else { "ok" },
                    h.queued,
                    h.sent,
                    h.dropped_queue_full,
                    h.dropped_rejected,
                    h.dropped_at_shutdown,
                    h.failed_attempts,
                ),
            )
        }
    };
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
        ],
        body,
    )
}

/// The email sender's state, like [`audit`]: `ok`, `degraded` or `off` and
/// counts since start, nothing else. No addresses. No sign-in. 503 while
/// degraded.
pub(super) async fn notify(State(state): State<AppState>) -> impl IntoResponse {
    let (status, body) = match &state.notifier {
        None => (StatusCode::OK, "status=off\n".to_owned()),
        Some(n) => {
            let h = n.health();
            (
                if h.degraded {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                },
                format!(
                    "status={}\nqueued={}\ndelivered={}\nfailed={}\nunknown={}\ndropped_queue_full={}\ndropped_at_shutdown={}\nrate_limited={}\nnot_allowed={}\ninvalid={}\nfailed_attempts={}\n",
                    if h.degraded { "degraded" } else { "ok" },
                    h.queued,
                    h.delivered,
                    h.failed,
                    h.unknown,
                    h.dropped_queue_full,
                    h.dropped_at_shutdown,
                    h.rate_limited,
                    h.not_allowed,
                    h.invalid,
                    h.failed_attempts,
                ),
            )
        }
    };
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
        ],
        body,
    )
}
