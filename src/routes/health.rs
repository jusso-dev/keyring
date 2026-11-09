use axum::http::header;
use axum::response::IntoResponse;

/// Liveness probe. Does no work and calls nothing.
pub async fn healthz() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], "ok")
}
