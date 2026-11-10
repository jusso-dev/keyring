//! Structured logging setup and the request log.
//!
//! Each request gets one line with its method, path (never the query
//! string), status and duration. Headers, bodies and query strings are never
//! logged, because they can carry secret values or tokens. Action lines,
//! such as "secret value revealed", also name the vault and the item, and
//! who did it by Entra object ID and tenant ID.

use std::io::IsTerminal;
use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing_subscriber::filter::LevelFilter;

/// Start the global `tracing` subscriber at the given level. The level was
/// checked by [`crate::config::Config`]; anything else falls back to info.
pub fn init(level: &str) {
    let level = level.parse::<LevelFilter>().unwrap_or(LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}

/// Middleware: log one line per request. The path is taken before the
/// handler runs and has no query string.
pub async fn request_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = Instant::now();
    let res = next.run(req).await;
    let status = res.status().as_u16();
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if res.status().is_server_error() {
        tracing::warn!(%method, %path, status, ms, "request");
    } else {
        tracing::info!(%method, %path, status, ms, "request");
    }
    res
}

/// Replace the default panic hook, which prints the panic message to
/// stderr. The message can hold request data (an `expect` with a formatted
/// value, a serde error quoting input), so log only where it happened.
pub fn quiet_panics() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        tracing::error!(%location, "panicked");
    }));
}
