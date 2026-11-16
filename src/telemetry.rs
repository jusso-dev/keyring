//! Structured logging setup and the request log.
//!
//! Each request gets one line with its method, path (never the query
//! string), status and duration. Headers, bodies and query strings are never
//! logged, because they can carry secret values or tokens.
//!
//! Keyring's own audit events (see [`crate::audit`]) are log lines too,
//! under the `keyring::audit` target. With `KEYRING_LOG_FORMAT=json` every
//! line is one JSON object, and audit events have `"kind":"audit"`.

use std::io::IsTerminal;
use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

use crate::config::LogFormat;

/// Start the global `tracing` subscriber at the given level and format.
/// The level was checked by [`crate::config::Config`]; anything else falls
/// back to info.
pub fn init(level: &str, format: LogFormat) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let level = level.parse::<LevelFilter>().unwrap_or(LevelFilter::INFO);
    let registry = tracing_subscriber::registry().with(filter(level));
    match format {
        LogFormat::Text => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_ansi(std::io::stdout().is_terminal()),
            )
            .init(),
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .event_format(JsonLines),
            )
            .init(),
    }
}

/// Lines at `level` and above, plus Keyring's audit events whatever the
/// level, so `KEYRING_LOG_LEVEL=warn` can't drop the record of a reveal.
pub fn filter(level: LevelFilter) -> tracing_subscriber::filter::Targets {
    tracing_subscriber::filter::Targets::new()
        .with_default(level)
        .with_target(crate::audit::TARGET, LevelFilter::INFO.max(level))
}

/// Writes each event as one JSON object on one line: `time`, `level`,
/// `kind` (`audit` for Keyring's audit events, `log` for the rest),
/// `message`, then the event's own fields. JSON encoding escapes every
/// string, so nothing in a field can start a new line.
///
/// Small and hand-written over `tracing-subscriber`'s `fmt`, so the `json`
/// feature and its extra crates aren't needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonLines;

impl<S, N> FormatEvent<S, N> for JsonLines
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        let mut obj = serde_json::Map::new();
        obj.insert(
            "time".into(),
            crate::audit::rfc3339_millis(std::time::SystemTime::now()).into(),
        );
        obj.insert("level".into(), meta.level().as_str().to_lowercase().into());
        obj.insert("kind".into(), "log".into());
        // An audit event's own fields, including its `time`, win.
        event.record(&mut JsonVisitor(&mut obj));
        let line = serde_json::to_string(&obj).map_err(|_| std::fmt::Error)?;
        writeln!(writer, "{line}")
    }
}

struct JsonVisitor<'a>(&'a mut serde_json::Map<String, serde_json::Value>);

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
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
