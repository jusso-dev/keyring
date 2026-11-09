//! Structured logging setup.
//!
//! Only metadata is logged: method, path, status and timing. Request and
//! response bodies, headers and query strings are never logged, because they
//! can carry secret values or tokens.

use std::io::IsTerminal;

use tracing_subscriber::filter::LevelFilter;

/// Start the global `tracing` subscriber at the given level.
pub fn init(level: &str) {
    let level = level.parse::<LevelFilter>().unwrap_or(LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}
