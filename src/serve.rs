//! The HTTP server loop.
//!
//! Like `axum::serve`, plus limits on slow or greedy clients:
//! - request headers must arrive within [`HEADER_READ_TIMEOUT`], so a client
//!   trickling headers can't hold a connection open;
//! - at most [`MAX_CONNECTIONS`] connections are open at once. Past that,
//!   new ones wait in the listen backlog instead of using up file handles;
//! - a connection is asked to close after [`MAX_CONNECTION_AGE`], and is cut
//!   off [`CLOSE_GRACE`] later. A client that sends a request and never
//!   reads the answer can't hold a socket for longer than that.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tower::ServiceExt;

/// Time a client has to send the request line and headers.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long shutdown waits for requests in flight.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);
/// Most connections open at once.
pub const MAX_CONNECTIONS: usize = 512;
/// After this long a connection finishes its current request and closes.
pub const MAX_CONNECTION_AGE: Duration = Duration::from_secs(5 * 60);
/// How long a closing connection gets to finish. Longer than the 90 second
/// request limit, so a slow page in progress still completes.
pub const CLOSE_GRACE: Duration = Duration::from_secs(2 * 60);

pub async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    serve_with(listener, app, shutdown, Limits::default()).await
}

/// Connection limits, so tests can use small ones.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_connections: usize,
    pub max_age: Duration,
    pub close_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_age: MAX_CONNECTION_AGE,
            close_grace: CLOSE_GRACE,
        }
    }
}

pub async fn serve_with(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
    limits: Limits,
) -> std::io::Result<()> {
    let mut builder = Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(64 * 1024);
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    // Flips to true when shutdown starts, telling every connection to close.
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::pin!(shutdown);
    loop {
        // Wait for a free slot before accepting, so extra clients queue in
        // the backlog rather than being accepted and dropped.
        let slot = tokio::select! {
            s = slots.clone().acquire_owned() => s.expect("the semaphore is never closed"),
            () = &mut shutdown => break,
        };
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((s, _)) => s,
                Err(e) => {
                    // Usually too many open files; back off briefly.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);
        let app = app.clone();
        let service = TowerToHyperService::new(tower::service_fn(move |req: Request<Incoming>| {
            let app = app.clone();
            async move {
                Ok::<_, Infallible>(
                    app.oneshot(req.map(axum::body::Body::new))
                        .await
                        .unwrap_or_else(|e| match e {}),
                )
            }
        }));
        let conn = builder.serve_connection(TokioIo::new(stream), service);
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            // Held until the connection ends, freeing the slot.
            let _slot = slot;
            tokio::pin!(conn);
            let closing_at = tokio::time::sleep(limits.max_age);
            tokio::pin!(closing_at);
            let mut closing = false;
            let result = loop {
                tokio::select! {
                    r = conn.as_mut() => break Some(r),
                    () = &mut closing_at => {
                        if closing {
                            // Didn't finish in time; drop it.
                            break None;
                        }
                        conn.as_mut().graceful_shutdown();
                        closing = true;
                        closing_at.as_mut().reset(tokio::time::Instant::now() + limits.close_grace);
                    }
                    _ = stop.wait_for(|stopping| *stopping), if !closing => {
                        conn.as_mut().graceful_shutdown();
                        closing = true;
                        closing_at.as_mut().reset(tokio::time::Instant::now() + limits.close_grace);
                    }
                }
            };
            match result {
                // Connection errors (client went away, header timeout)
                // are routine; nothing to log at info.
                Some(Err(e)) => tracing::debug!(error = %e, "connection ended with an error"),
                Some(Ok(())) => {}
                None => tracing::debug!("connection cut off after its close grace period"),
            }
        });
    }
    drop(listener);
    let _ = stop_tx.send(true);
    // Every connection holds a slot, so all slots free means all done.
    let all = u32::try_from(limits.max_connections).unwrap_or(u32::MAX);
    tokio::select! {
        _ = slots.acquire_many(all) => {},
        () = tokio::time::sleep(SHUTDOWN_GRACE) => tracing::warn!("shutdown grace period ran out"),
    }
    Ok(())
}
