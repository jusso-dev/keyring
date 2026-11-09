//! The HTTP server loop.
//!
//! Like `axum::serve`, plus limits on slow clients: request headers must
//! arrive within [`HEADER_READ_TIMEOUT`], so a client trickling headers
//! can't hold a connection open.

use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// Time a client has to send the request line and headers.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long shutdown waits for requests in flight.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

pub async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let mut builder = Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(64 * 1024);
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(s) => s,
                    Err(e) => {
                        // Usually too many open files; back off briefly.
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let app = app.clone();
                let service = TowerToHyperService::new(tower::service_fn(move |req: Request<Incoming>| {
                    let app = app.clone();
                    async move { Ok::<_, Infallible>(app.oneshot(req.map(axum::body::Body::new)).await.unwrap_or_else(|e| match e {})) }
                }));
                let conn = builder.serve_connection(TokioIo::new(stream), service);
                let conn = graceful.watch(conn);
                tokio::spawn(async move {
                    // Connection errors (client went away, header timeout)
                    // are routine; nothing to log at info.
                    if let Err(e) = conn.await {
                        tracing::debug!(error = %e, "connection ended with an error");
                    }
                });
            }
            () = &mut shutdown => break,
        }
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {},
        () = tokio::time::sleep(SHUTDOWN_GRACE) => tracing::warn!("shutdown grace period ran out"),
    }
    Ok(())
}
