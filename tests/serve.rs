//! The real server loop: normal requests work, slow headers are cut off,
//! and shutdown is graceful.

mod support;

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = keyring::app(keyring::AppState::new(support::config()));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        keyring::serve::serve(listener, app, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    (addr, tx, handle)
}

#[tokio::test]
async fn serves_requests() {
    let (addr, tx, handle) = start().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.ends_with("ok"));
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn slow_headers_are_cut_off() {
    let (addr, _tx, _handle) = start().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    // Start a request but never finish the headers.
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(
        keyring::serve::HEADER_READ_TIMEOUT + Duration::from_secs(5),
        s.read(&mut buf),
    )
    .await
    .expect("server should close the connection")
    .unwrap_or(0);
    let took = started.elapsed();
    assert!(
        took >= keyring::serve::HEADER_READ_TIMEOUT - Duration::from_secs(1),
        "closed too early: {took:?}"
    );
    // Either closed with no reply or a 408.
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(n == 0 || text.starts_with("HTTP/1.1 408"), "{text}");
}
