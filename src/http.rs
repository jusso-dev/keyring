//! The one outbound HTTP client, `reqwest` on rustls with the `ring` provider.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Once;
use std::time::Duration;

use openidconnect::{HttpRequest, HttpResponse};

static INSTALL_PROVIDER: Once = Once::new();

/// Build the shared client. `https_only` is off only for local test servers.
///
/// Fails if the TLS settings can't be loaded, for example when
/// `SSL_CERT_FILE` points at a file with no certificates in it. Called
/// before Keyring starts listening, so the error stops start-up.
pub fn client(https_only: bool) -> Result<reqwest::Client, HttpError> {
    INSTALL_PROVIDER.call_once(|| {
        // Fails only if another provider was installed first, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    reqwest::Client::builder()
        .https_only(https_only)
        // Token endpoints must not redirect; following one could leak codes.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("keyring/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(HttpError::from)
}

/// Error from an outbound call. Holds no request or response bodies.
#[derive(Debug)]
pub struct HttpError(String);

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpError {}

impl From<reqwest::Error> for HttpError {
    fn from(err: reqwest::Error) -> Self {
        // Strip the URL in case a query string carries anything sensitive.
        // reqwest's own message is only the kind ("error sending request");
        // the DNS, TLS or timeout detail is in the source chain.
        Self(error_chain(&err.without_url()))
    }
}

/// Flatten an error and its sources into one line for logs, such as
/// `error sending request: client error (Connect): dns error: ...`.
/// Errors from the HTTP layer never include bodies, so this holds no tokens.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    // Bounded, in case a source chain loops.
    for _ in 0..16 {
        let Some(e) = src else { break };
        let next = e.to_string();
        // Some layers repeat their source's text; don't print it twice.
        if !out.ends_with(&next) {
            out.push_str(": ");
            out.push_str(&next);
        }
        src = e.source();
    }
    out
}

/// Adapter so `openidconnect` sends its requests through our client.
#[derive(Clone)]
pub struct OidcHttp(pub reqwest::Client);

impl<'c> openidconnect::AsyncHttpClient<'c> for OidcHttp {
    type Error = HttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(send(&self.0, request))
    }
}

async fn send(client: &reqwest::Client, req: HttpRequest) -> Result<HttpResponse, HttpError> {
    let req = reqwest::Request::try_from(req)?;
    let res = client.execute(req).await?;
    let mut builder = openidconnect::http::Response::builder().status(res.status());
    for (name, value) in res.headers() {
        builder = builder.header(name, value);
    }
    let body = res.bytes().await?.to_vec();
    builder.body(body).map_err(|e| HttpError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn network_errors_keep_their_cause_but_not_the_url() {
        let client = client(false).unwrap();
        // Nothing listens on port 9 of localhost, so the connection fails.
        let err = client
            .get("http://127.0.0.1:9/secrets/x?api-version=7.4&token=hunter2")
            .send()
            .await
            .unwrap_err();
        let msg = HttpError::from(err).to_string();
        assert!(msg.starts_with("error sending request"), "{msg}");
        assert!(msg.len() > "error sending request".len(), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");
        assert!(!msg.contains("127.0.0.1:9/secrets"), "{msg}");
    }
}
