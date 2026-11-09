//! The one outbound HTTP client, `reqwest` on rustls with the `ring` provider.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Once;
use std::time::Duration;

use openidconnect::{HttpRequest, HttpResponse};

static INSTALL_PROVIDER: Once = Once::new();

/// Build the shared client. `https_only` is off only for local test servers.
pub fn client(https_only: bool) -> reqwest::Client {
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
        .expect("HTTP client settings are valid")
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
        Self(err.without_url().to_string())
    }
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
