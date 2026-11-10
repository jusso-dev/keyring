use std::process::ExitCode;

use keyring::config::Config;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Keyring can't start: {err}");
            return ExitCode::FAILURE;
        }
    };

    keyring::telemetry::init(&config.log_level);
    keyring::telemetry::quiet_panics();

    for name in config.test_overrides() {
        tracing::warn!(
            variable = name,
            "a test-only override is set; user tokens go to the host it names, not to Microsoft. Unset it outside the test suite"
        );
    }

    // Build everything that can fail before binding, so "keyring listening"
    // means Keyring really is ready.
    let listen = config.listen;
    let state = match keyring::AppState::try_new(config) {
        Ok(state) => state,
        Err(err) => {
            tracing::error!(error = %err, "could not set up the outbound HTTPS client; check SSL_CERT_FILE and the system trust store");
            return ExitCode::FAILURE;
        }
    };
    keyring::auth::session::spawn_sweeper(state.sessions.clone());

    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(addr = %listen, error = %err, "could not bind listen address");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %listen, "keyring listening");

    let app = keyring::app(state);
    if let Err(err) = keyring::serve::serve(listener, app, shutdown_signal()).await {
        tracing::error!(error = %err, "server error");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Resolves on Ctrl-C or SIGTERM. If a handler can't be registered, that
/// one never resolves, so a failed registration can't shut the server down.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "could not listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}
