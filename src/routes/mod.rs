//! HTTP routes.

mod assets;
mod health;
mod home;

use axum::Router;
use axum::routing::get;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(home::index))
        .route("/healthz", get(health::healthz))
        .route("/static/{file}", get(assets::serve))
}
