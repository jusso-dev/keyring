use askama::Template;
use axum::extract::State;
use axum::response::Html;

use crate::AppState;
use crate::routes::assets::render;

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    allow_purge: bool,
}

pub async fn index(State(state): State<AppState>) -> Html<String> {
    render(&HomePage {
        allow_purge: state.config.allow_purge,
    })
}
