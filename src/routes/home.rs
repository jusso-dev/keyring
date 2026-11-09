use askama::Template;
use axum::extract::State;
use axum::response::Html;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::routes::assets::render;
use crate::routes::shell::Shell;

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    shell: Shell,
    allow_purge: bool,
}

pub async fn index(State(state): State<AppState>, session: CurrentSession) -> Html<String> {
    render(&HomePage {
        shell: Shell::for_session(&session),
        allow_purge: state.config.allow_purge,
    })
}
