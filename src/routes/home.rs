use askama::Template;
use axum::extract::State;
use axum::response::Html;

use crate::AppState;
use crate::routes::assets::render;
use crate::routes::shell::{Section, Shell};

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    shell: Shell,
    allow_purge: bool,
    sections: [Section; 7],
}

pub(super) async fn index(State(state): State<AppState>, shell: Shell) -> Html<String> {
    render(&HomePage {
        shell: shell.at(Section::Home),
        allow_purge: state.config.allow_purge,
        sections: Section::NAV,
    })
}
