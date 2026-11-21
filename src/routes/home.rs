use askama::Template;
use axum::extract::State;
use axum::response::Html;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::executive::{OrgSnapshot, ReportScope};
use crate::routes::assets::render;
use crate::routes::reports::load_org_snapshot;
use crate::routes::shell::{Section, Shell};

#[derive(Template)]
#[template(path = "home.html")]
struct HomePage {
    shell: Shell,
    allow_purge: bool,
    sections: [Section; 12],
    snapshot: Option<OrgSnapshot>,
}

pub(super) async fn index(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
) -> Html<String> {
    // Load live organisation-wide metadata stats for the signed-in user.
    // If Resource Graph isn't reachable (or returns no vaults), degrade
    // cleanly so Home always renders without blocking access to sections.
    let snapshot = load_org_snapshot(&state, &session, ReportScope::All)
        .await
        .ok()
        .filter(OrgSnapshot::has_vaults);

    render(&HomePage {
        shell: shell.at(Section::Home),
        allow_purge: state.config.allow_purge,
        sections: Section::NAV,
        snapshot,
    })
}
