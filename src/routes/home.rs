use std::time::Duration;

use askama::Template;
use axum::extract::State;
use axum::response::Html;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::executive::{OrgSnapshot, ReportScope};
use crate::routes::assets::render;
use crate::routes::reports::load_org_snapshot;
use crate::routes::shell::{Section, Shell};

/// Maximum time Home will wait for the live organisation snapshot before
/// rendering the navigation shell without charts. Shorter than the 60-second
/// report fan-out deadline and covers `list_vaults` as well.
const HOME_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(12);

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
    // Bounded by `HOME_SNAPSHOT_TIMEOUT` so stalled private vaults never hold
    // up the Home page; errors and timeouts are logged before degrading.
    let snapshot = match tokio::time::timeout(
        HOME_SNAPSHOT_TIMEOUT,
        load_org_snapshot(&state, &session, ReportScope::All),
    )
    .await
    {
        Ok(Ok(snap)) => Some(snap).filter(OrgSnapshot::has_vaults),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "home organisation snapshot failed; rendering without dashboard");
            None
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = HOME_SNAPSHOT_TIMEOUT.as_secs(),
                "home organisation snapshot timed out; rendering without dashboard"
            );
            None
        }
    };

    render(&HomePage {
        shell: shell.at(Section::Home),
        allow_purge: state.config.allow_purge,
        sections: Section::NAV,
        snapshot,
    })
}
