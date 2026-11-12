//! The vault list and the vault picker.

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::vaults::{self, Vault, VaultFilter};
use crate::routes::assets::render;
use crate::routes::error::{Need, NextStep, PageError, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::vault_path;

/// Vaults shown per page of the list.
pub(super) const PER_PAGE: usize = 200;

pub(super) struct SubscriptionOption {
    pub id: String,
    pub name: String,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "vaults/list.html")]
struct VaultList {
    shell: Shell,
    vaults: Vec<Vault>,
    total: usize,
    shown_from: usize,
    filter: VaultFilter,
    subscriptions: Vec<SubscriptionOption>,
    page: usize,
    pages: usize,
    prev_url: Option<String>,
    next_url: Option<String>,
    selected: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct ListQuery {
    #[serde(flatten)]
    #[serde(default)]
    filter: VaultFilter,
    #[serde(default)]
    page: Option<usize>,
}

fn page_url(filter: &VaultFilter, page: usize) -> String {
    let enc = crate::auth::return_to::encode;
    format!(
        "/vaults?q={}&subscription={}&tag={}&page={page}",
        enc(&filter.q),
        enc(&filter.subscription),
        enc(&filter.tag)
    )
}

pub(super) async fn list(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(query): Query<ListQuery>,
) -> Response {
    let shell = shell.at(Section::Vaults);
    let all =
        match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
            Ok(v) => v,
            Err(err) => {
                let problem = Problem::from_azure(&err, Need::ListVaults).returning_to("/vaults");
                return PageError::new(shell, problem).into_response();
            }
        };

    let mut subscriptions: Vec<SubscriptionOption> = Vec::new();
    for v in &all {
        if !subscriptions
            .iter()
            .any(|s| s.id.eq_ignore_ascii_case(&v.subscription_id))
        {
            subscriptions.push(SubscriptionOption {
                id: v.subscription_id.clone(),
                name: v.subscription_name.clone(),
                selected: v
                    .subscription_id
                    .eq_ignore_ascii_case(&query.filter.subscription),
            });
        }
    }
    subscriptions.sort_by_key(|s| s.name.to_lowercase());

    let total = all.len();
    let matching: Vec<Vault> = all
        .into_iter()
        .filter(|v| query.filter.matches(v))
        .collect();
    let pages = matching.len().div_ceil(PER_PAGE).max(1);
    let page = query.page.unwrap_or(1).clamp(1, pages);
    let shown_from = (page - 1) * PER_PAGE;
    let vaults: Vec<Vault> = matching
        .into_iter()
        .skip(shown_from)
        .take(PER_PAGE)
        .collect();

    let page_view = VaultList {
        selected: session.0.selected_vault(),
        prev_url: (page > 1).then(|| page_url(&query.filter, page - 1)),
        next_url: (page < pages).then(|| page_url(&query.filter, page + 1)),
        shell,
        vaults,
        total,
        shown_from,
        filter: query.filter,
        subscriptions,
        page,
        pages,
    };
    render(&page_view).into_response()
}

/// A bare vault page such as `/secrets/x` gets the chosen vault in front.
/// Anything else (`/expiry`, an address that already names a vault) is left
/// as it is.
fn with_vault(vault: &str, path: &str) -> String {
    let scoped = ["/secrets", "/certificates", "/keys", "/audit"]
        .iter()
        .any(|base| {
            path.strip_prefix(base)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '.']))
        });
    if scoped {
        vault_path(vault, path)
    } else {
        path.to_owned()
    }
}

#[derive(Deserialize)]
pub(super) struct SelectForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    /// Where to go next. Local paths only; anything else goes to `/`.
    #[serde(default)]
    return_to: String,
}

/// Pick a vault. Only remembered in this session.
pub(super) async fn select(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Form(form): Form<SelectForm>,
) -> Response {
    if !session.0.csrf_matches_any(&form.csrf) {
        return PageError::new(shell, Problem::stale_form()).into_response();
    }
    let name = form.name.trim();
    if !vaults::is_valid_vault_name(name) {
        let problem = Problem::new(
            axum::http::StatusCode::BAD_REQUEST,
            "That isn't a vault name",
            "Pick a vault from the list.",
        )
        .returning_to("/vaults");
        return PageError::new(shell, problem).into_response();
    }
    // Only a vault the user can actually see. A stale form, a vault deleted
    // since the list was shown or a hand-made post would otherwise leave a
    // name that every page reports as unreachable.
    let all =
        match vaults::list_vaults(&state.azure, &session.0, &state.config.management_url).await {
            Ok(v) => v,
            Err(err) => {
                let problem = Problem::from_azure(&err, Need::ListVaults).returning_to("/vaults");
                return PageError::new(shell, problem).into_response();
            }
        };
    let Some(vault) = all.into_iter().find(|v| v.name.eq_ignore_ascii_case(name)) else {
        let problem = Problem::new(
            axum::http::StatusCode::NOT_FOUND,
            "That vault isn't in your list",
            "Keyring can't find a vault with that name among the ones you can see. It may have been deleted, or you may have lost access. Pick a vault from the list.",
        )
        .with_next(NextStep::Go {
            url: "/vaults".into(),
            label: "Choose a vault",
        });
        return PageError::new(shell, problem).into_response();
    };
    let name = vault.name;
    // Kept with the name so the audit view doesn't need to look it up.
    session.0.select_vault_with_id(name.clone(), vault.id);
    let next = if form.return_to.is_empty() {
        vault_path(&name, "/secrets")
    } else {
        with_vault(
            &name,
            &crate::auth::return_to::sanitise(Some(&form.return_to)),
        )
    };
    let mut res = Redirect::to(&next).into_response();
    flash::set(
        &state,
        &mut res,
        &Flash::success(format!("Now working in {name}.")),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_vault_page_gets_the_chosen_vault() {
        for (given, want) in [
            ("/secrets", "/v/kv/secrets"),
            ("/secrets/db", "/v/kv/secrets/db"),
            ("/audit?item=db", "/v/kv/audit?item=db"),
            ("/audit.csv", "/v/kv/audit.csv"),
            ("/certificates/-/new", "/v/kv/certificates/-/new"),
            ("/keys/k", "/v/kv/keys/k"),
            ("/expiry", "/expiry"),
            ("/", "/"),
            ("/secretsx", "/secretsx"),
            ("/v/other/secrets", "/v/other/secrets"),
        ] {
            assert_eq!(with_vault("kv", given), want, "{given}");
        }
    }
}
