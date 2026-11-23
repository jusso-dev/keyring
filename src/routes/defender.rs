//! Defender alerts: Microsoft Defender for Key Vault's plan on each
//! subscription the person's vaults are in, and its alerts on Key Vaults,
//! with a CSV. Read-only, from Resource Graph, as the signed-in person.

use std::collections::{BTreeMap, HashMap};

use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::defender as azure_defender;
use crate::azure::vaults::{self, Vault};
use crate::defender::{
    ALERT_DAYS, Alert, Defender, MAX_ALERTS, PlanState, Severity, SeverityCounts, not_read_row,
    to_csv,
};
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::{Section, Shell};

#[derive(Debug, Default, Deserialize, Clone)]
pub(super) struct DefenderFilter {
    /// One vault, or empty for all.
    #[serde(default)]
    pub vault: String,
    /// A severity slug, or empty for all.
    #[serde(default)]
    pub severity: String,
    /// `open` (the default), or `all` to include resolved and dismissed.
    #[serde(default)]
    pub status: String,
}

impl DefenderFilter {
    fn all_statuses(&self) -> bool {
        self.status == "all"
    }

    fn matches(&self, a: &Alert) -> bool {
        (self.all_statuses() || a.status.is_open())
            && (self.severity.is_empty() || a.severity.slug() == self.severity)
            && (self.vault.is_empty()
                || a.vault
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(&self.vault)))
    }

    fn query(&self) -> String {
        let enc = crate::auth::return_to::encode;
        format!(
            "vault={}&severity={}&status={}",
            enc(&self.vault),
            enc(&self.severity),
            enc(&self.status)
        )
    }
}

/// One subscription's plan, for the coverage table.
pub(super) struct PlanRow {
    pub subscription: String,
    pub vaults: usize,
    pub plan: PlanState,
}

pub(super) struct AlertRow {
    pub alert: Alert,
    /// The vault, if the person can see it, so the name can be a link.
    pub vault_link: Option<String>,
    pub subscription: String,
}

struct Loaded {
    defender: Defender,
    vaults: Vec<Vault>,
    sub_names: HashMap<String, String>,
}

async fn load(state: &AppState, session: &CurrentSession) -> Result<Loaded, AzureError> {
    let (vault_list, defender) = tokio::join!(
        vaults::list_vaults(&state.azure, &session.0, &state.config.management_url),
        azure_defender::read(&state.azure, &session.0, &state.config.management_url),
    );
    let vaults = vault_list?;
    let sub_names = vaults
        .iter()
        .map(|v| {
            (
                v.subscription_id.to_ascii_lowercase(),
                if v.subscription_name.is_empty() {
                    v.subscription_id.clone()
                } else {
                    v.subscription_name.clone()
                },
            )
        })
        .collect();
    Ok(Loaded {
        defender,
        vaults,
        sub_names,
    })
}

fn plan_rows(l: &Loaded) -> Vec<PlanRow> {
    let mut by_sub: BTreeMap<String, (String, usize)> = BTreeMap::new();
    for v in &l.vaults {
        let id = v.subscription_id.to_ascii_lowercase();
        let name = l.sub_names.get(&id).cloned().unwrap_or_else(|| id.clone());
        by_sub.entry(id).or_insert((name, 0)).1 += 1;
    }
    let mut rows: Vec<PlanRow> = by_sub
        .into_iter()
        .map(|(id, (subscription, vaults))| PlanRow {
            plan: l.defender.plan_for(&id),
            subscription,
            vaults,
        })
        .collect();
    rows.sort_by(|a, b| a.subscription.cmp(&b.subscription));
    rows
}

#[derive(Template)]
#[template(path = "defender.html")]
struct DefenderPage {
    shell: Shell,
    plans: Vec<PlanRow>,
    plans_error: Option<String>,
    alerts_error: Option<String>,
    rows: Vec<AlertRow>,
    open: SeverityCounts,
    plans_off: usize,
    plans_unknown: usize,
    vault_names: Vec<String>,
    severities: [Severity; 4],
    filter: DefenderFilter,
    csv_url: String,
    alert_days: u32,
    max_alerts: usize,
    capped: bool,
}

pub(super) async fn page(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<DefenderFilter>,
) -> PageResult {
    let shell = shell.at(Section::Defender);
    let loaded = match load(&state, &session).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell,
                Problem::from_azure(&e, Need::ListVaults).returning_to("/defender"),
            )
            .into());
        }
    };
    let plans = plan_rows(&loaded);
    let visible: HashMap<String, String> = loaded
        .vaults
        .iter()
        .map(|v| (v.name.to_ascii_lowercase(), v.name.clone()))
        .collect();
    let mut vault_names: Vec<String> = visible.values().cloned().collect();
    vault_names.sort();
    let (rows, capped) = match &loaded.defender.alerts {
        Ok(list) => (
            list.iter()
                .filter(|a| filter.matches(a))
                .map(|a| AlertRow {
                    vault_link: a.vault.as_ref().and_then(|v| visible.get(v).cloned()),
                    subscription: loaded
                        .sub_names
                        .get(&a.subscription_id)
                        .cloned()
                        .unwrap_or_else(|| a.subscription_id.clone()),
                    alert: a.clone(),
                })
                .collect(),
            list.len() >= MAX_ALERTS,
        ),
        Err(_) => (Vec::new(), false),
    };
    Ok(render(&DefenderPage {
        plans_off: plans.iter().filter(|p| p.plan == PlanState::Off).count(),
        plans_unknown: plans
            .iter()
            .filter(|p| matches!(p.plan, PlanState::Unknown(_)))
            .count(),
        plans_error: loaded.defender.plans.as_ref().err().cloned(),
        alerts_error: loaded.defender.alerts.as_ref().err().cloned(),
        open: loaded.defender.open_counts(),
        csv_url: format!("/defender.csv?{}", filter.query()),
        shell,
        plans,
        rows,
        vault_names,
        severities: Severity::ALL,
        filter,
        alert_days: ALERT_DAYS,
        max_alerts: MAX_ALERTS,
        capped,
    })
    .into_response())
}

pub(super) async fn csv(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Query(filter): Query<DefenderFilter>,
) -> PageResult {
    let loaded = match load(&state, &session).await {
        Ok(l) => l,
        Err(e) => {
            return Err(PageError::new(
                shell.at(Section::Defender),
                Problem::from_azure(&e, Need::ListVaults),
            )
            .into());
        }
    };
    let mut body = match &loaded.defender.alerts {
        Ok(list) => {
            let picked: Vec<Alert> = list.iter().filter(|a| filter.matches(a)).cloned().collect();
            let mut out = to_csv(&picked, &loaded.sub_names);
            if list.len() >= MAX_ALERTS {
                out.push_str(&not_read_row(&format!(
                    "Only the first {MAX_ALERTS} alerts were read, open ones first"
                )));
            }
            out
        }
        // The export says what it leaves out, so it can't pass for "no alerts".
        Err(why) => to_csv(&[], &loaded.sub_names) + &not_read_row(why),
    };
    for p in plan_rows(&loaded) {
        if let PlanState::Unknown(why) = &p.plan {
            body.push_str(&not_read_row(&format!(
                "Defender plan for {}: {why}",
                p.subscription
            )));
        }
    }
    let mut res: Response = (StatusCode::OK, body).into_response();
    let h = res.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"keyring-defender-alerts.csv\""),
    );
    Ok(no_store(res))
}
