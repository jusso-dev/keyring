//! Read Microsoft Defender for Key Vault through Azure Resource Graph, as
//! the signed-in person: each subscription's `KeyVaults` plan, and the
//! security alerts Defender raised on Key Vaults in the last
//! [`ALERT_DAYS`] days.
//!
//! Both are in the `securityresources` table. Resource Graph only returns
//! rows the person can read, so someone without Security Reader (or Reader)
//! on a subscription sees no plan row and no alerts for it. That is shown
//! as Unknown, never as "no alerts". Nothing here is stored or logged.

use serde::Deserialize;

use crate::auth::session::Session;
use crate::azure::vaults::run_query;
use crate::azure::{AzureClient, AzureError};
use crate::defender::{ALERT_DAYS, Defender, MAX_ALERTS, RawAlert};

/// Each subscription's Defender for Key Vault plan.
pub const PLANS_QUERY: &str = "securityresources \
| where type =~ 'microsoft.security/pricings' and name =~ 'KeyVaults' \
| project subscriptionId, pricingTier = tostring(properties.pricingTier)";

/// Defender alerts on Key Vaults: alert types `KV_*`, or any alert whose
/// resource identifiers name a vault. Newest first, at most [`MAX_ALERTS`].
pub fn alerts_query() -> String {
    format!(
        "securityresources \
| where type =~ 'microsoft.security/locations/alerts' \
| extend p = properties \
| extend alertType = tostring(p.alertType), ids = p.resourceIdentifiers, t = todatetime(p.timeGeneratedUtc) \
| where t > ago({ALERT_DAYS}d) \
| where alertType startswith 'KV_' or tostring(ids) contains 'microsoft.keyvault/vaults' \
| order by t desc \
| take {MAX_ALERTS} \
| project subscriptionId, alertType, displayName = tostring(p.alertDisplayName), \
severity = tostring(p.severity), status = tostring(p.status), \
timeGenerated = tostring(p.timeGeneratedUtc), intent = tostring(p.intent), \
compromisedEntity = tostring(p.compromisedEntity), alertUri = tostring(p.alertUri), \
resourceIdentifiers = ids"
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanRow {
    #[serde(default)]
    subscription_id: String,
    #[serde(default)]
    pricing_tier: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlertRow {
    #[serde(default)]
    subscription_id: Option<String>,
    #[serde(default)]
    alert_type: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    time_generated: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    compromised_entity: Option<String>,
    #[serde(default)]
    alert_uri: Option<String>,
    #[serde(default)]
    resource_identifiers: Option<serde_json::Value>,
}

impl From<AlertRow> for RawAlert {
    fn from(r: AlertRow) -> Self {
        Self {
            subscription_id: r.subscription_id.unwrap_or_default(),
            alert_type: r.alert_type.unwrap_or_default(),
            display_name: r.display_name.unwrap_or_default(),
            severity: r.severity.unwrap_or_default(),
            status: r.status.unwrap_or_default(),
            time_generated: r.time_generated.unwrap_or_default(),
            intent: r.intent.unwrap_or_default(),
            compromised_entity: r.compromised_entity.unwrap_or_default(),
            alert_uri: r.alert_uri.unwrap_or_default(),
            resource_identifiers: r.resource_identifiers,
        }
    }
}

/// Plain words for a failed Resource Graph read of Defender's tables.
pub fn reason(e: &AzureError) -> String {
    match e {
        AzureError::Status { status: 403, .. } => {
            "You don't have Security Reader or Reader where Defender for Cloud keeps it".into()
        }
        AzureError::Status { status: 429, .. } => {
            "Azure was throttling requests. Try again in a minute".into()
        }
        AzureError::Network(_) => "Couldn't reach Azure Resource Graph".into(),
        AzureError::Token(_) => "Sign-in needs refreshing".into(),
        _ => "Azure Resource Graph returned an error".into(),
    }
}

/// Defender plans and alerts, each kept or failed on its own.
pub async fn read(azure: &AzureClient, session: &Session, management_url: &str) -> Defender {
    let alerts_q = alerts_query();
    let (plans, alerts) = tokio::join!(
        run_query::<PlanRow>(azure, session, management_url, PLANS_QUERY),
        run_query::<AlertRow>(azure, session, management_url, &alerts_q),
    );
    let plans = plans
        .map(|rows| {
            rows.into_iter()
                .map(|r| (r.subscription_id, r.pricing_tier.unwrap_or_default()))
                .collect()
        })
        .map_err(|e| reason(&e));
    let alerts = alerts
        .map(|rows| rows.into_iter().map(RawAlert::from).collect())
        .map_err(|e| reason(&e));
    Defender::from_rows(plans, alerts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_read_only_the_security_tables() {
        assert!(PLANS_QUERY.starts_with("securityresources"));
        assert!(PLANS_QUERY.contains("'KeyVaults'"));
        let q = alerts_query();
        assert!(q.starts_with("securityresources"));
        assert!(q.contains("microsoft.security/locations/alerts"));
        assert!(q.contains("ago(90d)") && q.contains("take 1000"));
        assert!(q.contains("startswith 'KV_'"));
    }
}
