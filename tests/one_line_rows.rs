//! Every data table is one line per row, whatever the data. Real tenants
//! have long sign-in names, item names and descriptions, so the rule rests
//! on cell classes, not on short demo values: times sit in a `<time>` in a
//! nowrap cell, and free text in a `span.clip` cut with an ellipsis. Also
//! checks Keyring activity's plain action labels.

mod support;

use axum::http::StatusCode;
use keyring::audit::Action;
use serde_json::{Value, json};

const UPN: &str = "kr-e2e-colleague-1118@yumait.au";
const LONG_NAME: &str = "payments-gateway-settlement-db-password";
const LONG_NOTE: &str = "Connection string for the nightly settlement job that reconciles card payments with the bank file";

/// The cells of the first body row of the table with this caption id.
fn first_row<'a>(html: &'a str, caption_id: &str) -> Vec<&'a str> {
    let at = html
        .find(&format!("id=\"{caption_id}\""))
        .unwrap_or_else(|| panic!("no table {caption_id}"));
    // The table that holds this caption carries the one-line rule.
    let table = html[..at].rfind("<table").unwrap();
    let open = &html[table..table + html[table..].find('>').unwrap()];
    assert!(
        open.contains("one-line"),
        "{caption_id}: the table isn't one-line: {open}"
    );
    let body = &html[at..];
    let body = &body[body.find("<tbody>").unwrap()..];
    let row = &body[..body.find("</tr>").unwrap()];
    // Cells start at `<td` or `<th`, never at a `<time` inside one.
    let mut starts: Vec<usize> = row
        .match_indices("<td")
        .chain(row.match_indices("<th"))
        .map(|(i, _)| i)
        .collect();
    starts.sort_unstable();
    starts
        .iter()
        .enumerate()
        .map(|(n, &i)| &row[i..starts.get(n + 1).copied().unwrap_or(row.len())])
        .collect()
}

/// The header cells of the table with this caption id.
fn heads<'a>(html: &'a str, caption_id: &str) -> Vec<&'a str> {
    let at = html.find(&format!("id=\"{caption_id}\"")).unwrap();
    let head = &html[at..];
    let head = &head[..head.find("</thead>").unwrap()];
    head.split("<th scope=\"col\"").skip(1).collect()
}

fn col<'a>(html: &'a str, caption_id: &str, name: &str) -> &'a str {
    let i = heads(html, caption_id)
        .iter()
        .position(|h| h.contains(&format!(">{name}</th>")))
        .unwrap_or_else(|| panic!("{caption_id}: no column {name}"));
    first_row(html, caption_id)[i]
}

fn clipped(cell: &str, what: &str) {
    assert!(
        cell.contains(" clip clip-") || cell.contains("\"clip clip-"),
        "{what} isn't cut: {cell}"
    );
}

fn timed(cell: &str, what: &str) {
    assert!(
        cell.contains("class=\"cell-time\"") || cell.contains("class=\"nowrap"),
        "{what} can wrap: {cell}"
    );
}

#[tokio::test]
async fn list_columns_stay_on_one_line() {
    let w = support::world().await;
    let n = keyring::azure::secrets::now_ts();
    w.kv.state.put_with(LONG_NAME, "x", |v| {
        v.content_type = Some("application/vnd.example.settlement+json".into());
        v.exp = Some(n + 40 * 86_400);
        v.tags.insert("description".into(), LONG_NOTE.into());
        v.tags.insert("owner".into(), UPN.into());
    });
    w.kv.state.add_key_with(LONG_NAME, "RSA", |v| {
        v.tags.insert("description".into(), LONG_NOTE.into());
        v.tags.insert("owner".into(), UPN.into());
    });
    for (path, caption) in [
        ("/v/kv-test/secrets", "secret-table-caption"),
        ("/v/kv-test/keys", "key-table-caption"),
    ] {
        let (status, html) = w.page(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        clipped(col(&html, caption, "Name"), "name");
        clipped(col(&html, caption, "Description"), "description");
        clipped(col(&html, caption, "Owner"), "owner");
        timed(col(&html, caption, "Expires"), "expiry");
        // The whole note is still in the page for a screen reader.
        assert!(html.contains(LONG_NOTE), "{path}");
        // Lower-priority columns give way first on a narrow screen.
        assert!(
            html.contains("<th scope=\"col\" class=\"col-p2\">Description</th>"),
            "{path}"
        );
        // No Tags column: they're on each item's page, so rows fit at 1440.
        assert!(!html.contains(">Tags</th>"), "{path}");
    }
    let (_, html) = w.page("/v/kv-test/secrets").await;
    clipped(col(&html, "secret-table-caption", "Content type"), "type");
    timed(
        col(&html, "secret-table-caption", "Value changed"),
        "value changed",
    );
    assert!(html.contains("<th scope=\"col\" class=\"col-p3\">Content type</th>"));
}

#[tokio::test]
async fn vault_list_owners_stay_on_one_line() {
    let w = support::world().await;
    let mut row = support::vault_row("kv-test", "sub-a", true);
    row["tags"] = json!({"keyring-owners": UPN});
    *w.arm.state.vaults.lock().unwrap() = vec![row];
    let (_, html) = w.page("/vaults").await;
    clipped(col(&html, "vault-table-caption", "Owners"), "owners");
    assert!(col(&html, "vault-table-caption", "Name").contains("nowrap"));
}

#[tokio::test]
async fn key_vault_audit_rows_stay_on_one_line() {
    let w = support::world().await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    *w.arm.state.diagnostics.lock().unwrap() = Some(support::audit_settings(true));
    *w.arm.state.audit_rows.lock().unwrap() = vec![[
        "2026-11-18T05:22:09.123Z".into(),
        UPN.into(),
        "SecretGet".into(),
        LONG_NAME.into(),
        "OK".into(),
        "203.0.113.24".into(),
    ]];
    let (status, html) = w.page("/v/kv-test/audit").await;
    assert_eq!(status, StatusCode::OK);
    let when = col(&html, "audit-caption", "When (UTC)");
    timed(when, "when");
    assert!(
        when.contains("<time datetime=\"2026-11-18T05:22:09.123Z\">18 Nov 2026, 05:22</time>"),
        "{when}"
    );
    clipped(col(&html, "audit-caption", "Who"), "who");
    clipped(col(&html, "audit-caption", "Item"), "item");
    clipped(col(&html, "audit-caption", "What"), "what");
}

fn keyring_event(action: &str, upn: &str, outcome: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("TimeGenerated", json!("2026-11-18T05:22:09.456Z")),
        ("Vault", json!("kv-test")),
        ("Action", json!(action)),
        ("Outcome", json!(outcome)),
        ("ActorUpn", json!(upn)),
        ("ItemKind", json!("secret")),
        ("ItemName", json!(LONG_NAME)),
    ]
}

#[tokio::test]
async fn keyring_activity_rows_stay_on_one_line_with_plain_labels() {
    const WS: &str = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law";
    let w = support::world_with(&[("KEYRING_AUDIT_WORKSPACE_ID", WS)]).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    *w.arm.state.keyring_rows.lock().unwrap() = vec![
        keyring_event("secret.bulk_update", UPN, "success"),
        keyring_event("notify.sent", "", "success"),
    ];
    let (status, html) = w.page("/v/kv-test/audit/keyring").await;
    assert_eq!(status, StatusCode::OK);
    let when = col(&html, "keyring-caption", "When (UTC)");
    timed(when, "when");
    assert!(
        when.contains("<time datetime=\"2026-11-18T05:22:09.456Z\">18 Nov 2026, 05:22</time>"),
        "{when}"
    );
    clipped(col(&html, "keyring-caption", "Who"), "who");
    clipped(col(&html, "keyring-caption", "Item"), "item");
    let what = col(&html, "keyring-caption", "What");
    clipped(what, "what");
    // A plain label shows, not the code; the code stays in the markup.
    let bulk = Action::SecretBulkUpdate;
    assert_eq!(bulk.as_str(), "secret.bulk_update");
    assert!(
        what.contains(&format!(">{}</span>", bulk.label())),
        "{what}"
    );
    assert!(!what.contains(">secret.bulk_update<"), "{what}");
    assert!(what.contains("value=\"secret.bulk_update\""), "{what}");
    // Result is a badge, as everywhere else.
    assert!(
        col(&html, "keyring-caption", "Result")
            .contains("<span class=\"badge badge-ok\">Done</span>")
    );
    // No one signed in: Keyring, marked System.
    assert!(html.contains("Keyring <span class=\"badge badge-muted\">System</span>"));
    assert!(!html.contains("Nobody signed in"));
    // The filter offers each action by label, with its code.
    let sent = Action::NotifySent;
    assert_eq!(sent.as_str(), "notify.sent");
    assert!(html.contains(&format!(
        "<option value=\"notify.sent\">{} (notify.sent)</option>",
        sent.label()
    )));
}

/// Every action Keyring can write has a plain label, and no two share one.
#[test]
fn every_audit_action_has_a_label() {
    let mut seen = std::collections::HashSet::new();
    for a in Action::ALL {
        let label = a.label();
        assert!(!label.is_empty(), "{a} has no label");
        assert_ne!(label, a.as_str(), "{a}: the label is the code");
        assert!(!label.contains('.') && !label.contains('_'), "{a}: {label}");
        assert!(
            label.chars().next().is_some_and(char::is_uppercase),
            "{a}: {label}"
        );
        assert!(!label.contains('\u{2014}'), "{a}: no em dashes");
        assert!(seen.insert(label), "{a}: label {label} used twice");
        assert_eq!(Action::label_for(a.as_str()), Some(label));
    }
    assert_eq!(Action::label_for("not.an.action"), None);
}

fn reason_event(reason: &str, ticket: &str) -> Vec<(&'static str, Value)> {
    let mut e = keyring_event("share.grant", UPN, "refused");
    e.push(("Reason", json!(reason)));
    e.push(("Ticket", json!(ticket)));
    e
}

/// The reason and ticket are the point of the log, and this view is the
/// only place they show: a long reason opens in full, and the ticket has
/// its own column so the reason can never hide it.
#[tokio::test]
async fn keyring_activity_keeps_the_whole_reason_and_ticket_readable() {
    const WS: &str = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law";
    const LONG_REASON: &str = "Checking the settlement job's database login after the failed nightly run, before the bank file cut-off at noon";
    let w = support::world_with(&[("KEYRING_AUDIT_WORKSPACE_ID", WS)]).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    *w.arm.state.keyring_rows.lock().unwrap() = vec![reason_event(LONG_REASON, "INC-20418")];
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    let why = col(&html, "keyring-caption", "Why");
    assert!(why.contains("<details class=\"cell-more\">"), "{why}");
    assert!(
        why.contains(&format!("<p>{}</p>", LONG_REASON.replace('\'', "&#39;"))),
        "{why}"
    );
    let ticket = col(&html, "keyring-caption", "Ticket");
    assert!(ticket.contains(">INC-20418</td>"), "{ticket}");
    // The label doesn't claim the share happened; Result says it didn't.
    let what = col(&html, "keyring-caption", "What");
    assert!(what.contains(">Share secret</span>"), "{what}");
    assert!(col(&html, "keyring-caption", "Result").contains("Refused by Keyring"));

    // A short reason shows as it is, with no disclosure.
    *w.arm.state.keyring_rows.lock().unwrap() = vec![reason_event("Rotation check", "CHG-1")];
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    let why = col(&html, "keyring-caption", "Why");
    assert!(why.contains(">Rotation check</td>"), "{why}");
}

/// A time that isn't a whole UTC time is shown as it came, escaped, with
/// no `<time>`; an empty one says so.
#[tokio::test]
async fn unreadable_times_have_no_time_element() {
    const WS: &str = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law";
    let w = support::world_with(&[("KEYRING_AUDIT_WORKSPACE_ID", WS)]).await;
    *w.arm.state.vaults.lock().unwrap() = vec![support::vault_row("kv-test", "sub-a", true)];
    let mut odd = keyring_event("secret.reveal", UPN, "success");
    odd[0] = ("TimeGenerated", json!("2026-11-18T05:22:09+02:00<b>"));
    let mut empty = keyring_event("secret.reveal", UPN, "success");
    empty[0] = ("TimeGenerated", Value::Null);
    *w.arm.state.keyring_rows.lock().unwrap() = vec![odd];
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    let when = col(&html, "keyring-caption", "When (UTC)");
    assert!(!when.contains("<time"), "{when}");
    assert!(
        when.contains("2026-11-18T05:22:09+02:00&#60;b&#62;"),
        "{when}"
    );
    *w.arm.state.keyring_rows.lock().unwrap() = vec![empty];
    let (_, html) = w.page("/v/kv-test/audit/keyring").await;
    let when = col(&html, "keyring-caption", "When (UTC)");
    assert!(!when.contains("<time"), "{when}");
    assert!(when.contains("Not given"), "{when}");
}

/// Every owner address stays reachable when the cell is cut: more than
/// one, or a long one, opens in a disclosure with each link.
#[tokio::test]
async fn clipped_owners_and_resource_groups_open_in_full() {
    let w = support::world().await;
    let mut row = support::vault_row("kv-test", "sub-a", true);
    row["tags"] = json!({"keyring-owners": format!("{UPN}, ops@example.com")});
    row["resourceGroup"] =
        json!("rg-payments-settlement-reconciliation-production-australiaeast-001");
    *w.arm.state.vaults.lock().unwrap() = vec![row];
    let (_, html) = w.page("/vaults").await;
    let owners = col(&html, "vault-table-caption", "Owners");
    assert!(owners.contains("<details class=\"cell-more\">"), "{owners}");
    assert!(owners.contains("+1 more"), "{owners}");
    assert!(
        owners.contains("href=\"mailto:ops@example.com\""),
        "{owners}"
    );
    let rg = col(&html, "vault-table-caption", "Resource group");
    assert!(rg.contains("<details class=\"cell-more\">"), "{rg}");
    assert!(
        rg.contains("<p>rg-payments-settlement-reconciliation-production-australiaeast-001</p>"),
        "{rg}"
    );
}
