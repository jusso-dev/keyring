//! The docs quote limits and settings from the code. These tests fail when
//! one side changes without the other (#169). They read the files at build
//! time, so they need no network and no Azure.

use std::time::Duration;

const README: &str = include_str!("../README.md");
const ARCHITECTURE: &str = include_str!("../docs/architecture.md");
const DEPLOY: &str = include_str!("../docs/deploy.md");
const TROUBLESHOOTING: &str = include_str!("../docs/troubleshooting.md");
const CHECKLIST: &str = include_str!("../docs/real-vault-checklist.md");

fn minutes(d: Duration) -> u64 {
    d.as_secs() / 60
}

fn has(doc: &str, name: &str, text: &str) {
    assert!(doc.contains(text), "{name} should say: {text}");
}

#[test]
fn server_limits_match_the_architecture_doc() {
    use keyring::serve::{CLOSE_GRACE, HEADER_READ_TIMEOUT, MAX_CONNECTION_AGE, MAX_CONNECTIONS};
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("At most {MAX_CONNECTIONS} connections at once"),
    );
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!(
            "asked to close after {} minutes and cut off {} minutes later",
            minutes(MAX_CONNECTION_AGE),
            minutes(CLOSE_GRACE)
        ),
    );
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!(
            "Request headers must arrive within {} seconds",
            HEADER_READ_TIMEOUT.as_secs()
        ),
    );
}

#[test]
fn body_limits_match_the_architecture_doc() {
    use keyring::routes::{MAX_FORM_BYTES, MAX_VALUE_FORM_BYTES};
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("{} KB body limit on forms", MAX_FORM_BYTES / 1024),
    );
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!(
            "{} KB on the two forms that carry a secret value",
            MAX_VALUE_FORM_BYTES / 1024
        ),
    );
}

#[test]
fn session_timings_match_the_docs() {
    use keyring::auth::crypto::MAX_SEALED_AGE;
    use keyring::auth::session::{ABSOLUTE_TIMEOUT, IDLE_TIMEOUT, SWEEP_INTERVAL};
    assert_eq!(
        IDLE_TIMEOUT,
        Duration::from_secs(60 * 60),
        "docs say one hour idle"
    );
    let hours = ABSOLUTE_TIMEOUT.as_secs() / 3600;
    has(README, "README", &format!("{hours} hours after sign-in"));
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("an hour idle or {hours} hours in total"),
    );
    assert_eq!(SWEEP_INTERVAL, Duration::from_secs(60));
    has(ARCHITECTURE, "architecture.md", "every minute");
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("({} minutes for sign-in", minutes(MAX_SEALED_AGE)),
    );
}

#[test]
fn sign_in_metadata_timings_match_the_architecture_doc() {
    use keyring::auth::oidc::{METADATA_RETRY_AFTER, METADATA_TTL};
    assert_eq!(METADATA_TTL, Duration::from_secs(60 * 60));
    has(
        ARCHITECTURE,
        "architecture.md",
        "metadata and signing keys are cached for an hour",
    );
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!(
            "waits {} seconds before trying again",
            METADATA_RETRY_AFTER.as_secs()
        ),
    );
}

#[test]
fn azure_message_cap_matches_the_docs() {
    let cap = keyring::routes::error::MAX_AZURE_MESSAGE;
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("cut to {cap} characters"),
    );
    has(
        TROUBLESHOOTING,
        "troubleshooting.md",
        &format!("cut to {cap} characters"),
    );
}

#[test]
fn static_file_caching_matches_the_architecture_doc() {
    use keyring::routes::assets::{CACHE_UNVERSIONED, CACHE_VERSIONED};
    assert_eq!(CACHE_VERSIONED, "public, max-age=31536000, immutable");
    has(
        ARCHITECTURE,
        "architecture.md",
        "cached for a year (`immutable`)",
    );
    assert_eq!(CACHE_UNVERSIONED, "public, max-age=300");
    has(ARCHITECTURE, "architecture.md", "a five-minute cache");
}

#[test]
fn config_rules_match_the_readme() {
    use keyring::config::{LOG_LEVELS, MIN_SESSION_SECRET_LEN};
    has(
        README,
        "README",
        &format!("At least {MIN_SESSION_SECRET_LEN} random characters"),
    );
    let listed = format!(
        "`{}`, `{}`, `{}` (default), `{}` or `{}`",
        LOG_LEVELS[0], LOG_LEVELS[1], LOG_LEVELS[2], LOG_LEVELS[3], LOG_LEVELS[4]
    );
    has(README, "README", &listed);
    assert!(!LOG_LEVELS.contains(&"off"));
    has(README, "README", "including `off`");
    has(DEPLOY, "deploy.md", "including `off`");
    use keyring::config::{DEFAULT_STALE_AFTER_DAYS, MAX_STALE_AFTER_DAYS};
    has(
        README,
        "README",
        &format!("from 1 to {MAX_STALE_AFTER_DAYS}, default {DEFAULT_STALE_AFTER_DAYS}"),
    );
}

#[test]
fn the_real_vault_checklist_is_linked_and_covers_each_area() {
    has(README, "README", "(docs/real-vault-checklist.md)");
    has(DEPLOY, "deploy.md", "(real-vault-checklist.md)");
    has(ARCHITECTURE, "architecture.md", "(real-vault-checklist.md)");
    for section in [
        "## Sign-in and tokens",
        "## Secrets",
        "## Certificates",
        "## Keys",
        "## Expiry and audit",
        "## Deployment",
        "## In the browser",
    ] {
        has(CHECKLIST, "real-vault-checklist.md", section);
    }
}

/// Relative links between the docs point at files that exist. The CI step
/// "Docs point at real source files" covers `src/` paths in backticks.
#[test]
fn relative_doc_links_point_at_files_that_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = [
        ("README.md", README, root.to_path_buf()),
        ("docs/architecture.md", ARCHITECTURE, root.join("docs")),
        ("docs/deploy.md", DEPLOY, root.join("docs")),
        (
            "docs/troubleshooting.md",
            TROUBLESHOOTING,
            root.join("docs"),
        ),
        ("docs/real-vault-checklist.md", CHECKLIST, root.join("docs")),
    ];
    for (name, text, base) in docs {
        for (start, _) in text.match_indices("](") {
            let rest = &text[start + 2..];
            let Some(end) = rest.find(')') else { continue };
            let target = &rest[..end];
            if target.contains("://") || target.starts_with('#') || target.starts_with("mailto:") {
                continue;
            }
            let file = target.split('#').next().unwrap_or_default();
            assert!(
                base.join(file).exists(),
                "{name} links to {target}, which doesn't exist"
            );
        }
    }
}

#[test]
fn search_limits_match_the_architecture_doc() {
    use keyring::auth::session::LIST_TTL;
    use keyring::routes::search::{MAX_QUERY_CHARS, MAX_RESULTS};
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("capped at {MAX_QUERY_CHARS} characters, and the page at {MAX_RESULTS} results"),
    );
    has(
        ARCHITECTURE,
        "architecture.md",
        &format!("kept in the session for {} seconds", LIST_TTL.as_secs()),
    );
    has(CHECKLIST, "real-vault-checklist.md", "within 60 seconds");
}

#[test]
fn audit_actions_and_reasons_are_in_the_deploy_doc() {
    use keyring::audit::{Action, Refusal};
    for a in Action::ALL {
        has(DEPLOY, "deploy.md", &format!("`{}`", a.as_str()));
    }
    for r in Refusal::ALL {
        has(DEPLOY, "deploy.md", &format!("`{}`", r.as_str()));
    }
    has(
        DEPLOY,
        "deploy.md",
        &format!("cut to {} characters", keyring::audit::MAX_USER_AGENT),
    );
    has(README, "README.md", "`KEYRING_TRUSTED_PROXY_HOPS`");
}

/// Bold names in docs/guides/ that aren't in templates/, each with the file
/// that puts it on the page instead. Everything else in bold must be in a
/// template, so renaming a button or a heading fails here until the
/// walkthrough says the new name.
const BOLD_NOT_IN_TEMPLATES: &[(&str, &str)] = &[
    // Added to the page by Keyring's scripts: the idle notice and the pins.
    ("Stay signed in", "static/app.js"),
    ("Recently opened", "static/pins.js"),
    // Headings of error and result pages, passed to error.html or
    // pim/result.html from the handlers in src/routes/.
    ("Auditing is unavailable", "src/routes/audit_gate.rs"),
    ("Can't reach this vault", "src/routes/error.rs"),
    ("Confirm it's you", "src/routes/step_up.rs"),
    (
        "Key Vault couldn't do that right now",
        "src/routes/error.rs",
    ),
    ("Microsoft sign-in said no", "src/routes/error.rs"),
    ("No certificate yet", "src/routes/certs/download.rs"),
    ("Permanent delete is turned off", "src/routes/lifecycle.rs"),
    ("Please sign in again", "src/routes/error.rs"),
    ("Role turned on", "src/routes/pim.rs"),
    ("That didn't go through", "src/routes/error.rs"),
    ("That import has expired", "src/routes/secrets/import.rs"),
    ("That version is disabled", "src/routes/secrets/versions.rs"),
    (
        "That's already the current version",
        "src/routes/secrets/versions.rs",
    ),
    ("The name didn't match", "src/routes/confirm.rs"),
    ("The number didn't match", "src/routes/bulk.rs"),
    (
        "The private key can't be downloaded",
        "src/routes/certs/download.rs",
    ),
    (
        "This secret changed since you opened it",
        "src/routes/secrets/edit.rs",
    ),
    ("You don't have access", "src/routes/error.rs"),
    ("You switched vaults", "src/routes/error.rs"),
    (
        "Your organisation needs to approve Keyring",
        "src/routes/error.rs",
    ),
    // Labels Keyring fills into a template from Rust: secret types and
    // their fields (src/secret_types.rs), expiry groups (src/expiry.rs),
    // age bands (src/age.rs), health checks (src/health.rs), audit ranges
    // (src/azure/audit.rs) and the reports across vaults
    // (src/azure/audit_across.rs).
    ("Login", "src/secret_types.rs"),
    ("Database", "src/secret_types.rs"),
    ("SSH private key", "src/secret_types.rs"),
    ("URL", "src/secret_types.rs"),
    ("Username", "src/secret_types.rs"),
    ("Notes", "src/secret_types.rs"),
    ("Server", "src/secret_types.rs"),
    ("Endpoint", "src/secret_types.rs"),
    ("Host", "src/secret_types.rs"),
    ("Passphrase", "src/secret_types.rs"),
    ("Next 7 days", "src/expiry.rs"),
    ("8 to 30 days", "src/expiry.rs"),
    ("31 to 90 days", "src/expiry.rs"),
    ("More than 90 days", "src/expiry.rs"),
    ("No expiry set", "src/expiry.rs"),
    ("Under 90 days", "src/age.rs"),
    ("90 to 180 days", "src/age.rs"),
    ("180 to 365 days", "src/age.rs"),
    ("Over a year", "src/age.rs"),
    ("Network access", "src/health.rs"),
    ("Private endpoint", "src/health.rs"),
    ("Secret expiry", "src/health.rs"),
    ("Key rotation", "src/health.rs"),
    ("Last hour", "src/azure/audit.rs"),
    ("Last 24 hours", "src/azure/audit.rs"),
    ("Last 7 days", "src/azure/audit.rs"),
    ("Last 30 days", "src/azure/audit.rs"),
    ("Secret values read", "src/azure/audit_across.rs"),
    ("Private keys downloaded", "src/azure/audit_across.rs"),
    (
        "Deletes, purges and recoveries",
        "src/azure/audit_across.rs",
    ),
    ("Refused requests", "src/azure/audit_across.rs"),
    ("Activity by one person", "src/azure/audit_across.rs"),
    // Subjects of the health emails, built in src/notify/health.rs.
    ("Keyring's audit sink is failing", "src/notify/health.rs"),
    ("Keyring's audit sink has recovered", "src/notify/health.rs"),
    (
        "Many refused requests in a short time",
        "src/notify/health.rs",
    ),
    (
        "Keyring's client secret expires soon",
        "src/notify/health.rs",
    ),
    (
        "Keyring's client secret has expired",
        "src/notify/health.rs",
    ),
];

/// Every bold name in the walkthroughs (docs/guides/) is a button, field,
/// link or heading Keyring shows. Most are in templates/; the rest are in
/// the allow list above, and each of those must still be in the file it
/// names, so a rename there fails too.
#[test]
fn bold_names_in_the_walkthroughs_are_on_a_page() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut templates = String::new();
    let mut stack = vec![root.join("templates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                templates.push_str(&std::fs::read_to_string(&path).unwrap());
            }
        }
    }
    // Templates escape apostrophes in text, so compare with them plain.
    let templates = templates.replace("&#39;", "'");
    let bold = regex::Regex::new(r"\*\*([^*]+)\*\*").unwrap();
    let mut guides: Vec<_> = std::fs::read_dir(root.join("docs/guides"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    guides.sort();
    assert!(guides.len() >= 16, "the sixteen walkthroughs, 00 to 15");
    let mut missing = Vec::new();
    for path in &guides {
        let text = std::fs::read_to_string(path).unwrap();
        for cap in bold.captures_iter(&text) {
            let name = &cap[1];
            if templates.contains(name) || BOLD_NOT_IN_TEMPLATES.iter().any(|(n, _)| *n == name) {
                continue;
            }
            missing.push(format!("{}: {name}", path.display()));
        }
    }
    assert!(
        missing.is_empty(),
        "bold names in the walkthroughs that no template shows (rename them, \
         or add them to BOLD_NOT_IN_TEMPLATES with the file that shows them):\n{}",
        missing.join("\n")
    );
    for (name, file) in BOLD_NOT_IN_TEMPLATES {
        let source = std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|_| panic!("{file}, named for {name}, doesn't exist"));
        assert!(
            source.contains(name),
            "{file} no longer says {name}: update the walkthroughs and the allow list"
        );
    }
}
