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
