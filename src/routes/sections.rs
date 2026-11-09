//! Placeholder pages for sections that aren't built yet.

use askama::Template;
use axum::response::{IntoResponse, Response};

use crate::routes::assets::render;
use crate::routes::shell::{Section, Shell};

#[derive(Template)]
#[template(path = "coming_soon.html")]
struct ComingSoon {
    shell: Shell,
    title: &'static str,
    blurb: &'static str,
}

fn blurb(section: Section) -> &'static str {
    match section {
        Section::Vaults => "Every vault you can see, across all your subscriptions.",
        Section::Secrets => "Find, reveal, add and update secrets in a vault.",
        Section::Certificates => {
            "Upload, download and renew certificates, and see what's expiring."
        }
        Section::Keys => "Create, rotate and view keys. Key material never leaves Key Vault.",
        Section::Expiry => {
            "Secrets, certificates and keys that are about to expire, across your vaults."
        }
        Section::Generator => "Make strong passwords, GUIDs and API keys.",
        Section::Audit => "Who did what in a vault, from its diagnostic logs.",
        Section::Home => "",
    }
}

pub fn page(shell: Shell, section: Section) -> Response {
    render(&ComingSoon {
        shell: shell.at(section),
        title: section.label(),
        blurb: blurb(section),
    })
    .into_response()
}

macro_rules! placeholder {
    ($name:ident, $section:expr) => {
        pub async fn $name(shell: Shell) -> Response {
            page(shell, $section)
        }
    };
}

placeholder!(secrets, Section::Secrets);
placeholder!(certificates, Section::Certificates);
placeholder!(keys, Section::Keys);
placeholder!(expiry, Section::Expiry);
placeholder!(generator, Section::Generator);
placeholder!(audit, Section::Audit);
