//! "Edit details" for a certificate or a key: its description and tags.
//! Secrets have their own, fuller form (`secrets::edit`).
//!
//! Read, merge, write. The current version is read as the person, the form
//! is checked against it, and only `tags` is sent back, with
//! `PATCH /certificates/{name}/{version}` or `PATCH /keys/{name}/{version}`
//! on the person's on-behalf-of token. Every attribute, the policy and any
//! tag the form doesn't show are left as they are. If someone changed the
//! version since the form was opened, nothing is saved.
//!
//! The route is `audited(...)`, so the form token, the reason gate and the
//! audit event (`certificate.update`, `key.update`) are handled the same
//! way as every other change. The description is never logged or put in
//! the event.

use std::collections::BTreeMap;

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::certs::CertsApi;
use crate::azure::keys::KeysApi;
use crate::azure::secrets::{Attributes, UpdateProperties};
use crate::description;
use crate::routes::assets::render;
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::forms::FieldErrors;
use crate::routes::lifecycle::{Kind, redirect_with};
use crate::routes::secrets::form::with_note;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::Shell;
use crate::routes::tag_rows::{self, TagField, TagPost};
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, checked_name, vault_path};

/// What the form posts.
#[derive(Deserialize, Default)]
pub(crate) struct DetailsForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub description: String,
    /// The tag rows, without the description.
    #[serde(flatten)]
    pub tag_rows: TagPost,
    /// The version the form was opened on, and its `updated` time.
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub updated: String,
}

impl std::fmt::Debug for DetailsForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetailsForm")
            .field("version", &self.version)
            .field("tag_rows", &self.tag_rows)
            .finish_non_exhaustive()
    }
}

/// The current version, as far as this form is concerned.
pub(crate) struct Current {
    pub version: String,
    pub attributes: Attributes,
    pub tags: BTreeMap<String, String>,
}

impl Current {
    fn updated(&self) -> String {
        self.attributes
            .updated
            .map(|t| t.to_string())
            .unwrap_or_default()
    }
}

/// The tags to write, from the form and the current tags. `Ok(None)` when
/// nothing would change. Tags a row can't show are kept as they are.
pub(crate) fn new_tags(
    form: &DetailsForm,
    current: &BTreeMap<String, String>,
) -> Result<Option<BTreeMap<String, String>>, FieldErrors> {
    let mut errors = FieldErrors::new();
    let base = tag_rows::check(&form.tag_rows, current, &mut errors);
    let tags = with_note(&base, &form.description, &mut errors);
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok((tags != *current).then_some(tags))
}

#[derive(Template)]
#[template(path = "details.html")]
struct DetailsPage {
    shell: Shell,
    vault: String,
    kind: Kind,
    name: String,
    description: String,
    tags: TagField,
    version: String,
    updated: String,
    errors: FieldErrors,
}

impl DetailsPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

/// The form, filled from `current`, or from `posted` after an error.
#[allow(clippy::too_many_arguments)]
fn page(
    shell: Shell,
    vault: String,
    kind: Kind,
    name: String,
    current: &Current,
    posted: Option<&DetailsForm>,
    errors: FieldErrors,
    suggest: tag_rows::Suggestions,
) -> Response {
    let (description, tags) = match posted {
        Some(f) => (
            f.description.clone(),
            TagField::posted(&f.tag_rows, &current.tags),
        ),
        None => (
            description::of(&current.tags)
                .unwrap_or_default()
                .to_owned(),
            TagField::of(&current.tags),
        ),
    };
    let status = if errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    no_store(
        (
            status,
            render(&DetailsPage {
                shell,
                vault,
                kind,
                name,
                description,
                tags: tags.with(suggest),
                version: current.version.clone(),
                updated: current.updated(),
                errors,
            }),
        )
            .into_response(),
    )
}

/// The page for a form opened on an older version or `updated` time.
fn changed_problem(shell: Shell, vault: &str, kind: Kind, name: &str) -> Halt {
    PageError::new(
        shell,
        Problem::new(
            StatusCode::CONFLICT,
            match kind {
                Kind::Certificate => "This certificate changed since you opened it",
                _ => "This key changed since you opened it",
            },
            format!(
                "Someone saved a change to {name} after you opened the form, so nothing was saved. Open the form again to see the latest details, then make your change."
            ),
        )
        .returning_to(&kind.item_url(vault, name)),
    )
    .into()
}

/// One kind of item: how to read its current version and write its tags.
pub(crate) trait Editable: Send + Sync + 'static {
    const KIND: Kind;
    const READ: Need;
    const WRITE: Need;
    /// The current version, or the page to show instead.
    fn current(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
    ) -> impl Future<Output = Result<(Current, Shell), Halt>> + Send;
    /// `PATCH` the version with `tags` and nothing else.
    fn write(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        version: &str,
        tags: BTreeMap<String, String>,
    ) -> impl Future<Output = Result<(), AzureError>> + Send;
}

fn only_tags(tags: BTreeMap<String, String>) -> UpdateProperties {
    UpdateProperties {
        tags: Some(tags),
        ..UpdateProperties::default()
    }
}

pub(crate) struct Certificates;
pub(crate) struct Keys;

impl Editable for Certificates {
    const KIND: Kind = Kind::Certificate;
    const READ: Need = Need::ReadCertificates;
    const WRITE: Need = Need::ManageCertificates;

    async fn current(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
    ) -> Result<(Current, Shell), Halt> {
        match certs_api(state, session, vault).get_cert(name, None).await {
            Ok(b) => Ok((
                Current {
                    version: b.version().to_owned(),
                    attributes: b.attributes,
                    tags: b.tags.unwrap_or_default(),
                },
                shell,
            )),
            Err(e) => Err(azure_problem(
                shell,
                &e,
                Self::READ,
                &Self::KIND.item_url(vault, name),
            )),
        }
    }

    async fn write(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        version: &str,
        tags: BTreeMap<String, String>,
    ) -> Result<(), AzureError> {
        certs_api(state, session, vault)
            .update(name, version, &only_tags(tags))
            .await
            .map(|_| ())
    }
}

impl Editable for Keys {
    const KIND: Kind = Kind::Key;
    const READ: Need = Need::ReadKeys;
    const WRITE: Need = Need::ManageKeys;

    async fn current(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        shell: Shell,
    ) -> Result<(Current, Shell), Halt> {
        // A certificate's key is changed through the certificate.
        let (b, shell) = super::keys::unmanaged_key(state, session, vault, name, shell).await?;
        Ok((
            Current {
                version: b.version().to_owned(),
                attributes: b.attributes,
                tags: b.tags.unwrap_or_default(),
            },
            shell,
        ))
    }

    async fn write(
        state: &AppState,
        session: &CurrentSession,
        vault: &str,
        name: &str,
        version: &str,
        tags: BTreeMap<String, String>,
    ) -> Result<(), AzureError> {
        keys_api(state, session, vault)
            .update(name, version, &only_tags(tags))
            .await
            .map(|_| ())
    }
}

fn certs_api<'a>(state: &'a AppState, session: &'a CurrentSession, vault: &str) -> CertsApi<'a> {
    CertsApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

fn keys_api<'a>(state: &'a AppState, session: &'a CurrentSession, vault: &str) -> KeysApi<'a> {
    KeysApi {
        azure: &state.azure,
        session: &session.0,
        vault_url: state.config.vault_url(vault),
    }
}

/// Check the vault and the name from the address.
fn place<E: Editable>(
    session: &CurrentSession,
    shell: Shell,
    vault: &str,
    name: &str,
) -> Result<(String, String, Shell), Halt> {
    let (vault, shell) = vault_ctx::path_vault(session, shell, E::KIND.section(), vault)?;
    let (name, shell) = checked_name(name, shell)?;
    Ok((vault, name, shell))
}

pub(crate) async fn form<E: Editable>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
) -> PageResult {
    let (vault, name, shell) = place::<E>(&session, shell, &vault, &name)?;
    // The tag suggestions load beside the item, within their own limit.
    let (current, suggest) = tokio::join!(
        E::current(&state, &session, &vault, &name, shell),
        tag_rows::for_vault(&state, &session, &vault),
    );
    let (current, shell) = current?;
    Ok(page(
        shell,
        vault,
        E::KIND,
        name,
        &current,
        None,
        FieldErrors::new(),
        suggest,
    ))
}

pub(crate) async fn save<E: Editable>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path((vault, name)): Path<(String, String)>,
    Form(f): Form<DetailsForm>,
) -> PageResult {
    let (vault, name, shell) = place::<E>(&session, shell, &vault, &name)?;
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let (current, shell) = E::current(&state, &session, &vault, &name, shell).await?;
    if f.version != current.version || f.updated != current.updated() {
        return Err(changed_problem(shell, &vault, E::KIND, &name));
    }
    crate::audit::note_version(&current.version);
    let item = E::KIND.item_url(&vault, &name);
    let tags = match new_tags(&f, &current.tags) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Ok(redirect_with(
                &state,
                &item,
                format!("No changes to {name}."),
            ));
        }
        Err(errors) => {
            crate::audit::refuse(crate::audit::Refusal::InvalidRequest);
            let suggest = tag_rows::for_vault(&state, &session, &vault).await;
            return Ok(page(
                shell,
                vault,
                E::KIND,
                name,
                &current,
                Some(&f),
                errors,
                suggest,
            ));
        }
    };
    match E::write(&state, &session, &vault, &name, &current.version, tags).await {
        Ok(()) => Ok(redirect_with(
            &state,
            &item,
            format!("Saved changes to {name}."),
        )),
        Err(e) => Err(azure_problem(
            shell,
            &e,
            E::WRITE,
            &vault_path(&vault, &format!("{}/{name}/details", E::KIND.base())),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    fn form(description: &str, rows: &[(&str, &str)]) -> DetailsForm {
        DetailsForm {
            description: description.into(),
            tag_rows: TagPost::rows(rows),
            ..DetailsForm::default()
        }
    }

    #[test]
    fn note_is_merged_with_the_tags() {
        let cur = tags(&[("env", "prod")]);
        let t = new_tags(&form("Web front end", &[("env", "prod")]), &cur)
            .unwrap()
            .unwrap();
        assert_eq!(
            t,
            tags(&[("env", "prod"), ("description", "Web front end")])
        );
        // Unchanged: nothing to send.
        assert!(
            new_tags(&form("Web front end", &[("env", "prod")]), &t)
                .unwrap()
                .is_none()
        );
        // Empty removes the note and keeps the rest.
        let t2 = new_tags(&form("", &[("env", "prod")]), &t)
            .unwrap()
            .unwrap();
        assert_eq!(t2, cur);
    }

    #[test]
    fn tags_a_row_cant_show_are_kept() {
        let cur = tags(&[("a=b", " c "), ("two", "x\ny"), ("description", "old")]);
        // a=b has a row and comes back as it was; the other is kept.
        let t = new_tags(&form("new", &[("a=b", " c ")]), &cur)
            .unwrap()
            .unwrap();
        assert_eq!(
            t,
            tags(&[("a=b", " c "), ("two", "x\ny"), ("description", "new")])
        );
    }

    #[test]
    fn problems_are_refused_before_azure() {
        let full: BTreeMap<String, String> =
            (0..15).map(|i| (format!("k{i}"), "v".into())).collect();
        let rows: Vec<(&str, &str)> = full.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let e = new_tags(&form("note", &rows), &full).unwrap_err();
        assert!(e.error_for("description").unwrap().contains("15 tags"));
        let e = new_tags(&form("", &[("description", "sneaky")]), &BTreeMap::new()).unwrap_err();
        assert!(
            e.error_for("tag-name-1")
                .unwrap()
                .contains("Description field")
        );
        let e = new_tags(&form("a\u{202E}b", &[]), &BTreeMap::new()).unwrap_err();
        assert!(e.error_for("description").is_some());
    }

    #[test]
    fn debug_hides_the_note() {
        let f = form("TOPSECRETNOTE", &[]);
        assert!(!format!("{f:?}").contains("TOPSECRETNOTE"));
    }
}
