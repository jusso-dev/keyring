//! Change tags, expiry or enabled on many secrets, certificates or keys at
//! once (#216).
//!
//! The list's "With selected" form posts the ticked names and the change
//! to `{kind}/-/bulk`, which reads the list (properties only) and shows a
//! page with every item and exactly what will happen to it. That page's
//! form carries the names and the change in hidden fields to
//! `{kind}/-/bulk/apply`, which checks everything again, then for each
//! item reads its current properties and sends one `PATCH` as the person,
//! [`batch::CONCURRENCY`] at a time. Nothing is kept on the server between
//! the two posts.
//!
//! Key Vault replaces a version's tags as a whole, so a tag change is a
//! read then a write of the full set. The read is the same properties
//! call the edit pages use, never a value read. Someone else's change in
//! between can be overwritten; the window is the time between the two
//! calls for that item.
//!
//! Each item that reaches Key Vault gets its own audit event through
//! [`ItemEvents`], as an import does. Delete and purge are never offered
//! in bulk: one at a time is a feature there.

use std::collections::{BTreeMap, HashSet};

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;
use crate::audit::{self, ItemEvents, Outcome, Refusal};
use crate::auth::CurrentSession;
use crate::azure::AzureError;
use crate::azure::certs::CertsApi;
use crate::azure::keys::KeysApi;
use crate::azure::secrets::{
    DateChange, SecretsApi, Timestamp, UpdateAttributes, UpdateProperties, UpdateSecret, now_ts,
};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::batch::{self, Deadlines, Ran};
use crate::routes::error::{Halt, Need, PageError, PageResult, Problem};
use crate::routes::hints;
use crate::routes::lifecycle::Kind;
use crate::routes::secrets::form::{MAX_TAGS, new_expiry, one_tag};
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{self, azure_problem, check_csrf, is_valid_object_name};

/// Most items in one bulk change. The same as a list page holds.
pub(crate) const MAX_ITEMS: usize = 100;

/// Which list a bulk change is for. One marker type per kind, so the
/// router can name the handler for each.
pub(crate) trait Which {
    const KIND: Kind;
}

pub(crate) struct Secrets;
pub(crate) struct Certificates;
pub(crate) struct Keys;

impl Which for Secrets {
    const KIND: Kind = Kind::Secret;
}
impl Which for Certificates {
    const KIND: Kind = Kind::Certificate;
}
impl Which for Keys {
    const KIND: Kind = Kind::Key;
}

/// The audit action for applying a bulk change to `kind`.
pub(crate) fn action(kind: Kind) -> audit::Action {
    match kind {
        Kind::Secret => audit::Action::SecretBulkUpdate,
        Kind::Certificate => audit::Action::CertificateBulkUpdate,
        Kind::Key => audit::Action::KeyBulkUpdate,
    }
}

/// The permission hint for the "With selected" button and a refused item.
pub(crate) fn hint(kind: Kind) -> hints::Action {
    match kind {
        Kind::Secret => hints::Action::UpdateSecret,
        Kind::Certificate => hints::Action::UpdateCertificate,
        Kind::Key => hints::Action::UpdateKey,
    }
}

fn read_need(kind: Kind) -> Need {
    match kind {
        Kind::Secret => Need::ReadSecrets,
        Kind::Certificate => Need::ReadCertificates,
        Kind::Key => Need::ReadKeys,
    }
}

/// One change, the same for every item. `Debug` is written by hand so a
/// description never prints.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Op {
    SetTag(String, String),
    RemoveTag(String),
    /// Set the note in the `description` tag. Cleaned and checked.
    SetNote(String),
    RemoveNote,
    /// End of the chosen day, UTC.
    Expiry(Timestamp),
    Enable,
    Disable,
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetTag(k, v) => f.debug_tuple("SetTag").field(k).field(v).finish(),
            Self::RemoveTag(k) => f.debug_tuple("RemoveTag").field(k).finish(),
            // The note may hold sensitive context: never printed.
            Self::SetNote(_) => f.write_str("SetNote(..)"),
            Self::RemoveNote => f.write_str("RemoveNote"),
            Self::Expiry(e) => f.debug_tuple("Expiry").field(e).finish(),
            Self::Enable => f.write_str("Enable"),
            Self::Disable => f.write_str("Disable"),
        }
    }
}

impl Op {
    /// The change in words, for the page headings.
    fn describe(&self) -> String {
        match self {
            Self::SetTag(k, v) => format!("Set the tag {k}={v}"),
            Self::RemoveTag(k) => format!("Remove the tag {k}"),
            Self::SetNote(_) => "Set the description".into(),
            Self::RemoveNote => "Remove the description".into(),
            Self::Expiry(e) => format!("Set the expiry date to {}", dates::format_date(*e)),
            Self::Enable => "Enable".into(),
            Self::Disable => "Disable".into(),
        }
    }
}

/// What the forms post. The names come as repeated `item` fields, which
/// `serde_urlencoded` can't read into a list, so the body is read by hand.
/// `Debug` shows the change and how many items, never the form token, a
/// tag value or the description.
#[derive(Default)]
struct Posted {
    csrf: String,
    items: Vec<String>,
    op: String,
    tag_name: String,
    tag_value: String,
    description: String,
    expires: String,
    confirm_count: String,
}

impl std::fmt::Debug for Posted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Posted")
            .field("op", &self.op)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl Posted {
    fn parse(body: &[u8]) -> Self {
        let mut p = Self::default();
        for (k, v) in openidconnect::url::form_urlencoded::parse(body) {
            let v = v.into_owned();
            match k.as_ref() {
                "csrf" => p.csrf = v,
                "item" => p.items.push(v),
                "op" => p.op = v,
                "tag_name" => p.tag_name = v,
                "tag_value" => p.tag_value = v,
                "description" => p.description = v,
                "expires" => p.expires = v,
                "confirm_count" => p.confirm_count = v,
                _ => {}
            }
        }
        p
    }

    /// The change asked for, checked. Expiry is refused for certificates,
    /// whose dates come from the certificate itself.
    fn op(&self, kind: Kind, now: Timestamp) -> Result<Op, String> {
        match self.op.as_str() {
            "tag_set" => one_tag(&self.tag_name, &self.tag_value).map(|(k, v)| Op::SetTag(k, v)),
            "tag_remove" => one_tag(&self.tag_name, "").map(|(k, _)| Op::RemoveTag(k)),
            "description_set" => match crate::description::clean(&self.description)? {
                Some(n) => Ok(Op::SetNote(n)),
                None => Err(
                    "Type the description to set. To take it off, choose Remove the description."
                        .into(),
                ),
            },
            "description_remove" => Ok(Op::RemoveNote),
            "expiry" if kind == Kind::Certificate => Err(
                "A certificate's expiry date comes from the certificate. Renew it to change it."
                    .into(),
            ),
            "expiry" => new_expiry(&self.expires, now).map(Op::Expiry),
            "enable" => Ok(Op::Enable),
            "disable" => Ok(Op::Disable),
            "" => Err("Choose what to change.".into()),
            _ => Err("Choose one of the changes in the list.".into()),
        }
    }

    /// The ticked names, each checked against Key Vault's rules, with any
    /// repeat (ignoring case, as Key Vault does) dropped.
    fn items(&self, kind: Kind) -> Result<Vec<String>, String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for name in &self.items {
            if !is_valid_object_name(name) {
                return Err(format!(
                    "The list held a name that isn't a {} name. Nothing was changed.",
                    kind.noun()
                ));
            }
            if seen.insert(name.to_ascii_lowercase()) {
                out.push(name.clone());
            }
        }
        if out.is_empty() {
            return Err(format!(
                "Tick at least one {} in the list first.",
                kind.noun()
            ));
        }
        if out.len() > MAX_ITEMS {
            return Err(format!(
                "You can change up to {MAX_ITEMS} {} at a time. {} were ticked.",
                kind.plural(),
                out.len()
            ));
        }
        Ok(out)
    }
}

/// What Keyring knows of one item before changing it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Current {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub expires: Option<Timestamp>,
    pub not_before: Option<Timestamp>,
    pub tags: BTreeMap<String, String>,
    /// A certificate's backing secret or key.
    pub managed: bool,
}

/// Why an item is left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Blocked {
    Managed,
    TooManyTags,
    StartsAfter,
}

/// What will happen to one item.
#[derive(Debug)]
pub(crate) enum Plan {
    Change(String, UpdateProperties),
    NoChange(String),
    Blocked(Blocked, String),
}

/// Work out the change for one item. Pure, so the review page and the
/// apply step agree, and so it is easy to test.
pub(crate) fn plan(kind: Kind, op: &Op, cur: &Current) -> Plan {
    if cur.managed {
        return Plan::Blocked(
            Blocked::Managed,
            format!(
                "This {} belongs to the certificate {}. Change it from the certificate.",
                kind.noun(),
                cur.name
            ),
        );
    }
    let mut body = UpdateProperties::default();
    let words = match op {
        Op::SetTag(k, v) => {
            let old = cur.tags.get(k);
            if old == Some(v) {
                return Plan::NoChange(format!("Already has {}.", tag_text(k, v)));
            }
            let mut tags = cur.tags.clone();
            tags.insert(k.clone(), v.clone());
            if tags.len() > MAX_TAGS {
                return Plan::Blocked(
                    Blocked::TooManyTags,
                    format!(
                        "Already has {} tags, the most Key Vault allows. Remove one first.",
                        cur.tags.len()
                    ),
                );
            }
            body.tags = Some(tags);
            match old {
                Some(o) => format!("Changes {k} from {} to {}.", shown(o), shown(v)),
                None => format!("Adds {}.", tag_text(k, v)),
            }
        }
        Op::SetNote(note) => {
            let old = crate::description::of(&cur.tags);
            if old == Some(note.as_str()) {
                return Plan::NoChange("Already has this description.".into());
            }
            match crate::description::merge(&cur.tags, Some(note)) {
                Ok(tags) => body.tags = Some(tags),
                Err(m) => return Plan::Blocked(Blocked::TooManyTags, m),
            }
            if old.is_some() {
                "Replaces its description.".into()
            } else {
                "Adds the description.".into()
            }
        }
        Op::RemoveNote => {
            if !cur.tags.contains_key(crate::description::TAG) {
                return Plan::NoChange("Has no description.".into());
            }
            let mut tags = cur.tags.clone();
            tags.remove(crate::description::TAG);
            body.tags = Some(tags);
            "Removes its description.".into()
        }
        Op::RemoveTag(k) => {
            let Some(old) = cur.tags.get(k) else {
                return Plan::NoChange(format!("Has no {k} tag."));
            };
            let words = format!("Removes {}.", tag_text(k, old));
            let mut tags = cur.tags.clone();
            tags.remove(k);
            body.tags = Some(tags);
            words
        }
        Op::Expiry(exp) => match DateChange::between(cur.expires, Some(*exp)) {
            Some(DateChange::Set(t)) => {
                if let Some(nbf) = cur.not_before
                    && nbf >= t
                {
                    return Plan::Blocked(
                        Blocked::StartsAfter,
                        format!(
                            "Its start date, {}, isn't before that expiry date.",
                            dates::format_date(nbf)
                        ),
                    );
                }
                body.attributes.expires = DateChange::Set(t);
                match cur.expires {
                    Some(old) => format!(
                        "Changes expiry from {} to {}.",
                        dates::format_date(old),
                        dates::format_date(t)
                    ),
                    None => format!("Sets expiry to {}.", dates::format_date(t)),
                }
            }
            _ => {
                return Plan::NoChange(format!(
                    "Already expires on {}.",
                    dates::format_date(cur.expires.unwrap_or(*exp))
                ));
            }
        },
        Op::Enable | Op::Disable => {
            let on = *op == Op::Enable;
            if cur.enabled == on {
                return Plan::NoChange(if on {
                    "Already enabled.".into()
                } else {
                    "Already disabled.".into()
                });
            }
            body.attributes = UpdateAttributes {
                enabled: Some(on),
                ..UpdateAttributes::default()
            };
            if on {
                "Enables it.".into()
            } else {
                "Disables it.".into()
            }
        }
    };
    Plan::Change(words, body)
}

fn tag_text(k: &str, v: &str) -> String {
    if v.is_empty() {
        format!("the tag {k}")
    } else {
        format!("{k}={v}")
    }
}

fn shown(v: &str) -> &str {
    if v.is_empty() { "empty" } else { v }
}

/// The calls one bulk change makes, for one vault, as the person.
#[derive(Clone)]
struct Vault {
    azure: crate::azure::AzureClient,
    session: std::sync::Arc<crate::auth::session::Session>,
    url: String,
}

impl Vault {
    fn new(state: &AppState, session: &CurrentSession, vault: &str) -> Self {
        Self {
            azure: state.azure.clone(),
            session: session.0.clone(),
            url: state.config.vault_url(vault),
        }
    }

    fn secrets(&self) -> SecretsApi<'_> {
        SecretsApi {
            azure: &self.azure,
            session: &self.session,
            vault_url: self.url.clone(),
        }
    }

    fn certs(&self) -> CertsApi<'_> {
        CertsApi {
            azure: &self.azure,
            session: &self.session,
            vault_url: self.url.clone(),
        }
    }

    fn keys(&self) -> KeysApi<'_> {
        KeysApi {
            azure: &self.azure,
            session: &self.session,
            vault_url: self.url.clone(),
        }
    }

    /// Every item of `kind`, from the list call: names and properties.
    async fn list(&self, kind: Kind) -> Result<Vec<Current>, AzureError> {
        Ok(match kind {
            Kind::Secret => self
                .secrets()
                .list()
                .await?
                .into_iter()
                .map(|i| Current {
                    name: i.name().to_owned(),
                    version: i.version().to_owned(),
                    enabled: i.attributes.is_enabled(),
                    expires: i.attributes.expires,
                    not_before: i.attributes.not_before,
                    tags: i.tags().clone(),
                    managed: i.managed.unwrap_or(false),
                })
                .collect(),
            Kind::Certificate => self
                .certs()
                .list()
                .await?
                .into_iter()
                .map(|i| Current {
                    name: i.name().to_owned(),
                    version: i.version().to_owned(),
                    enabled: i.attributes.is_enabled(),
                    expires: i.attributes.expires,
                    not_before: i.attributes.not_before,
                    tags: i.tags().clone(),
                    managed: false,
                })
                .collect(),
            Kind::Key => self
                .keys()
                .list()
                .await?
                .into_iter()
                .map(|i| Current {
                    name: i.name().to_owned(),
                    version: i.version().to_owned(),
                    enabled: i.attributes.is_enabled(),
                    expires: i.attributes.expires,
                    not_before: i.attributes.not_before,
                    tags: i.tags().clone(),
                    managed: i.managed.unwrap_or(false),
                })
                .collect(),
        })
    }

    /// One item's current version, with the call each item's own pages
    /// use. For a secret that is the versions list, which never carries a
    /// value.
    async fn read(&self, kind: Kind, name: &str) -> Result<Current, AzureError> {
        Ok(match kind {
            Kind::Secret => {
                let i = self.secrets().properties(name).await?;
                Current {
                    name: i.name().to_owned(),
                    version: i.version().to_owned(),
                    enabled: i.attributes.is_enabled(),
                    expires: i.attributes.expires,
                    not_before: i.attributes.not_before,
                    tags: i.tags().clone(),
                    managed: i.managed.unwrap_or(false),
                }
            }
            Kind::Certificate => {
                let b = self.certs().get_cert(name, None).await?;
                Current {
                    name: name.to_owned(),
                    version: b.version().to_owned(),
                    enabled: b.attributes.is_enabled(),
                    expires: b.attributes.expires,
                    not_before: b.attributes.not_before,
                    tags: b.tags.clone().unwrap_or_default(),
                    managed: false,
                }
            }
            Kind::Key => {
                let b = self.keys().get(name, None).await?;
                Current {
                    name: name.to_owned(),
                    version: b.version().to_owned(),
                    enabled: b.attributes.is_enabled(),
                    expires: b.attributes.expires,
                    not_before: b.attributes.not_before,
                    tags: b.tags.clone().unwrap_or_default(),
                    managed: b.managed.unwrap_or(false),
                }
            }
        })
    }

    async fn write(
        &self,
        kind: Kind,
        cur: &Current,
        body: UpdateProperties,
    ) -> Result<(), AzureError> {
        match kind {
            Kind::Secret => {
                let body = UpdateSecret {
                    content_type: None,
                    attributes: body.attributes,
                    tags: body.tags,
                };
                self.secrets()
                    .update(&cur.name, &cur.version, &body)
                    .await
                    .map(|_| ())
            }
            Kind::Certificate => self
                .certs()
                .update(&cur.name, &cur.version, &body)
                .await
                .map(|_| ()),
            Kind::Key => self
                .keys()
                .update(&cur.name, &cur.version, &body)
                .await
                .map(|_| ()),
        }
    }
}

/// A refusal before anything is sent: the form couldn't be used.
fn bad_form(shell: Shell, kind: Kind, vault: &str, message: String) -> Halt {
    audit::refuse(Refusal::InvalidRequest);
    PageError::new(
        shell,
        Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Nothing was changed",
            message,
        )
        .returning_to(&kind.list_url(vault)),
    )
    .into()
}

/// One row of the review page.
pub(crate) struct ReviewRow {
    pub name: String,
    pub kind: RowKind,
    pub why: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowKind {
    Change,
    NoChange,
    Blocked,
    NotFound,
}

#[derive(Template)]
#[template(path = "bulk/review.html")]
struct ReviewPage {
    shell: Shell,
    vault: String,
    kind: Kind,
    change: String,
    rows: Vec<ReviewRow>,
    /// Names that will be changed, in the form's hidden fields.
    changing: Vec<String>,
    disable: bool,
    op: String,
    tag_name: String,
    tag_value: String,
    description: String,
    expires: String,
}

impl ReviewPage {
    fn noun_for(&self, n: usize) -> String {
        if n == 1 {
            format!("1 {}", self.kind.noun())
        } else {
            format!("{n} {}", self.kind.plural())
        }
    }
}

/// The "With selected" post from a list: show what will happen. Reads the
/// list only; changes nothing.
pub(crate) async fn review<K: Which>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    body: Bytes,
) -> PageResult {
    let kind = K::KIND;
    let (vault, shell) = vault_ctx::path_vault(&session, shell, kind.section(), &vault)?;
    let p = Posted::parse(&body);
    let shell = check_csrf(&session, &vault, &p.csrf, shell)?;
    let now = now_ts();
    let op = match p.op(kind, now) {
        Ok(op) => op,
        Err(m) => return Err(bad_form(shell, kind, &vault, m)),
    };
    let names = match p.items(kind) {
        Ok(n) => n,
        Err(m) => return Err(bad_form(shell, kind, &vault, m)),
    };
    let all = match Vault::new(&state, &session, &vault).list(kind).await {
        Ok(all) => all,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                read_need(kind),
                &kind.list_url(&vault),
            ));
        }
    };
    let mut rows = Vec::with_capacity(names.len());
    let mut changing = Vec::new();
    for name in names {
        let found = all.iter().find(|c| c.name.eq_ignore_ascii_case(&name));
        let row = match found {
            None => ReviewRow {
                name,
                kind: RowKind::NotFound,
                why: format!("There's no {} with this name now.", kind.noun()),
            },
            Some(cur) => match plan(kind, &op, cur) {
                Plan::Change(why, _) => {
                    changing.push(cur.name.clone());
                    ReviewRow {
                        name: cur.name.clone(),
                        kind: RowKind::Change,
                        why,
                    }
                }
                Plan::NoChange(why) => ReviewRow {
                    name: cur.name.clone(),
                    kind: RowKind::NoChange,
                    why,
                },
                Plan::Blocked(_, why) => ReviewRow {
                    name: cur.name.clone(),
                    kind: RowKind::Blocked,
                    why,
                },
            },
        };
        rows.push(row);
    }
    Ok(no_store(
        render(&ReviewPage {
            shell,
            vault,
            kind,
            change: op.describe(),
            rows,
            changing,
            disable: op == Op::Disable,
            op: p.op,
            tag_name: p.tag_name,
            tag_value: p.tag_value,
            description: p.description,
            expires: p.expires,
        })
        .into_response(),
    ))
}

/// How one item ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Done {
    Changed,
    NoChange,
    Blocked,
    NotFound,
    Denied,
    Failed,
    /// Not sent: Keyring ran out of time first.
    NotStarted,
    /// Sent, but Keyring stopped waiting for the answer.
    Unknown,
}

pub(crate) struct ResultRow {
    pub name: String,
    pub done: Done,
    pub why: String,
}

#[derive(Template)]
#[template(path = "bulk/results.html")]
struct ResultsPage {
    shell: Shell,
    vault: String,
    kind: Kind,
    change: String,
    rows: Vec<ResultRow>,
    changed: usize,
    not_changed: usize,
}

/// What one item's work came to.
enum Worked {
    Changed(String),
    NoChange(String),
    Blocked(String),
}

/// The second post, from the review page: change each item. Checks the
/// whole form again, since it comes back from the browser.
pub(crate) async fn apply<K: Which>(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    body: Bytes,
) -> PageResult {
    let kind = K::KIND;
    let (vault, shell) = vault_ctx::path_vault(&session, shell, kind.section(), &vault)?;
    let p = Posted::parse(&body);
    let shell = check_csrf(&session, &vault, &p.csrf, shell)?;
    let now = now_ts();
    let op = match p.op(kind, now) {
        Ok(op) => op,
        Err(m) => return Err(bad_form(shell, kind, &vault, m)),
    };
    let names = match p.items(kind) {
        Ok(n) => n,
        Err(m) => return Err(bad_form(shell, kind, &vault, m)),
    };
    if op == Op::Disable && p.confirm_count.trim() != names.len().to_string() {
        audit::refuse(Refusal::TypedNameMismatch);
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "The number didn't match",
                format!(
                    "Nothing was disabled. To confirm, type {} exactly, the number of {} to disable.",
                    names.len(),
                    kind.plural()
                ),
            )
            .returning_to(&kind.list_url(&vault)),
        )
        .into());
    }

    let api = Vault::new(&state, &session, &vault);
    let work_op = op.clone();
    let items: Vec<(String, String)> = names.iter().map(|n| (n.clone(), n.clone())).collect();
    let ran = batch::run_each(
        items,
        ItemEvents::for_request(action(kind), state.audit_sink.clone()),
        Deadlines::STANDARD,
        move |name: String| {
            let api = api.clone();
            let op = work_op.clone();
            async move {
                // A secret with no versions comes back as a 404 that no
                // call sent, so say so in the item's event.
                let cur = api
                    .read(kind, &name)
                    .await
                    .inspect_err(audit::note_azure_error)?;
                match plan(kind, &op, &cur) {
                    Plan::Change(words, body) => {
                        api.write(kind, &cur, body).await?;
                        Ok(Worked::Changed(words))
                    }
                    Plan::NoChange(words) => {
                        audit::end(Outcome::Success, "no_change");
                        Ok(Worked::NoChange(words))
                    }
                    Plan::Blocked(why, words) => {
                        audit::refuse(match why {
                            Blocked::Managed => Refusal::ManagedItem,
                            Blocked::TooManyTags => Refusal::TagLimit,
                            Blocked::StartsAfter => Refusal::InvalidRequest,
                        });
                        Ok(Worked::Blocked(words))
                    }
                }
            }
        },
    )
    .await;

    let rows: Vec<ResultRow> = names
        .into_iter()
        .zip(ran)
        .map(|(name, ran)| {
            let (done, why) = outcome(kind, ran);
            ResultRow { name, done, why }
        })
        .collect();
    let changed = rows.iter().filter(|r| r.done == Done::Changed).count();
    let failed: Vec<&ResultRow> = rows
        .iter()
        .filter(|r| !matches!(r.done, Done::Changed | Done::NoChange))
        .collect();
    // The request's own event says how the change as a whole went.
    if !failed.is_empty() {
        let outcome = if changed == 0 && failed.iter().all(|r| r.done == Done::Denied) {
            Outcome::Denied
        } else {
            Outcome::Failed
        };
        let code = if changed == 0 {
            "none_changed"
        } else {
            "partly_changed"
        };
        audit::end(outcome, code);
    }
    let not_changed = rows.len() - changed;
    Ok(no_store(
        render(&ResultsPage {
            shell,
            vault,
            kind,
            change: op.describe(),
            rows,
            changed,
            not_changed,
        })
        .into_response(),
    ))
}

/// The result and its reason, never Azure's message.
fn outcome(kind: Kind, ran: Ran<Worked, AzureError>) -> (Done, String) {
    match ran {
        Ran::Done(Ok(Worked::Changed(w))) => (Done::Changed, w),
        Ran::Done(Ok(Worked::NoChange(w))) => (Done::NoChange, w),
        Ran::Done(Ok(Worked::Blocked(w))) => (Done::Blocked, w),
        Ran::Done(Err(e)) => failed(kind, &e),
        Ran::NotStarted => (
            Done::NotStarted,
            "Not sent: Keyring ran out of time. Select the rest and try again.".into(),
        ),
        Ran::Unknown => (
            Done::Unknown,
            format!(
                "Keyring stopped waiting for Key Vault. Open the {} to see whether it changed.",
                kind.noun()
            ),
        ),
    }
}

fn failed(kind: Kind, e: &AzureError) -> (Done, String) {
    match e {
        AzureError::Status { status: 404, .. } => (
            Done::NotFound,
            format!(
                "There's no {} with this name now. It may have been deleted.",
                kind.noun()
            ),
        ),
        AzureError::Status {
            status: 401 | 403, ..
        } => (
            Done::Denied,
            format!(
                "Azure said you can't change this {}. That needs the {} role.",
                kind.noun(),
                hint(kind).need().role()
            ),
        ),
        AzureError::Status { status: 429, .. } => (
            Done::Failed,
            "Key Vault was too busy. Try this one again later.".into(),
        ),
        AzureError::Status { status, code, .. } => (
            Done::Failed,
            match code {
                Some(c) => format!("Key Vault answered {status} ({}).", audit::safe_code(c)),
                None => format!("Key Vault answered {status}."),
            },
        ),
        AzureError::Token(_) => (
            Done::Denied,
            "Keyring couldn't get a token for Key Vault as you. Sign in again.".into(),
        ),
        _ => (Done::Failed, "Keyring couldn't reach Key Vault.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cur(tags: &[(&str, &str)]) -> Current {
        Current {
            name: "db".into(),
            version: "v".into(),
            enabled: true,
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            ..Current::default()
        }
    }

    fn body(p: Plan) -> UpdateProperties {
        match p {
            Plan::Change(_, b) => b,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn debug_hides_the_description() {
        let op = Op::SetNote("TOPSECRETNOTE".into());
        assert_eq!(format!("{op:?}"), "SetNote(..)");
        let p =
            Posted::parse(b"op=description_set&description=TOPSECRETNOTE&item=a&item=b&csrf=TOKEN");
        let shown = format!("{p:?}");
        assert!(
            !shown.contains("TOPSECRETNOTE") && !shown.contains("TOKEN"),
            "{shown}"
        );
        assert!(
            shown.contains("description_set") && shown.contains("items: 2"),
            "{shown}"
        );
    }

    #[test]
    fn the_description_is_merged_and_counted() {
        let c = cur(&[("env", "prod")]);
        let Plan::Change(words, b) = plan(Kind::Key, &Op::SetNote("Signs invoices".into()), &c)
        else {
            panic!("should change");
        };
        assert_eq!(words, "Adds the description.");
        let tags = b.tags.unwrap();
        assert_eq!(tags["env"], "prod");
        assert_eq!(tags["description"], "Signs invoices");
        let noted = cur(&[("env", "prod"), ("description", "Signs invoices")]);
        assert!(matches!(
            plan(Kind::Key, &Op::SetNote("Signs invoices".into()), &noted),
            Plan::NoChange(_)
        ));
        let Plan::Change(_, b) = plan(Kind::Key, &Op::RemoveNote, &noted) else {
            panic!("should change");
        };
        assert_eq!(b.tags.unwrap().keys().collect::<Vec<_>>(), ["env"]);
        assert!(matches!(
            plan(Kind::Key, &Op::RemoveNote, &c),
            Plan::NoChange(_)
        ));
        let many: Vec<(String, String)> = (0..MAX_TAGS)
            .map(|i| (format!("k{i}"), "v".to_owned()))
            .collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert!(matches!(
            plan(Kind::Key, &Op::SetNote("n".into()), &cur(&refs)),
            Plan::Blocked(Blocked::TooManyTags, _)
        ));
    }

    #[test]
    fn tags_are_written_back_whole() {
        let c = cur(&[("env", "prod"), ("team", "ops")]);
        let b = body(plan(
            Kind::Secret,
            &Op::SetTag("owner".into(), "a".into()),
            &c,
        ));
        let tags = b.tags.unwrap();
        assert_eq!(tags.len(), 3, "the others are kept");
        assert_eq!(tags["env"], "prod");
        assert_eq!(b.attributes, UpdateAttributes::default());
        let b = body(plan(Kind::Key, &Op::RemoveTag("env".into()), &c));
        assert_eq!(b.tags.unwrap().keys().collect::<Vec<_>>(), ["team"]);
        assert!(matches!(
            plan(Kind::Key, &Op::RemoveTag("nope".into()), &c),
            Plan::NoChange(_)
        ));
        assert!(matches!(
            plan(Kind::Key, &Op::SetTag("env".into(), "prod".into()), &c),
            Plan::NoChange(_)
        ));
    }

    #[test]
    fn a_sixteenth_tag_is_refused_not_dropped() {
        let many: Vec<(String, String)> = (0..MAX_TAGS)
            .map(|i| (format!("t{i}"), "x".into()))
            .collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let c = cur(&refs);
        assert!(matches!(
            plan(Kind::Secret, &Op::SetTag("new".into(), "x".into()), &c),
            Plan::Blocked(Blocked::TooManyTags, _)
        ));
        // Changing one already there is fine.
        assert!(matches!(
            plan(Kind::Secret, &Op::SetTag("t0".into(), "y".into()), &c),
            Plan::Change(..)
        ));
    }

    #[test]
    fn managed_items_are_refused() {
        let mut c = cur(&[]);
        c.managed = true;
        for op in [Op::Enable, Op::Disable, Op::RemoveTag("a".into())] {
            assert!(matches!(
                plan(Kind::Secret, &op, &c),
                Plan::Blocked(Blocked::Managed, _)
            ));
        }
    }

    #[test]
    fn expiry_is_set_or_changed_and_keeps_the_same_day() {
        const DAY: i64 = 86_400;
        let mut c = cur(&[]);
        let exp = 20_000 * DAY + 86_399;
        let b = body(plan(Kind::Secret, &Op::Expiry(exp), &c));
        assert_eq!(b.attributes.expires, DateChange::Set(exp));
        assert!(b.tags.is_none(), "tags left alone");
        c.expires = Some(20_000 * DAY + 3600);
        assert!(matches!(
            plan(Kind::Secret, &Op::Expiry(exp), &c),
            Plan::NoChange(_)
        ));
        c.not_before = Some(30_000 * DAY);
        assert!(matches!(
            plan(Kind::Key, &Op::Expiry(25_000 * DAY), &c),
            Plan::Blocked(Blocked::StartsAfter, _)
        ));
    }

    #[test]
    fn enable_and_disable_send_only_enabled() {
        let c = cur(&[("a", "b")]);
        assert!(matches!(
            plan(Kind::Key, &Op::Enable, &c),
            Plan::NoChange(_)
        ));
        let b = body(plan(Kind::Certificate, &Op::Disable, &c));
        assert_eq!(b.attributes.enabled, Some(false));
        assert!(b.tags.is_none());
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"attributes":{"enabled":false}}"#);
    }

    #[test]
    fn the_form_is_checked() {
        let p = |body: &str| Posted::parse(body.as_bytes());
        let now = 1_800_000_000;
        let f = p("csrf=t&item=a&item=b&item=A&op=tag_set&tag_name=owner&tag_value=x");
        assert_eq!(f.items(Kind::Secret).unwrap(), ["a", "b"], "repeat dropped");
        assert_eq!(
            f.op(Kind::Secret, now).unwrap(),
            Op::SetTag("owner".into(), "x".into())
        );
        assert!(p("item=a%2Fb&op=enable").items(Kind::Secret).is_err());
        assert!(p("item=-a&op=enable").items(Kind::Secret).is_err());
        assert!(p("op=enable").items(Kind::Secret).is_err());
        let many: String = (0..=MAX_ITEMS).map(|i| format!("item=s{i}&")).collect();
        let err = p(&many).items(Kind::Secret).unwrap_err();
        assert!(err.contains("up to 100"), "{err}");
        assert!(
            p("op=expiry&expires=2099-01-01")
                .op(Kind::Certificate, now)
                .is_err()
        );
        assert!(p("op=expiry&expires=").op(Kind::Key, now).is_err());
        assert!(
            p("op=expiry&expires=2000-01-01")
                .op(Kind::Key, now)
                .is_err()
        );
        assert!(p("op=expiry&expires=2099-01-01").op(Kind::Key, now).is_ok());
        assert!(p("op=delete").op(Kind::Key, now).is_err());
        assert!(p("op=tag_set&tag_name=").op(Kind::Key, now).is_err());
        assert_eq!(
            p("op=description_set&description=Used%20by%20billing%0D%0Aand%20payroll")
                .op(Kind::Certificate, now)
                .unwrap(),
            Op::SetNote("Used by billing\nand payroll".into())
        );
        assert!(
            p("op=description_set&description=")
                .op(Kind::Key, now)
                .is_err()
        );
        assert!(
            p("op=description_set&description=a%E2%80%AEb")
                .op(Kind::Key, now)
                .is_err()
        );
        assert_eq!(
            p("op=description_remove").op(Kind::Key, now).unwrap(),
            Op::RemoveNote
        );
        assert!(
            p("op=tag_set&tag_name=description&tag_value=x")
                .op(Kind::Key, now)
                .is_err()
        );
        let long = "x".repeat(257);
        assert!(
            p(&format!("op=tag_set&tag_name=a&tag_value={long}"))
                .op(Kind::Key, now)
                .is_err()
        );
    }

    #[test]
    fn errors_name_the_role_and_never_azure_s_message() {
        let st = |status, code: Option<&str>| AzureError::Status {
            status,
            code: code.map(str::to_owned),
            message: Some("private detail".into()),
        };
        let (d, why) = failed(Kind::Secret, &st(403, Some("ForbiddenByRbac")));
        assert_eq!(d, Done::Denied);
        assert!(why.contains("Key Vault Secrets Officer"), "{why}");
        let (d, _) = failed(Kind::Key, &st(404, Some("KeyNotFound")));
        assert_eq!(d, Done::NotFound);
        let (d, why) = failed(Kind::Certificate, &st(500, Some("InternalError")));
        assert_eq!(d, Done::Failed);
        assert!(
            why.contains("InternalError") && !why.contains("private"),
            "{why}"
        );
    }
}
