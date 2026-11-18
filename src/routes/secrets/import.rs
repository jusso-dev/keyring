//! Import secrets from a `.env` or CSV file.
//!
//! Like a certificate upload: the file is read into memory and shown as a
//! preview of names (never values). The secrets wait in the server-side
//! session, as [`Secret`]s that are zeroised when dropped, until the person
//! imports them, starts again, or 10 minutes pass. On import each one is
//! written as the person, four at a time, and a results page shows what
//! happened to each. There is deliberately no export.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use askama::Template;
use axum::Form;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::AppState;
use crate::audit::{Action, ItemEvents, Outcome};
use crate::auth::CurrentSession;
use crate::auth::crypto::random_token;
use crate::auth::session::{PendingImport, PendingSecret, SkippedSecret};
use crate::azure::AzureError;
use crate::azure::secrets::{Attributes, SecretsApi, SetSecret, now_ts};
use crate::dates;
use crate::routes::assets::render;
use crate::routes::error::{Need, PageError, PageResult, Problem};
use crate::routes::flash::{self, Flash};
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::reveal::no_store;
use crate::routes::shell::Shell;
use crate::routes::vault_ctx::{azure_problem, check_csrf, vault_path};

use super::import_file::{self, Format, MAX_FILE_BYTES, MAX_ROWS};
use super::{api, current_vault};

use crate::routes::batch::{self, Deadlines, Ran};

const IMPORT_PATH: &str = "/secrets/-/import";

/// A row whose value misses `KEYRING_PASSWORD_POLICY`. Fixed words: no
/// rule, no length, nothing about the value.
pub(crate) const POLICY_PROBLEM: &str = "Its value doesn't meet Keyring's password policy.";
/// The problem for a row with no owner while `KEYRING_REQUIRE_OWNER` is on.
pub(crate) const OWNER_PROBLEM: &str = "It has no owner, and Keyring is set to need one. Add an owner column with an address for each row.";

#[derive(Template)]
#[template(path = "secrets/import.html")]
struct ImportPage {
    shell: Shell,
    vault: String,
    errors: FieldErrors,
    max_kb: usize,
    max_rows: usize,
}

impl ImportPage {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors.error_for(field)
    }
}

/// What will happen to one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    New,
    NewVersion,
    /// A deleted secret with this name can still be recovered.
    BlockedDeleted,
    /// The name belongs to a certificate.
    BlockedManaged,
    /// The row itself has a problem.
    Invalid,
}

pub(crate) struct PreviewRow {
    pub original: String,
    pub name: String,
    pub plan: Plan,
    pub why: String,
    pub content_type: String,
    pub expires: String,
    /// Tags, without the description, owner and notify.
    pub tags: Vec<(String, String)>,
    pub description: String,
    pub owner: crate::owner::Display,
}

impl PreviewRow {
    fn converted(&self) -> bool {
        self.original != self.name
    }
}

#[derive(Template)]
#[template(path = "secrets/import_preview.html")]
struct PreviewPage {
    shell: Shell,
    vault: String,
    file_name: String,
    rows: Vec<PreviewRow>,
    new: usize,
    versions: usize,
    skipped: usize,
    /// Deleted secrets couldn't be listed, so a name may still be blocked.
    deleted_unknown: bool,
    import_id: String,
    /// What `KEYRING_PASSWORD_POLICY` asks for, or empty when it is off.
    policy: String,
}

impl PreviewPage {
    fn writes(&self) -> usize {
        self.new + self.versions
    }
}

/// How one row ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    Created,
    NewVersion,
    Skipped,
    BlockedDeleted,
    Denied,
    Failed,
    /// Not sent: Keyring ran out of time first.
    NotStarted,
    /// Sent, but Keyring stopped waiting for the answer.
    Unknown,
}

impl Written {
    fn ok(self) -> bool {
        matches!(self, Self::Created | Self::NewVersion)
    }
}

pub(crate) struct ResultRow {
    pub original: String,
    pub name: String,
    pub result: Written,
    pub why: String,
}

#[derive(Template)]
#[template(path = "secrets/import_results.html")]
struct ResultsPage {
    shell: Shell,
    vault: String,
    rows: Vec<ResultRow>,
    written: usize,
    not_written: usize,
}

fn import_page(shell: Shell, vault: String, errors: FieldErrors) -> Response {
    let status = if errors.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    no_store(
        (
            status,
            render(&ImportPage {
                shell,
                vault,
                errors,
                max_kb: MAX_FILE_BYTES / 1024,
                max_rows: MAX_ROWS,
            }),
        )
            .into_response(),
    )
}

fn too_big_message() -> String {
    format!(
        "That file is over {} KB. Split it into smaller files.",
        MAX_FILE_BYTES / 1024
    )
}

pub(crate) async fn form(
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    // A fresh form means any import waiting from before isn't wanted.
    session.0.forget_pending_import();
    Ok(import_page(shell, vault, FieldErrors::new()))
}

#[derive(Deserialize)]
pub(crate) struct CancelForm {
    #[serde(default)]
    csrf: String,
}

/// "Start again" on the preview: drop the waiting secrets and go back.
pub(crate) async fn cancel(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Form(f): Form<CancelForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    // Dropping the waiting import is safe whichever vault the form was for.
    if !session.0.csrf_matches_any(&f.csrf) {
        return Err(PageError::new(shell, Problem::stale_form()).into());
    }
    session.0.forget_pending_import();
    let mut res = Redirect::to(&vault_path(&vault, IMPORT_PATH)).into_response();
    flash::set(
        &state,
        &mut res,
        &Flash::success("Keyring has forgotten that file. Nothing was imported."),
    );
    Ok(res)
}

/// The posted form. The file is wiped when dropped.
#[derive(Default)]
struct Posted {
    csrf: String,
    file: Option<Zeroizing<Vec<u8>>>,
    file_name: String,
    too_big: bool,
}

enum ReadError {
    TooBig,
    Broken,
    /// More than one file part. The form has one.
    TwoFiles,
}

impl From<axum::extract::multipart::MultipartError> for ReadError {
    fn from(e: axum::extract::multipart::MultipartError) -> Self {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::TooBig
        } else {
            Self::Broken
        }
    }
}

async fn read_multipart(mut mp: Multipart, p: &mut Posted) -> Result<(), ReadError> {
    let mut seen_file = false;
    while let Some(mut field) = mp.next_field().await? {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "file" => {
                if seen_file {
                    return Err(ReadError::TwoFiles);
                }
                seen_file = true;
                p.file_name = field.file_name().unwrap_or_default().to_owned();
                // Zeroising from the start, so a read that fails part way
                // still wipes what came before it.
                let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
                while let Some(chunk) = field.chunk().await? {
                    if p.too_big || buf.len() + chunk.len() > MAX_FILE_BYTES {
                        p.too_big = true;
                        buf.zeroize();
                        buf.clear();
                        continue;
                    }
                    if buf.capacity() < buf.len() + chunk.len() {
                        // Grow by hand, so the old allocation is wiped
                        // rather than left behind by a reallocation.
                        let mut bigger = Zeroizing::new(Vec::with_capacity(
                            (buf.len() + chunk.len())
                                .max(buf.capacity() * 2)
                                .min(MAX_FILE_BYTES),
                        ));
                        bigger.extend_from_slice(&buf);
                        buf = bigger;
                    }
                    buf.extend_from_slice(&chunk);
                }
                if !buf.is_empty() {
                    p.file = Some(buf);
                }
            }
            "csrf" => p.csrf = field.text().await?,
            _ => {}
        }
    }
    Ok(())
}

/// What's in the vault now, by lower-case name.
struct Existing {
    live: HashMap<String, bool>,
    deleted: Option<HashSet<String>>,
}

async fn existing(api: &SecretsApi<'_>) -> Result<Existing, AzureError> {
    let live = api
        .list()
        .await?
        .into_iter()
        .map(|s| (s.name().to_ascii_lowercase(), s.managed.unwrap_or_default()))
        .collect();
    // Listing deleted secrets needs a little more than writing them. If
    // it's refused, say so on the preview, and a blocked name is reported
    // when the import is tried.
    let deleted = match api.list_deleted().await {
        Ok(d) => Some(d.iter().map(|s| s.name().to_ascii_lowercase()).collect()),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't list deleted secrets for an import preview");
            None
        }
    };
    Ok(Existing { live, deleted })
}

pub(crate) async fn preview(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    multipart: Multipart,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    // Read before anything else, so "Start again" or a fresh form while
    // this preview runs means its import isn't kept.
    let generation = session.0.pending_import_generation();
    let mut p = Posted::default();
    let read = read_multipart(multipart, &mut p).await;
    // A body cut off at the size limit may end before the form token
    // arrived. Then all Keyring can say is that the file is too big:
    // nothing goes to Key Vault and nothing is kept.
    if matches!(read, Err(ReadError::TooBig)) && p.csrf.is_empty() {
        return Ok(import_page(
            shell,
            vault,
            FieldErrors::one("file", too_big_message()),
        ));
    }
    let shell = check_csrf(&session, &vault, &p.csrf, shell)?;
    let file_error = match (read, p.too_big, &p.file) {
        (Err(ReadError::TooBig), _, _) | (_, true, _) => Some(too_big_message()),
        (Err(ReadError::Broken), _, _) => Some("The upload didn't come through. Try again.".into()),
        (Err(ReadError::TwoFiles), _, _) => Some("Choose one file to import at a time.".into()),
        (Ok(()), false, None) => Some("Choose a file to import.".into()),
        _ => None,
    };
    if let Some(m) = file_error {
        return Ok(import_page(shell, vault, FieldErrors::one("file", m)));
    }
    let bytes = p.file.as_deref().map(Vec::as_slice).unwrap_or_default();
    let rules = crate::owner::Rules::of(&state.config);
    let rows =
        match import_file::parse(bytes, Format::from_file_name(&p.file_name), now_ts(), rules) {
            Ok(rows) => rows,
            Err(m) => return Ok(import_page(shell, vault, FieldErrors::one("file", m))),
        };
    let have = match existing(&api(&state, &session, &vault)).await {
        Ok(e) => e,
        Err(err) => {
            return Err(azure_problem(
                shell,
                &err,
                Need::ManageSecrets,
                &vault_path(&vault, IMPORT_PATH),
            ));
        }
    };

    let policy = &state.config.password_policy;
    let mut shown = Vec::with_capacity(rows.len());
    let mut pending = Vec::new();
    let mut skipped = Vec::new();
    for row in rows {
        let key = row.name.to_ascii_lowercase();
        let deleted = have.deleted.as_ref().is_some_and(|d| d.contains(&key));
        let (plan, why) = match (&row.problem, have.live.get(&key)) {
            (Some(m), _) => (Plan::Invalid, m.clone()),
            (None, Some(true)) => (
                Plan::BlockedManaged,
                "This name belongs to a certificate. Change it through the certificate.".into(),
            ),
            (None, Some(false)) => (Plan::NewVersion, String::new()),
            (None, None) if deleted => (
                Plan::BlockedDeleted,
                "A deleted secret with this name can still be recovered. Recover or purge it first, or rename this one.".into(),
            ),
            (None, None) => (Plan::New, String::new()),
        };
        // Every row that would be written is a plain secret (a Keyring
        // content type is a row problem), so its value is a Password and
        // the policy applies. The problem names no rule and nothing about
        // the value: the preview lists every row's problem.
        // A written row replaces the secret's tags, so with
        // KEYRING_REQUIRE_OWNER on, a row without an owner would leave an
        // ownerless secret, new or not.
        let writes = matches!(plan, Plan::New | Plan::NewVersion);
        let refused = if writes && policy.check("Value", &row.value).is_some() {
            Some((crate::audit::Refusal::PasswordPolicy, POLICY_PROBLEM))
        } else if writes && rules.require && crate::owner::owner_of(&row.tags).is_none() {
            Some((crate::audit::Refusal::OwnerRequired, OWNER_PROBLEM))
        } else {
            None
        };
        let (plan, why) = match refused {
            Some((_, m)) => (Plan::Invalid, m.to_owned()),
            None => (plan, why),
        };
        shown.push(PreviewRow {
            original: row.original.clone(),
            name: row.name.clone(),
            plan,
            why: why.clone(),
            content_type: row.content_type.clone().unwrap_or_default(),
            expires: row.expires.map(dates::format_date).unwrap_or_default(),
            tags: crate::owner::without_fields(&row.tags)
                .into_iter()
                .collect(),
            description: crate::description::of(&row.tags)
                .unwrap_or_default()
                .to_owned(),
            owner: crate::owner::Display::of_owner(
                crate::owner::owner_of(&row.tags).unwrap_or_default(),
            ),
        });
        if matches!(plan, Plan::New | Plan::NewVersion) {
            pending.push(PendingSecret {
                original: row.original,
                name: row.name,
                value: row.value,
                content_type: row.content_type,
                expires: row.expires,
                tags: row.tags,
                exists: plan == Plan::NewVersion,
            });
        } else {
            skipped.push(SkippedSecret {
                original: row.original,
                name: row.name,
                reason: why,
                refusal: refused.map(|(r, _)| r),
            });
        }
    }
    let count = |want: Plan| shown.iter().filter(|r| r.plan == want).count();
    let (new, versions) = (count(Plan::New), count(Plan::NewVersion));
    let import_id = random_token(16);
    let kept = session.0.set_pending_import(
        generation,
        PendingImport {
            id: import_id.clone(),
            vault: vault.clone(),
            rows: pending,
            skipped,
            created: Instant::now(),
        },
    );
    if !kept {
        return Ok(import_page(
            shell,
            vault,
            FieldErrors::one(
                "file",
                "Keyring forgot this file because the import was started again. Choose the file again.",
            ),
        ));
    }
    Ok(no_store(
        render(&PreviewPage {
            shell,
            vault,
            file_name: p.file_name.clone(),
            skipped: shown.len() - new - versions,
            rows: shown,
            new,
            versions,
            deleted_unknown: have.deleted.is_none(),
            import_id,
            policy: policy.describe(),
        })
        .into_response(),
    ))
}

#[derive(Deserialize)]
pub(crate) struct ConfirmForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    import_id: String,
}

/// Write each row with `write`, [`CONCURRENCY`] at a time, and say how each
/// went, in the same order. A row whose write began writes one `secret.import`
/// event (`cancelled` if Keyring stopped waiting for it). A row that never
/// reached Key Vault, because no write could start before `start`, writes no
/// event and is [`Written::NotStarted`]. Only a write cut off in flight is
/// [`Written::Unknown`].
pub(crate) async fn write_rows<F, Fut>(
    rows: Vec<PendingSecret>,
    events: ItemEvents,
    deadlines: Deadlines,
    write: F,
) -> Vec<(Written, String)>
where
    F: Fn(PendingSecret) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Result<(), AzureError>> + Send + 'static,
{
    let exists: Vec<bool> = rows.iter().map(|r| r.exists).collect();
    let items = rows.into_iter().map(|r| (r.name.clone(), r)).collect();
    batch::run_each(items, events, deadlines, write)
        .await
        .into_iter()
        .zip(exists)
        .map(|(ran, exists)| match ran {
            Ran::Done(res) => outcome_of(&res, exists),
            Ran::Unknown => (
                Written::Unknown,
                "Keyring stopped waiting for Key Vault. Open the secret to see whether it was written.".into(),
            ),
            Ran::NotStarted => (
                Written::NotStarted,
                "Not sent: the import ran out of time. Import the rest in a smaller file.".into(),
            ),
        })
        .collect()
}

/// What one write came to, and the reason code for the results page.
fn outcome_of(res: &Result<(), AzureError>, exists: bool) -> (Written, String) {
    match res {
        Ok(()) if exists => (Written::NewVersion, String::new()),
        Ok(()) => (Written::Created, String::new()),
        Err(AzureError::Status { status: 409, .. }) => (
            Written::BlockedDeleted,
            "A deleted secret with this name can still be recovered, or is being recovered."
                .into(),
        ),
        Err(AzureError::Status {
            status: 401 | 403, ..
        }) => (
            Written::Denied,
            "Azure said you can't change secrets in this vault (Key Vault Secrets Officer).".into(),
        ),
        Err(AzureError::Status { status: 429, .. }) => (
            Written::Failed,
            "Key Vault was too busy. Import the file again later; secrets already written get a new version.".into(),
        ),
        Err(AzureError::Status { status, .. }) => {
            (Written::Failed, format!("Key Vault answered {status}."))
        }
        Err(AzureError::Token(_)) => (
            Written::Denied,
            "Keyring couldn't get a token for Key Vault as you. Sign in again.".into(),
        ),
        Err(_) => (Written::Failed, "Keyring couldn't reach Key Vault.".into()),
    }
}

pub(crate) async fn confirm(
    State(state): State<AppState>,
    session: CurrentSession,
    shell: Shell,
    Path(vault): Path<String>,
    Form(f): Form<ConfirmForm>,
) -> PageResult {
    let (vault, shell) = current_vault(&session, shell, &vault)?;
    // The token is checked before the import is taken, so a forged post
    // can't throw away someone's waiting file.
    let shell = check_csrf(&session, &vault, &f.csrf, shell)?;
    let Some(import) = session
        .0
        .take_pending_import(&f.import_id)
        .filter(|u| u.vault == vault)
    else {
        crate::audit::refuse(crate::audit::Refusal::InvalidRequest);
        return Err(PageError::new(
            shell,
            Problem::new(
                StatusCode::GONE,
                "That import has expired",
                "Keyring only holds a file of secrets for 10 minutes, and only for one import. Choose the file again.",
            )
            .returning_to(&vault_path(&vault, IMPORT_PATH)),
        )
        .into());
    };
    let PendingImport { rows, skipped, .. } = import;
    // A row a Keyring-side rule refused gets its own `refused` event,
    // with the fixed reason code and nothing about the value or addresses.
    let events = ItemEvents::for_request(Action::SecretImport, state.audit_sink.clone());
    for s in &skipped {
        if let Some(r) = s.refusal {
            events.refused(&s.name, r).await;
        }
    }
    let names: Vec<(String, String)> = rows
        .iter()
        .map(|r| (r.original.clone(), r.name.clone()))
        .collect();
    let azure = state.azure.clone();
    let session_arc = session.0.clone();
    let vault_url = state.config.vault_url(&vault);
    let results = write_rows(
        rows,
        events,
        Deadlines::STANDARD,
        move |row: PendingSecret| {
            let azure = azure.clone();
            let session = session_arc.clone();
            let vault_url = vault_url.clone();
            async move {
                let api = SecretsApi {
                    azure: &azure,
                    session: &session,
                    vault_url,
                };
                // A written row replaces the secret's tags. Its reveal limit
                // is read again just before the write (properties only) and
                // carried, so an import can't clear `keyring-reveal`.
                // Key Vault may answer an unknown name with 404 or with
                // an empty list: either way the name is free.
                let current = match api.versions(&row.name).await {
                    Ok(c) => c,
                    Err(AzureError::Status { status: 404, .. }) => Vec::new(),
                    Err(e) => return Err(e),
                };
                let tags = match current.first() {
                    Some(c) => crate::reveal_limit::carry(&row.tags, c.tags()),
                    None => row.tags,
                };
                let body = SetSecret {
                    value: row.value,
                    content_type: row.content_type,
                    attributes: Attributes {
                        enabled: Some(true),
                        expires: row.expires,
                        ..Attributes::default()
                    },
                    tags: Some(tags),
                };
                api.set(&row.name, &body).await.map(|_| ())
            }
        },
    )
    .await;
    let mut out: Vec<ResultRow> = names
        .into_iter()
        .zip(results)
        .map(|((original, name), (result, why))| ResultRow {
            original,
            name,
            result,
            why,
        })
        .collect();
    let written = out.iter().filter(|r| r.result.ok()).count();
    let tried = out.len();
    out.extend(skipped.into_iter().map(|s| ResultRow {
        original: s.original,
        name: s.name,
        result: Written::Skipped,
        why: s.reason,
    }));

    // The request's own event says how the import as a whole went.
    if written < tried {
        let all_denied = out
            .iter()
            .filter(|r| !r.result.ok() && r.result != Written::Skipped)
            .all(|r| r.result == Written::Denied);
        let outcome = if all_denied && written == 0 {
            Outcome::Denied
        } else {
            Outcome::Failed
        };
        let code = if written == 0 {
            "none_written"
        } else {
            "partly_written"
        };
        crate::audit::end(outcome, code);
    }

    let not_written = out.len() - written;
    Ok(no_store(
        render(&ResultsPage {
            shell,
            vault,
            rows: out,
            written,
            not_written,
        })
        .into_response(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::batch::CONCURRENCY;
    use std::sync::Arc;
    use std::time::Duration;

    fn row(name: &str) -> PendingSecret {
        PendingSecret {
            original: name.into(),
            name: name.into(),
            value: crate::secret::Secret::new("v"),
            content_type: None,
            expires: None,
            tags: Default::default(),
            exists: false,
        }
    }

    // Each row's audit event comes from `ItemEvents::run` around its
    // write, so a row whose write was never called writes no event, and
    // one cut off in flight writes `cancelled` (tested in `audit`).
    #[tokio::test]
    async fn rows_queued_past_the_start_deadline_are_not_sent_and_not_unknown() {
        let sent = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let rows: Vec<PendingSecret> = (0..10).map(|i| row(&format!("s{i}"))).collect();
        // Every write hangs, so the four permits are never given back.
        let calls = sent.clone();
        let results = write_rows(
            rows,
            ItemEvents::for_request(Action::SecretImport, None),
            Deadlines {
                start: Duration::from_millis(200),
                stop: Duration::from_millis(500),
            },
            move |r: PendingSecret| {
                calls.lock().unwrap().push(r.name.clone());
                async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(())
                }
            },
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), CONCURRENCY, "only four writes began");
        let kinds: Vec<Written> = results.iter().map(|r| r.0).collect();
        assert_eq!(
            kinds.iter().filter(|k| **k == Written::Unknown).count(),
            CONCURRENCY,
            "{kinds:?}"
        );
        assert_eq!(
            kinds.iter().filter(|k| **k == Written::NotStarted).count(),
            10 - CONCURRENCY,
            "{kinds:?}"
        );
        for (i, (k, why)) in results.iter().enumerate() {
            let name = format!("s{i}");
            assert_eq!(*k == Written::Unknown, sent.contains(&name), "{name}");
            if *k == Written::NotStarted {
                assert!(why.starts_with("Not sent"), "{why}");
            }
        }
    }

    #[tokio::test]
    async fn writes_that_finish_are_reported_in_order() {
        let rows: Vec<PendingSecret> = (0..6).map(|i| row(&format!("s{i}"))).collect();
        let results = write_rows(
            rows,
            ItemEvents::for_request(Action::SecretImport, None),
            Deadlines::STANDARD,
            |r: PendingSecret| async move {
                if r.name == "s3" {
                    Err(AzureError::Status {
                        status: 403,
                        code: None,
                        message: None,
                    })
                } else {
                    Ok(())
                }
            },
        )
        .await;
        let kinds: Vec<Written> = results.iter().map(|r| r.0).collect();
        assert_eq!(
            kinds,
            [
                Written::Created,
                Written::Created,
                Written::Created,
                Written::Denied,
                Written::Created,
                Written::Created
            ]
        );
    }

    #[test]
    fn outcomes() {
        let st = |status| {
            Err(AzureError::Status {
                status,
                code: None,
                message: Some("private detail".into()),
            })
        };
        assert_eq!(outcome_of(&Ok(()), false).0, Written::Created);
        assert_eq!(outcome_of(&Ok(()), true).0, Written::NewVersion);
        assert_eq!(outcome_of(&st(409), false).0, Written::BlockedDeleted);
        assert_eq!(outcome_of(&st(403), false).0, Written::Denied);
        let (r, why) = outcome_of(&st(500), false);
        assert_eq!(r, Written::Failed);
        assert!(!why.contains("private detail"), "never Azure's message");
    }
}
