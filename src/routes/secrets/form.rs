//! Parsing and checking the create and edit forms. Pure functions, so the
//! rules are easy to test. The one side effect: a value refused by
//! `KEYRING_PASSWORD_POLICY` marks the request's audit event with the
//! fixed reason code `password_policy` (a no-op outside a request).

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::azure::secrets::{
    Attributes, DateChange, SecretItem, SetSecret, UpdateAttributes, UpdateSecret,
};
use crate::dates;
use crate::description;
use crate::owner;
use crate::password_policy::PasswordPolicy;
use crate::routes::forms::{FieldError, FieldErrors, name_problem};
use crate::routes::lifecycle::Kind;
use crate::routes::tag_rows::{self, TagPost};
use crate::secret::Secret;
use crate::secret_types::{ContentKind, SecretType, TypedValue, classify};

/// Most tags Key Vault allows on one item, the description included.
pub(crate) const MAX_TAGS: usize = crate::description::MAX_TAGS;
/// Longest tag name and value Key Vault takes, in characters.
pub(crate) const MAX_TAG_NAME: usize = 512;
pub(crate) const MAX_TAG_VALUE: usize = 256;
/// Key Vault's limit on a secret value (25 KB).
pub(crate) const MAX_VALUE_BYTES: usize = 25 * 1024;
pub(crate) const MAX_CONTENT_TYPE: usize = 255;

/// What the create and edit-properties forms post. Strings, because HTML
/// forms send strings and a missing checkbox sends nothing.
#[derive(Deserialize, Default)]
pub(crate) struct SecretForm {
    #[serde(default)]
    pub csrf: String,
    #[serde(default)]
    pub name: String,
    /// Only on create and "new value" forms.
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub content_type: String,
    /// `YYYY-MM-DD` or empty.
    #[serde(default)]
    pub expires: String,
    /// `YYYY-MM-DD` or empty.
    #[serde(default)]
    pub not_before: String,
    /// The tag rows. Never holds the `description` tag.
    #[serde(flatten)]
    pub tag_rows: TagPost,
    /// The note, kept in the `description` tag. Empty removes it.
    #[serde(default)]
    pub description: String,
    /// The `owner` tag. Empty removes it; not posted keeps it.
    #[serde(default)]
    pub owner: Option<String>,
    /// The `notify` tag. Empty removes it; not posted keeps it.
    #[serde(default)]
    pub notify: Option<String>,
    /// The reveal limit (`keyring-reveal`): empty, `copy-only`, `none` or
    /// `keep`. Not posted keeps it.
    #[serde(default)]
    pub reveal: Option<String>,
    /// A reason and ticket, asked for when the reveal limit is loosened.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ticket: String,
    /// Checkbox: present means on.
    #[serde(default)]
    pub enabled: Option<String>,
    /// Edit form only: the version the form was opened on.
    #[serde(default)]
    pub version: String,
    /// Edit form only: that version's `updated` time, in Unix seconds.
    #[serde(default)]
    pub updated: String,
    /// Create form only: `login`, `database`, `api-key`, `ssh-key`, or
    /// empty for a plain value. "Set a new value" takes the type from the
    /// secret instead.
    #[serde(default)]
    pub secret_type: String,
    /// The fields of a typed secret. Every one is part of the value, so
    /// each is read straight into a `Secret`.
    #[serde(flatten)]
    pub fields: TypedFields,
}

/// Every field name a built-in type uses. Values are never echoed back
/// into a page or printed.
#[derive(Deserialize, Default)]
pub(crate) struct TypedFields {
    #[serde(default)]
    url: Option<Secret>,
    #[serde(default)]
    username: Option<Secret>,
    #[serde(default)]
    password: Option<Secret>,
    #[serde(default)]
    notes: Option<Secret>,
    #[serde(default)]
    server: Option<Secret>,
    #[serde(default)]
    database: Option<Secret>,
    #[serde(default)]
    key: Option<Secret>,
    #[serde(default)]
    endpoint: Option<Secret>,
    #[serde(default)]
    host: Option<Secret>,
    #[serde(default)]
    private_key: Option<Secret>,
    #[serde(default)]
    passphrase: Option<Secret>,
}

impl TypedFields {
    fn get(&self, name: &str) -> Option<Secret> {
        match name {
            "url" => self.url.clone(),
            "username" => self.username.clone(),
            "password" => self.password.clone(),
            "notes" => self.notes.clone(),
            "server" => self.server.clone(),
            "database" => self.database.clone(),
            "key" => self.key.clone(),
            "endpoint" => self.endpoint.clone(),
            "host" => self.host.clone(),
            "private_key" => self.private_key.clone(),
            "passphrase" => self.passphrase.clone(),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set(&mut self, name: &str, value: &str) {
        let v = Some(Secret::new(value));
        match name {
            "url" => self.url = v,
            "username" => self.username = v,
            "password" => self.password = v,
            "notes" => self.notes = v,
            "server" => self.server = v,
            "database" => self.database = v,
            "key" => self.key = v,
            "endpoint" => self.endpoint = v,
            "host" => self.host = v,
            "private_key" => self.private_key = v,
            "passphrase" => self.passphrase = v,
            _ => panic!("no field {name}"),
        }
    }
}

impl SecretForm {
    /// The type chosen on the create form. `Err` for a type that doesn't
    /// exist.
    pub(crate) fn chosen_type(&self) -> Result<Option<SecretType>, ()> {
        match self.secret_type.trim() {
            "" | "password" => Ok(None),
            s => SecretType::from_slug(s).map(Some).ok_or(()),
        }
    }
}

impl std::fmt::Debug for SecretForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretForm")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

/// Said when `description` is typed as an ordinary tag name.
pub(crate) const DESCRIPTION_IS_A_FIELD: &str =
    "The description tag is set with the Description field. Put the note there, not in Tags.";

fn parse_date(field: &'static str, raw: &str, label: &str) -> Result<Option<i64>, FieldError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    dates::parse_iso_date(raw)
        .map(Some)
        .ok_or_else(|| FieldError {
            field,
            message: format!("{label} isn't a real date. Use the date picker or type YYYY-MM-DD."),
        })
}

/// One tag from the bulk change form, checked against the same limits as
/// the tag rows. Returns the trimmed name and value.
pub(crate) fn one_tag(name: &str, value: &str) -> Result<(String, String), String> {
    let (k, v) = (name.trim(), value.trim());
    if k.is_empty() {
        return Err("Give the tag a name.".into());
    }
    if description::is_reserved(k) {
        return Err(
            "The description tag has its own changes in the list: Set the description, or Remove the description."
                .into(),
        );
    }
    if owner::is_reserved(k) {
        return Err(
            "The owner and notify tags have their own changes in the list: Set the owner, Remove the owner, Set notify, or Remove notify."
                .into(),
        );
    }
    if crate::reveal_limit::is_tag(k) {
        crate::audit::refuse(crate::audit::Refusal::RevealLimited);
        return Err(
            "The keyring-reveal tag can't be changed in bulk. Set the reveal limit on each item's Edit details, where loosening it is checked and recorded."
                .into(),
        );
    }
    if k.contains(['\n', '\r']) || v.contains(['\n', '\r']) {
        return Err("A tag can't have a line break in it.".into());
    }
    if k.len() > MAX_TAG_NAME || v.len() > MAX_TAG_VALUE {
        return Err(format!(
            "That tag is too long. Tag names can be {MAX_TAG_NAME} characters and values {MAX_TAG_VALUE}."
        ));
    }
    Ok((k.to_owned(), v.to_owned()))
}

/// An expiry date from a form: the end of the chosen day, UTC, which
/// must be after `now`. Required, since Key Vault can't remove a date.
pub(crate) fn new_expiry(raw: &str, now: i64) -> Result<i64, String> {
    let day = parse_date("expires", raw, "Expiry date")
        .map_err(|e| e.message)?
        .ok_or("Choose an expiry date. Key Vault can't remove one, only set or change it.")?;
    let exp = day + 86_399;
    if exp <= now {
        return Err("The expiry date has already passed. Pick a later date.".into());
    }
    Ok(exp)
}

/// Everything except the value, checked.
pub(crate) struct Properties {
    pub content_type: Option<String>,
    pub attributes: Attributes,
    pub tags: BTreeMap<String, String>,
}

/// A date from the form, kept at the current version's exact time when the
/// calendar day is the same. The form only shows days, so without this an
/// expiry at 10:00 would move to the end of the day on every save.
fn same_day(current: Option<i64>, wanted: Option<i64>) -> Option<i64> {
    match (current, wanted) {
        (Some(c), Some(w)) if c.div_euclid(86_400) == w.div_euclid(86_400) => Some(c),
        _ => wanted,
    }
}

fn properties(
    form: &SecretForm,
    now: i64,
    current: Option<&Attributes>,
    current_tags: &BTreeMap<String, String>,
    rules: owner::Rules<'_>,
    errors: &mut FieldErrors,
) -> Properties {
    let content_type = form.content_type.trim();
    if content_type.len() > MAX_CONTENT_TYPE {
        errors.push("content_type", "Content type can be up to 255 characters.");
    }
    let expires = parse_date("expires", &form.expires, "Expiry date").unwrap_or_else(|e| {
        errors.push(e.field, e.message);
        None
    });
    let not_before = parse_date("not_before", &form.not_before, "Start date").unwrap_or_else(|e| {
        errors.push(e.field, e.message);
        None
    });
    // Expiry is end of the chosen day, so "expires 1 March" works all of
    // 1 March. A day that matches the current version keeps its exact time.
    let expires = same_day(current.and_then(|c| c.expires), expires.map(|d| d + 86_399));
    let not_before = same_day(current.and_then(|c| c.not_before), not_before);
    if let Some(exp) = expires
        && exp <= now
    {
        errors.push(
            "expires",
            "The expiry date has already passed. Pick a later date, or leave it blank.",
        );
    }
    if let (Some(exp), Some(nbf)) = (expires, not_before)
        && nbf >= exp
    {
        errors.push(
            "not_before",
            "The start date needs to be before the expiry date.",
        );
    }
    let tags = tag_rows::check(&form.tag_rows, current_tags, errors);
    let tags = with_fields(
        &tags,
        current_tags,
        &form.description,
        form.owners(),
        rules,
        errors,
    );
    let tags =
        crate::reveal_limit::merge_posted(&tags, current_tags, form.reveal.as_deref(), errors);
    Properties {
        content_type: (!content_type.is_empty()).then(|| content_type.to_owned()),
        attributes: Attributes {
            enabled: Some(form.enabled.is_some()),
            expires,
            not_before,
            ..Attributes::default()
        },
        tags,
    }
}

impl SecretForm {
    pub(crate) fn owners(&self) -> owner::Posted<'_> {
        owner::Posted {
            owner: self.owner.as_deref(),
            notify: self.notify.as_deref(),
        }
    }
}

/// The tags from the rows with the posted owner, notify and description
/// merged in ([`crate::owner::with_owners`], then the note). `current` is
/// the item's tags as they are, empty for a new item. A problem goes on its
/// field: `owner`, `notify` or `description`.
pub(crate) fn with_fields(
    tags: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
    note: &str,
    owners: owner::Posted<'_>,
    rules: owner::Rules<'_>,
    errors: &mut FieldErrors,
) -> BTreeMap<String, String> {
    let tags = owner::with_owners(tags, current, owners, rules, errors);
    match description::clean(note).and_then(|n| description::merge(&tags, n.as_deref())) {
        Ok(t) => t,
        Err(m) => {
            errors.push("description", m);
            tags
        }
    }
}

fn checked_value(
    form: &SecretForm,
    policy: &PasswordPolicy,
    errors: &mut FieldErrors,
) -> Option<Secret> {
    // Keep the value as typed, spaces included, except line breaks.
    // Browsers send a textarea's line breaks as CRLF whatever was pasted,
    // so store LF, which is what PEM files and .env blocks expect.
    let value = form.value.as_deref().map(normalise_newlines);
    match value {
        None => {
            errors.push("value", "Enter a value.");
            None
        }
        Some(v) if v.is_empty() => {
            errors.push("value", "Enter a value.");
            None
        }
        Some(v) if v.len() > MAX_VALUE_BYTES => {
            errors.push("value", "Values can be up to 25 KB.");
            None
        }
        Some(v) => {
            // A plain value is a Password, so the policy applies.
            let v = Secret::new(v);
            match policy.check("Value", &v) {
                Some(problem) => {
                    crate::audit::refuse(crate::audit::Refusal::PasswordPolicy);
                    errors.push("value", problem);
                    None
                }
                None => Some(v),
            }
        }
    }
}

/// The value of a typed secret, checked field by field.
fn checked_typed(
    kind: SecretType,
    form: &SecretForm,
    policy: &PasswordPolicy,
    errors: &mut FieldErrors,
) -> Option<Secret> {
    match TypedValue::check(kind, |n| form.fields.get(n)) {
        Ok(v) => match v.policy_problem(policy) {
            Some((field, problem)) => {
                crate::audit::refuse(crate::audit::Refusal::PasswordPolicy);
                errors.push(field, problem);
                None
            }
            None => Some(v.encode()),
        },
        Err(problems) => {
            for (field, message) in problems {
                errors.push(field, message);
            }
            None
        }
    }
}

/// A Keyring content type typed by hand would mark a value Keyring didn't
/// build. Refused, unless it is the one the secret already has.
fn keyring_type_typed(posted: Option<&str>, current: Option<&str>, errors: &mut FieldErrors) {
    if classify(posted) != ContentKind::Plain && posted != current {
        errors.push(
            "content_type",
            "Content types starting with application/vnd.keyring. are Keyring's own secret types. To make one, choose its type when you create the secret.",
        );
    }
}

/// CRLF to LF. A lone CR is left alone.
pub(crate) fn normalise_newlines(v: &str) -> String {
    v.replace("\r\n", "\n")
}

/// Check a create form. Gives the name and a body that sets a value. The
/// type is the one posted in `secret_type`, and is what the secret is
/// saved and shown as, so the password policy follows it.
pub(crate) fn for_create(
    form: &SecretForm,
    now: i64,
    policy: &PasswordPolicy,
    rules: owner::Rules<'_>,
) -> Result<(String, SetSecret), FieldErrors> {
    let mut errors = FieldErrors::new();
    let name = form.name.trim().to_owned();
    if let Some(m) = name_problem(Kind::Secret, &name) {
        errors.push("name", m);
    }
    let kind = form.chosen_type().unwrap_or_else(|()| {
        errors.push("secret_type", "Choose a type of secret from the list.");
        None
    });
    let value = match kind {
        Some(kind) => checked_typed(kind, form, policy, &mut errors),
        None => checked_value(form, policy, &mut errors),
    };
    let mut props = properties(form, now, None, &BTreeMap::new(), rules, &mut errors);
    match kind {
        Some(kind) => props.content_type = Some(kind.content_type()),
        None => keyring_type_typed(props.content_type.as_deref(), None, &mut errors),
    }
    match value {
        Some(value) if errors.is_empty() => Ok((
            name,
            SetSecret {
                value,
                content_type: props.content_type,
                attributes: props.attributes,
                tags: Some(props.tags),
            },
        )),
        _ => Err(errors),
    }
}

/// Check a "new value" form against the current version. Setting a value
/// always makes a new version. Dates on the same day as the current ones
/// keep their exact times, and tags a row can't show are carried over as
/// they are. The type comes from the secret, never the post, so the
/// password policy follows what the secret is.
pub(crate) fn for_new_value(
    form: &SecretForm,
    current: &SecretItem,
    now: i64,
    policy: &PasswordPolicy,
    rules: owner::Rules<'_>,
) -> Result<SetSecret, FieldErrors> {
    let mut errors = FieldErrors::new();
    let current_ct = current.content_type.as_deref();
    let value = match classify(current_ct) {
        ContentKind::Typed(kind) => checked_typed(kind, form, policy, &mut errors),
        _ => checked_value(form, policy, &mut errors),
    };
    let mut props = properties(
        form,
        now,
        Some(&current.attributes),
        current.tags(),
        rules,
        &mut errors,
    );
    if let ContentKind::Typed(_) = classify(current_ct) {
        // A typed secret stays typed, with its content type as it is.
        errors.retain(|e| e.field != "content_type");
        props.content_type = current.content_type.clone();
    } else {
        keyring_type_typed(props.content_type.as_deref(), current_ct, &mut errors);
    }
    match value {
        Some(value) if errors.is_empty() => Ok(SetSecret {
            value,
            content_type: props.content_type,
            attributes: props.attributes,
            tags: Some(props.tags),
        }),
        _ => Err(errors),
    }
}

pub(crate) const REMOVE_EXPIRY: &str = "Key Vault can't remove the expiry date from a version. To have no expiry, set a new value and leave Expires blank. Or pick a later date.";
pub(crate) const REMOVE_START: &str = "Key Vault can't remove the start date from a version. To have none, set a new value and leave Active from blank.";

/// Check an edit-properties form against the current version. The body
/// has no value, so this can never create a new version. Dates that didn't
/// change are left out. A removed date is refused: Key Vault keeps a
/// version's dates even when sent `null`, so only a new value can drop
/// one. Tags are only sent when they changed. Tags a row can't show are
/// kept as they are.
pub(crate) fn for_update(
    form: &SecretForm,
    item: &SecretItem,
    now: i64,
    rules: owner::Rules<'_>,
) -> Result<UpdateSecret, FieldErrors> {
    let current = &item.attributes;
    let mut errors = FieldErrors::new();
    // An expiry that's already passed but wasn't touched isn't an error.
    let props = properties(form, now, Some(current), item.tags(), rules, &mut errors);
    let typed = matches!(
        classify(item.content_type.as_deref()),
        ContentKind::Typed(_)
    );
    if typed {
        errors.retain(|e| e.field != "content_type");
    } else {
        keyring_type_typed(
            props.content_type.as_deref(),
            item.content_type.as_deref(),
            &mut errors,
        );
    }
    let expires = DateChange::between(current.expires, props.attributes.expires);
    if expires == Some(DateChange::Keep) {
        errors.retain(|e| e.field != "expires" || !e.message.contains("already passed"));
    }
    if expires.is_none() {
        errors.push("expires", REMOVE_EXPIRY);
    }
    let not_before = DateChange::between(current.not_before, props.attributes.not_before);
    if not_before.is_none() {
        errors.push("not_before", REMOVE_START);
    }
    match (expires, not_before) {
        (Some(expires), Some(not_before)) if errors.is_empty() => Ok(UpdateSecret {
            // Send an empty string to clear a content type that was
            // removed. A typed secret's is never sent, so it stays typed.
            content_type: (!typed).then(|| props.content_type.unwrap_or_default()),
            attributes: UpdateAttributes {
                enabled: props.attributes.enabled,
                not_before,
                expires,
            },
            tags: (props.tags != *item.tags()).then_some(props.tags),
        }),
        _ => Err(errors),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;
    const R: owner::Rules<'static> = owner::Rules::OFF;
    const OFF: PasswordPolicy = PasswordPolicy {
        min: None,
        upper: false,
        lower: false,
        digit: false,
        symbol: false,
        max_repeat: None,
        common: false,
    };

    fn item(attributes: Attributes, tags: &[(&str, &str)]) -> SecretItem {
        SecretItem {
            id: "https://kv.vault.azure.net/secrets/db-password/0123456789abcdef0123456789abcdef"
                .into(),
            attributes,
            tags: Some(
                tags.iter()
                    .map(|(k, v)| ((*k).into(), (*v).into()))
                    .collect(),
            ),
            content_type: None,
            managed: None,
        }
    }

    fn form() -> SecretForm {
        SecretForm {
            csrf: "t".into(),
            name: "db-password".into(),
            value: Some("hunter2".into()),
            enabled: Some("on".into()),
            ..SecretForm::default()
        }
    }

    #[test]
    fn create_builds_a_set_body() {
        let mut f = form();
        f.expires = "2027-01-31".into();
        f.tag_rows = TagPost::rows(&[("env", "prod"), ("", ""), ("team", "data"), ("flag", "")]);
        f.content_type = " text/plain ".into();
        let (name, body) = for_create(&f, NOW, &OFF, R).unwrap();
        assert_eq!(name, "db-password");
        assert_eq!(body.value.expose(), "hunter2");
        assert_eq!(body.content_type.as_deref(), Some("text/plain"));
        assert_eq!(body.attributes.enabled, Some(true));
        let exp = body.attributes.expires.unwrap();
        assert_eq!(crate::dates::iso_date(exp), "2027-01-31");
        let tags = body.tags.unwrap();
        assert_eq!(tags.get("team").map(String::as_str), Some("data"));
        assert_eq!(tags.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn value_is_kept_exactly() {
        let mut f = form();
        f.value = Some("  spaced value \n".into());
        let (_, body) = for_create(&f, NOW, &OFF, R).unwrap();
        assert_eq!(body.value.expose(), "  spaced value \n");
    }

    #[test]
    fn create_collects_every_problem() {
        let mut f = form();
        f.name = "bad name".into();
        f.value = Some(String::new());
        f.expires = "2020-01-01".into();
        f.tag_rows = TagPost::rows(&[("", "oops")]);
        let errors = for_create(&f, NOW, &OFF, R).err().unwrap();
        let fields: Vec<_> = errors.iter().map(|e| e.field).collect();
        assert_eq!(fields, vec!["name", "value", "expires", "tag-name-1"]);
    }

    #[test]
    fn dates_are_checked() {
        let mut f = form();
        f.expires = "2027-02-30".into();
        assert!(for_create(&f, NOW, &OFF, R).is_err());
        f.expires = "2027-03-01".into();
        f.not_before = "2027-03-02".into();
        let e = for_create(&f, NOW, &OFF, R).err().unwrap();
        assert_eq!(e[0].field, "not_before");
    }

    #[test]
    fn unchecked_box_disables() {
        let mut f = form();
        f.enabled = None;
        let (_, body) = for_create(&f, NOW, &OFF, R).unwrap();
        assert_eq!(body.attributes.enabled, Some(false));
    }

    #[test]
    fn update_keeps_untouched_dates_exactly() {
        // Expires at 10:00 UTC on 2027-02-06; the form shows that day.
        let current = Attributes {
            expires: Some(1_801_908_000),
            enabled: Some(true),
            ..Attributes::default()
        };
        let mut f = form();
        f.expires = "2027-02-06".into();
        f.tag_rows = TagPost::rows(&[("env", "prod")]);
        let current = item(current, &[]);
        let body = for_update(&f, &current, NOW, R).unwrap();
        let j = serde_json::to_value(&body).unwrap();
        assert!(
            j["attributes"].get("exp").is_none(),
            "unchanged expiry not sent"
        );
        f.expires = String::new();
        let errors = for_update(&f, &current, NOW, R).unwrap_err();
        assert_eq!(
            errors.error_for("expires"),
            Some(REMOVE_EXPIRY),
            "can't remove"
        );
        // A new value without the date drops it.
        f.value = Some("new".into());
        let body = for_new_value(&f, &current, NOW, &OFF, R).unwrap();
        assert_eq!(body.attributes.expires, None);
        // An expiry that passed earlier today, left alone, doesn't block other edits.
        let past = Attributes {
            expires: Some(NOW - 60),
            ..Attributes::default()
        };
        let mut f = form();
        f.expires = crate::dates::iso_date(NOW - 60);
        assert!(for_update(&f, &item(past, &[]), NOW, R).is_ok());
    }

    #[test]
    fn update_never_has_a_value() {
        let mut f = form();
        f.value = Some("should be ignored".into());
        let body = for_update(&f, &item(Attributes::default(), &[]), NOW, R).unwrap();
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("value").is_none());
        assert_eq!(json["contentType"], "");
    }

    #[test]
    fn line_breaks_become_lf() {
        let mut f = form();
        f.value = Some("\na\r\nb\r\n".into());
        let (_, body) = for_create(&f, NOW, &OFF, R).unwrap();
        assert_eq!(body.value.expose(), "\na\nb\n");
        // A value right at 25 KB once CRLF is LF isn't refused for its CRs.
        let line = "x".repeat(1023);
        f.value = Some(vec![line.as_str(); 25].join("\r\n") + "\r\n");
        assert!(for_create(&f, NOW, &OFF, R).is_ok());
    }

    #[test]
    fn update_sends_tags_only_when_changed() {
        let current = item(Attributes::default(), &[("env", "prod")]);
        let mut f = form();
        f.tag_rows = TagPost::rows(&[("env", "prod")]);
        let body = for_update(&f, &current, NOW, R).unwrap();
        assert!(body.tags.is_none(), "unchanged tags not sent");
        f.tag_rows = TagPost::rows(&[("env", "test")]);
        let body = for_update(&f, &current, NOW, R).unwrap();
        assert_eq!(body.tags.unwrap()["env"], "test");
    }

    #[test]
    fn tags_the_form_cant_show_are_never_rewritten() {
        let odd = item(
            Attributes::default(),
            &[("note", "two\nlines"), ("a=b", " c ")],
        );
        let mut f = form();
        // The form shows a row for a=b, and lists the other.
        f.tag_rows = TagPost::rows(&[("a=b", " c ")]);
        let body = for_update(&f, &odd, NOW, R).unwrap();
        assert!(body.tags.is_none());
        let body = for_new_value(&f, &odd, NOW, &OFF, R).unwrap();
        let tags = body.tags.unwrap();
        assert_eq!(tags["a=b"], " c ");
        assert_eq!(tags["note"], "two\nlines");
        // Clearing the row removes that tag only.
        f.tag_rows = TagPost::rows(&[]);
        let tags = for_update(&f, &odd, NOW, R).unwrap().tags.unwrap();
        assert_eq!(tags.keys().collect::<Vec<_>>(), ["note"]);
    }

    #[test]
    fn new_value_keeps_exact_times_on_the_same_day() {
        let day = 86_400;
        let midnight = (NOW / day + 100) * day;
        let current = item(
            Attributes {
                expires: Some(midnight + 10 * 3600),
                not_before: Some(midnight - 30 * day + 9 * 3600),
                ..Attributes::default()
            },
            &[],
        );
        let mut f = form();
        f.expires = crate::dates::iso_date(midnight);
        f.not_before = crate::dates::iso_date(midnight - 30 * day);
        let body = for_new_value(&f, &current, NOW, &OFF, R).unwrap();
        assert_eq!(body.attributes.expires, Some(midnight + 10 * 3600));
        assert_eq!(
            body.attributes.not_before,
            Some(midnight - 30 * day + 9 * 3600)
        );
        // A different day is taken as chosen: end of day for expiry.
        f.expires = crate::dates::iso_date(midnight + day);
        let body = for_new_value(&f, &current, NOW, &OFF, R).unwrap();
        assert_eq!(body.attributes.expires, Some(midnight + 2 * day - 1));
    }

    fn typed_form(kind: &str, fields: &[(&str, &str)]) -> SecretForm {
        let mut f = form();
        f.value = None;
        f.secret_type = kind.into();
        for (k, v) in fields {
            f.fields.set(k, v);
        }
        f
    }

    #[test]
    fn typed_create_sets_json_and_content_type() {
        let f = typed_form(
            "login",
            &[
                ("url", "https://a.test"),
                ("username", "u"),
                ("password", "p\"w"),
            ],
        );
        let (_, body) = for_create(&f, NOW, &OFF, R).unwrap();
        assert_eq!(
            body.content_type.as_deref(),
            Some("application/vnd.keyring.login+json;v=1")
        );
        assert_eq!(
            body.value.expose(),
            r#"{"url":"https://a.test","username":"u","password":"p\"w","notes":""}"#
        );
        // A typed content type typed by hand is ignored for a typed form.
        let mut f2 = typed_form("api-key", &[("key", "k")]);
        f2.content_type = "text/plain".into();
        let (_, body) = for_create(&f2, NOW, &OFF, R).unwrap();
        assert_eq!(
            body.content_type.as_deref(),
            Some("application/vnd.keyring.api-key+json;v=1")
        );
    }

    #[test]
    fn typed_create_reports_each_field() {
        let f = typed_form("database", &[("server", "s")]);
        let e = for_create(&f, NOW, &OFF, R).unwrap_err();
        let fields: Vec<_> = e.iter().map(|e| e.field).collect();
        assert_eq!(fields, ["username", "password"]);
        let e = for_create(&typed_form("wifi", &[]), NOW, &OFF, R).unwrap_err();
        assert_eq!(e[0].field, "secret_type");
    }

    #[test]
    fn keyring_content_types_cant_be_typed_by_hand() {
        let mut f = form();
        f.content_type = "application/vnd.keyring.login+json;v=1".into();
        let e = for_create(&f, NOW, &OFF, R).unwrap_err();
        assert_eq!(e[0].field, "content_type");
        // On a plain secret's edit form too.
        let e = for_update(&f, &item(Attributes::default(), &[]), NOW, R).unwrap_err();
        assert_eq!(e[0].field, "content_type");
    }

    #[test]
    fn typed_secrets_stay_typed() {
        let ct = "application/vnd.keyring.api-key+json;v=1";
        let mut current = item(Attributes::default(), &[]);
        current.content_type = Some(ct.into());
        // A new value takes the fields, and keeps the content type
        // whatever the form posted.
        let mut f = typed_form("", &[("key", "new-key")]);
        f.content_type = "text/plain".into();
        let body = for_new_value(&f, &current, NOW, &OFF, R).unwrap();
        assert_eq!(body.content_type.as_deref(), Some(ct));
        assert!(body.value.expose().contains("new-key"));
        // A plain value box doesn't count for a typed secret.
        let mut f = form();
        f.value = Some("plain".into());
        let e = for_new_value(&f, &current, NOW, &OFF, R).unwrap_err();
        assert_eq!(e[0].field, "key");
        // Edit details never sends the content type.
        let body = for_update(&form(), &current, NOW, R).unwrap();
        assert!(body.content_type.is_none());
    }

    #[test]
    fn owner_fields_follow_the_rules() {
        let mut f = form();
        f.owner = Some("Alex@Example.com".into());
        f.notify = Some("sam@example.com, team@example.com".into());
        let (_, body) = for_create(&f, NOW, &OFF, R).unwrap();
        let tags = body.tags.unwrap();
        assert_eq!(tags["owner"], "Alex@example.com");
        assert_eq!(tags["notify"], "sam@example.com, team@example.com");
        // The policy, on create and on each edit form.
        let on = owner::Rules {
            allowed: None,
            require: true,
        };
        f.owner = Some(String::new());
        let e = for_create(&f, NOW, &OFF, on).unwrap_err();
        assert_eq!(e.error_for("owner"), Some(owner::OWNER_NEEDED));
        let bare = item(Attributes::default(), &[]);
        assert!(
            for_update(&f, &bare, NOW, on)
                .unwrap_err()
                .error_for("owner")
                .is_some()
        );
        f.value = Some("v".into());
        assert!(
            for_new_value(&f, &bare, NOW, &OFF, on)
                .unwrap_err()
                .error_for("owner")
                .is_some()
        );
        // An untouched odd owner set elsewhere doesn't block an edit.
        let odd = item(Attributes::default(), &[("owner", "Payments Team")]);
        f.owner = Some("Payments Team".into());
        f.notify = Some(String::new());
        let body = for_update(&f, &odd, NOW, on).unwrap();
        assert!(body.tags.is_none(), "nothing changed, nothing sent");
    }

    #[test]
    fn debug_hides_value() {
        assert!(!format!("{:?}", form()).contains("hunter2"));
    }
}
