//! Parsing and checking the create and edit forms. Pure functions, so the
//! rules are easy to test.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::azure::secrets::{
    Attributes, DateChange, SecretItem, SetSecret, UpdateAttributes, UpdateSecret,
};
use crate::dates;
use crate::routes::forms::{FieldError, FieldErrors, name_problem};
use crate::routes::lifecycle::Kind;
use crate::secret::Secret;

/// Most tags Key Vault allows on one secret.
pub(crate) const MAX_TAGS: usize = 15;
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
    /// One `key=value` per line.
    #[serde(default)]
    pub tags: String,
    /// Checkbox: present means on.
    #[serde(default)]
    pub enabled: Option<String>,
    /// Edit form only: the version the form was opened on.
    #[serde(default)]
    pub version: String,
    /// Edit form only: that version's `updated` time, in Unix seconds.
    #[serde(default)]
    pub updated: String,
}

impl std::fmt::Debug for SecretForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretForm")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

/// Can these tags go through the `name=value` textarea and come back the
/// same? Not if a name has an `=`, either side has a line break, or either
/// side starts or ends with a space, because parsing trims and splits.
pub(crate) fn tags_editable(tags: &BTreeMap<String, String>) -> bool {
    let clean = |s: &str| s == s.trim() && !s.contains(['\n', '\r']);
    tags.iter()
        .all(|(k, v)| !k.is_empty() && !k.contains('=') && clean(k) && clean(v))
}

/// Parse tag lines. Blank lines are skipped. A name given twice is an
/// error, so nothing is dropped without a word.
pub(crate) fn parse_tags(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let mut tags = BTreeMap::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() {
            return Err(format!("Line {} has no tag name before the =.", i + 1));
        }
        if k.len() > 512 || v.len() > 256 {
            return Err(format!(
                "Line {} is too long. Tag names can be 512 characters and values 256.",
                i + 1
            ));
        }
        if tags.insert(k.to_owned(), v.to_owned()).is_some() {
            return Err(format!(
                "Line {} repeats the tag name {k}. Each name can only be used once.",
                i + 1
            ));
        }
    }
    if tags.len() > MAX_TAGS {
        return Err(format!(
            "Key Vault allows up to {MAX_TAGS} tags. This has {}.",
            tags.len()
        ));
    }
    Ok(tags)
}

/// Tags back into the textarea format.
pub(crate) fn format_tags(tags: &BTreeMap<String, String>) -> String {
    tags.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

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
    let tags = parse_tags(&form.tags).unwrap_or_else(|m| {
        errors.push("tags", m);
        BTreeMap::new()
    });
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

fn checked_value(form: &SecretForm, errors: &mut FieldErrors) -> Option<Secret> {
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
        Some(v) => Some(Secret::new(v)),
    }
}

/// CRLF to LF. A lone CR is left alone.
pub(crate) fn normalise_newlines(v: &str) -> String {
    v.replace("\r\n", "\n")
}

/// Check a create form. Gives the name and a body that sets a value.
pub(crate) fn for_create(form: &SecretForm, now: i64) -> Result<(String, SetSecret), FieldErrors> {
    let mut errors = FieldErrors::new();
    let name = form.name.trim().to_owned();
    if let Some(m) = name_problem(Kind::Secret, &name) {
        errors.push("name", m);
    }
    let value = checked_value(form, &mut errors);
    let props = properties(form, now, None, &mut errors);
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
/// keep their exact times, and tags the form can't show are carried over
/// as they are.
pub(crate) fn for_new_value(
    form: &SecretForm,
    current: &SecretItem,
    now: i64,
) -> Result<SetSecret, FieldErrors> {
    let mut errors = FieldErrors::new();
    let value = checked_value(form, &mut errors);
    let mut props = properties(form, now, Some(&current.attributes), &mut errors);
    if !tags_editable(current.tags()) {
        errors.retain(|e| e.field != "tags");
        props.tags = current.tags().clone();
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
/// one. Tags are only sent when they changed, and never when the form
/// can't show them.
pub(crate) fn for_update(
    form: &SecretForm,
    item: &SecretItem,
    now: i64,
) -> Result<UpdateSecret, FieldErrors> {
    let current = &item.attributes;
    let mut errors = FieldErrors::new();
    let editable = tags_editable(item.tags());
    // An expiry that's already passed but wasn't touched isn't an error.
    let props = properties(form, now, Some(current), &mut errors);
    if !editable {
        errors.retain(|e| e.field != "tags");
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
            // Send an empty string to clear a content type that was removed.
            content_type: Some(props.content_type.unwrap_or_default()),
            attributes: UpdateAttributes {
                enabled: props.attributes.enabled,
                not_before,
                expires,
            },
            tags: (editable && props.tags != *item.tags()).then_some(props.tags),
        }),
        _ => Err(errors),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

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
        f.tags = "env=prod\n\nteam = data \nflag".into();
        f.content_type = " text/plain ".into();
        let (name, body) = for_create(&f, NOW).unwrap();
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
        let (_, body) = for_create(&f, NOW).unwrap();
        assert_eq!(body.value.expose(), "  spaced value \n");
    }

    #[test]
    fn create_collects_every_problem() {
        let mut f = form();
        f.name = "bad name".into();
        f.value = Some(String::new());
        f.expires = "2020-01-01".into();
        f.tags = "=oops".into();
        let errors = for_create(&f, NOW).err().unwrap();
        let fields: Vec<_> = errors.iter().map(|e| e.field).collect();
        assert_eq!(fields, vec!["name", "value", "expires", "tags"]);
    }

    #[test]
    fn dates_are_checked() {
        let mut f = form();
        f.expires = "2027-02-30".into();
        assert!(for_create(&f, NOW).is_err());
        f.expires = "2027-03-01".into();
        f.not_before = "2027-03-02".into();
        let e = for_create(&f, NOW).err().unwrap();
        assert_eq!(e[0].field, "not_before");
    }

    #[test]
    fn unchecked_box_disables() {
        let mut f = form();
        f.enabled = None;
        let (_, body) = for_create(&f, NOW).unwrap();
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
        f.tags = "env=prod".into();
        let current = item(current, &[]);
        let body = for_update(&f, &current, NOW).unwrap();
        let j = serde_json::to_value(&body).unwrap();
        assert!(
            j["attributes"].get("exp").is_none(),
            "unchanged expiry not sent"
        );
        f.expires = String::new();
        let errors = for_update(&f, &current, NOW).unwrap_err();
        assert_eq!(
            errors.error_for("expires"),
            Some(REMOVE_EXPIRY),
            "can't remove"
        );
        // A new value without the date drops it.
        f.value = Some("new".into());
        let body = for_new_value(&f, &current, NOW).unwrap();
        assert_eq!(body.attributes.expires, None);
        // An expiry that passed earlier today, left alone, doesn't block other edits.
        let past = Attributes {
            expires: Some(NOW - 60),
            ..Attributes::default()
        };
        let mut f = form();
        f.expires = crate::dates::iso_date(NOW - 60);
        assert!(for_update(&f, &item(past, &[]), NOW).is_ok());
    }

    #[test]
    fn update_never_has_a_value() {
        let mut f = form();
        f.value = Some("should be ignored".into());
        let body = for_update(&f, &item(Attributes::default(), &[]), NOW).unwrap();
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("value").is_none());
        assert_eq!(json["contentType"], "");
    }

    #[test]
    fn tag_limits() {
        let many: String = (0..16).map(|i| format!("k{i}=v\n")).collect();
        assert!(parse_tags(&many).unwrap_err().contains("15"));
        let t = parse_tags("a=1\nb=2").unwrap();
        assert_eq!(format_tags(&t), "a=1\nb=2");
    }

    #[test]
    fn line_breaks_become_lf() {
        let mut f = form();
        f.value = Some("\na\r\nb\r\n".into());
        let (_, body) = for_create(&f, NOW).unwrap();
        assert_eq!(body.value.expose(), "\na\nb\n");
        // A value right at 25 KB once CRLF is LF isn't refused for its CRs.
        let line = "x".repeat(1023);
        f.value = Some(vec![line.as_str(); 25].join("\r\n") + "\r\n");
        assert!(for_create(&f, NOW).is_ok());
    }

    #[test]
    fn repeated_tag_names_are_an_error() {
        let e = parse_tags("env=prod\nteam=a\nenv=test").unwrap_err();
        assert!(e.contains("Line 3 repeats the tag name env"), "{e}");
    }

    #[test]
    fn which_tags_the_form_can_show() {
        let t = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect()
        };
        assert!(tags_editable(&t(&[("env", "prod"), ("flag", "")])));
        assert!(tags_editable(&t(&[("url", "a=b")])), "= in a value is fine");
        assert!(!tags_editable(&t(&[("a=b", "c")])));
        assert!(!tags_editable(&t(&[("note", "two\nlines")])));
        assert!(!tags_editable(&t(&[(" padded", "x")])));
        assert!(!tags_editable(&t(&[("k", "x ")])));
        // Each editable set comes back the same from the textarea.
        let ok = t(&[("env", "prod"), ("url", "a=b"), ("flag", "")]);
        assert_eq!(parse_tags(&format_tags(&ok)).unwrap(), ok);
    }

    #[test]
    fn update_sends_tags_only_when_changed() {
        let current = item(Attributes::default(), &[("env", "prod")]);
        let mut f = form();
        f.tags = "env=prod".into();
        let body = for_update(&f, &current, NOW).unwrap();
        assert!(body.tags.is_none(), "unchanged tags not sent");
        f.tags = "env=test".into();
        let body = for_update(&f, &current, NOW).unwrap();
        assert_eq!(body.tags.unwrap()["env"], "test");
    }

    #[test]
    fn tags_the_form_cant_show_are_never_rewritten() {
        let odd = item(Attributes::default(), &[("a=b", " c ")]);
        let mut f = form();
        // The form shows no textarea for these, so it posts nothing.
        f.tags = String::new();
        let body = for_update(&f, &odd, NOW).unwrap();
        assert!(body.tags.is_none());
        let body = for_new_value(&f, &odd, NOW).unwrap();
        assert_eq!(body.tags.unwrap()["a=b"], " c ");
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
        let body = for_new_value(&f, &current, NOW).unwrap();
        assert_eq!(body.attributes.expires, Some(midnight + 10 * 3600));
        assert_eq!(
            body.attributes.not_before,
            Some(midnight - 30 * day + 9 * 3600)
        );
        // A different day is taken as chosen: end of day for expiry.
        f.expires = crate::dates::iso_date(midnight + day);
        let body = for_new_value(&f, &current, NOW).unwrap();
        assert_eq!(body.attributes.expires, Some(midnight + 2 * day - 1));
    }

    #[test]
    fn debug_hides_value() {
        assert!(!format!("{:?}", form()).contains("hunter2"));
    }
}
