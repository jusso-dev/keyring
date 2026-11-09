//! Parsing and checking the create and edit forms. Pure functions, so the
//! rules are easy to test.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::azure::secrets::{
    Attributes, DateChange, SetSecret, UpdateAttributes, UpdateSecret, is_valid_secret_name,
};
use crate::dates;
use crate::secret::Secret;

/// Most tags Key Vault allows on one secret.
pub const MAX_TAGS: usize = 15;
/// Key Vault's limit on a secret value (25 KB).
pub const MAX_VALUE_BYTES: usize = 25 * 1024;
pub const MAX_CONTENT_TYPE: usize = 255;

/// What the create and edit-properties forms post. Strings, because HTML
/// forms send strings and a missing checkbox sends nothing.
#[derive(Deserialize, Default)]
pub struct SecretForm {
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
}

impl std::fmt::Debug for SecretForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretForm")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

/// One problem with one field, in words for the person filling it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: &'static str,
    pub message: String,
}

fn err(field: &'static str, message: impl Into<String>) -> FieldError {
    FieldError {
        field,
        message: message.into(),
    }
}

/// Explain what's wrong with a name, or `None` if it's fine.
pub fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("Give the secret a name.".into());
    }
    if name.len() > 127 {
        return Some(format!(
            "Names can be up to 127 characters. This one is {}.",
            name.len()
        ));
    }
    if !is_valid_secret_name(name) {
        let bad: String = name
            .chars()
            .filter(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
            .take(5)
            .collect();
        let shown: Vec<String> = bad
            .chars()
            .map(|c| {
                if c == ' ' {
                    "spaces".into()
                } else {
                    format!("\"{c}\"")
                }
            })
            .collect();
        return Some(format!(
            "Names can only use letters, numbers and hyphens. Remove {}.",
            shown.join(", ")
        ));
    }
    None
}

/// Parse tag lines. Blank lines are skipped.
pub fn parse_tags(raw: &str) -> Result<BTreeMap<String, String>, String> {
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
        tags.insert(k.to_owned(), v.to_owned());
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
pub fn format_tags(tags: &BTreeMap<String, String>) -> String {
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
    dates::parse_iso_date(raw).map(Some).ok_or_else(|| {
        err(
            field,
            format!("{label} isn't a real date. Use the date picker or type YYYY-MM-DD."),
        )
    })
}

/// Everything except the value, checked.
pub struct Properties {
    pub content_type: Option<String>,
    pub attributes: Attributes,
    pub tags: BTreeMap<String, String>,
}

fn properties(form: &SecretForm, now: i64, errors: &mut Vec<FieldError>) -> Properties {
    let content_type = form.content_type.trim();
    if content_type.len() > MAX_CONTENT_TYPE {
        errors.push(err(
            "content_type",
            "Content type can be up to 255 characters.",
        ));
    }
    let expires = parse_date("expires", &form.expires, "Expiry date").unwrap_or_else(|e| {
        errors.push(e);
        None
    });
    let not_before = parse_date("not_before", &form.not_before, "Start date").unwrap_or_else(|e| {
        errors.push(e);
        None
    });
    // Expiry is end of the chosen day, so "expires 1 March" works all of
    // 1 March.
    let expires = expires.map(|d| d + 86_399);
    if let Some(exp) = expires
        && exp <= now
    {
        errors.push(err(
            "expires",
            "The expiry date has already passed. Pick a later date, or leave it blank.",
        ));
    }
    if let (Some(exp), Some(nbf)) = (expires, not_before)
        && nbf >= exp
    {
        errors.push(err(
            "not_before",
            "The start date needs to be before the expiry date.",
        ));
    }
    let tags = parse_tags(&form.tags).unwrap_or_else(|m| {
        errors.push(err("tags", m));
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

fn checked_value(form: &SecretForm, errors: &mut Vec<FieldError>) -> Option<Secret> {
    match form.value.as_deref() {
        None | Some("") => {
            errors.push(err("value", "Enter a value."));
            None
        }
        Some(v) if v.len() > MAX_VALUE_BYTES => {
            errors.push(err("value", "Values can be up to 25 KB."));
            None
        }
        // Keep the value exactly as typed. Spaces can matter.
        Some(v) => Some(Secret::new(v)),
    }
}

/// Check a create form. Gives the name and a body that sets a value.
pub fn for_create(form: &SecretForm, now: i64) -> Result<(String, SetSecret), Vec<FieldError>> {
    let mut errors = Vec::new();
    let name = form.name.trim().to_owned();
    if let Some(m) = name_problem(&name) {
        errors.push(err("name", m));
    }
    let value = checked_value(form, &mut errors);
    let props = properties(form, now, &mut errors);
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

/// Check a "new value" form. Setting a value always makes a new version.
pub fn for_new_value(form: &SecretForm, now: i64) -> Result<SetSecret, Vec<FieldError>> {
    let mut errors = Vec::new();
    let value = checked_value(form, &mut errors);
    let props = properties(form, now, &mut errors);
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

/// Check an edit-properties form against the current version. The body
/// has no value, so this can never create a new version. Dates that didn't
/// change are left out; removed dates are sent as `null`.
pub fn for_update(
    form: &SecretForm,
    current: &Attributes,
    now: i64,
) -> Result<UpdateSecret, Vec<FieldError>> {
    let mut errors = Vec::new();
    // An expiry that's already passed but wasn't touched isn't an error.
    let mut props = properties(form, now, &mut errors);
    let wanted_exp = props.attributes.expires;
    let expires = DateChange::between(current.expires, wanted_exp);
    if expires == DateChange::Keep {
        errors.retain(|e| e.field != "expires" || !e.message.contains("already passed"));
    }
    if errors.is_empty() {
        props.attributes.enabled.get_or_insert(true);
        Ok(UpdateSecret {
            // Send an empty string to clear a content type that was removed.
            content_type: Some(props.content_type.unwrap_or_default()),
            attributes: UpdateAttributes {
                enabled: props.attributes.enabled,
                not_before: DateChange::between(current.not_before, props.attributes.not_before),
                expires,
            },
            tags: Some(props.tags),
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

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
    fn name_rules_explained() {
        assert_eq!(name_problem("ok-name-1"), None);
        assert_eq!(name_problem("").unwrap(), "Give the secret a name.");
        assert!(name_problem("db_password").unwrap().contains("\"_\""));
        assert!(name_problem("my secret").unwrap().contains("spaces"));
        assert!(name_problem(&"a".repeat(128)).unwrap().contains("127"));
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
        let body = for_update(&f, &current, NOW).unwrap();
        let j = serde_json::to_value(&body).unwrap();
        assert!(
            j["attributes"].get("exp").is_none(),
            "unchanged expiry not sent"
        );
        f.expires = String::new();
        let j = serde_json::to_value(for_update(&f, &current, NOW).unwrap()).unwrap();
        assert!(
            j["attributes"]["exp"].is_null(),
            "cleared expiry sent as null"
        );
        // An expiry that passed earlier today, left alone, doesn't block other edits.
        let past = Attributes {
            expires: Some(NOW - 60),
            ..Attributes::default()
        };
        let mut f = form();
        f.expires = crate::dates::iso_date(NOW - 60);
        assert!(for_update(&f, &past, NOW).is_ok());
    }

    #[test]
    fn update_never_has_a_value() {
        let mut f = form();
        f.value = Some("should be ignored".into());
        let body = for_update(&f, &Attributes::default(), NOW).unwrap();
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
    fn debug_hides_value() {
        assert!(!format!("{:?}", form()).contains("hunter2"));
    }
}
