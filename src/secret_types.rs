//! Secret types with several fields: Login, Database, API key and SSH
//! private key.
//!
//! A typed secret is an ordinary Key Vault secret whose content type is
//! `application/vnd.keyring.<type>+json;v=1` and whose value is compact
//! JSON: one string per field, every field present, nothing else. Other
//! tools see a plain JSON string. Nothing is stored outside Key Vault.
//!
//! Every field is part of the value, including URL, username and server,
//! so every field is held in a [`Secret`] and showing any of them is a
//! reveal. Reading is strict and bounded: a value that isn't exactly the
//! type's shape is [`Malformed`], and the reveal page shows it as a plain
//! value with a warning.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;

use crate::secret::Secret;

/// Key Vault's limit on a secret value (25 KB). A stored value longer than
/// this isn't parsed.
pub(crate) const MAX_VALUE_BYTES: usize = 25 * 1024;

/// Start of every Keyring content type.
const PREFIX: &str = "application/vnd.keyring.";
/// The only version this build reads and writes.
const VERSION: &str = "1";

/// One field of a type.
#[derive(Debug)]
pub(crate) struct Field {
    /// The JSON key, the form field's name and its element id.
    pub name: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// Masked in the form. Every field is still part of the secret value.
    pub secret: bool,
    /// Several lines (a textarea). Line breaks are saved as LF.
    pub multiline: bool,
    pub required: bool,
    /// Longest value, in characters.
    pub max_chars: usize,
    /// Offers the generator.
    pub generate: bool,
}

const fn field(name: &'static str, label: &'static str, max_chars: usize) -> Field {
    Field {
        name,
        label,
        help: "",
        secret: false,
        multiline: false,
        required: false,
        max_chars,
        generate: false,
    }
}

const fn password(name: &'static str, label: &'static str, required: bool) -> Field {
    Field {
        secret: true,
        required,
        generate: true,
        ..field(name, label, 1024)
    }
}

const NOTES: Field = Field {
    multiline: true,
    help: "Anything that helps whoever uses this. Saved in the value, so it is only shown on a reveal.",
    ..field("notes", "Notes", 4096)
};

const LOGIN: [Field; 4] = [
    field("url", "URL", 2048),
    field("username", "Username", 256),
    password("password", "Password", true),
    NOTES,
];

const DATABASE: [Field; 4] = [
    Field {
        required: true,
        help: "The server's host name, as the database driver expects it.",
        ..field("server", "Server", 512)
    },
    field("database", "Database", 256),
    Field {
        required: true,
        ..field("username", "Username", 256)
    },
    password("password", "Password", true),
];

const API_KEY: [Field; 3] = [
    Field {
        secret: true,
        required: true,
        generate: true,
        ..field("key", "Key", 4096)
    },
    field("endpoint", "Endpoint", 2048),
    NOTES,
];

const SSH_KEY: [Field; 4] = [
    field("username", "Username", 256),
    field("host", "Host", 512),
    Field {
        secret: true,
        multiline: true,
        required: true,
        help: "The whole key, including its BEGIN and END lines.",
        ..field("private_key", "Private key", 16 * 1024)
    },
    Field {
        help: "Only if the key has one.",
        ..password("passphrase", "Passphrase", false)
    },
];

/// A built-in type. Password, today's plain string, isn't one of these:
/// it has no Keyring content type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecretType {
    Login,
    Database,
    ApiKey,
    SshKey,
}

impl SecretType {
    pub(crate) const ALL: [Self; 4] = [Self::Login, Self::Database, Self::ApiKey, Self::SshKey];

    /// The name in the content type and in the create form's address.
    pub(crate) fn slug(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Database => "database",
            Self::ApiKey => "api-key",
            Self::SshKey => "ssh-key",
        }
    }

    pub(crate) fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.slug() == slug)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Database => "Database",
            Self::ApiKey => "API key",
            Self::SshKey => "SSH private key",
        }
    }

    pub(crate) fn content_type(self) -> String {
        format!("{PREFIX}{}+json;v={VERSION}", self.slug())
    }

    pub(crate) fn fields(self) -> &'static [Field] {
        match self {
            Self::Login => &LOGIN,
            Self::Database => &DATABASE,
            Self::ApiKey => &API_KEY,
            Self::SshKey => &SSH_KEY,
        }
    }

    /// The field `KEYRING_PASSWORD_POLICY` checks: Login's password. The
    /// other types' secrets are machine credentials, keys or passphrases,
    /// so the policy leaves them alone.
    pub(crate) fn policy_field(self) -> Option<&'static str> {
        match self {
            Self::Login => Some("password"),
            Self::Database | Self::ApiKey | Self::SshKey => None,
        }
    }
}

/// What a content type says about the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentKind {
    /// Not a Keyring type: shown and edited exactly as before.
    Plain,
    /// A Keyring type this build reads.
    Typed(SecretType),
    /// Starts like a Keyring type, but the type or version isn't one this
    /// build knows. Shown as a plain value with a warning.
    Unknown,
}

/// Read a content type. The media type is matched without regard to case;
/// the only parameter allowed is `v=1`.
pub(crate) fn classify(content_type: Option<&str>) -> ContentKind {
    let Some(ct) = content_type else {
        return ContentKind::Plain;
    };
    let mut parts = ct.split(';');
    let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    let Some(rest) = media.strip_prefix(PREFIX) else {
        return ContentKind::Plain;
    };
    let kind = rest.strip_suffix("+json").and_then(SecretType::from_slug);
    let params: Vec<&str> = parts.map(str::trim).filter(|p| !p.is_empty()).collect();
    let version_ok = matches!(params.as_slice(), [p] if p
        .split_once('=')
        .is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("v") && v.trim() == VERSION));
    match kind {
        Some(t) if version_ok => ContentKind::Typed(t),
        _ => ContentKind::Unknown,
    }
}

/// A stored value that isn't in its type's shape. Says nothing about the
/// value, so it can't leak any of it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// A typed value: one [`Secret`] per field, in the type's field order.
pub(crate) struct TypedValue {
    kind: SecretType,
    values: Vec<Secret>,
}

impl fmt::Debug for TypedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedValue")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl TypedValue {
    /// Each field with its value, in order.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'static Field, &Secret)> {
        self.kind.fields().iter().zip(&self.values)
    }

    fn get(&self, name: &str) -> &str {
        self.fields()
            .find(|(f, _)| f.name == name)
            .map(|(_, v)| v.expose())
            .unwrap_or_default()
    }

    /// Read a stored value strictly: a JSON object with exactly the type's
    /// fields, each a string, no repeats, nothing else. A value over Key
    /// Vault's limit isn't parsed.
    pub(crate) fn decode(kind: SecretType, raw: &Secret) -> Result<Self, Malformed> {
        let raw = raw.expose();
        if raw.len() > MAX_VALUE_BYTES {
            return Err(Malformed);
        }
        let pairs: Pairs = serde_json::from_str(raw).map_err(|_| Malformed)?;
        let fields = kind.fields();
        if pairs.0.len() != fields.len() {
            return Err(Malformed);
        }
        let mut slots: Vec<Option<Secret>> = fields.iter().map(|_| None).collect();
        for (key, value) in pairs.0 {
            let i = fields.iter().position(|f| f.name == key).ok_or(Malformed)?;
            if slots[i].replace(value).is_some() {
                return Err(Malformed);
            }
        }
        let values = slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(Malformed)?;
        Ok(Self { kind, values })
    }

    /// Check values from a form, in the type's field order. Line breaks in
    /// a several-line field become LF. Gives each problem with the field
    /// at fault.
    pub(crate) fn check(
        kind: SecretType,
        mut given: impl FnMut(&str) -> Option<Secret>,
    ) -> Result<Self, Vec<(&'static str, String)>> {
        let mut problems = Vec::new();
        let mut values = Vec::new();
        for f in kind.fields() {
            let v = given(f.name).unwrap_or_else(|| Secret::new(""));
            let v = if f.multiline && v.expose().contains('\r') {
                Secret::new(v.expose().replace("\r\n", "\n"))
            } else {
                v
            };
            let text = v.expose();
            if f.required && text.is_empty() {
                problems.push((f.name, format!("Enter the {}.", f.label.to_lowercase())));
            } else if !f.multiline && text.contains(['\n', '\r']) {
                problems.push((f.name, format!("{} can't have a line break.", f.label)));
            } else if text.chars().count() > f.max_chars {
                problems.push((
                    f.name,
                    format!("{} can be up to {} characters.", f.label, f.max_chars),
                ));
            }
            values.push(v);
        }
        if !problems.is_empty() {
            return Err(problems);
        }
        let typed = Self { kind, values };
        if typed.encode().expose().len() > MAX_VALUE_BYTES {
            // Name the field that takes the most room once encoded.
            let (f, _) = typed
                .fields()
                .max_by_key(|(_, v)| encoded_len(v.expose()))
                .unwrap_or((&kind.fields()[0], &typed.values[0]));
            return Err(vec![(
                f.name,
                format!(
                    "Together the fields are over Key Vault's 25 KB limit. Shorten {}.",
                    f.label
                ),
            )]);
        }
        Ok(typed)
    }

    /// The type's policy field against `KEYRING_PASSWORD_POLICY`: the
    /// field's name and what it fails, or `None`.
    pub(crate) fn policy_problem(
        &self,
        policy: &crate::password_policy::PasswordPolicy,
    ) -> Option<(&'static str, String)> {
        let name = self.kind.policy_field()?;
        let (field, value) = self.fields().find(|(f, _)| f.name == name)?;
        policy.check(field.label, value).map(|m| (field.name, m))
    }

    /// Compact JSON, every field present, in the type's order. Built by
    /// serde_json, so quotes, line breaks and Unicode are escaped properly.
    pub(crate) fn encode(&self) -> Secret {
        let json =
            serde_json::to_string(&Encoded(self)).expect("a map of strings always serialises");
        Secret::new(json)
    }

    /// A SQL Server (SqlClient) connection string from a Database secret.
    /// Every value is quoted, by SqlClient's rules: in single quotes when
    /// it holds a double quote but no single quote, otherwise in double
    /// quotes with every double quote doubled. `None` for another type, or
    /// when a value has a control character.
    pub(crate) fn sql_server(&self) -> Option<Secret> {
        let parts = self.database_parts(["Server", "Database", "User ID", "Password"])?;
        let s: Vec<String> = parts
            .iter()
            .map(|(k, v)| {
                if v.contains('"') && !v.contains('\'') {
                    format!("{k}='{v}'")
                } else {
                    format!("{k}=\"{}\"", v.replace('"', "\"\""))
                }
            })
            .collect();
        Some(Secret::new(s.join(";")))
    }

    /// A PostgreSQL (libpq keyword/value) connection string from a
    /// Database secret. Every value goes in single quotes, with `\` and
    /// `'` escaped by a backslash.
    pub(crate) fn postgres(&self) -> Option<Secret> {
        let parts = self.database_parts(["host", "dbname", "user", "password"])?;
        let s: Vec<String> = parts
            .iter()
            .map(|(k, v)| format!("{k}='{}'", v.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect();
        Some(Secret::new(s.join(" ")))
    }

    /// Server, database (left out when empty), username and password,
    /// under the given keywords.
    fn database_parts(&self, keys: [&'static str; 4]) -> Option<Vec<(&'static str, &str)>> {
        if self.kind != SecretType::Database {
            return None;
        }
        let values = [
            self.get("server"),
            self.get("database"),
            self.get("username"),
            self.get("password"),
        ];
        if values.iter().any(|v| v.chars().any(char::is_control)) {
            return None;
        }
        Some(
            keys.into_iter()
                .zip(values)
                .filter(|(k, v)| !(v.is_empty() && matches!(*k, "Database" | "dbname")))
                .collect(),
        )
    }
}

/// Length of a string once JSON-encoded, without making the copy.
fn encoded_len(s: &str) -> usize {
    s.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if c.is_control() && (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum()
}

struct Encoded<'a>(&'a TypedValue);

impl serde::Serialize for Encoded<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.values.len()))?;
        for (f, v) in self.0.fields() {
            m.serialize_entry(f.name, v.expose())?;
        }
        m.end()
    }
}

/// Most entries read from a stored object before giving up. More than any
/// type has, so a crafted value can't make Keyring collect thousands.
const MAX_ENTRIES: usize = 8;

/// A JSON object's entries in order, values kept as `Secret`s. A value
/// that isn't a string fails the parse.
struct Pairs(Vec<(String, Secret)>);

impl<'de> serde::Deserialize<'de> for Pairs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(PairsVisitor)
    }
}

struct PairsVisitor;

impl<'de> Visitor<'de> for PairsVisitor {
    type Value = Pairs;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object of strings")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pairs, A::Error> {
        let mut pairs = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if pairs.len() >= MAX_ENTRIES {
                return Err(de::Error::custom("too many entries"));
            }
            let value: Secret = map.next_value()?;
            pairs.push((key, value));
        }
        Ok(Pairs(pairs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(kind: SecretType, values: &[(&str, &str)]) -> TypedValue {
        TypedValue::check(kind, |n| {
            values
                .iter()
                .find(|(k, _)| *k == n)
                .map(|(_, v)| Secret::new(*v))
        })
        .unwrap()
    }

    #[test]
    fn content_types() {
        for t in SecretType::ALL {
            assert_eq!(classify(Some(&t.content_type())), ContentKind::Typed(t));
            assert_eq!(SecretType::from_slug(t.slug()), Some(t));
        }
        assert_eq!(
            SecretType::Login.content_type(),
            "application/vnd.keyring.login+json;v=1"
        );
        let c = |s: &str| classify(Some(s));
        assert_eq!(
            c(" Application/VND.Keyring.Login+JSON ; V=1 "),
            ContentKind::Typed(SecretType::Login)
        );
        assert_eq!(
            c("application/vnd.keyring.login+json;v=2"),
            ContentKind::Unknown
        );
        assert_eq!(
            c("application/vnd.keyring.login+json"),
            ContentKind::Unknown
        );
        assert_eq!(
            c("application/vnd.keyring.login+json;v=1;x=y"),
            ContentKind::Unknown
        );
        assert_eq!(
            c("application/vnd.keyring.wifi+json;v=1"),
            ContentKind::Unknown
        );
        assert_eq!(c("application/vnd.keyring.login;v=1"), ContentKind::Unknown);
        assert_eq!(c("text/plain"), ContentKind::Plain);
        assert_eq!(c("application/json"), ContentKind::Plain);
        assert_eq!(c(""), ContentKind::Plain);
        assert_eq!(classify(None), ContentKind::Plain);
    }

    #[test]
    fn json_round_trips_quotes_line_breaks_and_unicode() {
        let notes = "line one\nline \"two\"\t\\ end ü 日本 🔑 \u{1}";
        let v = typed(
            SecretType::Login,
            &[
                ("url", "https://example.test/a?b=\"c\""),
                ("username", "o'brien"),
                ("password", "p\"a\\s's{}@:/;"),
                ("notes", notes),
            ],
        );
        let json = v.encode();
        assert!(!json.expose().contains('\n'), "compact, one line");
        assert!(json.expose().starts_with("{\"url\":"), "field order kept");
        let back = TypedValue::decode(SecretType::Login, &json).unwrap();
        assert_eq!(back.get("notes"), notes);
        assert_eq!(back.get("password"), "p\"a\\s's{}@:/;");
        assert_eq!(back.get("username"), "o'brien");
        // Other tools read it as ordinary JSON.
        let plain: serde_json::Value = serde_json::from_str(json.expose()).unwrap();
        assert_eq!(plain["notes"], notes);
    }

    #[test]
    fn decode_is_strict() {
        let k = SecretType::ApiKey;
        let d = |s: &str| TypedValue::decode(k, &Secret::new(s)).map(|_| ());
        assert!(d(r#"{"key":"a","endpoint":"","notes":""}"#).is_ok());
        assert!(
            d(r#"{"notes":"","key":"a","endpoint":""}"#).is_ok(),
            "any order"
        );
        assert_eq!(d(r#"{"key":"a","endpoint":""}"#), Err(Malformed), "missing");
        assert_eq!(
            d(r#"{"key":"a","endpoint":"","notes":"","x":""}"#),
            Err(Malformed),
            "extra"
        );
        assert_eq!(
            d(r#"{"key":"a","key":"b","notes":""}"#),
            Err(Malformed),
            "repeated"
        );
        assert_eq!(d(r#"{"key":1,"endpoint":"","notes":""}"#), Err(Malformed));
        assert_eq!(
            d(r#"{"key":null,"endpoint":"","notes":""}"#),
            Err(Malformed)
        );
        assert_eq!(
            d(r#"{"key":["a"],"endpoint":"","notes":""}"#),
            Err(Malformed)
        );
        assert_eq!(d(r#"["a","b","c"]"#), Err(Malformed));
        assert_eq!(d("plain old password"), Err(Malformed));
        assert_eq!(d(""), Err(Malformed));
        assert_eq!(
            d(r#"{"key":"a","endpoint":"","notes":""} x"#),
            Err(Malformed)
        );
        let deep = "[".repeat(10_000);
        assert_eq!(d(&deep), Err(Malformed), "no panic on deep nesting");
        let many: String = (0..2000).map(|i| format!("\"k{i}\":\"\",")).collect();
        assert_eq!(d(&format!("{{{many}\"z\":\"\"}}")), Err(Malformed));
        let big = format!(
            r#"{{"key":"{}","endpoint":"","notes":""}}"#,
            "a".repeat(MAX_VALUE_BYTES)
        );
        assert_eq!(d(&big), Err(Malformed), "over 25 KB isn't parsed");
    }

    #[test]
    fn check_names_the_field() {
        let e = TypedValue::check(SecretType::Database, |_| None).unwrap_err();
        let fields: Vec<_> = e.iter().map(|(f, _)| *f).collect();
        assert_eq!(fields, ["server", "username", "password"]);
        let e = TypedValue::check(SecretType::Login, |n| {
            Some(Secret::new(if n == "username" { "a\nb" } else { "x" }))
        })
        .unwrap_err();
        assert_eq!(e[0].0, "username");
        let long = "x".repeat(257);
        let e = TypedValue::check(SecretType::Login, |n| {
            Some(Secret::new(if n == "username" {
                long.as_str()
            } else {
                "x"
            }))
        })
        .unwrap_err();
        assert_eq!(
            e[0],
            ("username", "Username can be up to 256 characters.".into())
        );
    }

    #[test]
    fn private_keys_keep_lines_as_lf() {
        let v = typed(
            SecretType::SshKey,
            &[("private_key", "-----BEGIN-----\r\nabc\r\n-----END-----\r\n")],
        );
        assert_eq!(
            v.get("private_key"),
            "-----BEGIN-----\nabc\n-----END-----\n"
        );
        assert_eq!(v.get("passphrase"), "");
    }

    #[test]
    fn the_25_kb_limit_names_the_biggest_field() {
        // Each field is under its own cap, but escaped quotes double the
        // notes, which takes the value past 25 KB.
        let notes = "\"".repeat(4096);
        let key = "k".repeat(4096);
        let r = TypedValue::check(SecretType::ApiKey, |n| {
            Some(Secret::new(match n {
                "notes" => notes.as_str(),
                "key" => key.as_str(),
                _ => "e",
            }))
        });
        assert!(r.is_ok(), "about 12 KB fits");
        let pk = format!("{}\n", "\"".repeat(16 * 1024 - 1));
        let e = TypedValue::check(SecretType::SshKey, |n| {
            Some(Secret::new(if n == "private_key" {
                pk.as_str()
            } else {
                ""
            }))
        })
        .unwrap_err();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, "private_key");
        assert!(e[0].1.contains("Shorten Private key"), "{}", e[0].1);
        assert_eq!(encoded_len("a\"\n\u{1}ü"), 1 + 2 + 2 + 6 + 2);
    }

    #[test]
    fn connection_strings_escape_each_part() {
        let nasty = "p;w'd\"{x} y@h:1/z\\";
        let v = typed(
            SecretType::Database,
            &[
                ("server", "db.example.test"),
                ("database", "app db"),
                ("username", "o'brien"),
                ("password", nasty),
            ],
        );
        assert_eq!(
            v.sql_server().unwrap().expose(),
            "Server=\"db.example.test\";Database=\"app db\";User ID=\"o'brien\";Password=\"p;w'd\"\"{x} y@h:1/z\\\""
        );
        assert_eq!(
            v.postgres().unwrap().expose(),
            "host='db.example.test' dbname='app db' user='o\\'brien' password='p;w\\'d\"{x} y@h:1/z\\\\'"
        );
        // A double quote and no single quote: single quotes, as is.
        let v = typed(
            SecretType::Database,
            &[("server", "s"), ("username", "u"), ("password", "a\"b;c")],
        );
        assert_eq!(
            v.sql_server().unwrap().expose(),
            "Server=\"s\";User ID=\"u\";Password='a\"b;c'"
        );
        // No database: the keyword is left out.
        let v = typed(
            SecretType::Database,
            &[("server", "s"), ("username", "u"), ("password", "p")],
        );
        assert_eq!(
            v.postgres().unwrap().expose(),
            "host='s' user='u' password='p'"
        );
        // A control character: not built at all.
        let raw =
            Secret::new(r#"{"server":"s","database":"","username":"u","password":"a\u0000b"}"#);
        let v = TypedValue::decode(SecretType::Database, &raw).unwrap();
        assert!(v.sql_server().is_none() && v.postgres().is_none());
        // Only for Database.
        let v = typed(SecretType::Login, &[("password", "p")]);
        assert!(v.sql_server().is_none());
    }

    #[test]
    fn debug_hides_values() {
        let v = typed(
            SecretType::Login,
            &[("password", "hunter2"), ("url", "u-r-l")],
        );
        let s = format!("{v:?}");
        assert!(!s.contains("hunter2") && !s.contains("u-r-l"));
    }
}
