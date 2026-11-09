//! The generator page. Values are made on the server, shown once in a
//! `no-store` response and never logged.

use askama::Template;
use axum::Form;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::auth::CurrentSession;
use crate::generator::{self, KeyFormat, PasswordOptions};
use crate::routes::assets::render;
use crate::routes::error::PageResult;
use crate::routes::secrets::reveal::{CLEAR_AFTER_SECS, no_store};
use crate::routes::shell::{Section, Shell};
use crate::routes::vault_ctx::check_csrf;
use crate::secret::Secret;

#[derive(Deserialize, Clone)]
pub struct GenForm {
    #[serde(default)]
    pub csrf: String,
    /// `password`, `guid` or `api_key`.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub length: String,
    #[serde(default)]
    pub lower: Option<String>,
    #[serde(default)]
    pub upper: Option<String>,
    #[serde(default)]
    pub digits: Option<String>,
    #[serde(default)]
    pub symbols: Option<String>,
    #[serde(default)]
    pub no_look_alikes: Option<String>,
    #[serde(default)]
    pub bytes: String,
    /// `base64url` or `hex`.
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub prefix: String,
    /// `1` when opened from a secret form, to offer "Use this value".
    #[serde(default)]
    pub for_secret: String,
}

impl Default for GenForm {
    fn default() -> Self {
        Self {
            csrf: String::new(),
            kind: "password".into(),
            length: "24".into(),
            lower: Some("on".into()),
            upper: Some("on".into()),
            digits: Some("on".into()),
            symbols: Some("on".into()),
            no_look_alikes: Some("on".into()),
            bytes: "32".into(),
            format: "base64url".into(),
            prefix: String::new(),
            for_secret: String::new(),
        }
    }
}

#[derive(Template)]
#[template(path = "generator.html")]
struct GenPage {
    shell: Shell,
    form: GenForm,
    value: Option<Secret>,
    error: Option<String>,
    clear_after: u32,
}

impl GenPage {
    fn value(&self) -> &str {
        self.value.as_ref().map(Secret::expose).unwrap_or_default()
    }
    fn is(&self, kind: &str) -> bool {
        self.form.kind == kind
    }
}

fn make(f: &GenForm) -> Result<Secret, String> {
    match f.kind.as_str() {
        "guid" => Ok(Secret::new(generator::guid())),
        "api_key" => {
            let bytes: usize = f
                .bytes
                .trim()
                .parse()
                .map_err(|_| "Pick a number of bytes.".to_owned())?;
            let prefix = f.prefix.trim();
            if !generator::is_valid_prefix(prefix) {
                return Err(
                    "The prefix can use letters, numbers, _ and -, up to 16 characters.".into(),
                );
            }
            let format = if f.format == "hex" {
                KeyFormat::Hex
            } else {
                KeyFormat::Base64Url
            };
            generator::api_key(bytes, format, prefix).map_err(|_| {
                format!(
                    "Pick between {} and {} bytes.",
                    generator::MIN_KEY_BYTES,
                    generator::MAX_KEY_BYTES
                )
            })
        }
        _ => {
            let length: usize = f
                .length
                .trim()
                .parse()
                .map_err(|_| "Pick a length.".to_owned())?;
            let o = PasswordOptions {
                length,
                lower: f.lower.is_some(),
                upper: f.upper.is_some(),
                digits: f.digits.is_some(),
                symbols: f.symbols.is_some(),
                no_look_alikes: f.no_look_alikes.is_some(),
            };
            generator::password(&o).map_err(|e| match e {
                generator::GenError::Length => {
                    format!(
                        "Pick a length from {} to {}.",
                        generator::MIN_LENGTH,
                        generator::MAX_LENGTH
                    )
                }
                generator::GenError::NoCharacterSets => {
                    "Tick at least one kind of character.".into()
                }
            })
        }
    }
}

pub async fn page(
    shell: Shell,
    axum::extract::Query(q): axum::extract::Query<ForSecret>,
) -> PageResult {
    let form = GenForm {
        for_secret: q.for_secret,
        ..GenForm::default()
    };
    Ok(render(&GenPage {
        shell: shell.at(Section::Generator),
        form,
        value: None,
        error: None,
        clear_after: CLEAR_AFTER_SECS,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct ForSecret {
    #[serde(default)]
    for_secret: String,
}

pub async fn generate(session: CurrentSession, shell: Shell, Form(f): Form<GenForm>) -> PageResult {
    let shell = check_csrf(&session, &f.csrf, shell.at(Section::Generator))?;
    let (value, error) = match make(&f) {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e)),
    };
    Ok(no_store(
        render(&GenPage {
            shell,
            form: f,
            value,
            error,
            clear_after: CLEAR_AFTER_SECS,
        })
        .into_response(),
    ))
}
