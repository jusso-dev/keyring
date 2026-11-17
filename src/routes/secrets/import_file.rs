//! Reading a `.env` or CSV file of secrets for import. Pure functions, so
//! the rules are easy to test.
//!
//! Values are kept exactly as typed, including ones that look like
//! spreadsheet formulas (`=SUM(A1)`): this is input to Key Vault, not a
//! file anyone opens in a spreadsheet. Values go straight into [`Secret`],
//! and errors never quote a value.

use std::collections::{BTreeMap, HashMap};

use zeroize::Zeroizing;

use crate::dates;
use crate::routes::forms::name_problem;
use crate::routes::lifecycle::Kind;
use crate::routes::secrets::form::{MAX_CONTENT_TYPE, MAX_TAGS, MAX_VALUE_BYTES};
use crate::secret::Secret;
use crate::secret_types::{ContentKind, classify};

/// Largest file accepted.
pub(crate) const MAX_FILE_BYTES: usize = 1024 * 1024;
/// Request size limit for the import route (file plus form fields).
pub(crate) const MAX_BODY_BYTES: usize = MAX_FILE_BYTES + 16 * 1024;
/// Most secrets in one file.
pub(crate) const MAX_ROWS: usize = 500;

/// The problem for a row with one of Keyring's own content types.
pub(crate) const KEYRING_TYPE: &str = "Its content type is one of Keyring's own secret types (application/vnd.keyring.). Typed secrets are made on the Create form, not imported.";

/// The two file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Env,
    Csv,
}

impl Format {
    /// CSV for a `.csv` file name, otherwise `.env`.
    pub(crate) fn from_file_name(name: &str) -> Self {
        if name.to_ascii_lowercase().ends_with(".csv") {
            Self::Csv
        } else {
            Self::Env
        }
    }
}

/// One secret from the file, checked against Key Vault's rules.
pub(crate) struct Row {
    /// Line in the file the row starts on, from 1.
    pub line: usize,
    /// The name as written in the file.
    pub original: String,
    /// The Key Vault name it becomes.
    pub name: String,
    pub value: Secret,
    pub content_type: Option<String>,
    /// End of the expiry day, Unix seconds.
    pub expires: Option<i64>,
    pub tags: BTreeMap<String, String>,
    /// Why this row can't be imported, if it can't. Never quotes the value.
    pub problem: Option<String>,
}

impl std::fmt::Debug for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Row")
            .field("line", &self.line)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A row before Key Vault's rules are applied.
struct Raw {
    line: usize,
    name: String,
    /// Wiped when dropped. A quoted `.env` value stops growing once it is
    /// over Key Vault's limit, and `too_long` says so.
    value: Zeroizing<String>,
    too_long: bool,
    content_type: String,
    expires: String,
    tags: String,
    /// The optional `description` column: the note, merged into the tags.
    description: String,
    /// The optional `owner` and `notify` columns.
    owner: String,
    notify: String,
}

/// Read a whole file. An `Err` is a message for the person about why the
/// file as a whole can't be used.
pub(crate) fn parse(
    bytes: &[u8],
    format: Format,
    now: i64,
    rules: crate::owner::Rules<'_>,
) -> Result<Vec<Row>, String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "This file isn't UTF-8 text. Save it as UTF-8 and try again.".to_owned())?;
    let raws = match format {
        Format::Env => parse_env(text)?,
        Format::Csv => parse_csv(text)?,
    };
    if raws.is_empty() {
        return Err("This file has no secrets in it.".into());
    }
    if raws.len() > MAX_ROWS {
        return Err(format!(
            "This file has {} secrets. Keyring imports up to {MAX_ROWS} at a time. Split it into smaller files.",
            raws.len()
        ));
    }
    let rows: Vec<Row> = raws.into_iter().map(|r| check(r, now, rules)).collect();
    clashes(&rows)?;
    Ok(rows)
}

/// Turn a name into one Key Vault accepts: every character other than a
/// letter, digit or hyphen becomes a hyphen, and leading hyphens go.
/// `DB_PASSWORD` becomes `DB-PASSWORD`.
pub(crate) fn convert_name(name: &str) -> String {
    let converted: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    converted.trim_start_matches('-').to_owned()
}

fn check(raw: Raw, now: i64, rules: crate::owner::Rules<'_>) -> Row {
    let original = raw.name.trim().to_owned();
    let name = convert_name(&original);
    let mut problem = name_problem(Kind::Secret, &name).map(|m| {
        if original.is_empty() {
            "It has no name.".to_owned()
        } else {
            m
        }
    });
    let value = crate::routes::secrets::form::normalise_newlines(&raw.value);
    if problem.is_none() && value.is_empty() {
        problem = Some("It has no value. Key Vault needs one.".into());
    }
    if problem.is_none() && (raw.too_long || value.len() > MAX_VALUE_BYTES) {
        problem = Some("Its value is over 25 KB, Key Vault's limit.".into());
    }
    let content_type = raw.content_type.trim().to_owned();
    if problem.is_none() && content_type.len() > MAX_CONTENT_TYPE {
        problem = Some("Its content type is over 255 characters.".into());
    }
    // Import writes plain secrets only. A Keyring content type would mark
    // a value whose fields nothing here checks as a Login or other typed
    // secret, the same rule the create form applies.
    if problem.is_none()
        && classify((!content_type.is_empty()).then_some(content_type.as_str()))
            != ContentKind::Plain
    {
        problem = Some(KEYRING_TYPE.into());
    }
    let mut expires = None;
    let raw_exp = raw.expires.trim();
    if !raw_exp.is_empty() {
        match dates::parse_iso_date(raw_exp) {
            // End of the day, as the create form does.
            Some(d) if d + 86_399 > now => expires = Some(d + 86_399),
            Some(_) => {
                problem.get_or_insert_with(|| "Its expiry date has already passed.".into());
            }
            None => {
                problem.get_or_insert_with(|| "Its expiry isn't a date. Use YYYY-MM-DD.".into());
            }
        }
    }
    // The owner columns follow the form's rules, but never the "required"
    // one here: the preview applies it, so it can write its own event.
    let owner_rules = crate::owner::Rules {
        require: false,
        ..rules
    };
    let tags = parse_tags(&raw.tags)
        .and_then(|t| {
            let owner = crate::owner::clean_owner(&raw.owner, owner_rules)?;
            let t = crate::owner::merge(&t, crate::owner::OWNER_TAG, owner.as_deref())?;
            let notify = crate::owner::clean_notify(&raw.notify, owner_rules)?;
            crate::owner::merge(&t, crate::owner::NOTIFY_TAG, notify.as_deref())
        })
        .and_then(|t| {
            crate::description::clean(&raw.description)
                .and_then(|n| crate::description::merge(&t, n.as_deref()))
        })
        .unwrap_or_else(|m| {
            problem.get_or_insert(m);
            BTreeMap::new()
        });
    Row {
        line: raw.line,
        original,
        name,
        value: Secret::new(value),
        content_type: (!content_type.is_empty()).then_some(content_type),
        expires,
        tags,
        problem,
    }
}

/// Tags in a CSV cell: `name=value` pairs separated by `;`.
fn parse_tags(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let mut tags = BTreeMap::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() {
            return Err("A tag has no name before the =.".into());
        }
        if crate::description::is_reserved(k) {
            return Err("Put the description in the description column, not in tags.".into());
        }
        if crate::owner::is_reserved(k) {
            return Err(
                "Put the owner and notify addresses in the owner and notify columns, not in tags."
                    .into(),
            );
        }
        if k.len() > 512 || v.len() > 256 {
            return Err("A tag is too long. Names can be 512 characters and values 256.".into());
        }
        if tags.insert(k.to_owned(), v.to_owned()).is_some() {
            return Err("A tag name is given twice.".into());
        }
    }
    if tags.len() > MAX_TAGS {
        return Err(format!("Key Vault allows up to {MAX_TAGS} tags."));
    }
    Ok(tags)
}

/// Two rows that become the same Key Vault name. Key Vault names ignore
/// case, so `db-password` and `DB_PASSWORD` clash.
fn clashes(rows: &[Row]) -> Result<(), String> {
    let mut seen: HashMap<String, &Row> = HashMap::new();
    let mut found = Vec::new();
    // Only names that pass Key Vault's rules are quoted. Any other row
    // already has a problem of its own, so it can't be imported anyway.
    for r in rows
        .iter()
        .filter(|r| name_problem(Kind::Secret, &r.name).is_none())
    {
        if let Some(first) = seen.get(&r.name.to_ascii_lowercase()) {
            found.push(if first.original == r.original {
                format!(
                    "{} is on line {} and line {}",
                    r.original, first.line, r.line
                )
            } else {
                format!(
                    "{} (line {}) and {} (line {}) both become {}",
                    first.original, first.line, r.original, r.line, first.name
                )
            });
        } else {
            seen.insert(r.name.to_ascii_lowercase(), r);
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    let shown: Vec<String> = found.iter().take(5).cloned().collect();
    let more = found.len().saturating_sub(shown.len());
    Err(format!(
        "Each secret needs its own Key Vault name, and Key Vault ignores case. {}{}. Rename them in the file and try again.",
        shown.join("; "),
        if more > 0 {
            format!("; and {more} more")
        } else {
            String::new()
        }
    ))
}

// ---------------------------------------------------------------------
// .env
// ---------------------------------------------------------------------

/// `NAME=value` lines. Blank lines and `#` comments are skipped, and an
/// `export ` in front is allowed. Values may be in double quotes (with
/// `\n`, `\r`, `\t`, `\"` and `\\` escapes, and line breaks), single quotes
/// (as written, line breaks allowed) or bare (to a ` #` comment, trimmed).
fn parse_env(text: &str) -> Result<Vec<Raw>, String> {
    let mut out = Vec::new();
    let mut lines = text.split('\n').enumerate().peekable();
    while let Some((i, line)) = lines.next() {
        let line_no = i + 1;
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(trimmed);
        let Some((name, rest)) = trimmed.split_once('=') else {
            return Err(format!(
                "Line {line_no} has no = sign. Each line needs NAME=value."
            ));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("Line {line_no} has no name before the =."));
        }
        let rest = rest.trim_start();
        let (value, too_long) = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                // Each character is looked at once, however many lines the
                // value runs over, and the value stops growing at the limit.
                let mut value = Quoted::new(q);
                let mut seg = &rest[1..];
                let after = loop {
                    if let Some(after) = value.feed(seg) {
                        break after;
                    }
                    match lines.next() {
                        Some((_, next)) => {
                            value.line_break();
                            seg = next.strip_suffix('\r').unwrap_or(next);
                        }
                        None => {
                            return Err(format!(
                                "The quote that starts on line {line_no} is never closed."
                            ));
                        }
                    }
                };
                let after = after.trim();
                if !after.is_empty() && !after.starts_with('#') {
                    return Err(format!("Line {line_no} has text after the closing quote."));
                }
                (value.value, value.too_long)
            }
            _ => {
                // A comment starts at a # with a space before it.
                let end = rest
                    .char_indices()
                    .find(|&(i, c)| c == '#' && rest[..i].ends_with([' ', '\t']))
                    .map_or(rest.len(), |(i, _)| i);
                (Zeroizing::new(rest[..end].trim_end().to_owned()), false)
            }
        };
        out.push(Raw {
            line: line_no,
            name: name.to_owned(),
            value,
            too_long,
            content_type: String::new(),
            expires: String::new(),
            tags: String::new(),
            description: String::new(),
            owner: String::new(),
            notify: String::new(),
        });
    }
    Ok(out)
}

/// A quoted `.env` value, read a line at a time. Double quotes take
/// escapes. The quote and escape state carry over from one line to the
/// next, so a value over many lines is read in one pass.
struct Quoted {
    q: char,
    /// Wiped when dropped, on every way out of the parser.
    value: Zeroizing<String>,
    /// A `\` was the last character, and the next one says what it means.
    escape: bool,
    /// The value went over Key Vault's limit and stopped growing.
    too_long: bool,
}

impl Quoted {
    fn new(q: char) -> Self {
        Self {
            q,
            value: Zeroizing::new(String::new()),
            escape: false,
            too_long: false,
        }
    }

    fn push(&mut self, c: char) {
        if self.too_long {
            return;
        }
        // CRLF counts as one line break, as the value is stored.
        if c == '\n' && self.value.ends_with('\r') {
            self.value.pop();
        }
        if self.value.len() + c.len_utf8() > MAX_VALUE_BYTES {
            self.too_long = true;
            return;
        }
        self.value.push(c);
    }

    /// Read one piece of a line. What follows the closing quote, or `None`
    /// if the quote is still open at the end of `seg`.
    fn feed<'a>(&mut self, seg: &'a str) -> Option<&'a str> {
        for (i, c) in seg.char_indices() {
            if self.escape {
                self.escaped(c);
            } else if c == self.q {
                return Some(&seg[i + 1..]);
            } else if c == '\\' && self.q == '"' {
                self.escape = true;
            } else {
                self.push(c);
            }
        }
        None
    }

    /// The line break between two lines inside the quotes.
    fn line_break(&mut self) {
        if self.escape {
            self.escaped('\n');
        } else {
            self.push('\n');
        }
    }

    fn escaped(&mut self, c: char) {
        self.escape = false;
        match c {
            'n' => self.push('\n'),
            'r' => self.push('\r'),
            't' => self.push('\t'),
            '"' => self.push('"'),
            '\\' => self.push('\\'),
            // Anything else is kept as written.
            other => {
                self.push('\\');
                self.push(other);
            }
        }
    }
}

// ---------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------

const COLUMNS: [&str; 8] = [
    "name",
    "value",
    "content_type",
    "expires",
    "tags",
    "description",
    "owner",
    "notify",
];

/// RFC 4180 CSV with a header row. `name` and `value` are needed;
/// `content_type`, `expires`, `tags`, `description`, `owner` and `notify`
/// are optional. Fields may be quoted,
/// with `""` for a quote, and quoted fields may hold commas and line
/// breaks. Blank lines are skipped.
fn parse_csv(text: &str) -> Result<Vec<Raw>, String> {
    let records = csv_records(text)?;
    let mut records = records.into_iter();
    let Some((_, header)) = records.next() else {
        return Ok(Vec::new());
    };
    let mut at: HashMap<&str, usize> = HashMap::new();
    for (i, h) in header.iter().enumerate() {
        let h = h.trim().to_ascii_lowercase();
        // The column is given by its place, never its text: a file with no
        // header row has a value there.
        let Some(col) = COLUMNS.iter().find(|c| **c == h) else {
            return Err(format!(
                "The first line needs column names: name, value, and optionally content_type, expires, tags, description, owner and notify. Keyring doesn't know the column name in column {} of the first line.",
                i + 1
            ));
        };
        if at.insert(col, i).is_some() {
            return Err(format!("The column {col} is in the first line twice."));
        }
    }
    if !at.contains_key("name") || !at.contains_key("value") {
        return Err(
            "The first line needs column names, including name and value. For example: name,value,content_type,expires,tags".into(),
        );
    }
    let mut out = Vec::new();
    for (line, mut fields) in records {
        if fields.len() != header.len() {
            let n = fields.len();
            return Err(format!(
                "Line {line} has {n} fields, but the first line has {}. Put a value that holds a comma in double quotes.",
                header.len()
            ));
        }
        let mut take = |col: &str| {
            at.get(col)
                .map(|&i| std::mem::take(&mut fields[i]))
                .unwrap_or_default()
        };
        let raw = Raw {
            line,
            name: take("name"),
            value: Zeroizing::new(take("value")),
            too_long: false,
            content_type: take("content_type"),
            expires: take("expires"),
            tags: take("tags"),
            description: take("description"),
            owner: take("owner"),
            notify: take("notify"),
        };
        drop(take);
        out.push(raw);
    }
    Ok(out)
}

/// One CSV record's fields, zeroised when dropped, so a file refused part
/// way through leaves no values behind.
type Fields = Zeroizing<Vec<String>>;

/// Split CSV text into records, each with the line it starts on. A record
/// that is one empty field (a blank line) is skipped.
fn csv_records(text: &str) -> Result<Vec<(usize, Fields)>, String> {
    let mut out = Vec::new();
    let mut fields: Fields = Zeroizing::new(Vec::new());
    let mut field = Zeroizing::new(String::new());
    let mut line = 1;
    let mut start = 1;
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    let mut field_started = false;
    let end_record = |fields: &mut Fields,
                      field: &mut Zeroizing<String>,
                      out: &mut Vec<(usize, Fields)>,
                      start: usize| {
        fields.push(std::mem::take(&mut **field));
        let record = std::mem::replace(fields, Zeroizing::new(Vec::new()));
        if !(record.len() == 1 && record[0].is_empty()) {
            out.push((start, record));
        }
    };
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => {
                    quoted = false;
                    match chars.peek() {
                        None | Some(',' | '\n' | '\r') => {}
                        Some(_) => {
                            return Err(format!(
                                "Line {line} has text straight after a closing quote. Inside quotes, write a quote as two quotes (\"\")."
                            ));
                        }
                    }
                }
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if !field_started => {
                quoted = true;
                field_started = true;
            }
            ',' => {
                fields.push(std::mem::take(&mut *field));
                field_started = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                end_record(&mut fields, &mut field, &mut out, start);
                field_started = false;
                line += 1;
                start = line;
            }
            _ => {
                field.push(c);
                field_started = true;
            }
        }
    }
    if quoted {
        return Err(format!(
            "The quote that starts on line {start} is never closed."
        ));
    }
    if !field.is_empty() || !fields.is_empty() {
        end_record(&mut fields, &mut field, &mut out, start);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

    fn env(text: &str) -> Vec<Row> {
        parse(text.as_bytes(), Format::Env, NOW, crate::owner::Rules::OFF).unwrap()
    }

    fn csv(text: &str) -> Vec<Row> {
        parse(text.as_bytes(), Format::Csv, NOW, crate::owner::Rules::OFF).unwrap()
    }

    fn values(rows: &[Row]) -> Vec<(&str, &str)> {
        rows.iter()
            .map(|r| (r.name.as_str(), r.value.expose()))
            .collect()
    }

    #[test]
    fn env_basics_comments_and_export() {
        let rows = env(
            "# a comment\n\nDB_PASSWORD=hunter2\nexport API_KEY = abc123 # trailing\n  PLAIN=a#b\nURL=http://x/#frag\n",
        );
        assert_eq!(
            values(&rows),
            [
                ("DB-PASSWORD", "hunter2"),
                ("API-KEY", "abc123"),
                ("PLAIN", "a#b"),
                ("URL", "http://x/#frag"),
            ]
        );
        assert_eq!(rows[0].original, "DB_PASSWORD");
        assert_eq!(rows[1].line, 4);
        assert!(rows.iter().all(|r| r.problem.is_none()));
    }

    #[test]
    fn env_quoting_and_escapes() {
        let rows = env(concat!(
            "A=\"two words # not a comment\"\n",
            "B='single $NO \\n escapes'\n",
            "C=\"line\\nbreak \\\"quoted\\\" tab\\t back\\\\slash \\x kept\"\n",
            "D=\"multi\nline\" # after\n",
            "E='also\nmulti'\n",
            "F=\"\"\n",
        ));
        assert_eq!(rows[0].value.expose(), "two words # not a comment");
        assert_eq!(rows[1].value.expose(), "single $NO \\n escapes");
        assert_eq!(
            rows[2].value.expose(),
            "line\nbreak \"quoted\" tab\t back\\slash \\x kept"
        );
        assert_eq!(rows[3].value.expose(), "multi\nline");
        assert_eq!(rows[4].value.expose(), "also\nmulti");
        assert_eq!(rows[4].line, 6, "line numbers count the extra lines");
        assert!(rows[5].problem.as_deref().unwrap().contains("no value"));
    }

    #[test]
    fn env_errors_name_the_line_never_the_value() {
        let e = parse(
            b"A=1\nnot a pair\n",
            Format::Env,
            NOW,
            crate::owner::Rules::OFF,
        )
        .err()
        .unwrap();
        assert!(e.contains("Line 2"), "{e}");
        let e = parse(
            b"A=\"never closed hunter2\n",
            Format::Env,
            NOW,
            crate::owner::Rules::OFF,
        )
        .err()
        .unwrap();
        assert!(e.contains("line 1") && !e.contains("hunter2"), "{e}");
        let e = parse(
            b"A=\"x\" junk\n",
            Format::Env,
            NOW,
            crate::owner::Rules::OFF,
        )
        .err()
        .unwrap();
        assert!(e.contains("after the closing quote"), "{e}");
        let e = parse(b"=x\n", Format::Env, NOW, crate::owner::Rules::OFF)
            .err()
            .unwrap();
        assert!(e.contains("no name"), "{e}");
    }

    #[test]
    fn bom_and_crlf() {
        let rows = env("\u{feff}A=1\r\nB=\"x\r\ny\"\r\n");
        assert_eq!(values(&rows), [("A", "1"), ("B", "x\ny")]);
        let rows = csv("\u{feff}name,value\r\nA,1\r\nB,\"x\r\ny\"\r\n");
        assert_eq!(values(&rows), [("A", "1"), ("B", "x\ny")]);
    }

    #[test]
    fn empty_values_are_kept_as_rows_with_a_problem() {
        let rows = env("A=\nB=''\n");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.problem.is_some()));
        let rows = csv("name,value\nA,\n");
        assert!(rows[0].problem.as_deref().unwrap().contains("no value"));
    }

    #[test]
    fn duplicate_and_clashing_names_are_refused() {
        let e = parse(b"A=1\nA=2\n", Format::Env, NOW, crate::owner::Rules::OFF)
            .err()
            .unwrap();
        assert!(e.contains("A is on line 1 and line 2"), "{e}");
        let e = parse(
            b"DB_PASSWORD=1\ndb-password=2\n",
            Format::Env,
            NOW,
            crate::owner::Rules::OFF,
        )
        .err()
        .unwrap();
        assert!(
            e.contains("DB_PASSWORD (line 1) and db-password (line 2) both become DB-PASSWORD"),
            "{e}"
        );
        assert!(!e.contains('1') || !e.contains("=1"));
    }

    #[test]
    fn names_are_converted() {
        assert_eq!(convert_name("DB_PASSWORD"), "DB-PASSWORD");
        assert_eq!(convert_name("app.db.url"), "app-db-url");
        assert_eq!(convert_name("_LEADING"), "LEADING");
        assert_eq!(convert_name("naïve"), "na-ve");
        let rows = env("___=x\n");
        assert!(rows[0].problem.is_some());
    }

    #[test]
    fn csv_columns_quotes_and_optional_fields() {
        let rows = csv(concat!(
            "Name,Value,content_type,expires,tags\n",
            "db_password,\"a,b \"\"c\"\"\",text/plain,2030-01-02,env=prod; team = ops\n",
            "\n",
            "plain, keeps spaces ,,,\n",
        ));
        // An optional description column, merged into the tags.
        let noted = csv(concat!(
            "name,value,tags,description\n",
            "a,v,env=prod,\"Used by the \"\"billing\"\" job\nline two\"\n",
            "b,v,description=x,\n",
            "c,v,,\"bad\u{202E}note\"\n",
        ));
        assert_eq!(
            noted[0].tags["description"],
            "Used by the \"billing\" job\nline two"
        );
        assert_eq!(noted[0].tags["env"], "prod");
        assert!(noted[0].problem.is_none());
        assert!(
            noted[1]
                .problem
                .as_deref()
                .unwrap()
                .contains("description column")
        );
        assert!(
            noted[2]
                .problem
                .as_deref()
                .unwrap()
                .contains("hidden character")
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "db-password");
        assert_eq!(rows[0].value.expose(), "a,b \"c\"");
        assert_eq!(rows[0].content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            rows[0].expires,
            Some(dates::parse_iso_date("2030-01-02").unwrap() + 86_399)
        );
        assert_eq!(
            rows[0].tags.iter().collect::<Vec<_>>(),
            [
                (&"env".to_owned(), &"prod".to_owned()),
                (&"team".to_owned(), &"ops".to_owned())
            ]
        );
        assert_eq!(rows[1].value.expose(), " keeps spaces ");
        assert_eq!(rows[1].line, 4);
        // Only name and value.
        let rows = csv("value,name\nv,n\n");
        assert_eq!(values(&rows), [("n", "v")]);
    }

    #[test]
    fn csv_formula_values_are_stored_as_typed() {
        let rows =
            csv("name,value\na,=SUM(A1:A2)\nb,+1\nc,-2\nd,@cmd\ne,\"=HYPERLINK(\"\"x\"\")\"\n");
        assert_eq!(
            values(&rows),
            [
                ("a", "=SUM(A1:A2)"),
                ("b", "+1"),
                ("c", "-2"),
                ("d", "@cmd"),
                ("e", "=HYPERLINK(\"x\")")
            ]
        );
        assert!(rows.iter().all(|r| r.problem.is_none()));
    }

    #[test]
    fn csv_errors() {
        for (text, expect) in [
            ("name,secret\na,b\n", "doesn't know the column"),
            ("name\na\n", "including name and value"),
            ("name,value,name\na,b,c\n", "twice"),
            ("name,value\na,b,c\n", "Line 2 has 3 fields"),
            ("name,value\na,\"open\n", "never closed"),
            ("name,value\na,\"x\"y\n", "after a closing quote"),
            ("name,value\n", "no secrets"),
        ] {
            let e = parse(text.as_bytes(), Format::Csv, NOW, crate::owner::Rules::OFF)
                .err()
                .unwrap();
            assert!(e.contains(expect), "{text:?}: {e}");
        }
    }

    #[test]
    fn errors_never_quote_a_value_looking_header() {
        // A .csv with no header row: its first line is a value.
        for text in [
            "PASSWORD=TopSecret42\na,b\n",
            "name,TopSecret42\na,b\n",
            "\"TopSecret42\",name,value\nx,a,b\n",
        ] {
            let e = parse(text.as_bytes(), Format::Csv, NOW, crate::owner::Rules::OFF)
                .err()
                .unwrap();
            assert!(!e.to_ascii_lowercase().contains("topsecret42"), "{e}");
            assert!(e.contains("column"), "{e}");
        }
        let e = parse(
            b"name,value\nPASSWORD=TopSecret42\n",
            Format::Csv,
            NOW,
            crate::owner::Rules::OFF,
        )
        .err()
        .unwrap();
        assert!(!e.to_ascii_lowercase().contains("topsecret42"), "{e}");
        // Tag names aren't quoted either.
        let rows = csv("name,value,tags\na,v,TopSecret42=1;TopSecret42=2\n");
        let p = rows[0].problem.as_deref().unwrap();
        assert!(p.contains("twice") && !p.contains("TopSecret42"), "{p}");
    }

    #[test]
    fn quoted_values_over_many_lines_are_read_in_one_pass() {
        // Just under 1 MB: one quote that never closes, over about 450,000
        // one-character lines.
        let mut text = String::from("A=\"");
        while text.len() < 900 * 1024 {
            text.push_str("x\n");
        }
        let t = std::time::Instant::now();
        let e = parse(text.as_bytes(), Format::Env, NOW, crate::owner::Rules::OFF)
            .err()
            .unwrap();
        assert!(e.contains("never closed"), "{e}");
        assert!(
            t.elapsed() < std::time::Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
        // Closed at the end: the value is over Key Vault's limit.
        text.push_str("\"\n");
        let t = std::time::Instant::now();
        let rows = env(&text);
        assert!(t.elapsed() < std::time::Duration::from_millis(500));
        assert!(rows[0].problem.as_deref().unwrap().contains("25 KB"));
        assert!(rows[0].value.expose().len() <= MAX_VALUE_BYTES);
        // An escape at the end of a line carries on to the next.
        assert_eq!(env("A=\"x\\\ny\"\n")[0].value.expose(), "x\\\ny");
        // Exactly at the limit is fine.
        let at = format!("A=\"{}\"\n", "x".repeat(MAX_VALUE_BYTES));
        assert!(env(&at)[0].problem.is_none());
    }

    #[test]
    fn keyring_content_types_are_refused() {
        let rows = csv(concat!(
            "name,value,content_type\n",
            "a,{},application/vnd.keyring.login+json;v=1\n",
            "b,x,APPLICATION/VND.KEYRING.DATABASE+JSON; v=1\n",
            "c,x,application/vnd.keyring.future+json;v=9\n",
            "d,x,application/vnd.keyring.login+json\n",
            "e,x,text/plain\n",
            "f,x,application/x-pem-file\n",
        ));
        for r in &rows[..4] {
            assert_eq!(r.problem.as_deref(), Some(KEYRING_TYPE), "{}", r.name);
        }
        assert!(rows[4].problem.is_none() && rows[5].problem.is_none());
    }

    #[test]
    fn row_problems() {
        let rows = csv(concat!(
            "name,value,expires,tags\n",
            "a,v,2001-01-01,\n",
            "b,v,next week,\n",
            "c,v,,=x\n",
            "d,v,,k=1;k=2\n",
        ));
        let p: Vec<&str> = rows.iter().map(|r| r.problem.as_deref().unwrap()).collect();
        assert!(p[0].contains("already passed"));
        assert!(p[1].contains("YYYY-MM-DD"));
        assert!(p[2].contains("no name"));
        assert!(p[3].contains("twice"));
        let big = format!("a={}\n", "x".repeat(MAX_VALUE_BYTES + 1));
        assert!(env(&big)[0].problem.as_deref().unwrap().contains("25 KB"));
    }

    #[test]
    fn limits_and_encoding() {
        let many: String = (0..=MAX_ROWS).map(|i| format!("S{i}=v\n")).collect();
        let e = parse(many.as_bytes(), Format::Env, NOW, crate::owner::Rules::OFF)
            .err()
            .unwrap();
        assert!(e.contains("up to 500"), "{e}");
        let e = parse(b"A=\xff\n", Format::Env, NOW, crate::owner::Rules::OFF)
            .err()
            .unwrap();
        assert!(e.contains("UTF-8"));
        assert_eq!(Format::from_file_name("Secrets.CSV"), Format::Csv);
        assert_eq!(Format::from_file_name(".env"), Format::Env);
    }
}
