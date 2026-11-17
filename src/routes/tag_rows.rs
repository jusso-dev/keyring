//! Tags as rows: a name input and a value input for each tag, on every
//! form that sets tags (#253), with suggestions from the vault's own lists.
//!
//! **Fields.** Row `n` posts `tag-name-n` and `tag-value-n`, `n` from 1 to
//! [`MAX_ROWS`]. The same strings are the inputs' ids, so an error links
//! to its row. Indexed names pair a name with its value whatever is typed
//! or left out. A row number over the cap, written oddly (`01`) or posted
//! twice is refused, never guessed at. An empty row is skipped, so
//! clearing a row removes that tag. The form also posts `tag-rows`, so a
//! post with no rows at all (every row removed) can be told apart from a
//! post that never had them, which leaves the tags as they are.
//!
//! **What a row can't show.** A text input drops line breaks, and an HTML
//! page can't carry a NUL. A tag with either in its name or value, or with
//! a blank name, is listed and kept as it is. Every other tag is shown
//! exactly, spaces and `=` included, and comes back unchanged.
//!
//! **Suggestions.** Read as the signed-in person from the vault's list
//! calls (names and properties, never a value), from the session's short
//! list cache when it is fresh, within [`SUGGEST_TIME`]. Never the
//! `description` note. If the lists can't be read in time, the form shows
//! without suggestions and works the same.
//!
//! **Tags with their own field.** `description`, `owner` and `notify`
//! ([`crate::owner::has_own_field`]) are never shown in a row, never
//! suggested as names, and refused in a row with a pointer to their field.
//! Owner values that are plain addresses are suggested in the owner field.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;
use std::time::Duration;

use crate::AppState;
use crate::auth::CurrentSession;
use crate::description;
use crate::owner;
use crate::routes::forms::FieldErrors;
use crate::routes::secrets::form::{DESCRIPTION_IS_A_FIELD, MAX_TAG_NAME, MAX_TAG_VALUE, MAX_TAGS};

/// Said when `owner` or `notify` is typed as an ordinary tag name.
pub(crate) const OWNER_IS_A_FIELD: &str = "The owner and notify tags are set with the Owner and Notify fields. Put the addresses there, not in Tags.";

/// Most rows read from a post, and shown on a form.
pub(crate) const MAX_ROWS: usize = 40;
/// Empty rows after the item's tags, so tags can be added without script.
pub(crate) const EMPTY_ROWS: usize = 3;
/// Most tag names suggested.
pub(crate) const MAX_NAMES: usize = 200;
/// Most values suggested for one name, and overall for a new row.
pub(crate) const MAX_VALUES: usize = 50;
/// Longest name or value suggested, in characters. Longer ones are left out.
pub(crate) const MAX_SUGGESTION_CHARS: usize = 100;
/// Most entries in a filter box's list.
pub(crate) const MAX_FILTER_OPTIONS: usize = 200;
/// How long a form waits for the lists before it shows without suggestions.
pub(crate) const SUGGEST_TIME: Duration = Duration::from_secs(2);

/// The datalist of values for a new row, or a name with no list of its own.
pub(crate) const ANY_VALUES: &str = "tag-values-any";

/// Said when a form from before tag rows is posted.
pub(crate) const OUT_OF_DATE: &str = "This form changed since you opened it, so nothing was saved. Open it again, then make your change.";

/// Each row's two field names, made once. A [`FieldErrors`] field is a
/// `&'static str`, and these are what the errors name.
static IDS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    (1..=MAX_ROWS)
        .map(|n| {
            let name: &'static str = Box::leak(format!("tag-name-{n}").into_boxed_str());
            let value: &'static str = Box::leak(format!("tag-value-{n}").into_boxed_str());
            (name, value)
        })
        .collect()
});

/// Row `n`'s name and value field. `n` is from 1 to [`MAX_ROWS`].
fn ids(n: usize) -> (&'static str, &'static str) {
    IDS[n - 1]
}

fn breaks(s: &str) -> bool {
    s.contains(['\r', '\n', '\0'])
}

/// Can a row show this tag and post it back the same?
pub(crate) fn fits(name: &str, value: &str) -> bool {
    !name.trim().is_empty() && !breaks(name) && !breaks(value)
}

/// The tags a row can't show, without the ones that have their own field.
/// Kept as they are.
pub(crate) fn locked(tags: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    tags.iter()
        .filter(|(k, v)| !owner::has_own_field(k) && !fits(k, v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The rows a form posted. Fill it with [`TagPost::take`], or let serde
/// fill it from a flattened form.
#[derive(Default, Clone)]
pub(crate) struct TagPost {
    rows: BTreeMap<usize, (Option<String>, Option<String>)>,
    /// A row field numbered over [`MAX_ROWS`] or oddly, or sent twice.
    odd: bool,
    /// The `tags` box from before rows: a form opened before an upgrade.
    old_box: bool,
    /// The form had tag rows (`tag-rows` was posted).
    shown: bool,
}

impl std::fmt::Debug for TagPost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TagPost")
            .field("rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}

/// A field [`TagPost::take`] reads.
pub(crate) fn is_tag_field(key: &str) -> bool {
    matches!(key, "tags" | "tag-rows")
        || key.starts_with("tag-name-")
        || key.starts_with("tag-value-")
}

impl TagPost {
    /// Read one posted field. True when it was a tag field.
    pub(crate) fn take(&mut self, key: &str, value: String) -> bool {
        match key {
            "tags" => self.old_box = true,
            "tag-rows" => self.shown = true,
            _ => {}
        }
        if matches!(key, "tags" | "tag-rows") {
            return true;
        }
        let (n, is_name) = if let Some(n) = key.strip_prefix("tag-name-") {
            (n, true)
        } else if let Some(n) = key.strip_prefix("tag-value-") {
            (n, false)
        } else {
            return false;
        };
        match n.parse::<usize>() {
            Ok(i) if (1..=MAX_ROWS).contains(&i) && n == i.to_string() => {
                let row = self.rows.entry(i).or_default();
                let slot = if is_name { &mut row.0 } else { &mut row.1 };
                if slot.is_some() {
                    self.odd = true;
                } else {
                    *slot = Some(value);
                }
            }
            _ => self.odd = true,
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn of(pairs: &[(&str, &str)]) -> Self {
        let mut p = Self {
            shown: true,
            ..Self::default()
        };
        for (k, v) in pairs {
            p.take(k, (*v).to_owned());
        }
        p
    }

    /// Rows `[(name, value)]` numbered from 1, for tests.
    #[cfg(test)]
    pub(crate) fn rows(rows: &[(&str, &str)]) -> Self {
        let mut p = Self {
            shown: true,
            ..Self::default()
        };
        for (i, (k, v)) in rows.iter().enumerate() {
            let (name, value) = ids(i + 1);
            p.take(name, (*k).to_owned());
            p.take(value, (*v).to_owned());
        }
        p
    }
}

impl<'de> serde::Deserialize<'de> for TagPost {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = TagPost;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("form fields")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<TagPost, A::Error> {
                // Only tag fields' values are read. Others, such as a typed
                // secret's fields, are skipped without being copied.
                let mut p = TagPost::default();
                while let Some(k) = m.next_key::<String>()? {
                    if is_tag_field(&k) {
                        let v = m.next_value::<String>()?;
                        p.take(&k, v);
                    } else {
                        m.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(p)
            }
        }
        d.deserialize_map(Fields)
    }
}

/// The tags to write: the rows, checked, and the tags of `current` a row
/// can't show, kept. Without the note, the owner and notify, which
/// [`super::secrets::form::with_fields`] merges in after. Each problem goes on its row's field, or on `tags`. A
/// post with no tag fields at all keeps every tag as it is.
pub(crate) fn check(
    post: &TagPost,
    current: &BTreeMap<String, String>,
    errors: &mut FieldErrors,
) -> BTreeMap<String, String> {
    if !post.shown && !post.old_box && !post.odd && post.rows.is_empty() {
        return owner::without_fields(current);
    }
    let kept = locked(current);
    let mut tags = kept.clone();
    if post.old_box {
        errors.push("tags", OUT_OF_DATE);
    }
    if post.odd {
        errors.push(
            "tags",
            "The form sent tag rows it doesn't have, so nothing was saved. Open it again, then make your change.",
        );
    }
    for (&n, (name, value)) in &post.rows {
        let (name_id, value_id) = ids(n);
        let name = name.as_deref().unwrap_or_default();
        let value = value.as_deref().unwrap_or_default();
        if name.trim().is_empty() {
            if !value.is_empty() {
                errors.push(
                    name_id,
                    "Give this tag a name, or clear its value to leave it out.",
                );
            }
            continue;
        }
        // A tag the item already has, posted back as it was, is kept
        // whatever its name: ` owner ` set in the portal is an ordinary tag
        // and mustn't block a save. A new or changed row with a name that
        // looks like a field's is refused.
        let unchanged =
            !owner::has_own_field(name) && current.get(name).is_some_and(|v| v == value);
        let problem = if !unchanged && description::is_reserved(name) {
            Some((name_id, DESCRIPTION_IS_A_FIELD.to_owned()))
        } else if !unchanged && owner::is_reserved(name) {
            Some((name_id, OWNER_IS_A_FIELD.to_owned()))
        } else if breaks(name) {
            Some((
                name_id,
                "A tag name can't have a line break in it.".to_owned(),
            ))
        } else if breaks(value) {
            Some((
                value_id,
                "A tag value can't have a line break in it.".to_owned(),
            ))
        } else if name.len() > MAX_TAG_NAME {
            Some((
                name_id,
                format!("Tag names can be up to {MAX_TAG_NAME} characters."),
            ))
        } else if value.len() > MAX_TAG_VALUE {
            Some((
                value_id,
                format!("Tag values can be up to {MAX_TAG_VALUE} characters."),
            ))
        } else if kept.contains_key(name) {
            Some((
                name_id,
                format!(
                    "There's already a tag called {name} that this form can't show. Pick another name."
                ),
            ))
        } else if tags.insert(name.to_owned(), value.to_owned()).is_some() {
            Some((
                name_id,
                format!(
                    "The tag name {name} is used more than once. Each name can only be used once."
                ),
            ))
        } else {
            None
        };
        if let Some((field, message)) = problem {
            errors.push(field, message);
        }
    }
    if tags.len() > MAX_TAGS {
        errors.push(
            "tags",
            format!(
                "Key Vault allows up to {MAX_TAGS} tags, the description, owner and notify included. This has {}.",
                tags.len()
            ),
        );
    }
    tags
}

/// One row on the form.
pub(crate) struct TagRow {
    pub n: usize,
    pub name: String,
    pub value: String,
    pub name_id: &'static str,
    pub value_id: &'static str,
}

impl TagRow {
    fn new(n: usize, name: &str, value: &str) -> Self {
        let (name_id, value_id) = ids(n);
        Self {
            n,
            name: name.to_owned(),
            value: value.to_owned(),
            name_id,
            value_id,
        }
    }
}

/// The tag rows, the tags kept as they are, and the suggestions, for a
/// form page.
pub(crate) struct TagField {
    pub rows: Vec<TagRow>,
    pub locked: Vec<(String, String)>,
    pub suggest: Suggestions,
}

impl TagField {
    /// Filled from an item's tags (or none, for a new item).
    pub(crate) fn of(tags: &BTreeMap<String, String>) -> Self {
        let mut rows: Vec<TagRow> = tags
            .iter()
            .filter(|(k, v)| !owner::has_own_field(k) && fits(k, v))
            .take(MAX_ROWS)
            .enumerate()
            .map(|(i, (k, v))| TagRow::new(i + 1, k, v))
            .collect();
        pad(&mut rows);
        Self {
            rows,
            locked: locked(tags).into_iter().collect(),
            suggest: Suggestions::default(),
        }
    }

    /// Filled back from a post that had a problem, row numbers kept so
    /// each error stays beside its row.
    pub(crate) fn posted(post: &TagPost, current: &BTreeMap<String, String>) -> Self {
        let last = post.rows.keys().next_back().copied().unwrap_or(0);
        let mut rows: Vec<TagRow> = (1..=last)
            .map(|n| match post.rows.get(&n) {
                Some((k, v)) => TagRow::new(
                    n,
                    k.as_deref().unwrap_or_default(),
                    v.as_deref().unwrap_or_default(),
                ),
                None => TagRow::new(n, "", ""),
            })
            .collect();
        pad(&mut rows);
        Self {
            rows,
            locked: locked(current).into_iter().collect(),
            suggest: Suggestions::default(),
        }
    }

    pub(crate) fn with(mut self, suggest: Suggestions) -> Self {
        self.suggest = suggest;
        self
    }
}

impl Default for TagField {
    /// A new item's: empty rows only.
    fn default() -> Self {
        Self::of(&BTreeMap::new())
    }
}

/// [`EMPTY_ROWS`] more rows, up to [`MAX_ROWS`].
fn pad(rows: &mut Vec<TagRow>) {
    let from = rows.last().map_or(1, |r| r.n + 1);
    let to = (from + EMPTY_ROWS - 1).min(MAX_ROWS);
    rows.extend((from..=to).map(|n| TagRow::new(n, "", "")));
}

/// One suggested name and the values used with it.
pub(crate) struct NameValues {
    pub name: String,
    pub list_id: String,
    pub values: Vec<String>,
}

/// Tag names in use, most used first, each with its values, and the most
/// used values overall. Owners are the `owner` values that are plain
/// addresses, for the owner field.
#[derive(Default)]
pub(crate) struct Suggestions {
    pub names: Vec<NameValues>,
    pub values: Vec<String>,
    pub owners: Vec<String>,
}

/// Fit for a suggestion: short, on one line, with nothing hidden in it.
fn usable(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= MAX_SUGGESTION_CHARS
        && !s.chars().any(crate::reason::is_unsafe)
}

/// Most used first, then in order; at most `max`.
fn ranked(counts: HashMap<&str, usize>, max: usize) -> Vec<&str> {
    let mut v: Vec<(&str, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter().take(max).map(|(s, _)| s).collect()
}

impl Suggestions {
    /// From each item's tags. The note is never suggested, and the tags
    /// with their own field aren't suggested as tags.
    pub(crate) fn from_sets<'a, I, T>(sets: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut names: HashMap<&str, usize> = HashMap::new();
        let mut by_name: HashMap<&str, HashMap<&str, usize>> = HashMap::new();
        let mut values: HashMap<&str, usize> = HashMap::new();
        let mut owners: HashMap<&str, usize> = HashMap::new();
        for set in sets {
            for (k, v) in set {
                if k == owner::OWNER_TAG && usable(v) && crate::notify::Address::parse(v).is_ok() {
                    *owners.entry(v).or_default() += 1;
                }
                if owner::has_own_field(k) || !usable(k) {
                    continue;
                }
                *names.entry(k).or_default() += 1;
                if usable(v) {
                    *by_name.entry(k).or_default().entry(v).or_default() += 1;
                    *values.entry(v).or_default() += 1;
                }
            }
        }
        let names = ranked(names, MAX_NAMES)
            .into_iter()
            .enumerate()
            .map(|(i, name)| NameValues {
                name: name.to_owned(),
                list_id: format!("tag-values-{}", i + 1),
                values: ranked(by_name.remove(name).unwrap_or_default(), MAX_VALUES)
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            })
            .collect();
        Self {
            names,
            values: ranked(values, MAX_VALUES)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            owners: ranked(owners, owner::MAX_SUGGESTED)
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    /// The value list for a row with this name.
    pub(crate) fn list_for(&self, name: &str) -> &str {
        self.names
            .iter()
            .find(|n| n.name == name && !n.values.is_empty())
            .map_or(ANY_VALUES, |n| n.list_id.as_str())
    }

    /// For a filter box: each name, then `name=value` for its values, most
    /// used first.
    pub(crate) fn filter_options(&self) -> Vec<String> {
        self.names
            .iter()
            .flat_map(|n| {
                std::iter::once(n.name.clone())
                    .chain(n.values.iter().map(|v| format!("{}={v}", n.name)))
            })
            .take(MAX_FILTER_OPTIONS)
            .collect()
    }
}

/// A filter box's suggestions from items read for a page (expiry, age,
/// search).
pub(crate) fn filter_options_of<'a>(
    items: impl IntoIterator<Item = &'a crate::expiry::Item>,
) -> Vec<String> {
    Suggestions::from_sets(
        items
            .into_iter()
            .map(|i| i.tags.iter().map(|(k, v)| (k.as_str(), v.as_str()))),
    )
    .filter_options()
}

/// Suggestions for a form in `vault`, from its lists as the person. Empty
/// when they can't be read within [`SUGGEST_TIME`].
pub(crate) async fn for_vault(
    state: &AppState,
    session: &CurrentSession,
    vault: &str,
) -> Suggestions {
    let read = super::every_vault::read(state, session, vec![vault.to_owned()]);
    match tokio::time::timeout(SUGGEST_TIME, read).await {
        Ok(fanned) => Suggestions::from_sets(fanned.read.iter().flat_map(|(_, items)| {
            items
                .iter()
                .map(|i| i.tags.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        })),
        Err(_) => Suggestions::default(),
    }
}

/// The link from a detail page's tag to its list, filtered by that tag.
/// `None` when the filter couldn't find it again: a name with an `=`, or
/// spaces at either end, which the filter trims.
pub(crate) fn filter_href(list: &str, name: &str, value: &str) -> Option<String> {
    let exact = |s: &str| s == s.trim();
    (!name.contains('=') && exact(name) && exact(value) && fits(name, value)).then(|| {
        format!(
            "{list}?tag={}",
            crate::auth::return_to::encode(&format!("{name}={value}"))
        )
    })
}

/// Does an item with `tags` match a list's tag filter, `name` or
/// `name=value`? Case-insensitive, as the secrets list matches. `tags` are
/// the item's tags as stored, `owner` and `notify` included, so
/// `owner=ops@example.com` finds them as it finds any tag. A `notify`
/// value matches the whole list or any one address in it.
pub(crate) fn matches_filter(filter: &str, tags: &[(String, String)]) -> bool {
    let tag = filter.trim();
    if tag.is_empty() {
        return true;
    }
    let (key, value) = match tag.split_once('=') {
        Some((k, v)) => (k.trim(), Some(v.trim())),
        None => (tag, None),
    };
    tags.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case(key)
            && value.is_none_or(|want| {
                v.eq_ignore_ascii_case(want)
                    || (k == owner::NOTIFY_TAG
                        && v.split(',').any(|e| e.trim().eq_ignore_ascii_case(want)))
            })
    })
}

/// What a list's tag filter and search box match: the item's tags with
/// `owner` and `notify` but without the description, which the search box
/// matches on its own.
pub(crate) fn filter_tags(tags: &BTreeMap<String, String>) -> Vec<(String, String)> {
    description::without(tags).into_iter().collect()
}

/// The text a list's search box and live filter match: the name, each tag
/// in `tags` as `name=value` and the description, lower case, line breaks
/// as spaces. It goes in a `data-filter-text` attribute (escaped) on a row
/// shown to people who can read the tags. Never logged.
pub(crate) fn filter_text(name: &str, tags: &[(String, String)], description: &str) -> String {
    let mut out = name.to_lowercase();
    for (k, v) in tags {
        out.push(' ');
        out.push_str(&format!("{k}={v}").to_lowercase());
    }
    if !description.is_empty() {
        out.push(' ');
        out.push_str(&description.to_lowercase());
    }
    out.replace(['\r', '\n'], " ")
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

    fn checked(
        post: &TagPost,
        current: &BTreeMap<String, String>,
    ) -> (BTreeMap<String, String>, FieldErrors) {
        let mut e = FieldErrors::new();
        let t = check(post, current, &mut e);
        (t, e)
    }

    #[test]
    fn rows_are_read_by_number_whatever_the_order() {
        let p = TagPost::of(&[
            ("tag-value-2", "data"),
            ("tag-name-1", "env"),
            ("tag-name-2", "team"),
            ("tag-value-1", "prod"),
            ("csrf", "x"),
        ]);
        let (t, e) = checked(&p, &BTreeMap::new());
        assert!(e.is_empty());
        assert_eq!(t, tags(&[("env", "prod"), ("team", "data")]));
    }

    #[test]
    fn spaces_and_equals_are_kept_exactly() {
        let p = TagPost::rows(&[(" a=b ", " c = d "), ("flag", "")]);
        let (t, e) = checked(&p, &BTreeMap::new());
        assert!(e.is_empty());
        assert_eq!(t, tags(&[(" a=b ", " c = d "), ("flag", "")]));
    }

    #[test]
    fn empty_rows_are_skipped_and_a_value_needs_a_name() {
        let p = TagPost::rows(&[("", ""), ("  ", ""), ("", "orphan")]);
        let (t, e) = checked(&p, &BTreeMap::new());
        assert!(t.is_empty());
        assert_eq!(e.len(), 1);
        assert!(
            e.error_for("tag-name-3")
                .unwrap()
                .contains("Give this tag a name")
        );
    }

    #[test]
    fn a_name_twice_is_refused_on_the_second_row() {
        let p = TagPost::rows(&[("env", "a"), ("team", "b"), ("env", "c")]);
        let (_, e) = checked(&p, &BTreeMap::new());
        assert_eq!(e.len(), 1);
        assert!(
            e.error_for("tag-name-3")
                .unwrap()
                .contains("env is used more than once")
        );
        // Case matters, as Key Vault keeps it.
        let p = TagPost::rows(&[("env", "a"), ("Env", "b")]);
        assert!(checked(&p, &BTreeMap::new()).1.is_empty());
    }

    #[test]
    fn odd_posts_are_refused_not_guessed() {
        for pairs in [
            &[("tag-name-1", "a"), ("tag-name-1", "b")][..],
            &[("tag-value-41", "x")],
            &[("tag-name-0", "x")],
            &[("tag-name-01", "x")],
            &[("tag-name-+1", "x")],
            &[("tag-name-", "x")],
        ] {
            let (_, e) = checked(&TagPost::of(pairs), &BTreeMap::new());
            assert!(e.error_for("tags").is_some(), "{pairs:?}");
        }
        // Up to the cap is fine, and gaps between rows are fine.
        let p = TagPost::of(&[("tag-name-40", "last"), ("tag-name-7", "seventh")]);
        let (t, e) = checked(&p, &BTreeMap::new());
        assert!(e.is_empty());
        assert_eq!(t.len(), 2);
        // The old box means an old page: never read as "no tags".
        let (_, e) = checked(&TagPost::of(&[("tags", "")]), &tags(&[("env", "prod")]));
        assert_eq!(e.error_for("tags"), Some(OUT_OF_DATE));
    }

    #[test]
    fn limits_and_the_reserved_name() {
        let long = "n".repeat(MAX_TAG_NAME + 1);
        let p = TagPost::rows(&[
            (&long, ""),
            ("v", &"x".repeat(MAX_TAG_VALUE + 1)),
            ("description", "x"),
            ("owner", "a@example.com"),
            (" notify", "b@example.com"),
            ("Owner", "kept as an ordinary tag"),
        ]);
        let (_, e) = checked(&p, &BTreeMap::new());
        assert!(e.error_for("tag-name-1").unwrap().contains("512"));
        assert!(e.error_for("tag-value-2").unwrap().contains("256"));
        assert_eq!(e.error_for("tag-name-3"), Some(DESCRIPTION_IS_A_FIELD));
        assert_eq!(e.error_for("tag-name-4"), Some(OWNER_IS_A_FIELD));
        assert_eq!(e.error_for("tag-name-5"), Some(OWNER_IS_A_FIELD));
        assert!(e.error_for("tag-name-6").is_none());
        let many: Vec<(String, String)> = (0..16).map(|i| (format!("k{i}"), "v".into())).collect();
        let rows: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let (_, e) = checked(&TagPost::rows(&rows), &BTreeMap::new());
        assert!(e.error_for("tags").unwrap().contains("This has 16"));
        // A line break can only come from a crafted post.
        let (_, e) = checked(&TagPost::rows(&[("a", "b\nc")]), &BTreeMap::new());
        assert!(e.error_for("tag-value-1").unwrap().contains("line break"));
    }

    #[test]
    fn tags_a_row_cant_show_are_kept_and_counted() {
        let cur = tags(&[
            ("note", "two\nlines"),
            ("env", "prod"),
            ("description", "x"),
        ]);
        assert_eq!(locked(&cur), tags(&[("note", "two\nlines")]));
        // The form shows env as a row; posting it back keeps both.
        let (t, e) = checked(&TagPost::rows(&[("env", "prod")]), &cur);
        assert!(e.is_empty());
        assert_eq!(t, tags(&[("env", "prod"), ("note", "two\nlines")]));
        // A row can't take the locked tag's name.
        let (_, e) = checked(&TagPost::rows(&[("note", "one")]), &cur);
        assert!(e.error_for("tag-name-1").unwrap().contains("can't show"));
        // Removing every row keeps the locked tag.
        let (t, _) = checked(&TagPost::of(&[("tag-rows", "1")]), &cur);
        assert_eq!(t, tags(&[("note", "two\nlines")]));
        // A post with no tag fields at all changes nothing.
        let (t, e) = checked(&TagPost::default(), &cur);
        assert!(e.is_empty());
        assert_eq!(t, owner::without_fields(&cur));
    }

    #[test]
    fn what_a_row_can_show() {
        assert!(fits("env", "prod"));
        assert!(fits("a=b", " c "));
        assert!(fits("flag", ""));
        assert!(!fits("", "x"));
        assert!(!fits("  ", "x"));
        assert!(!fits("a\nb", "x"));
        assert!(!fits("a", "b\r"));
        assert!(!fits("a", "nul\0"));
    }

    #[test]
    fn every_tag_that_fits_round_trips() {
        let cur = tags(&[
            ("env", "prod"),
            (" padded ", " x "),
            ("a=b", "c=d"),
            ("q\"<x>&", "'v' <b>"),
            ("flag", ""),
            ("description", "the note"),
            ("owner", "odd\nowner"),
            ("notify", "a@example.com"),
            ("multi", "line\nvalue"),
        ]);
        let field = TagField::of(&cur);
        assert_eq!(
            field.locked,
            vec![("multi".to_owned(), "line\nvalue".to_owned())]
        );
        // Post every row the form shows, as a browser would.
        let mut post = TagPost::default();
        for r in &field.rows {
            post.take(r.name_id, r.name.clone());
            post.take(r.value_id, r.value.clone());
        }
        let (t, e) = checked(&post, &cur);
        assert!(e.is_empty());
        assert_eq!(t, owner::without_fields(&cur));
        assert_eq!(field.rows.len(), 5 + EMPTY_ROWS);
        assert!(
            field
                .rows
                .iter()
                .rev()
                .take(EMPTY_ROWS)
                .all(|r| r.name.is_empty())
        );
    }

    #[test]
    fn posted_rows_keep_their_numbers() {
        let p = TagPost::of(&[("tag-name-3", "x"), ("tag-value-3", "y")]);
        let f = TagField::posted(&p, &BTreeMap::new());
        let ns: Vec<usize> = f.rows.iter().map(|r| r.n).collect();
        assert_eq!(ns, [1, 2, 3, 4, 5, 6]);
        assert_eq!(f.rows[2].name_id, "tag-name-3");
        assert_eq!(f.rows[2].value, "y");
        // Never more rows than the cap.
        let p = TagPost::of(&[("tag-name-40", "x")]);
        assert_eq!(TagField::posted(&p, &BTreeMap::new()).rows.len(), MAX_ROWS);
    }

    #[test]
    fn suggestions_rank_by_use_and_leave_out_the_note() {
        let items = [
            vec![
                ("env", "prod"),
                ("team", "data"),
                ("description", "secret note"),
            ],
            vec![("env", "prod"), ("owner", "a"), ("notify", "b@example.com")],
            vec![
                ("env", "test"),
                ("team", "web"),
                ("owner", "Alex@example.com"),
            ],
            vec![("owner", "Alex@example.com"), ("owner-team", "x")],
        ];
        let s = Suggestions::from_sets(items.iter().map(|t| t.iter().copied()));
        let names: Vec<&str> = s.names.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["env", "team", "owner-team"]);
        // Only owners that are plain addresses, never notify.
        assert_eq!(s.owners, ["Alex@example.com"]);
        assert_eq!(s.names[0].values, ["prod", "test"]);
        assert_eq!(s.names[0].list_id, "tag-values-1");
        assert_eq!(s.values[0], "prod");
        assert!(!s.values.iter().any(|v| v.contains("note")));
        assert_eq!(s.list_for("team"), "tag-values-2");
        assert_eq!(s.list_for("other"), ANY_VALUES);
        assert_eq!(&s.filter_options()[..3], ["env", "env=prod", "env=test"]);
    }

    #[test]
    fn suggestions_are_capped() {
        let names: Vec<String> = (0..300).map(|i| format!("n{i:03}")).collect();
        let values: Vec<String> = (0..80).map(|i| format!("v{i:02}")).collect();
        let long = "x".repeat(MAX_SUGGESTION_CHARS + 1);
        let mut sets: Vec<Vec<(&str, &str)>> =
            names.iter().map(|n| vec![(n.as_str(), "v")]).collect();
        sets.extend(values.iter().map(|v| vec![("n000", v.as_str())]));
        sets.push(vec![
            ("n000", long.as_str()),
            (long.as_str(), "x"),
            ("bad\u{202E}", "x"),
        ]);
        let s = Suggestions::from_sets(sets.iter().map(|t| t.iter().copied()));
        assert_eq!(s.names.len(), MAX_NAMES);
        assert_eq!(s.names[0].name, "n000");
        assert_eq!(s.names[0].values.len(), MAX_VALUES);
        assert!(s.values.len() <= MAX_VALUES);
        assert!(s.names.iter().all(|n| usable(&n.name)));
        assert!(!s.names[0].values.contains(&long));
        assert_eq!(s.filter_options().len(), MAX_FILTER_OPTIONS);
    }

    #[test]
    fn detail_links_are_encoded() {
        assert_eq!(
            filter_href("/v/kv/secrets", "env", "a b&c=d").unwrap(),
            "/v/kv/secrets?tag=env%3Da+b%26c%3Dd"
        );
        assert!(filter_href("/v/kv/keys", "a=b", "c").is_none());
        assert!(filter_href("/v/kv/keys", "a", " c").is_none());
        assert_eq!(
            filter_href("/v/kv/keys", "flag", "").unwrap(),
            "/v/kv/keys?tag=flag%3D"
        );
        assert!(matches_filter("ENV=Prod", &[("env".into(), "prod".into())]));
        assert!(matches_filter("env", &[("env".into(), "x".into())]));
        assert!(!matches_filter("env=x", &[("env".into(), "xy".into())]));
    }

    #[test]
    fn the_filter_finds_owner_and_each_notify_address() {
        let t = filter_tags(&tags(&[
            ("owner", "ops@example.com"),
            ("notify", "Sam@example.com, backup@example.com"),
            ("description", "note"),
            ("env", "prod"),
        ]));
        assert!(matches_filter("owner", &t));
        assert!(matches_filter("owner=OPS@example.com", &t));
        assert!(matches_filter("notify", &t));
        assert!(matches_filter("notify=sam@example.com", &t));
        assert!(matches_filter(" notify = BACKUP@example.com ", &t));
        assert!(matches_filter(
            "notify=sam@example.com, backup@example.com",
            &t
        ));
        assert!(!matches_filter("notify=pat@example.com", &t));
        assert!(!matches_filter("notify=example.com", &t));
        // The description stays out of the tag filter, as before.
        assert!(!matches_filter("description", &t));
        // Only `notify` is split: another tag's commas are part of its value.
        let other = filter_tags(&tags(&[("team", "a, b")]));
        assert!(!matches_filter("team=a", &other));
        let text = filter_text("DB", &t, "Line\nTwo");
        assert_eq!(
            text,
            "db env=prod notify=sam@example.com, backup@example.com owner=ops@example.com line two"
        );
    }

    #[test]
    fn a_padded_field_name_already_stored_is_kept_but_never_added() {
        let cur = tags(&[(" owner ", "x"), (" description ", "y"), ("env", "prod")]);
        let p = TagPost::rows(&[(" owner ", "x"), (" description ", "y"), ("env", "test")]);
        let (t, e) = checked(&p, &cur);
        assert_eq!(e, FieldErrors::new());
        assert_eq!(
            t,
            tags(&[(" owner ", "x"), (" description ", "y"), ("env", "test")])
        );
        // Changed, or new: refused with the pointer to the field.
        let p = TagPost::rows(&[
            (" owner ", "changed"),
            (" description ", "y"),
            (" notify", "z"),
        ]);
        let (_, e) = checked(&p, &cur);
        assert_eq!(e.error_for("tag-name-1"), Some(OWNER_IS_A_FIELD));
        assert!(e.error_for("tag-name-2").is_none());
        assert_eq!(e.error_for("tag-name-3"), Some(OWNER_IS_A_FIELD));
        // The exact names are never kept from a row, even unchanged.
        let cur = tags(&[("owner", "a@example.com")]);
        let (_, e) = checked(&TagPost::rows(&[("owner", "a@example.com")]), &cur);
        assert_eq!(e.error_for("tag-name-1"), Some(OWNER_IS_A_FIELD));
    }
}
