//! Paging for the item lists: the page size, the `page` query parameter
//! and what the pager shows.

use serde::Deserialize;

/// Rows per page on the secrets, certificates and keys lists and their
/// deleted lists.
pub const PER_PAGE: usize = 100;

/// The `page` query parameter on its own, for lists with no other filter.
#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub page: Option<usize>,
}

/// What the pager shows under a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pager {
    /// 1-based, always within `1..=pages`.
    pub page: usize,
    /// At least 1, even for an empty list.
    pub pages: usize,
    /// Rows before this page.
    pub shown_from: usize,
    /// Rows on this page.
    pub shown: usize,
    /// What the rows are, such as "secrets".
    pub noun: &'static str,
    pub prev_url: Option<String>,
    pub next_url: Option<String>,
}

impl Pager {
    /// Whether there is more than one page, so the pager is worth showing.
    pub fn is_needed(&self) -> bool {
        self.pages > 1
    }

    /// The 1-based number of the last row on this page.
    pub fn shown_to(&self) -> usize {
        self.shown_from + self.shown
    }
}

/// Cut `rows` to the requested page. A missing, zero or too-large page
/// number gives the nearest real page. `url` builds the link for a page.
pub fn paginate<T>(
    rows: Vec<T>,
    requested: Option<usize>,
    noun: &'static str,
    url: impl Fn(usize) -> String,
) -> (Vec<T>, Pager) {
    let pages = rows.len().div_ceil(PER_PAGE).max(1);
    let page = requested.unwrap_or(1).clamp(1, pages);
    let shown_from = (page - 1) * PER_PAGE;
    let rows: Vec<T> = rows.into_iter().skip(shown_from).take(PER_PAGE).collect();
    let pager = Pager {
        page,
        pages,
        shown_from,
        shown: rows.len(),
        noun,
        prev_url: (page > 1).then(|| url(page - 1)),
        next_url: (page < pages).then(|| url(page + 1)),
    };
    (rows, pager)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(p: usize) -> String {
        format!("/x?page={p}")
    }

    #[test]
    fn one_page() {
        let (rows, p) = paginate(vec![1, 2, 3], None, "things", url);
        assert_eq!(rows, [1, 2, 3]);
        assert_eq!((p.page, p.pages, p.shown_from, p.shown_to()), (1, 1, 0, 3));
        assert!(!p.is_needed());
        assert_eq!((p.prev_url, p.next_url), (None, None));
    }

    #[test]
    fn empty_list_has_one_page() {
        let (rows, p) = paginate(Vec::<u8>::new(), Some(4), "things", url);
        assert!(rows.is_empty());
        assert_eq!((p.page, p.pages), (1, 1));
    }

    #[test]
    fn middle_and_out_of_range_pages() {
        let all: Vec<usize> = (0..250).collect();
        let (rows, p) = paginate(all.clone(), Some(2), "things", url);
        assert_eq!(rows.first(), Some(&100));
        assert_eq!(rows.len(), 100);
        assert_eq!(p.pages, 3);
        assert_eq!(p.prev_url.as_deref(), Some("/x?page=1"));
        assert_eq!(p.next_url.as_deref(), Some("/x?page=3"));
        let (rows, p) = paginate(all.clone(), Some(9), "things", url);
        assert_eq!((p.page, rows.len(), p.shown_to()), (3, 50, 250));
        assert_eq!(p.next_url, None);
        let (_, p) = paginate(all, Some(0), "things", url);
        assert_eq!(p.page, 1);
    }
}
