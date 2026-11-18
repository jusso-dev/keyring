//! Just enough date handling for Key Vault's Unix timestamps: show them as
//! dates and read dates typed into forms. All in UTC.

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) to days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `9 Nov 2026`.
pub fn format_date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    format!("{d} {} {y}", MONTHS[(m - 1) as usize])
}

/// `9 Nov 2026, 14:05 UTC`.
pub fn format_datetime(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    format!(
        "{}, {:02}:{:02} UTC",
        format_date(ts),
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// `2026-11-09`, the format of `<input type="date">`.
pub fn iso_date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parse `YYYY-MM-DD` to midnight UTC. `None` if it isn't a real date.
pub fn parse_iso_date(s: &str) -> Option<i64> {
    let mut parts = s.trim().splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d == 0 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    // Reject 31 Feb and the like by round-tripping.
    (civil_from_days(days) == (y, m, d)).then_some(days * 86_400)
}

/// A time from a log, for a table cell: `iso` for `<time datetime>`, and
/// `short` to show, in UTC. `iso` is `None` when the text isn't a UTC time
/// Keyring can read; the cell then shows the text as it is, with no
/// `<time>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogTime {
    /// `2026-11-18T05:22:09.123Z`, milliseconds kept when the log has them.
    pub iso: Option<String>,
    /// `18 Nov 2026, 05:22`, or the text as given when it couldn't be read.
    pub short: String,
}

/// Read a Log Analytics time such as `2026-11-18T05:22:09.1234567Z`: the
/// whole text must be `YYYY-MM-DDTHH:MM:SS`, an optional fraction, then
/// `Z`. Anything else (an offset, trailing text, a leap second, an empty
/// value) isn't guessed at: it comes back as text, with no ISO time.
pub fn log_time(raw: &str) -> LogTime {
    parse_log_time(raw).unwrap_or_else(|| LogTime {
        iso: None,
        short: raw.to_owned(),
    })
}

fn parse_log_time(raw: &str) -> Option<LogTime> {
    let body = raw.strip_suffix('Z')?;
    let (date, clock) = body.split_once('T')?;
    if date.len() != 10 {
        return None;
    }
    let day = parse_iso_date(date)?;
    let (hms, fraction) = match clock.split_once('.') {
        Some((hms, f)) => (hms, Some(f)),
        None => (clock, None),
    };
    let digits = |t: &str| t.len() == 2 && t.bytes().all(|b| b.is_ascii_digit());
    let mut parts = hms.split(':');
    let (h, m, sec) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !digits(h) || !digits(m) || !digits(sec) {
        return None;
    }
    let (h, m, sec): (u32, u32, u32) = (h.parse().ok()?, m.parse().ok()?, sec.parse().ok()?);
    // No leap seconds: `<time>` can't hold one.
    if h > 23 || m > 59 || sec > 59 {
        return None;
    }
    let millis = match fraction {
        None => String::new(),
        Some(f) if !f.is_empty() && f.len() <= 9 && f.bytes().all(|b| b.is_ascii_digit()) => {
            format!(".{:0<3}", &f[..f.len().min(3)])
        }
        Some(_) => return None,
    };
    Some(LogTime {
        iso: Some(format!("{date}T{h:02}:{m:02}:{sec:02}{millis}Z")),
        short: format!("{}, {h:02}:{m:02}", format_date(day)),
    })
}

/// "in 3 days", "today", "5 days ago". Whole days, rounded towards now.
pub fn relative_days(ts: i64, now: i64) -> String {
    let days = (ts - now) / 86_400;
    match days {
        0 => "today".into(),
        1 => "in 1 day".into(),
        -1 => "1 day ago".into(),
        d if d > 0 => format!("in {d} days"),
        d => format!("{} days ago", -d),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_times_are_read_whole_or_not_at_all() {
        let t = log_time("2026-11-18T05:22:09.1234567Z");
        assert_eq!(t.iso.as_deref(), Some("2026-11-18T05:22:09.123Z"));
        assert_eq!(t.short, "18 Nov 2026, 05:22");
        let t = log_time("2026-11-18T05:22:09.4Z");
        assert_eq!(t.iso.as_deref(), Some("2026-11-18T05:22:09.400Z"));
        assert_eq!(
            log_time("2026-11-18T05:22:09Z").iso.as_deref(),
            Some("2026-11-18T05:22:09Z")
        );
        for bad in [
            "",
            "2026-11-18T05:22:09",
            "2026-11-18T05:22:09garbage",
            "2026-11-18T05:22:09+02:00",
            "2026-11-18T05:22:09.Z",
            "2026-11-18T05:22:09.12aZ",
            "2026-11-18T05:22:60Z",
            "2026-11-18T24:00:00Z",
            "2026-02-31T05:22:09Z",
            "2026-11-18 05:22:09Z",
            "2026-11-18T5:22:09Z",
        ] {
            let t = log_time(bad);
            assert_eq!(t.iso, None, "{bad}");
            assert_eq!(t.short, bad);
        }
    }

    #[test]
    fn round_trips_known_dates() {
        assert_eq!(format_date(0), "1 Jan 1970");
        assert_eq!(format_date(951_782_400), "29 Feb 2000");
        assert_eq!(format_datetime(1_794_233_100), "9 Nov 2026, 14:05 UTC");
        assert_eq!(iso_date(1_794_225_900), "2026-11-09");
        assert_eq!(parse_iso_date("2026-11-09"), Some(1_794_182_400));
        assert_eq!(parse_iso_date("2000-02-29"), Some(951_782_400));
    }

    #[test]
    fn rejects_bad_dates() {
        for bad in [
            "",
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "1969-12-31",
            "abc",
            "2026-1",
        ] {
            assert_eq!(parse_iso_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn relative() {
        let now = 1_000_000;
        assert_eq!(relative_days(now + 3 * 86_400, now), "in 3 days");
        assert_eq!(relative_days(now + 3600, now), "today");
        assert_eq!(relative_days(now - 86_400, now), "1 day ago");
        assert_eq!(relative_days(now - 5 * 86_400, now), "5 days ago");
    }
}
