//! Just enough date handling for Key Vault's Unix timestamps: show them as
//! dates and read dates typed into forms. All in UTC.

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
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
