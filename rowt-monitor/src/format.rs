//! Byte-rate formatters, tuned to reproduce the ground-truth renders exactly.

/// Header aggregate rate: `("2.9", "MB/s")`, `("144", "KB/s")`, `("5", "KB/s")`.
/// MB gets one decimal; KB/B are integer.
pub fn rate_parts(bytes_per_s: f64) -> (String, &'static str) {
    let b = bytes_per_s;
    if b >= 1_000_000.0 {
        (format!("{:.1}", b / 1_000_000.0), "MB/s")
    } else if b >= 1_000.0 {
        (format!("{:.0}", b / 1_000.0), "KB/s")
    } else {
        (format!("{:.0}", b), "B/s")
    }
}

/// Cumulative byte total for the metrics view, scaling all the way up (a year of
/// traffic reaches G/T): `1.2T`, `1.2G`, `48.6M`, `571K`, `0B`. One decimal from
/// M up; K/B integer. Kept separate from `compact` (which tops out at M for the
/// live per-connection column and must reproduce those exact strings).
pub fn bytes_total(bytes: f64) -> String {
    let b = bytes;
    if b >= 1_000_000_000_000.0 {
        format!("{:.1}T", b / 1_000_000_000_000.0)
    } else if b >= 1_000_000_000.0 {
        format!("{:.1}G", b / 1_000_000_000.0)
    } else if b >= 1_000_000.0 {
        format!("{:.1}M", b / 1_000_000.0)
    } else if b >= 1_000.0 {
        format!("{:.0}K", b / 1_000.0)
    } else {
        format!("{:.0}B", b)
    }
}

/// Compact per-connection byte figure for the table column: `8.0M`, `352.2M`,
/// `915K`, `104K`. M gets one decimal; K/B are integer. No `/s`, no arrow.
pub fn compact(bytes_per_s: f64) -> String {
    let b = bytes_per_s;
    if b >= 1_000_000.0 {
        format!("{:.1}M", b / 1_000_000.0)
    } else if b >= 1_000.0 {
        format!("{:.0}K", b / 1_000.0)
    } else {
        format!("{:.0}B", b)
    }
}

/// A tick age for the header: "50s", "14m", "3h". Coarse on purpose — it is a
/// liveness signal ("is the watchdog still completing ticks?"), not a clock.
pub fn age_short(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// A probe latency for the header and the strip: `42 ms` under a second, and
/// `7.2 s` from one second up — the figure the slow sample produces on a
/// high-latency link, kept short enough to sit beside a 15-character name in
/// the 96-column header.
pub fn latency(ms: u32) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", f64::from(ms) / 1000.0)
    }
}

#[cfg(test)]
mod latency_tests {
    use super::latency;

    #[test]
    fn under_a_second_stays_in_ms_and_a_second_or_more_reads_in_seconds() {
        assert_eq!(latency(42), "42 ms");
        assert_eq!(latency(999), "999 ms");
        assert_eq!(latency(1000), "1.0 s");
        assert_eq!(latency(7172), "7.2 s");
        assert_eq!(latency(12345), "12.3 s");
    }
}

#[cfg(test)]
mod age_tests {
    use super::age_short;

    #[test]
    fn it_rounds_down_to_the_unit_a_glance_needs() {
        assert_eq!(age_short(0), "0s");
        assert_eq!(age_short(59), "59s");
        assert_eq!(age_short(60), "1m");
        assert_eq!(age_short(14 * 60 + 59), "14m");
        assert_eq!(age_short(3600), "1h");
        assert_eq!(age_short(2 * 3600 + 3599), "2h");
    }
}
