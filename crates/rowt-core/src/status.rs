//! rowt #s41: the escape lane's health as `rowt status` reports it — passively.
//!
//! The watchdog (each tick) and the follower (each round) write what they last
//! observed, `watch.last` and `follow.last`, one `key=value` line each, and
//! `status` reads those instead of probing the lane again. Only when no
//! observation is fresh does `status` probe on its own (Hong, #s42: "default
//! to be passive, but if there is no observed status, start a probe right
//! away"), and that answer is reported, never written: the files are the
//! watchdog's and the follower's.
//!
//! What lives here is pure: the record's format, how one observation follows
//! another (when "since" moves), the freshness rule, and the verdict — five
//! words, `ok` `degraded` `holding` `down` `unknown`, and a reason — which is
//! the same in the text block and in `status --json`. bin/rowt writes the
//! records with `printf` in the same key order ([`Obs::format`]) and reaches
//! the verdict through `rowt-rs _status`, so there is one copy of it.

/// One observation of the escape lane.
///
/// `delay_ms` is the probe's answer when it answered. The three stamps carry
/// history from one observation to the next: when the lane was last seen ok,
/// since when it has been ok, since when it has been failing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Obs {
    /// `YYYY-MM-DD HH:MM:SS`, UTC — `date -u '+%Y-%m-%d %H:%M:%S'`, the form
    /// the parity normaliser masks; never an epoch.
    pub observed_at: String,
    /// `watchdog` or `follower` (a probe `status` made itself is `status`, in
    /// memory only).
    pub source: String,
    /// What was probed: a server tag, `auto`, or `escape` (the selector).
    pub target: String,
    /// `ok` | `slow` (answered only the patient probe) | `fail` | `offline`
    /// (the NIC had no address: nothing was asked).
    pub result: String,
    pub delay_ms: Option<u32>,
    pub last_ok_at: String,
    pub ok_since: String,
    pub fail_since: String,
}

/// The keys, in the order they are written. bin/rowt's `_obs_write` prints
/// the same eight lines in this order.
pub const KEYS: [&str; 8] = ["observed_at", "source", "target", "result", "delay_ms", "last_ok_at", "ok_since", "fail_since"];

impl Obs {
    /// Read a record. `None` when it is not one (empty, truncated, a hand edit):
    /// an observation needs at least a stamp and a result.
    pub fn parse(text: &str) -> Option<Obs> {
        let mut o = Obs::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim();
            match k.trim() {
                "observed_at" => o.observed_at = v.to_string(),
                "source" => o.source = v.to_string(),
                "target" => o.target = v.to_string(),
                "result" => o.result = v.to_string(),
                "delay_ms" => o.delay_ms = v.parse().ok(),
                "last_ok_at" => o.last_ok_at = v.to_string(),
                "ok_since" => o.ok_since = v.to_string(),
                "fail_since" => o.fail_since = v.to_string(),
                _ => {}
            }
        }
        if o.observed_at.is_empty() || o.result.is_empty() {
            return None;
        }
        Some(o)
    }

    /// The record as written: eight `key=value` lines, an empty value for a
    /// field that does not apply, a trailing newline.
    pub fn format(&self) -> String {
        format!(
            "observed_at={}\nsource={}\ntarget={}\nresult={}\ndelay_ms={}\nlast_ok_at={}\nok_since={}\nfail_since={}\n",
            self.observed_at, self.source, self.target, self.result,
            self.delay_ms.map(|d| d.to_string()).unwrap_or_default(),
            self.last_ok_at, self.ok_since, self.fail_since
        )
    }

    /// The observation that follows `prev`, made `now`.
    ///
    /// An answer (`ok`, `slow`) moves `last_ok_at` to now and keeps `ok_since`
    /// from a previous answer, or starts it; `fail_since` clears. No answer
    /// (`fail`, `offline`) keeps `fail_since` from a previous failure, or
    /// starts it; `ok_since` clears and `last_ok_at` stays what it was.
    pub fn next(prev: Option<&Obs>, now: &str, source: &str, target: &str, result: &str, delay_ms: Option<u32>) -> Obs {
        let answered = matches!(result, "ok" | "slow");
        let prev_answered = prev.map(|p| matches!(p.result.as_str(), "ok" | "slow")).unwrap_or(false);
        let carry = |s: &str| if s.is_empty() { now.to_string() } else { s.to_string() };
        Obs {
            observed_at: now.to_string(),
            source: source.to_string(),
            target: target.to_string(),
            result: result.to_string(),
            delay_ms: if answered { delay_ms } else { None },
            last_ok_at: if answered { now.to_string() } else { prev.map(|p| p.last_ok_at.clone()).unwrap_or_default() },
            ok_since: if !answered { String::new() } else if prev_answered { carry(&prev.unwrap().ok_since) } else { now.to_string() },
            fail_since: if answered { String::new() } else if prev.is_some() && !prev_answered { carry(&prev.unwrap().fail_since) } else { now.to_string() },
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS` read as UTC, as seconds since the epoch (the
/// escape-dns stamp parser, which keys the same form). `None` for anything else.
pub fn stamp_epoch(s: &str) -> Option<i64> {
    crate::escapedns::parse_utc_stamp(s.trim()).map(|t| t as i64)
}

/// Seconds since the epoch as `YYYY-MM-DD HH:MM:SS`, UTC — the inverse of
/// [`stamp_epoch`]; nothing before 1970 is ever stamped here.
pub fn epoch_stamp(epoch: i64) -> String {
    crate::escapedns::utc_stamp(epoch.max(0) as u64)
}

/// A time as sing-box's clash API writes it into a delay history —
/// RFC 3339, fractional seconds or not, `Z` or a `±HH:MM` offset — as the
/// stamp form, UTC. `None` for anything else.
pub fn rfc3339_to_stamp(s: &str) -> Option<String> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let zpos = rest.find(['Z', '+', '-'])?;
    let (time, zone) = rest.split_at(zpos);
    let time = time.split('.').next()?;
    let local = stamp_epoch(&format!("{date} {time}"))?;
    let offset = match zone {
        "Z" | "z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let (hh, mm) = z.get(1..)?.split_once(':').unwrap_or((z.get(1..)?, "0"));
            sign * (hh.parse::<i64>().ok()? * 3600 + mm.parse::<i64>().ok()? * 60)
        }
    };
    (local - offset >= 0).then(|| epoch_stamp(local - offset))
}

/// Is an observation made at `observed_at` still current at `now`? One-sided
/// on purpose: a stamp in the future counts as fresh (a fixture's way to be
/// "just observed" whenever the gate runs; on a real box the next tick
/// overwrites the stamp within an interval), a stamp older than `window`
/// seconds does not, and a stamp that is not a stamp never is.
pub fn fresh(observed_at: &str, now: i64, window: i64) -> bool {
    stamp_epoch(observed_at).map(|t| now - t <= window).unwrap_or(false)
}

/// The later of two observations, by their stamps.
pub fn freshest<'a>(a: Option<&'a Obs>, b: Option<&'a Obs>) -> Option<&'a Obs> {
    match (a, b) {
        (Some(x), Some(y)) => {
            if stamp_epoch(&y.observed_at).unwrap_or(i64::MIN) > stamp_epoch(&x.observed_at).unwrap_or(i64::MIN) { Some(y) } else { Some(x) }
        }
        (x, None) => x,
        (None, y) => y,
    }
}

/// What the verdict is made from. `hold` is `watch.hold`'s (since, tag) when
/// it names the server still pinned; `obs` the observation being judged (the
/// freshest fresh one, or the probe `status` just made); `fails` the
/// watchdog's streak and `fails_limit` where it recovers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inputs<'a> {
    pub mode: &'a str,
    pub router_running: bool,
    pub captive: bool,
    pub hold: Option<(&'a str, &'a str)>,
    pub obs: Option<&'a Obs>,
    pub fails: u32,
    pub fails_limit: u32,
}

/// The verdict: one of [`STATES`], a reason from [`REASONS`] (none when ok),
/// and since when (a stamp, or empty when nothing recorded the start).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub state: &'static str,
    pub reason: Option<&'static str>,
    pub since: String,
}

/// The five words, in order of concern.
pub const STATES: [&str; 5] = ["ok", "degraded", "holding", "down", "unknown"];
/// Every reason the verdict can give. Documented with the schema; additive.
pub const REASONS: [&str; 10] = [
    "local-mode", "router-stopped", "captive-portal", "pinned-dead", "no-observation",
    "offline", "all-dead", "probe-failed", "probe-failing", "slow",
];

/// The verdict, in order of what settles it first: no lane in local mode; a
/// stopped router; a captive portal holding the proxy off; the watchdog's hold
/// on a dead pinned server; then the observation — none is `unknown` (the
/// caller probes before asking again; a probe that gets no answer is `down`,
/// so this word is reserved rather than produced), `offline` is down for want of a
/// network, a failure is down once the streak reached the limit (or when the
/// follower, which tries every server, found none, or when `status` probed
/// itself and got nothing) and degraded before that, a slow answer is
/// degraded, an answer is ok.
pub fn verdict(i: &Inputs) -> Verdict {
    let v = |state, reason, since: &str| Verdict { state, reason, since: since.to_string() };
    if i.mode == "local" {
        return v("unknown", Some("local-mode"), "");
    }
    if !i.router_running {
        return v("down", Some("router-stopped"), "");
    }
    if i.captive {
        return v("down", Some("captive-portal"), "");
    }
    if let Some((since, _tag)) = i.hold {
        return v("holding", Some("pinned-dead"), since);
    }
    let Some(o) = i.obs else {
        return v("unknown", Some("no-observation"), "");
    };
    match o.result.as_str() {
        "ok" => v("ok", None, &o.ok_since),
        "slow" => v("degraded", Some("slow"), &o.ok_since),
        "offline" => v("down", Some("offline"), &o.fail_since),
        "fail" => {
            if o.source == "follower" {
                v("down", Some("all-dead"), &o.fail_since)
            } else if o.source == "status" || i.fails >= i.fails_limit {
                v("down", Some("probe-failed"), &o.fail_since)
            } else {
                v("degraded", Some("probe-failing"), &o.fail_since)
            }
        }
        _ => v("unknown", Some("no-observation"), ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-10-30 07:00:00";
    const T1: &str = "2026-10-30 07:02:00";
    const T2: &str = "2026-10-30 07:04:00";

    #[test]
    fn stamps_are_utc_epochs() {
        assert_eq!(stamp_epoch("2000-01-01 00:00:00"), Some(946_684_800));
        assert_eq!(stamp_epoch("2024-03-01 00:00:00"), Some(1_709_251_200));
        assert_eq!(stamp_epoch("2026-10-30 07:20:11"), Some(1_793_344_811));
        assert_eq!(stamp_epoch("1793431211"), None);
        assert_eq!(stamp_epoch(""), None);
        assert_eq!(stamp_epoch("2026-13-01 00:00:00"), None);
    }

    #[test]
    fn stamps_round_trip_and_history_times_convert() {
        for s in ["2000-01-01 00:00:00", "2024-03-01 00:00:00", "2026-10-30 07:20:11", "1999-12-31 23:59:59"] {
            assert_eq!(epoch_stamp(stamp_epoch(s).unwrap()), s);
        }
        assert_eq!(rfc3339_to_stamp("2026-10-30T07:19:25.123456789Z").as_deref(), Some("2026-10-30 07:19:25"));
        assert_eq!(rfc3339_to_stamp("2026-10-30T15:19:25+08:00").as_deref(), Some("2026-10-30 07:19:25"));
        assert_eq!(rfc3339_to_stamp("2026-10-30T02:19:25.5-05:00").as_deref(), Some("2026-10-30 07:19:25"));
        assert_eq!(rfc3339_to_stamp("1970-01-01T00:00:00Z").as_deref(), Some("1970-01-01 00:00:00"));
        assert_eq!(rfc3339_to_stamp("1969-12-31T23:59:59Z"), None);
        assert_eq!(rfc3339_to_stamp("2026-10-30 07:19:25"), None);
        assert_eq!(rfc3339_to_stamp(""), None);
    }

    #[test]
    fn freshness_is_one_sided() {
        let now = stamp_epoch(T1).unwrap();
        assert!(fresh(T1, now, 360));
        assert!(fresh(T0, now, 360));                 // 120 s old
        assert!(!fresh("2026-10-30 06:00:00", now, 360));
        assert!(fresh("2100-01-01 00:00:00", now, 360)); // the fixture trick
        assert!(!fresh("", now, 360));
    }

    #[test]
    fn a_record_round_trips_and_keeps_its_key_order() {
        let o = Obs::next(None, T0, "watchdog", "alpha", "ok", Some(83));
        let text = o.format();
        let keys: Vec<&str> = text.lines().map(|l| l.split_once('=').unwrap().0).collect();
        assert_eq!(keys, KEYS.to_vec());
        assert_eq!(Obs::parse(&text), Some(o.clone()));
        assert_eq!(text, "observed_at=2026-10-30 07:00:00\nsource=watchdog\ntarget=alpha\nresult=ok\ndelay_ms=83\nlast_ok_at=2026-10-30 07:00:00\nok_since=2026-10-30 07:00:00\nfail_since=\n");
        assert_eq!(Obs::parse(""), None);
        assert_eq!(Obs::parse("source=watchdog\n"), None);
        assert_eq!(Obs::parse("observed_at=x\nresult=ok\ndelay_ms=abc\n").unwrap().delay_ms, None);
    }

    #[test]
    fn since_moves_only_when_the_answer_changes() {
        let a = Obs::next(None, T0, "watchdog", "alpha", "ok", Some(80));
        assert_eq!((a.ok_since.as_str(), a.fail_since.as_str(), a.last_ok_at.as_str()), (T0, "", T0));
        let b = Obs::next(Some(&a), T1, "watchdog", "alpha", "ok", Some(90));
        assert_eq!((b.ok_since.as_str(), b.last_ok_at.as_str()), (T0, T1));
        let c = Obs::next(Some(&b), T2, "watchdog", "alpha", "fail", None);
        assert_eq!((c.ok_since.as_str(), c.fail_since.as_str(), c.last_ok_at.as_str(), c.delay_ms), ("", T2, T1, None));
        let d = Obs::next(Some(&c), "2026-10-30 07:06:00", "watchdog", "alpha", "offline", None);
        assert_eq!((d.fail_since.as_str(), d.last_ok_at.as_str()), (T2, T1));
        let e = Obs::next(Some(&d), "2026-10-30 07:08:00", "watchdog", "alpha", "slow", Some(900));
        assert_eq!((e.ok_since.as_str(), e.fail_since.as_str(), e.last_ok_at.as_str()), ("2026-10-30 07:08:00", "", "2026-10-30 07:08:00"));
        // A failure recorded with no earlier failure start carries "now".
        let f = Obs::next(Some(&Obs { result: "fail".into(), ..Obs::default() }), T0, "follower", "alpha", "fail", None);
        assert_eq!(f.fail_since, T0);
    }

    #[test]
    fn freshest_picks_by_stamp() {
        let a = Obs::next(None, T0, "watchdog", "alpha", "ok", None);
        let b = Obs::next(None, T1, "follower", "alpha", "fail", None);
        assert_eq!(freshest(Some(&a), Some(&b)), Some(&b));
        assert_eq!(freshest(Some(&b), Some(&a)), Some(&b));
        assert_eq!(freshest(None, Some(&a)), Some(&a));
        assert_eq!(freshest(None, None), None);
    }

    fn inputs<'a>(obs: Option<&'a Obs>, fails: u32) -> Inputs<'a> {
        Inputs { mode: "host", router_running: true, captive: false, hold: None, obs, fails, fails_limit: 3 }
    }

    #[test]
    fn the_verdict_settles_in_order() {
        let ok = Obs::next(None, T0, "watchdog", "alpha", "ok", Some(80));
        assert_eq!(verdict(&Inputs { mode: "local", ..inputs(Some(&ok), 0) }), Verdict { state: "unknown", reason: Some("local-mode"), since: "".into() });
        assert_eq!(verdict(&Inputs { router_running: false, ..inputs(Some(&ok), 0) }).reason, Some("router-stopped"));
        assert_eq!(verdict(&Inputs { captive: true, ..inputs(Some(&ok), 0) }).reason, Some("captive-portal"));
        let h = verdict(&Inputs { hold: Some((T0, "alpha")), ..inputs(Some(&ok), 3) });
        assert_eq!((h.state, h.reason, h.since.as_str()), ("holding", Some("pinned-dead"), T0));
        assert_eq!(verdict(&inputs(None, 0)), Verdict { state: "unknown", reason: Some("no-observation"), since: "".into() });
        assert_eq!(verdict(&inputs(Some(&ok), 0)), Verdict { state: "ok", reason: None, since: T0.into() });
    }

    #[test]
    fn a_failure_is_degraded_until_the_streak_or_the_follower_says_down() {
        let ok = Obs::next(None, T0, "watchdog", "alpha", "ok", Some(80));
        let fail = Obs::next(Some(&ok), T1, "watchdog", "alpha", "fail", None);
        let d = verdict(&inputs(Some(&fail), 1));
        assert_eq!((d.state, d.reason, d.since.as_str()), ("degraded", Some("probe-failing"), T1));
        let d = verdict(&inputs(Some(&fail), 3));
        assert_eq!((d.state, d.reason), ("down", Some("probe-failed")));
        let all = Obs::next(Some(&ok), T1, "follower", "alpha", "fail", None);
        assert_eq!(verdict(&inputs(Some(&all), 0)).reason, Some("all-dead"));
        let mine = Obs::next(Some(&ok), T1, "status", "escape", "fail", None);
        assert_eq!(verdict(&inputs(Some(&mine), 0)).reason, Some("probe-failed"));
        let slow = Obs::next(Some(&ok), T1, "watchdog", "alpha", "slow", Some(2000));
        let s = verdict(&inputs(Some(&slow), 0));
        assert_eq!((s.state, s.reason, s.since.as_str()), ("degraded", Some("slow"), T0));
        let off = Obs::next(Some(&ok), T1, "watchdog", "alpha", "offline", None);
        assert_eq!(verdict(&inputs(Some(&off), 0)).reason, Some("offline"));
        assert!(REASONS.contains(&"offline") && STATES.contains(&"holding"));
    }
}
