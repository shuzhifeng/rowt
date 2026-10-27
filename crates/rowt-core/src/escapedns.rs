//! The escape servers' own names, resolved by rowt over DoH and checked before
//! sing-box may dial them.
//!
//! sing-box resolves an outbound's server name through one DNS server picked
//! by name (`domain_resolver`, else `route.default_domain_resolver`), and DNS
//! rules — the only place it can filter answers — never see that lookup (1.13:
//! `common/dialer/dialer.go`). So it cannot refuse a poisoned answer for a
//! server name, nor fall back to a second resolver. rowt does both itself:
//!
//! - It asks EVERY DoH source (JSON API, `?name=<n>&type=A`), by default AliDNS
//!   and DNSPod, and compares them: one provider repeating a hijack, or still
//!   handing out a retired address, must not be the only word.
//! - It refuses, by category, answers no public server has: private,
//!   loopback, link-local, CGNAT, the unspecified and reserved blocks,
//!   multicast, and 198.18.0.0/15, where fake-IP DNS hands out addresses. Plus
//!   any `refuse` range — a local, per-box override; nothing real is seeded.
//!   A name with an `allow` list takes exactly the answers inside it instead —
//!   the way to let through a server that really lives on a private address.
//! - Sources that agree are believed — unless their answer differs from the
//!   last good one. Sources that disagree are not: a hijack can answer with an
//!   ordinary public address no category catches. Either way the new
//!   addresses are put to the delay test THROUGH the server itself (a twin of
//!   its outbound per address, `sing-box tools fetch` of the health URL), and
//!   only an answer the server itself answers through is taken. Otherwise the
//!   last good addresses stay — an unverified answer never replaces them — and
//!   with none, the system resolver's when it is not refused, used but never
//!   trusted (see [`decide`]).
//!
//! The result goes to `escape-hosts`, a hosts file sing-box reads through a
//! `hosts` DNS server (`dns-escape`) that each guarded member names as its
//! `domain_resolver`. sing-box re-reads that file when it changes, so a refresh
//! by the watchdog follows a provider's new entry addresses with no restart.
//! `escape-dns.tsv` is rowt's record of each name's verdict, for `rowt status`.
//!
//! IPv4 only: members resolve with `ipv4_only`. A name with no A record is
//! never guarded and keeps today's resolver.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

/// The default DoH sources, both asked about every name: AliDNS and DNSPod.
pub const DEFAULT_DOH: [&str; 2] = ["https://223.5.5.5/resolve", "https://1.12.12.12/dns-query"];

/// Seconds a name's verdict stays fresh before a refresh asks again.
pub const MAX_AGE_SECS: u64 = 300;

/// Never a public server's address, whatever a resolver says.
const ALWAYS_REFUSED: [(&str, &str); 11] = [
    ("0.0.0.0/8", "unspecified"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "CGNAT"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "reserved"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "fake-IP range"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
];

/// `escape-dns.txt`, the user's knobs. Lines:
///
/// ```text
/// off                          resolve server names the old way (dns-direct)
/// doh <url> [<url>…]           the DoH sources, in order (replaces the default)
/// refuse <cidr> [<cidr>…]      more ranges never to use (known sinkholes)
/// allow <name> <cidr> […]      for <name>, use only answers inside these
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conf {
    pub off: bool,
    pub doh: Vec<String>,
    pub refuse: Vec<ipnet::Ipv4Net>,
    pub allow: BTreeMap<String, Vec<ipnet::Ipv4Net>>,
}

impl Conf {
    pub fn parse(text: &str) -> Conf {
        let mut c = Conf { off: false, doh: Vec::new(), refuse: Vec::new(), allow: BTreeMap::new() };
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let w: Vec<&str> = line.split_whitespace().collect();
            match w.first().copied() {
                Some("off") => c.off = true,
                Some("doh") => c.doh.extend(w[1..].iter().map(|s| s.to_string())),
                Some("refuse") => c.refuse.extend(w[1..].iter().filter_map(|s| net(s))),
                Some("allow") if w.len() >= 3 => c.allow.entry(w[1].to_ascii_lowercase()).or_default()
                    .extend(w[2..].iter().filter_map(|s| net(s))),
                _ => {}
            }
        }
        if c.doh.is_empty() {
            c.doh = DEFAULT_DOH.iter().map(|s| s.to_string()).collect();
        }
        c
    }
}

/// A CIDR, or a bare address as a /32.
fn net(s: &str) -> Option<ipnet::Ipv4Net> {
    s.parse::<ipnet::Ipv4Net>().ok()
        .or_else(|| s.parse::<Ipv4Addr>().ok().map(|a| ipnet::Ipv4Net::new(a, 32).unwrap()))
        .map(|n| n.trunc())
}

/// Why `addr` must not be used for `name`, or `None` when it may.
///
/// A `refuse` range always wins. A name with an `allow` list takes exactly the
/// answers inside it — so a server that really does live on a private or CGNAT
/// address can be allowed by name — and nothing outside. Every other name is
/// held to the never-public ranges.
pub fn refusal(addr: Ipv4Addr, name: &str, c: &Conf) -> Option<String> {
    if c.refuse.iter().any(|n| n.contains(&addr)) {
        return Some("sinkhole".into());
    }
    if let Some(ok) = c.allow.get(&name.to_ascii_lowercase()) {
        return if ok.iter().any(|n| n.contains(&addr)) { None } else { Some("outside the allow list".into()) };
    }
    for (cidr, why) in ALWAYS_REFUSED {
        if cidr.parse::<ipnet::Ipv4Net>().unwrap().contains(&addr) {
            return Some(why.to_string());
        }
    }
    None
}

/// Is `server` a name to resolve, rather than an address literal?
pub fn is_name(server: &str) -> bool {
    !server.is_empty() && server.parse::<std::net::IpAddr>().is_err()
        && server.chars().any(|c| c.is_ascii_alphabetic())
}

/// A server name as it is compared: one trailing dot off, ASCII lower case —
/// jq's `rtrimstr(".") | ascii_downcase`, which the shell's render uses.
pub fn canon(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase()
}

/// The names the escape members dial, sorted and unique, lower-cased.
pub fn names(servers: &[Value]) -> Vec<String> {
    let set: BTreeSet<String> = servers.iter()
        .filter_map(|s| s.get("server").and_then(Value::as_str))
        .filter(|s| is_name(s))
        .map(|s| canon(s))
        .collect();
    set.into_iter().collect()
}

/// The A records in a DoH JSON answer (`Status` 0, `Answer[].type` 1), in
/// order. `None` when the body is not such an answer at all.
pub fn parse_answer(body: &str) -> Option<Vec<Ipv4Addr>> {
    let v: Value = serde_json::from_str(body).ok()?;
    if v.get("Status").and_then(Value::as_u64) != Some(0) {
        return None;
    }
    Some(v.get("Answer").and_then(Value::as_array).map(|a| a.iter()
        .filter(|r| r.get("type").and_then(Value::as_u64) == Some(1))
        .filter_map(|r| r.get("data").and_then(Value::as_str)?.parse().ok())
        .collect()).unwrap_or_default())
}

/// The host a DoH URL names, for messages: `https://223.5.5.5/resolve` → `223.5.5.5`.
pub fn source_label(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?']).next().unwrap_or(rest).to_string()
}

/// One name's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every source with a usable answer agrees — one source, or the
    /// addresses all of them gave.
    Ok,
    /// The sources disagreed, and exactly one source's addresses answered the
    /// probe through the server itself: those are used.
    Probed,
    /// The sources disagreed and the probe could not settle it: the last good
    /// addresses stay; with none, the system resolver's when it is not
    /// refused; with neither, no address at all.
    Disputed,
    /// The sources agree on an answer (or only one answered) that differs from
    /// the verified last good one, and the new addresses answered the probe
    /// through the server: the entry has moved, and they are used.
    Moved,
    /// The same, but the new addresses did not pass the probe (or it could not
    /// run): the last good addresses stay.
    Held,
    /// Sources answered, and every address was refused.
    Refused,
    /// No source answered.
    Unanswered,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Probed => "probed",
            Verdict::Disputed => "disputed",
            Verdict::Moved => "moved",
            Verdict::Held => "held",
            Verdict::Refused => "refused",
            Verdict::Unanswered => "unanswered",
        }
    }
    fn parse(s: &str) -> Option<Verdict> {
        match s {
            "ok" => Some(Verdict::Ok),
            "probed" => Some(Verdict::Probed),
            "disputed" => Some(Verdict::Disputed),
            "moved" => Some(Verdict::Moved),
            "held" => Some(Verdict::Held),
            "refused" => Some(Verdict::Refused),
            "unanswered" => Some(Verdict::Unanswered),
            _ => None,
        }
    }
}

/// Where a disputed name's addresses came from when no source's word was taken.
pub const FROM_LAST_GOOD: &str = "last good";
pub const FROM_SYSTEM: &str = "system resolver";

/// One row of `escape-dns.tsv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub verdict: Verdict,
    /// What sing-box is given: this answer's, or the last good one.
    pub addrs: Vec<Ipv4Addr>,
    /// Where the addresses came from: a source, `a+b` when they agreed, or
    /// [`FROM_LAST_GOOD`] / [`FROM_SYSTEM`] (empty for none).
    pub source: String,
    /// `addr=reason@source`, every refusal this refresh saw.
    pub refused: Vec<String>,
    /// `addr@source`: every address of a disagreement (probed, disputed), or
    /// the new addresses an answer brought (moved, held).
    pub disputed: Vec<String>,
    /// UTC `YYYY-MM-DD HH:MM:SS` of this verdict.
    pub when: String,
}

pub const TSV_HEADER: &str = "# rowt escape-server names, resolved by DoH: name, verdict, addresses given to sing-box, source, refused (addr=reason@source), disputed (addr@source), UTC time";
pub const HOSTS_HEADER: &str = "# rowt escape-server addresses (escape-dns.tsv says why) — written by rowt, read live by sing-box's dns-escape";

pub fn parse_tsv(text: &str) -> Vec<Row> {
    text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() != 7 {
            return None;
        }
        let list = |s: &str| -> Vec<String> {
            if s == "-" || s.is_empty() { Vec::new() } else { s.split(',').map(|x| x.to_string()).collect() }
        };
        Some(Row {
            name: f[0].to_string(),
            verdict: Verdict::parse(f[1])?,
            addrs: list(f[2]).iter().filter_map(|a| a.parse().ok()).collect(),
            source: if f[3] == "-" { String::new() } else { f[3].to_string() },
            refused: list(f[4]),
            disputed: list(f[5]),
            when: f[6].to_string(),
        })
    }).collect()
}

pub fn render_tsv(rows: &[Row]) -> String {
    let mut o = format!("{TSV_HEADER}\n");
    let dash = |v: String| if v.is_empty() { "-".to_string() } else { v };
    for r in rows {
        o.push_str(&format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\n", r.name, r.verdict.as_str(),
            dash(r.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",")),
            dash(r.source.clone()), dash(r.refused.join(",")), dash(r.disputed.join(",")), r.when));
    }
    o
}

pub fn render_hosts(rows: &[Row]) -> String {
    let mut o = format!("{HOSTS_HEADER}\n");
    for r in rows {
        for a in &r.addrs {
            o.push_str(&format!("{a} {}\n", r.name));
        }
    }
    o
}

/// What one source said about one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// An answer, possibly with no A records.
    Answer(Vec<Ipv4Addr>),
    /// No usable reply: unreachable, an HTTP error, not a DoH JSON answer.
    Nothing,
}

/// Decide one name from what EVERY source said (in source order), given its
/// previous row. A refused address is no answer; a source that gave only
/// refused addresses, or none, has no say.
///
/// The LAST GOOD answer is the previous row's addresses when they were
/// verified — a DoH answer taken, a probe passed, or one of those kept — and
/// never the system resolver's tie-break, which is only ever used, not trusted.
///
/// - No source with a say: what sing-box was last given stays.
/// - One source, or several that share addresses: those (the shared ones) —
///   as they are when there is no last good answer, or when every one of them
///   is in it. An answer with an address the last good one lacks must first
///   pass the probe through the server: the entry has moved, and it is used;
///   otherwise the last good answer is held. Whoever gave it: one source left
///   alone by a network that blocks the other, or both behind a network that
///   intercepts TLS, is not taken on its word. One probe per real move.
/// - Several with nothing in common — the shape of a hijack one resolver
///   repeats and another does not: no one source's word is taken. `probe` is
///   asked which of the candidates answer the delay test through the server
///   itself (`None`: it cannot be run). When the addresses that pass all come
///   from ONE source, they are used. Otherwise the last good addresses stay;
///   with none, `system` (the system resolver's answer) when it is not refused;
///   with neither, nothing — the server is not used rather than dial a guess.
pub fn decide(name: &str, c: &Conf, prev: Option<&Row>, when: &str, replies: &[(String, Reply)],
              probe: impl FnOnce(&[Ipv4Addr]) -> Option<Vec<Ipv4Addr>>,
              system: impl FnOnce() -> Option<Vec<Ipv4Addr>>) -> Row {
    let mut refused = Vec::new();
    let mut said: Vec<(String, Vec<Ipv4Addr>)> = Vec::new();
    for (label, reply) in replies {
        let Reply::Answer(addrs) = reply else { continue };
        let mut good: Vec<Ipv4Addr> = Vec::new();
        for a in addrs {
            match refusal(*a, name, c) {
                Some(why) => refused.push(format!("{a}={why}@{label}")),
                None if !good.contains(a) => good.push(*a),
                None => {}
            }
        }
        if !good.is_empty() {
            said.push((label.clone(), good));
        }
    }
    let row = |verdict, addrs: Vec<Ipv4Addr>, source: String, refused: Vec<String>, disputed: Vec<String>| Row {
        name: name.into(), verdict, addrs, source, refused, disputed, when: when.into(),
    };
    // What sing-box was last given, whatever it was; and the part of it that
    // is TRUSTED — anything but the system resolver's tie-break.
    let carried = prev.filter(|p| !p.addrs.is_empty()).map(|p| (p.addrs.clone(), p.source.clone()));
    let last: Option<Vec<Ipv4Addr>> = prev.filter(|p| !p.addrs.is_empty() && p.source != FROM_SYSTEM)
        .map(|p| p.addrs.clone());
    if said.is_empty() {
        // An empty answer (NOERROR, no A record) counts as no answer.
        let (addrs, source) = carried.unwrap_or_default();
        let verdict = if refused.is_empty() { Verdict::Unanswered } else { Verdict::Refused };
        return row(verdict, addrs, source, refused, Vec::new());
    }
    // One answer every source with a say gives.
    let agreed: Option<(String, Vec<Ipv4Addr>)> = if said.len() == 1 {
        Some(said[0].clone())
    } else {
        let common: Vec<Ipv4Addr> = said[0].1.iter().copied()
            .filter(|a| said[1..].iter().all(|(_, o)| o.contains(a))).collect();
        (!common.is_empty()).then(|| (said.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>().join("+"), common))
    };
    if let Some((label, addrs)) = agreed {
        let Some(last) = last else {
            return row(Verdict::Ok, addrs, label, refused, Vec::new());
        };
        let new: Vec<Ipv4Addr> = addrs.iter().copied().filter(|a| !last.contains(a)).collect();
        if new.is_empty() {
            return row(Verdict::Ok, addrs, label, refused, Vec::new());
        }
        // It differs from the last good answer: the server itself must vouch.
        let changed: Vec<String> = new.iter().map(|a| format!("{a}@{label}")).collect();
        let passed = probe(&new).unwrap_or_default();
        if new.iter().any(|a| passed.contains(a)) {
            let ok: Vec<Ipv4Addr> = addrs.iter().copied()
                .filter(|a| last.contains(a) || passed.contains(a)).collect();
            return row(Verdict::Moved, ok, label, refused, changed);
        }
        return row(Verdict::Held, last, FROM_LAST_GOOD.into(), refused, changed);
    }
    // They disagree.
    let disputed: Vec<String> = said.iter()
        .flat_map(|(l, addrs)| addrs.iter().map(move |a| format!("{a}@{l}"))).collect();
    let mut candidates: Vec<Ipv4Addr> = Vec::new();
    for (_, addrs) in &said {
        for a in addrs {
            if !candidates.contains(a) {
                candidates.push(*a);
            }
        }
    }
    if let Some(passed) = probe(&candidates) {
        let winners: Vec<&(String, Vec<Ipv4Addr>)> =
            said.iter().filter(|(_, addrs)| addrs.iter().any(|a| passed.contains(a))).collect();
        if winners.len() == 1 {
            let (label, addrs) = winners[0];
            let ok: Vec<Ipv4Addr> = addrs.iter().copied().filter(|a| passed.contains(a)).collect();
            return row(Verdict::Probed, ok, label.clone(), refused, disputed);
        }
    }
    if let Some(addrs) = last {
        return row(Verdict::Disputed, addrs, FROM_LAST_GOOD.into(), refused, disputed);
    }
    let sys: Vec<Ipv4Addr> = system().unwrap_or_default().into_iter()
        .filter(|a| refusal(*a, name, c).is_none()).collect();
    let source = if sys.is_empty() { String::new() } else { FROM_SYSTEM.into() };
    row(Verdict::Disputed, sys, source, refused, disputed)
}

/// The names whose members dial through `dns-escape`: rowt has an opinion —
/// usable addresses, or answers it refused (the member then fails closed
/// instead of asking a resolver that gave the same poisoned answer). A name
/// with no answer and nothing kept stays on dns-direct.
pub fn guarded(tsv: &str, conf: &str) -> BTreeSet<String> {
    if Conf::parse(conf).off {
        return BTreeSet::new();
    }
    parse_tsv(tsv).into_iter()
        .filter(|r| r.verdict != Verdict::Unanswered || !r.addrs.is_empty())
        .map(|r| r.name)
        .collect()
}

/// The `domain_resolver` a guarded member gets.
pub fn resolver() -> Value {
    json!({"server": "dns-escape", "strategy": "ipv4_only", "disable_cache": true})
}

/// Give each member whose server is a guarded name the `dns-escape` resolver.
/// The urltest and selector (no `server`) pass through.
pub fn guard_members(escapes: &Value, names: &BTreeSet<String>) -> Value {
    let Some(arr) = escapes.as_array() else { return escapes.clone() };
    Value::Array(arr.iter().map(|m| {
        let hit = m.get("server").and_then(Value::as_str)
            .map(|s| names.contains(&canon(s)))
            .unwrap_or(false);
        let mut m = m.clone();
        if hit {
            if let Some(o) = m.as_object_mut() {
                o.insert("domain_resolver".into(), resolver());
            }
        }
        m
    }).collect())
}

/// A copy of `member` that dials `addr` instead of its name — what the delay
/// probe of a disputed name tests. Everything that would have followed the
/// NAME keeps it: the TLS server name, and the Host a ws, http or httpupgrade
/// transport sends. Interface-bound like the router's members (`iface`), and
/// without a `detour` it could not resolve outside the router.
pub fn twin(member: &Value, addr: Ipv4Addr, tag: &str, iface: &str) -> Value {
    let name = member.get("server").and_then(Value::as_str).unwrap_or("");
    let name = name.strip_suffix('.').unwrap_or(name).to_string();
    let mut t = member.clone();
    let Some(o) = t.as_object_mut() else { return t };
    o.insert("tag".into(), json!(tag));
    o.insert("server".into(), json!(addr.to_string()));
    o.remove("detour");
    o.remove("domain_resolver");
    if !iface.is_empty() {
        o.insert("bind_interface".into(), json!(iface));
    }
    if let Some(tls) = o.get_mut("tls").and_then(Value::as_object_mut) {
        let on = tls.get("enabled").and_then(Value::as_bool).unwrap_or(false);
        let named = tls.get("server_name").and_then(Value::as_str).map(|v| !v.is_empty()).unwrap_or(false);
        if on && !named {
            tls.insert("server_name".into(), json!(name));
        }
    }
    if let Some(tr) = o.get_mut("transport").and_then(Value::as_object_mut) {
        match tr.get("type").and_then(Value::as_str) {
            Some("ws") => {
                let headers = tr.entry("headers").or_insert_with(|| json!({}));
                if let Some(h) = headers.as_object_mut() {
                    if !h.keys().any(|k| k.eq_ignore_ascii_case("host")) {
                        h.insert("Host".into(), json!(name));
                    }
                }
            }
            Some("http") => {
                let empty = tr.get("host").map(|h| h.as_array().map(|a| a.is_empty()).unwrap_or(false)
                                                || h.as_str().map(|s| s.is_empty()).unwrap_or(false)).unwrap_or(true);
                if empty {
                    tr.insert("host".into(), json!([name]));
                }
            }
            Some("httpupgrade") => {
                if tr.get("host").and_then(Value::as_str).map(|s| s.is_empty()).unwrap_or(true) {
                    tr.insert("host".into(), json!(name));
                }
            }
            _ => {}
        }
    }
    t
}

/// The config `sing-box tools fetch` runs the probe from: one twin per
/// candidate, tagged `probe-<n>`, and nothing else.
pub fn probe_config(member: &Value, candidates: &[Ipv4Addr], iface: &str) -> Value {
    json!({
        "log": {"level": "panic"},
        "outbounds": candidates.iter().enumerate()
            .map(|(i, a)| twin(member, *a, &format!("probe-{i}"), iface)).collect::<Vec<_>>(),
    })
}

/// The first member that dials `name` (in servers.json order), to probe it by.
pub fn member_for<'a>(servers: &'a [Value], name: &str) -> Option<&'a Value> {
    servers.iter().find(|s| s.get("server").and_then(Value::as_str).map(canon).as_deref() == Some(name))
}

/// Does any member name `dns-escape`? Then the render adds the hosts server.
pub fn uses_guard(escapes: &Value) -> bool {
    escapes.as_array().map(|a| a.iter().any(|m| {
        m.get("domain_resolver").and_then(|d| d.get("server")).and_then(Value::as_str) == Some("dns-escape")
    })).unwrap_or(false)
}

/// The hosts DNS server the guarded members resolve through.
pub fn hosts_server(path: &str) -> Value {
    json!({"type": "hosts", "tag": "dns-escape", "path": [path]})
}

/// `YYYY-MM-DD HH:MM:SS` for a Unix time, in UTC.
pub fn utc_stamp(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let secs = epoch % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// The inverse of [`utc_stamp`]; `None` for anything else.
pub fn parse_utc_stamp(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b' ' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // days_from_civil.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

fn join_addrs(a: &[Ipv4Addr]) -> String {
    a.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")
}

/// `203.0.113.66 (sinkhole, from A), …` — a row's refusals in words.
fn refused_words(r: &Row) -> String {
    r.refused.iter().map(|x| {
        let (a, rest) = x.split_once('=').unwrap_or((x, ""));
        let (why, from) = rest.split_once('@').unwrap_or((rest, ""));
        format!("{a} ({why}, from {from})")
    }).collect::<Vec<_>>().join(", ")
}

/// `203.0.113.66 from A; 198.51.100.7 from B` — what each source said, when
/// they disagreed.
fn disputed_words(r: &Row) -> String {
    let mut by: Vec<(String, Vec<String>)> = Vec::new();
    for x in &r.disputed {
        let (a, from) = x.split_once('@').unwrap_or((x, ""));
        match by.iter_mut().find(|(f, _)| f == from) {
            Some((_, v)) => v.push(a.to_string()),
            None => by.push((from.to_string(), vec![a.to_string()])),
        }
    }
    by.iter().map(|(f, v)| format!("{} from {f}", v.join(", "))).collect::<Vec<_>>().join("; ")
}

/// What a moved or held answer brought: `198.51.100.7 from B`.
fn changed_words(r: &Row) -> String {
    disputed_words(r)
}

/// How a disagreement ended, in the words `status` and the refresh both use.
fn settled_words(r: &Row) -> String {
    let given = join_addrs(&r.addrs);
    match (&r.verdict, r.source.as_str()) {
        (Verdict::Probed, from) => format!("{given} (from {from}) answered the probe through the server, so it is used"),
        (_, FROM_LAST_GOOD) => format!("the probe did not settle it, so {given}, the last good answer, stays"),
        (_, FROM_SYSTEM) => format!("the probe did not settle it and there is no last good answer, so {given} from the system resolver is used"),
        _ => "the probe did not settle it and nothing else can be trusted, so this server is not used".into(),
    }
}

/// What a refresh says on stderr about one name — every refusal, and a
/// disagreement with how it ended. Nothing for a clean answer.
pub fn warnings(r: &Row) -> Vec<String> {
    let n = &r.name;
    let mut o: Vec<String> = r.refused.iter().map(|x| {
        let (a, rest) = x.split_once('=').unwrap_or((x, ""));
        let (why, from) = rest.split_once('@').unwrap_or((rest, ""));
        format!("escape server {n}: refused {a} ({why}) from {from}")
    }).collect();
    match r.verdict {
        Verdict::Moved => o.push(format!(
            "escape server {n}: moved — {} answered the probe through the server, so it replaces the last good answer",
            changed_words(r))),
        Verdict::Held => o.push(format!(
            "escape server {n}: DoH now answers {}, not the last good answer, and it did not pass the probe through the server — {} stays",
            changed_words(r), join_addrs(&r.addrs))),
        _ if !r.disputed.is_empty() => o.push(format!(
            "escape server {n}: DoH sources disagree ({}) — {}", disputed_words(r), settled_words(r))),
        _ => {}
    }
    o
}

/// The `escape dns:` lines of `rowt status`, from the config's files. Empty
/// when there is nothing to say (no server is a name).
pub fn status_lines(servers: &[Value], tsv: &str, conf: &str) -> Vec<String> {
    let names = names(servers);
    if names.is_empty() {
        return Vec::new();
    }
    let c = Conf::parse(conf);
    if c.off {
        return vec!["escape dns:   off (escape-dns.txt) — server names resolve through dns-direct, unchecked".into()];
    }
    let rows: BTreeMap<String, Row> = parse_tsv(tsv).into_iter().map(|r| (r.name.clone(), r)).collect();
    let sources = c.doh.iter().map(|u| source_label(u)).collect::<Vec<_>>().join(" and ");
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut detail = Vec::new();
    let mut newest: Option<u64> = None;
    for n in &names {
        let Some(r) = rows.get(n) else {
            *counts.entry("not checked yet").or_default() += 1;
            detail.push(format!("  {n}: not checked yet — resolved through dns-direct until it is"));
            continue;
        };
        if let Some(t) = parse_utc_stamp(&r.when) {
            newest = Some(newest.map_or(t, |x| x.max(t)));
        }
        let given = join_addrs(&r.addrs);
        let refused = refused_words(r);
        let also = if refused.is_empty() { String::new() } else { format!("; REFUSED {refused}") };
        match r.verdict {
            Verdict::Ok => {
                *counts.entry("ok").or_default() += 1;
                if !refused.is_empty() {
                    detail.push(format!("  {n}: REFUSED {refused}; using {given} from {}", r.source));
                }
            }
            Verdict::Probed | Verdict::Disputed => {
                *counts.entry(r.verdict.as_str()).or_default() += 1;
                detail.push(format!("  {n}: DoH sources DISAGREE ({}) — {}{also}", disputed_words(r), settled_words(r)));
            }
            Verdict::Moved => {
                *counts.entry("moved").or_default() += 1;
                detail.push(format!("  {n}: MOVED — {} answered the probe through the server; using {given}{also}",
                                    changed_words(r)));
            }
            Verdict::Held => {
                *counts.entry("held").or_default() += 1;
                detail.push(format!("  {n}: DoH now answers {}, which did NOT pass the probe through the server — \
                                     still using {given}, the last good answer{also}", changed_words(r)));
            }
            Verdict::Refused => {
                *counts.entry("refused").or_default() += 1;
                detail.push(if given.is_empty() {
                    format!("  {n}: REFUSED {refused} — no good address, so this server is not used")
                } else {
                    format!("  {n}: REFUSED {refused} — still using {given}, the last good answer")
                });
            }
            Verdict::Unanswered => {
                *counts.entry("unanswered").or_default() += 1;
                detail.push(if given.is_empty() {
                    format!("  {n}: no DoH answer — resolved through dns-direct until one arrives")
                } else {
                    format!("  {n}: no DoH answer — still using {given}, the last good answer")
                });
            }
        }
    }
    let tally = ["ok", "moved", "held", "probed", "disputed", "refused", "unanswered", "not checked yet"].iter()
        .filter_map(|k| counts.get(k).map(|v| format!("{v} {k}")))
        .collect::<Vec<_>>().join(", ");
    let age = newest.map(|t| format!(", last checked {} UTC", utc_stamp(t))).unwrap_or_default();
    let mut out = vec![format!("escape dns:   {} server name(s), each asked of {sources}: {tally}{age}", names.len())];
    out.extend(detail);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Ipv4Addr { s.parse().unwrap() }

    #[test]
    fn the_never_public_ranges_are_refused_and_documentation_space_is_not() {
        let c = Conf::parse("");
        for (ip, why) in [("10.1.2.3", "private"), ("172.31.0.1", "private"), ("192.168.1.1", "private"),
                          ("127.0.0.1", "loopback"), ("169.254.9.9", "link-local"), ("100.64.0.1", "CGNAT"),
                          ("0.0.0.0", "unspecified"), ("198.18.0.7", "fake-IP range"), ("224.0.0.1", "multicast"),
                          ("255.255.255.255", "reserved")] {
            assert_eq!(refusal(a(ip), "entry.example", &c).as_deref(), Some(why), "{ip}");
        }
        for ip in ["192.0.2.10", "198.51.100.7", "203.0.113.5", "100.128.0.1", "172.32.0.1"] {
            assert_eq!(refusal(a(ip), "entry.example", &c), None, "{ip}");
        }
    }

    #[test]
    fn the_config_adds_sinkholes_allow_lists_and_sources() {
        let c = Conf::parse("# comment\nrefuse 192.0.2.0/24 198.51.100.9\nallow Entry.Example 203.0.113.0/24\ndoh http://127.0.0.1:1/q\nnonsense line\n");
        assert_eq!(c.doh, ["http://127.0.0.1:1/q"]);
        assert!(!c.off);
        assert_eq!(refusal(a("192.0.2.77"), "x.example", &c).as_deref(), Some("sinkhole"));
        assert_eq!(refusal(a("198.51.100.9"), "x.example", &c).as_deref(), Some("sinkhole"));
        assert_eq!(refusal(a("198.51.100.10"), "x.example", &c), None);
        // The allow list binds only its own name, case-insensitively.
        assert_eq!(refusal(a("198.51.100.10"), "entry.example", &c).as_deref(), Some("outside the allow list"));
        assert_eq!(refusal(a("203.0.113.9"), "ENTRY.example", &c), None);
        // An allow list is how a server that lives on a private or tailnet
        // address behind a name is let through — but never past a `refuse`.
        let t = Conf::parse("allow home.example 100.64.0.0/10 192.0.2.0/24\nrefuse 192.0.2.66\n");
        assert_eq!(refusal(a("100.100.1.2"), "home.example", &t), None);
        assert_eq!(refusal(a("100.100.1.2"), "other.example", &t).as_deref(), Some("CGNAT"));
        assert_eq!(refusal(a("10.0.0.1"), "home.example", &t).as_deref(), Some("outside the allow list"));
        assert_eq!(refusal(a("192.0.2.66"), "home.example", &t).as_deref(), Some("sinkhole"));
        assert!(Conf::parse("off\n").off);
        assert_eq!(Conf::parse("").doh, DEFAULT_DOH);
    }

    #[test]
    fn a_doh_json_answer_yields_its_a_records() {
        let body = r#"{"Status":0,"Answer":[{"name":"e.example.","type":5,"data":"f.example."},
                       {"name":"f.example.","type":1,"TTL":60,"data":"192.0.2.1"},
                       {"name":"f.example.","type":1,"data":"192.0.2.2"}]}"#;
        assert_eq!(parse_answer(body), Some(vec![a("192.0.2.1"), a("192.0.2.2")]));
        assert_eq!(parse_answer(r#"{"Status":3}"#), None);
        assert_eq!(parse_answer(r#"{"Status":0}"#), Some(vec![]));
        assert_eq!(parse_answer("<html>"), None);
        assert_eq!(source_label("https://1.12.12.12/dns-query"), "1.12.12.12");
    }

    const A: &str = "223.5.5.5";
    const B: &str = "1.12.12.12";

    fn says(a_: Reply, b_: Reply) -> Vec<(String, Reply)> {
        vec![(A.into(), a_), (B.into(), b_)]
    }
    fn ans(xs: &[&str]) -> Reply {
        Reply::Answer(xs.iter().map(|x| a(x)).collect())
    }
    fn good(addrs: &[&str]) -> Row {
        Row { name: "entry.example".into(), verdict: Verdict::Ok, addrs: addrs.iter().map(|x| a(x)).collect(),
              source: A.into(), refused: vec![], disputed: vec![], when: "x".into() }
    }
    /// A probe that must not be reached.
    fn no_probe(_: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>> {
        panic!("probed although the sources did not disagree")
    }
    fn no_system() -> Option<Vec<Ipv4Addr>> {
        panic!("asked the system resolver")
    }

    // The incident's shape, in documentation ranges: one resolver repeats the
    // hijack (A: 203.0.113.66, a public address no category refuses), the
    // other gives the real entry (B: 198.51.100.7).

    /// Both candidates may accept a connection; only B's passes the delay
    /// test through the server. B is used — on a fresh box too, with no last
    /// good answer to fall back on.
    #[test]
    fn a_disagreement_is_settled_by_the_probe_even_on_a_fresh_box() {
        let c = Conf::parse("");
        let mut probed = Vec::new();
        let r = decide("entry.example", &c, None, "t", &says(ans(&["203.0.113.66"]), ans(&["198.51.100.7"])),
                       |cands| { probed = cands.to_vec(); Some(vec![a("198.51.100.7")]) }, no_system);
        assert_eq!(probed, [a("203.0.113.66"), a("198.51.100.7")]);
        assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()),
                   (Verdict::Probed, vec![a("198.51.100.7")], B));
        assert_eq!(r.disputed, ["203.0.113.66@223.5.5.5", "198.51.100.7@1.12.12.12"]);
        // …and with a last good answer, B still replaces it: the server itself vouched.
        let prev = good(&["192.0.2.10"]);
        let r = decide("entry.example", &c, Some(&prev), "t", &says(ans(&["203.0.113.66"]), ans(&["198.51.100.7"])),
                       |_| Some(vec![a("198.51.100.7")]), no_system);
        assert_eq!(r.addrs, [a("198.51.100.7")]);
    }

    /// Neither passes, or both do, or the probe cannot run: the last good
    /// answer stays. A one-source answer never replaces it unverified.
    #[test]
    fn an_unsettled_disagreement_keeps_the_last_good_answer() {
        let c = Conf::parse("");
        let prev = good(&["192.0.2.10"]);
        let both = says(ans(&["203.0.113.66"]), ans(&["198.51.100.7"]));
        for probe in [Some(vec![]), Some(vec![a("203.0.113.66"), a("198.51.100.7")]), None] {
            let r = decide("entry.example", &c, Some(&prev), "t", &both, |_| probe.clone(), no_system);
            assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()),
                       (Verdict::Disputed, vec![a("192.0.2.10")], FROM_LAST_GOOD), "{probe:?}");
        }
    }

    /// No last good answer either: the system resolver's, unless refused —
    /// and with nothing trustworthy at all, no address (the server fails
    /// closed instead of dialing a guess).
    #[test]
    fn with_no_last_good_answer_the_system_resolver_breaks_the_tie_unless_refused() {
        let c = Conf::parse("");
        let both = says(ans(&["203.0.113.66"]), ans(&["198.51.100.7"]));
        let r = decide("entry.example", &c, None, "t", &both, |_| None, || Some(vec![a("203.0.113.66")]));
        assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()),
                   (Verdict::Disputed, vec![a("203.0.113.66")], FROM_SYSTEM));
        let r = decide("entry.example", &c, None, "t", &both, |_| Some(vec![]), || Some(vec![a("10.1.2.3")]));
        assert_eq!((r.verdict.clone(), r.addrs.len(), r.source.as_str()), (Verdict::Disputed, 0, ""));
        let r = decide("entry.example", &c, None, "t", &both, |_| None, || None);
        assert_eq!((r.verdict.clone(), r.addrs.len()), (Verdict::Disputed, 0));
        // Disputed with nothing is still guarded: the member gets no address.
        assert!(guarded(&render_tsv(&[r]), "").contains("entry.example"));
    }

    /// They agree with each other and with the last good answer, or there is
    /// no last good answer: used directly, no probe. They overlap: the
    /// addresses every source gave.
    #[test]
    fn agreement_is_used_directly() {
        let c = Conf::parse("");
        let r = decide("entry.example", &c, Some(&good(&["198.51.100.7"])), "t",
                       &says(ans(&["198.51.100.7"]), ans(&["198.51.100.7"])), no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()),
                   (Verdict::Ok, vec![a("198.51.100.7")], "223.5.5.5+1.12.12.12"));
        let r = decide("entry.example", &c, None, "t",
                       &says(ans(&["198.51.100.7"]), ans(&["198.51.100.7"])), no_probe, no_system);
        assert_eq!(r.verdict, Verdict::Ok);
        let r = decide("entry.example", &c, None, "t",
                       &says(ans(&["198.51.100.7", "198.51.100.8"]), ans(&["198.51.100.9", "198.51.100.7"])),
                       no_probe, no_system);
        assert_eq!(r.addrs, [a("198.51.100.7")]);
        // A subset of the last good answer brings nothing new: no probe.
        let r = decide("entry.example", &c, Some(&good(&["198.51.100.7", "198.51.100.8"])), "t",
                       &says(ans(&["198.51.100.8"]), Reply::Nothing), no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Ok, vec![a("198.51.100.8")]));
    }

    /// Both sources agree on an answer that differs from the verified last good
    /// one — a network that intercepts TLS sees both DoH streams. It must pass
    /// the probe through the server before it replaces the last good answer.
    #[test]
    fn an_agreed_answer_that_differs_from_last_good_is_probed_first() {
        let c = Conf::parse("");
        let both = says(ans(&["203.0.113.66"]), ans(&["203.0.113.66"]));
        let mut probed = Vec::new();
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t", &both,
                       |cands| { probed = cands.to_vec(); Some(vec![]) }, no_system);
        assert_eq!(probed, [a("203.0.113.66")]);
        assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()),
                   (Verdict::Held, vec![a("192.0.2.10")], FROM_LAST_GOOD));
        assert_eq!(r.disputed, ["203.0.113.66@223.5.5.5+1.12.12.12"]);
        // A real move passes: replaced, verdict moved.
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t",
                       &says(ans(&["198.51.100.7"]), ans(&["198.51.100.7"])),
                       |_| Some(vec![a("198.51.100.7")]), no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Moved, vec![a("198.51.100.7")]));
        // …and the next refresh, with the moved row as last good, needs no probe.
        let r = decide("entry.example", &c, Some(&r), "t",
                       &says(ans(&["198.51.100.7"]), ans(&["198.51.100.7"])), no_probe, no_system);
        assert_eq!(r.verdict, Verdict::Ok);
    }

    /// One source while the other is unreachable: used when there is no last
    /// good answer, unless refused. Against a verified last good answer it
    /// differs from, it must pass the probe: kept on failure, replaced on pass —
    /// the network that hijacks DNS may well block the honest DoH too.
    #[test]
    fn a_single_source_replaces_last_good_only_through_the_probe() {
        let c = Conf::parse("refuse 203.0.113.66\n");
        let r = decide("entry.example", &c, None, "t",
                       &says(Reply::Nothing, ans(&["198.51.100.7"])), no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()), (Verdict::Ok, vec![a("198.51.100.7")], B));
        let alone = says(ans(&["198.51.100.66"]), Reply::Nothing);
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t", &alone, |_| Some(vec![]), no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Held, vec![a("192.0.2.10")]));
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t", &alone, |_| None, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Held, vec![a("192.0.2.10")]), "no probe, no move");
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t", &alone,
                       |_| Some(vec![a("198.51.100.66")]), no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone(), r.source.as_str()),
                   (Verdict::Moved, vec![a("198.51.100.66")], A));
        // A refused answer is no answer: here A's is the local `refuse` override.
        let r = decide("entry.example", &c, None, "t",
                       &says(ans(&["203.0.113.66"]), ans(&["198.51.100.7"])), no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Ok, vec![a("198.51.100.7")]));
        assert_eq!(r.refused, ["203.0.113.66=sinkhole@223.5.5.5"]);
        // The only answer refused: nothing new, the last good stays.
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t",
                       &says(ans(&["203.0.113.66"]), Reply::Nothing), no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Refused, vec![a("192.0.2.10")]));
    }

    /// A tie the system resolver broke is used, never trusted: on the next
    /// refresh, with the same unsettled disagreement, it is not "the last good
    /// answer" — the system resolver is asked again, and with no answer from
    /// it the server gets nothing.
    #[test]
    fn a_system_resolver_tie_break_never_becomes_last_good() {
        let c = Conf::parse("");
        let both = says(ans(&["203.0.113.66"]), ans(&["198.51.100.7"]));
        let first = decide("entry.example", &c, None, "t", &both, |_| Some(vec![]), || Some(vec![a("203.0.113.66")]));
        assert_eq!((first.addrs.clone(), first.source.as_str()), (vec![a("203.0.113.66")], FROM_SYSTEM));
        let mut asked = false;
        let next = decide("entry.example", &c, Some(&first), "t", &both, |_| Some(vec![]), || { asked = true; None });
        assert!(asked, "the system tie-break was taken for a last good answer");
        assert_eq!((next.verdict.clone(), next.addrs.len(), next.source.as_str()), (Verdict::Disputed, 0, ""));
        // Nor does it make a single source's new answer skip the probe.
        let r = decide("entry.example", &c, Some(&first), "t", &says(ans(&["198.51.100.7"]), Reply::Nothing),
                       no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Ok, vec![a("198.51.100.7")]));
        // With no DoH answer at all, what sing-box has stays — still labelled
        // as the system resolver's, so a later refresh still does not trust it.
        let r = decide("entry.example", &c, Some(&first), "t", &says(Reply::Nothing, Reply::Nothing), no_probe, no_system);
        assert_eq!((r.addrs.clone(), r.source.as_str()), (vec![a("203.0.113.66")], FROM_SYSTEM));
    }

    /// Every source poisoned by category: refused, and the last good addresses
    /// stay — or, with none, nothing at all, so the member fails closed.
    #[test]
    fn all_refused_keeps_the_last_good_answer_or_gives_nothing() {
        let c = Conf::parse("");
        let r = decide("entry.example", &c, Some(&good(&["192.0.2.10"])), "t",
                       &says(ans(&["10.0.0.1"]), ans(&["10.0.0.1"])), no_probe, no_system);
        assert_eq!((r.verdict.clone(), r.addrs.clone()), (Verdict::Refused, vec![a("192.0.2.10")]));
        assert_eq!(r.refused, ["10.0.0.1=private@223.5.5.5", "10.0.0.1=private@1.12.12.12"]);
        let r = decide("entry.example", &c, None, "t", &says(ans(&["127.0.0.1"]), Reply::Nothing), no_probe, no_system);
        assert_eq!((r.verdict, r.addrs.len()), (Verdict::Refused, 0));
        let r = decide("entry.example", &c, None, "t", &says(Reply::Nothing, ans(&[])), no_probe, no_system);
        assert_eq!((r.verdict, r.addrs.len()), (Verdict::Unanswered, 0));
    }

    #[test]
    fn the_tsv_round_trips_and_guards_only_names_with_an_opinion() {
        let w = "2026-10-26 12:00:00".to_string();
        let rows = vec![
            Row { name: "a.example".into(), verdict: Verdict::Ok, addrs: vec![a("192.0.2.1")], source: A.into(),
                  refused: vec!["10.0.0.1=private@1.12.12.12".into()], disputed: vec![], when: w.clone() },
            Row { name: "b.example".into(), verdict: Verdict::Refused, addrs: vec![], source: String::new(),
                  refused: vec!["127.0.0.1=loopback@223.5.5.5".into()], disputed: vec![], when: w.clone() },
            Row { name: "c.example".into(), verdict: Verdict::Unanswered, addrs: vec![], source: String::new(),
                  refused: vec![], disputed: vec![], when: w.clone() },
            Row { name: "d.example".into(), verdict: Verdict::Unanswered, addrs: vec![a("192.0.2.4")], source: B.into(),
                  refused: vec![], disputed: vec![], when: w.clone() },
            Row { name: "e.example".into(), verdict: Verdict::Probed, addrs: vec![a("198.51.100.7")], source: B.into(),
                  refused: vec![], disputed: vec!["203.0.113.66@223.5.5.5".into(), "198.51.100.7@1.12.12.12".into()],
                  when: w.clone() },
        ];
        let tsv = render_tsv(&rows);
        assert_eq!(parse_tsv(&tsv), rows);
        assert!(tsv.contains("b.example\trefused\t-\t-\t127.0.0.1=loopback@223.5.5.5\t-\t"));
        let g = guarded(&tsv, "");
        assert_eq!(g.into_iter().collect::<Vec<_>>(), ["a.example", "b.example", "d.example", "e.example"]);
        assert!(guarded(&tsv, "off\n").is_empty());
        assert_eq!(render_hosts(&rows),
                   format!("{HOSTS_HEADER}\n192.0.2.1 a.example\n192.0.2.4 d.example\n198.51.100.7 e.example\n"));
    }

    #[test]
    fn guarding_touches_only_members_whose_server_is_a_guarded_name() {
        let escs = json!([
            {"type": "vless", "tag": "a", "server": "A.example", "server_port": 443},
            {"type": "vless", "tag": "b", "server": "192.0.2.9", "server_port": 443},
            {"type": "urltest", "tag": "auto", "outbounds": ["a", "b"]},
        ]);
        let names: BTreeSet<String> = ["a.example".to_string()].into();
        let g = guard_members(&escs, &names);
        assert_eq!(g[0]["domain_resolver"], resolver());
        assert!(g[1].get("domain_resolver").is_none());
        assert!(g[2].get("domain_resolver").is_none());
        assert!(uses_guard(&g));
        assert!(!uses_guard(&escs));
    }

    #[test]
    fn a_twin_dials_the_address_and_keeps_everything_that_followed_the_name() {
        let m = json!({"type": "vless", "tag": "entry-a", "server": "Entry.Example.", "server_port": 443,
                       "uuid": "u", "detour": "x", "tls": {"enabled": true},
                       "transport": {"type": "ws", "path": "/p"}});
        let t = twin(&m, a("198.51.100.7"), "probe-1", "en0");
        assert_eq!(t["tag"], "probe-1");
        assert_eq!(t["server"], "198.51.100.7");
        assert_eq!(t["server_port"], 443);
        assert_eq!(t["bind_interface"], "en0");
        assert_eq!(t["tls"]["server_name"], "Entry.Example");
        assert_eq!(t["transport"]["headers"]["Host"], "Entry.Example");
        assert!(t.get("detour").is_none());
        // A server name or Host already given is kept.
        let m = json!({"type": "trojan", "server": "e.example", "tls": {"enabled": true, "server_name": "cdn.example"},
                       "transport": {"type": "ws", "headers": {"host": "h.example"}}});
        let t = twin(&m, a("198.51.100.7"), "probe-0", "");
        assert_eq!(t["tls"]["server_name"], "cdn.example");
        assert_eq!(t["transport"]["headers"], json!({"host": "h.example"}));
        assert!(t.get("bind_interface").is_none());
        let cfg = probe_config(&m, &[a("203.0.113.66"), a("198.51.100.7")], "");
        assert_eq!(cfg["outbounds"][1]["tag"], "probe-1");
        assert_eq!(cfg["outbounds"][1]["server"], "198.51.100.7");
        let servers = vec![json!({"server": "x.example"}), m.clone()];
        assert_eq!(member_for(&servers, "e.example"), Some(&m));
    }

    #[test]
    fn names_skip_address_literals() {
        let s = vec![json!({"server": "Entry.Example."}), json!({"server": "192.0.2.1"}),
                     json!({"server": "2001:db8::1"}), json!({"server": "entry.example"}), json!({"tag": "x"})];
        assert_eq!(names(&s), ["entry.example"]);
    }

    #[test]
    fn utc_stamps_round_trip() {
        for t in [0u64, 951_782_400, 1_793_000_000, 1_793_016_000 + 59] {
            assert_eq!(parse_utc_stamp(&utc_stamp(t)), Some(t), "{t}");
        }
        assert_eq!(utc_stamp(0), "1970-01-01 00:00:00");
        assert_eq!(utc_stamp(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(parse_utc_stamp("2026-13-01 00:00:00"), None);
        assert_eq!(parse_utc_stamp("yesterday"), None);
    }

    #[test]
    fn status_and_warnings_say_when_a_new_answer_moved_or_was_held() {
        let held = Row { name: "entry.example".into(), verdict: Verdict::Held, addrs: vec![a("192.0.2.10")],
                         source: FROM_LAST_GOOD.into(), refused: vec![], disputed: vec!["203.0.113.66@223.5.5.5".into()],
                         when: utc_stamp(1000) };
        assert_eq!(warnings(&held), ["escape server entry.example: DoH now answers 203.0.113.66 from 223.5.5.5, not the last good answer, and it did not pass the probe through the server — 192.0.2.10 stays"]);
        let moved = Row { verdict: Verdict::Moved, addrs: vec![a("198.51.100.7")], source: B.into(),
                          disputed: vec!["198.51.100.7@1.12.12.12".into()], ..held.clone() };
        let lines = status_lines(&[json!({"server": "entry.example"})], &render_tsv(&[moved.clone()]), "");
        assert_eq!(lines[1], "  entry.example: MOVED — 198.51.100.7 from 1.12.12.12 answered the probe through the server; using 198.51.100.7");
        let lines = status_lines(&[json!({"server": "entry.example"})], &render_tsv(&[held]), "");
        assert!(lines[0].contains(": 1 held"), "{}", lines[0]);
        assert_eq!(lines[1], "  entry.example: DoH now answers 203.0.113.66 from 223.5.5.5, which did NOT pass the probe through the server — still using 192.0.2.10, the last good answer");
        assert_eq!(parse_tsv(&render_tsv(&[moved.clone()])), [moved]);
    }

    #[test]
    fn status_and_warnings_name_what_was_refused_and_what_disagreed() {
        let rows = [
            Row { name: "entry.example".into(), verdict: Verdict::Ok, addrs: vec![a("192.0.2.10")], source: B.into(),
                  refused: vec!["198.51.100.66=sinkhole@223.5.5.5".into()], disputed: vec![], when: utc_stamp(1000) },
            Row { name: "other.example".into(), verdict: Verdict::Probed, addrs: vec![a("198.51.100.7")], source: B.into(),
                  refused: vec![], disputed: vec!["203.0.113.66@223.5.5.5".into(), "198.51.100.7@1.12.12.12".into()],
                  when: utc_stamp(900) },
            Row { name: "third.example".into(), verdict: Verdict::Disputed, addrs: vec![a("192.0.2.30")],
                  source: FROM_LAST_GOOD.into(), refused: vec![],
                  disputed: vec!["203.0.113.66@223.5.5.5".into(), "198.51.100.7@1.12.12.12".into()], when: utc_stamp(900) },
        ];
        let tsv = render_tsv(&rows);
        let s = vec![json!({"server": "entry.example"}), json!({"server": "other.example"}),
                     json!({"server": "third.example"}), json!({"server": "fourth.example"})];
        let lines = status_lines(&s, &tsv, "");
        assert_eq!(lines[0], "escape dns:   4 server name(s), each asked of 223.5.5.5 and 1.12.12.12: 1 ok, 1 probed, 1 disputed, 1 not checked yet, last checked 1970-01-01 00:16:40 UTC");
        assert_eq!(lines[1], "  entry.example: REFUSED 198.51.100.66 (sinkhole, from 223.5.5.5); using 192.0.2.10 from 1.12.12.12");
        assert_eq!(lines[3], "  other.example: DoH sources DISAGREE (203.0.113.66 from 223.5.5.5; 198.51.100.7 from 1.12.12.12) — 198.51.100.7 (from 1.12.12.12) answered the probe through the server, so it is used");
        assert_eq!(lines[4], "  third.example: DoH sources DISAGREE (203.0.113.66 from 223.5.5.5; 198.51.100.7 from 1.12.12.12) — the probe did not settle it, so 192.0.2.30, the last good answer, stays");
        assert!(status_lines(&[json!({"server": "192.0.2.1"})], "", "").is_empty());
        assert_eq!(warnings(&rows[0]), ["escape server entry.example: refused 198.51.100.66 (sinkhole) from 223.5.5.5"]);
        assert_eq!(warnings(&rows[2]), ["escape server third.example: DoH sources disagree (203.0.113.66 from 223.5.5.5; 198.51.100.7 from 1.12.12.12) — the probe did not settle it, so 192.0.2.30, the last good answer, stays"]);
    }
}
