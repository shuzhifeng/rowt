//! The escape servers' names, resolved over DoH and checked — the I/O half of
//! `rowt_core::escapedns`, which says why.
//!
//! One implementation, two callers: bin/rowt reaches it as the hidden
//! `rowt-rs _escape-dns <refresh|guarded|status>`, and rowt-rs calls it in
//! process, at the same points (the render, the watchdog tick, `status`). So
//! the two never disagree about an answer, and `cli-diff` sees the same curl
//! calls on both sides.

use crate::lifecycle::{read, Ctx};
use rowt_core::escapedns::{self as ed, Conf, Reply, Row};
use rowt_platform::{Mac, Platform};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

fn now_epoch() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn servers(cfg: &Path) -> Vec<Value> {
    serde_json::from_str(&read(&cfg.join("servers.json"))).unwrap_or_default()
}

fn conf_text(cfg: &Path) -> String {
    read(&cfg.join("escape-dns.txt"))
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}

/// Write `body` to `p` through a rename, only when it differs — sing-box
/// re-reads escape-hosts on every change, and a refresh that changed nothing
/// should not look like one.
fn write_if_changed(p: &Path, body: &str) {
    if read(p) == body {
        return;
    }
    let tmp = p.with_extension("n");
    if std::fs::write(&tmp, body).is_ok() && std::fs::rename(&tmp, p).is_ok() {
        set_mode(p, 0o600);
    }
}

/// Ask one DoH source about one name. `Err(())` when the source itself could
/// not be reached (curl could not resolve, connect, or finish in time), so the
/// rest of this refresh skips it rather than waiting on it again.
fn ask(url: &str, name: &str, iface: &str) -> Result<Reply, ()> {
    let sep = if url.contains('?') { '&' } else { '?' };
    let full = format!("{url}{sep}name={}&type=A", rowt_core::pyurl::quote(name, ""));
    let mut c = Command::new("curl");
    c.args(["--noproxy", "*", "-sS", "--connect-timeout", "2", "-m", "4"]);
    if !iface.is_empty() {
        c.args(["--interface", iface]);
    }
    c.args(["-H", "accept: application/dns-json", &full]).stderr(Stdio::null());
    let Ok(o) = c.output() else { return Err(()) };
    match o.status.code() {
        Some(0) => Ok(match ed::parse_answer(&String::from_utf8_lossy(&o.stdout)) {
            Some(a) if !a.is_empty() => Reply::Answer(a),
            _ => Reply::Nothing,
        }),
        Some(6 | 7 | 28) => Err(()),
        _ => Ok(Reply::Nothing),
    }
}

/// The delay probe of a disputed name: which `candidates` answer a fetch of
/// the health URL (`ROWT_HEALTH_URL`, the watchdog's generate_204) THROUGH the
/// server itself, dialing that address — the same test urltest and the
/// watchdog run, so a sinkhole that merely accepts a connection fails it.
/// One twin of the name's member per candidate (`escapedns::twin`), each
/// fetched by `sing-box tools fetch` at once, each capped at
/// ROWT_HEALTH_TIMEOUT + 2 seconds and killed past it. `None` when it cannot
/// run: no sing-box yet, or no member dials this name.
fn probe(cfg: &Path, name: &str, candidates: &[std::net::Ipv4Addr], iface: &str) -> Option<Vec<std::net::Ipv4Addr>> {
    let sb = cfg.join("bin/sing-box");
    if !sb.is_file() {
        return None;
    }
    let servers = servers(cfg);
    let member = ed::member_for(&servers, name)?;
    let conf = ed::probe_config(member, candidates, iface);
    // It holds the member's credentials: written owner-only from the start,
    // and removed whatever the probes did.
    let path = cfg.join(format!(".escape-probe-{}.json", std::process::id()));
    let written = (|| -> Option<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
            .open(&path).ok()?;
        f.write_all(serde_json::to_string(&conf).ok()?.as_bytes()).ok()
    })();
    if written.is_none() {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    let url = crate::env_or("ROWT_HEALTH_URL", "https://www.gstatic.com/generate_204");
    let limit = std::time::Duration::from_secs(crate::env_or("ROWT_HEALTH_TIMEOUT", "8").parse::<u64>().unwrap_or(8) + 2);
    let handles: Vec<_> = candidates.iter().enumerate().map(|(i, a)| {
        let (sb, path, url, a) = (sb.clone(), path.clone(), url.clone(), *a);
        std::thread::spawn(move || {
            let Ok(mut child) = Command::new(&sb)
                .args(["tools", "fetch", "-c"]).arg(&path).args(["-o", &format!("probe-{i}"), &url])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else { return None };
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => return st.success().then_some(a),
                    Ok(None) if start.elapsed() < limit => std::thread::sleep(std::time::Duration::from_millis(100)),
                    // Past the cap: this child, by its own handle — nothing else.
                    _ => { let _ = child.kill(); let _ = child.wait(); return None; }
                }
            }
        })
    }).collect();
    let passed: Vec<_> = handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect();
    let _ = std::fs::remove_file(&path);
    Some(passed)
}

/// The system resolver's A records for `name` (`dig`, as `probe` reads it) —
/// the last word on a disputed name with no last good answer.
fn system_answer(name: &str) -> Option<Vec<std::net::Ipv4Addr>> {
    let o = Command::new("dig").args(["+short", "+time=2", "+tries=1", name, "A"])
        .stderr(Stdio::null()).output().ok()?;
    let addrs: Vec<_> = String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| l.trim().parse().ok()).collect();
    (!addrs.is_empty()).then_some(addrs)
}

/// Refresh every name whose verdict is older than `max_age` seconds (all of
/// them with 0), write escape-dns.tsv and escape-hosts, and say on stderr what
/// was refused and what the sources disagreed about. Every source is asked
/// about every name (`escapedns::decide` compares them); the probe runs only
/// for a name they disagree on. Does nothing when no server is a name, or when
/// escape-dns.txt says `off`.
pub fn refresh(cfg: &Path, max_age: u64) {
    let names = ed::names(&servers(cfg));
    let conf = Conf::parse(&conf_text(cfg));
    if names.is_empty() || conf.off {
        return;
    }
    let tsv_path = cfg.join("escape-dns.tsv");
    let prev: Vec<Row> = ed::parse_tsv(&read(&tsv_path));
    let now = now_epoch();
    let when = ed::utc_stamp(now);
    let fresh = |r: &Row| ed::parse_utc_stamp(&r.when).map(|t| now.saturating_sub(t) < max_age).unwrap_or(false);
    let mut iface: Option<String> = None;
    let mut dead: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::new();
    for n in &names {
        let old = prev.iter().find(|r| &r.name == n);
        if let Some(r) = old.filter(|r| fresh(r)) {
            rows.push(r.clone());
            continue;
        }
        // The physical NIC, like the dns-direct resolver this stands beside:
        // a corp VPN holding the default route must not carry these queries.
        let ifc = iface.get_or_insert_with(|| Mac.detect_iface().unwrap_or_default()).clone();
        // One after another, so the order of the queries is the order of the
        // sources; a source that cannot be reached is skipped for the rest.
        let replies: Vec<(String, Reply)> = conf.doh.iter().map(|url| {
            let reply = if dead.contains(url) {
                Reply::Nothing
            } else {
                ask(url, n, &ifc).unwrap_or_else(|()| {
                    dead.insert(url.to_string());
                    Reply::Nothing
                })
            };
            (ed::source_label(url), reply)
        }).collect();
        let row = ed::decide(n, &conf, old, &when, &replies,
                             |cands| probe(cfg, n, cands, &ifc), || system_answer(n));
        for w in ed::warnings(&row) {
            eprintln!("warning: {w}");
        }
        rows.push(row);
    }
    write_if_changed(&tsv_path, &ed::render_tsv(&rows));
    write_if_changed(&cfg.join("escape-hosts"), &ed::render_hosts(&rows));
}

/// The names the render guards (see `rowt_core::escapedns::guarded`).
pub fn guarded(cfg: &Path) -> BTreeSet<String> {
    ed::guarded(&read(&cfg.join("escape-dns.tsv")), &conf_text(cfg))
}

/// The `escape dns:` lines of `rowt status`.
pub fn status(cfg: &Path) -> Vec<String> {
    ed::status_lines(&servers(cfg), &read(&cfg.join("escape-dns.tsv")), &conf_text(cfg))
}

/// How long a name's verdict stays fresh: ROWT_ESCAPE_DNS_MAX_AGE seconds,
/// else `MAX_AGE_SECS`. 0 asks again on every refresh.
pub fn max_age() -> u64 {
    std::env::var("ROWT_ESCAPE_DNS_MAX_AGE").ok().and_then(|v| v.parse().ok()).unwrap_or(ed::MAX_AGE_SECS)
}

/// Before a host render: refresh what is stale, at the same point the shell
/// does it (`cmd_render`).
pub fn before_render(ctx: &Ctx) {
    if ctx.mode() == "host" {
        refresh(&ctx.cfg, max_age());
    }
}

/// `rowt-rs _escape-dns <refresh|guarded|status> --config-dir DIR` — the
/// shell's door to the same code. Answered ahead of the preamble, like
/// `_splitter`: no migration, rotation or audit line for a helper call.
pub fn helper(args: &[String]) -> i32 {
    let mut it = args.iter();
    let action = it.next().map(|s| s.as_str()).unwrap_or("");
    let mut dir: Option<String> = None;
    while let Some(a) = it.next() {
        if a == "--config-dir" {
            dir = it.next().cloned();
        }
    }
    let Some(dir) = dir else {
        eprintln!("usage: rowt-rs _escape-dns <refresh|guarded|status> --config-dir DIR");
        return 2;
    };
    let cfg = Path::new(&dir);
    match action {
        "refresh" => refresh(cfg, max_age()),
        "guarded" => {
            let g: Vec<String> = guarded(cfg).into_iter().collect();
            println!("{}", serde_json::to_string(&g).unwrap_or_else(|_| "[]".into()));
        }
        "status" => {
            for l in status(cfg) {
                println!("{l}");
            }
        }
        _ => {
            eprintln!("usage: rowt-rs _escape-dns <refresh|guarded|status> --config-dir DIR");
            return 2;
        }
    }
    0
}
