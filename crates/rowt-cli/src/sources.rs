//! Where each manual server came from — what `server import --replace` reads.
//!
//! `manual-sources.tsv` holds one line per (import source, manual server): the
//! source (`file:<name>` for a `server dump`, the review file's `_source` for
//! `--apply`), the tag the server has in manual.json, and its
//! `type:server:port`. No uuid or password. A server added by hand has no line,
//! so no `--replace` ever takes it.
//!
//! The shell's `_manual_import`, `_sources_prune` and `_sources_write`, step
//! for step: the comparisons are jq's (a tag matches only as the same string),
//! the identity is jq's string interpolation of type, server, port and secret,
//! and the file is `LC_ALL=C sort -u` under a fixed header — `cli-diff` compares
//! it byte for byte.

use crate::lifecycle::{read, Ctx};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const HEADER: &str = "# rowt: which import brought each manual server in, for 'server import --replace' (source, tag, type:server:port)";

fn file(cfg: &Path) -> PathBuf { cfg.join("manual-sources.tsv") }

fn info(msg: &str) { eprintln!("==> {msg}"); }

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}

/// `_canonical_source` — the one name a client's servers are recorded under:
/// `sr` is shadowrocket and `clashverge`/`verge` are clash-verge, as `--from`
/// accepts them. `--replace` matches on it.
pub fn canonical(source: &str) -> &str {
    match source {
        "sr" => "shadowrocket",
        "clashverge" | "verge" => "clash-verge",
        other => other,
    }
}

/// One recorded line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub s: String,
    pub t: String,
    pub e: String,
}

/// jq's `"\(x)"`: a string as itself, null as `null`, anything else as JSON.
fn interp(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// `def ep: "\(.type):\(.server):\(.server_port)"`.
pub fn ep(o: &Value) -> String {
    format!("{}:{}:{}", interp(o.get("type")), interp(o.get("server")), interp(o.get("server_port")))
}

/// jq's `(.k // "") != ""` — present, not null or false, and not the empty string.
fn set(v: Option<&Value>) -> Option<&Value> {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(x) => Some(x),
    }
}

/// `def ident: "\(ep):\(secret)"` — the endpoint plus its uuid or password.
pub fn ident(o: &Value) -> String {
    let secret = set(o.get("uuid")).or_else(|| set(o.get("password")))
        .map(|v| interp(Some(v))).unwrap_or_default();
    format!("{}:{secret}", ep(o))
}

/// `[.tag, ep]` against a recorded `[t, e]`: jq compares the tag as a value,
/// so only a string tag can ever equal what the file holds.
fn same(o: &Value, t: &str, e: &str) -> bool {
    o.get("tag").and_then(Value::as_str) == Some(t) && ep(o) == e
}

/// `_sources_json` — the lines with exactly three tab-separated fields that are
/// not comments (`awk -F'\t' '!/^#/ && NF == 3'`).
pub fn lines(cfg: &Path) -> Vec<Line> {
    read(&file(cfg)).lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 3).then(|| Line { s: f[0].into(), t: f[1].into(), e: f[2].into() })
        })
        .collect()
}

/// `_sources_write` — sorted unique under the header, or no file at all.
fn write(cfg: &Path, ls: &[Line]) {
    let body: BTreeSet<String> = ls.iter().map(|l| format!("{}\t{}\t{}", l.s, l.t, l.e)).collect();
    let p = file(cfg);
    if body.is_empty() {
        let _ = std::fs::remove_file(&p);
        return;
    }
    let mut out = format!("{HEADER}\n");
    for l in &body {
        out.push_str(l);
        out.push('\n');
    }
    let n = p.with_extension("tsv.n");
    if std::fs::write(&n, out).is_ok() && std::fs::rename(&n, &p).is_ok() {
        set_mode(&p, 0o600);
    }
}

/// The manual set as JSON, or `None` when the file is not JSON at all — jq
/// fails there and the shell writes nothing.
fn manual_value(cfg: &Path) -> Option<Value> {
    let p = cfg.join("manual.json");
    let body = read(&p);
    if body.is_empty() {
        return Some(Value::Array(Vec::new()));
    }
    serde_json::from_str(&body).ok()
}

/// `_sources_prune` — forget the lines whose server left manual.json.
pub fn prune(cfg: &Path) {
    if !file(cfg).is_file() {
        return;
    }
    let Some(m) = manual_value(cfg) else { return };
    let present: Vec<Value> = m.as_array().cloned().unwrap_or_default();
    if present.iter().any(|o| !o.is_object()) {
        return;
    }
    let kept: Vec<Line> = lines(cfg).into_iter()
        .filter(|l| present.iter().any(|o| same(o, &l.t, &l.e)))
        .collect();
    write(cfg, &kept);
}

/// `_manual_import` — merge `(source, outbound)` pairs into the manual set.
/// With `replace`, what an earlier import from the same source(s) brought in
/// goes first, unless another source also brought it in.
pub fn manual_import(ctx: &Ctx, pairs: &[(String, Value)], replace: bool) -> Result<(), String> {
    let cfg = &ctx.cfg;
    let manual_path = cfg.join("manual.json");
    if !std::fs::metadata(&manual_path).map(|m| m.len() > 0).unwrap_or(false) {
        std::fs::write(&manual_path, "[]\n").map_err(|e| format!("write: {e}"))?;
    }
    let prov = lines(cfg);
    let srcs: BTreeSet<String> = pairs.iter().map(|(s, _)| s.clone()).collect();
    let mut manual: Vec<Value> = serde_json::from_str(&read(&manual_path)).unwrap_or_default();

    if replace && !srcs.is_empty() {
        let others: Vec<(&str, &str)> = prov.iter().filter(|l| !srcs.contains(&l.s))
            .map(|l| (l.t.as_str(), l.e.as_str())).collect();
        let drop: Vec<(&str, &str)> = prov.iter().filter(|l| srcs.contains(&l.s))
            .map(|l| (l.t.as_str(), l.e.as_str()))
            .filter(|k| !others.contains(k)).collect();
        let hit = |o: &Value| drop.iter().any(|(t, e)| same(o, t, e));
        let names: Vec<String> = manual.iter().filter(|o| hit(o))
            .map(|o| interp(o.get("tag"))).collect();
        let from = srcs.iter().cloned().collect::<Vec<_>>().join(", ");
        if names.is_empty() {
            info(&format!("--replace: no earlier import from {from} recorded — nothing to drop. Servers imported \
                           before rowt recorded where they came from are not tracked; to start clean: {} server \
                           clear (every manual server), then import again", crate::PROG));
        } else {
            info(&format!("--replace: dropping the server(s) an earlier import from {from} brought in: {}",
                          names.join(", ")));
            manual.retain(|o| !hit(o));
        }
    }
    let before: Vec<String> = manual.iter().map(ident).collect();

    let mut all = manual;
    all.extend(pairs.iter().map(|(_, o)| o.clone()));
    let combined = rowt_core::sharelink::combine(&all);
    for w in &combined.warnings {
        eprintln!("{w}");
    }
    let n_file = manual_path.with_extension("json.n");
    std::fs::write(&n_file, rowt_core::sharelink::render(&Value::Array(combined.outbounds.clone())))
        .map_err(|e| format!("write: {e}"))?;
    std::fs::rename(&n_file, &manual_path).map_err(|e| format!("mv: {e}"))?;
    set_mode(&manual_path, 0o600);

    let m = combined.outbounds;
    if m.iter().any(|o| !o.is_object()) || pairs.iter().any(|(_, o)| !o.is_object()) {
        return Ok(());
    }
    let mut out: Vec<Line> = prov.into_iter()
        .filter(|l| !replace || !srcs.contains(&l.s))
        .filter(|l| m.iter().any(|o| same(o, &l.t, &l.e)))
        .collect();
    let claimed: Vec<(String, String)> = out.iter().map(|l| (l.t.clone(), l.e.clone())).collect();
    for (s, o) in pairs {
        let id = ident(o);
        let Some(e) = m.iter().find(|x| ident(x) == id) else { continue };
        let (tag, eep) = (interp(e.get("tag")), ep(e));
        let was_claimed = e.get("tag").and_then(Value::as_str)
            .map(|t| claimed.iter().any(|(ct, ce)| ct == t && *ce == eep)).unwrap_or(false);
        if !before.contains(&id) || was_claimed {
            out.push(Line { s: s.clone(), t: tag, e: eep });
        }
    }
    write(cfg, &out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_reads_like_jq_interpolation() {
        let o = json!({"type": "vless", "server": "a.example", "server_port": 443, "uuid": "u-1"});
        assert_eq!(ep(&o), "vless:a.example:443");
        assert_eq!(ident(&o), "vless:a.example:443:u-1");
        // An empty uuid falls through to the password, as `(.uuid // "") != ""` does.
        let p = json!({"type": "trojan", "server": "b.example", "server_port": "8443", "uuid": "", "password": "pw"});
        assert_eq!(ident(&p), "trojan:b.example:8443:pw");
        assert_eq!(ident(&json!({"server": "c.example"})), "null:c.example:null:");
    }

    #[test]
    fn a_client_is_recorded_under_one_name() {
        assert_eq!(canonical("sr"), "shadowrocket");
        assert_eq!(canonical("shadowrocket"), "shadowrocket");
        assert_eq!(canonical("verge"), "clash-verge");
        assert_eq!(canonical("clashverge"), "clash-verge");
        assert_eq!(canonical("file:servers.json"), "file:servers.json");
    }

    #[test]
    fn only_a_string_tag_matches_a_recorded_line() {
        let o = json!({"tag": "a", "type": "vless", "server": "a.example", "server_port": 443});
        assert!(same(&o, "a", "vless:a.example:443"));
        assert!(!same(&o, "a", "vless:a.example:8443"));
        let n = json!({"tag": 5, "type": "vless", "server": "a.example", "server_port": 443});
        assert!(!same(&n, "5", "vless:a.example:443"));
    }
}
