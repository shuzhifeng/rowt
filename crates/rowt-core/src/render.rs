//! The render, as pure functions.
//!
//! This is a reimplementation of the jq program in `bin/rowt` (`assemble_host`,
//! `assemble_vm`, `group_jq`, `list_json`). It is held to that original by
//! canonical-JSON equality — see PORTING.md §6.3 and `tests/parity`.
//!
//! Nothing here touches the network, the clock, or the OS. The two values that
//! do — the physical interface and the clash secret — are inputs, so the
//! platform seam stays in the shell until Phase 5.

use serde_json::{json, Map, Value};

/// One lane list, already parsed. Mirrors `list_json`'s output.
#[derive(Debug, Default, Clone)]
pub struct Lists {
    pub escape_domains: Vec<String>,
    pub corp_domains: Vec<String>,
    pub corp_cidrs: Vec<String>,
    pub block_domains: Vec<String>,
    // `--domain` entries (`domain:<host>` lines), rendered as sing-box `domain`
    // rules ahead of every suffix rule.
    pub escape_exact: Vec<String>,
    pub corp_exact: Vec<String>,
    pub block_exact: Vec<String>,
}

/// Cached `geosite:<name>` rule-sets, split the way the render uses them.
#[derive(Debug, Default, Clone)]
pub struct Geo {
    /// Categories named by the escape list that are present in the cache.
    pub escape: Vec<String>,
    /// Categories named by the block list that are present in the cache.
    pub block: Vec<String>,
    /// Every cached category referenced by any lane, as (tag, path).
    pub sets: Vec<(String, String)>,
    /// Path to the ad/tracker set, or empty when it is not cached.
    pub ads_path: String,
}

/// Everything the host render needs. Field-for-field the jq program's `--arg`s.
#[derive(Debug, Clone)]
pub struct HostInput {
    pub escapes: Value,
    pub listen: String,
    pub port: u64,
    pub iface: String,
    pub clash: String,
    pub secret: String,
    pub log_level: String,
    pub final_route: String,
    pub dns_direct: String,
    pub private_default: String,
    pub private_cidrs: Vec<String>,
    pub lists: Lists,
    pub geo: Geo,
    /// Where the escape lane's rules point. "escape" normally; "direct" in
    /// local mode, where no tunnel exists. The rules are still emitted either
    /// way — they carry precedence over broader block entries and the ad set.
    pub escape_outbound: String,
    /// The hosts file the guarded escape members resolve through
    /// (`escapedns`); the `dns-escape` server is rendered only when a member
    /// names it.
    pub escape_hosts: String,
    /// Named extra ports (`ports.tsv`, in `ports::rows` order). Empty renders
    /// byte-identically to a config from before they existed.
    pub ports: Vec<crate::ports::Port>,
}

/// Parse one lane list exactly as `list_json` does.
///
/// The order matters and is not obvious: comment/blank lines are dropped on the
/// RAW line, then *all* whitespace is removed from what survives (not merely
/// trimmed — an inner space would close up too), then a `*.z.com` becomes
/// `.z.com` (`unwildcard`), then `geosite:` meta lines go, then the CIDR/domain
/// filter runs, and finally empties are dropped.
pub fn parse_list(contents: &str, filter: Filter) -> Vec<String> {
    contents
        .lines()
        .filter(|raw| {
            let t = raw.trim_start_matches([' ', '\t']);
            !(t.is_empty() || t.starts_with('#'))
        })
        .map(|raw| raw.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .map(|s| unwildcard(&s))
        .filter(|s| !s.starts_with("geosite:"))
        .filter_map(|s| {
            let exact = s.strip_prefix(EXACT_PREFIX).map(str::to_string);
            match filter {
                Filter::Exact => exact,
                // A `domain:` line is an EXACT rule, never a suffix or a CIDR.
                // Every other filter MUST drop it: they select by "is / isn't a
                // CIDR", a test `domain:z.com` passes, so without this it would
                // render as a `domain_suffix` — silently becoming the leaky
                // suffix the flag exists to avoid.
                _ if exact.is_some() => None,
                Filter::All => Some(s),
                Filter::Cidr => is_cidr(&s).then_some(s),
                Filter::Domain => (!is_cidr(&s)).then_some(s),
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Marks a lane entry as an EXACT host rule (sing-box `domain`) rather than the
/// default `domain_suffix`. Same shape as `geosite:` — a hostname can't contain
/// a colon, so the prefix is unambiguous, and both readers already split on one.
pub const EXACT_PREFIX: &str = "domain:";

/// `*.z.com` → `.z.com`: the wildcard spelling of a dot-led entry.
///
/// Shadowrocket and Surge write "the names under z.com" as `*.z.com`, and so
/// did rowt's own onboard and README (`corp add '*.corp.example.com'`). sing-box's
/// `domain_suffix` has no wildcard, though, so a stored `*.z.com` was a literal
/// `*` that no name contains: the entry matched nothing, silently. rowt's own
/// spelling of the same thing is `.z.com` (sing-box: the subdomains, not the
/// apex), so the wildcard is read as the dot — by every reader of a lane list,
/// which is what makes an entry already on disk work without an edit, and by
/// `add`/`import`, which store the dot.
///
/// Only that shape: `*.` alone, and a `*` anywhere else, pass as written.
pub fn unwildcard(e: &str) -> String {
    match e.strip_prefix("*.") {
        Some(rest) if !rest.is_empty() => format!(".{rest}"),
        _ => e.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    All,
    Cidr,
    Domain,
    /// Only `domain:<host>` lines, with the prefix stripped.
    Exact,
}

/// `grep -E '/[0-9]+$'` — a trailing slash-and-digits marks a CIDR.
pub(crate) fn is_cidr(s: &str) -> bool {
    match s.rsplit_once('/') {
        Some((_, suffix)) => !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// The `geosite:<name>` categories named by a list, in file order with
/// duplicates kept — `geosites_of` does no dedupe, and neither does the per-lane
/// rule it feeds.
pub fn geosites_of(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|raw| {
            let t = raw.trim_start_matches([' ', '\t']);
            let rest = t.strip_prefix("geosite:")?;
            let rest = rest.trim_start_matches([' ', '\t']);
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
                .collect();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
        .collect()
}

/// How often `auto`'s urltest re-tests every server: `ROWT_AUTO_INTERVAL` when it
/// is set, else what `use auto --every` saved in state, else 20m — the shell's
/// `_auto_interval`. Read at every render, so a reload keeps the saved value.
pub fn auto_interval(env: Option<&str>, saved: &str) -> String {
    match env.filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None if !saved.is_empty() => saved.to_string(),
        None => "20m".to_string(),
    }
}

/// The urltest's settings: how often a round runs, how many ms faster another
/// server must test before a round moves the pick (`ROWT_AUTO_TOLERANCE`,
/// default 100), and whether a switch also closes the connections left on the
/// old pick (`ROWT_AUTO_INTERRUPT=1`, opt-in). The last two came from PR #4.
#[derive(Clone, Debug, PartialEq)]
pub struct UrlTest {
    pub interval: String,
    pub tolerance: u64,
    pub interrupt: bool,
}

impl UrlTest {
    /// From the environment's raw values and the saved `--every`, as the shell
    /// reads them. A tolerance that is not whole milliseconds renders as the
    /// default; the render refuses it first (`auto_tolerance`).
    pub fn new(interval: String, tolerance: Option<&str>, interrupt: Option<&str>) -> Self {
        UrlTest {
            interval,
            tolerance: auto_tolerance(tolerance).unwrap_or(100),
            interrupt: interrupt == Some("1"),
        }
    }
}

/// `ROWT_AUTO_TOLERANCE` as the shell's `_auto_tolerance` reads it: unset or
/// empty is 100; one to five digits is that many ms; anything else is `None`.
pub fn auto_tolerance(env: Option<&str>) -> Option<u64> {
    match env.filter(|v| !v.is_empty()) {
        None => Some(100),
        Some(v) if v.len() <= 5 && v.bytes().all(|b| b.is_ascii_digit()) => v.parse().ok(),
        Some(_) => None,
    }
}

/// Seconds in a `use auto --every` duration: whole numbers with `s`, `m` or `h`,
/// run together the way Go writes them (`90s`, `3m`, `1m30s`, `1h`). `None` for
/// anything else — the shell's `_duration_secs` prints nothing for the same.
pub fn duration_secs(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (mut total, mut n, mut digits) = (0u64, 0u64, false);
    for c in s.chars() {
        match c {
            '0'..='9' => {
                n = n.checked_mul(10)?.checked_add(c as u64 - '0' as u64)?;
                digits = true;
            }
            's' | 'm' | 'h' if digits => {
                let unit = match c { 'h' => 3600, 'm' => 60, _ => 1 };
                total = total.checked_add(n.checked_mul(unit)?)?;
                n = 0;
                digits = false;
            }
            _ => return None,
        }
    }
    if digits { None } else { Some(total) }
}

/// The escape outbound group: members (optionally interface-bound), then either
/// a urltest + selector (`auto`) or a plain selector pinned to one server.
pub fn group(servers: &[Value], iface: &str, selected: &str, auto: &UrlTest) -> Value {
    let members: Vec<Value> = servers
        .iter()
        .map(|s| {
            let mut m = s.clone();
            if !iface.is_empty() {
                if let Some(obj) = m.as_object_mut() {
                    obj.insert("bind_interface".into(), json!(iface));
                }
            }
            m
        })
        .collect();
    let tags: Vec<Value> = members.iter().map(|m| m["tag"].clone()).collect();

    let mut out = members.clone();
    if selected == "auto" {
        let mut urltest = json!({
            "type": "urltest", "tag": "auto", "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204", "interval": auto.interval,
            "tolerance": auto.tolerance
        });
        if auto.interrupt {
            urltest["interrupt_exist_connections"] = json!(true);
        }
        out.push(urltest);
        let mut sel_outbounds = vec![json!("auto")];
        sel_outbounds.extend(tags.iter().cloned());
        out.push(json!({
            "type": "selector", "tag": "escape",
            "outbounds": sel_outbounds, "default": "auto"
        }));
    } else {
        // jq: `if ($tags | index($sel)) then $sel else ($tags[0] // "block")`
        let default = if tags.iter().any(|t| t == selected) {
            json!(selected)
        } else {
            tags.first().cloned().unwrap_or(json!("block"))
        };
        out.push(json!({
            "type": "selector", "tag": "escape",
            "outbounds": tags, "default": default
        }));
    }
    Value::Array(out)
}

/// `domain:` (exact) rules across the three hand lists.
///
/// These are emitted BEFORE `suffix_rules` and that ordering is a correctness
/// requirement, not tidiness: sing-box route rules are first-match-wins, so an
/// exact `z.com` on block would otherwise lose to a suffix `z.com` on escape.
/// Exact is strictly the more specific statement, so it goes first.
///
/// Lane order escape → corp → block, plain and unsorted — no length ranking is
/// meaningful when only one exact entry can ever match a given host, and it
/// matches the tie-break `suffix_rules` lands on. `classify` scans in the same
/// order, so the explainer and the router agree on which lane claims a host that
/// (only by hand-editing — `_lane_dedupe` prevents it) sits in two.
fn exact_rules(lists: &Lists, escape_outbound: &str) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for (list, outbound) in [
        (&lists.escape_exact, escape_outbound),
        (&lists.corp_exact, "corp"),
        (&lists.block_exact, "block"),
    ] {
        if !list.is_empty() {
            out.push(json!({"domain": list, "outbound": outbound}));
        }
    }
    out
}

/// Suffix rules across the three hand lists, most-specific first.
///
/// jq sorts by `[label count, string length]` ascending and then reverses the
/// WHOLE array. jq's sort is stable, so equal keys keep block/corp/escape order
/// — and the reverse then flips that to escape/corp/block. Rust's `sort_by` is
/// stable too, so the same two steps reproduce it exactly, ties included.
fn suffix_rules(lists: &Lists, escape_outbound: &str) -> Vec<Value> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    pairs.extend(lists.block_domains.iter().map(|s| (s.as_str(), "block")));
    pairs.extend(lists.corp_domains.iter().map(|s| (s.as_str(), "corp")));
    pairs.extend(lists.escape_domains.iter().map(|s| (s.as_str(), escape_outbound)));

    // jq's `length` on a string counts codepoints, not bytes.
    pairs.sort_by_key(|(s, _)| (s.split('.').count(), s.chars().count()));
    pairs.reverse();

    pairs
        .into_iter()
        .map(|(s, o)| json!({"domain_suffix": [s], "outbound": o}))
        .collect()
}

/// The host configuration — what lands in `host.json`.
pub fn render_host(i: &HostInput) -> Value {
    let mut rules: Vec<Value> = vec![json!({"action": "sniff"})];
    rules.extend(exact_rules(&i.lists, &i.escape_outbound));
    rules.extend(suffix_rules(&i.lists, &i.escape_outbound));
    rules.extend(
        i.geo.escape.iter()
            .map(|n| json!({"rule_set": [format!("geosite-{n}")], "outbound": i.escape_outbound})),
    );
    rules.extend(
        i.geo.block.iter()
            .map(|n| json!({"rule_set": [format!("geosite-{n}")], "outbound": "block"})),
    );
    // The ad set sits before the address rules, and a name no rule matched is
    // resolved (only when the final route is direct) so the address rules can
    // route it — the shell's renderer explains why, at length.
    if !i.geo.ads_path.is_empty() {
        rules.push(json!({"rule_set": ["geosite-ads"], "outbound": "block"}));
    }
    let address_rules = !i.lists.corp_cidrs.is_empty() || i.private_default == "corp";
    if i.final_route == "direct" && address_rules {
        rules.push(json!({"action": "resolve", "server": "dns-direct", "strategy": "prefer_ipv4"}));
    }
    if !i.lists.corp_cidrs.is_empty() {
        rules.push(json!({"ip_cidr": i.lists.corp_cidrs, "outbound": "corp"}));
    }
    if i.private_default == "corp" {
        rules.push(json!({"ip_cidr": i.private_cidrs, "outbound": "corp"}));
    }
    let rules = port_rules(rules, i);

    let mut dns_servers = json!([
        {"type": "local", "tag": "local"},
        {"type": "https", "tag": "dns-direct", "server": i.dns_direct, "detour": "direct"}
    ]);
    if crate::escapedns::uses_guard(&i.escapes) {
        if let Some(a) = dns_servers.as_array_mut() {
            a.push(crate::escapedns::hosts_server(&i.escape_hosts));
        }
    }
    // Corp names must resolve through the corp resolver or they answer with a
    // public IP and leave the tunnel — so an EXACT corp entry needs this rule
    // just as much as a suffix one. `domain` sits first, mirroring the route
    // rules, and each half is omitted when empty so a suffix-only config renders
    // byte-identically to before this flag existed.
    let mut dns_rules: Vec<Value> = Vec::new();
    if !i.lists.corp_exact.is_empty() {
        dns_rules.push(json!({"domain": i.lists.corp_exact, "server": "local"}));
    }
    if !i.lists.corp_domains.is_empty() {
        dns_rules.push(json!({"domain_suffix": i.lists.corp_domains, "server": "local"}));
    }

    let mut outbounds = i.escapes.as_array().cloned().unwrap_or_default();
    outbounds.push(json!({
        "type": "direct", "tag": "corp",
        "domain_resolver": {"server": "local", "strategy": "prefer_ipv4"}
    }));
    outbounds.push(json!({"type": "direct", "tag": "direct", "bind_interface": i.iface}));
    outbounds.push(json!({"type": "block", "tag": "block"}));

    let mut route = Map::new();
    route.insert("rules".into(), json!(rules));
    route.insert("final".into(), json!(i.final_route));
    route.insert("auto_detect_interface".into(), json!(false));
    route.insert(
        "default_domain_resolver".into(),
        json!({"server": "dns-direct", "strategy": "prefer_ipv4"}),
    );
    let mut allsets: Vec<Value> = i
        .geo
        .sets
        .iter()
        .map(|(tag, path)| json!({"type": "local", "tag": tag, "format": "binary", "path": path}))
        .collect();
    if !i.geo.ads_path.is_empty() {
        allsets.push(json!({
            "type": "local", "tag": "geosite-ads",
            "format": "binary", "path": i.geo.ads_path
        }));
    }
    if !allsets.is_empty() {
        route.insert("rule_set".into(), json!(allsets));
    }

    let mut root = Map::new();
    root.insert("log".into(), json!({"level": i.log_level, "timestamp": true}));
    root.insert(
        "dns".into(),
        json!({"servers": dns_servers, "rules": dns_rules, "final": "dns-direct"}),
    );
    // A named port is loopback-only, like "in"; a VM reaches it through its
    // host-side forward, never directly.
    let mut inbounds = vec![json!({"type": "mixed", "tag": "in", "listen": i.listen, "listen_port": i.port})];
    inbounds.extend(i.ports.iter().map(|p| {
        json!({"type": "mixed", "tag": format!("{}-in", p.name), "listen": "127.0.0.1", "listen_port": p.listen_port()})
    }));
    root.insert("inbounds".into(), json!(inbounds));
    root.insert("outbounds".into(), json!(outbounds));
    root.insert("route".into(), Value::Object(route));
    if !i.clash.is_empty() {
        root.insert(
            "experimental".into(),
            json!({"clash_api": {"external_controller": i.clash, "secret": i.secret}}),
        );
    }
    Value::Object(root)
}

/// Main's rules with the named ports' rules inserted — pure insertions, so
/// main's rules are the same list, in the same order, with or without ports.
///
/// Every port shares every rule and differs only in what none matched. A port
/// whose catch-all is escape hands an unmatched NAME to the far end, so its
/// catch-all must come BEFORE the resolve rule (past it, the name would already
/// have been looked up at dns-direct), with the address rules after the resolve
/// repeated for it just above, since its connections to an IP still need them.
/// With no resolve rule its catch-all simply goes last. A direct or corp
/// catch-all shares the lookup and goes last, where main's final applies.
fn port_rules(rules: Vec<Value>, i: &HostInput) -> Vec<Value> {
    let inbound = |n: &str| json!([format!("{n}-in")]);
    let tun = i.ports.iter().filter(|p| p.fin == "escape");
    let mut out = match rules.iter().position(|r| r.get("action") == Some(&json!("resolve"))) {
        None => {
            let mut out = rules;
            out.extend(tun.map(|p| json!({"inbound": inbound(&p.name), "outbound": i.escape_outbound})));
            out
        }
        Some(ri) => {
            let mut out = rules[..ri].to_vec();
            for p in tun {
                if !i.lists.corp_cidrs.is_empty() {
                    out.push(json!({"inbound": inbound(&p.name), "ip_cidr": i.lists.corp_cidrs, "outbound": "corp"}));
                }
                if i.private_default == "corp" {
                    out.push(json!({"inbound": inbound(&p.name), "ip_cidr": i.private_cidrs, "outbound": "corp"}));
                }
                out.push(json!({"inbound": inbound(&p.name), "outbound": i.escape_outbound}));
            }
            out.extend_from_slice(&rules[ri..]);
            out
        }
    };
    out.extend(
        i.ports.iter().filter(|p| p.fin != "escape")
            .map(|p| json!({"inbound": inbound(&p.name), "outbound": p.fin})),
    );
    out
}

/// The VM guest configuration — everything it receives is escape traffic.
pub fn render_vm(escapes: &Value, listen: &str, port: u64, clash: &str, secret: &str, log_level: &str) -> Value {
    let mut outbounds = escapes.as_array().cloned().unwrap_or_default();
    outbounds.push(json!({"type": "direct", "tag": "direct"}));
    outbounds.push(json!({"type": "block", "tag": "block"}));

    let mut root = Map::new();
    root.insert("log".into(), json!({"level": log_level, "timestamp": true}));
    root.insert("dns".into(), json!({"servers": [{"type": "local", "tag": "local"}]}));
    root.insert(
        "inbounds".into(),
        json!([{"type": "mixed", "tag": "in", "listen": listen, "listen_port": port}]),
    );
    root.insert("outbounds".into(), json!(outbounds));
    root.insert(
        "route".into(),
        json!({
            "rules": [{"action": "sniff"}], "final": "escape",
            "auto_detect_interface": true, "default_domain_resolver": "local"
        }),
    );
    if !clash.is_empty() {
        root.insert(
            "experimental".into(),
            json!({"clash_api": {"external_controller": clash, "secret": secret}}),
        );
    }
    Value::Object(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env knob wins, then the saved `--every`, then 20m — and an EMPTY
    /// env value counts as unset, as `${ROWT_AUTO_INTERVAL:-}` does.
    #[test]
    fn the_auto_interval_prefers_env_then_state_then_the_default() {
        assert_eq!(auto_interval(Some("90s"), "3m"), "90s");
        assert_eq!(auto_interval(Some(""), "3m"), "3m");
        assert_eq!(auto_interval(None, "3m"), "3m");
        assert_eq!(auto_interval(None, ""), "20m");
    }

    #[test]
    fn durations_read_the_way_go_writes_them() {
        assert_eq!(duration_secs("3m"), Some(180));
        assert_eq!(duration_secs("90s"), Some(90));
        assert_eq!(duration_secs("1m30s"), Some(90));
        assert_eq!(duration_secs("1h"), Some(3600));
        for bad in ["", "3", "m", "3x", "1.5m", "-3m", "3m ", " 3m", "3M"] {
            assert_eq!(duration_secs(bad), None, "{bad:?}");
        }
    }

    fn auto(interval: &str) -> UrlTest {
        UrlTest::new(interval.to_string(), None, None)
    }

    #[test]
    fn the_urltest_carries_the_interval_it_is_given() {
        let servers = vec![json!({"type": "vless", "tag": "a", "server": "192.0.2.1", "server_port": 443})];
        let g = group(&servers, "", "auto", &auto("3m"));
        assert_eq!(g[1]["type"], "urltest");
        assert_eq!(g[1]["interval"], "3m");
        assert_eq!(g[1]["tolerance"], 100);
        assert!(g[1].get("interrupt_exist_connections").is_none(), "interrupting is opt-in");
    }

    #[test]
    fn tolerance_and_interrupt_come_from_their_knobs() {
        let servers = vec![json!({"type": "vless", "tag": "a", "server": "192.0.2.1", "server_port": 443})];
        let g = group(&servers, "", "auto", &UrlTest::new("20m".into(), Some("250"), Some("1")));
        assert_eq!(g[1]["tolerance"], 250);
        assert_eq!(g[1]["interrupt_exist_connections"], true);
        let keys: Vec<&String> = g[1].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["type", "tag", "outbounds", "url", "interval", "tolerance", "interrupt_exist_connections"],
                   "the shell's key order");
        assert!(UrlTest::new("20m".into(), None, Some("yes")) == auto("20m"), "only 1 turns it on");
        for (raw, want) in [(None, Some(100)), (Some(""), Some(100)), (Some("0"), Some(0)), (Some("007"), Some(7)),
                            (Some("99999"), Some(99999)), (Some("100000"), None), (Some("1e3"), None),
                            (Some("-5"), None), (Some(" 50"), None)] {
            assert_eq!(auto_tolerance(raw), want, "{raw:?}");
        }
    }

    #[test]
    fn list_parsing_matches_the_shell_pipeline() {
        let src = "# comment\n\nexample.com\n   spaced.example.org\ngeosite:google\n10.0.0.0/8\n  \n";
        assert_eq!(
            parse_list(src, Filter::Domain),
            vec!["example.com", "spaced.example.org"]
        );
        assert_eq!(parse_list(src, Filter::Cidr), vec!["10.0.0.0/8"]);
        assert_eq!(parse_list(src, Filter::All).len(), 3);
    }

    #[test]
    fn a_line_of_only_whitespace_is_dropped_not_emptied() {
        assert!(parse_list("   \n\t\n", Filter::All).is_empty());
    }

    /// A `*.z.com` on disk — written by an older rowt, or by hand from the
    /// docs — is read as the dot-led `.z.com` that sing-box can match. An exact
    /// `domain:*.z.com` is not a suffix and is left alone, and so are the shapes
    /// with nothing to anchor on.
    #[test]
    fn a_wildcard_entry_reads_as_its_dot_led_form() {
        let src = "*.wild.example\n  *.Spaced.example \n.dot.example\ndomain:*.exact.example\n*.\n*\na.*.example\n";
        assert_eq!(parse_list(src, Filter::Domain),
                   [".wild.example", ".Spaced.example", ".dot.example", "*.", "*", "a.*.example"]);
        assert_eq!(parse_list(src, Filter::Exact), ["*.exact.example"]);
        assert_eq!(unwildcard("*.z.com"), ".z.com");
        assert_eq!(unwildcard(".z.com"), ".z.com");
        assert_eq!(unwildcard("z.com"), "z.com");
    }

    #[test]
    fn geosite_lines_keep_file_order_and_duplicates() {
        let src = "geosite:google\nexample.com\ngeosite:apple\ngeosite:google\n";
        assert_eq!(geosites_of(src), vec!["google", "apple", "google"]);
    }

    #[test]
    fn suffix_rules_are_most_specific_first() {
        let lists = Lists {
            escape_domains: vec!["api.foo.com".into(), "z.com".into()],
            block_domains: vec!["foo.com".into()],
            ..Default::default()
        };
        let got: Vec<String> = suffix_rules(&lists, "escape")
            .iter()
            .map(|r| r["domain_suffix"][0].as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, vec!["api.foo.com", "foo.com", "z.com"]);
    }

    #[test]
    fn ties_resolve_escape_then_corp_then_block() {
        // Same label count and length in all three lanes: jq sorts stably and
        // then reverses the whole array, which flips the lane order.
        let lists = Lists {
            escape_domains: vec!["aaa.com".into()],
            corp_domains: vec!["bbb.com".into()],
            block_domains: vec!["ccc.com".into()],
            ..Default::default()
        };
        let got: Vec<String> = suffix_rules(&lists, "escape")
            .iter()
            .map(|r| r["outbound"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, vec!["escape", "corp", "block"]);
    }

    #[test]
    fn local_mode_retargets_escape_but_keeps_precedence() {
        // The rule for api.foo.com must still come first — dropping it would let
        // block's foo.com swallow the domain instead of sending it direct.
        let lists = Lists {
            escape_domains: vec!["api.foo.com".into()],
            block_domains: vec!["foo.com".into()],
            ..Default::default()
        };
        let r = suffix_rules(&lists, "direct");
        assert_eq!(r[0]["domain_suffix"][0], json!("api.foo.com"));
        assert_eq!(r[0]["outbound"], json!("direct"));
        assert_eq!(r[1]["outbound"], json!("block"));
    }

    #[test]
    fn selector_falls_back_when_the_selection_is_unknown() {
        let servers = vec![json!({"tag": "alpha"}), json!({"tag": "beta"})];
        let g = group(&servers, "en0", "ghost", &auto("20m"));
        let sel = g.as_array().unwrap().last().unwrap();
        assert_eq!(sel["default"], json!("alpha"));
        assert_eq!(g[0]["bind_interface"], json!("en0"));
    }

    #[test]
    fn an_empty_server_list_selects_block() {
        let g = group(&[], "en0", "ghost", &auto("20m"));
        assert_eq!(g.as_array().unwrap().last().unwrap()["default"], json!("block"));
    }

    /// The load-bearing exclusion: a `domain:` line has no `/N`, so it passes
    /// the "isn't a CIDR" test every other filter selects on. If it leaked
    /// through it would render as a `domain_suffix` — the exact leak the flag
    /// exists to prevent, and silent.
    #[test]
    fn exact_entries_never_leak_into_the_suffix_filters() {
        let src = "z.com\ndomain:host.z.com\n10.0.0.0/8\ngeosite:google\n";
        assert_eq!(parse_list(src, Filter::Domain), ["z.com"]);
        assert_eq!(parse_list(src, Filter::All), ["z.com", "10.0.0.0/8"]);
        assert_eq!(parse_list(src, Filter::Cidr), ["10.0.0.0/8"]);
        assert_eq!(parse_list(src, Filter::Exact), ["host.z.com"]);
        // A lane of nothing but exact entries renders NO suffix rules at all.
        let only = "domain:a.com\ndomain:b.com\n";
        assert!(parse_list(only, Filter::Domain).is_empty());
        assert_eq!(parse_list(only, Filter::Exact), ["a.com", "b.com"]);
    }

    #[test]
    fn exact_rules_are_emitted_before_every_suffix_rule() {
        let lists = Lists {
            escape_domains: vec!["z.com".into()],
            block_exact: vec!["z.com".into()],
            ..Default::default()
        };
        let r = [exact_rules(&lists, "escape"), suffix_rules(&lists, "escape")].concat();
        // First-match-wins: without this order the block exact would lose to the
        // escape suffix and `--domain` would silently do nothing.
        assert_eq!(r[0], json!({"domain": ["z.com"], "outbound": "block"}));
        assert_eq!(r[1], json!({"domain_suffix": ["z.com"], "outbound": "escape"}));
    }

    #[test]
    fn a_suffix_only_config_renders_exactly_as_before() {
        // The feature must be inert when unused — no empty `domain` rule, no
        // second dns rule — or every existing render diffs.
        let lists = Lists { corp_domains: vec!["corp.example".into()], ..Default::default() };
        assert!(exact_rules(&lists, "escape").is_empty());
    }
}
