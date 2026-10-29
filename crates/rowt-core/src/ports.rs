//! Named extra ports (`rowt port add <N> <name> [--final …]`), read as the shell
//! reads them.
//!
//! `ports.tsv` is a table — name, port, catch-all — of loopback mixed inbounds
//! that run main's rules and differ only in where traffic NO rule matched goes.
//! These are the shell's `_ports_rows`, `_port_dest` and `_port_rendered`; the
//! render's half lives in `render::render_host`.

use serde_json::Value;

/// One row of `ports.tsv`. The port stays as written: `status` and `explain`
/// print it from the file, and compare it with the rendered inbound as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub port: String,
    pub fin: String,
}

impl Port {
    /// The `listen_port` the render writes: jq's `tonumber` of the field.
    pub fn listen_port(&self) -> Value {
        match self.port.parse::<u64>() {
            Ok(n) => Value::from(n),
            Err(_) => self.port.parse::<f64>().map(Value::from).unwrap_or(Value::Null),
        }
    }
}

/// `_ports_rows`: the lines with three tab fields, an all-digit port and a
/// catch-all of escape, direct or corp, only the first of them per port in
/// FILE order (`awk '… && !seen[$2]++'`), then sorted as `LC_ALL=C sort` sorts
/// them (the whole line, byte by byte). A row a hand edit broke is skipped
/// rather than failing every render.
pub fn rows(contents: &str) -> Vec<Port> {
    let mut seen = std::collections::HashSet::new();
    let mut lines: Vec<&str> = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            // awk's NF is 0 for an empty line, however it splits. `seen` is
            // last, as in the awk, so only a row that passed the rest claims
            // its port — and awk compares the field as a string: 07892 and
            // 7892 are two ports to it.
            !l.is_empty()
                && f.len() == 3
                && !f[1].is_empty()
                && f[1].bytes().all(|b| b.is_ascii_digit())
                && matches!(f[2], "escape" | "direct" | "corp")
                && seen.insert(f[1])
        })
        .collect();
    lines.sort_unstable();
    lines
        .into_iter()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Port { name: f[0].to_string(), port: f[1].to_string(), fin: f[2].to_string() }
        })
        .collect()
}

/// The catch-all as `status` prints it: the word in the table, which a script
/// can grep for, and what it means here when that differs (`_port_catchall`
/// without its far-end phrase).
pub fn status_word(fin: &str, local: bool) -> String {
    if fin == "escape" && local { "escape (direct in local mode)".into() } else { fin.to_string() }
}

/// `_port_dest`: where a port's catch-all really sends traffic — escape is
/// direct in local mode, where no tunnel exists.
pub fn dest(fin: &str, local: bool) -> &str {
    if fin == "escape" && local { "direct" } else { fin }
}

/// `_port_rendered`: (name, port) for every named inbound the rendered
/// `host.json` carries — the table may be ahead of it until the next render.
/// Nothing when the file is missing or unreadable.
pub fn rendered(host_json: &str) -> Vec<(String, String)> {
    let v: Value = match serde_json::from_str(host_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    v["inbounds"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|ib| {
                    let tag = ib["tag"].as_str()?;
                    let name = tag.strip_suffix("-in").filter(|_| tag != "in")?;
                    let port = match &ib["listen_port"] {
                        Value::String(s) => s.clone(),
                        Value::Null => "null".to_string(),
                        other => other.to_string(),
                    };
                    Some((name.to_string(), port))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_skip_broken_lines_and_sort_like_c_sort() {
        let t = "# rowt: named extra ports\nvm\t7893\tcorp\nguest\t7892\tescape\nbad\tx\tescape\nshort\t1\n\nguest-2\t7894\tdirect\n";
        let r = rows(t);
        let names: Vec<&str> = r.iter().map(|p| p.name.as_str()).collect();
        // "guest\t…" sorts before "guest-2\t…": a tab is below '-'.
        assert_eq!(names, ["guest", "guest-2", "vm"]);
        assert_eq!(r[0], Port { name: "guest".into(), port: "7892".into(), fin: "escape".into() });
    }

    #[test]
    fn rows_drop_a_bad_catch_all_and_a_port_used_twice() {
        let t = "zz\t7892\tdirect\nguest\t7892\tescape\nweird\t7897\tblock\nok\t7897\tcorp\nlab\t7893\tcorp\n";
        let names: Vec<String> = rows(t).into_iter().map(|p| p.name).collect();
        // zz comes first in the file, so it keeps 7892 although guest sorts
        // first; weird's block is no catch-all, so it never claimed 7897.
        assert_eq!(names, ["lab", "ok", "zz"]);
    }

    #[test]
    fn status_says_what_escape_means_in_local_mode() {
        assert_eq!(status_word("escape", false), "escape");
        assert_eq!(status_word("escape", true), "escape (direct in local mode)");
        assert_eq!(status_word("corp", true), "corp");
    }

    #[test]
    fn rows_of_nothing() {
        assert!(rows("").is_empty());
        assert!(rows("# rowt: header only\n").is_empty());
    }

    #[test]
    fn escape_is_direct_in_local_mode() {
        assert_eq!(dest("escape", true), "direct");
        assert_eq!(dest("escape", false), "escape");
        assert_eq!(dest("corp", true), "corp");
    }

    #[test]
    fn rendered_lists_named_inbounds_only() {
        let h = r#"{"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":7890},
                    {"type":"mixed","tag":"guest-in","listen":"127.0.0.1","listen_port":7892}]}"#;
        assert_eq!(rendered(h), [("guest".to_string(), "7892".to_string())]);
        assert!(rendered("").is_empty());
        assert!(rendered("not json").is_empty());
    }

    #[test]
    fn listen_port_is_a_number() {
        let p = Port { name: "g".into(), port: "07892".into(), fin: "escape".into() };
        assert_eq!(p.listen_port(), serde_json::json!(7892));
    }
}
