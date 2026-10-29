#!/usr/bin/env bash
# Named ports (rowt port add | rm | list) — render snapshot test.
#
#   tests/ports.sh bin/rowt [<baseline bin/rowt>]
#
# Sandboxed: HOME / XDG_CONFIG_HOME point at a scratch tree, fake servers
# (documentation names and addresses, a dummy uuid), no router is started and
# nothing outside the scratch tree is written. Needs jq >= 1.7 and a sing-box
# 1.13.x for this OS (SB=…, default ../tools/sing-box if present, else the one
# on PATH). ROWT_IFACE defaults to en0 on macOS, eth0 elsewhere.
#
# Checks, in modes host (auto + manual), vm and local:
#   - no named ports renders byte-identical to the baseline rowt (when given)
#   - a port with --final escape adds exactly: inbound <name>-in (127.0.0.1:<port>)
#     and its rules — one catch-all {inbound:[<name>-in], outbound:escape|direct};
#     with a `resolve` rule in the render that catch-all sits right before the
#     resolve, after <name>-in copies of the corp/private IP rules; without one
#     it is simply last. Everything else in host.json — the main inbound, every
#     other rule in order, dns, outbounds — is byte-equal
#   - a port with --final corp adds its inbound and ONE rule, last
#   - every render passes `sing-box check`
#   - rm of the last port removes the table and renders exactly as before
# and the CLI: refusals, list, status, explain, audit, help, completion.
set -uo pipefail
NEW="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OLD="${2:-}"; [ -n "$OLD" ] && OLD="$(cd "$(dirname "$OLD")" && pwd)/$(basename "$OLD")"
HERE_T="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${SB:-}" ]; then
  if [ -x "$HERE_T/../tools/sing-box" ]; then SB="$HERE_T/../tools/sing-box"; else SB="$(command -v sing-box)"; fi
fi
[ -x "$SB" ] || { echo "no sing-box (set SB=)"; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/rowt-ports.XXXXXX")"
trap 'rm -rf "$T"' EXIT
pass=0 fail=0
ok()  { pass=$((pass+1)); echo "  ok   $*"; }
bad() { fail=$((fail+1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

_ifc=eth0; [ "$(uname)" = Darwin ] && _ifc=en0
export HOME="$T/home" XDG_CONFIG_HOME="$T/xdg" ROWT_IFACE="${ROWT_IFACE:-$_ifc}"
[ -d "$HERE_T/../tools/shim" ] && export PATH="$HERE_T/../tools/shim:$HERE_T/../tools/jqbin:$PATH"
CFG="$XDG_CONFIG_HOME/rowt"
mkdir -p "$HOME" "$CFG/bin" "$CFG/log"
cp "$SB" "$CFG/bin/sing-box"; chmod +x "$CFG/bin/sing-box"
cat > "$CFG/servers.json" <<'J'
[{"type":"vless","tag":"srv-a","server":"vps.example.com","server_port":443,
  "uuid":"00000000-0000-4000-8000-000000000000","flow":"xtls-rprx-vision",
  "tls":{"enabled":true,"server_name":"vps.example.com","utls":{"enabled":true,"fingerprint":"chrome"}}},
 {"type":"vless","tag":"srv-b","server":"192.0.2.10","server_port":443,
  "uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"vps2.example.com"}}]
J
cp "$CFG/servers.json" "$CFG/manual.json"; chmod 600 "$CFG"/*.json
printf 'mode=host\nselected=auto\nclash_secret=testsecret0000000000000\n' > "$CFG/state"
# lanes: templates + a corp CIDR, so the IP-range rules are part of the snapshot
"$NEW" version >/dev/null 2>&1   # seeds the lane lists
echo "10.200.0.0/16" >> "$CFG/corp-domains.txt"
echo "intranet.corp.example" >> "$CFG/corp-domains.txt"

R()  { "$NEW" "$@"; }
st() { sed -n "s/^$1=//p" "$CFG/state" | tail -1; }
stset() { { grep -v "^$1=" "$CFG/state"; echo "$1=$2"; } > "$CFG/state.n"; mv "$CFG/state.n" "$CFG/state"; }
tsv() { [ -f "$CFG/ports.tsv" ] && awk -F'\t' -v n="$1" '!/^#/ && $1 == n' "$CFG/ports.tsv" | tr '\t' ' '; }
H="$CFG/host.json"
strip_port() { # $1=name: the render without that port's inbound and rules
  jq -S --arg t "$1-in" 'del(.inbounds[] | select(.tag == $t)) | .route.rules |= map(select(((.inbound // []) | index($t)) | not))' "$2"
}
rm_all() { R port rm guest >/dev/null 2>&1; R port rm lab >/dev/null 2>&1; R port rm plain >/dev/null 2>&1; }

run_mode() { # $1=label  $2=where an escape catch-all goes in this mode
  local m="$1" esc="$2"
  echo "== $m"
  rm_all
  R render >/dev/null 2>"$T/err" || { bad "$m: render (no ports): $(tail -2 "$T/err")"; return; }
  cp "$H" "$T/$m-none.json"
  if [ -n "$OLD" ]; then
    "$OLD" render >/dev/null 2>&1 && cp "$H" "$T/$m-base.json"
    check "$m: no ports == baseline byte for byte" "cmp -s '$T/$m-none.json' '$T/$m-base.json'"
    R render >/dev/null 2>&1
  fi
  R port add 7892 guest --final escape >"$T/add.out" 2>&1 || { bad "$m: port add guest: $(cat "$T/add.out")"; return; }
  cp "$H" "$T/$m-guest.json"
  check "$m: table row guest 7892 escape" "[ \"\$(tsv guest)\" = 'guest 7892 escape' ]"
  check "$m: sing-box check (no ports)" "'$CFG/bin/sing-box' check -c '$T/$m-none.json'"
  check "$m: sing-box check (guest)"    "'$CFG/bin/sing-box' check -c '$T/$m-guest.json'"
  check "$m: guest minus its bits == no ports (jq -S)" "diff <(strip_port guest '$T/$m-guest.json') <(jq -S . '$T/$m-none.json') >/dev/null"
  check "$m: main inbound unchanged and first" "[ \"\$(jq -c '.inbounds[0]' '$T/$m-guest.json')\" = \"\$(jq -c '.inbounds[0]' '$T/$m-none.json')\" ]"
  check "$m: 2 inbounds with guest, 1 without" "[ \"\$(jq '.inbounds|length' '$T/$m-guest.json')/\$(jq '.inbounds|length' '$T/$m-none.json')\" = 2/1 ]"
  check "$m: guest-in = mixed 127.0.0.1:7892" "[ \"\$(jq -c '.inbounds[1]' '$T/$m-guest.json')\" = '{\"type\":\"mixed\",\"tag\":\"guest-in\",\"listen\":\"127.0.0.1\",\"listen_port\":7892}' ]"
  check "$m: existing rules unchanged, in order" "[ \"\$(jq -c '[.route.rules[] | select(.inbound == null)]' '$T/$m-guest.json')\" = \"\$(jq -c '.route.rules' '$T/$m-none.json')\" ]"
  check "$m: one catch-all {inbound:[guest-in], outbound:$esc}" "[ \"\$(jq -c '[.route.rules[] | select(. == {inbound:[\"guest-in\"], outbound:\"$esc\"})] | length' '$T/$m-guest.json')\" = 1 ]"
  local pos; pos="$(jq -r '.route.rules | (map((keys == ["inbound","outbound"]) and .inbound == ["guest-in"]) | index(true)) as $g | (map(.action == "resolve") | index(true)) as $r | if $r == null then (if $g == length-1 then "last" else "BAD \($g)" end) else (if $g == $r-1 then "before-resolve" else "BAD \($g)/\($r)" end) end' "$T/$m-guest.json")"
  check "$m: escape catch-all position ($pos)" "case '$pos' in last|before-resolve) true ;; *) false ;; esac"
  if [ "$pos" = before-resolve ]; then
    check "$m: guest-in copies of the IP rules just before its catch-all" "[ \"\$(jq -c '[.route.rules[] | select(.inbound == [\"guest-in\"] and .ip_cidr != null) | del(.inbound)]' '$T/$m-guest.json')\" = \"\$(jq -c '[.route.rules[] | select(.inbound == null and .ip_cidr != null)]' '$T/$m-guest.json')\" ]"
    check "$m: nothing after the resolve rule is guest-only" "jq -e '.route.rules | (map(.action == \"resolve\") | index(true)) as \$r | .[\$r:] | all(.inbound == null)' '$T/$m-guest.json' >/dev/null"
  else
    check "$m: no range copies without a resolve rule" "[ \"\$(jq '[.route.rules[] | select(.inbound == [\"guest-in\"])] | length' '$T/$m-guest.json')\" = 1 ]"
  fi
  check "$m: final unchanged" "[ \"\$(jq -r .route.final '$T/$m-guest.json')\" = \"\$(jq -r .route.final '$T/$m-none.json')\" ]"
  check "$m: dns block unchanged" "[ \"\$(jq -c .dns '$T/$m-guest.json')\" = \"\$(jq -c .dns '$T/$m-none.json')\" ]"
  check "$m: same resolve rules as without (none added)" "[ \"\$(jq -c '[.route.rules[] | select(.action == \"resolve\")]' '$T/$m-guest.json')\" = \"\$(jq -c '[.route.rules[] | select(.action == \"resolve\")]' '$T/$m-none.json')\" ]"
  check "$m: the catch-all outbound exists" "jq -e --arg o '$esc' 'any(.outbounds[]; .tag == \$o)' '$T/$m-guest.json' >/dev/null"
  check "$m: list prints the stored catch-all word" "R port list 2>/dev/null | grep -q '^guest  *127.0.0.1:7892  *unmatched -> escape'"
  # a second port whose catch-all is corp: one rule, last, after the lookup
  R port add 7893 lab --final corp >"$T/add2.out" 2>&1 || { bad "$m: port add lab: $(cat "$T/add2.out")"; return; }
  cp "$H" "$T/$m-two.json"
  check "$m: sing-box check (two ports)" "'$CFG/bin/sing-box' check -c '$T/$m-two.json'"
  check "$m: 3 inbounds, lab-in on 7893 last" "[ \"\$(jq -c '.inbounds | length, .[2]' '$T/$m-two.json' | tr '\n' ' ')\" = '3 {\"type\":\"mixed\",\"tag\":\"lab-in\",\"listen\":\"127.0.0.1\",\"listen_port\":7893} ' ]"
  check "$m: lab's catch-all is the LAST rule and its only rule" "[ \"\$(jq -c '.route.rules[-1]' '$T/$m-two.json')\" = '{\"inbound\":[\"lab-in\"],\"outbound\":\"corp\"}' ] && [ \"\$(jq '[.route.rules[] | select(.inbound == [\"lab-in\"])] | length' '$T/$m-two.json')\" = 1 ]"
  check "$m: two ports minus lab == guest alone (jq -S)" "diff <(strip_port lab '$T/$m-two.json') <(jq -S . '$T/$m-guest.json') >/dev/null"
  rm_all
  check "$m: rm both -> table gone, render == no ports byte for byte" "[ ! -f '$CFG/ports.tsv' ] && cmp -s '$H' '$T/$m-none.json'"
}

run_mode host-auto escape
stset selected srv-a; run_mode host-manual escape
stset selected auto
stset mode vm; stset vm_ip 192.0.2.50; run_mode vm escape
stset mode local; run_mode local direct
stset mode host

echo "== CLI"
rm_all
R port list > "$T/l0.out" 2>&1
check "list, no ports: the main row and a hint" "grep -q '^main  *127.0.0.1:7890  *unmatched -> direct (the system proxy port)' '$T/l0.out' && grep -q 'no named ports' '$T/l0.out'"
R port add 7893 guest --final escape >/dev/null 2>&1
check "add: stored and rendered" "[ \"\$(tsv guest | cut -d' ' -f2)/\$(jq '.inbounds[1].listen_port' '$H')\" = 7893/7893 ]"
check "--final=corp form" "R port add 7894 lab --final=corp >/dev/null 2>&1 && [ \"\$(tsv lab)\" = 'lab 7894 corp' ]"
check "no --final: main's catch-all (direct)" "R port add 7895 plain >/dev/null 2>&1 && [ \"\$(tsv plain)\" = 'plain 7895 direct' ]"
check "rows sorted by name" "[ \"\$(grep -v '^#' '$CFG/ports.tsv' | cut -f1 | tr '\n' ' ')\" = 'guest lab plain ' ]"
for p in 7890 7891 9090 9091 0 80 1023 70000 abc; do
  check "refuses port $p (table untouched)" "! R port add $p x$p >/dev/null 2>&1 && [ -z \"\$(tsv x$p)\" ]"
done
# a port something else holds: a listener of this test's own, which lsof sees
python3 -c 'import socket,sys,time; s=socket.socket(); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); time.sleep(30)' 17899 >/dev/null 2>&1 &
lpid=$!; sleep 0.5
check "refuses a port another process listens on" "! R port add 17899 busy >'$T/busy.out' 2>&1 && grep -q 'already in use' '$T/busy.out' && [ -z \"\$(tsv busy)\" ]"
kill $lpid 2>/dev/null; wait $lpid 2>/dev/null
check "refuses a port already named" "! R port add 7893 other >/dev/null 2>&1 && [ -z \"\$(tsv other)\" ]"
check "refuses a name already used" "! R port add 7896 guest >/dev/null 2>&1 && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
check "identical re-add is a no-op, rc 0" "R port add 7893 guest --final escape >'$T/re.out' 2>&1 && grep -q 'already 127.0.0.1:7893' '$T/re.out' && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
check "re-add with another catch-all is refused" "! R port add 7893 guest --final corp >/dev/null 2>&1 && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
check "re-add with another port is refused" "! R port add 7897 guest --final escape >/dev/null 2>&1 && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
# a render that fails for an unrelated reason: nothing lost, nothing gained
check "identical re-add with a failing render keeps the row" "! ROWT_AUTO_TOLERANCE=abc R port add 7893 guest --final escape >/dev/null 2>&1 && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
check "new add with a failing render adds nothing" "! ROWT_AUTO_TOLERANCE=abc R port add 7897 fail --final escape >/dev/null 2>&1 && [ -z \"\$(tsv fail)\" ] && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
check "rm with a failing render keeps the row" "! ROWT_AUTO_TOLERANCE=abc R port rm guest >/dev/null 2>&1 && [ \"\$(tsv guest)\" = 'guest 7893 escape' ]"
for n in main escape corp block direct hotspot Guest a_b 'a b' abcdefghijklmnopqrstuvwxyz0123456789; do
  check "refuses the name '$n'" "! R port add 7896 '$n' >/dev/null 2>&1 && [ ! -f '$H.bad' ]"
done
check "refuses --final foo" "! R port add 7896 foo --final foo >/dev/null 2>&1 && [ -z \"\$(tsv foo)\" ]"
check "refuses an unknown argument" "! R port add 7896 foo --bogus >/dev/null 2>&1 && [ -z \"\$(tsv foo)\" ]"
check "rm of an unknown name is a no-op, exit 0" "R port rm nope >'$T/rmno.out' 2>&1 && grep -q 'nothing to remove' '$T/rmno.out'"
check "rm main refused" "! R port rm main >/dev/null 2>&1"
R port list > "$T/l1.out" 2>&1
check "list: main first, then the rows with their catch-alls" "[ \"\$(grep -c . '$T/l1.out')\" = 4 ] && grep -q '^guest  *127.0.0.1:7893  *unmatched -> escape, names resolved at the far end' '$T/l1.out' && grep -q '^lab  *127.0.0.1:7894  *unmatched -> corp' '$T/l1.out' && grep -q '^plain  *127.0.0.1:7895  *unmatched -> direct' '$T/l1.out'"
R status > "$T/s.out" 2>&1
check "status: one line per named port" "grep -q '^port guest:   127.0.0.1:7893, unmatched -> escape (main unmatched -> direct)\$' '$T/s.out' && grep -q '^port lab:     127.0.0.1:7894, unmatched -> corp (main unmatched -> direct)\$' '$T/s.out' && grep -q '^port plain:   127.0.0.1:7895, unmatched -> direct (main unmatched -> direct)\$' '$T/s.out'"
R explain nothing.invalid > "$T/x1.out" 2>&1
check "explain unmatched name: escape port tunnels it, far-end note" "grep -q '^  guest:   via 127.0.0.1:7893 -> ESCAPE (no rule matched; this port.s catch-all, the name resolved at the far end)\$' '$T/x1.out'"
check "explain unmatched name: corp port line, no far-end note" "grep -q '^  lab:     via 127.0.0.1:7894 -> CORP (no rule matched; this port.s catch-all)\$' '$T/x1.out'"
check "explain unmatched name: a port with main's catch-all prints nothing" "! grep -q '^  plain:' '$T/x1.out'"
R explain intranet.corp.example > "$T/x2.out" 2>&1
check "explain a corp name: no port lines (a rule matched)" "! grep -q 'via 127.0.0.1:789' '$T/x2.out'"
R explain 10.200.1.1 > "$T/x3.out" 2>&1
check "explain a corp CIDR address: no port lines" "! grep -q 'via 127.0.0.1:789' '$T/x3.out'"
R explain 198.51.100.7 > "$T/x4.out" 2>&1
check "explain an unmatched address: escape and corp ports, no far-end note" "grep -q '^  guest:   via 127.0.0.1:7893 -> ESCAPE (no rule matched; this port.s catch-all)\$' '$T/x4.out' && grep -q '^  lab:     via 127.0.0.1:7894 -> CORP (no rule matched; this port.s catch-all)\$' '$T/x4.out' && ! grep -q '^  plain:' '$T/x4.out'"
# a hand-edited table: a bad catch-all and a second name on a used port are skipped, and list says so
# (aaa sorts before guest: the row already in the file must still win)
printf 'zed\t7898\tbogus\naaa\t7893\tcorp\n' >> "$CFG/ports.tsv"
R port list > "$T/lh.out" 2>&1
check "hand edit: bad rows skipped, list warns, the existing row keeps its port" "grep -q '2 line(s) in .*skipped' '$T/lh.out' && ! grep -q '^zed\|^aaa' '$T/lh.out' && grep -q '^guest  *127.0.0.1:7893' '$T/lh.out'"
R render >/dev/null 2>&1
check "hand edit: render ignores the skipped rows" "[ \"\$(jq '.inbounds|length' '$H')\" = 4 ] && ! jq -e '.inbounds[] | select(.tag == \"zed-in\" or .tag == \"aaa-in\")' '$H' >/dev/null && jq -e '.inbounds[] | select(.tag == \"guest-in\" and .listen_port == 7893)' '$H' >/dev/null"
grep -v '^zed\|^aaa' "$CFG/ports.tsv" > "$CFG/ports.tsv.n" && mv "$CFG/ports.tsv.n" "$CFG/ports.tsv"
R port rm lab >/dev/null 2>&1; R port rm plain >/dev/null 2>&1
check "rm one: the others stay" "[ \"\$(tsv guest)\" = 'guest 7893 escape' ] && [ -z \"\$(tsv lab)\" ] && [ \"\$(jq '.inbounds|length' '$H')\" = 2 ]"
R port rm guest >/dev/null 2>&1
check "rm the last: table gone" "[ ! -f '$CFG/ports.tsv' ]"
check "rm the last: host.json == the host-auto no-ports snapshot" "cmp -s '$H' '$T/host-auto-none.json'"
R status > "$T/s2.out" 2>&1
check "status: no port line without named ports" "! grep -q '^port ' '$T/s2.out'"
R explain nothing.invalid > "$T/x5.out" 2>&1
check "explain: no port line without named ports" "! grep -q 'via 127.0.0.1:789' '$T/x5.out'"
check "audit log records port add / rm" "grep -q 'BEGIN port add' '$CFG/log/audit.log' && grep -q 'BEGIN port rm' '$CFG/log/audit.log'"
check "port list is not audited" "! grep -q 'BEGIN port list' '$CFG/log/audit.log'"
R help port > "$T/h.out" 2>&1
check "help port" "grep -q 'named extra ports' '$T/h.out'"
check "completion offers add/rm/list only" "[ \"\$(R _complete port | cut -f1 | tr '\n' ' ')\" = 'add rm list ' ]"

echo "== apply (real engine)"
# A sing-box of its own on private ports, started as rowt starts the router
# (HUP ignored at exec, pid in host.pid), so add/rm's in-place reload is the
# real thing: the port opens or closes under the same pid, an identical re-add
# reloads nothing, and a port the router already serves from an older config
# (the upgrade from the fork) is re-added, not refused, and gets the new config.
E="$T/eng"; ECFG="$E/rowt"; mkdir -p "$ECFG/bin" "$ECFG/log"; cp "$SB" "$ECFG/bin/sing-box"
cp "$CFG/servers.json" "$CFG/manual.json" "$CFG/state" "$ECFG/"; for f in "$CFG"/*-domains.txt; do cp "$f" "$ECFG/"; done
chmod 600 "$ECFG"/*.json
EP=17890 EC=19090 EG=17892
RE() { XDG_CONFIG_HOME="$E" ROWT_PORT=$EP ROWT_CLASH_PORT=$EC "$NEW" "$@"; }
tsv_e() { [ -f "$ECFG/ports.tsv" ] && awk -F'\t' -v n="$1" '!/^#/ && $1 == n' "$ECFG/ports.tsv" | tr '\t' ' '; }
open_port() { ( exec 3<>"/dev/tcp/127.0.0.1/$1" ) 2>/dev/null; }
api() { curl --noproxy '*' -sS -m 2 -H "Authorization: Bearer testsecret0000000000000" "http://127.0.0.1:$EC/version" >/dev/null 2>&1; }
epid=""
stop_engine() { [ -n "$epid" ] && kill "$epid" 2>/dev/null; sleep 0.3; [ -n "$epid" ] && kill -9 "$epid" 2>/dev/null; epid=""; }
trap 'stop_engine; rm -rf "$T"' EXIT
if open_port $EP || open_port $EC || open_port $EG; then
  echo "  skip: 127.0.0.1:$EP, $EC or $EG is busy on this machine"
else
  RE render >/dev/null 2>"$T/err" || bad "engine: render: $(tail -1 "$T/err")"
  bash -c 'trap "" HUP; echo "$$" > "$1"; exec "$2" run -c "$3"' _ "$ECFG/host.pid" "$ECFG/bin/sing-box" "$ECFG/host.json" >"$E/sb.log" 2>&1 &
  sleep 0.5; epid="$(cat "$ECFG/host.pid" 2>/dev/null)"
  i=0; while [ "$i" -lt 20 ] && ! api; do sleep 0.5; i=$((i+1)); done
  check "engine: up on $EP, clash API on $EC (pid $epid)" "open_port $EP && api"
  RE port add $EG guest --final escape >"$T/e1.out" 2>&1; rc=$?
  check "engine: add reloads in place — same pid, port open (rc $rc)" "[ $rc = 0 ] && grep -q 'reloaded in place' '$T/e1.out' && open_port $EG && [ \"\$(cat '$ECFG/host.pid')\" = '$epid' ] && kill -0 $epid 2>/dev/null"
  RE port add $EG guest --final escape >"$T/e2.out" 2>&1; rc=$?
  check "engine: identical re-add — rc $rc, nothing reloaded" "[ $rc = 0 ] && grep -q 'already' '$T/e2.out' && ! grep -q 'reloaded' '$T/e2.out'"
  RE port rm guest >"$T/e3.out" 2>&1; rc=$?
  check "engine: rm reloads in place and the port closes" "[ $rc = 0 ] && grep -q 'reloaded in place' '$T/e3.out' && ! open_port $EG && kill -0 $epid 2>/dev/null"
  RE port add $EG guest --final escape >/dev/null 2>&1
  # (the file on disk must differ from the render in bytes, not just in origin:
  # the render's own level is warn, so change a field it always writes)
  rm -f "$ECFG/ports.tsv"; jq '.log.timestamp = false' "$ECFG/host.json" > "$ECFG/host.json.n" && mv "$ECFG/host.json.n" "$ECFG/host.json"
  RE port add $EG guest --final escape >"$T/e4.out" 2>&1; rc=$?
  check "engine: a port the router already serves is re-added and reloaded, not refused (rc $rc)" "[ $rc = 0 ] && grep -q 'reloaded in place' '$T/e4.out' && open_port $EG && [ \"\$(tsv_e guest)\" = 'guest $EG escape' ] && kill -0 $epid 2>/dev/null"
  RE port list >"$T/e5.out" 2>&1
  check "engine: list says listening" "grep -q '^guest .*(listening)' '$T/e5.out'"
  # the row is there but the router does not serve it (host.json stale, e.g.
  # written by hand): an identical re-add brings the port up instead of saying no change
  RE port rm guest >/dev/null 2>&1
  printf 'guest\t%s\tescape\n' "$EG" | { printf '# rowt: test\n'; cat; } > "$ECFG/ports.tsv"
  RE port add $EG guest --final escape >"$T/e7.out" 2>&1; rc=$?
  check "engine: identical re-add of a port the router lacks brings it up (rc $rc)" "[ $rc = 0 ] && grep -q 'already' '$T/e7.out' && grep -q 'reloaded in place' '$T/e7.out' && open_port $EG"
  RE status >"$T/e6.out" 2>&1
  check "engine: status shows the port" "grep -q '^port guest:   127.0.0.1:$EG, unmatched -> escape' '$T/e6.out'"
  stop_engine
fi

if [ -n "${KEEP:-}" ]; then mkdir -p "$KEEP"; cp "$T"/*.json "$T"/*.out "$E/sb.log" "$ECFG/host.json" "$KEEP"/ 2>/dev/null; fi
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
