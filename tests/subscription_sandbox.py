"""The parity sandbox, with a controllable local feed and a fake running router."""

from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[1]
PARITY = ROOT / "tests/parity"
LINK = "vless://00000000-0000-4000-8000-000000000001@node.example:443#alpha\n"


class Sandbox(AbstractContextManager):
    def __init__(self, implementation):
        self.temp = tempfile.TemporaryDirectory(prefix="rowt-sub-integration-")
        self.root = Path(self.temp.name)
        self.cfg = self.root / "home/rowt"
        self.answers = self.root / "env"
        self.shims = self.root / "shims"
        self.shims.mkdir()
        self.processes = []
        self.commands = {}
        self.implementation = implementation
        self.body = LINK
        self.requests = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.server = None
        self.server_thread = None

        for name, dest in [("config", self.cfg), ("env", self.answers)]:
            shutil.copytree(PARITY / "fixtures" / name, dest)
            shutil.copytree(
                PARITY / "fixtures/scenarios/best-tick-fresh" / name,
                dest, dirs_exist_ok=True,
            )
        (self.cfg / "host.pid.self").unlink()
        (self.cfg / "bin").mkdir()
        (self.cfg / "cache").mkdir(exist_ok=True)
        self.set_state("selected", "auto")
        # Keep optional corp-health tools and every OS mutation behind the
        # same recorder used by the existing parity tests.
        harness = (PARITY / "bin/parity").read_text()
        names = re.search(r'^SHIMS="([^"]+)"', harness, re.M).group(1).split()
        for name in names:
            (self.shims / name).symlink_to(PARITY / "shims/_recorder")
        self.env = {
            "HOME": str(self.root / "home"),
            "XDG_CONFIG_HOME": str(self.root / "home"),
            "PATH": str(self.shims) + os.pathsep + os.environ["PATH"],
            "PARITY_TRACE": str(self.root / "trace"),
            "PARITY_ENV": str(self.answers),
            "ROWT_IMPL": implementation,
            "ROWT_PY": "1",
            "ROWT_METRICS": "off",
            "ROWT_CORP_HEALTH": str(self.root / "no-corp-health"),
            "ROWT_CAPTIVE_CHECK": "0",
            "ROWT_CAPTIVE_RETRY": "",
            "ROWT_GEOSITE_BASE": "http://127.0.0.1:1",
            # A router this sandbox starts must not leave `auto`'s failover
            # follower polling after the test; tests/test_auto_follow.py turns
            # it on where it is the subject.
            "ROWT_AUTO_FOLLOW": "0",
            "TERM": "dumb", "LC_ALL": "C", "TZ": "UTC",
            "SUB_TEST_ROOT": str(self.root),
            "SUB_TEST_RECORDER": str(PARITY / "shims/_recorder"),
        }
        # Only the explicitly configured test feed may reach a real HTTP
        # client. All router, DNS and public-network requests stay recorded.
        (self.shims / "curl").unlink()
        self.executable(self.shims / "curl", r"""#!/bin/bash
last="${!#}"
if [ "$last" = "${SUB_TEST_FEED:-}" ]; then
  exec /usr/bin/curl "$@"
fi
# A fake clash API a test serves on its own port (tests/test_auto_follow.py).
if [ -n "${SUB_TEST_CLASH:-}" ]; then
  case "$last" in "http://127.0.0.1:$SUB_TEST_CLASH/"*) exec /usr/bin/curl "$@" ;; esac
fi
# Fake DoH sources (tests/test_escape_dns.py; SUB_TEST_DOH lists their ports),
# recorded like everything else and then answered for real — without
# `--interface`, which would bind the query to the sandbox's pretend NIC.
for doh in ${SUB_TEST_DOH:-}; do
  case "$last" in "http://127.0.0.1:$doh/"*)
    printf 'curl' >> "$PARITY_TRACE"; printf ' %q' "$@" >> "$PARITY_TRACE"; echo >> "$PARITY_TRACE"
    args=()
    while [ "$#" -gt 0 ]; do
      case "$1" in --interface) shift ;; *) args+=("$1") ;; esac
      shift
    done
    exec /usr/bin/curl "${args[@]}" ;;
  esac
done
case "$last" in
  http://127.0.0.1:9090/proxies/*/delay\?*) echo '{"delay":12}'; exit 0 ;;
esac
source "$SUB_TEST_RECORDER"
""")
        self.executable(self.cfg / "bin/sing-box", """#!/bin/bash
printf '%s\\n' "$1" >> "$SUB_TEST_ROOT/router-events"
case "$1" in
  version) echo 'sing-box version 1.13.14' ;;
  check) [ ! -f "$SUB_TEST_ROOT/reject-config" ] ;;
  run) echo "$$" >> "$SUB_TEST_ROOT/engine-pids"; exec /bin/sleep 300 ;;
esac
""")
        feed = self.root / "feed.txt"
        feed.write_text(LINK)
        self.set_feed(feed.as_uri())
        # Seed through the actual command, before creating any router process.
        self.run("sub", "update")
        # Initialize the simulated proxy bypass list too, so a healthy tick
        # does not reload for unrelated network configuration drift.
        self.run("proxy", "on", "--force")

    @staticmethod
    def executable(path, body):
        path.write_text(body)
        path.chmod(0o755)

    def set_state(self, key, value):
        path = self.cfg / "state"
        lines = [s for s in path.read_text().splitlines() if not s.startswith(key + "=")]
        path.write_text("\n".join(lines + [key + "=" + value]) + "\n")

    def set_feed(self, url):
        (self.cfg / "subs.txt").write_text(url + "\n")
        self.env["SUB_TEST_FEED"] = url

    def http_feed(self):
        sandbox = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                sandbox.requests += 1
                sandbox.entered.set()
                if not sandbox.release.wait(30):
                    return
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(sandbox.body.encode())
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.server_thread.start()
        self.set_feed(f"http://127.0.0.1:{self.server.server_port}/feed")

    def start_router(self):
        process = subprocess.Popen(["/bin/sleep", "300"], start_new_session=True)
        self.processes.append(process)
        (self.cfg / "host.pid").write_text(str(process.pid) + "\n")
        return process

    def start(self, *args, implementation=None):
        impl = implementation or self.implementation
        command = (["bash", str(ROOT / "bin/rowt")] if impl == "bash"
                   else [str(ROOT / "target/release/rowt-rs")])
        log = self.root / f"command-{len(self.commands)}"
        # Daemons must not inherit a pipe that communicate() would wait on.
        with log.open("w") as output:
            process = subprocess.Popen(
                command + list(args), env={**self.env, "ROWT_IMPL": impl},
                stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                start_new_session=True,
            )
        self.processes.append(process)
        self.commands[process.pid] = (args, log)
        return process

    def finish(self, process, ok=True):
        rc = process.wait(timeout=60)
        args, log = self.commands[process.pid]
        text = log.read_text()
        if rc != (0 if ok else 1):
            raise AssertionError(f"{args}: exit {rc}\n{text}")
        return text

    def run(self, *args, ok=True, implementation=None):
        return self.finish(self.start(*args, implementation=implementation), ok=ok)

    def due(self):
        os.utime(self.cfg / "sub-update.at", (1234, 1234))

    def starts(self):
        path = self.root / "router-events"
        return path.read_text().splitlines().count("run") if path.exists() else 0

    def pool(self):
        return json.loads((self.cfg / "servers.json").read_text())

    @staticmethod
    def command_of(pid):
        out = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
        return out.stdout.strip() if out.returncode == 0 else ""

    def recorded_engines(self):
        """Every fake engine `run` this sandbox saw, by the pid it wrote down.

        A fake engine writes its pid to engine-pids, then execs `sleep 300`:
        the same pid. Since 3.6.7 rowt starts its router in a session of its
        own, so a router a reload started is in no group this sandbox created,
        and a reload replaces host.pid — the record is what still names it."""
        path = self.root / "engine-pids"
        if not path.exists():
            return []
        return [int(line) for line in path.read_text().split() if line.isdigit()]

    def stray_pids(self):
        """This sandbox's processes still alive outside its own process groups:
        recorded fake engines, and an `auto` follower rowt detached."""
        found = [pid for pid in self.recorded_engines() if self.command_of(pid) == "/bin/sleep 300"]
        follow = self.cfg / "follow.pid"
        if follow.exists():
            text = follow.read_text().strip()
            if text.isdigit() and "watch follow" in self.command_of(int(text)):
                found.append(int(text))
        return found

    def __exit__(self, *args):
        self.release.set()
        try:
            # Our own processes, by the groups we created (start_new_session):
            # each Popen leads its group. Extinct groups are skipped — macOS
            # can report EPERM for those.
            for process in self.processes:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
            # Then what rowt detached, each by the pid it recorded, and only
            # while that pid still runs what the record says it is.
            for pid in self.stray_pids():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for process in self.processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                self.server_thread.join()
            self.temp.cleanup()
