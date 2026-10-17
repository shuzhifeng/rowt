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
  run) exec /bin/sleep 300 ;;
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

    def __exit__(self, *args):
        self.release.set()
        # Do not signal extinct process groups: macOS can report EPERM for
        # these. Only groups with a live process we created need cleanup.
        live = [p.pid for p in self.processes if p.poll() is None]
        pidfile = self.cfg / "host.pid"
        if pidfile.exists():
            live.append(int(pidfile.read_text()))
        groups = set()
        for pid in live:
            try:
                groups.add(os.getpgid(pid))
            except ProcessLookupError:
                pass
        try:
            for group in groups:
                if group not in {p.pid for p in self.processes}:
                    raise AssertionError("refusing to signal a process outside the test")
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for process in self.processes:
                process.wait(timeout=5)
        finally:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                self.server_thread.join()
            self.temp.cleanup()
