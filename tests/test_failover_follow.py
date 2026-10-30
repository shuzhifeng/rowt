"""`use <tag> --failover` (rowt #s36): the follower on a pinned preference, both
CLIs, against a fake clash API.

A plain selector never tests its members, so the follower tests the pin itself
each round (`GET /proxies/<pin>/delay`) and, off the pin, the server it is on.
The fake answers that delay test from a table of who is alive, serves the
selector's `now`, and takes `PUT /proxies/escape` the way sing-box does.

The drill: bring the router up with alpha pinned and the flag on (the follower
starts with it); kill alpha and require the selector on beta within a minute,
with the move in watch.log, the audit log and state; revive alpha and require
the selector back on it; kill everything and require the follower to say so
and stay; then a plain `use alpha` and require the follower to exit.

Run after cargo build --release --workspace: python3 tests/test_failover_follow.py
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import unittest
from urllib.parse import urlsplit

from subscription_sandbox import Sandbox
from test_auto_follow import alive, wait_for


class FakeSelector:
    """The parts of sing-box's clash API the failover follower and `status` read."""

    def __init__(self, delays: dict[str, int], now: str) -> None:
        self.lock = threading.Lock()
        self.alive = dict.fromkeys(delays, True)
        self.delays = dict(delays)
        self.now = now
        self.tests: list[str] = []
        self.puts: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body, code = fake.get(urlsplit(self.path).path)
                self.send_response(code)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def do_PUT(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                code = fake.put(urlsplit(self.path).path, body)
                self.send_response(code)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def get(self, path: str) -> tuple[dict, int]:
        with self.lock:
            if path == "/version":
                return {"version": "fake"}, 200
            if path == "/proxies/escape":
                return {"name": "escape", "now": self.now, "all": list(self.delays), "history": []}, 200
            parts = path.split("/")
            if len(parts) == 4 and parts[1] == "proxies" and parts[3] == "delay":
                tag = parts[2]
                self.tests.append(tag)
                if tag == "escape":
                    tag = self.now
                if tag not in self.delays:
                    return {"message": "not found"}, 404
                if self.alive[tag]:
                    return {"delay": self.delays[tag]}, 200
                return {"message": "An error occurred in the delay test"}, 503
            if path.startswith("/proxies/"):
                tag = parts[2]
                if tag not in self.delays:
                    return {"message": "not found"}, 404
                return {"name": tag, "history": []}, 200
            return {"message": "not found"}, 404

    def put(self, path: str, body: dict) -> int:
        with self.lock:
            if path != "/proxies/escape":
                return 404
            name = body.get("name", "")
            if name not in self.delays:
                return 400
            self.now = name
            self.puts.append(name)
            return 204

    def kill(self, tag: str) -> None:
        with self.lock:
            self.alive[tag] = False

    def kill_all(self) -> None:
        """Every server at once, under one lock, so no round sees a half-dead pool."""
        with self.lock:
            for tag in self.alive:
                self.alive[tag] = False

    def revive(self, tag: str) -> None:
        with self.lock:
            self.alive[tag] = True

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class FailoverFollowTests(unittest.TestCase):
    def test_a_dead_pin_is_left_and_returned_to_and_a_plain_use_ends_it(self):
        for implementation in ("bash", "rust"):
            with self.subTest(implementation=implementation):
                clash = FakeSelector({"alpha": 80, "beta": 120, "gamma": 150}, now="alpha")
                try:
                    with Sandbox(implementation) as box:
                        box.env.update({
                            "ROWT_AUTO_FOLLOW": "1",
                            "ROWT_AUTO_FOLLOW_EVERY": "2",
                            "ROWT_HEALTH_TIMEOUT": "2",
                            "ROWT_CLASH_PORT": str(clash.port),
                            "SUB_TEST_CLASH": str(clash.port),
                        })
                        # The sweep walks servers.json, so the pool has to name the
                        # servers the fake answers for (the sandbox ships alpha alone).
                        pool = box.cfg / "servers.json"
                        alpha = json.loads(pool.read_text())[0]
                        pool.write_text(json.dumps([
                            alpha,
                            {**alpha, "tag": "beta", "server": "203.0.113.11"},
                            {**alpha, "tag": "gamma", "server": "203.0.113.12"},
                        ]) + "\n")
                        box.set_state("selected", "alpha")
                        box.set_state("failover", "1")
                        box.run("router", "up")
                        pidfile = box.cfg / "follow.pid"
                        self.assertTrue(wait_for(pidfile.exists, 10), "router up did not start the follower for a --failover pin")
                        follower = int(pidfile.read_text())
                        self.assertTrue(wait_for(lambda: "alpha" in clash.tests, 10), "the follower never tested the pin")
                        self.assertEqual(clash.puts, [], "nothing moved while the pin answered")

                        # The pin dies: the first other server that answers is taken, live.
                        clash.kill("alpha")
                        self.assertTrue(wait_for(lambda: clash.now == "beta", 60), "the follower never left the dead pin")
                        log = box.cfg / "log/watch.log"
                        self.assertTrue(wait_for(lambda: "failover: alpha stopped answering — moved to beta" in log.read_text(), 10))
                        self.assertIn("watchdog failover: alpha stopped answering — moved to beta", (box.cfg / "log/audit.log").read_text())
                        state = box.cfg / "state"
                        self.assertTrue(wait_for(lambda: "failover_switch=" in state.read_text(), 10))
                        self.assertRegex(state.read_text(), r"failover_switch=\d{4}-\d\d-\d\d \d\d:\d\d:\d\d alpha -> beta\n")
                        status = box.run("status")
                        self.assertIn("active:       beta", status)
                        self.assertIn("failover:     prefers alpha; failover follower running (checks every 2s)", status)
                        self.assertIn("              on beta — alpha is not answering; back on it when it does", status)
                        self.assertIn("alpha -> beta", status)

                        # The stand-in dies too while the pin is still dead: the next
                        # live server is taken, and the line says which died.
                        clash.kill("beta")
                        self.assertTrue(wait_for(lambda: clash.now == "gamma", 60), "the follower never left the dead stand-in")
                        self.assertTrue(wait_for(lambda: "failover: beta stopped answering too (alpha still not answering) — moved to gamma" in log.read_text(), 10))
                        self.assertRegex(state.read_text(), r"failover_switch=\d{4}-\d\d-\d\d \d\d:\d\d:\d\d beta -> gamma\n")

                        # The pin answers again: back on it.
                        clash.revive("alpha")
                        self.assertTrue(wait_for(lambda: clash.now == "alpha", 60), "the follower never returned to the pin")
                        self.assertTrue(wait_for(lambda: "failover: alpha answers again — back on it (was on gamma)" in log.read_text(), 10))
                        self.assertRegex(state.read_text(), r"failover_switch=\d{4}-\d\d-\d\d \d\d:\d\d:\d\d gamma -> alpha\n")
                        self.assertNotIn("is not answering", box.run("status"))

                        # Everything dead: it says so and stays on the pin.
                        clash.kill_all()
                        self.assertTrue(wait_for(lambda: "failover: alpha stopped answering and no other server answered — staying on alpha"
                                                 in log.read_text(), 60))
                        self.assertEqual(clash.now, "alpha")

                        # A plain `use alpha` ends the preference: the follower exits.
                        out = box.run("use", "alpha")
                        self.assertIn("failover off — the follower stops at its next look", out)
                        self.assertTrue(wait_for(lambda: not alive(follower), 15), "the follower outlived the flag")
                        self.assertNotIn("failover:", box.run("status"))
                        box.run("router", "down")
                        print(f"\n  {implementation}: left the dead pin, returned, held with all dead, stopped on a plain use")
                finally:
                    clash.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
