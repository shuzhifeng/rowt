"""`auto`'s failover follower, both CLIs, against a fake clash API.

The fake models what sing-box 1.13's urltest does (protocol/group/urltest.go):
a failed connection through the pick deletes the pick's stored delay and
nothing more, and only a re-test (`GET /group/auto/delay`, or a round) moves
the group — to the fastest server that still has a delay. So without the
follower, a dead pick stays picked until the next round, up to a whole
`--every` interval later.

The drill: bring the router up in `auto` (the follower starts with it), let the
pick die the way sing-box records it, and require the group to be on a live
server within a minute — then let every server die and require the follower to
say so and stay put, and `router down` to stop it.

Then the trigger itself on the real engine, skipped when no sing-box binary is
found (ROWT_TEST_SINGBOX, the repo's bin/, or the Homebrew install's bundled
copy): a sing-box of its own on private ports — never the router this machine
runs — with urltest `auto` over two SOCKS members served on loopback. The pick
dies; one real connection through it fails; sing-box empties the pick's
history and stays on it; the follower moves the group within a minute.

Run after cargo build --release --workspace: python3 tests/test_auto_follow.py
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shutil
import subprocess
import threading
import time
import unittest
from urllib.parse import urlsplit
import urllib.request

from subscription_sandbox import Sandbox
from test_escape_dns import Generate204, Listener, find_singbox, free_port, socks5


class FakeClash:
    """The parts of sing-box's clash API the follower and `status` read."""

    def __init__(self, delays, pick):
        self.lock = threading.Lock()
        self.alive = dict.fromkeys(delays, True)
        self.delays = dict(delays)
        self.history = dict(delays)  # tag -> stored delay; absent = none
        self.pick = pick
        self.looks = 0
        self.retests = 0
        self.switched_at = None
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = fake.answer(urlsplit(self.path).path)
                self.send_response(200 if body is not None else 404)
                self.end_headers()
                self.wfile.write(json.dumps(body or {"message": "not found"}).encode())

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def answer(self, path):
        with self.lock:
            if path == "/version":
                return {"version": "fake"}
            if path == "/proxies/escape":
                return {"name": "escape", "now": "auto", "all": ["auto", *self.delays], "history": []}
            if path == "/proxies/auto":
                self.looks += 1
                return {"name": "auto", "now": self.pick, "all": list(self.delays), "history": []}
            if path.startswith("/proxies/"):
                tag = path.split("/")[2]
                if tag not in self.delays:
                    return None
                h = self.history.get(tag)
                return {"name": tag, "history": [] if h is None else [{"time": "t", "delay": h}]}
            if path == "/group/auto/delay":
                self.retests += 1
                # urlTest: re-test the servers without a figure, then Select —
                # keep a pick that has one, else take the fastest that does.
                for tag in self.delays:
                    if tag not in self.history:
                        if self.alive[tag]:
                            self.history[tag] = self.delays[tag]
                if self.pick not in self.history:
                    live = sorted((d, t) for t, d in self.history.items())
                    if live:
                        self.pick = live[0][1]
                        self.switched_at = time.monotonic()
                return {t: d for t, d in self.history.items()}
            return None

    def fail(self, tag):
        """What a failed dial through `tag` leaves behind: no figure."""
        with self.lock:
            self.alive[tag] = False
            self.history.pop(tag, None)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def wait_for(cond, timeout, step=0.2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


class AutoFollowTests(unittest.TestCase):
    def test_a_dead_pick_is_left_within_a_minute_and_the_follower_stops_with_the_router(self):
        for implementation in ("bash", "rust"):
            with self.subTest(implementation=implementation):
                clash = FakeClash({"alpha": 80, "beta": 120, "gamma": 150}, pick="alpha")
                try:
                    with Sandbox(implementation) as box:
                        box.env.update({
                            "ROWT_AUTO_FOLLOW": "1",
                            "ROWT_CLASH_PORT": str(clash.port),
                            "SUB_TEST_CLASH": str(clash.port),
                        })
                        box.set_state("selected", "auto")
                        box.run("router", "up")
                        pidfile = box.cfg / "follow.pid"
                        self.assertTrue(wait_for(pidfile.exists, 10), "router up did not start the follower")
                        follower = int(pidfile.read_text())
                        # Its first look, then it sleeps: fail the pick now,
                        # the way sing-box records a failed dial.
                        self.assertTrue(wait_for(lambda: clash.looks >= 1, 10))
                        failed_at = time.monotonic()
                        clash.fail("alpha")
                        self.assertTrue(wait_for(lambda: clash.pick == "beta", 60),
                                        "the follower never moved auto off the dead pick")
                        elapsed = clash.switched_at - failed_at
                        self.assertLess(elapsed, 60)
                        # The group has moved; the follower records it once its
                        # re-test request returns and it reads the new pick —
                        # watch.log, the audit log, then state, in that order.
                        state = box.cfg / "state"
                        self.assertTrue(wait_for(lambda: "auto_switch=" in state.read_text(), 10),
                                        "the follower did not record the switch")
                        self.assertRegex(state.read_text(),
                                         r"auto_switch=\d{4}-\d\d-\d\d \d\d:\d\d:\d\d alpha -> beta\n")
                        self.assertIn("auto: alpha stopped answering — re-tested now and moved to beta",
                                      (box.cfg / "log/watch.log").read_text())
                        self.assertIn("watchdog auto: alpha stopped answering", (box.cfg / "log/audit.log").read_text())
                        status = box.run("status")
                        self.assertIn("active:       auto → beta (sing-box urltest's pick)", status)
                        self.assertIn("failover follower running (checks every 15s)", status)
                        self.assertIn("alpha -> beta", status)

                        # Every server dead: the re-test finds nothing live, the
                        # follower says so and the group stays where it is.
                        retests = clash.retests
                        clash.fail("beta")
                        clash.fail("gamma")
                        self.assertTrue(wait_for(lambda: "no other server answered the re-test"
                                                 in (box.cfg / "log/watch.log").read_text(), 30))
                        self.assertEqual(clash.pick, "beta")
                        self.assertEqual(clash.retests, retests + 1)

                        box.run("router", "down")
                        self.assertFalse(pidfile.exists())
                        gone = wait_for(lambda: not alive(follower), 10)
                        self.assertTrue(gone, "router down left the follower running")
                        print(f"\n  {implementation}: dead pick left after {elapsed:.1f}s")
                finally:
                    clash.close()


class Member:
    """A SOCKS server for one urltest member, `delay` seconds slow to answer.
    Once dead it accepts and hangs up at once, so a dial through it fails."""

    def __init__(self, delay):
        self.delay = delay
        self.dead = False
        self.port = free_port()
        self.listener = Listener("127.0.0.1", self.port, self.serve)

    def serve(self, c):
        if self.dead:
            c.close()
            return
        time.sleep(self.delay)
        socks5(c)

    def close(self):
        self.listener.close()


class RealEngineDrill(unittest.TestCase):
    """What the follower rests on, on sing-box itself rather than a model."""

    @unittest.skipUnless(find_singbox(), "no sing-box binary (set ROWT_TEST_SINGBOX)")
    def test_a_failed_dial_empties_the_picks_history_and_the_follower_moves_auto(self):
        for implementation in ("bash", "rust"):
            with self.subTest(implementation=implementation):
                self.drill(implementation)

    def drill(self, implementation):
        web = ThreadingHTTPServer(("127.0.0.1", 0), Generate204)
        threading.Thread(target=web.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        url = f"http://127.0.0.1:{web.server_port}/generate_204"
        # Far enough apart that urltest's 50 ms tolerance cannot keep beta.
        alpha, beta = Member(0.02), Member(0.3)
        try:
            with Sandbox(implementation) as box:
                secret = next(line.split("=", 1)[1] for line in (box.cfg / "state").read_text().splitlines()
                              if line.startswith("clash_secret="))
                clash, mixed = free_port(), free_port()
                engine = box.root / "sing-box.real"
                shutil.copy(find_singbox(), engine)
                config = box.root / "drill.json"
                # rowt's shape, cut to what the follower touches: the escape
                # selector on `auto`, a urltest whose round is far away.
                config.write_text(json.dumps({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": mixed}],
                    "outbounds": [
                        {"type": "selector", "tag": "escape", "outbounds": ["auto", "alpha", "beta"],
                         "default": "auto"},
                        {"type": "urltest", "tag": "auto", "outbounds": ["alpha", "beta"], "url": url,
                         "interval": "30m", "tolerance": 50},
                        {"type": "socks", "tag": "alpha", "server": "127.0.0.1", "server_port": alpha.port,
                         "version": "5"},
                        {"type": "socks", "tag": "beta", "server": "127.0.0.1", "server_port": beta.port,
                         "version": "5"},
                    ],
                    "route": {"final": "escape"},
                    "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{clash}", "secret": secret}},
                }))
                with (box.root / "drill.log").open("w") as log:
                    router = subprocess.Popen([str(engine), "run", "-c", str(config)], stdin=subprocess.DEVNULL,
                                              stdout=log, stderr=log, start_new_session=True)
                box.processes.append(router)
                api = urllib.request.build_opener(urllib.request.ProxyHandler({}))

                def get(path):
                    request = urllib.request.Request(f"http://127.0.0.1:{clash}{path}",
                                                     headers={"Authorization": f"Bearer {secret}"})
                    try:
                        with api.open(request, timeout=20) as r:
                            return json.loads(r.read() or b"{}")
                    except OSError:
                        return None

                def pick():
                    return (get("/proxies/auto") or {}).get("now")

                def history(tag):
                    return (get(f"/proxies/{tag}") or {}).get("history")

                try:
                    self.assertTrue(wait_for(lambda: get("/version") is not None, 10),
                                    "the drill's sing-box never answered:\n" + (box.root / "drill.log").read_text())
                    # The first round: both measured, alpha picked.
                    get(f"/group/auto/delay?timeout=5000&url={url}")
                    self.assertTrue(wait_for(lambda: pick() == "alpha" and history("alpha"), 10),
                                    f"alpha was not picked: {get('/proxies/auto')}")
                    self.assertTrue(history("beta"))

                    (box.cfg / "host.pid").write_text(f"{router.pid}\n")
                    box.env.update({
                        "ROWT_AUTO_FOLLOW": "1",
                        "ROWT_CLASH_PORT": str(clash),
                        "SUB_TEST_CLASH": str(clash),
                        "ROWT_HEALTH_URL": url,
                    })
                    follower = box.start("watch", "follow")
                    time.sleep(3)  # its first look found alpha healthy; it sleeps 15 s
                    if follower.poll() is not None:
                        self.fail("the follower exited:\n" + box.commands[follower.pid][1].read_text())

                    # alpha dies; one connection through the group fails.
                    alpha.dead = True
                    failed_at = time.monotonic()
                    subprocess.run(["/usr/bin/curl", "-sS", "-m", "5", "--noproxy", "", "-x",
                                    f"http://127.0.0.1:{mixed}", url], capture_output=True)
                    # What sing-box does on its own: the pick's history is
                    # gone, and the group stays on it until a round.
                    self.assertEqual(history("alpha"), [])
                    self.assertEqual(pick(), "alpha")

                    self.assertTrue(wait_for(lambda: pick() == "beta", 60),
                                    "the follower never moved auto off the dead pick")
                    elapsed = time.monotonic() - failed_at
                    self.assertLess(elapsed, 60)
                    watch_log = box.cfg / "log/watch.log"
                    self.assertTrue(wait_for(lambda: watch_log.exists() and "moved to beta" in watch_log.read_text(),
                                             10))
                    self.assertIn("auto: alpha stopped answering — re-tested now and moved to beta",
                                  watch_log.read_text())
                    print(f"\n  {implementation}: real sing-box — dead pick left after {elapsed:.1f}s")
                finally:
                    # Both by the pid this test started; the sandbox stops
                    # whatever is left of its own process groups after this.
                    for process in (router, *[p for p in box.processes if p is not router]):
                        if process.poll() is None:
                            process.terminate()
                    router.wait(timeout=10)
        finally:
            alpha.close()
            beta.close()
            web.shutdown()
            web.server_close()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


if __name__ == "__main__":
    unittest.main()
