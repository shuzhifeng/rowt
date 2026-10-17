"""Exercise both subscription-update CLIs using local feeds and an isolated config.

Run after cargo build --release --workspace: python3 tests/test_subscriptions.py
"""

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest

from subscription_sandbox import Sandbox


ROOT = Path(__file__).resolve().parents[1]
LINK = "vless://00000000-0000-4000-8000-000000000001@node.example:443#node\n"


class SubscriptionTests(unittest.TestCase):
    def test_watchdog_refreshes_once_then_obeys_persisted_schedule(self):
        # Mode and interval boundaries are covered by the fast schedule tests.
        for implementation, selected in (("bash", "auto"), ("rust", "best")):
            with self.subTest(implementation=implementation, selected=selected):
                with Sandbox(implementation) as box:
                    box.set_state("selected", selected)
                    box.http_feed()
                    box.start_router()
                    (box.cfg / "sub-update.at").unlink()
                    box.run("watch", "tick")
                    self.assertEqual(box.requests, 1)
                    self.assertIn("unchanged", (box.cfg / "sub-update.result").read_text())
                    stamp = (box.cfg / "sub-update.at").stat().st_mtime_ns
                    box.run("watch", "tick")
                    self.assertEqual(box.requests, 1)
                    self.assertEqual((box.cfg / "sub-update.at").stat().st_mtime_ns, stamp)
                    self.assertEqual(box.starts(), 0)
                    self.assertFalse((box.cfg / "sub-update.lock").exists())
                    self.assertFalse((box.cfg / "watch.lock").exists())

    def test_running_router_reloads_only_for_changes_and_retries_failed_apply(self):
        for implementation in ("bash", "rust"):
            with self.subTest(implementation=implementation):
                with Sandbox(implementation) as box:
                    box.http_feed()
                    initial = box.start_router()
                    box.run("sub", "update")
                    self.assertEqual(box.starts(), 0)
                    self.assertIsNone(initial.poll())
                    box.body = box.body.replace(":443", ":8443")
                    box.run("sub", "update")
                    self.assertEqual(box.starts(), 1)
                    self.assertIsNotNone(initial.poll())
                    pid = (box.cfg / "host.pid").read_text()
                    box.run("sub", "update")
                    self.assertEqual(box.starts(), 1)
                    self.assertEqual((box.cfg / "host.pid").read_text(), pid)

                    box.body = box.body.replace(":8443", ":9443")
                    (box.root / "reject-config").touch()
                    box.run("sub", "update", ok=False)
                    self.assertTrue((box.cfg / "sub-update.pending").exists())
                    self.assertEqual(box.starts(), 1, "failed validation must not stop the router")
                    self.assertEqual((box.cfg / "host.pid").read_text(), pid)
                    (box.root / "reject-config").unlink()
                    # A saved update must remain pending while the router is down.
                    box.run("router", "down")
                    self.assertIn("pending", box.run("sub", "update", ok=False))
                    self.assertTrue((box.cfg / "sub-update.pending").exists())
                    self.assertEqual(box.starts(), 1)
                    box.start_router()
                    box.run("sub", "update")
                    self.assertEqual(box.starts(), 2)
                    self.assertFalse((box.cfg / "sub-update.pending").exists())
                    self.assertEqual(box.pool()[0]["server_port"], 9443)

    def test_manual_and_watchdog_refreshes_share_one_lock_across_processes(self):
        for implementation, first in (("bash", ("watch", "tick")), ("rust", ("sub", "update"))):
            with self.subTest(implementation=implementation, first=first):
                with Sandbox(implementation) as box:
                    box.http_feed()
                    box.start_router()
                    box.due()
                    box.release.clear()
                    process = box.start(*first)
                    self.assertTrue(box.entered.wait(20), "first refresh never fetched the feed")
                    stamp = (box.cfg / "sub-update.at").stat().st_mtime_ns
                    other = "rust" if implementation == "bash" else "bash"
                    self.assertIn("in progress", box.run("sub", "update", ok=False, implementation=other))
                    # Even a stale watchdog lock must not be reclaimed
                    # while a slow subscription refresh owns it.
                    if first[0] == "watch":
                        os.utime(box.cfg / "watch.lock", (1234, 1234))
                    box.run("watch", "tick", implementation=other)
                    self.assertEqual(box.requests, 1)
                    self.assertEqual((box.cfg / "sub-update.at").stat().st_mtime_ns, stamp)
                    box.release.set()
                    box.finish(process)
                    self.assertFalse((box.cfg / "sub-update.lock").exists())
                    self.assertFalse((box.cfg / "watch.lock").exists())

    def test_killed_refresh_can_be_recovered_by_either_cli(self):
        for implementation in ("bash", "rust"):
            with self.subTest(implementation=implementation):
                with Sandbox(implementation) as box:
                    box.http_feed()
                    box.release.clear()
                    process = box.start("sub", "update")
                    self.assertTrue(box.entered.wait(10))
                    old = box.pool()
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    self.assertTrue((box.cfg / "sub-update.lock").exists())
                    box.release.set()
                    other = "rust" if implementation == "bash" else "bash"
                    box.run("sub", "update", implementation=other)
                    self.assertFalse((box.cfg / "sub-update.lock").exists())
                    self.assertEqual(box.pool(), old)

    def test_bash_watchdog_schedule(self):
        source = (ROOT / "bin/rowt").read_text()
        function = re.search(r"^_watch_subscriptions\(\) \{.*?^\}", source, re.M | re.S).group()
        script = """
            sget() { case "$1" in selected) echo "$SELECTED" ;; mode) echo "$MODE" ;; esac; }
            sub_count() { echo 1; }
            ipconfig() { [ "$ONLINE" = 1 ] && echo 192.0.2.1; }
            info() { echo "==> $*" >&2; }
            _sub_update() { touch "$CFG/attempt"; echo 'subscriptions unchanged'; }
        """ + function + "\n_watch_subscriptions en0\n"
        cases = [
            ("auto", "host", "1", None, True),
            ("best", "host", "1", None, True),
            ("auto", "host", "1", 21590, False),
            ("best", "host", "1", 21590, False),
            ("auto", "host", "1", 21610, True),
            ("best", "host", "1", 21610, True),
            ("node", "host", "1", None, False),
            ("best", "local", "1", None, False),
            ("auto", "host", "0", None, False),
        ]
        for selected, mode, online, age, due in cases:
            with self.subTest(selected=selected, mode=mode, online=online, age=age):
                with tempfile.TemporaryDirectory(prefix="rowt-sub-schedule-") as scratch:
                    cfg = Path(scratch)
                    if age is not None:
                        stamp = cfg / "sub-update.at"
                        stamp.touch()
                        when = time.time() - age
                        os.utime(stamp, (when, when))
                    result = subprocess.run(
                        ["bash", "-c", script], capture_output=True, text=True,
                        env={"CFG": scratch, "SELECTED": selected, "MODE": mode,
                             "ONLINE": online, "PATH": "/usr/bin:/bin"}, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((cfg / "attempt").exists(), due)
                    self.assertEqual(result.stdout, "", "watchdog results belong in its log")

    def test_refresh_in_bash_and_rust(self):
        for implementation in ("bash", "rust"):
            with self.subTest(implementation=implementation):
                with tempfile.TemporaryDirectory(prefix="rowt-subscriptions-") as scratch:
                    self.check_refresh(Path(scratch), implementation)

    def check_refresh(self, scratch, implementation):
        cfg = scratch / "rowt"
        cfg.mkdir()
        state = cfg / "state"
        state.write_text("mode=host\nselected=best\n")
        feed = scratch / "feed.txt"
        feed.write_text(LINK)
        subs = cfg / "subs.txt"
        subs.write_text(feed.as_uri() + "\n")
        env = {
            "HOME": str(scratch),
            "XDG_CONFIG_HOME": str(scratch),
            "PATH": os.environ["PATH"],
            "ROWT_IMPL": implementation,
            "ROWT_PY": "1",
            "TERM": "dumb",
            "LC_ALL": "C",
        }
        command = (
            ["bash", str(ROOT / "bin/rowt")]
            if implementation == "bash"
            else [str(ROOT / "target/release/rowt-rs")]
        )

        def update(ok=True):
            result = subprocess.run(
                command + ["sub", "update"], env=env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0 if ok else 1, result.stderr)
            self.assertFalse((cfg / "sub-update.lock").exists())
            return result.stdout.strip() if ok else result.stderr

        self.assertEqual(update(), "subscriptions updated: +1 added, -0 removed, 0 changed")
        pool = cfg / "servers.json"
        stamp = cfg / "sub-update.at"
        self.assertEqual(pool.stat().st_mode & 0o777, 0o600)
        self.assertEqual(stamp.stat().st_mode & 0o777, 0o600)
        os.utime(pool, (1234, 1234))
        os.utime(stamp, (1234, 1234))
        self.assertEqual(update(), "subscriptions unchanged")
        self.assertEqual(pool.stat().st_mtime, 1234)
        self.assertGreater(stamp.stat().st_mtime, 1234)
        self.assertEqual(
            (cfg / "sub-update.result").read_text().strip(), "subscriptions unchanged"
        )

        second = LINK.replace("node.example", "second.example").replace("#node", "#second")
        feed.write_text(LINK.replace(":443", ":8443") + second)
        self.assertEqual(update(), "subscriptions updated: +1 added, -0 removed, 1 changed")
        state.write_text("mode=host\nselected=node\n")
        feed.write_text(LINK)
        self.assertEqual(update(), "subscriptions updated: +0 added, -1 removed, 1 changed")
        self.assertIn("selected=node\n", state.read_text())

        old = pool.read_bytes()
        subs.write_text(feed.as_uri() + "\nfile:///does-not-exist/secret-token\n")
        error = update(ok=False)
        self.assertIn("previous servers kept", error)
        self.assertNotIn("secret-token", error)
        self.assertEqual(pool.read_bytes(), old)
        self.assertIn("error:", (cfg / "sub-update.result").read_text())

        subs.write_text(feed.as_uri() + "\n")
        feed.write_text("not a subscription\n")
        update(ok=False)
        self.assertEqual(pool.read_bytes(), old)

        feed.write_text(second)
        self.assertEqual(update(), "subscriptions updated: +1 added, -1 removed, 0 changed")
        self.assertIn("selected=second\n", state.read_text())
        self.assertEqual([s["tag"] for s in json.loads(pool.read_text())], ["second"])

        # Both implementations must respect a lock held by another process.
        lock = cfg / "sub-update.lock"
        lock.mkdir()
        (lock / "pid").write_text(str(os.getpid()) + "\n")
        before = stamp.stat().st_mtime_ns
        result = subprocess.run(
            command + ["sub", "update"], env=env,
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("in progress", result.stderr)
        self.assertEqual(stamp.stat().st_mtime_ns, before)
        (lock / "pid").unlink()
        lock.rmdir()

        # A concurrent watchdog must also prevent a manual reload.
        watch = cfg / "watch.lock"
        watch.mkdir()
        self.assertIn("watchdog in progress", update(ok=False))
        self.assertEqual(stamp.stat().st_mtime_ns, before)


if __name__ == "__main__":
    unittest.main()
