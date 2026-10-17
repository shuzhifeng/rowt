//! Exercise the real LiveSource in a child process so its environment and
//! background workers cannot leak into other tests. All HTTP is loopback.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime};
use rowt_monitor::{model::Window, source::{CtlOutcome, LiveSource, Source}};

struct Fixture {
    root: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() { server.join().unwrap(); }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn live_subscription_updates_notify_and_reprobe() {
    let root = std::env::temp_dir().join(format!("rowt-sub-live-{}", std::process::id()));
    fs::create_dir_all(root.join("rowt")).unwrap();
    fs::create_dir_all(root.join("shims")).unwrap();
    let cfg = root.join("rowt");
    let stop = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let mut fixture = Fixture { root: root.clone(), stop: stop.clone(), server: None };
    let server_cfg = cfg.clone();
    fixture.server = Some(std::thread::spawn(move || {
        let mut clients = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    let cfg = server_cfg.clone();
                    let stop = stop.clone();
                    clients.push(std::thread::spawn(move || {
                        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut reader = BufReader::new(&mut socket);
                        let mut request = String::new();
                        reader.read_line(&mut request).unwrap();
                        loop {
                            let mut header = String::new();
                            if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" { break; }
                        }
                        let mut log = fs::OpenOptions::new().create(true).append(true).open(cfg.join("requests")).unwrap();
                        log.write_all(request.as_bytes()).unwrap();
                        let delay = request.contains("/delay?");
                        while delay && cfg.join("hold-probe").exists() && !stop.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        let body = if delay { r#"{"delay":12}"# }
                            else { r#"{"connections":[],"uploadTotal":0,"downloadTotal":0}"# };
                        let _ = write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("accept: {e}"),
            }
        }
        for client in clients { client.join().unwrap(); }
    }));
    for name in ["networksetup", "launchctl", "ps", "route", "ipconfig"] {
        executable(&root.join("shims").join(name), "#!/bin/sh\nexit 1\n");
    }
    executable(&root.join("rowt-stub"), r#"#!/bin/sh
cfg="$XDG_CONFIG_HOME/rowt"
printf '%s\n' "$*" >> "$cfg/control-calls"
touch "$cfg/control-started"
while [ ! -f "$cfg/control-release" ]; do sleep 0.01; done
echo '==> re-fetching subscriptions' >&2
if [ -f "$cfg/control-fail" ]; then
  echo 'error: simulated subscription failure' >&2
  exit 1
fi
echo 'subscriptions unchanged' > "$cfg/sub-update.result"
echo 'subscriptions unchanged'
"#);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "live_subscription_worker", "--nocapture"])
        .env("ROWT_SUB_TEST", &root)
        .env("HOME", &root).env("XDG_CONFIG_HOME", &root)
        .env("ROWT_CLASH_PORT", port.to_string())
        .env("ROWT_BIN", root.join("rowt-stub"))
        .env("PATH", format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", root.join("shims").display()))
        .env_remove("HTTP_PROXY").env_remove("HTTPS_PROXY").env_remove("ALL_PROXY")
        .env_remove("http_proxy").env_remove("https_proxy").env_remove("all_proxy")
        .output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for LiveSource");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn probes(cfg: &Path) -> usize {
    fs::read_to_string(cfg.join("requests")).unwrap_or_default().lines().filter(|l| l.contains("/delay?")).count()
}

fn write_pool(cfg: &Path, revision: u64) {
    let server = serde_json::json!({"type":"vless", "tag":"alpha", "server":format!("node-{revision}.example"), "server_port":443});
    fs::write(cfg.join("servers.json"), serde_json::json!([server.clone()]).to_string()).unwrap();
    fs::write(cfg.join("host.json"), serde_json::json!({"outbounds":[
        {"type":"selector", "tag":"escape", "outbounds":["alpha"]}, server
    ]}).to_string()).unwrap();
    // Deterministic, distinct mtimes even on coarse-resolution filesystems.
    for file in ["servers.json", "host.json"] {
        fs::File::open(cfg.join(file)).unwrap().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1000 + revision)).unwrap();
    }
}

#[test]
fn live_subscription_worker() {
    let Some(root) = std::env::var_os("ROWT_SUB_TEST") else { return; };
    let cfg = PathBuf::from(root).join("rowt");
    fs::write(cfg.join("state"), "mode=host\nselected=alpha\n").unwrap();
    write_pool(&cfg, 0);
    let mut source = LiveSource::new();
    source.poll(Window::M5, None);
    wait_until(|| probes(&cfg) == 3 && fs::read_to_string(cfg.join("latency.tsv")).unwrap_or_default().contains("alpha\t12\t3"));

    // Same tag, different endpoint: wait for the refresh lock, then reprobe.
    fs::create_dir(cfg.join("sub-update.lock")).unwrap();
    write_pool(&cfg, 1);
    source.poll(Window::M5, None);
    assert_eq!(probes(&cfg), 3);
    fs::remove_dir(cfg.join("sub-update.lock")).unwrap();
    let message = "subscriptions updated: +0 added, -0 removed, 1 changed";
    fs::write(cfg.join("sub-update.result"), message).unwrap();
    wait_until(|| { source.poll(Window::M5, None); probes(&cfg) == 6 });
    let outcomes = source.drain_ctl();
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(&outcomes[0], CtlOutcome::Ok(m) if m == message));
    source.poll(Window::M5, None);
    assert!(source.drain_ctl().is_empty(), "automatic result must not repeat every tick");
    assert_eq!(probes(&cfg), 6);

    // An update arriving during a probe still gets a fresh round afterwards.
    fs::write(cfg.join("hold-probe"), "").unwrap();
    write_pool(&cfg, 2);
    wait_until(|| { source.poll(Window::M5, None); probes(&cfg) == 7 });
    write_pool(&cfg, 3);
    source.poll(Window::M5, None);
    assert_eq!(probes(&cfg), 7);
    fs::remove_file(cfg.join("hold-probe")).unwrap();
    wait_until(|| { source.poll(Window::M5, None); probes(&cfg) == 12 });

    // Exercise the real asynchronous command runner and its duplicate guard.
    source.update_subscriptions().unwrap();
    assert!(source.restart_in_flight());
    assert!(source.update_subscriptions().is_err());
    wait_until(|| cfg.join("control-started").exists());
    fs::write(cfg.join("control-release"), "").unwrap();
    wait_until(|| !source.restart_in_flight());
    assert_eq!(fs::read_to_string(cfg.join("control-calls")).unwrap(), "sub update\n");
    let outcomes = source.drain_ctl();
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(&outcomes[0], CtlOutcome::Ok(m) if m == "subscriptions unchanged"));
    source.poll(Window::M5, None);
    assert!(source.drain_ctl().is_empty(), "manual result must not repeat via the status file");
    assert_eq!(probes(&cfg), 12, "unchanged subscriptions must not trigger a probe");

    fs::write(cfg.join("control-fail"), "").unwrap();
    source.update_subscriptions().unwrap();
    wait_until(|| !source.restart_in_flight());
    let outcomes = source.drain_ctl();
    assert!(matches!(&outcomes[0], CtlOutcome::Err(m) if m == "simulated subscription failure"));
}
