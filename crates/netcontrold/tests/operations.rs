#[cfg(test)]
fn test_revision(index: u32) -> netcontrol_core::Version {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}.{:02}.{:02}.{}",
        now.year(),
        now.month() as u8,
        now.day(),
        index + 1
    )
    .parse()
    .unwrap()
}

use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use netcontrol_core::{Engine, Simulator};
use netcontrold::http::{App, Authentication, Credential};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

struct Fixture {
    _directory: tempfile::TempDir,
    app: Arc<App>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_backend(Box::new(Simulator::new()))
    }
    fn with_backend(backend: Box<dyn netcontrol_core::Backend>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(&directory.path().join("state.json"), backend).unwrap(),
        ));
        let app = App::new(
            engine,
            Authentication::Scoped(vec![
                Credential {
                    name: "reader".into(),
                    token_sha256: netcontrold::identity::digest("synthetic-reader"),
                    permissions: vec!["state.read".into()],
                },
                Credential {
                    name: "operator".into(),
                    token_sha256: netcontrold::identity::digest("synthetic-operator"),
                    permissions: vec!["system.restart".into(), "diagnostics.run".into()],
                },
                Credential {
                    name: "path-operator".into(),
                    token_sha256: netcontrold::identity::digest("synthetic-path-operator"),
                    permissions: vec![
                        "diagnostics.run".into(),
                        "interfaces.write".into(),
                        "firewall.write".into(),
                    ],
                },
            ]),
            false,
        );
        Self {
            _directory: directory,
            app,
        }
    }
    async fn request(&self, method: &str, path: &str, body: Value, token: &str) -> (u16, Value) {
        self.request_body(
            method,
            path,
            Body::from(serde_json::to_vec(&body).unwrap()),
            token,
        )
        .await
    }
    async fn get(&self, path: &str, token: &str) -> (u16, Value) {
        self.request_body("GET", path, Body::empty(), token).await
    }
    async fn request_body(
        &self,
        method: &str,
        path: &str,
        body: Body,
        token: &str,
    ) -> (u16, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if !token.is_empty() {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let reply = netcontrold::http::router(self.app.clone())
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = reply.status().as_u16();
        let bytes = to_bytes(reply.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
}

#[tokio::test]
async fn host_experience_authentication_contract_and_unsupported_mode() {
    let f = Fixture::new();
    let latest = "/api/v1/statistics/host-experience/latest";
    let history = "/api/v1/statistics/host-experience/history";
    assert_eq!(f.get(latest, "").await.0, 401);
    assert_eq!(f.get(latest, "synthetic-operator").await.0, 403);
    assert_eq!(
        f.request("POST", latest, json!({}), "synthetic-reader")
            .await
            .0,
        405
    );
    assert_eq!(
        f.request("GET", latest, Value::Null, "synthetic-reader")
            .await
            .0,
        400
    );
    for path in [
        format!("{latest}?limit=257"),
        format!("{latest}?unknown=true"),
        format!("{latest}?address=2001:0db8::1"),
        format!("{latest}?limit=1&limit=1"),
        history.into(),
        format!("{history}?address=192.0.2.20&interface=lan0"),
    ] {
        let reply = f.get(&path, "synthetic-reader").await;
        assert_eq!(reply.0, 400, "{path}: {}", reply.1);
    }
    for path in [latest.into(), format!("{history}?address=192.0.2.20")] {
        let reply = f.get(&path, "synthetic-reader").await;
        assert_eq!(reply.0, 503, "{path}: {}", reply.1);
        assert!(reply.1["error"].as_str().unwrap().contains("native"));
    }
}

#[tokio::test]
async fn host_experience_reads_release_engine_lock_and_bound_concurrency() {
    use netcontrol_core::{Backend, Config, ExperienceRead, HostExperienceError};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    struct Slow {
        simulator: Simulator,
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<AtomicBool>,
    }
    impl Backend for Slow {
        fn scope(&self) -> anyhow::Result<String> {
            self.simulator.scope()
        }
        fn observe(&mut self, c: &Config) -> anyhow::Result<Config> {
            self.simulator.observe(c)
        }
        fn apply(&mut self, a: &Config, b: &Config) -> anyhow::Result<()> {
            self.simulator.apply(a, b)
        }
        fn runtime(&mut self, c: &Config) -> anyhow::Result<Value> {
            self.simulator.runtime(c)
        }
        fn statistics(&mut self, c: &Config, p: &str, q: &str) -> anyhow::Result<Value> {
            self.simulator.statistics(c, p, q)
        }
        fn repair(&mut self, c: &Config) -> anyhow::Result<Value> {
            self.simulator.repair(c)
        }
        fn prepare_host_experience(
            &mut self,
            _: &str,
            query: &str,
        ) -> anyhow::Result<ExperienceRead> {
            if query == "cursor=stale" {
                return Ok(Box::new(|| {
                    Err(HostExperienceError {
                        status: 409,
                        message: "expired fixture collection".into(),
                    }
                    .into())
                }));
            }
            if query == "cursor=oversize" {
                return Ok(Box::new(|| {
                    Ok(json!({"hosts":[],"oversized":"x".repeat(4<<20)}))
                }));
            }
            let started = self.started.clone();
            let release = self.release.clone();
            Ok(Box::new(move || {
                started.send(())?;
                let deadline = Instant::now() + Duration::from_secs(3);
                while !release.load(Ordering::Acquire) {
                    anyhow::ensure!(Instant::now() < deadline, "fixture experience read timeout");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(
                    json!({"schema":netcontrol_core::experience::SCHEMA,"hosts":[],"status":"starting"}),
                )
            }))
        }
    }
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(AtomicBool::new(false));
    let f = Fixture::with_backend(Box::new(Slow {
        simulator: Simulator::new(),
        started,
        release: release.clone(),
    }));
    let path = "/api/v1/statistics/host-experience/latest";
    let (a, b, c, d, ()) = tokio::join!(
        f.get(path, "synthetic-reader"),
        f.get(path, "synthetic-reader"),
        f.get(path, "synthetic-reader"),
        f.get(path, "synthetic-reader"),
        async {
            for _ in 0..4 {
                tokio::time::timeout(Duration::from_secs(2), starts.recv())
                    .await
                    .unwrap()
                    .unwrap();
            }
            assert!(
                f.app.engine.try_lock().is_ok(),
                "experience read held configuration engine lock"
            );
            let reply = f.get(path, "synthetic-reader").await;
            release.store(true, Ordering::Release);
            assert_eq!(reply.0, 429, "{}", reply.1);
        }
    );
    for reply in [a, b, c, d] {
        assert_eq!(reply.0, 200, "{}", reply.1);
    }
    assert_eq!(
        f.get(&format!("{path}?cursor=stale"), "synthetic-reader")
            .await
            .0,
        409
    );
    assert_eq!(
        f.get(&format!("{path}?cursor=oversize"), "synthetic-reader")
            .await
            .0,
        503
    );
}

#[tokio::test]
async fn path_test_http_auth_and_unsupported_backend_are_explicit() {
    let fixture = Fixture::new();
    let path = "/api/v1/diagnostics/path-tests";
    let body = json!({"interface":"lan0","source_address":"192.0.2.1","peer_address":"192.0.2.2",
        "maximum_mtu":9000,"pairing_secret":"synthetic-pairing-secret-1234567890"});
    assert_eq!(fixture.request("POST", path, body.clone(), "").await.0, 401);
    assert_eq!(
        fixture
            .request("POST", path, body.clone(), "synthetic-reader")
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .request("POST", path, body.clone(), "synthetic-operator")
            .await
            .0,
        403
    );
    assert_eq!(
        fixture
            .request("POST", path, json!({}), "synthetic-path-operator")
            .await
            .0,
        400
    );
    assert_eq!(
        fixture
            .request("POST", path, body, "synthetic-path-operator")
            .await
            .0,
        503
    );
}

#[tokio::test]
async fn operational_actions_auth_validation_and_simulated_dns_are_explicit() {
    let f = Fixture::new();
    for path in [
        "/api/v1/processes/restart",
        "/api/v1/diagnostics/dns-lookup",
    ] {
        assert_eq!(f.request("POST", path, json!({}), "").await.0, 401);
        assert_eq!(
            f.request("POST", path, json!({}), "synthetic-reader")
                .await
                .0,
            403
        );
        assert_eq!(
            f.request("GET", path, json!({}), "synthetic-operator")
                .await
                .0,
            405
        );
        assert_eq!(
            f.request(
                "POST",
                &format!("{path}?x=1"),
                json!({}),
                "synthetic-operator"
            )
            .await
            .0,
            400
        );
    }
    let path = "/api/v1/processes/restart";
    for (target, status) in [
        ("ntp", 409),
        ("1234", 404),
        ("mqtt", 503),
        ("netcontrold", 503),
    ] {
        assert_eq!(
            f.request("POST", path, json!({"target":target}), "synthetic-operator")
                .await
                .0,
            status,
            "{target}"
        );
    }
    assert_eq!(
        f.request(
            "POST",
            path,
            json!({"target":"ntp","pid":1234}),
            "synthetic-operator"
        )
        .await
        .0,
        400
    );
    let dns = "/api/v1/diagnostics/dns-lookup";
    let (status, value) = f
        .request(
            "POST",
            dns,
            json!({"interface":"wan0","hostname":"Google.COM."}),
            "synthetic-operator",
        )
        .await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["status"], "simulated");
    assert!(value["rtt_ms"].is_null());
    assert_eq!(value["hostname"], "google.com");
    assert_eq!(value["scope"], "simulator");
    assert_eq!(value["revision"], serde_json::json!(test_revision(0)));
    assert_eq!(
        f.app.engine.lock().unwrap().committed_revision(),
        test_revision(0)
    );
    for server in [json!("192.0.2.53"), json!("2001:db8::53"), Value::Null] {
        let (status, value) = f
            .request(
                "POST",
                dns,
                json!({"interface":"wan0","hostname":"example.test","server":server}),
                "synthetic-operator",
            )
            .await;
        assert_eq!(status, 200, "{value}");
        assert_eq!(value["status"], "simulated");
        assert!(value["server"].is_null());
        assert_eq!(value["revision"], serde_json::json!(test_revision(0)));
    }
    for body in [
        json!({"hostname":"example.test","server":"192.0.2.53"}),
        json!({"interface":null,"hostname":"example.test","server":"2001:db8::53"}),
    ] {
        let (status, value) = f.request("POST", dns, body, "synthetic-operator").await;
        assert_eq!(status, 200, "{value}");
        assert_eq!(value["status"], "simulated");
        assert!(value["interface"].is_null());
        assert!(value["rtt_ms"].is_null());
        assert_eq!(value["revision"], serde_json::json!(test_revision(0)));
    }
    for body in [
        json!({"hostname":"example.test"}),
        json!({"interface":null,"hostname":"example.test","server":null}),
        json!({"interface":"","hostname":"example.test","server":"192.0.2.53"}),
        json!({"interface":"wan0","hostname":"google.com","timeout_ms":5001}),
        json!({"interface":"wan0","hostname":"127.0.0.1"}),
        json!({"interface":"wan0","hostname":"google.com","record_type":"TXT"}),
        json!({"interface":"wan0","hostname":"google.com","server":"dns.example.test"}),
        json!({"interface":"wan0","hostname":"google.com","server":"192.0.2.53:5353"}),
        json!({"interface":"wan0","hostname":"google.com","server":"0.0.0.0"}),
        json!({"interface":"wan0","hostname":"google.com","server":"ff02::1"}),
        json!({"interface":"wan0","hostname":"google.com","server":53}),
        json!({"interface":"wan0","hostname":"google.com","resolver":"192.0.2.53"}),
    ] {
        assert_eq!(
            f.request("POST", dns, body, "synthetic-operator").await.0,
            400
        );
    }
}

#[tokio::test]
async fn daemon_restart_is_signalled_once_and_blocks_new_mutations() {
    let mut f = Fixture::new();
    let (signal, receiver) = tokio::sync::watch::channel(false);
    App::attach_processes(&mut f.app, Default::default(), Some(signal)).unwrap();
    let (status, value) = f
        .request(
            "POST",
            "/api/v1/processes/restart",
            json!({"target":"netcontrold"}),
            "synthetic-operator",
        )
        .await;
    assert_eq!(status, 202, "{value}");
    assert!(*receiver.borrow());
    assert!(f.app.engine.lock().unwrap().configuration_busy());
    for path in [
        "/api/v1/processes/restart",
        "/api/v1/diagnostics/dns-lookup",
    ] {
        assert_eq!(
            f.request("POST", path, json!({}), "synthetic-operator")
                .await
                .0,
            409
        );
    }
    assert_eq!(
        f.app.engine.lock().unwrap().committed_revision(),
        test_revision(0)
    );
}

#[tokio::test]
async fn dns_queries_release_engine_lock_and_enforce_concurrency_limit() {
    use netcontrol_core::{Backend, Config, DNSLookup, DNSLookupRequest};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    struct Slow {
        simulator: Simulator,
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: Arc<AtomicBool>,
    }
    impl Backend for Slow {
        fn scope(&self) -> anyhow::Result<String> {
            self.simulator.scope()
        }
        fn observe(&mut self, c: &Config) -> anyhow::Result<Config> {
            self.simulator.observe(c)
        }
        fn apply(&mut self, a: &Config, b: &Config) -> anyhow::Result<()> {
            self.simulator.apply(a, b)
        }
        fn runtime(&mut self, c: &Config) -> anyhow::Result<Value> {
            self.simulator.runtime(c)
        }
        fn statistics(&mut self, c: &Config, p: &str, q: &str) -> anyhow::Result<Value> {
            self.simulator.statistics(c, p, q)
        }
        fn repair(&mut self, c: &Config) -> anyhow::Result<Value> {
            self.simulator.repair(c)
        }
        fn prepare_dns_lookup(
            &mut self,
            _: &Config,
            _: &DNSLookupRequest,
        ) -> anyhow::Result<DNSLookup> {
            let started = self.started.clone();
            let release = self.release.clone();
            Ok(Box::new(move || {
                started.send(())?;
                let deadline = Instant::now() + Duration::from_secs(3);
                while !release.load(Ordering::Acquire) {
                    anyhow::ensure!(Instant::now() < deadline, "fixture DNS timeout");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(json!({"status":"simulated","rtt_ms":null}))
            }))
        }
    }
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(AtomicBool::new(false));
    let f = Fixture::with_backend(Box::new(Slow {
        simulator: Simulator::new(),
        started,
        release: release.clone(),
    }));
    let body = json!({"interface":"wan0","hostname":"example.test"});
    let path = "/api/v1/diagnostics/dns-lookup";
    let (first, second, ()) = tokio::join!(
        f.request("POST", path, body.clone(), "synthetic-operator"),
        f.request("POST", path, body.clone(), "synthetic-operator"),
        async {
            for _ in 0..2 {
                tokio::time::timeout(Duration::from_secs(2), starts.recv())
                    .await
                    .unwrap()
                    .unwrap();
            }
            assert!(
                f.app.engine.try_lock().is_ok(),
                "DNS query held configuration engine lock"
            );
            let reply = f
                .request("POST", path, body.clone(), "synthetic-operator")
                .await;
            release.store(true, Ordering::Release);
            assert_eq!(reply.0, 429, "{}", reply.1);
        }
    );
    assert_eq!(first.0, 200);
    assert_eq!(second.0, 200);
}

#[tokio::test]
async fn upgrade_maintenance_blocks_operational_actions() {
    let f = Fixture::new();
    f.app
        .engine
        .lock()
        .unwrap()
        .set_upgrade_maintenance(true)
        .unwrap();
    for path in [
        "/api/v1/processes/restart",
        "/api/v1/diagnostics/dns-lookup",
    ] {
        assert_eq!(
            f.request("POST", path, json!({}), "synthetic-operator")
                .await
                .0,
            409
        );
    }
}
