use crate::private_store::{read_private, write_private};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use netcontrol_core::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

const SYNC_INTERVAL: Duration = Duration::from_secs(3600);
const RESPONSE_LIMIT: usize = 4 << 20;
const CACHE_LIMIT: usize = 1 << 20;
const HOST_LIMIT: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    source_url: String,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    error: Option<String>,
    skipped_hosts: usize,
    hosts: Vec<Host>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    addresses: Vec<IpAddr>,
    host_name: Option<String>,
    icon: Option<String>,
    classification: Option<String>,
    threat_score: Option<i16>,
}

#[derive(Deserialize)]
struct Device {
    ip_address: Option<String>,
    ip6_address: Option<String>,
    dhcp_hostname: Option<String>,
    dns_hostname: Option<String>,
    lease_hostname: Option<String>,
    local_description: Option<String>,
    icon: Option<String>,
    threat_score: Option<i16>,
}

fn text(value: Option<String>, limit: usize) -> Result<Option<String>> {
    if let Some(value) = &value {
        ensure!(
            value.len() <= limit && !value.chars().any(char::is_control),
            "Sando text exceeds {limit} bytes or contains control characters"
        );
    }
    Ok(value.filter(|value| !value.trim().is_empty()))
}

fn is_mac(value: &str) -> bool {
    value.len() == 17
        && value.split(':').count() == 6
        && value
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn validate_host(host: &Host) -> Result<()> {
    ensure!(
        !host.addresses.is_empty()
            && host.addresses.len() <= 2
            && host.addresses.iter().collect::<BTreeSet<_>>().len() == host.addresses.len(),
        "Sando host requires one or two distinct IP addresses"
    );
    for address in &host.addresses {
        ensure!(
            !address.is_unspecified()
                && !address.is_multicast()
                && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast()),
            "Sando host requires unicast IP addresses"
        );
    }
    text(host.host_name.clone(), 255)?;
    text(host.icon.clone(), 128)?;
    text(host.classification.clone(), 512)?;
    ensure!(
        host.threat_score
            .is_none_or(|score| (-1..=100).contains(&score)),
        "Sando threat_score must be null or an integer in -1..100"
    );
    Ok(())
}

fn validate_hosts(hosts: &[Host]) -> Result<()> {
    ensure!(
        hosts.len() <= HOST_LIMIT,
        "Sando exceeds {HOST_LIMIT} hosts"
    );
    let mut addresses = BTreeSet::new();
    for host in hosts {
        validate_host(host)?;
        for address in &host.addresses {
            ensure!(
                addresses.insert(address),
                "Sando contains duplicate IP addresses"
            );
        }
    }
    Ok(())
}

fn project(bytes: &[u8]) -> Result<(Vec<Host>, usize)> {
    let devices: Vec<Device> = serde_json::from_slice(bytes).context("invalid Sando inventory")?;
    ensure!(
        devices.len() <= HOST_LIMIT,
        "Sando exceeds {HOST_LIMIT} hosts"
    );
    let mut hosts = Vec::new();
    let mut skipped = 0;
    for device in devices {
        let mut addresses = Vec::new();
        if let Some(value) = device.ip_address.filter(|value| !value.is_empty())
            && !is_mac(&value)
        {
            addresses.push(
                value
                    .parse::<IpAddr>()
                    .context("invalid Sando ip_address")?,
            );
        }
        if let Some(value) = device.ip6_address.filter(|value| !value.is_empty()) {
            let address = value
                .parse::<std::net::Ipv6Addr>()
                .context("invalid Sando ip6_address")?;
            if !addresses.contains(&IpAddr::V6(address)) {
                addresses.push(IpAddr::V6(address));
            }
        }
        if addresses.is_empty() {
            skipped += 1;
            continue;
        }
        let host = Host {
            addresses,
            host_name: text(device.dhcp_hostname, 255)?
                .or(text(device.dns_hostname, 255)?)
                .or(text(device.lease_hostname, 255)?),
            icon: text(device.icon, 128)?,
            classification: text(device.local_description, 512)?,
            threat_score: device.threat_score,
        };
        hosts.push(host);
    }
    validate_hosts(&hosts)?;
    Ok((hosts, skipped))
}

async fn fetch(client: &reqwest::Client, source: &str) -> Result<(Vec<Host>, usize)> {
    let mut response = client
        .get(format!("{}/api/localhosts", source.trim_end_matches('/')))
        .send()
        .await
        .context("Sando request failed")?;
    ensure!(
        response.status().is_success(),
        "Sando returned HTTP {}",
        response.status()
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= RESPONSE_LIMIT as u64),
        "Sando response exceeds {RESPONSE_LIMIT} bytes"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= RESPONSE_LIMIT,
            "Sando response exceeds {RESPONSE_LIMIT} bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    project(&bytes)
}

#[derive(Default)]
struct State {
    snapshot: Snapshot,
    syncing: bool,
    next_sync_at: Option<DateTime<Utc>>,
}

pub struct Manager {
    path: PathBuf,
    engine: Arc<Mutex<Engine>>,
    state: Mutex<State>,
}

impl Manager {
    pub fn open(path: &Path, engine: Arc<Mutex<Engine>>) -> Result<Arc<Self>> {
        crate::identity::secure_parent(path)?;
        let snapshot: Snapshot = if path.try_exists()? {
            serde_json::from_slice(&read_private(path)?).context("invalid Sando cache")?
        } else {
            Snapshot::default()
        };
        validate_hosts(&snapshot.hosts)?;
        ensure!(
            snapshot.skipped_hosts <= HOST_LIMIT,
            "invalid Sando skipped host count"
        );
        netcontrol_core::SandoConfig {
            api_url: snapshot.source_url.clone(),
            ..Default::default()
        }
        .validate()?;
        Ok(Arc::new(Self {
            path: path.into(),
            engine,
            state: Mutex::new(State {
                snapshot,
                ..Default::default()
            }),
        }))
    }

    pub fn status(&self) -> Result<Value> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        let config = &engine.saved_configuration().sando;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
        let empty = Snapshot {
            source_url: config.api_url.clone(),
            ..Default::default()
        };
        let snapshot = if state.snapshot.source_url == config.api_url {
            &state.snapshot
        } else {
            &empty
        };
        let status = if !config.sync_enabled {
            "disabled"
        } else if state.syncing && state.snapshot.source_url == config.api_url {
            "syncing"
        } else if snapshot.error.is_some() {
            "error"
        } else if snapshot.last_success_at.is_some() {
            "succeeded"
        } else {
            "pending"
        };
        let mut result = serde_json::to_value(snapshot)?;
        result["enabled"] = json!(config.sync_enabled);
        result["state"] = json!(status);
        result["sync_interval_seconds"] = json!(SYNC_INTERVAL.as_secs());
        result["next_sync_at"] = json!(if config.sync_enabled
            && snapshot.source_url == state.snapshot.source_url
        {
            state.next_sync_at
        } else {
            None
        });
        Ok(result)
    }

    fn source(&self) -> Result<(String, bool)> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        let config = &engine.saved_configuration().sando;
        Ok((config.api_url.clone(), config.sync_enabled))
    }

    fn finish(&self, source: &str, result: Result<(Vec<Host>, usize)>) -> Result<()> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        let config = &engine.saved_configuration().sando;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
        state.syncing = false;
        if !config.sync_enabled || config.api_url != source {
            return Ok(());
        }
        let now: DateTime<Utc> = std::time::SystemTime::now().into();
        if state.snapshot.source_url != source {
            state.snapshot = Snapshot {
                source_url: source.into(),
                ..Default::default()
            };
        }
        let mut next = state.snapshot.clone();
        next.last_attempt_at = Some(now);
        match result {
            Ok((hosts, skipped)) => {
                next.hosts = hosts;
                next.skipped_hosts = skipped;
                next.last_success_at = Some(now);
                next.error = None;
            }
            Err(error) => {
                tracing::warn!(%error, "Sando sync failed");
                next.error = Some(format!("Sando sync failed: {error:#}"));
            }
        }
        let saved = (|| -> Result<()> {
            let bytes = serde_json::to_vec(&next)?;
            ensure!(
                bytes.len() <= CACHE_LIMIT,
                "Sando cache exceeds {CACHE_LIMIT} bytes"
            );
            write_private(&self.path, &bytes)
        })();
        match saved {
            Ok(()) => state.snapshot = next,
            Err(error) => {
                tracing::error!(%error, "could not persist Sando sync");
                state.snapshot.last_attempt_at = Some(now);
                state.snapshot.error = Some(format!("Could not persist Sando sync: {error:#}"));
            }
        }
        state.next_sync_at = Some(now + chrono::TimeDelta::seconds(SYNC_INTERVAL.as_secs() as i64));
        Ok(())
    }

    pub async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) -> Result<()> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("netcontrol-sando-sync")
            .build()?;
        let result = self
            .worker(stop, move |source| {
                let client = client.clone();
                async move { fetch(&client, &source).await }
            })
            .await;
        if let Err(error) = &result {
            tracing::error!(%error, "Sando sync worker stopped");
        }
        result
    }

    async fn worker<F, Fut>(&self, mut stop: watch::Receiver<bool>, mut acquire: F) -> Result<()>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<(Vec<Host>, usize)>>,
    {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous = None;
        let mut due = Instant::now();
        let mut request = None;
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                _ = tick.tick() => {
                    let source = self.source()?;
                    if previous.as_ref() != Some(&source) {
                        request = None;
                        due = Instant::now();
                        let mut state = self.state.lock().map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
                        state.syncing = false;
                        state.next_sync_at = None;
                        if state.snapshot.source_url != source.0 {
                            state.snapshot = Snapshot { source_url: source.0.clone(), ..Default::default() };
                        }
                        previous = Some(source.clone());
                    }
                    if source.1 && request.is_none() && Instant::now() >= due {
                        let mut state = self.state.lock().map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
                        state.syncing = true;
                        state.next_sync_at = None;
                        request = Some(Box::pin(acquire(source.0)));
                    }
                }
                result = async { request.as_mut().expect("guarded Sando request").await }, if request.is_some() => {
                    request = None;
                    self.finish(&previous.as_ref().context("Sando source missing")?.0, result)?;
                    due = Instant::now() + SYNC_INTERVAL;
                }
            }
        }
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?
            .syncing = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn inventory() -> Vec<u8> {
        serde_json::to_vec(&json!([{
            "ip_address":"192.0.2.10", "ip6_address":"2001:db8::10",
            "dhcp_hostname":"camera.test", "dns_hostname":"dns.test",
            "lease_hostname":"lease.test", "icon":"camera_icon",
            "local_description":"Camera", "threat_score":-1,
            "tags":["unrelated"], "whitelisted":1
        }]))
        .unwrap()
    }

    fn fixture() -> (tempfile::TempDir, Arc<Manager>) {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager = Manager::open(&directory.path().join("sando.json"), engine).unwrap();
        (directory, manager)
    }

    fn stage(manager: &Manager, url: &str, enabled: bool) -> String {
        let mut engine = manager.engine.lock().unwrap();
        let mut config = engine.saved_configuration().clone();
        if config.interfaces.is_empty() {
            config.interfaces = serde_json::from_value(json!([{
                "name":"lan0","kind":"dummy","role":"lan","mtu":1500,
                "up":true,"addresses":["192.0.2.1/24"]
            }]))
            .unwrap();
        }
        config.sando.api_url = url.into();
        config.sando.sync_enabled = enabled;
        let base = engine.committed_revision();
        let reply = engine.request(
            "POST",
            "/api/v1/transactions",
            "",
            "test",
            &netcontrol_core::PERMISSIONS
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
            &serde_json::to_vec(
                &json!({"base_revision":base,"confirm_timeout_seconds":30,"config":config}),
            )
            .unwrap(),
        );
        assert_eq!(reply.status, 202, "{}", reply.body);
        reply.body["id"].as_str().unwrap().into()
    }

    fn complete(manager: &Manager, id: &str, action: &str) {
        let reply = manager.engine.lock().unwrap().request(
            "POST",
            &format!("/api/v1/transactions/{id}/{action}"),
            "",
            "test",
            &netcontrol_core::PERMISSIONS
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
            &[],
        );
        assert_eq!(reply.status, 200, "{}", reply.body);
    }

    fn configure(manager: &Manager, url: &str, enabled: bool) {
        complete(manager, &stage(manager, url, enabled), "confirm");
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn inventory_projection_preserves_classification_and_unknown_threat_score() {
        let (hosts, skipped) = project(&inventory()).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(hosts[0].host_name.as_deref(), Some("camera.test"));
        assert_eq!(hosts[0].icon.as_deref(), Some("camera_icon"));
        assert_eq!(hosts[0].classification.as_deref(), Some("Camera"));
        assert_eq!(hosts[0].threat_score, Some(-1));
        assert_eq!(hosts[0].addresses.len(), 2);
        let (hosts, skipped) = project(&serde_json::to_vec(&json!([
                                {"ip_address":"AA:BB:CC:DD:EE:FF"},
                                {"ip_address":null},
                                {"ip_address":"192.0.2.20","dhcp_hostname":"","dns_hostname":"dns.test","threat_score":0},
                                {"ip6_address":"2001:db8::30","lease_hostname":"lease.test","threat_score":null}
                            ])).unwrap()).unwrap();
        assert_eq!(skipped, 2);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host_name.as_deref(), Some("dns.test"));
        assert_eq!(hosts[0].threat_score, Some(0));
        assert_eq!(hosts[1].host_name.as_deref(), Some("lease.test"));
        assert_eq!(hosts[1].threat_score, None);
    }

    #[test]
    fn inventory_rejects_malformed_ambiguous_or_unbounded_metadata() {
        let baseline: Value = serde_json::from_slice(&inventory()).unwrap();
        for (field, invalid) in [
            ("ip_address", json!("not-an-ip")),
            ("ip_address", json!("224.0.0.1")),
            ("ip6_address", json!("192.0.2.10")),
            ("threat_score", json!(-2)),
            ("threat_score", json!(101)),
            ("threat_score", json!(1.5)),
            ("threat_score", json!("10")),
            ("icon", json!(5)),
            ("icon", json!("x".repeat(129))),
            ("local_description", json!("x".repeat(513))),
            ("dhcp_hostname", json!("bad\nname")),
        ] {
            let mut value = baseline.clone();
            value[0][field] = invalid;
            assert!(
                project(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{field}"
            );
        }
        assert!(project(b"{}").is_err());
        assert!(project(b"{malformed").is_err());
        assert!(project(&serde_json::to_vec(&json!([baseline[0], baseline[0]])).unwrap()).is_err());
        assert!(project(&serde_json::to_vec(&vec![json!({}); HOST_LIMIT + 1]).unwrap()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn hourly_sync_observes_only_confirmed_settings_and_preserves_firewall_and_revisions() {
        let (_directory, manager) = fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let (stop, receiver) = watch::channel(false);
        let task_manager = manager.clone();
        let worker = tokio::spawn(async move {
            task_manager
                .worker(receiver, move |_| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(project(&inventory()))
                })
                .await
        });
        settle().await;
        tokio::time::advance(SYNC_INTERVAL * 2).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let id = stage(&manager, "http://sando.example.test/proxy", true);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        complete(&manager, &id, "rollback");
        configure(&manager, "http://sando.example.test/proxy", true);
        let before = manager.engine.lock().unwrap().saved_configuration().clone();
        let revision = manager.engine.lock().unwrap().committed_revision();
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(manager.status().unwrap()["state"], "succeeded");
        assert_eq!(manager.status().unwrap()["hosts"][0]["threat_score"], -1);
        tokio::time::advance(SYNC_INTERVAL - Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            manager.engine.lock().unwrap().committed_revision(),
            revision
        );
        assert_eq!(
            *manager.engine.lock().unwrap().saved_configuration(),
            before
        );
        configure(&manager, "http://sando.example.test/proxy", false);
        tokio::time::advance(SYNC_INTERVAL * 2).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(manager.status().unwrap()["state"], "disabled");
        assert_eq!(
            manager.status().unwrap()["hosts"].as_array().unwrap().len(),
            1
        );
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
    }

    #[test]
    fn successful_snapshot_is_durable_and_failed_or_stale_syncs_do_not_replace_it() {
        let (_directory, manager) = fixture();
        configure(&manager, "http://sando.example.test", true);
        manager
            .finish("http://sando.example.test", project(&inventory()))
            .unwrap();
        let success = manager.status().unwrap();
        manager
            .finish(
                "http://sando.example.test",
                Err(anyhow::anyhow!("synthetic failure")),
            )
            .unwrap();
        let error = manager.status().unwrap();
        assert_eq!(error["state"], "error");
        assert_eq!(error["hosts"], success["hosts"]);
        assert_eq!(error["last_success_at"], success["last_success_at"]);
        assert!(
            error["error"]
                .as_str()
                .unwrap()
                .contains("synthetic failure")
        );
        let reopened = Manager::open(&manager.path, manager.engine.clone()).unwrap();
        assert_eq!(reopened.status().unwrap()["hosts"], success["hosts"]);
        assert_eq!(reopened.status().unwrap()["state"], "error");
        configure(&manager, "http://other.example.test", true);
        manager
            .finish("http://sando.example.test", project(&inventory()))
            .unwrap();
        let changed = manager.status().unwrap();
        assert!(changed["hosts"].as_array().unwrap().is_empty());
        assert_eq!(changed["state"], "pending");
        assert!(changed["last_success_at"].is_null());
        configure(&manager, "http://other.example.test", false);
        manager
            .finish("http://other.example.test", project(&inventory()))
            .unwrap();
        assert!(
            manager.status().unwrap()["hosts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disable_source_changes_and_shutdown_cancel_inflight_syncs() {
        let (_directory, manager) = fixture();
        configure(&manager, "http://first.example.test", true);
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let (stop, receiver) = watch::channel(false);
        let task_manager = manager.clone();
        let worker = tokio::spawn(async move {
            task_manager
                .worker(receiver, move |_| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    std::future::pending()
                })
                .await
        });
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(manager.status().unwrap()["state"], "syncing");
        configure(&manager, "http://second.example.test", true);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            manager.status().unwrap()["source_url"],
            "http://second.example.test"
        );
        configure(&manager, "http://second.example.test", false);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert!(!manager.state.lock().unwrap().syncing);
        configure(&manager, "http://second.example.test", true);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
        assert!(!manager.state.lock().unwrap().syncing);
        assert!(manager.status().unwrap()["last_success_at"].is_null());
    }

    #[test]
    fn persistence_errors_and_corrupt_caches_are_explicit() {
        let (_directory, manager) = fixture();
        configure(&manager, "http://sando.example.test", true);
        std::fs::create_dir(&manager.path).unwrap();
        manager
            .finish("http://sando.example.test", project(&inventory()))
            .unwrap();
        let status = manager.status().unwrap();
        assert_eq!(status["state"], "error");
        assert!(status["error"].as_str().unwrap().contains("persist"));
        assert!(status["hosts"].as_array().unwrap().is_empty());
        assert!(status["last_success_at"].is_null());
        std::fs::remove_dir(&manager.path).unwrap();
        write_private(&manager.path, b"{corrupt").unwrap();
        assert!(Manager::open(&manager.path, manager.engine.clone()).is_err());
    }

    #[tokio::test]
    async fn http_sync_preserves_proxy_prefix_and_rejects_redirects_errors_and_large_bodies() {
        use axum::{Router, routing::get};
        let app = Router::new()
            .route("/prefix/api/localhosts", get(|| async { inventory() }))
            .route(
                "/redirect/api/localhosts",
                get(|| async { axum::response::Redirect::temporary("/prefix/api/localhosts") }),
            )
            .route(
                "/error/api/localhosts",
                get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/large/api/localhosts",
                get(|| async { vec![b' '; RESPONSE_LIMIT + 1] }),
            )
            .route(
                "/limit/api/localhosts",
                get(|| async {
                    let mut bytes = inventory();
                    bytes.resize(RESPONSE_LIMIT, b' ');
                    bytes
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let (hosts, _) = fetch(&client, &format!("http://{address}/prefix/"))
            .await
            .unwrap();
        assert_eq!(hosts[0].host_name.as_deref(), Some("camera.test"));
        assert!(
            fetch(&client, &format!("http://{address}/limit"))
                .await
                .is_ok()
        );
        for path in ["redirect", "error", "large"] {
            assert!(
                fetch(&client, &format!("http://{address}/{path}"))
                    .await
                    .is_err(),
                "{path}"
            );
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn chunked_response_limit_is_enforced_without_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() <= 4096);
                }
                socket.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            ).await.unwrap();
                let chunk = vec![b' '; 65536];
                for _ in 0..=(RESPONSE_LIMIT / chunk.len()) {
                    if socket.write_all(b"10000\r\n").await.is_err()
                        || socket.write_all(&chunk).await.is_err()
                        || socket.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                }
                let _ = socket.write_all(b"0\r\n\r\n").await;
            });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let error = fetch(&client, &format!("http://{address}"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error:#}");
        server.await.unwrap();
    }
}
