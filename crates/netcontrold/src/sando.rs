use crate::private_store::{read_private, write_private};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use netcontrol_core::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

const SYNC_INTERVAL: Duration = Duration::from_secs(3600);
const POLICY_INTERVAL: Duration = Duration::from_secs(300);
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
    let response = client
        .get(format!("{}/api/localhosts", source.trim_end_matches('/')))
        .send()
        .await
        .context("Sando request failed")?;
    ensure!(
        response.status().is_success(),
        "Sando returned HTTP {}",
        response.status()
    );
    project(&response_bytes(response).await?)
}

async fn response_bytes(mut response: reqwest::Response) -> Result<Vec<u8>> {
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
    Ok(bytes)
}

#[derive(Debug)]
enum PolicyFetch {
    Unchanged,
    List { etag: String, entries: Vec<Value> },
}

async fn fetch_policies(
    client: &reqwest::Client,
    source: &str,
    etag: Option<&str>,
) -> Result<PolicyFetch> {
    let mut request = client.get(format!("{}/api/ignorelist", source.trim_end_matches('/')));
    if let Some(etag) = etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let response = request
        .send()
        .await
        .context("Sando policy request failed")?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        ensure!(
            etag.is_some(),
            "Sando returned 304 without a conditional request"
        );
        if let Some(returned) = response.headers().get(reqwest::header::ETAG) {
            ensure!(
                Some(returned.to_str()?) == etag,
                "Sando returned a mismatched 304 ETag"
            );
        }
        return Ok(PolicyFetch::Unchanged);
    }
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Sando policies returned HTTP {}",
        response.status()
    );
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .context("Sando policies require an ETag")?
        .to_str()?
        .to_owned();
    let tag = etag.strip_prefix("W/").unwrap_or(&etag);
    ensure!(
        etag.len() <= 512
            && tag.starts_with('"')
            && tag.ends_with('"')
            && tag.len() >= 2
            && tag.as_bytes()[1..tag.len() - 1]
                .iter()
                .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte)),
        "invalid Sando policy ETag"
    );
    let entries: Vec<Value> = serde_json::from_slice(&response_bytes(response).await?)
        .context("invalid Sando policy list")?;
    ensure!(entries.len() <= 4096, "Sando exceeds 4096 policy entries");
    Ok(PolicyFetch::List { etag, entries })
}

#[derive(Default, Serialize)]
struct PolicyState {
    source_url: String,
    etag: Option<String>,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    next_sync_at: Option<DateTime<Utc>>,
    error: Option<String>,
    imported_count: u32,
    skipped_count: u32,
    last_changed_revision: Option<netcontrol_core::Version>,
    #[serde(skip)]
    syncing: bool,
}

type PolicySource = (String, bool, Vec<netcontrol_core::FirewallHost>, bool);

fn policy_source(config: &netcontrol_core::Config) -> PolicySource {
    (
        config.sando.api_url.clone(),
        config.sando.policy_sync_enabled,
        config
            .firewall
            .policies
            .as_ref()
            .map(|policies| policies.hosts.clone())
            .unwrap_or_default(),
        config.ipv6_enabled,
    )
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
    policies: Mutex<PolicyState>,
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
            policies: Mutex::new(PolicyState::default()),
        }))
    }

    pub fn status(&self) -> Result<Value> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        let config = &engine.saved_configuration().sando;
        self.status_for(config, true)
    }

    pub(crate) fn mqtt_status(&self, config: &netcontrol_core::SandoConfig) -> Result<Value> {
        self.status_for(config, false)
    }

    pub(crate) fn local_descriptions(
        &self,
        config: &netcontrol_core::SandoConfig,
    ) -> Result<BTreeMap<IpAddr, String>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
        let mut names = BTreeMap::new();
        if state.snapshot.source_url == config.api_url {
            for host in &state.snapshot.hosts {
                if let Some(name) = &host.classification {
                    for address in &host.addresses {
                        names.insert(*address, name.clone());
                    }
                }
            }
        }
        Ok(names)
    }

    pub(crate) fn host_experience_metadata(
        &self,
        config: &netcontrol_core::SandoConfig,
    ) -> Result<BTreeMap<IpAddr, Value>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
        let snapshot = &state.snapshot;
        if snapshot.source_url != config.api_url || snapshot.last_success_at.is_none() {
            return Ok(BTreeMap::new());
        }
        let stale = snapshot.error.is_some()
            || snapshot
                .last_success_at
                .is_some_and(|at| Utc::now().signed_duration_since(at).num_seconds() > 7200);
        let mut result = BTreeMap::new();
        for host in &snapshot.hosts {
            let value = json!({
                "host_name":host.host_name,"icon":host.icon,"classification":host.classification,
                "status":if stale{"stale"}else{"available"},
                "last_success_at":snapshot.last_success_at,"error":snapshot.error
            });
            for ip in &host.addresses {
                result.insert(*ip, value.clone());
            }
        }
        Ok(result)
    }

    fn status_for(
        &self,
        config: &netcontrol_core::SandoConfig,
        include_hosts: bool,
    ) -> Result<Value> {
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
        let mut result = if include_hosts {
            serde_json::to_value(snapshot)?
        } else {
            json!({
                "last_attempt_at":snapshot.last_attempt_at,
                "last_success_at":snapshot.last_success_at,
                "host_count":snapshot.hosts.len(),
                "skipped_hosts":snapshot.skipped_hosts
            })
        };
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
        if !include_hosts {
            return Ok(result);
        }
        let policies = self
            .policies
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando policy status unavailable"))?;
        let empty = PolicyState {
            source_url: config.api_url.clone(),
            ..Default::default()
        };
        let policies = if policies.source_url == config.api_url {
            &*policies
        } else {
            &empty
        };
        let mut policy_status = serde_json::to_value(policies)?;
        policy_status["enabled"] = json!(config.policy_sync_enabled);
        policy_status["state"] = json!(if !config.policy_sync_enabled {
            "disabled"
        } else if policies.syncing {
            "syncing"
        } else if policies.error.is_some() {
            "error"
        } else if policies.last_success_at.is_some() {
            "succeeded"
        } else {
            "pending"
        });
        policy_status["sync_interval_seconds"] = json!(POLICY_INTERVAL.as_secs());
        if !config.policy_sync_enabled {
            policy_status["next_sync_at"] = Value::Null;
        }
        result["policies"] = policy_status;
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
        let hosts = self.worker(stop.clone(), {
            let client = client.clone();
            move |source| {
                let client = client.clone();
                async move { fetch(&client, &source).await }
            }
        });
        let result = tokio::try_join!(hosts, self.policy_worker(stop, client)).map(|_| ());
        if let Err(error) = &result {
            tracing::error!(%error, "Sando sync worker stopped");
        }
        result
    }

    fn policy_source(&self) -> Result<PolicySource> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        let config = engine.saved_configuration();
        Ok(policy_source(config))
    }

    fn finish_policies(
        &self,
        source: &PolicySource,
        result: Result<PolicyFetch>,
    ) -> Result<PolicySource> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        let config = engine.saved_configuration();
        let current = policy_source(config);
        if !current.1 || &current != source {
            return Ok(source.clone());
        }
        let mut policies = self
            .policies
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando policy status unavailable"))?;
        policies.syncing = false;
        let applied = match result {
            Ok(PolicyFetch::Unchanged) => Ok(()),
            Ok(PolicyFetch::List { etag, entries }) => {
                engine.sync_sando_policies(&source.0, &entries).map(|outcome| {
                    if outcome.skipped_count > 0 {
                        tracing::warn!(skipped_count = outcome.skipped_count, "Sando policy entries skipped");
                    }
                    policies.imported_count = outcome.imported_count;
                    policies.skipped_count = outcome.skipped_count;
                    policies.etag = Some(etag);
                    if outcome.changed {
                        policies.last_changed_revision = Some(engine.committed_revision());
                        tracing::info!(revision = %engine.committed_revision(), "Sando policies automatically committed");
                    }
                })
            }
            Err(error) => Err(error),
        };
        let now = Utc::now();
        policies.last_attempt_at = Some(now);
        policies.next_sync_at =
            Some(now + chrono::TimeDelta::seconds(POLICY_INTERVAL.as_secs() as i64));
        match applied {
            Ok(()) => {
                policies.last_success_at = Some(now);
                policies.error = None;
            }
            Err(error) => {
                tracing::warn!(%error, "Sando automatic policy sync failed");
                policies.error = Some(format!("Sando automatic policy sync failed: {error:#}"));
            }
        }
        let config = engine.saved_configuration();
        Ok(policy_source(config))
    }

    async fn policy_worker(
        self: &Arc<Self>,
        mut stop: watch::Receiver<bool>,
        client: reqwest::Client,
    ) -> Result<()> {
        let mut changes = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?
            .subscribe_configuration();
        let mut previous = None;
        let mut due = Instant::now();
        let mut request = None;
        loop {
            if *stop.borrow() {
                break;
            }
            let source = self.policy_source()?;
            if previous.as_ref() != Some(&source) {
                request = None;
                due = Instant::now();
                let mut policies = self
                    .policies
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Sando policy status unavailable"))?;
                if policies.source_url != source.0 {
                    *policies = PolicyState {
                        source_url: source.0.clone(),
                        ..Default::default()
                    };
                }
                policies.etag = None;
                policies.syncing = false;
                policies.next_sync_at = None;
                previous = Some(source.clone());
            }
            if source.1 && request.is_none() && Instant::now() >= due {
                let mut policies = self
                    .policies
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Sando policy status unavailable"))?;
                policies.syncing = true;
                policies.next_sync_at = None;
                let client = client.clone();
                let etag = policies.etag.clone();
                let url = source.0.clone();
                request = Some(Box::pin(async move {
                    fetch_policies(&client, &url, etag.as_deref()).await
                }));
            }
            let deadline = (source.1 && request.is_none()).then_some(due);
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                changed = changes.changed() => { changed.context("configuration notifications closed")?; }
                _ = crate::wait_until(deadline) => {}
                result = async { request.as_mut().expect("guarded Sando policy request").await }, if request.is_some() => {
                    request = None;
                    let manager = self.clone();
                    let source = source.clone();
                    previous = Some(tokio::task::spawn_blocking(move || manager.finish_policies(&source, result)).await??);
                    due = Instant::now() + POLICY_INTERVAL;
                }
            }
        }
        let mut policies = self
            .policies
            .lock()
            .map_err(|_| anyhow::anyhow!("Sando policy status unavailable"))?;
        policies.syncing = false;
        policies.next_sync_at = None;
        Ok(())
    }

    async fn worker<F, Fut>(&self, mut stop: watch::Receiver<bool>, mut acquire: F) -> Result<()>
    where
        F: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<(Vec<Host>, usize)>>,
    {
        let mut changes = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?
            .subscribe_configuration();
        let mut previous = None;
        let mut due = Instant::now();
        let mut request = None;
        loop {
            if *stop.borrow() {
                break;
            }
            let source = self.source()?;
            if previous.as_ref() != Some(&source) {
                request = None;
                due = Instant::now();
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
                state.syncing = false;
                state.next_sync_at = None;
                if state.snapshot.source_url != source.0 {
                    state.snapshot = Snapshot {
                        source_url: source.0.clone(),
                        ..Default::default()
                    };
                }
                previous = Some(source.clone());
            }
            if source.1 && request.is_none() && Instant::now() >= due {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Sando status unavailable"))?;
                state.syncing = true;
                state.next_sync_at = None;
                request = Some(Box::pin(acquire(source.0)));
            }
            let deadline = (source.1 && request.is_none()).then_some(due);
            tokio::select! {
                biased;
                _ = stop.changed() => break,
                changed = changes.changed() => { changed.context("configuration notifications closed")?; }
                _ = crate::wait_until(deadline) => {}
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

    fn configure_policies(manager: &Manager, url: &str, enabled: bool) {
        configure(manager, url, false);
        let mut engine = manager.engine.lock().unwrap();
        let mut config = engine.saved_configuration().clone();
        config.sando.policy_sync_enabled = enabled;
        if config.firewall.policies.is_none() {
            config.firewall.policies = Some(serde_json::from_value(json!({"hosts":[{
                "id":"camera","name":"Camera","addresses":["192.0.2.10"],"policy":"drop","rules":[]
            }]})).unwrap());
        }
        let revision = engine.committed_revision();
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
                &json!({"base_revision":revision,"confirm_timeout_seconds":30,"config":config}),
            )
            .unwrap(),
        );
        assert_eq!(reply.status, 202, "{}", reply.body);
        let id = reply.body["id"].as_str().unwrap().to_owned();
        drop(engine);
        complete(manager, &id, "confirm");
    }

    fn policy_entries(port: u16) -> Vec<Value> {
        vec![
            json!({"ignorelist_id":"synthetic","src_ip":"192.0.2.10","dst_ip":"198.51.100.20","protocol":6,"dst_port":port}),
        ]
    }

    #[tokio::test]
    async fn policy_http_etags_cover_initial_unchanged_edit_empty_and_errors() {
        use axum::{
            Router,
            http::{HeaderMap, StatusCode},
            routing::get,
        };
        let upstream = Arc::new(Mutex::new((
            "\"one\"".to_string(),
            json!(policy_entries(443)),
        )));
        let server_state = upstream.clone();
        let app = Router::new()
            .route(
                "/prefix/api/ignorelist",
                get(move |headers: HeaderMap| {
                    let state = server_state.clone();
                    async move {
                        let state = state.lock().unwrap();
                        let status = if headers
                            .get("if-none-match")
                            .is_some_and(|value| value == state.0.as_str())
                        {
                            StatusCode::NOT_MODIFIED
                        } else {
                            StatusCode::OK
                        };
                        (
                            status,
                            [("etag", state.0.clone())],
                            if status == StatusCode::OK {
                                state.1.to_string()
                            } else {
                                String::new()
                            },
                        )
                    }
                }),
            )
            .route("/missing/api/ignorelist", get(|| async { "[]" }))
            .route(
                "/bad/api/ignorelist",
                get(|| async { ([("etag", "\"bad\"")], "{}") }),
            )
            .route(
                "/large/api/ignorelist",
                get(|| async { ([("etag", "\"large\"")], vec![b' '; RESPONSE_LIMIT + 1]) }),
            )
            .route(
                "/error/api/ignorelist",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/redirect/api/ignorelist",
                get(|| async { axum::response::Redirect::temporary("/prefix/api/ignorelist") }),
            )
            .route(
                "/unsolicited/api/ignorelist",
                get(|| async { StatusCode::NOT_MODIFIED }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let (_directory, manager) = fixture();
        let url = format!("http://{address}/prefix/");
        configure_policies(&manager, &url, true);
        manager.policies.lock().unwrap().source_url = url.clone();
        let mut previous_revision = manager.engine.lock().unwrap().committed_revision();
        for (etag, entries, changed) in [
            ("\"one\"", policy_entries(443), true),
            ("\"two\"", policy_entries(80), true),
            ("\"three\"", vec![], true),
            ("\"four\"", vec![], false),
        ] {
            *upstream.lock().unwrap() = (etag.into(), json!(entries));
            let source = manager.policy_source().unwrap();
            let prior_tag = manager.policies.lock().unwrap().etag.clone();
            let fetched = fetch_policies(&client, &url, prior_tag.as_deref())
                .await
                .unwrap();
            manager.finish_policies(&source, Ok(fetched)).unwrap();
            let revision = manager.engine.lock().unwrap().committed_revision();
            assert_eq!(revision != previous_revision, changed);
            assert_eq!(manager.status().unwrap()["policies"]["etag"], etag);
            let unchanged = fetch_policies(&client, &url, Some(etag)).await.unwrap();
            assert!(matches!(unchanged, PolicyFetch::Unchanged));
            manager
                .finish_policies(&manager.policy_source().unwrap(), Ok(unchanged))
                .unwrap();
            assert_eq!(
                manager.engine.lock().unwrap().committed_revision(),
                revision
            );
            previous_revision = revision;
        }
        for path in [
            "missing",
            "bad",
            "large",
            "error",
            "redirect",
            "unsolicited",
        ] {
            assert!(
                fetch_policies(&client, &format!("http://{address}/{path}"), None)
                    .await
                    .is_err(),
                "{path}"
            );
        }
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn policy_conflicts_and_obsolete_results_never_advance_the_validator() {
        let (directory, manager) = fixture();
        let source = "http://sando.example.test";
        configure_policies(&manager, source, true);
        manager.policies.lock().unwrap().source_url = source.into();
        let key = manager.policy_source().unwrap();
        let pending = stage(&manager, source, false);
        manager
            .finish_policies(
                &key,
                Ok(PolicyFetch::List {
                    etag: "\"one\"".into(),
                    entries: policy_entries(443),
                }),
            )
            .unwrap();
        assert!(manager.policies.lock().unwrap().etag.is_none());
        assert_eq!(manager.status().unwrap()["policies"]["state"], "error");
        complete(&manager, &pending, "rollback");
        manager
            .finish_policies(
                &key,
                Ok(PolicyFetch::List {
                    etag: "\"one\"".into(),
                    entries: policy_entries(443),
                }),
            )
            .unwrap();
        assert_eq!(manager.status().unwrap()["policies"]["state"], "succeeded");
        let revision = manager.engine.lock().unwrap().committed_revision();
        configure_policies(&manager, source, false);
        manager
            .finish_policies(
                &key,
                Ok(PolicyFetch::List {
                    etag: "\"two\"".into(),
                    entries: vec![],
                }),
            )
            .unwrap();
        let config = manager.engine.lock().unwrap().saved_configuration().clone();
        assert_eq!(config.firewall.policies.unwrap().hosts[0].rules.len(), 1);
        assert_eq!(
            manager.policies.lock().unwrap().etag.as_deref(),
            Some("\"one\"")
        );
        let reopened =
            Manager::open(&directory.path().join("sando.json"), manager.engine.clone()).unwrap();
        assert!(reopened.policies.lock().unwrap().etag.is_none());
        assert_ne!(
            manager.engine.lock().unwrap().committed_revision(),
            revision
        );
    }

    #[tokio::test]
    async fn policy_worker_runs_independently_every_five_minutes_and_stops() {
        use axum::{Router, http::HeaderMap, routing::get};
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = calls.clone();
        let app = Router::new().route(
            "/api/ignorelist",
            get(move |headers: HeaderMap| {
                let attempt = requests.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        assert!(headers.get("if-none-match").is_none());
                    } else {
                        assert_eq!(headers["if-none-match"], "\"one\"");
                    }
                    (
                        [("etag", "\"one\"")],
                        serde_json::to_string(&policy_entries(443)).unwrap(),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (_directory, manager) = fixture();
        let url = format!("http://{address}");
        configure_policies(&manager, &url, true);
        let (stop, receiver) = watch::channel(false);
        let worker = tokio::spawn(manager.clone().run(receiver));
        async fn wait_success(manager: &Manager) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while manager.status().unwrap()["policies"]["state"] != "succeeded" {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        wait_success(&manager).await;
        settle().await;
        assert_eq!(manager.status().unwrap()["state"], "disabled");
        let revision = manager.engine.lock().unwrap().committed_revision();
        tokio::time::pause();
        tokio::time::advance(POLICY_INTERVAL - Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(5), async {
            while calls.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        wait_success(&manager).await;
        assert_eq!(
            manager.engine.lock().unwrap().committed_revision(),
            revision
        );
        configure_policies(&manager, &url, false);
        tokio::time::pause();
        settle().await;
        tokio::time::advance(POLICY_INTERVAL * 2).await;
        settle().await;
        tokio::time::resume();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
        assert!(!manager.policies.lock().unwrap().syncing);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn policy_source_changes_disable_and_shutdown_cancel_inflight_acquisition() {
        use axum::{Router, routing::get};
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = calls.clone();
        let app = Router::new()
            .route(
                "/slow/api/ignorelist",
                get(move || {
                    requests.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<String>()
                }),
            )
            .route(
                "/current/api/ignorelist",
                get(|| async { ([("etag", "\"current\"")], "[]") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (_directory, manager) = fixture();
        let slow = format!("http://{address}/slow");
        configure_policies(&manager, &slow, true);
        let (stop, receiver) = watch::channel(false);
        let worker = tokio::spawn(manager.clone().run(receiver));
        async fn wait_for(mut condition: impl FnMut() -> bool) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !condition() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        wait_for(|| calls.load(Ordering::SeqCst) == 1).await;
        configure_policies(&manager, &slow, false);
        wait_for(|| !manager.policies.lock().unwrap().syncing).await;
        assert!(manager.policies.lock().unwrap().last_success_at.is_none());
        configure_policies(&manager, &slow, true);
        wait_for(|| calls.load(Ordering::SeqCst) == 2).await;
        configure_policies(&manager, &format!("http://{address}/current"), true);
        wait_for(|| manager.status().unwrap()["policies"]["state"] == "succeeded").await;
        assert_eq!(manager.status().unwrap()["policies"]["etag"], "\"current\"");
        configure_policies(&manager, &slow, true);
        wait_for(|| calls.load(Ordering::SeqCst) == 3).await;
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!manager.policies.lock().unwrap().syncing);
        assert!(manager.policies.lock().unwrap().next_sync_at.is_none());
        server.abort();
        let _ = server.await;
    }

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
    fn experience_metadata_requires_current_success_and_reports_staleness() {
        let (_directory, manager) = fixture();
        let (hosts, _) = project(&inventory()).unwrap();
        let config = netcontrol_core::SandoConfig {
            api_url: "https://sando.example.test".into(),
            ..Default::default()
        };
        let ip = hosts[0].addresses[0];
        manager.state.lock().unwrap().snapshot = Snapshot {
            source_url: config.api_url.clone(),
            hosts,
            last_success_at: Some(Utc::now()),
            ..Default::default()
        };
        let metadata = manager.host_experience_metadata(&config).unwrap();
        assert_eq!(metadata[&ip]["status"], "available");
        assert_eq!(metadata[&ip]["classification"], "Camera");
        manager.state.lock().unwrap().snapshot.last_success_at =
            Some(Utc::now() - chrono::Duration::hours(3));
        assert_eq!(
            manager.host_experience_metadata(&config).unwrap()[&ip]["status"],
            "stale"
        );
        manager.state.lock().unwrap().snapshot.last_success_at = Some(Utc::now());
        manager.state.lock().unwrap().snapshot.error = Some("synthetic sync failure".into());
        assert_eq!(
            manager.host_experience_metadata(&config).unwrap()[&ip]["status"],
            "stale"
        );
        manager.state.lock().unwrap().snapshot.source_url = "https://other.example.test".into();
        assert!(
            manager
                .host_experience_metadata(&config)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cached_local_descriptions_match_current_source_and_preserve_disabled_cache() {
        let (_directory, manager) = fixture();
        let (hosts, _) = project(&inventory()).unwrap();
        manager.state.lock().unwrap().snapshot = Snapshot {
            source_url: "https://sando.example.test".into(),
            hosts: hosts.clone(),
            ..Default::default()
        };
        let mut config = netcontrol_core::SandoConfig {
            api_url: "https://sando.example.test".into(),
            ..Default::default()
        };
        let names = manager.local_descriptions(&config).unwrap();
        for address in &hosts[0].addresses {
            assert_eq!(names[address], "Camera");
        }
        assert_eq!(hosts[0].host_name.as_deref(), Some("camera.test"));
        config.api_url = "https://other.example.test".into();
        assert!(manager.local_descriptions(&config).unwrap().is_empty());
    }

    #[test]
    fn cached_local_descriptions_never_fall_back_to_hostnames() {
        let (_directory, manager) = fixture();
        let (hosts, _) = project(&serde_json::to_vec(&json!([
            {"ip_address":"192.0.2.10","dns_hostname":"dns.test","local_description":"Device label"},
            {"ip_address":"192.0.2.11","dns_hostname":"dns-only.test"},
            {"ip_address":"192.0.2.12","dhcp_hostname":"dhcp.test","local_description":null},
            {"ip_address":"192.0.2.13","lease_hostname":"lease.test","local_description":""},
            {"ip_address":"192.0.2.14","dns_hostname":"blank.test","local_description":"   "}
        ])).unwrap()).unwrap();
        manager.state.lock().unwrap().snapshot.hosts = hosts;
        let names = manager
            .local_descriptions(&netcontrol_core::SandoConfig::default())
            .unwrap();
        assert_eq!(
            names,
            BTreeMap::from([("192.0.2.10".parse().unwrap(), "Device label".into())])
        );
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
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        complete(&manager, &id, "rollback");
        configure(&manager, "http://sando.example.test/proxy", true);
        let before = manager.engine.lock().unwrap().saved_configuration().clone();
        let revision = manager.engine.lock().unwrap().committed_revision();
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(manager.status().unwrap()["state"], "succeeded");
        assert_eq!(manager.status().unwrap()["hosts"][0]["threat_score"], -1);
        let summary = manager.mqtt_status(&before.sando).unwrap();
        assert_eq!(summary["state"], "succeeded");
        assert_eq!(
            summary["host_count"],
            manager.status().unwrap()["hosts"].as_array().unwrap().len()
        );
        assert!(summary.get("hosts").is_none());
        assert!(summary.get("source_url").is_none());
        assert!(summary.get("error").is_none());
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
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            manager.status().unwrap()["source_url"],
            "http://second.example.test"
        );
        configure(&manager, "http://second.example.test", false);
        settle().await;
        assert!(!manager.state.lock().unwrap().syncing);
        configure(&manager, "http://second.example.test", true);
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
