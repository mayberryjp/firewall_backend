use crate::private_store::{identifier, private_file, read_private, valid_id, write_new_private};
use anyhow::{Context, Result, ensure};
use netcontrol_core::{DenyRecord, DiscordConfig, Engine};
use reqwest::{Client, Url};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use zeroize::Zeroizing;

pub use crate::dynamic_dns::Mode;

pub fn validate_webhook(value: &str) -> Result<()> {
    ensure!(value.len() <= 512, "invalid Discord webhook URL");
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid Discord webhook URL"))?;
    let parts: Vec<_> = url.path().split('/').collect();
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("discord.com")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.as_str() == value
            && parts.len() == 5
            && parts[0].is_empty()
            && parts[1] == "api"
            && parts[2] == "webhooks"
            && !parts[3].is_empty()
            && parts[3].len() <= 20
            && !parts[3].starts_with('0')
            && parts[3].bytes().all(|byte| byte.is_ascii_digit())
            && (16..=256).contains(&parts[4].len())
            && parts[4]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "expected a canonical HTTPS discord.com/api/webhooks/ID/TOKEN URL without query or fragment"
    );
    Ok(())
}

struct Secrets {
    root: PathBuf,
    _lock: File,
}

impl Secrets {
    fn open(root: &Path) -> Result<Self> {
        crate::identity::secure_parent(root)?;
        if !root.try_exists()? {
            let mut directory = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directory.mode(0o700);
            }
            directory.create(root)?;
        }
        let metadata = fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "invalid Discord private directory"
        );
        let path = root.join("lock");
        crate::identity::secure_parent(&path)?;
        let lock = private_file(&path, !path.try_exists()?)?;
        fs2::FileExt::try_lock_exclusive(&lock).context("Discord private store is already open")?;
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
        })
    }

    fn references(&self) -> Result<BTreeSet<String>> {
        let mut references = BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(reference) = name.strip_prefix("webhook-") {
                self.get(reference)?;
                references.insert(reference.to_owned());
            }
        }
        ensure!(
            references.len() <= 256,
            "Discord webhook store exceeds 256 entries"
        );
        Ok(references)
    }

    fn get(&self, reference: &str) -> Result<Zeroizing<String>> {
        ensure!(valid_id(reference), "invalid Discord webhook reference");
        let bytes = Zeroizing::new(read_private(
            &self.root.join(format!("webhook-{reference}")),
        )?);
        let value = Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned());
        validate_webhook(&value)?;
        Ok(value)
    }

    fn create(&self, value: &str) -> Result<String> {
        validate_webhook(value)?;
        ensure!(
            self.references()?.len() < 256,
            "Discord webhook store limit reached (256)"
        );
        let reference = identifier();
        write_new_private(
            &self.root.join(format!("webhook-{reference}")),
            value.as_bytes(),
        )?;
        Ok(reference)
    }
}

#[derive(Default, Serialize)]
struct Status {
    enabled: bool,
    notify_broadcast: bool,
    notify_tcp_closures: bool,
    state: &'static str,
    delivered: String,
    failed: String,
    last_drop_id: Option<String>,
    error: Option<String>,
}

pub struct Manager {
    secrets: Mutex<Secrets>,
    engine: Arc<Mutex<Engine>>,
    sando: Arc<crate::sando::Manager>,
    status: Mutex<Status>,
    mode: Mode,
}

impl Manager {
    pub fn open(
        root: &Path,
        engine: Arc<Mutex<Engine>>,
        mode: Mode,
        sando: Arc<crate::sando::Manager>,
    ) -> Result<Arc<Self>> {
        let secrets = Secrets::open(root)?;
        let references = secrets.references()?;
        let config = {
            let mut engine = engine
                .lock()
                .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
            let config = engine.saved_configuration().discord.clone();
            ensure!(
                config.webhook_ref.is_empty() || references.contains(&config.webhook_ref),
                "saved Discord webhook reference is unavailable"
            );
            ensure!(
                !config.enabled || mode != Mode::Unsupported,
                "Discord alerts require native Linux host mode"
            );
            engine.configure_discord((mode != Mode::Unsupported).then_some(references));
            config
        };
        Ok(Arc::new(Self {
            secrets: Mutex::new(secrets),
            engine,
            sando,
            mode,
            status: Mutex::new(Status {
                enabled: config.enabled,
                notify_broadcast: config.notify_broadcast,
                notify_tcp_closures: config.notify_tcp_closures,
                state: "starting",
                delivered: "0".into(),
                failed: "0".into(),
                ..Status::default()
            }),
        }))
    }

    pub fn create_webhook(&self, engine: &mut Engine, value: &str) -> Result<String> {
        let secrets = self
            .secrets
            .lock()
            .map_err(|_| anyhow::anyhow!("Discord private store unavailable"))?;
        let reference = secrets.create(value)?;
        engine.configure_discord((self.mode != Mode::Unsupported).then_some(secrets.references()?));
        Ok(reference)
    }

    pub fn status(&self) -> Result<Value> {
        let status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?;
        Ok(json!({
            "enabled": status.enabled, "state": status.state,
            "notify_broadcast": status.notify_broadcast,
            "notify_tcp_closures": status.notify_tcp_closures,
            "delivered": status.delivered, "failed": status.failed,
            "last_drop_id": status.last_drop_id, "error": status.error,
            "counters_scope": "daemon_session",
            "deduplication": ["source", "destination", "destination_port", "protocol"]
        }))
    }

    pub async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) -> Result<()> {
        let result = self.worker(stop).await;
        if let Err(error) = &result {
            let mut status = self
                .status
                .lock()
                .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?;
            status.state = "error";
            status.error = Some(error.to_string());
            tracing::error!(%error, "Discord notification worker stopped");
        }
        result
    }

    async fn worker(&self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .user_agent("netcontrol-discord")
            .build()?;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let (mut delivered, mut failed) = {
            let status = self
                .status
                .lock()
                .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?;
            (
                status.delivered.parse::<u64>()?,
                status.failed.parse::<u64>()?,
            )
        };
        'worker: loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = tick.tick() => {}
            }
            if *stop.borrow() {
                break;
            }
            let snapshot = {
                let mut engine = self
                    .engine
                    .lock()
                    .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
                if engine.configuration_busy() {
                    None
                } else {
                    let config = engine.saved_configuration().discord.clone();
                    let records = if self.mode == Mode::Native {
                        engine.first_firewall_drops(&config)?
                    } else {
                        Vec::new()
                    };
                    let saved = engine.saved_configuration();
                    let hostname = firewall_name(&saved.system);
                    let names = self.sando.local_descriptions(&saved.sando)?;
                    Some((config, hostname, names, records))
                }
            };
            let Some((config, hostname, names, records)) = snapshot else {
                self.status
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?
                    .state = "paused";
                continue;
            };
            {
                let mut status = self
                    .status
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?;
                status.enabled = config.enabled;
                status.notify_broadcast = config.notify_broadcast;
                status.notify_tcp_closures = config.notify_tcp_closures;
                status.state = if !config.enabled {
                    "disabled"
                } else if self.mode == Mode::Simulated {
                    "simulated"
                } else if self.mode == Mode::Unsupported {
                    "unavailable"
                } else if status.error.is_some() {
                    "error"
                } else {
                    "ready"
                };
            }
            let records: Vec<_> = records
                .into_iter()
                .filter(|record| config.should_notify_drop(record))
                .collect();
            if records.is_empty() {
                continue;
            }
            let url = {
                self.secrets
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Discord private store unavailable"))?
                    .get(&config.webhook_ref)?
            };
            let payloads = messages(&hostname, &records, &names)?;
            let mut offset = 0;
            for payload in payloads {
                let batch = payload["embeds"]
                    .as_array()
                    .context("Discord embeds unavailable")?
                    .len();
                let delivery_stop = stop.clone();
                let outcome = if self.configuration_is_changed(&config) {
                    Outcome::Failed(
                        "Discord configuration changed before delivery; batch was not replayed"
                            .into(),
                    )
                } else {
                    tokio::select! {
                        _ = stop.changed() => Outcome::Stopped,
                        _ = self.configuration_changed(&config) => Outcome::Failed("Discord configuration changed during delivery; batch was not replayed".into()),
                        result = deliver(&client, &url, &payload, delivery_stop) => result?,
                    }
                };
                let error = match outcome {
                    Outcome::Delivered => None,
                    Outcome::Stopped => break 'worker,
                    Outcome::Failed(error) => Some(error),
                };
                let count = if error.is_some() {
                    records.len() - offset
                } else {
                    batch
                };
                offset += count;
                let count = u64::try_from(count)?;
                let mut status = self
                    .status
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?;
                status.last_drop_id = Some(records[offset - 1].id.clone());
                if let Some(error) = error {
                    failed = failed
                        .checked_add(count)
                        .context("Discord failure counter exhausted")?;
                    status.failed = failed.to_string();
                    status.state = "error";
                    tracing::warn!(%error, "first-seen firewall drops could not be delivered to Discord");
                    status.error = Some(error);
                    break;
                } else {
                    delivered = delivered
                        .checked_add(count)
                        .context("Discord delivery counter exhausted")?;
                    status.delivered = delivered.to_string();
                    status.state = "ready";
                    status.error = None;
                }
            }
        }
        self.status
            .lock()
            .map_err(|_| anyhow::anyhow!("Discord status unavailable"))?
            .state = "stopped";
        Ok(())
    }

    async fn configuration_changed(&self, original: &DiscordConfig) {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if self.configuration_is_changed(original) {
                return;
            }
        }
    }

    fn configuration_is_changed(&self, original: &DiscordConfig) -> bool {
        match self.engine.lock() {
            Ok(engine) => {
                engine.configuration_busy() || &engine.saved_configuration().discord != original
            }
            Err(_) => true,
        }
    }
}

enum Outcome {
    Delivered,
    Failed(String),
    Stopped,
}

fn firewall_name(system: &netcontrol_core::SystemConfig) -> String {
    match (system.hostname.as_str(), system.domain.as_str()) {
        ("", _) => "Firewall".to_owned(),
        (hostname, "") => hostname.to_owned(),
        (hostname, domain) => format!("{hostname}.{domain}"),
    }
}

async fn deliver(
    client: &Client,
    url: &str,
    payload: &Value,
    mut stop: watch::Receiver<bool>,
) -> Result<Outcome> {
    for attempt in 0..3 {
        if *stop.borrow() {
            return Ok(Outcome::Stopped);
        }
        let response = tokio::select! {
            _ = stop.changed() => return Ok(Outcome::Stopped),
            response = client.post(url).query(&[("wait", "true")]).json(payload).send() => response,
        };
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                return Ok(Outcome::Failed(format!(
                    "Discord delivery failed: {}",
                    error.without_url()
                )));
            }
        };
        match response.status().as_u16() {
            200 | 204 => return Ok(Outcome::Delivered),
            429 => {
                let mut bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|error| error.without_url())?
                {
                    ensure!(
                        bytes.len() + chunk.len() <= 4096,
                        "oversized Discord rate-limit response"
                    );
                    bytes.extend_from_slice(&chunk);
                }
                let delay = retry_delay(&bytes)?;
                tracing::warn!(
                    retry_after_seconds = delay.as_secs_f64(),
                    "Discord rate limited first-seen drop notifications"
                );
                tokio::select! {
                    _ = stop.changed() => return Ok(Outcome::Stopped),
                    _ = tokio::time::sleep(delay) => {}
                }
                if attempt == 2 {
                    return Ok(Outcome::Failed(
                        "Discord rate limit persisted after three attempts".into(),
                    ));
                }
            }
            status => {
                return Ok(Outcome::Failed(format!(
                    "Discord webhook returned HTTP {status}"
                )));
            }
        }
    }
    unreachable!("bounded Discord delivery loop returns")
}

fn retry_delay(bytes: &[u8]) -> Result<Duration> {
    #[derive(serde::Deserialize)]
    struct RateLimit {
        retry_after: f64,
    }
    let response: RateLimit = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Discord rate-limit response"))?;
    ensure!(
        response.retry_after.is_finite() && (0.0..=86400.0).contains(&response.retry_after),
        "invalid Discord retry_after"
    );
    Ok(Duration::from_secs_f64(response.retry_after.max(0.001)))
}

fn message(
    hostname: &str,
    records: &[DenyRecord],
    names: &BTreeMap<IpAddr, String>,
) -> Result<Value> {
    ensure!(
        !records.is_empty() && records.len() <= 10,
        "invalid Discord drop batch"
    );
    let title = if hostname.is_empty() {
        "Firewall"
    } else {
        hostname
    };
    let embeds: Vec<_> = records.iter().map(|record| {
        let endpoint = |address: std::net::IpAddr, port: Option<u16>| {
            let endpoint = port.map_or_else(|| address.to_string(), |port| std::net::SocketAddr::new(address, port).to_string());
            if let Some(name) = names.get(&address) {
                format!("{endpoint} ({name})")
            } else {
                endpoint
            }
        };
        let protocol = match record.protocol { 6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", _ => "IP" };
        let flags = record.tcp_flags.map_or_else(|| "unavailable".into(), |flags| format!("0x{flags:02x}"));
        let tags = if record.tags.is_empty() { "none".into() } else {
            record.tags.iter().map(|tag| tag.as_str()).collect::<Vec<_>>().join(", ")
        };
        json!({
            "title": "New firewall drop",
            "author": {"name": title},
            "description": format!(
                "{} -> {}\nProtocol: {} ({}) | Chain: {} | Reason: {}\nIngress: {} | Egress: {}\nTCP flags: {} | Tags: {}\nDrop ID: {} | UTC epoch ms: {} | Bytes: {}",
                endpoint(record.source, record.source_port), endpoint(record.destination, record.destination_port),
                protocol, record.protocol, record.chain, record.reason,
                record.ingress.as_deref().unwrap_or("unavailable"),
                record.egress.as_deref().unwrap_or("unavailable"),
                flags, tags,
                record.id, record.timestamp_ms, record.packet_length,
            )
        })
    }).collect();
    ensure!(
        embeds.iter().map(embed_length).sum::<usize>() <= 6000,
        "Discord message exceeds embed limits"
    );
    Ok(json!({"embeds":embeds,"allowed_mentions":{"parse":[]}}))
}

fn embed_length(embed: &Value) -> usize {
    ["title", "description"]
        .iter()
        .map(|field| {
            embed[field]
                .as_str()
                .map_or(0, |value| value.chars().count())
        })
        .sum::<usize>()
        + embed["author"]["name"]
            .as_str()
            .map_or(0, |value| value.chars().count())
}

fn messages(
    hostname: &str,
    records: &[DenyRecord],
    names: &BTreeMap<IpAddr, String>,
) -> Result<Vec<Value>> {
    let mut payloads = Vec::new();
    let mut embeds = Vec::new();
    let mut length = 0;
    for record in records {
        let payload = message(hostname, std::slice::from_ref(record), names)?;
        let embed = payload["embeds"][0].clone();
        let size = embed_length(&embed);
        if embeds.len() == 10 || length + size > 6000 {
            payloads.push(json!({"embeds":embeds,"allowed_mentions":{"parse":[]}}));
            embeds = Vec::new();
            length = 0;
        }
        embeds.push(embed);
        length += size;
    }
    if !embeds.is_empty() {
        payloads.push(json!({"embeds":embeds,"allowed_mentions":{"parse":[]}}));
    }
    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webhook() -> String {
        format!(
            "https://discord.com/api/webhooks/123456789012345678/{}",
            "synthetic_token_".repeat(5)
        )
    }

    fn record() -> DenyRecord {
        serde_json::from_value(json!({
            "id":"1","timestamp_ms":1,"chain":"forward","reason":"policy","compiled_rule_index":null,
            "ruleset_id":"a".repeat(64),"source":"2001:db8::1","destination":"2001:db8::2",
            "protocol":6,"source_port":80,"destination_port":60254,
            "ingress_index":2,"egress_index":3,"ingress":"lan0","egress":"wan0","packet_length":60,
            "tcp_flags":17,"tcp_payload_length":0,"tags":["tcp_finish"]
        })).unwrap()
    }

    async fn api(
        service: &axum::Router,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> (u16, Value) {
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let mut request = axum::http::Request::builder().method(method).uri(path);
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let body = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        let response = service
            .clone()
            .oneshot(request.body(axum::body::Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn discord_http_webhook_upload_and_status_are_authorized_redacted_and_strict()
    -> Result<()> {
        use crate::http::{App, Authentication, Credential, router};
        let directory = tempfile::tempdir()?;
        let engine = Arc::new(Mutex::new(Engine::open(
            &directory.path().join("state.json"),
            Box::new(netcontrol_core::Simulator::new()),
        )?));
        let manager = Manager::open(
            &directory.path().join("discord"),
            engine.clone(),
            Mode::Simulated,
            crate::sando::Manager::open(&directory.path().join("sando"), engine.clone())?,
        )?;
        let mut app = App::new(
            engine,
            Authentication::Scoped(vec![
                Credential {
                    name: "reader".into(),
                    token_sha256: crate::identity::digest("reader"),
                    permissions: vec!["state.read".into()],
                },
                Credential {
                    name: "operator".into(),
                    token_sha256: crate::identity::digest("operator"),
                    permissions: vec!["state.read".into(), "discord.write".into()],
                },
            ]),
            false,
        );
        App::attach_discord(&mut app, manager)?;
        let service = router(app);
        let endpoint = "/api/v1/services/discord/webhooks";
        let payload = json!({"webhook_url":webhook()});
        assert_eq!(
            api(&service, "POST", endpoint, "", payload.clone()).await.0,
            401
        );
        assert_eq!(
            api(&service, "POST", endpoint, "reader", payload.clone())
                .await
                .0,
            403
        );
        assert_eq!(
            api(&service, "GET", endpoint, "operator", Value::Null)
                .await
                .0,
            405
        );
        assert_eq!(
            api(
                &service,
                "POST",
                &format!("{endpoint}?x=1"),
                "operator",
                payload.clone()
            )
            .await
            .0,
            400
        );
        for payload in [
            json!({"webhook_url":null}),
            json!({"webhook_url":42}),
            json!({"webhook_url":"http://127.0.0.1/private"}),
            json!({"webhook_url":webhook(),"extra":true}),
        ] {
            assert_eq!(
                api(&service, "POST", endpoint, "operator", payload).await.0,
                400
            );
        }
        let (status, body) = api(&service, "POST", endpoint, "operator", payload).await;
        assert_eq!(status, 201);
        assert!(valid_id(body["webhook_ref"].as_str().unwrap()));
        assert!(!body.to_string().contains("synthetic_token"));
        let endpoint = "/api/v1/services/discord/status";
        let (status, body) = api(&service, "GET", endpoint, "reader", Value::Null).await;
        assert_eq!(status, 200);
        assert_eq!(body["notify_broadcast"], false);
        assert_eq!(body["notify_tcp_closures"], false);
        assert!(!body.to_string().contains("synthetic_token"));
        assert_eq!(
            api(&service, "GET", endpoint, "reader", json!({})).await.0,
            400
        );
        Ok(())
    }

    #[test]
    fn discord_webhooks_are_canonical_provider_only_and_never_echo_tokens() {
        validate_webhook(&webhook()).unwrap();
        for value in [
            webhook().replace("https:", "http:"),
            webhook().replace("discord.com", "localhost"),
            webhook().replace("discord.com", "discord.com.evil.test"),
            webhook().replace("discord.com", "user@discord.com"),
            webhook().replace("discord.com", "discord.com:443"),
            format!("{}?thread_id=123", webhook()),
            format!("{}#fragment", webhook()),
            webhook().replace("/123456789012345678/", "/0123/"),
            webhook().replace("synthetic_token_", "token%2F"),
            "https://discord.com/api/webhooks/123/short".into(),
        ] {
            let error = validate_webhook(&value).unwrap_err().to_string();
            assert!(!error.contains("synthetic_token"));
            assert!(!error.contains(&value));
        }
    }

    #[test]
    fn discord_private_webhook_store_preserves_references_and_exposes_no_url_in_status()
    -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("discord");
        let store = Secrets::open(&directory)?;
        let reference = store.create(&webhook())?;
        assert_eq!(store.get(&reference)?.as_str(), webhook());
        assert_eq!(store.references()?, [reference.clone()].into());
        assert!(Secrets::open(&directory).is_err());
        drop(store);
        let store = Secrets::open(&directory)?;
        assert_eq!(store.get(&reference)?.as_str(), webhook());
        assert!(store.get("../invalid").is_err());
        Ok(())
    }

    #[test]
    fn discord_device_descriptions_use_exact_addresses_or_leave_endpoints_unlabelled() {
        let record = record();
        let names = BTreeMap::from([
            (record.source, "Camera".into()),
            (record.destination, "Remote server".into()),
        ]);
        let payload = message("fw.example.test", std::slice::from_ref(&record), &names).unwrap();
        assert_eq!(payload["embeds"][0]["author"]["name"], "fw.example.test");
        let text = payload["embeds"][0]["description"].as_str().unwrap();
        assert!(text.contains("[2001:db8::1]:80 (Camera) -> [2001:db8::2]:60254 (Remote server)"));
        let payload = message("fw", &[record], &BTreeMap::new()).unwrap();
        assert!(
            payload["embeds"][0]["description"]
                .as_str()
                .unwrap()
                .starts_with("[2001:db8::1]:80 -> [2001:db8::2]:60254\n")
        );
    }

    #[test]
    fn discord_firewall_name_uses_domain_only_with_a_hostname() {
        let mut system = netcontrol_core::SystemConfig::default();
        assert_eq!(firewall_name(&system), "Firewall");
        system.domain = "example.test".into();
        assert_eq!(firewall_name(&system), "Firewall");
        system.hostname = "fw".into();
        assert_eq!(firewall_name(&system), "fw.example.test");
        system.domain.clear();
        assert_eq!(firewall_name(&system), "fw");
    }

    #[test]
    fn discord_named_messages_split_without_losing_entries_or_exceeding_limits() {
        let record = record();
        let names = BTreeMap::from([
            (
                record.source,
                format!("{}{}", "@everyone".repeat(56), "s".repeat(8)),
            ),
            (record.destination, "d".repeat(512)),
        ]);
        let hostname = format!(
            "{}.{}.{}.{}",
            "f".repeat(63),
            "d".repeat(63),
            "d".repeat(63),
            "d".repeat(61)
        );
        let records = vec![record; 10];
        let payloads = messages(&hostname, &records, &names).unwrap();
        assert!(payloads.len() > 1);
        let mut count = 0;
        for payload in payloads {
            assert_eq!(payload["allowed_mentions"]["parse"], json!([]));
            let embeds = payload["embeds"].as_array().unwrap();
            assert!(embeds.len() <= 10);
            assert!(embeds.iter().map(embed_length).sum::<usize>() <= 6000);
            assert!(embeds.iter().all(|embed| {
                let text = embed["description"].as_str().unwrap();
                names.values().all(|name| text.contains(name))
            }));
            assert!(
                embeds
                    .iter()
                    .all(|embed| embed["title"].as_str().unwrap().chars().count() <= 256)
            );
            count += embeds.len();
        }
        assert_eq!(count, records.len());
        assert_eq!(
            messages("fw", &vec![records[0].clone(); 11], &BTreeMap::new())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn discord_messages_are_bounded_and_disable_mentions() {
        let payload = message("@everyone", &vec![record(); 10], &BTreeMap::new()).unwrap();
        assert_eq!(payload["allowed_mentions"]["parse"], json!([]));
        assert_eq!(payload["embeds"].as_array().unwrap().len(), 10);
        let text = payload["embeds"][0]["description"].as_str().unwrap();
        assert!(text.contains("[2001:db8::1]:80 -> [2001:db8::2]:60254"));
        assert!(text.contains("Protocol: TCP (6)"));
        assert!(text.contains("TCP flags: 0x11 | Tags: tcp_finish"));
        assert!(!text.contains("synthetic_token"));
        let mut broadcast = record();
        broadcast.source = "192.0.2.1".parse().unwrap();
        broadcast.destination = "255.255.255.255".parse().unwrap();
        broadcast.protocol = 17;
        broadcast.tcp_flags = None;
        broadcast.tcp_payload_length = None;
        broadcast.tags = vec![netcontrol_core::DenyTrafficTag::Ipv4Broadcast];
        let payload = message("", &[broadcast], &BTreeMap::new()).unwrap();
        assert!(
            payload["embeds"][0]["description"]
                .as_str()
                .unwrap()
                .contains("TCP flags: unavailable | Tags: ipv4_broadcast")
        );
        assert!(message("", &[], &BTreeMap::new()).is_err());
        assert!(message("", &vec![record(); 11], &BTreeMap::new()).is_err());
        assert_eq!(
            retry_delay(br#"{"retry_after":0.01,"global":false}"#).unwrap(),
            Duration::from_millis(10)
        );
        for bytes in [
            b"{}".as_slice(),
            br#"{"retry_after":-1}"#,
            br#"{"retry_after":86401}"#,
            br#"{"retry_after":"1"}"#,
        ] {
            assert!(retry_delay(bytes).is_err());
        }
    }

    #[tokio::test]
    async fn discord_delivery_retries_only_rate_limits_and_sends_wait_and_payload() -> Result<()> {
        use axum::{
            Json, Router,
            extract::{Query, State},
            http::StatusCode,
            routing::post,
        };
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let service = Router::new()
            .route(
                "/webhook",
                post(
                    |State(captured): State<Arc<Mutex<Vec<Value>>>>,
                     Query(query): Query<std::collections::BTreeMap<String, String>>,
                     Json(payload): Json<Value>| async move {
                        assert_eq!(query.get("wait").map(String::as_str), Some("true"));
                        let mut captured = captured.lock().unwrap();
                        captured.push(payload);
                        if captured.len() == 1 {
                            (
                                StatusCode::TOO_MANY_REQUESTS,
                                Json(json!({"retry_after":0.01})),
                            )
                        } else {
                            (StatusCode::OK, Json(json!({"id":"synthetic-message"})))
                        }
                    },
                ),
            )
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/webhook", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, service).await });
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let (_stop, receiver) = watch::channel(false);
        let payload = message("firewall-test", &[record()], &BTreeMap::new())?;
        let result = deliver(&client, &url, &payload, receiver).await;
        server.abort();
        let _ = server.await;
        assert!(matches!(result?, Outcome::Delivered));
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0], payload);
        assert_eq!(captured[1], payload);
        Ok(())
    }

    #[tokio::test]
    async fn discord_shutdown_cancels_a_long_rate_limit_without_repeating() -> Result<()> {
        use axum::{Json, Router, http::StatusCode, routing::post};
        let called = Arc::new(tokio::sync::Notify::new());
        let received = called.clone();
        let service = Router::new().route(
            "/webhook",
            post(move || {
                let called = called.clone();
                async move {
                    called.notify_one();
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({"retry_after":3600})),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/webhook", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, service).await });
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            deliver(
                &Client::new(),
                &url,
                &message("", &[record()], &BTreeMap::new())?,
                receiver,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), received.notified()).await?;
        stop.send(true)?;
        let result = tokio::time::timeout(Duration::from_secs(1), task).await;
        server.abort();
        let _ = server.await;
        assert!(matches!(result???, Outcome::Stopped));
        Ok(())
    }

    #[tokio::test]
    async fn discord_simulator_has_no_network_side_effect_and_reports_disabled_or_simulated()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let engine = Arc::new(Mutex::new(Engine::open(
            &directory.path().join("state.json"),
            Box::new(netcontrol_core::Simulator::new()),
        )?));
        let sando = crate::sando::Manager::open(&directory.path().join("sando"), engine.clone())?;
        let manager = Manager::open(
            &directory.path().join("discord"),
            engine,
            Mode::Simulated,
            sando,
        )?;
        let (stop, receiver) = watch::channel(false);
        let running = tokio::spawn(manager.clone().run(receiver));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(manager.status()?["state"], "disabled");
        stop.send(true)?;
        tokio::time::timeout(Duration::from_secs(1), running).await???;
        assert_eq!(manager.status()?["state"], "stopped");
        assert!(!manager.status()?.to_string().contains("synthetic_token"));
        Ok(())
    }

    #[tokio::test]
    async fn discord_confirmed_notification_flags_and_global_toggle_update_worker_and_cancel()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let engine = Arc::new(Mutex::new(Engine::open(
            &directory.path().join("state.json"),
            Box::new(netcontrol_core::Simulator::new()),
        )?));
        let manager = Manager::open(
            &directory.path().join("discord"),
            engine.clone(),
            Mode::Simulated,
            crate::sando::Manager::open(&directory.path().join("sando"), engine.clone())?,
        )?;
        let permissions: Vec<_> = netcontrol_core::PERMISSIONS
            .iter()
            .map(|value| value.to_string())
            .collect();
        let submit = |enabled: bool,
                      reference: &str,
                      notify_broadcast: bool,
                      notify_tcp_closures: bool|
         -> Result<String> {
            let mut engine = engine.lock().unwrap();
            let revision = engine
                .request(
                    "GET",
                    "/api/v1/revisions/latest",
                    "",
                    "operator",
                    &permissions,
                    &[],
                )
                .body["revision"]
                .clone();
            let mut config = engine.saved_configuration().clone();
            config.discord.enabled = enabled;
            config.discord.notify_broadcast = notify_broadcast;
            config.discord.notify_tcp_closures = notify_tcp_closures;
            config.discord.webhook_ref = reference.into();
            let body = serde_json::to_vec(
                &json!({"base_revision":revision,"confirm_timeout_seconds":30,"config":config}),
            )?;
            let reply = engine.request(
                "POST",
                "/api/v1/transactions",
                "",
                "operator",
                &permissions,
                &body,
            );
            ensure!(reply.status == 202, "{}", reply.body);
            Ok(reply.body["id"].as_str().unwrap().into())
        };
        let confirm = |id: &str| {
            assert_eq!(
                engine
                    .lock()
                    .unwrap()
                    .request(
                        "POST",
                        &format!("/api/v1/transactions/{id}/confirm"),
                        "",
                        "operator",
                        &permissions,
                        &[],
                    )
                    .status,
                200
            );
        };
        let reference = manager.create_webhook(&mut engine.lock().unwrap(), &webhook())?;
        let id = submit(true, &reference, false, false)?;
        confirm(&id);
        let original = engine.lock().unwrap().saved_configuration().discord.clone();
        let (stop, receiver) = watch::channel(false);
        let running = tokio::spawn(manager.clone().run(receiver));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(manager.status()?["state"], "simulated");
        assert_eq!(manager.status()?["enabled"], true);
        assert_eq!(manager.status()?["notify_broadcast"], false);
        assert_eq!(manager.status()?["notify_tcp_closures"], false);
        let id = submit(true, &reference, true, false)?;
        confirm(&id);
        tokio::time::timeout(
            Duration::from_secs(1),
            manager.configuration_changed(&original),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(manager.status()?["notify_broadcast"], true);
        assert_eq!(manager.status()?["notify_tcp_closures"], false);
        let original = engine.lock().unwrap().saved_configuration().discord.clone();
        let id = submit(true, &reference, false, true)?;
        confirm(&id);
        tokio::time::timeout(
            Duration::from_secs(1),
            manager.configuration_changed(&original),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(manager.status()?["notify_broadcast"], false);
        assert_eq!(manager.status()?["notify_tcp_closures"], true);
        let original = engine.lock().unwrap().saved_configuration().discord.clone();
        let id = submit(false, &reference, false, false)?;
        tokio::time::timeout(
            Duration::from_secs(1),
            manager.configuration_changed(&original),
        )
        .await?;
        confirm(&id);
        tokio::time::sleep(Duration::from_millis(1050)).await;
        let status = manager.status()?;
        assert_eq!(status["state"], "disabled");
        assert_eq!(status["enabled"], false);
        assert_eq!(status["notify_broadcast"], false);
        assert_eq!(status["notify_tcp_closures"], false);
        assert_eq!(status["delivered"], "0");
        stop.send(true)?;
        tokio::time::timeout(Duration::from_secs(1), running).await???;
        Ok(())
    }
}
