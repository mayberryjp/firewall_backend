use crate::private_store::{identifier, private_file, read_private, valid_id, write_new_private};
use anyhow::{Context, Result, ensure};
use netcontrol_core::{Engine, MQTTConfig};
use rumqttc::{AsyncClient, Event, EventLoop, LastWill, MqttOptions, Packet, QoS, Transport};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use zeroize::Zeroizing;

pub struct Secrets {
    root: PathBuf,
    pub device_id: String,
    _lock: File,
}

impl Secrets {
    pub fn open(root: &Path) -> Result<Self> {
        crate::identity::secure_parent(root)?;
        if !root.try_exists()? {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(root)?;
        }
        let metadata = fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "MQTT private path must be a directory"
        );
        crate::identity::secure_parent(&root.join("device-id"))?;
        let lock_path = root.join("lock");
        let lock = private_file(&lock_path, !lock_path.try_exists()?)?;
        fs2::FileExt::try_lock_exclusive(&lock).context("MQTT store is already open")?;
        let id_path = root.join("device-id");
        let device_id = if id_path.try_exists()? {
            String::from_utf8(read_private(&id_path)?)?
        } else {
            ensure!(
                fs::read_dir(root)?.count() == 1,
                "MQTT identity missing from nonempty store"
            );
            let id = identifier();
            write_new_private(&id_path, id.as_bytes())?;
            id
        };
        ensure!(valid_id(&device_id), "invalid MQTT device identity");
        Ok(Self {
            root: root.to_owned(),
            device_id,
            _lock: lock,
        })
    }

    pub fn references(&self) -> Result<BTreeSet<String>> {
        let mut references = BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(reference) = name.strip_prefix("password-") {
                ensure!(valid_id(reference), "invalid MQTT password reference file");
                let password = self.password(reference)?;
                ensure!(!password.is_empty(), "empty stored MQTT password");
                references.insert(reference.to_owned());
            }
        }
        Ok(references)
    }

    pub fn create_password(&self, password: &str) -> Result<String> {
        ensure!(
            !password.is_empty() && password.len() <= 4096 && !password.contains('\0'),
            "MQTT password must be 1..4096 UTF-8 bytes without NUL"
        );
        ensure!(
            self.references()?.len() < 256,
            "MQTT password store limit reached (256)"
        );
        let reference = identifier();
        write_new_private(
            &self.root.join(format!("password-{reference}")),
            password.as_bytes(),
        )?;
        Ok(reference)
    }

    pub fn password(&self, reference: &str) -> Result<Zeroizing<String>> {
        if reference.is_empty() {
            return Ok(Zeroizing::new(String::new()));
        }
        ensure!(valid_id(reference), "invalid MQTT password reference");
        let bytes = Zeroizing::new(read_private(
            &self.root.join(format!("password-{reference}")),
        )?);
        ensure!(
            !bytes.is_empty() && bytes.len() <= 4096,
            "invalid MQTT password file"
        );
        Ok(Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned()))
    }

    fn components(&self) -> Result<BTreeSet<String>> {
        let path = self.root.join("components.json");
        if !path.try_exists()? {
            return Ok(BTreeSet::new());
        }
        let components: BTreeSet<String> = serde_json::from_slice(&read_private(&path)?)?;
        ensure!(
            components.len() <= 8192
                && components.iter().all(|key| key.len() <= 128
                    && key.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'_')),
            "invalid MQTT discovery manifest"
        );
        Ok(components)
    }

    fn save_components(&self, components: &BTreeSet<String>) -> Result<()> {
        ensure!(
            components.len() <= 8192,
            "MQTT discovery manifest limit reached"
        );
        let pending = self
            .root
            .join(format!("components-{}.pending", identifier()));
        let result = (|| {
            let mut file = private_file(&pending, true)?;
            file.write_all(&serde_json::to_vec(components)?)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&pending, self.root.join("components.json"))?;
            #[cfg(unix)]
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(pending);
        }
        result
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Native,
    Simulated,
    Unsupported,
}

pub struct Manager {
    secrets: Mutex<Secrets>,
    status: Mutex<Value>,
    engine: Arc<Mutex<Engine>>,
    mode: Mode,
    started: Instant,
    device_id: String,
}

type Publication = (String, Vec<u8>, bool);

impl Manager {
    pub fn open(root: &Path, engine: Arc<Mutex<Engine>>, mode: Mode) -> Result<Arc<Self>> {
        let secrets = Secrets::open(root)?;
        secrets.components()?;
        engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?
            .configure_mqtt(if mode == Mode::Unsupported {
                None
            } else {
                Some(secrets.references()?)
            });
        let device_id = secrets.device_id.clone();
        Ok(Arc::new(Self {
            secrets: Mutex::new(secrets),
            status: Mutex::new(
                json!({"device_id":device_id,"enabled":false,"state":"disabled","error":null,"last_published_at_unix":null}),
            ),
            engine,
            mode,
            started: Instant::now(),
            device_id,
        }))
    }

    pub fn status(&self) -> Result<Value> {
        Ok(self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("MQTT status unavailable"))?
            .clone())
    }

    pub fn create_password(&self, engine: &mut Engine, password: &str) -> Result<String> {
        let secrets = self
            .secrets
            .lock()
            .map_err(|_| anyhow::anyhow!("MQTT store unavailable"))?;
        let reference = secrets.create_password(password)?;
        engine.configure_mqtt(if self.mode == Mode::Unsupported {
            None
        } else {
            Some(secrets.references()?)
        });
        Ok(reference)
    }

    fn state(&self, enabled: bool, state: &str, error: Option<&str>) {
        if let Ok(mut value) = self.status.lock() {
            value["enabled"] = json!(enabled);
            value["state"] = json!(state);
            value["error"] = json!(error);
        }
    }

    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut retry = Instant::now();
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                _ = stop.changed() => { break; }
                _ = interval.tick() => {
                    let config = match self.engine.try_lock() {
                        Ok(engine) => engine.saved_configuration().mqtt.clone(),
                        Err(_) => continue,
                    };
                    if !config.enabled {
                        self.state(false, "disabled", None);
                    } else if self.mode == Mode::Simulated {
                        self.state(true, "simulated", None);
                    } else if self.mode == Mode::Unsupported {
                        self.state(true, "unavailable", Some("MQTT publishing requires Linux host mode"));
                    } else if Instant::now() >= retry {
                        self.state(true, "connecting", None);
                        let result = self.session(config, stop.clone()).await;
                        if *stop.borrow() { break; }
                        if result.is_err() {
                            self.state(true, "reconnecting", Some("MQTT connection unavailable; check broker, TLS trust, credentials and source interface"));
                            retry = Instant::now() + Duration::from_secs(5);
                        }
                    }
                }
            }
            if *stop.borrow() {
                break;
            }
        }
        self.state(false, "stopped", None);
    }

    fn connection(&self, config: &MQTTConfig) -> Result<(AsyncClient, EventLoop)> {
        let (host, port, tls) = config.broker()?;
        let mut options = MqttOptions::new(format!("netcontrol_{}", self.device_id), host, port);
        options.set_keep_alive(Duration::from_secs(30));
        options.set_clean_session(true);
        options.set_max_packet_size(1 << 20, (1 << 20) + 4096);
        options.set_last_will(LastWill::new(
            format!("netcontrol/{}/availability", self.device_id),
            "offline",
            QoS::AtLeastOnce,
            true,
        ));
        if !config.username.is_empty() {
            let secrets = self
                .secrets
                .lock()
                .map_err(|_| anyhow::anyhow!("MQTT store unavailable"))?;
            let password = secrets.password(&config.password_ref)?;
            options.set_credentials(&config.username, &**password);
        }
        if tls {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_native_certs::load_native_certs().certs {
                roots.add(certificate)?;
            }
            ensure!(!roots.is_empty(), "MQTT TLS trust store is empty");
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            options.set_transport(Transport::tls_with_config(tls.into()));
        }
        let (client, mut events) = AsyncClient::new(options, 8);
        events.network_options.set_connection_timeout(5);
        bind_source(&mut events, &config.source_interface)?;
        Ok((client, events))
    }

    fn collect(&self, config: &MQTTConfig) -> Result<(Value, Value)> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        ensure!(!engine.configuration_busy(), "configuration is changing");
        let revision = engine.committed_revision();
        let reply = engine.request(
            "GET",
            "/api/v1/statistics",
            "",
            "mqtt-publisher",
            &["state.read".into()],
            &[],
        );
        ensure!(reply.status == 200, "statistics unavailable");
        telemetry(
            &self.device_id,
            config,
            revision,
            self.started.elapsed().as_secs(),
            &reply.body,
        )
    }

    async fn session(
        self: &Arc<Self>,
        config: MQTTConfig,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let (client, mut events) = self.connection(&config)?;
        let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(32);
        let mut polling = tokio::task::JoinSet::new();
        polling.spawn(async move {
            loop {
                let event = events.poll().await;
                let done = event.is_err()
                    || matches!(event, Ok(Event::Outgoing(rumqttc::Outgoing::Disconnect)));
                if event_sender.send(event).await.is_err() || done {
                    break;
                }
            }
        });
        let base = format!("netcontrol/{}", self.device_id);
        let discovery_topic = format!("homeassistant/device/netcontrol_{}/config", self.device_id);
        let mut queue = VecDeque::<Publication>::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut connected = false;
        let mut pending = 0usize;
        let mut batch_has_state = false;
        let mut manifest = None::<BTreeSet<String>>;
        let mut previous_discovery = None::<Value>;
        let mut force_discovery = true;
        let mut next_sample = Instant::now();
        let mut collecting = None::<tokio::task::JoinHandle<Result<(Value, Value)>>>;
        loop {
            while let Some((topic, payload, retain)) = queue.front() {
                if client
                    .try_publish(topic, QoS::AtLeastOnce, *retain, payload.clone())
                    .is_err()
                {
                    break;
                }
                pending += 1;
                queue.pop_front();
            }
            tokio::select! {
                _ = stop.changed() => { break; }
                _ = interval.tick() => {
                    if *stop.borrow() { break; }
                    if let Ok(engine) = self.engine.try_lock() {
                        if engine.saved_configuration().mqtt != config { break; }
                    }
                    if connected && collecting.is_none() && pending == 0 && queue.is_empty() && Instant::now() >= next_sample {
                        let manager = self.clone();
                        let settings = config.clone();
                        collecting = Some(tokio::task::spawn_blocking(move || manager.collect(&settings)));
                        next_sample = Instant::now() + Duration::from_secs(config.interval_seconds);
                    }
                }
                result = async { collecting.as_mut().unwrap().await }, if collecting.is_some() => {
                    collecting = None;
                    match result {
                        Ok(Ok((discovery, state))) => {
                            if force_discovery || previous_discovery.as_ref() != Some(&discovery) {
                                let secrets = self.secrets.lock().map_err(|_| anyhow::anyhow!("MQTT store unavailable"))?;
                                let before = secrets.components()?;
                                let after: BTreeSet<_> = discovery["components"].as_object().unwrap().keys().cloned().collect();
                                let mut removal = discovery.clone();
                                for key in before.difference(&after) {
                                    removal["components"][key] = json!({"platform":"sensor"});
                                }
                                secrets.save_components(&before.union(&after).cloned().collect())?;
                                if before != after {
                                    queue.push_back((discovery_topic.clone(), serde_json::to_vec(&removal)?, true));
                                }
                                queue.push_back((discovery_topic.clone(), serde_json::to_vec(&discovery)?, true));
                                manifest = Some(after);
                                previous_discovery = Some(discovery);
                                force_discovery = false;
                            }
                            queue.push_back((format!("{base}/availability"), b"online".to_vec(), true));
                            queue.push_back((format!("{base}/state"), serde_json::to_vec(&state)?, false));
                            batch_has_state = true;
                        }
                        _ => {
                            self.state(true, "error", Some("MQTT statistics collection unavailable"));
                            queue.push_back((format!("{base}/availability"), b"offline".to_vec(), true));
                        }
                    }
                }
                event = event_receiver.recv() => match event.context("MQTT event worker stopped")?? {
                    Event::Incoming(Packet::ConnAck(_)) => {
                        connected = true;
                        self.state(true, "running", None);
                        client.try_subscribe("homeassistant/status", QoS::AtLeastOnce)?;
                    }
                    Event::Incoming(Packet::Publish(publication)) if publication.topic == "homeassistant/status" && publication.payload == "online" => {
                        force_discovery = true;
                        next_sample = next_sample.min(Instant::now() + Duration::from_secs(5));
                    }
                    Event::Incoming(Packet::PubAck(_)) => {
                        pending = pending.saturating_sub(1);
                        if pending == 0 && queue.is_empty() && batch_has_state {
                            if let Some(keys) = manifest.take() {
                                self.secrets.lock().map_err(|_| anyhow::anyhow!("MQTT store unavailable"))?.save_components(&keys)?;
                            }
                            self.state(true, "running", None);
                            if let Ok(mut status) = self.status.lock() {
                                status["last_published_at_unix"] = json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
                            }
                            batch_has_state = false;
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(task) = collecting {
            task.abort();
        }
        let closing = async {
            client
                .publish(
                    format!("{base}/availability"),
                    QoS::AtLeastOnce,
                    true,
                    "offline",
                )
                .await?;
            client.disconnect().await?;
            loop {
                let event = event_receiver
                    .recv()
                    .await
                    .context("MQTT event worker stopped")??;
                if matches!(event, Event::Outgoing(rumqttc::Outgoing::Disconnect)) {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        let _ = tokio::time::timeout(Duration::from_secs(3), closing).await;
        polling.shutdown().await;
        Ok(())
    }
}

fn bind_source(events: &mut EventLoop, interface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        ensure!(!interface.is_empty(), "MQTT source interface is required");
        events.network_options.set_bind_device(interface);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (events, interface);
        anyhow::bail!("MQTT interface binding requires Linux")
    }
}

fn metric_key(kind: &str, name: &str, field: &str) -> String {
    format!(
        "{kind}_{}_{field}",
        hex::encode(Sha256::digest(name.as_bytes()))
    )
}

fn telemetry(
    device_id: &str,
    config: &MQTTConfig,
    revision: u64,
    uptime: u64,
    statistics: &Value,
) -> Result<(Value, Value)> {
    let base = format!("netcontrol/{device_id}");
    let mut metrics = Map::new();
    let mut components = Map::new();
    let mut add = |key: String,
                   name: String,
                   value: Value,
                   unit: Option<&str>,
                   cumulative: bool| {
        let mut component = json!({"platform":"sensor","name":name,"unique_id":format!("netcontrol_{device_id}_{key}"),
            "value_template":format!("{{{{ value_json.metrics.get('{key}') if value_json.metrics.get('{key}') is not none else 'unknown' }}}}"),
            "expire_after":config.interval_seconds * 3});
        if let Some(unit) = unit {
            component["unit_of_measurement"] = json!(unit);
            component["state_class"] = json!(if cumulative {
                "total_increasing"
            } else {
                "measurement"
            });
        }
        metrics.insert(key.clone(), value);
        components.insert(key, component);
    };
    add(
        "revision".into(),
        "Configuration revision".into(),
        json!(revision),
        None,
        false,
    );
    add(
        "uptime".into(),
        "Daemon uptime".into(),
        json!(uptime),
        Some("s"),
        false,
    );
    let version = env!("CARGO_PKG_VERSION");
    add(
        "version".into(),
        "Firewall version".into(),
        if version == "0.0.0" {
            Value::Null
        } else {
            json!(version)
        },
        None,
        false,
    );
    for interface in statistics["interfaces"]
        .as_array()
        .context("statistics interfaces missing")?
    {
        let name = interface["name"]
            .as_str()
            .context("statistics interface name missing")?;
        let available = interface["status"] == "available";
        add(
            metric_key("interface", name, "oper_state"),
            format!("{name} link state"),
            if available {
                interface["oper_state"].clone()
            } else {
                Value::Null
            },
            None,
            false,
        );
        for field in [
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
            "rx_errors",
            "tx_errors",
            "rx_dropped",
            "tx_dropped",
        ] {
            add(
                metric_key("interface", name, field),
                format!("{name} {field}"),
                if available {
                    interface["counters"][field].clone()
                } else {
                    Value::Null
                },
                Some(if field.ends_with("bytes") {
                    "B"
                } else {
                    "packets"
                }),
                true,
            );
        }
    }
    if let Some(gateways) = statistics["gateways"].as_array() {
        for gateway in gateways {
            let name = gateway["name"].as_str().context("gateway name missing")?;
            let available = gateway["sample_status"] == "available";
            for field in [
                "health",
                "sample_status",
                "process_state",
                "sent",
                "received",
                "lost",
                "pending",
                "loss_percent",
                "rtt_min_ms",
                "rtt_max_ms",
                "rtt_avg_ms",
                "rtt_stddev_ms",
                "rtt_p50_ms",
                "rtt_p95_ms",
                "rtt_variation_ms",
            ] {
                let unit = if field.ends_with("_ms") {
                    Some("ms")
                } else if field == "loss_percent" {
                    Some("%")
                } else {
                    None
                };
                let value = if available || matches!(field, "sample_status" | "process_state") {
                    gateway[field].clone()
                } else {
                    Value::Null
                };
                add(
                    metric_key("gateway", name, field),
                    format!("{name} {field}"),
                    value,
                    unit,
                    false,
                );
            }
        }
    }
    ensure!(components.len() <= 4096, "MQTT entity limit exceeded");
    let discovery = json!({"device":{"identifiers":[format!("netcontrol_{device_id}")],"name":format!("Netcontrol {}", &device_id[..8]),"manufacturer":"Netcontrol","model":"Firewall"},
        "origin":{"name":"netcontrold"},"components":components,"state_topic":format!("{base}/state"),
        "availability_topic":format!("{base}/availability"),"qos":1});
    let state = json!({"collected_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),"metrics":metrics});
    ensure!(
        serde_json::to_vec(&discovery)?.len() <= 1 << 20
            && serde_json::to_vec(&state)?.len() <= 1 << 20,
        "MQTT payload limit exceeded"
    );
    Ok((discovery, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{App, Authentication, Credential};
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    async fn api(
        app: Arc<App>,
        method: &str,
        path: &str,
        body: Value,
        token: &str,
    ) -> (u16, Value) {
        let response = crate::http::router(app)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn mqtt_api_secrets_permissions_confirmation_and_simulated_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager = Manager::open(
            &directory.path().join("mqtt"),
            engine.clone(),
            Mode::Simulated,
        )
        .unwrap();
        let mut app = App::new(
            engine,
            Authentication::Scoped(vec![
                Credential {
                    name: "writer".into(),
                    token_sha256: crate::identity::digest("synthetic-writer-token"),
                    permissions: netcontrol_core::PERMISSIONS
                        .iter()
                        .map(|permission| (*permission).into())
                        .collect(),
                },
                Credential {
                    name: "reader".into(),
                    token_sha256: crate::identity::digest("synthetic-reader-token"),
                    permissions: vec!["state.read".into(), "transactions.write".into()],
                },
            ]),
            false,
        );
        App::attach_mqtt(&mut app, manager.clone()).unwrap();
        let (stop, receiver) = watch::channel(false);
        let worker = tokio::spawn(manager.clone().run(receiver));
        assert_eq!(
            api(
                app.clone(),
                "GET",
                "/api/v1/services/mqtt/status",
                Value::Null,
                "bad-token"
            )
            .await
            .0,
            401
        );
        assert_eq!(
            api(
                app.clone(),
                "POST",
                "/api/v1/services/mqtt/passwords",
                json!({"password":"synthetic-only"}),
                "synthetic-reader-token"
            )
            .await
            .0,
            403
        );
        assert_eq!(
            api(
                app.clone(),
                "POST",
                "/api/v1/services/mqtt/passwords",
                json!({"password":null}),
                "synthetic-writer-token"
            )
            .await
            .0,
            400
        );
        let (status, created) = api(
            app.clone(),
            "POST",
            "/api/v1/services/mqtt/passwords",
            json!({"password":"synthetic-password-not-for-production"}),
            "synthetic-writer-token",
        )
        .await;
        assert_eq!(status, 201);
        assert!(created.get("password").is_none());
        let config = json!({"interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
            "mqtt":{"enabled":true,"endpoint":"mqtt://broker.example.test","username":"fixture","password_ref":created["password_ref"],"source_interface":"lan0"}});
        let (status, transaction) = api(
            app.clone(),
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":0,"confirm_timeout_seconds":30,"config":config}),
            "synthetic-writer-token",
        )
        .await;
        assert_eq!(status, 202, "{transaction}");
        assert_eq!(manager.status().unwrap()["enabled"], false);
        assert!(manager.collect(&MQTTConfig::default()).is_err());
        assert_eq!(
            api(
                app.clone(),
                "POST",
                "/api/v1/services/mqtt/passwords",
                json!({"password":"replacement"}),
                "synthetic-writer-token"
            )
            .await
            .0,
            409
        );
        assert_eq!(
            api(
                app.clone(),
                "POST",
                &format!(
                    "/api/v1/transactions/{}/confirm",
                    transaction["id"].as_str().unwrap()
                ),
                Value::Null,
                "synthetic-writer-token"
            )
            .await
            .0,
            200
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if manager.status().unwrap()["state"] == "simulated" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (status, state) = api(
            app.clone(),
            "GET",
            "/api/v1/state",
            Value::Null,
            "synthetic-reader-token",
        )
        .await;
        assert_eq!(status, 200);
        assert!(
            !serde_json::to_string(&state)
                .unwrap()
                .contains("synthetic-password-not-for-production")
        );
        let mut disabled = state["desired"].clone();
        disabled["mqtt"]["enabled"] = json!(false);
        assert_eq!(
            api(
                app.clone(),
                "POST",
                "/api/v1/transactions",
                json!({"base_revision":1,"confirm_timeout_seconds":30,"config":disabled}),
                "synthetic-reader-token"
            )
            .await
            .0,
            403
        );
        disabled["mqtt"]["password_ref"] = json!("00000000000000000000000000000000");
        assert_eq!(
            api(
                app.clone(),
                "POST",
                "/api/v1/transactions",
                json!({"base_revision":1,"confirm_timeout_seconds":30,"config":disabled}),
                "synthetic-writer-token"
            )
            .await
            .0,
            422
        );
        disabled["mqtt"]["password_ref"] = created["password_ref"].clone();
        let (status, transaction) = api(
            app.clone(),
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":1,"confirm_timeout_seconds":30,"config":disabled}),
            "synthetic-writer-token",
        )
        .await;
        assert_eq!(status, 202, "{transaction}");
        assert_eq!(
            api(
                app.clone(),
                "POST",
                &format!(
                    "/api/v1/transactions/{}/rollback",
                    transaction["id"].as_str().unwrap()
                ),
                Value::Null,
                "synthetic-writer-token"
            )
            .await
            .0,
            200
        );
        assert!(
            manager
                .engine
                .lock()
                .unwrap()
                .saved_configuration()
                .mqtt
                .enabled
        );
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(manager.status().unwrap()["state"], "stopped");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mqtt_missing_source_interface_never_falls_back() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager = Manager::open(&directory.path().join("mqtt"), engine, Mode::Native).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = MQTTConfig {
            endpoint: format!("mqtt://{}", listener.local_addr().unwrap()),
            source_interface: "no-such0".into(),
            ..Default::default()
        };
        let (_client, mut events) = manager.connection(&config).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), events.poll())
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    async fn broker_fixture(
        listener: tokio::net::TcpListener,
        messages: tokio::sync::mpsc::Sender<(usize, String, Vec<u8>)>,
    ) -> Result<()> {
        use bytes::BytesMut;
        use rumqttc::{ConnAck, ConnectReturnCode, PubAck, Publish, SubAck, SubscribeReasonCode};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for connection in 1..=2 {
            let (mut stream, peer) = listener.accept().await?;
            ensure!(
                peer.ip().to_string() == "198.18.0.1",
                "MQTT source address did not use the selected interface"
            );
            let mut input = BytesMut::new();
            let mut state_count = 0;
            'connection: loop {
                if stream.read_buf(&mut input).await? == 0 {
                    break;
                }
                loop {
                    let packet = match Packet::read(&mut input, (1 << 20) + 4096) {
                        Ok(packet) => packet,
                        Err(rumqttc::mqttbytes::Error::InsufficientBytes(_)) => break,
                        Err(_) => anyhow::bail!("invalid MQTT fixture packet"),
                    };
                    let mut output = BytesMut::new();
                    match packet {
                        Packet::Connect(connect) => {
                            ensure!(
                                connect.client_id.starts_with("netcontrol_"),
                                "invalid client identity"
                            );
                            ensure!(
                                connect.keep_alive == 30 && connect.clean_session,
                                "invalid connection lifecycle"
                            );
                            let login = connect.login.context("MQTT credentials missing")?;
                            ensure!(
                                login.username == "fixture"
                                    && login.password == "synthetic-broker-password",
                                "MQTT authentication fixture mismatch"
                            );
                            ensure!(
                                connect.last_will.context("MQTT will missing")?.message
                                    == "offline",
                                "invalid MQTT last will"
                            );
                            ConnAck::new(ConnectReturnCode::Success, false).write(&mut output)?;
                        }
                        Packet::Subscribe(subscribe) => {
                            SubAck::new(
                                subscribe.pkid,
                                vec![SubscribeReasonCode::Success(QoS::AtLeastOnce)],
                            )
                            .write(&mut output)?;
                        }
                        Packet::Publish(publication) => {
                            let state = publication.topic.ends_with("/state");
                            messages
                                .send((
                                    connection,
                                    publication.topic.clone(),
                                    publication.payload.to_vec(),
                                ))
                                .await?;
                            if publication.qos == QoS::AtLeastOnce {
                                PubAck::new(publication.pkid).write(&mut output)?;
                            }
                            if state {
                                state_count += 1;
                                if connection == 1 && state_count == 1 {
                                    Publish::new("homeassistant/status", QoS::AtMostOnce, "online")
                                        .write(&mut output)?;
                                }
                            }
                            stream.write_all(&output).await?;
                            if connection == 1 && state_count == 2 {
                                break 'connection;
                            }
                            continue;
                        }
                        Packet::PingReq => {
                            rumqttc::PingResp.write(&mut output)?;
                        }
                        Packet::Disconnect => {
                            messages
                                .send((connection, "$disconnect".into(), Vec::new()))
                                .await?;
                            break 'connection;
                        }
                        _ => {}
                    }
                    stream.write_all(&output).await?;
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1, Linux net_admin/sys_admin, nft and a stable machine ID"]
    fn mqtt_native_persistent_reconnect_and_confirmed_disable() -> Result<()> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "set NETCONTROL_INTEGRATION=1"
        );
        std::thread::spawn(|| -> Result<()> {
            ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0, "MQTT fixture requires private network namespace");
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            ensure!(descriptor >= 0, "MQTT fixture interface socket failed");
            let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            request.ifr_name[0] = b'l' as libc::c_char;
            request.ifr_name[1] = b'o' as libc::c_char;
            ensure!(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) } == 0, "read fixture loopback flags");
            unsafe { request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short; }
            ensure!(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &request) } == 0, "enable fixture loopback");
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
                use netcontrol_core::{Backend, Config, Simulator};
                let directory = tempfile::tempdir()?;
                let mut native = netcontrol_native::Native::open(netcontrol_native::NativeOptions {
                    namespace:String::new(), keys:directory.path().join("keys"), adopted_parents:Vec::new(),
                    allow_host_tunables:false, allow_host_services:false, gateway_monitoring:false,
                    services_state:directory.path().join("native"),
                })?;
                let empty = Config::empty();
                native.repair(&empty)?;
                let physical: Config = serde_json::from_value(json!({"interfaces":[{"name":"mqtt0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["198.18.0.1/24"]}]}))?;
                native.apply(&empty, &physical)?;
                let listener = tokio::net::TcpListener::bind("198.18.0.1:0").await?;
                let endpoint = format!("mqtt://{}", listener.local_addr()?);
                let engine = Arc::new(Mutex::new(Engine::open(&directory.path().join("state.json"), Box::new(Simulator::new()))?));
                let manager = Manager::open(&directory.path().join("mqtt"), engine.clone(), Mode::Native)?;
                let password_ref = manager.create_password(&mut engine.lock().unwrap(), "synthetic-broker-password")?;
                let mut config = physical.clone();
                config.mqtt = MQTTConfig { enabled:true, endpoint, username:"fixture".into(), password_ref, source_interface:"mqtt0".into(), interval_seconds:10 };
                let permissions: Vec<String> = netcontrol_core::PERMISSIONS.iter().map(|permission| (*permission).into()).collect();
                let submit = |config: &Config, revision| {
                    engine.lock().unwrap().request("POST", "/api/v1/transactions", "", "fixture", &permissions,
                        &serde_json::to_vec(&json!({"base_revision":revision,"confirm_timeout_seconds":30,"config":config})).unwrap())
                };
                let confirm = |id: &str| engine.lock().unwrap().request("POST", &format!("/api/v1/transactions/{id}/confirm"), "", "fixture", &permissions, &[]);
                let (stop, receiver) = watch::channel(false);
                let worker = tokio::spawn(manager.clone().run(receiver));
                let transaction = submit(&config, 0);
                ensure!(transaction.status == 202, "MQTT fixture transaction rejected");
                ensure!(tokio::time::timeout(Duration::from_millis(1200), listener.accept()).await.is_err(), "MQTT connected before confirmation");
                ensure!(confirm(transaction.body["id"].as_str().unwrap()).status == 200, "MQTT confirmation failed");
                let (messages, mut receive) = tokio::sync::mpsc::channel(64);
                let broker = tokio::spawn(broker_fixture(listener, messages));
                let mut connections = Vec::new();
                tokio::time::timeout(Duration::from_secs(25), async {
                    while connections.len() < 3 {
                        let (connection, topic, payload) = receive.recv().await.context("MQTT broker fixture stopped")?;
                        if topic.ends_with("/state") {
                            let value: Value = serde_json::from_slice(&payload)?;
                            ensure!(value["metrics"]["revision"] == 1, "unconfirmed or wrong revision published");
                            connections.push(connection);
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }).await.with_context(|| format!("MQTT sample sequence incomplete: status={}, connections={connections:?}, broker_finished={}", manager.status().unwrap(), broker.is_finished()))??;
                ensure!(connections == [1, 1, 2], "MQTT connection was not persistent or failed to reconnect");
                config.mqtt.enabled = false;
                let transaction = submit(&config, 1);
                ensure!(transaction.status == 202 && confirm(transaction.body["id"].as_str().unwrap()).status == 200, "MQTT disable failed");
                tokio::time::timeout(Duration::from_secs(6), async {
                    let mut offline = false;
                    loop {
                        let (_, topic, payload) = receive.recv().await.context("MQTT broker fixture stopped")?;
                        if topic.ends_with("/availability") && payload == b"offline" { offline = true; }
                        if topic == "$disconnect" {
                            ensure!(offline, "MQTT disconnect did not publish offline");
                            break;
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }).await??;
                broker.await??;
                stop.send(true)?;
                tokio::time::timeout(Duration::from_secs(5), worker).await??;
                native.apply(&physical, &empty)?;
                Ok(())
            })
        }).join().map_err(|_| anyhow::anyhow!("MQTT namespace fixture panicked"))?
    }

    #[test]
    fn mqtt_password_store_is_private_immutable_and_persistent() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("mqtt");
        let secrets = Secrets::open(&root).unwrap();
        let identity = secrets.device_id.clone();
        let reference = secrets.create_password("synthetic-fixture-only").unwrap();
        let second = secrets.create_password("replacement-fixture-only").unwrap();
        assert_ne!(reference, second);
        assert_eq!(
            &**secrets.password(&reference).unwrap(),
            "synthetic-fixture-only"
        );
        assert!(secrets.password("../device-id").is_err());
        assert!(Secrets::open(&root).is_err());
        assert!(write_new_private(&root.join("device-id"), b"replacement").is_err());
        let components = BTreeSet::from(["revision".to_owned()]);
        secrets.save_components(&components).unwrap();
        secrets.save_components(&components).unwrap();
        assert_eq!(secrets.components().unwrap(), components);
        assert!(!fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pending")
        }));
        drop(secrets);
        let secrets = Secrets::open(&root).unwrap();
        assert_eq!(secrets.device_id, identity);
        assert_eq!(secrets.references().unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join(format!("password-{reference}")))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            std::os::unix::fs::symlink(
                root.join("device-id"),
                root.join("password-00000000000000000000000000000000"),
            )
            .unwrap();
            assert!(secrets.references().is_err());
        }
    }

    #[test]
    fn mqtt_discovery_preserves_precision_and_unknown_measurements() {
        let config = MQTTConfig::default();
        let stats = json!({"interfaces":[{"name":"wan.1","status":"available","oper_state":"up","counters":{"rx_bytes":"18446744073709551615"}}],
            "gateways":[{"name":"wan","sample_status":"stale","health":"up","sent":30,"rtt_avg_ms":5.0}]});
        let id = "0123456789abcdef0123456789abcdef";
        let (discovery, state) = telemetry(id, &config, 42, 60, &stats).unwrap();
        assert_eq!(
            state["metrics"][metric_key("interface", "wan.1", "rx_bytes")],
            "18446744073709551615"
        );
        assert!(state["metrics"][metric_key("interface", "wan.1", "tx_bytes")].is_null());
        assert!(state["metrics"][metric_key("gateway", "wan", "rtt_avg_ms")].is_null());
        assert!(state["metrics"][metric_key("gateway", "wan", "health")].is_null());
        assert_eq!(state["metrics"]["revision"], 42);
        assert_eq!(discovery["components"]["revision"]["platform"], "sensor");
        assert_eq!(
            discovery["components"][metric_key("interface", "wan.1", "rx_bytes")]["state_class"],
            "total_increasing"
        );
        let serialized = serde_json::to_string(&discovery).unwrap();
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("command_topic"));
    }
}
