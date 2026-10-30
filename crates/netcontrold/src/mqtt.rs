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

use crate::private_store::{identifier, private_file, read_private, valid_id, write_new_private};
use anyhow::{Context, Result, ensure};
use netcontrol_core::{Engine, MQTTConfig};
use rumqttc::{AsyncClient, Event, EventLoop, LastWill, MqttOptions, Packet, QoS, Transport};
use serde::Serialize;
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
        Self::validate_components(&components)?;
        Ok(components)
    }

    fn validate_components(components: &BTreeSet<String>) -> Result<()> {
        ensure!(
            components.len() <= 8192 && components.iter().all(|key| valid_component(key)),
            "invalid MQTT discovery manifest"
        );
        Ok(())
    }

    fn save_components(&self, components: &BTreeSet<String>) -> Result<()> {
        Self::validate_components(components)?;
        let bytes = serde_json::to_vec(components)?;
        ensure!(
            bytes.len() <= 1 << 20,
            "MQTT discovery manifest size limit exceeded"
        );
        let pending = self
            .root
            .join(format!("components-{}.pending", identifier()));
        let result = (|| {
            let mut file = private_file(&pending, true)?;
            file.write_all(&bytes)?;
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
    pub(crate) health: Arc<crate::health::Monitor>,
    secrets: Mutex<Secrets>,
    status: Mutex<Status>,
    engine: Arc<Mutex<Engine>>,
    mode: Mode,
    started: Instant,
    device_id: String,
    cpu_baseline: Mutex<Option<crate::mqtt_host::CpuBaseline>>,
    sando: Mutex<Option<Arc<crate::sando::Manager>>>,
}

type Publication = (String, Vec<u8>, bool);

#[derive(Clone, Copy, Debug, Serialize)]
struct Failure {
    category: &'static str,
    message: &'static str,
    os_error_code: Option<i32>,
}

impl Failure {
    const fn new(category: &'static str, message: &'static str) -> Self {
        Self {
            category,
            message,
            os_error_code: None,
        }
    }

    fn classify(error: &anyhow::Error) -> Self {
        use rumqttc::{ConnectReturnCode, ConnectionError, StateError};
        if let Some(failure) = error.downcast_ref::<Self>() {
            return *failure;
        }
        // Never format library errors: they can contain credentials, packets or peer data.
        match error.downcast_ref::<ConnectionError>() {
            Some(ConnectionError::ConnectionRefused(code)) => match code {
                ConnectReturnCode::BadUserNamePassword => Self::new(
                    "authentication",
                    "MQTT broker rejected the username or password",
                ),
                ConnectReturnCode::NotAuthorized => Self::new(
                    "authorization",
                    "MQTT broker denied connection authorization",
                ),
                ConnectReturnCode::BadClientId => {
                    Self::new("client_id", "MQTT broker rejected the client ID")
                }
                ConnectReturnCode::ServiceUnavailable => {
                    Self::new("broker_unavailable", "MQTT broker reported unavailable")
                }
                _ => Self::new(
                    "protocol",
                    "MQTT broker rejected the protocol or connection",
                ),
            },
            Some(ConnectionError::Io(error))
            | Some(ConnectionError::MqttState(StateError::Io(error)))
            | Some(ConnectionError::MqttState(StateError::Deserialization(
                rumqttc::mqttbytes::Error::Io(error),
            ))) => Self::io(error),
            Some(ConnectionError::Tls(
                rumqttc::TlsError::TLS(rustls::Error::InvalidCertificate(_))
                | rumqttc::TlsError::WebPki(_),
            )) => Self::new(
                "tls_certificate",
                "MQTT broker certificate validation failed; check trust, hostname and clock",
            ),
            Some(ConnectionError::Tls(_)) => Self::new(
                "tls",
                "MQTT TLS handshake failed; check certificate trust, hostname, clock and broker TLS settings",
            ),
            Some(ConnectionError::NetworkTimeout) => {
                Self::new("connection_timeout", "MQTT broker connection timed out")
            }
            Some(ConnectionError::FlushTimeout) => {
                Self::new("write_timeout", "MQTT socket write timed out")
            }
            Some(ConnectionError::MqttState(StateError::AwaitPingResp)) => Self::new(
                "keepalive_timeout",
                "MQTT broker did not acknowledge the keepalive ping",
            ),
            Some(ConnectionError::MqttState(StateError::ConnectionAborted)) => {
                Self::new("connection_closed", "MQTT broker closed the connection")
            }
            Some(ConnectionError::MqttState(StateError::Deserialization(
                rumqttc::mqttbytes::Error::OutgoingPacketTooLarge { .. }
                | rumqttc::mqttbytes::Error::PayloadTooLong
                | rumqttc::mqttbytes::Error::PayloadSizeLimitExceeded(_),
            ))) => Self::new("packet_size", "MQTT packet exceeds the client size limit"),
            Some(ConnectionError::MqttState(_)) | Some(ConnectionError::NotConnAck(_)) => {
                Self::new("protocol", "MQTT protocol or acknowledgment sequence error")
            }
            Some(ConnectionError::RequestsDone) => {
                Self::new("client_channel", "MQTT client request channel closed")
            }
            None => {
                if error.downcast_ref::<rumqttc::ClientError>().is_some() {
                    Self::new("client_channel", "MQTT client request could not be queued")
                } else {
                    Self::new(
                        "internal",
                        "MQTT session failed; inspect daemon and broker health",
                    )
                }
            }
        }
    }

    fn io(error: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        #[cfg(target_os = "linux")]
        if error.raw_os_error() == Some(libc::ENODEV) {
            return Self {
                os_error_code: error.raw_os_error(),
                ..Self::new("source_interface", "MQTT source interface does not exist")
            };
        }
        let (category, message) = match error.kind() {
            ErrorKind::ConnectionRefused => (
                "connection_refused",
                "MQTT TCP connection refused; check broker listener and port",
            ),
            ErrorKind::ConnectionReset => ("connection_reset", "MQTT connection reset by peer"),
            ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof => {
                ("connection_closed", "MQTT connection closed or interrupted")
            }
            ErrorKind::TimedOut => ("network_timeout", "MQTT network operation timed out"),
            ErrorKind::PermissionDenied => (
                "permission_denied",
                "MQTT socket permission denied; check source-interface binding privileges and firewall policy",
            ),
            ErrorKind::AddrNotAvailable => (
                "source_interface",
                "MQTT local address unavailable; check the selected interface",
            ),
            ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => (
                "network_unreachable",
                "MQTT broker network or host is unreachable",
            ),
            _ => (
                "network_io",
                "MQTT network I/O failed; check DNS, routing, source interface and broker logs",
            ),
        };
        Self {
            os_error_code: error.raw_os_error(),
            ..Self::new(category, message)
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for Failure {}

#[derive(Serialize)]
struct RecordedFailure {
    #[serde(flatten)]
    failure: Failure,
    at_unix: i64,
}

#[derive(Default, Serialize)]
struct Status {
    device_id: String,
    enabled: bool,
    state: String,
    error: Option<String>,
    last_published_at_unix: Option<u64>,
    connection_attempts: u64,
    reconnect_count: u64,
    last_connected_at_unix: Option<i64>,
    last_failure: Option<RecordedFailure>,
}

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
            health: Arc::new(crate::health::Monitor::default()),
            secrets: Mutex::new(secrets),
            status: Mutex::new(Status {
                device_id: device_id.clone(),
                state: "disabled".into(),
                ..Status::default()
            }),
            engine,
            mode,
            started: Instant::now(),
            device_id,
            cpu_baseline: Mutex::new(None),
            sando: Mutex::new(None),
        }))
    }

    pub(crate) fn attach_sando(&self, manager: Arc<crate::sando::Manager>) -> Result<()> {
        *self
            .sando
            .lock()
            .map_err(|_| anyhow::anyhow!("MQTT Sando source unavailable"))? = Some(manager);
        Ok(())
    }

    pub fn status(&self) -> Result<Value> {
        let status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("MQTT status unavailable"))?;
        Ok(serde_json::to_value(&*status)?)
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
        self.update_status(|value| {
            value.enabled = enabled;
            value.state = state.into();
            value.error = error.map(str::to_owned);
        });
    }

    fn update_status(&self, update: impl FnOnce(&mut Status)) {
        match self.status.lock() {
            Ok(mut status) => update(&mut status),
            Err(_) => tracing::error!("MQTT status unavailable"),
        }
    }

    fn attempting(&self) {
        self.update_status(|status| {
            status.enabled = true;
            status.state = "connecting".into();
            status.connection_attempts = status.connection_attempts.saturating_add(1);
        });
    }

    fn connected(&self) {
        self.update_status(|status| {
            status.enabled = true;
            status.state = "running".into();
            status.error = None;
            status.last_connected_at_unix = Some(time::OffsetDateTime::now_utc().unix_timestamp());
        });
    }

    fn failed(&self, error: &anyhow::Error) {
        let failure = Failure::classify(error);
        tracing::warn!(
            category = failure.category,
            reason = failure.message,
            os_error_code = failure.os_error_code,
            "MQTT session failed; retrying in five seconds"
        );
        self.update_status(|status| {
            status.enabled = true;
            status.state = "reconnecting".into();
            status.error = Some(failure.message.into());
            status.reconnect_count = status.reconnect_count.saturating_add(1);
            status.last_failure = Some(RecordedFailure {
                failure,
                at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
            });
        });
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
                        self.attempting();
                        let result = self.session(config, stop.clone()).await;
                        if *stop.borrow() { break; }
                        if let Err(error) = result {
                            self.failed(&error);
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
        let (host, port, tls) = config.broker().context(Failure::new(
            "configuration",
            "MQTT broker endpoint is invalid",
        ))?;
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
                .map_err(|_| Failure::new("credentials", "MQTT password store unavailable"))?;
            let password = secrets
                .password(&config.password_ref)
                .context(Failure::new(
                    "credentials",
                    "MQTT stored password could not be read",
                ))?;
            options.set_credentials(&config.username, &**password);
        }
        if tls {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_native_certs::load_native_certs().certs {
                roots.add(certificate).context(Failure::new(
                    "tls_configuration",
                    "MQTT trusted CA certificate could not be loaded",
                ))?;
            }
            ensure!(
                !roots.is_empty(),
                Failure::new("tls_configuration", "MQTT TLS trust store is empty")
            );
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .context(Failure::new(
                "tls_configuration",
                "MQTT TLS configuration failed",
            ))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            options.set_transport(Transport::tls_with_config(tls.into()));
        }
        let (client, mut events) = AsyncClient::new(options, 8);
        events.network_options.set_connection_timeout(5);
        bind_source(&mut events, &config.source_interface).context(Failure::new(
            "source_interface",
            "MQTT source interface binding setup failed",
        ))?;
        Ok((client, events))
    }

    fn collect(&self, config: &MQTTConfig) -> Result<(Value, Value, Vec<&'static str>)> {
        let (
            revision,
            mut statistics,
            statistics_available,
            snapshot,
            runtime,
            firewall,
            firewall_readable,
            software,
            sando_config,
        ) = {
            let mut engine = self
                .engine
                .lock()
                .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
            ensure!(!engine.configuration_busy(), "configuration is changing");
            let revision = engine.committed_revision();
            let software = engine.saved_configuration().software.clone();
            let sando_config = engine.saved_configuration().sando.clone();
            let mut read = |path| {
                let reply = engine.request(
                    "GET",
                    path,
                    "",
                    "mqtt-publisher",
                    &["state.read".into()],
                    &[],
                );
                (reply.status == 200).then_some(reply.body)
            };
            let statistics = read("/api/v1/statistics");
            let available = statistics.is_some();
            let mut statistics =
                statistics.unwrap_or_else(|| json!({"interfaces":[],"gateways":[]}));
            if !available && let Some(protocols) = read("/api/v1/statistics/protocols") {
                statistics["protocols"] = protocols["protocols"].clone();
            }
            let runtime = read("/api/v1/runtime");
            if statistics.get("bgp").is_none()
                && let Some(bgp) = read("/api/v1/services/bgp/status")
            {
                statistics["bgp"] = bgp;
            }
            let snapshot = read("/api/v1/statistics/host");
            let firewall = read("/api/v1/statistics/firewall");
            let firewall_readable = firewall.is_some();
            let firewall = crate::mqtt_stats::firewall(
                firewall.as_ref(),
                &engine.saved_configuration().firewall,
            )?;
            (
                revision,
                statistics,
                available,
                snapshot,
                runtime,
                firewall,
                firewall_readable,
                software,
                sando_config,
            )
        };
        // All engine reads share one committed configuration; failed sources remain independent.
        let sando = self
            .sando
            .lock()
            .map_err(|_| anyhow::anyhow!("MQTT Sando source unavailable"))?
            .clone();
        let sando = match sando
            .as_ref()
            .map(|manager| manager.mqtt_status(&sando_config))
        {
            Some(Ok(status)) => Some(status),
            Some(Err(_)) => {
                tracing::warn!("Sando summary unavailable for MQTT");
                None
            }
            None => None,
        };
        let mut host = {
            let mut baseline = self
                .cpu_baseline
                .lock()
                .map_err(|_| anyhow::anyhow!("CPU baseline unavailable"))?;
            crate::mqtt_host::sensors(snapshot.as_ref(), &mut baseline)
        };
        if !statistics_available {
            host.retained.extend(["interface", "gateway"]);
        }
        for extra in [
            crate::mqtt_stats::protocols(&statistics)?,
            crate::mqtt_stats::services(runtime.as_ref())?,
            crate::mqtt_stats::bgp(statistics.get("bgp"))?,
            firewall,
            crate::mqtt_stats::software(&software),
            crate::mqtt_stats::sando(sando.as_ref()),
        ] {
            host.sensors.extend(extra.sensors);
            host.retained.extend(extra.retained);
        }
        statistics["telemetry_sources"] = json!({
            "network": statistics_available,
            "protocols": statistics["protocols"].is_array(),
            "host": snapshot.is_some(),
            "services": runtime.is_some(),
            "bgp": statistics.get("bgp").is_some(),
            "firewall": firewall_readable,
            "sando": sando.is_some()
        });
        for (source, readable) in statistics["telemetry_sources"]
            .as_object()
            .context("MQTT telemetry sources missing")?
        {
            crate::mqtt_host::push(
                &mut host.sensors,
                format!("source_{source}_readable"),
                format!("{source} statistics readable"),
                readable.clone(),
                None,
                None,
            );
        }
        let (mut discovery, mut state) = telemetry(
            &self.device_id,
            config,
            revision,
            self.started.elapsed().as_secs(),
            &statistics,
            &host,
        )?;
        let health = self.health.snapshot();
        state["process_health"] = health["process_health"].clone();
        state["active_alerts"] = health["active_alerts"].clone();
        state["statistics_available"] = json!(statistics_available);
        state["telemetry_sources"] = statistics["telemetry_sources"].clone();
        for (key, name, value) in [
            (
                "process_health",
                "Process health",
                health["process_health"]["status"].clone(),
            ),
            (
                "active_alert_count",
                "Active alert count",
                json!(health["active_alerts"].as_array().map_or(0, Vec::len)),
            ),
        ] {
            state["metrics"][key] = value;
            discovery["components"][key] = json!({"platform":"sensor","name":name,"unique_id":format!("netcontrol_{}_{key}", self.device_id),
                "value_template":format!("{{{{ value_json.metrics.get('{key}', 'unknown') }}}}"),"expire_after":config.interval_seconds * 3});
        }
        validate_telemetry(&discovery, &state)?;
        Ok((discovery, state, host.retained))
    }

    async fn session(
        self: &Arc<Self>,
        config: MQTTConfig,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let (client, mut events) = self.connection(&config)?;
        *self
            .cpu_baseline
            .lock()
            .map_err(|_| anyhow::anyhow!("CPU baseline unavailable"))? = None;
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
        let mut acknowledgement_deadline = None;
        let mut batch_has_state = false;
        let mut manifest = None::<BTreeSet<String>>;
        let mut previous_discovery = None::<Value>;
        let mut force_discovery = true;
        let mut next_sample = Instant::now();
        let mut collecting =
            None::<tokio::task::JoinHandle<Result<(Value, Value, Vec<&'static str>)>>>;
        loop {
            while let Some((topic, payload, retain)) = queue.front() {
                if client
                    .try_publish(topic, QoS::AtLeastOnce, *retain, payload.clone())
                    .is_err()
                {
                    break;
                }
                if pending == 0 {
                    acknowledgement_deadline = Some(Instant::now() + Duration::from_secs(30));
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
                    ensure!(acknowledgement_deadline.is_none_or(|deadline| Instant::now() < deadline), Failure::new(
                        "publication_ack_timeout", "MQTT broker did not acknowledge publications for 30 seconds; check publish ACLs, packet limits and broker logs"
                    ));
                    if connected && collecting.is_none() && pending == 0 && queue.is_empty() && Instant::now() >= next_sample {
                        let manager = self.clone();
                        let settings = config.clone();
                        collecting = Some(tokio::task::spawn_blocking(move || manager.collect(&settings)));
                        next_sample = Instant::now() + Duration::from_secs(config.interval_seconds);
                    }
                }
                result = async { collecting.as_mut().unwrap().await }, if collecting.is_some() => {
                    collecting = None;
                    match result.context("MQTT statistics worker failed").and_then(|result| result) {
                        Ok((mut discovery, state, retained)) => {
                            if let Some(previous) = previous_discovery.as_ref().and_then(|previous| previous["components"].as_object()) {
                                for (key, component) in previous.iter().filter(|(key, _)| retained.iter().any(|kind| key.starts_with(&format!("{kind}_")))) {
                                    discovery["components"][key] = component.clone();
                                }
                            }
                            if validate_telemetry(&discovery, &state).is_err() {
                                self.state(true, "error", Some("MQTT entity or payload limit exceeded"));
                                queue.push_back((format!("{base}/availability"), b"offline".to_vec(), true));
                                continue;
                            }
                            if force_discovery || previous_discovery.as_ref() != Some(&discovery) {
                                let secrets = self.secrets.lock().map_err(|_| anyhow::anyhow!("MQTT store unavailable"))?;
                                let before = secrets.components().context(Failure::new(
                                    "discovery_manifest", "MQTT discovery manifest could not be read or validated"
                                ))?;
                                let after: BTreeSet<_> = discovery["components"].as_object().unwrap().keys().cloned().collect();
                                // Entities of a section that could not be enumerated now are kept, not removed.
                                let kept: BTreeSet<_> = before.iter().filter(|key| retained.iter().any(|kind| key.starts_with(&format!("{kind}_")))).cloned().collect();
                                let mut removal = discovery.clone();
                                let mut removed = false;
                                for key in before.difference(&after).filter(|key| !kept.contains(*key)) {
                                    removal["components"][key] = json!({"platform":"sensor"});
                                    removed = true;
                                }
                                let removal_payload = serde_json::to_vec(&removal)?;
                                if removal_payload.len() > 1 << 20 {
                                    self.state(true, "error", Some("MQTT discovery removal payload limit exceeded"));
                                    queue.push_back((format!("{base}/availability"), b"offline".to_vec(), true));
                                    continue;
                                }
                                secrets.save_components(&before.union(&after).cloned().collect()).context(Failure::new(
                                    "discovery_manifest", "MQTT discovery manifest could not be saved"
                                ))?;
                                if removed {
                                    queue.push_back((discovery_topic.clone(), removal_payload, true));
                                }
                                queue.push_back((discovery_topic.clone(), serde_json::to_vec(&discovery)?, true));
                                manifest = Some(after.union(&kept).cloned().collect());
                                previous_discovery = Some(discovery);
                                force_discovery = false;
                            }
                            queue.push_back((format!("{base}/availability"), b"online".to_vec(), true));
                            queue.push_back((format!("{base}/state"), serde_json::to_vec(&state)?, false));
                            batch_has_state = true;
                        }
                        Err(error) => {
                            let message = error.to_string();
                            let message = if message.starts_with("MQTT ") { &message } else { "MQTT statistics collection unavailable" };
                            self.state(true, "error", Some(message));
                            queue.push_back((format!("{base}/availability"), b"offline".to_vec(), true));
                        }
                    }
                }
                event = event_receiver.recv() => match event.context(Failure::new("worker", "MQTT event worker stopped"))?? {
                    Event::Incoming(Packet::ConnAck(_)) => {
                        connected = true;
                        self.connected();
                        client.try_subscribe("homeassistant/status", QoS::AtLeastOnce)?;
                    }
                    Event::Incoming(Packet::Publish(publication)) if publication.topic == "homeassistant/status" && publication.payload == "online" => {
                        force_discovery = true;
                        next_sample = next_sample.min(Instant::now() + Duration::from_secs(5));
                    }
                    Event::Incoming(Packet::PubAck(_)) => {
                        pending = pending.saturating_sub(1);
                        acknowledgement_deadline = (pending > 0).then(|| Instant::now() + Duration::from_secs(30));
                        if pending == 0 && queue.is_empty() && batch_has_state {
                            if let Some(keys) = manifest.take() {
                                self.secrets.lock().map_err(|_| anyhow::anyhow!("MQTT store unavailable"))?.save_components(&keys).context(Failure::new(
                                    "discovery_manifest", "MQTT discovery manifest could not be saved"
                                ))?;
                            }
                            self.state(true, "running", None);
                            let published = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                            self.update_status(|status| status.last_published_at_unix = Some(published));
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

pub(crate) fn metric_key(kind: &str, name: &str, field: &str) -> String {
    format!(
        "{kind}_{}_{field}",
        hex::encode(Sha256::digest(name.as_bytes()))
    )
}

fn valid_component(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_telemetry(discovery: &Value, state: &Value) -> Result<()> {
    let components = discovery["components"]
        .as_object()
        .context("MQTT components missing")?;
    ensure!(components.len() <= 4096, "MQTT entity limit exceeded");
    ensure!(
        components.keys().all(|key| valid_component(key)),
        "invalid MQTT discovery component ID"
    );
    ensure!(
        serde_json::to_vec(discovery)?.len() <= 1 << 20
            && serde_json::to_vec(state)?.len() <= 1 << 20,
        "MQTT payload limit exceeded"
    );
    Ok(())
}

fn telemetry(
    device_id: &str,
    config: &MQTTConfig,
    revision: netcontrol_core::Version,
    uptime: u64,
    statistics: &Value,
    host: &crate::mqtt_host::HostSensors,
) -> Result<(Value, Value)> {
    let base = format!("netcontrol/{device_id}");
    let mut metrics = Map::new();
    let mut components = Map::new();
    let mut add = |key: String,
                   name: String,
                   value: Value,
                   unit: Option<&str>,
                   class: Option<&str>| {
        let mut component = json!({"platform":"sensor","name":name,"unique_id":format!("netcontrol_{device_id}_{key}"),
            "value_template":format!("{{{{ value_json.metrics.get('{key}') if value_json.metrics.get('{key}') is not none else 'unknown' }}}}"),
            "expire_after":config.interval_seconds * 3});
        if let Some(unit) = unit {
            component["unit_of_measurement"] = json!(unit);
            if unit == "°C" {
                component["device_class"] = json!("temperature");
            }
        }
        if let Some(class) = class {
            component["state_class"] = json!(class);
        }
        metrics.insert(key.clone(), value);
        components.insert(key, component);
    };
    add(
        "revision".into(),
        "Configuration revision".into(),
        json!(revision),
        None,
        None,
    );
    add(
        "uptime".into(),
        "Daemon uptime".into(),
        json!(uptime),
        Some("s"),
        Some("measurement"),
    );
    add(
        "version".into(),
        "Firewall version".into(),
        json!(netcontrol_core::RELEASE_VERSION),
        None,
        None,
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
            None,
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
            "multicast",
            "collisions",
            "rx_length_errors",
            "rx_over_errors",
            "rx_crc_errors",
            "rx_frame_errors",
            "rx_fifo_errors",
            "rx_missed_errors",
            "tx_aborted_errors",
            "tx_carrier_errors",
            "tx_fifo_errors",
            "tx_heartbeat_errors",
            "tx_window_errors",
            "rx_compressed",
            "tx_compressed",
            "rx_nohandler",
            "rx_otherhost_dropped",
        ] {
            add(
                metric_key("interface", name, field),
                format!("{name} {field}"),
                if available {
                    interface["counters"][field].clone()
                } else {
                    Value::Null
                },
                if field.ends_with("bytes") {
                    Some("B")
                } else if field == "collisions" {
                    None
                } else {
                    Some("packets")
                },
                Some("total_increasing"),
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
                "variation_pairs",
                "restart_count",
                "retrying",
                "last_success_at",
                "health_changed_at",
                "collected_at",
                "started_at",
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
                let value = if available
                    || matches!(
                        field,
                        "sample_status"
                            | "process_state"
                            | "retrying"
                            | "restart_count"
                            | "last_success_at"
                            | "health_changed_at"
                            | "collected_at"
                            | "started_at"
                    ) {
                    gateway[field].clone()
                } else {
                    Value::Null
                };
                add(
                    metric_key("gateway", name, field),
                    format!("{name} {field}"),
                    value,
                    unit,
                    if field == "restart_count" {
                        Some("total_increasing")
                    } else {
                        unit.map(|_| "measurement")
                    },
                );
            }
        }
    }
    for sensor in &host.sensors {
        add(
            sensor.key.clone(),
            sensor.name.clone(),
            sensor.value.clone(),
            sensor.unit,
            sensor.class,
        );
    }
    let diagnostics = &statistics["link_diagnostics"];
    let available = diagnostics["status"] == "available";
    for (field, unit) in [
        ("observed_retransmissions", None),
        ("observed_cwnd_reductions", None),
        ("retransmissions_per_second", Some("segments/s")),
        ("retransmissions_per_thousand_segments", None),
        ("cwnd_reductions", None),
        ("cwnd_min_segments", None),
        ("cwnd_max_segments", None),
        ("send_queue_max_bytes", Some("B")),
        ("peer_window_min_bytes", Some("B")),
        ("rtt_p50_ms", Some("ms")),
        ("rtt_p95_ms", Some("ms")),
        ("rtt_variation_max_ms", Some("ms")),
        ("rto_max_ms", Some("ms")),
        ("peer_zero_window_sockets", None),
    ] {
        add(
            metric_key("link", "local_tcp", field),
            format!("Local TCP {field}"),
            if available {
                diagnostics["local_tcp"][field].clone()
            } else {
                Value::Null
            },
            unit,
            Some(if field.starts_with("observed_") {
                "total_increasing"
            } else {
                "measurement"
            }),
        );
    }
    add(
        metric_key("link", "monitor", "status"),
        "Link diagnostics status".into(),
        diagnostics
            .get("status")
            .cloned()
            .unwrap_or_else(|| json!("unavailable")),
        None,
        None,
    );
    add(
        metric_key("link", "monitor", "signal_count"),
        "Link diagnostic signal count".into(),
        if available {
            json!(diagnostics["signals"].as_array().map_or(0, Vec::len))
        } else {
            Value::Null
        },
        None,
        Some("measurement"),
    );
    let discovery = json!({"device":{"identifiers":[format!("netcontrol_{device_id}")],"name":format!("Netcontrol {}", &device_id[..8]),"manufacturer":"Netcontrol","model":"Firewall"},
        "origin":{"name":"netcontrold"},"components":components,"state_topic":format!("{base}/state"),
        "availability_topic":format!("{base}/availability"),"qos":1});
    let state = json!({"collected_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),"metrics":metrics,
        "bgp":statistics.get("bgp").cloned().unwrap_or_else(||json!({"state":"unavailable","error":"BGP statistics unavailable","neighbors":[]})),
        "link_diagnostics":statistics.get("link_diagnostics").cloned().unwrap_or_else(|| json!({"status":"unavailable","error":"network statistics unavailable","signals":[]}))});
    validate_telemetry(&discovery, &state)?;
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
    async fn mqtt_collects_extended_statistics_and_preserves_partial_sources() {
        use netcontrol_core::{Backend, Config, Simulator};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Fixture {
            simulator: Simulator,
            fail: Arc<AtomicBool>,
        }
        impl Backend for Fixture {
            fn scope(&self) -> Result<String> {
                self.simulator.scope()
            }
            fn observe(&mut self, config: &Config) -> Result<Config> {
                self.simulator.observe(config)
            }
            fn apply(&mut self, before: &Config, after: &Config) -> Result<()> {
                self.simulator.apply(before, after)
            }
            fn repair(&mut self, config: &Config) -> Result<Value> {
                self.simulator.repair(config)
            }
            fn runtime(&mut self, _: &Config) -> Result<Value> {
                ensure!(
                    !self.fail.load(Ordering::SeqCst),
                    "synthetic service failure"
                );
                Ok(crate::mqtt_stats::tests::runtime())
            }
            fn statistics(&mut self, config: &Config, path: &str, query: &str) -> Result<Value> {
                let protocols = json!([{"name":"snmp","status":"available","groups":{"Tcp":{"RetransSegs":"9007199254740993"}}}]);
                match path {
                    "/api/v1/statistics" => {
                        ensure!(
                            !self.fail.load(Ordering::SeqCst),
                            "synthetic network failure"
                        );
                        Ok(json!({"interfaces":[{"name":"lan0","status":"available",
                            "counters":{"rx_crc_errors":"9007199254740993"}}],"protocols":protocols,
                            "bgp":{"state":"running","neighbors":[{"name":"edge","state":"established","received_prefixes":4}]}}))
                    }
                    "/api/v1/statistics/protocols" => Ok(json!({"protocols":protocols})),
                    "/api/v1/statistics/firewall" => Ok(
                        json!({"sample":{"status":"available"},"generation":"fixture",
                        "rules":[{"id":"omit-private-rule","config_path":"/firewall/policy",
                        "packets":"9007199254740993","bytes":"18446744073709551615"}]}),
                    ),
                    _ => self.simulator.statistics(config, path, query),
                }
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(Fixture {
                    simulator: Simulator::new(),
                    fail: fail.clone(),
                }),
            )
            .unwrap(),
        ));
        let manager = Manager::open(
            &directory.path().join("mqtt"),
            engine.clone(),
            Mode::Simulated,
        )
        .unwrap();
        let permissions: Vec<String> = netcontrol_core::PERMISSIONS
            .iter()
            .map(|permission| (*permission).into())
            .collect();
        let stage_drop_policy = || {
            let mut engine = engine.lock().unwrap();
            let mut candidate = engine.saved_configuration().clone();
            candidate.firewall.policy = "drop".into();
            let base = engine.committed_revision();
            engine.request(
                "POST",
                "/api/v1/transactions",
                "",
                "fixture",
                &permissions,
                &serde_json::to_vec(
                    &json!({"base_revision":base,"confirm_timeout_seconds":30,"config":candidate}),
                )
                .unwrap(),
            )
        };
        let pending = stage_drop_policy();
        assert_eq!(pending.status, 202);
        assert!(manager.collect(&MQTTConfig::default()).is_err());
        let rolled_back = engine.lock().unwrap().request(
            "POST",
            &format!(
                "/api/v1/transactions/{}/rollback",
                pending.body["id"].as_str().unwrap()
            ),
            "",
            "fixture",
            &permissions,
            &[],
        );
        assert_eq!(rolled_back.status, 200);
        let (_, rolled_back, _) = manager.collect(&MQTTConfig::default()).unwrap();
        assert_eq!(
            rolled_back["metrics"][metric_key("firewall", "accounting", "dropped_packets")],
            "0"
        );
        let pending = stage_drop_policy();
        assert_eq!(pending.status, 202);
        let confirmed = engine.lock().unwrap().request(
            "POST",
            &format!(
                "/api/v1/transactions/{}/confirm",
                pending.body["id"].as_str().unwrap()
            ),
            "",
            "fixture",
            &permissions,
            &[],
        );
        assert_eq!(confirmed.status, 200);
        let (discovery, state, _) = manager.collect(&MQTTConfig::default()).unwrap();
        assert_eq!(
            state["metrics"][metric_key("firewall", "accounting", "dropped_packets")],
            "9007199254740993"
        );
        assert_eq!(
            state["metrics"]
                .as_object()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with("firewall_"))
                .count(),
            7
        );
        for (kind, name, field, value) in [
            (
                "interface",
                "lan0",
                "rx_crc_errors",
                json!("9007199254740993"),
            ),
            (
                "protocol",
                "snmp/Tcp",
                "RetransSegs",
                json!("9007199254740993"),
            ),
            ("service", "ntp", "offset_ms", json!(-2.5)),
            (
                "service",
                "syslog",
                "captured_records",
                json!("18446744073709551615"),
            ),
            (
                "service",
                "udp-broadcast-relay:7",
                "received_bytes",
                json!("9007199254740993"),
            ),
            ("traffic", "lan0", "month_tx_packets", json!("6")),
            ("bgppeer", "edge", "received_prefixes", json!(4)),
            (
                "firewall",
                "accounting",
                "rule_match_packets",
                json!("9007199254740993"),
            ),
            ("software", "release", "check_state", json!("disabled")),
            (
                "wgpeer",
                "wg0/omit-private-key",
                "rx_bytes",
                json!("18446744073709551615"),
            ),
        ] {
            let key = metric_key(kind, name, field);
            assert_eq!(state["metrics"][&key], value, "{kind}/{name}/{field}");
            assert_eq!(discovery["components"][&key]["platform"], "sensor");
        }
        let payload = serde_json::to_string(&json!([discovery, state])).unwrap();
        assert!(!payload.contains("omit-private"));
        assert!(!payload.contains("private_key") && !payload.contains("config_path"));
        fail.store(true, Ordering::SeqCst);
        let (_, partial, retained) = manager.collect(&MQTTConfig::default()).unwrap();
        assert_eq!(partial["telemetry_sources"]["network"], false);
        assert_eq!(partial["telemetry_sources"]["services"], false);
        assert_eq!(partial["telemetry_sources"]["protocols"], true);
        assert_eq!(
            partial["metrics"][metric_key("protocol", "snmp/Tcp", "RetransSegs")],
            "9007199254740993"
        );
        for kind in [
            "interface",
            "gateway",
            "service",
            "flow",
            "traffic",
            "dhcprelay",
            "dhcpclient",
            "wgpeer",
        ] {
            assert!(retained.contains(&kind), "{kind}");
        }
        assert!(partial.get("process_health").is_some());
        assert!(
            partial["metrics"]
                .get(metric_key("service", "ntp", "offset_ms"))
                .is_none()
        );
    }

    #[tokio::test]
    async fn mqtt_sando_summary_is_attached_in_either_application_order() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        for first in [true, false] {
            let manager = Manager::open(
                &directory.path().join(format!("mqtt-{first}")),
                engine.clone(),
                Mode::Simulated,
            )
            .unwrap();
            let sando = crate::sando::Manager::open(
                &directory.path().join(format!("sando-{first}")),
                engine.clone(),
            )
            .unwrap();
            let mut app = App::new(engine.clone(), Authentication::Scoped(vec![]), false);
            if first {
                App::attach_sando(&mut app, sando.clone()).unwrap();
                App::attach_mqtt(&mut app, manager.clone()).unwrap();
            } else {
                App::attach_mqtt(&mut app, manager.clone()).unwrap();
                App::attach_sando(&mut app, sando.clone()).unwrap();
            }
            assert!(Arc::ptr_eq(
                manager.sando.lock().unwrap().as_ref().unwrap(),
                &sando
            ));
            let (_, state, _) = manager.collect(&MQTTConfig::default()).unwrap();
            assert_eq!(
                state["metrics"][metric_key("sando", "sync", "state")],
                "disabled"
            );
            assert_eq!(
                state["metrics"][metric_key("sando", "sync", "host_count")],
                0
            );
            assert_eq!(state["telemetry_sources"]["sando"], true);
        }
    }

    #[test]
    fn mqtt_final_payload_limits_include_merged_entities_and_exact_size_boundaries() {
        let mut discovery = json!({"components":{}});
        for index in 0..4096 {
            discovery["components"][format!("metric{index}")] = json!({});
        }
        assert!(validate_telemetry(&discovery, &json!({})).is_ok());
        discovery["components"]["retained_previous_entity"] = json!({});
        assert!(validate_telemetry(&discovery, &json!({})).is_err());
        let overhead = serde_json::to_vec(&json!({"data":""})).unwrap().len();
        let state = json!({"data":"a".repeat((1 << 20) - overhead)});
        assert_eq!(serde_json::to_vec(&state).unwrap().len(), 1 << 20);
        assert!(validate_telemetry(&json!({"components":{}}), &state).is_ok());
        let too_large = json!({"data":"a".repeat((1 << 20) - overhead + 1)});
        assert!(validate_telemetry(&json!({"components":{}}), &too_large).is_err());
        assert!(
            validate_telemetry(
                &json!({"components":{},"data":"a".repeat(1 << 20)}),
                &json!({})
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn mqtt_still_publishes_health_when_network_statistics_fail() {
        use netcontrol_core::{Backend, Config, Simulator};
        struct MissingStatistics(Simulator);
        impl Backend for MissingStatistics {
            fn scope(&self) -> Result<String> {
                self.0.scope()
            }
            fn observe(&mut self, config: &Config) -> Result<Config> {
                self.0.observe(config)
            }
            fn apply(&mut self, before: &Config, after: &Config) -> Result<()> {
                self.0.apply(before, after)
            }
            fn runtime(&mut self, config: &Config) -> Result<Value> {
                self.0.runtime(config)
            }
            fn statistics(&mut self, _: &Config, _: &str, _: &str) -> Result<Value> {
                anyhow::bail!("synthetic statistics failure")
            }
            fn repair(&mut self, config: &Config) -> Result<Value> {
                self.0.repair(config)
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(MissingStatistics(Simulator::new())),
            )
            .unwrap(),
        ));
        let manager =
            Manager::open(&directory.path().join("mqtt"), engine, Mode::Simulated).unwrap();
        manager.health.observe(None, &[], false);
        let (_, state, retained) = manager.collect(&MQTTConfig::default()).unwrap();
        assert_eq!(state["statistics_available"], false);
        assert_eq!(state["process_health"]["status"], "unknown");
        assert_eq!(state["active_alerts"][0]["code"], "runtime_unavailable");
        assert!(retained.contains(&"interface") && retained.contains(&"gateway"));
    }

    #[tokio::test]
    async fn mqtt_health_payload_matches_shared_snapshot_and_discovery() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager =
            Manager::open(&directory.path().join("mqtt"), engine, Mode::Simulated).unwrap();
        manager.health.observe(
            Some(&json!({"appliance_services":[{"name":"ntp","state":"error","retrying":true}]})),
            &[],
            false,
        );
        let (discovery, state, _) = manager.collect(&MQTTConfig::default()).unwrap();
        assert_eq!(
            state["process_health"],
            manager.health.snapshot()["process_health"]
        );
        assert_eq!(
            state["active_alerts"],
            manager.health.snapshot()["active_alerts"]
        );
        assert_eq!(state["metrics"]["process_health"], "unhealthy");
        assert_eq!(state["metrics"]["active_alert_count"], 1);
        assert_eq!(
            discovery["components"]["process_health"]["platform"],
            "sensor"
        );
        assert_eq!(
            discovery["components"]["active_alert_count"]["platform"],
            "sensor"
        );
    }

    #[tokio::test]
    async fn mqtt_status_api_exposes_only_safe_failure_history() {
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
            Authentication::Scoped(vec![Credential {
                name: "reader".into(),
                token_sha256: crate::identity::digest("synthetic-reader-token"),
                permissions: vec!["state.read".into()],
            }]),
            false,
        );
        App::attach_mqtt(&mut app, manager.clone()).unwrap();
        manager.attempting();
        manager.failed(&anyhow::Error::new(rumqttc::ConnectionError::Io(
            std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "sensitive-private-data",
            ),
        )));
        let (code, response) = api(
            app,
            "GET",
            "/api/v1/services/mqtt/status",
            Value::Null,
            "synthetic-reader-token",
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(response["state"], "reconnecting");
        assert_eq!(response["connection_attempts"], 1);
        assert_eq!(response["reconnect_count"], 1);
        assert_eq!(response["last_failure"]["category"], "connection_reset");
        assert_eq!(response["error"], response["last_failure"]["message"]);
        assert!(response["last_failure"]["at_unix"].is_i64());
        assert!(response["last_connected_at_unix"].is_null());
        assert!(!response.to_string().contains("sensitive"));
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
            json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,"config":config}),
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
                json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":disabled}),
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
                json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":disabled}),
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
            json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":disabled}),
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

    #[test]
    fn mqtt_failures_are_classified_without_formatting_sensitive_errors() {
        use rumqttc::{ConnectReturnCode, ConnectionError, StateError};
        let cases = [
            (
                ConnectionError::ConnectionRefused(ConnectReturnCode::BadUserNamePassword),
                "authentication",
            ),
            (
                ConnectionError::ConnectionRefused(ConnectReturnCode::NotAuthorized),
                "authorization",
            ),
            (
                ConnectionError::ConnectionRefused(ConnectReturnCode::BadClientId),
                "client_id",
            ),
            (
                ConnectionError::ConnectionRefused(ConnectReturnCode::ServiceUnavailable),
                "broker_unavailable",
            ),
            (
                ConnectionError::ConnectionRefused(ConnectReturnCode::RefusedProtocolVersion),
                "protocol",
            ),
            (ConnectionError::NetworkTimeout, "connection_timeout"),
            (ConnectionError::FlushTimeout, "write_timeout"),
            (
                ConnectionError::MqttState(StateError::AwaitPingResp),
                "keepalive_timeout",
            ),
            (
                ConnectionError::MqttState(StateError::ConnectionAborted),
                "connection_closed",
            ),
            (
                ConnectionError::MqttState(StateError::Deserialization(
                    rumqttc::mqttbytes::Error::PayloadSizeLimitExceeded(1 << 20),
                )),
                "packet_size",
            ),
            (
                ConnectionError::MqttState(StateError::Deserialization(
                    rumqttc::mqttbytes::Error::OutgoingPacketTooLarge {
                        pkt_size: 1 << 21,
                        max: 1 << 20,
                    },
                )),
                "packet_size",
            ),
            (
                ConnectionError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "sensitive-endpoint-and-password",
                )),
                "connection_reset",
            ),
            (
                ConnectionError::Tls(rumqttc::TlsError::Io(std::io::Error::other(
                    "sensitive-TLS-peer-data",
                ))),
                "tls",
            ),
            (
                ConnectionError::Tls(rumqttc::TlsError::TLS(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))),
                "tls_certificate",
            ),
            (
                ConnectionError::NotConnAck(Packet::Publish(rumqttc::Publish::new(
                    "sensitive-topic",
                    QoS::AtLeastOnce,
                    "sensitive-payload",
                ))),
                "protocol",
            ),
            (ConnectionError::RequestsDone, "client_channel"),
        ];
        for (error, category) in cases {
            let failure =
                Failure::classify(&anyhow::Error::new(error).context("sensitive-wrapper"));
            assert_eq!(failure.category, category);
            assert!(
                !serde_json::to_string(&failure)
                    .unwrap()
                    .contains("sensitive")
            );
            assert!(!format!("{failure:?} {failure}").contains("sensitive"));
        }
        let unknown = anyhow::anyhow!("sensitive-unknown-error");
        assert_eq!(Failure::classify(&unknown).category, "internal");
        let setup = unknown.context(Failure::new(
            "credentials",
            "MQTT stored password could not be read",
        ));
        assert_eq!(Failure::classify(&setup).category, "credentials");
        assert!(!Failure::classify(&setup).message.contains("sensitive"));
        let io = Failure::io(&std::io::Error::from_raw_os_error(1));
        assert_eq!(io.os_error_code, Some(1));
    }

    #[test]
    fn mqtt_failure_history_survives_retry_recovery_disable_and_stop() {
        #[derive(Clone)]
        struct Log(Arc<Mutex<Vec<u8>>>);
        impl Write for Log {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager =
            Manager::open(&directory.path().join("mqtt"), engine, Mode::Simulated).unwrap();
        let initial = manager.status().unwrap();
        assert_eq!(initial["connection_attempts"], 0);
        assert_eq!(initial["reconnect_count"], 0);
        assert!(initial["last_connected_at_unix"].is_null());
        assert!(initial["last_failure"].is_null());
        manager.attempting();
        let output = Arc::new(Mutex::new(Vec::new()));
        let log = Log(output.clone());
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(move || log.clone())
            .finish();
        let before = time::OffsetDateTime::now_utc().unix_timestamp();
        let error = anyhow::Error::new(rumqttc::ConnectionError::ConnectionRefused(
            rumqttc::ConnectReturnCode::BadUserNamePassword,
        ))
        .context("sensitive-password-endpoint-reference");
        tracing::subscriber::with_default(subscriber, || manager.failed(&error));
        let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("\"category\":\"authentication\""));
        assert!(logged.contains("MQTT broker rejected the username or password"));
        assert!(!logged.contains("sensitive"));
        let failed = manager.status().unwrap();
        assert_eq!(failed["state"], "reconnecting");
        assert_eq!(failed["connection_attempts"], 1);
        assert_eq!(failed["reconnect_count"], 1);
        assert_eq!(failed["last_failure"]["category"], "authentication");
        assert!(failed["last_failure"]["at_unix"].is_i64());
        assert!(
            (before..=time::OffsetDateTime::now_utc().unix_timestamp())
                .contains(&failed["last_failure"]["at_unix"].as_i64().unwrap())
        );
        assert!(failed["last_failure"]["os_error_code"].is_null());
        assert_eq!(failed["error"], failed["last_failure"]["message"]);
        manager.attempting();
        assert_eq!(manager.status().unwrap()["error"], failed["error"]);
        manager.connected();
        let recovered = manager.status().unwrap();
        assert_eq!(recovered["connection_attempts"], 2);
        assert_eq!(recovered["reconnect_count"], 1);
        assert!(recovered["last_connected_at_unix"].is_i64());
        assert!(recovered["error"].is_null());
        assert_eq!(recovered["last_failure"], failed["last_failure"]);
        manager.failed(&anyhow::Error::new(Failure::new(
            "publication_ack_timeout",
            "MQTT publication acknowledgment timed out",
        )));
        let latest = manager.status().unwrap();
        assert_eq!(latest["reconnect_count"], 2);
        assert_eq!(
            latest["last_failure"]["category"],
            "publication_ack_timeout"
        );
        for state in ["disabled", "stopped"] {
            manager.state(false, state, None);
            let status = manager.status().unwrap();
            assert!(status["error"].is_null());
            assert_eq!(status["last_failure"], latest["last_failure"]);
            assert_eq!(status["reconnect_count"], 2);
        }
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
        let error = tokio::time::timeout(Duration::from_secs(2), events.poll())
            .await
            .unwrap()
            .unwrap_err();
        let failure = Failure::classify(&error.into());
        assert_eq!(failure.category, "source_interface");
        assert_eq!(failure.os_error_code, Some(libc::ENODEV));
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
        for connection in 1..=3 {
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
                            if publication.qos == QoS::AtLeastOnce && connection != 2 {
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
                manager.secrets.lock().unwrap().save_components(&BTreeSet::from([
                    metric_key("protocol", "snmp/Tcp", "RetransSegs"),
                ]))?;
                manager.health.observe(Some(&json!({"appliance_services":[{"name":"ntp","state":"error","retrying":true}]})), &[], false);
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
                let transaction = submit(&config, test_revision(0));
                ensure!(transaction.status == 202, "MQTT fixture transaction rejected");
                ensure!(tokio::time::timeout(Duration::from_millis(1200), listener.accept()).await.is_err(), "MQTT connected before confirmation");
                ensure!(confirm(transaction.body["id"].as_str().unwrap()).status == 200, "MQTT confirmation failed");
                let (messages, mut receive) = tokio::sync::mpsc::channel(64);
                let broker = tokio::spawn(broker_fixture(listener, messages));
                let mut connections = Vec::new();
                let mut host_discovered = false;
                let mut health_interval = tokio::time::interval(Duration::from_secs(5));
                tokio::time::timeout(Duration::from_secs(65), async {
                    while connections.len() < 4 {
                        let (connection, topic, payload) = tokio::select! {
                            message = receive.recv() => message.context("MQTT broker fixture stopped")?,
                            _ = health_interval.tick() => {
                                manager.health.observe(Some(&json!({"appliance_services":[{"name":"ntp","state":"error","retrying":true}]})), &[], false);
                                continue;
                            }
                        };
                        if topic.ends_with("/config") {
                            let value: Value = serde_json::from_slice(&payload)?;
                            let components = &value["components"];
                            host_discovered |= components.get("memory_used_bytes").is_some() && components.get("load_1m").is_some();
                        }
                        if topic.ends_with("/state") {
                            let value: Value = serde_json::from_slice(&payload)?;
                            ensure!(value["metrics"]["revision"] == serde_json::json!(test_revision(1)), "unconfirmed or wrong revision published");
                            ensure!(value["process_health"]["status"] == "unhealthy" && value["active_alerts"][0]["retrying"] == true, "health/alerts were not published");
                            ensure!(value["metrics"].get("memory_used_bytes").is_some_and(Value::is_null), "host sensor missing or fabricated by the simulator");
                            ensure!(value["metrics"][metric_key("software", "release", "check_state")] == "disabled", "release summary missing from broker payload");
                            ensure!(value["metrics"].get(metric_key("firewall", "accounting", "dropped_packets")).is_some_and(Value::is_null), "unmeasured firewall drops missing or fabricated");
                            connections.push(connection);
                            manager.health.observe(Some(&json!({"appliance_services":[{"name":"ntp","state":"error","retrying":true}]})), &[], false);
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }).await.with_context(|| format!("MQTT sample sequence incomplete: status={}, connections={connections:?}, broker_finished={}", manager.status().unwrap(), broker.is_finished()))??;
                ensure!(host_discovered, "host sensors missing from discovery");
                ensure!(connections == [1, 1, 2, 3], "MQTT connection was not persistent or failed to reconnect after disconnect/acknowledgement timeout");
                let diagnostics = manager.status()?;
                ensure!(diagnostics["connection_attempts"] == 3 && diagnostics["reconnect_count"] == 2, "MQTT reconnect diagnostics did not track actual sessions: {diagnostics}");
                ensure!(diagnostics["last_failure"]["category"] == "publication_ack_timeout", "MQTT acknowledgment timeout reason was lost after reconnect: {diagnostics}");
                ensure!(diagnostics["last_connected_at_unix"].is_i64() && diagnostics["last_failure"]["at_unix"].is_i64(), "MQTT diagnostic timestamps missing");
                ensure!(diagnostics["error"].is_null(), "MQTT current error was not cleared after reconnect");
                config.mqtt.enabled = false;
                let transaction = submit(&config, test_revision(1));
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
    fn mqtt_protocol_discovery_manifest_survives_manager_restart() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("mqtt");
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager = Manager::open(&root, engine.clone(), Mode::Simulated).unwrap();
        let identity = manager.device_id.clone();
        let reference = manager
            .secrets
            .lock()
            .unwrap()
            .create_password("synthetic-manifest-fixture")
            .unwrap();
        let statistics = json!({"interfaces":[],"protocols":[
            {"name":"snmp","status":"available","groups":{"Tcp":{"RetransSegs":"42","CurrEstab":"5"}}},
            {"name":"snmp6","status":"available","groups":{"IPv6":{"Ip6InOctets":"9007199254740993"}}}
        ]});
        let host = crate::mqtt_stats::protocols(&statistics).unwrap();
        let (discovery, _) = telemetry(
            &identity,
            &MQTTConfig::default(),
            test_revision(0),
            1,
            &statistics,
            &host,
        )
        .unwrap();
        let components: BTreeSet<_> = discovery["components"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert!(components.contains(&metric_key("protocol", "snmp/Tcp", "RetransSegs")));
        assert!(components.contains(&metric_key("protocol", "snmp6/IPv6", "Ip6InOctets")));
        manager
            .secrets
            .lock()
            .unwrap()
            .save_components(&components)
            .unwrap();
        drop(manager);

        let manager = Manager::open(&root, engine, Mode::Simulated).unwrap();
        assert_eq!(manager.device_id, identity);
        let secrets = manager.secrets.lock().unwrap();
        assert_eq!(secrets.components().unwrap(), components);
        assert_eq!(
            &**secrets.password(&reference).unwrap(),
            "synthetic-manifest-fixture"
        );
    }

    #[test]
    fn mqtt_discovery_manifest_validation_is_symmetric() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = Secrets::open(&directory.path().join("mqtt")).unwrap();
        let valid = BTreeSet::from(["A".repeat(128), "metric_09_MixedCase".into()]);
        secrets.save_components(&valid).unwrap();
        assert_eq!(secrets.components().unwrap(), valid);
        let path = secrets.root.join("components.json");
        for key in [
            "",
            "bad-key",
            "bad/key",
            "bad.key",
            "bad key",
            "non_ascii_\u{e9}",
        ] {
            let invalid = BTreeSet::from([key.to_owned()]);
            assert!(secrets.save_components(&invalid).is_err(), "{key:?}");
            assert_eq!(secrets.components().unwrap(), valid);
            crate::private_store::write_private(&path, &serde_json::to_vec(&invalid).unwrap())
                .unwrap();
            assert!(secrets.components().is_err(), "{key:?}");
            secrets.save_components(&valid).unwrap();
            assert!(validate_telemetry(&json!({"components":{key:{}}}), &json!({})).is_err());
        }
        for invalid in [
            BTreeSet::from(["a".repeat(129)]),
            (0..8193).map(|index| format!("metric_{index}")).collect(),
            (0..8192).map(|index| format!("{index:0128}")).collect(),
        ] {
            assert!(secrets.save_components(&invalid).is_err());
            assert_eq!(secrets.components().unwrap(), valid);
        }
        let maximum = (0..8192).map(|index| format!("metric_{index}")).collect();
        secrets.save_components(&maximum).unwrap();
        assert_eq!(secrets.components().unwrap(), maximum);
        secrets.save_components(&BTreeSet::new()).unwrap();
        assert!(secrets.components().unwrap().is_empty());
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
    fn mqtt_bgp_preserves_neighbor_status_without_exporting_route_table() {
        let status = json!({"name":"bgp","state":"running","health":"degraded","installed_prefixes":3,
            "neighbors":[{"name":"edge","state":"active","received_prefixes":0,"error":"connection refused"}]});
        let (_, state) = telemetry(
            "0123456789abcdef0123456789abcdef",
            &MQTTConfig::default(),
            test_revision(0),
            1,
            &json!({"interfaces":[],"bgp":status}),
            &crate::mqtt_host::HostSensors::default(),
        )
        .unwrap();
        assert_eq!(state["bgp"], status);
        assert!(state["bgp"].get("routes").is_none());
    }

    #[test]
    fn mqtt_link_diagnostics_preserve_signals_precision_and_staleness() {
        let mut stats = json!({"interfaces":[],"link_diagnostics":{
            "status":"available","local_tcp":{"rtt_p95_ms":25.5,"retransmissions_per_second":2.0,"observed_retransmissions":"9007199254740993"},
            "signals":["local_egress_drops"],"packet_headers":{"kernel_drops":"9007199254740993"}}});
        let id = "0123456789abcdef0123456789abcdef";
        let (_, state) = telemetry(
            id,
            &MQTTConfig::default(),
            test_revision(0),
            1,
            &stats,
            &crate::mqtt_host::HostSensors::default(),
        )
        .unwrap();
        assert_eq!(state["link_diagnostics"], stats["link_diagnostics"]);
        assert_eq!(
            state["metrics"][metric_key("link", "local_tcp", "observed_retransmissions")],
            "9007199254740993"
        );
        assert_eq!(
            state["metrics"][metric_key("link", "local_tcp", "rtt_p95_ms")],
            25.5
        );
        assert_eq!(
            state["metrics"][metric_key("link", "monitor", "signal_count")],
            1
        );
        stats["link_diagnostics"]["status"] = json!("stale");
        let (_, state) = telemetry(
            id,
            &MQTTConfig::default(),
            test_revision(0),
            1,
            &stats,
            &crate::mqtt_host::HostSensors::default(),
        )
        .unwrap();
        assert!(state["metrics"][metric_key("link", "local_tcp", "rtt_p95_ms")].is_null());
        assert!(state["metrics"][metric_key("link", "monitor", "signal_count")].is_null());
    }

    #[test]
    fn mqtt_discovery_preserves_precision_and_unknown_measurements() {
        let config = MQTTConfig::default();
        let stats = json!({"interfaces":[{"name":"wan.1","status":"available","oper_state":"up","counters":{"rx_bytes":"18446744073709551615"}}],
            "gateways":[{"name":"wan","sample_status":"stale","health":"up","sent":30,"rtt_avg_ms":5.0}]});
        let id = "0123456789abcdef0123456789abcdef";
        let (discovery, state) = telemetry(
            id,
            &config,
            test_revision(42),
            60,
            &stats,
            &crate::mqtt_host::HostSensors::default(),
        )
        .unwrap();
        assert_eq!(
            state["metrics"][metric_key("interface", "wan.1", "rx_bytes")],
            "18446744073709551615"
        );
        assert!(state["metrics"][metric_key("interface", "wan.1", "tx_bytes")].is_null());
        assert!(state["metrics"][metric_key("gateway", "wan", "rtt_avg_ms")].is_null());
        assert!(state["metrics"][metric_key("gateway", "wan", "health")].is_null());
        assert_eq!(
            state["metrics"]["revision"],
            serde_json::json!(test_revision(42))
        );
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
