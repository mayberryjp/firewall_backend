//! In-process service workers. Native operations are Linux-only; parsing and protocol tests are portable.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod config;
mod counters;
mod dhcp;
mod flow;
mod gateway;
#[cfg(all(test, target_os = "linux"))]
mod integration;
#[cfg(target_os = "linux")]
mod linux;
mod ntp;
mod resolve;
mod syslog;
mod worker;

use anyhow::{Context, Result, bail, ensure};
use config::Config;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf};
use worker::Worker;

pub struct GatewayProbe {
    worker: Worker,
}

impl GatewayProbe {
    #[cfg(target_os = "linux")]
    pub fn start(value: &Value, namespace: std::sync::Arc<std::fs::File>) -> Result<Self> {
        let mut config: config::Gateway = serde_json::from_value(value.clone())?;
        config.routing_mark = (config.mode == "dhcp").then_some(config.routing_table);
        let name = config.name.clone();
        let worker = Worker::start(
            format!("dhcp-gateway:{name}"),
            Some(namespace),
            json!({"name":name}),
            move || gateway::prepare(config),
        )?;
        Ok(Self { worker })
    }

    pub fn snapshot(&self) -> Value {
        self.worker.snapshot()
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.worker.shutdown()
    }
}

pub struct ServiceOptions {
    pub namespace: Option<PathBuf>,
    pub state_directory: PathBuf,
    pub allow_host_services: bool,
    pub allow_gateway_monitoring: bool,
}
pub struct Services {
    options: ServiceOptions,
    config: Config,
    workers: BTreeMap<String, Worker>,
    error: Option<String>,
    #[cfg(target_os = "linux")]
    _ownership: std::fs::File,
    #[cfg(target_os = "linux")]
    host_namespace: std::sync::Arc<std::fs::File>,
    #[cfg(target_os = "linux")]
    managed_namespace: std::sync::Arc<std::fs::File>,
    #[cfg(target_os = "linux")]
    syslog_socket: Option<std::sync::Arc<syslog::JournalSocket>>,
}
impl Services {
    pub fn new(options: ServiceOptions) -> Result<Self> {
        ensure!(
            options.state_directory.is_absolute(),
            "services state directory must be absolute"
        );
        std::fs::create_dir_all(&options.state_directory)?;
        ensure!(
            std::fs::symlink_metadata(&options.state_directory)?.is_dir(),
            "services state directory must be a directory, not symlink"
        );
        if let Some(path) = &options.namespace {
            ensure!(
                path.is_absolute(),
                "namespace handle must be an absolute path"
            );
            std::fs::File::open(path).context("open configured service namespace")?;
            #[cfg(not(target_os = "linux"))]
            bail!("namespace service workers require Linux");
        }
        #[cfg(target_os = "linux")]
        let ownership = {
            use std::os::{
                fd::AsRawFd,
                unix::fs::{OpenOptionsExt, PermissionsExt},
            };
            std::fs::set_permissions(
                &options.state_directory,
                std::fs::Permissions::from_mode(0o700),
            )?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(options.state_directory.join("services-v1.lock"))?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "native service state already owned: {}",
                std::io::Error::last_os_error()
            );
            file
        };
        #[cfg(target_os = "linux")]
        let host_namespace = std::sync::Arc::new(
            std::fs::File::open("/proc/thread-self/ns/net")
                .context("pin original host network namespace")?,
        );
        #[cfg(target_os = "linux")]
        let managed_namespace = if let Some(path) = &options.namespace {
            std::sync::Arc::new(std::fs::File::open(path)?)
        } else {
            host_namespace.clone()
        };
        // Reject incompatible files even when the associated service is disabled.
        for scope in ["host", "managed"] {
            counters::Database::load(
                &options
                    .state_directory
                    .join(format!("traffic-{scope}-v1.json")),
                scope,
            )?;
        }
        Ok(Self {
            options,
            config: Config::default(),
            workers: BTreeMap::new(),
            error: None,
            #[cfg(target_os = "linux")]
            _ownership: ownership,
            #[cfg(target_os = "linux")]
            host_namespace,
            #[cfg(target_os = "linux")]
            managed_namespace,
            #[cfg(target_os = "linux")]
            syslog_socket: syslog::JournalSocket::activated()
                .context("receive systemd syslog socket")?,
        })
    }
    pub fn validate(&self, value: &Value) -> Result<()> {
        self.preflight(&Config::parse(value)?)
    }
    fn preflight(&self, c: &Config) -> Result<()> {
        #[cfg(target_os = "linux")]
        let isolated_namespace = {
            use std::os::unix::fs::MetadataExt;
            let host = self.host_namespace.metadata()?;
            let managed = self.managed_namespace.metadata()?;
            (host.dev(), host.ino()) != (managed.dev(), managed.ino())
        };
        #[cfg(not(target_os = "linux"))]
        let isolated_namespace = self.options.namespace.is_some();
        ensure!(
            !(c.ntp.enabled || c.syslog.enabled || c.vnstat.enabled)
                || self.options.allow_host_services,
            "host services require explicit allow_host_services opt-in"
        );
        ensure!(
            isolated_namespace
                || self.options.allow_host_services
                || !(c.interfaces.iter().any(|i| i.dhcp_relay.enabled)
                    || c.softflowd.iter().any(|f| f.enabled)
                    || c.gateway_monitors.iter().any(|g| g.enabled)),
            "managed services without an isolated namespace require explicit allow_host_services opt-in"
        );
        ensure!(
            !c.gateway_monitors.iter().any(|m| m.enabled) || self.options.allow_gateway_monitoring,
            "gateway probes require explicit allow_gateway_monitoring opt-in"
        );
        #[cfg(target_os = "linux")]
        if c.syslog.enabled {
            self.syslog_socket
                .as_ref()
                .context("native syslog requires systemd socket activation from netcontrol-syslog.socket and journald ForwardToSyslog=yes")?
                .check_path()?;
        }
        #[cfg(not(target_os = "linux"))]
        ensure!(
            !c.ntp.enabled
                && !c.syslog.enabled
                && !c.vnstat.enabled
                && !c.interfaces.iter().any(|i| i.dhcp_relay.enabled)
                && !c.softflowd.iter().any(|f| f.enabled)
                && !c.gateway_monitors.iter().any(|g| g.enabled),
            "native services require Linux; protocol validation is portable"
        );
        Ok(())
    }
    pub fn apply(&mut self, before: &Value, after: &Value) -> Result<()> {
        let previous = Config::parse(before)?;
        let next = Config::parse(after)?;
        self.preflight(&next)?;
        if self.config == next
            && self
                .workers
                .values()
                .all(|w| w.snapshot()["state"] == "running")
        {
            return Ok(());
        }
        ensure!(
            self.workers.is_empty() || self.config == previous,
            "service apply baseline does not match owned configuration"
        );
        self.stop_all()?;
        if let Err(error) = self.start(&next) {
            let original = format!("{error:#}");
            let stopped = self.stop_all();
            let restored = if stopped.is_ok() {
                self.start(&previous)
            } else {
                Err(anyhow::anyhow!("could not stop failed apply workers"))
            };
            self.config = previous;
            self.error = Some(format!(
                "apply failed: {original}; stop: {stopped:?}; restore: {restored:?}"
            ));
            bail!("{}", self.error.as_ref().unwrap())
        }
        self.config = next;
        self.error = None;
        Ok(())
    }
    fn start(&mut self, c: &Config) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let managed = Some(self.managed_namespace.clone());
            let host = Some(self.host_namespace.clone());
            let ipv6_enabled = c.ipv6_enabled;
            if c.ntp.enabled {
                let config = c.ntp.clone();
                self.insert(
                    "ntp",
                    host.clone(),
                    json!({"name":"ntp","scope":"host","sample_status":"warming_up"}),
                    move || ntp::prepare(config, ipv6_enabled),
                )?;
            }
            if c.syslog.enabled {
                let config = c.syslog.clone();
                let dir = self.options.state_directory.clone();
                let socket = self
                    .syslog_socket
                    .clone()
                    .context("systemd syslog socket missing")?;
                self.insert("syslog",host.clone(),json!({"name":"syslog","scope":"host","source":"journald","host_source":syslog::JOURNAL_SOCKET}),move||syslog::prepare(config,dir,socket,ipv6_enabled))?;
            }
            if c.vnstat.enabled {
                for scope in ["host", "managed"] {
                    let dir = self.options.state_directory.clone();
                    let scope_owned = scope.to_owned();
                    self.insert(&format!("vnstat-{scope}"),if scope=="host"{host.clone()}else{managed.clone()},json!({"name":format!("vnstat-{scope}"),"scope":scope,"schema":"netcontrol-services/counters/v1"}),move||counters::prepare(dir,scope_owned))?;
                }
            }
            let relays: Vec<_> = c
                .interfaces
                .iter()
                .filter(|i| i.dhcp_relay.enabled)
                .cloned()
                .collect();
            if !relays.is_empty() {
                self.insert(
                    "dhcp-relay",
                    managed.clone(),
                    json!({"name":"dhcp-relay","scope":"managed"}),
                    move || dhcp::prepare(relays),
                )?;
            }
            for f in c.softflowd.iter().filter(|f| f.enabled) {
                let config = f.clone();
                self.insert(&format!("flow:{}",f.name),managed.clone(),                                json!({"name":f.name,"scope":"managed","export_version":f.export_version,"address_family":if !ipv6_enabled || [1,5].contains(&f.export_version){"ipv4"}else{"dual"},"fragments":"excluded","capture_filter":f.capture_filter,"sampling_rate":f.sampling_rate,"sampling_metadata":f.export_version!=1}),move||flow::prepare(config,ipv6_enabled))?;
            }
            for m in c
                .gateway_monitors
                .iter()
                .filter(|m| m.enabled && m.mode == "explicit")
            {
                let config = m.clone();
                self.insert(
                    &format!("gateway:{}", m.name),
                    managed.clone(),
                    json!({"name":m.name,"scope":"managed"}),
                    move || gateway::prepare(config),
                )?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = c;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn insert(
        &mut self,
        name: &str,
        namespace: Option<std::sync::Arc<std::fs::File>>,
        initial: Value,
        prepare: impl FnOnce() -> Result<Box<dyn FnOnce(worker::ContextState) -> Result<()> + Send>>
        + Send
        + 'static,
    ) -> Result<()> {
        ensure!(
            !self.workers.contains_key(name),
            "duplicate native service worker"
        );
        let worker = Worker::start(name.into(), namespace, initial, prepare)
            .with_context(|| format!("start {name}"))?;
        self.workers.insert(name.into(), worker);
        Ok(())
    }
    fn stop_all(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for worker in self.workers.values_mut() {
            if let Err(e) = worker.shutdown() {
                errors.push(format!("{e:#}"));
            }
        }
        if !errors.is_empty() {
            bail!("service shutdown incomplete: {}", errors.join("; "))
        }
        self.workers.clear();
        Ok(())
    }
    fn row(&self, key: &str, enabled: bool, base: Value) -> Value {
        if enabled {
            if let Some(w) = self.workers.get(key) {
                let mut row = w.snapshot();
                for (k, v) in base.as_object().unwrap() {
                    row[k] = v.clone();
                }
                return row;
            }
        }
        let mut row = base;
        row["state"] = json!(if enabled { "stopped" } else { "disabled" });
        row
    }
    pub fn status(&self) -> Value {
        let c = &self.config;
        let appliance = vec![
            self.row("ntp", c.ntp.enabled, json!({"name":"ntp","scope":"host"})),
            self.row(
                "syslog",
                c.syslog.enabled,
                json!({"name":"syslog","scope":"host"}),
            ),
            self.row(
                "vnstat-host",
                c.vnstat.enabled,
                json!({"name":"vnstat-host","scope":"host"}),
            ),
            self.row(
                "vnstat-managed",
                c.vnstat.enabled,
                json!({"name":"vnstat-managed","scope":"managed"}),
            ),
        ];
        let relays: Vec<_> = c
            .interfaces
            .iter()
            .map(|i| {
                self.row(
                    "dhcp-relay",
                    i.dhcp_relay.enabled,
                    json!({"interface":i.name}),
                )
            })
            .collect();
        let flows: Vec<_> = c
            .softflowd
            .iter()
            .map(|f| {
                self.row(
                    &format!("flow:{}", f.name),
                    f.enabled,
                    json!({"name":f.name}),
                )
            })
            .collect();
        let gateways:Vec<_>=c.gateway_monitors.iter().map(|m|{
            let row=self.row(&format!("gateway:{}",m.name),m.enabled,json!({"name":m.name}));
            let mut stats=row.get("statistics").cloned().unwrap_or_else(||json!({"name":m.name,"process_state":row["state"],"sample_status":if m.enabled {"warming_up"}else{"disabled"},"health":"unknown","started_at":row["started_at"],"collected_at":null,"health_changed_at":null,"last_success_at":null,"sent":0,"received":0,"lost":0,"pending":0,"variation_pairs":0,"loss_percent":null,"rtt_min_ms":null,"rtt_max_ms":null,"rtt_avg_ms":null,"rtt_stddev_ms":null,"rtt_p50_ms":null,"rtt_p95_ms":null,"rtt_variation_ms":null}));
            stats["process_state"]=row["state"].clone();
            if row["state"]=="error" {stats["sample_status"]=json!("unavailable");stats["health"]=json!("unknown");stats["error"]=row["error"].clone();}
            else if row["state"]=="stopped"||row["state"]=="disabled"{stats["sample_status"]=row["state"].clone();stats["health"]=json!("unknown");}
            stats["mode"]=json!(m.mode);
            stats["interface"]=json!(m.interface);
            stats["resolved_source_address"]=if m.enabled && m.mode=="explicit" {json!(m.source_address)} else {Value::Null};
            stats["resolved_gateway"]=if m.enabled && m.mode=="explicit" {json!(m.gateway)} else {Value::Null};
            stats["resolved_routing_table"]=if m.enabled && m.mode=="explicit" {json!(m.routing_table)} else {Value::Null};
            stats["reason"]=Value::Null;
            if m.enabled && m.mode=="dhcp" {
                stats["process_state"]=json!("waiting");
                stats["sample_status"]=json!("waiting_for_dhcp");
                stats["reason"]=json!("waiting for DHCP lease");
            }
            stats
        }).collect();
        let mut result = json!({"appliance_services":appliance,"dhcp_relay":relays,"softflowd":flows,"gateway_monitors":gateways});
        if let Some(error) = &self.error {
            result["error"] = json!(error);
        }
        stringify_counts(&mut result);
        result
    }
    pub fn statistics(&self, path: &str, query: &str) -> Result<Value> {
        ensure!(
            query.is_empty(),
            "service statistics endpoints do not accept query parameters"
        );
        let path = path.strip_prefix("/api/v1").unwrap_or(path);
        let status = self.status();
        if path == "/statistics/gateways" || path.starts_with("/statistics/gateways/") {
            let gateways = status["gateway_monitors"].as_array().unwrap();
            let mut sample = json!({"scope":"managed","started_at":null,"collected_at":worker::now(),"status":if gateways.iter().all(|g|g["sample_status"]=="available"||g["sample_status"]=="disabled"){"available"}else{"partial"}});
            if let Some(name) = path.strip_prefix("/statistics/gateways/") {
                ensure!(config::name(name, 32), "invalid gateway monitor name");
                let monitor = gateways
                    .iter()
                    .find(|g| g["name"] == name)
                    .context("gateway monitor not found")?;
                sample["status"] = json!(if monitor["sample_status"] == "available"
                    || monitor["sample_status"] == "disabled"
                {
                    "available"
                } else {
                    "partial"
                });
                return Ok(json!({"sample":sample,"monitor":monitor}));
            }
            return Ok(json!({"sample":sample,"gateways":gateways}));
        }
        if path == "/statistics/vnstat" || path.starts_with("/statistics/vnstat/") {
            ensure!(self.config.vnstat.enabled, "vnstat is disabled");
            let scopes: Vec<_> = if let Some(scope) = path.strip_prefix("/statistics/vnstat/") {
                ensure!(
                    ["host", "managed"].contains(&scope),
                    "invalid traffic scope"
                );
                vec![scope]
            } else {
                vec!["host", "managed"]
            };
            let mut databases = serde_json::Map::new();
            for scope in scopes {
                let state = self
                    .workers
                    .get(&format!("vnstat-{scope}"))
                    .context("traffic worker unavailable")?
                    .snapshot();
                ensure!(
                    state["state"] == "running" && state.get("collected_at").is_some(),
                    "traffic history unavailable: {state}"
                );
                let db = counters::Database::load(
                    &self
                        .options
                        .state_directory
                        .join(format!("traffic-{scope}-v1.json")),
                    scope,
                )?;
                // JSON-safe integer strings for counters, including history.
                let mut v = serde_json::to_value(db)?;
                stringify_counts(&mut v);
                databases.insert(scope.into(), v);
            }
            return Ok(json!({"schema":"netcontrol-services/counters/v1","scopes":databases}));
        }
        bail!("service statistics endpoint not found: {path}")
    }
    pub fn repair(&mut self, config: &Value) -> Result<()> {
        let c = Config::parse(config)?;
        self.preflight(&c)?;
        self.stop_all()?;
        self.config = c.clone();
        if let Err(e) = self.start(&c) {
            self.error = Some(format!("{e:#}"));
            let stopped = self.stop_all();
            bail!("service repair failed: {e:#}; shutdown: {stopped:?}")
        }
        self.error = None;
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<()> {
        self.stop_all()
    }
}
fn stringify_counts(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets"].contains(&key.as_str()) {
                    if let Some(n) = value.as_u64() {
                        *value = json!(n.to_string());
                    }
                } else {
                    stringify_counts(value)
                }
            }
        }
        Value::Array(a) => {
            for value in a {
                stringify_counts(value)
            }
        }
        _ => {}
    }
}
impl Drop for Services {
    fn drop(&mut self) {
        let _ = self.stop_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn syslog_without_systemd_activation_fails_before_stopping_workers() {
        let directory =
            std::env::temp_dir().join(format!("nc-syslog-preflight-{}", rand::random::<u64>()));
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: true,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        let previous = json!({});
        services.apply(&previous, &previous).unwrap();
        let candidate = json!({"syslog":{"enabled":true,"servers":[{"host":"127.0.0.1","port":514,"transport":"udp"}]}});
        let before = services.status();
        assert!(
            services
                .validate(&candidate)
                .unwrap_err()
                .to_string()
                .contains("requires systemd socket activation")
        );
        assert!(
            services
                .apply(&previous, &candidate)
                .unwrap_err()
                .to_string()
                .contains("requires systemd socket activation")
        );
        assert_eq!(services.status(), before);
        assert!(services.workers.is_empty());
        drop(services);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_validation_requires_both_host_opt_ins_without_starting_workers() {
        let value = json!({
            "interfaces":[{"name":"wan0","kind":"ethernet","up":true}],
            "dhcp_clients":{"wan0":{}},
            "gateway_monitors":[{"name":"wan","mode":"dhcp","enabled":true,
                "interface":"wan0","target":"203.0.113.1"}]
        });
        for (allow_host_services, allow_gateway_monitoring, expected) in [
            (false, false, Some("explicit allow_host_services")),
            (true, false, Some("explicit allow_gateway_monitoring")),
            (true, true, None),
        ] {
            let directory = std::env::current_dir().unwrap().join(format!(
                "services-gateway-validation-{}",
                rand::random::<u64>()
            ));
            let services = Services::new(ServiceOptions {
                namespace: None,
                state_directory: directory.clone(),
                allow_host_services,
                allow_gateway_monitoring,
            })
            .unwrap();
            let before = services.status();
            match expected {
                Some(message) => assert!(
                    services
                        .validate(&value)
                        .unwrap_err()
                        .to_string()
                        .contains(message)
                ),
                None => services.validate(&value).unwrap(),
            }
            assert_eq!(services.status(), before);
            assert!(services.workers.is_empty());
            drop(services);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_namespace_handle_does_not_bypass_host_service_opt_in() {
        let directory = std::env::current_dir()
            .unwrap()
            .join(format!("services-current-scope-{}", rand::random::<u64>()));
        let services = Services::new(ServiceOptions {
            namespace: Some(std::path::PathBuf::from("/proc/thread-self/ns/net")),
            state_directory: directory.clone(),
            allow_host_services: false,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        let config = Config::parse(&json!({"interfaces":[{
            "name":"nic0","kind":"ethernet","up":true,"addresses":["192.0.2.2/24"],
            "dhcp_relay":{"enabled":true,"servers":["198.51.100.10"]}
        }]}))
        .unwrap();
        assert!(
            services
                .preflight(&config)
                .unwrap_err()
                .to_string()
                .contains("explicit allow_host_services")
        );
        drop(services);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn disabled_services_lifecycle_no_fake_pid() {
        let directory = std::env::current_dir()
            .unwrap()
            .join(format!("services-test-{}", rand::random::<u64>()));
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: false,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        services
            .apply(&json!({}), &json!({"ntp":{"enabled":false,"servers":[]}}))
            .unwrap();
        assert!(!services.status().to_string().contains("\"pid\""));
        assert_eq!(
            services.status()["appliance_services"][0]["state"],
            "disabled"
        );
        assert!(
            services
                .apply(
                    &json!({}),
                    &json!({"ntp":{"enabled":true,"servers":["192.0.2.1"]}})
                )
                .is_err()
        );
        assert!(services.statistics("/statistics/gateways", "x=1").is_err());
        assert_eq!(
            services.statistics("/statistics/gateways", "").unwrap()["gateways"],
            json!([])
        );
        services.shutdown().unwrap();
        drop(services);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn counters_are_decimal_strings() {
        let mut v = json!({"total":{"rx_bytes":u64::MAX,"tx_packets":9007199254740993u64}});
        stringify_counts(&mut v);
        assert_eq!(v["total"]["rx_bytes"], u64::MAX.to_string());
    }
    #[test]
    fn canonical_vnstat_paths_preserve_exact_body_and_reject_queries() {
        let directory = std::env::current_dir()
            .unwrap()
            .join(format!("vnstat-api-test-{}", rand::random::<u64>()));
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: true,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        assert!(
            services
                .statistics("/api/v1/statistics/vnstat", "")
                .unwrap_err()
                .to_string()
                .contains("disabled")
        );
        services.config.vnstat.enabled = true;
        for scope in ["host", "managed"] {
            let db = json!({"schema":"netcontrol-services/counters/v1","scope":scope,"interfaces":{"lan0":{"ifindex":3,"boot_id":"synthetic-boot","namespace_id":"4:4026533000","last":{"rx_bytes":120,"tx_bytes":100,"rx_packets":2,"tx_packets":1},"total":{"rx_bytes":20,"tx_bytes":0,"rx_packets":1,"tx_packets":0},"resets":0,"last_seen":"2026-10-19T06:00:00Z","present":true}},"history":[{"collected_at":"2026-10-19T06:00:00Z","interface":"lan0","delta":{"rx_bytes":20,"tx_bytes":0,"rx_packets":1,"tx_packets":0},"reset":false}]});
            std::fs::write(
                directory.join(format!("traffic-{scope}-v1.json")),
                serde_json::to_vec(&db).unwrap(),
            )
            .unwrap();
            let worker = Worker::start(
                format!("vnstat-{scope}"),
                None,
                json!({"collected_at":"2026-10-19T06:00:00Z"}),
                || {
                    Ok(Box::new(|ctx| {
                        while !ctx.wait(std::time::Duration::from_millis(10)) {}
                        Ok(())
                    }))
                },
            )
            .unwrap();
            services.workers.insert(format!("vnstat-{scope}"), worker);
        }
        let both = services
            .statistics("/api/v1/statistics/vnstat", "")
            .unwrap();
        assert_eq!(both["schema"], "netcontrol-services/counters/v1");
        assert_eq!(both["scopes"].as_object().unwrap().len(), 2);
        for scope in ["host", "managed"] {
            let single = services
                .statistics(&format!("/api/v1/statistics/vnstat/{scope}"), "")
                .unwrap();
            assert_eq!(
                single,
                json!({"schema":"netcontrol-services/counters/v1","scopes":{scope:both["scopes"][scope]}})
            );
            assert_eq!(
                single["scopes"][scope]["interfaces"]["lan0"]["last"]["rx_bytes"],
                "120"
            );
            assert_eq!(
                single["scopes"][scope]["history"][0]["delta"]["rx_packets"],
                "1"
            );
            assert_eq!(
                single,
                services
                    .statistics(&format!("/statistics/vnstat/{scope}"), "")
                    .unwrap()
            );
        }
        for query in ["scope=host", "limit=1", "?", " "] {
            assert!(
                services
                    .statistics("/api/v1/statistics/vnstat", query)
                    .is_err()
            );
        }
        for path in [
            "/api/v1/statistics/vnstat/",
            "/api/v1/statistics/vnstat/invalid",
            "/api/v1/statistics/vnstat/host/extra",
        ] {
            assert!(services.statistics(path, "").is_err());
        }
        services.shutdown().unwrap();
        assert!(
            services
                .statistics("/api/v1/statistics/vnstat", "")
                .is_err()
        );
        drop(services);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
