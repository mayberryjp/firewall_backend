//! In-process service workers. Native operations are Linux-only; parsing and protocol tests are portable.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod config;
mod counters;
mod dhcp;
mod dns_lookup;
pub use dns_lookup::lookup as dns_lookup;
mod flow;
mod gateway;
#[cfg(all(test, target_os = "linux"))]
mod integration;
#[cfg(target_os = "linux")]
mod linux;
mod mdns;
mod ntp;
mod resolve;
mod syslog;
mod udp_broadcast_relay;
mod worker;

use anyhow::{Context, Result, bail, ensure};
use config::Config;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
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
            move || gateway::prepare(config.clone()),
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
    pub fn verify_mdns(&self, value: &Value) -> Result<()> {
        let expected = Config::parse(value)?;
        ensure!(
            expected.mdns == self.config.mdns
                && expected.mdns_interfaces == self.config.mdns_interfaces
                && (!expected.mdns.enabled || expected.ipv6_enabled == self.config.ipv6_enabled),
            "native mDNS operational configuration does not match applied settings"
        );
        if expected.mdns.enabled {
            ensure!(
                self.workers.get("mdns").is_some_and(Worker::active),
                "native mDNS supervisor is not active"
            );
        } else {
            ensure!(
                !self.workers.contains_key("mdns"),
                "disabled mDNS still has an owned worker"
            );
        }
        Ok(())
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
                    || c.mdns.enabled
                    || c.udp_broadcast_relay.enabled
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
                .context("native syslog requires systemd socket activation from netcontrol-syslog.socket and journald ForwardToSyslog=yes")?;
        }
        #[cfg(not(target_os = "linux"))]
        ensure!(
            !c.ntp.enabled
                && !c.mdns.enabled
                && !c.udp_broadcast_relay.enabled
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
        if self.config == next && self.workers_current(&next) {
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
    pub fn verify(&self, value: &Value) -> Result<()> {
        let expected = Config::parse(value)?;
        ensure!(
            self.config == expected,
            "native service configuration does not match applied settings"
        );
        ensure!(
            self.workers_current(&expected),
            "native service supervisors do not match applied settings"
        );
        Ok(())
    }
    /// True when exactly the requested supervisors exist, including workers awaiting recovery.
    /// A shutdown leaves the stored configuration in place, so an empty worker set is not current.
    fn workers_current(&self, c: &Config) -> bool {
        self.workers.keys().cloned().collect::<BTreeSet<_>>() == expected_workers(c)
            && self.workers.values().all(Worker::active)
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
                    move || ntp::prepare(config.clone(), ipv6_enabled),
                )?;
            }
            if c.syslog.enabled {
                let config = c.syslog.clone();
                let dir = self.options.state_directory.clone();
                let socket = self
                    .syslog_socket
                    .clone()
                    .context("systemd syslog socket missing")?;
                self.insert("syslog",host.clone(),json!({"name":"syslog","scope":"host","source":"journald","host_source":syslog::JOURNAL_SOCKET}),move||syslog::prepare(config.clone(),dir.clone(),socket.clone(),ipv6_enabled))?;
            }
            if c.vnstat.enabled {
                let dir = self.options.state_directory.clone();
                let config = c.vnstat.clone();
                self.insert(
                    "vnstat",
                    host.clone(),
                    json!({"name":"vnstat","scope":"host","schema":counters::SCHEMA}),
                    move || counters::prepare(dir.clone(), config.clone()),
                )?;
            }
            let relays: Vec<_> = c
                .interfaces
                .iter()
                .filter(|i| i.dhcp_relay.enabled)
                .cloned()
                .collect();
            if c.mdns.enabled {
                let mut config = c.mdns.clone();
                config.publishing.aaaa_on_ipv4 &= c.ipv6_enabled;
                let interfaces = c.mdns_interfaces.clone();
                self.insert("mdns", managed.clone(), c.mdns_status.clone(), move || {
                    mdns::prepare(config.clone(), interfaces.clone())
                })?;
            }
            if !relays.is_empty() {
                self.insert(
                    "dhcp-relay",
                    managed.clone(),
                    json!({"name":"dhcp-relay","scope":"managed"}),
                    move || dhcp::prepare(relays.clone()),
                )?;
            }
            for instance in c
                .udp_broadcast_relay
                .instances
                .iter()
                .filter(|instance| c.udp_broadcast_relay.enabled && instance.enabled)
            {
                let config = instance.clone();
                self.insert(
                    &format!("udp-broadcast-relay:{}", instance.id),
                    managed.clone(),
                    instance.status(true, "starting"),
                    move || udp_broadcast_relay::prepare(config.clone()),
                )?;
            }
            for f in c.softflowd.iter().filter(|f| f.enabled) {
                let config = f.clone();
                self.insert(&format!("flow:{}",f.name),managed.clone(),                                json!({"name":f.name,"scope":"managed","export_version":f.export_version,"address_family":if !ipv6_enabled || [1,5].contains(&f.export_version){"ipv4"}else{"dual"},"fragments":"excluded","capture_filter":f.capture_filter,"sampling_rate":f.sampling_rate,"sampling_metadata":f.export_version!=1}),move||flow::prepare(config.clone(),ipv6_enabled))?;
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
                    move || gateway::prepare(config.clone()),
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
        prepare: impl FnMut() -> Result<Box<dyn FnOnce(worker::ContextState) -> Result<()> + Send>>
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
        let mut appliance = vec![
            self.row("ntp", c.ntp.enabled, json!({"name":"ntp","scope":"host"})),
            self.row(
                "syslog",
                c.syslog.enabled,
                json!({"name":"syslog","scope":"host"}),
            ),
            self.row(
                "vnstat",
                c.vnstat.enabled,
                json!({"name":"vnstat","scope":"host"}),
            ),
        ];
        let mut base = c.mdns_status.clone();
        if base.is_null() {
            let config = netcontrol_core::Config::default();
            base = config.mdns.status(&config, "disabled");
        }
        appliance.push(if let Some(worker) = self.workers.get("mdns") {
            worker.snapshot()
        } else {
            base["state"] = json!(if c.mdns.enabled {
                "stopped"
            } else {
                "disabled"
            });
            base
        });
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
        for instance in &c.udp_broadcast_relay.instances {
            appliance.push(
                self.workers
                    .get(&format!("udp-broadcast-relay:{}", instance.id))
                    .map(Worker::snapshot)
                    .unwrap_or_else(|| {
                        instance.status(
                            c.udp_broadcast_relay.enabled && instance.enabled,
                            if c.udp_broadcast_relay.enabled && instance.enabled {
                                "stopped"
                            } else {
                                "disabled"
                            },
                        )
                    }),
            );
        }
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
            for key in ["retrying", "restart_count", "last_error"] {
                if let Some(value) = row.get(key) {
                    stats[key] = value.clone();
                }
            }
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
        if path == "/statistics/vnstat" {
            ensure!(self.config.vnstat.enabled, "vnstat is disabled");
            let state = self
                .workers
                .get("vnstat")
                .context("traffic worker unavailable")?
                .snapshot();
            ensure!(
                state["state"] == "running" && state["collected_at"].is_string(),
                "traffic history unavailable: {state}"
            );
            let database = counters::Database::load(
                &self.options.state_directory.join(counters::FILE_NAME),
                "host",
            )?;
            let mut value = serde_json::to_value(database)?;
            stringify_counts(&mut value);
            return Ok(value);
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
    pub fn restart_worker(&mut self, target: &str) -> Result<Value> {
        let worker = self
            .workers
            .get_mut(target)
            .context("enabled service worker not found")?;
        worker.restart()?;
        Ok(worker.snapshot())
    }
    pub fn shutdown(&mut self) -> Result<()> {
        self.stop_all()
    }
}
fn expected_workers(c: &Config) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if c.mdns.enabled {
        keys.insert("mdns".to_owned());
    }
    keys.extend(
        c.udp_broadcast_relay
            .instances
            .iter()
            .filter(|instance| c.udp_broadcast_relay.enabled && instance.enabled)
            .map(|instance| format!("udp-broadcast-relay:{}", instance.id)),
    );
    if c.ntp.enabled {
        keys.insert("ntp".to_owned());
    }
    if c.syslog.enabled {
        keys.insert("syslog".to_owned());
    }
    if c.vnstat.enabled {
        keys.insert("vnstat".to_owned());
    }
    if c.interfaces.iter().any(|i| i.dhcp_relay.enabled) {
        keys.insert("dhcp-relay".to_owned());
    }
    keys.extend(
        c.softflowd
            .iter()
            .filter(|f| f.enabled)
            .map(|f| format!("flow:{}", f.name)),
    );
    keys.extend(
        c.gateway_monitors
            .iter()
            .filter(|m| m.enabled && m.mode == "explicit")
            .map(|m| format!("gateway:{}", m.name)),
    );
    keys
}
fn stringify_counts(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if [
                    "rx_bytes",
                    "tx_bytes",
                    "rx_packets",
                    "tx_packets",
                    "sent_datagrams",
                    "failed_datagrams",
                ]
                .contains(&key.as_str())
                {
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
    fn selective_restart_preserves_unrelated_worker() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let directory =
            std::env::temp_dir().join(format!("nc-selective-restart-{}", rand::random::<u64>()));
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: false,
            allow_gateway_monitoring: false,
        })?;
        let starts = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        for (name, count) in ["ntp", "mdns"].into_iter().zip(&starts) {
            let count = count.clone();
            services.workers.insert(
                name.into(),
                Worker::start(name.into(), None, json!({"name":name}), move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(Box::new(|context| {
                        while !context.wait(std::time::Duration::from_millis(5)) {}
                        Ok(())
                    }))
                })?,
            );
        }
        let previous = services.workers["ntp"].context.clone();
        let untouched = services.workers["mdns"].context.clone();
        assert_eq!(services.restart_worker("ntp")?["state"], "running");
        assert!(previous.stopping());
        assert!(!untouched.stopping());
        assert!(Arc::ptr_eq(
            &untouched.stop,
            &services.workers["mdns"].context.stop
        ));
        assert_eq!(starts[0].load(Ordering::SeqCst), 2);
        assert_eq!(starts[1].load(Ordering::SeqCst), 1);
        assert!(services.restart_worker("unknown").is_err());
        services.shutdown()?;
        drop(services);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

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
    fn a_shutdown_leaves_the_config_but_apply_must_not_treat_empty_workers_as_current() {
        let directory = std::env::current_dir().unwrap().join(format!(
            "services-workers-current-{}",
            rand::random::<u64>()
        ));
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: true,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        let idle = || {
            Worker::start("fixture".into(), None, json!({}), || {
                Ok(Box::new(|ctx| {
                    while !ctx.wait(std::time::Duration::from_millis(10)) {}
                    Ok(())
                }))
            })
            .unwrap()
        };
        let disabled = Config::parse(&json!({})).unwrap();
        let enabled = Config::parse(&json!({
            "ntp":{"enabled":true,"servers":["192.0.2.1"]},
            "vnstat":{"enabled":true}
        }))
        .unwrap();
        assert!(services.workers_current(&disabled));
        assert!(!services.workers_current(&enabled));
        services.workers.insert("ntp".into(), idle());
        assert!(!services.workers_current(&enabled));
        assert!(!services.workers_current(&disabled));
        services.workers.insert("vnstat".into(), idle());
        assert!(services.workers_current(&enabled));
        services.workers.insert("syslog".into(), idle());
        assert!(!services.workers_current(&enabled));
        services.shutdown().unwrap();
        assert!(!services.workers_current(&enabled));
        drop(services);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn recovering_services_verify_without_requiring_network_health() {
        let directory =
            std::env::temp_dir().join(format!("services-recovery-{}", rand::random::<u64>()));
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: true,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        let config = json!({"ntp":{"enabled":true,"servers":["192.0.2.1"]}});
        services.config = Config::parse(&config).unwrap();
        services.workers.insert(
            "ntp".into(),
            Worker::start("ntp".into(), None, json!({}), || {
                Err(anyhow::anyhow!("synthetic connectivity outage"))
            })
            .unwrap(),
        );
        assert_eq!(services.workers["ntp"].snapshot()["state"], "error");
        services.verify(&config).unwrap();
        services.apply(&config, &config).unwrap();
        assert_eq!(services.workers["ntp"].snapshot()["restart_count"], 1);
        assert!(services.verify(&json!({})).is_err());
        services.shutdown().unwrap();
        assert!(services.verify(&config).is_err());
        drop(services);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn retained_traffic_files_do_not_block_service_construction() {
        let directory =
            std::env::temp_dir().join(format!("services-retained-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let retained = [
            (
                "traffic-host-v1.json",
                b"retained host accounting".as_slice(),
            ),
            (
                "traffic-managed-v1.json",
                b"retained managed accounting".as_slice(),
            ),
            (
                counters::FILE_NAME,
                b"invalid current accounting".as_slice(),
            ),
        ];
        for (name, contents) in &retained {
            std::fs::write(directory.join(name), contents).unwrap();
        }
        let mut services = Services::new(ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: true,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        services.apply(&json!({}), &json!({})).unwrap();
        services.verify(&json!({})).unwrap();
        #[cfg(target_os = "linux")]
        {
            let enabled = json!({"vnstat":{"enabled":true}});
            services.apply(&json!({}), &enabled).unwrap();
            services.verify(&enabled).unwrap();
            let status = services.workers["vnstat"].snapshot();
            assert_eq!(status["state"], "error");
            assert_eq!(status["retrying"], true);
            assert!(status["error"].as_str().unwrap().contains("refusing reset"));
            assert!(
                services
                    .statistics("/api/v1/statistics/vnstat", "")
                    .is_err()
            );
            services.apply(&enabled, &json!({})).unwrap();
            services.verify(&json!({})).unwrap();
        }
        services.shutdown().unwrap();
        drop(services);
        for (name, contents) in &retained {
            assert_eq!(std::fs::read(directory.join(name)).unwrap(), *contents);
        }
        assert!(counters::Database::load(&directory.join(counters::FILE_NAME), "host").is_err());
        assert!(!directory.join("traffic-host-v2.pending").exists());
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
        {
            let mut db =
                counters::Database::load(&directory.join(counters::FILE_NAME), "host").unwrap();
            for bytes in [100, 120] {
                db.observe(
                    "synthetic-boot",
                    "4:4026533000",
                    "lan0",
                    3,
                    counters::Counts {
                        rx_bytes: bytes,
                        ..Default::default()
                    },
                    "2026-10-19T06:00:00Z",
                )
                .unwrap();
            }
            std::fs::write(
                directory.join(counters::FILE_NAME),
                serde_json::to_vec(&db).unwrap(),
            )
            .unwrap();
            let worker = Worker::start(
                "vnstat".into(),
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
            services.workers.insert("vnstat".into(), worker);
        }
        let both = services
            .statistics("/api/v1/statistics/vnstat", "")
            .unwrap();
        assert_eq!(both["schema"], counters::SCHEMA);
        assert_eq!(both["scope"], "host");
        assert_eq!(both["interfaces"]["lan0"]["last"]["rx_bytes"], "120");
        assert_eq!(
            both["interfaces"]["lan0"]["day"]["counts"]["rx_bytes"],
            "20"
        );
        assert_eq!(both["sent_datagrams"], "0");
        assert_eq!(both, services.statistics("/statistics/vnstat", "").unwrap());
        for query in ["scope=host", "limit=1", "?", " "] {
            assert!(
                services
                    .statistics("/api/v1/statistics/vnstat", query)
                    .is_err()
            );
        }
        for path in [
            "/api/v1/statistics/vnstat/host",
            "/api/v1/statistics/vnstat/managed",
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
