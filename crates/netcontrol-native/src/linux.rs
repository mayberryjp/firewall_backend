use crate::{
    NativeOptions,
    model::{EthernetSnapshot, Kernel, Network, Route},
};
use anyhow::{Context, Result, anyhow, ensure};
use netcontrol_core::{Backend, Config};
use netcontrol_services::{ServiceOptions, Services};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "nftables")]
mod firewall;
#[cfg(not(feature = "nftables"))]
mod firewall {
    use anyhow::{Result, bail};
    use serde_json::Value;
    pub fn validate(_: &Value, _: &[crate::model::Link]) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn verify(_: &Value, _: &Option<Value>, _: Option<&str>) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn apply(_: &Value, _: &[crate::model::Link]) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn remove_owned(_: &str) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn counters(
        _: &Value,
        _: &[crate::model::Link],
        _: &Option<Value>,
        _: &str,
    ) -> Result<Value> {
        bail!("native backend was built without nftables support")
    }
}
mod adoption;
mod bgp;
mod capabilities;
mod deny_log;
#[cfg(feature = "nftables")]
mod destination_rewrite;
mod dhcp_client;
mod dhcp_monitors;
#[cfg(all(test, feature = "nftables"))]
mod host_integration;
#[cfg(all(test, feature = "nftables"))]
mod integration;
mod interface_aliases;
mod ipv6;
mod link_monitor;
mod netfilter;
mod networking;
mod offloads;
mod panic_reboot;
mod path_test;
mod rpf;
mod rps;
mod rps_recommendations;
mod sysctl;
mod takeover;
mod takeover_bpf;
mod takeover_firewall;
mod takeover_legacy;
mod takeover_processes;
mod wireguard;
mod wireguard_dns;

pub use networking::Parent;

pub(super) fn create_wireguard_key(root: &Path, reference: &str) -> Result<String> {
    wireguard::create_key(root, reference)
}

pub(super) fn wireguard_public_key(root: &Path, reference: &str) -> Result<String> {
    wireguard::public_key(root, reference)
}

pub struct Native {
    panic_reboot: Option<panic_reboot::Guard>,
    path_test: path_test::Manager,
    performance: crate::performance::Monitor,
    bgp: bgp::Manager,
    link_monitor: link_monitor::Monitor,
    deny_log: deny_log::Monitor,
    options: NativeOptions,
    namespace: Arc<File>,
    namespace_path: PathBuf,
    identity: String,
    parents: BTreeMap<String, Parent>,
    services: Services,
    dhcp: dhcp_client::Manager,
    dhcp_monitors: dhcp_monitors::Manager,
    wireguard_dns: wireguard_dns::Manager,
    state: PathBuf,
    _lock: File,
    host_namespace: Option<Arc<File>>,
    _host_lock: Option<File>,
    boot: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    scope: String,
    firewall_config: Option<Value>,
    firewall_fingerprint: Option<String>,
    kernel_baseline: Kernel,
    #[serde(default)]
    ethernet_originals: BTreeMap<String, EthernetSnapshot>,
    #[serde(default)]
    vlan_originals: BTreeMap<String, EthernetSnapshot>,
    #[serde(default)]
    managed_interfaces: BTreeSet<String>,
    #[serde(default)]
    boot: String,
    #[serde(default)]
    committed_config: Option<Value>,
    #[serde(default)]
    ipv6_original: Option<ipv6::Snapshot>,
}

pub(super) fn validate_offline_state(ownership: &Value, receipt: Option<&Value>) -> Result<()> {
    let ownership: Ownership = serde_json::from_value(ownership.clone())?;
    if let Some(config) = &ownership.committed_config {
        let config: Config = serde_json::from_value(config.clone())?;
        config.validate()?;
    }
    if let Some(receipt) = receipt {
        let receipt: adoption::Receipt = serde_json::from_value(receipt.clone())?;
        ensure!(receipt.complete, "finish native adoption before conversion");
        ensure!(
            receipt.scope == ownership.scope,
            "native adoption scope mismatch"
        );
        receipt.config.validate()?;
        let _: Ownership = serde_json::from_value(receipt.ownership_before)?;
    }
    Ok(())
}

impl Ownership {
    fn handover_originals(&self, host_mode: bool) -> BTreeMap<String, EthernetSnapshot> {
        if !host_mode {
            return BTreeMap::new();
        }
        self.ethernet_originals
            .iter()
            .chain(
                self.vlan_originals
                    .iter()
                    .filter(|(name, _)| Path::new("/sys/class/net").join(name).exists()),
            )
            .filter(|(name, _)| self.managed_interfaces.contains(*name))
            .map(|(name, snapshot)| (name.clone(), snapshot.clone()))
            .collect()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    scope: String,
    before: Value,
    after: Value,
    kernel_before: Kernel,
    ownership_before: Ownership,
    #[serde(default)]
    ethernet_before: BTreeMap<String, EthernetSnapshot>,
    #[serde(default)]
    ethernet_originals: BTreeMap<String, EthernetSnapshot>,
    ipv6_before: ipv6::Snapshot,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostScope {
    machine: String,
    boot: String,
    device: u64,
    inode: u64,
    identity: String,
}

fn retain_committed_boot_routes(snapshot: &mut Value, committed: &[Route]) -> Result<()> {
    let routes: Vec<_> = Network::parse(snapshot)?
        .routes
        .into_iter()
        .filter(|route| committed.contains(route))
        .collect();
    snapshot["routes"] = serde_json::to_value(routes)?;
    Ok(())
}

impl Native {
    pub fn open(options: NativeOptions) -> Result<Self> {
        ensure!(
            cfg!(feature = "nftables"),
            "native backend was built without nftables support; this build cannot manage networking"
        );
        let host_mode = options.namespace.is_empty();
        let path = if host_mode {
            PathBuf::from("/proc/thread-self/ns/net")
        } else if Path::new(&options.namespace).is_absolute() {
            PathBuf::from(&options.namespace)
        } else {
            ensure!(
                crate::safe_name(&options.namespace, 64),
                "invalid named network namespace"
            );
            PathBuf::from("/run/netns").join(&options.namespace)
        };
        let namespace = Arc::new(if host_mode {
            File::open(&path)?
        } else {
            open_namespace(&path)?
        });
        ensure!(
            unsafe { libc::flock(namespace.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "network namespace is already owned, or nsfs does not support advisory ownership locking: {}",
            std::io::Error::last_os_error()
        );
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let meta = namespace.metadata()?;
        let mut identity = format!("linux:{}:{}:{}", boot.trim(), meta.dev(), meta.ino());
        let names: BTreeSet<_> = options.adopted_parents.iter().cloned().collect();
        ensure!(
            names.len() == options.adopted_parents.len(),
            "duplicate adopted parent"
        );
        ensure!(
            names.iter().all(|n| crate::safe_name(n, 15) && n != "lo"),
            "invalid adopted parent name"
        );
        let parents = session(namespace.clone(), move |rt, handle| {
            rt.block_on(networking::adopt(handle, &names))
        })?;
        if !parents.is_empty() {
            let identities: Vec<_> = parents
                .values()
                .map(|p| (&p.name, p.index, &p.kind, &p.mac))
                .collect();
            identity.push_str(&format!(
                ":parents:{}",
                hex::encode(Sha256::digest(serde_json::to_vec(&identities)?))
            ));
        }
        let state = options.services_state.join("native");
        ensure!(
            state.is_absolute(),
            "native state directory must be absolute"
        );
        trusted_directory(&state)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state.join("lock"))?;
        ensure!(
            lock.metadata()?.uid() == unsafe { libc::geteuid() }
                && lock.metadata()?.permissions().mode() & 0o077 == 0,
            "untrusted native lock file"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another native manager owns this state directory"
        );
        if host_mode {
            let machine = fs::read_to_string("/etc/machine-id")
                .context("host mode requires a stable /etc/machine-id")?;
            let machine = machine.trim().to_owned();
            ensure!(
                machine.len() == 32 && machine.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid /etc/machine-id"
            );
            let marker = state.join("host-scope.json");
            let host = if marker.try_exists()? {
                let saved: HostScope = read_json(&marker)?;
                ensure!(
                    saved.machine == machine,
                    "host state belongs to a different machine"
                );
                ensure!(
                    saved.boot != boot.trim()
                        || (saved.device == meta.dev() && saved.inode == meta.ino()),
                    "host state belongs to a different current-daemon namespace in this boot"
                );
                saved
            } else {
                HostScope {
                    machine: machine.clone(),
                    boot: boot.trim().into(),
                    device: meta.dev(),
                    inode: meta.ino(),
                    identity: format!(
                        "linux:host:{machine}:{}",
                        hex::encode(Sha256::digest(state.as_os_str().as_encoded_bytes()))
                    ),
                }
            };
            identity = host.identity;
            write_json(
                &marker,
                &HostScope {
                    machine,
                    boot: boot.trim().into(),
                    device: meta.dev(),
                    inode: meta.ino(),
                    identity: identity.clone(),
                },
            )?;
        }
        let (host_namespace, host_lock) = if host_mode || options.allow_host_tunables {
            let metadata = fs::symlink_metadata("/run")?;
            ensure!(
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "host tuning requires trusted root-owned /run"
            );
            let lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/run/netcontrol-host-tunables.lock")?;
            let metadata = lock.metadata()?;
            ensure!(
                metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
                "untrusted global host tunable lock"
            );
            ensure!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "host tunables already owned by another manager"
            );
            (
                Some(if host_mode {
                    namespace.clone()
                } else {
                    Arc::new(File::open("/proc/thread-self/ns/net")?)
                }),
                Some(lock),
            )
        } else {
            (None, None)
        };
        let services = Services::new(ServiceOptions {
            namespace: if host_mode { None } else { Some(path.clone()) },
            state_directory: options.services_state.clone(),
            allow_host_services: options.allow_host_services,
            allow_gateway_monitoring: options.gateway_monitoring,
        })?;
        let dhcp = dhcp_client::Manager::new(namespace.clone(), state.clone(), host_mode);
        let dhcp_monitors = dhcp_monitors::Manager::new(namespace.clone(), dhcp.state.clone());
        let mut native = Self {
            panic_reboot: None,
            path_test: path_test::Manager::new(
                namespace.clone(),
                state.clone(),
                boot.trim().into(),
            ),
            performance: Default::default(),
            wireguard_dns: wireguard_dns::Manager::new(
                namespace.clone(),
                options.keys.clone(),
                state.join("wireguard-dns.json"),
            )?,
            bgp: bgp::Manager::new(namespace.clone(), state.clone())?,
            link_monitor: link_monitor::Monitor::new(namespace.clone())?,
            deny_log: deny_log::Monitor::new(namespace.clone(), state.join("deny-log"))?,
            dhcp,
            dhcp_monitors,
            options,
            namespace,
            namespace_path: path,
            identity,
            parents,
            services,
            state,
            _lock: lock,
            host_namespace,
            _host_lock: host_lock,
            boot: boot.trim().into(),
        };
        native.path_test.recover()?;
        let ownership = native.ownership()?;
        ensure!(
            ownership.scope.is_empty() || ownership.scope == native.identity,
            "native ownership belongs to another host/namespace/parent identity; state is not reset"
        );
        ensure!(
            (ownership.kernel_baseline.host.is_empty()
                && ownership.kernel_baseline.rps.is_empty()
                && ownership.kernel_baseline.rfs.is_none()
                && ownership.kernel_baseline.offloads.is_empty())
                || native.host_namespace.is_some(),
            "host tunable recovery requires host mode or allow_host_tunables for a lab namespace"
        );
        native.bgp.recover()?;
        let originals = ownership.handover_originals(host_mode);
        let takeover_path = native.state.join("adoption.json");
        let takeover = if host_mode && takeover_path.try_exists()? {
            let receipt: adoption::Receipt = read_json(&takeover_path)?;
            receipt.takeover.is_some()
        } else {
            false
        };
        if takeover {
            let config = ownership
                .committed_config
                .as_ref()
                .map(Network::parse)
                .transpose()?;
            if let Some(config) = config {
                native.enforce_host_takeover(&config, ownership.firewall_fingerprint.is_some())?;
            }
        } else if !originals.is_empty() {
            let snapshots = originals.clone();
            session(native.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::check_ethernet(handle, &snapshots))
            })?;
            adoption::handover_interfaces(&originals)
                .context("restore managed-interface networkd handover before native recovery")?;
        }
        native.recover()?;
        if let Some(config) = native.ownership()?.committed_config {
            let mode = serde_json::from_value::<Config>(config)?.firewall.rpf_mode;
            session(native.namespace.clone(), move |_, _| rpf::set(mode))?;
        }
        if host_mode {
            native.panic_reboot = Some(panic_reboot::Guard::new()?);
        }
        Ok(native)
    }

    fn take_ownership(&self, originals: &BTreeMap<String, EthernetSnapshot>) -> Result<()> {
        let snapshots = originals.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &snapshots))
        })?;
        adoption::handover_interfaces(originals)?;
        let snapshots = originals.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::restore_interfaces(handle, &snapshots))
        })
        .context("apply captured settings after interface ownership takeover")
    }

    fn enforce_host_takeover(&self, config: &Network, preserve_owned: bool) -> Result<()> {
        if !self.options.namespace.is_empty() {
            return Ok(());
        }
        let path = self.state.join("adoption.json");
        if !path.try_exists()? {
            return Ok(());
        }
        let mut receipt: adoption::Receipt = read_json(&path)?;
        let Some(plan) = &mut receipt.takeover else {
            return Ok(());
        };
        plan.phase = "applying".into();
        plan.error.clear();
        write_json(&path, &receipt)?;
        let result = (|| -> Result<()> {
            let mut target = config.clone();
            let leases = self
                .dhcp
                .state
                .lock()
                .map_err(|_| anyhow!("DHCP state poisoned"))?
                .clone();
            dhcp_client::effective(&mut target, &leases)?;
            let dhcp_routes = leases
                .leases
                .iter()
                .filter(|(name, lease)| {
                    lease.valid() && target.dhcp_clients.get(*name) == Some(&lease.client)
                })
                .flat_map(|(_, lease)| lease.routes.clone())
                .collect::<Vec<_>>();
            takeover::disable_managers()?;
            takeover_processes::disable()?;
            let readonly = self.parents.keys().cloned().collect();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(takeover::enforce_kernel(
                    handle,
                    &target,
                    preserve_owned,
                    &dhcp_routes,
                    &readonly,
                ))
            })
        })();
        let plan = receipt
            .takeover
            .as_mut()
            .context("host takeover plan missing")?;
        match result {
            Ok(()) => {
                plan.phase = if receipt.complete {
                    "complete"
                } else {
                    "owned"
                }
                .into();
                plan.error.clear();
                write_json(&path, &receipt)
            }
            Err(error) => {
                plan.phase = "failed".into();
                plan.error = format!("{error:#}");
                write_json(&path, &receipt)?;
                Err(error.context("console host takeover failed; partial changes and durable capture retained; rerun from console"))
            }
        }
    }

    fn check_scope(&self) -> Result<()> {
        let current = if self.options.namespace.is_empty() {
            File::open(&self.namespace_path)?
        } else {
            open_namespace(&self.namespace_path)?
        };
        crate::ensure_unchanged(
            same_file(&self.namespace, &current)?,
            "named namespace was replaced; refusing stale namespace handle",
        )?;
        let metadata = self.namespace.metadata()?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        crate::ensure_unchanged(
            self.options.namespace.is_empty()
                || self.identity.starts_with(&format!(
                    "linux:{}:{}:{}",
                    boot.trim(),
                    metadata.dev(),
                    metadata.ino()
                )),
            "boot/namespace identity changed",
        )?;
        Ok(())
    }

    fn stop_services(&mut self) -> Result<()> {
        self.wireguard_dns.shutdown()?;
        self.bgp.shutdown()?;
        self.dhcp_monitors.shutdown()?;
        self.services.shutdown()
    }

    fn repair_services(&mut self, config: &Value) -> Result<()> {
        self.wireguard_dns.shutdown()?;
        self.bgp.shutdown()?;
        self.dhcp_monitors.shutdown()?;
        self.services.repair(config)?;
        self.dhcp_monitors.configure(config)?;
        self.bgp.configure(config)?;
        self.wireguard_dns.configure(config)
    }

    fn gateway_statistics(&self, path: &str) -> Result<Value> {
        let mut value = self
            .services
            .statistics("/api/v1/statistics/gateways", "")?;
        self.dhcp_monitors.merge(&mut value["gateways"])?;
        let rows = value["gateways"]
            .as_array()
            .context("gateway statistics missing")?;
        if let Some(name) = path.strip_prefix("/api/v1/statistics/gateways/") {
            let monitor = rows
                .iter()
                .find(|row| row["name"] == name)
                .context("gateway monitor not found")?
                .clone();
            value["sample"]["status"] = json!(if monitor["sample_status"] == "available"
                || monitor["sample_status"] == "disabled"
            {
                "available"
            } else {
                "partial"
            });
            value.as_object_mut().unwrap().remove("gateways");
            value["monitor"] = monitor;
        } else {
            value["sample"]["status"] =
                json!(if rows
                    .iter()
                    .all(|row| row["sample_status"] == "available"
                        || row["sample_status"] == "disabled")
                {
                    "available"
                } else {
                    "partial"
                });
        }
        Ok(value)
    }

    fn ownership(&self) -> Result<Ownership> {
        let path = self.state.join("ownership.json");
        if !path.try_exists()? {
            return Ok(Ownership::default());
        }
        let mut ownership: Ownership = read_json(&path)?;
        if let Some(config) = &mut ownership.committed_config {
            *config = serde_json::from_value::<Config>(config.clone())?.operational_value()?;
        }
        Ok(ownership)
    }

    fn save_ownership(&self, state: &Ownership) -> Result<()> {
        write_json(&self.state.join("ownership.json"), state)
    }

    fn verify_services(&self, config: &Value) -> Result<()> {
        self.services.verify(config)
    }

    fn verify(&self, config: &Value) -> Result<()> {
        self.check_scope()?;
        let bgp_state = self
            .bgp
            .state
            .lock()
            .map_err(|_| anyhow!("BGP state poisoned"))?;
        let mut effective_config = config.clone();
        bgp_state.effective(&mut effective_config)?;
        let mut network = Network::parse(&effective_config)?;
        network.validate(&self.parents.keys().cloned().collect())?;
        let leases = self
            .dhcp
            .state
            .lock()
            .map_err(|_| anyhow!("DHCP state poisoned"))?;
        dhcp_client::effective(&mut network, &leases)?;
        firewall::validate(&network.firewall, &network.interfaces)?;
        let parents = self.parents.clone();
        let ownership = self.ownership()?;
        if ownership.committed_config.is_some() {
            let enabled = network.ipv6_enabled;
            session(self.namespace.clone(), move |_, _| ipv6::verify(enabled))?;
        }
        let originals = ownership
            .ethernet_originals
            .iter()
            .filter(|(name, _)| {
                network
                    .interfaces
                    .iter()
                    .any(|l| &l.name == *name && l.kind == "ethernet")
            })
            .map(|(name, snapshot)| (name.clone(), snapshot.clone()))
            .collect();
        for link in network.interfaces.iter().filter(|l| l.kind == "ethernet") {
            ensure!(
                ownership.ethernet_originals.contains_key(&link.name),
                "managed Ethernet {} has no durable original snapshot",
                link.name
            );
        }
        let mut effective = ownership.kernel_baseline.clone();
        effective.overlay(&network.kernel);
        self.verify_kernel(&effective)?;
        let keys = self.wireguard_dns.control.clone();
        let lease_state = leases.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))?;
            rt.block_on(networking::verify(handle, &network, &parents, &keys))?;
            rt.block_on(networking::verify_dhcp(handle, &network, &lease_state))?;
            firewall::verify(
                &network.firewall,
                &ownership.firewall_config,
                ownership.firewall_fingerprint.as_deref(),
            )?;
            Ok(())
        })
    }

    fn preflight(&self, config: &Value) -> Result<()> {
        self.check_scope()?;
        let network = Network::parse(config)?;
        network.validate(&self.parents.keys().cloned().collect())?;
        ensure!(
            self.options.namespace.is_empty() || network.dns.is_empty(),
            "configured DNS publication requires native host mode"
        );
        ensure!(
            network.kernel.host.is_empty() || self.host_namespace.is_some(),
            "host-global kernel tunables require host mode or allow_host_tunables for a lab namespace"
        );
        self.allow_tuning(&network.kernel)?;
        for key in network.kernel.rps.keys() {
            let (name, _) = netcontrol_core::rps_target(key)?;
            ensure!(
                network.interfaces.iter().any(|link| link.name == name
                    && matches!(link.kind.as_str(), "ethernet" | "wireguard")),
                "RPS requires a managed physical Ethernet or WireGuard interface"
            );
        }
        firewall::validate(&network.firewall, &network.interfaces)?;
        let allowed_names: BTreeSet<_> = network
            .interfaces
            .iter()
            .map(|l| l.name.as_str())
            .chain(self.parents.keys().map(String::as_str))
            .collect();
        if let Some(policies) = network.firewall.get("policies").filter(|p| !p.is_null()) {
            for policy in policies["interfaces"]
                .as_array()
                .context("invalid firewall interface policies")?
            {
                ensure!(
                    allowed_names.contains(
                        policy["interface"]
                            .as_str()
                            .context("missing ingress interface")?
                    ),
                    "firewall ingress must be managed or adopted"
                );
            }
        }
        for nat in network.firewall["nat"]["masquerade"]
            .as_array()
            .context("invalid masquerade rules")?
        {
            ensure!(
                allowed_names.contains(
                    nat["out_interface"]
                        .as_str()
                        .context("missing masquerade interface")?
                ),
                "masquerade egress must be managed or adopted"
            );
        }
        rps::Io::system().preflight_masks(&network.kernel.rps)?;
        let wireguard = rps::wireguard_keys(&network)?;
        let mut eager = network.kernel.clone();
        eager.rps.retain(|key, _| {
            netcontrol_core::rps_target(key).is_ok_and(|(name, _)| !wireguard.contains_key(name))
        });
        self.preflight_kernel(&eager)?;
        let enabled = network.ipv6_enabled;
        session(self.namespace.clone(), move |_, _| ipv6::preflight(enabled))?;
        let parents = self.parents.clone();
        let keys = self.wireguard_dns.control.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_parents(handle, &parents))?;
            for link in &network.interfaces {
                if let Some(wg) = &link.wireguard {
                    keys.validate(wg, network.ipv6_enabled)?;
                }
            }
            Ok(())
        })
    }

    fn network_apply(
        &mut self,
        before: &Value,
        after: &Value,
        mut kernel: Kernel,
        ownership: &mut Ownership,
    ) -> Result<()> {
        self.check_scope()?;
        self.allow_tuning(&kernel)?;
        let mut before = Network::parse(before)?;
        let mut after = Network::parse(after)?;
        let leases = self
            .dhcp
            .state
            .lock()
            .map_err(|_| anyhow!("DHCP state poisoned"))?;
        dhcp_client::effective(&mut before, &leases)?;
        dhcp_client::effective(&mut after, &leases)?;
        let before_wireguard = rps::wireguard_keys(&before)?;
        let after_wireguard = rps::wireguard_keys(&after)?;
        let parents = self.parents.clone();
        let keys = self.wireguard_dns.control.clone();
        let namespace_values = kernel.namespace.clone();
        let originals = ownership.ethernet_originals.clone();
        let lease_state = leases.clone();
        let host_dns = self.options.namespace.is_empty()
            && (!after.dns.is_empty()
                || !after.dhcp_clients.is_empty()
                || self.state.join("adoption.json").exists());
        let original_ipv6 = ownership.ipv6_original.clone();
        let takeover_network = after.clone();
        let logging = crate::firewall_plan::drop_logging_enabled(&after.firewall)?;
        if logging {
            self.deny_log.configure(true)?;
        }
        let (fingerprint, original_ipv6) = session(self.namespace.clone(), move |rt, handle| {
            let mut original_ipv6 = original_ipv6;
            if after.ipv6_enabled {
                ipv6::set(true)?;
                if let Some(snapshot) = original_ipv6.take() {
                    rt.block_on(ipv6::restore_network(handle, &snapshot.unmanaged(&after)?))
                        .context("restore unmanaged IPv6 state before networking")?;
                }
            }
            rt.block_on(networking::reconcile(
                handle, &before, &after, &parents, &keys, &originals,
            ))
            .context("reconcile managed networking")?;
            if !after.ipv6_enabled {
                if original_ipv6.is_none() {
                    original_ipv6 = Some(rt.block_on(ipv6::capture(handle))?.unmanaged(&after)?);
                }
                ipv6::set(false)?;
            }
            sysctl::write_scope(&namespace_values, "namespace")?;
            let mode = serde_json::from_value::<netcontrol_core::Firewall>(after.firewall.clone())?
                .rpf_mode;
            rpf::set(mode)?;
            firewall::apply(&after.firewall, &after.interfaces)?;
            let fingerprint = netfilter::fingerprint()?;
            // Verify the result rather than interpreting a netlink ACK as convergence.
            rt.block_on(networking::verify(handle, &after, &parents, &keys))?;
            rt.block_on(networking::verify_dhcp(handle, &after, &lease_state))?;
            if host_dns {
                rt.block_on(networking::configure_dns(handle, &after, &lease_state))?;
            }
            sysctl::verify_scope(&namespace_values, "namespace")?;
            ipv6::verify(after.ipv6_enabled)?;
            Ok((fingerprint, original_ipv6))
        })?;
        if !logging {
            self.deny_log.configure(false)?;
        }
        ownership.ipv6_original = original_ipv6;
        drop(leases);
        if self.state.join("adoption.json").try_exists()? {
            self.enforce_host_takeover(&takeover_network, true)?;
        }
        if !kernel.host.is_empty() {
            let host = self
                .host_namespace
                .clone()
                .context("host tunable opt-in required")?;
            let values = kernel.host.clone();
            host_session(host, move |_, _| {
                sysctl::write_scope(&values, "host")?;
                sysctl::verify_scope(&values, "host")
            })?;
        }
        self.write_network_rps(&before_wireguard, &after_wireguard, &mut kernel, ownership)?;
        rps::Io::system().write_rfs(&kernel.rfs, &kernel.rfs_identity)?;
        offloads::Io::system().write_requested(
            &kernel.offloads,
            &kernel.offload_requested,
            &kernel.offload_identity,
        )?;
        ownership.scope = self.identity.clone();
        // Set by caller after actual kernel convergence; never synthesize a live fingerprint.
        ownership.firewall_fingerprint = Some(fingerprint);
        Ok(())
    }

    fn write_network_rps(
        &self,
        before: &BTreeMap<String, String>,
        after: &BTreeMap<String, String>,
        kernel: &mut Kernel,
        ownership: &mut Ownership,
    ) -> Result<()> {
        let io = rps::Io::system();
        rps::validate_values(&kernel.rps)?;
        for name in before.keys().filter(|name| !after.contains_key(*name)) {
            kernel.rps.retain(|key, _| {
                netcontrol_core::rps_target(key).is_ok_and(|(interface, _)| interface != name)
            });
            kernel.rps_identity.remove(name);
        }
        for (name, reference) in after {
            if before.get(name) == Some(reference) {
                continue;
            }
            let targets = kernel
                .rps
                .iter()
                .filter(|(key, _)| {
                    netcontrol_core::rps_target(key).is_ok_and(|(interface, _)| interface == name)
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let (original, identities) = io.read(&targets, &BTreeMap::new())?;
            if original.is_empty() {
                continue;
            }
            let public_key = wireguard::public_key(&self.options.keys, reference)?;
            ensure!(
                identities
                    .get(name)
                    .and_then(|identity| identity.wireguard_public_key.as_deref())
                    == Some(public_key.as_str()),
                "new/rekeyed WireGuard RPS identity does not match configured device"
            );
            ownership.kernel_baseline.capture_originals(&Kernel {
                rps: original,
                rps_identity: identities.clone(),
                ..Default::default()
            });
            kernel.rps_identity.extend(identities);
        }
        io.write(&kernel.rps, &kernel.rps_identity)
    }

    fn capture_kernel(&self, before: &Value, after: &Value) -> Result<Kernel> {
        let before = Network::parse(before)?;
        let after = Network::parse(after)?;
        let before_wireguard = rps::wireguard_keys(&before)?;
        let after_wireguard = rps::wireguard_keys(&after)?;
        let mut keys = before.kernel;
        keys.overlay(&after.kernel);
        // Include restored-but-retained baseline keys so drift cannot be bypassed by
        // removing a key from the desired configuration and changing it externally.
        let baseline = self.ownership()?.kernel_baseline;
        keys.capture_originals(&baseline);
        rps::validate_values(&keys.rps)?;
        keys.rps.retain(|key, _| {
            netcontrol_core::rps_target(key).is_ok_and(|(name, _)| {
                !after_wireguard.contains_key(name) || before_wireguard.contains_key(name)
            })
        });
        let (features, requested, identities) =
            offloads::Io::system().complete_state(&keys.offloads, &keys.offload_identity)?;
        keys.offloads = features;
        keys.offload_requested = requested;
        keys.offload_identity = identities;
        self.read_kernel(&keys)
    }

    fn capture_ipv6(&self, before: &Value) -> Result<ipv6::Snapshot> {
        let network = Network::parse(before)?;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(ipv6::capture(handle))?.unmanaged(&network)
        })
    }

    fn capture_ethernet(
        &self,
        before: &Value,
        after: &Value,
    ) -> Result<BTreeMap<String, EthernetSnapshot>> {
        let before = Network::parse(before)?;
        let after = Network::parse(after)?;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::capture_ethernet(handle, &before, &after))
        })
    }

    fn read_kernel(&self, keys: &Kernel) -> Result<Kernel> {
        self.allow_tuning(keys)?;
        let values = keys.namespace.clone();
        let namespace = session(self.namespace.clone(), move |_, _| {
            sysctl::read_scope(&values, "namespace")
        })?;
        let host = if keys.host.is_empty() {
            BTreeMap::new()
        } else {
            let handle = self
                .host_namespace
                .clone()
                .context("host tunable ownership is unavailable")?;
            let values = keys.host.clone();
            host_session(handle, move |_, _| sysctl::read_scope(&values, "host"))?
        };
        let (rps, rps_identity) = rps::Io::system().read(&keys.rps, &keys.rps_identity)?;
        let (rfs, rfs_identity) = rps::Io::system().read_rfs(&keys.rfs, &keys.rfs_identity)?;
        let (offloads, offload_requested, offload_identity) =
            offloads::Io::system().read_state(&keys.offloads, &keys.offload_identity)?;
        Ok(Kernel {
            namespace,
            host,
            rps,
            rps_identity,
            rfs,
            rfs_identity,
            offloads,
            offload_requested,
            offload_identity,
        })
    }

    fn verify_kernel(&self, values: &Kernel) -> Result<()> {
        crate::ensure_unchanged(
            self.read_kernel(values)?.same_values(values),
            "kernel tunable drift",
        )?;
        Ok(())
    }

    fn allow_tuning(&self, values: &Kernel) -> Result<()> {
        ensure!(
            (values.rps.is_empty() && values.rfs.is_none() && values.offloads.is_empty())
                || (self.options.namespace.is_empty() && self.host_namespace.is_some()),
            "RPS/RFS/NIC offload tuning requires native host mode and exclusive host tunable ownership"
        );
        Ok(())
    }

    fn performance_snapshot(&mut self, config: &Config) -> Result<Value> {
        self.check_scope()?;
        ensure!(
            self.options.namespace.is_empty(),
            "performance diagnostics require native host mode; host sysfs cannot describe a lab namespace"
        );
        let interfaces = session(self.namespace.clone(), |rt, handle| {
            rt.block_on(async {
                let started = std::time::Instant::now();
                let links = networking::links(handle).await?;
                ensure!(links.len() <= 8192, "performance interface limit exceeded");
                let names: BTreeMap<_,_> = links.iter().map(|link| {
                    let parent = networking::parent(link);
                    (parent.index, parent.name)
                }).collect();
                let mut rows = vec![];
                let mut queue_count = 0usize;
                let mut irq_count = 0usize;
                let io = rps::Io::system();
                for link in &links {
                    ensure!(started.elapsed() < std::time::Duration::from_secs(5), "performance interface collection exceeded time limit");
                    let parent = networking::parent(link);
                    let parent_index = (parent.kind == "vlan").then(|| {
                        link.attributes.iter().find_map(|attribute| match attribute {
                            netlink_packet_route::link::LinkAttribute::Link(index) => Some(*index),
                            _ => None,
                        })
                    }).flatten();
                    let mut errors = vec![];
                    let physical = match fs::symlink_metadata(format!("/sys/class/net/{}/device",parent.name)) {
                        Ok(metadata) => metadata.file_type().is_symlink(),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                        Err(error) => { errors.push(format!("physical identity: {error}")); false }
                    };
                    let mut queues = Value::Null;
                    let mut irqs = Value::Null;
                    if physical {
                        match io.queues(&parent.name) {
                            Ok(values) => {
                                queue_count += values.len();
                                ensure!(queue_count <= 4096, "performance RX queue limit exceeded");
                                queues = json!(values.into_iter().map(|(name,mask,flows)| json!({"name":name,"rps_cpus":mask,"rps_flow_cnt":flows})).collect::<Vec<_>>());
                            }
                            Err(error) => errors.push(format!("RX queues: {error:#}")),
                        }
                        match io.irqs(&parent.name) {
                            Ok(values) => {
                                irq_count += values.len();
                                ensure!(irq_count <= 65536, "performance NIC IRQ limit exceeded");
                                irqs = json!(values);
                            }
                            Err(error) => errors.push(format!("NIC IRQs: {error:#}")),
                        }
                    } else if parent.kind == "wireguard" {
                        match io.rps_queues(&parent.name) {
                            Ok(values) => {
                                queue_count += values.len();
                                ensure!(queue_count <= 4096, "performance RX queue limit exceeded");
                                queues = json!(values.into_iter().map(|(name,mask)| json!({"name":name,"rps_cpus":mask,"rps_flow_cnt":null})).collect::<Vec<_>>());
                            }
                            Err(error) => errors.push(format!("WireGuard RX queues: {error:#}")),
                        }
                    }
                    rows.push(json!({
                        "name":parent.name,"index":parent.index,"mac":parent.mac,
                        "kind":parent.kind,"up":parent.up,"physical":physical,
                        "parent_index":parent_index,"parent":parent_index.and_then(|index| names.get(&index)),
                        "rx_queues":queues,"irqs":irqs,"errors":errors
                    }));
                }
                let current: BTreeSet<_> = networking::links(handle).await?.iter().map(|link| {
                    let p = networking::parent(link);
                    (p.name,p.index,p.mac)
                }).collect();
                for row in &rows {
                    ensure!(current.contains(&(
                        row["name"].as_str().context("missing interface name")?.to_owned(),
                        u32::try_from(row["index"].as_u64().context("missing interface index")?)?,
                        row["mac"].as_str().context("missing MAC")?.to_owned()
                    )), "interface identity changed during performance diagnostics");
                }
                ensure!(started.elapsed() < std::time::Duration::from_secs(5), "performance interface collection exceeded time limit");
                rows.sort_by(|a,b| a["name"].as_str().cmp(&b["name"].as_str()));
                Ok(rows)
            })
        })?;
        let mut snapshot = self.performance.snapshot()?;
        let mut interfaces = interfaces;
        for row in &mut interfaces {
            row["managed"] = json!(config.interfaces.iter().any(|link| link.name == row["name"]
                && matches!(link.kind.as_str(), "ethernet" | "wireguard")));
        }
        if interfaces.iter().any(|row| {
            row["errors"]
                .as_array()
                .is_some_and(|errors| !errors.is_empty())
        }) {
            snapshot["sample"]["status"] = json!("partial");
        }
        snapshot["sample"]["backend_scope"] = json!(self.identity);
        snapshot["interfaces"] = json!(interfaces);
        snapshot["configured_rps"] = json!(config.kernel.rps);
        snapshot["configured_rfs"] = json!(config.kernel.rfs);
        snapshot["configured_offloads"] = json!(config.kernel.offloads);
        snapshot["rfs"] = match rps::Io::system().rfs_entries() {
            Ok(entries) => json!({"status":"ready","sock_flow_entries":entries,"error":null}),
            Err(error) => {
                snapshot["sample"]["status"] = json!("partial");
                json!({"status":"unavailable","sock_flow_entries":null,"error":format!("{error:#}")})
            }
        };
        snapshot["tuning_available"] = json!(self.host_namespace.is_some());
        snapshot["recommendations"] = json!(rps_recommendations::recommendations(&snapshot)?);
        Ok(snapshot)
    }

    fn preflight_kernel(&self, values: &Kernel) -> Result<()> {
        self.allow_tuning(values)?;
        rps::Io::system().preflight(&values.rps, &values.rps_identity)?;
        rps::Io::system().preflight_rfs(&values.rfs, &values.rfs_identity)?;
        offloads::Io::system().preflight(&values.offloads, &values.offload_identity)?;
        let namespace = values.namespace.clone();
        session(self.namespace.clone(), move |_, _| {
            for (name, value) in namespace {
                sysctl::preflight(&name, "namespace", &value)?;
            }
            Ok(())
        })?;
        if !values.host.is_empty() {
            let handle = self
                .host_namespace
                .clone()
                .context("host tunable ownership is unavailable")?;
            let host = values.host.clone();
            host_session(handle, move |_, _| {
                for (name, value) in host {
                    sysctl::preflight(&name, "host", &value)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    fn activate_ethernet(
        &self,
        config: &Value,
        originals: &BTreeMap<String, EthernetSnapshot>,
        captured: &BTreeMap<String, EthernetSnapshot>,
    ) -> Result<()> {
        self.check_scope()?;
        let network = Network::parse(config)?;
        for link in network
            .interfaces
            .iter()
            .filter(|link| link.kind == "ethernet" && link.up)
        {
            ensure!(
                originals.contains_key(&link.name),
                "managed Ethernet {} has no durable original snapshot",
                link.name
            );
            ensure!(
                captured.contains_key(&link.name),
                "managed Ethernet {} has no durable operation snapshot",
                link.name
            );
        }
        let originals = originals.clone();
        let captured = captured.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))?;
            rt.block_on(networking::check_ethernet(handle, &captured))?;
            rt.block_on(networking::activate_ethernet(handle, &network))
        })
    }

    fn recover(&mut self) -> Result<()> {
        self.recover_interface_aliases()?;
        let path = self.state.join("intent.json");
        if !path.try_exists()? {
            return Ok(());
        }
        let intent: Intent = read_json(&path)?;
        ensure!(
            intent.scope == self.identity,
            "pending native recovery belongs to another namespace"
        );
        self.preflight(&intent.before)?;
        let mut service_before = intent.before.clone();
        service_before
            .as_object_mut()
            .context("native recovery configuration must be an object")?
            .remove("_monitor_policy_rules");
        let mut ownership = intent.ownership_before.clone();
        ownership
            .ethernet_originals
            .extend(intent.ethernet_originals);
        self.stop_services()?;
        self.activate_ethernet(
            &intent.before,
            &ownership.ethernet_originals,
            &intent.ethernet_before,
        )
        .context("recovering Ethernet links; durable intent retained on failure")?;
        self.dhcp
            .configure(&service_before)
            .context("recover DHCP clients; durable intent retained on failure")?;
        self.network_apply(
            &intent.after,
            &intent.before,
            intent.kernel_before,
            &mut ownership,
        )
        .context("recovering interrupted native operation; durable intent retained on failure")?;
        let snapshots = intent.ethernet_before;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::restore_ethernet(handle, &snapshots))
        })?;
        let snapshot = intent.ipv6_before;
        session(self.namespace.clone(), move |rt, handle| {
            ipv6::restore_controls(&snapshot)?;
            rt.block_on(ipv6::restore_network(handle, &snapshot))
        })?;
        ownership.ipv6_original = intent.ownership_before.ipv6_original;
        ownership.ethernet_originals = intent.ownership_before.ethernet_originals;
        if intent.ownership_before.firewall_fingerprint.is_none() {
            let fingerprint = ownership
                .firewall_fingerprint
                .clone()
                .context("missing rollback firewall fingerprint")?;
            session(self.namespace.clone(), move |_, _| {
                firewall::remove_owned(&fingerprint)
            })?;
            ownership.firewall_config = None;
            ownership.firewall_fingerprint = None;
        } else {
            ownership.firewall_config = Some(Network::parse(&intent.before)?.firewall);
        }
        self.repair_services(&service_before)?;
        self.save_ownership(&ownership)?;
        remove_durable(&path)
    }

    fn reconcile_after_boot(
        &mut self,
        after: &Value,
        mut ownership: Ownership,
        rollback_from: Option<&Value>,
    ) -> Result<()> {
        ensure!(
            ownership.committed_config.as_ref() == Some(after)
                || (rollback_from.is_some()
                    && ownership.committed_config.as_ref() == rollback_from),
            "reboot configuration does not match durable native ownership; refusing implicit adoption"
        );
        self.preflight(after)?;
        let mut expected = Network::parse(
            ownership
                .committed_config
                .as_ref()
                .context("missing reboot configuration")?,
        )?;
        let leases = self
            .dhcp
            .state
            .lock()
            .map_err(|_| anyhow!("DHCP state poisoned"))?;
        let (reconciliation_leases, pending_routes) =
            self.dhcp.reconciliation_state(&expected, &leases)?;
        dhcp_client::effective(&mut expected, &reconciliation_leases)?;
        let committed_routes = expected.routes.clone();
        expected.routes.extend(pending_routes);
        expected.routes.sort();
        expected.routes.dedup();
        let originals = ownership.ethernet_originals.clone();
        let keys = self.wireguard_dns.control.clone();
        let (mut before, fingerprint) = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))?;
            Ok((
                rt.block_on(networking::boot_snapshot(handle, &expected, &keys))
                    .context("capture networking before startup reconciliation")?,
                netfilter::fingerprint()?,
            ))
        })?;
        // Interrupted DHCP updates are not committed boot state.
        retain_committed_boot_routes(&mut before, &committed_routes)?;
        let mut previous = ownership.clone();
        if ownership.boot != self.boot {
            // A prior-boot lease or interface index must never be resurrected.
            ownership.ipv6_original = None;
        }
        if fingerprint == netfilter::empty_fingerprint() {
            previous.firewall_config = None;
            previous.firewall_fingerprint = None;
        } else {
            crate::ensure_unchanged(
                ownership.firewall_fingerprint.as_deref() == Some(&fingerprint),
                "owned firewall changed across reboot",
            )?;
            before["firewall"] = ownership
                .firewall_config
                .clone()
                .context("missing reboot firewall ownership")?;
        }
        let a = Network::parse(&before)?;
        let b = Network::parse(after)?;
        let ethernet_before = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::preflight(handle, &a, &b))?;
            rt.block_on(networking::capture_ethernet(handle, &a, &b))
        })?;
        let kernel_before = self.capture_kernel(&before, after)?;
        for (name, snapshot) in &ethernet_before {
            ownership
                .ethernet_originals
                .entry(name.clone())
                .or_insert_with(|| snapshot.clone());
        }
        ownership.kernel_baseline.capture_originals(&kernel_before);
        let intent = Intent {
            scope: self.identity.clone(),
            before: before.clone(),
            after: after.clone(),
            kernel_before,
            ownership_before: previous,
            ethernet_before,
            ethernet_originals: ownership.ethernet_originals.clone(),
            ipv6_before: self.capture_ipv6(&before)?,
        };
        write_json(&self.state.join("intent.json"), &intent)?;
        drop(leases);
        let mut target = ownership.kernel_baseline.clone();
        let desired = Network::parse(after)?;
        target.overlay(&desired.kernel);
        let result = (|| -> Result<()> {
            self.stop_services()?;
            self.activate_ethernet(
                after,
                &ownership.ethernet_originals,
                &intent.ethernet_before,
            )?;
            self.dhcp
                .configure(after)
                .context("configure DHCP clients during startup reconciliation")?;
            self.network_apply(&before, after, target, &mut ownership)?;
            self.repair_services(after)?;
            ownership.firewall_config = Some(Network::parse(after)?.firewall);
            ownership.managed_interfaces = Network::parse(after)?
                .interfaces
                .into_iter()
                .map(|l| l.name)
                .collect();
            ownership
                .ethernet_originals
                .retain(|name, _| ownership.managed_interfaces.contains(name));
            ownership
                .vlan_originals
                .retain(|name, _| ownership.managed_interfaces.contains(name));
            ownership.committed_config = Some(after.clone());
            ownership
                .kernel_baseline
                .release_tuning(&Network::parse(after)?.kernel);
            ownership.boot = self.boot.clone();
            self.save_ownership(&ownership)?;
            remove_durable(&self.state.join("intent.json"))
        })();
        if let Err(error) = result {
            return match self.recover() {
                Ok(()) => {
                    Err(error.context("reboot reconciliation failed; captured boot state restored"))
                }
                Err(rollback) => Err(anyhow!(
                    "reboot reconciliation failed: {error:#}; recovery failed: {rollback:#}; intent retained"
                )),
            };
        }
        Ok(())
    }
}

impl Backend for Native {
    fn prepare_vlan_adoption(
        &mut self,
        before: &Config,
        request: &netcontrol_core::AdoptVlanRequest,
    ) -> Result<netcontrol_core::VlanAdoption> {
        self.path_test.ensure_idle()?;
        self.check_scope()?;
        ensure!(
            self.options.namespace.is_empty(),
            "VLAN adoption requires native host mode"
        );
        ensure!(
            !self.state.join("intent.json").try_exists()?,
            "native recovery is pending"
        );
        self.verify(&before.operational_value()?)?;
        let ownership = self.ownership()?;
        ensure!(
            !ownership.managed_interfaces.contains(&request.name),
            "VLAN already owned"
        );
        let scope = self.identity.clone();
        let saved = serde_json::to_value(&ownership)?;
        let wanted = request.clone();
        let ipv6_enabled = before.ipv6_enabled;
        let captured = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(adoption::capture_vlan(
                handle,
                scope,
                saved,
                &wanted,
                ipv6_enabled,
            ))
        })?;
        let mut config = before.clone();
        let mut link = captured
            .config
            .interfaces
            .first()
            .context("VLAN capture missing")?
            .clone();
        link.kind = "vlan".into();
        link.vlan = Some(netcontrol_core::VLAN {
            parent: request.parent.clone(),
            id: i64::from(request.id),
        });
        config.interfaces.push(link);
        config.routes.extend(captured.config.routes.clone());
        config.dns.extend(captured.config.dns.clone());
        config = config.normalized();
        config.validate()?;
        self.preflight(&config.operational_value()?)?;
        self.services.validate(&config.operational_value()?)?;
        Ok(netcontrol_core::VlanAdoption {
            config,
            receipt: serde_json::json!({"request":request,"capture":captured}),
        })
    }

    fn finish_vlan_adoption(
        &mut self,
        before: &Config,
        imported: &netcontrol_core::VlanAdoption,
    ) -> Result<()> {
        self.path_test.ensure_idle()?;
        self.check_scope()?;
        ensure!(
            self.options.namespace.is_empty(),
            "VLAN adoption requires native host mode"
        );
        ensure!(
            !self.state.join("intent.json").try_exists()?,
            "native recovery is pending"
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Capture {
            request: netcontrol_core::AdoptVlanRequest,
            capture: adoption::Receipt,
        }
        let token: Capture = serde_json::from_value(imported.receipt.clone())?;
        let receipt = token.capture;
        ensure!(
            receipt.scope == self.identity,
            "VLAN adoption belongs to another scope"
        );
        let previous: Ownership = serde_json::from_value(receipt.ownership_before.clone())?;
        let before_value = before.operational_value()?;
        let after_value = imported.config.operational_value()?;
        ensure!(
            previous.committed_config.as_ref() == Some(&before_value),
            "VLAN adoption baseline ownership mismatch"
        );
        let actual = self.ownership()?;
        adoption::check_vlan_source(&receipt)?;
        let wanted = token.request.clone();
        let originals = receipt.originals.clone();
        session(self.namespace.clone(), move |rt, handle| {
            let expected = originals
                .get(&wanted.name)
                .context("VLAN snapshot missing")?;
            rt.block_on(networking::check_vlan_identity(handle, &wanted, expected))
        })?;
        let already_owned = actual.committed_config.as_ref() == Some(&after_value);
        if !already_owned {
            ensure!(
                serde_json::to_value(&actual)? == serde_json::to_value(&previous)?,
                "VLAN adoption ownership changed"
            );
        }
        self.dhcp
            .configure(&before_value)
            .context("restore committed DHCP runtime before VLAN adoption verification")?;
        self.verify(&before_value)?;
        let result = (|| -> Result<()> {
            // An interrupted rollback can release networkd before restoring ownership.json.
            self.take_ownership(&receipt.originals)?;
            let captured = receipt.clone();
            let wanted = token.request.clone();
            session(self.namespace.clone(), move |rt, handle| {
                let expected = captured
                    .originals
                    .get(&wanted.name)
                    .context("VLAN snapshot missing")?;
                rt.block_on(networking::check_vlan_identity(handle, &wanted, expected))?;
                rt.block_on(adoption::transfer_routes(handle, &captured, false))
            })?;
            let snapshot = receipt
                .originals
                .get(&token.request.name)
                .context("VLAN snapshot missing")?;
            adoption::set_dns(
                snapshot.index,
                &receipt
                    .config
                    .dns
                    .get(&token.request.name)
                    .cloned()
                    .unwrap_or_default(),
                None,
            )?;
            self.services.apply(&before_value, &after_value)?;
            let mut ownership = previous.clone();
            ownership
                .managed_interfaces
                .insert(token.request.name.clone());
            ownership.vlan_originals.extend(receipt.originals.clone());
            ownership.committed_config = Some(after_value.clone());
            self.save_ownership(&ownership)?;
            self.verify(&after_value)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.services
                .apply(&after_value, &before_value)
                .context("VLAN service recovery failed; core adoption intent retained")?;
            let captured = receipt.clone();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::restore_ethernet(handle, &captured.originals))?;
                rt.block_on(adoption::transfer_routes(handle, &captured, true))
            })
            .context("VLAN route recovery failed; core adoption intent retained")?;
            adoption::check_vlan_source(&receipt)?;
            adoption::release(&receipt)
                .context("VLAN networkd recovery failed; core intent retained")?;
            let originals = receipt.originals.clone();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::restore_ethernet(handle, &originals))
            })
            .context("VLAN live configuration recovery failed; core intent retained")?;
            self.save_ownership(&previous)?;
            return Err(error.context("VLAN adoption failed; original ownership restored, retry requires unchanged capture"));
        }
        Ok(())
    }

    fn path_test_active(&self) -> bool {
        self.path_test.active()
    }

    fn start_path_test(
        &mut self,
        config: &Config,
        request: netcontrol_core::PathTestRequest,
    ) -> Result<Value> {
        self.check_scope()?;
        self.path_test.ensure_idle()?;
        ensure!(
            config.ipv6_enabled || request.source_address.is_ipv4(),
            "IPv6 path tests require IPv6 enabled in the committed configuration"
        );
        ensure!(
            !self.state.join("intent.json").try_exists()?,
            "native recovery is pending"
        );
        self.verify(&config.operational_value()?)?;
        // These workers change the chosen path asynchronously. Never stop unrelated
        // services or pretend that a changing route is a verified test path.
        path_test::validate_dhcp_path(config, &request)?;
        ensure!(
            !config.bgp.enabled,
            "path tests require a stable path: BGP is active"
        );
        let value = config.operational_value()?;
        path_test::validate_dynamic_dns_path(self.namespace.clone(), &request, &value)?;
        self.path_test
            .start(request, self.ownership()?.firewall_fingerprint)
    }

    fn path_test_status(&mut self) -> Result<Value> {
        self.path_test.status()
    }

    fn cancel_path_test(&mut self, id: &str) -> Result<Value> {
        self.path_test.cancel(id)
    }

    fn shutdown_path_test(&mut self) -> Result<()> {
        self.path_test.shutdown()
    }
    fn deny_log(&mut self, query: &netcontrol_core::DenyLogQuery) -> Result<Value> {
        self.check_scope()?;
        self.deny_log.snapshot(query)
    }
    fn first_firewall_drops(
        &mut self,
        config: &netcontrol_core::DiscordConfig,
    ) -> Result<Vec<netcontrol_core::DenyRecord>> {
        self.check_scope()?;
        self.deny_log.first_drops(config)
    }
    fn bgp_status(&mut self, _: &Config) -> Result<Value> {
        self.check_scope()?;
        let mut value = self.bgp.snapshot()?;
        value["scope"] = json!(self.identity);
        Ok(value)
    }
    fn prepare_dns_lookup(
        &mut self,
        config: &Config,
        request: &netcontrol_core::DNSLookupRequest,
    ) -> Result<netcontrol_core::DNSLookup> {
        self.check_scope()?;
        if let Some(interface) = request.interface.as_deref() {
            ensure!(
                config
                    .interfaces
                    .iter()
                    .any(|link| link.name == interface && link.up),
                "DNS lookup requires a configured up interface"
            );
        }
        let servers = if let Some(server) = request.server {
            ensure!(
                config.ipv6_enabled || server.is_ipv4(),
                "IPv6 DNS server requires global IPv6 to be enabled"
            );
            vec![server]
        } else {
            let interface = request
                .interface
                .as_deref()
                .ok_or_else(|| anyhow!("server is required when interface is omitted"))?;
            let state = self
                .dhcp
                .state
                .lock()
                .map_err(|_| anyhow!("DHCP state poisoned"))?;
            let configured = config.dns.get(interface).cloned().unwrap_or_default();
            let lease = state.leases.get(interface).filter(|lease| {
                lease.valid() && config.dhcp_clients.get(interface) == Some(&lease.client)
            });
            adoption::dns_addresses(&configured, lease.map_or(&[], |lease| lease.dns.as_slice()))?
                .into_iter()
                .filter(|ip| config.ipv6_enabled || ip.is_ipv4())
                .collect::<Vec<_>>()
        };
        ensure!(
            !servers.is_empty() && servers.len() <= 16,
            "selected interface requires 1..16 effective configured DNS servers"
        );
        let namespace = self.namespace.clone();
        let request = request.clone();
        let scope = self.identity.clone();
        Ok(Box::new(move || {
            session(namespace, move |_, _| {
                let mut value = netcontrol_services::dns_lookup(&request, &servers)?;
                value["scope"] = json!(scope);
                Ok(value)
            })
        }))
    }
    fn restart_process(&mut self, config: &Config, target: &str) -> Result<Value> {
        self.path_test.ensure_idle()?;
        self.check_scope()?;
        let value = config.operational_value()?;
        if let Some(interface) = target.strip_prefix("dhcp-client:") {
            self.dhcp.retry(&value, interface)?;
            return Ok(json!({"state":"restart_requested","interface":interface}));
        }
        if target == "dhcp-gateway-monitors" {
            self.dhcp_monitors.configure(&value)?;
            return self.gateway_statistics("/api/v1/statistics/gateways");
        }
        if target == "link-diagnostics" {
            self.link_monitor.restart(self.namespace.clone())?;
            return self.link_monitor.snapshot();
        }
        if target == "bgp" {
            return self.bgp.restart();
        }
        self.services.restart_worker(target)
    }
    fn initial_configuration(&mut self) -> Result<Config> {
        self.path_test.ensure_idle()?;
        if !self.options.namespace.is_empty() {
            return Ok(Config::empty());
        }
        let path = self.state.join("adoption.json");
        let mut receipt: adoption::Receipt = if path.try_exists()? {
            let receipt: adoption::Receipt = read_json(&path)?;
            ensure!(
                receipt.scope == self.identity,
                "adoption belongs to another host"
            );
            ensure!(
                !receipt.complete,
                "completed native adoption exists without its core journal; restore the journal instead of reusing the original baseline"
            );
            receipt
        } else {
            let ownership = self.ownership()?;
            ensure!(
                ownership.managed_interfaces.is_empty(),
                "managed native state exists without an initial core journal; refusing recapture"
            );
            ensure!(
                ownership
                    .committed_config
                    .as_ref()
                    .is_none_or(|value| Config::empty()
                        .operational_value()
                        .is_ok_and(|empty| *value == empty)),
                "configured native state exists without its initial core journal; state is not reset"
            );
            let scope = self.identity.clone();
            let previous = serde_json::to_value(&ownership)?;
            let readonly = self.parents.keys().cloned().collect();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(adoption::capture(handle, scope, previous, readonly))
            })?
        };
        let captured = self.capture_conntrack_tunables(&receipt.config.kernel)?;
        receipt.config.kernel.host.extend(captured.host);
        receipt.config.kernel.namespace.extend(captured.namespace);
        receipt.config.validate()?;
        write_json(&path, &receipt)?;
        ensure!(
            receipt.ipv6_before.is_some(),
            "initial physical takeover requires its captured IPv6 rollback snapshot"
        );
        receipt
            .config
            .validate()
            .context("invalid inherited baseline")?;
        if receipt.takeover.is_some() {
            let result = (|| -> Result<()> {
                let originals = receipt.managed_originals()?;
                let captured = originals.clone();
                session(self.namespace.clone(), move |rt, handle| {
                    rt.block_on(networking::check_ethernet(handle, &captured))
                })?;
                self.enforce_host_takeover(
                    &Network::parse(&receipt.config.operational_value()?)?,
                    self.ownership()?.firewall_fingerprint.is_some(),
                )?;
                session(self.namespace.clone(), move |rt, handle| {
                    rt.block_on(networking::restore_interfaces(handle, &originals))
                })?;
                let mut ownership = self.ownership()?;
                ownership.scope = self.identity.clone();
                ownership.ethernet_originals = receipt.managed_originals()?;
                ownership.managed_interfaces = receipt
                    .config
                    .interfaces
                    .iter()
                    .map(|link| link.name.clone())
                    .collect();
                ownership.committed_config = Some(receipt.config.operational_value()?);
                ownership.kernel_baseline.capture_originals(
                    &Network::parse(&receipt.config.operational_value()?)?.kernel,
                );
                ownership.boot = self.boot.clone();
                self.save_ownership(&ownership)?;
                Ok(())
            })();
            if let Err(error) = result {
                let mut failed: adoption::Receipt = read_json(&path)?;
                let plan = failed
                    .takeover
                    .as_mut()
                    .context("host takeover plan missing")?;
                plan.phase = "failed".into();
                plan.error = format!("{error:#}");
                write_json(&path, &failed)?;
                return Err(
                    error.context("console takeover incomplete; capture retained for retry")
                );
            }
            return Ok(receipt.config);
        }
        ensure!(
            receipt.config.interfaces.len() == receipt.originals.len()
                && receipt.config.interfaces.iter().all(|link| receipt
                    .originals
                    .get(&link.name)
                    .is_some_and(|snapshot| snapshot.name == link.name)),
            "inherited interface snapshot identities do not match the baseline"
        );
        let managed_originals = receipt.managed_originals()?;
        let result = (|| -> Result<()> {
            self.take_ownership(&managed_originals)?;
            let captured = receipt.clone();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(adoption::transfer_routes(handle, &captured, false))
            })?;
            for (name, lease) in &receipt.leases {
                write_json(&self.state.join(format!("dhcp-{name}.json")), lease)?;
            }
            let mut ownership = self.ownership()?;
            ownership.scope = self.identity.clone();
            ownership.ethernet_originals = managed_originals;
            ownership.managed_interfaces = receipt.originals.keys().cloned().collect();
            ownership.committed_config = Some(receipt.config.operational_value()?);
            ownership
                .kernel_baseline
                .capture_originals(&Network::parse(&receipt.config.operational_value()?)?.kernel);
            ownership.boot = self.boot.clone();
            self.save_ownership(&ownership)?;
            self.dhcp.configure(&receipt.config.operational_value()?)?;
            let network = Network::parse(&receipt.config.operational_value()?)?;
            let leases = self
                .dhcp
                .state
                .lock()
                .map_err(|_| anyhow!("DHCP state poisoned"))?;
            let lease_state = leases.clone();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::configure_dns(handle, &network, &lease_state))
            })?;
            Ok(())
        })();
        if let Err(error) = result {
            self.dhcp.shutdown()?;
            let captured = receipt.clone();
            session(self.namespace.clone(), move |rt, handle| {
                if let Some(snapshot) = &captured.ipv6_before {
                    ipv6::restore_controls(snapshot)?;
                    rt.block_on(ipv6::restore_network(handle, snapshot))?;
                }
                rt.block_on(networking::restore_ethernet(handle, &captured.originals))?;
                rt.block_on(adoption::transfer_routes(handle, &captured, true))
            })
            .context("adoption recovery failed; durable receipt retained")?;
            adoption::release(&receipt)
                .context("networkd ownership recovery failed; receipt retained")?;
            self.save_ownership(&serde_json::from_value(receipt.ownership_before)?)?;
            remove_durable(&path)?;
            return Err(
                error.context("physical interface inheritance failed; networkd ownership restored")
            );
        }
        Ok(receipt.config)
    }

    fn discover_interfaces(&mut self) -> Result<Value> {
        self.check_scope()?;
        let managed = self.ownership()?.managed_interfaces;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::discover(handle, &managed))
        })
    }
    fn discover_interface_capabilities(&mut self) -> Result<netcontrol_core::InterfaceInventory> {
        self.check_scope()?;
        let host_mode = self.options.namespace.is_empty();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(capabilities::discover(handle, host_mode))
        })
    }
    fn capture_conntrack_tunables(
        &mut self,
        configured: &netcontrol_core::KernelConfig,
    ) -> Result<netcontrol_core::KernelConfig> {
        self.check_scope()?;
        self.path_test.ensure_idle()?;
        ensure!(
            self.options.namespace.is_empty(),
            "automatic conntrack ownership requires native host mode"
        );
        let configured = configured.clone();
        session(self.namespace.clone(), move |_, _| {
            sysctl::capture_conntrack_tunables(&configured)
        })
    }

    fn scope(&self) -> Result<String> {
        self.check_scope()?;
        Ok(self.identity.clone())
    }

    fn observe(&mut self, expected: &Config) -> Result<Config> {
        self.path_test.ensure_idle()?;
        let config = expected.operational_value()?;
        self.verify(&config)?;
        self.verify_services(&config)?;
        Ok(expected.clone())
    }

    fn observe_for_repair(&mut self, expected: &Config) -> Result<Config> {
        self.path_test.ensure_idle()?;
        self.verify(&expected.operational_value()?)?;
        Ok(expected.clone())
    }

    fn configure_reporting_identity(
        &mut self,
        system: &netcontrol_core::SystemConfig,
    ) -> Result<()> {
        self.path_test.ensure_idle()?;
        self.services.configure_reporting_identity(system)
    }

    fn apply(&mut self, before: &Config, after: &Config) -> Result<()> {
        self.path_test.ensure_idle()?;
        let alias_config = after;
        (|| -> Result<()> {
            self.recover()?;
            let before = before.operational_value()?;
            let after = after.operational_value()?;
            self.services.validate(&after)?;
            self.preflight(&after)?;
            let mut ownership = self.ownership()?;
            if self.options.namespace.is_empty()
                && !ownership.boot.is_empty()
                && ownership.boot != self.boot
            {
                return self.reconcile_after_boot(&after, ownership, Some(&before));
            }
            if let Err(drift) = self.verify(&before) {
                let after_names: BTreeSet<_> = Network::parse(&after)?
                    .interfaces
                    .into_iter()
                    .map(|l| l.name)
                    .collect();
                let recorded_target = ownership.committed_config.as_ref() == Some(&after)
                    || (ownership.committed_config.is_none()
                        && after == Config::empty().operational_value()?);
                if recorded_target && ownership.managed_interfaces == after_names {
                    match self.verify(&after) {
                        Ok(()) => {
                            self.repair_services(&after)?;
                            return Ok(());
                        }
                        Err(error)
                            if self.options.namespace.is_empty()
                                && error
                                    .downcast_ref::<netcontrol_core::BackendDrift>()
                                    .is_some() =>
                        {
                            return self.reconcile_after_boot(&after, ownership, None);
                        }
                        Err(_) => {}
                    }
                }
                return Err(drift
                    .context("native drift guard: committed configuration differs from kernel"));
            }
            if before == after && ownership.committed_config.is_some() {
                let mode = serde_json::from_value::<Config>(after.clone())?
                    .firewall
                    .rpf_mode;
                session(self.namespace.clone(), move |_, _| rpf::set(mode))?;
                self.verify_services(&after)?;
                return Ok(());
            }
            let before_network = Network::parse(&before)?;
            let after_network = Network::parse(&after)?;
            let ethernet_before = session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::preflight(
                    handle,
                    &before_network,
                    &after_network,
                ))?;
                rt.block_on(networking::capture_ethernet(
                    handle,
                    &before_network,
                    &after_network,
                ))
            })?;
            let captured = self.capture_kernel(&before, &after)?;
            let previous_ownership = ownership.clone();
            for (name, snapshot) in &ethernet_before {
                ownership
                    .ethernet_originals
                    .entry(name.clone())
                    .or_insert_with(|| snapshot.clone());
            }
            ownership.kernel_baseline.capture_originals(&captured);
            let mut kernel_target = ownership.kernel_baseline.clone();
            kernel_target.overlay(&Network::parse(&after)?.kernel);
            let intent = Intent {
                scope: self.identity.clone(),
                before: before.clone(),
                after: after.clone(),
                kernel_before: captured.clone(),
                ownership_before: previous_ownership,
                ethernet_before,
                ethernet_originals: ownership.ethernet_originals.clone(),
                ipv6_before: self.capture_ipv6(&before)?,
            };
            write_json(&self.state.join("intent.json"), &intent)?;
            // Stop services before interface changes; their manager must restore prior workers on failure.
            let operation = (|| -> Result<()> {
                self.stop_services()?;
                self.activate_ethernet(
                    &after,
                    &ownership.ethernet_originals,
                    &intent.ethernet_before,
                )?;
                self.dhcp
                    .configure(&after)
                    .context("configure DHCP clients during native apply")?;
                self.network_apply(&before, &after, kernel_target, &mut ownership)?;
                ownership.firewall_config = Some(Network::parse(&after)?.firewall);
                ownership.managed_interfaces = Network::parse(&after)?
                    .interfaces
                    .iter()
                    .map(|l| l.name.clone())
                    .collect();
                ownership
                    .ethernet_originals
                    .retain(|name, _| ownership.managed_interfaces.contains(name));
                ownership
                    .vlan_originals
                    .retain(|name, _| ownership.managed_interfaces.contains(name));
                ownership.committed_config = Some(after.clone());
                ownership
                    .kernel_baseline
                    .release_tuning(&Network::parse(&after)?.kernel);
                ownership.boot = self.boot.clone();
                self.services.apply(&before, &after)?;
                self.dhcp_monitors.configure(&after)?;
                self.bgp.configure(&after)?;
                self.wireguard_dns.configure(&after)?;
                self.log("native networking and services converged")?;
                self.save_ownership(&ownership)?;
                remove_durable(&self.state.join("intent.json"))
            })();
            if let Err(error) = operation {
                return match self.recover() {
                    Ok(()) => {
                        Err(error.context("native apply failed; previous configuration restored"))
                    }
                    Err(rollback) => Err(anyhow!(
                        "native apply failed: {error:#}; rollback incomplete: {rollback:#}; durable recovery intent retained"
                    )),
                };
            }
            Ok(())
        })()?;
        self.reconcile_interface_aliases(alias_config)
    }

    fn retry_dhcp(&mut self, config: &Config, interface: &str) -> Result<()> {
        self.path_test.ensure_idle()?;
        self.check_scope()?;
        let value = config.operational_value()?;
        let ownership = self.ownership()?;
        crate::ensure_unchanged(
            !self.state.join("intent.json").try_exists()?
                && ownership.committed_config.as_ref() == Some(&value)
                && ownership.managed_interfaces.contains(interface),
            "DHCP retry requires committed native ownership with no pending recovery intent",
        )?;
        let originals = ownership
            .ethernet_originals
            .into_iter()
            .filter(|(name, _)| name == interface)
            .collect();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))
        })?;
        self.dhcp.retry(&value, interface)
    }

    fn factory_reset(&mut self, before: &Config, after: &Config) -> Result<()> {
        self.path_test.ensure_idle()?;
        ensure!(
            self.options.namespace.is_empty(),
            "factory reset requires host mode"
        );
        self.recover()?;
        let alias_config = after;
        let before = before.operational_value()?;
        let after = after.operational_value()?;
        self.reconcile_after_boot(&after, self.ownership()?, Some(&before))?;
        self.reconcile_interface_aliases(alias_config)
    }

    fn mdns_status(&mut self, _config: &Config) -> Result<Value> {
        let status = self.services.status();
        Ok(json!({"instances":status["appliance_services"].as_array()
            .context("native service statuses missing")?.iter()
            .filter(|row|row["name"]=="mdns").collect::<Vec<_>>(),
            "error":status.get("error").cloned().unwrap_or(json!(""))}))
    }

    fn runtime(&mut self, config: &Config) -> Result<Value> {
        self.check_scope()?;
        let parents = self.parents.clone();
        let parent_status = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::parent_status(handle, &parents))
        })?;
        let mut value = self.services.status();
        let mut bgp = self.bgp.snapshot()?;
        let summary = bgp.as_object_mut().context("BGP status missing")?;
        summary.remove("routes");
        summary.remove("advertised_routes");
        value["appliance_services"]
            .as_array_mut()
            .context("service status missing")?
            .push(bgp.clone());
        value["bgp"] = bgp;
        self.dhcp_monitors.merge(&mut value["gateway_monitors"])?;
        if !value.is_object() {
            value = json!({"services":value});
        }
        value["parents"] = parent_status;
        value["dhcp_clients"] = self.dhcp.status()?;
        value["scope"] = json!(self.identity);
        let adoption = self.state.join("adoption.json");
        value["host_takeover"] = if adoption.try_exists()? {
            let receipt: adoption::Receipt = read_json(&adoption)?;
            receipt
                .takeover
                .as_ref()
                .map(takeover::Plan::report)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        value["wireguard_dns"] = self.wireguard_dns.snapshot()?;
        let enabled = config.ipv6_enabled;
        value["ipv6"] = session(self.namespace.clone(), move |_, _| ipv6::status(enabled))?;
        let mode = config.firewall.rpf_mode;
        value["rpf"] = session(self.namespace.clone(), move |_, _| rpf::status(mode))?;
        value["kernel_panic"] = match &self.panic_reboot {
            Some(guard) => guard.status()?,
            None => Value::Null,
        };
        let desired = Network::parse(&config.operational_value()?)?.kernel;
        let baseline = self.ownership()?.kernel_baseline;
        let mut effective = baseline.clone();
        effective.overlay(&desired);
        let observed = self.read_kernel(&effective)?;
        value["kernel_tunables"] = json!({"desired":desired,"configured":desired,"effective":effective,"observed":observed,"captured_original":baseline,"drift":!effective.same_values(&observed)});
        let names: Vec<_> = Network::parse(&config.operational_value()?)?
            .interfaces
            .into_iter()
            .filter(|l| l.kind == "wireguard")
            .map(|l| l.name)
            .collect();
        value["wireguard"] = session(self.namespace.clone(), move |_, _| {
            Ok(json!(
                names
                    .iter()
                    .map(|name| wireguard::runtime(name))
                    .collect::<Result<Vec<_>>>()?
            ))
        })?;
        value["path_test"] = self.path_test.status()?;
        Ok(value)
    }

    fn delete_connections(
        &mut self,
        target: Option<(u32, &netcontrol_core::ConnectionTarget)>,
    ) -> Result<Value> {
        self.path_test.ensure_idle()?;
        self.check_scope()?;
        let target = target.map(|(id, target)| (id, target.clone()));
        let single = target.is_some();
        session(self.namespace.clone(), move |_, _| {
            netfilter::delete_connections(target.as_ref().map(|(id, target)| (*id, target)))
        })?;
        Ok(json!({"status":if single {"deleted"} else {"flushed"},"scope":self.identity}))
    }

    fn statistics(&mut self, config: &Config, path: &str, query: &str) -> Result<Value> {
        if path == "/api/v1/statistics/connections" {
            let query = netcontrol_core::ConnectionQuery::parse(query)?;
            self.check_scope()?;
            let started_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)?;
            let mut response = session(self.namespace.clone(), move |_, _| {
                crate::conntrack::snapshot(&netfilter::connections()?, &query)
            })?;
            let collected_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)?;
            let status = if response["summary"]["accounting_unavailable"]
                .as_u64()
                .unwrap_or(0)
                > 0
            {
                "partial"
            } else {
                "available"
            };
            response["sample"] = json!({"scope":self.identity,"started_at":started_at,"collected_at":collected_at,"status":status});
            return Ok(response);
        }
        ensure!(
            query.is_empty(),
            "statistics endpoints do not accept query parameters"
        );
        if path == "/api/v1/statistics/performance" {
            return self.performance_snapshot(config);
        }
        if path == "/api/v1/statistics/host" {
            return crate::host_health::snapshot();
        }
        self.check_scope()?;
        if path == "/api/v1/statistics/firewall" {
            self.path_test.ensure_idle().context(
                "firewall counters are temporarily unavailable during owned path-test leases",
            )?;
            let started_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)?;
            let ownership = self.ownership()?;
            let fingerprint = ownership
                .firewall_fingerprint
                .context("firewall counters unavailable; no owned firewall is installed")?;
            let network = Network::parse(&config.operational_value()?)?;
            let mut response = session(self.namespace.clone(), move |_, _| {
                firewall::counters(
                    &network.firewall,
                    &network.interfaces,
                    &ownership.firewall_config,
                    &fingerprint,
                )
            })?;
            response["sample"] = json!({
                "scope":self.identity, "started_at":started_at,
                "collected_at":time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)?,
                "status":"available"
            });
            return Ok(response);
        }
        if path == "/api/v1/statistics/link-diagnostics" {
            let mut value = self.link_monitor.snapshot()?;
            value["scope"] = json!(self.identity);
            return Ok(value);
        }
        if path == "/api/v1/statistics/gateways" || path.starts_with("/api/v1/statistics/gateways/")
        {
            return crate::statistics::service_response(
                path,
                self.gateway_statistics(path)?,
                &self.identity,
            );
        }
        if !matches!(
            path,
            "/api/v1/statistics" | "/api/v1/statistics/interfaces" | "/api/v1/statistics/protocols"
        ) && !path.starts_with("/api/v1/statistics/interfaces/")
        {
            return crate::statistics::service_response(
                path,
                self.services.statistics(path, query)?,
                &self.identity,
            );
        }
        let config = config.operational_value()?;
        let parents = self.parents.clone();
        let path = path.to_string();
        let query = query.to_string();
        let scope = self.identity.clone();
        let all = path == "/api/v1/statistics";
        let mut value = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::statistics(
                handle, &config, &parents, &scope, &path, &query,
            ))
        })?;
        if all {
            let mut bgp = self.bgp.snapshot()?;
            let summary = bgp.as_object_mut().context("BGP status missing")?;
            summary.remove("routes");
            summary.remove("advertised_routes");
            value["bgp"] = bgp;
            let mut diagnostics = self.link_monitor.snapshot()?;
            diagnostics["scope"] = json!(self.identity);
            value["link_diagnostics"] = diagnostics;
            let gateways = self.gateway_statistics("/api/v1/statistics/gateways")?;
            value["gateways"] = gateways["gateways"].clone();
            if gateways["sample"]["status"] == "partial" {
                value["sample"]["status"] = json!("partial");
            }
            crate::host_health::add_uptime(&mut value)?;
        }
        Ok(value)
    }

    fn repair(&mut self, config: &Config) -> Result<Value> {
        self.path_test.ensure_idle()?;
        self.recover()?;
        let value = config.operational_value()?;
        let originals = self.ownership()?.ethernet_originals;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))
        })?;
        self.dhcp_monitors.shutdown()?;
        let ownership = self.ownership()?;
        let boot_changed = self.options.namespace.is_empty()
            && !ownership.boot.is_empty()
            && ownership.boot != self.boot;
        let down_ethernet = if self.options.namespace.is_empty()
            && ownership.committed_config.as_ref() == Some(&value)
        {
            let network = Network::parse(&value)?;
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::needs_ethernet_activation(handle, &network))
            })
            .context("inspect configured Ethernet link state")?
        } else {
            false
        };
        if boot_changed || down_ethernet {
            self.reconcile_after_boot(&value, ownership, None)?;
        } else {
            self.dhcp
                .configure(&value)
                .context("configure DHCP clients during startup")?;
        }
        self.preflight(&value)?;
        if let Err(error) = self.verify(&value) {
            if self.options.namespace.is_empty()
                && error
                    .downcast_ref::<netcontrol_core::BackendDrift>()
                    .is_some()
            {
                self.reconcile_after_boot(&value, self.ownership()?, None)?;
                self.verify(&value)?;
            } else {
                return Err(error);
            }
        }
        // Refresh the verified firewall through a recovery intent so startup installs
        // the current compiler's telemetry without changing configuration revisions.
        let mut ownership = self.ownership()?;
        if ownership.committed_config.is_none() {
            self.apply(config, config)?;
            ownership = self.ownership()?;
        }
        {
            let network = Network::parse(&value)?;
            let logging = crate::firewall_plan::drop_logging_enabled(&network.firewall)?;
            if logging {
                self.deny_log.configure(true)?;
            }
            let captured = self.capture_kernel(&value, &value)?;
            let ethernet_before = self.capture_ethernet(&value, &value)?;
            let intent = Intent {
                scope: self.identity.clone(),
                before: value.clone(),
                after: value.clone(),
                kernel_before: captured.clone(),
                ownership_before: ownership.clone(),
                ethernet_before,
                ethernet_originals: ownership.ethernet_originals.clone(),
                ipv6_before: self.capture_ipv6(&value)?,
            };
            write_json(&self.state.join("intent.json"), &intent)?;
            if ownership.firewall_fingerprint.is_none() {
                self.network_apply(&value, &value, captured, &mut ownership)
                    .context(
                        "initial firewall bootstrap failed; scoped recovery intent retained",
                    )?;
            } else {
                let target = network.clone();
                ownership.firewall_fingerprint = Some(
                    session(self.namespace.clone(), move |_, _| {
                        let mode = serde_json::from_value::<netcontrol_core::Firewall>(
                            target.firewall.clone(),
                        )?
                        .rpf_mode;
                        rpf::set(mode)?;
                        firewall::apply(&target.firewall, &target.interfaces)?;
                        netfilter::fingerprint()
                    })
                    .context("firewall compiler refresh failed; scoped recovery intent retained")?,
                );
            }
            ownership.scope = self.identity.clone();
            if !logging {
                self.deny_log.configure(false)?;
            }
            ownership.firewall_config = Some(network.firewall);
            self.save_ownership(&ownership)?;
            remove_durable(&self.state.join("intent.json"))?;
        }
        self.repair_services(&value)?;
        let adoption_path = self.state.join("adoption.json");
        if adoption_path.try_exists()? {
            let mut receipt: adoption::Receipt = read_json(&adoption_path)?;
            if !receipt.complete {
                receipt.complete = true;
                if let Some(plan) = &mut receipt.takeover {
                    plan.phase = "complete".into();
                    plan.error.clear();
                }
                write_json(&adoption_path, &receipt)?;
            }
        }
        self.reconcile_interface_aliases(config)?;
        Ok(self.services.status())
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        if let Err(error) = self.path_test.shutdown() {
            eprintln!("path-test cleanup failed; recovery intent retained: {error:#}");
        }
        if let Err(error) = self.wireguard_dns.shutdown() {
            eprintln!("WireGuard DNS shutdown failed: {error:#}");
        }
        if let Err(error) = self.deny_log.shutdown() {
            eprintln!("deny-log shutdown failed: {error:#}");
        }
        if let Err(error) = self.bgp.shutdown() {
            eprintln!("BGP shutdown failed: {error:#}");
        }
        let _ = self.dhcp_monitors.shutdown();
        let _ = self.dhcp.shutdown();
        let _ = self.services.shutdown();
    }
}

impl Native {
    fn log(&self, message: &str) -> Result<()> {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.options.services_state.join("backend.log"))?;
        let metadata = log.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o022 == 0,
            "untrusted backend log"
        );
        writeln!(
            log,
            "{}",
            json!({"source":"backend","component":"native","message":message})
        )?;
        Ok(())
    }
}

fn open_namespace(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open precreated namespace {}", path.display()))?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } == 0,
        "stat namespace: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        info.f_type == 0x6e736673,
        "namespace path is not an nsfs mount"
    );
    ensure!(
        unsafe { libc::ioctl(file.as_raw_fd(), 0xb703) } == libc::CLONE_NEWNET,
        "namespace handle is not a network namespace"
    );
    Ok(file)
}

fn same_file(a: &File, b: &File) -> Result<bool> {
    let a = a.metadata()?;
    let b = b.metadata()?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

pub(crate) fn session<T: Send + 'static>(
    target: Arc<File>,
    operation: impl FnOnce(&tokio::runtime::Runtime, &rtnetlink::Handle) -> Result<T> + Send + 'static,
) -> Result<T> {
    run_session(target, operation)
}

fn host_session<T: Send + 'static>(
    target: Arc<File>,
    operation: impl FnOnce(&tokio::runtime::Runtime, &rtnetlink::Handle) -> Result<T> + Send + 'static,
) -> Result<T> {
    run_session(target, operation)
}

fn run_session<T: Send + 'static>(
    target: Arc<File>,
    operation: impl FnOnce(&tokio::runtime::Runtime, &rtnetlink::Handle) -> Result<T> + Send + 'static,
) -> Result<T> {
    std::thread::spawn(move || {
        let original = File::open("/proc/thread-self/ns/net")?;
        let switched = !same_file(&target, &original)?;
        ensure!(
            !switched || unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } == 0,
            "enter namespace: {}",
            std::io::Error::last_os_error()
        );
        let result = (|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let _entered = runtime.enter();
            let (connection, handle, _) = rtnetlink::new_connection()?;
            let task = runtime.spawn(connection);
            let result = operation(&runtime, &handle);
            task.abort();
            result
        })();
        let restored = if switched {
            unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) }
        } else {
            0
        };
        ensure!(
            restored == 0,
            "restore worker namespace failed: {}",
            std::io::Error::last_os_error()
        );
        result
    })
    .join()
    .map_err(|_| anyhow!("native namespace worker panicked"))?
}

fn trusted_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "native state directory must be owned by this user, non-symlink and private (0700)"
    );
    Ok(())
}

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= MAX_STATE_BYTES as u64,
        "untrusted native state file"
    );
    serde_json::from_reader(file).context("decode native state")
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let encoded = serde_json::to_vec(value)?;
    ensure!(
        encoded.len() <= MAX_STATE_BYTES,
        "native state exceeds 16 MiB recovery limit"
    );
    let pending = path.with_extension("writing");
    // A crash before rename can leave this non-authoritative staging file behind.
    if pending.try_exists()? {
        let metadata = fs::symlink_metadata(&pending)?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "untrusted stale native staging file"
        );
        fs::remove_file(&pending)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)?;
    let result = (|| {
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&pending, path)?;
        File::open(path.parent().context("state parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

fn remove_durable(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    File::open(path.parent().context("state parent")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn boot_rollback_excludes_only_uncommitted_dhcp_routes() -> Result<()> {
        let committed_dhcp = Route {
            destination: "203.0.113.0/24".into(),
            gateway: "192.0.2.1".into(),
            interface: "wan0".into(),
            table: 254,
            metric: 10,
        };
        let mut pending = committed_dhcp.clone();
        pending.gateway = "192.0.2.2".into();
        let static_route = Route {
            destination: "198.51.100.0/24".into(),
            gateway: String::new(),
            interface: "lan0".into(),
            table: 254,
            metric: 20,
        };
        let mut snapshot = serde_json::to_value(Config::empty())?;
        snapshot["routes"] = serde_json::to_value([pending, static_route.clone()])?;
        retain_committed_boot_routes(&mut snapshot, &[committed_dhcp, static_route.clone()])?;
        assert_eq!(Network::parse(&snapshot)?.routes, vec![static_route]);
        Ok(())
    }

    #[test]
    fn oversized_feature_snapshots_cannot_replace_readable_recovery_state() -> Result<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "netcontrol-state-size-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        let path = root.join("state.json");
        write_json(&path, &"original")?;
        let before = fs::read(&path)?;
        assert!(write_json(&path, &"x".repeat(MAX_STATE_BYTES)).is_err());
        assert_eq!(fs::read(&path)?, before);
        assert!(!path.with_extension("writing").exists());
        let boundary = "x".repeat(MAX_STATE_BYTES - 2);
        write_json(&path, &boundary)?;
        assert_eq!(fs::metadata(&path)?.len(), MAX_STATE_BYTES as u64);
        assert_eq!(read_json::<String>(&path)?, boundary);
        fs::remove_file(path)?;
        fs::remove_dir(root)?;
        Ok(())
    }

    fn inherited_ownership() -> Ownership {
        let mut ownership = Ownership::default();
        for name in ["owned0", "released0"] {
            ownership.ethernet_originals.insert(
                name.into(),
                EthernetSnapshot {
                    name: name.into(),
                    kind: "device".into(),
                    index: 2,
                    mac: "02:00:00:00:00:01".into(),
                    mtu: 1500,
                    up: true,
                    boot: "fixture".into(),
                    captured_unix: 0,
                    addresses: Vec::new(),
                },
            );
        }
        ownership.managed_interfaces.insert("owned0".into());
        ownership
    }

    #[test]
    fn interface_ownership_handover_restores_only_still_managed_interfaces() {
        let ownership = inherited_ownership();
        let selected = ownership.handover_originals(true);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected["owned0"], ownership.ethernet_originals["owned0"]);
        assert!(!selected.contains_key("released0"));
    }

    #[test]
    fn interface_ownership_handover_includes_non_inherited_physical_interfaces() {
        let ownership = inherited_ownership();
        assert!(ownership.handover_originals(false).is_empty());
        assert!(ownership.handover_originals(true).contains_key("owned0"));
    }

    #[test]
    fn interface_ownership_handover_does_not_discover_new_interfaces() {
        assert!(Ownership::default().handover_originals(true).is_empty());
    }
}
