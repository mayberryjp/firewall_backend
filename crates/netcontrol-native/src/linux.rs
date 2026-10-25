use crate::{
    NativeOptions,
    model::{EthernetSnapshot, Kernel, Network},
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
    pub fn validate(_: &Value) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn verify(_: &Value, _: &Option<Value>, _: Option<&str>) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn apply(_: &Value) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
    pub fn remove_owned(_: &str) -> Result<()> {
        bail!("native backend was built without nftables support")
    }
}
mod adoption;
mod dhcp_client;
#[cfg(all(test, feature = "nftables"))]
mod host_integration;
#[cfg(all(test, feature = "nftables"))]
mod integration;
mod ipv6;
mod netfilter;
mod networking;
mod sysctl;
mod wireguard;

pub use networking::Parent;

pub struct Native {
    options: NativeOptions,
    namespace: Arc<File>,
    namespace_path: PathBuf,
    identity: String,
    parents: BTreeMap<String, Parent>,
    services: Services,
    dhcp: dhcp_client::Manager,
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
    managed_interfaces: BTreeSet<String>,
    #[serde(default)]
    boot: String,
    #[serde(default)]
    committed_config: Option<Value>,
    #[serde(default)]
    ipv6_original: Option<ipv6::Snapshot>,
}

impl Ownership {
    fn handover_originals(
        &self,
        host_mode: bool,
        inherited: bool,
    ) -> BTreeMap<String, EthernetSnapshot> {
        if !host_mode || !inherited {
            return BTreeMap::new();
        }
        self.ethernet_originals
            .iter()
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
        let (host_namespace, host_lock) = if options.allow_host_tunables {
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
        let mut native = Self {
            dhcp: dhcp_client::Manager::new(namespace.clone(), state.clone(), host_mode),
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
        let ownership = native.ownership()?;
        ensure!(
            ownership.scope.is_empty() || ownership.scope == native.identity,
            "native ownership belongs to another host/namespace/parent identity; state is not reset"
        );
        ensure!(
            ownership.kernel_baseline.host.is_empty() || native.host_namespace.is_some(),
            "host tunable ownership requires explicit allow_host_tunables for recovery"
        );
        let originals = ownership.handover_originals(
            host_mode,
            host_mode && native.state.join("adoption.json").try_exists()?,
        );
        if !originals.is_empty() {
            let snapshots = originals.clone();
            session(native.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::check_ethernet(handle, &snapshots))
            })?;
            adoption::handover_interfaces(&originals)
                .context("restore managed-interface networkd handover before native recovery")?;
        }
        native.recover()?;
        Ok(native)
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

    fn ownership(&self) -> Result<Ownership> {
        let path = self.state.join("ownership.json");
        if !path.try_exists()? {
            return Ok(Ownership::default());
        }
        read_json(&path)
    }

    fn save_ownership(&self, state: &Ownership) -> Result<()> {
        write_json(&self.state.join("ownership.json"), state)
    }

    fn verify_services(&self, config: &Value) -> Result<()> {
        let status = self.services.status();
        let enabled = |v: &Value| v["enabled"].as_bool().unwrap_or(false);
        let running = |group: &str, key: &str, name: &str| -> Result<()> {
            let row = status[group]
                .as_array()
                .and_then(|rows| rows.iter().find(|r| r[key] == name))
                .with_context(|| format!("native service status missing {name}"))?;
            let state_key = if group == "gateway_monitors" {
                "process_state"
            } else {
                "state"
            };
            ensure!(
                row[state_key] == "running",
                "native service {name} is not healthy: {row}"
            );
            Ok(())
        };
        for (field, names) in [
            ("ntp", &["ntp"][..]),
            ("syslog", &["syslog"][..]),
            ("vnstat", &["vnstat-host", "vnstat-managed"][..]),
        ] {
            if enabled(&config[field]) {
                for name in names {
                    running("appliance_services", "name", name)?;
                }
            }
        }
        for link in config["interfaces"]
            .as_array()
            .context("interfaces missing")?
        {
            if enabled(&link["dhcp_relay"]) {
                running(
                    "dhcp_relay",
                    "interface",
                    link["name"].as_str().context("interface name")?,
                )?;
            }
        }
        for service in config["softflowd"]
            .as_array()
            .context("softflowd missing")?
        {
            if enabled(service) {
                running(
                    "softflowd",
                    "name",
                    service["name"].as_str().context("flow name")?,
                )?;
            }
        }
        for monitor in config["gateway_monitors"]
            .as_array()
            .context("gateway_monitors missing")?
        {
            if enabled(monitor) {
                running(
                    "gateway_monitors",
                    "name",
                    monitor["name"].as_str().context("gateway monitor name")?,
                )?;
            }
        }
        Ok(())
    }

    fn verify(&self, config: &Value) -> Result<()> {
        self.check_scope()?;
        let mut network = Network::parse(config)?;
        network.validate(&self.parents.keys().cloned().collect())?;
        let leases = self
            .dhcp
            .state
            .lock()
            .map_err(|_| anyhow!("DHCP state poisoned"))?;
        dhcp_client::effective(&mut network, &leases);
        firewall::validate(&network.firewall)?;
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
        effective.namespace.extend(network.kernel.namespace.clone());
        effective.host.extend(network.kernel.host.clone());
        self.verify_kernel(&effective)?;
        let keys = self.options.keys.clone();
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
            "host-global kernel tunables require explicit allow_host_tunables"
        );
        firewall::validate(&network.firewall)?;
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
        self.preflight_kernel(&network.kernel)?;
        let enabled = network.ipv6_enabled;
        session(self.namespace.clone(), move |_, _| ipv6::preflight(enabled))?;
        let parents = self.parents.clone();
        let keys = self.options.keys.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_parents(handle, &parents))?;
            for link in &network.interfaces {
                if let Some(wg) = &link.wireguard {
                    wireguard::validate(&keys, wg)?;
                }
            }
            Ok(())
        })
    }

    fn network_apply(
        &self,
        before: &Value,
        after: &Value,
        kernel: Kernel,
        ownership: &mut Ownership,
    ) -> Result<()> {
        self.check_scope()?;
        let mut before = Network::parse(before)?;
        let mut after = Network::parse(after)?;
        let leases = self
            .dhcp
            .state
            .lock()
            .map_err(|_| anyhow!("DHCP state poisoned"))?;
        dhcp_client::effective(&mut before, &leases);
        dhcp_client::effective(&mut after, &leases);
        let parents = self.parents.clone();
        let keys = self.options.keys.clone();
        let namespace_values = kernel.namespace.clone();
        let originals = ownership.ethernet_originals.clone();
        let lease_state = leases.clone();
        let host_dns = self.options.namespace.is_empty()
            && (!after.dns.is_empty()
                || !after.dhcp_clients.is_empty()
                || self.state.join("adoption.json").exists());
        let original_ipv6 = ownership.ipv6_original.clone();
        let (fingerprint, original_ipv6) = session(self.namespace.clone(), move |rt, handle| {
            let mut original_ipv6 = original_ipv6;
            if after.ipv6_enabled {
                ipv6::set(true)?;
                if let Some(snapshot) = original_ipv6.take() {
                    rt.block_on(ipv6::restore_network(handle, &snapshot.unmanaged(&after)?))?;
                }
            }
            rt.block_on(networking::reconcile(
                handle, &before, &after, &parents, &keys, &originals,
            ))?;
            if !after.ipv6_enabled {
                if original_ipv6.is_none() {
                    original_ipv6 = Some(rt.block_on(ipv6::capture(handle))?.unmanaged(&after)?);
                }
                ipv6::set(false)?;
            }
            sysctl::write_scope(&namespace_values, "namespace")?;
            firewall::apply(&after.firewall)?;
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
        ownership.ipv6_original = original_ipv6;
        if !kernel.host.is_empty() {
            let host = self
                .host_namespace
                .clone()
                .context("host tunable opt-in required")?;
            let values = kernel.host;
            host_session(host, move |_, _| {
                sysctl::write_scope(&values, "host")?;
                sysctl::verify_scope(&values, "host")
            })?;
        }
        ownership.scope = self.identity.clone();
        // Set by caller after actual kernel convergence; never synthesize a live fingerprint.
        ownership.firewall_fingerprint = Some(fingerprint);
        Ok(())
    }

    fn capture_kernel(&self, before: &Value, after: &Value) -> Result<Kernel> {
        let before = Network::parse(before)?;
        let after = Network::parse(after)?;
        let mut keys = before.kernel;
        keys.namespace.extend(after.kernel.namespace);
        keys.host.extend(after.kernel.host);
        // Include restored-but-retained baseline keys so drift cannot be bypassed by
        // removing a key from the desired configuration and changing it externally.
        let baseline = self.ownership()?.kernel_baseline;
        for (name, value) in baseline.namespace {
            keys.namespace.entry(name).or_insert(value);
        }

        for (name, value) in baseline.host {
            keys.host.entry(name).or_insert(value);
        }
        self.read_kernel(&keys)
    }

    fn capture_ipv6(&self, before: &Value) -> Result<ipv6::Snapshot> {
        let network = Network::parse(before)?;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(ipv6::capture(handle))?.unmanaged(&network)
        })
    }

    fn read_kernel(&self, keys: &Kernel) -> Result<Kernel> {
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
                .context("host tunables require operator allow_host_tunables")?;
            let values = keys.host.clone();
            host_session(handle, move |_, _| sysctl::read_scope(&values, "host"))?
        };
        Ok(Kernel { namespace, host })
    }

    fn verify_kernel(&self, values: &Kernel) -> Result<()> {
        crate::ensure_unchanged(self.read_kernel(values)? == *values, "kernel tunable drift")?;
        Ok(())
    }

    fn preflight_kernel(&self, values: &Kernel) -> Result<()> {
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
                .context("host tunables require operator allow_host_tunables")?;
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

    fn recover(&mut self) -> Result<()> {
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
        let mut ownership = intent.ownership_before.clone();
        ownership
            .ethernet_originals
            .extend(intent.ethernet_originals);
        self.services.shutdown()?;
        self.dhcp.configure(&intent.before)?;
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
        self.services.repair(&intent.before)?;
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
        let expected = Network::parse(
            ownership
                .committed_config
                .as_ref()
                .context("missing reboot configuration")?,
        )?;
        let originals = ownership.ethernet_originals.clone();
        let keys = self.options.keys.clone();
        let (mut before, fingerprint) = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))?;
            Ok((
                rt.block_on(networking::boot_snapshot(handle, &expected, &keys))?,
                netfilter::fingerprint()?,
            ))
        })?;
        let mut previous = ownership.clone();
        // A prior-boot lease or interface index must never be resurrected.
        ownership.ipv6_original = None;
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
        for (name, value) in &kernel_before.namespace {
            ownership
                .kernel_baseline
                .namespace
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
        for (name, value) in &kernel_before.host {
            ownership
                .kernel_baseline
                .host
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
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
        let mut target = ownership.kernel_baseline.clone();
        let desired = Network::parse(after)?;
        target.namespace.extend(desired.kernel.namespace);
        target.host.extend(desired.kernel.host);
        let result = (|| -> Result<()> {
            self.services.shutdown()?;
            self.dhcp.configure(after)?;
            self.network_apply(&before, after, target, &mut ownership)?;
            self.services.repair(after)?;
            ownership.firewall_config = Some(Network::parse(after)?.firewall);
            ownership.managed_interfaces = Network::parse(after)?
                .interfaces
                .into_iter()
                .map(|l| l.name)
                .collect();
            ownership
                .ethernet_originals
                .retain(|name, _| ownership.managed_interfaces.contains(name));
            ownership.committed_config = Some(after.clone());
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
    fn initial_configuration(&mut self) -> Result<Config> {
        if !self.options.namespace.is_empty() {
            return Ok(Config::empty());
        }
        let path = self.state.join("adoption.json");
        let receipt: adoption::Receipt = if path.try_exists()? {
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
                    .is_none_or(|value| serde_json::to_value(Config::empty())
                        .is_ok_and(|empty| *value == empty)),
                "configured native state exists without its initial core journal; state is not reset"
            );
            let scope = self.identity.clone();
            let previous = serde_json::to_value(&ownership)?;
            let readonly = self.parents.keys().cloned().collect();
            let receipt = session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(adoption::capture(handle, scope, previous, readonly))
            })?;
            if receipt.config.interfaces.is_empty() {
                return Ok(Config::empty());
            }
            write_json(&path, &receipt)?;
            receipt
        };
        receipt
            .config
            .validate()
            .context("invalid inherited baseline")?;
        ensure!(
            receipt.config.interfaces.len() == receipt.originals.len()
                && receipt.config.interfaces.iter().all(|link| receipt
                    .originals
                    .get(&link.name)
                    .is_some_and(|snapshot| snapshot.name == link.name)),
            "inherited interface snapshot identities do not match the baseline"
        );
        let originals = receipt.originals.clone();
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))
        })?;
        let result = (|| -> Result<()> {
            adoption::handover(&receipt)?;
            let captured = receipt.clone();
            session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(networking::restore_ethernet(handle, &captured.originals))?;
                rt.block_on(adoption::transfer_routes(handle, &captured, false))
            })?;
            for (name, lease) in &receipt.leases {
                write_json(&self.state.join(format!("dhcp-{name}.json")), lease)?;
            }
            let mut ownership = self.ownership()?;
            ownership.scope = self.identity.clone();
            ownership.ethernet_originals = receipt.originals.clone();
            ownership.managed_interfaces = receipt.originals.keys().cloned().collect();
            ownership.committed_config = Some(receipt.config.operational_value()?);
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
    fn scope(&self) -> Result<String> {
        self.check_scope()?;
        Ok(self.identity.clone())
    }

    fn observe(&mut self, expected: &Config) -> Result<Config> {
        let config = expected.operational_value()?;
        self.verify(&config)?;
        self.verify_services(&config)?;
        Ok(expected.clone())
    }

    fn observe_for_repair(&mut self, expected: &Config) -> Result<Config> {
        self.verify(&expected.operational_value()?)?;
        Ok(expected.clone())
    }

    fn apply(&mut self, before: &Config, after: &Config) -> Result<()> {
        self.recover()?;
        let before = before.operational_value()?;
        let after = after.operational_value()?;
        self.preflight(&before)?;
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
                    && after == serde_json::to_value(Config::empty())?);
            if recorded_target && ownership.managed_interfaces == after_names {
                match self.verify(&after) {
                    Ok(()) => {
                        self.services.repair(&after)?;
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
            return Err(
                drift.context("native drift guard: committed configuration differs from kernel")
            );
        }
        if before == after && ownership.committed_config.is_some() {
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
        for (name, value) in &captured.namespace {
            ownership
                .kernel_baseline
                .namespace
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
        for (name, value) in &captured.host {
            ownership
                .kernel_baseline
                .host
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
        let mut kernel_target = ownership.kernel_baseline.clone();
        kernel_target
            .namespace
            .extend(Network::parse(&after)?.kernel.namespace);
        kernel_target
            .host
            .extend(Network::parse(&after)?.kernel.host);
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
            self.services.shutdown()?;
            self.dhcp.configure(&after)?;
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
            ownership.committed_config = Some(after.clone());
            ownership.boot = self.boot.clone();
            self.services.apply(&before, &after)?;
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
    }

    fn retry_dhcp(&mut self, config: &Config, interface: &str) -> Result<()> {
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
        ensure!(
            self.options.namespace.is_empty(),
            "factory reset requires host mode"
        );
        self.recover()?;
        let before = before.operational_value()?;
        let after = after.operational_value()?;
        self.reconcile_after_boot(&after, self.ownership()?, Some(&before))
    }

    fn runtime(&mut self, config: &Config) -> Result<Value> {
        self.check_scope()?;
        let parents = self.parents.clone();
        let parent_status = session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::parent_status(handle, &parents))
        })?;
        let mut value = self.services.status();
        if !value.is_object() {
            value = json!({"services":value});
        }
        value["parents"] = parent_status;
        value["dhcp_clients"] = self.dhcp.status()?;
        value["scope"] = json!(self.identity);
        let enabled = config.ipv6_enabled;
        value["ipv6"] = session(self.namespace.clone(), move |_, _| ipv6::status(enabled))?;
        let desired = Network::parse(&config.operational_value()?)?.kernel;
        let baseline = self.ownership()?.kernel_baseline;
        let mut effective = baseline.clone();
        effective.namespace.extend(desired.namespace.clone());
        effective.host.extend(desired.host.clone());
        let observed = self.read_kernel(&effective)?;
        value["kernel_tunables"] = json!({"desired":desired,"configured":desired,"effective":effective,"observed":observed,"captured_original":baseline,"drift":effective != observed});
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
        Ok(value)
    }

    fn delete_connections(
        &mut self,
        target: Option<(u32, &netcontrol_core::ConnectionTarget)>,
    ) -> Result<Value> {
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
        self.check_scope()?;
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
            let gateways = self
                .services
                .statistics("/api/v1/statistics/gateways", "")?;
            value["gateways"] = gateways["gateways"].clone();
            if gateways["sample"]["status"] == "partial" {
                value["sample"]["status"] = json!("partial");
            }
        }
        Ok(value)
    }

    fn repair(&mut self, config: &Config) -> Result<Value> {
        self.recover()?;
        let value = config.operational_value()?;
        let originals = self.ownership()?.ethernet_originals;
        session(self.namespace.clone(), move |rt, handle| {
            rt.block_on(networking::check_ethernet(handle, &originals))
        })?;
        self.dhcp.configure(&value)?;
        let ownership = self.ownership()?;
        if self.options.namespace.is_empty()
            && !ownership.boot.is_empty()
            && ownership.boot != self.boot
        {
            self.reconcile_after_boot(&value, ownership, None)?;
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
        // Empty initial state has no owned nftables table yet. Bootstrap only the verified
        // current firewall; never overwrite a foreign table or repair unrelated drift.
        let mut ownership = self.ownership()?;
        if ownership.committed_config.is_none() {
            self.apply(config, config)?;
            ownership = self.ownership()?;
        }
        if self.options.namespace.is_empty()
            && ownership.firewall_fingerprint.is_none()
            && config == &Config::empty()
        {
            self.services.repair(&value)?;
            return Ok(self.services.status());
        }
        if ownership.firewall_fingerprint.is_none() {
            let firewall = Network::parse(&value)?.firewall;
            let captured = self.capture_kernel(&value, &value)?;
            let intent = Intent {
                scope: self.identity.clone(),
                before: value.clone(),
                after: value.clone(),
                kernel_before: captured.clone(),
                ownership_before: ownership.clone(),
                ethernet_before: BTreeMap::new(),
                ethernet_originals: ownership.ethernet_originals.clone(),
                ipv6_before: self.capture_ipv6(&value)?,
            };
            write_json(&self.state.join("intent.json"), &intent)?;
            self.network_apply(&value, &value, captured, &mut ownership)
                .context("initial firewall bootstrap failed; scoped recovery intent retained")?;
            ownership.scope = self.identity.clone();
            ownership.firewall_config = Some(firewall);
            self.save_ownership(&ownership)?;
            remove_durable(&self.state.join("intent.json"))?;
        }
        self.services.repair(&value)?;
        let adoption_path = self.state.join("adoption.json");
        if adoption_path.try_exists()? {
            let mut receipt: adoption::Receipt = read_json(&adoption_path)?;
            if !receipt.complete {
                receipt.complete = true;
                write_json(&adoption_path, &receipt)?;
            }
        }
        Ok(self.services.status())
    }
}

impl Drop for Native {
    fn drop(&mut self) {
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
            && metadata.len() <= 16 * 1024 * 1024,
        "untrusted native state file"
    );
    serde_json::from_reader(file).context("decode native state")
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
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
        file.write_all(&serde_json::to_vec(value)?)?;
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
    fn handover_restores_only_still_managed_interfaces() {
        let ownership = inherited_ownership();
        let selected = ownership.handover_originals(true, true);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected["owned0"], ownership.ethernet_originals["owned0"]);
        assert!(!selected.contains_key("released0"));
    }

    #[test]
    fn handover_skips_labs_and_non_inherited_configurations() {
        let ownership = inherited_ownership();
        for (host_mode, inherited) in [(false, false), (false, true), (true, false)] {
            assert!(
                ownership
                    .handover_originals(host_mode, inherited)
                    .is_empty()
            );
        }
    }

    #[test]
    fn handover_does_not_discover_new_interfaces() {
        assert!(
            Ownership::default()
                .handover_originals(true, true)
                .is_empty()
        );
    }
}
