//! Short-lived, crash-recoverable changes owned exclusively by one path test.
use super::{netfilter, networking, read_json, remove_durable, session, write_json};
use anyhow::{Context, Result, anyhow, ensure};
use netcontrol_core::{PATH_TEST_LIFETIME_SECONDS, PathTestRequest};
use netlink_packet_core::Emitable;
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlags, AddressHeaderFlags},
    link::{LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod permits;
pub(super) use permits::validate_lease_elements;
#[cfg(all(test, feature = "nftables"))]
mod integration_tests;

const INTENT: &str = "path-test.json";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Link {
    #[serde(rename = "interface")]
    name: String,
    index: u32,
    kind: String,
    address: Vec<u8>,
    parent: Option<u32>,
    approved: bool,
    original_mtu: u32,
    maximum_mtu: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    id: String,
    boot: String,
    namespace_device: u64,
    namespace_inode: u64,
    firewall_before: String,
    rules: Vec<Vec<u8>>,
    lease: Vec<u8>,
    links: Vec<Link>,
    deadline_unix_ns: u64,
}

impl Intent {
    fn validate(&self) -> Result<()> {
        ensure!(
            valid_id(&self.id) && !self.boot.is_empty() && self.boot.len() <= 64,
            "invalid path-test recovery identity"
        );
        ensure!(
            self.rules.len() == 8
                && self
                    .rules
                    .iter()
                    .all(|rule| (4..=4096).contains(&rule.len()))
                && (4..=1024).contains(&self.lease.len()),
            "invalid bounded path-test firewall snapshot"
        );
        ensure!(
            (1..=33).contains(&self.links.len())
                && self.links.iter().filter(|link| link.approved).count() <= 9
                && self.links[0].approved,
            "invalid bounded path-test link snapshot"
        );
        let mut names = std::collections::BTreeSet::new();
        let mut indices = std::collections::BTreeSet::new();
        for link in &self.links {
            ensure!(
                netcontrol_core::valid_interface_name(&link.name)
                    && names.insert(&link.name)
                    && link.index != 0
                    && indices.insert(link.index)
                    && link.original_mtu != 0
                    && link.address.len() <= 64
                    && link.kind.len() <= 64,
                "invalid path-test interface identity"
            );
            ensure!(
                !link.approved
                    || ((1280..=65535).contains(&link.maximum_mtu)
                        && link.maximum_mtu >= link.original_mtu),
                "invalid approved MTU snapshot"
            );
        }
        Ok(())
    }
}

struct Worker {
    cancel: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

pub(super) struct Manager {
    namespace: Arc<File>,
    directory: PathBuf,
    boot: String,
    state: Arc<Mutex<Value>>,
    active: Arc<AtomicBool>,
    worker: Option<Worker>,
    reservation: Option<Arc<netcontrol_services::path_test::Prepared>>,
}

pub(super) fn has_dns_endpoints(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key == "endpoint"
                && value.as_str().is_some_and(|endpoint| {
                    matches!(
                        netcontrol_core::WireGuardEndpoint::parse(endpoint),
                        Ok(Some(netcontrol_core::WireGuardEndpoint::Dns { .. }))
                    )
                }))
                || has_dns_endpoints(value)
        }),
        Value::Array(values) => values.iter().any(has_dns_endpoints),
        _ => false,
    }
}

pub(super) fn validate_dynamic_dns_path(
    namespace: Arc<File>,
    request: &PathTestRequest,
    config: &Value,
) -> Result<()> {
    let network = crate::model::Network::parse(config)?;
    let dynamic: std::collections::BTreeSet<_> = network
        .interfaces
        .iter()
        .filter(|link| link.wireguard.as_ref().is_some_and(has_dns_endpoints))
        .map(|link| link.name.clone())
        .collect();
    if dynamic.is_empty() {
        return Ok(());
    }
    let selected = request.interface.clone();
    session(namespace, move |rt, handle| {
        rt.block_on(async {
            let messages = tokio::time::timeout(Duration::from_secs(3), networking::links(handle)).await??;
            let message = messages.iter().find(|message| networking::name(message) == selected)
                .context("selected interface does not exist")?;
            let mut current = identity(message, 0)?;
            // These are demonstrably non-encapsulating L2 devices, not a whitelist
            // of test targets. Other IP-capable targets remain supported when
            // there is no asynchronously changing, unresolved tunnel underlay.
            ensure!(matches!(current.kind.as_str(),
                "device" | "vlan" | "macvlan" | "ipvlan" | "veth" | "dummy" | "bridge" | "bond" | "team"),
                "dynamic WireGuard DNS may change the selected tunnel's unresolved underlay");
            let mut visited = std::collections::BTreeSet::new();
            loop {
                ensure!(!dynamic.contains(&current.name),
                    "dynamic WireGuard DNS changes the selected path's endpoint");
                if !matches!(current.kind.as_str(), "vlan" | "macvlan" | "ipvlan") {
                    break;
                }
                let Some(parent) = current.parent else { break };
                ensure!(visited.insert(parent) && visited.len() <= 32, "invalid interface ancestry");
                let message = messages.iter().find(|message| message.header.index == parent)
                    .context("selected interface underlay cannot be resolved")?;
                current = identity(message, 0)?;
                ensure!(matches!(current.kind.as_str(),
                    "device" | "vlan" | "macvlan" | "ipvlan" | "veth" | "dummy" | "bridge" | "bond" | "team"),
                    "dynamic WireGuard DNS may change the selected path's unresolved tunnel underlay");
            }
            Ok(())
        })
    })
}

pub(super) fn validate_dhcp_path(
    config: &netcontrol_core::Config,
    _: &PathTestRequest,
) -> Result<()> {
    // DHCP can replace policy/default routes as well as interface MTU; a route
    // lookup alone cannot prove those asynchronous changes will remain unrelated.
    ensure!(
        config.dhcp_clients.is_empty(),
        "asynchronous DHCP address/route/MTU writers make exact path ownership unverifiable"
    );
    Ok(())
}

impl Manager {
    pub fn new(namespace: Arc<File>, directory: PathBuf, boot: String) -> Self {
        Self {
            namespace,
            directory,
            boot,
            state: Arc::new(Mutex::new(json!({
                "id":null,"state":"idle","active":false,"error":null,
                "progress":null,"result":null,"restoration":"not_required","mtu_changes":[]
            }))),
            active: Arc::new(AtomicBool::new(false)),
            worker: None,
            reservation: None,
        }
    }

    pub fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn ensure_idle(&self) -> Result<()> {
        ensure!(
            !self.active() && !self.directory.join(INTENT).try_exists()?,
            "path test is active or restoration is pending"
        );
        Ok(())
    }

    fn reap(&mut self) -> Result<()> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.join.is_finished())
        {
            self.worker
                .take()
                .context("missing path-test worker")?
                .join
                .join()
                .map_err(|_| anyhow!("path-test worker panicked; recovery intent retained"))?;
        }
        if self.worker.is_none() && !self.active() {
            self.reservation = None;
        }
        Ok(())
    }

    pub fn status(&mut self) -> Result<Value> {
        self.reap()?;
        let mut status = self
            .state
            .lock()
            .map_err(|_| anyhow!("path-test state poisoned"))?
            .clone();
        status["schema"] = json!("netcontrol-path-test-status-v1");
        status["permit_lease_seconds"] = json!(PATH_TEST_LIFETIME_SECONDS);
        status["mtu_restores_on_daemon_recovery"] = json!(true);
        status["conntrack_cleanup"] = json!("not_performed");
        status["warnings"] = json!([
            "Kernel permit expiry/removal does not retroactively revoke established conntrack acceptance. No unrelated connection state is flushed.",
            "A process crash releases socket reservations; remaining owned permits expire in the kernel within 90 seconds. MTU restoration requires daemon recovery."
        ]);
        let changes = status["mtu_changes"].clone();
        if changes
            .as_array()
            .is_some_and(|changes| !changes.is_empty())
        {
            let originals: Vec<Link> = serde_json::from_value(changes)?;
            status["mtu_changes"] = session(self.namespace.clone(), move |rt, handle| {
                rt.block_on(async {
                    let messages = networking::links(handle).await?;
                    let mut rows = Vec::new();
                    for original in originals {
                        let current = messages
                            .iter()
                            .find(|message| networking::name(message) == original.name)
                            .map(|message| identity(message, original.maximum_mtu))
                            .transpose()?;
                        let matches = current
                            .as_ref()
                            .is_some_and(|current| same_identity(current, &original));
                        let mut row = serde_json::to_value(&original)?;
                        row["observed_mtu"] =
                            json!(current.as_ref().map(|current| current.original_mtu));
                        row["identity_matches"] = json!(matches);
                        row["restored"] = json!(
                            matches
                                && current.as_ref().is_some_and(
                                    |current| current.original_mtu == original.original_mtu
                                )
                        );
                        rows.push(row);
                    }
                    Ok(json!(rows))
                })
            })?;
        }
        Ok(status)
    }

    pub fn recover(&mut self) -> Result<()> {
        ensure!(self.worker.is_none(), "cannot recover a running path test");
        let path = self.directory.join(INTENT);
        if !path.try_exists()? {
            return Ok(());
        }
        self.active.store(true, Ordering::Release);
        let intent: Intent = read_json(&path)?;
        intent.validate()?;
        let result = restore(self.namespace.clone(), &path, &self.boot, &intent);
        *self
            .state
            .lock()
            .map_err(|_| anyhow!("path-test state poisoned"))? = json!({
            "id":intent.id,"state":if result.is_ok() {"interrupted"} else {"cleanup_failed"},
            "active":result.is_err(),"error":result.as_ref().err().map(|error|format!("{error:#}")),
            "progress":null,"result":null,"mtu_changes":intent.links,
            "restoration":if result.is_err() {"pending"}
                else if self.boot != intent.boot {"kernel_reset"} else {"restored"}
        });
        if result.is_ok() {
            self.active.store(false, Ordering::Release);
            self.reservation = None;
        }
        result
    }

    pub fn start(
        &mut self,
        request: PathTestRequest,
        fingerprint: Option<String>,
    ) -> Result<Value> {
        let started = Instant::now();
        request.validate()?;
        self.ensure_idle()?;
        self.reap()?;
        let fingerprint = fingerprint.context("path test requires a durably owned firewall")?;
        let id = fs::read_to_string("/proc/sys/kernel/random/uuid")?
            .trim()
            .replace('-', "");
        ensure!(valid_id(&id), "invalid kernel-generated test identifier");
        let deadline = unix_ns()?
            .checked_add(PATH_TEST_LIFETIME_SECONDS * 1_000_000_000)
            .context("path-test deadline overflow")?;
        let source = request.clone();
        let expected = fingerprint.clone();
        let (links, prepared) = session(self.namespace.clone(), move |rt, handle| {
            ensure!(
                netfilter::fingerprint()? == expected,
                "owned firewall drift before path test"
            );
            permits::check_enforcement()?;
            let links = rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(3), snapshot(handle, &source)).await?
            })?;
            let prepared = netcontrol_services::path_test::prepare(&source)?;
            Ok((links, prepared))
        })?;
        let (rules, lease) = permits::rules(&request, &id, deadline)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = self.namespace.metadata()?;
        let intent = Intent {
            id: id.clone(),
            boot: self.boot.clone(),
            namespace_device: metadata.dev(),
            namespace_inode: metadata.ino(),
            firewall_before: fingerprint,
            rules,
            lease,
            links,
            deadline_unix_ns: deadline,
        };
        let path = self.directory.join(INTENT);
        // This is the ownership boundary: no kernel mutation precedes durable intent.
        intent.validate()?;
        write_json(&path, &intent)?;
        self.active.store(true, Ordering::Release);
        let prepared = Arc::new(prepared);
        self.reservation = Some(prepared.clone());
        *self
            .state
            .lock()
            .map_err(|_| anyhow!("path-test state poisoned"))? = json!({
            "id":id,"state":"preparing","active":true,"error":null,"progress":null,
            "result":null,"mtu_changes":intent.links,"restoration":"pending",
            "deadline_unix_ms":deadline / 1_000_000
        });
        let namespace = self.namespace.clone();
        let boot = self.boot.clone();
        let state = self.state.clone();
        let active = self.active.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = cancel.clone();
        let join = std::thread::Builder::new()
            .name("nc-path-test".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    execute(
                        namespace.clone(),
                        &intent,
                        &request,
                        prepared,
                        &stopping,
                        &state,
                        started,
                    )
                }))
                .unwrap_or_else(|_| Err(anyhow!("path-test worker panicked")));
                if let Ok(mut status) = state.lock() {
                    status["state"] = json!("restoring");
                    status["progress"] = Value::Null;
                }
                let cleanup = restore(namespace, &path, &boot, &intent);
                if let Ok(mut status) = state.lock() {
                    status["active"] = json!(cleanup.is_err());
                    status["restoration"] = json!(if cleanup.is_ok() {
                        "restored"
                    } else {
                        "pending"
                    });
                    status["state"] = json!(if cleanup.is_err() {
                        "cleanup_failed"
                    } else if stopping.load(Ordering::Acquire) {
                        "cancelled"
                    } else if result.is_err() {
                        "failed"
                    } else {
                        "completed"
                    });
                    status["error"] = json!(
                        cleanup
                            .as_ref()
                            .err()
                            .or(result.as_ref().err())
                            .map(|error| format!("{error:#}"))
                    );
                    status["result"] = result.unwrap_or(Value::Null);
                }
                if cleanup.is_ok() {
                    active.store(false, Ordering::Release);
                }
            });
        match join {
            Ok(join) => self.worker = Some(Worker { cancel, join }),
            Err(error) => {
                self.recover()
                    .context("recover failed path-test thread startup")?;
                return Err(error.into());
            }
        }
        self.status()
    }

    pub fn cancel(&mut self, id: &str) -> Result<Value> {
        self.reap()?;
        ensure!(valid_id(id), "invalid path-test identifier");
        ensure!(
            self.state
                .lock()
                .map_err(|_| anyhow!("path-test state poisoned"))?["id"]
                == id,
            "path-test identifier does not match retained session"
        );
        if let Some(worker) = &self.worker {
            worker.cancel.store(true, Ordering::Release);
        } else if self.active() {
            self.recover()?;
        }
        self.status()
    }

    pub fn shutdown(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker.cancel.store(true, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(40);
            while !worker.join.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if !worker.join.is_finished() {
                self.worker = Some(worker);
                anyhow::bail!("path-test shutdown exceeded cleanup deadline; intent retained");
            }
            worker
                .join
                .join()
                .map_err(|_| anyhow!("path-test worker panicked"))?;
        }
        if self.active() {
            self.recover()?;
        }
        if !self.active() {
            self.reservation = None;
        }
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unix_ns() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .try_into()?)
}

fn identity(message: &LinkMessage, maximum_mtu: u32) -> Result<Link> {
    let mut result = Link {
        name: networking::name(message),
        index: message.header.index,
        kind: "device".into(),
        address: Vec::new(),
        parent: None,
        approved: true,
        original_mtu: 0,
        maximum_mtu,
    };
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::Address(value) => result.address = value.clone(),
            LinkAttribute::Mtu(value) => result.original_mtu = *value,
            LinkAttribute::Link(value) => result.parent = Some(*value),
            LinkAttribute::LinkInfo(values) => {
                for value in values {
                    if let LinkInfo::Kind(value) = value {
                        result.kind = value.to_string();
                    }
                }
            }
            _ => {}
        }
    }
    ensure!(
        result.index != 0 && result.original_mtu != 0,
        "incomplete live interface snapshot"
    );
    Ok(result)
}

async fn snapshot(handle: &rtnetlink::Handle, request: &PathTestRequest) -> Result<Vec<Link>> {
    let messages = networking::links(handle).await?;
    let selected = messages
        .iter()
        .find(|message| networking::name(message) == request.interface)
        .context("selected interface does not exist")?;
    ensure!(
        selected.header.flags.contains(LinkFlags::Up)
            && !selected.header.flags.contains(LinkFlags::Loopback),
        "selected interface must be up and non-loopback"
    );
    if request.source_address.is_ipv6() {
        let disabled = fs::read_to_string(format!(
            "/proc/sys/net/ipv6/conf/{}/disable_ipv6",
            request.interface
        ))?;
        ensure!(
            disabled.trim() == "0",
            "IPv6 is disabled on the selected interface"
        );
    }
    let addresses = networking::addresses(handle, selected.header.index).await?;
    ensure!(addresses.iter().any(|message| {
        !message.header.flags.contains(AddressHeaderFlags::Tentative)
            && !message.header.flags.contains(AddressHeaderFlags::Dadfailed)
            && !message.attributes.iter().any(|attribute| matches!(attribute,
                AddressAttribute::Flags(flags) if flags.contains(AddressFlags::Tentative)
                    || flags.contains(AddressFlags::Dadfailed)))
            && !message.attributes.iter().any(|attribute| matches!(attribute,
                AddressAttribute::CacheInfo(info) if u64::from(info.ifa_valid) <= PATH_TEST_LIFETIME_SECONDS))
            && message.attributes.iter().find_map(|attribute| match attribute {
                AddressAttribute::Local(address) => Some(*address), _ => None,
            }).or_else(|| message.attributes.iter().find_map(|attribute| match attribute {
                AddressAttribute::Address(address) => Some(*address), _ => None,
            })) == Some(request.source_address)
    }), "selected source is not a usable address assigned to the selected interface");
    for message in &messages {
        for address in networking::addresses(handle, message.header.index).await? {
            for attribute in &address.attributes {
                if let AddressAttribute::Broadcast(broadcast) = attribute {
                    ensure!(
                        request.peer_address != IpAddr::V4(*broadcast)
                            && request.source_address != IpAddr::V4(*broadcast),
                        "source/peer is a known local directed broadcast address"
                    );
                }
            }
        }
    }
    check_route(request, selected.header.index)?;
    let mut chain = Vec::new();
    let mut current = identity(selected, request.maximum_mtu)?;
    let mut visited = std::collections::BTreeSet::new();
    while let Some(index) = current.parent {
        // IFLA_LINK means a lower link for VLAN/macvlan/ipvlan, but a peer for
        // veth and only part of route-dependent encapsulation for tunnels.
        if !matches!(current.kind.as_str(), "vlan" | "macvlan" | "ipvlan") {
            break;
        }
        ensure!(visited.insert(index), "cyclic interface ancestry");
        ensure!(
            visited.len() <= 32,
            "interface ancestry exceeds the bounded snapshot limit"
        );
        let Some(parent) = messages
            .iter()
            .find(|message| message.header.index == index)
        else {
            anyhow::bail!("interface underlay is outside the current namespace or missing");
        };
        current = identity(parent, 0)?;
        current.approved = false;
        chain.push(current.clone());
    }
    if !request.parents.is_empty() {
        let kind = identity(selected, request.maximum_mtu)?.kind;
        ensure!(
            kind == "vlan" || kind == "macvlan" || kind == "ipvlan",
            "tunnel underlay ancestry is ambiguous; parent MTU changes are not permitted"
        );
    }
    let mut result = vec![identity(selected, request.maximum_mtu)?];
    for ancestor in &chain {
        let mut ancestor = ancestor.clone();
        ancestor.maximum_mtu = ancestor.original_mtu;
        result.push(ancestor);
    }
    for approved in &request.parents {
        let parent = result
            .iter_mut()
            .find(|link| link.name == approved.interface && !link.approved)
            .context("approved parent is not a verified ancestor of the selected interface")?;
        parent.maximum_mtu = approved.maximum_mtu;
        parent.approved = true;
    }
    // Validate every bound before changing even one interface.
    for link in &result {
        if !link.approved {
            continue;
        }
        ensure!(
            link.maximum_mtu >= link.original_mtu,
            "maximum MTU must not lower live MTU on {}",
            link.name
        );
        let message = messages
            .iter()
            .find(|message| message.header.index == link.index)
            .context("interface disappeared")?;
        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        let attrs = crate::netlink_decode::attributes(&bytes[16..])?;
        let bound = |kind| {
            attrs
                .iter()
                .find(|(attribute, _)| attribute & 0x3fff == kind)
                .and_then(|(_, value)| <[u8; 4]>::try_from(value.as_slice()).ok())
                .map(u32::from_ne_bytes)
        };
        let minimum = bound(50).context("driver does not expose a trustworthy minimum MTU")?;
        let maximum = bound(51).context("driver does not expose a trustworthy maximum MTU")?;
        ensure!(
            minimum <= link.maximum_mtu && (maximum == 0 || link.maximum_mtu <= maximum),
            "requested maximum MTU exceeds driver limits for {}",
            link.name
        );
        if let Some(parent) = result
            .iter()
            .find(|parent| Some(parent.index) == link.parent)
        {
            ensure!(
                link.maximum_mtu <= parent.maximum_mtu,
                "maximum MTU on {} exceeds its approved/live parent MTU; explicitly approve a sufficient parent maximum",
                link.name
            );
        }
    }
    // Innermost first in the journal; raising uses the opposite order.
    result.sort_by_key(|link| {
        if link.name == request.interface {
            0
        } else {
            1 + chain
                .iter()
                .position(|ancestor| ancestor.index == link.index)
                .unwrap_or(chain.len())
        }
    });
    Ok(result)
}

fn same_identity(current: &Link, original: &Link) -> bool {
    current.name == original.name
        && current.index == original.index
        && current.kind == original.kind
        && current.address == original.address
        && current.parent == original.parent
}

async fn verify_links(handle: &rtnetlink::Handle, links: &[Link], raised: bool) -> Result<()> {
    let messages =
        tokio::time::timeout(Duration::from_secs(3), networking::links(handle)).await??;
    for original in links {
        let current = messages
            .iter()
            .find(|message| networking::name(message) == original.name)
            .context("snapshotted interface disappeared")?;
        let current = identity(current, original.maximum_mtu)?;
        ensure!(
            same_identity(&current, original),
            "snapshotted interface identity changed"
        );
        let expected = if raised && original.approved {
            original.maximum_mtu
        } else {
            original.original_mtu
        };
        ensure!(
            current.original_mtu == expected,
            "MTU changed unexpectedly on {}",
            original.name
        );
    }
    Ok(())
}

fn execute(
    namespace: Arc<File>,
    intent: &Intent,
    request: &PathTestRequest,
    prepared: Arc<netcontrol_services::path_test::Prepared>,
    cancel: &Arc<AtomicBool>,
    state: &Arc<Mutex<Value>>,
    started: Instant,
) -> Result<Value> {
    let intent = intent.clone();
    let request = request.clone();
    let cancel = cancel.clone();
    let state = state.clone();
    session(namespace, move |rt, handle| {
        ensure!(
            !cancel.load(Ordering::Acquire),
            "path test cancelled before preparation"
        );
        ensure!(
            unix_ns()? < intent.deadline_unix_ns,
            "path-test preparation timed out"
        );
        ensure!(
            netfilter::fingerprint()? == intent.firewall_before,
            "firewall changed before preparation"
        );
        permits::check_enforcement()?;
        rt.block_on(async {
            let current =
                tokio::time::timeout(Duration::from_secs(3), snapshot(handle, &request)).await??;
            ensure!(
                current == intent.links,
                "interface changed after durable snapshot"
            );
            for link in intent.links.iter().rev() {
                if !link.approved {
                    continue;
                }
                ensure!(!cancel.load(Ordering::Acquire), "path test cancelled");
                tokio::time::timeout(
                    Duration::from_millis(500),
                    handle
                        .link()
                        .set(
                            rtnetlink::LinkUnspec::new_with_index(link.index)
                                .mtu(link.maximum_mtu)
                                .build(),
                        )
                        .execute(),
                )
                .await??;
            }
            Ok::<_, anyhow::Error>(())
        })?;
        netfilter::with_budget(Duration::from_secs(5), || {
            permits::install(&intent.rules, &intent.lease)
        })?;
        rt.block_on(verify_links(handle, &intent.links, true))?;
        check_route(&request, intent.links[0].index)?;
        ensure!(
            started.elapsed() < Duration::from_secs(PATH_TEST_LIFETIME_SECONDS.saturating_sub(75)),
            "path-test preparation exceeded its bounded lifetime budget"
        );
        state
            .lock()
            .map_err(|_| anyhow!("path-test state poisoned"))?["state"] = json!("running");
        let result = prepared.run(&request, &cancel, &|progress| {
            if let Ok(mut status) = state.lock() {
                status["progress"] = progress;
            }
        })?;
        rt.block_on(verify_links(handle, &intent.links, true))?;
        check_route(&request, intent.links[0].index)?;
        Ok(result)
    })
}

fn restore(namespace: Arc<File>, path: &Path, boot: &str, intent: &Intent) -> Result<()> {
    intent.validate()?;
    use std::os::unix::fs::MetadataExt;
    let metadata = namespace.metadata()?;
    let same_boot = boot == intent.boot;
    // A reboot destroys namespace identities and nftables rules. Never apply an old
    // ifindex snapshot to the replacement network created by boot reconciliation.
    if !same_boot {
        remove_durable(path)?;
        return Ok(());
    }
    ensure!(
        metadata.dev() == intent.namespace_device && metadata.ino() == intent.namespace_inode,
        "path-test recovery namespace was replaced"
    );
    let owned = intent.clone();
    session(namespace, move |rt, handle| {
        let mut errors = Vec::new();
        if let Err(error) = netfilter::with_budget(Duration::from_secs(5), || {
            permits::remove(&owned.rules, &owned.lease, &owned.firewall_before)
        }) {
            errors.push(format!("firewall: {error:#}"));
        }
        rt.block_on(async {
            let messages =
                tokio::time::timeout(Duration::from_secs(3), networking::links(handle)).await??;
            for original in &owned.links {
                let result = async {
                    let message = messages
                        .iter()
                        .find(|message| networking::name(message) == original.name)
                        .context("original interface is absent")?;
                    let current = identity(message, original.maximum_mtu)?;
                    ensure!(
                        same_identity(&current, original),
                        "interface identity changed; refusing foreign replacement"
                    );
                    if !original.approved {
                        return Ok(());
                    }
                    ensure!(
                        current.original_mtu == original.original_mtu
                            || current.original_mtu == original.maximum_mtu,
                        "MTU changed externally; refusing to overwrite"
                    );
                    if current.original_mtu != original.original_mtu {
                        tokio::time::timeout(
                            Duration::from_millis(500),
                            handle
                                .link()
                                .set(
                                    rtnetlink::LinkUnspec::new_with_index(original.index)
                                        .mtu(original.original_mtu)
                                        .build(),
                                )
                                .execute(),
                        )
                        .await??;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = result {
                    errors.push(format!("{}: {error:#}", original.name));
                }
            }
            if errors.is_empty() {
                verify_links(handle, &owned.links, false).await?;
            }
            Ok::<_, anyhow::Error>(())
        })?;
        ensure!(
            errors.is_empty(),
            "path-test restoration pending: {}",
            errors.join("; ")
        );
        Ok(())
    })?;
    remove_durable(path)
}

fn attribute(kind: u16, bytes: &[u8]) -> Vec<u8> {
    let length = 4 + bytes.len();
    let mut result = Vec::with_capacity((length + 3) & !3);
    result.extend((length as u16).to_ne_bytes());
    result.extend(kind.to_ne_bytes());
    result.extend(bytes);
    result.resize((length + 3) & !3, 0);
    result
}

fn check_route(request: &PathTestRequest, index: u32) -> Result<()> {
    let (family, size, source, destination) = match (request.source_address, request.peer_address) {
        (IpAddr::V4(source), IpAddr::V4(peer)) => (
            libc::AF_INET as u8,
            32,
            source.octets().to_vec(),
            peer.octets().to_vec(),
        ),
        (IpAddr::V6(source), IpAddr::V6(peer)) => (
            libc::AF_INET6 as u8,
            128,
            source.octets().to_vec(),
            peer.octets().to_vec(),
        ),
        _ => anyhow::bail!("mixed address families"),
    };
    let mut body = vec![family, size, size, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    body.extend(attribute(1, &destination));
    body.extend(attribute(2, &source));
    let mut packet = Vec::new();
    packet.extend((16u32 + body.len() as u32).to_ne_bytes());
    packet.extend(26u16.to_ne_bytes()); // RTM_GETROUTE, not a route dump
    packet.extend(1u16.to_ne_bytes());
    packet.extend(1u32.to_ne_bytes());
    packet.extend(0u32.to_ne_bytes());
    packet.extend(body);
    let socket = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    ensure!(
        socket >= 0,
        "open route lookup: {}",
        std::io::Error::last_os_error()
    );
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    ensure!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const _,
                std::mem::size_of_val(&timeout) as _,
            )
        } == 0,
        "set route lookup timeout: {}",
        std::io::Error::last_os_error()
    );
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    ensure!(
        unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                packet.as_ptr() as *const _,
                packet.len(),
                0,
                &kernel as *const _ as *const _,
                std::mem::size_of_val(&kernel) as _,
            )
        } == packet.len() as isize,
        "send exact route lookup: {}",
        std::io::Error::last_os_error()
    );
    let mut response = [0u8; 8192];
    let length = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            response.as_mut_ptr() as *mut _,
            response.len(),
            0,
        )
    };
    ensure!(
        length >= 28 && length < response.len() as isize,
        "exact peer route lookup failed"
    );
    let length = length as usize;
    ensure!(
        u16::from_ne_bytes(response[4..6].try_into()?) == 24
            && u32::from_ne_bytes(response[8..12].try_into()?) == 1
            && response[16] == family
            && response[23] == 1,
        "peer route is not an exact unicast route"
    );
    let attrs = crate::netlink_decode::attributes(&response[28..length])?;
    let outputs = attrs
        .iter()
        .filter(|(kind, _)| kind & 0x3fff == 4)
        .collect::<Vec<_>>();
    ensure!(
        outputs.len() == 1 && outputs[0].1.as_slice() == index.to_ne_bytes(),
        "peer route uses a different or ambiguous interface; no fallback is permitted"
    );
    ensure!(
        !attrs.iter().any(|(kind, _)| kind & 0x3fff == 9),
        "multipath routes are not safe for a paired path test"
    );
    if let Some((_, address)) = attrs.iter().find(|(kind, _)| kind & 0x3fff == 7) {
        ensure!(
            *address == source,
            "route selected a different source address"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_dns_detection_distinguishes_numeric_wireguard_endpoints() {
        assert!(has_dns_endpoints(
            &json!({"peers":[{"endpoint":"vpn.example.test:51820"}]})
        ));
        assert!(!has_dns_endpoints(&json!({"peers":[
            {"endpoint":"192.0.2.10:51820"},{"endpoint":"[2001:db8::10]:51820"}
        ]})));
    }

    #[test]
    fn identifiers_are_bounded_and_canonical() {
        assert!(valid_id("0123456789abcdef0123456789abcdef"));
        for id in [
            "",
            "../state",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef",
        ] {
            assert!(!valid_id(id));
        }
    }

    #[test]
    fn identity_checks_do_not_confuse_mtu_with_foreign_replacement() {
        let original = Link {
            name: "test0".into(),
            index: 7,
            kind: "vlan".into(),
            address: vec![2, 0, 0, 0, 0, 1],
            parent: Some(3),
            approved: true,
            original_mtu: 1500,
            maximum_mtu: 9000,
        };
        let mut current = original.clone();
        current.original_mtu = 9000;
        assert!(same_identity(&current, &original));
        current.index += 1;
        assert!(!same_identity(&current, &original));
        current = original.clone();
        current.parent = Some(4);
        assert!(!same_identity(&current, &original));
    }

    #[test]
    fn persisted_intent_contains_no_secret_or_request() {
        let intent = Intent {
            id: "0123456789abcdef0123456789abcdef".into(),
            boot: "synthetic".into(),
            namespace_device: 1,
            namespace_inode: 2,
            firewall_before: "synthetic".into(),
            rules: vec![],
            lease: vec![],
            links: vec![],
            deadline_unix_ns: 1,
        };
        let encoded = serde_json::to_string(&intent).unwrap();
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("request"));
    }
}
