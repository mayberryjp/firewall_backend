use super::{networking, read_json, session, write_json};
use crate::model::{Network, Route};
use anyhow::{Context, Result, ensure};
use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State};
use netcontrol_core::{Config, DHCPClientConfig, DNSConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const PROTOCOL: u8 = 243;

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub client: DHCPClientConfig,
    pub address: String,
    pub server: Ipv4Addr,
    pub acquired_at: u64,
    pub lifetime: u32,
    pub renewal: u32,
    pub rebinding: u32,
    pub routes: Vec<Route>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: String,
    pub mtu: Option<u32>,
}

impl Lease {
    pub fn valid(&self) -> bool {
        now().is_ok_and(|time| time < self.acquired_at.saturating_add(u64::from(self.lifetime)))
    }

    fn wire(&self) -> Result<DhcpV4Lease> {
        let (address, prefix) = self
            .address
            .split_once('/')
            .context("DHCP address prefix missing")?;
        let prefix: u32 = prefix.parse()?;
        ensure!(prefix <= 32, "invalid DHCP prefix");
        let mut lease = DhcpV4Lease::default();
        lease.yiaddr = address.parse()?;
        lease.srv_id = self.server;
        lease.subnet_mask = Ipv4Addr::from(if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        });
        lease.lease_time_sec = self.lifetime;
        lease.t1_sec = self.renewal;
        lease.t2_sec = self.rebinding;
        Ok(lease)
    }

    fn received(interface: &str, client: DHCPClientConfig, wire: &DhcpV4Lease) -> Result<Self> {
        let prefix = wire.prefix_length();
        let mask = u32::from(wire.subnet_mask);
        ensure!(
            mask == if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            },
            "DHCP supplied a noncontiguous subnet mask"
        );
        ensure!(
            !wire.yiaddr.is_unspecified()
                && !wire.yiaddr.is_multicast()
                && !wire.yiaddr.is_broadcast(),
            "DHCP supplied an invalid address"
        );
        let mut routes = Vec::new();
        routes.push(Route {
            destination: format!("{}/{prefix}", Ipv4Addr::from(u32::from(wire.yiaddr) & mask)),
            gateway: String::new(),
            interface: interface.into(),
            table: 254,
            metric: client.route_metric,
        });
        if let Some(classless) = &wire.classless_routes {
            for route in classless {
                routes.push(Route {
                    destination: format!("{}/{}", route.destination, route.prefix_length),
                    gateway: if route.router.is_unspecified() {
                        String::new()
                    } else {
                        route.router.to_string()
                    },
                    interface: interface.into(),
                    table: 254,
                    metric: client.route_metric,
                });
            }
        } else if let Some(gateways) = &wire.gateways {
            for gateway in gateways {
                routes.push(Route {
                    destination: "0.0.0.0/0".into(),
                    gateway: gateway.to_string(),
                    interface: interface.into(),
                    table: 254,
                    metric: client.route_metric,
                });
            }
        }
        routes.sort();
        routes.dedup();
        let mtu = if client.use_mtu {
            wire.mtu.map(u32::from)
        } else {
            None
        };
        ensure!(
            mtu.is_none_or(|mtu| (1280..=65535).contains(&mtu)),
            "DHCP MTU is outside 1280..65535"
        );
        Ok(Self {
            client,
            address: format!("{}/{prefix}", wire.yiaddr),
            server: wire.srv_id,
            acquired_at: now()?,
            lifetime: wire.lease_time_sec,
            renewal: wire.t1_sec,
            rebinding: wire.t2_sec,
            routes,
            dns: wire.dns_srvs.clone().unwrap_or_default(),
            domain: wire.domain_name.clone().unwrap_or_default(),
            mtu,
        })
    }
}

#[derive(Clone, Default)]
pub struct State {
    pub leases: BTreeMap<String, Lease>,
    pub errors: BTreeMap<String, String>,
    pub addressing: BTreeMap<String, Addressing>,
}

#[derive(Clone, Default)]
pub struct Addressing {
    pub dns: DNSConfig,
    pub mtu: u32,
}

pub fn effective(network: &mut Network, state: &State) {
    for link in &mut network.interfaces {
        if network.dhcp_clients.contains_key(&link.name) {
            if let Some(lease) = state.leases.get(&link.name).filter(|lease| lease.valid()) {
                link.addresses.push(lease.address.clone());
                link.addresses.sort();
                link.addresses.dedup();
                if let Some(mtu) = lease.mtu {
                    link.mtu = mtu;
                }
            }
        }
    }
}

struct Worker {
    client: DHCPClientConfig,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl Worker {
    fn wait(&self, deadline: Instant) -> Result<()> {
        while !self.join.is_finished() {
            ensure!(
                Instant::now() < deadline,
                "DHCP worker did not stop; ownership retained until it exits"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

pub struct Manager {
    pub state: Arc<Mutex<State>>,
    workers: BTreeMap<String, Worker>,
    namespace: Arc<File>,
    directory: PathBuf,
    publish_dns: bool,
}

impl Manager {
    pub fn new(namespace: Arc<File>, directory: PathBuf, publish_dns: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            workers: BTreeMap::new(),
            namespace,
            directory,
            publish_dns,
        }
    }

    pub fn configure(&mut self, value: &Value) -> Result<()> {
        let config: Config = serde_json::from_value(value.clone())?;
        let addressing: BTreeMap<_, _> = config
            .interfaces
            .iter()
            .map(|link| {
                (
                    link.name.clone(),
                    Addressing {
                        dns: config.dns.get(&link.name).cloned().unwrap_or_default(),
                        mtu: link.mtu as u32,
                    },
                )
            })
            .collect();
        let wanted: BTreeMap<_, _> = config
            .dhcp_clients
            .into_iter()
            .filter(|(name, _)| {
                config
                    .interfaces
                    .iter()
                    .any(|link| &link.name == name && link.up)
            })
            .collect();
        let failed: std::collections::BTreeSet<_> = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?
            .errors
            .keys()
            .cloned()
            .collect();
        let removed: Vec<_> = self
            .workers
            .iter()
            .filter(|(name, worker)| {
                wanted.get(*name) != Some(&worker.client)
                    || worker.join.is_finished()
                    || failed.contains(*name)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in removed {
            let worker = self.workers.get(&name).context("DHCP worker missing")?;
            worker.stop.store(true, Ordering::Release);
            worker.wait(Instant::now() + Duration::from_secs(15))?;
            let worker = self.workers.remove(&name).context("DHCP worker missing")?;
            worker
                .join
                .join()
                .map_err(|_| anyhow::anyhow!("DHCP worker panicked"))?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
            if let Some(lease) = state.leases.remove(&name) {
                let settings = state.addressing.get(&name).cloned().unwrap_or_default();
                change_lease(
                    self.namespace.clone(),
                    self.publish_dns,
                    name.clone(),
                    Some(lease),
                    None,
                    settings,
                )?;
            }
            state.errors.remove(&name);
        }
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?
            .addressing = addressing.clone();
        for (name, client) in wanted {
            if self.workers.contains_key(&name) {
                continue;
            }
            let path = self.directory.join(format!("dhcp-{name}.json"));
            let intent_path = path.with_extension("intent");
            if intent_path.try_exists()? {
                let intent: LeaseIntent = read_json(&intent_path)?;
                let committed = if path.try_exists()? {
                    Some(read_json::<Lease>(&path)?)
                } else {
                    None
                };
                let target = committed.filter(|lease| lease.client == client && lease.valid());
                change_lease(
                    self.namespace.clone(),
                    self.publish_dns,
                    name.clone(),
                    Some(intent.after),
                    target,
                    addressing
                        .get(&name)
                        .cloned()
                        .context("DHCP addressing missing")?,
                )?;
                super::remove_durable(&intent_path)?;
            }
            let seed = if path.try_exists()? {
                Some(read_json::<Lease>(&path)?)
            } else {
                None
            };
            let seed = seed.filter(|lease| lease.client == client && lease.valid());
            if let Some(lease) = &seed {
                change_lease(
                    self.namespace.clone(),
                    self.publish_dns,
                    name.clone(),
                    None,
                    Some(lease.clone()),
                    addressing
                        .get(&name)
                        .cloned()
                        .context("DHCP interface addressing missing")?,
                )?;
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?
                    .leases
                    .insert(name.clone(), lease.clone());
            }
            let namespace = self.namespace.clone();
            let shared = self.state.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let interface = name.clone();
            let settings = client.clone();
            let publish_dns = self.publish_dns;
            let (ready, started) = mpsc::sync_channel(1);
            let failure = ready.clone();
            let join = std::thread::Builder::new()
                .name(format!("nc-dhcp-{name}"))
                .spawn(move || {
                    let recovery_namespace = namespace.clone();
                    let recovery_stop = stopping.clone();
                    let recovery_path = path.clone();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run(ClientTask {
                            namespace,
                            name: interface.clone(),
                            settings,
                            seed,
                            path,
                            stop: stopping,
                            shared: shared.clone(),
                            ready,
                            publish_dns,
                        })
                    }))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("DHCP worker panicked")));
                    if let Err(error) = result {
                        let _ = failure.try_send(Err(format!("{error:#}")));
                        if let Ok(mut state) = shared.lock() {
                            state.errors.insert(interface.clone(), format!("{error:#}"));
                        }
                        while !recovery_stop.load(Ordering::Acquire) {
                            if let Ok(mut state) = shared.lock() {
                                if let Some(lease) = state
                                    .leases
                                    .get(&interface)
                                    .filter(|lease| !lease.valid())
                                    .cloned()
                                {
                                    let addressing = state
                                        .addressing
                                        .get(&interface)
                                        .cloned()
                                        .unwrap_or_default();
                                    if change_lease(
                                        recovery_namespace.clone(),
                                        publish_dns,
                                        interface.clone(),
                                        Some(lease),
                                        None,
                                        addressing,
                                    )
                                    .is_ok()
                                    {
                                        state.leases.remove(&interface);
                                        let _ = super::remove_durable(&recovery_path);
                                    }
                                }
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                })?;
            self.workers
                .insert(name.clone(), Worker { client, stop, join });
            started
                .recv_timeout(Duration::from_secs(10))
                .context("DHCP startup did not complete")?
                .map_err(|error| anyhow::anyhow!("DHCP startup failed for {name}: {error}"))?;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<Value> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
        Ok(json!({"leases": state.leases, "errors": state.errors}))
    }

    pub fn shutdown(&mut self) -> Result<()> {
        for worker in self.workers.values() {
            worker.stop.store(true, Ordering::Release);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        for worker in self.workers.values() {
            worker.wait(deadline)?;
        }
        for (_, worker) in std::mem::take(&mut self.workers) {
            worker
                .join
                .join()
                .map_err(|_| anyhow::anyhow!("DHCP worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn change_lease(
    namespace: Arc<File>,
    publish_dns: bool,
    name: String,
    previous: Option<Lease>,
    next: Option<Lease>,
    addressing: Addressing,
) -> Result<()> {
    session(namespace, move |rt, handle| {
        rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                networking::dhcp_lease(
                    handle,
                    &name,
                    previous.as_ref(),
                    next.as_ref(),
                    &addressing,
                    publish_dns,
                ),
            )
            .await
            .context("DHCP kernel/DNS update timed out")?
        })
    })
}

struct ClientTask {
    namespace: Arc<File>,
    name: String,
    settings: DHCPClientConfig,
    seed: Option<Lease>,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<State>>,
    ready: mpsc::SyncSender<std::result::Result<(), String>>,
    publish_dns: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseIntent {
    after: Lease,
}

fn run(task: ClientTask) -> Result<()> {
    let ClientTask {
        namespace,
        name,
        settings,
        seed,
        path,
        stop,
        shared,
        ready,
        publish_dns,
    } = task;
    use std::os::fd::AsRawFd;
    let current = File::open("/proc/thread-self/ns/net")?;
    ensure!(
        super::same_file(&namespace, &current)?
            || unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0,
        "enter DHCP network namespace: {}",
        std::io::Error::last_os_error()
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let interface = name.clone();
    let parent = session(namespace.clone(), move |rt, handle| {
        rt.block_on(async {
            networking::links(handle)
                .await?
                .iter()
                .find(|link| networking::name(link) == interface)
                .map(networking::parent)
                .context("DHCP interface disappeared")
        })
    })?;
    runtime.block_on(async {
        let mut config = DhcpV4Config::new(&name);
        config.set_iface_index(parent.index);
        config.set_iface_mac(&parent.mac)?;
        if !settings.hostname.is_empty() { config.set_host_name(&settings.hostname); }
        if !settings.client_id.is_empty() {
            let identifier = hex::decode(&settings.client_id)?;
            ensure!(identifier.len() >= 2, "invalid DHCP client identifier");
            config.set_client_id(identifier[0], &identifier[1..]);
        } else { config.use_mac_as_client_id(); }
        let mut client = tokio::time::timeout(Duration::from_secs(5), DhcpV4Client::init(config, seed.as_ref().map(Lease::wire).transpose()?)).await??;
        ready.send(Ok(())).map_err(|_| anyhow::anyhow!("DHCP startup caller disappeared"))?;
        loop {
            if stop.load(Ordering::Acquire) { return Ok::<(), anyhow::Error>(()); }
            let result = {
                let running = client.run();
                tokio::pin!(running);
                loop {
                    tokio::select! {
                        result = &mut running => break Some(result),
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                            if stop.load(Ordering::Acquire) { return Ok(()); }
                            let mut state = shared.lock().map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
                            if state.leases.get(&name).is_some_and(|lease| !lease.valid()) {
                                let previous = state.leases.remove(&name);
                                change_lease(namespace.clone(), publish_dns, name.clone(), previous, None,
                                    state.addressing.get(&name).cloned().context("DHCP addressing missing")?)?;
                                super::remove_durable(&path)?;
                                break None;
                            }
                        }
                    }
                }
            };
            if let Some(result) = result {
                    match result {
                        Ok(DhcpV4State::Done(wire)) => {
                            let next = Lease::received(&name, settings.clone(), &wire)?;
                            client.done(*wire)?;
                            {
                                let mut state = shared.lock().map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
                                let previous = state.leases.get(&name).cloned();
                                let addressing = state.addressing.get(&name).cloned().context("DHCP addressing missing")?;
                                let intent_path = path.with_extension("intent");
                                write_json(&intent_path, &LeaseIntent { after: next.clone() })?;
                                let operation = change_lease(namespace.clone(), publish_dns, name.clone(), previous.clone(), Some(next.clone()), addressing.clone())
                                    .and_then(|()| write_json(&path, &next));
                                if let Err(error) = operation {
                                    change_lease(namespace.clone(), publish_dns, name.clone(), Some(next), previous, addressing)
                                        .context("DHCP rollback failed; lease intent retained")?;
                                    super::remove_durable(&intent_path)?;
                                    return Err(error.context("DHCP lease update failed; previous lease restored"));
                                }
                                state.leases.insert(name.clone(), next);
                                state.errors.remove(&name);
                                super::remove_durable(&intent_path)?;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            {
                                let mut state = shared.lock().map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
                                if matches!(error.kind(), mozim::ErrorKind::LeaseExpired | mozim::ErrorKind::NoLease) {
                                    let previous = state.leases.remove(&name);
                                    change_lease(namespace.clone(), publish_dns, name.clone(), previous, None,
                                        state.addressing.get(&name).cloned().context("DHCP addressing missing")?)?;
                                    super::remove_durable(&path)?;
                                }
                                state.errors.insert(name.clone(), error.to_string());
                            }
                            client.clean_up();
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
            } else { client.clean_up(); }
        }
    })
}
