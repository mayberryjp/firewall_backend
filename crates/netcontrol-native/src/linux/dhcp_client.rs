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
    pub routes: Vec<Route>,
}

pub fn effective(network: &mut Network, state: &State) -> Result<()> {
    let mut routes = Vec::new();
    for route in &network.routes {
        let (destination, _) = crate::model::parse_prefix(&route.destination, true)?;
        if !destination.is_ipv4()
            || !network.dhcp_clients.contains_key(&route.interface)
            || state.leases.get(&route.interface).is_some_and(|lease| {
                lease.valid() && network.dhcp_clients.get(&route.interface) == Some(&lease.client)
            })
        {
            routes.push(route.clone());
        }
    }
    network.routes = routes;
    for link in &mut network.interfaces {
        if network.dhcp_clients.contains_key(&link.name) {
            if let Some(lease) = state.leases.get(&link.name).filter(|lease| {
                lease.valid() && network.dhcp_clients.get(&link.name) == Some(&lease.client)
            }) {
                link.addresses.push(lease.address.clone());
                link.addresses.sort();
                link.addresses.dedup();
                if let Some(mtu) = lease.mtu {
                    link.mtu = mtu;
                }
            }
        }
    }
    Ok(())
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
        self.configure_selected(value, None)
    }

    fn stop_worker(&mut self, name: &str, deadline: Instant) -> Result<()> {
        if let Some(worker) = self.workers.get(name) {
            worker.stop.store(true, Ordering::Release);
            worker.wait(deadline)?;
            let worker = self.workers.remove(name).context("DHCP worker missing")?;
            worker
                .join
                .join()
                .map_err(|_| anyhow::anyhow!("DHCP worker panicked"))?;
        }
        Ok(())
    }

    pub fn retry(&mut self, value: &Value, name: &str) -> Result<()> {
        let config: Config = serde_json::from_value(value.clone())?;
        ensure!(
            config.dhcp_clients.contains_key(name)
                && config
                    .interfaces
                    .iter()
                    .any(|interface| interface.name == name && interface.up),
            "DHCP retry requires an up interface with DHCP configured"
        );
        self.stop_worker(name, Instant::now() + Duration::from_secs(15))?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?
            .errors
            .remove(name);
        self.configure_selected(value, Some(name))
    }

    fn configure_selected(&mut self, value: &Value, only: Option<&str>) -> Result<()> {
        let config: Config = serde_json::from_value(value.clone())?;
        let network = Network::parse(&config.operational_value()?)?;
        let addressing: BTreeMap<_, _> = config
            .interfaces
            .iter()
            .map(|link| {
                (
                    link.name.clone(),
                    Addressing {
                        dns: config.dns.get(&link.name).cloned().unwrap_or_default(),
                        mtu: link.mtu as u32,
                        routes: network
                            .routes
                            .iter()
                            .filter(|route| route.interface == link.name)
                            .cloned()
                            .collect(),
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
                only.is_none_or(|selected| selected == name.as_str())
                    && (wanted.get(*name) != Some(&worker.client)
                        || worker.join.is_finished()
                        || failed.contains(*name))
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in removed {
            self.stop_worker(&name, Instant::now() + Duration::from_secs(15))?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
            if let Some(lease) = state.leases.get(&name).cloned() {
                let settings = state.addressing.get(&name).cloned().unwrap_or_default();
                change_lease(
                    self.namespace.clone(),
                    self.publish_dns,
                    name.clone(),
                    Some(lease),
                    None,
                    settings,
                )?;
                state.leases.remove(&name);
            }
            state.errors.remove(&name);
        }
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?
            .addressing = addressing.clone();
        for (name, client) in wanted {
            if only.is_some_and(|selected| selected != name.as_str()) {
                continue;
            }
            if self.workers.contains_key(&name) {
                continue;
            }
            let path = self.directory.join(format!("dhcp-{name}.json"));
            let intent_path = path.with_extension("intent");
            let seed = if only.is_none() || intent_path.try_exists()? {
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
                seed
            } else {
                None
            };
            let seed = if only.is_some() { None } else { seed };
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
                                let previous = state.leases.get(&name).cloned();
                                change_lease(namespace.clone(), publish_dns, name.clone(), previous, None,
                                    state.addressing.get(&name).cloned().context("DHCP addressing missing")?)?;
                                state.leases.remove(&name);
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
                                    let previous = state.leases.get(&name).cloned();
                                    change_lease(namespace.clone(), publish_dns, name.clone(), previous, None,
                                        state.addressing.get(&name).cloned().context("DHCP addressing missing")?)?;
                                    state.leases.remove(&name);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_static_routes_follow_valid_matching_leases() -> Result<()> {
        let config: Config = serde_json::from_value(json!({
            "interfaces": [
                {"name":"wan0","kind":"dummy","role":"wan","mtu":1500,"up":true},
                {"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true}
            ],
            "dhcp_clients":{"wan0":{}},
            "routes":[
                {"destination":"198.51.100.0/24","gateway":"192.0.2.1","interface":"wan0","table":254,"metric":10},
                {"destination":"203.0.113.0/24","interface":"wan0","table":10001,"metric":10},
                {"destination":"2001:db8:1::/64","interface":"wan0","table":254,"metric":10},
                {"destination":"198.18.0.0/16","interface":"lan0","table":254,"metric":10},
                {"enabled":false,"destination":"198.19.0.0/16","interface":"wan0","table":254,"metric":10}
            ]
        }))?;
        let network = Network::parse(&config.operational_value()?)?;
        let mut state = State::default();
        let check = |state: &State, count: usize| -> Result<()> {
            let mut actual = network.clone();
            effective(&mut actual, state)?;
            assert_eq!(actual.routes.len(), count);
            assert!(actual.routes.iter().any(|route| route.interface == "lan0"));
            assert!(
                actual
                    .routes
                    .iter()
                    .any(|route| route.destination == "2001:db8:1::/64")
            );
            Ok(())
        };
        check(&state, 2)?;
        let lease: Lease = serde_json::from_value(json!({
            "client":{}, "address":"192.0.2.10/24", "server":"192.0.2.1",
            "acquired_at":now()?, "lifetime":3600, "renewal":1800, "rebinding":3150,
            "routes":[], "dns":[], "domain":"", "mtu":null
        }))?;
        state.leases.insert("wan0".into(), lease.clone());
        check(&state, 4)?;
        state.leases.get_mut("wan0").unwrap().lifetime = 0;
        check(&state, 2)?;
        state.leases.insert("wan0".into(), lease);
        state.leases.get_mut("wan0").unwrap().client.route_metric = 500;
        check(&state, 2)?;
        state.leases.clear();
        check(&state, 2)?;
        Ok(())
    }

    #[test]
    fn dhcp_worker_route_plan_tracks_enabled_configuration() -> Result<()> {
        let mut manager = manager();
        // No up interfaces: exercise plan publication without starting network workers.
        manager.configure(&json!({
            "interfaces":[{"name":"wan0","kind":"dummy","role":"wan","mtu":1500,"up":false}],
            "dhcp_clients":{"wan0":{}},
            "routes":[
                {"destination":"198.51.100.0/24","interface":"wan0","table":254,"metric":10},
                {"enabled":false,"destination":"203.0.113.0/24","interface":"wan0","table":254,"metric":10}
            ]
        }))?;
        assert_eq!(
            manager.state.lock().unwrap().addressing["wan0"]
                .routes
                .len(),
            1
        );
        manager.configure(&serde_json::to_value(Config::empty())?)?;
        assert!(manager.state.lock().unwrap().addressing.is_empty());
        Ok(())
    }

    fn blocked_worker() -> (Worker, mpsc::Sender<()>) {
        let (release, waiting) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let _ = waiting.recv();
        });
        (
            Worker {
                client: DHCPClientConfig::default(),
                stop: Arc::new(AtomicBool::new(false)),
                join,
            },
            release,
        )
    }

    fn manager() -> Manager {
        Manager::new(
            Arc::new(File::open("/proc/thread-self/ns/net").unwrap()),
            PathBuf::new(),
            false,
        )
    }

    #[test]
    fn dhcp_retry_stop_timeout_retains_ownership_and_other_workers() {
        let mut manager = manager();
        let (selected, selected_release) = blocked_worker();
        let (other, other_release) = blocked_worker();
        let other_stop = other.stop.clone();
        manager.workers.insert("wan0".into(), selected);
        manager.workers.insert("other0".into(), other);
        manager.state.lock().unwrap().leases.insert(
            "wan0".into(),
            Lease {
                client: DHCPClientConfig::default(),
                address: "192.0.2.10/24".into(),
                server: "192.0.2.1".parse().unwrap(),
                acquired_at: now().unwrap(),
                lifetime: 3600,
                renewal: 1800,
                rebinding: 3150,
                routes: vec![],
                dns: vec![],
                domain: String::new(),
                mtu: None,
            },
        );
        let before = manager.status().unwrap();
        let error = manager.stop_worker("wan0", Instant::now()).unwrap_err();
        let retained = manager.workers.contains_key("wan0");
        let isolated = !other_stop.load(Ordering::Acquire);
        selected_release.send(()).unwrap();
        other_release.send(()).unwrap();
        manager.shutdown().unwrap();
        assert_eq!(manager.status().unwrap(), before);
        assert!(error.to_string().contains("ownership retained"));
        assert!(retained);
        assert!(isolated);
    }

    #[test]
    fn dhcp_retry_selection_leaves_unrelated_failed_clients_alone() {
        let mut manager = manager();
        let (worker, release) = blocked_worker();
        let stop = worker.stop.clone();
        manager.workers.insert("other0".into(), worker);
        manager
            .state
            .lock()
            .unwrap()
            .errors
            .insert("other0".into(), "injected failure".into());
        let result = manager.configure_selected(&json!({
            "interfaces": [{"name": "other0", "kind": "dummy", "role": "wan", "mtu": 1500, "up": true}],
            "dhcp_clients": {"other0": {}}
        }), Some("wan0"));
        let isolated = !stop.load(Ordering::Acquire)
            && manager.workers.contains_key("other0")
            && manager.state.lock().unwrap().errors.contains_key("other0");
        release.send(()).unwrap();
        manager.shutdown().unwrap();
        result.unwrap();
        assert!(isolated);
    }
}
