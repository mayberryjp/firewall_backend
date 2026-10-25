use super::{dhcp_client, session};
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use netcontrol_core::{Config, GatewayMode, GatewayMonitor};
use netcontrol_services::GatewayProbe;
use netlink_packet_route::{
    route::{RouteAttribute, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute},
};
use rtnetlink::{Handle, IpVersion};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const FIRST_TABLE: u32 = 20000;
const LAST_TABLE: u32 = 20063;
const PROTOCOL: u8 = 244;
const FIRST_PRIORITY: u32 = 9000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Path {
    interface: String,
    source: Ipv4Addr,
    prefix: String,
    gateway: String,
    direct: bool,
    destination: String,
    table: u32,
}

fn resolve(
    monitor: &GatewayMonitor,
    table: u32,
    leases: &dhcp_client::State,
    config: &Config,
) -> Result<Option<Path>> {
    let Some(lease) = leases.leases.get(&monitor.interface).filter(|lease| {
        lease.valid() && config.dhcp_clients.get(&monitor.interface) == Some(&lease.client)
    }) else {
        return Ok(None);
    };
    let address: ipnet::Ipv4Net = lease.address.parse()?;
    let target: Ipv4Addr = monitor.target.parse()?;
    let mut candidates: Vec<_> = lease
        .routes
        .iter()
        .filter_map(|route| {
            let network: ipnet::Ipv4Net = route.destination.parse().ok()?;
            (route.interface == monitor.interface
                && route.table == 254
                && network.contains(&target))
            .then_some((network.prefix_len(), route.metric, route))
        })
        .collect();
    candidates.sort_by_key(|(prefix, metric, _)| (std::cmp::Reverse(*prefix), *metric));
    let (_, _, selected) = candidates
        .first()
        .context("active DHCP lease has no route to probe target")?;
    ensure!(
        candidates
            .iter()
            .take_while(
                |(prefix, metric, _)| *prefix == candidates[0].0 && *metric == candidates[0].1
            )
            .all(|(_, _, route)| route.gateway == selected.gateway),
        "ambiguous DHCP routes to probe target"
    );
    let gateway = if selected.gateway.is_empty() {
        monitor.target.clone()
    } else {
        selected.gateway.clone()
    };
    let gateway_ip: Ipv4Addr = gateway.parse()?;
    ensure!(
        netcontrol_core::global_unicast(address.addr().into())
            && netcontrol_core::global_unicast(gateway_ip.into())
            && address.addr() != target
            && address.addr() != gateway_ip,
        "invalid DHCP probe source/gateway"
    );
    Ok(Some(Path {
        interface: monitor.interface.clone(),
        source: address.addr(),
        prefix: address.trunc().to_string(),
        gateway,
        direct: selected.gateway.is_empty(),
        destination: selected.destination.clone(),
        table,
    }))
}

fn route_table(message: &netlink_packet_route::route::RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| {
            if let RouteAttribute::Table(table) = attribute {
                Some(*table)
            } else {
                None
            }
        })
        .unwrap_or(u32::from(message.header.table))
}

async fn clear(handle: &Handle, table: Option<u32>) -> Result<()> {
    for rule in handle
        .rule()
        .get(IpVersion::V4)
        .execute()
        .try_collect::<Vec<_>>()
        .await?
    {
        let tagged = rule
            .attributes
            .contains(&RuleAttribute::Protocol(RouteProtocol::Other(PROTOCOL)));
        let owned = rule.attributes.iter().any(|attribute| matches!(attribute, RuleAttribute::Priority(value) if (FIRST_PRIORITY..FIRST_PRIORITY + 64).contains(value) && table.is_none_or(|table| table - FIRST_TABLE + FIRST_PRIORITY == *value)));
        if tagged && owned {
            handle.rule().del(rule).execute().await?;
        }
    }
    for route in handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_collect::<Vec<_>>()
        .await?
    {
        let actual = route_table(&route);
        if route.header.protocol == RouteProtocol::Other(PROTOCOL)
            && (FIRST_TABLE..=LAST_TABLE).contains(&actual)
            && table.is_none_or(|table| actual == table)
        {
            handle.route().del(route).execute().await?;
        }
    }
    Ok(())
}

async fn install(handle: &Handle, path: &Path) -> Result<()> {
    clear(handle, Some(path.table)).await?;
    let rules = handle
        .rule()
        .get(IpVersion::V4)
        .execute()
        .try_collect::<Vec<_>>()
        .await?;
    let priority = path.table - FIRST_TABLE + FIRST_PRIORITY;
    ensure!(
        !rules
            .iter()
            .any(|rule| rule.attributes.contains(&RuleAttribute::Priority(priority))),
        "private DHCP monitor priority conflicts with an existing rule"
    );
    let routes = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_collect::<Vec<_>>()
        .await?;
    ensure!(
        !routes.iter().any(|route| route_table(route) == path.table),
        "private DHCP monitor table contains foreign routes"
    );
    let links = super::networking::links(handle).await?;
    let index = links
        .iter()
        .find(|link| super::networking::name(link) == path.interface)
        .context("DHCP monitor interface disappeared")?
        .header
        .index;
    let connected: ipnet::Ipv4Net = path.prefix.parse()?;
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(connected.network(), connected.prefix_len())
        .output_interface(index)
        .table_id(path.table)
        .protocol(RouteProtocol::Other(PROTOCOL))
        .scope(RouteScope::Link)
        .execute()
        .await?;
    if path.destination != path.prefix {
        let destination: ipnet::Ipv4Net = path.destination.parse()?;
        let request = handle
            .route()
            .add()
            .v4()
            .destination_prefix(destination.network(), destination.prefix_len())
            .output_interface(index)
            .table_id(path.table)
            .protocol(RouteProtocol::Other(PROTOCOL));
        if path.direct {
            request.scope(RouteScope::Link).execute().await?;
        } else if connected.contains(&path.gateway.parse::<Ipv4Addr>()?) {
            request
                .gateway(path.gateway.parse()?)
                .scope(RouteScope::Universe)
                .execute()
                .await?;
        } else {
            anyhow::bail!("DHCP gateway is not on the leased subnet");
        }
    }
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .table_id(path.table)
        .protocol(RouteProtocol::Other(PROTOCOL))
        .priority(u32::MAX)
        .kind(RouteType::Unreachable)
        .execute()
        .await?;
    let mut rule = handle
        .rule()
        .add()
        .v4()
        .source_prefix(path.source, 32)
        .table_id(path.table)
        .priority(priority)
        .action(RuleAction::ToTable)
        .output_interface(path.interface.clone());
    rule.message_mut()
        .attributes
        .push(RuleAttribute::Protocol(RouteProtocol::Other(PROTOCOL)));
    rule.message_mut().attributes.extend([
        RuleAttribute::FwMark(path.table),
        RuleAttribute::FwMask(u32::MAX),
    ]);
    rule.execute().await?;
    Ok(())
}

fn kernel(namespace: Arc<File>, path: Option<Path>, table: Option<u32>) -> Result<()> {
    session(namespace, move |runtime, handle| {
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                if let Some(path) = path {
                    install(handle, &path).await
                } else {
                    clear(handle, table).await
                }
            })
            .await
            .context("DHCP monitor kernel operation timed out")?
        })
    })
}

struct Entry {
    config: GatewayMonitor,
    table: u32,
    path: Option<Path>,
    probe: Option<GatewayProbe>,
    reason: Option<String>,
}

impl Entry {
    fn stop(&mut self, namespace: Arc<File>) -> Result<()> {
        if let Some(probe) = &mut self.probe {
            probe.shutdown()?;
        }
        self.probe = None;
        if self.path.is_some() {
            kernel(namespace, None, Some(self.table))?;
            self.path = None;
        }
        Ok(())
    }

    fn reconcile(&mut self, wanted: Option<Path>, namespace: Arc<File>) -> Result<()> {
        if self.path == wanted
            && (wanted.is_none()
                || self
                    .probe
                    .as_ref()
                    .is_some_and(|probe| probe.snapshot()["state"] == "running"))
        {
            return Ok(());
        }
        self.stop(namespace.clone())?;
        self.path = wanted;
        if let Some(path) = &self.path {
            kernel(namespace.clone(), Some(path.clone()), None)?;
            let mut config = serde_json::to_value(&self.config)?;
            config.as_object_mut().unwrap().remove("metadata");
            config["source_address"] = json!(path.source.to_string());
            config["gateway"] = json!(path.gateway);
            config["routing_table"] = json!(path.table);
            self.probe = Some(GatewayProbe::start(&config, namespace)?);
        }
        Ok(())
    }

    fn status(&self) -> Value {
        let snapshot = self.probe.as_ref().map(GatewayProbe::snapshot);
        let mut row = snapshot
            .as_ref()
            .and_then(|value| value.get("statistics"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let running = snapshot
            .as_ref()
            .is_some_and(|value| value["state"] == "running");
        row["name"] = json!(self.config.name);
        row["mode"] = json!("dhcp");
        row["interface"] = json!(self.config.interface);
        row["resolved_source_address"] = self
            .path
            .as_ref()
            .map(|path| json!(path.source.to_string()))
            .unwrap_or(Value::Null);
        row["resolved_gateway"] = self
            .path
            .as_ref()
            .filter(|path| !path.direct)
            .map(|path| json!(path.gateway))
            .unwrap_or(Value::Null);
        row["resolved_routing_table"] = self
            .path
            .as_ref()
            .map(|path| json!(path.table))
            .unwrap_or(Value::Null);
        row["process_state"] = json!(if running {
            "running"
        } else if self.reason.is_some() {
            "error"
        } else {
            "waiting"
        });
        row["reason"] = self
            .reason
            .as_ref()
            .map(|reason| json!(reason))
            .unwrap_or_else(|| {
                if running {
                    Value::Null
                } else {
                    json!("waiting for DHCP lease")
                }
            });
        if !running || self.reason.is_some() {
            row["health"] = json!("unknown");
            row["sample_status"] = json!(if self.reason.is_some() {
                "unavailable"
            } else {
                "waiting_for_dhcp"
            });
        }
        row
    }
}

pub struct Manager {
    namespace: Arc<File>,
    leases: Arc<Mutex<dhcp_client::State>>,
    rows: Arc<Mutex<BTreeMap<String, Value>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
}

impl Manager {
    pub fn new(namespace: Arc<File>, leases: Arc<Mutex<dhcp_client::State>>) -> Self {
        Self {
            namespace,
            leases,
            rows: Arc::new(Mutex::new(BTreeMap::new())),
            stop: Arc::new(AtomicBool::new(false)),
            join: None,
        }
    }

    pub fn configure(&mut self, value: &Value) -> Result<()> {
        self.shutdown()?;
        kernel(self.namespace.clone(), None, None)?;
        let config: Config = serde_json::from_value(value.clone())?;
        let monitors: Vec<_> = config
            .gateway_monitors
            .iter()
            .filter(|monitor| monitor.mode == GatewayMode::Dhcp && monitor.enabled)
            .cloned()
            .collect();
        ensure!(monitors.len() <= 64, "at most 64 DHCP gateway monitors");
        if monitors.is_empty() {
            return Ok(());
        }
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = self.stop.clone();
        let rows = self.rows.clone();
        let leases = self.leases.clone();
        let namespace = self.namespace.clone();
        self.join = Some(
            std::thread::Builder::new()
                .name("nc-dhcp-monitors".into())
                .spawn(move || {
                    let mut entries: Vec<_> = monitors
                        .into_iter()
                        .enumerate()
                        .map(|(index, monitor)| Entry {
                            config: monitor,
                            table: FIRST_TABLE + index as u32,
                            path: None,
                            probe: None,
                            reason: None,
                        })
                        .collect();
                    while !stop.load(Ordering::Acquire) {
                        let state = leases
                            .lock()
                            .map_err(|_| anyhow::anyhow!("DHCP state poisoned"))?;
                        for entry in &mut entries {
                            let result = resolve(&entry.config, entry.table, &state, &config)
                                .and_then(|path| entry.reconcile(path, namespace.clone()));
                            entry.reason = if let Err(error) = result {
                                let cleanup = entry.stop(namespace.clone());
                                Some(format!(
                                    "{error:#}{}",
                                    cleanup
                                        .err()
                                        .map(|error| format!("; cleanup: {error:#}"))
                                        .unwrap_or_default()
                                ))
                            } else {
                                None
                            };
                            rows.lock()
                                .map_err(|_| anyhow::anyhow!("monitor status poisoned"))?
                                .insert(entry.config.name.clone(), entry.status());
                        }
                        drop(state);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    for entry in &mut entries {
                        entry.stop(namespace.clone())?;
                    }
                    Ok(())
                })?,
        );
        Ok(())
    }

    pub fn merge(&self, value: &mut Value) -> Result<()> {
        let rows = self
            .rows
            .lock()
            .map_err(|_| anyhow::anyhow!("monitor status poisoned"))?;
        for row in value.as_array_mut().context("monitor rows missing")? {
            if let Some(dynamic) = row["name"].as_str().and_then(|name| rows.get(name)) {
                for (key, value) in dynamic.as_object().unwrap() {
                    row[key] = value.clone();
                }
            }
        }
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = &self.join {
            let deadline = Instant::now() + Duration::from_secs(80);
            while !join.is_finished() {
                ensure!(
                    Instant::now() < deadline,
                    "DHCP monitor shutdown timed out; ownership retained"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            self.join
                .take()
                .unwrap()
                .join()
                .map_err(|_| anyhow::anyhow!("DHCP monitor supervisor panicked"))??;
        }
        self.rows
            .lock()
            .map_err(|_| anyhow::anyhow!("monitor status poisoned"))?
            .clear();
        Ok(())
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        let _ = self.shutdown();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> Config {
        let mut config: Config = serde_json::from_value(json!({"interfaces":[
            {"name":"wan0","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":[]},
            {"name":"wan1","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":[]}],
            "dhcp_clients":{"wan0":{},"wan1":{}},
            "gateway_monitors":[{"name":"first","enabled":true,"mode":"dhcp","interface":"wan0","target":"1.1.1.1"},
                {"name":"second","enabled":true,"mode":"dhcp","interface":"wan1","target":"1.1.1.1"},
                {"name":"third","enabled":true,"mode":"dhcp","interface":"wan0","target":"1.0.0.1"},
                {"name":"fourth","enabled":true,"mode":"dhcp","interface":"wan0","target":"1.1.1.1"}]})).unwrap();
        config.normalize();
        config
    }

    fn lease(config: &Config, interface: &str, address: &str, gateway: &str) -> dhcp_client::Lease {
        let prefix: ipnet::Ipv4Net = address.parse().unwrap();
        dhcp_client::Lease {
            client: config.dhcp_clients[interface].clone(),
            address: address.into(),
            server: gateway.parse().unwrap(),
            acquired_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            lifetime: 3600,
            renewal: 1800,
            rebinding: 3150,
            routes: vec![
                crate::model::Route {
                    destination: prefix.trunc().to_string(),
                    gateway: String::new(),
                    interface: interface.into(),
                    table: 254,
                    metric: 100,
                },
                crate::model::Route {
                    destination: "0.0.0.0/0".into(),
                    gateway: gateway.into(),
                    interface: interface.into(),
                    table: 254,
                    metric: 100,
                },
            ],
            dns: vec![],
            domain: String::new(),
            mtu: None,
        }
    }

    #[test]
    fn dhcp_gateway_resolution_is_selected_lease_only_and_renewal_stable() {
        let config = configuration();
        config.validate().unwrap();
        let mut state = dhcp_client::State::default();
        let monitor = &config.gateway_monitors[0];
        state.leases.insert(
            "wan1".into(),
            lease(&config, "wan1", "192.0.2.2/24", "192.0.2.1"),
        );
        assert_eq!(
            resolve(monitor, FIRST_TABLE, &state, &config).unwrap(),
            None
        );
        state.leases.insert(
            "wan0".into(),
            lease(&config, "wan0", "198.51.100.2/24", "198.51.100.1"),
        );
        let first = resolve(monitor, FIRST_TABLE, &state, &config)
            .unwrap()
            .unwrap();
        let current = state.leases.get_mut("wan0").unwrap();
        current.acquired_at += 1;
        current.lifetime *= 2;
        current.dns.push("9.9.9.9".parse().unwrap());
        assert_eq!(
            resolve(monitor, FIRST_TABLE, &state, &config).unwrap(),
            Some(first.clone())
        );
        state.leases.get_mut("wan0").unwrap().routes[1].gateway = "198.51.100.3".into();
        assert_ne!(
            resolve(monitor, FIRST_TABLE, &state, &config).unwrap(),
            Some(first)
        );
        state
            .leases
            .get_mut("wan0")
            .unwrap()
            .routes
            .retain(|route| route.gateway.is_empty());
        assert!(resolve(monitor, FIRST_TABLE, &state, &config).is_err());
        state.leases.get_mut("wan0").unwrap().acquired_at = 0;
        assert_eq!(
            resolve(monitor, FIRST_TABLE, &state, &config).unwrap(),
            None
        );
    }

    #[test]
    fn dhcp_gateway_resolution_prefers_specific_routes_and_rejects_conflicts() {
        let config = configuration();
        let mut state = dhcp_client::State::default();
        let mut current = lease(&config, "wan0", "198.51.100.2/24", "198.51.100.1");
        current.routes.push(crate::model::Route {
            destination: "1.1.1.0/24".into(),
            gateway: "198.51.100.3".into(),
            interface: "wan0".into(),
            table: 254,
            metric: 200,
        });
        state.leases.insert("wan0".into(), current);
        assert_eq!(
            resolve(&config.gateway_monitors[0], FIRST_TABLE, &state, &config)
                .unwrap()
                .unwrap()
                .gateway,
            "198.51.100.3"
        );
        let mut conflicting = state.leases["wan0"].routes[2].clone();
        conflicting.gateway = "198.51.100.4".into();
        state
            .leases
            .get_mut("wan0")
            .unwrap()
            .routes
            .push(conflicting);
        assert!(resolve(&config.gateway_monitors[0], FIRST_TABLE, &state, &config).is_err());
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux namespace/net_admin/raw privileges"]
    fn dhcp_gateway_workers_follow_leases_without_cross_wan_fallback() -> Result<()> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "integration opt-in required"
        );
        let namespace = std::thread::spawn(|| -> Result<Arc<File>> {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                "unshare: {}",
                std::io::Error::last_os_error()
            );
            Ok(Arc::new(File::open("/proc/thread-self/ns/net")?))
        })
        .join()
        .unwrap()?;
        session(namespace.clone(), |runtime, handle| {
            runtime.block_on(async {
                for (interface, address) in [("wan0", "198.51.100.2"), ("wan1", "192.0.2.2")] {
                    handle
                        .link()
                        .add()
                        .dummy(interface.into())
                        .execute()
                        .await?;
                    let link = super::super::networking::links(handle)
                        .await?
                        .into_iter()
                        .find(|link| super::super::networking::name(link) == interface)
                        .unwrap();
                    handle.link().set(link.header.index).up().execute().await?;
                    handle
                        .address()
                        .add(link.header.index, address.parse()?, 24)
                        .execute()
                        .await?;
                }
                let other = super::super::networking::links(handle)
                    .await?
                    .into_iter()
                    .find(|link| super::super::networking::name(link) == "wan1")
                    .unwrap()
                    .header
                    .index;
                handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                    .gateway("192.0.2.1".parse()?)
                    .output_interface(other)
                    .table_id(254)
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
        let config = configuration();
        let leases = Arc::new(Mutex::new(dhcp_client::State::default()));
        let mut manager = Manager::new(namespace.clone(), leases.clone());
        manager.configure(&config.operational_value()?)?;
        fn wait(manager: &Manager, name: &str, state: &str) -> Value {
            let until = Instant::now() + Duration::from_secs(15);
            loop {
                let rows = manager.rows.lock().unwrap();
                let row = rows.get(name).cloned().unwrap_or(Value::Null);
                drop(rows);
                if row["process_state"] == state
                    && (state != "running" || row["started_at"].is_string())
                {
                    return row;
                }
                assert!(Instant::now() < until, "expected {name} {state}: {row}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        assert_eq!(wait(&manager, "first", "waiting")["health"], "unknown");
        leases.lock().unwrap().leases.insert(
            "wan1".into(),
            lease(&config, "wan1", "192.0.2.2/24", "192.0.2.1"),
        );
        wait(&manager, "second", "running");
        assert_eq!(
            wait(&manager, "first", "waiting")["resolved_source_address"],
            Value::Null
        );
        leases.lock().unwrap().leases.insert(
            "wan0".into(),
            lease(&config, "wan0", "198.51.100.2/24", "198.51.100.1"),
        );
        let running = wait(&manager, "first", "running");
        wait(&manager, "third", "running");
        wait(&manager, "fourth", "running");
        leases
            .lock()
            .unwrap()
            .leases
            .get_mut("wan0")
            .unwrap()
            .acquired_at += 1;
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            wait(&manager, "first", "running")["started_at"],
            running["started_at"]
        );
        leases
            .lock()
            .unwrap()
            .leases
            .get_mut("wan0")
            .unwrap()
            .routes[1]
            .gateway = "198.51.100.3".into();
        let until = Instant::now() + Duration::from_secs(15);
        while wait(&manager, "first", "running")["resolved_gateway"] != "198.51.100.3" {
            ensure!(Instant::now() < until, "gateway change not followed");
            std::thread::sleep(Duration::from_millis(20));
        }
        leases
            .lock()
            .unwrap()
            .leases
            .get_mut("wan0")
            .unwrap()
            .routes
            .retain(|route| route.gateway.is_empty());
        assert_eq!(wait(&manager, "first", "error")["health"], "unknown");
        assert_eq!(
            wait(&manager, "second", "running")["resolved_source_address"],
            "192.0.2.2"
        );
        leases
            .lock()
            .unwrap()
            .leases
            .get_mut("wan0")
            .unwrap()
            .acquired_at = 0;
        assert_eq!(wait(&manager, "first", "waiting")["health"], "unknown");
        session(namespace.clone(), |runtime, handle| {
            runtime.block_on(async {
                let index = super::super::networking::links(handle)
                    .await?
                    .into_iter()
                    .find(|link| super::super::networking::name(link) == "wan0")
                    .unwrap()
                    .header
                    .index;
                handle
                    .address()
                    .add(index, "198.51.100.4".parse()?, 24)
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
        leases.lock().unwrap().leases.insert(
            "wan0".into(),
            lease(&config, "wan0", "198.51.100.4/24", "198.51.100.1"),
        );
        assert_eq!(
            wait(&manager, "first", "running")["resolved_source_address"],
            "198.51.100.4"
        );
        manager.shutdown()?;
        let stale = resolve(
            &config.gateway_monitors[0],
            LAST_TABLE,
            &leases.lock().unwrap(),
            &config,
        )?
        .unwrap();
        kernel(namespace.clone(), Some(stale), None)?;
        manager.configure(&config.operational_value()?)?;
        wait(&manager, "first", "running");
        manager.configure(&Config::empty().operational_value()?)?;
        session(namespace, |runtime, handle| {
            runtime.block_on(async {
                assert!(
                    handle
                        .rule()
                        .get(IpVersion::V4)
                        .execute()
                        .try_collect::<Vec<_>>()
                        .await?
                        .iter()
                        .all(|rule| !rule
                            .attributes
                            .contains(&RuleAttribute::Protocol(RouteProtocol::Other(PROTOCOL))))
                );
                assert!(
                    handle
                        .route()
                        .get(IpVersion::V4)
                        .execute()
                        .try_collect::<Vec<_>>()
                        .await?
                        .iter()
                        .all(|route| route.header.protocol != RouteProtocol::Other(PROTOCOL))
                );
                Ok(())
            })
        })
    }
}
