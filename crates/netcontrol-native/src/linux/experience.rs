use super::{deny_log, experience_kernel as kernel};
use crate::{
    experience_analysis::Analyzer,
    experience_store::{Collection, Diagnostics, Filter, Source, Store},
    model::Network,
    netlink_decode::{attributes, c_string},
};
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use ipnet::IpNet;
use netcontrol_core::{
    Config, ExperienceRead, HostExperienceError, Version,
    experience::{
        self, Activity, AddressFamily, Connections, Coverage, EvidenceBucket, Firewall,
        HostIdentity, InterfaceIdentity, Metadata, Sample, SourceStatus, Traffic,
    },
};
use netlink_packet_route::{
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState},
    route::{RouteAddress, RouteAttribute, RouteScope},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    net::IpAddr,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Default)]
struct View {
    hosts: BTreeMap<IpAddr, HostIdentity>,
    interfaces: BTreeMap<String, String>,
    unmapped: Vec<Value>,
    excluded: usize,
}
struct Control {
    config: Option<Arc<Config>>,
    revision: Option<Version>,
    generation: u64,
    paused: bool,
    view: View,
    status: Value,
}
struct Shared {
    control: Mutex<Control>,
    store: Mutex<Option<Store>>,
    stop: AtomicBool,
    observing: AtomicBool,
    pause_ack: AtomicU64,
    connections: Mutex<Option<ConnectionSnapshot>>,
}
#[derive(Clone)]
struct ConnectionSnapshot {
    generation: u64,
    at_ms: i64,
    duration_ms: u64,
    counts: Option<BTreeMap<IpAddr, [u64; 3]>>,
    error: Option<String>,
}
struct ConnectionRequest {
    generation: u64,
    addresses: BTreeSet<IpAddr>,
}
fn connection_worker(shared: &Shared, receive: mpsc::Receiver<ConnectionRequest>) -> Result<()> {
    for request in receive {
        if shared.stop.load(Ordering::Acquire) {
            break;
        }
        let start = Instant::now();
        let mut counts = BTreeMap::new();
        let collected = super::netfilter::with_budget(Duration::from_secs(2), || {
            super::netfilter::visit_messages(1, 1, libc::AF_UNSPEC as u8, &[], &mut |payload| {
                crate::conntrack::add_host_counts(payload, &request.addresses, &mut counts)
            })
        });
        let snapshot = ConnectionSnapshot {
            generation: request.generation,
            at_ms: wall_ms()?,
            duration_ms: start.elapsed().as_millis().try_into()?,
            counts: if collected.is_ok() {
                Some(counts)
            } else {
                None
            },
            error: collected.as_ref().err().map(message),
        };
        let control = shared
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
        if control.generation == request.generation && !control.paused {
            *shared
                .connections
                .lock()
                .map_err(|_| anyhow::anyhow!("experience connections poisoned"))? = Some(snapshot);
        }
    }
    Ok(())
}
fn fresh_connections(
    snapshot: Option<ConnectionSnapshot>,
    generation: u64,
    now: i64,
) -> (Option<ConnectionSnapshot>, Option<String>) {
    match snapshot {
        Some(snapshot)
            if snapshot.generation == generation
                && (0..=2500).contains(&(now - snapshot.at_ms)) =>
        {
            if snapshot.counts.is_some() {
                (Some(snapshot), None)
            } else {
                (None, snapshot.error)
            }
        }
        _ => (
            None,
            Some("conntrack snapshot not ready or older than 2500 milliseconds".into()),
        ),
    }
}
pub(super) struct Manager {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<Result<()>>>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    collection: Option<String>,
    view: String,
    filter: Filter,
    limit: usize,
    after: IpAddr,
    issued_ms: i64,
}
enum Query {
    Latest(experience::LatestQuery),
    History(experience::HistoryQuery),
}
fn error(status: u16, message: impl Into<String>) -> anyhow::Error {
    HostExperienceError {
        status,
        message: message.into(),
    }
    .into()
}
fn wall_ms() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn iso(ms: i64) -> Result<String> {
    Ok(
        time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)?
            .format(&time::format_description::well_known::Rfc3339)?,
    )
}
fn uuid() -> Result<String> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/uuid")?;
    Ok(id.trim().to_owned())
}
fn message(error: &anyhow::Error) -> String {
    error
        .to_string()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(256)
        .collect()
}
impl Manager {
    pub(super) fn open(namespace: Arc<File>, root: PathBuf) -> Result<Arc<Self>> {
        let shared = Arc::new(Shared {
            control: Mutex::new(Control {
                config: None,
                revision: None,
                generation: 0,
                paused: true,
                view: View::default(),
                status: json!({"status":"starting","error":null}),
            }),
            store: Mutex::new(None),
            stop: AtomicBool::new(false),
            observing: AtomicBool::new(false),
            pause_ack: AtomicU64::new(0),
            connections: Mutex::new(None),
        });
        let output = shared.clone();
        let worker = thread::Builder::new()
            .name("host-experience".into())
            .spawn(move || {
                let result = run(&output, namespace, root);
                if let Err(error) = &result {
                    tracing::error!(%error,"protected-host experience worker failed");
                    if let Ok(mut control) = output.control.lock() {
                        control.status = json!({"status":"unavailable","error":message(error)});
                    }
                }
                result
            })?;
        Ok(Arc::new(Self {
            shared,
            worker: Mutex::new(Some(worker)),
        }))
    }
    pub(super) fn configure(&self, config: &Config, revision: Version, paused: bool) -> Result<()> {
        let mut control = self
            .shared
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
        if control.revision != Some(revision) {
            control.config = Some(Arc::new(config.clone()));
            control.revision = Some(revision);
            control.view.hosts.clear();
            control.view.interfaces = config
                .interfaces
                .iter()
                .map(|link| (link.name.clone(), link.role.clone()))
                .collect();
            control.generation = control
                .generation
                .checked_add(1)
                .context("experience generation exhausted")?;
        }
        if control.paused != paused {
            control.paused = paused;
            control.generation = control
                .generation
                .checked_add(1)
                .context("experience generation exhausted")?;
        }
        Ok(())
    }
    pub(super) fn pause(&self) -> Result<()> {
        let mut control = self
            .shared
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
        control.paused = true;
        control.generation = control
            .generation
            .checked_add(1)
            .context("experience generation exhausted")?;
        control.status["status"] = json!("partial");
        control.status["reasons"] = json!(["configuration_transition"]);
        let generation = control.generation;
        drop(control);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.shared.observing.load(Ordering::Acquire)
            && self.shared.pause_ack.load(Ordering::Acquire) < generation
        {
            ensure!(
                Instant::now() < deadline,
                "protected-host observer pause acknowledgement timed out"
            );
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }
    pub(super) fn status(&self) -> Result<Value> {
        let control = self
            .shared
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
        let mut status = control.status.clone();
        status["eligible_addresses"] = json!(control.view.hosts.len());
        status["unmapped_addresses"] = json!(control.view.unmapped.len());
        status["excluded_addresses"] = json!(control.view.excluded);
        status["unmapped"] = json!(control.view.unmapped);
        status["analysis_memory_bound_bytes"] =
            json!(crate::experience_analysis::working_memory_bound());
        self.checked_status(status)
    }
    fn checked_status(&self, mut status: Value) -> Result<Value> {
        if !self.shared.stop.load(Ordering::Acquire)
            && self
                .worker
                .lock()
                .map_err(|_| anyhow::anyhow!("experience worker poisoned"))?
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
        {
            status["status"] = json!("unavailable");
            if status["error"].is_null() {
                status["error"] =
                    json!("protected-host experience worker exited; restart the daemon");
            }
        }
        Ok(status)
    }
    pub(super) fn prepare_read(
        self: &Arc<Self>,
        path: &str,
        query: &str,
    ) -> Result<ExperienceRead> {
        let query = if path.ends_with("/latest") {
            Query::Latest(
                experience::LatestQuery::parse(query).map_err(|e| error(400, e.to_string()))?,
            )
        } else {
            Query::History(
                experience::HistoryQuery::parse(query).map_err(|e| error(400, e.to_string()))?,
            )
        };
        let manager = self.clone();
        let (view, status) = {
            let control = self
                .shared
                .control
                .lock()
                .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
            (control.view.clone(), control.status.clone())
        };
        let status = self.checked_status(status)?;
        Ok(Box::new(move || manager.read(query, view, status)))
    }
    fn read(&self, query: Query, view: View, status: Value) -> Result<Value> {
        let now = wall_ms()?;
        if status["status"] == "unavailable" {
            return Err(error(
                503,
                status["error"]
                    .as_str()
                    .unwrap_or("experience collector unavailable"),
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        let store = loop {
            match self.shared.store.try_lock() {
                Ok(store) => break store,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(error(503, "experience storage poisoned"));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(error(503, "experience storage busy; retry later"));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            }
        };
        let Some(store) = store.as_ref() else {
            return if matches!(query, Query::Latest(_)) && status["status"] == "starting" {
                self.starting(query, &view, &status)
            } else {
                Err(error(503, "experience storage is not ready"))
            };
        };
        match query {
            Query::Latest(query) => {
                let filter = Filter {
                    address: query.address.map(|ip| ip.to_string()),
                    interface: query.interface.clone(),
                };
                check_interface(&view, &query)?;
                let identities = filtered_hosts(&view, &query);
                let view_hash = hex::encode(Sha256::digest(serde_json::to_vec(&identities)?));
                let mut after = None;
                let mut collection = if let Some(token) = query.cursor.as_deref() {
                    let cursor: Cursor = serde_json::from_slice(
                        &hex::decode(token).map_err(|_| error(400, "invalid experience cursor"))?,
                    )
                    .map_err(|_| error(400, "invalid experience cursor"))?;
                    ensure_cursor(&cursor, &filter, query.limit, &view_hash, now)?;
                    if !identities
                        .iter()
                        .any(|host| host.ip_address == cursor.after)
                    {
                        return Err(error(400, "invalid experience cursor position"));
                    }
                    after = Some(cursor.after);
                    if let Some(id) = cursor.collection {
                        Some(
                            store
                                .collection_for_addresses(&id, &[], now)?
                                .ok_or_else(|| {
                                    error(
                                        409,
                                        "expired experience collection; restart latest paging",
                                    )
                                })?,
                        )
                    } else {
                        None
                    }
                } else {
                    store.latest_collection(now, &Filter::default(), 1, None)?
                };
                let remaining: Vec<_> = identities
                    .into_iter()
                    .filter(|host| after.is_none_or(|ip| host.ip_address > ip))
                    .collect();
                let more = remaining.len() > query.limit;
                let hosts: Vec<_> = remaining.into_iter().take(query.limit).collect();
                if let Some(header) = &collection {
                    let addresses: Vec<_> = hosts.iter().map(|host| host.ip_address).collect();
                    collection = Some(
                        store
                            .collection_for_addresses(&header.id, &addresses, now)?
                            .ok_or_else(|| {
                                error(409, "expired experience collection; restart latest paging")
                            })?,
                    );
                }
                let cursor = if more {
                    Some(hex::encode(serde_json::to_vec(&Cursor {
                        collection: collection.as_ref().map(|c| c.id.clone()),
                        view: view_hash,
                        filter,
                        limit: query.limit,
                        after: hosts
                            .last()
                            .context("page missing last address")?
                            .ip_address,
                        issued_ms: now,
                    })?))
                } else {
                    None
                };
                let mut rows = Vec::new();
                for host in hosts {
                    let sample = collection.as_ref().and_then(|c| {
                        c.samples.iter().find(|sample| {
                            sample.ip_address == host.ip_address
                                && sample.configured_host_id == host.configured_host_id
                                && sample.interface == host.interface
                        })
                    });
                    let usage = store.usage(host.ip_address, now)?;
                    let mut row = serde_json::to_value(host)?;
                    row["sample"] = json!(sample);
                    row["retained_usage"] = json!({"sent_bytes":usage.sent_bytes.map(|v|v.to_string()),
                        "received_bytes":usage.received_bytes.map(|v|v.to_string()),
                        "coverage_seconds":usage.coverage_ms as f64/1000.0,"complete":usage.complete});
                    rows.push(row);
                }
                let mut result = envelope("latest", &view, &status, collection.as_ref(), now)?;
                result["hosts"] = json!(rows);
                result["next_cursor"] = json!(cursor);
                result["clock_discontinuity"] = json!(store.clock_discontinuity(now)?);
                Ok(result)
            }
            Query::History(query) => {
                let history = store.history(query.address, now)?;
                let last = history
                    .slots
                    .iter()
                    .rev()
                    .find_map(|slot| slot.sample.as_ref());
                let host=view.hosts.get(&query.address).cloned().or_else(||last.map(|sample|HostIdentity{
                    ip_address:sample.ip_address,address_family:if sample.ip_address.is_ipv4(){AddressFamily::Ipv4}else{AddressFamily::Ipv6},
                    configured_host_id:sample.configured_host_id.clone(),configured_name:sample.configured_name.clone(),
                    currently_protected:false,interface:sample.interface.clone(),metadata:Metadata::default(),
                })).ok_or_else(||error(404,"address has no eligible protected-host attachment or retained LAN history"))?;
                let observed = history
                    .slots
                    .iter()
                    .filter(|slot| slot.sample.is_some())
                    .count();
                let complete = history.slots.len() == 360
                    && history.slots.iter().all(|slot| {
                        slot.sample
                            .as_ref()
                            .is_some_and(|sample| sample.coverage.complete)
                    });
                let latest = store.latest_collection(now, &Filter::default(), 1, None)?;
                let mut result = envelope("history", &view, &status, latest.as_ref(), now)?;
                let mut slots = Vec::with_capacity(history.slots.len());
                let start = history
                    .slots
                    .first()
                    .context("history window has no slots")?
                    .start_ms;
                let end = history
                    .slots
                    .last()
                    .context("history window has no slots")?
                    .end_ms;
                for slot in history.slots {
                    slots.push(json!({"start_at":iso(slot.start_ms)?,"end_at":iso(slot.end_ms)?,
                        "status":if slot.sample.is_some(){"observed"}else{"missing"},"sample":slot.sample}));
                }
                result["host"] = serde_json::to_value(host)?;
                result["window"] = json!({"start_at":iso(start)?,"end_at":iso(end)?});
                result["returned_samples"] = json!(observed);
                result["expected_slots"] = json!(360);
                result["coverage_complete"] = json!(complete);
                result["clock_discontinuity"] = json!(history.clock_discontinuity);
                result["samples"] = json!(slots);
                result["status"] = if observed > 0 {
                    json!(if complete { "available" } else { "partial" })
                } else {
                    json!("starting")
                };
                Ok(result)
            }
        }
    }
    fn starting(&self, query: Query, view: &View, status: &Value) -> Result<Value> {
        let Query::Latest(query) = query else {
            return Err(error(503, "experience storage is not ready"));
        };
        check_interface(view, &query)?;
        if query.cursor.is_some() {
            return Err(error(
                409,
                "experience storage is starting; restart latest paging",
            ));
        }
        if filtered_hosts(view, &query).len() > query.limit {
            return Err(error(
                503,
                "experience storage is initializing; retry latest paging",
            ));
        }
        let mut rows = Vec::new();
        for host in filtered_hosts(view, &query).into_iter().take(query.limit) {
            let mut row = serde_json::to_value(host)?;
            row["sample"] = Value::Null;
            row["retained_usage"] = json!({"sent_bytes":null,"received_bytes":null,"coverage_seconds":0,"complete":false});
            rows.push(row);
        }
        let mut result = envelope("latest", view, status, None, wall_ms()?)?;
        result["hosts"] = json!(rows);
        result["next_cursor"] = Value::Null;
        Ok(result)
    }
    pub(super) fn shutdown(&self) -> Result<()> {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(worker) = self
            .worker
            .lock()
            .map_err(|_| anyhow::anyhow!("experience worker poisoned"))?
            .take()
        {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("experience worker panicked"))??;
        }
        Ok(())
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            tracing::error!(%error,"experience shutdown failed");
        }
    }
}
fn check_interface(view: &View, query: &experience::LatestQuery) -> Result<()> {
    if let Some(name) = &query.interface {
        let role = view
            .interfaces
            .get(name)
            .ok_or_else(|| error(404, "unknown managed interface"))?;
        if role != "lan" {
            return Err(error(
                422,
                "host experience requires a managed LAN interface",
            ));
        }
    }
    Ok(())
}
fn filtered_hosts(view: &View, query: &experience::LatestQuery) -> Vec<HostIdentity> {
    view.hosts
        .values()
        .filter(|host| query.address.is_none_or(|ip| host.ip_address == ip))
        .filter(|host| {
            query
                .interface
                .as_ref()
                .is_none_or(|name| host.interface.as_ref().is_some_and(|i| &i.name == name))
        })
        .cloned()
        .collect()
}
fn ensure_cursor(
    cursor: &Cursor,
    filter: &Filter,
    limit: usize,
    view: &str,
    now: i64,
) -> Result<()> {
    if &cursor.filter != filter || cursor.limit != limit {
        return Err(error(400, "experience cursor does not match query filters"));
    }
    if cursor.view != view || cursor.issued_ms > now || now - cursor.issued_ms >= 3_600_000 {
        return Err(error(
            409,
            "experience collection or host attachment changed; restart latest paging",
        ));
    }
    Ok(())
}
fn envelope(
    kind: &str,
    view: &View,
    status: &Value,
    collection: Option<&Collection>,
    now: i64,
) -> Result<Value> {
    if let Some(collection) = collection {
        ensure!(
            collection.end_ms - collection.start_ms == 10_000,
            "invalid completed experience collection interval"
        );
    }
    let age = collection.map(|c| now.saturating_sub(c.end_ms));
    let response_status = if age.is_some_and(|age| age > 30_000) {
        "stale"
    } else if collection.is_none() {
        "starting"
    } else if status["status"] == "partial"
        || collection.is_some_and(|c| {
            c.diagnostics
                .sources
                .iter()
                .any(|source| source.status != "available")
        })
        || collection.is_some_and(|c| c.samples.iter().any(|s| !s.coverage.complete))
    {
        "partial"
    } else {
        "available"
    };
    let diagnostics = collection.map(|c| &c.diagnostics);
    Ok(json!({
        "schema":experience::SCHEMA,"kind":kind,"interval_seconds":10,"retention_seconds":3600,
        "status":response_status,"error":status["error"],"collection_id":collection.map(|c|&c.id),
        "collected_at":collection.map(|c|iso(c.end_ms)).transpose()?,"age_ms":age,
        "clock_discontinuity":collection.is_some_and(|c|c.clock_discontinuity),
        "collector":{
            "eligible_addresses":view.hosts.len(),"unmapped_addresses":view.unmapped.len(),"excluded_addresses":view.excluded,
            "unmapped":view.unmapped,
            "capture_dropped_packets":diagnostics.and_then(|d|d.capture_dropped_packets).map(|v|v.to_string()),
            "analysis_exclusions":diagnostics.and_then(|d|d.analysis_exclusions).map(|v|v.to_string()),
            "tracking_evictions":diagnostics.and_then(|d|d.tracking_evictions).map(|v|v.to_string()),
            "dropped_unattributed_packets":diagnostics.and_then(|d|d.dropped_unattributed_packets).map(|v|v.to_string()),
            "sources":diagnostics.map(|d|d.sources.iter().map(|s|json!({"name":s.name,"status":s.status,"error":s.error})).collect::<Vec<_>>()).unwrap_or_default(),
            "reasons":diagnostics.map(|d|d.reasons.clone()).unwrap_or_else(||vec!["insufficient_samples".into()])
        }
    }))
}

async fn discover(handle: &rtnetlink::Handle, config: &Config) -> Result<View> {
    let network = Network::parse(&config.operational_value()?)?;
    let managed = network
        .interfaces
        .iter()
        .map(|link| link.name.clone())
        .collect();
    let live_links: Vec<_> = handle.link().get().execute().try_collect().await?;
    let actual = super::networking::discover(handle, &managed).await?;
    let actual = actual.as_array().context("invalid live link inventory")?;
    let mut attachments: BTreeMap<u32, (InterfaceIdentity, Vec<IpNet>)> = BTreeMap::new();
    let mut owned = BTreeSet::new();
    for link in actual {
        let prefixes: Vec<IpNet> = link["addresses"]
            .as_array()
            .context("link addresses absent")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .context("invalid link address")?
                    .parse()
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<_>>()?;
        owned.extend(prefixes.iter().map(IpNet::addr));
        let name = link["name"].as_str().context("link name absent")?;
        if network
            .interfaces
            .iter()
            .any(|wanted| wanted.name == name && wanted.role == "lan" && wanted.up)
            && link["up"] == true
        {
            let index = u32::try_from(link["index"].as_u64().context("link index absent")?)?;
            let Some(live) = live_links.iter().find(|live| live.header.index == index) else {
                continue;
            };
            attachments.insert(
                index,
                (
                    InterfaceIdentity {
                        name: name.into(),
                        index,
                        kind: link["kind"].as_str().context("link kind absent")?.into(),
                        vlan_id: super::networking::vlan(live)?.map(|(_, id)| id),
                    },
                    prefixes,
                ),
            );
        }
    }
    for family in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
        let routes: Vec<_> = handle
            .route()
            .get(super::networking::route_query(family))
            .execute()
            .try_collect()
            .await?;
        ensure!(
            routes.len() <= 16384,
            "experience route attachment bound exceeded"
        );
        for route in routes {
            if route.header.scope != RouteScope::Link
                || route.header.destination_prefix_length == 0
                || route.attributes.iter().any(|a| {
                    matches!(
                        a,
                        RouteAttribute::Gateway(_)
                            | RouteAttribute::Via(_)
                            | RouteAttribute::MultiPath(_)
                    )
                })
            {
                continue;
            }
            let index = route.attributes.iter().find_map(|a| {
                if let RouteAttribute::Oif(index) = a {
                    Some(*index)
                } else {
                    None
                }
            });
            let destination = route.attributes.iter().find_map(|a| match a {
                RouteAttribute::Destination(RouteAddress::Inet(ip)) => Some(IpAddr::V4(*ip)),
                RouteAttribute::Destination(RouteAddress::Inet6(ip)) => Some(IpAddr::V6(*ip)),
                _ => None,
            });
            if let (Some(index), Some(destination)) = (index, destination) {
                if let Some((_, prefixes)) = attachments.get_mut(&index) {
                    prefixes.push(IpNet::new(
                        destination,
                        route.header.destination_prefix_length,
                    )?);
                }
            }
        }
    }
    let neighbours: Vec<_> = handle.neighbours().get().execute().try_collect().await?;
    ensure!(
        neighbours.len() <= 65536,
        "experience neighbor attachment bound exceeded"
    );
    let mut neighbours_by_ip: BTreeMap<IpAddr, BTreeSet<u32>> = BTreeMap::new();
    for neighbour in neighbours {
        if !attachments.contains_key(&neighbour.header.ifindex)
            || !matches!(
                neighbour.header.state,
                NeighbourState::Reachable
                    | NeighbourState::Stale
                    | NeighbourState::Delay
                    | NeighbourState::Probe
                    | NeighbourState::Permanent
                    | NeighbourState::Noarp
            )
        {
            continue;
        }
        for attribute in neighbour.attributes {
            let ip = match attribute {
                NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) => Some(IpAddr::V4(ip)),
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip)) => {
                    Some(IpAddr::V6(ip))
                }
                _ => None,
            };
            if let Some(ip) = ip {
                neighbours_by_ip
                    .entry(ip)
                    .or_default()
                    .insert(neighbour.header.ifindex);
            }
        }
    }
    let mut view = View {
        interfaces: network
            .interfaces
            .iter()
            .map(|link| (link.name.clone(), link.role.clone()))
            .collect(),
        ..View::default()
    };
    for host in config
        .firewall
        .policies
        .iter()
        .flat_map(|policies| &policies.hosts)
    {
        for address in &host.addresses {
            let ip: IpAddr = address.parse()?;
            if owned.contains(&ip) {
                view.excluded += 1;
                continue;
            }
            let candidates: Vec<_> = attachments
                .iter()
                .filter(|(_, (_, prefixes))| {
                    prefixes.iter().any(|prefix| {
                        prefix.contains(&ip)
                            && match prefix {
                                IpNet::V4(prefix) if prefix.prefix_len() < 31 => {
                                    ip != IpAddr::V4(prefix.network())
                                        && ip != IpAddr::V4(prefix.broadcast())
                                }
                                _ => true,
                            }
                    })
                })
                .collect();
            let observed: Vec<_> = candidates
                .iter()
                .filter(|(index, _)| {
                    neighbours_by_ip
                        .get(&ip)
                        .is_some_and(|neighbours| neighbours.contains(index))
                })
                .collect();
            let attachment = if observed.len() == 1 {
                Some(observed[0].1)
            } else if observed.is_empty() && candidates.len() == 1 {
                Some(candidates[0].1)
            } else {
                None
            };
            if let Some((interface, _)) = attachment {
                view.hosts.insert(
                    ip,
                    HostIdentity {
                        ip_address: ip,
                        address_family: if ip.is_ipv4() {
                            AddressFamily::Ipv4
                        } else {
                            AddressFamily::Ipv6
                        },
                        configured_host_id: host.id.clone(),
                        configured_name: host.name.clone(),
                        currently_protected: true,
                        interface: Some(interface.clone()),
                        metadata: Metadata::default(),
                    },
                );
            } else {
                view.unmapped.push(json!({"ip_address":ip,"configured_host_id":host.id,
                    "reason":if candidates.is_empty(){"no_direct_lan_attachment"}else{"ambiguous_lan_attachment"}}));
            }
        }
    }
    ensure!(
        view.hosts.len() <= experience::MAX_ADDRESSES,
        "experience address bound exceeded"
    );
    Ok(view)
}

#[derive(Clone, Default)]
struct Counters {
    sent: kernel::Count,
    received: kernel::Count,
    dropped_sent: kernel::Count,
    dropped_received: kernel::Count,
    last_seen_ms: Option<i64>,
}
struct Snapshot {
    hosts: BTreeMap<IpAddr, Counters>,
    drops_error: Option<String>,
    unattributed: Option<u64>,
    at: Instant,
    skew_ms: u64,
}
fn snapshot(addresses: &BTreeSet<IpAddr>) -> Result<Snapshot> {
    let start = Instant::now();
    super::netfilter::with_budget(Duration::from_secs(2), || {
        let mut hosts: BTreeMap<_, _> = addresses
            .iter()
            .map(|ip| (*ip, Counters::default()))
            .collect();
        for suffix in ["4", "6"] {
            for (name, sent) in [("sent", true), ("received", false)] {
                let counters = kernel::counts(kernel::TABLE, &format!("exp_{name}{suffix}"))?;
                let read_ms = wall_ms()?;
                for (ip, count) in counters {
                    let host = hosts
                        .get_mut(&ip)
                        .context("foreign experience counter address")?;
                    if let Some(age) = count.last_ms.filter(|age| *age < 3_600_000) {
                        let seen = read_ms
                            .checked_sub(i64::try_from(age)?)
                            .context("invalid activity timestamp")?;
                        host.last_seen_ms = Some(
                            host.last_seen_ms
                                .map_or(seen, |previous| previous.max(seen)),
                        );
                    }
                    if sent {
                        host.sent = count;
                    } else {
                        host.received = count;
                    }
                }
            }
        }
        let drops = (|| -> Result<Option<u64>> {
            for suffix in ["4", "6"] {
                for (name, sent) in [("sent", true), ("received", false)] {
                    for (ip, count) in
                        kernel::counts("netcontrol", &format!("exp_drop_{name}{suffix}"))?
                    {
                        if let Some(host) = hosts.get_mut(&ip) {
                            if sent {
                                host.dropped_sent = count;
                            } else {
                                host.dropped_received = count;
                            }
                        }
                    }
                }
            }
            Ok(Some(kernel::unattributed()?))
        })();
        let (unattributed, drops_error) = match drops {
            Ok(count) => (count, None),
            Err(error) => (None, Some(message(&error))),
        };
        Ok(Snapshot {
            hosts,
            drops_error,
            unattributed,
            at: Instant::now(),
            skew_ms: start.elapsed().as_millis().try_into()?,
        })
    })
}
fn deltas(before: &Counters, after: &Counters, duration: u64) -> Option<Traffic> {
    Some(Traffic::measured(
        after.sent.packets.checked_sub(before.sent.packets)?,
        after
            .received
            .packets
            .checked_sub(before.received.packets)?,
        after.sent.bytes.checked_sub(before.sent.bytes)?,
        after.received.bytes.checked_sub(before.received.bytes)?,
        duration,
    ))
}
fn observe(
    payload: &[u8],
    view: &View,
    analyzer: &mut Analyzer,
    anchor: (i64, Instant),
    previous: &mut Option<u32>,
    lost: &mut Option<u64>,
) -> Result<()> {
    ensure!(
        payload.len() >= 4 && u16::from_be_bytes(payload[2..4].try_into()?) == kernel::GROUP,
        "unexpected experience NFLOG group"
    );
    let attrs = attributes(&payload[4..])?;
    let get = |kind| {
        attrs
            .iter()
            .find(|(k, _)| k & 0x3fff == kind)
            .map(|(_, v)| v.as_slice())
    };
    let sequence = u32::from_be_bytes(get(12).context("NFLOG sequence missing")?.try_into()?);
    if let Some(last) = previous {
        let dropped = sequence.wrapping_sub(last.wrapping_add(1));
        if dropped != 0 {
            analyzer.capture_gap(u64::from(dropped));
            *lost = lost.and_then(|n| n.checked_add(u64::from(dropped)));
        }
    }
    *previous = Some(sequence);
    let sent = match c_string(get(10).context("capture prefix missing")?)? {
        "exp:sent" => true,
        "exp:received" => false,
        _ => anyhow::bail!("foreign experience capture prefix"),
    };
    let index = u32::from_be_bytes(
        get(if sent { 4 } else { 5 })
            .context("capture interface missing")?
            .try_into()?,
    );
    let packet = get(9).context("capture packet missing")?;
    let ip = match packet.first().map(|v| v >> 4) {
        Some(4) if packet.len() >= 20 => IpAddr::from(<[u8; 4]>::try_from(if sent {
            &packet[12..16]
        } else {
            &packet[16..20]
        })?),
        Some(6) if packet.len() >= 40 => IpAddr::from(<[u8; 16]>::try_from(if sent {
            &packet[8..24]
        } else {
            &packet[24..40]
        })?),
        _ => anyhow::bail!("invalid captured network header"),
    };
    let Some(host) = view.hosts.get(&ip) else {
        return Ok(());
    };
    ensure!(
        host.interface
            .as_ref()
            .is_some_and(|interface| interface.index == index),
        "capture attachment changed"
    );
    let stamp = get(3).context("NFLOG kernel timestamp missing")?;
    ensure!(stamp.len() == 16, "invalid NFLOG kernel timestamp");
    let micros = u64::from_be_bytes(stamp[..8].try_into()?)
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(u64::from_be_bytes(stamp[8..].try_into().ok()?)))
        .context("capture timestamp overflow")?;
    let anchor_micros = u64::try_from(anchor.0)?
        .checked_mul(1000)
        .context("capture anchor overflow")?;
    if micros < anchor_micros {
        return Ok(());
    }
    let at = anchor
        .1
        .checked_add(Duration::from_micros(micros - anchor_micros))
        .context("capture timestamp outside monotonic range")?;
    let now = Instant::now();
    ensure!(
        at <= now + Duration::from_millis(10)
            && now.saturating_duration_since(at) <= Duration::from_millis(250),
        "capture queue delay or clock discontinuity"
    );
    let original = if sent {
        if let Some(ct) = get(18) {
            let ct = [[payload[0], 0, 0, 0].to_vec(), ct.to_vec()].concat();
            crate::conntrack::original_destination(&ct, ip)?
        } else {
            None
        }
    } else {
        None
    };
    analyzer.observe_translated(ip, sent, packet, at, original)
}

fn run(shared: &Arc<Shared>, namespace: Arc<File>, root: PathBuf) -> Result<()> {
    let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
    let target = namespace.metadata()?;
    if current.dev() != target.dev() || current.ino() != target.ino() {
        ensure!(
            unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0,
            "enter experience namespace: {}",
            io::Error::last_os_error()
        );
    }
    let store = Store::open(&root.join("experience.sqlite"))?;
    *shared
        .store
        .lock()
        .map_err(|_| anyhow::anyhow!("experience storage poisoned"))? = Some(store);
    let capture = deny_log::socket_for(kernel::GROUP, 4608, 4 << 20, 5, 32)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (connection, handle, _) = {
        let _entered = runtime.enter();
        rtnetlink::new_connection()?
    };
    let connection = runtime.spawn(connection);
    struct Write {
        id: String,
        start: i64,
        end: i64,
        samples: Vec<Sample>,
        diagnostics: Diagnostics,
    }
    let (send, receive) = mpsc::sync_channel::<Write>(2);
    let writing = shared.clone();
    let writer = thread::Builder::new()
        .name("host-experience-writer".into())
        .spawn(move || -> Result<()> {
            loop {
                let collection = match receive.recv_timeout(Duration::from_secs(10)) {
                    Ok(collection) => Some(collection),
                    Err(mpsc::RecvTimeoutError::Timeout) => None,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let mut guard = writing
                    .store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience storage poisoned"))?;
                let store = guard.as_mut().context("experience writer unavailable")?;
                if let Some(collection) = collection {
                    store.insert_collection_with_diagnostics(
                        &collection.id,
                        collection.start,
                        collection.end,
                        &collection.samples,
                        &collection.diagnostics,
                    )?;
                    store.checkpoint()?;
                } else {
                    store.maintain(wall_ms()?)?;
                }
            }
            Ok(())
        })?;
    let (connections_send, connections_receive) = mpsc::sync_channel(1);
    let counting = shared.clone();
    let connection_worker = match thread::Builder::new()
        .name("host-experience-connections".into())
        .spawn(move || connection_worker(&counting, connections_receive))
    {
        Ok(worker) => worker,
        Err(error) => {
            drop(send);
            writer
                .join()
                .map_err(|_| anyhow::anyhow!("experience persistence writer panicked"))??;
            return Err(error).context("start experience connection worker");
        }
    };
    let mut connection_requested = None;
    let mut analyzer = Analyzer::new();
    let mut active_generation = None;
    let mut fingerprint = None;
    let mut view = View::default();
    let mut baseline = None;
    let mut evidence: BTreeMap<IpAddr, Vec<EvidenceBucket>> = BTreeMap::new();
    let mut epochs: BTreeMap<IpAddr, String> = BTreeMap::new();
    let mut anchor = (wall_ms()?, Instant::now());
    let mut next_wall = (anchor.0 / 10_000 + 1) * 10_000;
    let mut next = anchor.1 + Duration::from_millis((next_wall - anchor.0).try_into()?);
    let mut full_bucket = false;
    let mut sequence = None;
    let mut buffer = vec![0; 65536];
    let mut malformed = 0u64;
    let mut capture_lost = Some(0u64);
    shared.observing.store(true, Ordering::Release);
    let result = (|| -> Result<()> {
        while !shared.stop.load(Ordering::Acquire) {
            ensure!(
                !writer.is_finished(),
                "experience persistence writer exited"
            );
            ensure!(
                !connection_worker.is_finished(),
                "experience connection worker exited"
            );
            let (config, revision, generation, paused) = {
                let control = shared
                    .control
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
                (
                    control.config.clone(),
                    control.revision,
                    control.generation,
                    control.paused,
                )
            };
            let now = Instant::now();
            let wall = wall_ms()?;
            let clock_step = (wall
                - (anchor.0 + i64::try_from(now.duration_since(anchor.1).as_millis())?))
            .abs()
                > 1000;
            if paused || config.is_none() {
                if active_generation.take().is_some() {
                    analyzer.reset();
                    evidence.clear();
                    baseline = None;
                }
                shared.pause_ack.store(generation, Ordering::Release);
                if deny_log::poll(&capture, 100)? {
                    match deny_log::receive(&capture, &mut buffer) {
                        Ok(_) => (),
                        Err(error)
                            if error
                                .downcast_ref::<io::Error>()
                                .is_some_and(|e| e.raw_os_error() == Some(libc::ENOBUFS)) => {}
                        Err(error) => return Err(error),
                    }
                }
                continue;
            }
            let config = config.context("committed experience configuration missing")?;
            let revision = revision.context("committed experience revision missing")?;
            if active_generation != Some(generation) || clock_step {
                view = runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(2), discover(&handle, &config)).await?
                })?;
                let hosts = view
                    .hosts
                    .iter()
                    .map(|(ip, host)| {
                        Ok((
                            *ip,
                            host.interface
                                .as_ref()
                                .context("eligible host has no interface")?
                                .name
                                .clone(),
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                if let Some(expected) = &fingerprint {
                    ensure!(
                        super::netfilter::experience_fingerprint()? == *expected,
                        "experience policy drift"
                    );
                }
                kernel::install(&hosts)?;
                fingerprint = Some(super::netfilter::experience_fingerprint()?);
                analyzer.reset();
                analyzer.configure(hosts.keys().copied())?;
                evidence.clear();
                epochs = hosts
                    .keys()
                    .map(|ip| Ok((*ip, uuid()?)))
                    .collect::<Result<_>>()?;
                baseline = Some(snapshot(&hosts.keys().copied().collect())?);
                anchor = (wall_ms()?, Instant::now());
                next_wall = (anchor.0 / 10_000 + 1) * 10_000;
                next = anchor.1 + Duration::from_millis((next_wall - anchor.0).try_into()?);
                full_bucket = false;
                active_generation = Some(generation);
                sequence = None;
                connection_requested = None;
                let mut control = shared
                    .control
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
                if control.generation == generation {
                    control.view = view.clone();
                    control.status = json!({"status":"starting","error":null,
                        "reasons":[if clock_step{"clock_discontinuity"}else{"configuration_transition"}]});
                }
                if Instant::now().saturating_duration_since(
                    next.checked_sub(Duration::from_secs(2))
                        .context("invalid connection deadline")?,
                ) > Duration::ZERO
                    && connection_requested != Some((generation, next_wall))
                {
                    match connections_send.try_send(ConnectionRequest {
                        generation,
                        addresses: view.hosts.keys().copied().collect(),
                    }) {
                        Ok(()) | Err(mpsc::TrySendError::Full(_)) => (),
                        Err(mpsc::TrySendError::Disconnected(_)) => {
                            anyhow::bail!("experience connection worker unavailable")
                        }
                    }
                    connection_requested = Some((generation, next_wall));
                }
            }
            let drain_deadline = Instant::now() + Duration::from_millis(20);
            let mut wait = 20;
            while deny_log::poll(&capture, wait)? {
                match deny_log::receive(&capture, &mut buffer) {
                    Ok(length) => {
                        deny_log::frames(&buffer[..length], |kind, _, payload| {
                            ensure!(kind == 0x400, "unexpected experience capture message");
                            if let Err(error) = observe(
                                payload,
                                &view,
                                &mut analyzer,
                                anchor,
                                &mut sequence,
                                &mut capture_lost,
                            ) {
                                malformed = malformed.saturating_add(1);
                                analyzer.capture_gap(0);
                                tracing::debug!(%error,"protected-host capture excluded");
                            }
                            Ok(())
                        })?;
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.raw_os_error() == Some(libc::ENOBUFS)) =>
                    {
                        analyzer.capture_gap(0);
                        capture_lost = None;
                    }
                    Err(error) => return Err(error),
                }
                wait = 0;
                if Instant::now() >= drain_deadline {
                    if deny_log::poll(&capture, 0)? {
                        analyzer.capture_gap(0);
                        malformed = malformed.saturating_add(1);
                    }
                    break;
                }
            }
            if Instant::now() < next {
                continue;
            }
            if Instant::now().saturating_duration_since(next) >= Duration::from_secs(10) {
                active_generation = None;
                let mut control = shared
                    .control
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
                control.status =
                    json!({"status":"partial","error":null,"reasons":["missed_collection"]});
                continue;
            }
            let addresses = view.hosts.keys().copied().collect();
            ensure!(
                super::netfilter::experience_fingerprint()?
                    == *fingerprint
                        .as_ref()
                        .context("experience fingerprint missing")?,
                "experience policy drift"
            );
            let mut current = snapshot(&addresses)?;
            {
                let control = shared
                    .control
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
                if control.generation != generation || control.paused {
                    continue;
                }
            }
            let before = baseline
                .as_ref()
                .context("experience counter baseline missing")?;
            let observed_ms = wall_ms()?;
            let (connections, connections_error) = fresh_connections(
                shared
                    .connections
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience connections poisoned"))?
                    .clone(),
                generation,
                observed_ms,
            );
            for (ip, counts) in &mut current.hosts {
                let old = before
                    .hosts
                    .get(ip)
                    .context("host counter baseline missing")?;
                if old.sent.packets == counts.sent.packets
                    && old.sent.bytes == counts.sent.bytes
                    && old.received.packets == counts.received.packets
                    && old.received.bytes == counts.received.bytes
                {
                    counts.last_seen_ms = old.last_seen_ms;
                }
            }
            let duration = u64::try_from(current.at.duration_since(before.at).as_millis())?;
            let late = current.at.saturating_duration_since(next) > Duration::from_millis(250);
            let mut diagnostics = Diagnostics {
                capture_dropped_packets: capture_lost,
                analysis_exclusions: Some(malformed),
                tracking_evictions: Some(0),
                dropped_unattributed_packets: current
                    .unattributed
                    .zip(before.unattributed)
                    .and_then(|(after, before)| after.checked_sub(before)),
                sources: Vec::new(),
                reasons: Vec::new(),
            };
            let mut samples = Vec::with_capacity(view.hosts.len());
            for (ip, host) in &view.hosts {
                let counts = current
                    .hosts
                    .get(ip)
                    .context("host counter snapshot missing")?;
                let old = before
                    .hosts
                    .get(ip)
                    .context("host counter baseline missing")?;
                let mut sample = Sample::new(
                    *ip,
                    host.configured_host_id.clone(),
                    revision.to_string(),
                    epochs.get(ip).context("host epoch missing")?.clone(),
                    iso(next_wall - 10_000)?.parse()?,
                    iso(next_wall)?.parse()?,
                );
                sample.configured_name = host.configured_name.clone();
                sample.interface = host.interface.clone();
                sample.measured_duration_ms = duration;
                let traffic = deltas(old, counts, duration);
                let reset = traffic.is_none();
                if let Some(traffic) = traffic {
                    sample.traffic = traffic;
                } else {
                    sample.traffic.error = Some("counter_reset".into());
                    analyzer.reset_host(*ip);
                }
                sample.activity = if reset {
                    Activity::Unknown
                } else if sample.traffic.sent_packets.is_some_and(|count| count.0 > 0)
                    || sample
                        .traffic
                        .received_packets
                        .is_some_and(|count| count.0 > 0)
                {
                    Activity::Active
                } else {
                    Activity::Idle
                };
                if let Some(last) = counts
                    .last_seen_ms
                    .filter(|seen| observed_ms - *seen < 3_600_000)
                {
                    sample.last_seen_at = Some(iso(last)?.parse()?);
                }
                if current.drops_error.is_none() && before.drops_error.is_none() {
                    let sent = counts
                        .dropped_sent
                        .packets
                        .checked_sub(old.dropped_sent.packets);
                    let received = counts
                        .dropped_received
                        .packets
                        .checked_sub(old.dropped_received.packets);
                    sample.firewall = Firewall {
                        status: if sent.is_some() && received.is_some() {
                            SourceStatus::Available
                        } else {
                            SourceStatus::Partial
                        },
                        dropped_sent_packets: sent.map(Into::into),
                        dropped_received_packets: received.map(Into::into),
                        ..Firewall::default()
                    };
                } else {
                    sample.firewall.error =
                        Some("managed drop source unavailable; see collector diagnostics".into());
                }
                match &connections {
                    Some(connections) => {
                        let counts = connections
                            .counts
                            .as_ref()
                            .context("available conntrack snapshot has no counts")?
                            .get(ip)
                            .copied()
                            .unwrap_or([0; 3]);
                        sample.connections = Connections {
                            status: SourceStatus::Available,
                            error: None,
                            observed_at: Some(iso(connections.at_ms)?.parse()?),
                            measurement_duration_ms: Some(connections.duration_ms),
                            total: Some(counts[0].into()),
                            tcp_established: Some(counts[1].into()),
                            unreplied: Some(counts[2].into()),
                        };
                    }
                    None => sample.connections.error = connections_error.clone(),
                }
                let analysis = analyzer.finish(*ip, current.at);
                diagnostics.analysis_exclusions = diagnostics
                    .analysis_exclusions
                    .and_then(|n| n.checked_add(analysis.analysis_exclusions));
                diagnostics.tracking_evictions = diagnostics
                    .tracking_evictions
                    .and_then(|n| n.checked_add(analysis.tracking_evictions));
                sample.tcp = analysis.tcp;
                sample.dns = analysis.dns;
                sample.coverage = Coverage {
                    complete: full_bucket
                        && !late
                        && !reset
                        && analysis.capture_dropped_packets == 0
                        && analysis.evidence.tcp_complete
                        && analysis.evidence.dns_complete,
                    reasons: analysis.reasons,
                    traffic: "kernel_l3_pre_snat_sent_post_filter_received".into(),
                    firewall: "managed_nftables_only".into(),
                    tcp: "accepted_lan_tcp".into(),
                    dns: "accepted_client_visible_udp_tcp_53".into(),
                    connections: "shared_conntrack_snapshot".into(),
                };
                if !full_bucket {
                    experience::add_reason(
                        &mut sample.coverage.reasons,
                        "configuration_transition",
                    );
                }
                if late {
                    experience::add_reason(&mut sample.coverage.reasons, "capture_gap");
                }
                if reset {
                    experience::add_reason(&mut sample.coverage.reasons, "counter_reset");
                    let epoch = uuid()?;
                    epochs.insert(*ip, epoch.clone());
                    sample.observation_epoch = epoch;
                }

                if sample
                    .firewall
                    .dropped_sent_packets
                    .is_some_and(|n| n.0 > 0)
                    || sample
                        .firewall
                        .dropped_received_packets
                        .is_some_and(|n| n.0 > 0)
                {
                    experience::add_reason(&mut sample.coverage.reasons, "managed_policy_drops");
                }
                let window = evidence.entry(*ip).or_default();
                if reset {
                    window.clear();
                }
                if window.len() == 6 {
                    window.remove(0);
                }
                window.push(EvidenceBucket::from_sample(&sample, analysis.evidence));
                sample.experience = experience::score(window);
                samples.push(sample);
            }
            for (name, status, error) in [
                ("traffic", "available", None),
                (
                    "firewall",
                    if current.drops_error.is_some() {
                        "unavailable"
                    } else {
                        "available"
                    },
                    current.drops_error.clone(),
                ),
                (
                    "tcp_dns",
                    if diagnostics.capture_dropped_packets.is_none_or(|n| n > 0)
                        || diagnostics.analysis_exclusions.is_some_and(|n| n > 0)
                        || diagnostics.tracking_evictions.is_some_and(|n| n > 0)
                    {
                        "partial"
                    } else {
                        "available"
                    },
                    None,
                ),
                (
                    "connections",
                    if connections.is_some() {
                        "available"
                    } else {
                        "unavailable"
                    },
                    connections_error,
                ),
            ] {
                diagnostics.sources.push(Source {
                    name: name.into(),
                    status: status.into(),
                    error,
                });
            }
            if !full_bucket {
                diagnostics.reasons.push("configuration_transition".into());
            }
            if late {
                diagnostics.reasons.push("capture_gap".into());
            }
            let complete = samples.iter().all(|sample| sample.coverage.complete);
            let reasons = diagnostics.reasons.clone();
            {
                let control = shared
                    .control
                    .lock()
                    .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
                if control.generation != generation || control.paused {
                    continue;
                }
                send.try_send(Write {
                    id: uuid()?,
                    start: next_wall - 10_000,
                    end: next_wall,
                    samples,
                    diagnostics,
                })
                .context("experience persistence queue unavailable or full")?;
            }
            baseline = Some(current);
            malformed = 0;
            capture_lost = Some(0);
            let observed = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), discover(&handle, &config)).await?
            })?;
            let changed = serde_json::to_vec(&view.hosts)? != serde_json::to_vec(&observed.hosts)?;
            let mut control = shared
                .control
                .lock()
                .map_err(|_| anyhow::anyhow!("experience control poisoned"))?;
            if control.generation == generation {
                control.view = observed.clone();
                control.status = json!({"status":if complete{"available"}else{"partial"},
                    "error":null,"last_collected_at":iso(next_wall)?,"measurement_skew_ms":baseline.as_ref().map(|s|s.skew_ms),
                    "capture_group":kernel::GROUP,"reasons":reasons});
            }
            if changed {
                active_generation = None;
            }
            next_wall = (wall_ms()? / 10_000 + 1) * 10_000;
            next = anchor.1 + Duration::from_millis(u64::try_from(next_wall - anchor.0)?);
            full_bucket = !late;
        }
        Ok(())
    })();
    shared.observing.store(false, Ordering::Release);
    drop(connections_send);
    let counted = connection_worker
        .join()
        .map_err(|_| anyhow::anyhow!("experience connection worker panicked"))
        .and_then(|result| result);
    drop(send);
    let persisted = writer
        .join()
        .map_err(|_| anyhow::anyhow!("experience persistence writer panicked"))
        .and_then(|result| result);
    connection.abort();
    let cleanup = (|| -> Result<()> {
        if let Some(fingerprint) = fingerprint {
            kernel::remove(&fingerprint)?;
        }
        if let Some(store) = shared
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("experience storage poisoned"))?
            .take()
        {
            store.checkpoint()?;
        }
        persisted?;
        counted?;
        Ok(())
    })();
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("experience cleanup also failed: {cleanup}")))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        manager: Arc<Manager>,
        directory: PathBuf,
        end: i64,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            use std::os::unix::fs::DirBuilderExt;
            let directory = std::env::current_dir()?.join(format!(
                ".experience-api-test-{}-{}",
                std::process::id(),
                uuid()?
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
            let store = Store::open(&directory.join("experience.sqlite"))?;
            let view = View {
                hosts: [host("192.0.2.9"), host("192.0.2.10")]
                    .into_iter()
                    .map(|host| (host.ip_address, host))
                    .collect(),
                interfaces: BTreeMap::from([
                    ("vlan20".into(), "lan".into()),
                    ("wan0".into(), "wan".into()),
                ]),
                ..View::default()
            };
            let manager = Arc::new(Manager {
                shared: Arc::new(Shared {
                    control: Mutex::new(Control {
                        config: None,
                        revision: None,
                        generation: 1,
                        paused: false,
                        view,
                        status: json!({"status":"available","error":null}),
                    }),
                    store: Mutex::new(Some(store)),
                    stop: AtomicBool::new(false),
                    observing: AtomicBool::new(false),
                    pause_ack: AtomicU64::new(0),
                    connections: Mutex::new(None),
                }),
                worker: Mutex::new(None),
            });
            Ok(Self {
                manager,
                directory,
                end: (wall_ms()? / 10_000) * 10_000 - 10_000,
            })
        }
        fn insert(&self, id: &str, end: i64) -> Result<()> {
            let control = self.manager.shared.control.lock().unwrap();
            let samples = control
                .view
                .hosts
                .values()
                .map(|host| {
                    let mut sample = Sample::new(
                        host.ip_address,
                        host.configured_host_id.clone(),
                        "2026.11.14.1".into(),
                        "fixture-epoch".into(),
                        iso(end - 10_000)?.parse()?,
                        iso(end)?.parse()?,
                    );
                    sample.configured_name = host.configured_name.clone();
                    sample.interface = host.interface.clone();
                    sample.traffic = Traffic::measured(1, 2, 100, 200, 10_000);
                    sample.activity = Activity::Active;
                    Ok(sample)
                })
                .collect::<Result<Vec<_>>>()?;
            self.manager
                .shared
                .store
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .insert_collection_with_diagnostics(
                    id,
                    end - 10_000,
                    end,
                    &samples,
                    &Diagnostics::default(),
                )
        }
        fn read(&self, kind: &str, query: &str) -> Result<Value> {
            self.manager
                .prepare_read(&format!("/api/v1/statistics/host-experience/{kind}"), query)?(
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.manager.shared.store.lock().unwrap().take();
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }
    fn host(ip: &str) -> HostIdentity {
        HostIdentity {
            ip_address: ip.parse().unwrap(),
            address_family: AddressFamily::Ipv4,
            configured_host_id: "camera".into(),
            configured_name: "Camera".into(),
            currently_protected: true,
            interface: Some(InterfaceIdentity {
                name: "vlan20".into(),
                index: 20,
                kind: "vlan".into(),
                vlan_id: Some(20),
            }),
            metadata: Metadata::default(),
        }
    }
    fn status(error: anyhow::Error) -> u16 {
        error.downcast_ref::<HostExperienceError>().unwrap().status
    }
    #[test]
    fn latest_pages_pin_collection_and_reject_attachment_and_cursor_changes() -> Result<()> {
        let fixture = Fixture::new()?;
        fixture.insert("first", fixture.end)?;
        let first = fixture.read("latest", "limit=1")?;
        assert_eq!(first["hosts"][0]["ip_address"], "192.0.2.9");
        let cursor = first["next_cursor"].as_str().unwrap();
        fixture.insert("second", fixture.end + 10_000)?;
        let query = format!("limit=1&cursor={cursor}");
        let second = fixture.read("latest", &query)?;
        assert_eq!(second["collection_id"], "first");
        assert_eq!(second["hosts"][0]["ip_address"], "192.0.2.10");
        assert!(second["next_cursor"].is_null());
        assert_eq!(
            status(
                fixture
                    .read("latest", &format!("limit=2&cursor={cursor}"))
                    .unwrap_err()
            ),
            400
        );
        let mut modified: Cursor = serde_json::from_slice(&hex::decode(cursor)?)?;
        modified.after = "192.0.2.200".parse()?;
        assert_eq!(
            status(
                fixture
                    .read(
                        "latest",
                        &format!(
                            "limit=1&cursor={}",
                            hex::encode(serde_json::to_vec(&modified)?)
                        )
                    )
                    .unwrap_err()
            ),
            400
        );
        fixture
            .manager
            .shared
            .control
            .lock()
            .unwrap()
            .view
            .hosts
            .get_mut(&"192.0.2.9".parse()?)
            .unwrap()
            .configured_name = "Renamed".into();
        assert_eq!(status(fixture.read("latest", &query).unwrap_err()), 409);
        Ok(())
    }
    #[test]
    fn history_retains_removed_identity_and_new_attachment_has_no_relabelled_sample() -> Result<()>
    {
        let fixture = Fixture::new()?;
        fixture.insert("first", fixture.end)?;
        {
            let mut control = fixture.manager.shared.control.lock().unwrap();
            control.view.hosts.remove(&"192.0.2.9".parse()?);
            control
                .view
                .hosts
                .get_mut(&"192.0.2.10".parse()?)
                .unwrap()
                .configured_host_id = "replacement".into();
        }
        let latest = fixture.read("latest", "")?;
        assert_eq!(latest["hosts"].as_array().unwrap().len(), 1);
        assert!(latest["hosts"][0]["sample"].is_null());
        let history = fixture.read("history", "address=192.0.2.9")?;
        assert_eq!(history["host"]["configured_name"], "Camera");
        assert_eq!(history["host"]["currently_protected"], false);
        assert_eq!(history["samples"].as_array().unwrap().len(), 360);
        assert_eq!(
            history["window"]["start_at"],
            history["samples"][0]["start_at"]
        );
        assert_eq!(
            history["window"]["end_at"],
            history["samples"][359]["end_at"]
        );
        assert_eq!(history["returned_samples"], 1);
        assert_eq!(
            status(fixture.read("history", "address=192.0.2.200").unwrap_err()),
            404
        );
        assert_eq!(
            status(fixture.read("latest", "interface=missing").unwrap_err()),
            404
        );
        assert_eq!(
            status(fixture.read("latest", "interface=wan0").unwrap_err()),
            422
        );
        Ok(())
    }
    #[test]
    fn connection_freshness_never_substitutes_zero_for_missing_or_previous_generation() {
        let snapshot = ConnectionSnapshot {
            generation: 3,
            at_ms: 1000,
            duration_ms: 50,
            counts: Some(BTreeMap::new()),
            error: None,
        };
        assert!(
            fresh_connections(Some(snapshot.clone()), 3, 3500)
                .0
                .is_some()
        );
        assert!(
            fresh_connections(Some(snapshot.clone()), 3, 3501)
                .0
                .is_none()
        );
        assert!(
            fresh_connections(Some(snapshot.clone()), 4, 1000)
                .0
                .is_none()
        );
        assert!(fresh_connections(Some(snapshot), 3, 999).0.is_none());
        let missing = fresh_connections(None, 3, 1000);
        assert!(missing.0.is_none() && missing.1.is_some());
    }
    #[test]
    fn storage_contention_returns_bounded_error_without_stalling_configuration() -> Result<()> {
        let fixture = Fixture::new()?;
        let read = fixture
            .manager
            .prepare_read("/api/v1/statistics/host-experience/latest", "")?;
        let guard = fixture.manager.shared.store.lock().unwrap();
        let started = Instant::now();
        let worker = thread::spawn(read);
        assert!(fixture.manager.shared.control.try_lock().is_ok());
        let result = worker
            .join()
            .map_err(|_| anyhow::anyhow!("contention fixture panicked"))?;
        assert_eq!(status(result.unwrap_err()), 503);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(guard);
        assert!(fixture.read("latest", "").is_ok());
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN and CAP_NET_ADMIN; waits for two real ten-second buckets"]
    fn configured_lan_host_is_collected_persisted_and_exposed_without_http_polling() -> Result<()> {
        let fixture = Fixture::new()?;
        let root = fixture.directory.join("active");
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        thread::spawn(move||->Result<()>{
            ensure!(unsafe{libc::unshare(libc::CLONE_NEWNET)}==0,"create collection test namespace: {}",io::Error::last_os_error());
            let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(async{
                let(connection,handle,_)=rtnetlink::new_connection()?;
                let task=tokio::spawn(connection);
                handle.link().add(rtnetlink::LinkDummy::new("lan0").up().build()).execute().await?;
                let link=handle.link().get().match_name("lan0".into()).execute().try_next().await?.context("test LAN missing")?;
                handle.address().add(link.header.index,"192.0.2.1".parse()?,24).execute().await?;
                task.abort();
                Ok::<_,anyhow::Error>(())
            })?;
            let mut value=serde_json::to_value(Config::default())?;
            value["interfaces"]=json!([{"name":"lan0","kind":"ethernet","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}]);
            value["firewall"]["policies"]=json!({"hosts":[{"id":"camera","name":"Camera","addresses":["192.0.2.2"],"policy":"accept","rules":[]}],"interfaces":[]});
            let config:Config=serde_json::from_value(value)?;
            let manager=Manager::open(Arc::new(File::open("/proc/thread-self/ns/net")?),root)?;
            manager.configure(&config,"2026.11.14.1".parse()?,false)?;
            let deadline=Instant::now()+Duration::from_secs(30);
            while manager.shared.store.lock().unwrap().as_ref().is_none_or(|store|store.history("192.0.2.2".parse().unwrap(),wall_ms().unwrap()).unwrap().slots.iter().filter(|slot|slot.sample.is_some()).count()<2){
                ensure!(manager.status()?["status"]!="unavailable","active worker failed: {}",manager.status()?);
                ensure!(Instant::now()<deadline,"ten-second collector did not persist independently");
                thread::sleep(Duration::from_millis(100));
            }
            let read=manager.prepare_read("/api/v1/statistics/host-experience/latest","")?()?;
            ensure!(read["hosts"][0]["ip_address"]=="192.0.2.2","configured host not eligible: {read}");
            ensure!(read["hosts"][0]["interface"]["name"]=="lan0","wrong LAN attribution");
            let sample=&read["hosts"][0]["sample"];
            ensure!(sample["traffic"]["sent_packets"]=="0" && sample["traffic"]["received_packets"]=="0","idle kernel counters were not measured");
            ensure!(sample["experience"]["status"]=="idle" && sample["experience"]["score"].is_null(),"idle observation was falsely rated: {sample}");
            ensure!(sample["last_seen_at"].is_null(),"snapshot invented last seen");
            manager.pause()?;
            manager.shutdown()?;
            Ok(())
        }).join().map_err(|_|anyhow::anyhow!("active collection fixture panicked"))?
    }
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN and CAP_NET_ADMIN"]
    fn paused_worker_acknowledges_transition_and_joins_all_storage_and_connection_workers()
    -> Result<()> {
        let fixture = Fixture::new()?;
        let root = fixture.directory.join("live");
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let shared = thread::spawn(move || -> Result<()> {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                "create lifecycle test namespace: {}",
                io::Error::last_os_error()
            );
            let manager = Manager::open(Arc::new(File::open("/proc/thread-self/ns/net")?), root)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while !manager.shared.observing.load(Ordering::Acquire) {
                ensure!(
                    !manager
                        .worker
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .is_finished(),
                    "worker initialization failed: {}",
                    manager.status()?
                );
                ensure!(Instant::now() < deadline, "worker did not initialize");
                thread::sleep(Duration::from_millis(10));
            }
            manager.pause()?;
            let generation = manager.shared.control.lock().unwrap().generation;
            ensure!(
                manager.shared.pause_ack.load(Ordering::Acquire) >= generation,
                "pause returned before observer acknowledged"
            );
            let started = Instant::now();
            manager.shutdown()?;
            ensure!(
                started.elapsed() < Duration::from_secs(3),
                "paused shutdown was not bounded"
            );
            ensure!(
                manager.shared.store.lock().unwrap().is_none(),
                "shutdown left SQLite writer open"
            );
            ensure!(
                manager.worker.lock().unwrap().is_none(),
                "shutdown left observer handle"
            );
            manager.shutdown()?;
            Ok(())
        });
        shared
            .join()
            .map_err(|_| anyhow::anyhow!("worker lifecycle fixture panicked"))?
    }
}
