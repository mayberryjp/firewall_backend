mod kernel;
mod wire;
use anyhow::{Context, Result, anyhow, ensure};
use netcontrol_core::{BGPConfig, BGPNeighbor, Config};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wire::{Path, Prefix};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    prefix: Prefix,
    interface: String,
    gateway: Option<Ipv4Addr>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WGAddition {
    interface: String,
    key: String,
    prefix: Prefix,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    routes: Vec<Installed>,
    wg: Vec<WGAddition>,
}
pub(super) struct State {
    status: Value,
    ledger: Ledger,
}
impl State {
    pub fn effective(&self, value: &mut Value) -> Result<()> {
        for entry in &self.ledger.wg {
            for link in value["interfaces"]
                .as_array_mut()
                .context("interfaces missing")?
            {
                if link["name"] != entry.interface {
                    continue;
                }
                if let Some(peers) = link["wireguard"]["peers"].as_array_mut() {
                    for peer in peers {
                        if peer["public_key"] == entry.key {
                            let ips = peer["allowed_ips"]
                                .as_array_mut()
                                .context("AllowedIPs missing")?;
                            let prefix = json!(entry.prefix.to_string());
                            if !ips.contains(&prefix) {
                                ips.push(prefix);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
pub(super) struct Manager {
    namespace: Arc<File>,
    file: PathBuf,
    pub state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
    config: Config,
    recovery_pending: bool,
}
impl Manager {
    pub fn new(namespace: Arc<File>, root: PathBuf) -> Result<Self> {
        let file = root.join("bgp-owned.json");
        Ok(Self {
            recovery_pending: true,
            namespace,
            file,
            state: Arc::new(Mutex::new(State {
                status: json!({"name":"bgp","state":"disabled","neighbors":[],"routes":[],"advertised_routes":[],"error":null}),
                ledger: Ledger::default(),
            })),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            config: Config::empty(),
        })
    }
    pub fn recover(&mut self) -> Result<()> {
        let ledger: Ledger = if self.file.try_exists()? {
            super::read_json(&self.file)?
        } else {
            Ledger::default()
        };
        ensure!(
            ledger.routes.len() <= 32768 && ledger.wg.len() <= 32768,
            "oversized BGP ownership journal"
        );
        self.state
            .lock()
            .map_err(|_| anyhow!("BGP state poisoned"))?
            .ledger = ledger;
        self.recovery_pending = false;
        self.shutdown()
    }
    pub fn snapshot(&self) -> Result<Value> {
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow!("BGP state poisoned"))?
            .status
            .clone())
    }
    pub fn configure(&mut self, value: &Value) -> Result<()> {
        ensure!(
            !self.recovery_pending,
            "BGP ownership recovery has not completed"
        );
        self.shutdown()?;
        let config: Config = serde_json::from_value(value.clone())?;
        self.config = config.clone();
        if !config.bgp.enabled {
            self.state
                .lock()
                .map_err(|_| anyhow!("BGP state poisoned"))?
                .status = json!({"name":"bgp","state":"disabled","neighbors":[],"routes":[],"advertised_routes":[],"error":null});
            return Ok(());
        }
        self.stop = Arc::new(AtomicBool::new(false));
        self.state
            .lock()
            .map_err(|_| anyhow!("BGP state poisoned"))?
            .status = json!({"name":"bgp","state":"starting","neighbors":[],"routes":[],"advertised_routes":[],"error":null});
        let (stop, state, namespace, file) = (
            self.stop.clone(),
            self.state.clone(),
            self.namespace.clone(),
            self.file.clone(),
        );
        self.thread = Some(
            std::thread::Builder::new()
                .name("nc-bgp".into())
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let current = File::open("/proc/thread-self/ns/net")?;
                            if !super::same_file(&current, &namespace)? {
                                ensure!(
                                    unsafe {
                                        libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET)
                                    } == 0,
                                    "BGP namespace entry: {}",
                                    std::io::Error::last_os_error()
                                );
                            }
                            run(&config, &namespace, &file, &state, &stop)
                        }))
                        .unwrap_or_else(|_| Err(anyhow!("BGP worker panicked")));
                        if let Err(error) = result {
                            let mut shared =
                                state.lock().map_err(|_| anyhow!("BGP state poisoned"))?;
                            shared.status["advertised_routes"] = json!([]);
                            if let Err(cleanup) =
                                reconcile(&namespace, &file, &mut shared, &Ledger::default())
                            {
                                shared.status["error"] =
                                    json!(format!("{error:#}; BGP cleanup failed: {cleanup:#}"));
                            } else {
                                shared.status["routes"] = json!([]);
                                shared.status["error"] = json!(format!("{error:#}"));
                            }
                            shared.status["state"] = json!("error");
                            drop(shared);
                            for _ in 0..10 {
                                if stop.load(Ordering::Acquire) {
                                    break;
                                }
                                std::thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                    Ok(())
                })?,
        );
        Ok(())
    }
    pub fn restart(&mut self) -> Result<Value> {
        self.configure(&self.config.operational_value()?)?;
        self.snapshot()
    }
    pub fn shutdown(&mut self) -> Result<()> {
        if self.recovery_pending {
            return Ok(());
        }
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("BGP worker panicked"))??;
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("BGP state poisoned"))?;
        state.status["advertised_routes"] = json!([]);
        let ledger = state.ledger.clone();
        super::session(self.namespace.clone(), move |rt, h| {
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), kernel::cleanup(h, &ledger)).await?
            })
        })?;
        state.ledger = Ledger::default();
        if self.file.try_exists()? {
            super::remove_durable(&self.file)?;
        }
        state.status["state"] = json!(if self.config.bgp.enabled {
            "stopped"
        } else {
            "disabled"
        });
        state.status["routes"] = json!([]);
        Ok(())
    }
    #[cfg(test)]
    pub fn abandon_for_crash_fixture(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("BGP fixture join failed"))??;
        }
        self.state
            .lock()
            .map_err(|_| anyhow!("BGP state poisoned"))?
            .ledger = Ledger::default();
        self.recovery_pending = true;
        Ok(())
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            tracing::error!("BGP shutdown failed: {error:#}");
        }
    }
}

struct Connection {
    routes: BTreeMap<Prefix, Path>,
    stream: TcpStream,
    outbound: bool,
    input: Vec<u8>,
    output: Vec<u8>,
    open: Option<wire::Open>,
    established: bool,
    received: Instant,
    sent: Instant,
    started: Instant,
    advertised: BTreeSet<Prefix>,
}
impl Connection {
    fn new(stream: TcpStream, outbound: bool, bgp: &BGPConfig) -> Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        let now = Instant::now();
        Ok(Self {
            routes: BTreeMap::new(),
            stream,
            outbound,
            input: Vec::new(),
            output: wire::open(bgp.local_asn, bgp.router_id.parse()?, bgp.hold_seconds),
            open: None,
            established: false,
            received: now,
            sent: now,
            started: now,
            advertised: BTreeSet::new(),
        })
    }
    fn queue(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.output.len() + bytes.len() <= 1024 * 1024,
            "BGP transmit backlog exceeds 1 MiB"
        );
        self.output.extend(bytes);
        Ok(())
    }
    fn io(&mut self) -> Result<()> {
        let mut budget = 65536;
        while !self.output.is_empty() && budget > 0 {
            match self
                .stream
                .write(&self.output[..self.output.len().min(budget)])
            {
                Ok(0) => anyhow::bail!("BGP TCP closed during write"),
                Ok(n) => {
                    self.output.drain(..n);
                    budget -= n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let mut bytes = [0; 8192];
        for _ in 0..8 {
            match self.stream.read(&mut bytes) {
                Ok(0) => anyhow::bail!("BGP TCP closed"),
                Ok(n) => {
                    ensure!(
                        self.input.len() + n <= 65536,
                        "BGP receive backlog exceeds 64 KiB"
                    );
                    self.input.extend(&bytes[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
struct Neighbor {
    config: BGPNeighbor,
    connections: Vec<Connection>,
    routes: BTreeMap<Prefix, Path>,
    retry: Instant,
    error: Option<String>,
    rejected: u64,
    last_rejection: Option<Rejection>,
}
#[derive(Serialize)]
struct Rejection {
    prefix: String,
    next_hop: Ipv4Addr,
    reason: &'static str,
}
fn bound_socket(interface: &str, ttl: u8) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    ensure!(fd >= 0, "BGP socket: {}", std::io::Error::last_os_error());
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let device = std::ffi::CString::new(interface)?;
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.as_bytes_with_nul().len() as libc::socklen_t,
            )
        } == 0,
        "BGP bind interface: {}",
        std::io::Error::last_os_error()
    );
    let ttl = i32::from(ttl);
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TTL,
                (&ttl as *const i32).cast(),
                std::mem::size_of_val(&ttl) as libc::socklen_t,
            )
        } == 0,
        "BGP IP_TTL: {}",
        std::io::Error::last_os_error()
    );
    Ok(fd)
}
fn sockaddr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}
fn bind(fd: i32, local: Ipv4Addr, port: u16) -> Result<()> {
    let address = sockaddr(local, port);
    ensure!(
        unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } == 0,
        "BGP bind {local}:{port}: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
fn listen(local: Ipv4Addr, interface: &str, ttl: u8) -> Result<TcpListener> {
    let fd = bound_socket(interface, ttl)?;
    let yes = 1i32;
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&yes as *const i32).cast(),
                4,
            )
        } == 0,
        "BGP SO_REUSEADDR failed"
    );
    bind(fd.as_raw_fd(), local, 179)?;
    ensure!(
        unsafe { libc::listen(fd.as_raw_fd(), 32) } == 0,
        "BGP listen failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(TcpListener::from(fd))
}
fn connect(peer: &BGPNeighbor) -> Result<TcpStream> {
    let local = peer.local_address.parse()?;
    let fd = bound_socket(&peer.interface, peer.multihop_ttl)?;
    bind(fd.as_raw_fd(), local, 0)?;
    let address = sockaddr(peer.address.parse()?, 179);
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS),
            "BGP connect: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(TcpStream::from(fd))
}
fn process(
    connection: &mut Connection,
    neighbor: &mut Neighbor,
    bgp: &BGPConfig,
    connected: &BTreeSet<Prefix>,
) -> Result<()> {
    connection.io()?;
    while let Some((kind, body)) = wire::extract(&mut connection.input)? {
        match kind {
            1 => {
                ensure!(connection.open.is_none(), "unexpected duplicate BGP OPEN");
                let open = wire::parse_open(&body)?;
                ensure!(
                    open.asn == neighbor.config.remote_asn,
                    "BGP remote ASN mismatch"
                );
                ensure!(
                    open.router_id != bgp.router_id.parse::<Ipv4Addr>()?,
                    "BGP router ID collision"
                );
                ensure!(
                    open.four_byte || bgp.local_asn <= 65535,
                    "peer must support four-octet ASN"
                );
                connection.open = Some(open);
                connection.queue(&wire::frame(4, &[]))?;
            }
            4 => {
                wire::message(kind, &body)?;
                ensure!(connection.open.is_some(), "KEEPALIVE before OPEN");
                if !connection.established {
                    connection.established = true;
                    neighbor.error = None;
                }
            }
            2 => {
                ensure!(connection.established, "UPDATE before Established");
                let open = connection.open.as_ref().unwrap();
                let update = wire::update(
                    &body,
                    open.four_byte,
                    bgp.local_asn == neighbor.config.remote_asn,
                )?;
                for prefix in update.withdrawn {
                    connection.routes.remove(&prefix);
                }
                if let Some(path) = update.path {
                    let looped = path.as_path.contains(&bgp.local_asn)
                        || (bgp.local_asn != neighbor.config.remote_asn
                            && path.as_path.first() != Some(&neighbor.config.remote_asn));
                    let next_hop = path.next_hop.to_string();
                    let next_hop_allowed = if neighbor.config.allowed_next_hops.is_empty() {
                        next_hop == neighbor.config.address
                    } else {
                        neighbor.config.allowed_next_hops.contains(&next_hop)
                    };
                    for prefix in update.announced {
                        let reason = if looped {
                            Some("as_path")
                        } else if !next_hop_allowed {
                            Some("next_hop_not_allowed")
                        } else if prefix.length == 0 && !neighbor.config.accept_default {
                            Some("default_not_allowed")
                        } else if prefix.address.is_multicast() || prefix.address.is_loopback() {
                            Some("invalid_prefix")
                        } else if connected.contains(&prefix) {
                            Some("connected_route")
                        } else {
                            None
                        };
                        if let Some(reason) = reason {
                            connection.routes.remove(&prefix);
                            neighbor.rejected = neighbor.rejected.saturating_add(1);
                            neighbor.last_rejection = Some(Rejection {
                                prefix: prefix.to_string(),
                                next_hop: path.next_hop,
                                reason,
                            });
                            continue;
                        }
                        ensure!(
                            connection.routes.contains_key(&prefix)
                                || connection.routes.len() < bgp.max_prefixes,
                            "BGP max_prefixes exceeded"
                        );
                        connection.routes.insert(prefix, path.clone());
                    }
                }
            }
            _ => wire::message(kind, &body)?,
        }
        connection.received = Instant::now();
    }
    let hold = connection
        .open
        .as_ref()
        .map_or(bgp.hold_seconds, |open| bgp.hold_seconds.min(open.hold));
    if !connection.established {
        ensure!(
            connection.started.elapsed() < Duration::from_secs(30),
            "BGP OPEN/KEEPALIVE handshake timeout"
        );
    } else if hold > 0 {
        ensure!(
            connection.received.elapsed() < Duration::from_secs(u64::from(hold)),
            "BGP hold timer expired"
        );
        let interval = bgp.keepalive_seconds.min((hold / 3).max(1));
        if connection.sent.elapsed() >= Duration::from_secs(u64::from(interval)) {
            connection.queue(&wire::frame(4, &[]))?;
            connection.sent = Instant::now();
        }
    }
    if connection.established {
        let open = connection.open.as_ref().unwrap();
        let four_byte = open.four_byte;
        for prefix in connection
            .advertised
            .difference(connected)
            .copied()
            .collect::<Vec<_>>()
        {
            connection.queue(&wire::withdraw(prefix))?;
        }
        for prefix in connected
            .difference(&connection.advertised)
            .copied()
            .collect::<Vec<_>>()
        {
            connection.queue(&wire::announce(
                prefix,
                bgp.local_asn,
                neighbor.config.local_address.parse()?,
                four_byte,
                bgp.local_asn == neighbor.config.remote_asn,
            ))?;
        }
        connection.advertised = connected.clone();
    }
    Ok(())
}
fn advertised_routes(neighbors: &[Neighbor]) -> Vec<Value> {
    let mut routes = Vec::new();
    for neighbor in neighbors {
        if let Some(connection) = neighbor
            .connections
            .iter()
            .find(|connection| connection.established)
        {
            for prefix in &connection.advertised {
                routes.push(json!({"prefix":prefix.to_string(),"neighbor":neighbor.config.name,
                    "interface":neighbor.config.interface,"next_hop":neighbor.config.local_address,"source":"bgp"}));
            }
        }
    }
    routes
}

fn desired(
    config: &Config,
    neighbors: &[Neighbor],
    connected: &BTreeSet<Prefix>,
) -> (Ledger, Vec<Value>) {
    let mut candidates = BTreeMap::<Prefix, Vec<(usize, &Path)>>::new();
    for (index, neighbor) in neighbors.iter().enumerate() {
        for (prefix, path) in &neighbor.routes {
            candidates.entry(*prefix).or_default().push((index, path));
        }
    }
    let mut ledger = Ledger::default();
    let mut rows = Vec::new();
    for (prefix, mut paths) in candidates {
        paths.sort_by_key(|(i, p)| {
            (
                std::cmp::Reverse(if neighbors[*i].config.remote_asn == config.bgp.local_asn {
                    p.local_pref
                } else {
                    100
                }),
                p.as_path.len(),
                p.origin,
                neighbors[*i].config.remote_asn == config.bgp.local_asn,
                neighbors[*i].config.name.clone(),
            )
        });
        for (rank, (index, path)) in paths.iter().enumerate() {
            let peer = &neighbors[*index].config;
            let mut reason = if rank > 0 {
                Some("alternate_path")
            } else {
                None
            };
            if connected.contains(&prefix)
                || config
                    .routes
                    .iter()
                    .any(|r| r.enabled && r.table == 254 && r.destination == prefix.to_string())
            {
                reason = Some("connected_or_static_route");
            }
            let mut addition = None;
            if reason.is_none() && !peer.wireguard_public_key.is_empty() {
                if let Some(wg) = config
                    .interfaces
                    .iter()
                    .find(|i| i.name == peer.interface)
                    .and_then(|i| i.wireguard.as_ref())
                {
                    let mut covered = false;
                    for other in wg.peers.iter().filter(|p| p.enabled) {
                        for item in &other.allowed_ips {
                            if let Ok((std::net::IpAddr::V4(ip), len)) =
                                crate::model::parse_prefix(item, true)
                            {
                                if let Ok(static_prefix) = Prefix::new(ip, len) {
                                    if other.public_key != peer.wireguard_public_key
                                        && static_prefix.overlaps(prefix)
                                    {
                                        reason = Some("wireguard_static_peer_overlap");
                                    }
                                    if other.public_key == peer.wireguard_public_key
                                        && static_prefix.length <= prefix.length
                                        && static_prefix.overlaps(prefix)
                                    {
                                        covered = true;
                                    }
                                }
                            }
                        }
                    }
                    if ledger.wg.iter().any(|a| {
                        a.interface == peer.interface
                            && a.key != peer.wireguard_public_key
                            && a.prefix.overlaps(prefix)
                    }) {
                        reason = Some("wireguard_dynamic_peer_overlap");
                    }
                    if !covered {
                        addition = Some(WGAddition {
                            interface: peer.interface.clone(),
                            key: peer.wireguard_public_key.clone(),
                            prefix,
                        });
                    }
                }
            }
            if reason.is_none() {
                ledger.routes.push(Installed {
                    prefix,
                    interface: peer.interface.clone(),
                    gateway: if peer.wireguard_public_key.is_empty() {
                        Some(path.next_hop)
                    } else {
                        None
                    },
                });
                if let Some(addition) = addition {
                    ledger.wg.push(addition);
                }
            }
            rows.push(json!({"prefix":prefix.to_string(),"neighbor":peer.name,"interface":peer.interface,"next_hop":path.next_hop,
                "as_path":path.as_path,"origin":path.origin,"local_pref":path.local_pref,"med":path.med,
                "selected":reason.is_none(),"installed":false,"reason":reason,"source":"bgp"}));
        }
    }
    (ledger, rows)
}
fn reconcile(
    namespace: &Arc<File>,
    file: &std::path::Path,
    state: &mut State,
    next: &Ledger,
) -> Result<()> {
    let old = state.ledger.clone();
    let mut journal = next.clone();
    journal.routes.extend(old.routes.clone());
    journal.routes.sort();
    journal.routes.dedup();
    journal.wg.extend(old.wg.clone());
    journal.wg.sort();
    journal.wg.dedup();
    if journal != old {
        super::write_json(file, &journal)?;
    }
    // Keep ownership even on partial failure, so shutdown/recovery can remove every addition.
    state.ledger = journal;
    let next = next.clone();
    let install = next.clone();
    let keep_routes = next.routes.iter().collect::<BTreeSet<_>>();
    let keep_wg = next.wg.iter().collect::<BTreeSet<_>>();
    let remove = Ledger {
        routes: old
            .routes
            .iter()
            .filter(|r| !keep_routes.contains(r))
            .cloned()
            .collect(),
        wg: old
            .wg
            .iter()
            .filter(|r| !keep_wg.contains(r))
            .cloned()
            .collect(),
    };
    super::session(namespace.clone(), move |rt, h| {
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                kernel::cleanup(h, &remove).await?;
                kernel::wg(&install.wg, true)?;
                kernel::routes(h, &[], &install.routes).await?;
                Ok::<(), anyhow::Error>(())
            })
            .await?
        })
    })?;
    if old != next {
        super::write_json(file, &next)?;
    }
    state.ledger = next;
    Ok(())
}
fn run(
    config: &Config,
    namespace: &Arc<File>,
    file: &std::path::Path,
    state: &Arc<Mutex<State>>,
    stop: &AtomicBool,
) -> Result<()> {
    let bgp = &config.bgp;
    let mut listener_ttls = BTreeMap::<_, u8>::new();
    for peer in &bgp.neighbors {
        let key = (
            peer.interface.clone(),
            peer.local_address.parse::<Ipv4Addr>()?,
        );
        listener_ttls
            .entry(key)
            .and_modify(|ttl| *ttl = (*ttl).max(peer.multihop_ttl))
            .or_insert(peer.multihop_ttl);
    }
    // SYN-ACKs precede peer lookup, so shared listeners use the largest configured TTL.
    let listeners = listener_ttls
        .into_iter()
        .map(|(key, ttl)| listen(key.1, &key.0, ttl).map(|listener| (key, listener)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut neighbors = bgp
        .neighbors
        .iter()
        .cloned()
        .map(|config| Neighbor {
            config,
            connections: Vec::new(),
            routes: BTreeMap::new(),
            retry: Instant::now(),
            error: None,
            rejected: 0,
            last_rejection: None,
        })
        .collect::<Vec<_>>();
    let mut connected = BTreeSet::new();
    let mut refresh = Instant::now();
    let mut synced = true;
    while !stop.load(Ordering::Acquire) {
        let audit = Instant::now() >= refresh;
        if audit {
            let configured = config.clone();
            connected = super::session(namespace.clone(), move |rt, h| {
                rt.block_on(async {
                    tokio::time::timeout(Duration::from_secs(3), kernel::connected(h, &configured))
                        .await?
                })
            })?;
            refresh = Instant::now() + Duration::from_secs(2);
        }
        for ((interface, local), listener) in &listeners {
            for _ in 0..32 {
                match listener.accept() {
                    Ok((stream, address)) => {
                        if let Some(peer) = neighbors.iter_mut().find(|n| {
                            n.config.interface == *interface
                                && n.config.local_address == local.to_string()
                                && n.config.address == address.ip().to_string()
                        }) {
                            if peer.connections.len() < 2
                                && !peer
                                    .connections
                                    .iter()
                                    .any(|c| c.established || !c.outbound)
                            {
                                stream.set_ttl(u32::from(peer.config.multihop_ttl))?;
                                peer.connections.push(Connection::new(stream, false, bgp)?);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let mut total_prefixes = 0;
        for peer in &mut neighbors {
            if peer.connections.is_empty() && Instant::now() >= peer.retry {
                peer.retry = Instant::now() + Duration::from_secs(5);
                match connect(&peer.config).and_then(|stream| Connection::new(stream, true, bgp)) {
                    Ok(connection) => peer.connections.push(connection),
                    Err(error) => peer.error = Some(format!("{error:#}")),
                }
            }
            let mut connections = std::mem::take(&mut peer.connections);
            let mut surviving = Vec::new();
            for mut connection in connections.drain(..) {
                match process(&mut connection, peer, bgp, &connected) {
                    Ok(()) => surviving.push(connection),
                    Err(error) => {
                        let _ = connection.stream.write(&wire::frame(3, &[6, 0]));
                        peer.error = Some(format!("{error:#}"));
                    }
                }
            }
            if surviving.len() == 2 && surviving.iter().all(|c| c.open.is_some()) {
                let prefer_outbound = bgp.router_id.parse::<Ipv4Addr>()?
                    > surviving[0].open.as_ref().unwrap().router_id;
                let keep = surviving
                    .iter()
                    .position(|c| c.outbound == prefer_outbound)
                    .unwrap_or(0);
                let chosen = surviving.swap_remove(keep);
                surviving.clear();
                surviving.push(chosen);
            }
            peer.routes = surviving
                .iter()
                .find(|c| c.established)
                .map(|c| c.routes.clone())
                .unwrap_or_default();
            if total_prefixes + peer.routes.len() > bgp.max_prefixes {
                peer.error = Some("BGP global max_prefixes exceeded".into());
                peer.routes.clear();
                surviving.clear();
            }
            total_prefixes += peer.routes.len();
            peer.connections = surviving;
        }
        let (next, mut routes) = desired(config, &neighbors, &connected);
        let mut shared = state.lock().map_err(|_| anyhow!("BGP state poisoned"))?;
        let mut error = None;
        if next != shared.ledger || !synced || audit {
            match reconcile(namespace, file, &mut shared, &next) {
                Ok(()) => synced = true,
                Err(e) => {
                    synced = false;
                    error = Some(format!("{e:#}"));
                }
            }
        }
        for row in &mut routes {
            row["installed"] = json!(synced && row["selected"] == true);
        }
        let peers=neighbors.iter().map(|n|{
            let connection=n.connections.iter().find(|c|c.established).or_else(||n.connections.first());
            json!({"name":n.config.name,"address":n.config.address,"interface":n.config.interface,
                "state":if connection.is_some_and(|c|c.established){"established"}else if connection.is_some_and(|c|c.open.is_some()){"open_confirm"}else if connection.is_some(){"open_sent"}else{"active"},
                "received_prefixes":n.routes.len(),"rejected_prefixes":n.rejected,"last_rejection":n.last_rejection,
                "advertised_prefixes":connection.map_or(0,|c|c.advertised.len()),
                "negotiated_hold_seconds":connection.and_then(|c|c.open.as_ref()).map(|o|o.hold.min(bgp.hold_seconds)),
                "remote_router_id":connection.and_then(|c|c.open.as_ref()).map(|o|o.router_id),"error":n.error})
        }).collect::<Vec<_>>();
        shared.status = json!({"name":"bgp","state":"running","health":if error.is_some(){"degraded"}else if peers.iter().all(|p|p["state"]=="established"){"up"}else{"degraded"},
            "local_asn":bgp.local_asn,"router_id":bgp.router_id,"neighbors":peers,"routes":routes,"advertised_routes":advertised_routes(&neighbors),"error":error,
            "connected_prefixes":connected.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "installed_prefixes":if synced{next.routes.len()}else{0},"kernel_protocol":kernel::PROTOCOL,"route_metric":kernel::METRIC,"table":254});
        drop(shared);
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn neighbor() -> Neighbor {
        Neighbor {
            config: BGPNeighbor {
                metadata: Default::default(),
                name: "edge".into(),
                address: "192.0.2.2".into(),
                interface: "test0".into(),
                local_address: "192.0.2.1".into(),
                remote_asn: 65002,
                wireguard_public_key: String::new(),
                accept_default: false,
                multihop_ttl: 1,
                allowed_next_hops: Vec::new(),
            },
            connections: Vec::new(),
            routes: BTreeMap::new(),
            retry: Instant::now(),
            error: None,
            rejected: 0,
            last_rejection: None,
        }
    }
    #[test]
    fn advertised_route_rows_follow_established_session_state() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let bgp = BGPConfig {
            local_asn: 65001,
            router_id: "192.0.2.1".into(),
            ..Default::default()
        };
        let prefix = Prefix::new("203.0.113.0".parse()?, 24)?;
        let mut neighbors = Vec::new();
        let mut remotes = Vec::new();
        for (name, established) in [("edge", true), ("other", true), ("connecting", false)] {
            let stream = TcpStream::connect(listener.local_addr()?)?;
            remotes.push(listener.accept()?.0);
            let mut connection = Connection::new(stream, true, &bgp)?;
            connection.established = established;
            connection.advertised.insert(prefix);
            let mut peer = neighbor();
            peer.config.name = name.into();
            peer.connections.push(connection);
            neighbors.push(peer);
        }
        let rows = advertised_routes(&neighbors);
        assert_eq!(
            rows,
            vec![
                json!({"prefix":"203.0.113.0/24","neighbor":"edge","interface":"test0","next_hop":"192.0.2.1","source":"bgp"}),
                json!({"prefix":"203.0.113.0/24","neighbor":"other","interface":"test0","next_hop":"192.0.2.1","source":"bgp"}),
            ]
        );
        neighbors[0].connections[0].advertised.clear();
        assert_eq!(advertised_routes(&neighbors).len(), 1);
        neighbors[1].connections[0].established = false;
        assert!(advertised_routes(&neighbors).is_empty());
        neighbors[0].connections.clear();
        assert!(advertised_routes(&neighbors).is_empty());
        Ok(())
    }

    #[test]
    fn sessions_filter_loops_defaults_withdraw_and_expire_hold_timer() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let stream = TcpStream::connect(listener.local_addr()?)?;
        let (mut remote, _) = listener.accept()?;
        let bgp = BGPConfig {
            enabled: true,
            local_asn: 65001,
            router_id: "192.0.2.1".into(),
            hold_seconds: 3,
            keepalive_seconds: 1,
            ..Default::default()
        };
        let mut connection = Connection::new(stream, true, &bgp)?;
        let mut peer = neighbor();
        let connected = BTreeSet::new();
        let prefix = Prefix::new("198.51.100.0".parse()?, 24)?;
        let default = Prefix::new("0.0.0.0".parse()?, 0)?;
        let mut messages = wire::open(65002, "192.0.2.2".parse()?, 3);
        messages.extend(wire::frame(4, &[]));
        messages.extend(wire::announce(
            prefix,
            65002,
            "192.0.2.2".parse()?,
            true,
            false,
        ));
        messages.extend(wire::announce(
            default,
            65002,
            "192.0.2.2".parse()?,
            true,
            false,
        ));
        remote.write_all(&messages)?;
        for _ in 0..100 {
            process(&mut connection, &mut peer, &bgp, &connected)?;
            if connection.routes.contains_key(&prefix) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(connection.established);
        assert!(connection.routes.contains_key(&prefix));
        assert!(!connection.routes.contains_key(&default));
        assert_eq!(peer.rejected, 1);
        peer.config.accept_default = true;
        remote.write_all(&wire::announce(
            default,
            65002,
            "192.0.2.2".parse()?,
            true,
            false,
        ))?;
        for _ in 0..100 {
            process(&mut connection, &mut peer, &bgp, &connected)?;
            if connection.routes.contains_key(&default) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(connection.routes.contains_key(&default));
        let mut messages = wire::withdraw(prefix);
        messages.extend(wire::announce(
            default,
            65001,
            "192.0.2.2".parse()?,
            true,
            false,
        ));
        remote.write_all(&messages)?;
        for _ in 0..100 {
            process(&mut connection, &mut peer, &bgp, &connected)?;
            if connection.routes.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(connection.routes.is_empty());
        connection.received = Instant::now() - Duration::from_secs(4);
        assert!(
            process(&mut connection, &mut peer, &bgp, &connected)
                .unwrap_err()
                .to_string()
                .contains("hold timer")
        );
        Ok(())
    }

    #[test]
    fn routed_sessions_authorize_advertised_gateways_per_neighbor_and_withdraw() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let bgp = BGPConfig {
            local_asn: 65004,
            router_id: "192.0.2.2".into(),
            ..Default::default()
        };
        let prefix = Prefix::new("203.0.113.0".parse()?, 24)?;
        let mut peers = Vec::new();
        let mut remotes = Vec::new();
        for (name, address, gateway) in [
            ("first", "198.51.100.22", "192.0.2.1"),
            ("second", "198.51.100.23", "192.0.2.3"),
        ] {
            let stream = TcpStream::connect(listener.local_addr()?)?;
            remotes.push(listener.accept()?.0);
            let mut connection = Connection::new(stream, true, &bgp)?;
            let mut peer = neighbor();
            peer.config.name = name.into();
            peer.config.address = address.into();
            peer.config.local_address = "192.0.2.2".into();
            peer.config.multihop_ttl = 8;
            peer.config.allowed_next_hops = vec![gateway.into()];
            connection
                .input
                .extend(wire::open(65002, address.parse()?, 90));
            connection.input.extend(wire::frame(4, &[]));
            connection
                .input
                .extend(wire::announce(prefix, 65002, gateway.parse()?, true, false));
            process(&mut connection, &mut peer, &bgp, &BTreeSet::new())?;
            assert!(connection.established);
            assert_eq!(
                connection.routes[&prefix].next_hop,
                gateway.parse::<Ipv4Addr>()?
            );
            peer.routes = connection.routes.clone();
            peer.connections.push(connection);
            peers.push(peer);
        }
        let config = Config {
            bgp: bgp.clone(),
            ..Config::empty()
        };
        let (ledger, _) = desired(&config, &peers, &BTreeSet::new());
        assert_eq!(ledger.routes[0].gateway, Some("192.0.2.1".parse()?));

        let mut connection = peers[0].connections.remove(0);
        connection.input.extend(wire::announce(
            prefix,
            65002,
            "192.0.2.3".parse()?,
            true,
            false,
        ));
        process(&mut connection, &mut peers[0], &bgp, &BTreeSet::new())?;
        assert!(connection.routes.is_empty());
        assert_eq!(peers[0].rejected, 1);
        assert_eq!(
            serde_json::to_value(&peers[0].last_rejection)?,
            json!({"prefix":"203.0.113.0/24","next_hop":"192.0.2.3","reason":"next_hop_not_allowed"})
        );
        peers[0].routes = connection.routes.clone();
        let (ledger, _) = desired(&config, &peers, &BTreeSet::new());
        assert_eq!(ledger.routes[0].gateway, Some("192.0.2.3".parse()?));

        let mut connection = peers[1].connections.remove(0);
        connection.input.extend(wire::withdraw(prefix));
        process(&mut connection, &mut peers[1], &bgp, &BTreeSet::new())?;
        peers[1].routes = connection.routes;
        assert!(
            desired(&config, &peers, &BTreeSet::new())
                .0
                .routes
                .is_empty()
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin/mount privileges"]
    fn native_bgp_routed_peer_installs_advertised_gateway_and_cleans_up() -> Result<()> {
        use crate::linux::{integration::Fixture, session};
        use futures_util::TryStreamExt;
        use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteProtocol};
        let receiver = Fixture::new()?;
        let gateway = Fixture::new()?;
        let speaker = Fixture::new()?;
        let ns = |fixture: &Fixture| -> Result<Arc<File>> {
            Ok(Arc::new(File::open(fixture.options().namespace)?))
        };
        let receiver_ns = ns(&receiver)?;
        let gateway_ns = ns(&gateway)?;
        let speaker_ns = ns(&speaker)?;
        for (from, to, local, remote) in [
            (receiver_ns.clone(), gateway_ns.clone(), "peer0", "gw0"),
            (gateway_ns.clone(), speaker_ns.clone(), "gw1", "speaker0"),
        ] {
            session(from, move |rt, h| {
                rt.block_on(async {
                    h.link()
                        .add(rtnetlink::LinkVeth::new(local, remote).build())
                        .execute()
                        .await?;
                    let link = h
                        .link()
                        .get()
                        .match_name(remote.into())
                        .execute()
                        .try_next()
                        .await?
                        .context("veth missing")?;
                    h.link()
                        .set(
                            rtnetlink::LinkUnspec::new_with_index(link.header.index)
                                .setns_by_fd(to.as_raw_fd())
                                .build(),
                        )
                        .execute()
                        .await?;
                    Ok(())
                })
            })?;
        }
        for (namespace, interface, address) in [
            (receiver_ns.clone(), "peer0", "192.0.2.2"),
            (gateway_ns.clone(), "gw0", "192.0.2.1"),
            (gateway_ns.clone(), "gw1", "198.51.100.1"),
            (speaker_ns.clone(), "speaker0", "198.51.100.22"),
        ] {
            session(namespace, move |rt, h| {
                rt.block_on(async {
                    let link = h
                        .link()
                        .get()
                        .match_name(interface.into())
                        .execute()
                        .try_next()
                        .await?
                        .context("veth missing")?;
                    h.address()
                        .add(link.header.index, address.parse()?, 24)
                        .execute()
                        .await?;
                    h.link()
                        .set(
                            rtnetlink::LinkUnspec::new_with_index(link.header.index)
                                .up()
                                .build(),
                        )
                        .execute()
                        .await?;
                    Ok(())
                })
            })?;
        }
        session(gateway_ns, |_, _| {
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
            Ok(())
        })?;
        for (namespace, destination, via) in [
            (receiver_ns.clone(), "198.51.100.22", "192.0.2.1"),
            (speaker_ns.clone(), "192.0.2.2", "198.51.100.1"),
        ] {
            session(namespace, move |rt, h| {
                rt.block_on(
                    h.route()
                        .add(
                            rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                                .destination_prefix(destination.parse()?, 32)
                                .gateway(via.parse()?)
                                .build(),
                        )
                        .execute(),
                )?;
                Ok(())
            })?;
        }
        let config: Config = serde_json::from_value(json!({
            "interfaces":[{"name":"peer0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.2/24"]}],
            "routes":[{"enabled":true,"destination":"198.51.100.22/32","gateway":"192.0.2.1","interface":"peer0","table":254,"metric":10}],
            "bgp":{"enabled":true,"local_asn":65004,"router_id":"192.0.2.2",
                "neighbors":[{"name":"remote","interface":"peer0","local_address":"192.0.2.2",
                    "address":"198.51.100.22","remote_asn":65000,"multihop_ttl":8,"allowed_next_hops":["192.0.2.1"]}]}
        }))?;
        config.validate()?;
        let listener = session(speaker_ns.clone(), |_, _| {
            listen("198.51.100.22".parse()?, "speaker0", 8)
        })?;
        assert_eq!(listener.ttl()?, 8);
        let root = receiver.options().services_state;
        std::fs::create_dir_all(&root)?;
        let mut manager = Manager::new(receiver_ns.clone(), root)?;
        manager.recover()?;
        manager.configure(&config.operational_value()?)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let (mut remote, address) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    ensure!(
                        Instant::now() < deadline,
                        "routed BGP connect timeout: {}",
                        manager.snapshot()?
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error.into()),
            }
        };
        assert_eq!(address.ip(), "192.0.2.2".parse::<Ipv4Addr>()?);
        remote.set_nonblocking(false)?;
        remote.set_write_timeout(Some(Duration::from_secs(2)))?;
        let prefix = Prefix::new("203.0.113.0".parse()?, 24)?;
        let mut messages = wire::open(65000, "198.51.100.22".parse()?, 90);
        messages.extend(wire::frame(4, &[]));
        messages.extend(wire::announce(
            prefix,
            65000,
            "192.0.2.1".parse()?,
            true,
            false,
        ));
        remote.write_all(&messages)?;
        let wait_route = |present: bool| -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let status = manager.snapshot()?;
                let found = status["routes"].as_array().is_some_and(|routes| {
                    routes.iter().any(|r| {
                        r["prefix"] == "203.0.113.0/24"
                            && r["next_hop"] == "192.0.2.1"
                            && r["installed"] == true
                    })
                });
                if found == present {
                    return Ok(());
                }
                ensure!(
                    Instant::now() < deadline,
                    "BGP route presence {present}: {status}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        wait_route(true)?;
        let check_kernel = |present: bool| -> Result<()> {
            session(receiver_ns.clone(), move |rt, h| {
                let routes = rt.block_on(
                    h.route()
                        .get(crate::linux::networking::route_query(
                            rtnetlink::IpVersion::V4,
                        ))
                        .execute()
                        .try_collect::<Vec<_>>(),
                )?;
                let found = routes.iter().any(|r| {
                    r.header.protocol == RouteProtocol::Other(245)
                        && r.attributes
                            .contains(&RouteAttribute::Destination(RouteAddress::Inet(
                                "203.0.113.0".parse().unwrap(),
                            )))
                        && r.attributes
                            .contains(&RouteAttribute::Gateway(RouteAddress::Inet(
                                "192.0.2.1".parse().unwrap(),
                            )))
                });
                ensure!(found == present, "kernel advertised gateway mismatch");
                ensure!(
                    routes
                        .iter()
                        .any(|r| r.header.destination_prefix_length == 32
                            && r.attributes.contains(&RouteAttribute::Destination(
                                RouteAddress::Inet("198.51.100.22".parse().unwrap())
                            ))),
                    "bootstrap route lost"
                );
                Ok(())
            })
        };
        check_kernel(true)?;
        remote.write_all(&wire::withdraw(prefix))?;
        wait_route(false)?;
        check_kernel(false)?;
        drop(remote);
        drop(listener);
        manager.shutdown()?;

        // Reverse initiation exercises the passive listener and its per-peer TTL.
        manager.configure(&config.operational_value()?)?;
        let mut remote_peer = neighbor().config;
        remote_peer.interface = "speaker0".into();
        remote_peer.local_address = "198.51.100.22".into();
        remote_peer.address = "192.0.2.2".into();
        remote_peer.multihop_ttl = 8;
        let mut remote = session(speaker_ns, move |_, _| connect(&remote_peer))?;
        remote.set_nonblocking(false)?;
        remote.set_write_timeout(Some(Duration::from_secs(2)))?;
        remote.write_all(&messages)?;
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let status = manager.snapshot()?;
            if status["routes"]
                .as_array()
                .is_some_and(|r| r.iter().any(|r| r["installed"] == true))
            {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "passive routed BGP timeout: {status}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        check_kernel(true)?;
        manager.shutdown()?;
        check_kernel(false)?;
        assert!(
            manager.snapshot()?["routes"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
        Ok(())
    }

    #[test]
    fn best_path_selection_preserves_static_routes_and_wireguard_peer_ownership() -> Result<()> {
        let mut config = Config::empty();
        config.bgp.local_asn = 65001;
        let prefix = Prefix::new("198.51.100.0".parse()?, 24)?;
        let mut first = neighbor();
        first.routes.insert(
            prefix,
            Path {
                next_hop: "192.0.2.2".parse()?,
                as_path: vec![65002],
                origin: 0,
                local_pref: 100,
                med: 0,
            },
        );
        let mut second = neighbor();
        second.config.name = "other".into();
        second.routes.insert(
            prefix,
            Path {
                next_hop: "192.0.2.3".parse()?,
                as_path: vec![65003, 65004],
                origin: 0,
                local_pref: 100,
                med: 0,
            },
        );
        let (ledger, rows) = desired(&config, &[first, second], &BTreeSet::new());
        assert_eq!(ledger.routes.len(), 1);
        assert_eq!(rows.iter().filter(|r| r["selected"] == true).count(), 1);
        assert_eq!(ledger.routes[0].gateway, Some("192.0.2.2".parse()?));
        config.routes.push(netcontrol_core::Route {
            metadata: Default::default(),
            enabled: true,
            destination: prefix.to_string(),
            gateway: String::new(),
            interface: "test0".into(),
            table: 254,
            metric: 10,
        });
        let mut peer = neighbor();
        peer.routes.insert(
            prefix,
            Path {
                next_hop: "192.0.2.2".parse()?,
                as_path: vec![65002],
                origin: 0,
                local_pref: 100,
                med: 0,
            },
        );
        let (ledger, rows) = desired(&config, &[peer], &BTreeSet::new());
        assert!(ledger.routes.is_empty());
        assert_eq!(rows[0]["reason"], "connected_or_static_route");
        config.routes.clear();
        config.interfaces = serde_json::from_value(
            json!([{"name":"wg0","kind":"wireguard","role":"wan","up":true,"mtu":1420,"addresses":["10.0.0.1/30"],
            "wireguard":{"key_ref":"key","listen_port":51820,"peers":[
                {"public_key":"one","allowed_ips":["10.0.0.2/32"]},
                {"public_key":"two","allowed_ips":["198.51.100.0/24"]}]}}]),
        )?;
        let mut peer = neighbor();
        peer.config.interface = "wg0".into();
        peer.config.wireguard_public_key = "one".into();
        peer.routes.insert(
            prefix,
            Path {
                next_hop: "192.0.2.2".parse()?,
                as_path: vec![65002],
                origin: 0,
                local_pref: 100,
                med: 0,
            },
        );
        let (ledger, rows) = desired(&config, &[peer], &BTreeSet::new());
        assert!(ledger.wg.is_empty());
        assert!(ledger.routes.is_empty());
        assert_eq!(rows[0]["reason"], "wireguard_static_peer_overlap");
        Ok(())
    }
}
