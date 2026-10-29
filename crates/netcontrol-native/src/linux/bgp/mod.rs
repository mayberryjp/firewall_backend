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
            eprintln!("BGP shutdown failed: {error:#}");
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
}
fn bound_socket(local: Ipv4Addr, interface: &str) -> Result<std::os::fd::OwnedFd> {
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
    let _ = local;
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
fn listen(local: Ipv4Addr, interface: &str) -> Result<TcpListener> {
    let fd = bound_socket(local, interface)?;
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
    let fd = bound_socket(local, &peer.interface)?;
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
                    for prefix in update.announced {
                        // This deliberately small speaker accepts direct-next-hop paths only.
                        let blocked = looped
                            || path.next_hop != neighbor.config.address.parse::<Ipv4Addr>()?
                            || (prefix.length == 0 && !neighbor.config.accept_default)
                            || prefix.address.is_multicast()
                            || prefix.address.is_loopback()
                            || connected.contains(&prefix);
                        if blocked {
                            connection.routes.remove(&prefix);
                            neighbor.rejected = neighbor.rejected.saturating_add(1);
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
    let mut listeners = BTreeMap::new();
    for peer in &bgp.neighbors {
        let key = (
            peer.interface.clone(),
            peer.local_address.parse::<Ipv4Addr>()?,
        );
        if !listeners.contains_key(&key) {
            listeners.insert(key.clone(), listen(key.1, &key.0)?);
        }
    }
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
                "received_prefixes":n.routes.len(),"rejected_prefixes":n.rejected,
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
            },
            connections: Vec::new(),
            routes: BTreeMap::new(),
            retry: Instant::now(),
            error: None,
            rejected: 0,
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
