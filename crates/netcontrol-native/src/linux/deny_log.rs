use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use netcontrol_core::{DenyLogQuery, DenyRecord, DenyTrafficTag};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::File,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod store;
pub(super) const GROUP: u16 = 100;
const RATE: usize = 100;

struct State {
    store: store::Store,
    status: &'static str,
    error: Option<String>,
    discarded: u64,
    malformed: u64,
    overflow_events: u64,
    sequence_gaps: u64,
    broadcasts: BTreeSet<Ipv4Addr>,
}

pub(super) struct Monitor {
    namespace: Arc<File>,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Monitor {
    pub fn first_drops(&self, config: &netcontrol_core::DiscordConfig) -> Result<Vec<DenyRecord>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
        ensure!(
            state.status == "capturing",
            "firewall deny capture is unavailable"
        );
        state.store.first_drops(config)
    }

    pub fn new(namespace: Arc<File>, root: PathBuf) -> Result<Self> {
        let state = Arc::new(Mutex::new(State {
            store: store::Store::open(root)?,
            status: "disabled",
            error: None,
            discarded: 0,
            malformed: 0,
            overflow_events: 0,
            sequence_gaps: 0,
            broadcasts: BTreeSet::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        Ok(Self {
            namespace,
            state,
            stop,
            thread: None,
        })
    }

    pub fn configure(&mut self, enabled: bool) -> Result<()> {
        if !enabled {
            self.shutdown()?;
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?
                .status = "disabled";
            return Ok(());
        }
        if let Some(thread) = &self.thread {
            ensure!(
                !thread.is_finished(),
                "deny-log worker exited; restart the daemon"
            );
            return Ok(());
        }
        self.stop.store(false, Ordering::Relaxed);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
            state.status = "starting";
            state.error = None;
        }
        let namespace = self.namespace.clone();
        let output = self.state.clone();
        let stopping = self.stop.clone();
        let (ready, receive) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("firewall-deny-log".into())
            .spawn(move || {
                let setup = (|| -> Result<OwnedFd> {
                    let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
                    let target = namespace.metadata()?;
                    if current.dev() != target.dev() || current.ino() != target.ino() {
                        ensure!(
                            unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0,
                            "enter deny-log namespace: {}",
                            io::Error::last_os_error()
                        );
                    }
                    socket()
                })();
                let socket = match setup {
                    Ok(socket) => {
                        let _ = ready.send(Ok(()));
                        socket
                    }
                    Err(error) => {
                        let _ = ready.send(Err(format!("{error:#}")));
                        return;
                    }
                };
                let result = run(&socket, &output, &stopping);
                if let Err(error) = result {
                    tracing::error!("firewall deny logging failed: {error:#}");
                    if let Ok(mut state) = output.lock() {
                        state.status = "error";
                        state.error = Some(format!("{error:#}"));
                    }
                }
            })?;
        self.thread = Some(thread);
        match receive.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(()),
            result => {
                self.shutdown()?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
                state.status = "error";
                state.error = Some(format!("start firewall deny logger: {result:?}"));
                anyhow::bail!("start firewall deny logger: {result:?}");
            }
        }
    }

    pub fn snapshot(&self, query: &DenyLogQuery) -> Result<Value> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
        let mut value = state.store.query(query);
        value["capture"] = json!({
            "status":state.status,"error":state.error,"group":GROUP,"rate_limit_per_second":RATE,
            "discarded_records":state.discarded.to_string(),"malformed_records":state.malformed.to_string(),
            "overflow_events":state.overflow_events.to_string(),"sequence_gaps":state.sequence_gaps.to_string(),
            "counters_scope":"daemon_session","loss_count_exact":false
        });
        if self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
            && state.status == "capturing"
        {
            value["capture"]["status"] = json!("error");
            value["capture"]["error"] =
                json!("deny-log worker exited unexpectedly; restart the daemon");
        }
        Ok(value)
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("deny-log worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            tracing::error!("deny-log shutdown failed: {error:#}");
        }
    }
}

fn attribute(kind: u16, bytes: &[u8]) -> Vec<u8> {
    let length = 4 + bytes.len();
    let mut result = Vec::new();
    result.extend((length as u16).to_ne_bytes());
    result.extend(kind.to_ne_bytes());
    result.extend(bytes);
    result.resize((length + 3) & !3, 0);
    result
}

fn socket() -> Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_NETFILTER,
        )
    };
    ensure!(fd >= 0, "open NFLOG socket: {}", io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    ensure!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&address) as u32,
            )
        } == 0,
        "bind NFLOG socket: {}",
        io::Error::last_os_error()
    );
    let capacity: libc::c_int = 1 << 20;
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &capacity as *const _ as *const _,
                std::mem::size_of_val(&capacity) as u32,
            )
        } == 0,
        "set NFLOG buffer: {}",
        io::Error::last_os_error()
    );
    configure(&fd, 1, attribute(1, &[1]))?;
    let mut mode = 128u32.to_be_bytes().to_vec();
    mode.extend([2, 0]);
    configure(
        &fd,
        2,
        [
            attribute(2, &mode),
            attribute(3, &65536u32.to_be_bytes()),
            attribute(4, &1u32.to_be_bytes()),
            attribute(5, &1u32.to_be_bytes()),
            attribute(6, &1u16.to_be_bytes()),
        ]
        .concat(),
    )?;
    Ok(fd)
}

fn configure(fd: &OwnedFd, sequence: u32, attrs: Vec<u8>) -> Result<()> {
    let mut message = Vec::new();
    message.extend((20u32 + attrs.len() as u32).to_ne_bytes());
    message.extend(0x0401u16.to_ne_bytes());
    message.extend(5u16.to_ne_bytes());
    message.extend(sequence.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    message.extend([libc::AF_UNSPEC as u8, 0]);
    message.extend(GROUP.to_be_bytes());
    message.extend(attrs);
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    ensure!(
        unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                message.as_ptr() as *const _,
                message.len(),
                0,
                &kernel as *const _ as *const _,
                std::mem::size_of_val(&kernel) as u32,
            )
        } == message.len() as isize,
        "configure NFLOG: {}",
        io::Error::last_os_error()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = [0; 65536];
    loop {
        ensure!(
            Instant::now() < deadline,
            "NFLOG configuration acknowledgement timed out"
        );
        if !poll(fd, 100)? {
            continue;
        }
        let count = receive(fd, &mut bytes)?;
        let mut ack = None;
        frames(&bytes[..count], |kind, seq, payload| {
            if kind == 2 && seq == sequence {
                ensure!(payload.len() >= 20, "short NFLOG acknowledgement");
                let code = i32::from_ne_bytes(payload[..4].try_into()?);
                ensure!((-4095..=0).contains(&code), "invalid NFLOG error");
                ensure!(
                    code == 0,
                    "NFLOG configuration: {}",
                    io::Error::from_raw_os_error(-code)
                );
                ack = Some(());
            }
            Ok(())
        })?;
        if ack.is_some() {
            return Ok(());
        }
    }
}

fn poll(fd: &OwnedFd, timeout: i32) -> Result<bool> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, timeout) };
    if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
        return Ok(false);
    }
    ensure!(result >= 0, "poll NFLOG: {}", io::Error::last_os_error());
    ensure!(
        poll.revents & (libc::POLLHUP | libc::POLLNVAL) == 0,
        "NFLOG socket closed"
    );
    Ok(result > 0)
}

fn receive(fd: &OwnedFd, bytes: &mut [u8]) -> Result<usize> {
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&sender) as u32;
    let count = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            bytes.as_mut_ptr() as *mut _,
            bytes.len(),
            libc::MSG_TRUNC,
            &mut sender as *mut _ as *mut _,
            &mut length,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    ensure!(
        count > 0 && count as usize <= bytes.len(),
        "truncated/empty NFLOG datagram"
    );
    ensure!(
        length as usize == std::mem::size_of_val(&sender) && sender.nl_pid == 0,
        "NFLOG sender is not the kernel"
    );
    Ok(count as usize)
}

fn frames(mut bytes: &[u8], mut visit: impl FnMut(u16, u32, &[u8]) -> Result<()>) -> Result<()> {
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 16, "short NFLOG frame");
        let length = u32::from_ne_bytes(bytes[..4].try_into()?) as usize;
        ensure!(
            length >= 16 && length <= bytes.len() && (length + 3) & !3 <= bytes.len(),
            "invalid NFLOG frame length"
        );
        visit(
            u16::from_ne_bytes(bytes[4..6].try_into()?),
            u32::from_ne_bytes(bytes[8..12].try_into()?),
            &bytes[16..length],
        )?;
        bytes = &bytes[(length + 3) & !3..];
    }
    Ok(())
}

fn address_broadcasts(address: &AddressMessage) -> impl Iterator<Item = Ipv4Addr> + '_ {
    let local = address
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(IpAddr::V4(ip)) => Some(*ip),
            _ => None,
        })
        .or_else(|| {
            address
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Address(IpAddr::V4(ip)) => Some(*ip),
                    _ => None,
                })
        });
    let subnet = local
        .filter(|_| address.header.prefix_len <= 30)
        .map(|ip| Ipv4Addr::from(u32::from(ip) | (u32::MAX >> address.header.prefix_len)));
    address
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            AddressAttribute::Broadcast(ip) if address.header.prefix_len <= 30 => Some(*ip),
            _ => None,
        })
        .chain(subnet)
}

async fn broadcasts(handle: &rtnetlink::Handle) -> Result<BTreeSet<Ipv4Addr>> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut addresses = handle.address().get().execute();
        let mut result = BTreeSet::new();
        while let Some(address) = addresses.try_next().await? {
            result.extend(address_broadcasts(&address));
        }
        Ok::<_, anyhow::Error>(result)
    })
    .await
    .context("deny-log broadcast address snapshot timed out")?
}

fn run(fd: &OwnedFd, output: &Mutex<State>, stop: &AtomicBool) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (connection, handle, _) = runtime.block_on(async { rtnetlink::new_connection() })?;
    let _connection = runtime.spawn(connection);
    {
        let broadcasts = runtime.block_on(broadcasts(&handle))?;
        let mut state = output
            .lock()
            .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
        state.broadcasts = broadcasts;
        state.status = "capturing";
    }
    let mut bytes = [0; 65536];
    let mut pending = Vec::new();
    let mut window = Instant::now();
    let mut previous: Option<u32> = None;
    while !stop.load(Ordering::Relaxed) {
        if poll(fd, 100)? {
            for _ in 0..64 {
                let count = match receive(fd, &mut bytes) {
                    Ok(count) => count,
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock) =>
                    {
                        break;
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::Interrupted) =>
                    {
                        continue;
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.raw_os_error() == Some(libc::ENOBUFS)) =>
                    {
                        output
                            .lock()
                            .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?
                            .overflow_events += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                frames(&bytes[..count], |kind, _, payload| {
                    ensure!(kind == 0x0400, "unexpected NFLOG message type");
                    let mut state = output
                        .lock()
                        .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
                    collect(payload, &mut state, &mut pending, &mut previous);
                    Ok(())
                })?;
                if stop.load(Ordering::Relaxed) || window.elapsed() >= Duration::from_secs(1) {
                    break;
                }
            }
        }
        if window.elapsed() >= Duration::from_secs(1) {
            output
                .lock()
                .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?
                .store
                .append(&pending)?;
            pending.clear();
            let broadcasts = runtime.block_on(broadcasts(&handle))?;
            output
                .lock()
                .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?
                .broadcasts = broadcasts;
            window = Instant::now();
        }
    }
    let mut state = output
        .lock()
        .map_err(|_| anyhow::anyhow!("deny-log state poisoned"))?;
    state.store.append(&pending)?;
    state.status = "stopped";
    Ok(())
}

fn collect(
    payload: &[u8],
    state: &mut State,
    pending: &mut Vec<DenyRecord>,
    previous: &mut Option<u32>,
) {
    match decode(payload) {
        Ok((mut record, seq)) => {
            if let Some(last) = *previous {
                state.sequence_gaps += u64::from(seq.wrapping_sub(last.wrapping_add(1)));
            }
            *previous = Some(seq);
            if pending.len() >= RATE {
                state.discarded += 1;
            } else {
                record.ingress = interface(record.ingress_index);
                record.egress = interface(record.egress_index);
                if matches!(record.destination, IpAddr::V4(ip) if state.broadcasts.contains(&ip))
                    && !record.tags.contains(&DenyTrafficTag::Ipv4Broadcast)
                {
                    record.tags.push(DenyTrafficTag::Ipv4Broadcast);
                }
                pending.push(record);
            }
        }
        Err(error) => {
            state.malformed += 1;
            state.error = Some(format!("last malformed NFLOG record: {error:#}"));
        }
    }
}

fn interface(index: Option<u32>) -> Option<String> {
    let mut bytes = [0; libc::IF_NAMESIZE];
    let index = index?;
    if unsafe { libc::if_indextoname(index, bytes.as_mut_ptr()) }.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn decode(payload: &[u8]) -> Result<(DenyRecord, u32)> {
    ensure!(
        payload.len() >= 4 && u16::from_be_bytes(payload[2..4].try_into()?) == GROUP,
        "wrong NFLOG group"
    );
    let attrs = crate::netlink_decode::attributes(&payload[4..])?;
    let get = |kind| {
        attrs
            .iter()
            .find(|(k, _)| *k & 0x3fff == kind)
            .map(|(_, v)| v.as_slice())
    };
    let prefix = crate::netlink_decode::c_string(get(10).context("missing NFLOG prefix")?)?;
    let fields = prefix.split(':').collect::<Vec<_>>();
    ensure!(
        fields.len() == 5
            && fields[0] == "nc"
            && matches!(fields[1], "input" | "forward")
            && matches!(fields[2], "rule" | "policy" | "spoof_block"),
        "unrecognized deny-log prefix"
    );
    let index: u32 = fields[3].parse()?;
    ensure!(
        index <= 4096
            && (fields[2] == "rule" || index == 0)
            && fields[4].len() == 64
            && fields[4]
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "invalid deny-log rule identity"
    );
    let bytes = get(9).context("missing NFLOG packet header")?;
    let (source, destination, mut protocol, mut offset, length, mut fragment) =
        match bytes.first().map(|v| v >> 4) {
            Some(4) => {
                ensure!(bytes.len() >= 20, "short IPv4 header");
                let offset = usize::from(bytes[0] & 15) * 4;
                let length = u16::from_be_bytes(bytes[2..4].try_into()?) as u32;
                ensure!(
                    offset >= 20 && offset <= bytes.len() && length >= offset as u32,
                    "invalid IPv4 header"
                );
                (
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16])?)),
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20])?)),
                    bytes[9],
                    offset,
                    length,
                    u16::from_be_bytes(bytes[6..8].try_into()?) & 0x1fff != 0,
                )
            }
            Some(6) => {
                ensure!(bytes.len() >= 40, "short IPv6 header");
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24])?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40])?)),
                    bytes[6],
                    40,
                    u32::from(u16::from_be_bytes(bytes[4..6].try_into()?)) + 40,
                    false,
                )
            }
            _ => anyhow::bail!("unsupported deny-log packet family"),
        };
    let mut fragmented =
        fragment || (source.is_ipv4() && u16::from_be_bytes(bytes[6..8].try_into()?) & 0x2000 != 0);
    if source.is_ipv6() {
        for _ in 0..8 {
            if !matches!(protocol, 0 | 43 | 44 | 51 | 60) || offset + 2 > bytes.len() {
                break;
            }
            let next = bytes[offset];
            let size = match protocol {
                44 => {
                    if offset + 8 > bytes.len() {
                        break;
                    }
                    fragment =
                        u16::from_be_bytes(bytes[offset + 2..offset + 4].try_into()?) & 0xfff8 != 0;
                    fragmented = fragment || bytes[offset + 3] & 1 != 0;
                    8
                }
                51 => (usize::from(bytes[offset + 1]) + 2) * 4,
                _ => (usize::from(bytes[offset + 1]) + 1) * 8,
            };
            if offset + size > bytes.len() || offset + size > length as usize {
                break;
            }
            offset += size;
            protocol = next;
            if fragment {
                break;
            }
        }
    }
    let ports = if !fragment
        && matches!(protocol, 6 | 17 | 132)
        && offset + 4 <= bytes.len()
        && offset + 4 <= length as usize
    {
        Some((
            u16::from_be_bytes(bytes[offset..offset + 2].try_into()?),
            u16::from_be_bytes(bytes[offset + 2..offset + 4].try_into()?),
        ))
    } else {
        None
    };
    let tcp_flags = if protocol == 6
        && !fragment
        && offset + 20 <= bytes.len()
        && offset + 20 <= length as usize
    {
        let header_length = usize::from(bytes[offset + 12] >> 4) * 4;
        ensure!(
            header_length >= 20 && (fragmented || offset + header_length <= length as usize),
            "invalid deny-log TCP header length"
        );
        Some(bytes[offset + 13])
    } else {
        None
    };
    let tcp_payload_length = tcp_flags.and_then(|_| {
        (!fragmented).then(|| length - offset as u32 - u32::from(bytes[offset + 12] >> 4) * 4)
    });
    let mut tags = DenyTrafficTag::tcp(tcp_flags, tcp_payload_length);
    if matches!(destination, IpAddr::V4(ip) if ip.is_broadcast()) {
        tags.push(DenyTrafficTag::Ipv4Broadcast);
    }
    let index = |kind| -> Result<Option<u32>> {
        get(kind)
            .map(|v| -> Result<u32> { Ok(u32::from_be_bytes(v.try_into()?)) })
            .transpose()
            .map(|v| v.filter(|v| *v != 0))
    };
    let timestamp_ms = if let Some(timestamp) = get(3) {
        ensure!(timestamp.len() == 16, "invalid NFLOG timestamp");
        let seconds = u64::from_be_bytes(timestamp[..8].try_into()?);
        let micros = u64::from_be_bytes(timestamp[8..].try_into()?);
        ensure!(micros < 1_000_000, "invalid NFLOG microseconds");
        seconds
            .checked_mul(1000)
            .and_then(|v| v.checked_add(micros / 1000))
            .context("NFLOG timestamp overflow")?
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?
    };
    let sequence = u32::from_be_bytes(get(12).context("NFLOG sequence missing")?.try_into()?);
    Ok((
        DenyRecord {
            id: String::new(),
            timestamp_ms,
            chain: fields[1].into(),
            reason: fields[2].into(),
            compiled_rule_index: (fields[2] == "rule").then_some(fields[3].parse()?),
            ruleset_id: fields[4].into(),
            source,
            destination,
            protocol,
            source_port: ports.map(|v| v.0),
            destination_port: ports.map(|v| v.1),
            ingress_index: index(4)?,
            egress_index: index(5)?,
            ingress: None,
            egress: None,
            packet_length: length,
            tcp_flags,
            tcp_payload_length,
            tags,
        },
        sequence,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(packet: &[u8], sequence: u32) -> Vec<u8> {
        payload_with_reason(packet, sequence, "rule", 2)
    }

    fn payload_with_reason(packet: &[u8], sequence: u32, reason: &str, index: u32) -> Vec<u8> {
        let mut bytes = vec![libc::AF_INET as u8, 0];
        bytes.extend(GROUP.to_be_bytes());
        bytes.extend(attribute(9, packet));
        bytes.extend(attribute(
            10,
            format!("nc:input:{reason}:{index}:{}\0", "a".repeat(64)).as_bytes(),
        ));
        bytes.extend(attribute(12, &sequence.to_be_bytes()));
        bytes.extend(attribute(4, &2u32.to_be_bytes()));
        bytes.extend(attribute(
            3,
            &[2u64.to_be_bytes(), 123_456u64.to_be_bytes()].concat(),
        ));
        bytes
    }

    fn ipv4() -> Vec<u8> {
        let mut bytes = vec![0; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..24].copy_from_slice(&[0x04, 0xd2, 0, 53]);
        bytes
    }

    #[test]
    fn spoof_block_drop_reason_is_decoded_without_a_configured_rule_index() -> Result<()> {
        let (record, _) = decode(&payload_with_reason(&ipv4(), 1, "spoof_block", 0))?;
        assert_eq!(record.reason, "spoof_block");
        assert_eq!(record.chain, "input");
        assert!(record.compiled_rule_index.is_none());
        assert!(decode(&payload_with_reason(&ipv4(), 1, "spoof_block", 1)).is_err());
        Ok(())
    }

    fn tcp(flags: u8, payload_length: u16) -> Vec<u8> {
        let length = 40 + payload_length;
        let mut packet = ipv4();
        packet.resize(usize::from(length), 0);
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 6;
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }

    #[test]
    fn deny_log_tcp_metadata_handles_options_payload_fragments_and_capture_bounds() -> Result<()> {
        use DenyTrafficTag::*;
        for (flags, tags) in [
            (0x11, vec![TcpFinish]),
            (0x14, vec![TcpReset]),
            (0x10, vec![TcpAckOnly]),
            (0x02, vec![TcpConnectionAttempt]),
            (0x12, vec![]),
        ] {
            let record = decode(&payload(&tcp(flags, 0), 1))?.0;
            assert_eq!(record.packet_length, 40);
            assert_eq!(record.tcp_flags, Some(flags));
            assert_eq!(record.tcp_payload_length, Some(0));
            assert_eq!(record.tags, tags);
            record.validate_traffic()?;
        }
        let record = decode(&payload(&tcp(0x10, 10), 1))?.0;
        assert_eq!(record.tcp_payload_length, Some(10));
        assert!(record.tags.is_empty());

        let mut packet = tcp(0x10, 20);
        packet[32] = 0xa0;
        let record = decode(&payload(&packet[..40], 1))?.0;
        assert_eq!(record.tcp_payload_length, Some(0));
        assert_eq!(record.tags, [TcpAckOnly]);
        for size in 20..40 {
            let record = decode(&payload(&packet[..size], 1))?.0;
            assert_eq!(record.tcp_flags, None);
            assert_eq!(record.tcp_payload_length, None);
            assert!(record.tags.is_empty());
        }
        packet[32] = 0x40;
        assert!(decode(&payload(&packet, 1)).is_err());
        packet[32] = 0xf0;
        assert!(decode(&payload(&packet, 1)).is_err());

        let mut packet = tcp(0x10, 0);
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let record = decode(&payload(&packet, 1))?.0;
        assert_eq!(record.tcp_flags, Some(0x10));
        assert_eq!(record.tcp_payload_length, None);
        assert!(record.tags.is_empty());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(decode(&payload(&packet, 1))?.0.tcp_flags, None);

        let mut packet = tcp(0x11, 0);
        packet.splice(20..20, [0; 4]);
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&44u16.to_be_bytes());
        assert_eq!(decode(&payload(&packet, 1))?.0.tags, [TcpFinish]);

        let mut packet = vec![0; 68];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&28u16.to_be_bytes());
        packet[6] = 44;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>()?.octets());
        packet[40] = 6;
        packet[60] = 0x50;
        packet[61] = 0x10;
        let record = decode(&payload(&packet, 1))?.0;
        assert_eq!(record.tcp_payload_length, Some(0));
        assert_eq!(record.tags, [TcpAckOnly]);
        packet[43] = 1;
        let record = decode(&payload(&packet, 1))?.0;
        assert_eq!(record.tcp_flags, Some(0x10));
        assert_eq!(record.tcp_payload_length, None);
        assert!(record.tags.is_empty());
        packet[43] = 8;
        assert_eq!(decode(&payload(&packet, 1))?.0.tcp_flags, None);
        packet[6] = 0;
        packet[43] = 0;
        assert_eq!(decode(&payload(&packet, 1))?.0.tags, [TcpAckOnly]);
        let record = decode(&payload(&ipv4(), 1))?.0;
        assert_eq!(record.tcp_flags, None);
        assert!(record.tags.is_empty());
        Ok(())
    }

    #[test]
    fn deny_log_broadcasts_use_kernel_addresses_not_last_octet_guesses() -> Result<()> {
        let mut address = AddressMessage::default();
        address.header.prefix_len = 24;
        address.attributes = vec![AddressAttribute::Broadcast("10.4.30.255".parse()?)];
        assert_eq!(
            address_broadcasts(&address).collect::<Vec<_>>(),
            ["10.4.30.255".parse::<Ipv4Addr>()?]
        );
        address.header.prefix_len = 25;
        address.attributes = vec![AddressAttribute::Broadcast("10.4.30.127".parse()?)];
        let broadcasts: BTreeSet<_> = address_broadcasts(&address).collect();
        assert!(broadcasts.contains(&"10.4.30.127".parse()?));
        assert!(!broadcasts.contains(&"10.4.30.255".parse()?));
        address.header.prefix_len = 23;
        address.attributes = vec![AddressAttribute::Broadcast("10.4.31.255".parse()?)];
        let broadcasts: BTreeSet<_> = address_broadcasts(&address).collect();
        assert!(!broadcasts.contains(&"10.4.30.255".parse()?));
        for prefix in [31, 32] {
            address.header.prefix_len = prefix;
            assert_eq!(address_broadcasts(&address).count(), 0);
        }
        address.header.prefix_len = 24;
        address.attributes = vec![AddressAttribute::Local("10.4.30.1".parse()?)];
        assert_eq!(
            address_broadcasts(&address).collect::<Vec<_>>(),
            ["10.4.30.255".parse::<Ipv4Addr>()?]
        );
        address.header.prefix_len = 23;
        assert_eq!(
            address_broadcasts(&address).collect::<Vec<_>>(),
            ["10.4.31.255".parse::<Ipv4Addr>()?]
        );
        address.header.prefix_len = 25;
        address.attributes = vec![AddressAttribute::Address("10.4.30.1".parse()?)];
        assert_eq!(
            address_broadcasts(&address).collect::<Vec<_>>(),
            ["10.4.30.127".parse::<Ipv4Addr>()?]
        );
        address.header.prefix_len = 31;
        assert_eq!(address_broadcasts(&address).count(), 0);
        let mut packet = tcp(0x11, 0);
        packet[16..20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());
        let record = decode(&payload(&packet, 1))?.0;
        assert_eq!(
            record.tags,
            [DenyTrafficTag::TcpFinish, DenyTrafficTag::Ipv4Broadcast]
        );
        record.validate_traffic()?;
        Ok(())
    }

    #[test]
    fn deny_log_broadcast_snapshot_reads_current_namespace_without_mutation() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (connection, handle, _) = runtime.block_on(async { rtnetlink::new_connection() })?;
        let _connection = runtime.spawn(connection);
        runtime.block_on(broadcasts(&handle))?;
        Ok(())
    }

    #[test]
    fn deny_log_decodes_ipv4_ipv6_extensions_fragments_and_truncation() -> Result<()> {
        let mut packet = ipv4();
        let (record, sequence) = decode(&payload(&packet, 7))?;
        ensure!(
            sequence == 7
                && record.timestamp_ms == 2123
                && record.source_port == Some(1234)
                && record.destination_port == Some(53),
            "IPv4 tuple/time"
        );
        ensure!(
            record.chain == "input"
                && record.compiled_rule_index == Some(2)
                && record.ingress_index == Some(2),
            "attribution"
        );
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        ensure!(
            decode(&payload(&packet, 8))?.0.source_port.is_none(),
            "noninitial IPv4 fragment port fabricated"
        );
        packet[0] = 0x4f;
        ensure!(
            decode(&payload(&packet, 8)).is_err(),
            "truncated options accepted"
        );
        let mut packet = vec![0; 52];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12u16.to_be_bytes());
        packet[6] = 44;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>()?.octets());
        packet[40] = 6;
        packet[48..52].copy_from_slice(&[0x04, 0xd2, 1, 0xbb]);
        let record = decode(&payload(&packet, 9))?.0;
        ensure!(
            record.source.is_ipv6() && record.protocol == 6 && record.destination_port == Some(443),
            "IPv6 extension/port"
        );
        packet[42..44].copy_from_slice(&8u16.to_be_bytes());
        ensure!(
            decode(&payload(&packet, 10))?.0.source_port.is_none(),
            "noninitial IPv6 fragment port fabricated"
        );
        for size in 0..20 {
            ensure!(
                decode(&payload(&ipv4()[..size], 1)).is_err(),
                "short IP header accepted"
            );
        }
        ensure!(decode(&[0; 3]).is_err(), "short nfgen header accepted");
        Ok(())
    }

    #[test]
    fn deny_log_rate_bound_and_loss_accounting() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "deny-rate-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let result = (|| -> Result<()> {
            let mut state = State {
                store: store::Store::open(root.clone())?,
                status: "capturing",
                error: None,
                discarded: 0,
                malformed: 0,
                overflow_events: 0,
                sequence_gaps: 0,
                broadcasts: ["198.51.100.2".parse()?].into(),
            };
            let mut pending = Vec::new();
            let mut previous = Some(u32::MAX);
            for sequence in 0..110 {
                collect(
                    &payload(&ipv4(), sequence),
                    &mut state,
                    &mut pending,
                    &mut previous,
                );
            }
            ensure!(
                pending.len() == 100 && state.discarded == 10 && state.sequence_gaps == 0,
                "rate bound or sequence wrap"
            );
            collect(
                &payload(&ipv4(), 115),
                &mut state,
                &mut pending,
                &mut previous,
            );
            collect(&[], &mut state, &mut pending, &mut previous);
            ensure!(
                state.sequence_gaps == 5
                    && state.discarded == 11
                    && state.malformed == 1
                    && state.error.is_some(),
                "loss/error reporting"
            );
            state.store.append(&pending)?;
            assert_eq!(pending[0].tags, [DenyTrafficTag::Ipv4Broadcast]);
            ensure!(
                state.store.query(&DenyLogQuery::parse(
                    "limit=500&include_broadcast=true&include_tcp_closures=true"
                )?)["records"]
                    .as_array()
                    .unwrap()
                    .len()
                    == 100,
                "persisted rate bound"
            );
            Ok(())
        })();
        std::fs::remove_dir_all(&root)?;
        result
    }

    #[test]
    fn deny_log_frames_are_strict_and_bounded() -> Result<()> {
        let mut frame = vec![0; 20];
        frame[..4].copy_from_slice(&20u32.to_ne_bytes());
        frame[4..6].copy_from_slice(&0x0400u16.to_ne_bytes());
        let mut count = 0;
        frames(
            &[frame.clone(), frame.clone()].concat(),
            |kind, _, bytes| {
                ensure!(kind == 0x0400 && bytes.len() == 4, "frame contents");
                count += 1;
                Ok(())
            },
        )?;
        ensure!(count == 2, "batched frames");
        for size in 1..20 {
            ensure!(
                frames(&frame[..size], |_, _, _| Ok(())).is_err(),
                "truncated frame accepted"
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespaces, net_admin and NFLOG/nft_log"]
    fn deny_log_native_drops_accepts_restart_and_drift() -> Result<()> {
        use super::super::{firewall, netfilter, session};
        use futures_util::TryStreamExt;
        use std::{fs, net::UdpSocket};
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "set NETCONTROL_INTEGRATION=1"
        );
        let namespace = || -> Result<Arc<File>> {
            thread::spawn(|| -> Result<Arc<File>> {
                ensure!(
                    unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                    "test namespace: {}",
                    io::Error::last_os_error()
                );
                Ok(Arc::new(File::open("/proc/thread-self/ns/net")?))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("namespace fixture panicked"))?
        };
        let router = namespace()?;
        let client = namespace()?;
        let peer = client.clone();
        session(router.clone(), move |rt, handle| {
            rt.block_on(async {
                handle
                    .link()
                    .add(rtnetlink::LinkVeth::new("lan0", "client0").build())
                    .execute()
                    .await?;
                let link = handle
                    .link()
                    .get()
                    .match_name("client0".into())
                    .execute()
                    .try_next()
                    .await?
                    .context("missing veth peer")?;
                handle
                    .link()
                    .set(
                        rtnetlink::LinkUnspec::new_with_index(link.header.index)
                            .setns_by_fd(peer.as_raw_fd())
                            .build(),
                    )
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
        for (ns, name, ipv4, ipv6, gateway) in [
            (
                router.clone(),
                "lan0",
                "192.0.2.1",
                "2001:db8::1",
                "192.0.2.2",
            ),
            (
                client.clone(),
                "client0",
                "192.0.2.2",
                "2001:db8::2",
                "192.0.2.1",
            ),
        ] {
            session(ns, move |rt, handle| {
                rt.block_on(async {
                    fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0")?;
                    let link = handle
                        .link()
                        .get()
                        .match_name(name.into())
                        .execute()
                        .try_next()
                        .await?
                        .context("missing test interface")?;
                    handle
                        .address()
                        .add(link.header.index, ipv4.parse()?, 24)
                        .execute()
                        .await?;
                    handle
                        .address()
                        .add(link.header.index, ipv6.parse()?, 64)
                        .execute()
                        .await?;
                    handle
                        .link()
                        .set(
                            rtnetlink::LinkUnspec::new_with_index(link.header.index)
                                .up()
                                .build(),
                        )
                        .execute()
                        .await?;
                    handle
                        .route()
                        .add(
                            rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                                .destination_prefix("198.51.100.0".parse()?, 24)
                                .gateway(gateway.parse()?)
                                .output_interface(link.header.index)
                                .build(),
                        )
                        .execute()
                        .await?;
                    Ok(())
                })
            })?;
        }
        session(router.clone(), |_, _| {
            fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
            Ok(())
        })?;
        let root = std::env::temp_dir().join(format!(
            "deny-native-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let result = (|| -> Result<()> {
            let mut monitor = Monitor::new(router.clone(), root.clone())?;
            monitor.configure(true)?;
            let receiver4 = session(router.clone(), |_, _| {
                Ok(UdpSocket::bind("192.0.2.1:8080")?)
            })?;
            let receiver6 = session(router.clone(), |_, _| {
                Ok(UdpSocket::bind("[2001:db8::1]:8080")?)
            })?;
            receiver4.set_read_timeout(Some(Duration::from_millis(300)))?;
            receiver6.set_read_timeout(Some(Duration::from_millis(300)))?;
            let sender4 = session(client.clone(), |_, _| Ok(UdpSocket::bind("192.0.2.2:0")?))?;
            let sender6 = session(client.clone(), |_, _| {
                Ok(UdpSocket::bind("[2001:db8::2]:0")?)
            })?;
            let base = json!({"policy":"accept","allow_all_icmp":false,"rules":[],"nat":{"masquerade":[]},"input":{"policy":"accept","interfaces":[]}});
            let install = |value: Value| {
                session(router.clone(), move |_, _| {
                    firewall::apply(&value, &[])?;
                    netfilter::fingerprint()
                })
            };
            let original = install(base.clone())?;
            sender4.send_to(b"allowed", "192.0.2.1:8080")?;
            sender6.send_to(b"allowed", "[2001:db8::1]:8080")?;
            let mut bytes = [0; 32];
            ensure!(
                receiver4.recv(&mut bytes)? == 7 && receiver6.recv(&mut bytes)? == 7,
                "accept behavior changed"
            );
            thread::sleep(Duration::from_millis(1100));
            let query =
                DenyLogQuery::parse("limit=500&include_broadcast=true&include_tcp_closures=true")?;
            ensure!(
                monitor.snapshot(&query)?["records"] == json!([]),
                "accepted packets logged as denied"
            );
            let mut drop = base.clone();
            drop["policy"] = json!("drop");
            drop["input"]["policy"] = json!("drop");
            let fingerprint = install(drop.clone())?;
            sender4.send_to(b"denied", "192.0.2.1:8080")?;
            sender6.send_to(b"denied", "[2001:db8::1]:8080")?;
            sender4.send_to(b"denied", "198.51.100.9:8080")?;
            ensure!(
                receiver4.recv(&mut bytes).is_err() && receiver6.recv(&mut bytes).is_err(),
                "drop verdict changed"
            );
            let wait = |monitor: &Monitor, count: usize| -> Result<Value> {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let value = monitor.snapshot(&query)?;
                    ensure!(
                        value["capture"]["status"] != "error",
                        "capture failed: {value}"
                    );
                    if value["records"].as_array().unwrap().len() >= count {
                        return Ok(value);
                    }
                    ensure!(Instant::now() < deadline, "deny records missing: {value}");
                    thread::sleep(Duration::from_millis(50));
                }
            };
            let history = wait(&monitor, 3)?;
            let records = history["records"].as_array().unwrap();
            ensure!(
                records.iter().any(|r| r["chain"] == "input"
                    && r["source"] == "192.0.2.2"
                    && r["reason"] == "policy"),
                "IPv4 input policy absent"
            );
            ensure!(
                records
                    .iter()
                    .any(|r| r["chain"] == "input" && r["source"] == "2001:db8::2"),
                "IPv6 input policy absent"
            );
            ensure!(
                records
                    .iter()
                    .any(|r| r["chain"] == "forward" && r["reason"] == "policy"),
                "forward default absent"
            );
            ensure!(
                session(router.clone(), |_, _| netfilter::fingerprint())? == fingerprint,
                "logging caused firewall drift"
            );
            drop["rules"] = json!([{"source":"192.0.2.2/32","action":"drop"}]);
            drop["input"]["interfaces"] = json!([{"interface":"lan0","rules":[{"protocol":"udp","destination_ports":[8080],"action":"drop"}]}]);
            install(drop.clone())?;
            sender4.send_to(b"rule", "192.0.2.1:8080")?;
            sender4.send_to(b"rule", "198.51.100.9:8080")?;
            let history = wait(&monitor, 5)?;
            ensure!(
                history["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["reason"] == "rule")
                    .count()
                    == 2,
                "explicit drops absent"
            );
            monitor.shutdown()?;
            std::mem::drop(monitor);
            let mut monitor = Monitor::new(router.clone(), root.clone())?;
            monitor.configure(true)?;
            ensure!(
                monitor.snapshot(&query)?["records"] == history["records"],
                "history lost on restart"
            );
            drop["drop_logging_enabled"] = json!(false);
            let disabled_fingerprint = install(drop.clone())?;
            monitor.configure(false)?;
            ensure!(monitor.thread.is_none(), "disabled collector still running");
            let disabled = monitor.snapshot(&query)?;
            ensure!(
                disabled["capture"]["status"] == "disabled",
                "disabled status missing"
            );
            ensure!(
                monitor
                    .first_drops(&netcontrol_core::DiscordConfig {
                        enabled: true,
                        ..Default::default()
                    })
                    .is_err(),
                "disabled logging supplied alerts"
            );
            sender4.send_to(b"unlogged", "192.0.2.1:8080")?;
            sender4.send_to(b"unlogged", "198.51.100.9:8080")?;
            ensure!(
                receiver4.recv(&mut bytes).is_err(),
                "disabled logging changed drop verdict"
            );
            thread::sleep(Duration::from_millis(1100));
            ensure!(
                monitor.snapshot(&query)?["records"] == disabled["records"],
                "disabled logging recorded traffic"
            );
            let disabled_config = drop.clone();
            session(router.clone(), move |_, _| {
                let rules = netfilter::rules()?;
                for rule in rules {
                    for (kind, data) in crate::netlink_decode::attributes(&rule[4..])? {
                        if kind & 0x3fff == 4 {
                            for (_, expression) in crate::netlink_decode::attributes(&data)? {
                                for (kind, name) in crate::netlink_decode::attributes(&expression)?
                                {
                                    ensure!(
                                        kind & 0x3fff != 1 || name != b"log\0",
                                        "disabled rules contain log expressions"
                                    );
                                }
                            }
                        }
                    }
                }
                ensure!(
                    netfilter::fingerprint()? == disabled_fingerprint,
                    "disabled firewall drift"
                );
                let counters = firewall::counters(
                    &disabled_config,
                    &[],
                    &Some(disabled_config.clone()),
                    &disabled_fingerprint,
                )?;
                for chain in ["input", "forward"] {
                    ensure!(
                        counters["rules"]
                            .as_array()
                            .context("counter rows missing")?
                            .iter()
                            .any(|row| row["chain"] == chain
                                && row["packets"]
                                    .as_str()
                                    .and_then(|v| v.parse::<u64>().ok())
                                    .is_some_and(|v| v >= 1)),
                        "disabled logging stopped {chain} counters"
                    );
                }
                Ok(())
            })?;
            monitor.configure(true)?;
            drop["drop_logging_enabled"] = json!(true);
            install(drop)?;
            sender4.send_to(b"resumed", "192.0.2.1:8080")?;
            let resumed = wait(&monitor, disabled["records"].as_array().unwrap().len() + 1)?;
            ensure!(
                resumed["capture"]["status"] == "capturing",
                "capture did not resume"
            );
            ensure!(
                install(base)? != original,
                "rollback must reset counter generation"
            );
            sender4.send_to(b"restored", "192.0.2.1:8080")?;
            ensure!(
                receiver4.recv(&mut bytes)? == 8,
                "rollback did not restore acceptance"
            );
            std::mem::drop(monitor);
            Ok(())
        })();
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        result
    }
}
