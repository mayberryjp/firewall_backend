use crate::link_monitor::{Capture, delta, header, queue, rtt_rise, tcp_info, u32_at};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const NETLINK_LIMIT: usize = 16 * 1024 * 1024;
const ROW_LIMIT: usize = 8192;

pub struct Monitor {
    state: Arc<Mutex<(Instant, Value)>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Monitor {
    pub fn restart(&mut self, namespace: Arc<File>) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("link monitor thread panicked"))?;
        }
        *self = Self::new(namespace)?;
        Ok(())
    }
    pub fn new(namespace: Arc<File>) -> Result<Self> {
        let state = Arc::new(Mutex::new((
            Instant::now(),
            json!({
                "schema":"netcontrol-link-diagnostics/v1","status":"starting","collected_at":null,
                "error":null,"queues":null,"local_tcp":null,"packet_headers":null,"interfaces":null,"signals":[]
            }),
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let output = state.clone();
        let stopping = stop.clone();
        let thread = thread::Builder::new()
            .name("link-diagnostics".into())
            .spawn(move || {
                let result = (|| -> Result<()> {
                    let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
                    let target = namespace.metadata()?;
                    if current.dev() != target.dev() || current.ino() != target.ino() {
                        ensure!(
                            unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0,
                            "enter link monitor namespace: {}",
                            io::Error::last_os_error()
                        );
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    publish_error(&output, &error);
                    return;
                }
                let mut capture = Capture::default();
                let mut packet = None;
                let mut baseline = Baseline::default();
                let mut totals = Totals::default();
                let mut next = Instant::now();
                while !stopping.load(Ordering::Relaxed) {
                    if Instant::now() >= next {
                        if packet.is_none() {
                            match packet_socket() {
                                Ok(socket) => packet = Some(socket),
                                Err(error) => {
                                    publish_error(&output, &error);
                                    next = Instant::now() + Duration::from_secs(1);
                                    thread::sleep(Duration::from_millis(100));
                                    continue;
                                }
                            }
                        }
                        match sample(
                            packet.as_ref().unwrap(),
                            &mut capture,
                            &mut baseline,
                            &mut totals,
                        ) {
                            Ok(value) => {
                                if let Ok(mut state) = output.lock() {
                                    *state = (Instant::now(), value);
                                }
                            }
                            Err(error) => {
                                publish_error(&output, &error);
                                // Never bridge rate/delta baselines over an unavailable interval.
                                baseline = Baseline::default();
                            }
                        }
                        next = Instant::now() + Duration::from_secs(1);
                    }
                    if let Some(socket) = &packet {
                        if let Err(error) = receive(socket, &mut capture, &stopping) {
                            publish_error(&output, &error);
                            capture.capture_gaps += 1;
                            packet = None;
                            baseline = Baseline::default();
                        }
                    } else {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })?;
        Ok(Self {
            state,
            stop,
            thread: Some(thread),
        })
    }

    pub fn snapshot(&self) -> Result<Value> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("link monitor cache poisoned"))?;
        let mut value = state.1.clone();
        if state.0.elapsed() > Duration::from_secs(5) {
            value["status"] = json!("stale");
            value["error"] = json!("link monitor has not completed a sample within five seconds");
            value["signals"] = json!([]);
        }
        value["age_ms"] = json!(state.0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::TryStreamExt;
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
    };

    #[test]
    fn stale_and_failed_samples_cannot_look_healthy_or_refresh_timestamps() -> Result<()> {
        let monitor = Monitor {
            state: Arc::new(Mutex::new((
                Instant::now() - Duration::from_secs(6),
                json!({"status":"available","collected_at":"2026-10-27T00:00:00Z",
                    "signals":["local_egress_drops"],"local_tcp":{"observed_retransmissions":"7"}}),
            ))),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
        };
        let stale = monitor.snapshot()?;
        ensure!(
            stale["status"] == "stale" && stale["signals"] == json!([]),
            "stale evidence presented as current"
        );
        publish_error(&monitor.state, &anyhow::anyhow!("synthetic kernel failure"));
        let state = monitor.state.lock().unwrap();
        ensure!(
            state.1["status"] == "unavailable" && state.1["local_tcp"].is_null(),
            "failure fabricated TCP statistics"
        );
        ensure!(
            state.1["collected_at"] == "2026-10-27T00:00:00Z",
            "failure refreshed success timestamp"
        );
        Ok(())
    }

    fn namespace() -> Result<Arc<File>> {
        thread::spawn(|| {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                "test network namespace: {}",
                io::Error::last_os_error()
            );
            Ok(Arc::new(File::open("/proc/thread-self/ns/net")?))
        })
        .join()
        .map_err(|_| anyhow::anyhow!("namespace fixture panicked"))?
    }

    fn configure(
        namespace: Arc<File>,
        name: &str,
        address: &str,
        gateway: Option<&str>,
    ) -> Result<()> {
        let name = name.to_string();
        let address: std::net::IpAddr = address.parse()?;
        let gateway: Option<std::net::Ipv4Addr> = gateway.map(str::parse).transpose()?;
        super::super::session(namespace, move |runtime, handle| {
            runtime.block_on(async {
                for name in ["lo", name.as_str()] {
                    let link = handle
                        .link()
                        .get()
                        .match_name(name.into())
                        .execute()
                        .try_next()
                        .await?
                        .context("fixture link missing")?;
                    handle.link().set(link.header.index).up().execute().await?;
                    if name != "lo" {
                        handle
                            .address()
                            .add(link.header.index, address, 24)
                            .execute()
                            .await?;
                    }
                }
                if let Some(gateway) = gateway {
                    handle
                        .route()
                        .add()
                        .v4()
                        .destination_prefix("0.0.0.0".parse()?, 0)
                        .gateway(gateway)
                        .execute()
                        .await?;
                }
                Ok(())
            })
        })
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1, Linux SYS_ADMIN/NET_ADMIN/NET_RAW in disposable container"]
    fn native_link_diagnostics_observes_forwarded_tcp_without_local_sockets() -> Result<()> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "integration opt-in required"
        );
        let router = namespace()?;
        let client_ns = namespace()?;
        let server_ns = namespace()?;
        let client_target = client_ns.clone();
        let server_target = server_ns.clone();
        super::super::session(router.clone(), move |runtime, handle| {
            runtime.block_on(async {
                for (inside, outside, target) in [
                    ("diag-in", "diag-client", client_target),
                    ("diag-out", "diag-server", server_target),
                ] {
                    handle
                        .link()
                        .add()
                        .veth(inside.into(), outside.into())
                        .execute()
                        .await?;
                    let peer = handle
                        .link()
                        .get()
                        .match_name(outside.into())
                        .execute()
                        .try_next()
                        .await?
                        .context("missing veth peer")?;
                    handle
                        .link()
                        .set(peer.header.index)
                        .setns_by_fd(target.as_raw_fd())
                        .execute()
                        .await?;
                }
                std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
                Ok(())
            })
        })?;
        configure(router.clone(), "diag-in", "192.0.2.1", None)?;
        configure(router.clone(), "diag-out", "198.51.100.1", None)?;
        configure(
            client_ns.clone(),
            "diag-client",
            "192.0.2.2",
            Some("192.0.2.1"),
        )?;
        configure(
            server_ns.clone(),
            "diag-server",
            "198.51.100.2",
            Some("198.51.100.1"),
        )?;
        let listener = super::super::session(server_ns, |_, _| {
            let listener = TcpListener::bind("198.51.100.2:0")?;
            listener.set_nonblocking(true)?;
            Ok(listener)
        })?;
        let destination = listener.local_addr()?;
        let monitor = Monitor::new(router)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while monitor.snapshot()?["status"] != "available" {
            ensure!(
                Instant::now() < deadline,
                "forwarding monitor startup: {}",
                monitor.snapshot()?
            );
            thread::sleep(Duration::from_millis(20));
        }
        let mut client = super::super::session(client_ns, move |_, _| {
            Ok(TcpStream::connect_timeout(
                &destination,
                Duration::from_secs(2),
            )?)
        })?;
        let (server, _) = listener.accept()?;
        client.write_all(b"synthetic forwarded TCP traffic")?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let value = monitor.snapshot()?;
            let rows = value["packet_headers"]["interfaces"].as_array();
            if rows.is_some_and(|rows| {
                ["diag-in", "diag-out"]
                    .iter()
                    .all(|name| rows.iter().any(|row| row["name"] == *name))
            }) {
                ensure!(
                    value["local_tcp"]["established_sockets"] == 0,
                    "forwarded TCP must not be reported as local TCP: {value}"
                );
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "forwarded headers not observed: {value}"
            );
            thread::sleep(Duration::from_millis(20));
        }
        drop((client, server, monitor));
        Ok(())
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and packet sockets in a disposable container"]
    fn native_link_diagnostics_reports_capture_loss_without_fabricated_recovery() -> Result<()> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "integration opt-in required"
        );
        let packet = packet_socket()?;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        sender.connect(receiver.local_addr()?)?;
        for _ in 0..30_000 {
            sender.send(&[0u8; 1024])?;
        }
        let mut capture = Capture::default();
        let mut baseline = Baseline::default();
        let mut totals = Totals::default();
        let first = sample(&packet, &mut capture, &mut baseline, &mut totals)?;
        ensure!(
            capture.kernel_drops > 0,
            "fixture did not overflow header capture: {first}"
        );
        ensure!(
            first["status"] == "available"
                && first["packet_headers"]["statistics_complete"] == false,
            "capture loss stopped collection or claimed complete statistics"
        );
        let count = capture.kernel_drops;
        let second = sample(&packet, &mut capture, &mut baseline, &mut totals)?;
        ensure!(
            capture.kernel_drops >= count
                && second["packet_headers"]["statistics_complete"] == false,
            "capture loss disappeared on the next sample"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux packet sockets in a disposable network namespace/container"]
    fn native_link_diagnostics_collects_real_kernel_state_and_stops() -> Result<()> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "set NETCONTROL_INTEGRATION=1 on a disposable Linux host"
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (_server, _) = listener.accept()?;
        let packet = packet_socket()?;
        let mut capture = Capture::default();
        let mut baseline = Baseline::default();
        let mut totals = Totals::default();
        let first = sample(&packet, &mut capture, &mut baseline, &mut totals)?;
        ensure!(
            first["local_tcp"]["established_sockets"]
                .as_u64()
                .unwrap_or(0)
                >= 2,
            "real TCP sockets not measured: {first}"
        );
        ensure!(
            first["local_tcp"]["retransmissions_delta"].is_null(),
            "fabricated first delta"
        );
        client.write_all(b"synthetic link diagnostic fixture")?;
        thread::sleep(Duration::from_millis(50));
        receive(&packet, &mut capture, &AtomicBool::new(false))?;
        let second = sample(&packet, &mut capture, &mut baseline, &mut totals)?;
        ensure!(
            second["status"] == "available",
            "kernel sample unavailable: {second}"
        );
        ensure!(
            second["local_tcp"]["compared_sockets"]
                .as_u64()
                .unwrap_or(0)
                >= 2,
            "TCP identities not stable"
        );
        ensure!(
            second["packet_headers"]["interfaces"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "real TCP headers not captured: {second}"
        );
        ensure!(
            second["queues"].is_array() && second["interfaces"].is_array(),
            "missing kernel sections"
        );
        let monitor = Monitor::new(Arc::new(File::open("/proc/thread-self/ns/net")?))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let value = monitor.snapshot()?;
            if value["status"] == "available" {
                break;
            }
            ensure!(Instant::now() < deadline, "worker not responsive: {value}");
            thread::sleep(Duration::from_millis(20));
        }
        let started = Instant::now();
        drop(monitor);
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "worker shutdown exceeded two seconds"
        );
        Ok(())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                eprintln!("link diagnostics worker panicked during shutdown");
            }
        }
    }
}

fn publish_error(state: &Mutex<(Instant, Value)>, error: &anyhow::Error) {
    if let Ok(mut state) = state.lock() {
        state.1["status"] = json!("unavailable");
        state.1["error"] = json!(format!("{error:#}"));
        state.1["signals"] = json!([]);
        state.1["queues"] = Value::Null;
        state.1["local_tcp"] = Value::Null;
        state.1["packet_headers"] = Value::Null;
        state.1["interfaces"] = Value::Null;
        // Keep the last successful timestamp, so errors cannot look like fresh samples.
    }
}

fn socket(family: i32, kind: i32, protocol: i32) -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, protocol) };
    ensure!(
        fd >= 0,
        "link monitor socket: {}",
        io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn option<T>(fd: &OwnedFd, level: i32, name: i32, value: &T) -> Result<()> {
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (value as *const T).cast(),
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        } == 0,
        "link monitor socket option: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

fn packet_socket() -> Result<OwnedFd> {
    let fd = socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0)?;
    option(
        &fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &(4 * 1024 * 1024i32),
    )?;
    // SOCK_DGRAM removes link-layer headers, including on decrypted tunnel devices.
    // Filter on the kernel-provided protocol, not arbitrary packet payload bytes.
    let mut instructions = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0xffff_f000,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0x0800,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0x86dd,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 256,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    option(&fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program)?;
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    ensure!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } == 0,
        "bind header capture: {}",
        io::Error::last_os_error()
    );
    Ok(fd)
}

fn receive(fd: &OwnedFd, capture: &mut Capture, stop: &AtomicBool) -> Result<()> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut poll, 1, 100) };
    if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
        return Ok(());
    }
    ensure!(
        ready >= 0,
        "poll header capture: {}",
        io::Error::last_os_error()
    );
    ensure!(
        poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
        "header capture socket failed"
    );
    for _ in 0..4096 {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut bytes = [0u8; 256];
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        let size = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
                (&mut address as *mut libc::sockaddr_ll).cast(),
                &mut length,
            )
        };
        if size < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("receive TCP headers");
        }
        if address.sll_pkttype == libc::PACKET_OUTGOING || address.sll_ifindex <= 0 {
            continue;
        }
        match header(address.sll_ifindex as u32, &bytes[..size as usize]) {
            Ok(Some(header)) => capture.record(header, Instant::now()),
            Ok(None) => {}
            Err(_) => capture.rejected += 1,
        }
    }
    Ok(())
}

fn dump(protocol: i32, kind: u16, payload: &[u8], response_kind: u16) -> Result<Vec<Vec<u8>>> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, protocol)?;
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    option(&fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeout)?;
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    let mut request = ((16 + payload.len()) as u32).to_ne_bytes().to_vec();
    request.extend(kind.to_ne_bytes());
    request.extend(0x301u16.to_ne_bytes());
    request.extend(1u32.to_ne_bytes());
    request.extend(0u32.to_ne_bytes());
    request.extend(payload);
    ensure!(
        unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } == request.len() as isize,
        "send diagnostics dump: {}",
        io::Error::last_os_error()
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut rows = Vec::new();
    let mut total = 0;
    let mut buffer = vec![0u8; 65536];
    loop {
        ensure!(
            Instant::now() < deadline,
            "kernel diagnostics dump deadline exceeded"
        );
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&sender) as libc::socklen_t;
        let size = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut length,
            )
        };
        if size < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            size > 0 && size as usize <= buffer.len(),
            "receive diagnostics dump: truncated/failed: {}",
            io::Error::last_os_error()
        );
        ensure!(
            sender.nl_pid == 0,
            "diagnostics response is not from kernel"
        );
        total += size as usize;
        ensure!(
            total <= NETLINK_LIMIT,
            "kernel diagnostics byte limit exceeded"
        );
        let mut bytes = &buffer[..size as usize];
        while !bytes.is_empty() {
            ensure!(bytes.len() >= 16, "short diagnostics netlink header");
            let size = u32_at(bytes, 0)? as usize;
            let kind = u16::from_ne_bytes(bytes[4..6].try_into()?);
            let flags = u16::from_ne_bytes(bytes[6..8].try_into()?);
            ensure!(
                size >= 16 && size <= bytes.len() && ((size + 3) & !3) <= bytes.len(),
                "invalid diagnostics message"
            );
            ensure!(
                u32_at(bytes, 8)? == 1 && flags & 0x10 == 0,
                "interrupted/mismatched diagnostics dump"
            );
            let payload = &bytes[16..size];
            if kind == 3 {
                if payload.len() >= 4 {
                    ensure!(u32_at(payload, 0)? == 0, "kernel rejected diagnostics dump");
                }
                return Ok(rows);
            }
            if kind == 2 {
                let errno = u32_at(payload, 0)? as i32;
                ensure!(
                    errno == 0,
                    "kernel diagnostics: {}",
                    io::Error::from_raw_os_error(-errno)
                );
            } else {
                ensure!(
                    kind == response_kind,
                    "unexpected kernel diagnostics response"
                );
                ensure!(
                    rows.len() < ROW_LIMIT,
                    "kernel diagnostics row limit exceeded"
                );
                rows.push(payload.to_vec());
            }
            bytes = &bytes[(size + 3) & !3..];
        }
    }
}

#[derive(Default)]
struct Baseline {
    time: Option<Instant>,
    queues: BTreeMap<(u32, u32, u32, String), (u64, u64)>,
    sockets: BTreeMap<[u8; 8], (u64, u32, Option<u64>)>,
    interfaces: BTreeMap<u32, (String, u64, u64)>,
    rtt: Option<f64>,
    zero_observations: Option<u64>,
}

#[derive(Default)]
struct Totals {
    retransmissions: u64,
    cwnd_reductions: u64,
}

fn sample(
    packet: &OwnedFd,
    capture: &mut Capture,
    baseline: &mut Baseline,
    totals: &mut Totals,
) -> Result<Value> {
    let mut names = BTreeMap::new();
    let mut interface_rows = Vec::new();
    let mut interfaces = BTreeMap::new();
    let mut signals = BTreeSet::new();
    let mut link_request = vec![0; 16];
    link_request[0] = libc::AF_UNSPEC as u8;
    for bytes in dump(libc::NETLINK_ROUTE, 18, &link_request, 16)? {
        ensure!(bytes.len() >= 16, "short link diagnostics");
        let index = u32_at(&bytes, 4)?;
        let attrs = crate::netlink_decode::attributes(&bytes[16..])?;
        let name = attrs
            .iter()
            .find(|(kind, _)| *kind & 0x3fff == 3)
            .context("link name missing")?;
        let name = crate::netlink_decode::c_string(&name.1)?.to_string();
        names.insert(index, name.clone());
        if let Some((_, stats)) = attrs.iter().find(|(kind, _)| *kind & 0x3fff == 23) {
            ensure!(stats.len() >= 64, "short interface counters");
            let counter = |offset| -> Result<u64> {
                Ok(u64::from_ne_bytes(stats[offset..offset + 8].try_into()?))
            };
            let errors = counter(32)?
                .checked_add(counter(40)?)
                .context("interface error counter overflow")?;
            let drops = counter(48)?
                .checked_add(counter(56)?)
                .context("interface drop counter overflow")?;
            let old = baseline
                .interfaces
                .get(&index)
                .filter(|(old_name, _, _)| old_name == &name);
            let error_delta = delta(old.map(|(_, e, _)| *e), errors);
            let drop_delta = delta(old.map(|(_, _, d)| *d), drops);
            if error_delta.is_some_and(|v| v > 0) {
                signals.insert("interface_errors");
            }
            if drop_delta.is_some_and(|v| v > 0) {
                signals.insert("interface_drops");
            }
            interface_rows.push(json!({"index":index,"name":name,"errors":errors.to_string(),"drops":drops.to_string(),
                "errors_delta":error_delta.map(|v| v.to_string()),"drops_delta":drop_delta.map(|v| v.to_string())}));
            interfaces.insert(index, (name, errors, drops));
        }
    }
    let mut queues = Vec::new();
    let mut queue_baseline = BTreeMap::new();
    for bytes in dump(libc::NETLINK_ROUTE, 38, &[0; 20], 36)? {
        ensure!(bytes.len() >= 20, "short qdisc diagnostics");
        let index = u32_at(&bytes, 4)?;
        let handle = u32_at(&bytes, 8)?;
        let parent = u32_at(&bytes, 12)?;
        let attrs = crate::netlink_decode::attributes(&bytes[20..])?;
        let kind = attrs
            .iter()
            .find(|(kind, _)| *kind & 0x3fff == 1)
            .context("qdisc kind missing")?;
        let kind = crate::netlink_decode::c_string(&kind.1)?;
        let stats = attrs
            .iter()
            .find(|(kind, _)| *kind & 0x3fff == 7)
            .map(|(_, bytes)| crate::netlink_decode::attributes(bytes))
            .transpose()?;
        let queue_stats = stats
            .as_ref()
            .and_then(|attrs| attrs.iter().find(|(kind, _)| *kind & 0x3fff == 3));
        let mut row = json!({"index":index,"name":names.get(&index),"handle":handle,"parent":parent,"kind":kind,
            "status":"unavailable","queue":null,"drops_delta":null,"backlog_growth_bytes":null});
        if let Some((_, bytes)) = queue_stats {
            let value = queue(bytes)?;
            let drops = value["drops"]
                .as_str()
                .context("qdisc drops")?
                .parse::<u64>()?;
            let backlog = value["backlog_bytes"].as_u64().context("qdisc backlog")?;
            let key = (index, handle, parent, kind.to_string());
            let old = baseline.queues.get(&key);
            let drops_delta = delta(old.map(|v| v.0), drops);
            let growth = old.map(|v| i128::from(backlog) - i128::from(v.1));
            if drops_delta.is_some_and(|v| v > 0) {
                signals.insert("local_egress_drops");
            }
            if growth.is_some_and(|v| v > 0) {
                signals.insert("local_queue_growth");
            }
            row["status"] = json!("available");
            row["queue"] = value;
            row["drops_delta"] = json!(drops_delta.map(|v| v.to_string()));
            row["backlog_growth_bytes"] = json!(growth.map(|v| v.to_string()));
            queue_baseline.insert(key, (drops, backlog));
        }
        queues.push(row);
    }
    let mut sockets = BTreeMap::new();
    let mut rtts = Vec::new();
    let mut retransmissions = 0u64;
    let mut segments = 0u64;
    let mut reductions = 0u64;
    let mut compared = 0u64;
    let mut segments_complete = true;
    let mut peer_zero = 0u64;
    let mut peer_measured = 0usize;
    let mut max_rto = 0.0f64;
    let mut max_rtt_variation = 0.0f64;
    let mut max_unacked = 0u64;
    let mut max_lost = 0u64;
    let mut min_cwnd: Option<u32> = None;
    let mut max_cwnd: Option<u32> = None;
    let mut peer_window_min: Option<u64> = None;
    let mut max_send_queue: Option<u32> = None;
    for family in [libc::AF_INET, libc::AF_INET6] {
        let mut request = vec![0; 56];
        request[0] = family as u8;
        request[1] = libc::IPPROTO_TCP as u8;
        request[2] = 2; // INET_DIAG_INFO
        request[4..8].copy_from_slice(&2u32.to_ne_bytes()); // Established sockets only.
        for bytes in dump(libc::NETLINK_SOCK_DIAG, 20, &request, 20)? {
            ensure!(
                bytes.len() >= 72 && bytes[0] == family as u8,
                "invalid inet_diag response"
            );
            let cookie: [u8; 8] = bytes[44..52].try_into()?;
            ensure!(cookie != [255; 8], "kernel omitted socket identity");
            let attrs = crate::netlink_decode::attributes(&bytes[72..])?;
            let info = attrs
                .iter()
                .find(|(kind, _)| *kind & 0x3fff == 2)
                .context("kernel omitted TCP_INFO")?;
            let value = tcp_info(&info.1)?;
            let retrans = u64::from(u32_at(&info.1, 100)?);
            let cwnd = u32_at(&info.1, 80)?;
            min_cwnd = Some(min_cwnd.map_or(cwnd, |v| v.min(cwnd)));
            max_cwnd = Some(max_cwnd.map_or(cwnd, |v| v.max(cwnd)));
            let send_queue = u32_at(&bytes, 60)?;
            max_send_queue = Some(max_send_queue.map_or(send_queue, |v| v.max(send_queue)));
            if let Some(window) = value["peer_window_bytes"].as_u64() {
                peer_window_min = Some(peer_window_min.map_or(window, |v| v.min(window)));
            }
            let segs = if info.1.len() >= 144 {
                Some(u64::from(u32_at(&info.1, 136)?))
            } else {
                None
            };
            if let Some(old) = baseline.sockets.get(&cookie) {
                if let Some(change) = delta(Some(old.0), retrans) {
                    retransmissions += change;
                    compared += 1;
                    reductions += u64::from(cwnd < old.1);
                    if let Some(change) = segs.and_then(|segs| delta(old.2, segs)) {
                        segments += change;
                    } else {
                        segments_complete = false;
                    }
                } else {
                    segments_complete = false;
                }
            }
            peer_zero += u64::from(value["peer_window_bytes"] == 0);
            peer_measured += usize::from(!value["peer_window_bytes"].is_null());
            max_rto = max_rto.max(value["rto_ms"].as_f64().context("TCP RTO")?);
            max_rtt_variation = max_rtt_variation.max(
                value["rtt_variation_ms"]
                    .as_f64()
                    .context("TCP RTT variation")?,
            );
            max_unacked =
                max_unacked.max(value["unacked_segments"].as_u64().context("TCP unacked")?);
            max_lost = max_lost.max(value["lost_segments"].as_u64().context("TCP lost")?);
            let rtt = value["rtt_ms"].as_f64().context("TCP RTT")?;
            if rtt > 0.0 {
                rtts.push(rtt);
            }
            ensure!(sockets.len() < ROW_LIMIT, "TCP socket limit exceeded");
            sockets.insert(cookie, (retrans, cwnd, segs));
        }
    }
    rtts.sort_by(f64::total_cmp);
    let percentile = |percent: usize| {
        rtts.get((rtts.len() * percent).div_ceil(100).saturating_sub(1))
            .copied()
    };
    let p50 = percentile(50);
    if retransmissions > 0 {
        signals.insert("local_tcp_retransmissions");
    }
    if reductions > 0 {
        signals.insert("local_tcp_cwnd_reductions");
    }
    if rtt_rise(p50, baseline.rtt) {
        signals.insert("local_tcp_rtt_rise");
    }
    let mut statistics = [0u32; 3];
    let mut size = std::mem::size_of_val(&statistics) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                packet.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                statistics.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
            && size >= 8,
        "read capture drops: {}",
        io::Error::last_os_error()
    );
    capture.kernel_drops += u64::from(statistics[1]);
    capture.expire(Instant::now(), &names.keys().copied().collect());
    let mut headers = capture.snapshot();
    let zero = headers["interfaces"]
        .as_array()
        .context("header interfaces")?
        .iter()
        .try_fold(0u64, |sum, row| -> Result<u64> {
            Ok(sum
                + row["zero_window_observations"]
                    .as_str()
                    .context("zero windows")?
                    .parse::<u64>()?)
        })?;
    if delta(baseline.zero_observations, zero).is_some_and(|v| v > 0) || peer_zero > 0 {
        signals.insert("receiver_window_pressure");
    }
    for row in headers["interfaces"]
        .as_array_mut()
        .context("header interfaces")?
    {
        let index = row["index"].as_u64().context("header interface index")?;
        row["name"] = json!(names.get(&(index as u32)));
    }
    let now = Instant::now();
    let interval = baseline
        .time
        .map(|previous| now.duration_since(previous).as_secs_f64());
    totals.retransmissions += retransmissions;
    totals.cwnd_reductions += reductions;
    let value = json!({
        "schema":"netcontrol-link-diagnostics/v1","status":"available",
        "collected_at":time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
        "interval_seconds":interval,"error":null,"interfaces":interface_rows,"queues":queues,
        "local_tcp":{"established_sockets":sockets.len(),"compared_sockets":compared,
            "observed_retransmissions":totals.retransmissions.to_string(),
            "observed_cwnd_reductions":totals.cwnd_reductions.to_string(),
            "retransmissions_delta":if compared>0 {Some(retransmissions.to_string())} else {None},
            "retransmissions_per_second":interval.filter(|_|compared>0).map(|s|retransmissions as f64/s),
            "retransmissions_per_thousand_segments":if segments_complete && segments>0 {Some(retransmissions as f64*1000.0/segments as f64)} else {None},
            "cwnd_reductions":if compared>0 {Some(reductions)} else {None},
            "cwnd_min_segments":min_cwnd,"cwnd_max_segments":max_cwnd,
            "peer_window_min_bytes":peer_window_min,"send_queue_max_bytes":max_send_queue,
            "rtt_p50_ms":p50,"rtt_p95_ms":percentile(95),
            "rtt_variation_max_ms":if sockets.is_empty(){None}else{Some(max_rtt_variation)},
            "rto_max_ms":if sockets.is_empty(){None}else{Some(max_rto)},
            "unacked_segments_max":if sockets.is_empty(){None}else{Some(max_unacked)},
            "lost_segments_max":if sockets.is_empty(){None}else{Some(max_lost)},
            "peer_window_measured_sockets":peer_measured,
            "peer_zero_window_sockets":if peer_measured == sockets.len() {Some(peer_zero)} else {None}},
        "packet_headers":headers,"signals":signals,
        "coverage":{"local_tcp":"established sockets in this network namespace; one-second snapshots can miss short-lived events",
            "packet_headers":"plaintext ingress IPv4/IPv6 TCP ACK headers, including forwarded and local traffic; per-interface observations, not unique end-to-end flows",
            "windows":"raw 16-bit advertised-window changes per direction, not cwnd; no byte conversion without a complete scaling handshake",
            "queues":"qdisc queue snapshots, not packet sojourn time; parent/child qdiscs must not be summed",
            "limitations":"no encrypted inner TCP, fragment reassembly, active probes, exact loss localization, or cross-device correlation; NAT/tunnel observations may differ"}
    });
    *baseline = Baseline {
        time: Some(now),
        queues: queue_baseline,
        sockets,
        interfaces,
        rtt: p50,
        zero_observations: Some(zero),
    };
    Ok(value)
}
