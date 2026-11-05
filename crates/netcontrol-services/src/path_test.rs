//! Bounded, mutually authenticated endpoint measurements, not configuration advice.
use anyhow::Result;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"NCPATH01";
const HEADER: usize = 54;
const TAG: usize = 32;
const MIN_FRAME: usize = HEADER + TAG;
const MAX_FRAME: usize = 65_507;
const HELLO: u8 = 1;
const CHALLENGE: u8 = 2;
const CONSENT: u8 = 3;
const READY: u8 = 4;
const PROBE: u8 = 5;
const ACK: u8 = 6;
const REPORT: u8 = 7;
const TCP_HELLO: u8 = 8;
const TCP_CHALLENGE: u8 = 9;
const TCP_PROOF: u8 = 10;
const TCP_RECEIPT: u8 = 11;
const REPORT_ACK: u8 = 12;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts keys of every length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

struct Frame<'a> {
    kind: u8,
    role: u8,
    session: [u8; 32],
    sequence: u64,
    body: &'a [u8],
}

fn encode(
    key: &[u8],
    kind: u8,
    role: u8,
    session: &[u8; 32],
    sequence: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(MIN_FRAME + body.len());
    wire.extend_from_slice(MAGIC);
    wire.push(kind);
    wire.push(role);
    wire.extend_from_slice(session);
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(body);
    wire.extend_from_slice(&hmac(key, &wire));
    wire
}

fn decode<'a>(key: &[u8], wire: &'a [u8]) -> Option<Frame<'a>> {
    if !(MIN_FRAME..=MAX_FRAME).contains(&wire.len()) || &wire[..8] != MAGIC {
        return None;
    }
    let length = u32::from_be_bytes(wire[50..54].try_into().ok()?) as usize;
    if length != wire.len() - MIN_FRAME || wire[9] > 1 || !(HELLO..=REPORT_ACK).contains(&wire[8]) {
        return None;
    }
    let signed = wire.len() - TAG;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).ok()?;
    mac.update(&wire[..signed]);
    mac.verify_slice(&wire[signed..]).ok()?;
    Some(Frame {
        kind: wire[8],
        role: wire[9],
        session: wire[10..42].try_into().ok()?,
        sequence: u64::from_be_bytes(wire[42..50].try_into().ok()?),
        body: &wire[HEADER..signed],
    })
}

#[derive(Default)]
struct Replay {
    highest: u64,
    bits: u64,
}

impl Replay {
    fn accept(&mut self, sequence: u64) -> bool {
        if sequence == 0 {
            return false;
        }
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.highest = sequence;
            self.bits |= 1;
            true
        } else {
            let age = self.highest - sequence;
            if age >= 64 || self.bits & (1 << age) != 0 {
                return false;
            }
            self.bits |= 1 << age;
            true
        }
    }
}

/// Both endpoints must explicitly arm the same one-time secret in the intended namespace.
pub fn run(
    request: &netcontrol_core::PathTestRequest,
    cancel: &AtomicBool,
    progress: &dyn Fn(Value),
) -> Result<Value> {
    prepare(request)?.run(request, cancel, progress)
}

#[cfg(target_os = "linux")]
pub use native::Prepared;

#[cfg(not(target_os = "linux"))]
pub struct Prepared {
    _private: (),
}

/// Reserve both exclusive protocol sockets before installing any permit or changing MTUs.
/// Call inside the intended network namespace; no route lookup or peer traffic occurs here.
pub fn prepare(request: &netcontrol_core::PathTestRequest) -> Result<Prepared> {
    request.validate()?;
    #[cfg(target_os = "linux")]
    {
        native::prepare(request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("peer path MTU/MSS tests are supported only on Linux")
    }
}

#[cfg(not(target_os = "linux"))]
impl Prepared {
    pub fn run(
        &self,
        _request: &netcontrol_core::PathTestRequest,
        _cancel: &AtomicBool,
        _progress: &dyn Fn(Value),
    ) -> Result<Value> {
        anyhow::bail!("peer path MTU/MSS tests are supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use crate::linux;
    use anyhow::{Context, bail, ensure};
    use netcontrol_core::{
        PATH_TEST_ARM_SECONDS, PATH_TEST_LIFETIME_SECONDS, PATH_TEST_RUN_SECONDS, PathTestRequest,
    };
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::{self, Read, Write},
        mem,
        net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
        os::fd::{AsRawFd, OwnedFd},
        sync::{Mutex, atomic::Ordering},
        thread,
        time::{Duration, Instant},
    };

    const TICK: Duration = Duration::from_millis(5);
    const PROBES: usize = 3;
    // Even IPv4's 576-byte minimum carries a complete authenticated report fragment.
    const REPORT_CHUNK: usize = 384;
    const MAX_REPORT: usize = 16_384;
    const BULK_LIMIT: usize = 4 * 1024 * 1024;
    const BULK_BLOCK: usize = 16 * 1024;
    const MEASUREMENT_SECONDS: u64 = 27;

    fn check(cancel: &AtomicBool, deadline: Instant) -> Result<()> {
        ensure!(!cancel.load(Ordering::Relaxed), "path test cancelled");
        ensure!(Instant::now() < deadline, "path test deadline exceeded");
        Ok(())
    }

    fn transient(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
        )
    }

    fn bound(request: &PathTestRequest, kind: i32, port: u16) -> Result<OwnedFd> {
        let fd = linux::socket(
            if request.source_address.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            kind,
            0,
        )?;
        linux::bind_device(fd.as_raw_fd(), &request.interface)
            .context("binding path-test socket to selected interface")?;
        if request.source_address.is_ipv6() {
            linux::option(
                fd.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &1_i32,
            )?;
        }
        linux::bind(
            fd.as_raw_fd(),
            SocketAddr::new(request.source_address, port),
            0,
        )
        .context("binding path-test socket to selected source address")?;
        Ok(fd)
    }

    fn get_i32(fd: i32, level: i32, name: i32) -> Result<u32> {
        let mut value = 0_i32;
        let mut len = mem::size_of_val(&value) as libc::socklen_t;
        linux::check(unsafe {
            libc::getsockopt(fd, level, name, &mut value as *mut _ as *mut _, &mut len)
        })?;
        ensure!(value >= 0, "negative kernel socket limit");
        Ok(value as u32)
    }

    fn interface_mtu(fd: i32, name: &str) -> Result<u32> {
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        ensure!(name.len() < libc::IFNAMSIZ, "interface name too long");
        for (destination, source) in req.ifr_name.iter_mut().zip(name.bytes()) {
            *destination = source as libc::c_char;
        }
        linux::check(unsafe { libc::ioctl(fd, libc::SIOCGIFMTU as _, &mut req) })?;
        let mtu = unsafe { req.ifr_ifru.ifru_mtu };
        ensure!(mtu > 0, "selected interface has invalid MTU");
        Ok(mtu as u32)
    }

    pub struct Prepared {
        socket: UdpSocket,
        listener: TcpListener,
        interface: String,
        source: IpAddr,
        peer: IpAddr,
        port: u16,
        started: AtomicBool,
    }

    impl Prepared {
        /// Run once, retaining exclusive reservations until the orchestrator removes its permits.
        pub fn run(
            &self,
            request: &PathTestRequest,
            cancel: &AtomicBool,
            progress: &dyn Fn(Value),
        ) -> Result<Value> {
            request.validate()?;
            ensure!(
                self.interface == request.interface
                    && self.source == request.source_address
                    && self.peer == request.peer_address
                    && self.port == request.port,
                "path-test request does not match reserved interface/source/peer/port"
            );
            ensure!(
                !self.started.swap(true, Ordering::AcqRel),
                "prepared path test already started"
            );
            run(self, request, cancel, progress)
        }
    }

    pub(super) fn prepare(request: &PathTestRequest) -> Result<Prepared> {
        let udp_fd = bound(request, libc::SOCK_DGRAM, request.port)?;
        let v4 = request.source_address.is_ipv4();
        linux::option(
            udp_fd.as_raw_fd(),
            if v4 {
                libc::IPPROTO_IP
            } else {
                libc::IPPROTO_IPV6
            },
            if v4 {
                libc::IP_MTU_DISCOVER
            } else {
                libc::IPV6_MTU_DISCOVER
            },
            &if v4 {
                libc::IP_PMTUDISC_DO
            } else {
                libc::IPV6_PMTUDISC_DO
            },
        )?;
        let socket = UdpSocket::from(udp_fd);
        let listener_fd = bound(request, libc::SOCK_STREAM, request.port)?;
        linux::check(unsafe { libc::listen(listener_fd.as_raw_fd(), 8) })?;
        let listener = TcpListener::from(listener_fd);
        Ok(Prepared {
            socket,
            listener,
            interface: request.interface.clone(),
            source: request.source_address,
            peer: request.peer_address,
            port: request.port,
            started: AtomicBool::new(false),
        })
    }

    fn udp_limits(request: &PathTestRequest, socket: &UdpSocket) -> Result<(u32, u32, u32)> {
        let v4 = request.source_address.is_ipv4();
        socket.connect(SocketAddr::new(request.peer_address, request.port))?;
        let interface = interface_mtu(socket.as_raw_fd(), &request.interface)?;
        let route = get_i32(
            socket.as_raw_fd(),
            if v4 {
                libc::IPPROTO_IP
            } else {
                libc::IPPROTO_IPV6
            },
            if v4 { libc::IP_MTU } else { libc::IPV6_MTU },
        )?;
        let cap = request.maximum_mtu.min(interface).min(route).min(65_535);
        ensure!(
            cap >= if v4 { 576 } else { 1280 },
            "selected interface/route MTU below address-family minimum"
        );
        Ok((interface, route, cap))
    }

    fn base_key(request: &PathTestRequest) -> Zeroizing<[u8; 32]> {
        let (low, high) = if request.source_address < request.peer_address {
            (request.source_address, request.peer_address)
        } else {
            (request.peer_address, request.source_address)
        };
        let binding = format!("netcontrol-path-v1|{low}|{high}|{}", request.port);
        Zeroizing::new(hmac(request.pairing_secret.as_bytes(), binding.as_bytes()))
    }

    struct Session {
        id: [u8; 32],
        key: Zeroizing<[u8; 32]>,
        base: Zeroizing<[u8; 32]>,
        role: u8,
        local_caps: Caps,
        peer_caps: Caps,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Caps {
        receive: u32,
        send: u32,
    }

    impl Caps {
        fn wire(self) -> [u8; 8] {
            let mut wire = [0; 8];
            wire[..4].copy_from_slice(&self.receive.to_be_bytes());
            wire[4..].copy_from_slice(&self.send.to_be_bytes());
            wire
        }

        fn parse(wire: &[u8]) -> Option<Self> {
            if wire.len() != 8 {
                return None;
            }
            let receive = u32::from_be_bytes(wire[..4].try_into().ok()?);
            let send = u32::from_be_bytes(wire[4..].try_into().ok()?);
            ((576..=65_535).contains(&receive) && (576..=receive).contains(&send))
                .then_some(Self { receive, send })
        }
    }

    fn session_id(key: &[u8], first: &[u8; 32], second: &[u8; 32]) -> [u8; 32] {
        let mut material = Vec::from(b"netcontrol-path-session-v1".as_slice());
        material.extend_from_slice(first);
        material.extend_from_slice(second);
        hmac(key, &material)
    }

    enum Datagram {
        Packet(usize),
        Idle,
        PathError(&'static str),
    }

    fn receive(socket: &UdpSocket, buffer: &mut [u8]) -> Result<Datagram> {
        match socket.recv(buffer) {
            Ok(length) => Ok(Datagram::Packet(length)),
            Err(error) if transient(&error) => Ok(Datagram::Idle),
            Err(error) => match error.raw_os_error() {
                Some(libc::EMSGSIZE) => Ok(Datagram::PathError("emsgsize")),
                Some(libc::ECONNREFUSED) => Ok(Datagram::PathError("connection_refused")),
                Some(libc::ECONNRESET) => Ok(Datagram::PathError("connection_reset")),
                Some(libc::EHOSTUNREACH) => Ok(Datagram::PathError("host_unreachable")),
                Some(libc::ENETUNREACH) => Ok(Datagram::PathError("network_unreachable")),
                Some(libc::EACCES) | Some(libc::EPERM) => {
                    Ok(Datagram::PathError("administratively_prohibited"))
                }
                _ => Err(error.into()),
            },
        }
    }

    fn send_control(socket: &UdpSocket, wire: &[u8]) -> bool {
        socket.send(wire).is_ok_and(|length| length == wire.len())
    }

    fn handshake(
        request: &PathTestRequest,
        socket: &UdpSocket,
        caps: Caps,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Session> {
        let base = base_key(request);
        let role = u8::from(request.source_address > request.peer_address);
        let mine = rand::random::<[u8; 32]>();
        let mut first = None;
        let mut id = None;
        let mut peer_caps = None;
        let mut ready = false;
        let mut last_send = Instant::now() - Duration::from_secs(1);
        let mut buffer = [0_u8; 256];
        loop {
            check(cancel, deadline)?;
            if role == 0 && last_send.elapsed() >= Duration::from_millis(200) {
                let wire = match id {
                    Some(session) => encode(&*base, CONSENT, role, &session, 0, &caps.wire()),
                    None => encode(&*base, HELLO, role, &mine, 0, &[]),
                };
                send_control(socket, &wire);
                last_send = Instant::now();
            }
            // A fixed receive budget prevents spoofed traffic starving cancellation/deadlines.
            for _ in 0..16 {
                check(cancel, deadline)?;
                let length = match receive(socket, &mut buffer)? {
                    Datagram::Packet(length) => length,
                    Datagram::Idle => break,
                    Datagram::PathError(_) => continue,
                };
                let Some(frame) = decode(&*base, &buffer[..length]) else {
                    continue;
                };
                if frame.role == role || frame.sequence != 0 {
                    continue;
                }
                if role == 1 && frame.kind == HELLO && frame.body.is_empty() {
                    if first.is_some_and(|nonce| nonce != frame.session) {
                        continue;
                    }
                    first = Some(frame.session);
                    id = Some(session_id(&*base, &frame.session, &mine));
                    if last_send.elapsed() >= Duration::from_millis(100) {
                        let mut body = Vec::from(mine);
                        body.extend_from_slice(&caps.wire());
                        send_control(
                            socket,
                            &encode(&*base, CHALLENGE, role, &frame.session, 0, &body),
                        );
                        last_send = Instant::now();
                    }
                } else if role == 0
                    && frame.kind == CHALLENGE
                    && frame.session == mine
                    && frame.body.len() == 40
                {
                    let nonce: [u8; 32] = frame.body[..32].try_into().expect("checked nonce");
                    let candidate = session_id(&*base, &mine, &nonce);
                    if id.is_some_and(|current| current != candidate) {
                        continue;
                    }
                    id = Some(candidate);
                    peer_caps = Some(
                        Caps::parse(&frame.body[32..])
                            .context("invalid authenticated peer caps")?,
                    );
                } else if role == 1
                    && frame.kind == CONSENT
                    && Some(frame.session) == id
                    && frame.body.len() == 8
                {
                    peer_caps =
                        Some(Caps::parse(frame.body).context("invalid authenticated peer caps")?);
                    send_control(
                        socket,
                        &encode(&*base, READY, role, &frame.session, 0, &caps.wire()),
                    );
                    break;
                } else if role == 0
                    && frame.kind == READY
                    && Some(frame.session) == id
                    && frame.body.len() == 8
                {
                    ensure!(
                        peer_caps == Caps::parse(frame.body),
                        "peer caps changed during consent"
                    );
                    ready = true;
                    break;
                }
            }
            let consented = if role == 1 {
                peer_caps.is_some()
            } else {
                ready
            };
            if consented {
                check(cancel, deadline)?;
                let id = id.context("missing session")?;
                let peer_caps = peer_caps.context("missing peer caps")?;
                return Ok(Session {
                    id,
                    key: Zeroizing::new(hmac(&*base, &id)),
                    base,
                    role,
                    local_caps: caps,
                    peer_caps,
                });
            }
            thread::sleep(TICK);
        }
    }

    fn candidates(cap: u32, v6: bool) -> Vec<u32> {
        let minimum = if v6 { 1280 } else { 576 };
        let mut values: BTreeSet<u32> = [
            576, 1200, 1280, 1400, 1500, 2000, 3000, 4000, 6000, 8000, 9000,
        ]
        .into_iter()
        .filter(|value| *value >= minimum && *value <= cap)
        .collect();
        values.insert(cap);
        values.into_iter().collect()
    }

    #[derive(Default)]
    struct SizeStats {
        attempted: u32,
        sent: u32,
        delivered: u32,
        emsgsize: u32,
        send_errors: u32,
        rtts: Vec<f64>,
    }

    fn size_json(size: u32, stats: &SizeStats, inbound: bool) -> Value {
        let timed_out = stats.sent.saturating_sub(stats.delivered);
        let mean = (!stats.rtts.is_empty())
            .then(|| stats.rtts.iter().sum::<f64>() / stats.rtts.len() as f64);
        json!({
            "ip_size_bytes":size, "attempted":if inbound { Value::Null } else { json!(stats.attempted) },
            "sent":if inbound { Value::Null } else { json!(stats.sent) },
            "delivered":stats.delivered, "ack_timeouts":if inbound { Value::Null } else { json!(timed_out) },
            "loss_fraction":if inbound || stats.sent == 0 { Value::Null } else { json!(timed_out as f64 / stats.sent as f64) },
            "emsgsize":if inbound { Value::Null } else { json!(stats.emsgsize) },
            "send_errors":if inbound { Value::Null } else { json!(stats.send_errors) },
            "mean_rtt_ms":mean,
            "status":if stats.delivered > 0 { "verified" } else if stats.emsgsize > 0 { "local_or_route_limit" } else { "unknown" }
        })
    }

    fn udp_json(stats: &BTreeMap<u32, SizeStats>, inbound: bool) -> Value {
        json!({
            "largest_verified_ip_size_bytes":stats.iter().filter(|(_, s)| s.delivered > 0).map(|(size, _)| *size).max(),
            "delivery_evidence":if inbound { "authenticated_receive" } else { "authenticated_small_ack_for_received_probe" },
            "rtt_origin":if inbound { "peer" } else { "local" },
            "sizes":stats.iter().map(|(size, stats)| size_json(*size, stats, inbound)).collect::<Vec<_>>()
        })
    }

    fn limits() -> Value {
        json!([
            "Endpoint IP sizes only; no proof that an outer tunnel avoided fragmentation.",
            "Timeout/ACK loss is inconclusive, not proof of a path MTU. EMSGSIZE is a local or cached-route limit.",
            "Finite candidate sampling and short rate-limited TCP trials are not an ideal MTU or unrestricted benchmark.",
            "Goodput is capped at approximately 8 MiB/s and 4 MiB per trial; observed MSS includes peer/kernel constraints.",
            "TCP_INFO send/receive MSS is a kernel observation, not an on-wire segmentation or offload guarantee.",
            "TCP trials terminate on the two test endpoints, not forwarded LAN clients; TCP_MAXSEG is connection-local, not a persistent TCP clamp.",
            "Directional UDP proof uses a small authenticated received-size ACK, not an equal-size echo; missing ACKs remain inconclusive.",
            "RTT is round-trip latency, not one-way delay. TCP_INFO counters describe only each fresh test connection.",
            "No configuration is selected or changed by this protocol.",
            "Permit expiry alone does not revoke established conntrack state; teardown and any exact-tuple cleanup are orchestrator responsibilities.",
            "An operational selected-interface route/tunnel is required; this protocol does not traverse NAT or repair VPN policies."
        ])
    }

    fn tcp_info(stream: &TcpStream) -> Result<Value> {
        let mut info: libc::tcp_info = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&info) as libc::socklen_t;
        linux::check(unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                &mut info as *mut _ as *mut _,
                &mut len,
            )
        })?;
        // These fields are in the original stable Linux TCP_INFO prefix.
        ensure!(
            len as usize
                >= mem::offset_of!(libc::tcp_info, tcpi_total_retrans) + mem::size_of::<u32>(),
            "incomplete TCP_INFO"
        );
        Ok(json!({
            "effective_mss_bytes":info.tcpi_snd_mss,
            "observed_receive_mss_bytes":info.tcpi_rcv_mss,
            "retransmits":info.tcpi_total_retrans,
            "kernel_rtt_ms":info.tcpi_rtt as f64 / 1000.0
        }))
    }

    fn prepare_stream(stream: &TcpStream, request: &PathTestRequest) -> Result<()> {
        linux::bind_device(stream.as_raw_fd(), &request.interface)?;
        ensure!(
            stream.local_addr()?.ip() == request.source_address,
            "TCP selected source mismatch"
        );
        ensure!(
            stream.peer_addr()?.ip() == request.peer_address,
            "TCP peer mismatch"
        );
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_millis(50)))?;
        stream.set_write_timeout(Some(Duration::from_millis(50)))?;
        Ok(())
    }

    fn connect(
        request: &PathTestRequest,
        mss: u32,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<TcpStream> {
        let fd = bound(request, libc::SOCK_STREAM, 0)?;
        linux::option(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &(mss as i32),
        )?;
        let (address, len) =
            linux::sockaddr(SocketAddr::new(request.peer_address, request.port), 0);
        let result =
            unsafe { libc::connect(fd.as_raw_fd(), &address as *const _ as *const _, len) };
        if result != 0 {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(libc::EINPROGRESS),
                "TCP connect: {error}"
            );
            loop {
                check(cancel, deadline)?;
                let mut poll = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let status = unsafe { libc::poll(&mut poll, 1, 25) };
                if status < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                linux::check(status)?;
                if status > 0 {
                    let error = get_i32(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR)?;
                    ensure!(error == 0, "TCP connection failed (OS error {error})");
                    break;
                }
            }
        }
        let stream = TcpStream::from(fd);
        prepare_stream(&stream, request)?;
        Ok(stream)
    }

    fn write_bounded(
        stream: &mut TcpStream,
        mut data: &[u8],
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<()> {
        while !data.is_empty() {
            check(cancel, deadline)?;
            match stream.write(data) {
                Ok(0) => bail!("TCP closed during authenticated exchange"),
                Ok(length) => data = &data[length..],
                Err(error) if transient(&error) => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn read_bounded(
        stream: &mut TcpStream,
        mut data: &mut [u8],
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<()> {
        while !data.is_empty() {
            check(cancel, deadline)?;
            match stream.read(data) {
                Ok(0) => bail!("TCP closed during authenticated exchange"),
                Ok(length) => data = &mut data[length..],
                Err(error) if transient(&error) => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn tcp_write(
        stream: &mut TcpStream,
        wire: &[u8],
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<()> {
        ensure!(wire.len() <= 1024, "TCP control frame exceeds bound");
        write_bounded(stream, &(wire.len() as u32).to_be_bytes(), cancel, deadline)?;
        write_bounded(stream, wire, cancel, deadline)
    }

    fn tcp_read(stream: &mut TcpStream, cancel: &AtomicBool, deadline: Instant) -> Result<Vec<u8>> {
        let mut length = [0; 4];
        read_bounded(stream, &mut length, cancel, deadline)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            (MIN_FRAME..=1024).contains(&length),
            "TCP control frame outside bounds"
        );
        let mut wire = vec![0; length];
        read_bounded(stream, &mut wire, cancel, deadline)?;
        Ok(wire)
    }

    fn authenticated<'a>(
        session: &Session,
        wire: &'a [u8],
        kind: u8,
        trial: u64,
    ) -> Result<Frame<'a>> {
        let frame = decode(&*session.key, wire).context("unauthenticated TCP frame")?;
        ensure!(
            frame.role != session.role
                && frame.session == session.id
                && frame.kind == kind
                && frame.sequence == trial,
            "unexpected TCP session frame"
        );
        Ok(frame)
    }

    fn tcp_trial(
        request: &PathTestRequest,
        session: &Session,
        trial: u64,
        mss: u32,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Value> {
        let connect_at = Instant::now();
        let mut stream = connect(
            request,
            mss,
            cancel,
            deadline.min(Instant::now() + Duration::from_millis(700)),
        )?;
        let connect_ms = connect_at.elapsed().as_secs_f64() * 1000.0;
        let hello_nonce = rand::random::<[u8; 32]>();
        let mut body = Vec::from(hello_nonce);
        body.extend_from_slice(&mss.to_be_bytes());
        let authentication_deadline = deadline.min(Instant::now() + Duration::from_millis(700));
        let auth_at = Instant::now();
        tcp_write(
            &mut stream,
            &encode(
                &*session.key,
                TCP_HELLO,
                session.role,
                &session.id,
                trial,
                &body,
            ),
            cancel,
            authentication_deadline,
        )?;
        let wire = tcp_read(&mut stream, cancel, authentication_deadline)?;
        let challenge = authenticated(session, &wire, TCP_CHALLENGE, trial)?;
        ensure!(
            challenge.body.len() == 64 && constant_eq(&challenge.body[..32], &hello_nonce),
            "TCP challenge mismatch"
        );
        tcp_write(
            &mut stream,
            &encode(
                &*session.key,
                TCP_PROOF,
                session.role,
                &session.id,
                trial,
                challenge.body,
            ),
            cancel,
            authentication_deadline,
        )?;
        let authentication_rtt_ms = auth_at.elapsed().as_secs_f64() * 1000.0;
        let mut block = [0_u8; BULK_BLOCK];
        // The signed receipt authenticates the exact bytes observed, not just a byte count.
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let mut digest = Sha256::new();
        let mut sent = 0;
        let data_start = Instant::now();
        let data_end = deadline.min(data_start + Duration::from_millis(500));
        while sent < BULK_LIMIT && Instant::now() < data_end {
            check(cancel, deadline)?;
            let target = (sent + BULK_BLOCK).min(BULK_LIMIT);
            while sent < target && Instant::now() < data_end {
                check(cancel, deadline)?;
                match stream.write(&block[..(target - sent).min(block.len())]) {
                    Ok(0) => bail!("TCP bulk stream closed"),
                    Ok(length) => {
                        digest.update(&block[..length]);
                        sent += length;
                    }
                    Err(error) if transient(&error) => (),
                    Err(error) => return Err(error.into()),
                }
            }
            let paced = data_start + Duration::from_secs_f64(sent as f64 / (8.0 * 1024.0 * 1024.0));
            while Instant::now() < paced.min(data_end) {
                check(cancel, deadline)?;
                thread::sleep(TICK);
            }
        }
        stream.shutdown(Shutdown::Write)?;
        let wire = tcp_read(
            &mut stream,
            cancel,
            deadline.min(Instant::now() + Duration::from_millis(900)),
        )?;
        let receipt = authenticated(session, &wire, TCP_RECEIPT, trial)?;
        ensure!(receipt.body.len() <= 768, "TCP receipt outside bound");
        let receipt: Value = serde_json::from_slice(receipt.body)?;
        let digest: [u8; 32] = digest.finalize().into();
        let expected_digest = hex_bytes(&digest);
        ensure!(
            receipt["bytes"].as_u64() == Some(sent as u64)
                && receipt["sha256"].as_str() == Some(expected_digest.as_str()),
            "TCP receipt byte/digest mismatch"
        );
        let info = tcp_info(&stream)?;
        let elapsed_ms = receipt["elapsed_ms"]
            .as_f64()
            .context("missing receipt elapsed time")?;
        ensure!(
            elapsed_ms.is_finite() && elapsed_ms > 0.0 && elapsed_ms <= 2000.0,
            "invalid receipt timing"
        );
        Ok(json!({
            "trial":trial, "requested_mss_bytes":mss, "status":"measured",
            "effective_mss_bytes":info["effective_mss_bytes"],
            "peer_effective_mss_bytes":receipt["effective_mss_bytes"],
            "delivered_bytes":sent, "elapsed_ms":elapsed_ms,
            "goodput_bits_per_second":sent as f64 * 8.0 * 1000.0 / elapsed_ms,
            "retransmits":info["retransmits"], "kernel_rtt_ms":info["kernel_rtt_ms"],
            "connect_ms":connect_ms, "authentication_rtt_ms":authentication_rtt_ms,
            "error":Value::Null,
            "delivery_evidence":"authenticated_receiver_byte_count_and_sha256"
        }))
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        bytes
            .iter()
            .flat_map(|byte| {
                [
                    HEX[(byte >> 4) as usize] as char,
                    HEX[(byte & 15) as usize] as char,
                ]
            })
            .collect()
    }

    fn receive_trial(
        request: &PathTestRequest,
        session: &Session,
        stream: &mut TcpStream,
        seen: &mut BTreeSet<u64>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Value> {
        prepare_stream(stream, request)?;
        let authentication_deadline = deadline.min(Instant::now() + Duration::from_millis(700));
        let wire = tcp_read(
            stream,
            cancel,
            authentication_deadline.min(Instant::now() + Duration::from_millis(200)),
        )?;
        let frame = decode(&*session.key, &wire).context("unauthenticated TCP hello")?;
        ensure!(
            frame.role != session.role
                && frame.session == session.id
                && frame.kind == TCP_HELLO
                && (1..=3).contains(&frame.sequence)
                && frame.body.len() == 36,
            "unexpected TCP hello"
        );
        let trial = frame.sequence;
        ensure!(seen.insert(trial), "replayed TCP trial");
        let requested_mss = u32::from_be_bytes(frame.body[32..].try_into()?);
        ensure!(
            (48..=65_495).contains(&requested_mss),
            "invalid requested TCP MSS"
        );
        let mut challenge = Vec::from(&frame.body[..32]);
        challenge.extend_from_slice(&rand::random::<[u8; 32]>());
        tcp_write(
            stream,
            &encode(
                &*session.key,
                TCP_CHALLENGE,
                session.role,
                &session.id,
                trial,
                &challenge,
            ),
            cancel,
            authentication_deadline,
        )?;
        let proof = tcp_read(stream, cancel, authentication_deadline)?;
        let proof = authenticated(session, &proof, TCP_PROOF, trial)?;
        ensure!(constant_eq(proof.body, &challenge), "TCP proof mismatch");
        let started = Instant::now();
        let transfer_deadline = deadline.min(started + Duration::from_millis(1500));
        let mut bytes = 0;
        let mut buffer = [0; BULK_BLOCK];
        let mut digest = Sha256::new();
        loop {
            check(cancel, transfer_deadline)?;
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    bytes += length;
                    ensure!(bytes <= BULK_LIMIT, "TCP transfer exceeds bound");
                    digest.update(&buffer[..length]);
                }
                Err(error) if transient(&error) => (),
                Err(error) => return Err(error.into()),
            }
        }
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let info = tcp_info(stream)?;
        let receipt = json!({
            "bytes":bytes, "elapsed_ms":elapsed_ms.max(0.001),
            "sha256":hex_bytes(&digest.finalize()),
            "effective_mss_bytes":info["observed_receive_mss_bytes"],
        });
        tcp_write(
            stream,
            &encode(
                &*session.key,
                TCP_RECEIPT,
                session.role,
                &session.id,
                trial,
                &serde_json::to_vec(&receipt)?,
            ),
            cancel,
            deadline.min(Instant::now() + Duration::from_millis(300)),
        )?;
        Ok(json!({
            "trial":trial, "requested_mss_bytes":requested_mss, "status":"received",
            "effective_mss_bytes":info["observed_receive_mss_bytes"],
            "delivered_bytes":bytes, "elapsed_ms":elapsed_ms,
            "goodput_bits_per_second":bytes as f64 * 8.0 * 1000.0 / elapsed_ms.max(0.001),
            "retransmits":Value::Null, "kernel_rtt_ms":info["kernel_rtt_ms"],
            "sender_retransmits":Value::Null,"sender_effective_mss_bytes":Value::Null,
            "delivery_evidence":"authenticated_connection_receive_only"
        }))
    }

    fn mss_candidates(cap: u32, v6: bool) -> Vec<u32> {
        let overhead = if v6 { 60 } else { 40 };
        [
            if v6 { 1220 } else { 536 },
            1280 - overhead,
            (cap - overhead).min(32_767),
        ]
        .into_iter()
        .map(|value| value.min(cap - overhead))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
    }

    #[derive(Clone, Copy)]
    struct Measurements<'a> {
        request: &'a PathTestRequest,
        session: &'a Session,
        cap: u32,
        start: Instant,
        deadline: Instant,
        tcp_out: &'a Mutex<Vec<Value>>,
        tcp_in: &'a Mutex<Vec<Value>>,
    }

    fn tcp_send(measurements: &Measurements<'_>, cancel: &AtomicBool, deadline: Instant) {
        let Measurements {
            request,
            session,
            cap,
            start,
            tcp_out: output,
            ..
        } = *measurements;
        let phase = start + Duration::from_secs(if session.role == 0 { 7 } else { 15 });
        while Instant::now() < phase {
            if check(cancel, deadline).is_err() {
                return;
            }
            thread::sleep(TICK);
        }
        for (index, mss) in mss_candidates(cap, request.source_address.is_ipv6())
            .into_iter()
            .enumerate()
        {
            if check(cancel, deadline).is_err() {
                return;
            }
            let trial = index as u64 + 1;
            let result = tcp_trial(
                request,
                session,
                trial,
                mss,
                cancel,
                deadline.min(Instant::now() + Duration::from_millis(2400)),
            );
            let value = match result {
                Ok(value) => value,
                Err(error) => {
                    json!({"trial":trial,"requested_mss_bytes":mss,"status":"inconclusive",
                    "effective_mss_bytes":null,"peer_effective_mss_bytes":null,
                    "delivered_bytes":null,"elapsed_ms":null,"goodput_bits_per_second":null,
                    "retransmits":null,"kernel_rtt_ms":null,"connect_ms":null,
                    "authentication_rtt_ms":null,"delivery_evidence":null,
                    "error":format!("{error:#}")})
                }
            };
            output
                .lock()
                .expect("path-test TCP output poisoned")
                .push(value);
        }
    }

    fn tcp_receive(
        request: &PathTestRequest,
        session: &Session,
        listener: TcpListener,
        cancel: &AtomicBool,
        deadline: Instant,
        output: &Mutex<Vec<Value>>,
    ) {
        let mut seen = BTreeSet::new();
        let mut accepted = 0;
        while check(cancel, deadline).is_ok() && accepted < 32 && seen.len() < 3 {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    accepted += 1;
                    if peer.ip() != request.peer_address {
                        continue;
                    }
                    if let Ok(value) =
                        receive_trial(request, session, &mut stream, &mut seen, cancel, deadline)
                    {
                        output
                            .lock()
                            .expect("path-test TCP output poisoned")
                            .push(value);
                    }
                }
                Err(error) if transient(&error) => thread::sleep(TICK),
                Err(_) => return,
            }
        }
    }

    #[derive(Default)]
    struct ReportParts {
        digest: Option<[u8; 32]>,
        parts: Vec<Option<Vec<u8>>>,
    }

    impl ReportParts {
        fn insert(&mut self, body: &[u8]) -> Option<Vec<u8>> {
            if !(37..=36 + REPORT_CHUNK).contains(&body.len()) {
                return None;
            }
            let count = u16::from_be_bytes(body[..2].try_into().ok()?) as usize;
            let index = u16::from_be_bytes(body[2..4].try_into().ok()?) as usize;
            let digest: [u8; 32] = body[4..36].try_into().ok()?;
            if count == 0 || count > MAX_REPORT.div_ceil(REPORT_CHUNK) || index >= count {
                return None;
            }
            if self.digest.is_some_and(|value| value != digest) {
                return None;
            }
            if self.parts.is_empty() {
                self.digest = Some(digest);
                self.parts.resize(count, None);
            }
            if self.parts.len() != count {
                return None;
            }
            if index + 1 < count && body.len() != 36 + REPORT_CHUNK {
                return None;
            }
            if let Some(previous) = &self.parts[index] {
                if previous != &body[36..] {
                    return None;
                }
            } else {
                self.parts[index] = Some(body[36..].to_vec());
            }
            if self.parts.iter().any(Option::is_none) {
                return None;
            }
            let bytes: Vec<u8> = self
                .parts
                .iter()
                .flat_map(|part| part.as_ref().expect("checked parts").iter().copied())
                .collect();
            if bytes.len() > MAX_REPORT || !constant_eq(&Sha256::digest(&bytes), &digest) {
                return None;
            }
            Some(bytes)
        }
    }

    fn report_frames(report: &Value) -> Result<(Vec<Vec<u8>>, [u8; 32])> {
        let report = serde_json::to_vec(report)?;
        ensure!(
            report.len() <= MAX_REPORT,
            "internal path report exceeds bound"
        );
        let digest: [u8; 32] = Sha256::digest(&report).into();
        let count = report.len().div_ceil(REPORT_CHUNK);
        let bodies = report
            .chunks(REPORT_CHUNK)
            .enumerate()
            .map(|(index, chunk)| {
                let mut body = Vec::from((count as u16).to_be_bytes());
                body.extend_from_slice(&(index as u16).to_be_bytes());
                body.extend_from_slice(&digest);
                body.extend_from_slice(chunk);
                body
            })
            .collect();
        Ok((bodies, digest))
    }

    fn remote_report(bytes: &[u8], sizes: &[u32]) -> Option<Value> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let udp = &value["udp_outbound"];
        let rows = udp["sizes"].as_array()?;
        if rows.len() != sizes.len() {
            return None;
        }
        let mut clean_rows = Vec::new();
        for (row, size) in rows.iter().zip(sizes) {
            if row["ip_size_bytes"].as_u64()? != *size as u64 {
                return None;
            }
            for name in [
                "attempted",
                "sent",
                "delivered",
                "emsgsize",
                "send_errors",
                "ack_timeouts",
            ] {
                if row[name].as_u64()? > PROBES as u64 {
                    return None;
                }
            }
            if row["delivered"].as_u64()? > row["sent"].as_u64()?
                || row["sent"].as_u64()? > row["attempted"].as_u64()?
            {
                return None;
            }
            let status = row["status"].as_str()?;
            if !["verified", "local_or_route_limit", "unknown"].contains(&status) {
                return None;
            }
            for name in ["loss_fraction", "mean_rtt_ms"] {
                if !row[name].is_null()
                    && row[name]
                        .as_f64()
                        .is_none_or(|number| !number.is_finite() || number < 0.0)
                {
                    return None;
                }
            }
            let mut clean = serde_json::Map::new();
            for name in [
                "ip_size_bytes",
                "attempted",
                "sent",
                "delivered",
                "ack_timeouts",
                "loss_fraction",
                "emsgsize",
                "send_errors",
                "mean_rtt_ms",
                "status",
            ] {
                clean.insert(name.into(), row[name].clone());
            }
            clean_rows.push(Value::Object(clean));
        }
        let trials = value["tcp_outbound"].as_array()?;
        if trials.len() > 3 {
            return None;
        }
        let mut clean_trials = Vec::new();
        let mut seen = BTreeSet::new();
        for trial in trials {
            let index = trial["trial"].as_u64()?;
            if !(1..=3).contains(&index)
                || !seen.insert(index)
                || !matches!(trial["status"].as_str()?, "measured" | "inconclusive")
            {
                return None;
            }
            let mut clean = serde_json::Map::new();
            for name in [
                "trial",
                "requested_mss_bytes",
                "effective_mss_bytes",
                "peer_effective_mss_bytes",
                "delivered_bytes",
                "elapsed_ms",
                "goodput_bits_per_second",
                "retransmits",
                "kernel_rtt_ms",
                "connect_ms",
                "authentication_rtt_ms",
            ] {
                if !trial[name].is_null()
                    && trial[name]
                        .as_f64()
                        .is_none_or(|number| !number.is_finite() || number < 0.0)
                {
                    return None;
                }
                clean.insert(name.into(), trial[name].clone());
            }
            clean.insert("status".into(), trial["status"].clone());
            clean.insert(
                "delivery_evidence".into(),
                if trial["status"] == "measured" {
                    json!("authenticated_receiver_byte_count_and_sha256")
                } else {
                    Value::Null
                },
            );
            clean_trials.push(Value::Object(clean));
        }
        let largest = clean_rows
            .iter()
            .filter(|row| row["delivered"].as_u64().unwrap_or(0) > 0)
            .filter_map(|row| row["ip_size_bytes"].as_u64())
            .max();
        Some(json!({
            "udp_outbound":{"largest_verified_ip_size_bytes":largest,
                "delivery_evidence":"authenticated_small_ack_for_received_probe","rtt_origin":"local","sizes":clean_rows},
            "tcp_outbound":clean_trials
        }))
    }

    fn measure(
        measurements: &Measurements<'_>,
        socket: &UdpSocket,
        cancel: &AtomicBool,
        progress: &dyn Fn(Value),
    ) -> Result<Value> {
        let Measurements {
            request,
            session,
            cap,
            start,
            deadline,
            tcp_out,
            tcp_in,
        } = *measurements;
        let sizes = candidates(cap, request.source_address.is_ipv6());
        let inbound_sizes = candidates(
            session.peer_caps.send.min(session.local_caps.receive),
            request.source_address.is_ipv6(),
        );
        let overhead = if request.source_address.is_ipv4() {
            28
        } else {
            48
        };
        let mut outbound: BTreeMap<u32, SizeStats> = sizes
            .iter()
            .map(|size| (*size, SizeStats::default()))
            .collect();
        let mut inbound: BTreeMap<u32, SizeStats> = inbound_sizes
            .iter()
            .map(|size| (*size, SizeStats::default()))
            .collect();
        let mut pending = BTreeMap::<u64, (u32, Instant)>::new();
        let mut replay = Replay::default();
        let mut sequence = 0_u64;
        let mut sent_probes = 0;
        let mut last_probe = start - Duration::from_secs(1);
        let mut last_ready = start - Duration::from_secs(1);
        let mut last_report = start - Duration::from_secs(1);
        let mut last_report_ack = start - Duration::from_secs(1);
        let mut published_udp = false;
        let mut buffer = vec![0_u8; 65_536];
        let mut parts = ReportParts::default();
        let mut report: Option<(Vec<Vec<u8>>, [u8; 32])> = None;
        let mut report_index = 0;
        let mut report_acked = false;
        let mut remote = None;
        let mut path_errors = BTreeMap::<&'static str, u32>::new();
        loop {
            check(cancel, deadline + Duration::from_millis(100))?;
            if Instant::now() >= deadline {
                break;
            }
            let elapsed = start.elapsed();
            if sent_probes < sizes.len() * PROBES
                && last_probe.elapsed() >= Duration::from_millis(100)
            {
                let size = sizes[sent_probes / PROBES];
                let body = vec![0_u8; size as usize - overhead - MIN_FRAME];
                sequence += 1;
                let wire = encode(
                    &*session.key,
                    PROBE,
                    session.role,
                    &session.id,
                    sequence,
                    &body,
                );
                let stats = outbound.get_mut(&size).expect("known candidate");
                stats.attempted += 1;
                match socket.send(&wire) {
                    Ok(length) if length == wire.len() => {
                        stats.sent += 1;
                        pending.insert(sequence, (size, Instant::now()));
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                        stats.emsgsize += 1
                    }
                    _ => stats.send_errors += 1,
                }
                sent_probes += 1;
                last_probe = Instant::now();
            }
            if elapsed >= Duration::from_secs(7) && !published_udp {
                progress(
                    json!({"schema":"netcontrol-path-test-progress-v1","phase":"udp_complete",
                                "udp":{"outbound":udp_json(&outbound,false),"inbound":udp_json(&inbound,true)}}),
                );
                published_udp = true;
            }
            if elapsed >= Duration::from_secs(24) {
                if report.is_none() {
                    report = Some(report_frames(&json!({
                        "udp_outbound":udp_json(&outbound,false),
                        "tcp_outbound":*tcp_out.lock().expect("path-test TCP output poisoned")
                    }))?);
                }
                if !report_acked && last_report.elapsed() >= Duration::from_millis(25) {
                    let (bodies, _) = report.as_ref().expect("initialized report");
                    sequence += 1;
                    send_control(
                        socket,
                        &encode(
                            &*session.key,
                            REPORT,
                            session.role,
                            &session.id,
                            sequence,
                            &bodies[report_index % bodies.len()],
                        ),
                    );
                    report_index += 1;
                    last_report = Instant::now();
                }
            }
            for _ in 0..4 {
                check(cancel, deadline + Duration::from_millis(100))?;
                let length = match receive(socket, &mut buffer)? {
                    Datagram::Packet(length) => length,
                    Datagram::Idle => break,
                    Datagram::PathError(reason) => {
                        *path_errors.entry(reason).or_default() += 1;
                        continue;
                    }
                };
                // Retransmitted consent gets a rate-limited READY while data uses a different key.
                if session.role == 1 && elapsed < Duration::from_secs(2) {
                    if let Some(frame) = decode(&*session.base, &buffer[..length]) {
                        if frame.role == 0
                            && frame.kind == CONSENT
                            && frame.session == session.id
                            && frame.sequence == 0
                            && frame.body == session.peer_caps.wire()
                            && last_ready.elapsed() >= Duration::from_millis(100)
                        {
                            send_control(
                                socket,
                                &encode(
                                    &*session.base,
                                    READY,
                                    1,
                                    &session.id,
                                    0,
                                    &session.local_caps.wire(),
                                ),
                            );
                            last_ready = Instant::now();
                            continue;
                        }
                    }
                }
                let Some(frame) = decode(&*session.key, &buffer[..length]) else {
                    continue;
                };
                if frame.role == session.role
                    || frame.session != session.id
                    || !replay.accept(frame.sequence)
                {
                    continue;
                }
                match frame.kind {
                    PROBE if elapsed < Duration::from_secs(7) => {
                        let size = (length + overhead) as u32;
                        let Some(stats) = inbound.get_mut(&size) else {
                            continue;
                        };
                        if stats.delivered >= PROBES as u32
                            || frame.body.iter().any(|byte| *byte != 0)
                        {
                            continue;
                        }
                        stats.delivered += 1;
                        let mut body = Vec::from(frame.sequence.to_be_bytes());
                        body.extend_from_slice(&size.to_be_bytes());
                        sequence += 1;
                        send_control(
                            socket,
                            &encode(
                                &*session.key,
                                ACK,
                                session.role,
                                &session.id,
                                sequence,
                                &body,
                            ),
                        );
                    }
                    ACK if frame.body.len() == 12 && elapsed < Duration::from_secs(7) => {
                        let acknowledged = u64::from_be_bytes(frame.body[..8].try_into()?);
                        let size = u32::from_be_bytes(frame.body[8..].try_into()?);
                        if let Some((expected, at)) = pending.get(&acknowledged) {
                            if *expected == size {
                                let stats = outbound.get_mut(&size).expect("known candidate");
                                stats.delivered += 1;
                                stats.rtts.push(at.elapsed().as_secs_f64() * 1000.0);
                                pending.remove(&acknowledged);
                            }
                        }
                    }
                    REPORT if elapsed >= Duration::from_secs(23) => {
                        if let Some(bytes) = parts.insert(frame.body) {
                            if let Some(value) = remote_report(&bytes, &inbound_sizes) {
                                remote = Some(value);
                                if last_report_ack.elapsed() >= Duration::from_millis(100) {
                                    sequence += 1;
                                    send_control(
                                        socket,
                                        &encode(
                                            &*session.key,
                                            REPORT_ACK,
                                            session.role,
                                            &session.id,
                                            sequence,
                                            &Sha256::digest(&bytes),
                                        ),
                                    );
                                    last_report_ack = Instant::now();
                                }
                            }
                        }
                    }
                    REPORT_ACK if frame.body.len() == 32 => {
                        if let Some((_, digest)) = &report {
                            if constant_eq(frame.body, digest) {
                                report_acked = true;
                            }
                        }
                    }
                    _ => (),
                }
            }
            thread::sleep(TICK);
        }
        let outbound_udp = udp_json(&outbound, false);
        let mut inbound_udp = udp_json(&inbound, true);
        inbound_udp["peer_sender_report"] = remote
            .as_ref()
            .map_or(Value::Null, |value| value["udp_outbound"].clone());
        if let Some(remote) = &remote {
            for (row, peer_row) in inbound_udp["sizes"]
                .as_array_mut()
                .expect("local UDP rows")
                .iter_mut()
                .zip(
                    remote["udp_outbound"]["sizes"]
                        .as_array()
                        .expect("checked remote rows"),
                )
            {
                for name in [
                    "attempted",
                    "sent",
                    "emsgsize",
                    "send_errors",
                    "mean_rtt_ms",
                ] {
                    row[name] = peer_row[name].clone();
                }
                let sent = row["sent"].as_u64().unwrap_or(0);
                let received = row["delivered"].as_u64().unwrap_or(0);
                row["loss_fraction"] = if sent > 0 {
                    json!(sent.saturating_sub(received) as f64 / sent as f64)
                } else {
                    Value::Null
                };
            }
        }
        let tcp_out = tcp_out
            .lock()
            .expect("path-test TCP output poisoned")
            .clone();
        let mut tcp_in = tcp_in
            .lock()
            .expect("path-test TCP output poisoned")
            .clone();
        if let Some(trials) = remote
            .as_ref()
            .and_then(|remote| remote["tcp_outbound"].as_array())
        {
            for inbound in &mut tcp_in {
                if let Some(sender) = trials
                    .iter()
                    .find(|sender| sender["trial"] == inbound["trial"])
                {
                    inbound["sender_retransmits"] = sender["retransmits"].clone();
                    inbound["sender_effective_mss_bytes"] = sender["effective_mss_bytes"].clone();
                }
            }
        }
        let best = tcp_out
            .iter()
            .filter(|value| value["status"] == "measured")
            .max_by(|a, b| {
                a["goodput_bits_per_second"]
                    .as_f64()
                    .unwrap_or(0.0)
                    .total_cmp(&b["goodput_bits_per_second"].as_f64().unwrap_or(0.0))
            })
            .cloned();
        Ok(json!({
            "udp":{"outbound":outbound_udp,"inbound":inbound_udp,"receive_path_errors":path_errors},
            "tcp":{"outbound_trials":tcp_out,"inbound_trials":tcp_in,
                "peer_sender_trials":remote.as_ref().map_or(Value::Null, |value| value["tcp_outbound"].clone()),
                "trial_byte_limit":BULK_LIMIT,"rate_limit_bytes_per_second":8*1024*1024,
                "mss_observation":"TCP_INFO.tcpi_snd_mss (sender), TCP_INFO.tcpi_rcv_mss (receiver)"},
            "peer_report_received":remote.is_some(),"local_report_acknowledged":report_acked,
            "measured_candidates":{"largest_verified_outbound_ip_size_bytes":outbound_udp["largest_verified_ip_size_bytes"],
                "best_outbound_mss_trial":best,"automatic_configuration":false}
        }))
    }

    fn run(
        prepared: &Prepared,
        request: &PathTestRequest,
        cancel: &AtomicBool,
        progress: &dyn Fn(Value),
    ) -> Result<Value> {
        let beginning = Instant::now();
        let lifetime = beginning + Duration::from_secs(PATH_TEST_LIFETIME_SECONDS);
        check(cancel, lifetime)?;
        let socket = prepared.socket.try_clone()?;
        let listener = prepared.listener.try_clone()?;
        let (interface_mtu, route_mtu, local_cap) = udp_limits(request, &socket)?;
        progress(
            json!({"schema":"netcontrol-path-test-progress-v1","phase":"armed",
                        "arm_timeout_seconds":PATH_TEST_ARM_SECONDS}),
        );
        let receive_cap = request.maximum_mtu.min(interface_mtu).min(65_535);
        let session = handshake(
            request,
            &socket,
            Caps {
                receive: receive_cap,
                send: local_cap,
            },
            cancel,
            lifetime.min(beginning + Duration::from_secs(PATH_TEST_ARM_SECONDS)),
        )?;
        ensure!(
            session.peer_caps.send
                >= if request.source_address.is_ipv6() {
                    1280
                } else {
                    576
                },
            "peer cap below address-family minimum"
        );
        let cap = local_cap.min(session.peer_caps.receive);
        progress(
            json!({"schema":"netcontrol-path-test-progress-v1","phase":"paired",
                        "local_cap_bytes":local_cap,"peer_cap_bytes":session.peer_caps.receive,
                        "peer_send_cap_bytes":session.peer_caps.send,"local_receive_cap_bytes":receive_cap,"tested_cap_bytes":cap}),
        );
        let start = Instant::now();
        let deadline = lifetime
            .min(start + Duration::from_secs(MEASUREMENT_SECONDS.min(PATH_TEST_RUN_SECONDS)));
        let tcp_deadline = deadline.min(start + Duration::from_secs(24));
        let stop = AtomicBool::new(false);
        let tcp_out = Mutex::new(Vec::new());
        let tcp_in = Mutex::new(Vec::new());
        let measurements = Measurements {
            request,
            session: &session,
            cap,
            start,
            deadline,
            tcp_out: &tcp_out,
            tcp_in: &tcp_in,
        };
        let measured = thread::scope(|scope| {
            scope.spawn(|| tcp_send(&measurements, &stop, tcp_deadline));
            scope.spawn(|| tcp_receive(request, &session, listener, &stop, tcp_deadline, &tcp_in));
            let result = measure(&measurements, &socket, cancel, progress);
            stop.store(true, Ordering::Relaxed);
            result
        })?;
        let mut result = measured;
        result["schema"] = json!("netcontrol-path-test-v1");
        result["status"] = json!("completed");
        result["interface"] = json!(request.interface);
        result["source_address"] = json!(request.source_address);
        result["peer_address"] = json!(request.peer_address);
        result["port"] = json!(request.port);
        result["role"] = json!(if session.role == 0 {
            "initiator"
        } else {
            "responder"
        });
        result["session_id"] = json!(hex_bytes(&session.id));
        result["elapsed_ms"] = json!(beginning.elapsed().as_secs_f64() * 1000.0);
        result["limits"] = json!({
            "requested_maximum_mtu_bytes":request.maximum_mtu,"interface_mtu_bytes":interface_mtu,
            "initial_route_mtu_bytes":route_mtu,"local_cap_bytes":local_cap,"peer_cap_bytes":session.peer_caps.receive,
            "local_receive_cap_bytes":receive_cap,"peer_send_cap_bytes":session.peer_caps.send,
            "inbound_tested_cap_bytes":session.peer_caps.send.min(receive_cap),
            "path_mtu_bytes":Value::Null,
            "final_cached_route_mtu_bytes":get_i32(socket.as_raw_fd(),
                if request.source_address.is_ipv4() { libc::IPPROTO_IP } else { libc::IPPROTO_IPV6 },
                if request.source_address.is_ipv4() { libc::IP_MTU } else { libc::IPV6_MTU }).ok(),
            "tested_cap_bytes":cap,"ipv6_minimum_mtu_bytes":if request.source_address.is_ipv6() { json!(1280) } else { Value::Null },
            "ip_udp_overhead_bytes":if request.source_address.is_ipv4() { 28 } else { 48 },
            "maximum_probes_per_size":PROBES,"candidate_limit":12,"measurement_limit_seconds":PATH_TEST_RUN_SECONDS,
            "arm_limit_seconds":PATH_TEST_ARM_SECONDS,"lifetime_limit_seconds":PATH_TEST_LIFETIME_SECONDS
        });
        result["limitations"] = limits();
        progress(json!({"schema":"netcontrol-path-test-progress-v1","phase":"completed"}));
        Ok(result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn report_reassembly_is_bounded_and_authenticated() {
            let value = json!({"payload":"a".repeat(2500)});
            let (frames, _) = report_frames(&value).unwrap();
            let mut parts = ReportParts::default();
            let mut result = None;
            for frame in frames.iter().rev() {
                if let Some(bytes) = parts.insert(frame) {
                    result = Some(bytes);
                }
            }
            assert_eq!(
                serde_json::from_slice::<Value>(&result.unwrap()).unwrap(),
                value
            );
            let mut invalid = frames[0].clone();
            invalid[..2].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(ReportParts::default().insert(&invalid).is_none());
            let mut invalid = frames;
            invalid[0][36] ^= 1;
            let mut parts = ReportParts::default();
            for frame in invalid {
                assert!(parts.insert(&frame).is_none());
            }
        }

        #[test]
        fn candidates_respect_family_and_route_caps() {
            assert_eq!(candidates(1280, true), vec![1280]);
            assert_eq!(candidates(576, false), vec![576]);
            for v6 in [false, true] {
                let sizes = candidates(65_535, v6);
                assert!(sizes.len() <= 12);
                assert_eq!(sizes.last(), Some(&65_535));
                assert!(
                    sizes
                        .iter()
                        .all(|size| *size >= if v6 { 1280 } else { 576 })
                );
                for mss in mss_candidates(1280, v6) {
                    assert!(mss <= 1280 - if v6 { 60 } else { 40 });
                }
            }
        }

        #[test]
        fn session_changes_for_either_nonce() {
            let first = session_id(b"test key", &[1; 32], &[2; 32]);
            assert_ne!(first, session_id(b"test key", &[3; 32], &[2; 32]));
            assert_ne!(first, session_id(b"test key", &[1; 32], &[3; 32]));
            assert_ne!(first, session_id(b"test key", &[2; 32], &[1; 32]));
        }

        #[test]
        fn receive_caps_do_not_conflate_the_peers_outbound_route() {
            let caps = Caps {
                receive: 2000,
                send: 1500,
            };
            let parsed = Caps::parse(&caps.wire()).unwrap();
            assert_eq!(parsed.receive, 2000);
            assert_eq!(parsed.send, 1500);
            assert!(
                Caps::parse(
                    &Caps {
                        receive: 1500,
                        send: 2000
                    }
                    .wire()
                )
                .is_none()
            );
            assert!(Caps::parse(&[0; 8]).is_none());
            assert!(Caps::parse(&[0; 7]).is_none());
            let local = Caps {
                receive: 2000,
                send: 2000,
            };
            assert_eq!(local.send.min(parsed.receive), 2000);
            assert_eq!(parsed.send.min(local.receive), 1500);
        }

        #[test]
        fn tcp_session_parser_rejects_signed_reflections_and_wrong_scope() {
            let session = Session {
                id: [7; 32],
                key: Zeroizing::new([9; 32]),
                base: Zeroizing::new([3; 32]),
                role: 0,
                local_caps: Caps {
                    receive: 1500,
                    send: 1500,
                },
                peer_caps: Caps {
                    receive: 1500,
                    send: 1500,
                },
            };
            let valid = encode(&*session.key, TCP_CHALLENGE, 1, &session.id, 1, &[5; 64]);
            assert!(authenticated(&session, &valid, TCP_CHALLENGE, 1).is_ok());
            let reflected = encode(&*session.key, TCP_CHALLENGE, 0, &session.id, 1, &[5; 64]);
            assert!(authenticated(&session, &reflected, TCP_CHALLENGE, 1).is_err());
            let other_session = encode(&*session.key, TCP_CHALLENGE, 1, &[8; 32], 1, &[5; 64]);
            assert!(authenticated(&session, &other_session, TCP_CHALLENGE, 1).is_err());
            assert!(authenticated(&session, &valid, TCP_PROOF, 1).is_err());
            assert!(authenticated(&session, &valid, TCP_CHALLENGE, 2).is_err());
        }

        #[test]
        fn tcp_trial_failures_preserve_error_without_fabricated_measurements() {
            let request: PathTestRequest = serde_json::from_value(json!({
                "interface":"unavailable-interface-name",
                "source_address":"192.0.2.1","peer_address":"192.0.2.2",
                "maximum_mtu":1500,
                "pairing_secret":"synthetic-pairing-secret-1234567890"
            }))
            .unwrap();
            let caps = Caps {
                receive: 1500,
                send: 1500,
            };
            let session = Session {
                id: [7; 32],
                key: Zeroizing::new([9; 32]),
                base: Zeroizing::new([3; 32]),
                role: 0,
                local_caps: caps,
                peer_caps: caps,
            };
            let output = Mutex::new(Vec::new());
            let inbound = Mutex::new(Vec::new());
            let deadline = Instant::now() + Duration::from_secs(2);
            tcp_send(
                &Measurements {
                    request: &request,
                    session: &session,
                    cap: 1500,
                    start: Instant::now() - Duration::from_secs(7),
                    deadline,
                    tcp_out: &output,
                    tcp_in: &inbound,
                },
                &AtomicBool::new(false),
                deadline,
            );
            let rows = output.into_inner().unwrap();
            assert_eq!(rows.len(), 3);
            for row in rows {
                assert_eq!(row["status"], "inconclusive");
                assert!(row["error"].as_str().is_some_and(|error| !error.is_empty()));
                assert!(row["goodput_bits_per_second"].is_null());
                assert!(row["delivered_bytes"].is_null());
                assert!(!row.to_string().contains("synthetic-pairing-secret"));
            }
        }

        fn namespace(test: impl FnOnce() -> Result<()> + Send + 'static) {
            assert_eq!(
                std::env::var("NETCONTROL_INTEGRATION").as_deref(),
                Ok("1"),
                "set NETCONTROL_INTEGRATION=1 to authorize isolated privileged tests"
            );
            thread::spawn(move || {
                linux::check(unsafe { libc::unshare(libc::CLONE_NEWNET) })
                    .context("path-test fixture requires isolated network namespace privileges")?;
                let mut rename = link_header(linux::ifindex("lo")?, false);
                rename.extend_from_slice(&attribute(3, b"ptlo\0"));
                netlink(libc::RTM_NEWLINK, rename, false)?;
                let fd = linux::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
                let mut req: libc::ifreq = unsafe { mem::zeroed() };
                for (to, from) in req.ifr_name.iter_mut().zip(b"ptlo") {
                    *to = *from as _;
                }
                linux::check(unsafe {
                    libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut req)
                })?;
                unsafe {
                    req.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
                }
                linux::check(unsafe {
                    libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &req)
                })?;
                for (index, address) in ["192.0.2.1", "192.0.2.2"].iter().enumerate() {
                    let mut req: libc::ifreq = unsafe { mem::zeroed() };
                    for (to, from) in req.ifr_name.iter_mut().zip(format!("ptlo:{index}").bytes()) {
                        *to = from as _;
                    }
                    let address: std::net::Ipv4Addr = address.parse()?;
                    let mut sockaddr: libc::sockaddr_in = unsafe { mem::zeroed() };
                    sockaddr.sin_family = libc::AF_INET as _;
                    sockaddr.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
                    unsafe {
                        std::ptr::write(
                            &mut req.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in,
                            sockaddr,
                        );
                    }
                    linux::check(unsafe {
                        libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFADDR as _, &req)
                    })?;
                }
                test()
            })
            .join()
            .expect("path-test fixture panicked")
            .expect("path-test isolated fixture failed");
        }

        fn request(source: &str, peer: &str) -> PathTestRequest {
            let request: PathTestRequest = serde_json::from_value(json!({
                "interface":"ptlo","source_address":source,"peer_address":peer,"port":49872,
                "maximum_mtu":1500,"pairing_secret":"synthetic-isolated-test-secret-0123456789"
            }))
            .unwrap();
            request
                .validate()
                .expect("fixture request must satisfy the current production contract");
            request
        }

        fn paired(v6: bool) -> Result<()> {
            let (source, peer) = if v6 {
                #[repr(C)]
                struct In6Ifreq {
                    address: libc::in6_addr,
                    prefix: u32,
                    index: i32,
                }
                let fd = linux::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)?;
                for address in ["2001:db8::1", "2001:db8::2"] {
                    let address: std::net::Ipv6Addr = address.parse()?;
                    let req = In6Ifreq {
                        address: libc::in6_addr {
                            s6_addr: address.octets(),
                        },
                        prefix: 128,
                        index: linux::ifindex("ptlo")? as i32,
                    };
                    linux::check(unsafe {
                        libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFADDR as _, &req)
                    })?;
                }
                ("2001:db8::1", "2001:db8::2")
            } else {
                ("192.0.2.1", "192.0.2.2")
            };
            let low = request(source, peer);
            let high = request(peer, source);
            let cancel = AtomicBool::new(false);
            let (a, b) = thread::scope(|scope| {
                let peer = scope.spawn(|| super::super::run(&high, &cancel, &|_| {}));
                let local = super::super::run(&low, &cancel, &|_| {});
                (local, peer.join().expect("peer test panicked"))
            });
            for result in [a?, b?] {
                assert_eq!(result["schema"], "netcontrol-path-test-v1");
                assert_eq!(
                    result["udp"]["outbound"]["largest_verified_ip_size_bytes"],
                    1500
                );
                assert_eq!(
                    result["udp"]["inbound"]["largest_verified_ip_size_bytes"],
                    1500
                );
                assert_eq!(result["peer_report_received"], true);
                assert_eq!(result["local_report_acknowledged"], true);
                let trials = result["tcp"]["outbound_trials"].as_array().unwrap();
                assert!(trials.len() >= 2);
                for trial in trials {
                    assert_eq!(trial["status"], "measured", "{trial}");
                    assert!(trial["delivered_bytes"].as_u64().unwrap() > 0);
                    assert!(trial["goodput_bits_per_second"].as_f64().unwrap() > 0.0);
                    assert!(
                        trial["effective_mss_bytes"].as_u64().unwrap()
                            <= trial["requested_mss_bytes"].as_u64().unwrap()
                    );
                }
                assert!(!serde_json::to_string(&result)?.contains(low.pairing_secret.as_str()));
            }
            Ok(())
        }

        #[test]
        #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; no host mutation"]
        fn native_path_test_isolated_pair_ipv4() {
            namespace(|| paired(false));
        }

        #[test]
        #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; no host mutation"]
        fn native_path_test_isolated_pair_ipv6() {
            namespace(|| paired(true));
        }

        fn fresh_namespace() -> Result<std::fs::File> {
            thread::spawn(|| {
                linux::check(unsafe { libc::unshare(libc::CLONE_NEWNET) })?;
                Ok(std::fs::File::open("/proc/thread-self/ns/net")?)
            })
            .join()
            .map_err(|_| anyhow::anyhow!("namespace creation thread panicked"))?
        }

        fn in_namespace<T: Send + 'static>(
            namespace: std::fs::File,
            run: impl FnOnce() -> Result<T> + Send + 'static,
        ) -> Result<T> {
            thread::spawn(move || {
                linux::check(unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) })?;
                run()
            })
            .join()
            .map_err(|_| anyhow::anyhow!("isolated namespace thread panicked"))?
        }

        fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
            let length = value.len() + 4;
            let mut result = Vec::from((length as u16).to_ne_bytes());
            result.extend_from_slice(&kind.to_ne_bytes());
            result.extend_from_slice(value);
            result.resize((length + 3) & !3, 0);
            result
        }

        fn netlink(kind: u16, mut body: Vec<u8>, create: bool) -> Result<()> {
            let fd = linux::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
            let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as _;
            let mut wire = Vec::from(((16 + body.len()) as u32).to_ne_bytes());
            wire.extend_from_slice(&kind.to_ne_bytes());
            let flags = (libc::NLM_F_REQUEST
                | libc::NLM_F_ACK
                | if create {
                    libc::NLM_F_CREATE | libc::NLM_F_EXCL
                } else {
                    0
                }) as u16;
            wire.extend_from_slice(&flags.to_ne_bytes());
            wire.extend_from_slice(&1_u32.to_ne_bytes());
            wire.extend_from_slice(&0_u32.to_ne_bytes());
            wire.append(&mut body);
            let sent = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    wire.as_ptr() as *const _,
                    wire.len(),
                    0,
                    &kernel as *const _ as *const _,
                    mem::size_of_val(&kernel) as _,
                )
            };
            ensure!(
                sent == wire.len() as isize,
                "rtnetlink fixture send failed: {}",
                io::Error::last_os_error()
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut buffer = [0_u8; 4096];
            loop {
                ensure!(Instant::now() < deadline, "rtnetlink fixture ACK timed out");
                let length = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len(),
                        0,
                    )
                };
                if length < 0 {
                    let error = io::Error::last_os_error();
                    if transient(&error) {
                        thread::sleep(TICK);
                        continue;
                    }
                    return Err(error.into());
                }
                let length = length as usize;
                let mut offset = 0;
                while offset + 16 <= length {
                    let message_length =
                        u32::from_ne_bytes(buffer[offset..offset + 4].try_into()?) as usize;
                    ensure!(
                        message_length >= 16 && offset + message_length <= length,
                        "malformed fixture netlink ACK"
                    );
                    let message_kind =
                        u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into()?);
                    if message_kind == libc::NLMSG_ERROR as u16 {
                        ensure!(message_length >= 20, "short fixture netlink ACK");
                        let error =
                            i32::from_ne_bytes(buffer[offset + 16..offset + 20].try_into()?);
                        ensure!(
                            error == 0,
                            "rtnetlink fixture failed: {}",
                            io::Error::from_raw_os_error(-error)
                        );
                        return Ok(());
                    }
                    offset += (message_length + 3) & !3;
                }
            }
        }

        fn link_header(index: u32, up: bool) -> Vec<u8> {
            let mut body = vec![0_u8; 16];
            body[4..8].copy_from_slice(&index.to_ne_bytes());
            if up {
                body[8..12].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
                body[12..16].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
            }
            body
        }

        fn veth(router_name: &str, endpoint: &std::fs::File, router_mtu: u32) -> Result<()> {
            const NESTED: u16 = 1 << 15;
            let mut body = link_header(0, false);
            let mut name = router_name.as_bytes().to_vec();
            name.push(0);
            body.extend_from_slice(&attribute(3, &name)); // IFLA_IFNAME
            body.extend_from_slice(&attribute(4, &router_mtu.to_ne_bytes())); // IFLA_MTU
            let mut peer = link_header(0, false);
            peer.extend_from_slice(&attribute(3, b"pt0\0"));
            peer.extend_from_slice(&attribute(4, &2000_u32.to_ne_bytes()));
            peer.extend_from_slice(&attribute(28, &endpoint.as_raw_fd().to_ne_bytes())); // IFLA_NET_NS_FD
            let peer = attribute(1 | NESTED, &peer); // VETH_INFO_PEER
            let mut info = attribute(1, b"veth\0"); // IFLA_INFO_KIND
            info.extend_from_slice(&attribute(2 | NESTED, &peer)); // IFLA_INFO_DATA
            body.extend_from_slice(&attribute(18 | NESTED, &info)); // IFLA_LINKINFO
            netlink(libc::RTM_NEWLINK, body, true)
        }

        fn configure_link(name: &str, address: &str) -> Result<()> {
            let index = linux::ifindex(name)?;
            netlink(libc::RTM_NEWLINK, link_header(index, true), false)?;
            let mut body = vec![libc::AF_INET as u8, 24, 0, 0];
            body.extend_from_slice(&index.to_ne_bytes());
            let address: std::net::Ipv4Addr = address.parse()?;
            body.extend_from_slice(&attribute(1, &address.octets())); // IFA_ADDRESS
            body.extend_from_slice(&attribute(2, &address.octets())); // IFA_LOCAL
            netlink(libc::RTM_NEWADDR, body, true)
        }

        fn default_route(gateway: &str) -> Result<()> {
            let mut body = vec![libc::AF_INET as u8, 0, 0, 0, 254, 4, 0, 1, 0, 0, 0, 0];
            let gateway: std::net::Ipv4Addr = gateway.parse()?;
            body.extend_from_slice(&attribute(5, &gateway.octets())); // RTA_GATEWAY
            body.extend_from_slice(&attribute(4, &linux::ifindex("pt0")?.to_ne_bytes())); // RTA_OIF
            netlink(libc::RTM_NEWROUTE, body, true)
        }

        fn asymmetric_transit_route() -> Result<()> {
            // A more-specific route constrains only right-to-left forwarding; both veth links stay 2000.
            let mut body = vec![libc::AF_INET as u8, 25, 0, 0, 254, 4, 253, 1, 0, 0, 0, 0];
            body.extend_from_slice(&attribute(1, &[192, 0, 2, 0])); // RTA_DST
            body.extend_from_slice(&attribute(4, &linux::ifindex("left0")?.to_ne_bytes()));
            let mtu = attribute(2, &1500_u32.to_ne_bytes()); // RTAX_MTU
            body.extend_from_slice(&attribute(8 | (1 << 15), &mtu)); // RTA_METRICS
            netlink(libc::RTM_NEWROUTE, body, true)
        }

        fn routed_bottleneck(asymmetric: bool) -> Result<()> {
            ensure!(
                std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
                "set NETCONTROL_INTEGRATION=1 to authorize isolated privileged tests"
            );
            let left = fresh_namespace()?;
            let transit = fresh_namespace()?;
            let right = fresh_namespace()?;
            let left_target = left.try_clone()?;
            let right_target = right.try_clone()?;
            in_namespace(transit.try_clone()?, move || {
                veth("left0", &left_target, 2000)?;
                veth(
                    "right0",
                    &right_target,
                    if asymmetric { 2000 } else { 1500 },
                )?;
                configure_link("left0", "192.0.2.254")?;
                configure_link("right0", "198.51.100.254")?;
                if asymmetric {
                    asymmetric_transit_route()?;
                }
                // This procfs network sysctl resolves in this fresh transit namespace only.
                std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")?;
                Ok(())
            })?;
            in_namespace(left.try_clone()?, || {
                configure_link("pt0", "192.0.2.1")?;
                default_route("192.0.2.254")
            })?;
            in_namespace(right.try_clone()?, || {
                configure_link("pt0", "198.51.100.1")?;
                default_route("198.51.100.254")
            })?;
            let peer = thread::spawn(move || {
                in_namespace(right, || {
                    let mut request = request("198.51.100.1", "192.0.2.1");
                    request.interface = "pt0".into();
                    request.maximum_mtu = 2000;
                    super::super::run(&request, &AtomicBool::new(false), &|_| {})
                })
            });
            let local = in_namespace(left, || {
                let mut request = request("192.0.2.1", "198.51.100.1");
                request.interface = "pt0".into();
                request.maximum_mtu = 2000;
                super::super::run(&request, &AtomicBool::new(false), &|_| {})
            });
            let remote = peer
                .join()
                .map_err(|_| anyhow::anyhow!("routed endpoint panicked"))?;
            for result in [local?, remote?] {
                assert_eq!(result["limits"]["interface_mtu_bytes"], 2000);
                assert_eq!(result["limits"]["initial_route_mtu_bytes"], 2000);
                let left = result["source_address"] == "192.0.2.1";
                let expected_outbound = if asymmetric && left { 2000 } else { 1500 };
                let expected_inbound = if asymmetric && !left { 2000 } else { 1500 };
                assert_eq!(
                    result["udp"]["outbound"]["largest_verified_ip_size_bytes"],
                    expected_outbound
                );
                assert_eq!(
                    result["udp"]["inbound"]["largest_verified_ip_size_bytes"],
                    expected_inbound
                );
                let rows = result["udp"]["outbound"]["sizes"].as_array().unwrap();
                let verified = rows
                    .iter()
                    .find(|row| row["ip_size_bytes"] == 1500)
                    .unwrap();
                let above = rows
                    .iter()
                    .find(|row| row["ip_size_bytes"] == 2000)
                    .unwrap();
                assert!(verified["delivered"].as_u64().unwrap() > 0);
                if expected_outbound == 1500 {
                    assert_eq!(above["delivered"], 0);
                    assert_ne!(above["status"], "verified");
                } else {
                    assert!(above["delivered"].as_u64().unwrap() > 0);
                    assert_eq!(above["status"], "verified");
                }
                // Non-delivery above the verified size never becomes a guessed exact PMTU.
                assert!(result["limits"]["path_mtu_bytes"].is_null());
                assert_eq!(
                    result["measured_candidates"]["automatic_configuration"],
                    false
                );
            }
            drop(transit);
            Ok(())
        }

        #[test]
        #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; three fresh network namespaces only"]
        fn native_path_test_routed_hidden_1500_bottleneck() -> Result<()> {
            routed_bottleneck(false)
        }

        #[test]
        #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; three fresh network namespaces only"]
        fn native_path_test_routed_asymmetric_2000_forward_1500_reverse() -> Result<()> {
            routed_bottleneck(true)
        }

        #[test]
        #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; no host mutation"]
        fn native_path_test_reservation_rejects_occupied_udp_and_tcp() {
            namespace(|| {
                let request = request("192.0.2.1", "192.0.2.2");
                let fd = linux::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
                let before = interface_mtu(fd.as_raw_fd(), "ptlo")?;
                {
                    // An unrelated wildcard listener must not coexist with our exact-source reservation.
                    let _occupied = UdpSocket::bind(SocketAddr::new(
                        std::net::Ipv4Addr::UNSPECIFIED.into(),
                        request.port,
                    ))?;
                    let error = super::super::prepare(&request)
                        .err()
                        .expect("occupied UDP port must fail");
                    assert!(error.chain().any(|cause| {
                        cause
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.raw_os_error() == Some(libc::EADDRINUSE))
                    }));
                    assert_eq!(interface_mtu(fd.as_raw_fd(), "ptlo")?, before);
                }
                {
                    let _occupied = TcpListener::bind(SocketAddr::new(
                        std::net::Ipv4Addr::UNSPECIFIED.into(),
                        request.port,
                    ))?;
                    let error = super::super::prepare(&request)
                        .err()
                        .expect("occupied TCP port must fail");
                    assert!(error.chain().any(|cause| {
                        cause
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.raw_os_error() == Some(libc::EADDRINUSE))
                    }));
                    assert_eq!(interface_mtu(fd.as_raw_fd(), "ptlo")?, before);
                    // A TCP collision also releases the UDP socket prepared first.
                    let _released = bound(&request, libc::SOCK_DGRAM, request.port)?;
                }
                {
                    let prepared = super::super::prepare(&request)?;
                    assert!(bound(&request, libc::SOCK_DGRAM, request.port).is_err());
                    assert!(bound(&request, libc::SOCK_STREAM, request.port).is_err());
                    assert!(
                        prepared
                            .run(&request, &AtomicBool::new(true), &|_| {})
                            .is_err()
                    );
                    // The native owner may now remove permits while both reservations remain exclusive.
                    assert!(bound(&request, libc::SOCK_DGRAM, request.port).is_err());
                    assert!(bound(&request, libc::SOCK_STREAM, request.port).is_err());
                    let retry = prepared
                        .run(&request, &AtomicBool::new(false), &|_| {})
                        .unwrap_err();
                    assert!(retry.to_string().contains("already started"));
                    drop(prepared);
                }
                let _udp = bound(&request, libc::SOCK_DGRAM, request.port)?;
                let _tcp = bound(&request, libc::SOCK_STREAM, request.port)?;
                assert_eq!(interface_mtu(fd.as_raw_fd(), "ptlo")?, before);
                fn send_sync_and_static<T: Send + Sync + 'static>() {}
                send_sync_and_static::<Prepared>();
                Ok(())
            });
        }

        #[test]
        #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; no host mutation"]
        fn native_path_test_paired_cancellation_joins_workers() {
            namespace(|| {
                let low = request("192.0.2.1", "192.0.2.2");
                let high = request("192.0.2.2", "192.0.2.1");
                let cancel = AtomicBool::new(false);
                let paired = AtomicBool::new(false);
                let start = Instant::now();
                thread::scope(|scope| {
                    let peer = scope.spawn(|| {
                        super::super::run(&high, &cancel, &|event| {
                            if event["phase"] == "paired" {
                                paired.store(true, Ordering::Relaxed);
                                cancel.store(true, Ordering::Relaxed);
                            }
                        })
                    });
                    let local_error = super::super::run(&low, &cancel, &|_| {}).unwrap_err();
                    assert!(
                        local_error.to_string().contains("cancelled"),
                        "{local_error}"
                    );
                    let peer_error = peer.join().unwrap().unwrap_err();
                    assert!(peer_error.to_string().contains("cancelled"), "{peer_error}");
                });
                assert!(
                    paired.load(Ordering::Relaxed),
                    "cancellation must follow an authenticated pairing"
                );
                assert!(start.elapsed() < Duration::from_secs(2));
                // A fresh bind proves that all scoped sockets/workers were dropped.
                let _ = bound(&low, libc::SOCK_DGRAM, low.port)?;
                Ok(())
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_including_long_keys() {
        assert_eq!(
            hmac(&[0x0b; 20], b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7
            ]
        );
        assert_eq!(
            hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            [
                0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
                0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
                0x0e, 0xe3, 0x7f, 0x54
            ]
        );
    }

    #[test]
    fn frame_authentication_rejects_tampering_wrong_key_and_reflection() {
        let wire = encode(b"secret", PROBE, 0, &[7; 32], 1, b"payload");
        let parsed = decode(b"secret", &wire).unwrap();
        assert_eq!(parsed.kind, PROBE);
        assert_eq!(parsed.role, 0);
        assert_eq!(parsed.session, [7; 32]);
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.body, b"payload");
        assert!(decode(b"another secret", &wire).is_none());
        for index in 0..wire.len() {
            let mut changed = wire.clone();
            changed[index] ^= 1;
            assert!(decode(b"secret", &changed).is_none(), "{index}");
        }
        // Roles/kinds/session are inside the MAC; reversing a packet cannot authenticate.
        let mut reflected = wire;
        reflected[9] = 1;
        assert!(decode(b"secret", &reflected).is_none());
    }

    #[test]
    fn parser_rejects_truncation_oversize_and_invalid_fields() {
        let wire = encode(b"key", HELLO, 0, &[1; 32], 0, &[]);
        for length in 0..wire.len() {
            assert!(decode(b"key", &wire[..length]).is_none());
        }
        assert!(decode(b"key", &vec![0; MAX_FRAME + 1]).is_none());
        assert!(decode(b"key", &encode(b"key", HELLO, 2, &[1; 32], 0, &[])).is_none());
        assert!(decode(b"key", &encode(b"key", 0, 0, &[1; 32], 0, &[])).is_none());
        let mut invalid = wire.clone();
        invalid[50..54].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(b"key", &invalid).is_none());
        let mut appended = wire;
        appended.push(0);
        assert!(decode(b"key", &appended).is_none());
    }

    #[test]
    fn replay_window_accepts_reordering_once_and_rejects_old_frames() {
        let mut window = Replay::default();
        assert!(!window.accept(0));
        assert!(window.accept(2));
        assert!(window.accept(1));
        assert!(!window.accept(2));
        assert!(!window.accept(1));
        assert!(window.accept(65));
        assert!(!window.accept(1));
        assert!(window.accept(64));
        assert!(!window.accept(64));
        assert!(window.accept(u64::MAX));
        assert!(!window.accept(u64::MAX));
        assert!(!window.accept(65));
        assert!(Replay::default().accept(1));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_is_explicitly_unsupported() {
        let request = serde_json::from_value(serde_json::json!({
            "interface":"eth0","source_address":"192.0.2.1","peer_address":"192.0.2.2",
            "maximum_mtu":1500,"pairing_secret":"synthetic-path-test-secret-0123456789"
        }))
        .unwrap();
        let error = run(&request, &AtomicBool::new(false), &|_| {}).unwrap_err();
        assert!(error.to_string().contains("only on Linux"));
    }
}
