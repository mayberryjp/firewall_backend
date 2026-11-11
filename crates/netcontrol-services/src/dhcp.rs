use super::dhcp_telemetry::{Action, Telemetry};
use anyhow::{Result, ensure};
use std::net::Ipv4Addr;
const FIXED: usize = 240;
fn ip(p: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(p[offset], p[offset + 1], p[offset + 2], p[offset + 3])
}
fn valid(packet: &[u8]) -> bool {
    packet.len() >= FIXED
        && packet.len() <= 65507
        && packet[1] == 1
        && packet[2] == 6
        && packet[236..240] == [99, 130, 83, 99]
        && packet[28..34].iter().any(|x| *x != 0)
        && packet[28] & 1 == 0
        && packet[10] & 0x7f == 0
        && packet[11] == 0
        && {
            let mut i = 240;
            let mut msg = false;
            let mut end = false;
            let mut ok = true;
            while i < packet.len() {
                let tag = packet[i];
                i += 1;
                if tag == 255 {
                    end = true;
                    break;
                }
                if tag == 0 {
                    continue;
                }
                if i >= packet.len() {
                    ok = false;
                    break;
                }
                let n = packet[i] as usize;
                i += 1;
                if i + n > packet.len() {
                    ok = false;
                    break;
                }
                if tag == 53 {
                    if n != 1 || msg || !(1..=8).contains(&packet[i]) {
                        ok = false;
                        break;
                    }
                    msg = true;
                }
                i += n;
            }
            ok && msg && end
        }
}
fn message_type(packet: &[u8]) -> u8 {
    let mut p = 240;
    while p < packet.len() {
        let tag = packet[p];
        p += 1;
        if tag == 255 {
            break;
        }
        if tag == 0 {
            continue;
        }
        let n = packet[p] as usize;
        p += 1;
        if tag == 53 {
            return packet[p];
        }
        p += n;
    }
    0
}
#[derive(Debug, PartialEq)]
pub(crate) struct Metadata {
    pub message_type: u8,
    pub transaction_id: String,
    pub client_mac: String,
    pub client_address: Ipv4Addr,
    pub offered_address: Ipv4Addr,
    pub relay_address: Ipv4Addr,
    pub broadcast: bool,
    pub hops: u8,
}
pub(crate) fn metadata(packet: &[u8]) -> Option<Metadata> {
    valid(packet).then(|| Metadata {
        message_type: message_type(packet),
        transaction_id: format!(
            "{:08x}",
            u32::from_be_bytes(packet[4..8].try_into().unwrap())
        ),
        client_mac: packet[28..34]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        client_address: ip(packet, 12),
        offered_address: ip(packet, 16),
        relay_address: ip(packet, 24),
        broadcast: packet[10] & 0x80 != 0,
        hops: packet[3],
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare_observed(
    interfaces: Vec<super::config::Interface>,
    telemetry: Telemetry,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    telemetry.begin(interfaces.iter().map(|interface| interface.name.clone()))?;
    let prepared = prepare(interfaces, telemetry.clone());
    match prepared {
        Ok(run) => Ok(Box::new(move |ctx| {
            telemetry.record(None, Action::WorkerStart, "", &[], None)?;
            let result = run(ctx);
            telemetry.pending(Default::default())?;
            if let Err(error) = &result {
                telemetry.record(None, Action::WorkerError, &format!("{error:#}"), &[], None)?;
            }
            result
        })),
        Err(error) => {
            telemetry.record(None, Action::WorkerError, &format!("{error:#}"), &[], None)?;
            Err(error)
        }
    }
}

pub(crate) fn request(packet: &[u8], relay: Ipv4Addr) -> Result<Vec<u8>> {
    ensure!(
        valid(packet) && packet[0] == 1,
        "invalid DHCPv4 client packet"
    );
    ensure!(
        [1, 3, 4, 7, 8].contains(&message_type(packet)),
        "invalid DHCP client message type"
    );
    ensure!(
        packet[3] == 0 && ip(packet, 24).is_unspecified(),
        "downstream relay chaining is not accepted"
    );
    ensure!(ip(packet, 16).is_unspecified(), "client supplied yiaddr");
    let mut wire = packet.to_vec();
    wire[3] = 1;
    wire[24..28].copy_from_slice(&relay.octets());
    Ok(wire)
}
pub(crate) fn response(packet: &[u8], relay: Ipv4Addr) -> Result<(Ipv4Addr, bool)> {
    // Hops limits apply to forwarded requests, not BOOTREPLY (RFC 2131 table 3).
    ensure!(
        valid(packet) && packet[0] == 2 && ip(packet, 24) == relay,
        "invalid relay reply op/giaddr"
    );
    let kind = message_type(packet);
    ensure!(
        [2, 5, 6].contains(&kind),
        "invalid DHCP server message type"
    );
    let ci = ip(packet, 12);
    let yi = ip(packet, 16);
    let broadcast = packet[10] & 0x80 != 0;
    if kind == 6 {
        ensure!(
            ci.is_unspecified() && yi.is_unspecified(),
            "DHCPNAK must have zero ciaddr and yiaddr"
        );
        return Ok((Ipv4Addr::BROADCAST, true));
    }
    if !ci.is_unspecified() {
        ensure!(super::config::unicast(ci.into(), false), "invalid ciaddr");
        return Ok((ci, false));
    }
    if broadcast {
        return Ok((Ipv4Addr::BROADCAST, true));
    }
    ensure!(super::config::unicast(yi.into(), false), "invalid yiaddr");
    Ok((yi, false))
}
fn reply_matches(packet: &[u8], client: Ipv4Addr, broadcast: bool) -> Result<()> {
    if message_type(packet) != 6 {
        ensure!(
            ip(packet, 12) == client,
            "reply ciaddr does not match the tracked request"
        );
        ensure!(
            (packet[10] & 0x80 != 0) == broadcast,
            "reply broadcast flag does not match the tracked request"
        );
    }
    Ok(())
}
pub(crate) fn key(packet: &[u8]) -> [u8; 10] {
    let mut key = [0; 10];
    key[..4].copy_from_slice(&packet[4..8]);
    key[4..].copy_from_slice(&packet[28..34]);
    key
}
fn on_link(interfaces: &[String], ip: Ipv4Addr, relay: Ipv4Addr) -> bool {
    if ip == relay || !super::config::unicast(ip.into(), false) {
        return false;
    }
    interfaces.iter().any(|p| {
        if !super::config::contains(p, ip.into()) {
            return false;
        }
        let Some((base, bits)) = p.split_once('/') else {
            return false;
        };
        let (Ok(base), Ok(bits)) = (base.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
            return false;
        };
        if bits >= 31 {
            return true;
        }
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        let network = u32::from(base) & mask;
        let n = u32::from(ip);
        n != network && n != (network | !mask)
    })
}
fn valid_client_address(
    source: Ipv4Addr,
    client: Ipv4Addr,
    prefixes: &[String],
    relay: Ipv4Addr,
) -> bool {
    if client.is_unspecified() {
        source.is_unspecified()
    } else {
        on_link(prefixes, client, relay) && (source.is_unspecified() || source == client)
    }
}
#[cfg(target_os = "linux")]
fn recoverable_socket_error(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ECONNREFUSED
                | libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::ENETDOWN
                | libc::EHOSTDOWN
                | libc::ENOBUFS
                | libc::EMSGSIZE
        )
    )
}
pub(crate) fn unicast_wire(packet: &[u8], source: Ipv4Addr, target: Ipv4Addr) -> Result<Vec<u8>> {
    ensure!(packet.len() <= 65507, "DHCP packet too large");
    let mut wire = vec![0; 28 + packet.len()];
    wire[0] = 0x45;
    let len = wire.len() as u16;
    wire[2..4].copy_from_slice(&len.to_be_bytes());
    wire[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    wire[6] = 0x40;
    wire[8] = 64;
    wire[9] = 17;
    wire[12..16].copy_from_slice(&source.octets());
    wire[16..20].copy_from_slice(&target.octets());
    let checksum = super::gateway::checksum(&wire[..20]);
    wire[10..12].copy_from_slice(&checksum.to_be_bytes());
    wire[20..22].copy_from_slice(&67u16.to_be_bytes());
    wire[22..24].copy_from_slice(&68u16.to_be_bytes());
    wire[24..26].copy_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
    wire[28..].copy_from_slice(packet);
    let mut pseudo = Vec::with_capacity(12 + 8 + packet.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&target.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
    pseudo.extend_from_slice(&wire[20..]);
    let sum = super::gateway::checksum(&pseudo);
    wire[26..28].copy_from_slice(&if sum == 0 { 65535u16 } else { sum }.to_be_bytes());
    Ok(wire)
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    interfaces: Vec<super::config::Interface>,
    telemetry: Telemetry,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use crate::linux as l;
    use std::{
        collections::BTreeMap,
        mem,
        net::{IpAddr, SocketAddr},
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };
    let fd = l::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let packet_fd = l::socket(
        libc::AF_PACKET,
        libc::SOCK_DGRAM,
        (libc::ETH_P_IP as u16).to_be() as i32,
    )?;
    l::option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BROADCAST, &1i32)?;
    l::option(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_PKTINFO, &1i32)?;
    l::bind(fd.as_raw_fd(), SocketAddr::from(([0, 0, 0, 0], 67)), 0)?;
    let mut bindings = BTreeMap::new();
    for i in interfaces {
        let addr = i.relay_address()?;
        let (idx, addresses) = l::interface_snapshot(&i.name)?;
        ensure!(
            addresses.contains(&IpAddr::V4(addr)),
            "relay address missing on interface {}",
            i.name
        );
        let servers = i
            .dhcp_relay
            .servers
            .iter()
            .map(|s| s.parse::<Ipv4Addr>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        bindings.insert(idx, (i.name, addr, servers, i.addresses));
    }
    Ok(Box::new(move |ctx| {
        let mut buffer = vec![0u8; 65535];
        struct Transaction {
            index: u32,
            since: Instant,
            metadata: Metadata,
        }
        let mut transactions: BTreeMap<(Ipv4Addr, [u8; 10]), Transaction> = BTreeMap::new();
        let mut pruned = Instant::now();
        while !ctx.stopping() {
            if pruned.elapsed() >= Duration::from_secs(1) {
                let mut expired = Vec::new();
                for (key, transaction) in &transactions {
                    if transaction.since.elapsed() >= Duration::from_secs(120) {
                        expired.push(*key);
                    }
                }
                for key in expired {
                    let transaction = transactions
                        .remove(&key)
                        .ok_or_else(|| anyhow::anyhow!("missing expired DHCP transaction"))?;
                    let name = &bindings
                        .get(&transaction.index)
                        .ok_or_else(|| anyhow::anyhow!("missing DHCP relay binding"))?
                        .0;
                    telemetry.record_metadata(
                        Some(name),
                        Action::Expired,
                        "tracking_timeout",
                        Some(&transaction.metadata),
                        None,
                        "Relay tracking aged out after 120 seconds; this is not lease expiry",
                    )?;
                    telemetry.track(name, false)?;
                }
                pruned = Instant::now();
            }
            let mut src: libc::sockaddr_storage = unsafe { mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: buffer.as_mut_ptr() as *mut _,
                iov_len: buffer.len(),
            };
            // cmsghdr requires native word alignment.
            let mut control = [0usize; 16];
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_name = &mut src as *mut _ as *mut _;
            msg.msg_namelen = mem::size_of_val(&src) as _;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut _;
            msg.msg_controllen = mem::size_of_val(&control) as _;
            let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, 0) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted
                {
                    ctx.wait(Duration::from_millis(10));
                    continue;
                }
                if recoverable_socket_error(&e) {
                    telemetry.record_detail(
                        None,
                        Action::SendError,
                        "socket_error",
                        &[],
                        None,
                        &format!("UDP socket reported an asynchronous transport error: {e}"),
                    )?;
                    ctx.wait(Duration::from_millis(10));
                    continue;
                }
                return Err(e.into());
            }
            let mut idx = 0;
            let mut destination = Ipv4Addr::UNSPECIFIED;
            unsafe {
                let mut c = libc::CMSG_FIRSTHDR(&msg);
                while !c.is_null() {
                    if (*c).cmsg_level == libc::IPPROTO_IP
                        && (*c).cmsg_type == libc::IP_PKTINFO
                        && (*c).cmsg_len
                            >= libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as _) as _
                    {
                        let info =
                            std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::in_pktinfo);
                        idx = info.ipi_ifindex as u32;
                        destination = Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes());
                    }
                    c = libc::CMSG_NXTHDR(&msg, c);
                }
            }
            let packet = &buffer[..n as usize];
            let source = l::from_sockaddr(&src)?;
            let ingress = bindings.get(&idx).map(|binding| binding.0.as_str());
            if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                telemetry.record_detail(
                    ingress,
                    Action::Rejected,
                    "truncated_datagram",
                    &[],
                    Some(source),
                    "Receive buffer or ancillary metadata was truncated",
                )?;
                continue;
            }
            let IpAddr::V4(source_ip) = source.ip() else {
                telemetry.record(
                    ingress,
                    Action::Rejected,
                    "non_ipv4_source",
                    &[],
                    Some(source),
                )?;
                continue;
            };
            if packet.len() < FIXED {
                telemetry.record(
                    ingress,
                    Action::Rejected,
                    "short_packet",
                    packet,
                    Some(source),
                )?;
                continue;
            }
            if packet[0] == 1 {
                telemetry.record(ingress, Action::Request, "", packet, Some(source))?;
                let Some((name, relay, servers, prefixes)) = bindings.get(&idx) else {
                    telemetry.record(
                        None,
                        Action::Rejected,
                        "unmanaged_ingress",
                        packet,
                        Some(source),
                    )?;
                    continue;
                };
                if source.port() != 68
                    || !(destination == Ipv4Addr::BROADCAST || destination == *relay)
                {
                    telemetry.record_detail(
                        Some(name),
                        Action::Rejected,
                        "invalid_client_endpoint",
                        packet,
                        Some(source),
                        &format!("Requests require UDP/68 and broadcast or relay destination {relay}; received destination {destination}"),
                    )?;
                    continue;
                }
                if !valid_client_address(source_ip, ip(packet, 12), prefixes, *relay) {
                    telemetry.record_detail(
                        Some(name),
                        Action::Rejected,
                        "invalid_client_address",
                        packet,
                        Some(source),
                        "Nonzero ciaddr must be on-link unicast, not network/broadcast/relay; a nonzero source must match ciaddr",
                    )?;
                    continue;
                }
                let wire = match request(packet, *relay) {
                    Ok(wire) => wire,
                    Err(error) => {
                        telemetry.record_detail(
                            Some(name),
                            Action::Rejected,
                            "invalid_client_packet",
                            packet,
                            Some(source),
                            &format!("{error:#}"),
                        )?;
                        continue;
                    }
                };
                let (live, addresses) = l::interface_snapshot(name)?;
                ensure!(
                    live == idx && addresses.contains(&IpAddr::V4(*relay)),
                    "relay interface changed"
                );
                let transaction_key = (*relay, key(packet));
                if transactions.len() >= 65536 && !transactions.contains_key(&transaction_key) {
                    telemetry.record(
                        Some(name),
                        Action::Rejected,
                        "transaction_capacity",
                        packet,
                        Some(source),
                    )?;
                    continue;
                }
                let previous = transactions.insert(
                    transaction_key,
                    Transaction {
                        index: idx,
                        since: Instant::now(),
                        metadata: metadata(&wire).ok_or_else(|| {
                            anyhow::anyhow!("missing valid DHCP request metadata")
                        })?,
                    },
                );
                if let Some(previous) = previous {
                    let previous_name = &bindings
                        .get(&previous.index)
                        .ok_or_else(|| anyhow::anyhow!("missing previous DHCP relay binding"))?
                        .0;
                    telemetry.track(previous_name, false)?;
                }
                telemetry.track(name, true)?;
                for server in servers {
                    if ctx.stopping() {
                        break;
                    }
                    let peer = SocketAddr::from((*server, 67));
                    if let Err(error) = send_info(fd.as_raw_fd(), &wire, *server, 67, 0, *relay) {
                        telemetry.record_detail(
                            Some(name),
                            Action::SendError,
                            "to_server",
                            &wire,
                            Some(peer),
                            &format!("{error:#}"),
                        )?;
                        continue;
                    }
                    telemetry.record(Some(name), Action::ToServer, "", &wire, Some(peer))?;
                }
            } else if packet[0] == 2 {
                let Some(transaction) = transactions.get(&(ip(packet, 24), key(packet))) else {
                    telemetry.record(None, Action::Reply, "", packet, Some(source))?;
                    telemetry.record_detail(
                        None,
                        Action::Rejected,
                        "unmatched_reply",
                        packet,
                        Some(source),
                        "No tracked request matches this giaddr, transaction ID and client MAC",
                    )?;
                    continue;
                };
                let down = transaction.index;
                let client = transaction.metadata.client_address;
                let Some((name, relay, servers, prefixes)) = bindings.get(&down) else {
                    telemetry.record(
                        None,
                        Action::Rejected,
                        "missing_binding",
                        packet,
                        Some(source),
                    )?;
                    continue;
                };
                telemetry.record(Some(name), Action::Reply, "", packet, Some(source))?;
                if source.port() != 67 || !servers.contains(&source_ip) || destination != *relay {
                    telemetry.record_detail(
                        Some(name),
                        Action::Rejected,
                        "invalid_server_endpoint",
                        packet,
                        Some(source),
                        &format!("Reply requires a configured UDP/67 server and destination {relay}; received destination {destination}"),
                    )?;
                    continue;
                }
                let (target, broadcast) = match response(packet, *relay) {
                    Ok(route) => route,
                    Err(error) => {
                        telemetry.record_detail(
                            Some(name),
                            Action::Rejected,
                            "invalid_server_packet",
                            packet,
                            Some(source),
                            &format!("{error:#}"),
                        )?;
                        continue;
                    }
                };
                if let Err(error) = reply_matches(packet, client, transaction.metadata.broadcast) {
                    telemetry.record_detail(
                        Some(name),
                        Action::Rejected,
                        "invalid_server_endpoint",
                        packet,
                        Some(source),
                        &format!("{error:#}"),
                    )?;
                    continue;
                }
                if !broadcast && !on_link(prefixes, target, *relay) {
                    telemetry.record(
                        Some(name),
                        Action::Rejected,
                        "off_link_target",
                        packet,
                        Some(source),
                    )?;
                    continue;
                }
                let (live, addresses) = l::interface_snapshot(name)?;
                ensure!(
                    live == down && addresses.contains(&IpAddr::V4(*relay)),
                    "relay interface changed"
                );
                if !broadcast && client.is_unspecified() {
                    let wire = unicast_wire(packet, *relay, target)?;
                    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
                    addr.sll_family = libc::AF_PACKET as u16;
                    addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
                    addr.sll_ifindex = down as i32;
                    addr.sll_halen = 6;
                    addr.sll_addr[..6].copy_from_slice(&packet[28..34]);
                    let sent = unsafe {
                        libc::sendto(
                            packet_fd.as_raw_fd(),
                            wire.as_ptr() as *const _,
                            wire.len(),
                            libc::MSG_NOSIGNAL,
                            &addr as *const _ as *const _,
                            mem::size_of_val(&addr) as _,
                        )
                    };
                    if sent != wire.len() as isize {
                        let error = if sent < 0 {
                            anyhow::Error::from(std::io::Error::last_os_error())
                        } else {
                            anyhow::anyhow!(
                                "short DHCP layer2 send: {sent} of {} bytes",
                                wire.len()
                            )
                        };
                        telemetry.record_detail(
                            Some(name),
                            Action::SendError,
                            "to_client_layer2",
                            packet,
                            Some(SocketAddr::from((target, 68))),
                            &format!("{error:#}"),
                        )?;
                        continue;
                    }
                } else {
                    if let Err(error) = send_info(fd.as_raw_fd(), packet, target, 68, down, *relay)
                    {
                        telemetry.record_detail(
                            Some(name),
                            Action::SendError,
                            "to_client",
                            packet,
                            Some(SocketAddr::from((target, 68))),
                            &format!("{error:#}"),
                        )?;
                        continue;
                    }
                }
                telemetry.record(
                    Some(name),
                    Action::ToClient,
                    "",
                    packet,
                    Some(SocketAddr::from((target, 68))),
                )?;
            } else {
                telemetry.record(
                    ingress,
                    Action::Rejected,
                    "invalid_op",
                    packet,
                    Some(source),
                )?;
            }
            #[cfg(target_os = "linux")]
            fn send_info(
                fd: std::os::fd::RawFd,
                packet: &[u8],
                target: Ipv4Addr,
                port: u16,
                index: u32,
                source: Ipv4Addr,
            ) -> Result<()> {
                use std::{mem, net::SocketAddr};
                let (dest, len) = super::linux::sockaddr(SocketAddr::from((target, port)), 0);
                let mut iov = libc::iovec {
                    iov_base: packet.as_ptr() as *mut _,
                    iov_len: packet.len(),
                };
                let mut out: libc::msghdr = unsafe { mem::zeroed() };
                let mut ancillary = [0usize; 16];
                out.msg_name = &dest as *const _ as *mut _;
                out.msg_namelen = len;
                out.msg_iov = &mut iov;
                out.msg_iovlen = 1;
                out.msg_control = ancillary.as_mut_ptr() as *mut _;
                out.msg_controllen =
                    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as _) } as _;
                unsafe {
                    let c = libc::CMSG_FIRSTHDR(&out);
                    (*c).cmsg_level = libc::IPPROTO_IP;
                    (*c).cmsg_type = libc::IP_PKTINFO;
                    (*c).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as _) as _;
                    let info = libc::in_pktinfo {
                        ipi_ifindex: index as i32,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(source.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut libc::in_pktinfo, info);
                }
                let sent = unsafe { libc::sendmsg(fd, &out, libc::MSG_NOSIGNAL) };
                if sent < 0 {
                    return Err(anyhow::anyhow!(
                        "DHCP send: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                ensure!(
                    sent == packet.len() as isize,
                    "short DHCP send: {sent} of {} bytes",
                    packet.len()
                );
                Ok(())
            }
        }
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut p = vec![0; 244];
        p[0] = 1;
        p[1] = 1;
        p[2] = 6;
        p[28] = 2;
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        p[240..].copy_from_slice(&[53, 1, 1, 255]);
        p
    }
    #[test]
    fn relay_request_hops_cookie_options() {
        let p = packet();
        let fields = metadata(&p).unwrap();
        assert_eq!(fields.message_type, 1);
        assert_eq!(fields.transaction_id, "00000000");
        assert_eq!(fields.client_mac, "02:00:00:00:00:00");
        assert!(metadata(&p[..200]).is_none());
        let r = request(&p, "192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(r[3], 1);
        assert_eq!(&r[24..28], &[192, 0, 2, 1]);
        let mut bad = p.clone();
        bad[3] = 16;
        assert!(request(&bad, Ipv4Addr::LOCALHOST).is_err());
        bad = p.clone();
        bad[237] = 0;
        assert!(request(&bad, Ipv4Addr::LOCALHOST).is_err());
        bad = p.clone();
        bad[241] = 30;
        assert!(request(&bad, Ipv4Addr::LOCALHOST).is_err());
    }
    #[test]
    fn reply_route_and_giaddr() {
        let a = "192.0.2.1".parse().unwrap();
        let mut p = request(&packet(), a).unwrap();
        p[0] = 2;
        p[242] = 2;
        p[16..20].copy_from_slice(&[192, 0, 2, 20]);
        assert_eq!(
            response(&p, a).unwrap(),
            ("192.0.2.20".parse().unwrap(), false)
        );
        p[12..16].copy_from_slice(&[192, 0, 2, 5]);
        assert_eq!(
            response(&p, a).unwrap().0,
            "192.0.2.5".parse::<Ipv4Addr>().unwrap()
        );
        assert!(response(&p, "192.0.2.2".parse().unwrap()).is_err());
    }
    #[test]
    fn zero_source_requests_preserve_on_link_client_address_and_ack_target() {
        let relay: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let client: Ipv4Addr = "192.0.2.20".parse().unwrap();
        let prefixes = vec!["192.0.2.1/24".into()];
        for broadcast in [false, true] {
            let mut original = packet();
            original[242] = 3;
            original[12..16].copy_from_slice(&client.octets());
            original[10] = if broadcast { 0x80 } else { 0 };
            assert!(valid_client_address(
                Ipv4Addr::UNSPECIFIED,
                client,
                &prefixes,
                relay
            ));
            let forwarded = request(&original, relay).unwrap();
            let mut expected = original.clone();
            expected[3] = 1;
            expected[24..28].copy_from_slice(&relay.octets());
            assert_eq!(forwarded, expected);
            assert_eq!(key(&forwarded), key(&original));
            let mut ack = forwarded;
            ack[0] = 2;
            ack[3] = 0;
            ack[242] = 5;
            ack[16..20].copy_from_slice(&client.octets());
            assert_eq!(response(&ack, relay).unwrap(), (client, false));
        }
    }
    #[test]
    fn client_address_admission_retains_subnet_and_source_checks() {
        let relay = "192.0.2.1".parse().unwrap();
        let client = "192.0.2.20".parse().unwrap();
        let prefixes = vec!["192.0.2.1/24".into()];
        assert!(valid_client_address(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &prefixes,
            relay
        ));
        assert!(valid_client_address(client, client, &prefixes, relay));
        assert!(!valid_client_address(
            client,
            Ipv4Addr::UNSPECIFIED,
            &prefixes,
            relay
        ));
        assert!(!valid_client_address(
            "192.0.2.21".parse().unwrap(),
            client,
            &prefixes,
            relay
        ));
        for invalid in [
            "198.51.100.20",
            "192.0.2.0",
            "192.0.2.255",
            "192.0.2.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.1",
        ] {
            let invalid = invalid.parse().unwrap();
            for source in [Ipv4Addr::UNSPECIFIED, invalid] {
                assert!(!valid_client_address(source, invalid, &prefixes, relay));
            }
        }
    }
    #[test]
    fn server_replies_do_not_require_request_hops_to_be_echoed() {
        let relay = "10.4.20.1".parse().unwrap();
        let mut discover = packet();
        discover[4..8].copy_from_slice(&0x031f90b5u32.to_be_bytes());
        discover[10] = 0x80;
        discover[28..34].copy_from_slice(&[0x02, 0x00, 0x0a, 0x04, 0x14, 0x2e]);
        let forwarded = request(&discover, relay).unwrap();
        assert_eq!(forwarded[3], 1);
        for kind in [2, 5, 6] {
            for hops in [0, 1, 16, 255] {
                let mut reply = forwarded.clone();
                reply[0] = 2;
                reply[3] = hops;
                reply[242] = kind;
                if kind != 6 {
                    reply[16..20].copy_from_slice(&[10, 4, 20, 46]);
                }
                assert_eq!(key(&reply), key(&discover));
                assert_eq!(
                    response(&reply, relay).unwrap(),
                    (Ipv4Addr::BROADCAST, true),
                    "message type {kind}, hops {hops}"
                );
                reply[10] = 0;
                if kind != 6 {
                    assert_eq!(
                        response(&reply, relay).unwrap(),
                        ("10.4.20.46".parse().unwrap(), false)
                    );
                }
                reply[24..28].copy_from_slice(&[10, 4, 50, 1]);
                assert!(response(&reply, relay).is_err());
                reply[24..28].copy_from_slice(&relay.octets());
                reply[0] = 1;
                assert!(response(&reply, relay).is_err());
            }
        }
        let mut chained = discover;
        chained[3] = 1;
        assert!(request(&chained, relay).is_err());
    }
    #[test]
    fn layer2_unicast_ip_udp_checksum_and_subnet() {
        let source = "192.0.2.1".parse().unwrap();
        let target = "192.0.2.20".parse().unwrap();
        let p = packet();
        let wire = unicast_wire(&p, source, target).unwrap();
        assert_eq!(super::super::gateway::checksum(&wire[..20]), 0);
        assert_eq!(&wire[20..24], &[0, 67, 0, 68]);
        assert_eq!(&wire[28..], &p);
        let mut pseudo = vec![192, 0, 2, 1, 192, 0, 2, 20, 0, 17];
        pseudo.extend_from_slice(&((p.len() + 8) as u16).to_be_bytes());
        pseudo.extend_from_slice(&wire[20..]);
        assert_eq!(super::super::gateway::checksum(&pseudo), 0);
        let prefixes = vec!["192.0.2.1/24".into()];
        assert!(on_link(&prefixes, target, source));
        assert!(!on_link(&prefixes, "192.0.2.255".parse().unwrap(), source));
        assert!(!on_link(&prefixes, "192.0.2.0".parse().unwrap(), source));
        assert!(!on_link(&prefixes, "198.51.100.1".parse().unwrap(), source));
    }
    #[test]
    fn malformed_protocol_inputs_do_not_panic() {
        for length in 0..512 {
            let data: Vec<_> = (0..length).map(|_| rand::random()).collect();
            let _ = request(&data, Ipv4Addr::LOCALHOST);
            let _ = response(&data, Ipv4Addr::LOCALHOST);
        }
        let p = packet();
        for length in 0..p.len() {
            assert!(request(&p[..length], Ipv4Addr::LOCALHOST).is_err());
        }
        let mut p = packet();
        p[28] = 3;
        assert!(request(&p, Ipv4Addr::LOCALHOST).is_err());
    }
    #[test]
    fn broadcast_and_nak_override_unicast() {
        let relay = "192.0.2.1".parse().unwrap();
        let mut p = request(&packet(), relay).unwrap();
        p[0] = 2;
        p[242] = 2;
        p[16..20].copy_from_slice(&[192, 0, 2, 20]);
        p[10] = 0x80;
        assert_eq!(response(&p, relay).unwrap(), (Ipv4Addr::BROADCAST, true));
        p[10] = 0;
        p[242] = 6;
        p[12..16].copy_from_slice(&[192, 0, 2, 30]);
        assert!(response(&p, relay).is_err());
        p[12..20].fill(0);
        assert_eq!(response(&p, relay).unwrap(), (Ipv4Addr::BROADCAST, true));
    }
    #[test]
    fn nak_correlation_allows_server_broadcast_and_zero_client_address() {
        let relay = "192.0.2.1".parse().unwrap();
        let client = "192.0.2.20".parse().unwrap();
        let mut reply = request(&packet(), relay).unwrap();
        reply[0] = 2;
        reply[242] = 6;
        reply[10] = 0x80;
        for requested_client in [Ipv4Addr::UNSPECIFIED, client] {
            for requested_broadcast in [false, true] {
                assert_eq!(
                    response(&reply, relay).unwrap(),
                    (Ipv4Addr::BROADCAST, true)
                );
                assert!(reply_matches(&reply, requested_client, requested_broadcast).is_ok());
            }
        }
        reply[242] = 5;
        reply[12..16].copy_from_slice(&client.octets());
        reply[16..20].copy_from_slice(&client.octets());
        assert!(reply_matches(&reply, client, true).is_ok());
        assert!(reply_matches(&reply, client, false).is_err());
        assert!(reply_matches(&reply, "192.0.2.21".parse().unwrap(), true).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn asynchronous_transport_errors_do_not_mask_broken_sockets() {
        for code in [
            libc::ECONNREFUSED,
            libc::EHOSTUNREACH,
            libc::ENETUNREACH,
            libc::ENETDOWN,
            libc::EHOSTDOWN,
            libc::ENOBUFS,
            libc::EMSGSIZE,
        ] {
            assert!(recoverable_socket_error(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
        for code in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EFAULT] {
            assert!(!recoverable_socket_error(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
    }
}
