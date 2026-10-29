use anyhow::{Result, ensure};
use netcontrol_core::{UDPRelayInstance, UDPRelaySource};
use std::net::{Ipv4Addr, SocketAddrV4};

fn destination(
    instance: &UDPRelayInstance,
    received: Ipv4Addr,
    incoming_broadcast: Ipv4Addr,
    outgoing_broadcast: Ipv4Addr,
) -> Option<Ipv4Addr> {
    if received == Ipv4Addr::BROADCAST || received == incoming_broadcast {
        Some(outgoing_broadcast)
    } else {
        instance
            .multicast_address
            .filter(|group| *group == received)
    }
}

fn packet(
    instance: &UDPRelayInstance,
    source: SocketAddrV4,
    interface_address: Ipv4Addr,
    destination: Ipv4Addr,
    ttl: u8,
    tos: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= 65507 && ttl > 0,
        "invalid UDP relay datagram size or TTL"
    );
    let address = match instance.source {
        UDPRelaySource::Original => *source.ip(),
        _ => interface_address,
    };
    let port = if instance.source == UDPRelaySource::InterfaceAddressAndPort {
        instance.port
    } else {
        source.port()
    };
    let mut output = vec![0u8; payload.len() + 28];
    output[0] = 0x45;
    output[1] = (instance.id << 2) | (tos & 3);
    output[2..4].copy_from_slice(&((payload.len() + 28) as u16).to_be_bytes());
    output[8] = ttl;
    output[9] = 17;
    output[12..16].copy_from_slice(&address.octets());
    output[16..20].copy_from_slice(&destination.octets());
    let checksum = crate::gateway::checksum(&output[..20]);
    output[10..12].copy_from_slice(&checksum.to_be_bytes());
    output[20..22].copy_from_slice(&port.to_be_bytes());
    output[22..24].copy_from_slice(&instance.port.to_be_bytes());
    output[24..26].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    output[28..].copy_from_slice(payload);
    Ok(output)
}

#[cfg(target_os = "linux")]
pub(crate) use native::prepare;

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use crate::{
        linux as socket,
        worker::{ContextState, now},
    };
    use anyhow::Context;
    use serde_json::json;
    use std::{
        ffi::CStr,
        io, mem,
        net::{IpAddr, SocketAddr},
        os::fd::{AsRawFd, OwnedFd},
        time::{Duration, Instant},
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Link {
        name: String,
        index: u32,
        address: Ipv4Addr,
        broadcast: Ipv4Addr,
    }

    fn link(name: &str) -> Result<Link> {
        let index = socket::ifindex(name)?;
        let mut first = std::ptr::null_mut();
        socket::check(unsafe { libc::getifaddrs(&mut first) })?;
        struct Guard(*mut libc::ifaddrs);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe { libc::freeifaddrs(self.0) }
            }
        }
        let _guard = Guard(first);
        let mut current = first;
        let mut addresses = Vec::new();
        while !current.is_null() {
            let entry = unsafe { &*current };
            if !entry.ifa_name.is_null()
                && unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() == name.as_bytes()
            {
                let required = (libc::IFF_UP | libc::IFF_BROADCAST) as u32;
                ensure!(
                    entry.ifa_flags & required == required
                        && entry.ifa_flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) as u32
                            == 0,
                    "UDP relay interface {name} must be up and broadcast capable"
                );
                if !entry.ifa_addr.is_null()
                    && unsafe { (*entry.ifa_addr).sa_family } as i32 == libc::AF_INET
                    && !entry.ifa_netmask.is_null()
                    && !entry.ifa_ifu.is_null()
                {
                    let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                    let broadcast = unsafe { &*(entry.ifa_ifu as *const libc::sockaddr_in) };
                    let mask = unsafe { &*(entry.ifa_netmask as *const libc::sockaddr_in) };
                    let address = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
                    let broadcast = Ipv4Addr::from(broadcast.sin_addr.s_addr.to_ne_bytes());
                    if u32::from_be(mask.sin_addr.s_addr).count_ones() <= 30
                        && crate::config::unicast(IpAddr::V4(address), false)
                    {
                        addresses.push((address, broadcast));
                    }
                }
            }
            current = entry.ifa_next;
        }
        addresses.sort();
        let (address, broadcast) = addresses
            .first()
            .copied()
            .context("UDP relay interface has no usable IPv4 address")?;
        Ok(Link {
            name: name.into(),
            index,
            address,
            broadcast,
        })
    }

    struct Datagram {
        length: usize,
        source: SocketAddrV4,
        destination: Ipv4Addr,
        index: u32,
        ttl: u8,
        tos: u8,
    }

    fn receive(descriptor: &OwnedFd, buffer: &mut [u8]) -> Result<Option<Datagram>> {
        let mut address: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut control = [0usize; 64];
        let mut vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
        message.msg_namelen = mem::size_of_val(&address) as libc::socklen_t;
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = mem::size_of_val(&control);
        let length =
            unsafe { libc::recvmsg(descriptor.as_raw_fd(), &mut message, libc::MSG_TRUNC) };
        if length < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(None);
            }
            return Err(error.into());
        }
        ensure!(
            message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && length as usize <= buffer.len(),
            "truncated UDP relay datagram"
        );
        ensure!(
            address.sin_family as i32 == libc::AF_INET,
            "invalid UDP relay sender family"
        );
        let mut info = None;
        let mut ttl = None;
        let mut tos = None;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::IPPROTO_IP {
                    let size = (*header)
                        .cmsg_len
                        .saturating_sub(libc::CMSG_LEN(0) as usize);
                    match (*header).cmsg_type {
                        libc::IP_PKTINFO if size >= mem::size_of::<libc::in_pktinfo>() => {
                            info = Some(std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(),
                            ));
                        }
                        libc::IP_TTL if size >= mem::size_of::<i32>() => {
                            ttl = u8::try_from(std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<i32>(),
                            ))
                            .ok();
                        }
                        libc::IP_TOS if size >= 1 => {
                            tos = Some(*libc::CMSG_DATA(header));
                        }
                        _ => {}
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        let info = info.context("UDP relay ingress metadata missing")?;
        Ok(Some(Datagram {
            length: length as usize,
            source: SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            ),
            destination: Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()),
            index: u32::try_from(info.ipi_ifindex)?,
            ttl: ttl.context("UDP relay TTL missing")?,
            tos: tos.context("UDP relay DSCP missing")?,
        }))
    }

    pub(crate) fn prepare(
        instance: UDPRelayInstance,
    ) -> Result<Box<dyn FnOnce(ContextState) -> Result<()> + Send>> {
        socket::capabilities(13)?;
        let links = instance
            .interfaces
            .iter()
            .map(|name| link(name))
            .collect::<Result<Vec<_>>>()?;
        ensure!(links.len() >= 2, "UDP relay requires two interfaces");
        let receiver = socket::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
        for option in [libc::IP_PKTINFO, libc::IP_RECVTTL, libc::IP_RECVTOS] {
            socket::option(receiver.as_raw_fd(), libc::IPPROTO_IP, option, &1i32)?;
        }
        socket::option(
            receiver.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &1i32,
        )?;
        socket::option(
            receiver.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &(1 << 20),
        )?;
        socket::option(
            receiver.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_ALL,
            &0i32,
        )?;
        socket::bind(
            receiver.as_raw_fd(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), instance.port),
            0,
        )
        .context("bind UDP relay port (another service may own it)")?;
        let mut senders = Vec::new();
        for interface in &links {
            if let Some(group) = instance.multicast_address {
                let membership = libc::ip_mreqn {
                    imr_multiaddr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(group.octets()),
                    },
                    imr_address: libc::in_addr {
                        s_addr: u32::from_ne_bytes(interface.address.octets()),
                    },
                    imr_ifindex: interface.index as i32,
                };
                socket::option(
                    receiver.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_ADD_MEMBERSHIP,
                    &membership,
                )?;
            }
            let sender = socket::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)?;
            socket::bind_device(sender.as_raw_fd(), &interface.name)?;
            socket::option(
                sender.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &1i32,
            )?;
            socket::option(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                &1i32,
            )?;
            socket::option(
                sender.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_LOOP,
                &0i32,
            )?;
            senders.push(sender);
        }
        Ok(Box::new(move |context| {
            run(instance, links, receiver, senders, context)
        }))
    }

    fn run(
        instance: UDPRelayInstance,
        links: Vec<Link>,
        receiver: OwnedFd,
        senders: Vec<OwnedFd>,
        context: ContextState,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 65507];
        let mut counts = [0u64; 8];
        let mut tokens = 400.0f64;
        let mut refill = Instant::now();
        let mut checked = Instant::now();
        while !context.stopping() {
            if checked.elapsed() >= Duration::from_millis(100) {
                for interface in &links {
                    ensure!(
                        link(&interface.name)? == *interface,
                        "UDP relay interface identity/address changed; reopening sockets"
                    );
                }
                checked = Instant::now();
            }
            let mut ready = libc::pollfd {
                fd: receiver.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut ready, 1, 100) };
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            socket::check(result)?;
            ensure!(
                ready.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                "UDP relay receive socket failed"
            );
            for _ in 0..64 {
                if context.stopping() {
                    break;
                }
                let datagram = match receive(&receiver, &mut buffer) {
                    Ok(Some(datagram)) => datagram,
                    Ok(None) => break,
                    Err(error) => return Err(error),
                };
                counts[0] = counts[0].saturating_add(1);
                counts[2] = counts[2].saturating_add(datagram.length as u64);
                let incoming = links
                    .iter()
                    .position(|interface| interface.index == datagram.index);
                let Some(incoming) = incoming else {
                    counts[4] = counts[4].saturating_add(1);
                    continue;
                };
                if datagram.tos >> 2 == instance.id {
                    counts[5] = counts[5].saturating_add(1);
                    continue;
                }
                if !crate::config::unicast(IpAddr::V4(*datagram.source.ip()), false)
                    || datagram.source.port() == 0
                    || datagram.ttl == 0
                    || destination(
                        &instance,
                        datagram.destination,
                        links[incoming].broadcast,
                        links[incoming].broadcast,
                    )
                    .is_none()
                {
                    counts[4] = counts[4].saturating_add(1);
                    continue;
                }
                tokens = (tokens + refill.elapsed().as_secs_f64() * 200.0).min(400.0);
                refill = Instant::now();
                if tokens < 1.0 {
                    counts[6] = counts[6].saturating_add(1);
                    continue;
                }
                tokens -= 1.0;
                for (outgoing, interface) in links
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != incoming)
                {
                    ensure!(
                        socket::ifindex(&interface.name)? == interface.index,
                        "UDP relay interface identity changed"
                    );
                    let target = destination(
                        &instance,
                        datagram.destination,
                        links[incoming].broadcast,
                        interface.broadcast,
                    )
                    .unwrap();
                    let output = packet(
                        &instance,
                        datagram.source,
                        interface.address,
                        target,
                        datagram.ttl,
                        datagram.tos,
                        &buffer[..datagram.length],
                    )?;
                    match socket::send(
                        senders[outgoing].as_raw_fd(),
                        &output,
                        SocketAddr::new(IpAddr::V4(target), instance.port),
                        0,
                    ) {
                        Ok(()) => {
                            counts[1] = counts[1].saturating_add(1);
                            counts[3] = counts[3].saturating_add(datagram.length as u64);
                        }
                        Err(error) => {
                            counts[7] = counts[7].saturating_add(1);
                            context.update(|status| {
                                status["last_send_error"] =
                                    json!(format!("{}: {error:#}", interface.name));
                                status["last_send_error_at"] = json!(now());
                            });
                        }
                    }
                }
            }
            context.update(|status| {
                for (key, count) in [
                    "received_packets",
                    "transmitted_packets",
                    "received_bytes",
                    "transmitted_bytes",
                    "policy_drops",
                    "loop_drops",
                    "rate_limit_drops",
                    "send_errors",
                ]
                .into_iter()
                .zip(counts)
                {
                    status[key] = json!(count.to_string());
                }
                status["collected_at"] = json!(now());
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn udp_relay_packet_policy_and_source_modes() {
        let mut instance: UDPRelayInstance = serde_json::from_value(json!({"id":7,"enabled":true,"port":4001,"interfaces":["lan0","iot0"],"multicast_address":"239.255.255.250"})).unwrap();
        let incoming = Ipv4Addr::new(192, 0, 2, 255);
        let outgoing = Ipv4Addr::new(198, 51, 100, 255);
        let interface = Ipv4Addr::new(198, 51, 100, 1);
        let group = instance.multicast_address.unwrap();
        for broadcast in [incoming, Ipv4Addr::BROADCAST] {
            assert_eq!(
                destination(&instance, broadcast, incoming, outgoing),
                Some(outgoing)
            );
        }
        assert_eq!(
            destination(&instance, group, incoming, outgoing),
            Some(group)
        );
        assert_eq!(destination(&instance, interface, incoming, outgoing), None);
        assert_eq!(
            destination(&instance, Ipv4Addr::new(224, 0, 23, 0), incoming, outgoing),
            None
        );
        let source = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 4002);
        let payload = br#"{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}"#;
        for mode in [
            UDPRelaySource::Original,
            UDPRelaySource::InterfaceAddress,
            UDPRelaySource::InterfaceAddressAndPort,
        ] {
            instance.source = mode;
            let output = packet(&instance, source, interface, group, 1, 3, payload).unwrap();
            assert_eq!(output[1], 31);
            assert_eq!(output[8], 1);
            assert_eq!(crate::gateway::checksum(&output[..20]), 0);
            assert_eq!(
                &output[12..16],
                &if mode == UDPRelaySource::Original {
                    source.ip().octets()
                } else {
                    interface.octets()
                }
            );
            assert_eq!(
                u16::from_be_bytes(output[20..22].try_into().unwrap()),
                if mode == UDPRelaySource::InterfaceAddressAndPort {
                    4001
                } else {
                    4002
                }
            );
            assert_eq!(&output[28..], payload);
        }
        assert!(packet(&instance, source, interface, group, 1, 0, &vec![0; 65508]).is_err());
        assert!(packet(&instance, source, interface, group, 0, 0, &[]).is_err());
    }
}
