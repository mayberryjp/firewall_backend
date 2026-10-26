use super::*;
use crate::{
    linux as socket,
    worker::{ContextState, now},
};
use anyhow::Context;
use netcontrol_core::MDNSConfig;
use serde_json::json;
use std::{
    collections::{BTreeMap, VecDeque},
    hash::{Hash, Hasher},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::{
        fd::{AsRawFd, OwnedFd},
        linux::net::SocketAddrExt,
        unix::net::UnixDatagram,
    },
    thread,
};

const V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
type Run = Box<dyn FnOnce(ContextState) -> Result<()> + Send>;
type LinkWatch = std::sync::Arc<std::sync::Mutex<LinkMonitor>>;

#[derive(Debug, PartialEq)]
enum LinkEvent {
    New {
        index: u32,
        flags: u32,
        name: Option<Vec<u8>>,
    },
    Delete {
        index: u32,
        name: Option<Vec<u8>>,
    },
    Address {
        index: u32,
        deleted: bool,
    },
}
fn notification_attributes(bytes: &[u8], interface_names: bool) -> Result<Option<Vec<u8>>> {
    let mut at = 0;
    let mut name = None;
    while at < bytes.len() {
        ensure!(bytes.len() - at >= 4, "short route notification attribute");
        let length = u16::from_ne_bytes(bytes[at..at + 2].try_into()?) as usize;
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into()?) & 0x3fff;
        ensure!(
            length >= 4 && at + length <= bytes.len(),
            "invalid route notification attribute length"
        );
        if kind == 3 && interface_names {
            let value = &bytes[at + 4..at + length];
            ensure!(
                !value.is_empty()
                    && value.len() <= 16
                    && value.last() == Some(&0)
                    && !value[..value.len() - 1].contains(&0),
                "invalid route notification interface name"
            );
            name = Some(value[..value.len() - 1].to_vec());
        }
        let next = at + ((length + 3) & !3);
        ensure!(
            next <= bytes.len(),
            "truncated route notification attribute padding"
        );
        at = next;
    }
    Ok(name)
}
fn notification_events(bytes: &[u8], flags: i32, sender: u32) -> Result<Vec<LinkEvent>> {
    ensure!(
        sender == 0,
        "route notification did not originate from the kernel"
    );
    ensure!(
        flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0,
        "route notifications truncated; interface identity history lost"
    );
    ensure!(!bytes.is_empty(), "empty route notification");
    let mut events = Vec::new();
    let mut at = 0;
    let mut messages = 0;
    while at < bytes.len() {
        ensure!(bytes.len() - at >= 16, "short route notification header");
        let length = u32::from_ne_bytes(bytes[at..at + 4].try_into()?) as usize;
        let kind = u16::from_ne_bytes(bytes[at + 4..at + 6].try_into()?);
        let message_flags = u16::from_ne_bytes(bytes[at + 6..at + 8].try_into()?);
        ensure!(
            length >= 16 && at + length <= bytes.len(),
            "invalid route notification length"
        );
        ensure!(
            message_flags & 0x10 == 0,
            "interrupted route notifications; interface identity history lost"
        );
        messages += 1;
        ensure!(
            messages <= 512,
            "route notification message batch exceeded safety bound"
        );
        let body = &bytes[at + 16..at + length];
        match kind {
            1 | 3 => {}
            2 => {
                ensure!(body.len() >= 4, "short route notification error");
                ensure!(
                    i32::from_ne_bytes(body[..4].try_into()?) == 0,
                    "route notification kernel error; interface identity history lost"
                );
            }
            4 => bail!("route notification overrun; interface identity history lost"),
            16 | 17 => {
                ensure!(body.len() >= 16, "short route link notification");
                let index = i32::from_ne_bytes(body[4..8].try_into()?);
                ensure!(index > 0, "invalid route notification interface index");
                let name = notification_attributes(&body[16..], true)?;
                if kind == 17 {
                    events.push(LinkEvent::Delete {
                        index: index as u32,
                        name,
                    });
                } else {
                    events.push(LinkEvent::New {
                        index: index as u32,
                        flags: u32::from_ne_bytes(body[8..12].try_into()?),
                        name,
                    });
                }
            }
            20 | 21 => {
                ensure!(body.len() >= 8, "short route address notification");
                let index = u32::from_ne_bytes(body[4..8].try_into()?);
                ensure!(index > 0, "invalid route address interface index");
                notification_attributes(&body[8..], false)?;
                events.push(LinkEvent::Address {
                    index,
                    deleted: kind == 21,
                });
            }
            _ => {}
        }
        at += (length + 3) & !3;
        ensure!(at <= bytes.len(), "truncated route notification padding");
    }
    Ok(events)
}
#[derive(Default)]
struct LinkHistory {
    wanted: std::collections::BTreeSet<String>,
    required: BTreeMap<u32, String>,
    deleted: std::collections::BTreeSet<u32>,
    dirty: std::collections::BTreeSet<u32>,
    revisions: BTreeMap<u32, u64>,
    membership_revisions: BTreeMap<u32, u64>,
    error: Option<String>,
}
impl LinkHistory {
    fn check(&self) -> Result<()> {
        ensure!(
            self.error.is_none(),
            "{}",
            self.error
                .as_deref()
                .unwrap_or("route notification failure")
        );
        Ok(())
    }
    fn fail<T>(&mut self, error: impl std::fmt::Display) -> Result<T> {
        let text = self
            .error
            .get_or_insert_with(|| format!("mDNS interface monitor failed: {error}"))
            .clone();
        bail!("{text}")
    }
    fn ingest(&mut self, bytes: &[u8], flags: i32, sender: u32) -> Result<()> {
        self.check()?;
        let events = match notification_events(bytes, flags, sender) {
            Ok(events) => events,
            Err(error) => return self.fail(error),
        };
        for event in events {
            match event {
                LinkEvent::Delete { index, name } => {
                    if self.deleted.len() >= 8192 && !self.deleted.contains(&index) {
                        return self.fail("route deletion history exceeded safety bound");
                    }
                    self.deleted.insert(index);
                    if self.required.contains_key(&index)
                        || name.as_ref().is_some_and(|name| {
                            self.wanted.iter().any(|wanted| wanted.as_bytes() == name)
                        })
                    {
                        return self
                            .fail("required interface was deleted; explicit repair is required");
                    }
                }
                LinkEvent::New { index, flags, name } => {
                    if let Some(required) = self.required.get(&index) {
                        if name
                            .as_ref()
                            .is_some_and(|name| name != required.as_bytes())
                        {
                            return self.fail("required interface was renamed or replaced; explicit repair is required");
                        }
                        if flags & libc::IFF_UP as u32 == 0 {
                            return self.fail("required interface became administratively down; explicit repair is required");
                        }
                        self.changed(index)?;
                    }
                }
                LinkEvent::Address { index, deleted } => {
                    if self.required.contains_key(&index) {
                        self.changed(index)?;
                        if deleted {
                            self.membership_revisions
                                .insert(index, self.revisions[&index]);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn changed(&mut self, index: u32) -> Result<()> {
        self.dirty.insert(index);
        let revision = self.revisions.entry(index).or_default();
        let Some(next) = revision.checked_add(1) else {
            return self.fail("route notification revision overflow");
        };
        *revision = next;
        Ok(())
    }
    fn register(&mut self, index: u32, name: &str) -> Result<()> {
        self.check()?;
        if self.deleted.contains(&index) {
            return self.fail("interface index was deleted/reused during preparation");
        }
        if self.required.get(&index).is_some_and(|old| old != name) {
            return self.fail("interface index changed ownership during preparation");
        }
        self.required.insert(index, name.into());
        Ok(())
    }
    fn receive_error(&mut self, error: io::Error) -> Result<bool> {
        self.check()?;
        match error.kind() {
            io::ErrorKind::WouldBlock => Ok(false),
            io::ErrorKind::Interrupted => Ok(true),
            _ => self.fail(format!("route notification receive error: {error}")),
        }
    }
}
struct LinkMonitor {
    fd: OwnedFd,
    history: LinkHistory,
}
impl LinkMonitor {
    fn open(names: &[String]) -> Result<Self> {
        let fd = socket::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
        socket::option(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &262144i32,
        )?;
        socket::option(
            fd.as_raw_fd(),
            libc::SOL_NETLINK,
            libc::NETLINK_NO_ENOBUFS,
            &0i32,
        )?;
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as _;
        address.nl_groups = 1 | 0x10 | 0x100;
        socket::check(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&address) as _,
            )
        })?;
        Ok(Self {
            fd,
            history: LinkHistory {
                wanted: names.iter().cloned().collect(),
                ..Default::default()
            },
        })
    }
    fn drain(&mut self) -> Result<()> {
        self.history.check()?;
        let mut bytes = [0u8; 65536];
        for _ in 0..64 {
            let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut message: libc::msghdr = unsafe { mem::zeroed() };
            message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = mem::size_of_val(&sender) as _;
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            let n = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &mut message,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if n < 0 {
                let error = io::Error::last_os_error();
                if !self.history.receive_error(error)? {
                    return Ok(());
                }
                continue;
            }
            if n as usize > bytes.len()
                || message.msg_namelen as usize != mem::size_of_val(&sender)
                || sender.nl_family as i32 != libc::AF_NETLINK
            {
                return self.history.fail(
                    "route notification framing/truncation; interface identity history lost",
                );
            }
            self.history
                .ingest(&bytes[..n as usize], message.msg_flags, sender.nl_pid)?;
        }
        self.history.fail(
            "route notification backlog exceeded safety bound; interface identity history lost",
        )
    }
}
#[derive(Debug)]
struct AddressRefresh;
impl std::fmt::Display for AddressRefresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mDNS interface requires address/link refresh")
    }
}
impl std::error::Error for AddressRefresh {}

struct Bucket {
    tokens: f64,
    at: Instant,
}
impl Bucket {
    fn new() -> Self {
        Self {
            tokens: 400.0,
            at: Instant::now(),
        }
    }
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * 200.0).min(400.0);
        self.at = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}
struct Port {
    watch: Option<LinkWatch>,
    revision: u64,
    fd: OwnedFd,
    name: String,
    index: u32,
    ipv6: bool,
    addresses: Vec<IpAddr>,
    budget: usize,
    receive_loss_tracking: bool,
    receive_overflow: u32,
    ingress: Bucket,
    egress: Bucket,
    policy: Policy,
}
struct Datagram {
    bytes: Vec<u8>,
    source: SocketAddr,
    destination: IpAddr,
    index: u32,
    hop: i32,
    overflow: Option<u32>,
}
impl Port {
    fn monitored(name: &str, ipv6: bool, filters: &[String], watch: LinkWatch) -> Result<Self> {
        watch
            .lock()
            .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?
            .drain()?;
        let mut port = Self::open(name, ipv6, filters)?;
        {
            let mut monitor = watch
                .lock()
                .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
            monitor.history.register(port.index, name)?;
            monitor.drain()?;
        }
        for _ in 0..3 {
            let before = {
                let mut monitor = watch
                    .lock()
                    .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
                monitor.drain()?;
                monitor
                    .history
                    .revisions
                    .get(&port.index)
                    .copied()
                    .unwrap_or(0)
            };
            let (index, mut addresses) = socket::interface_snapshot(name)?;
            addresses.sort();
            let mut monitor = watch
                .lock()
                .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
            monitor.drain()?;
            ensure!(
                index == port.index && addresses == port.addresses,
                "mDNS interface changed during socket preparation"
            );
            if monitor.history.revisions.get(&index).copied().unwrap_or(0) == before {
                monitor.history.dirty.remove(&index);
                drop(monitor);
                port.revision = before;
                port.watch = Some(watch);
                return Ok(port);
            }
        }
        bail!("mDNS interface did not stabilize during socket preparation")
    }
    fn current(&self) -> Result<bool> {
        if let Some(watch) = &self.watch {
            let mut monitor = watch
                .lock()
                .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
            monitor.drain()?;
            return Ok(!monitor.history.dirty.contains(&self.index)
                && monitor
                    .history
                    .revisions
                    .get(&self.index)
                    .copied()
                    .unwrap_or(0)
                    == self.revision);
        }
        Ok(true)
    }
    fn refresh(&mut self, filters: &[String]) -> Result<bool> {
        let watch = self
            .watch
            .clone()
            .context("mDNS socket has no interface monitor")?;
        for _ in 0..3 {
            let (revision, restore_membership) = {
                let mut monitor = watch
                    .lock()
                    .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
                monitor.drain()?;
                (
                    monitor
                        .history
                        .revisions
                        .get(&self.index)
                        .copied()
                        .unwrap_or(0),
                    monitor
                        .history
                        .membership_revisions
                        .get(&self.index)
                        .copied()
                        .unwrap_or(0)
                        > self.revision,
                )
            };
            let (index, mut addresses) = socket::interface_snapshot(&self.name)?;
            addresses.sort();
            let budget = Self::payload_budget(self.fd.as_raw_fd(), &self.name, self.ipv6)?;
            let mut monitor = watch
                .lock()
                .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
            monitor.drain()?;
            ensure!(
                index == self.index,
                "mDNS required interface {} was replaced",
                self.name
            );
            if monitor.history.revisions.get(&index).copied().unwrap_or(0) != revision {
                continue;
            }
            if addresses != self.addresses || budget != self.budget || restore_membership {
                drop(monitor);
                *self = Self::monitored(&self.name, self.ipv6, filters, watch)?;
                return Ok(true);
            }
            // Lifetime, DAD, and carrier notifications need revalidation, not
            // descriptor replacement: closing would discard already queued queries.
            self.revision = revision;
            monitor.history.dirty.remove(&index);
            return Ok(false);
        }
        Err(AddressRefresh.into())
    }
    fn payload_budget(raw: std::os::fd::RawFd, name: &str, ipv6: bool) -> Result<usize> {
        let mut request: libc::ifreq = unsafe { mem::zeroed() };
        for (out, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *out = byte as libc::c_char;
        }
        socket::check(unsafe { libc::ioctl(raw, libc::SIOCGIFMTU as _, &mut request) })?;
        let mtu = unsafe { request.ifr_ifru.ifru_mtu };
        let budget = (mtu as usize)
            .saturating_sub(if ipv6 { 48 } else { 28 })
            .min(1232);
        ensure!(
            budget >= 512,
            "mDNS interface {name} MTU cannot carry a 512-byte DNS payload"
        );
        Ok(budget)
    }
    fn open(name: &str, ipv6: bool, filters: &[String]) -> Result<Self> {
        let (index, mut addresses) = socket::interface_snapshot(name)?;
        addresses.sort();
        ensure!(
            addresses
                .iter()
                .any(|ip| ip.is_ipv6() == ipv6 && source_valid(*ip)),
            "mDNS interface {name} needs a usable {} address",
            if ipv6 { "IPv6" } else { "IPv4" }
        );
        let fd = socket::socket(
            if ipv6 { libc::AF_INET6 } else { libc::AF_INET },
            libc::SOCK_DGRAM,
            0,
        )?;
        let raw = fd.as_raw_fd();
        let receive_loss_tracking =
            match socket::option(raw, libc::SOL_SOCKET, libc::SO_RXQ_OVFL, &1i32) {
                Ok(()) => true,
                Err(error)
                    if error.downcast_ref::<io::Error>().is_some_and(|error| {
                        matches!(
                            error.raw_os_error(),
                            Some(libc::ENOPROTOOPT) | Some(libc::EINVAL)
                        )
                    }) =>
                {
                    false
                }
                Err(error) => return Err(error).context("enable mDNS receive-loss accounting"),
            };
        let budget = Self::payload_budget(raw, name, ipv6)?;
        socket::option(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, &1i32)?;
        socket::bind_device(raw, name)?;
        if ipv6 {
            socket::option(raw, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &1i32)?;
            socket::option(raw, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &1i32)?;
            socket::option(raw, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, &1i32)?;
            socket::option(raw, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &255i32)?;
            socket::option(raw, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, &255i32)?;
            socket::option(raw, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &index)?;
            socket::bind(raw, "[::]:5353".parse()?, 0)?;
            let membership = libc::ipv6_mreq {
                ipv6mr_multiaddr: libc::in6_addr {
                    s6_addr: V6.octets(),
                },
                ipv6mr_interface: index,
            };
            socket::option(
                raw,
                libc::IPPROTO_IPV6,
                libc::IPV6_ADD_MEMBERSHIP,
                &membership,
            )?;
        } else {
            socket::option(raw, libc::IPPROTO_IP, libc::IP_PKTINFO, &1i32)?;
            socket::option(raw, libc::IPPROTO_IP, libc::IP_RECVTTL, &1i32)?;
            socket::option(raw, libc::IPPROTO_IP, libc::IP_TTL, &255i32)?;
            socket::option(raw, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, &255i32)?;
            socket::option(raw, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL, &0i32)?;
            let source = addresses
                .iter()
                .find_map(|ip| {
                    if let IpAddr::V4(ip) = ip {
                        Some(*ip)
                    } else {
                        None
                    }
                })
                .context("mDNS IPv4 address missing")?;
            let membership = libc::ip_mreqn {
                imr_multiaddr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(V4.octets()),
                },
                imr_address: libc::in_addr {
                    s_addr: u32::from_ne_bytes(source.octets()),
                },
                imr_ifindex: index as i32,
            };
            socket::option(raw, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &membership)?;
            socket::bind(raw, "0.0.0.0:5353".parse()?, 0)?;
            socket::option(raw, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &membership)?;
        }
        Ok(Self {
            watch: None,
            revision: 0,
            fd,
            name: name.into(),
            index,
            ipv6,
            addresses,
            budget,
            receive_loss_tracking,
            receive_overflow: 0,
            ingress: Bucket::new(),
            egress: Bucket::new(),
            policy: Policy::new(filters),
        })
    }
    fn group(&self) -> IpAddr {
        if self.ipv6 {
            IpAddr::V6(V6)
        } else {
            IpAddr::V4(V4)
        }
    }
    fn receive(&self) -> Result<Option<Datagram>> {
        if !self.current()? {
            return Ok(None);
        }
        let mut bytes = [0u8; 9000];
        let mut control = [0usize; 64];
        let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = mem::size_of_val(&source) as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;
        let count = unsafe {
            libc::recvmsg(
                self.fd.as_raw_fd(),
                &mut msg,
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if count < 0 {
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
            msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && count as usize <= bytes.len(),
            "receive_drop: truncated mDNS datagram/ancillary data"
        );
        let mut index = None;
        let mut destination = None;
        let mut hop = None;
        let mut overflow = None;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let header = &*cmsg;
                let data = libc::CMSG_DATA(cmsg);
                if header.cmsg_level == libc::SOL_SOCKET
                    && header.cmsg_type == libc::SO_RXQ_OVFL
                    && header.cmsg_len >= libc::CMSG_LEN(mem::size_of::<u32>() as _) as _
                {
                    overflow = Some(std::ptr::read_unaligned(data.cast::<u32>()));
                }
                if header.cmsg_level == libc::IPPROTO_IP
                    && header.cmsg_type == libc::IP_PKTINFO
                    && header.cmsg_len
                        >= libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as _) as _
                {
                    let info = std::ptr::read_unaligned(data.cast::<libc::in_pktinfo>());
                    index = Some(info.ipi_ifindex as u32);
                    destination = Some(IpAddr::V4(Ipv4Addr::from(
                        info.ipi_addr.s_addr.to_ne_bytes(),
                    )));
                }
                if header.cmsg_level == libc::IPPROTO_IPV6
                    && header.cmsg_type == libc::IPV6_PKTINFO
                    && header.cmsg_len
                        >= libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as _) as _
                {
                    let info = std::ptr::read_unaligned(data.cast::<libc::in6_pktinfo>());
                    index = Some(info.ipi6_ifindex);
                    destination = Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                }
                if ((header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_TTL)
                    || (header.cmsg_level == libc::IPPROTO_IPV6
                        && header.cmsg_type == libc::IPV6_HOPLIMIT))
                    && header.cmsg_len >= libc::CMSG_LEN(mem::size_of::<i32>() as _) as _
                {
                    hop = Some(std::ptr::read_unaligned(data.cast::<i32>()));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        if !self.current()? {
            return Ok(None);
        }
        Ok(Some(Datagram {
            bytes: bytes[..count as usize].to_vec(),
            source: socket::from_sockaddr(&source)?,
            destination: destination.context("receive_drop: missing mDNS destination")?,
            index: index.context("receive_drop: missing mDNS ingress")?,
            hop: hop.context("receive_drop: missing mDNS hop limit")?,
            overflow,
        }))
    }
    fn send(&self, payload: &[u8], destination: SocketAddr) -> Result<()> {
        let (address, len) = socket::sockaddr(destination, self.index);
        // Device bindings use an index, not a durable identity. Drain the
        // latched history immediately before sending; check/send is not atomic.
        if !self.current()? {
            return Err(AddressRefresh.into());
        }
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                libc::MSG_NOSIGNAL,
                (&address as *const libc::sockaddr_storage).cast(),
                len,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().into());
        }
        ensure!(sent as usize == payload.len(), "short mDNS send");
        Ok(())
    }
}
fn source_valid(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && match ip {
            IpAddr::V4(ip) => !ip.is_broadcast() && ip.octets()[0] != 0,
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none(),
        }
}
fn ownership() -> Result<UnixDatagram> {
    let address = std::os::unix::net::SocketAddr::from_abstract_name(b"netcontrol-mdns-v1")?;
    let guard = UnixDatagram::bind_addr(&address)
        .context("mDNS already owned by another cooperative reflector in this network namespace")?;
    for path in ["/proc/thread-self/net/udp", "/proc/thread-self/net/udp6"] {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("inspect UDP 5353 ownership in {path}"))?;
        ensure!(
            !text.lines().skip(1).any(|line| line
                .split_whitespace()
                .nth(1)
                .is_some_and(|local| local.ends_with(":14E9"))),
            "mDNS UDP 5353 already in use in managed namespace; explicitly disable the competing mDNS receiver/reflector before enabling Netcontrol"
        );
    }
    Ok(guard)
}
struct Request {
    port: usize,
    source: SocketAddr,
    message: Message,
    legacy: Option<Message>,
    egress: std::collections::BTreeSet<usize>,
    expires: Instant,
}
struct PublicationRequest {
    port: usize,
    source: SocketAddr,
    message: Message,
    due: Instant,
    bytes: usize,
}
struct Fingerprint {
    port: usize,
    hash: u64,
    expires: Instant,
}
fn fingerprint(payload: &[u8]) -> u64 {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    payload.hash(&mut hash);
    hash.finish()
}
#[derive(Default)]
struct Counts {
    values: BTreeMap<&'static str, u64>,
    receive_loss_tracking: bool,
}
impl Counts {
    fn add(&mut self, key: &'static str, n: u64) {
        let count = self.values.entry(key).or_default();
        *count = count.saturating_add(n);
    }
    fn snapshot(&self, ctx: &ContextState) {
        ctx.update(|row| {
            for (key, count) in &self.values {
                row[*key] = json!(count.to_string());
            }
            row["collected_at"] = json!(now());
            row["receive_drops"] = if self.receive_loss_tracking {
                json!(
                    self.values
                        .get("receive_drops")
                        .copied()
                        .unwrap_or(0)
                        .to_string()
                )
            } else {
                serde_json::Value::Null
            };
            let mut warnings = Vec::new();
            if !self.receive_loss_tracking {
                warnings.push("receive_loss_accounting_unavailable");
            }
            for (key, reason) in [
                ("receive_drops", "receive_loss"),
                ("rate_limit_drops", "rate_limit_loss"),
                ("queue_drops", "queue_loss"),
                ("oversize_drops", "oversize_loss"),
            ] {
                if self.values.get(key).is_some_and(|count| *count > 0) {
                    warnings.push(reason);
                }
            }
            row["warnings"] = json!(warnings);
            row["statistics_complete"] = json!(
                self.receive_loss_tracking
                    && ![
                        "receive_drops",
                        "queue_drops",
                        "rate_limit_drops",
                        "oversize_drops"
                    ]
                    .iter()
                    .any(|key| self.values.get(key).is_some_and(|count| *count > 0))
            );
        });
    }
}
fn publications(config: &MDNSConfig, port: &Port, ttl: u32) -> Vec<Record> {
    let p = &config.publishing;
    if !p.enabled {
        return Vec::new();
    }
    let host = Name::text(&format!("{}.{}", p.hostname, p.domain));
    let mut records = Vec::new();
    let mut add = |name: Name, kind, data, unique| {
        records.push(Record {
            name,
            kind,
            class: if unique { 0x8001 } else { 1 },
            ttl,
            data,
        })
    };
    if p.addresses {
        for address in &port.addresses {
            if !source_valid(*address) {
                continue;
            }
            match address {
                IpAddr::V4(ip) if !port.ipv6 || p.a_on_ipv6 => {
                    add(host.clone(), 1, Data::Bytes(ip.octets().to_vec()), true)
                }
                IpAddr::V6(ip) if port.ipv6 || p.aaaa_on_ipv4 => {
                    add(host.clone(), 28, Data::Bytes(ip.octets().to_vec()), true)
                }
                _ => {}
            }
        }
    }
    if p.hinfo {
        let cpu = std::env::consts::ARCH.as_bytes();
        let mut data = vec![cpu.len() as u8];
        data.extend_from_slice(cpu);
        data.extend_from_slice(&[5, b'L', b'i', b'n', b'u', b'x']);
        add(host.clone(), 13, Data::Bytes(data), true);
    }
    if p.workstation {
        let service = Name::text(&format!("_workstation._tcp.{}", p.domain));
        let instance = Name::text(&format!("{}._workstation._tcp.{}", p.hostname, p.domain));
        add(service.clone(), 12, Data::Name(instance.clone()), false);
        add(
            instance.clone(),
            33,
            Data::Srv([0, 0, 0, 0, 0, 9], host.clone()),
            true,
        );
        add(instance, 16, Data::Bytes(vec![0]), true);
        add(
            Name::text(&format!("_services._dns-sd._udp.{}", p.domain)),
            12,
            Data::Name(service),
            false,
        );
    }
    if p.browse_domain {
        for prefix in ["b", "db"] {
            add(
                Name::text(&format!("{prefix}._dns-sd._udp.local.")),
                12,
                Data::Name(Name::text(&p.domain)),
                false,
            );
        }
    }
    records
}
fn response(records: Vec<Record>) -> Message {
    Message {
        flags: 0x8400,
        records: [records, Vec::new(), Vec::new()],
        ..Message::default()
    }
}
fn conflicts(message: &Message, ours: &[Record]) -> bool {
    let different = message.records.iter().flatten().any(|peer| {
        peer.ttl > 0
            && ours
                .iter()
                .any(|own| own.class & 0x8000 != 0 && own.name == peer.name)
            && !ours
                .iter()
                .any(|own| own.name == peer.name && own.kind == peer.kind && own.data == peer.data)
    });
    if !different {
        return false;
    }
    if message.flags & 0x8000 != 0 {
        return true;
    }
    // RFC 6762 simultaneous probes: lexicographically later canonical RDATA
    // wins. Fail rather than silently rename the configured publication.
    fn key(record: &Record) -> Vec<u8> {
        let mut value = Vec::new();
        put16(&mut value, record.class & 0x7fff);
        put16(&mut value, record.kind);
        value.extend(record.rdata());
        value
    }
    let names = ours
        .iter()
        .filter(|r| r.class & 0x8000 != 0)
        .map(|r| r.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    names.iter().any(|name| {
        let mut own = ours
            .iter()
            .filter(|r| r.name == *name && r.class & 0x8000 != 0)
            .map(key)
            .collect::<Vec<_>>();
        let mut peer = message.records[1]
            .iter()
            .filter(|r| r.name == *name && r.ttl > 0)
            .map(key)
            .collect::<Vec<_>>();
        if peer.is_empty() {
            return false;
        }
        own.sort();
        peer.sort();
        own < peer
    })
}
fn probe(config: &MDNSConfig, ports: &[Port], ctx: Option<&ContextState>) -> Result<()> {
    if !config.publishing.enabled {
        return Ok(());
    }
    let delay = Duration::from_millis(rand::random::<u8>() as u64 % 250);
    if let Some(ctx) = ctx {
        if ctx.wait(delay) {
            return Ok(());
        }
    } else {
        thread::sleep(delay);
    }
    for round in 0..4 {
        if round < 3 {
            for port in ports {
                if ctx.is_some_and(ContextState::stopping) {
                    return Ok(());
                }
                let unique: Vec<_> = publications(config, port, 120)
                    .into_iter()
                    .filter(|r| r.class & 0x8000 != 0)
                    .collect();
                if unique.is_empty() {
                    continue;
                }
                let mut names = std::collections::BTreeSet::new();
                let questions = unique
                    .iter()
                    .filter(|r| names.insert(r.name.clone()))
                    .map(|r| Question {
                        name: r.name.clone(),
                        kind: 255,
                        class: 1,
                    })
                    .collect();
                let mut query = Message {
                    questions,
                    records: [Vec::new(), unique, Vec::new()],
                    ..Message::default()
                };
                for rr in &mut query.records[1] {
                    rr.class = 1;
                }
                let bytes = query.encode();
                ensure!(
                    bytes.len() <= port.budget,
                    "mDNS publisher probe RRset exceeds egress payload budget on {}; reduce published addresses/options",
                    port.name
                );
                port.send(&bytes, SocketAddr::new(port.group(), 5353))?;
            }
        }
        let until = Instant::now() + Duration::from_millis(250);
        while Instant::now() < until {
            if ctx.is_some_and(ContextState::stopping) {
                return Ok(());
            }
            for port in ports {
                // A hostile flood must not make the startup handshake unbounded.
                for _ in 0..32 {
                    match port.receive() {
                        Ok(Some(packet))
                            if packet.index == port.index
                                && packet.hop == 255
                                && packet.source.port() == 5353 =>
                        {
                            if let Ok(message) = Message::parse(&packet.bytes) {
                                ensure!(
                                    !conflicts(&message, &publications(config, port, 120)),
                                    "mDNS publication hostname conflict on {}",
                                    port.name
                                );
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(error) if error.to_string().starts_with("receive_drop:") => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
}
pub(crate) fn prepare(config: MDNSConfig, names: Vec<String>) -> Result<Run> {
    let guard = ownership()?;
    let watch = std::sync::Arc::new(std::sync::Mutex::new(LinkMonitor::open(&names)?));
    for _ in 0..3 {
        let mut ports = Vec::new();
        for name in &names {
            for ipv6 in [false, true] {
                if if ipv6 { config.ipv6 } else { config.ipv4 } {
                    ports.push(
                        Port::monitored(name, ipv6, &config.reflection.filters, watch.clone())
                            .with_context(|| format!("prepare mDNS {name}"))?,
                    );
                }
            }
        }
        match probe(&config, &ports, None) {
            Err(error) if error.downcast_ref::<AddressRefresh>().is_some() => continue,
            result => result?,
        }
        let mut current = true;
        for port in &ports {
            current &= port.current()?;
        }
        if !current {
            continue;
        }
        return Ok(Box::new(move |ctx| {
            let _guard = guard;
            run(config, ports, ctx, watch)
        }));
    }
    bail!("mDNS interfaces did not stabilize before readiness")
}

fn emit(
    ports: &mut [Port],
    index: usize,
    message: &Message,
    destination: SocketAddr,
    recent: &mut VecDeque<Fingerprint>,
    counts: &mut Counts,
) -> Result<bool> {
    let parts = match message.split(ports[index].budget) {
        Ok(parts) => parts,
        Err(_) => {
            counts.add("oversize_drops", 1);
            return Ok(false);
        }
    };
    if parts.len() > 256 || parts.iter().map(Vec::len).sum::<usize>() > 2 * 1024 * 1024 {
        counts.add("queue_drops", 1);
        return Ok(false);
    }
    let mut sent = false;
    for bytes in parts {
        if !ports[index].egress.take() {
            counts.add("rate_limit_drops", 1);
            continue;
        }
        match ports[index].send(&bytes, destination) {
            Ok(()) => {
                sent = true;
                counts.add("transmitted_packets", 1);
                counts.add("transmitted_bytes", bytes.len() as u64);
                if recent.len() >= 8192 {
                    recent.pop_front();
                }
                recent.push_back(Fingerprint {
                    port: index,
                    hash: fingerprint(&bytes),
                    expires: Instant::now() + Duration::from_secs(1),
                });
            }
            Err(error) => {
                if error.downcast_ref::<AddressRefresh>().is_some() {
                    counts.add("queue_drops", 1);
                    return Ok(false);
                }
                counts.add("send_errors", 1);
                // Congestion is a counted loss, but broken sockets/links must
                // fail service verification rather than masquerade as ready.
                let transient = error.downcast_ref::<io::Error>().is_some_and(|e| {
                    matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) || e.raw_os_error() == Some(libc::ENOBUFS)
                });
                if !transient {
                    return Err(error).context("mDNS egress failed");
                }
            }
        }
    }
    Ok(sent)
}
fn matching_response(message: &Message, request: &Message) -> bool {
    message.flags & 0x8000 != 0
        && request.questions.iter().any(|q| {
            message
                .records
                .iter()
                .flatten()
                .any(|r| r.name == q.name && (q.kind == 255 || q.kind == r.kind))
        })
}
fn run(
    config: MDNSConfig,
    mut ports: Vec<Port>,
    ctx: ContextState,
    watch: LinkWatch,
) -> Result<()> {
    let mut counts = Counts {
        receive_loss_tracking: ports.iter().all(|port| port.receive_loss_tracking),
        ..Counts::default()
    };
    let mut recent = VecDeque::<Fingerprint>::new();
    let mut ingress_recent = VecDeque::<Fingerprint>::new();
    let mut requests = VecDeque::<Request>::new();
    let mut publication_requests = VecDeque::<PublicationRequest>::new();
    let mut checked = Instant::now();
    let mut announced = Instant::now() - Duration::from_secs(120);
    let mut announcements = 0;
    let mut needs_probe = false;
    let outcome = (|| -> Result<()> {
        while !ctx.stopping() {
            let dirty = {
                let mut monitor = watch
                    .lock()
                    .map_err(|_| anyhow::anyhow!("mDNS interface monitor lock poisoned"))?;
                monitor.drain()?;
                let mut dirty = monitor.history.dirty.clone();
                dirty.extend(
                    ports
                        .iter()
                        .filter(|port| {
                            monitor
                                .history
                                .revisions
                                .get(&port.index)
                                .copied()
                                .unwrap_or(0)
                                != port.revision
                        })
                        .map(|port| port.index),
                );
                dirty
            };
            let now = Instant::now();
            recent.retain(|entry| entry.expires > now);
            ingress_recent.retain(|entry| entry.expires > now);
            requests.retain(|entry| entry.expires > now);
            for port in &mut ports {
                port.policy.prune(now);
            }
            if checked.elapsed() >= Duration::from_secs(1) || !dirty.is_empty() {
                for port in &mut ports {
                    let refreshed = match port.refresh(&config.reflection.filters) {
                        Err(error) if error.downcast_ref::<AddressRefresh>().is_some() => continue,
                        result => result?,
                    };
                    if refreshed {
                        counts.receive_loss_tracking = false;
                        recent.clear();
                        requests.clear();
                        publication_requests.clear();
                        announcements = 0;
                        needs_probe = true;
                    }
                }
                checked = now;
            }
            if needs_probe {
                match probe(&config, &ports, Some(&ctx)) {
                    Err(error) if error.downcast_ref::<AddressRefresh>().is_some() => continue,
                    result => result?,
                }
                needs_probe = false;
            }
            if config.publishing.enabled
                && (announcements == 0
                    || announced.elapsed()
                        >= Duration::from_secs(if announcements == 1 { 1 } else { 60 }))
            {
                for i in 0..ports.len() {
                    if ctx.stopping() {
                        break;
                    }
                    let message = response(publications(&config, &ports[i], 120));
                    let destination = SocketAddr::new(ports[i].group(), 5353);
                    emit(
                        &mut ports,
                        i,
                        &message,
                        destination,
                        &mut recent,
                        &mut counts,
                    )?;
                }
                announcements += 1;
                announced = Instant::now();
            }
            while let Some(index) = publication_requests
                .iter()
                .position(|request| request.due <= Instant::now())
            {
                if ctx.stopping() {
                    break;
                }
                let request = publication_requests
                    .remove(index)
                    .expect("located publication request");
                let legacy = request.source.port() != 5353;
                let own = publications(&config, &ports[request.port], 120);
                let mut unicast = Vec::new();
                let mut multicast = Vec::new();
                for rr in own {
                    let questions = request
                        .message
                        .questions
                        .iter()
                        .filter(|q| q.name == rr.name && (q.kind == 255 || q.kind == rr.kind))
                        .collect::<Vec<_>>();
                    if questions.is_empty()
                        || (!legacy
                            && request.message.records[0].iter().any(|known| {
                                known.name == rr.name
                                    && known.kind == rr.kind
                                    && known.data == rr.data
                                    && known.ttl >= rr.ttl / 2
                            }))
                    {
                        continue;
                    }
                    if legacy || questions.iter().all(|q| q.class & 0x8000 != 0) {
                        unicast.push(rr);
                    } else {
                        multicast.push(rr);
                    }
                }
                if !unicast.is_empty() {
                    let mut reply = response(unicast);
                    if legacy {
                        reply.legacy(&request.message);
                    }
                    emit(
                        &mut ports,
                        request.port,
                        &reply,
                        request.source,
                        &mut recent,
                        &mut counts,
                    )?;
                }
                if !multicast.is_empty() {
                    let destination = SocketAddr::new(ports[request.port].group(), 5353);
                    emit(
                        &mut ports,
                        request.port,
                        &response(multicast),
                        destination,
                        &mut recent,
                        &mut counts,
                    )?;
                }
            }
            for i in 0..ports.len() {
                // Fixed per-port batches prevent a flooded link starving shutdown
                // and the other family/interfaces.
                for _ in 0..32 {
                    if ctx.stopping() {
                        break;
                    }
                    let packet = match ports[i].receive() {
                        Ok(Some(packet)) => packet,
                        Ok(None) => break,
                        Err(error) if error.to_string().starts_with("receive_drop:") => {
                            counts.receive_loss_tracking = false;
                            counts.add("oversize_drops", 1);
                            continue;
                        }
                        Err(error) => return Err(error).context("mDNS receive failed"),
                    };
                    counts.add("received_packets", 1);
                    counts.add("received_bytes", packet.bytes.len() as u64);
                    if let Some(overflow) = packet.overflow {
                        counts.add(
                            "receive_drops",
                            overflow.wrapping_sub(ports[i].receive_overflow) as u64,
                        );
                        ports[i].receive_overflow = overflow;
                    }
                    if !ports[i].ingress.take() {
                        counts.add("rate_limit_drops", 1);
                        continue;
                    }
                    if packet.hop != 255 {
                        counts.add("hop_limit_drops", 1);
                        continue;
                    }
                    let multicast = packet.destination == ports[i].group();
                    if packet.index != ports[i].index
                        || !source_valid(packet.source.ip())
                        || packet.source.port() == 0
                        || (!multicast && !ports[i].addresses.contains(&packet.destination))
                    {
                        counts.add("policy_drops", 1);
                        continue;
                    }
                    let mut message = match Message::parse(&packet.bytes) {
                        Ok(message) => message,
                        Err(error) => {
                            counts.add(
                                if error.to_string().starts_with("unsupported_record:") {
                                    "unsupported_record_drops"
                                } else {
                                    "malformed_packets"
                                },
                                1,
                            );
                            continue;
                        }
                    };
                    if message.flags & 0x8000 != 0 && packet.source.port() != 5353 {
                        counts.add("policy_drops", 1);
                        continue;
                    }
                    let hash = fingerprint(&message.encode());
                    if ports[i].addresses.contains(&packet.source.ip())
                        && recent
                            .iter()
                            .any(|entry| entry.port == i && entry.hash == hash)
                    {
                        counts.add("duplicate_drops", 1);
                        continue;
                    }
                    // A unicast reply is only admissible for a query actually sent
                    // onto this link, never for an arbitrary DNS transaction ID.
                    if !multicast
                        && !requests.iter().any(|r| {
                            r.egress.contains(&i)
                                && ports[r.port].ipv6 == ports[i].ipv6
                                && matching_response(&message, &r.message)
                        })
                    {
                        counts.add("policy_drops", 1);
                        continue;
                    }
                    if config.publishing.enabled {
                        let own = publications(&config, &ports[i], 120);
                        let all_own = ports
                            .iter()
                            .flat_map(|port| publications(&config, port, 120))
                            .collect::<Vec<_>>();
                        if message.flags & 0x8000 != 0
                            && recent.iter().any(|entry| entry.hash == hash)
                            && message
                                .records
                                .iter()
                                .flatten()
                                .all(|r| all_own.contains(r))
                        {
                            counts.add("duplicate_drops", 1);
                            continue;
                        }
                        ensure!(
                            !conflicts(&message, &all_own),
                            "mDNS publication hostname conflict on {}",
                            ports[i].name
                        );
                        if message.flags & 0x8000 == 0 {
                            // TC known-answer continuations are collected before
                            // suppression. Do not answer the first fragment early.
                            let candidates = publication_requests
                                .iter()
                                .enumerate()
                                .filter(|(_, request)| {
                                    request.port == i
                                        && request.source == packet.source
                                        && request.message.id == message.id
                                        && (message.questions.is_empty()
                                            || request.message.questions == message.questions)
                                })
                                .map(|(index, _)| index)
                                .collect::<Vec<_>>();
                            let matched = if candidates.len() == 1 {
                                Some(candidates[0])
                            } else {
                                None
                            };
                            let interesting = own.iter().any(|rr| {
                                message.questions.iter().any(|q| {
                                    q.name == rr.name && (q.kind == 255 || q.kind == rr.kind)
                                })
                            });
                            let bytes = publication_requests
                                .iter()
                                .map(|request| request.bytes)
                                .sum::<usize>();
                            let incoming_bytes = message.encode().len();
                            if (matched.is_some() || interesting)
                                && bytes + incoming_bytes <= 2 * 1024 * 1024
                            {
                                if let Some(index) = matched {
                                    let request = &mut publication_requests[index];
                                    request.bytes += incoming_bytes;
                                    for known in &message.records[0] {
                                        if request
                                            .message
                                            .records
                                            .iter()
                                            .map(Vec::len)
                                            .sum::<usize>()
                                            + request.message.questions.len()
                                            >= 512
                                        {
                                            counts.add("queue_drops", 1);
                                            break;
                                        }
                                        request.message.records[0].push(known.clone());
                                    }
                                } else if publication_requests.len() + requests.len() < 1024 {
                                    let delay = if message.flags & 0x0200 != 0 {
                                        450
                                    } else if packet.source.port() != 5353
                                        || message.questions.iter().all(|q| q.class & 0x8000 != 0)
                                    {
                                        0
                                    } else {
                                        20 + rand::random::<u8>() as u64 % 101
                                    };
                                    let mut query = message.clone();
                                    query.records[1].clear();
                                    query.records[2].clear();
                                    publication_requests.push_back(PublicationRequest {
                                        port: i,
                                        source: packet.source,
                                        message: query,
                                        due: Instant::now() + Duration::from_millis(delay),
                                        bytes: incoming_bytes,
                                    });
                                } else {
                                    counts.add("queue_drops", 1);
                                }
                            } else if interesting || matched.is_some() {
                                counts.add("queue_drops", 1);
                            }
                        }
                    }
                    if !config.reflection.enabled {
                        continue;
                    }
                    let legacy_query = (packet.source.port() != 5353
                        && message.flags & 0x8000 == 0)
                        .then(|| Message {
                            id: message.id,
                            flags: message.flags,
                            questions: message.questions.clone(),
                            ..Message::default()
                        });
                    let used = ports
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| *index != i)
                        .map(|(_, port)| port.policy.associations.len())
                        .sum::<usize>();
                    ports[i].policy.limit = 8192usize.saturating_sub(used);
                    message = ports[i].policy.filter(&message, Instant::now());
                    if message.empty() {
                        counts.add("policy_drops", 1);
                        continue;
                    }
                    let mut request_index = None;
                    if message.flags & 0x8000 != 0 {
                        for request in &requests {
                            if request.egress.contains(&i)
                                && ports[request.port].ipv6 == ports[i].ipv6
                                && request.source.port() != 5353
                                && matching_response(&message, &request.message)
                            {
                                let mut reply = message.clone();
                                reply.legacy(request.legacy.as_ref().unwrap_or(&request.message));
                                emit(
                                    &mut ports,
                                    request.port,
                                    &reply,
                                    request.source,
                                    &mut recent,
                                    &mut counts,
                                )?;
                            }
                        }
                    } else {
                        if requests.len() + publication_requests.len() >= 1024 {
                            requests.pop_front();
                            counts.add("queue_drops", 1);
                        }
                        if requests.len() + publication_requests.len() < 1024 {
                            let query = Message {
                                id: message.id,
                                flags: message.flags,
                                questions: message.questions.clone(),
                                ..Message::default()
                            };
                            requests.push_back(Request {
                                port: i,
                                source: packet.source,
                                message: query,
                                legacy: legacy_query,
                                egress: std::collections::BTreeSet::new(),
                                expires: Instant::now() + Duration::from_secs(5),
                            });
                            request_index = Some(requests.len() - 1);
                        }
                    }
                    message.reflected();
                    let payload = message.encode();
                    // Separate returned-packet guard: an identical query may be
                    // independently originated on another LAN, but our own source
                    // addresses or an answer returned by a second reflector must
                    // not be fanned out indefinitely during the one-second window.
                    let hash =
                        fingerprint(&payload) ^ fingerprint(packet.source.to_string().as_bytes());
                    if ingress_recent
                        .iter()
                        .any(|entry| entry.port == i && entry.hash == hash)
                    {
                        counts.add("duplicate_drops", 1);
                        continue;
                    }
                    if ingress_recent.len() >= 8192 {
                        ingress_recent.pop_front();
                    }
                    ingress_recent.push_back(Fingerprint {
                        port: i,
                        hash,
                        expires: Instant::now() + Duration::from_secs(1),
                    });
                    for j in 0..ports.len() {
                        if ctx.stopping() {
                            break;
                        }
                        if i == j || ports[i].ipv6 != ports[j].ipv6 {
                            continue;
                        }
                        let destination = SocketAddr::new(ports[j].group(), 5353);
                        let sent = emit(
                            &mut ports,
                            j,
                            &message,
                            destination,
                            &mut recent,
                            &mut counts,
                        )?;
                        if sent {
                            if let Some(index) = request_index {
                                requests[index].egress.insert(j);
                            }
                        }
                    }
                }
            }
            counts.snapshot(&ctx);
            ctx.wait(Duration::from_millis(10));
        }
        if config.publishing.enabled {
            for port in &ports {
                let goodbye = response(publications(&config, port, 0));
                for bytes in goodbye.split(port.budget)? {
                    // Final goodbye is the only intentional send after stop.
                    if port
                        .send(&bytes, SocketAddr::new(port.group(), 5353))
                        .is_ok()
                    {
                        counts.add("transmitted_packets", 1);
                        counts.add("transmitted_bytes", bytes.len() as u64);
                    } else {
                        counts.add("send_errors", 1);
                    }
                }
            }
        }
        Ok(())
    })();
    counts.snapshot(&ctx);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_bucket_and_reply_matching_are_bounded() {
        let mut bucket = Bucket::new();
        for _ in 0..400 {
            assert!(bucket.take());
        }
        assert!(!bucket.take());
        let request = Message {
            questions: vec![Question {
                name: Name::text("_ipp._tcp.local."),
                kind: 12,
                class: 1,
            }],
            ..Message::default()
        };
        let answer = response(vec![Record {
            name: Name::text("_ipp._tcp.local."),
            kind: 12,
            class: 1,
            ttl: 120,
            data: Data::Name(Name::text("p._ipp._tcp.local.")),
        }]);
        assert!(matching_response(&answer, &request));
        assert!(!matching_response(&Message::default(), &request));
    }
    #[test]
    fn probe_tie_breaks_per_name_and_active_conflicts_fail() {
        let mut own = vec![Record {
            name: Name::text("appliance.local."),
            kind: 1,
            class: 0x8001,
            ttl: 120,
            data: Data::Bytes(vec![192, 0, 2, 1]),
        }];
        let mut peer = own[0].clone();
        peer.class = 1;
        peer.data = Data::Bytes(vec![192, 0, 2, 2]);
        let mut probe = Message {
            records: [Vec::new(), vec![peer], Vec::new()],
            ..Message::default()
        };
        assert!(conflicts(&probe, &own));
        own[0].data = Data::Bytes(vec![192, 0, 2, 3]);
        own.push(Record {
            name: Name::text("aaa-other.local."),
            kind: 1,
            class: 0x8001,
            ttl: 120,
            data: Data::Bytes(vec![192, 0, 2, 99]),
        });
        assert!(!conflicts(&probe, &own));
        probe.flags = 0x8400;
        assert!(conflicts(&probe, &own));
        probe.records[1][0].ttl = 0;
        assert!(!conflicts(&probe, &own));
    }

    fn attribute(kind: u16, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(bytes);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }
    fn notification(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&[0; 10]);
        bytes.extend_from_slice(body);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }
    fn link_notification(kind: u16, index: u32, name: Option<&str>, up: bool) -> Vec<u8> {
        let mut body = vec![0; 16];
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        if up {
            body[8..12].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
        }
        if let Some(name) = name {
            body.extend(attribute(3, format!("{name}\0").as_bytes()));
        }
        notification(kind, &body)
    }
    #[test]
    fn mdns_link_history_latches_deletion_reuse_rename_and_down() -> Result<()> {
        for replacement in [
            link_notification(17, 7, Some("lan1"), true),
            link_notification(16, 7, Some("other"), true),
            link_notification(16, 7, Some("lan1"), false),
        ] {
            let mut history = LinkHistory::default();
            history.register(7, "lan1")?;
            assert!(history.ingest(&replacement, 0, 0).is_err());
            let latched = history.error.clone();
            assert!(
                history
                    .ingest(&link_notification(16, 7, Some("lan1"), true), 0, 0)
                    .is_err()
            );
            assert_eq!(history.error, latched);
            assert!(history.register(7, "lan1").is_err());
        }
        let mut history = LinkHistory::default();
        history.ingest(&link_notification(17, 7, None, true), 0, 0)?;
        history.ingest(&link_notification(16, 7, Some("lan1"), true), 0, 0)?;
        assert!(history.register(7, "lan1").is_err());
        let mut history = LinkHistory {
            wanted: ["lan1".into()].into_iter().collect(),
            ..Default::default()
        };
        assert!(
            history
                .ingest(&link_notification(17, 9, Some("lan1"), true), 0, 0)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn mdns_link_notifications_track_address_revisions_and_ignore_unrelated_links() -> Result<()> {
        let mut history = LinkHistory::default();
        history.register(7, "lan1")?;
        let mut address = vec![libc::AF_INET as u8, 24, 0, 0];
        address.extend(7u32.to_ne_bytes());
        address.extend(attribute(3, b"lan1:alias\0"));
        let mut multipart = link_notification(16, 7, Some("lan1"), true);
        multipart.extend(notification(20, &address));
        multipart.extend(notification(21, &address));
        multipart.extend(link_notification(17, 8, Some("unrelated"), true));
        history.ingest(&multipart, 0, 0)?;
        assert_eq!(history.revisions[&7], 3);
        assert_eq!(history.membership_revisions[&7], 3);
        assert_eq!(history.dirty, [7].into_iter().collect());
        assert!(history.check().is_ok());
        // A refresh of one family must not erase another socket's stale revision.
        history.dirty.clear();
        let old_revision = 2;
        assert_ne!(history.revisions[&7], old_revision);
        history.revisions.insert(7, u64::MAX);
        assert!(history.changed(7).is_err());
        assert!(history.check().is_err());
        Ok(())
    }
    #[test]
    fn mdns_link_notification_loss_and_malformed_frames_fail_closed() {
        let valid = link_notification(16, 7, Some("lan1"), true);
        let mut interrupted = valid.clone();
        interrupted[6..8].copy_from_slice(&0x10u16.to_ne_bytes());
        let mut invalid_length = valid.clone();
        invalid_length[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut invalid_attribute = valid.clone();
        invalid_attribute[32..34].copy_from_slice(&3u16.to_ne_bytes());
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut oversized = Vec::new();
        for _ in 0..513 {
            oversized.extend(notification(1, &[]));
        }
        for (bytes, flags, sender) in [
            (valid.clone(), libc::MSG_TRUNC, 0),
            (valid.clone(), libc::MSG_CTRUNC, 0),
            (valid, 0, 42),
            (interrupted, 0, 0),
            (invalid_length, 0, 0),
            (invalid_attribute, 0, 0),
            (trailing, 0, 0),
            (oversized, 0, 0),
            (notification(4, &[]), 0, 0),
            (notification(2, &(-libc::ENOBUFS).to_ne_bytes()), 0, 0),
            (notification(2, &[]), 0, 0),
            (vec![], 0, 0),
        ] {
            let mut history = LinkHistory::default();
            assert!(history.ingest(&bytes, flags, sender).is_err());
            assert!(history.check().is_err());
            assert!(history.ingest(&notification(1, &[]), 0, 0).is_err());
        }
        let mut history = LinkHistory::default();
        assert!(
            !history
                .receive_error(io::Error::from_raw_os_error(libc::EAGAIN))
                .unwrap()
        );
        assert!(
            history
                .receive_error(io::Error::from_raw_os_error(libc::EINTR))
                .unwrap()
        );
        assert!(
            history
                .receive_error(io::Error::from_raw_os_error(libc::ENOBUFS))
                .is_err()
        );
        assert!(
            history
                .receive_error(io::Error::from_raw_os_error(libc::EAGAIN))
                .is_err()
        );
        let mut history = LinkHistory::default();
        history.deleted.extend(1..=8192);
        assert!(
            history
                .ingest(&link_notification(17, 8193, None, true), 0, 0)
                .is_err()
        );
    }
    fn netlink(kind: u16, body: &[u8]) -> Result<()> {
        let flags = if kind == 16 && body[4..8] != [0, 0, 0, 0] {
            5
        } else {
            0x605
        };
        netlink_flags(kind, body, flags)
    }
    fn netlink_flags(kind: u16, body: &[u8], flags: u16) -> Result<()> {
        let fd = socket::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as _;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&1u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(body);
        socket::check(unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&address) as _,
            ) as i32
        })?;
        let until = Instant::now() + Duration::from_secs(2);
        let mut buffer = [0u8; 4096];
        while Instant::now() < until {
            let n =
                unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if n >= 20 {
                let code = i32::from_ne_bytes(buffer[16..20].try_into()?);
                ensure!(
                    u16::from_ne_bytes(buffer[4..6].try_into()?) == 2 && code == 0,
                    "mDNS fixture netlink error {code}"
                );
                return Ok(());
            }
            thread::sleep(Duration::from_millis(5));
        }
        bail!("mDNS fixture netlink ACK timed out")
    }
    fn inside<T: Send + 'static>(
        namespace: std::sync::Arc<std::fs::File>,
        test: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        thread::spawn(move || {
            socket::check(unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) })?;
            test()
        })
        .join()
        .map_err(|_| anyhow::anyhow!("mDNS client namespace thread panicked"))?
    }
    fn configure_link(name: &str, n: u8, last: u8) -> Result<()> {
        let fd = socket::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let mut request: libc::ifreq = unsafe { mem::zeroed() };
        for (out, b) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *out = b as _;
        }
        request.ifr_ifru.ifru_flags = libc::IFF_UP as i16;
        socket::check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) })?;
        let mut body = vec![libc::AF_INET as u8, 24, 0, 0];
        body.extend_from_slice(&socket::ifindex(name)?.to_ne_bytes());
        body.extend(attribute(1, &[192, 0, n, last]));
        body.extend(attribute(2, &[192, 0, n, last]));
        netlink(20, &body)?;
        let mut body = vec![libc::AF_INET6 as u8, 64, libc::IFA_F_NODAD as u8, 0];
        body.extend_from_slice(&socket::ifindex(name)?.to_ne_bytes());
        let ip = Ipv6Addr::new(0xfd00, n as u16, 0, 0, 0, 0, 0, last as u16);
        body.extend(attribute(1, &ip.octets()));
        netlink(20, &body)?;
        let mut body = vec![libc::AF_INET6 as u8, 64, libc::IFA_F_NODAD as u8, 253];
        body.extend_from_slice(&socket::ifindex(name)?.to_ne_bytes());
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, n as u16, last as u16);
        body.extend(attribute(1, &ip.octets()));
        netlink(20, &body)
    }
    fn create_veth(lan: &str, peer: &str, index: u32, mac: Option<&[u8]>) -> Result<()> {
        let mut body = vec![0u8; 16];
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        let mut peer_info = vec![0u8; 16];
        peer_info.extend(attribute(3, format!("{peer}\0").as_bytes()));
        let mut link_info = attribute(1, b"veth\0");
        link_info.extend(attribute(2, &attribute(1, &peer_info)));
        body.extend(attribute(3, format!("{lan}\0").as_bytes()));
        if let Some(mac) = mac {
            body.extend(attribute(1, mac));
        }
        body.extend(attribute(18, &link_info));
        netlink_flags(16, &body, 0x605)
    }
    fn links() -> Result<Vec<std::sync::Arc<std::fs::File>>> {
        let mut clients = Vec::new();
        for n in 1..=3 {
            let lan = format!("lan{n}");
            let peer = format!("peer{n}");
            create_veth(&lan, &peer, 0, None)?;
            let client = std::sync::Arc::new(
                thread::spawn(|| -> Result<std::fs::File> {
                    socket::check(unsafe { libc::unshare(libc::CLONE_NEWNET) })?;
                    Ok(std::fs::File::open("/proc/thread-self/ns/net")?)
                })
                .join()
                .unwrap()?,
            );
            let mut body = vec![0u8; 16];
            body[4..8].copy_from_slice(&(socket::ifindex(&peer)? as i32).to_ne_bytes());
            body.extend(attribute(28, &client.as_raw_fd().to_ne_bytes()));
            netlink(16, &body)?;
            configure_link(&lan, n, 1)?;
            inside(client.clone(), move || configure_link(&peer, n, 2))?;
            clients.push(client);
        }
        Ok(clients)
    }
    fn isolated(
        test: impl FnOnce(Vec<std::sync::Arc<std::fs::File>>) -> Result<()> + Send + 'static,
    ) {
        assert_eq!(std::env::var("NETCONTROL_INTEGRATION").as_deref(), Ok("1"));
        thread::spawn(move || -> Result<()> {
            socket::check(unsafe { libc::unshare(libc::CLONE_NEWNET) })?;
            test(links()?)
        })
        .join()
        .unwrap()
        .unwrap();
    }
    fn received(port: &Port, source: IpAddr, response: bool) -> Result<Message> {
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if let Some(packet) = port.receive()? {
                let message = Message::parse(&packet.bytes)?;
                if packet.source.ip() == source && (message.flags & 0x8000 != 0) == response {
                    ensure!(
                        packet.hop == 255
                            && packet.index == port.index
                            && packet.source.port() == 5353,
                        "wrong mDNS wire source/hop/interface"
                    );
                    return Ok(message);
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        bail!("mDNS reflected packet missing")
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_reflection_v4_v6_filter_legacy_and_shutdown() {
        isolated(|clients| {
            for (ipv6, filter) in [
                (false, "_ipp._tcp.local."),
                (true, "_ipp._tcp.local."),
                (false, "printer.local."),
                (true, "printer.local."),
            ] {
                let mut config = MDNSConfig {
                    enabled: true,
                    ipv4: !ipv6,
                    ipv6,
                    ..MDNSConfig::default()
                };
                config.reflection.enabled = true;
                config.reflection.filters = vec![filter.into()];
                let mut worker = crate::worker::Worker::start(
                    "mdns-wire-test".into(),
                    None,
                    json!({}),
                    move || prepare(config, vec!["lan1".into(), "lan2".into()]),
                )?;
                ensure!(
                    ownership().is_err(),
                    "cooperative ownership was not exclusive"
                );
                let peer1 = inside(clients[0].clone(), move || Port::open("peer1", ipv6, &[]))?;
                let peer2 = inside(clients[1].clone(), move || Port::open("peer2", ipv6, &[]))?;
                let excluded = inside(clients[2].clone(), move || Port::open("peer3", ipv6, &[]))?;
                let mut query = Message {
                    id: 123,
                    questions: vec![Question {
                        name: Name::text("_ipp._tcp.local."),
                        kind: 12,
                        class: 0x8001,
                    }],
                    ..Message::default()
                };
                query.records[0].push(Record {
                    name: Name::text("private.local."),
                    kind: 1,
                    class: 1,
                    ttl: 120,
                    data: Data::Bytes(vec![192, 0, 2, 99]),
                });
                peer1.send(&query.encode(), SocketAddr::new(peer1.group(), 5353))?;
                let source2: IpAddr = if ipv6 {
                    "fe80::2:1".parse()?
                } else {
                    "192.0.2.1".parse()?
                };
                let reflected = received(&peer2, source2, false)
                    .with_context(|| format!("query ipv6={ipv6}, worker={}", worker.snapshot()))?;
                ensure!(
                    reflected.id == 0 && reflected.questions[0].class == 1,
                    "QU/ID not normalized"
                );
                ensure!(
                    reflected.records.iter().all(Vec::is_empty),
                    "browse question leaked unrelated known answers for {filter}"
                );
                let answer = response(vec![
                    Record {
                        name: Name::text("_ipp._tcp.local."),
                        kind: 12,
                        class: 1,
                        ttl: 120,
                        data: Data::Name(Name::text("printer._ipp._tcp.local.")),
                    },
                    Record {
                        name: Name::text("printer._ipp._tcp.local."),
                        kind: 33,
                        class: 0x8001,
                        ttl: 120,
                        data: Data::Srv([0, 0, 0, 0, 2, 119], Name::text("printer.local.")),
                    },
                    Record {
                        name: Name::text("printer.local."),
                        kind: 1,
                        class: 0x8001,
                        ttl: 120,
                        data: Data::Bytes(vec![192, 0, 2, 2]),
                    },
                    Record {
                        name: Name::text("private.local."),
                        kind: 1,
                        class: 0x8001,
                        ttl: 120,
                        data: Data::Bytes(vec![192, 0, 2, 99]),
                    },
                ]);
                peer2.send(&answer.encode(), SocketAddr::new(peer2.group(), 5353))?;
                let source1: IpAddr = if ipv6 {
                    "fe80::1:1".parse()?
                } else {
                    "192.0.1.1".parse()?
                };
                let reflected = received(&peer1, source1, true)
                    .with_context(|| format!("answer ipv6={ipv6}, worker={}", worker.snapshot()))?;
                ensure!(
                    reflected.records[0].len() == 3 && reflected.records[0][1].class == 0x8001,
                    "filter/cache-flush wire behavior incorrect"
                );
                ensure!(
                    excluded.receive()?.is_none(),
                    "mDNS leaked to unselected interface"
                );
                let followup = Message {
                    questions: vec![Question {
                        name: Name::text("printer._ipp._tcp.local."),
                        kind: 33,
                        class: 1,
                    }],
                    ..Message::default()
                };
                peer1.send(&followup.encode(), SocketAddr::new(peer1.group(), 5353))?;
                let reflected = received(&peer2, source2, false)
                    .with_context(|| format!("instance query filter={filter}, ipv6={ipv6}"))?;
                ensure!(
                    reflected.questions == followup.questions,
                    "instance query was not reflected"
                );
                if !ipv6 {
                    let client = inside(clients[0].clone(), || {
                        let client = std::net::UdpSocket::bind("192.0.1.2:0")?;
                        socket::bind_device(client.as_raw_fd(), "peer1")?;
                        client.set_multicast_ttl_v4(255)?;
                        Ok(client)
                    })?;
                    query.id = 77;
                    query.questions[0].class = 1;
                    query.questions.push(Question {
                        name: Name::text("_ssh._tcp.local."),
                        kind: 12,
                        class: 1,
                    });
                    client.send_to(&query.encode(), "224.0.0.251:5353")?;
                    received(&peer2, source2, false)
                        .with_context(|| format!("legacy query worker={}", worker.snapshot()))?;
                    peer2.send(&answer.encode(), SocketAddr::new(peer2.group(), 5353))?;
                    client.set_read_timeout(Some(Duration::from_secs(2)))?;
                    let mut buffer = [0u8; 9000];
                    let (len, _) = client.recv_from(&mut buffer)?;
                    let reply = Message::parse(&buffer[..len])?;
                    ensure!(
                        reply.id == 77
                            && reply.questions == query.questions
                            && reply
                                .records
                                .iter()
                                .flatten()
                                .all(|r| r.class == 1 && r.ttl <= 10),
                        "legacy reply reconstruction failed"
                    );
                }
                let start = Instant::now();
                worker.shutdown()?;
                ensure!(
                    start.elapsed() < Duration::from_secs(1),
                    "mDNS shutdown exceeded one second"
                );
                ensure!(
                    worker.snapshot()["state"] == "stopped",
                    "mDNS worker failed: {}",
                    worker.snapshot()
                );
                drop((peer1, peer2, excluded));
                drop(ownership()?);
            }
            Ok(())
        });
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_kernel_receive_loss_is_visible() {
        isolated(|clients| {
            let port = Port::open("lan1", false, &[])?;
            ensure!(
                port.receive_loss_tracking,
                "Linux fixture lacks SO_RXQ_OVFL"
            );
            socket::option(
                port.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &8192i32,
            )?;
            let peer = inside(clients[0].clone(), || Port::open("peer1", false, &[]))?;
            let message = Message::default().encode();
            for _ in 0..1024 {
                peer.send(&message, SocketAddr::new(peer.group(), 5353))?;
            }
            while port.receive()?.is_some() {}
            peer.send(&message, SocketAddr::new(peer.group(), 5353))?;
            let until = Instant::now() + Duration::from_secs(2);
            let overflow = loop {
                if let Some(packet) = port.receive()? {
                    if let Some(overflow) = packet.overflow {
                        break overflow;
                    }
                }
                ensure!(
                    Instant::now() < until,
                    "SO_RXQ_OVFL did not report the forced socket overflow"
                );
                thread::sleep(Duration::from_millis(5));
            };
            ensure!(overflow > 0, "forced mDNS receive overflow was not counted");
            let mut counts = Counts {
                receive_loss_tracking: true,
                ..Counts::default()
            };
            counts.add("receive_drops", overflow as u64);
            let ctx = ContextState {
                stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                status: std::sync::Arc::new(std::sync::Mutex::new(json!({}))),
            };
            counts.snapshot(&ctx);
            let status = ctx.status.lock().unwrap();
            let expected = overflow.to_string();
            ensure!(
                status["receive_drops"].as_str() == Some(expected.as_str())
                    && status["statistics_complete"] == false,
                "receive-loss status was not exact/incomplete"
            );
            Ok(())
        });
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_publishing_queries_goodbye_and_conflict() {
        isolated(|clients| {
            let mut config = MDNSConfig {
                enabled: true,
                ipv6: false,
                ..MDNSConfig::default()
            };
            config.publishing = netcontrol_core::MDNSPublishing {
                enabled: true,
                hostname: "appliance".into(),
                addresses: true,
                hinfo: true,
                workstation: true,
                browse_domain: true,
                ..Default::default()
            };
            let first = config.clone();
            let mut worker = crate::worker::Worker::start(
                "mdns-publisher-test".into(),
                None,
                json!({}),
                move || prepare(first, vec!["lan1".into()]),
            )?;
            let peer = inside(clients[0].clone(), || Port::open("peer1", false, &[]))?;
            // DAD/lifetime changes notify even when the address set is identical.
            // A query queued behind that notification must not disappear in reprobes.
            let mut notifications = LinkMonitor::open(&["lan1".into()])?;
            let index = socket::ifindex("lan1")?;
            notifications.history.register(index, "lan1")?;
            let before = socket::interface_snapshot("lan1")?;
            let mut body = vec![libc::AF_INET6 as u8, 64, libc::IFA_F_NODAD as u8, 0];
            body.extend(index.to_ne_bytes());
            body.extend(attribute(
                1,
                &Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1).octets(),
            ));
            let mut lifetime = Vec::new();
            for value in [3600u32, 7200, 0, 0] {
                lifetime.extend(value.to_ne_bytes());
            }
            body.extend(attribute(6, &lifetime));
            netlink_flags(20, &body, 0x505)?;
            notifications.drain()?;
            ensure!(
                notifications.history.dirty.contains(&index),
                "fixture did not generate an address notification"
            );
            ensure!(
                before == socket::interface_snapshot("lan1")?,
                "lifetime update changed interface addresses"
            );
            let query = Message {
                questions: vec![Question {
                    name: Name::text("appliance.local."),
                    kind: 255,
                    class: 0x8001,
                }],
                ..Message::default()
            };
            peer.send(&query.encode(), SocketAddr::new(peer.group(), 5353))?;
            let until = Instant::now() + Duration::from_secs(2);
            let mut found = false;
            while Instant::now() < until {
                if let Some(packet) = peer.receive()? {
                    let message = Message::parse(&packet.bytes)?;
                    if packet.destination == "192.0.1.2".parse::<IpAddr>()? {
                        ensure!(
                            packet.hop == 255 && packet.source.port() == 5353,
                            "bad publisher source"
                        );
                        ensure!(
                            message.records[0].len() == 2
                                && message.records[0].iter().any(|r| r.kind == 1)
                                && message.records[0].iter().any(|r| r.kind == 13),
                            "missing A/HINFO publication"
                        );
                        found = true;
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            ensure!(
                found,
                "publisher QU response missing; worker={}",
                worker.snapshot()
            );
            while peer.receive()?.is_some() {}
            let truncated = Message {
                flags: 0x0200,
                questions: vec![Question {
                    name: Name::text("appliance.local."),
                    kind: 1,
                    class: 1,
                }],
                ..Message::default()
            };
            peer.send(&truncated.encode(), SocketAddr::new(peer.group(), 5353))?;
            let continuation = Message {
                records: [
                    vec![Record {
                        name: Name::text("appliance.local."),
                        kind: 1,
                        class: 1,
                        ttl: 120,
                        data: Data::Bytes(vec![192, 0, 1, 1]),
                    }],
                    Vec::new(),
                    Vec::new(),
                ],
                ..Message::default()
            };
            peer.send(&continuation.encode(), SocketAddr::new(peer.group(), 5353))?;
            let until = Instant::now() + Duration::from_millis(600);
            while Instant::now() < until {
                if let Some(packet) = peer.receive()? {
                    let message = Message::parse(&packet.bytes)?;
                    ensure!(
                        message.flags & 0x8000 == 0,
                        "publisher ignored known-answer continuation suppression"
                    );
                }
                thread::sleep(Duration::from_millis(5));
            }
            worker.shutdown()?;
            let until = Instant::now() + Duration::from_secs(2);
            let mut goodbye = false;
            while Instant::now() < until {
                if let Some(packet) = peer.receive()? {
                    let message = Message::parse(&packet.bytes)?;
                    if message.flags & 0x8000 != 0
                        && !message.records[0].is_empty()
                        && message.records[0].iter().all(|r| r.ttl == 0)
                    {
                        let kinds = message.records[0]
                            .iter()
                            .map(|r| r.kind)
                            .collect::<Vec<_>>();
                        ensure!(
                            kinds.contains(&1)
                                && kinds.contains(&13)
                                && kinds.contains(&12)
                                && kinds.contains(&33)
                                && kinds.contains(&16),
                            "publication options were not emitted"
                        );
                        ensure!(!kinds.contains(&28), "IPv6 publication was not suppressed");
                        goodbye = true;
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            ensure!(goodbye, "publisher did not send TTL-zero goodbyes");
            let mut worker = crate::worker::Worker::start(
                "mdns-conflict-test".into(),
                None,
                json!({}),
                move || prepare(config, vec!["lan1".into()]),
            )?;
            let conflict = response(vec![Record {
                name: Name::text("appliance.local."),
                kind: 1,
                class: 0x8001,
                ttl: 120,
                data: Data::Bytes(vec![192, 0, 1, 99]),
            }]);
            peer.send(&conflict.encode(), SocketAddr::new(peer.group(), 5353))?;
            let until = Instant::now() + Duration::from_secs(2);
            while worker.snapshot()["state"] != "error" && Instant::now() < until {
                thread::sleep(Duration::from_millis(10));
            }
            ensure!(
                worker.snapshot()["state"] == "error"
                    && worker.snapshot()["error"]
                        .as_str()
                        .is_some_and(|s| s.contains("hostname conflict")),
                "publisher conflict did not fail visibly: {}",
                worker.snapshot()
            );
            worker.shutdown()?;
            Ok(())
        });
    }
    fn reflecting_config() -> netcontrol_core::Config {
        let mut config = netcontrol_core::Config::default();
        for (n, name) in [(1, "lan1"), (2, "lan2")] {
            config.interfaces.push(netcontrol_core::Interface {
                name: name.into(),
                kind: "ethernet".into(),
                role: "lan".into(),
                mtu: 1500,
                up: true,
                addresses: vec![format!("192.0.{n}.1/24")],
                metadata: Default::default(),
                dhcp_relay: Default::default(),
                wireguard: None,
                vlan: None,
            });
        }
        config.mdns.enabled = true;
        config.mdns.reflection.enabled = true;
        config.mdns.interfaces = vec!["lan1".into(), "lan2".into()];
        config
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_recycled_interface_identity_latches_error_until_repair() {
        isolated(|clients| {
            let directory = std::env::current_dir()?
                .join("target")
                .join(format!("mdns-identity-{}", rand::random::<u64>()));
            let mut services = crate::Services::new(crate::ServiceOptions {
                namespace: None,
                state_directory: directory.clone(),
                allow_host_services: true,
                allow_gateway_monitoring: false,
            })?;
            let enabled = reflecting_config().operational_value()?;
            services.apply(
                &netcontrol_core::Config::default().operational_value()?,
                &enabled,
            )?;
            let watch =
                std::sync::Arc::new(std::sync::Mutex::new(LinkMonitor::open(&["lan1".into()])?));
            let old = Port::monitored("lan1", false, &[], watch)?;
            let mut before = socket::interface_snapshot("lan1")?;
            before.1.sort();
            let fd = socket::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
            let mut request: libc::ifreq = unsafe { mem::zeroed() };
            for (out, b) in request.ifr_name.iter_mut().zip(b"lan1") {
                *out = *b as _;
            }
            socket::check(unsafe {
                libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut request)
            })?;
            let mac = unsafe {
                request.ifr_ifru.ifru_hwaddr.sa_data[..6]
                    .iter()
                    .map(|v| *v as u8)
                    .collect::<Vec<_>>()
            };
            let mut body = vec![0u8; 16];
            body[4..8].copy_from_slice(&old.index.to_ne_bytes());
            netlink_flags(17, &body, 5)?;
            create_veth("lan1", "peer1", old.index, Some(&mac))?;
            ensure!(
                socket::ifindex("lan1")? == old.index,
                "kernel did not recycle the requested interface index"
            );
            let mut body = vec![0u8; 16];
            body[4..8].copy_from_slice(&socket::ifindex("peer1")?.to_ne_bytes());
            body.extend(attribute(28, &clients[0].as_raw_fd().to_ne_bytes()));
            netlink(16, &body)?;
            configure_link("lan1", 1, 1)?;
            inside(clients[0].clone(), || configure_link("peer1", 1, 2))?;
            let mut after = socket::interface_snapshot("lan1")?;
            after.1.sort();
            ensure!(
                before == after,
                "replacement did not reproduce the original name/index/addresses: {before:?} != {after:?}"
            );
            let error = old
                .send(
                    &Message::default().encode(),
                    SocketAddr::new(old.group(), 5353),
                )
                .unwrap_err();
            ensure!(
                error.to_string().contains("interface monitor failed"),
                "stale socket send did not fail closed: {error}"
            );
            ensure!(
                old.receive().is_err(),
                "stale socket receive resumed after identity reuse"
            );
            let until = Instant::now() + Duration::from_secs(1);
            loop {
                let status = services.status();
                let row = status["appliance_services"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["name"] == "mdns")
                    .unwrap();
                if row["state"] == "error" {
                    ensure!(
                        row["error"]
                            .as_str()
                            .is_some_and(|error| error.contains("interface monitor failed")),
                        "worker did not report the identity-monitor failure: {row}"
                    );
                    break;
                }
                ensure!(
                    Instant::now() < until,
                    "replacement did not promptly fail worker/status: {row}"
                );
                thread::sleep(Duration::from_millis(5));
            }
            ensure!(
                services.verify_mdns(&enabled).is_err(),
                "failed identity passed verification"
            );
            drop(old);
            services.repair(&enabled)?;
            services.verify_mdns(&enabled)?;
            let peer1 = inside(clients[0].clone(), || Port::open("peer1", false, &[]))?;
            let peer2 = inside(clients[1].clone(), || Port::open("peer2", false, &[]))?;
            let query = Message {
                questions: vec![Question {
                    name: Name::text("_ipp._tcp.local."),
                    kind: 12,
                    class: 1,
                }],
                ..Message::default()
            };
            peer2.send(&query.encode(), SocketAddr::new(peer2.group(), 5353))?;
            received(&peer1, "192.0.1.1".parse()?, false)?;
            let started = Instant::now();
            services.shutdown()?;
            ensure!(
                started.elapsed() < Duration::from_secs(1),
                "repaired worker shutdown was not bounded"
            );
            drop(services);
            std::fs::remove_dir_all(directory)?;
            Ok(())
        });
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_address_refresh_blocks_stale_sockets_and_resumes_both_families() {
        isolated(|clients| {
            let config = reflecting_config().mdns;
            let mut worker = crate::worker::Worker::start(
                "mdns-refresh-test".into(),
                None,
                json!({}),
                move || prepare(config, vec!["lan1".into(), "lan2".into()]),
            )?;
            let watch =
                std::sync::Arc::new(std::sync::Mutex::new(LinkMonitor::open(&["lan1".into()])?));
            let old_v4 = Port::monitored("lan1", false, &[], watch.clone())?;
            let old_v6 = Port::monitored("lan1", true, &[], watch.clone())?;
            // A distinct prefix prevents primary removal from deleting a secondary.
            let mut body = vec![libc::AF_INET as u8, 32, 0, 0];
            body.extend(socket::ifindex("lan1")?.to_ne_bytes());
            body.extend(attribute(1, &[192, 0, 1, 9]));
            body.extend(attribute(2, &[192, 0, 1, 9]));
            netlink(20, &body)?;
            let mut body = vec![libc::AF_INET as u8, 24, 0, 0];
            body.extend(socket::ifindex("lan1")?.to_ne_bytes());
            body.extend(attribute(1, &[192, 0, 1, 1]));
            body.extend(attribute(2, &[192, 0, 1, 1]));
            netlink_flags(21, &body, 5)?;
            let error = old_v4
                .send(
                    &Message::default().encode(),
                    SocketAddr::new(old_v4.group(), 5353),
                )
                .unwrap_err();
            ensure!(
                error.downcast_ref::<AddressRefresh>().is_some(),
                "address change did not defer stale egress: {error}"
            );
            let mut refreshed_v4 = Port::monitored("lan1", false, &[], watch.clone())?;
            ensure!(
                !old_v6.current()?,
                "IPv4 refresh hid stale IPv6 socket generation"
            );
            let mut refreshed_v6 = Port::monitored("lan1", true, &[], watch)?;
            ensure!(
                refreshed_v4.current()? && refreshed_v6.current()?,
                "fresh socket generations are not usable"
            );
            for (ipv6, source) in [(false, "192.0.1.9"), (true, "fe80::1:1")] {
                let peer1 = inside(clients[0].clone(), move || Port::open("peer1", ipv6, &[]))?;
                let peer2 = inside(clients[1].clone(), move || Port::open("peer2", ipv6, &[]))?;
                let query = Message {
                    questions: vec![Question {
                        name: Name::text("_ipp._tcp.local."),
                        kind: 12,
                        class: 1,
                    }],
                    ..Message::default()
                };
                peer2.send(&query.encode(), SocketAddr::new(peer2.group(), 5353))?;
                received(&peer1, source.parse()?, false).with_context(|| {
                    format!("address refresh ipv6={ipv6}, worker={}", worker.snapshot())
                })?;
            }
            ensure!(
                worker.snapshot()["state"] == "running",
                "valid address change failed worker: {}",
                worker.snapshot()
            );
            let started = Instant::now();
            worker.shutdown()?;
            ensure!(
                started.elapsed() < Duration::from_secs(1),
                "address-refresh worker shutdown was not bounded"
            );
            // Deletion/readdition needs fresh memberships even when snapshots match.
            let mut body = vec![libc::AF_INET6 as u8, 64, libc::IFA_F_NODAD as u8, 0];
            body.extend(socket::ifindex("lan1")?.to_ne_bytes());
            body.extend(attribute(
                1,
                &Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1).octets(),
            ));
            netlink_flags(21, &body, 5)?;
            netlink(20, &body)?;
            let mut addresses = socket::interface_snapshot("lan1")?.1;
            addresses.sort();
            ensure!(
                addresses == refreshed_v4.addresses,
                "fixture did not restore identical addresses"
            );
            ensure!(
                refreshed_v4.refresh(&[])?,
                "address deletion failed to restore IPv4 membership"
            );
            ensure!(
                refreshed_v6.refresh(&[])?,
                "IPv4 refresh hid required IPv6 membership restoration"
            );
            Ok(())
        });
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_route_notification_enobufs_latches_failure() {
        isolated(|_| {
            let mut monitor = LinkMonitor::open(&["lan1".into()])?;
            monitor.history.register(socket::ifindex("lan1")?, "lan1")?;
            socket::option(
                monitor.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &4096i32,
            )?;
            for last in 10..74 {
                let mut body = vec![libc::AF_INET as u8, 24, 0, 0];
                body.extend(socket::ifindex("lan1")?.to_ne_bytes());
                body.extend(attribute(1, &[192, 0, 1, last]));
                body.extend(attribute(2, &[192, 0, 1, last]));
                netlink(20, &body)?;
            }
            let error = monitor.drain().unwrap_err().to_string();
            ensure!(
                error.contains(&format!("os error {}", libc::ENOBUFS)),
                "receive loss was not reported as ENOBUFS: {error}"
            );
            ensure!(
                monitor.drain().unwrap_err().to_string() == error,
                "overflow failure was not latched"
            );
            Ok(())
        });
    }
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and fresh Linux network namespace/veth privileges"]
    fn native_mdns_apply_rollback_restart_repair_and_port_ownership() {
        isolated(|clients| {
            let directory = std::env::current_dir()?
                .join("target")
                .join(format!("mdns-services-{}", rand::random::<u64>()));
            let mut services = crate::Services::new(crate::ServiceOptions {
                namespace: None,
                state_directory: directory.clone(),
                allow_host_services: true,
                allow_gateway_monitoring: false,
            })?;
            let mut config = netcontrol_core::Config::default();
            for (n, name) in [(1, "lan1"), (2, "lan2")] {
                config.interfaces.push(netcontrol_core::Interface {
                    name: name.into(),
                    kind: "ethernet".into(),
                    role: "lan".into(),
                    mtu: 1500,
                    up: true,
                    addresses: vec![format!("192.0.{n}.1/24")],
                    metadata: Default::default(),
                    dhcp_relay: Default::default(),
                    wireguard: None,
                    vlan: None,
                });
            }
            config.mdns.enabled = true;
            config.mdns.ipv6 = false;
            config.mdns.reflection.enabled = true;
            config.mdns.interfaces = vec!["lan1".into(), "lan2".into()];
            let disabled = netcontrol_core::Config::default().operational_value()?;
            let enabled = config.operational_value()?;
            let competing = std::net::UdpSocket::bind("0.0.0.0:5353")?;
            ensure!(
                services.apply(&disabled, &enabled).is_err(),
                "conflicting UDP 5353 receiver was accepted"
            );
            drop(competing);
            services.apply(&disabled, &enabled)?;
            services.verify_mdns(&enabled)?;
            ensure!(
                services.status()["appliance_services"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["name"] == "mdns" && r["state"] == "running"),
                "mDNS not running"
            );
            services.shutdown()?;
            services.apply(&enabled, &enabled)?;
            let mut broken = config.clone();
            broken.interfaces[1].name = "missing".into();
            broken.mdns.interfaces[1] = "missing".into();
            ensure!(
                services
                    .apply(&enabled, &broken.operational_value()?)
                    .is_err(),
                "missing link was accepted"
            );
            let row = services.status()["appliance_services"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == "mdns")
                .unwrap()
                .clone();
            ensure!(
                row["state"] == "running",
                "failed apply did not restore previous worker: {row}"
            );
            let fd = socket::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
            let mut request: libc::ifreq = unsafe { mem::zeroed() };
            for (out, b) in request.ifr_name.iter_mut().zip(b"lan1") {
                *out = *b as _;
            }
            request.ifr_ifru.ifru_flags = 0;
            socket::check(unsafe {
                libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request)
            })?;
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                let status = services.status();
                let row = status["appliance_services"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["name"] == "mdns")
                    .unwrap();
                if row["state"] == "error" {
                    ensure!(
                        services.verify_mdns(&enabled).is_err(),
                        "failed mDNS worker passed verification"
                    );
                    break;
                }
                ensure!(
                    Instant::now() < until,
                    "link failure was not visible in service status"
                );
                thread::sleep(Duration::from_millis(10));
            }
            request.ifr_ifru.ifru_flags = libc::IFF_UP as i16;
            socket::check(unsafe {
                libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request)
            })?;
            services.repair(&enabled)?;
            services.verify_mdns(&enabled)?;
            let row = services.status()["appliance_services"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == "mdns")
                .unwrap()
                .clone();
            ensure!(row["state"] == "running", "mDNS repair failed: {row}");
            let mut publishing = config.clone();
            publishing.mdns.reflection.enabled = false;
            publishing.mdns.publishing = netcontrol_core::MDNSPublishing {
                enabled: true,
                hostname: "cross-family".into(),
                addresses: true,
                aaaa_on_ipv4: true,
                ..Default::default()
            };
            let published = publishing.operational_value()?;
            services.apply(&enabled, &published)?;
            let peer = inside(clients[0].clone(), || Port::open("peer1", false, &[]))?;
            let query = Message {
                questions: vec![Question {
                    name: Name::text("cross-family.local."),
                    kind: 255,
                    class: 0x8001,
                }],
                ..Message::default()
            };
            peer.send(&query.encode(), SocketAddr::new(peer.group(), 5353))?;
            let answer = received(&peer, "192.0.1.1".parse()?, true)?;
            ensure!(
                answer.records[0].iter().any(|rr| rr.kind == 28),
                "aaaa_on_ipv4 did not publish AAAA with IPv6 transport disabled"
            );
            publishing.ipv6_enabled = false;
            let suppressed = publishing.operational_value()?;
            services.apply(&published, &suppressed)?;
            services.verify_mdns(&suppressed)?;
            while peer.receive()?.is_some() {}
            peer.send(&query.encode(), SocketAddr::new(peer.group(), 5353))?;
            let answer = received(&peer, "192.0.1.1".parse()?, true)?;
            ensure!(
                answer.records[0].iter().any(|rr| rr.kind == 1)
                    && answer.records[0].iter().all(|rr| rr.kind != 28),
                "global IPv6 policy did not suppress AAAA over IPv4"
            );
            ensure!(
                publishing.mdns.publishing.aaaa_on_ipv4,
                "saved preference was changed"
            );
            services.shutdown()?;
            drop(services);
            std::fs::remove_dir_all(directory)?;
            Ok(())
        });
    }
}
