use anyhow::{Result, ensure};
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Key {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    proto: u8,
    tos: u8,
}
#[derive(Debug, Clone)]
pub(crate) struct Flow {
    pub bytes: u64,
    pub packets: u64,
    pub first: u32,
    pub last: u32,
    pub flags: u8,
    pub changed: std::time::Instant,
}

#[cfg(any(target_os = "linux", test))]
struct FlowTable {
    flows: std::collections::HashMap<Key, Flow>,
    oldest: std::collections::BTreeSet<(std::time::Instant, Key)>,
    capacity: usize,
    fixed_counters: bool,
}

#[cfg(any(target_os = "linux", test))]
impl FlowTable {
    fn new(capacity: usize, fixed_counters: bool) -> Self {
        Self {
            flows: std::collections::HashMap::new(),
            oldest: std::collections::BTreeSet::new(),
            capacity,
            fixed_counters,
        }
    }

    fn record(
        &mut self,
        key: Key,
        bytes: u32,
        flags: u8,
        now: std::time::Instant,
        uptime: u32,
    ) -> Option<(Key, Flow)> {
        let mut evicted = None;
        if self.flows.len() >= self.capacity && !self.flows.contains_key(&key) {
            let (_, old) = self
                .oldest
                .pop_first()
                .expect("full flow table has an oldest flow");
            evicted = Some(self.flows.remove_entry(&old).expect("oldest flow exists"));
        }
        let fresh = || Flow {
            bytes: 0,
            packets: 0,
            first: uptime,
            last: uptime,
            flags: 0,
            changed: now,
        };
        let flow = match self.flows.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let flow = entry.into_mut();
                self.oldest.remove(&(flow.changed, key));
                if self.fixed_counters
                    && (flow.bytes + u64::from(bytes) > u64::from(u32::MAX)
                        || flow.packets == u64::from(u32::MAX))
                {
                    evicted = Some((key, std::mem::replace(flow, fresh())));
                }
                flow
            }
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(fresh()),
        };
        flow.bytes += u64::from(bytes);
        flow.packets += 1;
        flow.last = uptime;
        flow.flags |= flags;
        flow.changed = now;
        self.oldest.insert((now, key));
        evicted
    }

    fn remove(&mut self, key: &Key) -> Option<(Key, Flow)> {
        let item = self.flows.remove_entry(key)?;
        self.oldest.remove(&(item.1.changed, item.0));
        Some(item)
    }
}

#[cfg(any(target_os = "linux", test))]
struct FlowTimeouts {
    general: std::time::Duration,
    tcp: std::time::Duration,
    tcp_fin: std::time::Duration,
    tcp_rst: std::time::Duration,
    udp: std::time::Duration,
    icmp: std::time::Duration,
    maxlife_ms: u64,
    scan_interval: std::time::Duration,
}

#[cfg(any(target_os = "linux", test))]
impl FlowTimeouts {
    fn new(values: &BTreeMap<String, u64>) -> Self {
        let general = values.get("general").copied().unwrap_or(60);
        let idle =
            |key: &str| std::time::Duration::from_secs(values.get(key).copied().unwrap_or(general));
        Self {
            general: std::time::Duration::from_secs(general),
            tcp: idle("tcp"),
            tcp_fin: idle("tcp.fin"),
            tcp_rst: idle("tcp.rst"),
            udp: idle("udp"),
            icmp: idle("icmp"),
            maxlife_ms: values.get("maxlife").copied().unwrap_or(3600) * 1000,
            scan_interval: std::time::Duration::from_secs(
                values.get("expint").copied().unwrap_or(1),
            ),
        }
    }

    fn expired(
        &self,
        key: &Key,
        flow: &Flow,
        now: std::time::Instant,
        uptime: u32,
        fixed_counters: bool,
    ) -> bool {
        let idle = match key.proto {
            6 if flow.flags & 4 != 0 => self.tcp_rst,
            6 if flow.flags & 1 != 0 => self.tcp_fin,
            6 => self.tcp,
            17 => self.udp,
            1 | 58 => self.icmp,
            _ => self.general,
        };
        (!idle.is_zero() && now.duration_since(flow.changed) >= idle)
            || (self.maxlife_ms > 0
                && u64::from(uptime.wrapping_sub(flow.first)) >= self.maxlife_ms)
            || (fixed_counters
                && (flow.bytes > u64::from(u32::MAX) - 65535
                    || flow.packets >= u64::from(u32::MAX)))
    }
}

pub(crate) fn parse(frame: &[u8]) -> Result<Option<(Key, u32, u8)>> {
    ensure!(frame.len() >= 14, "short Ethernet frame");
    let mut pos = 14;
    let mut kind = u16::from_be_bytes([frame[12], frame[13]]);
    for _ in 0..2 {
        if kind == 0x8100 || kind == 0x88a8 {
            ensure!(frame.len() >= pos + 4, "short VLAN");
            kind = u16::from_be_bytes([frame[pos + 2], frame[pos + 3]]);
            pos += 4;
        }
    }
    let (src, dst, proto, tos, ihl, size) = match kind {
        0x0800 => {
            ensure!(
                frame.len() >= pos + 20 && frame[pos] >> 4 == 4,
                "short/invalid IPv4"
            );
            let ihl = (frame[pos] & 15) as usize * 4;
            let size = u16::from_be_bytes([frame[pos + 2], frame[pos + 3]]) as usize;
            ensure!(
                ihl >= 20 && size >= ihl && frame.len() >= pos + ihl,
                "invalid IPv4 length"
            );
            if u16::from_be_bytes([frame[pos + 6], frame[pos + 7]]) & 0x3fff != 0 {
                return Ok(None);
            }
            let src = IpAddr::V4(Ipv4Addr::new(
                frame[pos + 12],
                frame[pos + 13],
                frame[pos + 14],
                frame[pos + 15],
            ));
            let dst = IpAddr::V4(Ipv4Addr::new(
                frame[pos + 16],
                frame[pos + 17],
                frame[pos + 18],
                frame[pos + 19],
            ));
            (src, dst, frame[pos + 9], frame[pos + 1], ihl, size)
        }
        0x86dd => {
            ensure!(
                frame.len() >= pos + 40 && frame[pos] >> 4 == 6,
                "short/invalid IPv6"
            );
            let size = 40 + u16::from_be_bytes([frame[pos + 4], frame[pos + 5]]) as usize;
            ensure!(
                size > 40 || frame[pos + 6] == 59,
                "IPv6 jumbograms unsupported"
            );
            let src = IpAddr::from(<[u8; 16]>::try_from(&frame[pos + 8..pos + 24])?);
            let dst = IpAddr::from(<[u8; 16]>::try_from(&frame[pos + 24..pos + 40])?);
            let mut proto = frame[pos + 6];
            let mut ihl = 40;
            let mut extensions = 0;
            while [0, 43, 60, 51, 44].contains(&proto) {
                if proto == 44 {
                    return Ok(None);
                }
                ensure!(
                    extensions < 8 && ihl + 2 <= size && frame.len() >= pos + ihl + 2,
                    "invalid IPv6 extension chain"
                );
                let next = frame[pos + ihl];
                let length = if proto == 51 {
                    (frame[pos + ihl + 1] as usize + 2) * 4
                } else {
                    (frame[pos + ihl + 1] as usize + 1) * 8
                };
                ensure!(
                    length >= 8 && ihl + length <= size && frame.len() >= pos + ihl + length,
                    "short IPv6 extension"
                );
                ihl += length;
                proto = next;
                extensions += 1;
            }
            let tos = ((frame[pos] & 15) << 4) | (frame[pos + 1] >> 4);
            (src, dst, proto, tos, ihl, size)
        }
        _ => return Ok(None),
    };
    let mut sport = 0;
    let mut dport = 0;
    let mut flags = 0;
    let at = pos + ihl;
    if proto == 6 || proto == 17 {
        ensure!(
            size >= ihl + if proto == 6 { 20 } else { 8 }
                && frame.len() >= at + if proto == 6 { 20 } else { 8 },
            "short transport header"
        );
        sport = u16::from_be_bytes([frame[at], frame[at + 1]]);
        dport = u16::from_be_bytes([frame[at + 2], frame[at + 3]]);
        if proto == 6 {
            let tcp_header = (frame[at + 12] >> 4) as usize * 4;
            ensure!(
                tcp_header >= 20 && tcp_header <= size - ihl && frame.len() >= at + tcp_header,
                "invalid/truncated TCP data offset"
            );
            flags = frame[at + 13];
        } else {
            let udp_size = u16::from_be_bytes([frame[at + 4], frame[at + 5]]) as usize;
            ensure!(
                udp_size >= 8 && udp_size <= size - ihl,
                "invalid UDP length"
            );
        }
    } else if proto == 1 || proto == 58 {
        ensure!(size >= ihl + 2 && frame.len() >= at + 2, "short ICMP");
        dport = u16::from_be_bytes([frame[at], frame[at + 1]]);
    }
    Ok(Some((
        Key {
            src,
            dst,
            sport,
            dport,
            proto,
            tos,
        },
        size as u32,
        flags,
    )))
}
pub(crate) fn v5(
    flows: &[(Key, Flow)],
    uptime: u32,
    sequence: u32,
    epoch: std::time::SystemTime,
    sampling: u32,
) -> Result<Vec<u8>> {
    fixed_export(flows, 5, uptime, sequence, epoch, sampling)
}
pub(crate) fn v1(
    flows: &[(Key, Flow)],
    uptime: u32,
    epoch: std::time::SystemTime,
) -> Result<Vec<u8>> {
    fixed_export(flows, 1, uptime, 0, epoch, 1)
}
fn fixed_export(
    flows: &[(Key, Flow)],
    version: u16,
    uptime: u32,
    sequence: u32,
    epoch: std::time::SystemTime,
    sampling: u32,
) -> Result<Vec<u8>> {
    let header = if version == 1 { 16 } else { 24 };
    ensure!(
        [1, 5].contains(&version)
            && !flows.is_empty()
            && flows.len() <= if version == 1 { 24 } else { 30 }
            && sampling <= 16383,
        "invalid fixed-format NetFlow version/batch/sampling"
    );
    let mut packet = vec![0u8; header + 48 * flows.len()];
    packet[..2].copy_from_slice(&version.to_be_bytes());
    packet[2..4].copy_from_slice(&(flows.len() as u16).to_be_bytes());
    packet[4..8].copy_from_slice(&uptime.to_be_bytes());
    let t = epoch.duration_since(std::time::UNIX_EPOCH)?;
    packet[8..12].copy_from_slice(&(t.as_secs() as u32).to_be_bytes());
    packet[12..16].copy_from_slice(&t.subsec_nanos().to_be_bytes());
    if version == 5 {
        packet[16..20].copy_from_slice(&sequence.to_be_bytes());
        let sample = if sampling > 1 {
            0x4000 | sampling as u16
        } else {
            0
        };
        packet[22..24].copy_from_slice(&sample.to_be_bytes());
    }
    for (i, (key, flow)) in flows.iter().enumerate() {
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (key.src, key.dst) else {
            anyhow::bail!("fixed-format NetFlow v1/v5 cannot represent IPv6")
        };
        let p = &mut packet[header + 48 * i..header + 48 * (i + 1)];
        p[..4].copy_from_slice(&src.octets());
        p[4..8].copy_from_slice(&dst.octets());
        ensure!(
            flow.bytes <= u32::MAX as u64 && flow.packets <= u32::MAX as u64,
            "fixed-format NetFlow counter overflow"
        );
        p[16..20].copy_from_slice(&(flow.packets as u32).to_be_bytes());
        p[20..24].copy_from_slice(&(flow.bytes as u32).to_be_bytes());
        p[24..28].copy_from_slice(&flow.first.to_be_bytes());
        p[28..32].copy_from_slice(&flow.last.to_be_bytes());
        p[32..34].copy_from_slice(&key.sport.to_be_bytes());
        p[34..36].copy_from_slice(&key.dport.to_be_bytes());
        p[if version == 1 { 40 } else { 37 }] = flow.flags;
        p[38] = key.proto;
        p[39] = key.tos;
    }
    Ok(packet)
}
pub(crate) fn template_export(
    flows: &[(Key, Flow)],
    version: u16,
    uptime: u32,
    sequence: u32,
    epoch: std::time::SystemTime,
    sampling: u32,
    domain: u32,
) -> Result<Vec<u8>> {
    ensure!(
        [9, 10].contains(&version) && !flows.is_empty() && flows.len() <= 30,
        "invalid template export version/count"
    );
    let t = epoch.duration_since(std::time::UNIX_EPOCH)?;
    let mut packet = vec![0; if version == 9 { 20 } else { 16 }];
    packet[..2].copy_from_slice(&version.to_be_bytes());
    if version == 9 {
        packet[2..4].copy_from_slice(&((flows.len() + 2) as u16).to_be_bytes());
        packet[4..8].copy_from_slice(&uptime.to_be_bytes());
        packet[8..12].copy_from_slice(&(t.as_secs() as u32).to_be_bytes());
        packet[12..16].copy_from_slice(&sequence.to_be_bytes());
        packet[16..20].copy_from_slice(&domain.to_be_bytes());
    } else {
        packet[4..8].copy_from_slice(&(t.as_secs() as u32).to_be_bytes());
        packet[8..12].copy_from_slice(&sequence.to_be_bytes());
        packet[12..16].copy_from_slice(&domain.to_be_bytes());
    }
    let append_set = |packet: &mut Vec<u8>, id: u16, content: &[u8]| {
        packet.extend_from_slice(&id.to_be_bytes());
        let length = (content.len() + 4 + 3) & !3;
        packet.extend_from_slice(&(length as u16).to_be_bytes());
        packet.extend_from_slice(content);
        while packet.len() % 4 != 0 {
            packet.push(0);
        }
    };
    let mut templates = Vec::new();
    for ipv6 in [false, true] {
        let fields = [
            (if ipv6 { 27 } else { 8 }, if ipv6 { 16 } else { 4 }),
            (if ipv6 { 28 } else { 12 }, if ipv6 { 16 } else { 4 }),
            (7, 2),
            (11, 2),
            (4, 1),
            (5, 1),
            (6, 1),
            (2, 8),
            (1, 8),
            (
                if version == 10 { 152 } else { 22 },
                if version == 10 { 8 } else { 4 },
            ),
            (
                if version == 10 { 153 } else { 21 },
                if version == 10 { 8 } else { 4 },
            ),
            (34, 4),
            (35, 1),
        ];
        templates.extend_from_slice(&(if ipv6 { 257u16 } else { 256u16 }).to_be_bytes());
        templates.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for (id, len) in fields {
            templates.extend_from_slice(&(id as u16).to_be_bytes());
            templates.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }
    append_set(&mut packet, if version == 9 { 0 } else { 2 }, &templates);
    for ipv6 in [false, true] {
        let mut records = Vec::new();
        for (key, flow) in flows.iter().filter(|(key, _)| key.src.is_ipv6() == ipv6) {
            match (key.src, key.dst) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    records.extend_from_slice(&src.octets());
                    records.extend_from_slice(&dst.octets());
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    records.extend_from_slice(&src.octets());
                    records.extend_from_slice(&dst.octets());
                }
                _ => anyhow::bail!("flow address family mismatch"),
            }
            records.extend_from_slice(&key.sport.to_be_bytes());
            records.extend_from_slice(&key.dport.to_be_bytes());
            records.extend_from_slice(&[key.proto, key.tos, flow.flags]);
            records.extend_from_slice(&flow.packets.to_be_bytes());
            records.extend_from_slice(&flow.bytes.to_be_bytes());
            if version == 10 {
                let now = t.as_millis() as u64;
                records.extend_from_slice(
                    &now.saturating_sub(uptime.wrapping_sub(flow.first) as u64)
                        .to_be_bytes(),
                );
                records.extend_from_slice(
                    &now.saturating_sub(uptime.wrapping_sub(flow.last) as u64)
                        .to_be_bytes(),
                );
            } else {
                records.extend_from_slice(&flow.first.to_be_bytes());
                records.extend_from_slice(&flow.last.to_be_bytes());
            }
            records.extend_from_slice(&sampling.to_be_bytes());
            records.push(1);
        }
        if !records.is_empty() {
            append_set(&mut packet, if ipv6 { 257 } else { 256 }, &records);
        }
    }
    ensure!(packet.len() <= 65507, "template export exceeds UDP limit");
    if version == 10 {
        let n = packet.len() as u16;
        packet[2..4].copy_from_slice(&n.to_be_bytes());
    }
    Ok(packet)
}
#[cfg(target_os = "linux")]
const CAPTURE_BATCH: usize = 64;
#[cfg(target_os = "linux")]
const CAPTURE_BUFFER_BYTES: i32 = 4 * 1024 * 1024;

#[cfg(target_os = "linux")]
struct CaptureBatch {
    buffers: Vec<Vec<u8>>,
    lengths: [usize; CAPTURE_BATCH],
}

#[cfg(target_os = "linux")]
impl CaptureBatch {
    fn new(snaplen: usize) -> Self {
        Self {
            buffers: vec![vec![0; snaplen]; CAPTURE_BATCH],
            lengths: [0; CAPTURE_BATCH],
        }
    }

    fn receive(&mut self, fd: std::os::fd::RawFd) -> Result<usize> {
        let mut vectors: [_; CAPTURE_BATCH] = std::array::from_fn(|i| libc::iovec {
            iov_base: self.buffers[i].as_mut_ptr().cast(),
            iov_len: self.buffers[i].len(),
        });
        let mut messages: [_; CAPTURE_BATCH] = std::array::from_fn(|i| {
            let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
            message.msg_hdr.msg_iov = &mut vectors[i];
            message.msg_hdr.msg_iovlen = 1;
            message
        });
        // All buffers and descriptors remain live and stationary through recvmmsg.
        let count = unsafe {
            libc::recvmmsg(
                fd,
                messages.as_mut_ptr(),
                CAPTURE_BATCH as u32,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            return match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Ok(0),
                _ => Err(error.into()),
            };
        }
        for (length, message) in self.lengths.iter_mut().zip(&messages).take(count as usize) {
            *length = message.msg_len as usize;
        }
        Ok(count as usize)
    }

    fn packet(&self, index: usize) -> &[u8] {
        &self.buffers[index][..self.lengths[index]]
    }
}

#[cfg(target_os = "linux")]
fn wait_for_capture(fd: std::os::fd::RawFd) -> Result<()> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut descriptor, 1, 10) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    ensure!(
        descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
        "capture socket poll failed: events {:#x}",
        descriptor.revents
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    config: super::config::Flow,
    ipv6_enabled: bool,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use crate::linux as l;
    use std::{
        mem,
        net::{SocketAddr, UdpSocket},
        os::fd::AsRawFd,
        time::{Duration, Instant, SystemTime},
    };
    let filter = config.filter()?;
    let timeouts = FlowTimeouts::new(&config.timeouts);
    let fd = l::socket(
        libc::AF_PACKET,
        libc::SOCK_RAW,
        (libc::ETH_P_ALL as u16).to_be() as i32,
    )?;
    l::option(
        fd.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &CAPTURE_BUFFER_BYTES,
    )?;
    let index = l::ifindex(&config.interface)?;
    let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    address.sll_ifindex = index as i32;
    l::check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const _,
            mem::size_of_val(&address) as _,
        )
    })?;
    if config.promiscuous {
        let mut req: libc::packet_mreq = unsafe { mem::zeroed() };
        req.mr_ifindex = index as i32;
        req.mr_type = libc::PACKET_MR_PROMISC as u16;
        l::option(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &req,
        )?;
    }
    let collector: SocketAddr = config.collector.parse()?;
    let socket = UdpSocket::bind(if collector.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.connect(collector)?;
    socket.set_write_timeout(Some(Duration::from_millis(250)))?;
    Ok(Box::new(move |ctx| {
        let start = Instant::now();
        let mut capture = CaptureBatch::new(config.snaplen);
        let mut pending = Vec::with_capacity(CAPTURE_BATCH);
        let fixed_counters = [1, 5].contains(&config.export_version);
        let mut table = FlowTable::new(config.max_flows, fixed_counters);
        let mut sampled = 0u64;
        let mut sequence = 0u32;
        let mut exports = 0u64;
        let mut ignored_ipv6 = 0u64;
        let mut malformed = 0u64;
        let mut filtered = 0u64;
        let mut dropped = 0u64;
        ctx.update(|s| {
            s["dropped_packets"] = serde_json::json!("0");
            s["statistics_complete"] = serde_json::json!(true);
        });
        let domain = rand::random::<u32>();
        let mut last_flush = Instant::now();
        let export = |batch: &[(Key, Flow)], sequence: &mut u32, exports: &mut u64| -> Result<()> {
            let begin = Instant::now();
            for chunk in batch.chunks(if config.export_version == 1 { 24 } else { 30 }) {
                ensure!(
                    begin.elapsed() < Duration::from_secs(2),
                    "NetFlow export batch exceeded 2s bound; {} records could not be delivered",
                    batch.len()
                );
                let p = if config.export_version == 1 {
                    v1(chunk, start.elapsed().as_millis() as u32, SystemTime::now())?
                } else if config.export_version == 5 {
                    v5(
                        chunk,
                        start.elapsed().as_millis() as u32,
                        *sequence,
                        SystemTime::now(),
                        config.sampling_rate,
                    )?
                } else {
                    template_export(
                        chunk,
                        config.export_version,
                        start.elapsed().as_millis() as u32,
                        *sequence,
                        SystemTime::now(),
                        config.sampling_rate,
                        domain,
                    )?
                };
                ensure!(socket.send(&p)? == p.len(), "short NetFlow UDP write");
                *sequence = sequence.wrapping_add(if config.export_version == 9 {
                    1
                } else {
                    chunk.len() as u32
                });
                *exports += chunk.len() as u64;
            }
            Ok(())
        };
        while !ctx.stopping() {
            ensure!(
                l::ifindex(&config.interface)? == index,
                "capture interface replaced"
            );
            for _ in 0..4 {
                let count = capture.receive(fd.as_raw_fd())?;
                for packet in 0..count {
                    if ctx.stopping() {
                        break;
                    }
                    sampled = sampled.wrapping_add(1);
                    if sampled % config.sampling_rate as u64 != 0 {
                        continue;
                    }
                    let item = match parse(capture.packet(packet)) {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            ignored_ipv6 += 1;
                            continue;
                        }
                        Err(_) => {
                            malformed += 1;
                            continue;
                        }
                    };
                    let (key, bytes, flags) = item;
                    if (!ipv6_enabled && key.src.is_ipv6())
                        || !filter.matches(key.src.is_ipv6(), key.proto)
                    {
                        filtered += 1;
                        continue;
                    }
                    if [1, 5].contains(&config.export_version) && key.src.is_ipv6() {
                        ignored_ipv6 += 1;
                        continue;
                    }
                    if key.proto == 17 && key.dst == collector.ip() && key.dport == collector.port()
                    {
                        continue;
                    }
                    let now = Instant::now();
                    let uptime = now.duration_since(start).as_millis() as u32;
                    if let Some(item) = table.record(key, bytes, flags, now, uptime) {
                        pending.push(item);
                    }
                }
                if !pending.is_empty() {
                    export(&pending, &mut sequence, &mut exports)?;
                    pending.clear();
                }
                if count < CAPTURE_BATCH || ctx.stopping() {
                    break;
                }
            }
            if last_flush.elapsed() >= timeouts.scan_interval {
                let now = Instant::now();
                let uptime = now.duration_since(start).as_millis() as u32;
                let keys: Vec<Key> = table
                    .flows
                    .iter()
                    .filter(|(k, v)| timeouts.expired(k, v, now, uptime, fixed_counters))
                    .map(|(k, _)| *k)
                    .collect();
                let batch: Vec<_> = keys.into_iter().filter_map(|k| table.remove(&k)).collect();
                export(&batch, &mut sequence, &mut exports)?;
                last_flush = Instant::now();
                // PACKET_STATISTICS is reset by getsockopt; accumulate drops explicitly.
                let mut stats: libc::tpacket_stats = unsafe { mem::zeroed() };
                let mut size = mem::size_of_val(&stats) as libc::socklen_t;
                l::check(unsafe {
                    libc::getsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_PACKET,
                        libc::PACKET_STATISTICS,
                        &mut stats as *mut _ as *mut _,
                        &mut size,
                    )
                })?;
                dropped += u64::from(stats.tp_drops);
                ctx.update(|s| {
                    s["dropped_packets"] = serde_json::json!(dropped.to_string());
                    s["statistics_complete"] = serde_json::json!(dropped == 0);
                    s["active_flows"] = serde_json::json!(table.flows.len());
                    s["exported_flows"] = serde_json::json!(exports);
                    s["excluded_packets"] = serde_json::json!(ignored_ipv6);
                    s["filtered_packets"] = serde_json::json!(filtered);
                    s["malformed_packets"] = serde_json::json!(malformed);
                });
            }
            wait_for_capture(fd.as_raw_fd())?;
        }
        export(
            &table.flows.into_iter().collect::<Vec<_>>(),
            &mut sequence,
            &mut exports,
        )?;
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn flow_test_key(index: u32) -> Key {
        Key {
            src: Ipv4Addr::from(0x0a000000 | index).into(),
            dst: "198.51.100.1".parse().unwrap(),
            sport: 12345,
            dport: 443,
            proto: 6,
            tos: 0,
        }
    }

    fn assert_flow_index(table: &FlowTable) {
        assert_eq!(table.flows.len(), table.oldest.len());
        assert!(table.flows.len() <= table.capacity);
        for (key, flow) in &table.flows {
            assert!(table.oldest.contains(&(flow.changed, *key)));
        }
    }

    #[test]
    fn flow_table_preserves_counts_flags_lru_and_removal() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut table = FlowTable::new(2, true);
        let a = flow_test_key(1);
        let b = flow_test_key(2);
        let c = flow_test_key(3);
        assert!(table.record(a, 40, 2, now, u32::MAX - 5).is_none());
        assert!(table.record(b, 50, 0, now, u32::MAX - 5).is_none());
        assert_flow_index(&table);
        assert!(
            table
                .record(a, 60, 0x10, now + Duration::from_millis(9), 3)
                .is_none()
        );
        let evicted = table
            .record(c, 70, 0, now + Duration::from_millis(10), 4)
            .unwrap();
        assert_eq!(evicted.0, b);
        assert_eq!(evicted.1.packets, 1);
        assert_flow_index(&table);
        let (_, flow) = table.remove(&a).unwrap();
        assert_eq!((flow.packets, flow.bytes, flow.flags), (2, 100, 0x12));
        assert_eq!((flow.first, flow.last), (u32::MAX - 5, 3));
        assert!(table.remove(&a).is_none());
        assert_flow_index(&table);
        assert!(
            table
                .record(b, 80, 0, now + Duration::from_millis(11), 5)
                .is_none()
        );
        assert_flow_index(&table);
    }

    #[test]
    fn flow_table_rolls_fixed_counters_without_losing_incoming_packet() {
        use std::time::{Duration, Instant};
        for fixed in [false, true] {
            let now = Instant::now();
            let key = flow_test_key(1);
            let mut table = FlowTable::new(1, fixed);
            table.record(key, 40, 1, now, 1);
            table.flows.get_mut(&key).unwrap().bytes = u64::from(u32::MAX) - 10;
            let evicted = table.record(key, 64, 0x10, now + Duration::from_millis(1), 2);
            assert_eq!(evicted.is_some(), fixed);
            let flow = &table.flows[&key];
            if fixed {
                let (_, old) = evicted.unwrap();
                assert_eq!(old.bytes, u64::from(u32::MAX) - 10);
                assert_eq!(
                    (flow.packets, flow.bytes, flow.first, flow.flags),
                    (1, 64, 2, 0x10)
                );
            } else {
                assert_eq!(flow.bytes, u64::from(u32::MAX) + 54);
                assert_eq!((flow.packets, flow.first, flow.flags), (2, 1, 0x11));
            }
            table.flows.get_mut(&key).unwrap().packets = u64::from(u32::MAX);
            let evicted = table.record(key, 20, 4, now + Duration::from_millis(2), 3);
            assert_eq!(evicted.is_some(), fixed);
            assert_eq!(
                table.flows[&key].packets,
                if fixed { 1 } else { u64::from(u32::MAX) + 1 }
            );
            assert_flow_index(&table);
        }
    }

    #[test]
    fn flow_timeouts_preserve_classes_priority_defaults_and_disabled_values() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut table = FlowTable::new(1, false);
        let key = flow_test_key(1);
        table.record(key, 40, 0, now, 0);
        let mut flow = table.remove(&key).unwrap().1;
        let timeouts = FlowTimeouts::new(&BTreeMap::from([
            ("general".into(), 10),
            ("tcp".into(), 100),
            ("tcp.fin".into(), 3),
            ("tcp.rst".into(), 1),
            ("udp".into(), 0),
            ("icmp".into(), 2),
            ("maxlife".into(), 0),
            ("expint".into(), 0),
        ]));
        assert!(timeouts.scan_interval.is_zero());
        for (proto, flags, seconds) in [
            (6, 0, 100),
            (6, 1, 3),
            (6, 4, 1),
            (6, 5, 1),
            (1, 0, 2),
            (58, 0, 2),
            (47, 0, 10),
        ] {
            let key = Key { proto, ..key };
            flow.flags = flags;
            assert!(!timeouts.expired(
                &key,
                &flow,
                now + Duration::from_secs(seconds - 1),
                0,
                false
            ));
            assert!(timeouts.expired(&key, &flow, now + Duration::from_secs(seconds), 0, false));
        }
        assert!(!timeouts.expired(
            &Key { proto: 17, ..key },
            &flow,
            now + Duration::from_secs(1000),
            0,
            false
        ));
        let defaults = FlowTimeouts::new(&BTreeMap::new());
        assert_eq!(defaults.general, Duration::from_secs(60));
        assert_eq!(defaults.tcp_fin, defaults.general);
        assert_eq!(defaults.maxlife_ms, 3_600_000);
        assert_eq!(defaults.scan_interval, Duration::from_secs(1));
        let fallback =
            FlowTimeouts::new(&BTreeMap::from([("general".into(), 7), ("tcp".into(), 99)]));
        assert_eq!(fallback.tcp_fin, Duration::from_secs(7));
        assert_eq!(fallback.tcp_rst, Duration::from_secs(7));
    }

    #[test]
    fn flow_expiry_preserves_uptime_wrap_and_fixed_counter_thresholds() {
        use std::time::Instant;
        let now = Instant::now();
        let key = flow_test_key(1);
        let mut table = FlowTable::new(1, true);
        table.record(key, 40, 0, now, u32::MAX - 500);
        let mut flow = table.remove(&key).unwrap().1;
        let timeouts =
            FlowTimeouts::new(&BTreeMap::from([("tcp".into(), 0), ("maxlife".into(), 1)]));
        assert!(!timeouts.expired(&key, &flow, now, 498, true));
        assert!(timeouts.expired(&key, &flow, now, 499, true));
        let no_age = FlowTimeouts::new(&BTreeMap::from([("tcp".into(), 0), ("maxlife".into(), 0)]));
        flow.bytes = u64::from(u32::MAX) - 65535;
        assert!(!no_age.expired(&key, &flow, now, 0, true));
        flow.bytes += 1;
        assert!(no_age.expired(&key, &flow, now, 0, true));
        assert!(!no_age.expired(&key, &flow, now, 0, false));
        flow.bytes = 40;
        flow.packets = u64::from(u32::MAX);
        assert!(no_age.expired(&key, &flow, now, 0, true));
        assert!(!no_age.expired(&key, &flow, now, 0, false));
    }

    #[test]
    #[ignore = "manual release-mode flow-accounting throughput measurement"]
    fn flow_accounting_throughput() {
        use std::time::Instant;
        const CAPACITY: usize = 4096;
        const PACKETS: u32 = 1_000_000;
        let keys: Vec<_> = (0..CAPACITY as u32).map(flow_test_key).collect();
        for churn in [false, true] {
            let mut table = FlowTable::new(CAPACITY, true);
            let mut evicted = 0;
            let begin = Instant::now();
            for packet in 0..PACKETS {
                let key = if churn {
                    flow_test_key(packet)
                } else {
                    keys[packet as usize % CAPACITY]
                };
                if let Some((_, flow)) = table.record(key, 64, 0x10, Instant::now(), packet) {
                    evicted += flow.packets;
                }
            }
            let elapsed = begin.elapsed();
            assert_eq!(table.flows.len(), CAPACITY);
            assert_eq!(
                evicted + table.flows.values().map(|flow| flow.packets).sum::<u64>(),
                u64::from(PACKETS)
            );
            println!(
                "flow accounting churn={churn}: {PACKETS} packets in {elapsed:?} ({:.0} packets/s)",
                f64::from(PACKETS) / elapsed.as_secs_f64()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_batches_preserve_order_boundaries_and_snaplen() -> Result<()> {
        use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram, time::Duration};
        let (sender, receiver) = UnixDatagram::pair()?;
        receiver.set_nonblocking(true)?;
        sender.set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut batch = CaptureBatch::new(64);
        assert_eq!(batch.receive(receiver.as_raw_fd())?, 0);
        for i in 0..CAPTURE_BATCH + 1 {
            sender.send(&[i as u8; 128])?;
        }
        wait_for_capture(receiver.as_raw_fd())?;
        assert_eq!(batch.receive(receiver.as_raw_fd())?, CAPTURE_BATCH);
        for i in 0..CAPTURE_BATCH {
            assert_eq!(batch.packet(i), &[i as u8; 64]);
        }
        assert_eq!(batch.receive(receiver.as_raw_fd())?, 1);
        assert_eq!(batch.packet(0), &[CAPTURE_BATCH as u8; 64]);
        sender.send(b"short")?;
        sender.send(b"")?;
        assert_eq!(batch.receive(receiver.as_raw_fd())?, 2);
        assert_eq!(batch.packet(0), b"short");
        assert_eq!(batch.packet(1), b"");
        assert_eq!(batch.receive(receiver.as_raw_fd())?, 0);
        assert!(batch.receive(-1).is_err());
        assert!(wait_for_capture(i32::MAX).is_err());
        Ok(())
    }

    #[test]
    fn netflow_v1_exact_header_records_lengths_and_endian_fields() {
        let key = Key {
            src: "192.0.2.1".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            sport: 0x1234,
            dport: 0xabcd,
            proto: 6,
            tos: 0x2e,
        };
        let flow = Flow {
            bytes: 0x0a0b0c0d,
            packets: 0x01020304,
            first: 0x11223344,
            last: 0x55667788,
            flags: 0x13,
            changed: std::time::Instant::now(),
        };
        let epoch = std::time::UNIX_EPOCH + std::time::Duration::new(0x10203040, 100000000);
        let p = v1(&[(key, flow.clone())], 0x99aabbcc, epoch).unwrap();
        let header = [
            0, 1, 0, 1, 0x99, 0xaa, 0xbb, 0xcc, 0x10, 0x20, 0x30, 0x40, 0x05, 0xf5, 0xe1, 0x00,
        ];
        let record = [
            192, 0, 2, 1, 198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0x0a, 0x0b, 0x0c,
            0x0d, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x12, 0x34, 0xab, 0xcd, 0, 0, 6,
            0x2e, 0x13, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(p.len(), 16 + 48);
        assert_eq!(&p[..16], &header);
        assert_eq!(&p[16..], &record);
        let records = vec![(key, flow.clone()); 24];
        let p = v1(&records, 0, epoch).unwrap();
        assert_eq!(p.len(), 16 + 24 * 48);
        assert_eq!(&p[2..4], &24u16.to_be_bytes());
        for r in p[16..].chunks_exact(48) {
            assert_eq!(r, &record);
        }
        assert!(v1(&vec![(key, flow.clone()); 25], 0, epoch).is_err());
        assert!(v1(&[], 0, epoch).is_err());
        let mut ipv6 = key;
        ipv6.src = "2001:db8::1".parse().unwrap();
        ipv6.dst = "2001:db8::2".parse().unwrap();
        assert!(v1(&[(ipv6, flow.clone())], 0, epoch).is_err());
        let mut overflow = flow;
        overflow.bytes = u32::MAX as u64 + 1;
        assert!(v1(&[(key, overflow)], 0, epoch).is_err());
    }
    #[test]
    fn ethernet_ipv4_udp_and_v5() {
        let mut frame = vec![0; 42];
        frame[12..14].copy_from_slice(&[8, 0]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&28u16.to_be_bytes());
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        frame[34..38].copy_from_slice(&[0, 53, 0, 80]);
        frame[38..40].copy_from_slice(&8u16.to_be_bytes());
        let (k, bytes, flags) = parse(&frame).unwrap().unwrap();
        assert_eq!(bytes, 28);
        assert_eq!(k.sport, 53);
        let f = Flow {
            bytes: 28,
            packets: 1,
            first: 1,
            last: 2,
            flags,
            changed: std::time::Instant::now(),
        };
        let p = v5(&[(k, f)], 3, 7, std::time::UNIX_EPOCH, 1).unwrap();
        assert_eq!(p.len(), 72);
        assert_eq!(&p[..4], &[0, 5, 0, 1]);
        assert_eq!(&p[24..28], &[192, 0, 2, 1]);
        assert_eq!(p[62], 17);
        frame[20] = 0x20;
        assert!(parse(&frame).unwrap().is_none());
        assert!(parse(&frame[..15]).is_err());
    }
    #[test]
    fn malformed_capture_never_panics_or_exports_wrong_family() {
        for length in 0..512 {
            let data: Vec<_> = (0..length).map(|_| rand::random()).collect();
            let _ = parse(&data);
        }
        let mut ipv6 = vec![0; 54];
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert!(parse(&ipv6).is_err());
        assert!(v5(&[], 0, 0, std::time::UNIX_EPOCH, 1).is_err());
    }
    fn ipv6_udp() -> Vec<u8> {
        let mut frame = vec![0; 62];
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&8u16.to_be_bytes());
        frame[20] = 17;
        frame[21] = 64;
        frame[22..38].copy_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        frame[38..54].copy_from_slice(
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        frame[54..58].copy_from_slice(&[0x12, 0x34, 0x23, 0x45]);
        frame[58..60].copy_from_slice(&8u16.to_be_bytes());
        frame
    }
    #[test]
    fn ipv6_parser_v9_and_ipfix_wire_fields() {
        let (key, size, flags) = parse(&ipv6_udp()).unwrap().unwrap();
        assert!(key.src.is_ipv6());
        assert_eq!(size, 48);
        assert_eq!(key.sport, 0x1234);
        let flow = Flow {
            bytes: u32::MAX as u64 + 17,
            packets: 9,
            first: 100,
            last: 150,
            flags,
            changed: std::time::Instant::now(),
        };
        assert!(v5(&[(key, flow.clone())], 200, 7, std::time::UNIX_EPOCH, 1).is_err());
        for version in [9, 10] {
            let epoch = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_800_000_000_000);
            let p = template_export(&[(key, flow.clone())], version, 200, 7, epoch, 1000000, 123)
                .unwrap();
            assert_eq!(&p[..2], &version.to_be_bytes());
            let header = if version == 9 { 20 } else { 16 };
            if version == 9 {
                assert_eq!(&p[2..4], &3u16.to_be_bytes());
                assert_eq!(&p[12..16], &7u32.to_be_bytes())
            } else {
                assert_eq!(
                    u16::from_be_bytes(p[2..4].try_into().unwrap()) as usize,
                    p.len()
                );
                assert_eq!(&p[8..12], &7u32.to_be_bytes());
            }
            assert_eq!(
                u16::from_be_bytes(p[header..header + 2].try_into().unwrap()),
                if version == 9 { 0 } else { 2 }
            );
            let template_size =
                u16::from_be_bytes(p[header + 2..header + 4].try_into().unwrap()) as usize;
            assert_eq!(template_size, 116);
            let data = header + template_size;
            assert_eq!(&p[data..data + 2], &257u16.to_be_bytes());
            let record = &p[data + 4..];
            assert_eq!(
                &record[..16],
                &"2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            );
            assert_eq!(
                u64::from_be_bytes(record[47..55].try_into().unwrap()),
                u32::MAX as u64 + 17
            );
            if version == 10 {
                assert_eq!(
                    u64::from_be_bytes(record[55..63].try_into().unwrap()),
                    1_799_999_999_900
                );
            }
            assert_eq!(record.last(), Some(&1));
        }
    }
    #[test]
    fn ipv6_fragment_and_malformed_extension_are_explicitly_excluded() {
        let mut frame = ipv6_udp();
        frame[20] = 44;
        assert!(parse(&frame).unwrap().is_none());
        frame[20] = 0;
        frame[55] = 200;
        assert!(parse(&frame).is_err());
    }
}
