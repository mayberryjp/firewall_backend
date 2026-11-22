use anyhow::{Context, Result, ensure};
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
    expiry: Option<std::time::Instant>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
struct ExportCounters {
    flows: u64,
    packets: u64,
    bytes: u64,
    flow_packets: u64,
    flow_bytes: u64,
    errors: u64,
}

#[cfg(any(target_os = "linux", test))]
impl ExportCounters {
    fn sent(&mut self, batch: &[(Key, Flow)], bytes: usize) {
        self.flows = self.flows.saturating_add(batch.len() as u64);
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
        for (_, flow) in batch {
            self.flow_packets = self.flow_packets.saturating_add(flow.packets);
            self.flow_bytes = self.flow_bytes.saturating_add(flow.bytes);
        }
    }

    fn publish(&self, status: &mut serde_json::Value) {
        status["exported_flows"] = serde_json::json!(self.flows);
        for (field, value) in [
            ("exported_packets", self.packets),
            ("exported_bytes", self.bytes),
            ("exported_flow_packets", self.flow_packets),
            ("exported_flow_bytes", self.flow_bytes),
            ("export_errors", self.errors),
        ] {
            status[field] = serde_json::json!(value.to_string());
        }
    }
}

#[cfg(any(target_os = "linux", test))]
trait DatagramSender {
    fn limit(&mut self) -> Result<usize>;
    fn send(&mut self, packet: &[u8]) -> std::io::Result<usize>;
    fn reduce_limit(&mut self, failed_size: usize) -> Result<()>;
}

#[cfg(any(target_os = "linux", test))]
struct ExportSession<S> {
    sender: S,
    version: u16,
    sampling: u32,
    start: std::time::Instant,
    domain: u32,
    sequence: u32,
    template_refreshed: Option<std::time::Instant>,
    data_messages: u32,
    counters: ExportCounters,
}

#[cfg(any(target_os = "linux", test))]
impl<S: DatagramSender> ExportSession<S> {
    fn new(sender: S, version: u16, sampling: u32) -> Result<Self> {
        super::config::validate_sampling(version, sampling)?;
        Ok(Self {
            sender,
            version,
            sampling,
            start: std::time::Instant::now(),
            domain: rand::random(),
            sequence: 0,
            template_refreshed: None,
            data_messages: 0,
            counters: ExportCounters::default(),
        })
    }

    fn publish(&mut self, status: &mut serde_json::Value) {
        self.counters.publish(status);
    }

    fn check_deadline(begin: std::time::Instant) -> Result<()> {
        ensure!(
            begin.elapsed() < std::time::Duration::from_secs(2),
            "flow export batch exceeded two-second deadline"
        );
        Ok(())
    }

    fn recover_size(&mut self, size: usize) -> Result<()> {
        self.sender.reduce_limit(size)?;
        let limit = self.sender.limit()?;
        ensure!(
            limit < size,
            "EMSGSIZE recovery did not reduce the message budget"
        );
        tracing::warn!(
            failed_payload_bytes = size,
            message_size_limit = limit,
            "flow export EMSGSIZE; reducing payload budget and retrying unsent records"
        );
        Ok(())
    }

    fn refresh_inner(&mut self, now: std::time::Instant, begin: std::time::Instant) -> Result<()> {
        if self.version != 10
            || (self
                .template_refreshed
                .is_some_and(|last| now.duration_since(last) < std::time::Duration::from_secs(600))
                && self.data_messages < 20)
        {
            return Ok(());
        }
        let copies = if self.template_refreshed.is_none() {
            2
        } else {
            1
        };
        for _ in 0..copies {
            loop {
                Self::check_deadline(begin)?;
                let limit = self.sender.limit()?;
                let packet = ipfix_templates(
                    self.sequence,
                    std::time::SystemTime::now(),
                    self.domain,
                    limit,
                )?;
                match self.sender.send(&packet) {
                    Ok(n) => {
                        ensure!(n == packet.len(), "short IPFIX template UDP write");
                        self.counters.sent(&[], n);
                        break;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                        self.recover_size(packet.len())?;
                    }
                    Err(error) => return Err(error).context("IPFIX template UDP send"),
                }
            }
        }
        self.template_refreshed = Some(now);
        self.data_messages = 0;
        Ok(())
    }

    fn maintain_at(&mut self, now: std::time::Instant) -> Result<()> {
        let result = self.refresh_inner(now, std::time::Instant::now());
        if result.is_err() {
            self.counters.errors = self.counters.errors.saturating_add(1);
        }
        result
    }

    fn export(&mut self, batch: &[(Key, Flow)]) -> Result<()> {
        let begin = std::time::Instant::now();
        let result = (|| {
            let mut offset = 0;
            while offset < batch.len() {
                Self::check_deadline(begin)?;
                self.refresh_inner(std::time::Instant::now(), begin)?;
                let limit = self.sender.limit()?;
                let count = record_batch_len(&batch[offset..], self.version, limit)?;
                let chunk = &batch[offset..offset + count];
                let uptime = self.start.elapsed().as_millis() as u32;
                let epoch = std::time::SystemTime::now();
                let packet = if self.version == 5 {
                    v5(chunk, uptime, self.sequence, epoch, self.sampling, limit)?
                } else {
                    ipfix_data(
                        chunk,
                        uptime,
                        self.sequence,
                        epoch,
                        self.sampling,
                        self.domain,
                        limit,
                    )?
                };
                match self.sender.send(&packet) {
                    Ok(n) => {
                        ensure!(n == packet.len(), "short flow export UDP write");
                        self.counters.sent(chunk, n);
                        self.sequence = self.sequence.wrapping_add(count as u32);
                        if self.version == 10 {
                            self.data_messages += 1;
                        }
                        offset += count;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                        self.recover_size(packet.len())?;
                    }
                    Err(error) => return Err(error).context("flow export UDP send"),
                }
            }
            self.refresh_inner(std::time::Instant::now(), begin)
        })();
        if result.is_err() {
            self.counters.errors = self.counters.errors.saturating_add(1);
        }
        result
    }
}

#[cfg(any(target_os = "linux", test))]
fn payload_budget(configured: usize, ipv6: bool, mtu: Option<usize>) -> Result<usize> {
    let headers = if ipv6 { 48 } else { 28 };
    let mtu = mtu.unwrap_or(512);
    ensure!(mtu > headers, "route MTU cannot fit IP and UDP headers");
    Ok(configured.min(mtu - headers))
}

#[cfg(target_os = "linux")]
struct UdpSender {
    socket: std::net::UdpSocket,
    ipv6: bool,
    configured: usize,
    budget: usize,
}

#[cfg(target_os = "linux")]
impl UdpSender {
    fn new(collector: std::net::SocketAddr, configured: usize) -> Result<Self> {
        use std::os::fd::AsRawFd;
        let ipv6 = collector.is_ipv6();
        let socket = std::net::UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" })?;
        crate::linux::option(
            socket.as_raw_fd(),
            if ipv6 {
                libc::IPPROTO_IPV6
            } else {
                libc::IPPROTO_IP
            },
            if ipv6 {
                libc::IPV6_MTU_DISCOVER
            } else {
                libc::IP_MTU_DISCOVER
            },
            &if ipv6 {
                libc::IPV6_PMTUDISC_DO
            } else {
                libc::IP_PMTUDISC_DO
            },
        )?;
        if ipv6 {
            crate::linux::option(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                &1i32,
            )?;
        }
        socket.connect(collector)?;
        socket.set_nonblocking(true)?;
        let mut sender = Self {
            socket,
            ipv6,
            configured,
            budget: configured,
        };
        sender.limit()?;
        Ok(sender)
    }
}

#[cfg(target_os = "linux")]
impl DatagramSender for UdpSender {
    fn limit(&mut self) -> Result<usize> {
        use std::{mem, os::fd::AsRawFd};
        let mut mtu = 0i32;
        let mut size = mem::size_of_val(&mtu) as libc::socklen_t;
        crate::linux::check(unsafe {
            libc::getsockopt(
                self.socket.as_raw_fd(),
                if self.ipv6 {
                    libc::IPPROTO_IPV6
                } else {
                    libc::IPPROTO_IP
                },
                if self.ipv6 {
                    libc::IPV6_MTU
                } else {
                    libc::IP_MTU
                },
                &mut mtu as *mut _ as *mut libc::c_void,
                &mut size,
            )
        })?;
        ensure!(
            size as usize == mem::size_of_val(&mtu) && mtu >= 0,
            "invalid route MTU response"
        );
        let mtu = if mtu == 0 {
            tracing::warn!("flow export route MTU unknown; limiting total IP packet to 512 bytes");
            None
        } else {
            Some(mtu as usize)
        };
        self.budget = self
            .budget
            .min(payload_budget(self.configured, self.ipv6, mtu)?);
        Ok(self.budget)
    }

    fn send(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.socket.send(packet)
    }

    fn reduce_limit(&mut self, failed_size: usize) -> Result<()> {
        self.limit()?;
        ensure!(
            failed_size > 1,
            "EMSGSIZE: no smaller flow export message is possible"
        );
        self.budget = self.budget.min(failed_size - 1);
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
struct FlowTable {
    flows: BTreeMap<Key, Flow>,
    oldest: std::collections::BTreeSet<(std::time::Instant, Key)>,
    expiry: std::collections::BTreeSet<(std::time::Instant, Key)>,
    capacity: usize,
    fixed_counters: bool,
    timeouts: FlowTimeouts,
}

#[cfg(any(target_os = "linux", test))]
impl FlowTable {
    fn new(capacity: usize, fixed_counters: bool, timeouts: FlowTimeouts) -> Self {
        Self {
            flows: BTreeMap::new(),
            oldest: std::collections::BTreeSet::new(),
            expiry: std::collections::BTreeSet::new(),
            capacity,
            fixed_counters,
            timeouts,
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
            let (_, old) = *self
                .oldest
                .first()
                .expect("full flow table has an oldest flow");
            evicted = self.remove(&old);
        }
        let fresh = || Flow {
            bytes: 0,
            packets: 0,
            first: uptime,
            last: uptime,
            flags: 0,
            changed: now,
            expiry: None,
        };
        let flow = match self.flows.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => {
                let flow = entry.into_mut();
                self.oldest.remove(&(flow.changed, key));
                if let Some(deadline) = flow.expiry {
                    self.expiry.remove(&(deadline, key));
                }
                if self.fixed_counters
                    && (flow.bytes + u64::from(bytes) > u64::from(u32::MAX)
                        || flow.packets == u64::from(u32::MAX))
                {
                    evicted = Some((key, std::mem::replace(flow, fresh())));
                }
                flow
            }
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(fresh()),
        };
        flow.bytes += u64::from(bytes);
        flow.packets += 1;
        flow.last = uptime;
        flow.flags |= flags;
        flow.changed = now;
        flow.expiry = self
            .timeouts
            .deadline(&key, flow, now, uptime, self.fixed_counters);
        if let Some(deadline) = flow.expiry {
            self.expiry.insert((deadline, key));
        }
        self.oldest.insert((now, key));
        evicted
    }

    fn remove(&mut self, key: &Key) -> Option<(Key, Flow)> {
        let item = self.flows.remove_entry(key)?;
        self.oldest.remove(&(item.1.changed, item.0));
        if let Some(deadline) = item.1.expiry {
            self.expiry.remove(&(deadline, item.0));
        }
        Some(item)
    }

    fn expired_batch(&mut self, now: std::time::Instant, limit: usize) -> Vec<(Key, Flow)> {
        let mut batch = Vec::new();
        while batch.len() < limit {
            let Some(&(deadline, key)) = self.expiry.first() else {
                break;
            };
            if deadline > now {
                break;
            }
            batch.push(self.remove(&key).expect("expiry index references a flow"));
        }
        batch
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
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

    fn deadline(
        &self,
        key: &Key,
        flow: &Flow,
        now: std::time::Instant,
        uptime: u32,
        fixed_counters: bool,
    ) -> Option<std::time::Instant> {
        let idle = match key.proto {
            6 if flow.flags & 4 != 0 => self.tcp_rst,
            6 if flow.flags & 1 != 0 => self.tcp_fin,
            6 => self.tcp,
            17 => self.udp,
            1 | 58 => self.icmp,
            _ => self.general,
        };
        let idle = (!idle.is_zero()).then(|| flow.changed + idle);
        let maxlife = (self.maxlife_ms > 0).then(|| {
            now + std::time::Duration::from_millis(
                self.maxlife_ms
                    .saturating_sub(u64::from(uptime.wrapping_sub(flow.first))),
            )
        });
        let counters = (fixed_counters
            && (flow.bytes > u64::from(u32::MAX) - 65535 || flow.packets >= u64::from(u32::MAX)))
        .then_some(now);
        [idle, maxlife, counters].into_iter().flatten().min()
    }

    #[cfg(test)]
    fn expired(
        &self,
        key: &Key,
        flow: &Flow,
        now: std::time::Instant,
        uptime: u32,
        fixed_counters: bool,
    ) -> bool {
        self.deadline(key, flow, now, uptime, fixed_counters)
            .is_some_and(|deadline| deadline <= now)
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
fn record_batch_len(flows: &[(Key, Flow)], version: u16, limit: usize) -> Result<usize> {
    ensure!([5, 10].contains(&version), "export version must be 5 or 10");
    let mut size = if version == 5 { 24 } else { 16 };
    let mut families = [false; 2];
    let mut count = 0;
    for (key, _) in flows {
        ensure!(
            key.src.is_ipv6() == key.dst.is_ipv6(),
            "flow address family mismatch"
        );
        ensure!(
            version != 5 || key.src.is_ipv4(),
            "NetFlow v5 cannot represent IPv6"
        );
        let family = usize::from(key.src.is_ipv6());
        let record_size = if version == 5 {
            48
        } else if family == 1 {
            76
        } else {
            52
        };
        let set_header = if version == 10 && !families[family] {
            4
        } else {
            0
        };
        if size + set_header + record_size > limit {
            break;
        }
        size += set_header + record_size;
        families[family] = true;
        count += 1;
    }
    ensure!(
        count > 0,
        "message budget of {limit} bytes cannot fit one flow record"
    );
    Ok(count)
}

fn v5(
    flows: &[(Key, Flow)],
    uptime: u32,
    sequence: u32,
    epoch: std::time::SystemTime,
    sampling: u32,
    limit: usize,
) -> Result<Vec<u8>> {
    super::config::validate_sampling(5, sampling)?;
    ensure!(
        limit <= 65507 && record_batch_len(flows, 5, limit)? == flows.len(),
        "NetFlow v5 batch exceeds message budget"
    );
    let mut packet = vec![0u8; 24 + 48 * flows.len()];
    packet[..2].copy_from_slice(&5u16.to_be_bytes());
    packet[2..4].copy_from_slice(&(flows.len() as u16).to_be_bytes());
    packet[4..8].copy_from_slice(&uptime.to_be_bytes());
    let t = epoch.duration_since(std::time::UNIX_EPOCH)?;
    packet[8..12].copy_from_slice(&(t.as_secs() as u32).to_be_bytes());
    packet[12..16].copy_from_slice(&t.subsec_nanos().to_be_bytes());
    packet[16..20].copy_from_slice(&sequence.to_be_bytes());
    let sample = if sampling > 1 {
        0x4000 | sampling as u16
    } else {
        0
    };
    packet[22..24].copy_from_slice(&sample.to_be_bytes());
    for (i, (key, flow)) in flows.iter().enumerate() {
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (key.src, key.dst) else {
            anyhow::bail!("NetFlow v5 cannot represent IPv6")
        };
        let p = &mut packet[24 + 48 * i..24 + 48 * (i + 1)];
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
        p[37] = flow.flags;
        p[38] = key.proto;
        p[39] = key.tos;
    }
    Ok(packet)
}
fn ipfix_header(sequence: u32, epoch: std::time::SystemTime, domain: u32) -> Result<Vec<u8>> {
    let t = epoch.duration_since(std::time::UNIX_EPOCH)?;
    let mut packet = vec![0; 16];
    packet[..2].copy_from_slice(&10u16.to_be_bytes());
    packet[4..8].copy_from_slice(&(t.as_secs() as u32).to_be_bytes());
    packet[8..12].copy_from_slice(&sequence.to_be_bytes());
    packet[12..16].copy_from_slice(&domain.to_be_bytes());
    Ok(packet)
}
fn append_set(packet: &mut Vec<u8>, id: u16, content: &[u8]) {
    packet.extend_from_slice(&id.to_be_bytes());
    let length = (content.len() + 4 + 3) & !3;
    packet.extend_from_slice(&(length as u16).to_be_bytes());
    packet.extend_from_slice(content);
    while packet.len() % 4 != 0 {
        packet.push(0);
    }
}
fn finish_ipfix(mut packet: Vec<u8>) -> Vec<u8> {
    let length = packet.len() as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet
}
fn ipfix_templates(
    sequence: u32,
    epoch: std::time::SystemTime,
    domain: u32,
    limit: usize,
) -> Result<Vec<u8>> {
    ensure!(
        limit >= 132,
        "message budget of {limit} bytes cannot fit IPFIX templates"
    );
    let mut packet = ipfix_header(sequence, epoch, domain)?;
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
            (152, 8),
            (153, 8),
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
    append_set(&mut packet, 2, &templates);
    Ok(finish_ipfix(packet))
}
fn ipfix_data(
    flows: &[(Key, Flow)],
    uptime: u32,
    sequence: u32,
    epoch: std::time::SystemTime,
    sampling: u32,
    domain: u32,
    limit: usize,
) -> Result<Vec<u8>> {
    super::config::validate_sampling(10, sampling)?;
    ensure!(
        limit <= 65507 && record_batch_len(flows, 10, limit)? == flows.len(),
        "IPFIX batch exceeds message budget"
    );
    let t = epoch.duration_since(std::time::UNIX_EPOCH)?;
    let mut packet = ipfix_header(sequence, epoch, domain)?;
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
            let now = t.as_millis() as u64;
            records.extend_from_slice(
                &now.saturating_sub(uptime.wrapping_sub(flow.first) as u64)
                    .to_be_bytes(),
            );
            records.extend_from_slice(
                &now.saturating_sub(uptime.wrapping_sub(flow.last) as u64)
                    .to_be_bytes(),
            );
            records.extend_from_slice(&sampling.to_be_bytes());
            records.push(1);
        }
        if !records.is_empty() {
            append_set(&mut packet, if ipv6 { 257 } else { 256 }, &records);
        }
    }
    Ok(finish_ipfix(packet))
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
    super::config::validate_sampling(config.export_version, config.sampling_rate)?;
    ensure!(
        (132..=65507).contains(&config.max_message_size),
        "invalid max_message_size"
    );
    use crate::linux as l;
    use std::{
        mem,
        net::SocketAddr,
        os::fd::AsRawFd,
        time::{Duration, Instant},
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
    let sender = UdpSender::new(collector, config.max_message_size)?;
    Ok(Box::new(move |ctx| {
        let mut exports = ExportSession::new(sender, config.export_version, config.sampling_rate)?;
        let start = exports.start;
        let mut capture = CaptureBatch::new(config.snaplen);
        let mut pending = Vec::with_capacity(CAPTURE_BATCH);
        let fixed_counters = config.export_version == 5;
        let mut table = FlowTable::new(config.max_flows, fixed_counters, timeouts);
        let mut sampling_remaining = config.sampling_rate;
        let mut ignored_ipv6 = 0u64;
        let mut malformed = 0u64;
        let mut filtered = 0u64;
        let mut dropped = 0u64;
        ctx.update(|s| {
            exports.publish(s);
            s["message_size_limit"] = serde_json::json!(exports.sender.budget);
            s["dropped_packets"] = serde_json::json!("0");
            s["statistics_complete"] = serde_json::json!(true);
        });
        let mut last_flush = Instant::now();
        let mut draining = false;
        let export =
            |batch: &[(Key, Flow)], exports: &mut ExportSession<UdpSender>| -> Result<()> {
                let result = exports.export(batch);
                ctx.update(|s| {
                    exports.publish(s);
                    s["message_size_limit"] = serde_json::json!(exports.sender.budget);
                });
                result
            };
        while !ctx.stopping() {
            let refresh = exports.maintain_at(Instant::now());
            ctx.update(|s| {
                exports.publish(s);
                s["message_size_limit"] = serde_json::json!(exports.sender.budget);
            });
            refresh?;
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
                    sampling_remaining -= 1;
                    if sampling_remaining != 0 {
                        continue;
                    }
                    sampling_remaining = config.sampling_rate;
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
                    if config.export_version == 5 && key.src.is_ipv6() {
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
                    export(&pending, &mut exports)?;
                    pending.clear();
                }
                if count < CAPTURE_BATCH || ctx.stopping() {
                    break;
                }
            }
            if draining || last_flush.elapsed() >= timeouts.scan_interval {
                let now = Instant::now();
                let batch = table.expired_batch(now, CAPTURE_BATCH);
                draining = table
                    .expiry
                    .first()
                    .is_some_and(|(deadline, _)| *deadline <= now);
                export(&batch, &mut exports)?;
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
                    s["excluded_packets"] = serde_json::json!(ignored_ipv6);
                    s["filtered_packets"] = serde_json::json!(filtered);
                    s["malformed_packets"] = serde_json::json!(malformed);
                });
            }
            wait_for_capture(fd.as_raw_fd())?;
        }
        let shutdown = Instant::now();
        while !table.flows.is_empty() {
            if shutdown.elapsed() >= Duration::from_secs(2) {
                tracing::warn!(
                    remaining_flows = table.flows.len(),
                    "NetFlow shutdown export exceeded two seconds; remaining records were not exported"
                );
                anyhow::bail!("NetFlow shutdown export deadline exceeded");
            }
            let mut batch = Vec::with_capacity(CAPTURE_BATCH);
            while batch.len() < CAPTURE_BATCH {
                let Some(&(_, key)) = table.oldest.first() else {
                    break;
                };
                batch.push(table.remove(&key).expect("oldest flow exists"));
            }
            if let Err(error) = export(&batch, &mut exports) {
                tracing::warn!(%error, remaining_flows = table.flows.len() + batch.len(), "NetFlow final export failed; remaining records were not exported");
                return Err(error);
            }
        }
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;

    struct TestSender {
        budget: usize,
        attempts: usize,
        packets: Vec<Vec<u8>>,
        failures: BTreeMap<usize, i32>,
        learned_limit: usize,
    }
    impl TestSender {
        fn new(budget: usize) -> Self {
            Self {
                budget,
                attempts: 0,
                packets: Vec::new(),
                failures: BTreeMap::new(),
                learned_limit: budget,
            }
        }
    }
    impl DatagramSender for TestSender {
        fn limit(&mut self) -> Result<usize> {
            Ok(self.budget)
        }
        fn send(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            self.attempts += 1;
            if let Some(code) = self.failures.remove(&self.attempts) {
                return Err(std::io::Error::from_raw_os_error(code));
            }
            self.packets.push(packet.to_vec());
            Ok(packet.len())
        }
        fn reduce_limit(&mut self, failed_size: usize) -> Result<()> {
            self.budget = self.budget.min(self.learned_limit).min(failed_size - 1);
            Ok(())
        }
    }
    fn test_batch(count: u32) -> Vec<(Key, Flow)> {
        (1..=count)
            .map(|index| {
                (
                    flow_test_key(index),
                    Flow {
                        packets: u64::from(index),
                        bytes: u64::from(index) * 40,
                        first: 1,
                        last: 2,
                        flags: 0,
                        changed: std::time::Instant::now(),
                        expiry: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn byte_budgets_include_headers_and_both_address_family_sets() {
        let ipv4 = test_batch(100);
        let mut ipv6 = ipv4.clone();
        for (key, _) in &mut ipv6 {
            key.src = "2001:db8::1".parse().unwrap();
            key.dst = "2001:db8::2".parse().unwrap();
        }
        let mixed = [ipv4[0].clone(), ipv6[0].clone()];
        for (batch, version, exact) in [
            (&ipv4[..1], 5, 72),
            (&ipv4[..1], 10, 72),
            (&ipv6[..1], 10, 96),
            (&mixed[..], 10, 152),
        ] {
            assert_eq!(
                record_batch_len(batch, version, exact).unwrap(),
                batch.len()
            );
            assert!(record_batch_len(batch, version, exact - 1).is_err() || batch.len() == 2);
            let packet = if version == 5 {
                v5(batch, 0, 0, std::time::UNIX_EPOCH, 1, exact).unwrap()
            } else {
                ipfix_data(batch, 0, 0, std::time::UNIX_EPOCH, 1, 1, exact).unwrap()
            };
            assert_eq!(packet.len(), exact);
        }
        assert_eq!(record_batch_len(&mixed, 10, 151).unwrap(), 1);
        assert!(ipfix_data(&mixed, 0, 0, std::time::UNIX_EPOCH, 1, 1, 151).is_err());
        assert_eq!(record_batch_len(&ipv4, 5, 1200).unwrap(), 24);
        assert_eq!(record_batch_len(&ipv4, 10, 1200).unwrap(), 22);
        assert_eq!(record_batch_len(&ipv6, 10, 1200).unwrap(), 15);
        assert_eq!(record_batch_len(&ipv4, 5, 4096).unwrap(), 84);
        assert_eq!(record_batch_len(&ipv6, 10, 4096).unwrap(), 53);
        assert!(ipfix_templates(0, std::time::UNIX_EPOCH, 1, 131).is_err());
        assert_eq!(payload_budget(1200, false, None).unwrap(), 484);
        assert_eq!(payload_budget(1200, true, None).unwrap(), 464);
        assert_eq!(payload_budget(4096, false, Some(576)).unwrap(), 548);
        assert_eq!(payload_budget(4096, true, Some(1280)).unwrap(), 1232);
        assert!(payload_budget(1200, false, Some(28)).is_err());
        for version in [1, 9] {
            assert!(ExportSession::new(TestSender::new(1200), version, 1).is_err());
        }
    }

    #[test]
    fn templates_refresh_independently_at_600_seconds_or_20_data_messages() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut session = ExportSession::new(TestSender::new(132), 10, 1).unwrap();
        session.maintain_at(now).unwrap();
        assert_eq!(
            (
                session.counters.packets,
                session.counters.flows,
                session.sequence
            ),
            (2, 0, 0)
        );
        assert_eq!(session.counters.bytes, 264);
        session.maintain_at(now + Duration::from_secs(599)).unwrap();
        assert_eq!(session.counters.packets, 2);
        session.maintain_at(now + Duration::from_secs(600)).unwrap();
        assert_eq!(session.counters.packets, 3);
        // Use a separate clock/session so subsequent real-time exports do not precede a test refresh.
        let mut session = ExportSession::new(TestSender::new(132), 10, 1).unwrap();
        session.export(&test_batch(38)).unwrap();
        assert_eq!(session.sender.packets.len(), 21);
        assert!(
            session.sender.packets[2..]
                .iter()
                .all(|p| p[16..18] == 256u16.to_be_bytes())
        );
        session.export(&test_batch(2)).unwrap();
        assert_eq!(session.sender.packets.len(), 23);
        let refresh = session.sender.packets.last().unwrap();
        assert_eq!(&refresh[16..18], &2u16.to_be_bytes());
        assert_eq!(&refresh[8..12], &40u32.to_be_bytes());
        assert_eq!(
            (
                session.sequence,
                session.counters.flows,
                session.data_messages
            ),
            (40, 40, 0)
        );
        assert_eq!(
            (session.counters.flow_packets, session.counters.flow_bytes),
            (744, 29760)
        );
        assert!(
            ExportSession::<TestSender>::check_deadline(Instant::now() - Duration::from_secs(2))
                .is_err()
        );
    }

    #[test]
    fn emsgsize_rebatches_only_unsent_records_and_preserves_sequence() {
        for version in [5, 10] {
            let mut sender = TestSender::new(1200);
            // Fail after a successful data message, not after the initial template copies.
            sender
                .failures
                .insert(if version == 5 { 2 } else { 4 }, libc::EMSGSIZE);
            sender.learned_limit = 548;
            let mut session = ExportSession::new(sender, version, 3).unwrap();
            session.export(&test_batch(61)).unwrap();
            let mut count = 0u32;
            for packet in &session.sender.packets {
                let (sequence, records) = if version == 5 {
                    (
                        u32::from_be_bytes(packet[16..20].try_into().unwrap()),
                        u16::from_be_bytes(packet[2..4].try_into().unwrap()) as u32,
                    )
                } else {
                    (
                        u32::from_be_bytes(packet[8..12].try_into().unwrap()),
                        if packet[16..18] == 2u16.to_be_bytes() {
                            0
                        } else {
                            ((packet.len() - 20) / 52) as u32
                        },
                    )
                };
                assert_eq!(sequence, count);
                count += records;
            }
            assert_eq!(
                (count, session.sequence, session.counters.flows),
                (61, 61, 61)
            );
            assert_eq!(
                (
                    session.counters.flow_packets,
                    session.counters.flow_bytes,
                    session.counters.errors
                ),
                (1891, 75640, 0)
            );
            assert!(
                session
                    .sender
                    .packets
                    .iter()
                    .skip(if version == 5 { 1 } else { 3 })
                    .all(|p| p.len() <= 548)
            );
        }
        for (version, budget) in [(5, 72), (10, 132)] {
            let mut sender = TestSender::new(budget);
            sender.failures.insert(1, libc::EMSGSIZE);
            let mut session = ExportSession::new(sender, version, 1).unwrap();
            assert!(session.export(&test_batch(1)).is_err());
            assert_eq!(
                (
                    session.sender.attempts,
                    session.counters.errors,
                    session.sequence,
                    session.counters.packets
                ),
                (1, 1, 0, 0)
            );
        }
        let mut sender = TestSender::new(1200);
        sender.failures = BTreeMap::from([(1, libc::EMSGSIZE), (2, libc::EMSGSIZE)]);
        let mut session = ExportSession::new(sender, 5, 1).unwrap();
        session.export(&test_batch(61)).unwrap();
        assert!(session.sender.budget < 1128);
        assert_eq!((session.sequence, session.counters.errors), (61, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/raw-socket privileges"]
    fn native_flow_mtu_reduction_recovers_emsgsize_without_fragments() {
        use std::{mem, net::UdpSocket, os::fd::AsRawFd, time::Duration};
        struct ShrinkingSender {
            inner: UdpSender,
            shrink: bool,
            emsgsize: usize,
        }
        impl DatagramSender for ShrinkingSender {
            fn limit(&mut self) -> Result<usize> {
                self.inner.limit()
            }
            fn reduce_limit(&mut self, size: usize) -> Result<()> {
                self.inner.reduce_limit(size)
            }
            fn send(&mut self, packet: &[u8]) -> std::io::Result<usize> {
                if self.shrink && packet.len() > 132 {
                    self.shrink = false;
                    let mut request: libc::ifreq = unsafe { mem::zeroed() };
                    request.ifr_name[0] = b'l' as _;
                    request.ifr_name[1] = b'o' as _;
                    request.ifr_ifru.ifru_mtu = if self.inner.ipv6 { 1280 } else { 576 };
                    if unsafe {
                        libc::ioctl(
                            self.inner.socket.as_raw_fd(),
                            libc::SIOCSIFMTU as _,
                            &request,
                        )
                    } < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                let result = self.inner.send(packet);
                if result
                    .as_ref()
                    .is_err_and(|e| e.raw_os_error() == Some(libc::EMSGSIZE))
                {
                    self.emsgsize += 1;
                }
                result
            }
        }
        assert_eq!(std::env::var("NETCONTROL_INTEGRATION").as_deref(), Ok("1"));
        for version in [5, 10] {
            std::thread::spawn(move || -> Result<()> {
                crate::linux::check(unsafe { libc::unshare(libc::CLONE_NEWNET) })?;
                let control = crate::linux::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
                let mut request: libc::ifreq = unsafe { mem::zeroed() };
                request.ifr_name[0] = b'l' as _;
                request.ifr_name[1] = b'o' as _;
                request.ifr_ifru.ifru_flags = libc::IFF_UP as i16;
                crate::linux::check(unsafe {
                    libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request)
                })?;
                let ipv6 = version == 10;
                let collector = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })?;
                collector.set_read_timeout(Some(Duration::from_secs(1)))?;
                let raw = crate::linux::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW,
                    (libc::ETH_P_ALL as u16).to_be() as i32,
                )?;
                let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
                address.sll_family = libc::AF_PACKET as u16;
                address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
                address.sll_ifindex = crate::linux::ifindex("lo")? as i32;
                crate::linux::check(unsafe {
                    libc::bind(
                        raw.as_raw_fd(),
                        &address as *const _ as *const _,
                        mem::size_of_val(&address) as _,
                    )
                })?;
                let sender = ShrinkingSender {
                    inner: UdpSender::new(collector.local_addr()?, 4096)?,
                    shrink: true,
                    emsgsize: 0,
                };
                let mut session = ExportSession::new(sender, version, 1)?;
                let mut batch = test_batch(80);
                if ipv6 {
                    for (key, _) in &mut batch {
                        key.src = "2001:db8::1".parse()?;
                        key.dst = "2001:db8::2".parse()?;
                    }
                }
                session.export(&batch)?;
                assert_eq!(session.sender.emsgsize, 1);
                assert_eq!(session.sender.inner.budget, if ipv6 { 1232 } else { 548 });
                assert_eq!(
                    (
                        session.sequence,
                        session.counters.flows,
                        session.counters.errors
                    ),
                    (80, 80, 0)
                );
                let mut received_records = 0;
                let mut received_bytes = 0;
                let mut buffer = [0; 4096];
                for _ in 0..session.counters.packets {
                    let n = collector.recv(&mut buffer)?;
                    assert!(n <= session.sender.inner.budget);
                    received_bytes += n as u64;
                    received_records += if version == 5 {
                        (n - 24) / 48
                    } else if buffer[16..18] == 2u16.to_be_bytes() {
                        0
                    } else {
                        (n - 20) / 76
                    };
                }
                assert_eq!(received_records, 80);
                assert_eq!(received_bytes, session.counters.bytes);
                let mut capture = CaptureBatch::new(4096);
                let mut wire_packets = 0;
                loop {
                    let count = capture.receive(raw.as_raw_fd())?;
                    if count == 0 {
                        break;
                    }
                    for index in 0..count {
                        let packet = capture.packet(index);
                        if ipv6 {
                            assert_eq!(packet[20], 17, "fragment extension header emitted");
                            assert!(
                                40 + u16::from_be_bytes(packet[18..20].try_into()?) as usize
                                    <= 1280
                            );
                        } else {
                            let fragment = u16::from_be_bytes(packet[20..22].try_into()?);
                            assert_eq!(fragment & 0x3fff, 0, "IPv4 fragmentation emitted");
                            assert_ne!(fragment & 0x4000, 0, "IPv4 DF missing");
                            assert!(u16::from_be_bytes(packet[16..18].try_into()?) <= 576);
                        }
                        wire_packets += 1;
                    }
                }
                assert_eq!(wire_packets, session.counters.packets * 2);
                Ok(())
            })
            .join()
            .expect("MTU test thread panic")
            .expect("native MTU validation failed");
        }
    }

    #[test]
    fn export_counters_match_udp_datagrams_and_sampled_flow_totals_for_all_versions() {
        for version in [5, 10] {
            for sampling in [1, 4, if version == 5 { 16383 } else { 1_000_000 }] {
                let batch = test_batch(61);
                let mut session =
                    ExportSession::new(TestSender::new(1200), version, sampling).unwrap();
                session.export(&batch).unwrap();
                let mut bytes = 0u64;
                for buffer in &session.sender.packets {
                    let n = buffer.len();
                    assert!(n <= 1200);
                    assert_eq!(&buffer[..2], &version.to_be_bytes());
                    if version == 5 {
                        let field = if sampling == 1 {
                            0
                        } else {
                            0x4000 | sampling as u16
                        };
                        assert_eq!(&buffer[22..24], &field.to_be_bytes());
                    } else if buffer[16..18] == 256u16.to_be_bytes() {
                        let interval = 20 + 47;
                        assert_eq!(&buffer[interval..interval + 4], &sampling.to_be_bytes());
                        assert_eq!(buffer[interval + 4], 1);
                    }
                    bytes += n as u64;
                }
                let counters = &session.counters;
                assert_eq!(counters.packets, if version == 5 { 3 } else { 5 });
                assert_eq!(counters.bytes, bytes);
                assert_eq!(counters.flows, 61);
                assert_eq!(counters.flow_packets, 1891);
                assert_eq!(counters.flow_bytes, 75640);
                assert_eq!(counters.errors, 0);
                assert_eq!(session.sequence, 61);
            }
        }
    }

    #[test]
    fn export_counters_preserve_partial_success_errors_and_instance_isolation() {
        let flow = Flow {
            packets: 3,
            bytes: 120,
            first: 1,
            last: 2,
            flags: 0,
            changed: std::time::Instant::now(),
            expiry: None,
        };
        let batch = vec![(flow_test_key(1), flow); 31];
        let mut sender = TestSender::new(1200);
        sender.failures.insert(2, libc::ECONNREFUSED);
        let mut session = ExportSession::new(sender, 5, 1).unwrap();
        assert!(session.export(&batch).is_err());
        let mut status = serde_json::json!({});
        session.publish(&mut status);
        assert_eq!(
            status,
            serde_json::json!({
                "exported_flows":24,"exported_packets":"1","exported_bytes":"1176",
                "exported_flow_packets":"72","exported_flow_bytes":"2880","export_errors":"1"
            })
        );
        session.export(&[]).unwrap();
        assert_eq!(session.counters.errors, 1);
        session.export(&batch[..1]).unwrap();
        let counters = &session.counters;
        assert_eq!(
            (counters.flows, counters.packets, counters.bytes),
            (25, 2, 1248)
        );
        assert_eq!((counters.flow_packets, counters.flow_bytes), (75, 3000));
        assert_eq!(counters.errors, 1);
        ExportCounters::default().publish(&mut status);
        assert_eq!(
            status,
            serde_json::json!({
                "exported_flows":0,"exported_packets":"0","exported_bytes":"0",
                "exported_flow_packets":"0","exported_flow_bytes":"0","export_errors":"0"
            })
        );
        assert_eq!(counters.flows, 25);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preparation_rejects_invalid_sampling_before_opening_capture() {
        for version in [5, 10] {
            for rate in [0, if version == 5 { 16384 } else { 1_000_001 }] {
                let config: super::super::config::Flow =
                    serde_json::from_value(serde_json::json!({
                        "name":"unsampled","enabled":true,"interface":"absent",
                        "collector":"192.0.2.1:4739","export_version":version,
                        "sampling_rate":rate,"max_flows":100,"snaplen":128,"promiscuous":false
                    }))
                    .unwrap();
                let error = match prepare(config, true) {
                    Ok(_) => panic!("invalid sampling unexpectedly passed worker preparation"),
                    Err(error) => error,
                };
                assert!(
                    error.to_string().contains("sampling_rate")
                        || error.to_string().contains("sampling interval"),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn export_counters_keep_exact_u64_strings_and_saturate_without_wrapping() {
        let mut counters = ExportCounters {
            flows: u64::MAX,
            packets: u64::MAX,
            bytes: u64::MAX,
            flow_packets: u64::MAX,
            flow_bytes: u64::MAX,
            errors: u64::MAX,
        };
        let batch = [(
            flow_test_key(1),
            Flow {
                packets: 1,
                bytes: 40,
                first: 0,
                last: 0,
                flags: 0,
                changed: std::time::Instant::now(),
                expiry: None,
            },
        )];
        counters.sent(&batch, 72);
        let mut status = serde_json::json!({});
        counters.publish(&mut status);
        assert_eq!(status["exported_flows"], u64::MAX);
        for field in [
            "exported_packets",
            "exported_bytes",
            "exported_flow_packets",
            "exported_flow_bytes",
            "export_errors",
        ] {
            assert_eq!(status[field], u64::MAX.to_string());
        }
    }

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
            if let Some(deadline) = flow.expiry {
                assert!(table.expiry.contains(&(deadline, *key)));
            }
        }
        assert_eq!(
            table.expiry.len(),
            table
                .flows
                .values()
                .filter(|flow| flow.expiry.is_some())
                .count()
        );
    }

    fn test_table(capacity: usize, fixed: bool) -> FlowTable {
        FlowTable::new(capacity, fixed, FlowTimeouts::new(&BTreeMap::new()))
    }

    #[test]
    fn indexed_expiry_drains_large_peaks_in_bounded_batches_without_stale_entries() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut table = test_table(20_000, false);
        for index in 0..20_000 {
            table.record(flow_test_key(index), 64, 0x10, now, 0);
        }
        assert!(
            table
                .expired_batch(now + Duration::from_secs(59), 17)
                .is_empty()
        );
        let mut exported = 0;
        while !table.flows.is_empty() {
            let batch = table.expired_batch(now + Duration::from_secs(60), 17);
            assert!(!batch.is_empty() && batch.len() <= 17);
            exported += batch.iter().map(|(_, flow)| flow.packets).sum::<u64>();
            assert_flow_index(&table);
        }
        assert_eq!(exported, 20_000);
        assert!(table.oldest.is_empty() && table.expiry.is_empty());
        table.record(
            flow_test_key(1),
            128,
            0x10,
            now + Duration::from_secs(61),
            61_000,
        );
        assert!(
            table
                .expired_batch(now + Duration::from_secs(120), 17)
                .is_empty()
        );
        assert_eq!(
            table
                .expired_batch(now + Duration::from_secs(121), 17)
                .len(),
            1
        );
    }

    #[test]
    fn indexed_expiry_updates_idle_flags_maxlife_and_disabled_deadlines() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let key = flow_test_key(1);
        let mut table = FlowTable::new(
            1,
            false,
            FlowTimeouts::new(&BTreeMap::from([
                ("tcp".into(), 10),
                ("tcp.rst".into(), 1),
                ("maxlife".into(), 15),
            ])),
        );
        table.record(key, 40, 0x10, now, u32::MAX - 500);
        table.record(key, 40, 0x10, now + Duration::from_secs(9), 8499);
        assert_flow_index(&table);
        assert!(
            table
                .expired_batch(now + Duration::from_secs(10), 64)
                .is_empty()
        );
        assert!(
            table
                .expired_batch(now + Duration::from_secs(14), 64)
                .is_empty()
        );
        assert_eq!(
            table.expired_batch(now + Duration::from_secs(15), 64).len(),
            1
        );
        table.record(key, 40, 0x10, now, 0);
        table.record(key, 40, 4, now + Duration::from_secs(1), 1000);
        assert_flow_index(&table);
        assert_eq!(
            table.expired_batch(now + Duration::from_secs(2), 64).len(),
            1
        );
        let mut table = FlowTable::new(
            1,
            false,
            FlowTimeouts::new(&BTreeMap::from([("tcp".into(), 0), ("maxlife".into(), 0)])),
        );
        table.record(key, 40, 0x10, now, 0);
        assert!(table.expiry.is_empty());
        assert!(
            table
                .expired_batch(now + Duration::from_secs(86400), 64)
                .is_empty()
        );
        assert_flow_index(&table);
    }

    #[test]
    fn flow_table_preserves_counts_flags_lru_and_removal() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut table = test_table(2, true);
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
            let mut table = test_table(1, fixed);
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
        let mut table = test_table(1, false);
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
        let mut table = test_table(1, true);
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
            let mut table = test_table(CAPACITY, true);
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
    fn netflow_v5_exact_header_records_lengths_and_endian_fields() {
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
            expiry: None,
        };
        let epoch = std::time::UNIX_EPOCH + std::time::Duration::new(0x10203040, 100000000);
        let p = v5(&[(key, flow.clone())], 0x99aabbcc, 0, epoch, 1, 1200).unwrap();
        let header = [
            0, 5, 0, 1, 0x99, 0xaa, 0xbb, 0xcc, 0x10, 0x20, 0x30, 0x40, 0x05, 0xf5, 0xe1, 0x00, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let record = [
            192, 0, 2, 1, 198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0x0a, 0x0b, 0x0c,
            0x0d, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x12, 0x34, 0xab, 0xcd, 0, 0x13,
            6, 0x2e, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(p.len(), 24 + 48);
        assert_eq!(&p[..24], &header);
        assert_eq!(&p[24..], &record);
        let records = vec![(key, flow.clone()); 24];
        let p = v5(&records, 0, 0, epoch, 1, 1200).unwrap();
        assert_eq!(p.len(), 24 + 24 * 48);
        assert_eq!(&p[2..4], &24u16.to_be_bytes());
        for r in p[24..].chunks_exact(48) {
            assert_eq!(r, &record);
        }
        assert!(v5(&vec![(key, flow.clone()); 25], 0, 0, epoch, 1, 1200).is_err());
        assert!(v5(&[], 0, 0, epoch, 1, 1200).is_err());
        let mut ipv6 = key;
        ipv6.src = "2001:db8::1".parse().unwrap();
        ipv6.dst = "2001:db8::2".parse().unwrap();
        assert!(v5(&[(ipv6, flow.clone())], 0, 0, epoch, 1, 1200).is_err());
        let mut overflow = flow;
        overflow.bytes = u32::MAX as u64 + 1;
        assert!(v5(&[(key, overflow)], 0, 0, epoch, 1, 1200).is_err());
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
            expiry: None,
        };
        let p = v5(&[(k, f)], 3, 7, std::time::UNIX_EPOCH, 1, 1200).unwrap();
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
        assert!(v5(&[], 0, 0, std::time::UNIX_EPOCH, 1, 1200).is_err());
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
    fn ipv6_parser_and_ipfix_wire_fields() {
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
            expiry: None,
        };
        assert!(
            v5(
                &[(key, flow.clone())],
                200,
                7,
                std::time::UNIX_EPOCH,
                1,
                1200
            )
            .is_err()
        );
        for sampling in [1, 4, 1_000_000] {
            let epoch = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_800_000_000_000);
            let p = ipfix_data(&[(key, flow.clone())], 200, 7, epoch, sampling, 123, 1200).unwrap();
            assert_eq!(&p[..2], &10u16.to_be_bytes());
            assert_eq!(
                u16::from_be_bytes(p[2..4].try_into().unwrap()) as usize,
                p.len()
            );
            assert_eq!(&p[8..12], &7u32.to_be_bytes());
            let templates = ipfix_templates(7, epoch, 123, 1200).unwrap();
            assert_eq!(templates.len(), 132);
            assert_eq!(&templates[16..20], &[0, 2, 0, 116]);
            let data = 16;
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
            assert_eq!(
                u64::from_be_bytes(record[55..63].try_into().unwrap()),
                1_799_999_999_900
            );
            let interval = 71;
            assert_eq!(&record[interval..interval + 4], &sampling.to_be_bytes());
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
