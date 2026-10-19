use anyhow::{Result, ensure};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
pub(crate) fn prepare(
    config: super::config::Flow,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use crate::linux as l;
    use std::{
        mem,
        net::{SocketAddr, UdpSocket},
        os::fd::AsRawFd,
        time::{Duration, Instant, SystemTime},
    };
    let filter = config.filter()?;
    let fd = l::socket(
        libc::AF_PACKET,
        libc::SOCK_RAW,
        (libc::ETH_P_ALL as u16).to_be() as i32,
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
        let mut buffer = vec![0; config.snaplen];
        let mut table: BTreeMap<Key, Flow> = BTreeMap::new();
        let mut oldest = std::collections::BTreeSet::new();
        let mut sampled = 0u64;
        let mut sequence = 0u32;
        let mut exports = 0u64;
        let mut ignored_ipv6 = 0u64;
        let mut malformed = 0u64;
        let mut filtered = 0u64;
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
            for _ in 0..256 {
                if ctx.stopping() {
                    break;
                }
                let n = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len(),
                        0,
                    )
                };
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted
                    {
                        break;
                    }
                    return Err(e.into());
                }
                sampled = sampled.wrapping_add(1);
                if sampled % config.sampling_rate as u64 != 0 {
                    continue;
                }
                let item = match parse(&buffer[..n as usize]) {
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
                if !filter.matches(key.src.is_ipv6(), key.proto) {
                    filtered += 1;
                    continue;
                }
                if [1, 5].contains(&config.export_version) && key.src.is_ipv6() {
                    ignored_ipv6 += 1;
                    continue;
                }
                if key.proto == 17 && key.dst == collector.ip() && key.dport == collector.port() {
                    continue;
                }
                if [1, 5].contains(&config.export_version)
                    && table.get(&key).is_some_and(|flow| {
                        flow.bytes + bytes as u64 > u32::MAX as u64
                            || flow.packets == u32::MAX as u64
                    })
                {
                    if let Some(item) = table.remove_entry(&key) {
                        oldest.remove(&(item.1.changed, item.0.clone()));
                        export(&[item], &mut sequence, &mut exports)?;
                    }
                }
                if !table.contains_key(&key) && table.len() >= config.max_flows {
                    if let Some((_, old)) = oldest.pop_first() {
                        export(
                            &[table.remove_entry(&old).unwrap()],
                            &mut sequence,
                            &mut exports,
                        )?;
                    }
                }
                let uptime = start.elapsed().as_millis() as u32;
                let f = table.entry(key.clone()).or_insert(Flow {
                    bytes: 0,
                    packets: 0,
                    first: uptime,
                    last: uptime,
                    flags: 0,
                    changed: Instant::now(),
                });
                oldest.remove(&(f.changed, key.clone()));
                f.bytes += bytes as u64;
                f.packets += 1;
                f.last = uptime;
                f.flags |= flags;
                f.changed = Instant::now();
                oldest.insert((f.changed, key));
            }
            let interval = config.timeouts.get("expint").copied().unwrap_or(1);
            if last_flush.elapsed() >= Duration::from_secs(interval) {
                let now = start.elapsed().as_millis() as u32;
                let keys: Vec<Key> = table
                    .iter()
                    .filter(|(k, v)| {
                        let idle = if k.proto == 6 && v.flags & 4 != 0 {
                            "tcp.rst"
                        } else if k.proto == 6 && v.flags & 1 != 0 {
                            "tcp.fin"
                        } else if k.proto == 6 {
                            "tcp"
                        } else if k.proto == 17 {
                            "udp"
                        } else if k.proto == 1 || k.proto == 58 {
                            "icmp"
                        } else {
                            "general"
                        };
                        let seconds = config.timeouts.get(idle).copied().unwrap_or_else(|| {
                            config.timeouts.get("general").copied().unwrap_or(60)
                        });
                        let max = config.timeouts.get("maxlife").copied().unwrap_or(3600);
                        (seconds > 0 && v.changed.elapsed() >= Duration::from_secs(seconds))
                            || (max > 0 && now.wrapping_sub(v.first) as u64 >= max * 1000)
                            || ([1, 5].contains(&config.export_version)
                                && (v.bytes > u32::MAX as u64 - 65535
                                    || v.packets >= u32::MAX as u64))
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                let batch: Vec<_> = keys
                    .into_iter()
                    .filter_map(|k| table.remove_entry(&k))
                    .collect();
                for (key, flow) in &batch {
                    oldest.remove(&(flow.changed, key.clone()));
                }
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
                ensure!(
                    stats.tp_drops == 0,
                    "AF_PACKET dropped {} packets; statistics incomplete",
                    stats.tp_drops
                );
                ctx.update(|s| {
                    s["active_flows"] = serde_json::json!(table.len());
                    s["exported_flows"] = serde_json::json!(exports);
                    s["excluded_packets"] = serde_json::json!(ignored_ipv6);
                    s["filtered_packets"] = serde_json::json!(filtered);
                    s["malformed_packets"] = serde_json::json!(malformed);
                });
            }
            ctx.wait(Duration::from_millis(10));
        }
        export(
            &table.into_iter().collect::<Vec<_>>(),
            &mut sequence,
            &mut exports,
        )?;
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
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
        let p = v1(&[(key.clone(), flow.clone())], 0x99aabbcc, epoch).unwrap();
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
        let records = vec![(key.clone(), flow.clone()); 24];
        let p = v1(&records, 0, epoch).unwrap();
        assert_eq!(p.len(), 16 + 24 * 48);
        assert_eq!(&p[2..4], &24u16.to_be_bytes());
        for r in p[16..].chunks_exact(48) {
            assert_eq!(r, &record);
        }
        assert!(v1(&vec![(key.clone(), flow.clone()); 25], 0, epoch).is_err());
        assert!(v1(&[], 0, epoch).is_err());
        let mut ipv6 = key.clone();
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
        assert!(
            v5(
                &[(key.clone(), flow.clone())],
                200,
                7,
                std::time::UNIX_EPOCH,
                1
            )
            .is_err()
        );
        for version in [9, 10] {
            let epoch = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_800_000_000_000);
            let p = template_export(
                &[(key.clone(), flow.clone())],
                version,
                200,
                7,
                epoch,
                1000000,
                123,
            )
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
