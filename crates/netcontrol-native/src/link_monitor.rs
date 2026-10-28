use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const FLOW_LIMIT: usize = 8192;
pub const IDLE_SECONDS: u64 = 120;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key {
    pub interface: u32,
    source: [u8; 16],
    destination: [u8; 16],
    ports: [u8; 4],
    ipv6: bool,
}

pub struct Header {
    pub key: Key,
    pub window: u16,
    pub syn: bool,
    pub ack: bool,
    pub closed: bool,
    pub sequence: u32,
    pub acknowledgment: u32,
}

/// Decodes only captured network/TCP headers; payload is never retained.
pub fn header(interface: u32, packet: &[u8]) -> Result<Option<Header>> {
    ensure!(!packet.is_empty(), "empty network header");
    let mut source = [0; 16];
    let mut destination = [0; 16];
    let (mut offset, mut protocol, end, ipv6) = match packet[0] >> 4 {
        4 => {
            ensure!(packet.len() >= 20, "short IPv4 header");
            let size = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let offset = usize::from(packet[0] & 15) * 4;
            ensure!(
                offset >= 20 && size >= offset && packet.len() >= offset,
                "invalid IPv4 header"
            );
            if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
                return Ok(None);
            }
            source[..4].copy_from_slice(&packet[12..16]);
            destination[..4].copy_from_slice(&packet[16..20]);
            (offset, packet[9], size, false)
        }
        6 => {
            ensure!(packet.len() >= 40, "short IPv6 header");
            source.copy_from_slice(&packet[8..24]);
            destination.copy_from_slice(&packet[24..40]);
            let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if length == 0 {
                return Ok(None);
            }
            (40, packet[6], 40 + length, true)
        }
        _ => return Ok(None),
    };
    for _ in 0..8 {
        if !ipv6 || !matches!(protocol, 0 | 43 | 60 | 51) {
            break;
        }
        ensure!(
            offset + 2 <= packet.len() && offset + 2 <= end,
            "short IPv6 extension"
        );
        let length = if protocol == 51 {
            (usize::from(packet[offset + 1]) + 2) * 4
        } else {
            (usize::from(packet[offset + 1]) + 1) * 8
        };
        protocol = packet[offset];
        offset += length;
    }
    if protocol != 6 {
        return Ok(None);
    }
    ensure!(
        offset + 20 <= packet.len() && offset + 20 <= end,
        "short TCP header"
    );
    let tcp = &packet[offset..];
    let length = usize::from(tcp[12] >> 4) * 4;
    ensure!(
        length >= 20 && offset + length <= end && tcp.len() >= length,
        "invalid TCP header"
    );
    let syn = tcp[13] & 2 != 0;
    let mut scale = None;
    if syn {
        let mut i = 20;
        while i < length {
            match tcp[i] {
                0 => break,
                1 => i += 1,
                kind => {
                    ensure!(i + 2 <= length, "short TCP option");
                    let size = usize::from(tcp[i + 1]);
                    ensure!(size >= 2 && i + size <= length, "invalid TCP option");
                    if kind == 3 {
                        ensure!(size == 3 && scale.is_none(), "invalid TCP window scale");
                        scale = Some(tcp[i + 2].min(14));
                    }
                    i += size;
                }
            }
        }
    }
    Ok(Some(Header {
        key: Key {
            interface,
            source,
            destination,
            ports: tcp[..4].try_into()?,
            ipv6,
        },
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        sequence: u32::from_be_bytes(tcp[4..8].try_into()?),
        acknowledgment: u32::from_be_bytes(tcp[8..12].try_into()?),
        syn,
        ack: tcp[13] & 16 != 0,
        closed: tcp[13] & 5 != 0,
    }))
}

struct Flow {
    window: u16,
    sequence: Option<u32>,
    acknowledgment: u32,
    seen: Instant,
}

#[derive(Default)]
struct Windows {
    packets: u64,
    zero_observations: u64,
    zero_transitions: u64,
    decreases: u64,
    min_raw: Option<u16>,
    max_raw: Option<u16>,
}

#[derive(Default)]
pub struct Capture {
    flows: BTreeMap<Key, Flow>,
    interfaces: BTreeMap<u32, Windows>,
    pub rejected: u64,
    pub untracked: u64,
    pub kernel_drops: u64,
    pub capture_gaps: u64,
}

impl Capture {
    pub fn record(&mut self, header: Header, now: Instant) {
        // ACK windows are meaningful; SYN windows and out-of-order observations
        // must not masquerade as receiver-pressure transitions.
        if !header.ack || header.syn {
            self.flows.remove(&header.key);
            return;
        }
        if self.interfaces.len() >= FLOW_LIMIT
            && !self.interfaces.contains_key(&header.key.interface)
        {
            self.untracked += 1;
            return;
        }
        let row = self.interfaces.entry(header.key.interface).or_default();
        row.packets += 1;
        row.min_raw = Some(row.min_raw.map_or(header.window, |v| v.min(header.window)));
        row.max_raw = Some(row.max_raw.map_or(header.window, |v| v.max(header.window)));
        row.zero_observations += u64::from(header.window == 0);
        if header.closed {
            self.flows.remove(&header.key);
            return;
        }
        if let Some(flow) = self.flows.get_mut(&header.key) {
            let ordered = flow.sequence.is_none_or(|sequence| {
                let change = header.sequence.wrapping_sub(sequence);
                change < (1 << 31)
                    && (change != 0
                        || header.acknowledgment.wrapping_sub(flow.acknowledgment) < (1 << 31))
            });
            if ordered {
                row.zero_transitions += u64::from(flow.window != 0 && header.window == 0);
                row.decreases += u64::from(header.window < flow.window);
                flow.window = header.window;
                flow.sequence = Some(header.sequence);
                flow.acknowledgment = header.acknowledgment;
            }
            flow.seen = now;
        } else if self.flows.len() < FLOW_LIMIT {
            self.flows.insert(
                header.key,
                Flow {
                    window: header.window,
                    sequence: Some(header.sequence),
                    acknowledgment: header.acknowledgment,
                    seen: now,
                },
            );
        } else {
            self.untracked += 1;
        }
    }

    pub fn expire(&mut self, now: Instant, interfaces: &std::collections::BTreeSet<u32>) {
        self.flows.retain(|key, flow| {
            interfaces.contains(&key.interface)
                && now.duration_since(flow.seen) < Duration::from_secs(IDLE_SECONDS)
        });
        self.interfaces.retain(|key, _| interfaces.contains(key));
    }

    pub fn snapshot(&self) -> Value {
        let interfaces: Vec<_> = self
            .interfaces
            .iter()
            .map(|(index, row)| {
                json!({
                    "index":index, "tcp_ack_packets":row.packets.to_string(),
                    "zero_window_observations":row.zero_observations.to_string(),
                    "zero_window_transitions":row.zero_transitions.to_string(),
                    "window_decreases":row.decreases.to_string(),
                    "window_raw_min":row.min_raw,"window_raw_max":row.max_raw
                })
            })
            .collect();
        json!({"status":"available","interfaces":interfaces,
            "tracked_directions":self.flows.len(),"flow_limit":FLOW_LIMIT,
            "kernel_drops":self.kernel_drops.to_string(),"rejected_headers":self.rejected.to_string(),
            "untracked_packets":self.untracked.to_string(),
            "capture_gaps":self.capture_gaps.to_string(),
            "statistics_complete":self.kernel_drops == 0 && self.rejected == 0 && self.untracked == 0 && self.capture_gaps == 0})
    }
}

pub fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    ensure!(bytes.len() >= offset + 4, "short kernel statistic");
    Ok(u32::from_ne_bytes(bytes[offset..offset + 4].try_into()?))
}

pub fn tcp_info(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() >= 104, "kernel TCP_INFO is too short");
    Ok(json!({
        "rto_ms":f64::from(u32_at(bytes, 8)?)/1000.0,
        "rtt_ms":f64::from(u32_at(bytes, 68)?)/1000.0,
        "rtt_variation_ms":f64::from(u32_at(bytes, 72)?)/1000.0,
        "cwnd_segments":u32_at(bytes, 80)?,
        "retransmissions":u32_at(bytes, 100)?.to_string(),
        "unacked_segments":u32_at(bytes, 24)?,
        "lost_segments":u32_at(bytes, 32)?,
        "peer_window_bytes":if bytes.len() >= 232 {Some(u32_at(bytes, 228)?)} else {None}
    }))
}

pub fn queue(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() >= 20, "short qdisc queue statistic");
    Ok(
        json!({"qlen_packets":u32_at(bytes,0)?,"backlog_bytes":u32_at(bytes,4)?,
        "drops":u32_at(bytes,8)?.to_string(),"requeues":u32_at(bytes,12)?.to_string(),
        "overlimits":u32_at(bytes,16)?.to_string()}),
    )
}

pub fn delta(previous: Option<u64>, current: u64) -> Option<u64> {
    previous.and_then(|value| current.checked_sub(value))
}

pub fn rtt_rise(current: Option<f64>, previous: Option<f64>) -> bool {
    current
        .zip(previous)
        .is_some_and(|(now, old)| now > old * 2.0 && now - old > 20.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(window: u16) -> Vec<u8> {
        let mut bytes = vec![0; 40];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
        bytes[9] = 6;
        bytes[32] = 0x50;
        bytes[33] = 16;
        bytes[34..36].copy_from_slice(&window.to_be_bytes());
        bytes
    }

    #[test]
    fn windows_are_not_congestion_windows_and_first_zero_is_not_a_transition() {
        let mut capture = Capture::default();
        let now = Instant::now();
        for window in [0, 100, 50, 0, 0] {
            capture.record(header(7, &packet(window)).unwrap().unwrap(), now);
        }
        let snapshot = capture.snapshot();
        assert_eq!(snapshot["interfaces"][0]["zero_window_observations"], "3");
        assert_eq!(snapshot["interfaces"][0]["zero_window_transitions"], "1");
        assert_eq!(snapshot["interfaces"][0]["window_decreases"], "2");
        capture.expire(
            now + Duration::from_secs(121),
            &std::collections::BTreeSet::from([7]),
        );
        assert_eq!(capture.snapshot()["tracked_directions"], 0);
    }

    #[test]
    fn headers_reject_malformed_skip_fragments_and_bound_options() {
        let mut bytes = packet(1);
        for length in 0..40 {
            assert!(header(1, &bytes[..length]).is_err());
        }
        bytes[6] = 0x20;
        assert!(header(1, &bytes).unwrap().is_none());
        bytes[6] = 0;
        bytes[32] = 0x40;
        assert!(header(1, &bytes).is_err());
        let mut ipv6 = vec![0; 60];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&20u16.to_be_bytes());
        ipv6[6] = 6;
        ipv6[52] = 0x50;
        assert!(header(2, &ipv6).unwrap().is_some());
        ipv6[6] = 44;
        assert!(header(2, &ipv6).unwrap().is_none());
    }

    #[test]
    fn kernel_layout_units_precision_and_resets() {
        let mut info = vec![0; 232];
        info[68..72].copy_from_slice(&12500u32.to_ne_bytes());
        info[80..84].copy_from_slice(&10u32.to_ne_bytes());
        info[100..104].copy_from_slice(&u32::MAX.to_ne_bytes());
        info[228..232].copy_from_slice(&65536u32.to_ne_bytes());
        let parsed = tcp_info(&info).unwrap();
        assert_eq!(parsed["rtt_ms"], 12.5);
        assert_eq!(parsed["retransmissions"], "4294967295");
        assert_eq!(parsed["peer_window_bytes"], 65536);
        assert!(tcp_info(&info[..100]).is_err());
        assert!(tcp_info(&info[..104]).unwrap()["peer_window_bytes"].is_null());
        assert!(queue(&[0; 19]).is_err());
        let queue_bytes: Vec<_> = [2u32, 4096, 3, 4, 5]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect();
        assert_eq!(
            queue(&queue_bytes).unwrap(),
            json!({
                "qlen_packets":2,"backlog_bytes":4096,"drops":"3","requeues":"4","overlimits":"5"
            })
        );
        assert_eq!(delta(None, 5), None);
        assert_eq!(delta(Some(7), 5), None);
        assert_eq!(delta(Some(5), 7), Some(2));
        assert!(!rtt_rise(None, Some(10.0)));
        assert!(!rtt_rise(Some(100.0), None));
        assert!(!rtt_rise(Some(30.0), Some(10.0)));
        assert!(rtt_rise(Some(30.001), Some(10.0)));
        assert!(!rtt_rise(Some(40.0), Some(20.0)));
        assert!(rtt_rise(Some(40.001), Some(20.0)));
    }

    #[test]
    fn tracking_is_bounded_and_stale_ack_does_not_change_window() {
        let now = Instant::now();
        let mut capture = Capture::default();
        let mut bytes = packet(100);
        bytes[28..32].copy_from_slice(&10u32.to_be_bytes());
        capture.record(header(1, &bytes).unwrap().unwrap(), now);
        bytes[28..32].copy_from_slice(&9u32.to_be_bytes());
        bytes[34..36].copy_from_slice(&0u16.to_be_bytes());
        capture.record(header(1, &bytes).unwrap().unwrap(), now);
        assert_eq!(
            capture.snapshot()["interfaces"][0]["zero_window_transitions"],
            "0"
        );
        for port in 1..=FLOW_LIMIT {
            let mut item = header(1, &packet(100)).unwrap().unwrap();
            item.key.ports[..2].copy_from_slice(&(port as u16).to_be_bytes());
            capture.record(item, now);
        }
        assert_eq!(capture.snapshot()["tracked_directions"], FLOW_LIMIT);
        assert_eq!(capture.snapshot()["untracked_packets"], "1");
        assert_eq!(capture.snapshot()["statistics_complete"], false);
        capture.expire(now, &std::collections::BTreeSet::new());
        assert_eq!(capture.snapshot()["tracked_directions"], 0);
        assert_eq!(capture.snapshot()["interfaces"], json!([]));
    }
}
