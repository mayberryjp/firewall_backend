#[cfg(target_os = "linux")]
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for part in bytes.chunks(2) {
        sum += ((part[0] as u32) << 8) | part.get(1).copied().unwrap_or(0) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16)
    }
    !(sum as u16)
}
pub(crate) fn echo(sequence: u64, id: u16, nonce: &[u8; 16], ipv6: bool) -> Vec<u8> {
    let mut p = vec![0; 32];
    p[0] = if ipv6 { 128 } else { 8 };
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&(sequence as u16).to_be_bytes());
    p[8..24].copy_from_slice(nonce);
    p[24..32].copy_from_slice(&sequence.to_be_bytes());
    if !ipv6 {
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
    }
    p
}
pub(crate) fn reply(mut packet: &[u8], id: u16, nonce: &[u8; 16], ipv6: bool) -> Option<u64> {
    if !ipv6 {
        if packet.first()? >> 4 != 4 {
            return None;
        }
        let header = (packet[0] & 15) as usize * 4;
        if header < 20 || packet.len() < header + 32 || packet[9] != 1 {
            return None;
        }
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if length != packet.len()
            || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
            || checksum(&packet[..header]) != 0
        {
            return None;
        }
        packet = &packet[header..];
        if checksum(packet) != 0 {
            return None;
        }
    }
    if packet.len() != 32
        || packet[0] != if ipv6 { 129 } else { 0 }
        || packet[1] != 0
        || packet[4..6] != id.to_be_bytes()
        || &packet[8..24] != nonce
    {
        return None;
    }
    let seq = u64::from_be_bytes(packet[24..32].try_into().ok()?);
    if packet[6..8] != (seq as u16).to_be_bytes() {
        return None;
    }
    Some(seq)
}
struct Probe {
    seq: u64,
    sent: Instant,
    rtt: Option<f64>,
}
pub(crate) struct Window {
    config: super::config::Gateway,
    start: Instant,
    started_at: String,
    probes: VecDeque<Probe>,
    health: String,
    candidate: String,
    candidate_since: Instant,
    changed: Option<String>,
    last_success: Option<String>,
}
impl Window {
    fn new(config: super::config::Gateway, start: Instant) -> Self {
        Self {
            config,
            start,
            started_at: super::worker::now(),
            probes: VecDeque::new(),
            health: "unknown".into(),
            candidate: String::new(),
            candidate_since: start,
            changed: None,
            last_success: None,
        }
    }
    fn sent(&mut self, seq: u64, now: Instant) {
        self.probes.push_back(Probe {
            seq,
            sent: now,
            rtt: None,
        });
    }
    fn received(&mut self, seq: u64, now: Instant) {
        if let Some(p) = self
            .probes
            .iter_mut()
            .find(|p| p.seq == seq && p.rtt.is_none())
        {
            if let Some(delta) = now.checked_duration_since(p.sent) {
                if delta <= Duration::from_millis(self.config.loss_timeout_ms) {
                    p.rtt = Some(delta.as_secs_f64() * 1000.);
                    self.last_success = Some(super::worker::now());
                }
            }
        }
    }
    fn sample(&mut self, now: Instant) -> Value {
        while self.probes.front().is_some_and(|p| {
            now.duration_since(p.sent) > Duration::from_millis(self.config.window_ms)
        }) {
            self.probes.pop_front();
        }
        let mut values = Vec::new();
        let mut lost = 0usize;
        let mut pending = 0usize;
        let mut previous: Option<&Probe> = None;
        let mut variation = 0.;
        let mut pairs = 0usize;
        for p in &self.probes {
            if let Some(rtt) = p.rtt {
                values.push(rtt);
                if let Some(old) = previous {
                    if old.seq + 1 == p.seq {
                        if let Some(v) = old.rtt {
                            variation += (rtt - v).abs();
                            pairs += 1;
                        }
                    }
                }
            } else if now.duration_since(p.sent)
                >= Duration::from_millis(self.config.loss_timeout_ms)
            {
                lost += 1
            } else {
                pending += 1
            }
            previous = Some(p);
        }
        let received = values.len();
        let loss = if received + lost > 0 {
            Some(lost as f64 * 100. / (received + lost) as f64)
        } else {
            None
        };
        let avg = if values.is_empty() {
            None
        } else {
            Some(values.iter().sum::<f64>() / values.len() as f64)
        };
        let stddev = avg.map(|a| {
            (values.iter().map(|v| (v - a).powi(2)).sum::<f64>() / values.len() as f64).sqrt()
        });
        values.sort_by(f64::total_cmp);
        let percentile = |q: f64| {
            if values.is_empty() {
                None
            } else {
                Some(values[(q * values.len() as f64).ceil() as usize - 1])
            }
        };
        let var = if pairs > 0 {
            Some(variation / pairs as f64)
        } else {
            None
        };
        let mut sample_status = "warming_up";
        if now.duration_since(self.start) >= Duration::from_millis(self.config.window_ms) {
            if let Some(loss) = loss {
                sample_status = "available";
                let candidate = if loss == 100. {
                    "down"
                } else if loss >= self.config.loss_threshold_percent as f64
                    || avg.is_some_and(|a| a >= self.config.latency_threshold_ms as f64)
                    || (self.config.rtt_variation_threshold_ms > 0
                        && var.is_some_and(|v| v >= self.config.rtt_variation_threshold_ms as f64))
                {
                    "degraded"
                } else {
                    "up"
                };
                if self.candidate != candidate {
                    self.candidate = candidate.into();
                    self.candidate_since = now;
                }
                let rank = |s: &str| match s {
                    "up" => 0,
                    "degraded" => 1,
                    "down" => 2,
                    _ => -1,
                };
                let hold = if candidate == "up" || rank(candidate) < rank(&self.health) {
                    self.config.recovery_hold_ms
                } else {
                    self.config.failure_hold_ms
                };
                if self.health != candidate
                    && now.duration_since(self.candidate_since) >= Duration::from_millis(hold)
                {
                    self.health = candidate.into();
                    self.changed = Some(super::worker::now());
                }
            } else {
                sample_status = "unavailable";
                self.health = "unknown".into();
                self.candidate.clear();
            }
        }
        json!({"name":self.config.name,"process_state":"running","sample_status":sample_status,"health":self.health,"started_at":self.started_at,
            "collected_at":super::worker::now(),"health_changed_at":self.changed,"last_success_at":self.last_success,"sent":self.probes.len(),
            "received":received,"lost":lost,"pending":pending,"variation_pairs":pairs,"loss_percent":loss,
            "rtt_min_ms":values.first(),"rtt_max_ms":values.last(),"rtt_avg_ms":avg,"rtt_stddev_ms":stddev,
            "rtt_p50_ms":percentile(0.5),"rtt_p95_ms":percentile(0.95),"rtt_variation_ms":var})
    }
}

#[cfg(target_os = "linux")]
fn path(config: &super::config::Gateway, index: u32) -> Result<()> {
    use crate::linux as l;
    use std::{net::IpAddr, os::fd::AsRawFd};
    fn attr(packet: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
        packet.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
        packet.extend_from_slice(&kind.to_ne_bytes());
        packet.extend_from_slice(bytes);
        while packet.len() % 4 != 0 {
            packet.push(0);
        }
    }
    let fd = l::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    l::check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const _,
            std::mem::size_of_val(&address) as _,
        )
    })?;
    let src: IpAddr = config.source_address.parse()?;
    let dst: IpAddr = config.target.parse()?;
    let seq = rand::random::<u32>();
    let mut p = vec![0; 28];
    p[4..6].copy_from_slice(&26u16.to_ne_bytes());
    p[6..8].copy_from_slice(&1u16.to_ne_bytes());
    p[8..12].copy_from_slice(&seq.to_ne_bytes());
    p[16] = if src.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    p[17] = if src.is_ipv4() { 32 } else { 128 };
    p[18] = p[17];
    // Request the policy-selected table as well as the matching FIB route.
    p[24..28].copy_from_slice(&(0x1000u32 | 0x2000).to_ne_bytes());
    let bytes = |ip: IpAddr| match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    attr(&mut p, 1, &bytes(dst));
    attr(&mut p, 2, &bytes(src));
    if matches!(dst,IpAddr::V6(v) if v.is_unicast_link_local()) {
        attr(&mut p, 4, &index.to_ne_bytes());
    }
    let len = p.len() as u32;
    p[..4].copy_from_slice(&len.to_ne_bytes());
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            p.as_ptr() as *const _,
            p.len(),
            0,
            &address as *const _ as *const _,
            std::mem::size_of_val(&address) as _,
        )
    };
    ensure!(n == p.len() as isize, "route lookup send failed");
    let start = Instant::now();
    let mut out = [0; 8192];
    loop {
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                out.as_mut_ptr() as *mut _,
                out.len(),
                libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock
                && start.elapsed() < Duration::from_millis(250)
            {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            return Err(e.into());
        }
        ensure!(
            n >= 28 && n as usize <= out.len(),
            "short/truncated route result"
        );
        let p = &out[..n as usize];
        ensure!(
            u32::from_ne_bytes(p[8..12].try_into()?) == seq,
            "route lookup sequence mismatch"
        );
        ensure!(
            u16::from_ne_bytes(p[4..6].try_into()?) == 24,
            "route lookup rejected"
        );
        ensure!(p[23] == 1, "route is not unicast");
        let mut table = p[20] as u32;
        let mut interface = 0;
        let mut gateway = None;
        let mut at = 28;
        while at + 4 <= p.len() {
            let n = u16::from_ne_bytes(p[at..at + 2].try_into()?) as usize;
            let kind = u16::from_ne_bytes(p[at + 2..at + 4].try_into()?);
            ensure!(n >= 4 && at + n <= p.len(), "malformed route attribute");
            let v = &p[at + 4..at + n];
            match kind {
                4 if v.len() == 4 => interface = u32::from_ne_bytes(v.try_into()?),
                15 if v.len() == 4 => table = u32::from_ne_bytes(v.try_into()?),
                5 if v.len() == 4 => gateway = Some(IpAddr::from(<[u8; 4]>::try_from(v)?)),
                5 if v.len() == 16 => gateway = Some(IpAddr::from(<[u8; 16]>::try_from(v)?)),
                9 => anyhow::bail!("multipath monitor routes are unsupported"),
                _ => {}
            }
            at += (n + 3) & !3;
        }
        let expected: IpAddr = config.gateway.parse()?;
        ensure!(
            table == config.routing_table
                && interface == index
                && (gateway == Some(expected) || (dst == expected && gateway.is_none())),
            "effective gateway route no longer matches configured table/interface/next-hop: observed table {table}, interface {interface}, gateway {gateway:?}; expected table {}, interface {index}, gateway {expected}",
            config.routing_table
        );
        return Ok(());
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    config: super::config::Gateway,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use crate::linux as l;
    use std::{
        net::{IpAddr, SocketAddr},
        os::fd::AsRawFd,
    };
    let src: IpAddr = config.source_address.parse()?;
    let target: IpAddr = config.target.parse()?;
    let ipv6 = src.is_ipv6();
    let (index, addresses) = l::interface_snapshot(&config.interface)?;
    ensure!(addresses.contains(&src), "gateway source address missing");
    path(&config, index)?;
    let fd = l::socket(
        if ipv6 { libc::AF_INET6 } else { libc::AF_INET },
        libc::SOCK_RAW,
        if ipv6 {
            libc::IPPROTO_ICMPV6
        } else {
            libc::IPPROTO_ICMP
        },
    )?;
    l::bind_device(fd.as_raw_fd(), &config.interface)?;
    l::bind(fd.as_raw_fd(), SocketAddr::new(src, 0), index)?;
    let id = rand::random::<u16>();
    let nonce = rand::random::<[u8; 16]>();
    Ok(Box::new(move |ctx| {
        let mut window = Window::new(config.clone(), Instant::now());
        let mut seq = 0;
        let mut next = Instant::now();
        let mut buffer = [0; 2048];
        let mut sampled = Instant::now();
        while !ctx.stopping() {
            let now = Instant::now();
            if now >= next {
                let (live, addresses) = l::interface_snapshot(&config.interface)?;
                ensure!(
                    live == index && addresses.contains(&src),
                    "gateway interface/source drift"
                );
                path(&config, index)?;
                seq += 1;
                let wire = echo(seq, id, &nonce, ipv6);
                let sent = Instant::now();
                l::send(fd.as_raw_fd(), &wire, SocketAddr::new(target, 0), index)?;
                window.sent(seq, sent);
                next = sent + Duration::from_millis(config.probe_interval_ms);
            }
            for _ in 0..128 {
                let Some((n, from)) = l::recv(fd.as_raw_fd(), &mut buffer)? else {
                    break;
                };
                if from.ip() == target {
                    if let Some(seq) = reply(&buffer[..n], id, &nonce, ipv6) {
                        window.received(seq, Instant::now());
                    }
                }
            }
            if sampled.elapsed() >= Duration::from_millis(100) {
                let stats = window.sample(Instant::now());
                ctx.update(|s| s["statistics"] = stats);
                sampled = Instant::now();
            }
            ctx.wait(Duration::from_millis(10));
        }
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_sequence_and_checksums() {
        let nonce = [7; 16];
        let mut p = echo(123, 19, &nonce, true);
        p[0] = 129;
        assert_eq!(reply(&p, 19, &nonce, true), Some(123));
        p[8] ^= 1;
        assert_eq!(reply(&p, 19, &nonce, true), None);
        let p = echo(1, 2, &nonce, false);
        assert_eq!(checksum(&p), 0);
    }
    fn config() -> super::super::config::Gateway {
        serde_json::from_value(json!({"name":"test","enabled":true,"interface":"test0","source_address":"192.0.2.1","gateway":"192.0.2.2","target":"192.0.2.3","routing_table":10000,"probe_interval_ms":100,"loss_timeout_ms":100,"window_ms":1000,"latency_threshold_ms":100,"loss_threshold_percent":20,"rtt_variation_threshold_ms":0,"failure_hold_ms":100,"recovery_hold_ms":100})).unwrap()
    }
    #[test]
    fn rolling_loss_health_holds_and_late_reply() {
        let start = Instant::now();
        let mut w = Window::new(config(), start);
        w.sent(1, start + Duration::from_millis(800));
        w.sent(2, start + Duration::from_millis(900));
        w.received(1, start + Duration::from_millis(810));
        w.received(2, start + Duration::from_millis(1100)); // too late; remains lost
        let a = w.sample(start + Duration::from_millis(1000));
        assert_eq!(a["received"], 1);
        assert_eq!(a["lost"], 1);
        assert_eq!(a["health"], "unknown");
        assert_eq!(a["loss_percent"], 50.);
        let a = w.sample(start + Duration::from_millis(1100));
        assert_eq!(a["health"], "degraded");
        let a = w.sample(start + Duration::from_millis(2100));
        assert_eq!(a["sample_status"], "unavailable");
        assert_eq!(a["health"], "unknown");
    }
    #[test]
    fn truncated_random_icmp_never_panics() {
        for length in 0..128 {
            let p: Vec<_> = (0..length).map(|_| rand::random()).collect();
            assert_eq!(reply(&p, 1, &[0; 16], false), None);
            assert_eq!(reply(&p, 1, &[0; 16], true), None);
        }
    }
}
