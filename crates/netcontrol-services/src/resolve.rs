use anyhow::{Context, Result, bail, ensure};
use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    time::Duration,
};

fn dns_name(data: &[u8], mut p: usize) -> Result<(usize, Vec<u8>)> {
    let mut labels = 0;
    let mut name = Vec::new();
    let mut end = None;
    loop {
        let b = *data.get(p).context("truncated DNS name")?;
        p += 1;
        ensure!(labels < 128, "DNS compression cycle/label limit");
        if b == 0 {
            return Ok((end.unwrap_or(p), name));
        }
        if b & 0xc0 == 0xc0 {
            let lo = *data.get(p).context("truncated DNS compression pointer")?;
            let target = (((b & 0x3f) as usize) << 8) | lo as usize;
            ensure!(target < p - 1, "DNS compression must point backward");
            if end.is_none() {
                end = Some(p + 1)
            }
            p = target;
            labels += 1;
            continue;
        }
        ensure!(b <= 63 && p + b as usize <= data.len(), "invalid DNS name");
        if !name.is_empty() {
            name.push(b'.')
        }
        name.extend(data[p..p + b as usize].iter().map(u8::to_ascii_lowercase));
        ensure!(name.len() <= 253, "DNS name too long");
        p += b as usize;
        labels += 1;
    }
}
pub(crate) fn parse(data: &[u8], id: u16, question: &[u8]) -> Result<Vec<IpAddr>> {
    ensure!(
        data.len() >= 12
            && data[0..2] == id.to_be_bytes()
            && data[2] & 0x80 != 0
            && data[2] & 0x7a == 0
            && data[3] & 0x0f == 0,
        "invalid, truncated, or unsuccessful DNS response"
    );
    ensure!(
        u16::from_be_bytes([data[4], data[5]]) == 1,
        "DNS response must echo one question"
    );
    ensure!(
        data.get(12..12 + question.len()) == Some(question),
        "DNS question mismatch"
    );
    let count = u16::from_be_bytes([data[6], data[7]]) as usize;
    ensure!(question.len() >= 5, "short DNS question");
    let (_, asked) = dns_name(data, 12)?;
    let requested =
        u16::from_be_bytes([question[question.len() - 4], question[question.len() - 3]]);
    let mut p = 12 + question.len();
    let mut answers = Vec::new();
    let mut aliases = std::collections::BTreeMap::new();
    for _ in 0..count {
        let (next, owner) = dns_name(data, p)?;
        p = next;
        ensure!(p + 10 <= data.len(), "truncated DNS record");
        let kind = u16::from_be_bytes([data[p], data[p + 1]]);
        let class = u16::from_be_bytes([data[p + 2], data[p + 3]]);
        let len = u16::from_be_bytes([data[p + 8], data[p + 9]]) as usize;
        p += 10;
        ensure!(p + len <= data.len(), "truncated DNS rdata");
        if class == 1 {
            if kind == requested && kind == 1 && len == 4 {
                answers.push((
                    owner.clone(),
                    IpAddr::from(<[u8; 4]>::try_from(&data[p..p + 4])?),
                ));
            }
            if kind == requested && kind == 28 && len == 16 {
                answers.push((
                    owner.clone(),
                    IpAddr::from(<[u8; 16]>::try_from(&data[p..p + 16])?),
                ));
            }
            if kind == 5 {
                let (end, target) = dns_name(data, p)?;
                ensure!(end == p + len, "invalid CNAME rdata");
                ensure!(
                    aliases.insert(owner, target).is_none(),
                    "duplicate DNS alias"
                );
            }
        }
        p += len;
    }
    let mut owner = asked;
    for _ in 0..8 {
        let result: Vec<_> = answers
            .iter()
            .filter(|(name, _)| name == &owner)
            .map(|(_, ip)| *ip)
            .collect();
        if !result.is_empty() {
            return Ok(result);
        }
        if let Some(next) = aliases.get(&owner) {
            owner = next.clone()
        } else {
            return Ok(Vec::new());
        }
    }
    bail!("DNS alias cycle/depth limit")
}
pub fn resolve(host: &str, port: u16, ipv6_enabled: bool) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure!(
            ipv6_enabled || ip.is_ipv4(),
            "IPv6 destination requires ipv6_enabled"
        );
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let mut result = Vec::new();
    for line in hosts.lines() {
        let mut words = line.split('#').next().unwrap_or("").split_whitespace();
        if let Some(ip) = words.next().and_then(|w| w.parse::<IpAddr>().ok()) {
            if (ipv6_enabled || ip.is_ipv4()) && words.any(|w| w.eq_ignore_ascii_case(host)) {
                result.push(SocketAddr::new(ip, port));
            }
        }
    }
    if !result.is_empty() {
        return Ok(result);
    }
    let config = std::fs::read_to_string("/etc/resolv.conf")
        .context("read native DNS resolver configuration")?;
    let servers: Vec<IpAddr> = config
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver "))
        .filter_map(|s| s.trim().parse().ok())
        .filter(|ip: &IpAddr| ipv6_enabled || ip.is_ipv4())
        .take(2)
        .collect();
    for server in servers {
        for kind in [1u16, 28] {
            if kind == 28 && !ipv6_enabled {
                continue;
            }
            let socket = UdpSocket::bind(if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })?;
            socket.set_read_timeout(Some(Duration::from_millis(300)))?;
            socket.set_write_timeout(Some(Duration::from_millis(300)))?;
            socket.connect(SocketAddr::new(server, 53))?;
            let id = rand::random::<u16>();
            let mut packet = vec![0u8; 12];
            packet[..2].copy_from_slice(&id.to_be_bytes());
            packet[2] = 1;
            packet[5] = 1;
            let mut question = Vec::new();
            for label in host.split('.') {
                question.push(label.len() as u8);
                question.extend_from_slice(label.as_bytes());
            }
            question.push(0);
            question.extend_from_slice(&kind.to_be_bytes());
            question.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&question);
            socket.send(&packet)?;
            let mut buffer = [0; 4096];
            if let Ok(n) = socket.recv(&mut buffer) {
                if let Ok(ips) = parse(&buffer[..n], id, &question) {
                    result.extend(
                        ips.into_iter()
                            .filter(|ip| super::config::unicast(*ip, false) || ip.is_loopback())
                            .map(|ip| SocketAddr::new(ip, port)),
                    );
                }
            }
        }
        if !result.is_empty() {
            return Ok(result);
        }
    }
    bail!(
        "native DNS resolution failed for {host}; requires reachable UDP resolver and untruncated A/AAAA response"
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_only_resolution_rejects_ipv6_literals() {
        assert!(resolve("::1", 123, false).is_err());
        assert!(resolve("2001:db8::1", 514, false).is_err());
        assert_eq!(
            resolve("127.0.0.1", 123, false).unwrap(),
            vec!["127.0.0.1:123".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            resolve("::1", 123, true).unwrap(),
            vec!["[::1]:123".parse::<SocketAddr>().unwrap()]
        );
    }
    #[test]
    fn rejects_dns_spoofing_truncation_and_short_packets() {
        assert!(parse(&[0; 11], 1, &[]).is_err());
        let mut p = vec![0; 12];
        p[1] = 1;
        p[2] = 0x82;
        p[5] = 1;
        assert!(parse(&p, 1, &[]).is_err());
        p[2] = 0x80;
        assert!(parse(&p, 2, &[]).is_err());
    }
    #[test]
    fn matching_dns_answer_and_compression_bounds() {
        let question = b"\x07example\x04test\0\0\x01\0\x01";
        let mut p = vec![0; 12];
        p[1] = 7;
        p[2] = 0x81;
        p[3] = 0x80;
        p[5] = 1;
        p[7] = 1;
        p.extend_from_slice(question);
        p.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        assert_eq!(
            parse(&p, 7, question).unwrap(),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        let start = 12 + question.len();
        p[start + 1] = 0xff;
        assert!(parse(&p, 7, question).is_err());
    }
    #[test]
    fn unrelated_dns_answer_not_accepted() {
        let question = b"\x07example\x04test\0\0\x01\0\x01";
        let mut p = vec![0; 12];
        p[1] = 7;
        p[2] = 0x80;
        p[5] = 1;
        p[7] = 1;
        p.extend_from_slice(question);
        p.extend_from_slice(b"\x03bad\x04test\0");
        p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        assert!(parse(&p, 7, question).unwrap().is_empty());
        for n in 0..p.len() {
            assert!(parse(&p[..n], 7, question).is_err());
        }
    }
}
