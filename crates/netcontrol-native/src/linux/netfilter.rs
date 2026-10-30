//! Read-only raw dumps preserve chain policy/unknown attributes for strict drift guards.
//! In particular, they avoid relying on lossy high-level netfilter decoders.
use crate::netlink_decode::{attributes, c_string};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub fn empty_fingerprint() -> String {
    hex::encode(Sha256::digest([]))
}

pub fn fingerprint() -> Result<String> {
    let mut records = Vec::new();
    let mut rule_chains: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    let tables = dump(1, false)?;
    let exists = tables
        .iter()
        .map(|payload| -> Result<bool> {
            ensure!(payload.len() >= 4, "short nfgen table response");
            let attrs = attributes(&payload[4..])?;
            let name = attrs
                .iter()
                .find(|(kind, _)| kind & 0x3fff == 1)
                .context("table name missing")?;
            Ok(c_string(&name.1)? == "netcontrol")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .any(|v| v);
    if !exists {
        return Ok(empty_fingerprint());
    }
    // Objects and flowtables are not part of this compiler and must not be hidden in its table.
    for message in [1u16, 4, 7, 10, 19, 23] {
        let messages = if message == 1 {
            tables.clone()
        } else {
            dump(message, true)?
        };
        for payload in messages {
            ensure!(
                payload.len() >= 4 && payload[0] == libc::NFPROTO_INET as u8,
                "invalid nftables dump family"
            );
            let attrs = attributes(&payload[4..])?;
            let table_kind = 1;
            let Some(table) = attrs.iter().find(|(kind, _)| kind & 0x3fff == table_kind) else {
                bail!("nftables object missing table name");
            };
            if c_string(&table.1)? != "netcontrol" {
                continue;
            }
            crate::ensure_unchanged(
                matches!(message, 1 | 4 | 7),
                "owned nftables table contains unsupported sets/objects/flowtables",
            )?;
            let mut record = message.to_ne_bytes().to_vec();
            for (kind, value) in &attrs {
                let base = kind & 0x3fff;
                let dynamic = match message {
                    1 => matches!(base, 3..=5),              // table use, handle, padding
                    4 => matches!(base, 2 | 6 | 8 | 9 | 11), // chain handle/use/counters/pad/id
                    7 => matches!(base, 3 | 6 | 8 | 9 | 10 | 11), // rule handle/position/IDs/pad
                    _ => false,
                };
                if dynamic {
                    continue;
                }
                let normalized;
                let value = if message == 7 && base == 4 {
                    normalized = crate::firewall_counters::normalize_expressions(value)?;
                    &normalized
                } else {
                    value
                };
                record.extend(kind.to_ne_bytes());
                record.extend((value.len() as u32).to_ne_bytes());
                record.extend(value);
            }
            if message == 7 {
                let chain = attrs
                    .iter()
                    .find(|(kind, _)| kind & 0x3fff == 2)
                    .context("nftables rule missing chain")?;
                rule_chains
                    .entry(c_string(&chain.1)?.to_string())
                    .or_default()
                    .push(record);
            } else {
                records.push(record);
            }
        }
    }
    records.sort();
    let mut hash = Sha256::new();
    for record in records
        .into_iter()
        .chain(rule_chains.into_values().flatten())
    {
        hash.update((record.len() as u64).to_ne_bytes());
        hash.update(record);
    }
    Ok(hex::encode(hash.finalize()))
}

fn dump(message: u16, filter_table: bool) -> Result<Vec<Vec<u8>>> {
    let mut attrs = Vec::new();
    if filter_table {
        attrs.extend(15u16.to_ne_bytes());
        attrs.extend(1u16.to_ne_bytes());
        attrs.extend(b"netcontrol\0");
        attrs.push(0);
    }
    dump_messages(10, message, libc::NFPROTO_INET as u8, &attrs)
}

#[cfg(feature = "nftables")]
pub fn rules() -> Result<Vec<Vec<u8>>> {
    dump(7, true)
}

pub fn connections() -> Result<Vec<Vec<u8>>> {
    dump_messages(1, 1, libc::AF_UNSPEC as u8, &[])
}

pub fn delete_connections(target: Option<(u32, &netcontrol_core::ConnectionTarget)>) -> Result<()> {
    let (family, attrs) = match target {
        Some((id, target)) => crate::conntrack::delete_attributes(id, target)?,
        None => (libc::AF_UNSPEC as u8, Vec::new()),
    };
    exchange(1, 2, family, &attrs, true)?;
    Ok(())
}

fn dump_messages(subsystem: u16, message: u16, family: u8, attrs: &[u8]) -> Result<Vec<Vec<u8>>> {
    exchange(subsystem, message, family, attrs, false)
}

fn delete_acknowledgement(payload: &[u8], request: &[u8]) -> Result<()> {
    ensure!(
        payload.len() >= 20 && payload[4..20] == request[..16],
        "invalid netfilter delete acknowledgement"
    );
    let error = i32::from_ne_bytes(payload[..4].try_into()?);
    ensure!(
        (-4095..=0).contains(&error),
        "invalid netfilter delete error number"
    );
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(-error).into());
    }
    Ok(())
}

fn exchange(
    subsystem: u16,
    message: u16,
    family: u8,
    attrs: &[u8],
    ack: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut request = Vec::new();
    request.extend((20u32 + attrs.len() as u32).to_ne_bytes());
    request.extend(((subsystem << 8) | message).to_ne_bytes());
    request.extend(if ack { 5u16 } else { 0x301u16 }.to_ne_bytes());
    request.extend(1u32.to_ne_bytes());
    request.extend(0u32.to_ne_bytes());
    request.extend([family, 0, 0, 0]);
    request.extend(attrs);
    exchange_request(&request, subsystem, ack, None)
}

pub(super) fn send_batch(request: &[u8], last_sequence: u32) -> Result<()> {
    exchange_request(request, 10, true, Some(last_sequence))?;
    Ok(())
}

fn exchange_request(
    request: &[u8],
    subsystem: u16,
    ack: bool,
    batch_sequence: Option<u32>,
) -> Result<Vec<Vec<u8>>> {
    let mut headers = BTreeMap::new();
    if batch_sequence.is_some() {
        let mut frames = request;
        while !frames.is_empty() {
            ensure!(frames.len() >= 20, "short nftables batch frame");
            let length = u32::from_ne_bytes(frames[..4].try_into()?) as usize;
            ensure!(
                length >= 20 && length <= frames.len(),
                "invalid nftables batch frame"
            );
            headers.insert(u32::from_ne_bytes(frames[8..12].try_into()?), &frames[..16]);
            let aligned = (length + 3) & !3;
            ensure!(aligned <= frames.len(), "short nftables batch padding");
            frames = &frames[aligned..];
        }
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    ensure!(
        fd >= 0,
        "open netfilter socket: {}",
        std::io::Error::last_os_error()
    );
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    ensure!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&address) as u32,
            )
        } == 0,
        "bind netfilter socket: {}",
        std::io::Error::last_os_error()
    );
    if batch_sequence.is_some() {
        // A whole atomic batch is processed before its ACKs can be drained.
        // Reserve bounded queue space for per-rule ACK socket-buffer overhead.
        let capacity: libc::c_int = 4 * 1024 * 1024;
        ensure!(
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &capacity as *const _ as *const _,
                    std::mem::size_of_val(&capacity) as u32,
                )
            } == 0,
            "reserve nftables batch acknowledgement buffer: {}",
            std::io::Error::last_os_error()
        );
    }
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const _,
                std::mem::size_of_val(&timeout) as u32,
            )
        } == 0,
        "netfilter socket timeout"
    );
    ensure!(
        unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr() as *const _,
                request.len(),
                0,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&address) as u32,
            )
        } == request.len() as isize,
        "send netfilter dump"
    );
    let mut result = Vec::new();
    let mut total = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .context("netfilter dump exceeded five-second collection budget")?;
        let timeout = libc::timeval {
            tv_sec: remaining.as_secs() as libc::time_t,
            tv_usec: remaining.subsec_micros().max(1) as libc::suseconds_t,
        };
        ensure!(
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout as *const _ as *const _,
                    std::mem::size_of_val(&timeout) as u32,
                )
            } == 0,
            "netfilter receive timeout"
        );
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut sender_length = std::mem::size_of_val(&sender) as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                libc::MSG_TRUNC,
                &mut sender as *mut _ as *mut libc::sockaddr,
                &mut sender_length,
            )
        };
        ensure!(
            received > 0 && received as usize <= buffer.len(),
            "receive netfilter dump/truncated datagram: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            sender_length as usize == std::mem::size_of_val(&sender)
                && sender.nl_family == libc::AF_NETLINK as u16
                && sender.nl_pid == 0,
            "netfilter response did not originate from the kernel"
        );
        total += received as usize;
        ensure!(total <= 64 * 1024 * 1024, "oversized netfilter inventory");
        let mut data = &buffer[..received as usize];
        while !data.is_empty() {
            ensure!(data.len() >= 16, "short netlink message");
            let length = u32::from_ne_bytes(data[0..4].try_into()?) as usize;
            let kind = u16::from_ne_bytes(data[4..6].try_into()?);
            let flags = u16::from_ne_bytes(data[6..8].try_into()?);
            let sequence = u32::from_ne_bytes(data[8..12].try_into()?);
            ensure!(
                length >= 16
                    && length <= data.len()
                    && batch_sequence.map_or(sequence == 1, |_| headers.contains_key(&sequence)),
                "invalid netfilter response frame"
            );
            ensure!(
                flags & 0x10 == 0,
                "netfilter dump interrupted by concurrent mutation"
            );
            let payload = &data[16..length];
            if kind == 2 {
                if ack {
                    let header = if batch_sequence.is_some() {
                        headers
                            .get(&sequence)
                            .context("unknown nftables acknowledgement")?
                    } else {
                        &request
                    };
                    delete_acknowledgement(payload, header)?;
                    if batch_sequence.is_none_or(|last| sequence == last) {
                        return Ok(result);
                    }
                }
                ensure!(payload.len() >= 4, "short netlink error");
                let error = i32::from_ne_bytes(payload[..4].try_into()?);
                ensure!(
                    error == 0,
                    "netfilter dump: {}",
                    std::io::Error::from_raw_os_error(-error)
                );
            } else if kind == 3 {
                ensure!(!ack, "unexpected dump completion for conntrack delete");
                if payload.len() >= 4 {
                    ensure!(
                        i32::from_ne_bytes(payload[..4].try_into()?) == 0,
                        "netfilter dump failed"
                    );
                }
                return Ok(result);
            } else {
                ensure!(!ack, "unexpected data record for conntrack delete");
                ensure!(kind >> 8 == subsystem, "unexpected netfilter message type");
                ensure!(
                    subsystem != 1 || kind & 0xff == 0,
                    "unexpected conntrack dump record"
                );
                ensure!(
                    subsystem != 1 || result.len() < 100_000,
                    "conntrack snapshot exceeds 100000 entries"
                );
                result.push(payload.to_vec());
            }
            let aligned = (length + 3) & !3;
            ensure!(aligned <= data.len(), "short netlink message padding");
            data = &data[aligned..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_delete_requires_exact_ack_and_preserves_not_found() {
        let mut request = Vec::new();
        request.extend(20u32.to_ne_bytes());
        request.extend(0x102u16.to_ne_bytes());
        request.extend(5u16.to_ne_bytes());
        request.extend(1u32.to_ne_bytes());
        request.extend(0u32.to_ne_bytes());
        request.extend([0; 4]);
        let mut payload = 0i32.to_ne_bytes().to_vec();
        payload.extend(&request[..16]);
        delete_acknowledgement(&payload, &request).unwrap();
        assert!(delete_acknowledgement(&payload[..19], &request).is_err());
        payload[12] ^= 1;
        assert!(delete_acknowledgement(&payload, &request).is_err());
        payload[12] ^= 1;
        payload[..4].copy_from_slice(&(-libc::ENOENT).to_ne_bytes());
        let error = delete_acknowledgement(&payload, &request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        payload[..4].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            delete_acknowledgement(&payload, &request)
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
