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
    let mut request = Vec::new();
    request.extend((if filter_table { 36u32 } else { 20u32 }).to_ne_bytes());
    request.extend(((10u16 << 8) | message).to_ne_bytes());
    request.extend(0x301u16.to_ne_bytes()); // REQUEST | ROOT | MATCH
    request.extend(1u32.to_ne_bytes());
    request.extend(0u32.to_ne_bytes());
    request.extend([libc::NFPROTO_INET as u8, 0, 0, 0]);
    if filter_table {
        request.extend(15u16.to_ne_bytes());
        request.extend(1u16.to_ne_bytes());
        request.extend(b"netcontrol\0");
        request.push(0);
    }
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
        "send nftables dump"
    );
    let mut result = Vec::new();
    let mut total = 0usize;
    loop {
        let mut buffer = vec![0u8; 1024 * 1024];
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        ensure!(
            received > 0 && received as usize <= buffer.len(),
            "receive nftables dump/truncated datagram: {}",
            std::io::Error::last_os_error()
        );
        total += received as usize;
        ensure!(total <= 64 * 1024 * 1024, "oversized nftables inventory");
        let mut data = &buffer[..received as usize];
        while !data.is_empty() {
            ensure!(data.len() >= 16, "short netlink message");
            let length = u32::from_ne_bytes(data[0..4].try_into()?) as usize;
            let kind = u16::from_ne_bytes(data[4..6].try_into()?);
            let flags = u16::from_ne_bytes(data[6..8].try_into()?);
            let sequence = u32::from_ne_bytes(data[8..12].try_into()?);
            ensure!(
                length >= 16 && length <= data.len() && sequence == 1,
                "invalid netfilter response frame"
            );
            ensure!(
                flags & 0x10 == 0,
                "nftables dump interrupted by concurrent mutation"
            );
            let payload = &data[16..length];
            if kind == 2 {
                ensure!(payload.len() >= 4, "short netlink error");
                let error = i32::from_ne_bytes(payload[..4].try_into()?);
                ensure!(
                    error == 0,
                    "nftables dump: {}",
                    std::io::Error::from_raw_os_error(-error)
                );
            } else if kind == 3 {
                if payload.len() >= 4 {
                    ensure!(
                        i32::from_ne_bytes(payload[..4].try_into()?) == 0,
                        "nftables dump failed"
                    );
                }
                return Ok(result);
            } else {
                ensure!(kind >> 8 == 10, "unexpected netfilter message type");
                result.push(payload.to_vec());
            }
            let aligned = (length + 3) & !3;
            ensure!(aligned <= data.len(), "short netlink message padding");
            data = &data[aligned..];
        }
    }
}
