//! Read-only raw dumps preserve chain policy/unknown attributes for strict drift guards.
//! In particular, they avoid relying on lossy high-level netfilter decoders.
use crate::netlink_decode::{attributes, c_string};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::BTreeMap,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

thread_local! {
    static DEADLINE: Cell<Option<std::time::Instant>> = const { Cell::new(None) };
}

pub(super) fn with_budget<T>(
    duration: std::time::Duration,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let previous = DEADLINE.replace(Some(std::time::Instant::now() + duration));
    struct Reset(Option<std::time::Instant>);
    impl Drop for Reset {
        fn drop(&mut self) {
            DEADLINE.set(self.0);
        }
    }
    let _reset = Reset(previous);
    operation()
}

pub fn empty_fingerprint() -> String {
    hex::encode(Sha256::digest([]))
}

pub fn fingerprint() -> Result<String> {
    fingerprint_excluding(&[], None)
}

pub(super) fn normalized_rule(payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() >= 4, "short rule");
    let mut record = Vec::new();
    for (kind, value) in attributes(&payload[4..])? {
        let base = kind & 0x3fff;
        if matches!(base, 3 | 6 | 8 | 9 | 10 | 11) {
            continue;
        }
        let value = if base == 4 {
            canonical_expressions(&crate::firewall_counters::normalize_expressions(&value)?)?
        } else {
            value
        };
        record.push((base, value));
    }
    record.sort();
    Ok(serde_json::to_vec(&record)?)
}

fn canonical_attributes(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for (kind, value) in attributes(bytes)? {
        result.push((kind & 0x3fff, value));
    }
    result.sort();
    Ok(serde_json::to_vec(&result)?)
}

fn canonical_expressions(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut expressions = Vec::new();
    for (kind, expression) in attributes(bytes)? {
        ensure!(kind & 0x3fff == 1, "invalid expression list");
        let fields = attributes(&expression)?;
        ensure!(fields.len() == 2, "unexpected expression fields");
        let name = fields
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 1)
            .context("expression name missing")?;
        let data = fields
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 2)
            .context("expression data missing")?;
        let mut values = Vec::new();
        for (kind, value) in attributes(&data.1)? {
            let base = kind & 0x3fff;
            let nested =
                (name.1 == b"cmp\0" && base == 3) || (name.1 == b"immediate\0" && base == 2);
            let value = if nested {
                let mut data = attributes(&value)?;
                for (kind, value) in &mut data {
                    if *kind & 0x3fff == 2 {
                        *value = canonical_attributes(value)?;
                    }
                    *kind &= 0x3fff;
                }
                data.sort();
                serde_json::to_vec(&data)?
            } else {
                value
            };
            values.push((base, value));
        }
        values.sort();
        expressions.push((name.1.clone(), values));
    }
    Ok(serde_json::to_vec(&expressions)?)
}

pub(super) fn normalized_set(payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() >= 4, "short set");
    let mut attrs = attributes(&payload[4..])?;
    for (kind, value) in &attrs {
        match kind & 0x3fff {
            19 => {
                // Kernel %ps text can include a module suffix and is truncated
                // to 39 bytes; it is informational, not set-policy identity.
                let implementation = c_string(value)?;
                ensure!(
                    !implementation.is_empty()
                        && implementation.len() <= 39
                        && implementation
                            .bytes()
                            .all(|byte| byte.is_ascii_graphic() || byte == b' '),
                    "invalid kernel set implementation metadata"
                );
            }
            20 => {
                // NFTA_SET_COUNT includes elements waiting for timeout GC. Its
                // only owned values are zero or our one explicitly checked key.
                ensure!(
                    value.len() == 4 && u32::from_be_bytes(value.as_slice().try_into()?) <= 1,
                    "foreign element count in owned path-test lease"
                );
            }
            _ => {}
        }
    }
    attrs.retain(|(kind, value)| {
        !matches!(kind & 0x3fff, 10 | 14 | 16 | 19 | 20)
            && !(kind & 0x3fff == 9 && value.is_empty())
    });
    for (kind, _) in &mut attrs {
        *kind &= 0x3fff;
    }
    attrs.sort();
    Ok(serde_json::to_vec(&attrs)?)
}

pub(super) fn fingerprint_excluding(
    owned_rules: &[Vec<u8>],
    lease: Option<&[u8]>,
) -> Result<String> {
    let mut records = Vec::new();
    let mut seen_owned = std::collections::BTreeSet::new();
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
            if message == 10 {
                if let Some(expected) = lease {
                    if normalized_set(&payload)? == normalized_set(expected)? {
                        super::path_test::validate_lease_elements()?;
                        continue;
                    }
                    let expected_attrs = attributes(&expected[4..])?;
                    let owned_identity = [2, 13].iter().all(|identity| {
                        attrs
                            .iter()
                            .find(|(kind, _)| kind & 0x3fff == *identity)
                            .map(|(_, value)| value)
                            == expected_attrs
                                .iter()
                                .find(|(kind, _)| kind & 0x3fff == *identity)
                                .map(|(_, value)| value)
                    });
                    if owned_identity {
                        let observed: Vec<(u16, Vec<u8>)> =
                            serde_json::from_slice(&normalized_set(&payload)?)?;
                        let expected: Vec<(u16, Vec<u8>)> =
                            serde_json::from_slice(&normalized_set(expected)?)?;
                        let changes: Vec<_> = observed
                            .iter()
                            .filter(|field| !expected.contains(field))
                            .map(|(kind, value)| {
                                let expected =
                                    expected.iter().find(|(expected, _)| expected == kind);
                                if matches!(*kind, 3..=12) && value.len() <= 32 {
                                    format!(
                                        "{kind}: observed={}, expected={}",
                                        hex::encode(value),
                                        expected
                                            .map(|(_, value)| hex::encode(value))
                                            .unwrap_or_else(|| "absent".into())
                                    )
                                } else {
                                    format!(
                                        "{kind}: observed length {}, expected length {:?}",
                                        value.len(),
                                        expected.map(|(_, value)| value.len())
                                    )
                                }
                            })
                            .collect();
                        let missing: Vec<_> = expected
                            .iter()
                            .filter(|field| !observed.contains(field))
                            .map(|(kind, _)| *kind)
                            .collect();
                        bail!(
                            "owned path-test lease set metadata differs from durable intent: {}; expected-only fields: {missing:?}",
                            changes.join("; ")
                        );
                    }
                }
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
                if !owned_rules.is_empty() {
                    let normalized = normalized_rule(&payload)?;
                    if owned_rules.contains(&normalized) {
                        ensure!(
                            seen_owned.insert(normalized),
                            "duplicate owned path-test rule"
                        );
                        continue;
                    }
                }
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

pub(super) fn host_firewall_snapshot() -> Result<Vec<Vec<u8>>> {
    let mut snapshot = Vec::new();
    for kind in [1u16, 4, 7, 10, 19, 23] {
        for payload in dump_messages(10, kind, libc::NFPROTO_UNSPEC as u8, &[])? {
            let mut record = kind.to_ne_bytes().to_vec();
            record.extend(payload);
            snapshot.push(record);
        }
    }
    Ok(snapshot)
}

#[cfg(not(feature = "nftables"))]
pub(super) fn clear_host_firewall(_preserve_owned: bool) -> Result<()> {
    bail!("host takeover requires the nftables feature")
}

#[cfg(feature = "nftables")]
pub(super) fn clear_host_firewall(preserve_owned: bool) -> Result<()> {
    use rustables::{Batch, MsgType, ProtocolFamily, Table};
    let mut batch = Batch::new();
    let mut count = 0;
    for payload in dump_messages(10, 1, libc::NFPROTO_UNSPEC as u8, &[])? {
        ensure!(payload.len() >= 4, "short host nftables table");
        let attrs = attributes(&payload[4..])?;
        let name = attrs
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 1)
            .context("nftables table name missing")?;
        let name = c_string(&name.1)?;
        if preserve_owned && payload[0] == libc::NFPROTO_INET as u8 && name == "netcontrol" {
            continue;
        }
        let family = match i32::from(payload[0]) {
            libc::NFPROTO_INET => ProtocolFamily::Inet,
            libc::NFPROTO_IPV4 => ProtocolFamily::Ipv4,
            libc::NFPROTO_IPV6 => ProtocolFamily::Ipv6,
            libc::NFPROTO_ARP => ProtocolFamily::Arp,
            libc::NFPROTO_BRIDGE => ProtocolFamily::Bridge,
            libc::NFPROTO_NETDEV => ProtocolFamily::NetDev,
            _ => bail!("unsupported nftables family {}", payload[0]),
        };
        batch.add(&Table::new(family).with_name(name), MsgType::Del);
        count += 1;
    }
    if count > 0 {
        send_batch(&batch.finalize(), count)?;
    }
    let remaining = dump_messages(10, 1, libc::NFPROTO_UNSPEC as u8, &[])?;
    ensure!(
        remaining.iter().all(|payload| {
            preserve_owned
                && payload.first() == Some(&(libc::NFPROTO_INET as u8))
                && attributes(&payload[4..]).is_ok_and(|attrs| {
                    attrs
                        .iter()
                        .any(|(kind, name)| kind & 0x3fff == 1 && name == b"netcontrol\0")
                })
        }),
        "foreign nftables tables remain after takeover"
    );
    Ok(())
}

pub fn delete_connections(target: Option<(u32, &netcontrol_core::ConnectionTarget)>) -> Result<()> {
    let (family, attrs) = match target {
        Some((id, target)) => crate::conntrack::delete_attributes(id, target)?,
        None => (libc::AF_UNSPEC as u8, Vec::new()),
    };
    exchange(1, 2, family, &attrs, true)?;
    Ok(())
}

pub(super) fn dump_messages(
    subsystem: u16,
    message: u16,
    family: u8,
    attrs: &[u8],
) -> Result<Vec<Vec<u8>>> {
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
    let mut request = request.to_vec();
    prepare_batch(&mut request, last_sequence)?;
    exchange_request(&request, 10, true, Some(last_sequence))?;
    Ok(())
}

fn prepare_batch(request: &mut [u8], last_sequence: u32) -> Result<()> {
    let end_sequence = last_sequence
        .checked_add(1)
        .filter(|_| last_sequence > 0)
        .context("invalid nftables batch sequence")?;
    let mut frames = request;
    let mut expected = 0u64;
    while !frames.is_empty() {
        ensure!(frames.len() >= 20, "short nftables batch frame");
        let length = u32::from_ne_bytes(frames[..4].try_into()?) as usize;
        let aligned = (length + 3) & !3;
        ensure!(
            length >= 20 && aligned <= frames.len(),
            "invalid nftables batch frame"
        );
        let sequence = u32::from_ne_bytes(frames[8..12].try_into()?);
        let kind = u16::from_ne_bytes(frames[4..6].try_into()?);
        ensure!(
            u64::from(sequence) == expected
                && sequence <= end_sequence
                && if sequence == 0 {
                    kind == libc::NFNL_MSG_BATCH_BEGIN as u16
                } else if sequence == end_sequence {
                    kind == libc::NFNL_MSG_BATCH_END as u16
                } else {
                    kind >> 8 == 10
                },
            "invalid nftables batch ordering"
        );
        // Errors are returned even without NLM_F_ACK. One final success ACK
        // avoids overflowing the receive queue before an atomic batch completes.
        let mut flags = u16::from_ne_bytes(frames[6..8].try_into()?) & !4;
        if sequence == last_sequence {
            flags |= 4;
        }
        frames[6..8].copy_from_slice(&flags.to_ne_bytes());
        expected += 1;
        frames = &mut frames[aligned..];
    }
    ensure!(
        expected == u64::from(end_sequence) + 1,
        "incomplete nftables batch"
    );
    Ok(())
}

fn reserve_batch_send_buffer(fd: &OwnedFd, length: usize) -> Result<()> {
    // Netlink requires the entire transaction in one datagram and leaves
    // 32 bytes of socket-buffer headroom. Never split the atomic transaction.
    let required = length
        .checked_add(32)
        .and_then(|length| libc::c_int::try_from(length).ok())
        .context("nftables transaction exceeds socket buffer size range")?;
    let set = |option| -> Result<()> {
        ensure!(
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    &required as *const _ as *const _,
                    std::mem::size_of_val(&required) as u32,
                )
            } == 0,
            "reserve {length}-byte atomic nftables send buffer: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    };
    let capacity = || -> Result<libc::c_int> {
        let mut capacity: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&capacity) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &mut capacity as *mut _ as *mut _,
                    &mut size,
                )
            } == 0,
            "read nftables send buffer capacity: {}",
            std::io::Error::last_os_error()
        );
        Ok(capacity)
    };
    set(libc::SO_SNDBUF)?;
    if capacity()? < required {
        // SO_SNDBUF is silently clamped by wmem_max. NET_ADMIN is already
        // required for firewall mutation; FORCE changes only this socket.
        set(libc::SO_SNDBUFFORCE)?;
    }
    ensure!(
        capacity()? >= required,
        "kernel send buffer cannot hold {length}-byte atomic nftables transaction"
    );
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
        reserve_batch_send_buffer(&fd, request.len())?;
        // Leave room for error responses; successful batches need only one ACK.
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
        "send {}-byte netfilter request: {}",
        request.len(),
        std::io::Error::last_os_error()
    );
    let mut result = Vec::new();
    let mut total = 0usize;
    let default_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let deadline = DEADLINE
        .get()
        .map_or(default_deadline, |deadline| deadline.min(default_deadline));
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
    fn atomic_batch_requests_only_the_final_success_ack() -> Result<()> {
        let table = rustables::Table::new(rustables::ProtocolFamily::Inet).with_name("netcontrol");
        let mut batch = rustables::Batch::new();
        batch.add(&table, rustables::MsgType::Add);
        batch.add(&table, rustables::MsgType::Del);
        batch.add(&table, rustables::MsgType::Add);
        let original = batch.finalize();
        let mut request = original.clone();
        prepare_batch(&mut request, 3)?;
        let mut offset = 0;
        for sequence in 0..=4 {
            let length = u32::from_ne_bytes(request[offset..offset + 4].try_into()?) as usize;
            let mut expected = original[offset..offset + length].to_vec();
            let flags = u16::from_ne_bytes(expected[6..8].try_into()?);
            let flags = (flags & !4) | if sequence == 3 { 4 } else { 0 };
            expected[6..8].copy_from_slice(&flags.to_ne_bytes());
            assert_eq!(request[offset..offset + length], expected);
            offset += (length + 3) & !3;
        }
        assert_eq!(offset, request.len());
        for length in [0, 19, original.len() - 1, original.len() - 20] {
            assert!(prepare_batch(&mut original[..length].to_vec(), 3).is_err());
        }
        for last in [0, 2, 4, u32::MAX] {
            assert!(prepare_batch(&mut original.clone(), last).is_err());
        }
        for (offset, value) in [(0, 19u32), (8, 1u32), (28, 0u32)] {
            let mut invalid = original.clone();
            invalid[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            assert!(prepare_batch(&mut invalid, 3).is_err());
        }
        let mut invalid = original;
        invalid[4..6].copy_from_slice(&0x0a00u16.to_ne_bytes());
        assert!(prepare_batch(&mut invalid, 3).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_NET_ADMIN"]
    fn atomic_batch_send_buffer_exceeds_the_normal_socket_limit() -> Result<()> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "set NETCONTROL_INTEGRATION=1 for privileged native integration tests"
        );
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        ensure!(raw >= 0, "open test netfilter socket");
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let maximum: usize = std::fs::read_to_string("/proc/sys/net/core/wmem_max")?
            .trim()
            .parse()?;
        let length = maximum.checked_mul(2).context("socket limit overflow")? + 4096;
        reserve_batch_send_buffer(&fd, length)?;
        let mut capacity: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&capacity) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &mut capacity as *mut _ as *mut _,
                    &mut size,
                )
            },
            0
        );
        assert!(capacity as usize >= length + 32);
        assert!(reserve_batch_send_buffer(&fd, usize::MAX).is_err());
        Ok(())
    }

    fn set_payload(fields: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![1, 0, 0, 0];
        for (kind, value) in fields {
            let length = value.len() + 4;
            bytes.extend((length as u16).to_ne_bytes());
            bytes.extend(kind.to_ne_bytes());
            bytes.extend(value);
            bytes.resize((bytes.len() + 3) & !3, 0);
        }
        bytes
    }

    #[test]
    fn lease_set_normalization_preserves_identity_and_ignores_only_kernel_bookkeeping() {
        let fields = vec![
            (1, b"netcontrol\0".to_vec()),
            (2, b"netcontrol_path_test_lease\0".to_vec()),
            (3, 16u32.to_be_bytes().to_vec()),
            (4, 0u32.to_be_bytes().to_vec()),
            (5, 4u32.to_be_bytes().to_vec()),
            (11, 90000u64.to_be_bytes().to_vec()),
            (13, b"netcontrol-path-test:synthetic".to_vec()),
        ];
        let mut request = fields.clone();
        request.push((10, 1u32.to_be_bytes().to_vec()));
        let mut kernel = fields.clone();
        kernel.push((9, Vec::new()));
        kernel.push((14, Vec::new()));
        kernel.push((16, 7u64.to_be_bytes().to_vec()));
        kernel.push((19, b"nft_rhash_fast_ops\0".to_vec()));
        kernel.push((20, 1u32.to_be_bytes().to_vec()));
        kernel.reverse();
        for (kind, _) in &mut kernel {
            *kind |= 0x4000;
        }
        let expected = normalized_set(&set_payload(&request)).unwrap();
        assert_eq!(expected, normalized_set(&set_payload(&kernel)).unwrap());
        let truncated = format!("{} [nf_tables\0", "nft_".repeat(7));
        assert_eq!(truncated.len(), 40);
        for implementation in [
            b"nft_rhash_fast_ops\0".as_slice(),
            b"nft_rhash_fast_ops [nf_tables]\0",
            b"nft_rhash_fast_ops.llvm.1 [nf_tables]\0",
            truncated.as_bytes(),
        ] {
            let mut observed = fields.clone();
            observed.push((19, implementation.to_vec()));
            assert_eq!(expected, normalized_set(&set_payload(&observed)).unwrap());
        }
        for field in [2, 3, 4, 5, 11, 13] {
            let mut changed = fields.clone();
            changed
                .iter_mut()
                .find(|(kind, _)| *kind == field)
                .unwrap()
                .1
                .push(1);
            assert_ne!(expected, normalized_set(&set_payload(&changed)).unwrap());
        }
        let mut unknown = fields.clone();
        unknown.push((21, Vec::new()));
        assert_ne!(expected, normalized_set(&set_payload(&unknown)).unwrap());
        for count in [0u32, 1] {
            let mut observed = fields.clone();
            observed.push((20, count.to_be_bytes().to_vec()));
            assert_eq!(expected, normalized_set(&set_payload(&observed)).unwrap());
        }
        let mut foreign_count = fields.clone();
        foreign_count.push((20, 2u32.to_be_bytes().to_vec()));
        assert!(normalized_set(&set_payload(&foreign_count)).is_err());
        for implementation in [
            b"not-terminated".to_vec(),
            b"\0".to_vec(),
            b"nft_rhash\0extra\0".to_vec(),
            b"nft_rhash\n[nf_tables]\0".to_vec(),
            b"nft_rhash\t[nf_tables]\0".to_vec(),
            b"nft_rhash\x7f\0".to_vec(),
            b"nft_rhash\xff\0".to_vec(),
            format!("{}\0", "x".repeat(40)).into_bytes(),
        ] {
            let mut invalid_type = fields.clone();
            invalid_type.push((19, implementation));
            assert!(normalized_set(&set_payload(&invalid_type)).is_err());
        }
    }

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
