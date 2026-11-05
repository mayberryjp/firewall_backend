//! Bounded Linux nftables UAPI encoding; no textual rules or external processes.
use super::{attribute, unix_ns};
use crate::linux::netfilter;
use crate::netlink_decode::{attributes, c_string};
use anyhow::{Context, Result, ensure};
use netcontrol_core::{PATH_TEST_LIFETIME_SECONDS, PathTestRequest};
use std::net::IpAddr;

const TABLE: &[u8] = b"netcontrol\0";
const LEASE: &[u8] = b"netcontrol_path_test_lease\0";
const INET: u8 = libc::NFPROTO_INET as u8;
const NESTED: u16 = 0x8000;

fn number(kind: u16, number: u32) -> Vec<u8> {
    attribute(kind, &number.to_be_bytes())
}

fn expression(name: &str, data: Vec<u8>) -> Vec<u8> {
    attribute(
        1 | NESTED,
        &[
            attribute(1, format!("{name}\0").as_bytes()),
            attribute(2 | NESTED, &data),
        ]
        .concat(),
    )
}

fn compare(bytes: &[u8]) -> Vec<u8> {
    expression(
        "cmp",
        [
            number(1, 1),
            number(2, 0),
            attribute(3 | NESTED, &attribute(1, bytes)),
        ]
        .concat(),
    )
}

fn meta(key: u32) -> Vec<u8> {
    expression("meta", [number(1, 1), number(2, key)].concat())
}

fn payload(base: u32, offset: u32, length: u32) -> Vec<u8> {
    expression(
        "payload",
        [
            number(1, 1),
            number(2, base),
            number(3, offset),
            number(4, length),
        ]
        .concat(),
    )
}

fn immediate(register: u32, data: Vec<u8>) -> Vec<u8> {
    expression(
        "immediate",
        [number(1, register), attribute(2 | NESTED, &data)].concat(),
    )
}

fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend((16u32 + payload.len() as u32).to_ne_bytes());
    result.extend(((10u16 << 8) | kind).to_ne_bytes());
    result.extend(flags.to_ne_bytes());
    result.extend(sequence.to_ne_bytes());
    result.extend(0u32.to_ne_bytes());
    result.extend(payload);
    result
}

fn batch(items: &[(u16, u16, Vec<u8>)]) -> Result<()> {
    ensure!(
        items.len() <= 16,
        "path-test nftables batch exceeds its fixed bound"
    );
    let frame = |kind: u16, sequence: u32| {
        let mut bytes = Vec::new();
        bytes.extend(20u32.to_ne_bytes());
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(1u16.to_ne_bytes());
        bytes.extend(sequence.to_ne_bytes());
        bytes.extend(0u32.to_ne_bytes());
        bytes.extend([libc::AF_UNSPEC as u8, 0, 0, 10]);
        bytes
    };
    let mut bytes = frame(0x10, 0); // NFNL_MSG_BATCH_BEGIN
    for (index, (kind, flags, payload)) in items.iter().enumerate() {
        bytes.extend(message(*kind, *flags, index as u32 + 1, payload));
    }
    bytes.extend(frame(0x11, items.len() as u32 + 1));
    netfilter::send_batch(&bytes, items.len() as u32)
}

fn nft_payload(attrs: Vec<u8>) -> Vec<u8> {
    [[INET, 0, 0, 0].to_vec(), attrs].concat()
}

pub(super) fn rules(
    request: &PathTestRequest,
    id: &str,
    _deadline: u64,
) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let timeout = PATH_TEST_LIFETIME_SECONDS * 1000;
    let lease = nft_payload(
        [
            attribute(1, TABLE),
            attribute(2, LEASE),
            number(3, 0x10), // NFT_SET_TIMEOUT: expiration uses kernel monotonic timers
            number(4, 0),
            number(5, 4),
            number(10, 1),
            attribute(11, &timeout.to_be_bytes()),
            attribute(13, format!("netcontrol-path-test:{id}").as_bytes()),
        ]
        .concat(),
    );
    let mut rules = Vec::new();
    for outbound in [false, true] {
        let (source, peer) = if outbound {
            (request.source_address, request.peer_address)
        } else {
            (request.peer_address, request.source_address)
        };
        let (family, source, peer, source_offset, destination_offset) = match (source, peer) {
            (IpAddr::V4(source), IpAddr::V4(peer)) => (
                libc::NFPROTO_IPV4 as u8,
                source.octets().to_vec(),
                peer.octets().to_vec(),
                12,
                16,
            ),
            (IpAddr::V6(source), IpAddr::V6(peer)) => (
                libc::NFPROTO_IPV6 as u8,
                source.octets().to_vec(),
                peer.octets().to_vec(),
                8,
                24,
            ),
            _ => anyhow::bail!("mixed path-test address families"),
        };
        let mut interface = [0; libc::IFNAMSIZ];
        ensure!(
            request.interface.len() < interface.len(),
            "invalid interface name"
        );
        interface[..request.interface.len()].copy_from_slice(request.interface.as_bytes());
        for protocol in [libc::IPPROTO_UDP as u8, libc::IPPROTO_TCP as u8] {
            for source_port in [false, true] {
                let mut expressions = [
                    // The lease independently expires after <=90s even when userspace
                    // crashes or CLOCK_REALTIME steps backwards.
                    immediate(1, attribute(1, &1u32.to_be_bytes())),
                    expression(
                        "lookup",
                        [attribute(1, LEASE), number(2, 1), number(5, 0)].concat(),
                    ),
                    meta(if outbound { 7 } else { 6 }),
                    compare(&interface),
                    meta(15),
                    compare(&[family]),
                    meta(16),
                    compare(&[protocol]),
                    payload(1, source_offset, source.len() as u32),
                    compare(&source),
                    payload(1, destination_offset, peer.len() as u32),
                    compare(&peer),
                    payload(2, if source_port { 0 } else { 2 }, 2),
                    compare(&request.port.to_be_bytes()),
                ]
                .concat();
                if protocol == libc::IPPROTO_UDP as u8 {
                    // Both UDP endpoints reserve the same configured test port.
                    expressions.extend(payload(2, if source_port { 2 } else { 0 }, 2));
                    expressions.extend(compare(&request.port.to_be_bytes()));
                } else if source_port {
                    // A peer choosing our test port as its source must not gain
                    // NEW access to arbitrary local ports. Only replies to an
                    // already established, exact-peer TCP trial are permitted.
                    expressions.extend(expression("ct", [number(1, 1), number(2, 0)].concat()));
                    expressions.extend(compare(&2u32.to_ne_bytes()));
                }
                expressions.extend(immediate(0, attribute(2 | NESTED, &number(1, 1)))); // NFT_REG_VERDICT, NF_ACCEPT
                rules.push(nft_payload(
                    [
                        attribute(1, TABLE),
                        attribute(2, if outbound { b"output\0" } else { b"input\0" }),
                        attribute(4 | NESTED, &expressions),
                        attribute(
                            7,
                            format!(
                                "netcontrol-path-test:{id}:{outbound}:{protocol}:{source_port}"
                            )
                            .as_bytes(),
                        ),
                    ]
                    .concat(),
                ));
            }
        }
    }
    Ok((rules, lease))
}

pub(super) fn install(rules: &[Vec<u8>], lease: &[u8]) -> Result<()> {
    let mut messages = vec![(9, 0x605, lease.to_vec())]; // NEWSET REQUEST|ACK|CREATE|EXCL
    let element = attribute(
        1 | NESTED,
        &attribute(1 | NESTED, &attribute(1, &1u32.to_be_bytes())),
    );
    messages.push((
        12,
        0x605,
        nft_payload(
            [
                attribute(1, TABLE),
                attribute(2, LEASE),
                attribute(3 | NESTED, &element),
                number(4, 1),
            ]
            .concat(),
        ),
    ));
    for rule in rules {
        // Deliberately omit APPEND: insertion is before the actual enforcement
        // chain's configured drop rules, not a bypassing parallel base chain.
        messages.push((6, 0x405, rule.clone()));
    }
    batch(&messages)
}

pub(super) fn remove(rules: &[Vec<u8>], lease: &[u8], before: &str) -> Result<()> {
    let normalized = rules
        .iter()
        .map(|rule| netfilter::normalized_rule(rule))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        netfilter::fingerprint_excluding(&normalized, Some(lease))? == before,
        "external firewall change: refusing to replace or adopt it"
    );
    let mut messages = Vec::new();
    for rule in netfilter::dump_messages(10, 7, INET, &attribute(1, TABLE))? {
        if !normalized.contains(&netfilter::normalized_rule(&rule)?) {
            continue;
        }
        let attrs = attributes(&rule[4..])?;
        let chain = attrs
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 2)
            .context("owned rule chain missing")?;
        let handle = attrs
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 3)
            .context("owned rule handle missing")?;
        messages.push((
            8,
            5,
            nft_payload(
                [
                    attribute(1, TABLE),
                    attribute(2, &chain.1),
                    attribute(3, &handle.1),
                ]
                .concat(),
            ),
        ));
    }
    let sets = netfilter::dump_messages(10, 10, INET, &attribute(1, TABLE))?;
    let mut lease_exists = false;
    for set in sets {
        if netfilter::normalized_set(&set)? == netfilter::normalized_set(lease)? {
            lease_exists = true;
        }
    }
    if lease_exists {
        messages.push((
            11,
            5,
            nft_payload([attribute(1, TABLE), attribute(2, LEASE)].concat()),
        ));
    }
    if !messages.is_empty() {
        batch(&messages)?;
    }
    ensure!(
        netfilter::fingerprint()? == before,
        "firewall restoration verification failed"
    );
    Ok(())
}

pub(crate) fn validate_lease_elements() -> Result<()> {
    let attrs = [attribute(1, TABLE), attribute(2, LEASE)].concat();
    for payload in netfilter::dump_messages(10, 13, INET, &attrs)? {
        ensure!(payload.len() >= 4, "short lease element response");
        let attrs = attributes(&payload[4..])?;
        ensure!(
            attrs.iter().all(|(kind, _)| matches!(kind & 0x3fff, 1..=4)),
            "unexpected lease element attributes"
        );
        for (_, elements) in attrs.iter().filter(|(kind, _)| kind & 0x3fff == 3) {
            let elements = attributes(elements)?;
            ensure!(elements.len() <= 1, "foreign elements in owned test lease");
            for (_, element) in elements {
                let values = attributes(&element)?;
                let key = values
                    .iter()
                    .find(|(kind, _)| kind & 0x3fff == 1)
                    .context("lease key missing")?;
                ensure!(
                    attributes(&key.1)? == vec![(1, 1u32.to_be_bytes().to_vec())],
                    "foreign key in owned test lease"
                );
                for (kind, bytes) in values {
                    match kind & 0x3fff {
                        1 | 8 => {}
                        4 | 5 => ensure!(
                            bytes.len() == 8
                                && u64::from_be_bytes(bytes.as_slice().try_into()?)
                                    <= PATH_TEST_LIFETIME_SECONDS * 1000,
                            "foreign timeout in owned test lease"
                        ),
                        _ => anyhow::bail!("foreign data in owned test lease"),
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn check_enforcement() -> Result<()> {
    let mut input = false;
    let mut output = false;
    for payload in netfilter::dump_messages(10, 4, libc::AF_UNSPEC as u8, &[])? {
        ensure!(payload.len() >= 4, "short nftables enforcement chain");
        let attrs = attributes(&payload[4..])?;
        let table = attrs
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 1)
            .context("chain table missing")?;
        let name = attrs
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 3)
            .context("chain name missing")?;
        let Some((_, hook)) = attrs.iter().find(|(kind, _)| kind & 0x3fff == 4) else {
            continue;
        };
        let hook_attrs = attributes(hook)?;
        let hook = hook_attrs
            .iter()
            .find(|(kind, _)| kind & 0x3fff == 1)
            .context("chain hook missing")?;
        ensure!(hook.1.len() == 4, "invalid chain hook");
        let hook = u32::from_be_bytes(hook.1.as_slice().try_into()?);
        // Foreign ingress/prerouting, postrouting or egress enforcement can also
        // reject/redirect plaintext. Refuse rather than claim an open path.
        if payload[0] != INET || table.1 != TABLE {
            if matches!(payload[0], 1 | 2 | 10) && hook == 2 {
                continue;
            }
            anyhow::bail!("foreign nftables enforcement chain makes scoped test permits ambiguous");
        }
        let name = c_string(&name.1)?;
        if hook == 1 {
            ensure!(name == "input", "unexpected native input enforcement chain");
            input = true;
        } else if hook == 3 {
            ensure!(
                name == "output",
                "unexpected native output enforcement chain"
            );
            output = true;
        }
    }
    ensure!(
        input && output,
        "owned firewall has no canonical input/output enforcement chains; apply current configuration first"
    );
    ensure!(unix_ns()? != 0, "system clock is unavailable");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> PathTestRequest {
        serde_json::from_value(json!({"interface":"test0","source_address":"192.0.2.1",
            "peer_address":"192.0.2.2","maximum_mtu":9000,
            "pairing_secret":"synthetic-pairing-secret-1234567890"}))
        .unwrap()
    }

    #[test]
    fn permits_are_exact_scoped_and_expiring_in_real_enforcement_chains() {
        let (rules, lease) = rules(&request(), "0123456789abcdef0123456789abcdef", 123456).unwrap();
        assert_eq!(rules.len(), 8);
        assert!(
            lease
                .windows(8)
                .any(|value| value == 90000u64.to_be_bytes())
        );
        for rule in rules {
            let attrs = attributes(&rule[4..]).unwrap();
            let chain = attrs.iter().find(|(kind, _)| kind & 0x3fff == 2).unwrap();
            assert!([b"input\0".as_slice(), b"output\0"].contains(&chain.1.as_slice()));
            let expressions = attrs.iter().find(|(kind, _)| kind & 0x3fff == 4).unwrap();
            let userdata = &attrs.iter().find(|(kind, _)| kind & 0x3fff == 7).unwrap().1;
            for (_, expression) in attributes(&expressions.1).unwrap() {
                let fields = attributes(&expression).unwrap();
                if fields
                    .iter()
                    .any(|(kind, value)| kind & 0x3fff == 1 && value == b"lookup\0")
                {
                    let data = fields.iter().find(|(kind, _)| kind & 0x3fff == 2).unwrap();
                    assert!(
                        attributes(&data.1)
                            .unwrap()
                            .contains(&(5, 0u32.to_be_bytes().to_vec()))
                    );
                }
            }
            if userdata.ends_with(b":6:true") {
                assert!(expressions.1.windows(3).any(|value| value == b"ct\0"));
            }
            assert!(expressions.1.windows(7).any(|value| value == b"lookup\0"));
            assert!(
                expressions
                    .1
                    .windows(4)
                    .any(|value| value == [192, 0, 2, 1])
            );
            assert!(
                expressions
                    .1
                    .windows(4)
                    .any(|value| value == [192, 0, 2, 2])
            );
            assert!(
                expressions
                    .1
                    .windows(2)
                    .any(|value| value == request().port.to_be_bytes())
            );
            assert!(!rule.windows(6).any(|value| value == b"secret"));
        }
    }
}
