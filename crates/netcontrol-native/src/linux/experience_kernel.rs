use super::nft_wire::{attribute as a, expression as expr, number as n};
use crate::netlink_decode::{attributes, c_string};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::IpAddr};

pub(super) const TABLE: &str = "netcontrol_experience";
pub(super) const OWNER: &[u8] = b"netcontrol-experience-v1";
pub(super) const DROP_CHAIN: &str = "experience_drop";
pub(super) const GROUP: u16 = 101;
type Item = (u16, u16, Vec<u8>);

fn string(kind: u16, value: &str) -> Vec<u8> {
    a(kind, format!("{value}\0").as_bytes())
}
fn counter_last() -> Vec<u8> {
    [
        expr(
            "counter",
            [a(1, &0u64.to_be_bytes()), a(2, &0u64.to_be_bytes())].concat(),
        ),
        expr("last", [n(1, 0), a(2, &0u64.to_be_bytes())].concat()),
    ]
    .concat()
}
fn set(table: &str, name: &str, ipv6: bool, dynamic: bool, keys: &[Vec<u8>]) -> Result<Item> {
    set_key(table, name, if ipv6 { 32 } else { 20 }, dynamic, keys)
}
fn set_key(table: &str, name: &str, length: u32, dynamic: bool, keys: &[Vec<u8>]) -> Result<Item> {
    let id = [
        "exp_eligible4",
        "exp_sent4",
        "exp_received4",
        "exp_eligible6",
        "exp_sent6",
        "exp_received6",
        "exp_lan",
        "exp_drop_sent4",
        "exp_drop_received4",
        "exp_drop_sent6",
        "exp_drop_received6",
    ]
    .iter()
    .position(|candidate| *candidate == name)
    .context("unknown experience set declaration")? as u32
        + 1;
    let hash = hex::encode(Sha256::digest(keys.concat()));
    Ok((
        9,
        0x605,
        [
            string(1, table),
            string(2, name),
            n(3, if dynamic { 0x120 } else { 0 }),
            n(4, 0),
            n(5, length),
            a(0x8009, &n(1, 2048)),
            n(10, id),
            a(13, format!("netcontrol-experience-v1:{hash}").as_bytes()),
            if dynamic {
                a(0x8012, &counter_last())
            } else {
                Vec::new()
            },
        ]
        .concat(),
    ))
}
fn key_items(table: &str, name: &str, keys: &[Vec<u8>]) -> Vec<Item> {
    keys.chunks(512)
        .map(|keys| {
            let values = keys
                .iter()
                .map(|key| a(0x8001, &a(0x8001, &a(1, key))))
                .collect::<Vec<_>>()
                .concat();
            (
                12,
                0x605,
                [string(1, table), string(2, name), a(0x8003, &values)].concat(),
            )
        })
        .collect()
}
fn key(interface: &str, ip: IpAddr) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[..interface.len()].copy_from_slice(interface.as_bytes());
    match ip {
        IpAddr::V4(ip) => bytes.extend(ip.octets()),
        IpAddr::V6(ip) => bytes.extend(ip.octets()),
    }
    bytes
}
fn load(ipv6: bool, sent: bool) -> Vec<u8> {
    let offset = match (ipv6, sent) {
        (false, true) => 12,
        (false, false) => 16,
        (true, true) => 8,
        (true, false) => 24,
    };
    [
        expr("meta", [n(1, 4), n(2, 15)].concat()),
        expr(
            "cmp",
            [
                n(1, 4),
                n(2, 0),
                a(0x8003, &a(1, &[if ipv6 { 10 } else { 2 }])),
            ]
            .concat(),
        ),
        expr("meta", [n(1, 1), n(2, if sent { 6 } else { 7 })].concat()),
        expr(
            "payload",
            [
                n(1, 2),
                n(2, 1),
                n(3, offset),
                n(4, if ipv6 { 16 } else { 4 }),
            ]
            .concat(),
        ),
        expr(
            "lookup",
            [
                string(
                    1,
                    if ipv6 {
                        "exp_eligible6"
                    } else {
                        "exp_eligible4"
                    },
                ),
                n(2, 1),
            ]
            .concat(),
        ),
    ]
    .concat()
}
fn update(name: &str) -> Vec<u8> {
    expr(
        "dynset",
        [
            string(1, name),
            n(3, 1),
            n(4, 1),
            n(9, 2),
            a(0x800a, &counter_last()),
        ]
        .concat(),
    )
}
fn compare(register: u32, bytes: &[u8]) -> Vec<u8> {
    expr(
        "cmp",
        [n(1, register), n(2, 0), a(0x8003, &a(1, bytes))].concat(),
    )
}
#[derive(Clone, Copy)]
enum DnsPort {
    Source,
    Destination,
    OriginalDestination,
}
fn transport_capture(ipv6: bool, sent: bool, protocol: u8, port: Option<DnsPort>) -> Vec<u8> {
    let mut expressions = load(ipv6, sent);
    expressions.extend(expr("meta", [n(1, 3), n(2, 16)].concat()));
    expressions.extend(compare(3, &[protocol]));
    if let Some(port) = port {
        expressions.extend(match port {
            DnsPort::Source | DnsPort::Destination => expr(
                "payload",
                [
                    n(1, 3),
                    n(2, 2),
                    n(
                        3,
                        if matches!(port, DnsPort::Source) {
                            0
                        } else {
                            2
                        },
                    ),
                    n(4, 2),
                ]
                .concat(),
            ),
            DnsPort::OriginalDestination => expr("ct", [n(1, 3), n(2, 12), a(3, &[0])].concat()),
        });
        expressions.extend(compare(3, &53u16.to_be_bytes()));
    }
    expressions.extend(expr(
        "log",
        [
            a(1, &GROUP.to_be_bytes()),
            string(2, if sent { "exp:sent" } else { "exp:received" }),
            n(3, if port.is_some() { 4608 } else { 256 }),
            a(4, &32u16.to_be_bytes()),
        ]
        .concat(),
    ));
    expressions.extend(expr(
        "immediate",
        [n(1, 0), a(0x8002, &a(0x8002, &n(1, (-5i32) as u32)))].concat(),
    ));
    expressions
}
fn rule(table: &str, chain: &str, expressions: Vec<u8>) -> Item {
    (
        6,
        0xc05,
        [
            string(1, table),
            string(2, chain),
            a(0x8004, &expressions),
            a(7, OWNER),
        ]
        .concat(),
    )
}
fn elements(table: &str, name: &str) -> Result<Vec<Vec<u8>>> {
    let values =
        super::netfilter::dump_messages(10, 13, 1, &[string(1, table), string(2, name)].concat())?;
    let mut output = Vec::new();
    for value in values {
        for (kind, data) in attributes(&value[4..])? {
            if kind & 0x3fff == 3 {
                for (kind, elem) in attributes(&data)? {
                    ensure!(kind & 0x3fff == 1, "invalid experience set element");
                    output.push(elem);
                }
            }
        }
    }
    ensure!(
        output.len() <= 2048,
        "experience set exceeds host address bound"
    );
    Ok(output)
}
pub(super) fn is_set(payload: &[u8]) -> Result<bool> {
    let attrs = attributes(&payload[4..])?;
    let name = attrs
        .iter()
        .find(|(k, _)| k & 0x3fff == 2)
        .context("set name missing")?;
    Ok(matches!(
        c_string(&name.1)?,
        "exp_lan"
            | "exp_eligible4"
            | "exp_eligible6"
            | "exp_drop_sent4"
            | "exp_drop_sent6"
            | "exp_drop_received4"
            | "exp_drop_received6"
    ))
}
pub(super) fn normalize_set(payload: &[u8], table: &str) -> Result<Vec<u8>> {
    let mut attrs = attributes(&payload[4..])?;
    let name = c_string(
        &attrs
            .iter()
            .find(|(k, _)| k & 0x3fff == 2)
            .context("set name missing")?
            .1,
    )?;
    ensure!(
        matches!(
            name,
            "exp_lan"
                | "exp_eligible4"
                | "exp_eligible6"
                | "exp_drop_sent4"
                | "exp_drop_sent6"
                | "exp_drop_received4"
                | "exp_drop_received6"
                | "exp_sent4"
                | "exp_sent6"
                | "exp_received4"
                | "exp_received6"
        ),
        "foreign set in experience accounting table"
    );
    let owner = &attrs
        .iter()
        .find(|(k, _)| k & 0x3fff == 13)
        .context("experience set owner missing")?
        .1;
    let owner = std::str::from_utf8(owner)?;
    ensure!(
        owner.starts_with("netcontrol-experience-v1:") && owner.len() == 89,
        "unowned experience accounting set"
    );
    let mut keys = Vec::new();
    for elem in elements(table, name)? {
        let attrs = attributes(&elem)?;
        let data = &attrs
            .iter()
            .find(|(k, _)| k & 0x3fff == 1)
            .context("element key missing")?
            .1;
        let fields = attributes(data)?;
        keys.push(
            fields
                .iter()
                .find(|(k, _)| k & 0x3fff == 1)
                .context("element value missing")?
                .1
                .clone(),
        );
    }
    keys.sort();
    if name == "exp_lan" || name.starts_with("exp_eligible") {
        ensure!(
            hex::encode(Sha256::digest(keys.concat())) == owner[25..],
            "experience host membership drift"
        );
    } else {
        let mut eligible = std::collections::BTreeSet::new();
        for elem in elements(
            table,
            if name.ends_with('6') {
                "exp_eligible6"
            } else {
                "exp_eligible4"
            },
        )? {
            let attrs = attributes(&elem)?;
            let data = &attrs
                .iter()
                .find(|(k, _)| k & 0x3fff == 1)
                .context("eligible key missing")?
                .1;
            let fields = attributes(data)?;
            eligible.insert(
                fields
                    .iter()
                    .find(|(k, _)| k & 0x3fff == 1)
                    .context("eligible value missing")?
                    .1
                    .clone(),
            );
        }
        ensure!(
            keys.iter().all(|key| eligible.contains(key)),
            "foreign experience counter membership"
        );
    }
    attrs.retain(|(k, _)| !matches!(k & 0x3fff, 10 | 14 | 16 | 19 | 20));
    for (kind, _) in &mut attrs {
        *kind &= 0x3fff;
    }
    attrs.sort();
    Ok(serde_json::to_vec(&attrs)?)
}
fn layout(table: &str, hosts: &BTreeMap<IpAddr, String>) -> Result<(Vec<Item>, Vec<Item>)> {
    let mut sets = Vec::new();
    let mut rules = Vec::new();
    for ipv6 in [false, true] {
        let suffix = if ipv6 { "6" } else { "4" };
        let mut keys: Vec<_> = hosts
            .iter()
            .filter(|(ip, _)| ip.is_ipv6() == ipv6)
            .map(|(ip, name)| key(name, *ip))
            .collect();
        keys.sort();
        let eligible = format!("exp_eligible{suffix}");
        sets.push(set(table, &eligible, ipv6, false, &keys)?);
        sets.extend(key_items(table, &eligible, &keys));
        for sent in [true, false] {
            let name = format!("exp_{}{suffix}", if sent { "sent" } else { "received" });
            sets.push(set(table, &name, ipv6, true, &keys)?);
            let chain = if sent { "ingress" } else { "egress" };
            rules.push(rule(
                table,
                chain,
                [load(ipv6, sent), update(&name)].concat(),
            ));
        }
    }
    Ok((sets, rules))
}
pub(super) fn drop_layout(
    value: &serde_json::Value,
    links: &[crate::model::Link],
) -> Result<(Vec<Item>, Vec<Item>)> {
    let mut hosts = std::collections::BTreeSet::new();
    if let Some(rows) = value["policies"]["hosts"].as_array() {
        for host in rows {
            for address in host["addresses"]
                .as_array()
                .context("host addresses missing")?
            {
                let ip: IpAddr = address.as_str().context("invalid host address")?.parse()?;
                hosts.insert(ip);
            }
        }
    }
    let mut sets = Vec::new();
    let mut rules = Vec::new();
    let mut lans: Vec<_> = links
        .iter()
        .filter(|link| link.role == "lan")
        .map(|link| {
            let mut name = vec![0; 16];
            name[..link.name.len()].copy_from_slice(link.name.as_bytes());
            name
        })
        .collect();
    lans.sort();
    sets.push(set_key("netcontrol", "exp_lan", 16, false, &lans)?);
    sets.extend(key_items("netcontrol", "exp_lan", &lans));
    for ipv6 in [false, true] {
        let suffix = if ipv6 { "6" } else { "4" };
        let mut keys: Vec<_> = hosts
            .iter()
            .filter(|ip| ip.is_ipv6() == ipv6)
            .map(|ip| match ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            })
            .collect();
        keys.sort();
        let eligible = format!("exp_eligible{suffix}");
        sets.push(set_key(
            "netcontrol",
            &eligible,
            if ipv6 { 16 } else { 4 },
            false,
            &keys,
        )?);
        sets.extend(key_items("netcontrol", &eligible, &keys));
        for sent in [true, false] {
            let name = format!(
                "exp_drop_{}{suffix}",
                if sent { "sent" } else { "received" }
            );
            sets.push(set_key(
                "netcontrol",
                &name,
                if ipv6 { 16 } else { 4 },
                true,
                &keys,
            )?);
            rules.push(rule(
                "netcontrol",
                DROP_CHAIN,
                [load_drop(ipv6, sent), update(&name)].concat(),
            ));
        }
    }
    for ipv6 in [false, true] {
        for sent in [true, false] {
            let ret = expr(
                "immediate",
                [n(1, 0), a(0x8002, &a(0x8002, &n(1, (-5i32) as u32)))].concat(),
            );
            rules.push(rule(
                "netcontrol",
                DROP_CHAIN,
                [load_drop(ipv6, sent), ret].concat(),
            ));
        }
    }
    rules.push(rule(
        "netcontrol",
        DROP_CHAIN,
        expr(
            "counter",
            [a(1, &0u64.to_be_bytes()), a(2, &0u64.to_be_bytes())].concat(),
        ),
    ));
    Ok((sets, rules))
}
fn load_drop(ipv6: bool, sent: bool) -> Vec<u8> {
    let offset = match (ipv6, sent) {
        (false, true) => 12,
        (false, false) => 16,
        (true, true) => 8,
        (true, false) => 24,
    };
    [
        expr("meta", [n(1, 4), n(2, 15)].concat()),
        compare(4, &[if ipv6 { 10 } else { 2 }]),
        expr("meta", [n(1, 1), n(2, if sent { 6 } else { 7 })].concat()),
        expr("lookup", [string(1, "exp_lan"), n(2, 1)].concat()),
        expr(
            "payload",
            [
                n(1, 1),
                n(2, 1),
                n(3, offset),
                n(4, if ipv6 { 16 } else { 4 }),
            ]
            .concat(),
        ),
        expr(
            "lookup",
            [
                string(
                    1,
                    if ipv6 {
                        "exp_eligible6"
                    } else {
                        "exp_eligible4"
                    },
                ),
                n(2, 1),
            ]
            .concat(),
        ),
    ]
    .concat()
}

#[derive(Clone, Debug, Default)]
pub(super) struct Count {
    pub packets: u64,
    pub bytes: u64,
    pub last_ms: Option<u64>,
}
pub(super) fn counts(table: &str, name: &str) -> Result<BTreeMap<IpAddr, Count>> {
    let mut result = BTreeMap::new();
    for elem in elements(table, name)? {
        let attrs = attributes(&elem)?;
        let get = |kind| {
            attrs
                .iter()
                .find(|(k, _)| k & 0x3fff == kind)
                .map(|(_, v)| v.as_slice())
        };
        let data = attributes(get(1).context("counter key missing")?)?;
        let key = &data
            .iter()
            .find(|(k, _)| k & 0x3fff == 1)
            .context("counter key value missing")?
            .1;
        let ip = match key.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(key.as_slice())?),
            16 => IpAddr::from(<[u8; 16]>::try_from(key.as_slice())?),
            20 => IpAddr::from(<[u8; 4]>::try_from(&key[16..])?),
            32 => IpAddr::from(<[u8; 16]>::try_from(&key[16..])?),
            _ => anyhow::bail!("invalid experience key"),
        };
        let mut count = Count::default();
        let expressions = get(11).context("counter/last expressions missing")?;
        for (_, expression) in attributes(expressions)? {
            let fields = attributes(&expression)?;
            let name = c_string(
                &fields
                    .iter()
                    .find(|(k, _)| k & 0x3fff == 1)
                    .context("expression name")?
                    .1,
            )?;
            let fields = attributes(
                &fields
                    .iter()
                    .find(|(k, _)| k & 0x3fff == 2)
                    .context("expression data")?
                    .1,
            )?;
            let data = |kind| {
                fields
                    .iter()
                    .find(|(k, _)| k & 0x3fff == kind)
                    .map(|(_, v)| v.as_slice())
            };
            if name == "counter" {
                count.bytes = u64::from_be_bytes(data(1).context("counter bytes")?.try_into()?);
                count.packets = u64::from_be_bytes(data(2).context("counter packets")?.try_into()?);
            } else if name == "last" && data(1).is_some_and(|v| v == 1u32.to_be_bytes()) {
                count.last_ms = Some(u64::from_be_bytes(
                    data(2).context("last milliseconds")?.try_into()?,
                ));
            }
        }
        ensure!(
            result.insert(ip, count).is_none(),
            "duplicate experience address attribution"
        );
    }
    Ok(result)
}
pub(super) fn unattributed() -> Result<u64> {
    let payloads = super::netfilter::dump_messages(
        10,
        7,
        1,
        &[string(1, "netcontrol"), string(2, DROP_CHAIN)].concat(),
    )?;
    for payload in payloads {
        let attrs = attributes(&payload[4..])?;
        let expressions = &attrs
            .iter()
            .find(|(k, _)| k & 0x3fff == 4)
            .context("drop expressions missing")?
            .1;
        for (_, expression) in attributes(expressions)? {
            let attrs = attributes(&expression)?;
            if attrs
                .iter()
                .any(|(k, v)| k & 0x3fff == 1 && v == b"counter\0")
            {
                let data = &attrs
                    .iter()
                    .find(|(k, _)| k & 0x3fff == 2)
                    .context("drop counter missing")?
                    .1;
                let attrs = attributes(data)?;
                return Ok(u64::from_be_bytes(
                    attrs
                        .iter()
                        .find(|(k, _)| k & 0x3fff == 2)
                        .context("drop packets missing")?
                        .1
                        .as_slice()
                        .try_into()?,
                ));
            }
        }
    }
    anyhow::bail!("unattributed managed drop counter missing")
}
pub(super) fn remove(fingerprint: &str) -> Result<()> {
    ensure!(
        super::netfilter::experience_fingerprint()? == fingerprint,
        "experience table drift; refusing to remove foreign changes"
    );
    super::nft_wire::send(&[(2, 5, string(1, TABLE))])
}
pub(super) fn install(hosts: &BTreeMap<IpAddr, String>) -> Result<()> {
    let current = super::netfilter::dump_messages(10, 1, 1, &[])?;
    let exists = current.iter().any(|p| {
        attributes(&p[4..]).is_ok_and(|attrs| {
            attrs
                .iter()
                .any(|(k, v)| k & 0x3fff == 1 && v == format!("{TABLE}\0").as_bytes())
        })
    });
    if exists {
        for p in &current {
            let attrs = attributes(&p[4..])?;
            if attrs
                .iter()
                .any(|(k, v)| k & 0x3fff == 1 && v == format!("{TABLE}\0").as_bytes())
            {
                ensure!(
                    attrs.iter().any(|(k, v)| k & 0x3fff == 6 && v == OWNER),
                    "foreign experience table"
                );
            }
        }
    }
    let table_attrs = [string(1, TABLE), a(6, OWNER)].concat();
    let mut items = vec![
        (0, 0x405, table_attrs.clone()),
        (2, 5, table_attrs.clone()),
        (0, 0x605, table_attrs),
    ];
    let (sets, rules) = layout(TABLE, hosts)?;
    items.extend(sets);
    for (name, hook, priority) in [
        ("ingress", 0, -300i32),
        ("egress", 4, 300i32),
        ("forward_capture", 2, 300i32),
        ("input_capture", 1, 300i32),
    ] {
        items.push((
            3,
            0x605,
            [
                string(1, TABLE),
                string(3, name),
                string(7, "filter"),
                a(0x8004, &[n(1, hook), n(2, priority as u32)].concat()),
                n(5, 1),
                a(12, OWNER),
            ]
            .concat(),
        ));
    }
    items.extend(rules);
    for ipv6 in [false, true] {
        for sent in [true, false] {
            for (protocol, port) in [
                (6, Some(DnsPort::Source)),
                (6, Some(DnsPort::Destination)),
                (17, Some(DnsPort::Source)),
                (17, Some(DnsPort::Destination)),
                (6, Some(DnsPort::OriginalDestination)),
                (17, Some(DnsPort::OriginalDestination)),
                (6, None),
            ] {
                if sent {
                    for chain in ["forward_capture", "input_capture"] {
                        items.push(rule(
                            TABLE,
                            chain,
                            transport_capture(ipv6, sent, protocol, port),
                        ));
                    }
                } else {
                    items.push(rule(
                        TABLE,
                        "egress",
                        transport_capture(ipv6, sent, protocol, port),
                    ));
                }
            }
        }
    }
    super::nft_wire::send(&items).context("install protected-host counters and passive capture")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN and CAP_NET_ADMIN"]
    fn kernel_counters_capture_and_activity() -> Result<()> {
        std::thread::spawn(|| -> Result<()> {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                "create disposable network namespace: {}",
                std::io::Error::last_os_error()
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let (connection, handle, _) = rtnetlink::new_connection()?;
                let task = tokio::spawn(connection);
                handle
                    .link()
                    .set(rtnetlink::LinkUnspec::new_with_index(1).up().build())
                    .execute()
                    .await?;
                task.abort();
                Ok::<_, anyhow::Error>(())
            })?;
            let hosts = BTreeMap::from([("127.0.0.1".parse()?, "lo".to_owned())]);
            let capture = super::super::deny_log::socket_for(GROUP, 4608, 4 << 20, 5, 32)?;
            install(&hosts)?;
            let fingerprint = super::super::netfilter::experience_fingerprint()?;
            let server = std::net::UdpSocket::bind("127.0.0.1:53")?;
            let client = std::net::UdpSocket::bind("127.0.0.1:0")?;
            client.send_to(b"hello", server.local_addr()?)?;
            let mut buf = [0; 32];
            server.recv_from(&mut buf)?;
            ensure!(
                fingerprint == super::super::netfilter::experience_fingerprint()?,
                "mutable accounting changed policy fingerprint"
            );
            for name in ["exp_sent4", "exp_received4"] {
                let values = counts(TABLE, name)?;
                let count = values
                    .get(&"127.0.0.1".parse()?)
                    .context("host counter absent")?;
                ensure!(
                    count.packets == 1 && count.bytes == 33 && count.last_ms.is_some(),
                    "invalid host-perspective counters: {count:?}"
                );
            }
            let mut buffer = [0; 65536];
            ensure!(
                super::super::deny_log::poll(&capture, 1000)?,
                "passive capture absent"
            );
            let received = super::super::deny_log::receive(&capture, &mut buffer)?;
            let mut packets = 0;
            super::super::deny_log::frames(&buffer[..received], |kind, _, _| {
                if kind == 0x400 {
                    packets += 1;
                }
                Ok(())
            })?;
            ensure!(packets > 0, "passive NFLOG packet absent");
            install(&hosts)?;
            ensure!(
                counts(TABLE, "exp_sent4")?.is_empty(),
                "reset must not retain old counters"
            );
            let mut hosts = BTreeMap::from([("::1".parse()?, "lo".to_owned())]);
            for index in 1..2048u128 {
                hosts.insert(
                    IpAddr::V6(std::net::Ipv6Addr::from((0x20010db8u128 << 96) | index)),
                    "lo".to_owned(),
                );
            }
            install(&hosts)?;
            let fingerprint = super::super::netfilter::experience_fingerprint()?;
            let server = std::net::UdpSocket::bind("[::1]:53")?;
            let client = std::net::UdpSocket::bind("[::1]:0")?;
            let payload = vec![0; 4096];
            client.send_to(&payload, server.local_addr()?)?;
            let mut received = vec![0; 4096];
            ensure!(
                server.recv_from(&mut received)?.0 == 4096,
                "IPv6 UDP payload truncated"
            );
            for name in ["exp_sent6", "exp_received6"] {
                let values = counts(TABLE, name)?;
                let count = values
                    .get(&"::1".parse()?)
                    .context("IPv6 host counter absent")?;
                ensure!(
                    count.packets == 1 && count.bytes == 4144 && count.last_ms.is_some(),
                    "invalid IPv6 counters: {count:?}"
                );
            }
            ensure!(
                fingerprint == super::super::netfilter::experience_fingerprint()?,
                "IPv6 accounting changed policy fingerprint"
            );
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut full = false;
            while !full && std::time::Instant::now() < deadline {
                if !super::super::deny_log::poll(&capture, 100)? {
                    continue;
                }
                let length = super::super::deny_log::receive(&capture, &mut buffer)?;
                super::super::deny_log::frames(&buffer[..length], |kind, _, packet| {
                    if kind == 0x400 && packet[0] == libc::AF_INET6 as u8 {
                        for (kind, value) in attributes(&packet[4..])? {
                            if kind & 0x3fff == 9 && value.len() == 4144 && value[48..] == payload {
                                full = true;
                            }
                        }
                    }
                    Ok(())
                })?;
            }
            ensure!(full, "full 4096-byte IPv6 DNS capture absent");
            remove(&fingerprint)?;
            Ok(())
        })
        .join()
        .map_err(|_| anyhow::anyhow!("kernel test panicked"))?
    }
}
