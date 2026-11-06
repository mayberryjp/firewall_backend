use super::takeover::Plan;
use crate::netlink_decode::{attributes, c_string};
use anyhow::{Context, Result, bail, ensure};
use netcontrol_core::Config;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn field(attrs: &[(u16, Vec<u8>)], key: u16) -> Result<&[u8]> {
    attrs
        .iter()
        .find(|(kind, _)| kind & 0x3fff == key)
        .map(|(_, value)| value.as_slice())
        .context("missing nftables attribute")
}
fn number(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes.try_into().context("invalid nftables integer")?,
    ))
}
fn keys(attrs: &[(u16, Vec<u8>)], allowed: &[u16]) -> Result<()> {
    ensure!(
        attrs
            .iter()
            .all(|(key, _)| allowed.contains(&(key & 0x3fff))),
        "unsupported nftables expression attributes"
    );
    let distinct: std::collections::BTreeSet<_> =
        attrs.iter().map(|(key, _)| key & 0x3fff).collect();
    ensure!(
        distinct.len() == attrs.len(),
        "duplicate nftables expression attribute"
    );
    Ok(())
}
fn interface_name(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() <= 16, "invalid interface comparison length");
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated interface comparison")?;
    ensure!(
        bytes[end..].iter().all(|byte| *byte == 0),
        "nonzero interface comparison padding"
    );
    let name = std::str::from_utf8(&bytes[..end])?;
    ensure!(
        netcontrol_core::valid_interface_name(name),
        "invalid interface comparison"
    );
    Ok(name.into())
}

#[derive(Default)]
struct Match {
    source: String,
    destination: String,
    ingress: String,
    egress: String,
    protocol: String,
    ports: Vec<u16>,
    action: String,
}

#[derive(Clone)]
struct Load {
    field: &'static str,
    mask: Option<Vec<u8>>,
}

fn decode(payload: &[u8]) -> Result<Match> {
    ensure!(payload.len() >= 4, "short nftables rule");
    let attrs = attributes(&payload[4..])?;
    let mut result = Match::default();
    let mut registers = BTreeMap::<u32, Load>::new();
    for (kind, expression) in attributes(field(&attrs, 4)?)? {
        ensure!(kind & 0x3fff == 1, "invalid expression list");
        let fields = attributes(&expression)?;
        let name = c_string(field(&fields, 1)?)?;
        let data = attributes(field(&fields, 2)?)?;
        ensure!(result.action.is_empty(), "expression after verdict");
        match name {
            "counter" => {
                keys(&data, &[1, 2])?;
            }
            "meta" => {
                keys(&data, &[1, 2])?;
                let key = number(field(&data, 2)?)?;
                let name = match key {
                    6 => "ingress",
                    7 => "egress",
                    15 => "family",
                    16 => "protocol",
                    _ => bail!("unsupported meta key {key}"),
                };
                registers.insert(
                    number(field(&data, 1)?)?,
                    Load {
                        field: name,
                        mask: None,
                    },
                );
            }
            "payload" => {
                keys(&data, &[1, 2, 3, 4])?;
                let base = number(field(&data, 2)?)?;
                let offset = number(field(&data, 3)?)?;
                let len = number(field(&data, 4)?)?;
                let name = match (base, offset, len) {
                    (1, 12, 4) => "source",
                    (1, 16, 4) => "destination",
                    (1, 9, 1) => "protocol",
                    (2, 2, 2) => "port",
                    _ => bail!("unsupported payload match"),
                };
                registers.insert(
                    number(field(&data, 1)?)?,
                    Load {
                        field: name,
                        mask: None,
                    },
                );
            }
            "bitwise" => {
                keys(&data, &[1, 2, 3, 4, 5, 6])?;
                ensure!(number(field(&data, 3)?)? == 4, "unsupported bitwise length");
                if let Some((_, operation)) = data.iter().find(|(key, _)| key & 0x3fff == 6) {
                    ensure!(number(operation)? == 0, "unsupported bitwise operation");
                }
                let source = number(field(&data, 1)?)?;
                let mut loaded = registers
                    .get(&source)
                    .cloned()
                    .context("bitwise register missing")?;
                ensure!(
                    matches!(loaded.field, "source" | "destination") && loaded.mask.is_none(),
                    "unsupported bitwise expression"
                );
                let mask = attributes(field(&data, 4)?)?;
                let xor = attributes(field(&data, 5)?)?;
                keys(&mask, &[1])?;
                keys(&xor, &[1])?;
                ensure!(
                    field(&mask, 1)?.len() == 4 && field(&xor, 1)?.len() == 4,
                    "invalid IPv4 bitwise operands"
                );
                ensure!(
                    field(&xor, 1)?.iter().all(|v| *v == 0),
                    "unsupported bitwise XOR"
                );
                loaded.mask = Some(field(&mask, 1)?.to_vec());
                registers.insert(number(field(&data, 2)?)?, loaded);
            }
            "cmp" => {
                keys(&data, &[1, 2, 3])?;
                ensure!(
                    number(field(&data, 2)?)? == 0,
                    "only exact equality matches are representable"
                );
                let loaded = registers
                    .remove(&number(field(&data, 1)?)?)
                    .context("comparison register missing")?;
                let value = attributes(field(&data, 3)?)?;
                keys(&value, &[1])?;
                let bytes = field(&value, 1)?;
                match loaded.field {
                    "family" => ensure!(
                        bytes == [libc::NFPROTO_IPV4 as u8],
                        "IPv6 or unsupported family match"
                    ),
                    "ingress" | "egress" => {
                        let name = interface_name(bytes)?;
                        let target = if loaded.field == "ingress" {
                            &mut result.ingress
                        } else {
                            &mut result.egress
                        };
                        ensure!(target.is_empty(), "duplicate interface predicate");
                        *target = name;
                    }
                    "source" | "destination" => {
                        let octets: [u8; 4] = bytes.try_into().context("IPv4 address size")?;
                        let mask = loaded
                            .mask
                            .map(|m| -> Result<u32> {
                                Ok(u32::from_be_bytes(m.as_slice().try_into()?))
                            })
                            .transpose()?
                            .unwrap_or(u32::MAX);
                        let prefix = mask.leading_ones();
                        ensure!(
                            mask == u32::MAX.checked_shl(32 - prefix).unwrap_or(0),
                            "non-prefix IPv4 mask"
                        );
                        ensure!(
                            u32::from_be_bytes(octets) & !mask == 0,
                            "noncanonical prefix match"
                        );
                        let target = if loaded.field == "source" {
                            &mut result.source
                        } else {
                            &mut result.destination
                        };
                        ensure!(target.is_empty(), "duplicate address predicate");
                        *target = format!("{}/{prefix}", std::net::Ipv4Addr::from(octets));
                    }
                    "protocol" => {
                        ensure!(result.protocol.is_empty(), "duplicate protocol predicate");
                        result.protocol = match bytes {
                            [6] => "tcp",
                            [17] => "udp",
                            [1] => "icmp",
                            _ => bail!("unsupported protocol"),
                        }
                        .into();
                    }
                    "port" => {
                        ensure!(
                            result.ports.is_empty(),
                            "multiple port comparisons cannot be combined"
                        );
                        result
                            .ports
                            .push(u16::from_be_bytes(bytes.try_into().context("port size")?));
                    }
                    _ => bail!("unsupported comparison"),
                }
            }
            "immediate" => {
                keys(&data, &[1, 2])?;
                ensure!(
                    number(field(&data, 1)?)? == 0,
                    "unsupported immediate register"
                );
                let value = attributes(field(&data, 2)?)?;
                keys(&value, &[2])?;
                let verdict = attributes(field(&value, 2)?)?;
                keys(&verdict, &[1])?;
                result.action = match number(field(&verdict, 1)?)? {
                    0 => "drop",
                    1 => "accept",
                    _ => bail!("jump/return/other verdict is unsupported"),
                }
                .into();
            }
            "masq" => {
                ensure!(data.is_empty(), "masquerade options are unsupported");
                result.action = "masquerade".into();
            }
            _ => bail!("unsupported nftables expression {name}"),
        }
    }
    ensure!(
        registers.is_empty() && !result.action.is_empty(),
        "incomplete nftables predicate or verdict"
    );
    if !result.ports.is_empty() {
        ensure!(
            matches!(result.protocol.as_str(), "tcp" | "udp"),
            "port match requires TCP/UDP"
        );
    }
    Ok(result)
}

struct Chain {
    family: u8,
    table: String,
    name: String,
    hook: Option<u32>,
    policy: String,
}

pub(super) fn import(snapshot: &[Vec<u8>], config: &mut Config, plan: &mut Plan) -> Result<()> {
    let mut chains = Vec::new();
    for record in snapshot {
        ensure!(record.len() >= 6, "short firewall snapshot");
        let kind = u16::from_ne_bytes(record[..2].try_into()?);
        let attrs = attributes(&record[6..])?;
        match kind {
            1 => plan.item(
                format!(
                    "firewall-table:{}:{}",
                    record[2],
                    c_string(field(&attrs, 1)?)?
                ),
                "disabled",
                "foreign table removed after representable policy import",
            ),
            4 => {
                let hook = attrs
                    .iter()
                    .find(|(key, _)| key & 0x3fff == 4)
                    .map(|(_, v)| -> Result<u32> { number(field(&attributes(v)?, 1)?) })
                    .transpose()?;
                let policy = attrs
                    .iter()
                    .find(|(key, _)| key & 0x3fff == 5)
                    .map(|(_, v)| number(v))
                    .transpose()?
                    .unwrap_or(1);
                chains.push(Chain {
                    family: record[2],
                    table: c_string(field(&attrs, 1)?)?.into(),
                    name: c_string(field(&attrs, 3)?)?.into(),
                    hook,
                    policy: match policy {
                        0 => "drop",
                        1 => "accept",
                        _ => bail!("invalid chain policy"),
                    }
                    .into(),
                });
            }
            _ => {}
        }
    }
    let representable = |chain: &Chain| {
        [libc::NFPROTO_INET as u8, libc::NFPROTO_IPV4 as u8].contains(&chain.family)
            && chain.hook.is_some_and(|hook| {
                matches!(hook, 1 | 2 | 4)
                    && chains
                        .iter()
                        .filter(|c| {
                            [libc::NFPROTO_INET as u8, libc::NFPROTO_IPV4 as u8].contains(&c.family)
                                && c.hook == Some(hook)
                        })
                        .count()
                        == 1
            })
    };
    if !chains.is_empty() {
        config.firewall.allow_all_icmp = false;
    }
    for chain in &chains {
        let resource = format!(
            "firewall-chain:{}:{}:{}",
            chain.family, chain.table, chain.name
        );
        if !representable(chain) {
            plan.item(resource,"disabled","unsupported hook, IPv6, jump chain or multiple base chains cannot be represented without changing traversal");
            continue;
        }
        if chain.hook == Some(4) && chain.policy != "accept" {
            plan.item(resource,"disabled","postrouting drop policy is unsupported; representable masquerade rules are considered separately");
            continue;
        }
        match chain.hook {
            Some(2) => config.firewall.policy = chain.policy.clone(),
            Some(1) => {
                config.firewall.input = Some(netcontrol_core::InputFirewall {
                    policy: chain.policy.clone(),
                    interfaces: config
                        .interfaces
                        .iter()
                        .map(|link| netcontrol_core::InterfacePolicy {
                            metadata: Default::default(),
                            interface: link.name.clone(),
                            rules: vec![],
                        })
                        .collect(),
                })
            }
            _ => {}
        }
        plan.item(resource, "imported", "representable base chain policy");
    }
    for record in snapshot {
        if u16::from_ne_bytes(record[..2].try_into()?) != 7 {
            continue;
        }
        let payload = &record[2..];
        let attrs = attributes(&payload[4..])?;
        let table = c_string(field(&attrs, 1)?)?;
        let name = c_string(field(&attrs, 2)?)?;
        let resource = format!(
            "firewall-rule:{}:{table}:{name}:{}",
            payload[0],
            hex::encode(Sha256::digest(payload))
        );
        let chain = chains
            .iter()
            .find(|c| c.family == payload[0] && c.table == table && c.name == name)
            .context("nftables rule chain missing")?;
        let parsed = (|| -> Result<Config> {
            ensure!(representable(chain), "rule traversal cannot be represented");
            let rule = decode(payload)?;
            let mut candidate = config.clone();
            let base = json!({"origin":"inherited","action":rule.action,"destination":rule.destination,"protocol":rule.protocol,"destination_ports":rule.ports});
            match chain.hook {
                Some(2) => {
                    ensure!(
                        rule.ingress.is_empty()
                            && rule.egress.is_empty()
                            && rule.action != "masquerade",
                        "forward interface match or action not representable"
                    );
                    let mut value = base;
                    value["source"] = json!(rule.source);
                    candidate
                        .firewall
                        .rules
                        .push(serde_json::from_value(value)?);
                }
                Some(1) => {
                    ensure!(
                        rule.source.is_empty()
                            && rule.egress.is_empty()
                            && rule.action != "masquerade",
                        "input source/egress/action not representable"
                    );
                    let input = candidate
                        .firewall
                        .input
                        .as_mut()
                        .context("input policy missing")?;
                    ensure!(
                        rule.ingress.is_empty()
                            || input.interfaces.iter().any(|i| i.interface == rule.ingress),
                        "unmanaged input interface"
                    );
                    for iface in &mut input.interfaces {
                        if rule.ingress.is_empty() || rule.ingress == iface.interface {
                            iface.rules.push(serde_json::from_value(base.clone())?);
                        }
                    }
                }
                Some(4) => {
                    ensure!(
                        rule.action == "masquerade"
                            && rule.ingress.is_empty()
                            && rule.destination.is_empty()
                            && rule.protocol.is_empty()
                            && rule.ports.is_empty(),
                        "only plain IPv4 source/egress masquerade is representable"
                    );
                    candidate.firewall.nat.masquerade.push(serde_json::from_value(json!({"origin":"inherited","family":"ipv4","source":rule.source,"out_interface":rule.egress}))?);
                }
                _ => bail!("unsupported hook"),
            }
            candidate.validate()?;
            Ok(candidate)
        })();
        match parsed {
            Ok(candidate) => {
                *config = candidate;
                plan.item(resource, "imported", "owned supported rule");
            }
            Err(error) => plan.item(resource, "disabled", format!("{error:#}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_firewall_capture_fails_explicitly() {
        let mut config = Config::empty();
        let mut plan:Plan=serde_json::from_value(json!({"phase":"captured","error":"","items":[],"units":[],"route_snapshot":[],"rule_snapshot":[],"qdisc_snapshot":[],"firewall_snapshot":[],"legacy_snapshot":[]})).unwrap();
        assert!(import(&[vec![1, 0]], &mut config, &mut plan).is_err());
        assert!(decode(&[]).is_err());
        let attribute = |kind: u16, value: &[u8]| {
            let mut data = ((value.len() + 4) as u16).to_ne_bytes().to_vec();
            data.extend(kind.to_ne_bytes());
            data.extend(value);
            data.resize(data.len().next_multiple_of(4), 0);
            data
        };
        let mut record = 4u16.to_ne_bytes().to_vec();
        record.extend([libc::NFPROTO_IPV4 as u8, 0, 0, 0]);
        record.extend(attribute(1, b"nat\0"));
        record.extend(attribute(3, b"post\0"));
        record.extend(attribute(4, &attribute(1, &4u32.to_be_bytes())));
        record.extend(attribute(5, &0u32.to_be_bytes()));
        import(&[record], &mut config, &mut plan).unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].disposition, "disabled");
        assert!(plan.items[0].reason.contains("postrouting drop policy"));
    }
}
