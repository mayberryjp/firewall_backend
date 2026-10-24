use crate::model::{EthernetSnapshot, Network, PROTOCOL, Route, Rule, ethernet_kind, parse_prefix};
use anyhow::{Context, Result, bail, ensure};
use futures_util::TryStreamExt;
use netlink_packet_route::{
    AddressFamily,
    address::{
        AddressAttribute, AddressFlag, AddressHeaderFlag, AddressMessage, AddressMessageBuffer,
        AddressScope,
    },
    link::{InfoData, InfoVlan, LinkAttribute, LinkFlag, LinkInfo, LinkMessage, VlanProtocol},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use netlink_packet_utils::{Emitable, Parseable};
use rtnetlink::{Handle, IpVersion};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_route_scope_matches_linux_address_family_semantics() -> Result<()> {
        let names = BTreeMap::from([(7, "test0".to_string())]);
        for (family, destination, gateway, scope) in [
            (AddressFamily::Inet, "203.0.113.0", None, RouteScope::Link),
            (
                AddressFamily::Inet,
                "203.0.113.0",
                Some("192.0.2.1"),
                RouteScope::Universe,
            ),
            (
                AddressFamily::Inet6,
                "2001:db8:300::",
                None,
                RouteScope::Universe,
            ),
            (
                AddressFamily::Inet6,
                "2001:db8:300::",
                Some("2001:db8::1"),
                RouteScope::Universe,
            ),
        ] {
            let mut message = RouteMessage::default();
            message.header.address_family = family;
            message.header.kind = RouteType::Unicast;
            message.header.scope = scope;
            message.header.table = 254;
            message.header.destination_prefix_length = if family == AddressFamily::Inet {
                24
            } else {
                64
            };
            let address = |value: &str| -> Result<RouteAddress> {
                Ok(match value.parse::<IpAddr>()? {
                    IpAddr::V4(ip) => RouteAddress::Inet(ip),
                    IpAddr::V6(ip) => RouteAddress::Inet6(ip),
                })
            };
            message.attributes = vec![
                RouteAttribute::Destination(address(destination)?),
                RouteAttribute::Oif(7),
            ];
            if let Some(gateway) = gateway {
                message
                    .attributes
                    .push(RouteAttribute::Gateway(address(gateway)?));
            }
            let decoded = decode_route(&message, &names)?;
            assert_eq!(decoded.interface, "test0");
            assert_eq!(decoded.gateway, gateway.unwrap_or_default());
            message.header.scope = RouteScope::Host;
            assert!(decode_route(&message, &names).is_err());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Parent {
    pub name: String,
    pub kind: String,
    pub index: u32,
    pub mac: String,
    pub mtu: u32,
    pub up: bool,
}

pub(super) async fn links(handle: &Handle) -> Result<Vec<LinkMessage>> {
    Ok(handle.link().get().execute().try_collect().await?)
}
pub(super) fn name(link: &LinkMessage) -> String {
    link.attributes
        .iter()
        .find_map(|a| {
            if let LinkAttribute::IfName(v) = a {
                Some(v.clone())
            } else {
                None
            }
        })
        .unwrap_or_default()
}
fn kind(link: &LinkMessage) -> String {
    for a in &link.attributes {
        if let LinkAttribute::LinkInfo(info) = a {
            for v in info {
                if let LinkInfo::Kind(kind) = v {
                    return kind.to_string();
                }
            }
        }
    }
    if name(link) == "lo" {
        "loopback".into()
    } else {
        "device".into()
    }
}
fn mtu(link: &LinkMessage) -> u32 {
    link.attributes
        .iter()
        .find_map(|a| {
            if let LinkAttribute::Mtu(v) = a {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap_or_default()
}
pub(super) fn parent(link: &LinkMessage) -> Parent {
    let mac = link
        .attributes
        .iter()
        .find_map(|a| {
            if let LinkAttribute::Address(v) = a {
                Some(
                    v.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                )
            } else {
                None
            }
        })
        .unwrap_or_default();
    Parent {
        name: name(link),
        kind: kind(link),
        index: link.header.index,
        mac,
        mtu: mtu(link),
        up: link.header.flags.contains(&LinkFlag::Up),
    }
}

fn matches_kind(actual: &LinkMessage, wanted: &str) -> bool {
    let actual = kind(actual);
    actual == wanted || (wanted == "ethernet" && ethernet_kind(&actual))
}

pub async fn discover(handle: &Handle, managed: &BTreeSet<String>) -> Result<Value> {
    let mut inventory = Vec::new();
    for link in links(handle).await? {
        let p = parent(&link);
        let mut prefixes = Vec::new();
        for address in addresses(handle, p.index).await? {
            let ip = address
                .attributes
                .iter()
                .find_map(|a| match a {
                    AddressAttribute::Local(ip) => Some(*ip),
                    _ => None,
                })
                .or_else(|| {
                    address.attributes.iter().find_map(|a| match a {
                        AddressAttribute::Address(ip) => Some(*ip),
                        _ => None,
                    })
                });
            if let Some(ip) = ip {
                prefixes.push(format!("{ip}/{}", address.header.prefix_len));
            }
        }
        prefixes.sort();
        prefixes.dedup();
        let ownership = if p.kind == "loopback" {
            "loopback"
        } else if managed.contains(&p.name) {
            "managed"
        } else {
            "unmanaged"
        };
        inventory.push(json!({
            "name":p.name,"kind":if ethernet_kind(&p.kind) { "ethernet" } else { &p.kind },
            "index":p.index,"mac":p.mac,"mtu":p.mtu,"up":p.up,
            "addresses":prefixes,"ownership":ownership
        }));
    }
    inventory.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!(inventory))
}

pub async fn capture_ethernet(
    handle: &Handle,
    before: &Network,
    after: &Network,
) -> Result<BTreeMap<String, EthernetSnapshot>> {
    let available = links(handle).await?;
    let mut result = BTreeMap::new();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let captured_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for desired in before
        .interfaces
        .iter()
        .chain(&after.interfaces)
        .filter(|l| l.kind == "ethernet")
    {
        let link = available
            .iter()
            .find(|l| name(l) == desired.name)
            .with_context(|| format!("Ethernet interface {} must already exist", desired.name))?;
        let p = parent(link);
        ensure!(
            ethernet_kind(&p.kind) && p.mac.len() == 17,
            "{} is not a physical Ethernet device or veth",
            desired.name
        );
        let messages = addresses(handle, p.index).await?;
        let addresses = messages
            .iter()
            .filter(|a| a.header.scope != AddressScope::Link)
            .map(|a| {
                let mut raw = vec![0; a.buffer_len()];
                a.emit(&mut raw);
                raw
            })
            .collect();
        result.insert(
            p.name.clone(),
            EthernetSnapshot {
                name: p.name,
                kind: p.kind,
                index: p.index,
                mac: p.mac,
                mtu: p.mtu,
                up: p.up,
                boot: boot.trim().into(),
                captured_unix,
                addresses,
            },
        );
    }
    Ok(result)
}

pub async fn check_ethernet(
    handle: &Handle,
    snapshots: &BTreeMap<String, EthernetSnapshot>,
) -> Result<()> {
    let available = links(handle).await?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    for snapshot in snapshots.values() {
        let p = available
            .iter()
            .find(|l| name(l) == snapshot.name)
            .map(parent)
            .with_context(|| format!("captured Ethernet interface {} missing", snapshot.name))?;
        crate::ensure_unchanged(
            p.kind == snapshot.kind
                && p.mac == snapshot.mac
                && (boot.trim() != snapshot.boot || p.index == snapshot.index),
            format!(
                "captured Ethernet interface {} changed identity",
                snapshot.name
            ),
        )?;
    }
    Ok(())
}

pub async fn restore_ethernet(
    handle: &Handle,
    snapshots: &BTreeMap<String, EthernetSnapshot>,
) -> Result<()> {
    check_ethernet(handle, snapshots).await?;
    let available = links(handle).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for snapshot in snapshots.values() {
        let index = available
            .iter()
            .find(|l| name(l) == snapshot.name)
            .context("Ethernet disappeared")?
            .header
            .index;
        let mut original = Vec::new();
        for bytes in &snapshot.addresses {
            let mut address = AddressMessage::parse(&AddressMessageBuffer::new_checked(bytes)?)?;
            address.header.index = index;
            let elapsed = now.checked_sub(snapshot.captured_unix);
            let mut expired = false;
            for attribute in &mut address.attributes {
                if let AddressAttribute::CacheInfo(info) = attribute {
                    for lifetime in [&mut info.ifa_preferred, &mut info.ifa_valid] {
                        if *lifetime != u32::MAX {
                            let elapsed = u32::try_from(elapsed.context("clock moved backward; cannot safely restore a finite address lifetime")?).unwrap_or(u32::MAX);
                            *lifetime = lifetime.saturating_sub(elapsed);
                        }
                    }
                    expired = info.ifa_valid == 0;
                    info.cstamp = 0;
                    info.tstamp = 0;
                }
            }
            if !expired {
                original.push(address);
            }
        }
        for address in addresses(handle, index).await? {
            if address.header.scope != AddressScope::Link
                && !original.iter().any(|old| same_address(old, &address))
            {
                handle.address().del(address).execute().await?;
            }
        }
        handle.link().set(index).mtu(snapshot.mtu).execute().await?;
        let request = handle.link().set(index);
        if snapshot.up {
            request.up().execute().await?;
        } else {
            request.down().execute().await?;
        }
        for address in original {
            let ip = address
                .attributes
                .iter()
                .find_map(|a| match a {
                    AddressAttribute::Local(ip) | AddressAttribute::Address(ip) => Some(*ip),
                    _ => None,
                })
                .context("captured address missing IP")?;
            let mut request = handle
                .address()
                .add(index, ip, address.header.prefix_len)
                .replace();
            *request.message_mut() = address;
            request.execute().await?;
        }
    }
    Ok(())
}

fn same_address(a: &AddressMessage, b: &AddressMessage) -> bool {
    a.header.family == b.header.family
        && a.header.prefix_len == b.header.prefix_len
        && a.attributes
            .iter()
            .filter(|a| matches!(a, AddressAttribute::Local(_) | AddressAttribute::Address(_)))
            .eq(b
                .attributes
                .iter()
                .filter(|a| matches!(a, AddressAttribute::Local(_) | AddressAttribute::Address(_))))
}
pub async fn adopt(handle: &Handle, names: &BTreeSet<String>) -> Result<BTreeMap<String, Parent>> {
    let available = links(handle).await?;
    let mut result = BTreeMap::new();
    for wanted in names {
        let link = available
            .iter()
            .find(|l| name(l) == *wanted)
            .with_context(|| format!("adopted parent {wanted} unavailable"))?;
        let p = parent(link);
        ensure!(
            matches!(p.kind.as_str(), "device" | "dummy" | "veth") && p.mac.len() == 17,
            "adopted parent must be a precreated Ethernet device, veth or dummy"
        );
        result.insert(wanted.clone(), p);
    }
    Ok(result)
}
pub async fn check_parents(handle: &Handle, parents: &BTreeMap<String, Parent>) -> Result<()> {
    let available = links(handle).await?;
    for (name, expected) in parents {
        let actual = available
            .iter()
            .find(|l| self::name(l) == *name)
            .map(parent)
            .ok_or_else(|| {
                netcontrol_core::BackendDrift(format!("adopted parent {name} disappeared"))
            })?;
        crate::ensure_unchanged(
            actual.index == expected.index
                && actual.kind == expected.kind
                && actual.mac == expected.mac,
            format!("adopted parent {name} changed identity"),
        )?;
    }
    Ok(())
}
pub async fn parent_status(handle: &Handle, parents: &BTreeMap<String, Parent>) -> Result<Value> {
    let available = links(handle).await?;
    let result: Vec<_> = parents
        .iter()
        .map(|(name, expected)| {
            let actual = available
                .iter()
                .find(|l| self::name(l) == *name)
                .map(parent);
            match actual {
                Some(actual) => {
                    let valid = actual.index == expected.index
                        && actual.kind == expected.kind
                        && actual.mac == expected.mac;
                    let mut value = serde_json::to_value(actual).unwrap_or(Value::Null);
                    value["available"] = json!(valid);
                    value["error"] = json!(if valid {
                        ""
                    } else {
                        "adopted parent identity changed"
                    });
                    value
                }
                None => json!({"name":name,"available":false,"error":"adopted parent disappeared"}),
            }
        })
        .collect();
    Ok(json!(result))
}

fn vlan(link: &LinkMessage) -> Result<Option<(u32, u16)>> {
    if kind(link) != "vlan" {
        return Ok(None);
    }
    let parent = link
        .attributes
        .iter()
        .find_map(|a| {
            if let LinkAttribute::Link(i) = a {
                Some(*i)
            } else {
                None
            }
        })
        .context("VLAN missing parent index")?;
    let mut id = None;
    for a in &link.attributes {
        if let LinkAttribute::LinkInfo(info) = a {
            for info in info {
                if let LinkInfo::Data(InfoData::Vlan(attributes)) = info {
                    for a in attributes {
                        match a {
                            InfoVlan::Id(value) => id = Some(*value),
                            InfoVlan::Protocol(value) => ensure!(
                                *value == VlanProtocol::Ieee8021Q,
                                "unsupported VLAN protocol"
                            ),
                            InfoVlan::Flags((value, _)) => {
                                ensure!(*value & !1 == 0, "unsupported VLAN flags")
                            }
                            InfoVlan::EgressQos(v) | InfoVlan::IngressQos(v) => {
                                ensure!(v.is_empty(), "unsupported VLAN QoS mapping")
                            }
                            _ => bail!("unsupported VLAN identity attribute"),
                        }
                    }
                }
            }
        }
    }
    Ok(Some((parent, id.context("VLAN missing ID")?)))
}

pub(super) async fn addresses(handle: &Handle, index: u32) -> Result<Vec<AddressMessage>> {
    Ok(handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await?)
}
pub(super) fn address_string(address: &AddressMessage) -> Result<Option<String>> {
    if address.header.scope == AddressScope::Link {
        return Ok(None);
    }
    ensure!(
        address.header.scope == AddressScope::Universe,
        "unsupported managed address scope"
    );
    let local = address.attributes.iter().find_map(|a| {
        if let AddressAttribute::Local(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    let peer = address.attributes.iter().find_map(|a| {
        if let AddressAttribute::Address(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    ensure!(
        local.is_none() || peer.is_none() || local == peer,
        "unsupported point-to-point address"
    );
    ensure!(
        !address.header.flags.contains(&AddressHeaderFlag::Tentative)
            && !address.header.flags.contains(&AddressHeaderFlag::Dadfailed),
        "address is tentative or DAD failed"
    );
    let ip = local.or(peer).context("address missing IP")?;
    Ok(Some(format!("{ip}/{}", address.header.prefix_len)))
}

fn route_ip(address: &RouteAddress) -> Result<IpAddr> {
    match address {
        RouteAddress::Inet(v) => Ok((*v).into()),
        RouteAddress::Inet6(v) => Ok((*v).into()),
        _ => bail!("unsupported route address"),
    }
}

pub(super) fn route_key(message: &RouteMessage) -> Result<(u32, u32, String)> {
    let table = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table));
    let metric = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or_default();
    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(address) => Some(route_ip(address)),
            _ => None,
        })
        .transpose()?
        .unwrap_or_else(|| {
            if message.header.address_family == AddressFamily::Inet {
                IpAddr::from([0; 4])
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            }
        });
    Ok((
        table,
        metric,
        format!("{destination}/{}", message.header.destination_prefix_length),
    ))
}

pub async fn check_initial_policy_rules(handle: &Handle) -> Result<()> {
    for version in [IpVersion::V4, IpVersion::V6] {
        let messages: Vec<RuleMessage> = handle.rule().get(version).execute().try_collect().await?;
        for message in messages {
            let priority = message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RuleAttribute::Priority(priority) => Some(*priority),
                    _ => None,
                })
                .unwrap_or_default();
            let table = message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RuleAttribute::Table(table) => Some(*table),
                    _ => None,
                })
                .unwrap_or(u32::from(message.header.table));
            ensure!(
                matches!((priority, table), (0, 255) | (32766, 254) | (32767, 253))
                    && message.header.src_len == 0
                    && message.header.dst_len == 0
                    && message.header.action == RuleAction::ToTable
                    && message.header.tos == 0
                    && message.header.flags.is_empty()
                    && message.attributes.iter().all(|attribute| match attribute {
                        RuleAttribute::Priority(_)
                        | RuleAttribute::Table(_)
                        | RuleAttribute::Protocol(_) => true,
                        RuleAttribute::SuppressPrefixLen(value)
                        | RuleAttribute::SuppressIfGroup(value) => *value == u32::MAX,
                        _ => false,
                    }),
                "automatic inheritance cannot preserve custom policy routing; host configuration was not changed; rejected rule: {message:?}"
            );
        }
    }
    Ok(())
}
async fn owned_routes(handle: &Handle) -> Result<Vec<RouteMessage>> {
    let mut owned = Vec::new();
    for version in [IpVersion::V4, IpVersion::V6] {
        let messages: Vec<RouteMessage> =
            handle.route().get(version).execute().try_collect().await?;
        for message in messages {
            let table = message
                .attributes
                .iter()
                .find_map(|a| {
                    if let RouteAttribute::Table(v) = a {
                        Some(*v)
                    } else {
                        None
                    }
                })
                .unwrap_or(message.header.table as u32);
            if (table == 254 || (10000..=19999).contains(&table))
                && message.header.protocol == RouteProtocol::Other(PROTOCOL)
            {
                owned.push(message);
            }
        }
    }
    Ok(owned)
}
pub(super) fn decode_route(message: &RouteMessage, names: &BTreeMap<u32, String>) -> Result<Route> {
    ensure!(
        message.header.kind == RouteType::Unicast
            && message.header.source_prefix_length == 0
            && message.header.tos == 0
            && message.header.flags.is_empty(),
        "unsupported owned route header"
    );
    let default = match message.header.address_family {
        AddressFamily::Inet => IpAddr::from([0u8; 4]),
        AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        _ => bail!("unsupported route family"),
    };
    let mut destination = default;
    let mut gateway = String::new();
    let mut interface = None;
    let mut table = message.header.table as u32;
    let mut metric = 0;
    for a in &message.attributes {
        match a {
            RouteAttribute::Destination(v) => destination = route_ip(v)?,
            RouteAttribute::Gateway(v) => gateway = route_ip(v)?.to_string(),
            RouteAttribute::Oif(v) => interface = names.get(v).cloned(),
            RouteAttribute::Table(v) => table = *v,
            RouteAttribute::Priority(v) => metric = *v,
            RouteAttribute::CacheInfo(_) | RouteAttribute::Preference(_) => {}
            _ => bail!("unsupported owned route attribute"),
        }
    }
    let scope = if destination.is_ipv4() && gateway.is_empty() {
        RouteScope::Link
    } else {
        RouteScope::Universe
    };
    ensure!(message.header.scope == scope, "owned route scope changed");
    Ok(Route {
        destination: format!("{destination}/{}", message.header.destination_prefix_length),
        gateway,
        interface: interface.context("owned route interface missing")?,
        table,
        metric,
    })
}

pub async fn preflight(handle: &Handle, before: &Network, after: &Network) -> Result<()> {
    let available = links(handle).await?;
    for desired in &after.interfaces {
        let existing = available.iter().find(|l| name(l) == desired.name);
        let previous = before.interfaces.iter().find(|l| l.name == desired.name);
        if desired.kind == "ethernet" {
            let existing = existing
                .with_context(|| format!("Ethernet {} must already exist", desired.name))?;
            ensure!(
                ethernet_kind(&kind(existing)),
                "{} is not Ethernet/veth",
                desired.name
            );
            ensure!(
                previous.is_none_or(|p| p.kind == "ethernet"),
                "cannot adopt an owned virtual interface as Ethernet"
            );
        } else {
            ensure!(
                previous.is_none_or(|p| p.kind != "ethernet"),
                "cannot replace Ethernet with a virtual interface"
            );
            ensure!(
                existing.is_none() || previous.is_some(),
                "interface {} already exists without managed ownership",
                desired.name
            );
        }
    }
    for version in [IpVersion::V4, IpVersion::V6] {
        let messages: Vec<RouteMessage> =
            handle.route().get(version).execute().try_collect().await?;
        for message in messages {
            if message.header.protocol == RouteProtocol::Other(PROTOCOL) {
                continue;
            }
            let table = message
                .attributes
                .iter()
                .find_map(|a| match a {
                    RouteAttribute::Table(table) => Some(*table),
                    _ => None,
                })
                .unwrap_or(message.header.table as u32);
            let metric = message
                .attributes
                .iter()
                .find_map(|a| match a {
                    RouteAttribute::Priority(metric) => Some(*metric),
                    _ => None,
                })
                .unwrap_or_default();
            let destination = message
                .attributes
                .iter()
                .find_map(|a| match a {
                    RouteAttribute::Destination(ip) => Some(route_ip(ip)),
                    _ => None,
                })
                .transpose()?
                .unwrap_or_else(|| {
                    if message.header.address_family == AddressFamily::Inet {
                        IpAddr::from([0; 4])
                    } else {
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                    }
                });
            let prefix = format!("{destination}/{}", message.header.destination_prefix_length);
            ensure!(
                !after
                    .routes
                    .iter()
                    .any(|r| r.table == table && r.metric == metric && r.destination == prefix),
                "route {prefix} table {table} metric {metric} conflicts with an unowned kernel/DHCP/operator route"
            );
        }
    }
    Ok(())
}
pub async fn boot_snapshot(handle: &Handle, expected: &Network, keys: &Path) -> Result<Value> {
    let available = links(handle).await?;
    let names = available
        .iter()
        .map(|l| (l.header.index, name(l)))
        .collect();
    let mut actual = Vec::new();
    for desired in &expected.interfaces {
        let Some(link) = available.iter().find(|l| name(l) == desired.name) else {
            ensure!(
                desired.kind != "ethernet",
                "configured Ethernet {} is missing after reboot",
                desired.name
            );
            continue;
        };
        ensure!(
            matches_kind(link, &desired.kind),
            "owned interface {} has conflicting kind after reboot",
            desired.name
        );
        if let Some(v) = &desired.vlan {
            let parent = available
                .iter()
                .find(|p| name(p) == v.parent)
                .context("reboot VLAN parent missing")?;
            ensure!(
                vlan(link)? == Some((parent.header.index, v.id)),
                "owned VLAN identity changed after reboot"
            );
        }
        if let Some(wg) = &desired.wireguard {
            super::wireguard::verify(keys, &desired.name, wg)
                .context("existing WireGuard state cannot be safely snapshotted after reboot")?;
        }
        let mut observed = desired.clone();
        observed.mtu = mtu(link);
        observed.up = link.header.flags.contains(&LinkFlag::Up);
        observed.addresses = addresses(handle, link.header.index)
            .await?
            .iter()
            .map(address_string)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        actual.push(observed);
    }
    let routes = owned_routes(handle)
        .await?
        .iter()
        .map(|r| decode_route(r, &names))
        .collect::<Result<Vec<_>>>()?;
    let rules = owned_rules(handle)
        .await?
        .iter()
        .map(decode_rule)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        routes.iter().all(|r| expected.routes.contains(r)),
        "unexpected protocol-242 route after reboot"
    );
    ensure!(
        rules.iter().all(|r| expected.policy_rules.contains(r)),
        "unexpected owned policy rule after reboot"
    );
    let mut value = serde_json::to_value(netcontrol_core::Config::empty())?;
    value["interfaces"] = serde_json::to_value(actual)?;
    value["routes"] = serde_json::to_value(routes)?;
    value["policy_rules"] = serde_json::to_value(rules)?;
    Ok(value)
}

async fn owned_rules(handle: &Handle) -> Result<Vec<RuleMessage>> {
    let mut owned = Vec::new();
    for version in [IpVersion::V4, IpVersion::V6] {
        let messages: Vec<RuleMessage> = handle.rule().get(version).execute().try_collect().await?;
        for message in messages {
            let priority = message
                .attributes
                .iter()
                .find_map(|a| {
                    if let RuleAttribute::Priority(v) = a {
                        Some(*v)
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            if (10000..=19999).contains(&priority) {
                owned.push(message);
            }
        }
    }
    Ok(owned)
}
fn decode_rule(message: &RuleMessage) -> Result<Rule> {
    ensure!(
        message.header.action == RuleAction::ToTable
            && message.header.dst_len == 0
            && message.header.tos == 0
            && message.header.flags.is_empty(),
        "unsupported owned policy rule action/header"
    );
    let mut source = match message.header.family {
        AddressFamily::Inet => IpAddr::from([0u8; 4]),
        AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        _ => bail!("unsupported rule family"),
    };
    let mut priority = None;
    let mut table = message.header.table as u32;
    for a in &message.attributes {
        match a {
            RuleAttribute::Source(v) => source = *v,
            RuleAttribute::Priority(v) => priority = Some(*v),
            RuleAttribute::Table(v) => table = *v,
            RuleAttribute::Protocol(_) => {}
            RuleAttribute::SuppressIfGroup(v) | RuleAttribute::SuppressPrefixLen(v)
                if *v == u32::MAX => {}
            _ => bail!("unsupported owned policy rule attribute"),
        }
    }
    ensure!(
        table == 254 || (10000..=19999).contains(&table),
        "owned policy rule points outside managed tables"
    );
    Ok(Rule {
        source: format!("{source}/{}", message.header.src_len),
        priority: priority.context("policy priority missing")?,
        table,
    })
}

pub async fn verify(
    handle: &Handle,
    network: &Network,
    parents: &BTreeMap<String, Parent>,
    keys: &Path,
) -> Result<()> {
    check_parents(handle, parents).await?;
    let available = links(handle).await?;
    let by_index: BTreeMap<_, _> = available
        .iter()
        .map(|l| (l.header.index, name(l)))
        .collect();
    let by_name: BTreeMap<_, _> = available.iter().map(|l| (name(l), l)).collect();
    for desired in &network.interfaces {
        let actual = by_name.get(&desired.name).ok_or_else(|| {
            netcontrol_core::BackendDrift(format!("managed interface {} missing", desired.name))
        })?;
        crate::ensure_unchanged(
            matches_kind(actual, &desired.kind)
                && mtu(actual) == desired.mtu
                && actual.header.flags.contains(&LinkFlag::Up) == desired.up,
            format!("interface {} kind/MTU/up drift", desired.name),
        )?;
        if let Some(v) = &desired.vlan {
            let expected_parent = by_name
                .get(&v.parent)
                .ok_or_else(|| netcontrol_core::BackendDrift("VLAN parent missing".into()))?;
            crate::ensure_unchanged(
                desired.mtu <= mtu(expected_parent),
                "VLAN MTU exceeds parent",
            )?;
            crate::ensure_unchanged(
                vlan(actual)? == Some((expected_parent.header.index, v.id)),
                "VLAN identity drift",
            )?;
        }
        let mut actual_addresses = Vec::new();
        for address in addresses(handle, actual.header.index).await? {
            if let Some(address) = address_string(&address)? {
                actual_addresses.push(address);
            }
        }
        actual_addresses.sort();
        crate::ensure_unchanged(
            actual_addresses == desired.addresses,
            format!("interface {} address drift", desired.name),
        )?;
        if let Some(wg) = &desired.wireguard {
            super::wireguard::verify(keys, &desired.name, wg)?;
        }
    }
    let mut routes = owned_routes(handle)
        .await?
        .iter()
        .map(|v| decode_route(v, &by_index))
        .collect::<Result<Vec<_>>>()?;
    routes.sort();
    crate::ensure_unchanged(routes == network.routes, "owned route drift")?;
    let mut rules = owned_rules(handle)
        .await?
        .iter()
        .map(decode_rule)
        .collect::<Result<Vec<_>>>()?;
    rules.sort();
    crate::ensure_unchanged(rules == network.policy_rules, "owned policy rule drift")?;
    Ok(())
}

pub async fn reconcile(
    handle: &Handle,
    before: &Network,
    after: &Network,
    parents: &BTreeMap<String, Parent>,
    keys: &Path,
    originals: &BTreeMap<String, EthernetSnapshot>,
) -> Result<()> {
    check_parents(handle, parents).await?;
    let allowed: BTreeSet<_> = before
        .interfaces
        .iter()
        .chain(&after.interfaces)
        .map(|l| l.name.clone())
        .collect();
    let mut available = links(handle).await?;
    // Remove obsolete owned rules/routes before link changes. Retain matching entries
    // so an unrelated edit does not create an avoidable routing outage.
    let mut present_rules = BTreeSet::new();
    for message in owned_rules(handle).await? {
        let rule = decode_rule(&message)?;
        if after.policy_rules.contains(&rule) {
            present_rules.insert(rule);
        } else {
            handle.rule().del(message).execute().await?;
        }
    }
    let by_index = available
        .iter()
        .map(|l| (l.header.index, name(l)))
        .collect();
    let mut present_routes = BTreeSet::new();
    for message in owned_routes(handle).await? {
        let route = decode_route(&message, &by_index)?;
        if after.routes.contains(&route) {
            present_routes.insert(route);
        } else {
            handle.route().del(message).execute().await?;
        }
    }
    // Recreate identity changes and removed links children-first.
    let wanted: BTreeMap<_, _> = after
        .interfaces
        .iter()
        .map(|v| (v.name.clone(), v))
        .collect();
    let mut remove = BTreeSet::new();
    for link in &available {
        let name = name(link);
        if !allowed.contains(&name) || parents.contains_key(&name) {
            continue;
        }
        if before
            .interfaces
            .iter()
            .chain(&after.interfaces)
            .any(|l| l.name == name && l.kind == "ethernet")
        {
            ensure!(
                ethernet_kind(&kind(link)),
                "refusing to replace preexisting Ethernet {name}"
            );
            ensure!(
                wanted.get(&name).is_none_or(|l| l.kind == "ethernet"),
                "Ethernet cannot change kind"
            );
            continue;
        }
        ensure!(
            !ethernet_kind(&kind(link)),
            "refusing to delete or replace preexisting Ethernet link {name}"
        );
        let replace = match wanted.get(&name) {
            None => true,
            Some(wanted) if !matches_kind(link, &wanted.kind) => true,
            Some(wanted) => match &wanted.vlan {
                Some(v) => {
                    let parent_index = available
                        .iter()
                        .find(|p| self::name(p) == v.parent)
                        .map(|p| p.header.index);
                    vlan(link)? != parent_index.map(|index| (index, v.id))
                }
                None => false,
            },
        };
        if replace {
            remove.insert(link.header.index);
        }
    }
    // If a parent is recreated, all managed descendants must be recreated too.
    loop {
        let old_len = remove.len();
        for link in &available {
            if link
                .attributes
                .iter()
                .any(|a| matches!(a, LinkAttribute::Link(v) if remove.contains(v)))
            {
                ensure!(
                    allowed.contains(&name(link)),
                    "refusing parent deletion that would destroy unmanaged child {}",
                    name(link)
                );
                ensure!(
                    !ethernet_kind(&kind(link)),
                    "refusing parent deletion that would destroy Ethernet {}",
                    name(link)
                );
                remove.insert(link.header.index);
            }
        }
        if remove.len() == old_len {
            break;
        }
    }
    while !remove.is_empty() {
        let index = *remove
            .iter()
            .find(|index| {
                !available.iter().any(|l| {
                    remove.contains(&l.header.index)
                        && l.attributes
                            .iter()
                            .any(|a| matches!(a, LinkAttribute::Link(v) if v == *index))
                })
            })
            .context("cyclic live VLAN dependency")?;
        handle.link().del(index).execute().await?;
        remove.remove(&index);
        available.retain(|l| l.header.index != index);
    }
    let restored: BTreeMap<_, _> = originals
        .iter()
        .filter(|(name, _)| {
            before
                .interfaces
                .iter()
                .any(|l| l.name == **name && l.kind == "ethernet")
                && !wanted.contains_key(*name)
        })
        .map(|(name, snapshot)| (name.clone(), snapshot.clone()))
        .collect();
    restore_ethernet(handle, &restored).await?;
    for desired in after.ordered_links()? {
        let index = if let Some(link) = available.iter().find(|l| name(l) == desired.name) {
            link.header.index
        } else {
            match desired.kind.as_str() {
                "dummy" => {
                    handle
                        .link()
                        .add()
                        .dummy(desired.name.clone())
                        .execute()
                        .await?
                }
                "wireguard" => {
                    handle
                        .link()
                        .add()
                        .wireguard(desired.name.clone())
                        .execute()
                        .await?
                }
                "vlan" => {
                    let vlan = desired.vlan.as_ref().context("missing VLAN")?;
                    let parent = available
                        .iter()
                        .find(|l| name(l) == vlan.parent)
                        .context("VLAN parent unavailable")?;
                    ensure!(desired.mtu <= mtu(parent), "VLAN MTU exceeds parent");
                    handle
                        .link()
                        .add()
                        .vlan(desired.name.clone(), parent.header.index, vlan.id)
                        .execute()
                        .await?;
                }
                _ => bail!("unsupported native link kind"),
            }
            available = links(handle).await?;
            available
                .iter()
                .find(|l| name(l) == desired.name)
                .context("created link not found")?
                .header
                .index
        };
        handle.link().set(index).mtu(desired.mtu).execute().await?;
        let request = handle.link().set(index);
        if desired.up {
            request.up().execute().await?;
        } else {
            request.down().execute().await?;
        }
        for address in addresses(handle, index).await? {
            if let Some(prefix) = address_string(&address)? {
                if !desired.addresses.contains(&prefix) {
                    handle.address().del(address).execute().await?;
                }
            }
        }
        for prefix in &desired.addresses {
            let (ip, len) = parse_prefix(prefix, false)?;
            if after.dhcp_clients.contains_key(&desired.name) && ip.is_ipv4() {
                continue;
            }
            let mut request = handle.address().add(index, ip, len).replace();
            request
                .message_mut()
                .attributes
                .push(AddressAttribute::Flags(vec![AddressFlag::Nodad]));
            request.execute().await?;
        }
        if let Some(wg) = &desired.wireguard {
            if super::wireguard::verify(keys, &desired.name, wg).is_err() {
                super::wireguard::apply(keys, &desired.name, wg)?;
            }
        }
    }
    available = links(handle).await?;
    for route in &after.routes {
        if present_routes.contains(route) {
            continue;
        }
        let index = available
            .iter()
            .find(|l| name(l) == route.interface)
            .context("route interface unavailable")?
            .header
            .index;
        let (destination, length) = parse_prefix(&route.destination, true)?;
        let scope = if destination.is_ipv4() && route.gateway.is_empty() {
            RouteScope::Link
        } else {
            RouteScope::Universe
        };
        let request = handle
            .route()
            .add()
            .table_id(route.table)
            .priority(route.metric)
            .output_interface(index)
            .protocol(RouteProtocol::Other(PROTOCOL))
            .scope(scope);
        match destination {
            IpAddr::V4(ip) => {
                let mut request = request.v4().destination_prefix(ip, length);
                if !route.gateway.is_empty() {
                    request = request.gateway(route.gateway.parse()?);
                }
                request.execute().await?;
            }
            IpAddr::V6(ip) => {
                let mut request = request.v6().destination_prefix(ip, length);
                if !route.gateway.is_empty() {
                    request = request.gateway(route.gateway.parse()?);
                }
                request.execute().await?;
            }
        }
    }
    for rule in &after.policy_rules {
        if present_rules.contains(rule) {
            continue;
        }
        let (source, length) = parse_prefix(&rule.source, true)?;
        let request = handle
            .rule()
            .add()
            .table_id(rule.table)
            .priority(rule.priority)
            .action(RuleAction::ToTable);
        match source {
            IpAddr::V4(ip) => request.v4().source_prefix(ip, length).execute().await?,
            IpAddr::V6(ip) => request.v6().source_prefix(ip, length).execute().await?,
        }
    }
    Ok(())
}

pub async fn dhcp_lease(
    handle: &Handle,
    name: &str,
    previous: Option<&super::dhcp_client::Lease>,
    next: Option<&super::dhcp_client::Lease>,
    addressing: &super::dhcp_client::Addressing,
    publish_dns: bool,
) -> Result<()> {
    let link = links(handle)
        .await?
        .into_iter()
        .find(|link| self::name(link) == name)
        .context("DHCP interface disappeared")?;
    let index = link.header.index;
    let routes: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_collect()
        .await?;
    if let Some(lease) = next {
        for message in &routes {
            if message.header.protocol == RouteProtocol::Other(super::dhcp_client::PROTOCOL)
                && message.attributes.iter().any(
                    |attribute| matches!(attribute, RouteAttribute::Oif(value) if *value == index),
                )
            {
                continue;
            }
            let (table, metric, prefix) = route_key(message)?;
            ensure!(
                !lease.routes.iter().any(|route| route.table == table
                    && route.metric == metric
                    && route.destination == prefix),
                "DHCP route {prefix} conflicts with a route not owned by this client"
            );
        }
    }
    let mtu = next.and_then(|lease| lease.mtu).unwrap_or(addressing.mtu);
    if mtu != 0 {
        handle.link().set(index).mtu(mtu).execute().await?;
    }
    if let Some(previous) = previous {
        if next.is_none_or(|lease| lease.address != previous.address) {
            for address in addresses(handle, index).await? {
                if address_string(&address)?.as_deref() == Some(previous.address.as_str()) {
                    handle.address().del(address).execute().await?;
                }
            }
        }
    }
    if let Some(lease) = next {
        let (ip, length) = parse_prefix(&lease.address, false)?;
        let remaining = lease
            .acquired_at
            .saturating_add(u64::from(lease.lifetime))
            .saturating_sub(super::dhcp_client::now()?)
            .min(u64::from(u32::MAX)) as u32;
        ensure!(remaining > 0, "cannot apply an expired DHCP lease");
        let mut request = handle.address().add(index, ip, length).replace();
        let mut cache = netlink_packet_route::address::CacheInfo::default();
        cache.ifa_preferred = remaining;
        cache.ifa_valid = remaining;
        request
            .message_mut()
            .attributes
            .push(AddressAttribute::CacheInfo(cache));
        request
            .message_mut()
            .attributes
            .push(AddressAttribute::Flags(vec![
                netlink_packet_route::address::AddressFlag::Noprefixroute,
            ]));
        request.execute().await?;
    }
    let names = BTreeMap::from([(index, name.to_owned())]);
    for message in routes {
        if message.header.protocol != RouteProtocol::Other(super::dhcp_client::PROTOCOL)
            || !message
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RouteAttribute::Oif(value) if *value == index))
        {
            continue;
        }
        let mut decoded = message.clone();
        decoded
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::PrefSource(_)));
        let observed = decode_route(&decoded, &names)?;
        if !next.is_some_and(|lease| lease.routes.contains(&observed)) {
            handle.route().del(message).execute().await?;
        }
    }
    if let Some(lease) = next {
        let mut routes: Vec<_> = lease.routes.iter().collect();
        routes.sort_by_key(|route| !route.gateway.is_empty());
        for route in routes {
            let (destination, length) = parse_prefix(&route.destination, true)?;
            let IpAddr::V4(destination) = destination else {
                bail!("DHCPv4 supplied an IPv6 route")
            };
            let mut request = handle
                .route()
                .add()
                .v4()
                .destination_prefix(destination, length)
                .output_interface(index)
                .table_id(route.table)
                .priority(route.metric)
                .protocol(RouteProtocol::Other(super::dhcp_client::PROTOCOL))
                .scope(if route.gateway.is_empty() {
                    RouteScope::Link
                } else {
                    RouteScope::Universe
                })
                .replace();
            if !route.gateway.is_empty() {
                request = request.gateway(route.gateway.parse()?);
            }
            request.execute().await?;
        }
    }
    if publish_dns {
        super::adoption::set_dns(index, &addressing.dns, next)?;
    }
    Ok(())
}

pub async fn configure_dns(
    handle: &Handle,
    network: &Network,
    state: &super::dhcp_client::State,
) -> Result<()> {
    let available = links(handle).await?;
    for desired in &network.interfaces {
        let link = available
            .iter()
            .find(|link| name(link) == desired.name)
            .context("DNS interface disappeared")?;
        let configured = network.dns.get(&desired.name).cloned().unwrap_or_default();
        let lease = state.leases.get(&desired.name).filter(|lease| {
            lease.valid() && network.dhcp_clients.get(&desired.name) == Some(&lease.client)
        });
        super::adoption::set_dns(link.header.index, &configured, lease)?;
    }
    Ok(())
}

pub async fn verify_dhcp(
    handle: &Handle,
    network: &Network,
    state: &super::dhcp_client::State,
) -> Result<()> {
    let names: BTreeMap<_, _> = links(handle)
        .await?
        .iter()
        .filter(|link| {
            network
                .interfaces
                .iter()
                .any(|desired| desired.name == name(link))
        })
        .map(|link| (link.header.index, name(link)))
        .collect();
    let mut expected: Vec<_> = state
        .leases
        .iter()
        .filter(|(name, lease)| {
            lease.valid() && network.dhcp_clients.get(*name) == Some(&lease.client)
        })
        .flat_map(|(_, lease)| lease.routes.clone())
        .collect();
    let mut observed = Vec::new();
    let routes: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_collect()
        .await?;
    for mut route in routes {
        if route.header.protocol != RouteProtocol::Other(super::dhcp_client::PROTOCOL)
            || !route.attributes.iter().any(|attribute| matches!(attribute, RouteAttribute::Oif(index) if names.contains_key(index))) { continue; }
        for attribute in &route.attributes {
            if let RouteAttribute::PrefSource(address) = attribute {
                ensure!(
                    state.leases.values().any(|lease| lease.valid()
                        && lease.address.split_once('/').is_some_and(|(ip, _)| ip
                            == route_ip(address)
                                .map(|ip| ip.to_string())
                                .unwrap_or_default())),
                    "DHCP route preferred source drift"
                );
            }
        }
        route
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::PrefSource(_)));
        observed.push(decode_route(&route, &names)?);
    }
    expected.sort();
    observed.sort();
    crate::ensure_unchanged(expected == observed, "DHCP route drift")
}

pub async fn statistics(
    handle: &Handle,
    config: &Value,
    parents: &BTreeMap<String, Parent>,
    scope: &str,
    path: &str,
    query: &str,
) -> Result<Value> {
    ensure!(
        query.is_empty(),
        "statistics endpoints do not accept query parameters"
    );
    let started_at =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let filter = path.strip_prefix("/api/v1/statistics/interfaces/");
    if let Some(filter) = filter {
        ensure!(
            crate::safe_name(filter, 15),
            "invalid statistics interface name"
        );
    }
    let interfaces_only = path == "/api/v1/statistics/interfaces" || filter.is_some();
    let mut interfaces = Vec::new();
    if path != "/api/v1/statistics/protocols" {
        for link in links(handle).await? {
            let name = name(&link);
            if filter.is_some_and(|v| v != name) {
                continue;
            }
            let p = parent(&link);
            let ownership = if name == "lo" {
                "loopback"
            } else if parents.contains_key(&name) {
                "adopted_parent"
            } else if config["interfaces"]
                .as_array()
                .is_some_and(|links| links.iter().any(|l| l["name"] == name))
            {
                "managed"
            } else {
                "unmanaged"
            };
            let stats = link
                .attributes
                .iter()
                .find_map(|a| {
                    if let LinkAttribute::Stats64(v) = a {
                        Some(v)
                    } else {
                        None
                    }
                })
                .context("kernel omitted 64-bit link statistics")?;
            let oper_state = link
                .attributes
                .iter()
                .find_map(|a| {
                    if let LinkAttribute::OperState(v) = a {
                        Some(
                            match v {
                                netlink_packet_route::link::State::Unknown => "unknown",
                                netlink_packet_route::link::State::NotPresent => "notpresent",
                                netlink_packet_route::link::State::Down => "down",
                                netlink_packet_route::link::State::LowerLayerDown => {
                                    "lowerlayerdown"
                                }
                                netlink_packet_route::link::State::Testing => "testing",
                                netlink_packet_route::link::State::Dormant => "dormant",
                                netlink_packet_route::link::State::Up => "up",
                                _ => "unknown",
                            }
                            .to_string(),
                        )
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "unknown".into());
            interfaces.push(json!({"name":name,"index":p.index,"kind":p.kind,"mac":p.mac,"mtu":p.mtu,"admin_up":p.up,"oper_state":oper_state,"ownership":ownership,"status":"available","counter_bits":64,"counters":{
                "rx_bytes":stats.rx_bytes.to_string(),"tx_bytes":stats.tx_bytes.to_string(),"rx_packets":stats.rx_packets.to_string(),"tx_packets":stats.tx_packets.to_string(),
                "rx_errors":stats.rx_errors.to_string(),"tx_errors":stats.tx_errors.to_string(),"rx_dropped":stats.rx_dropped.to_string(),"tx_dropped":stats.tx_dropped.to_string(),
                "multicast":stats.multicast.to_string(),"collisions":stats.collisions.to_string(),"rx_length_errors":stats.rx_length_errors.to_string(),"rx_over_errors":stats.rx_over_errors.to_string(),
                "rx_crc_errors":stats.rx_crc_errors.to_string(),"rx_frame_errors":stats.rx_frame_errors.to_string(),"rx_fifo_errors":stats.rx_fifo_errors.to_string(),"rx_missed_errors":stats.rx_missed_errors.to_string(),
                "tx_aborted_errors":stats.tx_aborted_errors.to_string(),"tx_carrier_errors":stats.tx_carrier_errors.to_string(),"tx_fifo_errors":stats.tx_fifo_errors.to_string(),
                "tx_heartbeat_errors":stats.tx_heartbeat_errors.to_string(),"tx_window_errors":stats.tx_window_errors.to_string(),"rx_compressed":stats.rx_compressed.to_string(),
                "tx_compressed":stats.tx_compressed.to_string(),"rx_nohandler":stats.rx_nohandler.to_string(),"rx_otherhost_dropped":stats.rx_otherhost_dropped.to_string()}}));
        }
        ensure!(
            filter.is_none() || !interfaces.is_empty(),
            "statistics interface not found"
        );
    } else {
        ensure!(
            filter.is_none(),
            "interface filter is not valid for protocol counters"
        );
    }
    let mut protocols = Vec::new();
    if !interfaces_only {
        for source in ["snmp", "netstat", "snmp6"] {
            use std::io::Read;
            let mut content = String::new();
            std::fs::File::open(format!("/proc/thread-self/net/{source}"))?
                .take(1024 * 1024 + 1)
                .read_to_string(&mut content)?;
            let counters = if source == "snmp6" {
                json!({"IPv6":crate::statistics::ipv6_counters(&content)?})
            } else {
                crate::statistics::paired_counters(&content)?
            };
            protocols.push(json!({"name":source,"status":"available","groups":counters}));
        }
    }
    let collected_at =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    interfaces.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let sample = json!({"scope":scope,"started_at":started_at,"collected_at":collected_at,"status":"available"});
    if filter.is_some() {
        Ok(json!({"sample":sample,"interface":interfaces.remove(0)}))
    } else if interfaces_only {
        Ok(json!({"sample":sample,"interfaces":interfaces}))
    } else if path == "/api/v1/statistics/protocols" {
        Ok(json!({"sample":sample,"protocols":protocols}))
    } else {
        Ok(json!({"interfaces":interfaces,"protocols":protocols,"sample":sample}))
    }
}
