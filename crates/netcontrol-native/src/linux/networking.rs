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
    route::{
        RouteAddress, RouteAttribute, RouteMessage, RoutePreference, RouteProtocol, RouteScope,
        RouteType,
    },
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use netlink_packet_utils::{Emitable, Parseable, nla::Nla};
use rtnetlink::{Handle, IpVersion};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn adoption_links() -> (LinkMessage, LinkMessage, netcontrol_core::AdoptVlanRequest) {
        let request = netcontrol_core::AdoptVlanRequest {
            name: "vlan50".into(),
            parent: "eth0".into(),
            id: 50,
        };
        let mut parent = LinkMessage::default();
        parent.header.index = 2;
        parent.attributes = vec![
            LinkAttribute::IfName("eth0".into()),
            LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]),
        ];
        let mut link = LinkMessage::default();
        link.header.index = 3;
        link.attributes = vec![
            LinkAttribute::IfName("vlan50".into()),
            LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]),
            LinkAttribute::Link(2),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(netlink_packet_route::link::InfoKind::Vlan),
                LinkInfo::Data(InfoData::Vlan(vec![
                    InfoVlan::Id(50),
                    InfoVlan::Protocol(VlanProtocol::Ieee8021Q),
                    InfoVlan::Flags((1, u32::MAX)),
                ])),
            ]),
        ];
        (link, parent, request)
    }

    #[test]
    fn startup_ethernet_activation_selects_only_managed_configured_up_links() -> Result<()> {
        let config: netcontrol_core::Config = serde_json::from_value(json!({
            "interfaces": [
                {"name":"static0","kind":"ethernet","role":"lan","mtu":1500,"up":true,
                 "addresses":["192.0.2.1/24"]},
                {"name":"dhcp0","kind":"ethernet","role":"wan","mtu":1500,"up":true},
                {"name":"disabled0","kind":"ethernet","role":"unassigned","mtu":1500,"up":false}
            ],
            "dhcp_clients":{"dhcp0":{}}
        }))?;
        let network = Network::parse(&config.operational_value()?)?;
        let link = |name: &str, index, up| {
            let mut link = LinkMessage::default();
            link.header.index = index;
            if up {
                link.header.flags.push(LinkFlag::Up);
            }
            link.attributes.push(LinkAttribute::IfName(name.into()));
            link
        };
        let mut available = vec![
            link("static0", 2, false),
            link("dhcp0", 3, false),
            link("disabled0", 4, false),
            link("unmanaged0", 5, false),
        ];
        assert_eq!(
            down_configured_ethernet(&network, &available)?,
            vec![("dhcp0".into(), 3), ("static0".into(), 2)]
        );
        available[0].header.flags.push(LinkFlag::Up);
        assert_eq!(
            down_configured_ethernet(&network, &available)?,
            vec![("dhcp0".into(), 3)]
        );
        let mut wrong_kind = available.clone();
        wrong_kind[0]
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                netlink_packet_route::link::InfoKind::Dummy,
            )]));
        assert!(down_configured_ethernet(&network, &wrong_kind).is_err());
        available.retain(|link| name(link) != "dhcp0");
        assert!(down_configured_ethernet(&network, &available).is_err());
        Ok(())
    }

    #[test]
    fn ethernet_rollback_distinguishes_address_and_prefix_route_flags() {
        let mut captured = AddressMessage::default();
        captured.header.family = AddressFamily::Inet;
        captured.header.prefix_len = 24;
        captured
            .attributes
            .push(AddressAttribute::Local("192.0.2.2".parse().unwrap()));
        captured
            .attributes
            .push(AddressAttribute::Flags(vec![AddressFlag::Noprefixroute]));
        let mut current = captured.clone();
        assert!(same_address(&captured, &current));
        assert!(same_prefix_route_flag(&captured, &current));
        current
            .attributes
            .retain(|attribute| !matches!(attribute, AddressAttribute::Flags(_)));
        assert!(same_address(&captured, &current));
        assert!(!same_prefix_route_flag(&captured, &current));
    }

    #[test]
    fn vlan_adoption_requires_exact_unmastered_nonstacked_standard_identity() {
        let (link, parent, request) = adoption_links();
        validate_adoptable_vlan(&link, &parent, &request).unwrap();
        let mut wrong = request.clone();
        wrong.id = 51;
        assert!(validate_adoptable_vlan(&link, &parent, &wrong).is_err());
        let mut replacement = parent.clone();
        replacement.header.index = 7;
        assert!(validate_adoptable_vlan(&link, &replacement, &request).is_err());
        let mut mastered = link.clone();
        mastered.attributes.push(LinkAttribute::Controller(9));
        assert!(validate_adoptable_vlan(&mastered, &parent, &request).is_err());
        let mut mastered_parent = parent.clone();
        mastered_parent
            .attributes
            .push(LinkAttribute::Controller(9));
        assert!(validate_adoptable_vlan(&link, &mastered_parent, &request).is_err());
        let mut stacked = parent.clone();
        stacked
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                netlink_packet_route::link::InfoKind::Vlan,
            )]));
        assert!(validate_adoptable_vlan(&link, &stacked, &request).is_err());
        for attribute in [
            InfoVlan::Protocol(VlanProtocol::Ieee8021Ad),
            InfoVlan::Flags((2, u32::MAX)),
            InfoVlan::Flags((0, u32::MAX)),
            InfoVlan::IngressQos(vec![netlink_packet_route::link::VlanQosMapping::Mapping(
                0, 1,
            )]),
        ] {
            let mut foreign = link.clone();
            foreign
                .attributes
                .retain(|attribute| !matches!(attribute, LinkAttribute::LinkInfo(_)));
            foreign.attributes.push(LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(netlink_packet_route::link::InfoKind::Vlan),
                LinkInfo::Data(InfoData::Vlan(vec![InfoVlan::Id(50), attribute])),
            ]));
            assert!(validate_adoptable_vlan(&foreign, &parent, &request).is_err());
        }
    }

    #[test]
    fn vlan_adoption_rejects_nonconnected_and_nonstandard_routes() {
        let mut address = AddressMessage::default();
        address.header.family = AddressFamily::Inet;
        address.header.prefix_len = 24;
        address
            .attributes
            .push(AddressAttribute::Local("192.0.2.1".parse().unwrap()));
        let mut route = RouteMessage::default();
        route.header.address_family = AddressFamily::Inet;
        route.header.destination_prefix_length = 24;
        route.header.table = 254;
        route.header.protocol = RouteProtocol::Kernel;
        route.header.kind = RouteType::Unicast;
        route.header.scope = RouteScope::Link;
        route.attributes = vec![
            RouteAttribute::Oif(3),
            RouteAttribute::Destination(RouteAddress::Inet("192.0.2.0".parse().unwrap())),
        ];
        validate_vlan_connected_route(&route, &[address.clone()]).unwrap();
        route.header.protocol = RouteProtocol::Static;
        assert!(validate_vlan_connected_route(&route, &[address.clone()]).is_err());
        route.header.protocol = RouteProtocol::Kernel;
        route.attributes.push(RouteAttribute::Priority(5));
        assert!(validate_vlan_connected_route(&route, &[address.clone()]).is_err());
        route.attributes.pop();
        route.header.destination_prefix_length = 0;
        assert!(validate_vlan_connected_route(&route, &[address]).is_err());
    }

    fn permanent_vlan_address(ip: &str) -> AddressMessage {
        let mut address = AddressMessage::default();
        address.header.family = AddressFamily::Inet;
        address.header.prefix_len = 24;
        address.header.index = 3;
        address.header.flags = vec![AddressHeaderFlag::Permanent];
        let mut cache = netlink_packet_route::address::CacheInfo::default();
        cache.ifa_valid = u32::MAX;
        cache.ifa_preferred = u32::MAX;
        cache.cstamp = 10;
        cache.tstamp = 20;
        address.attributes = vec![
            AddressAttribute::Address(ip.parse().unwrap()),
            AddressAttribute::Local(ip.parse().unwrap()),
            AddressAttribute::Label("vlan50".into()),
            AddressAttribute::CacheInfo(cache),
        ];
        address
    }

    fn vlan_snapshot(addresses: Vec<AddressMessage>) -> EthernetSnapshot {
        EthernetSnapshot {
            name: "vlan50".into(),
            kind: "vlan".into(),
            index: 3,
            mac: "02:00:00:00:00:01".into(),
            mtu: 1500,
            up: true,
            boot: "test-boot".into(),
            captured_unix: 1,
            addresses: addresses
                .into_iter()
                .map(|address| {
                    let mut raw = vec![0; address.buffer_len()];
                    address.emit(&mut raw);
                    raw
                })
                .collect(),
        }
    }

    #[test]
    fn interface_ownership_comparison_ignores_timestamps_and_dump_order() {
        let mut first = permanent_vlan_address("192.0.2.1");
        let second = permanent_vlan_address("198.51.100.1");
        let expected = vlan_snapshot(vec![first.clone(), second.clone()]);
        for attribute in &mut first.attributes {
            if let AddressAttribute::CacheInfo(info) = attribute {
                info.cstamp += 100;
                info.tstamp += 200;
            }
        }
        first.attributes.reverse();
        let mut current = vlan_snapshot(vec![second, first]);
        current.captured_unix += 300;
        assert_ne!(current.addresses, expected.addresses);
        check_interface_snapshot(&current, &expected).unwrap();
    }

    #[test]
    fn interface_ownership_comparison_rejects_identity_and_settings_changes() {
        let address = permanent_vlan_address("192.0.2.1");
        let expected = vlan_snapshot(vec![address.clone()]);
        for field in ["name", "kind", "index", "mac", "mtu", "up", "addresses"] {
            let mut current = expected.clone();
            match field {
                "name" => current.name = "different".into(),
                "kind" => current.kind = "veth".into(),
                "index" => current.index += 1,
                "mac" => current.mac = "02:00:00:00:00:02".into(),
                "mtu" => current.mtu += 1,
                "up" => current.up = false,
                "addresses" => current.addresses.clear(),
                _ => unreachable!(),
            }
            let error = check_interface_snapshot(&current, &expected).unwrap_err();
            assert!(error.to_string().contains(field), "{field}: {error}");
        }
        for field in [
            "prefix",
            "scope",
            "flags",
            "local",
            "label",
            "valid",
            "preferred",
        ] {
            let mut changed = address.clone();
            match field {
                "prefix" => changed.header.prefix_len = 25,
                "scope" => changed.header.scope = AddressScope::Host,
                "flags" => changed.header.flags.clear(),
                "local" => {
                    changed.attributes[1] = AddressAttribute::Local("192.0.2.2".parse().unwrap())
                }
                "label" => changed.attributes[2] = AddressAttribute::Label("different".into()),
                "valid" | "preferred" => {
                    let AddressAttribute::CacheInfo(info) = &mut changed.attributes[3] else {
                        unreachable!()
                    };
                    if field == "valid" {
                        info.ifa_valid = 120;
                    } else {
                        info.ifa_preferred = 120;
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                check_interface_snapshot(&vlan_snapshot(vec![changed]), &expected).is_err(),
                "{field}"
            );
        }
        let mut malformed = expected.clone();
        malformed.addresses = vec![vec![0]];
        assert!(check_interface_snapshot(&malformed, &expected).is_err());
    }

    #[test]
    fn interface_ownership_comparison_handles_lease_expiry_and_reboot_indices() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut address = permanent_vlan_address("192.0.2.1");
        let AddressAttribute::CacheInfo(cache) = &mut address.attributes[3] else {
            unreachable!()
        };
        cache.ifa_valid = 120;
        cache.ifa_preferred = 60;
        let mut expected = vlan_snapshot(vec![address.clone()]);
        expected.kind = "veth".into();
        expected.captured_unix = now - 10;
        let AddressAttribute::CacheInfo(cache) = &mut address.attributes[3] else {
            unreachable!()
        };
        cache.ifa_valid = 110;
        cache.ifa_preferred = 50;
        let mut current = vlan_snapshot(vec![address.clone()]);
        current.kind = "veth".into();
        current.captured_unix = now;
        check_interface_snapshot(&current, &expected).unwrap();
        let mut changed = address.clone();
        let AddressAttribute::CacheInfo(cache) = &mut changed.attributes[3] else {
            unreachable!()
        };
        cache.ifa_valid -= 20;
        let mut drifted = current.clone();
        drifted.addresses = vlan_snapshot(vec![changed]).addresses;
        assert!(check_interface_snapshot(&drifted, &expected).is_err());

        current.boot = "new-boot".into();
        current.index += 1;
        check_interface_snapshot(&current, &expected).unwrap();
        expected.captured_unix = now - 121;
        current.addresses.clear();
        check_interface_snapshot(&current, &expected).unwrap();
        expected.captured_unix = now + 60;
        assert!(check_interface_snapshot(&current, &expected).is_err());
    }

    #[test]
    fn loopback_kind_uses_kernel_flags_not_interface_name() {
        let mut link = LinkMessage::default();
        link.header.flags = vec![LinkFlag::Loopback];
        link.attributes.push(LinkAttribute::IfName("local0".into()));
        assert_eq!(kind(&link), "loopback");
        link.header.flags.clear();
        assert_eq!(kind(&link), "device");
        link.attributes = vec![LinkAttribute::IfName("lo".into())];
        assert_eq!(kind(&link), "device");
    }

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
            message
                .header
                .flags
                .push(netlink_packet_route::route::RouteFlag::Linkdown);
            assert!(decode_route(&message, &names).is_err());
            message.header.protocol = RouteProtocol::Other(PROTOCOL);
            assert_eq!(decode_route(&message, &names)?, decoded);
            message.header.protocol = RouteProtocol::Other(super::super::dhcp_client::PROTOCOL);
            assert_eq!(decode_route(&message, &names)?, decoded);
            message.header.scope = RouteScope::Host;
            assert!(decode_route(&message, &names).is_err());
        }
        Ok(())
    }

    #[test]
    fn deviceless_kernel_route_types_decode_only_as_the_configured_blackhole() -> Result<()> {
        let names = BTreeMap::from([(1, "lo".to_string()), (7, "test0".to_string())]);
        let configured = |action: &str| netcontrol_core::BlackholeConfig {
            name: "bh0".into(),
            action: action.into(),
            ..Default::default()
        };
        for (family, destination, length, device, kind, action) in [
            (
                AddressFamily::Inet,
                "198.51.100.0",
                24,
                None,
                RouteType::BlackHole,
                "blackhole",
            ),
            (
                AddressFamily::Inet6,
                "2001:db8:dead::",
                48,
                Some(1),
                RouteType::Unreachable,
                "unreachable",
            ),
            (
                AddressFamily::Inet,
                "203.0.113.0",
                24,
                None,
                RouteType::Prohibit,
                "prohibit",
            ),
        ] {
            let mut message = RouteMessage::default();
            message.header.address_family = family;
            message.header.kind = kind;
            message.header.scope = RouteScope::Universe;
            message.header.table = 254;
            message.header.destination_prefix_length = length;
            let address = match destination.parse::<IpAddr>()? {
                IpAddr::V4(ip) => RouteAddress::Inet(ip),
                IpAddr::V6(ip) => RouteAddress::Inet6(ip),
            };
            message.attributes = vec![
                RouteAttribute::Destination(address),
                RouteAttribute::Priority(50),
            ];
            if let Some(device) = device {
                message.attributes.push(RouteAttribute::Oif(device));
            }
            let route = decode_owned_route(&message, &names, Some(&configured(action)))?;
            assert_eq!(route.interface, "bh0");
            assert!(route.gateway.is_empty());
            assert_eq!(route.metric, 50);
            let other = decode_owned_route(&message, &names, Some(&configured("blackhole")))?;
            let expected = if action == "blackhole" {
                "bh0".to_string()
            } else {
                format!("blackhole:{action}")
            };
            assert_eq!(other.interface, expected);
            assert!(decode_route(&message, &names).is_err());
            let mut wrong_device = message.clone();
            wrong_device.attributes.push(RouteAttribute::Oif(7));
            assert!(decode_owned_route(&wrong_device, &names, Some(&configured(action))).is_err());
            let mut with_gateway = message.clone();
            with_gateway
                .attributes
                .push(RouteAttribute::Gateway(match family {
                    AddressFamily::Inet => RouteAddress::Inet("192.0.2.1".parse()?),
                    _ => RouteAddress::Inet6("2001:db8::1".parse()?),
                }));
            assert!(decode_owned_route(&with_gateway, &names, Some(&configured(action))).is_err());
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
    if link.header.flags.contains(&LinkFlag::Loopback) {
        return "loopback".into();
    }
    for a in &link.attributes {
        if let LinkAttribute::LinkInfo(info) = a {
            for v in info {
                if let LinkInfo::Kind(kind) = v {
                    return kind.to_string();
                }
            }
        }
    }
    "device".into()
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

fn down_configured_ethernet(
    network: &Network,
    available: &[LinkMessage],
) -> Result<Vec<(String, u32)>> {
    let mut down = Vec::new();
    for desired in network
        .interfaces
        .iter()
        .filter(|link| link.kind == "ethernet" && link.up)
    {
        let actual = available
            .iter()
            .find(|link| name(link) == desired.name)
            .with_context(|| format!("configured Ethernet {} is missing", desired.name))?;
        ensure!(
            matches_kind(actual, "ethernet"),
            "configured Ethernet {} changed kind",
            desired.name
        );
        if !actual.header.flags.contains(&LinkFlag::Up) {
            down.push((desired.name.clone(), actual.header.index));
        }
    }
    Ok(down)
}

pub(super) async fn needs_ethernet_activation(handle: &Handle, network: &Network) -> Result<bool> {
    Ok(!down_configured_ethernet(network, &links(handle).await?)?.is_empty())
}

pub(super) async fn activate_ethernet(handle: &Handle, network: &Network) -> Result<()> {
    for (name, index) in down_configured_ethernet(network, &links(handle).await?)? {
        handle
            .link()
            .set(index)
            .up()
            .execute()
            .await
            .with_context(|| format!("bring configured Ethernet {name} up"))?;
    }
    let remaining = down_configured_ethernet(network, &links(handle).await?)?;
    ensure!(
        remaining.is_empty(),
        "configured Ethernet interfaces remain administratively down: {}",
        remaining
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
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
            "addresses":prefixes,"ownership":ownership,
            "role":if ownership == "loopback" { Some("loopback") } else { None },
            "addressing_type":if ownership == "loopback" { Some("static") } else { None }
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
    let names = before
        .interfaces
        .iter()
        .chain(&after.interfaces)
        .filter(|link| link.kind == "ethernet")
        .map(|link| link.name.clone())
        .collect();
    let snapshots = capture_interfaces(handle, &names).await?;
    for snapshot in snapshots.values() {
        ensure!(
            ethernet_kind(&snapshot.kind) && snapshot.mac.len() == 17,
            "{} is not a physical Ethernet device or veth",
            snapshot.name
        );
    }
    Ok(snapshots)
}

pub(super) async fn capture_interfaces(
    handle: &Handle,
    names: &BTreeSet<String>,
) -> Result<BTreeMap<String, EthernetSnapshot>> {
    let available = links(handle).await?;
    let mut result = BTreeMap::new();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let captured_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for desired in names {
        let link = available
            .iter()
            .find(|link| name(link) == *desired)
            .with_context(|| format!("interface {desired} must already exist"))?;
        let p = parent(link);
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

fn validate_vlan_connected_route(route: &RouteMessage, addresses: &[AddressMessage]) -> Result<()> {
    let table = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table));
    ensure!(
        route.header.protocol == RouteProtocol::Kernel
            && route
                .header
                .flags
                .iter()
                .all(|flag| *flag == netlink_packet_route::route::RouteFlag::Linkdown)
            && route.header.source_prefix_length == 0
            && route.header.tos == 0,
        "VLAN adoption supports only ordinary kernel-connected routes"
    );
    if table == 255 {
        let multicast = route.header.kind == RouteType::Multicast
            && route.header.address_family == AddressFamily::Inet6
            && route.header.destination_prefix_length == 8
            && route.attributes.iter().any(|attribute| matches!(attribute,
                RouteAttribute::Destination(RouteAddress::Inet6(address)) if *address == "ff00::".parse::<std::net::Ipv6Addr>().expect("constant IPv6")));
        ensure!(
            matches!(route.header.kind, RouteType::Local | RouteType::Broadcast) || multicast,
            "unsupported VLAN local-table route: {:?}",
            route.header
        );
        return Ok(());
    }
    ensure!(
        table == 254 && route.header.kind == RouteType::Unicast,
        "unsupported VLAN route table/type"
    );
    let destination = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(address) => Some(route_ip(address)),
            _ => None,
        })
        .context("VLAN default routes cannot be adopted")??;
    let prefix = route.header.destination_prefix_length;
    ensure!(
        addresses.iter().any(|address| {
            address.header.prefix_len == prefix
                && address.attributes.iter().any(|attribute| {
                    let ip = match attribute {
                        AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => ip,
                        _ => return false,
                    };
                    ipnet::IpNet::new(*ip, prefix)
                        .is_ok_and(|network| network.network() == destination)
                })
        }),
        "VLAN kernel route is not address-connected"
    );
    for attribute in &route.attributes {
        ensure!(match attribute {
            RouteAttribute::Destination(_) | RouteAttribute::Oif(_) | RouteAttribute::Table(_) => true,
            RouteAttribute::Priority(metric) => *metric == if destination.is_ipv4() { 0 } else { 256 },
            RouteAttribute::Preference(preference) => *preference == RoutePreference::Medium,
            RouteAttribute::CacheInfo(cache) => cache.expires == 0 && cache.error == 0,
            RouteAttribute::PrefSource(ip) => route_ip(ip).is_ok_and(|ip| addresses.iter().any(|address|
                address.attributes.iter().any(|attribute| matches!(attribute,
                    AddressAttribute::Address(value) | AddressAttribute::Local(value) if *value == ip)))),
            _ => false,
        },         "unsupported VLAN connected-route attribute: {attribute:?}");
    }
    Ok(())
}

pub(super) async fn capture_vlan_snapshot(
    handle: &Handle,
    request: &netcontrol_core::AdoptVlanRequest,
) -> Result<EthernetSnapshot> {
    let p = adoptable_vlan(handle, request).await?;
    let messages = addresses(handle, p.index).await?;
    for version in [IpVersion::V4, IpVersion::V6] {
        let routes: Vec<RouteMessage> = handle.route().get(version).execute().try_collect().await?;
        for route in routes {
            ensure!(
                !route.attributes.iter().any(|attribute| matches!(
                    attribute,
                    RouteAttribute::MultiPath(_)
                ) || matches!(attribute, RouteAttribute::Other(value) if value.kind() == 30)),
                "VLAN adoption cannot safely attribute multipath/nexthop-object routes"
            );
            let associated = route.attributes.iter().any(|attribute| {
                matches!(attribute,
                RouteAttribute::Oif(index) | RouteAttribute::Iif(index) if *index == p.index)
            });
            if associated {
                validate_vlan_connected_route(&route, &messages)?;
            }
        }
    }
    let mut raw = Vec::new();
    for message in messages {
        if message.header.scope == AddressScope::Link {
            continue;
        }
        address_string(&message)?.context("unsupported VLAN address")?;
        validate_vlan_address(&message, &request.name)?;
        ensure!(!message.attributes.iter().any(|attribute| matches!(attribute,
            AddressAttribute::CacheInfo(info) if info.ifa_valid != u32::MAX || info.ifa_preferred != u32::MAX)),
            "dynamic VLAN addresses cannot be adopted");
        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        raw.push(bytes);
    }
    Ok(EthernetSnapshot {
        name: p.name,
        kind: p.kind,
        index: p.index,
        mac: p.mac,
        mtu: p.mtu,
        up: p.up,
        boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        captured_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        addresses: raw,
    })
}

async fn adoptable_vlan(
    handle: &Handle,
    request: &netcontrol_core::AdoptVlanRequest,
) -> Result<Parent> {
    let available = links(handle).await?;
    let link = available
        .iter()
        .find(|link| name(link) == request.name)
        .context("requested VLAN does not exist")?;
    let parent_link = available
        .iter()
        .find(|link| name(link) == request.parent)
        .context("VLAN parent does not exist")?;
    validate_adoptable_vlan(link, parent_link, request)?;
    ensure!(!available.iter().any(|other| other.attributes.iter()
        .any(|attribute| matches!(attribute, LinkAttribute::Link(index) if *index == link.header.index))),
        "VLAN has stacked/dependent links");
    Ok(parent(link))
}

pub(super) async fn check_vlan_identity(
    handle: &Handle,
    request: &netcontrol_core::AdoptVlanRequest,
    expected: &EthernetSnapshot,
) -> Result<()> {
    let current = adoptable_vlan(handle, request).await?;
    crate::ensure_unchanged(
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == expected.boot
            && current.name == expected.name
            && current.kind == expected.kind
            && current.index == expected.index
            && current.mac == expected.mac,
        "VLAN identity changed since durable capture",
    )
}

fn normalized_interface_addresses(snapshot: &EthernetSnapshot, now: u64) -> Result<Vec<Vec<u8>>> {
    let mut addresses = Vec::new();
    for raw in &snapshot.addresses {
        let mut address = AddressMessage::parse(&AddressMessageBuffer::new_checked(raw)?)?;
        address.header.index = 0;
        let mut expired = false;
        for attribute in &mut address.attributes {
            if let AddressAttribute::CacheInfo(info) = attribute {
                info.cstamp = 0;
                info.tstamp = 0;
                for lifetime in [&mut info.ifa_valid, &mut info.ifa_preferred] {
                    if *lifetime != u32::MAX {
                        let elapsed = now.checked_sub(snapshot.captured_unix).context(
                            "clock moved backward while verifying an interface address lifetime",
                        )?;
                        *lifetime =
                            lifetime.saturating_sub(u32::try_from(elapsed).unwrap_or(u32::MAX));
                    }
                }
                expired = info.ifa_valid == 0;
            }
        }
        if expired {
            continue;
        }
        address.attributes.sort_by_key(|attribute| attribute.kind());
        let mut normalized = vec![0; address.buffer_len()];
        address.emit(&mut normalized);
        addresses.push(normalized);
    }
    addresses.sort();
    Ok(addresses)
}

fn interface_addresses_match(
    current: &EthernetSnapshot,
    expected: &EthernetSnapshot,
    now: u64,
) -> Result<bool> {
    let current = normalized_interface_addresses(current, now)?;
    let expected = normalized_interface_addresses(expected, now)?;
    if current.len() != expected.len() {
        return Ok(false);
    }
    for (current, expected) in current.iter().zip(&expected) {
        let mut current = AddressMessage::parse(&AddressMessageBuffer::new_checked(current)?)?;
        let expected = AddressMessage::parse(&AddressMessageBuffer::new_checked(expected)?)?;
        for (current, expected) in current.attributes.iter_mut().zip(&expected.attributes) {
            if let (AddressAttribute::CacheInfo(current), AddressAttribute::CacheInfo(expected)) =
                (current, expected)
            {
                for (current, expected) in [
                    (&mut current.ifa_valid, expected.ifa_valid),
                    (&mut current.ifa_preferred, expected.ifa_preferred),
                ] {
                    // Netlink lifetimes and capture times have independent one-second rounding.
                    if *current > 0
                        && *current < u32::MAX
                        && expected > 0
                        && expected < u32::MAX
                        && current.abs_diff(expected) <= 1
                    {
                        *current = expected;
                    }
                }
            }
        }
        if current != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn check_interface_snapshot(
    current: &EthernetSnapshot,
    expected: &EthernetSnapshot,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for (field, unchanged) in [
        ("name", current.name == expected.name),
        ("kind", current.kind == expected.kind),
        (
            "index",
            current.boot != expected.boot || current.index == expected.index,
        ),
        ("mac", current.mac == expected.mac),
        ("mtu", current.mtu == expected.mtu),
        ("up", current.up == expected.up),
        (
            "addresses",
            interface_addresses_match(current, expected, now)?,
        ),
    ] {
        crate::ensure_unchanged(
            unchanged,
            format!("interface {} changed {field}", expected.name),
        )?;
    }
    Ok(())
}

pub(super) async fn restore_interfaces(
    handle: &Handle,
    snapshots: &BTreeMap<String, EthernetSnapshot>,
) -> Result<()> {
    restore_ethernet(handle, snapshots).await?;
    let names = snapshots.keys().cloned().collect();
    let current = capture_interfaces(handle, &names).await?;
    for (name, expected) in snapshots {
        check_interface_snapshot(&current[name], expected)?;
    }
    Ok(())
}

fn validate_vlan_address(message: &AddressMessage, name: &str) -> Result<()> {
    let ipv4 = message.header.family == AddressFamily::Inet;
    ensure!(
        message
            .header
            .flags
            .iter()
            .all(|flag| *flag == AddressHeaderFlag::Permanent
                || (ipv4 && *flag == AddressHeaderFlag::Secondary)),
        "unsupported VLAN address flags"
    );
    for attribute in &message.attributes {
        let supported = match attribute {
            AddressAttribute::Address(_)
            | AddressAttribute::Local(_)
            | AddressAttribute::CacheInfo(_) => true,
            AddressAttribute::Label(label) => label == name,
            AddressAttribute::Flags(flags) => flags.iter().all(|flag| {
                *flag == AddressFlag::Permanent || (ipv4 && *flag == AddressFlag::Secondary)
            }),
            AddressAttribute::Broadcast(broadcast) => {
                message.attributes.iter().any(|attribute| match attribute {
                    AddressAttribute::Local(IpAddr::V4(address))
                    | AddressAttribute::Address(IpAddr::V4(address)) => {
                        ipnet::Ipv4Net::new(*address, message.header.prefix_len)
                            .is_ok_and(|network| network.broadcast() == *broadcast)
                    }
                    _ => false,
                })
            }
            _ => false,
        };
        ensure!(supported, "unsupported VLAN address attribute");
    }
    Ok(())
}

fn validate_adoptable_vlan(
    link: &LinkMessage,
    parent_link: &LinkMessage,
    request: &netcontrol_core::AdoptVlanRequest,
) -> Result<()> {
    ensure!(
        name(link) == request.name && name(parent_link) == request.parent,
        "VLAN name mismatch"
    );
    ensure!(
        ethernet_kind(&kind(parent_link)),
        "stacked/non-Ethernet VLAN parent is unsupported"
    );
    for device in [link, parent_link] {
        ensure!(
            !device
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, LinkAttribute::Controller(_))),
            "mastered VLAN or parent cannot be adopted"
        );
    }
    ensure!(
        vlan(link)? == Some((parent_link.header.index, request.id)),
        "VLAN parent/ID mismatch"
    );
    ensure!(
        link.header.flags.iter().all(|flag| matches!(
            flag,
            LinkFlag::Up
                | LinkFlag::Broadcast
                | LinkFlag::Running
                | LinkFlag::Multicast
                | LinkFlag::LowerUp
                | LinkFlag::Dormant
        )),
        "unsupported VLAN link flags"
    );
    for attribute in &link.attributes {
        if let LinkAttribute::LinkInfo(info) = attribute {
            for entry in info {
                match entry {
                    LinkInfo::Kind(_) => {}
                    LinkInfo::Data(InfoData::Vlan(attributes)) => {
                        ensure!(
                            attributes.iter().all(|attribute| !matches!(attribute,
                            InfoVlan::Flags((flags, _)) if *flags != 1)),
                            "nondefault VLAN flags cannot be adopted"
                        );
                    }
                    _ => bail!("unsupported VLAN link identity"),
                }
            }
        }
    }
    ensure!(
        parent(link).mac.len() == 17 && parent(parent_link).mac.len() == 17,
        "VLAN/parent Ethernet identity missing"
    );
    Ok(())
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
            if address.header.scope == AddressScope::Link {
                continue;
            }
            let captured = original.iter().find(|old| same_address(old, &address));
            if captured.is_some_and(|old| !same_prefix_route_flag(old, &address)) {
                ensure!(
                    !snapshot.up,
                    "cannot safely restore prefix-route flags on up Ethernet {}",
                    snapshot.name
                );
            }
            if captured.is_none_or(|old| !same_prefix_route_flag(old, &address)) {
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

fn same_prefix_route_flag(a: &AddressMessage, b: &AddressMessage) -> bool {
    let has_no_prefix_route = |address: &AddressMessage| {
        address.attributes.iter().any(|attribute| {
            matches!(attribute, AddressAttribute::Flags(flags) if flags.contains(&AddressFlag::Noprefixroute))
        })
    };
    has_no_prefix_route(a) == has_no_prefix_route(b)
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

pub(super) fn vlan(link: &LinkMessage) -> Result<Option<(u32, u16)>> {
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
    check_policy_rules(handle, false).await
}

pub(super) async fn check_vlan_policy_rules(handle: &Handle) -> Result<()> {
    check_policy_rules(handle, true).await
}

async fn check_policy_rules(handle: &Handle, allow_managed: bool) -> Result<()> {
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
            if allow_managed && (10000..=19999).contains(&priority) {
                continue;
            }
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
    decode_owned_route(message, names, None)
}

fn blackhole_type(action: &str) -> Result<RouteType> {
    match action {
        "blackhole" => Ok(RouteType::BlackHole),
        "unreachable" => Ok(RouteType::Unreachable),
        "prohibit" => Ok(RouteType::Prohibit),
        _ => bail!("unsupported blackhole action"),
    }
}

fn blackhole_action(kind: &RouteType) -> Option<&'static str> {
    match kind {
        RouteType::BlackHole => Some("blackhole"),
        RouteType::Unreachable => Some("unreachable"),
        RouteType::Prohibit => Some("prohibit"),
        _ => None,
    }
}

/// `blackhole` is `Some` only for owned routes, where deviceless kernel route types map to its name.
pub(super) fn decode_owned_route(
    message: &RouteMessage,
    names: &BTreeMap<u32, String>,
    blackhole: Option<&netcontrol_core::BlackholeConfig>,
) -> Result<Route> {
    let action = blackhole.and_then(|_| blackhole_action(&message.header.kind));
    // On our routes, Linkdown reflects live interface state rather than configuration.
    ensure!(
        (message.header.kind == RouteType::Unicast || action.is_some())
            && message.header.source_prefix_length == 0
            && message.header.tos == 0
            && message
                .header
                .flags
                .iter()
                .all(|flag| *flag == netlink_packet_route::route::RouteFlag::Linkdown)
            && (message.header.flags.is_empty()
                || matches!(
                    message.header.protocol,
                    RouteProtocol::Other(PROTOCOL)
                        | RouteProtocol::Other(super::dhcp_client::PROTOCOL)
                )),
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
    let scope = if action.is_some() {
        RouteScope::Universe
    } else if destination.is_ipv4() && gateway.is_empty() {
        RouteScope::Link
    } else {
        RouteScope::Universe
    };
    ensure!(message.header.scope == scope, "owned route scope changed");
    let interface = match action {
        // IPv6 kernel blackhole routes report the loopback device; IPv4 ones report none.
        Some(action) => {
            ensure!(
                gateway.is_empty() && interface.as_deref().is_none_or(|name| name == "lo"),
                "unsupported owned blackhole route"
            );
            blackhole
                .filter(|config| config.configured() && config.action == action)
                .map(|config| config.name.clone())
                .unwrap_or_else(|| format!("blackhole:{action}"))
        }
        None => interface.context("owned route interface missing")?,
    };
    Ok(Route {
        destination: format!("{destination}/{}", message.header.destination_prefix_length),
        gateway,
        interface,
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
pub async fn boot_snapshot(
    handle: &Handle,
    expected: &Network,
    keys: &super::wireguard::Control,
) -> Result<Value> {
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
            keys.verify(&desired.name, wg)
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
        .map(|r| decode_owned_route(r, &names, Some(&expected.blackhole)))
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
    value["ipv6_enabled"] = serde_json::json!(expected.ipv6_enabled);
    value["interfaces"] = serde_json::to_value(actual)?;
    value["routes"] = serde_json::to_value(routes)?;
    value["blackhole"] = serde_json::to_value(&expected.blackhole)?;
    value["_monitor_policy_rules"] = serde_json::to_value(rules)?;
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
pub(super) fn decode_rule(message: &RuleMessage) -> Result<Rule> {
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
    keys: &super::wireguard::Control,
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
            keys.verify(&desired.name, wg)?;
        }
    }
    let mut routes = owned_routes(handle)
        .await?
        .iter()
        .map(|v| decode_owned_route(v, &by_index, Some(&network.blackhole)))
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
    keys: &super::wireguard::Control,
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
    for message in owned_routes(handle).await? {
        let route = decode_owned_route(&message, &by_index, Some(&after.blackhole))?;
        if !after.routes.contains(&route) {
            handle
                .route()
                .del(message)
                .execute()
                .await
                .with_context(|| {
                    format!(
                        "remove managed route {} on {}",
                        route.destination, route.interface
                    )
                })?;
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
        handle
            .link()
            .set(index)
            .mtu(desired.mtu)
            .execute()
            .await
            .with_context(|| format!("set MTU on {}", desired.name))?;
        let request = handle.link().set(index);
        if desired.up {
            request
                .up()
                .execute()
                .await
                .with_context(|| format!("bring interface {} up", desired.name))?;
        } else {
            request
                .down()
                .execute()
                .await
                .with_context(|| format!("bring interface {} down", desired.name))?;
        }
        for address in addresses(handle, index).await? {
            if let Some(prefix) = address_string(&address)? {
                if !desired.addresses.contains(&prefix) {
                    handle
                        .address()
                        .del(address)
                        .execute()
                        .await
                        .with_context(|| {
                            format!("remove address {prefix} from {}", desired.name)
                        })?;
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
            request
                .execute()
                .await
                .with_context(|| format!("configure address {prefix} on {}", desired.name))?;
        }
        if let Some(wg) = &desired.wireguard {
            let changed = before
                .interfaces
                .iter()
                .find(|link| link.name == desired.name)
                .and_then(|link| link.wireguard.as_ref())
                != Some(wg);
            if changed || keys.verify(&desired.name, wg).is_err() {
                keys.apply(&desired.name, wg, after.ipv6_enabled)?;
            }
        }
    }
    available = links(handle).await?;
    let by_index = available
        .iter()
        .map(|link| (link.header.index, name(link)))
        .collect();
    // Address removal can invalidate routes that were present before reconciliation.
    let present_routes = owned_routes(handle)
        .await?
        .iter()
        .map(|message| decode_owned_route(message, &by_index, Some(&after.blackhole)))
        .collect::<Result<BTreeSet<_>>>()?;
    for route in &after.routes {
        if present_routes.contains(route) {
            continue;
        }
        install_route(handle, route, &available, &after.blackhole)
            .await
            .with_context(|| {
                format!(
                    "install managed route {} on {}",
                    route.destination, route.interface
                )
            })?;
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

async fn install_route(
    handle: &Handle,
    route: &Route,
    available: &[LinkMessage],
    blackhole: &netcontrol_core::BlackholeConfig,
) -> Result<()> {
    let (destination, length) = parse_prefix(&route.destination, true)?;
    let drop = blackhole.targets(&route.interface);
    let scope = if drop || !destination.is_ipv4() || !route.gateway.is_empty() {
        RouteScope::Universe
    } else {
        RouteScope::Link
    };
    let mut request = handle
        .route()
        .add()
        .table_id(route.table)
        .priority(route.metric)
        .protocol(RouteProtocol::Other(PROTOCOL))
        .scope(scope);
    request = if drop {
        request.kind(blackhole_type(&blackhole.action)?)
    } else {
        let index = available
            .iter()
            .find(|link| name(link) == route.interface)
            .context("route interface unavailable")?
            .header
            .index;
        request.output_interface(index)
    };
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
    Ok(())
}

async fn dhcp_static_routes(
    handle: &Handle,
    interface: &str,
    previous: &[Route],
    next: &[Route],
    install: bool,
) -> Result<()> {
    let available = links(handle).await?;
    let names = available
        .iter()
        .map(|link| (link.header.index, name(link)))
        .collect();
    let messages: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_collect()
        .await?;
    let mut missing = Vec::new();
    let mut remove = Vec::new();
    for route in previous.iter().chain(next) {
        ensure!(
            route.interface == interface,
            "DHCP static route interface mismatch"
        );
        let key = (route.table, route.metric, route.destination.clone());
        let mut found = false;
        for message in &messages {
            if route_key(message)? != key {
                continue;
            }
            crate::ensure_unchanged(
                message.header.protocol == RouteProtocol::Other(PROTOCOL) && {
                    let observed = decode_route(message, &names)?;
                    previous.contains(&observed) || next.contains(&observed)
                },
                format!(
                    "DHCP static route {} conflicts with existing route",
                    route.destination
                ),
            )?;
            let observed = decode_route(message, &names)?;
            found |= observed == *route;
            if !next.contains(&observed) && !remove.contains(message) {
                remove.push(message.clone());
            }
        }
        if install && !found && next.contains(route) && !missing.contains(&route) {
            missing.push(route);
        }
    }
    for message in remove {
        handle.route().del(message).execute().await?;
    }
    missing.sort_by_key(|route| !route.gateway.is_empty());
    for route in missing {
        install_route(handle, route, &available, &Default::default())
            .await
            .with_context(|| {
                format!("restore DHCP-dependent static route {}", route.destination)
            })?;
    }
    let observed: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V4)
        .execute()
        .try_collect()
        .await?;
    for route in previous.iter().chain(next) {
        let key = (route.table, route.metric, route.destination.clone());
        let mut matches = 0;
        for message in &observed {
            if route_key(message)? == key {
                ensure!(
                    message.header.protocol == RouteProtocol::Other(PROTOCOL)
                        && next.contains(&decode_route(message, &names)?),
                    "DHCP-dependent static route {} did not converge",
                    route.destination
                );
                matches += 1;
            }
        }
        ensure!(
            !install
                || matches
                    == usize::from(next.iter().any(|wanted| {
                        wanted.table == route.table
                            && wanted.metric == route.metric
                            && wanted.destination == route.destination
                    })),
            "DHCP-dependent static route {} did not converge",
            route.destination
        );
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
    let previous_static = super::dhcp_client::lease_routes(name, &addressing.routes, previous)?;
    let next_static = super::dhcp_client::lease_routes(name, &addressing.routes, next)?;
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
    // Validate ownership and remove obsolete next hops before changing lease addresses/routes.
    dhcp_static_routes(handle, name, &previous_static, &next_static, false).await?;
    let mtu = next.and_then(|lease| lease.mtu).unwrap_or(addressing.mtu);
    if mtu != 0 {
        handle
            .link()
            .set(index)
            .mtu(mtu)
            .execute()
            .await
            .with_context(|| format!("set DHCP MTU on {name}"))?;
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
            handle
                .route()
                .del(message)
                .execute()
                .await
                .with_context(|| format!("remove DHCP route {} on {name}", observed.destination))?;
        }
    }
    if let Some(previous) = previous {
        if next.is_none_or(|lease| lease.address != previous.address) {
            for address in addresses(handle, index).await? {
                if address_string(&address)?.as_deref() == Some(previous.address.as_str()) {
                    handle
                        .address()
                        .del(address)
                        .execute()
                        .await
                        .with_context(|| {
                            format!("remove DHCP address {} from {name}", previous.address)
                        })?;
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
        request
            .execute()
            .await
            .with_context(|| format!("configure DHCP address {} on {name}", lease.address))?;
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
            request
                .execute()
                .await
                .with_context(|| format!("install DHCP route {} on {name}", route.destination))?;
        }
        dhcp_static_routes(handle, name, &previous_static, &next_static, true).await?;
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
