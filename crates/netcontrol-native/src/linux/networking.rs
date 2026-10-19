use crate::model::{Network, PROTOCOL, Route, Rule, parse_prefix};
use anyhow::{Context, Result, bail, ensure};
use futures_util::TryStreamExt;
use netlink_packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressFlag, AddressHeaderFlag, AddressMessage, AddressScope},
    link::{InfoData, InfoVlan, LinkAttribute, LinkFlag, LinkInfo, LinkMessage, VlanProtocol},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use rtnetlink::{Handle, IpVersion};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Parent {
    pub name: String,
    pub kind: String,
    pub index: u32,
    pub mac: String,
    pub mtu: u32,
    pub up: bool,
}

async fn links(handle: &Handle) -> Result<Vec<LinkMessage>> {
    Ok(handle.link().get().execute().try_collect().await?)
}
fn name(link: &LinkMessage) -> String {
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
fn parent(link: &LinkMessage) -> Parent {
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

async fn addresses(handle: &Handle, index: u32) -> Result<Vec<AddressMessage>> {
    Ok(handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await?)
}
fn address_string(address: &AddressMessage) -> Result<Option<String>> {
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
            if (10000..=19999).contains(&table) {
                crate::ensure_unchanged(
                    message.header.protocol == RouteProtocol::Other(PROTOCOL),
                    "foreign route in reserved managed table",
                )?;
                owned.push(message);
            }
        }
    }
    Ok(owned)
}
fn decode_route(message: &RouteMessage, names: &BTreeMap<u32, String>) -> Result<Route> {
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
    let scope = if gateway.is_empty() {
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
        (10000..=19999).contains(&table),
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
    let wanted: BTreeSet<_> = network.interfaces.iter().map(|v| v.name.clone()).collect();
    for link in &available {
        let name = name(link);
        crate::ensure_unchanged(
            name == "lo" || parents.contains_key(&name) || wanted.contains(&name),
            format!("unexpected unmanaged interface {name} in isolated namespace"),
        )?;
    }
    for desired in &network.interfaces {
        let actual = by_name.get(&desired.name).ok_or_else(|| {
            netcontrol_core::BackendDrift(format!("managed interface {} missing", desired.name))
        })?;
        crate::ensure_unchanged(
            kind(actual) == desired.kind
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
) -> Result<()> {
    check_parents(handle, parents).await?;
    let allowed: BTreeSet<_> = before
        .interfaces
        .iter()
        .chain(&after.interfaces)
        .map(|l| l.name.clone())
        .collect();
    let mut available = links(handle).await?;
    for link in &available {
        let name = name(link);
        ensure!(
            name == "lo" || parents.contains_key(&name) || allowed.contains(&name),
            "refusing unexpected interface {name} during reconcile/recovery"
        );
    }
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
        let route = decode_route(&message, &by_index)?;
        if !after.routes.contains(&route) {
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
        let replace = match wanted.get(&name) {
            None => true,
            Some(wanted) if kind(link) != wanted.kind => true,
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
            if allowed.contains(&name(link))
                && link
                    .attributes
                    .iter()
                    .any(|a| matches!(a, LinkAttribute::Link(v) if remove.contains(v)))
            {
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
        let mut current = BTreeSet::new();
        for address in addresses(handle, index).await? {
            if let Some(prefix) = address_string(&address)? {
                if !desired.addresses.contains(&prefix) {
                    handle.address().del(address).execute().await?;
                } else {
                    current.insert(prefix);
                }
            }
        }
        for prefix in &desired.addresses {
            if current.contains(prefix) {
                continue;
            }
            let (ip, len) = parse_prefix(prefix, false)?;
            let mut request = handle.address().add(index, ip, len);
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
        let request = handle.link().set(index);
        if desired.up {
            request.up().execute().await?;
        } else {
            request.down().execute().await?;
        }
    }
    available = links(handle).await?;
    for route in &after.routes {
        let index = available
            .iter()
            .find(|l| name(l) == route.interface)
            .context("route interface unavailable")?
            .header
            .index;
        let (destination, length) = parse_prefix(&route.destination, true)?;
        let scope = if route.gateway.is_empty() {
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
            .scope(scope)
            .replace();
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
