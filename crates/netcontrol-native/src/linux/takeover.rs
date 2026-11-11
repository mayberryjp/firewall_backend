use super::{adoption, ipv6, netfilter, networking};
use crate::model::{Network, PROTOCOL};
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use netcontrol_core::{Config, DHCPClientConfig, DNSConfig, Interface};
use netlink_packet_core::Emitable;
use netlink_packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressScope},
    link::{LinkAttribute, LinkMessage, LinkXdp},
    route::{RouteMessage, RouteProtocol},
    rule::{RuleAction, RuleAttribute, RuleMessage},
    tc::{TcAttribute, TcHandle},
};
use rtnetlink::{Handle, IpVersion};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Item {
    pub resource: String,
    pub disposition: String,
    pub reason: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub phase: String,
    pub error: String,
    pub items: Vec<Item>,
    pub units: Vec<String>,
    pub route_snapshot: Vec<Vec<u8>>,
    pub rule_snapshot: Vec<Vec<u8>>,
    pub qdisc_snapshot: Vec<Vec<u8>>,
    pub firewall_snapshot: Vec<Vec<u8>>,
    pub legacy_snapshot: Vec<super::takeover_legacy::Table>,
}

impl Plan {
    fn new() -> Self {
        Self {
            phase: "captured".into(),
            error: String::new(),
            items: vec![],
            units: vec![],
            route_snapshot: vec![],
            rule_snapshot: vec![],
            qdisc_snapshot: vec![],
            firewall_snapshot: vec![],
            legacy_snapshot: vec![],
        }
    }

    pub(super) fn item(
        &mut self,
        resource: impl Into<String>,
        disposition: &str,
        reason: impl Into<String>,
    ) {
        self.items.push(Item {
            resource: resource.into(),
            disposition: disposition.into(),
            reason: reason.into(),
        });
    }

    pub(super) fn report(&self) -> Value {
        json!({"mode":"console","phase":self.phase,"error":self.error,"items":self.items,
            "connectivity_confirmation_required":false})
    }
}

fn raw(message: &impl Emitable) -> Vec<u8> {
    let mut bytes = vec![0; message.buffer_len()];
    message.emit(&mut bytes);
    bytes
}

fn candidate_kind(
    link: &LinkMessage,
    names: &BTreeMap<u32, String>,
) -> Result<Option<(String, Option<netcontrol_core::VLAN>)>> {
    let parent = networking::parent(link);
    if parent.name == "lo" || parent.mac.len() != 17 {
        return Ok(None);
    }
    match parent.kind.as_str() {
        "device" | "veth" => Ok(Some(("ethernet".into(), None))),
        "dummy" => Ok(Some(("dummy".into(), None))),
        "vlan" => {
            let Some((index, id)) = networking::vlan(link)? else {
                return Ok(None);
            };
            Ok(names.get(&index).map(|name| {
                (
                    "vlan".into(),
                    Some(netcontrol_core::VLAN {
                        parent: name.clone(),
                        id: i64::from(id),
                    }),
                )
            }))
        }
        _ => Ok(None),
    }
}

pub(super) async fn capture(
    handle: &Handle,
    scope: String,
    ownership_before: Value,
    readonly: BTreeSet<String>,
) -> Result<adoption::Receipt> {
    let (mut receipt, mut plan) = capture_kernel(handle, scope, ownership_before, readonly).await?;
    import_network_manager(&mut receipt.config, &mut plan)?;
    receipt.config = receipt.config.normalized();
    receipt.config.validate()?;
    for (pid, name) in super::takeover_processes::capture()? {
        plan.item(
            format!("process:{pid}:{name}"),
            "disabled",
            "competing process in this network namespace; terminate by pinned process identity",
        );
    }
    plan.units = competing_units()?;
    for unit in plan.units.clone() {
        plan.item(
            format!("service:{unit}"),
            "disabled",
            "competing host networking or unsupported appliance service; persistently masked",
        );
    }
    receipt.takeover = Some(plan);
    Ok(receipt)
}

pub(super) async fn capture_kernel(
    handle: &Handle,
    scope: String,
    ownership_before: Value,
    readonly: BTreeSet<String>,
) -> Result<(adoption::Receipt, Plan)> {
    let mut plan = Plan::new();
    let available = networking::links(handle).await?;
    let protected_indices: BTreeSet<_> = available
        .iter()
        .filter(|link| readonly.contains(&networking::name(link)))
        .map(|link| link.header.index)
        .collect();
    let mut names = BTreeMap::new();
    let mut chosen = BTreeMap::new();
    for link in &available {
        let parent = networking::parent(link);
        if readonly.contains(&parent.name) {
            continue;
        }
        if has_xdp(link) {
            plan.item(
                format!("xdp:{}", parent.name),
                "disabled",
                "unmanaged XDP programs are detached",
            );
        }
        for (hook, program, link_id) in super::takeover_bpf::capture(parent.index)? {
            plan.item(
                format!("tcx:{}:{hook}:{program}:{link_id}", parent.name),
                "disabled",
                "unmanaged TCX program is detached",
            );
        }
        if !readonly.contains(&parent.name)
            && matches!(parent.kind.as_str(), "device" | "veth")
            && parent.mac.len() == 17
        {
            names.insert(parent.index, parent.name.clone());
            chosen.insert(parent.name.clone(), ("ethernet".into(), None));
        }
    }
    loop {
        let count = chosen.len();
        for link in &available {
            let parent = networking::parent(link);
            if readonly.contains(&parent.name) || chosen.contains_key(&parent.name) {
                continue;
            }
            let candidate = match candidate_kind(link, &names) {
                Ok(candidate) => candidate,
                Err(error) => {
                    plan.item(
                        format!("interface:{}", parent.name),
                        "disabled",
                        format!("{error:#}"),
                    );
                    None
                }
            };
            if let Some(kind) = candidate {
                names.insert(parent.index, parent.name.clone());
                chosen.insert(parent.name, kind);
            }
        }
        if chosen.len() == count {
            break;
        }
    }
    let mut config = Config::empty();
    for link in &available {
        let parent = networking::parent(link);
        if parent.kind == "loopback" || readonly.contains(&parent.name) {
            continue;
        }
        let Some((kind, vlan)) = chosen.get(&parent.name) else {
            plan.item(
                format!("interface:{}", parent.name),
                "disabled",
                format!(
                    "unsupported or unimportable {} topology; link down and detached",
                    parent.kind
                ),
            );
            continue;
        };
        let messages = networking::addresses(handle, parent.index).await?;
        let mut addresses = Vec::new();
        let mut dhcp = false;
        for message in messages {
            if message.header.family == AddressFamily::Inet6 {
                plan.item(
                    format!("address:{}:ipv6", parent.name),
                    "disabled",
                    "IPv6 is disabled",
                );
                continue;
            }
            if message.header.scope == AddressScope::Link {
                continue;
            }
            let finite = message.attributes.iter().any(
                |a| matches!(a, AddressAttribute::CacheInfo(info) if info.ifa_valid != u32::MAX),
            );
            if finite {
                dhcp = true;
                plan.item(
                    format!("dhcp:{}", parent.name),
                    "imported",
                    "finite IPv4 address becomes an in-process DHCPv4 client, never a static lease",
                );
                continue;
            }
            match networking::address_string(&message) {
                Ok(Some(address)) => addresses.push(address),
                Ok(None) => {}
                Err(error) => plan.item(
                    format!("address:{}", parent.name),
                    "disabled",
                    format!("{error:#}"),
                ),
            }
        }
        let state_path = format!("/run/systemd/netif/links/{}", parent.index);
        let mut client = DHCPClientConfig::default();
        if Path::new(&state_path).try_exists()? {
            let state = adoption::fields(Path::new(&state_path))?;
            if let Some(path) = state
                .get("default", "NETWORK_FILE")
                .filter(|p| !p.is_empty())
            {
                match adoption::settings(Path::new(&path)) {
                    Ok(settings) => {
                        if let Some(mode) = settings.get("Network", "DHCP") {
                            dhcp |= matches!(mode.as_str(), "yes" | "true" | "both" | "ipv4");
                        }
                        if let Some(metric) = adoption::dhcp_setting(&settings, "RouteMetric") {
                            match metric.parse::<u32>() {
                                Ok(metric) => client.route_metric = metric,
                                Err(error) => plan.item(
                                    format!("dhcp:{}:metric", parent.name),
                                    "disabled",
                                    error.to_string(),
                                ),
                            }
                        }
                        client.hostname =
                            adoption::dhcp_setting(&settings, "Hostname").unwrap_or_default();
                        client.use_mtu = adoption::dhcp_setting(&settings, "UseMTU")
                            .is_some_and(|s| matches!(s.as_str(), "yes" | "true"));
                        if let Some(domains) = adoption::dhcp_setting(&settings, "UseDomains") {
                            client.use_domains = match domains.as_str() {
                                "yes" | "true" => "yes",
                                "route" => "route",
                                _ => "no",
                            }
                            .into();
                        }
                        let lease_path = format!("/run/systemd/netif/leases/{}", parent.index);
                        if Path::new(&lease_path).try_exists()? {
                            let lease = adoption::fields(Path::new(&lease_path))?;
                            if let Some(identifier) = lease.get("default", "CLIENTID") {
                                let identifier = identifier.replace(':', "");
                                match hex::decode(&identifier) {
                                    Ok(bytes) if (2..=255).contains(&bytes.len()) => client.client_id=identifier,
                                    _ => plan.item(format!("dhcp:{}:client-id",parent.name),"disabled","unrepresentable DHCP client identifier; native MAC identity selected"),
                                }
                            }
                        }
                        let dns = DNSConfig {
                            servers: settings
                                .get("Network", "DNS")
                                .unwrap_or_default()
                                .split_whitespace()
                                .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
                                .map(|ip| ip.to_string())
                                .collect(),
                            override_dhcp_dns: false,
                            ..Default::default()
                        };
                        if !dns.servers.is_empty() {
                            config.dns.insert(parent.name.clone(), dns);
                        }
                        plan.item(format!("networkd:{}", parent.name), "disabled", "only representable IPv4/DHCP/DNS settings are imported; other manager settings no longer run");
                    }
                    Err(error) => plan.item(
                        format!("networkd:{}", parent.name),
                        "disabled",
                        format!("unrepresentable manager configuration: {error:#}"),
                    ),
                }
            }
        }
        if dhcp && addresses.is_empty() && kind == "ethernet" {
            config.dhcp_clients.insert(parent.name.clone(), client);
        } else if dhcp {
            plan.item(
                format!("dhcp:{}", parent.name),
                "disabled",
                "DHCP cannot coexist with imported static IPv4 or run on this interface kind",
            );
        }
        plan.item(
            format!("interface:{}", parent.name),
            "imported",
            format!("owned {kind}; preserve MTU, administrative state and supported static IPv4"),
        );
        config.interfaces.push(Interface {
            name: parent.name,
            kind: kind.clone(),
            vlan: vlan.clone(),
            role: "unassigned".into(),
            mtu: i64::from(parent.mtu),
            up: parent.up,
            addresses,
            metadata: Default::default(),
            dhcp_relay: Default::default(),
            wireguard: None,
        });
    }
    for version in [IpVersion::V4, IpVersion::V6] {
        let routes: Vec<RouteMessage> = handle
            .route()
            .get(networking::route_query(version.clone()))
            .execute()
            .try_collect()
            .await?;
        for message in routes {
            plan.route_snapshot.push(raw(&message));
            if message.header.protocol == RouteProtocol::Kernel {
                continue;
            }
            let imported = if version == IpVersion::V4
                && matches!(
                    message.header.protocol,
                    RouteProtocol::Static | RouteProtocol::Boot
                ) {
                networking::decode_route(&message, &names).and_then(|route| {
                    let mut value = serde_json::to_value(route)?;
                    value["enabled"] = json!(true);
                    let route: netcontrol_core::Route = serde_json::from_value(value)?;
                    let mut candidate = config.clone();
                    candidate.routes.push(route.clone());
                    candidate.validate()?;
                    Ok(route)
                })
            } else {
                Err(anyhow::anyhow!(
                    "unsupported route family/protocol or dynamic route must be relearned by its DHCP client"
                ))
            };
            match imported {
                Ok(route) => {
                    plan.item(
                        format!("route:{}:{}", route.interface, route.destination),
                        "imported",
                        "owned static route",
                    );
                    config.routes.push(route);
                }
                Err(error) => plan.item(
                    format!("route:{}", hex::encode(raw(&message))),
                    "disabled",
                    format!("{error:#}"),
                ),
            }
        }
        let rules: Vec<RuleMessage> = handle.rule().get(version).execute().try_collect().await?;
        for rule in rules {
            plan.rule_snapshot.push(raw(&rule));
            if !standard_rule(&rule) {
                plan.item(
                    format!("policy-rule:{}", hex::encode(raw(&rule))),
                    "disabled",
                    "custom source/policy routing is not configurable",
                );
            }
        }
    }
    for qdisc in handle
        .qdisc()
        .get()
        .execute()
        .try_collect::<Vec<_>>()
        .await?
    {
        plan.qdisc_snapshot.push(raw(&qdisc));
        if custom_qdisc(&qdisc)
            && !u32::try_from(qdisc.header.index)
                .is_ok_and(|index| protected_indices.contains(&index))
        {
            plan.item(
                format!(
                    "traffic-control:{}:{:?}",
                    qdisc.header.index, qdisc.header.handle
                ),
                "disabled",
                "traffic shaping/filtering is unsupported",
            );
        }
    }
    plan.firewall_snapshot = netfilter::host_firewall_snapshot()?;
    plan.legacy_snapshot = super::takeover_legacy::capture()?;
    for table in plan.legacy_snapshot.clone() {
        plan.item(format!("legacy-firewall:{}:{}",table.family,table.name),"disabled","legacy xtables traversal/extensions are unsupported; clear rules and set built-in policies to ACCEPT");
    }
    super::takeover_firewall::import(&plan.firewall_snapshot.clone(), &mut config, &mut plan)?;
    plan.item(
        "ipv6",
        "disabled",
        "all/default/per-interface controls; DHCPv6/SLAAC and IPv6 routes disabled",
    );
    config = config.normalized();
    config
        .validate()
        .context("validate imported host configuration")?;
    let names = config
        .interfaces
        .iter()
        .map(|link| link.name.clone())
        .collect();
    let originals = networking::capture_interfaces(handle, &names).await?;
    let receipt = adoption::Receipt::host(
        scope,
        config,
        originals,
        ownership_before,
        ipv6::capture(handle).await?,
        plan.clone(),
    );
    Ok((receipt, plan))
}

pub(super) fn standard_rule(rule: &RuleMessage) -> bool {
    let priority = rule
        .attributes
        .iter()
        .find_map(|a| {
            if let RuleAttribute::Priority(v) = a {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap_or(0);
    let table = rule
        .attributes
        .iter()
        .find_map(|a| {
            if let RuleAttribute::Table(v) = a {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap_or(u32::from(rule.header.table));
    matches!((priority, table), (0, 255) | (32766, 254) | (32767, 253))
        && rule.header.src_len == 0
        && rule.header.dst_len == 0
        && rule.header.tos == 0
        && rule.header.action == RuleAction::ToTable
        && rule.header.flags.is_empty()
        && rule.attributes.iter().all(|a| match a {
            RuleAttribute::Priority(_) | RuleAttribute::Table(_) | RuleAttribute::Protocol(_) => {
                true
            }
            RuleAttribute::SuppressPrefixLen(v) | RuleAttribute::SuppressIfGroup(v) => {
                *v == u32::MAX
            }
            _ => false,
        })
}

fn import_network_manager(config: &mut Config, plan: &mut Plan) -> Result<()> {
    let names: BTreeSet<_> = config
        .interfaces
        .iter()
        .map(|link| link.name.clone())
        .collect();
    let sources = adoption::bus(move |connection| {
        let bus = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )?;
        let active: bool = bus.call("NameHasOwner", &("org.freedesktop.NetworkManager",))?;
        if !active {
            return Ok(Vec::new());
        }
        let manager = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )?;
        let devices: Vec<zbus::zvariant::OwnedObjectPath> = manager.call("GetDevices", &())?;
        let mut sources = Vec::new();
        for path in devices {
            let device = zbus::blocking::Proxy::new(
                &connection,
                "org.freedesktop.NetworkManager",
                path,
                "org.freedesktop.NetworkManager.Device",
            )?;
            let name: String = device.get_property("Interface")?;
            if !names.contains(&name) {
                continue;
            }
            type Settings = BTreeMap<String, BTreeMap<String, zbus::zvariant::OwnedValue>>;
            let applied: Result<(Settings, u64), zbus::Error> =
                device.call("GetAppliedConnection", &(0u32,));
            let source = (|| -> Result<(String, Vec<String>, Option<u32>)> {
                let (settings, _) = applied?;
                let ipv4 = settings
                    .get("ipv4")
                    .context("NetworkManager IPv4 settings missing")?;
                let method = ipv4
                    .get("method")
                    .context("NetworkManager IPv4 method missing")?
                    .downcast_ref::<&str>()?
                    .to_owned();
                let dns = ipv4
                    .get("dns-data")
                    .map(|value| -> Result<Vec<String>> {
                        Ok(Vec::<String>::try_from(value.try_clone()?)?)
                    })
                    .transpose()?
                    .unwrap_or_default();
                let metric = ipv4
                    .get("route-metric")
                    .map(|value| -> Result<Option<u32>> {
                        let metric = i64::try_from(value.try_clone()?)?;
                        if metric == -1 {
                            return Ok(None);
                        }
                        Ok(Some(u32::try_from(metric)?))
                    })
                    .transpose()?
                    .flatten();
                Ok((method, dns, metric))
            })();
            sources.push((name, source));
        }
        Ok(sources)
    })?;
    for (name, source) in sources {
        match source {
            Ok((method, dns, metric)) => {
                let link = config
                    .interfaces
                    .iter()
                    .find(|link| link.name == name)
                    .context("NetworkManager interface missing")?;
                if method == "auto" && link.kind == "ethernet" && link.addresses.is_empty() {
                    let client = config.dhcp_clients.entry(name.clone()).or_default();
                    if let Some(metric) = metric {
                        client.route_metric = metric;
                    }
                    plan.item(
                        format!("networkmanager:{name}:dhcp"),
                        "imported",
                        "in-process DHCPv4 replaces NetworkManager, including unleased clients",
                    );
                } else if method != "manual" && method != "disabled" {
                    plan.item(format!("networkmanager:{name}:ipv4"),"disabled","IPv4 method cannot coexist with imported static configuration or is unsupported");
                }
                for server in dns {
                    match server.parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => config
                            .dns
                            .entry(name.clone())
                            .or_default()
                            .servers
                            .push(ip.to_string()),
                        Err(_) => plan.item(
                            format!("networkmanager:{name}:dns"),
                            "disabled",
                            "IPv6 or invalid DNS server",
                        ),
                    }
                }
                plan.item(
                    format!("networkmanager:{name}"),
                    "disabled",
                    "manager relinquished; only representable IPv4 settings are retained",
                );
            }
            Err(error) => plan.item(
                format!("networkmanager:{name}"),
                "disabled",
                format!("unimportable applied manager settings: {error:#}"),
            ),
        }
    }
    Ok(())
}

fn custom_qdisc(qdisc: &netlink_packet_route::tc::TcMessage) -> bool {
    qdisc.header.handle != TcHandle::UNSPEC
        && qdisc.attributes.iter().any(
            |a| matches!(a, TcAttribute::Kind(kind) if !matches!(kind.as_str(), "noqueue" | "mq")),
        )
}

fn has_xdp(link: &LinkMessage) -> bool {
    link.attributes.iter().any(|attribute|matches!(attribute,LinkAttribute::Xdp(values) if values.iter().any(|value| matches!(value,LinkXdp::ProgId(id)|LinkXdp::DrvProgId(id)|LinkXdp::SkbProgId(id)|LinkXdp::HwProgId(id) if *id!=0))))
}

async fn detach_xdp(handle: &Handle, link: &LinkMessage) -> Result<()> {
    if !has_xdp(link) {
        return Ok(());
    }
    let mut modes = Vec::new();
    for attribute in &link.attributes {
        if let LinkAttribute::Xdp(values) = attribute {
            for value in values {
                match value {
                    LinkXdp::DrvProgId(id) if *id != 0 => modes.push(1 << 2),
                    LinkXdp::SkbProgId(id) if *id != 0 => modes.push(1 << 1),
                    LinkXdp::HwProgId(id) if *id != 0 => modes.push(1 << 3),
                    _ => {}
                }
            }
        }
    }
    if modes.is_empty() {
        modes.push(0);
    }
    for mode in modes {
        let request = handle.link().set(
            rtnetlink::LinkUnspec::new_with_index(link.header.index)
                .append_extra_attribute(LinkAttribute::Xdp(vec![
                    LinkXdp::Fd(-1),
                    LinkXdp::Flags(mode),
                ]))
                .build(),
        );
        request
            .execute()
            .await
            .context("detach unsupported XDP program")?;
    }
    Ok(())
}

pub(super) async fn enforce_kernel(
    handle: &Handle,
    config: &Network,
    preserve_owned_firewall: bool,
    dhcp_routes: &[crate::model::Route],
    readonly: &BTreeSet<String>,
) -> Result<()> {
    let names: BTreeSet<_> = config.interfaces.iter().map(|l| l.name.as_str()).collect();
    let mut protected = BTreeSet::<i32>::new();
    for link in networking::links(handle).await? {
        let name = networking::name(&link);
        if readonly.contains(&name) {
            protected.insert(link.header.index.try_into()?);
            continue;
        }
        super::takeover_bpf::clear(link.header.index)?;
        detach_xdp(handle, &link).await?;
        let name = networking::name(&link);
        if link
            .header
            .flags
            .contains(netlink_packet_route::link::LinkFlags::Loopback)
        {
            continue;
        }
        if link
            .attributes
            .iter()
            .any(|a| matches!(a, LinkAttribute::Controller(_)))
        {
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .nocontroller()
                        .build(),
                )
                .execute()
                .await?;
        }
        if !names.contains(name.as_str()) {
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .down()
                        .build(),
                )
                .execute()
                .await?;
            for address in networking::addresses(handle, link.header.index).await? {
                handle.address().del(address).execute().await?;
            }
        } else {
            let desired = config
                .interfaces
                .iter()
                .find(|interface| interface.name == name)
                .context("managed link missing")?;
            for address in networking::addresses(handle, link.header.index).await? {
                let keep = match networking::address_string(&address)? {
                    Some(value) => desired.addresses.contains(&value),
                    None => {
                        config.ipv6_enabled
                            && address.header.family == AddressFamily::Inet6
                            && address.header.scope == AddressScope::Link
                    }
                };
                if !keep {
                    handle.address().del(address).execute().await?;
                }
            }
        }
    }
    for qdisc in handle
        .qdisc()
        .get()
        .execute()
        .try_collect::<Vec<_>>()
        .await?
    {
        if !protected.contains(&qdisc.header.index)
            && custom_qdisc(&qdisc)
            && matches!(qdisc.header.parent, TcHandle::ROOT | TcHandle::INGRESS)
        {
            let mut request = handle.qdisc().del(qdisc.header.index);
            *request.message_mut() = qdisc;
            request.execute().await?;
        }
    }
    let left = handle
        .qdisc()
        .get()
        .execute()
        .try_collect::<Vec<_>>()
        .await?;
    ensure!(
        !left
            .iter()
            .any(|qdisc| !protected.contains(&qdisc.header.index) && custom_qdisc(qdisc)),
        "unsupported traffic control remains after takeover"
    );
    ensure!(
        !networking::links(handle)
            .await?
            .iter()
            .any(|link| !readonly.contains(&networking::name(link)) && has_xdp(link)),
        "XDP remains after takeover"
    );
    let indices = networking::links(handle)
        .await?
        .iter()
        .map(|link| (link.header.index, networking::name(link)))
        .collect();
    for version in [IpVersion::V4, IpVersion::V6] {
        for rule in handle
            .rule()
            .get(version.clone())
            .execute()
            .try_collect::<Vec<_>>()
            .await?
        {
            let owned = preserve_owned_firewall
                && networking::decode_rule(&rule)
                    .is_ok_and(|rule| config.policy_rules.contains(&rule));
            if !standard_rule(&rule) && !owned {
                handle.rule().del(rule).execute().await?;
            }
        }
        for route in handle
            .route()
            .get(crate::linux::networking::route_query(version))
            .execute()
            .try_collect::<Vec<_>>()
            .await?
        {
            if route.header.protocol == RouteProtocol::Kernel {
                continue;
            }
            if preserve_owned_firewall
                && route.header.protocol == RouteProtocol::Other(PROTOCOL)
                && networking::decode_owned_route(&route, &indices, Some(&config.blackhole))
                    .is_ok_and(|route| config.routes.contains(&route))
            {
                continue;
            }
            if preserve_owned_firewall
                && route.header.protocol == RouteProtocol::Other(super::dhcp_client::PROTOCOL)
            {
                let mut candidate = route.clone();
                let valid_source = candidate
                    .attributes
                    .iter()
                    .all(|attribute| match attribute {
                        netlink_packet_route::route::RouteAttribute::PrefSource(
                            netlink_packet_route::route::RouteAddress::Inet(ip),
                        ) => config.interfaces.iter().any(|link| {
                            link.addresses.iter().any(|address| {
                                address
                                    .split_once('/')
                                    .is_some_and(|(address, _)| address == ip.to_string())
                            })
                        }),
                        netlink_packet_route::route::RouteAttribute::PrefSource(_) => false,
                        _ => true,
                    });
                candidate.attributes.retain(|attribute| {
                    !matches!(
                        attribute,
                        netlink_packet_route::route::RouteAttribute::PrefSource(_)
                    )
                });
                if valid_source
                    && networking::decode_route(&candidate, &indices)
                        .is_ok_and(|route| dhcp_routes.contains(&route))
                {
                    continue;
                }
            }
            handle.route().del(route).execute().await?;
        }
    }
    netfilter::clear_host_firewall(preserve_owned_firewall)?;
    super::takeover_legacy::clear()?;
    ipv6::set(config.ipv6_enabled)?;
    Ok(())
}

fn competing(name: &str) -> bool {
    matches!(
        name,
        "NetworkManager.service"
            | "NetworkManager-wait-online.service"
            | "systemd-networkd.service"
            | "systemd-networkd.socket"
            | "systemd-networkd-wait-online.service"
            | "networking.service"
            | "dhcpcd.service"
            | "dhclient.service"
            | "connman.service"
            | "wicked.service"
            | "wickedd.service"
            | "ufw.service"
            | "firewalld.service"
            | "nftables.service"
            | "iptables.service"
            | "ip6tables.service"
            | "dnsmasq.service"
            | "isc-dhcp-server.service"
            | "isc-dhcp-server6.service"
            | "kea-dhcp4-server.service"
            | "kea-dhcp6-server.service"
            | "radvd.service"
            | "avahi-daemon.service"
            | "avahi-daemon.socket"
            | "docker.service"
            | "docker.socket"
            | "containerd.service"
            | "libvirtd.service"
            | "libvirtd.socket"
            | "virtqemud.service"
            | "openvswitch-switch.service"
            | "ovs-vswitchd.service"
            | "ovsdb-server.service"
            | "tailscaled.service"
            | "zerotier-one.service"
            | "openvpn.service"
            | "bird.service"
            | "bird6.service"
            | "frr.service"
    ) || (name.ends_with(".service")
        && [
            "dhcpcd@",
            "dhclient@",
            "netplan-ovs-",
            "wg-quick@",
            "openvpn@",
            "openvpn-client@",
            "openvpn-server@",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix)))
}

type ListedUnit = (
    String,
    String,
    String,
    String,
    String,
    String,
    zbus::zvariant::OwnedObjectPath,
    u32,
    String,
    zbus::zvariant::OwnedObjectPath,
);

fn competing_units() -> Result<Vec<String>> {
    adoption::bus(|connection| {
        let manager = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )?;
        let files: Vec<(String, String)> = manager.call("ListUnitFiles", &())?;
        let units: Vec<ListedUnit> = manager.call("ListUnits", &())?;
        let mut names: BTreeSet<_> = files
            .into_iter()
            .filter_map(|(path, _)| {
                Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .filter(|name| competing(name))
            .collect();
        names.extend(
            units
                .into_iter()
                .map(|unit| unit.0)
                .filter(|name| competing(name)),
        );
        Ok(names.into_iter().collect())
    })
    .context("inventory systemd networking owners before takeover")
}

pub(super) fn disable_managers() -> Result<()> {
    let units = competing_units()?;
    if units.is_empty() {
        return Ok(());
    }
    adoption::bus(move |connection| {
        let manager = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )?;
        let _: Vec<(String, String, String)> =
            manager.call("MaskUnitFiles", &(units.clone(), false, true))?;
        let _: () = manager.call("Reload", &())?;
        for name in &units {
            let state: String = manager.call("GetUnitFileState", &(name,))?;
            ensure!(
                state == "masked",
                "competing service {name} is not persistently masked"
            );
            if name.contains("@.") {
                continue;
            }
            let path: zbus::zvariant::OwnedObjectPath = manager.call("LoadUnit", &(name,))?;
            let unit = zbus::blocking::Proxy::new(
                &connection,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.systemd1.Unit",
            )?;
            let state: String = unit.get_property("ActiveState")?;
            if !matches!(state.as_str(), "inactive" | "failed") {
                let _: zbus::zvariant::OwnedObjectPath =
                    manager.call("StopUnit", &(name, "replace"))?;
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let state: String = unit.get_property("ActiveState")?;
                    if matches!(state.as_str(), "inactive" | "failed") {
                        break;
                    }
                    ensure!(
                        Instant::now() < deadline,
                        "competing service {name} did not stop"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let state: String = manager.call("GetUnitFileState", &(name,))?;
            ensure!(
                state == "masked",
                "competing service {name} is not persistently masked"
            );
        }
        Ok(())
    })
    .context("disable competing host networking; console recovery may be required")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_scope_excludes_our_daemon_resolver_and_wifi_authentication() {
        for unit in [
            "systemd-networkd.service",
            "NetworkManager.service",
            "nftables.service",
            "wg-quick@wg0.service",
            "dhclient@eth0.service",
        ] {
            assert!(competing(unit));
        }
        for unit in [
            "netcontrold.service",
            "systemd-resolved.service",
            "wpa_supplicant.service",
            "sshd.service",
        ] {
            assert!(!competing(unit));
        }
    }

    #[test]
    fn reports_do_not_expose_raw_private_snapshots() {
        let mut plan = Plan::new();
        plan.route_snapshot.push(vec![1, 2, 3]);
        plan.item("test", "disabled", "unsupported");
        let report = plan.report();
        assert!(report.get("route_snapshot").is_none());
        assert_eq!(report["connectivity_confirmation_required"], false);
        assert_eq!(report["items"][0]["disposition"], "disabled");
    }
}
