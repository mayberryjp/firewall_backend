use super::{Installed, Ledger, WGAddition, wire::Prefix};
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use netlink_packet_route::{
    link::LinkAttribute,
    route::{RouteAddress, RouteAttribute, RouteProtocol, RouteScope},
};
use rtnetlink::{Handle, IpVersion};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};
use wireguard_control::{Backend, Device, DeviceUpdate, Key, PeerConfigBuilder};

pub const PROTOCOL: u8 = 245;
pub const METRIC: u32 = 200;
pub async fn routes(handle: &Handle, remove: &[Installed], add: &[Installed]) -> Result<()> {
    if remove.is_empty() && add.is_empty() {
        return Ok(());
    }
    let links = handle
        .link()
        .get()
        .execute()
        .try_collect::<Vec<_>>()
        .await?;
    let indices = links
        .iter()
        .filter_map(|link| {
            link.attributes.iter().find_map(|attribute| {
                if let LinkAttribute::IfName(name) = attribute {
                    Some((name.as_str(), link.header.index))
                } else {
                    None
                }
            })
        })
        .collect::<BTreeMap<_, _>>();
    let mut messages = handle.route().get(IpVersion::V4).execute();
    let mut existing = BTreeMap::new();
    while let Some(message) = messages.try_next().await? {
        let destination = message
            .attributes
            .iter()
            .find_map(|a| match a {
                RouteAttribute::Destination(RouteAddress::Inet(ip)) => Some(*ip),
                _ => None,
            })
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        let table = message
            .attributes
            .iter()
            .find_map(|a| {
                if let RouteAttribute::Table(t) = a {
                    Some(*t)
                } else {
                    None
                }
            })
            .unwrap_or(u32::from(message.header.table));
        if table != 254 || message.header.source_prefix_length != 0 || message.header.tos != 0 {
            continue;
        }
        let metric = message
            .attributes
            .iter()
            .find_map(|a| {
                if let RouteAttribute::Priority(m) = a {
                    Some(*m)
                } else {
                    None
                }
            })
            .unwrap_or(0);
        if metric != METRIC {
            continue;
        }
        existing.insert(
            Prefix::new(destination, message.header.destination_prefix_length)?,
            message,
        );
    }
    let matches = |message: &netlink_packet_route::route::RouteMessage, route: &Installed| {
        let index = message.attributes.iter().find_map(|a| {
            if let RouteAttribute::Oif(i) = a {
                Some(*i)
            } else {
                None
            }
        });
        let gateway = message.attributes.iter().find_map(|a| {
            if let RouteAttribute::Gateway(RouteAddress::Inet(ip)) = a {
                Some(*ip)
            } else {
                None
            }
        });
        message.header.protocol == RouteProtocol::Other(PROTOCOL)
            && message.header.source_prefix_length == 0
            && message.header.tos == 0
            && index == indices.get(route.interface.as_str()).copied()
            && gateway == route.gateway
    };
    for route in remove {
        if existing
            .get(&route.prefix)
            .is_some_and(|message| matches(message, route))
        {
            let message = existing
                .remove(&route.prefix)
                .context("BGP cleanup route disappeared")?;
            handle.route().del(message).execute().await?;
        }
    }
    for route in add {
        if let Some(message) = existing.get(&route.prefix) {
            ensure!(
                matches(message, route),
                "BGP route conflicts with a foreign route: {}",
                route.prefix
            );
            continue;
        }
        let index = *indices
            .get(route.interface.as_str())
            .context("BGP route interface missing")?;
        let request = handle
            .route()
            .add()
            .v4()
            .destination_prefix(route.prefix.address, route.prefix.length)
            .table_id(254)
            .priority(METRIC)
            .protocol(RouteProtocol::Other(PROTOCOL))
            .output_interface(index)
            .scope(if route.gateway.is_some() {
                RouteScope::Universe
            } else {
                RouteScope::Link
            });
        if let Some(gateway) = route.gateway {
            request.gateway(gateway).execute().await?;
        } else {
            request.execute().await?;
        }
    }
    Ok(())
}
pub fn wg(additions: &[WGAddition], add: bool) -> Result<()> {
    let interfaces = additions
        .iter()
        .map(|a| &a.interface)
        .collect::<BTreeSet<_>>();
    for interface in interfaces {
        let name = interface.parse()?;
        let c_name = std::ffi::CString::new(interface.as_str())?;
        if !add && unsafe { libc::if_nametoindex(c_name.as_ptr()) } == 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO)) {
                continue;
            }
            return Err(error.into());
        }
        let device = Device::get(&name, Backend::Kernel)?;
        let actual_keys = device
            .peers
            .iter()
            .map(|p| p.config.public_key.to_base64())
            .collect::<BTreeSet<_>>();
        if add {
            for entry in additions.iter().filter(|a| a.interface == *interface) {
                ensure!(
                    actual_keys.contains(&entry.key),
                    "BGP WireGuard peer disappeared"
                );
            }
        }
        let mut updates = Vec::new();
        for peer in device.peers {
            let key = peer.config.public_key.to_base64();
            let entries = additions
                .iter()
                .filter(|a| a.interface == *interface && a.key == key)
                .collect::<Vec<_>>();
            if entries.is_empty() {
                continue;
            }
            let mut prefixes = peer
                .config
                .allowed_ips
                .iter()
                .map(|p| format!("{}/{}", p.address, p.cidr))
                .collect::<BTreeSet<_>>();
            let original = prefixes.clone();
            for entry in entries {
                if add {
                    prefixes.insert(entry.prefix.to_string());
                } else {
                    prefixes.remove(&entry.prefix.to_string());
                }
                if prefixes == original {
                    continue;
                }
            }
            let mut builder =
                PeerConfigBuilder::new(&Key::from_base64(&key)?).replace_allowed_ips();
            for prefix in prefixes {
                let (ip, len) = crate::model::parse_prefix(&prefix, true)?;
                builder = builder.add_allowed_ip(ip, len);
            }
            updates.push(builder);
        }
        if !updates.is_empty() {
            DeviceUpdate::new()
                .add_peers(&updates)
                .apply(&name, Backend::Kernel)?;
        }
    }
    Ok(())
}
pub async fn cleanup(handle: &Handle, ledger: &Ledger) -> Result<()> {
    routes(handle, &ledger.routes, &[]).await?;
    wg(&ledger.wg, false)
}
pub async fn connected(
    handle: &Handle,
    config: &netcontrol_core::Config,
) -> Result<BTreeSet<Prefix>> {
    let links = handle
        .link()
        .get()
        .execute()
        .try_collect::<Vec<_>>()
        .await?;
    let allowed = links
        .iter()
        .filter(|l| {
            l.header
                .flags
                .contains(&netlink_packet_route::link::LinkFlag::Up)
        })
        .filter_map(|l| {
            l.attributes.iter().find_map(|a| {
                if let LinkAttribute::IfName(n) = a {
                    Some((l.header.index, n))
                } else {
                    None
                }
            })
        })
        .filter(|(_, name)| config.interfaces.iter().any(|i| i.up && &i.name == *name))
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    let mut messages = handle.address().get().execute();
    let mut result = BTreeSet::new();
    while let Some(message) = messages.try_next().await? {
        if !allowed.contains(&message.header.index) {
            continue;
        }
        for attribute in &message.attributes {
            if let netlink_packet_route::address::AddressAttribute::Local(IpAddr::V4(ip)) =
                attribute
            {
                if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() {
                    result.insert(Prefix::new(*ip, message.header.prefix_len)?);
                }
            }
        }
    }
    ensure!(
        result.len() <= 4096,
        "BGP connected export exceeds 4096 prefixes"
    );
    Ok(result)
}
