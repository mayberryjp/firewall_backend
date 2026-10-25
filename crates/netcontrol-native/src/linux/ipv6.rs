use super::networking;
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use netlink_packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressFlag, AddressMessage, AddressMessageBuffer},
    route::{RouteAttribute, RouteMessage, RouteMessageBuffer, RouteProtocol},
};
use netlink_packet_utils::{Emitable, Parseable};
use rtnetlink::{Handle, IpVersion};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    boot: String,
    captured_unix: u64,
    controls: BTreeMap<String, String>,
    links: Vec<(networking::Parent, Vec<Vec<u8>>)>,
    routes: Vec<Vec<u8>>,
}

impl Snapshot {
    pub(super) fn unmanaged(mut self, network: &crate::model::Network) -> Result<Self> {
        let managed: std::collections::BTreeSet<_> = self
            .links
            .iter()
            .filter(|(link, _)| network.interfaces.iter().any(|l| l.name == link.name))
            .map(|(link, _)| link.index)
            .collect();
        self.links
            .retain(|(link, _)| !managed.contains(&link.index));
        let mut routes = Vec::new();
        for bytes in self.routes {
            let route = RouteMessage::parse(&RouteMessageBuffer::new_checked(&bytes)?)?;
            if route.header.protocol != RouteProtocol::Other(crate::model::PROTOCOL)
                && !route
                    .attributes
                    .iter()
                    .any(|a| matches!(a, RouteAttribute::Oif(index) if managed.contains(index)))
            {
                routes.push(bytes);
            }
        }
        self.routes = routes;
        Ok(self)
    }
}

fn path(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0']),
        "invalid IPv6 interface name"
    );
    Ok(PathBuf::from("/proc/sys/net/ipv6/conf")
        .join(name)
        .join("disable_ipv6"))
}

fn read(name: &str) -> Result<String> {
    let value = fs::read_to_string(path(name)?)
        .with_context(|| format!("read IPv6 disable control for {name}"))?;
    let value = value.trim();
    ensure!(
        matches!(value, "0" | "1"),
        "invalid IPv6 control for {name}"
    );
    Ok(value.into())
}

fn write(name: &str, value: &str) -> Result<()> {
    ensure!(matches!(value, "0" | "1"), "invalid IPv6 disable value");
    if read(name)? != value {
        fs::write(path(name)?, format!("{value}\n"))
            .with_context(|| format!("write IPv6 disable control for {name}"))?;
    }
    ensure!(
        read(name)? == value,
        "kernel rejected IPv6 control for {name}"
    );
    Ok(())
}

pub(super) fn controls() -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for entry in fs::read_dir("/proc/sys/net/ipv6/conf")
        .context("IPv6 kernel support and writable IPv6 sysctls are required")?
    {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 IPv6 interface name"))?;
        values.insert(name.clone(), read(&name)?);
    }
    ensure!(
        values.contains_key("all") && values.contains_key("default"),
        "missing global IPv6 controls"
    );
    Ok(values)
}

pub(super) fn preflight(enabled: bool) -> Result<()> {
    let expected = if enabled { "0" } else { "1" };
    for (name, value) in controls()? {
        if value != expected {
            fs::OpenOptions::new().write(true).open(path(&name)?)?;
        }
    }
    Ok(())
}

pub(super) fn set(enabled: bool) -> Result<()> {
    let value = if enabled { "0" } else { "1" };
    // Default first closes the new-interface window; "all" includes loopback.
    write("default", value)?;
    write("all", value)?;
    for name in controls()?
        .keys()
        .filter(|n| !matches!(n.as_str(), "all" | "default"))
    {
        write(name, value)?;
    }
    verify(enabled)
}

pub(super) fn verify(enabled: bool) -> Result<()> {
    let expected = if enabled { "0" } else { "1" };
    crate::ensure_unchanged(
        controls()?.values().all(|value| value == expected),
        "global IPv6 disable controls drift",
    )
}

pub(super) fn status(enabled: bool) -> Result<Value> {
    let observed = controls()?;
    let expected = if enabled { "0" } else { "1" };
    Ok(
        json!({"enabled":enabled,"status":"measured","disable_ipv6":observed,
        "drift":observed.values().any(|value|value != expected)}),
    )
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn raw(message: &impl Emitable) -> Vec<u8> {
    let mut bytes = vec![0; message.buffer_len()];
    message.emit(&mut bytes);
    bytes
}

pub(super) async fn capture(handle: &Handle) -> Result<Snapshot> {
    let mut links = Vec::new();
    for link in networking::links(handle).await? {
        let parent = networking::parent(&link);
        let addresses = networking::addresses(handle, parent.index)
            .await?
            .iter()
            .filter(|a| a.header.family == AddressFamily::Inet6)
            .map(raw)
            .collect();
        links.push((parent, addresses));
    }
    let routes: Vec<RouteMessage> = handle
        .route()
        .get(IpVersion::V6)
        .execute()
        .try_collect()
        .await?;
    Ok(Snapshot {
        boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        captured_unix: now()?,
        controls: controls()?,
        links,
        routes: routes
            .iter()
            .filter(|route| route.header.protocol != RouteProtocol::Kernel)
            .map(raw)
            .collect(),
    })
}

fn remaining(lifetime: u32, elapsed: u64) -> u32 {
    if lifetime == u32::MAX {
        lifetime
    } else {
        lifetime.saturating_sub(u32::try_from(elapsed).unwrap_or(u32::MAX))
    }
}

pub(super) async fn restore_network(handle: &Handle, snapshot: &Snapshot) -> Result<()> {
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == snapshot.boot,
        "cannot restore IPv6 snapshot from another boot"
    );
    let available = networking::links(handle).await?;
    let elapsed = now()?
        .checked_sub(snapshot.captured_unix)
        .context("clock moved backward; refusing stale IPv6 lifetimes")?;
    for (saved, addresses) in &snapshot.links {
        let actual = available
            .iter()
            .find(|link| networking::name(link) == saved.name)
            .map(networking::parent)
            .with_context(|| format!("IPv6 snapshot interface {} missing", saved.name))?;
        ensure!(
            actual.index == saved.index && actual.kind == saved.kind && actual.mac == saved.mac,
            "IPv6 snapshot interface {} changed identity",
            saved.name
        );
        for bytes in addresses {
            let mut address = AddressMessage::parse(&AddressMessageBuffer::new_checked(bytes)?)?;
            let mut expired = false;
            for attribute in &mut address.attributes {
                if let AddressAttribute::CacheInfo(info) = attribute {
                    info.ifa_preferred = remaining(info.ifa_preferred, elapsed);
                    info.ifa_valid = remaining(info.ifa_valid, elapsed);
                    expired = info.ifa_valid == 0;
                    info.cstamp = 0;
                    info.tstamp = 0;
                }
                if let AddressAttribute::Flags(flags) = attribute {
                    flags.retain(|flag| {
                        !matches!(flag, AddressFlag::Tentative | AddressFlag::Dadfailed)
                    });
                }
            }
            if expired {
                continue;
            }
            let ip = address
                .attributes
                .iter()
                .find_map(|a| match a {
                    AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => Some(*ip),
                    _ => None,
                })
                .context("IPv6 snapshot address missing IP")?;
            let mut request = handle
                .address()
                .add(saved.index, ip, address.header.prefix_len)
                .replace();
            *request.message_mut() = address;
            request.execute().await.context("restore IPv6 address")?;
        }
    }
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(ticks > 0, "cannot determine IPv6 route expiry clock");
    for bytes in &snapshot.routes {
        let mut route = RouteMessage::parse(&RouteMessageBuffer::new_checked(bytes)?)?;
        let mut expired = false;
        for attribute in &mut route.attributes {
            if let RouteAttribute::Expires(lifetime) = attribute {
                *lifetime = remaining(*lifetime, elapsed.saturating_mul(ticks as u64));
                expired = *lifetime == 0;
            }
        }
        if expired {
            continue;
        }
        route
            .attributes
            .retain(|a| !matches!(a, RouteAttribute::CacheInfo(_)));
        let mut request = handle.route().add().v6().replace();
        *request.message_mut() = route;
        request.execute().await.context("restore IPv6 route")?;
    }
    Ok(())
}

pub(super) fn restore_controls(snapshot: &Snapshot) -> Result<()> {
    for name in ["default", "all"] {
        write(
            name,
            snapshot
                .controls
                .get(name)
                .context("missing captured IPv6 control")?,
        )?;
    }
    for (name, value) in &snapshot.controls {
        if !matches!(name.as_str(), "default" | "all") {
            write(name, value)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_paths_and_lifetimes_are_strict() {
        assert!(path("vlan.20").unwrap().ends_with("vlan.20/disable_ipv6"));
        for invalid in ["", ".", "..", "../all", "a/b", "a\0b"] {
            assert!(path(invalid).is_err());
        }
        assert_eq!(remaining(u32::MAX, 100), u32::MAX);
        assert_eq!(remaining(30, 10), 20);
        assert_eq!(remaining(30, 40), 0);
    }
}
