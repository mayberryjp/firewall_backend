use super::{
    dhcp_client::{Lease, now},
    networking,
};
use crate::model::{EthernetSnapshot, Network, PROTOCOL};
use anyhow::{Context, Result, anyhow, bail, ensure};
use configparser::ini::Ini;
use futures_util::TryStreamExt;
use netcontrol_core::{Config, DHCPClientConfig, DHCPRelayConfig, DNSConfig, DNSDomain, Interface};
use netlink_packet_route::{
    address::{AddressAttribute, AddressScope},
    link::LinkAttribute,
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteMessageBuffer, RouteProtocol},
};
use netlink_packet_utils::{Emitable, Parseable};
use rtnetlink::{Handle, IpVersion};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::Ipv4Addr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub scope: String,
    pub config: Config,
    pub originals: BTreeMap<String, EthernetSnapshot>,
    pub leases: BTreeMap<String, Lease>,
    pub routes: Vec<Vec<u8>>,
    pub ownership_before: serde_json::Value,
    pub complete: bool,
}

fn bus<T: Send + 'static>(
    operation: impl FnOnce(zbus::blocking::Connection) -> Result<T> + Send + 'static,
) -> Result<T> {
    std::thread::spawn(move || {
        operation(
            zbus::blocking::connection::Builder::system()?
                .method_timeout(std::time::Duration::from_secs(3))
                .build()?,
        )
    })
    .join()
    .map_err(|_| anyhow!("system bus operation panicked"))?
}

fn networkd(indices: Vec<u32>) -> Result<()> {
    bus(move |connection| {
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.network1",
            "/org/freedesktop/network1",
            "org.freedesktop.network1.Manager",
        )?;
        let _: () = proxy.call("Reload", &())?;
        for index in indices {
            let _: () = proxy.call("ReconfigureLink", &(index as i32,))?;
        }
        Ok(())
    })
}

pub fn set_dns(index: u32, configured: &DNSConfig, lease: Option<&Lease>) -> Result<()> {
    let mut servers = Vec::new();
    for server in &configured.servers {
        let address: std::net::IpAddr = server.parse()?;
        servers.push(match address {
            std::net::IpAddr::V4(address) => (libc::AF_INET, address.octets().to_vec()),
            std::net::IpAddr::V6(address) => (libc::AF_INET6, address.octets().to_vec()),
        });
    }
    let mut domains: Vec<(String, bool)> = configured
        .domains
        .iter()
        .map(|domain| (domain.name.clone(), domain.route_only))
        .collect();
    if let Some(lease) = lease {
        for server in &lease.dns {
            let server = (libc::AF_INET, server.octets().to_vec());
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
        if !lease.domain.is_empty()
            && lease.client.use_domains != "no"
            && !domains.iter().any(|(domain, _)| domain == &lease.domain)
        {
            domains.push((lease.domain.clone(), lease.client.use_domains == "route"));
        }
    }
    bus(move |connection| {
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
        )?;
        let _: () = proxy.call("SetLinkDNS", &(index as i32, servers))?;
        let _: () = proxy.call("SetLinkDomains", &(index as i32, domains))?;
        Ok(())
    })
}

fn fields(path: &Path) -> Result<Ini> {
    parse_fields(path, fs::read_to_string(path)?)
}

fn parse_fields(path: &Path, contents: String) -> Result<Ini> {
    ensure!(
        !contents.lines().any(|line| line.trim_end().ends_with('\\')),
        "continued systemd assignments are not supported for inheritance: {}",
        path.display()
    );
    let mut ini = Ini::new();
    ini.read(contents.clone())
        .map_err(|error| anyhow!("read {}: {error}", path.display()))?;
    let mut network = false;
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in contents.lines().map(str::trim) {
        if line.starts_with('[') {
            network = line
                .split_once(']')
                .is_some_and(|(section, _)| section.eq_ignore_ascii_case("[Network"));
        } else if network {
            if let Some((key, _)) = line.split_once('=') {
                let key = key.trim().to_ascii_lowercase();
                if matches!(key.as_str(), "dns" | "domains") {
                    ensure!(
                        !line.contains('#'),
                        "DNS server names/inline comments are unsupported for inheritance"
                    );
                    let mut assignment = Ini::new();
                    assignment
                        .read(format!("[Network]\n{line}"))
                        .map_err(|error| anyhow!(error))?;
                    let value = assignment.get("Network", &key).unwrap_or_default();
                    let values = lists.entry(key).or_default();
                    if value.is_empty() {
                        values.clear();
                    } else {
                        values.push(value);
                    }
                }
            }
        }
    }
    for (key, values) in lists {
        ini.set("Network", &key, Some(values.join(" ")));
    }
    Ok(ini)
}

fn settings(path: &Path) -> Result<Ini> {
    let mut contents = fs::read_to_string(path)?;
    let basename = path
        .file_name()
        .context("networkd configuration filename missing")?;
    let mut dropins = BTreeMap::new();
    for directory in [
        "/usr/lib/systemd/network",
        "/usr/local/lib/systemd/network",
        "/run/systemd/network",
        "/etc/systemd/network",
    ] {
        let directory = Path::new(directory).join(format!("{}.d", basename.to_string_lossy()));
        if directory.try_exists()? {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "conf")
                {
                    dropins.insert(entry.file_name(), entry.path());
                }
            }
        }
    }
    for path in dropins.values() {
        contents.push('\n');
        contents.push_str(&fs::read_to_string(path)?);
    }
    parse_fields(path, contents)
}

fn dhcp_setting(config: &Ini, key: &str) -> Option<String> {
    config
        .get("DHCPv4", key)
        .or_else(|| config.get("DHCP", key))
}

pub async fn capture(
    handle: &Handle,
    scope: String,
    ownership_before: serde_json::Value,
    readonly: std::collections::BTreeSet<String>,
) -> Result<Receipt> {
    let available = networking::links(handle).await?;
    let available: Vec<_> = available
        .into_iter()
        .filter(|link| {
            let name = networking::name(link);
            name != "lo"
                && !readonly.contains(&name)
                && Path::new("/sys/class/net")
                    .join(name)
                    .join("device")
                    .exists()
        })
        .collect();
    if available.is_empty() {
        return Ok(Receipt {
            scope,
            config: Config::empty(),
            originals: BTreeMap::new(),
            leases: BTreeMap::new(),
            routes: Vec::new(),
            ownership_before,
            complete: false,
        });
    }
    bus(|connection| {
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )?;
        let active: bool = proxy.call("NameHasOwner", &("org.freedesktop.NetworkManager",))?;
        ensure!(
            !active,
            "automatic inheritance currently requires systemd-networkd, not NetworkManager; host configuration was not changed"
        );
        for service in ["org.freedesktop.network1", "org.freedesktop.resolve1"] {
            let active: bool = proxy.call("NameHasOwner", &(service,))?;
            ensure!(
                active,
                "automatic inheritance requires running {service}; host configuration was not changed"
            );
        }
        Ok(())
    })?;
    networking::check_initial_policy_rules(handle).await?;
    let mut config = Config::empty();
    let mut leases = BTreeMap::new();
    let mut names = BTreeMap::new();
    for link in &available {
        let parent = networking::parent(link);
        if parent.name == "lo"
            || !Path::new("/sys/class/net")
                .join(&parent.name)
                .join("device")
                .try_exists()?
        {
            continue;
        }
        ensure!(
            parent.kind == "device" && parent.mac.len() == 17,
            "unsupported physical NIC {}",
            parent.name
        );
        ensure!(
            !link
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, LinkAttribute::Controller(_))),
            "cannot inherit bridged/bonded physical NIC {} without its master configuration",
            parent.name
        );
        let state_path = PathBuf::from(format!("/run/systemd/netif/links/{}", parent.index));
        ensure!(
            state_path.try_exists()?,
            "systemd-networkd has no state for {}",
            parent.name
        );
        let state = fields(&state_path)?;
        let network = state
            .get("default", "NETWORK_FILE")
            .filter(|path| !path.is_empty());
        let settings = network
            .as_ref()
            .map(|path| settings(Path::new(path)))
            .transpose()?;
        let mut dhcp = false;
        let mut client = DHCPClientConfig::default();
        if let Some(settings) = &settings {
            let mode = settings
                .get("Network", "DHCP")
                .unwrap_or_else(|| "no".into());
            ensure!(
                !matches!(mode.as_str(), "yes" | "true" | "ipv6" | "both"),
                "{} uses DHCPv6; dynamic IPv6 inheritance is not implemented",
                parent.name
            );
            dhcp = mode == "ipv4";
            for key in [
                "DHCPServer",
                "IPv6SendRA",
                "DHCPPrefixDelegation",
                "IPMasquerade",
            ] {
                ensure!(
                    settings
                        .get("Network", key)
                        .is_none_or(|value| matches!(value.as_str(), "no" | "false")),
                    "{} has unsupported networkd {key}",
                    parent.name
                );
            }
            for key in [
                "VendorClassIdentifier",
                "UserClass",
                "SendOption",
                "SendVendorOption",
                "AllowList",
                "DenyList",
                "RouteTable",
            ] {
                ensure!(
                    dhcp_setting(settings, key).is_none(),
                    "{} has unsupported DHCP option {key}",
                    parent.name
                );
            }
            for key in ["UseDNS", "UseRoutes", "UseGateway"] {
                ensure!(
                    dhcp_setting(settings, key)
                        .is_none_or(|value| matches!(value.as_str(), "yes" | "true")),
                    "{} disables DHCP {key}; inheritance cannot preserve this setting",
                    parent.name
                );
            }
            client.route_metric = dhcp_setting(settings, "RouteMetric")
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(1024);
            client.use_mtu = dhcp_setting(settings, "UseMTU")
                .is_some_and(|value| value == "yes" || value == "true");
            client.use_domains = dhcp_setting(settings, "UseDomains")
                .map(|value| match value.as_str() {
                    "true" => "yes".into(),
                    "false" => "no".into(),
                    _ => value,
                })
                .unwrap_or_else(|| "no".into());
            let dns = DNSConfig {
                servers: settings
                    .get("Network", "DNS")
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
                domains: settings
                    .get("Network", "Domains")
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(|domain| DNSDomain {
                        name: domain.trim_start_matches('~').into(),
                        route_only: domain.starts_with('~'),
                    })
                    .collect(),
            };
            if !dns.servers.is_empty() || !dns.domains.is_empty() {
                config.dns.insert(parent.name.clone(), dns);
            }
            client.hostname = dhcp_setting(settings, "Hostname").unwrap_or_default();
            if dhcp_setting(settings, "SendHostname")
                .is_some_and(|value| value == "no" || value == "false")
            {
                client.hostname.clear();
            }
            if dhcp
                && client.hostname.is_empty()
                && dhcp_setting(settings, "SendHostname")
                    .is_none_or(|value| value != "no" && value != "false")
            {
                client.hostname = fs::read_to_string("/proc/sys/kernel/hostname")?
                    .trim()
                    .into();
            }
        }
        let messages = networking::addresses(handle, parent.index).await?;
        let mut addresses = Vec::new();
        let lease_path = PathBuf::from(format!("/run/systemd/netif/leases/{}", parent.index));
        let lease = if dhcp {
            ensure!(
                lease_path.try_exists()?,
                "{} needs an active DHCPv4 lease to preserve its client identity",
                parent.name
            );
            let data = fields(&lease_path)?;
            client.client_id = data
                .get("default", "CLIENTID")
                .context("networkd lease has no CLIENTID")?
                .replace(':', "");
            let ip: Ipv4Addr = data
                .get("default", "ADDRESS")
                .context("networkd lease address missing")?
                .parse()?;
            let address = messages
                .iter()
                .find_map(|message| {
                    let prefix = networking::address_string(message).ok().flatten()?;
                    prefix
                        .starts_with(&format!("{ip}/"))
                        .then_some((prefix, message))
                })
                .context("DHCP lease does not match the live interface address")?;
            let remaining = address
                .1
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::CacheInfo(info) => Some(info.ifa_valid),
                    _ => None,
                })
                .context("DHCP address lifetime missing")?;
            ensure!(
                remaining > 2 && remaining < u32::MAX,
                "DHCP address has no usable finite lifetime"
            );
            Some(Lease {
                client: client.clone(),
                address: address.0,
                server: data
                    .get("default", "SERVER_ADDRESS")
                    .context("networkd DHCP server missing")?
                    .parse()?,
                acquired_at: now()?,
                lifetime: remaining,
                renewal: (remaining / 2).max(1),
                rebinding: ((remaining / 8) * 7).max(2),
                routes: Vec::new(),
                dns: data
                    .get("default", "DNS")
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(str::parse)
                    .collect::<Result<Vec<_>, _>>()?,
                domain: data.get("default", "DOMAINNAME").unwrap_or_default(),
                mtu: None,
            })
        } else {
            None
        };
        for message in messages {
            if message.header.scope == AddressScope::Link {
                continue;
            }
            let address =
                networking::address_string(&message)?.context("unsupported inherited address")?;
            if lease.as_ref().is_some_and(|lease| lease.address == address) {
                continue;
            }
            ensure!(!message.attributes.iter().any(|attribute| matches!(attribute, AddressAttribute::CacheInfo(info) if info.ifa_valid != u32::MAX || info.ifa_preferred != u32::MAX)),
                "{} has an unsupported dynamic address {address}; DHCPv6/SLAAC cannot become static", parent.name);
            addresses.push(address);
        }
        if let Some(lease) = lease {
            config.dhcp_clients.insert(parent.name.clone(), client);
            leases.insert(parent.name.clone(), lease);
        }
        names.insert(parent.index, parent.name.clone());
        config.interfaces.push(Interface {
            name: parent.name,
            kind: "ethernet".into(),
            role: "unassigned".into(),
            mtu: i64::from(parent.mtu),
            up: parent.up,
            addresses,
            dhcp_relay: DHCPRelayConfig::default(),
            wireguard: None,
            vlan: None,
        });
    }
    let mut routes = Vec::new();
    for version in [IpVersion::V4, IpVersion::V6] {
        let live: Vec<RouteMessage> = handle.route().get(version).execute().try_collect().await?;
        for message in live {
            let index = message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RouteAttribute::Oif(index) => Some(*index),
                    _ => None,
                });
            if !index.is_some_and(|index| names.contains_key(&index)) || message.header.table == 255
            {
                continue;
            }
            let mut decoded = message.clone();
            let interface = names
                .get(&index.context("route interface missing")?)
                .context("route interface unknown")?;
            if message.header.protocol == RouteProtocol::Kernel {
                let Some(lease) = leases.get(interface) else {
                    continue;
                };
                let (address, length) = crate::model::parse_prefix(&lease.address, false)?;
                let std::net::IpAddr::V4(address) = address else {
                    bail!("inherited DHCP address is not IPv4");
                };
                let mask = if length == 0 {
                    0
                } else {
                    u32::MAX << (32 - length)
                };
                let (table, _, destination) = networking::route_key(&message)?;
                if table != 254
                    || destination
                        != format!("{}/{length}", Ipv4Addr::from(u32::from(address) & mask))
                {
                    continue;
                }
            }
            let dynamic = matches!(
                message.header.protocol,
                RouteProtocol::Dhcp | RouteProtocol::Kernel
            );
            if dynamic {
                ensure!(
                    leases.contains_key(interface),
                    "DHCP route has no inherited DHCP client"
                );
                let lease_ip: Ipv4Addr = leases[interface]
                    .address
                    .split_once('/')
                    .context("inherited DHCP address prefix missing")?
                    .0
                    .parse()?;
                ensure!(
                    message.attributes.iter().all(|attribute| !matches!(
                        attribute,
                        RouteAttribute::PrefSource(source) if *source != RouteAddress::Inet(lease_ip)
                    )),
                    "inherited DHCP route preferred source differs from the lease address"
                );
                decoded
                    .attributes
                    .retain(|attribute| !matches!(attribute, RouteAttribute::PrefSource(_)));
            } else {
                ensure!(
                    matches!(
                        message.header.protocol,
                        RouteProtocol::Static | RouteProtocol::Boot
                    ),
                    "unsupported inherited route protocol"
                );
            }
            let route = networking::decode_route(&decoded, &names)?;
            if dynamic {
                leases
                    .get_mut(interface)
                    .context("DHCP lease missing")?
                    .routes
                    .push(route);
            } else {
                config
                    .routes
                    .push(serde_json::from_value(serde_json::to_value(route)?)?);
            }
            let mut raw = vec![0; message.buffer_len()];
            message.emit(&mut raw);
            routes.push(raw);
        }
    }
    config = config.normalized();
    config
        .validate()
        .context("host configuration cannot be inherited without changing its semantics")?;
    let network = Network::parse(&serde_json::to_value(&config)?)?;
    let originals = networking::capture_ethernet(handle, &network, &network).await?;
    for interface in &config.interfaces {
        ensure!(
            !override_path(&interface.name).try_exists()?,
            "existing handover file without an adoption receipt for {}",
            interface.name
        );
    }
    Ok(Receipt {
        scope,
        config,
        originals,
        leases,
        routes,
        ownership_before,
        complete: false,
    })
}

fn override_path(name: &str) -> PathBuf {
    Path::new("/etc/systemd/network").join(format!("00-netcontrol-{name}.network"))
}

fn override_contents(name: &str) -> String {
    format!(
        "[Match]\nName={name}\n\n[Link]\nUnmanaged=yes\nRequiredForOnline=no\n\n[Network]\nKeepConfiguration=yes\n\n[DHCPv4]\nSendRelease=no\n"
    )
}

pub fn handover(receipt: &Receipt) -> Result<()> {
    let directory = Path::new("/etc/systemd/network");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0,
        "networkd configuration directory must be root-owned, non-symlink and not group/other writable"
    );
    for interface in &receipt.config.interfaces {
        let path = override_path(&interface.name);
        let contents = override_contents(&interface.name);
        if path.try_exists()? {
            ensure!(
                fs::symlink_metadata(&path)?.is_file(),
                "handover file cannot be a symlink"
            );
            ensure!(
                fs::read_to_string(&path)? == contents,
                "handover file changed: {}",
                path.display()
            );
        } else {
            let temporary = directory.join(format!(
                ".netcontrol-{}-{}-{}.tmp",
                interface.name,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            fs::hard_link(&temporary, &path)
                .context("publish networkd handover without replacing an existing file")?;
            fs::remove_file(temporary)?;
            fs::File::open(path.parent().context("handover directory missing")?)?.sync_all()?;
        }
    }
    let indices = current_indices(receipt)?;
    networkd(indices.clone())?;
    for (snapshot, index) in receipt.originals.values().zip(indices) {
        let state = fields(Path::new(&format!("/run/systemd/netif/links/{}", index)))?;
        ensure!(
            state.get("default", "ADMIN_STATE").as_deref() == Some("unmanaged"),
            "networkd did not relinquish {}",
            snapshot.name
        );
    }
    Ok(())
}

pub async fn transfer_routes(handle: &Handle, receipt: &Receipt, restore: bool) -> Result<()> {
    let available = networking::links(handle).await?;
    for raw in &receipt.routes {
        let mut message = RouteMessage::parse(&RouteMessageBuffer::new_checked(raw)?)?;
        let old_index = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            })
            .context("inherited route interface missing")?;
        let snapshot = receipt
            .originals
            .values()
            .find(|snapshot| snapshot.index == old_index)
            .context("inherited route snapshot missing")?;
        if message.header.protocol == RouteProtocol::Dhcp
            && !receipt
                .leases
                .get(&snapshot.name)
                .is_some_and(|lease| lease.valid())
        {
            continue;
        }
        let index = available
            .iter()
            .find(|link| networking::name(link) == snapshot.name)
            .context("inherited route NIC missing")?
            .header
            .index;
        for attribute in &mut message.attributes {
            if let RouteAttribute::Oif(value) = attribute {
                *value = index;
            }
        }
        let original = message.clone();
        message.header.protocol = if original.header.protocol == RouteProtocol::Dhcp {
            RouteProtocol::Other(super::dhcp_client::PROTOCOL)
        } else {
            RouteProtocol::Other(PROTOCOL)
        };
        if restore {
            let _ = handle.route().del(message).execute().await;
            message = original;
        }
        let mut request = handle.route().add();
        *request.message_mut() = message;
        request.replace().execute().await?;
    }
    Ok(())
}

pub fn release(receipt: &Receipt) -> Result<()> {
    for interface in &receipt.config.interfaces {
        let path = override_path(&interface.name);
        if path.try_exists()? {
            ensure!(
                fs::symlink_metadata(&path)?.is_file(),
                "handover file cannot be a symlink"
            );
            ensure!(
                fs::read_to_string(&path)? == override_contents(&interface.name),
                "handover file changed; refusing to remove it"
            );
            super::remove_durable(&path)?;
        }
    }
    networkd(current_indices(receipt)?)
}

fn current_indices(receipt: &Receipt) -> Result<Vec<u32>> {
    receipt
        .originals
        .values()
        .map(|snapshot| {
            fs::read_to_string(format!("/sys/class/net/{}/ifindex", snapshot.name))?
                .trim()
                .parse::<u32>()
                .map_err(anyhow::Error::from)
        })
        .collect()
}
