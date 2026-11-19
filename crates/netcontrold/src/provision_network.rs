use anyhow::{Context, Result, bail, ensure};
use netcontrol_core::{Config, Interface, VLAN, canonical_prefix, valid_interface_name};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, Read, Write},
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlan {
    pub management_interface: String,
    pub interfaces: Vec<PlannedInterface>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedInterface {
    pub name: String,
    pub role: String,
    pub vlan: Option<VLAN>,
    pub ipv4: Addressing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Addressing {
    None {},
    Dhcp {},
    Static {
        address: String,
        gateway: Option<Ipv4Addr>,
        dns: Vec<Ipv4Addr>,
    },
}

fn host_prefix(address: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = canonical_prefix(address, false)?;
    let IpAddr::V4(ip) = ip else {
        bail!("installer addressing must be IPv4");
    };
    ensure!(
        prefix > 0 && usable_ip(ip),
        "requires a usable unicast IPv4 host/prefix (1..32)"
    );
    if prefix < 31 {
        let mask = u32::MAX << (32 - prefix);
        ensure!(
            u32::from(ip) & !mask != 0 && u32::from(ip) & !mask != !mask,
            "address must not be the subnet or broadcast address"
        );
    }
    Ok((ip, prefix))
}

fn usable_ip(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && ip.octets()[0] != 0
        && ip.octets()[0] < 240
}

fn subnet(address: &str) -> Result<String> {
    let (ip, prefix) = host_prefix(address)?;
    let mask = u32::MAX << (32 - prefix);
    Ok(format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask)))
}

impl NetworkPlan {
    pub fn validate_host(&self) -> Result<()> {
        let links = discover(
            Path::new("/sys/class/net"),
            Path::new("/proc/net/vlan/config"),
        )?;
        for existing in &links {
            ensure!(
                self.interfaces
                    .iter()
                    .any(|link| link.name == existing.name && link.vlan == existing.vlan),
                "plan must review every existing Ethernet/VLAN interface, including {} with its current identity",
                existing.name
            );
        }
        for link in &self.interfaces {
            if !links.iter().any(|existing| existing.name == link.name) {
                ensure!(
                    link.vlan.is_some()
                        && !Path::new("/sys/class/net").join(&link.name).try_exists()?,
                    "new interface must be a VLAN with an unused name: {}",
                    link.name
                );
            }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        fs::File::open(path)
            .context("open installer network plan")?
            .take(65537)
            .read_to_end(&mut bytes)
            .context("read installer network plan")?;
        ensure!(bytes.len() <= 65536, "network plan exceeds 64 KiB");
        let plan: Self =
            serde_json::from_slice(&bytes).context("invalid installer network plan")?;
        plan.candidate(&Config::default())?;
        Ok(plan)
    }

    pub fn management_address(&self) -> Result<&str> {
        let link = self
            .interfaces
            .iter()
            .find(|link| link.name == self.management_interface && link.role == "lan")
            .context("management interface must be a configured LAN")?;
        let Addressing::Static { address, .. } = &link.ipv4 else {
            bail!("management LAN requires a static IPv4 address");
        };
        Ok(address)
    }

    pub fn candidate(&self, saved: &Config) -> Result<Config> {
        ensure!(
            !self.interfaces.is_empty() && self.interfaces.len() <= 64,
            "installer supports 1..64 interfaces"
        );
        let mut config = Config {
            software: saved.software.clone(),
            system: saved.system.clone(),
            kernel: saved.kernel.clone(),
            ..Config::default()
        };
        let mut names = BTreeSet::new();
        let mut prefixes: Vec<&str> = Vec::new();
        let mut gateways = 0;
        for link in &self.interfaces {
            ensure!(
                valid_interface_name(&link.name) && names.insert(link.name.clone()),
                "invalid or duplicate interface name: {}",
                link.name
            );
            ensure!(
                matches!(link.role.as_str(), "wan" | "lan" | "unassigned"),
                "invalid role for {}",
                link.name
            );
            if let Some(vlan) = &link.vlan {
                ensure!(
                    self.interfaces
                        .iter()
                        .any(|parent| parent.name == vlan.parent),
                    "VLAN parent must be included in the plan: {}",
                    vlan.parent
                );
            }
            if let Some(existing) = saved.interfaces.iter().find(|i| i.name == link.name) {
                ensure!(
                    existing.vlan == link.vlan
                        && existing.kind
                            == if link.vlan.is_some() {
                                "vlan"
                            } else {
                                "ethernet"
                            },
                    "plan changes existing interface kind or VLAN identity: {}",
                    link.name
                );
            } else if !saved.interfaces.is_empty() {
                ensure!(
                    link.vlan.is_some(),
                    "physical interface not found in imported host: {}",
                    link.name
                );
            }
            let mut interface: Interface = serde_json::from_value(json!({
                "name": link.name, "kind": if link.vlan.is_some() {"vlan"} else {"ethernet"},
                "role": link.role, "mtu": 1500, "up": true, "addresses": [], "vlan": link.vlan
            }))?;
            match &link.ipv4 {
                Addressing::None {} => ensure!(
                    link.role == "unassigned",
                    "WAN/LAN interfaces need DHCP or static IPv4; use unassigned for an unaddressed trunk"
                ),
                Addressing::Dhcp {} => {
                    ensure!(link.role != "unassigned", "unassigned links must use none");
                    config.dhcp_clients.insert(
                        link.name.clone(),
                        netcontrol_core::DHCPClientConfig {
                            route_metric: if link.role == "wan" { 100 } else { 600 },
                            ..Default::default()
                        },
                    );
                }
                Addressing::Static {
                    address,
                    gateway,
                    dns,
                } => {
                    ensure!(link.role != "unassigned", "unassigned links must use none");
                    let (ip, prefix) = host_prefix(address)?;
                    for other in &prefixes {
                        ensure!(
                            !super::provision::overlaps(address, other)?,
                            "static subnets overlap: {address} and {other}"
                        );
                    }
                    prefixes.push(address);
                    interface.addresses.push(address.clone());
                    if let Some(gateway) = gateway {
                        let mask = u32::MAX << (32 - prefix);
                        ensure!(
                            link.role == "wan"
                                && usable_ip(*gateway)
                                && *gateway != ip
                                && u32::from(*gateway) & mask == u32::from(ip) & mask,
                            "static gateway must be a different on-link WAN IPv4 host"
                        );
                        host_prefix(&format!("{gateway}/{prefix}"))?;
                        config.routes.push(serde_json::from_value(json!({
                            "destination":"0.0.0.0/0", "gateway":gateway,
                            "interface":link.name, "table":254, "metric":100
                        }))?);
                        gateways += 1;
                    }
                    ensure!(
                        dns.len() <= 8
                            && dns.iter().all(|ip| usable_ip(*ip))
                            && dns.iter().collect::<BTreeSet<_>>().len() == dns.len(),
                        "DNS requires at most eight unique unicast IPv4 servers"
                    );
                    if !dns.is_empty() {
                        config.dns.insert(
                            link.name.clone(),
                            serde_json::from_value(json!({
                                "servers":dns, "override_dhcp_dns":true
                            }))?,
                        );
                    }
                    ensure!(
                        link.role != "wan" || (gateway.is_some() && !dns.is_empty()),
                        "static WAN requires a gateway and at least one DNS server"
                    );
                }
            }
            config.interfaces.push(interface);
        }
        ensure!(
            gateways <= 1,
            "only one static default gateway is supported"
        );
        let wans: Vec<_> = self.interfaces.iter().filter(|i| i.role == "wan").collect();
        ensure!(
            wans.len() == 1,
            "select exactly one WAN for the starter policy"
        );
        let wan = &wans[0].name;
        let management = self.management_address()?;
        let (ip, prefix) = host_prefix(management)?;
        ensure!(
            ip.is_private()
                && (8..=30).contains(&prefix)
                && prefix
                    >= match ip.octets() {
                        [10, ..] => 8,
                        [172, ..] => 12,
                        _ => 16,
                    },
            "management LAN requires a usable RFC1918 host/prefix entirely within private space (8..30)"
        );
        let mut forwarding = Vec::new();
        let mut input = Vec::new();
        let mut sources = BTreeSet::new();
        for link in &self.interfaces {
            if link.role == "lan" {
                forwarding.push(json!({"interface":link.name, "rules":[{"out_interface":wan,"action":"accept"}]}));
                input.push(json!({"interface":link.name,"rules":[{"action":"accept"}]}));
                sources.insert(match &link.ipv4 {
                    Addressing::Static { address, .. } => subnet(address)?,
                    Addressing::Dhcp {} => String::new(),
                    Addressing::None {} => unreachable!(),
                });
            }
            if matches!(link.ipv4, Addressing::Dhcp {}) {
                let rule = json!({"protocol":"udp","destination_ports":[68],"action":"accept"});
                if link.role != "lan" {
                    input.push(json!({"interface":link.name,"rules":[rule]}));
                }
            }
        }
        if sources.contains("") {
            sources = BTreeSet::from([String::new()]);
        }
        let nat: Vec<_> = sources
            .iter()
            .map(|source| {
                json!({
                    "family":"ipv4","source":source,"out_interface":wan
                })
            })
            .collect();
        config.firewall = serde_json::from_value(json!({
            "allow_all_icmp":false, "policy":"drop", "rules":[],
            "policies":{"hosts":[],"interfaces":forwarding},
            "input":{"policy":"drop","interfaces":input},
            "nat":{"masquerade":nat}
        }))?;
        for existing in &saved.interfaces {
            if existing.kind == "ethernet" && !names.contains(&existing.name) {
                let mut unused = existing.clone();
                unused.role = "unassigned".into();
                unused.up = false;
                unused.addresses.clear();
                unused.dhcp_relay = Default::default();
                config.interfaces.push(unused);
            }
        }
        config.validate()?;
        Ok(config.normalized())
    }

    pub fn apply(&self, engine: &mut netcontrol_core::Engine) -> Result<()> {
        ensure!(
            engine.is_initial_configuration(),
            "network provisioning requires an initial journal"
        );
        let config = self.candidate(engine.saved_configuration())?;
        engine.commit_initial_configuration(config)?;
        Ok(())
    }
}

fn ask(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: &str,
) -> Result<String> {
    write!(output, "{label} [{default}]: ")?;
    output.flush()?;
    let mut line = String::new();
    ensure!(
        input.read_line(&mut line)? != 0,
        "installation cancelled: input ended"
    );
    let value = line.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

fn choice(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: &str,
    values: &[&str],
) -> Result<String> {
    loop {
        let value = ask(input, output, label, default)?;
        if values.contains(&value.as_str()) {
            return Ok(value);
        }
        writeln!(output, "Choose {}.", values.join("/"))?;
    }
}

fn discover(directory: &Path, vlan_table: &Path) -> Result<Vec<PlannedInterface>> {
    let mut links = Vec::new();
    for entry in fs::read_dir(directory).context("list host interfaces")? {
        let entry = entry?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 interface name"))?;
        if path.join("device").is_dir()
            && !path.join("wireless").exists()
            && !path.join("phy80211").exists()
            && fs::read_to_string(path.join("type"))?.trim() == "1"
        {
            links.push(PlannedInterface {
                name,
                role: "unassigned".into(),
                vlan: None,
                ipv4: Addressing::None {},
            });
        }
    }
    links.sort_by(|a, b| a.name.cmp(&b.name));
    ensure!(
        !links.is_empty(),
        "at least one physical Ethernet interface is required"
    );
    if vlan_table.try_exists()? {
        let table = fs::read_to_string(vlan_table)?;
        let mut pending = Vec::new();
        for line in table.lines().skip(2) {
            let parts: Vec<_> = line.split('|').map(str::trim).collect();
            ensure!(parts.len() == 3, "invalid /proc/net/vlan/config row");
            let id = parts[1]
                .parse::<i64>()
                .context("invalid existing VLAN ID")?;
            pending.push(PlannedInterface {
                name: parts[0].into(),
                role: "unassigned".into(),
                vlan: Some(VLAN {
                    parent: parts[2].into(),
                    id,
                }),
                ipv4: Addressing::None {},
            });
        }
        while !pending.is_empty() {
            let Some(index) = pending.iter().position(|link| {
                link.vlan
                    .as_ref()
                    .is_some_and(|v| links.iter().any(|i| i.name == v.parent))
            }) else {
                bail!(
                    "existing VLAN has an unsupported parent or cyclic topology; correct it from the console before installing"
                );
            };
            links.push(pending.remove(index));
        }
    }
    Ok(links)
}

pub fn wizard(
    input: &mut impl BufRead,
    output: &mut impl Write,
    mut links: Vec<PlannedInterface>,
) -> Result<NetworkPlan> {
    writeln!(
        output,
        "IPv4 interface setup. All LANs are trusted for router access. LAN forwarding is allowed only to WAN.\nNo DHCP/DNS server is installed. Unassigned ports carry no IP; use them as VLAN parents.\nExisting networking/firewall will be replaced; IPv6 stays disabled. Use a local console."
    )?;
    for link in &links {
        writeln!(
            output,
            "  {}{}",
            link.name,
            link.vlan
                .as_ref()
                .map(|v| format!(" (VLAN {} on {})", v.id, v.parent))
                .unwrap_or_default()
        )?;
    }
    while choice(input, output, "Add a VLAN? yes/no", "no", &["yes", "no"])? == "yes" {
        ensure!(links.len() < 64, "at most 64 installer interfaces");
        let name = loop {
            let name = ask(input, output, "VLAN interface name", "")?;
            if valid_interface_name(&name) && !links.iter().any(|i| i.name == name) {
                break name;
            }
            writeln!(
                output,
                "Enter a unique valid Linux interface name (1..15 characters)."
            )?;
        };
        let parent = loop {
            let parent = ask(
                input,
                output,
                "Parent interface (physical or previously listed VLAN)",
                "",
            )?;
            if links.iter().any(|i| i.name == parent) {
                break parent;
            }
            writeln!(output, "Parent must be a listed interface.")?;
        };
        let id = loop {
            let value = ask(input, output, "VLAN ID (1..4094)", "")?;
            if let Ok(id) = value.parse::<i64>()
                && (1..=4094).contains(&id)
                && !links.iter().any(|i| {
                    i.vlan
                        .as_ref()
                        .is_some_and(|v| v.parent == parent && v.id == id)
                })
            {
                break id;
            }
            writeln!(
                output,
                "Enter an unused parent/ID pair; ID must be 1..4094."
            )?;
        };
        links.push(PlannedInterface {
            name,
            role: "unassigned".into(),
            vlan: Some(VLAN { parent, id }),
            ipv4: Addressing::None {},
        });
    }
    loop {
        for link in &mut links {
            writeln!(output, "\nInterface {}", link.name)?;
            link.role = choice(
                input,
                output,
                "Role wan/lan/unassigned",
                "unassigned",
                &["wan", "lan", "unassigned"],
            )?;
            if link.role == "unassigned" {
                link.ipv4 = Addressing::None {};
                continue;
            }
            let method = choice(
                input,
                output,
                "IPv4 dhcp/static",
                if link.role == "wan" { "dhcp" } else { "static" },
                &["dhcp", "static"],
            )?;
            link.ipv4 = if method == "dhcp" {
                Addressing::Dhcp {}
            } else {
                let address = loop {
                    let address = ask(
                        input,
                        output,
                        "IPv4 host/prefix",
                        if link.role == "lan" {
                            "192.168.0.1/24"
                        } else {
                            ""
                        },
                    )?;
                    match host_prefix(&address) {
                        Ok(_) => break address,
                        Err(error) => writeln!(output, "Invalid address: {error}")?,
                    }
                };
                let mut gateway = None;
                let mut dns = Vec::new();
                if link.role == "wan" {
                    gateway = Some(loop {
                        let value = ask(input, output, "WAN gateway IPv4 (on-link)", "")?;
                        if let Ok(ip) = value.parse::<Ipv4Addr>()
                            && usable_ip(ip)
                            && let Ok((host, prefix)) = host_prefix(&address)
                            && host != ip
                            && let Ok(gateway_subnet) = subnet(&format!("{ip}/{prefix}"))
                            && gateway_subnet == subnet(&address)?
                        {
                            break ip;
                        }
                        writeln!(output, "Enter a different usable on-link IPv4 gateway.")?;
                    });
                    dns = loop {
                        let value = ask(
                            input,
                            output,
                            "DNS IPv4 servers (space-separated, 1..8)",
                            "",
                        )?;
                        if let Ok(servers) = value
                            .split_whitespace()
                            .map(str::parse::<Ipv4Addr>)
                            .collect::<std::result::Result<Vec<_>, _>>()
                            && !servers.is_empty()
                            && servers.len() <= 8
                            && servers.iter().all(|ip| usable_ip(*ip))
                            && servers.iter().collect::<BTreeSet<_>>().len() == servers.len()
                        {
                            break servers;
                        }
                        writeln!(output, "Enter 1..8 unique unicast IPv4 DNS servers.")?;
                    };
                }
                Addressing::Static {
                    address,
                    gateway,
                    dns,
                }
            };
        }
        let management_interface = ask(
            input,
            output,
            "Management LAN interface (must have a private static IPv4)",
            "",
        )?;
        let plan = NetworkPlan {
            management_interface,
            interfaces: links.clone(),
        };
        if let Err(error) = plan.candidate(&Config::default()) {
            writeln!(
                output,
                "Invalid network plan: {error:#}\nReview interface roles and addressing again."
            )?;
            continue;
        }
        writeln!(
            output,
            "\nProposed network plan:\n{}",
            serde_json::to_string_pretty(&plan)?
        )?;
        writeln!(
            output,
            "Starter policy: router access from ALL LANs; LAN -> WAN only, IPv4 masquerade; unsolicited WAN input/forwarding dropped (DHCP replies allowed). Existing firewall rules are replaced.\nNo connectivity rollback. No DHCP/DNS server; clients need their own addressing and DNS."
        )?;
        ensure!(
            choice(
                input,
                output,
                "Apply this plan? yes/no",
                "no",
                &["yes", "no"]
            )? == "yes",
            "installation cancelled"
        );
        return Ok(plan);
    }
}

pub fn create_plan(path: &Path) -> Result<()> {
    let links = discover(
        Path::new("/sys/class/net"),
        Path::new("/proc/net/vlan/config"),
    )?;
    let plan = wizard(
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
        links,
    )?;
    plan.validate_host()?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("create new private network plan")?;
    serde_json::to_writer_pretty(&mut file, &plan)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> NetworkPlan {
        serde_json::from_value(json!({
            "management_interface":"lan50",
            "interfaces":[
                {"name":"eth0","role":"unassigned","vlan":null,"ipv4":{"method":"none"}},
                {"name":"wan20","role":"wan","vlan":{"parent":"eth0","id":20},"ipv4":{"method":"dhcp"}},
                {"name":"lan50","role":"lan","vlan":{"parent":"eth0","id":50},
                 "ipv4":{"method":"static","address":"192.168.50.1/24","gateway":null,"dns":[]}},
                {"name":"lan60","role":"lan","vlan":{"parent":"lan50","id":60},
                 "ipv4":{"method":"static","address":"10.60.0.1/24","gateway":null,"dns":[]}}
            ]
        })).unwrap()
    }

    #[test]
    fn shared_trunk_and_nested_vlans_get_explicit_lan_to_wan_policy() {
        let config = plan().candidate(&Config::default()).unwrap();
        assert_eq!(config.interfaces.len(), 4);
        assert!(!config.ipv6_enabled);
        assert_eq!(config.dhcp_clients.keys().collect::<Vec<_>>(), ["wan20"]);
        let firewall = serde_json::to_value(&config.firewall).unwrap();
        assert_eq!(firewall["policy"], "drop");
        assert_eq!(firewall["allow_all_icmp"], false);
        assert_eq!(firewall["input"]["policy"], "drop");
        assert_eq!(
            firewall["policies"]["interfaces"],
            json!([
                {"interface":"lan50","rules":[{"origin":"manual","import_source":null,"out_interface":"wan20","action":"accept"}]},
                {"interface":"lan60","rules":[{"origin":"manual","import_source":null,"out_interface":"wan20","action":"accept"}]}
            ])
        );
        assert_eq!(config.firewall.nat.masquerade.len(), 2);
        assert!(
            config
                .firewall
                .nat
                .masquerade
                .iter()
                .all(|rule| rule.out_interface == "wan20")
        );
        let input = config.firewall.input.unwrap();
        let wan = input
            .interfaces
            .iter()
            .find(|i| i.interface == "wan20")
            .unwrap();
        assert_eq!(wan.rules.len(), 1);
        assert_eq!(wan.rules[0].protocol, "udp");
        assert_eq!(wan.rules[0].destination_ports, [68]);
    }

    #[test]
    fn static_wan_replaces_imported_routes_dns_and_firewall_but_keeps_kernel_ownership() {
        let mut plan = plan();
        plan.interfaces[1].ipv4 = Addressing::Static {
            address: "198.51.100.2/24".into(),
            gateway: Some("198.51.100.1".parse().unwrap()),
            dns: vec!["192.0.2.53".parse().unwrap()],
        };
        plan.interfaces[3].ipv4 = Addressing::Dhcp {};
        let mut saved = plan.candidate(&Config::default()).unwrap();
        saved.firewall.policy = "accept".into();
        saved
            .kernel
            .host
            .insert("net.netfilter.nf_conntrack_max".into(), "131072".into());
        saved.interfaces.push(serde_json::from_value(json!({
            "name":"wifi0","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":["10.9.0.1/24"]
        })).unwrap());
        let config = plan.candidate(&saved).unwrap();
        assert_eq!(config.kernel, saved.kernel);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].gateway, "198.51.100.1");
        assert_eq!(config.dns["wan20"].servers, ["192.0.2.53"]);
        assert!(!config.dhcp_clients.contains_key("wan20"));
        assert!(config.dhcp_clients.contains_key("lan60"));
        assert_eq!(config.firewall.nat.masquerade.len(), 1);
        assert!(config.firewall.nat.masquerade[0].source.is_empty());
        assert_eq!(config.firewall.policy, "drop");
        let wifi = config
            .interfaces
            .iter()
            .find(|i| i.name == "wifi0")
            .unwrap();
        assert!(!wifi.up);
        assert!(wifi.addresses.is_empty());
        assert_eq!(wifi.role, "unassigned");
        assert!(
            !config
                .firewall
                .input
                .unwrap()
                .interfaces
                .iter()
                .any(|i| i.interface == "wan20")
        );
    }

    #[test]
    fn invalid_topology_addressing_and_unknown_fields_are_rejected() {
        let original = serde_json::to_value(plan()).unwrap();
        for (pointer, value) in [
            ("/interfaces/1/role", json!("lan")),
            ("/interfaces/2/role", json!("wan")),
            ("/interfaces/2/name", json!("eth0")),
            ("/interfaces/2/vlan/id", json!(4095)),
            ("/interfaces/2/vlan/id", json!(20)),
            ("/interfaces/2/vlan/parent", json!("missing")),
            ("/interfaces/2/vlan/parent", json!("lan60")),
            ("/interfaces/2/ipv4/address", json!("192.168.50.0/24")),
            ("/interfaces/2/ipv4/address", json!("192.168.50.255/24")),
            ("/interfaces/2/ipv4/address", json!("198.51.100.2/24")),
            ("/interfaces/3/ipv4/address", json!("192.168.50.2/24")),
            ("/interfaces/2/ipv4", json!({"method":"dhcp"})),
            ("/management_interface", json!("wan20")),
            ("/interfaces/1/ipv4", json!({"method":"none"})),
            (
                "/interfaces/1/ipv4",
                json!({"method":"static","address":"198.51.100.2/24","gateway":"203.0.113.1","dns":["192.0.2.53"]}),
            ),
            (
                "/interfaces/1/ipv4",
                json!({"method":"static","address":"198.51.100.2/24","gateway":"198.51.100.2","dns":["192.0.2.53"]}),
            ),
            (
                "/interfaces/1/ipv4",
                json!({"method":"static","address":"198.51.100.2/24","gateway":"198.51.100.1","dns":[]}),
            ),
        ] {
            let mut value_plan = original.clone();
            *value_plan.pointer_mut(pointer).unwrap() = value;
            let plan: NetworkPlan = serde_json::from_value(value_plan).unwrap();
            assert!(
                plan.candidate(&Config::default()).is_err(),
                "{pointer}: {plan:?}"
            );
        }
        let mut bad = original.clone();
        bad["unexpected"] = json!(true);
        assert!(serde_json::from_value::<NetworkPlan>(bad).is_err());
        let mut bad = original;
        bad["interfaces"][1]["ipv4"]["address"] = json!("192.0.2.1/24");
        assert!(serde_json::from_value::<NetworkPlan>(bad).is_err());
        let mut saved = plan().candidate(&Config::default()).unwrap();
        saved.interfaces[1].vlan.as_mut().unwrap().id = 21;
        assert!(plan().candidate(&saved).is_err());
    }

    #[test]
    fn wizard_creates_trunk_reprompts_bad_inputs_and_requires_confirmation() {
        let physical = vec![plan().interfaces[0].clone()];
        let input = concat!(
            "yes\nwan20\nmissing\neth0\n0\n20\n",
            "yes\nlan50\neth0\n20\n50\nno\n",
            "unassigned\nwan\ninvalid\ndhcp\nlan\nstatic\ninvalid\n192.168.50.1/24\nlan50\nyes\n"
        );
        let mut output = Vec::new();
        let result = wizard(&mut input.as_bytes(), &mut output, physical.clone()).unwrap();
        assert_eq!(result.interfaces.len(), 3);
        assert_eq!(result.management_interface, "lan50");
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Parent must be a listed interface"));
        assert!(output.contains("Invalid address"));
        assert!(output.contains("Existing firewall rules are replaced"));
        assert!(output.contains("Proposed network plan"));
        let declined = input.strip_suffix("yes\n").unwrap().to_owned() + "no\n";
        assert!(wizard(&mut declined.as_bytes(), &mut Vec::new(), physical.clone()).is_err());
        assert!(wizard(&mut &b""[..], &mut Vec::new(), physical).is_err());
    }

    #[test]
    fn wizard_static_wan_retries_invalid_gateway_and_dns() {
        let links = vec![
            PlannedInterface {
                name: "wan0".into(),
                role: "unassigned".into(),
                vlan: None,
                ipv4: Addressing::None {},
            },
            PlannedInterface {
                name: "lan0".into(),
                role: "unassigned".into(),
                vlan: None,
                ipv4: Addressing::None {},
            },
        ];
        let input = concat!(
            "no\nwan\nstatic\n198.51.100.2/24\n",
            "198.51.100.0\n203.0.113.1\n198.51.100.1\n",
            "invalid\n192.0.2.53 192.0.2.53\n192.0.2.53\n",
            "lan\nstatic\n192.168.10.1/24\nlan0\nyes\n"
        );
        let mut output = Vec::new();
        let result = wizard(&mut input.as_bytes(), &mut output, links).unwrap();
        let config = result.candidate(&Config::default()).unwrap();
        assert_eq!(config.routes[0].gateway, "198.51.100.1");
        assert_eq!(config.dns["wan0"].servers, ["192.0.2.53"]);
    }

    #[test]
    fn discovery_lists_single_physical_trunk_and_orders_existing_vlan_parents() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["eth0", "wifi0", "lo", "virtual0"] {
            let link = directory.path().join(name);
            fs::create_dir(&link).unwrap();
            fs::write(link.join("type"), "1\n").unwrap();
            if matches!(name, "eth0" | "wifi0") {
                fs::create_dir(link.join("device")).unwrap();
            }
            if name == "wifi0" {
                fs::create_dir(link.join("wireless")).unwrap();
            }
        }
        let table = directory.path().join("vlans");
        fs::write(&table, "VLAN Dev name | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\nnested | 60 | lan50\nlan50 | 50 | eth0\n").unwrap();
        let links = discover(directory.path(), &table).unwrap();
        assert_eq!(
            links.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            ["eth0", "lan50", "nested"]
        );
        fs::write(
            &table,
            "VLAN Dev name | VLAN ID\nName-Type: synthetic\nlan50 | 50 | missing\n",
        )
        .unwrap();
        assert!(discover(directory.path(), &table).is_err());
    }

    #[test]
    fn plan_commit_is_durable_and_refuses_a_second_install() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.json");
        let mut engine =
            netcontrol_core::Engine::open(&state, Box::new(netcontrol_core::Simulator::new()))
                .unwrap();
        let plan = plan();
        plan.apply(&mut engine).unwrap();
        assert_eq!(engine.saved_configuration().interfaces.len(), 4);
        assert!(plan.apply(&mut engine).is_err());
        engine.shutdown().unwrap();
        drop(engine);
        let engine =
            netcontrol_core::Engine::open(&state, Box::new(netcontrol_core::Simulator::new()))
                .unwrap();
        assert_eq!(engine.saved_configuration().interfaces.len(), 4);
        assert_eq!(engine.saved_configuration().firewall.policy, "drop");
    }
}
