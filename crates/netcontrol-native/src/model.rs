use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub const PROTOCOL: u8 = 242;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EthernetSnapshot {
    pub name: String,
    pub kind: String,
    pub index: u32,
    pub mac: String,
    pub mtu: u32,
    pub up: bool,
    pub boot: String,
    pub captured_unix: u64,
    pub addresses: Vec<Vec<u8>>,
}

pub fn ethernet_kind(kind: &str) -> bool {
    matches!(kind, "device" | "veth")
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub kind: String,
    pub role: String,
    pub mtu: u32,
    pub up: bool,
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<Vlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<Value>,
    #[serde(default)]
    pub dhcp_relay: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Vlan {
    pub parent: String,
    pub id: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub destination: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    pub interface: String,
    pub table: u32,
    pub metric: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rule {
    pub source: String,
    pub priority: u32,
    pub table: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Kernel {
    #[serde(default)]
    pub namespace: BTreeMap<String, String>,
    #[serde(default)]
    pub host: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Network {
    pub interfaces: Vec<Link>,
    pub routes: Vec<Route>,
    pub policy_rules: Vec<Rule>,
    pub firewall: Value,
    #[serde(default)]
    pub kernel: Kernel,
}

impl Network {
    pub fn parse(value: &Value) -> Result<Self> {
        let mut n: Self =
            serde_json::from_value(value.clone()).context("native network configuration")?;
        n.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        for link in &mut n.interfaces {
            link.addresses.sort();
        }
        n.routes.sort();
        n.policy_rules.sort();
        Ok(n)
    }

    pub fn validate(&self, parents: &BTreeSet<String>) -> Result<()> {
        let mut names = BTreeSet::new();
        for link in &self.interfaces {
            ensure!(
                crate::safe_name(&link.name, 15) && link.name != "lo",
                "invalid managed interface name"
            );
            ensure!(
                names.insert(link.name.clone()),
                "duplicate managed interface"
            );
            ensure!(
                !parents.contains(&link.name),
                "adopted parent {} is read-only",
                link.name
            );
            ensure!(
                matches!(link.role.as_str(), "wan" | "lan"),
                "interface role must be wan or lan"
            );
            ensure!((576..=65535).contains(&link.mtu), "invalid interface MTU");
            match link.kind.as_str() {
                "dummy" | "ethernet" => ensure!(
                    link.vlan.is_none() && link.wireguard.is_none(),
                    "Ethernet/dummy cannot have VLAN/WireGuard settings"
                ),
                "vlan" => {
                    let vlan = link.vlan.as_ref().context("VLAN requires parent and ID")?;
                    ensure!((1..=4094).contains(&vlan.id), "invalid VLAN ID");
                    ensure!(
                        link.wireguard.is_none(),
                        "VLAN cannot have WireGuard settings"
                    );
                }
                "wireguard" => {
                    ensure!(link.vlan.is_none(), "WireGuard cannot have VLAN settings");
                    let wg = link
                        .wireguard
                        .as_ref()
                        .context("WireGuard settings required")?;
                    ensure!(
                        crate::safe_name(
                            wg["key_ref"]
                                .as_str()
                                .context("WireGuard key_ref required")?,
                            64
                        ),
                        "invalid key reference"
                    );
                    ensure!(
                        wg["listen_port"].as_u64().is_some_and(|v| v <= 65535),
                        "invalid WireGuard listen port"
                    );
                    ensure!(wg["peers"].is_array(), "WireGuard peers required");
                }
                kind => bail!("unsupported native interface kind {kind}"),
            }
            let mut addresses = BTreeSet::new();
            for prefix in &link.addresses {
                let (ip, _) = parse_prefix(prefix, false)?;
                ensure!(
                    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(),
                    "managed address must be unicast"
                );
                ensure!(addresses.insert(prefix), "duplicate interface address");
            }
        }
        for link in &self.interfaces {
            if let Some(vlan) = &link.vlan {
                ensure!(
                    parents.contains(&vlan.parent) || names.contains(&vlan.parent),
                    "VLAN parent must be managed or explicitly adopted"
                );
            }
        }
        self.ordered_links()?;
        let mut routes = BTreeSet::new();
        for route in &self.routes {
            let (destination, _) = parse_prefix(&route.destination, true)?;
            ensure!(
                route.table == 254 || (10000..=19999).contains(&route.table),
                "route table must be main (254) or in owned range 10000..19999"
            );
            ensure!(
                names.contains(&route.interface) || parents.contains(&route.interface),
                "route interface must be managed or adopted"
            );
            ensure!(
                routes.insert((&route.destination, route.table, route.metric)),
                "duplicate route key"
            );
            if !route.gateway.is_empty() {
                let gateway: IpAddr = route
                    .gateway
                    .parse()
                    .context("invalid numeric route gateway")?;
                ensure!(
                    gateway.is_ipv4() == destination.is_ipv4()
                        && !gateway.is_unspecified()
                        && !gateway.is_multicast(),
                    "invalid gateway family/address"
                );
                ensure!(
                    gateway.to_string() == route.gateway,
                    "gateway must be canonical"
                );
            }
        }
        let mut priorities = BTreeSet::new();
        for rule in &self.policy_rules {
            let (source, _) = parse_prefix(&rule.source, true)?;
            ensure!(
                (rule.table == 254 || (10000..=19999).contains(&rule.table))
                    && (10000..=19999).contains(&rule.priority),
                "policy rule table/priority outside owned range"
            );
            ensure!(
                priorities.insert((source.is_ipv4(), rule.priority)),
                "duplicate policy rule priority"
            );
        }
        for (name, value) in &self.kernel.namespace {
            crate::tunables::validate(name, "namespace", value)?;
        }
        for (name, value) in &self.kernel.host {
            crate::tunables::validate(name, "host", value)?;
        }
        Ok(())
    }

    pub fn ordered_links(&self) -> Result<Vec<&Link>> {
        let mut remaining: Vec<_> = self.interfaces.iter().collect();
        let managed: BTreeSet<_> = self.interfaces.iter().map(|v| &v.name).collect();
        let mut done = BTreeSet::new();
        let mut result = Vec::new();
        while !remaining.is_empty() {
            let position = remaining.iter().position(|v| {
                v.vlan
                    .as_ref()
                    .is_none_or(|p| !managed.contains(&p.parent) || done.contains(&p.parent))
            });
            let Some(position) = position else {
                bail!("cyclic VLAN dependency");
            };
            let link = remaining.remove(position);
            done.insert(link.name.clone());
            result.push(link);
        }
        Ok(result)
    }
}

pub fn parse_prefix(value: &str, network: bool) -> Result<(IpAddr, u8)> {
    let net: IpNet = value.parse().context("invalid IP prefix")?;
    let (address, length) = value.split_once('/').context("missing prefix length")?;
    let ip: IpAddr = address.parse()?;
    let length: u8 = length.parse()?;
    ensure!(
        format!("{ip}/{length}") == value,
        "prefix must be canonical"
    );
    ensure!(
        !matches!(ip, IpAddr::V6(a) if a.to_ipv4_mapped().is_some()),
        "IPv4-mapped IPv6 is not supported"
    );
    if network {
        ensure!(net.network() == ip, "prefix must contain network address");
    }
    Ok((ip, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ethernet_vlan_and_main_routes_are_explicitly_supported() {
        let mut value = serde_json::json!({
            "interfaces":[
                {"name":"nic0","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":["192.0.2.2/24","2001:db8::2/64"]},
                {"name":"lan100","kind":"vlan","role":"lan","mtu":1400,"up":false,"addresses":[],"vlan":{"parent":"nic0","id":100}}
            ],
            "routes":[{"destination":"0.0.0.0/0","gateway":"192.0.2.1","interface":"nic0","table":254,"metric":100}],
            "policy_rules":[{"source":"192.0.2.0/24","table":254,"priority":10000}],
            "firewall":{}
        });
        Network::parse(&value)
            .unwrap()
            .validate(&BTreeSet::new())
            .unwrap();
        assert_eq!(
            Network::parse(&value).unwrap().ordered_links().unwrap()[0].name,
            "nic0"
        );
        value["routes"][0]["table"] = serde_json::json!(253);
        assert!(
            Network::parse(&value)
                .unwrap()
                .validate(&BTreeSet::new())
                .is_err()
        );
        value["routes"][0]["table"] = serde_json::json!(254);
        value["interfaces"][0]["vlan"] = serde_json::json!({"parent":"other0","id":1});
        assert!(
            Network::parse(&value)
                .unwrap()
                .validate(&BTreeSet::new())
                .is_err()
        );
    }

    #[test]
    fn ethernet_kind_and_durable_snapshot_are_lossless() {
        assert!(ethernet_kind("device") && ethernet_kind("veth"));
        for kind in ["dummy", "vlan", "wireguard", "bridge", "loopback"] {
            assert!(!ethernet_kind(kind));
        }
        let snapshot = EthernetSnapshot {
            name: "nic0".into(),
            kind: "veth".into(),
            index: 42,
            mac: "02:00:00:00:00:42".into(),
            mtu: 1500,
            up: false,
            boot: "synthetic-boot".into(),
            captured_unix: 1234,
            addresses: vec![vec![0, 1, 127, 128, 255]],
        };
        let decoded: EthernetSnapshot =
            serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn prefix_host_bits_and_families() {
        assert!(parse_prefix("192.0.2.4/24", false).is_ok());
        assert!(parse_prefix("192.0.2.4/24", true).is_err());
        assert!(parse_prefix("2001:db8::/64", true).is_ok());
        for value in [
            "192.0.2.0/033",
            "::ffff:192.0.2.1/128",
            "192.0.2.1",
            "../x",
            "2001:0db8::/64",
        ] {
            assert!(parse_prefix(value, false).is_err(), "{value}");
        }
    }
    #[test]
    fn no_unsupported_kind_succeeds() {
        let value = serde_json::json!({"interfaces":[{"name":"wg0","kind":"bridge","role":"lan","mtu":1420,"up":true,"addresses":[]}],"routes":[],"policy_rules":[],"firewall":{}});
        assert!(
            Network::parse(&value)
                .unwrap()
                .validate(&BTreeSet::new())
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
    }
    #[test]
    fn read_only_parent_is_not_managed() {
        let value = serde_json::json!({"interfaces":[{"name":"eth0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":[]}],"routes":[],"policy_rules":[],"firewall":{}});
        assert!(
            Network::parse(&value)
                .unwrap()
                .validate(&BTreeSet::from(["eth0".into()]))
                .is_err()
        );
    }
    #[test]
    fn network_fields_round_trip_without_losing_metadata() {
        let value = serde_json::json!({
            "interfaces":[
                {"name":"trunk0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":["192.0.2.2/24"],"dhcp_relay":{"enabled":false,"servers":[]}},
                {"name":"lan100","kind":"vlan","role":"lan","mtu":1400,"up":false,"addresses":[],"vlan":{"parent":"trunk0","id":100},"dhcp_relay":{"enabled":false,"servers":["198.51.100.10"]}}
            ],
            "routes":[{"destination":"203.0.113.0/24","gateway":"192.0.2.1","interface":"trunk0","table":10000,"metric":10}],
            "policy_rules":[{"source":"192.0.2.0/24","table":10000,"priority":10000}],
            "firewall":{"policy":"accept","allow_all_icmp":true,"rules":[],"nat":{"masquerade":[]}},
            "kernel":{"namespace":{"net.ipv4.tcp_syncookies":"1"},"host":{}}
        });
        let network = Network::parse(&value).unwrap();
        network.validate(&BTreeSet::new()).unwrap();
        let link = &network.interfaces[0];
        let round_trip: Link = serde_json::from_value(serde_json::to_value(link).unwrap()).unwrap();
        assert_eq!(round_trip, *link);
        assert_eq!(round_trip.role, "lan");
        assert_eq!(round_trip.dhcp_relay["servers"][0], "198.51.100.10");
        assert_eq!(network.ordered_links().unwrap()[0].name, "trunk0");
        let route: Route =
            serde_json::from_value(serde_json::to_value(&network.routes[0]).unwrap()).unwrap();
        assert_eq!(route, network.routes[0]);
    }
}
