use crate::Config;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BGPConfig {
    #[serde(skip_serializing_if = "crate::ObjectMetadata::is_empty")]
    pub metadata: crate::ObjectMetadata,
    pub enabled: bool,
    pub local_asn: u32,
    pub router_id: String,
    pub keepalive_seconds: u16,
    pub hold_seconds: u16,
    pub max_prefixes: usize,
    pub neighbors: Vec<BGPNeighbor>,
}

impl Default for BGPConfig {
    fn default() -> Self {
        Self {
            metadata: Default::default(),
            enabled: false,
            local_asn: 0,
            router_id: String::new(),
            keepalive_seconds: 30,
            hold_seconds: 90,
            max_prefixes: 4096,
            neighbors: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BGPNeighbor {
    #[serde(default, skip_serializing_if = "crate::ObjectMetadata::is_empty")]
    pub metadata: crate::ObjectMetadata,
    pub name: String,
    pub address: String,
    pub interface: String,
    pub local_address: String,
    pub remote_asn: u32,
    #[serde(default)]
    pub wireguard_public_key: String,
    #[serde(default)]
    pub accept_default: bool,
    #[serde(default = "default_multihop_ttl")]
    pub multihop_ttl: u8,
    #[serde(default)]
    pub allowed_next_hops: Vec<String>,
}

fn default_multihop_ttl() -> u8 {
    1
}

impl BGPConfig {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.neighbors.len() <= 32,
            "BGP supports at most 32 neighbors"
        );
        ensure!(
            (3..=65535).contains(&self.hold_seconds)
                && self.keepalive_seconds > 0
                && self.keepalive_seconds <= self.hold_seconds / 3,
            "BGP keepalive must be 1..hold_seconds/3; hold_seconds must be 3..65535"
        );
        ensure!(
            (1..=16384).contains(&self.max_prefixes),
            "BGP max_prefixes must be 1..16384 across all neighbors"
        );
        if self.enabled
            || !self.neighbors.is_empty()
            || self.local_asn != 0
            || !self.router_id.is_empty()
        {
            ensure!(
                valid_asn(self.local_asn),
                "BGP local_asn must be 1..4294967294, excluding AS_TRANS 23456 and reserved 65535"
            );
            let id: Ipv4Addr = self.router_id.parse()?;
            ensure!(
                unicast(id),
                "BGP router_id must be a nonzero unicast IPv4 address"
            );
        }
        ensure!(
            !self.enabled || !self.neighbors.is_empty(),
            "enabled BGP requires a neighbor"
        );
        let mut names = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for peer in &self.neighbors {
            ensure!(
                crate::valid_interface_name(&peer.name) && names.insert(&peer.name),
                "invalid or duplicate BGP neighbor name"
            );
            ensure!(valid_asn(peer.remote_asn), "invalid BGP remote_asn");
            let remote: Ipv4Addr = peer.address.parse()?;
            let local: Ipv4Addr = peer.local_address.parse()?;
            ensure!(peer.multihop_ttl > 0, "BGP multihop_ttl must be 1..255");
            ensure!(
                peer.allowed_next_hops.len() <= 32,
                "BGP supports at most 32 allowed_next_hops per neighbor"
            );
            ensure!(
                unicast(remote) && unicast(local) && remote != local && addresses.insert(remote),
                "BGP neighbor addresses must be unique unicast IPv4 addresses different from local_address"
            );
            let link = config
                .interfaces
                .iter()
                .find(|l| l.name == peer.interface)
                .ok_or_else(|| {
                    anyhow::anyhow!("BGP interface {} is not configured", peer.interface)
                })?;
            ensure!(link.up, "BGP interface must be configured up");
            ensure!(
                link.addresses
                    .iter()
                    .any(|a| a.split('/').next() == Some(peer.local_address.as_str())),
                "BGP local_address must be statically configured on the peering interface"
            );
            let mut next_hops = BTreeSet::new();
            for address in &peer.allowed_next_hops {
                let next_hop: Ipv4Addr = address.parse()?;
                ensure!(
                    unicast(next_hop) && next_hops.insert(next_hop),
                    "BGP allowed_next_hops must be unique unicast IPv4 addresses"
                );
                ensure!(
                    !config
                        .interfaces
                        .iter()
                        .flat_map(|i| &i.addresses)
                        .any(|a| {
                            crate::canonical_prefix(a, false)
                                .is_ok_and(|(ip, _)| ip == std::net::IpAddr::V4(next_hop))
                        }),
                    "BGP allowed_next_hops must not be the firewall's own addresses"
                );
            }
            if let Some(wg) = &link.wireguard {
                let wg_peer=wg.peers.iter().find(|p|p.enabled && p.public_key==peer.wireguard_public_key)
                    .ok_or_else(||anyhow::anyhow!("BGP WireGuard neighbor requires an enabled peer public key on its interface"))?;
                ensure!(
                    keys.insert((&peer.interface, &peer.wireguard_public_key)),
                    "one BGP neighbor per WireGuard peer is supported"
                );
                ensure!(
                    covers(&wg_peer.allowed_ips, remote),
                    "WireGuard static AllowedIPs must cover the BGP neighbor address to bootstrap peering"
                );
                for next_hop in next_hops {
                    ensure!(
                        covers(&wg_peer.allowed_ips, next_hop),
                        "BGP WireGuard allowed_next_hops must be covered by the referenced peer's static AllowedIPs"
                    );
                    ensure!(
                        !wg.peers.iter().any(|other| other.enabled
                            && other.public_key != peer.wireguard_public_key
                            && covers(&other.allowed_ips, next_hop)),
                        "BGP WireGuard allowed_next_hops must not overlap another enabled peer's static AllowedIPs"
                    );
                }
            } else {
                ensure!(
                    peer.wireguard_public_key.is_empty(),
                    "wireguard_public_key requires a WireGuard interface"
                );
                let direct = on_link(&link.addresses, remote);
                ensure!(
                    direct || peer.multihop_ttl > 1,
                    "routed BGP neighbor requires multihop_ttl greater than 1"
                );
                ensure!(
                    direct || !peer.allowed_next_hops.is_empty(),
                    "routed BGP neighbor requires explicit on-link allowed_next_hops"
                );
                for next_hop in next_hops {
                    ensure!(
                        on_link(&link.addresses, next_hop),
                        "BGP allowed_next_hops must be usable addresses directly connected on the selected interface"
                    );
                }
            }
        }
        Ok(())
    }
}

fn covers(prefixes: &[String], address: Ipv4Addr) -> bool {
    prefixes.iter().any(|prefix| {
        crate::canonical_prefix(prefix, true).is_ok_and(|(ip, length)| match ip {
            std::net::IpAddr::V4(ip) => contains(ip, length, address),
            _ => false,
        })
    })
}

fn on_link(addresses: &[String], candidate: Ipv4Addr) -> bool {
    addresses.iter().any(|prefix| {
        crate::canonical_prefix(prefix, false).is_ok_and(|(ip, length)| {
            let std::net::IpAddr::V4(ip) = ip else {
                return false;
            };
            if !contains(ip, length, candidate) {
                return false;
            }
            if length >= 31 {
                return true;
            }
            let mask = u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0);
            let network = u32::from(ip) & mask;
            let address = u32::from(candidate);
            address != network && address != (network | !mask)
        })
    })
}

pub fn valid_asn(asn: u32) -> bool {
    asn > 0 && asn < u32::MAX && asn != 23456 && asn != 65535
}
pub fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_loopback()
        && ip.octets()[0] < 224
}
pub fn contains(network: Ipv4Addr, length: u8, address: Ipv4Addr) -> bool {
    let mask = u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0);
    u32::from(network) & mask == u32::from(address) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_requires_explicit_identity_interface_and_safe_timers() {
        let mut c:Config=serde_json::from_value(serde_json::json!({
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.1/24"]}],
            "bgp":{"enabled":true,"local_asn":4200000001u32,"router_id":"192.0.2.1",
                "neighbors":[{"name":"edge","interface":"lan0","local_address":"192.0.2.1","address":"192.0.2.2","remote_asn":65002}]}
        })).unwrap();
        c.validate().unwrap();
        c.bgp.keepalive_seconds = 31;
        assert!(c.validate().is_err());
        c.bgp.keepalive_seconds = 30;
        c.bgp.neighbors[0].address = "198.51.100.1".into();
        assert!(c.validate().is_err());
        assert!(contains(
            "192.0.2.0".parse().unwrap(),
            24,
            "192.0.2.7".parse().unwrap()
        ));
        assert!(!contains(
            "192.0.2.0".parse().unwrap(),
            24,
            "192.0.3.7".parse().unwrap()
        ));
    }

    #[test]
    fn routed_peering_requires_explicit_ttl_and_usable_authorized_gateways() -> Result<()> {
        let mut c: Config = serde_json::from_value(serde_json::json!({
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.2/24"]}],
            "bgp":{"enabled":true,"local_asn":65004,"router_id":"192.0.2.2",
                "neighbors":[{"name":"remote","interface":"lan0","local_address":"192.0.2.2",
                    "address":"198.51.100.22","remote_asn":65000,"allowed_next_hops":["192.0.2.1"]}]}
        }))?;
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("multihop_ttl")
        );
        c.bgp.neighbors[0].multihop_ttl = 8;
        c.validate()?;
        c.bgp.neighbors[0].allowed_next_hops.clear();
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("allowed_next_hops")
        );
        for invalid in [
            vec!["192.0.2.2"],
            vec!["192.0.2.0"],
            vec!["192.0.2.255"],
            vec!["198.51.100.1"],
            vec!["127.0.0.1"],
            vec!["0.0.0.0"],
            vec!["224.0.0.1"],
            vec!["::1"],
            vec!["192.0.2.1", "192.0.2.1"],
        ] {
            c.bgp.neighbors[0].allowed_next_hops = invalid.into_iter().map(String::from).collect();
            assert!(c.validate().is_err(), "{:?}", c.bgp.neighbors[0]);
        }
        c.bgp.neighbors[0].allowed_next_hops = vec!["192.0.2.1".into()];
        c.bgp.neighbors[0].multihop_ttl = 0;
        assert!(c.validate().is_err());
        c.bgp.neighbors[0].multihop_ttl = 255;
        c.bgp.neighbors[0].allowed_next_hops = (1..=33).map(|n| format!("192.0.2.{n}")).collect();
        assert!(c.validate().is_err());
        c.bgp.neighbors[0].allowed_next_hops = vec!["192.0.2.1".into()];
        c.validate()?;

        c.interfaces[0].addresses = vec!["192.0.2.0/31".into()];
        c.bgp.neighbors[0].local_address = "192.0.2.0".into();
        c.validate()?;
        c.interfaces[0].addresses = vec!["192.0.2.2/32".into()];
        c.bgp.neighbors[0].local_address = "192.0.2.2".into();
        assert!(c.validate().is_err());

        Ok(())
    }

    #[test]
    fn wireguard_separates_speaker_and_next_hop_without_cross_peer_authorization() -> Result<()> {
        let example: serde_json::Value =
            serde_json::from_str(include_str!("../../../examples/bgp.json"))?;
        let mut c: Config = serde_json::from_value(example["config"].clone())?;
        c.validate()?;
        c.bgp.neighbors[0].allowed_next_hops.clear();
        c.validate()?;
        c.bgp.neighbors[0].address = "198.51.100.22".into();
        c.bgp.neighbors[0].multihop_ttl = 8;
        c.bgp.neighbors[0].allowed_next_hops = vec!["10.10.0.2".into()];
        let wg = c.interfaces[0].wireguard.as_mut().unwrap();
        wg.peers[0].allowed_ips.push("198.51.100.22/32".into());
        c.validate()?;
        // WireGuard uses peer ownership, not an Ethernet-subnet or ARP gateway.
        c.bgp.neighbors[0].allowed_next_hops = vec!["203.0.113.1".into()];
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("static AllowedIPs")
        );
        c.interfaces[0].wireguard.as_mut().unwrap().peers[0]
            .allowed_ips
            .push("203.0.113.1/32".into());
        c.validate()?;
        for invalid in [
            vec!["10.10.0.1"],
            vec!["127.0.0.1"],
            vec!["0.0.0.0"],
            vec!["224.0.0.1"],
            vec!["255.255.255.255"],
            vec!["::1"],
            vec!["10.10.0.2", "10.10.0.2"],
        ] {
            c.bgp.neighbors[0].allowed_next_hops = invalid.into_iter().map(String::from).collect();
            assert!(c.validate().is_err(), "{:?}", c.bgp.neighbors[0]);
        }
        c.bgp.neighbors[0].allowed_next_hops = vec!["10.10.0.2".into()];
        let mut other = c.interfaces[0].wireguard.as_ref().unwrap().peers[0].clone();
        other.public_key = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into();
        other.allowed_ips = vec!["10.10.0.0/29".into()];
        c.interfaces[0]
            .wireguard
            .as_mut()
            .unwrap()
            .peers
            .push(other);
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("another enabled peer")
        );
        c.interfaces[0].wireguard.as_mut().unwrap().peers[1].enabled = false;
        c.validate()?;
        c.interfaces[0].wireguard.as_mut().unwrap().peers[0]
            .allowed_ips
            .retain(|p| p != "198.51.100.22/32");
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("neighbor address")
        );
        Ok(())
    }
}
