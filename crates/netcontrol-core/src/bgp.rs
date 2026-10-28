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
            if let Some(wg) = &link.wireguard {
                let wg_peer=wg.peers.iter().find(|p|p.enabled && p.public_key==peer.wireguard_public_key)
                    .ok_or_else(||anyhow::anyhow!("BGP WireGuard neighbor requires an enabled peer public key on its interface"))?;
                ensure!(
                    keys.insert((&peer.interface, &peer.wireguard_public_key)),
                    "one BGP neighbor per WireGuard peer is supported"
                );
                ensure!(
                    wg_peer.allowed_ips.iter().any(|prefix| {
                        crate::canonical_prefix(prefix, true).is_ok_and(|(ip, len)| match ip {
                            std::net::IpAddr::V4(ip) => contains(ip, len, remote),
                            _ => false,
                        })
                    }),
                    "WireGuard static AllowedIPs must cover the BGP neighbor address to bootstrap peering"
                );
            } else {
                ensure!(
                    peer.wireguard_public_key.is_empty(),
                    "wireguard_public_key requires a WireGuard interface"
                );
                ensure!(
                    link.addresses.iter().any(|prefix| {
                        crate::canonical_prefix(prefix, false).is_ok_and(|(ip, len)| match ip {
                            std::net::IpAddr::V4(ip) => contains(ip, len, remote),
                            _ => false,
                        })
                    }),
                    "BGP neighbor must be directly connected on the selected interface"
                );
            }
        }
        Ok(())
    }
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
}
