use crate::{Config, ObjectMetadata};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::Ipv4Addr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UDPRelaySource {
    #[default]
    Original,
    InterfaceAddress,
    InterfaceAddressAndPort,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UDPRelayInstance {
    pub id: u8,
    pub enabled: bool,
    pub port: u16,
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub multicast_address: Option<Ipv4Addr>,
    #[serde(default)]
    pub source: UDPRelaySource,
    #[serde(default, skip_serializing_if = "ObjectMetadata::is_empty")]
    pub metadata: ObjectMetadata,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UDPBroadcastRelayConfig {
    pub enabled: bool,
    pub instances: Vec<UDPRelayInstance>,
    #[serde(skip_serializing_if = "ObjectMetadata::is_empty")]
    pub metadata: ObjectMetadata,
}

impl UDPBroadcastRelayConfig {
    pub fn normalize(&mut self) {
        self.instances.sort_by_key(|instance| instance.id);
        for instance in &mut self.instances {
            instance.interfaces.sort();
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.instances.len() <= 63,
            "at most 63 UDP broadcast relay instances"
        );
        let mut ids = BTreeSet::new();
        let mut ports = BTreeSet::new();
        for instance in &self.instances {
            ensure!(
                (1..=63).contains(&instance.id) && ids.insert(instance.id),
                "UDP relay instance IDs must be unique in 1..63"
            );
            ensure!(
                instance.port > 0 && ports.insert(instance.port),
                "UDP relay ports must be nonzero and unique"
            );
            ensure!(
                (2..=32).contains(&instance.interfaces.len()),
                "UDP relay requires 2..32 interfaces"
            );
            let mut names = BTreeSet::new();
            for name in &instance.interfaces {
                ensure!(names.insert(name), "duplicate UDP relay interface {name}");
                let link = config.interfaces.iter().find(|link| link.name == *name);
                ensure!(
                    link.is_some_and(
                        |link| link.up && matches!(link.kind.as_str(), "ethernet" | "vlan")
                    ),
                    "UDP relay interface {name} must be a configured, up Ethernet/VLAN link"
                );
                let link = link.unwrap();
                ensure!(
                    config.dhcp_clients.contains_key(name)
                        || link
                            .addresses
                            .iter()
                            .any(|address| crate::canonical_prefix(address, false)
                                .is_ok_and(|(address, prefix)| address.is_ipv4() && prefix <= 30)),
                    "UDP relay interface {name} requires broadcast-capable IPv4 addressing"
                );
            }
            ensure!(
                instance
                    .multicast_address
                    .is_none_or(|address| address.is_multicast()),
                "UDP relay multicast_address must be an IPv4 multicast group"
            );
            if self.enabled && instance.enabled {
                ensure!(
                    !(config.mdns.enabled && instance.port == 5353),
                    "UDP relay port conflicts with enabled mDNS"
                );
                ensure!(
                    !(config.interfaces.iter().any(|link| link.dhcp_relay.enabled)
                        && instance.port == 67),
                    "UDP relay port conflicts with enabled DHCP relay"
                );
                ensure!(
                    config.dhcp_clients.is_empty() || instance.port != 68,
                    "UDP relay port conflicts with enabled DHCP clients"
                );
            }
        }
        ensure!(
            !self.enabled || self.instances.iter().any(|instance| instance.enabled),
            "enabled UDP broadcast relay requires an enabled instance"
        );
        Ok(())
    }
}

impl UDPRelayInstance {
    pub fn status(&self, enabled: bool, state: &str) -> Value {
        json!({"name":"udp-broadcast-relay","instance_id":self.id,"scope":"managed",
            "enabled":enabled,"state":state,"port":self.port,"interfaces":self.interfaces,
            "multicast_address":self.multicast_address,"source":self.source,
            "started_at":null,"collected_at":null,"error":null,
            "received_packets":"0","transmitted_packets":"0","received_bytes":"0",
            "transmitted_bytes":"0","policy_drops":"0","loop_drops":"0",
            "rate_limit_drops":"0","send_errors":"0","last_send_error":null,"last_send_error_at":null,
            "receive_drops":null,"statistics_complete":false,
            "limits":{"interfaces":32,"payload_bytes":65507,"packets_per_second":200,
                "burst":400,"poll_ms":100,"shutdown_ms":1000}})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        serde_json::from_value(json!({"interfaces":[
            {"name":"lan0","kind":"ethernet","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]},
            {"name":"iot0","kind":"ethernet","role":"lan","mtu":1500,"up":true,"addresses":["198.51.100.1/24"]}],
            "udp_broadcast_relay":{"enabled":true,"instances":[
                {"id":1,"enabled":true,"port":4001,"interfaces":["lan0","iot0"],"multicast_address":"239.255.255.250"},
                {"id":2,"enabled":true,"port":3610,"interfaces":["lan0","iot0"],"multicast_address":"224.0.23.0"}]}})).unwrap()
    }

    #[test]
    fn udp_relay_contract_validation_and_normalization() {
        let config = config();
        config.validate().unwrap();
        assert_eq!(
            config.udp_broadcast_relay.instances[0].source,
            UDPRelaySource::Original
        );
        assert!(!Config::default().udp_broadcast_relay.enabled);
        for invalid in [
            json!({"id":0}),
            json!({"port":0}),
            json!({"id":2}),
            json!({"port":3610}),
            json!({"interfaces":["lan0"]}),
            json!({"interfaces":["lan0","lan0"]}),
            json!({"interfaces":["lan0","missing"]}),
            json!({"multicast_address":"192.0.2.5"}),
            json!({"source":"1.1.1.1"}),
            json!({"extra":true}),
        ] {
            let mut value = serde_json::to_value(&config).unwrap();
            value["udp_broadcast_relay"]["instances"][0]
                .as_object_mut()
                .unwrap()
                .extend(invalid.as_object().unwrap().clone());
            assert!(
                serde_json::from_value::<Config>(value)
                    .and_then(|candidate| candidate.validate().map_err(serde::de::Error::custom))
                    .is_err(),
                "accepted {invalid}"
            );
        }
        for kind in ["dummy", "wireguard"] {
            let mut invalid = config.clone();
            invalid.interfaces[0].kind = kind.into();
            assert!(invalid.udp_broadcast_relay.validate(&invalid).is_err());
        }
        let mut normalized = config.clone();
        normalized.udp_broadcast_relay.instances.reverse();
        normalized.normalize();
        assert_eq!(
            normalized.udp_broadcast_relay.instances[0].interfaces,
            ["iot0", "lan0"]
        );
        let mut conflict = config.clone();
        conflict.mdns.enabled = true;
        conflict.udp_broadcast_relay.instances[0].port = 5353;
        assert!(conflict.udp_broadcast_relay.validate(&conflict).is_err());
        conflict.udp_broadcast_relay.enabled = false;
        conflict.udp_broadcast_relay.validate(&conflict).unwrap();
    }
}
