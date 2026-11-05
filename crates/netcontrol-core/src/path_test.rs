use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, net::IpAddr};
use zeroize::Zeroizing;

pub const PATH_TEST_PORT: u16 = 49872;
pub const PATH_TEST_ARM_SECONDS: u64 = 30;
pub const PATH_TEST_RUN_SECONDS: u64 = 30;
pub const PATH_TEST_LIFETIME_SECONDS: u64 = 90;

fn port() -> u16 {
    PATH_TEST_PORT
}

fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathTestParent {
    pub interface: String,
    pub maximum_mtu: u32,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathTestRequest {
    pub interface: String,
    pub source_address: IpAddr,
    pub peer_address: IpAddr,
    #[serde(default = "port")]
    pub port: u16,
    pub maximum_mtu: u32,
    #[serde(default)]
    pub parents: Vec<PathTestParent>,
    #[serde(deserialize_with = "secret")]
    pub pairing_secret: Zeroizing<String>,
}

impl PathTestRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::valid_interface_name(&self.interface),
            "invalid test interface"
        );
        ensure!(
            self.source_address.is_ipv4() == self.peer_address.is_ipv4(),
            "source and peer must use the same address family"
        );
        for address in [self.source_address, self.peer_address] {
            ensure!(
                !address.is_unspecified() && !address.is_multicast() && !address.is_loopback(),
                "path tests require unicast non-loopback source and peer addresses"
            );
            ensure!(
                !matches!(address, IpAddr::V6(value) if value.is_unicast_link_local()),
                "IPv6 link-local addresses are not supported; use globally scoped or unique-local addresses"
            );
            ensure!(
                address != IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
                "broadcast is not a test peer"
            );
        }
        ensure!(
            self.source_address != self.peer_address,
            "peer must be a different address"
        );
        ensure!(
            (1024..=65535).contains(&self.port),
            "test port must be 1024..65535"
        );
        ensure!(
            (1280..=65535).contains(&self.maximum_mtu),
            "maximum MTU must be 1280..65535 bytes"
        );
        ensure!(
            self.parents.len() <= 8,
            "at most eight explicitly approved parent interfaces"
        );
        let mut names = BTreeSet::from([self.interface.as_str()]);
        for parent in &self.parents {
            ensure!(
                crate::valid_interface_name(&parent.interface) && names.insert(&parent.interface),
                "invalid or duplicate approved parent interface"
            );
            ensure!(
                (1280..=65535).contains(&parent.maximum_mtu),
                "parent maximum MTU must be 1280..65535 bytes"
            );
        }
        ensure!(
            (32..=128).contains(&self.pairing_secret.len())
                && self
                    .pairing_secret
                    .bytes()
                    .all(|value| value.is_ascii_graphic()),
            "pairing secret must be 32..128 non-space printable ASCII bytes; use a random one-time secret"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_test_requests_are_strict_and_bounded() {
        let valid = json!({"interface":"eth0","source_address":"192.0.2.1",
            "peer_address":"192.0.2.2","maximum_mtu":9000,
            "pairing_secret":"synthetic-pairing-secret-1234567890"});
        serde_json::from_value::<PathTestRequest>(valid.clone())
            .unwrap()
            .validate()
            .unwrap();
        for (field, value) in [
            ("peer_address", json!("224.0.0.1")),
            ("peer_address", json!("::1")),
            ("peer_address", json!("192.0.2.1")),
            ("maximum_mtu", json!(65536)),
            ("port", json!(80)),
            ("pairing_secret", json!("short")),
            ("parents", json!([{"interface":"eth0","maximum_mtu":9000}])),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                serde_json::from_value::<PathTestRequest>(invalid)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        let mut invalid = valid;
        invalid["unexpected"] = json!(true);
        assert!(serde_json::from_value::<PathTestRequest>(invalid).is_err());
    }

    #[test]
    fn path_test_limits_and_address_families_are_exact() {
        let valid = json!({"interface":"eth0","source_address":"192.0.2.1",
            "peer_address":"192.0.2.2","maximum_mtu":9000,
            "pairing_secret":"synthetic-pairing-secret-1234567890"});
        for (field, value) in [
            ("maximum_mtu", json!(1280)),
            ("maximum_mtu", json!(65535)),
            ("port", json!(1024)),
            ("port", json!(65535)),
            ("pairing_secret", json!("a".repeat(32))),
            ("pairing_secret", json!("a".repeat(128))),
            (
                "parents",
                json!(
                    (0..8)
                        .map(|id| json!({"interface":format!("p{id}"),"maximum_mtu":9000}))
                        .collect::<Vec<_>>()
                ),
            ),
        ] {
            let mut request = valid.clone();
            request[field] = value;
            serde_json::from_value::<PathTestRequest>(request)
                .unwrap()
                .validate()
                .unwrap();
        }
        for (field, value) in [
            ("maximum_mtu", json!(1279)),
            ("port", json!(1023)),
            ("pairing_secret", json!("a".repeat(31))),
            ("pairing_secret", json!("a".repeat(129))),
            ("pairing_secret", json!(format!("{} ", "a".repeat(32)))),
            (
                "parents",
                json!(
                    (0..9)
                        .map(|id| json!({"interface":format!("p{id}"),"maximum_mtu":9000}))
                        .collect::<Vec<_>>()
                ),
            ),
        ] {
            let mut request = valid.clone();
            request[field] = value;
            assert!(
                serde_json::from_value::<PathTestRequest>(request)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        let mut ipv6 = valid.clone();
        ipv6["source_address"] = json!("fd00::1");
        ipv6["peer_address"] = json!("fd00::2");
        serde_json::from_value::<PathTestRequest>(ipv6)
            .unwrap()
            .validate()
            .unwrap();
        let mut defaults = valid;
        defaults["pairing_secret"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<PathTestRequest>(defaults).is_err());
    }
}
