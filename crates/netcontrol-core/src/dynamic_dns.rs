use crate::Config;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicDNSAddressSource {
    Interface,
    PublicIp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicDNSConfig {
    #[serde(default)]
    pub metadata: crate::ObjectMetadata,
    pub name: String,
    pub enabled: bool,
    pub source_interface: String,
    pub address_source: DynamicDNSAddressSource,
    pub tenant_id: String,
    pub client_id: String,
    pub secret_ref: String,
    pub zone_resource_id: String,
    pub record_name: String,
    pub ttl_seconds: u32,
    pub interval_seconds: u64,
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl DynamicDNSConfig {
    pub fn zone_name(&self) -> Result<&str> {
        let parts: Vec<_> = self.zone_resource_id.split('/').collect();
        ensure!(
            parts.len() == 9
                && parts[0].is_empty()
                && parts[1] == "subscriptions"
                && uuid(parts[2])
                && parts[3] == "resourceGroups"
                && !parts[4].is_empty()
                && parts[4].len() <= 90
                && !parts[4].ends_with('.')
                && parts[4]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-()".contains(&b))
                && parts[5] == "providers"
                && parts[6] == "Microsoft.Network"
                && parts[7] == "dnszones"
                && dns_name(parts[8])
                && parts[8].contains('.'),
            "Azure zone_resource_id must identify a public Microsoft.Network/dnszones zone"
        );
        Ok(parts[8])
    }
}

pub(crate) fn validate(config: &Config) -> Result<()> {
    ensure!(
        config.dynamic_dns.len() <= 32,
        "at most 32 Dynamic DNS entries are allowed"
    );
    let mut names = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for entry in &config.dynamic_dns {
        ensure!(
            !entry.name.is_empty()
                && entry.name.len() <= 64
                && entry
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && names.insert(&entry.name),
            "Dynamic DNS names must be unique 1..64 ASCII letters, digits, underscores or hyphens"
        );
        ensure!(
            uuid(&entry.tenant_id) && uuid(&entry.client_id),
            "Dynamic DNS tenant_id and client_id must be UUIDs"
        );
        ensure!(
            entry.secret_ref.len() == 32
                && entry
                    .secret_ref
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Dynamic DNS secret_ref must be 32 lowercase hexadecimal characters"
        );
        let zone = entry.zone_name()?;
        ensure!(
            (entry.record_name == "@" || dns_name(&entry.record_name))
                && entry.record_name != zone
                && !entry.record_name.ends_with(&format!(".{zone}"))
                && (entry.record_name == "@" || entry.record_name.len() + zone.len() < 253),
            "Dynamic DNS record_name must be @ or a lowercase relative DNS name, not the FQDN"
        );
        ensure!(
            targets.insert((
                entry.zone_resource_id.to_ascii_lowercase(),
                &entry.record_name
            )),
            "Dynamic DNS entries cannot manage the same Azure A record"
        );
        ensure!(
            (30..=86400).contains(&entry.ttl_seconds)
                && (60..=86400).contains(&entry.interval_seconds),
            "Dynamic DNS TTL must be 30..86400 seconds and interval 60..86400 seconds"
        );
        ensure!(
            crate::valid_interface_name(&entry.source_interface),
            "invalid Dynamic DNS source interface"
        );
        if entry.enabled {
            ensure!(
                config
                    .interfaces
                    .iter()
                    .any(|i| i.name == entry.source_interface && i.up),
                "enabled Dynamic DNS requires an up managed source interface"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn entry() -> DynamicDNSConfig {
        serde_json::from_value(json!({
            "name":"azure-wan", "enabled":true, "source_interface":"wan0",
            "address_source":"public_ip",
            "tenant_id":"11111111-1111-4111-8111-111111111111",
            "client_id":"22222222-2222-4222-8222-222222222222",
            "secret_ref":"0123456789abcdef0123456789abcdef",
            "zone_resource_id":"/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com",
            "record_name":"home", "ttl_seconds":300, "interval_seconds":60
        })).unwrap()
    }

    fn config() -> Config {
        let mut config: Config = serde_json::from_value(json!({
            "interfaces":[{"name":"wan0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":[]}]
        })).unwrap();
        config.dynamic_dns.push(entry());
        config
    }

    #[test]
    fn dynamic_dns_schema_validation_and_native_isolation() {
        let config = config();
        config.validate().unwrap();
        let mut empty = config.clone();
        empty.dynamic_dns.clear();
        assert_eq!(
            config.operational_value().unwrap(),
            empty.operational_value().unwrap()
        );
        assert_ne!(config, empty);
        for name in ["@", "home", "vpn.home"] {
            let mut candidate = config.clone();
            candidate.dynamic_dns[0].record_name = name.into();
            candidate.validate().unwrap();
        }
        for name in [
            "",
            "example.com",
            "home.example.com",
            "../escape",
            "*",
            "UPPER",
            "a..b",
            "-host",
        ] {
            let mut candidate = config.clone();
            candidate.dynamic_dns[0].record_name = name.into();
            assert!(candidate.validate().is_err(), "{name}");
        }
        let mut candidate = config.clone();
        candidate.dynamic_dns.push(entry());
        assert!(candidate.validate().is_err());
        candidate.dynamic_dns[1].name = "second".into();
        assert!(candidate.validate().is_err());
        candidate.dynamic_dns[1].record_name = "second".into();
        candidate.validate().unwrap();
    }

    #[test]
    fn dynamic_dns_exact_bounds_and_required_fields() {
        let mut maximum = config();
        maximum.dynamic_dns = (0..32)
            .map(|index| {
                let mut entry = entry();
                entry.name = format!("entry-{index}");
                entry.record_name = format!("host-{index}");
                entry
            })
            .collect();
        maximum.validate().unwrap();
        maximum.dynamic_dns.push(entry());
        assert!(maximum.validate().is_err());
        for ttl in [30, 86400] {
            for interval in [60, 86400] {
                let mut candidate = config();
                candidate.dynamic_dns[0].ttl_seconds = ttl;
                candidate.dynamic_dns[0].interval_seconds = interval;
                candidate.validate().unwrap();
            }
        }
        for (field, value) in [
            ("ttl_seconds", json!(29)),
            ("ttl_seconds", json!(86401)),
            ("interval_seconds", json!(59)),
            ("interval_seconds", json!(86401)),
            ("tenant_id", json!("common")),
            ("client_id", json!("not-a-uuid")),
            ("secret_ref", json!("../secret")),
            ("zone_resource_id", json!("/bad")),
            ("source_interface", json!("missing")),
        ] {
            let mut value_config = serde_json::to_value(config()).unwrap();
            value_config["dynamic_dns"][0][field] = value;
            let candidate: Config = serde_json::from_value(value_config).unwrap();
            assert!(candidate.validate().is_err(), "{field}");
        }
        let value = serde_json::to_value(entry()).unwrap();
        for field in value.as_object().unwrap().keys() {
            if field == "metadata" {
                continue;
            }
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<DynamicDNSConfig>(missing).is_err(),
                "{field}"
            );
        }
        let mut inline = value;
        inline["client_secret"] = json!("synthetic-only");
        assert!(serde_json::from_value::<DynamicDNSConfig>(inline).is_err());
    }
}
