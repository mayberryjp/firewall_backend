use crate::{Config, ObjectMetadata};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MDNSInterfaceMode {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MDNSReflection {
    pub enabled: bool,
    pub filters: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MDNSPublishing {
    pub enabled: bool,
    pub hostname: String,
    pub domain: String,
    pub addresses: bool,
    pub hinfo: bool,
    pub workstation: bool,
    pub browse_domain: bool,
    pub aaaa_on_ipv4: bool,
    pub a_on_ipv6: bool,
}
impl Default for MDNSPublishing {
    fn default() -> Self {
        Self {
            enabled: false,
            hostname: String::new(),
            domain: "local.".into(),
            addresses: false,
            hinfo: false,
            workstation: false,
            browse_domain: false,
            aaaa_on_ipv4: false,
            a_on_ipv6: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MDNSConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "ObjectMetadata::is_empty")]
    pub metadata: ObjectMetadata,
    pub interface_mode: MDNSInterfaceMode,
    pub interfaces: Vec<String>,
    pub ipv4: bool,
    pub ipv6: bool,
    pub reflection: MDNSReflection,
    pub publishing: MDNSPublishing,
}
impl Default for MDNSConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            metadata: Default::default(),
            interface_mode: Default::default(),
            interfaces: Vec::new(),
            ipv4: true,
            ipv6: true,
            reflection: Default::default(),
            publishing: Default::default(),
        }
    }
}

fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn valid_mdns_name(s: &str) -> bool {
    s.len() <= 253
        && s.ends_with('.')
        && (s.eq_ignore_ascii_case("local.") || s.to_ascii_lowercase().ends_with(".local."))
        && s[..s.len() - 1].split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
}
impl MDNSConfig {
    pub fn effective_interfaces(&self, config: &Config) -> Vec<String> {
        let mut names: Vec<_> = config
            .interfaces
            .iter()
            .filter(|link| {
                link.up
                    && link.role == "lan"
                    && matches!(link.kind.as_str(), "ethernet" | "vlan")
                    && (self.interfaces.contains(&link.name)
                        == (self.interface_mode == MDNSInterfaceMode::Allow))
            })
            .map(|link| link.name.clone())
            .collect();
        names.sort();
        names
    }
    pub fn normalize(&mut self) {
        self.interfaces.sort();
        for filter in &mut self.reflection.filters {
            filter.make_ascii_lowercase();
        }
        self.reflection.filters.sort();
        self.publishing.domain.make_ascii_lowercase();
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.interfaces.len() <= 32,
            "mDNS supports at most 32 interface entries"
        );
        let mut names = BTreeSet::new();
        for name in &self.interfaces {
            ensure!(names.insert(name), "duplicate mDNS interface {name}");
            let link = config.interfaces.iter().find(|i| i.name == *name);
            ensure!(
                link.is_some_and(|i| matches!(i.kind.as_str(), "ethernet" | "vlan")),
                "mDNS interface {name} must be a configured Ethernet/VLAN link"
            );
            if self.interface_mode == MDNSInterfaceMode::Allow {
                ensure!(
                    link.is_some_and(|i| i.up && i.role == "lan"),
                    "mDNS allow interface {name} must be administratively up with role lan"
                );
            }
        }
        ensure!(
            self.reflection.filters.len() <= 64,
            "at most 64 mDNS filters"
        );
        let mut filters = BTreeSet::new();
        for filter in &self.reflection.filters {
            ensure!(
                valid_mdns_name(filter),
                "mDNS filters must be absolute local DNS names without patterns"
            );
            let lower = filter.to_ascii_lowercase();
            let labels: Vec<_> = lower.trim_end_matches('.').split('.').collect();
            let service = labels.len() >= 3
                && labels[0].starts_with('_')
                && matches!(labels[1], "_tcp" | "_udp");
            let subtype = labels.len() >= 5
                && labels[0].starts_with('_')
                && labels[1] == "_sub"
                && labels[2].starts_with('_')
                && matches!(labels[3], "_tcp" | "_udp");
            let host = labels.len() >= 2 && labels.iter().all(|label| !label.contains('_'));
            ensure!(
                service || subtype || host,
                "mDNS filter must identify a service type, subtype or provider hostname"
            );
            ensure!(filters.insert(lower), "duplicate mDNS filter");
        }
        let p = &self.publishing;
        ensure!(
            p.hostname.is_empty() || hostname(&p.hostname),
            "mDNS publishing hostname must be a lowercase hostname label"
        );
        ensure!(
            valid_mdns_name(&p.domain) && !p.domain.contains('_'),
            "mDNS publishing domain must be local. or an absolute subdomain"
        );
        ensure!(
            !p.aaaa_on_ipv4 || (self.ipv4 && p.addresses),
            "aaaa_on_ipv4 requires IPv4 transport and addresses"
        );
        ensure!(
            !p.a_on_ipv6 || (self.ipv6 && p.addresses),
            "a_on_ipv6 requires IPv6 preference and addresses"
        );
        if p.enabled {
            ensure!(
                p.addresses || p.hinfo || p.workstation || p.browse_domain,
                "enabled mDNS publishing needs a publication flag"
            );
            ensure!(
                !p.hostname.is_empty() || hostname(&config.system.hostname),
                "mDNS publishing requires an explicit hostname or valid system.hostname"
            );
            let effective = if p.hostname.is_empty() {
                &config.system.hostname
            } else {
                &p.hostname
            };
            ensure!(
                effective.len() + p.domain.len() < 253,
                "mDNS publishing hostname/domain is too long"
            );
            if p.workstation {
                ensure!(
                    effective.len() + "_workstation._tcp.".len() + p.domain.len() < 253
                        && "_services._dns-sd._udp.".len() + p.domain.len() <= 253,
                    "mDNS workstation instance or service enumeration name exceeds 253 bytes"
                );
            }
        }
        if self.enabled {
            ensure!(
                self.ipv4 || (self.ipv6 && config.ipv6_enabled),
                "mDNS requires an effective address family"
            );
            ensure!(
                self.reflection.enabled || p.enabled,
                "enabled mDNS needs reflection or publishing"
            );
            let count = self.effective_interfaces(config).len();
            ensure!(
                (if self.reflection.enabled { 2 } else { 1 }..=32).contains(&count),
                "mDNS requires 2..32 eligible links for reflection or 1..32 for publishing"
            );
        }
        Ok(())
    }
    pub fn status(&self, config: &Config, state: &str) -> Value {
        let mut value = json!({
            "name":"mdns","scope":"managed","enabled":self.enabled,"state":state,
            "started_at":null,"collected_at":null,"error":null,
            "effective_interfaces":self.effective_interfaces(config),
            "effective_families":[],
            "reflection_enabled":self.reflection.enabled,"publishing_enabled":self.publishing.enabled,
            "receive_drops":null,"statistics_complete":false,
            "warnings":if matches!(state, "disabled" | "simulated") {vec![]} else {vec!["receive_loss_accounting_unavailable"]},
            "limits":{"interfaces":32,"payload_bytes":9000,"records":512,"fingerprints":8192,
                "fingerprint_seconds":1,"association_seconds":120,"egress_payload_bytes":1232,
                "associations":8192,"requesters":1024,"requester_seconds":5,
                "packets_per_second":200,"burst":400,"queue_datagrams":256,"queue_bytes":2097152,
                "poll_ms":100,"shutdown_ms":1000}
        });
        let mut families = Vec::new();
        if self.ipv4 {
            families.push("ipv4");
        }
        if self.ipv6 && config.ipv6_enabled {
            families.push("ipv6");
        }
        value["effective_families"] = json!(families);
        for name in [
            "received_packets",
            "transmitted_packets",
            "received_bytes",
            "transmitted_bytes",
            "malformed_packets",
            "hop_limit_drops",
            "policy_drops",
            "duplicate_drops",
            "rate_limit_drops",
            "queue_drops",
            "oversize_drops",
            "unsupported_record_drops",
            "send_errors",
        ] {
            value[name] = json!("0");
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inactive_status_does_not_report_receive_loss_warnings() {
        let config = Config::default();
        for state in ["disabled", "simulated"] {
            let status = config.mdns.status(&config, state);
            assert_eq!(status["state"], state);
            assert_eq!(status["warnings"], json!([]));
            assert_eq!(status["statistics_complete"], false);
            assert_eq!(status["receive_drops"], Value::Null);
        }
        assert_eq!(
            config.mdns.status(&config, "running")["warnings"],
            json!(["receive_loss_accounting_unavailable"])
        );
    }

    fn config() -> Config {
        let mut c = Config::default();
        for name in ["lan1", "lan2", "wan"] {
            c.interfaces.push(crate::Interface {
                metadata: Default::default(),
                name: name.into(),
                kind: "ethernet".into(),
                role: if name == "wan" { "wan" } else { "lan" }.into(),
                mtu: 1500,
                up: true,
                addresses: Vec::new(),
                dhcp_relay: Default::default(),
                wireguard: None,
                vlan: None,
            });
        }
        c.mdns.enabled = true;
        c.mdns.reflection.enabled = true;
        c.mdns.interfaces = vec!["lan1".into(), "lan2".into()];
        c
    }
    #[test]
    fn membership_validation_and_normalization() {
        let mut c = config();
        c.mdns.reflection.filters = vec!["_IPP._tcp.LOCAL.".into(), "printer.local.".into()];
        c.normalize();
        c.validate().unwrap();
        assert_eq!(c.mdns.reflection.filters[0], "_ipp._tcp.local.");
        c.mdns.interfaces.push("wan".into());
        assert!(c.validate().is_err());
        c.mdns.interface_mode = MDNSInterfaceMode::Deny;
        c.mdns.interfaces = vec!["wan".into()];
        assert_eq!(c.mdns.effective_interfaces(&c), ["lan1", "lan2"]);
        c.validate().unwrap();
        c.ipv6_enabled = false;
        c.mdns.ipv4 = false;
        assert!(c.validate().is_err());
        c.mdns.enabled = false;
        c.validate().unwrap();
        c.mdns.reflection.filters.push("*.local.".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn publishing_operational_hostname_and_metadata() {
        let mut c = config();
        c.system.hostname = "appliance".into();
        c.mdns.publishing.enabled = true;
        c.mdns.publishing.addresses = true;
        c.mdns.metadata.display_name = "Discovery".into();
        c.validate().unwrap();
        let value = c.operational_value().unwrap();
        assert_eq!(value["mdns"]["publishing"]["hostname"], "appliance");
        assert!(value["mdns"].get("metadata").is_none());
        assert_eq!(c.mdns.publishing.hostname, "");
        c.system.domain = "example.test".into();
        assert_eq!(c.operational_value().unwrap(), value);
        c.system.hostname = "changed".into();
        assert_eq!(
            c.operational_value().unwrap()["mdns"]["publishing"]["hostname"],
            "changed"
        );
        c.system.hostname.clear();
        assert!(c.validate().is_err());
        assert!(
            serde_json::to_value(Config::default())
                .unwrap()
                .get("mdns")
                .is_some()
        );
    }
    #[test]
    fn transactions_committed_reads_status_permissions_restore_and_repair() {
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("mdns-engine-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.json");
        let mut engine = crate::Engine::open(&path, Box::new(crate::Simulator::new())).unwrap();
        let all = crate::PERMISSIONS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>();
        let restricted = all
            .iter()
            .filter(|p| p.as_str() != "mdns.write")
            .cloned()
            .collect::<Vec<_>>();
        let candidate = config();
        let body = serde_json::to_vec(
            &json!({"base_revision":0,"confirm_timeout_seconds":30,"config":candidate}),
        )
        .unwrap();
        assert_eq!(
            engine
                .request(
                    "POST",
                    "/api/v1/transactions",
                    "",
                    "operator",
                    &restricted,
                    &body
                )
                .status,
            403
        );
        let reply = engine.request("POST", "/api/v1/transactions", "", "operator", &all, &body);
        assert_eq!(reply.status, 202, "{}", reply.body);
        let id = reply.body["id"].as_str().unwrap().to_owned();
        let read = engine.request("GET", "/api/v1/services/mdns", "", "operator", &all, &[]);
        assert_eq!(read.body["enabled"], false);
        let status = engine.request(
            "GET",
            "/api/v1/services/mdns/status",
            "",
            "operator",
            &all,
            &[],
        );
        assert_eq!(status.body["instances"][0]["state"], "simulated");
        assert_eq!(status.body["instances"][0]["received_packets"], "0");
        for service in [
            "mdns",
            "ntp",
            "syslog",
            "vnstat",
            "softflowd",
            "dhcp-relay",
            "gateway-monitoring",
        ] {
            let path = format!("/api/v1/services/{service}/reconcile");
            assert_eq!(
                engine
                    .request("POST", &path, "", "operator", &restricted, &[])
                    .status,
                403
            );
        }
        for path in ["/api/v1/services/mdns", "/api/v1/services/mdns/status"] {
            assert_eq!(
                engine
                    .request("GET", path, "ignored=1", "operator", &all, &[])
                    .status,
                400
            );
        }
        assert_eq!(
            engine
                .request(
                    "POST",
                    "/api/v1/services/mdns/reconcile",
                    "ignored=1",
                    "operator",
                    &all,
                    &[]
                )
                .status,
            400
        );
        assert_eq!(
            engine
                .request(
                    "POST",
                    "/api/v1/services/mdns/reconcile",
                    "",
                    "operator",
                    &all,
                    b"{}"
                )
                .status,
            400
        );
        assert_eq!(
            engine
                .request(
                    "POST",
                    "/api/v1/services/mdns/reconcile",
                    "",
                    "operator",
                    &all,
                    &[]
                )
                .status,
            200
        );
        assert_eq!(
            engine
                .request(
                    "POST",
                    &format!("/api/v1/transactions/{id}/confirm"),
                    "",
                    "operator",
                    &all,
                    &[]
                )
                .status,
            200
        );
        let read = engine.request("GET", "/api/v1/services/mdns", "", "operator", &all, &[]);
        assert_eq!(read.body, serde_json::to_value(&candidate.mdns).unwrap());
        let body =
            serde_json::to_vec(&json!({"base_revision":1,"confirm_timeout_seconds":30})).unwrap();
        assert_eq!(
            engine
                .request(
                    "POST",
                    "/api/v1/revisions/0/restore",
                    "",
                    "operator",
                    &restricted,
                    &body
                )
                .status,
            403
        );
        let reply = engine.request(
            "POST",
            "/api/v1/revisions/0/restore",
            "",
            "operator",
            &all,
            &body,
        );
        assert_eq!(reply.status, 202, "{}", reply.body);
        let id = reply.body["id"].as_str().unwrap();
        assert_eq!(
            engine
                .request("GET", "/api/v1/services/mdns", "", "operator", &all, &[])
                .body["enabled"],
            true
        );
        assert_eq!(
            engine
                .request(
                    "POST",
                    &format!("/api/v1/transactions/{id}/rollback"),
                    "",
                    "operator",
                    &all,
                    &[]
                )
                .status,
            200
        );
        engine.shutdown().unwrap();
        drop(engine);
        let mut engine = crate::Engine::open(&path, Box::new(crate::Simulator::new())).unwrap();
        assert_eq!(
            engine
                .request("GET", "/api/v1/services/mdns", "", "operator", &all, &[])
                .body["enabled"],
            true
        );
        engine.shutdown().unwrap();
        drop(engine);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn strict_limits_duplicates_and_disabled_validation() {
        let mut c = config();
        c.mdns.interfaces.push("lan1".into());
        assert!(c.validate().is_err());
        c.mdns.interfaces.pop();
        c.mdns.reflection.filters = vec!["printer.local.".into(), "PRINTER.local.".into()];
        assert!(c.validate().is_err());
        c.mdns.reflection.filters = vec!["x.local.".into(); 65];
        assert!(c.validate().is_err());
        c.mdns.reflection.filters.clear();
        c.mdns.enabled = false;
        c.mdns.publishing.domain = "example.com.".into();
        assert!(c.validate().is_err());
        c.mdns.publishing.domain = "local.".into();
        c.mdns.publishing.aaaa_on_ipv4 = true;
        assert!(c.validate().is_err());
        c.mdns.publishing.addresses = true;
        c.validate().unwrap();
        let firewall = c.firewall.clone();
        c.mdns.enabled = true;
        c.validate().unwrap();
        assert_eq!(
            firewall, c.firewall,
            "mDNS must not insert implicit firewall accepts"
        );
        c.mdns.publishing.enabled = true;
        c.mdns.publishing.hostname = "a".into();
        c.mdns.publishing.workstation = true;
        c.mdns.publishing.domain = format!(
            "{}.{}.{}.{}.local.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(48)
        );
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("workstation")
        );
    }
}
