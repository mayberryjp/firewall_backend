use crate::{Config, FilterProtocol, FirewallHost, HostPolicyRule, RuleOrigin};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SandoPolicyOutcome {
    pub imported_count: u32,
    pub skipped_count: u32,
    pub changed: bool,
}

#[derive(Clone, Debug)]
pub struct SandoHost {
    pub addresses: Vec<std::net::IpAddr>,
    pub host_name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SandoHostOutcome {
    pub added_count: u32,
    pub skipped_count: u32,
    pub changed: bool,
}

pub(crate) fn host_candidate(
    config: &Config,
    hosts: &[SandoHost],
) -> Result<(Config, SandoHostOutcome)> {
    ensure!(hosts.len() <= 4096, "Sando exceeds 4096 hosts");
    let mut next = config.clone();
    let mut outcome = SandoHostOutcome::default();
    let mut policies = config.firewall.policies.clone().unwrap_or_default();
    for host in hosts {
        let addresses: Vec<_> = host
            .addresses
            .iter()
            .filter(|ip| {
                crate::global_unicast(**ip)
                    && crate::canonical_ip(&ip.to_string()).is_ok()
                    && (ip.is_ipv4() || config.ipv6_enabled)
            })
            .map(ToString::to_string)
            .collect();
        let Some(primary) = addresses.first() else {
            outcome.skipped_count += 1;
            continue;
        };
        let owners: Vec<_> = policies
            .hosts
            .iter()
            .filter(|existing| {
                existing
                    .addresses
                    .iter()
                    .any(|address| addresses.contains(address))
            })
            .collect();
        if !owners.is_empty() {
            if owners.len() != 1
                || !addresses
                    .iter()
                    .all(|address| owners[0].addresses.contains(address))
            {
                outcome.skipped_count += 1;
            }
            continue;
        }
        let id = format!("sando_{}", primary.replace([':', '.'], "_"));
        let mut name = host
            .host_name
            .as_deref()
            .unwrap_or(primary)
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();
        while name.len() > 80 {
            name.pop();
        }
        name = name.trim_end().to_owned();
        if name.is_empty() || policies.hosts.iter().any(|existing| existing.name == name) {
            name = primary.clone();
        }
        if policies
            .hosts
            .iter()
            .any(|existing| existing.id == id || existing.name == name)
        {
            outcome.skipped_count += 1;
            continue;
        }
        policies.hosts.push(FirewallHost {
            metadata: Default::default(),
            id,
            name,
            addresses,
            policy: "drop".into(),
            rules: Vec::new(),
        });
        outcome.added_count += 1;
    }
    if outcome.added_count > 0 {
        ensure!(
            config.firewall.rules.is_empty(),
            "Sando host sync requires host policies; remove legacy forwarding rules through a reviewed transaction"
        );
        next.firewall.policies = Some(policies);
        next.validate()?;
        outcome.changed = true;
    }
    Ok((next, outcome))
}

fn integer(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        let text = value.as_str()?;
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    })
}

fn policy_rule(entry: &Value) -> Option<(std::net::IpAddr, HostPolicyRule)> {
    let source = entry
        .get("src_ip")?
        .as_str()?
        .parse::<std::net::IpAddr>()
        .ok()?;
    let destination_text = entry.get("dst_ip")?.as_str()?;
    let destination = if destination_text == "*" {
        if source.is_ipv4() {
            "0.0.0.0/0".into()
        } else {
            "::/0".into()
        }
    } else {
        let destination = crate::canonical_ip(destination_text).ok()?;
        if !crate::global_unicast(destination) || source.is_ipv4() != destination.is_ipv4() {
            return None;
        }
        format!(
            "{destination}/{}",
            if destination.is_ipv4() { 32 } else { 128 }
        )
    };
    if !crate::global_unicast(source)
        || crate::canonical_ip(entry.get("src_ip")?.as_str()?).is_err()
    {
        return None;
    }
    let protocol = match integer(entry.get("protocol")?)? {
        6 => FilterProtocol::Tcp,
        17 => FilterProtocol::Udp,
        1 => FilterProtocol::Icmp,
        58 => FilterProtocol::Icmpv6,
        _ => return None,
    };
    if !protocol.matches_family(source) {
        return None;
    }
    let port_value = entry.get("dst_port")?;
    let destination_ports = match protocol {
        _ if port_value.as_str() == Some("*") => vec![],
        FilterProtocol::Tcp | FilterProtocol::Udp => {
            let port = integer(port_value)?;
            if !(1..=65535).contains(&port) {
                return None;
            }
            vec![port]
        }
        FilterProtocol::Icmp | FilterProtocol::Icmpv6 if integer(port_value) == Some(0) => vec![],
        _ => return None,
    };
    Some((
        source,
        HostPolicyRule {
            origin: RuleOrigin::Import,
            import_source: Some("sando".into()),
            metadata: Default::default(),
            out_interface: String::new(),
            destination_host: String::new(),
            destination,
            protocol: match protocol {
                FilterProtocol::Tcp => "tcp",
                FilterProtocol::Udp => "udp",
                FilterProtocol::Icmp => "icmp",
                FilterProtocol::Icmpv6 => "icmpv6",
                FilterProtocol::Any => return None,
            }
            .into(),
            destination_ports,
            action: "accept".into(),
        },
    ))
}

fn sando_owned(rule: &HostPolicyRule) -> bool {
    rule.origin == RuleOrigin::Import && rule.import_source.as_deref() == Some("sando")
}

fn same_match(left: &HostPolicyRule, right: &HostPolicyRule) -> bool {
    left.out_interface == right.out_interface
        && left.destination_host == right.destination_host
        && left.destination == right.destination
        && left.protocol == right.protocol
        && left.destination_ports == right.destination_ports
        && left.action == right.action
}

pub(crate) fn policy_candidate(
    config: &Config,
    entries: &[Value],
) -> Result<(Config, SandoPolicyOutcome)> {
    ensure!(entries.len() <= 4096, "Sando exceeds 4096 policy entries");
    let mut next = config.clone();
    let mut outcome = SandoPolicyOutcome::default();
    let Some(policies) = next.firewall.policies.as_mut() else {
        ensure!(
            entries.is_empty(),
            "No replacement rules could be imported; existing rules were retained"
        );
        return Ok((next, outcome));
    };
    let mut replacements = vec![Vec::new(); policies.hosts.len()];
    let mut supported = false;
    for entry in entries {
        let mapped = policy_rule(entry).and_then(|(source, rule)| {
            if source.is_ipv6() && !config.ipv6_enabled {
                return None;
            }
            let index = policies.hosts.iter().position(|host| {
                host.addresses
                    .iter()
                    .any(|address| address.parse() == Ok(source))
            })?;
            Some((index, rule))
        });
        if let Some((index, rule)) = mapped {
            supported = true;
            if replacements[index]
                .iter()
                .any(|existing| same_match(existing, &rule))
                || policies.hosts[index]
                    .rules
                    .iter()
                    .any(|existing| !sando_owned(existing) && same_match(existing, &rule))
            {
                outcome.skipped_count += 1;
            } else {
                replacements[index].push(rule);
                outcome.imported_count += 1;
            }
        } else {
            outcome.skipped_count += 1;
        }
    }
    ensure!(
        entries.is_empty() || supported,
        "No replacement rules could be imported; existing rules were retained"
    );
    for (host, mut rules) in policies.hosts.iter_mut().zip(replacements) {
        if !host.rules.iter().any(sando_owned) && rules.is_empty() {
            continue;
        }
        let mut retained: Vec<_> = host
            .rules
            .iter()
            .filter(|rule| !sando_owned(rule))
            .cloned()
            .collect();
        retained.sort_by_key(|rule| rule.origin != RuleOrigin::Manual);
        // Keep unchanged permits in their saved order, independent of upstream query ordering.
        for old in host.rules.iter().filter(|rule| sando_owned(rule)) {
            if let Some(index) = rules.iter().position(|rule| same_match(old, rule)) {
                rules.remove(index);
                retained.push(old.clone());
            }
        }
        retained.extend(rules);
        host.rules = retained;
    }
    next.validate()?;
    Ok((next, outcome))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandoConfig {
    pub api_url: String,
    pub sync_enabled: bool,
    pub policy_sync_enabled: bool,
    pub hosts_import: Option<SandoImportState>,
    pub rules_import: Option<SandoImportState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandoImportState {
    pub source_url: String,
    pub import_count: u32,
    pub last_import_at: DateTime<Utc>,
    pub status: SandoImportStatus,
    pub imported_count: u32,
    pub skipped_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandoImportStatus {
    Succeeded,
    Partial,
}

fn validate_url(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 2048
            && (value.starts_with("http://") || value.starts_with("https://"))
            && !value.contains('\\')
            && !value.chars().any(|c| c.is_whitespace() || c.is_control()),
        "Sando URL must be an absolute http:// or https:// base URL of 1..2048 bytes without whitespace, control characters or backslashes"
    );
    let (_, remainder) = value
        .split_once("://")
        .context("Sando URL requires an HTTP scheme")?;
    let authority = remainder
        .split('/')
        .next()
        .context("Sando URL requires a host")?;
    ensure!(
        !authority.is_empty() && !authority.contains('@'),
        "Sando URL requires a host without credentials"
    );
    let url = url::Url::parse(value)?;
    ensure!(
        url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.port() != Some(0)
            && url.query().is_none()
            && url.fragment().is_none(),
        "Sando URL requires a host and must not contain credentials, query parameters, fragments or port zero"
    );
    Ok(())
}

impl SandoConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !(self.sync_enabled || self.policy_sync_enabled) || !self.api_url.is_empty(),
            "Sando sync requires a configured api_url"
        );
        if !self.api_url.is_empty() {
            validate_url(&self.api_url)?;
        }
        for state in [&self.hosts_import, &self.rules_import]
            .into_iter()
            .flatten()
        {
            validate_url(&state.source_url)?;
            ensure!(
                state.import_count > 0,
                "Sando import_count must be 1..4294967295"
            );
            ensure!(
                (1970..=9999).contains(&state.last_import_at.year()),
                "Sando last_import_at must be an RFC3339 timestamp in years 1970..9999"
            );
            ensure!(
                match state.status {
                    SandoImportStatus::Succeeded => state.skipped_count == 0,
                    SandoImportStatus::Partial =>
                        state.imported_count > 0 && state.skipped_count > 0,
                },
                "Sando succeeded imports require zero skipped items; partial imports require both imported and skipped items"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn automatic_hosts_use_browser_identity_defaults_and_preserve_existing_hosts() {
        let config: Config = serde_json::from_value(json!({
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
            "firewall":{"policies":{"hosts":[
                {"id":"manual","name":"Camera","addresses":["192.0.2.10"],"policy":"accept","rules":[{"action":"drop"}]}
            ]}}
        })).unwrap();
        let hosts = [
            SandoHost {
                addresses: vec!["192.0.2.10".parse().unwrap()],
                host_name: Some("Changed name".into()),
            },
            SandoHost {
                addresses: vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()],
                host_name: None,
            },
            SandoHost {
                addresses: vec![
                    "192.0.2.20".parse().unwrap(),
                    "2001:db8::20".parse().unwrap(),
                ],
                host_name: Some("Camera".into()),
            },
            SandoHost {
                addresses: vec!["fe80::20".parse().unwrap()],
                host_name: None,
            },
        ];
        let (next, outcome) = host_candidate(&config, &hosts).unwrap();
        assert_eq!((outcome.added_count, outcome.skipped_count), (1, 2));
        assert!(outcome.changed);
        let policies = next.firewall.policies.as_ref().unwrap();
        assert_eq!(
            policies.hosts[0],
            config.firewall.policies.as_ref().unwrap().hosts[0]
        );
        assert_eq!(policies.hosts[1].id, "sando_192_0_2_20");
        assert_eq!(policies.hosts[1].name, "192.0.2.20");
        assert_eq!(policies.hosts[1].addresses, ["192.0.2.20"]);
        assert_eq!(policies.hosts[1].policy, "drop");
        assert!(policies.hosts[1].rules.is_empty());
        assert_eq!(host_candidate(&next, &hosts).unwrap().0, next);
        assert!(!host_candidate(&next, &[]).unwrap().1.changed);
        assert_eq!(host_candidate(&next, &[]).unwrap().0, next);
    }

    #[test]
    fn automatic_hosts_support_dual_stack_names_and_fail_atomic_configuration_limits() {
        let config = Config {
            ipv6_enabled: true,
            ..Default::default()
        };
        let host = SandoHost {
            addresses: vec![
                "192.0.2.20".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
            ],
            host_name: Some(format!(" {} ", "\u{754c}".repeat(40))),
        };
        let (mut next, _) = host_candidate(&config, &[host]).unwrap();
        let added = &next.firewall.policies.as_ref().unwrap().hosts[0];
        assert_eq!(added.addresses.len(), 2);
        assert!(added.name.len() <= 80);
        let hosts = (1..=129)
            .map(|index| SandoHost {
                addresses: vec![format!("198.51.100.{index}").parse().unwrap()],
                host_name: None,
            })
            .collect::<Vec<_>>();
        assert!(
            host_candidate(&next, &hosts)
                .unwrap_err()
                .to_string()
                .contains("128 hosts")
        );
        next.firewall.policies = None;
        next.firewall.rules =
            serde_json::from_value(json!([{"source":"192.0.2.0/24","action":"accept"}])).unwrap();
        assert!(
            host_candidate(&next, &hosts[..1])
                .unwrap_err()
                .to_string()
                .contains("legacy forwarding")
        );
    }

    #[test]
    fn automatic_policies_skip_unsupported_entries_without_broadening_sources() {
        let config: Config = serde_json::from_value(json!({
            "ipv6_enabled":true,
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
            "firewall":{"policies":{"hosts":[
                {"id":"camera","name":"Camera","addresses":["192.0.2.10","2001:db8::10"],"policy":"drop","rules":[]},
                {"id":"multiple","name":"Multiple addresses","addresses":["192.0.2.20","192.0.2.21"],"policy":"drop","rules":[]}
            ]}}
        })).unwrap();
        let good =
            json!({"src_ip":"192.0.2.10","dst_ip":"198.51.100.20","protocol":"6","dst_port":"443"});
        let mut entries = vec![
            good.clone(),
            json!({"src_ip":"2001:db8::10","dst_ip":"2001:db8::20","protocol":58,"dst_port":0}),
            good.clone(),
        ];
        for (field, invalid) in [
            ("src_ip", json!("*")),
            ("src_ip", json!("192.0.2.99")),
            ("dst_ip", json!("198.51.100.0/24")),
            ("dst_ip", json!("2001:db8::20")),
            ("dst_ip", json!("224.0.0.1")),
            ("protocol", json!("*")),
            ("protocol", json!(47)),
            ("protocol", json!(58)),
            ("dst_port", json!(0)),
            ("dst_port", json!(65536)),
            ("dst_port", json!(true)),
            ("dst_port", Value::Null),
        ] {
            let mut entry = good.clone();
            entry[field] = invalid;
            entries.push(entry);
        }
        entries.push(
            json!({"src_ip":"192.0.2.10","dst_ip":"198.51.100.20","protocol":1,"dst_port":53}),
        );
        entries.push(
            json!({"src_ip":"192.0.2.10","dst_ip":"198.51.100.20","protocol":1,"dst_port":0}),
        );
        let (next, outcome) = policy_candidate(&config, &entries).unwrap();
        assert_eq!(outcome.imported_count, 3);
        assert_eq!(outcome.skipped_count as usize, entries.len() - 3);
        let policies = next.firewall.policies.unwrap();
        assert_eq!(policies.hosts[0].rules[0].destination_ports, [443]);
        assert_eq!(policies.hosts[0].rules[1].protocol, "icmpv6");
        assert!(policies.hosts[0].rules[1].destination_ports.is_empty());
        assert_eq!(policies.hosts[0].rules[2].protocol, "icmp");
        assert!(policies.hosts[1].rules.is_empty());
    }

    #[test]
    fn browser_wildcards_and_portless_icmp_map_without_inventing_wildcards() {
        for (source, destination, expected) in [
            ("192.0.2.10", "*", "0.0.0.0/0"),
            ("2001:db8::10", "*", "::/0"),
            ("192.0.2.10", "198.51.100.20", "198.51.100.20/32"),
        ] {
            for protocol in [6, 17, if source.contains(':') { 58 } else { 1 }] {
                let (_, rule) = policy_rule(&json!({
                    "src_ip":source,"dst_ip":destination,"protocol":protocol,"dst_port":"*"
                }))
                .unwrap();
                assert_eq!(rule.destination, expected);
                assert!(rule.destination_ports.is_empty());
                let zero = json!({"src_ip":source,"dst_ip":destination,"protocol":protocol,"dst_port":"0"});
                assert_eq!(policy_rule(&zero).is_some(), matches!(protocol, 1 | 58));
                for invalid in [Value::Null, json!(""), json!("any"), json!(false)] {
                    let mut entry = zero.clone();
                    entry["dst_port"] = invalid;
                    assert!(policy_rule(&entry).is_none());
                }
            }
        }
        assert!(
            policy_rule(&json!({"src_ip":"*","dst_ip":"*","protocol":6,"dst_port":"*"})).is_none()
        );
    }

    #[test]
    fn browser_replacement_deduplicates_retained_rules_and_preserves_saved_permit_order() {
        let config: Config = serde_json::from_value(json!({
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
            "firewall":{"policies":{"hosts":[
                {"id":"camera","name":"Camera","addresses":["192.0.2.10","192.0.2.11"],"policy":"drop","rules":[
                    {"origin":"import","import_source":"other","destination":"198.51.100.20/32","protocol":"tcp","destination_ports":[443],"action":"accept"},
                    {"destination":"198.51.100.30/32","protocol":"udp","destination_ports":[53],"action":"accept"},
                    {"origin":"import","import_source":"sando","destination":"0.0.0.0/0","protocol":"icmp","action":"accept"},
                    {"origin":"import","import_source":"sando","destination":"198.51.100.40/32","protocol":"tcp","destination_ports":[443],"action":"accept"}
                ]}
            ]}}
        })).unwrap();
        let entries = [
            json!({"src_ip":"192.0.2.11","dst_ip":"198.51.100.40","protocol":6,"dst_port":443}),
            json!({"src_ip":"192.0.2.10","dst_ip":"*","protocol":1,"dst_port":0}),
            json!({"src_ip":"192.0.2.10","dst_ip":"198.51.100.20","protocol":6,"dst_port":443}),
            json!({"src_ip":"192.0.2.10","dst_ip":"198.51.100.30","protocol":17,"dst_port":53}),
        ];
        let (next, outcome) = policy_candidate(&config, &entries).unwrap();
        assert_eq!((outcome.imported_count, outcome.skipped_count), (2, 2));
        let mut expected = config.clone();
        expected.firewall.policies.as_mut().unwrap().hosts[0]
            .rules
            .swap(0, 1);
        assert_eq!(next, expected);
        let reversed: Vec<_> = entries.into_iter().rev().collect();
        assert_eq!(policy_candidate(&next, &reversed).unwrap().0, next);
        assert_eq!(
            policy_candidate(&next, &reversed[0..1])
                .unwrap()
                .1
                .imported_count,
            0
        );
        assert!(
            policy_candidate(
                &next,
                &[json!({"src_ip":"*","dst_ip":"*","protocol":6,"dst_port":"*"})]
            )
            .is_err()
        );
        let (empty, _) = policy_candidate(&next, &[]).unwrap();
        assert_eq!(empty.firewall.policies.unwrap().hosts[0].rules.len(), 2);
    }

    fn config() -> SandoConfig {
        serde_json::from_value(json!({
            "api_url":"https://sando.example.test/proxy",
            "hosts_import":{
                "source_url":"http://192.0.2.10:8044",
                "import_count":2,
                "last_import_at":"2026-10-30T00:00:00Z",
                "status":"partial",
                "imported_count":3,
                "skipped_count":1
            }
        }))
        .unwrap()
    }

    #[test]
    fn defaults_and_confirmed_import_records_roundtrip_without_losing_source() {
        assert_eq!(
            serde_json::to_value(SandoConfig::default()).unwrap(),
            json!({"api_url":"","sync_enabled":false,"policy_sync_enabled":false,"hosts_import":null,"rules_import":null})
        );
        let config = config();
        config.validate().unwrap();
        assert_eq!(config.rules_import, None);
        assert_eq!(
            serde_json::from_value::<SandoConfig>(serde_json::to_value(&config).unwrap()).unwrap(),
            config
        );
        let mut disconnected = config;
        disconnected.api_url.clear();
        disconnected.validate().unwrap();
        assert_eq!(
            disconnected.hosts_import.unwrap().source_url,
            "http://192.0.2.10:8044"
        );
    }

    #[test]
    fn url_validation_accepts_browser_reachable_bases_not_credentials_or_request_data() {
        for valid in [
            "http://192.0.2.10:8044",
            "https://sando.example.test",
            "https://sando.example.test/proxy/",
            "http://[2001:db8::10]:8044",
        ] {
            validate_url(valid).unwrap();
        }

        for invalid in [
            "",
            "sando.example.test",
            "//sando.example.test",
            "ftp://sando.example.test",
            "http:///sando.example.test",
            "http://user:password@sando.example.test",
            "http://user@sando.example.test",
            "http://sando.example.test:0",
            "http://sando.example.test:65536",
            "http://sando.example.test?token=synthetic",
            "http://sando.example.test#fragment",
            " http://sando.example.test",
            "http://sando.example.test/\n",
            "http://sando.example.test\\path",
        ] {
            assert!(validate_url(invalid).is_err(), "{invalid}");
        }
        assert!(validate_url(&format!("https://sando.example.test/{}", "x".repeat(2048))).is_err());
    }

    #[test]
    fn sync_requires_a_url_and_a_boolean_flag() {
        let mut config = SandoConfig {
            sync_enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.api_url = "https://sando.example.test/proxy".into();
        config.validate().unwrap();
        for invalid in [json!(null), json!("true"), json!(1)] {
            assert!(
                serde_json::from_value::<SandoConfig>(json!({"sync_enabled":invalid})).is_err()
            );
            assert!(
                serde_json::from_value::<SandoConfig>(json!({"policy_sync_enabled":invalid}))
                    .is_err()
            );
        }
        config.sync_enabled = false;
        config.policy_sync_enabled = true;
        config.api_url.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn import_records_reject_invalid_types_missing_fields_and_inconsistent_outcomes() {
        let baseline = serde_json::to_value(config()).unwrap();
        for (field, invalid) in [
            ("import_count", json!(0)),
            ("last_import_at", json!("1969-12-31T23:59:59Z")),
            ("status", json!("succeeded")),
            ("imported_count", json!(0)),
            ("skipped_count", json!(0)),
            ("source_url", json!("javascript:alert(1)")),
        ] {
            let mut value = baseline.clone();
            value["hosts_import"][field] = invalid;
            assert!(
                serde_json::from_value::<SandoConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        for (field, invalid) in [
            ("status", json!("failed")),
            ("last_import_at", json!("2026-02-29")),
            ("import_count", json!(-1)),
            ("import_count", json!(4294967296u64)),
            ("import_count", json!("2")),
            ("imported_count", json!(1.5)),
        ] {
            let mut value = baseline.clone();
            value["hosts_import"][field] = invalid;
            assert!(
                serde_json::from_value::<SandoConfig>(value).is_err(),
                "{field}"
            );
        }
        let mut missing = baseline.clone();
        missing["hosts_import"]
            .as_object_mut()
            .unwrap()
            .remove("source_url");
        assert!(serde_json::from_value::<SandoConfig>(missing).is_err());
        let mut success = baseline;
        success["hosts_import"]["status"] = json!("succeeded");
        success["hosts_import"]["skipped_count"] = json!(0);
        success["hosts_import"]["imported_count"] = json!(0);
        serde_json::from_value::<SandoConfig>(success)
            .unwrap()
            .validate()
            .unwrap();
    }
}
