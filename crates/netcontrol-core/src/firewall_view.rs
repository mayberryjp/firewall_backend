use crate::{Config, Firewall, RuleOrigin, compile_spoof_block};
use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize)]
struct FirewallView<'a> {
    #[serde(flatten)]
    firewall: &'a Firewall,
    system_policies: Vec<SystemPolicy>,
}

#[derive(Serialize)]
struct SystemPolicy {
    id: &'static str,
    origin: RuleOrigin,
    read_only: bool,
    config_path: &'static str,
    enabled: bool,
    chains: Vec<SystemChain>,
}

#[derive(Serialize)]
struct SystemChain {
    name: String,
    hook: &'static str,
    priority: i32,
    policy: &'static str,
    rules: Vec<SystemRule>,
}

#[derive(Serialize)]
struct SystemRule {
    id: String,
    order: usize,
    counter_id: String,
    config_path: Option<&'static str>,
    action: String,
    matches: RuleMatch,
}

#[derive(Serialize)]
struct RuleMatch {
    family: &'static str,
    ingress_interface: String,
    source: Option<String>,
    destination: Option<String>,
    protocol: String,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    hop_limit: Option<u8>,
}

pub(crate) fn firewall_view(config: &Config) -> Result<serde_json::Value> {
    let plans = compile_spoof_block(
        &serde_json::to_value(&config.firewall)?,
        config
            .interfaces
            .iter()
            .filter(|link| link.role == "lan")
            .map(|link| (link.name.as_str(), link.addresses.as_slice())),
    )?;
    let mut chains = Vec::new();
    if !plans.is_empty() {
        for hook in ["input", "forward"] {
            let name = format!("{hook}_spoof_block");
            let mut rules = Vec::with_capacity(plans.len());
            for (order, plan) in plans.iter().enumerate() {
                let ipv4 = match plan.family {
                    Some(ipv4) => ipv4,
                    None => plan
                        .source
                        .parse::<ipnet::IpNet>()
                        .context("generated spoof-block rule has no address family")?
                        .addr()
                        .is_ipv4(),
                };
                rules.push(SystemRule {
                    id: format!("{name}:{order}"),
                    order,
                    counter_id: format!("{name}:{}", plan.counter_key),
                    config_path: plan
                        .counter_key
                        .starts_with('/')
                        .then_some("/firewall/spoof_block"),
                    action: plan.action.clone(),
                    matches: RuleMatch {
                        family: if ipv4 { "ipv4" } else { "ipv6" },
                        ingress_interface: plan.ingress.clone(),
                        source: (!plan.source.is_empty()).then(|| plan.source.clone()),
                        destination: (!plan.destination.is_empty())
                            .then(|| plan.destination.clone()),
                        protocol: if plan.protocol.is_empty() {
                            "any".into()
                        } else {
                            plan.protocol.clone()
                        },
                        source_port: (plan.source_port != 0).then_some(plan.source_port),
                        destination_port: (plan.port != 0).then_some(plan.port),
                        icmp_type: plan.icmpv6_type,
                        icmp_code: plan.icmpv6_type.map(|_| 0),
                        hop_limit: plan.hop_limit,
                    },
                });
            }
            chains.push(SystemChain {
                name,
                hook,
                priority: -1,
                policy: "accept",
                rules,
            });
        }
    }
    Ok(serde_json::to_value(FirewallView {
        firewall: &config.firewall,
        system_policies: vec![SystemPolicy {
            id: "spoof_block",
            origin: RuleOrigin::System,
            read_only: true,
            config_path: "/firewall/spoof_block",
            enabled: config.firewall.spoof_block,
            chains,
        }],
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn config() -> Config {
        serde_json::from_value(json!({
            "ipv6_enabled":true,
            "interfaces":[
                {"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,
                 "addresses":["192.0.2.1/24","192.0.2.2/24","2001:db8:1::1/64"]},
                {"name":"lan1","kind":"dummy","role":"lan","mtu":1500,"up":false,"addresses":[]},
                {"name":"wan0","kind":"dummy","role":"wan","mtu":1500,"up":true,
                 "addresses":["198.51.100.1/24"]}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn spoof_block_view_exposes_exact_ordered_matches_and_counter_links() {
        let config = config();
        let response = firewall_view(&config).unwrap();
        let policy = &response["system_policies"][0];
        assert_eq!(policy["id"], "spoof_block");
        assert_eq!(policy["origin"], "system");
        assert_eq!(policy["read_only"], true);
        assert_eq!(policy["config_path"], "/firewall/spoof_block");
        assert_eq!(policy["enabled"], true);
        let chains = policy["chains"].as_array().unwrap();
        assert_eq!(chains.len(), 2);
        // The extra IPv4 address adds an exact DHCP destination, not a duplicate subnet.
        for (hook, chain) in ["input", "forward"].into_iter().zip(chains) {
            let name = format!("{hook}_spoof_block");
            assert_eq!(chain["name"], name);
            assert_eq!(chain["hook"], hook);
            assert_eq!(chain["priority"], -1);
            assert_eq!(chain["policy"], "accept");
            let rules = chain["rules"].as_array().unwrap();
            assert_eq!(rules.len(), 50);
            for (order, rule) in rules.iter().enumerate() {
                assert_eq!(rule["order"], order);
                assert_eq!(rule["id"], format!("{name}:{order}"));
                assert_ne!(rule["matches"]["ingress_interface"], "wan0");
            }
            assert_eq!(
                rules[0],
                json!({
                    "id":format!("{name}:0"),"order":0,
                    "counter_id":format!("{name}:generated/spoof_block/lan0/local"),
                    "config_path":null,"action":"return",
                    "matches":{"family":"ipv4","ingress_interface":"lan0",
                        "source":"192.0.2.0/24","destination":null,"protocol":"any",
                        "source_port":null,"destination_port":null,
                        "icmp_type":null,"icmp_code":null,"hop_limit":null}
                })
            );
            let dhcp: Vec<_> = rules
                .iter()
                .filter(|rule| rule["matches"]["source_port"] == 68)
                .collect();
            assert_eq!(dhcp.len(), 4);
            assert!(dhcp.iter().all(|rule| rule["action"] == "return"
                && rule["matches"]["family"] == "ipv4"
                && rule["matches"]["source"] == "0.0.0.0/32"
                && rule["matches"]["protocol"] == "udp"
                && rule["matches"]["destination_port"] == 67));
            let dhcpv6: Vec<_> = rules
                .iter()
                .filter(|rule| rule["matches"]["source_port"] == 546)
                .collect();
            assert_eq!(dhcpv6.len(), 4);
            assert!(dhcpv6.iter().all(|rule| rule["action"] == "return"
                && rule["matches"]["family"] == "ipv6"
                && rule["matches"]["source"] == "fe80::/10"
                && rule["matches"]["protocol"] == "udp"
                && rule["matches"]["destination_port"] == 547));
            let control: Vec<_> = rules
                .iter()
                .filter(|rule| rule["matches"]["protocol"] == "icmpv6")
                .collect();
            assert_eq!(control.len(), 36);
            assert!(control.iter().all(|rule| rule["action"] == "return"
                && rule["matches"]["family"] == "ipv6"
                && rule["matches"]["icmp_code"] == 0
                && matches!(rule["matches"]["hop_limit"].as_u64(), Some(1 | 255))));
            for interface in ["lan0", "lan1"] {
                let interface_rules: Vec<_> = rules
                    .iter()
                    .filter(|rule| rule["matches"]["ingress_interface"] == interface)
                    .collect();
                for (offset, family) in ["ipv4", "ipv6"].into_iter().enumerate() {
                    let drop = interface_rules[interface_rules.len() - 2 + offset];
                    assert_eq!(drop["action"], "drop");
                    assert_eq!(drop["matches"]["family"], family);
                    assert_eq!(drop["matches"]["source"], Value::Null);
                    assert_eq!(drop["matches"]["destination"], Value::Null);
                    assert_eq!(drop["matches"]["protocol"], "any");
                    assert_eq!(drop["counter_id"], format!("{name}:/firewall/spoof_block"));
                    assert_eq!(drop["config_path"], "/firewall/spoof_block");
                }
            }
        }
    }

    #[test]
    fn spoof_block_view_is_read_only_and_tracks_disabled_empty_and_changed_lans() {
        let mut config = config();
        let before = serde_json::to_value(&config).unwrap();
        let mut response = firewall_view(&config).unwrap();
        response.as_object_mut().unwrap().remove("system_policies");
        assert_eq!(response, before["firewall"]);
        assert_eq!(serde_json::to_value(&config).unwrap(), before);
        let mut invalid_config = before.clone();
        invalid_config["firewall"] = firewall_view(&config).unwrap();
        assert!(serde_json::from_value::<Config>(invalid_config).is_err());
        config.firewall.spoof_block = false;
        let response = firewall_view(&config).unwrap();
        assert_eq!(response["system_policies"][0]["enabled"], false);
        assert_eq!(response["system_policies"][0]["chains"], json!([]));
        config.firewall.spoof_block = true;
        config.interfaces.clear();
        let response = firewall_view(&config).unwrap();
        assert_eq!(response["system_policies"][0]["enabled"], true);
        assert_eq!(response["system_policies"][0]["chains"], json!([]));
        config = serde_json::from_value(before).unwrap();
        config.interfaces[0].addresses = vec!["10.4.0.1/16".into()];
        let response = firewall_view(&config).unwrap();
        assert_eq!(
            response["system_policies"][0]["chains"][0]["rules"][0]["matches"]["source"],
            "10.4.0.0/16"
        );
        config.interfaces[0].role = "wan".into();
        let response = firewall_view(&config).unwrap();
        assert!(
            response["system_policies"][0]["chains"][0]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|rule| rule["matches"]["ingress_interface"] == "lan1")
        );
    }
}
