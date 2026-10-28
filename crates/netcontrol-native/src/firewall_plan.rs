use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Match {
    pub source: String,
    pub destination: String,
    pub ingress: String,
    pub egress: String,
    pub protocol: String,
    pub port: u16,
    pub action: String,
    pub established_related: bool,
}

pub fn destination_rewrites(
    firewall: &Value,
) -> Result<Vec<netcontrol_core::DestinationRewriteRule>> {
    let Some(value) = firewall["nat"].get("destination_rewrite") else {
        return Ok(vec![]);
    };
    let rules: Vec<netcontrol_core::DestinationRewriteRule> =
        serde_json::from_value(value.clone()).context("destination rewrite rules")?;
    ensure!(rules.len() <= 256, "at most 256 destination rewrite rules");
    let mut matches = std::collections::BTreeSet::new();
    for rule in &rules {
        let target: IpAddr = rule.target_address.parse()?;
        ensure!(
            target.to_string() == rule.target_address
                && netcontrol_core::global_unicast(target)
                && crate::safe_name(&rule.out_interface, 15)
                && crate::safe_name(&rule.target_interface, 15)
                && rule.out_interface != rule.target_interface
                && matches!(rule.protocol.as_str(), "tcp" | "udp")
                && rule.destination_port != 0,
            "invalid destination rewrite rule"
        );
        ensure!(
            matches.insert((
                &rule.out_interface,
                &rule.protocol,
                rule.destination_port,
                target.is_ipv4()
            )),
            "duplicate destination rewrite match"
        );
    }
    Ok(rules)
}
fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .with_context(|| format!("firewall {key} must be an array"))
}
fn action(value: &str) -> Result<()> {
    ensure!(
        matches!(value, "accept" | "drop"),
        "firewall action must be accept/drop"
    );
    Ok(())
}
fn host_prefix(value: &str) -> Result<String> {
    let ip: IpAddr = value.parse()?;
    ensure!(
        ip.to_string() == value && !ip.is_multicast() && !ip.is_unspecified(),
        "invalid firewall host address"
    );
    Ok(format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
}

pub fn compile(firewall: &Value) -> Result<Vec<Match>> {
    destination_rewrites(firewall)?;
    action(string(firewall, "policy"))?;
    ensure!(
        firewall["allow_all_icmp"].is_boolean(),
        "allow_all_icmp must be explicit boolean"
    );
    let mut output = Vec::new();
    let rules = array(firewall, "rules")?;
    if let Some(policies) = firewall.get("policies").filter(|v| !v.is_null()) {
        ensure!(
            rules.is_empty(),
            "cannot combine ordered rules and host/interface policies"
        );
        let mut hosts = BTreeMap::new();
        for host in array(policies, "hosts")? {
            let id = string(host, "id");
            ensure!(
                !id.is_empty() && hosts.insert(id, host).is_none(),
                "duplicate firewall host ID"
            );
            action(string(host, "policy"))?;
        }
        output.push(Match {
            action: "accept".into(),
            established_related: true,
            ..Match::default()
        });
        for interface in array(policies, "interfaces")? {
            let ingress = string(interface, "interface");
            ensure!(
                crate::safe_name(ingress, 15),
                "invalid firewall ingress interface"
            );
            for rule in array(interface, "rules")? {
                expand(&mut output, rule, &["".into()], ingress, &hosts)?;
            }
        }
        for host in array(policies, "hosts")? {
            let sources = array(host, "addresses")?
                .iter()
                .map(|a| host_prefix(a.as_str().context("host address must be string")?))
                .collect::<Result<Vec<_>>>()?;
            for rule in array(host, "rules")? {
                expand(&mut output, rule, &sources, "", &hosts)?;
            }
            for source in sources {
                output.push(Match {
                    source,
                    action: string(host, "policy").into(),
                    ..Match::default()
                });
            }
            ensure!(output.len() <= 4096, "firewall expands beyond 4096 rules");
        }
    } else {
        for rule in rules {
            let source = string(rule, "source").to_string();
            let destination = string(rule, "destination").to_string();
            for prefix in [&source, &destination]
                .into_iter()
                .filter(|v| !v.is_empty())
            {
                crate::model::parse_prefix(prefix, true)?;
            }
            if !source.is_empty() && !destination.is_empty() {
                ensure!(
                    crate::model::parse_prefix(&source, true)?.0.is_ipv4()
                        == crate::model::parse_prefix(&destination, true)?.0.is_ipv4(),
                    "firewall source/destination family mismatch"
                );
            }
            action(string(rule, "action"))?;
            output.push(Match {
                source,
                destination,
                action: string(rule, "action").into(),
                ..Match::default()
            });
        }
    }
    for nat in array(&firewall["nat"], "masquerade")? {
        let family = string(nat, "family");
        ensure!(
            matches!(family, "ipv4" | "ipv6"),
            "invalid masquerade family"
        );
        ensure!(
            crate::safe_name(string(nat, "out_interface"), 15),
            "invalid masquerade interface"
        );
        let source = string(nat, "source");
        if !source.is_empty() {
            ensure!(
                crate::model::parse_prefix(source, true)?.0.is_ipv4() == (family == "ipv4"),
                "masquerade source family mismatch"
            );
        }
    }
    ensure!(output.len() <= 4096, "firewall expands beyond 4096 rules");
    Ok(output)
}

pub fn compile_input(firewall: &Value) -> Result<Vec<Match>> {
    let Some(input) = firewall.get("input").filter(|value| !value.is_null()) else {
        return Ok(vec![]);
    };
    action(string(input, "policy"))?;
    for interface in array(input, "interfaces")? {
        for rule in array(interface, "rules")? {
            ensure!(
                string(rule, "out_interface").is_empty()
                    && string(rule, "destination_host").is_empty(),
                "input rules cannot match egress interfaces or destination hosts"
            );
        }
    }
    let mut plans = compile(&serde_json::json!({
        "policy": string(input, "policy"), "allow_all_icmp": false, "rules": [],
        "nat": {"masquerade": []},
        "policies": {"hosts": [], "interfaces": input["interfaces"]}
    }))?;
    plans.insert(
        0,
        Match {
            ingress: "lo".into(),
            action: "accept".into(),
            ..Match::default()
        },
    );
    Ok(plans)
}

fn expand(
    output: &mut Vec<Match>,
    rule: &Value,
    sources: &[String],
    ingress: &str,
    hosts: &BTreeMap<&str, &Value>,
) -> Result<()> {
    action(string(rule, "action"))?;
    let egress = string(rule, "out_interface");
    ensure!(
        egress.is_empty() || crate::safe_name(egress, 15),
        "invalid firewall outgoing interface"
    );
    let protocol = string(rule, "protocol");
    ensure!(
        matches!(protocol, "" | "tcp" | "udp"),
        "unsupported host policy protocol"
    );
    let destinations = if !string(rule, "destination_host").is_empty() {
        ensure!(
            string(rule, "destination").is_empty(),
            "destination and destination_host conflict"
        );
        let host = hosts
            .get(string(rule, "destination_host"))
            .context("unknown destination host")?;
        array(host, "addresses")?
            .iter()
            .map(|v| host_prefix(v.as_str().context("host address must be string")?))
            .collect::<Result<Vec<_>>>()?
    } else {
        let value = string(rule, "destination").to_string();
        if !value.is_empty() {
            crate::model::parse_prefix(&value, true)?;
        }
        vec![value]
    };
    let ports = match rule.get("destination_ports").and_then(Value::as_array) {
        Some(v) if !v.is_empty() => {
            ensure!(!protocol.is_empty(), "destination ports require protocol");
            v.iter()
                .map(|v| {
                    let port = u16::try_from(v.as_u64().context("invalid destination port")?)?;
                    ensure!(port != 0, "destination port zero is not allowed");
                    Ok(port)
                })
                .collect::<Result<Vec<_>>>()?
        }
        _ => vec![0],
    };
    let before = output.len();
    for source in sources {
        for destination in &destinations {
            if !source.is_empty()
                && !destination.is_empty()
                && crate::model::parse_prefix(source, true)?.0.is_ipv4()
                    != crate::model::parse_prefix(destination, true)?.0.is_ipv4()
            {
                continue;
            }
            for port in &ports {
                output.push(Match {
                    source: source.clone(),
                    destination: destination.clone(),
                    ingress: ingress.into(),
                    egress: egress.into(),
                    protocol: protocol.into(),
                    port: *port,
                    action: string(rule, "action").into(),
                    established_related: false,
                });
                ensure!(output.len() <= 4096, "firewall expands beyond 4096 rules");
            }
        }
    }
    if output.len() == before {
        bail!("host policy destinations have no common source address family");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn appliance_input_allows_loopback_replies_lan_and_dhcp_only() {
        let mut firewall = json!({"input": {"policy": "drop", "interfaces": [
            {"interface": "eno2", "rules": [{"action": "accept"}]},
            {"interface": "eno1", "rules": [{"destination": "0.0.0.0/0", "protocol": "udp", "destination_ports": [68], "action": "accept"}]}
        ]}});
        let plans = compile_input(&firewall).unwrap();
        assert_eq!(plans.len(), 4);
        assert_eq!(plans[0].ingress, "lo");
        assert!(plans[1].established_related);
        assert_eq!(plans[2].ingress, "eno2");
        assert!(plans[2].protocol.is_empty());
        assert_eq!(plans[3].ingress, "eno1");
        assert_eq!(plans[3].protocol, "udp");
        assert_eq!(plans[3].port, 68);
        assert_eq!(plans[3].destination, "0.0.0.0/0");
        firewall["input"]["interfaces"][0]["rules"][0]["out_interface"] = json!("eno1");
        assert!(compile_input(&firewall).is_err());
        assert!(compile_input(&json!({})).unwrap().is_empty());
    }
    #[test]
    fn ordered_rules_are_not_sorted_by_action() {
        let f = json!({"policy":"drop","allow_all_icmp":true,"rules":[{"action":"drop","source":"192.0.2.0/24"},{"action":"accept"}],"nat":{"masquerade":[]}});
        let rules = compile(&f).unwrap();
        assert_eq!(rules[0].action, "drop");
        assert_eq!(rules[1].action, "accept");
    }
    #[test]
    fn policy_order_and_expansion() {
        let f = json!({"policy":"drop","allow_all_icmp":false,"rules":[],"nat":{"masquerade":[]},"policies":{"hosts":[{"id":"client","addresses":["192.0.2.2","2001:db8::2"],"policy":"drop","rules":[{"protocol":"tcp","destination_ports":[443],"action":"accept"}]}],"interfaces":[{"interface":"lan0","rules":[{"action":"drop","destination":"198.51.100.0/24"}]}]}});
        let rules = compile(&f).unwrap();
        assert!(rules[0].established_related);
        assert_eq!(rules[1].ingress, "lan0");
        assert_eq!(rules[2].port, 443);
        assert_eq!(rules[4].action, "drop");
        assert_eq!(rules.len(), 6);
    }
    #[test]
    fn family_mismatch_and_rule_expansion_rejected() {
        let f = json!({"policy":"accept","allow_all_icmp":false,"rules":[{"source":"192.0.2.0/24","destination":"2001:db8::/32","action":"accept"}],"nat":{"masquerade":[]}});
        assert!(compile(&f).is_err());
    }
    #[test]
    fn appliance_policy_matches_both_ports() {
        let mut firewall = json!({"policy":"drop","allow_all_icmp":false,"rules":[],"nat":{"masquerade":[]},"policies":{"hosts":[],"interfaces":[{"interface":"lan0","rules":[{"out_interface":"wan0","action":"accept"}]}]}});
        let rules = compile(&firewall).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].established_related);
        assert_eq!(rules[1].ingress, "lan0");
        assert_eq!(rules[1].egress, "wan0");
        firewall["policies"]["interfaces"][0]["rules"][0]["out_interface"] = json!("bad/name");
        assert!(compile(&firewall).is_err());
    }
}
