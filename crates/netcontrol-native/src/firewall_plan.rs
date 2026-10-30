use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Match {
    pub counter_key: String,
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

fn ports(rule: &Value, protocol: netcontrol_core::FilterProtocol) -> Result<Vec<u16>> {
    let values = match rule.get("destination_ports") {
        None => vec![],
        Some(value) => value
            .as_array()
            .context("destination_ports must be an array")?
            .iter()
            .map(|value| value.as_i64().context("invalid destination port"))
            .collect::<Result<Vec<_>>>()?,
    };
    protocol.validate_ports(&values)?;
    if values.is_empty() {
        Ok(vec![0])
    } else {
        values
            .into_iter()
            .map(|port| Ok(u16::try_from(port)?))
            .collect()
    }
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
            counter_key: "generated/forward/established_related".into(),
            action: "accept".into(),
            established_related: true,
            ..Match::default()
        });
        for (index, interface) in array(policies, "interfaces")?.iter().enumerate() {
            let ingress = string(interface, "interface");
            ensure!(
                crate::safe_name(ingress, 15),
                "invalid firewall ingress interface"
            );
            for (rule_index, rule) in array(interface, "rules")?.iter().enumerate() {
                expand(
                    &mut output,
                    rule,
                    &["".into()],
                    ingress,
                    &hosts,
                    &format!("/firewall/policies/interfaces/{index}/rules/{rule_index}"),
                )?;
            }
        }
        for (index, host) in array(policies, "hosts")?.iter().enumerate() {
            let sources = array(host, "addresses")?
                .iter()
                .map(|a| host_prefix(a.as_str().context("host address must be string")?))
                .collect::<Result<Vec<_>>>()?;
            for (rule_index, rule) in array(host, "rules")?.iter().enumerate() {
                expand(
                    &mut output,
                    rule,
                    &sources,
                    "",
                    &hosts,
                    &format!("/firewall/policies/hosts/{index}/rules/{rule_index}"),
                )?;
            }
            for source in sources {
                output.push(Match {
                    counter_key: format!("/firewall/policies/hosts/{index}/policy"),
                    source,
                    action: string(host, "policy").into(),
                    ..Match::default()
                });
            }
            ensure!(output.len() <= 4096, "firewall expands beyond 4096 rules");
        }
    } else {
        for (index, rule) in rules.iter().enumerate() {
            let source = string(rule, "source").to_string();
            let destination = string(rule, "destination").to_string();
            let protocol = netcontrol_core::FilterProtocol::parse(string(rule, "protocol"))?;
            let ports = ports(rule, protocol)?;
            for prefix in [&source, &destination]
                .into_iter()
                .filter(|v| !v.is_empty())
            {
                ensure!(
                    protocol.matches_family(crate::model::parse_prefix(prefix, true)?.0),
                    "firewall protocol and address family disagree"
                );
            }
            if !source.is_empty() && !destination.is_empty() {
                ensure!(
                    crate::model::parse_prefix(&source, true)?.0.is_ipv4()
                        == crate::model::parse_prefix(&destination, true)?.0.is_ipv4(),
                    "firewall source/destination family mismatch"
                );
            }
            action(string(rule, "action"))?;
            for port in ports {
                output.push(Match {
                    counter_key: format!("/firewall/rules/{index}"),
                    source: source.clone(),
                    destination: destination.clone(),
                    protocol: string(rule, "protocol").into(),
                    port,
                    action: string(rule, "action").into(),
                    ..Match::default()
                });
                ensure!(output.len() <= 4096, "firewall expands beyond 4096 rules");
            }
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
    for plan in &mut plans {
        plan.counter_key = if plan.established_related {
            "generated/input/established_related".into()
        } else {
            plan.counter_key.replacen(
                "/firewall/policies/interfaces/",
                "/firewall/input/interfaces/",
                1,
            )
        };
    }
    plans.insert(
        0,
        Match {
            counter_key: "generated/input/loopback".into(),
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
    counter_key: &str,
) -> Result<()> {
    action(string(rule, "action"))?;
    let egress = string(rule, "out_interface");
    ensure!(
        egress.is_empty() || crate::safe_name(egress, 15),
        "invalid firewall outgoing interface"
    );
    let protocol = string(rule, "protocol");
    let parsed_protocol = netcontrol_core::FilterProtocol::parse(protocol)?;
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
    let ports = ports(rule, parsed_protocol)?;
    let before = output.len();
    for source in sources {
        for destination in &destinations {
            if (!source.is_empty()
                && !parsed_protocol.matches_family(crate::model::parse_prefix(source, true)?.0))
                || (!destination.is_empty()
                    && !parsed_protocol
                        .matches_family(crate::model::parse_prefix(destination, true)?.0))
            {
                continue;
            }
            if !source.is_empty()
                && !destination.is_empty()
                && crate::model::parse_prefix(source, true)?.0.is_ipv4()
                    != crate::model::parse_prefix(destination, true)?.0.is_ipv4()
            {
                continue;
            }
            for port in &ports {
                output.push(Match {
                    counter_key: counter_key.into(),
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
        bail!("host policy protocol/source/destination have no compatible address family");
    }
    Ok(())
}

pub fn counter_layout(firewall: &Value) -> Result<BTreeMap<(String, String), usize>> {
    let mut layout = BTreeMap::new();
    let mut add = |chain: &str, key: &str| {
        *layout
            .entry((chain.to_owned(), key.to_owned()))
            .or_insert(0) += 1;
    };
    for plan in compile(firewall)? {
        add("forward", &plan.counter_key);
    }
    add("forward", "/firewall/policy");
    let input = compile_input(firewall)?;
    if !input.is_empty() || firewall["allow_all_icmp"] == true {
        for plan in input {
            add("input", &plan.counter_key);
        }
        add(
            "input",
            if firewall.get("input").is_some_and(|v| !v.is_null()) {
                "/firewall/input/policy"
            } else {
                "generated/input/policy"
            },
        );
    }
    if firewall["allow_all_icmp"] == true {
        for chain in ["forward", "input", "output"] {
            add(chain, "/firewall/allow_all_icmp");
        }
        add("output", "generated/output/policy");
    }
    for (index, _) in array(&firewall["nat"], "masquerade")?.iter().enumerate() {
        add("postrouting", &format!("/firewall/nat/masquerade/{index}"));
    }
    for (index, _) in destination_rewrites(firewall)?.iter().enumerate() {
        add(
            "destination_rewrite",
            &format!("/firewall/nat/destination_rewrite/{index}"),
        );
    }
    Ok(layout)
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
    fn icmp_filters_expand_only_compatible_families_in_all_scopes() {
        let mut firewall = json!({"policy":"drop","allow_all_icmp":false,"rules":[],"nat":{"masquerade":[]},
            "policies":{"hosts":[
                {"id":"client","addresses":["192.0.2.2","2001:db8::2"],"policy":"drop","rules":[
                    {"protocol":"icmp","destination_host":"server","action":"accept"},
                    {"protocol":"icmpv6","destination_host":"server","action":"drop"}]},
                {"id":"server","addresses":["198.51.100.2","2001:db8:1::2"],"policy":"drop","rules":[]}],
                "interfaces":[{"interface":"lan0","rules":[{"protocol":"icmpv6","action":"drop"}]}]},
            "input":{"policy":"drop","interfaces":[{"interface":"lan0","rules":[
                {"protocol":"icmp","action":"drop"},{"protocol":"icmpv6","action":"accept"}]}]}});
        let plans = compile(&firewall).unwrap();
        let matches: Vec<_> = plans
            .iter()
            .filter(|rule| rule.counter_key.contains("/hosts/0/rules/"))
            .collect();
        assert_eq!(matches.len(), 2);
        assert_eq!(
            (&matches[0].source, &matches[0].destination, matches[0].port),
            (
                &"192.0.2.2/32".to_string(),
                &"198.51.100.2/32".to_string(),
                0
            )
        );
        assert_eq!(
            (&matches[1].source, &matches[1].destination),
            (
                &"2001:db8::2/128".to_string(),
                &"2001:db8:1::2/128".to_string()
            )
        );
        assert_eq!(plans[1].protocol, "icmpv6");
        let input = compile_input(&firewall).unwrap();
        assert_eq!(input[2].protocol, "icmp");
        assert_eq!(input[3].protocol, "icmpv6");
        let layout = counter_layout(&firewall).unwrap();
        assert_eq!(
            layout[&(
                "forward".into(),
                "/firewall/policies/hosts/0/rules/0".into()
            )],
            1
        );
        firewall["policies"]["hosts"][0]["rules"][0]["destination_ports"] = json!([80]);
        assert!(compile(&firewall).is_err());
        firewall["policies"]["hosts"][0]["rules"][0] =
            json!({"protocol":"icmpv6","destination":"192.0.2.0/24","action":"accept"});
        assert!(compile(&firewall).is_err());
    }

    #[test]
    fn legacy_protocol_port_expansion_preserves_order_and_counter_identity() {
        let mut firewall = json!({"policy":"drop","allow_all_icmp":false,"nat":{"masquerade":[]},"rules":[
            {"protocol":"tcp","destination_ports":[80,443],"action":"drop"},
            {"protocol":"icmp","action":"accept"},{"protocol":"icmpv6","action":"drop"}]});
        let plans = compile(&firewall).unwrap();
        assert_eq!(plans.len(), 4);
        assert_eq!((plans[0].port, plans[1].port), (80, 443));
        assert_eq!(plans[0].counter_key, plans[1].counter_key);
        assert_eq!(
            (&plans[2].protocol, &plans[3].protocol),
            (&"icmp".into(), &"icmpv6".into())
        );
        assert_eq!(
            counter_layout(&firewall).unwrap()[&("forward".into(), "/firewall/rules/0".into())],
            2
        );
        for rule in [
            json!({"protocol":"icmp","destination":"2001:db8::/32","action":"accept"}),
            json!({"protocol":"icmpv6","source":"192.0.2.0/24","action":"accept"}),
            json!({"protocol":"icmp","destination_ports":[80],"action":"accept"}),
            json!({"protocol":"sctp","action":"accept"}),
            json!({"protocol":"udp","destination_ports":[80,80],"action":"accept"}),
        ] {
            firewall["rules"] = json!([rule]);
            assert!(compile(&firewall).is_err(), "{firewall}");
        }
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

    #[test]
    fn counter_layout_maps_logical_rules_expansions_defaults_and_generated_rules() {
        let mut f = serde_json::to_value(netcontrol_core::Firewall::default()).unwrap();
        f["policies"] = json!({
            "hosts":[{"id":"client","addresses":["192.0.2.2","2001:db8::2"],
                "policy":"drop","rules":[{"protocol":"tcp","destination_ports":[80,443],"action":"accept"}]}],
            "interfaces":[{"interface":"lan0","rules":[{"action":"drop"}]}]
        });
        f["input"] = json!({"policy":"drop","interfaces":[
            {"interface":"lan0","rules":[{"protocol":"tcp","destination_ports":[22,443],"action":"accept"}]}
        ]});
        f["nat"]["masquerade"] = json!([{"family":"ipv4","out_interface":"wan0"}]);
        f["nat"]["destination_rewrite"] = json!([{
            "out_interface":"wan0","target_interface":"lan0","target_address":"192.0.2.53",
            "protocol":"udp","destination_port":53
        }]);
        let layout = counter_layout(&f).unwrap();
        for (chain, key, count) in [
            ("forward", "/firewall/policies/hosts/0/rules/0", 4),
            ("forward", "/firewall/policies/hosts/0/policy", 2),
            ("forward", "/firewall/policies/interfaces/0/rules/0", 1),
            ("forward", "/firewall/policy", 1),
            ("input", "/firewall/input/interfaces/0/rules/0", 2),
            ("input", "generated/input/loopback", 1),
            ("input", "generated/input/established_related", 1),
            ("input", "/firewall/input/policy", 1),
            ("output", "generated/output/policy", 1),
            ("postrouting", "/firewall/nat/masquerade/0", 1),
            (
                "destination_rewrite",
                "/firewall/nat/destination_rewrite/0",
                1,
            ),
        ] {
            assert_eq!(
                layout.get(&(chain.into(), key.into())),
                Some(&count),
                "{chain}:{key}"
            );
        }
        for chain in ["forward", "input", "output"] {
            assert_eq!(
                layout[&(chain.into(), "/firewall/allow_all_icmp".into())],
                1
            );
        }
        let f = json!({"policy":"drop","allow_all_icmp":false,"rules":[{"action":"drop"}],
            "nat":{"masquerade":[]}});
        assert_eq!(
            counter_layout(&f).unwrap(),
            BTreeMap::from([
                (("forward".into(), "/firewall/rules/0".into()), 1),
                (("forward".into(), "/firewall/policy".into()), 1)
            ])
        );
    }
}
