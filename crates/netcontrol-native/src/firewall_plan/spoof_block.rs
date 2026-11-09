use super::Match;
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde_json::Value;
use std::collections::BTreeSet;

pub fn compile(firewall: &Value, interfaces: &[crate::model::Link]) -> Result<Vec<Match>> {
    let enabled = match firewall.get("spoof_block") {
        None => true,
        Some(value) => value
            .as_bool()
            .context("firewall spoof_block must be a boolean")?,
    };
    let mut plans = Vec::new();
    if !enabled {
        return Ok(plans);
    }
    for link in interfaces.iter().filter(|link| link.role == "lan") {
        ensure!(
            crate::safe_name(&link.name, 15),
            "invalid LAN interface name"
        );
        let mut networks = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for address in &link.addresses {
            crate::model::parse_prefix(address, false)?;
            let prefix: IpNet = address.parse()?;
            networks.insert(prefix.trunc());
            addresses.insert(prefix.addr());
        }
        let base = Match {
            ingress: link.name.clone(),
            action: "return".into(),
            ..Default::default()
        };
        for network in &networks {
            plans.push(Match {
                counter_key: format!("generated/spoof_block/{}/local", link.name),
                source: network.to_string(),
                ..base.clone()
            });
        }
        let bootstrap = format!("generated/spoof_block/{}/bootstrap", link.name);
        for destination in std::iter::once("255.255.255.255/32".into()).chain(
            addresses
                .iter()
                .filter(|address| address.is_ipv4())
                .map(|address| format!("{address}/32")),
        ) {
            plans.push(Match {
                counter_key: bootstrap.clone(),
                source: "0.0.0.0/32".into(),
                destination,
                protocol: "udp".into(),
                source_port: 68,
                port: 67,
                ..base.clone()
            });
        }
        for destination in ["ff02::1:2/128", "fe80::/10"] {
            plans.push(Match {
                counter_key: bootstrap.clone(),
                source: "fe80::/10".into(),
                destination: destination.into(),
                protocol: "udp".into(),
                source_port: 546,
                port: 547,
                ..base.clone()
            });
        }
        let control = format!("generated/spoof_block/{}/ipv6_control", link.name);
        let destinations: BTreeSet<String> = ["fe80::/10".into(), "ff02::/16".into()]
            .into_iter()
            .chain(
                networks
                    .iter()
                    .filter(|network| matches!(network, IpNet::V6(_)))
                    .map(ToString::to_string),
            )
            .collect();
        for destination in destinations {
            for icmpv6_type in [133, 134, 135, 136] {
                plans.push(Match {
                    counter_key: control.clone(),
                    source: "fe80::/10".into(),
                    destination: destination.clone(),
                    protocol: "icmpv6".into(),
                    icmpv6_type: Some(icmpv6_type),
                    hop_limit: Some(255),
                    ..base.clone()
                });
            }
        }
        for (icmpv6_type, destination, hop_limit) in [
            (133, "ff02::2/128", 255),
            (135, "ff02::1:ff00:0/104", 255),
            (131, "ff02::/16", 1),
            (143, "ff02::/16", 1),
        ] {
            plans.push(Match {
                counter_key: control.clone(),
                source: "::/128".into(),
                destination: destination.into(),
                protocol: "icmpv6".into(),
                icmpv6_type: Some(icmpv6_type),
                hop_limit: Some(hop_limit),
                ..base.clone()
            });
        }
        for icmpv6_type in [130, 131, 132, 143] {
            plans.push(Match {
                counter_key: control.clone(),
                source: "fe80::/10".into(),
                destination: "ff02::/16".into(),
                protocol: "icmpv6".into(),
                icmpv6_type: Some(icmpv6_type),
                hop_limit: Some(1),
                ..base.clone()
            });
        }
        for ipv4 in [true, false] {
            plans.push(Match {
                counter_key: "/firewall/spoof_block".into(),
                action: "drop".into(),
                family: Some(ipv4),
                ..base.clone()
            });
        }
        ensure!(
            plans.len() <= netcontrol_core::FIREWALL_EXPANSION_LIMIT,
            "spoof block expands beyond {} rules",
            netcontrol_core::FIREWALL_EXPANSION_LIMIT
        );
    }
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn interfaces() -> Vec<crate::model::Link> {
        serde_json::from_value(json!([
            {"name":"lan0","role":"lan","kind":"ethernet","up":true,"mtu":1500,
             "addresses":["192.0.2.1/24","192.0.2.2/24","198.51.100.1/25","2001:db8:1::1/64"]},
            {"name":"wan0","role":"wan","kind":"ethernet","up":true,"mtu":1500,
             "addresses":["203.0.113.1/24"]},
            {"name":"lan1","role":"lan","kind":"vlan","up":false,"mtu":1500,"addresses":[]}
        ]))
        .unwrap()
    }

    #[test]
    fn spoof_block_expansion_accepts_exact_limit_and_rejects_one_extra() {
        let mut links = interfaces();
        links[0].addresses = (0..(netcontrol_core::FIREWALL_EXPANSION_LIMIT - 42) / 2)
            .map(|index| format!("10.{}.{}.1/32", index / 256, index % 256))
            .collect();
        assert_eq!(
            compile(&json!({}), &links).unwrap().len(),
            netcontrol_core::FIREWALL_EXPANSION_LIMIT
        );
        links[0].addresses.push("10.255.255.1/32".into());
        assert!(
            compile(&json!({}), &links)
                .unwrap_err()
                .to_string()
                .contains("20480")
        );
    }

    #[test]
    fn spoof_block_defaults_strict_boolean_lan_networks_and_fail_closed() {
        let links = interfaces();
        let plans = compile(&json!({}), &links).unwrap();
        assert!(
            compile(&json!({"spoof_block":false}), &links)
                .unwrap()
                .is_empty()
        );
        for value in [Value::Null, json!(1), json!("true")] {
            assert!(compile(&json!({"spoof_block":value}), &links).is_err());
        }
        assert!(!plans.iter().any(|plan| plan.ingress == "wan0"));
        let networks: Vec<_> = plans
            .iter()
            .filter(|plan| plan.counter_key.ends_with("/local"))
            .map(|plan| plan.source.as_str())
            .collect();
        assert_eq!(
            networks,
            ["192.0.2.0/24", "198.51.100.0/25", "2001:db8:1::/64"]
        );
        assert!(
            plans
                .iter()
                .filter(|plan| plan.action != "drop")
                .all(|plan| plan.action == "return")
        );
        assert_eq!(plans.iter().filter(|plan| plan.action == "drop").count(), 4);
        assert!(
            plans
                .iter()
                .filter(|plan| plan.ingress == "lan1")
                .all(|plan| !plan.counter_key.ends_with("/local"))
        );
        for interface in ["lan0", "lan1"] {
            let indices: Vec<_> = plans
                .iter()
                .enumerate()
                .filter(|(_, plan)| plan.ingress == interface)
                .collect();
            assert!(
                indices
                    .iter()
                    .rev()
                    .take(2)
                    .all(|(_, plan)| plan.action == "drop")
            );
        }
    }

    #[test]
    fn spoof_block_bootstrap_exceptions_are_constrained_and_return_only() {
        let plans = compile(&json!({}), &interfaces()).unwrap();
        for plan in plans
            .iter()
            .filter(|plan| plan.counter_key.ends_with("/bootstrap"))
        {
            assert_eq!(plan.action, "return");
            assert_eq!(plan.protocol, "udp");
            assert!(matches!(
                (plan.source_port, plan.port),
                (68, 67) | (546, 547)
            ));
            assert!(matches!(plan.source.as_str(), "0.0.0.0/32" | "fe80::/10"));
            assert!(!plan.destination.is_empty());
        }
        for plan in plans
            .iter()
            .filter(|plan| plan.counter_key.ends_with("/ipv6_control"))
        {
            assert_eq!(plan.action, "return");
            assert_eq!(plan.protocol, "icmpv6");
            assert!(matches!(plan.hop_limit, Some(1 | 255)));
            assert!(plan.icmpv6_type.is_some());
            assert!(!plan.destination.is_empty());
            assert!(matches!(plan.source.as_str(), "::/128" | "fe80::/10"));
        }
        let mut changed = interfaces();
        changed[0].addresses = vec!["10.4.0.1/16".into()];
        assert_ne!(compile(&json!({}), &changed).unwrap(), plans);
    }
}
