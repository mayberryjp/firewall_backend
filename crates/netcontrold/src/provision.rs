use anyhow::{Context, Result, ensure};
use netcontrol_core::{Config, Engine, PERMISSIONS, Reply, canonical_prefix, valid_interface_name};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn checked(reply: Reply) -> Result<Value> {
    ensure!(
        reply.status < 300,
        "provisioning failed ({}): {}",
        reply.status,
        reply.body
    );
    Ok(reply.body)
}

fn overlaps(first: &str, second: &str) -> Result<bool> {
    let (first, first_prefix) = canonical_prefix(first, false)?;
    let (second, second_prefix) = canonical_prefix(second, false)?;
    let (IpAddr::V4(first), IpAddr::V4(second)) = (first, second) else {
        return Ok(false);
    };
    let mask = u32::MAX
        .checked_shl(u32::from(32 - first_prefix.min(second_prefix)))
        .unwrap_or(0);
    Ok(u32::from(first) & mask == u32::from(second) & mask)
}

pub fn candidate(mut config: Config, wan: &str, lan: &str, address: &str) -> Result<Config> {
    ensure!(
        wan != lan && valid_interface_name(wan) && valid_interface_name(lan),
        "WAN and LAN must be distinct valid interface names"
    );
    let (ip, prefix) = canonical_prefix(address, false)?;
    let IpAddr::V4(ip) = ip else {
        anyhow::bail!("LAN requires an IPv4 address")
    };
    ensure!(
        ip.is_private() && (8..=30).contains(&prefix),
        "LAN requires an RFC1918 address with prefix length 8..30"
    );
    ensure!(
        prefix
            >= match ip.octets() {
                [10, ..] => 8,
                [172, ..] => 12,
                _ => 16,
            },
        "LAN subnet must be entirely inside RFC1918 space"
    );
    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(ip) & mask;
    ensure!(
        u32::from(ip) != network && u32::from(ip) != (network | !mask),
        "LAN address must not be the network or broadcast address"
    );
    for name in [wan, lan] {
        ensure!(
            config
                .interfaces
                .iter()
                .any(|interface| interface.name == name && interface.kind == "ethernet"),
            "provisioning requires physical Ethernet interface {name}"
        );
    }
    for interface in &config.interfaces {
        if interface.name == lan {
            continue;
        }
        for other in &interface.addresses {
            ensure!(
                !overlaps(address, other)?,
                "LAN subnet overlaps interface {}",
                interface.name
            );
        }
    }
    ensure!(
        config
            .routes
            .iter()
            .all(|route| route.destination != "0.0.0.0/0"
                || route.interface == wan
                || route.interface == lan),
        "another interface has a default route"
    );
    for interface in &mut config.interfaces {
        interface.role = if interface.name == wan {
            "wan"
        } else if interface.name == lan {
            "lan"
        } else {
            "unassigned"
        }
        .into();
        if interface.name == lan {
            interface.addresses = vec![address.into()];
            interface.up = true;
        }
        if interface.name == wan {
            interface.up = true;
            interface.addresses.clear();
        }
    }
    config
        .routes
        .retain(|route| route.interface != lan && route.interface != wan);
    config.dhcp_clients.remove(lan);
    config.dhcp_clients.entry(wan.into()).or_default();
    config.dns.remove(lan);
    config.dns.remove(wan);
    config.firewall = serde_json::from_value(json!({
        "allow_all_icmp": false,
        "policy": "drop",
        "rules": [],
        "policies": {"hosts": [], "interfaces": [{"interface": lan, "rules": [{"action": "accept"}]}]},
        "input": {"policy": "drop", "interfaces": [
            {"interface": lan, "rules": [{"action": "accept"}]},
            {"interface": wan, "rules": [{"destination": "0.0.0.0/0", "protocol": "udp", "destination_ports": [68], "action": "accept"}]}
        ]},
        "nat": {"masquerade": [{"family": "ipv4", "source": format!("{}/{prefix}", Ipv4Addr::from(network)), "out_interface": wan}]}
    }))?;
    config.validate()?;
    Ok(config.normalized())
}

fn wan_ready(runtime: &Value, wan: &str, lan: &str, address: &str) -> Result<bool> {
    let errors = &runtime["dhcp_clients"]["errors"];
    ensure!(
        errors.get(wan).is_none(),
        "WAN DHCP worker failed: {}",
        errors[wan]
    );
    let lease = &runtime["dhcp_clients"]["leases"][wan];
    if let Some(leases) = runtime["dhcp_clients"]["leases"].as_object() {
        for (name, lease) in leases {
            if name == lan {
                continue;
            }
            ensure!(
                name == wan
                    || !lease["routes"].as_array().is_some_and(|routes| routes
                        .iter()
                        .any(|route| route["destination"] == "0.0.0.0/0")),
                "another DHCP interface has a default route: {name}"
            );
            if let Some(other) = lease["address"].as_str() {
                ensure!(
                    !overlaps(address, other)?,
                    "LAN subnet overlaps DHCP lease on {name}"
                );
            }
        }
    }
    Ok(lease["address"].is_string()
        && lease["routes"].as_array().is_some_and(|routes| {
            routes
                .iter()
                .any(|route| route["destination"] == "0.0.0.0/0" && route["table"] == 254)
        }))
}

pub async fn apply(engine: &mut Engine, wan: &str, lan: &str, address: &str) -> Result<()> {
    let permissions = PERMISSIONS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let state = checked(engine.request(
        "GET",
        "/api/v1/state",
        "",
        "local-installer",
        &permissions,
        &[],
    ))?;
    ensure!(
        engine.is_initial_configuration() && state.get("active_transaction").is_none(),
        "appliance provisioning requires an unconfigured initial journal; existing state was not reset"
    );
    let baseline: Config = serde_json::from_value(state["desired"].clone())?;
    ensure!(
        baseline.firewall == netcontrol_core::Firewall::default()
            && baseline
                .interfaces
                .iter()
                .all(|interface| interface.role == "unassigned"),
        "appliance provisioning refuses existing role or firewall configuration"
    );
    let config = factory_candidate(&baseline, wan, lan, address)?;
    let request = serde_json::to_vec(
        &json!({"base_revision": engine.committed_revision(), "confirm_timeout_seconds": 60,
        "description": "Initial LAN/WAN appliance provisioning", "config": config}),
    )?;
    let transaction = checked(engine.request(
        "POST",
        "/api/v1/transactions",
        "",
        "local-installer",
        &permissions,
        &request,
    ))?;
    let id = transaction["id"]
        .as_str()
        .context("provisioning transaction has no ID")?;
    let ready = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            engine.tick()?;
            let runtime = checked(engine.request(
                "GET",
                "/api/v1/runtime",
                "",
                "local-installer",
                &permissions,
                &[],
            ))?;
            if wan_ready(&runtime, wan, lan, address)? {
                return Ok::<(), anyhow::Error>(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "WAN DHCP did not obtain an IPv4 lease/default route within 30 seconds"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    .await;
    if let Err(error) = ready {
        checked(engine.request(
            "POST",
            &format!("/api/v1/transactions/{id}/rollback"),
            "",
            "local-installer",
            &permissions,
            &[],
        ))
        .with_context(|| {
            format!("WAN DHCP provisioning failed ({error:#}); rollback also failed")
        })?;
        return Err(error.context("WAN DHCP provisioning failed; initial transaction rolled back"));
    }
    checked(engine.request(
        "POST",
        &format!("/api/v1/transactions/{id}/confirm"),
        "",
        "local-installer",
        &permissions,
        &[],
    ))?;
    Ok(())
}

fn factory_candidate(saved: &Config, wan: &str, lan: &str, address: &str) -> Result<Config> {
    let interfaces = saved
        .interfaces
        .iter()
        .filter(|interface| interface.kind == "ethernet")
        .map(|interface| {
            json!({"name": interface.name, "kind": "ethernet", "role": "unassigned",
            "mtu": 1500, "up": true, "addresses": []})
        })
        .collect::<Vec<_>>();
    let baseline = serde_json::from_value(json!({"interfaces": interfaces}))?;
    candidate(baseline, wan, lan, address)
}

pub fn factory_reset(engine: &mut Engine, wan: &str, lan: &str, address: &str) -> Result<()> {
    let config = factory_candidate(engine.saved_configuration(), wan, lan, address)?;
    engine.factory_reset(config)?;
    Ok(())
}

pub fn enable_forwarding(engine: &mut Engine) -> Result<()> {
    let permissions = vec!["state.read".to_owned()];
    let state = checked(engine.request(
        "GET",
        "/api/v1/state",
        "",
        "local-appliance",
        &permissions,
        &[],
    ))?;
    let config: Config = serde_json::from_value(state["desired"].clone())?;
    ensure!(
        config
            .interfaces
            .iter()
            .any(|interface| interface.role == "lan")
            && config
                .interfaces
                .iter()
                .any(|interface| interface.role == "wan"),
        "appliance requires provisioned LAN/WAN roles before enabling forwarding; run install.sh on a fresh device"
    );
    #[cfg(target_os = "linux")]
    {
        let path = "/proc/sys/net/ipv4/ip_forward";
        std::fs::write(path, "1\n").context("enable appliance IPv4 forwarding")?;
        ensure!(
            std::fs::read_to_string(path)?.trim() == "1",
            "IPv4 forwarding did not enable"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("appliance forwarding requires Linux")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial() -> Config {
        serde_json::from_value(json!({"interfaces": [
            {"name":"wan0","kind":"ethernet","role":"unassigned","mtu":1500,"up":true,"addresses":["198.51.100.2/24"]},
            {"name":"lan0","kind":"ethernet","role":"unassigned","mtu":1500,"up":false,"addresses":[]}
        ],"routes":[{"enabled":true,"destination":"0.0.0.0/0","gateway":"198.51.100.1","interface":"wan0","table":254,"metric":100}]})).unwrap()
    }
    #[test]
    fn factory_reset_discards_custom_network_configuration() {
        let mut saved = initial();
        saved.dhcp_clients.insert("lan0".into(), Default::default());
        saved.interfaces.push(
            serde_json::from_value(json!({"name":"wifi0", "kind":"ethernet",
            "role":"wan", "mtu":1400, "up":true, "addresses":[]}))
            .unwrap(),
        );
        saved.interfaces.push(
            serde_json::from_value(json!({"name":"extra0", "kind":"dummy",
            "role":"lan", "mtu":1400, "up":true, "addresses":["192.0.2.1/24"]}))
            .unwrap(),
        );
        saved
            .dhcp_clients
            .insert("wifi0".into(), Default::default());
        saved.dns.insert(
            "wan0".into(),
            serde_json::from_value(json!({"servers":["192.0.2.53"]})).unwrap(),
        );
        let factory = factory_candidate(&saved, "wan0", "lan0", "192.168.0.1/24").unwrap();
        assert_eq!(
            factory.dhcp_clients.keys().cloned().collect::<Vec<_>>(),
            ["wan0"]
        );
        assert!(factory.dns.is_empty());
        assert!(factory.routes.is_empty());
        assert!(
            !factory
                .interfaces
                .iter()
                .any(|interface| interface.name == "extra0")
        );
        let wifi = factory
            .interfaces
            .iter()
            .find(|interface| interface.name == "wifi0")
            .unwrap();
        assert_eq!(wifi.role, "unassigned");
        assert_eq!(wifi.mtu, 1500);
        assert!(wifi.addresses.is_empty());
        let lan = factory
            .interfaces
            .iter()
            .find(|interface| interface.name == "lan0")
            .unwrap();
        assert_eq!(lan.role, "lan");
        assert_eq!(lan.addresses, ["192.168.0.1/24"]);
        assert_eq!(factory.firewall.nat.masquerade[0].source, "192.168.0.0/24");
    }

    #[test]
    fn appliance_defaults_and_invalid_topologies() {
        let config = candidate(initial(), "wan0", "lan0", "192.168.0.1/24").unwrap();
        assert_eq!(
            config
                .interfaces
                .iter()
                .find(|interface| interface.name == "lan0")
                .unwrap()
                .addresses,
            ["192.168.0.1/24"]
        );
        assert_eq!(config.firewall.policy, "drop");
        assert!(!config.firewall.allow_all_icmp);
        assert_eq!(
            config.firewall.policies.unwrap().interfaces[0].rules[0].out_interface,
            ""
        );
        assert_eq!(config.firewall.nat.masquerade[0].source, "192.168.0.0/24");
        assert!(config.dhcp_clients.contains_key("wan0"));
        assert!(config.routes.is_empty());
        assert!(
            config
                .interfaces
                .iter()
                .find(|interface| interface.name == "wan0")
                .unwrap()
                .addresses
                .is_empty()
        );
        let input = config.firewall.input.unwrap();
        assert_eq!(input.policy, "drop");
        assert_eq!(
            input
                .interfaces
                .iter()
                .find(|interface| interface.interface == "lan0")
                .unwrap()
                .rules[0]
                .protocol,
            ""
        );
        assert_eq!(
            input
                .interfaces
                .iter()
                .find(|interface| interface.interface == "wan0")
                .unwrap()
                .rules[0]
                .destination_ports,
            [68]
        );
        for address in [
            "192.168.10.0/24",
            "192.168.10.255/24",
            "2001:db8::1/64",
            "127.0.0.1/24",
            "192.168.10.1/32",
        ] {
            assert!(
                candidate(initial(), "wan0", "lan0", address).is_err(),
                "{address}"
            );
        }
        assert!(candidate(initial(), "wan0", "wan0", "192.168.10.1/24").is_err());
        assert!(candidate(initial(), "missing", "lan0", "192.168.10.1/24").is_err());
        let mut overlap = initial();
        overlap.interfaces[0].addresses = vec!["192.168.10.2/24".into()];
        assert!(candidate(overlap, "wan0", "lan0", "192.168.10.1/24").is_err());
        assert!(candidate(initial(), "wan0", "lan0", "192.168.10.1/8").is_err());
        let mut dhcp = initial();
        dhcp.interfaces[0].addresses.clear();
        dhcp.routes.clear();
        dhcp.dhcp_clients.insert("wan0".into(), Default::default());
        let provisioned = candidate(dhcp, "wan0", "lan0", "192.168.10.1/24").unwrap();
        assert!(
            provisioned
                .interfaces
                .iter()
                .find(|interface| interface.name == "wan0")
                .unwrap()
                .addresses
                .is_empty()
        );
        assert!(provisioned.dhcp_clients.contains_key("wan0"));
    }
    #[test]
    fn wan_readiness_requires_dhcp_default_route_and_no_subnet_collision() {
        let mut runtime = json!({"dhcp_clients": {"errors": {}, "leases": {}}});
        assert!(!wan_ready(&runtime, "wan0", "lan0", "192.168.0.1/24").unwrap());
        runtime["dhcp_clients"]["leases"]["wan0"] = json!({"address": "198.51.100.2/24", "routes": [{"destination": "0.0.0.0/0", "table": 254}]});
        assert!(wan_ready(&runtime, "wan0", "lan0", "192.168.0.1/24").unwrap());
        runtime["dhcp_clients"]["leases"]["wan0"]["address"] = json!("192.168.0.2/24");
        assert!(wan_ready(&runtime, "wan0", "lan0", "192.168.0.1/24").is_err());
        runtime["dhcp_clients"]["errors"]["wan0"] = json!("synthetic failure");
        assert!(wan_ready(&runtime, "wan0", "lan0", "192.168.0.1/24").is_err());
    }
}
