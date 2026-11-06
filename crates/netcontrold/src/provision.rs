use anyhow::{Context, Result, ensure};
use netcontrol_core::{Config, Engine, PERMISSIONS, Reply, canonical_prefix, valid_interface_name};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct VlanLan {
    pub name: String,
    pub parent: String,
    pub id: u16,
}

impl VlanLan {
    fn validate(&self) -> Result<()> {
        ensure!(
            valid_interface_name(&self.name)
                && valid_interface_name(&self.parent)
                && self.name != self.parent
                && (1..=4094).contains(&self.id),
            "VLAN LAN requires distinct valid interface/parent names and an ID from 1 through 4094"
        );
        Ok(())
    }

    fn interface(&self, address: &str) -> Result<netcontrol_core::Interface> {
        self.validate()?;
        Ok(serde_json::from_value(json!({
            "name": self.name, "kind": "vlan", "role": "lan", "mtu": 1500,
            "up": true, "addresses": [address],
            "vlan": {"parent": self.parent, "id": self.id}
        }))?)
    }

    fn check_identity(&self, interface: &netcontrol_core::Interface) -> Result<()> {
        ensure!(
            interface.name == self.name
                && interface.kind == "vlan"
                && interface.vlan.as_ref().is_some_and(|settings| {
                    settings.parent == self.parent && settings.id == i64::from(self.id)
                }),
            "requested VLAN differs from the saved managed interface"
        );
        Ok(())
    }
}

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
    ensure!(
        config
            .interfaces
            .iter()
            .any(|interface| interface.name == wan && interface.kind == "ethernet"),
        "provisioning requires physical Ethernet WAN interface {wan}"
    );
    let lan_interface = config
        .interfaces
        .iter()
        .find(|interface| interface.name == lan)
        .context("LAN interface is missing")?;
    if lan_interface.kind == "vlan" {
        let vlan = lan_interface
            .vlan
            .as_ref()
            .context("LAN VLAN settings missing")?;
        ensure!(
            vlan.parent != wan
                && config
                    .interfaces
                    .iter()
                    .any(|interface| interface.name == vlan.parent && interface.kind == "ethernet"),
            "LAN VLAN requires a managed physical parent distinct from WAN"
        );
    } else {
        ensure!(
            lan_interface.kind == "ethernet",
            "LAN must be physical Ethernet or an explicit VLAN"
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
        "allow_all_icmp": true,
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

pub fn takeover_candidate(
    saved: &Config,
    wan: &str,
    lan: &str,
    address: &str,
    vlan: Option<&VlanLan>,
) -> Result<Config> {
    factory_vlan_candidate(saved, wan, lan, address, vlan)?;
    let mut config = saved.clone();
    if let Some(vlan) = vlan {
        vlan.validate()?;
        ensure!(
            vlan.name == lan,
            "requested LAN name differs from VLAN name"
        );
        if let Some(existing) = config.interfaces.iter().find(|i| i.name == lan) {
            vlan.check_identity(existing)?;
        } else {
            let mut interface = vlan.interface(address)?;
            interface.mtu = config
                .interfaces
                .iter()
                .find(|i| i.name == vlan.parent)
                .context("VLAN parent missing")?
                .mtu;
            config.interfaces.push(interface);
        }
    }
    for interface in &config.interfaces {
        if interface.name != lan {
            for other in &interface.addresses {
                ensure!(
                    !overlaps(address, other)?,
                    "LAN subnet overlaps imported interface {}",
                    interface.name
                );
            }
        }
    }
    for interface in &mut config.interfaces {
        if interface.name == wan {
            interface.role = "wan".into();
            interface.up = true;
        }
        if interface.name == lan {
            interface.role = "lan".into();
            interface.addresses = vec![address.into()];
            interface.up = true;
        }
    }
    config.dhcp_clients.remove(lan);
    if config
        .interfaces
        .iter()
        .any(|i| i.name == wan && i.addresses.is_empty())
    {
        config.dhcp_clients.entry(wan.into()).or_default();
    }
    config.validate()?;
    Ok(config.normalized())
}

pub async fn apply(engine: &mut Engine, wan: &str, lan: &str, address: &str) -> Result<()> {
    apply_with_vlan(engine, wan, lan, address, None).await
}

pub async fn apply_with_vlan(
    engine: &mut Engine,
    wan: &str,
    lan: &str,
    address: &str,
    vlan: Option<&VlanLan>,
) -> Result<()> {
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
    let config = takeover_candidate(engine.saved_configuration(), wan, lan, address, vlan)?;
    engine.commit_initial_configuration(config)?;
    Ok(())
}

fn factory_candidate(saved: &Config, wan: &str, lan: &str, address: &str) -> Result<Config> {
    factory_vlan_candidate(saved, wan, lan, address, None)
}

fn factory_vlan_candidate(
    saved: &Config,
    wan: &str,
    lan: &str,
    address: &str,
    vlan: Option<&VlanLan>,
) -> Result<Config> {
    let interfaces = saved
        .interfaces
        .iter()
        .filter(|interface| interface.kind == "ethernet")
        .map(|interface| {
            json!({"name": interface.name, "kind": "ethernet", "role": "unassigned",
            "mtu": 1500, "up": true, "addresses": []})
        })
        .collect::<Vec<_>>();
    let mut baseline: Config = serde_json::from_value(json!({"interfaces": interfaces}))?;
    if let Some(vlan) = vlan {
        let interface =
            if let Some(existing) = saved.interfaces.iter().find(|i| i.name == vlan.name) {
                vlan.check_identity(existing)?;
                existing.clone()
            } else {
                vlan.interface(address)?
            };
        baseline.interfaces.push(interface);
    }
    candidate(baseline, wan, lan, address)
}

fn prepare_vlan(engine: &mut Engine, vlan: &VlanLan, permissions: &[String]) -> Result<()> {
    if let Some(interface) = engine
        .saved_configuration()
        .interfaces
        .iter()
        .find(|interface| interface.name == vlan.name)
    {
        vlan.check_identity(interface)?;
        return Ok(());
    }
    let discovered = checked(engine.request(
        "GET",
        "/api/v1/interfaces/discovered",
        "",
        "local-lan-setup",
        permissions,
        &[],
    ))?;
    let discovered = discovered
        .as_array()
        .context("invalid interface discovery response")?;
    if discovered
        .iter()
        .any(|interface| interface["name"].as_str() == Some(vlan.name.as_str()))
    {
        checked(engine.request(
            "POST",
            "/api/v1/interfaces/adopt-vlan",
            "",
            "local-lan-setup",
            permissions,
            &serde_json::to_vec(&json!({"name":vlan.name,"parent":vlan.parent,"id":vlan.id}))?,
        ))?;
    }
    Ok(())
}

pub fn vlan_lan_candidate(saved: &Config, vlan: &VlanLan, address: &str) -> Result<Config> {
    vlan.validate()?;
    let parents = saved
        .interfaces
        .iter()
        .filter(|interface| interface.role == "lan")
        .collect::<Vec<_>>();
    ensure!(
        parents.len() == 1 && parents[0].name == vlan.parent && parents[0].kind == "ethernet",
        "automatic VLAN correction requires one physical LAN matching the requested parent"
    );
    let parent = parents[0];
    ensure!(
        parent.addresses.len() == 1,
        "automatic VLAN correction requires exactly one original LAN address"
    );
    let wan = saved
        .interfaces
        .iter()
        .filter(|interface| interface.role == "wan")
        .collect::<Vec<_>>();
    ensure!(
        wan.len() == 1 && wan[0].kind == "ethernet",
        "automatic VLAN correction requires one physical WAN"
    );
    let wan = wan[0].name.clone();
    let mut plain = saved.clone();
    plain
        .interfaces
        .retain(|interface| interface.name != vlan.name);
    let expected = factory_candidate(&plain, &wan, &vlan.parent, &parent.addresses[0])?;
    ensure!(
        plain.operational_value()? == expected.operational_value()?,
        "automatic VLAN correction only supports unchanged factory network policy; use a complete confirmed configuration for customized networking"
    );
    let mut target = saved.clone();
    let parent = target
        .interfaces
        .iter_mut()
        .find(|interface| interface.name == vlan.parent)
        .context("LAN parent missing")?;
    parent.addresses.clear();
    parent.role = "unassigned".into();
    if let Some(interface) = target
        .interfaces
        .iter()
        .find(|interface| interface.name == vlan.name)
    {
        vlan.check_identity(interface)?;
        ensure!(
            interface.addresses.is_empty() || interface.addresses == [address],
            "existing VLAN has different addresses; refusing to discard them automatically"
        );
    } else {
        target.interfaces.push(vlan.interface(address)?);
    }
    let mut target = candidate(target, &wan, &vlan.name, address)?;
    let mut firewall = saved.firewall.clone();
    if let Some(policies) = &mut firewall.policies {
        for policy in &mut policies.interfaces {
            if policy.interface == vlan.parent {
                policy.interface = vlan.name.clone();
            }
        }
    }
    if let Some(input) = &mut firewall.input {
        for policy in &mut input.interfaces {
            if policy.interface == vlan.parent {
                policy.interface = vlan.name.clone();
            }
        }
    }
    firewall.nat.masquerade[0].source = target.firewall.nat.masquerade[0].source.clone();
    target.firewall = firewall;
    target.validate()?;
    Ok(target.normalized())
}

pub fn configure_vlan_lan(engine: &mut Engine, vlan: &VlanLan, address: &str) -> Result<Value> {
    let permissions = PERMISSIONS
        .iter()
        .map(|permission| (*permission).to_owned())
        .collect::<Vec<_>>();
    // Refuse customized/invalid configurations before acquiring an external VLAN.
    vlan_lan_candidate(engine.saved_configuration(), vlan, address)?;
    prepare_vlan(engine, vlan, &permissions)?;
    let config = vlan_lan_candidate(engine.saved_configuration(), vlan, address)?;
    checked(engine.request(
        "POST",
        "/api/v1/transactions",
        "",
        "local-lan-setup",
        &permissions,
        &serde_json::to_vec(&json!({
            "base_revision": engine.committed_revision(),
            "confirm_timeout_seconds": 120,
            "description": "Move factory LAN to an explicit tagged VLAN",
            "config": config
        }))?,
    ))
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

    fn tagged_lan() -> VlanLan {
        VlanLan {
            name: "vlan50".into(),
            parent: "lan0".into(),
            id: 50,
        }
    }

    #[test]
    fn tagged_factory_lan_wires_roles_address_firewall_and_nat() {
        let vlan = tagged_lan();
        let config =
            factory_vlan_candidate(&initial(), "wan0", "vlan50", "10.4.50.1/24", Some(&vlan))
                .unwrap();
        let parent = config
            .interfaces
            .iter()
            .find(|interface| interface.name == "lan0")
            .unwrap();
        assert_eq!(parent.role, "unassigned");
        assert!(parent.addresses.is_empty());
        let lan = config
            .interfaces
            .iter()
            .find(|interface| interface.name == "vlan50")
            .unwrap();
        assert_eq!(lan.role, "lan");
        assert_eq!(lan.addresses, ["10.4.50.1/24"]);
        assert_eq!(lan.vlan.as_ref().unwrap().parent, "lan0");
        assert_eq!(lan.vlan.as_ref().unwrap().id, 50);
        let firewall = serde_json::to_value(&config.firewall).unwrap();
        assert_eq!(firewall["policies"]["interfaces"][0]["interface"], "vlan50");
        assert_eq!(firewall["input"]["interfaces"][0]["interface"], "vlan50");
        assert_eq!(firewall["nat"]["masquerade"][0]["source"], "10.4.50.0/24");
        assert_eq!(firewall["nat"]["masquerade"][0]["out_interface"], "wan0");
        assert!(config.dhcp_clients.contains_key("wan0"));
        let mut bad = vlan.clone();
        bad.parent = "wan0".into();
        assert!(
            factory_vlan_candidate(&initial(), "wan0", "vlan50", "10.4.50.1/24", Some(&bad))
                .is_err()
        );
        bad = vlan;
        bad.id = 0;
        assert!(
            factory_vlan_candidate(&initial(), "wan0", "vlan50", "10.4.50.1/24", Some(&bad))
                .is_err()
        );
    }

    #[test]
    fn correcting_default_lan_preserves_imported_vlan_and_rejects_customized_policy() {
        let vlan = tagged_lan();
        let saved = factory_candidate(&initial(), "wan0", "lan0", "192.168.0.1/24").unwrap();
        let target = vlan_lan_candidate(&saved, &vlan, "10.4.50.1/24").unwrap();
        assert_eq!(
            target,
            factory_vlan_candidate(&saved, "wan0", "vlan50", "10.4.50.1/24", Some(&vlan)).unwrap()
        );
        let mut imported = saved.clone();
        let mut link = vlan.interface("10.4.50.1/24").unwrap();
        link.role = "unassigned".into();
        link.mtu = 1400;
        imported.interfaces.push(link);
        let target = vlan_lan_candidate(&imported, &vlan, "10.4.50.1/24").unwrap();
        assert_eq!(
            target
                .interfaces
                .iter()
                .find(|interface| interface.name == vlan.name)
                .unwrap()
                .mtu,
            1400
        );
        let fresh =
            factory_vlan_candidate(&imported, "wan0", "vlan50", "10.4.50.1/24", Some(&vlan))
                .unwrap();
        assert_eq!(
            fresh
                .interfaces
                .iter()
                .find(|i| i.name == vlan.name)
                .unwrap()
                .mtu,
            1400
        );
        let mut annotated = serde_json::to_value(&saved).unwrap();
        annotated["firewall"]["input"]["interfaces"][0]["metadata"] =
            json!({"display_name": "Trusted LAN", "description": "Console setup"});
        let annotated: Config = serde_json::from_value(annotated).unwrap();
        let target = vlan_lan_candidate(&annotated, &vlan, "10.4.50.1/24").unwrap();
        assert_eq!(
            serde_json::to_value(target.firewall.input.unwrap()).unwrap()["interfaces"][0]["metadata"]
                ["display_name"],
            "Trusted LAN"
        );
        assert_eq!(
            imported
                .interfaces
                .iter()
                .find(|interface| interface.name == "lan0")
                .unwrap()
                .addresses,
            ["192.168.0.1/24"]
        );
        assert!(vlan_lan_candidate(&imported, &vlan, "10.4.51.1/24").is_err());
        let mut custom = saved.clone();
        custom.firewall.allow_all_icmp = false;
        assert!(vlan_lan_candidate(&custom, &vlan, "10.4.50.1/24").is_err());
        custom = saved;
        custom
            .interfaces
            .iter_mut()
            .find(|interface| interface.name == "lan0")
            .unwrap()
            .addresses
            .push("192.168.5.1/24".into());
        assert!(vlan_lan_candidate(&custom, &vlan, "10.4.50.1/24").is_err());
    }
    #[test]
    fn factory_reset_discards_custom_network_configuration() {
        let mut saved = initial();
        saved.ipv6_enabled = true;
        saved.firewall.allow_all_icmp = false;
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
        assert!(!factory.ipv6_enabled);
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
        assert!(factory.firewall.allow_all_icmp);
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
        assert!(config.firewall.allow_all_icmp);
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
    fn takeover_preserves_static_wan_routes_dns_firewall_and_other_interfaces() {
        let mut saved = initial();
        saved
            .interfaces
            .iter_mut()
            .find(|i| i.name == "wan0")
            .unwrap()
            .addresses = vec!["198.51.100.2/24".into()];
        saved.routes=serde_json::from_value(json!([{"destination":"0.0.0.0/0","gateway":"198.51.100.1","interface":"wan0","table":254,"metric":10}])).unwrap();
        saved.dns.insert(
            "wan0".into(),
            serde_json::from_value(json!({"servers":["192.0.2.53"]})).unwrap(),
        );
        saved.firewall.policy = "drop".into();
        let next = takeover_candidate(&saved, "wan0", "lan0", "192.168.0.1/24", None).unwrap();
        assert_eq!(next.routes, saved.routes);
        assert_eq!(next.dns, saved.dns);
        assert_eq!(next.firewall, saved.firewall);
        assert_eq!(
            next.interfaces
                .iter()
                .find(|i| i.name == "wan0")
                .unwrap()
                .addresses,
            ["198.51.100.2/24"]
        );
        assert!(!next.dhcp_clients.contains_key("wan0"));
        assert_eq!(
            next.interfaces.iter().find(|i| i.name == "wifi0"),
            saved.interfaces.iter().find(|i| i.name == "wifi0")
        );
    }
}
