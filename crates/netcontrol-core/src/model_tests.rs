use super::*;
use serde_json::{Value, json};

fn candidate() -> Config {
    serde_json::from_value(json!({
        "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
        "routes":[{"enabled":true,"destination":"192.0.2.0/24","interface":"lan0","table":10000,"metric":100}],
        "firewall":{"policy":"drop","rules":[{"source":"192.0.2.0/24","action":"accept"}]}
    })).expect("valid fixture")
}

#[test]
fn blackhole_section_is_named_once_and_many_routes_may_target_it() {
    let mut config = candidate();
    assert!(!config.blackhole.configured());
    assert_eq!(config.blackhole.action, "blackhole");
    let route = |destination: &str, metric: i64| {
        let mut route = config.routes[0].clone();
        route.destination = destination.into();
        route.interface = "bh0".into();
        route.table = 254;
        route.metric = metric;
        route
    };
    let first = route("198.51.100.0/24", 50);
    let second = route("2001:db8:dead::/48", 60);
    let mut unconfigured = config.clone();
    unconfigured.routes.push(first.clone());
    assert!(unconfigured.validate().is_err());
    config.blackhole.name = "bh0".into();
    config.routes.extend([first, second]);
    config.validate().unwrap();
    for action in ["unreachable", "prohibit"] {
        let mut valid = config.clone();
        valid.blackhole.action = action.into();
        valid.validate().unwrap();
    }
    let mut invalid = config.clone();
    invalid.blackhole.action = "drop".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.routes[1].gateway = "192.0.2.254".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.blackhole.name = "lan0".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.blackhole.name = "bad name".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.ipv6_enabled = false;
    assert!(invalid.validate().is_err());
    let operational = config.operational_value().unwrap();
    assert_eq!(operational["blackhole"]["name"], "bh0");
    assert_eq!(operational["routes"].as_array().unwrap().len(), 3);
    config.routes[1].enabled = false;
    assert_eq!(
        config.operational_value().unwrap()["routes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let roundtrip: Config = serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
    assert_eq!(roundtrip, config);
    let mut unknown = serde_json::to_value(&config).unwrap();
    unknown["blackhole"]["device"] = json!("dummy0");
    assert!(serde_json::from_value::<Config>(unknown).is_err());
}

#[test]
fn mqtt_settings_do_not_change_native_operational_configuration() {
    let before = candidate();
    let mut after = before.clone();
    after.mqtt.enabled = true;
    after.mqtt.endpoint = "mqtts://broker.example.test".into();
    after.mqtt.username = "synthetic-user".into();
    after.mqtt.source_interface = "lan0".into();
    after.mqtt.interval_seconds = 120;
    after.validate().unwrap();
    assert_ne!(before, after);
    assert!(serde_json::to_value(&after).unwrap().get("mqtt").is_some());
    assert!(after.operational_value().unwrap().get("mqtt").is_none());
    assert_eq!(
        before.operational_value().unwrap(),
        after.operational_value().unwrap()
    );
    after.interfaces[0].mtu = 1400;
    assert_ne!(
        before.operational_value().unwrap(),
        after.operational_value().unwrap()
    );
}

#[test]
fn mqtt_configuration_defaults_validation_and_no_inline_password() {
    let mut config = candidate();
    assert!(!config.mqtt.enabled);
    assert_eq!(config.mqtt.interval_seconds, 60);
    config.mqtt.enabled = true;
    assert!(config.validate().is_err());
    config.mqtt.endpoint = "mqtts://broker.example.test:8883".into();
    config.mqtt.source_interface = "lan0".into();
    config.validate().unwrap();
    assert_eq!(
        config.mqtt.broker().unwrap(),
        ("broker.example.test".into(), 8883, true)
    );
    let mut ipv6 = config.clone();
    ipv6.mqtt.endpoint = "mqtt://[2001:db8::1]".into();
    assert_eq!(
        ipv6.mqtt.broker().unwrap(),
        ("2001:db8::1".into(), 1883, false)
    );
    ipv6.validate().unwrap();
    ipv6.ipv6_enabled = false;
    assert!(ipv6.validate().is_err());
    for endpoint in [
        "http://broker.example.test",
        "mqtt://user:secret@broker.example.test",
        "mqtt://broker.example.test/path",
        "mqtt://broker.example.test?option=1",
        "mqtt://broker.example.test:0",
    ] {
        let mut invalid = config.clone();
        invalid.mqtt.endpoint = endpoint.into();
        assert!(invalid.validate().is_err());
    }
    let mut value = serde_json::to_value(&config).unwrap();
    value["mqtt"]["password"] = json!("synthetic-test-only");
    assert!(serde_json::from_value::<Config>(value).is_err());
    config.mqtt.interval_seconds = 0;
    assert!(config.validate().is_err());
}

#[test]
fn static_route_enabled_controls_operational_projection() {
    let mut config = candidate();
    config.validate().unwrap();
    assert_eq!(
        config.operational_value().unwrap()["routes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    config.routes[0].enabled = false;
    config.validate().unwrap();
    let saved = serde_json::to_value(&config).unwrap();
    assert_eq!(saved["routes"][0]["enabled"], false);
    assert_eq!(
        serde_json::from_value::<Config>(saved.clone()).unwrap(),
        config
    );
    assert!(
        config.operational_value().unwrap()["routes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for invalid in [json!(null), json!("false"), json!(0)] {
        let mut value = saved.clone();
        value["routes"][0]["enabled"] = invalid;
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
    let mut missing = saved;
    missing["routes"][0]
        .as_object_mut()
        .unwrap()
        .remove("enabled");
    let defaulted: Config = serde_json::from_value(missing).unwrap();
    assert!(defaulted.routes[0].enabled);
    assert_eq!(
        serde_json::to_value(&defaulted).unwrap()["routes"][0]["enabled"],
        true
    );
    assert_eq!(
        defaulted.operational_value().unwrap()["routes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    config.routes[0].metric = 0;
    assert!(config.validate().is_err());
}

#[test]
fn static_route_disabled_cannot_support_enabled_gateway_monitor() {
    let example: Value =
        serde_json::from_str(include_str!("../../../examples/gateway-monitoring.json")).unwrap();
    let mut config: Config = serde_json::from_value(example["config"].clone()).unwrap();
    config.normalize();
    config.validate().unwrap();
    config.routes[0].enabled = false;
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("enabled explicit matching route")
    );
    let table = config.routes[0].table;
    for monitor in &mut config.gateway_monitors {
        if monitor.routing_table == table {
            monitor.enabled = false;
        }
    }
    config.validate().unwrap();
    config.routes.push(config.routes[0].clone());
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate route")
    );
}

#[test]
fn global_ipv6_defaults_and_conflicting_configuration() {
    assert!(Config::empty().ipv6_enabled);
    assert!(
        serde_json::from_value::<Config>(json!({}))
            .unwrap()
            .ipv6_enabled
    );
    assert_eq!(
        serde_json::to_value(Config::empty()).unwrap()["ipv6_enabled"],
        true
    );
    for invalid in [json!(null), json!("false"), json!(0)] {
        assert!(serde_json::from_value::<Config>(json!({"ipv6_enabled":invalid})).is_err());
    }
    let mut ipv4 = candidate();
    ipv4.ipv6_enabled = false;
    ipv4.validate().unwrap();
    let mut cases = Vec::new();
    let mut value = serde_json::to_value(&ipv4).unwrap();
    value["interfaces"][0]["addresses"] = json!(["2001:db8::1/64"]);
    cases.push(value);
    let mut value = serde_json::to_value(&ipv4).unwrap();
    value["routes"][0]["destination"] = json!("2001:db8:1::/64");
    cases.push(value);
    let mut value = serde_json::to_value(&ipv4).unwrap();
    value["dns"] = json!({"lan0":{"servers":["::1"],"domains":[]}});
    cases.push(value);
    let mut value = serde_json::to_value(&ipv4).unwrap();
    value["ntp"]["servers"] = json!(["2001:db8::123"]);
    cases.push(value);
    let mut value = serde_json::to_value(&ipv4).unwrap();
    value["syslog"]["servers"] = json!([{"host":"2001:db8::514","port":514,"transport":"udp"}]);
    cases.push(value);
    let mut value = serde_json::to_value(&ipv4).unwrap();
    value["firewall"]["rules"][0]["source"] = json!("2001:db8::/64");
    cases.push(value);
    for mut value in cases {
        let config: Config = serde_json::from_value(value.clone()).unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("ipv6_enabled"),
            "{value}"
        );
        value["ipv6_enabled"] = json!(true);
        serde_json::from_value::<Config>(value)
            .unwrap()
            .validate()
            .unwrap();
    }
    // Hostnames and descriptive strings are not IP literals.
    ipv4.ntp.servers.push("time.example.test".into());
    ipv4.interfaces[0].metadata.description = "IPv6 example: 2001:db8::1".into();
    ipv4.validate().unwrap();
}

#[test]
fn interface_metadata_is_descriptive_not_an_identity() {
    let mut config = candidate();
    config.interfaces[0].metadata = ObjectMetadata {
        display_name: "Office LAN".into(),
        description: "Staff network".into(),
    };
    config.validate().unwrap();
    let decoded: Config = serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
    assert_eq!(decoded, config);
    assert_eq!(decoded.interfaces[0].name, "lan0");
    config.interfaces[0].metadata.display_name = "x".repeat(129);
    assert!(config.validate().is_err());
}

#[test]
fn metadata_defaults_types_limits_and_operational_projection() {
    let mut config = candidate();
    assert!(config.interfaces[0].metadata.is_empty());
    let baseline = config.operational_value().unwrap();
    for display_name in [" ".into(), "bad\nname".into(), "x".repeat(129)] {
        config.interfaces[0].metadata.display_name = display_name;
        assert!(config.validate().is_err());
    }
    config.interfaces[0].metadata.display_name = "\u{00e9}".repeat(128);
    config.interfaces[0].metadata.description = "Details\nwith\ttabs".into();
    config.validate().unwrap();
    assert_eq!(config.operational_value().unwrap(), baseline);
    config.interfaces[0].metadata.description = "x".repeat(2049);
    assert!(config.validate().is_err());
    config.interfaces[0].metadata.description = "bad\u{0000}text".into();
    assert!(config.validate().is_err());
    for invalid in [
        json!(null),
        json!("name"),
        json!({"unknown": "value"}),
        json!({"display_name": null}),
    ] {
        let mut value = baseline.clone();
        value["interfaces"][0]["metadata"] = invalid;
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
    let mut config = Config::empty();
    config
        .dhcp_clients
        .insert("metadata".into(), Default::default());
    config.dns.insert("metadata".into(), Default::default());
    let value = config.operational_value().unwrap();
    assert!(value["dhcp_clients"].get("metadata").is_some());
    assert!(value["dns"].get("metadata").is_some());
}

#[test]
fn host_ethernet_and_main_table_routes_validate_without_relaxing_reserved_values() {
    let mut config = candidate();
    config.interfaces[0].kind = "ethernet".into();
    config.interfaces[0].dhcp_relay = DHCPRelayConfig {
        metadata: Default::default(),
        enabled: true,
        servers: vec!["192.0.2.2".into()],
    };
    config.routes[0].table = 254;
    config.validate().unwrap();
    for table in [0, 1, 253, 255, 9999, 20000] {
        let mut invalid = config.clone();
        invalid.routes[0].table = table;
        assert!(invalid.validate().is_err(), "route table {table}");
    }
    let mut invalid = config.clone();
    invalid.interfaces[0].kind = "bridge".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config;
    invalid.interfaces[0].vlan = Some(VLAN {
        parent: "eth1".into(),
        id: 10,
    });
    assert!(invalid.validate().is_err());
}
#[test]
fn empty_and_icmp_defaults_are_explicit() {
    let empty = Config::empty();
    assert!(empty.firewall.allow_all_icmp);
    empty.validate().unwrap();
    let c: Config = serde_json::from_str(r#"{"firewall":{"policy":"drop"}}"#).unwrap();
    assert!(c.firewall.allow_all_icmp);
    for v in [json!(null), json!("true"), json!(1), json!({})] {
        assert!(
            serde_json::from_value::<Config>(json!({"firewall":{"allow_all_icmp":v}})).is_err()
        );
    }
    let mut other = empty.clone();
    other.firewall.allow_all_icmp = false;
    assert_ne!(empty, other);
}
#[test]
fn masquerade_supports_dynamic_wan_but_not_missing_family_or_interface() {
    let mut config = candidate();
    let mut wan = config.interfaces[0].clone();
    wan.name = "wan0".into();
    wan.kind = "ethernet".into();
    wan.role = "wan".into();
    wan.addresses.clear();
    config.interfaces.push(wan);
    config
        .dhcp_clients
        .insert("wan0".into(), DHCPClientConfig::default());
    config.firewall.nat.masquerade.push(MasqueradeRule {
        metadata: Default::default(),
        family: "ipv4".into(),
        source: "192.0.2.0/24".into(),
        out_interface: "wan0".into(),
    });
    config.validate().unwrap();
    config.firewall.nat.masquerade[0].family = "ipv6".into();
    assert!(config.validate().is_err());
    config.firewall.nat.masquerade[0].family = "ipv4".into();
    config.dhcp_clients.clear();
    assert!(config.validate().is_err());
}
#[test]
fn unknown_fields_rejected_at_every_feature_boundary() {
    let c = serde_json::to_value(candidate()).unwrap();
    for path in [
        "/",
        "/ntp",
        "/syslog",
        "/vnstat",
        "/firewall",
        "/firewall/nat",
        "/kernel",
        "/interfaces/0",
        "/interfaces/0/dhcp_relay",
        "/routes/0",
    ] {
        let mut changed = c.clone();
        let target = if path == "/" {
            &mut changed
        } else {
            changed.pointer_mut(path).unwrap()
        };
        target["surprise"] = json!(true);
        assert!(serde_json::from_value::<Config>(changed).is_err(), "{path}");
    }
    let mut c = c;
    c["interfaces"][0].as_object_mut().unwrap().remove("role");
    assert!(serde_json::from_value::<Config>(c).is_err());
}
#[test]
fn policy_egress_requires_a_managed_interface() {
    let mut config = candidate();
    config.firewall.rules.clear();
    config.firewall.policies = Some(serde_json::from_value(json!({
        "hosts": [],
        "interfaces": [{"interface": "lan0", "rules": [{"out_interface": "lan0", "action": "accept"}]}]
    })).unwrap());
    config.validate().unwrap();
    config.firewall.policies.as_mut().unwrap().interfaces[0].rules[0].out_interface =
        "missing0".into();
    assert!(config.validate().is_err());
}
#[test]
fn input_policy_requires_managed_ingress_and_input_appropriate_rules() {
    let mut config = candidate();
    config.firewall.input = Some(
        serde_json::from_value(json!({
            "policy": "drop", "interfaces": [{"interface": "lan0", "rules": [{"action": "accept"}]}]
        }))
        .unwrap(),
    );
    config.validate().unwrap();
    let baseline = config.clone();
    config.firewall.input.as_mut().unwrap().interfaces[0].interface = "missing0".into();
    assert!(config.validate().is_err());
    for invalid in [
        json!({"out_interface": "lan0", "action": "accept"}),
        json!({"destination_host": "client", "action": "accept"}),
        json!({"destination_ports": [68], "action": "accept"}),
    ] {
        let mut config = baseline.clone();
        config.firewall.input.as_mut().unwrap().interfaces[0].rules[0] =
            serde_json::from_value(invalid).unwrap();
        assert!(config.validate().is_err());
    }
    assert!(
        serde_json::from_value::<InputFirewall>(json!({"policy": "drop", "surprise": true}))
            .is_err()
    );
}
#[test]
fn normalization_preserves_ordered_policy_semantics() {
    let mut c = candidate();
    c.interfaces[0].addresses.push("198.51.100.1/24".into());
    c.normalize();
    let mut other = c.clone();
    other.interfaces[0].addresses.reverse();
    assert_eq!(c, other.normalized());
    c.firewall.rules.push(FirewallRule {
        metadata: Default::default(),
        source: String::new(),
        destination: String::new(),
        action: "drop".into(),
    });
    other = c.clone();
    other.firewall.rules.reverse();
    assert_ne!(c.normalized(), other.normalized());
}
#[test]
fn interface_route_rule_and_nat_validation_edges() {
    candidate().validate().unwrap();
    let base = serde_json::to_value(candidate()).unwrap();
    let cases = [
        ("/interfaces/0/name", json!("lo")),
        ("/interfaces/0/name", json!("..")),
        ("/interfaces/0/role", json!("")),
        ("/interfaces/0/role", json!("LAN")),
        ("/interfaces/0/kind", json!("bridge")),
        ("/interfaces/0/mtu", json!(1279)),
        ("/interfaces/0/mtu", json!(65536)),
        ("/interfaces/0/addresses", json!(["fe80::1/64"])),
        (
            "/interfaces/0/addresses",
            json!(["192.0.2.1/24", "192.0.2.1/24"]),
        ),
        ("/routes/0/destination", json!("192.0.2.1/24")),
        ("/routes/0/table", json!(253)),
        ("/routes/0/interface", json!("unknown")),
        ("/routes/0/metric", json!(2147483648i64)),
        ("/routes/0/gateway", json!("2001:db8::1")),
        ("/firewall/policy", json!("reject")),
        ("/firewall/rules/0/action", json!("reject")),
        ("/firewall/rules/0/destination", json!("2001:db8::/32")),
    ];
    for (path, v) in cases {
        let mut c = base.clone();
        if path.ends_with("/gateway") {
            c["routes"][0]["gateway"] = v;
        } else if path.ends_with("/destination") && path.starts_with("/firewall") {
            c["firewall"]["rules"][0]["destination"] = v;
        } else {
            *c.pointer_mut(path).unwrap() = v;
        }
        let c: Config = serde_json::from_value(c).unwrap();
        assert!(c.validate().is_err(), "{path}");
    }
    let mut c = candidate();
    c.routes.push(c.routes[0].clone());
    assert!(c.validate().is_err());
    let mut c = candidate();
    c.interfaces.push(c.interfaces[0].clone());
    assert!(c.validate().is_err());
    let mut c = candidate();
    c.firewall.nat.masquerade.push(MasqueradeRule {
        metadata: Default::default(),
        family: "ipv6".into(),
        source: "".into(),
        out_interface: "lan0".into(),
    });
    assert!(c.validate().is_err());
    c.firewall.nat.masquerade[0].family = "ipv4".into();
    c.validate().unwrap();
}
#[test]
fn canonical_addresses_reject_ambiguous_inputs() {
    for s in [
        "::ffff:192.0.2.1",
        "2001:0db8::1",
        "192.0.002.1",
        "fe80::1%eth0",
        " 192.0.2.1",
    ] {
        assert!(canonical_ip(s).is_err(), "{s}");
    }
    for s in [
        "192.0.2.0/024",
        "192.0.2.1/24",
        "2001:db8::1/32",
        "0.0.0.0/33",
        "::/129",
    ] {
        assert!(canonical_prefix(s, true).is_err(), "{s}");
    }
    canonical_prefix("192.0.2.1/24", false).unwrap();
    canonical_prefix("::/0", true).unwrap();
}
#[test]
fn appliance_hostname_and_destination_validation() {
    for host in [
        "EXAMPLE.com",
        "a..com",
        "-a.com",
        "a-.com",
        "999.1.2.3",
        "",
        "0.0.0.0",
        "224.0.0.1",
        "fe80::1",
    ] {
        let mut c = Config::empty();
        c.ntp.servers = vec![host.into()];
        assert!(c.validate().is_err(), "{host}");
    }
    let mut c = Config::empty();
    c.ntp.enabled = true;
    assert!(c.validate().is_err());
    c.ntp.servers = vec!["ntp.example.invalid".into(), "127.0.0.1".into()];
    c.validate().unwrap();
    c.ntp.servers.push("127.0.0.1".into());
    assert!(c.validate().is_err());
    let mut c = Config::empty();
    c.syslog.servers.push(SyslogServer {
        metadata: Default::default(),
        host: "logs.example.invalid".into(),
        port: 6514,
        transport: "tls".into(),
    });
    c.validate().unwrap();
    c.syslog.servers[0].transport = "https".into();
    assert!(c.validate().is_err());
}
#[test]
fn vlan_cycles_identity_and_mtu_are_rejected() {
    let mut c = candidate();
    let child = Interface {
        metadata: Default::default(),
        name: "vlan0".into(),
        kind: "vlan".into(),
        role: "lan".into(),
        mtu: 1500,
        up: true,
        addresses: vec![],
        dhcp_relay: Default::default(),
        wireguard: None,
        vlan: Some(VLAN {
            parent: "lan0".into(),
            id: 1,
        }),
    };
    c.interfaces.push(child);
    c.validate().unwrap();
    c.interfaces[1].mtu = 1501;
    assert!(c.validate().is_err());
    c.interfaces[1].mtu = 1500;
    c.interfaces[0].kind = "vlan".into();
    c.interfaces[0].vlan = Some(VLAN {
        parent: "vlan0".into(),
        id: 2,
    });
    assert!(c.validate().is_err());
    c.interfaces[0].vlan = None;
    c.interfaces[0].kind = "dummy".into();
    let mut duplicate = c.interfaces[1].clone();
    duplicate.name = "vlan1".into();
    c.interfaces.push(duplicate);
    assert!(c.validate().is_err());
}
#[test]
fn wireguard_keys_endpoints_and_allowed_ips() {
    use base64::Engine as _;
    let mut c = candidate();
    let l = &mut c.interfaces[0];
    l.kind = "wireguard".into();
    l.wireguard = Some(WireGuard {
        key_ref: "lab-key".into(),
        listen_port: 51820,
        peers: vec![Peer {
            metadata: Default::default(),
            public_key: base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            endpoint: "[2001:db8::1]:51820".into(),
            allowed_ips: vec!["198.51.100.0/24".into()],
            persistent_keepalive_seconds: 25,
        }],
    });
    c.validate().unwrap();
    let mut bad = c.clone();
    bad.interfaces[0].wireguard.as_mut().unwrap().listen_port = 0;
    assert!(bad.validate().is_err());
    for key in [
        "bad".into(),
        base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
    ] {
        let mut bad = c.clone();
        bad.interfaces[0].wireguard.as_mut().unwrap().peers[0].public_key = key;
        assert!(bad.validate().is_err());
    }
    let mut bad = c.clone();
    let w = bad.interfaces[0].wireguard.as_mut().unwrap();
    w.peers.push(w.peers[0].clone());
    assert!(bad.validate().is_err());
    let mut bad = c;
    bad.interfaces[0].wireguard.as_mut().unwrap().peers[0].endpoint = "host.invalid:1".into();
    assert!(bad.validate().is_err());
}
#[test]
fn relay_requires_servers_and_unique_bound_address() {
    let mut c = candidate();
    c.interfaces[0].dhcp_relay.enabled = true;
    assert!(c.validate().is_err());
    c.interfaces[0].dhcp_relay.servers = vec!["198.51.100.2".into()];
    c.validate().unwrap();
    let mut second = c.interfaces[0].clone();
    second.name = "lan1".into();
    c.interfaces.push(second);
    assert!(c.validate().is_err());
    c.interfaces.pop();
    c.interfaces[0].up = false;
    assert!(c.validate().is_err());
}
#[test]
fn kernel_catalog_and_canonical_values() {
    assert_eq!(kernel_catalog().len(), 22);
    for (k, v) in [
        ("net.ipv4.tcp_sack", "2"),
        ("net.ipv4.tcp_rmem", "1 3 2"),
        ("net.ipv4.tcp_rmem", "1  2 3"),
        ("net.ipv4.ip_local_port_range", "1000 1000"),
        ("net.core.somaxconn", "01"),
        ("net.core.somaxconn", "+1"),
        ("net.core.somaxconn", "2147483648"),
        ("net.ipv4.tcp_congestion_control", "bad/name"),
        ("unknown", "1"),
    ] {
        let mut c = Config::empty();
        c.kernel.namespace.insert(k.into(), v.into());
        assert!(c.validate().is_err(), "{k}={v}");
    }
    let mut c = Config::empty();
    c.kernel
        .namespace
        .insert("net.ipv4.tcp_rmem".into(), "4096 131072 6291456".into());
    c.validate().unwrap();
    c.kernel.host.insert("net.ipv4.tcp_sack".into(), "1".into());
    assert!(c.validate().is_err());
}
#[test]
fn policy_references_ports_expansion_and_family() {
    let mut c = candidate();
    c.firewall.rules.clear();
    c.firewall.policies = Some(FirewallPolicies {
        hosts: vec![
            FirewallHost {
                metadata: Default::default(),
                id: "client".into(),
                name: "Client".into(),
                addresses: vec!["192.0.2.10".into()],
                policy: "drop".into(),
                rules: vec![HostPolicyRule {
                    metadata: Default::default(),
                    out_interface: "".into(),
                    destination_host: "server".into(),
                    destination: "".into(),
                    protocol: "tcp".into(),
                    destination_ports: vec![443],
                    action: "accept".into(),
                }],
            },
            FirewallHost {
                metadata: Default::default(),
                id: "server".into(),
                name: "Server".into(),
                addresses: vec!["198.51.100.10".into()],
                policy: "accept".into(),
                rules: vec![],
            },
        ],
        interfaces: vec![],
    });
    c.validate().unwrap();
    let mut bad = c.clone();
    bad.firewall.policies.as_mut().unwrap().hosts[1].addresses = vec!["2001:db8::10".into()];
    assert!(bad.validate().is_err());
    let mut bad = c.clone();
    bad.firewall.policies.as_mut().unwrap().hosts[0].rules[0].destination_ports = vec![443, 443];
    assert!(bad.validate().is_err());
    let mut bad = c.clone();
    bad.firewall.policies.as_mut().unwrap().hosts[0].rules[0].destination_host = "missing".into();
    assert!(bad.validate().is_err());
    let mut bad = c.clone();
    bad.firewall.policies.as_mut().unwrap().hosts[0].name = " Client".into();
    assert!(bad.validate().is_err());
    let mut bad = c;
    bad.firewall.rules.push(FirewallRule {
        metadata: Default::default(),
        source: "".into(),
        destination: "".into(),
        action: "drop".into(),
    });
    assert!(bad.validate().is_err());
}
#[test]
fn all_current_example_feature_schemas_validate() {
    fn annotate(value: &mut Value, path: &str, paths: &mut Vec<String>) {
        if path == "/mqtt" {
            return;
        }
        match value {
            Value::Object(object) => {
                for (key, child) in object.iter_mut() {
                    annotate(child, &format!("{path}/{key}"), paths);
                }
                if [
                    "kind",
                    "action",
                    "enabled",
                    "public_key",
                    "priority",
                    "family",
                    "interface",
                    "name",
                    "hostname",
                    "domains",
                ]
                .iter()
                .any(|key| object.contains_key(*key))
                    || object.get("host").is_some_and(Value::is_string)
                {
                    object.insert("metadata".into(), json!({"display_name": "Descriptive name", "description": "Operator notes"}));
                    paths.push(format!("{path}/metadata"));
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter_mut().enumerate() {
                    annotate(child, &format!("{path}/{index}"), paths);
                }
            }
            _ => {}
        }
    }
    for raw in [
        include_str!("../../../examples/appliance-services.json"),
        include_str!("../../../examples/dhcp-relay.json"),
        include_str!("../../../examples/gateway-monitoring.json"),
        include_str!("../../../examples/host-policies.json"),
        include_str!("../../../examples/kernel-mixed-conservative.json"),
        include_str!("../../../examples/migration.json"),
        include_str!("../../../examples/vlan-softflowd.json"),
    ] {
        let v: Value = serde_json::from_str(raw).unwrap();
        let mut c: Config = serde_json::from_value(v["config"].clone()).unwrap();
        c.normalize();
        c.validate().unwrap();
        let roundtrip: Config = serde_json::from_slice(&serde_json::to_vec(&c).unwrap()).unwrap();
        assert_eq!(c, roundtrip);
        let mut annotated = serde_json::to_value(&c).unwrap();
        let mut paths = vec![];
        annotate(&mut annotated, "", &mut paths);
        assert!(!paths.is_empty());
        assert!(annotated["kernel"].get("metadata").is_none());
        assert!(annotated["mqtt"].get("metadata").is_none());
        let described: Config = serde_json::from_value(annotated.clone()).unwrap();
        described.validate().unwrap();
        assert_eq!(
            described.operational_value().unwrap(),
            c.operational_value().unwrap()
        );
        let roundtrip: Config =
            serde_json::from_value(serde_json::to_value(&described).unwrap()).unwrap();
        assert_eq!(described, roundtrip);
        for path in paths {
            let mut invalid = annotated.clone();
            invalid.pointer_mut(&path).unwrap()["display_name"] = json!("x".repeat(129));
            assert!(
                serde_json::from_value::<Config>(invalid)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{path}"
            );
        }
    }
}
#[test]
fn policy_expansion_accepts_exact_limit_and_rejects_one_extra() {
    let mut p = FirewallPolicies::default();
    for i in 0..2 {
        let mut h = FirewallHost {
            metadata: Default::default(),
            id: format!("host{i}"),
            name: format!("Host {i}"),
            addresses: vec![format!("192.0.2.{}", i + 1)],
            policy: "drop".into(),
            rules: vec![],
        };
        for j in 0..64 {
            let count = if i == 1 && j == 63 { 29 } else { 32 };
            h.rules.push(HostPolicyRule {
                metadata: Default::default(),
                out_interface: "".into(),
                destination_host: "".into(),
                destination: "".into(),
                protocol: "tcp".into(),
                destination_ports: (1..=count).collect(),
                action: "accept".into(),
            });
        }
        p.hosts.push(h);
    }
    p.validate().unwrap();
    p.hosts[1].rules[63].destination_ports.push(30);
    assert!(p.validate().is_err());
}
#[test]
fn monitor_defaults_normalize_and_enabled_cross_references_are_required() {
    let v: Value =
        serde_json::from_str(include_str!("../../../examples/gateway-monitoring.json")).unwrap();
    let mut c: Config = serde_json::from_value(v["config"].clone()).unwrap();
    c.normalize();
    c.validate().unwrap();
    for change in 0..7 {
        let mut bad = c.clone();
        match change {
            0 => bad.gateway_monitors[0].routing_table = 254,
            1 => bad.gateway_monitors[0].target = bad.gateway_monitors[0].source_address.clone(),
            2 => bad.gateway_monitors[0].probe_interval_ms = 99,
            3 => bad.gateway_monitors[0].window_ms = 999,
            4 => bad.gateway_monitors[0].loss_timeout_ms = 60000,
            5 => bad.interfaces[0].up = false,
            _ => bad.routes.clear(),
        }
        assert!(bad.validate().is_err(), "case {change}");
    }
    for monitor in &mut c.gateway_monitors {
        monitor.enabled = false;
    }
    c.routes.clear();
    c.validate().unwrap();
    c.gateway_monitors[0].probe_interval_ms = 0;
    c.normalize();
    assert_eq!(c.gateway_monitors[0].probe_interval_ms, 1000);
}
#[test]
fn source_policy_configuration_is_rejected_even_when_empty() {
    for rules in [
        json!([]),
        json!(null),
        json!([{
            "source":"192.0.2.0/24","priority":10000,"table":10000
        }]),
    ] {
        let error = serde_json::from_value::<Config>(json!({"policy_rules":rules}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `policy_rules`"), "{error}");
    }
    assert!(
        serde_json::to_value(Config::empty())
            .unwrap()
            .get("policy_rules")
            .is_none()
    );
    assert!(serde_json::from_value::<Config>(json!({"_monitor_policy_rules":[]})).is_err());
}

#[test]
fn current_examples_without_source_policy_validate() {
    for raw in [
        include_str!("../../../examples/appliance-services.json"),
        include_str!("../../../examples/dhcp-relay.json"),
        include_str!("../../../examples/gateway-monitoring.json"),
        include_str!("../../../examples/host-policies.json"),
        include_str!("../../../examples/kernel-mixed-conservative.json"),
        include_str!("../../../examples/migration.json"),
        include_str!("../../../examples/vlan-softflowd.json"),
    ] {
        let example: Value = serde_json::from_str(raw).unwrap();
        assert!(example["config"].get("policy_rules").is_none());
        let mut config: Config = serde_json::from_value(example["config"].clone()).unwrap();
        config.normalize();
        config.validate().unwrap();
        assert_eq!(
            serde_json::from_value::<Config>(serde_json::to_value(&config).unwrap()).unwrap(),
            config
        );
    }
}

#[test]
fn enabled_monitors_sharing_a_source_require_the_same_table() {
    let v: Value =
        serde_json::from_str(include_str!("../../../examples/gateway-monitoring.json")).unwrap();
    let mut c: Config = serde_json::from_value(v["config"].clone()).unwrap();
    c.normalize();
    let mut duplicate = c.gateway_monitors[0].clone();
    duplicate.name = "second-probe".into();
    c.gateway_monitors.push(duplicate);
    c.validate().unwrap();
    let mut route = c.routes[0].clone();
    route.table = 10002;
    c.routes.push(route);
    c.gateway_monitors.last_mut().unwrap().routing_table = 10002;
    assert!(
        c.validate()
            .unwrap_err()
            .to_string()
            .contains("same routing table")
    );
    c.gateway_monitors.last_mut().unwrap().enabled = false;
    c.validate().unwrap();
}
#[test]
fn softflowd_all_fields_and_timeout_limits_are_validated() {
    let v: Value =
        serde_json::from_str(include_str!("../../../examples/vlan-softflowd.json")).unwrap();
    let c: Config = serde_json::from_value(v["config"].clone()).unwrap();
    c.validate().unwrap();
    for change in 0..9 {
        let mut bad = c.clone();
        let s = &mut bad.softflowd[0];
        match change {
            0 => s.export_version = 8,
            1 => s.sampling_rate = 0,
            2 => s.max_flows = 1000001,
            3 => s.snaplen = 63,
            4 => s.capture_filter = "tcp\nudp".into(),
            5 => s.collector = "host.invalid:9995".into(),
            6 => {
                s.timeouts.insert("unknown".into(), 10);
            }
            7 => {
                s.timeouts.insert("general".into(), 0);
            }
            _ => {
                s.timeouts.insert("udp".into(), 604801);
            }
        }
        assert!(bad.validate().is_err(), "case {change}");
    }
}
