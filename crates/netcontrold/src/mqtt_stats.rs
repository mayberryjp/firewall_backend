use crate::mqtt::metric_key;
use crate::mqtt_host::{COUNTER, GAUGE, HostSensors, push, scalar};
use anyhow::{Result, ensure};
use netcontrol_core::SoftwareMetadata;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn metric(
    out: &mut HostSensors,
    kind: &str,
    name: &str,
    field: &str,
    value: &Value,
    unit: Option<&'static str>,
    class: Option<&'static str>,
) {
    let value = if value.is_boolean() {
        value.clone()
    } else if class == Some(COUNTER) && value.is_u64() {
        json!(value.as_u64().unwrap().to_string())
    } else {
        scalar(value)
    };
    push(
        &mut out.sensors,
        metric_key(kind, name, field),
        format!(
            "{} {field}",
            match kind {
                "firewall" => "Firewall",
                "sando" => "Sando",
                "software" => "Software",
                _ => name,
            }
        ),
        value,
        unit,
        class,
    );
}

pub fn protocols(statistics: &Value) -> Result<HostSensors> {
    let mut out = HostSensors::default();
    let Some(rows) = statistics["protocols"].as_array() else {
        out.retained.push("protocol");
        return Ok(out);
    };
    let mut count = 0;
    for row in rows {
        let Some(source) = row["name"].as_str() else {
            out.retained.push("protocol");
            continue;
        };
        metric(
            &mut out,
            "protocol",
            source,
            "status",
            &row["status"],
            None,
            None,
        );
        let Some(groups) = row["groups"].as_object() else {
            out.retained.push("protocol");
            continue;
        };
        for (group, fields) in groups {
            let Some(fields) = fields.as_object() else {
                out.retained.push("protocol");
                continue;
            };
            for (field, value) in fields {
                // These SNMP fields describe configuration, not measured counters.
                if matches!(
                    field.as_str(),
                    "Forwarding" | "DefaultTTL" | "RtoAlgorithm" | "RtoMin" | "RtoMax" | "MaxConn"
                ) {
                    continue;
                }
                count += 1;
                ensure!(count <= 1024, "MQTT protocol metric limit exceeded");
                metric(
                    &mut out,
                    "protocol",
                    &format!("{source}/{group}"),
                    field,
                    if row["status"] == "available" {
                        value
                    } else {
                        &Value::Null
                    },
                    field.contains("Octets").then_some("B"),
                    Some(if field == "CurrEstab" { GAUGE } else { COUNTER }),
                );
            }
        }
    }
    Ok(out)
}

pub fn services(runtime: Option<&Value>) -> Result<HostSensors> {
    let mut out = HostSensors::default();
    let Some(runtime) = runtime else {
        out.retained.extend([
            "service",
            "dhcprelay",
            "dhcpclient",
            "traffic",
            "flow",
            "wgpeer",
        ]);
        return Ok(out);
    };
    match runtime["appliance_services"].as_array() {
        None => out.retained.extend(["service", "traffic"]),
        Some(rows) => {
            ensure!(rows.len() <= 256, "MQTT service instance limit exceeded");
            for row in rows {
                let Some(name) = row["name"].as_str() else {
                    out.retained.extend(["service", "traffic"]);
                    continue;
                };
                if name == "bgp" {
                    continue;
                }
                let identity = row["instance_id"]
                    .as_u64()
                    .map_or_else(|| name.to_owned(), |id| format!("{name}:{id}"));
                let running = row["state"] == "running";
                for field in [
                    "state",
                    "started_at",
                    "collected_at",
                    "sample_status",
                    "retrying",
                ] {
                    metric(
                        &mut out,
                        "service",
                        &identity,
                        field,
                        &row[field],
                        None,
                        None,
                    );
                }
                metric(
                    &mut out,
                    "service",
                    &identity,
                    "restart_count",
                    &row["restart_count"],
                    None,
                    Some(COUNTER),
                );
                metric(
                    &mut out,
                    "service",
                    &identity,
                    "error_present",
                    &json!(
                        ["error", "last_send_error", "last_report_error"]
                            .iter()
                            .any(|field| row[*field]
                                .as_str()
                                .is_some_and(|error| !error.is_empty()))
                    ),
                    None,
                    None,
                );
                match name {
                    "ntp" => {
                        metric(
                            &mut out,
                            "service",
                            &identity,
                            "discipline",
                            if running {
                                &row["discipline"]
                            } else {
                                &Value::Null
                            },
                            None,
                            None,
                        );
                        for field in [
                            "offset_ms",
                            "delay_ms",
                            "requested_slew_ms",
                            "uncorrected_offset_ms",
                        ] {
                            metric(
                                &mut out,
                                "service",
                                &identity,
                                field,
                                if running && row["sample_status"] == "available" {
                                    &row[field]
                                } else {
                                    &Value::Null
                                },
                                Some("ms"),
                                Some(GAUGE),
                            );
                        }
                    }
                    "syslog" => {
                        for field in ["captured_records", "forwarded_records", "failed_deliveries"]
                        {
                            metric(
                                &mut out,
                                "service",
                                &identity,
                                field,
                                if running { &row[field] } else { &Value::Null },
                                Some(if field == "failed_deliveries" {
                                    "deliveries"
                                } else {
                                    "records"
                                }),
                                Some(COUNTER),
                            );
                        }
                        metric(
                            &mut out,
                            "service",
                            &identity,
                            "destination_error_count",
                            &if running {
                                row["destination_errors"]
                                    .as_array()
                                    .map_or(Value::Null, |errors| json!(errors.len()))
                            } else {
                                Value::Null
                            },
                            None,
                            Some(GAUGE),
                        );
                    }
                    "mdns" | "udp-broadcast-relay" => {
                        let sampled = running && row["collected_at"].is_string();
                        for field in [
                            "received_packets",
                            "transmitted_packets",
                            "received_bytes",
                            "transmitted_bytes",
                            "policy_drops",
                            "loop_drops",
                            "duplicate_drops",
                            "hop_limit_drops",
                            "queue_drops",
                            "oversize_drops",
                            "unsupported_record_drops",
                            "malformed_packets",
                            "rate_limit_drops",
                            "receive_drops",
                            "send_errors",
                        ] {
                            if (name == "mdns" && field == "loop_drops")
                                || (name == "udp-broadcast-relay"
                                    && matches!(
                                        field,
                                        "duplicate_drops"
                                            | "hop_limit_drops"
                                            | "queue_drops"
                                            | "oversize_drops"
                                            | "unsupported_record_drops"
                                            | "malformed_packets"
                                    ))
                            {
                                continue;
                            }
                            metric(
                                &mut out,
                                "service",
                                &identity,
                                field,
                                if sampled { &row[field] } else { &Value::Null },
                                field.ends_with("_bytes").then_some("B"),
                                Some(COUNTER),
                            );
                        }
                        metric(
                            &mut out,
                            "service",
                            &identity,
                            "statistics_complete",
                            if sampled {
                                &row["statistics_complete"]
                            } else {
                                &Value::Null
                            },
                            None,
                            None,
                        );
                    }
                    "vnstat" => traffic(&mut out, row)?,
                    _ => {}
                }
            }
        }
    }
    match runtime["dhcp_relay"].as_array() {
        None => out.retained.push("dhcprelay"),
        Some(rows) => {
            ensure!(rows.len() <= 256, "MQTT DHCP relay limit exceeded");
            for row in rows {
                let Some(name) = row["interface"].as_str() else {
                    out.retained.push("dhcprelay");
                    continue;
                };
                for field in ["state", "retrying", "started_at"] {
                    metric(&mut out, "dhcprelay", name, field, &row[field], None, None);
                }
                metric(
                    &mut out,
                    "dhcprelay",
                    name,
                    "restart_count",
                    &row["restart_count"],
                    None,
                    Some(COUNTER),
                );
            }
        }
    }
    let flow = crate::mqtt_flow::sensors(Some(&json!({"instances":runtime["softflowd"]})));
    out.sensors.extend(flow.sensors);
    out.retained.extend(flow.retained);
    dhcp_clients(&mut out, &runtime["dhcp_clients"])?;
    wireguard(&mut out, &runtime["wireguard"])?;
    Ok(out)
}

fn wireguard(out: &mut HostSensors, status: &Value) -> Result<()> {
    let Some(interfaces) = status.as_array() else {
        out.retained.push("wgpeer");
        return Ok(());
    };
    let mut count = 0;
    for row in interfaces {
        let (Some(interface), Some(peers)) = (row["interface"].as_str(), row["peers"].as_array())
        else {
            out.retained.push("wgpeer");
            continue;
        };
        metric(
            out,
            "wgpeer",
            interface,
            "peer_count",
            &json!(peers.len()),
            None,
            Some(GAUGE),
        );
        for peer in peers {
            count += 1;
            ensure!(count <= 128, "MQTT WireGuard peer limit exceeded");
            let Some(public_key) = peer["public_key"].as_str() else {
                out.retained.push("wgpeer");
                continue;
            };
            let identity = format!("{interface}/{public_key}");
            let label = hex::encode(Sha256::digest(public_key.as_bytes()));
            for field in ["rx_bytes", "tx_bytes", "last_handshake_unix_seconds"] {
                let bytes = field.ends_with("_bytes");
                push(
                    &mut out.sensors,
                    metric_key("wgpeer", &identity, field),
                    format!("{interface} peer {} {field}", &label[..8]),
                    scalar(&peer[field]),
                    Some(if bytes { "B" } else { "s" }),
                    bytes.then_some(COUNTER),
                );
            }
        }
    }
    Ok(())
}

fn dhcp_clients(out: &mut HostSensors, status: &Value) -> Result<()> {
    let (Some(leases), Some(errors)) = (status["leases"].as_object(), status["errors"].as_object())
    else {
        out.retained.push("dhcpclient");
        return Ok(());
    };
    let names: std::collections::BTreeSet<_> = leases.keys().chain(errors.keys()).collect();
    ensure!(names.len() <= 256, "MQTT DHCP client limit exceeded");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for name in names {
        let lease = &status["leases"][name];
        let expires = lease["acquired_at"]
            .as_u64()
            .zip(lease["lifetime"].as_u64())
            .and_then(|(start, lifetime)| start.checked_add(lifetime));
        metric(
            out,
            "dhcpclient",
            name,
            "lease_valid",
            &json!(expires.is_some_and(|end| end > now)),
            None,
            None,
        );
        metric(
            out,
            "dhcpclient",
            name,
            "error_present",
            &json!(
                errors
                    .get(name)
                    .and_then(Value::as_str)
                    .is_some_and(|error| !error.is_empty())
            ),
            None,
            None,
        );
        for field in ["acquired_at", "lifetime", "renewal", "rebinding"] {
            metric(
                out,
                "dhcpclient",
                name,
                field,
                &lease[field],
                Some("s"),
                Some(GAUGE),
            );
        }
        metric(
            out,
            "dhcpclient",
            name,
            "expires_at_unix",
            &json!(expires),
            Some("s"),
            Some(GAUGE),
        );
    }
    Ok(())
}

fn traffic(out: &mut HostSensors, row: &Value) -> Result<()> {
    let available = row["state"] == "running" && row["collected_at"].is_string();
    for field in ["sent_datagrams", "failed_datagrams"] {
        metric(
            out,
            "service",
            "vnstat",
            field,
            if available { &row[field] } else { &Value::Null },
            Some("datagrams"),
            Some(COUNTER),
        );
    }
    metric(
        out,
        "service",
        "vnstat",
        "last_report_date",
        &row["last_report_date"],
        None,
        None,
    );
    let Some(interfaces) = row["interfaces"].as_object() else {
        out.retained.push("traffic");
        return Ok(());
    };
    ensure!(
        interfaces.len() <= 128,
        "MQTT traffic interface limit exceeded"
    );
    for (name, interface) in interfaces {
        metric(
            out,
            "traffic",
            name,
            "present",
            if available {
                &interface["present"]
            } else {
                &Value::Null
            },
            None,
            None,
        );
        metric(
            out,
            "traffic",
            name,
            "last_seen",
            &interface["last_seen"],
            None,
            None,
        );
        metric(
            out,
            "traffic",
            name,
            "resets",
            if available {
                &interface["resets"]
            } else {
                &Value::Null
            },
            None,
            Some(COUNTER),
        );
        for period in ["day", "month", "total"] {
            if period != "total" {
                metric(
                    out,
                    "traffic",
                    name,
                    &format!("{period}_date"),
                    &interface[period]["date"],
                    None,
                    None,
                );
            }
            let counts = if period == "total" {
                &interface["total"]
            } else {
                &interface[period]["counts"]
            };
            for field in ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets"] {
                metric(
                    out,
                    "traffic",
                    name,
                    &format!("{period}_{field}"),
                    if available && interface["present"] == true {
                        &counts[field]
                    } else {
                        &Value::Null
                    },
                    Some(if field.ends_with("_bytes") {
                        "B"
                    } else {
                        "packets"
                    }),
                    Some(if period == "total" { COUNTER } else { GAUGE }),
                );
            }
        }
    }
    Ok(())
}

pub fn bgp(status: Option<&Value>) -> Result<HostSensors> {
    let mut out = HostSensors::default();
    let row = status.unwrap_or(&Value::Null);
    let available = row["state"] == "running";
    if !matches!(
        row["state"].as_str(),
        Some("running" | "disabled" | "simulated")
    ) {
        out.retained.push("bgppeer");
    }
    for field in ["state", "health"] {
        metric(&mut out, "bgp", "bgp", field, &row[field], None, None);
    }
    metric(
        &mut out,
        "bgp",
        "bgp",
        "installed_prefixes",
        if available {
            &row["installed_prefixes"]
        } else {
            &Value::Null
        },
        Some("prefixes"),
        Some(GAUGE),
    );
    let peers = row["neighbors"].as_array();
    metric(
        &mut out,
        "bgp",
        "bgp",
        "connected_prefix_count",
        &if available {
            row["connected_prefixes"]
                .as_array()
                .map_or(Value::Null, |prefixes| json!(prefixes.len()))
        } else {
            Value::Null
        },
        Some("prefixes"),
        Some(GAUGE),
    );
    for (field, value) in [
        ("neighbor_count", peers.map(|peers| peers.len())),
        (
            "established_neighbors",
            peers.map(|peers| {
                peers
                    .iter()
                    .filter(|peer| peer["state"] == "established")
                    .count()
            }),
        ),
    ] {
        metric(
            &mut out,
            "bgp",
            "bgp",
            field,
            &if available { json!(value) } else { Value::Null },
            None,
            Some(GAUGE),
        );
    }
    let Some(peers) = peers else {
        out.retained.push("bgppeer");
        return Ok(out);
    };
    ensure!(peers.len() <= 128, "MQTT BGP neighbor limit exceeded");
    for peer in peers {
        let Some(name) = peer["name"].as_str() else {
            out.retained.push("bgppeer");
            continue;
        };
        metric(
            &mut out,
            "bgppeer",
            name,
            "state",
            if available || row["state"] == "simulated" {
                &peer["state"]
            } else {
                &Value::Null
            },
            None,
            None,
        );
        for field in [
            "received_prefixes",
            "advertised_prefixes",
            "rejected_prefixes",
            "negotiated_hold_seconds",
        ] {
            metric(
                &mut out,
                "bgppeer",
                name,
                field,
                if available {
                    &peer[field]
                } else {
                    &Value::Null
                },
                Some(if field.ends_with("_seconds") {
                    "s"
                } else {
                    "prefixes"
                }),
                Some(if field == "rejected_prefixes" {
                    COUNTER
                } else {
                    GAUGE
                }),
            );
        }
    }
    Ok(out)
}

pub fn software(metadata: &SoftwareMetadata) -> HostSensors {
    let mut out = HostSensors::default();
    for (field, value) in [
        ("latest_version", json!(metadata.latest_version)),
        ("update_available", json!(metadata.update_available)),
        ("last_checked_at", json!(metadata.last_checked_at)),
        (
            "check_state",
            json!(if metadata.repository.is_none() {
                "disabled"
            } else if metadata.error.is_some() {
                "error"
            } else if metadata.latest_version.is_some() {
                "succeeded"
            } else {
                "pending"
            }),
        ),
    ] {
        metric(&mut out, "software", "release", field, &value, None, None);
    }
    out
}

pub fn sando(status: Option<&Value>) -> HostSensors {
    let mut out = HostSensors::default();
    let row = status.unwrap_or(&Value::Null);
    for field in [
        "enabled",
        "state",
        "last_attempt_at",
        "last_success_at",
        "next_sync_at",
        "host_count",
        "skipped_hosts",
    ] {
        metric(
            &mut out,
            "sando",
            "sync",
            field,
            &row[field],
            None,
            matches!(field, "host_count" | "skipped_hosts").then_some(GAUGE),
        );
    }
    out
}

pub fn firewall(
    status: Option<&Value>,
    configuration: &netcontrol_core::Firewall,
) -> Result<HostSensors> {
    let mut out = HostSensors::default();
    let row = status.unwrap_or(&Value::Null);
    let rules = (row["sample"]["status"] == "available")
        .then(|| row["rules"].as_array())
        .flatten();
    let configuration = json!({"firewall":configuration});
    for field in ["generation", "ruleset_id"] {
        metric(
            &mut out,
            "firewall",
            "accounting",
            field,
            &row[field],
            None,
            None,
        );
    }
    metric(
        &mut out,
        "firewall",
        "accounting",
        "logical_rule_count",
        &rules.map_or(Value::Null, |rules| json!(rules.len())),
        None,
        Some(GAUGE),
    );
    for field in ["packets", "bytes"] {
        let (mut total, mut dropped) = (0u128, 0u128);
        if let Some(rules) = rules {
            for rule in rules {
                let count = rule[field]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("MQTT firewall counter missing"))?
                    .parse::<u128>()?;
                total = total
                    .checked_add(count)
                    .ok_or_else(|| anyhow::anyhow!("MQTT firewall counter sum overflow"))?;
                let path = rule
                    .get("config_path")
                    .ok_or_else(|| anyhow::anyhow!("MQTT firewall counter path missing"))?;
                ensure!(
                    path.is_null() || path.is_string(),
                    "MQTT firewall counter path invalid"
                );
                let path = path.as_str();
                // Generated bypass/default rows accept; configured DROP policies/rules are terminal.
                let drop = if let Some(path) = path.filter(|path| {
                    *path != "/firewall/allow_all_icmp" && !path.starts_with("/firewall/nat/")
                }) {
                    let configured = configuration
                        .pointer(path)
                        .ok_or_else(|| anyhow::anyhow!("MQTT firewall counter path not found"))?;
                    let action = if path.ends_with("/policy") {
                        configured.as_str()
                    } else {
                        configured["action"].as_str()
                    };
                    ensure!(
                        matches!(action, Some("accept" | "drop")),
                        "MQTT firewall counter action missing"
                    );
                    action == Some("drop")
                } else {
                    false
                };
                if drop {
                    dropped = dropped
                        .checked_add(count)
                        .ok_or_else(|| anyhow::anyhow!("MQTT firewall drop sum overflow"))?;
                }
            }
        }
        for (prefix, count) in [("rule_match", total), ("dropped", dropped)] {
            metric(
                &mut out,
                "firewall",
                "accounting",
                &format!("{prefix}_{field}"),
                &if rules.is_some() {
                    json!(count.to_string())
                } else {
                    Value::Null
                },
                Some(if field == "bytes" {
                    "B"
                } else if prefix == "dropped" {
                    "packets"
                } else {
                    "matches"
                }),
                Some(COUNTER),
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn runtime() -> Value {
        json!({
            "appliance_services":[
                {"name":"ntp","state":"running","sample_status":"available","offset_ms":-2.5,
                    "delay_ms":1.0,"requested_slew_ms":-2.0,"uncorrected_offset_ms":-0.5},
                {"name":"syslog","state":"running","captured_records":"18446744073709551615",
                    "forwarded_records":"42","failed_deliveries":"3","destination_errors":["omit-private-error"]},
                {"name":"mdns","state":"running","collected_at":"2026-10-30T12:00:00Z",
                    "received_packets":"13","receive_drops":null,"queue_drops":"2","statistics_complete":false,
                    "malformed_packets":"4","unsupported_record_drops":"5"},
                {"name":"udp-broadcast-relay","instance_id":7,"state":"running",
                    "collected_at":"2026-10-30T12:00:00Z","received_bytes":"9007199254740993",
                    "received_packets":"0","statistics_complete":false},
                {"name":"vnstat","state":"running","collected_at":"2026-10-30T12:00:00Z",
                    "sent_datagrams":"11","failed_datagrams":"1","last_report_date":"2026-10-29",
                    "last_report_error":"omit-private-error","collector":"omit-private-config",
                    "interfaces":{"lan0":{"present":true,"last_seen":"2026-10-30T12:00:00Z","resets":"2",
                        "total":{"rx_bytes":"18446744073709551615","tx_bytes":"10","rx_packets":"3","tx_packets":"4"},
                        "day":{"date":"2026-10-30","counts":{"rx_bytes":"12","tx_bytes":"13","rx_packets":"1","tx_packets":"2"}},
                        "month":{"date":"2026-10","counts":{"rx_bytes":"30","tx_bytes":"31","rx_packets":"5","tx_packets":"6"}}}}}],
            "dhcp_relay":[{"interface":"lan0","state":"running","restart_count":"3","retrying":true}],
            "dhcp_clients":{"leases":{"wan0":{"acquired_at":1,"lifetime":2,"renewal":1,"rebinding":1,
                "address":"omit-private-address"}},"errors":{"wan0":"omit-private-error"}},
            "softflowd":[{"name":"office","state":"running","dropped_packets":"9007199254740993"}],
            "wireguard":[{"interface":"wg0","peers":[{"public_key":"omit-private-key",
                "endpoint":"omit-private-address","rx_bytes":"18446744073709551615","tx_bytes":"1",
                "last_handshake_unix_seconds":1}]}]
        })
    }

    fn sensor<'a>(
        out: &'a HostSensors,
        kind: &str,
        name: &str,
        field: &str,
    ) -> &'a crate::mqtt_host::Sensor {
        let key = metric_key(kind, name, field);
        out.sensors
            .iter()
            .find(|sensor| sensor.key == key)
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    #[test]
    fn mqtt_protocol_counters_preserve_precision_and_classify_gauges() {
        let stats = json!({"protocols":[
            {"name":"snmp","status":"available","groups":{"Tcp":{"CurrEstab":"5","RetransSegs":"18446744073709551615","MaxConn":"-1","RtoMin":"200"}}},
            {"name":"snmp6","status":"available","groups":{"IPv6":{"Ip6InOctets":"9007199254740993"}}},
            {"name":"netstat","status":"unavailable","groups":{"TcpExt":{"ListenDrops":"99"}}}
        ]});
        let out = protocols(&stats).unwrap();
        let counter = sensor(&out, "protocol", "snmp/Tcp", "RetransSegs");
        assert_eq!(counter.value, "18446744073709551615");
        assert_eq!(counter.class, Some(COUNTER));
        assert_eq!(
            sensor(&out, "protocol", "snmp/Tcp", "CurrEstab").class,
            Some(GAUGE)
        );
        assert_eq!(
            sensor(&out, "protocol", "snmp6/IPv6", "Ip6InOctets").unit,
            Some("B")
        );
        assert!(
            sensor(&out, "protocol", "netstat/TcpExt", "ListenDrops")
                .value
                .is_null()
        );
        assert!(
            !out.sensors
                .iter()
                .any(|sensor| sensor.key.ends_with("_MaxConn") || sensor.key.ends_with("_RtoMin"))
        );
        assert!(
            protocols(&Value::Null)
                .unwrap()
                .retained
                .contains(&"protocol")
        );
        let mut oversized =
            json!({"protocols":[{"name":"snmp","status":"available","groups":{"Tcp":{}}}]});
        for index in 0..1025 {
            oversized["protocols"][0]["groups"]["Tcp"][format!("Counter{index}")] = json!("1");
        }
        assert!(protocols(&oversized).is_err());
    }

    #[test]
    fn mqtt_service_traffic_and_dhcp_coverage_is_lossless_and_selective() {
        let runtime = runtime();
        let out = services(Some(&runtime)).unwrap();
        for (kind, name, field, expected) in [
            ("service", "ntp", "offset_ms", json!(-2.5)),
            (
                "service",
                "syslog",
                "captured_records",
                json!("18446744073709551615"),
            ),
            ("service", "syslog", "destination_error_count", json!(1)),
            ("service", "mdns", "statistics_complete", json!(false)),
            ("service", "mdns", "queue_drops", json!("2")),
            ("service", "mdns", "malformed_packets", json!("4")),
            ("service", "mdns", "unsupported_record_drops", json!("5")),
            (
                "service",
                "udp-broadcast-relay:7",
                "received_bytes",
                json!("9007199254740993"),
            ),
            (
                "service",
                "udp-broadcast-relay:7",
                "received_packets",
                json!("0"),
            ),
            ("service", "vnstat", "sent_datagrams", json!("11")),
            ("service", "vnstat", "failed_datagrams", json!("1")),
            ("service", "vnstat", "error_present", json!(true)),
            (
                "traffic",
                "lan0",
                "total_rx_bytes",
                json!("18446744073709551615"),
            ),
            ("traffic", "lan0", "day_rx_bytes", json!("12")),
            ("traffic", "lan0", "month_tx_packets", json!("6")),
            ("traffic", "lan0", "day_date", json!("2026-10-30")),
            ("dhcprelay", "lan0", "restart_count", json!("3")),
            ("dhcpclient", "wan0", "expires_at_unix", json!(3)),
            ("dhcpclient", "wan0", "lease_valid", json!(false)),
            ("dhcpclient", "wan0", "error_present", json!(true)),
            (
                "flow",
                "office",
                "dropped_packets",
                json!("9007199254740993"),
            ),
        ] {
            assert_eq!(
                sensor(&out, kind, name, field).value,
                expected,
                "{kind}/{name}/{field}"
            );
        }
        assert_eq!(
            sensor(&out, "wgpeer", "wg0/omit-private-key", "rx_bytes").value,
            "18446744073709551615"
        );
        assert_eq!(
            sensor(
                &out,
                "wgpeer",
                "wg0/omit-private-key",
                "last_handshake_unix_seconds"
            )
            .value,
            1
        );
        assert_eq!(
            sensor(&out, "traffic", "lan0", "total_rx_bytes").class,
            Some(COUNTER)
        );
        assert_eq!(
            sensor(&out, "traffic", "lan0", "day_rx_bytes").class,
            Some(GAUGE)
        );
        assert!(
            sensor(&out, "service", "mdns", "receive_drops")
                .value
                .is_null()
        );
        for sensor in &out.sensors {
            assert!(!format!("{} {}", sensor.name, sensor.value).contains("omit-private"));
        }
        let mut stopped = runtime.clone();
        for row in stopped["appliance_services"].as_array_mut().unwrap() {
            row["state"] = json!("stopped");
        }
        let stopped = services(Some(&stopped)).unwrap();
        for (kind, name, field) in [
            ("service", "ntp", "offset_ms"),
            ("service", "syslog", "captured_records"),
            ("service", "mdns", "queue_drops"),
            ("service", "udp-broadcast-relay:7", "received_packets"),
            ("service", "vnstat", "sent_datagrams"),
            ("traffic", "lan0", "total_rx_bytes"),
        ] {
            assert!(sensor(&stopped, kind, name, field).value.is_null());
        }
        let mut unsampled = runtime.clone();
        unsampled["appliance_services"][0]["sample_status"] = json!("unavailable");
        unsampled["appliance_services"][3]["collected_at"] = Value::Null;
        unsampled["appliance_services"][4]["interfaces"]["lan0"]["present"] = json!(false);
        let unsampled = services(Some(&unsampled)).unwrap();
        assert!(
            sensor(&unsampled, "service", "ntp", "offset_ms")
                .value
                .is_null()
        );
        assert!(
            sensor(
                &unsampled,
                "service",
                "udp-broadcast-relay:7",
                "received_packets"
            )
            .value
            .is_null()
        );
        assert!(
            sensor(&unsampled, "traffic", "lan0", "day_rx_bytes")
                .value
                .is_null()
        );
        let failed = services(None).unwrap();
        for kind in ["service", "traffic", "flow", "dhcprelay", "dhcpclient"] {
            assert!(failed.retained.contains(&kind));
        }
        let empty = services(Some(
            &json!({"appliance_services":[],"dhcp_relay":[],"softflowd":[],
            "dhcp_clients":{"leases":{},"errors":{}},"wireguard":[]}),
        ))
        .unwrap();
        assert!(empty.sensors.is_empty() && empty.retained.is_empty());
    }

    #[test]
    fn mqtt_bgp_release_sando_and_firewall_summaries_exclude_bulk_records() {
        let out = bgp(Some(&json!({"state":"running","installed_prefixes":4,
            "neighbors":[{"name":"edge","state":"established","received_prefixes":4,"advertised_prefixes":2,"rejected_prefixes":9}],
            "routes":["omit-private-route"]}))).unwrap();
        assert_eq!(sensor(&out, "bgp", "bgp", "established_neighbors").value, 1);
        assert_eq!(
            sensor(&out, "bgppeer", "edge", "rejected_prefixes").value,
            "9"
        );
        assert!(bgp(None).unwrap().retained.contains(&"bgppeer"));
        let metadata = SoftwareMetadata::default();
        let out = software(&metadata);
        assert_eq!(
            sensor(&out, "software", "release", "check_state").value,
            "disabled"
        );
        assert!(
            sensor(&out, "software", "release", "update_available")
                .value
                .is_null()
        );
        let mut metadata = metadata;
        metadata.repository = Some("owner/repository".into());
        metadata.last_checked_at = Some(chrono::Utc::now());
        metadata.latest_version = Some(metadata.version);
        metadata.update_available = Some(false);
        let out = software(&metadata);
        assert_eq!(
            sensor(&out, "software", "release", "check_state").value,
            "succeeded"
        );
        assert_eq!(
            sensor(&out, "software", "release", "update_available").value,
            false
        );
        metadata.latest_version = None;
        metadata.update_available = None;
        metadata.error = Some("omit-private-error".into());
        let out = software(&metadata);
        assert_eq!(
            sensor(&out, "software", "release", "check_state").value,
            "error"
        );
        assert!(
            sensor(&out, "software", "release", "update_available")
                .value
                .is_null()
        );
        let out = sando(Some(
            &json!({"state":"succeeded","host_count":2,"skipped_hosts":1,"hosts":["omit-private-host"]}),
        ));
        assert_eq!(sensor(&out, "sando", "sync", "host_count").value, 2);
        assert_eq!(out.sensors.len(), 7);
        let out = firewall(Some(
            &json!({"sample":{"status":"available"},"generation":"g","ruleset_id":"r","rules":[
            {"id":"omit-private-rule","config_path":null,"packets":"18446744073709551615","bytes":"9007199254740993"},
            {"config_path":null,"packets":"1","bytes":"7"}]}),
        ), &netcontrol_core::Firewall::default())
        .unwrap();
        assert_eq!(out.sensors.len(), 7);
        assert_eq!(
            sensor(&out, "firewall", "accounting", "rule_match_packets").value,
            "18446744073709551616"
        );
        assert_eq!(
            sensor(&out, "firewall", "accounting", "rule_match_bytes").value,
            "9007199254741000"
        );
        assert!(
            firewall(
                Some(&json!({"sample":{"status":"available"},"rules":[{"packets":"bad"}]})),
                &netcontrol_core::Firewall::default()
            )
            .is_err()
        );
        let unavailable = firewall(
            Some(&json!({"sample":{"status":"simulated"},"rules":[]})),
            &netcontrol_core::Firewall::default(),
        )
        .unwrap();
        assert!(
            sensor(&unavailable, "firewall", "accounting", "rule_match_packets")
                .value
                .is_null()
        );
        for sensor in &out.sensors {
            assert!(
                !sensor.name.contains("omit-private")
                    && !sensor.value.to_string().contains("omit-private")
            );
        }
    }

    #[test]
    fn mqtt_overall_firewall_drops_include_rules_and_defaults_but_not_accepts_or_nat() {
        let configuration: netcontrol_core::Firewall = serde_json::from_value(json!({
            "policy":"drop","allow_all_icmp":true,
            "nat":{"masquerade":[{"out_interface":"wan0","source":"192.0.2.0/24","family":"ipv4"}]},
            "policies":{
                "hosts":[{"id":"host-a","name":"Host A","addresses":["192.0.2.2"],"policy":"drop","rules":[{"action":"drop"}]}],
                "interfaces":[{"interface":"lan0","rules":[{"action":"drop"},{"action":"accept"}]}]},
            "input":{"policy":"drop","interfaces":[{"interface":"lan0","rules":[{"action":"drop"}]}]}
        })).unwrap();
        let rows: Vec<_> = [
            ("/firewall/policy", 1),
            ("/firewall/input/policy", 2),
            ("/firewall/policies/hosts/0/policy", 3),
            ("/firewall/policies/hosts/0/rules/0", 5),
            ("/firewall/policies/interfaces/0/rules/0", 7),
            ("/firewall/input/interfaces/0/rules/0", 11),
            ("/firewall/policies/interfaces/0/rules/1", 13),
            ("/firewall/allow_all_icmp", 17),
            ("/firewall/nat/masquerade/0", 19),
        ].into_iter().map(|(path, packets)| json!({"config_path":path,"packets":packets.to_string(),"bytes":(packets * 10).to_string()}))
            .chain([json!({"config_path":null,"packets":"23","bytes":"230"})]).collect();
        let snapshot = json!({"sample":{"status":"available"},"rules":rows});
        let out = firewall(Some(&snapshot), &configuration).unwrap();
        assert_eq!(
            sensor(&out, "firewall", "accounting", "dropped_packets").value,
            "29"
        );
        assert_eq!(
            sensor(&out, "firewall", "accounting", "dropped_bytes").value,
            "290"
        );
        assert_eq!(
            sensor(&out, "firewall", "accounting", "dropped_packets").class,
            Some(COUNTER)
        );
        assert_eq!(out.sensors.len(), 7);
        let configuration: netcontrol_core::Firewall = serde_json::from_value(json!({
            "policy":"accept","rules":[{"action":"drop"},{"action":"accept"}]
        }))
        .unwrap();
        let snapshot = json!({"sample":{"status":"available"},"rules":[
            {"config_path":"/firewall/rules/0","packets":"18446744073709551615","bytes":"18446744073709551615"},
            {"config_path":"/firewall/rules/1","packets":"10","bytes":"100"}]});
        let out = firewall(Some(&snapshot), &configuration).unwrap();
        assert_eq!(
            sensor(&out, "firewall", "accounting", "dropped_packets").value,
            "18446744073709551615"
        );
        let unavailable = firewall(None, &configuration).unwrap();
        assert!(
            sensor(&unavailable, "firewall", "accounting", "dropped_packets")
                .value
                .is_null()
        );
        let malformed = json!({"sample":{"status":"available"},"rules":[
            {"config_path":"/firewall/rules/9","packets":"1","bytes":"1"}]});
        assert!(firewall(Some(&malformed), &configuration).is_err());
    }
}
