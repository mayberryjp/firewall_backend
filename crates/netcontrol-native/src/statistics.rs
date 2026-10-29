use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn service_response(path: &str, mut value: Value, scope: &str) -> Result<Value> {
    if value["sample"].is_object() {
        value["sample"]["scope"] = json!(scope);
    }
    match path {
        "/api/v1/statistics/vnstat" => {
            ensure!(
                value["schema"] == "netcontrol-services/counters/v2"
                    && value["scope"] == "host"
                    && value["interfaces"].is_object()
                    && value["history"].is_array(),
                "invalid native traffic history response"
            );
        }
        "/api/v1/statistics/gateways" => {
            let gateways = value
                .as_object_mut()
                .context("gateway statistics object")?
                .remove("gateways")
                .context("gateway statistics array")?;
            value["monitors"] = gateways;
        }
        _ => {}
    }
    Ok(value)
}

pub fn paired_counters(input: &str) -> Result<Value> {
    ensure!(input.len() <= 1024 * 1024, "oversized protocol statistics");
    let lines: Vec<_> = input.lines().filter(|l| !l.trim().is_empty()).collect();
    ensure!(
        !lines.is_empty() && lines.len() % 2 == 0,
        "empty/unpaired protocol counter lines"
    );
    let mut result = BTreeMap::new();
    for pair in lines.chunks_exact(2) {
        let keys: Vec<_> = pair[0].split_whitespace().collect();
        let values: Vec<_> = pair[1].split_whitespace().collect();
        ensure!(
            !keys.is_empty() && keys.len() == values.len() && keys[0] == values[0],
            "protocol counter headings mismatch"
        );
        ensure!(
            keys.len() >= 2 && keys[0].ends_with(':') && field_name(keys[0].trim_end_matches(':')),
            "invalid protocol group"
        );
        let mut counters = BTreeMap::new();
        for (key, value) in keys[1..].iter().zip(&values[1..]) {
            ensure!(field_name(key), "invalid protocol counter name");
            let number = canonical_counter(keys[0].trim_end_matches(':'), key, value)?;
            ensure!(
                counters.insert(*key, number).is_none(),
                "duplicate protocol counter"
            );
        }
        ensure!(
            result
                .insert(keys[0].trim_end_matches(':'), counters)
                .is_none(),
            "duplicate protocol group"
        );
    }
    Ok(json!(result))
}

pub fn ipv6_counters(input: &str) -> Result<Value> {
    ensure!(
        !input.trim().is_empty() && input.len() <= 1024 * 1024,
        "empty/oversized IPv6 statistics"
    );
    let mut result = BTreeMap::new();
    for line in input.lines().filter(|l| !l.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 2, "invalid IPv6 counter line");
        ensure!(field_name(fields[0]), "invalid IPv6 counter name");
        let number = canonical_counter("IPv6", fields[0], fields[1])?;
        ensure!(
            result.insert(fields[0], number).is_none(),
            "duplicate IPv6 counter"
        );
    }

    Ok(json!(result))
}

fn field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'_')
}

fn canonical_counter(group: &str, name: &str, value: &str) -> Result<String> {
    if group == "Tcp" && name == "MaxConn" && value == "-1" {
        return Ok(value.into());
    }
    let number: u64 = value.parse().context("invalid protocol counter")?;
    ensure!(number.to_string() == value, "noncanonical protocol counter");
    Ok(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traffic_history_preserves_schema_scopes_and_exact_counter_strings() {
        let services = json!({
            "schema":"netcontrol-services/counters/v2", "scope":"host", "history":[],
            "interfaces":{"vlan100":{
                "namespace_id":"net:[123456]","rx_bytes":"18446744073709551615",
                "daily":{"2026-01-01":{"rx_bytes":"9007199254740993","tx_bytes":"7"}}
            }}
        });
        let output = service_response(
            "/api/v1/statistics/vnstat",
            services.clone(),
            "boot:namespace",
        )
        .unwrap();
        assert_eq!(output, services);
        assert!(service_response("/api/v1/statistics/vnstat", json!({}), "scope").is_err());
    }

    #[test]
    fn counters_preserve_large_integer_precision() {
        let v = paired_counters("Tcp: MaxConn InSegs\nTcp: -1 18446744073709551615\n").unwrap();
        assert_eq!(v["Tcp"]["InSegs"], "18446744073709551615");
        assert_eq!(v["Tcp"]["MaxConn"], "-1");
        assert!(paired_counters("Ip: In\nIp: 1 2").is_err());
        assert!(paired_counters("Ip: In").is_err());
        assert!(ipv6_counters("Ip6InReceives 10\nIp6InReceives 2").is_err());
        for value in ["01", "+1", "-1", "18446744073709551616"] {
            assert!(paired_counters(&format!("Ip: InReceives\nIp: {value}")).is_err());
        }
        assert!(paired_counters("").is_err());
        assert!(ipv6_counters("").is_err());
    }
}
