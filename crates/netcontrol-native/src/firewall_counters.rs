use crate::netlink_decode::{attributes, c_string};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

const PREFIX: &str = "netcontrol-counter-v1";

fn ranges(bytes: &[u8]) -> Result<Vec<(u16, Range<usize>)>> {
    let mut offset = 0;
    Ok(attributes(bytes)?
        .into_iter()
        .map(|(kind, value)| {
            let range = offset + 4..offset + 4 + value.len();
            offset += (4 + value.len() + 3) & !3;
            (kind, range)
        })
        .collect())
}

fn field(fields: &[(u16, Range<usize>)], kind: u16) -> Result<Range<usize>> {
    let mut matches = fields.iter().filter(|(value, _)| value & 0x3fff == kind);
    let range = matches
        .next()
        .with_context(|| format!("missing nftables attribute {kind}"))?
        .1
        .clone();
    ensure!(
        matches.next().is_none(),
        "duplicate nftables attribute {kind}"
    );
    Ok(range)
}

fn counter_positions(bytes: &[u8]) -> Result<Vec<(usize, usize)>> {
    let mut counters = Vec::new();
    for (kind, range) in ranges(bytes)? {
        ensure!(kind & 0x3fff == 1, "invalid nftables expression list");
        let expression = &bytes[range.clone()];
        let fields = ranges(expression)?;
        let name = field(&fields, 1)?;
        if c_string(&expression[name])? != "counter" {
            continue;
        }
        let data_range = field(&fields, 2)?;
        let data = &expression[data_range.clone()];
        let fields = ranges(data)?;
        let byte_count = field(&fields, 1)?;
        let packet_count = field(&fields, 2)?;
        ensure!(
            byte_count.len() == 8 && packet_count.len() == 8,
            "invalid nftables counter width"
        );
        counters.push((
            range.start + data_range.start + byte_count.start,
            range.start + data_range.start + packet_count.start,
        ));
    }
    Ok(counters)
}

pub fn normalize_expressions(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut normalized = bytes.to_vec();
    for (byte_count, packet_count) in counter_positions(bytes)? {
        normalized[byte_count..byte_count + 8].fill(0);
        normalized[packet_count..packet_count + 8].fill(0);
    }
    Ok(normalized)
}

fn valid_generation(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

pub fn userdata(generation: &str, key: &str) -> Result<Vec<u8>> {
    ensure!(
        valid_generation(generation),
        "invalid firewall counter generation"
    );
    ensure!(
        (key.starts_with("/firewall/") || key.starts_with("generated/"))
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-".contains(&byte)),
        "invalid firewall counter key"
    );
    let bytes = format!("{PREFIX}|{generation}|{key}").into_bytes();
    ensure!(
        bytes.len() <= 256,
        "firewall counter identity exceeds kernel limit"
    );
    Ok(bytes)
}

pub fn snapshot(
    payloads: &[Vec<u8>],
    expected: &BTreeMap<(String, String), usize>,
) -> Result<Value> {
    ensure!(
        payloads.len() <= 16_384,
        "firewall snapshot exceeds 16384 kernel rules"
    );
    let mut totals = BTreeMap::<(String, String), (usize, u128, u128)>::new();
    let mut generation = None;
    let mut handles = BTreeSet::new();
    for payload in payloads {
        ensure!(
            payload.len() >= 4 && payload[0] == 1,
            "invalid nftables rule family"
        );
        let bytes = &payload[4..];
        let fields = ranges(bytes)?;
        ensure!(
            c_string(&bytes[field(&fields, 1)?])? == "netcontrol",
            "unexpected nftables table"
        );
        let chain = c_string(&bytes[field(&fields, 2)?])?.to_owned();
        let handle_bytes = &bytes[field(&fields, 3)?];
        ensure!(handle_bytes.len() == 8, "invalid nftables rule handle");
        let handle = u64::from_be_bytes(handle_bytes.try_into()?);
        ensure!(
            handle > 0 && handles.insert((chain.clone(), handle)),
            "duplicate/invalid nftables rule handle"
        );
        let data = std::str::from_utf8(&bytes[field(&fields, 7)?])
            .context("firewall counter identity unavailable; apply an instrumented firewall")?;
        let parts: Vec<_> = data.split('|').collect();
        ensure!(
            parts.len() == 3 && parts[0] == PREFIX,
            "firewall rule accounting is unavailable"
        );
        ensure!(
            userdata(parts[1], parts[2])? == data.as_bytes(),
            "invalid firewall counter identity"
        );
        if let Some(previous) = &generation {
            ensure!(previous == parts[1], "mixed firewall counter generations");
        } else {
            generation = Some(parts[1].to_owned());
        }
        let key = (chain, parts[2].to_owned());
        ensure!(
            expected.contains_key(&key),
            "unexpected firewall counter identity"
        );
        let expressions = &bytes[field(&fields, 4)?];
        let positions = counter_positions(expressions)?;
        ensure!(
            positions.len() == 1,
            "each firewall rule requires exactly one counter"
        );
        let (byte_count, packet_count) = positions[0];
        let bytes = u64::from_be_bytes(expressions[byte_count..byte_count + 8].try_into()?);
        let packets = u64::from_be_bytes(expressions[packet_count..packet_count + 8].try_into()?);
        let total = totals.entry(key).or_default();
        total.0 += 1;
        total.1 = total
            .1
            .checked_add(packets.into())
            .context("firewall packet sum overflow")?;
        total.2 = total
            .2
            .checked_add(bytes.into())
            .context("firewall byte sum overflow")?;
    }
    ensure!(
        totals.len() == expected.len()
            && expected
                .iter()
                .all(|(key, count)| totals.get(key).is_some_and(|total| total.0 == *count)),
        "incomplete firewall counter snapshot"
    );
    let generation = generation.context("firewall counters unavailable; no instrumented rules")?;
    let mut hash = Sha256::new();
    hash.update(generation);
    for (chain, handle) in handles {
        hash.update(chain.as_bytes());
        hash.update([0]);
        hash.update(handle.to_be_bytes());
    }
    let rules: Vec<_> = totals
        .into_iter()
        .map(|((chain, key), (count, packets, bytes))| {
            json!({
                "id":format!("{chain}:{key}"),
                "chain":chain,
                "config_path":key.starts_with('/').then_some(key),
                "expanded_rules":count,
                "packets":packets.to_string(),
                "bytes":bytes.to_string()
            })
        })
        .collect();
    Ok(json!({
        "schema":"netcontrol-firewall-counters/v1",
        "generation":hex::encode(hash.finalize()),
        "rules":rules
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATION: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const KEY: &str = "/firewall/rules/0";

    fn attribute(kind: u16, data: &[u8]) -> Vec<u8> {
        let length = 4 + data.len();
        let mut bytes = (length as u16).to_ne_bytes().to_vec();
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(data);
        bytes.resize((length + 3) & !3, 0);
        bytes
    }

    fn expression(name: &str, data: &[u8]) -> Vec<u8> {
        attribute(
            0x8001,
            &[
                attribute(1, format!("{name}\0").as_bytes()),
                attribute(0x8002, data),
            ]
            .concat(),
        )
    }

    fn counter(packets: u64, bytes: u64) -> Vec<u8> {
        expression(
            "counter",
            &[
                attribute(0x4001, &bytes.to_be_bytes()),
                attribute(0x4002, &packets.to_be_bytes()),
                attribute(3, &[]),
            ]
            .concat(),
        )
    }

    fn payload(handle: u64, generation: &str, key: &str, packets: u64, bytes: u64) -> Vec<u8> {
        [
            vec![1, 0, 0, 0],
            attribute(1, b"netcontrol\0"),
            attribute(2, b"forward\0"),
            attribute(0x4003, &handle.to_be_bytes()),
            attribute(0x8004, &counter(packets, bytes)),
            attribute(7, &userdata(generation, key).unwrap()),
        ]
        .concat()
    }

    #[test]
    fn counter_normalization_changes_only_numeric_values_preserving_matching_and_unknown_data() {
        let comparison = expression("cmp", &[5, 0, 1, 0, 0, 0, 0, 0]);
        let first = [
            comparison.clone(),
            counter(5, 600),
            expression("immediate", &[]),
        ]
        .concat();
        let second = [
            comparison.clone(),
            counter(u64::MAX, u64::MAX),
            expression("immediate", &[]),
        ]
        .concat();
        let expected = [
            comparison.clone(),
            counter(0, 0),
            expression("immediate", &[]),
        ]
        .concat();
        assert_eq!(normalize_expressions(&first).unwrap(), expected);
        assert_eq!(normalize_expressions(&second).unwrap(), expected);
        assert_eq!(normalize_expressions(&comparison).unwrap(), comparison);
        let changed = [
            expression("cmp", &[5, 0, 1, 0, 1, 0, 0, 0]),
            counter(5, 600),
        ]
        .concat();
        assert_ne!(
            normalize_expressions(&first).unwrap(),
            normalize_expressions(&changed).unwrap()
        );
        let unknown = expression(
            "counter",
            &[
                attribute(1, &42u64.to_be_bytes()),
                attribute(2, &5u64.to_be_bytes()),
                attribute(19, &[1, 2, 3, 4]),
            ]
            .concat(),
        );
        let normalized = normalize_expressions(&unknown).unwrap();
        assert!(normalized.ends_with(&attribute(19, &[1, 2, 3, 4])));
        for invalid in [
            expression("counter", &attribute(1, &0u64.to_be_bytes())),
            expression(
                "counter",
                &[attribute(1, &[0; 4]), attribute(2, &[0; 8])].concat(),
            ),
            expression(
                "counter",
                &[
                    attribute(1, &[0; 8]),
                    attribute(1, &[0; 8]),
                    attribute(2, &[0; 8]),
                ]
                .concat(),
            ),
            vec![0, 0, 0, 0],
        ] {
            assert!(normalize_expressions(&invalid).is_err());
        }
    }

    #[test]
    fn counter_snapshot_aggregates_expansions_exactly_and_tracks_resets_without_value_drift() {
        let expected = BTreeMap::from([(("forward".into(), KEY.into()), 2)]);
        let rows = vec![
            payload(10, GENERATION, KEY, u64::MAX, u64::MAX),
            payload(11, GENERATION, KEY, u64::MAX, 9007199254740993),
        ];
        let result = snapshot(&rows, &expected).unwrap();
        assert_eq!(
            result["rules"][0]["packets"],
            (u64::MAX as u128 * 2).to_string()
        );
        assert_eq!(
            result["rules"][0]["bytes"],
            (u64::MAX as u128 + 9007199254740993).to_string()
        );
        assert_eq!(result["rules"][0]["expanded_rules"], 2);
        assert_eq!(result["rules"][0]["id"], format!("forward:{KEY}"));
        assert_eq!(result["rules"][0]["config_path"], KEY);
        let generation = &result["generation"];
        assert_eq!(
            *generation,
            snapshot(
                &[
                    payload(11, GENERATION, KEY, 0, 0),
                    payload(10, GENERATION, KEY, 1, 1)
                ],
                &expected
            )
            .unwrap()["generation"]
        );
        assert_ne!(
            *generation,
            snapshot(
                &[
                    payload(12, GENERATION, KEY, 0, 0),
                    payload(13, GENERATION, KEY, 0, 0)
                ],
                &expected
            )
            .unwrap()["generation"]
        );
        assert_ne!(
            *generation,
            snapshot(
                &[
                    payload(10, "ffffffff-ffff-ffff-ffff-ffffffffffff", KEY, 0, 0),
                    payload(11, "ffffffff-ffff-ffff-ffff-ffffffffffff", KEY, 0, 0),
                ],
                &expected
            )
            .unwrap()["generation"]
        );
    }

    #[test]
    fn counter_snapshot_rejects_missing_duplicate_mixed_or_unattributable_rules() {
        let expected = BTreeMap::from([(("forward".into(), KEY.into()), 1)]);
        let good = payload(1, GENERATION, KEY, 0, 0);
        assert!(snapshot(std::slice::from_ref(&good), &expected).is_ok());
        assert!(snapshot(&[], &expected).is_err());
        assert!(snapshot(&[good.clone(), good.clone()], &expected).is_err());
        assert!(snapshot(&[good[..good.len() - 1].to_vec()], &expected).is_err());
        assert!(snapshot(&[payload(0, GENERATION, KEY, 0, 0)], &expected).is_err());
        assert!(
            snapshot(
                &[payload(1, GENERATION, "/firewall/rules/1", 0, 0)],
                &expected
            )
            .is_err()
        );
        let expected = BTreeMap::from([(("forward".into(), KEY.into()), 2)]);
        assert!(snapshot(std::slice::from_ref(&good), &expected).is_err());
        assert!(
            snapshot(
                &[
                    good,
                    payload(2, "ffffffff-ffff-ffff-ffff-ffffffffffff", KEY, 0, 0)
                ],
                &expected
            )
            .is_err()
        );
        assert!(userdata("invalid", KEY).is_err());
        assert!(userdata(GENERATION, "unsafe|key").is_err());
    }

    #[test]
    fn counter_snapshot_requires_exactly_one_counter_and_explicit_generated_identity() {
        let key = "generated/forward/established_related";
        let expected = BTreeMap::from([(("forward".into(), key.into()), 1)]);
        let raw = payload(1, GENERATION, key, 0, 0);
        let snapshot = snapshot(std::slice::from_ref(&raw), &expected).unwrap();
        assert!(snapshot["rules"][0]["config_path"].is_null());
        assert_eq!(snapshot["rules"][0]["id"], format!("forward:{key}"));
        let expressions = ranges(&raw[4..]).unwrap();
        let expression_range = field(&expressions, 4).unwrap();
        let start = expression_range.start;
        let end = 4 + ((expression_range.end + 3) & !3);
        for expressions in [Vec::new(), [counter(1, 1), counter(2, 2)].concat()] {
            let modified = [&raw[..start], &attribute(0x8004, &expressions), &raw[end..]].concat();
            assert!(super::snapshot(&[modified], &expected).is_err());
        }
        assert!(super::snapshot(&vec![raw; 16_385], &expected).is_err());
    }
}
