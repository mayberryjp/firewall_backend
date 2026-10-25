use crate::netlink_decode::attributes;
use anyhow::{Context, Result, ensure};
use netcontrol_core::ConnectionQuery;
use serde::Serialize;
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = ((value.len() + 4) as u16).to_ne_bytes().to_vec();
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(value);
    bytes.resize((bytes.len() + 3) & !3, 0);
    bytes
}

pub fn delete_attributes(
    id: u32,
    target: &netcontrol_core::ConnectionTarget,
) -> Result<(u8, Vec<u8>)> {
    target.validate()?;
    let mut ip = Vec::new();
    match (target.original.source, target.original.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            ip.extend(attribute(1, &source.octets()));
            ip.extend(attribute(2, &destination.octets()));
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            ip.extend(attribute(3, &source.octets()));
            ip.extend(attribute(4, &destination.octets()));
        }
        _ => anyhow::bail!("connection address families disagree"),
    }
    let mut protocol = attribute(1, &[target.protocol]);
    if let (Some(source), Some(destination)) = (
        target.original.source_port,
        target.original.destination_port,
    ) {
        protocol.extend(attribute(2, &source.to_be_bytes()));
        protocol.extend(attribute(3, &destination.to_be_bytes()));
    } else {
        let kind = if target.protocol == 58 { 7 } else { 4 };
        protocol.extend(attribute(
            kind,
            &target
                .original
                .icmp_id
                .context("missing ICMP ID")?
                .to_be_bytes(),
        ));
        protocol.extend(attribute(
            kind + 1,
            &[target.original.icmp_type.context("missing ICMP type")?],
        ));
        protocol.extend(attribute(
            kind + 2,
            &[target.original.icmp_code.context("missing ICMP code")?],
        ));
    }
    let mut tuple = attribute(0x8001, &ip);
    tuple.extend(attribute(0x8002, &protocol));
    let mut attrs = attribute(0x8001, &tuple);
    attrs.extend(attribute(12, &id.to_be_bytes()));
    attrs.extend(attribute(18, &target.zone.to_be_bytes()));
    Ok((if target.family == "ipv4" { 2 } else { 10 }, attrs))
}

type Attributes = Vec<(u16, Vec<u8>)>;

fn field(attrs: &Attributes, kind: u16) -> Result<Option<&[u8]>> {
    let mut matching = attrs
        .iter()
        .filter(|(candidate, _)| candidate & 0x3fff == kind);
    let value = matching.next().map(|(_, value)| value.as_slice());
    ensure!(
        matching.next().is_none(),
        "duplicate conntrack attribute {kind}"
    );
    Ok(value)
}

fn required(attrs: &Attributes, kind: u16) -> Result<&[u8]> {
    field(attrs, kind)?.with_context(|| format!("missing conntrack attribute {kind}"))
}

fn byte(attrs: &Attributes, kind: u16) -> Result<Option<u8>> {
    field(attrs, kind)?
        .map(|value| {
            ensure!(value.len() == 1, "invalid conntrack byte attribute");
            Ok(value[0])
        })
        .transpose()
}

fn short(attrs: &Attributes, kind: u16) -> Result<Option<u16>> {
    field(attrs, kind)?
        .map(|value| Ok(u16::from_be_bytes(value.try_into()?)))
        .transpose()
}

fn integer(attrs: &Attributes, kind: u16) -> Result<Option<u32>> {
    field(attrs, kind)?
        .map(|value| Ok(u32::from_be_bytes(value.try_into()?)))
        .transpose()
}

#[derive(Debug, Serialize)]
struct Tuple {
    source: IpAddr,
    destination: IpAddr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    icmp_id: Option<u16>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    zone: Option<u16>,
}

fn tuple(bytes: &[u8], family: u8) -> Result<(u8, Tuple)> {
    let tuple = attributes(bytes)?;
    let ip = attributes(required(&tuple, 1)?)?;
    let protocol = attributes(required(&tuple, 2)?)?;
    let (source, destination) = if family == 2 {
        (
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(required(&ip, 1)?)?)),
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(required(&ip, 2)?)?)),
        )
    } else {
        (
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(required(&ip, 3)?)?)),
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(required(&ip, 4)?)?)),
        )
    };
    let number = byte(&protocol, 1)?.context("missing conntrack protocol")?;
    let icmp = if number == 58 { 7 } else { 4 };
    Ok((
        number,
        Tuple {
            source,
            destination,
            source_port: short(&protocol, 2)?,
            destination_port: short(&protocol, 3)?,
            icmp_id: short(&protocol, icmp)?,
            icmp_type: byte(&protocol, icmp + 1)?,
            icmp_code: byte(&protocol, icmp + 2)?,
            zone: short(&tuple, 3)?,
        },
    ))
}

#[derive(Debug, Serialize)]
struct Counters {
    packets: String,
    bytes: String,
}

fn counters(bytes: Option<&[u8]>) -> Result<Option<Counters>> {
    let Some(bytes) = bytes else { return Ok(None) };
    let attrs = attributes(bytes)?;
    let counter = |kind| -> Result<String> {
        if let Some(value) = field(&attrs, kind)? {
            return Ok(u64::from_be_bytes(value.try_into()?).to_string());
        }
        Ok(u32::from_be_bytes(required(&attrs, kind + 2)?.try_into()?).to_string())
    };
    Ok(Some(Counters {
        packets: counter(1)?,
        bytes: counter(2)?,
    }))
}

#[derive(Debug, Serialize)]
struct Connection {
    id: Option<String>,
    zone: u16,
    family: &'static str,
    protocol: u8,
    protocol_name: &'static str,
    state: String,
    tcp_state: Option<u8>,
    status: u32,
    seen_reply: bool,
    assured: bool,
    source_nat: bool,
    destination_nat: bool,
    mark: u32,
    timeout_seconds: Option<u32>,
    original: Tuple,
    reply: Tuple,
    original_counters: Option<Counters>,
    reply_counters: Option<Counters>,
}

fn decode(payload: &[u8]) -> Result<Connection> {
    ensure!(
        payload.len() >= 4 && matches!(payload[0], 2 | 10) && payload[1] == 0,
        "invalid conntrack nfgen header"
    );
    let attrs = attributes(&payload[4..])?;
    let (protocol, original) = tuple(required(&attrs, 1)?, payload[0])?;
    let (reply_protocol, reply) = tuple(required(&attrs, 2)?, payload[0])?;
    ensure!(
        protocol == reply_protocol,
        "conntrack tuple protocols disagree"
    );
    let status = integer(&attrs, 3)?.context("missing conntrack status")?;
    let tcp_state = if protocol == 6 {
        if let Some(info) = field(&attrs, 4)? {
            let info = attributes(info)?;
            if let Some(tcp) = field(&info, 1)? {
                byte(&attributes(tcp)?, 1)?
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    let state = match tcp_state {
        Some(0) => "NONE",
        Some(1) => "SYN_SENT",
        Some(2) => "SYN_RECV",
        Some(3) => "ESTABLISHED",
        Some(4) => "FIN_WAIT",
        Some(5) => "CLOSE_WAIT",
        Some(6) => "LAST_ACK",
        Some(7) => "TIME_WAIT",
        Some(8) => "CLOSE",
        Some(9) => "LISTEN",
        Some(10) => "SYN_SENT2",
        Some(_) => "UNKNOWN",
        None if status & 4 != 0 => "ASSURED",
        None if status & 2 != 0 => "SEEN_REPLY",
        None => "UNREPLIED",
    }
    .to_string();
    Ok(Connection {
        id: integer(&attrs, 12)?.map(|id| id.to_string()),
        zone: short(&attrs, 18)?.unwrap_or(0),
        family: if payload[0] == 2 { "ipv4" } else { "ipv6" },
        protocol,
        protocol_name: match protocol {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            58 => "icmpv6",
            132 => "sctp",
            _ => "other",
        },
        state,
        tcp_state,
        status,
        seen_reply: status & 2 != 0,
        assured: status & 4 != 0,
        source_nat: status & 16 != 0,
        destination_nat: status & 32 != 0,
        mark: integer(&attrs, 8)?.unwrap_or(0),
        timeout_seconds: integer(&attrs, 7)?,
        original,
        reply,
        original_counters: counters(field(&attrs, 9)?)?,
        reply_counters: counters(field(&attrs, 10)?)?,
    })
}

impl Connection {
    fn matches(&self, query: &ConnectionQuery) -> bool {
        query
            .family
            .as_deref()
            .is_none_or(|family| family == self.family)
            && query
                .protocol
                .is_none_or(|protocol| protocol == self.protocol)
            && query.zone.is_none_or(|zone| zone == self.zone)
            && query.address.is_none_or(|address| {
                [&self.original, &self.reply]
                    .iter()
                    .any(|tuple| tuple.source == address || tuple.destination == address)
            })
            && query.port.is_none_or(|port| {
                [&self.original, &self.reply].iter().any(|tuple| {
                    tuple.source_port == Some(port) || tuple.destination_port == Some(port)
                })
            })
    }
}

pub fn snapshot(payloads: &[Vec<u8>], query: &ConnectionQuery) -> Result<Value> {
    ensure!(
        payloads.len() <= 100_000,
        "conntrack snapshot exceeds 100000 entries"
    );
    let mut matches = Vec::new();
    for payload in payloads {
        let entry = decode(payload)?;
        if entry.matches(query) {
            matches.push(entry);
        }
    }
    matches.sort_by(|left, right| {
        (
            left.zone,
            &left.id,
            left.original.source,
            left.original.destination,
            left.protocol,
            left.original.source_port,
            left.original.destination_port,
            left.original.icmp_id,
        )
            .cmp(&(
                right.zone,
                &right.id,
                right.original.source,
                right.original.destination,
                right.protocol,
                right.original.source_port,
                right.original.destination_port,
                right.original.icmp_id,
            ))
    });
    let matched = matches.len();
    let unavailable = matches
        .iter()
        .filter(|entry| entry.original_counters.is_none() || entry.reply_counters.is_none())
        .count();
    let connections: Vec<_> = matches
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .collect();
    let returned = connections.len();
    let next = (query.offset.saturating_add(returned) < matched).then_some(query.offset + returned);
    Ok(json!({
        "schema": "netcontrol-connections/v1", "connections": connections,
        "summary": {"total": payloads.len(), "matched": matched, "returned": returned, "accounting_unavailable": unavailable},
        "limit": query.limit, "offset": query.offset, "next_offset": next
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_delete_attributes_bind_original_tuple_id_and_zone() {
        let mut target: netcontrol_core::ConnectionTarget = serde_json::from_value(serde_json::json!({"family":"ipv4","protocol":6,"zone":7,"original":{"source":"192.0.2.2","destination":"198.51.100.2","source_port":50000,"destination_port":443}})).unwrap();
        let (family, bytes) = delete_attributes(123, &target).unwrap();
        assert_eq!(family, 2);
        let attrs = attributes(&bytes).unwrap();
        assert_eq!(integer(&attrs, 12).unwrap(), Some(123));
        assert_eq!(short(&attrs, 18).unwrap(), Some(7));
        let (protocol, original) = tuple(required(&attrs, 1).unwrap(), family).unwrap();
        assert_eq!(protocol, 6);
        assert_eq!(original.source.to_string(), "192.0.2.2");
        assert_eq!(original.destination_port, Some(443));
        target.family = "ipv6".into();
        target.protocol = 58;
        target.original.source = "2001:db8::1".parse().unwrap();
        target.original.destination = "2001:db8::2".parse().unwrap();
        target.original.source_port = None;
        target.original.destination_port = None;
        target.original.icmp_id = Some(0x1234);
        target.original.icmp_type = Some(128);
        target.original.icmp_code = Some(0);
        let (family, bytes) = delete_attributes(456, &target).unwrap();
        let attrs = attributes(&bytes).unwrap();
        let (protocol, original) = tuple(required(&attrs, 1).unwrap(), family).unwrap();
        assert_eq!(family, 10);
        assert_eq!(protocol, 58);
        assert_eq!(original.icmp_id, Some(0x1234));
        assert_eq!(original.icmp_type, Some(128));
    }

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = ((value.len() + 4) as u16).to_ne_bytes().to_vec();
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }
    fn joined(parts: Vec<Vec<u8>>) -> Vec<u8> {
        parts.into_iter().flatten().collect()
    }
    fn wire_tuple(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        joined(vec![
            attr(
                0x8001,
                &joined(vec![attr(1, &source), attr(2, &destination)]),
            ),
            attr(
                0x8002,
                &joined(vec![
                    attr(1, &[6]),
                    attr(2, &source_port.to_be_bytes()),
                    attr(3, &destination_port.to_be_bytes()),
                ]),
            ),
        ])
    }
    fn record(accounting: bool) -> Vec<u8> {
        let mut bytes = vec![2, 0, 0, 0];
        bytes.extend(joined(vec![
            attr(
                0x8001,
                &wire_tuple([192, 0, 2, 10], [198, 51, 100, 20], 40000, 443),
            ),
            attr(
                0x8002,
                &wire_tuple([198, 51, 100, 20], [203, 0, 113, 10], 443, 50000),
            ),
            attr(3, &22u32.to_be_bytes()),
            attr(7, &120u32.to_be_bytes()),
            attr(12, &42u32.to_be_bytes()),
            attr(0x8004, &attr(0x8001, &attr(1, &[3]))),
        ]));
        if accounting {
            for kind in [9, 10] {
                bytes.extend(attr(
                    kind | 0x8000,
                    &joined(vec![
                        attr(1, &u64::MAX.to_be_bytes()),
                        attr(2, &9007199254740993u64.to_be_bytes()),
                    ]),
                ));
            }
        }
        bytes
    }
    #[test]
    fn conntrack_preserves_nat_state_and_precise_directional_counters() {
        let value = snapshot(
            &[record(true)],
            &ConnectionQuery::parse("port=50000&address=203.0.113.10").unwrap(),
        )
        .unwrap();
        assert_eq!(value["summary"]["matched"], 1);
        let entry = &value["connections"][0];
        assert_eq!(entry["state"], "ESTABLISHED");
        assert_eq!(entry["source_nat"], true);
        assert_eq!(entry["original"]["source"], "192.0.2.10");
        assert_eq!(entry["reply"]["destination"], "203.0.113.10");
        assert_eq!(entry["original_counters"]["packets"], u64::MAX.to_string());
        assert_eq!(entry["reply_counters"]["bytes"], "9007199254740993");
    }
    #[test]
    fn conntrack_distinguishes_missing_accounting_and_applies_bounded_paging() {
        let values = vec![record(false), record(true)];
        let page = snapshot(&values, &ConnectionQuery::parse("limit=1").unwrap()).unwrap();
        assert_eq!(page["summary"]["accounting_unavailable"], 1);
        assert_eq!(page["next_offset"], 1);
        assert!(page["connections"][0]["original_counters"].is_null());
        assert_eq!(
            snapshot(&values, &ConnectionQuery::parse("family=ipv6").unwrap()).unwrap()["summary"]
                ["matched"],
            0
        );
        assert_eq!(
            snapshot(&values, &ConnectionQuery::parse("offset=100").unwrap()).unwrap()["connections"],
            json!([])
        );
    }
    #[test]
    fn conntrack_decodes_ipv6_icmp_and_unknown_protocols_without_fake_ports() {
        let source = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let destination = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
        let wire_tuple = |source: &[u8], destination: &[u8], protocol| {
            joined(vec![
                attr(0x8001, &joined(vec![attr(3, source), attr(4, destination)])),
                attr(
                    0x8002,
                    &joined(vec![
                        attr(1, &[protocol]),
                        attr(7, &42u16.to_be_bytes()),
                        attr(8, &[128]),
                        attr(9, &[0]),
                    ]),
                ),
            ])
        };
        let mut record = vec![10, 0, 0, 0];
        record.extend(joined(vec![
            attr(0x8001, &wire_tuple(&source, &destination, 58)),
            attr(0x8002, &wire_tuple(&destination, &source, 58)),
            attr(3, &0u32.to_be_bytes()),
        ]));
        let value = snapshot(
            &[record],
            &ConnectionQuery::parse("family=ipv6&protocol=icmpv6&address=2001%3Adb8%3A%3A1")
                .unwrap(),
        )
        .unwrap();
        let entry = &value["connections"][0];
        assert_eq!(entry["family"], "ipv6");
        assert_eq!(entry["original"]["icmp_id"], 42);
        assert!(entry["original"]["source_port"].is_null());
        assert!(entry["id"].is_null());
        assert!(entry["timeout_seconds"].is_null());
        let mut unknown = vec![10, 0, 0, 0];
        unknown.extend(joined(vec![
            attr(0x8001, &wire_tuple(&source, &destination, 253)),
            attr(0x8002, &wire_tuple(&destination, &source, 253)),
            attr(3, &0u32.to_be_bytes()),
        ]));
        assert_eq!(decode(&unknown).unwrap().protocol_name, "other");
        let bytes = joined(vec![
            attr(3, &5u32.to_be_bytes()),
            attr(4, &100u32.to_be_bytes()),
        ]);
        let counted = counters(Some(&bytes)).unwrap().unwrap();
        assert_eq!(counted.packets, "5");
        assert_eq!(counted.bytes, "100");
    }

    #[test]
    fn conntrack_rejects_truncated_or_ambiguous_kernel_records() {
        let value = record(true);
        for end in 0..4 {
            assert!(decode(&value[..end]).is_err());
        }
        assert!(decode(&value[..value.len() - 1]).is_err());
        let mut duplicate = value.clone();
        duplicate.extend(attr(3, &0u32.to_be_bytes()));
        assert!(decode(&duplicate).is_err());
        let mut unsupported = value;
        unsupported[0] = 99;
        assert!(decode(&unsupported).is_err());
    }
}
