use super::networking;
use anyhow::{Result, bail, ensure};
use futures_util::TryStreamExt;
use netlink_packet_core::{Emitable, Nla};
use netlink_packet_route::{
    AddressFamily,
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteVia},
};
use rtnetlink::{Handle, IpVersion};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) async fn snapshot(handle: &Handle, scope: &str) -> Result<Value> {
    let names = networking::links(handle)
        .await?
        .iter()
        .map(|link| {
            let parent = networking::parent(link);
            (parent.index, parent.name)
        })
        .collect();
    let mut rows = vec![];
    let mut bytes = 0usize;
    for version in [IpVersion::V4, IpVersion::V6] {
        let mut messages = handle
            .route()
            .get(networking::route_query(version))
            .execute();
        while let Some(message) = messages.try_next().await? {
            bytes += message.buffer_len();
            ensure!(
                rows.len() < 65536 && bytes <= 8 * 1024 * 1024,
                "route table exceeds collection limit (65536 routes / 8 MiB netlink payload)"
            );
            rows.push(decode(&message, &names)?);
        }
    }
    Ok(json!({
        "source":"kernel", "scope":scope,
        "byte_order":if cfg!(target_endian = "little") { "little" } else { "big" },
        "collected_at_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(),
        "routes":rows
    }))
}

fn ip(address: &RouteAddress) -> Result<String> {
    match address {
        RouteAddress::Inet(ip) => Ok(ip.to_string()),
        RouteAddress::Inet6(ip) => Ok(ip.to_string()),
        _ => bail!("non-IP address in IPv4/IPv6 route dump"),
    }
}

fn raw(attribute: &impl Nla) -> Value {
    let mut bytes = vec![0; attribute.value_len()];
    attribute.emit_value(&mut bytes);
    json!({
        "kind":attribute.kind(), "value_hex":hex::encode(bytes),
        "nested":attribute.is_nested(), "network_byte_order":attribute.is_network_byteorder()
    })
}

fn attributes(attributes: &[RouteAttribute]) -> Vec<Value> {
    attributes.iter().map(raw).collect()
}

fn gateway(attributes: &[RouteAttribute]) -> Result<Value> {
    for attribute in attributes {
        match attribute {
            RouteAttribute::Gateway(address) => return Ok(json!(ip(address)?)),
            RouteAttribute::Via(RouteVia::Inet(address)) => return Ok(json!(address.to_string())),
            RouteAttribute::Via(RouteVia::Inet6(address)) => return Ok(json!(address.to_string())),
            _ => {}
        }
    }
    Ok(Value::Null)
}

fn decode(message: &RouteMessage, names: &BTreeMap<u32, String>) -> Result<Value> {
    let header = &message.header;
    let (family, zero) = match header.address_family {
        AddressFamily::Inet => ("ipv4", "0.0.0.0"),
        AddressFamily::Inet6 => ("ipv6", "::"),
        _ => bail!("unexpected route dump address family"),
    };
    let mut destination = zero.to_owned();
    let mut source = zero.to_owned();
    let mut row = json!({
        "family":family, "table":u32::from(header.table), "header_table":header.table,
        "protocol":u8::from(header.protocol), "scope":u8::from(header.scope),
        "type":u8::from(header.kind), "tos":header.tos, "flags":header.flags.bits(),
        "gateway":gateway(&message.attributes)?,
        "interface_index":null, "interface":null,
        "input_interface_index":null, "input_interface":null,
        "preferred_source":null, "metric":null, "preference":null,
        "expires":null, "mark":null, "uid":null, "nexthop_id":null,
        "metrics":[], "cache_info":null, "next_hops":[],
        "attributes":attributes(&message.attributes)
    });
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(address) => destination = ip(address)?,
            RouteAttribute::Source(address) => source = ip(address)?,
            RouteAttribute::PrefSource(address) => row["preferred_source"] = json!(ip(address)?),
            RouteAttribute::Table(table) => row["table"] = json!(table),
            RouteAttribute::Priority(metric) => row["metric"] = json!(metric),
            RouteAttribute::Oif(index) => {
                row["interface_index"] = json!(index);
                row["interface"] = json!(names.get(index));
            }
            RouteAttribute::Iif(index) => {
                row["input_interface_index"] = json!(index);
                row["input_interface"] = json!(names.get(index));
            }
            RouteAttribute::Preference(value) => row["preference"] = json!(u8::from(*value)),
            RouteAttribute::Expires(value) => row["expires"] = json!(value.to_string()),
            RouteAttribute::MulticastExpires(value) => row["expires"] = json!(value.to_string()),
            RouteAttribute::Mark(value) => row["mark"] = json!(value),
            RouteAttribute::Uid(value) => row["uid"] = json!(value),
            RouteAttribute::Metrics(metrics) => {
                row["metrics"] = json!(metrics.iter().map(raw).collect::<Vec<_>>())
            }
            RouteAttribute::CacheInfo(cache) => {
                row["cache_info"] = json!({
                    "clntref":cache.clntref, "last_use":cache.last_use,
                    "expires":cache.expires, "error":cache.error, "used":cache.used,
                    "id":cache.id, "ts":cache.ts, "ts_age":cache.ts_age
                });
            }
            RouteAttribute::MultiPath(hops) => {
                let mut next_hops = vec![];
                for hop in hops {
                    next_hops.push(json!({
                        "interface_index":hop.interface_index,
                        "interface":names.get(&hop.interface_index),
                        "gateway":gateway(&hop.attributes)?,
                        "weight":u16::from(hop.hops) + 1,
                        "flags":hop.flags.bits(),
                        "attributes":attributes(&hop.attributes)
                    }));
                }
                row["next_hops"] = json!(next_hops);
            }
            RouteAttribute::Other(value) if value.kind() == 30 => {
                let mut bytes = vec![0; value.value_len()];
                value.emit_value(&mut bytes);
                ensure!(bytes.len() == 4, "invalid route nexthop ID payload");
                row["nexthop_id"] = json!(u32::from_ne_bytes(
                    bytes.try_into().expect("checked length")
                ));
            }
            _ => {}
        }
    }
    row["destination"] = json!(format!(
        "{destination}/{}",
        header.destination_prefix_length
    ));
    row["source_prefix"] = json!(format!("{source}/{}", header.source_prefix_length));
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{DefaultNla, Parseable};
    use netlink_packet_route::route::{
        RouteMessageBuffer, RouteMetric, RouteNextHop, RouteNextHopFlags, RouteProtocol, RouteType,
    };

    #[test]
    fn route_table_decodes_defaults_local_blackholes_and_extended_tables() -> Result<()> {
        let names = BTreeMap::from([(2, "wan0".into())]);
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut message = RouteMessage::default();
            message.header.address_family = family;
            message.header.table = 254;
            message.header.protocol = RouteProtocol::Other(245);
            message.attributes = vec![
                RouteAttribute::Table(4000000000),
                RouteAttribute::Priority(0),
                RouteAttribute::Oif(2),
                RouteAttribute::Other(DefaultNla::new(30, 123u32.to_ne_bytes().to_vec())),
                RouteAttribute::Other(DefaultNla::new(999, vec![1, 2, 3])),
            ];
            let row = decode(&message, &names)?;
            assert_eq!(
                row["destination"],
                if family == AddressFamily::Inet {
                    "0.0.0.0/0"
                } else {
                    "::/0"
                }
            );
            assert_eq!(row["table"], 4000000000u32);
            assert_eq!(row["protocol"], 245);
            assert_eq!(row["metric"], 0);
            assert_eq!(row["interface"], "wan0");
            assert_eq!(row["nexthop_id"], 123);
            assert_eq!(
                row["attributes"][4],
                json!({"kind":999,"value_hex":"010203","nested":false,"network_byte_order":false})
            );
            message.attributes.clear();
            for kind in [
                RouteType::Local,
                RouteType::BlackHole,
                RouteType::Unreachable,
                RouteType::Prohibit,
            ] {
                message.header.kind = kind;
                let row = decode(&message, &names)?;
                assert_eq!(row["type"], u8::from(kind));
                assert!(row["gateway"].is_null());
                assert!(row["interface_index"].is_null());
                assert!(row["metric"].is_null());
            }
        }
        Ok(())
    }

    #[test]
    fn route_table_preserves_source_metrics_multipath_and_missing_link_names() -> Result<()> {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet6;
        message.header.destination_prefix_length = 64;
        message.header.source_prefix_length = 64;
        let mut hop = RouteNextHop::default();
        hop.interface_index = 77;
        hop.hops = 255;
        hop.flags = RouteNextHopFlags::Onlink;
        hop.attributes = vec![RouteAttribute::Gateway(RouteAddress::Inet6(
            "fe80::1".parse()?,
        ))];
        message.attributes = vec![
            RouteAttribute::Destination(RouteAddress::Inet6("2001:db8:1::".parse()?)),
            RouteAttribute::Source(RouteAddress::Inet6("2001:db8:2::".parse()?)),
            RouteAttribute::PrefSource(RouteAddress::Inet6("2001:db8:2::5".parse()?)),
            RouteAttribute::Metrics(vec![RouteMetric::Mtu(1400)]),
            RouteAttribute::MultiPath(vec![hop]),
        ];
        let row = decode(&message, &BTreeMap::new())?;
        assert_eq!(row["destination"], "2001:db8:1::/64");
        assert_eq!(row["source_prefix"], "2001:db8:2::/64");
        assert_eq!(row["preferred_source"], "2001:db8:2::5");
        assert_eq!(row["next_hops"][0]["weight"], 256);
        assert_eq!(row["next_hops"][0]["gateway"], "fe80::1");
        assert_eq!(row["next_hops"][0]["interface_index"], 77);
        assert!(row["next_hops"][0]["interface"].is_null());
        assert_eq!(row["metrics"][0], raw(&RouteMetric::Mtu(1400)));
        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        let parsed = RouteMessage::parse(&RouteMessageBuffer::new_checked(&bytes)?)?;
        assert_eq!(decode(&parsed, &BTreeMap::new())?, row);
        Ok(())
    }

    #[tokio::test]
    async fn route_table_reads_live_kernel_without_privileged_mutation() -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(connection);
        let result = snapshot(&handle, "test-namespace").await;
        task.abort();
        let snapshot = result?;
        assert_eq!(snapshot["source"], "kernel");
        assert_eq!(snapshot["scope"], "test-namespace");
        assert!(snapshot["collected_at_unix_ms"].is_number());
        let rows = snapshot["routes"].as_array().expect("route array");
        assert!(
            rows.iter()
                .any(|row| row["table"] == 255 && row["type"] == 2)
        );
        Ok(())
    }
}
