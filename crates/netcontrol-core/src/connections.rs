use anyhow::{Result, ensure};
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTuple {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub icmp_id: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub zone: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTarget {
    pub family: String,
    pub protocol: u8,
    pub zone: u16,
    pub original: ConnectionTuple,
}

impl ConnectionTarget {
    pub fn validate(&self) -> Result<()> {
        let tuple = &self.original;
        ensure!(
            matches!(self.family.as_str(), "ipv4" | "ipv6"),
            "connection family must be ipv4 or ipv6"
        );
        ensure!(
            (self.family == "ipv4") == tuple.source.is_ipv4()
                && tuple.source.is_ipv4() == tuple.destination.is_ipv4(),
            "connection family and tuple addresses disagree"
        );
        ensure!(
            tuple.zone.is_none_or(|zone| zone == self.zone),
            "direction-specific zones are not supported for deletion"
        );
        match self.protocol {
            6 | 17 | 132 => ensure!(
                tuple.source_port.is_some()
                    && tuple.destination_port.is_some()
                    && tuple.icmp_id.is_none()
                    && tuple.icmp_type.is_none()
                    && tuple.icmp_code.is_none(),
                "TCP/UDP/SCTP deletion requires both ports and no ICMP fields"
            ),
            1 | 58 => {
                ensure!(
                    (self.protocol == 1) == (self.family == "ipv4"),
                    "ICMP protocol and family disagree"
                );
                ensure!(
                    tuple.source_port.is_none()
                        && tuple.destination_port.is_none()
                        && tuple.icmp_id.is_some()
                        && tuple.icmp_type.is_some()
                        && tuple.icmp_code.is_some(),
                    "ICMP deletion requires ID/type/code and no ports"
                );
            }
            _ => anyhow::bail!("targeted deletion supports TCP, UDP, SCTP, ICMP and ICMPv6 only"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionQuery {
    pub limit: usize,
    pub offset: usize,
    pub family: Option<String>,
    pub protocol: Option<u8>,
    pub address: Option<IpAddr>,
    pub port: Option<u16>,
    pub zone: Option<u16>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    limit: Option<String>,
    offset: Option<String>,
    family: Option<String>,
    protocol: Option<String>,
    address: Option<String>,
    port: Option<String>,
    zone: Option<String>,
}

fn number(value: &str, maximum: u32) -> Result<u32> {
    let number: u32 = value.parse()?;
    ensure!(
        number <= maximum && number.to_string() == value,
        "noncanonical or out-of-range connection query number"
    );
    Ok(number)
}

impl ConnectionQuery {
    pub fn parse(query: &str) -> Result<Self> {
        ensure!(query.len() <= 4096, "connection query exceeds 4096 bytes");
        let fields: Parameters = serde_urlencoded::from_str(query)?;
        let limit = fields
            .limit
            .as_deref()
            .map(|value| number(value, 1000))
            .transpose()?
            .unwrap_or(100) as usize;
        ensure!(limit > 0, "connection limit must be 1..1000");
        let offset = fields
            .offset
            .as_deref()
            .map(|value| number(value, 1_000_000))
            .transpose()?
            .unwrap_or(0) as usize;
        ensure!(
            fields
                .family
                .as_deref()
                .is_none_or(|value| matches!(value, "ipv4" | "ipv6")),
            "connection family must be ipv4 or ipv6"
        );
        let protocol = fields
            .protocol
            .as_deref()
            .map(|value| -> Result<u8> {
                Ok(match value {
                    "icmp" => 1,
                    "tcp" => 6,
                    "udp" => 17,
                    "icmpv6" => 58,
                    "sctp" => 132,
                    _ => number(value, 255)? as u8,
                })
            })
            .transpose()?;
        let address = fields
            .address
            .as_deref()
            .map(|value| -> Result<IpAddr> {
                let address: IpAddr = value.parse()?;
                ensure!(
                    address.to_string() == value,
                    "connection address must be a canonical IP literal"
                );
                Ok(address)
            })
            .transpose()?;
        if let (Some(family), Some(address)) = (&fields.family, address) {
            ensure!(
                (family == "ipv4") == address.is_ipv4(),
                "connection address and family disagree"
            );
        }
        Ok(Self {
            limit,
            offset,
            family: fields.family,
            protocol,
            address,
            port: fields
                .port
                .as_deref()
                .map(|value| number(value, 65535).map(|value| value as u16))
                .transpose()?,
            zone: fields
                .zone
                .as_deref()
                .map(|value| number(value, 65535).map(|value| value as u16))
                .transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targeted_connection_deletion_validates_complete_protocol_identity() {
        let mut target: ConnectionTarget = serde_json::from_value(serde_json::json!({"family":"ipv4","protocol":17,"zone":0,"original":{"source":"192.0.2.2","destination":"198.51.100.2","source_port":1234,"destination_port":53}})).unwrap();
        target.validate().unwrap();
        target.original.destination_port = None;
        assert!(target.validate().is_err());
        target.protocol = 1;
        target.original.source_port = None;
        target.original.icmp_id = Some(42);
        target.original.icmp_type = Some(8);
        target.original.icmp_code = Some(0);
        target.validate().unwrap();
        target.protocol = 58;
        assert!(target.validate().is_err());
        target.family = "ipv6".into();
        target.original.source = "2001:db8::1".parse().unwrap();
        target.original.destination = "2001:db8::2".parse().unwrap();
        target.original.icmp_type = Some(128);
        target.validate().unwrap();
        target.original.zone = Some(7);
        assert!(target.validate().is_err());
        target.original.zone = None;
        target.protocol = 47;
        assert!(target.validate().is_err());
    }

    #[test]
    fn connection_query_defaults_filters_and_url_decoding() {
        let defaults = ConnectionQuery::parse("").unwrap();
        assert_eq!(defaults.limit, 100);
        assert_eq!(defaults.offset, 0);
        let filtered = ConnectionQuery::parse("family=ipv6&protocol=tcp&address=2001%3Adb8%3A%3A1&port=443&zone=0&limit=1000&offset=10").unwrap();
        assert_eq!(filtered.address, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(filtered.protocol, Some(6));
        assert_eq!(filtered.port, Some(443));
        assert_eq!(filtered.limit, 1000);
        assert_eq!(
            ConnectionQuery::parse("protocol=255").unwrap().protocol,
            Some(255)
        );
    }

    #[test]
    fn connection_query_rejects_ambiguous_or_unbounded_input() {
        for query in [
            "limit=0",
            "limit=1001",
            "limit=01",
            "limit=+1",
            "limit=1&limit=2",
            "unknown=1",
            "offset=1000001",
            "family=all",
            "protocol=TCP",
            "protocol=256",
            "address=host.example",
            "address=2001:0db8::1",
            "family=ipv4&address=::1",
            "port=65536",
            "zone=-1",
            "limit=%FF",
        ] {
            assert!(ConnectionQuery::parse(query).is_err(), "accepted {query}");
        }
    }
}
