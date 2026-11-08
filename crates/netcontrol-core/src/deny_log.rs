use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyTrafficTag {
    TcpFinish,
    TcpReset,
    TcpAckOnly,
    TcpConnectionAttempt,
    Ipv4Broadcast,
}

impl DenyTrafficTag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TcpFinish => "tcp_finish",
            Self::TcpReset => "tcp_reset",
            Self::TcpAckOnly => "tcp_ack_only",
            Self::TcpConnectionAttempt => "tcp_connection_attempt",
            Self::Ipv4Broadcast => "ipv4_broadcast",
        }
    }

    pub fn tcp(flags: Option<u8>, payload_length: Option<u32>) -> Vec<Self> {
        let mut tags = Vec::new();
        if let Some(flags) = flags {
            if flags & 0x01 != 0 {
                tags.push(Self::TcpFinish);
            }
            if flags & 0x04 != 0 {
                tags.push(Self::TcpReset);
            }
            if flags == 0x10 && payload_length == Some(0) {
                tags.push(Self::TcpAckOnly);
            }
            if flags & 0x17 == 0x02 {
                tags.push(Self::TcpConnectionAttempt);
            }
        }
        tags
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRecord {
    pub id: String,
    pub timestamp_ms: u64,
    pub chain: String,
    pub reason: String,
    pub compiled_rule_index: Option<u32>,
    pub ruleset_id: String,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub ingress_index: Option<u32>,
    pub egress_index: Option<u32>,
    pub ingress: Option<String>,
    pub egress: Option<String>,
    pub packet_length: u32,
    pub tcp_flags: Option<u8>,
    pub tcp_payload_length: Option<u32>,
    pub tags: Vec<DenyTrafficTag>,
}

impl DenyRecord {
    pub fn matches_traffic_categories(
        &self,
        include_broadcast: bool,
        include_tcp_closures: bool,
    ) -> bool {
        (include_broadcast || !self.tags.contains(&DenyTrafficTag::Ipv4Broadcast))
            && (include_tcp_closures
                || !self.tags.iter().any(|tag| {
                    matches!(
                        tag,
                        DenyTrafficTag::TcpFinish
                            | DenyTrafficTag::TcpReset
                            | DenyTrafficTag::TcpAckOnly
                    )
                }))
    }

    pub fn validate_traffic(&self) -> Result<()> {
        let tcp_tags = DenyTrafficTag::tcp(self.tcp_flags, self.tcp_payload_length);
        let broadcast = self.tags.contains(&DenyTrafficTag::Ipv4Broadcast);
        let mut expected = tcp_tags;
        if broadcast {
            expected.push(DenyTrafficTag::Ipv4Broadcast);
        }
        ensure!(
            (self.protocol == 6 || self.tcp_flags.is_none())
                && self.tcp_payload_length.is_none_or(|length| {
                    self.tcp_flags.is_some() && length <= self.packet_length
                })
                && (!broadcast || self.destination.is_ipv4())
                && (!matches!(self.destination, IpAddr::V4(ip) if ip.is_broadcast()) || broadcast)
                && self.tags == expected,
            "invalid deny-log traffic metadata"
        );
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    limit: Option<String>,
    before_id: Option<String>,
    since_ms: Option<String>,
    until_ms: Option<String>,
    address: Option<String>,
    protocol: Option<String>,
    chain: Option<String>,
    include_broadcast: Option<String>,
    include_tcp_closures: Option<String>,
}

#[derive(Debug)]
pub struct DenyLogQuery {
    pub limit: usize,
    pub before_id: Option<u64>,
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
    pub address: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub chain: Option<String>,
    pub include_broadcast: bool,
    pub include_tcp_closures: bool,
}

fn number(value: &str, maximum: u64) -> Result<u64> {
    let number: u64 = value.parse()?;
    ensure!(
        number <= maximum && number.to_string() == value,
        "noncanonical or out-of-range deny-log query number"
    );
    Ok(number)
}

impl DenyLogQuery {
    pub fn parse(query: &str) -> Result<Self> {
        ensure!(query.len() <= 4096, "deny-log query exceeds 4096 bytes");
        let fields: Parameters = serde_urlencoded::from_str(query)?;
        let limit = fields
            .limit
            .as_deref()
            .map(|v| number(v, 500))
            .transpose()?
            .unwrap_or(100);
        ensure!(limit > 0, "deny-log limit must be 1..500");
        let before_id = fields
            .before_id
            .as_deref()
            .map(|v| number(v, u64::MAX))
            .transpose()?;
        ensure!(before_id != Some(0), "before_id must be positive");
        let since_ms = fields
            .since_ms
            .as_deref()
            .map(|v| number(v, 253_402_300_799_999))
            .transpose()?;
        let until_ms = fields
            .until_ms
            .as_deref()
            .map(|v| number(v, 253_402_300_799_999))
            .transpose()?;
        ensure!(
            since_ms.zip(until_ms).is_none_or(|(a, b)| a <= b),
            "since_ms must not exceed until_ms"
        );
        let address = fields
            .address
            .as_deref()
            .map(|value| -> Result<IpAddr> {
                let address: IpAddr = value.parse()?;
                ensure!(
                    address.to_string() == value,
                    "address must be a canonical IP literal"
                );
                Ok(address)
            })
            .transpose()?;
        let protocol = fields
            .protocol
            .as_deref()
            .map(|v| number(v, 255).map(|v| v as u8))
            .transpose()?;
        ensure!(
            fields
                .chain
                .as_deref()
                .is_none_or(|v| matches!(v, "input" | "forward")),
            "chain must be input or forward"
        );
        Ok(Self {
            limit: limit as usize,
            before_id,
            since_ms,
            until_ms,
            address,
            protocol,
            chain: fields.chain,
            include_broadcast: fields
                .include_broadcast
                .as_deref()
                .map(str::parse::<bool>)
                .transpose()?
                .unwrap_or(false),
            include_tcp_closures: fields
                .include_tcp_closures
                .as_deref()
                .map(str::parse::<bool>)
                .transpose()?
                .unwrap_or(false),
        })
    }

    pub fn matches(&self, record: &DenyRecord) -> bool {
        self.since_ms.is_none_or(|v| record.timestamp_ms >= v)
            && self.until_ms.is_none_or(|v| record.timestamp_ms <= v)
            && self
                .address
                .is_none_or(|v| record.source == v || record.destination == v)
            && self.protocol.is_none_or(|v| record.protocol == v)
            && self.chain.as_ref().is_none_or(|v| &record.chain == v)
            && record.matches_traffic_categories(self.include_broadcast, self.include_tcp_closures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_log_query_is_bounded_and_strict() {
        assert_eq!(DenyLogQuery::parse("").unwrap().limit, 100);
        let defaults = DenyLogQuery::parse("").unwrap();
        assert!(!defaults.include_broadcast && !defaults.include_tcp_closures);
        for include_broadcast in [false, true] {
            for include_tcp_closures in [false, true] {
                let query = DenyLogQuery::parse(&format!(
                    "include_broadcast={include_broadcast}&include_tcp_closures={include_tcp_closures}"
                ))
                .unwrap();
                assert_eq!(query.include_broadcast, include_broadcast);
                assert_eq!(query.include_tcp_closures, include_tcp_closures);
            }
        }
        let query = DenyLogQuery::parse("limit=500&before_id=18446744073709551615&since_ms=0&until_ms=1&address=2001%3Adb8%3A%3A1&protocol=17&chain=forward").unwrap();
        assert_eq!(query.before_id, Some(u64::MAX));
        for bad in [
            "limit=0",
            "limit=501",
            "limit=01",
            "before_id=0",
            "before_id=-1",
            "protocol=256",
            "chain=output",
            "address=example.test",
            "since_ms=2&until_ms=1",
            "limit=1&limit=2",
            "unknown=1",
            "until_ms=253402300800000",
            "tag=unknown",
            "tag=ipv4_broadcast",
            "tag=",
            "tag=tcp_reset&tag=tcp_finish",
            "exclude_tags=",
            "exclude_tags=tcp_finish,tcp_reset",
            "exclude_tags=ipv4_broadcast",
            "exclude_tags=tcp_reset,",
            "exclude_tags=tcp_reset,tcp_reset",
            "exclude_tags=tcp_reset,unknown",
            "exclude_tags=tcp_reset,%20tcp_finish",
            "exclude_tags=tcp_reset&exclude_tags=tcp_finish",
            "include_broadcast=",
            "include_broadcast=1",
            "include_broadcast=True",
            "include_broadcast=false&include_broadcast=true",
            "include_tcp_closures=",
            "include_tcp_closures=0",
            "include_tcp_closures=FALSE",
            "include_tcp_closures=%20true",
            "include_tcp_closures=true&include_tcp_closures=true",
        ] {
            assert!(DenyLogQuery::parse(bad).is_err(), "{bad}");
        }
        assert!(DenyLogQuery::parse(&"a".repeat(4097)).is_err());
    }

    #[test]
    fn deny_log_category_filters_combine_with_existing_selection() {
        let base: DenyRecord = serde_json::from_value(serde_json::json!({
            "id":"1","timestamp_ms":10,"chain":"forward","reason":"rule","compiled_rule_index":0,
            "ruleset_id":"a".repeat(64),"source":"192.0.2.1","destination":"198.51.100.1",
            "protocol":6,"source_port":1234,"destination_port":443,
            "ingress_index":null,"egress_index":null,"ingress":null,"egress":null,"packet_length":40,
            "tcp_flags":16,"tcp_payload_length":0,"tags":["tcp_ack_only"]
        }))
        .unwrap();
        for include_broadcast in [false, true] {
            for include_tcp_closures in [false, true] {
                let query = DenyLogQuery::parse(&format!(
                    "include_broadcast={include_broadcast}&include_tcp_closures={include_tcp_closures}&protocol=6&chain=forward&address=192.0.2.1&since_ms=10&until_ms=10"
                ))
                .unwrap();
                for flags in [0x11, 0x14, 0x15, 0x10, 0x02, 0x18] {
                    for broadcast in [false, true] {
                        let mut record = base.clone();
                        record.tcp_flags = Some(flags);
                        record.tags = DenyTrafficTag::tcp(Some(flags), Some(0));
                        if broadcast {
                            record.destination = "255.255.255.255".parse().unwrap();
                            record.tags.push(DenyTrafficTag::Ipv4Broadcast);
                        }
                        record.validate_traffic().unwrap();
                        assert_eq!(
                            query.matches(&record),
                            (!broadcast || include_broadcast)
                                && (!matches!(flags, 0x11 | 0x14 | 0x15 | 0x10)
                                    || include_tcp_closures)
                        );
                    }
                }
                for (flags, payload) in [(Some(0x10), None), (Some(0x10), Some(1)), (None, None)] {
                    let mut record = base.clone();
                    record.tcp_flags = flags;
                    record.tcp_payload_length = payload;
                    record.tags = DenyTrafficTag::tcp(flags, payload);
                    assert!(query.matches(&record));
                    record.timestamp_ms = 11;
                    assert!(!query.matches(&record));
                    record.timestamp_ms = 10;
                    record.chain = "input".into();
                    assert!(!query.matches(&record));
                    record.chain = "forward".into();
                    record.source = "192.0.2.2".parse().unwrap();
                    assert!(!query.matches(&record));
                    record.source = base.source;
                    record.protocol = 17;
                    assert!(!query.matches(&record));
                }
            }
        }
    }

    #[test]
    fn deny_log_tcp_tags_describe_flags_not_connection_state() {
        use DenyTrafficTag::*;
        assert_eq!(DenyTrafficTag::tcp(Some(0x11), Some(0)), [TcpFinish]);
        assert_eq!(DenyTrafficTag::tcp(Some(0x14), Some(0)), [TcpReset]);
        assert_eq!(
            DenyTrafficTag::tcp(Some(0x15), Some(0)),
            [TcpFinish, TcpReset]
        );
        assert_eq!(DenyTrafficTag::tcp(Some(0x10), Some(0)), [TcpAckOnly]);
        assert!(DenyTrafficTag::tcp(Some(0x10), Some(1)).is_empty());
        assert!(DenyTrafficTag::tcp(Some(0x10), None).is_empty());
        assert!(DenyTrafficTag::tcp(Some(0x18), Some(0)).is_empty());
        assert!(DenyTrafficTag::tcp(Some(0x30), Some(0)).is_empty());
        assert_eq!(
            DenyTrafficTag::tcp(Some(0x02), Some(0)),
            [TcpConnectionAttempt]
        );
        assert!(DenyTrafficTag::tcp(Some(0x12), Some(0)).is_empty());
        assert!(DenyTrafficTag::tcp(None, None).is_empty());
    }
}
