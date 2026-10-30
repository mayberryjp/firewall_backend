use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_log_query_is_bounded_and_strict() {
        assert_eq!(DenyLogQuery::parse("").unwrap().limit, 100);
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
        ] {
            assert!(DenyLogQuery::parse(bad).is_err(), "{bad}");
        }
        assert!(DenyLogQuery::parse(&"a".repeat(4097)).is_err());
    }
}
