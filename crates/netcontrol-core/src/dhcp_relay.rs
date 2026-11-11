use anyhow::{Result, ensure};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    cursor: Option<String>,
    limit: Option<String>,
    interface: Option<String>,
}

#[derive(Debug)]
pub struct DHCPRelayLogQuery {
    pub cursor: Option<(String, u64)>,
    pub limit: usize,
    pub interface: Option<String>,
}

impl DHCPRelayLogQuery {
    pub fn parse(query: &str) -> Result<Self> {
        ensure!(
            query.len() <= 1024,
            "DHCP relay log query exceeds 1024 bytes"
        );
        let fields: Parameters = serde_urlencoded::from_str(query)?;
        let limit = fields.limit.as_deref().unwrap_or("100");
        let parsed: usize = limit.parse()?;
        ensure!(
            (1..=500).contains(&parsed) && parsed.to_string() == limit,
            "DHCP relay log limit must be canonical 1..500"
        );
        if let Some(name) = &fields.interface {
            ensure!(crate::valid_interface_name(name), "invalid relay interface");
        }
        let cursor = fields
            .cursor
            .map(|value| -> Result<_> {
                let (epoch, sequence) = value
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("invalid relay log cursor"))?;
                ensure!(
                    epoch.len() == 32
                        && epoch
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid relay log cursor epoch"
                );
                let number: u64 = sequence.parse()?;
                ensure!(
                    number.to_string() == sequence,
                    "invalid relay log cursor sequence"
                );
                Ok((epoch.to_owned(), number))
            })
            .transpose()?;
        Ok(Self {
            cursor,
            limit: parsed,
            interface: fields.interface,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_log_query_is_strict_and_bounded() {
        assert_eq!(DHCPRelayLogQuery::parse("").unwrap().limit, 100);
        assert!(DHCPRelayLogQuery::parse("limit=500&interface=vlan10").is_ok());
        assert!(DHCPRelayLogQuery::parse("cursor=0123456789abcdef0123456789abcdef%3A0").is_ok());
        for query in [
            "limit=0",
            "limit=501",
            "limit=01",
            "limit=+1",
            "limit=1&limit=2",
            "unknown=1",
            "interface=",
            "interface=bad/name",
            "cursor=",
            "cursor=bad:1",
            "cursor=0123456789abcdef0123456789abcdef:01",
        ] {
            assert!(DHCPRelayLogQuery::parse(query).is_err(), "{query}");
        }
    }
}
