use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
pub enum DNSRecordType {
    #[default]
    A,
    AAAA,
}
impl DNSRecordType {
    pub fn number(self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
        }
    }
}
fn timeout() -> u64 {
    2000
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DNSLookupRequest {
    pub interface: String,
    pub hostname: String,
    #[serde(default)]
    pub record_type: DNSRecordType,
    #[serde(default = "timeout")]
    pub timeout_ms: u64,
}
impl DNSLookupRequest {
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            crate::valid_interface_name(&self.interface),
            "invalid DNS interface"
        );
        ensure!(
            (100..=5000).contains(&self.timeout_ms),
            "timeout_ms must be 100..5000"
        );
        let host = self.hostname.strip_suffix('.').unwrap_or(&self.hostname);
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && host.is_ascii()
                && host.parse::<std::net::IpAddr>().is_err()
                && host.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "hostname must be a DNS name with 1..63-character ASCII labels, at most 253 characters"
        );
        self.hostname = host.to_ascii_lowercase();
        Ok(())
    }
}

pub type DNSLookup = Box<dyn FnOnce() -> Result<serde_json::Value> + Send>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_inputs_are_bounded_and_do_not_accept_arbitrary_servers() {
        let mut request: DNSLookupRequest =
            serde_json::from_str(r#"{"interface":"wan0","hostname":"Google.COM."}"#).unwrap();
        request.validate().unwrap();
        assert_eq!(request.hostname, "google.com");
        assert_eq!(request.timeout_ms, 2000);
        for host in [
            "",
            "127.0.0.1",
            "bad..test",
            "-bad.test",
            "bad_.test",
            "a.test\n",
        ] {
            request.hostname = host.into();
            assert!(request.validate().is_err());
        }
        assert!(
            serde_json::from_str::<DNSLookupRequest>(
                r#"{"interface":"wan0","hostname":"example.test","server":"192.0.2.1"}"#
            )
            .is_err()
        );
    }
}
