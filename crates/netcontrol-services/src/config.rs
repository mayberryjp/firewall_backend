use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Ntp {
    pub enabled: bool,
    pub servers: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    pub host: String,
    pub port: u16,
    pub transport: String,
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Syslog {
    pub enabled: bool,
    pub servers: Vec<Destination>,
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Vnstat {
    pub enabled: bool,
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Relay {
    pub enabled: bool,
    pub servers: Vec<String>,
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Interface {
    pub name: String,
    pub kind: String,
    pub up: bool,
    pub addresses: Vec<String>,
    pub dhcp_relay: Relay,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Flow {
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    pub collector: String,
    pub export_version: u16,
    pub sampling_rate: u32,
    pub max_flows: usize,
    pub snaplen: usize,
    pub promiscuous: bool,
    #[serde(default)]
    pub capture_filter: String,
    #[serde(default)]
    pub timeouts: BTreeMap<String, u64>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum CaptureFilter {
    All,
    Ipv4,
    Ipv6,
    Protocol(u8),
}
impl CaptureFilter {
    pub(crate) fn matches(self, ipv6: bool, protocol: u8) -> bool {
        match self {
            Self::All => true,
            Self::Ipv4 => !ipv6,
            Self::Ipv6 => ipv6,
            Self::Protocol(1) => !ipv6 && protocol == 1,
            Self::Protocol(58) => ipv6 && protocol == 58,
            Self::Protocol(p) => protocol == p,
        }
    }
}
impl Flow {
    pub(crate) fn filter(&self) -> Result<CaptureFilter> {
        match self.capture_filter.as_str() {
            "" => Ok(CaptureFilter::All),
            "ip" => Ok(CaptureFilter::Ipv4),
            "ip6" => Ok(CaptureFilter::Ipv6),
            "tcp" => Ok(CaptureFilter::Protocol(6)),
            "udp" => Ok(CaptureFilter::Protocol(17)),
            "icmp" => Ok(CaptureFilter::Protocol(1)),
            "icmp6" => Ok(CaptureFilter::Protocol(58)),
            _ => bail!(
                "native capture_filter supports only empty, ip, ip6, tcp, udp, icmp, or icmp6"
            ),
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gateway {
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    #[serde(default = "explicit_mode")]
    pub mode: String,
    #[serde(default)]
    pub source_address: String,
    #[serde(default)]
    pub gateway: String,
    pub target: String,
    #[serde(default)]
    pub routing_table: u32,
    #[serde(skip)]
    pub routing_mark: Option<u32>,
    #[serde(default = "probe_interval")]
    pub probe_interval_ms: u64,
    #[serde(default = "loss_timeout")]
    pub loss_timeout_ms: u64,
    #[serde(default = "window")]
    pub window_ms: u64,
    #[serde(default = "latency_threshold")]
    pub latency_threshold_ms: u64,
    #[serde(default = "loss_threshold")]
    pub loss_threshold_percent: u64,
    #[serde(default)]
    pub rtt_variation_threshold_ms: u64,
    #[serde(default = "failure_hold")]
    pub failure_hold_ms: u64,
    #[serde(default = "recovery_hold")]
    pub recovery_hold_ms: u64,
}
fn explicit_mode() -> String {
    "explicit".into()
}
fn probe_interval() -> u64 {
    1000
}
fn loss_timeout() -> u64 {
    2000
}
fn window() -> u64 {
    30000
}
fn latency_threshold() -> u64 {
    150
}
fn loss_threshold() -> u64 {
    20
}
fn failure_hold() -> u64 {
    3000
}
fn recovery_hold() -> u64 {
    5000
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub(crate) struct Config {
    pub mdns: netcontrol_core::MDNSConfig,
    pub udp_broadcast_relay: netcontrol_core::UDPBroadcastRelayConfig,
    #[serde(skip)]
    pub mdns_interfaces: Vec<String>,
    #[serde(skip)]
    pub mdns_status: Value,
    pub ipv6_enabled: bool,
    pub ntp: Ntp,
    pub syslog: Syslog,
    pub vnstat: Vnstat,
    pub interfaces: Vec<Interface>,
    pub softflowd: Vec<Flow>,
    pub gateway_monitors: Vec<Gateway>,
    pub routes: Vec<Value>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            mdns: Default::default(),
            udp_broadcast_relay: Default::default(),
            mdns_interfaces: Vec::new(),
            mdns_status: Value::Null,
            ipv6_enabled: true,
            ntp: Ntp::default(),
            syslog: Syslog::default(),
            vnstat: Vnstat::default(),
            interfaces: Vec::new(),
            softflowd: Vec::new(),
            gateway_monitors: Vec::new(),
            routes: Vec::new(),
        }
    }
}
pub(crate) fn name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
pub(crate) fn interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value != "lo"
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
}
pub(crate) fn unicast(ip: IpAddr, link_local: bool) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_loopback()
                && !v.is_link_local()
                && v.octets()[0] != 0
        }
        IpAddr::V6(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_loopback()
                && v.to_ipv4_mapped().is_none()
                && (link_local || !v.is_unicast_link_local())
        }
    }
}
fn address(text: &str, link_local: bool) -> Result<IpAddr> {
    let ip: IpAddr = text.parse().context("invalid IP address")?;
    ensure!(
        ip.to_string() == text && unicast(ip, link_local),
        "noncanonical or nonunicast address {text}"
    );
    Ok(ip)
}
fn host(text: &str) -> bool {
    if let Ok(ip) = text.parse::<IpAddr>() {
        return ip.to_string() == text && (unicast(ip, false) || ip.is_loopback());
    }
    text.len() <= 253
        && !text.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && text.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
pub(crate) fn contains(prefix: &str, ip: IpAddr) -> bool {
    let Some((text, bits)) = prefix.split_once('/') else {
        return false;
    };
    let (Ok(base), Ok(bits)) = (text.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (base, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) if bits <= 32 => {
            bits == 0 || (u32::from(a) >> (32 - bits)) == (u32::from(b) >> (32 - bits))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if bits <= 128 => {
            bits == 0 || (u128::from(a) >> (128 - bits)) == (u128::from(b) >> (128 - bits))
        }
        _ => false,
    }
}
impl Interface {
    pub(crate) fn relay_address(&self) -> Result<Ipv4Addr> {
        let mut addresses = self.addresses.clone();
        addresses.sort();
        for a in addresses {
            let Some((text, bits)) = a.split_once('/') else {
                bail!("invalid interface prefix {a}")
            };
            let ip: IpAddr = text.parse()?;
            let n: u32 = bits.parse()?;
            ensure!(
                n <= if ip.is_ipv4() { 32 } else { 128 },
                "invalid prefix length"
            );
            if let IpAddr::V4(v) = ip {
                if unicast(ip, false) {
                    return Ok(v);
                }
            }
        }
        bail!("relay {} requires a unicast IPv4 address", self.name)
    }
}
impl Config {
    pub(crate) fn parse(v: &Value) -> Result<Self> {
        ensure!(v.is_object(), "service configuration must be an object");
        let mut c: Self = serde_json::from_value(v.clone()).context("service configuration")?;
        if v.get("udp_broadcast_relay").is_some() {
            let config: netcontrol_core::Config =
                serde_json::from_value(v.clone()).context("UDP relay operational configuration")?;
            c.udp_broadcast_relay.validate(&config)?;
        }
        if v.get("mdns").is_some() {
            let config: netcontrol_core::Config = serde_json::from_value(serde_json::json!({
                "mdns":v["mdns"], "interfaces":v.get("interfaces").cloned().unwrap_or_else(||serde_json::json!([])),
                "ipv6_enabled":c.ipv6_enabled,
                "system":v.get("system").cloned().unwrap_or_else(||serde_json::json!({}))
            }))
                .context("mDNS operational configuration")?;
            config.mdns.validate(&config)?;
            c.mdns_interfaces = config.mdns.effective_interfaces(&config);
            c.mdns_status = config.mdns.status(&config, "disabled");
            c.mdns.ipv6 &= c.ipv6_enabled;
        }
        ensure!(
            c.ntp.servers.len() <= 8 && (!c.ntp.enabled || !c.ntp.servers.is_empty()),
            "NTP requires 1..8 servers when enabled"
        );
        let mut seen = BTreeSet::new();
        for h in &c.ntp.servers {
            ensure!(
                host(h) && seen.insert(h),
                "invalid/duplicate NTP server {h}"
            );
        }
        ensure!(
            c.syslog.servers.len() <= 8 && (!c.syslog.enabled || !c.syslog.servers.is_empty()),
            "syslog requires 1..8 destinations when enabled"
        );
        let mut seen = BTreeSet::new();
        for d in &c.syslog.servers {
            ensure!(
                host(&d.host)
                    && d.port != 0
                    && ["udp", "tcp", "tls"].contains(&d.transport.as_str()),
                "invalid syslog destination"
            );
            ensure!(
                seen.insert((&d.host, d.port, &d.transport)),
                "duplicate syslog destination"
            );
        }
        let mut ips = BTreeSet::new();
        let mut names = BTreeSet::new();
        for i in &c.interfaces {
            ensure!(
                interface(&i.name) && names.insert(&i.name),
                "invalid/duplicate interface name"
            );
            ensure!(
                i.dhcp_relay.servers.len() <= 64,
                "DHCP relay supports at most 64 upstream servers"
            );
            let mut servers = BTreeSet::new();
            for s in &i.dhcp_relay.servers {
                let ip = address(s, false)?;
                ensure!(
                    ip.is_ipv4() && servers.insert(ip),
                    "DHCP upstreams must be unique IPv4"
                );
            }
            if i.dhcp_relay.enabled {
                ensure!(
                    i.up && ["ethernet", "dummy", "vlan"].contains(&i.kind.as_str())
                        && !servers.is_empty(),
                    "relay requires up Ethernet/dummy/VLAN and upstream servers"
                );
                ensure!(
                    ips.insert(i.relay_address()?),
                    "duplicate DHCP relay address"
                );
            }
        }
        ensure!(c.softflowd.len() <= 16, "at most 16 flow exporters");
        let mut seen = BTreeSet::new();
        for f in &c.softflowd {
            ensure!(
                name(&f.name, 32) && seen.insert(&f.name) && interface(&f.interface),
                "invalid flow name/interface"
            );
            let a: SocketAddr = f
                .collector
                .parse()
                .context("numeric collector IP:port required")?;
            ensure!(
                a.to_string() == f.collector
                    && a.port() != 0
                    && (unicast(a.ip(), false) || a.ip().is_loopback()),
                "invalid collector address"
            );
            ensure!(
                [1, 5, 9, 10].contains(&f.export_version),
                "invalid NetFlow version"
            );
            ensure!(
                (1..=1_000_000).contains(&f.sampling_rate)
                    && (1..=1_000_000).contains(&f.max_flows)
                    && (64..=65535).contains(&f.snaplen),
                "invalid flow sampling/capacity/snaplen"
            );
            ensure!(
                f.capture_filter.len() <= 4096
                    && !f.capture_filter.bytes().any(|b| b"\r\n\0".contains(&b)),
                "invalid capture filter"
            );
            for (k, v) in &f.timeouts {
                ensure!(
                    [
                        "general", "tcp", "tcp.rst", "tcp.fin", "udp", "icmp", "maxlife", "expint"
                    ]
                    .contains(&k.as_str())
                        && *v <= 604800
                        && (*v > 0 || k != "general"),
                    "invalid flow timeout"
                );
            }
            f.filter()?;
            ensure!(
                f.export_version != 5 || f.sampling_rate <= 16383,
                "NetFlow v5 sampling interval is limited to 16383"
            );
        }
        ensure!(
            c.gateway_monitors.len() <= 64,
            "at most 64 gateway monitors"
        );
        let mut seen = BTreeSet::new();
        let mut source_tables = std::collections::BTreeMap::new();
        for m in &c.gateway_monitors {
            ensure!(
                name(&m.name, 32) && seen.insert(&m.name) && interface(&m.interface),
                "invalid gateway name/interface"
            );
            let dst = address(&m.target, true)?;
            ensure!(
                matches!(m.mode.as_str(), "explicit" | "dhcp"),
                "invalid gateway mode"
            );
            if m.mode == "dhcp" {
                ensure!(
                    m.source_address.is_empty()
                        && m.gateway.is_empty()
                        && m.routing_table == 0
                        && dst.is_ipv4(),
                    "DHCP gateway fields must be automatic and target IPv4"
                );
                ensure!(
                    v["dhcp_clients"].get(&m.interface).is_some()
                        && c.interfaces
                            .iter()
                            .any(|link| link.name == m.interface && (!m.enabled || link.up)),
                    "DHCP monitor requires a DHCP interface"
                );
            } else {
                let src = address(&m.source_address, false)?;
                let gw = address(&m.gateway, true)?;
                ensure!(
                    src.is_ipv4() == gw.is_ipv4()
                        && src.is_ipv4() == dst.is_ipv4()
                        && src != gw
                        && src != dst
                        && (m.routing_table == 254 || (10000..=19999).contains(&m.routing_table)),
                    "invalid gateway family/source/table"
                );
            }
            ensure!(
                (100..=60000).contains(&m.probe_interval_ms)
                    && (100..=60000).contains(&m.loss_timeout_ms)
                    && m.loss_timeout_ms <= 10 * m.probe_interval_ms
                    && (1000..=300000).contains(&m.window_ms)
                    && m.window_ms >= 2 * m.loss_timeout_ms
                    && m.window_ms >= 3 * m.probe_interval_ms
                    && m.window_ms <= 1024 * m.probe_interval_ms,
                "invalid gateway timing"
            );
            ensure!(
                (1..=60000).contains(&m.latency_threshold_ms)
                    && (1..=100).contains(&m.loss_threshold_percent)
                    && m.rtt_variation_threshold_ms <= 60000
                    && (100..=60000).contains(&m.failure_hold_ms)
                    && (100..=60000).contains(&m.recovery_hold_ms),
                "invalid gateway thresholds"
            );
            if m.enabled && m.mode == "explicit" {
                let src = address(&m.source_address, false)?;
                let gw = address(&m.gateway, true)?;
                ensure!(
                    source_tables
                        .insert(src, m.routing_table)
                        .is_none_or(|table| table == m.routing_table),
                    "enabled gateway monitors sharing a source address must use the same routing table"
                );
                ensure!(
                    c.interfaces.iter().any(|i| i.name == m.interface
                        && i.up
                        && i.addresses
                            .iter()
                            .any(|p| p.split('/').next() == Some(m.source_address.as_str()))),
                    "gateway source missing on up managed interface"
                );
                ensure!(
                    c.routes.iter().any(|r| r["interface"] == m.interface
                        && r["table"].as_u64() == Some(m.routing_table as u64)
                        && r["destination"].as_str().is_some_and(|p| contains(p, dst))
                        && (r["gateway"] == m.gateway
                            || (dst == gw && r["gateway"].as_str().unwrap_or("").is_empty()))),
                    "gateway requires matching explicit route"
                );
            }
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_monitor_uses_internal_routing_not_public_rules() {
        let example: Value =
            serde_json::from_str(include_str!("../../../examples/gateway-monitoring.json"))
                .unwrap();
        let mut value = example["config"].clone();
        Config::parse(&value).unwrap();
        let mut duplicate = value["gateway_monitors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|monitor| monitor["mode"] != "dhcp")
            .unwrap()
            .clone();
        duplicate["name"] = serde_json::json!("second-probe");
        value["gateway_monitors"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        Config::parse(&value).unwrap();
        let mut route = value["routes"][0].clone();
        route["table"] = serde_json::json!(10002);
        value["routes"].as_array_mut().unwrap().push(route);
        let duplicate_index = value["gateway_monitors"].as_array().unwrap().len() - 1;
        value["gateway_monitors"][duplicate_index]["routing_table"] = serde_json::json!(10002);
        assert!(
            Config::parse(&value)
                .unwrap_err()
                .to_string()
                .contains("same routing table")
        );
        value["gateway_monitors"][duplicate_index]["enabled"] = serde_json::json!(false);
        Config::parse(&value).unwrap();
    }

    use serde_json::json;
    #[test]
    fn ethernet_relay_and_main_table_gateway_are_supported() {
        let mut value = json!({
            "interfaces":[{"name":"nic0","kind":"ethernet","up":true,"addresses":["192.0.2.2/24"],"dhcp_relay":{"enabled":true,"servers":["198.51.100.10"]}}],
            "gateway_monitors":[{"name":"wan","enabled":false,"interface":"nic0","source_address":"192.0.2.2","gateway":"192.0.2.1","target":"203.0.113.1","routing_table":254}]
        });
        assert!(Config::parse(&value).is_ok());
        value["gateway_monitors"][0]["routing_table"] = json!(253);
        assert!(Config::parse(&value).is_err());
        value["gateway_monitors"][0]["routing_table"] = json!(254);
        value["interfaces"][0]["up"] = json!(false);
        assert!(Config::parse(&value).is_err());
    }

    #[test]
    fn bounds_and_strict_service_fields() {
        assert!(Config::parse(&json!({})).is_ok());
        assert!(Config::parse(&json!({"ntp":{"enabled":true,"servers":[]}})).is_err());
        assert!(Config::parse(&json!({"ntp":{"enabled":false,"unexpected":1}})).is_err());
        assert!(
            Config::parse(
                &json!({"syslog":{"servers":[{"host":"UPPER","port":514,"transport":"udp"}]}})
            )
            .is_err()
        );
        assert!(Config::parse(&json!({"ntp":{"servers":["127.0.0.1"]}})).is_ok());
    }
    #[test]
    fn prefix_families_and_zero() {
        assert!(interface("wan.100"));
        assert!(!interface("../bad"));
        assert!(contains("0.0.0.0/0", "192.0.2.1".parse().unwrap()));
        assert!(!contains("::/0", "192.0.2.1".parse().unwrap()));
        assert!(contains("2001:db8::/32", "2001:db8::1".parse().unwrap()));
        assert!(!contains("192.0.2.0/33", "192.0.2.1".parse().unwrap()));
    }
    #[test]
    fn supported_flow_versions_and_typed_filters() {
        let mut flow = json!({"name":"flows","enabled":false,"interface":"wan.100","collector":"192.0.2.100:2055","export_version":9,"sampling_rate":1000000,"max_flows":100,"snaplen":128,"promiscuous":false,"capture_filter":"udp","timeouts":{}});
        assert!(Config::parse(&json!({"softflowd":[flow.clone()]})).is_ok());
        let parsed: Flow = serde_json::from_value(flow.clone()).unwrap();
        assert!(parsed.filter().unwrap().matches(true, 17));
        assert!(!parsed.filter().unwrap().matches(false, 6));
        flow["capture_filter"] = json!("udp port 53");
        assert!(Config::parse(&json!({"softflowd":[flow.clone()]})).is_err());
        flow["capture_filter"] = json!("");
        flow["export_version"] = json!(1);
        assert!(Config::parse(&json!({"softflowd":[flow.clone()]})).is_ok());
        flow["export_version"] = json!(5);
        assert!(Config::parse(&json!({"softflowd":[flow.clone()]})).is_err());
        flow["sampling_rate"] = json!(1);
        assert!(Config::parse(&json!({"softflowd":[flow]})).is_ok());
    }
}
