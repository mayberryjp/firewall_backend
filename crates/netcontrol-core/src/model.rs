use anyhow::{Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

fn yes() -> bool {
    true
}
fn accept() -> String {
    "accept".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub ntp: NTPConfig,
    pub syslog: SyslogConfig,
    pub vnstat: VNStatConfig,
    pub gateway_monitors: Vec<GatewayMonitor>,
    pub interfaces: Vec<Interface>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub dhcp_clients: BTreeMap<String, DHCPClientConfig>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub dns: BTreeMap<String, DNSConfig>,
    pub routes: Vec<Route>,
    pub policy_rules: Vec<Rule>,
    pub firewall: Firewall,
    pub softflowd: Vec<SoftflowdConfig>,
    pub kernel: KernelConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    pub kind: String,
    pub role: String,
    pub mtu: i64,
    pub up: bool,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub dhcp_relay: DHCPRelayConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<VLAN>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    pub key_ref: String,
    pub listen_port: i64,
    #[serde(default)]
    pub peers: Vec<Peer>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive_seconds: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VLAN {
    pub parent: String,
    pub id: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DHCPRelayConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DHCPClientConfig {
    pub client_id: String,
    pub hostname: String,
    pub route_metric: u32,
    pub use_mtu: bool,
    pub use_domains: String,
}
impl Default for DHCPClientConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            hostname: String::new(),
            route_metric: 0,
            use_mtu: false,
            use_domains: "no".into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DNSConfig {
    pub servers: Vec<String>,
    pub domains: Vec<DNSDomain>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DNSDomain {
    pub name: String,
    pub route_only: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub destination: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    pub interface: String,
    pub table: i64,
    pub metric: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub priority: i64,
    pub source: String,
    pub table: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Firewall {
    #[serde(default = "yes")]
    pub allow_all_icmp: bool,
    #[serde(default = "accept")]
    pub policy: String,
    pub rules: Vec<FirewallRule>,
    pub nat: NAT,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<FirewallPolicies>,
}
impl Default for Firewall {
    fn default() -> Self {
        Self {
            allow_all_icmp: true,
            policy: accept(),
            rules: vec![],
            nat: NAT::default(),
            policies: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NAT {
    pub masquerade: Vec<MasqueradeRule>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasqueradeRule {
    pub family: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    pub out_interface: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub destination: String,
    pub action: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallPolicies {
    pub hosts: Vec<FirewallHost>,
    pub interfaces: Vec<InterfacePolicy>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallHost {
    pub id: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub policy: String,
    #[serde(default)]
    pub rules: Vec<HostPolicyRule>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfacePolicy {
    pub interface: String,
    #[serde(default)]
    pub rules: Vec<HostPolicyRule>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicyRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub destination_host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub destination: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_ports: Vec<i64>,
    pub action: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NTPConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub servers: Vec<SyslogServer>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogServer {
    pub host: String,
    pub port: i64,
    pub transport: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct VNStatConfig {
    pub enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftflowdConfig {
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    pub collector: String,
    pub export_version: i64,
    pub sampling_rate: i64,
    pub max_flows: i64,
    pub snaplen: i64,
    pub promiscuous: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub capture_filter: String,
    #[serde(default)]
    pub timeouts: BTreeMap<String, i64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct KernelConfig {
    pub namespace: BTreeMap<String, String>,
    pub host: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayMonitor {
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    pub source_address: String,
    pub gateway: String,
    pub target: String,
    pub routing_table: i64,
    #[serde(default)]
    pub probe_interval_ms: i64,
    #[serde(default)]
    pub loss_timeout_ms: i64,
    #[serde(default)]
    pub window_ms: i64,
    #[serde(default)]
    pub latency_threshold_ms: i64,
    #[serde(default)]
    pub loss_threshold_percent: i64,
    #[serde(default)]
    pub rtt_variation_threshold_ms: i64,
    #[serde(default)]
    pub failure_hold_ms: i64,
    #[serde(default)]
    pub recovery_hold_ms: i64,
}

pub fn valid_interface_name(s: &str) -> bool {
    !["lo", ".", ".."].contains(&s) && valid_name(s, 15, true)
}
fn valid_name(s: &str, max: usize, dots: bool) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || (dots && c == b'.'))
}
pub fn canonical_ip(s: &str) -> Result<IpAddr> {
    let ip: IpAddr = s.parse()?;
    ensure!(
        ip.to_string() == s && !matches!(ip,IpAddr::V6(a) if a.to_ipv4_mapped().is_some()),
        "non-canonical IP address {s:?}"
    );
    Ok(ip)
}
pub fn global_unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(a) => !a.is_link_local() && a.octets() != [255, 255, 255, 255],
            IpAddr::V6(a) => a.segments()[0] & 0xffc0 != 0xfe80,
        }
}
pub fn canonical_prefix(s: &str, network: bool) -> Result<(IpAddr, u8)> {
    let (text, bits) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid IP prefix {s:?}"))?;
    let ip = canonical_ip(text)?;
    let bits: u8 = bits.parse()?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    ensure!(
        bits <= width && format!("{ip}/{bits}") == s,
        "non-canonical IP prefix {s:?}"
    );
    if network {
        ensure!(masked(ip, bits) == ip, "non-canonical network prefix {s:?}");
    }
    Ok((ip, bits))
}
fn masked(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(
            (u32::from(a)
                & if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                })
            .into(),
        ),
        IpAddr::V6(a) => IpAddr::V6(
            (u128::from(a)
                & if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                })
            .into(),
        ),
    }
}
fn contains(prefix: &str, ip: IpAddr) -> bool {
    canonical_prefix(prefix, true)
        .is_ok_and(|(a, b)| a.is_ipv4() == ip.is_ipv4() && masked(ip, b) == a)
}
fn valid_host(host: &str) -> bool {
    if let Ok(a) = canonical_ip(host) {
        return global_unicast(a) || a.is_loopback();
    }
    !host.is_empty()
        && host.len() <= 253
        && !host.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && host.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
fn socket(s: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = s.parse()?;
    canonical_ip(&addr.ip().to_string())?;
    ensure!(
        addr.port() != 0 && addr.to_string() == s && !s.contains('%'),
        "endpoint must be canonical numeric IP:port"
    );
    Ok(addr)
}
fn action(s: &str) -> bool {
    matches!(s, "accept" | "drop")
}

impl Config {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn normalize(&mut self) {
        self.ntp.servers.sort();
        self.syslog
            .servers
            .sort_by_key(|s| format!("{}:{}:{}", s.transport, s.host, s.port));
        self.gateway_monitors.sort_by(|a, b| a.name.cmp(&b.name));
        for m in &mut self.gateway_monitors {
            m.normalize();
        }
        self.softflowd.sort_by(|a, b| a.name.cmp(&b.name));
        for l in &mut self.interfaces {
            l.addresses.sort();
            l.dhcp_relay.servers.sort();
            if let Some(w) = &mut l.wireguard {
                for p in &mut w.peers {
                    p.allowed_ips.sort();
                }
                w.peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
            }
        }
        for dns in self.dns.values_mut() {
            dns.domains
                .sort_by(|a, b| a.name.cmp(&b.name).then(a.route_only.cmp(&b.route_only)));
        }
        self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        self.routes
            .sort_by_key(|r| format!("{}/{}/{}", r.table, r.destination, r.metric));
        self.policy_rules.sort_by_key(|r| r.priority);
        if let Some(p) = &mut self.firewall.policies {
            p.hosts.sort_by(|a, b| a.id.cmp(&b.id));
            p.interfaces.sort_by(|a, b| a.interface.cmp(&b.interface));
            for h in &mut p.hosts {
                h.addresses.sort();
                for r in &mut h.rules {
                    r.destination_ports.sort();
                }
            }
            for i in &mut p.interfaces {
                for r in &mut i.rules {
                    r.destination_ports.sort();
                }
            }
        }
    }
    pub fn normalized(&self) -> Self {
        let mut c = self.clone();
        c.normalize();
        c
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.ntp.servers.len() <= 8 && (!self.ntp.enabled || !self.ntp.servers.is_empty()),
            "NTP requires 1..8 servers when enabled"
        );
        let mut seen = BTreeSet::new();
        for h in &self.ntp.servers {
            ensure!(
                valid_host(h) && seen.insert(h),
                "invalid or duplicate NTP server {h:?}"
            );
        }
        ensure!(
            self.syslog.servers.len() <= 8
                && (!self.syslog.enabled || !self.syslog.servers.is_empty()),
            "syslog requires 1..8 servers when enabled"
        );
        let mut destinations = BTreeSet::new();
        for s in &self.syslog.servers {
            ensure!(
                valid_host(&s.host)
                    && (1..=65535).contains(&s.port)
                    && ["udp", "tcp", "tls"].contains(&s.transport.as_str())
                    && destinations.insert((&s.host, s.port, &s.transport)),
                "invalid or duplicate syslog destination"
            );
        }
        self.kernel.validate()?;
        let mut names = BTreeSet::new();
        let mut vlan_ids = BTreeSet::new();
        let mut relay_addresses = BTreeSet::new();
        for l in &self.interfaces {
            ensure!(
                valid_interface_name(&l.name) && names.insert(&l.name),
                "invalid or duplicate interface name {:?}",
                l.name
            );
            ensure!(
                ["wan", "lan", "unassigned"].contains(&l.role.as_str()),
                "interface {}: role must be wan, lan or unassigned",
                l.name
            );
            ensure!(
                ["ethernet", "dummy", "wireguard", "vlan"].contains(&l.kind.as_str()),
                "supported kinds are ethernet, dummy, wireguard, and vlan"
            );
            ensure!((1280..=65535).contains(&l.mtu), "MTU must be 1280..65535");
            let mut addresses = BTreeSet::new();
            for a in &l.addresses {
                let (ip, _) = canonical_prefix(a, false)?;
                ensure!(
                    global_unicast(ip) && addresses.insert(a),
                    "invalid or duplicate interface address"
                );
            }
            match (&l.wireguard, l.kind.as_str()) {
                (Some(w), "wireguard") => {
                    ensure!(
                        valid_name(&w.key_ref, 64, false) && (1..=65535).contains(&w.listen_port),
                        "invalid WireGuard key reference or listen port"
                    );
                    let mut keys = BTreeSet::new();
                    let mut allowed = BTreeSet::new();
                    for p in &w.peers {
                        let key = STANDARD.decode(&p.public_key)?;
                        ensure!(
                            key.len() == 32
                                && key.iter().any(|b| *b != 0)
                                && STANDARD.encode(&key) == p.public_key
                                && keys.insert(&p.public_key),
                            "invalid or duplicate WireGuard public key"
                        );
                        if !p.endpoint.is_empty() {
                            socket(&p.endpoint)?;
                        }
                        ensure!(
                            (0..=65535).contains(&p.persistent_keepalive_seconds),
                            "invalid keepalive"
                        );
                        for a in &p.allowed_ips {
                            canonical_prefix(a, true)?;
                            ensure!(allowed.insert(a), "duplicate WireGuard allowed IP");
                        }
                    }
                }
                (None, "wireguard") => bail!("WireGuard configuration required"),
                (Some(_), _) => bail!("WireGuard settings require wireguard kind"),
                _ => {}
            }
            match (&l.vlan, l.kind.as_str()) {
                (Some(v), "vlan") => {
                    ensure!(
                        valid_interface_name(&v.parent)
                            && (1..=4094).contains(&v.id)
                            && vlan_ids.insert((&v.parent, v.id)),
                        "invalid or duplicate VLAN parent/ID"
                    );
                    let mut visited = BTreeSet::new();
                    let mut current = l;
                    while let Some(v) = &current.vlan {
                        ensure!(visited.insert(&current.name), "VLAN parent cycle");
                        if let Some(parent) = self.interfaces.iter().find(|i| i.name == v.parent) {
                            ensure!(
                                parent.kind != "wireguard" && current.mtu <= parent.mtu,
                                "invalid VLAN parent kind or MTU"
                            );
                            current = parent;
                        } else {
                            break;
                        }
                    }
                }
                (None, "vlan") => bail!("VLAN configuration required"),
                (Some(_), _) => bail!("VLAN settings require vlan kind"),
                _ => {}
            }
            let mut servers = BTreeSet::new();
            for s in &l.dhcp_relay.servers {
                let a = canonical_ip(s)?;
                ensure!(
                    a.is_ipv4() && global_unicast(a) && servers.insert(s),
                    "invalid or duplicate DHCP relay server"
                );
            }
            if l.dhcp_relay.enabled {
                ensure!(
                    l.up && ["ethernet", "dummy", "vlan"].contains(&l.kind.as_str())
                        && !l.dhcp_relay.servers.is_empty(),
                    "enabled DHCP relay requires up Ethernet/dummy/VLAN and servers"
                );
                let addr = l
                    .addresses
                    .iter()
                    .filter_map(|s| canonical_prefix(s, false).ok())
                    .map(|p| p.0)
                    .filter(|a| a.is_ipv4())
                    .min()
                    .ok_or_else(|| anyhow::anyhow!("DHCP relay requires IPv4 address"))?;
                ensure!(
                    relay_addresses.insert(addr),
                    "DHCP relays require distinct relay addresses"
                );
            }
        }
        let mut routes = BTreeSet::new();
        for (name, client) in &self.dhcp_clients {
            ensure!(
                matches!(client.use_domains.as_str(), "no" | "route" | "yes"),
                "invalid DHCP use_domains"
            );
            let interface = self
                .interfaces
                .iter()
                .find(|link| &link.name == name)
                .ok_or_else(|| anyhow::anyhow!("DHCP client interface {name} is not configured"))?;
            ensure!(
                interface.kind == "ethernet" && !interface.dhcp_relay.enabled,
                "DHCP clients require Ethernet without a DHCP relay"
            );
            ensure!(
                client.hostname.len() <= 253
                    && (client.hostname.is_empty() || valid_host(&client.hostname)),
                "invalid DHCP hostname"
            );
            if !client.client_id.is_empty() {
                let identifier = hex::decode(&client.client_id)?;
                ensure!(
                    (2..=255).contains(&identifier.len()),
                    "DHCP client_id must encode 2..255 bytes including its type"
                );
            }
            ensure!(
                !interface.addresses.iter().any(|prefix| prefix
                    .split('/')
                    .next()
                    .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())),
                "DHCP interfaces cannot also have static IPv4 addresses"
            );
        }
        for (name, dns) in &self.dns {
            ensure!(
                self.interfaces.iter().any(|link| &link.name == name),
                "DNS interface {name:?} is not configured"
            );
            ensure!(
                dns.servers.len() <= 8 && dns.domains.len() <= 32,
                "DNS supports at most 8 servers and 32 domains per interface"
            );
            let mut servers = BTreeSet::new();
            for server in &dns.servers {
                let ip = canonical_ip(server)?;
                ensure!(
                    (global_unicast(ip) || ip.is_loopback()) && servers.insert(server),
                    "invalid or duplicate DNS server"
                );
            }
            let mut domains = BTreeSet::new();
            for domain in &dns.domains {
                ensure!(
                    ((domain.name == "." && domain.route_only)
                        || (valid_host(&domain.name) && domain.name.parse::<IpAddr>().is_err()))
                        && domains.insert(&domain.name),
                    "invalid or duplicate DNS domain"
                );
            }
        }
        for r in &self.routes {
            let (a, _) = canonical_prefix(&r.destination, true)?;
            ensure!(
                names.contains(&r.interface)
                    && (r.table == 254 || (10000..=19999).contains(&r.table))
                    && (1..=2147483647).contains(&r.metric),
                "route requires managed interface, table 254 or 10000..19999, positive 32-bit metric"
            );
            if !r.gateway.is_empty() {
                ensure!(
                    canonical_ip(&r.gateway)?.is_ipv4() == a.is_ipv4(),
                    "route gateway family mismatch"
                );
            }
            ensure!(
                routes.insert((r.table, &r.destination, r.metric)),
                "duplicate route table/destination/metric"
            );
        }
        let mut priorities = BTreeSet::new();
        for r in &self.policy_rules {
            canonical_prefix(&r.source, true)?;
            ensure!(
                (r.table == 254 || (10000..=19999).contains(&r.table))
                    && (10000..=19999).contains(&r.priority)
                    && priorities.insert(r.priority),
                "policy rules require unique priorities in 10000..19999 and table 254 or 10000..19999"
            );
        }
        ensure!(
            action(&self.firewall.policy),
            "firewall policy must be accept or drop"
        );
        for r in &self.firewall.rules {
            ensure!(action(&r.action), "invalid firewall action");
            let a = if r.source.is_empty() {
                None
            } else {
                Some(canonical_prefix(&r.source, true)?.0)
            };
            let b = if r.destination.is_empty() {
                None
            } else {
                Some(canonical_prefix(&r.destination, true)?.0)
            };
            ensure!(
                !matches!((a,b),(Some(a),Some(b)) if a.is_ipv4()!=b.is_ipv4()),
                "firewall address family mismatch"
            );
        }
        if let Some(p) = &self.firewall.policies {
            ensure!(
                self.firewall.rules.is_empty(),
                "firewall rules cannot be mixed with host/interface policies"
            );
            p.validate()?;
        }
        for r in &self.firewall.nat.masquerade {
            ensure!(
                ["ipv4", "ipv6"].contains(&r.family.as_str()) && names.contains(&r.out_interface),
                "masquerade requires family and managed egress interface"
            );
            if !r.source.is_empty() {
                ensure!(
                    canonical_prefix(&r.source, true)?.0.is_ipv4() == (r.family == "ipv4"),
                    "masquerade source family mismatch"
                );
            }
            ensure!(
                self.interfaces.iter().any(|l| l.name == r.out_interface
                    && l.addresses.iter().any(|a| canonical_prefix(a, false)
                        .is_ok_and(|p| p.0.is_ipv4() == (r.family == "ipv4")))),
                "masquerade egress requires an address of its family"
            );
        }
        self.validate_softflowd()?;
        self.validate_monitors()?;
        Ok(())
    }
    fn validate_softflowd(&self) -> Result<()> {
        ensure!(self.softflowd.len() <= 16, "at most 16 softflowd instances");
        let mut names = BTreeSet::new();
        for s in &self.softflowd {
            ensure!(
                valid_name(&s.name, 32, false)
                    && names.insert(&s.name)
                    && valid_interface_name(&s.interface),
                "invalid softflowd name/interface"
            );
            let a = socket(&s.collector)?.ip();
            ensure!(
                global_unicast(a) || a.is_loopback(),
                "invalid collector address"
            );
            ensure!(
                [1, 5, 9, 10].contains(&s.export_version),
                "export version must be 1, 5, 9, or 10"
            );
            ensure!(
                (1..=1000000).contains(&s.sampling_rate)
                    && (1..=1000000).contains(&s.max_flows)
                    && (64..=65535).contains(&s.snaplen),
                "invalid sampling/max_flows/snaplen"
            );
            ensure!(
                s.export_version != 5 || s.sampling_rate <= 16383,
                "NetFlow v5 sampling interval is limited to 16383"
            );
            ensure!(
                ["", "ip", "ip6", "tcp", "udp", "icmp", "icmp6"]
                    .contains(&s.capture_filter.as_str()),
                "capture_filter must be empty, ip, ip6, tcp, udp, icmp, or icmp6"
            );
            for (k, v) in &s.timeouts {
                ensure!(
                    [
                        "general", "tcp", "tcp.rst", "tcp.fin", "udp", "icmp", "maxlife", "expint"
                    ]
                    .contains(&k.as_str())
                        && (0..=604800).contains(v)
                        && !(*v == 0 && k == "general"),
                    "invalid softflowd timeout"
                );
            }
        }
        Ok(())
    }
    fn validate_monitors(&self) -> Result<()> {
        ensure!(
            self.gateway_monitors.len() <= 64,
            "at most 64 gateway monitors"
        );
        let mut names = BTreeSet::new();
        for original in &self.gateway_monitors {
            let mut m = original.clone();
            m.normalize();
            ensure!(
                valid_name(&m.name, 32, false)
                    && names.insert(&original.name)
                    && valid_interface_name(&m.interface),
                "invalid or duplicate gateway monitor name/interface"
            );
            let s = canonical_ip(&m.source_address)?;
            let g = canonical_ip(&m.gateway)?;
            let t = canonical_ip(&m.target)?;
            let remote = |a: IpAddr| {
                global_unicast(a) || matches!(a,IpAddr::V6(v) if v.segments()[0]&0xffc0==0xfe80)
            };
            ensure!(
                global_unicast(s)
                    && remote(g)
                    && remote(t)
                    && s.is_ipv4() == g.is_ipv4()
                    && s.is_ipv4() == t.is_ipv4()
                    && s != g
                    && s != t
                    && (m.routing_table == 254 || (10000..=19999).contains(&m.routing_table)),
                "invalid gateway monitor addresses/table"
            );
            ensure!(
                (100..=60000).contains(&m.probe_interval_ms)
                    && (100..=60000).contains(&m.loss_timeout_ms)
                    && m.loss_timeout_ms <= 10 * m.probe_interval_ms
                    && (1000..=300000).contains(&m.window_ms)
                    && m.window_ms >= 2 * m.loss_timeout_ms
                    && m.window_ms >= 3 * m.probe_interval_ms
                    && m.window_ms <= 1024 * m.probe_interval_ms,
                "invalid monitor interval/timeout/window"
            );
            ensure!(
                (1..=60000).contains(&m.latency_threshold_ms)
                    && (1..=100).contains(&m.loss_threshold_percent)
                    && (0..=60000).contains(&m.rtt_variation_threshold_ms)
                    && (100..=60000).contains(&m.failure_hold_ms)
                    && (100..=60000).contains(&m.recovery_hold_ms),
                "invalid monitor thresholds/holds"
            );
            if m.enabled {
                ensure!(
                    self.interfaces.iter().any(|l| l.name == m.interface
                        && l.up
                        && l.addresses
                            .iter()
                            .any(|a| canonical_prefix(a, false).is_ok_and(|p| p.0 == s))),
                    "monitor source must belong to up managed interface"
                );
                ensure!(
                    self.routes.iter().any(|r| r.interface == m.interface
                        && r.table == m.routing_table
                        && contains(&r.destination, t)
                        && (r.gateway == m.gateway || (g == t && r.gateway.is_empty())))
                        && self
                            .policy_rules
                            .iter()
                            .any(|r| r.table == m.routing_table && contains(&r.source, s)),
                    "monitor requires explicit matching route and source-policy rule"
                );
            }
        }
        Ok(())
    }
}
impl GatewayMonitor {
    fn normalize(&mut self) {
        for (v, d) in [
            (&mut self.probe_interval_ms, 1000),
            (&mut self.loss_timeout_ms, 2000),
            (&mut self.window_ms, 30000),
            (&mut self.latency_threshold_ms, 150),
            (&mut self.loss_threshold_percent, 20),
            (&mut self.failure_hold_ms, 3000),
            (&mut self.recovery_hold_ms, 5000),
        ] {
            if *v == 0 {
                *v = d;
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct KernelParameter {
    pub name: &'static str,
    pub scope: &'static str,
    pub kind: &'static str,
    pub min: i64,
    pub max: i64,
    pub count: usize,
    pub description: &'static str,
}
pub fn kernel_catalog() -> Vec<KernelParameter> {
    let mut items = vec![];
    for (name, min, max, count) in [
        ("net.core.somaxconn", 0, 2147483647, 1),
        ("net.ipv4.tcp_max_syn_backlog", 0, 2147483647, 1),
        ("net.ipv4.tcp_syncookies", 0, 2, 1),
        ("net.ipv4.tcp_sack", 0, 1, 1),
        ("net.ipv4.tcp_window_scaling", 0, 1, 1),
        ("net.ipv4.tcp_timestamps", 0, 2, 1),
        ("net.ipv4.tcp_moderate_rcvbuf", 0, 1, 1),
        ("net.ipv4.tcp_mtu_probing", 0, 2, 1),
        ("net.ipv4.tcp_slow_start_after_idle", 0, 1, 1),
        ("net.ipv4.tcp_autocorking", 0, 1, 1),
        ("net.ipv4.tcp_no_metrics_save", 0, 1, 1),
        ("net.ipv4.tcp_rmem", 1, 2147483647, 3),
        ("net.ipv4.tcp_wmem", 1, 2147483647, 3),
        ("net.ipv4.ip_local_port_range", 1, 65535, 2),
    ] {
        items.push(KernelParameter {
            name,
            scope: "namespace",
            kind: if count == 1 { "integer" } else { "vector" },
            min,
            max,
            count,
            description: "Explicitly owned namespace kernel parameter.",
        });
    }
    items.push(KernelParameter {
        name: "net.ipv4.tcp_congestion_control",
        scope: "namespace",
        kind: "algorithm",
        min: 0,
        max: 0,
        count: 0,
        description: "Default congestion algorithm for new connections; must already be available.",
    });
    for (name, min) in [
        ("net.core.rmem_max", 1),
        ("net.core.wmem_max", 1),
        ("net.core.rmem_default", 1),
        ("net.core.wmem_default", 1),
        ("net.core.netdev_max_backlog", 0),
        ("net.core.netdev_budget", 1),
        ("net.core.netdev_budget_usecs", 0),
    ] {
        items.push(KernelParameter {
            name,
            scope: "host",
            kind: "integer",
            min,
            max: 2147483647,
            count: 1,
            description: "Host-global setting; affects other applications and namespaces.",
        });
    }
    items.sort_by_key(|p| (p.scope, p.name));
    items
}
impl KernelConfig {
    pub fn validate(&self) -> Result<()> {
        for (scope, map) in [("namespace", &self.namespace), ("host", &self.host)] {
            for (name, value) in map {
                let p = kernel_catalog()
                    .into_iter()
                    .find(|p| p.scope == scope && p.name == name)
                    .ok_or_else(|| anyhow::anyhow!("unsupported kernel tunable {scope}/{name}"))?;
                if p.kind == "algorithm" {
                    ensure!(valid_name(value, 15, false), "invalid congestion algorithm");
                    continue;
                }
                let fields: Vec<_> = value.split(' ').collect();
                ensure!(
                    fields.len() == p.count,
                    "expected {} canonical integers for {name}",
                    p.count
                );
                let mut prior = None;
                for f in fields {
                    let n: i64 = f.parse()?;
                    ensure!(
                        n.to_string() == f && n >= p.min && n <= p.max,
                        "non-canonical or out-of-range kernel value for {name}"
                    );
                    ensure!(
                        p.kind != "vector" || prior.is_none_or(|v| n >= v),
                        "kernel vector must be nondecreasing"
                    );
                    if p.count == 2 {
                        ensure!(prior != Some(n), "port range requires at least two ports");
                    }
                    prior = Some(n);
                }
            }
        }
        Ok(())
    }
}
impl FirewallPolicies {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.hosts.len() <= 128 && self.interfaces.len() <= 32,
            "at most 128 hosts and 32 ingress policies"
        );
        let mut hosts = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        let mut names = BTreeSet::new();
        for h in &self.hosts {
            ensure!(
                valid_name(&h.id, 64, false) && hosts.insert(&h.id, h).is_none(),
                "invalid or duplicate firewall host ID"
            );
            ensure!(
                !h.name.is_empty()
                    && h.name.len() <= 80
                    && h.name.trim() == h.name
                    && !h.name.chars().any(char::is_control)
                    && names.insert(&h.name),
                "invalid or duplicate firewall host name"
            );
            ensure!(
                action(&h.policy) && !h.addresses.is_empty() && h.addresses.len() <= 16,
                "host requires accept/drop and 1..16 addresses"
            );
            for s in &h.addresses {
                ensure!(
                    global_unicast(canonical_ip(s)?) && addresses.insert(s),
                    "host addresses must be unique canonical unicast IPs"
                );
            }
        }
        let validate_rules = |rules: &[HostPolicyRule],
                              source: Option<&FirewallHost>|
         -> Result<usize> {
            ensure!(rules.len() <= 64, "at most 64 rules per host/interface");
            let mut count = 0usize;
            for r in rules {
                ensure!(
                    action(&r.action) && ["", "tcp", "udp"].contains(&r.protocol.as_str()),
                    "invalid policy action/protocol"
                );
                ensure!(
                    r.destination_host.is_empty()
                        || (r.destination.is_empty() && hosts.contains_key(&r.destination_host)),
                    "destination_host must exist and excludes destination"
                );
                let destinations: Vec<IpAddr> = if !r.destination_host.is_empty() {
                    hosts[&r.destination_host]
                        .addresses
                        .iter()
                        .map(|a| canonical_ip(a))
                        .collect::<Result<_>>()?
                } else if !r.destination.is_empty() {
                    vec![canonical_prefix(&r.destination, true)?.0]
                } else {
                    vec![]
                };
                ensure!(
                    r.destination_ports.len() <= 32
                        && (r.destination_ports.is_empty() || !r.protocol.is_empty()),
                    "ports require tcp/udp, maximum 32"
                );
                let mut ports = BTreeSet::new();
                for p in &r.destination_ports {
                    ensure!(
                        (1..=65535).contains(p) && ports.insert(p),
                        "invalid or duplicate destination port"
                    );
                }
                let mut pairs = 0;
                if let Some(h) = source {
                    for a in &h.addresses {
                        let ip = canonical_ip(a)?;
                        pairs += if destinations.is_empty() {
                            1
                        } else {
                            destinations
                                .iter()
                                .filter(|d| d.is_ipv4() == ip.is_ipv4())
                                .count()
                        };
                    }
                } else {
                    pairs = destinations.len().max(1);
                }
                ensure!(
                    pairs > 0,
                    "policy destination has no family in common with source host"
                );
                count += pairs * r.destination_ports.len().max(1);
            }
            Ok(count)
        };
        let mut count = 1;
        let mut interfaces = BTreeSet::new();
        for i in &self.interfaces {
            ensure!(
                valid_interface_name(&i.interface) && interfaces.insert(&i.interface),
                "invalid or duplicate ingress policy interface"
            );
            count += validate_rules(&i.rules, None)?;
        }
        for h in &self.hosts {
            count += validate_rules(&h.rules, Some(h))? + h.addresses.len();
        }
        ensure!(count <= 4096, "firewall policies expand beyond 4096 rules");
        ensure!(
            serde_json::to_vec(self)?.len() <= 65536,
            "firewall policy metadata exceeds 65536 bytes"
        );
        Ok(())
    }
}
