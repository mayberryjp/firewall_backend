use crate::{Backend, Config};
use anyhow::{Result, ensure};
use chrono::Utc;
use serde_json::{Value, json};

/// In-memory deterministic backend. Simulated samples never masquerade as measurements.
#[derive(Default)]
pub struct Simulator {
    state: Config,
    original: crate::KernelConfig,
    live: crate::KernelConfig,
}
impl Simulator {
    pub fn new() -> Self {
        Self {
            state: Config::empty(),
            original: Default::default(),
            live: Default::default(),
        }
    }
    pub fn with_config(mut config: Config) -> Result<Self> {
        config.normalize();
        config.validate()?;
        let mut simulator = Self::new();
        simulator.apply(&Config::empty(), &config)?;
        Ok(simulator)
    }
    pub fn state(&self) -> &Config {
        &self.state
    }
}
pub(crate) fn gateway_samples(config: &Config) -> Vec<Value> {
    config.gateway_monitors.iter().map(|m|json!({
        "name":m.name,"process_state":if m.enabled{"simulated"}else{"disabled"},
        "sample_status":if m.enabled{"simulated"}else{"disabled"},"health":"unknown",
        "started_at":null,"collected_at":null,"health_changed_at":null,"last_success_at":null,
        "sent":0,"received":0,"lost":0,"pending":0,"variation_pairs":0,
        "loss_percent":null,"rtt_min_ms":null,"rtt_max_ms":null,"rtt_avg_ms":null,
        "rtt_stddev_ms":null,"rtt_p50_ms":null,"rtt_p95_ms":null,"rtt_variation_ms":null
    })).collect()
}
impl Backend for Simulator {
    fn scope(&self) -> Result<String> {
        Ok("simulator".into())
    }
    fn observe(&mut self, _expected: &Config) -> Result<Config> {
        Ok(self.state.clone())
    }
    fn discover_interfaces(&mut self) -> Result<Value> {
        Ok(json!(
            self.state
                .interfaces
                .iter()
                .map(|link| json!({
                    "name": link.name,
                    "kind": link.kind,
                    "index": null,
                    "mac": null,
                    "mtu": link.mtu,
                    "up": link.up,
                    "addresses": link.addresses,
                    "ownership": "managed"
                }))
                .collect::<Vec<_>>()
        ))
    }
    fn apply(&mut self, _before: &Config, after: &Config) -> Result<()> {
        after.validate()?;
        if let Some(p) = &after.firewall.policies {
            for i in &p.interfaces {
                ensure!(
                    after.interfaces.iter().any(|l| l.name == i.interface),
                    "firewall ingress interface is not managed"
                );
            }
        }
        for l in &after.interfaces {
            if let Some(v) = &l.vlan {
                ensure!(
                    after.interfaces.iter().any(|p| p.name == v.parent),
                    "VLAN parent is not available in simulator"
                );
            }
        }
        for (scope, values, original, live) in [
            (
                "namespace",
                &after.kernel.namespace,
                &mut self.original.namespace,
                &mut self.live.namespace,
            ),
            (
                "host",
                &after.kernel.host,
                &mut self.original.host,
                &mut self.live.host,
            ),
        ] {
            for name in values.keys() {
                if !original.contains_key(name) {
                    let value = live
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| simulated_kernel_default(scope, name));
                    original.insert(name.clone(), value);
                }
            }
            for (name, value) in original.iter() {
                live.insert(name.clone(), values.get(name).unwrap_or(value).clone());
            }
        }
        self.state = after.normalized();
        Ok(())
    }
    fn factory_reset(&mut self, before: &Config, after: &Config) -> Result<()> {
        self.apply(before, after)
    }
    fn runtime(&mut self, config: &Config) -> Result<Value> {
        let mut appliance = vec![];
        for (name, scope, enabled) in [
            ("ntp", "host", config.ntp.enabled),
            ("syslog", "host", config.syslog.enabled),
            ("vnstat-host", "host", config.vnstat.enabled),
            ("vnstat-managed", "managed", config.vnstat.enabled),
        ] {
            appliance.push(
                json!({"name":name,"scope":scope,"state":if enabled{"simulated"}else{"disabled"}}),
            );
        }
        let softflowd: Vec<_> = config
            .softflowd
            .iter()
            .map(|s| json!({"name":s.name,"state":if s.enabled{"simulated"}else{"disabled"}}))
            .collect();
        let relays:Vec<_>=config.interfaces.iter().map(|l|json!({"interface":l.name,"state":if l.dhcp_relay.enabled{"simulated"}else{"disabled"}})).collect();
        Ok(
            json!({"appliance_services":appliance,"gateway_monitors":gateway_samples(config),"dhcp_relay":relays,"parent_interfaces":[],"softflowd":softflowd,
            "ipv6":{"enabled":config.ipv6_enabled,"status":"simulated","disable_ipv6":null,"drift":null},
            "kernel_tunables":{"desired":config.kernel,"configured":config.kernel,"effective":self.live,"observed":self.live,
                "captured_original":self.original,"drift":false}}),
        )
    }
    fn statistics(&mut self, config: &Config, path: &str, query: &str) -> Result<Value> {
        if path == "/api/v1/statistics/connections" {
            let query = crate::ConnectionQuery::parse(query)?;
            return Ok(json!({
                "schema":"netcontrol-connections/v1",
                "sample":{"scope":"simulator","started_at":Utc::now(),"collected_at":Utc::now(),"status":"simulated"},
                "connections":[],"summary":{"total":null,"matched":null,"returned":0,"accounting_unavailable":null},
                "limit":query.limit,"offset":query.offset,"next_offset":null
            }));
        }
        ensure!(
            query.is_empty(),
            "statistics endpoints do not accept query parameters"
        );
        if [
            "/api/v1/statistics/vnstat",
            "/api/v1/statistics/vnstat/host",
            "/api/v1/statistics/vnstat/managed",
        ]
        .contains(&path)
        {
            ensure!(config.vnstat.enabled, "vnstat is disabled");
            anyhow::bail!(
                "traffic history unavailable: simulator does not collect traffic counters"
            );
        }
        let sample = json!({"scope":"simulator","started_at":Utc::now(),"collected_at":Utc::now(),"status":"simulated"});
        let interfaces:Vec<_>=self.state.interfaces.iter().map(|l|json!({"name":l.name,"kind":l.kind,"ownership":"managed","mtu":l.mtu,"admin_up":l.up,
            "oper_state":"unknown","status":"simulated","counters":null})).collect();
        let protocols: Vec<_> = ["snmp", "netstat", "snmp6"]
            .iter()
            .map(|name| json!({"name":name,"status":"simulated","groups":null}))
            .collect();
        let gateways = gateway_samples(config);
        match path {
            "/api/v1/statistics" => Ok(
                json!({"sample":sample,"interfaces":interfaces,"protocols":protocols,"gateways":gateways}),
            ),
            "/api/v1/statistics/interfaces" => Ok(json!({"sample":sample,"interfaces":interfaces})),
            "/api/v1/statistics/protocols" => Ok(json!({"sample":sample,"protocols":protocols})),
            "/api/v1/statistics/gateways" => Ok(json!({"sample":sample,"monitors":gateways})),
            _ => {
                if let Some(name) = path.strip_prefix("/api/v1/statistics/interfaces/") {
                    let interface = interfaces
                        .into_iter()
                        .find(|l| l["name"] == name)
                        .ok_or_else(|| anyhow::anyhow!("statistics interface not found"))?;
                    return Ok(json!({"sample":sample,"interface":interface}));
                }
                if let Some(name) = path.strip_prefix("/api/v1/statistics/gateways/") {
                    let monitor = gateways
                        .into_iter()
                        .find(|l| l["name"] == name)
                        .ok_or_else(|| anyhow::anyhow!("gateway monitor not found"))?;
                    return Ok(json!({"sample":sample,"monitor":monitor}));
                }
                anyhow::bail!("statistics endpoint not found")
            }
        }
    }
    fn repair(&mut self, config: &Config) -> Result<Value> {
        let before = self.state.clone();
        self.apply(&before, config)?;
        self.runtime(config)
    }
}
fn simulated_kernel_default(scope: &str, name: &str) -> String {
    match name {
        "net.ipv4.tcp_rmem" => "4096 131072 6291456",
        "net.ipv4.tcp_wmem" => "4096 16384 4194304",
        "net.ipv4.ip_local_port_range" => "32768 60999",
        "net.ipv4.tcp_congestion_control" => "cubic",
        "net.core.somaxconn" | "net.ipv4.tcp_max_syn_backlog" => "4096",
        "net.core.rmem_max"
        | "net.core.wmem_max"
        | "net.core.rmem_default"
        | "net.core.wmem_default" => "212992",
        "net.core.netdev_max_backlog" => "1000",
        "net.core.netdev_budget" => "300",
        "net.core.netdev_budget_usecs" => "2000",
        "net.ipv4.tcp_mtu_probing" | "net.ipv4.tcp_no_metrics_save" => "0",
        _ => {
            if scope == "host" {
                "212992"
            } else {
                "1"
            }
        }
    }
    .into()
}
