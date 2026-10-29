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
        "mode":m.mode,"interface":m.interface,
        "resolved_source_address":if m.enabled && m.mode==crate::GatewayMode::Explicit {json!(m.source_address)}else{Value::Null},
        "resolved_gateway":if m.enabled && m.mode==crate::GatewayMode::Explicit {json!(m.gateway)}else{Value::Null},
        "resolved_routing_table":if m.enabled && m.mode==crate::GatewayMode::Explicit {json!(m.routing_table)}else{Value::Null},
        "reason":if m.enabled && m.mode==crate::GatewayMode::Dhcp {json!("DHCP leases are not simulated")}else{Value::Null},
        "sample_status":if m.enabled{"simulated"}else{"disabled"},"health":"unknown",
        "started_at":null,"collected_at":null,"health_changed_at":null,"last_success_at":null,
        "sent":0,"received":0,"lost":0,"pending":0,"variation_pairs":0,
        "loss_percent":null,"rtt_min_ms":null,"rtt_max_ms":null,"rtt_avg_ms":null,
        "rtt_stddev_ms":null,"rtt_p50_ms":null,"rtt_p95_ms":null,"rtt_variation_ms":null
    })).collect()
}
impl Backend for Simulator {
    fn bgp_status(&mut self, config: &Config) -> Result<Value> {
        Ok(
            json!({"name":"bgp","scope":"simulator","state":if config.bgp.enabled{"simulated"}else{"disabled"},
            "local_asn":config.bgp.local_asn,"router_id":config.bgp.router_id,"neighbors":config.bgp.neighbors.iter().map(|n|json!({"name":n.name,"address":n.address,"interface":n.interface,"state":"simulated","received_prefixes":null,"advertised_prefixes":null,"rejected_prefixes":null,"error":null})).collect::<Vec<_>>(),
            "routes":[],"advertised_routes":[],"connected_prefixes":[],"installed_prefixes":null,"error":null}),
        )
    }
    fn prepare_dns_lookup(
        &mut self,
        _: &Config,
        request: &crate::DNSLookupRequest,
    ) -> Result<crate::DNSLookup> {
        let request = request.clone();
        Ok(Box::new(move || {
            Ok(
                json!({"status":"simulated","scope":"simulator","interface":request.interface,"hostname":request.hostname,
            "record_type":request.record_type,"rtt_ms":null,"elapsed_ms":null,"server":null,"transport":null,"rcode":null,"addresses":[],"attempts":[]}),
            )
        }))
    }
    fn restart_process(&mut self, _: &Config, _: &str) -> Result<Value> {
        Ok(json!({"state":"simulated"}))
    }
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
            ("vnstat", "host", config.vnstat.enabled),
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
        appliance.push(config.mdns.status(
            config,
            if config.mdns.enabled {
                "simulated"
            } else {
                "disabled"
            },
        ));
        let bgp = self.bgp_status(config)?;
        for instance in &config.udp_broadcast_relay.instances {
            let enabled = config.udp_broadcast_relay.enabled && instance.enabled;
            appliance
                .push(instance.status(enabled, if enabled { "simulated" } else { "disabled" }));
        }
        appliance.push(bgp.clone());
        Ok(
            json!({"bgp":bgp,"appliance_services":appliance,"gateway_monitors":gateway_samples(config),"dhcp_relay":relays,"parent_interfaces":[],"softflowd":softflowd,
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
        if path == "/api/v1/statistics/host" {
            let mut sections = serde_json::Map::new();
            for name in [
                "cpu",
                "memory",
                "load",
                "uptime",
                "vm",
                "pressure_cpu",
                "pressure_memory",
                "pressure_io",
                "disks",
                "filesystems",
                "thermal",
                "hwmon",
            ] {
                sections.insert(name.into(), json!({
                    "status":"simulated","data":null,"error":"simulator does not measure host health"
                }));
            }
            return Ok(json!({
                "schema":"netcontrol-host-health/v1",
                "sample":{"scope":"simulator","boot_id":null,"started_at":Utc::now(),
                    "collected_at":Utc::now(),"status":"simulated"},
                "sections":sections
            }));
        }
        if path == "/api/v1/statistics/vnstat" {
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
        let diagnostics = json!({"schema":"netcontrol-link-diagnostics/v1","scope":"simulator",
            "status":"simulated","collected_at":null,"age_ms":null,"interval_seconds":null,
            "error":null,"interfaces":null,"queues":null,"local_tcp":null,"packet_headers":null,"signals":[]});
        match path {
            "/api/v1/statistics/link-diagnostics" => Ok(diagnostics),
            "/api/v1/statistics" => Ok(
                json!({"sample":sample,"interfaces":interfaces,"protocols":protocols,"gateways":gateways,"link_diagnostics":diagnostics,"bgp":self.bgp_status(config)?}),
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
