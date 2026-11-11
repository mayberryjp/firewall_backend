//! Typed networking domain, durable transactions, and deterministic simulator.
mod bgp;
mod deny_log;
mod dhcp_relay;
mod diagnostics;
mod logs;
pub use logs::{
    DiskLog, LOG_MESSAGE_BYTES, LOG_PAGE_BYTES, LOG_SEGMENT_BYTES, LOG_SEGMENTS, LogCursorAhead,
    LogEntry, LogPage, LogQuery, LogSource,
};
mod path_test;
pub use bgp::{BGPConfig, BGPNeighbor};
pub use deny_log::{DenyLogQuery, DenyRecord, DenyTrafficTag};
pub use dhcp_relay::DHCPRelayLogQuery;
pub use path_test::{
    PATH_TEST_ARM_SECONDS, PATH_TEST_LIFETIME_SECONDS, PATH_TEST_PORT, PATH_TEST_RUN_SECONDS,
    PathTestParent, PathTestRequest,
};
mod dynamic_dns;
pub use diagnostics::{DNSLookup, DNSLookupRequest, DNSRecordType};
mod engine;
mod interface_capabilities;
pub use interface_capabilities::*;
mod mdns;
mod model;
mod rps;
pub use rps::{MAX_CPU_ID, cpu_mask, parse_cpu_list, parse_cpu_mask, rps_target, validate_rps};
mod tuning;
pub use tuning::{NIC_OFFLOAD_FEATURES, NicOffloads, RfsConfig, validate_nic_offloads};
mod sando;
mod simulator;
mod store;
mod udp_broadcast_relay;
mod version;

pub use version::{RELEASE_VERSION, SoftwareMetadata, Version};

pub use udp_broadcast_relay::{UDPBroadcastRelayConfig, UDPRelayInstance, UDPRelaySource};

pub use dynamic_dns::{DynamicDNSAddressSource, DynamicDNSConfig};
pub use engine::{Engine, PERMISSIONS, Reply, TimezoneCheck, Transaction, validate_offline_state};
pub use mdns::{
    MDNSConfig, MDNSFilterCounters, MDNSInterfaceMode, MDNSPublishing, MDNSReflection,
    valid_mdns_name,
};
pub use model::*;
pub use sando::{SandoConfig, SandoImportState, SandoImportStatus};
pub use simulator::Simulator;

use anyhow::Result;
use serde_json::Value;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptVlanRequest {
    pub name: String,
    pub parent: String,
    pub id: u16,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlanAdoption {
    pub config: Config,
    pub receipt: Value,
}

#[derive(Debug)]
pub struct BackendDrift(pub String);
impl std::fmt::Display for BackendDrift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for BackendDrift {}

mod connections;
pub use connections::{ConnectionQuery, ConnectionTarget, ConnectionTuple};

/// Implementations must observe real state and report unsupported operations as errors.
pub trait Backend: Send {
    fn syslog_capture_active(&self) -> bool {
        false
    }
    fn logs(&mut self, _source: LogSource, _query: &LogQuery) -> Result<Value> {
        anyhow::bail!("log history requires the native Linux backend")
    }
    fn dhcp_relay_log(&mut self, _query: &DHCPRelayLogQuery) -> Result<Value> {
        anyhow::bail!("DHCP relay logs require the native Linux backend")
    }
    /// Capture only: no networking or ownership changes before the core intent is durable.
    fn prepare_vlan_adoption(
        &mut self,
        _before: &Config,
        _request: &AdoptVlanRequest,
    ) -> Result<VlanAdoption> {
        anyhow::bail!("VLAN adoption requires the native Linux host backend")
    }
    /// Resume the exact durable capture; implementations must be idempotent and fail closed on drift.
    fn finish_vlan_adoption(&mut self, _before: &Config, _adoption: &VlanAdoption) -> Result<()> {
        anyhow::bail!("VLAN adoption requires the native Linux host backend")
    }
    fn path_test_active(&self) -> bool {
        false
    }
    fn start_path_test(&mut self, _config: &Config, _request: PathTestRequest) -> Result<Value> {
        anyhow::bail!("active path tests require the native Linux backend")
    }
    fn path_test_status(&mut self) -> Result<Value> {
        anyhow::bail!("active path tests require the native Linux backend")
    }
    fn cancel_path_test(&mut self, _id: &str) -> Result<Value> {
        anyhow::bail!("active path tests require the native Linux backend")
    }
    fn shutdown_path_test(&mut self) -> Result<()> {
        Ok(())
    }
    fn deny_log(&mut self, _query: &DenyLogQuery) -> Result<Value> {
        anyhow::bail!("firewall deny logging requires the native Linux backend")
    }
    fn first_firewall_drops(&mut self, _config: &DiscordConfig) -> Result<Vec<DenyRecord>> {
        anyhow::bail!("first-seen firewall drops require the native Linux backend")
    }
    fn bgp_status(&mut self, config: &Config) -> Result<Value> {
        let runtime = self.runtime(config)?;
        runtime
            .get("bgp")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("BGP status unavailable"))
    }
    fn prepare_dns_lookup(
        &mut self,
        _config: &Config,
        _request: &DNSLookupRequest,
    ) -> Result<DNSLookup> {
        anyhow::bail!("DNS diagnostics are not supported by this backend")
    }
    fn restart_process(&mut self, _config: &Config, _target: &str) -> Result<Value> {
        anyhow::bail!("managed worker restart is not supported by this backend")
    }
    fn mdns_status(&mut self, config: &Config) -> Result<Value> {
        let runtime = self.runtime(config)?;
        let rows = runtime["appliance_services"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("backend returned invalid service statuses"))?;
        Ok(
            serde_json::json!({"instances":rows.iter().filter(|row|row["name"]=="mdns").collect::<Vec<_>>(),
            "error":runtime.get("error").cloned().unwrap_or_else(||serde_json::json!(""))}),
        )
    }
    fn scope(&self) -> Result<String>;
    fn initial_configuration(&mut self) -> Result<Config> {
        Ok(Config::empty())
    }
    fn capture_conntrack_tunables(&mut self, _configured: &KernelConfig) -> Result<KernelConfig> {
        anyhow::bail!("conntrack ownership capture requires the native Linux host backend")
    }
    fn observe(&mut self, expected: &Config) -> Result<Config>;
    fn discover_interfaces(&mut self) -> Result<Value> {
        anyhow::bail!("interface discovery is not supported by this backend")
    }
    fn discover_interface_capabilities(&mut self) -> Result<InterfaceInventory> {
        anyhow::bail!("interface capability discovery is not supported by this backend")
    }
    fn observe_for_repair(&mut self, expected: &Config) -> Result<Config> {
        self.observe(expected)
    }
    fn apply(&mut self, before: &Config, after: &Config) -> Result<()>;
    fn configure_reporting_identity(&mut self, _system: &SystemConfig) -> Result<()> {
        Ok(())
    }
    fn retry_dhcp(&mut self, _config: &Config, _interface: &str) -> Result<()> {
        anyhow::bail!("DHCP retry is not supported by this backend")
    }
    fn delete_connections(&mut self, _target: Option<(u32, &ConnectionTarget)>) -> Result<Value> {
        anyhow::bail!("connection deletion is not supported by this backend")
    }
    fn factory_reset(&mut self, _before: &Config, _after: &Config) -> Result<()> {
        anyhow::bail!("factory reset is not supported by this backend")
    }
    fn runtime(&mut self, config: &Config) -> Result<Value>;
    fn statistics(&mut self, config: &Config, path: &str, query: &str) -> Result<Value>;
    fn repair(&mut self, config: &Config) -> Result<Value>;
}

#[cfg(test)]
mod model_tests;
