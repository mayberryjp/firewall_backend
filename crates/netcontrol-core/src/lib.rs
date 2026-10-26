//! Typed networking domain, durable transactions, and deterministic simulator.
mod dynamic_dns;
mod engine;
mod mdns;
mod model;
mod simulator;
mod store;

pub use dynamic_dns::{DynamicDNSAddressSource, DynamicDNSConfig};
pub use engine::{Engine, PERMISSIONS, Reply, TimezoneCheck, Transaction, validate_offline_state};
pub use mdns::{MDNSConfig, MDNSInterfaceMode, MDNSPublishing, MDNSReflection, valid_mdns_name};
pub use model::*;
pub use simulator::Simulator;

use anyhow::Result;
use serde_json::Value;

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
    fn observe(&mut self, expected: &Config) -> Result<Config>;
    fn discover_interfaces(&mut self) -> Result<Value> {
        anyhow::bail!("interface discovery is not supported by this backend")
    }
    fn observe_for_repair(&mut self, expected: &Config) -> Result<Config> {
        self.observe(expected)
    }
    fn apply(&mut self, before: &Config, after: &Config) -> Result<()>;
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
