use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceCapabilitySnapshot {
    pub collected_at: String,
    pub scope: String,
    pub inventory: InterfaceInventory,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceInventory {
    pub source: InventorySource,
    pub status: InventoryStatus,
    pub kernel_release: Option<String>,
    pub boot_id: Option<String>,
    pub errors: Vec<String>,
    pub interfaces: Vec<InterfaceCapabilities>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventorySource {
    Native,
    Simulator,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Observed,
    Partial,
    Simulated,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceCapabilities {
    pub name: String,
    pub index: Option<u32>,
    pub mac: Option<String>,
    pub kind: String,
    pub driver: Option<InterfaceDriver>,
    pub hardware: Option<InterfaceHardware>,
    pub link: Option<InterfaceLink>,
    pub channels: Option<InterfaceChannels>,
    pub queues: Vec<InterfaceQueue>,
    pub capabilities: Vec<PerformanceCapability>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceDriver {
    pub name: String,
    pub version: Option<String>,
    pub firmware_version: Option<String>,
    pub expansion_rom_version: Option<String>,
    pub bus_address: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceHardware {
    pub bus: Option<String>,
    pub address: Option<String>,
    pub vendor_id: Option<String>,
    pub device_id: Option<String>,
    pub subsystem_vendor_id: Option<String>,
    pub subsystem_device_id: Option<String>,
    pub revision: Option<String>,
    pub numa_node: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceLink {
    pub carrier: Option<bool>,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<String>,
    pub autonegotiation: Option<bool>,
    pub supported_modes: Vec<InterfaceLinkMode>,
    pub advertised_modes: Vec<InterfaceLinkMode>,
    pub partner_advertised_modes: Vec<InterfaceLinkMode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceLinkMode {
    pub bit: u32,
    pub name: Option<String>,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceChannels {
    pub max_rx: u32,
    pub max_tx: u32,
    pub max_other: u32,
    pub max_combined: u32,
    pub rx: u32,
    pub tx: u32,
    pub other: u32,
    pub combined: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceQueue {
    pub name: String,
    pub rps_cpus: Option<String>,
    pub rps_flow_count: Option<u32>,
    pub xps_cpus: Option<String>,
    pub xps_rxqs: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Supported,
    Unsupported,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceCapability {
    pub name: String,
    pub support: CapabilitySupport,
    pub enabled: Option<bool>,
    pub evidence: Vec<String>,
    pub reason: Option<String>,
}

impl PerformanceCapability {
    pub fn unknown(name: &str, reason: &str) -> Self {
        Self {
            name: name.into(),
            support: CapabilitySupport::Unknown,
            enabled: None,
            evidence: vec![],
            reason: Some(reason.into()),
        }
    }
}

pub const PERFORMANCE_CAPABILITIES: &[&str] = &[
    "rss",
    "rps",
    "rfs",
    "accelerated_rfs",
    "xps",
    "xps_rxqs",
    "xdp_generic",
    "xdp_native",
    "xdp_hardware",
    "xdp_redirect",
    "xdp_rx_scatter_gather",
    "af_xdp_copy",
    "af_xdp_zero_copy",
    "dpdk",
];
