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
    pub rss: Option<InterfaceRss>,
    pub interrupts: Option<Vec<InterfaceInterrupt>>,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceQueue {
    pub name: String,
    pub rps_cpus: Option<String>,
    pub rps_flow_count: Option<u32>,
    pub xps_cpus: Option<String>,
    pub xps_rxqs: Option<String>,
    pub irqs: Option<Vec<u32>>,
    pub irq_mapping_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceRss {
    pub context: u32,
    pub indirection_table: Option<Vec<u32>>,
    pub hash_function: Option<u8>,
    pub input_transformation: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceInterrupt {
    pub irq: u32,
    pub description: Option<String>,
    pub effective_cpus: Option<Vec<u32>>,
    pub counts: Option<Vec<InterfaceInterruptCount>>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceInterruptCount {
    pub cpu_id: u32,
    pub interrupts: String,
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
    pub inherited_from: Option<String>,
    pub evidence: Vec<String>,
    pub reason: Option<String>,
}

impl PerformanceCapability {
    pub fn unknown(name: &str, reason: &str) -> Self {
        Self {
            name: name.into(),
            support: CapabilitySupport::Unknown,
            enabled: None,
            inherited_from: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_inherited_rps_serialization_preserves_unknown_and_raw_masks() {
        for enabled in [Some(true), Some(false), None] {
            let mut rps = PerformanceCapability::unknown("rps", "parent observation");
            rps.enabled = enabled;
            rps.inherited_from = Some("eno1".into());
            let row = InterfaceCapabilities {
                name: "vlan10".into(),
                kind: "vlan".into(),
                queues: vec![InterfaceQueue {
                    name: "rx-0".into(),
                    rps_cpus: Some("0".into()),
                    rps_flow_count: None,
                    xps_cpus: None,
                    xps_rxqs: None,
                    ..Default::default()
                }],
                capabilities: vec![rps, PerformanceCapability::unknown("rss", "not observed")],
                ..Default::default()
            };
            let value = serde_json::to_value(&row).unwrap();
            assert_eq!(
                value["capabilities"][0]["enabled"],
                serde_json::json!(enabled)
            );
            assert_eq!(value["capabilities"][0]["inherited_from"], "eno1");
            assert!(value["capabilities"][1]["inherited_from"].is_null());
            let restored: InterfaceCapabilities = serde_json::from_value(value).unwrap();
            assert_eq!(restored.capabilities[0].enabled, enabled);
            assert_eq!(
                restored.capabilities[0].inherited_from.as_deref(),
                Some("eno1")
            );
            assert_eq!(restored.queues[0].rps_cpus.as_deref(), Some("0"));
        }
    }

    #[test]
    fn capabilities_rss_irq_serialization_preserves_exact_counts_and_unknowns() {
        let row = InterfaceCapabilities {
            rss: Some(InterfaceRss {
                context: 0,
                indirection_table: Some(vec![0, 1, 2, 3]),
                hash_function: Some(1),
                input_transformation: Some(0),
            }),
            interrupts: Some(vec![InterfaceInterrupt {
                irq: 135,
                description: Some("PCI-MSI enp1s0-TxRx-0".into()),
                effective_cpus: Some(vec![1]),
                counts: Some(vec![InterfaceInterruptCount {
                    cpu_id: 1,
                    interrupts: u64::MAX.to_string(),
                }]),
                errors: vec![],
            }]),
            queues: vec![
                InterfaceQueue {
                    name: "rx-0".into(),
                    irqs: Some(vec![135]),
                    ..Default::default()
                },
                InterfaceQueue {
                    name: "rx-1".into(),
                    irq_mapping_reason: Some("driver queue mapping unavailable".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let value = serde_json::to_value(&row).unwrap();
        assert_eq!(
            value["interrupts"][0]["counts"][0]["interrupts"],
            u64::MAX.to_string()
        );
        assert!(value["queues"][1]["irqs"].is_null());
        let restored: InterfaceCapabilities = serde_json::from_value(value).unwrap();
        assert_eq!(
            restored.rss.unwrap().indirection_table.unwrap(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(restored.queues[0].irqs, Some(vec![135]));
    }
}
