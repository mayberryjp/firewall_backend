use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type NicOffloads = BTreeMap<String, BTreeMap<String, bool>>;

pub const NIC_OFFLOAD_FEATURES: &[&str] = &[
    "rx-checksum",
    "tx-checksum-ipv4",
    "tx-checksum-ip-generic",
    "tx-checksum-ipv6",
    "tx-scatter-gather",
    "tx-scatter-gather-fraglist",
    "tx-tcp-segmentation",
    "tx-tcp6-segmentation",
    "tx-tcp-ecn-segmentation",
    "tx-tcp-mangleid-segmentation",
    "tx-generic-segmentation",
    "tx-gso-partial",
    "rx-gro",
    "rx-gro-hw",
    "rx-udp-gro-forwarding",
    "rx-lro",
    "rx-vlan-hw-parse",
    "tx-vlan-hw-insert",
    "rx-vlan-stag-hw-parse",
    "tx-vlan-stag-hw-insert",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RfsConfig {
    pub sock_flow_entries: u32,
    pub queues: BTreeMap<String, u32>,
}

impl RfsConfig {
    pub fn validate(&self) -> Result<()> {
        fn count(value: u32) -> bool {
            value == 0 || (value.is_power_of_two() && value <= 1_048_576)
        }
        ensure!(
            count(self.sock_flow_entries) && self.queues.len() <= 64,
            "RFS requires zero or power-of-two counts up to 1048576 and at most 64 queues"
        );
        let mut total = 0u64;
        for (key, value) in &self.queues {
            crate::rps_target(key)?;
            ensure!(
                count(*value),
                "RFS queue count must be zero or a power of two up to 1048576"
            );
            total += u64::from(*value);
        }
        ensure!(
            total <= u64::from(self.sock_flow_entries),
            "RFS queue counts exceed sock_flow_entries budget"
        );
        Ok(())
    }
}

pub fn validate_nic_offloads(values: &NicOffloads) -> Result<()> {
    ensure!(values.len() <= 32, "at most 32 NIC offload interfaces");
    for (name, features) in values {
        ensure!(
            crate::valid_interface_name(name) && !features.is_empty(),
            "NIC offloads require a valid interface and nonempty feature map"
        );
        for (feature, enabled) in features {
            ensure!(
                NIC_OFFLOAD_FEATURES.contains(&feature.as_str()),
                "unsupported configurable NIC offload {feature}"
            );
            ensure!(
                feature != "rx-lro" || !enabled,
                "large receive offload cannot be enabled on a forwarding firewall"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfs_budgets_are_bounded_exact_powers_of_two() {
        let mut rfs = RfsConfig {
            sock_flow_entries: 1_048_576,
            queues: [("eno1/rx-0".into(), 1_048_576)].into(),
        };
        rfs.validate().unwrap();
        for count in [1_048_577, 3, u32::MAX] {
            rfs.sock_flow_entries = count;
            assert!(rfs.validate().is_err());
        }
        rfs.sock_flow_entries = 1_048_576;
        rfs.queues.insert("eno1/rx-1".into(), 1);
        assert!(rfs.validate().is_err());
        rfs.queues = (0..64)
            .map(|queue| (format!("eno1/rx-{queue}"), 0))
            .collect();
        rfs.sock_flow_entries = 0;
        rfs.validate().unwrap();
        rfs.queues.insert("eno1/rx-64".into(), 0);
        assert!(rfs.validate().is_err());
        rfs.queues = [("eno1/rx-00".into(), 0)].into();
        assert!(rfs.validate().is_err());
        rfs.queues = [("eno1/rx-0".into(), 3)].into();
        assert!(rfs.validate().is_err());
    }

    #[test]
    fn nic_offloads_reject_unbounded_unknown_and_forwarding_unsafe_settings() {
        for feature in NIC_OFFLOAD_FEATURES {
            validate_nic_offloads(&[("eno1".into(), [(feature.to_string(), false)].into())].into())
                .unwrap();
        }
        for (name, features) in [
            ("../eno1", [("rx-checksum".into(), true)].into()),
            ("eno1", [("rx-all".into(), true)].into()),
            ("eno1", [("rx-lro".into(), true)].into()),
            ("eno1", [("ethtool:rx-checksum".into(), true)].into()),
            ("eno1", BTreeMap::new()),
        ] {
            assert!(validate_nic_offloads(&[(name.into(), features)].into()).is_err());
        }
        let mut maps: NicOffloads = (0..32)
            .map(|index| (format!("eth{index}"), [("rx-checksum".into(), true)].into()))
            .collect();
        validate_nic_offloads(&maps).unwrap();
        maps.insert("eth32".into(), [("rx-checksum".into(), true)].into());
        assert!(validate_nic_offloads(&maps).is_err());
    }
}
