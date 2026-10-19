//! Direct Linux kernel networking in an explicitly selected, pre-created namespace.
//! No external networking or service programs are launched.
#[cfg(not(target_os = "linux"))]
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOptions {
    pub namespace: String,
    #[serde(default = "default_keys")]
    pub keys: PathBuf,
    #[serde(default)]
    pub adopted_parents: Vec<String>,
    #[serde(default)]
    pub allow_host_tunables: bool,
    #[serde(default)]
    pub allow_host_services: bool,
    #[serde(default)]
    pub gateway_monitoring: bool,
    #[serde(default = "default_services")]
    pub services_state: PathBuf,
}

fn default_keys() -> PathBuf {
    PathBuf::from("/etc/netcontrol/keys")
}
fn default_services() -> PathBuf {
    PathBuf::from("/var/lib/netcontrol/services")
}

#[cfg_attr(
    any(not(target_os = "linux"), not(feature = "nftables")),
    allow(dead_code)
)]
mod firewall_plan;
#[cfg(target_os = "linux")]
mod linux;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod model;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod netlink_decode;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod statistics;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod tunables;
#[cfg(target_os = "linux")]
pub use linux::Native;

#[cfg(not(target_os = "linux"))]
pub struct Native;

#[cfg(not(target_os = "linux"))]
impl Native {
    pub fn open(_: NativeOptions) -> Result<Self> {
        bail!("the native backend requires Linux; no non-Linux networking fallback exists")
    }
}

#[cfg(not(target_os = "linux"))]
impl netcontrol_core::Backend for Native {
    fn scope(&self) -> Result<String> {
        bail!("native backend requires Linux")
    }
    fn observe(&mut self, _: &netcontrol_core::Config) -> Result<netcontrol_core::Config> {
        bail!("native backend requires Linux")
    }
    fn apply(&mut self, _: &netcontrol_core::Config, _: &netcontrol_core::Config) -> Result<()> {
        bail!("native backend requires Linux")
    }
    fn runtime(&mut self, _: &netcontrol_core::Config) -> Result<serde_json::Value> {
        bail!("native backend requires Linux")
    }
    fn statistics(
        &mut self,
        _: &netcontrol_core::Config,
        _: &str,
        _: &str,
    ) -> Result<serde_json::Value> {
        bail!("native backend requires Linux")
    }
    fn repair(&mut self, _: &netcontrol_core::Config) -> Result<serde_json::Value> {
        bail!("native backend requires Linux")
    }
}

pub(crate) fn safe_name(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn ensure_unchanged(condition: bool, message: impl Into<String>) -> anyhow::Result<()> {
    anyhow::ensure!(condition, netcontrol_core::BackendDrift(message.into()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drift_is_typed_without_reclassifying_read_failures() {
        fn check(read: anyhow::Result<bool>) -> anyhow::Result<()> {
            ensure_unchanged(read?, "observed state differs")
        }
        assert!(check(Ok(true)).is_ok());
        let drift = check(Ok(false))
            .unwrap_err()
            .context("network verification");
        assert!(
            drift
                .downcast_ref::<netcontrol_core::BackendDrift>()
                .is_some()
        );
        let unavailable = check(Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )
        .into()))
        .unwrap_err();
        assert!(
            unavailable
                .downcast_ref::<netcontrol_core::BackendDrift>()
                .is_none()
        );
        assert!(unavailable.downcast_ref::<std::io::Error>().is_some());
    }

    #[test]
    fn namespace_is_never_defaulted() {
        assert!(serde_json::from_str::<NativeOptions>("{}").is_err());
        let options: NativeOptions = serde_json::from_str(r#"{"namespace":"lab"}"#).unwrap();
        assert_eq!(options.namespace, "lab");
        assert!(!options.allow_host_tunables);
        assert!(
            serde_json::from_str::<NativeOptions>(r#"{"namespace":"lab","unexpected":true}"#)
                .is_err()
        );
    }
    #[test]
    fn names_cannot_escape_roots() {
        for bad in ["", ".", "..", "../host", "a/b", "a\\b", "lo\0", "a b"] {
            assert!(!safe_name(bad, 64));
        }
        assert!(safe_name("lab_01", 64));
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn nonlinux_is_explicit_error() {
        let options = serde_json::from_str(r#"{"namespace":"lab"}"#).unwrap();
        assert!(
            Native::open(options)
                .err()
                .unwrap()
                .to_string()
                .contains("requires Linux")
        );
    }
}
