use anyhow::{Result, bail, ensure};

pub fn validate(name: &str, scope: &str, value: &str) -> Result<()> {
    let (min, max, count) = match (scope, name) {
        ("namespace", "net.core.somaxconn" | "net.ipv4.tcp_max_syn_backlog") => {
            (0, i32::MAX as i64, 1)
        }
        (
            "namespace",
            "net.ipv4.tcp_syncookies" | "net.ipv4.tcp_timestamps" | "net.ipv4.tcp_mtu_probing",
        ) => (0, 2, 1),
        (
            "namespace",
            "net.ipv4.tcp_sack"
            | "net.ipv4.tcp_window_scaling"
            | "net.ipv4.tcp_moderate_rcvbuf"
            | "net.ipv4.tcp_slow_start_after_idle"
            | "net.ipv4.tcp_autocorking"
            | "net.ipv4.tcp_no_metrics_save",
        ) => (0, 1, 1),
        ("namespace", "net.ipv4.tcp_rmem" | "net.ipv4.tcp_wmem") => (1, i32::MAX as i64, 3),
        ("namespace", "net.ipv4.ip_local_port_range") => (1, 65535, 2),
        ("namespace", "net.ipv4.tcp_congestion_control") => {
            ensure!(
                !value.is_empty()
                    && value.len() <= 15
                    && value
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'-')),
                "invalid congestion algorithm"
            );
            return Ok(());
        }
        (
            "host",
            "net.core.rmem_max"
            | "net.core.wmem_max"
            | "net.core.rmem_default"
            | "net.core.wmem_default"
            | "net.core.netdev_budget",
        ) => (1, i32::MAX as i64, 1),
        ("host", "net.core.netdev_max_backlog" | "net.core.netdev_budget_usecs") => {
            (0, i32::MAX as i64, 1)
        }
        (_, name) if name.starts_with("net.netfilter.") => {
            let parameter = netcontrol_core::kernel_catalog()
                .into_iter()
                .find(|parameter| parameter.scope == scope && parameter.name == name)
                .ok_or_else(|| anyhow::anyhow!("unsupported {scope} kernel tunable {name}"))?;
            (parameter.min, parameter.max, parameter.count)
        }
        _ => bail!("unsupported {scope} kernel tunable {name}"),
    };
    let fields: Vec<_> = value.split(' ').collect();
    ensure!(
        fields.len() == count,
        "incorrect kernel value element count"
    );
    let mut previous = min;
    for (i, field) in fields.iter().enumerate() {
        let number: i64 = field.parse()?;
        ensure!(
            number.to_string() == *field && (min..=max).contains(&number),
            "noncanonical or out-of-range kernel value"
        );
        ensure!(
            count == 1 || i == 0 || number >= previous,
            "kernel vector must be nondecreasing"
        );
        previous = number;
    }
    ensure!(
        count != 2 || fields[0] != fields[1],
        "port range requires two distinct endpoints"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validate_kernel_values_strictly() {
        assert!(validate("net.ipv4.tcp_rmem", "namespace", "4096 131072 6291456").is_ok());
        assert!(validate("net.core.rmem_max", "host", "212992").is_ok());
        for value in ["01", "+1", " 1", "1 ", "3", "-1"] {
            assert!(validate("net.ipv4.tcp_syncookies", "namespace", value).is_err());
        }
        assert!(validate("net.ipv4.ip_local_port_range", "namespace", "100 100").is_err());
        assert!(validate("net.ipv4.tcp_rmem", "namespace", "4 3 5").is_err());
        assert!(validate("../../x", "namespace", "1").is_err());
        assert!(validate("net.core.rmem_max", "namespace", "1").is_err());
        assert!(validate("net.ipv4.tcp_congestion_control", "namespace", "cubic\n").is_err());
    }

    #[test]
    fn conntrack_native_validation_matches_catalog_bounds_and_scopes() {
        let parameters: Vec<_> = netcontrol_core::kernel_catalog()
            .into_iter()
            .filter(|parameter| parameter.name.starts_with("net.netfilter."))
            .collect();
        assert_eq!(parameters.len(), 9);
        for parameter in parameters {
            for value in [parameter.min, parameter.max] {
                validate(parameter.name, parameter.scope, &value.to_string()).unwrap();
            }
            for value in [
                (parameter.min - 1).to_string(),
                (parameter.max + 1).to_string(),
                "01".into(),
                "+1".into(),
                "1 2".into(),
                "1\n".into(),
            ] {
                assert!(validate(parameter.name, parameter.scope, &value).is_err());
            }
            let wrong_scope = if parameter.scope == "host" {
                "namespace"
            } else {
                "host"
            };
            assert!(validate(parameter.name, wrong_scope, &parameter.min.to_string()).is_err());
        }
        for name in [
            "net.netfilter.nf_conntrack_count",
            "net.netfilter.nf_conntrack_buckets",
            "net.netfilter.nf_conntrack_tcp_be_liberal",
            "net.netfilter.nf_conntrack_tcp_loose",
        ] {
            for scope in ["namespace", "host"] {
                assert!(validate(name, scope, "1").is_err());
            }
        }
    }
}
