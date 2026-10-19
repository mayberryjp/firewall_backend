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
}
