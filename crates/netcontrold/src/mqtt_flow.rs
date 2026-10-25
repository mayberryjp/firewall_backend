use crate::mqtt::metric_key;
use crate::mqtt_host::{COUNTER, GAUGE, HostSensors, push, scalar};
use serde_json::Value;

const MAX_INSTANCES: usize = 64;

/// One set of sensors per configured NetFlow/IPFIX instance; absent counters stay null, never zero.
pub fn sensors(status: Option<&Value>) -> HostSensors {
    let mut out = HostSensors::default();
    let Some(rows) = status.and_then(|status| status["instances"].as_array()) else {
        out.retained.push("flow");
        return out;
    };
    let mut incomplete = false;
    for row in rows.iter().take(MAX_INSTANCES) {
        let Some(name) = row["name"].as_str() else {
            incomplete = true;
            continue;
        };
        let key = |field: &str| metric_key("flow", name, field);
        push(
            &mut out.sensors,
            key("state"),
            format!("{name} flow export state"),
            row["state"]
                .as_str()
                .map_or(Value::Null, |state| state.into()),
            None,
            None,
        );
        push(
            &mut out.sensors,
            key("statistics_complete"),
            format!("{name} flow capture statistics complete"),
            row["statistics_complete"]
                .as_bool()
                .map_or(Value::Null, Value::Bool),
            None,
            None,
        );
        for (field, label, unit, class) in [
            ("dropped_packets", "dropped packets", "packets", COUNTER),
            ("active_flows", "active flows", "flows", GAUGE),
            ("exported_flows", "exported flows", "flows", COUNTER),
            ("excluded_packets", "excluded packets", "packets", COUNTER),
            ("filtered_packets", "filtered packets", "packets", COUNTER),
            ("malformed_packets", "malformed packets", "packets", COUNTER),
        ] {
            push(
                &mut out.sensors,
                key(field),
                format!("{name} flow {label}"),
                scalar(&row[field]),
                Some(unit),
                Some(class),
            );
        }
    }
    if incomplete {
        out.retained.push("flow");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn value(sensors: &HostSensors, name: &str, field: &str) -> Value {
        let key = metric_key("flow", name, field);
        sensors
            .sensors
            .iter()
            .find(|sensor| sensor.key == key)
            .unwrap_or_else(|| panic!("missing {key}"))
            .value
            .clone()
    }

    #[test]
    fn flow_sensors_keep_exact_drops_and_report_unknown_as_null() {
        let status = json!({"error":"","instances":[
            {"name":"office","state":"running","dropped_packets":"18446744073709551615","statistics_complete":false,
             "active_flows":4,"exported_flows":9,"excluded_packets":1,"filtered_packets":2,"malformed_packets":0},
            {"name":"lab","state":"stopped"},
            {"name":"off","state":"disabled"}]});
        let sensors = sensors(Some(&status));
        assert!(sensors.retained.is_empty());
        assert_eq!(
            value(&sensors, "office", "dropped_packets"),
            "18446744073709551615"
        );
        assert_eq!(value(&sensors, "office", "statistics_complete"), false);
        assert_eq!(value(&sensors, "office", "state"), "running");
        assert_eq!(value(&sensors, "office", "active_flows"), json!(4));
        assert_eq!(value(&sensors, "office", "malformed_packets"), json!(0));
        for name in ["lab", "off"] {
            for field in [
                "dropped_packets",
                "statistics_complete",
                "active_flows",
                "exported_flows",
                "excluded_packets",
                "filtered_packets",
                "malformed_packets",
            ] {
                assert!(value(&sensors, name, field).is_null(), "{name} {field}");
            }
        }
        assert_eq!(value(&sensors, "lab", "state"), "stopped");
        assert_eq!(value(&sensors, "off", "state"), "disabled");
    }

    #[test]
    fn unreadable_or_incomplete_status_keeps_existing_entities() {
        assert_eq!(sensors(None).retained, ["flow"]);
        assert_eq!(sensors(Some(&json!({"instances":null}))).retained, ["flow"]);
        let partial = sensors(Some(&json!({"instances":[{"state":"running"}]})));
        assert!(partial.sensors.is_empty());
        assert_eq!(partial.retained, ["flow"]);
        let none = sensors(Some(&json!({"instances":[]})));
        assert!(none.sensors.is_empty() && none.retained.is_empty());
    }
}
