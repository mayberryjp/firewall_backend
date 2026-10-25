use crate::mqtt::metric_key;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const GAUGE: &str = "measurement";
pub const COUNTER: &str = "total_increasing";
const MAX_CPUS: usize = 256;
const MAX_FILESYSTEMS: usize = 64;
const MAX_THERMAL: usize = 64;
const MAX_HWMON: usize = 128;
// Counters that contribute to busy percentage; guest ticks are already inside user/nice.
const TICK_FIELDS: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

pub struct Sensor {
    pub key: String,
    pub name: String,
    pub value: Value,
    pub unit: Option<&'static str>,
    pub class: Option<&'static str>,
}

#[derive(Default)]
pub struct HostSensors {
    pub sensors: Vec<Sensor>,
    /// Entity key prefixes whose set could not be enumerated this sample; Home Assistant keeps them.
    pub retained: Vec<&'static str>,
}

#[derive(Default)]
pub struct CpuBaseline {
    boot_id: String,
    ticks: BTreeMap<String, BTreeMap<String, u128>>,
}

fn data<'a>(host: Option<&'a Value>, section: &str) -> Option<&'a Value> {
    let section = host?["sections"].get(section)?;
    matches!(section["status"].as_str(), Some("available" | "partial"))
        .then_some(&section["data"])
        .filter(|data| !data.is_null())
}

pub(crate) fn scalar(value: &Value) -> Value {
    if value.is_string() || value.is_number() {
        value.clone()
    } else {
        Value::Null
    }
}

fn ticks(row: &Value) -> Option<BTreeMap<String, u128>> {
    let map = row["ticks"].as_object()?;
    let mut out = BTreeMap::new();
    for key in TICK_FIELDS {
        if let Some(value) = map.get(key) {
            out.insert(key.to_owned(), value.as_str()?.parse().ok()?);
        }
    }
    out.contains_key("idle").then_some(out)
}

fn busy_percent(previous: &BTreeMap<String, u128>, now: &BTreeMap<String, u128>) -> Option<f64> {
    if previous.len() != now.len() {
        return None;
    }
    let (mut total, mut idle) = (0u128, 0u128);
    for (key, current) in now {
        let delta = current.checked_sub(*previous.get(key)?)?;
        total += delta;
        if key == "idle" || key == "iowait" {
            idle += delta;
        }
    }
    (total > 0).then(|| 100.0 * (total - idle) as f64 / total as f64)
}

pub(crate) fn push(
    sensors: &mut Vec<Sensor>,
    key: impl Into<String>,
    name: impl Into<String>,
    value: Value,
    unit: Option<&'static str>,
    class: Option<&'static str>,
) {
    sensors.push(Sensor {
        key: key.into(),
        name: name.into(),
        value,
        unit,
        class,
    });
}

/// Unavailable readings stay null (unknown in Home Assistant), never zero.
pub fn sensors(host: Option<&Value>, baseline: &mut Option<CpuBaseline>) -> HostSensors {
    let mut sensors = Vec::new();
    let mut retained = Vec::new();

    let memory = data(host, "memory");
    let bytes = |name: &str| memory.map_or(Value::Null, |memory| scalar(&memory["bytes"][name]));
    let used = |name: &str| memory.map_or(Value::Null, |memory| scalar(&memory[name]));
    for (key, name, value) in [
        ("memory_total_bytes", "Memory total", bytes("MemTotal")),
        (
            "memory_available_bytes",
            "Memory available",
            bytes("MemAvailable"),
        ),
        ("memory_used_bytes", "Memory used", used("used_bytes")),
        ("swap_total_bytes", "Swap total", bytes("SwapTotal")),
        ("swap_used_bytes", "Swap used", used("swap_used_bytes")),
    ] {
        push(&mut sensors, key, name, value, Some("B"), Some(GAUGE));
    }

    let load = data(host, "load");
    for (key, name, field) in [
        ("load_1m", "Load average 1 minute", "one"),
        ("load_5m", "Load average 5 minutes", "five"),
        ("load_15m", "Load average 15 minutes", "fifteen"),
    ] {
        let value = load.map_or(Value::Null, |load| scalar(&load[field]));
        push(&mut sensors, key, name, value, None, Some(GAUGE));
    }
    let uptime =
        data(host, "uptime").map_or(Value::Null, |uptime| scalar(&uptime["uptime_seconds"]));
    push(
        &mut sensors,
        "host_uptime_seconds",
        "Host uptime",
        uptime,
        Some("s"),
        Some(GAUGE),
    );
    let oom = data(host, "vm").map_or(Value::Null, |vm| scalar(&vm["oom_kill"]));
    push(
        &mut sensors,
        "oom_kills",
        "OOM kills",
        oom,
        Some("kills"),
        Some(COUNTER),
    );

    for (section, label, categories) in [
        ("pressure_cpu", "CPU", &["some"][..]),
        ("pressure_memory", "memory", &["some", "full"][..]),
        ("pressure_io", "I/O", &["some", "full"][..]),
    ] {
        let pressure = data(host, section);
        for category in categories {
            let value =
                pressure.map_or(Value::Null, |pressure| scalar(&pressure[category]["avg10"]));
            push(
                &mut sensors,
                format!("{section}_{category}_avg10"),
                format!("{label} pressure {category} (10 s)"),
                value,
                Some("%"),
                Some(GAUGE),
            );
        }
    }

    let boot_id = host
        .and_then(|host| host["sample"]["boot_id"].as_str())
        .unwrap_or_default();
    let cpu = data(host, "cpu");
    let mut current = BTreeMap::new();
    match cpu.and_then(|cpu| cpu["cpus"].as_array()) {
        Some(rows) => {
            let previous = baseline
                .as_ref()
                .filter(|baseline| baseline.boot_id == boot_id)
                .map(|baseline| &baseline.ticks);
            for row in rows.iter().take(MAX_CPUS) {
                let Some(name) = row["name"].as_str() else {
                    continue;
                };
                let now = ticks(row);
                let percent = match (previous.and_then(|previous| previous.get(name)), &now) {
                    (Some(previous), Some(now)) => busy_percent(previous, now),
                    _ => None,
                };
                let label = match name.strip_prefix("cpu").filter(|index| !index.is_empty()) {
                    Some(index) => format!("CPU {index} busy"),
                    None => "CPU total busy".to_owned(),
                };
                push(
                    &mut sensors,
                    metric_key("cpu", name, "busy_percent"),
                    label,
                    percent.map_or(Value::Null, |percent| {
                        json!((percent * 100.0).round() / 100.0)
                    }),
                    Some("%"),
                    Some(GAUGE),
                );
                if let Some(now) = now {
                    current.insert(name.to_owned(), now);
                }
            }
        }
        None => retained.push("cpu"),
    }
    *baseline = cpu.map(|_| CpuBaseline {
        boot_id: boot_id.to_owned(),
        ticks: current,
    });

    match data(host, "thermal").and_then(Value::as_array) {
        Some(rows) => {
            for row in rows.iter().take(MAX_THERMAL) {
                let Some(id) = row["id"].as_str() else {
                    continue;
                };
                let value = (row["status"] == "available")
                    .then(|| row["data"]["temperature_millicelsius"].as_i64())
                    .flatten()
                    .map_or(Value::Null, |milli| json!(milli as f64 / 1000.0));
                push(
                    &mut sensors,
                    metric_key("thermal", id, "temperature"),
                    format!("{id} temperature"),
                    value,
                    Some("°C"),
                    Some(GAUGE),
                );
            }
        }
        None => retained.push("thermal"),
    }

    match data(host, "hwmon").and_then(Value::as_array) {
        Some(rows) => {
            let mut incomplete = false;
            for row in rows.iter().take(MAX_HWMON) {
                let (Some(id), Some(chip), Some(unit)) = (
                    row["id"].as_str(),
                    row["chip"].as_str(),
                    row["unit"].as_str(),
                ) else {
                    incomplete = true;
                    continue;
                };
                let (unit, divisor) = match unit {
                    "millicelsius" => ("°C", 1000.0),
                    "rpm" => ("RPM", 1.0),
                    _ => continue,
                };
                let value = (row["status"] == "available")
                    .then(|| row["data"]["value"].as_i64())
                    .flatten()
                    .map_or(Value::Null, |value| json!(value as f64 / divisor));
                push(
                    &mut sensors,
                    metric_key("hwmon", id, "value"),
                    format!("{chip} {id}"),
                    value,
                    Some(unit),
                    Some(GAUGE),
                );
            }
            if incomplete {
                retained.push("hwmon");
            }
        }
        None => retained.push("hwmon"),
    }

    match data(host, "filesystems").and_then(Value::as_array) {
        Some(rows) => {
            let mut seen = BTreeSet::new();
            for row in rows {
                let Some(mount) = row["mount_point"].as_str() else {
                    continue;
                };
                if seen.len() >= MAX_FILESYSTEMS || !seen.insert(mount) {
                    continue;
                }
                let usage = &row["usage"];
                for (field, label) in [
                    ("total_bytes", "total"),
                    ("used_bytes", "used"),
                    ("available_bytes", "available"),
                ] {
                    let value = if usage["status"] == "available" {
                        scalar(&usage["data"][field])
                    } else {
                        Value::Null
                    };
                    push(
                        &mut sensors,
                        metric_key("fs", mount, field),
                        format!("{mount} {label}"),
                        value,
                        Some("B"),
                        Some(GAUGE),
                    );
                }
            }
        }
        None => retained.push("fs"),
    }
    HostSensors { sensors, retained }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(user: u64, idle: u64) -> Value {
        json!({"sample":{"boot_id":"00000000-0000-0000-0000-000000000001"},"sections":{
            "cpu":{"status":"available","error":null,"data":{"ticks_per_second":100,"cpus":[
                {"name":"cpu","ticks":{"user":(user*2).to_string(),"idle":(idle*2).to_string(),"guest":"7"}},
                {"name":"cpu0","ticks":{"user":user.to_string(),"idle":idle.to_string()}},
                {"name":"cpu1","ticks":{"user":user.to_string(),"idle":idle.to_string()}}]}},
            "memory":{"status":"available","error":null,"data":{"bytes":{"MemTotal":"8000","MemAvailable":"3000","SwapTotal":"1000"},"used_bytes":"5000","swap_used_bytes":"10"}},
            "load":{"status":"available","error":null,"data":{"one":0.5,"five":0.25,"fifteen":0.1}},
            "uptime":{"status":"available","error":null,"data":{"uptime_seconds":123.5,"idle_seconds":9.0}},
            "vm":{"status":"available","error":null,"data":{"oom_kill":"3"}},
            "pressure_cpu":{"status":"available","error":null,"data":{"some":{"avg10":1.5}}},
            "pressure_memory":{"status":"unavailable","error":"no PSI","data":null},
            "pressure_io":{"status":"available","error":null,"data":{"some":{"avg10":2.0},"full":{"avg10":0.5}}},
            "filesystems":{"status":"available","error":null,"data":[
                {"mount_point":"/","usage":{"status":"available","error":null,"data":{"total_bytes":"18446744073709551615","used_bytes":"5","available_bytes":"4"}}},
                {"mount_point":"/data","usage":{"status":"unavailable","error":"statvfs","data":null}}]},
            "thermal":{"status":"partial","error":null,"data":[
                {"id":"thermal_zone0","status":"available","error":null,"data":{"type":"x86","temperature_millicelsius":-1500}},
                {"id":"thermal_zone1","status":"unavailable","error":"read","data":null}]},
            "hwmon":{"status":"available","error":null,"data":[
                {"id":"hwmon0/temp1","chip":"coretemp","unit":"millicelsius","status":"available","error":null,"data":{"value":42500,"label":null}},
                {"id":"hwmon0/fan1","chip":"coretemp","unit":"rpm","status":"available","error":null,"data":{"value":0,"label":null}}]}
        }})
    }

    fn value(host: &HostSensors, key: &str) -> Value {
        host.sensors
            .iter()
            .find(|sensor| sensor.key == key)
            .unwrap_or_else(|| panic!("missing {key}"))
            .value
            .clone()
    }

    #[test]
    fn per_core_utilization_needs_two_valid_samples_and_never_reports_zero_for_unknown() {
        let mut baseline = None;
        let first = sensors(Some(&snapshot(100, 900)), &mut baseline);
        let core = metric_key("cpu", "cpu0", "busy_percent");
        assert!(value(&first, &core).is_null());
        assert!(value(&first, &metric_key("cpu", "cpu", "busy_percent")).is_null());
        let second = sensors(Some(&snapshot(150, 950)), &mut baseline);
        assert_eq!(value(&second, &core), json!(50.0));
        assert_eq!(
            value(&second, &metric_key("cpu", "cpu1", "busy_percent")),
            json!(50.0)
        );
        assert_eq!(
            value(&second, &metric_key("cpu", "cpu", "busy_percent")),
            json!(50.0)
        );
        // A counter decrease or no elapsed ticks is a reset, not a fabricated rate.
        assert!(value(&sensors(Some(&snapshot(10, 10)), &mut baseline), &core).is_null());
        assert!(value(&sensors(Some(&snapshot(10, 10)), &mut baseline), &core).is_null());
        let mut other_boot = snapshot(200, 1000);
        other_boot["sample"]["boot_id"] = json!("00000000-0000-0000-0000-000000000002");
        assert!(value(&sensors(Some(&other_boot), &mut baseline), &core).is_null());
        let missing = sensors(None, &mut baseline);
        assert!(missing.sensors.iter().all(|sensor| sensor.key != core));
        assert!(baseline.is_none());
    }

    #[test]
    fn sensors_preserve_units_precision_and_unknown_values() {
        let mut baseline = None;
        let host = sensors(Some(&snapshot(1, 1)), &mut baseline);
        assert_eq!(value(&host, "memory_used_bytes"), "5000");
        assert_eq!(value(&host, "swap_used_bytes"), "10");
        assert!(value(&host, "memory_total_bytes") == "8000");
        assert_eq!(value(&host, "load_5m"), json!(0.25));
        assert_eq!(value(&host, "host_uptime_seconds"), json!(123.5));
        assert_eq!(value(&host, "oom_kills"), "3");
        assert_eq!(value(&host, "pressure_cpu_some_avg10"), json!(1.5));
        assert!(value(&host, "pressure_memory_some_avg10").is_null());
        assert_eq!(value(&host, "pressure_io_full_avg10"), json!(0.5));
        assert!(
            !host
                .sensors
                .iter()
                .any(|sensor| sensor.key == "pressure_cpu_full_avg10")
        );
        assert_eq!(
            value(&host, &metric_key("fs", "/", "total_bytes")),
            "18446744073709551615"
        );
        assert!(value(&host, &metric_key("fs", "/data", "used_bytes")).is_null());
        assert_eq!(
            value(
                &host,
                &metric_key("thermal", "thermal_zone0", "temperature")
            ),
            json!(-1.5)
        );
        assert!(
            value(
                &host,
                &metric_key("thermal", "thermal_zone1", "temperature")
            )
            .is_null()
        );
        assert_eq!(
            value(&host, &metric_key("hwmon", "hwmon0/temp1", "value")),
            json!(42.5)
        );
        assert_eq!(
            value(&host, &metric_key("hwmon", "hwmon0/fan1", "value")),
            json!(0.0)
        );
        assert!(host.retained.is_empty());
        let unit = |key: String| {
            host.sensors
                .iter()
                .find(|sensor| sensor.key == key)
                .unwrap()
                .unit
        };
        assert_eq!(
            unit(metric_key("hwmon", "hwmon0/fan1", "value")),
            Some("RPM")
        );
        assert_eq!(
            unit(metric_key("hwmon", "hwmon0/temp1", "value")),
            Some("°C")
        );
    }

    #[test]
    fn failed_sections_publish_unknown_and_keep_dynamic_entities() {
        let mut baseline = None;
        let host = sensors(None, &mut baseline);
        assert!(host.sensors.iter().all(|sensor| sensor.value.is_null()));
        assert_eq!(host.retained, ["cpu", "thermal", "hwmon", "fs"]);
        let mut partial = snapshot(1, 1);
        partial["sections"]["hwmon"]["data"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"hwmon9","status":"unavailable","error":"name","data":null}));
        let host = sensors(Some(&partial), &mut baseline);
        assert_eq!(host.retained, ["hwmon"]);
    }

    #[test]
    fn entity_counts_are_bounded() {
        let cpus: Vec<Value> = (0..400)
            .map(|index| json!({"name":format!("cpu{index}"),"ticks":{"user":"1","idle":"1"}}))
            .collect();
        let mut host = snapshot(1, 1);
        host["sections"]["cpu"]["data"]["cpus"] = json!(cpus);
        let mut baseline = None;
        let sensors = sensors(Some(&host), &mut baseline);
        let cpu = sensors
            .sensors
            .iter()
            .filter(|sensor| sensor.key.starts_with("cpu_"))
            .count();
        assert_eq!(cpu, MAX_CPUS);
    }
}
