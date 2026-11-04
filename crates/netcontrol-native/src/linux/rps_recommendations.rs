use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn ids(value: &Value) -> Result<BTreeSet<u32>> {
    value
        .as_array()
        .context("CPU/IRQ IDs unavailable")?
        .iter()
        .map(|id| Ok(u32::try_from(id.as_u64().context("invalid CPU/IRQ ID")?)?))
        .collect()
}

fn section<'a>(snapshot: &'a Value, name: &str) -> Result<&'a Value> {
    let section = &snapshot["sections"][name];
    ensure!(
        section["status"] == "available",
        "{name} evidence unavailable"
    );
    ensure!(!section["data"].is_null(), "{name} data unavailable");
    Ok(&section["data"])
}

fn sampled<'a>(snapshot: &'a Value, name: &str) -> Result<&'a Value> {
    let data = section(snapshot, name)?;
    ensure!(
        data["baseline"] == "ready",
        "{name} needs a stable second sample"
    );
    let interval = data["sample_interval_seconds"]
        .as_f64()
        .context("sample interval unavailable")?;
    ensure!(
        (1.0..=30.0).contains(&interval),
        "{name} sample interval must be 1..30 seconds"
    );
    Ok(data)
}

fn count(value: &Value) -> Result<u64> {
    Ok(value
        .as_str()
        .context("counter delta unavailable")?
        .parse()?)
}

fn core(topology: &Value, id: u32) -> Result<(i64, i64, BTreeSet<u32>)> {
    let row = topology["cpus"]
        .as_array()
        .context("CPU topology unavailable")?
        .iter()
        .find(|row| row["cpu_id"].as_u64() == Some(u64::from(id)))
        .context("CPU topology missing")?;
    let package = &row["physical_package_id"];
    let core = &row["core_id"];
    ensure!(
        package["status"] == "available" && core["status"] == "available",
        "CPU core identity unavailable"
    );
    let nodes = ids(&row["numa_node_ids"])?;
    ensure!(nodes.len() == 1, "CPU NUMA locality unavailable");
    Ok((
        package["data"]
            .as_i64()
            .context("CPU package unavailable")?,
        core["data"].as_i64().context("CPU core unavailable")?,
        nodes,
    ))
}

fn trial(snapshot: &Value, interface: &Value) -> Result<(String, Value)> {
    ensure!(
        snapshot["sample"]["identity_stable"] == true,
        "sample identity was not rechecked"
    );
    let online = ids(section(snapshot, "online_cpus")?)?;
    let allowed = ids(section(snapshot, "allowed_cpus")?)?;
    let isolated = ids(section(snapshot, "isolated_cpus")?)?;
    let eligible: BTreeSet<_> = online
        .intersection(&allowed)
        .copied()
        .filter(|id| !isolated.contains(id))
        .collect();
    ensure!(
        eligible.len() > 1,
        "multiple online allowed nonisolated CPUs are required"
    );
    let cpus = sampled(snapshot, "cpu")?;
    let softirqs = sampled(snapshot, "softirqs")?;
    let interrupts = sampled(snapshot, "interrupts")?;
    let cpu_interval = cpus["sample_interval_seconds"]
        .as_f64()
        .context("CPU interval missing")?;
    for data in [softirqs, interrupts] {
        let interval = data["sample_interval_seconds"]
            .as_f64()
            .context("source interval missing")?;
        ensure!(
            (interval - cpu_interval).abs() <= 0.1 + f64::EPSILON * interval.max(cpu_interval),
            "CPU/IRQ source intervals are not aligned"
        );
    }
    let topology = section(snapshot, "topology")?;
    ensure!(
        topology["partial"] == false,
        "complete CPU topology is required"
    );
    let affinity = section(snapshot, "irq_affinity")?;
    ensure!(
        affinity["partial"] == false,
        "complete IRQ affinity evidence is required"
    );
    let irqs = ids(&interface["irqs"])?;
    ensure!(!irqs.is_empty(), "NIC IRQ association unavailable");
    let mut irq_cpus = BTreeSet::new();
    for irq in &irqs {
        let row = affinity["rows"]
            .as_array()
            .context("IRQ affinities missing")?
            .iter()
            .find(|row| row["irq"].as_u64() == Some(u64::from(*irq)))
            .context("NIC IRQ affinity missing")?;
        let effective = &row["effective_affinity_list"];
        ensure!(
            effective["status"] == "available",
            "effective NIC IRQ affinity unavailable"
        );
        let cpus = ids(&effective["data"]["cpu_ids"])?;
        ensure!(!cpus.is_empty(), "effective NIC IRQ affinity is empty");
        irq_cpus.extend(cpus);
    }
    let cpu_rows = cpus["rows"].as_array().context("CPU utilization missing")?;
    let softirq_rows = softirqs["rows"]
        .as_array()
        .context("NET_RX activity missing")?;
    let irq_rows = interrupts["rows"]
        .as_array()
        .context("IRQ activity missing")?;
    let mut loaded = None;
    for row in cpu_rows {
        let id = u32::try_from(row["cpu_id"].as_u64().context("CPU ID missing")?)?;
        if !eligible.contains(&id) || !irq_cpus.contains(&id) {
            continue;
        }
        let busy = row["busy_percent"]
            .as_f64()
            .context("CPU utilization unavailable")?;
        let softirq = row["softirq_percent"]
            .as_f64()
            .context("softirq utilization unavailable")?;
        if busy < 80.0 || softirq < 30.0 {
            continue;
        }
        let net_rx = softirq_rows
            .iter()
            .find(|row| row["cpu_id"].as_u64() == Some(u64::from(id)))
            .context("CPU NET_RX evidence missing")?;
        if count(&net_rx["delta"]["net_rx"])? == 0 {
            continue;
        }
        let active = irq_rows.iter().any(|irq| {
            irq["cpu_id"].as_u64() == Some(u64::from(id))
                && irq["irq"]
                    .as_u64()
                    .and_then(|irq| u32::try_from(irq).ok())
                    .is_some_and(|irq| irqs.contains(&irq))
                && count(&irq["delta"]["interrupts"]).is_ok_and(|delta| delta > 0)
        });
        if active {
            loaded = Some((id, busy, softirq));
            break;
        }
    }
    let (loaded, busy, softirq) = loaded.context(
        "no associated IRQ CPU meets busy >=80%, softirq >=30% and positive NET_RX/IRQ activity",
    )?;
    let (package, loaded_core, nodes) = core(topology, loaded)?;
    let mut targets = vec![];
    for row in cpu_rows {
        let id = u32::try_from(row["cpu_id"].as_u64().context("CPU ID missing")?)?;
        if !eligible.contains(&id) || irq_cpus.contains(&id) {
            continue;
        }
        let busy = row["busy_percent"]
            .as_f64()
            .context("target CPU utilization unavailable")?;
        let softirq = row["softirq_percent"]
            .as_f64()
            .context("target softirq utilization unavailable")?;
        let (target_package, target_core, target_nodes) = core(topology, id)?;
        if busy <= 50.0
            && softirq <= 10.0
            && target_package == package
            && target_core != loaded_core
            && target_nodes == nodes
        {
            targets.push((id, busy, target_core));
        }
    }
    targets.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
    let mut selected = BTreeSet::new();
    let mut selected_cores = BTreeSet::new();
    for (id, _, core) in targets {
        if selected_cores.insert(core) {
            selected.insert(id);
        }
        if selected.len() == 2 {
            break;
        }
    }
    ensure!(
        !selected.is_empty(),
        "no idle, non-sibling local core outside NIC IRQ affinity is available"
    );
    Ok((
        netcontrol_core::cpu_mask(&selected),
        json!({
            "irq_cpu":loaded,"busy_percent":busy,"softirq_percent":softirq,
            "cpu_sample_interval_seconds":cpu_interval,"target_cpus":selected,
            "locality":"same package and NUMA node as the observed busy IRQ CPU"
        }),
    ))
}

pub(super) fn recommendations(snapshot: &Value) -> Result<Vec<Value>> {
    let interfaces = snapshot["interfaces"]
        .as_array()
        .context("performance interface evidence missing")?;
    let mut result = vec![];
    for interface in interfaces {
        if interface["managed"] != true
            || interface["physical"] != true
            || interface["up"] != true
            || interface["errors"]
                .as_array()
                .is_none_or(|errors| !errors.is_empty())
        {
            continue;
        }
        let Some(queues) = interface["rx_queues"]
            .as_array()
            .filter(|queues| queues.len() == 1)
        else {
            continue;
        };
        if queues[0]["rps_cpus"] != "0" {
            continue;
        }
        let key = format!(
            "{}/{}",
            interface["name"]
                .as_str()
                .context("performance interface name missing")?,
            queues[0]["name"]
                .as_str()
                .context("performance RX queue name missing")?
        );
        netcontrol_core::rps_target(&key)?;
        let (status, mask, evidence, reason) = match trial(snapshot, interface) {
            Ok((mask, evidence)) => (
                "trial",
                json!(mask),
                evidence,
                "Measured IRQ/CPU pressure permits an explicit RPS trial; benefit is unverified"
                    .to_owned(),
            ),
            Err(error) => (
                "insufficient_evidence",
                Value::Null,
                Value::Null,
                format!("{error:#}"),
            ),
        };
        result.push(json!({
            "kind":"rps","target":key,"status":status,"suggested_mask":mask,
            "evidence":evidence,"reason":reason,"automatic":false,
            "tuning_available":snapshot["tuning_available"]
        }));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture() -> Value {
        let available = |data: Value| json!({"status":"available","data":data,"error":null});
        let sampled = |rows: Value| {
            available(json!({"baseline":"ready","sample_interval_seconds":2.0,"rows":rows}))
        };
        let mut sections = BTreeMap::new();
        for key in ["online_cpus", "allowed_cpus"] {
            sections.insert(key, available(json!([0, 1, 2, 3])));
        }
        sections.insert("isolated_cpus", available(json!([])));
        sections.insert(
            "cpu",
            sampled(json!([
                {"cpu_id":0,"busy_percent":85.0,"softirq_percent":35.0},
                {"cpu_id":1,"busy_percent":10.0,"softirq_percent":2.0},
                {"cpu_id":2,"busy_percent":10.0,"softirq_percent":2.0},
                {"cpu_id":3,"busy_percent":20.0,"softirq_percent":3.0}
            ])),
        );
        sections.insert(
            "softirqs",
            sampled(json!([{"cpu_id":0,"delta":{"net_rx":"100"}}])),
        );
        sections.insert(
            "interrupts",
            sampled(json!([{"irq":41,"cpu_id":0,"delta":{"interrupts":"50"}}])),
        );
        sections.insert(
            "irq_affinity",
            available(json!({"partial":false,"rows":[
                {"irq":41,"effective_affinity_list":{"status":"available","data":{"cpu_ids":[0]}}}
            ]})),
        );
        sections.insert(
            "topology",
            available(json!({"partial":false,"cpus":(0..4).map(|id|json!({
            "cpu_id":id,"physical_package_id":available(json!(0)),"core_id":available(json!(id)),
            "numa_node_ids":[0]
        })).collect::<Vec<_>>()})),
        );
        json!({"sample":{"identity_stable":true},"sections":sections,"tuning_available":true,"interfaces":[
            {"name":"eno1","up":true,"managed":true,"physical":true,"errors":[],
                "irqs":[41],"rx_queues":[{"name":"rx-0","rps_cpus":"0"}]}
        ]})
    }

    #[test]
    fn performance_rps_trial_requires_exact_pressure_thresholds_and_local_idle_cores() {
        let mut sample = fixture();
        let result = recommendations(&sample).unwrap();
        assert_eq!(result[0]["status"], "trial");
        assert_eq!(result[0]["suggested_mask"], "6");
        assert_eq!(result[0]["automatic"], false);
        sample["sections"]["cpu"]["data"]["rows"][0]["busy_percent"] = json!(79.99);
        assert_eq!(
            recommendations(&sample).unwrap()[0]["suggested_mask"],
            Value::Null
        );
        sample = fixture();
        sample["sections"]["cpu"]["data"]["rows"][0]["softirq_percent"] = json!(29.99);
        assert_eq!(
            recommendations(&sample).unwrap()[0]["suggested_mask"],
            Value::Null
        );
        sample = fixture();
        sample["sections"]["cpu"]["data"]["rows"][0]["busy_percent"] = json!(80.0);
        sample["sections"]["cpu"]["data"]["rows"][0]["softirq_percent"] = json!(30.0);
        assert_eq!(recommendations(&sample).unwrap()[0]["status"], "trial");
        sample["sections"]["isolated_cpus"]["data"] = json!([1]);
        sample["sections"]["topology"]["data"]["cpus"][2]["core_id"]["data"] = json!(0);
        assert_eq!(recommendations(&sample).unwrap()[0]["suggested_mask"], "8");
    }

    #[test]
    fn performance_rps_abstains_for_missing_reset_stale_and_unrelated_evidence() {
        for (pointer, value) in [
            ("/sample/identity_stable", json!(false)),
            ("/sections/cpu/data/baseline", json!("starting")),
            ("/sections/cpu/data/sample_interval_seconds", json!(0.99)),
            (
                "/sections/softirqs/data/sample_interval_seconds",
                json!(30.01),
            ),
            (
                "/sections/interrupts/data/sample_interval_seconds",
                json!(2.2),
            ),
            ("/sections/softirqs/data/rows/0/delta/net_rx", json!("0")),
            (
                "/sections/interrupts/data/rows/0/delta/interrupts",
                json!("0"),
            ),
            ("/sections/interrupts/data/rows/0/irq", json!(42)),
            ("/sections/topology/data/partial", json!(true)),
            ("/sections/irq_affinity/data/partial", json!(true)),
            ("/sections/allowed_cpus/data", json!([0])),
            ("/sections/topology/data/cpus/0/numa_node_ids", Value::Null),
        ] {
            let mut sample = fixture();
            *sample.pointer_mut(pointer).unwrap() = value;
            let rows = recommendations(&sample).unwrap();
            assert_eq!(rows[0]["status"], "insufficient_evidence", "{pointer}");
            assert!(rows[0]["suggested_mask"].is_null(), "{pointer}");
            assert!(
                rows[0]["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty())
            );
        }
        for (pointer, value) in [
            ("/interfaces/0/managed", json!(false)),
            ("/interfaces/0/physical", json!(false)),
            ("/interfaces/0/rx_queues/0/rps_cpus", json!("2")),
            ("/interfaces/0/errors", json!(["queue read failed"])),
        ] {
            let mut sample = fixture();
            *sample.pointer_mut(pointer).unwrap() = value;
            assert!(recommendations(&sample).unwrap().is_empty());
        }
    }

    #[test]
    fn performance_rps_recommendation_interval_and_target_thresholds_are_inclusive() {
        for interval in [1.0, 30.0] {
            let mut sample = fixture();
            for source in ["cpu", "softirqs", "interrupts"] {
                sample["sections"][source]["data"]["sample_interval_seconds"] = json!(interval);
            }
            assert_eq!(recommendations(&sample).unwrap()[0]["status"], "trial");
        }
        let mut sample = fixture();
        sample["sections"]["softirqs"]["data"]["sample_interval_seconds"] = json!(2.1);
        assert_eq!(recommendations(&sample).unwrap()[0]["status"], "trial");
        sample["sections"]["softirqs"]["data"]["sample_interval_seconds"] = json!(2.100001);
        assert_eq!(
            recommendations(&sample).unwrap()[0]["status"],
            "insufficient_evidence"
        );
        sample = fixture();
        for cpu in [1, 2, 3] {
            sample["sections"]["cpu"]["data"]["rows"][cpu]["busy_percent"] = json!(50.0);
            sample["sections"]["cpu"]["data"]["rows"][cpu]["softirq_percent"] = json!(10.0);
        }
        assert_eq!(recommendations(&sample).unwrap()[0]["suggested_mask"], "6");
        for cpu in [1, 2, 3] {
            sample["sections"]["cpu"]["data"]["rows"][cpu]["busy_percent"] = json!(50.01);
        }
        assert_eq!(
            recommendations(&sample).unwrap()[0]["status"],
            "insufficient_evidence"
        );
    }
}
