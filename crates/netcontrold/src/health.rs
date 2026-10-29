use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};

const STALE_AFTER: Duration = Duration::from_secs(15);

struct Snapshot {
    value: Value,
    sampled: Option<Instant>,
    stale_at: Option<String>,
}

pub struct Monitor {
    started: Instant,
    snapshot: Mutex<Snapshot>,
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unavailable".into())
}

impl Default for Monitor {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            snapshot: Mutex::new(Snapshot {
                value: json!({"active_alerts":[],"process_health":{"status":"unknown","healthy":null,"collected_at":null,"components":[]}}),
                sampled: None,
                stale_at: None,
            }),
        }
    }
}

impl Monitor {
    pub fn observe(&self, runtime: Option<&Value>, managers: &[(&str, Value)], watchdog: bool) {
        let timestamp = now();
        let mut components = Vec::new();
        let mut alerts = BTreeMap::<String, Value>::new();
        let mut inspect = |component: &str, resource: &str, row: &Value| {
            let id = format!("{component}:{}", hex::encode(resource.as_bytes()));
            let state = row["process_state"]
                .as_str()
                .or_else(|| row["state"].as_str())
                .unwrap_or("unknown");
            let healthy = match state {
                "running" | "current" => Some(true),
                "error" | "stopped" | "unavailable" | "reconnecting" => Some(false),
                _ => None,
            };
            let retrying = row["retrying"]
                .as_bool()
                .unwrap_or(matches!(state, "reconnecting" | "connecting"));
            components.push(json!({"id":id,"component":component,"resource":resource,"state":state,"healthy":healthy,"retrying":retrying,"collected_at":timestamp}));
            let failed = healthy == Some(false);
            let inactive = matches!(state, "disabled" | "simulated");
            let warning = row["error"].as_str().is_some_and(|error| !error.is_empty())
                || (!inactive
                    && (row["sample_status"] == "unavailable"
                        || matches!(
                            row["health"].as_str(),
                            Some("down" | "degraded" | "unhealthy")
                        )
                        || row["statistics_complete"] == false
                        || row["warnings"]
                            .as_array()
                            .is_some_and(|warnings| !warnings.is_empty())));
            if failed || warning {
                let code = if failed {
                    "worker_unavailable"
                } else {
                    "service_warning"
                };
                let alert_id = format!("{id}:{code}");
                alerts.insert(alert_id.clone(), json!({"id":alert_id,"component":component,"resource":resource,
                    "severity":if failed {"error"} else {"warning"},"code":code,
                    "message":if failed {format!("{component} reports state {state}")} else {format!("{component} reports unavailable samples or a service error; inspect its status")},
                    "retrying":retrying,"first_seen_at":timestamp,"last_seen_at":timestamp}));
            }
        };
        if let Some(runtime) = runtime {
            for group in [
                "appliance_services",
                "dhcp_relay",
                "softflowd",
                "gateway_monitors",
            ] {
                for row in runtime[group].as_array().into_iter().flatten() {
                    let resource = row["name"]
                        .as_str()
                        .or_else(|| row["interface"].as_str())
                        .unwrap_or(group);
                    let resource = row["instance_id"]
                        .as_u64()
                        .map(|id| format!("{resource}:{id}"))
                        .unwrap_or_else(|| resource.to_owned());
                    inspect(group, &resource, row);
                }
            }
            if runtime["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty())
            {
                inspect(
                    "platform",
                    "runtime",
                    &json!({"state":"running","error":"runtime warning"}),
                );
            }
            for (resource, error) in runtime["dhcp_clients"]["errors"]
                .as_object()
                .into_iter()
                .flatten()
            {
                if error.as_str().is_some_and(|error| !error.is_empty()) {
                    inspect(
                        "dhcp_client",
                        resource,
                        &json!({"state":"error","retrying":true}),
                    );
                }
            }
        }
        for (component, status) in managers {
            if let Some(accounts) = status["entries"].as_array() {
                for account in accounts {
                    inspect(
                        component,
                        account["name"].as_str().unwrap_or(component),
                        account,
                    );
                }
            } else if *component == "system" && status.get("state").is_none() {
                for setting in ["hostname", "timezone"] {
                    inspect(component, setting, &status[setting]);
                }
            } else {
                inspect(component, component, status);
            }
        }
        if runtime.is_none() {
            alerts.insert("platform:runtime_unavailable".into(), json!({"id":"platform:runtime_unavailable","component":"platform","resource":null,"severity":"warning","code":"runtime_unavailable",
                "message":"Native runtime status could not be collected","retrying":true,"first_seen_at":timestamp,"last_seen_at":timestamp}));
        }
        if let Ok(mut snapshot) = self.snapshot.lock() {
            if runtime.is_none() {
                let native = |value: &Value| {
                    matches!(
                        value["component"].as_str(),
                        Some(
                            "appliance_services"
                                | "dhcp_relay"
                                | "softflowd"
                                | "gateway_monitors"
                                | "dhcp_client"
                        )
                    )
                };
                components.extend(
                    snapshot.value["process_health"]["components"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|row| native(row))
                        .cloned(),
                );
                for alert in snapshot.value["active_alerts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|alert| native(alert))
                {
                    if let Some(id) = alert["id"].as_str() {
                        alerts.insert(id.to_owned(), alert.clone());
                    }
                }
            }
            components.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
            let unhealthy = components.iter().any(|row| row["healthy"] == false);
            let unknown = components.iter().any(|row| {
                row["healthy"].is_null()
                    && !matches!(
                        row["state"].as_str(),
                        Some("disabled" | "simulated" | "waiting" | "unmanaged")
                    )
            });
            let healthy = if runtime.is_none() {
                None
            } else if unhealthy {
                Some(false)
            } else if !unknown {
                Some(true)
            } else {
                None
            };
            let previous: BTreeMap<_, _> = snapshot.value["active_alerts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|alert| {
                    alert["id"]
                        .as_str()
                        .map(|id| (id.to_owned(), alert["first_seen_at"].clone()))
                })
                .collect();
            for (id, alert) in &mut alerts {
                if let Some(first_seen) = previous.get(id) {
                    alert["first_seen_at"] = first_seen.clone();
                }
            }
            snapshot.value = json!({"active_alerts":alerts.into_values().collect::<Vec<_>>(),
                "process_health":{"status":match healthy {Some(true)=>"healthy",Some(false)=>"unhealthy",None=>"unknown"},"healthy":healthy,"collected_at":timestamp,"runtime_available":runtime.is_some(),"components":components,
                "daemon":{"pid":std::process::id(),"state":"running","healthy":true,"uptime_seconds":self.started.elapsed().as_secs(),"watchdog_enabled":watchdog}}});
            snapshot.sampled = Some(Instant::now());
            snapshot.stale_at = (time::OffsetDateTime::now_utc() + time::Duration::seconds(15))
                .format(&time::format_description::well_known::Rfc3339)
                .ok();
        }
    }

    pub fn snapshot(&self) -> Value {
        let Ok(snapshot) = self.snapshot.lock() else {
            return json!({"active_alerts":[{"id":"platform:health_unavailable","component":"platform","resource":null,"severity":"error","code":"health_unavailable","message":"Process health status is unavailable","retrying":false,"first_seen_at":null,"last_seen_at":null}],
                "process_health":{"status":"unknown","healthy":null,"collected_at":null,"stale":true,"components":[]}});
        };
        let mut value = snapshot.value.clone();
        if snapshot
            .sampled
            .is_none_or(|sampled| sampled.elapsed() > STALE_AFTER)
        {
            value["process_health"]["status"] = json!("unknown");
            value["process_health"]["healthy"] = Value::Null;
            value["process_health"]["stale"] = json!(true);
            if value["process_health"].get("daemon").is_some() {
                value["process_health"]["daemon"]["healthy"] = Value::Null;
                value["process_health"]["daemon"]["state"] = json!("unknown");
            }
            if snapshot.sampled.is_some() {
                value["active_alerts"].as_array_mut().unwrap().push(json!({"id":"platform:monitor_stale","component":"platform","resource":null,"severity":"warning","code":"monitor_stale",
                    "message":"Process health collection has not made recent progress","retrying":true,"first_seen_at":snapshot.stale_at,"last_seen_at":now()}));
            }
        } else {
            value["process_health"]["stale"] = json!(false);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn udp_relay_instances_keep_independent_health_alerts() {
        let monitor = super::Monitor::default();
        monitor.observe(Some(&serde_json::json!({"appliance_services":[
            {"name":"udp-broadcast-relay","instance_id":1,"state":"error","retrying":true,"error":"synthetic bind conflict"},
            {"name":"udp-broadcast-relay","instance_id":2,"state":"error","retrying":true,"error":"synthetic missing IPv4"}
        ]})), &[], false);
        let snapshot = monitor.snapshot();
        assert_eq!(snapshot["active_alerts"].as_array().unwrap().len(), 2);
        assert_ne!(
            snapshot["process_health"]["components"][0]["id"],
            snapshot["process_health"]["components"][1]["id"]
        );
        assert_eq!(
            snapshot["process_health"]["components"][0]["resource"],
            "udp-broadcast-relay:1"
        );
    }

    #[test]
    fn bgp_worker_health_is_independent_of_neighbor_availability() {
        let monitor = super::Monitor::default();
        monitor.observe(Some(&serde_json::json!({"appliance_services":[{"name":"bgp","state":"running","health":"degraded","error":null}]})),&[],false);
        let value = monitor.snapshot();
        assert_eq!(value["process_health"]["components"][0]["resource"], "bgp");
        assert_eq!(value["process_health"]["components"][0]["healthy"], true);
        assert_eq!(value["active_alerts"][0]["code"], "service_warning");
        monitor.observe(Some(&serde_json::json!({"appliance_services":[{"name":"bgp","state":"running","health":"up","error":null}]})),&[],false);
        assert_eq!(monitor.snapshot()["active_alerts"], serde_json::json!([]));
    }
    use super::*;

    #[test]
    fn inactive_mdns_statistics_do_not_raise_alerts_and_disable_clears_failure() {
        let monitor = Monitor::default();
        let config = netcontrol_core::Config::default();
        let mut row = config.mdns.status(&config, "error");
        row["error"] = json!("synthetic worker failure");
        monitor.observe(Some(&json!({"appliance_services":[row]})), &[], false);
        assert_eq!(monitor.snapshot()["process_health"]["status"], "unhealthy");
        assert_eq!(
            monitor.snapshot()["active_alerts"][0]["code"],
            "worker_unavailable"
        );

        for state in ["disabled", "simulated"] {
            let mut row = config.mdns.status(&config, state);
            monitor.observe(
                Some(&json!({"appliance_services":[row.clone()]})),
                &[],
                false,
            );
            assert_eq!(monitor.snapshot()["process_health"]["status"], "healthy");
            assert_eq!(monitor.snapshot()["active_alerts"], json!([]));
            assert_eq!(
                monitor.snapshot()["process_health"]["components"][0]["healthy"],
                Value::Null
            );

            row["warnings"] = json!(["receive_loss_accounting_unavailable"]);
            monitor.observe(Some(&json!({"appliance_services":[row]})), &[], false);
            assert_eq!(monitor.snapshot()["active_alerts"], json!([]));
        }

        let row = config.mdns.status(&config, "running");
        monitor.observe(Some(&json!({"appliance_services":[row]})), &[], false);
        assert_eq!(monitor.snapshot()["process_health"]["status"], "healthy");
        assert_eq!(
            monitor.snapshot()["active_alerts"][0]["code"],
            "service_warning"
        );
    }

    #[test]
    fn health_alerts_are_observational_deduplicated_and_clear_on_recovery() {
        let monitor = Monitor::default();
        assert_eq!(monitor.snapshot()["process_health"]["healthy"], Value::Null);
        let mut runtime = json!({"appliance_services":[{"name":"ntp","state":"running","sample_status":"unavailable","error":"synthetic upstream failure"}]});
        monitor.observe(Some(&runtime), &[], false);
        let warning = monitor.snapshot();
        assert_eq!(warning["process_health"]["healthy"], true);
        assert_eq!(warning["active_alerts"][0]["severity"], "warning");
        monitor.observe(Some(&runtime), &[], false);
        let repeated = monitor.snapshot();
        assert_eq!(repeated["active_alerts"].as_array().unwrap().len(), 1);
        assert_eq!(
            repeated["active_alerts"][0]["first_seen_at"],
            warning["active_alerts"][0]["first_seen_at"]
        );
        runtime["appliance_services"][0] = json!({"name":"ntp","state":"error","retrying":true});
        monitor.observe(Some(&runtime), &[], true);
        let failed = monitor.snapshot();
        assert_eq!(failed["process_health"]["status"], "unhealthy");
        assert_eq!(failed["active_alerts"][0]["retrying"], true);
        monitor.observe(None, &[], true);
        let unavailable = monitor.snapshot();
        assert_eq!(unavailable["process_health"]["status"], "unknown");
        assert!(
            unavailable["active_alerts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|alert| alert["id"] == failed["active_alerts"][0]["id"])
        );
        runtime["appliance_services"][0] =
            json!({"name":"ntp","state":"running","last_error":"historical failure"});
        monitor.observe(Some(&runtime), &[], true);
        assert_eq!(monitor.snapshot()["active_alerts"], json!([]));
        assert_eq!(monitor.snapshot()["process_health"]["status"], "healthy");
    }

    #[test]
    fn unavailable_manager_and_poisoned_cache_remain_explicit() {
        let monitor = std::sync::Arc::new(Monitor::default());
        monitor.observe(
            Some(&json!({})),
            &[("system", json!({"state":"unavailable"}))],
            false,
        );
        assert_eq!(monitor.snapshot()["process_health"]["status"], "unhealthy");
        assert_eq!(
            monitor.snapshot()["active_alerts"][0]["component"],
            "system"
        );
        let locked = monitor.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = locked.snapshot.lock().unwrap();
                panic!("synthetic health-cache failure");
            })
            .join()
            .is_err()
        );
        let snapshot = monitor.snapshot();
        assert_eq!(snapshot["process_health"]["status"], "unknown");
        assert_eq!(snapshot["process_health"]["stale"], true);
        assert_eq!(snapshot["active_alerts"][0]["code"], "health_unavailable");
    }

    #[test]
    fn missing_and_stale_runtime_do_not_claim_health() {
        let monitor = Monitor::default();
        monitor.observe(None, &[], false);
        assert_eq!(monitor.snapshot()["process_health"]["status"], "unknown");
        assert_eq!(
            monitor.snapshot()["active_alerts"][0]["code"],
            "runtime_unavailable"
        );
        monitor.observe(Some(&json!({})), &[], false);
        monitor.snapshot.lock().unwrap().sampled =
            Some(Instant::now() - STALE_AFTER - Duration::from_secs(1));
        assert_eq!(monitor.snapshot()["process_health"]["healthy"], Value::Null);
        assert_eq!(monitor.snapshot()["process_health"]["stale"], true);
        assert_eq!(
            monitor.snapshot()["active_alerts"][0]["code"],
            "monitor_stale"
        );
    }
}
