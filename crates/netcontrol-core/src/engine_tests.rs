#[cfg(test)]
fn test_revision(index: u32) -> crate::Version {
    format!("{}.{}", chrono::Utc::now().format("%Y.%m.%d"), index + 1)
        .parse()
        .unwrap()
}

use super::*;
use crate::{Simulator, SystemConfig};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct Fixture {
    dir: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = PathBuf::from("target").join("core-tests").join(format!(
            "{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn path(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    fn engine(&self) -> Engine {
        Engine::open(&self.path(), Box::new(Simulator::new())).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn all() -> Vec<String> {
    PERMISSIONS.iter().map(|s| s.to_string()).collect()
}
fn config() -> Config {
    serde_json::from_value(json!({"interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}]})).unwrap()
}
fn request(e: &mut Engine, method: &str, path: &str, body: Value) -> Reply {
    e.request(
        method,
        path,
        "",
        "operator",
        &all(),
        &serde_json::to_vec(&body).unwrap(),
    )
}
fn submit(e: &mut Engine, c: Config) -> Reply {
    request(
        e,
        "POST",
        "/api/v1/transactions",
        json!({"base_revision":e.state.revision,"confirm_timeout_seconds":30,"description":" Update network ","config":c}),
    )
}
fn confirm(e: &mut Engine, id: &str) -> Reply {
    request(
        e,
        "POST",
        &format!("/api/v1/transactions/{id}/confirm"),
        Value::Null,
    )
}

fn firewall_clear_config(host_policies: bool) -> Config {
    let mut candidate = config();
    candidate.interfaces.push(
        serde_json::from_value(json!({
            "name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,
            "addresses":["198.51.100.1/24"]
        }))
        .unwrap(),
    );
    candidate.firewall = serde_json::from_value(json!({
        "policy":"drop","allow_all_icmp":false,
        "nat":{
            "masquerade":[{"family":"ipv4","out_interface":"wan0","source":"192.0.2.0/24"}],
            "destination_rewrite":[{
                "out_interface":"wan0","protocol":"udp","destination_port":53,
                "target_interface":"lan0","target_address":"192.0.2.53"
            }]
        },
        "input":{"policy":"drop","interfaces":[{
            "interface":"lan0","rules":[{
                "protocol":"tcp","destination_ports":[443],"action":"accept"
            }]
        }]}
    }))
    .unwrap();
    if host_policies {
        candidate.firewall.policies = Some(serde_json::from_value(json!({
            "hosts":[{
                "id":"camera","name":"Camera","addresses":["192.0.2.10"],"policy":"drop",
                "rules":[{"protocol":"tcp","destination_ports":[443],"action":"accept"}]
            }],
            "interfaces":[{
                "interface":"lan0",
                "metadata":{"display_name":"LAN override","description":"Preserved interface metadata"},
                "rules":[{"destination_host":"camera","action":"drop"}]
            }]
        })).unwrap());
    } else {
        candidate.firewall.rules = serde_json::from_value(json!([
            {"source":"192.0.2.0/24","destination":"198.51.100.0/24","action":"accept"}
        ]))
        .unwrap();
    }
    candidate.sando.api_url = "http://sando.example.test".into();
    candidate.sando.sync_enabled = true;
    candidate.validate().unwrap();
    candidate
}

#[test]
fn firewall_bulk_clear_confirms_only_hosts_and_forward_rules_and_survives_restart() {
    for host_policies in [false, true] {
        let fixture = Fixture::new();
        let mut engine = fixture.engine();
        let original = firewall_clear_config(host_policies);
        let initial = submit(&mut engine, original.clone());
        assert_eq!(initial.status, 202, "{}", initial.body);
        assert_eq!(
            confirm(&mut engine, initial.body["id"].as_str().unwrap()).status,
            200
        );
        let base = engine.committed_revision();
        let response = engine.request(
            "DELETE",
            "/api/v1/firewall/hosts-and-rules",
            "",
            "operator",
            &["transactions.write".into(), "firewall.write".into()],
            &serde_json::to_vec(&json!({
                "base_revision":base,"confirm_timeout_seconds":30,"confirm":true
            }))
            .unwrap(),
        );
        assert_eq!(response.status, 202, "{}", response.body);
        assert_eq!(response.body["status"], "pending_confirmation");
        assert_eq!(
            response.body["description"],
            "Clear firewall hosts and forwarding rules"
        );
        let id = response.body["id"].as_str().unwrap().to_owned();
        assert_eq!(
            response.location,
            Some(format!("/api/v1/transactions/{id}"))
        );
        assert_eq!(engine.saved_configuration(), &original.normalized());
        assert_eq!(engine.committed_revision(), base);
        let mut expected = original.clone();
        expected.firewall.rules = vec![];
        if let Some(policies) = &mut expected.firewall.policies {
            policies.hosts = vec![];
            policies.interfaces[0].rules = vec![];
        }
        assert_eq!(response.body["candidate"], json!(expected.normalized()));
        assert_eq!(engine.expected(), expected.normalized());
        drop(engine);
        let mut engine = fixture.engine();
        assert_eq!(engine.active().unwrap().id, id);
        assert_eq!(engine.saved_configuration(), &original.normalized());
        assert_eq!(confirm(&mut engine, &id).status, 200);
        assert_eq!(engine.saved_configuration(), &expected.normalized());
        assert_ne!(engine.committed_revision(), base);
        drop(engine);
        let mut engine = fixture.engine();
        assert_eq!(engine.saved_configuration(), &expected.normalized());
        let old = request(
            &mut engine,
            "GET",
            &format!("/api/v1/revisions/{base}"),
            Value::Null,
        );
        assert_eq!(old.body["config"], json!(original.normalized()));
    }
}

#[test]
fn firewall_bulk_clear_requires_explicit_scoped_input_and_normal_transaction_guards() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let base = engine.committed_revision();
    let valid = json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":true});
    let path = "/api/v1/firewall/hosts-and-rules";
    for missing in ["transactions.write", "firewall.write"] {
        let permissions: Vec<_> = all().into_iter().filter(|p| p != missing).collect();
        assert_eq!(
            engine
                .request(
                    "DELETE",
                    path,
                    "",
                    "operator",
                    &permissions,
                    &serde_json::to_vec(&valid).unwrap()
                )
                .status,
            403
        );
    }
    for method in ["GET", "POST", "PUT"] {
        assert_eq!(
            request(&mut engine, method, path, valid.clone()).status,
            405
        );
    }
    assert_eq!(
        engine
            .request(
                "DELETE",
                path,
                "unexpected=1",
                "operator",
                &all(),
                &serde_json::to_vec(&valid).unwrap()
            )
            .status,
        400
    );
    assert_eq!(
        engine
            .request(
                "DELETE",
                path,
                "",
                "",
                &all(),
                &serde_json::to_vec(&valid).unwrap()
            )
            .status,
        401
    );
    for body in [
        json!({}),
        json!({"base_revision":base,"confirm_timeout_seconds":30}),
        json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":false}),
        json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":"true"}),
        json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":true,"config":{}}),
        json!({"base_revision":1,"confirm_timeout_seconds":30,"confirm":true}),
    ] {
        let result = request(&mut engine, "DELETE", path, body);
        assert_eq!(result.status, 400, "{}", result.body);
        assert!(engine.active().is_none());
    }
    for timeout in [9, 301] {
        assert_eq!(
            request(
                &mut engine,
                "DELETE",
                path,
                json!({"base_revision":base,"confirm_timeout_seconds":timeout,"confirm":true})
            )
            .status,
            422
        );
    }
    assert_eq!(request(&mut engine, "DELETE", path,
        json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":true,"description":"x".repeat(1025)})).status, 422);
    assert_eq!(
        request(
            &mut engine,
            "DELETE",
            path,
            json!({"base_revision":"2000.01.01.1","confirm_timeout_seconds":30,"confirm":true})
        )
        .status,
        409
    );
    engine.set_upgrade_maintenance(true).unwrap();
    assert_eq!(
        request(&mut engine, "DELETE", path, valid.clone()).status,
        409
    );
    engine.set_upgrade_maintenance(false).unwrap();
    engine.begin_restart().unwrap();
    assert_eq!(
        request(&mut engine, "DELETE", path, valid.clone()).status,
        409
    );
    engine.cancel_restart();
    let active = submit(&mut engine, config());
    assert_eq!(active.status, 202);
    assert_eq!(request(&mut engine, "DELETE", path, valid).status, 409);
}

#[test]
fn firewall_bulk_clear_rolls_back_explicitly_or_at_deadline_after_restart() {
    for expire in [false, true] {
        let fixture = Fixture::new();
        let mut engine = fixture.engine();
        let original = firewall_clear_config(true);
        let initial = submit(&mut engine, original.clone());
        assert_eq!(initial.status, 202);
        assert_eq!(
            confirm(&mut engine, initial.body["id"].as_str().unwrap()).status,
            200
        );
        let base = engine.committed_revision();
        let response = request(
            &mut engine,
            "DELETE",
            "/api/v1/firewall/hosts-and-rules",
            json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":true,"description":" Reviewed bulk clear "}),
        );
        assert_eq!(response.status, 202, "{}", response.body);
        assert_eq!(response.body["description"], "Reviewed bulk clear");
        let id = response.body["id"].as_str().unwrap().to_owned();
        drop(engine);
        let mut engine = fixture.engine();
        if expire {
            engine.now = Some(engine.active().unwrap().confirmation_deadline);
            engine.tick().unwrap();
        } else {
            let rolled_back = request(
                &mut engine,
                "POST",
                &format!("/api/v1/transactions/{id}/rollback"),
                Value::Null,
            );
            assert_eq!(rolled_back.status, 200);
        }
        assert_eq!(engine.state.transactions[&id].status, "rolled_back");
        assert!(engine.active().is_none());
        assert_eq!(engine.saved_configuration(), &original.normalized());
        assert_eq!(engine.expected(), original.normalized());
        assert_eq!(engine.committed_revision(), base);
    }
}

#[test]
fn firewall_bulk_clear_rejects_drift_and_preserves_state_on_apply_or_persistence_failure() {
    for failure in ["drift", "observation", "persistence", "apply"] {
        let fixture = Fixture::new();
        let (mut engine, faults) = faulty(&fixture);
        let original = firewall_clear_config(true);
        let initial = submit(&mut engine, original.clone());
        assert_eq!(initial.status, 202, "{}", initial.body);
        assert_eq!(
            confirm(&mut engine, initial.body["id"].as_str().unwrap()).status,
            200
        );
        let base = engine.committed_revision();
        let applies = faults.lock().unwrap().apply_count;
        match failure {
            "drift" => faults.lock().unwrap().state.firewall.allow_all_icmp = true,
            "observation" => faults.lock().unwrap().fail_observe = true,
            "persistence" => engine.store.fail_after.set(Some(0)),
            "apply" => faults.lock().unwrap().fail_applies = 1,
            _ => unreachable!(),
        }
        let response = request(
            &mut engine,
            "DELETE",
            "/api/v1/firewall/hosts-and-rules",
            json!({"base_revision":base,"confirm_timeout_seconds":30,"confirm":true}),
        );
        assert_eq!(
            response.status,
            if failure == "drift" { 409 } else { 500 },
            "{}",
            response.body
        );
        assert_eq!(engine.saved_configuration(), &original.normalized());
        assert_eq!(engine.committed_revision(), base);
        assert!(engine.active().is_none());
        let faults = faults.lock().unwrap();
        assert_eq!(faults.connection_flushes, 0);
        if failure == "apply" {
            assert_eq!(response.body["transaction"]["status"], "rolled_back");
            assert_eq!(faults.state, original.normalized());
        } else {
            assert_eq!(faults.apply_count, applies);
        }
    }
}

#[test]
fn udp_relay_api_authorization_persistence_and_rollback() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut candidate = config();
    candidate.interfaces[0].kind = "ethernet".into();
    let mut second = candidate.interfaces[0].clone();
    second.name = "iot0".into();
    second.addresses = vec!["198.51.100.1/24".into()];
    candidate.interfaces.push(second);
    candidate.udp_broadcast_relay = serde_json::from_value(json!({"enabled":true,"instances":[{"id":1,"enabled":true,"port":4001,"interfaces":["lan0","iot0"],"multicast_address":"239.255.255.250"}]})).unwrap();
    let mut permissions = all();
    permissions.retain(|permission| permission != "udp_broadcast_relay.write");
    let forbidden = engine.request(
        "POST",
        "/api/v1/transactions",
        "",
        "operator",
        &permissions,
        &serde_json::to_vec(
            &json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,"config":candidate}),
        )
        .unwrap(),
    );
    assert_eq!(forbidden.status, 403);
    let transaction = submit(&mut engine, candidate.clone());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    let id = transaction.body["id"].as_str().unwrap();
    assert_eq!(confirm(&mut engine, id).status, 200);
    let status = request(
        &mut engine,
        "GET",
        "/api/v1/services/udp-broadcast-relay/status",
        Value::Null,
    );
    assert_eq!(status.status, 200);
    assert_eq!(status.body["instances"][0]["state"], "simulated");
    assert_eq!(status.body["instances"][0]["port"], 4001);
    assert_eq!(
        request(
            &mut engine,
            "GET",
            "/api/v1/services/udp-broadcast-relay",
            Value::Null
        )
        .body["enabled"],
        true
    );
    assert_eq!(
        engine
            .request(
                "GET",
                "/api/v1/services/udp-broadcast-relay/status",
                "extra=1",
                "operator",
                &all(),
                &[]
            )
            .status,
        400
    );
    let mut disabled = candidate.clone();
    disabled.udp_broadcast_relay.enabled = false;
    let transaction = submit(&mut engine, disabled);
    assert_eq!(transaction.status, 202);
    let id = transaction.body["id"].as_str().unwrap();
    assert_eq!(
        request(
            &mut engine,
            "POST",
            &format!("/api/v1/transactions/{id}/rollback"),
            Value::Null
        )
        .status,
        200
    );
    assert!(engine.saved_configuration().udp_broadcast_relay.enabled);
    drop(engine);
    let mut reopened = fixture.engine();
    assert!(reopened.saved_configuration().udp_broadcast_relay.enabled);
    assert_eq!(
        request(
            &mut reopened,
            "GET",
            "/api/v1/services/udp-broadcast-relay",
            Value::Null
        )
        .body["instances"][0]["id"],
        1
    );
}

#[test]
fn bgp_advertised_api_returns_the_session_inventory_not_received_routes() {
    let fixture = Fixture::new();
    let advertised = json!([{"prefix":"203.0.113.0/24","neighbor":"edge","interface":"wan0","next_hop":"192.0.2.1","source":"bgp"}]);
    let received = json!([{"prefix":"198.51.100.0/24","neighbor":"edge"}]);
    let faults = Arc::new(Mutex::new(Faults {
        bgp_response: Some(json!({"scope":"fault-test","state":"running","error":null,
            "routes":received,"advertised_routes":advertised,"connected_prefixes":["203.0.113.0/24","192.0.2.0/24"]})),
        ..Default::default()
    }));
    let mut engine = Engine::open(&fixture.path(), Box::new(FaultBackend(faults))).unwrap();
    let response = request(
        &mut engine,
        "GET",
        "/api/v1/routes/bgp/advertised",
        Value::Null,
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body,
        json!({"source":"bgp","scope":"fault-test","state":"running","error":null,"routes":advertised})
    );
    assert_eq!(
        request(&mut engine, "GET", "/api/v1/routes/bgp", Value::Null).body["routes"],
        received
    );
    let summary = request(
        &mut engine,
        "GET",
        "/api/v1/services/bgp/status",
        Value::Null,
    );
    assert!(summary.body.get("routes").is_none());
    assert!(summary.body.get("advertised_routes").is_none());
}

#[test]
fn bgp_api_permissions_transactions_restart_and_route_visibility() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut candidate = config();
    candidate.bgp=serde_json::from_value(json!({"enabled":true,"local_asn":65001,"router_id":"192.0.2.1",
        "neighbors":[{"name":"edge","interface":"lan0","local_address":"192.0.2.1","address":"192.0.2.2","remote_asn":65002}]})).unwrap();
    let transaction = submit(&mut engine, candidate.clone());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    assert_eq!(
        confirm(&mut engine, transaction.body["id"].as_str().unwrap()).status,
        200
    );
    for path in [
        "/api/v1/services/bgp",
        "/api/v1/services/bgp/status",
        "/api/v1/routes/bgp",
        "/api/v1/routes/bgp/advertised",
    ] {
        let response = engine.request("GET", path, "", "reader", &["state.read".into()], &[]);
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(
            engine
                .request("GET", path, "x=1", "reader", &["state.read".into()], &[])
                .status,
            400
        );
        assert_eq!(
            engine.request("GET", path, "", "reader", &[], &[]).status,
            403
        );
        assert_eq!(
            engine
                .request("POST", path, "", "reader", &["state.read".into()], b"{}")
                .status,
            405
        );
    }
    let routes = request(&mut engine, "GET", "/api/v1/routes/bgp", Value::Null);
    assert_eq!(routes.body["source"], "bgp");
    assert_eq!(routes.body["state"], "simulated");
    assert_eq!(routes.body["routes"], json!([]));
    let advertised = request(
        &mut engine,
        "GET",
        "/api/v1/routes/bgp/advertised",
        Value::Null,
    );
    assert_eq!(advertised.body["source"], "bgp");
    assert_eq!(advertised.body["state"], "simulated");
    assert_eq!(advertised.body["routes"], json!([]));
    let summary = request(
        &mut engine,
        "GET",
        "/api/v1/services/bgp/status",
        Value::Null,
    );
    assert!(summary.body.get("routes").is_none());
    assert!(summary.body.get("advertised_routes").is_none());
    assert_eq!(engine.restart_process("bgp").body["status"], "simulated");
    assert_eq!(engine.committed_revision(), test_revision(1));
    let stats = request(&mut engine, "GET", "/api/v1/statistics", Value::Null);
    assert_eq!(stats.body["bgp"]["state"], "simulated");
    let mut no_bgp = all();
    no_bgp.retain(|p| p != "bgp.write");
    candidate.bgp.keepalive_seconds = 20;
    let response=engine.request("POST","/api/v1/transactions","","operator",&no_bgp,
        &serde_json::to_vec(&json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"description":"BGP timers","config":candidate})).unwrap());
    assert_eq!(response.status, 403, "{}", response.body);
}

#[test]
fn destination_rewrite_permissions_persistence_and_rollback() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut initial = config();
    initial.interfaces.push(
        serde_json::from_value(json!({
            "name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,
            "addresses":["198.51.100.1/24"]
        }))
        .unwrap(),
    );
    let transaction = submit(&mut engine, initial.clone());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    assert_eq!(
        confirm(&mut engine, transaction.body["id"].as_str().unwrap()).status,
        200
    );
    let mut rewritten = initial.clone();
    rewritten.firewall.nat.destination_rewrite.push(
        serde_json::from_value(json!({
            "out_interface":"wan0","protocol":"udp","destination_port":53,
            "target_interface":"lan0","target_address":"192.0.2.53",
            "metadata":{"display_name":"Local DNS","description":"Forwarded UDP DNS"}
        }))
        .unwrap(),
    );
    let limited: Vec<_> = all().into_iter().filter(|p| p != "nat.write").collect();
    let body = serde_json::to_vec(
        &json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":rewritten}),
    )
    .unwrap();
    assert_eq!(
        engine
            .request(
                "POST",
                "/api/v1/transactions",
                "",
                "limited",
                &limited,
                &body
            )
            .status,
        403
    );
    let mut invalid = rewritten.clone();
    invalid.firewall.nat.destination_rewrite[0].target_address = "203.0.113.53".into();
    assert_eq!(submit(&mut engine, invalid).status, 422);
    let transaction = submit(&mut engine, rewritten.clone());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    let id = transaction.body["id"].as_str().unwrap();
    assert_eq!(
        engine
            .request(
                "POST",
                &format!("/api/v1/transactions/{id}/confirm"),
                "",
                "limited",
                &limited,
                &[]
            )
            .status,
        403
    );
    assert_eq!(confirm(&mut engine, id).status, 200);
    let nat = request(&mut engine, "GET", "/api/v1/firewall/nat", Value::Null);
    assert_eq!(nat.status, 200);
    assert_eq!(
        nat.body["destination_rewrite"][0]["target_address"],
        "192.0.2.53"
    );
    drop(engine);
    let mut engine = Engine::open(
        &fixture.path(),
        Box::new(Simulator::with_config(rewritten.clone()).unwrap()),
    )
    .unwrap();
    assert_eq!(engine.saved_configuration(), &rewritten);
    let transaction = submit(&mut engine, initial);
    assert_eq!(transaction.status, 202);
    assert_eq!(
        request(
            &mut engine,
            "POST",
            &format!(
                "/api/v1/transactions/{}/rollback",
                transaction.body["id"].as_str().unwrap()
            ),
            Value::Null
        )
        .status,
        200
    );
    assert_eq!(engine.saved_configuration(), &rewritten);
    let mut metadata = rewritten.clone();
    metadata.firewall.nat.destination_rewrite[0]
        .metadata
        .description = "Updated description".into();
    assert_eq!(
        metadata.operational_value().unwrap(),
        rewritten.operational_value().unwrap()
    );
    let body = serde_json::to_vec(
        &json!({"base_revision":test_revision(2),"confirm_timeout_seconds":30,"config":metadata}),
    )
    .unwrap();
    assert_eq!(
        engine
            .request(
                "POST",
                "/api/v1/transactions",
                "",
                "limited",
                &limited,
                &body
            )
            .status,
        403
    );
}

#[test]
fn operational_restarts_do_not_change_revision_and_reject_pending_transactions() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let reply = engine.restart_process("link-diagnostics");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["status"], "simulated");
    assert_eq!(engine.committed_revision(), test_revision(0));
    assert_eq!(engine.restart_process("ntp").status, 409);
    assert_eq!(engine.restart_process("flow:missing").status, 404);
    let transaction = submit(&mut engine, config());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    assert!(engine.begin_restart().is_err());
    assert_eq!(engine.restart_process("link-diagnostics").status, 409);
    let request: crate::DNSLookupRequest =
        serde_json::from_value(json!({"interface":"lan0","hostname":"example.test"})).unwrap();
    assert!(engine.prepare_dns_lookup(&request).is_err());
}

#[test]
fn link_diagnostics_are_read_only_scoped_and_never_fabricated_in_simulator() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let path = "/api/v1/statistics/link-diagnostics";
    let reply = engine.request("GET", path, "", "reader", &["state.read".into()], &[]);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["schema"], "netcontrol-link-diagnostics/v1");
    assert_eq!(reply.body["status"], "simulated");
    assert!(reply.body["local_tcp"].is_null());
    assert!(reply.body["packet_headers"].is_null());
    let aggregate = request(&mut engine, "GET", "/api/v1/statistics", Value::Null);
    assert_eq!(aggregate.body["link_diagnostics"], reply.body);
    assert_eq!(
        engine.request("GET", path, "", "reader", &[], &[]).status,
        403
    );
    assert_eq!(
        engine
            .request(
                "GET",
                path,
                "limit=1",
                "reader",
                &["state.read".into()],
                &[]
            )
            .status,
        400
    );
    assert_eq!(request(&mut engine, "POST", path, Value::Null).status, 405);
}

#[test]
fn dynamic_dns_permissions_references_confirmation_and_rollback() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let entry = crate::dynamic_dns::tests::entry();
    let mut candidate = config();
    let mut entry = entry;
    entry.source_interface = "lan0".into();
    candidate.dynamic_dns.push(entry.clone());
    assert_eq!(submit(&mut engine, candidate.clone()).status, 422);
    engine.configure_dynamic_dns(Some(BTreeSet::new()));
    assert_eq!(submit(&mut engine, candidate.clone()).status, 422);
    engine.configure_dynamic_dns(Some(BTreeSet::from([entry.secret_ref.clone()])));
    let mut before = candidate.clone();
    before.dynamic_dns.clear();
    let permissions: Vec<_> = all()
        .into_iter()
        .filter(|p| p != "dynamic_dns.write")
        .collect();
    assert_eq!(
        authorize(&permissions, &before, &candidate)
            .unwrap_err()
            .status,
        403
    );
    assert!(authorize(&all(), &before, &candidate).is_ok());
    let pending = submit(&mut engine, candidate.clone());
    assert_eq!(pending.status, 202, "{}", pending.body);
    assert!(engine.saved_configuration().dynamic_dns.is_empty());
    let id = pending.body["id"].as_str().unwrap();
    assert_eq!(
        request(
            &mut engine,
            "POST",
            &format!("/api/v1/transactions/{id}/rollback"),
            Value::Null
        )
        .status,
        200
    );
    assert!(engine.saved_configuration().dynamic_dns.is_empty());
    let pending = submit(&mut engine, candidate.clone());
    let id = pending.body["id"].as_str().unwrap();
    assert_eq!(confirm(&mut engine, id).status, 200);
    assert_eq!(
        engine.saved_configuration().dynamic_dns,
        candidate.dynamic_dns
    );
    let saved = serde_json::to_string(&engine.state).unwrap();
    assert!(!saved.contains("client_secret"));
    drop(engine);
    let engine = fixture.engine();
    assert_eq!(
        engine.saved_configuration().dynamic_dns,
        candidate.dynamic_dns
    );
}

#[test]
fn offline_conversion_validation_checks_history_and_refuses_active_transactions() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    validate_offline_state(&serde_json::to_vec(&engine.state).unwrap()).unwrap();
    let pending = submit(&mut engine, config());
    let id = pending.body["id"].as_str().unwrap();
    assert!(validate_offline_state(&serde_json::to_vec(&engine.state).unwrap()).is_err());
    confirm(&mut engine, id);
    validate_offline_state(&serde_json::to_vec(&engine.state).unwrap()).unwrap();
    engine.state.transactions.clear();
    assert!(validate_offline_state(&serde_json::to_vec(&engine.state).unwrap()).is_err());
}

#[test]
fn dhcp_gateway_monitor_saves_without_static_address_route_or_lease() {
    let value = json!({"interfaces":[{"name":"wan0","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":[]}],
        "dhcp_clients":{"wan0":{}},"gateway_monitors":[{"name":"wan","enabled":true,"mode":"dhcp","interface":"wan0","target":"1.1.1.1"}]});
    let config: Config = serde_json::from_value(value.clone()).unwrap();
    config.validate().unwrap();
    let normalized = config.normalized();
    let serialized = serde_json::to_value(&normalized).unwrap();
    assert!(
        serialized["gateway_monitors"][0]
            .get("source_address")
            .is_none()
    );
    assert!(serialized["gateway_monitors"][0].get("gateway").is_none());
    assert!(
        serialized["gateway_monitors"][0]
            .get("routing_table")
            .is_none()
    );
    let mut ipv4_only = normalized.clone();
    ipv4_only.ipv6_enabled = false;
    ipv4_only.validate().unwrap();
    for (field, invalid) in [
        ("source_address", json!("192.0.2.2")),
        ("gateway", json!("192.0.2.1")),
        ("routing_table", json!(254)),
        ("target", json!("2001:db8::1")),
        ("mode", json!("automatic")),
    ] {
        let mut bad = value.clone();
        bad["gateway_monitors"][0][field] = invalid;
        assert!(
            serde_json::from_value::<Config>(bad).map_or(true, |config| config.validate().is_err())
        );
    }
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let reply = submit(&mut engine, normalized.clone());
    assert_eq!(reply.status, 202, "{}", reply.body);
    let id = reply.body["id"].as_str().unwrap();
    assert_eq!(confirm(&mut engine, id).status, 200);
    let runtime = request(&mut engine, "GET", "/api/v1/runtime", Value::Null);
    assert_eq!(runtime.status, 200);
    assert_eq!(
        runtime.body["capabilities"]["gateway_monitor_modes"],
        json!(["explicit", "dhcp"])
    );
    assert_eq!(runtime.body["gateway_monitors"][0]["mode"], "dhcp");
    assert_eq!(runtime.body["gateway_monitors"][0]["health"], "unknown");
    drop(engine);
    let mut engine = Engine::open(
        &fixture.path(),
        Box::new(Simulator::with_config(normalized.clone()).unwrap()),
    )
    .unwrap();
    assert_eq!(engine.saved_configuration(), &normalized);
    let mut deleted = normalized.clone();
    deleted.gateway_monitors.clear();
    let reply = submit(&mut engine, deleted);
    assert_eq!(reply.status, 202);
    let id = reply.body["id"].as_str().unwrap();
    let rollback = request(
        &mut engine,
        "POST",
        &format!("/api/v1/transactions/{id}/rollback"),
        Value::Null,
    );
    assert_eq!(rollback.status, 200);
    assert_eq!(engine.saved_configuration(), &normalized);
}

#[test]
fn static_route_enabled_permission_restart_and_rollback() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut initial = serde_json::to_value(config()).unwrap();
    initial["routes"] =
        json!([{"destination":"203.0.113.0/24","interface":"lan0","table":10000,"metric":10}]);
    let reply = request(
        &mut engine,
        "POST",
        "/api/v1/transactions",
        json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,"config":initial.clone()}),
    );
    let initial: Config = serde_json::from_value(initial).unwrap();
    assert!(initial.routes[0].enabled);
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(
        confirm(&mut engine, reply.body["id"].as_str().unwrap()).status,
        200
    );
    let mut disabled = initial.clone();
    assert_eq!(
        request(&mut engine, "GET", "/api/v1/routes", Value::Null).body[0]["enabled"],
        true
    );
    disabled.routes[0].enabled = false;
    let permissions: Vec<_> = all().into_iter().filter(|p| p != "routes.write").collect();
    let body = serde_json::to_vec(
        &json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":disabled}),
    )
    .unwrap();
    assert_eq!(
        engine
            .request(
                "POST",
                "/api/v1/transactions",
                "",
                "limited",
                &permissions,
                &body
            )
            .status,
        403
    );
    let mut invalid = serde_json::to_value(&disabled).unwrap();
    invalid["routes"][0]["enabled"] = Value::Null;
    assert_eq!(
        request(
            &mut engine,
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":invalid})
        )
        .status,
        400
    );
    let reply = submit(&mut engine, disabled.clone());
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(
        confirm(&mut engine, reply.body["id"].as_str().unwrap()).status,
        200
    );
    assert_eq!(
        request(&mut engine, "GET", "/api/v1/routes", Value::Null).body[0]["enabled"],
        false
    );
    drop(engine);
    let mut engine = Engine::open(
        &fixture.path(),
        Box::new(Simulator::with_config(disabled.clone()).unwrap()),
    )
    .unwrap();
    assert_eq!(engine.saved_configuration(), &disabled);
    let reply = submit(&mut engine, initial);
    assert_eq!(reply.status, 202);
    let rollback = request(
        &mut engine,
        "POST",
        &format!(
            "/api/v1/transactions/{}/rollback",
            reply.body["id"].as_str().unwrap()
        ),
        Value::Null,
    );
    assert_eq!(rollback.status, 200);
    assert_eq!(engine.saved_configuration(), &disabled);
}

#[test]
fn global_ipv6_permission_commit_restart_and_rollback() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut disabled = Config::empty();
    disabled.ipv6_enabled = false;
    let reply = engine.request(
        "POST",
        "/api/v1/transactions",
        "",
        "limited",
        &["transactions.write".into()],
        &serde_json::to_vec(
            &json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,"config":disabled}),
        )
        .unwrap(),
    );
    assert_eq!(reply.status, 403);
    assert!(
        reply.body["error"]
            .as_str()
            .unwrap()
            .contains("kernel.namespace.write")
    );
    let reply = submit(&mut engine, disabled.clone());
    assert_eq!(reply.status, 202);
    let id = reply.body["id"].as_str().unwrap();
    assert_eq!(confirm(&mut engine, id).status, 200);
    assert!(!engine.saved_configuration().ipv6_enabled);
    drop(engine);
    let mut engine = Engine::open(
        &fixture.path(),
        Box::new(Simulator::with_config(disabled).unwrap()),
    )
    .unwrap();
    assert!(!engine.saved_configuration().ipv6_enabled);
    let reply = submit(&mut engine, Config::empty());
    assert_eq!(reply.status, 202);
    let id = reply.body["id"].as_str().unwrap();
    let rollback = request(
        &mut engine,
        "POST",
        &format!("/api/v1/transactions/{id}/rollback"),
        Value::Null,
    );
    assert_eq!(rollback.status, 200);
    assert!(!engine.saved_configuration().ipv6_enabled);
    let runtime = request(&mut engine, "GET", "/api/v1/runtime", Value::Null);
    assert_eq!(runtime.body["ipv6"]["enabled"], false);
    assert_eq!(runtime.body["ipv6"]["status"], "simulated");
}

#[test]
fn descriptive_metadata_requires_resource_permission_and_survives_reopen() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let initial = submit(&mut engine, config());
    assert_eq!(
        confirm(&mut engine, initial.body["id"].as_str().unwrap()).status,
        200
    );
    let mut described = engine.saved_configuration().clone();
    described.interfaces[0].metadata.display_name = "Office LAN".into();
    described.interfaces[0].metadata.description = "Operator notes".into();
    let body = serde_json::to_vec(
        &json!({"base_revision": test_revision(1), "confirm_timeout_seconds": 30, "config": described}),
    )
    .unwrap();
    assert_eq!(
        engine
            .request(
                "POST",
                "/api/v1/transactions",
                "",
                "restricted",
                &["transactions.write".into()],
                &body
            )
            .status,
        403
    );
    let transaction = submit(&mut engine, described.clone());
    assert_eq!(transaction.status, 202);
    assert_eq!(
        confirm(&mut engine, transaction.body["id"].as_str().unwrap()).status,
        200
    );
    engine.shutdown().unwrap();
    drop(engine);
    let mut engine = fixture.engine();
    assert_eq!(engine.saved_configuration(), &described.normalized());
    let state = request(&mut engine, "GET", "/api/v1/state", Value::Null);
    assert_eq!(state.status, 200);
    assert_eq!(
        state.body["desired"]["interfaces"][0]["metadata"]["display_name"],
        "Office LAN"
    );
    assert_eq!(
        state.body["observed"]["interfaces"][0]["metadata"]["display_name"],
        "Office LAN"
    );
}

#[test]
fn every_example_json_is_a_valid_current_transaction_request() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("workspace root")
        .to_path_buf();
    let mut files: Vec<_> = fs::read_dir(root.join("examples"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "example fixtures must exist");
    for path in files {
        let bytes = fs::read(&path).unwrap();
        let mut request: SubmitRequest =
            parse(&bytes).unwrap_or_else(|error| panic!("{}: {}", path.display(), error.error));
        request.config.normalize();
        request
            .config
            .validate()
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(
            (10..=300).contains(&request.confirm_timeout_seconds),
            "{}: invalid confirmation timeout",
            path.display()
        );
        assert!(
            request.description.trim().len() <= 1024,
            "{}: description exceeds limit",
            path.display()
        );
        assert_eq!(
            request.base_revision.to_string(),
            "2026.10.29.1",
            "{}: fresh-state fixture",
            path.display()
        );
    }
}

#[cfg(windows)]
#[test]
fn long_windows_state_paths_support_atomic_publication_and_restart() {
    let fixture = Fixture::new();
    let path = fixture
        .dir
        .join("a".repeat(80))
        .join("b".repeat(80))
        .join("state.json");
    assert!(
        std::env::current_dir()
            .unwrap()
            .join(&path)
            .as_os_str()
            .len()
            > 260
    );
    let mut engine = Engine::open(&path, Box::new(Simulator::new())).unwrap();
    let transaction = submit(&mut engine, config());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    let committed = confirm(&mut engine, transaction.body["id"].as_str().unwrap());
    assert_eq!(committed.status, 200, "{}", committed.body);
    drop(engine);
    let engine = Engine::open(&path, Box::new(Simulator::new())).unwrap();
    assert_eq!(engine.state.revision, test_revision(1));
    assert_eq!(engine.state.desired, config().normalized());
}

#[test]
fn persistent_envelope_shape_is_explicit_and_rust_only() {
    let fixture = Fixture::new();
    let _engine = fixture.engine();
    let envelope: Value = serde_json::from_slice(&fs::read(fixture.path()).unwrap()).unwrap();
    let keys: BTreeSet<_> = envelope
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, BTreeSet::from(["schema", "sha256", "state"]));
    assert_eq!(envelope["schema"], "netcontrol-rust-state-v2");
    assert_eq!(envelope["sha256"].as_str().unwrap().len(), 64);
    let keys: BTreeSet<_> = envelope["state"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "scope",
            "revision",
            "initial_revision",
            "desired",
            "active_transaction",
            "initialized_at",
            "transactions"
        ])
    );
    assert!(envelope["state"]["active_transaction"].is_null());
    assert!(envelope["state"]["initialized_at"].is_string());
    assert_eq!(envelope["state"]["transactions"], json!({}));
}

#[test]
fn transaction_confirmation_history_restore_and_locations() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    assert_eq!(r.status, 202, "{}", r.body);
    let id = r.body["id"].as_str().unwrap().to_string();
    assert_eq!(r.location, Some(format!("/api/v1/transactions/{id}")));
    assert_eq!(r.body["status"], "pending_confirmation");
    assert_eq!(r.body["description"], "Update network");
    let state = request(&mut e, "GET", "/api/v1/state", Value::Null);
    assert_eq!(state.body["revision"], serde_json::json!(test_revision(0)));
    assert_eq!(state.body["desired"]["interfaces"], json!([]));
    assert_eq!(state.body["observed"]["interfaces"][0]["name"], "lan0");
    assert_eq!(state.body["drift"], false);
    assert_eq!(confirm(&mut e, &id).status, 200);
    assert_eq!(e.state.revision, test_revision(1));
    assert_eq!(confirm(&mut e, &id).status, 200);
    assert_eq!(e.state.revision, test_revision(1));
    let list = request(&mut e, "GET", "/api/v1/revisions", Value::Null);
    assert_eq!(list.body["revisions"].as_array().unwrap().len(), 2);
    assert_eq!(list.body["revisions"][0]["current"], true);
    let revision = request(
        &mut e,
        "GET",
        &format!("/api/v1/revisions/{}", test_revision(1)),
        Value::Null,
    );
    assert_eq!(revision.body["config"], json!(config().normalized()));
    let restore = request(
        &mut e,
        "POST",
        &format!("/api/v1/revisions/{}/restore", test_revision(0)),
        json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30}),
    );
    assert_eq!(restore.status, 202, "{}", restore.body);
    assert_eq!(
        restore.body["restored_from_revision"],
        serde_json::json!(test_revision(0))
    );
    let restored_id = restore.body["id"].as_str().unwrap();
    assert_eq!(confirm(&mut e, restored_id).status, 200);
    assert_eq!(e.state.revision, test_revision(2));
    assert_eq!(e.state.desired, Config::empty());
    drop(e);
    let e = f.engine();
    assert_eq!(e.state.revision, test_revision(2));
}
#[test]
fn pending_confirmation_survives_restart_and_expiry_rolls_back() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap().to_string();
    drop(e);
    let mut e = f.engine();
    assert_eq!(e.active().unwrap().id, id);
    assert_eq!(e.expected(), config().normalized());
    e.now = Some(e.active().unwrap().confirmation_deadline);
    e.tick().unwrap();
    assert!(e.active().is_none());
    assert_eq!(e.state.transactions[&id].status, "rolled_back");
    assert_eq!(
        e.backend.observe(&Config::empty()).unwrap(),
        Config::empty()
    );
    drop(e);
    assert!(f.engine().active().is_none());
}
#[test]
fn startup_recovers_applying_rolling_back_and_recovery_failed() {
    for status in ["applying", "rolling_back", "recovery_failed"] {
        let f = Fixture::new();
        let mut e = f.engine();
        let r = submit(&mut e, config());
        let id = r.body["id"].as_str().unwrap().to_string();
        e.state.transactions.get_mut(&id).unwrap().status = status.into();
        e.store.save(&e.state).unwrap();
        drop(e);
        let e = f.engine();
        assert_eq!(e.state.transactions[&id].status, "rolled_back");
        assert!(e.active().is_none());
    }
}
#[test]
fn startup_recovers_expired_pending_confirmation() {
    let f = Fixture::new();
    let mut e = f.engine();
    // Keep the empty archive consistent when backdating across a UTC day boundary.
    e.state.initialized_at = Utc::now() - Duration::hours(26);
    e.state.initial_revision = Version::first(e.state.initialized_at.date_naive()).unwrap();
    e.state.revision = e.state.initial_revision;
    e.store.save(&e.state).unwrap();
    e.now = Some(e.state.initialized_at + Duration::hours(1));
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap().to_string();
    drop(e);
    let e = f.engine();
    assert_eq!(e.state.transactions[&id].status, "rolled_back");
}
#[test]
fn rollback_is_idempotent_and_does_not_advance_revision() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap();
    let path = format!("/api/v1/transactions/{id}/rollback");
    assert_eq!(request(&mut e, "POST", &path, Value::Null).status, 200);
    assert_eq!(request(&mut e, "POST", &path, Value::Null).status, 200);
    assert_eq!(e.state.revision, test_revision(0));
    assert_eq!(confirm(&mut e, id).status, 409);
}
#[test]
fn confirmation_at_deadline_is_rejected_and_reverted() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap();
    e.now = Some(e.active().unwrap().confirmation_deadline);
    let r = confirm(&mut e, id);
    assert_eq!(r.status, 409);
    assert_eq!(r.body["transaction"]["status"], "rolled_back");
}
#[derive(Default)]
struct Faults {
    bgp_response: Option<Value>,
    connection_flushes: usize,
    connection_targets: Vec<Option<(u32, crate::ConnectionTarget)>>,
    missing_connection: bool,
    fail_connection_flush: bool,
    dhcp_retries: Vec<String>,
    fail_dhcp_retry: bool,
    state: Config,
    initial_count: usize,
    fail_applies: usize,
    contextual_apply_error: bool,
    apply_count: usize,
    fail_observe: bool,
    typed_network_drift: bool,
    worker_failed: bool,
    repair_count: usize,
    post_apply_drift: bool,
    traffic_response: Option<Value>,
    traffic_error: Option<String>,
    statistics_calls: Vec<(String, String)>,
    discovery_error: bool,
    discovery_calls: usize,
}
struct FaultBackend(Arc<Mutex<Faults>>);
impl Backend for FaultBackend {
    fn bgp_status(&mut self, _: &Config) -> Result<Value> {
        self.0
            .lock()
            .unwrap()
            .bgp_response
            .clone()
            .ok_or_else(|| anyhow::anyhow!("BGP test snapshot unavailable"))
    }
    fn delete_connections(
        &mut self,
        target: Option<(u32, &crate::ConnectionTarget)>,
    ) -> Result<Value> {
        let mut faults = self.0.lock().unwrap();
        faults.connection_flushes += 1;
        faults
            .connection_targets
            .push(target.map(|(id, target)| (id, target.clone())));
        if faults.missing_connection {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        ensure!(
            !faults.fail_connection_flush,
            "injected connection flush failure; outcome may be partial"
        );
        Ok(json!({"status":"flushed","scope":"fault-test"}))
    }
    fn retry_dhcp(&mut self, _: &Config, interface: &str) -> Result<()> {
        let mut faults = self.0.lock().unwrap();
        faults.dhcp_retries.push(interface.into());
        if faults.typed_network_drift {
            return Err(crate::BackendDrift("injected DHCP ownership drift".into()).into());
        }
        ensure!(!faults.fail_dhcp_retry, "injected DHCP retry failure");
        Ok(())
    }
    fn scope(&self) -> Result<String> {
        Ok("fault-test".into())
    }
    fn initial_configuration(&mut self) -> Result<Config> {
        self.0.lock().unwrap().initial_count += 1;
        Ok(Config::empty())
    }
    fn observe(&mut self, _: &Config) -> Result<Config> {
        let f = self.0.lock().unwrap();
        ensure!(!f.fail_observe, "injected observation error");
        ensure!(!f.worker_failed, "injected worker health error");
        Ok(f.state.clone())
    }
    fn discover_interfaces(&mut self) -> Result<Value> {
        let mut f = self.0.lock().unwrap();
        f.discovery_calls += 1;
        ensure!(!f.discovery_error, "injected discovery read failure");
        Ok(json!([{
            "name":"eth0","kind":"ethernet","index":2,"mac":"02:00:00:00:00:01",
            "mtu":1500,"up":true,"addresses":["192.0.2.10/24","fe80::1/64"],"ownership":"unmanaged"
        }, {
            "name":"lo","kind":"loopback","index":1,"mac":"00:00:00:00:00:00",
            "mtu":65536,"up":true,"addresses":["127.0.0.1/8","::1/128"],"ownership":"loopback"
        }]))
    }
    fn observe_for_repair(&mut self, _: &Config) -> Result<Config> {
        let f = self.0.lock().unwrap();
        if f.typed_network_drift {
            return Err(
                anyhow::Error::new(crate::BackendDrift("injected network drift".into()))
                    .context("verify repair ownership"),
            );
        }

        if f.fail_observe {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected observation error",
            )
            .into());
        }
        Ok(f.state.clone())
    }
    fn apply(&mut self, _: &Config, after: &Config) -> Result<()> {
        let mut f = self.0.lock().unwrap();
        f.apply_count += 1;
        f.state = after.clone();
        if f.fail_applies > 0 {
            f.fail_applies -= 1;
            if f.contextual_apply_error {
                return Err(anyhow::anyhow!("injected partial apply error")
                    .context("native apply failed; previous configuration restored"));
            }
            bail!("injected partial apply error");
        }
        if f.post_apply_drift {
            f.state.firewall.allow_all_icmp = !after.firewall.allow_all_icmp;
        }
        Ok(())
    }
    fn factory_reset(&mut self, before: &Config, after: &Config) -> Result<()> {
        self.apply(before, after)
    }
    fn runtime(&mut self, _: &Config) -> Result<Value> {
        Ok(json!({}))
    }
    fn statistics(&mut self, _: &Config, path: &str, query: &str) -> Result<Value> {
        let mut faults = self.0.lock().unwrap();
        faults.statistics_calls.push((path.into(), query.into()));
        if let Some(error) = &faults.traffic_error {
            bail!("{error}");
        }
        if let Some(response) = &faults.traffic_response {
            return Ok(response.clone());
        }
        bail!("unsupported test statistics")
    }
    fn repair(&mut self, c: &Config) -> Result<Value> {
        let mut faults = self.0.lock().unwrap();
        faults.state = c.clone();
        faults.worker_failed = false;
        faults.repair_count += 1;
        Ok(json!({}))
    }
}
#[test]
fn dhcp_retry_is_authorized_scoped_and_does_not_change_configuration() {
    let fixture = Fixture::new();
    let (mut engine, faults) = faulty(&fixture);
    let mut desired = config();
    desired.interfaces[0].kind = "ethernet".into();
    desired.interfaces[0].addresses.clear();
    desired
        .dhcp_clients
        .insert("lan0".into(), Default::default());
    let pending = submit(&mut engine, desired.clone());
    let path = "/api/v1/interfaces/lan0/dhcp/retry";
    assert_eq!(request(&mut engine, "POST", path, json!({})).status, 409);
    assert_eq!(
        confirm(&mut engine, pending.body["id"].as_str().unwrap()).status,
        200
    );
    let before = fs::read(fixture.path()).unwrap();
    let permission = vec!["interfaces.write".into()];
    assert_eq!(
        engine
            .request("POST", path, "", "operator", &["state.read".into()], &[])
            .status,
        403
    );
    assert_eq!(
        engine
            .request("POST", path, "", "", &permission, &[])
            .status,
        401
    );
    assert_eq!(
        engine
            .request("GET", path, "", "operator", &permission, &[])
            .status,
        405
    );
    assert_eq!(
        engine
            .request("POST", path, "unexpected=1", "operator", &permission, &[])
            .status,
        400
    );
    for body in [b"null".as_slice(), b"[]", b"{\"unknown\":true}"] {
        assert_eq!(
            engine
                .request("POST", path, "", "operator", &permission, body)
                .status,
            400
        );
    }
    assert_eq!(
        request(
            &mut engine,
            "POST",
            "/api/v1/interfaces/missing0/dhcp/retry",
            json!({})
        )
        .status,
        404
    );
    assert!(faults.lock().unwrap().dhcp_retries.is_empty());
    faults.lock().unwrap().fail_observe = true;
    let reply = engine.request("POST", path, "", "operator", &permission, &[]);
    assert_eq!(reply.status, 202);
    assert_eq!(
        reply.body,
        json!({"interface": "lan0", "status": "retrying"})
    );
    assert_eq!(faults.lock().unwrap().dhcp_retries, ["lan0"]);
    faults.lock().unwrap().fail_dhcp_retry = true;
    assert_eq!(
        engine
            .request("POST", path, "", "operator", &permission, b"{}")
            .status,
        503
    );
    faults.lock().unwrap().fail_dhcp_retry = false;
    faults.lock().unwrap().typed_network_drift = true;
    assert_eq!(
        engine
            .request("POST", path, "", "operator", &permission, &[])
            .status,
        409
    );
    assert_eq!(
        request(
            &mut engine,
            "POST",
            "/api/v1/interfaces/../dhcp/retry",
            json!({})
        )
        .status,
        400
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert_eq!(engine.saved_configuration(), &desired.normalized());
}

#[test]
fn connection_flush_requires_explicit_authorization_and_confirmation() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let before = fs::read(fixture.path()).unwrap();
    let path = "/api/v1/connections";
    let permissions = ["connections.delete".into()];
    let body = br#"{"confirm":true}"#;
    assert_eq!(
        engine
            .request("DELETE", path, "", "", &permissions, body)
            .status,
        401
    );
    for permission in ["state.read", "firewall.write", "transactions.write"] {
        assert_eq!(
            engine
                .request("DELETE", path, "", "operator", &[permission.into()], body)
                .status,
            403
        );
    }
    for method in ["GET", "PUT", "POST"] {
        assert_eq!(
            engine
                .request(method, path, "", "operator", &permissions, body)
                .status,
            405
        );
    }
    for invalid in [
        b"".as_slice(),
        b"{}",
        b"null",
        b"[]",
        br#"{"confirm":false}"#,
        br#"{"confirm":"true"}"#,
        br#"{"confirm":true,"family":"ipv4"}"#,
        br#"{"confirm":true,"confirm":true}"#,
    ] {
        assert_eq!(
            engine
                .request("DELETE", path, "", "operator", &permissions, invalid)
                .status,
            400
        );
    }
    assert_eq!(
        engine
            .request("DELETE", path, "limit=1", "operator", &permissions, body)
            .status,
        400
    );
    engine.set_upgrade_maintenance(true).unwrap();
    assert_eq!(
        engine
            .request("DELETE", path, "", "operator", &permissions, body)
            .status,
        409
    );
    engine.set_upgrade_maintenance(false).unwrap();
    assert_eq!(backend.lock().unwrap().connection_flushes, 0);
    backend.lock().unwrap().fail_observe = true;
    let reply = engine.request("DELETE", path, "", "operator", &permissions, body);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, json!({"status":"flushed","scope":"fault-test"}));
    backend.lock().unwrap().fail_connection_flush = true;
    let reply = engine.request("DELETE", path, "", "operator", &permissions, body);
    assert_eq!(reply.status, 503);
    assert!(reply.body["transaction"].is_null());
    assert_eq!(backend.lock().unwrap().connection_flushes, 2);
    assert_eq!(backend.lock().unwrap().apply_count, 0);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    backend.lock().unwrap().fail_observe = false;
    assert_eq!(submit(&mut engine, config()).status, 202);
    assert_eq!(
        engine
            .request("DELETE", path, "", "operator", &permissions, body)
            .status,
        409
    );
    assert_eq!(backend.lock().unwrap().connection_flushes, 2);
}

#[test]
fn simulator_connection_flush_is_explicitly_unsupported() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let reply = engine.request(
        "DELETE",
        "/api/v1/connections",
        "",
        "operator",
        &["connections.delete".into()],
        br#"{"confirm":true}"#,
    );
    assert_eq!(reply.status, 503);
    assert!(
        reply.body["error"]
            .as_str()
            .unwrap()
            .contains("not supported")
    );
}

#[test]
fn connection_delete_targets_id_tuple_and_zone_and_never_falls_back_to_flush() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let before = fs::read(fixture.path()).unwrap();
    let permissions = ["connections.delete".into()];
    let body = br#"{"family":"ipv4","protocol":6,"zone":7,"original":{"source":"192.0.2.2","destination":"198.51.100.2","source_port":50000,"destination_port":443}}"#;
    for path in [
        "/api/v1/connections/",
        "/api/v1/connections/01",
        "/api/v1/connections/-1",
        "/api/v1/connections/4294967296",
        "/api/v1/connections/1/extra",
        "/api/v1/connections/flush",
    ] {
        assert_eq!(
            engine
                .request("DELETE", path, "", "operator", &permissions, body)
                .status,
            400
        );
    }
    let path = "/api/v1/connections/123";
    for invalid in [b"".as_slice(),b"{}",br#"{"confirm":true}"#,br#"{"family":"ipv4","protocol":6,"zone":0,"original":{"source":"192.0.2.2","destination":"198.51.100.2"}}"#] {
        assert_eq!(engine.request("DELETE",path,"","operator",&permissions,invalid).status,400);
    }
    assert_eq!(
        engine
            .request("DELETE", path, "", "operator", &["state.read".into()], body)
            .status,
        403
    );
    assert_eq!(backend.lock().unwrap().connection_flushes, 0);
    let result = engine.request("DELETE", path, "", "operator", &permissions, body);
    assert_eq!(result.status, 200);
    let expected: crate::ConnectionTarget = serde_json::from_slice(body).unwrap();
    assert_eq!(
        backend.lock().unwrap().connection_targets,
        vec![Some((123, expected))]
    );
    backend.lock().unwrap().missing_connection = true;
    assert_eq!(
        engine
            .request("DELETE", path, "", "operator", &permissions, body)
            .status,
        404
    );
    assert!(
        backend
            .lock()
            .unwrap()
            .connection_targets
            .iter()
            .all(Option::is_some)
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
}

#[test]
fn dhcp_retry_rejects_down_or_unconfigured_interfaces() {
    for configured in [false, true] {
        let fixture = Fixture::new();
        let (mut engine, faults) = faulty(&fixture);
        let mut desired = config();
        desired.interfaces[0].kind = "ethernet".into();
        if configured {
            desired.interfaces[0].addresses.clear();
            desired.interfaces[0].up = false;
            desired
                .dhcp_clients
                .insert("lan0".into(), Default::default());
        }
        let pending = submit(&mut engine, desired);
        assert_eq!(
            confirm(&mut engine, pending.body["id"].as_str().unwrap()).status,
            200
        );
        assert_eq!(
            request(
                &mut engine,
                "POST",
                "/api/v1/interfaces/lan0/dhcp/retry",
                json!({})
            )
            .status,
            409
        );
        assert!(faults.lock().unwrap().dhcp_retries.is_empty());
    }
}

#[test]
fn saved_startup_never_initializes_or_recaptures_an_empty_journal() {
    let fixture = Fixture::new();
    assert!(Engine::open_saved(&fixture.path(), Box::new(Simulator::new())).is_err());
    assert!(!fixture.path().exists());
    let (engine, faults) = faulty(&fixture);
    let initial_count = faults.lock().unwrap().initial_count;
    drop(engine);
    let engine =
        Engine::open_saved(&fixture.path(), Box::new(FaultBackend(faults.clone()))).unwrap();
    assert_eq!(faults.lock().unwrap().initial_count, initial_count);
    assert_eq!(engine.state.desired, Config::empty());
}

#[test]
fn explicit_factory_reset_replaces_saved_configuration_without_pre_reset_repair() {
    let fixture = Fixture::new();
    let (mut engine, faults) = faulty(&fixture);
    let transaction = submit(&mut engine, config());
    assert_eq!(
        confirm(&mut engine, transaction.body["id"].as_str().unwrap()).status,
        200
    );
    drop(engine);
    let repairs = faults.lock().unwrap().repair_count;
    faults.lock().unwrap().state = Config::empty();
    let mut engine =
        Engine::open_for_factory_reset(&fixture.path(), Box::new(FaultBackend(faults.clone())))
            .unwrap();
    assert_eq!(faults.lock().unwrap().repair_count, repairs);
    faults.lock().unwrap().fail_observe = true;
    assert_eq!(
        request(&mut engine, "GET", "/api/v1/state", Value::Null).status,
        503
    );
    assert_eq!(engine.saved_configuration(), &config().normalized());
    faults.lock().unwrap().fail_observe = false;
    let reset = engine.factory_reset(Config::empty()).unwrap();
    assert_eq!(reset.status, "committed");
    assert_eq!(reset.actor, "local-factory-reset");
    assert_eq!(engine.state.desired, Config::empty());
    assert_eq!(engine.state.revision, test_revision(2));
    assert!(engine.state.active_transaction.is_none());
    assert_eq!(engine.state.transactions.len(), 2);
    engine.shutdown().unwrap();
    assert!(engine.factory_reset(Config::empty()).is_err());
}

#[test]
fn failed_factory_reset_rolls_back_and_active_transactions_block_reset() {
    let fixture = Fixture::new();
    let (mut engine, faults) = faulty(&fixture);
    let transaction = submit(&mut engine, config());
    assert!(engine.factory_reset(Config::empty()).is_err());
    assert_eq!(
        confirm(&mut engine, transaction.body["id"].as_str().unwrap()).status,
        200
    );
    faults.lock().unwrap().fail_applies = 1;
    assert!(engine.factory_reset(Config::empty()).is_err());
    assert_eq!(engine.state.desired, config().normalized());
    assert_eq!(engine.state.revision, test_revision(1));
    assert!(engine.state.active_transaction.is_none());
    assert_eq!(faults.lock().unwrap().state, config().normalized());
}

#[test]
fn interface_discovery_is_readonly_authorized_and_independent_of_observation() {
    let fixture = Fixture::new();
    let (mut engine, faults) = faulty(&fixture);
    faults.lock().unwrap().fail_observe = true;
    let reply = request(
        &mut engine,
        "GET",
        "/api/v1/interfaces/discovered",
        Value::Null,
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body.as_array().unwrap().len(), 2);
    assert_eq!(reply.body[0]["name"], "eth0");
    assert_eq!(reply.body[0]["ownership"], "unmanaged");
    assert_eq!(
        reply.body[0]["addresses"],
        json!(["192.0.2.10/24", "fe80::1/64"])
    );
    assert_eq!(reply.body[1]["name"], "lo");
    assert_eq!(reply.body[1]["kind"], "loopback");
    assert_eq!(reply.body[1]["ownership"], "loopback");
    assert_eq!(
        reply.body[1]["addresses"],
        json!(["127.0.0.1/8", "::1/128"])
    );
    assert_eq!(faults.lock().unwrap().apply_count, 0);
    assert_eq!(engine.state.revision, test_revision(0));
    assert!(engine.state.desired.interfaces.is_empty());
    let calls = faults.lock().unwrap().discovery_calls;
    assert_eq!(
        engine
            .request(
                "GET",
                "/api/v1/interfaces/discovered",
                "",
                "readonly",
                &[],
                &[]
            )
            .status,
        403
    );
    assert_eq!(
        engine
            .request("GET", "/api/v1/interfaces/discovered", "", "", &all(), &[])
            .status,
        401
    );
    assert_eq!(
        engine
            .request(
                "GET",
                "/api/v1/interfaces/discovered",
                "unexpected=1",
                "operator",
                &all(),
                &[]
            )
            .status,
        400
    );
    assert_eq!(
        request(
            &mut engine,
            "POST",
            "/api/v1/interfaces/discovered",
            Value::Null
        )
        .status,
        405
    );
    assert_eq!(faults.lock().unwrap().discovery_calls, calls);
    faults.lock().unwrap().discovery_error = true;
    let reply = request(
        &mut engine,
        "GET",
        "/api/v1/interfaces/discovered",
        Value::Null,
    );
    assert_eq!(reply.status, 503);
    assert!(
        reply.body["error"]
            .as_str()
            .unwrap()
            .contains("injected discovery read failure")
    );
}

fn faulty(f: &Fixture) -> (Engine, Arc<Mutex<Faults>>) {
    let state = Arc::new(Mutex::new(Faults::default()));
    let e = Engine::open(&f.path(), Box::new(FaultBackend(state.clone()))).unwrap();
    (e, state)
}
#[test]
fn apply_failure_rolls_back_and_returns_transaction() {
    let f = Fixture::new();
    let (mut e, faults) = faulty(&f);
    faults.lock().unwrap().fail_applies = 1;
    let r = submit(&mut e, config());
    assert_eq!(r.status, 500);
    assert_eq!(r.body["transaction"]["status"], "rolled_back");
    assert_eq!(faults.lock().unwrap().state, Config::empty());
    assert!(e.active().is_none());
}
#[test]
fn contextual_apply_failure_preserves_cause_in_response_and_durable_transaction() {
    for fail_applies in [1, 2] {
        let f = Fixture::new();
        let (mut e, faults) = faulty(&f);
        {
            let mut faults = faults.lock().unwrap();
            faults.fail_applies = fail_applies;
            faults.contextual_apply_error = true;
        }
        let r = submit(&mut e, config());
        assert_eq!(r.status, 500);
        let status = if fail_applies == 1 {
            "rolled_back"
        } else {
            "recovery_failed"
        };
        assert_eq!(r.body["transaction"]["status"], status);
        let cause =
            "native apply failed; previous configuration restored: injected partial apply error";
        for error in [&r.body["error"], &r.body["transaction"]["error"]] {
            assert!(error.as_str().unwrap().contains(cause), "{error}");
            if fail_applies == 2 {
                assert_eq!(error.as_str().unwrap().matches(cause).count(), 2);
            }
        }
        let saved: State = e.store.load().unwrap().unwrap();
        let id = r.body["transaction"]["id"].as_str().unwrap();
        assert_eq!(saved.transactions[id].error, r.body["transaction"]["error"]);
        assert_eq!(saved.transactions[id].status, status);
    }
}
#[test]
fn failed_recovery_blocks_writes_and_manual_retry_succeeds() {
    let f = Fixture::new();
    let (mut e, faults) = faulty(&f);
    faults.lock().unwrap().fail_applies = 2;
    let r = submit(&mut e, config());
    assert_eq!(r.status, 500);
    assert_eq!(r.body["transaction"]["status"], "recovery_failed");
    let id = r.body["transaction"]["id"].as_str().unwrap();
    assert_eq!(submit(&mut e, config()).status, 409);
    let r = request(
        &mut e,
        "POST",
        &format!("/api/v1/transactions/{id}/rollback"),
        Value::Null,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(e.active().is_none());
}
#[test]
fn intent_is_durable_before_backend_changes() {
    let f = Fixture::new();
    let (mut e, faults) = faulty(&f);
    e.store.fail_after.set(Some(0));
    let r = submit(&mut e, config());
    assert_eq!(r.status, 500);
    assert_eq!(faults.lock().unwrap().apply_count, 0);
    assert!(e.state.transactions.is_empty());
    assert!(
        e.store
            .load::<State>()
            .unwrap()
            .unwrap()
            .transactions
            .is_empty()
    );
}
#[test]
fn pending_save_failure_triggers_rollback() {
    let f = Fixture::new();
    let mut e = f.engine();
    e.store.fail_after.set(Some(1));
    let r = submit(&mut e, config());
    assert_eq!(r.status, 500);
    assert_eq!(r.body["transaction"]["status"], "rolled_back");
    assert!(e.active().is_none());
    assert_eq!(e.state.revision, test_revision(0));
}
#[test]
fn failed_confirmation_save_preserves_pending_and_is_retryable() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap();
    e.store.fail_after.set(Some(0));
    assert_eq!(confirm(&mut e, id).status, 500);
    assert_eq!(e.state.revision, test_revision(0));
    assert_eq!(e.active().unwrap().status, "pending_confirmation");
    assert_eq!(confirm(&mut e, id).status, 200);
    assert_eq!(e.state.revision, test_revision(1));
}
#[test]
fn failed_rollback_result_save_keeps_durable_recovery_intent() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap().to_string();
    e.store.fail_after.set(Some(1));
    assert!(e.rollback(&id, "test").is_err());
    assert_eq!(e.active().unwrap().status, "recovery_failed");
    let durable = e.store.load::<State>().unwrap().unwrap();
    assert_eq!(durable.transactions[&id].status, "rolling_back");
    drop(e);
    let e = f.engine();
    assert_eq!(e.state.transactions[&id].status, "rolled_back");
}
#[test]
fn drift_blocks_submit_and_confirmation() {
    let f = Fixture::new();
    let (mut e, faults) = faulty(&f);
    faults.lock().unwrap().state.firewall.allow_all_icmp = false;
    let r = request(&mut e, "GET", "/api/v1/state", Value::Null);
    assert_eq!(r.body["drift"], true);
    assert_eq!(submit(&mut e, config()).status, 409);
    faults.lock().unwrap().state = Config::empty();
    let r = submit(&mut e, config());
    assert_eq!(r.status, 202, "{}", r.body);
    let id = r.body["id"].as_str().unwrap();
    faults.lock().unwrap().state.firewall.allow_all_icmp = false;
    assert_eq!(confirm(&mut e, id).status, 409);
    assert_eq!(e.state.revision, test_revision(0));
    assert!(e.active().is_some());
}
#[test]
fn post_apply_verification_mismatch_never_becomes_pending() {
    let f = Fixture::new();
    let (mut e, faults) = faulty(&f);
    faults.lock().unwrap().post_apply_drift = true;
    let r = submit(&mut e, config());
    assert_eq!(r.status, 500);
    assert_ne!(r.body["transaction"]["status"], "pending_confirmation");
}
#[test]
fn state_lock_contention_and_release() {
    let f = Fixture::new();
    let e = f.engine();
    assert!(Engine::open(&f.path(), Box::new(Simulator::new())).is_err());
    drop(e);
    f.engine();
}
#[test]
fn corrupt_and_incompatible_journals_are_never_reset() {
    for bytes in [
        b"".as_slice(),
        b"{bad",
        b"{}",
        br#"{"scope":"simulator","revision":0,"desired":{},"transactions":{}}"#,
        br#"{"schema":"foreign","sha256":"","state":{}}"#,
    ] {
        let f = Fixture::new();
        fs::write(f.path(), bytes).unwrap();
        assert!(Engine::open(&f.path(), Box::new(Simulator::new())).is_err());
        assert_eq!(fs::read(f.path()).unwrap(), bytes);
    }
    let f = Fixture::new();
    let e = f.engine();
    drop(e);
    let mut bytes = fs::read(f.path()).unwrap();
    let offset = bytes.iter().position(|b| *b == b'0').unwrap();
    bytes[offset] = b'1';
    fs::write(f.path(), &bytes).unwrap();
    assert!(Engine::open(&f.path(), Box::new(Simulator::new())).is_err());
    assert_eq!(fs::read(f.path()).unwrap(), bytes);
}
#[test]
fn typed_history_and_active_pointer_integrity_are_checked() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap();
    confirm(&mut e, id);
    let original = e.state.clone();
    e.state.transactions.clear();
    e.store.save(&e.state).unwrap();
    drop(e);
    assert!(Engine::open(&f.path(), Box::new(Simulator::new())).is_err());
    let store = Store::open(&f.path()).unwrap();
    let mut state = original;
    state.active_transaction = Some("missing".into());
    store.save(&state).unwrap();
    drop(store);
    assert!(Engine::open(&f.path(), Box::new(Simulator::new())).is_err());
}
#[test]
fn stale_base_active_conflicts_and_invalid_timeout_have_exact_statuses() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = request(
        &mut e,
        "POST",
        "/api/v1/transactions",
        json!({"base_revision":test_revision(9),"confirm_timeout_seconds":30,"config":{}}),
    );
    assert_eq!(r.status, 409);
    for timeout in [0, 9, 301] {
        let r = request(
            &mut e,
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":test_revision(0),"confirm_timeout_seconds":timeout,"config":{}}),
        );
        assert_eq!(r.status, 422);
    }
    let r = submit(&mut e, config());
    assert_eq!(r.status, 202);
    assert_eq!(submit(&mut e, config()).status, 409);
}
#[test]
fn strict_json_validation_and_body_limits() {
    let f = Fixture::new();
    let mut e = f.engine();
    for body in [
        br#"{"config":{},"confirm_timeout_seconds":30,"unknown":1}"#.as_slice(),
        br#"{"config":{},"confirm_timeout_seconds":30}{}"#,
        b"null",
        b"[]",
        b"",
    ] {
        assert_eq!(
            e.request("POST", "/api/v1/transactions", "", "operator", &all(), body)
                .status,
            400
        );
    }
    assert_eq!(
        e.request(
            "POST",
            "/api/v1/transactions",
            "",
            "operator",
            &all(),
            &vec![b' '; (1 << 20) + 1]
        )
        .status,
        400
    );
}
#[test]
fn fine_grained_permissions_cover_confirmation_and_restore() {
    let f = Fixture::new();
    let mut e = f.engine();
    let c = config();
    let body = serde_json::to_vec(
        &json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,"config":c}),
    )
    .unwrap();
    let writer = vec!["transactions.write".into()];
    assert_eq!(
        e.request("POST", "/api/v1/transactions", "", "writer", &writer, &body)
            .status,
        403
    );
    let iface = vec!["transactions.write".into(), "interfaces.write".into()];
    let r = e.request("POST", "/api/v1/transactions", "", "writer", &iface, &body);
    assert_eq!(r.status, 202);
    let id = r.body["id"].as_str().unwrap();
    assert_eq!(
        e.request(
            "POST",
            &format!("/api/v1/transactions/{id}/confirm"),
            "",
            "writer",
            &writer,
            &[]
        )
        .status,
        403
    );
    assert_eq!(confirm(&mut e, id).status, 200);
    let r = e.request(
        "POST",
        &format!("/api/v1/revisions/{}/restore", test_revision(0)),
        "",
        "writer",
        &iface,
        &serde_json::to_vec(
            &json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30}),
        )
        .unwrap(),
    );
    assert_eq!(r.status, 403);
    assert_eq!(
        e.request("GET", "/api/v1/state", "", "writer", &writer, &[])
            .status,
        403
    );
    assert_eq!(
        e.request("GET", "/api/v1/state", "", "", &all(), &[])
            .status,
        401
    );
}
#[test]
fn sando_import_state_and_firewall_changes_confirm_rollback_and_reopen_together() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let initial = engine.committed_revision();
    let mut candidate = config();
    candidate.sando = serde_json::from_value(json!({
        "api_url":"http://sando.example.invalid:8044",
        "sync_enabled":true,
        "hosts_import":{
            "source_url":"http://sando.example.invalid:8044",
            "import_count":1,"last_import_at":"2026-10-30T00:00:00Z",
            "status":"succeeded","imported_count":1,"skipped_count":0
        },
        "rules_import":{
            "source_url":"http://sando.example.invalid:8044",
            "import_count":2,"last_import_at":"2026-10-30T00:01:00Z",
            "status":"partial","imported_count":1,"skipped_count":2
        }
    }))
    .unwrap();
    candidate.firewall.policies = Some(serde_json::from_value(json!({
        "hosts":[{
            "id":"sando-device-1","name":"Camera","addresses":["192.0.2.20"],
            "policy":"drop","rules":[{
                "destination":"203.0.113.53/32","protocol":"udp","destination_ports":[53],"action":"accept"
            }]
        }]
    })).unwrap());
    for denied in ["sando.write", "firewall.write"] {
        let permissions: Vec<_> = all()
            .into_iter()
            .filter(|permission| permission != denied)
            .collect();
        let response = engine.request(
            "POST",
            "/api/v1/transactions",
            "",
            "operator",
            &permissions,
            &serde_json::to_vec(
                &json!({"base_revision":initial,"confirm_timeout_seconds":30,"config":candidate}),
            )
            .unwrap(),
        );
        assert_eq!(response.status, 403, "{}", response.body);
        assert!(response.body["error"].as_str().unwrap().contains(denied));
    }
    let pending = submit(&mut engine, candidate.clone());
    assert_eq!(pending.status, 202, "{}", pending.body);
    let id = pending.body["id"].as_str().unwrap();
    assert_eq!(
        engine.saved_configuration().sando,
        crate::SandoConfig::default()
    );
    assert_eq!(engine.committed_revision(), initial);
    let reader = request(&mut engine, "GET", "/api/v1/revisions/latest", Value::Null);
    assert!(reader.body["config"]["sando"]["hosts_import"].is_null());
    let without_sando: Vec<_> = all()
        .into_iter()
        .filter(|permission| permission != "sando.write")
        .collect();
    for action in ["confirm", "rollback"] {
        assert_eq!(
            engine
                .request(
                    "POST",
                    &format!("/api/v1/transactions/{id}/{action}"),
                    "",
                    "operator",
                    &without_sando,
                    &[]
                )
                .status,
            403
        );
    }
    assert_eq!(confirm(&mut engine, id).status, 200);
    assert_eq!(engine.saved_configuration().sando, candidate.sando);
    assert_eq!(
        engine.saved_configuration().firewall.policies,
        candidate.firewall.policies
    );
    let mut changed = candidate.clone();
    changed.sando.rules_import.as_mut().unwrap().import_count = 3;
    changed.firewall.policies.as_mut().unwrap().hosts[0].rules[0].action = "drop".into();
    let pending = submit(&mut engine, changed);
    assert_eq!(pending.status, 202);
    let pending_id = pending.body["id"].as_str().unwrap().to_owned();
    drop(engine);
    let mut engine = fixture.engine();
    assert_eq!(engine.saved_configuration().sando, candidate.sando);
    assert_eq!(
        request(
            &mut engine,
            "POST",
            &format!("/api/v1/transactions/{pending_id}/rollback"),
            Value::Null
        )
        .status,
        200
    );
    assert_eq!(engine.saved_configuration().sando, candidate.sando);
    assert_eq!(
        engine.saved_configuration().firewall.policies,
        candidate.firewall.policies
    );
    let base = engine.committed_revision();
    let restored = request(
        &mut engine,
        "POST",
        &format!("/api/v1/revisions/{initial}/restore"),
        json!({"base_revision":base,"confirm_timeout_seconds":30}),
    );
    assert_eq!(restored.status, 202, "{}", restored.body);
    assert_eq!(
        confirm(&mut engine, restored.body["id"].as_str().unwrap()).status,
        200
    );
    assert_eq!(
        engine.saved_configuration().sando,
        crate::SandoConfig::default()
    );
    assert!(engine.saved_configuration().firewall.policies.is_none());
    drop(engine);
    let mut engine = fixture.engine();
    let historical = request(
        &mut engine,
        "GET",
        &format!("/api/v1/revisions/{base}"),
        Value::Null,
    );
    assert_eq!(historical.body["config"]["sando"], json!(candidate.sando));
}

#[test]
fn sando_api_validates_known_fields_instead_of_dropping_invalid_import_state() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    for (sando, status) in [
        (json!({"api_url":"javascript:alert(1)"}), 422),
        (
            json!({"api_url":"http://sando.example.test?token=synthetic"}),
            422,
        ),
        (json!({"api_url":42}), 400),
        (json!({"sync_enabled":true}), 422),
        (json!({"sync_enabled":"true"}), 400),
        (json!({"hosts_import":{"status":"succeeded"}}), 400),
        (
            json!({"hosts_import":{"source_url":"http://sando.example.test","import_count":0,
            "last_import_at":"2026-10-30T00:00:00Z","status":"succeeded","imported_count":0,"skipped_count":0}}),
            422,
        ),
    ] {
        let base = engine.committed_revision();
        let response = request(
            &mut engine,
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":base,"confirm_timeout_seconds":30,"config":{"sando":sando}}),
        );
        assert_eq!(response.status, status, "{}", response.body);
        assert!(response.body["error"].is_string());
        assert_eq!(
            engine.saved_configuration().sando,
            crate::SandoConfig::default()
        );
    }
}

#[test]
fn host_system_settings_need_backend_support_and_only_changed_values_are_checked() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut candidate = config();
    candidate.system.hostname = "fw-1".into();
    assert_eq!(submit(&mut engine, candidate.clone()).status, 422);
    engine.configure_system(Some(Arc::new(|zone| zone == "UTC")));
    candidate.system.timezone = "Mars/Base".into();
    assert_eq!(submit(&mut engine, candidate.clone()).status, 422);
    candidate.system.timezone = "UTC".into();
    let pending = submit(&mut engine, candidate.clone());
    assert_eq!(pending.status, 202, "{}", pending.body);
    assert_eq!(engine.saved_configuration().system, SystemConfig::default());
    let id = pending.body["id"].as_str().unwrap().to_owned();
    assert_eq!(confirm(&mut engine, &id).status, 200);
    assert_eq!(engine.saved_configuration().system.hostname, "fw-1");
    assert_eq!(engine.saved_configuration().system.timezone, "UTC");

    // A zone that disappears from the host only blocks changing the zone itself.
    engine.configure_system(Some(Arc::new(|_| false)));
    candidate.interfaces[0].mtu = 1400;
    let pending = submit(&mut engine, candidate.clone());
    assert_eq!(pending.status, 202, "{}", pending.body);
    let id = pending.body["id"].as_str().unwrap().to_owned();
    assert_eq!(confirm(&mut engine, &id).status, 200);
    candidate.system.timezone = "America/Chicago".into();
    assert_eq!(submit(&mut engine, candidate.clone()).status, 422);

    // Clearing is always allowed, and unchanged values survive a backend without support.
    engine.configure_system(None);
    candidate.system.timezone = "UTC".into();
    candidate.interfaces[0].mtu = 1300;
    let pending = submit(&mut engine, candidate.clone());
    assert_eq!(pending.status, 202, "{}", pending.body);
    let id = pending.body["id"].as_str().unwrap().to_owned();
    assert_eq!(confirm(&mut engine, &id).status, 200);
    // The cosmetic domain needs no host support, even beside managed host settings.
    candidate.system.domain = "home.example.test".into();
    let pending = submit(&mut engine, candidate.clone());
    assert_eq!(pending.status, 202, "{}", pending.body);
    let id = pending.body["id"].as_str().unwrap().to_owned();
    assert_eq!(confirm(&mut engine, &id).status, 200);
    assert_eq!(
        engine.saved_configuration().system.domain,
        "home.example.test"
    );
    candidate.system = SystemConfig::default();
    assert_eq!(submit(&mut engine, candidate).status, 202);
}

#[test]
fn all_domain_permissions_are_independently_required() {
    let before = Config::empty();
    let cases = [
        (
            "ntp.write",
            json!({"ntp":{"enabled":false,"servers":["ntp.invalid"]}}),
        ),
        (
            "syslog.write",
            json!({"syslog":{"servers":[{"host":"log.invalid","port":514,"transport":"udp"}]}}),
        ),
        ("vnstat.write", json!({"vnstat":{"enabled":true}})),
        ("mqtt.write", json!({"mqtt":{"interval_seconds":120}})),
        ("system.write", json!({"system":{"hostname":"fw-1"}})),
        ("system.write", json!({"system":{"timezone":"UTC"}})),
        (
            "sando.write",
            json!({"sando":{"api_url":"http://192.0.2.10:8044"}}),
        ),
        (
            "system.write",
            json!({"system":{"domain":"home.example.test"}}),
        ),
        (
            "firewall.write",
            json!({"firewall":{"allow_all_icmp":false}}),
        ),
        (
            "nat.write",
            json!({"firewall":{"nat":{"masquerade":[{"family":"ipv4","out_interface":"lan0"}]}}}),
        ),
        (
            "kernel.namespace.write",
            json!({"kernel":{"namespace":{"net.core.somaxconn":"8192"}}}),
        ),
        (
            "kernel.host.write",
            json!({"kernel":{"host":{"net.core.rmem_max":"4194304"}}}),
        ),
        (
            "routes.write",
            json!({"routes":[{"enabled":true,"destination":"0.0.0.0/0","interface":"lan0","table":10000,"metric":1}]}),
        ),
        (
            "routes.write",
            json!({"blackhole":{"name":"blackhole0","action":"unreachable"}}),
        ),
    ];
    for (permission, v) in cases {
        let after: Config = serde_json::from_value(v).unwrap();
        let allowed: Vec<_> = all().into_iter().filter(|p| p != permission).collect();
        let err = authorize(&allowed, &before, &after).expect_err("must deny");
        assert_eq!(err.status, 403);
        assert!(err.error.contains(permission));
        assert!(authorize(&all(), &before, &after).is_ok());
    }
}
#[test]
fn toggling_a_wireguard_peer_requires_wireguard_write_and_commits_through_a_transaction() {
    use base64::Engine as _;
    let fixture = Fixture::new();
    let mut e = fixture.engine();
    let mut config = config();
    config.interfaces[0].kind = "wireguard".into();
    config.interfaces[0].wireguard = Some(crate::WireGuard {
        key_ref: "lab-key".into(),
        listen_port: 51820,
        peers: vec![crate::Peer {
            metadata: Default::default(),
            enabled: true,
            public_key: base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
            endpoint: String::new(),
            allowed_ips: vec!["198.51.100.0/24".into()],
            persistent_keepalive_seconds: 25,
        }],
    });
    let reply = submit(&mut e, config.clone());
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(
        confirm(&mut e, reply.body["id"].as_str().unwrap()).status,
        200
    );
    let mut disabled = config.clone();
    disabled.interfaces[0].wireguard.as_mut().unwrap().peers[0].enabled = false;
    let without: Vec<_> = all()
        .into_iter()
        .filter(|permission| permission != "wireguard.write")
        .collect();
    let denied = authorize(&without, &config, &disabled).unwrap_err();
    assert_eq!(denied.status, 403);
    assert!(denied.error.contains("wireguard.write"));
    assert!(authorize(&all(), &config, &disabled).is_ok());
    let reply = submit(&mut e, disabled.clone());
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(
        reply.body["candidate"]["interfaces"][0]["wireguard"]["peers"][0]["enabled"],
        false
    );
    assert_eq!(
        confirm(&mut e, reply.body["id"].as_str().unwrap()).status,
        200
    );
    let state = request(&mut e, "GET", "/api/v1/state", Value::Null);
    assert_eq!(
        state.body["desired"]["interfaces"][0]["wireguard"]["peers"][0]["enabled"],
        false
    );
}

#[test]
fn reconcile_repairs_failed_workers_without_weakening_normal_observation() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    for service in [
        "ntp",
        "syslog",
        "vnstat",
        "softflowd",
        "dhcp-relay",
        "gateway-monitoring",
    ] {
        backend.lock().unwrap().worker_failed = true;
        assert_eq!(
            request(&mut engine, "GET", "/api/v1/state", Value::Null).status,
            503
        );
        let before_repairs = backend.lock().unwrap().repair_count;
        let reply = request(
            &mut engine,
            "POST",
            &format!("/api/v1/services/{service}/reconcile"),
            Value::Null,
        );
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(backend.lock().unwrap().repair_count, before_repairs + 1);
        assert!(!backend.lock().unwrap().worker_failed);
        assert_eq!(
            request(&mut engine, "GET", "/api/v1/state", Value::Null).status,
            200
        );
        assert_eq!(engine.state.revision, test_revision(0));
        assert_eq!(engine.state.desired, Config::empty());
    }
}

#[test]
fn reconcile_still_rejects_network_drift_and_observation_errors() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let before_repairs = backend.lock().unwrap().repair_count;
    {
        let mut faults = backend.lock().unwrap();
        faults.worker_failed = true;
        faults.state.firewall.allow_all_icmp = false;
    }
    let reply = request(
        &mut engine,
        "POST",
        "/api/v1/services/softflowd/reconcile",
        Value::Null,
    );
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(backend.lock().unwrap().repair_count, before_repairs);
    assert!(backend.lock().unwrap().worker_failed);
    {
        let mut faults = backend.lock().unwrap();
        faults.state = Config::empty();
        faults.typed_network_drift = true;
    }
    let reply = request(
        &mut engine,
        "POST",
        "/api/v1/services/softflowd/reconcile",
        Value::Null,
    );
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(backend.lock().unwrap().repair_count, before_repairs);
    assert!(backend.lock().unwrap().worker_failed);
    {
        let mut faults = backend.lock().unwrap();
        faults.state = Config::empty();
        faults.typed_network_drift = false;
        faults.fail_observe = true;
    }
    let reply = request(
        &mut engine,
        "POST",
        "/api/v1/services/softflowd/reconcile",
        Value::Null,
    );
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(backend.lock().unwrap().repair_count, before_repairs);
    assert!(backend.lock().unwrap().worker_failed);
}

#[test]
fn unsupported_flow_filters_and_v5_sampling_fail_validation_before_backend_apply() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let mut config = config();
    config.softflowd = vec![
        serde_json::from_value(json!({
            "name":"flow0","enabled":true,"interface":"lan0","collector":"192.0.2.10:9995",
            "export_version":10,"sampling_rate":100,"max_flows":1024,"snaplen":128,
            "promiscuous":false,"capture_filter":""
        }))
        .unwrap(),
    ];
    for filter in ["", "ip", "ip6", "tcp", "udp", "icmp", "icmp6"] {
        config.softflowd[0].capture_filter = filter.into();
        config.normalize();
        config.validate().unwrap();
    }
    for filter in [
        "ip or ip6",
        "tcp port 443",
        "TCP",
        " tcp",
        "tcp ",
        "icmp\n",
        "\0",
    ] {
        config.softflowd[0].capture_filter = filter.into();
        let reply = submit(&mut engine, config.clone());
        assert_eq!(reply.status, 422, "{filter:?}: {}", reply.body);
        assert!(engine.state.transactions.is_empty());
    }
    config.softflowd[0].capture_filter.clear();
    config.softflowd[0].export_version = 5;
    config.softflowd[0].sampling_rate = 16383;
    config.validate().unwrap();
    config.softflowd[0].sampling_rate = 16384;
    let reply = submit(&mut engine, config.clone());
    assert_eq!(reply.status, 422, "{}", reply.body);
    assert!(engine.state.transactions.is_empty());
    for version in [1, 9, 10] {
        config.softflowd[0].export_version = version;
        config.softflowd[0].sampling_rate = 1000000;
        config.validate().unwrap();
    }
}

#[test]
fn source_policy_api_removed_and_configuration_field_ignored_without_mutation() {
    let f = Fixture::new();
    let mut e = f.engine();
    assert!(!PERMISSIONS.contains(&"policy.write"));
    for (method, status) in [("GET", 404), ("POST", 404), ("DELETE", 405)] {
        let reply = request(&mut e, method, "/api/v1/policy-rules", Value::Null);
        assert_eq!(reply.status, status, "{}", reply.body);
    }
    for rules in [
        json!([]),
        json!(null),
        json!([{
            "source":"192.0.2.0/24","table":10000,"priority":10000
        }]),
    ] {
        let reply = request(
            &mut e,
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,
                "config":{"policy_rules":rules}}),
        );
        assert_eq!(reply.status, 202, "{}", reply.body);
        assert_eq!(
            reply.body["ignored_fields"],
            json!(["/config/policy_rules"])
        );
        assert!(reply.body["candidate"].get("policy_rules").is_none());
        let id = reply.body["id"].as_str().unwrap().to_owned();
        let rolled_back = request(
            &mut e,
            "POST",
            &format!("/api/v1/transactions/{id}/rollback"),
            Value::Null,
        );
        assert_eq!(rolled_back.status, 200, "{}", rolled_back.body);
        assert_eq!(e.state.revision, test_revision(0));
    }
    let state = request(&mut e, "GET", "/api/v1/state", Value::Null);
    for field in ["desired", "observed"] {
        assert!(state.body[field].get("policy_rules").is_none());
    }
}

#[test]
fn unknown_configuration_fields_are_dropped_and_reported_but_known_fields_stay_strict() {
    let f = Fixture::new();
    let mut e = f.engine();
    let body = json!({"base_revision":test_revision(0),"confirm_timeout_seconds":30,"config":{
        "future_top_level":{"a":1},
        "mqtt":{"enabled":false,"mqtt":"same-name-as-parent","extra/slash":1},
        "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,
            "addresses":["192.0.2.1/24"],"preferred_new_option":true}]}});
    let reply = request(&mut e, "POST", "/api/v1/transactions", body);
    assert_eq!(reply.status, 202, "{}", reply.body);
    let mut ignored: Vec<_> = reply.body["ignored_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect();
    ignored.sort();
    assert_eq!(
        ignored,
        [
            "/config/future_top_level",
            "/config/interfaces/0/preferred_new_option",
            "/config/mqtt/extra~1slash",
            "/config/mqtt/mqtt",
        ]
    );
    assert_eq!(reply.body["candidate"]["interfaces"][0]["name"], "lan0");
    let id = reply.body["id"].as_str().unwrap().to_owned();
    assert_eq!(confirm(&mut e, &id).status, 200);
    let state = request(&mut e, "GET", "/api/v1/state", Value::Null);
    assert!(state.body["desired"].get("future_top_level").is_none());
    assert!(
        state.body["desired"]["interfaces"][0]
            .get("preferred_new_option")
            .is_none()
    );
    let clean = request(
        &mut e,
        "POST",
        "/api/v1/transactions",
        json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":state.body["desired"]}),
    );
    assert_eq!(clean.status, 202, "{}", clean.body);
    assert_eq!(clean.body["ignored_fields"], json!([]));
    assert_eq!(
        request(
            &mut e,
            "POST",
            &format!(
                "/api/v1/transactions/{}/rollback",
                clean.body["id"].as_str().unwrap()
            ),
            Value::Null
        )
        .status,
        200
    );

    for config in [
        json!({"mqtt":{"interval_seconds":"sixty"}}),
        json!({"interfaces":[{"name":"lan0","unknown":1}]}),
        json!({"ipv6_enabled":null}),
        json!(null),
    ] {
        let reply = request(
            &mut e,
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":config}),
        );
        assert_eq!(reply.status, 400, "{config}: {}", reply.body);
    }
    for body in [
        json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30,"config":{},"envelope_extra":1}),
        json!({"base_revision":test_revision(1),"config":{}}),
    ] {
        assert_eq!(
            request(&mut e, "POST", "/api/v1/transactions", body).status,
            400
        );
    }
}

#[test]
fn gateway_monitors_without_public_rules_commit_restart_and_rollback() {
    let f = Fixture::new();
    let mut e = f.engine();
    let example: Value =
        serde_json::from_str(include_str!("../../../examples/gateway-monitoring.json")).unwrap();
    let mut config: Config = serde_json::from_value(example["config"].clone()).unwrap();
    config.interfaces[0].kind = "dummy".into();
    config.interfaces[0].vlan = None;
    let allowed: Vec<_> = all()
        .into_iter()
        .filter(|p| p != "gateway_monitors.write")
        .collect();
    assert_eq!(
        authorize(&allowed, &Config::empty(), &config)
            .unwrap_err()
            .status,
        403
    );
    let reply = submit(&mut e, config.clone());
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(
        confirm(&mut e, reply.body["id"].as_str().unwrap()).status,
        200
    );
    drop(e);
    let mut e = Engine::open(
        &f.path(),
        Box::new(Simulator::with_config(config.clone()).unwrap()),
    )
    .unwrap();
    assert_eq!(e.saved_configuration(), &config.normalized());
    let reply = submit(&mut e, Config::empty());
    assert_eq!(reply.status, 202, "{}", reply.body);
    let rollback = request(
        &mut e,
        "POST",
        &format!(
            "/api/v1/transactions/{}/rollback",
            reply.body["id"].as_str().unwrap()
        ),
        Value::Null,
    );
    assert_eq!(rollback.status, 200, "{}", rollback.body);
    assert_eq!(e.saved_configuration(), &config.normalized());
}

#[test]
fn read_routes_runtime_statistics_and_reconcile_contract() {
    let f = Fixture::new();
    let mut e = f.engine();
    let paths = [
        "state",
        "interfaces",
        "vlans",
        "gateway-monitors",
        "services/softflowd",
        "services/ntp",
        "services/syslog",
        "services/vnstat",
        "routes",
        "firewall/rules",
        "firewall/hosts",
        "firewall/interface-policies",
        "firewall/nat",
        "wireguard",
        "runtime",
        "parent-interfaces",
        "services/softflowd/status",
        "services/dhcp-relay/status",
        "services/gateway-monitoring/status",
        "services/ntp/status",
        "services/syslog/status",
        "services/vnstat/status",
        "kernel/tunables/catalog",
        "kernel/tunables",
        "statistics",
        "statistics/interfaces",
        "statistics/protocols",
        "statistics/link-diagnostics",
        "statistics/gateways",
    ];
    for path in paths {
        let r = request(&mut e, "GET", &format!("/api/v1/{path}"), Value::Null);
        assert_eq!(r.status, 200, "{path}: {}", r.body);
    }
    for service in [
        "softflowd",
        "dhcp-relay",
        "gateway-monitoring",
        "ntp",
        "syslog",
        "vnstat",
    ] {
        let r = request(
            &mut e,
            "POST",
            &format!("/api/v1/services/{service}/reconcile"),
            Value::Null,
        );
        assert_eq!(r.status, 200, "{}", r.body);
    }
    assert_eq!(
        request(
            &mut e,
            "GET",
            "/api/v1/statistics/interfaces/missing",
            Value::Null
        )
        .status,
        404
    );
    assert_eq!(
        request(
            &mut e,
            "GET",
            "/api/v1/statistics/gateways/missing",
            Value::Null
        )
        .status,
        404
    );
    assert_eq!(
        e.request("GET", "/api/v1/statistics", "x=1", "operator", &all(), &[])
            .status,
        400
    );
    assert_eq!(
        request(&mut e, "POST", "/api/v1/statistics", Value::Null).status,
        405
    );
    assert_eq!(
        request(&mut e, "PUT", "/api/v1/state", Value::Null).status,
        405
    );
    assert_eq!(
        request(&mut e, "GET", "/api/v1/unknown", Value::Null).status,
        404
    );
    assert_eq!(
        request(
            &mut e,
            "GET",
            "/api/v1/services/unknown/status",
            Value::Null
        )
        .status,
        404
    );
    assert_eq!(
        request(&mut e, "GET", "/api/v1/interfaces/missing", Value::Null).status,
        404
    );
}
#[test]
fn calendar_revisions_roll_days_preserve_history_and_reject_clock_regression() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let initial = engine.committed_revision();
    let tomorrow = Utc::now() + Duration::days(1);
    engine.now = Some(tomorrow);
    let transaction = submit(&mut engine, config());
    assert_eq!(transaction.status, 202, "{}", transaction.body);
    let committed = confirm(&mut engine, transaction.body["id"].as_str().unwrap());
    assert_eq!(committed.status, 200, "{}", committed.body);
    let next_day = Version::first(tomorrow.date_naive()).unwrap();
    assert_eq!(engine.committed_revision(), next_day);
    assert_eq!(committed.body["committed_revision"], json!(next_day));
    drop(engine);
    let mut engine = fixture.engine();
    engine.now = Some(tomorrow + Duration::seconds(1));
    let restored = request(
        &mut engine,
        "POST",
        &format!("/api/v1/revisions/{initial}/restore"),
        json!({"base_revision":next_day,"confirm_timeout_seconds":30}),
    );
    assert_eq!(restored.status, 202, "{}", restored.body);
    assert_eq!(
        confirm(&mut engine, restored.body["id"].as_str().unwrap()).status,
        200
    );
    assert_eq!(
        engine.committed_revision(),
        next_day.next(tomorrow.date_naive()).unwrap()
    );
    engine.now = Some(tomorrow - Duration::days(1));
    let transaction = submit(&mut engine, config());
    assert_eq!(transaction.status, 202);
    let failed = confirm(&mut engine, transaction.body["id"].as_str().unwrap());
    assert_eq!(failed.status, 503);
    assert!(failed.body["error"].as_str().unwrap().contains("UTC clock"));
    let rolled_back = request(
        &mut engine,
        "POST",
        &format!(
            "/api/v1/transactions/{}/rollback",
            transaction.body["id"].as_str().unwrap()
        ),
        Value::Null,
    );
    assert_eq!(rolled_back.status, 200);
}

#[test]
fn saved_software_metadata_does_not_change_revisions_or_rollback_to_old_software() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let initial = engine.committed_revision();
    let pending = submit(&mut engine, config());
    assert_eq!(pending.status, 202);
    let metadata = SoftwareMetadata {
        repository: Some("example/netcontrol".into()),
        latest_version: Some("9999.12.31.10".parse().unwrap()),
        update_available: Some(true),
        last_checked_at: Some(Utc::now()),
        ..Default::default()
    };
    engine.update_software_metadata(metadata.clone()).unwrap();
    assert_eq!(engine.committed_revision(), initial);
    assert_eq!(
        confirm(&mut engine, pending.body["id"].as_str().unwrap()).status,
        200
    );
    assert_eq!(engine.saved_configuration().software, metadata);
    let current = engine.committed_revision();
    let latest = request(&mut engine, "GET", "/api/v1/revisions/latest", Value::Null);
    assert_eq!(latest.body["config"]["software"], json!(metadata));
    let restore = request(
        &mut engine,
        "POST",
        &format!("/api/v1/revisions/{initial}/restore"),
        json!({"base_revision":current,"confirm_timeout_seconds":30}),
    );
    assert_eq!(restore.status, 202, "{}", restore.body);
    assert_eq!(
        confirm(&mut engine, restore.body["id"].as_str().unwrap()).status,
        200
    );
    assert_eq!(engine.saved_configuration().software, metadata);
    let mut forged = engine.saved_configuration().clone();
    forged.software.update_available = Some(false);
    assert_eq!(submit(&mut engine, forged).status, 422);
    drop(engine);
    let mut engine = fixture.engine();
    assert_eq!(engine.saved_configuration().software, metadata);
    let saved = fs::read(fixture.path()).unwrap();
    engine.store.fail_after.set(Some(0));
    assert!(
        engine
            .update_software_metadata(SoftwareMetadata::default())
            .is_err()
    );
    assert_eq!(engine.saved_configuration().software, metadata);
    assert_eq!(fs::read(fixture.path()).unwrap(), saved);
}

#[test]
fn old_numeric_revision_state_is_rejected_without_overwriting_data() {
    let fixture = Fixture::new();
    let engine = fixture.engine();
    let mut state = serde_json::to_value(&engine.state).unwrap();
    state["revision"] = json!(0);
    engine.store.save(&state).unwrap();
    let saved = fs::read(fixture.path()).unwrap();
    drop(engine);
    assert!(Engine::open(&fixture.path(), Box::new(Simulator::new())).is_err());
    assert_eq!(fs::read(fixture.path()).unwrap(), saved);
}

#[test]
fn latest_revision_tracks_commits_not_provisional_changes_and_survives_restart() {
    let f = Fixture::new();
    let mut e = f.engine();
    let path = "/api/v1/revisions/latest";
    let initial = request(&mut e, "GET", path, Value::Null);
    assert_eq!(initial.status, 200, "{}", initial.body);
    assert_eq!(
        initial.body,
        request(
            &mut e,
            "GET",
            &format!("/api/v1/revisions/{}", test_revision(0)),
            Value::Null
        )
        .body
    );
    assert_eq!(
        initial.body["revision"],
        serde_json::json!(test_revision(0))
    );
    assert_eq!(initial.body["current"], true);
    assert_eq!(initial.body["config"], json!(Config::empty()));

    let applied = submit(&mut e, config());
    assert_eq!(applied.status, 202, "{}", applied.body);
    let id = applied.body["id"].as_str().unwrap();
    assert_eq!(request(&mut e, "GET", path, Value::Null).body, initial.body);
    assert_eq!(confirm(&mut e, id).status, 200);
    let committed = request(&mut e, "GET", path, Value::Null);
    assert_eq!(committed.status, 200, "{}", committed.body);
    assert_eq!(
        committed.body,
        request(
            &mut e,
            "GET",
            &format!("/api/v1/revisions/{}", test_revision(1)),
            Value::Null
        )
        .body
    );
    assert_eq!(
        committed.body["revision"],
        serde_json::json!(test_revision(1))
    );
    assert_eq!(committed.body["current"], true);
    assert_eq!(committed.body["config"], json!(config().normalized()));

    let pending = submit(&mut e, Config::empty());
    assert_eq!(pending.status, 202, "{}", pending.body);
    assert_eq!(
        request(&mut e, "GET", path, Value::Null).body,
        committed.body
    );
    let rollback = request(
        &mut e,
        "POST",
        &format!(
            "/api/v1/transactions/{}/rollback",
            pending.body["id"].as_str().unwrap()
        ),
        Value::Null,
    );
    assert_eq!(rollback.status, 200, "{}", rollback.body);
    assert_eq!(
        request(&mut e, "GET", path, Value::Null).body,
        committed.body
    );

    let restored = request(
        &mut e,
        "POST",
        &format!("/api/v1/revisions/{}/restore", test_revision(0)),
        json!({"base_revision":test_revision(1),"confirm_timeout_seconds":30}),
    );
    assert_eq!(restored.status, 202, "{}", restored.body);
    assert_eq!(
        request(&mut e, "GET", path, Value::Null).body,
        committed.body
    );
    assert_eq!(
        confirm(&mut e, restored.body["id"].as_str().unwrap()).status,
        200
    );
    let latest = request(&mut e, "GET", path, Value::Null);
    assert_eq!(latest.status, 200, "{}", latest.body);
    assert_eq!(latest.body["revision"], serde_json::json!(test_revision(2)));
    assert_eq!(
        latest.body["restored_from_revision"],
        serde_json::json!(test_revision(0))
    );
    assert_eq!(latest.body["config"], initial.body["config"]);
    drop(e);
    let mut e = f.engine();
    assert_eq!(request(&mut e, "GET", path, Value::Null).body, latest.body);
}

#[test]
fn latest_revision_is_authorized_readonly_and_independent_of_observation() {
    let f = Fixture::new();
    let (mut e, faults) = faulty(&f);
    let applied = submit(&mut e, config());
    assert_eq!(applied.status, 202, "{}", applied.body);
    assert_eq!(
        confirm(&mut e, applied.body["id"].as_str().unwrap()).status,
        200
    );
    let expected = request(
        &mut e,
        "GET",
        &format!("/api/v1/revisions/{}", test_revision(1)),
        Value::Null,
    )
    .body;
    let saved = fs::read(f.path()).unwrap();
    faults.lock().unwrap().fail_observe = true;
    let path = "/api/v1/revisions/latest";
    let reader = vec!["state.read".into()];
    assert_eq!(e.request("GET", path, "", "", &reader, &[]).status, 401);
    assert_eq!(e.request("GET", path, "", "reader", &[], &[]).status, 403);
    for query in ["limit=1", "before_revision=1", "unknown=1", "limit="] {
        let reply = e.request("GET", path, query, "reader", &reader, &[]);
        assert_eq!(reply.status, 400, "{query}: {}", reply.body);
        assert!(reply.body["error"].is_string());
    }
    let latest = e.request("GET", path, "", "reader", &reader, &[]);
    assert_eq!(latest.status, 200, "{}", latest.body);
    assert_eq!(latest.body, expected);
    assert_eq!(
        request(&mut e, "GET", "/api/v1/state", Value::Null).status,
        503
    );
    assert_eq!(fs::read(f.path()).unwrap(), saved);
    assert_eq!(faults.lock().unwrap().apply_count, 1);
    assert_eq!(
        request(&mut e, "GET", "/api/v1/revisions/latest/extra", Value::Null).status,
        404
    );
}

#[test]
fn revision_pagination_and_strict_queries() {
    let f = Fixture::new();
    let mut e = f.engine();
    for _ in 0..3 {
        let r = submit(&mut e, Config::empty());
        assert_eq!(r.status, 202, "{}", r.body);
        let committed = confirm(&mut e, r.body["id"].as_str().unwrap());
        assert_eq!(committed.status, 200, "{}", committed.body);
    }
    let r = e.request("GET", "/api/v1/revisions", "limit=2", "reader", &all(), &[]);
    assert_eq!(
        r.body["revisions"][0]["revision"],
        serde_json::json!(test_revision(3))
    );
    assert_eq!(
        r.body["next_before_revision"],
        serde_json::json!(test_revision(2))
    );
    let r = e.request(
        "GET",
        "/api/v1/revisions",
        &format!("limit=2&before_revision={}", test_revision(2)),
        "reader",
        &all(),
        &[],
    );
    assert_eq!(
        r.body["revisions"][0]["revision"],
        serde_json::json!(test_revision(1))
    );
    assert!(r.body.get("next_before_revision").is_none());
    for query in [
        "limit=0",
        "limit=101",
        "limit=",
        "limit=1&limit=2",
        "unknown=1",
        "before_revision=-1",
        "before_revision=18446744073709551616",
    ] {
        assert_eq!(
            e.request("GET", "/api/v1/revisions", query, "reader", &all(), &[])
                .status,
            400,
            "{query}"
        );
    }
}
#[test]
fn simulator_kernel_removal_and_rollback_restore_original_values() {
    let f = Fixture::new();
    let mut e = f.engine();
    let mut config = Config::empty();
    config
        .kernel
        .namespace
        .insert("net.core.somaxconn".into(), "8192".into());
    let r = submit(&mut e, config);
    let kernel = request(&mut e, "GET", "/api/v1/kernel/tunables", Value::Null);
    assert_eq!(kernel.body["desired"], json!(KernelConfig::default()));
    assert_eq!(
        kernel.body["configured"]["namespace"]["net.core.somaxconn"],
        "8192"
    );
    assert_eq!(
        kernel.body["captured_original"]["namespace"]["net.core.somaxconn"],
        "4096"
    );
    assert_eq!(confirm(&mut e, r.body["id"].as_str().unwrap()).status, 200);
    let r = submit(&mut e, Config::empty());
    let kernel = request(&mut e, "GET", "/api/v1/kernel/tunables", Value::Null);
    assert_eq!(
        kernel.body["effective"]["namespace"]["net.core.somaxconn"],
        "4096"
    );
    let rollback = request(
        &mut e,
        "POST",
        &format!(
            "/api/v1/transactions/{}/rollback",
            r.body["id"].as_str().unwrap()
        ),
        Value::Null,
    );
    assert_eq!(rollback.status, 200);
    let kernel = request(&mut e, "GET", "/api/v1/kernel/tunables", Value::Null);
    assert_eq!(
        kernel.body["effective"]["namespace"]["net.core.somaxconn"],
        "8192"
    );
}

#[test]
fn host_health_is_authorized_readonly_and_independent_of_configuration_observation() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let path = "/api/v1/statistics/host";
    let expected = json!({"schema":"netcontrol-host-health/v1","sample":{"scope":"host","status":"partial"},"sections":{}});
    backend.lock().unwrap().traffic_response = Some(expected.clone());
    backend.lock().unwrap().fail_observe = true;
    assert_eq!(
        engine.request("GET", path, "", "reader", &[], &[]).status,
        403
    );
    assert_eq!(
        engine
            .request("GET", path, "x=1", "reader", &all(), &[])
            .status,
        400
    );
    assert_eq!(request(&mut engine, "POST", path, Value::Null).status, 405);
    assert_eq!(
        request(
            &mut engine,
            "GET",
            "/api/v1/statistics/host/extra",
            Value::Null
        )
        .status,
        404
    );
    assert!(backend.lock().unwrap().statistics_calls.is_empty());
    let reply = engine.request("GET", path, "", "reader", &["state.read".into()], &[]);
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body, expected);
    backend.lock().unwrap().traffic_error = Some("host metrics unavailable".into());
    assert_eq!(request(&mut engine, "GET", path, Value::Null).status, 503);
}

#[test]
fn host_health_simulator_never_measures_the_development_host() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let before = request(&mut engine, "GET", "/api/v1/state", Value::Null);
    let reply = request(&mut engine, "GET", "/api/v1/statistics/host", Value::Null);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["sample"]["scope"], "simulator");
    assert_eq!(reply.body["sample"]["status"], "simulated");
    assert!(reply.body["sample"]["boot_id"].is_null());
    let sections = reply.body["sections"].as_object().unwrap();
    assert_eq!(sections.len(), 12);
    for value in sections.values() {
        assert_eq!(value["status"], "simulated");
        assert!(value["data"].is_null());
        assert!(value["error"].is_string());
    }
    assert_eq!(
        request(&mut engine, "GET", "/api/v1/state", Value::Null).body,
        before.body
    );
}

#[test]
fn traffic_history_routes_reach_backend_and_preserve_canonical_history() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let path = "/api/v1/statistics/vnstat";
    {
        let expected = json!({
            "schema":"netcontrol-services/counters/v2",
            "scope":"host",
            "interfaces":{},
            "history":[{
                "collected_at":"2026-10-19T06:30:00Z",
                "interface":"lan0",
                "delta":{"rx_bytes":"1000","tx_bytes":"2000","rx_packets":"10","tx_packets":"20"},
                "reset":false
            }]
        });
        backend.lock().unwrap().traffic_response = Some(expected.clone());
        let reply = request(&mut engine, "GET", path, Value::Null);
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(reply.body, expected);
        assert_eq!(
            backend.lock().unwrap().statistics_calls.last(),
            Some(&(path.to_owned(), String::new()))
        );
    }
}

#[test]
fn traffic_history_auth_query_scope_and_backend_errors_are_not_hidden() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let path = "/api/v1/statistics/vnstat";
    assert_eq!(
        engine.request("GET", path, "", "reader", &[], &[]).status,
        403
    );
    for query in ["limit=10", "scope=host", "unused="] {
        assert_eq!(
            engine
                .request("GET", path, query, "reader", &all(), &[])
                .status,
            400
        );
    }
    for invalid in [
        "/api/v1/statistics/vnstat/host",
        "/api/v1/statistics/vnstat/managed",
        "/api/v1/statistics/vnstat/",
        "/api/v1/statistics/vnstat/unknown",
        "/api/v1/statistics/vnstat/host/extra",
    ] {
        assert_eq!(
            request(&mut engine, "GET", invalid, Value::Null).status,
            404
        );
    }
    assert!(backend.lock().unwrap().statistics_calls.is_empty());
    for error in [
        "vnstat is disabled",
        "traffic worker unavailable",
        "traffic history unavailable: worker stopped",
    ] {
        backend.lock().unwrap().traffic_error = Some(error.into());
        let reply = request(&mut engine, "GET", path, Value::Null);
        assert_eq!(reply.status, 503, "{}", reply.body);
        assert_eq!(reply.body["error"], error);
        assert!(reply.body["transaction"].is_null());
    }
    assert_eq!(request(&mut engine, "POST", path, Value::Null).status, 405);
}

#[test]
fn simulator_traffic_history_never_fabricates_measured_counters() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let status = request(
        &mut engine,
        "GET",
        "/api/v1/services/vnstat/status",
        Value::Null,
    );
    assert_eq!(status.status, 200);
    assert_eq!(
        status.body["instances"],
        json!([{"name":"vnstat","scope":"host","state":"disabled"}])
    );
    {
        let path = "/api/v1/statistics/vnstat";
        let disabled = request(&mut engine, "GET", path, Value::Null);
        assert_eq!(disabled.status, 503);
        assert_eq!(disabled.body["error"], "vnstat is disabled");
    }
    let mut config = Config::empty();
    config.vnstat.enabled = true;
    assert_eq!(submit(&mut engine, config).status, 202);
    {
        let path = "/api/v1/statistics/vnstat";
        let unavailable = request(&mut engine, "GET", path, Value::Null);
        assert_eq!(unavailable.status, 503);
        assert!(
            unavailable.body["error"]
                .as_str()
                .unwrap()
                .contains("simulator does not collect")
        );
        assert!(unavailable.body.get("scopes").is_none());
    }
}

#[test]
fn connection_statistics_are_authorized_filtered_and_readonly() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let expected = json!({"schema":"netcontrol-connections/v1","sample":{"status":"partial"},"connections":[],"summary":{"total":0}});
    backend.lock().unwrap().traffic_response = Some(expected.clone());
    backend.lock().unwrap().fail_observe = true;
    let before = fs::read(fixture.path()).unwrap();
    let path = "/api/v1/statistics/connections";
    let query = "family=ipv4&protocol=tcp&port=443&limit=20&offset=0";
    assert_eq!(
        engine
            .request("GET", path, query, "reader", &[], &[])
            .status,
        403
    );
    assert_eq!(
        engine.request("GET", path, query, "", &all(), &[]).status,
        401
    );
    for query in [
        "unknown=1",
        "limit=0",
        "limit=1001",
        "port=65536",
        "offset=-1",
        "protocol=tcp&protocol=udp",
    ] {
        assert_eq!(
            engine
                .request("GET", path, query, "reader", &["state.read".into()], &[])
                .status,
            400
        );
    }
    assert_eq!(request(&mut engine, "POST", path, Value::Null).status, 405);
    assert!(backend.lock().unwrap().statistics_calls.is_empty());
    let reply = engine.request("GET", path, query, "reader", &["state.read".into()], &[]);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, expected);
    assert_eq!(
        backend.lock().unwrap().statistics_calls,
        [(path.into(), query.into())]
    );
    backend.lock().unwrap().traffic_error = Some("conntrack unavailable".into());
    assert_eq!(
        engine
            .request("GET", path, "", "reader", &["state.read".into()], &[])
            .status,
        503
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert_eq!(backend.lock().unwrap().apply_count, 0);
}

#[test]
fn upgrade_maintenance_blocks_configuration_writes_without_changing_saved_state() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    let before = fs::read(fixture.path()).unwrap();
    engine.set_upgrade_maintenance(true).unwrap();
    assert_eq!(
        engine
            .request("POST", "/api/v1/transactions", "", "admin", &all(), b"{}")
            .status,
        409
    );
    assert_eq!(
        engine
            .request(
                "GET",
                "/api/v1/state",
                "",
                "reader",
                &["state.read".into()],
                b""
            )
            .status,
        200
    );
    engine.set_upgrade_maintenance(false).unwrap();
    assert_eq!(backend.lock().unwrap().apply_count, 0);
    assert_eq!(fs::read(fixture.path()).unwrap(), before);
    assert_eq!(submit(&mut engine, config()).status, 202);
    assert!(engine.set_upgrade_maintenance(true).is_err());
}

#[test]
fn simulator_connection_statistics_do_not_fabricate_live_sessions_or_totals() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let reply = engine.request(
        "GET",
        "/api/v1/statistics/connections",
        "limit=10",
        "reader",
        &["state.read".into()],
        &[],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["sample"]["status"], "simulated");
    assert!(reply.body["summary"]["total"].is_null());
    assert_eq!(reply.body["connections"], json!([]));
    assert_eq!(reply.body["limit"], 10);
}

#[test]
fn simulator_statistics_are_explicitly_unmeasured() {
    let f = Fixture::new();
    let mut e = f.engine();
    let transaction = submit(&mut e, config());
    assert_eq!(transaction.status, 202);
    let r = request(
        &mut e,
        "GET",
        "/api/v1/statistics/interfaces/lan0",
        Value::Null,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["sample"]["status"], "simulated");
    assert_eq!(r.body["interface"]["status"], "simulated");
    assert!(r.body["interface"]["counters"].is_null());
    assert!(r.body["interface"].get("pid").is_none());
    let runtime = request(&mut e, "GET", "/api/v1/runtime", Value::Null);
    assert!(
        runtime.body["appliance_services"]
            .as_array()
            .unwrap()
            .iter()
            .all(|service| service.get("pid").is_none())
    );
}

#[test]
fn shutdown_is_idempotent_and_stops_requests() {
    let f = Fixture::new();
    let mut e = f.engine();
    e.shutdown().unwrap();
    e.shutdown().unwrap();
    assert_eq!(
        request(&mut e, "GET", "/api/v1/state", Value::Null).status,
        503
    );
}
