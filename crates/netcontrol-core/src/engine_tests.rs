use super::*;
use crate::Simulator;
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
    initial["routes"] = json!([{"enabled":true,"destination":"203.0.113.0/24","interface":"lan0","table":10000,"metric":10}]);
    let initial: Config = serde_json::from_value(initial).unwrap();
    let reply = submit(&mut engine, initial.clone());
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(
        confirm(&mut engine, reply.body["id"].as_str().unwrap()).status,
        200
    );
    let mut disabled = initial.clone();
    disabled.routes[0].enabled = false;
    let permissions: Vec<_> = all().into_iter().filter(|p| p != "routes.write").collect();
    let body = serde_json::to_vec(
        &json!({"base_revision":1,"confirm_timeout_seconds":30,"config":disabled}),
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
    invalid["routes"][0]
        .as_object_mut()
        .unwrap()
        .remove("enabled");
    assert_eq!(
        request(
            &mut engine,
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":1,"confirm_timeout_seconds":30,"config":invalid})
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
            &json!({"base_revision":0,"confirm_timeout_seconds":30,"config":disabled}),
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
        &json!({"base_revision": 1, "confirm_timeout_seconds": 30, "config": described}),
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
            request.base_revision,
            0,
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
    assert_eq!(engine.state.revision, 1);
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
    assert_eq!(envelope["schema"], "netcontrol-rust-state-v1");
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
    assert_eq!(state.body["revision"], 0);
    assert_eq!(state.body["desired"]["interfaces"], json!([]));
    assert_eq!(state.body["observed"]["interfaces"][0]["name"], "lan0");
    assert_eq!(state.body["drift"], false);
    assert_eq!(confirm(&mut e, &id).status, 200);
    assert_eq!(e.state.revision, 1);
    assert_eq!(confirm(&mut e, &id).status, 200);
    assert_eq!(e.state.revision, 1);
    let list = request(&mut e, "GET", "/api/v1/revisions", Value::Null);
    assert_eq!(list.body["revisions"].as_array().unwrap().len(), 2);
    assert_eq!(list.body["revisions"][0]["current"], true);
    let revision = request(&mut e, "GET", "/api/v1/revisions/1", Value::Null);
    assert_eq!(revision.body["config"], json!(config().normalized()));
    let restore = request(
        &mut e,
        "POST",
        "/api/v1/revisions/0/restore",
        json!({"base_revision":1,"confirm_timeout_seconds":30}),
    );
    assert_eq!(restore.status, 202, "{}", restore.body);
    assert_eq!(restore.body["restored_from_revision"], 0);
    let restored_id = restore.body["id"].as_str().unwrap();
    assert_eq!(confirm(&mut e, restored_id).status, 200);
    assert_eq!(e.state.revision, 2);
    assert_eq!(e.state.desired, Config::empty());
    drop(e);
    let e = f.engine();
    assert_eq!(e.state.revision, 2);
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
    // Preserve a valid initial/submission time while placing the whole transaction in the past.
    e.state.initialized_at = Utc::now() - Duration::hours(2);
    e.store.save(&e.state).unwrap();
    e.now = Some(Utc::now() - Duration::hours(1));
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
    assert_eq!(e.state.revision, 0);
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
    assert_eq!(engine.state.revision, 2);
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
    assert_eq!(engine.state.revision, 1);
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
    assert_eq!(engine.state.revision, 0);
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
    assert_eq!(e.state.revision, 0);
}
#[test]
fn failed_confirmation_save_preserves_pending_and_is_retryable() {
    let f = Fixture::new();
    let mut e = f.engine();
    let r = submit(&mut e, config());
    let id = r.body["id"].as_str().unwrap();
    e.store.fail_after.set(Some(0));
    assert_eq!(confirm(&mut e, id).status, 500);
    assert_eq!(e.state.revision, 0);
    assert_eq!(e.active().unwrap().status, "pending_confirmation");
    assert_eq!(confirm(&mut e, id).status, 200);
    assert_eq!(e.state.revision, 1);
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
    assert_eq!(e.state.revision, 0);
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
        json!({"base_revision":9,"confirm_timeout_seconds":30,"config":{}}),
    );
    assert_eq!(r.status, 409);
    for timeout in [0, 9, 301] {
        let r = request(
            &mut e,
            "POST",
            "/api/v1/transactions",
            json!({"confirm_timeout_seconds":timeout,"config":{}}),
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
    let body = serde_json::to_vec(&json!({"confirm_timeout_seconds":30,"config":c})).unwrap();
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
        "/api/v1/revisions/0/restore",
        "",
        "writer",
        &iface,
        br#"{"base_revision":1,"confirm_timeout_seconds":30}"#,
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
        assert_eq!(engine.state.revision, 0);
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
fn source_policy_api_removed_and_configuration_rejected_without_mutation() {
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
            json!({"base_revision":0,"confirm_timeout_seconds":30,
                "config":{"policy_rules":rules}}),
        );
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert!(
            reply.body["error"]
                .as_str()
                .unwrap()
                .contains("policy_rules")
        );
        assert!(e.state.transactions.is_empty());
        assert_eq!(e.state.revision, 0);
    }
    let state = request(&mut e, "GET", "/api/v1/state", Value::Null);
    for field in ["desired", "observed"] {
        assert!(state.body[field].get("policy_rules").is_none());
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
    assert_eq!(r.body["revisions"][0]["revision"], 3);
    assert_eq!(r.body["next_before_revision"], 2);
    let r = e.request(
        "GET",
        "/api/v1/revisions",
        "limit=2&before_revision=2",
        "reader",
        &all(),
        &[],
    );
    assert_eq!(r.body["revisions"][0]["revision"], 1);
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
fn traffic_history_routes_reach_backend_and_preserve_canonical_history() {
    let fixture = Fixture::new();
    let (mut engine, backend) = faulty(&fixture);
    for (path, scopes) in [
        ("/api/v1/statistics/vnstat", vec!["host", "managed"]),
        ("/api/v1/statistics/vnstat/host", vec!["host"]),
        ("/api/v1/statistics/vnstat/managed", vec!["managed"]),
    ] {
        let mut databases = serde_json::Map::new();
        for scope in scopes {
            databases.insert(scope.into(), json!({
                "schema":"netcontrol-services/counters/v1",
                "scope":scope,
                "interfaces":{},
                "history":[{
                    "collected_at":"2026-10-19T06:30:00Z",
                    "interface":"lan0",
                    "delta":{"rx_bytes":"1000","tx_bytes":"2000","rx_packets":"10","tx_packets":"20"},
                    "reset":false
                }]
            }));
        }
        let expected = json!({"schema":"netcontrol-services/counters/v1","scopes":databases});
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
    for path in [
        "/api/v1/statistics/vnstat",
        "/api/v1/statistics/vnstat/host",
        "/api/v1/statistics/vnstat/managed",
    ] {
        let disabled = request(&mut engine, "GET", path, Value::Null);
        assert_eq!(disabled.status, 503);
        assert_eq!(disabled.body["error"], "vnstat is disabled");
    }
    let mut config = Config::empty();
    config.vnstat.enabled = true;
    assert_eq!(submit(&mut engine, config).status, 202);
    for path in [
        "/api/v1/statistics/vnstat",
        "/api/v1/statistics/vnstat/host",
        "/api/v1/statistics/vnstat/managed",
    ] {
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
