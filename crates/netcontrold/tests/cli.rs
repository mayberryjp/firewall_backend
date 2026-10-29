use netcontrol_core::{Config, Engine, PERMISSIONS, Simulator};
use netcontrold::{
    cli::{CliSession, CommandResult, LINE_LIMIT},
    http::{App, Authentication, Credential},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct Fixture {
    app: Arc<App>,
    principal: Credential,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new(permissions: &[&str]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            &directory.path().join("state.json"),
            Box::new(Simulator::new()),
        )
        .unwrap();
        let principal = Credential {
            name: "cli-test".into(),
            token_sha256: String::new(),
            permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
        };
        let app = App::new(
            Arc::new(Mutex::new(engine)),
            Authentication::Scoped(Vec::new()),
            false,
        );
        Self {
            app,
            principal,
            directory,
        }
    }
    fn command(&self, cli: &mut CliSession, command: &str) -> CommandResult {
        cli.execute(&self.app, &self.principal, command)
    }
    fn ok(&self, cli: &mut CliSession, command: &str) -> String {
        let result = self.command(cli, command);
        assert!(!result.failed, "{command}: {}", result.output);
        result.output
    }
    fn fail(&self, cli: &mut CliSession, command: &str, message: &str) {
        let result = self.command(cli, command);
        assert!(result.failed, "{command}: unexpectedly succeeded");
        assert!(
            result.output.contains(message),
            "{command}: {}",
            result.output
        );
    }
    fn request(&self, path: &str) -> Value {
        let reply = self.app.engine.lock().unwrap().request(
            "GET",
            path,
            "",
            "test",
            &PERMISSIONS
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
            &[],
        );
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply.body
    }
    fn configure(&self, cli: &mut CliSession) {
        self.ok(cli, "enable");
        self.ok(cli, "configure terminal");
    }
    fn interface(&self, cli: &mut CliSession, name: &str) {
        self.ok(cli, &format!("interface {name} dummy"));
        self.ok(cli, "role lan");
        self.ok(cli, "no shutdown");
        self.ok(cli, "ip address 192.0.2.1/24");
        self.ok(cli, "exit");
    }
}

#[test]
fn destination_rewrite_cli_stages_validates_commits_and_removes() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.interface(&mut cli, "lan0");
    f.ok(&mut cli, "interface wan0 dummy");
    f.ok(&mut cli, "role wan");
    f.ok(&mut cli, "no shutdown");
    f.ok(&mut cli, "ip address 198.51.100.1/24");
    f.ok(&mut cli, "exit");
    f.ok(
        &mut cli,
        "nat destination-rewrite wan0 udp 53 lan0 192.0.2.53",
    );
    f.ok(
        &mut cli,
        "nat destination-rewrite wan0 tcp 53 lan0 192.0.2.53",
    );
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    assert_eq!(
        f.request("/api/v1/firewall/nat")["destination_rewrite"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    f.ok(&mut cli, "configure terminal");
    f.ok(&mut cli, "no nat destination-rewrite 0");
    f.ok(&mut cli, "no nat destination-rewrite 0");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    assert_eq!(
        f.request("/api/v1/firewall/nat")["destination_rewrite"],
        json!([])
    );
}

#[test]
fn link_diagnostics_show_is_read_only_and_permission_checked() {
    let f = Fixture::new(&["state.read"]);
    let mut cli = CliSession::new();
    let value: Value =
        serde_json::from_str(&f.ok(&mut cli, "show statistics link-diagnostics")).unwrap();
    assert_eq!(value["status"], "simulated");
    assert!(value["local_tcp"].is_null());
    let denied = Fixture::new(&[]);
    denied.fail(&mut cli, "show statistics link-diagnostics", "403");
}

#[test]
fn bgp_candidate_status_routes_and_permissions() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli,r#"set /interfaces [{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}]"#);
    f.ok(&mut cli,r#"bgp {"enabled":true,"local_asn":65001,"router_id":"192.0.2.1","neighbors":[{"name":"edge","address":"192.0.2.2","local_address":"192.0.2.1","interface":"lan0","remote_asn":65002}]}"#);
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    let status: Value = serde_json::from_str(&f.ok(&mut cli, "show bgp status")).unwrap();
    assert_eq!(status["state"], "simulated");
    let routes: Value = serde_json::from_str(&f.ok(&mut cli, "show routes bgp")).unwrap();
    assert_eq!(routes["source"], "bgp");
    assert_eq!(routes["routes"], json!([]));
    f.ok(&mut cli, "configure terminal");
    f.ok(&mut cli, "no bgp");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    assert_eq!(f.request("/api/v1/services/bgp")["enabled"], false);
    let denied = Fixture::new(&["state.read", "transactions.write"]);
    let mut cli = CliSession::new();
    denied.configure(&mut cli);
    denied.ok(&mut cli, r#"bgp {"metadata":{"display_name":"Routing"}}"#);
    denied.fail(&mut cli, "commit confirmed 30", "bgp.write");
}

#[test]
fn udp_relay_cli_stages_commits_and_resets() {
    let fixture = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    fixture.configure(&mut cli);
    fixture.ok(&mut cli, r#"set /interfaces [{"name":"lan0","kind":"ethernet","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]},{"name":"iot0","kind":"ethernet","role":"lan","mtu":1500,"up":true,"addresses":["198.51.100.1/24"]}]"#);
    fixture.ok(&mut cli, r#"udp-broadcast-relay {"enabled":true,"instances":[{"id":1,"enabled":true,"port":4001,"interfaces":["lan0","iot0"],"multicast_address":"239.255.255.250"}]}"#);
    fixture.ok(&mut cli, "commit check");
    fixture.ok(&mut cli, "commit confirmed 30");
    fixture.ok(&mut cli, "confirm");
    assert_eq!(
        fixture.request("/api/v1/services/udp-broadcast-relay")["enabled"],
        true
    );
    let status: Value =
        serde_json::from_str(&fixture.ok(&mut cli, "show udp-broadcast-relay status")).unwrap();
    assert_eq!(status["instances"][0]["state"], "simulated");
    fixture.ok(&mut cli, "configure terminal");
    fixture.ok(&mut cli, "no udp-broadcast-relay");
    fixture.ok(&mut cli, "commit confirmed 30");
    fixture.ok(&mut cli, "confirm");
    assert_eq!(
        fixture.request("/api/v1/services/udp-broadcast-relay")["enabled"],
        false
    );
}

#[test]
fn mdns_candidate_show_status_repair_and_permission() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli,r#"set /interfaces [{"name":"lan1","kind":"ethernet","role":"lan","mtu":1500,"up":true},{"name":"lan2","kind":"ethernet","role":"lan","mtu":1500,"up":true}]"#);
    f.ok(&mut cli,r#"mdns {"enabled":true,"interfaces":["lan1","lan2"],"ipv6":false,"reflection":{"enabled":true,"filters":["_IPP._tcp.local."]}}"#);
    f.ok(&mut cli, "commit check");
    let committed: Value = serde_json::from_str(&f.ok(&mut cli, "show mdns")).unwrap();
    assert_eq!(committed["enabled"], false);
    f.ok(&mut cli, "commit confirmed 30");
    let status: Value = serde_json::from_str(&f.ok(&mut cli, "show mdns status")).unwrap();
    assert_eq!(status["instances"][0]["state"], "simulated");
    f.ok(&mut cli, "confirm");
    let committed: Value = serde_json::from_str(&f.ok(&mut cli, "show mdns")).unwrap();
    assert_eq!(
        committed["reflection"]["filters"],
        json!(["_ipp._tcp.local."])
    );
    f.ok(&mut cli, "reconcile services mdns");
    f.ok(&mut cli, "configure terminal");
    f.ok(&mut cli, "no mdns");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    assert_eq!(f.request("/api/v1/services/mdns")["enabled"], false);
    let limited = Fixture::new(&["state.read", "transactions.write", "interfaces.write"]);
    let mut cli = CliSession::new();
    limited.configure(&mut cli);
    limited.ok(
        &mut cli,
        r#"mdns {"metadata":{"display_name":"Discovery"}}"#,
    );
    limited.fail(&mut cli, "commit confirmed 30", "mdns.write");
}

#[test]
fn host_health_cli_uses_readonly_statistics_route() {
    let fixture = Fixture::new(&["state.read"]);
    let mut cli = CliSession::new();
    let output = fixture.ok(&mut cli, "show statistics host");
    let value: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["schema"], "netcontrol-host-health/v1");
    assert_eq!(value["sample"]["status"], "simulated");
    assert!(value["sections"]["memory"]["data"].is_null());
    let denied = Fixture::new(&[]);
    denied.fail(&mut cli, "show statistics host", "permission");
}

#[test]
fn static_route_delete_accepts_disabled_record_with_metadata() {
    let f = Fixture::new(PERMISSIONS);
    let config = json!({
        "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
        "routes":[{"metadata":{"display_name":"Spare route"},"enabled":false,"destination":"203.0.113.0/24","interface":"lan0","table":10000,"metric":10}]
    });
    {
        let mut engine = f.app.engine.lock().unwrap();
        let reply = engine.request(
            "POST",
            "/api/v1/transactions",
            "",
            "test",
            &f.principal.permissions,
            &serde_json::to_vec(
                &json!({"base_revision":0,"confirm_timeout_seconds":30,"config":config}),
            )
            .unwrap(),
        );
        assert_eq!(reply.status, 202, "{}", reply.body);
        let reply = engine.request(
            "POST",
            &format!(
                "/api/v1/transactions/{}/confirm",
                reply.body["id"].as_str().unwrap()
            ),
            "",
            "test",
            &f.principal.permissions,
            &[],
        );
        assert_eq!(reply.status, 200);
    }
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "no ip route 203.0.113.0/24 lan0 direct 10000 10");
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    assert_eq!(f.request("/api/v1/routes"), json!([]));
}

#[test]
fn blackhole_routes_are_staged_with_ip_route_and_checked_against_the_named_section() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.interface(&mut cli, "lan0");
    f.ok(
        &mut cli,
        "ip route 198.51.100.0/24 blackhole0 direct 254 50",
    );
    f.fail(&mut cli, "commit check", "422");
    f.ok(
        &mut cli,
        r#"set /blackhole {"name":"blackhole0","action":"unreachable"}"#,
    );
    f.ok(&mut cli, "commit check");
    f.ok(
        &mut cli,
        "ipv6 route 2001:db8:dead::/48 blackhole0 direct 254 50",
    );
    f.ok(&mut cli, "commit check");
    f.ok(
        &mut cli,
        "ip route 203.0.113.0/24 blackhole0 192.0.2.254 254 60",
    );
    f.fail(&mut cli, "commit check", "gateway");
    f.ok(
        &mut cli,
        "no ip route 203.0.113.0/24 blackhole0 192.0.2.254 254 60",
    );
    f.ok(&mut cli, "commit check");
    let candidate = f.ok(&mut cli, "show candidate-config");
    assert!(candidate.contains("blackhole0") && candidate.contains("unreachable"));
    f.ok(
        &mut cli,
        "no ip route 198.51.100.0/24 blackhole0 direct 254 50",
    );
    f.ok(&mut cli, "commit check");
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
}

#[test]
fn hostname_and_timezone_are_staged_checked_committed_and_cleared() {
    let f = Fixture::new(PERMISSIONS);
    f.app
        .engine
        .lock()
        .unwrap()
        .configure_system(Some(Arc::new(|zone| zone == "UTC")));
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "hostname Fw-1");
    f.fail(&mut cli, "commit check", "hostname");
    f.ok(&mut cli, "hostname fw-1");
    f.ok(&mut cli, "timezone Mars/Base");
    // Shape is checked offline; host availability is checked when the transaction is submitted.
    f.ok(&mut cli, "commit check");
    f.fail(&mut cli, "commit confirmed 30 Unknown zone", "timezone");
    f.ok(&mut cli, "timezone UTC");
    f.ok(&mut cli, "domain Home.Example");
    f.fail(&mut cli, "commit check", "domain");
    f.ok(&mut cli, "domain home.example.test");
    f.ok(&mut cli, "commit check");
    assert_eq!(
        f.request("/api/v1/state")["desired"]["system"],
        json!({"hostname":"","domain":"","timezone":""})
    );
    f.ok(&mut cli, "commit confirmed 30 Name the appliance");
    f.ok(&mut cli, "confirm");
    assert_eq!(
        f.request("/api/v1/state")["desired"]["system"],
        json!({"hostname":"fw-1","domain":"home.example.test","timezone":"UTC"})
    );
    f.ok(&mut cli, "configure terminal");
    f.ok(&mut cli, "no hostname");
    f.ok(&mut cli, "no domain");
    f.ok(&mut cli, "no timezone");
    f.ok(&mut cli, "commit confirmed 30 Release host settings");
    f.ok(&mut cli, "confirm");
    assert_eq!(
        f.request("/api/v1/state")["desired"]["system"],
        json!({"hostname":"","domain":"","timezone":""})
    );
}

#[test]
fn global_ipv6_cli_stages_checks_commits_and_rolls_back() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "ipv6 disable");
    f.ok(&mut cli, "commit check");
    assert_eq!(f.request("/api/v1/state")["desired"]["ipv6_enabled"], true);
    f.ok(&mut cli, "commit confirmed 30 Disable IPv6");
    assert_eq!(f.request("/api/v1/runtime")["ipv6"]["enabled"], false);
    f.ok(&mut cli, "rollback");
    assert_eq!(f.request("/api/v1/runtime")["ipv6"]["enabled"], true);
    f.ok(&mut cli, "configure terminal");
    f.ok(&mut cli, "ipv6 disable");
    f.ok(&mut cli, "ipv6 enable");
    f.ok(&mut cli, "commit check");
    assert!(
        f.ok(&mut cli, "show candidate-config")
            .contains("\"ipv6_enabled\": true")
    );
}

#[test]
fn ethernet_candidate_main_routes_and_readonly_discovery_use_shared_engine() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    assert_eq!(f.ok(&mut cli, "show interfaces discovered").trim(), "[]");
    f.configure(&mut cli);
    f.ok(&mut cli, "interface eth0 ethernet");
    f.ok(&mut cli, "no shutdown");
    f.ok(&mut cli, "ip address 192.0.2.10/24");
    f.ok(&mut cli, "exit");
    f.ok(&mut cli, "ip route 0.0.0.0/0 eth0 192.0.2.1 254 100");
    f.ok(&mut cli, "commit check");
    assert_eq!(f.request("/api/v1/interfaces/discovered"), json!([]));
    f.ok(&mut cli, "commit confirmed 30 Host Ethernet");
    let discovery = f.request("/api/v1/interfaces/discovered");
    assert_eq!(discovery[0]["kind"], "ethernet");
    assert_eq!(discovery[0]["ownership"], "managed");
    f.ok(&mut cli, "rollback");
    assert_eq!(f.request("/api/v1/interfaces/discovered"), json!([]));
    let read = Fixture::new(&["state.read"]);
    read.ok(&mut CliSession::new(), "show interfaces discovered");
    let denied = Fixture::new(&[]);
    denied.fail(&mut CliSession::new(), "show interfaces discovered", "403");
}

#[test]
fn candidate_is_private_until_explicit_commit_and_confirmation_is_durable() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    assert_eq!(cli.prompt(), "netcontrol> ");
    f.configure(&mut cli);
    f.interface(&mut cli, "lan0");
    assert!(f.ok(&mut cli, "show candidate-config").contains("lan0"));
    assert!(f.ok(&mut cli, "compare").contains("/interfaces"));
    assert!(
        f.request("/api/v1/state")["desired"]["interfaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, "commit confirmed 30 CLI change");
    assert_eq!(cli.prompt(), "netcontrol# ");
    let state = f.request("/api/v1/state");
    assert_eq!(state["revision"], 0);
    assert!(
        state["desired"]["interfaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(state["observed"]["interfaces"][0]["name"], "lan0");
    assert_eq!(
        state["active_transaction"]["status"],
        "pending_confirmation"
    );
    f.ok(&mut cli, "confirm");
    assert_eq!(f.request("/api/v1/state")["revision"], 1);
    assert!(f.ok(&mut cli, "show running-config").contains("lan0"));
    f.app.engine.lock().unwrap().shutdown().unwrap();
    let path = f.directory.path().join("state.json");
    drop(f.app);
    let mut reopened = Engine::open(&path, Box::new(Simulator::new())).unwrap();
    let reply = reopened.request(
        "GET",
        "/api/v1/revisions/1",
        "",
        "test",
        &["state.read".into()],
        &[],
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["config"]["interfaces"][0]["name"], "lan0");
}

#[test]
fn session_isolation_stale_revision_conflict_and_http_interoperation() {
    let f = Fixture::new(PERMISSIONS);
    let mut first = CliSession::new();
    let mut second = CliSession::new();
    f.configure(&mut first);
    f.configure(&mut second);
    f.interface(&mut first, "lan0");
    assert!(!f.ok(&mut second, "show candidate-config").contains("lan0"));
    f.ok(&mut first, "commit confirmed 30");
    let state = f.request("/api/v1/state");
    let id = state["active_transaction"]["id"].as_str().unwrap();
    let reply = f.app.engine.lock().unwrap().request(
        "POST",
        &format!("/api/v1/transactions/{id}/confirm"),
        "",
        "http-client",
        &PERMISSIONS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>(),
        &[],
    );
    assert_eq!(reply.status, 200);
    f.ok(&mut second, "firewall policy drop");
    f.fail(&mut second, "commit confirmed 30", "409");
    assert!(
        f.ok(&mut second, "show candidate-config")
            .contains("\"drop\"")
    );
    assert_eq!(
        f.request("/api/v1/state")["desired"]["firewall"]["policy"],
        "accept"
    );
}

#[test]
fn disconnect_exit_discard_and_rollback_never_imply_confirmation() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.interface(&mut cli, "lan0");
    f.ok(&mut cli, "commit confirmed 30");
    let result = f.command(&mut cli, "exit");
    assert!(result.exit);
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
    let state = f.request("/api/v1/state");
    let id = state["active_transaction"]["id"].as_str().unwrap();
    let mut recovery = CliSession::new();
    f.ok(&mut recovery, "enable");
    f.ok(&mut recovery, &format!("rollback {id}"));
    assert!(
        f.request("/api/v1/state")["observed"]["interfaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.ok(&mut recovery, "configure terminal");
    f.interface(&mut recovery, "lan1");
    f.ok(&mut recovery, "end");
    f.ok(&mut recovery, "discard");
    f.fail(&mut recovery, "show candidate-config", "no candidate");
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
}

#[test]
fn enable_does_not_elevate_scoped_permissions() {
    let f = Fixture::new(&["state.read"]);
    let mut cli = CliSession::new();
    f.ok(&mut cli, "enable");
    f.ok(&mut cli, "show running-config");
    f.fail(&mut cli, "configure terminal", "transactions.write");
    f.fail(&mut cli, "confirm unknown", "403");
    let f = Fixture::new(&["state.read", "transactions.write", "interfaces.write"]);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "firewall policy drop");
    f.fail(&mut cli, "commit confirmed 30", "firewall.write");
    assert!(f.request("/api/v1/state")["active_transaction"].is_null());
    assert!(f.ok(&mut cli, "show candidate-config").contains("\"drop\""));
}

#[test]
fn edits_are_schema_checked_atomic_and_semantic_errors_preserve_candidate() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    let before = f.ok(&mut cli, "show candidate-config");
    for command in [
        "set /invented true",
        "set /interfaces null",
        "set /firewall/allow_all_icmp null",
        "delete /does-not-exist",
        "set /interfaces/00 {}",
        "set /kernel/namespace/invalid~escape \"x\"",
        "load candidate {\"unknown\":true}",
    ] {
        assert!(f.command(&mut cli, command).failed, "{command}");
        assert_eq!(f.ok(&mut cli, "show candidate-config"), before);
    }
    f.ok(&mut cli, "set /ntp/enabled true");
    f.fail(&mut cli, "commit check", "422");
    f.fail(&mut cli, "commit confirmed 30", "422");
    f.ok(&mut cli, "ntp server time.example.test");
    f.ok(&mut cli, "commit check");
    assert_eq!(
        f.request("/api/v1/state")["desired"]["ntp"]["enabled"],
        false
    );
}

#[test]
fn generic_json_edits_cover_all_configuration_fields_and_pointer_escaping() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    let config: Value =
        serde_json::from_str(include_str!("../../../examples/appliance-services.json")).unwrap();
    let config = config.get("config").unwrap_or(&config);
    f.ok(&mut cli, &format!("load candidate {config}"));
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, "set /kernel/namespace/net.ipv4.ip_forward \"1\"");
    f.ok(&mut cli, "delete /kernel/namespace/net.ipv4.ip_forward");
    f.ok(&mut cli, "set /ntp/servers/- \"backup.example.test\"");
    f.ok(&mut cli, "delete /ntp/servers/0");
    f.ok(&mut cli, "set /kernel/namespace/a~1b~0c \"1\"");
    assert!(f.ok(&mut cli, "show candidate-config").contains("a/b~c"));
    f.ok(&mut cli, "delete /kernel/namespace/a~1b~0c");
    f.ok(&mut cli, "commit check");
}

#[test]
fn ergonomic_interfaces_routes_policies_and_services_preserve_complete_config() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.interface(&mut cli, "uplink");
    f.ok(&mut cli, "interface uplink.10 vlan");
    f.ok(&mut cli, "vlan parent uplink");
    f.ok(&mut cli, "vlan id 10");
    f.ok(&mut cli, "mtu 1400");
    f.ok(&mut cli, "role wan");
    f.ok(&mut cli, "ip address 198.51.100.1/24");
    f.ok(&mut cli, "ipv6 address 2001:db8::1/64");
    f.ok(&mut cli, "no shutdown");
    f.ok(&mut cli, "dhcp-relay server 203.0.113.10");
    f.ok(&mut cli, "dhcp-relay enable");
    f.ok(&mut cli, "exit");
    f.ok(
        &mut cli,
        "ip route 203.0.113.0/24 uplink.10 198.51.100.2 10000 10",
    );
    f.ok(
        &mut cli,
        "ip route 198.51.100.0/24 uplink.10 direct 10001 20",
    );
    f.ok(
        &mut cli,
        "no ip route 198.51.100.0/24 uplink.10 direct 10001 20",
    );
    assert!(
        f.command(&mut cli, "policy-rule 10000 192.0.2.0/24 10000")
            .failed
    );
    assert!(f.command(&mut cli, "no policy-rule 10000").failed);
    assert!(f.command(&mut cli, "show policy-rules").failed);
    f.ok(&mut cli, "firewall policy drop");
    f.ok(&mut cli, "firewall allow-all-icmp disable");
    f.ok(&mut cli, "firewall rule 192.0.2.0/24 any accept");
    f.ok(&mut cli, "nat masquerade ipv4 uplink.10 192.0.2.0/24");
    f.ok(&mut cli, "syslog server logs.example.test 6514 tls");
    f.ok(&mut cli, "syslog enable");
    f.ok(&mut cli, "vnstat enable");
    f.ok(
        &mut cli,
        "kernel namespace net.ipv4.tcp_congestion_control cubic",
    );
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    let config = &f.request("/api/v1/state")["desired"];
    assert!(config.get("policy_rules").is_none());
    assert_eq!(config["interfaces"].as_array().unwrap().len(), 2);
    assert_eq!(config["routes"].as_array().unwrap().len(), 1);
    assert_eq!(config["routes"][0]["enabled"], true);
    assert_eq!(config["firewall"]["policy"], "drop");
    assert_eq!(config["syslog"]["enabled"], true);
    assert_eq!(config["vnstat"]["enabled"], true);
}

#[test]
fn restore_uses_new_transaction_and_requires_explicit_confirmation() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "firewall policy drop");
    f.ok(&mut cli, "commit confirmed 30");
    f.ok(&mut cli, "confirm");
    f.ok(
        &mut cli,
        "restore revision 0 confirmed 30 return to initial",
    );
    assert_eq!(f.request("/api/v1/state")["revision"], 1);
    f.ok(&mut cli, "confirm");
    assert_eq!(f.request("/api/v1/state")["revision"], 2);
    assert_eq!(
        f.request("/api/v1/state")["desired"]["firewall"]["policy"],
        "accept"
    );
    assert!(
        f.ok(&mut cli, "show revisions")
            .contains("restored_from_revision")
    );
    f.ok(&mut cli, "configure terminal");
    f.fail(&mut cli, "restore revision 0 confirmed 30", "discard");
}

#[test]
fn commands_are_bounded_and_not_shell_or_immediate_writes() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    for command in [
        "show runtime\nshow state",
        "show runtime\r",
        "show \u{1b}[2J",
        "show\tstate",
        "sh -c id",
        "enable; configure terminal",
    ] {
        assert!(f.command(&mut cli, command).failed, "{command:?}");
    }
    f.fail(&mut cli, &"x".repeat(LINE_LIMIT + 1), "exceeds");
    f.configure(&mut cli);
    f.fail(&mut cli, "commit", "commit confirmed");
    f.fail(&mut cli, "commit confirmed 9", "10..300");
    f.fail(&mut cli, "commit confirmed 301", "10..300");
    f.ok(&mut cli, "load candidate {}");
    f.ok(&mut cli, "load   candidate   {\"ntp\":{\"servers\":[]}}");
    f.ok(&mut cli, "set    /ntp/enabled    false");
    assert_eq!(
        serde_json::from_value::<Config>(json!({})).unwrap(),
        Config::empty()
    );
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
}

#[test]
fn every_current_example_can_be_loaded_checked_and_edited_without_live_writes() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    for input in [
        include_str!("../../../examples/appliance-services.json"),
        include_str!("../../../examples/dhcp-relay.json"),
        include_str!("../../../examples/gateway-monitoring.json"),
        include_str!("../../../examples/host-policies.json"),
        include_str!("../../../examples/kernel-mixed-conservative.json"),
        include_str!("../../../examples/migration.json"),
        include_str!("../../../examples/vlan-softflowd.json"),
    ] {
        let input: Value = serde_json::from_str(input).unwrap();
        let config = input.get("config").unwrap_or(&input);
        f.ok(&mut cli, &format!("load candidate {config}"));
        f.ok(&mut cli, "commit check");
        f.ok(&mut cli, "set /firewall/allow_all_icmp false");
        f.ok(&mut cli, "commit check");
    }
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
}

#[test]
fn wireguard_peer_can_be_disabled_and_reenabled_without_losing_its_settings() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "interface wg0 wireguard");
    f.ok(&mut cli, "role wan");
    f.ok(&mut cli, "mtu 1420");
    f.ok(&mut cli, "wireguard key-ref wg0");
    f.ok(&mut cli, "wireguard listen-port 51820");
    let public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let peer = json!({
        "public_key":public_key,"endpoint":"203.0.113.1:51820",
        "allowed_ips":["198.51.100.0/24"],"persistent_keepalive_seconds":25
    });
    f.ok(&mut cli, &format!("wireguard peer {peer}"));
    f.ok(&mut cli, "exit");
    let enabled = |cli: &mut CliSession| -> Value {
        let output = f.ok(cli, "show candidate-config");
        let json = output.split_once(":\n").unwrap().1;
        let candidate: Value = serde_json::from_str(json).unwrap();
        candidate["interfaces"][0]["wireguard"]["peers"][0]["enabled"].clone()
    };
    assert_eq!(enabled(&mut cli), true);
    f.ok(
        &mut cli,
        "set /interfaces/0/wireguard/peers/0/enabled false",
    );
    f.ok(&mut cli, "commit check");
    assert_eq!(enabled(&mut cli), false);
    let candidate = f.ok(&mut cli, "show candidate-config");
    assert!(candidate.contains(public_key) && candidate.contains("203.0.113.1:51820"));
    f.fail(
        &mut cli,
        "set /interfaces/0/wireguard/peers/0/enabled null",
        "",
    );
    f.fail(
        &mut cli,
        "set /interfaces/0/wireguard/peers/0/enabled \"no\"",
        "",
    );
    f.ok(&mut cli, "set /interfaces/0/wireguard/peers/0/enabled true");
    assert_eq!(enabled(&mut cli), true);
    f.ok(&mut cli, "interface wg0");
    let disabled =
        json!({"enabled":false,"public_key":public_key,"allowed_ips":["198.51.100.0/24"]});
    f.ok(&mut cli, &format!("wireguard peer {disabled}"));
    f.ok(&mut cli, "exit");
    assert_eq!(enabled(&mut cli), false);
    f.ok(&mut cli, "commit check");
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
}

#[test]
fn wireguard_peer_staging_and_removal_preserve_interface_settings() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.ok(&mut cli, "interface wg0 wireguard");
    f.ok(&mut cli, "role wan");
    f.ok(&mut cli, "mtu 1420");
    f.ok(&mut cli, "wireguard key-ref wg0");
    f.ok(&mut cli, "wireguard listen-port 51820");
    let public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let peer = json!({
        "public_key":public_key,"endpoint":"203.0.113.1:51820",
        "allowed_ips":["198.51.100.0/24"],"persistent_keepalive_seconds":25
    });
    f.ok(&mut cli, &format!("wireguard peer {peer}"));
    f.ok(&mut cli, "commit check");
    f.ok(&mut cli, &format!("no wireguard peer {public_key}"));
    f.ok(&mut cli, "commit check");
    assert!(!f.ok(&mut cli, "show candidate-config").contains(public_key));
    f.fail(&mut cli, "vlan id 10", "not a VLAN");
    f.ok(&mut cli, "exit");
    f.fail(&mut cli, "interface wg0 dummy", "kind differs");
}

#[test]
fn confirmation_timeout_rolls_back_even_after_cli_session_is_dropped() {
    let f = Fixture::new(PERMISSIONS);
    let mut cli = CliSession::new();
    f.configure(&mut cli);
    f.interface(&mut cli, "lan0");
    f.ok(&mut cli, "commit confirmed 10");
    let state = f.request("/api/v1/state");
    let id = state["active_transaction"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    drop(cli);
    std::thread::sleep(std::time::Duration::from_millis(10_100));
    f.app.engine.lock().unwrap().tick().unwrap();
    assert_eq!(
        f.request(&format!("/api/v1/transactions/{id}"))["status"],
        "rolled_back"
    );
    assert_eq!(f.request("/api/v1/state")["revision"], 0);
    assert!(
        f.request("/api/v1/state")["observed"]["interfaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
