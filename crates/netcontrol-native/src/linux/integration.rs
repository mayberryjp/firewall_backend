use super::*;
use std::{ffi::CString, os::unix::fs::DirBuilderExt};

struct Fixture {
    root: PathBuf,
    namespace: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self> {
        ensure!(
            std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
            "set NETCONTROL_INTEGRATION=1 for privileged native integration tests"
        );
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::env::current_dir()?.join(format!(
            ".native-integration-{}-{stamp}",
            std::process::id()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let namespace = root.join("namespace");
        File::create(&namespace)?;
        let target = namespace.clone();
        let created = std::thread::spawn(move || -> Result<()> {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                "unshare network namespace requires CAP_SYS_ADMIN: {}",
                std::io::Error::last_os_error()
            );
            let source = CString::new("/proc/thread-self/ns/net")?;
            let target = CString::new(target.as_os_str().as_encoded_bytes())?;
            ensure!(
                unsafe {
                    libc::mount(
                        source.as_ptr(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                } == 0,
                "pin test namespace requires mount privilege: {}",
                std::io::Error::last_os_error()
            );
            Ok(())
        })
        .join()
        .map_err(|_| anyhow!("namespace fixture worker panic"))?;
        if let Err(error) = created {
            let _ = fs::remove_dir_all(&root);
            return Err(error);
        }
        Ok(Self { root, namespace })
    }
    fn options(&self) -> NativeOptions {
        NativeOptions {
            namespace: self.namespace.to_string_lossy().into_owned(),
            keys: self.root.join("keys"),
            services_state: self.root.join("services"),
            adopted_parents: Vec::new(),
            allow_host_tunables: false,
            allow_host_services: false,
            gateway_monitoring: false,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let target = CString::new(self.namespace.as_os_str().as_encoded_bytes()).unwrap();
        let unmounted = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
        if unmounted == 0 {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn config(value: Value) -> Result<Config> {
    Ok(serde_json::from_value(value)?)
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_vnstat_statistics_delegates_live_history_and_scope() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    options.allow_host_services = true;
    let mut native = Native::open(options)?;
    let empty = Config::empty();
    native.repair(&empty)?;
    assert!(
        native
            .statistics(&empty, "/api/v1/statistics/vnstat", "")
            .unwrap_err()
            .to_string()
            .contains("disabled")
    );
    let mut desired = serde_json::to_value(&empty)?;
    desired["vnstat"] = json!({"enabled":true});
    let desired = config(desired)?;
    native.apply(&empty, &desired)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let all = loop {
        match native.statistics(&desired, "/api/v1/statistics/vnstat", "") {
            Ok(value) => break value,
            Err(error)
                if error.to_string().contains("traffic history unavailable")
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    };
    assert_eq!(all["schema"], "netcontrol-services/counters/v1");
    assert_eq!(all["scope"], native.scope()?);
    assert_eq!(all["scopes"].as_object().unwrap().len(), 2);
    for name in ["host", "managed"] {
        let path = format!("/api/v1/statistics/vnstat/{name}");
        let selected = native.statistics(&desired, &path, "")?;
        assert_eq!(selected["scopes"].as_object().unwrap().len(), 1);
        assert_eq!(selected["scopes"][name]["scope"], name);
        assert_eq!(selected["scope"], all["scope"]);
        assert!(native.statistics(&desired, &path, "limit=1").is_err());
    }
    assert!(
        native
            .statistics(&desired, "/api/v1/statistics/vnstat/other", "")
            .is_err()
    );
    native.services.shutdown()?;
    assert!(native.observe(&desired).is_err());
    assert_eq!(
        serde_json::to_value(native.observe_for_repair(&desired)?)?,
        serde_json::to_value(&desired)?
    );
    let repaired = native.repair(&desired)?;
    for name in ["vnstat-host", "vnstat-managed"] {
        let worker = repaired["appliance_services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        assert_eq!(worker["state"], "running");
    }
    native.observe(&desired)?;
    native.apply(&desired, &empty)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft/WireGuard modules"]
fn native_links_routes_rules_firewall_sysctl_rollback_and_restart() -> Result<()> {
    let fixture = Fixture::new()?;
    fs::create_dir(&fixture.options().keys)?;
    let mut key = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(fixture.options().keys.join("wg-key"))?;
    key.write_all(wireguard_control::Key([1u8; 32]).to_base64().as_bytes())?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut value = serde_json::to_value(&empty)?;
    value["interfaces"] = json!([
        {"name":"trunk0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":["192.0.2.2/24"],"dhcp_relay":{"enabled":false,"servers":[]}},
        {"name":"vlan100","kind":"vlan","role":"lan","mtu":1400,"up":true,"addresses":["198.51.100.2/24","2001:db8:100::2/64"],"vlan":{"parent":"trunk0","id":100},"dhcp_relay":{"enabled":false,"servers":[]}},
        {"name":"wg0","kind":"wireguard","role":"lan","mtu":1380,"up":true,"addresses":["2001:db8:200::2/64"],"wireguard":{"key_ref":"wg-key","listen_port":51820,"peers":[]},"dhcp_relay":{"enabled":false,"servers":[]}}
    ]);
    value["routes"] = json!([
        {"destination":"203.0.113.0/24","interface":"trunk0","gateway":"192.0.2.1","table":10000,"metric":10},
        {"destination":"2001:db8:300::/64","interface":"wg0","table":10001,"metric":10}
    ]);
    value["policy_rules"] = json!([
        {"source":"192.0.2.0/24","table":10000,"priority":10000},
        {"source":"::/0","table":10001,"priority":10001}
    ]);
    value["kernel"]["namespace"] = json!({"net.ipv4.tcp_syncookies":"1"});
    value["firewall"] = json!({"policy":"drop","allow_all_icmp":true,"rules":[{"source":"192.0.2.0/24","action":"accept"},{"action":"drop"}],"nat":{"masquerade":[{"family":"ipv4","source":"198.51.100.0/24","out_interface":"trunk0"},{"family":"ipv6","source":"2001:db8:100::/64","out_interface":"wg0"}]}});
    let after = config(value)?;
    native.apply(&empty, &after)?;
    assert_eq!(
        serde_json::to_value(native.observe(&after)?)?,
        serde_json::to_value(&after)?
    );
    let scope = native.scope()?;
    let runtime = native.runtime(&after)?;
    assert_eq!(runtime["wireguard"][0]["listen_port"], 51820);
    assert!(
        runtime["kernel_tunables"]["captured_original"]["namespace"]["net.ipv4.tcp_syncookies"]
            .is_string()
    );
    let original =
        runtime["kernel_tunables"]["captured_original"]["namespace"]["net.ipv4.tcp_syncookies"]
            .clone();
    let statistics = native.statistics(&after, "/api/v1/statistics/interfaces/trunk0", "")?;
    assert_eq!(statistics["interface"]["name"], "trunk0");
    assert!(statistics["interface"]["counters"]["rx_bytes"].is_string());
    drop(native);
    let mut native = Native::open(fixture.options())?;
    assert_eq!(native.scope()?, scope);
    native.observe(&after)?;
    native.apply(&after, &empty)?;
    native.observe(&empty)?;
    assert_eq!(
        native.runtime(&empty)?["kernel_tunables"]["observed"]["namespace"]["net.ipv4.tcp_syncookies"],
        original
    );
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_preserves_unmanaged_links_and_adopted_parent() -> Result<()> {
    let fixture = Fixture::new()?;
    let namespace = Arc::new(open_namespace(&fixture.namespace)?);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle.link().add().dummy("uplink".into()).execute().await?;
            Ok(())
        })
    })?;
    let mut options = fixture.options();
    options.adopted_parents.push("uplink".into());
    let mut native = Native::open(options)?;
    let empty = Config::empty();
    native.repair(&empty)?;
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .dummy("foreign".into())
                .execute()
                .await?;
            Ok(())
        })
    })?;
    native.observe(&empty)?;
    native.observe_for_repair(&empty)?;
    native.repair(&empty)?;
    native.apply(&empty, &empty)?;
    let names = session(namespace, |rt, handle| {
        rt.block_on(async {
            use futures_util::TryStreamExt;
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            Ok(links
                .into_iter()
                .flat_map(|l| l.attributes)
                .filter_map(|a| {
                    if let netlink_packet_route::link::LinkAttribute::IfName(v) = a {
                        Some(v)
                    } else {
                        None
                    }
                })
                .collect::<BTreeSet<_>>())
        })
    })?;
    assert!(names.contains("foreign") && names.contains("uplink"));
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_firewall_external_mutation_is_detected() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    session(native.namespace.clone(), |_, _| {
        let table = rustables::Table::new(rustables::ProtocolFamily::Inet).with_name("netcontrol");
        let chain = rustables::Chain::new(&table).with_name("forward");
        let mut batch = rustables::Batch::new();
        rustables::Rule::new(&chain)?
            .drop()
            .add_to_batch(&mut batch);
        batch.send()?;
        Ok(())
    })?;
    assert!(native.observe(&empty).is_err());
    assert!(
        native
            .observe_for_repair(&empty)
            .unwrap_err()
            .downcast_ref::<netcontrol_core::BackendDrift>()
            .is_some()
    );
    assert!(native.repair(&empty).is_err());
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_durable_intent_restores_interrupted_network_changes() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let before = serde_json::to_value(&empty)?;
    let mut after = before.clone();
    after["interfaces"] = json!([{"name":"partial0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":[],"dhcp_relay":{"enabled":false,"servers":[]}}]);
    let ownership = native.ownership()?;
    let intent = Intent {
        scope: native.identity.clone(),
        before: before.clone(),
        after: after.clone(),
        kernel_before: Kernel::default(),
        ownership_before: ownership.clone(),
        ethernet_before: BTreeMap::new(),
        ethernet_originals: BTreeMap::new(),
    };
    write_json(&native.state.join("intent.json"), &intent)?;
    let mut ownership_after = ownership;
    native.network_apply(&before, &after, Kernel::default(), &mut ownership_after)?;
    drop(native);
    let mut recovered = Native::open(fixture.options())?;
    assert!(!recovered.state.join("intent.json").exists());
    recovered.observe(&empty)?;
    Ok(())
}
