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
fn native_blackhole_routes_drop_traffic_change_action_rename_rollback_and_restart() -> Result<()> {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let build = |name: &str, action: &str| -> Result<Config> {
        let config = config(json!({
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,
                "addresses":["192.0.2.1/24","2001:db8::1/64"]}],
            "blackhole":{"name":name,"action":action},
            "routes":[
                {"enabled":true,"destination":"198.51.100.0/24","interface":name,"table":254,"metric":50},
                {"enabled":true,"destination":"2001:db8:dead::/48","interface":name,"table":254,"metric":50},
                {"enabled":true,"destination":"203.0.113.0/24","interface":name,"table":10000,"metric":60},
                {"enabled":true,"destination":"192.0.2.128/25","interface":"lan0","table":254,"metric":70}
            ]
        }))?;
        config.validate()?;
        Ok(config)
    };
    // The kernel's own verdict when a socket tries to reach each blackholed destination.
    let verdict = |native: &Native, destination: &str| -> Result<Option<i32>> {
        let destination: std::net::IpAddr = destination.parse()?;
        session(native.namespace.clone(), move |_, _| {
            let socket = std::net::UdpSocket::bind(if destination.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })?;
            Ok(socket
                .connect((destination, 9))
                .err()
                .and_then(|error| error.raw_os_error()))
        })
    };
    let installed = |native: &Native, desired: &Config| -> Result<usize> {
        let network = Network::parse(&desired.operational_value()?)?;
        let keys = options.keys.clone();
        session(native.namespace.clone(), move |rt, handle| {
            let snapshot = rt.block_on(networking::boot_snapshot(handle, &network, &keys))?;
            Ok(snapshot["routes"].as_array().unwrap().len())
        })
    };
    let blackhole = build("bh0", "blackhole")?;
    native.apply(&empty, &blackhole)?;
    assert_eq!(native.observe(&blackhole)?, blackhole);
    assert_eq!(installed(&native, &blackhole)?, 4);
    for destination in ["198.51.100.7", "2001:db8:dead::7"] {
        assert_eq!(
            verdict(&native, destination)?,
            Some(libc::EINVAL),
            "{destination}"
        );
    }
    assert_eq!(verdict(&native, "192.0.2.200")?, None);

    let unreachable = build("bh0", "unreachable")?;
    native.apply(&blackhole, &unreachable)?;
    assert_eq!(native.observe(&unreachable)?, unreachable);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::EHOSTUNREACH));
    assert_eq!(
        verdict(&native, "2001:db8:dead::7")?,
        Some(libc::EHOSTUNREACH)
    );
    let prohibit = build("bh0", "prohibit")?;
    native.apply(&unreachable, &prohibit)?;
    assert_eq!(native.observe(&prohibit)?, prohibit);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::EACCES));
    assert_eq!(verdict(&native, "2001:db8:dead::7")?, Some(libc::EACCES));

    // Renaming leaves identical kernel routes and must not be treated as drift.
    let renamed = build("drop0", "prohibit")?;
    native.apply(&prohibit, &renamed)?;
    assert_eq!(native.observe(&renamed)?, renamed);
    assert_eq!(installed(&native, &renamed)?, 4);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::EACCES));

    let mut disabled = renamed.clone();
    disabled.routes[0].enabled = false;
    native.apply(&renamed, &disabled)?;
    assert_eq!(installed(&native, &disabled)?, 3);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::ENETUNREACH));
    native.apply(&disabled, &renamed)?;

    drop(native);
    let mut native = Native::open(options.clone())?;
    native.repair(&renamed)?;
    assert_eq!(native.observe(&renamed)?, renamed);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::EACCES));

    let mut failing = build("drop0", "blackhole")?;
    failing.ntp.enabled = true;
    failing.ntp.servers = vec!["192.0.2.123".into()];
    assert!(native.apply(&renamed, &failing).is_err());
    assert_eq!(native.observe(&renamed)?, renamed);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::EACCES));

    native.apply(&renamed, &empty)?;
    assert_eq!(installed(&native, &empty)?, 0);
    assert_eq!(verdict(&native, "198.51.100.7")?, Some(libc::ENETUNREACH));
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_static_route_enabled_toggle_restart_and_rollback() -> Result<()> {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let active = config(json!({
        "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":1500,"up":true,
            "addresses":["192.0.2.1/24","2001:db8::1/64"]}],
        "routes":[
            {"enabled":true,"destination":"203.0.113.0/24","interface":"lan0","table":10000,"metric":10},
            {"enabled":true,"destination":"2001:db8:10::/64","interface":"lan0","table":10001,"metric":10}
        ]
    }))?;
    active.validate()?;
    let installed = |native: &Native, desired: &Config| -> Result<usize> {
        let network = Network::parse(&desired.operational_value()?)?;
        let keys = options.keys.clone();
        session(native.namespace.clone(), move |rt, handle| {
            let snapshot = rt.block_on(networking::boot_snapshot(handle, &network, &keys))?;
            Ok(snapshot["routes"].as_array().unwrap().len())
        })
    };
    let mut disabled = active.clone();
    for route in &mut disabled.routes {
        route.enabled = false;
    }
    native.apply(&empty, &disabled)?;
    assert_eq!(installed(&native, &disabled)?, 0);
    assert_eq!(native.observe(&disabled)?, disabled);
    native.apply(&disabled, &active)?;
    assert_eq!(installed(&native, &active)?, 2);
    native.apply(&active, &disabled)?;
    assert_eq!(installed(&native, &disabled)?, 0);
    drop(native);
    let mut native = Native::open(options.clone())?;
    native.repair(&disabled)?;
    assert_eq!(native.observe(&disabled)?, disabled);
    assert_eq!(installed(&native, &disabled)?, 0);
    native.apply(&disabled, &active)?;
    assert_eq!(installed(&native, &active)?, 2);
    native.apply(&active, &disabled)?;
    assert_eq!(native.observe(&disabled)?, disabled);
    assert_eq!(installed(&native, &disabled)?, 0);
    native.apply(&disabled, &empty)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn global_ipv6_disables_existing_loopback_and_future_links_and_restores() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .dummy("unmanaged0".into())
                .execute()
                .await?;
            let links = networking::links(handle).await?;
            for name in ["lo", "unmanaged0"] {
                let index = links
                    .iter()
                    .find(|l| networking::name(l) == name)
                    .unwrap()
                    .header
                    .index;
                handle.link().set(index).up().execute().await?;
                if name == "unmanaged0" {
                    handle
                        .address()
                        .add(index, "2001:db8::1".parse()?, 64)
                        .execute()
                        .await?;
                    handle
                        .route()
                        .add()
                        .v6()
                        .destination_prefix("2001:db8:20::".parse()?, 64)
                        .output_interface(index)
                        .priority(123)
                        .protocol(netlink_packet_route::route::RouteProtocol::Static)
                        .execute()
                        .await?;
                }
            }
            Ok(())
        })
    })?;
    let mut disabled = empty.clone();
    disabled.ipv6_enabled = false;
    native.apply(&empty, &disabled)?;
    session(native.namespace.clone(), |rt, handle| {
        ipv6::verify(false)?;
        rt.block_on(async {
            handle
                .link()
                .add()
                .dummy("future0".into())
                .execute()
                .await?;
            for link in networking::links(handle).await? {
                assert!(
                    networking::addresses(handle, link.header.index)
                        .await?
                        .iter()
                        .all(|a| a.header.family != netlink_packet_route::AddressFamily::Inet6)
                );
            }
            Ok(())
        })
    })?;
    drop(native);
    let mut native = Native::open(fixture.options())?;
    native.repair(&disabled)?;
    native.observe(&disabled)?;
    native.apply(&disabled, &empty)?;
    session(native.namespace.clone(), |rt, handle| {
        ipv6::verify(true)?;
        rt.block_on(async {
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|l| networking::name(l) == "unmanaged0")
                .unwrap();
            assert!(
                networking::addresses(handle, link.header.index)
                    .await?
                    .iter()
                    .any(|a| networking::address_string(a).unwrap().as_deref()
                        == Some("2001:db8::1/64"))
            );
            use futures_util::TryStreamExt;
            use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
            let routes: Vec<RouteMessage> = handle.route().get(rtnetlink::IpVersion::V6)
                .execute().try_collect().await?;
            assert!(routes.iter().any(|route| route.attributes.iter().any(|a|
                matches!(a, RouteAttribute::Destination(RouteAddress::Inet6(ip)) if *ip == "2001:db8:20::".parse::<std::net::Ipv6Addr>().unwrap()))));
            Ok(())
        })
    })?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn global_ipv6_managed_addresses_routes_and_interrupted_disable_recover() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let dual = config(json!({
        "interfaces":[{"name":"dual0","kind":"dummy","role":"lan","mtu":1500,"up":true,
            "addresses":["192.0.2.1/24","2001:db8::1/64"]}],
        "routes":[{"enabled":true,"destination":"2001:db8:10::/64","interface":"dual0","table":10000,"metric":10}]
    }))?;
    native.apply(&empty, &dual)?;
    let mut disabled = dual.clone();
    disabled.ipv6_enabled = false;
    disabled.interfaces[0]
        .addresses
        .retain(|address| !address.contains(':'));
    disabled.routes.clear();
    native.apply(&dual, &disabled)?;
    native.observe(&disabled)?;
    native.apply(&disabled, &dual)?;
    native.observe(&dual)?;

    let before = dual.operational_value()?;
    let after = disabled.operational_value()?;
    let ownership = native.ownership()?;
    let intent = Intent {
        scope: native.identity.clone(),
        before: before.clone(),
        after: after.clone(),
        kernel_before: native.capture_kernel(&before, &after)?,
        ownership_before: ownership.clone(),
        ethernet_before: BTreeMap::new(),
        ethernet_originals: BTreeMap::new(),
        ipv6_before: native.capture_ipv6(&before)?,
    };
    write_json(&native.state.join("intent.json"), &intent)?;
    let mut provisional = ownership;
    native.network_apply(&before, &after, Kernel::default(), &mut provisional)?;
    drop(native);
    let mut native = Native::open(fixture.options())?;
    assert!(!native.state.join("intent.json").exists());
    native.observe(&dual)?;
    assert_eq!(native.runtime(&dual)?["ipv6"]["drift"], false);
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft/conntrack modules"]
fn native_connection_statistics_observe_udp_without_mutating_owned_state() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut desired = serde_json::to_value(&empty)?;
    desired["firewall"]["input"] = json!({"policy":"accept","interfaces":[]});
    let desired = config(desired)?;
    native.apply(&empty, &desired)?;
    let port = session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let index = networking::links(handle)
                .await?
                .iter()
                .find(|link| networking::name(link) == "lo")
                .context("loopback missing")?
                .header
                .index;
            handle.link().set(index).up().execute().await?;
            let server = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let client = std::net::UdpSocket::bind("127.0.0.1:0")?;
            for socket in [&server, &client] {
                socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
            }
            client.send_to(b"request", server.local_addr()?)?;
            let mut bytes = [0; 32];
            let (_, source) = server.recv_from(&mut bytes)?;
            server.send_to(b"reply", source)?;
            client.recv_from(&mut bytes)?;
            Ok(server.local_addr()?.port())
        })
    })?;
    let ownership = fs::read(native.state.join("ownership.json"))?;
    let fingerprint = session(native.namespace.clone(), |_, _| netfilter::fingerprint())?;
    let result = native.statistics(
        &desired,
        "/api/v1/statistics/connections",
        &format!("protocol=udp&port={port}"),
    )?;
    assert_eq!(result["schema"], "netcontrol-connections/v1");
    assert_eq!(result["sample"]["scope"], native.identity);
    assert_eq!(result["summary"]["matched"], 1);
    assert_eq!(
        result["connections"][0]["original"]["destination_port"],
        port
    );
    assert_eq!(result["connections"][0]["original"]["source"], "127.0.0.1");
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
    assert_eq!(
        session(native.namespace.clone(), |_, _| netfilter::fingerprint())?,
        fingerprint
    );
    native.observe(&desired)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespace/net_admin privileges and nft/conntrack modules"]
fn native_connection_delete_targets_one_entry_then_flushes_only_its_namespace() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut value = serde_json::to_value(&empty)?;
    value["firewall"]["input"] = json!({"policy":"accept","interfaces":[]});
    let desired = config(value)?;
    native.apply(&empty, &desired)?;
    let ports = session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let index = networking::links(handle)
                .await?
                .iter()
                .find(|link| networking::name(link) == "lo")
                .context("loopback missing")?
                .header
                .index;
            handle.link().set(index).up().execute().await?;
            let mut ports = Vec::new();
            let mut sockets = Vec::new();
            for _ in 0..2 {
                let server = std::net::UdpSocket::bind("127.0.0.1:0")?;
                server.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                let client = std::net::UdpSocket::bind("127.0.0.1:0")?;
                client.send_to(b"fixture", server.local_addr()?)?;
                server.recv_from(&mut [0; 32])?;
                ports.push(server.local_addr()?.port());
                sockets.extend([server, client]);
            }
            Ok(ports)
        })
    })?;
    let ownership = fs::read(native.state.join("ownership.json"))?;
    let fingerprint = session(native.namespace.clone(), |_, _| netfilter::fingerprint())?;
    let path = "/api/v1/statistics/connections";
    let snapshot = native.statistics(&desired, path, &format!("protocol=udp&port={}", ports[0]))?;
    assert_eq!(snapshot["summary"]["matched"], 1);
    let entry = &snapshot["connections"][0];
    let id: u32 = entry["id"]
        .as_str()
        .context("kernel conntrack ID missing")?
        .parse()?;
    let target: netcontrol_core::ConnectionTarget = serde_json::from_value(
        json!({"family":entry["family"],"protocol":entry["protocol"],"zone":entry["zone"],"original":entry["original"]}),
    )?;
    let error = native
        .delete_connections(Some((id.wrapping_add(1), &target)))
        .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .context("expected typed kernel error")?
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        native.delete_connections(Some((id, &target)))?["status"],
        "deleted"
    );
    assert_eq!(
        native.statistics(&desired, path, &format!("protocol=udp&port={}", ports[0]))?["summary"]["matched"],
        0
    );
    assert_eq!(
        native.statistics(&desired, path, &format!("protocol=udp&port={}", ports[1]))?["summary"]["matched"],
        1
    );
    assert!(native.delete_connections(Some((id, &target))).is_err());
    assert_eq!(native.delete_connections(None)?["status"], "flushed");
    assert_eq!(
        native.statistics(&desired, path, "")?["summary"]["total"],
        0
    );
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
    assert_eq!(
        session(native.namespace.clone(), |_, _| netfilter::fingerprint())?,
        fingerprint
    );
    native.observe(&desired)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_dhcp_gateway_waiting_apply_rollback_reopen_and_recovery() -> Result<()> {
    let fixture = Fixture::new()?;
    let namespace = Arc::new(File::open(&fixture.namespace)?);
    session(namespace, |runtime, handle| {
        runtime.block_on(async {
            handle
                .link()
                .add()
                .veth("wan0".into(), "peer0".into())
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let mut options = fixture.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut desired = config(
        json!({"interfaces":[{"name":"wan0","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":[]}],
        "dhcp_clients":{"wan0":{}},
        "routes":[{"destination":"198.51.100.0/24","gateway":"192.0.2.1","interface":"wan0","table":254,"metric":10}],
        "gateway_monitors":[{"name":"wan","mode":"dhcp","enabled":true,"interface":"wan0","target":"1.1.1.1"}]}),
    )?;
    desired.normalize();
    desired.validate()?;
    let ownership_before = fs::read(native.state.join("ownership.json"))?;
    let error = native.apply(&empty, &desired).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit allow_gateway_monitoring"),
        "{error:#}"
    );
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(
        fs::read(native.state.join("ownership.json"))?,
        ownership_before
    );
    native.apply(&desired, &empty)?;
    native.observe(&empty)?;
    drop(native);
    options.gateway_monitoring = true;
    let mut native = Native::open(options.clone())?;
    native.repair(&empty)?;
    native.apply(&empty, &desired)?;
    native.observe(&desired)?;
    let mut route_disabled = desired.clone();
    route_disabled.routes[0].enabled = false;
    native.apply(&desired, &route_disabled)?;
    native.observe(&route_disabled)?;
    native.apply(&route_disabled, &desired)?;
    native.observe(&desired)?;
    let runtime = native.runtime(&desired)?;
    assert_eq!(runtime["gateway_monitors"][0]["health"], "unknown");
    assert_eq!(runtime["gateway_monitors"][0]["process_state"], "waiting");
    assert_eq!(
        native.statistics(&desired, "/api/v1/statistics/gateways/wan", "")?["monitor"]["health"],
        "unknown"
    );
    let mut disabled = desired.clone();
    disabled.gateway_monitors[0].enabled = false;
    native.apply(&desired, &disabled)?;
    assert_eq!(
        native.runtime(&disabled)?["gateway_monitors"][0]["process_state"],
        "disabled"
    );
    native.apply(&disabled, &desired)?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    native.repair(&desired)?;
    native.observe(&desired)?;
    let mut deleted = desired.clone();
    deleted.gateway_monitors.clear();
    let before = desired.operational_value()?;
    let after = deleted.operational_value()?;
    let intent = Intent {
        scope: native.identity.clone(),
        before: before.clone(),
        after: after.clone(),
        kernel_before: native.capture_kernel(&before, &after)?,
        ownership_before: native.ownership()?,
        ethernet_before: BTreeMap::new(),
        ethernet_originals: native.ownership()?.ethernet_originals,
        ipv6_before: native.capture_ipv6(&before)?,
    };
    write_json(&native.state.join("intent.json"), &intent)?;
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&desired)?;
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(
        native.runtime(&desired)?["gateway_monitors"][0]["process_state"],
        "waiting"
    );
    native.apply(&desired, &deleted)?;
    assert_eq!(native.runtime(&deleted)?["gateway_monitors"], json!([]));
    native.apply(&deleted, &empty)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_dhcp_installs_connected_route_before_default_gateway() -> Result<()> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::{
        address::AddressAttribute,
        route::{RouteAttribute, RouteProtocol},
    };
    use rtnetlink::IpVersion;

    let fixture = Fixture::new()?;
    let namespace = Arc::new(File::open(&fixture.namespace)?);
    session(namespace, |rt, handle| {
        rt.block_on(async {
            handle.link().add().dummy("dhcp0".into()).execute().await?;
            let index = networking::links(handle).await?.iter()
                .find(|link| networking::name(link) == "dhcp0")
                .context("test DHCP interface missing")?.header.index;
            handle.link().set(index).up().execute().await?;
            let lease: dhcp_client::Lease = serde_json::from_value(json!({
                "client": {}, "address": "192.0.2.10/24", "server": "192.0.2.1",
                "acquired_at": dhcp_client::now()?, "lifetime": 3600,
                "renewal": 1800, "rebinding": 3150,
                "routes": [
                    {"destination": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "dhcp0", "table": 254, "metric": 0},
                    {"destination": "192.0.2.0/24", "gateway": "", "interface": "dhcp0", "table": 254, "metric": 0}
                ], "dns": [], "domain": "", "mtu": null
            }))?;
            let addressing = dhcp_client::Addressing { mtu: 1500, ..Default::default() };
            networking::dhcp_lease(handle, "dhcp0", None, Some(&lease), &addressing, false).await?;
            let addresses: Vec<_> = handle.address().get().set_link_index_filter(index)
                .execute().try_collect().await?;
            let leased_ip = "192.0.2.10".parse::<std::net::IpAddr>()?;
            assert!(addresses.iter().any(|address| address.attributes.iter().any(
                |attribute| matches!(attribute, AddressAttribute::Local(value) if *value == leased_ip)
            )));
            let routes: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            let owned: Vec<_> = routes.iter().filter(|route| route.header.protocol == RouteProtocol::Other(dhcp_client::PROTOCOL)
                && route.attributes.iter().any(|attribute| matches!(attribute, RouteAttribute::Oif(value) if *value == index))).collect();
            assert_eq!(owned.len(), 2);
            assert!(owned.iter().any(|route| route.header.destination_prefix_length == 0));
            assert!(owned.iter().any(|route| route.header.destination_prefix_length == 24));

            let mut renewed = lease.clone();
            renewed.lifetime = 7200;
            networking::dhcp_lease(handle, "dhcp0", Some(&lease), Some(&renewed), &addressing, false).await?;
            networking::dhcp_lease(handle, "dhcp0", Some(&renewed), None, &addressing, false).await?;
            let addresses: Vec<_> = handle.address().get().set_link_index_filter(index)
                .execute().try_collect().await?;
            assert!(!addresses.iter().any(|address| address.attributes.iter().any(
                |attribute| matches!(attribute, AddressAttribute::Local(value) if *value == leased_ip)
            )));
            let routes: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            assert!(!routes.iter().any(|route| route.header.protocol == RouteProtocol::Other(dhcp_client::PROTOCOL)));
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_dhcp_static_routes_survive_renewal_address_change_expiry_and_rollback() -> Result<()> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::route::{RouteAttribute, RouteProtocol};
    use rtnetlink::IpVersion;

    let fixture = Fixture::new()?;
    session(Arc::new(File::open(&fixture.namespace)?), |rt, handle| {
        rt.block_on(async {
            handle.link().add().dummy("dhcp0".into()).execute().await?;
            let index = networking::links(handle).await?.iter()
                .find(|link| networking::name(link) == "dhcp0")
                .context("test DHCP interface missing")?.header.index;
            handle.link().set(index).up().execute().await?;
            let lease: dhcp_client::Lease = serde_json::from_value(json!({
                "client":{}, "address":"192.0.2.10/24", "server":"192.0.2.1",
                "acquired_at":dhcp_client::now()?, "lifetime":3600,
                "renewal":1800, "rebinding":3150,
                "routes":[
                    {"destination":"0.0.0.0/0","gateway":"192.0.2.1","interface":"dhcp0","table":254,"metric":0},
                    {"destination":"192.0.2.0/24","interface":"dhcp0","table":254,"metric":0}
                ], "dns":[], "domain":"", "mtu":null
            }))?;
            let addressing = dhcp_client::Addressing {
                mtu: 1500,
                routes: serde_json::from_value(json!([
                    {"destination":"198.51.100.0/24","gateway":"192.0.2.1","interface":"dhcp0","table":254,"metric":10},
                    {"destination":"203.0.113.0/24","interface":"dhcp0","table":10001,"metric":20}
                ]))?,
                ..Default::default()
            };
            let owned = || async {
                let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
                let mut routes = messages.iter()
                    .filter(|message| message.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL))
                    .map(|message| networking::decode_route(message, &BTreeMap::from([(index, "dhcp0".into())])))
                    .collect::<Result<Vec<_>>>()?;
                routes.sort();
                Ok::<_, anyhow::Error>(routes)
            };
            let mut expected = addressing.routes.clone();
            expected.sort();
            handle.link().add().dummy("other0".into()).execute().await?;
            let other = networking::links(handle).await?.iter()
                .find(|link| networking::name(link) == "other0")
                .context("unrelated test interface missing")?.header.index;
            handle.link().set(other).up().execute().await?;
            handle.route().add().v4().destination_prefix("198.19.0.0".parse()?, 16)
                .output_interface(other).priority(30).protocol(RouteProtocol::Other(99))
                .scope(netlink_packet_route::route::RouteScope::Link).execute().await?;
            networking::dhcp_lease(handle, "dhcp0", None, Some(&lease), &addressing, false).await?;
            assert_eq!(owned().await?, expected);
            networking::dhcp_lease(handle, "dhcp0", Some(&lease), Some(&lease), &addressing, false).await?;
            assert_eq!(owned().await?, expected);

            // A known configured route lost by the kernel is restored on the next lease update.
            let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            let route = messages.into_iter().find(|message| message.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL))
                .context("static test route missing")?;
            handle.route().del(route).execute().await?;
            networking::dhcp_lease(handle, "dhcp0", Some(&lease), Some(&lease), &addressing, false).await?;
            assert_eq!(owned().await?, expected);

            let mut changed = lease.clone();
            changed.address = "192.0.2.11/24".into();
            networking::dhcp_lease(handle, "dhcp0", Some(&lease), Some(&changed), &addressing, false).await?;
            assert_eq!(owned().await?, expected);
            networking::dhcp_lease(handle, "dhcp0", Some(&changed), None, &addressing, false).await?;
            assert!(owned().await?.is_empty());
            networking::dhcp_lease(handle, "dhcp0", None, Some(&changed), &addressing, false).await?;
            assert_eq!(owned().await?, expected);

            let mut unreachable = changed.clone();
            unreachable.address = "198.18.0.10/24".into();
            unreachable.routes = serde_json::from_value(json!([
                {"destination":"198.18.0.0/24","interface":"dhcp0","table":254,"metric":0}
            ]))?;
            let error = networking::dhcp_lease(handle, "dhcp0", Some(&changed), Some(&unreachable), &addressing, false).await.unwrap_err();
            assert!(format!("{error:#}").contains("restore DHCP-dependent static route"), "{error:#}");
            networking::dhcp_lease(handle, "dhcp0", Some(&unreachable), Some(&changed), &addressing, false).await?;
            assert_eq!(owned().await?, expected);

            // Never replace an operator's route sharing a configured identity.
            let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            for message in messages {
                if message.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL)
                    && message.attributes.iter().any(|attribute| matches!(attribute, RouteAttribute::Priority(10))) {
                    handle.route().del(message).execute().await?;
                }
            }
            handle.route().add().v4().destination_prefix("198.51.100.0".parse()?, 24)
                .gateway("192.0.2.1".parse()?).output_interface(index).priority(10)
                .protocol(RouteProtocol::Other(99)).execute().await?;
            let error = networking::dhcp_lease(handle, "dhcp0", Some(&changed), Some(&changed), &addressing, false).await.unwrap_err();
            assert!(format!("{error:#}").contains("conflicts with existing route"), "{error:#}");
            let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            assert_eq!(messages.iter().filter(|message| message.header.protocol == RouteProtocol::Other(99)).count(), 2);
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_static_routes_rechecked_after_configured_address_replacement() -> Result<()> {
    let fixture = Fixture::new()?;
    let keys = fixture.root.join("keys");
    session(
        Arc::new(File::open(&fixture.namespace)?),
        move |rt, handle| {
            rt.block_on(async {
            let empty = Network::parse(&Config::empty().operational_value()?)?;
            let before = Network::parse(&config(json!({
                "interfaces":[{"name":"test0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":["192.0.2.10/24"]}],
                "routes":[{"destination":"198.51.100.0/24","gateway":"192.0.2.1","interface":"test0","table":254,"metric":10}]
            }))?.operational_value()?)?;
            let mut after = before.clone();
            after.interfaces[0].addresses = vec!["192.0.2.11/24".into()];
            let parents = BTreeMap::new();
            let originals = BTreeMap::new();
            networking::reconcile(handle, &empty, &before, &parents, &keys, &originals).await?;
            networking::verify(handle, &before, &parents, &keys).await?;
            networking::reconcile(handle, &before, &after, &parents, &keys, &originals).await?;
            networking::verify(handle, &after, &parents, &keys).await?;
            networking::reconcile(handle, &after, &before, &parents, &keys, &originals).await?;
            networking::verify(handle, &before, &parents, &keys).await?;
            networking::reconcile(handle, &before, &empty, &parents, &keys, &originals).await?;
            networking::verify(handle, &empty, &parents, &keys).await?;
            Ok(())
        })
        },
    )
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
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_network_only_change_restarts_the_services_it_stopped() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    options.allow_host_services = true;
    let mut native = Native::open(options)?;
    let empty = Config::empty();
    native.repair(&empty)?;
    // The MTU is not part of the services view, so only the stop/start around the apply matters.
    let build = |mtu: u32| -> Result<Config> {
        config(json!({
            "interfaces":[{"name":"lan0","kind":"dummy","role":"lan","mtu":mtu,"up":true,
                "addresses":["192.0.2.1/24"]}],
            "vnstat":{"enabled":true},
            "ntp":{"enabled":true,"servers":["192.0.2.123"]}
        }))
    };
    let first = build(1500)?;
    native.apply(&empty, &first)?;
    native.observe(&first)?;
    let capabilities = fs::read_to_string("/proc/self/status")?;
    let effective = capabilities
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .context("CapEff missing")?;
    if u64::from_str_radix(effective, 16)? & (1 << 25) == 0 {
        let status = native.runtime(&first)?;
        let ntp = status["appliance_services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "ntp")
            .unwrap();
        assert_eq!(ntp["state"], "error");
        assert_eq!(ntp["retrying"], true);
    }
    let second = build(1400)?;
    native.apply(&first, &second)?;
    native.observe(&second)?;
    native.apply(&second, &first)?;
    native.observe(&first)?;
    native.apply(&first, &empty)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft/WireGuard modules"]
fn native_wireguard_peer_enabled_toggle_restart_and_rollback() -> Result<()> {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    wireguard::create_key(&options.keys, "wg-key")?;
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let key = |byte: u8| wireguard_control::Key([byte; 32]).to_base64();
    let build = |first: bool, second: bool| -> Result<Config> {
        let config = config(json!({
            "interfaces":[{"name":"wg0","kind":"wireguard","role":"unassigned","mtu":1420,"up":true,
                "addresses":["192.0.2.10/24"],
                "wireguard":{"key_ref":"wg-key","listen_port":51820,"peers":[
                    {"enabled":first,"public_key":key(5),"endpoint":"192.0.2.50:51820","allowed_ips":["198.51.100.0/24"],"persistent_keepalive_seconds":25},
                    {"enabled":second,"public_key":key(6),"allowed_ips":["203.0.113.0/24"]}]}}]
        }))?;
        config.validate()?;
        Ok(config)
    };
    let installed = |native: &mut Native, config: &Config| -> Result<Vec<String>> {
        let runtime = native.runtime(config)?;
        let mut peers: Vec<String> = runtime["wireguard"][0]["peers"]
            .as_array()
            .context("WireGuard runtime missing")?
            .iter()
            .map(|peer| peer["public_key"].as_str().unwrap().to_owned())
            .collect();
        peers.sort();
        Ok(peers)
    };
    let sorted = |mut keys: Vec<String>| {
        keys.sort();
        keys
    };
    let both = build(true, true)?;
    native.apply(&empty, &both)?;
    assert_eq!(native.observe(&both)?, both);
    assert_eq!(installed(&mut native, &both)?, sorted(vec![key(5), key(6)]));

    let only_second = build(false, true)?;
    native.apply(&both, &only_second)?;
    assert_eq!(native.observe(&only_second)?, only_second);
    assert_eq!(installed(&mut native, &only_second)?, [key(6)]);

    let none = build(false, false)?;
    native.apply(&only_second, &none)?;
    assert_eq!(native.observe(&none)?, none);
    assert!(installed(&mut native, &none)?.is_empty());

    let only_first = build(true, false)?;
    native.apply(&none, &only_first)?;
    assert_eq!(native.observe(&only_first)?, only_first);
    assert_eq!(installed(&mut native, &only_first)?, [key(5)]);

    drop(native);
    let mut native = Native::open(options.clone())?;
    native.repair(&only_first)?;
    assert_eq!(native.observe(&only_first)?, only_first);
    assert_eq!(installed(&mut native, &only_first)?, [key(5)]);

    let mut failing = build(true, true)?;
    failing.ntp.enabled = true;
    failing.ntp.servers = vec!["192.0.2.123".into()];
    assert!(native.apply(&only_first, &failing).is_err());
    assert_eq!(native.observe(&only_first)?, only_first);
    assert_eq!(installed(&mut native, &only_first)?, [key(5)]);

    native.apply(&only_first, &empty)?;
    native.observe(&empty)?;
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
    let mut options = fixture.options();
    options.gateway_monitoring = true;
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut value = serde_json::to_value(&empty)?;
    value["interfaces"] = json!([
        {"name":"trunk0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":["192.0.2.2/24"],"dhcp_relay":{"enabled":false,"servers":[]}},
        {"name":"vlan100","kind":"vlan","role":"lan","mtu":1400,"up":true,"addresses":["198.51.100.2/24","2001:db8:100::2/64"],"vlan":{"parent":"trunk0","id":100},"dhcp_relay":{"enabled":false,"servers":[]}},
        {"name":"wg0","kind":"wireguard","role":"lan","mtu":1380,"up":true,"addresses":["2001:db8:200::2/64"],"wireguard":{"key_ref":"wg-key","listen_port":51820,"peers":[]},"dhcp_relay":{"enabled":false,"servers":[]}}
    ]);
    value["routes"] = json!([
        {"enabled":true,"destination":"203.0.113.0/24","interface":"trunk0","gateway":"192.0.2.1","table":10000,"metric":10},
        {"enabled":true,"destination":"2001:db8:300::/64","interface":"wg0","table":10001,"metric":10},
        {"enabled":true,"destination":"2001:db8:100::1/128","interface":"vlan100","table":10002,"metric":10}
    ]);
    value["gateway_monitors"] = json!([
        {"name":"wan-v4","enabled":true,"interface":"trunk0","source_address":"192.0.2.2",
         "gateway":"192.0.2.1","target":"203.0.113.1","routing_table":10000},
        {"name":"wan-v6","enabled":true,"interface":"vlan100","source_address":"2001:db8:100::2",
         "gateway":"2001:db8:100::1","target":"2001:db8:100::1","routing_table":10002}
    ]);
    value["kernel"]["namespace"] = json!({"net.ipv4.tcp_syncookies":"1"});
    value["firewall"] = json!({"policy":"drop","allow_all_icmp":true,"rules":[{"source":"192.0.2.0/24","action":"accept"},{"action":"drop"}],"nat":{"masquerade":[{"family":"ipv4","source":"198.51.100.0/24","out_interface":"trunk0"},{"family":"ipv6","source":"2001:db8:100::/64","out_interface":"wg0"}]}});
    let mut after = config(value)?;
    after.normalize();
    after.validate()?;
    native.apply(&empty, &after)?;
    assert_eq!(
        serde_json::to_value(native.observe(&after)?)?,
        serde_json::to_value(&after)?
    );
    let plan = after.operational_value()?;
    let keys = options.keys.clone();
    let snapshot = session(native.namespace.clone(), move |rt, handle| {
        rt.block_on(networking::boot_snapshot(
            handle,
            &Network::parse(&plan)?,
            &keys,
        ))
    })?;
    assert!(snapshot.get("policy_rules").is_none());
    assert_eq!(
        Network::parse(&snapshot)?.policy_rules,
        Network::parse(&after.operational_value()?)?.policy_rules
    );
    let mut disabled = after.clone();
    for monitor in &mut disabled.gateway_monitors {
        monitor.enabled = false;
    }
    native.apply(&after, &disabled)?;
    native.observe(&disabled)?;
    native.apply(&disabled, &after)?;
    native.observe(&after)?;
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
    let mut native = Native::open(options)?;
    assert_eq!(native.scope()?, scope);
    native.repair(&after)?;
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
        ipv6_before: native.capture_ipv6(&before)?,
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
