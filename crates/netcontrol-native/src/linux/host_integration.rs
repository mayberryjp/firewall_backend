//! Host-mode semantics run only after a child test process unshares its own network.
use super::*;
use futures_util::TryStreamExt;
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlag},
    route::{RouteProtocol, RouteScope},
};
use std::os::unix::fs::DirBuilderExt;

struct StateDirectory(PathBuf);
impl Drop for StateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn row(native: &mut Native, name: &str) -> Result<Value> {
    native
        .discover_interfaces()?
        .as_array()
        .context("inventory array")?
        .iter()
        .find(|v| v["name"] == name)
        .cloned()
        .context("inventory interface missing")
}

fn foreign_routes(namespace: Arc<File>) -> Result<usize> {
    session(namespace, |rt, handle| {
        rt.block_on(async {
            let routes: Vec<_> = handle
                .route()
                .get(rtnetlink::IpVersion::V4)
                .execute()
                .try_collect()
                .await?;
            Ok(routes
                .iter()
                .filter(|r| r.header.protocol == RouteProtocol::Boot)
                .count())
        })
    })
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_current_namespace_ethernet_apply_rollback_recovery_and_reboot() -> Result<()> {
    ensure!(
        std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
        "set NETCONTROL_INTEGRATION=1; privileged tests never mutate the invoking namespace"
    );
    if std::env::var("NETCONTROL_HOST_FIXTURE_CHILD").as_deref() != Ok("1") {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "linux::host_integration::native_current_namespace_ethernet_apply_rollback_recovery_and_reboot",
                "--ignored", "--nocapture", "--test-threads=1"])
            .env("NETCONTROL_HOST_FIXTURE_CHILD", "1").status()?;
        ensure!(
            status.success(),
            "isolated host-mode child fixture failed: {status}"
        );
        return Ok(());
    }
    ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
        "child fixture requires CAP_SYS_ADMIN for unshare: {}",
        std::io::Error::last_os_error()
    );
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .veth("nic0".into(), "peer0".into())
                .execute()
                .await?;
            handle
                .link()
                .add()
                .dummy("unrelated0".into())
                .execute()
                .await?;
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            let index = |wanted: &str| -> Result<u32> {
                links
                    .iter()
                    .find(|l| {
                        l.attributes.iter().any(|a|
                matches!(a, netlink_packet_route::link::LinkAttribute::IfName(n) if n == wanted))
                    })
                    .map(|l| l.header.index)
                    .context("fixture interface missing")
            };
            let nic = index("nic0")?;
            handle.link().set(nic).mtu(1450).up().execute().await?;
            for (ip, len) in [("192.0.2.8", 24), ("2001:db8:1::8", 64)] {
                let mut request = handle.address().add(nic, ip.parse()?, len);
                request
                    .message_mut()
                    .attributes
                    .push(AddressAttribute::Flags(vec![AddressFlag::Nodad]));
                request.execute().await?;
            }
            let unrelated = index("unrelated0")?;
            handle.link().set(unrelated).up().execute().await?;
            handle
                .route()
                .add()
                .v4()
                .destination_prefix("10.0.0.0".parse()?, 8)
                .table_id(254)
                .priority(7)
                .output_interface(unrelated)
                .protocol(RouteProtocol::Boot)
                .scope(RouteScope::Link)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let directory = StateDirectory(
        std::env::current_dir()?.join(format!(".native-host-{}-{stamp}", std::process::id())),
    );
    fs::DirBuilder::new().mode(0o700).create(&directory.0)?;
    let options = NativeOptions {
        namespace: String::new(),
        keys: directory.0.join("keys"),
        services_state: directory.0.join("services"),
        adopted_parents: Vec::new(),
        allow_host_tunables: false,
        allow_host_services: false,
        gateway_monitoring: false,
    };
    let mut native = Native::open(options.clone())?;
    let scope = native.scope()?;
    assert!(scope.starts_with("linux:host:"));
    let empty = Config::empty();
    let baseline = row(&mut native, "nic0")?;
    assert_eq!(baseline["kind"], "ethernet");
    assert_eq!(baseline["ownership"], "unmanaged");
    let unrelated = row(&mut native, "unrelated0")?;
    let foreign_count = foreign_routes(namespace.clone())?;
    native.repair(&empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);
    assert_eq!(
        session(namespace.clone(), |_, _| netfilter::fingerprint())?,
        netfilter::empty_fingerprint()
    );

    let mut value = serde_json::to_value(&empty)?;
    value["interfaces"] = json!([
        {"name":"nic0","kind":"ethernet","role":"wan","mtu":1400,"up":true,
            "addresses":["198.51.100.8/24","2001:db8:2::8/64"],"dhcp_relay":{"enabled":false,"servers":[]}},
        {"name":"nic100","kind":"vlan","role":"lan","mtu":1300,"up":true,
            "addresses":["198.18.1.1/24"],"vlan":{"parent":"nic0","id":100},"dhcp_relay":{"enabled":false,"servers":[]}}
    ]);
    value["routes"] = json!([{"destination":"0.0.0.0/0","gateway":"198.51.100.1","interface":"nic0","table":254,"metric":200}]);
    let desired: Config = serde_json::from_value(value.clone())?;

    let mut collision = serde_json::to_value(&empty)?;
    collision["interfaces"] = json!([{"name":"unrelated0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":[]}]);
    assert!(
        native
            .apply(&empty, &serde_json::from_value(collision)?)
            .is_err()
    );
    let mut conflict = value.clone();
    conflict["routes"] =
        json!([{"destination":"10.0.0.0/8","interface":"nic0","table":254,"metric":7}]);
    assert!(
        native
            .apply(&empty, &serde_json::from_value(conflict)?)
            .unwrap_err()
            .to_string()
            .contains("conflicts")
    );
    assert_eq!(row(&mut native, "nic0")?, baseline);

    // The first Ethernet transaction fails only after networking changed.
    let mut failed = value.clone();
    failed["ntp"] = json!({"enabled":true,"servers":["192.0.2.123"]});
    assert!(
        native
            .apply(&empty, &serde_json::from_value(failed)?)
            .is_err()
    );
    assert_eq!(row(&mut native, "nic0")?, baseline);
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(
        session(namespace.clone(), |_, _| netfilter::fingerprint())?,
        netfilter::empty_fingerprint()
    );

    native.apply(&empty, &desired)?;
    native.observe(&desired)?;
    let managed = row(&mut native, "nic0")?;
    assert_eq!(managed["ownership"], "managed");
    assert_eq!(managed["index"], baseline["index"]);
    assert_eq!(managed["mac"], baseline["mac"]);
    assert_eq!(native.ownership()?.ethernet_originals["nic0"].mtu, 1450);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            let index = links
                .iter()
                .find(|l| {
                    l.attributes.iter().any(|a|
            matches!(a, netlink_packet_route::link::LinkAttribute::IfName(n) if n == "nic0"))
                })
                .context("nic missing")?
                .header
                .index;
            handle.link().set(index).mtu(1390).execute().await?;
            Ok(())
        })
    })?;
    assert!(native.observe(&desired).is_err());
    assert_eq!(row(&mut native, "nic0")?["mtu"], 1390);
    let snapshots = native.ownership()?.ethernet_originals;
    session(namespace.clone(), move |rt, handle| {
        rt.block_on(networking::restore_ethernet(handle, &snapshots))
    })?;
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let routes: Vec<_> = handle
                .route()
                .get(rtnetlink::IpVersion::V4)
                .execute()
                .try_collect()
                .await?;
            for route in routes
                .into_iter()
                .filter(|r| r.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL))
            {
                handle.route().del(route).execute().await?;
            }
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            for link in links.iter().filter(|l| {
                l.attributes.iter().any(|a|
                matches!(a, netlink_packet_route::link::LinkAttribute::IfName(n) if n == "nic100"))
            }) {
                handle.link().del(link.header.index).execute().await?;
            }
            Ok::<(), anyhow::Error>(())
        })?;
        let fingerprint = netfilter::fingerprint()?;
        firewall::remove_owned(&fingerprint)
    })?;
    // Restore the committed candidate through the explicit reboot path, not a drift bypass.
    let mut ownership = native.ownership()?;
    ownership.boot = "synthetic-previous-boot".into();
    native.save_ownership(&ownership)?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    native.repair(&desired)?;
    native.observe(&desired)?;
    assert_eq!(native.scope()?, scope);

    for rollback in [false, true] {
        session(namespace.clone(), |rt, handle| {
            rt.block_on(async {
                let links = networking::links(handle).await?;
                let index = links
                    .iter()
                    .find(|link| networking::name(link) == "nic0")
                    .context("fixture NIC missing")?
                    .header
                    .index;
                handle
                    .address()
                    .add(index, "198.51.100.250".parse()?, 32)
                    .execute()
                    .await?;
                Ok::<(), anyhow::Error>(())
            })
        })?;
        assert!(native.observe(&desired).is_err());
        if rollback {
            native.apply(&desired, &desired)?;
        } else {
            native.repair(&desired)?;
        }
        native.observe(&desired)?;
        assert_eq!(
            native.ownership()?.committed_config,
            Some(serde_json::to_value(&desired)?)
        );
    }

    // Core expires pending transactions before startup repair; do not replay the expired candidate.
    let mut ownership = native.ownership()?;
    ownership.boot = "synthetic-previous-boot".into();
    native.save_ownership(&ownership)?;
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let links: Vec<_> = handle.link().get().execute().try_collect().await?;
            let vlan = links
                .iter()
                .find(|l| {
                    l.attributes.iter().any(|a|
            matches!(a, netlink_packet_route::link::LinkAttribute::IfName(n) if n == "nic100"))
                })
                .context("fixture VLAN missing")?;
            handle.link().del(vlan.header.index).execute().await?;
            Ok(())
        })
    })?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    native.apply(&desired, &empty)?;
    native.observe(&empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);
    native.apply(&empty, &desired)?;

    let mut down = value.clone();
    down["interfaces"] = json!([{"name":"nic0","kind":"ethernet","role":"wan","mtu":1400,"up":false,"addresses":[]}]);
    down["routes"] = json!([]);
    let down: Config = serde_json::from_value(down)?;
    native.apply(&desired, &down)?;
    native.observe(&down)?;
    native.apply(&down, &empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);

    // Persist originals only in the intent, then emulate process loss before ownership save.
    let before = serde_json::to_value(&empty)?;
    let a = Network::parse(&before)?;
    let b = Network::parse(&value)?;
    let captured = session(namespace.clone(), move |rt, handle| {
        rt.block_on(networking::capture_ethernet(handle, &a, &b))
    })?;
    let previous = native.ownership()?;
    let mut applying = previous.clone();
    applying.ethernet_originals.extend(captured.clone());
    write_json(
        &native.state.join("intent.json"),
        &Intent {
            scope: scope.clone(),
            before: before.clone(),
            after: value.clone(),
            kernel_before: Kernel::default(),
            ownership_before: previous,
            ethernet_before: captured,
            ethernet_originals: applying.ethernet_originals.clone(),
        },
    )?;
    native.network_apply(&before, &value, Kernel::default(), &mut applying)?;
    drop(native);
    let mut native = Native::open(options)?;
    assert!(!native.state.join("intent.json").exists());
    native.observe(&empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);
    assert_eq!(row(&mut native, "unrelated0")?, unrelated);
    assert_eq!(foreign_routes(namespace)?, foreign_count);
    Ok(())
}
