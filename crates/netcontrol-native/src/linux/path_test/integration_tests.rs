use super::*;
use crate::linux::{Backend, Config, Native, firewall, integration::Fixture};
use crate::netlink_decode::attributes;

fn setup() -> Result<(Fixture, Native, Config)> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let config: Config = serde_json::from_value(json!({
        "interfaces":[{"name":"path0","kind":"dummy","role":"wan",
            "mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
        "firewall":{"policy":"drop","allow_all_icmp":false,
            "input":{"policy":"drop","interfaces":[]}}
    }))?;
    native.apply(&Config::empty(), &config)?;
    Ok((fixture, native, config))
}

fn request() -> PathTestRequest {
    serde_json::from_value(json!({"interface":"path0","source_address":"192.0.2.1",
        "peer_address":"192.0.2.2","maximum_mtu":9000,
        "pairing_secret":"synthetic-pairing-secret-1234567890"}))
    .unwrap()
}

fn mtu(native: &Native) -> Result<u32> {
    named_mtu(native, "path0")
}

fn named_mtu(native: &Native, name: &str) -> Result<u32> {
    let name = name.to_owned();
    session(native.namespace.clone(), move |rt, handle| {
        rt.block_on(async {
            let messages = networking::links(handle).await?;
            Ok(identity(
                messages
                    .iter()
                    .find(|message| networking::name(message) == name)
                    .context("test interface missing")?,
                9000,
            )?
            .original_mtu)
        })
    })
}

fn vlan_setup() -> Result<(Fixture, Native, Config)> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let config: Config = serde_json::from_value(json!({
        "firewall":{"policy":"drop","allow_all_icmp":false,
            "input":{"policy":"drop","interfaces":[]}}
    }))?;
    native.apply(&Config::empty(), &config)?;
    session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            for name in ["lower0", "other0"] {
                handle
                    .link()
                    .add(rtnetlink::LinkDummy::new(&name).build())
                    .execute()
                    .await?;
            }
            let links = networking::links(handle).await?;
            let parent = links
                .iter()
                .find(|message| networking::name(message) == "lower0")
                .context("VLAN parent missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(parent.header.index)
                        .mtu(1500)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            handle
                .link()
                .add(rtnetlink::LinkVlan::new(&"path0", parent.header.index, 42).build())
                .execute()
                .await?;
            let links = networking::links(handle).await?;
            let child = links
                .iter()
                .find(|message| networking::name(message) == "path0")
                .context("VLAN child missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(child.header.index)
                        .mtu(1500)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            handle
                .address()
                .add(child.header.index, "192.0.2.1".parse()?, 24)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    Ok((fixture, native, config))
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_approved_vlan_parent_is_raised_then_both_original_mtus_are_restored() -> Result<()> {
    let (_fixture, mut native, config) = vlan_setup()?;
    let mut request = request();
    request.parents.push(netcontrol_core::PathTestParent {
        interface: "lower0".into(),
        maximum_mtu: 9000,
    });
    let initial = native.start_path_test(&config, request)?;
    let id = initial["id"]
        .as_str()
        .context("test identifier missing")?
        .to_owned();
    wait(&mut native, "running", 5)?;
    assert_eq!(named_mtu(&native, "lower0")?, 9000);
    assert_eq!(mtu(&native)?, 9000);
    native.cancel_path_test(&id)?;
    wait(&mut native, "cancelled", 8)?;
    assert_eq!(named_mtu(&native, "lower0")?, 1500);
    assert_eq!(mtu(&native)?, 1500);
    assert!(!native.path_test_active());
    native.observe(&config)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_vlan_parent_nonancestor_unapproved_and_below_live_requests_never_mutate() -> Result<()>
{
    let (_fixture, mut native, config) = vlan_setup()?;
    for (parent, maximum) in [
        (None, 9000),
        (Some("other0"), 9000),
        (Some("lower0"), 1280),
        (Some("lower0"), 1500),
    ] {
        let mut request = request();
        if let Some(parent) = parent {
            request.parents.push(netcontrol_core::PathTestParent {
                interface: parent.into(),
                maximum_mtu: maximum,
            });
        }
        assert!(native.start_path_test(&config, request).is_err());
        assert_eq!(named_mtu(&native, "lower0")?, 1500);
        assert_eq!(mtu(&native)?, 1500);
        assert!(!native.path_test_active());
        assert!(!native.state.join(INTENT).exists());
    }
    Ok(())
}

fn wait(native: &mut Native, desired: &str, seconds: u64) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let value = native.path_test_status()?;
        if value["state"] == desired {
            return Ok(value);
        }
        ensure!(Instant::now() < deadline, "test status deadline: {value}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_cancel_restores_original_and_blocks_concurrent_apply() -> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    let original = native.ownership()?.firewall_fingerprint;
    let status = native.start_path_test(&config, request())?;
    let id = status["id"]
        .as_str()
        .context("test identifier missing")?
        .to_owned();
    assert!(native.path_test_active());
    assert!(native.apply(&config, &config).is_err());
    wait(&mut native, "running", 5)?;
    assert_eq!(mtu(&native)?, 9000);
    assert!(
        native
            .statistics(&config, "/api/v1/statistics/firewall", "")
            .is_err()
    );
    assert!(native.observe(&config).is_err());
    assert_eq!(native.runtime(&config)?["path_test"]["id"], id);
    assert_eq!(native.ownership()?.firewall_fingerprint, original);
    native.cancel_path_test(&id)?;
    let status = wait(&mut native, "cancelled", 8)?;
    assert_eq!(status["restoration"], "restored");
    assert!(!status.to_string().contains("synthetic-pairing-secret"));
    assert!(!native.path_test_active());
    assert_eq!(mtu(&native)?, 1500);
    assert!(!native.state.join(INTENT).exists());
    let expected = original.context("original fingerprint missing")?;
    session(native.namespace.clone(), move |_, _| {
        ensure!(
            netfilter::fingerprint()? == expected,
            "firewall not restored"
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_rejects_nonlocal_sources_broadcast_and_unapproved_lowering_before_mutation()
-> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    for (source, peer, maximum) in [
        ("192.0.2.3", "192.0.2.2", 9000),
        ("192.0.2.1", "192.0.2.255", 9000),
        ("192.0.2.1", "192.0.2.2", 1280),
    ] {
        let mut request = request();
        request.source_address = source.parse()?;
        request.peer_address = peer.parse()?;
        request.maximum_mtu = maximum;
        assert!(native.start_path_test(&config, request).is_err());
        assert!(!native.path_test_active());
        assert_eq!(mtu(&native)?, 1500);
        assert!(!native.state.join(INTENT).exists());
    }
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_occupied_udp_and_tcp_ports_never_mutate_mtu_or_firewall() -> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    let before = native
        .ownership()?
        .firewall_fingerprint
        .context("firewall missing")?;
    let mut request = request();
    request.port = 8080;
    let udp = session(native.namespace.clone(), |_, _| {
        Ok(std::net::UdpSocket::bind("192.0.2.1:8080")?)
    })?;
    assert!(native.start_path_test(&config, request.clone()).is_err());
    assert_eq!(mtu(&native)?, 1500);
    assert!(!native.state.join(INTENT).exists());
    drop(udp);
    let tcp = session(native.namespace.clone(), |_, _| {
        Ok(std::net::TcpListener::bind("192.0.2.1:8080")?)
    })?;
    assert!(native.start_path_test(&config, request).is_err());
    assert_eq!(mtu(&native)?, 1500);
    assert!(!native.state.join(INTENT).exists());
    drop(tcp);
    session(native.namespace.clone(), move |_, _| {
        ensure!(
            netfilter::fingerprint()? == before,
            "occupied port changed firewall"
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_cleanup_failure_retains_busy_intent_and_refuses_external_mtu() -> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    let status = native.start_path_test(&config, request())?;
    let id = status["id"]
        .as_str()
        .context("test identifier missing")?
        .to_owned();
    wait(&mut native, "running", 5)?;
    session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|message| networking::name(message) == "path0")
                .context("test interface missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .mtu(8000)
                        .build(),
                )
                .execute()
                .await?;
            Ok(())
        })
    })?;
    native.cancel_path_test(&id)?;
    let status = wait(&mut native, "cleanup_failed", 8)?;
    assert!(
        status["error"]
            .as_str()
            .is_some_and(|error| error.contains("externally"))
    );
    assert!(native.path_test_active());
    assert!(native.state.join(INTENT).exists());
    assert_eq!(mtu(&native)?, 8000);
    session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|message| networking::name(message) == "path0")
                .context("test interface missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .mtu(9000)
                        .build(),
                )
                .execute()
                .await?;
            Ok(())
        })
    })?;
    native.cancel_path_test(&id)?;
    assert!(!native.path_test_active());
    assert_eq!(mtu(&native)?, 1500);
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_refuses_foreign_firewall_replacement_and_restores_owned_mtu() -> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    let status = native.start_path_test(&config, request())?;
    let id = status["id"]
        .as_str()
        .context("test identifier missing")?
        .to_owned();
    wait(&mut native, "running", 5)?;
    let value = config.operational_value()?["firewall"].clone();
    let foreign = session(native.namespace.clone(), move |_, _| {
        firewall::apply(&value, &[])?;
        netfilter::fingerprint()
    })?;
    native.cancel_path_test(&id)?;
    wait(&mut native, "cleanup_failed", 8)?;
    assert!(native.path_test_active());
    assert_eq!(mtu(&native)?, 1500);
    session(native.namespace.clone(), move |_, _| {
        ensure!(
            netfilter::fingerprint()? == foreign,
            "foreign firewall was overwritten"
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_refuses_replaced_interface_identity() -> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    let status = native.start_path_test(&config, request())?;
    let id = status["id"]
        .as_str()
        .context("test identifier missing")?
        .to_owned();
    wait(&mut native, "running", 5)?;
    session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let original = networking::links(handle)
                .await?
                .into_iter()
                .find(|message| networking::name(message) == "path0")
                .context("test interface missing")?;
            handle.link().del(original.header.index).execute().await?;
            handle
                .link()
                .add(rtnetlink::LinkDummy::new(&"path0").build())
                .execute()
                .await?;
            let replacement = networking::links(handle)
                .await?
                .into_iter()
                .find(|message| networking::name(message) == "path0")
                .context("replacement missing")?;
            ensure!(
                replacement.header.index != original.header.index,
                "fixture did not replace identity"
            );
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(replacement.header.index)
                        .mtu(1700)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            Ok(())
        })
    })?;
    native.cancel_path_test(&id)?;
    wait(&mut native, "cleanup_failed", 8)?;
    assert!(native.path_test_active());
    assert_eq!(mtu(&native)?, 1700);
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_restart_recovers_durable_before_snapshot_before_reconciliation() -> Result<()> {
    let (fixture, native, _config) = setup()?;
    let namespace = native.namespace.clone();
    let request = request();
    let snapshot_request = request.clone();
    let links = session(namespace.clone(), move |rt, handle| {
        rt.block_on(snapshot(handle, &snapshot_request))
    })?;
    let deadline = unix_ns()? + PATH_TEST_LIFETIME_SECONDS * 1_000_000_000;
    let id = "0123456789abcdef0123456789abcdef";
    let (rules, lease) = permits::rules(&request, id, deadline)?;
    use std::os::unix::fs::MetadataExt;
    let metadata = namespace.metadata()?;
    let intent = Intent {
        id: id.into(),
        boot: native.boot.clone(),
        namespace_device: metadata.dev(),
        namespace_inode: metadata.ino(),
        firewall_before: native
            .ownership()?
            .firewall_fingerprint
            .context("firewall missing")?,
        rules,
        lease,
        links,
        deadline_unix_ns: deadline,
    };
    write_json(&native.state.join(INTENT), &intent)?;
    session(namespace, move |rt, handle| {
        rt.block_on(
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(intent.links[0].index)
                        .mtu(9000)
                        .build(),
                )
                .execute(),
        )?;
        permits::install(&intent.rules, &intent.lease)
    })?;
    // No worker owns this fault-injection intent: dropping the initial fixture
    // models userspace dying after mutation, without touching host networking.
    drop(native);
    let mut restarted = Native::open(fixture.options())?;
    assert_eq!(mtu(&restarted)?, 1500);
    assert!(!restarted.path_test_active());
    assert_eq!(restarted.path_test_status()?["state"], "interrupted");
    assert!(!restarted.state.join(INTENT).exists());
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_unpaired_failure_and_shutdown_restore_originals() -> Result<()> {
    let (_fixture, mut native, config) = setup()?;
    native.start_path_test(&config, request())?;
    let status = wait(&mut native, "failed", 38)?;
    assert_eq!(status["restoration"], "restored");
    assert_eq!(mtu(&native)?, 1500);
    native.start_path_test(&config, request())?;
    wait(&mut native, "running", 5)?;
    native.shutdown_path_test()?;
    assert!(!native.path_test_active());
    assert_eq!(mtu(&native)?, 1500);
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and isolated Linux net_admin/mount namespaces"]
fn path_test_kernel_lease_expires_without_worker_or_cleanup() -> Result<()> {
    let (_fixture, native, config) = setup()?;
    let firewall_value = config.operational_value()?["firewall"].clone();
    session(native.namespace.clone(), move |_, _| {
        firewall::validate(&firewall_value, &[])?;
        permits::check_enforcement()?;
        let before = netfilter::fingerprint()?;
        let (rules, lease) = permits::rules(
            &request(),
            "0123456789abcdef0123456789abcdef",
            unix_ns()? + 1_000_000_000,
        )?;
        // A shorter test-only lease exercises the exact production timeout path.
        let mut lease_attrs = attributes(&lease[4..])?;
        for (kind, value) in &mut lease_attrs {
            if *kind & 0x3fff == 11 {
                // Whole seconds round-trip exactly through every kernel HZ;
                // sub-tick millisecond values are quantized by nftables.
                *value = 1000u64.to_be_bytes().to_vec();
            }
        }
        let lease = [
            [libc::NFPROTO_INET as u8, 0, 0, 0].to_vec(),
            lease_attrs
                .into_iter()
                .flat_map(|(kind, value)| attribute(kind, &value))
                .collect(),
        ]
        .concat();
        permits::install(&rules, &lease)?;
        std::thread::sleep(Duration::from_millis(1500));
        let attrs = [
            attribute(1, b"netcontrol\0"),
            attribute(2, b"netcontrol_path_test_lease\0"),
        ]
        .concat();
        let elements = netfilter::dump_messages(10, 13, libc::NFPROTO_INET as u8, &attrs)?;
        for element in elements {
            for (kind, values) in attributes(&element[4..])? {
                if kind & 0x3fff == 3 {
                    ensure!(
                        attributes(&values)?.is_empty(),
                        "expired kernel permit remains usable"
                    );
                }
            }
        }
        permits::remove(&rules, &lease, &before)
    })
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and two isolated Linux net_admin/mount namespaces"]
fn path_test_paired_native_drop_input_completes_and_restores_both_unmanaged_interfaces()
-> Result<()> {
    let left_fixture = Fixture::new()?;
    let right_fixture = Fixture::new()?;
    let mut left = Native::open(left_fixture.options())?;
    let mut right = Native::open(right_fixture.options())?;
    let config: Config = serde_json::from_value(json!({
        "firewall":{"policy":"drop","allow_all_icmp":false,
            "input":{"policy":"drop","interfaces":[]}}
    }))?;
    left.apply(&Config::empty(), &config)?;
    right.apply(&Config::empty(), &config)?;
    let target = right.namespace.clone();
    session(left.namespace.clone(), move |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add(rtnetlink::LinkVeth::new(&"path0", &"path1").build())
                .execute()
                .await?;
            let links = networking::links(handle).await?;
            let peer = links
                .iter()
                .find(|message| networking::name(message) == "path1")
                .context("paired interface missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(peer.header.index)
                        .setns_by_fd(target.as_raw_fd())
                        .build(),
                )
                .execute()
                .await?;
            let selected = links
                .iter()
                .find(|message| networking::name(message) == "path0")
                .context("selected interface missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(selected.header.index)
                        .mtu(1500)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            handle
                .address()
                .add(selected.header.index, "192.0.2.1".parse()?, 24)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    session(right.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let links = networking::links(handle).await?;
            let peer = links
                .iter()
                .find(|message| networking::name(message) == "path1")
                .context("paired interface missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(peer.header.index)
                        .mtu(1500)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            handle
                .address()
                .add(peer.header.index, "192.0.2.2".parse()?, 24)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    left.start_path_test(&config, request())?;
    let mut reverse = request();
    reverse.interface = "path1".into();
    reverse.source_address = "192.0.2.2".parse()?;
    reverse.peer_address = "192.0.2.1".parse()?;
    right.start_path_test(&config, reverse)?;
    let left_result = wait(&mut left, "completed", 70)?;
    let right_result = wait(&mut right, "completed", 10)?;
    assert_eq!(left_result["restoration"], "restored");
    assert_eq!(right_result["restoration"], "restored");
    assert_eq!(left_result["result"]["schema"], "netcontrol-path-test-v1");
    assert_eq!(right_result["result"]["schema"], "netcontrol-path-test-v1");
    assert!(!left.path_test_active() && !right.path_test_active());
    assert_eq!(mtu(&left)?, 1500);
    session(right.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let links = networking::links(handle).await?;
            let peer = links
                .iter()
                .find(|message| networking::name(message) == "path1")
                .context("paired interface missing")?;
            ensure!(
                identity(peer, 9000)?.original_mtu == 1500,
                "peer original MTU not restored"
            );
            Ok(())
        })
    })?;
    left.observe(&config)?;
    right.observe(&config)?;
    Ok(())
}
