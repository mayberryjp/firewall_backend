use super::*;
use std::{ffi::CString, os::unix::fs::DirBuilderExt};

pub(super) struct Fixture {
    root: PathBuf,
    namespace: PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
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
    pub(super) fn options(&self) -> NativeOptions {
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
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated Linux namespaces, conntrack procfs and host-tuning privileges"]
fn conntrack_ownership_captures_live_timeouts_and_preserves_saved_host_key() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut options = fixture.options();
    options.allow_host_tunables = true;
    let mut native = Native::open(options.clone())?;
    let before = Config::empty();
    native.repair(&before)?;
    let host = native
        .read_kernel(&Kernel {
            host: netcontrol_core::missing_conntrack_tunables(&before.kernel).host,
            ..Default::default()
        })?
        .host;
    let saved = netcontrol_core::KernelConfig {
        host,
        ..Default::default()
    };
    let saved_host = saved.host.clone();
    let captured = session(native.namespace.clone(), move |_, _| {
        sysctl::capture_conntrack_tunables(&saved)
    })?;
    ensure!(
        captured.host.is_empty() && captured.namespace.len() == 8,
        "incomplete live conntrack capture"
    );
    let mut configured = before.clone();
    configured.kernel = captured.clone();
    native.apply(&before, &configured)?;
    let value = configured.operational_value()?;
    native.verify(&value)?;
    let ownership = native.ownership()?;
    ensure!(
        ownership.kernel_baseline.host == captured.host
            && ownership.kernel_baseline.namespace == captured.namespace,
        "conntrack originals were not captured"
    );
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&configured)?;
    native.verify(&value)?;
    let remaining = session(native.namespace.clone(), move |_, _| {
        let mut configured = captured;
        configured.host = saved_host;
        sysctl::capture_conntrack_tunables(&configured)
    })?;
    ensure!(
        remaining == netcontrol_core::KernelConfig::default(),
        "already owned conntrack values were recaptured"
    );
    native.apply(&configured, &before)?;
    native.verify(&before.operational_value()?)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespaces/net_admin and NFLOG/nftables"]
fn drop_logging_native_apply_rollback_and_restart() -> Result<()> {
    let fixture = Fixture::new()?;
    let base = Config::empty();
    let mut native = Native::open(fixture.options())?;
    native.repair(&base)?;
    let query = netcontrol_core::DenyLogQuery::parse("")?;
    let mut disabled = base.clone();
    disabled.firewall.drop_logging_enabled = false;
    native.apply(&base, &disabled)?;
    ensure!(
        native.deny_log(&query)?["capture"]["status"] == "disabled",
        "apply did not stop logging"
    );
    native.verify(&disabled.operational_value()?)?;
    native.apply(&disabled, &base)?;
    ensure!(
        matches!(
            native.deny_log(&query)?["capture"]["status"].as_str(),
            Some("starting" | "capturing")
        ),
        "rollback did not start logging"
    );
    native.apply(&base, &disabled)?;
    drop(native);
    let mut native = Native::open(fixture.options())?;
    native.repair(&disabled)?;
    ensure!(
        native.deny_log(&query)?["capture"]["status"] == "disabled",
        "restart enabled disabled logging"
    );
    native.verify(&disabled.operational_value()?)?;
    native.apply(&disabled, &base)?;
    ensure!(
        matches!(
            native.deny_log(&query)?["capture"]["status"].as_str(),
            Some("starting" | "capturing")
        ),
        "re-enable after restart did not start logging"
    );
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespaces/net_admin and nftables"]
fn native_dhcp_relay_generated_input_permits_packets_restart_disable_and_rollback() -> Result<()> {
    use futures_util::TryStreamExt;
    use std::{
        net::UdpSocket,
        os::fd::{FromRawFd, OwnedFd},
        time::Duration,
    };
    let router = Fixture::new()?;
    let client = Fixture::new()?;
    let server = Fixture::new()?;
    let router_ns = Arc::new(File::open(&router.namespace)?);
    let client_ns = Arc::new(File::open(&client.namespace)?);
    let server_ns = Arc::new(File::open(&server.namespace)?);
    for (name, peer, target) in [
        ("trunk0", "client0", client_ns.clone()),
        ("srv0", "server0", server_ns.clone()),
    ] {
        session(router_ns.clone(), move |rt, handle| {
            rt.block_on(async {
                handle
                    .link()
                    .add()
                    .veth(name.into(), peer.into())
                    .execute()
                    .await?;
                let link = handle
                    .link()
                    .get()
                    .match_name(peer.into())
                    .execute()
                    .try_next()
                    .await?
                    .context("DHCP peer missing")?;
                handle
                    .link()
                    .set(link.header.index)
                    .setns_by_fd(target.as_raw_fd())
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
    }
    session(client_ns.clone(), |rt, handle| {
        rt.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("client0".into())
                .execute()
                .try_next()
                .await?
                .context("DHCP client trunk missing")?;
            handle.link().set(link.header.index).up().execute().await?;
            handle
                .link()
                .add()
                .vlan("vlan30".into(), link.header.index, 30)
                .execute()
                .await?;
            let vlan = handle
                .link()
                .get()
                .match_name("vlan30".into())
                .execute()
                .try_next()
                .await?
                .context("DHCP client VLAN missing")?;
            handle
                .address()
                .add(vlan.header.index, "10.4.30.2".parse()?, 24)
                .execute()
                .await?;
            handle.link().set(vlan.header.index).up().execute().await?;
            Ok(())
        })
    })?;
    session(server_ns.clone(), |rt, handle| {
        rt.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("server0".into())
                .execute()
                .try_next()
                .await?
                .context("DHCP server link missing")?;
            for address in ["10.4.40.40", "10.4.40.41", "10.4.40.42"] {
                handle
                    .address()
                    .add(link.header.index, address.parse()?, 24)
                    .execute()
                    .await?;
            }
            handle.link().set(link.header.index).up().execute().await?;
            handle
                .route()
                .add()
                .v4()
                .destination_prefix("10.4.30.0".parse()?, 24)
                .gateway("10.4.40.1".parse()?)
                .output_interface(link.header.index)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let socket = |namespace: Arc<File>, address: &'static str| {
        session(namespace, move |_, _| {
            let socket = UdpSocket::bind(address)?;
            socket.set_broadcast(true)?;
            socket.set_read_timeout(Some(Duration::from_millis(600)))?;
            Ok(socket)
        })
    };
    let upstream = socket(server_ns.clone(), "10.4.40.40:67")?;
    let replacement = socket(server_ns.clone(), "10.4.40.41:67")?;
    let outsider = socket(server_ns.clone(), "10.4.40.42:67")?;
    let wrong_port = socket(server_ns.clone(), "10.4.40.40:68")?;
    let downstream = socket(client_ns.clone(), "0.0.0.0:68")?;
    let send_discover = |id: u32, broadcast: bool, source_port: u16, destination_port: u16| {
        let mut packet = vec![0u8; 300];
        packet[..4].copy_from_slice(&[1, 1, 6, 0]);
        packet[4..8].copy_from_slice(&id.to_be_bytes());
        packet[8..10].copy_from_slice(&561u16.to_be_bytes());
        if broadcast {
            packet[10] = 0x80;
        }
        packet[28..34].copy_from_slice(&[0x74, 0xfa, 0x29, 0x3e, 0x5d, 0x96]);
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
        packet[240..284].copy_from_slice(&[
            53, 1, 1, 57, 2, 2, 64, 55, 8, 1, 3, 6, 12, 15, 28, 42, 43, 12, 9, b'o', b'f', b'f',
            b'i', b'c', b'e', b'-', b'a', b'p', 60, 4, b'u', b'b', b'n', b't', 61, 7, 1, 0x74,
            0xfa, 0x29, 0x3e, 0x5d, 0x96, 255,
        ]);
        let payload = packet.clone();
        session(client_ns.clone(), move |rt, handle| {
            let link = rt
                .block_on(
                    handle
                        .link()
                        .get()
                        .match_name("vlan30".into())
                        .execute()
                        .try_next(),
                )?
                .context("DHCP client VLAN missing")?;
            let descriptor = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    (libc::ETH_P_IP as u16).to_be() as i32,
                )
            };
            ensure!(
                descriptor >= 0,
                "DHCP injection socket: {}",
                std::io::Error::last_os_error()
            );
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            let mut wire = vec![0; 28 + payload.len()];
            wire[0] = 0x45;
            let length = u16::try_from(wire.len())?;
            wire[2..4].copy_from_slice(&length.to_be_bytes());
            wire[8] = 64;
            wire[9] = 17;
            wire[16..20].fill(255);
            let mut checksum: u32 = wire[..20]
                .chunks_exact(2)
                .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
                .sum();
            while checksum > 65535 {
                checksum = (checksum & 65535) + (checksum >> 16);
            }
            wire[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
            wire[20..22].copy_from_slice(&source_port.to_be_bytes());
            wire[22..24].copy_from_slice(&destination_port.to_be_bytes());
            wire[24..26].copy_from_slice(&u16::try_from(payload.len() + 8)?.to_be_bytes());
            wire[28..].copy_from_slice(&payload);
            let mut destination: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            destination.sll_family = libc::AF_PACKET as _;
            destination.sll_protocol = (libc::ETH_P_IP as u16).to_be();
            destination.sll_ifindex = link.header.index as _;
            destination.sll_halen = 6;
            destination.sll_addr[..6].fill(255);
            let sent = unsafe {
                libc::sendto(
                    descriptor.as_raw_fd(),
                    wire.as_ptr().cast(),
                    wire.len(),
                    0,
                    &destination as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&destination) as _,
                )
            };
            ensure!(
                sent == wire.len() as isize,
                "DHCP frame injection: {}",
                std::io::Error::last_os_error()
            );
            Ok(())
        })?;
        Ok::<_, anyhow::Error>(packet)
    };
    let assert_no_packet = |socket: &UdpSocket| -> Result<()> {
        match socket.recv_from(&mut [0u8; 1500]) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(())
            }
            result => anyhow::bail!("unexpected DHCP receive result: {result:?}"),
        }
    };
    let exchange = |id: u32, server: &UdpSocket, relay: &str| -> Result<()> {
        let request = send_discover(id, true, 68, 67)?;
        let mut wire = [0u8; 1500];
        let (size, peer) = server
            .recv_from(&mut wire)
            .context("Discover was not relayed")?;
        assert_eq!(peer, format!("{relay}:67").parse()?);
        assert_eq!(size, request.len());
        assert_eq!(&wire[4..8], &request[4..8]);
        assert_eq!(wire[3], 1);
        assert_eq!(
            &wire[24..28],
            &relay.parse::<std::net::Ipv4Addr>()?.octets()
        );
        wire[0] = 2;
        wire[3] = 0;
        wire[16..20].copy_from_slice(&[10, 4, 30, 100]);
        wire[242] = 2;
        server.send_to(&wire[..size], peer)?;
        let (length, _) = downstream
            .recv_from(&mut wire)
            .context("Offer was not delivered")?;
        assert_eq!(length, request.len());
        assert_eq!(wire[0], 2);
        assert_eq!(&wire[4..8], &request[4..8]);
        assert_eq!(&wire[16..20], &[10, 4, 30, 100]);
        Ok(())
    };
    let options = router.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let disabled = config(json!({
        "ipv6_enabled":false,
        "interfaces":[
            {"name":"trunk0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":[]},
            {"name":"vlan30","kind":"vlan","role":"lan","up":true,"mtu":1500,
             "addresses":["10.4.30.1/24"],"vlan":{"parent":"trunk0","id":30},
             "dhcp_relay":{"enabled":false,"servers":["10.4.40.40"]}},
            {"name":"srv0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["10.4.40.1/24"]}
        ],
        "firewall":{"policy":"drop","allow_all_icmp":false,"rules":[],
            "input":{"policy":"drop","interfaces":[]}}
    }))?;
    disabled.validate()?;
    native.apply(&empty, &disabled)?;
    send_discover(1, false, 68, 67)?;
    assert_no_packet(&upstream)?;
    let mut enabled = disabled.clone();
    enabled.interfaces[1].dhcp_relay.enabled = true;
    native.apply(&disabled, &enabled)?;
    assert_eq!(native.observe(&enabled)?, enabled);
    assert_eq!(enabled.firewall, disabled.firewall);

    // Exercise the configured-server permit before any matching outbound flow exists.
    upstream.send_to(b"configured server", "10.4.30.1:67")?;
    // Reproduce the zero-source, flags=0 Discover before testing broadcast Offers.
    send_discover(2, false, 68, 67)?;
    let mut wire = [0u8; 1500];
    let (_, peer) = upstream.recv_from(&mut wire)?;
    assert_eq!(peer.to_string(), "10.4.30.1:67");
    assert_eq!(wire[10], 0);

    outsider.send_to(b"unconfigured server", "10.4.30.1:67")?;
    wrong_port.send_to(b"wrong source port", "10.4.30.1:67")?;
    upstream.send_to(b"wrong local address", "10.4.40.1:67")?;
    upstream.send_to(b"wrong destination port", "10.4.30.1:68")?;
    upstream.send_to(b"disabled ingress", "255.255.255.255:67")?;
    send_discover(3, false, 69, 67)?;
    send_discover(4, false, 68, 8080)?;
    let path = "/api/v1/statistics/firewall";
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let snapshot = loop {
        let snapshot = native.statistics(&enabled, path, "")?;
        if firewall_counter(&snapshot, "input:/firewall/input/policy")?["packets"]
            .as_str()
            .context("missing input drops")?
            .parse::<u64>()?
            >= 7
        {
            break snapshot;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "missing negative-path drops: {snapshot}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        firewall_counter(&snapshot, "input:generated/input/dhcp_relay/vlan30/clients")?["packets"],
        "1"
    );
    assert_eq!(
        firewall_counter(&snapshot, "input:generated/input/dhcp_relay/vlan30/servers")?["packets"],
        "1"
    );
    assert!(
        firewall_counter(&snapshot, "input:/firewall/input/policy")?["packets"]
            .as_str()
            .context("missing input drops")?
            .parse::<u64>()?
            >= 7
    );
    exchange(5, &upstream, "10.4.30.1")?;
    let mut renewal = wire[..300].to_vec();
    renewal[3] = 0;
    renewal[4..8].copy_from_slice(&50u32.to_be_bytes());
    renewal[12..16].copy_from_slice(&[10, 4, 30, 2]);
    renewal[24..28].fill(0);
    renewal[242] = 3;
    downstream.send_to(&renewal, "10.4.30.1:67")?;
    let (length, _) = upstream.recv_from(&mut wire)?;
    assert_eq!(length, 300);
    assert_eq!(&wire[4..8], &50u32.to_be_bytes());
    assert_eq!(&wire[12..16], &[10, 4, 30, 2]);

    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&enabled)?;
    assert_eq!(native.observe(&enabled)?, enabled);
    assert_eq!(
        native.statistics(&enabled, path, "")?["ruleset_id"],
        snapshot["ruleset_id"]
    );
    exchange(6, &upstream, "10.4.30.1")?;
    let mut changed = enabled.clone();
    changed.interfaces[1].addresses = vec!["10.4.30.9/24".into()];
    changed.interfaces[1].dhcp_relay.servers = vec!["10.4.40.41".into()];
    native.apply(&enabled, &changed)?;
    assert_ne!(
        native.statistics(&changed, path, "")?["ruleset_id"],
        snapshot["ruleset_id"]
    );
    upstream.send_to(b"removed server", "10.4.30.9:67")?;
    exchange(7, &replacement, "10.4.30.9")?;
    assert_ne!(
        firewall_counter(
            &native.statistics(&changed, path, "")?,
            "input:/firewall/input/policy"
        )?["packets"],
        "0"
    );
    assert_no_packet(&upstream)?;
    native.apply(&changed, &enabled)?;
    exchange(8, &upstream, "10.4.30.1")?;
    let before = enabled.operational_value()?;
    let after = changed.operational_value()?;
    let ownership = native.ownership()?;
    let intent = Intent {
        scope: native.identity.clone(),
        before: before.clone(),
        after: after.clone(),
        kernel_before: native.capture_kernel(&before, &after)?,
        ownership_before: ownership.clone(),
        ethernet_before: native.capture_ethernet(&before, &after)?,
        ethernet_originals: ownership.ethernet_originals.clone(),
        ipv6_before: native.capture_ipv6(&before)?,
    };
    write_json(&native.state.join("intent.json"), &intent)?;
    let mut provisional = ownership;
    native.network_apply(&before, &after, Kernel::default(), &mut provisional)?;
    drop(native);
    let mut native = Native::open(router.options())?;
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(native.observe(&enabled)?, enabled);
    exchange(9, &upstream, "10.4.30.1")?;
    let mut failing = changed.clone();
    failing.ntp.enabled = true;
    failing.ntp.servers = vec!["10.4.40.40".into()];
    assert!(native.apply(&enabled, &failing).is_err());
    assert_eq!(native.observe(&enabled)?, enabled);
    exchange(10, &upstream, "10.4.30.1")?;
    native.apply(&enabled, &disabled)?;
    let stopped = native.statistics(&disabled, path, "")?;
    assert!(
        !stopped["rules"]
            .as_array()
            .context("missing counters")?
            .iter()
            .any(|row| row["id"]
                .as_str()
                .is_some_and(|id| id.contains("dhcp_relay")))
    );
    send_discover(11, false, 68, 67)?;
    assert_no_packet(&upstream)?;
    assert_eq!(native.observe(&disabled)?, disabled);
    native.apply(&disabled, &empty)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_interface_ownership_restores_physical_and_vlan_without_touching_other_links() -> Result<()>
{
    let fixture = Fixture::new()?;
    let namespace = Arc::new(File::open(&fixture.namespace)?);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
        handle.link().add().veth("parent0".into(), "peer0".into()).execute().await?;
        let links = networking::links(handle).await?;
        let parent = links.iter().find(|link| networking::name(link) == "parent0").context("parent missing")?.header.index;
        handle.link().set(parent).up().execute().await?;
        let peer = links.iter().find(|link| networking::name(link) == "peer0").context("peer missing")?.header.index;
        handle.link().set(peer).up().execute().await?;
        handle.link().add().vlan("vlan50".into(), parent, 50).execute().await?;
        let links = networking::links(handle).await?;
        let index = links.iter().find(|link| networking::name(link) == "vlan50").context("VLAN missing")?.header.index;
        handle.link().set(index).up().execute().await?;
        handle.address().add(index, "192.0.2.1".parse()?, 24).execute().await?;
        let wanted = netcontrol_core::AdoptVlanRequest {name:"vlan50".into(),parent:"parent0".into(),id:50};
        let snapshot = networking::capture_vlan_snapshot(handle, &wanted).await?;
        assert_eq!(snapshot.index, index);
        assert_eq!(snapshot.addresses.len(), 1);
        assert_eq!(snapshot.kind, "vlan");
        let mut wrong = wanted.clone();
        wrong.id = 51;
        assert!(networking::capture_vlan_snapshot(handle, &wrong).await.is_err());
        let before = Network::parse(&config(json!({"interfaces":[{"name":"parent0","kind":"ethernet","role":"unassigned","up":false,"mtu":1500,"addresses":[]}]}))?.operational_value()?)?;
        let after = Network::parse(&config(json!({"interfaces":[
            {"name":"parent0","kind":"ethernet","role":"unassigned","up":false,"mtu":1500,"addresses":[]},
            {"name":"vlan50","kind":"vlan","role":"unassigned","up":false,"mtu":1500,"addresses":["192.0.2.1/24"],"vlan":{"parent":"parent0","id":50}}
        ]}))?.operational_value()?)?;
        assert!(networking::preflight(handle, &before, &after).await.is_err());
        let repeated = networking::capture_vlan_snapshot(handle, &wanted).await?;
        assert_eq!(repeated.index, index);
        assert_eq!(repeated.addresses, snapshot.addresses);
        handle.address().add(parent, "203.0.113.1".parse()?, 24).execute().await?;
        let mut dynamic = handle.address().add(parent, "203.0.114.1".parse()?, 24);
        let mut cache = netlink_packet_route::address::CacheInfo::default();
        cache.ifa_valid = 180;
        cache.ifa_preferred = 120;
        dynamic.message_mut().attributes.push(netlink_packet_route::address::AddressAttribute::CacheInfo(cache));
        dynamic.execute().await?;
        let mut originals = networking::capture_ethernet(handle, &before, &before).await?;
        originals.insert(wanted.name.clone(), snapshot.clone());
        let untouched = networking::links(handle).await?.into_iter()
            .find(|link| networking::name(link) == "peer0").context("peer missing")?;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        for address in networking::addresses(handle, parent).await? {
            if address.header.scope != netlink_packet_route::address::AddressScope::Link {
                handle.address().del(address).execute().await?;
            }
        }
        handle.address().add(parent, "203.0.115.1".parse()?, 24).execute().await?;
        handle.link().set(parent).mtu(1450).execute().await?;
        handle.link().set(parent).down().execute().await?;
        handle.address().add(index, "198.51.100.1".parse()?, 24).execute().await?;
        handle.link().set(index).mtu(1400).execute().await?;
        networking::check_vlan_identity(handle, &wanted, &snapshot).await?;
        networking::restore_interfaces(handle, &originals).await?;
        let restored = networking::capture_vlan_snapshot(handle, &wanted).await?;
        assert_ne!(restored.addresses, snapshot.addresses);
        networking::check_interface_snapshot(&restored, &snapshot)?;
        networking::restore_interfaces(handle, &originals).await?;
        let retried = networking::capture_vlan_snapshot(handle, &wanted).await?;
        networking::check_interface_snapshot(&retried, &snapshot)?;
        let peer_after = networking::links(handle).await?.into_iter()
            .find(|link| networking::name(link) == "peer0").context("peer disappeared")?;
        let peer_before = networking::parent(&untouched);
        let peer_after = networking::parent(&peer_after);
        assert_eq!((peer_after.name, peer_after.index, peer_after.mac, peer_after.mtu, peer_after.up),
            (peer_before.name, peer_before.index, peer_before.mac, peer_before.mtu, peer_before.up));
        assert_eq!(networking::addresses(handle, parent).await?.iter()
            .filter(|address| address.header.scope != netlink_packet_route::address::AddressScope::Link).count(), 2);
        handle.link().add().vlan("stacked".into(), index, 51).execute().await?;
        assert!(networking::capture_vlan_snapshot(handle, &wanted).await.is_err());
        let stacked = networking::links(handle).await?.into_iter().find(|link| networking::name(link) == "stacked").context("stacked missing")?;
        handle.link().del(stacked.header.index).execute().await?;
        let mut address = handle.address().add(index, "198.51.100.1".parse()?, 24);
        let mut cache = netlink_packet_route::address::CacheInfo::default();
        cache.ifa_preferred = 120;
        cache.ifa_valid = 120;
        address.message_mut().attributes.push(netlink_packet_route::address::AddressAttribute::CacheInfo(cache));
        address.execute().await?;
        assert!(networking::capture_vlan_snapshot(handle, &wanted).await.is_err());
        let present = networking::links(handle).await?.into_iter().find(|link| networking::name(link) == "vlan50").context("VLAN was deleted")?;
        assert_eq!(present.header.index, index);
        assert_eq!(networking::addresses(handle, index).await?.iter()
            .filter(|address| address.header.scope != netlink_packet_route::address::AddressScope::Link).count(), 2);
        Ok(())
    })
    })?;
    Ok(())
}

fn firewall_counter<'a>(snapshot: &'a Value, id: &str) -> Result<&'a Value> {
    snapshot["rules"]
        .as_array()
        .context("counter rows missing")?
        .iter()
        .find(|row| row["id"] == id)
        .with_context(|| format!("counter {id} missing: {snapshot}"))
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_capabilities_discovery_is_namespace_scoped_and_passive() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    session(native.namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .dummy("caps-test0".into())
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let before = native.discover_interfaces()?;
    let inventory = native.discover_interface_capabilities()?;
    assert_eq!(inventory.source, netcontrol_core::InventorySource::Native);
    assert_eq!(inventory.interfaces.len(), 2);
    let dummy = inventory
        .interfaces
        .iter()
        .find(|row| row.name == "caps-test0")
        .context("namespace dummy missing from capabilities")?;
    assert_eq!(dummy.kind, "dummy");
    assert!(dummy.hardware.is_none());
    assert!(dummy.queues.is_empty());
    assert!(
        dummy
            .errors
            .iter()
            .any(|error| error.contains("lab network namespace"))
    );
    assert_eq!(native.discover_interfaces()?, before);
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_loopback_discovery_has_fixed_role_and_static_addressing() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    for raised in [false, true] {
        if raised {
            session(native.namespace.clone(), |rt, handle| {
                rt.block_on(async {
                    let index = networking::links(handle)
                        .await?
                        .iter()
                        .find(|link| {
                            link.header
                                .flags
                                .contains(&netlink_packet_route::link::LinkFlag::Loopback)
                        })
                        .context("loopback missing")?
                        .header
                        .index;
                    handle.link().set(index).up().execute().await?;
                    handle
                        .link()
                        .add()
                        .dummy("lo-test0".into())
                        .execute()
                        .await?;
                    Ok(())
                })
            })?;
        }
        let inventory = native.discover_interfaces()?;
        let rows = inventory.as_array().context("discovery is not an array")?;
        let loopback = rows
            .iter()
            .find(|row| row["kind"] == "loopback")
            .context("loopback not discovered")?;
        assert_eq!(loopback["role"], "loopback");
        assert_eq!(loopback["addressing_type"], "static");
        assert_eq!(loopback["ownership"], "loopback");
        assert_eq!(loopback["up"], raised);
        for row in rows.iter().filter(|row| row["kind"] != "loopback") {
            assert!(row.as_object().unwrap().contains_key("role"));
            assert!(row["role"].is_null());
            assert!(row.as_object().unwrap().contains_key("addressing_type"));
            assert!(row["addressing_type"].is_null());
        }
        if raised {
            assert!(
                rows.iter()
                    .any(|row| row["name"] == "lo-test0" && row["kind"] == "dummy")
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespaces/net_admin and raw sockets"]
fn native_udp_relay_discovery_source_modes_recovery_and_rollback() -> Result<()> {
    use futures_util::TryStreamExt;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::{
        net::{Ipv4Addr, SocketAddr, UdpSocket},
        time::{Duration, Instant},
    };
    let router = Fixture::new()?;
    let controller = Fixture::new()?;
    let device = Fixture::new()?;
    let outsider = Fixture::new()?;
    let router_ns = Arc::new(File::open(&router.namespace)?);
    let controller_ns = Arc::new(File::open(&controller.namespace)?);
    let device_ns = Arc::new(File::open(&device.namespace)?);
    let outsider_ns = Arc::new(File::open(&outsider.namespace)?);
    for (name, peer, namespace, address, gateway) in [
        (
            "lan0",
            "client0",
            controller_ns.clone(),
            "192.0.2.2",
            "192.0.2.1",
        ),
        (
            "iot0",
            "device0",
            device_ns.clone(),
            "198.51.100.2",
            "198.51.100.1",
        ),
        (
            "other0",
            "outside0",
            outsider_ns.clone(),
            "203.0.113.2",
            "203.0.113.1",
        ),
    ] {
        let target = namespace.clone();
        session(router_ns.clone(), move |runtime, handle| {
            runtime.block_on(async {
                handle
                    .link()
                    .add()
                    .veth(name.into(), peer.into())
                    .execute()
                    .await?;
                let link = handle
                    .link()
                    .get()
                    .match_name(peer.into())
                    .execute()
                    .try_next()
                    .await?
                    .context("relay peer missing")?;
                handle
                    .link()
                    .set(link.header.index)
                    .setns_by_fd(target.as_raw_fd())
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
        session(namespace, move |runtime, handle| {
            runtime.block_on(async {
                let link = handle
                    .link()
                    .get()
                    .match_name(peer.into())
                    .execute()
                    .try_next()
                    .await?
                    .context("relay peer missing")?;
                handle
                    .address()
                    .add(link.header.index, address.parse()?, 24)
                    .execute()
                    .await?;
                handle.link().set(link.header.index).up().execute().await?;
                handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix("0.0.0.0".parse()?, 0)
                    .gateway(gateway.parse()?)
                    .output_interface(link.header.index)
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
    }
    let options = router.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let physical = config(json!({"interfaces":[
        {"name":"lan0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.1/24"]},
        {"name":"iot0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["198.51.100.1/24"]},
        {"name":"other0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["203.0.113.1/24"]}
    ]}))?;
    native.apply(&empty, &physical)?;
    session(router_ns.clone(), |_, _| {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
        Ok(())
    })?;
    let group = Ipv4Addr::new(239, 255, 255, 250);
    let echonet = Ipv4Addr::new(224, 0, 23, 0);
    let make_socket =
        |namespace: Arc<File>, address: &'static str, port: u16, group: Option<Ipv4Addr>| {
            session(namespace, move |_, _| {
                let socket =
                    UdpSocket::bind((if group.is_some() { "0.0.0.0" } else { address }, port))?;
                socket.set_read_timeout(Some(Duration::from_millis(350)))?;
                socket.set_broadcast(true)?;
                if let Some(group) = group {
                    socket.join_multicast_v4(&group, &address.parse()?)?;
                }
                let interface = u32::from_ne_bytes(address.parse::<Ipv4Addr>()?.octets());
                ensure!(
                    unsafe {
                        libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::IPPROTO_IP,
                            libc::IP_MULTICAST_IF,
                            (&interface as *const u32).cast(),
                            4,
                        )
                    } == 0,
                    "fixture multicast interface failed"
                );
                socket.set_multicast_ttl_v4(1)?;
                Ok(socket)
            })
        };
    let client = make_socket(controller_ns.clone(), "192.0.2.2", 4002, None)?;
    let target = make_socket(device_ns.clone(), "198.51.100.2", 4001, Some(group))?;
    let captured = session(device_ns.clone(), |_, _| {
        let descriptor = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_UDP,
            )
        };
        ensure!(
            descriptor >= 0,
            "open fixture UDP capture: {}",
            std::io::Error::last_os_error()
        );
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        ensure!(
            unsafe {
                libc::setsockopt(
                    descriptor.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&timeout as *const libc::timeval).cast(),
                    std::mem::size_of_val(&timeout) as _,
                )
            } == 0,
            "capture timeout"
        );
        Ok(descriptor)
    })?;
    let echonet_target = make_socket(device_ns.clone(), "198.51.100.2", 3610, Some(echonet))?;
    let outside = make_socket(outsider_ns, "203.0.113.2", 4002, None)?;
    let mut desired = physical.clone();
    desired.udp_broadcast_relay = serde_json::from_value(json!({"enabled":true,"instances":[
        {"id":1,"enabled":true,"port":4001,"interfaces":["lan0","iot0"],"multicast_address":"239.255.255.250"},
        {"id":2,"enabled":true,"port":3610,"interfaces":["lan0","iot0"],"multicast_address":"224.0.23.0"}]}))?;
    desired.validate()?;
    native.apply(&physical, &desired)?;
    let wait_running = |native: &mut Native, desired: &Config| -> Result<()> {
        let started = Instant::now();
        loop {
            let status = native.runtime(desired)?;
            let rows: Vec<_> = status["appliance_services"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["name"] == "udp-broadcast-relay")
                .collect();
            if rows.len() == 2 && rows.iter().all(|row| row["state"] == "running") {
                return Ok(());
            }
            ensure!(
                started.elapsed() < Duration::from_secs(8),
                "relay supervisors failed to recover: {status}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    wait_running(&mut native, &desired)?;
    let scan = br#"{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}"#;
    let mut buffer = [0; 2048];
    for destination in [
        "239.255.255.250:4001",
        "255.255.255.255:4001",
        "192.0.2.255:4001",
    ] {
        client.send_to(scan, destination)?;
        let (length, source) = target
            .recv_from(&mut buffer)
            .context("Govee discovery was not relayed")?;
        ensure!(
            source == "192.0.2.2:4002".parse::<SocketAddr>()? && &buffer[..length] == scan,
            "relay changed original source or payload: {source}"
        );
        let mut wire = [0; 2048];
        let length = unsafe {
            libc::recv(
                captured.as_raw_fd(),
                wire.as_mut_ptr().cast(),
                wire.len(),
                0,
            )
        };
        ensure!(
            length == (28 + scan.len()) as isize
                && wire[0] == 0x45
                && wire[1] >> 2 == 1
                && &wire[28..length as usize] == scan,
            "forwarded IPv4 DSCP/header/payload mismatch"
        );
        let expected = if destination.starts_with("239.") {
            [239, 255, 255, 250]
        } else {
            [198, 51, 100, 255]
        };
        ensure!(
            wire[16..20] == expected,
            "broadcast destination was not rewritten"
        );
        if destination.starts_with("239.") {
            ensure!(wire[8] == 1, "multicast TTL was changed");
        }
        ensure!(
            target.recv_from(&mut buffer).is_err(),
            "discovery echoed repeatedly"
        );
    }
    target.send_to(b"synthetic govee response", "192.0.2.2:4002")?;
    let (length, source) = client.recv_from(&mut buffer)?;
    ensure!(
        source.ip().to_string() == "198.51.100.2"
            && &buffer[..length] == b"synthetic govee response",
        "Govee routed reply failed"
    );
    let echonet_request = [
        0x10, 0x81, 0, 1, 0x05, 0xff, 1, 0x0e, 0xf0, 1, 0x62, 1, 0xd6, 0,
    ];
    client.send_to(&echonet_request, (echonet, 3610))?;
    let (length, source) = echonet_target.recv_from(&mut buffer)?;
    ensure!(
        source.ip().to_string() == "192.0.2.2" && buffer[..length] == echonet_request,
        "ECHONET discovery changed"
    );
    client.send_to(b"unicast must not relay", "192.0.2.1:4001")?;
    outside.send_to(b"unselected interface", "203.0.113.255:4001")?;
    ensure!(
        target.recv_from(&mut buffer).is_err(),
        "unicast/unselected ingress relayed"
    );
    let tag = 4i32;
    ensure!(
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                (&tag as *const i32).cast(),
                4,
            )
        } == 0,
        "set fixture DSCP"
    );
    client.send_to(b"tagged echo", (group, 4001))?;
    ensure!(
        target.recv_from(&mut buffer).is_err(),
        "instance DSCP echo was relayed"
    );
    let tag = 0i32;
    ensure!(
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                (&tag as *const i32).cast(),
                4,
            )
        } == 0,
        "clear fixture DSCP"
    );
    for source in [
        netcontrol_core::UDPRelaySource::InterfaceAddress,
        netcontrol_core::UDPRelaySource::InterfaceAddressAndPort,
    ] {
        let before = desired.clone();
        desired.udp_broadcast_relay.instances[0].source = source;
        native.apply(&before, &desired)?;
        wait_running(&mut native, &desired)?;
        client.send_to(scan, (group, 4001))?;
        let (_, peer) = target.recv_from(&mut buffer)?;
        ensure!(
            peer.ip().to_string() == "198.51.100.1"
                && peer.port()
                    == if source == netcontrol_core::UDPRelaySource::InterfaceAddressAndPort {
                        4001
                    } else {
                        4002
                    },
            "source rewrite mode failed: {peer}"
        );
    }
    let before = desired.clone();
    desired.udp_broadcast_relay.instances[0].source = netcontrol_core::UDPRelaySource::Original;
    native.apply(&before, &desired)?;
    wait_running(&mut native, &desired)?;
    native.restart_process(&desired, "udp-broadcast-relay:1")?;
    wait_running(&mut native, &desired)?;
    session(router_ns.clone(), |runtime, handle| {
        runtime.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("iot0".into())
                .execute()
                .try_next()
                .await?
                .context("iot0 missing")?;
            handle
                .link()
                .set(link.header.index)
                .down()
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let started = Instant::now();
    loop {
        let status = native.runtime(&desired)?;
        if status["appliance_services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == "udp-broadcast-relay" && row["retrying"] == true)
        {
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(3),
            "relay link failure was not observable"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    session(router_ns.clone(), |runtime, handle| {
        runtime.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("iot0".into())
                .execute()
                .try_next()
                .await?
                .context("iot0 missing")?;
            handle.link().set(link.header.index).up().execute().await?;
            Ok(())
        })
    })?;
    wait_running(&mut native, &desired)?;
    client.send_to(scan, (group, 4001))?;
    target.recv_from(&mut buffer)?;
    let mut blocked = desired.clone();
    blocked.firewall.input = Some(serde_json::from_value(
        json!({"policy":"drop","interfaces":[]}),
    )?);
    native.apply(&desired, &blocked)?;
    wait_running(&mut native, &blocked)?;
    client.send_to(scan, (group, 4001))?;
    ensure!(
        target.recv_from(&mut buffer).is_err(),
        "relay bypassed host-input firewall"
    );
    native.apply(&blocked, &desired)?;
    wait_running(&mut native, &desired)?;
    client.send_to(&[0x5a; 2000], (group, 4001))?;
    ensure!(
        target.recv_from(&mut buffer).is_err(),
        "oversized raw send unexpectedly fragmented"
    );
    let status = native.runtime(&desired)?;
    let row = status["appliance_services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "udp-broadcast-relay" && row["instance_id"] == 1)
        .context("relay status missing")?;
    ensure!(
        row["state"] == "running"
            && row["send_errors"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|count| count > 0)
            && row["last_send_error"].is_string(),
        "MTU send failure was hidden: {row}"
    );
    native.apply(&desired, &physical)?;
    client.send_to(scan, (group, 4001))?;
    ensure!(
        target.recv_from(&mut buffer).is_err(),
        "disabled relay still forwards"
    );
    let occupied = session(router_ns.clone(), |_, _| {
        Ok(UdpSocket::bind("0.0.0.0:4001")?)
    })?;
    native.apply(&physical, &desired)?;
    let started = Instant::now();
    loop {
        let status = native.runtime(&desired)?;
        if status["appliance_services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["instance_id"] == 1 && row["retrying"] == true)
        {
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(3),
            "port conflict not observable"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(occupied);
    wait_running(&mut native, &desired)?;
    client.send_to(scan, (group, 4001))?;
    target.recv_from(&mut buffer)?;
    let stopped = Instant::now();
    native.services.shutdown()?;
    ensure!(
        stopped.elapsed() < Duration::from_secs(1),
        "relay supervisors did not join promptly"
    );
    drop(native);
    let mut reopened = Native::open(options)?;
    reopened.repair(&desired)?;
    wait_running(&mut reopened, &desired)?;
    client.send_to(scan, (group, 4001))?;
    target.recv_from(&mut buffer)?;
    reopened.apply(&desired, &physical)?;
    client.send_to(scan, (group, 4001))?;
    ensure!(
        target.recv_from(&mut buffer).is_err(),
        "rollback did not stop relay"
    );
    reopened.apply(&physical, &empty)?;
    drop(reopened);
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespaces/net_admin, forwarding and nft FIB/NAT"]
fn native_destination_rewrite_packets_filtering_restart_and_rollback() -> Result<()> {
    use futures_util::TryStreamExt;
    use std::io::Read;
    use std::{
        net::{TcpListener, TcpStream, UdpSocket},
        time::Duration,
    };
    let router = Fixture::new()?;
    let client = Fixture::new()?;
    let server = Fixture::new()?;
    let router_ns = Arc::new(File::open(&router.namespace)?);
    let client_ns = Arc::new(File::open(&client.namespace)?);
    let server_ns = Arc::new(File::open(&server.namespace)?);
    for (name, peer, namespace, address, gateway) in [
        (
            "lan0",
            "client0",
            client_ns.clone(),
            "192.0.2.2",
            "192.0.2.1",
        ),
        (
            "lan1",
            "server0",
            server_ns.clone(),
            "198.51.100.53",
            "198.51.100.1",
        ),
    ] {
        let target = namespace.clone();
        session(router_ns.clone(), move |rt, handle| {
            rt.block_on(async {
                handle
                    .link()
                    .add()
                    .veth(name.into(), peer.into())
                    .execute()
                    .await?;
                let link = handle
                    .link()
                    .get()
                    .match_name(peer.into())
                    .execute()
                    .try_next()
                    .await?
                    .context("peer missing")?;
                handle
                    .link()
                    .set(link.header.index)
                    .setns_by_fd(target.as_raw_fd())
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
        session(namespace, move |rt, handle| {
            rt.block_on(async {
                fs::write(format!("/proc/sys/net/ipv6/conf/{peer}/accept_dad"), "0")?;
                let (ipv6, gateway6) = if peer == "client0" {
                    ("2001:db8:3::2", "2001:db8:3::1")
                } else {
                    ("2001:db8:2::53", "2001:db8:2::1")
                };
                let link = handle
                    .link()
                    .get()
                    .match_name(peer.into())
                    .execute()
                    .try_next()
                    .await?
                    .context("peer missing")?;
                handle
                    .address()
                    .add(link.header.index, ipv6.parse()?, 64)
                    .execute()
                    .await?;
                handle
                    .address()
                    .add(link.header.index, address.parse()?, 24)
                    .execute()
                    .await?;
                handle.link().set(link.header.index).up().execute().await?;
                handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix("0.0.0.0".parse()?, 0)
                    .gateway(gateway.parse()?)
                    .output_interface(link.header.index)
                    .execute()
                    .await?;
                handle
                    .route()
                    .add()
                    .v6()
                    .destination_prefix("::".parse()?, 0)
                    .gateway(gateway6.parse()?)
                    .output_interface(link.header.index)
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
    }
    session(router_ns.clone(), |_, _| {
        for name in ["lan0", "lan1"] {
            fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0")?;
        }
        Ok(())
    })?;
    let options = router.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let desired = config(json!({
        "ipv6_enabled":true,
        "interfaces":[
            {"name":"lan0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.1/24","2001:db8:3::1/64"]},
            {"name":"lan1","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["198.51.100.1/24","2001:db8:2::1/64"]},
            {"name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,"addresses":["203.0.113.1/24","2001:db8:1::1/64"]}
        ],
        "routes":[
            {"destination":"0.0.0.0/0","interface":"wan0","table":254,"metric":100},
            {"destination":"::/0","interface":"wan0","table":254,"metric":100}
        ],
        "firewall":{"allow_all_icmp":false,"policy":"accept","nat":{"destination_rewrite":[
            {"out_interface":"wan0","protocol":"udp","destination_port":53,"target_interface":"lan1","target_address":"198.51.100.53"},
            {"out_interface":"wan0","protocol":"tcp","destination_port":53,"target_interface":"lan1","target_address":"198.51.100.53"},
            {"out_interface":"wan0","protocol":"udp","destination_port":53,"target_interface":"lan1","target_address":"2001:db8:2::53"}
        ]}}
    }))?;
    desired.validate()?;
    native
        .apply(&empty, &desired)
        .context("install destination rewrite fixture")?;
    session(router_ns.clone(), |_, _| {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
        fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
        Ok(())
    })?;
    let (udp, tcp) = session(server_ns.clone(), |_, _| {
        let udp = UdpSocket::bind("198.51.100.53:53")?;
        udp.set_read_timeout(Some(Duration::from_millis(300)))?;
        let tcp = TcpListener::bind("198.51.100.53:53")?;
        tcp.set_nonblocking(true)?;
        Ok((udp, tcp))
    })?;
    let exchange = |destination: &'static str| -> Result<()> {
        let socket = session(client_ns.clone(), move |_, _| {
            let socket = UdpSocket::bind("192.0.2.2:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.send_to(b"rewrite", destination)?;
            Ok(socket)
        })?;
        let mut bytes = [0; 32];
        let (size, peer) = udp
            .recv_from(&mut bytes)
            .with_context(|| format!("target did not receive {destination}"))?;
        ensure!(
            peer.ip().to_string() == "192.0.2.2" && &bytes[..size] == b"rewrite",
            "source or payload changed"
        );
        udp.send_to(b"reply", peer)?;
        let (size, peer) = socket.recv_from(&mut bytes).with_context(|| {
            format!("client did not receive reverse NAT reply from {destination}")
        })?;
        ensure!(
            peer.to_string() == destination && &bytes[..size] == b"reply",
            "reverse NAT failed"
        );
        Ok(())
    };
    exchange("8.8.8.8:53")?;
    exchange("9.9.9.9:53")?;
    let udp6 = session(server_ns.clone(), |_, _| {
        let socket = UdpSocket::bind("[2001:db8:2::53]:53")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        Ok(socket)
    })?;
    let client6 = session(client_ns.clone(), |_, _| {
        let socket = UdpSocket::bind("[2001:db8:3::2]:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.send_to(b"ipv6", "[2001:4860:4860::8888]:53")?;
        Ok(socket)
    })?;
    let mut bytes6 = [0; 16];
    let (size, peer) = udp6
        .recv_from(&mut bytes6)
        .context("IPv6 target did not receive rewrite")?;
    ensure!(
        peer.ip().to_string() == "2001:db8:3::2" && &bytes6[..size] == b"ipv6",
        "IPv6 source/payload changed"
    );
    udp6.send_to(b"reply6", peer)?;
    let (size, peer) = client6
        .recv_from(&mut bytes6)
        .context("IPv6 reverse NAT failed")?;
    ensure!(
        peer.to_string() == "[2001:4860:4860::8888]:53" && &bytes6[..size] == b"reply6",
        "IPv6 reply tuple/payload changed"
    );
    let tcp_client = session(client_ns.clone(), |_, _| {
        Ok(TcpStream::connect_timeout(
            &"8.8.4.4:53".parse()?,
            Duration::from_secs(2),
        )?)
    })?;
    let (mut stream, peer) = tcp.accept()?;
    ensure!(peer.ip().to_string() == "192.0.2.2", "TCP source changed");
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut tcp_client = tcp_client;
    tcp_client.set_read_timeout(Some(Duration::from_secs(2)))?;
    tcp_client.write_all(b"tcp")?;
    let mut data = [0; 3];
    stream.read_exact(&mut data)?;
    ensure!(&data == b"tcp", "TCP data failed");
    stream.write_all(b"ack")?;
    tcp_client.read_exact(&mut data)?;
    ensure!(&data == b"ack", "TCP reverse NAT failed");
    let no_rewrite = |namespace: Arc<File>, destination: &'static str| -> Result<()> {
        session(namespace, move |_, _| {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.send_to(b"not rewritten", destination)?;
            Ok(())
        })?;
        match udp.recv_from(&mut [0; 32]) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(())
            }
            other => anyhow::bail!("unexpected rewritten packet: {other:?}"),
        }
    };
    no_rewrite(client_ns.clone(), "8.8.8.8:54")?;
    no_rewrite(router_ns.clone(), "9.9.9.9:53")?;
    // A LAN-routed destination on the same port must remain local, not hit this server.
    no_rewrite(client_ns.clone(), "198.51.100.99:53")?;
    let before = native.statistics(&desired, "/api/v1/statistics/firewall", "")?;
    for (index, minimum) in [(0, 2u128), (1, 1), (2, 1)] {
        let row = firewall_counter(
            &before,
            &format!("destination_rewrite:/firewall/nat/destination_rewrite/{index}"),
        )?;
        ensure!(
            row["packets"]
                .as_str()
                .context("packet count missing")?
                .parse::<u128>()?
                >= minimum,
            "DNAT counter missed traffic: {row}"
        );
    }
    native.observe(&desired)?;
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&desired)?;
    native.observe(&desired)?;
    ensure!(
        native.statistics(&desired, "/api/v1/statistics/firewall", "")?["generation"]
            != before["generation"],
        "startup repair must refresh firewall counter generation"
    );
    exchange("1.1.1.1:53")?;
    let mut blocked = desired.clone();
    blocked.firewall.policy = "drop".into();
    native.apply(&desired, &blocked)?;
    no_rewrite(client_ns.clone(), "8.8.4.4:53")?;
    native.apply(&blocked, &desired)?;
    exchange("208.67.222.222:53")?;
    let mut removed = desired.clone();
    removed.firewall.nat.destination_rewrite.clear();
    native.apply(&desired, &removed)?;
    no_rewrite(client_ns.clone(), "1.0.0.1:53")?;
    native.apply(&removed, &desired)?;
    exchange("208.67.220.220:53")?;
    native.observe(&desired)?;
    let mut maximum = desired.clone();
    maximum.firewall.nat.destination_rewrite = (1..=256)
        .map(|port| {
            let mut rule = desired.firewall.nat.destination_rewrite[0].clone();
            rule.destination_port = port;
            rule
        })
        .collect();
    maximum.validate()?;
    native.apply(&desired, &maximum)?;
    native.observe(&maximum)?;
    native.apply(&maximum, &desired)?;
    native.observe(&desired)?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, namespaces/net_admin, nftables and WireGuard"]
fn native_bgp_wireguard_learns_installs_withdraws_and_preserves_static_configuration() -> Result<()>
{
    use futures_util::TryStreamExt;
    let first = Fixture::new()?;
    let second = Fixture::new()?;
    let ns1 = Arc::new(File::open(&first.namespace)?);
    let ns2 = Arc::new(File::open(&second.namespace)?);
    let target = ns2.clone();
    session(ns1.clone(), move |rt, h| {
        rt.block_on(async {
            h.link()
                .add()
                .veth("under0".into(), "under1".into())
                .execute()
                .await?;
            let peer = h
                .link()
                .get()
                .match_name("under1".into())
                .execute()
                .try_next()
                .await?
                .context("veth missing")?;
            h.link()
                .set(peer.header.index)
                .setns_by_fd(target.as_raw_fd())
                .execute()
                .await?;
            let local = h
                .link()
                .get()
                .match_name("under0".into())
                .execute()
                .try_next()
                .await?
                .context("veth missing")?;
            h.address()
                .add(local.header.index, "192.0.2.1".parse()?, 24)
                .execute()
                .await?;
            h.link().set(local.header.index).up().execute().await?;
            Ok::<(), anyhow::Error>(())
        })
    })?;
    session(ns2, |rt, h| {
        rt.block_on(async {
            let link = h
                .link()
                .get()
                .match_name("under1".into())
                .execute()
                .try_next()
                .await?
                .context("veth missing")?;
            h.address()
                .add(link.header.index, "192.0.2.2".parse()?, 24)
                .execute()
                .await?;
            h.link().set(link.header.index).up().execute().await?;
            Ok::<(), anyhow::Error>(())
        })
    })?;
    let key1 = wireguard::create_key(&first.root.join("keys"), "bgp")?;
    let key2 = wireguard::create_key(&second.root.join("keys"), "bgp")?;
    let make = |side: u8, peer_key: &str| -> Result<Config> {
        let other = 3 - side;
        config(json!({
            "interfaces":[
                {"name":"wg0","kind":"wireguard","role":"wan","up":true,"mtu":1420,"addresses":[format!("10.10.0.{side}/30")],
                    "wireguard":{"key_ref":"bgp","listen_port":51820,"peers":[{"public_key":peer_key,"endpoint":format!("192.0.2.{other}:51820"),"allowed_ips":[format!("10.10.0.{other}/32")]}]}},
                {"name":"lan0","kind":"dummy","role":"lan","up":true,"mtu":1500,"addresses":[format!("198.51.{side}.1/24")]}
            ],
            "bgp":{"enabled":true,"local_asn":65000+u32::from(side),"router_id":format!("10.10.0.{side}"),
                "hold_seconds":6,"keepalive_seconds":2,
                "neighbors":[{"name":"remote","address":format!("10.10.0.{other}"),"remote_asn":65000+u32::from(other),"interface":"wg0","local_address":format!("10.10.0.{side}"),"wireguard_public_key":peer_key}]}
        }))
    };
    let config1 = make(1, &key2)?;
    config1.validate()?;
    let config2 = make(2, &key1)?;
    config2.validate()?;
    let mut a = Native::open(first.options())?;
    let mut b = Native::open(second.options())?;
    a.apply(&Config::empty(), &config1)
        .context("first BGP router apply")?;
    b.apply(&Config::empty(), &config2)
        .context("second BGP router apply")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let status = a.bgp_status(&config1)?;
        if status["routes"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|r| r["prefix"] == "198.51.2.0/24" && r["installed"] == true)
        }) {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "BGP did not install route: {status}; remote {}",
            b.bgp_status(&config2)?
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let status = a.bgp_status(&config1)?;
    let advertised = status["advertised_routes"]
        .as_array()
        .context("advertised inventory missing")?;
    ensure!(advertised.iter().any(|row| row == &json!({"prefix":"198.51.1.0/24","neighbor":"remote","interface":"wg0","next_hop":"10.10.0.1","source":"bgp"})), "established BGP session did not expose its advertisements: {status}");
    ensure!(
        !advertised
            .iter()
            .any(|row| row["prefix"] == "198.51.2.0/24"),
        "received route was mislabeled as advertised"
    );
    ensure!(
        status["neighbors"][0]["advertised_prefixes"].as_u64() == Some(advertised.len() as u64),
        "advertised count/list mismatch: {status}"
    );
    let runtime = a.runtime(&config1)?;
    ensure!(
        runtime["bgp"].get("advertised_routes").is_none(),
        "runtime leaked full advertised inventory"
    );
    let statistics = a.statistics(&config1, "/api/v1/statistics", "")?;
    ensure!(
        statistics["bgp"].get("advertised_routes").is_none(),
        "statistics leaked full advertised inventory"
    );
    ensure!(
        a.observe(&config1)? == config1,
        "BGP contaminated desired configuration"
    );
    let check = |namespace: Arc<File>, expected: bool| -> Result<()> {
        session(namespace, move |rt, h| {
            let device = wireguard_control::Device::get(
                &"wg0".parse()?,
                wireguard_control::Backend::Kernel,
            )?;
            let ips = device.peers[0]
                .config
                .allowed_ips
                .iter()
                .map(|p| format!("{}/{}", p.address, p.cidr))
                .collect::<Vec<_>>();
            ensure!(
                ips.contains(&"10.10.0.2/32".to_string()),
                "static WireGuard prefix lost"
            );
            ensure!(
                ips.contains(&"198.51.2.0/24".to_string()) == expected,
                "dynamic WireGuard prefix mismatch: {ips:?}"
            );
            let routes = rt.block_on(
                h.route()
                    .get(rtnetlink::IpVersion::V4)
                    .execute()
                    .try_collect::<Vec<_>>(),
            )?;
            let found=routes.iter().any(|r|r.header.protocol==netlink_packet_route::route::RouteProtocol::Other(245)
                && r.attributes.iter().any(|attr|matches!(attr,netlink_packet_route::route::RouteAttribute::Destination(netlink_packet_route::route::RouteAddress::Inet(ip)) if *ip=="198.51.2.0".parse::<std::net::Ipv4Addr>().unwrap())));
            ensure!(found == expected, "BGP kernel route mismatch");
            Ok(())
        })
    };
    check(a.namespace.clone(), true)?;
    {
        let _guard = a
            .bgp
            .state
            .lock()
            .map_err(|_| anyhow!("BGP fixture lock"))?;
        let peer_key = key2.clone();
        session(a.namespace.clone(), move |rt, h| {
            let key = wireguard_control::Key::from_base64(&peer_key)?;
            wireguard_control::DeviceUpdate::new()
                .add_peers(&[wireguard_control::PeerConfigBuilder::new(&key)
                    .replace_allowed_ips()
                    .add_allowed_ip("10.10.0.2".parse()?, 32)])
                .apply(&"wg0".parse()?, wireguard_control::Backend::Kernel)?;
            rt.block_on(async {
                let routes = h
                    .route()
                    .get(rtnetlink::IpVersion::V4)
                    .execute()
                    .try_collect::<Vec<_>>()
                    .await?;
                for route in routes {
                    if route.header.protocol
                        == netlink_packet_route::route::RouteProtocol::Other(245)
                    {
                        h.route().del(route).execute().await?;
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        })?;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        match check(a.namespace.clone(), true) {
            Ok(()) => break,
            Err(error) => {
                ensure!(
                    std::time::Instant::now() < deadline,
                    "BGP audit did not repair missing owned entries: {error:#}"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    a.bgp.abandon_for_crash_fixture()?;
    let mut recovered = bgp::Manager::new(a.namespace.clone(), a.state.clone())?;
    recovered.recover()?;
    a.bgp = recovered;
    ensure!(
        a.bgp_status(&config1)?["advertised_routes"] == json!([]),
        "recovery retained stale advertisements"
    );
    check(a.namespace.clone(), false)?;
    a.bgp.configure(&config1.operational_value()?)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let status = a.bgp_status(&config1)?;
        if status["routes"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|r| r["prefix"] == "198.51.2.0/24" && r["installed"] == true)
        }) {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "BGP did not recover after crash fixture: {status}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    b.bgp.shutdown()?;
    ensure!(
        b.bgp_status(&config2)?["advertised_routes"] == json!([]),
        "shutdown retained stale advertisements"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = a.bgp_status(&config1)?;
        if status["routes"].as_array().is_some_and(Vec::is_empty)
            && status["advertised_routes"]
                .as_array()
                .is_some_and(Vec::is_empty)
        {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "BGP did not withdraw on session loss: {status}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    check(a.namespace.clone(), false)?;
    a.bgp.restart()?;
    ensure!(
        a.bgp_status(&config1)?["advertised_routes"] == json!([]),
        "restart retained stale advertisements"
    );
    ensure!(
        a.observe(&config1)? == config1,
        "BGP restart changed configuration"
    );
    let mut changed = config1.clone();
    changed
        .interfaces
        .iter_mut()
        .find(|i| i.name == "lan0")
        .context("LAN missing")?
        .mtu = 1400;
    a.apply(&config1, &changed)?;
    ensure!(
        a.observe(&changed)? == changed,
        "BGP blocked a network-only apply"
    );
    a.apply(&changed, &config1)?;
    ensure!(a.observe(&config1)? == config1, "BGP blocked rollback");
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespaces/net_admin and nftables"]
fn native_operational_dns_and_link_monitor_restart_preserve_configuration() -> Result<()> {
    use futures_util::TryStreamExt;
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let desired = config(json!({
        "interfaces":[{"name":"diag0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"]}],
        "dns":{"diag0":{"servers":["127.0.0.1"]}}
    }))?;
    desired.validate()?;
    let mut network = desired.clone();
    // Namespace fixtures cannot publish DNS to the host's systemd-resolved.
    network.dns.clear();
    native.apply(&Config::empty(), &network)?;
    let namespace = native.namespace.clone();
    let listener = session(namespace, |runtime, handle| {
        runtime.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("lo".into())
                .execute()
                .try_next()
                .await?
                .context("loopback missing")?;
            handle.link().set(link.header.index).up().execute().await?;
            Ok::<(), anyhow::Error>(())
        })?;
        let socket = std::net::UdpSocket::bind("0.0.0.0:53")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        Ok(socket)
    })?;
    let server = std::thread::spawn(move || -> Result<()> {
        let mut bytes = [0; 512];
        for _ in 0..5 {
            let (size, peer) = listener.recv_from(&mut bytes)?;
            let mut response = bytes[..size].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[7] = 1;
            response.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            listener.send_to(&response, peer)?;
        }
        Ok(())
    });
    let mut request: netcontrol_core::DNSLookupRequest =
        serde_json::from_value(json!({"interface":"diag0","hostname":"example.test"}))?;
    request.validate()?;
    let lookup = native.prepare_dns_lookup(&desired, &request)?;
    let value = lookup()?;
    ensure!(
        value["status"] == "answered"
            && value["server"] == "127.0.0.1"
            && value["addresses"] == json!(["192.0.2.7"])
            && value["rtt_ms"].as_f64().is_some_and(|v| v > 0.0),
        "configured DNS lookup failed: {value}"
    );
    request.server = Some("127.0.0.1".parse()?);
    let mut overridden = desired.clone();
    overridden.dns.get_mut("diag0").unwrap().servers = vec!["127.0.0.2".into()];
    for snapshot in [&overridden, &network] {
        let value = native.prepare_dns_lookup(snapshot, &request)?()?;
        ensure!(
            value["status"] == "answered"
                && value["server"] == "127.0.0.1"
                && value["attempts"]
                    .as_array()
                    .is_some_and(|attempts| attempts.len() == 1),
            "explicit DNS server was not used exclusively: {value}"
        );
    }
    request.interface = None;
    request.server = Some("192.0.2.1".parse()?);
    for snapshot in [&network, &Config::empty()] {
        let value = native.prepare_dns_lookup(snapshot, &request)?()?;
        ensure!(
            value["status"] == "answered"
                && value["server"] == "192.0.2.1"
                && value["interface"].is_null()
                && value["attempts"]
                    .as_array()
                    .is_some_and(|attempts| attempts.len() == 1),
            "unbound explicit DNS query failed: {value}"
        );
    }
    server
        .join()
        .map_err(|_| anyhow!("DNS fixture panicked"))??;
    request.server = Some("127.0.0.2".parse()?);
    request.timeout_ms = 100;
    let value = native.prepare_dns_lookup(&desired, &request)?()?;
    ensure!(
        value["status"] == "failed"
            && value["attempts"]
                .as_array()
                .is_some_and(|attempts| attempts.len() == 1)
            && value["attempts"][0]["server"] == "127.0.0.2",
        "explicit DNS failure fell back to configured servers: {value}"
    );
    request.server = Some("::1".parse()?);
    let mut ipv4_only = network.clone();
    ipv4_only.ipv6_enabled = false;
    ensure!(
        native.prepare_dns_lookup(&ipv4_only, &request).is_err(),
        "IPv6 policy bypassed"
    );
    request.server = Some("127.0.0.1".parse()?);
    request.interface = Some("missing0".into());
    ensure!(
        native.prepare_dns_lookup(&network, &request).is_err(),
        "missing interface accepted"
    );
    native.restart_process(&network, "link-diagnostics")?;
    ensure!(
        native.observe(&network)? == network,
        "restart or diagnostic changed configuration"
    );
    Ok(())
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
            "ipv6_enabled":true,
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
        let keys = native.wireguard_dns.control.clone();
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
        "ipv6_enabled":true,
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
        let keys = native.wireguard_dns.control.clone();
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
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated Linux namespaces, net_admin and nftables"]
fn native_startup_ethernet_dhcp_and_interrupted_recovery() -> Result<()> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::route::{RouteAttribute, RouteProtocol};

    let fixture = Fixture::new()?;
    let options = fixture.options();
    let namespace = Arc::new(File::open(&fixture.namespace)?);
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            for (name, peer) in [
                ("static0", "staticpeer"),
                ("dhcp0", "dhcppeer"),
                ("disabled0", "disabledpeer"),
                ("unmanaged0", "unmanagedpeer"),
            ] {
                handle
                    .link()
                    .add()
                    .veth(name.into(), peer.into())
                    .execute()
                    .await?;
            }
            for link in networking::links(handle).await? {
                if matches!(networking::name(&link).as_str(), "staticpeer" | "dhcppeer") {
                    handle.link().set(link.header.index).up().execute().await?;
                }
            }
            Ok(())
        })
    })?;
    let desired = config(json!({
        "interfaces":[
            {"name":"static0","kind":"ethernet","role":"lan","mtu":1500,"up":true,
             "addresses":["198.51.100.1/24"]},
            {"name":"dhcp0","kind":"ethernet","role":"wan","mtu":1500,"up":true},
            {"name":"disabled0","kind":"ethernet","role":"unassigned","mtu":1500,"up":false}
        ],
        "dhcp_clients":{"dhcp0":{}},
        "routes":[
            {"destination":"203.0.113.0/24","interface":"static0","table":10000,"metric":10},
            {"destination":"198.18.0.0/16","gateway":"dhcp","interface":"dhcp0","table":10001,"metric":10}
        ]
    }))?;
    desired.validate()?;
    native.apply(&empty, &desired)?;
    native.dhcp.shutdown()?;
    let value = desired.operational_value()?;
    let lease = dhcp_client::Lease {
        client: netcontrol_core::DHCPClientConfig::default(),
        address: "192.0.2.2/24".into(),
        server: "192.0.2.1".parse()?,
        acquired_at: dhcp_client::now()?,
        lifetime: 3600,
        renewal: 1800,
        rebinding: 3150,
        routes: vec![
            Route {
                destination: "192.0.2.0/24".into(),
                gateway: String::new(),
                interface: "dhcp0".into(),
                table: 254,
                metric: 0,
            },
            Route {
                destination: "0.0.0.0/0".into(),
                gateway: "192.0.2.1".into(),
                interface: "dhcp0".into(),
                table: 254,
                metric: 100,
            },
        ],
        dns: vec![],
        domain: String::new(),
        mtu: None,
    };
    let lease_path = native.state.join("dhcp-dhcp0.json");
    let lease_intent = lease_path.with_extension("intent");
    let set_down = |names: Vec<&'static str>| -> Result<()> {
        session(namespace.clone(), move |rt, handle| {
            rt.block_on(async {
                let links = networking::links(handle).await?;
                for name in names {
                    let link = links
                        .iter()
                        .find(|link| networking::name(link) == name)
                        .context("fixture Ethernet missing")?;
                    handle
                        .link()
                        .set(link.header.index)
                        .down()
                        .execute()
                        .await?;
                }
                Ok(())
            })
        })
    };
    let states = || -> Result<BTreeMap<String, bool>> {
        session(namespace.clone(), |rt, handle| {
            rt.block_on(async {
                Ok(networking::links(handle)
                    .await?
                    .into_iter()
                    .map(|link| {
                        (
                            networking::name(&link),
                            link.header
                                .flags
                                .contains(&netlink_packet_route::link::LinkFlag::Up),
                        )
                    })
                    .collect())
            })
        })
    };
    let assert_states = |static_up, dhcp_up| -> Result<()> {
        let states = states()?;
        assert_eq!(states["static0"], static_up);
        assert_eq!(states["dhcp0"], dhcp_up);
        assert!(!states["disabled0"]);
        assert!(!states["unmanaged0"]);
        Ok(())
    };
    let reconcile = |native: &mut Native, target: &Value| -> Result<()> {
        native.reconcile_after_boot(target, native.ownership()?, None)
    };

    set_down(vec!["static0", "dhcp0"])?;
    let mut invalid_lease = lease.clone();
    invalid_lease.routes[1].gateway = "198.51.100.99".into();
    write_json(&lease_path, &invalid_lease)?;
    let saved = fs::read(&lease_path)?;
    let error = reconcile(&mut native, &value).unwrap_err();
    assert!(format!("{error:#}").contains("configure DHCP clients during startup reconciliation"));
    assert!(
        format!("{error:#}").contains("captured boot state restored"),
        "{error:#}"
    );
    assert_states(false, false)?;
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(fs::read(&lease_path)?, saved);

    write_json(&lease_path, &lease)?;
    reconcile(&mut native, &value).context("reconcile after lease restoration failure")?;
    native.observe(&desired)?;
    assert_states(true, true)?;

    native.dhcp.shutdown()?;
    set_down(vec!["static0", "dhcp0"])?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    let previous_ownership = native.ownership()?;
    let mut unreachable = desired.clone();
    unreachable.routes[0].gateway = "203.0.113.1".into();
    unreachable.validate()?;
    let unreachable_value = unreachable.operational_value()?;
    let mut unreachable_ownership = previous_ownership.clone();
    unreachable_ownership.committed_config = Some(unreachable_value.clone());
    let saved = fs::read(&lease_path)?;
    let error = native
        .reconcile_after_boot(&unreachable_value, unreachable_ownership, None)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("install managed route 203.0.113.0/24 on static0"),
        "{error:#}"
    );
    assert!(
        format!("{error:#}").contains("captured boot state restored"),
        "{error:#}"
    );
    assert_states(false, false)?;
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(fs::read(&lease_path)?, saved);
    let mut restored_ownership = native.ownership()?;
    restored_ownership.committed_config = previous_ownership.committed_config;
    native.save_ownership(&restored_ownership)?;
    reconcile(&mut native, &value).context("reconcile after static route failure")?;
    native.observe(&desired)?;
    assert_states(true, true)?;

    native.dhcp.shutdown()?;
    let mut pending = lease.clone();
    pending.routes[1].gateway = "192.0.2.3".into();
    let addressing = dhcp_client::Addressing {
        routes: Network::parse(&value)?
            .routes
            .into_iter()
            .filter(|route| route.interface == "dhcp0")
            .collect(),
        ..Default::default()
    };
    let previous = lease.clone();
    let pending_kernel = pending.clone();
    session(namespace.clone(), move |rt, handle| {
        rt.block_on(networking::dhcp_lease(
            handle,
            "dhcp0",
            Some(&previous),
            Some(&pending_kernel),
            &addressing,
            false,
        ))
    })?;
    write_json(&lease_intent, &json!({"after":pending}))?;
    set_down(vec!["static0"])?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    reconcile(&mut native, &value).context("reconcile interrupted DHCP route update")?;
    native.observe(&desired)?;
    assert_states(true, true)?;
    assert!(!lease_intent.exists());

    native.dhcp.shutdown()?;
    let previous = native.ownership()?;
    let mut intent = Intent {
        scope: native.identity.clone(),
        before: value.clone(),
        after: value.clone(),
        kernel_before: native.capture_kernel(&value, &value)?,
        ownership_before: previous.clone(),
        ethernet_before: native.capture_ethernet(&value, &value)?,
        ethernet_originals: previous.ethernet_originals.clone(),
        ipv6_before: native.capture_ipv6(&value)?,
    };
    let missing = intent
        .ethernet_before
        .remove("dhcp0")
        .context("fixture DHCP snapshot missing")?;
    write_json(&native.state.join("intent.json"), &intent)?;
    set_down(vec!["static0", "dhcp0"])?;
    drop(native);
    let error = match Native::open(options.clone()) {
        Ok(_) => anyhow::bail!("recovery accepted a missing Ethernet operation snapshot"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("no durable operation snapshot"));
    assert_states(false, false)?;
    assert!(
        options
            .services_state
            .join("native")
            .join("intent.json")
            .exists()
    );
    intent.ethernet_before.insert("dhcp0".into(), missing);
    write_json(
        &options.services_state.join("native").join("intent.json"),
        &intent,
    )?;
    let mut native = Native::open(options)?;
    native.observe(&desired)?;
    assert_states(true, true)?;
    assert!(!native.state.join("intent.json").exists());
    native.dhcp.shutdown()?;
    let snapshots = native.capture_ethernet(&value, &value)?;
    let index = session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == "dhcp0")
                .context("fixture DHCP interface missing")?;
            let index = link.header.index;
            let mut removed = false;
            for address in networking::addresses(handle, index).await? {
                if networking::address_string(&address)?.as_deref() == Some("192.0.2.2/24") {
                    handle.address().del(address).execute().await?;
                    removed = true;
                }
            }
            ensure!(removed, "fixture DHCP address missing");
            handle
                .address()
                .add(index, "192.0.2.2".parse()?, 24)
                .execute()
                .await?;
            handle
                .route()
                .add()
                .v4()
                .destination_prefix("198.18.0.0".parse()?, 16)
                .gateway("192.0.2.1".parse()?)
                .output_interface(index)
                .table_id(10001)
                .priority(10)
                .protocol(RouteProtocol::Other(crate::model::PROTOCOL))
                .execute()
                .await?;
            Ok(index)
        })
    })?;
    let error = session(namespace.clone(), move |rt, handle| {
        rt.block_on(networking::restore_ethernet(handle, &snapshots))
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("cannot safely restore prefix-route flags"));
    session(namespace, move |rt, handle| {
        rt.block_on(async {
            let routes: Vec<_> = handle
                .route()
                .get(rtnetlink::IpVersion::V4)
                .execute()
                .try_collect()
                .await?;
            assert!(routes.iter().any(|route| {
                route.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL)
                    && route
                        .attributes
                        .iter()
                        .any(|attribute| matches!(attribute, RouteAttribute::Oif(value) if *value == index))
            }));
            Ok(())
        })
    })?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn global_ipv6_disables_existing_loopback_and_future_links_and_restores() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let mut empty = Config::empty();
    empty.ipv6_enabled = true;
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
        "ipv6_enabled":true,
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
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespaces/net_admin, raw sockets and nft counter/log modules"]
fn native_icmp_filters_match_both_families_extension_headers_and_rollback() -> Result<()> {
    use futures_util::TryStreamExt;
    use std::{
        net::UdpSocket,
        os::fd::FromRawFd,
        time::{Duration, Instant},
    };
    let router = Fixture::new()?;
    let client = Fixture::new()?;
    let router_ns = Arc::new(File::open(&router.namespace)?);
    let client_ns = Arc::new(File::open(&client.namespace)?);
    let peer = client_ns.clone();
    session(router_ns.clone(), move |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .veth("lan0".into(), "client0".into())
                .execute()
                .await?;
            let link = handle
                .link()
                .get()
                .match_name("client0".into())
                .execute()
                .try_next()
                .await?
                .context("ICMP peer missing")?;
            handle
                .link()
                .set(link.header.index)
                .setns_by_fd(peer.as_raw_fd())
                .execute()
                .await?;
            fs::write("/proc/sys/net/ipv6/conf/lan0/accept_dad", "0")?;
            Ok(())
        })
    })?;
    session(client_ns.clone(), |rt, handle| {
        rt.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("client0".into())
                .execute()
                .try_next()
                .await?
                .context("ICMP peer missing")?;
            fs::write("/proc/sys/net/ipv6/conf/client0/accept_dad", "0")?;
            handle
                .address()
                .add(link.header.index, "192.0.2.2".parse()?, 24)
                .execute()
                .await?;
            handle
                .address()
                .add(link.header.index, "2001:db8::2".parse()?, 64)
                .execute()
                .await?;
            handle.link().set(link.header.index).up().execute().await?;
            handle
                .route()
                .add()
                .v4()
                .destination_prefix("0.0.0.0".parse()?, 0)
                .gateway("192.0.2.1".parse()?)
                .output_interface(link.header.index)
                .execute()
                .await?;
            handle
                .route()
                .add()
                .v6()
                .destination_prefix("::".parse()?, 0)
                .gateway("2001:db8::1".parse()?)
                .output_interface(link.header.index)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let empty = Config::empty();
    let mut native = Native::open(router.options())?;
    native.repair(&empty)?;
    let desired = config(json!({
        "ipv6_enabled":true,
        "interfaces":[
            {"name":"lan0","kind":"ethernet","role":"lan","up":true,"mtu":1500,
                "addresses":["192.0.2.1/24","2001:db8::1/64"]},
            {"name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,
                "addresses":["198.51.100.1/24","2001:db8:1::1/64"]}
        ],
        "firewall":{"policy":"drop","allow_all_icmp":false,
            "policies":{
                "hosts":[{"id":"client","name":"Client","addresses":["192.0.2.2","2001:db8::2"],
                    "policy":"drop","rules":[{"protocol":"icmp","action":"drop"}]}],
                "interfaces":[{"interface":"lan0","rules":[
                    {"protocol":"icmpv6","destination":"2001:db8:1::2/128","action":"drop"}]}]
            },
            "input":{"policy":"accept","interfaces":[{"interface":"lan0","rules":[
                {"protocol":"icmp","destination":"192.0.2.1/32","action":"drop"},
                {"protocol":"icmpv6","destination":"2001:db8::1/128","action":"drop"}
            ]}]}
        }
    }))?;
    desired.validate()?;
    native.apply(&empty, &desired)?;
    session(router_ns.clone(), |_, _| {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
        fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
        Ok(())
    })?;
    let send = |expect_reply: bool| {
        session(client_ns.clone(), move |_, _| {
            for ipv6 in [false, true] {
                let fd = unsafe {
                    libc::socket(
                        if ipv6 { libc::AF_INET6 } else { libc::AF_INET },
                        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                        if ipv6 {
                            libc::IPPROTO_ICMPV6
                        } else {
                            libc::IPPROTO_ICMP
                        },
                    )
                };
                ensure!(fd >= 0, "ICMP socket: {}", std::io::Error::last_os_error());
                let socket = unsafe { UdpSocket::from_raw_fd(fd) };
                let (packet, addresses) = if ipv6 {
                    (
                        [128, 0, 0, 0, 0x12, 0x34, 0, 1],
                        ["[2001:db8::1]:0", "[2001:db8:1::2]:0"],
                    )
                } else {
                    (
                        [8, 0, 0xe5, 0xca, 0x12, 0x34, 0, 1],
                        ["192.0.2.1:0", "198.51.100.2:0"],
                    )
                };
                for address in addresses {
                    socket.send_to(&packet, address)?;
                }
                if ipv6 {
                    let options = [58u8, 0, 1, 4, 0, 0, 0, 0];
                    let result = unsafe {
                        libc::setsockopt(
                            fd,
                            libc::IPPROTO_IPV6,
                            libc::IPV6_DSTOPTS,
                            options.as_ptr().cast(),
                            options.len() as libc::socklen_t,
                        )
                    };
                    ensure!(
                        result == 0,
                        "IPv6 destination options: {}",
                        std::io::Error::last_os_error()
                    );
                    for address in addresses {
                        socket.send_to(&packet, address)?;
                    }
                }
                socket.set_read_timeout(Some(Duration::from_millis(100)))?;
                let deadline = Instant::now() + Duration::from_secs(1);
                let mut replied = false;
                loop {
                    let mut bytes = [0; 2048];
                    match socket.recv(&mut bytes) {
                        Ok(size) => {
                            let offset = if ipv6 {
                                0
                            } else {
                                usize::from(bytes[0] & 15) * 4
                            };
                            replied |=
                                bytes[..size].get(offset) == Some(&if ipv6 { 129 } else { 0 });
                            ensure!(
                                Instant::now() < deadline,
                                "ICMP receive did not become idle"
                            );
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                ensure!(
                    replied == expect_reply,
                    "unexpected ICMP echo reply state: IPv6={ipv6}, reply={replied}"
                );
            }
            let socket = UdpSocket::bind("192.0.2.2:0")?;
            for port in [9000, 9001, 9002] {
                socket.send_to(b"ports", format!("198.51.100.2:{port}"))?;
            }
            Ok(())
        })
    };
    let count = |snapshot: &Value, id: &str| -> Result<u128> {
        Ok(firewall_counter(snapshot, id)?["packets"]
            .as_str()
            .context("missing packets")?
            .parse()?)
    };
    let mut legacy = desired.clone();
    legacy.firewall.policies = None;
    legacy.firewall.rules = serde_json::from_value(json!([
        {"protocol":"icmp","action":"drop"}, {"protocol":"icmpv6","action":"drop"},
        {"protocol":"udp","destination_ports":[9000,9002],"action":"drop"}
    ]))?;
    let mut previous_generation = None;
    for (index, (current, expected)) in [
        (
            &desired,
            [
                ("forward:/firewall/policies/hosts/0/rules/0", 1),
                ("forward:/firewall/policies/interfaces/0/rules/0", 2),
            ],
        ),
        (
            &legacy,
            [
                ("forward:/firewall/rules/0", 1),
                ("forward:/firewall/rules/1", 2),
            ],
        ),
        (
            &desired,
            [
                ("forward:/firewall/policies/hosts/0/rules/0", 1),
                ("forward:/firewall/policies/interfaces/0/rules/0", 2),
            ],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        send(false)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let measured = loop {
            let snapshot = native.statistics(current, "/api/v1/statistics/firewall", "")?;
            if count(&snapshot, expected[0].0)? >= expected[0].1
                && count(&snapshot, expected[1].0)? >= expected[1].1
                && count(&snapshot, "input:/firewall/input/interfaces/0/rules/1")? >= 2
            {
                break snapshot;
            }
            ensure!(
                Instant::now() < deadline,
                "ICMP counters missing: {snapshot}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(count(&measured, expected[0].0)?, 1);
        assert_eq!(count(&measured, expected[1].0)?, 2);
        assert!(count(&measured, "input:/firewall/input/interfaces/0/rules/0")? >= 1);
        if current.firewall.policies.is_none() {
            assert_eq!(count(&measured, "forward:/firewall/rules/2")?, 2);
            assert_eq!(
                firewall_counter(&measured, "forward:/firewall/rules/2")?["expanded_rules"],
                2
            );
        }
        if let Some(generation) = &previous_generation {
            assert_ne!(generation, &measured["generation"]);
        }
        previous_generation = Some(measured["generation"].clone());
        native.observe(current)?;
        if index < 2 {
            let next = if current.firewall.policies.is_some() {
                &legacy
            } else {
                &desired
            };
            native.apply(current, next)?;
        }
    }
    let mut accepting = desired.clone();
    for rule in &mut accepting.firewall.input.as_mut().unwrap().interfaces[0].rules {
        rule.action = "accept".into();
    }
    native.apply(&desired, &accepting)?;
    send(true)?;
    let accepted = native.statistics(&accepting, "/api/v1/statistics/firewall", "")?;
    for index in 0..2 {
        ensure!(
            count(
                &accepted,
                &format!("input:/firewall/input/interfaces/0/rules/{index}")
            )? > 0,
            "explicit ICMP accept did not match"
        );
    }
    native.observe(&accepting)?;
    Ok(())
}

#[test]
#[ignore = "requires Linux network namespaces and NET_ADMIN"]
fn native_firewall_counters_measure_rules_defaults_nat_and_resets_without_drift() -> Result<()> {
    use futures_util::TryStreamExt;
    use std::{
        net::UdpSocket,
        os::fd::FromRawFd,
        time::{Duration, Instant},
    };
    let router = Fixture::new()?;
    let client = Fixture::new()?;
    let router_ns = Arc::new(File::open(&router.namespace)?);
    let client_ns = Arc::new(File::open(&client.namespace)?);
    let peer = client_ns.clone();
    session(router_ns.clone(), move |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .veth("lan0".into(), "client0".into())
                .execute()
                .await?;
            let link = handle
                .link()
                .get()
                .match_name("client0".into())
                .execute()
                .try_next()
                .await?
                .context("counter peer missing")?;
            handle
                .link()
                .set(link.header.index)
                .setns_by_fd(peer.as_raw_fd())
                .execute()
                .await?;
            Ok(())
        })
    })?;
    session(client_ns.clone(), |rt, handle| {
        rt.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("client0".into())
                .execute()
                .try_next()
                .await?
                .context("counter peer missing")?;
            for address in ["192.0.2.2", "192.0.2.4"] {
                handle
                    .address()
                    .add(link.header.index, address.parse()?, 24)
                    .execute()
                    .await?;
            }

            handle.link().set(link.header.index).up().execute().await?;
            handle
                .route()
                .add()
                .v4()
                .destination_prefix("0.0.0.0".parse()?, 0)
                .gateway("192.0.2.1".parse()?)
                .output_interface(link.header.index)
                .execute()
                .await?;
            Ok(())
        })
    })?;
    let options = router.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let desired = config(json!({
        "interfaces":[
            {"name":"lan0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.1/24"]},
            {"name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,"addresses":["198.51.100.1/24"]}
        ],
        "firewall":{"policy":"drop","allow_all_icmp":true,
            "policies":{
                "interfaces":[{"interface":"lan0","rules":[{"protocol":"udp","destination_ports":[9000],"action":"drop"}]}],
                "hosts":[{"id":"client","name":"Client","addresses":["192.0.2.2","192.0.2.3"],"policy":"drop",
                    "rules":[{"protocol":"udp","destination_ports":[8080,8081],"action":"accept"}]}]
            },
            "input":{"policy":"drop","interfaces":[{"interface":"lan0","rules":[
                {"protocol":"udp","destination_ports":[7070],"action":"accept"},
                {"protocol":"udp","destination_ports":[7071],"action":"drop"}
            ]}]},
            "nat":{"masquerade":[{"family":"ipv4","out_interface":"wan0"}]}
        }
    }))?;
    desired.validate()?;
    native.apply(&empty, &desired)?;
    session(router_ns.clone(), |_, _| {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
        Ok(())
    })?;
    let path = "/api/v1/statistics/firewall";
    let initial = native.statistics(&desired, path, "")?;
    let ownership = fs::read(native.state.join("ownership.json"))?;
    let fingerprint = session(router_ns.clone(), |_, _| netfilter::fingerprint())?;
    let listener = session(router_ns.clone(), |_, _| {
        let socket = UdpSocket::bind("192.0.2.1:7070")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        Ok(socket)
    })?;
    session(client_ns.clone(), |_, _| {
        let socket = UdpSocket::bind("192.0.2.2:0")?;
        for port in [8080, 8081, 8082, 9000] {
            socket.send_to(b"counter", format!("198.51.100.2:{port}"))?;
        }
        let other = UdpSocket::bind("192.0.2.4:0")?;
        other.send_to(b"counter", "198.51.100.2:8080")?;
        for port in [7070, 7071, 7072] {
            socket.send_to(b"counter", format!("192.0.2.1:{port}"))?;
        }
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            )
        };
        ensure!(
            fd >= 0,
            "ICMP test socket failed: {}",
            std::io::Error::last_os_error()
        );
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        for address in ["192.0.2.1:0", "198.51.100.2:0"] {
            socket.send_to(&[8, 0, 0xe5, 0xca, 0x12, 0x34, 0, 1], address)?;
        }
        Ok(())
    })?;
    assert_eq!(listener.recv(&mut [0; 32])?, 7);
    let count = |snapshot: &Value, id: &str| -> Result<u128> {
        Ok(firewall_counter(snapshot, id)?["packets"]
            .as_str()
            .context("packet count missing")?
            .parse()?)
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let measured = loop {
        let snapshot = native.statistics(&desired, path, "")?;
        if count(&snapshot, "forward:/firewall/policies/hosts/0/rules/0")? >= 2
            && count(&snapshot, "input:/firewall/input/policy")? >= 1
        {
            break snapshot;
        }
        ensure!(
            Instant::now() < deadline,
            "counter traffic not observed: {snapshot}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    for id in [
        "forward:/firewall/policies/interfaces/0/rules/0",
        "forward:/firewall/policies/hosts/0/policy",
        "forward:/firewall/policy",
        "input:/firewall/input/interfaces/0/rules/0",
        "input:/firewall/input/interfaces/0/rules/1",
        "input:/firewall/input/policy",
        "forward:/firewall/allow_all_icmp",
        "input:/firewall/allow_all_icmp",
        "output:/firewall/allow_all_icmp",
        "postrouting:/firewall/nat/masquerade/0",
    ] {
        ensure!(
            count(&measured, id)? > 0,
            "counter did not match traffic: {id}: {measured}"
        );
    }
    let accepted = firewall_counter(&measured, "forward:/firewall/policies/hosts/0/rules/0")?;
    assert_eq!(accepted["expanded_rules"], 4);
    assert_eq!(accepted["packets"], "2");
    assert_eq!(accepted["bytes"], "70");
    assert_eq!(initial["generation"], measured["generation"]);
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
    assert_eq!(
        session(router_ns.clone(), |_, _| netfilter::fingerprint())?,
        fingerprint
    );
    native.observe(&desired)?;
    assert_eq!(
        native.statistics(&desired, path, "")?["generation"],
        measured["generation"]
    );
    let mut relabeled = desired.clone();
    let policies = relabeled.firewall.policies.as_mut().unwrap();
    policies.hosts[0].rules[0].origin = netcontrol_core::RuleOrigin::Import;
    policies.hosts[0].rules[0].import_source = Some("sando".into());
    policies.interfaces[0].rules[0].origin = netcontrol_core::RuleOrigin::Inherited;
    relabeled.firewall.input.as_mut().unwrap().interfaces[0].rules[0].origin =
        netcontrol_core::RuleOrigin::System;
    relabeled.firewall.nat.masquerade[0].origin = netcontrol_core::RuleOrigin::Import;
    relabeled.firewall.nat.masquerade[0].import_source = Some("other".into());
    relabeled.validate()?;
    native.apply(&desired, &relabeled)?;
    native.observe(&relabeled)?;
    let same_rules = native.statistics(&relabeled, path, "")?;
    assert_eq!(same_rules["generation"], measured["generation"]);
    assert_eq!(same_rules["ruleset_id"], measured["ruleset_id"]);
    assert_eq!(
        firewall_counter(&same_rules, "forward:/firewall/policies/hosts/0/rules/0")?,
        accepted
    );
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
    assert_eq!(
        session(router_ns.clone(), |_, _| netfilter::fingerprint())?,
        fingerprint
    );
    native.apply(&relabeled, &desired)?;
    drop(native);
    let mut native = Native::open(options)?;
    assert_eq!(
        native.statistics(&desired, path, "")?["generation"],
        measured["generation"]
    );
    native.repair(&desired)?;
    let repaired = native.statistics(&desired, path, "")?;
    assert_ne!(repaired["generation"], measured["generation"]);
    assert_eq!(
        count(&repaired, "forward:/firewall/policies/hosts/0/rules/0")?,
        0
    );
    let mut candidate = desired.clone();
    candidate.firewall.policies = None;
    candidate.firewall.rules =
        serde_json::from_value(json!([{"source":"192.0.2.2/32","action":"accept"}]))?;
    native.apply(&desired, &candidate)?;
    let applied = native.statistics(&candidate, path, "")?;
    assert_ne!(applied["generation"], repaired["generation"]);
    session(client_ns.clone(), |_, _| {
        UdpSocket::bind("192.0.2.2:0")?.send_to(b"legacy", "198.51.100.2:9090")?;
        Ok(())
    })?;
    ensure!(
        count(
            &native.statistics(&candidate, path, "")?,
            "forward:/firewall/rules/0"
        )? > 0,
        "legacy rule did not count traffic"
    );
    native.apply(&candidate, &desired)?;
    let rolled_back = native.statistics(&desired, path, "")?;
    assert_ne!(rolled_back["generation"], applied["generation"]);
    assert_eq!(
        count(&rolled_back, "forward:/firewall/policies/hosts/0/rules/0")?,
        0
    );
    session(router_ns, |_, _| {
        use rustables::{Batch, Chain, ProtocolFamily, Rule, Table};
        let table = Table::new(ProtocolFamily::Inet).with_name("netcontrol");
        let chain = Chain::new(&table).with_name("forward");
        let mut batch = Batch::new();
        Rule::new(&chain)?.accept().add_to_batch(&mut batch);
        batch.send()?;
        Ok(())
    })?;
    assert!(native.statistics(&desired, path, "").is_err());
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_aggregate_uptime_is_host_scoped_and_readonly() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut native = Native::open(fixture.options())?;
    let desired = Config::empty();
    native.repair(&desired)?;
    let ownership = fs::read(native.state.join("ownership.json"))?;
    let before: f64 = fs::read_to_string("/proc/uptime")?
        .split_whitespace()
        .next()
        .context("uptime missing")?
        .parse()?;
    let aggregate = native.statistics(&desired, "/api/v1/statistics", "")?;
    let after: f64 = fs::read_to_string("/proc/uptime")?
        .split_whitespace()
        .next()
        .context("uptime missing")?
        .parse()?;
    assert_eq!(aggregate["sample"]["scope"], native.identity);
    assert_eq!(aggregate["uptime"]["scope"], "host");
    assert_eq!(aggregate["uptime"]["status"], "available");
    assert!(aggregate["uptime"]["error"].is_null());
    let uptime = aggregate["uptime"]["data"]["uptime_seconds"]
        .as_f64()
        .context("uptime missing")?;
    assert!(uptime >= before && uptime <= after);
    assert!(
        aggregate["uptime"]["data"]["idle_seconds"]
            .as_f64()
            .context("idle missing")?
            >= 0.0
    );
    assert_eq!(
        aggregate["uptime"]["collected_at"],
        aggregate["sample"]["collected_at"]
    );
    let interfaces = native.statistics(&desired, "/api/v1/statistics/interfaces", "")?;
    assert!(interfaces.get("uptime").is_none());
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
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
        "routes":[{"destination":"198.51.100.0/24","gateway":"dhcp","interface":"wan0","table":254,"metric":10}],
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
        ethernet_before: native.capture_ethernet(&before, &after)?,
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
fn native_dhcp_gateway_routes_follow_site_changes_and_preserve_ownership() -> Result<()> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::route::{RouteProtocol, RouteScope};
    use rtnetlink::IpVersion;

    let fixture = Fixture::new()?;
    let root = fixture.root.clone();
    session(
        Arc::new(File::open(&fixture.namespace)?),
        move |rt, handle| {
            rt.block_on(async {
            handle.link().add().veth("wan0".into(), "peer0".into()).execute().await?;
            let index = networking::links(handle).await?.iter()
                .find(|link| networking::name(link) == "wan0")
                .context("DHCP test interface missing")?.header.index;
            handle.link().set(index).up().execute().await?;
            let lease: dhcp_client::Lease = serde_json::from_value(json!({
                "client":{}, "address":"192.0.2.10/24", "server":"192.0.2.1",
                "acquired_at":dhcp_client::now()?, "lifetime":3600,
                "renewal":1800, "rebinding":3150,
                "routes":[
                    {"destination":"192.0.2.0/24","interface":"wan0","table":254,"metric":0},
                    {"destination":"0.0.0.0/0","gateway":"192.0.2.1","interface":"wan0","table":254,"metric":100}
                ], "dns":[], "domain":"", "mtu":null
            }))?;
            let configured: Config = serde_json::from_value(json!({
                "interfaces":[{"name":"wan0","kind":"ethernet","role":"wan","mtu":1500,"up":true}],
                "dhcp_clients":{"wan0":{}},
                "routes":[
                    {"destination":"203.0.113.10/32","gateway":"dhcp","interface":"wan0","table":254,"metric":10},
                    {"destination":"203.0.113.11/32","gateway":"dhcp","interface":"wan0","table":10001,"metric":20}
                ]
            }))?;
            configured.validate()?;
            let mut network = Network::parse(&configured.operational_value()?)?;
            let addressing = dhcp_client::Addressing {
                mtu:1500, routes:network.routes.clone(), ..Default::default()
            };
            let owned = || async {
                let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
                let mut routes = messages.iter()
                    .filter(|message| message.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL))
                    .map(|message| networking::decode_route(message, &BTreeMap::from([(index, "wan0".into())])))
                    .collect::<Result<Vec<_>>>()?;
                routes.sort();
                Ok::<_, anyhow::Error>(routes)
            };
            let expected = |lease: &dhcp_client::Lease, settings: &dhcp_client::Addressing| -> Result<Vec<crate::model::Route>> {
                let mut routes = dhcp_client::lease_routes("wan0", &settings.routes, Some(lease))?;
                routes.sort();
                Ok(routes)
            };
            networking::dhcp_lease(handle, "wan0", None, Some(&lease), &addressing, false).await?;
            assert_eq!(owned().await?, expected(&lease, &addressing)?);
            networking::dhcp_lease(handle, "wan0", Some(&lease), Some(&lease), &addressing, false).await?;
            assert_eq!(owned().await?, expected(&lease, &addressing)?);
            let mut state = dhcp_client::State::default();
            state.leases.insert("wan0".into(), lease.clone());
            dhcp_client::effective(&mut network, &state)?;
            assert_eq!(network.routes, owned().await?);
            let keys = wireguard::Control {
                keys: root.join("keys"),
                dns: wireguard_dns::Cache::new(root.join("wireguard-dns.json"))?,
            };
            let snapshot = networking::boot_snapshot(handle, &network, &keys).await?;
            assert_eq!(Network::parse(&snapshot)?.routes, network.routes);

            let mut changed = lease.clone();
            changed.address = "198.51.100.10/24".into();
            changed.server = "198.51.100.1".parse()?;
            changed.routes[0].destination = "198.51.100.0/24".into();
            changed.routes[1].gateway = "198.51.100.1".into();
            networking::dhcp_lease(handle, "wan0", Some(&lease), Some(&changed), &addressing, false).await?;
            assert_eq!(owned().await?, expected(&changed, &addressing)?);
            let mut same_address = changed.clone();
            same_address.routes[1].gateway = "198.51.100.2".into();
            networking::dhcp_lease(handle, "wan0", Some(&changed), Some(&same_address), &addressing, false).await?;
            assert_eq!(owned().await?, expected(&same_address, &addressing)?);
            networking::dhcp_lease(handle, "wan0", Some(&same_address), Some(&changed), &addressing, false).await?;
            assert_eq!(owned().await?, expected(&changed, &addressing)?);

            // A lease without a usable default fails before any networking mutation.
            let mut missing = changed.clone();
            missing.routes.pop();
            assert!(networking::dhcp_lease(handle, "wan0", Some(&changed), Some(&missing), &addressing, false).await.is_err());
            assert_eq!(owned().await?, expected(&changed, &addressing)?);

            // A pinned route can still reject a new site; rollback restores both modes.
            let mut pinned = addressing.clone();
            pinned.routes.push(serde_json::from_value(json!({
                "destination":"203.0.113.12/32","gateway":"198.51.100.1",
                "interface":"wan0","table":254,"metric":30
            }))?);
            networking::dhcp_lease(handle, "wan0", Some(&changed), Some(&changed), &pinned, false).await?;
            let mut failed = changed.clone();
            failed.address = "198.18.0.10/24".into();
            failed.routes[0].destination = "198.18.0.0/24".into();
            failed.routes[1].gateway = "198.18.0.1".into();
            assert!(networking::dhcp_lease(handle, "wan0", Some(&changed), Some(&failed), &pinned, false).await.is_err());
            networking::dhcp_lease(handle, "wan0", Some(&failed), Some(&changed), &pinned, false).await?;
            assert_eq!(owned().await?, expected(&changed, &pinned)?);
            networking::dhcp_lease(handle, "wan0", Some(&changed), None, &pinned, false).await?;
            assert!(owned().await?.is_empty());
            networking::dhcp_lease(handle, "wan0", None, Some(&changed), &addressing, false).await?;
            assert_eq!(owned().await?, expected(&changed, &addressing)?);

            let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            let owned_route = messages.into_iter().find(|message|
                message.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL)
                    && message.header.table == 254).context("owned host route missing")?;
            handle.route().del(owned_route).execute().await?;
            handle.route().add().v4().destination_prefix("203.0.113.10".parse()?, 32)
                .output_interface(index).priority(10).protocol(RouteProtocol::Other(99))
                .scope(RouteScope::Link).execute().await?;
            let before = owned().await?;
            let error = networking::dhcp_lease(handle, "wan0", Some(&changed), Some(&same_address), &addressing, false).await.unwrap_err();
            assert!(format!("{error:#}").contains("conflicts with existing route"), "{error:#}");
            assert_eq!(owned().await?, before);
            let messages: Vec<_> = handle.route().get(IpVersion::V4).execute().try_collect().await?;
            assert!(messages.iter().any(|message| message.header.protocol == RouteProtocol::Other(99)));
            assert_eq!(configured.routes[0].gateway, "dhcp");
            Ok(())
        })
        },
    )
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_dhcp_gateway_lease_intent_recovery_and_restart() -> Result<()> {
    use futures_util::TryStreamExt;
    use netlink_packet_route::route::RouteProtocol;
    use rtnetlink::IpVersion;

    let fixture = Fixture::new()?;
    let namespace = Arc::new(File::open(&fixture.namespace)?);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .veth("wan0".into(), "peer0".into())
                .execute()
                .await?;
            let index = networking::links(handle)
                .await?
                .iter()
                .find(|link| networking::name(link) == "wan0")
                .context("DHCP test interface missing")?
                .header
                .index;
            handle.link().set(index).up().execute().await?;
            Ok(())
        })
    })?;
    let configured: Config = serde_json::from_value(json!({
        "interfaces":[{"name":"wan0","kind":"ethernet","role":"wan","mtu":1500,"up":true}],
        "dhcp_clients":{"wan0":{}},
        "routes":[{"destination":"203.0.113.10/32","gateway":"dhcp","interface":"wan0","table":254,"metric":10}]
    }))?;
    configured.validate()?;
    let plan = configured.operational_value()?;
    let network = Network::parse(&plan)?;
    let settings = dhcp_client::Addressing {
        mtu: 1500,
        routes: network.routes,
        ..Default::default()
    };
    let committed: dhcp_client::Lease = serde_json::from_value(json!({
        "client":{}, "address":"192.0.2.10/24", "server":"192.0.2.1",
        "acquired_at":dhcp_client::now()?, "lifetime":3600,
        "renewal":1800, "rebinding":3150,
        "routes":[
            {"destination":"192.0.2.0/24","interface":"wan0","table":254,"metric":0},
            {"destination":"0.0.0.0/0","gateway":"192.0.2.1","interface":"wan0","table":254,"metric":100}
        ], "dns":[], "domain":"", "mtu":null
    }))?;
    let mut interrupted = committed.clone();
    interrupted.address = "198.51.100.10/24".into();
    interrupted.routes[0].destination = "198.51.100.0/24".into();
    interrupted.routes[1].gateway = "198.51.100.1".into();
    let applied = interrupted.clone();
    session(namespace.clone(), move |rt, handle| {
        rt.block_on(networking::dhcp_lease(
            handle,
            "wan0",
            None,
            Some(&applied),
            &settings,
            false,
        ))
    })?;
    let directory = fixture.root.join("clients");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let lease_path = directory.join("dhcp-wan0.json");
    let intent_path = directory.join("dhcp-wan0.intent");
    write_json(&lease_path, &committed)?;
    write_json(&intent_path, &json!({"after":interrupted}))?;
    let persisted = fs::read(&lease_path)?;
    for _ in 0..2 {
        let mut manager = dhcp_client::Manager::new(namespace.clone(), directory.clone(), false);
        manager.configure(&plan)?;
        assert_eq!(manager.status()?["errors"], json!({}));
        assert_eq!(
            manager.status()?["leases"]["wan0"],
            serde_json::to_value(&committed)?
        );
        assert!(!intent_path.exists());
        assert_eq!(fs::read(&lease_path)?, persisted);
        let mut effective = Network::parse(&plan)?;
        dhcp_client::effective(
            &mut effective,
            &*manager
                .state
                .lock()
                .map_err(|_| anyhow!("DHCP state poisoned"))?,
        )?;
        session(namespace.clone(), move |rt, handle| {
            rt.block_on(async {
                let available = networking::links(handle).await?;
                let names = available
                    .iter()
                    .map(|link| (link.header.index, networking::name(link)))
                    .collect();
                let routes: Vec<_> = handle
                    .route()
                    .get(IpVersion::V4)
                    .execute()
                    .try_collect()
                    .await?;
                let actual = routes
                    .iter()
                    .filter(|route| {
                        route.header.protocol == RouteProtocol::Other(crate::model::PROTOCOL)
                    })
                    .map(|route| networking::decode_route(route, &names))
                    .collect::<Result<Vec<_>>>()?;
                assert_eq!(actual, effective.routes);
                Ok(())
            })
        })?;
        manager.shutdown()?;
    }
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/net_admin privileges"]
fn native_static_routes_rechecked_after_configured_address_replacement() -> Result<()> {
    let fixture = Fixture::new()?;
    let keys = wireguard::Control {
        keys: fixture.root.join("keys"),
        dns: wireguard_dns::Cache::new(fixture.root.join("wireguard-dns.json"))?,
    };
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
    assert_eq!(all["schema"], "netcontrol-services/counters/v2");
    assert_eq!(all["scope"], "host");
    assert!(all["interfaces"].is_object());
    for name in ["host", "managed"] {
        let path = format!("/api/v1/statistics/vnstat/{name}");
        assert!(native.statistics(&desired, &path, "").is_err());
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
    {
        let name = "vnstat";
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
fn native_wireguard_dns_refresh_failure_restart_rollback_and_disabled_peer() -> Result<()> {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };
    use wireguard_control::{Backend as WgBackend, Device, DeviceUpdate, Key, PeerConfigBuilder};
    let fixture = Fixture::new()?;
    let options = fixture.options();
    wireguard::create_key(&options.keys, "wg")?;
    let public = Key([9; 32]).get_public().to_base64();
    let mut desired = config(json!({"ipv6_enabled":false,"interfaces":[{
        "name":"wg0","kind":"wireguard","role":"lan","up":true,"mtu":1420,
        "addresses":["10.44.0.1/24"],"wireguard":{"key_ref":"wg","listen_port":51820,
            "peers":[{"public_key":public,"endpoint":"localhost:51820",
                "allowed_ips":["10.44.0.2/32"],"persistent_keepalive_seconds":25}]}
    }]}))?;
    desired.validate()?;
    let empty = Config::empty();
    let mut native = Native::open(options.clone())?;
    native.repair(&empty)?;
    native.apply(&empty, &desired)?;
    let endpoint = |native: &Native| -> Result<Option<std::net::SocketAddr>> {
        session(native.namespace.clone(), |_, _| {
            let device = Device::get(&"wg0".parse()?, WgBackend::Kernel)?;
            Ok(device.peers.first().and_then(|peer| peer.config.endpoint))
        })
    };
    assert_eq!(endpoint(&native)?, Some("127.0.0.1:51820".parse()?));
    native.wireguard_dns.shutdown()?;
    let phase = Arc::new(AtomicUsize::new(0));
    let answers = phase.clone();
    native
        .wireguard_dns
        .control
        .dns
        .set_resolver(Arc::new(move |_, port, _| {
            let address = match answers.load(Ordering::Acquire) {
                0 => "127.0.0.1",
                1 => "192.0.2.20",
                2 => anyhow::bail!("synthetic DNS failure"),
                3 => "2001:db8::20",
                _ => "192.0.2.30",
            };
            Ok(vec![std::net::SocketAddr::new(address.parse()?, port)])
        }));
    native
        .wireguard_dns
        .configure_for_test(&desired.operational_value()?, Duration::from_millis(20))?;
    let ownership = fs::read(native.state.join("ownership.json"))?;
    let wait = |native: &Native, expected: &str, has_error: bool| -> Result<()> {
        let expected = Some(expected.parse()?);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = native.wireguard_dns.snapshot()?;
            if endpoint(native)? == expected && status["peers"][0]["error"].is_string() == has_error
            {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "WireGuard DNS convergence failed: {status}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    phase.store(1, Ordering::Release);
    wait(&native, "192.0.2.20:51820", false)?;
    assert_eq!(native.observe(&desired)?, desired);
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
    session(native.namespace.clone(), |_, _| {
        let device = Device::get(&"wg0".parse()?, WgBackend::Kernel)?;
        assert_eq!(device.listen_port, Some(51820));
        assert_eq!(device.peers.len(), 1);
        assert_eq!(
            device.peers[0].config.persistent_keepalive_interval,
            Some(25)
        );
        assert_eq!(device.peers[0].config.allowed_ips.len(), 1);
        assert_eq!(
            device.peers[0].config.allowed_ips[0].address,
            "10.44.0.2".parse::<std::net::IpAddr>()?
        );
        Ok(())
    })?;
    phase.store(2, Ordering::Release);
    wait(&native, "192.0.2.20:51820", true)?;
    assert!(
        native.runtime(&desired)?["wireguard_dns"]["peers"][0]["error"]
            .as_str()
            .unwrap()
            .contains("DNS failure")
    );
    assert_eq!(native.observe(&desired)?, desired);
    phase.store(3, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = native.wireguard_dns.snapshot()?;
        if status["peers"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("enabled IP families"))
        {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "IPv4-only DNS resolution did not reject AAAA-only answers"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(endpoint(&native)?, Some("192.0.2.20:51820".parse()?));
    let bgp_peer = public.clone();
    session(native.namespace.clone(), move |_, _| {
        DeviceUpdate::new()
            .add_peer(
                PeerConfigBuilder::new(&Key::from_base64(&bgp_peer)?)
                    .add_allowed_ip("198.51.100.0".parse()?, 24),
            )
            .apply(&"wg0".parse()?, WgBackend::Kernel)?;
        Ok(())
    })?;
    phase.store(4, Ordering::Release);
    wait(&native, "192.0.2.30:51820", false)?;
    let bgp_peer = public.clone();
    session(native.namespace.clone(), move |_, _| {
        let device = Device::get(&"wg0".parse()?, WgBackend::Kernel)?;
        assert_eq!(device.peers[0].config.allowed_ips.len(), 2);
        DeviceUpdate::new()
            .add_peer(
                PeerConfigBuilder::new(&Key::from_base64(&bgp_peer)?)
                    .replace_allowed_ips()
                    .add_allowed_ip("10.44.0.2".parse()?, 32),
            )
            .apply(&"wg0".parse()?, WgBackend::Kernel)?;
        Ok(())
    })?;
    let mut changed = desired.clone();
    changed.interfaces[0].wireguard.as_mut().unwrap().peers[0].endpoint =
        "other.example.test:51820".into();
    native.apply(&desired, &changed)?;
    phase.store(2, Ordering::Release);
    native.apply(&changed, &desired)?;
    assert_eq!(native.observe(&desired)?, desired);
    assert_eq!(endpoint(&native)?, Some("192.0.2.30:51820".parse()?));
    let mut unresolved = desired.clone();
    unresolved.interfaces[0].wireguard.as_mut().unwrap().peers[0].endpoint =
        "missing.example.test:51820".into();
    assert!(native.apply(&desired, &unresolved).is_err());
    assert_eq!(native.observe(&desired)?, desired);
    drop(native);
    let mut native = Native::open(options)?;
    native
        .wireguard_dns
        .control
        .dns
        .set_resolver(Arc::new(|_, _, _| {
            anyhow::bail!("synthetic offline startup")
        }));
    native.repair(&desired)?;
    assert_eq!(endpoint(&native)?, Some("192.0.2.30:51820".parse()?));
    let mut disabled = unresolved;
    disabled.interfaces[0].wireguard.as_mut().unwrap().peers[0].enabled = false;
    native.apply(&desired, &disabled)?;
    assert!(
        !native.wireguard_dns.snapshot()?["running"]
            .as_bool()
            .unwrap()
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(endpoint(&native)?, None);
    desired.interfaces[0].wireguard.as_mut().unwrap().peers[0].endpoint = "192.0.2.40:51820".into();
    native.apply(&disabled, &desired)?;
    let peer = public.clone();
    session(native.namespace.clone(), move |_, _| {
        DeviceUpdate::new()
            .add_peer(
                PeerConfigBuilder::new(&Key::from_base64(&peer)?)
                    .set_endpoint("192.0.2.50:51820".parse()?),
            )
            .apply(&"wg0".parse()?, WgBackend::Kernel)?;
        Ok(())
    })?;
    assert!(
        native
            .observe(&desired)
            .unwrap_err()
            .downcast_ref::<netcontrol_core::BackendDrift>()
            .is_some()
    );
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
    value["ipv6_enabled"] = json!(true);
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
    let keys = native.wireguard_dns.control.clone();
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
fn native_conntrack_timeouts_apply_restart_rollback_and_restore_originals() -> Result<()> {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut after = empty.clone();
    for parameter in netcontrol_core::kernel_catalog()
        .into_iter()
        .filter(|parameter| {
            parameter.name.starts_with("net.netfilter.") && parameter.scope == "namespace"
        })
    {
        after
            .kernel
            .namespace
            .insert(parameter.name.into(), "300".into());
    }
    after.validate()?;
    native.apply(&empty, &after)?;
    native.observe(&after)?;
    let runtime = native.runtime(&after)?;
    let original = runtime["kernel_tunables"]["captured_original"]["namespace"].clone();
    for name in after.kernel.namespace.keys() {
        assert!(original[name].is_string());
        assert_eq!(
            runtime["kernel_tunables"]["observed"]["namespace"][name],
            "300"
        );
    }
    let mut changed = after.clone();
    for value in changed.kernel.namespace.values_mut() {
        *value = "301".into();
    }
    native.apply(&after, &changed)?;
    native.observe(&changed)?;
    native.apply(&changed, &after)?;
    native.observe(&after)?;
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&after)?;
    native.observe(&after)?;
    native.apply(&after, &empty)?;
    native.observe(&empty)?;
    assert_eq!(
        native.runtime(&empty)?["kernel_tunables"]["observed"]["namespace"],
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
fn native_large_import_is_atomic_across_apply_restart_and_rollback() -> Result<()> {
    let fixture = Fixture::new()?;
    let options = fixture.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let mut desired = empty.clone();
    desired.firewall.rules = serde_json::from_value(Value::Array(
        (0..4096)
            .map(|index| {
                json!({
                    "source": format!("198.18.{}.{}/32", index / 256, index % 256),
                    "action": "accept",
                    "origin": "import",
                    "import_source": "sando"
                })
            })
            .collect(),
    ))?;
    desired.validate()?;
    native.apply(&empty, &desired)?;
    native.observe(&desired)?;
    let path = "/api/v1/statistics/firewall";
    let counters = native.statistics(&desired, path, "")?;
    assert_eq!(
        firewall_counter(&counters, "forward:/firewall/rules/4095")?["expanded_rules"],
        1
    );
    let fingerprint = session(native.namespace.clone(), |_, _| netfilter::fingerprint())?;
    let ownership = fs::read(native.state.join("ownership.json"))?;
    session(native.namespace.clone(), move |_, _| {
        use rustables::{Batch, Chain, MsgType, ProtocolFamily, Rule, Table};
        let table = Table::new(ProtocolFamily::Inet).with_name("netcontrol");
        let mut batch = Batch::new();
        batch.add(&table, MsgType::Add);
        batch.add(&table, MsgType::Del);
        batch.add(&table, MsgType::Add);
        let chain = Chain::new(&table)
            .with_name("forward")
            .add_to_batch(&mut batch);
        let missing = Chain::new(&table).with_name("missing");
        for index in 0..4096 {
            let target = if index == 2048 { &missing } else { &chain };
            Rule::new(target)?
                .with_userdata(vec![b'x'; 200])
                .accept()
                .add_to_batch(&mut batch);
        }
        let bytes = batch.finalize();
        let default: usize = fs::read_to_string("/proc/sys/net/core/wmem_default")?
            .trim()
            .parse()?;
        ensure!(
            bytes.len() > default,
            "regression batch must exceed the default send buffer"
        );
        let error = netfilter::send_batch(&bytes, 4100).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(netfilter::fingerprint()?, fingerprint);
        Ok(())
    })?;
    assert_eq!(fs::read(native.state.join("ownership.json"))?, ownership);
    native.observe(&desired)?;
    drop(native);
    let mut native = Native::open(options)?;
    native.observe_for_repair(&desired)?;
    assert_eq!(
        native.statistics(&desired, path, "")?["generation"],
        counters["generation"]
    );
    native.repair(&desired)?;
    native.observe(&desired)?;
    assert_ne!(
        native.statistics(&desired, path, "")?["generation"],
        counters["generation"]
    );
    native.apply(&desired, &empty)?;
    native.observe(&empty)?;
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
