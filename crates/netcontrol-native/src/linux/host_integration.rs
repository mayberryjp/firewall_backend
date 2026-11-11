//! Host-mode semantics run only after a child test process unshares its own network.
use super::*;
use futures_util::TryStreamExt;
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlags},
    link::{LinkAttribute, LinkMessage},
    route::{RouteProtocol, RouteScope},
};
use std::os::unix::fs::DirBuilderExt;

struct StateDirectory(PathBuf);
impl Drop for StateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated mount/network namespaces and nft/WireGuard/RPS support"]
fn native_wireguard_rps_lifecycle_recovery_and_replacement() -> Result<()> {
    ensure!(
        std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
        "set NETCONTROL_INTEGRATION=1; fixture never mutates the invoking network or mounts"
    );
    if std::env::var("NETCONTROL_WG_RPS_CHILD").as_deref() != Ok("1") {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "linux::host_integration::native_wireguard_rps_lifecycle_recovery_and_replacement",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NETCONTROL_WG_RPS_CHILD", "1")
            .status()?;
        ensure!(
            status.success(),
            "isolated WireGuard RPS child failed: {status}"
        );
        return Ok(());
    }
    ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) } == 0,
        "unshare network/mount namespaces: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } == 0,
        "make child mounts private: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe {
            libc::mount(
                c"sysfs".as_ptr(),
                c"/sys".as_ptr(),
                c"sysfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        } == 0,
        "mount child network sysfs: {}",
        std::io::Error::last_os_error()
    );
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    let directory = StateDirectory(std::env::current_dir()?.join(format!(
        ".native-wg-rps-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    )));
    fs::DirBuilder::new().mode(0o700).create(&directory.0)?;
    let options = NativeOptions {
        namespace: String::new(),
        keys: directory.0.join("keys"),
        services_state: directory.0.join("services"),
        adopted_parents: vec![],
        allow_host_tunables: false,
        allow_host_services: false,
        gateway_monitoring: false,
    };
    let first_key = wireguard::create_key(&options.keys, "first-key")?;
    let second_key = wireguard::create_key(&options.keys, "second-key")?;
    let online = netcontrol_core::parse_cpu_list(
        fs::read_to_string("/sys/devices/system/cpu/online")?.trim(),
    )?;
    let cpu = *online.first().context("no online CPU")?;
    let mask = netcontrol_core::cpu_mask(&[cpu].into());
    let mut desired: Config = serde_json::from_value(json!({
        "interfaces":[{"name":"wg0","kind":"wireguard","role":"wan","mtu":1420,"up":true,
            "addresses":[],"wireguard":{"key_ref":"first-key","listen_port":51820,"peers":[]}}],
        "kernel":{"rps":{"wg0/rx-0":mask}}
    }))?;
    desired.normalize();
    desired.validate()?;
    let empty = Config::empty();
    let mut native = Native::open(options.clone())?;
    native.repair(&empty)?;
    let read_mask = || -> Result<String> {
        Ok(rps::Io::system()
            .read(&desired.kernel.rps, &BTreeMap::new())?
            .0["wg0/rx-0"]
            .clone())
    };
    let mut unsupported = desired.clone();
    unsupported.kernel.rps = [("wg0/rx-4095".into(), mask.clone())].into();
    assert!(native.apply(&empty, &unsupported).is_err());
    assert!(!Path::new("/sys/class/net/wg0").exists());
    assert!(!native.state.join("intent.json").exists());
    native.observe(&empty)?;

    native.apply(&empty, &desired)?;
    assert_eq!(read_mask()?, mask);
    assert!(rps::Io::system().queues("wg0").is_err());
    assert!(
        rps::Io::system()
            .read(&[("lo/rx-0".into(), mask.clone())].into(), &BTreeMap::new())
            .is_err()
    );
    let ownership = native.ownership()?;
    let original = ownership.kernel_baseline.rps["wg0/rx-0"].clone();
    let identity = ownership.kernel_baseline.rps_identity["wg0"].clone();
    assert_eq!(
        identity.wireguard_public_key.as_deref(),
        Some(first_key.as_str())
    );
    assert!(identity.mac.is_empty());
    let sample = native.statistics(&desired, "/api/v1/statistics/performance", "")?;
    let row = sample["interfaces"]
        .as_array()
        .context("interface rows")?
        .iter()
        .find(|row| row["name"] == "wg0")
        .context("WireGuard diagnostic row")?;
    assert_eq!(row["managed"], true);
    assert_eq!(row["physical"], false);
    assert_eq!(row["rx_queues"][0]["rps_cpus"], mask);
    assert!(row["rx_queues"][0]["rps_flow_cnt"].is_null() && row["irqs"].is_null());
    assert!(
        sample["recommendations"]
            .as_array()
            .context("recommendations")?
            .is_empty()
    );
    let mut clear = desired.clone();
    clear.kernel.rps.clear();
    native.apply(&desired, &clear)?;
    assert_eq!(read_mask()?, original);
    assert!(native.ownership()?.kernel_baseline.rps.is_empty());
    native.apply(&clear, &desired)?;
    let mut disabled = desired.clone();
    disabled.kernel.rps.insert("wg0/rx-0".into(), "0".into());
    native.apply(&desired, &disabled)?;
    assert_eq!(read_mask()?, "0");
    native.apply(&disabled, &desired)?;

    let mut rekeyed = desired.clone();
    rekeyed.interfaces[0]
        .wireguard
        .as_mut()
        .context("WireGuard settings")?
        .key_ref = "second-key".into();
    native.apply(&desired, &rekeyed)?;
    assert_eq!(
        native.ownership()?.kernel_baseline.rps_identity["wg0"]
            .wireguard_public_key
            .as_deref(),
        Some(second_key.as_str())
    );
    assert_eq!(
        native.ownership()?.kernel_baseline.rps["wg0/rx-0"],
        original
    );
    native.apply(&rekeyed, &desired)?;
    native.observe(&desired)?;
    native.apply(&desired, &empty)?;
    assert!(!Path::new("/sys/class/net/wg0").exists());
    assert!(native.ownership()?.kernel_baseline.rps_identity.is_empty());
    native.apply(&empty, &desired)?;
    assert_ne!(
        native.ownership()?.kernel_baseline.rps_identity["wg0"].index,
        identity.index
    );

    // Interrupt a deletion after kernel convergence but before ownership is saved.
    let before = desired.operational_value()?;
    let after = empty.operational_value()?;
    let previous = native.ownership()?;
    let kernel_before = native.capture_kernel(&before, &after)?;
    write_json(
        &native.state.join("intent.json"),
        &Intent {
            scope: native.identity.clone(),
            before: before.clone(),
            after: after.clone(),
            kernel_before,
            ownership_before: previous.clone(),
            ethernet_before: BTreeMap::new(),
            ethernet_originals: BTreeMap::new(),
            ipv6_before: native.capture_ipv6(&before)?,
        },
    )?;
    let mut applying = previous.clone();
    native.network_apply(&before, &after, previous.kernel_baseline, &mut applying)?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    native.observe(&desired)?;
    assert_eq!(read_mask()?, mask);
    assert!(!native.state.join("intent.json").exists());

    let delete = |namespace: Arc<File>| -> Result<()> {
        session(namespace, |rt, handle| {
            rt.block_on(async {
                let link = networking::links(handle)
                    .await?
                    .into_iter()
                    .find(|link| networking::name(link) == "wg0")
                    .context("WireGuard link")?;
                handle.link().del(link.header.index).execute().await?;
                Ok(())
            })
        })
    };
    delete(namespace.clone())?;
    let mut ownership = native.ownership()?;
    ownership.boot = "synthetic-previous-boot".into();
    native.save_ownership(&ownership)?;
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&desired)?;
    native.observe(&desired)?;
    assert_eq!(read_mask()?, mask);
    assert_eq!(
        native.ownership()?.kernel_baseline.rps["wg0/rx-0"],
        original
    );

    // Even an externally recreated device using the same key cannot inherit ownership.
    delete(namespace.clone())?;
    let keys = native.wireguard_dns.control.clone();
    let a = Network::parse(&empty.operational_value()?)?;
    let b = Network::parse(&before)?;
    session(namespace, move |rt, handle| {
        rt.block_on(networking::reconcile(
            handle,
            &a,
            &b,
            &BTreeMap::new(),
            &keys,
            &BTreeMap::new(),
        ))
    })?;
    rps::Io::system().write(&desired.kernel.rps, &BTreeMap::new())?;
    assert!(native.observe(&desired).is_err());
    assert!(native.apply(&desired, &disabled).is_err());
    assert_eq!(read_mask()?, mask);
    assert!(!native.state.join("intent.json").exists());
    Ok(())
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

fn fixture_link(namespace: Arc<File>, name: &str) -> Result<LinkMessage> {
    let name = name.to_owned();
    session(namespace, move |rt, handle| {
        rt.block_on(async {
            networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == name)
                .context("fixture link missing")
        })
    })
}

fn link_alias(namespace: Arc<File>, name: &str) -> Result<String> {
    Ok(fixture_link(namespace, name)?
        .attributes
        .into_iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfAlias(value) => Some(value),
            _ => None,
        })
        .unwrap_or_default())
}

fn change_alias(namespace: Arc<File>, name: &str, alias: &str) -> Result<()> {
    let index = fixture_link(namespace.clone(), name)?.header.index;
    let alias = alias.to_owned();
    session(namespace, move |rt, handle| {
        rt.block_on(async {
            let request = handle.link().set(
                rtnetlink::LinkUnspec::new_with_index(index)
                    .append_extra_attribute(LinkAttribute::IfAlias(alias))
                    .build(),
            );
            request.execute().await?;
            Ok(())
        })
    })
}

fn foreign_routes(namespace: Arc<File>) -> Result<usize> {
    session(namespace, |rt, handle| {
        rt.block_on(async {
            let routes: Vec<_> = handle
                .route()
                .get(crate::linux::networking::route_query(
                    rtnetlink::IpVersion::V4,
                ))
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
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespaces, nftables, XDP and traffic-control support"]
fn native_aggressive_takeover_imports_supported_state_and_clears_foreign_networking() -> Result<()>
{
    if !isolate_host_fixture(
        "linux::host_integration::native_aggressive_takeover_imports_supported_state_and_clears_foreign_networking",
    )? {
        return Ok(());
    }
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    session(namespace, |rt, handle| {
        rt.block_on(async {
        use rustables::{Batch,Chain,ChainType,ChainPolicy,Hook,HookClass,Table,ProtocolFamily,Rule,Protocol};
        use rustables::expr::{Conntrack,ConntrackKey,Masquerade};
        use netlink_packet_route::{address::CacheInfo,link::LinkXdp};
        use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};
        ipv6::set(true)?;
        handle.link().add(rtnetlink::LinkVeth::new(&"nic0", &"peer0").build()).execute().await?;
        handle.link().add(rtnetlink::LinkDummy::new(&"aux0").build()).execute().await?;
        handle.link().add(rtnetlink::LinkBridge::new(&"foreign0").build()).execute().await?;
        let links=networking::links(handle).await?;
        let index=|name:&str|links.iter().find(|link|networking::name(link)==name).map(|link|link.header.index).context("fixture link missing");
        let nic=index("nic0")?;
        let peer=index("peer0")?;
        let bridge=index("foreign0")?;
        for id in [nic,peer,bridge,index("aux0")?] {
            handle.link().set(rtnetlink::LinkUnspec::new_with_index(id).up().build()).execute().await?;
        }
        handle.link().set(rtnetlink::LinkUnspec::new_with_index(nic).controller(bridge).mtu(1450).build()).execute().await?;
        handle.link().add(rtnetlink::LinkVlan::new(&"tag10", nic, 10).build()).execute().await?;
        let vlan=networking::links(handle).await?.into_iter().find(|link|networking::name(link)=="tag10").context("fixture VLAN missing")?.header.index;
        handle.link().add(rtnetlink::LinkVlan::new(&"tag20", vlan, 20).build()).execute().await?;
        handle.address().add(nic,"192.0.2.1".parse()?,24).execute().await?;
        handle.address().add(bridge,"198.18.0.1".parse()?,24).execute().await?;
        let mut dynamic=handle.address().add(peer,"198.51.100.8".parse()?,24);
        let mut lifetime=CacheInfo::default();
        lifetime.ifa_preferred=1800;
        lifetime.ifa_valid=3600;
        dynamic.message_mut().attributes.push(AddressAttribute::CacheInfo(lifetime));
        dynamic.execute().await?;
        handle.route().add(rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new().destination_prefix("10.50.0.0".parse()?,16).output_interface(nic).protocol(RouteProtocol::Static).scope(RouteScope::Link).build()).execute().await?;
        for priority in [9999,10005] {
            handle.rule().add().v4().priority(priority).table_id(10005).execute().await?;
        }
        handle.qdisc().add(i32::try_from(nic)?).ingress().execute().await?;
        #[repr(C)]
        struct Program {kind:u32,count:u32,instructions:u64,license:u64,log_level:u32,log_size:u32,log:u64}
        let instructions:[u8;16]=[0xb7,0,0,0,2,0,0,0,0x95,0,0,0,0,0,0,0];
        let program=Program{kind:6,count:2,instructions:instructions.as_ptr() as u64,license:c"GPL".as_ptr() as u64,log_level:0,log_size:0,log:0};
        let fd=unsafe{libc::syscall(libc::SYS_bpf,5,&program,std::mem::size_of::<Program>())};
        ensure!(fd>=0,"load fixture XDP: {}",std::io::Error::last_os_error());
        let fd=unsafe{OwnedFd::from_raw_fd(i32::try_from(fd)?)};
        let attach=handle.link().set(rtnetlink::LinkUnspec::new_with_index(nic).append_extra_attribute(LinkAttribute::Xdp(vec![LinkXdp::Fd(fd.as_raw_fd()),LinkXdp::Flags(1<<1)])).build());
        attach.execute().await?;
        let tc_instructions:[u8;16]=[0xb7,0,0,0,0,0,0,0,0x95,0,0,0,0,0,0,0];
        let tc_program=Program{kind:3,count:2,instructions:tc_instructions.as_ptr() as u64,license:c"GPL".as_ptr() as u64,log_level:0,log_size:0,log:0};
        let tc_fd=unsafe{libc::syscall(libc::SYS_bpf,5,&tc_program,std::mem::size_of::<Program>())};
        ensure!(tc_fd>=0,"load fixture TCX: {}",std::io::Error::last_os_error());
        let tc_fd=unsafe{OwnedFd::from_raw_fd(i32::try_from(tc_fd)?)};
        let tc_attach=[nic,tc_fd.as_raw_fd() as u32,46,0u32];
        ensure!(unsafe{libc::syscall(libc::SYS_bpf,8,tc_attach.as_ptr(),std::mem::size_of_val(&tc_attach))}==0,
            "attach fixture TCX: {}",std::io::Error::last_os_error());
        #[repr(C)]
        struct TcLink {program:u32,interface:u32,hook:u32,flags:u32,relative:u32,padding:u32,revision:u64}
        let tc_link=TcLink{program:tc_fd.as_raw_fd() as u32,interface:nic,hook:47,flags:0,relative:0,padding:0,revision:0};
        let tc_link=unsafe{libc::syscall(libc::SYS_bpf,28,&tc_link,std::mem::size_of::<TcLink>())};
        ensure!(tc_link>=0,"attach fixture TCX link: {}",std::io::Error::last_os_error());
        let _tc_link=unsafe{OwnedFd::from_raw_fd(i32::try_from(tc_link)?)};
        let state=format!("/run/systemd/netif/links/{nic}");
        fs::create_dir_all("/run/systemd/netif/links")?;
        fs::write(&state,"NETWORK_FILE=/etc/systemd/import.network\n")?;
        fs::write("/etc/systemd/import.network","[Network]\nDNS=203.0.113.53\n")?;
        let mut batch=Batch::new();
        let table=Table::new(ProtocolFamily::Ipv4).with_name("foreign").add_to_batch(&mut batch);
        let forward=Chain::new(&table).with_name("forward").with_type(ChainType::Filter).with_hook(Hook::new(HookClass::Forward,0)).with_policy(ChainPolicy::Drop).add_to_batch(&mut batch);
        Rule::new(&forward)?.snetwork("192.0.2.0/24".parse()?)?.accept().add_to_batch(&mut batch);
        Rule::new(&forward)?.with_expr(Conntrack::new(ConntrackKey::State)).drop().add_to_batch(&mut batch);
        let input=Chain::new(&table).with_name("input").with_type(ChainType::Filter).with_hook(Hook::new(HookClass::In,0)).with_policy(ChainPolicy::Drop).add_to_batch(&mut batch);
        Rule::new(&input)?.iiface("nic0")?.dport(443,Protocol::TCP).accept().add_to_batch(&mut batch);
        let post=Chain::new(&table).with_name("post").with_type(ChainType::Nat).with_hook(Hook::new(HookClass::PostRouting,100)).with_policy(ChainPolicy::Accept).add_to_batch(&mut batch);
        Rule::new(&post)?.oiface("nic0")?.with_expr(Masquerade{}).add_to_batch(&mut batch);
        Table::new(ProtocolFamily::Inet).with_name("netcontrol").add_to_batch(&mut batch);
        netfilter::send_batch(&batch.finalize(),9)?;
        let (receipt,plan)=takeover::capture_kernel(handle,"takeover-fixture".into(),json!({}),BTreeSet::new()).await?;
        let config=&receipt.config;
        assert!(!config.ipv6_enabled);
        assert_eq!(config.interfaces.len(),5);
        assert!(config.interfaces.iter().any(|link|link.name=="aux0" && link.kind=="dummy"));
        assert!(config.interfaces.iter().any(|link|link.name=="tag20" && link.vlan.as_ref().is_some_and(|vlan|vlan.parent=="tag10")));
        assert!(!config.interfaces.iter().any(|link|link.name=="foreign0"));
        assert_eq!(config.dns["nic0"].servers,vec!["203.0.113.53"]);
        assert!(config.dhcp_clients.contains_key("peer0"));
        assert!(config.interfaces.iter().find(|link|link.name=="peer0").unwrap().addresses.is_empty());
        assert_eq!(config.routes.len(),1,"report: {}",plan.report());
        assert_eq!(config.firewall.policy,"drop");
        assert_eq!(config.firewall.rules.len(),1,"report: {}",plan.report());
        assert_eq!(config.firewall.rules[0].source,"192.0.2.0/24");
        let input=config.firewall.input.as_ref().unwrap();
        assert_eq!(input.policy,"drop");
        let rules=&input.interfaces.iter().find(|link|link.interface=="nic0").unwrap().rules;
        assert_eq!(rules.len(),1,"report: {}",plan.report());
        assert_eq!(rules[0].destination_ports,vec![443]);
        assert_eq!(config.firewall.nat.masquerade.len(),1,"report: {}",plan.report());
        assert!(plan.items.iter().any(|item|item.resource.starts_with("firewall-rule:") && item.disposition=="disabled"));
        assert!(plan.items.iter().any(|item|item.resource.starts_with("tcx:nic0:") && item.disposition=="disabled"));
        let mut network=Network::parse(&config.operational_value()?)?;
        takeover::enforce_kernel(handle,&network,false,&[],&BTreeSet::new()).await?;
        networking::restore_interfaces(handle,&receipt.managed_originals()?).await?;
        let rules=handle.rule().get(rtnetlink::IpVersion::V4).execute().try_collect::<Vec<_>>().await?;
        assert!(rules.iter().all(takeover::standard_rule));
        network.policy_rules.push(crate::model::Rule{source:"0.0.0.0/0".into(),priority:10006,table:10006});
        for priority in [10006,10007] {
            handle.rule().add().v4().priority(priority).table_id(priority).execute().await?;
        }
        for prefix in ["10.50.0.0","10.51.0.0"] {
            handle.route().add(rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new().destination_prefix(prefix.parse()?,16).output_interface(nic).protocol(RouteProtocol::Other(crate::model::PROTOCOL)).scope(RouteScope::Link).build()).execute().await?;
        }
        takeover::enforce_kernel(handle,&network,true,&[],&BTreeSet::new()).await?;
        let routes=handle.route().get(crate::linux::networking::route_query(rtnetlink::IpVersion::V4)).execute().try_collect::<Vec<_>>().await?;
        assert_eq!(routes.iter().filter(|route|route.header.protocol==RouteProtocol::Other(crate::model::PROTOCOL)).count(),1);
        assert_eq!(netfilter::host_firewall_snapshot()?.len(),0);
        let links=networking::links(handle).await?;
        let bridge=links.iter().find(|link|networking::name(link)=="foreign0").unwrap();
        assert!(!bridge.header.flags.contains(netlink_packet_route::link::LinkFlags::Up));
        assert!(networking::addresses(handle,bridge.header.index).await?.is_empty());
        let nic=links.iter().find(|link|networking::name(link)=="nic0").unwrap();
        assert!(!nic.attributes.iter().any(|attr|matches!(attr,LinkAttribute::Controller(_))));
        assert!(!nic.attributes.iter().any(|attr|matches!(attr,LinkAttribute::Xdp(values) if values.iter().any(|attr|matches!(attr,LinkXdp::ProgId(id) if *id!=0)))));
        let rules=handle.rule().get(rtnetlink::IpVersion::V4).execute().try_collect::<Vec<_>>().await?;
        assert!(rules.iter().all(|rule|takeover::standard_rule(rule) || networking::decode_rule(rule).is_ok_and(|rule|network.policy_rules.contains(&rule))));
        assert!(networking::addresses(handle,peer).await?.iter().all(|message|message.header.family!=netlink_packet_route::AddressFamily::Inet));
        assert!(fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")?.trim()=="1");
        let nic_addresses=networking::addresses(handle,nic.header.index).await?;
        assert!(nic_addresses.iter().any(|address|networking::address_string(address).is_ok_and(|value|value.as_deref()==Some("192.0.2.1/24"))));
        let mut released=network.clone();
        released.interfaces.retain(|link|!matches!(link.name.as_str(),"nic0"|"tag10"|"tag20"));
        released.routes.clear();
        released.policy_rules.clear();
        handle.qdisc().add(i32::try_from(nic.header.index)?).ingress().execute().await?;
        let readonly=["nic0".into()].into();
        takeover::enforce_kernel(handle,&released,true,&[],&readonly).await?;
        assert!(networking::addresses(handle,nic.header.index).await?.iter().any(|address|networking::address_string(address).is_ok_and(|value|value.as_deref()==Some("192.0.2.1/24"))));
        let qdiscs=handle.qdisc().get().execute().try_collect::<Vec<_>>().await?;
        assert!(qdiscs.iter().any(|qdisc|qdisc.header.index==i32::try_from(nic.header.index).unwrap() && qdisc.header.parent==netlink_packet_route::tc::TcHandle::INGRESS));
        let (_,protected_plan)=takeover::capture_kernel(handle,"readonly-fixture".into(),json!({}),readonly).await?;
        assert!(!protected_plan.items.iter().any(|item|item.resource.starts_with(&format!("traffic-control:{}:",nic.header.index))));
        takeover::enforce_kernel(handle,&released,true,&[],&BTreeSet::new()).await?;
        assert!(networking::addresses(handle,nic.header.index).await?.is_empty());
        Ok(())
    })
    })
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespaces, pidfds and /bin/sleep fixture"]
fn native_takeover_stops_only_same_namespace_competitors() -> Result<()> {
    if !isolate_host_fixture(
        "linux::host_integration::native_takeover_stops_only_same_namespace_competitors",
    )? {
        return Ok(());
    }
    use std::{
        os::unix::process::CommandExt,
        process::{Child, Command},
    };
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = StateDirectory(
        std::env::current_dir()?.join(format!(".native-takeover-process-{}", std::process::id())),
    );
    fs::DirBuilder::new().mode(0o700).create(&directory.0)?;
    let executable = directory.0.join("dhclient");
    fs::copy("/bin/sleep", &executable)?;
    let mut same = ChildGuard(Command::new(&executable).arg("60").spawn()?);
    let mut other = Command::new(&executable);
    other.arg("60");
    unsafe {
        other.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWNET) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut other = ChildGuard(other.spawn()?);
    let processes = takeover_processes::capture()?;
    assert!(processes.iter().any(|(pid, _)| *pid == same.0.id()));
    assert!(!processes.iter().any(|(pid, _)| *pid == other.0.id()));
    takeover_processes::disable()?;
    assert!(!same.0.wait()?.success());
    assert!(other.0.try_wait()?.is_none());
    takeover_processes::disable()?;
    Ok(())
}

pub(super) fn isolate_host_fixture(test_name: &str) -> Result<bool> {
    ensure!(
        std::env::var("NETCONTROL_INTEGRATION").as_deref() == Ok("1"),
        "set NETCONTROL_INTEGRATION=1; privileged tests never mutate the invoking namespace"
    );
    if std::env::var("NETCONTROL_HOST_FIXTURE_CHILD").as_deref() != Ok(test_name) {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                test_name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NETCONTROL_HOST_FIXTURE_CHILD", test_name)
            .status()?;
        ensure!(
            status.success(),
            "isolated host-mode child fixture failed: {status}"
        );
        return Ok(false);
    }
    ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) } == 0,
        "child fixture requires CAP_SYS_ADMIN for unshare: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } == 0,
        "make fixture mounts private: {}",
        std::io::Error::last_os_error()
    );
    for (source, target, kind) in [
        (c"sysfs", c"/sys", c"sysfs"),
        (c"tmpfs", c"/run", c"tmpfs"),
        (c"tmpfs", c"/etc/systemd", c"tmpfs"),
    ] {
        ensure!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    kind.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            } == 0,
            "mount isolated fixture {}: {}",
            target.to_string_lossy(),
            std::io::Error::last_os_error()
        );
    }
    for path in ["/run", "/etc/systemd"] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(true)
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux network namespace privileges"]
fn ethernet_activation_precedes_dhcp_lease_restore() -> Result<()> {
    let test_name = "linux::host_integration::ethernet_activation_precedes_dhcp_lease_restore";
    if !isolate_host_fixture(test_name)? {
        return Ok(());
    }
    let state = StateDirectory(std::env::temp_dir().join(format!(
        ".native-activation-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    )));
    fs::DirBuilder::new().mode(0o700).create(&state.0)?;
    let keys = wireguard::Control {
        keys: state.0.join("keys"),
        dns: wireguard_dns::Cache::new(state.0.join("wireguard-dns.json"))?,
    };
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    session(namespace, move |rt, handle| {
        rt.block_on(async {
            for (name, peer) in [
                ("dhcp0", "peer0"),
                ("static0", "staticpeer"),
                ("disabled0", "disabledpeer"),
                ("unmanaged0", "unmanagedpeer"),
            ] {
                handle
                    .link()
                    .add(rtnetlink::LinkVeth::new(&name, &peer).build())
                    .execute()
                    .await?;
            }
            let links = networking::links(handle).await?;
            let index = links
                .iter()
                .find(|link| networking::name(link) == "dhcp0")
                .context("DHCP fixture interface missing")?
                .header
                .index;
            let peer = links
                .iter()
                .find(|link| networking::name(link) == "peer0")
                .context("DHCP fixture peer missing")?
                .header
                .index;
            handle
                .link()
                .set(rtnetlink::LinkUnspec::new_with_index(peer).up().build())
                .execute()
                .await?;
            handle
                .link()
                .set(rtnetlink::LinkUnspec::new_with_index(index).down().build())
                .execute()
                .await?;
            let config: Config = serde_json::from_value(json!({
                "interfaces":[
                    {"name":"dhcp0","kind":"ethernet","role":"wan","mtu":1500,"up":true},
                    {"name":"static0","kind":"ethernet","role":"lan","mtu":1500,"up":true,
                     "addresses":["198.51.100.1/24"]},
                    {"name":"disabled0","kind":"ethernet","role":"unassigned","mtu":1500,"up":false}
                ],
                "dhcp_clients":{"dhcp0":{}}
            }))?;
            let network = Network::parse(&config.operational_value()?)?;
            let snapshots = networking::capture_ethernet(handle, &network, &network).await?;
            let mut replaced = snapshots.clone();
            let identity = replaced
                .get_mut("static0")
                .context("static fixture identity missing")?;
            identity.mac = if identity.mac == "02:00:00:00:00:01" {
                "02:00:00:00:00:02"
            } else {
                "02:00:00:00:00:01"
            }
            .into();
            assert!(networking::check_ethernet(handle, &replaced).await.is_err());
            assert!(networking::needs_ethernet_activation(handle, &network).await?);
            networking::activate_ethernet(handle, &network).await?;
            let activated = networking::links(handle).await?;
            for (name, expected_up) in [
                ("dhcp0", true),
                ("static0", true),
                ("disabled0", false),
                ("unmanaged0", false),
            ] {
                let link = activated
                    .iter()
                    .find(|link| networking::name(link) == name)
                    .context("activation fixture interface missing")?;
                assert_eq!(
                    link.header
                        .flags
                        .contains(netlink_packet_route::link::LinkFlags::Up),
                    expected_up,
                    "{name}"
                );
            }
            assert!(!networking::needs_ethernet_activation(handle, &network).await?);
            let committed_route = Route {
                destination: "203.0.113.0/24".into(),
                gateway: "192.0.2.1".into(),
                interface: "dhcp0".into(),
                table: 254,
                metric: 10,
            };
            let mut pending_route = committed_route.clone();
            pending_route.gateway = "192.0.2.3".into();
            let mut configured_route = committed_route.clone();
            configured_route.gateway = "dhcp".into();
            let lease = dhcp_client::Lease {
                client: netcontrol_core::DHCPClientConfig::default(),
                address: "192.0.2.2/24".into(),
                server: "192.0.2.1".parse()?,
                acquired_at: dhcp_client::now()?,
                lifetime: 3600,
                renewal: 1800,
                rebinding: 3150,
                routes: vec![
                    crate::model::Route {
                        destination: "192.0.2.0/24".into(),
                        gateway: String::new(),
                        interface: "dhcp0".into(),
                        table: 254,
                        metric: 0,
                    },
                    crate::model::Route {
                        destination: "0.0.0.0/0".into(),
                        gateway: "192.0.2.3".into(),
                        interface: "dhcp0".into(),
                        table: 254,
                        metric: 100,
                    },
                ],
                dns: Vec::new(),
                domain: String::new(),
                mtu: None,
            };
            networking::dhcp_lease(
                handle,
                "dhcp0",
                None,
                Some(&lease),
                &dhcp_client::Addressing {
                    routes: vec![configured_route],
                    ..Default::default()
                },
                false,
            )
            .await?;
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == "dhcp0")
                .context("DHCP fixture interface disappeared")?;
            ensure!(
                link.header
                    .flags
                    .contains(netlink_packet_route::link::LinkFlags::Up),
                "DHCP lease restore left its interface down"
            );
            let routes: Vec<netlink_packet_route::route::RouteMessage> = handle
                .route()
                .get(crate::linux::networking::route_query(
                    rtnetlink::IpVersion::V4,
                ))
                .execute()
                .try_collect()
                .await?;
            ensure!(
                routes.iter().any(|route| {
                    route.header.protocol == RouteProtocol::Other(dhcp_client::PROTOCOL)
                        && route.attributes.iter().any(|attribute| {
                            matches!(
                                attribute,
                                netlink_packet_route::route::RouteAttribute::Oif(value)
                                    if *value == index
                            )
                        })
                }),
                "DHCP lease restore did not install its routes"
            );
            handle
                .link()
                .set(rtnetlink::LinkUnspec::new_with_index(peer).down().build())
                .execute()
                .await?;
            let mut allowed = network.clone();
            allowed.routes = vec![committed_route.clone(), pending_route];
            let mut captured = networking::boot_snapshot(handle, &allowed, &keys).await?;
            assert_eq!(Network::parse(&captured)?.routes.len(), 1);
            allowed.routes.pop();
            assert!(
                networking::boot_snapshot(handle, &allowed, &keys)
                    .await
                    .is_err(),
                "a route not covered by the committed or pending DHCP state was accepted"
            );
            retain_committed_boot_routes(&mut captured, &[committed_route])?;
            assert!(Network::parse(&captured)?.routes.is_empty());
            networking::restore_ethernet(handle, &snapshots).await?;
            let restored = networking::links(handle).await?;
            for name in ["dhcp0", "static0", "disabled0", "unmanaged0"] {
                let link = restored
                    .iter()
                    .find(|link| networking::name(link) == name)
                    .context("restored fixture interface missing")?;
                assert!(
                    !link
                        .header
                        .flags
                        .contains(netlink_packet_route::link::LinkFlags::Up),
                    "{name} was not restored to its original state"
                );
            }
            assert!(
                networking::addresses(handle, index)
                    .await?
                    .iter()
                    .all(|address| networking::address_string(address)
                        .is_ok_and(|value| value.as_deref() != Some("192.0.2.2/24")))
            );
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_default_ipv6_policy_controls_empty_host_restart_and_future_links() -> Result<()> {
    if !isolate_host_fixture(
        "linux::host_integration::native_default_ipv6_policy_controls_empty_host_restart_and_future_links",
    )? {
        return Ok(());
    }
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    session(namespace.clone(), |rt, handle| {
        ipv6::set(true)?;
        rt.block_on(async {
            handle
                .link()
                .add(rtnetlink::LinkVeth::new(&"nic0", &"peer0").build())
                .execute()
                .await?;
            let link = handle
                .link()
                .get()
                .match_name("nic0".into())
                .execute()
                .try_next()
                .await?
                .context("fixture NIC missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            for address in ["192.0.2.1", "2001:db8::1"] {
                let ip: std::net::IpAddr = address.parse()?;
                let mut request =
                    handle
                        .address()
                        .add(link.header.index, ip, if ip.is_ipv4() { 24 } else { 64 });
                request
                    .message_mut()
                    .attributes
                    .push(AddressAttribute::Flags(AddressFlags::Nodad));
                request.execute().await?;
            }
            Ok(())
        })
    })?;
    let directory = StateDirectory(std::env::current_dir()?.join(format!(
        ".native-ipv6-default-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    )));
    fs::DirBuilder::new().mode(0o700).create(&directory.0)?;
    let options = NativeOptions {
        namespace: String::new(),
        keys: directory.0.join("keys"),
        services_state: directory.0.join("services"),
        adopted_parents: vec![],
        allow_host_tunables: false,
        allow_host_services: false,
        gateway_monitoring: false,
    };
    let empty = Config::empty();
    assert!(!empty.ipv6_enabled);
    let mut native = Native::open(options.clone())?;
    let mut imported = empty.clone();
    imported.interfaces = serde_json::from_value(json!([{
        "name":"nic0","kind":"ethernet","role":"unassigned","mtu":1500,"up":true,
        "addresses":["192.0.2.1/24"]
    }]))?;
    let plan = Network::parse(&imported.operational_value()?)?;
    let originals = session(namespace.clone(), move |rt, handle| {
        rt.block_on(networking::capture_ethernet(handle, &plan, &plan))
    })?;
    let receipt: adoption::Receipt = serde_json::from_value(json!({
        "scope":native.identity,"config":imported,"originals":originals,
        "leases":{},"routes":[],"ownership_before":native.ownership()?,"complete":false
    }))?;
    let managed = receipt.managed_originals()?;
    assert!(managed["nic0"].addresses.len() < receipt.originals["nic0"].addresses.len());
    native.repair(&empty)?;
    native.observe(&empty)?;
    assert_eq!(native.runtime(&empty)?["ipv6"]["drift"], false);
    session(namespace.clone(), |rt, handle| {
        ipv6::verify(false)?;
        rt.block_on(async {
            handle
                .link()
                .add(rtnetlink::LinkDummy::new(&"future0").build())
                .execute()
                .await?;
            for link in networking::links(handle).await? {
                let addresses = networking::addresses(handle, link.header.index).await?;
                assert!(
                    addresses
                        .iter()
                        .all(|a| a.header.family != netlink_packet_route::AddressFamily::Inet6)
                );
                if networking::name(&link) == "nic0" {
                    assert!(
                        addresses
                            .iter()
                            .any(|a| networking::address_string(a).unwrap().as_deref()
                                == Some("192.0.2.1/24"))
                    );
                }
            }
            Ok(())
        })
    })?;
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&empty)?;
    native.observe(&empty)?;
    let mut enabled = empty.clone();
    enabled.ipv6_enabled = true;
    native.apply(&empty, &enabled)?;
    session(namespace, |rt, handle| {
        ipv6::verify(true)?;
        rt.block_on(async {
            let nic = handle
                .link()
                .get()
                .match_name("nic0".into())
                .execute()
                .try_next()
                .await?
                .context("fixture NIC missing")?;
            assert!(
                networking::addresses(handle, nic.header.index)
                    .await?
                    .iter()
                    .any(|a| networking::address_string(a).unwrap().as_deref()
                        == Some("2001:db8::1/64"))
            );
            Ok(())
        })
    })?;
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_vlan_adoption_recovery_restores_committed_dhcp_before_verification() -> Result<()> {
    use sha2::Digest;

    if !isolate_host_fixture(
        "linux::host_integration::native_vlan_adoption_recovery_restores_committed_dhcp_before_verification",
    )? {
        return Ok(());
    }
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add(rtnetlink::LinkVeth::new(&"wan0", &"lan0").build())
                .execute()
                .await?;
            for link in networking::links(handle).await? {
                if matches!(networking::name(&link).as_str(), "wan0" | "lan0") {
                    handle
                        .link()
                        .set(
                            rtnetlink::LinkUnspec::new_with_index(link.header.index)
                                .up()
                                .build(),
                        )
                        .execute()
                        .await?;
                }
            }
            Ok(())
        })
    })?;
    let directory = StateDirectory(std::env::current_dir()?.join(format!(
        ".native-vlan-dhcp-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    )));
    fs::DirBuilder::new().mode(0o700).create(&directory.0)?;
    let options = NativeOptions {
        namespace: String::new(),
        keys: directory.0.join("keys"),
        services_state: directory.0.join("services"),
        adopted_parents: vec![],
        allow_host_tunables: false,
        allow_host_services: false,
        gateway_monitoring: false,
    };
    let before: Config = serde_json::from_value(json!({
        "interfaces":[
            {"name":"wan0","kind":"ethernet","role":"wan","mtu":1500,"up":true,"addresses":[]},
            {"name":"lan0","kind":"ethernet","role":"lan","mtu":1500,"up":true,"addresses":["192.168.0.1/24"]}
        ],
        "dhcp_clients":{"wan0":{}}
    }))?;
    before.validate()?;
    let mut native = Native::open(options.clone())?;
    native.repair(&Config::empty())?;
    // Keep real DHCP/kernel recovery, without depending on a host resolved D-Bus service.
    native.dhcp = dhcp_client::Manager::new(namespace.clone(), native.state.clone(), false);
    let lease: dhcp_client::Lease = serde_json::from_value(json!({
        "client":{}, "address":"192.0.2.10/24", "server":"192.0.2.1",
        "acquired_at":dhcp_client::now()?, "lifetime":3600,
        "renewal":1800, "rebinding":3150,
        "routes":[
            {"destination":"192.0.2.0/24","interface":"wan0","table":254,"metric":0},
            {"destination":"0.0.0.0/0","gateway":"192.0.2.1","interface":"wan0","table":254,"metric":100}
        ], "dns":[], "domain":"", "mtu":null
    }))?;
    let lease_path = native.state.join("dhcp-wan0.json");
    write_json(&lease_path, &lease)?;
    let saved_lease = fs::read(&lease_path)?;
    let mut links_only = before.clone();
    links_only.dhcp_clients.clear();
    native.apply(&Config::empty(), &links_only)?;
    native.dhcp.configure(&before.operational_value()?)?;
    let mut ownership = native.ownership()?;
    ownership.committed_config = Some(before.operational_value()?);
    native.save_ownership(&ownership)?;
    native.verify(&before.operational_value()?)?;
    let request = netcontrol_core::AdoptVlanRequest {
        name: "vlan50".into(),
        parent: "lan0".into(),
        id: 50,
    };
    let wanted = request.clone();
    let snapshot = session(namespace.clone(), move |rt, handle| {
        rt.block_on(async {
            let parent = networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == wanted.parent)
                .context("LAN parent missing")?
                .header
                .index;
            handle
                .link()
                .add(rtnetlink::LinkVlan::new(&wanted.name.clone(), parent, wanted.id).build())
                .execute()
                .await?;
            let vlan = networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == wanted.name)
                .context("VLAN missing")?
                .header
                .index;
            handle
                .link()
                .set(rtnetlink::LinkUnspec::new_with_index(vlan).up().build())
                .execute()
                .await?;
            handle
                .address()
                .add(vlan, "10.4.50.1".parse()?, 24)
                .execute()
                .await?;
            networking::capture_vlan_snapshot(handle, &wanted).await
        })
    })?;
    let mut after = before.clone();
    after.interfaces.push(serde_json::from_value(json!({
        "name":"vlan50","kind":"vlan","role":"unassigned","mtu":1500,"up":true,
        "addresses":["10.4.50.1/24"],"vlan":{"parent":"lan0","id":50}
    }))?);
    after.normalize();
    after.validate()?;
    let previous = native.ownership()?;
    let source = directory.0.join("vlan50.network");
    fs::write(&source, "[Network]\nIPv6AcceptRA=no\n")?;
    let source_digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        &json!({"network":{"ipv6acceptra":"no"}}),
    )?));
    let imported = netcontrol_core::VlanAdoption {
        config: after.clone(),
        receipt: json!({"request":request,"capture":{
            "scope":native.identity,"config":after,
            "originals":{"vlan50":snapshot},"leases":{},"routes":[],
            "ownership_before":previous,"complete":false,
            "networkd_source":{"path":source,"sha256":source_digest}
        }}),
    };
    drop(native);
    for already_owned in [false, true] {
        let mut native = Native::open(options.clone())?;
        native.dhcp = dhcp_client::Manager::new(namespace.clone(), native.state.clone(), false);
        assert!(native.dhcp.state.lock().unwrap().leases.is_empty());
        let cold_error = native.verify(&before.operational_value()?).unwrap_err();
        assert!(
            format!("{cold_error:#}").contains("interface wan0 address drift"),
            "{cold_error:#}"
        );
        if already_owned {
            let mut ownership = previous.clone();
            ownership.managed_interfaces.insert("vlan50".into());
            ownership
                .vlan_originals
                .insert("vlan50".into(), snapshot.clone());
            ownership.committed_config = Some(imported.config.operational_value()?);
            native.save_ownership(&ownership)?;
        }
        let ownership_before = fs::read(native.state.join("ownership.json"))?;
        let error = native.finish_vlan_adoption(&before, &imported).unwrap_err();
        // The isolated fixture deliberately has no networkd/resolved bus. Reach that
        // boundary, rather than rejecting the WAN's restored lease as address drift.
        assert!(
            format!("{error:#}").contains("VLAN networkd recovery failed"),
            "{error:#}"
        );
        assert_eq!(
            native.dhcp.state.lock().unwrap().leases["wan0"].address,
            lease.address
        );
        native.verify(&before.operational_value()?)?;
        assert_eq!(fs::read(&lease_path)?, saved_lease);
        assert_eq!(
            fs::read(native.state.join("ownership.json"))?,
            ownership_before
        );
        let extra = session(namespace.clone(), |rt, handle| {
            rt.block_on(async {
                let wan = networking::links(handle)
                    .await?
                    .into_iter()
                    .find(|link| networking::name(link) == "wan0")
                    .context("WAN missing")?
                    .header
                    .index;
                let mut add = handle.address().add(wan, "198.51.100.10".parse()?, 24);
                let message = add.message_mut().clone();
                add.execute().await?;
                Ok(message)
            })
        })?;
        let error = native.finish_vlan_adoption(&before, &imported).unwrap_err();
        assert!(
            format!("{error:#}").contains("interface wan0 address drift"),
            "{error:#}"
        );
        session(namespace.clone(), move |rt, handle| {
            rt.block_on(handle.address().del(extra).execute())?;
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, Linux namespace/net_admin privileges and nft modules"]
fn native_current_namespace_ethernet_apply_rollback_recovery_and_reboot() -> Result<()> {
    if !isolate_host_fixture(
        "linux::host_integration::native_current_namespace_ethernet_apply_rollback_recovery_and_reboot",
    )? {
        return Ok(());
    }
    let namespace = Arc::new(File::open("/proc/thread-self/ns/net")?);
    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add(rtnetlink::LinkVeth::new(&"nic0", &"peer0").build())
                .execute()
                .await?;
            handle
                .link()
                .add(rtnetlink::LinkVeth::new(&"cold0", &"coldpeer0").build())
                .execute()
                .await?;
            handle
                .link()
                .add(rtnetlink::LinkDummy::new(&"unrelated0").build())
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
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(nic)
                        .mtu(1450)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            for (ip, len) in [("192.0.2.8", 24), ("2001:db8:1::8", 64)] {
                let mut request = handle.address().add(nic, ip.parse()?, len);
                request
                    .message_mut()
                    .attributes
                    .push(AddressAttribute::Flags(AddressFlags::Nodad));
                request.execute().await?;
            }
            let unrelated = index("unrelated0")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(unrelated)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            handle
                .route()
                .add(
                    rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                        .destination_prefix("10.0.0.0".parse()?, 8)
                        .table_id(254)
                        .priority(7)
                        .output_interface(unrelated)
                        .protocol(RouteProtocol::Boot)
                        .scope(RouteScope::Link)
                        .build(),
                )
                .execute()
                .await?;
            Ok(())
        })
    })?;
    change_alias(namespace.clone(), "nic0", "Original physical label")?;
    change_alias(namespace.clone(), "peer0", "Original peer label")?;
    change_alias(namespace.clone(), "unrelated0", "Unmanaged label")?;
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
    assert!(native.host_namespace.is_some());
    assert!(native._host_lock.is_some());
    let competing_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/run/netcontrol-host-tunables.lock")?;
    assert_eq!(
        unsafe { libc::flock(competing_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EWOULDBLOCK)
    );
    let scope = native.scope()?;
    assert!(scope.starts_with("linux:host:"));
    let mut empty = Config::empty();
    empty.ipv6_enabled = true;
    let unchanged_ownership = serde_json::to_value(native.ownership()?)?;
    let unchanged_firewall = session(namespace.clone(), |_, _| netfilter::fingerprint())?;
    let first = native.statistics(&empty, "/api/v1/statistics/performance", "")?;
    assert_eq!(first["schema"], "netcontrol-performance/v1");
    assert_eq!(first["sample"]["scope"], "host");
    assert_eq!(first["sample"]["backend_scope"], scope);
    assert_eq!(first["tuning_available"], true);
    assert_eq!(first["recommendations"], json!([]));
    assert_eq!(first["sections"]["cpu"]["status"], "available");
    let first_cpus = first["sections"]["cpu"]["data"]["rows"]
        .as_array()
        .context("live CPU rows missing")?;
    assert!(!first_cpus.is_empty());
    assert!(
        first_cpus
            .iter()
            .all(|cpu| cpu["delta"].is_null() && cpu["busy_percent"].is_null())
    );
    std::thread::sleep(std::time::Duration::from_millis(1050));
    let second = native.statistics(&empty, "/api/v1/statistics/performance", "")?;
    assert_eq!(second["sample"]["identity_stable"], true);
    assert_eq!(second["sections"]["cpu"]["data"]["baseline"], "ready");
    let second_cpus = second["sections"]["cpu"]["data"]["rows"]
        .as_array()
        .context("second live CPU rows missing")?;
    assert!(second_cpus.iter().any(|cpu| {
        cpu["busy_percent"]
            .as_f64()
            .is_some_and(|busy| (0.0..=100.0).contains(&busy))
            && cpu["delta"]["total_ticks"].as_str().is_some()
    }));
    assert!(matches!(
        second["sample"]["status"].as_str(),
        Some("available" | "partial")
    ));
    assert!(
        second["sample"]["sample_interval_seconds"]
            .as_f64()
            .is_some_and(|interval| interval >= 1.0)
    );
    assert_eq!(
        serde_json::to_value(native.ownership()?)?,
        unchanged_ownership
    );
    assert_eq!(
        session(namespace.clone(), |_, _| netfilter::fingerprint())?,
        unchanged_firewall
    );
    for tuning in [
        Kernel {
            rps: [("nic0/rx-0".into(), "1".into())].into(),
            ..Default::default()
        },
        Kernel {
            rfs: Some(netcontrol_core::RfsConfig {
                sock_flow_entries: 0,
                queues: [("nic0/rx-0".into(), 0)].into(),
            }),
            ..Default::default()
        },
        Kernel {
            offloads: [("nic0".into(), [("rx-checksum".into(), true)].into())].into(),
            ..Default::default()
        },
    ] {
        native.allow_tuning(&tuning)?;
        assert!(native.preflight_kernel(&tuning).is_err());
    }
    let baseline = row(&mut native, "nic0")?;
    assert_eq!(baseline["kind"], "ethernet");
    assert_eq!(baseline["ownership"], "unmanaged");
    let cold_baseline = row(&mut native, "cold0")?;
    assert_eq!(cold_baseline["up"], false);
    let unrelated = row(&mut native, "unrelated0")?;
    let foreign_count = foreign_routes(namespace.clone())?;
    native.repair(&empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);
    let baseline_firewall = session(namespace.clone(), |_, _| netfilter::fingerprint())?;
    assert_ne!(baseline_firewall, netfilter::empty_fingerprint());

    let mut value = serde_json::to_value(&empty)?;
    value["interfaces"] = json!([
        {"name":"nic0","kind":"ethernet","role":"wan","mtu":1400,"up":true,
            "addresses":["198.51.100.8/24","2001:db8:2::8/64"],"dhcp_relay":{"enabled":false,"servers":[]}},
        {"name":"nic100","kind":"vlan","role":"lan","mtu":1300,"up":true,
            "addresses":["198.18.1.1/24"],"vlan":{"parent":"nic0","id":100},"dhcp_relay":{"enabled":false,"servers":[]}}
    ]);
    value["routes"] = json!([{"enabled":true,"destination":"0.0.0.0/0","gateway":"198.51.100.1","interface":"nic0","table":254,"metric":200}]);
    let desired: Config = serde_json::from_value(value.clone())?;

    let mut collision = serde_json::to_value(&empty)?;
    collision["interfaces"] = json!([{"name":"unrelated0","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":[]}]);
    assert!(
        native
            .apply(&empty, &serde_json::from_value(collision)?)
            .is_err()
    );
    let mut conflict = value.clone();
    conflict["routes"] = json!([{"enabled":true,"destination":"10.0.0.0/8","interface":"nic0","table":254,"metric":7}]);
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
    failed["interfaces"].as_array_mut().unwrap().push(json!({
        "name":"cold0","kind":"ethernet","role":"lan","mtu":1500,"up":true,
        "addresses":["203.0.113.1/24"]
    }));
    failed["ntp"] = json!({"enabled":true,"servers":["192.0.2.123"]});
    assert!(
        native
            .apply(&empty, &serde_json::from_value(failed)?)
            .is_err()
    );
    assert_eq!(row(&mut native, "nic0")?, baseline);
    assert_eq!(row(&mut native, "cold0")?, cold_baseline);
    assert_eq!(
        link_alias(namespace.clone(), "nic0")?,
        "Original physical label"
    );
    assert!(!native.state.join("intent.json").exists());
    assert_eq!(
        session(namespace.clone(), |_, _| netfilter::fingerprint())?,
        baseline_firewall
    );

    native.apply(&empty, &desired)?;
    native.observe(&desired)?;
    let unchanged = fs::read(native.state.join("ownership.json"))?;
    for offloads in [true, false] {
        let mut rejected = desired.clone();
        if offloads {
            rejected
                .kernel
                .offloads
                .insert("nic0".into(), [("rx-checksum".into(), true)].into());
        } else {
            rejected.kernel.rfs = Some(netcontrol_core::RfsConfig {
                sock_flow_entries: 0,
                queues: [("nic0/rx-0".into(), 0)].into(),
            });
        }
        rejected.validate()?;
        assert!(native.apply(&desired, &rejected).is_err());
        native.apply(&rejected, &desired)?;
        native.observe(&desired)?;
        assert_eq!(fs::read(native.state.join("ownership.json"))?, unchanged);
        assert!(!native.state.join("intent.json").exists());
    }
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "WAN");
    assert_eq!(link_alias(namespace.clone(), "nic100")?, "");
    assert_eq!(
        link_alias(namespace.clone(), "peer0")?,
        "Original peer label"
    );
    assert_eq!(
        link_alias(namespace.clone(), "unrelated0")?,
        "Unmanaged label"
    );
    let managed = row(&mut native, "nic0")?;
    assert_eq!(managed["ownership"], "managed");
    assert_eq!(managed["index"], baseline["index"]);
    assert_eq!(managed["mac"], baseline["mac"]);
    assert_eq!(native.ownership()?.ethernet_originals["nic0"].mtu, 1450);
    let ownership_path = native.state.join("ownership.json");
    let unchanged_ownership = fs::read(&ownership_path)?;
    let mut mqtt_desired = desired.clone();
    mqtt_desired.mqtt.enabled = true;
    mqtt_desired.mqtt.endpoint = "mqtts://broker.example.test".into();
    mqtt_desired.mqtt.source_interface = "nic0".into();
    mqtt_desired.validate()?;
    native.apply(&desired, &mqtt_desired)?;
    native.observe(&mqtt_desired)?;
    assert_eq!(fs::read(&ownership_path)?, unchanged_ownership);
    assert!(!native.state.join("intent.json").exists());
    let mut software_desired = desired.clone();
    software_desired.software = serde_json::from_value(json!({
        "version":"2026.11.04.1","repository":"example/netcontrol",
        "latest_version":"2026.11.04.2","update_available":true,
        "last_checked_at":"2026-11-04T00:00:00Z","error":null
    }))?;
    software_desired.validate()?;
    native.apply(&desired, &software_desired)?;
    native.observe(&software_desired)?;
    assert_eq!(fs::read(&ownership_path)?, unchanged_ownership);
    assert!(!native.state.join("intent.json").exists());
    let mut recorded = native.ownership()?;
    recorded.committed_config = Some(serde_json::to_value(&mqtt_desired)?);
    native.save_ownership(&recorded)?;
    assert_eq!(
        native.ownership()?.committed_config,
        Some(desired.operational_value()?)
    );
    native.repair(&desired)?;
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
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(index)
                        .mtu(1390)
                        .build(),
                )
                .execute()
                .await?;
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
                .get(crate::linux::networking::route_query(
                    rtnetlink::IpVersion::V4,
                ))
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
            let nic = links
                .iter()
                .find(|link| networking::name(link) == "nic0")
                .context("fixture NIC missing")?
                .header
                .index;
            handle
                .link()
                .set(rtnetlink::LinkUnspec::new_with_index(nic).down().build())
                .execute()
                .await?;
            Ok::<(), anyhow::Error>(())
        })?;
        let fingerprint = netfilter::fingerprint()?;
        firewall::remove_owned(&fingerprint)
    })?;
    // Restore the committed candidate through the explicit reboot path, not a drift bypass.
    let mut ownership = native.ownership()?;
    ownership.boot = "synthetic-previous-boot".into();
    let mut committed = serde_json::to_value(&software_desired)?;
    committed.as_object_mut().unwrap().remove("mqtt");
    ownership.committed_config = Some(committed);
    native.save_ownership(&ownership)?;
    drop(native);
    let mut native = Native::open(options.clone())?;
    let mut conflicting = desired.clone();
    conflicting.interfaces[0].mtu = 1390;
    assert!(
        native
            .repair(&conflicting)
            .unwrap_err()
            .to_string()
            .contains("does not match durable native ownership")
    );
    assert_eq!(row(&mut native, "nic0")?["up"], false);
    native.repair(&desired)?;
    native.observe(&desired)?;
    assert_eq!(native.scope()?, scope);
    assert_eq!(row(&mut native, "nic0")?["up"], true);
    assert_eq!(row(&mut native, "cold0")?, cold_baseline);

    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == "nic0")
                .context("fixture NIC missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .down()
                        .build(),
                )
                .execute()
                .await?;
            Ok::<(), anyhow::Error>(())
        })
    })?;
    let valid_ownership = native.ownership()?;
    let mut replaced = valid_ownership.clone();
    let recorded = replaced
        .ethernet_originals
        .get_mut("nic0")
        .context("fixture Ethernet identity missing")?;
    recorded.mac = if recorded.mac == "02:00:00:00:00:01" {
        "02:00:00:00:00:02"
    } else {
        "02:00:00:00:00:01"
    }
    .into();
    native.save_ownership(&replaced)?;
    assert!(
        native
            .repair(&desired)
            .unwrap_err()
            .to_string()
            .contains("changed identity")
    );
    assert_eq!(row(&mut native, "nic0")?["up"], false);
    native.save_ownership(&valid_ownership)?;
    native.repair(&desired)?;
    native.observe(&desired)?;
    assert_eq!(row(&mut native, "nic0")?["up"], true);

    session(namespace.clone(), |rt, handle| {
        rt.block_on(async {
            let link = networking::links(handle)
                .await?
                .into_iter()
                .find(|link| networking::name(link) == "nic0")
                .context("fixture NIC missing")?;
            handle
                .link()
                .set(
                    rtnetlink::LinkUnspec::new_with_index(link.header.index)
                        .down()
                        .build(),
                )
                .execute()
                .await?;
            Ok::<(), anyhow::Error>(())
        })
    })?;
    let before = desired.operational_value()?;
    let previous = native.ownership()?;
    let mut intent = Intent {
        scope: native.identity.clone(),
        before: before.clone(),
        after: before.clone(),
        kernel_before: native.capture_kernel(&before, &before)?,
        ownership_before: previous.clone(),
        ethernet_before: BTreeMap::new(),
        ethernet_originals: previous.ethernet_originals.clone(),
        ipv6_before: native.capture_ipv6(&before)?,
    };
    write_json(&native.state.join("intent.json"), &intent)?;
    let error = native.recover().unwrap_err();
    assert!(format!("{error:#}").contains("no durable operation snapshot"));
    assert_eq!(row(&mut native, "nic0")?["up"], false);
    assert!(native.state.join("intent.json").exists());
    intent.ethernet_before = native.capture_ethernet(&before, &before)?;
    write_json(&native.state.join("intent.json"), &intent)?;
    native.recover()?;
    assert!(!native.state.join("intent.json").exists());
    native.repair(&desired)?;
    native.observe(&desired)?;
    assert_eq!(row(&mut native, "nic0")?["up"], true);

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
            Some(desired.operational_value()?)
        );
    }

    let ownership_before = fs::read(native.state.join("ownership.json"))?;
    let mut described = desired.clone();
    described.interfaces[0].metadata.display_name = "Office LAN".into();
    let runtime_before = native.services.status();
    native.apply(&desired, &described)?;
    assert_eq!(native.observe(&described)?, described);
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "Office LAN [WAN]");
    assert_eq!(native.services.status(), runtime_before);
    assert_eq!(
        fs::read(native.state.join("ownership.json"))?,
        ownership_before
    );
    assert!(!native.state.join("intent.json").exists());
    assert!(!native.state.join("interface-alias-intent.json").exists());
    let alias_state_path = native.state.join("interface-aliases.json");
    let alias_state_before = fs::read(&alias_state_path)?;
    let mut annotated = described.clone();
    annotated.interfaces[0].metadata.description = "No kernel label change".into();
    native.apply(&described, &annotated)?;
    assert_eq!(fs::read(&alias_state_path)?, alias_state_before);
    assert_eq!(
        fs::read(native.state.join("ownership.json"))?,
        ownership_before
    );

    let mut lan = described.clone();
    lan.interfaces[0].role = "lan".into();
    native.apply(&described, &lan)?;
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "Office LAN [LAN]");
    native.apply(&lan, &described)?;
    let mut unicode = described.clone();
    unicode.interfaces[0].metadata.display_name = "\u{1f310}".repeat(128);
    unicode.validate()?;
    native.apply(&described, &unicode)?;
    let long_alias = link_alias(namespace.clone(), "nic0")?;
    assert!(long_alias.len() <= 255);
    assert!(long_alias.ends_with(" [WAN]"));
    assert_eq!(native.observe(&unicode)?, unicode);
    native.apply(&unicode, &described)?;

    // Force a kernel label failure after nic0 changes; every label must roll back.
    let mut rejected = described.clone();
    rejected.interfaces[0].metadata.display_name = "Partially applied".into();
    let mut peer = rejected.interfaces[0].clone();
    peer.name = "peer0".into();
    peer.addresses.clear();
    peer.metadata.display_name = "Rejected\0suffix".into();
    rejected.interfaces.push(peer);
    assert!(native.reconcile_interface_aliases(&rejected).is_err());
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "Office LAN [WAN]");
    assert_eq!(
        link_alias(namespace.clone(), "peer0")?,
        "Original peer label"
    );
    assert_eq!(fs::read(&alias_state_path)?, alias_state_before);
    assert!(!native.state.join("interface-alias-intent.json").exists());

    let saved: Value = read_json(&alias_state_path)?;
    let link = fixture_link(namespace.clone(), "nic0")?;
    write_json(
        &native.state.join("interface-alias-intent.json"),
        &json!({
            "before": saved,
            "links": {"nic0": {
                "interface": networking::parent(&link),
                "boot": native.boot,
                "alias": "Office LAN [WAN]"
            }}
        }),
    )?;
    change_alias(namespace.clone(), "nic0", "Interrupted label update")?;
    native.recover()?;
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "Office LAN [WAN]");
    assert_eq!(fs::read(&alias_state_path)?, alias_state_before);
    assert!(!native.state.join("interface-alias-intent.json").exists());

    change_alias(namespace.clone(), "nic0", "")?;
    native.observe(&described)?;
    native.repair(&described)?;
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "Office LAN [WAN]");
    native.apply(&described, &desired)?;
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "WAN");

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
    assert_eq!(
        link_alias(namespace.clone(), "nic0")?,
        "Original physical label"
    );
    native.apply(&empty, &desired)?;

    let mut down = value.clone();
    down["interfaces"] = json!([{"name":"nic0","kind":"ethernet","role":"wan","mtu":1400,"up":false,"addresses":[]}]);
    down["routes"] = json!([]);
    let down: Config = serde_json::from_value(down)?;
    native.apply(&desired, &down)?;
    native.observe(&down)?;
    assert_eq!(link_alias(namespace.clone(), "nic0")?, "WAN");
    native.apply(&down, &empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);
    assert_eq!(
        link_alias(namespace.clone(), "nic0")?,
        "Original physical label"
    );

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
            ipv6_before: native.capture_ipv6(&before)?,
        },
    )?;
    native.network_apply(&before, &value, Kernel::default(), &mut applying)?;
    drop(native);
    let mut native = Native::open(options)?;
    assert!(!native.state.join("intent.json").exists());
    native.observe(&empty)?;
    assert_eq!(row(&mut native, "nic0")?, baseline);
    assert_eq!(row(&mut native, "unrelated0")?, unrelated);
    assert_eq!(
        link_alias(namespace.clone(), "nic0")?,
        "Original physical label"
    );
    assert_eq!(
        link_alias(namespace.clone(), "peer0")?,
        "Original peer label"
    );
    assert_eq!(
        link_alias(namespace.clone(), "unrelated0")?,
        "Unmanaged label"
    );
    assert_eq!(foreign_routes(namespace)?, foreign_count);
    Ok(())
}
