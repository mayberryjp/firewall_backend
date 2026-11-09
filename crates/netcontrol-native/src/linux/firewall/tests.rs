use crate::linux::{Native, integration::Fixture, session};
use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use netcontrol_core::{Backend, Config, DenyLogQuery};
use serde_json::{Value, json};
use std::{
    fs::File,
    net::UdpSocket,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::Duration,
};

fn send_ipv4_packet(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    payload: &[u8],
) -> Result<()> {
    let index = unsafe { libc::if_nametoindex(c"peer0".as_ptr()) };
    ensure!(index != 0, "missing packet injection interface");
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(0x0800u16.to_be()),
        )
    };
    ensure!(
        fd >= 0,
        "packet socket: {}",
        std::io::Error::last_os_error()
    );
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut frame = vec![0; 34];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&u16::try_from(20 + payload.len())?.to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&destination);
    let mut checksum: u32 = ip
        .chunks_exact(2)
        .map(|chunk| u32::from(u16::from_be_bytes([chunk[0], chunk[1]])))
        .sum();
    while checksum > 0xffff {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    ip[10..12].copy_from_slice(&(!u16::try_from(checksum)?).to_be_bytes());
    frame.extend(payload);
    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: 0x0800u16.to_be(),
        sll_ifindex: i32::try_from(index)?,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
    };
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    ensure!(
        sent == isize::try_from(frame.len())?,
        "send test packet: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn packets(snapshot: &Value, id: &str) -> Result<u128> {
    snapshot["rules"]
        .as_array()
        .context("missing counter rows")?
        .iter()
        .find(|row| row["id"] == id)
        .context("missing counter")?["packets"]
        .as_str()
        .context("missing packet count")?
        .parse()
        .map_err(Into::into)
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1, isolated Linux namespaces and NET_ADMIN/SYS_ADMIN"]
fn native_spoof_block_enforces_lan_input_forward_fallthrough_restart_and_rollback() -> Result<()> {
    let router = Fixture::new()?;
    let peer = Fixture::new()?;
    let router_ns = Arc::new(File::open(router.options().namespace)?);
    let peer_ns = Arc::new(File::open(peer.options().namespace)?);
    let target = peer_ns.clone();
    session(router_ns.clone(), move |rt, handle| {
        rt.block_on(async {
            handle
                .link()
                .add()
                .veth("lan0".into(), "peer0".into())
                .execute()
                .await?;
            let link = handle
                .link()
                .get()
                .match_name("peer0".into())
                .execute()
                .try_next()
                .await?
                .context("missing peer link")?;
            handle
                .link()
                .set(link.header.index)
                .setns_by_fd(target.as_raw_fd())
                .execute()
                .await?;
            Ok(())
        })
    })?;
    session(peer_ns.clone(), |rt, handle| {
        rt.block_on(async {
            let link = handle
                .link()
                .get()
                .match_name("peer0".into())
                .execute()
                .try_next()
                .await?
                .context("missing peer link")?;
            for address in [
                "192.0.2.2",
                "203.0.113.2",
                "2001:db8::2",
                "2001:db8:ffff::2",
            ] {
                let address: std::net::IpAddr = address.parse()?;
                handle
                    .address()
                    .add(
                        link.header.index,
                        address,
                        if address.is_ipv4() { 24 } else { 64 },
                    )
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
    let options = router.options();
    let mut native = Native::open(options.clone())?;
    let empty = Config::empty();
    native.repair(&empty)?;
    let enabled: Config = serde_json::from_value(json!({
        "ipv6_enabled":true,
        "interfaces":[
            {"name":"lan0","kind":"ethernet","role":"lan","up":true,"mtu":1500,
             "addresses":["192.0.2.1/24","2001:db8::1/64"]},
            {"name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,
             "addresses":["198.51.100.1/24","2001:db8:1::1/64"]}
        ],
        "routes":[
            {"enabled":true,"destination":"203.0.113.2/32","interface":"lan0","gateway":"","table":254,"metric":100},
            {"enabled":true,"destination":"2001:db8:ffff::2/128","interface":"lan0","gateway":"","table":254,"metric":100}
        ],
        "firewall":{"policy":"drop","allow_all_icmp":true,
            "policies":{"hosts":[],"interfaces":[{"interface":"lan0","rules":[{"action":"accept"}]}]},
            "input":{"policy":"drop","interfaces":[{"interface":"lan0","rules":[
                {"protocol":"udp","destination_ports":[9000],"action":"accept"},
                {"protocol":"icmpv6","action":"accept"}
            ]}]}
        }
    }))?;
    enabled.validate()?;
    native.apply(&empty, &enabled)?;
    session(router_ns.clone(), |_, _| {
        for (key, value) in [
            ("ipv4/ip_forward", "1"),
            ("ipv6/conf/all/forwarding", "1"),
            ("ipv4/conf/all/rp_filter", "0"),
            ("ipv4/conf/lan0/rp_filter", "0"),
        ] {
            std::fs::write(format!("/proc/sys/net/{key}"), value)?;
        }
        Ok(())
    })?;
    let listeners = session(router_ns.clone(), |_, _| {
        let v4 = UdpSocket::bind("192.0.2.1:9000")?;
        let v6 = UdpSocket::bind("[2001:db8::1]:9000")?;
        for socket in [&v4, &v6] {
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        }
        Ok((v4, v6))
    })?;
    // Wait for ordinary kernel DAD before testing globally addressed UDP.
    std::thread::sleep(Duration::from_secs(2));
    let sources = [
        "192.0.2.2:0",
        "203.0.113.2:0",
        "[2001:db8::2]:0",
        "[2001:db8:ffff::2]:0",
    ];
    let sockets = Arc::new(session(peer_ns.clone(), move |_, _| {
        sources
            .into_iter()
            .map(UdpSocket::bind)
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(Into::into)
    })?);
    let send = || -> Result<()> {
        let sockets = sockets.clone();
        session(peer_ns.clone(), move |_, _| {
            for (index, socket) in sockets.iter().enumerate() {
                let destinations = if index < 2 {
                    ["192.0.2.1:9000", "192.0.2.1:9001", "198.51.100.2:9000"]
                } else {
                    [
                        "[2001:db8::1]:9000",
                        "[2001:db8::1]:9001",
                        "[2001:db8:1::2]:9000",
                    ]
                };
                for destination in destinations {
                    socket.send_to(b"source-guard", destination)?;
                }
            }
            Ok(())
        })
    };
    send()?;
    let path = "/api/v1/statistics/firewall";
    let snapshot = native.statistics(&enabled, path, "")?;
    for socket in [&listeners.0, &listeners.1] {
        let mut bytes = [0; 32];
        let address = socket.local_addr()?;
        let (length, source) = socket
            .recv_from(&mut bytes)
            .with_context(|| format!("receive valid LAN UDP on {address}: {snapshot}"))?;
        assert_eq!(&bytes[..length], b"source-guard");
        assert!(matches!(
            source.ip().to_string().as_str(),
            "192.0.2.2" | "2001:db8::2"
        ));
        socket.send_to(b"reply", source)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        assert!(matches!(
            socket.recv(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    }
    let snapshot = native.statistics(&enabled, path, "")?;
    assert!(packets(&snapshot, "input_spoof_block:/firewall/spoof_block")? >= 4);
    assert!(packets(&snapshot, "forward_spoof_block:/firewall/spoof_block")? >= 2);
    assert!(packets(&snapshot, "input:/firewall/input/policy")? >= 2);
    assert!(packets(&snapshot, "forward:/firewall/policies/interfaces/0/rules/0")? >= 2);
    session(peer_ns.clone(), |_, _| {
        send_ipv4_packet([0; 4], [255; 4], 17, &[0, 68, 0, 67, 0, 8, 0, 0])?;
        send_ipv4_packet([0; 4], [255; 4], 17, &[0x23, 0x28, 0x23, 0x28, 0, 8, 0, 0])?;
        send_ipv4_packet(
            [203, 0, 113, 2],
            [192, 0, 2, 1],
            1,
            &[8, 0, 0xe5, 0xca, 0x12, 0x34, 0, 1],
        )?;
        Ok(())
    })?;
    let snapshot = native.statistics(&enabled, path, "")?;
    assert!(
        packets(
            &snapshot,
            "input_spoof_block:generated/spoof_block/lan0/bootstrap"
        )? >= 1
    );
    assert!(
        packets(&snapshot, "input_spoof_block:/firewall/spoof_block")? >= 6,
        "{snapshot}"
    );
    assert_eq!(packets(&snapshot, "input:/firewall/allow_all_icmp")?, 0);
    let query =
        DenyLogQuery::parse("chain=input&include_broadcast=true&include_tcp_closures=true")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let history = native.deny_log(&query)?;
        if history["records"]
            .as_array()
            .context("missing deny history")?
            .iter()
            .any(|record| {
                record["reason"] == "spoof_block"
                    && record["source"] == "203.0.113.2"
                    && record["protocol"] == 1
                    && record["compiled_rule_index"].is_null()
            })
        {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "spoof block NFLOG record missing: {history}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    native.verify(&enabled.operational_value()?)?;
    drop(native);
    let mut native = Native::open(options)?;
    native.repair(&enabled)?;
    native.verify(&enabled.operational_value()?)?;
    send()?;
    let snapshot = native.statistics(&enabled, path, "")?;
    assert!(packets(&snapshot, "input_spoof_block:/firewall/spoof_block")? >= 4);
    let mut disabled = enabled.clone();
    disabled.firewall.spoof_block = false;
    native.apply(&enabled, &disabled)?;
    send()?;
    for socket in [&listeners.0, &listeners.1] {
        for _ in 0..3 {
            let (_, source) = socket.recv_from(&mut [0; 32])?;
            socket.send_to(b"reply", source)?;
        }
    }
    send()?;
    let snapshot = native.statistics(&disabled, path, "")?;
    assert!(
        !snapshot["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["config_path"] == "/firewall/spoof_block")
    );
    assert!(packets(&snapshot, "forward:/firewall/policies/interfaces/0/rules/0")? >= 4);
    assert!(packets(&snapshot, "input:generated/input/established_related")? >= 4);
    native.apply(&disabled, &enabled)?;
    send()?;
    let snapshot = native.statistics(&enabled, path, "")?;
    assert!(packets(&snapshot, "input_spoof_block:/firewall/spoof_block")? >= 4);
    assert!(packets(&snapshot, "forward_spoof_block:/firewall/spoof_block")? >= 2);
    assert!(packets(&snapshot, "input:generated/input/established_related")? >= 2);
    native.verify(&enabled.operational_value()?)?;
    ensure!(
        enabled.firewall.spoof_block,
        "omitted setting was not enabled"
    );
    Ok(())
}
