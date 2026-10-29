//! Explicit privileged Linux checks; all mutations occur on fresh namespace threads.
#![cfg(all(test, target_os = "linux"))]
use super::*;
use std::{
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

fn isolated(test: impl FnOnce() -> Result<()> + Send + 'static) {
    assert_eq!(
        std::env::var("NETCONTROL_INTEGRATION").as_deref(),
        Ok("1"),
        "set NETCONTROL_INTEGRATION=1 to authorize privileged native tests"
    );
    std::thread::spawn(move || {
        ensure!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
            "integration requires CAP_SYS_ADMIN/new network namespace: {}",
            std::io::Error::last_os_error()
        );
        let fd = linux::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        request.ifr_name[0] = b'l' as _;
        request.ifr_name[1] = b'o' as _;
        linux::check(unsafe {
            libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request)
        })?;
        unsafe {
            request.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
        }
        linux::check(unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) })?;
        test()
    })
    .join()
    .expect("native test thread panic")
    .expect("native integration failed");
}
#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/raw-socket privileges"]
fn native_icmp_v4_v6_echo_no_children() {
    isolated(|| {
        for v6 in [false, true] {
            let ip = if v6 { "::1" } else { "127.0.0.1" }.parse::<std::net::IpAddr>()?;
            let fd = linux::socket(
                if v6 { libc::AF_INET6 } else { libc::AF_INET },
                libc::SOCK_RAW,
                if v6 {
                    libc::IPPROTO_ICMPV6
                } else {
                    libc::IPPROTO_ICMP
                },
            )?;
            linux::bind(fd.as_raw_fd(), SocketAddr::new(ip, 0), 1)?;
            let nonce = rand::random::<[u8; 16]>();
            let wire = gateway::echo(45, 27, &nonce, v6);
            linux::send(fd.as_raw_fd(), &wire, SocketAddr::new(ip, 0), 1)?;
            let start = Instant::now();
            let mut buffer = [0; 2048];
            let mut received = false;
            while start.elapsed() < Duration::from_secs(2) {
                if let Some((n, from)) = linux::recv(fd.as_raw_fd(), &mut buffer)? {
                    if from.ip() == ip && gateway::reply(&buffer[..n], 27, &nonce, v6) == Some(45) {
                        received = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            ensure!(received, "native ICMP echo reply missing for {ip}");
        }
        Ok(())
    });
}
#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace privileges"]
fn native_counter_worker_persists_history_and_joins() {
    isolated(|| {
        let directory =
            std::env::temp_dir().join(format!("native-counters-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory)?;
        let mut worker = worker::Worker::start(
            "counter-test".into(),
            None,
            json!({"name":"counter-test"}),
            {
                let directory = directory.clone();
                move || {
                    counters::prepare(directory.clone(), netcontrol_core::VNStatConfig::default())
                }
            },
        )?;
        let path = directory.join(counters::FILE_NAME);
        let start = Instant::now();
        while !path.exists() && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let server = UdpSocket::bind("127.0.0.1:0")?;
        server.set_read_timeout(Some(Duration::from_secs(1)))?;
        let client = UdpSocket::bind("127.0.0.1:0")?;
        client.send_to(b"native traffic", server.local_addr()?)?;
        let mut buffer = [0; 64];
        server.recv(&mut buffer)?;
        let sampled = Instant::now();
        while sampled.elapsed() < Duration::from_secs(8) {
            if counters::Database::load(&path, "host")?
                .interfaces
                .get("lo")
                .is_some_and(|value| value.total.rx_packets > 0)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        worker.shutdown()?;
        ensure!(
            worker.snapshot()["state"] == "stopped",
            "counter worker failed: {}",
            worker.snapshot()
        );
        let db = counters::Database::load(&path, "host")?;
        ensure!(
            db.interfaces["lo"].total.rx_bytes >= 14 && db.interfaces["lo"].total.rx_packets > 0,
            "counter worker did not record loopback traffic"
        );
        ensure!(db.history.len() >= 2, "counter history not persisted");
        let persisted = std::fs::read(&path)?;
        let loaded = counters::Database::load(&path, "host")?;
        ensure!(
            loaded.interfaces["lo"].total.rx_bytes == db.interfaces["lo"].total.rx_bytes,
            "counter reload changed history"
        );
        ensure!(
            std::fs::read(&path)? == persisted,
            "counter read modified file"
        );
        client.send_to(b"restart traffic", server.local_addr()?)?;
        server.recv(&mut buffer)?;
        let mut resumed = worker::Worker::start(
            "counter-test".into(),
            None,
            json!({"name":"counter-test"}),
            {
                let directory = directory.clone();
                move || {
                    counters::prepare(directory.clone(), netcontrol_core::VNStatConfig::default())
                }
            },
        )?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let current = counters::Database::load(&path, "host")?;
            if current.interfaces["lo"].total.rx_bytes > db.interfaces["lo"].total.rx_bytes {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "counter restart did not preserve/advance history"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        resumed.shutdown()?;
        ensure!(
            resumed.snapshot()["state"] == "stopped",
            "restarted worker did not join"
        );
        std::fs::remove_dir_all(directory)?;
        Ok(())
    });
}
#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace privileges"]
fn native_ntp_udp_fixture_validates_origin_without_changing_clock() {
    isolated(|| {
        let server = UdpSocket::bind("127.0.0.1:123")?;
        server.set_read_timeout(Some(Duration::from_secs(1)))?;
        let client = UdpSocket::bind("127.0.0.1:0")?;
        client.connect("127.0.0.1:123")?;
        client.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut request = [0; 48];
        request[0] = 0x23;
        let t = 1_800_000_000.;
        let origin = ntp::stamp(t);
        request[40..48].copy_from_slice(&origin);
        client.send(&request)?;
        let mut wire = [0; 48];
        let (n, from) = server.recv_from(&mut wire)?;
        ensure!(n == 48, "NTP request length");
        let mut response = [0; 48];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&wire[40..48]);
        response[32..40].copy_from_slice(&ntp::stamp(t + 0.01));
        response[40..48].copy_from_slice(&ntp::stamp(t + 0.02));
        server.send_to(&response, from)?;
        let n = client.recv(&mut wire)?;
        let (offset, delay) = ntp::sample(&wire[..n], origin, t, t + 0.03)?;
        ensure!(
            offset.abs() < 0.001 && delay < 0.021,
            "invalid native NTP sample"
        );
        response[24] ^= 1;
        ensure!(
            ntp::sample(&response, origin, t, t + 0.03).is_err(),
            "spoofed origin accepted"
        );
        Ok(())
    });
}
#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/raw-socket privileges"]
fn native_af_packet_drops_report_incomplete_statistics_and_keep_exporting() {
    isolated(|| {
        let collector = UdpSocket::bind("127.0.0.1:2055")?;
        collector.set_read_timeout(Some(Duration::from_secs(5)))?;
        let target = UdpSocket::bind("127.0.0.1:25001")?;
        let sender = UdpSocket::bind("127.0.0.1:25002")?;
        let config = config::Flow {
            name: "loss-test".into(),
            enabled: true,
            interface: "lo".into(),
            collector: "127.0.0.1:2055".into(),
            export_version: 5,
            sampling_rate: 1,
            max_flows: 100,
            snaplen: 128,
            promiscuous: false,
            capture_filter: String::new(),
            timeouts: std::collections::BTreeMap::from([("general".into(), 1)]),
        };
        let mut worker = worker::Worker::start(
            "flow-loss-test".into(),
            None,
            json!({"name":"loss-test"}),
            move || {
                let run = flow::prepare(config.clone(), true)?;
                // Fill the capture socket before its receive loop starts.
                for _ in 0..16_384 {
                    sender.send_to(&[0; 1024], target.local_addr()?)?;
                }
                Ok(run)
            },
        )?;
        let mut buffer = [0; 2048];
        let n = collector.recv(&mut buffer)?;
        ensure!(
            n >= 72 && buffer[..2] == 5u16.to_be_bytes(),
            "missing export after capture loss"
        );
        let start = Instant::now();
        while worker.snapshot()["statistics_complete"] != false
            && start.elapsed() < Duration::from_secs(3)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let first = worker.snapshot();
        let dropped: u64 = first["dropped_packets"]
            .as_str()
            .context("missing exact capture-drop counter")?
            .parse()?;
        ensure!(
            dropped > 0,
            "capture-drop fixture did not overflow the socket"
        );
        ensure!(
            first["state"] == "running" && first["statistics_complete"] == false,
            "capture loss stopped the worker or was hidden: {first}"
        );
        let target = UdpSocket::bind("127.0.0.1:25003")?;
        let sender = UdpSocket::bind("127.0.0.1:25004")?;
        sender.send_to(b"after-loss", target.local_addr()?)?;
        let n = collector.recv(&mut buffer)?;
        ensure!(
            n >= 72 && buffer[..2] == 5u16.to_be_bytes(),
            "export did not continue"
        );
        worker.shutdown()?;
        let final_status = worker.snapshot();
        ensure!(
            final_status["state"] == "stopped"
                && final_status["statistics_complete"] == false
                && final_status["dropped_packets"]
                    .as_str()
                    .context("missing drops")?
                    .parse::<u64>()?
                    >= dropped
                && final_status["exported_flows"]
                    .as_u64()
                    .context("missing final exports")?
                    > first["exported_flows"]
                        .as_u64()
                        .context("missing initial exports")?
                && final_status.get("error").is_none(),
            "loss accounting, continued export or shutdown failed: {final_status}"
        );
        Ok(())
    });
}
#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/raw-socket privileges"]
fn native_flow_capacity_exports_are_batched_and_lossless() {
    isolated(|| {
        let collector = UdpSocket::bind("127.0.0.1:2055")?;
        collector.set_read_timeout(Some(Duration::from_secs(5)))?;
        let target = UdpSocket::bind("127.0.0.1:25001")?;
        let destination = target.local_addr()?;
        let senders: Vec<_> = (0..128)
            .map(|_| UdpSocket::bind("127.0.0.1:0"))
            .collect::<std::io::Result<_>>()?;
        let ports: std::collections::BTreeSet<_> = senders
            .iter()
            .map(|sender| sender.local_addr().map(|address| address.port()))
            .collect::<std::io::Result<_>>()?;
        let config = config::Flow {
            name: "capacity-test".into(),
            enabled: true,
            interface: "lo".into(),
            collector: "127.0.0.1:2055".into(),
            export_version: 5,
            sampling_rate: 1,
            max_flows: 8,
            snaplen: 128,
            promiscuous: false,
            capture_filter: String::new(),
            timeouts: std::collections::BTreeMap::from([("general".into(), 1)]),
        };
        let mut worker = worker::Worker::start(
            "flow-capacity-test".into(),
            None,
            json!({"name":"capacity-test"}),
            move || {
                let run = flow::prepare(config.clone(), true)?;
                // Queue a bounded burst so each receive batch contains multiple flows.
                for sender in &senders {
                    sender.send_to(&[0; 16], destination)?;
                }
                Ok(run)
            },
        )?;
        let mut seen = std::collections::BTreeSet::new();
        let mut datagrams = 0;
        let mut buffer = [0; 2048];
        while seen.len() < ports.len() {
            let n = collector.recv(&mut buffer)?;
            ensure!(
                n >= 72 && buffer[..2] == 5u16.to_be_bytes(),
                "invalid capacity-driven v5 export"
            );
            let records = usize::from(u16::from_be_bytes(buffer[2..4].try_into()?));
            ensure!(
                records <= 30 && n == 24 + records * 48,
                "invalid v5 record count"
            );
            ensure!(
                u32::from_be_bytes(buffer[16..20].try_into()?) as usize == seen.len(),
                "batched v5 sequence skipped or repeated records"
            );
            for record in buffer[24..n].chunks_exact(48) {
                let port = u16::from_be_bytes(record[32..34].try_into()?);
                ensure!(
                    ports.contains(&port) && seen.insert(port),
                    "unknown or duplicated flow {port}"
                );
                ensure!(
                    u32::from_be_bytes(record[16..20].try_into()?) == 2
                        && u32::from_be_bytes(record[20..24].try_into()?) == 88,
                    "capacity eviction lost captured packets or bytes"
                );
            }
            datagrams += 1;
        }
        worker.shutdown()?;
        ensure!(
            seen == ports && datagrams < ports.len() / 2,
            "capacity exports were not batched"
        );
        let status = worker.snapshot();
        ensure!(
            status["state"] == "stopped"
                && status["dropped_packets"] == "0"
                && status["statistics_complete"] == true
                && status.get("error").is_none(),
            "capacity-driven export or shutdown failed: {status}"
        );
        Ok(())
    });
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/raw-socket privileges"]
fn native_flow_sustained_capture_above_old_receive_ceiling() {
    isolated(|| {
        for sampling_rate in [1, 4] {
            let collector = UdpSocket::bind("127.0.0.1:2055")?;
            collector.set_read_timeout(Some(Duration::from_secs(5)))?;
            let target = UdpSocket::bind("127.0.0.1:25001")?;
            let sender = UdpSocket::bind("127.0.0.1:25002")?;
            let config = config::Flow {
                name: "throughput-test".into(),
                enabled: true,
                interface: "lo".into(),
                collector: "127.0.0.1:2055".into(),
                export_version: 5,
                sampling_rate,
                max_flows: 100,
                snaplen: 128,
                promiscuous: false,
                capture_filter: String::new(),
                timeouts: std::collections::BTreeMap::from([("general".into(), 1)]),
            };
            let mut worker = worker::Worker::start(
                "flow-throughput-test".into(),
                None,
                json!({"name":"throughput-test"}),
                move || flow::prepare(config.clone(), true),
            )?;
            let started = Instant::now();
            const DATAGRAMS: u32 = 32_768;
            for _ in 0..DATAGRAMS / 64 {
                for _ in 0..64 {
                    sender.send_to(&[0; 16], target.local_addr()?)?;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let elapsed = started.elapsed();
            // Loopback delivers both outgoing and incoming copies to AF_PACKET.
            let captured = DATAGRAMS * 2;
            ensure!(
                f64::from(captured) / elapsed.as_secs_f64() > 25_600.0,
                "fixture did not exceed the old 256 packets/10ms ceiling: {elapsed:?}"
            );
            let mut buffer = [0; 2048];
            let n = collector.recv(&mut buffer)?;
            ensure!(
                n == 72 && buffer[..2] == 5u16.to_be_bytes(),
                "expected one v5 flow, received {n} bytes"
            );
            let packets = u32::from_be_bytes(buffer[40..44].try_into()?);
            let bytes = u32::from_be_bytes(buffer[44..48].try_into()?);
            ensure!(
                packets == captured / sampling_rate && bytes == packets * 44,
                "capture/sampling lost or duplicated packets: {packets}, {bytes} bytes, sampling {sampling_rate}"
            );
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let sending = stop.clone();
            let destination = target.local_addr()?;
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            sender.set_write_timeout(Some(Duration::from_millis(250)))?;
            let traffic = std::thread::spawn(move || -> Result<()> {
                sender.send_to(&[0; 16], destination)?;
                ready_tx.send(())?;
                while !sending.load(std::sync::atomic::Ordering::Acquire) {
                    for _ in 0..64 {
                        sender.send_to(&[0; 16], destination)?;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(())
            });
            let ready = ready_rx.recv_timeout(Duration::from_secs(1));
            let start = Instant::now();
            let shutdown = worker.shutdown();
            stop.store(true, std::sync::atomic::Ordering::Release);
            traffic.join().expect("traffic thread panic")?;
            ready?;
            shutdown?;
            ensure!(
                start.elapsed() < Duration::from_secs(1),
                "capture shutdown exceeded 1s"
            );
            let status = worker.snapshot();
            ensure!(
                status["state"] == "stopped"
                    && status["dropped_packets"] == "0"
                    && status["statistics_complete"] == true
                    && status.get("error").is_none(),
                "sustained capture lost packets or failed: {status}"
            );
        }
        Ok(())
    });
}

#[test]
#[ignore = "requires NETCONTROL_INTEGRATION=1 and Linux namespace/raw-socket privileges"]
fn native_af_packet_capture_exports_v1_v5_v9_ipfix_and_ipv6() {
    isolated(|| {
        let directory =
            std::env::current_dir()?.join(format!("native-flow-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory)?;
        let collector = UdpSocket::bind("127.0.0.1:2055")?;
        collector.set_read_timeout(Some(Duration::from_secs(3)))?;
        for version in [1u16, 5, 9, 10] {
            let config = config::Flow {
                name: "test".into(),
                enabled: true,
                interface: "lo".into(),
                collector: "127.0.0.1:2055".into(),
                export_version: version,
                sampling_rate: 1,
                max_flows: 100,
                snaplen: 128,
                promiscuous: false,
                capture_filter: String::new(),
                timeouts: std::collections::BTreeMap::from([("general".into(), 1)]),
            };
            let mut worker = worker::Worker::start(
                "flow-test".into(),
                None,
                json!({"name":"flow-test"}),
                move || flow::prepare(config.clone(), true),
            )?;
            let target = UdpSocket::bind(if [1, 5].contains(&version) {
                "127.0.0.1:25001"
            } else {
                "[::1]:25001"
            })?;
            let sender = UdpSocket::bind(if [1, 5].contains(&version) {
                "127.0.0.1:25002"
            } else {
                "[::1]:25002"
            })?;
            sender.send_to(b"flow-test-native", target.local_addr()?)?;
            let mut buffer = [0; 2048];
            let n = collector.recv(&mut buffer)?;
            ensure!(
                n >= if version == 1 { 64 } else { 72 } && buffer[..2] == version.to_be_bytes(),
                "invalid native NetFlow export"
            );
            ensure!(buffer[2..4] != [0, 0], "empty native flow export");
            let status = worker.snapshot();
            ensure!(
                status["dropped_packets"] == "0" && status["statistics_complete"] == true,
                "fresh loss-free exporter did not reset capture statistics: {status}"
            );
            worker.shutdown()?;
            ensure!(
                worker.snapshot()["state"] == "stopped",
                "flow worker shutdown failed: {}",
                worker.snapshot()
            );
            if ![1, 5].contains(&version) {
                let header = if version == 9 { 20 } else { 16 };
                let templates =
                    u16::from_be_bytes(buffer[header + 2..header + 4].try_into()?) as usize;
                ensure!(
                    buffer[header + templates..header + templates + 2] == 257u16.to_be_bytes(),
                    "IPv6 export did not use template257"
                );
            }
        }
        std::fs::remove_dir_all(directory)?;
        Ok(())
    });
}
