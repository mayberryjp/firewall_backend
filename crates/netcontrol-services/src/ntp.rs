use anyhow::{Result, ensure};
const EPOCH: f64 = 2_208_988_800.;
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
fn timestamp_seconds(bytes: &[u8], around: f64) -> i64 {
    let seconds = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as f64;
    let era = ((around + EPOCH - seconds) / 4_294_967_296.).round();
    (seconds + era * 4_294_967_296. - EPOCH) as i64
}
fn timestamp(bytes: &[u8], around: f64) -> f64 {
    let fraction = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as f64 / 4_294_967_296.;
    timestamp_seconds(bytes, around) as f64 + fraction
}
pub(crate) fn stamp(unix: f64) -> [u8; 8] {
    let ntp = unix + EPOCH;
    let mut out = [0; 8];
    out[..4].copy_from_slice(&(ntp.floor() as u64 as u32).to_be_bytes());
    out[4..].copy_from_slice(&((ntp.fract() * 4_294_967_296.) as u32).to_be_bytes());
    out
}
pub(crate) fn sample(
    packet: &[u8],
    origin: [u8; 8],
    t1: f64,
    t4: f64,
) -> Result<(f64, f64, String)> {
    ensure!(
        packet.len() == 48,
        "NTP extensions/authentication are not supported"
    );
    let version = (packet[0] >> 3) & 7;
    ensure!(
        packet[0] >> 6 != 3 && (version == 3 || version == 4) && packet[0] & 7 == 4,
        "invalid NTP leap/version/server mode"
    );
    ensure!(
        (1..=15).contains(&packet[1]),
        "NTP kiss-of-death or invalid stratum"
    );
    ensure!(packet[24..32] == origin, "NTP originate timestamp mismatch");
    ensure!(
        packet[32..40].iter().any(|b| *b != 0) && packet[40..48].iter().any(|b| *b != 0),
        "zero NTP timestamps"
    );
    let t2 = timestamp(&packet[32..40], t1);
    let t3 = timestamp(&packet[40..48], t1);
    let delay = (t4 - t1) - (t3 - t2);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.;
    let root_delay = i32::from_be_bytes(packet[4..8].try_into().unwrap()) as f64 / 65536.;
    let dispersion = u32::from_be_bytes(packet[8..12].try_into().unwrap()) as f64 / 65536.;
    ensure!(
        t4 >= t1
            && t4 - t1 <= 5.
            && t3 >= t2
            && (-0.001..=3.).contains(&delay)
            && root_delay >= 0.
            && root_delay / 2. + dispersion + delay.max(0.) / 2. <= 1.5,
        "NTP invalid timing or excessive root distance"
    );
    ensure!(offset.is_finite(), "invalid nonfinite NTP offset");
    let fraction = u64::from(u32::from_be_bytes(packet[44..48].try_into()?));
    let nanoseconds = (fraction * 1_000_000_000 / 4_294_967_296) as u32;
    let server_time =
        time::OffsetDateTime::from_unix_timestamp(timestamp_seconds(&packet[40..48], t1))?
            .replace_nanosecond(nanoseconds)?
            .format(&time::format_description::well_known::Rfc3339)?;
    Ok((offset, delay.max(0.), server_time))
}
#[cfg(any(target_os = "linux", test))]
fn corrected_time(unix_seconds: f64, elapsed: std::time::Duration) -> Result<std::time::Duration> {
    let target = std::time::Duration::try_from_secs_f64(unix_seconds)
        .map_err(|error| anyhow::anyhow!("invalid NTP clock target: {error}"))?;
    target
        .checked_add(elapsed)
        .ok_or_else(|| anyhow::anyhow!("NTP clock target overflow"))
}
#[cfg(target_os = "linux")]
fn open_server(host: &str, ipv6_enabled: bool) -> Result<std::net::UdpSocket> {
    use std::net::UdpSocket;
    let address = super::resolve::resolve(host, 123, ipv6_enabled)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no NTP server address"))?;
    let s = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    s.connect(address)?;
    s.set_nonblocking(true)?;
    Ok(s)
}
#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    config: super::config::Ntp,
    ipv6_enabled: bool,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use std::time::Duration;
    super::linux::capabilities(25)?;
    // Unresolvable servers are retried every poll; DNS may be down when the worker starts.
    let mut sockets = Vec::new();
    let mut pending = Vec::new();
    for host in config.servers {
        match open_server(&host, ipv6_enabled) {
            Ok(socket) => sockets.push((host, socket)),
            Err(_) => pending.push(host),
        }
    }
    // Query privilege/clock support before reporting a running service.
    let mut check: libc::timex = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::adjtimex(&mut check) } >= 0,
        "adjtimex query failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(Box::new(move |ctx| {
        poll(
            ctx,
            sockets,
            pending,
            move |host| open_server(host, ipv6_enabled),
            POLL_INTERVAL,
            Duration::from_secs(3),
            |target| {
                let target = libc::timespec {
                    tv_sec: target.as_secs().try_into()?,
                    tv_nsec: target.subsec_nanos().into(),
                };
                ensure!(
                    unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &target) } == 0,
                    "NTP clock step failed: {}",
                    std::io::Error::last_os_error()
                );
                Ok(())
            },
        )
    }))
}
#[cfg(any(target_os = "linux", test))]
fn poll(
    ctx: super::worker::ContextState,
    mut sockets: Vec<(String, std::net::UdpSocket)>,
    mut pending: Vec<String>,
    mut open: impl FnMut(&str) -> Result<std::net::UdpSocket>,
    interval: std::time::Duration,
    response_timeout: std::time::Duration,
    mut step: impl FnMut(std::time::Duration) -> Result<()>,
) -> Result<()> {
    use serde_json::json;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    while !ctx.stopping() {
        let mut samples = Vec::new();
        let mut errors = Vec::new();
        pending.retain(|host| match open(host) {
            Ok(socket) => {
                sockets.push((host.clone(), socket));
                false
            }
            Err(error) => {
                errors.push(format!("{host}: {error:#}"));
                true
            }
        });
        for (host, socket) in &sockets {
            if ctx.stopping() {
                break;
            }
            let mut discard = [0; 512];
            for _ in 0..64 {
                if socket.recv(&mut discard).is_err() {
                    break;
                }
            }
            let mut wire = [0; 48];
            wire[0] = 0x23;
            let t1 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
            let origin = stamp(t1);
            wire[40..48].copy_from_slice(&origin);
            socket.send(&wire)?;
            let start = Instant::now();
            let mut got = false;
            while start.elapsed() < response_timeout && !ctx.stopping() {
                match socket.recv(&mut discard) {
                    Ok(n) => {
                        let received_at = Instant::now();
                        let t4 = t1 + received_at.duration_since(start).as_secs_f64();
                        match sample(&discard[..n], origin, t1, t4) {
                            Ok((offset, delay, server_time)) => {
                                samples.push((
                                    offset,
                                    delay,
                                    host,
                                    server_time,
                                    t4 + offset,
                                    received_at,
                                ));
                                got = true;
                                break;
                            }
                            Err(e) => errors.push(format!("{host}: {e}")),
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        ctx.wait(Duration::from_millis(20));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if !got {
                errors.push(format!("{host}: no valid NTP sample"));
            }
        }
        if ctx.stopping() {
            break;
        }
        samples.sort_by(|a, b| a.1.total_cmp(&b.1));
        if let Some((offset, delay, host, server_time, target, received_at)) = samples.first() {
            // Advance the selected sample through time spent querying other servers.
            step(corrected_time(*target, received_at.elapsed())?)?;
            ctx.update(|s| {
                s["sample_status"] = json!("available");
                s["server"] = json!(host);
                s["server_time"] = json!(server_time);
                s["offset_ms"] = json!(offset * 1000.);
                s["delay_ms"] = json!(delay * 1000.);
                s["requested_step_ms"] = json!(offset * 1000.);
                s["discipline"] = json!("step");
                s["collected_at"] = json!(super::worker::now());
                s.as_object_mut().unwrap().remove("error");
            });
        } else {
            ctx.update(|s| {
                s["sample_status"] = json!("unavailable");
                s["error"] = json!(errors.join("; "));
            });
        }
        ctx.wait(interval);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Worker;
    use serde_json::{Value, json};
    use std::{
        net::UdpSocket,
        sync::mpsc,
        time::{Duration, Instant},
    };

    fn wait_for(worker: &Worker, predicate: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = worker.snapshot();
            if predicate(&status) {
                return status;
            }
            assert!(Instant::now() < deadline, "unexpected NTP status: {status}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn respond_with_offset(server: &UdpSocket, offset: f64) -> f64 {
        let mut wire = [0; 48];
        let (n, from) = server.recv_from(&mut wire).unwrap();
        assert_eq!(n, 48);
        let origin = <[u8; 8]>::try_from(&wire[40..48]).unwrap();
        let target = timestamp(&origin, 1_800_000_000.) + offset;
        wire[0] = 0x24;
        wire[1] = 2;
        wire[24..32].copy_from_slice(&origin);
        wire[32..40].copy_from_slice(&stamp(target));
        wire[40..48].copy_from_slice(&stamp(target));
        server.send_to(&wire, from).unwrap();
        target
    }

    fn respond(server: &UdpSocket) {
        respond_with_offset(server, 0.);
    }

    #[test]
    fn missing_samples_keep_polling_preserve_stale_sample_and_recover() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        let (step_tx, step_rx) = mpsc::channel();
        let mut worker = Worker::start("ntp".into(), None, json!({"name":"ntp"}), move || {
            let client = client.try_clone()?;
            let step_tx = step_tx.clone();
            Ok(Box::new(move |ctx| {
                poll(
                    ctx,
                    vec![("fixture".into(), client)],
                    vec![],
                    |_| anyhow::bail!("unused"),
                    Duration::from_millis(5),
                    Duration::from_millis(100),
                    |requested| {
                        step_tx.send(requested)?;
                        Ok(())
                    },
                )
            }))
        })
        .unwrap();
        respond(&server);
        step_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let available = wait_for(&worker, |s| s["sample_status"] == "available");
        assert!(available["server_time"].as_str().is_some_and(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .is_ok()
        }));
        for _ in 0..4 {
            let mut request = [0; 48];
            server.recv_from(&mut request).unwrap();
        }
        let unavailable = wait_for(&worker, |s| s["sample_status"] == "unavailable");
        assert_eq!(unavailable["state"], "running");
        assert!(
            unavailable["error"]
                .as_str()
                .unwrap()
                .contains("fixture: no valid NTP sample")
        );
        for key in [
            "server",
            "server_time",
            "collected_at",
            "offset_ms",
            "delay_ms",
            "requested_step_ms",
        ] {
            assert_eq!(unavailable[key], available[key], "{key}");
        }
        respond(&server);
        step_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let recovered = wait_for(&worker, |s| s["sample_status"] == "available");
        assert_eq!(recovered["state"], "running");
        assert!(recovered.get("error").is_none());
        assert_ne!(recovered["collected_at"], available["collected_at"]);
        let start = Instant::now();
        worker.shutdown().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(worker.snapshot()["state"], "stopped");
    }

    #[test]
    fn unresolved_servers_keep_the_worker_running_and_are_retried_each_poll() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        let mut worker = Worker::start("ntp".into(), None, json!({}), move || {
            let mut client = Some(client.try_clone()?);
            let mut attempts = 0;
            Ok(Box::new(move |ctx| {
                poll(
                    ctx,
                    vec![],
                    vec!["late.example.test".into()],
                    move |_| {
                        attempts += 1;
                        if attempts < 3 {
                            anyhow::bail!("synthetic resolver outage");
                        }
                        Ok(client.take().expect("opened once"))
                    },
                    Duration::from_millis(5),
                    Duration::from_millis(100),
                    |_| Ok(()),
                )
            }))
        })
        .unwrap();
        let unavailable = wait_for(&worker, |s| s["sample_status"] == "unavailable");
        assert_eq!(unavailable["state"], "running");
        assert!(
            unavailable["error"]
                .as_str()
                .unwrap()
                .contains("late.example.test: synthetic resolver outage")
        );
        respond(&server);
        let available = wait_for(&worker, |s| s["sample_status"] == "available");
        assert_eq!(available["server"], "late.example.test");
        assert!(available.get("error").is_none());
        worker.shutdown().unwrap();
    }

    #[test]
    fn missing_samples_shutdown_interrupts_poll_wait() {
        let mut worker = Worker::start("ntp".into(), None, json!({}), || {
            Ok(Box::new(|ctx| {
                poll(
                    ctx,
                    vec![],
                    vec![],
                    |_| anyhow::bail!("unused"),
                    POLL_INTERVAL,
                    Duration::from_secs(3),
                    |_| panic!("no samples must not adjust the clock"),
                )
            }))
        })
        .unwrap();
        wait_for(&worker, |s| s["sample_status"] == "unavailable");
        let start = Instant::now();
        worker.shutdown().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(worker.snapshot()["state"], "stopped");
    }

    #[test]
    fn clock_adjustment_failure_reports_recovery_without_stopping_supervision() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        let mut worker = Worker::start("ntp".into(), None, json!({}), move || {
            let client = client.try_clone()?;
            Ok(Box::new(move |ctx| {
                poll(
                    ctx,
                    vec![("fixture".into(), client)],
                    vec![],
                    |_| anyhow::bail!("unused"),
                    Duration::from_millis(5),
                    Duration::from_secs(1),
                    |_| anyhow::bail!("injected clock adjustment failure"),
                )
            }))
        })
        .unwrap();
        respond(&server);
        let failed = wait_for(&worker, |s| s["state"] == "error");
        assert_eq!(failed["error"], "injected clock adjustment failure");
        assert_eq!(failed["retrying"], true);
        assert!(worker.active());
        worker.shutdown().unwrap();
    }

    fn reply() -> ([u8; 48], f64, [u8; 8]) {
        let t = 1_800_000_000.;
        let origin = stamp(t);
        let mut p = [0; 48];
        p[0] = 0x24;
        p[1] = 2;
        p[24..32].copy_from_slice(&origin);
        p[32..40].copy_from_slice(&stamp(t + 0.02));
        p[40..48].copy_from_slice(&stamp(t + 0.03));
        (p, t, origin)
    }
    #[test]
    fn validates_ntp_samples() {
        let (mut p, t, origin) = reply();
        let (offset, delay, _) = sample(&p, origin, t, t + 0.04).unwrap();
        assert!((offset - 0.005).abs() < 0.00001);
        assert!((delay - 0.03).abs() < 0.00001);
        p[1] = 0;
        assert!(sample(&p, origin, t, t + 0.04).is_err());
        p[1] = 2;
        p[0] |= 0xc0;
        assert!(sample(&p, origin, t, t + 0.04).is_err());
        let (mut p, t, o) = reply();
        p[24] = 0;
        assert!(sample(&p, o, t, t + 0.04).is_err());
        let (mut p, t, o) = reply();
        p[32..40].copy_from_slice(&stamp(t + 3.));
        p[40..48].copy_from_slice(&stamp(t + 3.01));
        let (offset, _, _) = sample(&p, o, t, t + 0.04).unwrap();
        assert!((offset - 2.985).abs() < 0.00001);
    }
    #[test]
    fn server_time_uses_transmit_timestamp_despite_a_three_day_clock_error() {
        let (mut packet, local, origin) = reply();
        let server = local - 3. * 86400.;
        packet[32..40].copy_from_slice(&stamp(server + 0.125));
        packet[40..48].copy_from_slice(&stamp(server + 0.25));
        let (offset, _, server_time) = sample(&packet, origin, local, local + 0.25).unwrap();
        let reported = time::OffsetDateTime::parse(
            &server_time,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert_eq!(reported.unix_timestamp(), server as i64);
        assert_eq!(reported.nanosecond(), 250_000_000);
        assert!(offset < -259199.);
    }
    #[test]
    fn clock_targets_preserve_full_corrections_and_elapsed_time() {
        let local = 1_800_000_000.;
        for offset in [-259200., -25828.041862, 0., 259200.] {
            let target = corrected_time(local + offset, Duration::from_millis(125)).unwrap();
            assert!((target.as_secs_f64() - (local + offset + 0.125)).abs() < 0.000001);
        }
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.] {
            assert!(corrected_time(invalid, Duration::ZERO).is_err());
        }
        assert!(corrected_time(local, Duration::MAX).is_err());
    }
    #[test]
    fn manual_restart_interrupts_daily_wait_and_steps_offsets_without_changing_host_clock() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        let (step_tx, step_rx) = mpsc::channel();
        let mut worker = Worker::start(
            "ntp".into(),
            None,
            json!({"sample_status":"warming_up"}),
            move || {
                let client = client.try_clone()?;
                let step_tx = step_tx.clone();
                Ok(Box::new(move |ctx| {
                    poll(
                        ctx,
                        vec![("fixture".into(), client)],
                        vec![],
                        |_| anyhow::bail!("unused"),
                        POLL_INTERVAL,
                        Duration::from_secs(1),
                        |target| {
                            step_tx.send(target)?;
                            Ok(())
                        },
                    )
                }))
            },
        )
        .unwrap();
        for (round, offset) in [0., -259200., 259200.].into_iter().enumerate() {
            if round > 0 {
                let start = Instant::now();
                worker.restart().unwrap();
                assert!(start.elapsed() < Duration::from_secs(1));
                let warming = worker.snapshot();
                assert_eq!(warming["sample_status"], "warming_up");
                assert!(warming.get("collected_at").is_none());
            }
            let server_time = respond_with_offset(&server, offset);
            let target = step_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!((target.as_secs_f64() - server_time).abs() < 1.);
            let available = wait_for(&worker, |s| {
                s["sample_status"] == "available"
                    && s["offset_ms"]
                        .as_f64()
                        .is_some_and(|value| (value - offset * 1000.).abs() < 1000.)
            });
            assert_eq!(available["discipline"], "step");
            assert_eq!(available["requested_step_ms"], available["offset_ms"]);
            assert!(available.get("requested_slew_ms").is_none());
            assert!(available.get("uncorrected_offset_ms").is_none());
        }
        worker.shutdown().unwrap();
    }
    #[test]
    fn era_rollover() {
        let t = 2_100_000_000.;
        assert!((timestamp(&stamp(t), t) - t).abs() < 0.0001);
    }
    #[test]
    fn truncated_and_random_ntp_never_panics() {
        for length in 0..128 {
            let packet: Vec<_> = (0..length).map(|_| rand::random()).collect();
            assert!(sample(&packet, [0; 8], 1., 2.).is_err());
        }
        let (p, t, o) = reply();
        let mut large = p.to_vec();
        large.push(0);
        assert!(sample(&large, o, t, t + 0.04).is_err());
    }
}
