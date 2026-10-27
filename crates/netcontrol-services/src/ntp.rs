use anyhow::{Result, ensure};
const EPOCH: f64 = 2_208_988_800.;
fn timestamp(bytes: &[u8], around: f64) -> f64 {
    let seconds = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as f64;
    let fraction = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as f64 / 4_294_967_296.;
    let era = ((around + EPOCH - seconds) / 4_294_967_296.).round();
    seconds + fraction + era * 4_294_967_296. - EPOCH
}
pub(crate) fn stamp(unix: f64) -> [u8; 8] {
    let ntp = unix + EPOCH;
    let mut out = [0; 8];
    out[..4].copy_from_slice(&(ntp.floor() as u64 as u32).to_be_bytes());
    out[4..].copy_from_slice(&((ntp.fract() * 4_294_967_296.) as u32).to_be_bytes());
    out
}
pub(crate) fn sample(packet: &[u8], origin: [u8; 8], t1: f64, t4: f64) -> Result<(f64, f64)> {
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
    Ok((offset, delay.max(0.)))
}
pub(crate) fn bounded_slew(offset_seconds: f64) -> Result<(i64, f64)> {
    ensure!(
        offset_seconds.is_finite(),
        "NTP slew requires a finite offset"
    );
    let requested_us = (offset_seconds.clamp(-0.5, 0.5) * 1_000_000.).round() as i64;
    Ok((
        requested_us,
        offset_seconds - requested_us as f64 / 1_000_000.,
    ))
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
            Duration::from_secs(64),
            Duration::from_secs(3),
            |requested_us| {
                let mut tx: libc::timex = unsafe { std::mem::zeroed() };
                tx.modes = 0x8001; // ADJ_OFFSET_SINGLESHOT; never ADJ_SETOFFSET or clock_settime.
                tx.offset = requested_us as _;
                ensure!(
                    unsafe { libc::adjtimex(&mut tx) } >= 0,
                    "bounded NTP slew failed: {}",
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
    mut slew: impl FnMut(i64) -> Result<()>,
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
                        let t4 = t1 + start.elapsed().as_secs_f64();
                        match sample(&discard[..n], origin, t1, t4) {
                            Ok((offset, delay)) => {
                                samples.push((offset, delay, host));
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
        if let Some((offset, delay, host)) = samples.first() {
            let (requested_us, uncorrected) = bounded_slew(*offset)?;
            slew(requested_us)?;
            ctx.update(|s| {
                s["sample_status"] = json!("available");
                s["server"] = json!(host);
                s["offset_ms"] = json!(offset * 1000.);
                s["delay_ms"] = json!(delay * 1000.);
                s["requested_slew_ms"] = json!(requested_us as f64 / 1000.);
                s["uncorrected_offset_ms"] = json!(uncorrected * 1000.);
                s["discipline"] = json!("slew_only");
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

    fn respond(server: &UdpSocket) {
        let mut wire = [0; 48];
        let (n, from) = server.recv_from(&mut wire).unwrap();
        assert_eq!(n, 48);
        let origin = <[u8; 8]>::try_from(&wire[40..48]).unwrap();
        wire[0] = 0x24;
        wire[1] = 2;
        wire[24..32].copy_from_slice(&origin);
        wire[32..40].copy_from_slice(&origin);
        server.send_to(&wire, from).unwrap();
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
        let (slew_tx, slew_rx) = mpsc::channel();
        let mut worker = Worker::start("ntp".into(), None, json!({"name":"ntp"}), move || {
            let client = client.try_clone()?;
            let slew_tx = slew_tx.clone();
            Ok(Box::new(move |ctx| {
                poll(
                    ctx,
                    vec![("fixture".into(), client)],
                    vec![],
                    |_| anyhow::bail!("unused"),
                    Duration::from_millis(5),
                    Duration::from_millis(100),
                    |requested| {
                        slew_tx.send(requested)?;
                        Ok(())
                    },
                )
            }))
        })
        .unwrap();
        respond(&server);
        assert!(slew_rx.recv_timeout(Duration::from_secs(2)).unwrap().abs() <= 500000);
        let available = wait_for(&worker, |s| s["sample_status"] == "available");
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
            "collected_at",
            "offset_ms",
            "delay_ms",
            "requested_slew_ms",
            "uncorrected_offset_ms",
        ] {
            assert_eq!(unavailable[key], available[key], "{key}");
        }
        respond(&server);
        assert!(slew_rx.recv_timeout(Duration::from_secs(2)).unwrap().abs() <= 500000);
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
                    Duration::from_secs(64),
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
    fn validates_ntp_and_slew_bounds() {
        let (mut p, t, origin) = reply();
        let (offset, delay) = sample(&p, origin, t, t + 0.04).unwrap();
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
        let (offset, _) = sample(&p, o, t, t + 0.04).unwrap();
        assert!((offset - 2.985).abs() < 0.00001);
    }
    #[test]
    fn bounded_slew_requests_and_residual_are_exact() {
        for (offset, expected_us, residual) in [
            (2., 500000, 1.5),
            (-3., -500000, -2.5),
            (0.5, 500000, 0.),
            (-0.5, -500000, 0.),
            (0.125, 125000, 0.),
            (-0.125, -125000, 0.),
            (0., 0, 0.),
        ] {
            let (requested, left) = bounded_slew(offset).unwrap();
            assert_eq!(requested, expected_us);
            assert_eq!(left, residual);
            assert!(requested.abs() <= 500000);
        }
        assert!(bounded_slew(f64::NAN).is_err());
        assert!(bounded_slew(f64::INFINITY).is_err());
        let (requested, residual) = bounded_slew(0.00000125).unwrap();
        assert_eq!(requested, 1);
        assert!((residual - 0.00000025).abs() < 1e-15);
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
