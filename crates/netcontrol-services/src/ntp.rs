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
pub(crate) fn prepare(
    config: super::config::Ntp,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use serde_json::json;
    use std::{
        net::UdpSocket,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    super::linux::capabilities(25)?;
    let mut sockets = Vec::new();
    for host in config.servers {
        let address = super::resolve::resolve(&host, 123)?
            .into_iter()
            .next()
            .unwrap();
        let s = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        s.connect(address)?;
        s.set_nonblocking(true)?;
        sockets.push((host, s));
    }
    // Query privilege/clock support before reporting a running service.
    let mut check: libc::timex = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::adjtimex(&mut check) } >= 0,
        "adjtimex query failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(Box::new(move |ctx| {
        let mut failures = 0;
        while !ctx.stopping() {
            let mut samples = Vec::new();
            let mut errors = Vec::new();
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
                while start.elapsed() < Duration::from_secs(3) && !ctx.stopping() {
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
                let mut tx: libc::timex = unsafe { std::mem::zeroed() };
                tx.modes = 0x8001; // ADJ_OFFSET_SINGLESHOT; never ADJ_SETOFFSET or clock_settime.
                let (requested_us, uncorrected) = bounded_slew(*offset)?;
                tx.offset = requested_us as _;
                ensure!(
                    unsafe { libc::adjtimex(&mut tx) } >= 0,
                    "bounded NTP slew failed: {}",
                    std::io::Error::last_os_error()
                );
                failures = 0;
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
                failures += 1;
                ctx.update(|s| {
                    s["sample_status"] = json!("unavailable");
                    s["error"] = json!(errors.join("; "));
                });
                ensure!(
                    failures < 3,
                    "no valid NTP samples after three polling rounds: {}",
                    errors.join("; ")
                );
            }
            ctx.wait(Duration::from_secs(64));
        }
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
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
