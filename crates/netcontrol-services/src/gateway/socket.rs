use crate::linux as l;
use anyhow::{Context, Result, ensure};
use std::{
    io, mem,
    net::SocketAddr,
    os::fd::RawFd,
    time::{Duration, Instant, SystemTime},
};

pub(super) fn configure(fd: RawFd, id: u16, nonce: &[u8; 16], ipv6: bool) -> Result<()> {
    let instruction = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let mut filter = vec![instruction(
        if ipv6 {
            (libc::BPF_LDX | libc::BPF_IMM) as u16
        } else {
            (libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH) as u16
        },
        0,
    )];
    let mut fields = vec![
        (libc::BPF_H, 0, if ipv6 { 129 << 8 } else { 0 }),
        (libc::BPF_H, 4, u32::from(id)),
    ];
    for (i, word) in nonce.chunks_exact(4).enumerate() {
        fields.push((
            libc::BPF_W,
            8 + i as u32 * 4,
            u32::from_be_bytes(word.try_into()?),
        ));
    }
    for (size, offset, expected) in fields {
        filter.push(instruction(
            (libc::BPF_LD | size | libc::BPF_IND) as u16,
            offset,
        ));
        filter.push(instruction(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            expected,
        ));
    }
    filter.push(instruction((libc::BPF_RET | libc::BPF_K) as u16, u32::MAX));
    filter.push(instruction((libc::BPF_RET | libc::BPF_K) as u16, 0));
    let reject = filter.len() - 1;
    for at in (2..reject - 1).step_by(2) {
        filter[at].jf = (reject - at - 1).try_into()?;
    }
    let program = libc::sock_fprog {
        len: filter.len().try_into()?,
        filter: filter.as_mut_ptr(),
    };
    l::option(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program)
        .context("install gateway reply filter")?;
    l::option(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, &1i32)?;
    Ok(())
}

pub(super) fn check_queue(fd: RawFd) -> Result<()> {
    // SO_MEMINFO reports cumulative drops even without a subsequent datagram;
    // SO_RXQ_OVFL ancillary data alone cannot detect that case.
    let mut memory = [0u32; 9];
    let mut length = mem::size_of_val(&memory) as libc::socklen_t;
    l::check(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MEMINFO,
            memory.as_mut_ptr().cast(),
            &mut length,
        )
    })?;
    ensure!(
        length as usize == mem::size_of_val(&memory),
        "incomplete gateway socket memory statistics"
    );
    let dropped = memory[8]; // SK_MEMINFO_DROPS
    ensure!(
        dropped == 0,
        "gateway local receive queue overflow: {dropped} packets"
    );
    Ok(())
}

// Linux software receive timestamps use CLOCK_REALTIME. Detect clock steps
// instead of letting appliance time correction fabricate RTTs or packet loss.
pub(super) struct ReceiveClock {
    monotonic: Instant,
    realtime: SystemTime,
    uncertainty: Duration,
}

impl ReceiveClock {
    pub(super) fn now() -> Result<Self> {
        let monotonic = Instant::now();
        let realtime = SystemTime::now();
        let uncertainty = monotonic.elapsed();
        ensure!(
            uncertainty <= Duration::from_millis(1),
            "gateway clock sampling delayed"
        );
        Ok(Self {
            monotonic,
            realtime,
            uncertainty,
        })
    }

    fn validate_at(&self, current: &Self) -> Result<()> {
        let elapsed = current.monotonic.duration_since(self.monotonic);
        let expected = self
            .realtime
            .checked_add(elapsed)
            .context("gateway clock overflow")?;
        let difference = current
            .realtime
            .duration_since(expected)
            .or_else(|_| expected.duration_since(current.realtime))?;
        ensure!(
            difference <= Duration::from_millis(1) + self.uncertainty + current.uncertainty,
            "gateway receive clock changed; restarting measurements"
        );
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.validate_at(&Self::now()?)
    }

    pub(super) fn arrival(&self, timestamp: SystemTime) -> Result<Instant> {
        self.validate()?;
        self.monotonic
            .checked_add(
                timestamp
                    .duration_since(self.realtime)
                    .context("gateway receive timestamp precedes measurement clock")?,
            )
            .context("gateway receive timestamp overflow")
    }
}

pub(super) fn recv(
    fd: RawFd,
    buffer: &mut [u8],
) -> Result<Option<(usize, SocketAddr, SystemTime)>> {
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut control = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = mem::size_of_val(&address) as _;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control);
    let n = loop {
        let n = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_TRUNC) };
        if n >= 0 {
            break n as usize;
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::WouldBlock => return Ok(None),
            io::ErrorKind::Interrupted => continue,
            _ => return Err(error.into()),
        }
    };
    ensure!(
        n <= buffer.len() && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0,
        "truncated gateway reply or receive metadata"
    );
    let mut timestamp = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let h = unsafe { &*header };
        if h.cmsg_level == libc::SOL_SOCKET {
            let payload = h
                .cmsg_len
                .saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
            if h.cmsg_type == libc::SCM_TIMESTAMPNS {
                ensure!(
                    payload >= mem::size_of::<libc::timespec>(),
                    "short gateway timestamp"
                );
                let stamp = unsafe {
                    libc::CMSG_DATA(header)
                        .cast::<libc::timespec>()
                        .read_unaligned()
                };
                ensure!(
                    stamp.tv_sec >= 0 && (0..1_000_000_000).contains(&stamp.tv_nsec),
                    "invalid gateway receive timestamp"
                );
                timestamp = SystemTime::UNIX_EPOCH.checked_add(Duration::new(
                    stamp.tv_sec.try_into()?,
                    stamp.tv_nsec.try_into()?,
                ));
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    Ok(Some((
        n,
        l::from_sockaddr(&address)?,
        timestamp.context("gateway receive timestamp missing")?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{Window, checksum, echo, reply};
    use std::os::fd::AsRawFd;

    #[test]
    fn clock_steps_in_both_directions_invalidate_measurements() -> Result<()> {
        let clock = ReceiveClock::now()?;
        for step in [Duration::ZERO, Duration::from_secs(3)] {
            let mut current = ReceiveClock {
                monotonic: clock.monotonic + Duration::from_secs(10),
                realtime: clock.realtime + Duration::from_secs(10) + step,
                uncertainty: Duration::ZERO,
            };
            assert_eq!(clock.validate_at(&current).is_ok(), step.is_zero());
            current.realtime -= step * 2;
            assert_eq!(clock.validate_at(&current).is_ok(), step.is_zero());
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux CAP_NET_RAW and IPv4/IPv6 loopback"]
    fn kernel_arrival_excludes_worker_delay_and_filters_unrelated_icmp() -> Result<()> {
        for ipv6 in [false, true] {
            let fd = l::socket(
                if ipv6 { libc::AF_INET6 } else { libc::AF_INET },
                libc::SOCK_RAW,
                if ipv6 {
                    libc::IPPROTO_ICMPV6
                } else {
                    libc::IPPROTO_ICMP
                },
            )?;
            let fd = fd.as_raw_fd();
            let target: SocketAddr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }.parse()?;
            let id = rand::random();
            let nonce = rand::random();
            configure(fd, id, &nonce, ipv6)?;
            let clock = ReceiveClock::now()?;
            let directory = tempfile::tempdir()?;
            let log = netcontrol_core::PerformanceLog::open(&directory.path().join("performance"))?;
            let start = Instant::now();
            let mut window = Window::new(crate::gateway::tests::config(), start);
            window.sent(1, start);
            let response = |seq, id, nonce: &[u8; 16], size| {
                let mut packet = echo(seq, id, nonce, ipv6);
                packet[0] = if ipv6 { 129 } else { 0 };
                packet.resize(size, 0);
                packet[2..4].fill(0);
                if !ipv6 {
                    let sum = checksum(&packet);
                    packet[2..4].copy_from_slice(&sum.to_be_bytes());
                }
                packet
            };
            for _ in 0..256 {
                l::send(
                    fd,
                    &response(1, id.wrapping_add(1), &nonce, 4096),
                    target,
                    0,
                )?;
                let mut wrong = nonce;
                wrong[15] ^= 1;
                l::send(fd, &response(1, id, &wrong, 4096), target, 0)?;
            }
            l::send(fd, &response(1, id, &nonce, 32), target, 0)?;
            std::thread::sleep(Duration::from_millis(250));
            let mut buffer = [0; 2048];
            let (n, from, arrived) = recv(fd, &mut buffer)?.context("matching reply missing")?;
            assert_eq!(from.ip(), target.ip());
            assert_eq!(reply(&buffer[..n], id, &nonce, ipv6), Some(1));
            window.received(1, clock.arrival(arrived)?);
            let stats = window.observe(Instant::now(), &log);
            assert_eq!(stats["received"], 1);
            assert_eq!(stats["lost"], 0);
            assert!(stats["rtt_avg_ms"].as_f64().unwrap() < 100.);
            assert!(
                log.read(&netcontrol_core::LogQuery::parse("")?)?["entries"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert!(recv(fd, &mut buffer)?.is_none());
            check_queue(fd)?;

            let sent = Instant::now();
            window.sent(2, sent);
            std::thread::sleep(Duration::from_millis(150));
            l::send(fd, &response(2, id, &nonce, 32), target, 0)?;
            let (_, _, arrived) = recv(fd, &mut buffer)?.context("late reply missing")?;
            window.received(2, clock.arrival(arrived)?);
            assert_eq!(window.observe(Instant::now(), &log)["lost"], 1);
            let page = log.read(&netcontrol_core::LogQuery::parse("")?)?;
            let entries = page["entries"].as_array().unwrap();
            assert_eq!(entries.len(), 1);
            let event: serde_json::Value =
                serde_json::from_str(entries[0]["message"].as_str().unwrap())?;
            assert_eq!(event["event"], "gateway_probe_loss");
            assert_eq!(event["details"]["first_sequence"], "2");

            let sent = Instant::now();
            window.sent(3, sent);
            l::send(fd, &echo(3, id, &nonce, ipv6), target, 0)?;
            let (n, from, arrived) = loop {
                if let Some(packet) = recv(fd, &mut buffer)? {
                    break packet;
                }
                ensure!(
                    sent.elapsed() < Duration::from_secs(1),
                    "kernel echo reply missing"
                );
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(from.ip(), target.ip());
            assert_eq!(reply(&buffer[..n], id, &nonce, ipv6), Some(3));
            window.received(3, clock.arrival(arrived)?);
            let stats = window.sample(Instant::now());
            assert_eq!(stats["received"], 2);
            assert_eq!(stats["lost"], 1);
            check_queue(fd)?;
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux CAP_NET_RAW and IPv4 loopback"]
    fn local_receive_overflow_is_explicit_without_a_subsequent_reply() -> Result<()> {
        let fd = l::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)?;
        let fd = fd.as_raw_fd();
        let id = rand::random();
        let nonce = rand::random();
        configure(fd, id, &nonce, false)?;
        l::option(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &4096i32)?;
        check_queue(fd)?;
        let mut packet = echo(1, id, &nonce, false);
        packet[0] = 0;
        packet[2..4].fill(0);
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
        for _ in 0..256 {
            l::send(fd, &packet, "127.0.0.1:0".parse()?, 0)?;
        }
        let error = check_queue(fd).expect_err("receive overflow must not become network loss");
        assert!(error.to_string().contains("local receive queue overflow"));
        Ok(())
    }
}
