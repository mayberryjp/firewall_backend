use anyhow::{Context, Result, ensure};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct Watchdog {
    #[cfg(target_os = "linux")]
    socket: Option<(
        std::os::unix::net::UnixDatagram,
        std::os::unix::net::SocketAddr,
    )>,
    interval: Option<Duration>,
    last: Mutex<Instant>,
    ready: AtomicBool,
}

impl Watchdog {
    pub fn from_environment() -> Result<Self> {
        Self::configured(
            std::env::var("NOTIFY_SOCKET").ok().as_deref(),
            std::env::var("WATCHDOG_USEC").ok().as_deref(),
            std::env::var("WATCHDOG_PID").ok().as_deref(),
        )
    }

    fn configured(socket: Option<&str>, usec: Option<&str>, pid: Option<&str>) -> Result<Self> {
        let targeted = pid
            .map(|pid| pid.parse::<u32>())
            .transpose()
            .context("invalid WATCHDOG_PID")?
            .is_none_or(|pid| pid == std::process::id());
        let interval = if targeted {
            usec.map(|value| -> Result<Duration> {
                let timeout: u64 = value.parse().context("invalid WATCHDOG_USEC")?;
                ensure!(timeout > 0, "WATCHDOG_USEC must be positive");
                ensure!(socket.is_some(), "WATCHDOG_USEC requires NOTIFY_SOCKET");
                Ok(Duration::from_micros(timeout) / 2)
            })
            .transpose()?
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let socket = socket
            .map(|path| -> Result<_> {
                use std::os::{
                    linux::net::SocketAddrExt,
                    unix::net::{SocketAddr, UnixDatagram},
                };
                let address = if let Some(name) = path.strip_prefix('@') {
                    ensure!(!name.is_empty(), "NOTIFY_SOCKET abstract name is empty");
                    SocketAddr::from_abstract_name(name.as_bytes())?
                } else {
                    ensure!(
                        path.starts_with('/'),
                        "NOTIFY_SOCKET must be absolute or abstract"
                    );
                    SocketAddr::from_pathname(path)?
                };
                let socket = UnixDatagram::unbound()?;
                socket.set_nonblocking(true)?;
                Ok((socket, address))
            })
            .transpose()?;
        #[cfg(not(target_os = "linux"))]
        {
            ensure!(
                socket.is_none() && interval.is_none(),
                "systemd notifications require Linux"
            );
        }
        Ok(Self {
            #[cfg(target_os = "linux")]
            socket,
            interval,
            last: Mutex::new(Instant::now()),
            ready: AtomicBool::new(false),
        })
    }

    pub fn enabled(&self) -> bool {
        self.interval.is_some()
    }

    fn send(&self, message: &[u8]) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some((socket, address)) = &self.socket {
            ensure!(
                socket.send_to_addr(message, address)? == message.len(),
                "short systemd notification"
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = message;
        Ok(())
    }

    pub fn ready(&self) -> Result<()> {
        self.send(
            b"READY=1\nSTATUS=HTTP listener ready; service availability is reported separately",
        )?;
        *self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("watchdog clock unavailable"))? = Instant::now();
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    pub fn heartbeat(&self) -> Result<()> {
        if !self.ready.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(interval) = self.interval {
            let mut last = self
                .last
                .lock()
                .map_err(|_| anyhow::anyhow!("watchdog clock unavailable"))?;
            if last.elapsed() >= interval {
                self.send(b"WATCHDOG=1")?;
                *last = Instant::now();
            }
        }
        Ok(())
    }

    pub fn stopping(&self) -> Result<()> {
        self.ready.store(false, Ordering::Release);
        self.send(b"STOPPING=1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_is_optional_and_respects_the_target_pid() {
        assert!(!Watchdog::configured(None, None, None).unwrap().enabled());
        assert!(
            !Watchdog::configured(None, Some("1000"), Some("0"))
                .unwrap()
                .enabled()
        );
        assert!(Watchdog::configured(None, Some("1000"), None).is_err());
        assert!(Watchdog::configured(None, Some("invalid"), None).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn watchdog_notifies_only_after_ready_and_progress_then_stops() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let watchdog = Watchdog::configured(path.to_str(), Some("60000000"), None).unwrap();
        let mut buffer = [0; 256];
        watchdog.heartbeat().unwrap();
        assert!(receiver.recv(&mut buffer).is_err());
        watchdog.ready().unwrap();
        let count = receiver.recv(&mut buffer).unwrap();
        assert!(buffer[..count].starts_with(b"READY=1\n"));
        watchdog.heartbeat().unwrap();
        assert!(receiver.recv(&mut buffer).is_err());
        *watchdog.last.lock().unwrap() = Instant::now() - Duration::from_secs(31);
        watchdog.heartbeat().unwrap();
        let count = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"WATCHDOG=1");
        watchdog.stopping().unwrap();
        let count = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"STOPPING=1");
        *watchdog.last.lock().unwrap() = Instant::now() - Duration::from_secs(31);
        watchdog.heartbeat().unwrap();
        assert!(receiver.recv(&mut buffer).is_err());
    }
}
