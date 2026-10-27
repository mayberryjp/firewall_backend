use anyhow::{Context, Result, ensure};
#[cfg(test)]
use std::io::Read;
#[cfg(any(test, target_os = "linux"))]
use std::sync::Arc;
use std::{
    io::Write,
    net::{TcpStream, UdpSocket},
    time::{Duration, Instant},
};
pub(crate) fn message(input: &[u8], hostname: &str, app: &str, timestamp: &str) -> Vec<u8> {
    let mut pri = 14u16;
    let mut body = input;
    if input.first() == Some(&b'<') {
        if let Some(end) = input.iter().take(6).position(|b| *b == b'>') {
            if let Ok(n) = std::str::from_utf8(&input[1..end])
                .unwrap_or("")
                .parse::<u16>()
            {
                if n <= 191 {
                    pri = n;
                    body = &input[end + 1..];
                }
            }
        }
    }
    let host: String = hostname
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(255)
        .collect();
    let host = if host.is_empty() { "-" } else { &host };
    let body = String::from_utf8_lossy(body);
    let body = body
        .trim_end_matches(['\n', '\r'])
        .replace('\0', "\\0")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("<{pri}>1 {timestamp} {host} {app} - - - {body}").into_bytes()
}
pub(crate) fn frame(message: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{} ", message.len()).into_bytes();
    bytes.extend_from_slice(message);
    bytes
}
enum Remote {
    Udp(UdpSocket),
    Tcp(TcpStream),
    #[cfg(all(target_os = "linux", feature = "tls"))]
    Tls(Box<rustls::ClientConnection>, TcpStream),
}
struct DestinationState {
    destination: super::config::Destination,
    remote: Option<Remote>,
    retry_at: Instant,
    delay: Duration,
    error: Option<String>,
}
impl DestinationState {
    fn failed(&mut self, error: anyhow::Error) {
        self.remote = None;
        self.error = Some(format!("{error:#}"));
        self.retry_at = Instant::now() + self.delay;
        self.delay = (self.delay * 2).min(Duration::from_secs(30));
    }
    fn reconnect(&mut self, ipv6_enabled: bool) {
        if self.remote.is_none() && Instant::now() >= self.retry_at {
            match Remote::connect(&self.destination, ipv6_enabled) {
                Ok(remote) => {
                    self.remote = Some(remote);
                    self.error = None;
                }
                Err(error) => self.failed(error),
            }
        }
    }
    fn forward(&mut self, bytes: &[u8], ctx: &super::worker::ContextState) -> bool {
        if let Some(remote) = &mut self.remote {
            match remote.forward(bytes, ctx) {
                Ok(()) => {
                    self.delay = Duration::from_secs(1);
                    return true;
                }
                Err(error) => self.failed(error),
            }
        }
        false
    }
}
fn write_bounded(
    stream: &mut TcpStream,
    mut data: &[u8],
    ctx: &super::worker::ContextState,
) -> Result<()> {
    let start = Instant::now();
    while !data.is_empty() {
        ensure!(!ctx.stopping(), "syslog forwarding interrupted by shutdown");
        ensure!(
            start.elapsed() < Duration::from_millis(500),
            "syslog TCP write timeout"
        );
        match stream.write(data) {
            Ok(n) => {
                ensure!(n > 0, "syslog TCP peer closed");
                data = &data[n..];
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                ctx.wait(Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
#[cfg(all(target_os = "linux", feature = "tls"))]
fn tls_io(
    connection: &mut rustls::ClientConnection,
    stream: &mut TcpStream,
    deadline: Duration,
    ctx: Option<&super::worker::ContextState>,
) -> Result<()> {
    let start = Instant::now();
    while connection.is_handshaking() || connection.wants_write() {
        ensure!(
            start.elapsed() < deadline && !ctx.is_some_and(|c| c.stopping()),
            "syslog TLS I/O timeout/stopped"
        );
        match connection.complete_io(stream) {
            Ok((read, written)) => ensure!(
                read + written > 0 || !connection.is_handshaking(),
                "TLS peer closed during handshake"
            ),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
impl Remote {
    fn connect(destination: &super::config::Destination, ipv6_enabled: bool) -> Result<Self> {
        let addresses = super::resolve::resolve(&destination.host, destination.port, ipv6_enabled)?;
        let address = addresses.first().context("no syslog destination address")?;
        if destination.transport == "udp" {
            let s = UdpSocket::bind(if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })?;
            s.connect(address)?;
            s.set_nonblocking(true)?;
            return Ok(Self::Udp(s));
        }
        let stream = TcpStream::connect_timeout(address, Duration::from_millis(500))?;
        stream.set_nonblocking(true)?;
        if destination.transport == "tcp" {
            return Ok(Self::Tcp(stream));
        }
        #[cfg(not(all(target_os = "linux", feature = "tls")))]
        {
            anyhow::bail!("native syslog TLS forwarding requires Linux and the tls feature");
        }
        #[cfg(all(target_os = "linux", feature = "tls"))]
        {
            let mut stream = stream;
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                roots.add(cert)?;
            }
            ensure!(
                !roots.is_empty(),
                "syslog TLS requires nonempty system CA trust store"
            );
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(destination.host.clone())
                .context("TLS hostname/IP")?;
            let mut connection = rustls::ClientConnection::new(Arc::new(config), name)?;
            connection.set_buffer_limit(Some(128 * 1024));
            tls_io(&mut connection, &mut stream, Duration::from_secs(3), None)?;
            Ok(Self::Tls(Box::new(connection), stream))
        }
    }
    fn forward(&mut self, bytes: &[u8], ctx: &super::worker::ContextState) -> Result<()> {
        ensure!(
            bytes.len() <= 65000,
            "syslog record exceeds 65000-byte bound"
        );
        match self {
            Self::Udp(s) => ensure!(s.send(bytes)? == bytes.len(), "short syslog UDP send"),
            Self::Tcp(s) => write_bounded(s, &frame(bytes), ctx)?,
            #[cfg(all(target_os = "linux", feature = "tls"))]
            Self::Tls(connection, stream) => {
                connection.writer().write_all(&frame(bytes))?;
                tls_io(connection, stream, Duration::from_millis(500), Some(ctx))?;
            }
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
pub(crate) const JOURNAL_SOCKET: &str = "/run/systemd/journal/syslog";

#[cfg(target_os = "linux")]
fn activation_matches(pid: Option<&str>, fds: Option<&str>, names: Option<&str>) -> Result<bool> {
    if pid.is_none() && fds.is_none() && names.is_none() {
        return Ok(false);
    }
    let pid: u32 = pid.context("systemd LISTEN_PID is missing")?.parse()?;
    if pid != std::process::id() {
        return Ok(false);
    }
    ensure!(
        fds == Some("1") && names == Some("netcontrol-syslog"),
        "expected exactly one systemd socket named netcontrol-syslog"
    );
    Ok(true)
}

#[cfg(target_os = "linux")]
pub(crate) struct JournalSocket {
    socket: std::os::unix::net::UnixDatagram,
    path: std::path::PathBuf,
    identity: (u64, u64),
}

#[cfg(target_os = "linux")]
impl JournalSocket {
    pub(crate) fn activated() -> Result<Option<Arc<Self>>> {
        fn variable(name: &str) -> Result<Option<String>> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(error) => Err(error).with_context(|| format!("read {name}")),
            }
        }
        let pid = variable("LISTEN_PID")?;
        let fds = variable("LISTEN_FDS")?;
        let names = variable("LISTEN_FDNAMES")?;
        if !activation_matches(pid.as_deref(), fds.as_deref(), names.as_deref())? {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self::from_fd(
            3,
            std::path::Path::new(JOURNAL_SOCKET),
        )?)))
    }

    fn from_fd(fd: std::os::fd::RawFd, path: &std::path::Path) -> Result<Self> {
        use std::os::{fd::FromRawFd, unix::fs::MetadataExt};
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        ensure!(
            flags >= 0,
            "invalid systemd syslog descriptor: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
            "protect inherited syslog descriptor: {}",
            std::io::Error::last_os_error()
        );
        // Keep the inherited descriptor alive across service worker restarts.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(
            duplicate >= 0,
            "duplicate systemd syslog descriptor: {}",
            std::io::Error::last_os_error()
        );
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) };
        let socket = std::os::unix::net::UnixDatagram::from(owned);
        let mut kind: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut kind as *mut libc::c_int).cast(),
                    &mut length,
                )
            } == 0
                && kind == libc::SOCK_DGRAM,
            "systemd syslog descriptor must be a datagram socket"
        );
        ensure!(
            socket.local_addr()?.as_pathname() == Some(path),
            "systemd syslog socket must be bound to {}",
            path.display()
        );
        socket.set_nonblocking(true)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let value = Self {
            socket,
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        };
        value.check_path()?;
        Ok(value)
    }

    pub(crate) fn check_path(&self) -> Result<()> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = std::fs::symlink_metadata(&self.path)
            .context("systemd syslog socket path unavailable")?;
        ensure!(
            metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity,
            "systemd syslog socket path replaced"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    config: super::config::Syslog,
    directory: std::path::PathBuf,
    socket: Arc<JournalSocket>,
    ipv6_enabled: bool,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
    socket.check_path()?;
    let mut remotes: Vec<_> = config
        .servers
        .into_iter()
        .map(|destination| DestinationState {
            destination,
            remote: None,
            retry_at: Instant::now(),
            delay: Duration::from_secs(1),
            error: None,
        })
        .collect();
    let mut local = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(directory.join("syslog-host.log"))?;
    ensure!(
        local.metadata()?.is_file(),
        "local syslog destination must be regular file"
    );
    let mut hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")?
        .trim()
        .to_owned();
    Ok(Box::new(move |ctx| {
        let mut buffer = vec![0; 65536];
        let mut forwarded = 0u64;
        let mut captured = 0u64;
        let mut failed_deliveries = 0u64;
        let mut hostname_read = Instant::now();
        while !ctx.stopping() {
            socket.check_path()?;
            for remote in &mut remotes {
                if ctx.stopping() {
                    break;
                }
                remote.reconnect(ipv6_enabled);
            }
            // The appliance hostname is configurable at runtime; keep the last good value on a failed read.
            if hostname_read.elapsed() >= Duration::from_secs(1) {
                hostname_read = Instant::now();
                if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
                    hostname = name.trim().to_owned();
                }
            }
            for _ in 0..64 {
                match socket.socket.recv(&mut buffer) {
                    Ok(n) => {
                        ensure!(n < buffer.len(), "oversize journald syslog datagram");
                        let record =
                            message(&buffer[..n], &hostname, "journald", &super::worker::now());
                        ensure!(record.len() <= 65000, "syslog record too large");
                        local.write_all(&record)?;
                        local.write_all(b"\n")?;
                        captured = captured.saturating_add(1);
                        let mut delivered = true;
                        for remote in &mut remotes {
                            if !remote.forward(&record, &ctx) {
                                delivered = false;
                                failed_deliveries = failed_deliveries.saturating_add(1);
                            }
                        }
                        if delivered {
                            forwarded = forwarded.saturating_add(1);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e).context("journald syslog receive failed"),
                }
            }
            ctx.update(|s| {
                s["forwarded_records"] = serde_json::json!(forwarded);
                s["captured_records"] = serde_json::json!(captured);
                s["failed_deliveries"] = serde_json::json!(failed_deliveries);
                let errors: Vec<_> = remotes
                    .iter()
                    .filter_map(|remote| {
                        remote.error.as_ref().map(|error| {
                            format!(
                                "{}:{}: {error}",
                                remote.destination.host, remote.destination.port
                            )
                        })
                    })
                    .collect();
                s["destination_errors"] = serde_json::json!(errors);
                if errors.is_empty() {
                    s.as_object_mut().unwrap().remove("error");
                } else {
                    s["error"] = serde_json::json!(errors.join("; "));
                }
            });
            ctx.wait(Duration::from_millis(20));
        }
        local.sync_data()?;
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn activation_requires_current_pid_and_exact_named_descriptor() {
        let pid = std::process::id().to_string();
        assert!(!activation_matches(None, None, None).unwrap());
        assert!(!activation_matches(Some("0"), Some("1"), Some("netcontrol-syslog")).unwrap());
        assert!(activation_matches(Some(&pid), Some("1"), Some("netcontrol-syslog")).unwrap());
        for (process, fds, names) in [
            (None, Some("1"), Some("netcontrol-syslog")),
            (Some("invalid"), Some("1"), Some("netcontrol-syslog")),
            (Some(pid.as_str()), None, Some("netcontrol-syslog")),
            (
                Some(pid.as_str()),
                Some("2"),
                Some("netcontrol-syslog:other"),
            ),
            (Some(pid.as_str()), Some("1"), Some("syslog")),
        ] {
            assert!(activation_matches(process, fds, names).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inherited_socket_validation_lifecycle_and_no_duplicate_sources() {
        use std::os::{
            fd::AsRawFd,
            unix::net::{UnixDatagram, UnixListener},
        };
        let directory = std::env::temp_dir().join(format!("nc-journal-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("syslog");
        let inherited = UnixDatagram::bind(&path).unwrap();
        let socket = Arc::new(JournalSocket::from_fd(inherited.as_raw_fd(), &path).unwrap());
        assert!(JournalSocket::from_fd(inherited.as_raw_fd(), &directory.join("wrong")).is_err());
        let stream_path = directory.join("stream");
        let stream = UnixListener::bind(&stream_path).unwrap();
        assert!(JournalSocket::from_fd(stream.as_raw_fd(), &stream_path).is_err());
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(JournalSocket::from_fd(file.as_raw_fd(), &path).is_err());
        let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
        collector
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let config = super::super::config::Syslog {
            enabled: true,
            servers: vec![super::super::config::Destination {
                host: "127.0.0.1".into(),
                port: collector.local_addr().unwrap().port(),
                transport: "udp".into(),
            }],
        };
        let sender = UnixDatagram::unbound().unwrap();
        for attempt in 0..2 {
            let mut worker = super::super::worker::Worker::start(
                "journal-test".into(),
                None,
                serde_json::json!({}),
                {
                    let directory = directory.clone();
                    let socket = socket.clone();
                    let config = config.clone();
                    move || prepare(config.clone(), directory.clone(), socket.clone(), true)
                },
            )
            .unwrap();
            std::fs::write(directory.join("backend.log"), b"must not be tailed\n").unwrap();
            let input = format!("<30>Oct 25 15:00:00 appliance app: synthetic-{attempt}");
            sender.send_to(input.as_bytes(), &path).unwrap();
            let mut buffer = [0; 4096];
            let n = collector.recv(&mut buffer).unwrap();
            let record = String::from_utf8_lossy(&buffer[..n]);
            assert!(record.starts_with("<30>1 "));
            assert!(record.contains(" journald - - - Oct 25"));
            assert!(record.contains(&format!("synthetic-{attempt}")));
            assert!(
                collector.recv(&mut buffer).is_err(),
                "duplicate/direct backend source forwarded"
            );
            worker.shutdown().unwrap();
            assert_eq!(worker.snapshot()["state"], "stopped");
            assert_eq!(worker.snapshot()["forwarded_records"], 1);
            assert!(path.exists(), "worker must not unlink systemd's socket");
        }
        let mut services = super::super::Services::new(super::super::ServiceOptions {
            namespace: None,
            state_directory: directory.clone(),
            allow_host_services: true,
            allow_gateway_monitoring: false,
        })
        .unwrap();
        services.syslog_socket = Some(socket.clone());
        let enabled = serde_json::json!({"syslog":{"enabled":true,"servers":[{
            "host":"127.0.0.1","port":collector.local_addr().unwrap().port(),"transport":"udp"
        }]}});
        services.apply(&serde_json::json!({}), &enabled).unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = closed.local_addr().unwrap().port();
        drop(closed);
        let failing = serde_json::json!({"syslog":{"enabled":true,"servers":[{
            "host":"127.0.0.1","port":unused_port,"transport":"tcp"
        }]}});
        services.apply(&enabled, &failing).unwrap();
        assert_eq!(services.workers["syslog"].snapshot()["state"], "running");
        services.verify(&failing).unwrap();
        sender
            .send_to(b"<30>captured during collector outage", &path)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while services.workers["syslog"].snapshot()["captured_records"] != 1 {
            assert!(
                Instant::now() < deadline,
                "local capture stopped during remote outage"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            services.workers["syslog"].snapshot()["failed_deliveries"],
            1
        );
        assert!(
            std::fs::read_to_string(directory.join("syslog-host.log"))
                .unwrap()
                .contains("captured during collector outage")
        );
        let recovered_collector = std::net::TcpListener::bind(("127.0.0.1", unused_port)).unwrap();
        recovered_collector.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut connection, _) = loop {
            match recovered_collector.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "collector did not reconnect");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        connection
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        sender
            .send_to(b"<30>collector recovered automatically", &path)
            .unwrap();
        let mut recovered = [0; 4096];
        let count = connection.read(&mut recovered).unwrap();
        assert!(
            String::from_utf8_lossy(&recovered[..count])
                .contains("collector recovered automatically")
        );
        services.repair(&enabled).unwrap();
        sender
            .send_to(b"<30>restored after rollback and repair", &path)
            .unwrap();
        let mut buffer = [0; 4096];
        let n = collector.recv(&mut buffer).unwrap();
        assert!(
            String::from_utf8_lossy(&buffer[..n]).contains("restored after rollback and repair")
        );
        services.shutdown().unwrap();
        assert!(path.exists());
        drop(services);
        let mut lost_source = super::super::worker::Worker::start(
            "journal-path-loss".into(),
            None,
            serde_json::json!({}),
            {
                let socket = socket.clone();
                let config = config.clone();
                let directory = directory.clone();
                move || prepare(config.clone(), directory.clone(), socket.clone(), true)
            },
        )
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        let _replacement = UnixDatagram::bind(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while lost_source.snapshot()["state"] == "running" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(lost_source.snapshot()["state"], "error");
        assert!(
            lost_source.snapshot()["error"]
                .as_str()
                .unwrap()
                .contains("systemd syslog socket path")
        );
        lost_source.shutdown().unwrap();
        assert!(
            socket.check_path().is_err(),
            "socket replacement must be detected"
        );
        assert!(prepare(config, directory.clone(), socket, true).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rfc5424_framing_and_injection() {
        let m = message(
            b"<30>hello\nworld\0",
            "host name",
            "netcontrold",
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(
            String::from_utf8(m.clone()).unwrap(),
            "<30>1 2026-01-01T00:00:00Z hostname netcontrold - - - hello\\nworld\\0"
        );
        let framed = frame(&m);
        assert!(framed.ends_with(&m));
        assert!(framed.starts_with(format!("{} ", m.len()).as_bytes()));
        assert!(
            String::from_utf8(message(b"<999>body", "x", "host", "-"))
                .unwrap()
                .starts_with("<14>1 ")
        );
    }
    fn ctx() -> super::super::worker::ContextState {
        super::super::worker::ContextState {
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            status: Arc::new(std::sync::Mutex::new(serde_json::json!({}))),
        }
    }
    #[test]
    fn native_udp_and_octet_counted_tcp_forwarding() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let destination = super::super::config::Destination {
            host: "127.0.0.1".into(),
            port: udp.local_addr().unwrap().port(),
            transport: "udp".into(),
        };
        let mut remote = Remote::connect(&destination, true).unwrap();
        let bytes = message(b"synthetic", "test", "backend", "-");
        remote.forward(&bytes, &ctx()).unwrap();
        let mut buffer = [0; 1024];
        let n = udp.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], &bytes);
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let mut remote = Remote::connect(
            &super::super::config::Destination {
                host: "127.0.0.1".into(),
                port,
                transport: "tcp".into(),
            },
            true,
        )
        .unwrap();
        let (mut server, _) = tcp.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        remote.forward(&bytes, &ctx()).unwrap();
        let expected = frame(&bytes);
        let mut got = vec![0; expected.len()];
        server.read_exact(&mut got).unwrap();
        assert_eq!(got, expected);
    }
}
