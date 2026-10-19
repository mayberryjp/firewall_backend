use anyhow::{Context, Result, ensure};
#[cfg(any(test, target_os = "linux"))]
use std::io::Read;
#[cfg(any(test, all(target_os = "linux", feature = "tls")))]
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
    fn connect(destination: &super::config::Destination) -> Result<Self> {
        let addresses = super::resolve::resolve(&destination.host, destination.port)?;
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
pub(crate) fn prepare(
    config: super::config::Syslog,
    directory: std::path::PathBuf,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    use std::{
        fs::OpenOptions,
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixDatagram,
        },
    };
    let mut remotes = Vec::new();
    for server in config.servers {
        remotes.push(Remote::connect(&server)?);
    }
    // Do not steal a socket or silently omit whole-host logging.
    ensure!(
        !std::path::Path::new("/dev/log").try_exists()?,
        "host /dev/log already owned; stop conflicting logger explicitly"
    );
    let socket = UnixDatagram::bind("/dev/log").context("own host /dev/log")?;
    socket.set_nonblocking(true)?;
    let metadata = std::fs::symlink_metadata("/dev/log")?;
    struct Ownership {
        device: u64,
        inode: u64,
    }
    impl Drop for Ownership {
        fn drop(&mut self) {
            if let Ok(m) = std::fs::symlink_metadata("/dev/log") {
                if m.dev() == self.device && m.ino() == self.inode {
                    let _ = std::fs::remove_file("/dev/log");
                }
            }
        }
    }
    let ownership = Ownership {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    std::fs::set_permissions("/dev/log", std::fs::Permissions::from_mode(0o666))?;
    let mut kernel = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/kmsg")
        .context("own kernel log reader (/dev/kmsg required)")?;
    let backend_path = directory.join("backend.log");
    let mut create = OpenOptions::new();
    create
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    ensure!(
        create.open(&backend_path)?.metadata()?.is_file(),
        "backend source must be regular file"
    );
    let backend = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(&backend_path)?;
    ensure!(
        backend.metadata()?.is_file(),
        "backend log must be regular file"
    );
    let mut backend = backend;
    use std::io::{Seek, SeekFrom};
    backend.seek(SeekFrom::End(0))?;
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
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")?
        .trim()
        .to_owned();
    Ok(Box::new(move |ctx| {
        let _ownership = ownership;
        let mut buffer = vec![0; 65536];
        let mut lines = Vec::new();
        let forwarded = std::cell::Cell::new(0u64);
        let mut forward = |bytes: &[u8], app: &str| -> Result<()> {
            let record = message(bytes, &hostname, app, &super::worker::now());
            ensure!(record.len() <= 65000, "syslog record too large");
            local.write_all(&record)?;
            local.write_all(b"\n")?;
            for remote in &mut remotes {
                remote.forward(&record, &ctx)?;
            }
            forwarded.set(forwarded.get() + 1);
            Ok(())
        };
        while !ctx.stopping() {
            let m = std::fs::symlink_metadata("/dev/log")?;
            ensure!(
                m.dev() == _ownership.device && m.ino() == _ownership.inode,
                "host logging socket ownership lost"
            );
            for _ in 0..64 {
                match socket.recv(&mut buffer) {
                    Ok(n) => {
                        ensure!(n < buffer.len(), "oversize host syslog datagram");
                        forward(&buffer[..n], "host")?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            for _ in 0..64 {
                match kernel.read(&mut buffer) {
                    Ok(0) => anyhow::bail!("kernel logging source closed"),
                    Ok(n) => forward(&buffer[..n], "kernel")?,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e).context("kernel logging source failed"),
                }
            }
            let disk = std::fs::metadata(&backend_path)?;
            let open = backend.metadata()?;
            if disk.dev() != open.dev() || disk.ino() != open.ino() {
                backend = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                    .open(&backend_path)?;
                ensure!(
                    backend.metadata()?.is_file(),
                    "rotated backend source is not regular"
                );
                lines.clear();
            }
            ensure!(
                backend.stream_position()? <= backend.metadata()?.len(),
                "backend log truncated; source history loss"
            );
            let n = backend.read(&mut buffer)?;
            lines.extend_from_slice(&buffer[..n]);
            while let Some(end) = lines.iter().position(|b| *b == b'\n') {
                let record: Vec<_> = lines.drain(..=end).collect();
                forward(&record, "netcontrold")?;
            }
            ensure!(lines.len() <= 64000, "backend log line exceeds bound");
            ctx.update(|s| s["forwarded_records"] = serde_json::json!(forwarded.get()));
            ctx.wait(Duration::from_millis(20));
        }
        local.sync_data()?;
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
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
        let mut remote = Remote::connect(&destination).unwrap();
        let bytes = message(b"synthetic", "test", "backend", "-");
        remote.forward(&bytes, &ctx()).unwrap();
        let mut buffer = [0; 1024];
        let n = udp.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], &bytes);
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let mut remote = Remote::connect(&super::super::config::Destination {
            host: "127.0.0.1".into(),
            port,
            transport: "tcp".into(),
        })
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
