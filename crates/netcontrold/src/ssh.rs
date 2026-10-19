//! In-process, API-key-only SSH transport for the configuration CLI.
use crate::{
    cli::{CliSession, CommandResult},
    http::App,
};
use anyhow::{Context, Result, bail};
use rand::RngCore;
use russh::{
    Channel, ChannelId, Disconnect, MethodKind, Pty,
    keys::{
        Algorithm, PrivateKey,
        ssh_key::{
            LineEnding,
            private::{Ed25519Keypair, KeypairData},
        },
    },
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Shutdown,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use zeroize::Zeroizing;

const MAX_LINE: usize = 64 * 1024;
const MAX_KEY: u64 = 16 * 1024;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SESSION_TIMEOUT: Duration = Duration::from_secs(1800);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const BANNER: &str = "Netcontrol configuration CLI\r\nAPI-key permissions apply to every command. Type ? for help.\r\n";
const _: () = assert!(log::STATIC_MAX_LEVEL as usize <= log::LevelFilter::Info as usize);

fn check_key_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_KEY {
        bail!("SSH host key must be a regular file no larger than 16 KiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!("SSH host key must be daemon-owned, owner-only, and have one link");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("SSH host key must not be a reparse point");
        }
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct Information {
            attributes: u32,
            creation: [u32; 2],
            access: [u32; 2],
            write: [u32; 2],
            volume: u32,
            size_high: u32,
            size_low: u32,
            links: u32,
            index_high: u32,
            index_low: u32,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetFileInformationByHandle(
                handle: *mut std::ffi::c_void,
                info: *mut Information,
            ) -> i32;
        }
        let mut information = std::mem::MaybeUninit::<Information>::uninit();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { information.assume_init() }.links != 1 {
            bail!("SSH host key must have one link");
        }
    }
    Ok(())
}

fn open_key(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("SSH host key must be a regular file, not a symlink");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
        options.share_mode(1);
    }
    let file = options.open(path)?;
    check_key_file(&file)?;
    Ok(file)
}

/// Load or exclusively create an unencrypted OpenSSH Ed25519 host key.
/// Existing invalid keys are never replaced. The parent directory must already exist.
pub fn load_host_key(path: &Path) -> Result<PrivateKey> {
    crate::identity::secure_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *seed);
            let key = PrivateKey::new(
                KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)),
                "netcontrol",
            )?;
            let encoded = key.to_openssh(LineEnding::LF)?;
            let mut options = OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            match options.open(path) {
                Ok(mut file) => {
                    check_key_file(&file)?;
                    file.write_all(encoded.as_bytes())?;
                    file.sync_all()?;
                    #[cfg(unix)]
                    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    let mut encoded = Zeroizing::new(Vec::new());
    open_key(path)?
        .take(MAX_KEY + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_KEY as usize {
        bail!("SSH host key exceeds size limit");
    }
    let key = PrivateKey::from_openssh(&*encoded)
        .context("invalid SSH host key; refusing replacement")?;
    if key.algorithm() != Algorithm::Ed25519 || key.is_encrypted() {
        bail!("SSH host key must be an unencrypted OpenSSH Ed25519 key");
    }
    Ok(key)
}

struct Rate {
    since: Instant,
    count: usize,
}
impl Rate {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            count: 0,
        }
    }
    fn allow(&mut self, limit: usize) -> bool {
        if self.since.elapsed() >= Duration::from_secs(60) {
            *self = Self::new();
        }
        self.count += 1;
        self.count <= limit
    }
}

struct SocketGuard(std::net::TcpStream);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

/// Serve only the supplied listener; SSH is never enabled or bound implicitly.
pub async fn serve(
    listener: TcpListener,
    host_key_path: &Path,
    app: Arc<App>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let key = load_host_key(host_key_path)?;
    tracing::info!(
        host_key_fingerprint = %key.public_key().fingerprint(russh::keys::HashAlg::Sha256),
        "SSH Ed25519 host key ready"
    );
    let config = Arc::new(server::Config {
        methods: (&[MethodKind::Password][..]).into(),
        keys: vec![key],
        max_auth_attempts: 3,
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(1)),
        inactivity_timeout: Some(IDLE_TIMEOUT),
        maximum_packet_size: 32 * 1024,
        window_size: 64 * 1024,
        event_buffer_size: 16,
        channel_buffer_size: 8,
        ..Default::default()
    });
    let auth_rate = Arc::new(Mutex::new(Rate::new()));
    let mut accept_rate = Rate::new();
    let mut connections = JoinSet::new();
    let (connection_stop, connection_shutdown) = watch::channel(false);
    let mut failure = None;
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(_)) = result {
                    tracing::warn!("SSH connection task failed");
                }
            }
            accepted = listener.accept() => {
                let (socket, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::error!("SSH listener failed");
                        failure = Some(anyhow::Error::from(error).context("accept SSH connection"));
                        break;
                    }
                };
                if connections.len() >= MAX_CONNECTIONS || !accept_rate.allow(60) {
                    tracing::warn!("SSH connection capacity or rate limit reached");
                    continue;
                }
                let prepare = || -> std::io::Result<_> {
                    socket.set_nodelay(true)?;
                    let socket = socket.into_std()?;
                    let guard = SocketGuard(socket.try_clone()?);
                    Ok((tokio::net::TcpStream::from_std(socket)?, guard))
                };
                let (socket, guard) = match prepare() {
                    Ok(connection) => connection,
                    Err(_) => {
                        tracing::warn!("SSH socket preparation failed");
                        continue;
                    }
                };
                let config = config.clone();
                let handler = Handler::new(app.clone(), auth_rate.clone());
                let authenticated = handler.authenticated.clone();
                let mut shutdown = connection_shutdown.clone();
                connections.spawn(async move {
                    let guard = guard;
                    let running = tokio::select! {
                        _ = shutdown.changed() => return,
                        result = tokio::time::timeout(HANDSHAKE_TIMEOUT, server::run_stream(config, socket, handler)) => {
                            match result {
                                Ok(Ok(running)) => running,
                                _ => {
                                    tracing::warn!("SSH handshake failed or timed out");
                                    return;
                                }
                            }
                        }
                    };
                    let handle = running.handle();
                    tokio::pin!(running);
                    tokio::select! {
                        result = &mut running => {
                            if result.is_err() {
                                tracing::warn!("SSH session ended with a protocol or transport error");
                            }
                            return;
                        }
                        _ = shutdown.changed() => {}
                        _ = tokio::time::sleep(SESSION_TIMEOUT) => {}
                        _ = async {
                            tokio::time::sleep(HANDSHAKE_TIMEOUT).await;
                            if authenticated.load(std::sync::atomic::Ordering::Acquire) {
                                std::future::pending::<()>().await;
                            }
                        } => {
                            tracing::warn!("SSH authentication timed out");
                        }
                    }
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        handle.disconnect(Disconnect::ByApplication, "SSH service closing".into(), String::new()),
                    ).await;
                    if tokio::time::timeout(Duration::from_secs(1), &mut running).await.is_ok() {
                        return;
                    }
                    drop(guard);
                    if tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut running).await.is_err() {
                        tracing::error!("SSH session did not finish within shutdown deadline");
                    }
                });
            }
        }
    }
    drop(listener);
    let _ = connection_stop.send(true);
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            tracing::warn!("SSH connection task failed during shutdown");
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

struct Handler {
    app: Arc<App>,
    auth_rate: Arc<Mutex<Rate>>,
    key: Option<Zeroizing<String>>,
    cli: Option<CliSession>,
    channel: Option<ChannelId>,
    pty: bool,
    shell: bool,
    started: bool,
    line: Vec<u8>,
    invalid: bool,
    after_cr: bool,
    authenticated: Arc<std::sync::atomic::AtomicBool>,
}
impl Handler {
    fn new(app: Arc<App>, auth_rate: Arc<Mutex<Rate>>) -> Self {
        Self {
            app,
            auth_rate,
            key: None,
            cli: Some(CliSession::new()),
            channel: None,
            pty: false,
            shell: false,
            started: false,
            line: Vec::new(),
            invalid: false,
            after_cr: false,
            authenticated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    fn render(output: &str) -> Option<Vec<u8>> {
        if output.len() > MAX_OUTPUT {
            return None;
        }
        let mut safe = String::new();
        for c in output.chars() {
            if c == '\n' {
                safe.push_str("\r\n");
            } else if c == '\r' {
                // Normalize line endings and never emit terminal escape sequences.
            } else if !c.is_control() {
                safe.push(c);
            }
            if safe.len() > MAX_OUTPUT {
                return None;
            }
        }
        Some(safe.into_bytes())
    }
    fn send(session: &mut Session, channel: ChannelId, output: &str) -> Result<()> {
        let safe = Self::render(output).context("SSH output exceeds 4 MiB")?;
        session.data(channel, safe)?;
        Ok(())
    }
    fn finish(session: &mut Session, channel: ChannelId, failed: bool) -> Result<()> {
        session.exit_status_request(channel, u32::from(failed))?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
    async fn command(
        &mut self,
        line: String,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool> {
        let key = self.key.as_ref().context("unauthenticated SSH command")?;
        let app = self.app.clone();
        let key = Zeroizing::new(key.to_string());
        let mut cli = self.cli.take().context("SSH command already running")?;
        let outcome = tokio::task::spawn_blocking(move || match app.authenticate_api_key(&key) {
            Ok(Some(principal)) => {
                let result = cli.execute(&app, &principal, &line);
                (cli, Some(result))
            }
            _ => (cli, None),
        })
        .await
        .context("SSH command worker failed")?;
        self.cli = Some(outcome.0);
        let Some(CommandResult {
            output,
            failed,
            exit,
        }) = outcome.1
        else {
            tracing::warn!("SSH API-key authorization no longer valid");
            Self::send(session, channel, "% API key revoked or unavailable\n")?;
            Self::finish(session, channel, true)?;
            session.disconnect(Disconnect::ByApplication, "API key no longer valid", "")?;
            self.key = None;
            return Ok(true);
        };
        let failed = match Self::render(&output) {
            Some(rendered) => {
                session.data(channel, rendered)?;
                if !output.is_empty() && !output.ends_with('\n') {
                    Self::send(session, channel, "\n")?;
                }
                failed
            }
            None => {
                Self::send(
                    session,
                    channel,
                    "% Output exceeds the 4 MiB SSH limit; no command output was sent. The command may already have completed or applied changes; inspect state and transactions before retrying. Use narrower show commands or the HTTP API.\n",
                )?;
                true
            }
        };
        if exit || !self.shell {
            Self::finish(session, channel, failed)?;
            return Ok(true);
        }
        Self::send(session, channel, self.cli.as_ref().unwrap().prompt())?;
        Ok(false)
    }
}

impl server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth> {
        let allowed = self
            .auth_rate
            .lock()
            .map(|mut rate| rate.allow(30))
            .unwrap_or(false);
        if user != "apikey" || password.is_empty() || password.len() > 4096 || !allowed {
            return Ok(Auth::reject());
        }
        let app = self.app.clone();
        let key = Zeroizing::new(password.to_owned());
        let result = tokio::task::spawn_blocking(move || {
            let valid = matches!(app.authenticate_api_key(&key), Ok(Some(_)));
            (key, valid)
        })
        .await?;
        if !result.1 {
            tracing::warn!("SSH API-key authentication rejected");
            return Ok(Auth::reject());
        }
        self.key = Some(result.0);
        self.authenticated
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        if self.key.is_some() && self.channel.is_none() {
            self.channel = Some(channel.id());
            reply.accept().await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        if self.channel == Some(channel) && !self.started && !self.pty {
            self.pty = true;
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        if self.channel != Some(channel) || !self.pty || self.started {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.started = true;
        self.shell = true;
        session.channel_success(channel)?;
        Self::send(session, channel, BANNER)?;
        Self::send(session, channel, self.cli.as_ref().unwrap().prompt())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        if self.channel != Some(channel) || self.started {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.started = true;
        let line = std::str::from_utf8(data).ok().filter(|line| {
            !line.trim().is_empty() && line.len() <= MAX_LINE && !line.chars().any(char::is_control)
        });
        let Some(line) = line else {
            session.channel_failure(channel)?;
            Self::send(
                session,
                channel,
                "% Exec requires exactly one UTF-8 CLI command without controls\n",
            )?;
            return Self::finish(session, channel, true);
        };
        session.channel_success(channel)?;
        self.command(line.to_owned(), channel, session).await?;
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<()> {
        if self.channel != Some(channel) || !self.shell {
            return Ok(());
        }
        let mut echo = Vec::with_capacity(data.len().min(32 * 1024));
        for &byte in data {
            if byte == b'\n' && self.after_cr {
                self.after_cr = false;
                continue;
            }
            self.after_cr = byte == b'\r';
            match byte {
                3 => {
                    if !echo.is_empty() {
                        session.data(channel, std::mem::take(&mut echo))?;
                    }
                    self.line.clear();
                    self.invalid = false;
                    Self::send(session, channel, "^C\n")?;
                    Self::send(session, channel, self.cli.as_ref().unwrap().prompt())?;
                }
                4 => {
                    if !echo.is_empty() {
                        session.data(channel, std::mem::take(&mut echo))?;
                    }
                    self.line.clear();
                    self.invalid = false;
                    self.cli = None;
                    self.shell = false;
                    Self::send(session, channel, "\n")?;
                    Self::finish(session, channel, false)?;
                    break;
                }
                b'\r' | b'\n' => {
                    if !echo.is_empty() {
                        session.data(channel, std::mem::take(&mut echo))?;
                    }
                    Self::send(session, channel, "\n")?;
                    let bytes = std::mem::take(&mut self.line);
                    let line = std::str::from_utf8(&bytes)
                        .ok()
                        .filter(|line| !line.chars().any(char::is_control));
                    if let Some(line) = line.filter(|_| !self.invalid) {
                        if self.command(line.to_owned(), channel, session).await? {
                            self.shell = false;
                            break;
                        }
                    } else {
                        self.invalid = false;
                        Self::send(
                            session,
                            channel,
                            "% Invalid input: use UTF-8 text, maximum 64 KiB, no controls or escape sequences\n",
                        )?;
                        Self::send(session, channel, self.cli.as_ref().unwrap().prompt())?;
                    }
                }
                8 | 127 if !self.invalid => {
                    if self.line.pop().is_some() {
                        while self.line.last().is_some_and(|b| b & 0xc0 == 0x80) {
                            self.line.pop();
                        }
                        if self.line.last().is_some_and(|b| b & 0xc0 == 0xc0) {
                            self.line.pop();
                        }
                        echo.extend_from_slice(b"\x08 \x08");
                    }
                }
                0..=31 | 127 => self.invalid = true,
                _ if self.invalid => {}
                _ if self.line.len() >= MAX_LINE => {
                    self.invalid = true;
                    self.line.clear();
                }
                _ => {
                    self.line.push(byte);
                    if byte.is_ascii() {
                        echo.push(byte);
                    }
                }
            }
            if echo.len() >= 32 * 1024 {
                session.data(channel, std::mem::take(&mut echo))?;
            }
        }
        if !echo.is_empty() {
            session.data(channel, echo)?;
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        if self.channel == Some(channel) {
            self.cli = None;
            self.shell = false;
            Self::finish(session, channel, self.invalid || !self.line.is_empty())?;
        }
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn agent_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<bool> {
        session.channel_failure(channel)?;
        // Russh 0.63's false branch emits an unrelated global REQUEST_FAILURE.
        // The channel request is already rejected; its true branch is a no-op
        // because no global reply is pending. Keep this tied to the pinned version.
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(channel)?;
        Ok(())
    }
}
