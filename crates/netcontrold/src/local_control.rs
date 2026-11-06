//! Root-only local administration; never exposed over TCP.
pub const DEFAULT_SOCKET: &str = "/run/netcontrol/control.sock";

#[cfg(target_os = "linux")]
mod linux {
    use crate::http::{App, Authentication};
    use anyhow::{Context, Result, bail, ensure};
    use serde::{Deserialize, Serialize};
    use std::{
        fs,
        io::{BufRead, BufReader, IsTerminal, Write},
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::watch,
        task::JoinSet,
    };
    use zeroize::{Zeroize, Zeroizing};

    const MAX_FRAME: usize = 4096;
    const IO_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "operation", deny_unknown_fields)]
    enum Request {
        Status {},
        CreateKey {
            name: String,
            account: Option<AccountInput>,
        },
        ConfigureLan {
            name: String,
            parent: String,
            id: u16,
            address: String,
        },
        ConfirmNetworkChange {
            id: String,
        },
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AccountInput {
        username: String,
        password: String,
    }
    impl Drop for AccountInput {
        fn drop(&mut self) {
            self.password.zeroize();
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "result", deny_unknown_fields)]
    enum Response {
        Status { account_exists: bool },
        Created { api_key: String },
        NetworkChanged { transaction_id: String },
        NetworkConfirmed {},
        Error { message: String },
    }
    impl Drop for Response {
        fn drop(&mut self) {
            if let Self::Created { api_key } = self {
                api_key.zeroize();
            }
        }
    }

    fn root() -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "local administration requires root"
        );
        Ok(())
    }
    fn secure_directory(path: &Path) -> Result<()> {
        let parent = path.parent().context("control socket needs a directory")?;
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "control socket directory must be a root-owned, owner-only directory, not a symlink"
        );
        crate::identity::secure_parent(parent)?;
        Ok(())
    }
    fn socket_metadata(path: &Path) -> Result<fs::Metadata> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_socket() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "control socket must be root-owned and owner-only, not a symlink"
        );
        Ok(metadata)
    }

    pub struct Listener {
        listener: UnixListener,
        path: PathBuf,
        device: u64,
        inode: u64,
    }
    impl Listener {
        pub fn bind(path: &Path) -> Result<Self> {
            root()?;
            let parent = path.parent().context("control socket needs a directory")?;
            match fs::symlink_metadata(parent) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    crate::identity::secure_parent(parent)?;
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new().mode(0o700).create(parent)?;
                }
                Err(error) => return Err(error.into()),
            }
            secure_directory(path)?;
            match socket_metadata(path) {
                Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
                    Ok(_) => bail!("local control socket is already in use"),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        fs::remove_file(path)?;
                    }
                    Err(error) => return Err(error.into()),
                },
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error),
            }
            let listener = UnixListener::bind(path).context("bind local control socket")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            let metadata = socket_metadata(path)?;
            Ok(Self {
                listener,
                path: path.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        fn cleanup(&self) -> Result<()> {
            let metadata = socket_metadata(&self.path)?;
            ensure!(
                metadata.dev() == self.device && metadata.ino() == self.inode,
                "local control socket was replaced; refusing to remove it"
            );
            fs::remove_file(&self.path)?;
            Ok(())
        }
        pub async fn serve(self, app: Arc<App>, mut stop: watch::Receiver<bool>) -> Result<()> {
            let mut tasks = JoinSet::new();
            let result = async {
                loop {
                    if *stop.borrow() {
                        break;
                    }
                    tokio::select! {
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() { break; }
                        }
                        joined = tasks.join_next(), if !tasks.is_empty() => {
                            joined.context("missing local control task")?
                                .context("local control task failed")?;
                        }
                        accepted = self.listener.accept(), if tasks.len() < 8 => {
                            let (stream, _) = accepted.context("accept local control connection")?;
                            if stream.peer_cred()?.uid() != 0 {
                                tracing::warn!("rejected non-root local control peer");
                                continue;
                            }
                            let app = app.clone();
                            tasks.spawn(async move {
                                if let Err(error) = handle(stream, app).await {
                                    tracing::warn!(%error, "local control request failed");
                                }
                            });
                        }
                    }
                }
                // Finish accepted identity writes before engine/process shutdown.
                while let Some(joined) = tasks.join_next().await {
                    joined.context("local control task failed during shutdown")?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let cleanup = self.cleanup();
            result?;
            cleanup.context("remove local control socket")
        }
    }

    async fn read_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
        let length = stream.read_u32().await? as usize;
        ensure!(
            (1..=MAX_FRAME).contains(&length),
            "invalid local control frame length"
        );
        let mut bytes = Zeroizing::new(vec![0; length]);
        stream.read_exact(&mut bytes).await?;
        Ok(bytes)
    }
    async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        ensure!(
            bytes.len() <= MAX_FRAME,
            "local control response exceeds size limit"
        );
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        Ok(())
    }
    fn execute(app: &App, request: &Request) -> Result<Response> {
        let Authentication::Device(store) = &app.auth else {
            bail!("local control administration is unavailable with --auth-file");
        };
        match request {
            Request::ConfigureLan {
                name,
                parent,
                id,
                address,
            } => {
                let mut engine = app
                    .engine
                    .lock()
                    .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
                let transaction = crate::provision::configure_vlan_lan(
                    &mut engine,
                    &crate::provision::VlanLan {
                        name: name.clone(),
                        parent: parent.clone(),
                        id: *id,
                    },
                    address,
                )?;
                let transaction_id = transaction["id"]
                    .as_str()
                    .context("LAN transaction returned no ID")?
                    .to_owned();
                return Ok(Response::NetworkChanged { transaction_id });
            }
            Request::ConfirmNetworkChange { id } => {
                ensure!(
                    !id.is_empty()
                        && id.len() <= 80
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                    "invalid transaction ID"
                );
                let permissions = netcontrol_core::PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<Vec<_>>();
                let reply = app
                    .engine
                    .lock()
                    .map_err(|_| anyhow::anyhow!("engine unavailable"))?
                    .request(
                        "POST",
                        &format!("/api/v1/transactions/{id}/confirm"),
                        "",
                        "local-lan-setup",
                        &permissions,
                        &[],
                    );
                ensure!(
                    reply.status < 300,
                    "network confirmation failed ({}): {}",
                    reply.status,
                    reply.body
                );
                return Ok(Response::NetworkConfirmed {});
            }
            _ => {}
        }
        let mut store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("credential store unavailable"))?;
        store.check_health()?;
        match request {
            Request::Status {} => Ok(Response::Status {
                account_exists: store.status().0,
            }),
            Request::CreateKey { name, account } => {
                let (_, api_key) = store.create_local_key(
                    name,
                    account
                        .as_ref()
                        .map(|account| (account.username.as_str(), account.password.as_str())),
                )?;
                Ok(Response::Created { api_key })
            }
            Request::ConfigureLan { .. } | Request::ConfirmNetworkChange { .. } => {
                unreachable!("network commands handled before identity lock")
            }
        }
    }
    async fn handle(mut stream: UnixStream, app: Arc<App>) -> Result<()> {
        let bytes = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut stream))
            .await
            .context("local control input timed out")??;
        let request: Request =
            serde_json::from_slice(&bytes).context("invalid local control request")?;
        let response = tokio::task::spawn_blocking(move || {
            execute(&app, &request).unwrap_or_else(|error| {
                tracing::warn!(%error, "local control operation rejected");
                Response::Error {
                    message: error.to_string(),
                }
            })
        })
        .await
        .context("local control operation failed")?;
        tokio::time::timeout(IO_TIMEOUT, write_frame(&mut stream, &response))
            .await
            .context("local control output timed out")?
    }
    async fn exchange(path: &Path, request: &Request) -> Result<Response> {
        secure_directory(path)?;
        socket_metadata(path)?;
        let timeout = if matches!(request, Request::ConfigureLan { .. }) {
            Duration::from_secs(120)
        } else {
            IO_TIMEOUT
        };
        tokio::time::timeout(timeout, async {
            let mut stream = UnixStream::connect(path)
                .await
                .context("connect to running daemon control socket")?;
            ensure!(
                stream.peer_cred()?.uid() == 0,
                "local control daemon must run as root"
            );
            write_frame(&mut stream, request).await?;
            let bytes = read_frame(&mut stream).await?;
            serde_json::from_slice(&bytes).context("invalid local control response")
        })
        .await
        .context(
            "local control request timed out; operation outcome may be uncertain; inspect state before retrying",
        )?
    }

    fn prompt(reader: &mut BufReader<fs::File>, label: &str, hidden: bool) -> Result<String> {
        let fd = std::os::fd::AsRawFd::as_raw_fd(reader.get_ref());
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if hidden {
            ensure!(
                unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == 0,
                "read terminal settings failed"
            );
        }
        let original = hidden.then(|| unsafe { original.assume_init() });
        if let Some(original) = original {
            let mut settings = original;
            settings.c_lflag &= !libc::ECHO;
            ensure!(
                unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &settings) } == 0,
                "disable terminal echo failed"
            );
        }
        let mut line = Zeroizing::new(String::new());
        let read = (|| -> Result<usize> {
            reader.get_mut().write_all(label.as_bytes())?;
            reader.get_mut().flush()?;
            Ok(reader.read_line(&mut line)?)
        })();
        let restore = if let Some(original) = original {
            let restored = unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &original) };
            reader.get_mut().write_all(b"\n")?;
            ensure!(restored == 0, "restore terminal echo failed");
            Ok(())
        } else {
            Ok::<_, anyhow::Error>(())
        };
        restore?;
        ensure!(read? > 0, "terminal input ended");
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }
    pub async fn create_key(path: &Path, name: &str) -> Result<()> {
        root()?;
        ensure!(
            std::io::stdout().is_terminal(),
            "API key output requires a terminal; do not redirect secrets"
        );
        let account_exists = match exchange(path, &Request::Status {}).await? {
            Response::Status { account_exists } => account_exists,
            Response::Error { ref message } => bail!("{message}"),
            _ => bail!("unexpected local control response"),
        };
        eprintln!("This creates a full-permission API key and finishes pending device onboarding.");
        let account = if account_exists {
            None
        } else {
            let tty = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .context("initial account setup requires an interactive terminal")?;
            let mut reader = BufReader::new(tty);
            let username = prompt(&mut reader, "Device username: ", false)?;
            let password = Zeroizing::new(prompt(
                &mut reader,
                "Device password (12..72 bytes): ",
                true,
            )?);
            let confirmation = Zeroizing::new(prompt(&mut reader, "Confirm password: ", true)?);
            ensure!(*password == *confirmation, "passwords do not match");
            Some(AccountInput {
                username,
                password: password.to_string(),
            })
        };
        match exchange(
            path,
            &Request::CreateKey {
                name: name.to_owned(),
                account,
            },
        )
        .await?
        {
            Response::Created { ref api_key } => {
                eprintln!(
                    "Save this API key now. It cannot be displayed again. Use it as the SSH password."
                );
                println!("{api_key}");
                Ok(())
            }
            Response::Error { ref message } => bail!("{message}"),
            _ => bail!("unexpected local control response"),
        }
    }

    pub async fn configure_lan(
        path: &Path,
        name: &str,
        parent: &str,
        id: u16,
        address: &str,
    ) -> Result<()> {
        root()?;
        eprintln!(
            "Moving the factory LAN changes addressing, firewall and NAT. Verify from the console; confirmation expires in 120 seconds."
        );
        match exchange(
            path,
            &Request::ConfigureLan {
                name: name.to_owned(),
                parent: parent.to_owned(),
                id,
                address: address.to_owned(),
            },
        )
        .await?
        {
            Response::NetworkChanged { ref transaction_id } => {
                println!("{transaction_id}");
                eprintln!(
                    "Provisional LAN change applied. Verify tagged-LAN connectivity, then run:\n  sudo netcontrold --confirm-network-change {transaction_id}"
                );
                eprintln!(
                    "Do not restart the daemon until confirmed. After confirmation, set NETCONTROL_LISTEN={}:8080 in /etc/netcontrol/appliance.env, preserving other settings, then restart netcontrold with systemctl.",
                    address.split('/').next().context("LAN address missing")?
                );
                Ok(())
            }
            Response::Error { ref message } => bail!("{message}"),
            _ => bail!("unexpected local control response"),
        }
    }

    pub async fn confirm_network_change(path: &Path, id: &str) -> Result<()> {
        root()?;
        match exchange(path, &Request::ConfirmNetworkChange { id: id.to_owned() }).await? {
            Response::NetworkConfirmed {} => {
                println!(
                    "Network transaction confirmed and saved. Update the management listener environment and restart the service only if required for its new address."
                );
                Ok(())
            }
            Response::Error { ref message } => bail!("{message}"),
            _ => bail!("unexpected local control response"),
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{Listener, configure_lan, confirm_network_change, create_key};

#[cfg(not(target_os = "linux"))]
pub async fn create_key(_: &std::path::Path, _: &str) -> anyhow::Result<()> {
    anyhow::bail!("live local API-key creation is supported only on Linux");
}

#[cfg(not(target_os = "linux"))]
pub async fn configure_lan(
    _: &std::path::Path,
    _: &str,
    _: &str,
    _: u16,
    _: &str,
) -> anyhow::Result<()> {
    anyhow::bail!("local LAN configuration is supported only on Linux");
}

#[cfg(not(target_os = "linux"))]
pub async fn confirm_network_change(_: &std::path::Path, _: &str) -> anyhow::Result<()> {
    anyhow::bail!("local network confirmation is supported only on Linux");
}
