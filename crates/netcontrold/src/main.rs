use anyhow::{Context, Result, bail};
use clap::Parser;
use netcontrol_core::{Backend, Engine, Simulator};
use netcontrol_native::{Native, NativeOptions};
use netcontrold::{
    http::{App, Authentication, load_credentials, router},
    identity::Store,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

mod provision;

#[derive(Parser)]
#[command(name = "netcontrold", version = netcontrol_core::RELEASE_VERSION, about = "Native Rust network control daemon")]
struct Options {
    #[arg(long, default_value = "simulator", value_parser = ["simulator", "linux"])]
    backend: String,
    #[arg(
        long,
        help = "Enable IPv4 forwarding after native firewall reconciliation"
    )]
    appliance: bool,
    #[arg(long, requires_all = ["appliance", "provision_lan"], help = "One-time appliance WAN interface; provision and exit")]
    provision_wan: Option<String>,
    #[arg(
        long,
        requires = "provision_wan",
        help = "One-time appliance LAN interface"
    )]
    provision_lan: Option<String>,
    #[arg(long, requires_all = ["appliance", "provision_wan", "provision_lan"], help = "Explicitly replace saved networking with factory configuration and exit")]
    factory_reset: bool,
    #[arg(long, default_value = "192.168.0.1/24")]
    provision_lan_address: String,
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,
    #[arg(long, default_value = "state.json")]
    state: PathBuf,
    #[arg(
        long,
        help = "Private schema-1 JSON identity store; default <state>.credentials.json"
    )]
    credential_db: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with = "credential_db",
        help = "Private schema-1 scoped API-key hash file; disables onboarding"
    )]
    auth_file: Option<PathBuf>,
    #[arg(
        long,
        default_value = "",
        help = "Optional isolated lab namespace; native mode defaults to the host network namespace"
    )]
    namespace: String,
    #[arg(long, default_value = "/etc/netcontrol/keys")]
    keys: PathBuf,
    #[arg(long, value_delimiter = ',')]
    adopt_parents: Vec<String>,
    #[arg(long)]
    allow_host_tunables: bool,
    #[arg(long, env = "NETCONTROL_ALLOW_HOST_SERVICES")]
    allow_host_services: bool,
    #[arg(long = "gateway-monitoring", env = "NETCONTROL_GATEWAY_MONITORING")]
    allow_gateway_monitoring: bool,
    #[arg(long, default_value = "/var/lib/netcontrol/services")]
    services_state_dir: PathBuf,
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    #[arg(
        long,
        env = "NETCONTROL_SSH_LISTEN",
        help = "Enable the in-process configuration SSH server, for example 0.0.0.0:2222"
    )]
    ssh_listen: Option<String>,
    #[arg(
        long,
        requires = "ssh_listen",
        help = "Private persistent Ed25519 host key; default <state>.ssh-key"
    )]
    ssh_host_key: Option<PathBuf>,
    #[arg(
        long,
        help = "Root-owned private JSON configuration enabling signed Ubuntu self-upgrades"
    )]
    upgrade_config: Option<PathBuf>,
    #[arg(long, hide = true, conflicts_with = "upgrade_recover")]
    upgrade_worker: bool,
    #[arg(long, hide = true)]
    upgrade_recover: bool,
    #[arg(
        long,
        value_name = "NAME",
        help = "Create a new WireGuard private key file NAME in --keys, print its public key and exit"
    )]
    create_wireguard_key: Option<String>,
    #[arg(
        long,
        value_name = "NAME",
        conflicts_with = "create_wireguard_key",
        help = "Print the public key of the stored WireGuard private key NAME in --keys and exit"
    )]
    wireguard_public_key: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Options::parse()).await {
        eprintln!("netcontrold: {error:#}");
        std::process::exit(1);
    }
}
fn absolute(path: &std::path::Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let parent = path.parent().context("path needs parent")?;
    Ok(if parent.exists() {
        parent
            .canonicalize()?
            .join(path.file_name().context("path needs filename")?)
    } else {
        path
    })
}
fn appended(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
fn same_path(first: &std::path::Path, second: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        first
            .to_string_lossy()
            .eq_ignore_ascii_case(&second.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        first == second
    }
}
async fn run(options: Options) -> Result<()> {
    if options.create_wireguard_key.is_some() || options.wireguard_public_key.is_some() {
        let public = match (&options.create_wireguard_key, &options.wireguard_public_key) {
            (Some(name), _) => netcontrol_native::create_wireguard_key(&options.keys, name)?,
            (_, Some(name)) => netcontrol_native::wireguard_public_key(&options.keys, name)?,
            _ => unreachable!(),
        };
        println!("{public}");
        return Ok(());
    }
    configure_logging(&options)?;
    if options.upgrade_worker || options.upgrade_recover {
        return tokio::task::spawn_blocking(move || {
            netcontrold::updates::helper(options.upgrade_recover)
        })
        .await?;
    }
    let updates = if let Some(path) = &options.upgrade_config {
        if options.backend != "linux" || !options.namespace.is_empty() || !options.appliance {
            bail!("self-upgrade requires the Linux host appliance backend");
        }
        Some(netcontrold::updates::Manager::open(path)?)
    } else {
        None
    };
    if options.appliance && (options.backend != "linux" || !options.namespace.is_empty()) {
        bail!("appliance provisioning and forwarding require the Linux host backend");
    }
    let listen = tokio::net::lookup_host(&options.listen)
        .await
        .context("resolve management listener")?
        .next()
        .context("management listener resolved to no addresses")?;
    let tls = if let (Some(cert), Some(key)) = (&options.tls_cert, &options.tls_key) {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        Some(
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("load native TLS certificate and key")?,
        )
    } else {
        None
    };
    let credential_path = options
        .credential_db
        .clone()
        .unwrap_or_else(|| appended(&options.state, ".credentials.json"));
    let state = absolute(&options.state)?;
    let auth_path = options.auth_file.as_ref().unwrap_or(&credential_path);
    let auth = absolute(auth_path)?;
    let state_lock = absolute(&appended(&options.state, ".lock"))?;
    let auth_lock = absolute(&appended(auth_path, ".lock"))?;
    if same_path(&auth, &state)
        || same_path(&auth, &state_lock)
        || (options.auth_file.is_none() && same_path(&auth_lock, &state))
    {
        bail!("credentials, network state, and their lock files must use different paths");
    }
    let ssh = if let Some(listen) = &options.ssh_listen {
        let path = options
            .ssh_host_key
            .clone()
            .unwrap_or_else(|| appended(&options.state, ".ssh-key"));
        let key_path = absolute(&path)?;
        if [&state, &auth, &state_lock, &auth_lock]
            .into_iter()
            .any(|other| same_path(&key_path, other))
        {
            bail!(
                "SSH host key must use a different path from network state, credentials and lock files"
            );
        }
        netcontrold::ssh::load_host_key(&path)?;
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .context("bind configuration SSH listener")?;
        tracing::info!(address = %listener.local_addr()?, "configuration SSH listener enabled");
        Some((listener, path))
    } else {
        None
    };
    let auth = if let Some(path) = &options.auth_file {
        Authentication::Scoped(load_credentials(path)?)
    } else {
        let store = Store::open(&credential_path)?;
        if !store.status().0 {
            tracing::warn!("unclaimed device; restrict management access until setup is complete");
        }
        Authentication::Device(Mutex::new(store))
    };
    if tls.is_none() {
        tracing::warn!(
            "HTTP is unencrypted; passwords and API keys require a trusted management network"
        );
    }
    fn configure_logging(options: &Options) -> Result<()> {
        if options.backend != "linux" || !options.allow_host_services {
            tracing_subscriber::fmt()
                .json()
                .with_writer(std::io::stderr)
                .try_init()
                .map_err(|_| anyhow::anyhow!("initialize daemon logging"))?;
            return Ok(());
        }
        use tracing_subscriber::fmt::writer::MakeWriterExt;
        let mut directory = std::fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&options.services_state_dir)?;
        let path = options.services_state_dir.join("backend.log");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("backend log must be a regular file");
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.mode() & 0o077 != 0
                        || metadata.uid() != unsafe { libc::geteuid() }
                        || metadata.nlink() != 1
                    {
                        bail!(
                            "backend log must be private, owned by the daemon, and not hard-linked"
                        );
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut open = std::fs::OpenOptions::new();
        open.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = open.open(path)?;
        tracing_subscriber::fmt()
            .json()
            .with_writer(Mutex::new(file).and(std::io::stderr))
            .try_init()
            .map_err(|_| anyhow::anyhow!("initialize daemon logging"))?;
        Ok(())
    }
    let saved_native_startup = options.backend == "linux"
        && options.namespace.is_empty()
        && options.provision_wan.is_none();
    if saved_native_startup && !options.state.try_exists()? {
        bail!(
            "no saved native configuration; run install.sh for initial provisioning instead of upgrading an unconfigured device"
        );
    }
    let mqtt_mode = if options.backend == "simulator" {
        netcontrold::mqtt::Mode::Simulated
    } else if options.namespace.is_empty() {
        netcontrold::mqtt::Mode::Native
    } else {
        netcontrold::mqtt::Mode::Unsupported
    };
    let mqtt_root = appended(&options.state, ".mqtt");
    let backend: Box<dyn Backend> = match options.backend.as_str() {
        "linux" => Box::new(Native::open(NativeOptions {
            namespace: options.namespace,
            keys: options.keys,
            adopted_parents: options.adopt_parents,
            allow_host_tunables: options.allow_host_tunables,
            allow_host_services: options.allow_host_services,
            gateway_monitoring: options.allow_gateway_monitoring,
            services_state: options.services_state_dir,
        })?),
        _ => Box::new(Simulator::new()),
    };
    let mut engine = if options.factory_reset {
        Engine::open_for_factory_reset(&options.state, backend)?
    } else if saved_native_startup {
        Engine::open_saved(&options.state, backend)?
    } else {
        Engine::open(&options.state, backend)?
    };
    if let (Some(wan), Some(lan)) = (&options.provision_wan, &options.provision_lan) {
        if options.factory_reset {
            provision::factory_reset(&mut engine, wan, lan, &options.provision_lan_address)?;
            provision::enable_forwarding(&mut engine)?;
        } else {
            provision::apply(&mut engine, wan, lan, &options.provision_lan_address).await?;
        }
        engine.shutdown()?;
        tracing::info!(
            wan,
            lan,
            "appliance provisioned; IPv4 forwarding enables on service startup"
        );
        return Ok(());
    }
    if options.appliance {
        provision::enable_forwarding(&mut engine)?;
    }
    let release_config = updates
        .as_ref()
        .map(netcontrold::updates::Manager::release_config);
    netcontrold::updates::initialize_release_check(&mut engine, release_config.as_ref())?;
    let engine = Arc::new(Mutex::new(engine));
    let mut app = if let Some(updates) = updates {
        updates.mark_ready()?;
        App::with_updates(engine.clone(), auth, tls.is_some(), updates)?
    } else {
        App::new(engine.clone(), auth, tls.is_some())
    };
    let mqtt = netcontrold::mqtt::Manager::open(&mqtt_root, engine.clone(), mqtt_mode)?;
    App::attach_mqtt(&mut app, mqtt.clone())?;
    let dynamic_dns_mode = if mqtt_mode == netcontrold::mqtt::Mode::Simulated {
        netcontrold::dynamic_dns::Mode::Simulated
    } else if mqtt_mode == netcontrold::mqtt::Mode::Native {
        netcontrold::dynamic_dns::Mode::Native
    } else {
        netcontrold::dynamic_dns::Mode::Unsupported
    };
    let dynamic_dns = netcontrold::dynamic_dns::Manager::open(
        &appended(&options.state, ".dynamic-dns"),
        engine.clone(),
        dynamic_dns_mode,
    )?;
    App::attach_dynamic_dns(&mut app, dynamic_dns.clone())?;
    let system_mode = if mqtt_mode == netcontrold::mqtt::Mode::Simulated {
        netcontrold::host_system::Mode::Simulated
    } else if mqtt_mode == netcontrold::mqtt::Mode::Native {
        netcontrold::host_system::Mode::Native
    } else {
        netcontrold::host_system::Mode::Unsupported
    };
    let system = netcontrold::host_system::Manager::open(engine.clone(), system_mode)?;
    App::attach_system(&mut app, system.clone())?;
    let watchdog = Arc::new(netcontrold::watchdog::Watchdog::from_environment()?);
    let (restart_tx, restart_rx) = tokio::sync::watch::channel(false);
    let restart_requested = restart_rx.clone();
    let controls: std::collections::BTreeMap<_, _> = ["mqtt", "dynamic-dns", "system"]
        .into_iter()
        .map(|name| {
            (
                name.to_string(),
                Arc::new(netcontrold::processes::Control::default()),
            )
        })
        .collect();
    App::attach_processes(
        &mut app,
        controls.clone(),
        (system_mode == netcontrold::host_system::Mode::Native && watchdog.enabled())
            .then_some(restart_tx),
    )?;
    let (system_stop, system_receiver) = tokio::sync::watch::channel(false);
    let system_control = controls["system"].clone();
    let system_task = tokio::spawn(async move {
        system_control
            .run(system_receiver, move |receiver| {
                let system = system.clone();
                async move {
                    system.reset_retry()?;
                    system.run(receiver).await;
                    Ok(())
                }
            })
            .await
    });
    let (dynamic_dns_stop, dynamic_dns_receiver) = tokio::sync::watch::channel(false);
    let dynamic_dns_control = controls["dynamic-dns"].clone();
    let dynamic_dns_task = tokio::spawn(async move {
        dynamic_dns_control
            .run(dynamic_dns_receiver, move |receiver| {
                dynamic_dns.clone().run(receiver)
            })
            .await
    });
    let (mqtt_stop, mqtt_receiver) = tokio::sync::watch::channel(false);
    let (release_stop, release_receiver) = tokio::sync::watch::channel(false);
    let release_task = tokio::spawn(netcontrold::updates::monitor_releases(
        engine.clone(),
        release_config,
        release_receiver,
    ));
    let mqtt_control = controls["mqtt"].clone();
    let mqtt_task = tokio::spawn(async move {
        mqtt_control
            .run(mqtt_receiver, move |receiver| {
                let mqtt = mqtt.clone();
                async move {
                    mqtt.run(receiver).await;
                    Ok(())
                }
            })
            .await
    });
    let handle = axum_server::Handle::new();
    let (ssh_stop_tx, ssh_stop_rx) = tokio::sync::watch::channel(false);
    let mut ssh_task = ssh.map(|(listener, path)| {
        let app = app.clone();
        tokio::spawn(
            async move { netcontrold::ssh::serve(listener, &path, app, ssh_stop_rx).await },
        )
    });
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let readiness_watchdog = watchdog.clone();
    let readiness_handle = handle.clone();
    let readiness = tokio::spawn(async move {
        if readiness_handle.listening().await.is_some() {
            if let Err(error) = readiness_watchdog.ready() {
                tracing::warn!(%error, "systemd readiness notification failed");
            }
        }
    });
    let tick_engine = engine.clone();
    let tick_app = app.clone();
    let tick_handle = handle.clone();
    let tick_ssh_stop = ssh_stop_tx.clone();
    let tick_watchdog = watchdog.clone();
    let task_handles = [
        ("mqtt", mqtt_task.abort_handle()),
        ("dynamic_dns", dynamic_dns_task.abort_handle()),
        ("system", system_task.abort_handle()),
        ("release_check", release_task.abort_handle()),
    ];
    let ticker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        let mut next_health = std::time::Instant::now();
        loop {
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() { return Ok::<(), anyhow::Error>(()); }
                }
                _ = interval.tick() => {
                    let engine = tick_engine.clone();
                    let app = tick_app.clone();
                    let refresh_health = std::time::Instant::now() >= next_health;
                    if refresh_health {
                        next_health = std::time::Instant::now() + Duration::from_secs(2);
                    }
                    let watchdog_enabled = tick_watchdog.enabled();
                    let tasks: Vec<_> = task_handles.iter().map(|(name, handle)| (*name, handle.is_finished())).collect();
                    let result = tokio::task::spawn_blocking(move || {
                        app.refresh_upgrade_gate()?;
                        engine.lock().map_err(|_| anyhow::anyhow!("engine lock poisoned"))?.tick()?;
                        if refresh_health {
                            app.refresh_health(watchdog_enabled, &tasks);
                        }
                        Ok::<(), anyhow::Error>(())
                    }).await
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("deadline worker failed")));
                    if let Err(error) = result {
                        let _ = tick_ssh_stop.send(true);
                        tick_handle.graceful_shutdown(Some(Duration::from_secs(10)));
                        return Err(error.context("background transaction deadline tick failed"));
                    }
                    if let Err(error) = tick_watchdog.heartbeat() {
                        tracing::warn!(%error, "systemd watchdog notification failed");
                    }
                }
            }
        }
    });
    let signal_handle = handle.clone();
    let signal_ssh_stop = ssh_stop_tx.clone();
    let signals = tokio::spawn(async move {
        let mut restart = restart_rx;
        tokio::select! {
            _=shutdown_signal()=>{},
            _=async {
                // An absent API restart sender is not a shutdown request.
                loop {
                    if *restart.borrow() {break;}
                    if restart.changed().await.is_err() {std::future::pending::<()>().await;}
                }
            }=>{},
        }
        let _ = signal_ssh_stop.send(true);
        signal_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    let service = router(app).into_make_service();
    let http_handle = handle.clone();
    let served = async move {
        match tls {
            Some(config) => {
                axum_server::bind_rustls(listen, config)
                    .handle(http_handle)
                    .serve(service)
                    .await
            }
            None => {
                axum_server::bind(listen)
                    .handle(http_handle)
                    .serve(service)
                    .await
            }
        }
    };
    tokio::pin!(served);
    let mut ssh_finished = None;
    let served = if let Some(task) = ssh_task.as_mut() {
        tokio::select! {
            result = &mut served => result,
            result = task => {
                ssh_finished = Some(result);
                handle.graceful_shutdown(Some(Duration::from_secs(10)));
                served.await
            }
        }
    } else {
        served.await
    };
    readiness.abort();
    if let Err(error) = watchdog.stopping() {
        tracing::warn!(%error, "systemd stopping notification failed");
    }
    let stopping = *ssh_stop_tx.borrow();
    let _ = ssh_stop_tx.send(true);
    let ssh_result = if let Some(result) = ssh_finished {
        match result {
            Ok(Ok(())) if !stopping => Err(anyhow::anyhow!("SSH listener stopped unexpectedly")),
            Ok(result) => result,
            Err(error) => Err(error.into()),
        }
    } else if let Some(mut task) = ssh_task {
        match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(anyhow::anyhow!("SSH server shutdown timed out"))
            }
        }
    } else {
        Ok(())
    };
    let _ = stop_tx.send(true);
    let _ = mqtt_stop.send(true);
    let _ = dynamic_dns_stop.send(true);
    let _ = system_stop.send(true);
    let _ = release_stop.send(true);
    signals.abort();
    mqtt_task.await.context("MQTT worker shutdown failed")??;
    system_task
        .await
        .context("host system worker shutdown failed")??;
    dynamic_dns_task
        .await
        .context("Dynamic DNS worker shutdown failed")??;
    release_task
        .await
        .context("release checker shutdown failed")??;
    let tick_result = ticker.await.context("deadline ticker task");
    let shutdown_result = engine
        .lock()
        .map_err(|_| anyhow::anyhow!("engine lock poisoned"))?
        .shutdown();
    shutdown_result.context("durable engine shutdown failed")?;
    tick_result??;
    ssh_result.context("configuration SSH server failed")?;
    if *restart_requested.borrow() {
        bail!("daemon restart requested; supervised service will restart");
    }
    served.context("HTTP listener failed")
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_current_contract_and_rejected_legacy_flags() {
        let options = Options::try_parse_from(["netcontrold"]).unwrap();
        assert_eq!(options.listen, "0.0.0.0:8080");
        assert_eq!(options.backend, "simulator");
        assert!(!options.appliance);
        assert!(
            Options::try_parse_from([
                "netcontrold",
                "--provision-wan",
                "wan0",
                "--provision-lan",
                "lan0"
            ])
            .is_err()
        );
        assert!(
            Options::try_parse_from(["netcontrold", "--appliance", "--provision-wan", "wan0"])
                .is_err()
        );
        let appliance = Options::try_parse_from([
            "netcontrold",
            "--backend",
            "linux",
            "--appliance",
            "--provision-wan",
            "wan0",
            "--provision-lan",
            "lan0",
        ])
        .unwrap();
        assert_eq!(appliance.provision_lan_address, "192.168.0.1/24");
        assert!(!appliance.factory_reset);
        assert!(Options::try_parse_from(["netcontrold", "--factory-reset"]).is_err());
        let reset = Options::try_parse_from([
            "netcontrold",
            "--backend",
            "linux",
            "--appliance",
            "--factory-reset",
            "--provision-wan",
            "wan0",
            "--provision-lan",
            "lan0",
        ])
        .unwrap();
        assert!(reset.factory_reset);
        assert!(options.credential_db.is_none());
        assert!(options.ssh_listen.is_none());
        assert!(options.ssh_host_key.is_none());
        assert!(Options::try_parse_from(["netcontrold", "--ssh-host-key", "host.key"]).is_err());
        let ssh = Options::try_parse_from([
            "netcontrold",
            "--ssh-listen",
            "127.0.0.1:2222",
            "--ssh-host-key",
            "host.key",
        ])
        .unwrap();
        assert_eq!(ssh.ssh_listen.as_deref(), Some("127.0.0.1:2222"));
        assert!(
            Options::try_parse_from([
                "netcontrold",
                "--credential-db",
                "identity.json",
                "--auth-file",
                "auth.json"
            ])
            .is_err()
        );
        assert!(Options::try_parse_from(["netcontrold", "--tls-cert", "cert.pem"]).is_err());
        assert!(Options::try_parse_from(["netcontrold", "--tls-key", "key.pem"]).is_err());
        for flag in [
            "--softflowd-binary",
            "--dhcp-relay-binary",
            "--ntp-binary",
            "--syslog-binary",
            "--vnstatd-binary",
            "--softflowd-uid",
            "--services-runtime-dir",
        ] {
            assert!(Options::try_parse_from(["netcontrold", flag, "old-value"]).is_err());
        }
        let options = Options::try_parse_from([
            "netcontrold",
            "--backend",
            "linux",
            "--namespace",
            "lab",
            "--keys",
            "keys",
            "--adopt-parents",
            "eth0,eth1",
            "--gateway-monitoring",
            "--allow-host-tunables",
            "--allow-host-services",
        ])
        .unwrap();
        assert_eq!(options.adopt_parents, vec!["eth0", "eth1"]);
        assert!(
            options.allow_gateway_monitoring
                && options.allow_host_tunables
                && options.allow_host_services
        );
    }
}
