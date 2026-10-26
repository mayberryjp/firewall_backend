use crate::private_store::identifier;
use anyhow::{Context, Result, ensure};
use netcontrol_core::{Engine, SystemConfig, valid_hostname, valid_timezone_name};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

const ZONEINFO: &str = "usr/share/zoneinfo";
const NOT_ZONES: [&str; 5] = ["posix", "right", "posixrules", "localtime", "Factory"];
const MAX_ZONES: usize = 2048;
const RETRY_AFTER: Duration = Duration::from_secs(30);
const REAPPLY_AFTER: Duration = Duration::from_secs(10);
const SIMULATED_ZONES: [&str; 8] = [
    "America/Chicago",
    "America/Los_Angeles",
    "America/New_York",
    "Asia/Tokyo",
    "Australia/Sydney",
    "Europe/Berlin",
    "Europe/London",
    "UTC",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Native,
    Simulated,
    Unsupported,
}

type SetHostname = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Host files below `root` (the real `/` outside tests) and the kernel hostname setter.
struct Host {
    root: PathBuf,
    set_hostname: SetHostname,
}

impl Host {
    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn kernel_hostname(&self) -> Result<String> {
        let name = fs::read_to_string(self.path("proc/sys/kernel/hostname"))
            .context("read kernel hostname")?;
        Ok(name.trim().to_owned())
    }

    fn file_hostname(&self) -> Result<Option<String>> {
        match fs::read_to_string(self.path("etc/hostname")) {
            Ok(name) => Ok(Some(name.trim().to_owned())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("read /etc/hostname"),
        }
    }

    fn hostname_current(&self, wanted: &str) -> Result<bool> {
        Ok(self.kernel_hostname()? == wanted && self.file_hostname()?.as_deref() == Some(wanted))
    }

    fn apply_hostname(&self, wanted: &str) -> Result<()> {
        ensure!(valid_hostname(wanted), "invalid hostname");
        if self.kernel_hostname()? != wanted {
            (self.set_hostname)(wanted)?;
        }
        if self.file_hostname()?.as_deref() != Some(wanted) {
            write_atomic(&self.path("etc/hostname"), format!("{wanted}\n").as_bytes())
                .context("write /etc/hostname")?;
        }
        Ok(())
    }

    fn observed_timezone(&self) -> Option<String> {
        let target = fs::read_link(self.path("etc/localtime")).ok()?;
        let (_, zone) = target.to_str()?.split_once("zoneinfo/")?;
        valid_timezone_name(zone).then(|| zone.to_owned())
    }

    /// The zone must be a TZif file that resolves inside the zoneinfo directory.
    fn zone_file(&self, zone: &str) -> Result<PathBuf> {
        ensure!(
            !zone.is_empty() && valid_timezone_name(zone),
            "invalid timezone name"
        );
        let first = zone.split('/').next().unwrap_or_default();
        ensure!(!NOT_ZONES.contains(&first), "not a timezone: {zone}");
        let base = fs::canonicalize(self.path(ZONEINFO))
            .context("timezone database (tzdata) is not installed on this host")?;
        let file = fs::canonicalize(base.join(zone))
            .with_context(|| format!("timezone {zone} is not in the host timezone database"))?;
        ensure!(
            file.starts_with(&base) && is_tzif(&file),
            "timezone {zone} is not a valid timezone database file"
        );
        Ok(file)
    }

    fn apply_timezone(&self, zone: &str) -> Result<()> {
        self.zone_file(zone)?;
        #[cfg(unix)]
        {
            let link = self.path("etc/localtime");
            let pending = self.path(&format!("etc/.localtime.netcontrol-{}", identifier()));
            std::os::unix::fs::symlink(format!("/{ZONEINFO}/{zone}"), &pending)
                .context("create timezone link")?;
            if let Err(error) = fs::rename(&pending, &link) {
                let _ = fs::remove_file(&pending);
                return Err(error).context("replace /etc/localtime");
            }
            // Debian-style hosts also record the name; create it only where it already exists.
            if fs::symlink_metadata(self.path("etc/timezone")).is_ok_and(|m| m.is_file()) {
                write_atomic(&self.path("etc/timezone"), format!("{zone}\n").as_bytes())
                    .context("write /etc/timezone")?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        anyhow::bail!("timezone management requires Linux host mode")
    }

    fn zones(&self) -> Vec<String> {
        let mut zones = BTreeSet::new();
        let mut pending = vec![(self.path(ZONEINFO), String::new(), 0)];
        while let Some((directory, prefix, depth)) = pending.pop() {
            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                if prefix.is_empty() && NOT_ZONES.contains(&name.as_str()) {
                    continue;
                }
                let relative = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if metadata.is_dir() {
                    if depth < 2 {
                        pending.push((entry.path(), relative, depth + 1));
                    }
                } else if metadata.is_file()
                    && valid_timezone_name(&relative)
                    && is_tzif(&entry.path())
                    && zones.len() < MAX_ZONES
                {
                    zones.insert(relative);
                }
            }
        }
        zones.into_iter().collect()
    }
}

fn is_tzif(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && &magic == b"TZif"
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().context("file has no parent directory")?;
    let pending = directory.join(format!(
        ".{}.netcontrol-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .context("file name is not UTF-8")?,
        identifier()
    ));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&pending, fs::Permissions::from_mode(0o644))?;
        }
        fs::rename(&pending, path)?;
        #[cfg(unix)]
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

#[cfg(target_os = "linux")]
fn kernel_set_hostname(name: &str) -> Result<()> {
    let result = unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) };
    ensure!(
        result == 0,
        "setting the kernel hostname failed: {} (the daemon needs CAP_SYS_ADMIN)",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn kernel_set_hostname(_: &str) -> Result<()> {
    anyhow::bail!("hostname management requires Linux host mode")
}

#[derive(Default)]
struct Backoff {
    configured: String,
    next: Option<Instant>,
}

impl Backoff {
    /// A changed configured value is applied immediately; otherwise wait out the delay.
    fn due(&mut self, configured: &str, now: Instant) -> bool {
        if self.configured != configured {
            *self = Self {
                configured: configured.to_owned(),
                next: None,
            };
        }
        self.next.is_none_or(|next| now >= next)
    }
}

pub struct Manager {
    host: Arc<Host>,
    engine: Arc<Mutex<Engine>>,
    mode: Mode,
    status: Mutex<Value>,
    backoff: Mutex<[Backoff; 2]>,
}

fn setting(configured: &str, observed: Option<String>, state: &str, error: Option<&str>) -> Value {
    json!({"configured":configured,"observed":observed,"state":state,"error":error})
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Manager {
    pub fn open(engine: Arc<Mutex<Engine>>, mode: Mode) -> Result<Arc<Self>> {
        Self::with_host(
            engine,
            mode,
            Host {
                root: PathBuf::from("/"),
                set_hostname: Box::new(kernel_set_hostname),
            },
        )
    }

    fn with_host(engine: Arc<Mutex<Engine>>, mode: Mode, host: Host) -> Result<Arc<Self>> {
        let host = Arc::new(host);
        let check: Option<netcontrol_core::TimezoneCheck> = match mode {
            Mode::Unsupported => None,
            Mode::Simulated => Some(Arc::new(|_| true)),
            Mode::Native => {
                let host = host.clone();
                Some(Arc::new(move |zone| host.zone_file(zone).is_ok()))
            }
        };
        engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?
            .configure_system(check);
        Ok(Arc::new(Self {
            host,
            engine,
            mode,
            status: Mutex::new(json!({
                "hostname":setting("", None, "unmanaged", None),
                "timezone":setting("", None, "unmanaged", None),
                "last_applied_at_unix":null
            })),
            backoff: Mutex::new([Backoff::default(), Backoff::default()]),
        }))
    }

    pub fn status(&self) -> Result<Value> {
        Ok(self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("system status unavailable"))?
            .clone())
    }

    pub fn timezones(&self) -> Vec<String> {
        match self.mode {
            Mode::Native => self.host.zones(),
            Mode::Simulated => SIMULATED_ZONES.iter().map(|zone| (*zone).into()).collect(),
            Mode::Unsupported => Vec::new(),
        }
    }

    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = tick.tick() => {}
            }
            if *stop.borrow() {
                break;
            }
            let manager = self.clone();
            if tokio::task::spawn_blocking(move || manager.reconcile(Instant::now()))
                .await
                .is_err()
            {
                tracing::error!("host system reconciliation task failed");
            }
        }
    }

    /// Applies confirmed settings only; unmanaged (empty) values leave the host untouched.
    fn reconcile(&self, now: Instant) {
        let config = match self.engine.try_lock() {
            Ok(engine) => {
                (!engine.configuration_busy()).then(|| engine.saved_configuration().system.clone())
            }
            Err(_) => return,
        };
        let paused = config.is_none();
        let config = config.unwrap_or_else(|| self.configured());
        let (hostname, timezone) = (
            self.reconcile_setting(0, &config, now, paused),
            self.reconcile_setting(1, &config, now, paused),
        );
        let applied = [&hostname, &timezone].iter().any(|(_, applied)| *applied);
        if let Ok(mut status) = self.status.lock() {
            status["hostname"] = hostname.0;
            status["timezone"] = timezone.0;
            if applied {
                status["last_applied_at_unix"] = json!(now_unix());
            }
        }
    }

    fn configured(&self) -> SystemConfig {
        self.status
            .lock()
            .map(|status| SystemConfig {
                hostname: status["hostname"]["configured"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                timezone: status["timezone"]["configured"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                ..Default::default()
            })
            .unwrap_or_default()
    }

    /// Returns the setting's status row and whether this call changed the host.
    fn reconcile_setting(
        &self,
        index: usize,
        config: &SystemConfig,
        now: Instant,
        paused: bool,
    ) -> (Value, bool) {
        let (kind, configured) = if index == 0 {
            ("hostname", config.hostname.as_str())
        } else {
            ("timezone", config.timezone.as_str())
        };
        let read = || -> Option<String> {
            if self.mode != Mode::Native {
                return None;
            }
            if index == 0 {
                self.host.kernel_hostname().ok()
            } else {
                self.host.observed_timezone()
            }
        };
        if configured.is_empty() {
            return (setting("", read(), "unmanaged", None), false);
        }
        match self.mode {
            Mode::Unsupported => {
                return (
                    setting(
                        configured,
                        None,
                        "unavailable",
                        Some("host system settings require Linux host mode"),
                    ),
                    false,
                );
            }
            Mode::Simulated => return (setting(configured, None, "simulated", None), false),
            Mode::Native => {}
        }
        if paused {
            return (setting(configured, read(), "paused", None), false);
        }
        let current = if index == 0 {
            self.host.hostname_current(configured)
        } else {
            Ok(self.host.observed_timezone().as_deref() == Some(configured))
        };
        let current = match current {
            Ok(current) => current,
            Err(error) => {
                return (
                    setting(configured, read(), "error", Some(&format!("{error:#}"))),
                    false,
                );
            }
        };
        let Ok(mut backoff) = self.backoff.lock() else {
            return (
                setting(configured, read(), "error", Some("state unavailable")),
                false,
            );
        };
        if current {
            // Keeps any re-apply delay so an external agent that fights back cannot cause a hot loop.
            backoff[index].due(configured, now);
            return (setting(configured, read(), "current", None), false);
        }
        if !backoff[index].due(configured, now) {
            let state = self.status.lock().ok().and_then(|status| {
                (status[kind]["state"] == "error").then(|| status[kind].clone())
            });
            return match state {
                Some(row) => (row, false),
                None => (setting(configured, read(), "applying", None), false),
            };
        }
        let result = if index == 0 {
            self.host.apply_hostname(configured)
        } else {
            self.host.apply_timezone(configured)
        };
        match result {
            Ok(()) => {
                backoff[index].next = Some(now + REAPPLY_AFTER);
                tracing::info!(setting = kind, value = configured, "host setting applied");
                (setting(configured, read(), "current", None), true)
            }
            Err(error) => {
                backoff[index].next = Some(now + RETRY_AFTER);
                let message = format!("{error:#}");
                tracing::warn!(setting = kind, error = %message, "host setting failed");
                (setting(configured, read(), "error", Some(&message)), false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcontrol_core::{Config, Simulator};

    struct Fixture {
        directory: tempfile::TempDir,
        engine: Arc<Mutex<Engine>>,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            for relative in ["etc", "proc/sys/kernel", "usr/share/zoneinfo/America"] {
                fs::create_dir_all(directory.path().join(relative)).unwrap();
            }
            fs::write(directory.path().join("proc/sys/kernel/hostname"), "old\n").unwrap();
            for zone in ["UTC", "America/New_York", "America/Chicago"] {
                fs::write(
                    directory.path().join(ZONEINFO).join(zone),
                    b"TZif2-synthetic",
                )
                .unwrap();
            }
            fs::write(
                directory.path().join(ZONEINFO).join("zone.tab"),
                "not a zone",
            )
            .unwrap();
            fs::write(directory.path().join(ZONEINFO).join("leapseconds"), "text").unwrap();
            let engine = Arc::new(Mutex::new(
                Engine::open(
                    &directory.path().join("state.json"),
                    Box::new(Simulator::new()),
                )
                .unwrap(),
            ));
            Self { directory, engine }
        }

        fn manager(&self, mode: Mode) -> Arc<Manager> {
            let root = self.directory.path().to_owned();
            let proc = root.join("proc/sys/kernel/hostname");
            Manager::with_host(
                self.engine.clone(),
                mode,
                Host {
                    root,
                    set_hostname: Box::new(move |name| {
                        fs::write(&proc, format!("{name}\n"))?;
                        Ok(())
                    }),
                },
            )
            .unwrap()
        }

        fn configure(&self, system: SystemConfig) {
            let mut engine = self.engine.lock().unwrap();
            let mut config: Config = engine.saved_configuration().clone();
            config.system = system;
            let reply = submit(&mut engine, &config);
            assert_eq!(reply.status, 202, "{}", reply.body);
            let id = reply.body["id"].as_str().unwrap().to_owned();
            let confirm = engine.request(
                "POST",
                &format!("/api/v1/transactions/{id}/confirm"),
                "",
                "fixture",
                &permissions(),
                &[],
            );
            assert_eq!(confirm.status, 200, "{}", confirm.body);
        }

        fn read(&self, relative: &str) -> String {
            fs::read_to_string(self.directory.path().join(relative)).unwrap()
        }
    }

    fn permissions() -> Vec<String> {
        netcontrol_core::PERMISSIONS
            .iter()
            .map(|p| (*p).to_owned())
            .collect()
    }

    fn submit(engine: &mut Engine, config: &Config) -> netcontrol_core::Reply {
        let body = serde_json::to_vec(&json!({
            "base_revision":engine.committed_revision(),
            "confirm_timeout_seconds":30,
            "config":config
        }))
        .unwrap();
        engine.request(
            "POST",
            "/api/v1/transactions",
            "",
            "fixture",
            &permissions(),
            &body,
        )
    }

    fn system(hostname: &str, timezone: &str) -> SystemConfig {
        SystemConfig {
            hostname: hostname.into(),
            timezone: timezone.into(),
            ..Default::default()
        }
    }

    #[test]
    fn zone_listing_accepts_only_tzif_files_and_zone_names() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.directory.path().join("usr/share/zoneinfo/posix")).unwrap();
        fs::write(
            fixture
                .directory
                .path()
                .join("usr/share/zoneinfo/posix/UTC"),
            b"TZif2",
        )
        .unwrap();
        let manager = fixture.manager(Mode::Native);
        assert_eq!(
            manager.timezones(),
            ["America/Chicago", "America/New_York", "UTC"]
        );
        for bad in [
            "zone.tab",
            "leapseconds",
            "../etc/passwd",
            "posix/UTC",
            "America",
            "America/Nowhere",
        ] {
            assert!(manager.host.zone_file(bad).is_err(), "{bad}");
        }
        assert!(manager.host.zone_file("America/New_York").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_must_stay_inside_the_zone_database() {
        let fixture = Fixture::new();
        let outside = fixture.directory.path().join("outside");
        fs::write(&outside, b"TZif2-outside").unwrap();
        std::os::unix::fs::symlink(
            &outside,
            fixture.directory.path().join("usr/share/zoneinfo/Escape"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "America/New_York",
            fixture.directory.path().join("usr/share/zoneinfo/Eastern"),
        )
        .unwrap();
        let manager = fixture.manager(Mode::Native);
        assert!(manager.host.zone_file("Escape").is_err());
        assert!(manager.host.zone_file("Eastern").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_settings_apply_atomically_and_report_status() {
        let fixture = Fixture::new();
        fs::write(fixture.directory.path().join("etc/timezone"), "Etc/UTC\n").unwrap();
        fs::write(fixture.directory.path().join("etc/localtime"), b"old-copy").unwrap();
        let manager = fixture.manager(Mode::Native);
        let start = Instant::now();
        manager.reconcile(start);
        let status = manager.status().unwrap();
        assert_eq!(status["hostname"]["state"], "unmanaged");
        assert_eq!(status["hostname"]["observed"], "old");
        assert_eq!(fixture.read("proc/sys/kernel/hostname"), "old\n");

        fixture.configure(system("fw-1", "America/New_York"));
        manager.reconcile(start);
        let status = manager.status().unwrap();
        assert_eq!(status["hostname"]["state"], "current", "{status}");
        assert_eq!(status["hostname"]["observed"], "fw-1");
        assert_eq!(status["timezone"]["state"], "current", "{status}");
        assert_eq!(status["timezone"]["observed"], "America/New_York");
        assert!(status["last_applied_at_unix"].is_u64());
        assert_eq!(fixture.read("etc/hostname"), "fw-1\n");
        assert_eq!(fixture.read("proc/sys/kernel/hostname"), "fw-1\n");
        assert_eq!(fixture.read("etc/timezone"), "America/New_York\n");
        assert_eq!(
            fs::read_link(fixture.directory.path().join("etc/localtime")).unwrap(),
            Path::new("/usr/share/zoneinfo/America/New_York")
        );
        assert!(
            fs::read_dir(fixture.directory.path().join("etc"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
        );

        // External drift is repaired, but not more often than the re-apply delay.
        fs::write(fixture.directory.path().join("etc/hostname"), "other\n").unwrap();
        manager.reconcile(start + Duration::from_secs(1));
        assert_eq!(fixture.read("etc/hostname"), "other\n");
        manager.reconcile(start + REAPPLY_AFTER + Duration::from_secs(1));
        assert_eq!(fixture.read("etc/hostname"), "fw-1\n");

        // Clearing a value stops management and leaves the host as it is.
        fixture.configure(system("", ""));
        manager.reconcile(start + Duration::from_secs(60));
        let status = manager.status().unwrap();
        assert_eq!(status["hostname"]["state"], "unmanaged");
        assert_eq!(status["hostname"]["observed"], "fw-1");
        assert_eq!(status["timezone"]["observed"], "America/New_York");
    }

    #[cfg(unix)]
    #[test]
    fn timezone_file_is_not_created_where_the_host_has_none() {
        let fixture = Fixture::new();
        let manager = fixture.manager(Mode::Native);
        fixture.configure(system("", "UTC"));
        manager.reconcile(Instant::now());
        assert_eq!(manager.status().unwrap()["timezone"]["state"], "current");
        assert!(!fixture.directory.path().join("etc/timezone").exists());
    }

    #[test]
    fn failures_are_reported_and_retried_after_a_delay() {
        let fixture = Fixture::new();
        let root = fixture.directory.path().to_owned();
        let attempts = Arc::new(Mutex::new(0u32));
        let counter = attempts.clone();
        let manager = Manager::with_host(
            fixture.engine.clone(),
            Mode::Native,
            Host {
                root: root.clone(),
                set_hostname: Box::new(move |_| {
                    *counter.lock().unwrap() += 1;
                    anyhow::bail!("setting the kernel hostname failed: synthetic")
                }),
            },
        )
        .unwrap();
        fixture.configure(system("fw-2", ""));
        let start = Instant::now();
        manager.reconcile(start);
        let status = manager.status().unwrap();
        assert_eq!(status["hostname"]["state"], "error");
        assert!(
            status["hostname"]["error"]
                .as_str()
                .unwrap()
                .contains("synthetic")
        );
        assert_eq!(status["hostname"]["observed"], "old");
        assert!(!root.join("etc/hostname").exists());
        manager.reconcile(start + Duration::from_secs(5));
        assert_eq!(*attempts.lock().unwrap(), 1);
        assert_eq!(manager.status().unwrap()["hostname"]["state"], "error");
        manager.reconcile(start + RETRY_AFTER + Duration::from_secs(1));
        assert_eq!(*attempts.lock().unwrap(), 2);
    }

    #[test]
    fn unknown_zone_is_rejected_at_submit_but_a_valid_zone_is_accepted() {
        let fixture = Fixture::new();
        let _manager = fixture.manager(Mode::Native);
        let mut engine = fixture.engine.lock().unwrap();
        let mut config = engine.saved_configuration().clone();
        config.system.timezone = "America/Nowhere".into();
        let reply = submit(&mut engine, &config);
        assert_eq!(reply.status, 422, "{}", reply.body);
        assert!(reply.body["error"].as_str().unwrap().contains("timezone"));
        config.system.timezone = "America/Chicago".into();
        assert_eq!(submit(&mut engine, &config).status, 202);
    }

    #[test]
    fn simulator_and_unsupported_modes_never_touch_the_host() {
        let fixture = Fixture::new();
        let manager = fixture.manager(Mode::Simulated);
        assert!(manager.timezones().contains(&"UTC".to_owned()));
        fixture.configure(system("sim-1", "Europe/London"));
        manager.reconcile(Instant::now());
        let status = manager.status().unwrap();
        assert_eq!(status["hostname"]["state"], "simulated");
        assert_eq!(status["timezone"]["state"], "simulated");
        assert_eq!(fixture.read("proc/sys/kernel/hostname"), "old\n");
        assert!(!fixture.directory.path().join("etc/hostname").exists());

        let unsupported = fixture.manager(Mode::Unsupported);
        assert!(unsupported.timezones().is_empty());
        unsupported.reconcile(Instant::now());
        let status = unsupported.status().unwrap();
        assert_eq!(status["hostname"]["state"], "unavailable");
        assert!(status["hostname"]["error"].as_str().is_some());
    }

    #[test]
    fn unsupported_backend_rejects_changed_host_settings() {
        let fixture = Fixture::new();
        let _manager = fixture.manager(Mode::Unsupported);
        let mut engine = fixture.engine.lock().unwrap();
        let mut config = engine.saved_configuration().clone();
        config.system.hostname = "fw-3".into();
        let reply = submit(&mut engine, &config);
        assert_eq!(reply.status, 422, "{}", reply.body);
    }

    #[test]
    #[ignore = "needs a disposable Linux container with CAP_SYS_ADMIN and NETCONTROL_INTEGRATION=1"]
    fn real_kernel_hostname_is_set_and_persisted() {
        assert_eq!(std::env::var("NETCONTROL_INTEGRATION").as_deref(), Ok("1"));
        let fixture = Fixture::new();
        let manager = Manager::with_host(
            fixture.engine.clone(),
            Mode::Native,
            Host {
                root: fixture.directory.path().to_owned(),
                set_hostname: Box::new(kernel_set_hostname),
            },
        )
        .unwrap();
        // The kernel value is real; /etc/hostname lives in the fixture, not the container.
        fs::write(
            fixture.directory.path().join("proc/sys/kernel/hostname"),
            "unused\n",
        )
        .unwrap();
        manager.host.apply_hostname("netcontrol-it").unwrap();
        assert_eq!(
            fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            "netcontrol-it"
        );
        assert_eq!(fixture.read("etc/hostname"), "netcontrol-it\n");
    }
}
