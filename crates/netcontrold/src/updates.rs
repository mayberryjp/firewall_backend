use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use netcontrol_package::update::{self, Manifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const ROOT: &str = "/var/lib/netcontrol-updates";
const UNIT: &str = "netcontrol-upgrade-worker.service";
const SERVICE: &str = "netcontrold.service";
const RECOVERY: &str = "[Unit]\nDescription=Recover interrupted Netcontrol upgrade\nAfter=local-fs.target\nBefore=netcontrold.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/var/lib/netcontrol-updates/helper --upgrade-recover\n\n[Install]\nWantedBy=multi-user.target\n";
const DEPENDENCY: &str = "[Unit]\nRequires=netcontrol-upgrade-recovery.service\nAfter=netcontrol-upgrade-recovery.service\n";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub repository: String,
    pub token_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repository: "mayberryjp/firewall_backend".into(),
            token_file: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub version: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub error: Option<String>,
    pub last_successful_version: Option<String>,
    destination: PathBuf,
    previous_sha256: String,
}

impl Job {
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({"id":self.id,"version":self.version,"status":self.status,"created_at":self.created_at,"updated_at":self.updated_at,"error":self.error,"last_successful_version":self.last_successful_version})
    }
    pub fn active(&self) -> bool {
        !matches!(self.status.as_str(), "succeeded" | "failed" | "rolled_back")
    }
}

pub struct Manager {
    config: Config,
    root: PathBuf,
}

fn now() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?)
}

fn safe_parents(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    for parent in path.ancestors().skip(1) {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "update path parents must be root-owned and not writable by other users"
        );
    }
    Ok(())
}

fn regular(path: &Path, private: bool) -> Result<()> {
    safe_parents(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "update file must be regular"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & if private { 0o077 } else { 0o022 } == 0,
            "update file ownership or permissions are unsafe"
        );
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

fn read(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    regular(path, private)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "update file {} exceeds {limit} byte limit",
        path.display()
    );
    Ok(bytes)
}

fn directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "update directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "update directory must be root-owned and private"
        );
    }
    Ok(())
}

fn atomic(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    atomic_write(path, executable, |file| {
        file.write_all(bytes)?;
        Ok(())
    })
}

fn atomic_write(
    path: &Path,
    executable: bool,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    let parent = path.parent().context("update path has no parent")?;
    let temporary = parent.join(format!(".netcontrol-{}", crate::identity::secret("")?));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if executable { 0o755 } else { 0o600 });
        }
        #[cfg(not(unix))]
        let _ = executable;
        let mut file = options.open(&temporary)?;
        write(&mut file)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(if executable {
                0o755
            } else {
                0o600
            }))?;
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn copy_and_hash(mut source: impl Read, destination: &mut impl Write) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = source.read(&mut buffer)?;
        if length == 0 {
            return Ok(hex::encode(digest.finalize()));
        }
        destination.write_all(&buffer[..length])?;
        digest.update(&buffer[..length]);
    }
}

fn executable_digest(path: &Path) -> Result<String> {
    regular(path, false)?;
    copy_and_hash(File::open(path)?, &mut std::io::sink())
        .with_context(|| format!("hash installed executable {}", path.display()))
}

fn atomic_executable(path: &Path, source: &Path, expected: Option<&str>) -> Result<String> {
    regular(source, false)?;
    let mut digest = String::new();
    atomic_write(path, true, |file| {
        digest = copy_and_hash(File::open(source)?, file)?;
        ensure!(
            expected.is_none_or(|expected| digest == expected),
            "executable digest does not match expected backup"
        );
        Ok(())
    })
    .with_context(|| format!("copy executable {} to {}", source.display(), path.display()))?;
    Ok(digest)
}

fn command(program: &str, arguments: &[&str]) -> Result<String> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("upgrade service command timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "upgrade service command failed: {program}"
    );
    ensure!(
        output.stdout.len() <= 64 * 1024,
        "upgrade command output too large"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn systemctl(arguments: &[&str]) -> Result<String> {
    command("systemctl", arguments)
}

fn show(property: &str) -> Result<String> {
    systemctl(&[
        "show",
        SERVICE,
        "--value",
        &format!("--property={property}"),
    ])
}

fn prepare_conntrack() -> Result<()> {
    command("modprobe", &["nf_conntrack"])?;
    command(
        "sysctl",
        &[
            "-w",
            "net.netfilter.nf_conntrack_acct=1",
            "net.netfilter.nf_conntrack_checksum=1",
        ],
    )?;
    for key in [
        "net.netfilter.nf_conntrack_acct",
        "net.netfilter.nf_conntrack_checksum",
    ] {
        ensure!(
            command("sysctl", &["-n", key])? == "1",
            "conntrack prerequisite did not take effect"
        );
    }
    for (path, bytes) in [
        (
            "/etc/sysctl.d/90-netcontrol-conntrack.conf",
            b"net.netfilter.nf_conntrack_acct = 1\nnet.netfilter.nf_conntrack_checksum = 1\n"
                .as_slice(),
        ),
        (
            "/etc/modules-load.d/netcontrol-conntrack.conf",
            b"nf_conntrack\n".as_slice(),
        ),
    ] {
        let path = Path::new(path);
        if path.try_exists()? {
            regular(path, false)?;
        }
        atomic(path, bytes, false)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
        }
        File::open(path)?.sync_all()?;
    }
    Ok(())
}

fn validate_config(config: &Config) -> Result<()> {
    let parts: Vec<_> = config.repository.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && part.len() <= 100
                && !part.starts_with('.')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))),
        "repository must be a GitHub owner/repository name"
    );
    ensure!(
        config
            .token_file
            .as_ref()
            .is_none_or(|path| path.is_absolute()),
        "update token path must be absolute"
    );
    Ok(())
}

fn parse_config(bytes: &[u8]) -> Result<Config> {
    let config: Config = serde_json::from_slice(bytes)
        .context("upgrade configuration must contain only repository and optional token_file; no signing key")?;
    validate_config(&config)?;
    Ok(config)
}

pub fn configure(path: &Path) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "upgrade bootstrap requires Linux"
    );
    #[cfg(unix)]
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "upgrade bootstrap requires root"
    );
    ensure!(
        path.is_absolute(),
        "upgrade configuration path must be absolute"
    );
    let parent = path
        .parent()
        .context("upgrade configuration needs a parent")?;
    safe_parents(parent)?;
    if !parent.try_exists()? {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    safe_parents(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            parse_config(&read(path, 4096, true)?)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic(path, &serde_json::to_vec_pretty(&Config::default())?, false)?;
        }
        Err(error) => return Err(error.into()),
    }
    println!(
        "GitHub HTTPS upgrade configuration ready: {}",
        path.display()
    );
    Ok(())
}

impl Manager {
    pub fn release_config(&self) -> Config {
        self.config.clone()
    }
    pub fn repository(&self) -> &str {
        &self.config.repository
    }
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
            "self-upgrade requires Ubuntu amd64 Linux"
        );
        #[cfg(unix)]
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "self-upgrade requires root"
        );
        let os = fs::read_to_string("/etc/os-release")?;
        ensure!(
            os.lines()
                .any(|line| matches!(line, "ID=ubuntu" | "ID=\"ubuntu\"")),
            "self-upgrade requires Ubuntu"
        );
        ensure!(
            Path::new("/run/systemd/system").is_dir(),
            "self-upgrade requires systemd"
        );
        let config = parse_config(&read(path, 4096, true)?)?;
        directory(Path::new(ROOT))?;
        Ok(Self {
            config,
            root: PathBuf::from(ROOT),
        })
    }

    pub fn job(&self) -> Result<Option<Job>> {
        let path = self.root.join("job.json");
        if !path.try_exists()? {
            return Ok(None);
        }
        let job: Job = serde_json::from_slice(&read(&path, 16 * 1024, true)?)?;
        update::version(&job.version)?;
        ensure!(
            matches!(
                job.status.as_str(),
                "queued"
                    | "downloading"
                    | "installing"
                    | "checking"
                    | "succeeded"
                    | "failed"
                    | "rolled_back"
                    | "recovery_required"
            ),
            "invalid upgrade job status"
        );
        ensure!(
            job.destination.is_absolute()
                && job
                    .destination
                    .file_name()
                    .is_some_and(|name| name == "netcontrold")
                && job.previous_sha256.len() == 64
                && hex::decode(&job.previous_sha256).is_ok(),
            "invalid upgrade recovery metadata"
        );
        Ok(Some(job))
    }

    fn save(&self, job: &mut Job, status: &str, error: Option<&str>) -> Result<()> {
        let mut next = job.clone();
        next.status = status.to_owned();
        next.updated_at = now()?;
        next.error = error.map(str::to_owned);
        atomic(
            &self.root.join("job.json"),
            &serde_json::to_vec(&next)?,
            false,
        )?;
        *job = next;
        Ok(())
    }

    pub fn active(&self) -> Result<bool> {
        Ok(self.job()?.is_some_and(|job| job.active()))
    }

    pub fn start(&self, requested: &str) -> Result<Job> {
        let parsed = update::version(requested)?;
        ensure!(
            parsed > update::version(netcontrol_core::RELEASE_VERSION)?,
            "requested version must be newer than the running version"
        );
        ensure!(!self.active()?, "another upgrade or recovery is active");
        let previous_version = self.job()?.and_then(|job| job.last_successful_version);
        if let Some(previous) = &previous_version {
            ensure!(
                parsed > update::version(previous)?,
                "requested version must be newer than the last successful upgrade"
            );
        }
        ensure!(
            show("MainPID")? == std::process::id().to_string(),
            "API daemon is not the installed systemd service"
        );
        let destination = std::env::current_exe()?.canonicalize()?;
        ensure!(
            destination
                .file_name()
                .is_some_and(|name| name == "netcontrold"),
            "service executable must be named netcontrold"
        );
        regular(&destination, false)?;
        let exec_start = show("ExecStart")?;
        ensure!(
            exec_start.matches("path=").count() == 1
                && exec_start.contains(&format!("path={} ;", destination.display())),
            "service ExecStart must directly run the current executable"
        );
        ensure!(
            matches!(
                systemctl(&["show", UNIT, "--property=ActiveState", "--value"])?.as_str(),
                "inactive" | "failed"
            ),
            "upgrade worker is already active"
        );
        let previous_sha256 = atomic_executable(&self.root.join("helper"), &destination, None)?;
        atomic(
            &self.root.join("config.json"),
            &serde_json::to_vec(&self.config)?,
            false,
        )?;
        let recovery = Path::new("/etc/systemd/system/netcontrol-upgrade-recovery.service");
        if recovery.try_exists()? {
            ensure!(
                read(recovery, 4096, false)? == RECOVERY.as_bytes(),
                "existing upgrade recovery unit differs from supplied unit"
            );
        } else {
            atomic(recovery, RECOVERY.as_bytes(), false)?;
        }
        let dropins = Path::new("/etc/systemd/system/netcontrold.service.d");
        if !dropins.try_exists()? {
            fs::create_dir(dropins)?;
        }
        let dependency = dropins.join("50-netcontrol-upgrade-recovery.conf");
        if dependency.try_exists()? {
            ensure!(
                read(&dependency, 4096, false)? == DEPENDENCY.as_bytes(),
                "existing upgrade recovery dependency differs from supplied configuration"
            );
        } else {
            atomic(&dependency, DEPENDENCY.as_bytes(), false)?;
        }
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "netcontrol-upgrade-recovery.service"])?;
        systemctl(&["start", "netcontrol-upgrade-recovery.service"])?;
        let timestamp = now()?;
        let mut job = Job {
            id: crate::identity::secret("upgrade_")?,
            version: requested.to_owned(),
            status: "queued".into(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            error: None,
            last_successful_version: previous_version,
            destination,
            previous_sha256,
        };
        self.save(&mut job, "queued", None)?;
        let launched = command(
            "systemd-run",
            &[
                "--unit=netcontrol-upgrade-worker",
                "--collect",
                "--property=Type=exec",
                "--property=Restart=on-failure",
                "--property=RestartSec=2s",
                "--property=UMask=0077",
                "/var/lib/netcontrol-updates/helper",
                "--upgrade-worker",
            ],
        );
        if launched.is_err() && systemctl(&["is-active", UNIT]).is_err() {
            self.save(
                &mut job,
                "failed",
                Some("could not launch independent upgrade worker"),
            )?;
            bail!("could not launch independent upgrade worker");
        }
        Ok(job)
    }

    pub fn mark_ready(&self) -> Result<()> {
        let digest = executable_digest(&std::env::current_exe()?)?;
        atomic(
            &self.root.join("ready.json"),
            &serde_json::to_vec(&serde_json::json!({"pid":std::process::id(),"sha256":digest}))?,
            false,
        )
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

pub fn initialize_release_check(
    engine: &mut netcontrol_core::Engine,
    config: Option<&Config>,
) -> Result<()> {
    engine.update_software_metadata(netcontrol_core::SoftwareMetadata {
        repository: config.map(|config| config.repository.clone()),
        ..Default::default()
    })
}

fn release_metadata(
    repository: &str,
    release: &Release,
) -> Result<netcontrol_core::SoftwareMetadata> {
    ensure!(
        !release.draft && !release.prerelease,
        "latest release must be published and stable"
    );
    let latest = update::version(
        release
            .tag_name
            .strip_prefix('v')
            .context("release tag must start with v")?,
    )?;
    let mut metadata = netcontrol_core::SoftwareMetadata::default();
    metadata.repository = Some(repository.into());
    metadata.latest_version = Some(latest);
    metadata.update_available = Some(latest > metadata.version);
    metadata.last_checked_at = Some(now()?.parse()?);
    Ok(metadata)
}

async fn discover_release(config: &Config) -> Result<netcontrol_core::SoftwareMetadata> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("netcontrol-release-checker"),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
    );
    if let Some(path) = &config.token_file {
        let token = String::from_utf8(read(path, 4096, true)?)?;
        let mut header =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.trim()))?;
        header.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, header);
    }
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client
        .get(format!(
            "https://api.github.com/repos/{}/releases/latest",
            config.repository
        ))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= 1024 * 1024),
        "release response exceeds size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 1024 * 1024,
            "release response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    let release: Release = serde_json::from_slice(&bytes)?;
    release_metadata(&config.repository, &release)
}

#[derive(Clone)]
pub struct ReleaseCheckControl {
    sender: tokio::sync::mpsc::Sender<tokio::sync::OwnedSemaphorePermit>,
    slot: std::sync::Arc<tokio::sync::Semaphore>,
}

pub struct ReleaseCheckRequests {
    receiver: tokio::sync::mpsc::Receiver<tokio::sync::OwnedSemaphorePermit>,
    slot: std::sync::Arc<tokio::sync::Semaphore>,
}

pub fn release_check_channel() -> (ReleaseCheckControl, ReleaseCheckRequests) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let slot = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    (
        ReleaseCheckControl {
            sender,
            slot: slot.clone(),
        },
        ReleaseCheckRequests { receiver, slot },
    )
}

impl ReleaseCheckControl {
    pub fn request(&self) -> Result<bool> {
        ensure!(!self.sender.is_closed(), "release check worker unavailable");
        let Ok(permit) = self.slot.clone().try_acquire_owned() else {
            return Ok(false);
        };
        self.sender
            .try_send(permit)
            .map_err(|_| anyhow::anyhow!("release check worker unavailable"))?;
        Ok(true)
    }
}

pub async fn monitor_releases(
    engine: std::sync::Arc<std::sync::Mutex<netcontrol_core::Engine>>,
    config: Option<Config>,
    stop: tokio::sync::watch::Receiver<bool>,
    requests: ReleaseCheckRequests,
) -> Result<()> {
    let repository = config.as_ref().map(|config| config.repository.clone());
    run_release_checks(engine, repository, stop, requests, || async {
        discover_release(
            config
                .as_ref()
                .context("release checker configuration missing")?,
        )
        .await
    })
    .await
}

async fn run_release_checks<F, Fut>(
    engine: std::sync::Arc<std::sync::Mutex<netcontrol_core::Engine>>,
    repository: Option<String>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    mut requests: ReleaseCheckRequests,
    mut check: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<netcontrol_core::SoftwareMetadata>>,
{
    if *stop.borrow() {
        return Ok(());
    }
    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let _permit = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return Ok(()); }
                continue;
            }
            Some(permit) = requests.receiver.recv(), if repository.is_some() => permit,
            _ = interval.tick(), if repository.is_some() => {
                let Ok(permit) = requests.slot.clone().try_acquire_owned() else {
                    continue;
                };
                permit
            }
        };
        let checked = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return Ok(()); }
                continue;
            }
            result = check() => result
        };
        let metadata = match checked {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(%error, "release check failed");
                netcontrol_core::SoftwareMetadata {
                    repository: repository.clone(),
                    last_checked_at: Some(now()?.parse()?),
                    error: Some(format!("Release check failed: {error}")),
                    ..Default::default()
                }
            }
        };
        engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine lock poisoned"))?
            .update_software_metadata(metadata)?;
    }
}
#[derive(Deserialize)]
struct Asset {
    id: u64,
    name: String,
    size: u64,
}

fn release_asset<'a>(release: &'a Release, name: &str, limit: u64) -> Result<&'a Asset> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches.next().context("missing release asset")?;
    ensure!(
        matches.next().is_none() && asset.id > 0 && asset.size > 0 && asset.size <= limit,
        "duplicate or invalid release asset"
    );
    Ok(asset)
}

impl Manager {
    fn download(&self, job: &Job) -> Result<(Manifest, Vec<u8>)> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static("netcontrol-updater"),
        );
        if let Some(path) = &self.config.token_file {
            let token = String::from_utf8(read(path, 4096, true)?)?;
            let mut value =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.trim()))?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        let client = reqwest::blocking::Client::builder()
            .default_headers(headers)
            .https_only(true)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        let base = format!("https://api.github.com/repos/{}", self.config.repository);
        let fetch = |url: &str, limit: usize, accept: &str| -> Result<Vec<u8>> {
            let response = client
                .get(url)
                .header(reqwest::header::ACCEPT, accept)
                .send()?
                .error_for_status()?;
            ensure!(
                response
                    .content_length()
                    .is_none_or(|length| length <= limit as u64),
                "release download exceeds size limit"
            );
            let mut bytes = Vec::new();
            response.take(limit as u64 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= limit, "release download exceeds size limit");
            Ok(bytes)
        };
        let release: Release = serde_json::from_slice(&fetch(
            &format!("{base}/releases/tags/v{}", job.version),
            1024 * 1024,
            "application/vnd.github+json",
        )?)?;
        ensure!(
            !release.draft
                && !release.prerelease
                && release.tag_name == format!("v{}", job.version),
            "release tag does not match requested version"
        );
        let asset = |name: &str, limit: usize| -> Result<Vec<u8>> {
            let metadata = release_asset(&release, name, limit as u64)?;
            fetch(
                &format!("{base}/releases/assets/{}", metadata.id),
                limit,
                "application/octet-stream",
            )
        };
        let bytes = asset("netcontrol-ubuntu-amd64.json", update::MANIFEST_LIMIT)?;
        let manifest = update::parse_manifest(&bytes, &job.version)?;
        ensure!(
            release_asset(&release, "netcontrold-ubuntu-amd64", manifest.size)?.size
                == manifest.size,
            "release binary metadata size does not match manifest"
        );
        let binary = asset("netcontrold-ubuntu-amd64", manifest.size as usize)?;
        update::verify_binary(&binary, &manifest)?;
        Ok((manifest, binary))
    }

    fn restore(&self, job: &mut Job, restart: bool) -> Result<()> {
        let previous = self.root.join("previous");
        ensure!(
            executable_digest(&previous)? == job.previous_sha256,
            "previous executable backup is invalid"
        );
        if restart {
            systemctl(&["stop", SERVICE])?;
        }
        if executable_digest(&job.destination)? != job.previous_sha256 {
            atomic_executable(&job.destination, &previous, Some(&job.previous_sha256))?;
        }
        if restart {
            systemctl(&["start", SERVICE])?;
        }
        self.save(job, "rolled_back", Some("replacement failed or was interrupted; previous executable restored; verify state and connectivity"))
    }

    fn apply(&self, job: &mut Job) -> Result<()> {
        self.save(job, "downloading", None)?;
        let (manifest, binary) = self.download(job)?;
        atomic(&self.root.join("candidate"), &binary, true)?;
        ensure!(
            command("/var/lib/netcontrol-updates/candidate", &["--help"])?
                .contains("--upgrade-config"),
            "replacement does not support self-upgrade configuration"
        );
        ensure!(
            command("/var/lib/netcontrol-updates/candidate", &["--version"])?.trim()
                == format!("netcontrold {}", manifest.version),
            "replacement embedded version does not match manifest"
        );
        ensure!(
            executable_digest(&job.destination)? == job.previous_sha256,
            "installed executable changed during download"
        );
        prepare_conntrack()?;
        atomic_executable(
            &self.root.join("previous"),
            &job.destination,
            Some(&job.previous_sha256),
        )?;
        self.save(job, "installing", None)?;
        systemctl(&["stop", SERVICE])?;
        atomic(&job.destination, &binary, true)?;
        self.save(job, "checking", None)?;
        systemctl(&["start", SERVICE])?;
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut stable = None;
        while Instant::now() < deadline {
            let ready = (|| -> Result<bool> {
                let value: serde_json::Value =
                    serde_json::from_slice(&read(&self.root.join("ready.json"), 4096, true)?)?;
                Ok(value["sha256"].as_str() == Some(manifest.sha256.as_str())
                    && value["pid"].as_u64().is_some_and(|pid| {
                        show("MainPID").is_ok_and(|current| current == pid.to_string())
                    })
                    && systemctl(&["is-active", SERVICE]).is_ok())
            })()
            .unwrap_or(false);
            if ready {
                let pid = show("MainPID")?;
                let (healthy_pid, start) =
                    stable.get_or_insert_with(|| (pid.clone(), Instant::now()));
                if *healthy_pid != pid {
                    *healthy_pid = pid;
                    *start = Instant::now();
                }
                if start.elapsed() >= Duration::from_secs(5) {
                    let previous = job.last_successful_version.clone();
                    job.last_successful_version = Some(job.version.clone());
                    if let Err(error) = self.save(job, "succeeded", None) {
                        job.last_successful_version = previous;
                        return Err(error);
                    }
                    return Ok(());
                }
            } else {
                stable = None;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        bail!("replacement failed readiness/stability checks")
    }
}

pub fn helper(recover: bool) -> Result<()> {
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "upgrade recovery requires Linux amd64"
    );
    directory(Path::new(ROOT))?;
    let manager = Manager {
        config: parse_config(&read(&Path::new(ROOT).join("config.json"), 4096, true)?)?,
        root: PathBuf::from(ROOT),
    };
    let lock_path = manager.root.join("worker.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(&lock_path)?;
    regular(&lock_path, true)?;
    lock.try_lock_exclusive()
        .context("upgrade worker already running")?;
    let Some(mut job) = manager.job()? else {
        return Ok(());
    };
    if !job.active() {
        return Ok(());
    }
    if matches!(
        job.status.as_str(),
        "installing" | "checking" | "recovery_required"
    ) {
        if let Err(error) = manager.restore(&mut job, !recover) {
            manager.save(
                &mut job,
                "recovery_required",
                Some("binary recovery failed; local console intervention required"),
            )?;
            return Err(error);
        }
        return Ok(());
    }
    if recover {
        return manager.save(
            &mut job,
            "failed",
            Some("upgrade interrupted before installation; installed executable unchanged"),
        );
    }
    if let Err(error) = manager.apply(&mut job) {
        tracing::error!(error = %error, "software upgrade failed");
        if matches!(job.status.as_str(), "installing" | "checking") {
            if manager.restore(&mut job, true).is_err() {
                manager.save(
                    &mut job,
                    "recovery_required",
                    Some("binary recovery failed; local console intervention required"),
                )?;
                bail!("software upgrade requires local recovery");
            }
        } else {
            manager.save(&mut job, "failed", Some("release download, validation, prerequisites or staging failed; installed executable unchanged"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_executable_streaming_exceeds_download_limit_with_bounded_buffers() {
        #[derive(Default)]
        struct Counter {
            bytes: u64,
            largest_write: usize,
        }
        impl Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes += bytes.len() as u64;
                self.largest_write = self.largest_write.max(bytes.len());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let length = update::BINARY_LIMIT + 1;
        let mut destination = Counter::default();
        let digest = copy_and_hash(std::io::repeat(0).take(length), &mut destination).unwrap();
        let mut expected = Sha256::new();
        for _ in 0..update::BINARY_LIMIT / 4096 {
            expected.update([0; 4096]);
        }
        expected.update([0]);
        assert_eq!(digest, hex::encode(expected.finalize()));
        assert_eq!(destination.bytes, length);
        assert!(destination.largest_write <= 64 * 1024);
    }

    #[test]
    fn executable_streaming_preserves_bytes_and_propagates_io_failures() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected read failure"))
            }
        }
        let mut destination = Vec::new();
        assert_eq!(
            copy_and_hash(&b"executable fixture"[..], &mut destination).unwrap(),
            hash(b"executable fixture")
        );
        assert_eq!(destination, b"executable fixture");
        assert!(copy_and_hash(BrokenReader, &mut std::io::sink()).is_err());
        assert!(copy_and_hash(&b"fixture"[..], &mut &mut [][..]).is_err());
    }

    fn job(status: &str) -> Job {
        Job {
            id: "upgrade_test".into(),
            version: "2026.10.29.1".into(),
            status: status.into(),
            created_at: "2026-10-24T00:00:00Z".into(),
            updated_at: "2026-10-24T00:00:00Z".into(),
            error: None,
            last_successful_version: None,
            destination: PathBuf::from("/usr/local/sbin/netcontrold"),
            previous_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn release_discovery_reports_current_newer_and_invalid_releases() {
        let release = |tag: &str| Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let current = release_metadata(
            "example/netcontrol",
            &release(&format!("v{}", netcontrol_core::RELEASE_VERSION)),
        )
        .unwrap();
        assert_eq!(current.update_available, Some(false));
        assert!(current.last_checked_at.is_some());
        let newer = release_metadata("example/netcontrol", &release("v9999.12.31.10")).unwrap();
        assert_eq!(newer.update_available, Some(true));
        let older = release_metadata("example/netcontrol", &release("v0001.01.01.1")).unwrap();
        assert_eq!(older.update_available, Some(false));
        for invalid in ["v1.2.3", "v2026.02.29.1", "2026.10.29.1", "v2026.10.29.01"] {
            assert!(release_metadata("example/netcontrol", &release(invalid)).is_err());
        }
        let mut invalid = release("v9999.12.31.10");
        invalid.draft = true;
        assert!(release_metadata("example/netcontrol", &invalid).is_err());
        invalid.draft = false;
        invalid.prerelease = true;
        assert!(release_metadata("example/netcontrol", &invalid).is_err());
    }

    #[test]
    fn upgrade_configuration_defaults_need_no_signing_key_and_reject_invalid_sources() {
        let config = Config::default();
        validate_config(&config).unwrap();
        assert_eq!(config.repository, "mayberryjp/firewall_backend");
        assert!(config.token_file.is_none());
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({"repository":"mayberryjp/firewall_backend","token_file":null})
        );
        parse_config(br#"{"repository":"example/netcontrol"}"#).unwrap();
        for bytes in [
            br#"{"repository":"https://example.test/a"}"#.as_slice(),
            br#"{"repository":"../a"}"#,
            br#"{"repository":"example/netcontrol","token_file":"relative"}"#,
            br#"{"repository":"example/netcontrol","public_key":"/etc/old.pub"}"#,
            br#"{"repository":"example/netcontrol","unknown":true}"#,
        ] {
            assert!(parse_config(bytes).is_err());
        }
    }

    #[test]
    fn release_assets_reject_missing_duplicate_empty_and_oversized_downloads() {
        let mut release = Release {
            tag_name: "v9999.12.31.1".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        assert!(release_asset(&release, "binary", 64).is_err());
        release.assets.push(Asset {
            id: 1,
            name: "binary".into(),
            size: 64,
        });
        assert_eq!(release_asset(&release, "binary", 64).unwrap().size, 64);
        assert!(release_asset(&release, "binary", 63).is_err());
        release.assets[0].size = 0;
        assert!(release_asset(&release, "binary", 64).is_err());
        release.assets[0].size = 64;
        release.assets.push(Asset {
            id: 2,
            name: "binary".into(),
            size: 64,
        });
        assert!(release_asset(&release, "binary", 64).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and a private fixture under /var/lib; no systemd or networking"]
    fn upgrade_bootstrap_creates_private_settings_and_preserves_or_rejects_existing_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::Builder::new()
            .prefix("netcontrol-bootstrap-")
            .tempdir_in("/var/lib")
            .unwrap();
        let path = root.path().join("settings").join("updates.json");
        configure(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let defaults = read(&path, 4096, true).unwrap();
        configure(&path).unwrap();
        assert_eq!(read(&path, 4096, true).unwrap(), defaults);
        let custom =
            br#"{"repository":"example/private","token_file":"/etc/netcontrol/github.token"}"#;
        atomic(&path, custom, false).unwrap();
        configure(&path).unwrap();
        assert_eq!(read(&path, 4096, true).unwrap(), custom);
        let invalid = br#"{"repository":"example/private","public_key":"/etc/old.pub"}"#;
        atomic(&path, invalid, false).unwrap();
        assert!(configure(&path).is_err());
        assert_eq!(read(&path, 4096, true).unwrap(), invalid);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(configure(&path).is_err());
        fs::remove_file(&path).unwrap();
        let target = root.path().join("operator-settings");
        atomic(&target, custom, false).unwrap();
        symlink(&target, &path).unwrap();
        assert!(configure(&path).is_err());
        assert_eq!(read(&target, 4096, true).unwrap(), custom);
    }
    #[tokio::test(start_paused = true)]
    async fn release_checks_run_at_startup_daily_persist_errors_and_stop() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let engine = Arc::new(Mutex::new(
            netcontrol_core::Engine::open(&path, Box::new(netcontrol_core::Simulator::new()))
                .unwrap(),
        ));
        let initial = engine.lock().unwrap().committed_revision();
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (_control, requests) = release_check_channel();
        let worker = tokio::spawn(run_release_checks(
            engine.clone(),
            Some("example/netcontrol".into()),
            receiver,
            requests,
            move || {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt > 0 {
                        bail!("synthetic release failure");
                    }
                    release_metadata(
                        "example/netcontrol",
                        &Release {
                            tag_name: "v9999.12.31.10".into(),
                            draft: false,
                            prerelease: false,
                            assets: vec![],
                        },
                    )
                }
            },
        ));
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            engine
                .lock()
                .unwrap()
                .saved_configuration()
                .software
                .update_available,
            Some(true)
        );
        tokio::time::advance(Duration::from_secs(86_399)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let metadata = engine
            .lock()
            .unwrap()
            .saved_configuration()
            .software
            .clone();
        assert_eq!(metadata.update_available, None);
        assert_eq!(metadata.latest_version, None);
        assert!(
            metadata
                .error
                .as_ref()
                .unwrap()
                .contains("synthetic release failure")
        );
        assert!(metadata.last_checked_at.is_some());
        assert_eq!(engine.lock().unwrap().committed_revision(), initial);
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
        drop(engine);
        let reopened =
            netcontrol_core::Engine::open(&path, Box::new(netcontrol_core::Simulator::new()))
                .unwrap();
        assert_eq!(reopened.saved_configuration().software, metadata);
    }

    #[tokio::test]
    async fn release_checker_cancels_inflight_checks_and_disabled_checks_do_not_run() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        for enabled in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let engine = Arc::new(Mutex::new(
                netcontrol_core::Engine::open(
                    &directory.path().join("state.json"),
                    Box::new(netcontrol_core::Simulator::new()),
                )
                .unwrap(),
            ));
            initialize_release_check(&mut engine.lock().unwrap(), None).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let (stop, receiver) = tokio::sync::watch::channel(false);
            let (_control, requests) = release_check_channel();
            let worker = tokio::spawn(run_release_checks(
                engine.clone(),
                enabled.then(|| "example/netcontrol".into()),
                receiver,
                requests,
                move || {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<netcontrol_core::SoftwareMetadata>>()
                },
            ));
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(enabled));
            stop.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                engine.lock().unwrap().saved_configuration().software,
                netcontrol_core::SoftwareMetadata::default()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn manual_release_checks_share_daily_worker_persist_results_and_cancel_on_shutdown() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let engine = Arc::new(Mutex::new(
            netcontrol_core::Engine::open(&path, Box::new(netcontrol_core::Simulator::new()))
                .unwrap(),
        ));
        let revision = engine.lock().unwrap().committed_revision();
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let gate = Arc::new(tokio::sync::Notify::new());
        let check_gate = gate.clone();
        let (control, requests) = release_check_channel();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(run_release_checks(
            engine.clone(),
            Some("example/netcontrol".into()),
            receiver,
            requests,
            move || {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let gate = check_gate.clone();
                async move {
                    gate.notified().await;
                    if attempt == 2 {
                        bail!("synthetic manual release failure");
                    }
                    release_metadata(
                        "example/netcontrol",
                        &Release {
                            tag_name: format!("v9999.12.31.{}", attempt + 10),
                            draft: false,
                            prerelease: false,
                            assets: vec![],
                        },
                    )
                }
            },
        ));
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!control.request().unwrap());
        gate.notify_one();
        tokio::task::yield_now().await;
        let previous = engine
            .lock()
            .unwrap()
            .saved_configuration()
            .software
            .clone();
        assert_eq!(
            previous.latest_version.unwrap().to_string(),
            "9999.12.31.10"
        );

        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(control.request().unwrap());
        assert!(!control.request().unwrap());
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!control.request().unwrap());
        assert_eq!(
            engine.lock().unwrap().saved_configuration().software,
            previous
        );
        gate.notify_one();
        tokio::task::yield_now().await;
        assert_eq!(
            engine
                .lock()
                .unwrap()
                .saved_configuration()
                .software
                .latest_version
                .unwrap()
                .to_string(),
            "9999.12.31.11"
        );

        assert!(control.request().unwrap());
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        tokio::time::advance(Duration::from_secs(82_800)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        gate.notify_one();
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert!(!control.request().unwrap());
        let failed = engine
            .lock()
            .unwrap()
            .saved_configuration()
            .software
            .clone();
        assert!(failed.latest_version.is_none());
        assert!(failed.update_available.is_none());
        assert!(failed.last_checked_at.is_some());
        assert!(
            failed
                .error
                .as_ref()
                .unwrap()
                .contains("synthetic manual release failure")
        );
        assert_eq!(engine.lock().unwrap().committed_revision(), revision);

        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
        assert!(control.request().is_err());
        assert_eq!(
            engine.lock().unwrap().saved_configuration().software,
            failed
        );
        drop(engine);
        let reopened =
            netcontrol_core::Engine::open(&path, Box::new(netcontrol_core::Simulator::new()))
                .unwrap();
        assert_eq!(reopened.saved_configuration().software, failed);
    }

    #[tokio::test]
    async fn release_checker_shutdown_discards_queued_manual_requests() {
        use std::sync::{Arc, Mutex};
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            netcontrol_core::Engine::open(
                &directory.path().join("state.json"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let (control, requests) = release_check_channel();
        assert!(control.request().unwrap());
        let (_stop, receiver) = tokio::sync::watch::channel(true);
        run_release_checks(
            engine.clone(),
            Some("example/netcontrol".into()),
            receiver,
            requests,
            || std::future::ready(Err(anyhow::anyhow!("source must not run"))),
        )
        .await
        .unwrap();
        assert!(control.request().is_err());
        assert_eq!(
            engine.lock().unwrap().saved_configuration().software,
            netcontrol_core::SoftwareMetadata::default(),
        );
    }

    #[test]
    fn only_terminal_jobs_release_the_maintenance_gate() {
        for status in [
            "queued",
            "downloading",
            "installing",
            "checking",
            "recovery_required",
        ] {
            assert!(job(status).active());
        }
        for status in ["succeeded", "failed", "rolled_back"] {
            assert!(!job(status).active());
        }
    }

    #[test]
    fn public_status_excludes_installation_paths_and_backup_metadata() {
        let value = job("queued").public();
        assert_eq!(value["version"], "2026.10.29.1");
        assert!(value.get("destination").is_none());
        assert!(value.get("previous_sha256").is_none());
        assert!(value["last_successful_version"].is_null());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and a private fixture under /var/lib; no systemd or networking"]
    fn interrupted_update_restores_verified_backup_without_touching_services() {
        let root = tempfile::Builder::new()
            .prefix("netcontrol-upgrade-test-")
            .tempdir_in("/var/lib")
            .unwrap();
        let manager = Manager {
            config: Config {
                repository: "example/netcontrol".into(),
                token_file: None,
            },
            root: root.path().to_owned(),
        };
        let mut state = job("checking");
        state.destination = root.path().join("netcontrold");
        state.previous_sha256 = hash(b"previous executable fixture");
        atomic(&state.destination, b"replacement executable fixture", true).unwrap();
        atomic(
            &root.path().join("previous"),
            b"previous executable fixture",
            true,
        )
        .unwrap();
        manager.save(&mut state, "checking", None).unwrap();
        assert!(manager.job().unwrap().unwrap().active());
        manager.restore(&mut state, false).unwrap();
        assert_eq!(
            read(&state.destination, 1024, false).unwrap(),
            b"previous executable fixture"
        );
        assert_eq!(manager.job().unwrap().unwrap().status, "rolled_back");
        atomic(&state.destination, b"replacement executable fixture", true).unwrap();
        atomic(
            &root.path().join("previous"),
            b"corrupt backup fixture",
            true,
        )
        .unwrap();
        assert!(manager.restore(&mut state, false).is_err());
        assert_eq!(
            read(&state.destination, 1024, false).unwrap(),
            b"replacement executable fixture"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and a private fixture under /var/lib; no systemd or networking"]
    fn large_installed_executable_readiness_copy_and_recovery_preserve_verified_bytes() {
        const READINESS_CHILD: &str = "NETCONTROL_LARGE_EXECUTABLE_READINESS_CHILD";
        if let Some(root) = std::env::var_os(READINESS_CHILD) {
            Manager {
                config: Config::default(),
                root: root.into(),
            }
            .mark_ready()
            .unwrap();
            return;
        }
        let root = tempfile::Builder::new()
            .prefix("netcontrol-large-executable-test-")
            .tempdir_in("/var/lib")
            .unwrap();
        let manager = Manager {
            config: Config::default(),
            root: root.path().to_owned(),
        };
        let destination = root.path().join("netcontrold");
        atomic(&destination, b"large source executable fixture", true).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&destination)
            .unwrap()
            .set_len(update::BINARY_LIMIT + 1)
            .unwrap();
        let digest = executable_digest(&destination).unwrap();
        let helper = root.path().join("helper");
        assert_eq!(
            atomic_executable(&helper, &destination, None).unwrap(),
            digest
        );
        assert!(atomic_executable(&helper, &destination, Some(&"0".repeat(64))).is_err());
        assert_eq!(executable_digest(&helper).unwrap(), digest);
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".netcontrol-")
        }));
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        assert!(atomic_executable(&helper, &link, None).is_err());
        let error = read(&destination, 1024, false).unwrap_err().to_string();
        assert!(error.contains("netcontrold") && error.contains("1024 byte limit"));
        atomic_executable(&root.path().join("previous"), &destination, Some(&digest)).unwrap();
        let mut state = job("checking");
        state.destination = destination.clone();
        state.previous_sha256 = digest.clone();
        atomic(&destination, b"replacement executable fixture", true).unwrap();
        manager.save(&mut state, "checking", None).unwrap();
        manager.restore(&mut state, false).unwrap();
        assert_eq!(
            fs::metadata(&destination).unwrap().len(),
            update::BINARY_LIMIT + 1
        );
        assert_eq!(executable_digest(&destination).unwrap(), digest);
        assert_eq!(manager.job().unwrap().unwrap().status, "rolled_back");

        let probe = root.path().join("readiness-probe");
        fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let length = fs::metadata(&probe)
            .unwrap()
            .len()
            .max(update::BINARY_LIMIT + 1);
        OpenOptions::new()
            .write(true)
            .open(&probe)
            .unwrap()
            .set_len(length)
            .unwrap();
        let child = Command::new(&probe)
            .args([
                "--exact",
                "updates::tests::large_installed_executable_readiness_copy_and_recovery_preserve_verified_bytes",
                "--ignored",
                "--nocapture",
            ])
            .env(READINESS_CHILD, root.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "readiness subprocess failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let ready: serde_json::Value =
            serde_json::from_slice(&read(&root.path().join("ready.json"), 4096, true).unwrap())
                .unwrap();
        assert_eq!(ready["pid"], pid);
        assert_eq!(ready["sha256"], executable_digest(&probe).unwrap());
    }
}
