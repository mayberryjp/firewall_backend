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
    pub public_key: PathBuf,
    pub token_file: Option<PathBuf>,
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

fn regular(path: &Path, private: bool) -> Result<()> {
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
    ensure!(bytes.len() <= limit, "update file exceeds size limit");
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
        file.write_all(bytes)?;
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

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
        config.public_key.is_absolute()
            && config
                .token_file
                .as_ref()
                .is_none_or(|path| path.is_absolute()),
        "update key/token paths must be absolute"
    );
    ensure!(
        read(&config.public_key, 32, false)?.len() == 32,
        "update public key must contain 32 binary bytes"
    );
    Ok(())
}

impl Manager {
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
        let config: Config = serde_json::from_slice(&read(path, 4096, true)?)?;
        validate_config(&config)?;
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
        let current = read(&destination, update::BINARY_LIMIT as usize, false)?;
        atomic(&self.root.join("helper"), &current, true)?;
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
            previous_sha256: hash(&current),
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
        atomic(
            &self.root.join("ready.json"),
            &serde_json::to_vec(
                &serde_json::json!({"pid":std::process::id(),"sha256":hash(&read(&std::env::current_exe()?, update::BINARY_LIMIT as usize, false)?)}),
            )?,
            false,
        )
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    id: u64,
    name: String,
    size: u64,
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
            !release.draft && release.tag_name == format!("v{}", job.version),
            "release tag does not match requested version"
        );
        let asset = |name: &str, limit: usize| -> Result<Vec<u8>> {
            let matches: Vec<_> = release
                .assets
                .iter()
                .filter(|asset| asset.name == name)
                .collect();
            ensure!(
                matches.len() == 1 && matches[0].size <= limit as u64,
                "missing, duplicate or oversized release asset"
            );
            fetch(
                &format!("{base}/releases/assets/{}", matches[0].id),
                limit,
                "application/octet-stream",
            )
        };
        let bytes = asset("netcontrol-ubuntu-amd64.json", update::MANIFEST_LIMIT)?;
        let signature = asset("netcontrol-ubuntu-amd64.sig", 64)?;
        let key: [u8; 32] = read(&self.config.public_key, 32, false)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid update key"))?;
        let manifest = update::verify_manifest(&bytes, &signature, &key, &job.version)?;
        let binary = asset("netcontrold-ubuntu-amd64", manifest.size as usize)?;
        update::verify_binary(&binary, &manifest)?;
        Ok((manifest, binary))
    }

    fn restore(&self, job: &mut Job, restart: bool) -> Result<()> {
        let previous = read(
            &self.root.join("previous"),
            update::BINARY_LIMIT as usize,
            false,
        )?;
        ensure!(
            hash(&previous) == job.previous_sha256,
            "previous executable backup is invalid"
        );
        if restart {
            systemctl(&["stop", SERVICE])?;
        }
        regular(&job.destination, false)?;
        if hash(&read(
            &job.destination,
            update::BINARY_LIMIT as usize,
            false,
        )?) != job.previous_sha256
        {
            atomic(&job.destination, &previous, true)?;
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
        let previous = read(&job.destination, update::BINARY_LIMIT as usize, false)?;
        ensure!(
            hash(&previous) == job.previous_sha256,
            "installed executable changed during download"
        );
        prepare_conntrack()?;
        atomic(&self.root.join("previous"), &previous, true)?;
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
        config: serde_json::from_slice(&read(&Path::new(ROOT).join("config.json"), 4096, true)?)?,
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

    fn job(status: &str) -> Job {
        Job {
            id: "upgrade_test".into(),
            version: "1.2.3".into(),
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
        assert_eq!(value["version"], "1.2.3");
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
                public_key: root.path().join("unused-key"),
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
}
