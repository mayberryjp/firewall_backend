use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const SCHEMA: &str = "netcontrol-rust-state-v2";
const MAX_STATE: u64 = 256 * 1024 * 1024;
#[derive(Debug)]
pub(crate) struct DurabilityError(String);
impl std::fmt::Display for DurabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "journal publication durability is uncertain; restart required: {}",
            self.0
        )
    }
}
impl std::error::Error for DurabilityError {}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    schema: String,
    sha256: String,
    state: T,
}

pub(crate) struct Store {
    path: PathBuf,
    _lock: File,
    #[cfg(test)]
    pub fail_after: std::cell::Cell<Option<usize>>,
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.file_name().is_some(),
            "state path requires a file name"
        );
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .context("create state directory")?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent).context("create state directory")?;
        let lock_path = PathBuf::from(format!("{}.lock", path.display()));
        for candidate in [path, lock_path.as_path()] {
            match fs::symlink_metadata(candidate) {
                Ok(metadata) => ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "state and lock paths must be regular files, not links"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&lock_path).context("open state lock")?;
        lock.try_lock_exclusive()
            .context("state is locked by another process")?;
        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
            #[cfg(test)]
            fail_after: std::cell::Cell::new(None),
        })
    }
    pub fn load<T: serde::de::DeserializeOwned>(&self) -> Result<Option<T>> {
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure!(f.metadata()?.len() <= MAX_STATE, "state exceeds size limit");
        let mut bytes = vec![];
        f.read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty(),
            "state is empty/corrupt; refusing to initialize over existing data"
        );
        let envelope: Envelope<Box<serde_json::value::RawValue>> =
            serde_json::from_slice(&bytes)
                .context("invalid/incompatible Rust state; Go journals are not accepted")?;
        ensure!(
            envelope.schema == SCHEMA,
            "incompatible state schema {:?}; expected {:?}; no automatic conversion. For numeric v1 state, stop the daemon and preview netcontrol-state-convert --date-revisions; see docs/BUILD_AND_INSTALL.md",
            envelope.schema,
            SCHEMA
        );
        let hash = hex::encode(Sha256::digest(envelope.state.get().as_bytes()));
        ensure!(
            hash == envelope.sha256,
            "state checksum mismatch; refusing corrupt data"
        );
        let state = serde_json::from_str(envelope.state.get())
            .context("invalid/incompatible Rust state payload")?;
        Ok(Some(state))
    }
    pub fn save<T: Serialize>(&self, state: &T) -> Result<()> {
        #[cfg(test)]
        if let Some(left) = self.fail_after.get() {
            if left == 0 {
                self.fail_after.set(None);
                anyhow::bail!("injected journal write failure");
            }
            self.fail_after.set(Some(left - 1));
        }
        let state = serde_json::value::to_raw_value(state)?;
        let hash = hex::encode(Sha256::digest(state.get().as_bytes()));
        let envelope = Envelope {
            schema: SCHEMA.into(),
            sha256: hash,
            state,
        };
        let data = serde_json::to_vec(&envelope)?;
        ensure!(data.len() as u64 <= MAX_STATE, "state exceeds size limit");
        let mut random = [0u8; 16];
        rand::thread_rng().try_fill_bytes(&mut random)?;
        let pending = PathBuf::from(format!(
            "{}.pending-{}",
            self.path.display(),
            hex::encode(random)
        ));
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&pending).context("create pending journal")?;
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);
            replace(&pending, &self.path).context("atomically replace journal")?;
            #[cfg(unix)]
            {
                let parent = self
                    .path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|e| anyhow::Error::new(DurabilityError(e.to_string())))?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        result
    }
}
#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to)?;
    Ok(())
}
#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let from = fs::canonicalize(from).context("resolve extended-length pending path")?;
    let filename = to
        .file_name()
        .context("journal destination requires a filename")?;
    let parent = to
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let to = fs::canonicalize(parent)
        .context("resolve extended-length journal directory")?
        .join(filename);
    let from: Vec<_> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<_> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // Indexers/antivirus can briefly deny replacement even when our handles are closed.
    // Each attempt remains atomic; never remove the prior journal to work around a denial.
    retry_windows_publication(|| {
        // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?;
    Ok(())
}

#[cfg(windows)]
fn retry_windows_publication(
    mut publish: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match publish() {
            Ok(()) => return Ok(()),
            Err(error) => {
                if attempt >= 7 || !matches!(error.raw_os_error(), Some(5 | 32 | 33)) {
                    return Err(error);
                }
                std::thread::sleep(std::time::Duration::from_millis(2 << attempt));
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_verification_uses_saved_payload_not_current_field_order() {
        #[derive(Serialize)]
        struct WrittenState {
            label: String,
            count: u32,
        }
        #[derive(Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct ReadState {
            count: u32,
            label: String,
        }
        let directory = std::env::temp_dir().join(format!(
            "netcontrol-checksum-{:032x}",
            rand::random::<u128>()
        ));
        let path = directory.join("state.json");
        let store = Store::open(&path).unwrap();
        store
            .save(&WrittenState {
                label: "synthetic".into(),
                count: 7,
            })
            .unwrap();
        let saved = fs::read(&path).unwrap();
        let loaded = store.load::<ReadState>();
        assert_eq!(fs::read(&path).unwrap(), saved);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
        assert_eq!(
            loaded.unwrap(),
            Some(ReadState {
                count: 7,
                label: "synthetic".into(),
            })
        );
    }

    #[test]
    fn checksum_validation_precedes_defaults_and_rejects_tampered_or_unknown_state() {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CurrentState {
            desired: crate::Config,
        }
        let directory = std::env::temp_dir().join(format!(
            "netcontrol-checksum-model-{:032x}",
            rand::random::<u128>()
        ));
        let path = directory.join("state.json");
        let store = Store::open(&path).unwrap();
        store.save(&serde_json::json!({"desired": {}})).unwrap();
        let saved = fs::read(&path).unwrap();
        let loaded = store.load::<CurrentState>();
        assert_eq!(fs::read(&path).unwrap(), saved);

        let mut envelope: Envelope<Box<serde_json::value::RawValue>> =
            serde_json::from_slice(&saved).unwrap();
        envelope.state = serde_json::value::to_raw_value(
            &serde_json::json!({"desired": {"ipv6_enabled": false}}),
        )
        .unwrap();
        let tampered = serde_json::to_vec(&envelope).unwrap();
        fs::write(&path, &tampered).unwrap();
        let corruption = store.load::<CurrentState>().unwrap_err().to_string();
        assert_eq!(fs::read(&path).unwrap(), tampered);

        store
            .save(&serde_json::json!({"desired": {"unexpected_field": true}}))
            .unwrap();
        let invalid = fs::read(&path).unwrap();
        let incompatible = store.load::<CurrentState>().unwrap_err().to_string();
        assert_eq!(fs::read(&path).unwrap(), invalid);
        drop(store);
        fs::remove_dir_all(directory).unwrap();

        assert!(loaded.unwrap().unwrap().desired.ipv6_enabled);
        assert!(corruption.contains("checksum mismatch"));
        assert!(incompatible.contains("invalid/incompatible Rust state payload"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::retry_windows_publication;

    #[test]
    fn publication_retries_transient_denials_but_propagates_other_errors() {
        let mut attempts = 0;
        retry_windows_publication(|| {
            attempts += 1;
            if attempts < 3 {
                Err(std::io::Error::from_raw_os_error(5))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 3);
        let mut attempts = 0;
        let error = retry_windows_publication(|| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(87))
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.raw_os_error(), Some(87));
    }

    #[test]
    fn publication_retry_count_is_bounded() {
        let mut attempts = 0;
        let error = retry_windows_publication(|| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(32))
        })
        .unwrap_err();
        assert_eq!(attempts, 8);
        assert_eq!(error.raw_os_error(), Some(32));
    }
}
