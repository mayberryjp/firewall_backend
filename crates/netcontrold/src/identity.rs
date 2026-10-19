use anyhow::{Context, Result, bail};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

pub const SESSION_LIFETIME: u64 = 1800;
const SESSION_LIMIT: usize = 32;
const KEY_LIMIT: usize = 100;

#[derive(Debug)]
pub struct IdentityError {
    pub status: u16,
    pub message: &'static str,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for IdentityError {}

fn reject<T>(status: u16, message: &'static str) -> Result<T> {
    Err(IdentityError { status, message }.into())
}
fn denied<T>() -> Result<T> {
    reject(401, "invalid credentials or expired session")
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub fn secret(prefix: &str) -> Result<String> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("secure random source unavailable")?;
    Ok(format!("{prefix}{}", hex::encode(bytes)))
}
fn valid_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    username: String,
    password_hash: String,
    complete: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub id: String,
    pub name: String,
    pub masked: String,
    pub created_at: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    key: Key,
    token_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    schema: u32,
    account: Option<Account>,
    sessions: BTreeMap<String, u64>,
    keys: BTreeMap<String, StoredKey>,
}
impl Default for Database {
    fn default() -> Self {
        Self {
            schema: 1,
            account: None,
            sessions: BTreeMap::new(),
            keys: BTreeMap::new(),
        }
    }
}

pub struct Store {
    path: PathBuf,
    _lock: File,
    data: Database,
    healthy: bool,
}

fn private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("credential files must be regular files, not symlinks");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
        {
            bail!("credential files must be owner-only, owned by the daemon, and not hard-linked");
        }
    }
    Ok(())
}
pub(crate) fn secure_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let metadata = fs::metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            bail!("credential directory must be daemon-owned and not writable by other users");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut options = fs::DirBuilder::new();
        options.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(parent)?;
        secure_parent(path)?;
        let lock_path = path.with_file_name(format!(
            "{}.lock",
            path.file_name()
                .context("credential path needs filename")?
                .to_string_lossy()
        ));
        let lock = match create_private(&lock_path) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                private_file(&lock_path)?;
                OpenOptions::new().read(true).write(true).open(&lock_path)?
            }
            Err(error) => return Err(error),
        };
        lock.try_lock_exclusive()
            .context("credential database is locked by another process")?;
        let exists = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let data = if exists {
            private_file(path)?;
            if fs::metadata(path)?.len() > 1_048_576 {
                bail!("credential database exceeds size limit");
            }
            let data: Database = serde_json::from_slice(&fs::read(path)?)
                .context("invalid credential database; refusing to reset identity")?;
            Self::validate(&data)?;
            data
        } else {
            Database::default()
        };
        let store = Self {
            path: path.to_owned(),
            _lock: lock,
            data,
            healthy: true,
        };
        if !exists {
            store.persist(&store.data)?;
        }
        Ok(store)
    }
    fn validate(data: &Database) -> Result<()> {
        if data.schema != 1 || data.sessions.len() > SESSION_LIMIT || data.keys.len() > KEY_LIMIT {
            bail!("unsupported or invalid credential schema");
        }
        if data.account.is_none() && (!data.keys.is_empty() || !data.sessions.is_empty()) {
            bail!("orphaned credentials");
        }
        if let Some(a) = &data.account {
            if !valid_name(&a.username, 64) || !a.password_hash.starts_with("$argon2id$") {
                bail!("invalid stored account");
            }
            let hash = PasswordHash::new(&a.password_hash)
                .map_err(|_| anyhow::anyhow!("invalid password hash"))?;
            if hash.salt.is_none() || hash.hash.is_none() || a.password_hash.len() > 256 {
                bail!("incomplete password hash");
            }
        }
        let valid_hash = |s: &str| s.len() == 64 && hex::decode(s).is_ok();
        let mut hashes = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for (id, key) in &data.keys {
            if !valid_hash(id)
                || id != &key.key.id
                || !valid_name(&key.key.name, 80)
                || !valid_hash(&key.token_sha256)
                || !hashes.insert(&key.token_sha256)
                || !names.insert(&key.key.name)
                || key.key.masked.len() != 10
                || !key.key.masked.starts_with("nc_...")
                || time::OffsetDateTime::parse(
                    &key.key.created_at,
                    &time::format_description::well_known::Rfc3339,
                )
                .is_err()
            {
                bail!("invalid stored API key");
            }
        }
        if data
            .sessions
            .iter()
            .any(|(hash, expiry)| !valid_hash(hash) || *expiry == 0)
        {
            bail!("invalid stored session");
        }
        Ok(())
    }
    fn persist(&self, data: &Database) -> Result<()> {
        // The stable lock file survives atomic replacement of the data file.
        if self.path.exists() {
            private_file(&self.path)?;
        }
        let filename = self
            .path
            .file_name()
            .context("credential path needs filename")?;
        let pending = self.path.with_file_name(format!(
            ".{}.pending-{}",
            filename.to_string_lossy(),
            secret("")?
        ));
        let result = (|| -> Result<()> {
            let mut file = create_private(&pending)?;
            file.write_all(&serde_json::to_vec(data)?)?;
            file.sync_all()?;
            drop(file);
            Self::replace(&pending, &self.path).context("commit credential update")?;
            #[cfg(unix)]
            File::open(
                self.path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        result
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
        let from = from.canonicalize()?;
        let to = to
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?
            .join(to.file_name().context("credential path needs filename")?);
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        // Antivirus/indexers can transiently deny replacement; retry the atomic
        // operation itself, never unlinking the old database.
        for attempt in 0..8 {
            if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } != 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(5 | 32 | 33)) || attempt == 7 {
                return Err(error.into());
            }
            std::thread::sleep(std::time::Duration::from_millis(2 << attempt));
        }
        unreachable!("bounded replacement loop always returns")
    }
    fn update<T>(&mut self, change: impl FnOnce(&mut Database) -> Result<T>) -> Result<T> {
        self.check_health()?;
        let mut next = self.data.clone();
        let result = change(&mut next)?;
        if let Err(error) = self.persist(&next) {
            // A failed fsync can leave an uncertain durable outcome. Never overwrite
            // it using stale in-memory credentials; require an operator restart.
            self.healthy = false;
            return Err(error);
        }
        self.data = next;
        Ok(result)
    }
    pub fn check_health(&self) -> Result<()> {
        if !self.healthy {
            bail!("credential persistence failed; restart required");
        }
        Ok(())
    }
    pub fn status(&self) -> (bool, bool, &str) {
        self.data
            .account
            .as_ref()
            .map(|a| (true, a.complete, a.username.as_str()))
            .unwrap_or((false, false, ""))
    }
    fn add_session(data: &mut Database, token: &str) -> Result<()> {
        let now = now();
        data.sessions.retain(|_, expiry| *expiry > now);
        if data.sessions.len() >= SESSION_LIMIT {
            return reject(
                409,
                "too many active sessions; log out or wait for sessions to expire",
            );
        }
        data.sessions.insert(digest(token), now + SESSION_LIFETIME);
        Ok(())
    }
    pub fn setup(&mut self, username: &str, password: &str) -> Result<String> {
        self.check_health()?;
        if !valid_name(username, 64) || !(12..=72).contains(&password.len()) {
            return reject(400, "invalid username, password, or key name");
        }
        if self.data.account.is_some() {
            return reject(409, "device account already exists");
        }
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("password hashing failed"))?
            .to_string();
        let token = secret("session_")?;
        self.update(|data| {
            data.account = Some(Account {
                username: username.to_owned(),
                password_hash,
                complete: false,
            });
            Self::add_session(data, &token)
        })?;
        Ok(token)
    }
    pub fn login(&mut self, username: &str, password: &str) -> Result<String> {
        self.check_health()?;
        let Some(account) = &self.data.account else {
            return denied();
        };
        if password.len() > 72 {
            return denied();
        }
        let hash = PasswordHash::new(&account.password_hash)
            .map_err(|_| anyhow::anyhow!("invalid stored hash"))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_err()
            || account
                .username
                .as_bytes()
                .ct_eq(username.as_bytes())
                .unwrap_u8()
                != 1
        {
            return denied();
        }
        let token = secret("session_")?;
        self.update(|data| Self::add_session(data, &token))?;
        Ok(token)
    }
    pub fn session(&self, token: &str) -> Result<()> {
        self.check_health()?;
        if !token.is_empty()
            && self
                .data
                .sessions
                .get(&digest(token))
                .is_some_and(|expiry| *expiry > now())
        {
            Ok(())
        } else {
            denied()
        }
    }
    pub fn logout(&mut self, token: &str) -> Result<()> {
        self.session(token)?;
        self.update(|data| {
            data.sessions.remove(&digest(token));
            Ok(())
        })
    }
    pub fn keys(&self, token: &str) -> Result<Vec<Key>> {
        self.session(token)?;
        Ok(self.data.keys.values().map(|k| k.key.clone()).collect())
    }
    pub fn create_key(&mut self, token: &str, name: &str) -> Result<(Key, String)> {
        self.session(token)?;
        if !valid_name(name, 80) {
            return reject(400, "invalid username, password, or key name");
        }
        if self.data.keys.len() >= KEY_LIMIT {
            return reject(
                400,
                "invalid username, password, or key name: maximum of 100 API keys",
            );
        }
        if self.data.keys.values().any(|key| key.key.name == name) {
            return reject(
                400,
                "invalid username, password, or key name: key names must be unique",
            );
        }
        let value = secret("nc_")?;
        let id = secret("")?;
        let key = Key {
            id: id.clone(),
            name: name.to_owned(),
            masked: format!("nc_...{}", &value[value.len() - 4..]),
            created_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)?,
        };
        let stored = StoredKey {
            key: key.clone(),
            token_sha256: digest(&value),
        };
        self.update(|data| {
            data.keys.insert(id, stored);
            Ok(())
        })?;
        Ok((key, value))
    }
    pub fn delete_key(&mut self, token: &str, id: &str) -> Result<()> {
        self.session(token)?;
        if !self.data.keys.contains_key(id) {
            return reject(404, "API key not found");
        }
        self.update(|data| {
            data.keys.remove(id);
            Ok(())
        })
    }
    pub fn complete(&mut self, token: &str) -> Result<()> {
        self.session(token)?;
        if self.data.keys.is_empty() {
            return reject(409, "create and save an API key before finishing setup");
        }
        self.update(|data| {
            data.account.as_mut().context("missing account")?.complete = true;
            Ok(())
        })
    }
    pub fn authenticate(&self, token: &str) -> Option<Key> {
        if !self.healthy
            || token.len() != 67
            || !token.starts_with("nc_")
            || !self.data.account.as_ref().is_some_and(|a| a.complete)
        {
            return None;
        }
        let hash = digest(token);
        self.data
            .keys
            .values()
            .find(|key| {
                key.token_sha256
                    .as_bytes()
                    .ct_eq(hash.as_bytes())
                    .unwrap_u8()
                    == 1
            })
            .map(|key| key.key.clone())
    }
}
