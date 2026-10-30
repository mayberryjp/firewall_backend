use anyhow::{Context, Result, ensure};
use rand::RngCore;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(crate) fn identifier() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub(crate) fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn private_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "private file must be daemon-owned, owner-only and not linked"
        );
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        if !create {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "invalid private file"
            );
        }
        Ok(options.open(path)?)
    }
}

pub(crate) fn read_private(path: &Path) -> Result<Vec<u8>> {
    let file = private_file(path, false)?;
    ensure!(
        file.metadata()?.len() <= 1 << 20,
        "private file exceeds limit"
    );
    let mut bytes = Vec::new();
    file.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1 << 20, "private file exceeds limit");
    Ok(bytes)
}

pub(crate) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(!path.try_exists()?, "private file already exists");
    write_private(path, bytes)
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.try_exists()? {
        private_file(path, false)?;
    }
    let parent = path.parent().context("private file has no parent")?;
    let pending = parent.join(format!("{}.pending", identifier()));
    let result = (|| {
        let mut file = private_file(&pending, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&pending, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(pending);
    }
    result
}
