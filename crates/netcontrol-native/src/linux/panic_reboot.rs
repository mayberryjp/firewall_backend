use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const SECONDS: i32 = 10;
const DIRECTORY: &str = "/etc/sysctl.d";
const FILE: &str = "99-netcontrol-panic.conf";
const CONTENT: &[u8] =
    b"# Owned by netcontrold; established at startup in native host mode.\nkernel.panic = 10\n";

fn control(write: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/proc/sys/kernel/panic")
        .context("open mandatory kernel.panic control")?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0
            && stat.f_type as u64 == libc::PROC_SUPER_MAGIC as u64,
        "kernel.panic control must be procfs"
    );
    Ok(file)
}

fn read() -> Result<i32> {
    let mut text = String::new();
    control(false)?.take(33).read_to_string(&mut text)?;
    ensure!(text.len() <= 32, "oversized kernel.panic value");
    text.trim().parse().context("invalid kernel.panic value")
}

fn take_over_control(
    mut read: impl FnMut() -> Result<i32>,
    mut write: impl FnMut() -> Result<()>,
) -> Result<()> {
    if read()? != SECONDS {
        write()?;
    }
    ensure!(read()? == SECONDS, "kernel.panic takeover did not converge");
    Ok(())
}

fn persist(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory).context("create panic reboot sysctl directory")?;
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "panic reboot sysctl directory must be root-owned, non-symlink and not writable by others"
    );
    let path = directory.join(FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && metadata.uid() == 0 && metadata.nlink() == 1,
                "refusing unsafe panic reboot sysctl file"
            );
            if metadata.mode() & 0o777 == 0o644 && fs::read(&path)? == CONTENT {
                return Ok(());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let pending = directory.join(format!(".{FILE}.writing"));
    match fs::symlink_metadata(&pending) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && metadata.uid() == 0 && metadata.nlink() == 1,
                "refusing unsafe panic reboot staging file"
            );
            fs::remove_file(&pending)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)?;
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
    file.write_all(CONTENT)?;
    file.sync_all()?;
    fs::rename(&pending, &path)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

pub(super) fn take_over() -> Result<()> {
    take_over_control(read, || {
        control(true)?
            .write_all(b"10\n")
            .context("take over kernel.panic")
    })
    .context("claim mandatory panic reboot policy")?;
    persist(Path::new(DIRECTORY)).context("persist mandatory panic reboot policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    #[test]
    fn takes_over_disabled_immediate_and_other_delays_and_verifies_readback() -> Result<()> {
        for original in [0, -1, 1, 30, 10] {
            let value = AtomicI32::new(original);
            let writes = AtomicUsize::new(0);
            take_over_control(
                || Ok(value.load(Ordering::SeqCst)),
                || {
                    writes.fetch_add(1, Ordering::SeqCst);
                    value.store(SECONDS, Ordering::SeqCst);
                    Ok(())
                },
            )?;
            assert_eq!(value.load(Ordering::SeqCst), 10);
            assert_eq!(writes.load(Ordering::SeqCst), usize::from(original != 10));
        }
        assert!(take_over_control(|| Ok(0), || Ok(())).is_err());
        assert!(take_over_control(|| anyhow::bail!("read failed"), || Ok(())).is_err());
        assert!(take_over_control(|| Ok(0), || anyhow::bail!("write failed")).is_err());
        Ok(())
    }

    #[test]
    fn startup_rechecks_an_already_correct_value() {
        let mut observations = [Ok(SECONDS), Ok(0)].into_iter();
        assert!(
            take_over_control(
                || observations.next().unwrap(),
                || panic!("already correct value must not be written"),
            )
            .is_err()
        );
        let mut observations = [Ok(SECONDS), Err(anyhow::anyhow!("readback failed"))].into_iter();
        assert!(
            take_over_control(
                || observations.next().unwrap(),
                || panic!("already correct value must not be written"),
            )
            .is_err()
        );
    }

    #[test]
    fn startup_persists_boot_file_without_touching_other_settings() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("root-owned sysctl persistence test requires root");
            return Ok(());
        }
        let directory = Path::new(".").join(format!(".netcontrol-panic-{}", std::process::id()));
        fs::create_dir(&directory)?;
        let result = (|| -> Result<()> {
            let unrelated = directory.join("10-unrelated.conf");
            fs::write(&unrelated, b"kernel.panic_on_oops = 0\n")?;
            persist(&directory)?;
            assert_eq!(fs::read(directory.join(FILE))?, CONTENT);
            let metadata = fs::metadata(directory.join(FILE))?;
            assert_eq!(metadata.uid(), 0);
            assert_eq!(metadata.mode() & 0o777, 0o644);
            persist(&directory)?;
            assert_eq!(fs::metadata(directory.join(FILE))?.ino(), metadata.ino());
            fs::write(directory.join(FILE), b"kernel.panic = 0\n")?;
            persist(&directory)?;
            persist(&directory)?;
            assert_eq!(fs::read(directory.join(FILE))?, CONTENT);
            assert_eq!(fs::read(&unrelated)?, b"kernel.panic_on_oops = 0\n");
            fs::remove_file(directory.join(FILE))?;
            std::os::unix::fs::symlink(&unrelated, directory.join(FILE))?;
            assert!(persist(&directory).is_err());
            assert_eq!(fs::read(&unrelated)?, b"kernel.panic_on_oops = 0\n");
            fs::remove_file(directory.join(FILE))?;
            std::os::unix::fs::symlink(&unrelated, directory.join(format!(".{FILE}.writing")))?;
            assert!(persist(&directory).is_err());
            Ok(())
        })();
        fs::remove_dir_all(&directory)?;
        result
    }
}
