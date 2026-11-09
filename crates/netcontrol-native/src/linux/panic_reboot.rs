use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

const SECONDS: i32 = 10;
const INTERVAL: Duration = Duration::from_secs(1);
const DIRECTORY: &str = "/etc/sysctl.d";
const FILE: &str = "99-netcontrol-panic.conf";
const CONTENT: &[u8] =
    b"# Owned by netcontrold; reclaimed every second in native host mode.\nkernel.panic = 10\n";

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

fn enforce_control(
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

fn enforce() -> Result<()> {
    enforce_control(read, || {
        control(true)?
            .write_all(b"10\n")
            .context("take over kernel.panic")
    })?;
    persist(Path::new(DIRECTORY)).context("persist mandatory panic reboot policy")
}

pub(super) struct Guard {
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
    error: Arc<Mutex<Option<String>>>,
}

impl Guard {
    pub fn new() -> Result<Self> {
        Self::start(enforce, INTERVAL)
    }

    fn start(
        mut enforce: impl FnMut() -> Result<()> + Send + 'static,
        interval: Duration,
    ) -> Result<Self> {
        enforce().context("claim mandatory panic reboot policy")?;
        let error = Arc::new(Mutex::new(None));
        let output = error.clone();
        let (stop, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("panic-reboot".into())
            .spawn(move || {
                loop {
                    match receiver.recv_timeout(interval) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    let result = enforce();
                    let next = result.err().map(|error| format!("{error:#}"));
                    let mut current = match output.lock() {
                        Ok(current) => current,
                        Err(error) => {
                            eprintln!("panic reboot enforcement status poisoned: {error}");
                            break;
                        }
                    };
                    if *current != next {
                        if let Some(error) = &next {
                            eprintln!("panic reboot enforcement failed; retrying: {error}");
                        } else {
                            eprintln!("panic reboot enforcement recovered");
                        }
                    }
                    *current = next;
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
            error,
        })
    }

    pub fn status(&self) -> Result<Value> {
        let error = self
            .error
            .lock()
            .map_err(|_| anyhow::anyhow!("panic reboot status poisoned"))?;
        let observed = read();
        let live_error = observed.as_ref().err().map(|error| format!("{error:#}"));
        let error = live_error.or_else(|| error.clone());
        let observed = observed.ok();
        let running = self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished());
        let drift = observed.map(|value| value != SECONDS);
        Ok(json!({
            "state": if running && error.is_none() && drift == Some(false) { "running" } else { "error" },
            "retrying": running, "error": error, "reboot_after_seconds": SECONDS,
            "observed_seconds": observed, "drift": drift, "enforcement_interval_seconds": 1,
            "persistence_file": format!("{DIRECTORY}/{FILE}")
        }))
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            eprintln!("panic reboot enforcement thread panicked");
        }
    }
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
            enforce_control(
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
        assert!(enforce_control(|| Ok(0), || Ok(())).is_err());
        assert!(enforce_control(|| anyhow::bail!("read failed"), || Ok(())).is_err());
        assert!(enforce_control(|| Ok(0), || anyhow::bail!("write failed")).is_err());
        Ok(())
    }

    #[test]
    fn worker_retries_recovers_and_stops_before_returning() -> Result<()> {
        let (events, received) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let guard = Guard::start(
            move || {
                let call = count.fetch_add(1, Ordering::SeqCst);
                events.send(call)?;
                if call == 1 {
                    anyhow::bail!("synthetic enforcement failure");
                }
                Ok(())
            },
            Duration::from_millis(5),
        )?;
        for expected in 0..4 {
            assert_eq!(received.recv_timeout(Duration::from_secs(2))?, expected);
        }
        drop(guard);
        let stopped = calls.load(Ordering::SeqCst);
        thread::sleep(Duration::from_millis(20));
        assert_eq!(calls.load(Ordering::SeqCst), stopped);
        assert!(Guard::start(|| anyhow::bail!("startup failure"), INTERVAL).is_err());
        Ok(())
    }

    #[test]
    fn worker_reclaims_external_drift() -> Result<()> {
        let value = Arc::new(AtomicI32::new(0));
        let observed = value.clone();
        let (events, received) = mpsc::channel();
        let guard = Guard::start(
            move || {
                enforce_control(
                    || Ok(observed.load(Ordering::SeqCst)),
                    || {
                        observed.store(SECONDS, Ordering::SeqCst);
                        Ok(())
                    },
                )?;
                events.send(())?;
                Ok(())
            },
            Duration::from_millis(5),
        )?;
        received.recv_timeout(Duration::from_secs(2))?;
        assert_eq!(value.load(Ordering::SeqCst), 10);
        value.store(0, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while value.load(Ordering::SeqCst) != 10 {
            assert!(
                std::time::Instant::now() < deadline,
                "drift was not reclaimed"
            );
            received.recv_timeout(Duration::from_secs(2))?;
        }
        drop(guard);
        assert_eq!(value.load(Ordering::SeqCst), 10);
        Ok(())
    }

    #[test]
    fn boot_file_is_reclaimed_without_touching_other_settings() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("root-owned sysctl persistence test requires root");
            return Ok(());
        }
        let directory =
            std::env::temp_dir().join(format!("netcontrol-panic-{}", std::process::id()));
        fs::create_dir(&directory)?;
        let result = (|| -> Result<()> {
            let unrelated = directory.join("10-unrelated.conf");
            fs::write(&unrelated, b"kernel.panic_on_oops = 0\n")?;
            persist(&directory)?;
            assert_eq!(fs::read(directory.join(FILE))?, CONTENT);
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
