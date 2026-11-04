use super::super::model::RpsIdentity;
use anyhow::{Context, Result, ensure};
use netcontrol_core::{cpu_mask, parse_cpu_list, parse_cpu_mask, rps_target, validate_rps};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::PathBuf,
};

pub(super) struct Io {
    net: PathBuf,
    online: PathBuf,
    boot: PathBuf,
    sysfs: bool,
}

fn text(file: File) -> Result<String> {
    let mut value = String::new();
    file.take(65537).read_to_string(&mut value)?;
    ensure!(value.len() <= 65536, "oversized RPS source");
    Ok(value.trim().to_owned())
}

fn child(directory: &File, name: &str, write: bool, is_directory: bool) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let flags = if write {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    } | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if is_directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    ensure!(
        fd >= 0,
        "open RPS source: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_values(values: &BTreeMap<String, String>) -> Result<()> {
    ensure!(values.len() <= 128, "RPS transaction queue limit exceeded");
    for (key, value) in values {
        validate_rps(&[(key.clone(), value.clone())].into())?;
    }
    Ok(())
}

impl Io {
    pub(super) fn system() -> Self {
        Self {
            net: "/sys/class/net".into(),
            online: "/sys/devices/system/cpu/online".into(),
            boot: "/proc/sys/kernel/random/boot_id".into(),
            sysfs: true,
        }
    }

    fn interface(&self, name: &str) -> Result<File> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(self.net.join(name))
            .with_context(|| format!("open RPS interface {name}"))?;
        if self.sysfs {
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } == 0
                    && stat.f_type as u64 == libc::SYSFS_MAGIC as u64,
                "RPS controls must reside on sysfs"
            );
            ensure!(
                fs::symlink_metadata(self.net.join(name).join("device"))?
                    .file_type()
                    .is_symlink(),
                "RPS tuning requires a physical Ethernet device"
            );
        }
        Ok(directory)
    }

    fn identity(&self, directory: &File) -> Result<RpsIdentity> {
        let index = text(child(directory, "ifindex", false, false)?)?.parse()?;
        let mac = text(child(directory, "address", false, false)?)?;
        let boot = text(File::open(&self.boot)?)?;
        ensure!(
            index > 0 && !mac.is_empty() && !boot.is_empty(),
            "invalid RPS interface identity"
        );
        Ok(RpsIdentity { index, mac, boot })
    }

    fn queue(&self, directory: &File, queue: &str, write: bool) -> Result<File> {
        let queues = child(directory, "queues", false, true)?;
        let queue = child(&queues, queue, false, true)?;
        child(&queue, "rps_cpus", write, false)
    }

    fn check_identity(actual: &RpsIdentity, expected: &RpsIdentity) -> Result<()> {
        crate::ensure_unchanged(
            actual.mac == expected.mac
                && (actual.boot != expected.boot || actual.index == expected.index),
            "RPS interface identity changed",
        )
    }

    fn one(
        &self,
        key: &str,
        expected: Option<&RpsIdentity>,
        writable: bool,
    ) -> Result<(String, RpsIdentity)> {
        let (name, queue) = rps_target(key)?;
        let directory = self.interface(name)?;
        let identity = self.identity(&directory)?;
        if let Some(expected) = expected {
            Self::check_identity(&identity, expected)?;
        }
        let mask = cpu_mask(&parse_cpu_mask(&text(
            self.queue(&directory, queue, false)?,
        )?)?);
        if writable {
            self.queue(&directory, queue, true)?;
        }
        Self::check_identity(&self.identity(&self.interface(name)?)?, &identity)?;
        Ok((mask, identity))
    }

    pub(super) fn read(
        &self,
        values: &BTreeMap<String, String>,
        expected: &BTreeMap<String, RpsIdentity>,
    ) -> Result<(BTreeMap<String, String>, BTreeMap<String, RpsIdentity>)> {
        validate_values(values)?;
        let mut masks = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for key in values.keys() {
            let (name, _) = rps_target(key)?;
            let (mask, identity) = self
                .one(key, expected.get(name), false)
                .with_context(|| format!("read RPS {key}"))?;
            masks.insert(key.clone(), mask);
            identities.insert(name.to_owned(), identity);
        }
        Ok((masks, identities))
    }

    pub(super) fn preflight(
        &self,
        values: &BTreeMap<String, String>,
        expected: &BTreeMap<String, RpsIdentity>,
    ) -> Result<()> {
        validate_values(values)?;
        if values.is_empty() {
            return Ok(());
        }
        let online = parse_cpu_list(&text(File::open(&self.online)?)?)?;
        ensure!(!online.is_empty(), "online CPUs unavailable");
        for (key, mask) in values {
            ensure!(
                parse_cpu_mask(mask)?.is_subset(&online),
                "RPS {key} selects offline CPUs"
            );
            let (name, _) = rps_target(key)?;
            self.one(key, expected.get(name), true)
                .with_context(|| format!("preflight RPS {key}"))?;
        }
        Ok(())
    }

    pub(super) fn write(
        &self,
        values: &BTreeMap<String, String>,
        expected: &BTreeMap<String, RpsIdentity>,
    ) -> Result<()> {
        self.preflight(values, expected)?;
        for (key, value) in values {
            let (name, queue) = rps_target(key)?;
            let (current, identity) = self.one(key, expected.get(name), false)?;
            if &current == value {
                continue;
            }
            let directory = self.interface(name)?;
            Self::check_identity(&self.identity(&directory)?, &identity)?;
            self.queue(&directory, queue, true)?
                .write_all(format!("{value}\n").as_bytes())
                .with_context(|| format!("write RPS {key}"))?;
            let (observed, _) = self.one(key, Some(&identity), false)?;
            ensure!(
                observed == *value,
                "kernel rejected exact RPS mask for {key}"
            );
        }
        Ok(())
    }

    pub(super) fn queues(&self, name: &str) -> Result<Vec<(String, String)>> {
        let directory = self.interface(name)?;
        let identity = self.identity(&directory)?;
        let mut result = Vec::new();
        for (index, entry) in fs::read_dir(self.net.join(name).join("queues"))?.enumerate() {
            ensure!(index < 8192, "too many interface queues");
            let entry = entry?;
            let queue = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 queue"))?;
            if !queue.starts_with("rx-") {
                continue;
            }
            ensure!(result.len() < 4096, "too many RX queues");
            let (mask, _) = self.one(&format!("{name}/{queue}"), Some(&identity), false)?;
            result.push((queue, mask));
        }
        result.sort();
        Ok(result)
    }

    pub(super) fn irqs(&self, name: &str) -> Result<Vec<u32>> {
        self.interface(name)?;
        let device = self.net.join(name).join("device");
        let mut irqs = std::collections::BTreeSet::new();
        match fs::read_dir(device.join("msi_irqs")) {
            Ok(entries) => {
                for (index, entry) in entries.enumerate() {
                    ensure!(index < 256, "too many NIC IRQs");
                    irqs.insert(
                        entry?
                            .file_name()
                            .to_str()
                            .context("invalid IRQ filename")?
                            .parse()?,
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if irqs.is_empty() {
            let irq: u32 = text(File::open(device.join("irq"))?)?.parse()?;
            ensure!(irq > 0, "NIC IRQ association unavailable");
            irqs.insert(irq);
        }
        Ok(irqs.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "netcontrol-rps-{}-{}",
                std::process::id(),
                time::OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            fs::create_dir_all(root.join("eno1/queues/rx-0")).unwrap();
            fs::write(root.join("eno1/ifindex"), "3\n").unwrap();
            fs::write(root.join("eno1/address"), "02:00:00:00:00:01\n").unwrap();
            fs::write(root.join("eno1/queues/rx-0/rps_cpus"), "00\n").unwrap();
            fs::write(root.join("online"), "0-3\n").unwrap();
            fs::write(root.join("boot"), "boot-a\n").unwrap();
            Self(root)
        }
        fn io(&self) -> Io {
            Io {
                net: self.0.clone(),
                online: self.0.join("online"),
                boot: self.0.join("boot"),
                sysfs: false,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn rps_io_capture_apply_restore_and_identity_guards() {
        let f = Fixture::new();
        let io = f.io();
        let target = [("eno1/rx-0".into(), "c".into())].into();
        let (before, identity) = io.read(&target, &BTreeMap::new()).unwrap();
        assert_eq!(before["eno1/rx-0"], "0");
        io.write(&target, &identity).unwrap();
        assert_eq!(io.read(&target, &identity).unwrap().0, target);
        io.write(&before, &identity).unwrap();
        assert_eq!(io.read(&target, &identity).unwrap().0, before);
        fs::write(f.0.join("eno1/ifindex"), "4\n").unwrap();
        assert!(io.write(&target, &identity).is_err());
        fs::write(f.0.join("boot"), "boot-b\n").unwrap();
        io.write(&target, &identity).unwrap();
        fs::write(f.0.join("eno1/address"), "02:00:00:00:00:02\n").unwrap();
        assert!(io.write(&target, &identity).is_err());
    }

    #[test]
    fn rps_io_preflights_every_queue_and_rejects_offline_symlink_and_non_sysfs() {
        let f = Fixture::new();
        let io = f.io();
        let values = [
            ("eno1/rx-0".into(), "2".into()),
            ("eno1/rx-1".into(), "4".into()),
        ]
        .into();
        assert!(io.write(&values, &BTreeMap::new()).is_err());
        assert_eq!(
            fs::read_to_string(f.0.join("eno1/queues/rx-0/rps_cpus")).unwrap(),
            "00\n"
        );
        assert!(
            io.preflight(
                &[("eno1/rx-0".into(), "10".into())].into(),
                &BTreeMap::new()
            )
            .is_err()
        );
        fs::rename(f.0.join("eno1/queues/rx-0/rps_cpus"), f.0.join("mask")).unwrap();
        std::os::unix::fs::symlink(f.0.join("mask"), f.0.join("eno1/queues/rx-0/rps_cpus"))
            .unwrap();
        assert!(
            io.preflight(&[("eno1/rx-0".into(), "2".into())].into(), &BTreeMap::new())
                .is_err()
        );
        let mut strict = io;
        strict.sysfs = true;
        assert!(strict.queues("eno1").is_err());
    }

    #[test]
    fn rps_io_failed_readback_recovers_from_a_serialized_capture() {
        let f = Fixture::new();
        let io = f.io();
        fs::write(f.0.join("online"), "0-15\n").unwrap();
        fs::write(f.0.join("eno1/queues/rx-0/rps_cpus"), "ffff\n").unwrap();
        let desired = [("eno1/rx-0".into(), "1".into())].into();
        let (before, identity) = io.read(&desired, &BTreeMap::new()).unwrap();
        let durable = serde_json::to_vec(&(before, identity)).unwrap();
        // A regular fixture retains the suffix of a shorter write, simulating rejected readback.
        assert!(io.write(&desired, &BTreeMap::new()).is_err());
        let (before, identity) = serde_json::from_slice(&durable).unwrap();
        assert!(io.write(&before, &identity).is_err());
        fs::write(f.0.join("eno1/queues/rx-0/rps_cpus"), "0\n").unwrap();
        io.write(&before, &identity).unwrap();
        assert_eq!(io.read(&before, &identity).unwrap().0, before);
    }
}
