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
    rfs_table: PathBuf,
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
            rfs_table: "/proc/sys/net/core/rps_sock_flow_entries".into(),
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
        self.queue_control(directory, queue, "rps_cpus", write)
    }

    fn queue_control(
        &self,
        directory: &File,
        queue: &str,
        control: &str,
        write: bool,
    ) -> Result<File> {
        let queues = child(directory, "queues", false, true)?;
        let queue = child(&queues, queue, false, true)?;
        child(&queue, control, write, false)
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

    fn global_rfs(&self, write: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(!write)
            .write(write)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.rfs_table)
            .context(
                "open RFS sock_flow_entries (kernel RFS support and host privileges required)",
            )?;
        if self.sysfs {
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0
                    && stat.f_type as u64 == libc::PROC_SUPER_MAGIC as u64,
                "RFS global table control must reside on procfs"
            );
        }
        Ok(file)
    }

    pub(super) fn rfs_entries(&self) -> Result<u32> {
        text(self.global_rfs(false)?)?
            .parse()
            .context("read RFS sock_flow_entries")
    }

    fn rfs_one(
        &self,
        key: &str,
        expected: Option<&RpsIdentity>,
        writable: bool,
    ) -> Result<(u32, RpsIdentity)> {
        let (name, queue) = rps_target(key)?;
        let directory = self.interface(name)?;
        let identity = self.identity(&directory)?;
        if let Some(expected) = expected {
            Self::check_identity(&identity, expected)?;
        }
        let count = text(self.queue_control(&directory, queue, "rps_flow_cnt", false)?)?.parse()?;
        if writable {
            self.queue_control(&directory, queue, "rps_flow_cnt", true)?;
        }
        Self::check_identity(&self.identity(&self.interface(name)?)?, &identity)?;
        Ok((count, identity))
    }

    pub(super) fn read_rfs(
        &self,
        values: &Option<netcontrol_core::RfsConfig>,
        expected: &BTreeMap<String, RpsIdentity>,
    ) -> Result<(
        Option<netcontrol_core::RfsConfig>,
        BTreeMap<String, RpsIdentity>,
    )> {
        let Some(values) = values else {
            return Ok((None, BTreeMap::new()));
        };
        ensure!(
            values.queues.len() <= 128,
            "RFS transaction queue limit exceeded"
        );
        let mut queues = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let sock_flow_entries = self.rfs_entries()?;
        for key in values.queues.keys() {
            let (name, _) = rps_target(key)?;
            let (count, identity) = self
                .rfs_one(key, expected.get(name), false)
                .with_context(|| format!("read RFS {key}"))?;
            queues.insert(key.clone(), count);
            identities.insert(name.to_owned(), identity);
        }
        Ok((
            Some(netcontrol_core::RfsConfig {
                sock_flow_entries,
                queues,
            }),
            identities,
        ))
    }

    pub(super) fn preflight_rfs(
        &self,
        values: &Option<netcontrol_core::RfsConfig>,
        expected: &BTreeMap<String, RpsIdentity>,
    ) -> Result<()> {
        let Some(values) = values else {
            return Ok(());
        };
        ensure!(
            values.queues.len() <= 128
                && (values.sock_flow_entries == 0 || values.sock_flow_entries.is_power_of_two()),
            "invalid RFS recovery table/queue counts"
        );
        self.rfs_entries()?;
        self.global_rfs(true)?;
        for (key, count) in &values.queues {
            ensure!(
                *count == 0 || count.is_power_of_two(),
                "invalid RFS queue count"
            );
            let (name, _) = rps_target(key)?;
            self.rfs_one(key, expected.get(name), true)
                .with_context(|| format!("preflight RFS {key}"))?;
        }
        Ok(())
    }

    pub(super) fn write_rfs(
        &self,
        values: &Option<netcontrol_core::RfsConfig>,
        expected: &BTreeMap<String, RpsIdentity>,
    ) -> Result<()> {
        self.preflight_rfs(values, expected)?;
        let Some(values) = values else {
            return Ok(());
        };
        if values.sock_flow_entries > 0 && self.rfs_entries()? != values.sock_flow_entries {
            self.global_rfs(true)?
                .write_all(format!("{}\n", values.sock_flow_entries).as_bytes())?;
            ensure!(
                self.rfs_entries()? == values.sock_flow_entries,
                "RFS global table readback mismatch"
            );
        }
        for (key, target) in &values.queues {
            let (name, queue) = rps_target(key)?;
            let (current, identity) = self.rfs_one(key, expected.get(name), false)?;
            if current == *target {
                continue;
            }
            let directory = self.interface(name)?;
            Self::check_identity(&self.identity(&directory)?, &identity)?;
            self.queue_control(&directory, queue, "rps_flow_cnt", true)?
                .write_all(format!("{target}\n").as_bytes())
                .with_context(|| format!("write RFS {key}"))?;
            ensure!(
                self.rfs_one(key, Some(&identity), false)?.0 == *target,
                "RFS queue readback mismatch for {key}"
            );
        }
        if values.sock_flow_entries == 0 && self.rfs_entries()? != 0 {
            self.global_rfs(true)?.write_all(b"0\n")?;
        }
        ensure!(
            self.read_rfs(&Some(values.clone()), expected)?.0.as_ref() == Some(values),
            "RFS exact readback mismatch"
        );
        Ok(())
    }

    pub(super) fn queues(&self, name: &str) -> Result<Vec<(String, String, u32)>> {
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
            let (flows, _) = self.rfs_one(&format!("{name}/{queue}"), Some(&identity), false)?;
            result.push((queue, mask, flows));
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
            fs::write(root.join("eno1/queues/rx-0/rps_flow_cnt"), "1024\n").unwrap();
            fs::write(root.join("rfs_entries"), "4096\n").unwrap();
            fs::write(root.join("online"), "0-3\n").unwrap();
            fs::write(root.join("boot"), "boot-a\n").unwrap();
            Self(root)
        }
        fn io(&self) -> Io {
            Io {
                net: self.0.clone(),
                online: self.0.join("online"),
                boot: self.0.join("boot"),
                rfs_table: self.0.join("rfs_entries"),
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

    #[test]
    fn rfs_io_captures_global_and_queue_tables_restores_and_guards_identity() {
        let f = Fixture::new();
        let io = f.io();
        let desired = Some(netcontrol_core::RfsConfig {
            sock_flow_entries: 8192,
            queues: [("eno1/rx-0".into(), 2048)].into(),
        });
        let (before, identity) = io.read_rfs(&desired, &BTreeMap::new()).unwrap();
        assert_eq!(before.as_ref().unwrap().sock_flow_entries, 4096);
        assert_eq!(before.as_ref().unwrap().queues["eno1/rx-0"], 1024);
        let durable = serde_json::to_vec(&(before.clone(), identity.clone())).unwrap();
        io.write_rfs(&desired, &identity).unwrap();
        assert_eq!(io.read_rfs(&desired, &identity).unwrap().0, desired);
        let (before, identity) = serde_json::from_slice(&durable).unwrap();
        io.write_rfs(&before, &identity).unwrap();
        assert_eq!(io.read_rfs(&before, &identity).unwrap().0, before);
        fs::write(f.0.join("eno1/ifindex"), "4\n").unwrap();
        assert!(io.write_rfs(&desired, &identity).is_err());
        assert_eq!(io.rfs_entries().unwrap(), 4096);
        fs::write(f.0.join("boot"), "boot-b\n").unwrap();
        io.write_rfs(&desired, &identity).unwrap();
        fs::write(f.0.join("eno1/address"), "02:00:00:00:00:02\n").unwrap();
        assert!(io.write_rfs(&before, &identity).is_err());
    }

    #[test]
    fn rfs_io_rejects_missing_queues_and_symlinks_before_any_mutation() {
        let f = Fixture::new();
        let io = f.io();
        let desired = Some(netcontrol_core::RfsConfig {
            sock_flow_entries: 8192,
            queues: [("eno1/rx-0".into(), 2048), ("eno1/rx-1".into(), 2048)].into(),
        });
        assert!(io.write_rfs(&desired, &BTreeMap::new()).is_err());
        assert_eq!(io.rfs_entries().unwrap(), 4096);
        assert_eq!(
            fs::read_to_string(f.0.join("eno1/queues/rx-0/rps_flow_cnt")).unwrap(),
            "1024\n"
        );
        fs::rename(f.0.join("rfs_entries"), f.0.join("original")).unwrap();
        std::os::unix::fs::symlink(f.0.join("original"), f.0.join("rfs_entries")).unwrap();
        assert!(io.preflight_rfs(&desired, &BTreeMap::new()).is_err());
        assert!(io.read_rfs(&None, &BTreeMap::new()).unwrap().0.is_none());
    }

    #[test]
    fn rfs_rejected_readback_keeps_serialized_originals_for_retry() {
        let f = Fixture::new();
        let io = f.io();
        let desired = Some(netcontrol_core::RfsConfig {
            sock_flow_entries: 1,
            queues: BTreeMap::new(),
        });
        let (before, ids) = io.read_rfs(&desired, &BTreeMap::new()).unwrap();
        let durable = serde_json::to_vec(&(before, ids)).unwrap();
        assert!(io.write_rfs(&desired, &BTreeMap::new()).is_err());
        let (before, ids) = serde_json::from_slice(&durable).unwrap();
        assert!(io.write_rfs(&before, &ids).is_err());
        fs::write(f.0.join("rfs_entries"), "0\n").unwrap();
        io.write_rfs(&before, &ids).unwrap();
        assert_eq!(io.read_rfs(&before, &ids).unwrap().0, before);
    }
}
