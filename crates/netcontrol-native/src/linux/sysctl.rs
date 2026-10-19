use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};

fn open(name: &str, write: bool) -> Result<File> {
    // Names reach here only after allowlist validation; no arbitrary proc paths are exposed.
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("/proc/sys/{}", name.replace('.', "/")))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0
            && stat.f_type as u64 == libc::PROC_SUPER_MAGIC as u64,
        "kernel tunable must be procfs"
    );
    Ok(file)
}

fn read_one(name: &str, scope: &str) -> Result<String> {
    let mut bytes = Vec::new();
    open(name, false)?.take(257).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 256, "oversized kernel value");
    let value = String::from_utf8(bytes)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    crate::tunables::validate(name, scope, &value)?;
    Ok(value)
}

pub fn preflight(name: &str, scope: &str, value: &str) -> Result<()> {
    crate::tunables::validate(name, scope, value)?;
    read_one(name, scope)?;
    open(name, true)?;
    if name == "net.ipv4.tcp_congestion_control" {
        let mut text = String::new();
        open("net.ipv4.tcp_available_congestion_control", false)?
            .take(4097)
            .read_to_string(&mut text)?;
        ensure!(
            text.len() <= 4096 && text.split_whitespace().any(|v| v == value),
            "requested congestion algorithm is not loaded; provision it outside netcontrol"
        );
    }
    Ok(())
}

pub fn read_scope(
    keys: &BTreeMap<String, String>,
    scope: &str,
) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (name, hint) in keys {
        crate::tunables::validate(name, scope, hint)?;
        result.insert(name.clone(), read_one(name, scope)?);
    }
    Ok(result)
}
pub fn verify_scope(expected: &BTreeMap<String, String>, scope: &str) -> Result<()> {
    ensure!(
        read_scope(expected, scope)? == *expected,
        "{scope} kernel tunable drift"
    );
    Ok(())
}
pub fn write_scope(values: &BTreeMap<String, String>, scope: &str) -> Result<()> {
    // Validate and check every target before the first write.
    for (name, value) in values {
        preflight(name, scope, value)?;
    }
    for (name, value) in values {
        if read_one(name, scope)? == *value {
            continue;
        }
        open(name, true)?
            .write_all(format!("{value}\n").as_bytes())
            .with_context(|| format!("write kernel tunable {name}"))?;
        ensure!(
            read_one(name, scope)? == *value,
            "kernel rejected exact value for {name}"
        );
    }
    Ok(())
}
