use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

fn competing(name: &str) -> bool {
    matches!(
        name,
        "NetworkManager"
            | "systemd-networkd"
            | "dhclient"
            | "dhcpcd"
            | "connmand"
            | "wickedd"
            | "dnsmasq"
            | "radvd"
            | "dhcpd"
            | "kea-dhcp4"
            | "kea-dhcp6"
            | "openvpn"
            | "tailscaled"
            | "zerotier-one"
            | "ovs-vswitchd"
            | "ovsdb-server"
            | "bird"
            | "bird6"
            | "zebra"
            | "bgpd"
    )
}

pub(super) fn capture() -> Result<Vec<(u32, String)>> {
    let namespace = fs::read_link("/proc/thread-self/ns/net")?;
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let executable = match fs::read_link(entry.path().join("exe")) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("inventory executable for PID {pid}"));
            }
        };
        let Some(name) = executable.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !competing(name) {
            continue;
        }
        match fs::read_link(entry.path().join("ns").join("net")) {
            Ok(found) if found == namespace => processes.push((pid, name.into())),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inventory network namespace for PID {pid}"));
            }
        }
    }
    Ok(processes)
}

pub(super) fn disable() -> Result<()> {
    let namespace = fs::read_link("/proc/thread-self/ns/net")?;
    for (pid, name) in capture()? {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error).context("open competing process pidfd");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(i32::try_from(raw)?) };
        // A pidfd pins the inventoried process; never signal a recycled numeric PID.
        let signal = |signal: i32| -> Result<()> {
            let status = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if status < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error).context("stop competing process");
                }
            }
            Ok(())
        };
        let current = fs::read_link(Path::new("/proc").join(pid.to_string()).join("exe"));
        if current
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        ensure!(
            current?.file_name().and_then(|name| name.to_str()) == Some(name.as_str()),
            "competing executable changed during takeover"
        );
        let current_namespace = fs::read_link(
            Path::new("/proc")
                .join(pid.to_string())
                .join("ns")
                .join("net"),
        );
        if current_namespace
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        if current_namespace? != namespace {
            continue;
        }
        signal(libc::SIGTERM)?;
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = |poll: &mut libc::pollfd, timeout: i32| -> Result<bool> {
            loop {
                let result = unsafe { libc::poll(poll, 1, timeout) };
                if result >= 0 {
                    return Ok(result > 0);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error).context("wait for competing process shutdown");
                }
            }
        };
        if !wait(&mut poll, 10000)? {
            signal(libc::SIGKILL)?;
            ensure!(
                wait(&mut poll, 5000)?,
                "competing process {name} PID {pid} remains running"
            );
        }
    }
    ensure!(
        capture()?.is_empty(),
        "competing networking processes respawned; disable their launcher from console"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_scope_preserves_native_workers_resolver_and_remote_access() {
        for name in ["dhclient", "NetworkManager", "dnsmasq", "bird"] {
            assert!(competing(name));
        }
        for name in [
            "netcontrold",
            "systemd-resolved",
            "wpa_supplicant",
            "sshd",
            "sleep",
        ] {
            assert!(!competing(name));
        }
    }
}
