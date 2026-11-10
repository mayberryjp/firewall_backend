use anyhow::{Context, Result, ensure};
use netcontrol_core::RpfMode;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::PathBuf,
};

const ROOT: &str = "/proc/sys/net/ipv4/conf";

fn open(name: &str, write: bool) -> Result<File> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0']),
        "invalid RPF interface name"
    );
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PathBuf::from(ROOT).join(name).join("rp_filter"))
        .with_context(|| format!("open IPv4 RPF control for {name}"))?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0
            && stat.f_type as u64 == libc::PROC_SUPER_MAGIC as u64,
        "RPF control must be procfs"
    );
    Ok(file)
}

fn read(name: &str) -> Result<String> {
    let mut value = String::new();
    open(name, false)?.take(16).read_to_string(&mut value)?;
    let value = value.trim();
    ensure!(
        matches!(value, "0" | "1" | "2"),
        "invalid kernel RPF value for {name}"
    );
    Ok(value.into())
}

fn controls() -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for entry in fs::read_dir(ROOT).context("IPv4 RPF kernel controls are required")? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 RPF interface name"))?;
        values.insert(name.clone(), read(&name)?);
    }
    ensure!(
        values.contains_key("all") && values.contains_key("default"),
        "missing global RPF controls"
    );
    Ok(values)
}

pub(super) fn set(mode: RpfMode) -> Result<()> {
    let values = controls()?;
    for name in values.keys() {
        open(name, true)?;
    }
    let value = mode.kernel_value();
    // Both global and per-link values are owned: Linux uses their numeric maximum.
    for name in ["default", "all"].into_iter().chain(
        values
            .keys()
            .map(String::as_str)
            .filter(|name| !matches!(*name, "all" | "default")),
    ) {
        if read(name)? != value {
            open(name, true)?
                .write_all(format!("{value}\n").as_bytes())
                .with_context(|| format!("take over IPv4 RPF control for {name}"))?;
        }
    }
    ensure!(
        controls()?.values().all(|observed| observed == value),
        "kernel RPF takeover did not converge"
    );
    Ok(())
}

pub(super) fn status(mode: RpfMode) -> Result<Value> {
    let values = controls()?;
    let drift = values.values().any(|value| value != mode.kernel_value());
    Ok(json!({"mode":mode,"family":"ipv4","status":"measured","rp_filter":values,"drift":drift}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::{Native, integration::Fixture, session};
    use futures_util::TryStreamExt;
    use netcontrol_core::{Backend, Config};
    use std::{net::UdpSocket, sync::Arc, time::Duration};

    #[test]
    fn rpf_control_paths_reject_traversal() {
        for name in ["", ".", "..", "a/b", "/tmp", "a\0b"] {
            assert!(
                open(name, false)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid RPF")
            );
        }
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1, isolated Linux namespaces and NET_ADMIN/SYS_ADMIN"]
    fn native_rpf_takes_all_interfaces_tracks_modes_reopen_recovery_and_packets() -> Result<()> {
        let router = Fixture::new()?;
        let peer = Fixture::new()?;
        let router_ns = Arc::new(File::open(router.options().namespace)?);
        let peer_ns = Arc::new(File::open(peer.options().namespace)?);
        let destination = peer_ns.clone();
        session(router_ns.clone(), move |rt, handle| {
            rt.block_on(async {
                handle
                    .link()
                    .add()
                    .veth("lan0".into(), "peer0".into())
                    .execute()
                    .await?;
                let link = handle
                    .link()
                    .get()
                    .match_name("peer0".into())
                    .execute()
                    .try_next()
                    .await?
                    .context("missing RPF peer")?;
                handle
                    .link()
                    .set(link.header.index)
                    .setns_by_fd(destination.as_raw_fd())
                    .execute()
                    .await?;
                Ok(())
            })
        })?;
        session(peer_ns.clone(), |rt, handle| {
            set(RpfMode::Disabled)?;
            rt.block_on(async {
                let link = handle
                    .link()
                    .get()
                    .match_name("peer0".into())
                    .execute()
                    .try_next()
                    .await?
                    .context("missing RPF client")?;
                for address in ["192.0.2.2", "198.51.100.2", "203.0.113.2"] {
                    handle
                        .address()
                        .add(link.header.index, address.parse()?, 24)
                        .execute()
                        .await?;
                }
                handle.link().set(link.header.index).up().execute().await?;
                Ok(())
            })
        })?;
        let mut native = Native::open(router.options())?;
        let empty = Config::empty();
        native.repair(&empty)?;
        let runtime = native.runtime(&empty)?;
        assert_eq!(runtime["rpf"]["mode"], "disabled");
        assert_eq!(runtime["rpf"]["drift"], false);
        for value in runtime["rpf"]["rp_filter"].as_object().unwrap().values() {
            assert_eq!(value, "0");
        }
        let strict: Config = serde_json::from_value(json!({
            "firewall":{"rpf_mode":"strict"},
            "interfaces":[
                {"name":"lan0","kind":"ethernet","role":"lan","up":true,"mtu":1500,"addresses":["192.0.2.1/24"]},
                {"name":"wan0","kind":"dummy","role":"wan","up":true,"mtu":1500,"addresses":["198.51.100.1/24"]},
                {"name":"unused0","kind":"dummy","role":"unassigned","up":false,"mtu":1500,"addresses":[]}
            ]
        }))?;
        native.apply(&empty, &strict)?;
        let listener = session(router_ns.clone(), |_, _| {
            let socket = UdpSocket::bind("192.0.2.1:9000")?;
            socket.set_read_timeout(Some(Duration::from_millis(150)))?;
            Ok(socket)
        })?;
        let check = |expected: [bool; 3]| -> Result<()> {
            for (source, accepted) in ["192.0.2.2:0", "198.51.100.2:0", "203.0.113.2:0"]
                .into_iter()
                .zip(expected)
            {
                session(peer_ns.clone(), move |_, _| {
                    UdpSocket::bind(source)?.send_to(source.as_bytes(), "192.0.2.1:9000")?;
                    Ok(())
                })?;
                let mut bytes = [0; 64];
                match listener.recv_from(&mut bytes) {
                    Ok((length, _)) => {
                        ensure!(accepted, "RPF unexpectedly admitted {source}");
                        assert_eq!(&bytes[..length], source.as_bytes());
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        ensure!(!accepted, "RPF unexpectedly dropped {source}");
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        };
        check([true, false, false])?;
        let runtime = native.runtime(&strict)?;
        for name in ["all", "default", "lo", "lan0", "wan0", "unused0"] {
            assert_eq!(runtime["rpf"]["rp_filter"][name], "1");
        }
        session(router_ns.clone(), |rt, handle| {
            rt.block_on(handle.link().add().dummy("unmanaged@0".into()).execute())?;
            assert_eq!(read("unmanaged@0")?, "1");
            Ok(())
        })?;
        let mut current = strict.clone();
        for (mode, accepted) in [
            (RpfMode::Loose, [true, true, false]),
            (RpfMode::Disabled, [true, true, true]),
            (RpfMode::Strict, [true, false, false]),
        ] {
            let mut next = current.clone();
            next.firewall.rpf_mode = mode;
            native.apply(&current, &next)?;
            assert_eq!(native.runtime(&next)?["rpf"]["drift"], false);
            check(accepted)?;
            current = next;
        }
        session(router_ns.clone(), |rt, handle| {
            set(RpfMode::Loose)?;
            rt.block_on(handle.link().add().dummy("external0".into()).execute())?;
            Ok(())
        })?;
        assert_eq!(native.runtime(&strict)?["rpf"]["drift"], true);
        assert_eq!(native.observe(&strict)?, strict);
        native.apply(&strict, &strict)?;
        assert_eq!(
            native.runtime(&strict)?["rpf"]["rp_filter"]["external0"],
            "1"
        );
        assert_eq!(native.runtime(&strict)?["rpf"]["drift"], false);
        session(router_ns.clone(), |_, _| set(RpfMode::Disabled))?;
        native.repair(&strict)?;
        assert_eq!(native.runtime(&strict)?["rpf"]["drift"], false);
        let mut loose = strict.clone();
        loose.firewall.rpf_mode = RpfMode::Loose;
        native.apply(&strict, &loose)?;
        session(router_ns.clone(), |_, _| set(RpfMode::Strict))?;
        drop(native);
        let mut native = Native::open(router.options())?;
        assert_eq!(native.runtime(&loose)?["rpf"]["drift"], false);
        native.repair(&loose)?;
        check([true, true, false])?;
        // Simulate an interrupted mode change with the normal durable native intent.
        let before = loose.operational_value()?;
        let after = strict.operational_value()?;
        let ownership = native.ownership()?;
        let captured = native.capture_kernel(&before, &after)?;
        let intent = crate::linux::Intent {
            scope: native.identity.clone(),
            before: before.clone(),
            after: after.clone(),
            kernel_before: captured.clone(),
            ownership_before: ownership.clone(),
            ethernet_before: native.capture_ethernet(&before, &after)?,
            ethernet_originals: ownership.ethernet_originals.clone(),
            ipv6_before: native.capture_ipv6(&before)?,
        };
        crate::linux::write_json(&native.state.join("intent.json"), &intent)?;
        native.network_apply(&before, &after, captured, &mut ownership.clone())?;
        check([true, false, false])?;
        drop(native);
        let mut native = Native::open(router.options())?;
        assert!(!native.state.join("intent.json").exists());
        assert_eq!(native.runtime(&loose)?["rpf"]["drift"], false);
        check([true, true, false])?;
        let counters = native.statistics(&loose, "/api/v1/statistics/firewall", "")?;
        assert!(
            counters["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| !row["chain"].as_str().unwrap().contains("spoof")
                    && row["config_path"] != "/firewall/rpf_mode")
        );
        let rules = session(router_ns.clone(), |_, _| crate::linux::netfilter::rules())?;
        assert!(!serde_json::to_string(&rules)?.contains("spoof_block"));
        let mut disabled = loose.clone();
        disabled.firewall.rpf_mode = RpfMode::Disabled;
        native.apply(&loose, &disabled)?;
        session(router_ns.clone(), |_, _| set(RpfMode::Strict))?;
        drop(native);
        let mut native = Native::open(router.options())?;
        assert_eq!(native.runtime(&disabled)?["rpf"]["drift"], false);
        check([true, true, true])?;
        Ok(())
    }
}
