use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

fn private_key(root: &Path, reference: &str) -> Result<Key> {
    ensure!(
        crate::safe_name(reference, 64),
        "invalid private key reference"
    );
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let root_metadata = root.metadata()?;
    ensure!(
        root_metadata.is_dir()
            && root_metadata.uid() == unsafe { libc::geteuid() }
            && root_metadata.mode() & 0o022 == 0,
        "untrusted WireGuard key directory"
    );
    let filename = std::ffi::CString::new(reference)?;
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            filename.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "open WireGuard key reference: {}",
        std::io::Error::last_os_error()
    );
    use std::os::fd::FromRawFd;
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.len() <= 128,
        "WireGuard key must be a private regular file owned by the daemon user, at most 128 bytes"
    );
    let mut bytes = Vec::new();
    (&mut file).take(129).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 128, "oversized private key");
    let text = std::str::from_utf8(&bytes).context("private key encoding")?;
    let result = Key::from_base64(text.trim()).context("invalid private key encoding");
    // Avoid retaining key-file contents after the parsed fixed-size key is obtained.
    bytes.fill(0);
    let key = result?;
    ensure!(key != Key::zero(), "zero WireGuard private key rejected");
    Ok(key)
}

fn settings(root: &Path, value: &Value) -> Result<(Key, u16, Vec<PeerConfigBuilder>)> {
    let reference = value["key_ref"]
        .as_str()
        .context("missing WireGuard key_ref")?;
    let key = private_key(root, reference)?;
    let port = u16::try_from(
        value["listen_port"]
            .as_u64()
            .context("missing WireGuard listen_port")?,
    )?;
    // The contract requires a stable port for synchronous drift checks.
    ensure!(
        port != 0,
        "WireGuard listen_port=0 is not supported: a random effective port cannot satisfy the committed contract"
    );
    let mut peers = Vec::new();
    let mut keys = std::collections::BTreeSet::new();
    for peer in value["peers"]
        .as_array()
        .context("missing WireGuard peers")?
    {
        let public = Key::from_base64(
            peer["public_key"]
                .as_str()
                .context("missing peer public_key")?,
        )
        .context("invalid peer public key")?;
        ensure!(
            public != Key::zero() && keys.insert(public.to_base64()),
            "zero or duplicate WireGuard public key"
        );
        let mut builder = PeerConfigBuilder::new(&public)
            .replace_allowed_ips()
            .unset_preshared_key();
        let keepalive = u16::try_from(
            peer["persistent_keepalive_seconds"]
                .as_u64()
                .context("missing keepalive seconds")?,
        )?;
        builder = builder.set_persistent_keepalive_interval(keepalive);
        if let Some(endpoint) = peer
            .get("endpoint")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            let address: std::net::SocketAddr = endpoint
                .parse()
                .context("peer endpoint must be a numeric socket address")?;
            ensure!(
                address.port() != 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast(),
                "invalid peer endpoint"
            );
            builder = builder.set_endpoint(address);
        }
        for prefix in peer["allowed_ips"]
            .as_array()
            .context("missing allowed_ips")?
        {
            let (ip, len) = crate::model::parse_prefix(
                prefix
                    .as_str()
                    .context("allowed_ips must contain strings")?,
                true,
            )?;
            builder = builder.add_allowed_ip(ip, len);
        }
        peers.push(builder);
    }
    Ok((key, port, peers))
}

pub fn validate(root: &Path, value: &Value) -> Result<()> {
    settings(root, value)?;
    Ok(())
}

pub fn apply(root: &Path, name: &str, value: &Value) -> Result<()> {
    let (key, port, peers) = settings(root, value)?;
    let name: InterfaceName = name.parse()?;
    DeviceUpdate::new()
        .set_private_key(key)
        .set_listen_port(port)
        .unset_fwmark()
        .replace_peers()
        .add_peers(&peers)
        .apply(&name, Backend::Kernel)?;
    Ok(())
}

pub fn verify(root: &Path, name: &str, value: &Value) -> Result<()> {
    let (key, port, peers) = settings(root, value)?;
    let device = Device::get(&name.parse()?, Backend::Kernel)?;
    crate::ensure_unchanged(
        device.public_key == Some(key.get_public())
            && device.listen_port == Some(port)
            && device.fwmark.unwrap_or_default() == 0,
        "WireGuard device configuration drift",
    )?;
    let expected: BTreeMap<_, _> = peers
        .into_iter()
        .map(|v| {
            let config = v.into_peer_config();
            (config.public_key.to_base64(), config)
        })
        .collect();
    crate::ensure_unchanged(
        device.peers.len() == expected.len(),
        "WireGuard peer count drift",
    )?;
    for peer in device.peers {
        let expected = expected
            .get(&peer.config.public_key.to_base64())
            .ok_or_else(|| netcontrol_core::BackendDrift("unexpected WireGuard peer".into()))?;
        let mut actual_ips: Vec<_> = peer
            .config
            .allowed_ips
            .iter()
            .map(|p| format!("{}/{}", p.address, p.cidr))
            .collect();
        let mut expected_ips: Vec<_> = expected
            .allowed_ips
            .iter()
            .map(|p| format!("{}/{}", p.address, p.cidr))
            .collect();
        actual_ips.sort();
        expected_ips.sort();
        crate::ensure_unchanged(
            actual_ips == expected_ips
                && peer
                    .config
                    .preshared_key
                    .as_ref()
                    .is_none_or(|v| v == &Key::zero())
                && peer
                    .config
                    .persistent_keepalive_interval
                    .unwrap_or_default()
                    == expected.persistent_keepalive_interval.unwrap_or_default(),
            "WireGuard peer allowed IP/keepalive/PSK drift",
        )?;
        // Endpoint roaming is kernel runtime state. Explicit configured endpoints are checked;
        // omitted endpoints deliberately permit authenticated peer roaming.
        if expected.endpoint.is_some() {
            crate::ensure_unchanged(
                peer.config.endpoint == expected.endpoint,
                "WireGuard endpoint drift",
            )?;
        }
    }
    Ok(())
}

pub fn runtime(name: &str) -> Result<Value> {
    let device = Device::get(&name.parse()?, Backend::Kernel)?;
    Ok(
        json!({"interface":name,"public_key":device.public_key.map(|v| v.to_base64()),"listen_port":device.listen_port,"peers":device.peers.iter().map(|p| json!({"public_key":p.config.public_key.to_base64(),"endpoint":p.config.endpoint.map(|v|v.to_string()),"rx_bytes":p.stats.rx_bytes.to_string(),"tx_bytes":p.stats.tx_bytes.to_string(),"last_handshake_unix_seconds":p.stats.last_handshake_time.and_then(|t|t.duration_since(std::time::UNIX_EPOCH).ok()).map(|v|v.as_secs())})).collect::<Vec<_>>()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    struct Keys(std::path::PathBuf);
    impl Keys {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::current_dir()
                .unwrap()
                .join(format!(".native-keys-{}-{stamp}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            Self(root)
        }
        fn write(&self, contents: &str, mode: u32) {
            std::fs::write(self.0.join("key"), contents).unwrap();
            std::fs::set_permissions(self.0.join("key"), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
    }
    impl Drop for Keys {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn key_reader_rejects_paths_symlinks_and_public_permissions() {
        let fixture = Keys::new();
        let key = Key([7u8; 32]);
        fixture.write(&key.to_base64(), 0o600);
        assert!(private_key(&fixture.0, "key").unwrap() == key);
        assert!(private_key(&fixture.0, "../key").is_err());
        std::os::unix::fs::symlink(fixture.0.join("key"), fixture.0.join("alias")).unwrap();
        assert!(private_key(&fixture.0, "alias").is_err());
        fixture.write(&key.to_base64(), 0o644);
        assert!(private_key(&fixture.0, "key").is_err());
    }

    #[test]
    fn key_reader_rejects_zero_invalid_and_oversized_files() {
        let fixture = Keys::new();
        for contents in [
            Key::zero().to_base64(),
            "not-a-wireguard-key".into(),
            "x".repeat(129),
        ] {
            fixture.write(&contents, 0o600);
            assert!(private_key(&fixture.0, "key").is_err());
        }
    }
}
