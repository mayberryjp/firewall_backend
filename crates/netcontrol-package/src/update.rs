use anyhow::{Result, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TARGET: &str = "ubuntu-amd64-systemd";
pub const BINARY_LIMIT: u64 = 256 * 1024 * 1024;
pub const MANIFEST_LIMIT: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub version: String,
    pub target: String,
    pub size: u64,
    pub sha256: String,
}

pub fn version(input: &str) -> Result<netcontrol_core::Version> {
    input.parse()
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        version(&self.version)?;
        ensure!(
            self.schema == 1 && self.target == TARGET,
            "unsupported update schema or target"
        );
        ensure!(
            (64..=BINARY_LIMIT).contains(&self.size),
            "invalid update binary size"
        );
        ensure!(
            self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid update SHA-256"
        );
        Ok(())
    }
}

pub fn verify_manifest(
    bytes: &[u8],
    signature: &[u8],
    key: &[u8; 32],
    expected_version: &str,
) -> Result<Manifest> {
    ensure!(bytes.len() <= MANIFEST_LIMIT, "update manifest too large");
    VerifyingKey::from_bytes(key)?.verify_strict(bytes, &Signature::from_slice(signature)?)?;
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    manifest.validate()?;
    ensure!(
        manifest.version == expected_version,
        "signed update version does not match requested version"
    );
    Ok(manifest)
}

pub fn verify_binary(bytes: &[u8], manifest: &Manifest) -> Result<()> {
    manifest.validate()?;
    ensure!(
        bytes.len() as u64 == manifest.size
            && hex::encode(Sha256::digest(bytes)) == manifest.sha256,
        "update size or SHA-256 mismatch"
    );
    ensure!(
        bytes.len() >= 64
            && &bytes[..4] == b"\x7fELF"
            && bytes[4] == 2
            && bytes[5] == 1
            && u16::from_le_bytes([bytes[18], bytes[19]]) == 62,
        "update must be an amd64 Linux ELF executable"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn update_versions_are_canonical_not_paths_or_urls() {
        for valid in ["2026.10.29.1", "2026.01.01.1", "2024.02.29.10"] {
            assert!(version(valid).is_ok());
        }
        for invalid in [
            "latest",
            "v1.2.3",
            "01.2.3",
            "1.2",
            "../1.2.3",
            "https://example.invalid",
            "1.2.3+build",
            " 1.2.3",
        ] {
            assert!(version(invalid).is_err());
        }
    }

    #[test]
    fn signatures_bind_version_target_size_and_digest() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut binary = vec![0; 64];
        binary[..6].copy_from_slice(b"\x7fELF\x02\x01");
        binary[18] = 62;
        let mut manifest = Manifest {
            schema: 1,
            version: "2026.10.29.1".into(),
            target: TARGET.into(),
            size: binary.len() as u64,
            sha256: hex::encode(Sha256::digest(&binary)),
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = key.sign(&bytes).to_bytes();
        let verified = verify_manifest(
            &bytes,
            &signature,
            &key.verifying_key().to_bytes(),
            "2026.10.29.1",
        )
        .unwrap();
        verify_binary(&binary, &verified).unwrap();
        assert!(
            verify_manifest(
                &bytes,
                &signature,
                &key.verifying_key().to_bytes(),
                "2026.10.29.2"
            )
            .is_err()
        );
        assert!(
            verify_manifest(
                &bytes,
                &signature,
                &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
                "2026.10.29.1"
            )
            .is_err()
        );
        binary[63] ^= 1;
        assert!(verify_binary(&binary, &verified).is_err());
        manifest.target = "other".into();
        assert!(manifest.validate().is_err());
    }
}
