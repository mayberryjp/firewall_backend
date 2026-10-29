use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"NCPKG001";
const LIMIT: usize = 256 * 1024 * 1024;
const MANIFEST_LIMIT: usize = 64 * 1024;
const RECEIPT: &str = "var/lib/netcontrol-package/installed.json";
const JOURNAL: &str = "var/lib/netcontrol-package/transaction.json";
const PATHS: [(&str, u32); 4] = [
    ("usr/sbin/netcontrold", 0o755),
    ("usr/sbin/netcontrol-package", 0o755),
    ("etc/init.d/netcontrold", 0o755),
    ("etc/conf.d/netcontrold", 0o644),
];

#[derive(Parser)]
#[command(about = "Build, verify and install signed native Netcontrol packages")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Build {
        #[arg(long)]
        daemon: PathBuf,
        #[arg(long)]
        installer: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        package: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Install {
        package: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, default_value = "/")]
        root: PathBuf,
    },
    Recover {
        #[arg(long, default_value = "/")]
        root: PathBuf,
    },
    BuildUpdate {
        #[arg(long)]
        daemon: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    mode: u32,
    size: usize,
    sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    product: String,
    target: String,
    entries: Vec<Entry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    package_sha256: String,
    manifest: Manifest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Before {
    path: String,
    mode: u32,
    data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    format: u32,
    files: Vec<Before>,
}

struct Package {
    manifest: Manifest,
    files: Vec<Vec<u8>>,
    digest: String,
}

fn main() {
    if let Err(error) = execute(Cli::parse().command) {
        eprintln!("netcontrol-package: {error:#}");
        std::process::exit(1);
    }
}

fn execute(command: Command) -> Result<()> {
    match command {
        Command::BuildUpdate {
            daemon,
            version,
            signing_key,
            output_dir,
        } => {
            use netcontrol_package::update::{self, Manifest};
            update::version(&version)?;
            let binary = read_bounded(&daemon)?;
            validate_elf(&binary, "x86_64-unknown-linux-musl")?;
            let manifest = Manifest {
                schema: 1,
                version,
                target: update::TARGET.into(),
                size: binary.len() as u64,
                sha256: hash(&binary),
            };
            update::verify_binary(&binary, &manifest)?;
            let bytes = serde_json::to_vec(&manifest)?;
            let key = SigningKey::from_bytes(&read_key(&signing_key)?);
            fs::create_dir(&output_dir).context("output directory must not already exist")?;
            create_file(&output_dir.join("netcontrold-ubuntu-amd64"), &binary, 0o755)?;
            create_file(
                &output_dir.join("netcontrol-ubuntu-amd64.json"),
                &bytes,
                0o644,
            )?;
            create_file(
                &output_dir.join("netcontrol-ubuntu-amd64.sig"),
                &key.sign(&bytes).to_bytes(),
                0o644,
            )?;
            println!("Created signed Ubuntu update assets; nothing was uploaded or released.");
        }
        Command::Keygen {
            private_key,
            public_key,
        } => {
            ensure!(
                private_key != public_key,
                "private and public key paths must differ"
            );
            let key = SigningKey::generate(&mut OsRng);
            create_file(&private_key, &key.to_bytes(), 0o600)?;
            if let Err(error) = create_file(&public_key, &key.verifying_key().to_bytes(), 0o644) {
                fs::remove_file(&private_key).context("remove incomplete signing key pair")?;
                return Err(error);
            }
            println!("Created signing key pair; keep the private key offline and private.");
        }
        Command::Build {
            daemon,
            installer,
            target,
            signing_key,
            output,
        } => {
            let key = SigningKey::from_bytes(&read_key(&signing_key)?);
            let files = vec![
                read_bounded(&daemon)?,
                read_bounded(&installer)?,
                include_str!("../../../packaging/native/netcontrold.initd")
                    .replace("\r\n", "\n")
                    .into_bytes(),
                include_str!("../../../packaging/native/netcontrold.confd")
                    .replace("\r\n", "\n")
                    .into_bytes(),
            ];
            let bytes = build(&target, &files, &key)?;
            create_file(&output, &bytes, 0o644)?;
            println!("{}  {}", hash(&bytes), output.display());
        }
        Command::Verify {
            package,
            public_key,
        } => {
            let package = verify(&read_bounded(&package)?, &read_key(&public_key)?)?;
            println!("{}", serde_json::to_string_pretty(&package.manifest)?);
            println!("Verified Ed25519 signature; SHA-256 {}", package.digest);
        }
        Command::Install {
            package,
            public_key,
            root,
        } => {
            ensure!(cfg!(target_os = "linux"), "installation requires Linux");
            let package = verify(&read_bounded(&package)?, &read_key(&public_key)?)?;
            ensure!(
                package.manifest.target == host_target()?,
                "package target does not match this machine"
            );
            let root = root
                .canonicalize()
                .context("installation root must exist")?;
            let _lock = lock_root(&root)?;
            install(&root, &package)?;
            println!(
                "Installed verified package {}. Service was not started.",
                package.digest
            );
        }
        Command::Recover { root } => {
            ensure!(cfg!(target_os = "linux"), "recovery requires Linux");
            let root = root.canonicalize()?;
            let _lock = lock_root(&root)?;
            recover(&root)?;
            println!(
                "Installation rollback complete; application state and credentials were not modified."
            );
        }
    }
    Ok(())
}

fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut data = Vec::new();
    file.take((LIMIT + 1) as u64).read_to_end(&mut data)?;
    ensure!(
        data.len() <= LIMIT,
        "file exceeds the 256 MiB package limit"
    );
    Ok(data)
}

fn read_key(path: &Path) -> Result<[u8; 32]> {
    read_bounded(path)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must contain exactly 32 binary bytes"))
}

fn host_target() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        arch => bail!("unsupported machine architecture {arch}"),
    }
}

fn validate_elf(data: &[u8], target: &str) -> Result<()> {
    let machine = match target {
        "x86_64-unknown-linux-musl" => 62,
        "aarch64-unknown-linux-musl" => 183,
        _ => bail!("unsupported package target {target}"),
    };
    ensure!(
        data.len() >= 64 && &data[..4] == b"\x7fELF",
        "binary must be a Linux ELF executable"
    );
    ensure!(
        data[4] == 2
            && data[5] == 1
            && data[6] == 1
            && matches!(data[7], 0 | 3)
            && u32::from_le_bytes(data[20..24].try_into()?) == 1
            && u16::from_le_bytes(data[52..54].try_into()?) == 64,
        "binary must be ELF64 little-endian"
    );
    ensure!(
        u16::from_le_bytes([data[18], data[19]]) == machine,
        "ELF architecture does not match package target"
    );
    ensure!(
        matches!(u16::from_le_bytes([data[16], data[17]]), 2 | 3),
        "ELF must be executable or static PIE"
    );
    let entry = u64::from_le_bytes(data[24..32].try_into()?);
    let offset = usize::try_from(u64::from_le_bytes(data[32..40].try_into()?))?;
    let entry_size = u16::from_le_bytes(data[54..56].try_into()?) as usize;
    let count = u16::from_le_bytes(data[56..58].try_into()?) as usize;
    ensure!(
        count > 0 && entry_size >= 56,
        "ELF has no valid program headers"
    );
    let mut executable_entry = false;
    let mut dynamic_seen = false;
    for index in 0..count {
        let start = offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .context("ELF header overflow")?,
            )
            .context("ELF offset overflow")?;
        let end = start.checked_add(56).context("ELF header overflow")?;
        ensure!(end <= data.len(), "truncated ELF program header");
        let kind = u32::from_le_bytes(data[start..start + 4].try_into()?);
        ensure!(
            kind != 3,
            "dynamic ELF interpreters are not supported; build statically for musl"
        );
        if kind != 1 && kind != 2 {
            continue;
        }
        let flags = u32::from_le_bytes(data[start + 4..start + 8].try_into()?);
        let file_offset =
            usize::try_from(u64::from_le_bytes(data[start + 8..start + 16].try_into()?))?;
        let address = u64::from_le_bytes(data[start + 16..start + 24].try_into()?);
        let file_size =
            usize::try_from(u64::from_le_bytes(data[start + 32..start + 40].try_into()?))?;
        let memory_size = u64::from_le_bytes(data[start + 40..start + 48].try_into()?);
        let file_end = file_offset
            .checked_add(file_size)
            .context("ELF segment overflow")?;
        ensure!(file_end <= data.len(), "truncated ELF segment");
        if kind == 1 {
            ensure!(file_size as u64 <= memory_size, "invalid ELF load segment");
            executable_entry |= entry != 0
                && flags & 1 != 0
                && entry >= address
                && entry - address < file_size as u64;
        } else {
            ensure!(!dynamic_seen, "multiple ELF dynamic segments");
            dynamic_seen = true;
            ensure!(
                file_size > 0 && file_size % 16 == 0,
                "invalid ELF dynamic segment"
            );
            let mut terminated = false;
            for item in data[file_offset..file_end].chunks_exact(16) {
                let tag = u64::from_le_bytes(item[..8].try_into()?);
                ensure!(
                    tag != 1,
                    "ELF shared-library dependencies are not supported; build statically for musl"
                );
                if tag == 0 {
                    terminated = true;
                    break;
                }
            }
            ensure!(terminated, "unterminated ELF dynamic segment");
        }
    }
    ensure!(
        executable_entry,
        "ELF entry point must be inside a file-backed executable load segment"
    );
    Ok(())
}

fn build(target: &str, files: &[Vec<u8>], key: &SigningKey) -> Result<Vec<u8>> {
    ensure!(
        files.len() == PATHS.len(),
        "package requires exactly four payload files"
    );
    validate_elf(&files[0], target)?;
    validate_elf(&files[1], target)?;
    let manifest = Manifest {
        format: 1,
        product: "netcontrol".into(),
        target: target.into(),
        entries: PATHS
            .iter()
            .zip(files)
            .map(|((path, mode), data)| Entry {
                path: (*path).into(),
                mode: *mode,
                size: data.len(),
                sha256: hash(data),
            })
            .collect(),
    };
    let manifest = serde_json::to_vec(&manifest)?;
    ensure!(manifest.len() <= MANIFEST_LIMIT, "manifest too large");
    let mut result = MAGIC.to_vec();
    result.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    result.extend_from_slice(&manifest);
    for file in files {
        ensure!(
            result
                .len()
                .checked_add(file.len())
                .is_some_and(|size| size <= LIMIT - 64),
            "package exceeds size limit"
        );
        result.extend_from_slice(file);
    }
    let signature = key.sign(&result);
    result.extend_from_slice(&signature.to_bytes());
    Ok(result)
}

fn verify(bytes: &[u8], public_key: &[u8; 32]) -> Result<Package> {
    ensure!(
        bytes.len() >= 12 + 64 && bytes.len() <= LIMIT,
        "invalid package size"
    );
    ensure!(&bytes[..8] == MAGIC, "unsupported package format");
    let end = bytes.len() - 64;
    let key = VerifyingKey::from_bytes(public_key).context("invalid trusted public key")?;
    let signature = Signature::from_slice(&bytes[end..])?;
    key.verify_strict(&bytes[..end], &signature)
        .context("package signature verification failed")?;
    let length = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
    ensure!(
        length <= MANIFEST_LIMIT && 12 + length <= end,
        "invalid manifest size"
    );
    let manifest: Manifest =
        serde_json::from_slice(&bytes[12..12 + length]).context("invalid package manifest")?;
    ensure!(
        manifest.format == 1 && manifest.product == "netcontrol",
        "unsupported package manifest"
    );
    ensure!(
        manifest.entries.len() == PATHS.len(),
        "unexpected payload file count"
    );
    let mut offset = 12 + length;
    let mut files = Vec::new();
    for (entry, (path, mode)) in manifest.entries.iter().zip(PATHS) {
        ensure!(
            entry.path == path && entry.mode == mode,
            "unexpected package path or file permissions"
        );
        let next = offset
            .checked_add(entry.size)
            .context("payload size overflow")?;
        ensure!(next <= end, "truncated payload");
        let data = &bytes[offset..next];
        ensure!(
            hash(data) == entry.sha256,
            "payload checksum mismatch for {}",
            entry.path
        );
        files.push(data.to_vec());
        offset = next;
    }
    ensure!(offset == end, "trailing unsigned or unlisted payload");
    validate_elf(&files[0], &manifest.target)?;
    validate_elf(&files[1], &manifest.target)?;
    Ok(Package {
        manifest,
        files,
        digest: hash(bytes),
    })
}

fn set_mode(file: &File, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

fn create_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    let write: Result<()> = (|| {
        set_mode(&file, mode)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    if write.is_err() {
        fs::remove_file(path)
            .with_context(|| format!("remove incomplete file {}", path.display()))?;
    }
    write
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn checked_path(root: &Path, relative: &str) -> Result<PathBuf> {
    ensure!(
        !relative.is_empty() && !relative.contains(['\\', ':']),
        "invalid installation path"
    );
    let path = Path::new(relative);
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_))),
        "invalid installation path"
    );
    let mut current = root.to_path_buf();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "symlink in installation path {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(current)
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("file must have a parent directory")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".netcontrol-{:016x}.tmp", rand::random::<u64>()));
    create_file(&temporary, data, mode)?;
    if let Err(error) = fs::rename(&temporary, path) {
        fs::remove_file(&temporary).context("remove failed staging file")?;
        return Err(error).context("commit staged file");
    }
    sync_directory(parent)
}

fn lock_root(root: &Path) -> Result<File> {
    let directory = checked_path(root, "var/lib/netcontrol-package")?;
    fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let path = checked_path(root, "var/lib/netcontrol-package/lock")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock_exclusive()
        .context("another installation or recovery is running")?;
    Ok(file)
}

fn install(root: &Path, package: &Package) -> Result<()> {
    ensure!(
        !checked_path(root, JOURNAL)?.exists(),
        "interrupted installation; run netcontrol-package recover first"
    );
    let receipt_path = checked_path(root, RECEIPT)?;
    let old: Option<Receipt> = match fs::read(&receipt_path) {
        Ok(bytes) => {
            Some(serde_json::from_slice(&bytes).context("invalid installed package receipt")?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut before = Vec::new();
    for entry in &package.manifest.entries {
        let path = checked_path(root, &entry.path)?;
        let data = match fs::read(&path) {
            Ok(data) => {
                let owned = old.as_ref().and_then(|receipt| {
                    receipt
                        .manifest
                        .entries
                        .iter()
                        .find(|old| old.path == entry.path)
                });
                ensure!(
                    owned.is_some_and(|old| hash(&data) == old.sha256),
                    "refusing to overwrite unowned or modified file {}",
                    path.display()
                );
                Some(data)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        before.push(Before {
            path: entry.path.clone(),
            mode: entry.mode,
            data,
        });
    }
    before.push(Before {
        path: RECEIPT.into(),
        mode: 0o600,
        data: match fs::read(&receipt_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        },
    });
    let transaction = Transaction {
        format: 1,
        files: before,
    };
    let journal = serde_json::to_vec(&transaction)?;
    ensure!(
        journal.len() <= LIMIT,
        "installation recovery journal exceeds size limit"
    );
    atomic_write(&checked_path(root, JOURNAL)?, &journal, 0o600)?;
    let result: Result<()> = (|| {
        for (entry, data) in package.manifest.entries.iter().zip(&package.files) {
            atomic_write(&checked_path(root, &entry.path)?, data, entry.mode)?;
        }
        let receipt = Receipt {
            package_sha256: package.digest.clone(),
            manifest: package.manifest.clone(),
        };
        atomic_write(&receipt_path, &serde_json::to_vec_pretty(&receipt)?, 0o600)?;
        fs::remove_file(checked_path(root, JOURNAL)?)?;
        sync_directory(&root.join("var/lib/netcontrol-package"))?;
        Ok(())
    })();
    if let Err(error) = result {
        recover(root).context(format!(
            "installation failed ({error:#}); rollback also failed"
        ))?;
        return Err(error).context("installation failed and was rolled back");
    }
    Ok(())
}

fn recover(root: &Path) -> Result<()> {
    let journal = checked_path(root, JOURNAL)?;
    let bytes = read_bounded(&journal).context("no readable interrupted-installation journal")?;
    let transaction: Transaction = serde_json::from_slice(&bytes)?;
    ensure!(
        transaction.format == 1 && transaction.files.len() == PATHS.len() + 1,
        "invalid installation recovery journal"
    );
    for (index, before) in transaction.files.iter().enumerate() {
        let allowed = if index < PATHS.len() {
            PATHS[index].0
        } else {
            RECEIPT
        };
        ensure!(before.path == allowed, "unexpected recovery path");
        let expected_mode = if index < PATHS.len() {
            PATHS[index].1
        } else {
            0o600
        };
        ensure!(
            before.mode == expected_mode,
            "unexpected recovery file mode"
        );
        checked_path(root, &before.path)?;
    }
    for before in transaction.files.iter().rev() {
        let path = checked_path(root, &before.path)?;
        match &before.data {
            Some(data) => atomic_write(&path, data, before.mode)?,
            None => match fs::remove_file(&path) {
                Ok(()) => sync_directory(path.parent().context("missing recovery parent")?)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }
    }
    fs::remove_file(journal)?;
    sync_directory(&root.join("var/lib/netcontrol-package"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf() -> Vec<u8> {
        let mut elf = vec![0; 192];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 2;
        elf[18] = 62;
        elf[20] = 1;
        elf[24..32].copy_from_slice(&0x10b0u64.to_le_bytes());
        elf[32] = 64;
        elf[52] = 64;
        elf[54] = 56;
        elf[56] = 1;
        elf[64] = 1;
        elf[68] = 5;
        elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&192u64.to_le_bytes());
        elf[104..112].copy_from_slice(&192u64.to_le_bytes());
        elf[176] = 0xc3;
        elf
    }

    fn fixture() -> (Vec<u8>, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let bytes = build(
            "x86_64-unknown-linux-musl",
            &[elf(), elf(), b"init".to_vec(), b"config".to_vec()],
            &key,
        )
        .unwrap();
        (bytes, key)
    }

    #[test]
    fn build_update_emits_version_bound_signed_assets_without_overwriting() {
        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let daemon = root.path().join("daemon");
        let signing_key = root.path().join("key");
        let output_dir = root.path().join("release");
        fs::write(&daemon, elf()).unwrap();
        fs::write(&signing_key, key.to_bytes()).unwrap();
        let command = || Command::BuildUpdate {
            daemon: daemon.clone(),
            version: "2026.10.29.1".into(),
            signing_key: signing_key.clone(),
            output_dir: output_dir.clone(),
        };
        execute(command()).unwrap();
        assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 3);
        let manifest = netcontrol_package::update::verify_manifest(
            &fs::read(output_dir.join("netcontrol-ubuntu-amd64.json")).unwrap(),
            &fs::read(output_dir.join("netcontrol-ubuntu-amd64.sig")).unwrap(),
            &key.verifying_key().to_bytes(),
            "2026.10.29.1",
        )
        .unwrap();
        netcontrol_package::update::verify_binary(
            &fs::read(output_dir.join("netcontrold-ubuntu-amd64")).unwrap(),
            &manifest,
        )
        .unwrap();
        assert!(execute(command()).is_err());
    }

    #[test]
    fn signed_round_trip_and_tampering() {
        let (bytes, key) = fixture();
        let package = verify(&bytes, &key.verifying_key().to_bytes()).unwrap();
        assert_eq!(package.files[0], elf());
        assert_eq!(package.manifest.entries.len(), 4);
        for index in [0, 8, 15, bytes.len() - 65, bytes.len() - 1] {
            let mut altered = bytes.clone();
            altered[index] ^= 1;
            assert!(verify(&altered, &key.verifying_key().to_bytes()).is_err());
        }
        assert!(
            verify(
                &bytes,
                &SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
            )
            .is_err()
        );
        assert!(verify(&bytes[..bytes.len() - 1], &key.verifying_key().to_bytes()).is_err());
    }

    #[test]
    fn rejects_wrong_target_and_dynamic_binary() {
        let key = SigningKey::generate(&mut OsRng);
        assert!(
            build(
                "aarch64-unknown-linux-musl",
                &[elf(), elf(), vec![], vec![]],
                &key
            )
            .is_err()
        );
        let mut dynamic = elf();
        dynamic[64] = 3;
        assert!(validate_elf(&dynamic, "x86_64-unknown-linux-musl").is_err());
        assert!(validate_elf(&elf()[..70], "x86_64-unknown-linux-musl").is_err());
    }

    #[test]
    fn requires_executable_entry_and_bounded_load_segments() {
        for (offset, bytes) in [
            (24, 0u64.to_le_bytes()),
            (68, 0u64.to_le_bytes()),
            (96, 193u64.to_le_bytes()),
            (104, 191u64.to_le_bytes()),
        ] {
            let mut invalid = elf();
            invalid[offset..offset + 8].copy_from_slice(&bytes);
            assert!(validate_elf(&invalid, "x86_64-unknown-linux-musl").is_err());
        }
    }

    #[test]
    fn rejects_shared_dependencies_without_an_interpreter() {
        let mut binary = elf();
        binary.resize(224, 0);
        binary[16] = 3;
        binary[56] = 2;
        binary[96..104].copy_from_slice(&224u64.to_le_bytes());
        binary[104..112].copy_from_slice(&224u64.to_le_bytes());
        binary[120] = 2;
        binary[128..136].copy_from_slice(&192u64.to_le_bytes());
        binary[152..160].copy_from_slice(&32u64.to_le_bytes());
        binary[160..168].copy_from_slice(&32u64.to_le_bytes());
        binary[192] = 1;
        assert!(validate_elf(&binary, "x86_64-unknown-linux-musl").is_err());
        binary[192] = 21;
        binary[208] = 30;
        assert!(validate_elf(&binary, "x86_64-unknown-linux-musl").is_err());
        binary[192] = 0;
        assert!(validate_elf(&binary, "x86_64-unknown-linux-musl").is_ok());
        binary[152] = 31;
        assert!(validate_elf(&binary, "x86_64-unknown-linux-musl").is_err());
        binary[152] = 32;
        binary.pop();
        assert!(validate_elf(&binary, "x86_64-unknown-linux-musl").is_err());
    }

    #[test]
    fn installs_idempotently_and_preserves_state() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (bytes, key) = fixture();
        let package = verify(&bytes, &key.verifying_key().to_bytes()).unwrap();
        let _lock = lock_root(root).unwrap();
        fs::create_dir_all(root.join("var/lib/netcontrol")).unwrap();
        fs::write(root.join("var/lib/netcontrol/credentials.json"), b"keep").unwrap();
        install(root, &package).unwrap();
        install(root, &package).unwrap();
        assert_eq!(fs::read(root.join(PATHS[0].0)).unwrap(), elf());
        assert_eq!(
            fs::read(root.join("var/lib/netcontrol/credentials.json")).unwrap(),
            b"keep"
        );
        fs::write(root.join(PATHS[3].0), b"locally edited config").unwrap();
        assert!(install(root, &package).is_err());
        assert_eq!(
            fs::read(root.join(PATHS[3].0)).unwrap(),
            b"locally edited config"
        );
    }

    #[test]
    fn rejects_unowned_files_and_recovers_interruption() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let _lock = lock_root(root).unwrap();
        let (bytes, key) = fixture();
        let package = verify(&bytes, &key.verifying_key().to_bytes()).unwrap();
        let binary = root.join(PATHS[0].0);
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"not owned").unwrap();
        assert!(install(root, &package).is_err());
        let transaction = Transaction {
            format: 1,
            files: PATHS
                .iter()
                .map(|(path, mode)| Before {
                    path: (*path).into(),
                    mode: *mode,
                    data: if *path == PATHS[0].0 {
                        Some(b"original".to_vec())
                    } else {
                        None
                    },
                })
                .chain(std::iter::once(Before {
                    path: RECEIPT.into(),
                    mode: 0o600,
                    data: None,
                }))
                .collect(),
        };
        atomic_write(
            &root.join(JOURNAL),
            &serde_json::to_vec(&transaction).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(install(root, &package).is_err());
        recover(root).unwrap();
        assert_eq!(fs::read(binary).unwrap(), b"original");
        assert!(!root.join(JOURNAL).exists());
    }

    #[test]
    fn paths_and_keys_are_strict() {
        let root = tempfile::tempdir().unwrap();
        for path in ["../escape", "/absolute", "a/../../escape", "C:\\escape"] {
            assert!(checked_path(root.path(), path).is_err(), "{path}");
        }
        let key = root.path().join("key");
        create_file(&key, &[0; 32], 0o600).unwrap();
        assert!(create_file(&key, b"replacement", 0o600).is_err());
        assert_eq!(read_key(&key).unwrap(), [0; 32]);
    }

    #[test]
    fn rejects_signed_malformed_manifest() {
        let (bytes, key) = fixture();
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let manifest: Manifest = serde_json::from_slice(&bytes[12..12 + length]).unwrap();
        for kind in 0..4 {
            let mut modified = manifest.clone();
            match kind {
                0 => modified.entries[0].path = "../credentials.json".into(),
                1 => modified.entries[0].mode = 0o4777,
                2 => modified.entries[0].size = usize::MAX,
                _ => modified.entries[0].sha256 = "00".repeat(32),
            }
            let json = serde_json::to_vec(&modified).unwrap();
            let mut encoded = MAGIC.to_vec();
            encoded.extend_from_slice(&(json.len() as u32).to_le_bytes());
            encoded.extend_from_slice(&json);
            encoded.extend_from_slice(&bytes[12 + length..bytes.len() - 64]);
            let signature = key.sign(&encoded);
            encoded.extend_from_slice(&signature.to_bytes());
            assert!(verify(&encoded, &key.verifying_key().to_bytes()).is_err());
        }
    }

    #[test]
    fn exclusive_lock_and_invalid_recovery_do_not_modify_files() {
        let root = tempfile::tempdir().unwrap();
        let _lock = lock_root(root.path()).unwrap();
        assert!(lock_root(root.path()).is_err());
        let binary = root.path().join(PATHS[0].0);
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"keep").unwrap();
        let mut files: Vec<Before> = PATHS
            .iter()
            .map(|(path, mode)| Before {
                path: (*path).into(),
                mode: *mode,
                data: None,
            })
            .collect();
        files.push(Before {
            path: "../escape".into(),
            mode: 0o600,
            data: None,
        });
        atomic_write(
            &root.path().join(JOURNAL),
            &serde_json::to_vec(&Transaction { format: 1, files }).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(recover(root.path()).is_err());
        assert_eq!(fs::read(binary).unwrap(), b"keep");
        assert!(root.path().join(JOURNAL).exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_installation_paths() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("usr")).unwrap();
        assert!(checked_path(root.path(), PATHS[0].0).is_err());
    }
}
