use anyhow::{Context, Result, ensure};
use clap::Parser;
use fs2::FileExt;
use netcontrol_core::{Config, validate_offline_state};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

const MAX_FILE: u64 = 256 * 1024 * 1024;

#[derive(Parser)]
#[command(
    about = "Offline, explicit removal of empty retired policy_rules fields; preview by default"
)]
struct Options {
    #[arg(long)]
    state: PathBuf,
    #[arg(
        long,
        help = "Native service state root; defaults to /var/lib/netcontrol/services for Linux journals"
    )]
    services_state_dir: Option<PathBuf>,
    #[arg(long)]
    apply: bool,
    #[arg(
        long,
        requires = "apply",
        help = "Explicit noninteractive confirmation"
    )]
    yes: bool,
    #[arg(
        long,
        requires = "apply",
        help = "New private directory for originals, replacements and manifest"
    )]
    backup_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    sha256: String,
    state: Box<RawValue>,
}

#[derive(Serialize)]
struct Change {
    location: String,
    rules: usize,
}

struct Replacement {
    path: PathBuf,
    original: Vec<u8>,
    converted: Vec<u8>,
}

struct Plan {
    files: Vec<Replacement>,
    changes: Vec<Change>,
    _locks: Vec<File>,
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(
                self,
                value: f64,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key {key}"
                        )));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice::<UniqueJson>(bytes)?.0)
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn private_regular(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "not a regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() },
            "file must be private, owned by this user and not hard-linked: {}",
            path.display()
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "directory ancestors must not be symlinks: {}",
            ancestor.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)?;
        ensure!(
            metadata.mode() & 0o077 == 0 && metadata.uid() == unsafe { libc::geteuid() },
            "directory must be private and owned by this user: {}",
            path.display()
        );
    }
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)),
        "paths must not contain '..'"
    );
    Ok(path)
}

fn lock(path: &Path) -> Result<File> {
    if path.try_exists()? {
        private_regular(path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    private_regular(path)?;
    file.try_lock_exclusive()
        .context("stop the daemon/other state tools before conversion")?;
    Ok(file)
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    private_directory(path.parent().context("file needs parent")?)?;
    private_regular(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_FILE,
        "file exceeds size limit"
    );
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "file exceeds size limit");
    Ok(bytes)
}

fn remove_field(
    config: &mut Value,
    location: String,
    changes: &mut Vec<Change>,
    operational: bool,
) -> Result<()> {
    let object = config
        .as_object_mut()
        .context("configuration must be an object")?;
    if let Some(rules) = object.remove("policy_rules") {
        let rules = rules
            .as_array()
            .with_context(|| format!("{location}: policy_rules must be an array"))?;
        changes.push(Change {
            location,
            rules: rules.len(),
        });
    }
    let typed: Config = serde_json::from_value(config.clone())
        .context("configuration has other incompatible fields")?;
    typed.validate()?;
    ensure!(
        typed == typed.normalized(),
        "configuration is not normalized"
    );
    if operational {
        *config = typed.operational_value()?;
    }
    Ok(())
}

fn ownership_config(value: &mut Value, location: &str, changes: &mut Vec<Change>) -> Result<()> {
    if let Some(config) = value
        .get_mut("committed_config")
        .filter(|config| !config.is_null())
    {
        remove_field(
            config,
            format!("{location}/committed_config"),
            changes,
            true,
        )?;
    }
    Ok(())
}

impl Plan {
    fn prepare(options: &Options) -> Result<Self> {
        let state_path = absolute(&options.state)?;
        private_directory(state_path.parent().context("state needs parent")?)?;
        private_regular(&state_path)?;
        let mut lock_name = state_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let mut locks = vec![lock(Path::new(&lock_name))?];
        let original = read_private(&state_path)?;
        let envelope: Envelope = serde_json::from_slice(&original)?;
        ensure!(
            envelope.schema == "netcontrol-rust-state-v2",
            "unsupported journal schema"
        );
        ensure!(
            hex::encode(Sha256::digest(envelope.state.get().as_bytes())) == envelope.sha256,
            "state checksum mismatch; conversion cannot repair corruption"
        );
        let mut payload = parse_json(envelope.state.get().as_bytes())?;
        let scope = payload["scope"]
            .as_str()
            .context("missing journal scope")?
            .to_owned();
        let mut changes = Vec::new();
        remove_field(
            payload
                .get_mut("desired")
                .context("missing desired configuration")?,
            "state/desired".into(),
            &mut changes,
            false,
        )?;
        let transactions = payload
            .get_mut("transactions")
            .and_then(Value::as_object_mut)
            .context("missing transaction map")?;
        for (id, transaction) in transactions {
            for field in ["previous", "candidate"] {
                remove_field(
                    transaction
                        .get_mut(field)
                        .context("missing transaction configuration")?,
                    format!("state/transactions/{id}/{field}"),
                    &mut changes,
                    false,
                )?;
            }
        }
        validate_offline_state(&serde_json::to_vec(&payload)?)?;
        let mut files = Vec::new();
        if scope.starts_with("linux:") {
            let root = absolute(
                options
                    .services_state_dir
                    .as_deref()
                    .unwrap_or(Path::new("/var/lib/netcontrol/services")),
            )?
            .join("native");
            private_directory(&root)?;
            locks.push(lock(&root.join("lock"))?);
            ensure!(
                !exists(&root.join("intent.json"))?,
                "recover the native intent with the previous binary before conversion"
            );
            let ownership_path = root.join("ownership.json");
            let ownership_bytes = read_private(&ownership_path)?;
            let mut ownership = parse_json(&ownership_bytes)?;
            ensure!(
                ownership["scope"] == scope,
                "native ownership belongs to a different journal scope"
            );
            ownership_config(&mut ownership, "native/ownership", &mut changes)?;
            if let Some(config) = ownership
                .get("committed_config")
                .filter(|config| !config.is_null())
            {
                let desired: Config = serde_json::from_value(payload["desired"].clone())?;
                ensure!(
                    *config == desired.operational_value()?,
                    "native ownership and desired configuration disagree"
                );
            }
            let adoption_path = root.join("adoption.json");
            let mut adoption = None;
            if exists(&adoption_path)? {
                let bytes = read_private(&adoption_path)?;
                let mut receipt = parse_json(&bytes)?;
                remove_field(
                    receipt
                        .get_mut("config")
                        .context("missing adoption configuration")?,
                    "native/adoption/config".into(),
                    &mut changes,
                    false,
                )?;
                ownership_config(
                    receipt
                        .get_mut("ownership_before")
                        .context("missing adoption ownership")?,
                    "native/adoption/ownership_before",
                    &mut changes,
                )?;
                files.push(Replacement {
                    path: adoption_path,
                    original: bytes,
                    converted: serde_json::to_vec(&receipt)?,
                });
                adoption = Some(receipt);
            }
            netcontrol_native::validate_offline_native_state(&ownership, adoption.as_ref())?;
            files.push(Replacement {
                path: ownership_path,
                original: ownership_bytes,
                converted: serde_json::to_vec(&ownership)?,
            });
        } else {
            ensure!(
                scope == "simulator" && options.services_state_dir.is_none(),
                "unsupported scope or unexpected native directory"
            );
        }
        let bytes = serde_json::to_vec(&payload)?;
        let converted = serde_json::to_vec(
            &json!({"schema": envelope.schema, "sha256": hex::encode(Sha256::digest(&bytes)), "state": payload}),
        )?;
        files.push(Replacement {
            path: state_path,
            original,
            converted,
        });
        Ok(Self {
            files,
            changes,
            _locks: locks,
        })
    }

    fn apply(&self, directory: &Path) -> Result<()> {
        self.apply_with(directory, publish)
    }

    fn apply_with(
        &self,
        directory: &Path,
        mut publish_file: impl FnMut(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.changes.is_empty(),
            "no retired fields found; no conversion needed"
        );
        ensure!(
            self.changes.iter().all(|change| change.rules == 0),
            "non-empty source rules require review/decommissioning with the previous binary; no files changed"
        );
        for file in &self.files {
            ensure!(
                read_private(&file.path)? == file.original,
                "source changed since preview; aborting"
            );
        }
        let directory = absolute(directory)?;
        private_directory(
            directory
                .parent()
                .context("backup directory needs parent")?,
        )?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&directory)
            .context("backup directory must not already exist")?;
        let entries: Vec<_> = self.files.iter().enumerate().map(|(index, file)| json!({
            "path": file.path, "original": format!("{index}.original"), "converted": format!("{index}.converted"),
            "original_sha256": hex::encode(Sha256::digest(&file.original)), "converted_sha256": hex::encode(Sha256::digest(&file.converted))
        })).collect();
        for (index, file) in self.files.iter().enumerate() {
            write_new(&directory.join(format!("{index}.original")), &file.original)?;
            write_new(
                &directory.join(format!("{index}.converted")),
                &file.converted,
            )?;
        }
        write_new(
            &directory.join("manifest.json"),
            &serde_json::to_vec_pretty(
                &json!({"schema":1,"operation":"remove-empty-policy-rules","files":entries,"changes":self.changes}),
            )?,
        )?;
        sync_directory(&directory)?;
        sync_directory(directory.parent().unwrap())?;
        let publication = (|| -> Result<()> {
            for file in &self.files {
                ensure!(
                    read_private(&file.path)? == file.original,
                    "source changed before publication"
                );
                publish_file(&file.path, &file.converted)?;
            }
            write_new(&directory.join("completed"), b"conversion completed\n")?;
            sync_directory(&directory)
        })();
        if let Err(error) = publication {
            anyhow::bail!(
                "publication failed or durability uncertain: {error:#}; do not start the daemon; preserve backup/staged bundle at {} and restore ALL originals before retrying",
                directory.display()
            );
        }
        Ok(())
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        cfg!(unix),
        "publishing conversion requires Unix atomic rename"
    );
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".conversion-{:032x}", rand::random::<u128>()));
    let staged = PathBuf::from(name);
    write_new(&staged, bytes)?;
    fs::rename(&staged, path)?;
    sync_directory(path.parent().context("destination needs parent")?)
}

fn run(options: Options) -> Result<()> {
    let plan = Plan::prepare(&options)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"changes":plan.changes,"files":plan.files.iter().map(|file| &file.path).collect::<Vec<_>>(),"nonempty_rules_block_apply":plan.changes.iter().any(|change|change.rules>0)})
        )?
    );
    if !options.apply {
        return Ok(());
    }
    ensure!(!plan.changes.is_empty(), "no conversion needed");
    ensure!(
        plan.changes.iter().all(|change| change.rules == 0),
        "non-empty policy rules block conversion; use the previous binary for review"
    );
    if !options.yes {
        ensure!(
            std::io::stdin().is_terminal(),
            "interactive confirmation requires a terminal; explicitly use --apply --yes for unattended operation"
        );
        eprint!(
            "This rewrites archived configurations, not live networking. Type CONVERT to continue (default: cancel): "
        );
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        ensure!(
            answer.trim() == "CONVERT",
            "conversion cancelled; no state files changed"
        );
    }
    let directory = options.backup_dir.unwrap_or_else(|| {
        let mut path = options.state.as_os_str().to_os_string();
        path.push(format!(".policy-removal-{:032x}", rand::random::<u128>()));
        PathBuf::from(path)
    });
    plan.apply(&directory)?;
    println!(
        "Conversion completed. Backup: {}. The daemon was not started; verify startup and connectivity separately.",
        absolute(&directory)?.display()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run(Options::parse()) {
        eprintln!("netcontrol-state-convert: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcontrol_core::{Engine, PERMISSIONS, Simulator};

    struct Fixture {
        directory: tempfile::TempDir,
        options: Options,
    }

    impl Fixture {
        fn new(history: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            }
            let state = directory.path().join("state.json");
            let mut engine = Engine::open(&state, Box::new(Simulator::new())).unwrap();
            if history {
                let permissions: Vec<String> =
                    PERMISSIONS.iter().map(|value| (*value).into()).collect();
                let request = json!({"base_revision":engine.committed_revision(),"confirm_timeout_seconds":30,"config":{"interfaces":[{"name":"policy_rules","kind":"dummy","role":"lan","mtu":1500,"up":true,"addresses":["192.0.2.1/24"],"metadata":{"description":"policy_rules stays descriptive"}}]}});
                let reply = engine.request(
                    "POST",
                    "/api/v1/transactions",
                    "",
                    "synthetic",
                    &permissions,
                    &serde_json::to_vec(&request).unwrap(),
                );
                assert_eq!(reply.status, 202);
                let reply = engine.request(
                    "POST",
                    &format!(
                        "/api/v1/transactions/{}/confirm",
                        reply.body["id"].as_str().unwrap()
                    ),
                    "",
                    "synthetic",
                    &permissions,
                    b"{}",
                );
                assert_eq!(reply.status, 200);
            }
            drop(engine);
            let options = Options {
                state,
                services_state_dir: None,
                apply: false,
                yes: false,
                backup_dir: None,
            };
            let fixture = Self { directory, options };
            let mut payload = fixture.payload();
            payload["desired"]["policy_rules"] = json!([]);
            for transaction in payload["transactions"]
                .as_object_mut()
                .unwrap()
                .values_mut()
            {
                transaction["previous"]["policy_rules"] = json!([]);
                transaction["candidate"]["policy_rules"] = json!([]);
            }
            fixture.save_payload(&payload);
            fixture
        }

        fn payload(&self) -> Value {
            let envelope: Envelope =
                serde_json::from_slice(&fs::read(&self.options.state).unwrap()).unwrap();
            parse_json(envelope.state.get().as_bytes()).unwrap()
        }

        fn save_payload(&self, payload: &Value) {
            let bytes = serde_json::to_vec(payload).unwrap();
            let envelope = json!({"schema":"netcontrol-rust-state-v2","sha256":hex::encode(Sha256::digest(&bytes)),"state":payload});
            fs::write(&self.options.state, serde_json::to_vec(&envelope).unwrap()).unwrap();
        }

        fn backup(&self) -> PathBuf {
            self.directory.path().join("backup")
        }

        fn native(&mut self) -> PathBuf {
            let services = self.directory.path().join("services");
            let native = services.join("native");
            fs::create_dir(&services).unwrap();
            fs::create_dir(&native).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&services, fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let mut payload = self.payload();
            payload["scope"] = json!("linux:host:synthetic");
            self.save_payload(&payload);
            let ownership = json!({"scope":payload["scope"],"firewall_config":null,"firewall_fingerprint":null,"kernel_baseline":{"namespace":{},"host":{}},"committed_config":payload["desired"]});
            write_new(
                &native.join("ownership.json"),
                &serde_json::to_vec(&ownership).unwrap(),
            )
            .unwrap();
            let receipt = json!({"scope":payload["scope"],"config":payload["desired"],"originals":{},"leases":{},"routes":[],"ownership_before":ownership,"complete":true});
            write_new(
                &native.join("adoption.json"),
                &serde_json::to_vec(&receipt).unwrap(),
            )
            .unwrap();
            self.options.services_state_dir = Some(services);
            native
        }
    }

    #[test]
    fn preview_and_apply_preserve_history_and_exact_private_backup() {
        let fixture = Fixture::new(true);
        let original = fs::read(&fixture.options.state).unwrap();
        let original_revision = fixture.payload()["revision"].clone();
        let plan = Plan::prepare(&fixture.options).unwrap();
        assert_eq!(plan.changes.len(), 3);
        assert_eq!(fs::read(&fixture.options.state).unwrap(), original);
        assert!(!fixture.backup().exists());
        plan.apply(&fixture.backup()).unwrap();
        assert_eq!(
            fs::read(fixture.backup().join("0.original")).unwrap(),
            original
        );
        assert!(fixture.backup().join("completed").exists());
        let payload = fixture.payload();
        assert_eq!(payload["revision"], original_revision);
        assert_eq!(payload["transactions"].as_object().unwrap().len(), 1);
        assert_eq!(payload["desired"]["interfaces"][0]["name"], "policy_rules");
        assert!(payload["desired"].get("policy_rules").is_none());
        private_regular(&fixture.backup().join("0.original")).unwrap();
        drop(plan);
        let reopened =
            Engine::open_saved(&fixture.options.state, Box::new(Simulator::new())).unwrap();
        assert!(Plan::prepare(&fixture.options).is_err());
        drop(reopened);
        let repeat = Plan::prepare(&fixture.options).unwrap();
        assert!(repeat.changes.is_empty());
        assert!(
            repeat
                .apply(&fixture.directory.path().join("repeat"))
                .is_err()
        );
    }

    #[test]
    fn nonempty_unknown_corrupt_and_changed_sources_are_not_published() {
        let fixture = Fixture::new(false);
        let mut payload = fixture.payload();
        payload["desired"]["policy_rules"] =
            json!([{"priority":10000,"source":"192.0.2.0/24","table":10000}]);
        fixture.save_payload(&payload);
        let plan = Plan::prepare(&fixture.options).unwrap();
        assert_eq!(plan.changes[0].rules, 1);
        assert!(plan.apply(&fixture.backup()).is_err());
        assert!(!fixture.backup().exists());
        drop(plan);
        payload["desired"]["policy_rules"] = json!([]);
        payload["desired"]["unknown"] = json!(true);
        fixture.save_payload(&payload);
        assert!(Plan::prepare(&fixture.options).is_err());
        payload["desired"]
            .as_object_mut()
            .unwrap()
            .remove("unknown");
        fixture.save_payload(&payload);
        let plan = Plan::prepare(&fixture.options).unwrap();
        fs::write(&fixture.options.state, b"corrupt").unwrap();
        assert!(plan.apply(&fixture.backup()).is_err());
        assert_eq!(fs::read(&fixture.options.state).unwrap(), b"corrupt");
        assert!(!fixture.backup().exists());
        drop(plan);
        assert!(Plan::prepare(&fixture.options).is_err());
    }

    #[test]
    fn native_snapshots_convert_together_and_failure_keeps_all_originals() {
        let mut fixture = Fixture::new(false);
        let native = fixture.native();
        let plan = Plan::prepare(&fixture.options).unwrap();
        assert_eq!(plan.files.len(), 3);
        assert_eq!(plan.changes.len(), 4);
        let mut calls = 0;
        let error = plan
            .apply_with(&fixture.backup(), |path, bytes| {
                calls += 1;
                ensure!(calls < 2, "injected publication failure");
                publish(path, bytes)
            })
            .unwrap_err();
        assert!(error.to_string().contains("do not start the daemon"));
        assert!(!fixture.backup().join("completed").exists());
        for (index, file) in plan.files.iter().enumerate() {
            assert_eq!(
                fs::read(fixture.backup().join(format!("{index}.original"))).unwrap(),
                file.original
            );
            publish(&file.path, &file.original).unwrap();
        }
        drop(plan);
        let plan = Plan::prepare(&fixture.options).unwrap();
        let complete = fixture.directory.path().join("complete");
        plan.apply(&complete).unwrap();
        let ownership = parse_json(&fs::read(native.join("ownership.json")).unwrap()).unwrap();
        let receipt = parse_json(&fs::read(native.join("adoption.json")).unwrap()).unwrap();
        assert!(ownership["committed_config"].get("policy_rules").is_none());
        assert!(receipt["config"].get("policy_rules").is_none());
        assert!(
            receipt["ownership_before"]["committed_config"]
                .get("policy_rules")
                .is_none()
        );
        netcontrol_native::validate_offline_native_state(&ownership, Some(&receipt)).unwrap();
    }

    #[test]
    fn native_intent_and_scope_mismatch_block_preview() {
        let mut fixture = Fixture::new(false);
        let native = fixture.native();
        write_new(&native.join("intent.json"), b"{}").unwrap();
        assert!(Plan::prepare(&fixture.options).is_err());
        fs::remove_file(native.join("intent.json")).unwrap();
        let path = native.join("ownership.json");
        let mut ownership = parse_json(&fs::read(&path).unwrap()).unwrap();
        ownership["scope"] = json!("linux:other");
        fs::write(path, serde_json::to_vec(&ownership).unwrap()).unwrap();
        assert!(Plan::prepare(&fixture.options).is_err());
    }

    #[test]
    fn duplicate_keys_and_unconfirmed_apply_are_rejected() {
        assert!(parse_json(br#"{"desired":{"policy_rules":[],"policy_rules":[{}]}}"#).is_err());
        assert!(Options::try_parse_from(["convert", "--state", "state.json", "--yes"]).is_err());
        let fixture = Fixture::new(false);
        fs::create_dir(fixture.backup()).unwrap();
        let plan = Plan::prepare(&fixture.options).unwrap();
        let original = fs::read(&fixture.options.state).unwrap();
        assert!(plan.apply(&fixture.backup()).is_err());
        assert_eq!(fs::read(&fixture.options.state).unwrap(), original);
    }

    #[test]
    fn checksum_tampering_and_preview_run_do_not_change_inputs() {
        let fixture = Fixture::new(false);
        let original = fs::read(&fixture.options.state).unwrap();
        run(Options {
            state: fixture.options.state.clone(),
            services_state_dir: None,
            apply: false,
            yes: false,
            backup_dir: None,
        })
        .unwrap();
        assert_eq!(fs::read(&fixture.options.state).unwrap(), original);
        let mut envelope = parse_json(&original).unwrap();
        envelope["state"]["desired"]["ipv6_enabled"] = json!(false);
        fs::write(
            &fixture.options.state,
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let error = Plan::prepare(&fixture.options)
            .err()
            .expect("checksum tampering must fail");
        assert!(error.to_string().contains("checksum mismatch"));
        assert!(!fixture.backup().exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_hardlink_inputs_are_refused() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new(false);
        let original = fs::read(&fixture.options.state).unwrap();
        let alias = fixture.directory.path().join("alias.json");
        symlink(&fixture.options.state, &alias).unwrap();
        let options = Options {
            state: alias.clone(),
            services_state_dir: None,
            apply: false,
            yes: false,
            backup_dir: None,
        };
        assert!(Plan::prepare(&options).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&fixture.options.state, &alias).unwrap();
        assert!(Plan::prepare(&fixture.options).is_err());
        assert_eq!(fs::read(&fixture.options.state).unwrap(), original);
    }
}
