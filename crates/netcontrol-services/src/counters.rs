use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
#[cfg(any(test, target_os = "linux"))]
use std::path::PathBuf;
use std::{collections::BTreeMap, path::Path};
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Counts {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}
impl Counts {
    fn delta(&self, old: &Self) -> Self {
        Self {
            rx_bytes: self.rx_bytes.saturating_sub(old.rx_bytes),
            tx_bytes: self.tx_bytes.saturating_sub(old.tx_bytes),
            rx_packets: self.rx_packets.saturating_sub(old.rx_packets),
            tx_packets: self.tx_packets.saturating_sub(old.tx_packets),
        }
    }
    fn reset(&self, old: &Self) -> bool {
        self.rx_bytes < old.rx_bytes
            || self.tx_bytes < old.tx_bytes
            || self.rx_packets < old.rx_packets
            || self.tx_packets < old.tx_packets
    }
    fn add(&mut self, v: &Self) -> Result<()> {
        self.rx_bytes = self
            .rx_bytes
            .checked_add(v.rx_bytes)
            .context("rx byte history overflow")?;
        self.tx_bytes = self
            .tx_bytes
            .checked_add(v.tx_bytes)
            .context("tx byte history overflow")?;
        self.rx_packets = self
            .rx_packets
            .checked_add(v.rx_packets)
            .context("rx packet history overflow")?;
        self.tx_packets = self
            .tx_packets
            .checked_add(v.tx_packets)
            .context("tx packet history overflow")?;
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CounterInterface {
    pub ifindex: u32,
    pub boot_id: String,
    pub namespace_id: String,
    pub last: Counts,
    pub total: Counts,
    pub resets: u64,
    pub last_seen: String,
    pub present: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub collected_at: String,
    pub interface: String,
    pub delta: Counts,
    pub reset: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    pub schema: String,
    pub scope: String,
    pub interfaces: BTreeMap<String, CounterInterface>,
    pub history: Vec<Record>,
}
impl Database {
    pub fn load(path: &Path, scope: &str) -> Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                metadata.is_file(),
                "traffic state must be a regular file, not symlink/directory; retained without modification"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::read(path) {
            Ok(bytes) => {
                let value: Self = serde_json::from_slice(&bytes)
                    .context("invalid Rust traffic database; refusing reset")?;
                ensure!(
                    value.schema == "netcontrol-services/counters/v1" && value.scope == scope,
                    "incompatible traffic database schema/scope; retained without modification"
                );
                ensure!(
                    value.history.len() <= 10000,
                    "traffic history limit exceeded"
                );
                for (name, interface) in &value.interfaces {
                    ensure!(
                        !name.is_empty()
                            && name.len() <= 15
                            && !name.contains(['/', ':', '\0'])
                            && interface.ifindex > 0
                            && !interface.boot_id.is_empty()
                            && !interface.namespace_id.is_empty()
                            && !interface.last_seen.is_empty(),
                        "invalid retained traffic interface record"
                    );
                }
                Ok(value)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                schema: "netcontrol-services/counters/v1".into(),
                scope: scope.into(),
                interfaces: BTreeMap::new(),
                history: Vec::new(),
            }),
            Err(e) => Err(e.into()),
        }
    }
    pub fn observe(
        &mut self,
        boot: &str,
        namespace: &str,
        name: &str,
        index: u32,
        counters: Counts,
        now: &str,
    ) -> Result<()> {
        let mut delta = Counts::default();
        let mut reset = false;
        if let Some(old) = self.interfaces.get_mut(name) {
            reset = old.boot_id != boot
                || old.namespace_id != namespace
                || old.ifindex != index
                || !old.present
                || counters.reset(&old.last);
            delta = if reset {
                counters.clone()
            } else {
                counters.delta(&old.last)
            };
            old.total.add(&delta)?;
            old.last = counters;
            old.boot_id = boot.into();
            old.namespace_id = namespace.into();
            old.ifindex = index;
            old.present = true;
            old.last_seen = now.into();
            if reset {
                old.resets = old.resets.checked_add(1).context("reset count overflow")?;
            }
        } else {
            // The first observation is a baseline, not historical traffic we did not observe.
            self.interfaces.insert(
                name.into(),
                CounterInterface {
                    ifindex: index,
                    boot_id: boot.into(),
                    namespace_id: namespace.into(),
                    last: counters,
                    total: Counts::default(),
                    resets: 0,
                    last_seen: now.into(),
                    present: true,
                },
            );
        }
        self.history.push(Record {
            collected_at: now.into(),
            interface: name.into(),
            delta,
            reset,
        });
        if self.history.len() > 10000 {
            self.history.drain(..self.history.len() - 10000);
        }
        Ok(())
    }
    pub fn persist(&self, path: &Path) -> Result<()> {
        let pending = path.with_extension("pending");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&pending).context(
            "create new traffic snapshot; unresolved .pending snapshots require operator review",
        )?;
        use std::io::Write;
        f.write_all(&serde_json::to_vec(self)?)?;
        f.sync_all()?;
        // Windows does not allow atomic replacement through rename; native persistence is Linux-only.
        #[cfg(target_os = "linux")]
        {
            std::fs::rename(&pending, path)?;
            std::fs::File::open(path.parent().context("database parent missing")?)?.sync_all()?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            anyhow::bail!("native counter persistence requires Linux");
        }
        #[allow(unreachable_code)]
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn read() -> Result<BTreeMap<String, (u32, Counts)>> {
    let content = std::fs::read_to_string("/proc/thread-self/net/dev")?;
    let mut values = BTreeMap::new();
    for line in content.lines().skip(2) {
        let (name, data) = line.split_once(':').context("malformed /proc/net/dev")?;
        let name = name.trim();
        let n: Vec<u64> = data
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(n.len() >= 16, "short /proc/net/dev counter row");
        values.insert(
            name.into(),
            (
                super::linux::ifindex(name)?,
                Counts {
                    rx_bytes: n[0],
                    rx_packets: n[1],
                    tx_bytes: n[8],
                    tx_packets: n[9],
                },
            ),
        );
    }
    Ok(values)
}
#[cfg(target_os = "linux")]
pub(crate) fn prepare(
    directory: PathBuf,
    scope: String,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    let path = directory.join(format!("traffic-{scope}-v1.json"));
    let mut database = Database::load(&path, &scope)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    ensure!(!boot.is_empty(), "missing Linux boot identity");
    use std::os::unix::fs::MetadataExt;
    let ns = std::fs::metadata("/proc/thread-self/ns/net")?;
    let namespace = format!("{}:{}", ns.dev(), ns.ino());
    read()?;
    Ok(Box::new(move |ctx| {
        while !ctx.stopping() {
            let current = read()?;
            let now = super::worker::now();
            for (name, value) in &mut database.interfaces {
                if !current.contains_key(name) {
                    value.present = false;
                }
            }
            for (name, (index, counts)) in current {
                database.observe(&boot, &namespace, &name, index, counts, &now)?;
            }
            database.persist(&path)?;
            ctx.update(|s| {
                s["collected_at"] = serde_json::json!(now);
                s["interfaces"] = serde_json::to_value(&database.interfaces).unwrap();
                s["database_directory"] = serde_json::json!(directory);
            });
            ctx.wait(std::time::Duration::from_secs(5));
        }
        Ok(())
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counters_baseline_delta_reset_and_boot() {
        let mut db = Database {
            schema: "netcontrol-services/counters/v1".into(),
            scope: "managed".into(),
            interfaces: BTreeMap::new(),
            history: vec![],
        };
        let value = |n| Counts {
            rx_bytes: n,
            tx_bytes: n,
            rx_packets: n,
            tx_packets: n,
        };
        db.observe("boot1", "ns1", "eth0", 1, value(100), "a")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 0);
        db.observe("boot1", "ns1", "eth0", 1, value(150), "b")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 50);
        db.observe("boot2", "ns1", "eth0", 1, value(20), "c")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 70);
        db.observe("boot2", "ns1", "eth0", 1, value(3), "d")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 73);
        assert_eq!(db.interfaces["eth0"].resets, 2);
        db.interfaces.get_mut("eth0").unwrap().present = false;
        db.observe("boot2", "ns1", "eth0", 1, value(4), "e")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].resets, 3);
        db.observe("boot2", "ns2", "eth0", 1, value(100), "f")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].resets, 4);
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 177);
    }
    #[test]
    fn incompatible_database_is_not_reset() {
        let path = PathBuf::from(format!("counter-test-{}.json", rand::random::<u64>()));
        std::fs::write(&path, b"{\"schema\":\"go-vnstat\"}").unwrap();
        assert!(Database::load(&path, "host").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"schema\":\"go-vnstat\"}");
        std::fs::remove_file(path).unwrap();
    }
}
