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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Period {
    pub date: String,
    pub counts: Counts,
}
impl Period {
    fn add(&mut self, date: &str, delta: &Counts) -> Result<()> {
        if self.date != date {
            self.date = date.into();
            self.counts = Counts::default();
        }
        self.counts.add(delta)
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
    pub day: Period,
    pub month: Period,
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
    pub last_report_date: Option<String>,
    pub last_report_error: Option<String>,
    pub sent_datagrams: u64,
    pub failed_datagrams: u64,
}
pub(crate) const SCHEMA: &str = "netcontrol-services/counters/v2";
pub(crate) const FILE_NAME: &str = "traffic-host-v2.json";
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
                    value.schema == SCHEMA && value.scope == scope && scope == "host",
                    "incompatible traffic database schema/scope; retained without modification"
                );
                ensure!(
                    value.history.len() <= 10000,
                    "traffic history limit exceeded"
                );
                let date_format =
                    time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")?;
                if let Some(date) = &value.last_report_date {
                    time::Date::parse(date, &date_format)
                        .context("invalid last traffic report date")?;
                }
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
                    time::Date::parse(&interface.day.date, &date_format)
                        .context("invalid daily traffic date")?;
                    time::Date::parse(&format!("{}-01", interface.month.date), &date_format)
                        .context("invalid monthly traffic date")?;
                    time::OffsetDateTime::parse(
                        &interface.last_seen,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .context("invalid traffic observation timestamp")?;
                }
                Ok(value)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                schema: SCHEMA.into(),
                scope: scope.into(),
                interfaces: BTreeMap::new(),
                history: Vec::new(),
                last_report_date: None,
                last_report_error: None,
                sent_datagrams: 0,
                failed_datagrams: 0,
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
        let calendar =
            time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)?;
        let day = calendar.date().to_string();
        let month = format!("{:04}-{:02}", calendar.year(), u8::from(calendar.month()));
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
            old.day.add(&day, &delta)?;
            old.month.add(&month, &delta)?;
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
                    day: Period {
                        date: day,
                        counts: Counts::default(),
                    },
                    month: Period {
                        date: month,
                        counts: Counts::default(),
                    },
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
    fn report_due(&self, now: time::OffsetDateTime) -> bool {
        now.hour() == 23
            && now.minute() == 59
            && self
                .last_report_date
                .as_deref()
                .is_none_or(|date| date < now.date().to_string().as_str())
    }
    #[cfg(target_os = "linux")]
    fn report(&mut self, collector: &str, now: time::OffsetDateTime) -> Result<()> {
        let address: std::net::SocketAddr = collector.parse()?;
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")?;
        let hostname = hostname.trim();
        ensure!(
            !hostname.is_empty()
                && hostname.len() <= 253
                && hostname
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
            "invalid reporting hostname"
        );
        let socket = std::net::UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_nonblocking(true)?;
        self.last_report_error = None;
        for (name, interface) in &self.interfaces {
            if !interface.present {
                continue;
            }
            if name.contains([';', '|', '\n', '\r']) {
                self.failed_datagrams = self.failed_datagrams.saturating_add(1);
                self.last_report_error = Some(format!(
                    "interface name {name:?} cannot be represented in vnstat reports"
                ));
                continue;
            }
            let line = format!("{hostname}|{}\n", interface.oneline(name, now));
            match socket.send_to(line.as_bytes(), address) {
                Ok(length) if length == line.len() => {
                    self.sent_datagrams = self.sent_datagrams.saturating_add(1);
                }
                result => {
                    self.failed_datagrams = self.failed_datagrams.saturating_add(1);
                    self.last_report_error = Some(format!("UDP report for {name}: {result:?}"));
                }
            }
        }
        self.last_report_date = Some(now.date().to_string());
        Ok(())
    }
}
fn amount(value: u128) -> String {
    if value < 1024 {
        return format!("{value} B");
    }
    let mut scaled = value as f64;
    let mut unit = "B";
    for next in ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] {
        scaled /= 1024.0;
        unit = next;
        if scaled < 1024.0 {
            break;
        }
    }
    format!("{scaled:.2} {unit}")
}
fn rate(counts: &Counts, seconds: u64) -> String {
    let mut scaled =
        (counts.rx_bytes as f64 + counts.tx_bytes as f64) * 8.0 / seconds.max(1) as f64;
    let mut unit = "bit/s";
    for next in ["kbit/s", "Mbit/s", "Gbit/s", "Tbit/s", "Pbit/s", "Ebit/s"] {
        if scaled < 1000.0 {
            break;
        }
        scaled /= 1000.0;
        unit = next;
    }
    if unit == "bit/s" {
        format!("{scaled:.0} {unit}")
    } else {
        format!("{scaled:.2} {unit}")
    }
}
impl CounterInterface {
    fn oneline(&self, name: &str, now: time::OffsetDateTime) -> String {
        let seconds =
            u64::from(now.hour()) * 3600 + u64::from(now.minute()) * 60 + u64::from(now.second());
        [
            "1".into(),
            name.into(),
            self.day.date.clone(),
            amount(self.day.counts.rx_bytes.into()),
            amount(self.day.counts.tx_bytes.into()),
            amount(u128::from(self.day.counts.rx_bytes) + u128::from(self.day.counts.tx_bytes)),
            rate(&self.day.counts, seconds),
            self.month.date.clone(),
            amount(self.month.counts.rx_bytes.into()),
            amount(self.month.counts.tx_bytes.into()),
            amount(u128::from(self.month.counts.rx_bytes) + u128::from(self.month.counts.tx_bytes)),
            rate(
                &self.month.counts,
                u64::from(now.day() - 1) * 86400 + seconds,
            ),
            amount(self.total.rx_bytes.into()),
            amount(self.total.tx_bytes.into()),
            amount(u128::from(self.total.rx_bytes) + u128::from(self.total.tx_bytes)),
        ]
        .join(";")
    }
}
#[cfg(target_os = "linux")]
fn local_now() -> Result<time::OffsetDateTime> {
    let now = time::OffsetDateTime::now_utc();
    let seconds = now.unix_timestamp();
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::localtime_r(&seconds, &mut local) }.is_null(),
        "cannot read host local time"
    );
    Ok(now.to_offset(time::UtcOffset::from_whole_seconds(
        local.tm_gmtoff.try_into()?,
    )?))
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
        let Ok(index) = super::linux::ifindex(name) else {
            if !Path::new("/sys/class/net").join(name).exists() {
                continue;
            }
            anyhow::bail!("cannot identify traffic interface {name}");
        };
        values.insert(
            name.into(),
            (
                index,
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
    config: netcontrol_core::VNStatConfig,
) -> Result<Box<dyn FnOnce(super::worker::ContextState) -> Result<()> + Send>> {
    let path = directory.join(FILE_NAME);
    ensure!(
        path.exists() || !directory.join("traffic-host-v1.json").exists(),
        "prior traffic-host-v1.json retained; explicit operator archival is required before starting new calendar accounting"
    );
    let mut database = Database::load(&path, "host")?;
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
            let calendar = local_now()?;
            let now = calendar.format(&time::format_description::well_known::Rfc3339)?;
            for (name, value) in &mut database.interfaces {
                if !current.contains_key(name) {
                    value.present = false;
                }
            }
            for (name, (index, counts)) in current {
                database.observe(&boot, &namespace, &name, index, counts, &now)?;
            }
            if let Some(collector) = &config.collector {
                if database.report_due(calendar) {
                    if let Err(error) = database.report(collector, calendar) {
                        database.last_report_error = Some(format!("{error:#}"));
                        database.failed_datagrams = database.failed_datagrams.saturating_add(1);
                    }
                }
            }
            database.persist(&path)?;
            ctx.update(|s| {
                s["collected_at"] = serde_json::json!(now);
                s["interfaces"] = serde_json::to_value(&database.interfaces).unwrap();
                s["database_directory"] = serde_json::json!(directory);
                s["collector"] = serde_json::json!(config.collector);
                s["last_report_date"] = serde_json::json!(database.last_report_date);
                s["last_report_error"] = serde_json::json!(database.last_report_error);
                s["sent_datagrams"] = serde_json::json!(database.sent_datagrams.to_string());
                s["failed_datagrams"] = serde_json::json!(database.failed_datagrams.to_string());
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
            schema: SCHEMA.into(),
            scope: "host".into(),
            interfaces: BTreeMap::new(),
            history: vec![],
            last_report_date: None,
            last_report_error: None,
            sent_datagrams: 0,
            failed_datagrams: 0,
        };
        let value = |n| Counts {
            rx_bytes: n,
            tx_bytes: n,
            rx_packets: n,
            tx_packets: n,
        };
        db.observe(
            "boot1",
            "ns1",
            "eth0",
            1,
            value(100),
            "2026-10-28T00:00:00Z",
        )
        .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 0);
        db.observe(
            "boot1",
            "ns1",
            "eth0",
            1,
            value(150),
            "2026-10-28T01:00:00Z",
        )
        .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 50);
        db.observe("boot2", "ns1", "eth0", 1, value(20), "2026-10-28T02:00:00Z")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 70);
        db.observe("boot2", "ns1", "eth0", 1, value(3), "2026-10-28T03:00:00Z")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 73);
        assert_eq!(db.interfaces["eth0"].resets, 2);
        db.interfaces.get_mut("eth0").unwrap().present = false;
        db.observe("boot2", "ns1", "eth0", 1, value(4), "2026-10-28T04:00:00Z")
            .unwrap();
        assert_eq!(db.interfaces["eth0"].resets, 3);
        db.observe(
            "boot2",
            "ns2",
            "eth0",
            1,
            value(100),
            "2026-10-28T05:00:00Z",
        )
        .unwrap();
        assert_eq!(db.interfaces["eth0"].resets, 4);
        assert_eq!(db.interfaces["eth0"].total.rx_bytes, 177);
    }
    #[test]
    fn calendar_buckets_roll_over_without_resetting_lifetime_totals() {
        let path = PathBuf::from(format!(
            "missing-counter-test-{}.json",
            rand::random::<u64>()
        ));
        let mut database = Database::load(&path, "host").unwrap();
        for (now, bytes) in [
            ("2026-10-31T23:59:50+09:00", 100),
            ("2026-10-31T23:59:55+09:00", 150),
            ("2026-11-01T00:00:00+09:00", 175),
        ] {
            database
                .observe(
                    "boot",
                    "ns",
                    "vlan20",
                    2,
                    Counts {
                        rx_bytes: bytes,
                        ..Counts::default()
                    },
                    now,
                )
                .unwrap();
        }
        let interface = &database.interfaces["vlan20"];
        assert_eq!(interface.total.rx_bytes, 75);
        assert_eq!(interface.day.date, "2026-11-01");
        assert_eq!(interface.day.counts.rx_bytes, 25);
        assert_eq!(interface.month.date, "2026-11");
        assert_eq!(interface.month.counts.rx_bytes, 25);
    }
    #[test]
    fn oneline_format_matches_fifteen_field_human_readable_protocol() {
        let path = PathBuf::from(format!(
            "missing-counter-test-{}.json",
            rand::random::<u64>()
        ));
        let mut database = Database::load(&path, "host").unwrap();
        let now = "2026-10-28T23:59:00+09:00";
        for (rx_bytes, tx_bytes) in [(100, 200), (1124, 2248)] {
            database
                .observe(
                    "boot",
                    "ns",
                    "veth_homepage",
                    2,
                    Counts {
                        rx_bytes,
                        tx_bytes,
                        ..Default::default()
                    },
                    now,
                )
                .unwrap();
        }
        let calendar =
            time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)
                .unwrap();
        let line = database.interfaces["veth_homepage"].oneline("veth_homepage", calendar);
        assert_eq!(
            line,
            "1;veth_homepage;2026-10-28;1.00 KiB;2.00 KiB;3.00 KiB;0 bit/s;2026-10;1.00 KiB;2.00 KiB;3.00 KiB;0 bit/s;1.00 KiB;2.00 KiB;3.00 KiB"
        );
        assert_eq!(line.split(';').count(), 15);
        assert_eq!(amount(0), "0 B");
        assert_eq!(amount(1024 * 1024), "1.00 MiB");
        assert_eq!(
            rate(
                &Counts {
                    rx_bytes: 125_000,
                    ..Default::default()
                },
                1
            ),
            "1.00 Mbit/s"
        );
        assert!(database.report_due(calendar));
        assert!(!database.report_due(calendar - time::Duration::minutes(1)));
        assert!(!database.report_due(calendar + time::Duration::minutes(1)));
        database.last_report_date = Some("2026-10-28".into());
        assert!(!database.report_due(calendar));
        assert!(!database.report_due(calendar - time::Duration::days(1)));
        assert!(database.report_due(calendar + time::Duration::days(1)));
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn udp_reporting_persists_date_and_does_not_invent_zero_records() {
        let directory =
            std::env::temp_dir().join(format!("traffic-report-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join(FILE_NAME);
        let mut database = Database::load(&path, "host").unwrap();
        let now = "2026-10-28T23:59:05+09:00";
        for (name, index) in [("lo", 1), ("vlan20", 2), ("removed", 3), ("bad|name", 4)] {
            database
                .observe("boot", "ns", name, index, Counts::default(), now)
                .unwrap();
        }
        database.interfaces.get_mut("removed").unwrap().present = false;
        let calendar =
            time::OffsetDateTime::parse(now, &time::format_description::well_known::Rfc3339)
                .unwrap();
        assert!(database.report("not-a-socket", calendar).is_err());
        assert!(database.report_due(calendar));
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        database
            .report(&receiver.local_addr().unwrap().to_string(), calendar)
            .unwrap();
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        let mut received = Vec::new();
        for _ in 0..2 {
            let mut buffer = [0; 2048];
            let length = receiver.recv(&mut buffer).unwrap();
            let wire = std::str::from_utf8(&buffer[..length]).unwrap();
            assert!(wire.starts_with(&format!("{}|1;", hostname.trim())));
            assert!(wire.ends_with('\n'));
            let fields: Vec<_> = wire
                .trim_end()
                .split_once('|')
                .unwrap()
                .1
                .split(';')
                .collect();
            assert_eq!(fields.len(), 15);
            assert_eq!(fields[2], "2026-10-28");
            received.push(fields[1].to_owned());
        }
        assert_eq!(received, ["lo", "vlan20"]);
        assert_eq!(database.sent_datagrams, 2);
        assert_eq!(database.failed_datagrams, 1);
        assert!(
            database
                .last_report_error
                .as_ref()
                .unwrap()
                .contains("cannot be represented")
        );
        database.persist(&path).unwrap();
        let restored = Database::load(&path, "host").unwrap();
        assert!(!restored.report_due(calendar));
        assert_eq!(restored.sent_datagrams, 2);
        assert!(restored.report_due(calendar + time::Duration::days(1)));
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn old_accounting_is_retained_and_never_implicitly_reset() {
        let directory =
            std::env::temp_dir().join(format!("traffic-prior-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let prior = directory.join("traffic-host-v1.json");
        std::fs::write(&prior, b"retained accounting").unwrap();
        let error = prepare(directory.clone(), netcontrol_core::VNStatConfig::default())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("operator archival"));
        assert_eq!(std::fs::read(&prior).unwrap(), b"retained accounting");
        assert!(!directory.join(FILE_NAME).exists());
        std::fs::remove_dir_all(directory).unwrap();
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
