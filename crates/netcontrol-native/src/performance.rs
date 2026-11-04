//! Passive host CPU/interrupt diagnostics. No network probes or kernel writes.
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_SMALL_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_FILES: usize = 24 * 1024;
const MAX_ROWS: usize = 4096;
const MAX_LINES: usize = 16 * 1024;
const MAX_IRQ_CPU_ROWS: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct Monitor {
    cpu: Option<Baseline>,
    softirqs: Option<Baseline>,
    softnet: Option<Baseline>,
    interrupts: Option<Baseline>,
    previous_sample: Option<(Instant, String)>,
}

struct Baseline {
    at: Instant,
    identity: String,
    counters: BTreeMap<String, Vec<u64>>,
}

struct CounterRow {
    key: String,
    metadata: Value,
    counts: Vec<u64>,
}

struct Counters {
    fields: &'static [&'static str],
    rows: Vec<CounterRow>,
    metadata: Value,
}

trait Sources {
    fn read(&mut self, path: &Path) -> Result<String>;
    fn entries(&mut self, path: &Path) -> Result<Vec<PathBuf>>;
}

struct HostSources {
    remaining_bytes: usize,
    remaining_files: usize,
}

impl Sources for HostSources {
    fn read(&mut self, path: &Path) -> Result<String> {
        ensure!(
            self.remaining_files > 0,
            "sample file-read budget exhausted"
        );
        self.remaining_files -= 1;
        let limit = if matches!(
            path.file_name().and_then(|s| s.to_str()),
            Some("stat" | "softirqs" | "softnet_stat" | "interrupts")
        ) {
            MAX_BYTES
        } else {
            MAX_SMALL_BYTES
        };
        let limit = limit.min(self.remaining_bytes);
        ensure!(limit > 0, "sample byte budget exhausted");
        let mut bytes = Vec::new();
        let result = File::open(path)
            .with_context(|| format!("open {}", path.display()))?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes);
        self.remaining_bytes = self.remaining_bytes.saturating_sub(bytes.len());
        result.with_context(|| format!("read {}", path.display()))?;
        ensure!(bytes.len() <= limit, "source exceeds bounded read limit");
        String::from_utf8(bytes).context("kernel source is not UTF-8")
    }

    fn entries(&mut self, path: &Path) -> Result<Vec<PathBuf>> {
        ensure!(
            self.remaining_files > 0,
            "sample file-read budget exhausted"
        );
        self.remaining_files -= 1;
        let mut entries = Vec::new();
        for entry in fs::read_dir(path).with_context(|| format!("list {}", path.display()))? {
            ensure!(entries.len() < MAX_ROWS, "too many kernel source entries");
            entries.push(entry?.path());
        }
        entries.sort();
        Ok(entries)
    }
}

impl Monitor {
    pub(crate) fn snapshot(&mut self) -> Result<Value> {
        self.snapshot_from(
            &mut HostSources {
                remaining_bytes: MAX_TOTAL_BYTES,
                remaining_files: MAX_FILES,
            },
            Path::new("/proc"),
            Path::new("/sys"),
            Instant::now,
        )
    }

    fn snapshot_from(
        &mut self,
        sources: &mut impl Sources,
        proc: &Path,
        sys: &Path,
        mut clock: impl FnMut() -> Instant,
    ) -> Result<Value> {
        let sampled_at = clock();
        let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let boot = sources
            .read(&proc.join("sys/kernel/random/boot_id"))
            .and_then(|text| boot_id(&text));
        let online = sources
            .read(&sys.join("devices/system/cpu/online"))
            .and_then(|text| cpu_list(&text));
        let allowed = sources
            .read(&proc.join("thread-self/status"))
            .and_then(|text| allowed_cpus(&text));
        let isolated = sources
            .read(&sys.join("devices/system/cpu/isolated"))
            .and_then(|text| cpu_list(&text));
        let topology = online
            .as_ref()
            .map_err(|error| anyhow::anyhow!("online CPUs unavailable: {error:#}"))
            .and_then(|cpus| topology(sources, sys, cpus));
        let identity =
            match (&boot, &online, &allowed, &topology) {
                (Ok(boot), Ok(online), Ok(allowed), Ok(topology)) => Some(serde_json::to_string(
                    &(boot, online, allowed, isolated.as_ref().ok(), topology),
                )?),
                _ => None,
            };
        let mut interval = self.previous_sample.as_ref().and_then(|(previous, key)| {
            (identity.as_ref() == Some(key))
                .then(|| sampled_at.checked_duration_since(*previous))
                .flatten()
                .map(|duration| duration.as_secs_f64())
                .filter(|seconds| *seconds > 0.0)
        });
        self.previous_sample = identity.clone().map(|key| (sampled_at, key));
        let mut sections = Map::new();
        sections.insert("boot_id".into(), section(boot.map(|value| json!(value))));
        sections.insert(
            "online_cpus".into(),
            section(online.map(|value| json!(value))),
        );
        sections.insert(
            "allowed_cpus".into(),
            section(allowed.map(|value| json!(value))),
        );
        sections.insert(
            "isolated_cpus".into(),
            section(isolated.map(|value| json!(value))),
        );
        sections.insert("topology".into(), section(topology));
        for (name, filename, parser, previous) in [
            (
                "cpu",
                "stat",
                parse_cpu as fn(&str) -> Result<Counters>,
                &mut self.cpu,
            ),
            ("softirqs", "softirqs", parse_softirqs, &mut self.softirqs),
            (
                "softnet",
                "net/softnet_stat",
                parse_softnet,
                &mut self.softnet,
            ),
        ] {
            let result = sources.read(&proc.join(filename)).and_then(|s| parser(&s));
            sections.insert(
                name.into(),
                counter_section(
                    result,
                    previous,
                    identity.as_deref(),
                    clock(),
                    name == "cpu",
                ),
            );
        }
        let interrupts = sources
            .read(&proc.join("interrupts"))
            .and_then(|text| parse_interrupts(&text));
        let interrupts_at = clock();
        let affinities = match &interrupts {
            Ok(counters) => section(irq_affinities(sources, proc, counters)),
            Err(error) => section(Err(anyhow::anyhow!(
                "numeric IRQ enumeration unavailable: {error:#}"
            ))),
        };
        let irq_identity = identity
            .as_ref()
            .filter(|_| affinities["status"] == "available")
            .map(|key| format!("{key}:irq_affinity:{affinities}"));
        sections.insert(
            "interrupts".into(),
            counter_section(
                interrupts,
                &mut self.interrupts,
                irq_identity.as_deref(),
                interrupts_at,
                false,
            ),
        );
        sections.insert("irq_affinity".into(), affinities);
        let recheck = identity_recheck(sources, proc, sys, &sections);
        let identity_stable = recheck["data"]["stable"] == true;
        sections.insert("identity_recheck".into(), recheck);
        if !identity_stable {
            *self = Self::default();
            interval = None;
            for name in ["cpu", "softirqs", "softnet", "interrupts"] {
                let source = &mut sections[name];
                if source["data"].is_null() {
                    continue;
                }
                source["status"] = json!("partial");
                source["data"]["partial"] = json!(true);
                source["data"]["baseline"] = json!("identity_unstable");
                source["data"]["sample_interval_seconds"] = Value::Null;
                if let Some(rows) = source["data"]["rows"].as_array_mut() {
                    for row in rows {
                        row["delta"] = Value::Null;
                        row["per_second"] = Value::Null;
                        if name == "cpu" {
                            row["busy_percent"] = Value::Null;
                            row["softirq_percent"] = Value::Null;
                        }
                    }
                }
            }
        }
        let complete = sections
            .values()
            .all(|value| value["status"] == "available");
        Ok(json!({
            "schema":"netcontrol-performance/v1",
            "sample":{
                "scope":"host",
                "started_at":started_at,
                "collected_at":OffsetDateTime::now_utc().format(&Rfc3339)?,
                "sample_interval_seconds":interval,
                "status":if complete {"available"} else {"partial"},
                "allowed_cpus_scope":"collector_thread",
                "identity_stable":identity_stable,
                "atomic":false
            },
            "sections":sections
        }))
    }
}

fn identity_recheck(
    sources: &mut impl Sources,
    proc: &Path,
    sys: &Path,
    sections: &Map<String, Value>,
) -> Value {
    let mut stable = true;
    let mut checks = Map::new();
    for (name, path) in [
        ("boot_id", proc.join("sys/kernel/random/boot_id")),
        ("online_cpus", sys.join("devices/system/cpu/online")),
        ("allowed_cpus", proc.join("thread-self/status")),
        ("isolated_cpus", sys.join("devices/system/cpu/isolated")),
    ] {
        let final_value = section(sources.read(&path).and_then(|text| match name {
            "boot_id" => boot_id(&text).map(|id| json!(id)),
            "allowed_cpus" => allowed_cpus(&text).map(|ids| json!(ids)),
            _ => cpu_list(&text).map(|ids| json!(ids)),
        }));
        let initial_value = &sections[name];
        let available =
            initial_value["status"] == "available" && final_value["status"] == "available";
        let matches = available && initial_value["data"] == final_value["data"];
        stable &= matches;
        checks.insert(
            name.into(),
            json!({
                "initial":initial_value,
                "final":final_value,
                "matches":matches,
                "error":if matches {
                    None
                } else if available {
                    Some("identity value changed during collection")
                } else {
                    Some("identity source unavailable during initial or final read")
                }
            }),
        );
    }
    json!({
        "status":if stable {"available"} else {"partial"},
        "data":{"partial":!stable,"stable":stable,"checks":checks},
        "error":if stable {None} else {Some("host identity changed or could not be verified during collection")}
    })
}

fn section(result: Result<Value>) -> Value {
    match result {
        Ok(data) => {
            let partial = data.get("partial").and_then(Value::as_bool) == Some(true);
            json!({"status":if partial {"partial"} else {"available"},"data":data,"error":null})
        }
        Err(error) => json!({"status":"unavailable","data":null,"error":format!("{error:#}")}),
    }
}

fn counter_section(
    result: Result<Counters>,
    previous: &mut Option<Baseline>,
    identity: Option<&str>,
    now: Instant,
    cpu: bool,
) -> Value {
    let counters = match result {
        Ok(counters) => counters,
        Err(error) => {
            *previous = None;
            return section(Err(error));
        }
    };
    let current: BTreeMap<_, _> = counters
        .rows
        .iter()
        .map(|row| (row.key.clone(), row.counts.clone()))
        .collect();
    let cpu_ids_available = counters.metadata["cpu_ids_available"] != false;
    let identity = identity
        .filter(|_| cpu_ids_available)
        .map(|key| format!("{key}:{}", counters.metadata));
    let mut reason = "initial_or_source_recovered";
    let mut interval = None;
    let mut deltas = None;
    if let Some(key) = &identity {
        if let Some(old) = previous.as_ref() {
            if old.identity != *key || !old.counters.keys().eq(current.keys()) {
                reason = "topology_or_source_layout_changed";
            } else if let Some(duration) = now.checked_duration_since(old.at) {
                let seconds = duration.as_secs_f64();
                if seconds > 0.0 {
                    let changes: Option<BTreeMap<_, Vec<_>>> = current
                        .iter()
                        .map(|(key, values)| {
                            let before = &old.counters[key];
                            (values.len() == before.len())
                                .then(|| {
                                    values
                                        .iter()
                                        .zip(before)
                                        .map(|(a, b)| a.checked_sub(*b))
                                        .collect::<Option<Vec<_>>>()
                                })
                                .flatten()
                                .map(|values| (key.clone(), values))
                        })
                        .collect();
                    if let Some(changes) = changes {
                        interval = Some(seconds);
                        deltas = Some(changes);
                        reason = "ready";
                    } else {
                        reason = "counter_reset";
                    }
                } else {
                    reason = "nonpositive_interval";
                }
            } else {
                reason = "monotonic_clock_reset";
            }
        }
    } else {
        reason = if cpu_ids_available {
            "identity_unavailable"
        } else {
            "cpu_identity_unavailable"
        };
    }
    let rows: Vec<_> = counters
        .rows
        .into_iter()
        .map(|row| {
            let mut value = row.metadata;
            value["counts"] = string_counts(counters.fields, &row.counts);
            let change = deltas.as_ref().and_then(|values| values.get(&row.key));
            value["delta"] = change
                .map(|values| string_counts(counters.fields, values))
                .unwrap_or(Value::Null);
            value["per_second"] = match (change, interval) {
                (Some(values), Some(seconds)) => Value::Object(
                    counters
                        .fields
                        .iter()
                        .zip(values)
                        .map(|(key, count)| ((*key).into(), json!(*count as f64 / seconds)))
                        .collect(),
                ),
                _ => Value::Null,
            };
            if cpu {
                // user/nice already include guest/guest_nice: sum only the first eight fields.
                value["busy_percent"] = change
                    .filter(|values| values[10] > 0)
                    .map(|values| json!(100.0 * values[11] as f64 / values[10] as f64))
                    .unwrap_or(Value::Null);
                value["softirq_percent"] = change
                    .filter(|values| values[10] > 0)
                    .map(|values| json!(100.0 * values[6] as f64 / values[10] as f64))
                    .unwrap_or(Value::Null);
            }
            value
        })
        .collect();
    *previous = identity.map(|identity| Baseline {
        at: now,
        identity,
        counters: current,
    });
    section(Ok(json!({
        "partial":counters.metadata["partial"] == true,
        "metadata":counters.metadata,
        "sample_interval_seconds":interval,
        "baseline":reason,
        "rows":rows
    })))
}

fn string_counts(fields: &[&str], values: &[u64]) -> Value {
    Value::Object(
        fields
            .iter()
            .zip(values)
            .map(|(key, value)| ((*key).into(), json!(value.to_string())))
            .collect(),
    )
}

fn lines(text: &str) -> Result<Vec<&str>> {
    ensure!(text.len() <= MAX_BYTES, "source exceeds 2 MiB");
    let mut result = Vec::new();
    for line in text.lines() {
        ensure!(result.len() < MAX_LINES, "source has too many lines");
        result.push(line);
    }
    Ok(result)
}

fn unsigned(text: &str) -> Result<u64> {
    ensure!(
        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid decimal kernel counter"
    );
    text.parse().context("decimal kernel counter overflow")
}

fn cpu_id(text: &str) -> Result<u32> {
    u32::try_from(unsigned(text)?).context("CPU identifier overflow")
}

fn cpu_list(text: &str) -> Result<Vec<u32>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(text.len() <= MAX_SMALL_BYTES, "CPU list too long");
    let mut cpus = BTreeSet::new();
    for word in text.split(',') {
        let (first, last) = match word.split_once('-') {
            Some((first, last)) => (cpu_id(first)?, cpu_id(last)?),
            None => {
                let id = cpu_id(word)?;
                (id, id)
            }
        };
        ensure!(first <= last, "reversed CPU range");
        ensure!(
            u64::from(last) - u64::from(first) < MAX_ROWS as u64,
            "CPU range exceeds row limit"
        );
        for cpu in first..=last {
            ensure!(cpus.len() < MAX_ROWS, "CPU list exceeds row limit");
            ensure!(cpus.insert(cpu), "duplicate CPU identifier");
        }
    }
    Ok(cpus.into_iter().collect())
}

fn allowed_cpus(text: &str) -> Result<Vec<u32>> {
    let mut found = None;
    for line in lines(text)? {
        if let Some(list) = line.strip_prefix("Cpus_allowed_list:") {
            ensure!(found.is_none(), "duplicate allowed CPU list");
            let cpus = cpu_list(list)?;
            ensure!(!cpus.is_empty(), "empty allowed CPU list");
            found = Some(cpus);
        }
    }
    found.context("Cpus_allowed_list unavailable")
}

fn boot_id(text: &str) -> Result<String> {
    let text = text.trim();
    ensure!(
        text.len() == 36
            && text.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }),
        "invalid boot identity"
    );
    Ok(text.to_owned())
}

fn parse_cpu(text: &str) -> Result<Counters> {
    const FIELDS: &[&str] = &[
        "user_ticks",
        "nice_ticks",
        "system_ticks",
        "idle_ticks",
        "iowait_ticks",
        "irq_ticks",
        "softirq_ticks",
        "steal_ticks",
        "guest_ticks",
        "guest_nice_ticks",
        "total_ticks",
        "busy_ticks",
    ];
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let mut field_count = None;
    for line in lines(text)? {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else {
            continue;
        };
        let Some(id) = name.strip_prefix("cpu").filter(|id| !id.is_empty()) else {
            continue;
        };
        if !id.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let id = cpu_id(id)?;
        ensure!(rows.len() < MAX_ROWS, "too many per-CPU rows");
        ensure!(seen.insert(id), "duplicate per-CPU stat row");
        let mut values: Vec<u64> = words.map(unsigned).collect::<Result<_>>()?;
        ensure!(
            (7..=10).contains(&values.len()),
            "unsupported CPU tick shape"
        );
        ensure!(
            field_count.is_none_or(|count| count == values.len()),
            "inconsistent CPU tick shape"
        );
        field_count = Some(values.len());
        values.resize(10, 0);
        let total = values[..8]
            .iter()
            .try_fold(0_u64, |sum, value| sum.checked_add(*value))
            .context("CPU total counter overflow")?;
        let busy = total - values[3] - values[4];
        values.extend([total, busy]);
        rows.push(CounterRow {
            key: id.to_string(),
            metadata: json!({"cpu_id":id}),
            counts: values,
        });
    }
    ensure!(!rows.is_empty(), "no per-CPU stat rows");
    Ok(Counters {
        fields: FIELDS,
        rows,
        metadata: json!({
            "source":"/proc/stat",
            "tick_fields":field_count,
            "units":"USER_HZ_ticks",
            "total_excludes_guest_double_count":true,
            "busy_excludes_idle_and_iowait":true
        }),
    })
}

fn cpu_header(line: &str) -> Result<Vec<u32>> {
    let mut cpus = Vec::new();
    let mut seen = BTreeSet::new();
    for word in line.split_whitespace() {
        ensure!(cpus.len() < MAX_ROWS, "too many CPU columns");
        let id = cpu_id(word.strip_prefix("CPU").context("invalid CPU header")?)?;
        ensure!(seen.insert(id), "duplicate CPU header");
        cpus.push(id);
    }
    ensure!(!cpus.is_empty(), "missing CPU header");
    Ok(cpus)
}

fn parse_softirqs(text: &str) -> Result<Counters> {
    let lines = lines(text)?;
    let cpus = cpu_header(lines.first().context("missing softirq header")?)?;
    let mut rx = None;
    let mut tx = None;
    for line in &lines[1..] {
        let Some((name, values)) = line.split_once(':') else {
            ensure!(line.trim().is_empty(), "invalid softirq row");
            continue;
        };
        let target = match name.trim() {
            "NET_RX" => &mut rx,
            "NET_TX" => &mut tx,
            _ => continue,
        };
        ensure!(target.is_none(), "duplicate network softirq row");
        let counts = values
            .split_whitespace()
            .map(unsigned)
            .collect::<Result<Vec<_>>>()?;
        ensure!(counts.len() == cpus.len(), "softirq CPU column mismatch");
        *target = Some(counts);
    }
    let rx = rx.context("NET_RX unavailable")?;
    let tx = tx.context("NET_TX unavailable")?;
    Ok(Counters {
        fields: &["net_rx", "net_tx"],
        rows: cpus
            .iter()
            .enumerate()
            .map(|(index, id)| CounterRow {
                key: id.to_string(),
                metadata: json!({"cpu_id":id}),
                counts: vec![rx[index], tx[index]],
            })
            .collect(),
        metadata: json!({"source":"/proc/softirqs","cpu_ids":cpus,"units":"softirq_invocations"}),
    })
}

fn parse_softnet(text: &str) -> Result<Counters> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let mut columns = None;
    for line in lines(text)? {
        ensure!(!line.trim().is_empty(), "empty softnet row");
        ensure!(rows.len() < MAX_ROWS, "too many softnet rows");
        let words: Vec<_> = line.split_whitespace().collect();
        // Historical 11-column kernels omit CPU IDs and skip offline CPUs.
        // Modern kernels append backlog length and an explicit CPU ID at columns 12 and 13.
        ensure!(
            words.len() == 11 || (13..=32).contains(&words.len()),
            "unsupported softnet layout (expected historical 11 or modern 13+ columns)"
        );
        ensure!(
            columns.is_none_or(|count| count == words.len()),
            "inconsistent softnet layout"
        );
        columns = Some(words.len());
        let values = words
            .iter()
            .map(|word| {
                ensure!(
                    !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "invalid hexadecimal softnet counter"
                );
                u64::from_str_radix(word, 16).context("softnet counter overflow")
            })
            .collect::<Result<Vec<_>>>()?;
        let id = if words.len() == 11 {
            None
        } else {
            Some(u32::try_from(values[12]).context("softnet CPU ID overflow")?)
        };
        if let Some(id) = id {
            ensure!(seen.insert(id), "duplicate softnet CPU ID");
        }
        rows.push(CounterRow {
            key: id
                .map(|id| id.to_string())
                .unwrap_or_else(|| format!("row/{}", rows.len())),
            metadata: if id.is_some() {
                json!({"cpu_id":id})
            } else {
                json!({"cpu_id":null,"row_index":rows.len()})
            },
            counts: values[..3].to_vec(),
        });
    }
    ensure!(!rows.is_empty(), "softnet counters unavailable");
    Ok(Counters {
        fields: &["processed", "dropped", "time_squeeze"],
        rows,
        metadata: json!({
            "source":"/proc/net/softnet_stat",
            "columns":columns,
            "cpu_id_source":if columns == Some(11) {"unavailable_historical_11_column"} else {"column_13_hex"},
            "cpu_ids_available":columns != Some(11),
            "partial":columns == Some(11),
            "limitation":if columns == Some(11) {
                Some("Historical output omits CPU IDs and skips offline CPUs; row indices are not CPU IDs. Rates are unavailable.")
            } else {
                None
            },
            "counter_width_bits":32,
            "decrease_policy":"reset_baseline_no_wrap_inference",
            "units":"kernel_events"
        }),
    })
}

fn parse_interrupts(text: &str) -> Result<Counters> {
    let lines = lines(text)?;
    let cpus = cpu_header(lines.first().context("missing interrupt header")?)?;
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for line in &lines[1..] {
        if line.trim().is_empty() {
            continue;
        }
        let (label, rest) = line.split_once(':').context("invalid interrupt row")?;
        let label = label.trim();
        if !label.bytes().all(|byte| byte.is_ascii_digit()) || label.is_empty() {
            continue;
        }
        ensure!(seen.len() < MAX_ROWS, "too many numeric hardware IRQs");
        let irq = cpu_id(label)?;
        ensure!(seen.insert(irq), "duplicate numeric hardware IRQ");
        let mut words = rest.split_whitespace();
        let mut counts = Vec::new();
        for _ in &cpus {
            counts.push(unsigned(words.next().context("missing IRQ CPU counter")?)?);
        }
        let description = words.collect::<Vec<_>>().join(" ");
        ensure!(!description.is_empty(), "missing hardware IRQ description");
        for (id, count) in cpus.iter().zip(counts) {
            ensure!(
                rows.len() < MAX_IRQ_CPU_ROWS,
                "IRQ/CPU matrix exceeds row limit"
            );
            rows.push(CounterRow {
                key: format!("{irq}/{id}/{description}"),
                metadata: json!({"irq":irq,"cpu_id":id,"description":description}),
                counts: vec![count],
            });
        }
    }
    Ok(Counters {
        fields: &["interrupts"],
        rows,
        metadata: json!({"source":"/proc/interrupts","cpu_ids":cpus,"numeric_hardware_irqs_only":true}),
    })
}

fn irq_affinities(sources: &mut impl Sources, proc: &Path, interrupts: &Counters) -> Result<Value> {
    let irqs: BTreeSet<_> = interrupts
        .rows
        .iter()
        .filter_map(|row| row.metadata["irq"].as_u64())
        .collect();
    let mut partial = false;
    let mut rows = Vec::new();
    for irq in irqs {
        let mut row = json!({"irq":irq});
        for name in ["smp_affinity_list", "effective_affinity_list"] {
            let path = proc.join("irq").join(irq.to_string()).join(name);
            let evidence = section(
                sources
                    .read(&path)
                    .and_then(|text| cpu_list(&text))
                    .map(|cpus| json!({"cpu_ids":cpus})),
            );
            partial |= evidence["status"] != "available";
            row[name] = evidence;
        }
        rows.push(row);
    }
    Ok(json!({"partial":partial,"rows":rows}))
}

fn topology(sources: &mut impl Sources, sys: &Path, cpus: &[u32]) -> Result<Value> {
    ensure!(!cpus.is_empty(), "online CPU list is empty");
    let numa = section(numa_nodes(sources, sys));
    let mut partial = numa["status"] != "available";
    let mut numa_by_cpu = BTreeMap::<u64, Vec<u64>>::new();
    if let Some(nodes) = numa["data"].as_array() {
        for node in nodes {
            let id = node["node_id"].as_u64().context("invalid NUMA node ID")?;
            for cpu in node["cpu_ids"]
                .as_array()
                .context("invalid NUMA CPU list")?
            {
                numa_by_cpu
                    .entry(cpu.as_u64().context("invalid NUMA CPU ID")?)
                    .or_default()
                    .push(id);
            }
        }
    }
    let mut rows = Vec::new();
    for cpu in cpus {
        let mut row = json!({"cpu_id":cpu});
        for name in ["physical_package_id", "core_id"] {
            let path = sys
                .join("devices/system/cpu")
                .join(format!("cpu{cpu}"))
                .join("topology")
                .join(name);
            let evidence = section(sources.read(&path).and_then(|text| {
                let value: i32 = text.trim().parse().context("invalid topology identifier")?;
                ensure!(value >= 0, "topology identifier not exposed by kernel");
                Ok(json!(value))
            }));
            partial |= evidence["status"] != "available";
            row[name] = evidence;
        }
        row["numa_node_ids"] = if numa["status"] == "available" {
            json!(
                numa_by_cpu
                    .get(&u64::from(*cpu))
                    .cloned()
                    .unwrap_or_default()
            )
        } else {
            Value::Null
        };
        rows.push(row);
    }
    Ok(json!({"partial":partial,"cpus":rows,"numa":numa}))
}

fn numa_nodes(sources: &mut impl Sources, sys: &Path) -> Result<Value> {
    let path = sys.join("devices/system/node");
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in sources.entries(&path)? {
        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(id) = name.strip_prefix("node") else {
            continue;
        };
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        ensure!(rows.len() < MAX_ROWS, "too many NUMA nodes");
        let id = cpu_id(id)?;
        ensure!(seen.insert(id), "duplicate NUMA node");
        let cpus = cpu_list(&sources.read(&entry.join("cpulist"))?)?;
        rows.push(json!({"node_id":id,"cpu_ids":cpus}));
    }
    ensure!(!rows.is_empty(), "NUMA topology not exposed");
    rows.sort_by_key(|row| row["node_id"].as_u64());
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, time::Duration};

    fn cpu_text(user: u64, idle: u64, softirq: u64) -> String {
        format!("cpu 0 0 0 0\ncpu3 {user} 0 10 {idle} 0 5 {softirq} 0 7 0\n")
    }

    fn counter_data(
        text: &str,
        previous: &mut Option<Baseline>,
        identity: Option<&str>,
        at: Instant,
    ) -> Value {
        counter_section(parse_cpu(text), previous, identity, at, true)["data"].clone()
    }

    #[test]
    fn cpu_deltas_exclude_guest_double_counting_and_use_elapsed_time() {
        let now = Instant::now();
        let mut baseline = None;
        let first = counter_data(&cpu_text(20, 100, 5), &mut baseline, Some("a"), now);
        assert_eq!(first["rows"][0]["counts"]["total_ticks"], "140");
        assert_eq!(first["rows"][0]["counts"]["busy_ticks"], "40");
        assert!(first["rows"][0]["busy_percent"].is_null());
        let next = counter_data(
            &cpu_text(40, 160, 25),
            &mut baseline,
            Some("a"),
            now + Duration::from_secs(2),
        );
        assert_eq!(next["sample_interval_seconds"], 2.0);
        assert_eq!(next["rows"][0]["busy_percent"], 40.0);
        assert_eq!(next["rows"][0]["softirq_percent"], 20.0);
        assert_eq!(next["rows"][0]["per_second"]["softirq_ticks"], 10.0);
        assert_eq!(next["rows"][0]["delta"]["total_ticks"], "100");
    }

    #[test]
    fn resets_identity_changes_and_failed_sources_clear_rates() {
        let now = Instant::now();
        let mut baseline = None;
        counter_data(&cpu_text(20, 100, 5), &mut baseline, Some("a"), now);
        let reset = counter_data(
            &cpu_text(10, 100, 5),
            &mut baseline,
            Some("a"),
            now + Duration::from_secs(1),
        );
        assert_eq!(reset["baseline"], "counter_reset");
        assert!(reset["sample_interval_seconds"].is_null());
        let changed = counter_data(
            &cpu_text(20, 110, 6),
            &mut baseline,
            Some("b"),
            now + Duration::from_secs(2),
        );
        assert_eq!(changed["baseline"], "topology_or_source_layout_changed");
        let failed = counter_section(
            Err(anyhow::anyhow!("fixture read failed")),
            &mut baseline,
            Some("b"),
            now + Duration::from_secs(3),
            true,
        );
        assert_eq!(failed["status"], "unavailable");
        assert!(baseline.is_none());
        let recovered = counter_data(
            &cpu_text(30, 120, 7),
            &mut baseline,
            Some("b"),
            now + Duration::from_secs(4),
        );
        assert!(recovered["rows"][0]["delta"].is_null());
        let unknown = counter_data(
            &cpu_text(40, 130, 8),
            &mut baseline,
            None,
            now + Duration::from_secs(5),
        );
        assert_eq!(unknown["baseline"], "identity_unavailable");
        assert!(baseline.is_none());
    }

    #[test]
    fn zero_elapsed_and_zero_tick_delta_never_invent_utilization() {
        let now = Instant::now();
        let mut baseline = None;
        let text = cpu_text(20, 100, 5);
        counter_data(&text, &mut baseline, Some("a"), now);
        let same = counter_data(&text, &mut baseline, Some("a"), now);
        assert_eq!(same["baseline"], "nonpositive_interval");
        let idle = counter_data(
            &text,
            &mut baseline,
            Some("a"),
            now + Duration::from_secs(1),
        );
        assert_eq!(idle["baseline"], "ready");
        assert!(idle["rows"][0]["busy_percent"].is_null());
    }

    #[test]
    fn softirq_sparse_cpu_headers_and_large_decimal_counts_are_exact() {
        let parsed = parse_softirqs(
            " CPU7 CPU2\n NET_TX: 9007199254740993 4\n NET_RX: 18446744073709551615 8\n",
        )
        .unwrap();
        assert_eq!(parsed.rows[0].metadata["cpu_id"], 7);
        assert_eq!(parsed.rows[1].counts, [8, 4]);
        let rendered = counter_section(Ok(parsed), &mut None, Some("a"), Instant::now(), false);
        assert_eq!(
            rendered["data"]["rows"][0]["counts"]["net_rx"],
            "18446744073709551615"
        );
        assert!(parse_softirqs("CPU0 CPU0\nNET_RX: 1 2\nNET_TX: 3 4").is_err());
        assert!(parse_softirqs("CPU0\nNET_RX: 1\n").is_err());
    }

    #[test]
    fn modern_softnet_uses_explicit_hex_cpu_id_not_line_number() {
        let modern = parse_softnet(
            "00000010 00000002 00000003 0 0 0 0 0 0 0 0 4 0000000a\n\
             00000020 00000005 00000006 0 0 0 0 0 0 0 0 1 00000002\n",
        )
        .unwrap();
        assert_eq!(modern.rows[0].metadata["cpu_id"], 10);
        assert_eq!(modern.rows[1].metadata["cpu_id"], 2);
        assert_eq!(modern.rows[0].counts, [16, 2, 3]);
        assert_eq!(modern.metadata["cpu_id_source"], "column_13_hex");
        let extended = parse_softnet("1 2 3 0 0 0 0 0 0 0 0 4 a 2 2").unwrap();
        assert_eq!(extended.rows[0].metadata["cpu_id"], 10);
        assert!(parse_softnet("1 2 3 0 0 0 0 0 0 0 0 4").is_err());
        assert!(parse_softnet("1 2 3 0 0 0 0 0 0 0 0 4 a\n1 2 3 0 0 0 0 0 0 0 0 4 a").is_err());
    }

    #[test]
    fn historical_softnet_never_invents_cpu_ids_or_rates() {
        let parsed = parse_softnet("1 2 3 0 0 0 0 0 0 0 0\n4 5 6 0 0 0 0 0 0 0 0").unwrap();
        assert!(parsed.rows[0].metadata["cpu_id"].is_null());
        assert_eq!(parsed.rows[1].metadata["row_index"], 1);
        assert_eq!(
            parsed.metadata["cpu_id_source"],
            "unavailable_historical_11_column"
        );
        let mut baseline = None;
        let rendered = counter_section(Ok(parsed), &mut baseline, Some("a"), Instant::now(), false);
        assert_eq!(rendered["status"], "partial");
        assert_eq!(rendered["data"]["baseline"], "cpu_identity_unavailable");
        assert!(baseline.is_none());
    }

    #[test]
    fn interrupts_preserve_cpu_ids_and_skip_pseudo_interrupts() {
        let parsed = parse_interrupts(
            " CPU3 CPU8\n 41: 9007199254740993 2 PCI-MSI eth0-rx-0\n\
             NMI: 1 2 Non-maskable interrupts\n ERR: 4\n",
        )
        .unwrap();
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0].metadata["irq"], 41);
        assert_eq!(parsed.rows[0].metadata["cpu_id"], 3);
        assert_eq!(parsed.rows[0].counts, [9007199254740993]);
        assert_eq!(parsed.rows[1].metadata["cpu_id"], 8);
        assert!(parse_interrupts("CPU0 CPU1\n1: 4 PCI-MSI dev").is_err());
        assert!(parse_interrupts("").is_err());
    }

    #[test]
    fn parsers_reject_duplicates_overflows_and_unbounded_cpu_lists() {
        assert_eq!(cpu_list("0-2,7,10-11\n").unwrap(), [0, 1, 2, 7, 10, 11]);
        for text in ["2-1", "0-4294967295", "0,0", "0-2,1", "-1", "0, 1"] {
            assert!(cpu_list(text).is_err(), "{text}");
        }
        assert!(parse_cpu("cpu0 1 2 3 4 5 6 7\ncpu0 1 2 3 4 5 6 7").is_err());
        assert!(parse_cpu("cpu0 18446744073709551615 1 0 0 0 0 0").is_err());
        assert!(allowed_cpus("Name: example\n").is_err());
        assert!(parse_cpu(&"x".repeat(MAX_BYTES + 1)).is_err());
    }

    #[derive(Default)]
    struct Fixture {
        files: BTreeMap<PathBuf, String>,
        directories: BTreeMap<PathBuf, Vec<PathBuf>>,
        reads: BTreeMap<PathBuf, VecDeque<Option<String>>>,
    }

    impl Sources for Fixture {
        fn read(&mut self, path: &Path) -> Result<String> {
            if let Some(text) = self.reads.get_mut(path).and_then(VecDeque::pop_front) {
                return text.with_context(|| {
                    format!("fixture scheduled read unavailable: {}", path.display())
                });
            }
            self.files
                .get(path)
                .cloned()
                .with_context(|| format!("fixture source unavailable: {}", path.display()))
        }

        fn entries(&mut self, path: &Path) -> Result<Vec<PathBuf>> {
            self.directories
                .get(path)
                .cloned()
                .with_context(|| format!("fixture directory unavailable: {}", path.display()))
        }
    }

    impl Fixture {
        fn complete() -> Self {
            let mut fixture = Self::default();
            for (path, text) in [
                (
                    "proc/sys/kernel/random/boot_id",
                    "00000000-0000-0000-0000-000000000001",
                ),
                ("sys/devices/system/cpu/online", "3"),
                ("sys/devices/system/cpu/isolated", ""),
                ("proc/thread-self/status", "Cpus_allowed_list:\t3\n"),
                ("proc/softirqs", "CPU3\nNET_RX: 8\nNET_TX: 4\n"),
                ("proc/net/softnet_stat", "10 0 0 0 0 0 0 0 0 0 0 0 3"),
                ("proc/interrupts", "CPU3\n41: 5 PCI-MSI eth0-rx-0\n"),
                ("proc/irq/41/smp_affinity_list", "3"),
                ("proc/irq/41/effective_affinity_list", "3"),
                (
                    "sys/devices/system/cpu/cpu3/topology/physical_package_id",
                    "0",
                ),
                ("sys/devices/system/cpu/cpu3/topology/core_id", "1"),
                ("sys/devices/system/node/node0/cpulist", "3"),
            ] {
                fixture.files.insert(PathBuf::from(path), text.into());
            }
            fixture
                .files
                .insert(PathBuf::from("proc/stat"), cpu_text(20, 100, 5));
            fixture.directories.insert(
                PathBuf::from("sys/devices/system/node"),
                vec![PathBuf::from("sys/devices/system/node/node0")],
            );
            fixture
        }
    }

    #[test]
    fn read_only_fixture_snapshot_has_host_scope_and_isolates_source_failures() {
        let mut fixture = Fixture::complete();
        let mut monitor = Monitor::default();
        let now = Instant::now();
        let first = monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || now)
            .unwrap();
        assert_eq!(first["sample"]["scope"], "host");
        assert_eq!(first["sample"]["status"], "available");
        assert!(first["sample"]["sample_interval_seconds"].is_null());
        assert!(
            first["sample"]["collected_at"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
        assert_eq!(
            first["sections"]["topology"]["data"]["cpus"][0]["numa_node_ids"],
            json!([0])
        );
        fixture.files.remove(Path::new("proc/softirqs"));
        let second = monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                now + Duration::from_secs(2)
            })
            .unwrap();
        assert_eq!(second["sample"]["status"], "partial");
        assert_eq!(second["sample"]["sample_interval_seconds"], 2.0);
        assert_eq!(second["sections"]["softirqs"]["status"], "unavailable");
        assert_eq!(second["sections"]["cpu"]["data"]["baseline"], "ready");
        assert!(monitor.softirqs.is_none());
        fixture.files.insert(
            PathBuf::from("proc/softirqs"),
            "CPU3\nNET_RX: 9\nNET_TX: 5\n".into(),
        );
        fixture.files.insert(
            PathBuf::from("sys/devices/system/cpu/cpu3/topology/core_id"),
            "2".into(),
        );
        let third = monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                now + Duration::from_secs(3)
            })
            .unwrap();
        assert!(third["sample"]["sample_interval_seconds"].is_null());
        assert!(third["sections"]["cpu"]["data"]["rows"][0]["busy_percent"].is_null());
        assert!(third["sections"]["softirqs"]["data"]["rows"][0]["delta"].is_null());
    }

    #[test]
    fn unavailable_affinity_and_topology_are_partial_not_zero_success() {
        let mut fixture = Fixture::complete();
        fixture
            .files
            .remove(Path::new("proc/irq/41/effective_affinity_list"));
        fixture
            .files
            .remove(Path::new("sys/devices/system/cpu/cpu3/topology/core_id"));
        let result = Monitor::default()
            .snapshot_from(
                &mut fixture,
                Path::new("proc"),
                Path::new("sys"),
                Instant::now,
            )
            .unwrap();
        assert_eq!(result["sample"]["status"], "partial");
        assert_eq!(result["sections"]["irq_affinity"]["status"], "partial");
        assert_eq!(
            result["sections"]["irq_affinity"]["data"]["rows"][0]["smp_affinity_list"]["data"]["cpu_ids"],
            json!([3])
        );
        assert_eq!(
            result["sections"]["irq_affinity"]["data"]["rows"][0]["effective_affinity_list"]["status"],
            "unavailable"
        );
        assert_eq!(result["sections"]["topology"]["status"], "partial");
        assert!(result["sections"]["topology"]["data"]["cpus"][0]["core_id"]["data"].is_null());
    }

    #[test]
    fn source_intervals_use_capture_times_and_isolation_changes_reset_baselines() {
        let mut fixture = Fixture::complete();
        let mut monitor = Monitor::default();
        let now = Instant::now();
        let mut times = [0, 1, 2, 3, 4].into_iter();
        monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                now + Duration::from_secs(times.next().unwrap())
            })
            .unwrap();
        let mut times = [10, 12, 14, 16, 18].into_iter();
        let second = monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                now + Duration::from_secs(times.next().unwrap())
            })
            .unwrap();
        assert_eq!(second["sample"]["sample_interval_seconds"], 10.0);
        for (name, seconds) in [
            ("cpu", 11.0),
            ("softirqs", 12.0),
            ("softnet", 13.0),
            ("interrupts", 14.0),
        ] {
            assert_eq!(
                second["sections"][name]["data"]["sample_interval_seconds"],
                seconds
            );
        }
        fixture
            .files
            .insert(PathBuf::from("sys/devices/system/cpu/isolated"), "3".into());
        let third = monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                now + Duration::from_secs(30)
            })
            .unwrap();
        assert_eq!(third["sections"]["isolated_cpus"]["data"], json!([3]));
        assert!(third["sample"]["sample_interval_seconds"].is_null());
        assert_eq!(
            third["sections"]["cpu"]["data"]["baseline"],
            "topology_or_source_layout_changed"
        );
    }

    #[test]
    fn irq_affinity_changes_reset_irq_baselines_without_invalidating_cpu_rates() {
        for name in ["smp_affinity_list", "effective_affinity_list"] {
            let mut fixture = Fixture::complete();
            let mut monitor = Monitor::default();
            let now = Instant::now();
            monitor
                .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || now)
                .unwrap();
            fixture
                .files
                .insert(Path::new("proc/irq/41").join(name), "2-3".into());
            let changed = monitor
                .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                    now + Duration::from_secs(2)
                })
                .unwrap();
            assert_eq!(changed["sample"]["identity_stable"], true);
            assert_eq!(changed["sections"]["cpu"]["data"]["baseline"], "ready");
            assert_eq!(
                changed["sections"]["interrupts"]["data"]["baseline"],
                "topology_or_source_layout_changed"
            );
            assert!(changed["sections"]["interrupts"]["data"]["rows"][0]["delta"].is_null());
            let stable = monitor
                .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                    now + Duration::from_secs(4)
                })
                .unwrap();
            assert_eq!(
                stable["sections"]["interrupts"]["data"]["baseline"],
                "ready"
            );
        }
    }

    #[test]
    fn final_identity_changes_suppress_all_rates_and_clear_all_baselines() {
        for (name, path, changed) in [
            (
                "boot_id",
                "proc/sys/kernel/random/boot_id",
                "00000000-0000-0000-0000-000000000002",
            ),
            ("online_cpus", "sys/devices/system/cpu/online", "3,7"),
            (
                "allowed_cpus",
                "proc/thread-self/status",
                "Cpus_allowed_list: 3,7",
            ),
            ("isolated_cpus", "sys/devices/system/cpu/isolated", "3"),
        ] {
            let mut fixture = Fixture::complete();
            let mut monitor = Monitor::default();
            let now = Instant::now();
            monitor
                .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || now)
                .unwrap();
            let original = fixture.files[Path::new(path)].clone();
            fixture.reads.insert(
                PathBuf::from(path),
                VecDeque::from([Some(original), Some(changed.into())]),
            );
            let unstable = monitor
                .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                    now + Duration::from_secs(2)
                })
                .unwrap();
            assert_eq!(unstable["sample"]["identity_stable"], false, "{name}");
            assert_eq!(unstable["sample"]["status"], "partial");
            assert!(unstable["sample"]["sample_interval_seconds"].is_null());
            assert_eq!(
                unstable["sections"]["identity_recheck"]["data"]["checks"][name]["matches"],
                false
            );
            assert!(
                unstable["sections"]["identity_recheck"]["data"]["checks"][name]["error"]
                    .is_string()
            );
            for source in ["cpu", "softirqs", "softnet", "interrupts"] {
                let data = &unstable["sections"][source]["data"];
                assert_eq!(data["baseline"], "identity_unstable");
                assert!(data["sample_interval_seconds"].is_null());
                assert!(data["rows"][0]["counts"].is_object());
                assert!(data["rows"][0]["delta"].is_null());
                assert!(data["rows"][0]["per_second"].is_null());
            }
            assert!(unstable["sections"]["cpu"]["data"]["rows"][0]["busy_percent"].is_null());
            assert!(unstable["sections"]["cpu"]["data"]["rows"][0]["softirq_percent"].is_null());
            assert!(monitor.cpu.is_none());
            assert!(monitor.softirqs.is_none());
            assert!(monitor.softnet.is_none());
            assert!(monitor.interrupts.is_none());
            assert!(monitor.previous_sample.is_none());
            let recovered = monitor
                .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                    now + Duration::from_secs(4)
                })
                .unwrap();
            assert_eq!(recovered["sample"]["identity_stable"], true);
            assert_eq!(
                recovered["sections"]["cpu"]["data"]["baseline"],
                "initial_or_source_recovered"
            );
        }
    }

    #[test]
    fn final_identity_read_failure_is_explicit_and_never_retains_rates() {
        let mut fixture = Fixture::complete();
        let mut monitor = Monitor::default();
        let now = Instant::now();
        monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || now)
            .unwrap();
        fixture.reads.insert(
            PathBuf::from("proc/thread-self/status"),
            VecDeque::from([Some("Cpus_allowed_list: 3".into()), None]),
        );
        let result = monitor
            .snapshot_from(&mut fixture, Path::new("proc"), Path::new("sys"), || {
                now + Duration::from_secs(2)
            })
            .unwrap();
        assert_eq!(result["sample"]["identity_stable"], false);
        assert_eq!(result["sections"]["identity_recheck"]["status"], "partial");
        let check = &result["sections"]["identity_recheck"]["data"]["checks"]["allowed_cpus"];
        assert_eq!(check["initial"]["status"], "available");
        assert_eq!(check["final"]["status"], "unavailable");
        assert!(check["final"]["data"].is_null());
        assert!(check["final"]["error"].is_string());
        assert!(monitor.previous_sample.is_none());
        assert!(monitor.cpu.is_none());
        assert!(result["sections"]["cpu"]["data"]["rows"][0]["delta"].is_null());
    }
}
