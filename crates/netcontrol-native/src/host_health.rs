use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

fn read(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        text.len() as u64 <= MAX_BYTES,
        "kernel source exceeds 2 MiB"
    );
    Ok(text)
}

fn entries(path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("list {}", path.display()))? {
        ensure!(paths.len() < MAX_ENTRIES, "too many kernel source entries");
        paths.push(entry?.path());
    }
    paths.sort();
    Ok(paths)
}

fn number(text: &str) -> Result<u64> {
    text.parse().context("invalid unsigned kernel counter")
}

fn decimal(text: &str) -> Result<f64> {
    let value: f64 = text.parse().context("invalid kernel decimal")?;
    ensure!(value.is_finite() && value >= 0.0, "invalid kernel gauge");
    Ok(value)
}

fn optional_text(path: &Path) -> Result<Option<String>> {
    match read(path) {
        Ok(text) => Ok(Some(text.trim().to_owned())),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn section(result: Result<Value>) -> Value {
    match result {
        Ok(data) => {
            let complete = data.as_array().is_none_or(|rows| {
                rows.iter().all(|row| {
                    row.get("status").is_none_or(|s| s == "available")
                        && row.get("usage").is_none_or(available)
                })
            });
            json!({"status":if complete {"available"} else {"partial"},"data":data,"error":null})
        }
        Err(error) => json!({"status":"unavailable","data":null,"error":format!("{error:#}")}),
    }
}

pub(crate) fn snapshot() -> Result<Value> {
    snapshot_at(Path::new("/proc"), Path::new("/sys"))
}

fn snapshot_at(proc: &Path, sys: &Path) -> Result<Value> {
    let started = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let boot_id = read(&proc.join("sys/kernel/random/boot_id"))?;
    let boot_id = boot_id.trim();
    ensure!(
        boot_id.len() == 36
            && boot_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }),
        "invalid kernel boot identity"
    );
    let mut sections = Map::new();
    for (name, result) in [
        ("cpu", read(&proc.join("stat")).and_then(|s| cpu(&s))),
        (
            "memory",
            read(&proc.join("meminfo")).and_then(|s| memory(&s)),
        ),
        ("load", read(&proc.join("loadavg")).and_then(|s| load(&s))),
        (
            "uptime",
            read(&proc.join("uptime")).and_then(|s| uptime(&s)),
        ),
        ("vm", read(&proc.join("vmstat")).and_then(|s| vm(&s))),
        (
            "disks",
            read(&proc.join("diskstats")).and_then(|s| disks(&s)),
        ),
        ("filesystems", filesystems(proc)),
        ("thermal", thermal(&sys.join("class/thermal"))),
        ("hwmon", hwmon(&sys.join("class/hwmon"))),
    ] {
        sections.insert(name.into(), section(result));
    }
    for name in ["cpu", "memory", "io"] {
        sections.insert(
            format!("pressure_{name}"),
            section(read(&proc.join("pressure").join(name)).and_then(|s| pressure(&s))),
        );
    }
    let complete = sections.values().all(available);
    Ok(json!({
        "schema":"netcontrol-host-health/v1",
        "sample":{"scope":"host","boot_id":boot_id,"started_at":started,
            "collected_at":OffsetDateTime::now_utc().format(&Rfc3339)?,
            "status":if complete {"available"} else {"partial"}},
        "sections":sections
    }))
}

fn available(value: &Value) -> bool {
    value["status"] == "available"
}

fn cpu(text: &str) -> Result<Value> {
    let mut rows = Vec::new();
    let mut gauges = Map::new();
    let fields = [
        "user",
        "nice",
        "system",
        "idle",
        "iowait",
        "irq",
        "softirq",
        "steal",
        "guest",
        "guest_nice",
    ];
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        let Some(name) = words.first().copied() else {
            continue;
        };
        if name == "cpu"
            || name
                .strip_prefix("cpu")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            ensure!((5..=11).contains(&words.len()), "invalid CPU tick fields");
            let mut ticks = Map::new();
            for (key, value) in fields.iter().zip(&words[1..]) {
                ticks.insert((*key).into(), json!(number(value)?.to_string()));
            }
            rows.push(json!({"name":name,"ticks":ticks}));
        } else if ["ctxt", "processes", "procs_running", "procs_blocked"].contains(&name) {
            ensure!(words.len() == 2, "invalid scheduler counter");
            ensure!(
                gauges
                    .insert(name.into(), json!(number(words[1])?.to_string()))
                    .is_none(),
                "duplicate scheduler counter"
            );
        }
    }
    ensure!(
        rows.iter().filter(|row| row["name"] == "cpu").count() == 1,
        "missing or duplicate aggregate CPU"
    );
    let names: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    ensure!(names.len() == rows.len(), "duplicate CPU");
    // Linux exports CPU times in USER_HZ, not the kernel's internal CONFIG_HZ.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(ticks_per_second > 0, "CPU clock tick frequency unavailable");
    Ok(json!({"ticks_per_second":ticks_per_second,"cpus":rows,"scheduler":gauges}))
}

fn memory(text: &str) -> Result<Value> {
    let mut bytes = Map::new();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(words.len() >= 2, "invalid meminfo line");
        if words.get(2) == Some(&"kB") {
            ensure!(words.len() == 3, "invalid meminfo units");
            let value = number(words[1])?
                .checked_mul(1024)
                .context("memory byte overflow")?;
            let key = words[0].strip_suffix(':').context("invalid meminfo key")?;
            ensure!(
                bytes.insert(key.into(), json!(value.to_string())).is_none(),
                "duplicate memory field"
            );
        } else {
            ensure!(words.len() == 2, "unsupported meminfo units");
            number(words[1])?;
        }
    }
    for key in [
        "MemTotal",
        "MemFree",
        "MemAvailable",
        "SwapTotal",
        "SwapFree",
    ] {
        ensure!(
            bytes.contains_key(key),
            "required memory field {key} unavailable"
        );
    }
    let total = number(bytes["MemTotal"].as_str().unwrap())?;
    let available = number(bytes["MemAvailable"].as_str().unwrap())?;
    let swap_total = number(bytes["SwapTotal"].as_str().unwrap())?;
    let swap_free = number(bytes["SwapFree"].as_str().unwrap())?;
    Ok(json!({
        "bytes":bytes,
        "used_bytes":total.checked_sub(available).context("MemAvailable exceeds MemTotal")?.to_string(),
        "swap_used_bytes":swap_total.checked_sub(swap_free).context("SwapFree exceeds SwapTotal")?.to_string()
    }))
}

fn load(text: &str) -> Result<Value> {
    let words: Vec<_> = text.split_whitespace().collect();
    ensure!(words.len() == 5, "invalid loadavg fields");
    let (running, total) = words[3].split_once('/').context("invalid task counts")?;
    Ok(
        json!({"one":decimal(words[0])?,"five":decimal(words[1])?,"fifteen":decimal(words[2])?,
        "runnable_tasks":number(running)?.to_string(),"total_tasks":number(total)?.to_string(),
        "last_pid":number(words[4])?.to_string()}),
    )
}

fn uptime(text: &str) -> Result<Value> {
    let words: Vec<_> = text.split_whitespace().collect();
    ensure!(words.len() == 2, "invalid uptime fields");
    Ok(json!({"uptime_seconds":decimal(words[0])?,"idle_seconds":decimal(words[1])?}))
}

fn vm(text: &str) -> Result<Value> {
    let mut counters = Map::new();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(words.len() == 2, "invalid vmstat line");
        if [
            "pgpgin",
            "pgpgout",
            "pswpin",
            "pswpout",
            "pgfault",
            "pgmajfault",
            "oom_kill",
        ]
        .contains(&words[0])
        {
            ensure!(
                counters
                    .insert(words[0].into(), json!(number(words[1])?.to_string()))
                    .is_none(),
                "duplicate VM counter"
            );
        }
    }
    ensure!(!counters.is_empty(), "VM counters unavailable");
    Ok(json!(counters))
}

fn pressure(text: &str) -> Result<Value> {
    let mut rows = Map::new();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(
            words.len() == 5 && ["some", "full"].contains(&words[0]),
            "invalid pressure line"
        );
        let mut row = Map::new();
        for word in &words[1..] {
            let (name, value) = word.split_once('=').context("invalid pressure field")?;
            let value = match name {
                "avg10" | "avg60" | "avg300" => {
                    let value = decimal(value)?;
                    ensure!(value <= 100.0, "invalid pressure percentage");
                    json!(value)
                }
                "total" => json!(number(value)?.to_string()),
                _ => bail!("unknown pressure field"),
            };
            ensure!(
                row.insert(name.into(), value).is_none(),
                "duplicate pressure field"
            );
        }
        ensure!(
            rows.insert(words[0].into(), json!(row)).is_none(),
            "duplicate pressure category"
        );
    }
    ensure!(
        rows.contains_key("some"),
        "pressure some category unavailable"
    );
    Ok(json!(rows))
}

fn disks(text: &str) -> Result<Value> {
    let mut rows = Vec::new();
    let fields = [
        "reads_completed",
        "reads_merged",
        "sectors_read",
        "read_ms",
        "writes_completed",
        "writes_merged",
        "sectors_written",
        "write_ms",
        "io_in_progress",
        "io_ms",
        "weighted_io_ms",
        "discards_completed",
        "discards_merged",
        "sectors_discarded",
        "discard_ms",
        "flushes_completed",
        "flush_ms",
    ];
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(
            [14, 18, 20].contains(&words.len()),
            "unsupported diskstats field count"
        );
        let mut counters = Map::new();
        for (key, value) in fields.iter().zip(&words[3..]) {
            counters.insert((*key).into(), json!(number(value)?.to_string()));
        }
        rows.push(
            json!({"name":words[2],"major":number(words[0])?.to_string(),
            "minor":number(words[1])?.to_string(),"counters":counters}),
        );
    }
    Ok(json!(rows))
}

fn mount_path(text: &str) -> Result<PathBuf> {
    let mut bytes = Vec::new();
    let input = text.as_bytes();
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\\' {
            let escaped = input.get(i + 1..i + 4).context("truncated mount escape")?;
            bytes.push(match escaped {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => bail!("invalid mount escape"),
            });
            i += 4;
        } else {
            bytes.push(input[i]);
            i += 1;
        }
    }
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
    ensure!(path.is_absolute(), "mount path must be absolute");
    Ok(path)
}

fn filesystem(path: &Path) -> Result<Value> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // statvfs initializes the complete structure on success.
    if unsafe { libc::statvfs(name.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("statvfs");
    }
    let info = unsafe { info.assume_init() };
    let scale = |blocks: u64| -> Result<String> {
        Ok(blocks
            .checked_mul(info.f_frsize)
            .context("filesystem byte overflow")?
            .to_string())
    };
    Ok(json!({
        "total_bytes":scale(info.f_blocks)?,"free_bytes":scale(info.f_bfree)?,
        "available_bytes":scale(info.f_bavail)?,
        "used_bytes":scale(info.f_blocks.checked_sub(info.f_bfree).context("invalid filesystem free blocks")?)?,
        "total_inodes":info.f_files.to_string(),"free_inodes":info.f_ffree.to_string(),
        "available_inodes":info.f_favail.to_string(),
        "read_only":info.f_flag & libc::ST_RDONLY != 0
    }))
}

fn filesystems(proc: &Path) -> Result<Value> {
    let text = read(&proc.join("self/mountinfo"))?;
    let mut rows = Vec::new();
    for line in text.lines() {
        let (left, right) = line
            .split_once(" - ")
            .context("invalid mountinfo separator")?;
        let left: Vec<_> = left.split_whitespace().collect();
        let right: Vec<_> = right.split_whitespace().collect();
        ensure!(
            left.len() >= 6 && right.len() >= 3,
            "invalid mountinfo fields"
        );
        // Never stat network/FUSE/autofs mounts: a remote server could block collection.
        if ![
            "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs", "overlay",
            "tmpfs", "ramfs", "squashfs", "vfat", "exfat", "ntfs3",
        ]
        .contains(&right[0])
        {
            continue;
        }
        ensure!(rows.len() < MAX_ENTRIES, "too many filesystems");
        let path = mount_path(left[4])?;
        rows.push(
            json!({"mount_id":number(left[0])?.to_string(),"device":left[2],
            "mount_point":path,"filesystem":right[0],"usage":section(filesystem(&path))}),
        );
    }
    Ok(json!(rows))
}

fn thermal(root: &Path) -> Result<Value> {
    let mut rows = Vec::new();
    for path in entries(root)? {
        let name = path.file_name().context("thermal name")?.to_string_lossy();
        if !indexed(&name, "thermal_zone", "") {
            continue;
        }
        let value = (|| {
            let kind = read(&path.join("type"))?;
            let temp: i64 = read(&path.join("temp"))?
                .trim()
                .parse()
                .context("invalid thermal temperature")?;
            Ok(json!({"type":kind.trim(),"temperature_millicelsius":temp}))
        })();
        let mut row = section(value);
        row["id"] = json!(name);
        rows.push(row);
    }
    Ok(json!(rows))
}

fn indexed(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

fn hwmon(root: &Path) -> Result<Value> {
    let mut rows = Vec::new();
    for device in entries(root)? {
        let id = device.file_name().context("hwmon name")?.to_string_lossy();
        if !indexed(&id, "hwmon", "") {
            continue;
        }
        let sensors = (|| -> Result<Vec<Value>> {
            let chip = read(&device.join("name"))?;
            let mut sensors = Vec::new();
            for input in entries(&device)? {
                let name = input.file_name().context("sensor name")?.to_string_lossy();
                let unit = if indexed(&name, "temp", "_input") {
                    "millicelsius"
                } else if indexed(&name, "fan", "_input") {
                    "rpm"
                } else {
                    continue;
                };
                let stem = name.strip_suffix("_input").unwrap();
                let result = (|| {
                    let value: i64 = read(&input)?
                        .trim()
                        .parse()
                        .context("invalid sensor value")?;
                    ensure!(unit != "rpm" || value >= 0, "invalid negative fan speed");
                    let fault = optional_text(&device.join(format!("{stem}_fault")))?;
                    if let Some(fault) = fault {
                        ensure!(fault == "0", "kernel reports sensor fault ({fault})");
                    }
                    let label = optional_text(&device.join(format!("{stem}_label")))?;
                    Ok(json!({"value":value,"label":label}))
                })();
                let mut row = section(result);
                row["id"] = json!(format!("{id}/{stem}"));
                row["chip"] = json!(chip.trim());
                row["unit"] = json!(unit);
                sensors.push(row);
            }
            Ok(sensors)
        })();
        match sensors {
            Ok(sensors) => rows.extend(sensors),
            Err(error) => {
                let mut row = section(Err(error));
                row["id"] = json!(id);
                rows.push(row);
            }
        }
        ensure!(rows.len() <= MAX_ENTRIES, "too many hardware sensors");
    }
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "netcontrol-health-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn write(&self, path: &str, value: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, value).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn host_health_partial_sources_and_sensor_faults_are_explicit() {
        let fixture = Fixture::new();
        fixture.write(
            "proc/sys/kernel/random/boot_id",
            "00000000-0000-0000-0000-000000000001\n",
        );
        fixture.write("proc/uptime", "10.5 50\n");
        fixture.write("sys/class/thermal/thermal_zone0/type", "cpu\n");
        fixture.write("sys/class/thermal/thermal_zone0/temp", "-5000\n");
        fixture.write("sys/class/thermal/thermal_zone1/type", "broken\n");
        fixture.write("sys/class/hwmon/hwmon0/name", "test_chip\n");
        fixture.write("sys/class/hwmon/hwmon0/temp1_input", "42500\n");
        fixture.write("sys/class/hwmon/hwmon0/temp1_label", "Package\n");
        fixture.write("sys/class/hwmon/hwmon0/fan1_input", "0\n");
        fixture.write("sys/class/hwmon/hwmon0/fan2_input", "1200\n");
        fixture.write("sys/class/hwmon/hwmon0/fan2_fault", "1\n");
        let snapshot = snapshot_at(&fixture.0.join("proc"), &fixture.0.join("sys")).unwrap();
        assert_eq!(snapshot["sample"]["status"], "partial");
        assert_eq!(snapshot["sections"]["cpu"]["status"], "unavailable");
        assert!(snapshot["sections"]["cpu"]["data"].is_null());
        assert!(
            snapshot["sections"]["cpu"]["error"]
                .as_str()
                .unwrap()
                .contains("stat")
        );
        assert_eq!(
            snapshot["sections"]["uptime"]["data"]["uptime_seconds"],
            10.5
        );
        let thermal = &snapshot["sections"]["thermal"];
        assert_eq!(thermal["status"], "partial");
        assert_eq!(
            thermal["data"][0]["data"]["temperature_millicelsius"],
            -5000
        );
        assert_eq!(thermal["data"][1]["status"], "unavailable");
        let hwmon = &snapshot["sections"]["hwmon"];
        assert_eq!(hwmon["status"], "partial");
        assert_eq!(hwmon["data"][0]["data"]["value"], 0);
        assert_eq!(hwmon["data"][1]["status"], "unavailable");
        assert_eq!(hwmon["data"][2]["data"]["value"], 42500);
        assert_eq!(hwmon["data"][2]["data"]["label"], "Package");
        fixture.write("proc/sys/kernel/random/boot_id", "bad\n");
        assert!(snapshot_at(&fixture.0.join("proc"), &fixture.0.join("sys")).is_err());
    }

    #[test]
    fn host_health_filesystem_errors_are_partial_and_remote_mounts_are_skipped() {
        let fixture = Fixture::new();
        fixture.write(
            "self/mountinfo",
            concat!(
                "1 0 8:1 / /definitely-missing-netcontrol-health-mount rw - ext4 /dev/test rw\n",
                "2 0 0:1 / /never-stat-this-remote rw - nfs server:/data rw\n"
            ),
        );
        let result = section(filesystems(&fixture.0));
        assert_eq!(result["status"], "partial");
        assert_eq!(result["data"].as_array().unwrap().len(), 1);
        assert_eq!(result["data"][0]["usage"]["status"], "unavailable");
        assert!(result["data"][0]["usage"]["data"].is_null());
        let oversized = fixture.0.join("oversized");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        assert!(read(&oversized).is_err());
    }

    #[test]
    fn host_health_parsers_keep_precision_and_units() {
        let value = cpu("cpu 9007199254740993 2 3 4 5 6 7 8 9 10\ncpu0 1 2 3 4\nctxt 18446744073709551615\nprocs_running 2\n").unwrap();
        assert_eq!(value["cpus"][0]["ticks"]["user"], "9007199254740993");
        assert_eq!(value["scheduler"]["ctxt"], "18446744073709551615");
        assert!(value["cpus"][1]["ticks"].get("iowait").is_none());
        assert!(value["ticks_per_second"].as_i64().unwrap() > 0);
        let value = memory("MemTotal: 100 kB\nMemFree: 20 kB\nMemAvailable: 40 kB\nSwapTotal: 10 kB\nSwapFree: 4 kB\nHugePages_Total: 0\n").unwrap();
        assert_eq!(value["used_bytes"], "61440");
        assert_eq!(value["swap_used_bytes"], "6144");
        assert!(value["bytes"].get("HugePages_Total").is_none());
        let value =
            pressure("some avg10=0.00 avg60=1.20 avg300=2.30 total=9007199254740993\n").unwrap();
        assert_eq!(value["some"]["total"], "9007199254740993");
        assert_eq!(value["some"]["avg60"], 1.2);
        assert!(value.get("full").is_none());
        assert_eq!(
            load("1.25 2.5 3.75 2/500 123").unwrap()["total_tasks"],
            "500"
        );
        assert_eq!(uptime("10.5 30.5").unwrap()["idle_seconds"], 30.5);
        let value = disks("8 0 sda 1 2 3 4 5 6 7 8 9 10 11\n").unwrap();
        assert_eq!(value[0]["counters"]["sectors_read"], "3");
        assert_eq!(value[0]["counters"]["io_in_progress"], "9");
        assert!(value[0]["counters"].get("discard_ms").is_none());
        assert_eq!(
            vm("oom_kill 3\npgfault 9007199254740993\nnr_free_pages 3\n").unwrap()["pgfault"],
            "9007199254740993"
        );
    }

    #[test]
    fn host_health_rejects_malformed_or_impossible_measurements() {
        for text in [
            "",
            "cpu 1 2\n",
            "cpu 1 2 3 -4\n",
            "cpu 1 2 3 4\ncpu 1 2 3 4\n",
        ] {
            assert!(cpu(text).is_err());
        }
        assert!(memory("MemTotal: 18446744073709551615 kB").is_err());
        assert!(memory("MemTotal: 10 kB").is_err());
        for text in [
            "",
            "some avg10=NaN avg60=0 avg300=0 total=0",
            "some avg10=101 avg60=0 avg300=0 total=0",
            "some avg10=0 avg10=0 avg300=0 total=0",
            "some avg10=0 avg60=0 avg300=0 total=-1",
        ] {
            assert!(pressure(text).is_err());
        }
        assert!(load("NaN 0 0 1/2 3").is_err());
        assert!(uptime("-1 0").is_err());
        assert!(disks("8 0 sda 1 2 3").is_err());
        assert!(vm("pgfault -1").is_err());
        assert_eq!(
            mount_path(r"/mnt/a\040b\134c").unwrap(),
            Path::new("/mnt/a b\\c")
        );
        assert!(mount_path(r"/mnt/\999").is_err());
        assert!(mount_path("relative").is_err());
    }

    #[test]
    fn host_health_live_kernel_snapshot_is_readonly_and_scoped() {
        let snapshot = snapshot().unwrap();
        assert_eq!(snapshot["schema"], "netcontrol-host-health/v1");
        assert_eq!(snapshot["sample"]["scope"], "host");
        assert_eq!(snapshot["sample"]["boot_id"].as_str().unwrap().len(), 36);
        assert_eq!(snapshot["sections"].as_object().unwrap().len(), 12);
        for name in [
            "cpu",
            "memory",
            "load",
            "uptime",
            "vm",
            "disks",
            "filesystems",
        ] {
            assert_eq!(
                snapshot["sections"][name]["status"], "available",
                "{name}: {}",
                snapshot["sections"][name]
            );
        }
        let usage = filesystem(Path::new("/")).unwrap();
        let total = number(usage["total_bytes"].as_str().unwrap()).unwrap();
        let free = number(usage["free_bytes"].as_str().unwrap()).unwrap();
        let used = number(usage["used_bytes"].as_str().unwrap()).unwrap();
        assert_eq!(used + free, total);
    }
}
