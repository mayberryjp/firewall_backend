use anyhow::{Context, Result, ensure};
use chrono::Utc;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const LOG_SEGMENT_BYTES: usize = 2 * 1024 * 1024;
pub const LOG_SEGMENTS: usize = 4;
pub const LOG_MESSAGE_BYTES: usize = 65_000;
pub const LOG_PAGE_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum LogSource {
    Syslog,
    Netcontrol,
}

impl LogSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Syslog => "syslog",
            Self::Netcontrol => "netcontrol",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    cursor: Option<String>,
    limit: Option<String>,
}

#[derive(Debug)]
pub struct LogQuery {
    pub cursor: Option<(String, u64)>,
    pub limit: usize,
}

impl LogQuery {
    pub fn parse(query: &str) -> Result<Self> {
        ensure!(query.len() <= 1024, "log query exceeds 1024 bytes");
        let fields: Parameters = serde_urlencoded::from_str(query)?;
        let limit = fields.limit.as_deref().unwrap_or("100");
        let number: usize = limit.parse()?;
        ensure!(
            (1..=500).contains(&number) && number.to_string() == limit,
            "log limit must be canonical 1..500"
        );
        let cursor = fields
            .cursor
            .map(|value| -> Result<_> {
                let (epoch, sequence) = value.split_once(':').context("invalid log cursor")?;
                ensure!(valid_epoch(epoch), "invalid log cursor epoch");
                let number: u64 = sequence.parse()?;
                ensure!(
                    number.to_string() == sequence,
                    "invalid log cursor sequence"
                );
                Ok((epoch.to_owned(), number))
            })
            .transpose()?;
        Ok(Self {
            cursor,
            limit: number,
        })
    }
}

fn valid_epoch(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug)]
pub struct LogCursorAhead;

impl std::fmt::Display for LogCursorAhead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("log cursor is ahead of retained history")
    }
}
impl std::error::Error for LogCursorAhead {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub sequence: String,
    pub timestamp: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    pub next_cursor: String,
    pub oldest_cursor: Option<String>,
    pub gap: bool,
    pub reset: bool,
    pub has_more: bool,
    pub retention_bytes: usize,
    pub max_message_bytes: usize,
}

struct Segment {
    path: PathBuf,
    bytes: usize,
    entries: Vec<LogEntry>,
}

struct Inner {
    directory: PathBuf,
    epoch: String,
    sequence: u64,
    segments: VecDeque<Segment>,
    file: Option<File>,
    error: Option<String>,
    segment_bytes: usize,
    segment_count: usize,
    _lock: File,
}

#[derive(Clone)]
pub struct DiskLog(Arc<Mutex<Inner>>);

fn secure_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        for ancestor in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            ensure!(
                !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
                "log directory ancestry must not contain symlinks"
            );
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "log directory must be private and owned by the daemon"
        );
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "untrusted log directory"
        );
    }
    Ok(())
}

fn open_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true);
    if create {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    ensure!(
        create || !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "log file must not be a symlink"
    );
    let file = options
        .open(path)
        .with_context(|| format!("open log file {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "log path must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "log file must be private, daemon-owned and not hard-linked"
        );
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl DiskLog {
    pub fn open(directory: &Path) -> Result<Self> {
        Self::open_bounded(directory, LOG_SEGMENT_BYTES, LOG_SEGMENTS)
    }

    fn open_bounded(directory: &Path, segment_bytes: usize, segment_count: usize) -> Result<Self> {
        secure_directory(directory)?;
        let lock_path = directory.join("writer.lock");
        let lock = match open_file(&lock_path, true) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                open_file(&lock_path, false)?
            }
            Err(error) => return Err(error),
        };
        lock.try_lock_exclusive()
            .context("log history is already owned")?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("invalid log history filename")?;
            if name == "writer.lock" || name == "identity" {
                continue;
            }
            let sequence = name
                .strip_suffix(".jsonl")
                .context("unknown file in log history")?;
            let number: u64 = sequence.parse()?;
            ensure!(
                number > 0 && format!("{number:020}") == sequence,
                "invalid log segment filename"
            );
            paths.push((number, entry.path()));
        }
        paths.sort_by_key(|(number, _)| *number);
        ensure!(
            paths.len() <= segment_count + 1,
            "log history exceeds segment bound"
        );
        let identity = directory.join("identity");
        let epoch = match open_file(&identity, false) {
            Ok(file) => {
                ensure!(file.metadata()?.len() == 32, "invalid log identity size");
                fs::read_to_string(&identity)?
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                ensure!(
                    paths.is_empty(),
                    "log identity missing; retained history was not reset"
                );
                let epoch = format!("{:032x}", rand::random::<u128>());
                let mut file = open_file(&identity, true)?;
                file.write_all(epoch.as_bytes())?;
                file.sync_all()?;
                sync_directory(directory)?;
                epoch
            }
            Err(error) => return Err(error),
        };
        ensure!(valid_epoch(&epoch), "invalid log history identity");
        let mut segments = VecDeque::new();
        let mut sequence = 0u64;
        let segment_total = paths.len();
        for (index, (start, path)) in paths.into_iter().enumerate() {
            let file = open_file(&path, false)?;
            let size = file.metadata()?.len();
            ensure!(
                size <= segment_bytes as u64,
                "log segment exceeds size bound"
            );
            let bytes = fs::read(&path)?;
            ensure!(
                bytes.is_empty() || bytes.last() == Some(&b'\n'),
                "incomplete log segment; retained data was not reset"
            );
            let mut entries = Vec::new();
            for line in bytes.split_inclusive(|b| *b == b'\n') {
                let line = &line[..line.len() - 1];
                ensure!(line.len() <= LOG_PAGE_BYTES, "log entry exceeds size bound");
                let entry: LogEntry = serde_json::from_slice(line).context("invalid log entry")?;
                let number: u64 = entry.sequence.parse()?;
                let expected = if sequence == 0 {
                    start
                } else {
                    sequence.checked_add(1).context("log sequence exhausted")?
                };
                ensure!(
                    number.to_string() == entry.sequence
                        && number == expected
                        && (!entries.is_empty() || number == start)
                        && entry.message.len() <= LOG_MESSAGE_BYTES,
                    "invalid log sequence or message size"
                );
                chrono::DateTime::parse_from_rfc3339(&entry.timestamp)?;
                sequence = number;
                entries.push(entry);
            }
            ensure!(
                !entries.is_empty() || Some(start) == sequence.checked_add(1),
                "invalid empty log segment"
            );
            ensure!(
                !entries.is_empty() || index + 1 == segment_total,
                "empty nonfinal log segment"
            );
            segments.push_back(Segment {
                path,
                bytes: bytes.len(),
                entries,
            });
        }
        // A crash can occur after creating the next segment but before its first record.
        if segments
            .back()
            .is_some_and(|segment| segment.entries.is_empty())
        {
            let empty = segments.pop_back().context("log segment missing")?;
            fs::remove_file(empty.path)?;
            sync_directory(directory)?;
        }
        let file = segments
            .back()
            .map(|s| open_file(&s.path, false))
            .transpose()?;
        let mut inner = Inner {
            directory: directory.to_owned(),
            epoch,
            sequence,
            segments,
            file,
            error: None,
            segment_bytes,
            segment_count,
            _lock: lock,
        };
        inner.prune()?;
        Ok(Self(Arc::new(Mutex::new(inner))))
    }

    pub fn append(&self, message: &str) -> Result<()> {
        ensure!(
            message.len() <= LOG_MESSAGE_BYTES,
            "log message exceeds 65000 bytes"
        );
        let mut inner = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("log storage lock poisoned"))?;
        ensure!(
            inner.error.is_none(),
            "log storage unavailable: {:?}",
            inner.error
        );
        let result = inner.append(message);
        if let Err(error) = &result {
            inner.error = Some(format!("{error:#}"));
        }
        result
    }

    pub fn sync(&self) -> Result<()> {
        let inner = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("log storage lock poisoned"))?;
        ensure!(
            inner.error.is_none(),
            "log storage unavailable: {:?}",
            inner.error
        );
        inner.check_active()?;
        if let Some(file) = &inner.file {
            file.sync_data()?;
        }
        Ok(())
    }

    pub fn read(&self, query: &LogQuery) -> Result<LogPage> {
        let inner = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("log storage lock poisoned"))?;
        ensure!(
            inner.error.is_none(),
            "log storage unavailable: {:?}",
            inner.error
        );
        inner.check_active()?;
        let reset = query
            .cursor
            .as_ref()
            .is_some_and(|(epoch, _)| epoch != &inner.epoch);
        let cursor = query
            .cursor
            .as_ref()
            .filter(|_| !reset)
            .map(|(_, seq)| *seq);
        if cursor.is_some_and(|seq| seq > inner.sequence) {
            return Err(LogCursorAhead.into());
        }
        let all: Vec<_> = inner
            .segments
            .iter()
            .flat_map(|s| s.entries.iter())
            .collect();
        let oldest = all.first().map(|e| e.sequence.parse::<u64>().unwrap());
        let gap = cursor
            .zip(oldest)
            .is_some_and(|(seq, first)| seq.saturating_add(1) < first);
        let start = if let Some(seq) = cursor {
            all.partition_point(|e| e.sequence.parse::<u64>().unwrap() <= seq)
        } else {
            // A first visit shows the newest bounded page, in chronological order.
            let mut bytes = 0;
            let mut count = 0;
            for entry in all.iter().rev().take(query.limit) {
                let size = serde_json::to_vec(entry)?.len();
                if bytes + size > LOG_PAGE_BYTES {
                    break;
                }
                bytes += size;
                count += 1;
            }
            all.len() - count
        };
        let mut entries = Vec::new();
        let mut bytes = 0;
        for entry in all.iter().skip(start).take(query.limit) {
            let size = serde_json::to_vec(entry)?.len();
            if bytes + size > LOG_PAGE_BYTES {
                break;
            }
            bytes += size;
            entries.push((*entry).clone());
        }
        let last = entries
            .last()
            .map(|e| e.sequence.parse::<u64>().unwrap())
            .unwrap_or(cursor.unwrap_or(inner.sequence));
        Ok(LogPage {
            has_more: start + entries.len() < all.len(),
            entries,
            next_cursor: format!("{}:{last}", inner.epoch),
            oldest_cursor: oldest.map(|seq| format!("{}:{}", inner.epoch, seq.saturating_sub(1))),
            gap,
            reset,
            retention_bytes: inner.segment_bytes * inner.segment_count,
            max_message_bytes: LOG_MESSAGE_BYTES,
        })
    }
}

impl Inner {
    fn check_active(&self) -> Result<()> {
        if let (Some(file), Some(segment)) = (&self.file, self.segments.back()) {
            let path = open_file(&segment.path, false)?;
            let current = path.metadata()?;
            let owned = file.metadata()?;
            ensure!(
                current.len() == segment.bytes as u64 && owned.len() == current.len(),
                "log segment was modified externally"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    (current.dev(), current.ino()) == (owned.dev(), owned.ino()),
                    "log segment was replaced externally"
                );
            }
        }
        Ok(())
    }
    fn append(&mut self, message: &str) -> Result<()> {
        self.check_active()?;
        let sequence = self
            .sequence
            .checked_add(1)
            .context("log sequence exhausted")?;
        let entry = LogEntry {
            sequence: sequence.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            message: message.to_owned(),
        };
        let mut bytes = serde_json::to_vec(&entry)?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() <= self.segment_bytes && bytes.len() <= LOG_PAGE_BYTES,
            "encoded log entry exceeds bound"
        );
        if self
            .segments
            .back()
            .is_none_or(|s| s.bytes + bytes.len() > self.segment_bytes)
        {
            if let Some(file) = &self.file {
                file.sync_data()?;
            }
            let path = self.directory.join(format!("{sequence:020}.jsonl"));
            let file = open_file(&path, true)?;
            sync_directory(&self.directory)?;
            self.file = Some(file);
            self.segments.push_back(Segment {
                path,
                bytes: 0,
                entries: Vec::new(),
            });
        }
        let file = self.file.as_mut().context("log segment missing")?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        let segment = self.segments.back_mut().context("log segment missing")?;
        segment.bytes += bytes.len();
        segment.entries.push(entry);
        self.sequence = sequence;
        self.prune()
    }

    fn prune(&mut self) -> Result<()> {
        while self.segments.len() > self.segment_count {
            let segment = self.segments.front().context("log segment missing")?;
            let _validated = open_file(&segment.path, false)?;
            fs::remove_file(&segment.path)?;
            sync_directory(&self.directory)?;
            self.segments.pop_front();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_queries_are_strict_and_bounded() {
        assert_eq!(LogQuery::parse("").unwrap().limit, 100);
        assert!(LogQuery::parse("limit=500&cursor=0123456789abcdef0123456789abcdef:0").is_ok());
        for query in [
            "limit=0",
            "limit=501",
            "limit=01",
            "limit=1&limit=2",
            "unknown=1",
            "cursor=",
            "cursor=bad:0",
            "cursor=0123456789abcdef0123456789abcdef:01",
        ] {
            assert!(LogQuery::parse(query).is_err(), "{query}");
        }
        assert!(LogQuery::parse(&"x".repeat(1025)).is_err());
    }

    #[test]
    fn log_rotation_pagination_and_persistence_are_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open_bounded(&path, 400, 2).unwrap();
        let cursor = log.read(&LogQuery::parse("").unwrap()).unwrap().next_cursor;
        for i in 0..12 {
            log.append(&format!("synthetic {i} {}", "x".repeat(90)))
                .unwrap();
        }
        let page = log
            .read(&LogQuery::parse(&format!("cursor={cursor}&limit=1")).unwrap())
            .unwrap();
        assert!(page.gap && page.has_more);
        assert_eq!(page.entries.len(), 1);
        let resumed = page.next_cursor.clone();
        let first = page.entries[0].sequence.clone();
        let epoch = resumed.split_once(':').unwrap().0.to_owned();
        assert!(
            DiskLog::open_bounded(&path, 400, 2).is_err(),
            "two writers acquired ownership"
        );
        drop(log);
        let log = DiskLog::open_bounded(&path, 400, 2).unwrap();
        let page = log
            .read(&LogQuery::parse(&format!("cursor={resumed}&limit=500")).unwrap())
            .unwrap();
        assert!(!page.reset && !page.gap && !page.has_more);
        assert!(
            page.entries
                .iter()
                .all(|e| e.sequence.parse::<u64>().unwrap() > first.parse::<u64>().unwrap())
        );
        let bytes: u64 = fs::read_dir(&path)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
            .map(|e| e.metadata().unwrap().len())
            .sum();
        assert!(bytes <= 800);
        let tail = log.read(&LogQuery::parse("limit=1").unwrap()).unwrap();
        assert_eq!(tail.entries[0].sequence, "12");
        assert!(!tail.has_more);
        assert!(
            log.read(&LogQuery::parse(&format!("cursor={epoch}:13")).unwrap())
                .unwrap_err()
                .is::<LogCursorAhead>()
        );
        let reset = log
            .read(&LogQuery::parse("cursor=00000000000000000000000000000000:999").unwrap())
            .unwrap();
        assert!(reset.reset && !reset.gap);
        log.append("after restart").unwrap();
        assert_eq!(
            log.read(&LogQuery::parse("limit=1").unwrap())
                .unwrap()
                .entries[0]
                .sequence,
            "13"
        );
    }

    #[test]
    fn log_page_bytes_errors_and_concurrent_writes() {
        let directory = tempfile::tempdir().unwrap();
        let log = DiskLog::open(&directory.path().join("logs")).unwrap();
        let initial = log.read(&LogQuery::parse("").unwrap()).unwrap().next_cursor;
        let message = "\0".repeat(LOG_MESSAGE_BYTES);
        log.append(&message).unwrap();
        log.append(&message).unwrap();
        let page = log
            .read(&LogQuery::parse(&format!("cursor={initial}&limit=500")).unwrap())
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(page.has_more);
        assert!(serde_json::to_vec(&page).unwrap().len() < 1024 * 1024);
        assert!(log.append(&"x".repeat(LOG_MESSAGE_BYTES + 1)).is_err());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        log.append("concurrent synthetic").unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            log.read(&LogQuery::parse("limit=1").unwrap())
                .unwrap()
                .entries[0]
                .sequence,
            "82"
        );
    }

    #[test]
    fn production_log_retention_enforces_four_two_mib_segments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open(&path).unwrap();
        let cursor = log.read(&LogQuery::parse("").unwrap()).unwrap().next_cursor;
        let message = "x".repeat(LOG_MESSAGE_BYTES);
        for _ in 0..140 {
            log.append(&message).unwrap();
        }
        let segments: Vec<_> = fs::read_dir(&path)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
            .map(|e| e.metadata().unwrap().len())
            .collect();
        assert_eq!(segments.len(), 4);
        assert!(segments.iter().all(|bytes| *bytes <= 2 * 1024 * 1024));
        assert!(segments.iter().sum::<u64>() <= 8 * 1024 * 1024);
        let page = log
            .read(&LogQuery::parse(&format!("cursor={cursor}&limit=500")).unwrap())
            .unwrap();
        assert_eq!(page.retention_bytes, 8_388_608);
        assert!(page.gap && page.has_more);
        assert!(serde_json::to_vec(&page.entries).unwrap().len() < LOG_PAGE_BYTES + 500);
        assert!(serde_json::to_vec(&page).unwrap().len() < 1024 * 1024);
    }

    #[test]
    fn corrupt_history_is_explicit_and_not_reset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open(&path).unwrap();
        log.append("synthetic").unwrap();
        drop(log);
        let segment = path.join("00000000000000000001.jsonl");
        let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
        file.write_all(b"{incomplete").unwrap();
        let original = fs::read(&segment).unwrap();
        assert!(DiskLog::open(&path).is_err());
        assert_eq!(fs::read(&segment).unwrap(), original);
    }

    #[test]
    fn interrupted_rotation_preserves_retained_records_and_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open_bounded(&path, 200, 2).unwrap();
        for _ in 0..3 {
            log.append(&"x".repeat(60)).unwrap();
        }
        let before = log.read(&LogQuery::parse("").unwrap()).unwrap();
        assert_eq!(before.entries.len(), 2);
        drop(log);
        drop(open_file(&path.join("00000000000000000004.jsonl"), true).unwrap());
        let reopened = DiskLog::open_bounded(&path, 200, 2).unwrap();
        let after = reopened.read(&LogQuery::parse("").unwrap()).unwrap();
        assert_eq!(after.next_cursor, before.next_cursor);
        assert_eq!(after.entries.len(), before.entries.len());
        reopened.append("after interrupted rotation").unwrap();
        assert_eq!(
            reopened
                .read(&LogQuery::parse("limit=1").unwrap())
                .unwrap()
                .entries[0]
                .sequence,
            "4"
        );
    }

    #[test]
    fn missing_active_segment_is_not_reported_as_success() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open(&path).unwrap();
        log.append("synthetic").unwrap();
        fs::remove_file(path.join("00000000000000000001.jsonl")).unwrap();
        assert!(log.read(&LogQuery::parse("").unwrap()).is_err());
        assert!(
            log.append("must not succeed into an unlinked file")
                .is_err()
        );
        assert!(log.sync().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn log_storage_rejects_links_and_public_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open(&path).unwrap();
        log.append("private synthetic").unwrap();
        drop(log);
        let identity = path.join("identity");
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(DiskLog::open(&path).is_err());
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
        let linked = directory.path().join("linked");
        symlink(&path, &linked).unwrap();
        assert!(DiskLog::open(&linked).is_err());
        let segment = path.join("00000000000000000001.jsonl");
        fs::hard_link(&segment, directory.path().join("hard-link")).unwrap();
        assert!(DiskLog::open(&path).is_err());
    }
}
