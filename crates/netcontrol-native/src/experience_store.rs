//! Private, bounded, completed-bucket storage. Display metadata is deliberately
//! not part of this database.
use anyhow::{Context, Result, bail, ensure};
use netcontrol_core::experience::Sample;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    cell::Cell,
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    net::IpAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const RETENTION_MS: i64 = 3_600_000;
pub const INTERVAL_MS: i64 = 10_000;
pub const MAX_SLOTS: usize = 360;
const MAX_HOSTS: usize = 2048;
const MAIN_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const WAL_LIMIT: u64 = 32 * 1024 * 1024;
const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x4e435845;
const JSON_LIMIT: usize = 2048;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub address: Option<String>,
    pub interface: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Collection {
    pub id: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub samples: Vec<Sample>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub next_cursor: Option<String>,
    pub clock_discontinuity: bool,
    pub diagnostics: Diagnostics,
}

#[derive(Clone, Debug, Default)]
pub struct Diagnostics {
    pub capture_dropped_packets: Option<u64>,
    pub analysis_exclusions: Option<u64>,
    pub tracking_evictions: Option<u64>,
    pub dropped_unattributed_packets: Option<u64>,
    pub sources: Vec<Source>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Source {
    pub name: String,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HistorySlot {
    pub start_ms: i64,
    pub end_ms: i64,
    pub sample: Option<Sample>,
}

#[derive(Clone, Debug)]
pub struct History {
    pub slots: Vec<HistorySlot>,
    pub clock_discontinuity: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Usage {
    pub sent_bytes: Option<u128>,
    pub received_bytes: Option<u128>,
    pub coverage_ms: u64,
    pub complete: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    collection: String,
    filter: Filter,
    limit: usize,
    after: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorError {
    Invalid,
    FilterMismatch,
    Expired,
}
impl std::fmt::Display for CursorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid experience cursor",
            Self::FilterMismatch => "experience cursor does not match query filters",
            Self::Expired => "expired experience collection cursor; restart latest paging",
        })
    }
}
impl std::error::Error for CursorError {}

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Counter,
    Integer,
    Real,
    Bool,
    ScoreJson,
}

struct Column {
    path: &'static str,
    kind: Kind,
}

macro_rules! columns {
    ($($path:literal => $kind:ident),* $(,)?) => {
        const COLUMNS: &[Column] = &[$(Column { path: $path, kind: Kind::$kind }),*];
    };
}

// Each metric has its own typed SQL column. JSON is restricted to the bounded
// score explanation; neither payloads nor arbitrary sample objects are stored.
columns! {
    "last_seen_at" => Text,
    "activity" => Text,
    "measured_duration_ms" => Integer,
    "traffic.status" => Text,
    "traffic.error" => Text,
    "traffic.sent_packets" => Counter,
    "traffic.received_packets" => Counter,
    "traffic.sent_bytes" => Counter,
    "traffic.received_bytes" => Counter,
    "traffic.sent_bps" => Real,
    "traffic.received_bps" => Real,
    "traffic.packet_unit" => Text,
    "traffic.byte_unit" => Text,
    "firewall.status" => Text,
    "firewall.error" => Text,
    "firewall.dropped_sent_packets" => Counter,
    "firewall.dropped_received_packets" => Counter,
    "firewall.drop_coverage" => Text,
    "connections.status" => Text,
    "connections.error" => Text,
    "connections.observed_at" => Text,
    "connections.measurement_duration_ms" => Integer,
    "connections.total" => Counter,
    "connections.tcp_established" => Counter,
    "connections.unreplied" => Counter,
    "tcp.status" => Text,
    "tcp.error" => Text,
    "tcp.data_packets_sent" => Counter,
    "tcp.data_packets_received" => Counter,
    "tcp.retransmission_observations_sent" => Counter,
    "tcp.retransmission_observations_received" => Counter,
    "tcp.retransmission_percent_sent" => Real,
    "tcp.retransmission_percent_received" => Real,
    "tcp.window_decreases_host" => Counter,
    "tcp.window_decreases_peer" => Counter,
    "tcp.zero_window_observations_host" => Counter,
    "tcp.zero_window_observations_peer" => Counter,
    "tcp.zero_window_transitions_host" => Counter,
    "tcp.zero_window_transitions_peer" => Counter,
    "tcp.advertised_window_min_bytes_host" => Integer,
    "tcp.advertised_window_min_bytes_peer" => Integer,
    "tcp.rtt_remote.samples" => Counter,
    "tcp.rtt_remote.variation_pairs" => Counter,
    "tcp.rtt_remote.p50_ms" => Real,
    "tcp.rtt_remote.p95_ms" => Real,
    "tcp.rtt_remote.min_ms" => Real,
    "tcp.rtt_remote.max_ms" => Real,
    "tcp.rtt_remote.variation_mean_ms" => Real,
    "tcp.rtt_host.samples" => Counter,
    "tcp.rtt_host.variation_pairs" => Counter,
    "tcp.rtt_host.p50_ms" => Real,
    "tcp.rtt_host.p95_ms" => Real,
    "tcp.rtt_host.min_ms" => Real,
    "tcp.rtt_host.max_ms" => Real,
    "tcp.rtt_host.variation_mean_ms" => Real,
    "dns.status" => Text,
    "dns.error" => Text,
    "dns.requests" => Counter,
    "dns.responses" => Counter,
    "dns.unanswered" => Counter,
    "dns.pending_at_close" => Counter,
    "dns.servfail_responses" => Counter,
    "dns.refused_responses" => Counter,
    "dns.excluded_observations" => Counter,
    "dns.response_time_p50_ms" => Real,
    "dns.response_time_p95_ms" => Real,
    "dns.response_time_variation_mean_ms" => Real,
    "dns.unanswered_percent" => Real,
    "experience.algorithm" => Text,
    "experience.score" => Integer,
    "experience.level" => Text,
    "experience.status" => Text,
    "experience.confidence" => Text,
    "experience.basis_seconds" => Integer,
    "experience.components" => ScoreJson,
    "experience.reasons" => ScoreJson,
    "coverage.complete" => Bool,
    "coverage.traffic" => Text,
    "coverage.firewall" => Text,
    "coverage.tcp" => Text,
    "coverage.dns" => Text,
    "coverage.connections" => Text,
}

pub struct Store {
    writer: Connection,
    reader: Connection,
    path: PathBuf,
    _lock: File,
    started: Instant,
    logical_anchor: Cell<i64>,
    last_wall: Cell<i64>,
    quarantine: Cell<i64>,
    discontinuity_ms: Cell<i64>,
    restart_seq: i64,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_at(path, wall_ms()?)
    }

    fn open_at(path: &Path, now_ms: i64) -> Result<Self> {
        ensure!(now_ms >= 0, "invalid store clock");
        let root = path
            .parent()
            .context("experience database needs a private directory")?;
        trusted_directory(root)?;
        let lock = File::open(root)?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "experience database is already owned by another writer"
        );
        let existed = path.try_exists()?;
        if !existed {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?
                .sync_all()?;
            lock.sync_all()?;
        }
        validate_files(path)?;
        let writer = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        writer.busy_timeout(Duration::from_millis(250))?;
        // Validate before changing journal mode or installing the schema.
        let version: i64 = writer.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let app: i64 = writer.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        if existed {
            ensure!(
                version == SCHEMA_VERSION && app == APPLICATION_ID,
                "unsupported experience database schema; existing data preserved"
            );
            validate_schema(&writer)?;
        } else {
            ensure!(
                version == 0 && app == 0,
                "unexpected new experience database"
            );
            writer.execute_batch(&schema_sql())?;
        }
        ensure!(
            writer.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))? == "ok",
            "corrupt experience database; existing data preserved"
        );
        let foreign_errors: i64 =
            writer.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        ensure!(
            foreign_errors == 0,
            "corrupt experience database references"
        );
        writer.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             PRAGMA wal_autocheckpoint=1024; PRAGMA journal_size_limit=0;
             PRAGMA max_page_count=524288; PRAGMA cache_size=-8192;
             PRAGMA cache_spill=OFF; PRAGMA trusted_schema=OFF;",
        )?;
        ensure!(
            writer.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? == 4096,
            "unsupported experience database page size"
        );
        let persisted: (i64, i64, i64, i64) = writer.query_row(
            "SELECT wall_ms,logical_ms,quarantine_seq,discontinuity_ms FROM store_state WHERE singleton=1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let maximum: i64 =
            writer.query_row("SELECT coalesce(max(seq),0) FROM buckets", [], |r| r.get(0))?;
        let untrusted_restart = maximum > 0 && now_ms <= persisted.0;
        let quarantine = if untrusted_restart {
            maximum.max(persisted.2)
        } else {
            persisted.2
        };
        let reader = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        reader.busy_timeout(Duration::from_millis(250))?;
        reader.execute_batch("PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096;")?;
        let mut store = Self {
            writer,
            reader,
            path: path.to_owned(),
            _lock: lock,
            started: Instant::now(),
            logical_anchor: Cell::new(now_ms.max(persisted.1)),
            last_wall: Cell::new(now_ms),
            quarantine: Cell::new(quarantine),
            discontinuity_ms: Cell::new(if untrusted_restart {
                persisted.1.max(now_ms)
            } else {
                persisted.3
            }),
            restart_seq: maximum,
        };
        store.prune(now_ms)?;
        validate_files(path)?;
        Ok(store)
    }

    fn clock(&self, now_ms: i64) -> Result<i64> {
        ensure!(now_ms >= 0, "invalid store clock");
        let backwards = now_ms < self.last_wall.get();
        if backwards {
            let max =
                self.reader
                    .query_row("SELECT coalesce(max(seq),0) FROM buckets", [], |r| {
                        r.get::<_, i64>(0)
                    })?;
            self.quarantine.set(self.quarantine.get().max(max));
        }
        self.last_wall.set(now_ms);
        let elapsed = i64::try_from(self.started.elapsed().as_millis())?;
        let logical = self
            .logical_anchor
            .get()
            .checked_add(elapsed)
            .context("store clock exhausted")?
            .max(now_ms);
        if backwards {
            self.discontinuity_ms.set(logical);
        }
        self.logical_anchor.set(logical - elapsed);
        Ok(logical)
    }

    /// Only a fully completed collection is admitted. Failed validation or SQL
    /// writes leave unexpired previous collections unchanged.
    pub fn insert_collection_with_diagnostics(
        &mut self,
        id: &str,
        start_ms: i64,
        end_ms: i64,
        samples: &[Sample],
        diagnostics: &Diagnostics,
    ) -> Result<()> {
        self.insert_collection_at_with_diagnostics(
            id,
            start_ms,
            end_ms,
            samples,
            wall_ms()?,
            diagnostics,
        )
    }

    #[cfg(test)]
    fn insert_collection_at(
        &mut self,
        id: &str,
        start_ms: i64,
        end_ms: i64,
        samples: &[Sample],
        now_ms: i64,
    ) -> Result<()> {
        let diagnostics = Diagnostics {
            reasons: vec!["collection_diagnostics_unavailable".into()],
            ..Diagnostics::default()
        };
        self.insert_collection_at_with_diagnostics(
            id,
            start_ms,
            end_ms,
            samples,
            now_ms,
            &diagnostics,
        )
    }

    fn insert_collection_at_with_diagnostics(
        &mut self,
        id: &str,
        start_ms: i64,
        end_ms: i64,
        samples: &[Sample],
        now_ms: i64,
        diagnostics: &Diagnostics,
    ) -> Result<()> {
        bounded_text(id, 128)?;
        ensure!(
            start_ms >= 0 && end_ms > start_ms && end_ms - start_ms == INTERVAL_MS,
            "collection must describe one completed ten-second bucket"
        );
        ensure!(end_ms <= now_ms, "collection is not completed");
        ensure!(
            samples.len() <= MAX_HOSTS,
            "too many experience collection hosts"
        );
        ensure!(
            diagnostics.sources.len() <= 16 && diagnostics.reasons.len() <= 32,
            "oversized collection diagnostics"
        );
        let mut source_names = BTreeSet::new();
        for source in &diagnostics.sources {
            bounded_text(&source.name, 32)?;
            bounded_text(&source.status, 32)?;
            ensure!(
                source_names.insert(&source.name),
                "duplicate collection source"
            );
            if let Some(error) = &source.error {
                bounded_text(error, 1024)?;
            }
        }
        for reason in &diagnostics.reasons {
            bounded_text(reason, 128)?;
        }
        let mut keys = BTreeSet::new();
        let mut encoded = Vec::with_capacity(samples.len());
        let mut estimated_bytes = 0usize;
        for sample in samples {
            let row = EncodedSample::new(sample, start_ms, end_ms)?;
            ensure!(keys.insert(row.address.clone()), "duplicate collection IP");
            estimated_bytes = estimated_bytes
                .checked_add(row.encoded_size())
                .context("collection size overflow")?;
            encoded.push(row);
        }
        // There are no external database readers under the exclusive directory
        // ownership contract. Checkpoints must still fail explicitly if blocked.
        self.checkpoint()?;
        ensure!(
            estimated_bytes
                .saturating_mul(2)
                .saturating_add(8 * 1024 * 1024)
                <= WAL_LIMIT as usize,
            "experience collection exceeds WAL transaction admission budget"
        );
        let logical = self.clock(now_ms)?;
        let expired: i64 = self.writer.query_row(
            "SELECT count(*) FROM buckets WHERE retention_ms<=?1 OR end_ms<=?2",
            params![
                logical.saturating_sub(RETENTION_MS),
                now_ms.saturating_sub(RETENTION_MS)
            ],
            |r| r.get(0),
        )?;
        if expired > 1 {
            // Recovery after a long writer outage is maintenance of already
            // invisible data. Bound that work before admitting a new collection.
            self.prune(now_ms)?;
        }
        let quarantine = self.quarantine.get();
        let epoch_boundary = quarantine.max(self.restart_seq);
        let tx = self
            .writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous: Option<(i64, i64)> = tx
            .query_row(
                "SELECT seq,end_ms FROM buckets ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((seq, end)) = previous {
            ensure!(
                seq <= quarantine || end_ms.checked_sub(end).is_some_and(|d| d >= INTERVAL_MS),
                "collection cadence regressed or overlapped without a clock discontinuity"
            );
        }
        tx.execute("INSERT INTO buckets(collection_id,start_ms,end_ms,retention_ms,capture_dropped_packets,
                analysis_exclusions,tracking_evictions,dropped_unattributed_packets) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id,start_ms,end_ms,logical,diagnostics.capture_dropped_packets.map(|c|c.to_string()),
                diagnostics.analysis_exclusions.map(|c|c.to_string()),diagnostics.tracking_evictions.map(|c|c.to_string()),
                diagnostics.dropped_unattributed_packets.map(|c|c.to_string())])?;
        let bucket = tx.last_insert_rowid();
        for source in &diagnostics.sources {
            tx.execute(
                "INSERT INTO bucket_sources(bucket_id,name,status,error) VALUES (?1,?2,?3,?4)",
                params![bucket, source.name, source.status, source.error],
            )?;
        }
        for (position, reason) in diagnostics.reasons.iter().enumerate() {
            tx.execute(
                "INSERT INTO bucket_reasons(bucket_id,position,reason) VALUES (?1,?2,?3)",
                params![bucket, position as i64, reason],
            )?;
        }
        let insert_sql = sample_insert_sql();
        {
            let mut insert = tx.prepare_cached(&insert_sql)?;
            let mut checked_epochs = BTreeSet::new();
            for row in encoded {
                if epoch_boundary > 0 && checked_epochs.insert(row.epoch.clone()) {
                    let previous_epoch: bool=tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM host_epochs e JOIN host_samples s ON s.identity_id=e.id
                         WHERE e.epoch=?1 AND s.bucket_id<=?2)",params![row.epoch,epoch_boundary],|r|r.get(0))?;
                    ensure!(
                        !previous_epoch,
                        "collector restart or clock discontinuity requires a new observation epoch"
                    );
                }
                tx.execute(
                    "INSERT INTO collector_runs(epoch,start_ms,end_ms,anchor_wall_ms,anchor_logical_ms)
                     VALUES (?1,?2,?3,?4,?5) ON CONFLICT(epoch) DO UPDATE SET end_ms=excluded.end_ms",
                    params![row.epoch,start_ms,end_ms,now_ms,logical],
                )?;
                tx.execute(
                    "INSERT INTO host_epochs(address,epoch,host_id,configured_name,revision,interface_name,interface_index,interface_kind,vlan_id)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                     ON CONFLICT(address,epoch,host_id,configured_name,revision,interface_name,interface_index,interface_kind,vlan_id) DO NOTHING",
                    params![row.address, row.epoch, row.host_id,row.configured_name, row.revision, row.interface_name,
                        row.interface_index, row.interface_kind, row.vlan_id],
                )?;
                let identity: i64 = tx.query_row(
                    "SELECT id FROM host_epochs WHERE address=?1 AND epoch=?2 AND host_id=?3 AND configured_name=?4 AND revision=?5
                     AND interface_name=?6 AND interface_index=?7 AND interface_kind=?8 AND vlan_id=?9",
                    params![row.address, row.epoch, row.host_id,row.configured_name, row.revision, row.interface_name,
                        row.interface_index, row.interface_kind, row.vlan_id], |r| r.get(0),
                )?;
                let mut values = vec![
                    rusqlite::types::Value::Integer(bucket),
                    rusqlite::types::Value::Blob(row.address),
                    rusqlite::types::Value::Integer(identity),
                ];
                values.extend(row.metrics);
                insert.execute(rusqlite::params_from_iter(values))?;
                let sample_id = tx.last_insert_rowid();
                for (position, reason) in row.coverage_reasons.into_iter().enumerate() {
                    tx.execute(
                        "INSERT INTO coverage_reasons(sample_id,position,reason) VALUES (?1,?2,?3)",
                        params![sample_id, position as i64, reason],
                    )?;
                }
            }
        }
        prune_transaction(&tx, logical, now_ms)?;
        persist_clock(
            &tx,
            now_ms,
            logical,
            quarantine,
            self.discontinuity_ms.get(),
        )?;
        enforce_wal_budget(&tx)?;
        tx.commit()?;
        self.checkpoint()
            .context("experience collection committed, but final checkpoint failed")?;
        Ok(())
    }

    /// Expire retained telemetry even while collection is paused; never create
    /// a synthetic collection or reset still-valid observations.
    pub fn maintain(&mut self, now_ms: i64) -> Result<()> {
        self.prune(now_ms)
    }

    pub fn prune(&mut self, now_ms: i64) -> Result<()> {
        let logical = self.clock(now_ms)?;
        loop {
            self.checkpoint()?;
            let tx = self
                .writer
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            prune_transaction(&tx, logical, now_ms)?;
            persist_clock(
                &tx,
                now_ms,
                logical,
                self.quarantine.get(),
                self.discontinuity_ms.get(),
            )?;
            enforce_wal_budget(&tx)?;
            tx.commit()?;
            self.checkpoint()
                .context("experience pruning committed, but final checkpoint failed")?;
            let remaining: bool = self.writer.query_row(
                "SELECT EXISTS(SELECT 1 FROM buckets WHERE retention_ms<=?1 OR end_ms<=?2)",
                params![
                    logical.saturating_sub(RETENTION_MS),
                    now_ms.saturating_sub(RETENTION_MS)
                ],
                |r| r.get(0),
            )?;
            if !remaining {
                break;
            }
        }
        Ok(())
    }

    pub fn latest_collection(
        &self,
        now_ms: i64,
        filter: &Filter,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Option<Collection>> {
        ensure!((1..=256).contains(&limit), "invalid experience page limit");
        let address = filter.address.as_deref().map(address_key).transpose()?;
        if let Some(interface) = &filter.interface {
            bounded_text(interface, 15)?;
        }
        let deadline = ReadDeadline::new(&self.reader);
        let logical = self.clock(now_ms)?;
        let tx = self.reader.unchecked_transaction()?;
        let mut after = Vec::new();
        let collection = if let Some(token) = cursor {
            ensure!(token.len() <= 1024, CursorError::Invalid);
            let decoded: Cursor =
                serde_json::from_slice(&hex::decode(token).map_err(|_| CursorError::Invalid)?)
                    .map_err(|_| CursorError::Invalid)?;
            ensure!(decoded.version == 1, CursorError::Invalid);
            ensure!(
                &decoded.filter == filter && decoded.limit == limit,
                CursorError::FilterMismatch
            );
            address_literal(&decoded.after).map_err(|_| CursorError::Invalid)?;
            after = decoded.after;
            tx.query_row(
                "SELECT seq,collection_id,start_ms,end_ms FROM buckets
                 WHERE collection_id=?1 AND seq>?2 AND retention_ms>?3 AND end_ms>?4 AND end_ms<=?5",
                params![decoded.collection,self.quarantine.get(),logical.saturating_sub(RETENTION_MS),
                    now_ms.saturating_sub(RETENTION_MS),now_ms],
                |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)),
            ).optional()?.context(CursorError::Expired)?
        } else {
            let collection = tx.query_row(
                "SELECT seq,collection_id,start_ms,end_ms FROM buckets
                 WHERE seq>?1 AND retention_ms>?2 AND end_ms>?3 AND end_ms<=?4 ORDER BY seq DESC LIMIT 1",
                params![self.quarantine.get(),logical.saturating_sub(RETENTION_MS),
                    now_ms.saturating_sub(RETENTION_MS),now_ms],
                |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)),
            ).optional()?;
            let Some(collection) = collection else {
                return Ok(None);
            };
            collection
        };
        if !after.is_empty() {
            let found: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM host_samples s JOIN host_epochs e ON e.id=s.identity_id
                 WHERE s.bucket_id=?1 AND s.address=?2 AND (?3 IS NULL OR s.address=?3)
                 AND (?4 IS NULL OR e.interface_name=?4))",
                params![collection.0,after,address,filter.interface], |r|r.get(0),
            )?;
            ensure!(found, CursorError::Invalid);
        }
        let sql = format!(
            "{} WHERE s.bucket_id=?1 AND s.address>?2 AND (?3 IS NULL OR s.address=?3)
            AND (?4 IS NULL OR e.interface_name=?4) ORDER BY s.address LIMIT ?5",
            select_sql()
        );
        let mut samples = read_samples(
            &tx,
            &sql,
            rusqlite::params_from_iter([
                rusqlite::types::Value::Integer(collection.0),
                rusqlite::types::Value::Blob(after),
                address.map_or(rusqlite::types::Value::Null, rusqlite::types::Value::Blob),
                filter
                    .interface
                    .clone()
                    .map_or(rusqlite::types::Value::Null, rusqlite::types::Value::Text),
                rusqlite::types::Value::Integer((limit + 1) as i64),
            ]),
            &deadline,
        )?;
        let next_cursor = if samples.len() > limit {
            samples.truncate(limit);
            let after = address_key(
                &samples
                    .last()
                    .context("empty continuation page")?
                    .ip_address
                    .to_string(),
            )?;
            let token = hex::encode(serde_json::to_vec(&Cursor {
                version: 1,
                collection: collection.1.clone(),
                filter: filter.clone(),
                limit,
                after,
            })?);
            ensure!(
                token.len() <= 1024,
                "experience cursor exceeds bounded size"
            );
            Some(token)
        } else {
            None
        };
        let diagnostics = read_diagnostics(&tx, collection.0)?;
        tx.commit()?;
        deadline.check()?;
        Ok(Some(Collection {
            id: collection.1,
            start_ms: collection.2,
            end_ms: collection.3,
            samples,
            next_cursor,
            clock_discontinuity: self.has_discontinuity(logical),
            diagnostics,
        }))
    }

    /// Internal bounded collection access; callers building table responses use
    /// `latest_collection` instead of loading every host into an HTTP page.
    #[cfg(test)]
    pub fn samples(&self, collection_id: &str, now_ms: i64) -> Result<Vec<Sample>> {
        bounded_text(collection_id, 128)?;
        let deadline = ReadDeadline::new(&self.reader);
        let logical = self.clock(now_ms)?;
        let tx = self.reader.unchecked_transaction()?;
        let sql = format!(
            "{} WHERE b.collection_id=?1 AND b.seq>?2 AND b.retention_ms>?3
            AND b.end_ms>?4 AND b.end_ms<=?5 ORDER BY s.address LIMIT 2049",
            select_sql()
        );
        let samples = read_samples(
            &tx,
            &sql,
            params![
                collection_id,
                self.quarantine.get(),
                logical.saturating_sub(RETENTION_MS),
                now_ms.saturating_sub(RETENTION_MS),
                now_ms
            ],
            &deadline,
        )?;
        ensure!(
            samples.len() <= MAX_HOSTS,
            "experience collection row bound violated"
        );
        tx.commit()?;
        deadline.check()?;
        Ok(samples)
    }

    pub fn collection_for_addresses(
        &self,
        id: &str,
        addresses: &[IpAddr],
        now_ms: i64,
    ) -> Result<Option<Collection>> {
        bounded_text(id, 128)?;
        ensure!(
            addresses.len() <= 256,
            "too many requested experience collection addresses"
        );
        let mut keys = BTreeSet::new();
        for address in addresses {
            ensure!(
                keys.insert(address_key(&address.to_string())?),
                "duplicate requested experience collection address"
            );
        }
        let deadline = ReadDeadline::new(&self.reader);
        let logical = self.clock(now_ms)?;
        let tx = self.reader.unchecked_transaction()?;
        let header = tx
            .query_row(
                "SELECT seq,collection_id,start_ms,end_ms FROM buckets
             WHERE collection_id=?1 AND seq>?2 AND retention_ms>?3 AND end_ms>?4 AND end_ms<=?5",
                params![
                    id,
                    self.quarantine.get(),
                    logical.saturating_sub(RETENTION_MS),
                    now_ms.saturating_sub(RETENTION_MS),
                    now_ms
                ],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some(header) = header else {
            return Ok(None);
        };
        let samples = if keys.is_empty() {
            Vec::new()
        } else {
            let placeholders = (2..=keys.len() + 1)
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "{} WHERE s.bucket_id=?1 AND s.address IN ({placeholders}) ORDER BY s.address",
                select_sql()
            );
            let mut values = Vec::with_capacity(keys.len() + 1);
            values.push(rusqlite::types::Value::Integer(header.0));
            values.extend(keys.into_iter().map(rusqlite::types::Value::Blob));
            read_samples(&tx, &sql, rusqlite::params_from_iter(values), &deadline)?
        };
        let diagnostics = read_diagnostics(&tx, header.0)?;
        tx.commit()?;
        deadline.check()?;
        Ok(Some(Collection {
            id: header.1,
            start_ms: header.2,
            end_ms: header.3,
            samples,
            next_cursor: None,
            clock_discontinuity: self.has_discontinuity(logical),
            diagnostics,
        }))
    }

    pub fn history(&self, address: IpAddr, now_ms: i64) -> Result<History> {
        let samples = self.address_samples(address, now_ms)?;
        let mut discontinuity = self.has_discontinuity(self.clock(now_ms)?);
        let end = now_ms - now_ms.rem_euclid(INTERVAL_MS);
        let mut slots = Vec::with_capacity(MAX_SLOTS);
        let offset = samples
            .first()
            .map_or(0, |s| s.end_at.timestamp_millis().rem_euclid(INTERVAL_MS));
        discontinuity |= offset != 0
            || samples.windows(2).any(|pair| {
                pair[1].start_at.timestamp_millis() < pair[0].end_at.timestamp_millis()
            });
        if !discontinuity {
            let mut observed = samples.into_iter().peekable();
            for index in 0..MAX_SLOTS {
                let slot_end = end - ((MAX_SLOTS - 1 - index) as i64) * INTERVAL_MS;
                while observed
                    .peek()
                    .is_some_and(|sample| sample.end_at.timestamp_millis() < slot_end)
                {
                    observed.next();
                }
                let sample = if observed
                    .peek()
                    .is_some_and(|sample| sample.end_at.timestamp_millis() == slot_end)
                {
                    observed.next()
                } else {
                    None
                };
                slots.push(HistorySlot {
                    start_ms: slot_end - INTERVAL_MS,
                    end_ms: slot_end,
                    sample,
                });
            }
        } else {
            // Do not fabricate a UTC-perfect grid across a changed clock anchor.
            // The observed collection order remains authoritative.
            for sample in samples {
                let start_ms = sample.start_at.timestamp_millis();
                let end_ms = sample.end_at.timestamp_millis();
                if let Some(last) = slots.last().map(|s: &HistorySlot| s.end_ms) {
                    let count =
                        ((start_ms - last).max(0) / INTERVAL_MS).min(MAX_SLOTS as i64) as usize;
                    for index in 0..count {
                        let start = last + index as i64 * INTERVAL_MS;
                        slots.push(HistorySlot {
                            start_ms: start,
                            end_ms: start + INTERVAL_MS,
                            sample: None,
                        });
                    }
                }
                slots.push(HistorySlot {
                    start_ms,
                    end_ms,
                    sample: Some(sample),
                });
                if slots.len() > MAX_SLOTS {
                    slots.drain(..slots.len() - MAX_SLOTS);
                }
            }
            let tail = slots.last().map_or(end, |s| s.end_ms);
            let count = ((now_ms - tail).max(0) / INTERVAL_MS).min(MAX_SLOTS as i64) as usize;
            for index in 0..count {
                let start = tail + index as i64 * INTERVAL_MS;
                slots.push(HistorySlot {
                    start_ms: start,
                    end_ms: start + INTERVAL_MS,
                    sample: None,
                });
            }
            if slots.len() > MAX_SLOTS {
                slots.drain(..slots.len() - MAX_SLOTS);
            }
            let missing = MAX_SLOTS - slots.len();
            let start = slots.first().map_or(end, |s| s.start_ms);
            let mut prefix = (0..missing)
                .map(|index| {
                    let slot_start = start - (missing - index) as i64 * INTERVAL_MS;
                    HistorySlot {
                        start_ms: slot_start,
                        end_ms: slot_start + INTERVAL_MS,
                        sample: None,
                    }
                })
                .collect::<Vec<_>>();
            prefix.extend(slots);
            slots = prefix;
        }
        Ok(History {
            slots,
            clock_discontinuity: discontinuity,
        })
    }

    pub fn usage(&self, address: IpAddr, now_ms: i64) -> Result<Usage> {
        let deadline = ReadDeadline::new(&self.reader);
        let logical = self.clock(now_ms)?;
        let tx = self.reader.unchecked_transaction()?;
        let mut usage = Usage {
            complete: !self.has_discontinuity(logical),
            ..Usage::default()
        };
        let mut previous = None;
        let mut count = 0;
        {
            let mut statement=tx.prepare(
                "SELECT s.traffic_sent_bytes,s.traffic_received_bytes,s.measured_duration_ms,
                    s.coverage_complete,s.traffic_status,b.start_ms,b.end_ms,e.epoch,e.host_id,
                    e.interface_name,e.interface_index,e.interface_kind,e.vlan_id
                 FROM host_samples s JOIN buckets b ON b.seq=s.bucket_id JOIN host_epochs e ON e.id=s.identity_id
                 WHERE s.address=?1 AND b.seq>?2 AND b.retention_ms>?3 AND b.end_ms>?4 AND b.end_ms<=?5
                 ORDER BY b.seq LIMIT 361",
            )?;
            let mut rows = statement.query(params![
                address_key(&address.to_string())?,
                self.quarantine.get(),
                logical.saturating_sub(RETENTION_MS),
                now_ms.saturating_sub(RETENTION_MS),
                now_ms
            ])?;
            while let Some(row) = rows.next()? {
                deadline.check()?;
                count += 1;
                ensure!(count <= MAX_SLOTS, "experience usage row bound violated");
                let sent = decimal_counter(row.get::<_, Option<String>>(0)?.as_deref())?;
                let received = decimal_counter(row.get::<_, Option<String>>(1)?.as_deref())?;
                let duration: i64 = row.get(2)?;
                let complete: i64 = row.get(3)?;
                let status: String = row.get(4)?;
                ensure!(
                    (0..=2 * INTERVAL_MS).contains(&duration) && matches!(complete, 0 | 1),
                    "invalid persisted usage duration or coverage"
                );
                ensure!(
                    matches!(
                        status.as_str(),
                        "available" | "unavailable" | "partial" | "not_observed"
                    ),
                    "invalid persisted traffic status"
                );
                let start: i64 = row.get(5)?;
                let end: i64 = row.get(6)?;
                ensure!(
                    start >= 0 && end.checked_sub(start) == Some(INTERVAL_MS),
                    "invalid persisted usage bucket timestamps"
                );
                let identity = (
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                );
                bounded_text(&identity.0, 128)?;
                bounded_text(&identity.1, 255)?;
                if identity.3 == 0 {
                    ensure!(
                        identity.2.is_empty() && identity.4.is_empty() && identity.5 == 0,
                        "invalid persisted absent interface"
                    );
                } else {
                    bounded_text(&identity.2, 15)?;
                    bounded_text(&identity.4, 32)?;
                    ensure!(
                        (1..=u32::MAX as i64).contains(&identity.3)
                            && (identity.5 == 0 || (1..=4094).contains(&identity.5)),
                        "invalid persisted usage interface"
                    );
                }
                if let Some((old_end, old_identity)) = &previous {
                    usage.complete &= *old_end == start && old_identity == &identity;
                }
                previous = Some((end, identity));
                let valid = status == "available";
                if valid {
                    if let Some(sent) = sent {
                        *usage.sent_bytes.get_or_insert(0) += u128::from(sent);
                    }
                    if let Some(received) = received {
                        *usage.received_bytes.get_or_insert(0) += u128::from(received);
                    }
                    if sent.is_some() && received.is_some() {
                        usage.coverage_ms += if complete == 1 {
                            INTERVAL_MS as u64
                        } else {
                            (duration as u64).min(INTERVAL_MS as u64)
                        };
                    }
                }
                usage.complete &=
                    valid && complete == 1 && duration > 0 && sent.is_some() && received.is_some();
            }
        }
        usage.complete &= count == MAX_SLOTS;
        ensure!(
            usage.coverage_ms <= RETENTION_MS as u64,
            "experience usage coverage bound violated"
        );
        tx.commit()?;
        deadline.check()?;
        Ok(usage)
    }

    fn address_samples(&self, address: IpAddr, now_ms: i64) -> Result<Vec<Sample>> {
        let deadline = ReadDeadline::new(&self.reader);
        let logical = self.clock(now_ms)?;
        let tx = self.reader.unchecked_transaction()?;
        let sql = format!(
            "{} WHERE s.address=?1 AND b.seq>?2 AND b.retention_ms>?3
            AND b.end_ms>?4 AND b.end_ms<=?5 ORDER BY b.seq LIMIT 361",
            select_sql()
        );
        let samples = read_samples(
            &tx,
            &sql,
            params![
                address_key(&address.to_string())?,
                self.quarantine.get(),
                logical.saturating_sub(RETENTION_MS),
                now_ms.saturating_sub(RETENTION_MS),
                now_ms
            ],
            &deadline,
        )?;
        ensure!(
            samples.len() <= MAX_SLOTS,
            "experience history row bound violated"
        );
        tx.commit()?;
        deadline.check()?;
        Ok(samples)
    }

    fn has_discontinuity(&self, logical: i64) -> bool {
        self.discontinuity_ms.get() > 0
            && self.discontinuity_ms.get() > logical.saturating_sub(RETENTION_MS)
    }

    pub fn clock_discontinuity(&self, now_ms: i64) -> Result<bool> {
        Ok(self.has_discontinuity(self.clock(now_ms)?))
    }

    pub fn checkpoint(&self) -> Result<()> {
        let (busy, _, _): (i64, i64, i64) =
            self.writer
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        ensure!(busy == 0, "experience WAL checkpoint blocked");
        // The main-page ceiling is enforced by SQLite; the WAL is additionally
        // checked before and after every admitted completed transaction.
        if self.path.exists() {
            validate_files(&self.path)?;
        }
        Ok(())
    }
}

fn select_sql() -> String {
    let metrics = COLUMNS
        .iter()
        .map(|column| format!("s.{}", column_name(column.path)))
        .collect::<Vec<_>>()
        .join(",");
    format!("SELECT s.id,s.address,e.epoch,e.host_id,e.revision,e.interface_name,e.interface_index,
        e.interface_kind,e.vlan_id,b.start_ms,b.end_ms,e.configured_name,{metrics}
        FROM host_samples s JOIN buckets b ON b.seq=s.bucket_id JOIN host_epochs e ON e.id=s.identity_id")
}

fn read_diagnostics(tx: &Transaction<'_>, bucket: i64) -> Result<Diagnostics> {
    let counters: [Option<String>;4]=tx.query_row(
        "SELECT capture_dropped_packets,analysis_exclusions,tracking_evictions,dropped_unattributed_packets FROM buckets WHERE seq=?1",
        [bucket],|r|Ok([r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?]))?;
    let counter = |text: &Option<String>| -> Result<Option<u64>> {
        text.as_ref()
            .map(|text| {
                let value: u64 = text.parse()?;
                ensure!(value.to_string() == *text, "corrupt collection counter");
                Ok(value)
            })
            .transpose()
    };
    let mut statement = tx.prepare(
        "SELECT name,status,error FROM bucket_sources WHERE bucket_id=?1 ORDER BY name LIMIT 17",
    )?;
    let sources = statement
        .query_map([bucket], |r| {
            Ok(Source {
                name: r.get(0)?,
                status: r.get(1)?,
                error: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(sources.len() <= 16, "corrupt collection source bound");
    for source in &sources {
        bounded_text(&source.name, 32)?;
        bounded_text(&source.status, 32)?;
        if let Some(error) = &source.error {
            bounded_text(error, 1024)?;
        }
    }
    let mut statement = tx.prepare(
        "SELECT reason FROM bucket_reasons WHERE bucket_id=?1 ORDER BY position LIMIT 33",
    )?;
    let reasons = statement
        .query_map([bucket], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(reasons.len() <= 32, "corrupt collection reason bound");
    for reason in &reasons {
        bounded_text(reason, 128)?;
    }
    Ok(Diagnostics {
        capture_dropped_packets: counter(&counters[0])?,
        analysis_exclusions: counter(&counters[1])?,
        tracking_evictions: counter(&counters[2])?,
        dropped_unattributed_packets: counter(&counters[3])?,
        sources,
        reasons,
    })
}

fn decimal_counter(text: Option<&str>) -> Result<Option<u64>> {
    text.map(|text| {
        let value: u64 = text.parse().context("invalid persisted unsigned counter")?;
        ensure!(
            value.to_string() == text,
            "noncanonical persisted unsigned counter"
        );
        Ok(value)
    })
    .transpose()
}

fn read_samples<P: rusqlite::Params>(
    tx: &Transaction<'_>,
    sql: &str,
    parameters: P,
    deadline: &ReadDeadline,
) -> Result<Vec<Sample>> {
    let mut statement = tx.prepare(sql)?;
    let mut rows = statement.query(parameters)?;
    let mut samples = Vec::new();
    while let Some(row) = rows.next()? {
        deadline.check()?;
        let id: i64 = row.get(0)?;
        let address: Vec<u8> = row.get(1)?;
        let index: i64 = row.get(6)?;
        let vlan: i64 = row.get(8)?;
        let mut value = Value::Object(Map::new());
        put(
            &mut value,
            "ip_address",
            Value::String(address_literal(&address)?),
        );
        for (path, index) in [
            ("observation_epoch", 2),
            ("configured_host_id", 3),
            ("configuration_revision", 4),
        ] {
            put(&mut value, path, Value::String(row.get(index)?));
        }
        if index == 0 {
            put(&mut value, "interface", Value::Null);
        } else {
            put(&mut value, "interface.name", Value::String(row.get(5)?));
            put(&mut value, "interface.index", Value::from(index));
            put(&mut value, "interface.kind", Value::String(row.get(7)?));
            put(
                &mut value,
                "interface.vlan_id",
                if vlan == 0 {
                    Value::Null
                } else {
                    Value::from(vlan)
                },
            );
        }
        put(
            &mut value,
            "start_at",
            Value::String(timestamp_literal(row.get(9)?)?),
        );
        put(
            &mut value,
            "end_at",
            Value::String(timestamp_literal(row.get(10)?)?),
        );
        put(&mut value, "configured_name", Value::String(row.get(11)?));
        for (index, column) in COLUMNS.iter().enumerate() {
            let metric: rusqlite::types::Value = row.get(index + 12)?;
            let decoded = decode_metric(metric, column)?;
            put(&mut value, column.path, decoded);
        }
        let mut reasons =
            tx.prepare("SELECT reason FROM coverage_reasons WHERE sample_id=?1 ORDER BY position")?;
        let reasons = reasons
            .query_map([id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        put(
            &mut value,
            "coverage.reasons",
            Value::Array(reasons.into_iter().map(Value::String).collect()),
        );
        let sample: Sample =
            serde_json::from_value(value).context("invalid persisted experience sample")?;
        EncodedSample::new(
            &sample,
            sample.start_at.timestamp_millis(),
            sample.end_at.timestamp_millis(),
        )?;
        samples.push(sample);
    }
    Ok(samples)
}

fn decode_metric(value: rusqlite::types::Value, column: &Column) -> Result<Value> {
    use rusqlite::types::Value as Sql;
    let decoded = match (column.kind, value) {
        (_, Sql::Null) => Value::Null,
        (Kind::Text | Kind::Counter, Sql::Text(text)) => Value::String(text),
        (Kind::Integer, Sql::Integer(integer)) => Value::from(integer),
        (Kind::Bool, Sql::Integer(0)) => Value::Bool(false),
        (Kind::Bool, Sql::Integer(1)) => Value::Bool(true),
        (Kind::Real, Sql::Real(real)) => {
            Value::Number(serde_json::Number::from_f64(real).context("nonfinite persisted metric")?)
        }
        (Kind::ScoreJson, Sql::Text(text)) => {
            ensure!(
                text.len() <= JSON_LIMIT,
                "oversized persisted score explanation"
            );
            serde_json::from_str(&text)?
        }
        _ => bail!("invalid persisted experience metric type: {}", column.path),
    };
    encode_metric(&decoded, column)?;
    Ok(decoded)
}

struct ReadDeadline {
    connection: *mut rusqlite::ffi::sqlite3,
    started: Box<Instant>,
}
impl ReadDeadline {
    fn new(connection: &Connection) -> Self {
        let mut started = Box::new(Instant::now());
        let handle = unsafe { connection.handle() };
        let pointer = (&mut *started as *mut Instant).cast();
        unsafe {
            rusqlite::ffi::sqlite3_progress_handler(handle, 1000, Some(read_progress), pointer);
            rusqlite::ffi::sqlite3_busy_handler(handle, Some(read_busy), pointer);
        }
        Self {
            connection: handle,
            started,
        }
    }
    fn check(&self) -> Result<()> {
        ensure!(
            self.started.elapsed() < Duration::from_millis(900),
            "experience query read deadline exceeded"
        );
        Ok(())
    }
}
impl Drop for ReadDeadline {
    fn drop(&mut self) {
        unsafe {
            rusqlite::ffi::sqlite3_progress_handler(self.connection, 0, None, std::ptr::null_mut());
            rusqlite::ffi::sqlite3_busy_timeout(self.connection, 250);
        }
    }
}
unsafe extern "C" fn read_progress(pointer: *mut std::ffi::c_void) -> std::ffi::c_int {
    let started = unsafe { &*pointer.cast::<Instant>() };
    i32::from(started.elapsed() >= Duration::from_millis(900))
}
unsafe extern "C" fn read_busy(
    pointer: *mut std::ffi::c_void,
    retries: std::ffi::c_int,
) -> std::ffi::c_int {
    let started = unsafe { &*pointer.cast::<Instant>() };
    if retries >= 50 || started.elapsed() >= Duration::from_millis(900) {
        return 0;
    }
    std::thread::sleep(Duration::from_millis(5));
    1
}

fn wall_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn trusted_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path.parent().context("missing experience storage parent")?;
        ensure!(parent != path, "invalid experience storage root");
        if !parent.exists() {
            trusted_directory(parent)?;
        }
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0,
            "untrusted experience storage parent"
        );
        fs::DirBuilder::new().mode(0o700).create(path)?;
        File::open(parent)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "experience directory must be private and owner-only"
    );
    let mut ancestor = path.parent();
    while let Some(parent) = ancestor {
        if parent.as_os_str().is_empty() {
            break;
        }
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.mode() & 0o022 == 0,
            "untrusted experience directory ancestor"
        );
        ancestor = parent.parent();
    }
    Ok(())
}

fn validate_files(path: &Path) -> Result<()> {
    for (suffix, limit) in [
        ("", MAIN_LIMIT),
        ("-wal", WAL_LIMIT),
        ("-shm", 1024 * 1024),
        ("-journal", WAL_LIMIT),
    ] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let name = PathBuf::from(name);
        let metadata = match fs::symlink_metadata(&name) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.len() <= limit,
            "untrusted or oversized experience database file: {}",
            name.display()
        );
    }
    Ok(())
}

fn bounded_text(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "invalid bounded experience text"
    );
    Ok(())
}

fn column_name(path: &str) -> String {
    path.replace('.', "_")
}

fn schema_sql() -> String {
    let metrics = COLUMNS
        .iter()
        .map(|c| {
            let name = column_name(c.path);
            let kind = match c.kind {
                Kind::Integer | Kind::Bool => "INTEGER",
                Kind::Real => "REAL",
                _ => "TEXT",
            };
            format!(",{name} {kind}")
        })
        .collect::<String>();
    format!(
        "PRAGMA page_size=4096; BEGIN IMMEDIATE;
         CREATE TABLE store_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),wall_ms INTEGER NOT NULL,
             logical_ms INTEGER NOT NULL,quarantine_seq INTEGER NOT NULL,discontinuity_ms INTEGER NOT NULL) STRICT;
         INSERT INTO store_state VALUES(1,0,0,0,0);
         CREATE TABLE collector_runs(epoch TEXT PRIMARY KEY,start_ms INTEGER NOT NULL,end_ms INTEGER NOT NULL,
             anchor_wall_ms INTEGER NOT NULL,anchor_logical_ms INTEGER NOT NULL) STRICT;
         CREATE TABLE host_epochs(id INTEGER PRIMARY KEY,address BLOB NOT NULL,epoch TEXT NOT NULL REFERENCES collector_runs(epoch),
             host_id TEXT NOT NULL,configured_name TEXT NOT NULL,revision TEXT NOT NULL,interface_name TEXT NOT NULL,interface_index INTEGER NOT NULL,
             interface_kind TEXT NOT NULL,vlan_id INTEGER NOT NULL,
             UNIQUE(address,epoch,host_id,configured_name,revision,interface_name,interface_index,interface_kind,vlan_id)) STRICT;
         CREATE INDEX epoch_identity ON host_epochs(epoch,id);
         CREATE TABLE buckets(seq INTEGER PRIMARY KEY AUTOINCREMENT,collection_id TEXT NOT NULL UNIQUE,
             start_ms INTEGER NOT NULL,end_ms INTEGER NOT NULL,retention_ms INTEGER NOT NULL,
             capture_dropped_packets TEXT,analysis_exclusions TEXT,tracking_evictions TEXT,dropped_unattributed_packets TEXT) STRICT;
         CREATE INDEX bucket_expiry ON buckets(retention_ms);
         CREATE TABLE bucket_sources(bucket_id INTEGER NOT NULL REFERENCES buckets(seq) ON DELETE CASCADE,
             name TEXT NOT NULL,status TEXT NOT NULL,error TEXT,PRIMARY KEY(bucket_id,name)) STRICT;
         CREATE TABLE bucket_reasons(bucket_id INTEGER NOT NULL REFERENCES buckets(seq) ON DELETE CASCADE,
             position INTEGER NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(bucket_id,position)) STRICT;
         CREATE TABLE host_samples(id INTEGER PRIMARY KEY,bucket_id INTEGER NOT NULL REFERENCES buckets(seq) ON DELETE CASCADE,
             address BLOB NOT NULL CHECK(length(address) IN (5,17)),identity_id INTEGER NOT NULL REFERENCES host_epochs(id)
             {metrics}, UNIQUE(address,bucket_id)) STRICT;
         CREATE INDEX sample_bucket_address ON host_samples(bucket_id,address);
         CREATE INDEX sample_identity ON host_samples(identity_id);
         CREATE TABLE coverage_reasons(sample_id INTEGER NOT NULL REFERENCES host_samples(id) ON DELETE CASCADE,
             position INTEGER NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(sample_id,position),UNIQUE(sample_id,reason)) STRICT;
         PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={SCHEMA_VERSION}; COMMIT;"
    )
}

fn validate_schema(connection: &Connection) -> Result<()> {
    // Compare every table/index definition, not merely user_version: a damaged
    // same-version schema is an error, never an invitation to recreate tables.
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(&schema_sql())?;
    let definitions = |db: &Connection| -> Result<Vec<(String, String, Option<String>)>> {
        let mut statement = db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
        Ok(statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    };
    ensure!(
        definitions(connection)? == definitions(&expected)?,
        "invalid experience database schema; existing data preserved"
    );
    Ok(())
}

fn sample_insert_sql() -> String {
    let names = COLUMNS
        .iter()
        .map(|c| column_name(c.path))
        .collect::<Vec<_>>()
        .join(",");
    let placeholders = (1..=COLUMNS.len() + 3)
        .map(|v| format!("?{v}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "INSERT INTO host_samples(bucket_id,address,identity_id,{names}) VALUES ({placeholders})"
    )
}

fn prune_transaction(tx: &Transaction<'_>, logical_ms: i64, now_ms: i64) -> Result<()> {
    // A bucket is at most 2048 samples. A whole-hour outage must not turn
    // startup cleanup into a 737280-row, gigabyte-sized WAL transaction.
    tx.execute(
        "DELETE FROM buckets WHERE seq IN (
        SELECT seq FROM buckets WHERE retention_ms<=?1 OR end_ms<=?2 ORDER BY seq LIMIT 1)",
        params![
            logical_ms.saturating_sub(RETENTION_MS),
            now_ms.saturating_sub(RETENTION_MS)
        ],
    )?;
    tx.execute("DELETE FROM host_epochs WHERE NOT EXISTS(SELECT 1 FROM host_samples WHERE identity_id=host_epochs.id)", [])?;
    tx.execute("DELETE FROM collector_runs WHERE NOT EXISTS(SELECT 1 FROM host_epochs WHERE epoch=collector_runs.epoch)", [])?;
    let rows: i64 = tx.query_row("SELECT count(*) FROM host_samples", [], |r| r.get(0))?;
    let buckets: i64 = tx.query_row("SELECT count(*) FROM buckets", [], |r| r.get(0))?;
    ensure!(
        rows <= (MAX_HOSTS * MAX_SLOTS) as i64 && buckets <= MAX_SLOTS as i64,
        "experience retention capacity exceeded; previous collections preserved"
    );
    Ok(())
}

fn persist_clock(
    tx: &Transaction<'_>,
    wall: i64,
    logical: i64,
    quarantine: i64,
    discontinuity: i64,
) -> Result<()> {
    tx.execute("UPDATE store_state SET wall_ms=?1,logical_ms=?2,quarantine_seq=?3,discontinuity_ms=?4 WHERE singleton=1",
        params![wall,logical,quarantine,discontinuity])?;
    Ok(())
}

fn enforce_wal_budget(connection: &Connection) -> Result<()> {
    // cache_spill=OFF retains every modified page until commit. Consequently
    // ALL page-cache allocation is a conservative upper bound on dirty pages,
    // not just an estimate of row sizes. Starting from a truncated WAL, each
    // dirty page contributes one 4096-byte frame and its 24-byte frame header.
    let (mut bytes, mut high) = (0, 0);
    let result = unsafe {
        rusqlite::ffi::sqlite3_db_status(
            connection.handle(),
            rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED,
            &mut bytes,
            &mut high,
            0,
        )
    };
    ensure!(
        result == rusqlite::ffi::SQLITE_OK && bytes >= 0,
        "cannot bound experience WAL page cache"
    );
    let pages = (bytes as u64).div_ceil(4096) + 4;
    ensure!(
        32 + pages * (4096 + 24) <= WAL_LIMIT,
        "experience transaction exceeds hard WAL page budget; previous collection preserved"
    );
    Ok(())
}

struct EncodedSample {
    address: Vec<u8>,
    epoch: String,
    host_id: String,
    configured_name: String,
    revision: String,
    interface_name: String,
    interface_index: i64,
    interface_kind: String,
    vlan_id: i64,
    metrics: Vec<rusqlite::types::Value>,
    coverage_reasons: Vec<String>,
}

impl EncodedSample {
    fn new(sample: &Sample, start_ms: i64, end_ms: i64) -> Result<Self> {
        ensure!(
            [
                sample.traffic.sent_bps,
                sample.traffic.received_bps,
                sample.tcp.retransmission_percent_sent,
                sample.tcp.retransmission_percent_received,
                sample.tcp.rtt_remote.p50_ms,
                sample.tcp.rtt_remote.p95_ms,
                sample.tcp.rtt_remote.min_ms,
                sample.tcp.rtt_remote.max_ms,
                sample.tcp.rtt_remote.variation_mean_ms,
                sample.tcp.rtt_host.p50_ms,
                sample.tcp.rtt_host.p95_ms,
                sample.tcp.rtt_host.min_ms,
                sample.tcp.rtt_host.max_ms,
                sample.tcp.rtt_host.variation_mean_ms,
                sample.dns.response_time_p50_ms,
                sample.dns.response_time_p95_ms,
                sample.dns.response_time_variation_mean_ms,
                sample.dns.unanswered_percent,
            ]
            .into_iter()
            .flatten()
            .all(|v| v.is_finite() && v >= 0.0),
            "nonfinite or negative experience metric"
        );
        ensure!(
            sample
                .experience
                .components
                .iter()
                .all(|c| c.value.is_finite() && c.value >= 0.0 && c.score <= 100),
            "invalid score contributor"
        );
        ensure!(
            sample.experience.components.len() <= 16 && sample.experience.reasons.len() <= 32,
            "oversized experience explanation"
        );
        for component in &sample.experience.components {
            bounded_text(&component.code, 64)?;
            bounded_text(&component.unit, 32)?;
        }
        for reason in &sample.experience.reasons {
            bounded_text(reason, 128)?;
        }
        ensure!(
            sample.experience.score.is_none_or(|score| score <= 100)
                && sample.experience.basis_seconds <= 60,
            "invalid experience score or basis"
        );
        ensure!(
            !sample.coverage.complete || sample.measured_duration_ms > 0,
            "complete coverage requires a positive measured duration"
        );
        let value = serde_json::to_value(sample)?;
        validate_projection(&value, "")?;
        ensure!(
            sample.start_at.timestamp_subsec_nanos() % 1_000_000 == 0
                && sample.end_at.timestamp_subsec_nanos() % 1_000_000 == 0,
            "collection labels must use exact millisecond precision"
        );
        let text = |path: &str, max| -> Result<String> {
            let result = get(&value, path)
                .and_then(Value::as_str)
                .context("missing experience identity")?;
            bounded_text(result, max)?;
            Ok(result.to_owned())
        };
        let address_literal = text("ip_address", 45)?;
        let address = address_key(&address_literal)?;
        ensure!(
            timestamp_ms(&text("start_at", 40)?)? == start_ms
                && timestamp_ms(&text("end_at", 40)?)? == end_ms,
            "sample/collection timestamps differ"
        );
        let epoch = text("observation_epoch", 128)?;
        let host_id = text("configured_host_id", 255)?;
        let configured_name = text("configured_name", 255)?;
        let revision = text("configuration_revision", 64)?;
        let (interface_name, interface_index, interface_kind, vlan_id) =
            if value.get("interface").is_some_and(Value::is_null) {
                (String::new(), 0, String::new(), 0)
            } else {
                let index = get(&value, "interface.index")
                    .and_then(Value::as_i64)
                    .context("invalid interface index")?;
                ensure!(
                    (1..=u32::MAX as i64).contains(&index),
                    "invalid interface index"
                );
                (
                    text("interface.name", 15)?,
                    index,
                    text("interface.kind", 32)?,
                    get(&value, "interface.vlan_id")
                        .and_then(Value::as_i64)
                        .unwrap_or(0),
                )
            };
        ensure!(
            vlan_id == 0 || (1..=4094).contains(&vlan_id),
            "invalid VLAN ID"
        );
        let mut metrics = Vec::with_capacity(COLUMNS.len());
        for column in COLUMNS {
            let metric =
                get(&value, column.path).context(format!("missing metric {}", column.path))?;
            metrics.push(encode_metric(metric, column)?);
        }
        let duration = get(&value, "measured_duration_ms")
            .and_then(Value::as_i64)
            .context("missing duration")?;
        ensure!(
            (0..=2 * INTERVAL_MS).contains(&duration),
            "invalid measured duration"
        );
        let reasons = get(&value, "coverage.reasons")
            .and_then(Value::as_array)
            .context("missing coverage reasons")?;
        ensure!(reasons.len() <= 32, "too many coverage reasons");
        let mut coverage_reasons = Vec::with_capacity(reasons.len());
        for reason in reasons {
            let reason = reason.as_str().context("invalid coverage reason")?;
            bounded_text(reason, 128)?;
            ensure!(
                !coverage_reasons.iter().any(|r| r == reason),
                "duplicate coverage reason"
            );
            coverage_reasons.push(reason.to_owned());
        }
        Ok(Self {
            address,
            epoch,
            host_id,
            configured_name,
            revision,
            interface_name,
            interface_index,
            interface_kind,
            vlan_id,
            metrics,
            coverage_reasons,
        })
    }

    fn encoded_size(&self) -> usize {
        self.metrics
            .iter()
            .map(|v| match v {
                rusqlite::types::Value::Text(s) => s.len() + 4,
                rusqlite::types::Value::Blob(b) => b.len() + 4,
                _ => 9,
            })
            .sum::<usize>()
            + self.coverage_reasons.iter().map(String::len).sum::<usize>()
            + self.address.len()
            + self.epoch.len()
            + self.host_id.len()
            + self.configured_name.len()
            + self.revision.len()
            + self.interface_name.len()
            + self.interface_kind.len()
            + 256
    }
}

fn validate_projection(value: &Value, path: &str) -> Result<()> {
    if let Some(object) = value.as_object() {
        for (name, child) in object {
            let path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            validate_projection(child, &path)?;
        }
    } else {
        let allowed = COLUMNS.iter().any(|column| column.path == path)
            || matches!(
                path,
                "ip_address"
                    | "configured_host_id"
                    | "configured_name"
                    | "configuration_revision"
                    | "observation_epoch"
                    | "start_at"
                    | "end_at"
                    | "interface"
                    | "interface.name"
                    | "interface.index"
                    | "interface.kind"
                    | "interface.vlan_id"
                    | "coverage.reasons"
            );
        ensure!(allowed, "experience model has an unstored field: {path}");
    }
    Ok(())
}

fn get<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = value;
    for part in path.split('.') {
        value = value.get(part)?;
    }
    Some(value)
}

fn put(root: &mut Value, path: &str, value: Value) {
    if let Some((head, tail)) = path.split_once('.') {
        let child = root
            .as_object_mut()
            .expect("sample object")
            .entry(head)
            .or_insert_with(|| Value::Object(Map::new()));
        put(child, tail, value);
    } else {
        root.as_object_mut()
            .expect("sample object")
            .insert(path.to_owned(), value);
    }
}

fn encode_metric(value: &Value, column: &Column) -> Result<rusqlite::types::Value> {
    use rusqlite::types::Value as Sql;
    if value.is_null() {
        return Ok(Sql::Null);
    }
    Ok(match column.kind {
        Kind::Text => {
            let text = value.as_str().context("invalid text metric")?;
            bounded_text(
                text,
                if column.path.ends_with(".error") {
                    1024
                } else {
                    255
                },
            )?;
            if matches!(column.path, "last_seen_at" | "connections.observed_at") {
                timestamp_ms(text)?;
            }
            Sql::Text(text.to_owned())
        }
        Kind::Counter => {
            let text = value.as_str().context("counter must be a decimal string")?;
            let number: u64 = text.parse().context("invalid unsigned counter")?;
            ensure!(number.to_string() == text, "noncanonical unsigned counter");
            Sql::Text(text.to_owned())
        }
        Kind::Integer => {
            let number = value.as_i64().context("invalid integer metric")?;
            ensure!(number >= 0, "negative integer metric");
            Sql::Integer(number)
        }
        Kind::Real => {
            let number = value.as_f64().context("invalid real metric")?;
            ensure!(number.is_finite() && number >= 0.0, "invalid finite metric");
            Sql::Real(number)
        }
        Kind::Bool => Sql::Integer(i64::from(
            value.as_bool().context("invalid boolean metric")?,
        )),
        Kind::ScoreJson => {
            ensure!(value.is_array(), "invalid score explanation");
            let json = serde_json::to_string(value)?;
            ensure!(
                json.len() <= JSON_LIMIT,
                "score explanation exceeds storage budget"
            );
            Sql::Text(json)
        }
    })
}

fn address_key(literal: &str) -> Result<Vec<u8>> {
    let address: IpAddr = literal.parse().context("invalid experience address")?;
    ensure!(
        address.to_string() == literal,
        "experience address must be canonical"
    );
    let mut bytes = Vec::with_capacity(17);
    match address {
        IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    Ok(bytes)
}

fn address_literal(bytes: &[u8]) -> Result<String> {
    match bytes {
        [4, a, b, c, d] => Ok(std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        bytes if bytes.len() == 17 && bytes[0] == 6 => {
            let octets: [u8; 16] = bytes[1..].try_into()?;
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => bail!("corrupt experience address"),
    }
}

// UTC RFC3339 only, with optional fractional seconds. This avoids adding a
// second timestamp dependency solely for the private persistence layer.
fn timestamp_ms(value: &str) -> Result<i64> {
    let bytes = value.as_bytes();
    ensure!(
        bytes.len() >= 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && value.ends_with('Z'),
        "experience timestamp must be UTC RFC3339"
    );
    let number = |range: std::ops::Range<usize>| -> Result<i64> {
        let field = value.get(range).context("invalid timestamp field")?;
        ensure!(
            field.bytes().all(|b| b.is_ascii_digit()),
            "invalid timestamp digits"
        );
        Ok(field.parse()?)
    };
    let (year, month, day, hour, minute, second) = (
        number(0..4)?,
        number(5..7)?,
        number(8..10)?,
        number(11..13)?,
        number(14..16)?,
        number(17..19)?,
    );
    ensure!(
        (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && hour < 24
            && minute < 60
            && second < 60,
        "timestamp out of range"
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1..=days[(month - 1) as usize]).contains(&day),
        "invalid timestamp calendar day"
    );
    let fraction = if bytes.len() == 20 {
        0
    } else {
        ensure!(
            bytes[19] == b'.' && (22..=30).contains(&bytes.len()),
            "invalid timestamp fraction"
        );
        let digits = &value[20..value.len() - 1];
        ensure!(
            digits.bytes().all(|b| b.is_ascii_digit()),
            "invalid timestamp fraction"
        );
        let mut milliseconds = digits.chars().take(3).collect::<String>();
        while milliseconds.len() < 3 {
            milliseconds.push('0');
        }
        milliseconds.parse::<i64>()?
    };
    let y = year - i64::from(month <= 2);
    let era = y / 400;
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let days_since_epoch =
        era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + day - 1 - 719468;
    Ok(((days_since_epoch * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + fraction)
}

fn timestamp_literal(ms: i64) -> Result<String> {
    ensure!(ms >= 0, "invalid retained timestamp");
    let seconds = ms / 1000;
    let z = seconds / 86400 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    ensure!(year <= 9999, "retained timestamp out of range");
    let time = seconds % 86400;
    let fraction = ms % 1000;
    if fraction == 0 {
        Ok(format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            time / 3600,
            time / 60 % 60,
            time % 60
        ))
    } else {
        Ok(format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{fraction:03}Z",
            time / 3600,
            time / 60 % 60,
            time % 60
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcontrol_core::experience::{Count, InterfaceIdentity, Traffic};
    use std::sync::atomic::{AtomicU64, Ordering};

    const BASE: i64 = 1_794_614_400_000;
    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".experience-store-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn database(&self) -> PathBuf {
            self.0.join("experience.sqlite")
        }
        fn open(&self, now_ms: i64) -> Store {
            Store::open_at(&self.database(), now_ms).unwrap()
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn sample(address: &str, end: i64) -> Sample {
        let mut sample = Sample::new(
            address.parse().unwrap(),
            "synthetic-host".into(),
            "2026.11.14.1".into(),
            "synthetic-epoch".into(),
            timestamp_literal(end - INTERVAL_MS)
                .unwrap()
                .parse()
                .unwrap(),
            timestamp_literal(end).unwrap().parse().unwrap(),
        );
        sample.configured_name = "Synthetic protected host".into();
        sample.interface = Some(InterfaceIdentity {
            name: "vlan20".into(),
            index: 20,
            kind: "vlan".into(),
            vlan_id: Some(20),
        });
        sample.measured_duration_ms = INTERVAL_MS as u64;
        sample.traffic = Traffic::measured(1, 2, 3, 4, INTERVAL_MS as u64);
        sample.coverage.complete = true;
        sample.coverage.traffic = "complete".into();
        sample
    }

    fn insert(store: &mut Store, id: &str, end: i64, samples: &[Sample]) {
        store
            .insert_collection_at(id, end - INTERVAL_MS, end, samples, end)
            .unwrap();
    }

    fn count(store: &Store, table: &str) -> i64 {
        store
            .reader
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn scalar_roundtrip_unsigned_precision_null_interface_and_source_errors() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        let mut item = sample("192.0.2.2", end);
        item.traffic.sent_bytes = Some(Count(u64::MAX));
        item.tcp.rtt_remote.samples = Count(u64::MAX);
        item.firewall.error = Some("synthetic unavailable source".into());
        item.connections.status = netcontrol_core::experience::SourceStatus::Available;
        item.connections.total = Some(Count(u64::MAX));
        item.connections.observed_at = Some(timestamp_literal(end - 500).unwrap().parse().unwrap());
        item.connections.measurement_duration_ms = Some(1_000);
        item.interface = None;
        item.coverage.reasons = vec!["second".into(), "first".into()];
        insert(&mut store, "one", end, &[item.clone()]);
        assert_eq!(store.samples("one", end).unwrap(), vec![item]);
        let scalar: String = store
            .reader
            .query_row("SELECT traffic_sent_bytes FROM host_samples", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(scalar, u64::MAX.to_string());
        assert_eq!(
            store
                .usage("192.0.2.2".parse().unwrap(), end)
                .unwrap()
                .sent_bytes,
            Some(u128::from(u64::MAX))
        );
        let mut item = sample("192.0.2.2", end + INTERVAL_MS);
        item.traffic.sent_bytes = Some(Count(u64::MAX));
        insert(&mut store, "two", end + INTERVAL_MS, &[item]);
        assert_eq!(
            store
                .usage("192.0.2.2".parse().unwrap(), end + INTERVAL_MS)
                .unwrap()
                .sent_bytes,
            Some(u128::from(u64::MAX) * 2)
        );
    }

    #[test]
    fn entire_collection_and_expiry_are_atomic_on_validation_or_sql_failure() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let first = BASE + INTERVAL_MS;
        insert(
            &mut store,
            "one",
            first,
            &[sample("192.0.2.1", first), sample("192.0.2.2", first)],
        );
        let second = first + INTERVAL_MS;
        let repeated = sample("192.0.2.1", second);
        assert!(
            store
                .insert_collection_at("two", first, second, &[repeated.clone(), repeated], second)
                .is_err()
        );
        assert!(
            store
                .insert_collection_at("one", first, second, &[sample("192.0.2.1", second)], second)
                .is_err()
        );
        assert_eq!(count(&store, "buckets"), 1);
        assert_eq!(count(&store, "host_samples"), 2);
        assert_eq!(
            store
                .latest_collection(second, &Filter::default(), 100, None)
                .unwrap()
                .unwrap()
                .id,
            "one"
        );
        let mut invalid = sample("192.0.2.1", second);
        invalid.traffic.sent_bps = Some(f64::NAN);
        assert!(
            store
                .insert_collection_at("two", first, second, &[invalid], second)
                .is_err()
        );
        assert_eq!(count(&store, "host_samples"), 2);
    }

    #[test]
    fn retention_excludes_exact_cutoff_and_never_returns_361_slots() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        for index in 1..=361 {
            let end = BASE + i64::from(index) * INTERVAL_MS;
            let mut measured = sample("192.0.2.1", end);
            measured.measured_duration_ms = 10_002;
            measured.traffic = Traffic::measured(1, 2, 3, 4, 10_002);
            insert(&mut store, &format!("bucket-{index}"), end, &[measured]);
        }
        let now = BASE + 361 * INTERVAL_MS;
        let history = store.history("192.0.2.1".parse().unwrap(), now).unwrap();
        assert_eq!(history.slots.len(), MAX_SLOTS);
        assert!(
            history
                .slots
                .iter()
                .all(|slot| slot.sample.is_some() && slot.end_ms > now - RETENTION_MS)
        );
        assert_eq!(
            history.slots.first().unwrap().end_ms,
            BASE + 2 * INTERVAL_MS
        );
        assert_eq!(count(&store, "host_samples"), 360);
        assert_eq!(count(&store, "buckets"), 360);
        let usage = store.usage("192.0.2.1".parse().unwrap(), now).unwrap();
        assert!(usage.complete);
        assert_eq!(usage.coverage_ms, RETENTION_MS as u64);
    }

    #[test]
    fn commit_scheduling_jitter_does_not_keep_a_361st_expired_bucket() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        for index in 1..=361 {
            let end = BASE + i64::from(index) * INTERVAL_MS;
            let now = end + if index == 1 { 100 } else { 50 };
            store
                .insert_collection_at(
                    &format!("bucket-{index}"),
                    end - INTERVAL_MS,
                    end,
                    &[sample("192.0.2.1", end)],
                    now,
                )
                .unwrap();
        }
        assert_eq!(count(&store, "buckets"), 360);
        assert_eq!(count(&store, "host_samples"), 360);
    }

    #[test]
    fn truthful_10002ms_measurement_retains_rates_with_nominal_complete_coverage() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        let mut item = sample("192.0.2.1", end);
        item.measured_duration_ms = 10_002;
        item.traffic = Traffic::measured(1, 2, 30_000, 40_000, 10_002);
        insert(&mut store, "one", end, &[item.clone()]);
        assert_eq!(store.samples("one", end).unwrap(), vec![item]);
        assert_eq!(
            store
                .usage("192.0.2.1".parse().unwrap(), end)
                .unwrap()
                .coverage_ms,
            10_000
        );
        let next = end + INTERVAL_MS;
        let mut partial = sample("192.0.2.1", next);
        partial.coverage.complete = false;
        partial.measured_duration_ms = 20_000;
        insert(&mut store, "two", next, &[partial]);
        let usage = store.usage("192.0.2.1".parse().unwrap(), next).unwrap();
        assert_eq!(usage.coverage_ms, 20_000);
        assert!(!usage.complete);
        let later = next + INTERVAL_MS;
        let mut invalid = sample("192.0.2.1", later);
        invalid.measured_duration_ms = 20_001;
        assert!(
            store
                .insert_collection_at("three", next, later, &[invalid], later)
                .is_err()
        );
        assert_eq!(count(&store, "buckets"), 2);
    }

    #[test]
    fn configured_display_name_is_bounded_by_utf8_bytes_and_retained_once_per_epoch_identity() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        let mut item = sample("192.0.2.1", end);
        item.configured_name = format!("{}x", "é".repeat(127));
        insert(&mut store, "one", end, &[item.clone()]);
        assert_eq!(
            store.samples("one", end).unwrap()[0].configured_name,
            item.configured_name
        );
        let next = end + INTERVAL_MS;
        item.start_at = timestamp_literal(end).unwrap().parse().unwrap();
        item.end_at = timestamp_literal(next).unwrap().parse().unwrap();
        insert(&mut store, "two", next, &[item.clone()]);
        assert_eq!(count(&store, "host_epochs"), 1);
        let later = next + INTERVAL_MS;
        item.start_at = timestamp_literal(next).unwrap().parse().unwrap();
        item.end_at = timestamp_literal(later).unwrap().parse().unwrap();
        item.configured_name = "é".repeat(128);
        assert!(
            store
                .insert_collection_at("three", next, later, &[item], later)
                .is_err()
        );
        assert_eq!(count(&store, "host_samples"), 2);
    }

    #[test]
    fn stopped_writer_expiry_is_filtered_without_mutating_the_database() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        insert(&mut store, "one", end, &[sample("192.0.2.1", end)]);
        assert!(
            store
                .latest_collection(end + RETENTION_MS - 1, &Filter::default(), 100, None)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .latest_collection(end + RETENTION_MS, &Filter::default(), 100, None)
                .unwrap()
                .is_none()
        );
        let history = store
            .history("192.0.2.1".parse().unwrap(), end + RETENTION_MS)
            .unwrap();
        assert_eq!(history.slots.len(), 360);
        assert!(history.slots.iter().all(|slot| slot.sample.is_none()));
        assert_eq!(count(&store, "host_samples"), 1);
        store.prune(end + RETENTION_MS).unwrap();
        for table in [
            "host_samples",
            "host_epochs",
            "collector_runs",
            "buckets",
            "coverage_reasons",
            "bucket_reasons",
            "bucket_sources",
        ] {
            assert_eq!(count(&store, table), 0);
        }
    }

    #[test]
    fn paused_collection_maintenance_expires_rows_and_metadata_without_resetting_valid_data() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let first_end = BASE + INTERVAL_MS;
        let mut expired = sample("192.0.2.1", first_end);
        expired.observation_epoch = "expired-run".into();
        expired.coverage.reasons = vec!["expired-evidence".into()];
        let diagnostics = Diagnostics {
            sources: vec![Source {
                name: "traffic".into(),
                status: "available".into(),
                error: None,
            }],
            reasons: vec!["synthetic-pause".into()],
            ..Diagnostics::default()
        };
        store
            .insert_collection_at_with_diagnostics(
                "expired",
                first_end - INTERVAL_MS,
                first_end,
                &[expired],
                first_end,
                &diagnostics,
            )
            .unwrap();
        let valid_end = first_end + 2 * INTERVAL_MS;
        let mut valid = sample("192.0.2.2", valid_end);
        valid.observation_epoch = "valid-run".into();
        valid.configured_name = "Still valid protected host".into();
        valid.coverage.reasons = vec!["valid-evidence".into()];
        store
            .insert_collection_at_with_diagnostics(
                "valid",
                valid_end - INTERVAL_MS,
                valid_end,
                &[valid.clone()],
                valid_end,
                &diagnostics,
            )
            .unwrap();
        let cutoff = first_end + RETENTION_MS;
        store.maintain(cutoff - 1).unwrap();
        assert_eq!(count(&store, "host_samples"), 2);
        assert_eq!(count(&store, "buckets"), 2);
        store.maintain(cutoff).unwrap();
        assert_eq!(store.samples("valid", cutoff).unwrap(), vec![valid]);
        assert!(store.samples("expired", cutoff).unwrap().is_empty());
        for table in [
            "host_samples",
            "host_epochs",
            "collector_runs",
            "buckets",
            "coverage_reasons",
            "bucket_reasons",
            "bucket_sources",
        ] {
            assert_eq!(count(&store, table), 1);
        }
        assert_eq!(
            store
                .reader
                .query_row("SELECT epoch FROM collector_runs", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "valid-run"
        );
        store.maintain(valid_end + RETENTION_MS).unwrap();
        for table in [
            "host_samples",
            "host_epochs",
            "collector_runs",
            "buckets",
            "coverage_reasons",
            "bucket_reasons",
            "bucket_sources",
        ] {
            assert_eq!(count(&store, table), 0);
        }
    }

    #[test]
    fn restart_preserves_only_unexpired_samples() {
        let directory = TestDirectory::new();
        let end = BASE + INTERVAL_MS;
        {
            let mut store = directory.open(BASE);
            insert(&mut store, "one", end, &[sample("192.0.2.1", end)]);
        }
        {
            let store = directory.open(end + 1000);
            assert_eq!(store.samples("one", end + 1000).unwrap().len(), 1);
        }
        let store = directory.open(end + RETENTION_MS);
        assert_eq!(count(&store, "host_samples"), 0);
    }

    #[test]
    fn resumed_collector_must_not_reuse_the_previous_run_epoch() {
        let directory = TestDirectory::new();
        let end = BASE + INTERVAL_MS;
        {
            let mut store = directory.open(BASE);
            insert(&mut store, "one", end, &[sample("192.0.2.1", end)]);
        }
        let mut store = directory.open(end + 1);
        let next = end + INTERVAL_MS;
        assert!(
            store
                .insert_collection_at("two", end, next, &[sample("192.0.2.1", next)], next)
                .is_err()
        );
        assert_eq!(count(&store, "host_samples"), 1);
        let mut resumed = sample("192.0.2.1", next);
        resumed.observation_epoch = "new-run".into();
        insert(&mut store, "two", next, &[resumed]);
        assert_eq!(count(&store, "host_samples"), 2);
        assert_eq!(count(&store, "collector_runs"), 2);
    }

    #[test]
    fn schema_corruption_is_rejected_without_recreation_or_data_reset() {
        let directory = TestDirectory::new();
        let end = BASE + INTERVAL_MS;
        {
            let mut store = directory.open(BASE);
            insert(&mut store, "one", end, &[sample("192.0.2.1", end)]);
            store
                .writer
                .execute_batch("DROP INDEX sample_identity")
                .unwrap();
            store.checkpoint().unwrap();
        }
        let before = fs::read(directory.database()).unwrap();
        assert!(Store::open_at(&directory.database(), end).is_err());
        assert_eq!(fs::read(directory.database()).unwrap(), before);
        let db = Connection::open(directory.database()).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM host_samples", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn unsupported_version_and_unversioned_existing_database_fail_closed() {
        for version in [0, 2] {
            let directory = TestDirectory::new();
            {
                let store = directory.open(BASE);
                store
                    .writer
                    .execute_batch(&format!("PRAGMA user_version={version}"))
                    .unwrap();
                store.checkpoint().unwrap();
            }
            let before = fs::read(directory.database()).unwrap();
            assert!(Store::open_at(&directory.database(), BASE).is_err());
            assert_eq!(fs::read(directory.database()).unwrap(), before);
        }
    }

    #[test]
    fn corrupt_database_header_is_preserved_on_open_failure() {
        let directory = TestDirectory::new();
        drop(directory.open(BASE));
        let corrupt = b"this is deliberately not a SQLite database";
        fs::write(directory.database(), corrupt).unwrap();
        assert!(Store::open_at(&directory.database(), BASE).is_err());
        assert_eq!(fs::read(directory.database()).unwrap(), corrupt);
    }

    #[test]
    fn sqlite_page_full_failure_rolls_back_every_host_and_bucket() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let first = BASE + INTERVAL_MS;
        insert(&mut store, "one", first, &[sample("192.0.2.1", first)]);
        let pages: i64 = store
            .writer
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        store
            .writer
            .execute_batch(&format!("PRAGMA max_page_count={pages}"))
            .unwrap();
        let second = first + INTERVAL_MS;
        let mut incoming = Vec::new();
        for index in 2..=100 {
            let mut item = sample(&format!("192.0.2.{index}"), second);
            item.traffic.error = Some("x".repeat(1024));
            item.tcp.error = Some("x".repeat(1024));
            incoming.push(item);
        }
        assert!(
            store
                .insert_collection_at("two", first, second, &incoming, second)
                .is_err()
        );
        assert_eq!(count(&store, "host_samples"), 1);
        assert_eq!(count(&store, "buckets"), 1);
        assert_eq!(store.samples("one", second).unwrap().len(), 1);
    }

    #[test]
    fn busy_writer_fails_boundedly_without_publishing_partial_collection() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let other = Connection::open(directory.database()).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        let start = Instant::now();
        let end = BASE + INTERVAL_MS;
        assert!(
            store
                .insert_collection_at("one", BASE, end, &[sample("192.0.2.1", end)], end)
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        other.execute_batch("ROLLBACK").unwrap();
        assert_eq!(count(&store, "host_samples"), 0);
        assert_eq!(count(&store, "buckets"), 0);
    }

    #[test]
    fn directory_lock_and_owner_only_files_are_enforced() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        assert!(Store::open_at(&directory.database(), BASE).is_err());
        let end = BASE + INTERVAL_MS;
        insert(&mut store, "one", end, &[sample("192.0.2.1", end)]);
        validate_files(&directory.database()).unwrap();
        assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o077, 0);
        assert_eq!(
            fs::metadata(directory.database()).unwrap().mode() & 0o077,
            0
        );
        drop(store);
        let reopened = directory.open(end);
        drop(reopened);
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.database(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Store::open_at(&directory.database(), end).is_err());
    }

    #[test]
    fn hostile_wal_symlink_is_rejected_before_sqlite_opens_it() {
        let directory = TestDirectory::new();
        drop(directory.open(BASE));
        let target = directory.0.join("protected-marker");
        fs::write(&target, b"do not alter").unwrap();
        let wal = directory.0.join("experience.sqlite-wal");
        validate_files(&directory.database()).unwrap();
        match fs::symlink_metadata(&wal) {
            Ok(metadata) => {
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                fs::remove_file(&wal).unwrap();
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
        assert!(fs::symlink_metadata(&wal).is_err());
        std::os::unix::fs::symlink(&target, &wal).unwrap();
        assert!(Store::open_at(&directory.database(), BASE).is_err());
        assert_eq!(fs::read(target).unwrap(), b"do not alter");
    }

    #[test]
    fn backwards_clock_quarantines_reads_and_survives_restart_without_reset() {
        let directory = TestDirectory::new();
        let end = BASE + INTERVAL_MS;
        {
            let mut store = directory.open(BASE);
            insert(&mut store, "old", end, &[sample("192.0.2.1", end)]);
            let backwards = BASE - INTERVAL_MS;
            assert!(
                store
                    .latest_collection(backwards, &Filter::default(), 100, None)
                    .unwrap()
                    .is_none()
            );
            assert!(store.clock_discontinuity(backwards).unwrap());
            let mut new = sample("192.0.2.1", backwards);
            new.observation_epoch = "new-epoch".into();
            insert(&mut store, "new", backwards, &[new]);
            assert_eq!(count(&store, "host_samples"), 2);
            assert_eq!(store.samples("old", backwards).unwrap().len(), 0);
            assert_eq!(store.samples("new", backwards).unwrap().len(), 1);
        }
        let store = directory.open(BASE - INTERVAL_MS + 1);
        assert_eq!(count(&store, "host_samples"), 2);
        assert_eq!(
            store.samples("old", BASE - INTERVAL_MS + 1).unwrap().len(),
            0
        );
        assert_eq!(
            store.samples("new", BASE - INTERVAL_MS + 1).unwrap().len(),
            1
        );
    }

    #[test]
    fn restart_into_backwards_clock_quarantines_old_buckets_explicitly() {
        let directory = TestDirectory::new();
        let end = BASE + INTERVAL_MS;
        {
            let mut store = directory.open(BASE);
            insert(&mut store, "old", end, &[sample("192.0.2.1", end)]);
        }
        let store = directory.open(BASE);
        assert_eq!(count(&store, "host_samples"), 1);
        assert!(
            store
                .latest_collection(BASE, &Filter::default(), 100, None)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .history("192.0.2.1".parse().unwrap(), BASE)
                .unwrap()
                .clock_discontinuity
        );
    }

    #[test]
    fn restart_without_forward_clock_evidence_does_not_extend_old_telemetry() {
        let directory = TestDirectory::new();
        let end = BASE + INTERVAL_MS;
        {
            let mut store = directory.open(BASE);
            insert(&mut store, "one", end, &[sample("192.0.2.1", end)]);
        }
        let store = directory.open(end);
        assert_eq!(count(&store, "host_samples"), 1);
        assert!(
            store
                .latest_collection(end, &Filter::default(), 100, None)
                .unwrap()
                .is_none()
        );
        assert!(store.clock_discontinuity(end).unwrap());
    }

    #[test]
    fn pagination_remains_on_one_completed_collection_with_numeric_address_order() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        insert(
            &mut store,
            "one",
            end,
            &[
                sample("2001:db8::1", end),
                sample("192.0.2.10", end),
                sample("192.0.2.2", end),
                sample("192.0.2.1", end),
            ],
        );
        let first = store
            .latest_collection(end, &Filter::default(), 2, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            first
                .samples
                .iter()
                .map(|s| s.ip_address.to_string())
                .collect::<Vec<_>>(),
            vec!["192.0.2.1", "192.0.2.2"]
        );
        let token = first.next_cursor.unwrap();
        let next = end + INTERVAL_MS;
        insert(&mut store, "two", next, &[sample("192.0.2.100", next)]);
        let second = store
            .latest_collection(next, &Filter::default(), 2, Some(&token))
            .unwrap()
            .unwrap();
        assert_eq!(second.id, "one");
        assert_eq!(
            second
                .samples
                .iter()
                .map(|s| s.ip_address.to_string())
                .collect::<Vec<_>>(),
            vec!["192.0.2.10", "2001:db8::1"]
        );
        assert!(second.next_cursor.is_none());
        assert!(
            store
                .latest_collection(
                    next,
                    &Filter {
                        address: Some("192.0.2.1".into()),
                        interface: None
                    },
                    2,
                    Some(&token)
                )
                .is_err()
        );
        assert!(
            store
                .latest_collection(next, &Filter::default(), 1, Some(&token))
                .is_err()
        );
        let expired = store
            .latest_collection(end + RETENTION_MS, &Filter::default(), 2, Some(&token))
            .unwrap_err();
        assert!(expired.to_string().contains("restart latest paging"));
        assert_eq!(
            expired.downcast_ref::<CursorError>(),
            Some(&CursorError::Expired)
        );
    }

    #[test]
    fn diagnostics_are_atomic_and_bound_to_the_paged_collection() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        let diagnostics = Diagnostics {
            capture_dropped_packets: Some(u64::MAX),
            analysis_exclusions: None,
            tracking_evictions: Some(4),
            dropped_unattributed_packets: Some(3),
            sources: vec![Source {
                name: "traffic".into(),
                status: "partial".into(),
                error: Some("synthetic failure".into()),
            }],
            reasons: vec!["capture_gap".into()],
        };
        store
            .insert_collection_at_with_diagnostics(
                "one",
                BASE,
                end,
                &[sample("192.0.2.1", end), sample("192.0.2.2", end)],
                end,
                &diagnostics,
            )
            .unwrap();
        let first = store
            .latest_collection(end, &Filter::default(), 1, None)
            .unwrap()
            .unwrap();
        assert_eq!(first.diagnostics.capture_dropped_packets, Some(u64::MAX));
        assert_eq!(first.diagnostics.analysis_exclusions, None);
        assert_eq!(
            first.diagnostics.sources[0].error.as_deref(),
            Some("synthetic failure")
        );
        let next = end + INTERVAL_MS;
        insert(&mut store, "two", next, &[sample("192.0.2.1", next)]);
        let page = store
            .latest_collection(next, &Filter::default(), 1, first.next_cursor.as_deref())
            .unwrap()
            .unwrap();
        assert_eq!(page.diagnostics.reasons, vec!["capture_gap"]);
        assert_eq!(page.diagnostics.tracking_evictions, Some(4));
        store.prune(next + RETENTION_MS).unwrap();
        assert_eq!(count(&store, "bucket_sources"), 0);
        assert_eq!(count(&store, "bucket_reasons"), 0);
    }

    #[test]
    fn selected_address_collection_read_preserves_header_and_omits_unobserved_hosts() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        insert(
            &mut store,
            "one",
            end,
            &[
                sample("192.0.2.1", end),
                sample("192.0.2.2", end),
                sample("2001:db8::1", end),
            ],
        );
        let next = end + INTERVAL_MS;
        insert(&mut store, "two", next, &[sample("192.0.2.100", next)]);
        let requested = ["2001:db8::1", "192.0.2.2", "192.0.2.3"].map(|ip| ip.parse().unwrap());
        let selected = store
            .collection_for_addresses("one", &requested, next)
            .unwrap()
            .unwrap();
        assert_eq!(selected.id, "one");
        assert_eq!(selected.end_ms, end);
        assert_eq!(
            selected
                .samples
                .iter()
                .map(|s| s.ip_address.to_string())
                .collect::<Vec<_>>(),
            vec!["192.0.2.2", "2001:db8::1"]
        );
        assert!(selected.next_cursor.is_none());
        assert_eq!(
            selected.diagnostics.reasons,
            vec!["collection_diagnostics_unavailable"]
        );
        let empty = store
            .collection_for_addresses("one", &[], next)
            .unwrap()
            .unwrap();
        assert!(empty.samples.is_empty());
        assert_eq!(empty.end_ms, end);
        assert!(
            store
                .collection_for_addresses("unknown", &requested, next)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .collection_for_addresses("one", &requested, end + RETENTION_MS)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .collection_for_addresses("two", &[requested[0], requested[0]], end + RETENTION_MS)
                .is_err()
        );
        let excess = (1..=257)
            .map(|index| IpAddr::V6(std::net::Ipv6Addr::from(index as u128)))
            .collect::<Vec<_>>();
        assert!(
            store
                .collection_for_addresses("two", &excess, end + RETENTION_MS)
                .is_err()
        );
    }

    #[test]
    fn history_has_explicit_missing_slots_and_preserves_removed_host_and_epoch_identity() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let one = BASE + INTERVAL_MS;
        let three = BASE + 3 * INTERVAL_MS;
        insert(&mut store, "one", one, &[sample("192.0.2.1", one)]);
        let mut moved = sample("192.0.2.1", three);
        moved.configured_host_id = "replacement-host".into();
        moved.configured_name = "Replacement owner display name".into();
        moved.observation_epoch = "replacement-epoch".into();
        moved.interface.as_mut().unwrap().name = "vlan30".into();
        insert(&mut store, "three", three, &[moved]);
        let four = three + INTERVAL_MS;
        insert(&mut store, "four", four, &[sample("192.0.2.2", four)]);
        let history = store.history("192.0.2.1".parse().unwrap(), four).unwrap();
        assert_eq!(history.slots.len(), 360);
        let tail = &history.slots[356..];
        assert_eq!(
            tail.iter().map(|s| s.sample.is_some()).collect::<Vec<_>>(),
            vec![true, false, true, false]
        );
        assert_eq!(
            tail[0].sample.as_ref().unwrap().configured_host_id,
            "synthetic-host"
        );
        assert_eq!(
            tail[0].sample.as_ref().unwrap().configured_name,
            "Synthetic protected host"
        );
        assert_eq!(
            tail[2].sample.as_ref().unwrap().configured_host_id,
            "replacement-host"
        );
        assert_eq!(
            tail[2].sample.as_ref().unwrap().configured_name,
            "Replacement owner display name"
        );
        assert!(
            !store
                .usage("192.0.2.1".parse().unwrap(), four)
                .unwrap()
                .complete
        );
        assert_eq!(
            store
                .latest_collection(four, &Filter::default(), 100, None)
                .unwrap()
                .unwrap()
                .samples
                .len(),
            1
        );
    }

    #[test]
    fn churn_prunes_every_unreferenced_identity_run_and_reason() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        for index in 1..=400 {
            let end = BASE + i64::from(index) * INTERVAL_MS;
            let address = format!("10.0.{}.{}", index / 256, index % 256);
            let mut item = sample(&address, end);
            item.observation_epoch = format!("epoch-{index}");
            item.coverage.reasons = vec!["synthetic-gap".into()];
            insert(&mut store, &format!("bucket-{index}"), end, &[item]);
        }
        for table in [
            "host_samples",
            "host_epochs",
            "collector_runs",
            "buckets",
            "coverage_reasons",
        ] {
            assert_eq!(count(&store, table), 360);
        }
        store.checkpoint().unwrap();
        assert!(fs::metadata(directory.database()).unwrap().len() <= MAIN_LIMIT);
        assert!(
            fs::metadata(directory.0.join("experience.sqlite-wal"))
                .unwrap()
                .len()
                <= WAL_LIMIT
        );
    }

    #[test]
    fn oversized_score_explanation_is_rejected_without_partial_commit() {
        let directory = TestDirectory::new();
        let mut store = directory.open(BASE);
        let end = BASE + INTERVAL_MS;
        let mut item = sample("192.0.2.1", end);
        item.experience.reasons = vec!["x".repeat(JSON_LIMIT + 1)];
        assert!(
            store
                .insert_collection_at("one", BASE, end, &[item], end)
                .is_err()
        );
        assert_eq!(count(&store, "buckets"), 0);
        assert_eq!(count(&store, "host_samples"), 0);
    }

    #[test]
    fn deadline_interrupts_sql_and_restores_connection_for_following_reads() {
        let directory = TestDirectory::new();
        let store = directory.open(BASE);
        {
            let mut deadline = ReadDeadline::new(&store.reader);
            *deadline.started = Instant::now() - Duration::from_secs(2);
            assert!(store.reader.query_row(
                    "WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<1000000) SELECT sum(v) FROM n",
                    [],|r|r.get::<_,i64>(0)).is_err());
        }
        assert_eq!(count(&store, "host_samples"), 0);
    }

    #[test]
    #[ignore = "manual full-retention disk sizing: 2048 populated IPv6 hosts and 360 completed buckets"]
    fn full_retention_2048_populated_ipv6_addresses_scale() {
        use netcontrol_core::experience::{
            Activity, Component, Confidence, ExperienceLevel, ExperienceStatus, SourceStatus,
            Timing,
        };
        let directory = TestDirectory::new();
        let cleanup_path = directory.0.clone();
        println!(
            "experience sizing owns directory={} pid={}",
            directory.0.display(),
            std::process::id()
        );
        let mut store = directory.open(BASE);
        unsafe extern "C" fn observe_wal(
            pointer: *mut std::ffi::c_void,
            _connection: *mut rusqlite::ffi::sqlite3,
            _database: *const std::ffi::c_char,
            frames: std::ffi::c_int,
        ) -> std::ffi::c_int {
            let peak = unsafe { &*pointer.cast::<Cell<u64>>() };
            if frames >= 0 {
                peak.set(peak.get().max(32 + frames as u64 * (4096 + 24)));
            }
            rusqlite::ffi::SQLITE_OK
        }
        struct WalObserver {
            connection: *mut rusqlite::ffi::sqlite3,
            peak: Box<Cell<u64>>,
        }
        impl Drop for WalObserver {
            fn drop(&mut self) {
                unsafe {
                    rusqlite::ffi::sqlite3_wal_hook(self.connection, None, std::ptr::null_mut());
                }
            }
        }
        let mut observer = WalObserver {
            connection: unsafe { store.writer.handle() },
            peak: Box::new(Cell::new(0)),
        };
        unsafe {
            rusqlite::ffi::sqlite3_wal_hook(
                observer.connection,
                Some(observe_wal),
                (&mut *observer.peak as *mut Cell<u64>).cast(),
            );
        }
        let started = Instant::now();
        let timing = Timing {
            samples: Count(u64::MAX),
            variation_pairs: Count(u64::MAX),
            p50_ms: Some(75.12345678901234),
            p95_ms: Some(149.12345678901234),
            min_ms: Some(0.123456789012345),
            max_ms: Some(4999.123456789012),
            variation_mean_ms: Some(49.12345678901234),
        };
        macro_rules! maximum_counters {
                ($value:expr; $($field:ident),+ $(,)?) => {
                    $(($value).$field=Some(Count(u64::MAX));)+
                };
            }
        let mut incoming = Vec::with_capacity(MAX_HOSTS);
        for index in 1..=MAX_HOSTS {
            let address = std::net::Ipv6Addr::new(
                0x2001,
                0xdb8,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
                0xffff,
                index as u16,
            );
            let mut item = sample(&address.to_string(), BASE + INTERVAL_MS);
            item.configured_host_id =
                format!("protected-ipv6-host-{index:04}-high-capacity-statistics-identity");
            item.configured_name = format!("Protected IPv6 host {index:04} - {}", "x".repeat(227));
            item.observation_epoch = "00000000-0000-4000-8000-000000000001".into();
            item.interface = Some(InterfaceIdentity {
                name: "vlan4094-lan123".into(),
                index: u32::MAX,
                kind: "vlan".into(),
                vlan_id: Some(4094),
            });
            item.last_seen_at = Some(
                timestamp_literal(BASE + INTERVAL_MS - 1)
                    .unwrap()
                    .parse()
                    .unwrap(),
            );
            item.activity = Activity::Active;
            maximum_counters!(item.traffic;sent_packets,received_packets,sent_bytes,received_bytes);
            item.traffic.sent_bps = Some(u64::MAX as f64 * 0.8);
            item.traffic.received_bps = Some(u64::MAX as f64 * 0.8);
            item.firewall.status = SourceStatus::Available;
            maximum_counters!(item.firewall;dropped_sent_packets,dropped_received_packets);
            item.connections.status = SourceStatus::Available;
            item.connections.measurement_duration_ms = Some(1_000);
            maximum_counters!(item.connections;total,tcp_established,unreplied);
            item.tcp.status = SourceStatus::Available;
            maximum_counters!(item.tcp;
                    data_packets_sent,data_packets_received,retransmission_observations_sent,
                    retransmission_observations_received,window_decreases_host,window_decreases_peer,
                    zero_window_observations_host,zero_window_observations_peer,
                    zero_window_transitions_host,zero_window_transitions_peer);
            item.tcp.retransmission_percent_sent = Some(1.123456789012345);
            item.tcp.retransmission_percent_received = Some(1.123456789012345);
            item.tcp.advertised_window_min_bytes_host = Some(1_073_725_440);
            item.tcp.advertised_window_min_bytes_peer = Some(1_073_725_440);
            item.tcp.rtt_remote = timing.clone();
            item.tcp.rtt_host = timing.clone();
            item.dns.status = SourceStatus::Available;
            maximum_counters!(item.dns;
                    requests,responses,unanswered,pending_at_close,servfail_responses,
                    refused_responses,excluded_observations);
            item.dns.response_time_p50_ms = Some(49.12345678901234);
            item.dns.response_time_p95_ms = Some(99.12345678901234);
            item.dns.response_time_variation_mean_ms = Some(24.12345678901234);
            item.dns.unanswered_percent = Some(4.123456789012345);
            item.experience.score = Some(75);
            item.experience.level = ExperienceLevel::Good;
            item.experience.status = ExperienceStatus::Rated;
            item.experience.confidence = Confidence::High;
            item.experience.basis_seconds = 60;
            item.experience.components = [
                ("tcp_repeats_sent", 1.123456789012345, "percent"),
                ("tcp_repeats_received", 1.123456789012345, "percent"),
                ("remote_ack_delay", 149.12345678901234, "ms"),
                ("host_ack_delay", 39.12345678901234, "ms"),
                ("dns_response_delay", 99.12345678901234, "ms"),
                ("dns_unanswered", 4.123456789012345, "percent"),
            ]
            .into_iter()
            .map(|(code, value, unit)| Component {
                code: code.into(),
                score: 75,
                value,
                unit: unit.into(),
                samples: Count(u64::MAX),
            })
            .collect();
            item.experience.reasons = vec![
                "managed_policy_drops".into(),
                "tcp_histogram_estimate".into(),
                "dns_histogram_estimate".into(),
                "offload_packet_units".into(),
                "same_lan_traffic_unobserved".into(),
                "passive_boundary_observation".into(),
            ];
            item.coverage.reasons = vec![
                "offload_packet_units".into(),
                "same_lan_traffic_unobserved".into(),
            ];
            item.coverage.traffic = "complete".into();
            item.coverage.firewall = "managed_nftables_only".into();
            item.coverage.tcp = "complete".into();
            item.coverage.dns = "complete".into();
            item.coverage.connections = "snapshot".into();
            incoming.push(item);
        }
        println!(
            "experience sizing scalar_sample_json_bytes={} configured_main_limit={} configured_wal_limit={}",
            serde_json::to_vec(&incoming[0]).unwrap().len(),
            MAIN_LIMIT,
            WAL_LIMIT
        );
        let sizes = |store: &Store| {
            let main = fs::metadata(&store.path).unwrap().len();
            let mut wal = store.path.as_os_str().to_owned();
            wal.push("-wal");
            let wal = fs::metadata(PathBuf::from(wal)).map_or(0, |m| m.len());
            (main, wal)
        };
        for index in 1..=MAX_SLOTS {
            let end = BASE + index as i64 * INTERVAL_MS;
            let labels = sample("192.0.2.1", end);
            for item in &mut incoming {
                item.start_at = labels.start_at;
                item.end_at = labels.end_at;
                item.last_seen_at = Some(timestamp_literal(end - 1).unwrap().parse().unwrap());
                item.connections.observed_at =
                    Some(timestamp_literal(end - 500).unwrap().parse().unwrap());
            }
            if let Err(error) = store.insert_collection_at(
                &format!("scale-bucket-{index:03}"),
                end - INTERVAL_MS,
                end,
                &incoming,
                end,
            ) {
                let rows = count(&store, "host_samples");
                let (main, wal) = sizes(&store);
                let projection = if rows > 0 {
                    u128::from(main) * (MAX_HOSTS * MAX_SLOTS) as u128 / rows as u128
                } else {
                    0
                };
                eprintln!(
                    "experience sizing CAPACITY FAILURE bucket={} committed_rows={} main_bytes={} wal_bytes={} peak_wal_bytes={} elapsed_seconds={:.3} projected_full_main_bytes={} error={error:#}",
                    index,
                    rows,
                    main,
                    wal,
                    observer.peak.get(),
                    started.elapsed().as_secs_f64(),
                    projection
                );
                panic!(
                    "full one-hour engineering budget not established; preserve 2048 hosts and 360 buckets, revise limits only from measured sizing"
                );
            }
            if index % 60 == 0 {
                let (main, wal) = sizes(&store);
                println!(
                    "experience sizing progress buckets={} rows={} main_bytes={} wal_bytes={} peak_wal_bytes={} elapsed_seconds={:.3}",
                    index,
                    count(&store, "host_samples"),
                    main,
                    wal,
                    observer.peak.get(),
                    started.elapsed().as_secs_f64()
                );
            }
        }
        assert_eq!(
            count(&store, "host_samples"),
            (MAX_HOSTS * MAX_SLOTS) as i64
        );
        assert_eq!(count(&store, "buckets"), MAX_SLOTS as i64);
        assert_eq!(count(&store, "host_epochs"), MAX_HOSTS as i64);
        assert_eq!(count(&store, "collector_runs"), 1);
        let now = BASE + MAX_SLOTS as i64 * INTERVAL_MS;
        let address = incoming[0].ip_address;
        let page = store
            .latest_collection(now, &Filter::default(), 256, None)
            .unwrap()
            .unwrap();
        assert_eq!(page.samples.len(), 256);
        assert!(page.next_cursor.is_some());
        let selected_addresses = incoming
            .iter()
            .take(256)
            .map(|item| item.ip_address)
            .collect::<Vec<_>>();
        let lookup_started = Instant::now();
        let selected = store
            .collection_for_addresses(&page.id, &selected_addresses, now)
            .unwrap()
            .unwrap();
        assert_eq!(selected.samples.len(), 256);
        assert!(selected.samples[0].connections.observed_at.is_some());
        assert_eq!(
            selected.samples[0].connections.measurement_duration_ms,
            Some(1_000)
        );
        println!(
            "experience sizing address_lookup_hosts=256 elapsed_ms={:.3} latest_metric_json_bytes={}",
            lookup_started.elapsed().as_secs_f64() * 1000.0,
            serde_json::to_vec(&selected.samples).unwrap().len()
        );
        let history = store.history(address, now).unwrap();
        assert_eq!(history.slots.len(), MAX_SLOTS);
        assert!(history.slots.iter().all(|slot| slot.sample.is_some()));
        let history_samples = history
            .slots
            .iter()
            .filter_map(|slot| slot.sample.as_ref())
            .collect::<Vec<_>>();
        println!(
            "experience sizing history_slots={} history_metric_json_bytes={}",
            history.slots.len(),
            serde_json::to_vec(&history_samples).unwrap().len()
        );
        let usage = store.usage(address, now).unwrap();
        assert_eq!(
            usage.sent_bytes,
            Some(u128::from(u64::MAX) * MAX_SLOTS as u128)
        );
        assert_eq!(usage.coverage_ms, RETENTION_MS as u64);
        assert!(usage.complete);
        let usage_started = Instant::now();
        for item in incoming.iter().take(100) {
            let usage = store.usage(item.ip_address, now).unwrap();
            assert_eq!(
                usage.sent_bytes,
                Some(u128::from(u64::MAX) * MAX_SLOTS as u128)
            );
            assert!(usage.complete);
        }
        println!(
            "experience sizing narrow_usage_hosts=100 projected_rows={} elapsed_ms={:.3}",
            100 * MAX_SLOTS,
            usage_started.elapsed().as_secs_f64() * 1000.0
        );
        let (main, wal) = sizes(&store);
        assert!(main <= MAIN_LIMIT && wal <= WAL_LIMIT);
        println!(
            "experience sizing FULL rows={} main_bytes={} wal_bytes={} peak_wal_bytes={} elapsed_seconds={:.3}",
            count(&store, "host_samples"),
            main,
            wal,
            observer.peak.get(),
            started.elapsed().as_secs_f64()
        );
        let previous_peak = observer.peak.get();
        drop(observer);
        drop(store);
        let reopen_started = Instant::now();
        let reopen_now = now + 1;
        let mut store = directory.open(reopen_now);
        let reopen_elapsed = reopen_started.elapsed();
        assert_eq!(
            count(&store, "host_samples"),
            (MAX_HOSTS * MAX_SLOTS) as i64
        );
        assert_eq!(count(&store, "buckets"), MAX_SLOTS as i64);
        assert_eq!(count(&store, "host_epochs"), MAX_HOSTS as i64);
        assert_eq!(count(&store, "collector_runs"), 1);
        let restarted = store
            .collection_for_addresses(&page.id, &selected_addresses, reopen_now)
            .unwrap()
            .unwrap();
        assert_eq!(restarted.samples, selected.samples);
        let restarted_history = store.history(address, reopen_now).unwrap();
        assert_eq!(restarted_history.slots.len(), MAX_SLOTS);
        assert!(
            restarted_history
                .slots
                .iter()
                .all(|slot| slot.sample.is_some())
        );
        let restarted_usage = store.usage(address, reopen_now).unwrap();
        assert_eq!(
            restarted_usage.sent_bytes,
            Some(u128::from(u64::MAX) * MAX_SLOTS as u128)
        );
        assert!(restarted_usage.complete);
        assert!(!store.clock_discontinuity(reopen_now).unwrap());
        let (main, wal) = sizes(&store);
        println!(
            "experience sizing REOPEN rows={} main_bytes={} wal_bytes={} reopen_elapsed_seconds={:.3}",
            count(&store, "host_samples"),
            main,
            wal,
            reopen_elapsed.as_secs_f64()
        );
        let mut observer = WalObserver {
            connection: unsafe { store.writer.handle() },
            peak: Box::new(Cell::new(previous_peak)),
        };
        unsafe {
            rusqlite::ffi::sqlite3_wal_hook(
                observer.connection,
                Some(observe_wal),
                (&mut *observer.peak as *mut Cell<u64>).cast(),
            );
        }
        let expired = now + RETENTION_MS;
        assert!(
            store
                .latest_collection(expired, &Filter::default(), 256, None)
                .unwrap()
                .is_none()
        );
        let history = store.history(address, expired).unwrap();
        assert_eq!(history.slots.len(), MAX_SLOTS);
        assert!(history.slots.iter().all(|slot| slot.sample.is_none()));
        store.prune(expired).unwrap();
        for table in [
            "host_samples",
            "buckets",
            "host_epochs",
            "collector_runs",
            "coverage_reasons",
            "bucket_sources",
            "bucket_reasons",
        ] {
            assert_eq!(count(&store, table), 0);
        }
        let (main, wal) = sizes(&store);
        assert!(observer.peak.get() <= WAL_LIMIT);
        println!(
            "experience sizing EXPIRED rows=0 main_bytes={} wal_bytes={} peak_wal_bytes={} elapsed_seconds={:.3}",
            main,
            wal,
            observer.peak.get(),
            started.elapsed().as_secs_f64()
        );
        drop(observer);
        drop(store);
        drop(directory);
        assert!(!cleanup_path.exists());
        println!(
            "experience sizing CLEANED directory={}",
            cleanup_path.display()
        );
    }
}
