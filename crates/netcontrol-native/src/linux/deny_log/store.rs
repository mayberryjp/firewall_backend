use anyhow::{Context, Result, ensure};
use netcontrol_core::{DenyLogQuery, DenyRecord};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt, path::PathBuf};

const SEGMENTS: u64 = 8;
const RECORDS: u64 = 512;
const SEGMENT_BYTES: usize = 512 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    schema: u32,
    records: Vec<DenyRecord>,
}

pub(super) struct Store {
    root: PathBuf,
    records: BTreeMap<u64, DenyRecord>,
    next: u64,
    first_seen: Connection,
    alerting: bool,
}

impl Store {
    pub fn open(root: PathBuf) -> Result<Self> {
        super::super::trusted_directory(&root)?;
        let mut records = BTreeMap::new();
        for slot in 0..SEGMENTS {
            let path = root.join(format!("deny-{slot}.json"));
            if !path.try_exists()? {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.mode() & 0o077 == 0
                    && metadata.len() <= SEGMENT_BYTES as u64,
                "untrusted or oversized deny-log segment"
            );
            let segment: Segment = super::super::read_json(&path)?;
            ensure!(
                segment.schema == 1
                    && !segment.records.is_empty()
                    && segment.records.len() <= RECORDS as usize,
                "invalid deny-log segment"
            );
            let mut last = None;
            let mut generation = None;
            for record in segment.records {
                let id: u64 = record.id.parse()?;
                let group = (id.checked_sub(1).context("zero deny-log ID")?) / RECORDS;
                ensure!(
                    id.to_string() == record.id && group % SEGMENTS == slot,
                    "invalid deny-log record ID/slot"
                );
                ensure!(
                    last.is_none_or(|v| id == v + 1) && generation.is_none_or(|v| v == group),
                    "invalid deny-log segment ordering"
                );
                validate(&record)?;
                last = Some(id);
                generation = Some(group);
                ensure!(
                    records.insert(id, record).is_none(),
                    "duplicate deny-log ID"
                );
            }
        }
        let next = records.last_key_value().map_or(Ok(1), |(id, _)| {
            id.checked_add(1).context("deny-log IDs exhausted")
        })?;
        if let Some((&oldest, _)) = records.first_key_value() {
            ensure!(
                next - oldest <= RECORDS * SEGMENTS && records.len() as u64 == next - oldest,
                "deny-log history has missing records"
            );
        }
        let path = root.join("first-seen.sqlite");
        if !path.try_exists()? {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .sync_all()?;
            std::fs::File::open(&root)?.sync_all()?;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "untrusted first-seen drop database"
        );
        let mut first_seen = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        first_seen.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
        let schema: u32 = first_seen.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if schema == 0 {
            let tables: u32 = first_seen.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get(0),
            )?;
            ensure!(tables == 0, "unversioned first-seen drop database");
            first_seen.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE first_seen (
                     tuple BLOB PRIMARY KEY NOT NULL CHECK(length(tuple) IN (13,37)),
                     alert TEXT
                 ) WITHOUT ROWID;
                 CREATE INDEX pending_alerts ON first_seen(tuple) WHERE alert IS NOT NULL;
                 PRAGMA user_version=1; COMMIT;",
            )?;
        } else {
            ensure!(schema == 1, "unsupported first-seen drop database schema");
        }
        ensure!(
            first_seen.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))? == "ok",
            "corrupt first-seen drop database"
        );
        let transaction = first_seen.transaction()?;
        for record in records.values() {
            transaction.execute(
                "INSERT OR IGNORE INTO first_seen(tuple) VALUES (?1)",
                [Self::tuple(record)],
            )?;
        }
        transaction.commit()?;
        Ok(Self {
            root,
            records,
            next,
            first_seen,
            alerting: false,
        })
    }

    pub fn append(&mut self, incoming: &[DenyRecord]) -> Result<()> {
        let mut offset = 0;
        while offset < incoming.len() {
            let group = (self.next - 1) / RECORDS;
            let slot = group % SEGMENTS;
            let first = group * RECORDS + 1;
            let mut segment = Segment {
                schema: 1,
                records: self
                    .records
                    .range(first..self.next)
                    .map(|(_, v)| v.clone())
                    .collect(),
            };
            let count = (RECORDS as usize - segment.records.len()).min(incoming.len() - offset);
            for record in &incoming[offset..offset + count] {
                let mut record = record.clone();
                record.id = first
                    .checked_add(segment.records.len() as u64)
                    .context("deny-log IDs exhausted")?
                    .to_string();
                ensure!(record.id != u64::MAX.to_string(), "deny-log IDs exhausted");
                validate(&record)?;
                segment.records.push(record);
            }
            let bytes = serde_json::to_vec(&segment)?;
            ensure!(
                bytes.len() <= SEGMENT_BYTES,
                "deny-log segment exceeds limit"
            );
            super::super::write_json(&self.root.join(format!("deny-{slot}.json")), &segment)?;
            let transaction = self.first_seen.transaction()?;
            for record in &segment.records {
                let alert = self
                    .alerting
                    .then(|| serde_json::to_string(record))
                    .transpose()?;
                transaction.execute(
                    "INSERT OR IGNORE INTO first_seen(tuple, alert) VALUES (?1, ?2)",
                    params![Self::tuple(record), alert],
                )?;
            }
            transaction.commit()?;
            self.records
                .retain(|id, _| (id - 1) / RECORDS % SEGMENTS != slot);
            for record in segment.records {
                let id: u64 = record.id.parse()?;
                self.next = id.checked_add(1).context("deny-log IDs exhausted")?;
                self.records.insert(id, record);
            }
            offset += count;
        }
        Ok(())
    }

    pub fn first_drops(&mut self, enabled: bool) -> Result<Vec<DenyRecord>> {
        self.alerting = enabled;
        if !enabled {
            self.first_seen.execute(
                "UPDATE first_seen SET alert=NULL WHERE alert IS NOT NULL",
                [],
            )?;
            return Ok(Vec::new());
        }
        let transaction = self.first_seen.transaction()?;
        let mut records = Vec::new();
        {
            let mut statement = transaction.prepare(
                "SELECT tuple, alert FROM first_seen WHERE alert IS NOT NULL ORDER BY tuple LIMIT 10",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (key, alert) = row?;
                let record: DenyRecord = serde_json::from_str(&alert)?;
                validate(&record)?;
                ensure!(
                    key == Self::tuple(&record),
                    "first-seen drop tuple mismatch"
                );
                records.push(record);
            }
        }
        for record in &records {
            transaction.execute(
                "UPDATE first_seen SET alert=NULL WHERE tuple=?1",
                [Self::tuple(record)],
            )?;
        }
        transaction.commit()?;
        Ok(records)
    }

    pub fn query(&self, query: &DenyLogQuery) -> Value {
        let mut matches = self.records.iter().rev().filter(|(id, record)| {
            query.before_id.is_none_or(|v| **id < v) && query.matches(record)
        });
        let records = matches
            .by_ref()
            .take(query.limit)
            .map(|(_, v)| v)
            .collect::<Vec<_>>();
        let next = matches
            .next()
            .and_then(|_| records.last().map(|v| v.id.clone()));
        json!({
            "records":records, "next_before_id":next,
            "oldest_id":self.records.first_key_value().map(|(_, v)| &v.id),
            "newest_id":self.records.last_key_value().map(|(_, v)| &v.id),
            "cursor_expired":query.before_id.is_some_and(|cursor| self.records.first_key_value().is_some_and(|(id, _)| cursor <= *id && *id > 1)),
            "retention":{"max_records":RECORDS * SEGMENTS,"max_segment_bytes":SEGMENT_BYTES,"segments":SEGMENTS}
        })
    }

    fn tuple(record: &DenyRecord) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(37);
        match (record.source, record.destination) {
            (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
                bytes.push(4);
                bytes.extend(source.octets());
                bytes.extend(destination.octets());
            }
            (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
                bytes.push(6);
                bytes.extend(source.octets());
                bytes.extend(destination.octets());
            }
            _ => unreachable!("validated drop addresses have the same family"),
        }
        bytes.push(record.protocol);
        bytes.push(u8::from(record.destination_port.is_some()));
        bytes.extend(record.destination_port.unwrap_or(0).to_be_bytes());
        bytes
    }
}

fn validate(record: &DenyRecord) -> Result<()> {
    ensure!(
        matches!(record.chain.as_str(), "input" | "forward")
            && matches!(record.reason.as_str(), "rule" | "policy")
            && (record.reason == "rule") == record.compiled_rule_index.is_some()
            && record.compiled_rule_index.is_none_or(|v| v <= 4096)
            && record.ruleset_id.len() == 64
            && record
                .ruleset_id
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            && record.source.is_ipv4() == record.destination.is_ipv4()
            && record.timestamp_ms <= 253_402_300_799_999
            && [&record.ingress, &record.egress].into_iter().all(|v| v
                .as_ref()
                .is_none_or(|v| !v.is_empty()
                    && v.len() <= 15
                    && !v.chars().any(char::is_control))),
        "invalid deny-log record"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> DenyRecord {
        serde_json::from_value(json!({
            "id":"","timestamp_ms":1,"chain":"forward","reason":"rule","compiled_rule_index":2,
            "ruleset_id":"a".repeat(64),"source":"192.0.2.1","destination":"198.51.100.1",
            "protocol":17,"source_port":1234,"destination_port":53,
            "ingress_index":2,"egress_index":3,"ingress":"lan0","egress":"wan0","packet_length":28
        }))
        .unwrap()
    }

    #[test]
    fn discord_first_seen_index_ignores_source_port_and_survives_rotation_restart_and_disable()
    -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "discord-drop-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let result = (|| -> Result<()> {
            let mut store = Store::open(root.clone())?;
            store.append(&[record()])?;
            assert!(store.first_drops(true)?.is_empty());
            let mut first = record();
            first.destination_port = Some(443);
            store.append(&[first.clone(), first.clone()])?;
            let mut repeated = first.clone();
            repeated.source_port = Some(60000);
            repeated.chain = "input".into();
            repeated.ingress = Some("other0".into());
            repeated.reason = "policy".into();
            repeated.compiled_rule_index = None;
            store.append(&[repeated])?;
            let events = store.first_drops(true)?;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].id, "2");
            assert_eq!(events[0].source_port, first.source_port);
            assert!(store.first_drops(true)?.is_empty());
            for _ in 0..43 {
                store.append(&vec![record(); 100])?;
            }
            assert!(
                !store
                    .records
                    .values()
                    .any(|row| row.destination_port == Some(443))
            );
            drop(store);
            let mut store = Store::open(root.clone())?;
            assert!(store.first_drops(true)?.is_empty());
            store.append(&[first])?;
            assert!(store.first_drops(true)?.is_empty());
            assert!(store.first_drops(false)?.is_empty());
            let mut disabled = record();
            disabled.destination_port = Some(8080);
            store.append(&[disabled.clone()])?;
            assert!(store.first_drops(true)?.is_empty());
            store.append(&[disabled])?;
            assert!(store.first_drops(true)?.is_empty());
            let mut queued = record();
            queued.destination_port = Some(8443);
            store.append(&[queued])?;
            drop(store);
            let mut store = Store::open(root.clone())?;
            let events = store.first_drops(true)?;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].destination_port, Some(8443));
            assert!(store.first_drops(true)?.is_empty());
            Ok(())
        })();
        std::fs::remove_dir_all(&root)?;
        result
    }

    #[test]
    fn discord_tuple_identity_uses_exact_requested_fields_and_distinguishes_null_ports() {
        let baseline = record();
        let key = Store::tuple(&baseline);
        for change in 0..5 {
            let mut changed = baseline.clone();
            match change {
                0 => changed.source = "192.0.2.2".parse().unwrap(),
                1 => changed.destination = "198.51.100.2".parse().unwrap(),
                2 => changed.destination_port = Some(0),
                3 => changed.destination_port = None,
                _ => changed.protocol = 6,
            }
            assert_ne!(Store::tuple(&changed), key);
        }
        let mut none = baseline.clone();
        none.destination_port = None;
        let mut zero = none.clone();
        zero.destination_port = Some(0);
        assert_ne!(Store::tuple(&none), Store::tuple(&zero));
        let mut ipv6 = baseline.clone();
        ipv6.source = "2001:db8::1".parse().unwrap();
        ipv6.destination = "2001:db8::2".parse().unwrap();
        assert_ne!(Store::tuple(&ipv6), key);
    }

    #[test]
    fn deny_log_rotation_restart_filters_and_cursors() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "deny-log-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let result = (|| -> Result<()> {
            let mut store = Store::open(root.clone())?;
            for _ in 0..43 {
                store.append(&vec![record(); 100])?;
            }
            let result = store.query(&DenyLogQuery::parse("limit=1")?);
            ensure!(
                result["records"][0]["id"] == "4300" && result["next_before_id"] == "4300",
                "newest/cursor"
            );
            ensure!(
                result["oldest_id"] == "513" && store.records.len() == 3788,
                "rotation bound"
            );
            drop(store);
            let mut store = Store::open(root.clone())?;
            ensure!(store.next == 4301, "restart ID");
            store.append(&[record()])?;
            let page = store.query(&DenyLogQuery::parse(
                "limit=2&before_id=4300&protocol=17&address=192.0.2.1&since_ms=1&until_ms=1",
            )?);
            ensure!(
                page["records"][0]["id"] == "4299" && page["records"][1]["id"] == "4298",
                "stable page"
            );
            ensure!(
                store.query(&DenyLogQuery::parse("before_id=500")?)["cursor_expired"] == true,
                "expired cursor"
            );
            ensure!(
                store.query(&DenyLogQuery::parse("protocol=6")?)["records"] == json!([]),
                "protocol filter"
            );
            ensure!(
                store.query(&DenyLogQuery::parse("chain=input")?)["records"] == json!([]),
                "chain filter"
            );
            std::fs::write(root.join("deny-0.json"), b"broken")?;
            ensure!(Store::open(root.clone()).is_err(), "corrupt state accepted");
            ensure!(
                std::fs::read(root.join("deny-0.json"))? == b"broken",
                "corrupt state changed"
            );
            Ok(())
        })();
        std::fs::remove_dir_all(&root)?;
        result
    }

    #[test]
    fn deny_log_storage_failures_do_not_publish_or_overwrite_unsafe_files() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "deny-failure-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let result = (|| -> Result<()> {
            let mut store = Store::open(root.clone())?;
            store.append(&[record()])?;
            let before = std::fs::read(root.join("deny-0.json"))?;
            let query = DenyLogQuery::parse("")?;
            let response = store.query(&query);
            std::fs::create_dir(root.join("deny-0.writing"))?;
            ensure!(
                store.append(&[record()]).is_err(),
                "unsafe staging path accepted"
            );
            ensure!(
                store.query(&query) == response
                    && std::fs::read(root.join("deny-0.json"))? == before,
                "failed write published records"
            );
            std::fs::remove_dir(root.join("deny-0.writing"))?;
            std::fs::hard_link(root.join("deny-0.json"), root.join("linked.json"))?;
            ensure!(
                Store::open(root.clone()).is_err(),
                "hard-linked traffic metadata accepted"
            );
            std::fs::remove_file(root.join("linked.json"))?;
            std::fs::rename(root.join("deny-0.json"), root.join("target.json"))?;
            std::os::unix::fs::symlink("target.json", root.join("deny-0.json"))?;
            ensure!(Store::open(root.clone()).is_err(), "symlink accepted");
            ensure!(
                std::fs::read(root.join("target.json"))? == before,
                "unsafe target modified"
            );
            Ok(())
        })();
        std::fs::remove_dir_all(&root)?;
        result
    }
}
