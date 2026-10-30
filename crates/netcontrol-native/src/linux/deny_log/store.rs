use anyhow::{Context, Result, ensure};
use netcontrol_core::{DenyLogQuery, DenyRecord};
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
        Ok(Self {
            root,
            records,
            next,
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
