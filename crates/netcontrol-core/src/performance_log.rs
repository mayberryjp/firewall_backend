use crate::{DiskLog, LogQuery};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone)]
pub struct PerformanceLog {
    log: DiskLog,
    error_reported: Arc<AtomicBool>,
}

impl PerformanceLog {
    pub fn open(directory: &Path) -> Result<Self> {
        Ok(Self {
            log: DiskLog::open(directory)?,
            error_reported: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn record(&self, event: &str, observed_at: &str, details: Value) {
        let message = json!({
            "schema":"netcontrol-performance/v1",
            "event":event,
            "observed_at":observed_at,
            "details":details
        });
        if let Err(error) = self.log.append(&message.to_string()) {
            if !self.error_reported.swap(true, Ordering::Relaxed) {
                tracing::error!(%error, event, "performance log storage failed; inspect the performance log API and retained files");
            }
        }
    }

    pub fn read(&self, query: &LogQuery) -> Result<Value> {
        let mut page = serde_json::to_value(self.log.read(query)?)?;
        page["source"] = json!("performance");
        page["capture"] = json!({"state":"running","retrying":false,"error":null});
        Ok(page)
    }

    pub fn purge(&self) -> Result<Value> {
        self.log.purge()?;
        Ok(json!({"source":"performance","purged":true}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_producers_persist_in_one_ordered_stream_across_restart() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("performance");
        let log = PerformanceLog::open(&path)?;
        let handles: Vec<_> = (0..2)
            .map(|producer| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for count in 0..3 {
                        log.record(
                            if producer == 0 {
                                "link_observation"
                            } else {
                                "gateway_probe_loss"
                            },
                            "2026-11-17T01:00:00Z",
                            json!({"count":count}),
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let page = log.read(&LogQuery::parse("")?)?;
        assert_eq!(page["entries"].as_array().unwrap().len(), 6);
        let cursor = page["next_cursor"].as_str().unwrap().to_owned();
        for (index, entry) in page["entries"].as_array().unwrap().iter().enumerate() {
            assert_eq!(entry["sequence"], (index + 1).to_string());
            let message: Value = serde_json::from_str(entry["message"].as_str().unwrap())?;
            assert_eq!(message["observed_at"], "2026-11-17T01:00:00Z");
        }
        drop(log);
        let log = PerformanceLog::open(&path)?;
        assert_eq!(log.read(&LogQuery::parse("")?)?["entries"], page["entries"]);
        assert!(
            log.read(&LogQuery::parse(&format!("cursor={cursor}"))?)?["entries"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn purge_is_shared_with_active_producers_and_leaves_other_logs_untouched() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("performance");
        let other = DiskLog::open(&directory.path().join("netcontrol"))?;
        other.append("keep this diagnostic")?;
        let log = PerformanceLog::open(&path)?;
        let producer = log.clone();
        producer.record("link_observation", "2026-11-17T01:00:00Z", json!({}));
        let cursor = log.read(&LogQuery::parse("")?)?["next_cursor"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(log.purge()?, json!({"source":"performance","purged":true}));
        assert_eq!(other.read(&LogQuery::parse("")?)?.entries.len(), 1);
        let query = LogQuery::parse(&format!("cursor={cursor}"))?;
        assert_eq!(producer.read(&query)?["entries"], json!([]));
        let handle = std::thread::spawn(move || {
            producer.record("gateway_probe_loss", "2026-11-17T01:00:01Z", json!({}));
        });
        handle.join().unwrap();
        let page = log.read(&query)?;
        assert_eq!(page["reset"], true);
        assert_eq!(page["entries"].as_array().unwrap().len(), 1);
        assert!(
            page["entries"][0]["message"]
                .as_str()
                .unwrap()
                .contains("gateway_probe_loss")
        );
        drop(log);
        assert_eq!(
            PerformanceLog::open(&path)?.read(&query)?["entries"],
            page["entries"]
        );
        Ok(())
    }

    #[test]
    fn storage_failure_is_not_an_empty_success() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("performance");
        let log = PerformanceLog::open(&path)?;
        log.record("link_observation", "2026-11-17T01:00:00Z", json!({}));
        let segment = std::fs::read_dir(&path)?
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(segment)?
            .write_all(b"corruption")?;
        log.record("link_observation", "2026-11-17T01:00:01Z", json!({}));
        assert!(log.read(&LogQuery::parse("")?).is_err());
        assert!(log.error_reported.load(Ordering::Relaxed));
        Ok(())
    }

    use std::io::Write;
}
