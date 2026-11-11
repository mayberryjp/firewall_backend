use anyhow::Result;
use netcontrol_core::{DiskLog, LOG_MESSAGE_BYTES};
use std::{io::Write, path::Path};
use tracing_subscriber::fmt::writer::MakeWriterExt;

struct EventWriter {
    log: DiskLog,
    buffer: Vec<u8>,
}

impl Write for EventWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        for part in bytes.split_inclusive(|b| *b == b'\n') {
            let complete = part.last() == Some(&b'\n');
            let content = if complete {
                &part[..part.len() - 1]
            } else {
                part
            };
            if self.buffer.len() + content.len() > LOG_MESSAGE_BYTES {
                return Err(std::io::Error::other(
                    "daemon log event exceeds 65000 bytes",
                ));
            }
            self.buffer.extend_from_slice(content);
            if complete {
                let text = std::str::from_utf8(&self.buffer).map_err(std::io::Error::other)?;
                self.log.append(text).map_err(std::io::Error::other)?;
                self.buffer.clear();
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.log.sync().map_err(std::io::Error::other)
    }
}

pub fn configure(directory: Option<&Path>) -> Result<Option<DiskLog>> {
    let log = directory
        .map(|path| DiskLog::open(&path.join("logs").join("netcontrol")))
        .transpose()?;
    if let Some(log) = &log {
        let writer_log = log.clone();
        let writer = move || EventWriter {
            log: writer_log.clone(),
            buffer: Vec::new(),
        };
        tracing_subscriber::fmt()
            .json()
            .with_writer(writer.and(std::io::stderr))
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize daemon logging: {error}"))?;
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize daemon logging: {error}"))?;
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcontrol_core::LogQuery;

    #[test]
    fn tracing_diagnostics_are_queryable_after_reopening_storage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logs");
        let log = DiskLog::open(&path).unwrap();
        let sink = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || EventWriter {
                log: sink.clone(),
                buffer: Vec::new(),
            })
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(component = "synthetic", "daemon generated event");
            tracing::error!(component = "synthetic-worker", "worker generated failure");
        });
        drop(log);
        let reopened = DiskLog::open(&path).unwrap();
        let page = reopened.read(&LogQuery::parse("").unwrap()).unwrap();
        assert_eq!(page.entries.len(), 2);
        let first: serde_json::Value = serde_json::from_str(&page.entries[0].message).unwrap();
        let second: serde_json::Value = serde_json::from_str(&page.entries[1].message).unwrap();
        assert_eq!(first["fields"]["message"], "daemon generated event");
        assert_eq!(second["level"], "ERROR");
    }

    #[test]
    fn daemon_events_are_captured_once_despite_fragmented_writes() {
        let directory = tempfile::tempdir().unwrap();
        let log = DiskLog::open(&directory.path().join("logs")).unwrap();
        let mut writer = EventWriter {
            log: log.clone(),
            buffer: Vec::new(),
        };
        writer.write_all(b"{\"message\":\"synthetic").unwrap();
        assert!(
            log.read(&LogQuery::parse("").unwrap())
                .unwrap()
                .entries
                .is_empty()
        );
        writer
            .write_all(b" event\"}\n{\"message\":\"second\"}\n")
            .unwrap();
        writer.flush().unwrap();
        let page = log.read(&LogQuery::parse("").unwrap()).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].message, "{\"message\":\"synthetic event\"}");
        assert!(
            writer
                .write_all(&vec![b'x'; LOG_MESSAGE_BYTES + 1])
                .is_err()
        );
    }
}
