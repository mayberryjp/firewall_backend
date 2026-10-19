use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(crate) fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unavailable".into())
}
#[derive(Clone)]
pub(crate) struct ContextState {
    pub stop: Arc<std::sync::atomic::AtomicBool>,
    pub status: Arc<Mutex<Value>>,
}
impl ContextState {
    pub fn stopping(&self) -> bool {
        self.stop.load(std::sync::atomic::Ordering::Acquire)
    }
    pub fn wait(&self, duration: Duration) -> bool {
        let end = Instant::now() + duration;
        while !self.stopping() && Instant::now() < end {
            thread::sleep(
                Duration::from_millis(20).min(end.saturating_duration_since(Instant::now())),
            );
        }
        self.stopping()
    }
    pub fn update(&self, f: impl FnOnce(&mut Value)) {
        if let Ok(mut s) = self.status.lock() {
            f(&mut s);
        }
    }
}
pub(crate) struct Worker {
    pub name: String,
    pub context: ContextState,
    join: Option<JoinHandle<()>>,
    done: mpsc::Receiver<()>,
}
impl Worker {
    pub fn start(
        name: String,
        namespace: Option<Arc<std::fs::File>>,
        initial: Value,
        prepare: impl FnOnce() -> Result<Box<dyn FnOnce(ContextState) -> Result<()> + Send>>
        + Send
        + 'static,
    ) -> Result<Self> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done) = mpsc::sync_channel(1);
        let context = ContextState {
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            status: Arc::new(Mutex::new(initial)),
        };
        let ctx = context.clone();
        let join = thread::Builder::new()
            .name(format!("nc-{name}"))
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        if let Some(file) = namespace {
                            #[cfg(target_os = "linux")]
                            {
                                use std::os::fd::AsRawFd;
                                use std::os::unix::fs::MetadataExt;
                                let current = std::fs::metadata("/proc/thread-self/ns/net")?;
                                let target = file.metadata()?;
                                if (current.dev(), current.ino()) != (target.dev(), target.ino())
                                    && unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) }
                                        != 0
                                {
                                    return Err(std::io::Error::last_os_error().into());
                                }
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                let _ = file;
                                anyhow::bail!("network namespace workers require Linux");
                            }
                        }
                        let run = prepare()?;
                        ctx.update(|s| {
                            s["state"] = json!("running");
                            s["started_at"] = json!(now());
                        });
                        let _ = ready_tx.send(Ok::<(), String>(()));
                        run(ctx.clone())
                    }))
                    .unwrap_or_else(|_| Err(anyhow!("service worker panicked")));
                match result {
                    Ok(()) => ctx.update(|s| s["state"] = json!("stopped")),
                    Err(error) => {
                        let text = format!("{error:#}");
                        let _ = ready_tx.send(Err(text.clone()));
                        ctx.update(|s| {
                            s["state"] = json!("error");
                            s["error"] = json!(text);
                        });
                    }
                }
                let _ = done_tx.send(());
            })
            .context("start native service thread")?;
        let mut worker = Self {
            name,
            context,
            join: Some(join),
            done,
        };
        match ready_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(())) => Ok(worker),
            other => {
                worker
                    .context
                    .stop
                    .store(true, std::sync::atomic::Ordering::Release);
                worker.shutdown()?;
                Err(anyhow!("service startup failed: {other:?}"))
            }
        }
    }
    pub fn snapshot(&self) -> Value {
        self.context
            .status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| json!({"state":"error","error":"status lock poisoned"}))
    }
    pub fn shutdown(&mut self) -> Result<()> {
        self.context
            .stop
            .store(true, std::sync::atomic::Ordering::Release);
        if self.join.is_some() {
            self.done
                .recv_timeout(Duration::from_secs(10))
                .map_err(|e| anyhow!("{} worker stop timeout: {e}", self.name))?;
            if let Some(h) = self.join.take() {
                h.join()
                    .map_err(|_| anyhow!("{} thread join failed", self.name))?;
            }
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.context
            .stop
            .store(true, std::sync::atomic::Ordering::Release);
        // All workers use bounded nonblocking I/O. Never detach an owned thread.
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_stop_and_error_status_without_process_ids() {
        let mut w = Worker::start(
            "test-loop".into(),
            None,
            json!({"name":"test-loop"}),
            || {
                Ok(Box::new(|ctx| {
                    while !ctx.wait(Duration::from_millis(20)) {}
                    Ok(())
                }))
            },
        )
        .unwrap();
        assert_eq!(w.snapshot()["state"], "running");
        assert!(w.snapshot().get("pid").is_none());
        let start = Instant::now();
        w.shutdown().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(w.snapshot()["state"], "stopped");
        w.shutdown().unwrap();
        let mut failed = Worker::start("test-error".into(), None, json!({}), || {
            Ok(Box::new(|_| Err(anyhow!("injected native I/O failure"))))
        })
        .unwrap();
        for _ in 0..100 {
            if failed.snapshot()["state"] == "error" {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(failed.snapshot()["state"], "error");
        assert!(
            failed.snapshot()["error"]
                .as_str()
                .unwrap()
                .contains("injected")
        );
        failed.shutdown().unwrap();
    }
    #[test]
    fn startup_failure_and_panics_are_joined() {
        assert!(
            Worker::start("prepare-failure".into(), None, json!({}), || Err(anyhow!(
                "missing privilege"
            )))
            .is_err()
        );
        assert!(
            Worker::start("prepare-panic".into(), None, json!({}), || panic!(
                "injected startup panic"
            ))
            .is_err()
        );
    }
}
