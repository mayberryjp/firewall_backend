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
    namespace: Option<Arc<std::fs::File>>,
    initial: Value,
    prepare: Arc<Mutex<Prepare>>,
}
type Prepare =
    Box<dyn FnMut() -> Result<Box<dyn FnOnce(ContextState) -> Result<()> + Send>> + Send>;
impl Worker {
    pub fn start(
        name: String,
        namespace: Option<Arc<std::fs::File>>,
        initial: Value,
        prepare: impl FnMut() -> Result<Box<dyn FnOnce(ContextState) -> Result<()> + Send>>
        + Send
        + 'static,
    ) -> Result<Self> {
        Self::start_shared(
            name,
            namespace,
            initial,
            Arc::new(Mutex::new(Box::new(prepare))),
        )
    }
    fn start_shared(
        name: String,
        namespace: Option<Arc<std::fs::File>>,
        initial: Value,
        prepare: Arc<Mutex<Prepare>>,
    ) -> Result<Self> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done) = mpsc::sync_channel(1);
        let context = ContextState {
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            status: Arc::new(Mutex::new(initial.clone())),
        };
        let ctx = context.clone();
        let worker_namespace = namespace.clone();
        let worker_prepare = prepare.clone();
        let join = thread::Builder::new()
            .name(format!("nc-{name}"))
            .spawn(move || {
                let mut delay = Duration::from_secs(1);
                let mut restart_count = 0u64;
                while !ctx.stopping() {
                    let attempt = Instant::now();
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                            if let Some(file) = &worker_namespace {
                                #[cfg(target_os = "linux")]
                                {
                                    use std::os::fd::AsRawFd;
                                    use std::os::unix::fs::MetadataExt;
                                    let current = std::fs::metadata("/proc/thread-self/ns/net")?;
                                    let target = file.metadata()?;
                                    if (current.dev(), current.ino())
                                        != (target.dev(), target.ino())
                                        && unsafe {
                                            libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET)
                                        } != 0
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
                            let run = {
                                let mut prepare = worker_prepare
                                    .lock()
                                    .map_err(|_| anyhow!("worker preparation lock poisoned"))?;
                                // Catch preparation panics before dropping the factory guard,
                                // so the reusable factory remains available for recovery.
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                    &mut *prepare,
                                ))
                                .unwrap_or_else(|_| {
                                    Err(anyhow!("service worker preparation panicked"))
                                })?
                            };
                            ctx.update(|s| {
                                s["state"] = json!("running");
                                s["started_at"] = json!(now());
                                s["retrying"] = json!(false);
                                s["restart_count"] = json!(restart_count);
                                if s.get("sample_status").is_some() {
                                    s["sample_status"] = json!("warming_up");
                                }
                                s.as_object_mut().unwrap().remove("error");
                            });
                            let _ = ready_tx.send(Ok::<(), String>(()));
                            run(ctx.clone())
                        }))
                        .unwrap_or_else(|_| Err(anyhow!("service worker panicked")));
                    if ctx.stopping() {
                        break;
                    }
                    let text = match result {
                        Ok(()) => "service worker exited unexpectedly".to_owned(),
                        Err(error) => format!("{error:#}"),
                    };
                    restart_count = restart_count.saturating_add(1);
                    ctx.update(|s| {
                        s["state"] = json!("error");
                        s["error"] = json!(text);
                        s["last_error"] = json!(text);
                        s["retrying"] = json!(true);
                        s["restart_count"] = json!(restart_count);
                        if s.get("sample_status").is_some() {
                            s["sample_status"] = json!("unavailable");
                        }
                    });
                    let _ = ready_tx.try_send(Ok::<(), String>(()));
                    if attempt.elapsed() >= Duration::from_secs(60) {
                        delay = Duration::from_secs(1);
                    }
                    if ctx.wait(delay) {
                        break;
                    }
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
                ctx.update(|s| {
                    s["state"] = json!("stopped");
                    s["retrying"] = json!(false);
                });
                let _ = done_tx.send(());
            })
            .context("start native service thread")?;
        let mut worker = Self {
            name,
            context,
            join: Some(join),
            done,
            namespace,
            initial,
            prepare,
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
    pub fn restart(&mut self) -> Result<()> {
        self.shutdown()?;
        *self = Self::start_shared(
            self.name.clone(),
            self.namespace.clone(),
            self.initial.clone(),
            self.prepare.clone(),
        )?;
        Ok(())
    }
    pub fn snapshot(&self) -> Value {
        self.context
            .status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| json!({"state":"error","error":"status lock poisoned"}))
    }
    pub fn active(&self) -> bool {
        !self.context.stopping() && self.join.as_ref().is_some_and(|join| !join.is_finished())
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
    fn forced_restart_reuses_factory_and_joins_the_previous_attempt() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let prepared = Arc::new(AtomicUsize::new(0));
        let count = prepared.clone();
        let mut worker = Worker::start(
            "restart-test".into(),
            None,
            json!({"name":"restart-test"}),
            move || {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(|ctx| {
                    while !ctx.wait(Duration::from_millis(5)) {}
                    Ok(())
                }))
            },
        )
        .unwrap();
        let old = worker.context.clone();
        worker.restart().unwrap();
        assert!(old.stopping());
        assert_eq!(old.status.lock().unwrap()["state"], "stopped");
        assert_eq!(prepared.load(Ordering::SeqCst), 2);
        assert!(worker.active());
        worker.shutdown().unwrap();
    }

    #[test]
    fn preparation_panic_does_not_poison_recovery_or_forced_restart() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let prepared = Arc::new(AtomicUsize::new(0));
        let count = prepared.clone();
        let mut worker = Worker::start("prepare-panic".into(), None, json!({}), move || {
            assert_ne!(
                count.fetch_add(1, Ordering::SeqCst),
                0,
                "synthetic preparation panic"
            );
            Ok(Box::new(|ctx| {
                while !ctx.wait(Duration::from_millis(5)) {}
                Ok(())
            }))
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while worker.snapshot()["state"] != "running" {
            assert!(Instant::now() < deadline, "{}", worker.snapshot());
            thread::sleep(Duration::from_millis(10));
        }
        worker.restart().unwrap();
        assert_eq!(prepared.load(Ordering::SeqCst), 3);
        worker.shutdown().unwrap();
    }

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
    fn startup_failure_and_panics_keep_retrying_until_shutdown() {
        for mut worker in [
            Worker::start("prepare-failure".into(), None, json!({}), || {
                Err(anyhow!("missing privilege"))
            })
            .unwrap(),
            Worker::start("prepare-panic".into(), None, json!({}), || {
                panic!("injected startup panic")
            })
            .unwrap(),
        ] {
            assert!(worker.active());
            assert_eq!(worker.snapshot()["state"], "error");
            assert_eq!(worker.snapshot()["retrying"], true);
            let start = Instant::now();
            worker.shutdown().unwrap();
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(!worker.active());
            assert_eq!(worker.snapshot()["state"], "stopped");
        }
    }
    #[test]
    fn runtime_failure_reopens_resources_and_recovers_without_operator_action() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = attempts.clone();
        let mut worker = Worker::start("recovery".into(), None, json!({}), move || {
            let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(move |ctx| {
                if attempt == 0 {
                    return Err(anyhow!("injected connectivity failure"));
                }
                while !ctx.wait(Duration::from_millis(20)) {}
                Ok(())
            }))
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while observed.load(std::sync::atomic::Ordering::SeqCst) < 2
            || worker.snapshot()["state"] != "running"
        {
            assert!(Instant::now() < deadline, "worker did not recover");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(worker.snapshot()["retrying"], false);
        assert_eq!(worker.snapshot()["restart_count"], 1);
        assert!(worker.snapshot().get("error").is_none());
        assert_eq!(
            worker.snapshot()["last_error"],
            "injected connectivity failure"
        );
        worker.shutdown().unwrap();
    }
}
