use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::watch;

pub struct Control {
    requested: watch::Sender<u64>,
    active: AtomicBool,
    status: Mutex<Value>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            requested: watch::Sender::new(0),
            active: AtomicBool::new(false),
            status: Mutex::new(json!({"state":"stopped","error":null})),
        }
    }
}

impl Control {
    pub fn status(&self) -> Result<Value> {
        Ok(self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("process status unavailable"))?
            .clone())
    }
    fn state(&self, state: &str, error: Option<String>) -> Result<()> {
        *self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("process status unavailable"))? =
            json!({"state":state,"error":error,"generation":*self.requested.borrow()});
        Ok(())
    }
    pub fn request(&self) -> Result<u64> {
        ensure!(
            self.active.load(Ordering::Acquire),
            "managed task is not running"
        );
        let next = self
            .requested
            .borrow()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("restart generation exhausted"))?;
        self.requested
            .send(next)
            .map_err(|_| anyhow::anyhow!("managed task is unavailable"))?;
        Ok(next)
    }

    pub async fn run<F, Fut>(&self, mut stop: watch::Receiver<bool>, mut start: F) -> Result<()>
    where
        F: FnMut(watch::Receiver<bool>) -> Fut,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        struct Active<'a>(&'a AtomicBool);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let mut restart = self.requested.subscribe();
        self.active.store(true, Ordering::Release);
        let _active = Active(&self.active);
        loop {
            if *stop.borrow() {
                self.state("stopped", None)?;
                return Ok(());
            }
            let (local_stop, receiver) = watch::channel(false);
            struct Task<T>(tokio::task::JoinHandle<T>);
            impl<T> Drop for Task<T> {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let mut task = Task(tokio::spawn(start(receiver)));
            self.state("running", None)?;
            let (stopping, joined) = tokio::select! {
                result = &mut task.0 => {
                    let error=match result {
                        Ok(Ok(()))=>"managed task stopped unexpectedly".to_string(),
                        Ok(Err(error))=>format!("{error:#}"),
                        Err(error)=>format!("managed task failed: {error}"),
                    };
                    tracing::error!(%error,"managed process stopped; explicit restart remains available");
                    self.state("error",Some(error))?;
                    let stopping=tokio::select! {
                        _=stop.changed()=>true,
                        _=restart.changed()=>false,
                    };
                    (stopping,true)
                },
                _ = stop.changed() => (true,false),
                _ = restart.changed() => (false,false),
            };
            if !joined {
                // A concurrent exit is observed by the join below, never detached.
                let _ = local_stop.send(true);
                self.state("restarting", None)?;
                match (&mut task.0).await {
                    Ok(Ok(())) => {}
                    result => {
                        let error = format!("managed task stop failed: {result:?}");
                        tracing::error!(%error,"managed process shutdown failed");
                        self.state("error", Some(error))?;
                    }
                }
            }
            if stopping || *stop.borrow() {
                self.state("stopped", None)?;
                return Ok(());
            }
            restart.borrow_and_update();
        }
    }
}

pub fn reply(target: &str, generation: u64) -> Value {
    json!({"target":target,"status":"restart_requested","generation":generation})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicUsize};
    use std::time::Duration;

    #[tokio::test]
    async fn failed_and_panicked_managers_remain_restartable() {
        let control = Arc::new(Control::default());
        let starts = Arc::new(AtomicUsize::new(0));
        let (stop, receiver) = watch::channel(false);
        let task = {
            let control = control.clone();
            let starts = starts.clone();
            tokio::spawn(async move {
                control
                    .run(receiver, move |mut stop| {
                        let attempt = starts.fetch_add(1, Ordering::SeqCst);
                        async move {
                            match attempt {
                                0 => anyhow::bail!("synthetic manager failure"),
                                1 => panic!("synthetic manager panic"),
                                _ => {
                                    if !*stop.borrow() {
                                        stop.changed().await?;
                                    }
                                    Ok(())
                                }
                            }
                        }
                    })
                    .await
            })
        };
        for expected in 1..=2 {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if starts.load(Ordering::SeqCst) == expected
                        && control.status().unwrap()["state"] == "error"
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(control.status().unwrap()["error"].is_string());
            control.request().unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while starts.load(Ordering::SeqCst) != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert!(control.request().is_err());
    }

    #[tokio::test]
    async fn restart_joins_previous_attempt_and_shutdown_prevents_another_start() {
        let control = Arc::new(Control::default());
        assert!(control.request().is_err());
        let starts = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let (stop, receiver) = watch::channel(false);
        let worker = {
            let control = control.clone();
            let starts = starts.clone();
            let active = active.clone();
            tokio::spawn(async move {
                control
                    .run(receiver, move |mut stop| {
                        let starts = starts.clone();
                        let active = active.clone();
                        async move {
                            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                            starts.fetch_add(1, Ordering::SeqCst);
                            if !*stop.borrow() {
                                stop.changed().await.unwrap();
                            }
                            active.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        }
                    })
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while starts.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
            control.request().unwrap();
            while starts.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(control.request().is_err());
        assert_eq!(starts.load(Ordering::SeqCst), 2);
    }
}
