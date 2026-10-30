use super::{read_json, session, wireguard, write_json};
use anyhow::{Context, Result, anyhow, ensure};
use netcontrol_core::WireGuardEndpoint;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wireguard_control::{Backend, Device, DeviceUpdate, Key, PeerConfigBuilder};

type Resolver = Arc<dyn Fn(&str, u16, bool) -> Result<Vec<SocketAddr>> + Send + Sync>;
const INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    endpoint: String,
    ipv6_enabled: bool,
    resolved_endpoint: SocketAddr,
    last_attempt_unix_ms: u64,
    last_success_unix_ms: u64,
    error: Option<String>,
}

fn key(endpoint: &str, ipv6_enabled: bool) -> String {
    format!("{ipv6_enabled}/{endpoint}")
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn select(
    mut addresses: Vec<SocketAddr>,
    current: Option<SocketAddr>,
    port: u16,
    ipv6: bool,
) -> Result<SocketAddr> {
    addresses.retain(|address| {
        address.port() == port
            && (ipv6 || address.is_ipv4())
            && matches!(
                WireGuardEndpoint::parse(&address.to_string()),
                Ok(Some(WireGuardEndpoint::Numeric(_)))
            )
    });
    addresses.sort_unstable();
    addresses.dedup();
    if let Some(current) = current.filter(|address| addresses.contains(address)) {
        return Ok(current);
    }
    addresses
        .into_iter()
        .next()
        .context("WireGuard DNS returned no usable address for the enabled IP families")
}

#[derive(Clone)]
pub(super) struct Cache {
    path: PathBuf,
    entries: Arc<Mutex<BTreeMap<String, Entry>>>,
    resolver: Resolver,
}

impl Cache {
    pub fn new(path: PathBuf) -> Result<Self> {
        let mut entries = BTreeMap::new();
        if path.try_exists()? {
            for entry in read_json::<Vec<Entry>>(&path)? {
                let Some(WireGuardEndpoint::Dns { port, .. }) =
                    WireGuardEndpoint::parse(&entry.endpoint)?
                else {
                    anyhow::bail!("invalid cached WireGuard DNS name");
                };
                select(
                    vec![entry.resolved_endpoint],
                    None,
                    port,
                    entry.ipv6_enabled,
                )?;
                ensure!(
                    entries
                        .insert(key(&entry.endpoint, entry.ipv6_enabled), entry)
                        .is_none(),
                    "duplicate cached WireGuard DNS endpoint"
                );
            }
        }
        Ok(Self {
            path,
            entries: Arc::new(Mutex::new(entries)),
            resolver: Arc::new(netcontrol_services::resolve_addresses),
        })
    }

    fn save(&self, entries: &BTreeMap<String, Entry>) -> Result<()> {
        write_json(&self.path, &entries.values().collect::<Vec<_>>())
    }

    pub fn resolve(&self, endpoint: &str, ipv6: bool) -> Result<SocketAddr> {
        let cache_key = key(endpoint, ipv6);
        if let Some(entry) = self
            .entries
            .lock()
            .map_err(|_| anyhow!("WireGuard DNS cache poisoned"))?
            .get(&cache_key)
        {
            return Ok(entry.resolved_endpoint);
        }
        let Some(WireGuardEndpoint::Dns { host, port }) = WireGuardEndpoint::parse(endpoint)?
        else {
            anyhow::bail!("expected a WireGuard DNS endpoint");
        };
        let address = select((self.resolver)(&host, port, ipv6)?, None, port, ipv6)
            .with_context(|| format!("resolve WireGuard endpoint {endpoint}"))?;
        let timestamp = now()?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("WireGuard DNS cache poisoned"))?;
        if let Some(entry) = entries.get(&cache_key) {
            return Ok(entry.resolved_endpoint);
        }
        entries.insert(
            cache_key.clone(),
            Entry {
                endpoint: endpoint.into(),
                ipv6_enabled: ipv6,
                resolved_endpoint: address,
                last_attempt_unix_ms: timestamp,
                last_success_unix_ms: timestamp,
                error: None,
            },
        );
        if let Err(error) = self.save(&entries) {
            entries.remove(&cache_key);
            return Err(error.context("persist initial WireGuard DNS resolution"));
        }
        Ok(address)
    }

    fn refresh(
        &self,
        target: &Target,
        stop: &AtomicBool,
        update: impl FnOnce(SocketAddr) -> Result<()>,
    ) -> Result<()> {
        let Some(WireGuardEndpoint::Dns { host, port }) =
            WireGuardEndpoint::parse(&target.endpoint)?
        else {
            anyhow::bail!("expected a WireGuard DNS endpoint");
        };
        let cache_key = key(&target.endpoint, target.ipv6);
        let old = self
            .entries
            .lock()
            .map_err(|_| anyhow!("WireGuard DNS cache poisoned"))?
            .get(&cache_key)
            .context("WireGuard DNS cache entry missing")?
            .clone();
        let timestamp = now()?;
        let result = (self.resolver)(&host, port, target.ipv6).and_then(|addresses| {
            select(addresses, Some(old.resolved_endpoint), port, target.ipv6)
        });
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut entry = old;
        entry.last_attempt_unix_ms = timestamp;
        let result = result.and_then(|address| {
            update(address)?;
            entry.resolved_endpoint = address;
            entry.last_success_unix_ms = timestamp;
            Ok(())
        });
        entry.error = result.err().map(|error| format!("{error:#}"));
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("WireGuard DNS cache poisoned"))?;
        entries.insert(cache_key, entry);
        self.save(&entries).context("persist WireGuard DNS refresh")
    }

    #[cfg(test)]
    pub fn set_resolver(&mut self, resolver: Resolver) {
        self.resolver = resolver;
    }
}

#[derive(Clone)]
struct Target {
    endpoint: String,
    ipv6: bool,
    peers: Vec<(String, String, String)>,
}

pub(super) struct Manager {
    pub control: wireguard::Control,
    namespace: Arc<File>,
    targets: Vec<Target>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
    error: Arc<Mutex<Option<String>>>,
}

impl Manager {
    pub fn new(namespace: Arc<File>, keys: PathBuf, path: PathBuf) -> Result<Self> {
        Ok(Self {
            control: wireguard::Control {
                keys,
                dns: Cache::new(path)?,
            },
            namespace,
            targets: vec![],
            stop: Arc::new(AtomicBool::new(false)),
            join: None,
            error: Arc::new(Mutex::new(None)),
        })
    }

    pub fn configure(&mut self, config: &Value) -> Result<()> {
        self.start(config, INTERVAL)
    }

    fn start(&mut self, config: &Value, interval: Duration) -> Result<()> {
        self.shutdown()?;
        let network = crate::model::Network::parse(config)?;
        let mut targets = BTreeMap::<String, Target>::new();
        for link in &network.interfaces {
            if let Some(wg) = &link.wireguard {
                for peer in wg["peers"].as_array().context("WireGuard peers missing")? {
                    let endpoint = match peer.get("endpoint") {
                        None => "",
                        Some(value) => value.as_str().context("invalid WireGuard endpoint")?,
                    };
                    if matches!(
                        WireGuardEndpoint::parse(endpoint)?,
                        Some(WireGuardEndpoint::Dns { .. })
                    ) {
                        self.control.dns.resolve(endpoint, network.ipv6_enabled)?;
                        targets
                            .entry(key(endpoint, network.ipv6_enabled))
                            .or_insert_with(|| Target {
                                endpoint: endpoint.into(),
                                ipv6: network.ipv6_enabled,
                                peers: vec![],
                            })
                            .peers
                            .push((
                                link.name.clone(),
                                peer["public_key"]
                                    .as_str()
                                    .context("peer public key missing")?
                                    .into(),
                                wireguard::public_key(
                                    &self.control.keys,
                                    wg["key_ref"]
                                        .as_str()
                                        .context("WireGuard key reference missing")?,
                                )?,
                            ));
                    }
                }
            }
        }
        self.targets = targets.into_values().collect();
        if self.targets.is_empty() {
            return Ok(());
        }
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = self.stop.clone();
        let targets = self.targets.clone();
        let control = self.control.clone();
        let namespace = self.namespace.clone();
        let error = self.error.clone();
        self.join = Some(std::thread::Builder::new().name("nc-wg-dns".into()).spawn(
            move || {
                let result = (|| -> Result<()> {
                    while !stop.load(Ordering::Acquire) {
                        for target in &targets {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            session(namespace.clone(), {
                                let target = target.clone();
                                let control = control.clone();
                                let stop = stop.clone();
                                move |_, _| {
                                    control.dns.refresh(&target, &stop, |address| {
                                        for (name, public_key, device_key) in &target.peers {
                                            let name = name.parse()?;
                                            let public = Key::from_base64(public_key)?;
                                            let device = Device::get(&name, Backend::Kernel)?;
                                            crate::ensure_unchanged(
                                                device.public_key.as_ref().is_some_and(|key| {
                                                    key.to_base64() == *device_key
                                                }),
                                                "WireGuard DNS device identity drift",
                                            )?;
                                            let peer = device
                                                .peers
                                                .iter()
                                                .find(|peer| peer.config.public_key == public)
                                                .context("WireGuard DNS peer was removed")?;
                                            if peer.config.endpoint != Some(address) {
                                                DeviceUpdate::new()
                                                    .add_peer(
                                                        PeerConfigBuilder::new(&public)
                                                            .set_endpoint(address),
                                                    )
                                                    .apply(&name, Backend::Kernel)?;
                                            }
                                        }
                                        Ok(())
                                    })
                                }
                            })?;
                        }
                        let deadline = Instant::now() + interval;
                        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(50).min(interval));
                        }
                    }
                    Ok(())
                })();
                if let Err(failure) = &result {
                    *error
                        .lock()
                        .map_err(|_| anyhow!("WireGuard DNS status poisoned"))? =
                        Some(format!("{failure:#}"));
                    eprintln!("WireGuard DNS worker failed: {failure:#}");
                }
                result
            },
        )?);
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Value> {
        let entries = self
            .control
            .dns
            .entries
            .lock()
            .map_err(|_| anyhow!("WireGuard DNS cache poisoned"))?;
        let mut peers = Vec::new();
        for target in &self.targets {
            let entry = entries
                .get(&key(&target.endpoint, target.ipv6))
                .context("WireGuard DNS cache entry missing")?;
            for (name, public_key, _) in &target.peers {
                let mut row = serde_json::to_value(entry)?;
                row["interface"] = json!(name);
                row["public_key"] = json!(public_key);
                peers.push(row);
            }
        }
        Ok(
            json!({"running":self.join.as_ref().is_some_and(|join| !join.is_finished()),
            "refresh_interval_seconds":INTERVAL.as_secs(), "peers":peers,
            "error":*self.error.lock().map_err(|_| anyhow!("WireGuard DNS status poisoned"))?}),
        )
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = &self.join {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !join.is_finished() {
                ensure!(
                    Instant::now() < deadline,
                    "WireGuard DNS shutdown timed out; ownership retained"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            self.join
                .take()
                .unwrap()
                .join()
                .map_err(|_| anyhow!("WireGuard DNS worker panicked"))??;
        }
        self.targets.clear();
        *self
            .error
            .lock()
            .map_err(|_| anyhow!("WireGuard DNS status poisoned"))? = None;
        Ok(())
    }

    #[cfg(test)]
    pub fn configure_for_test(&mut self, config: &Value, interval: Duration) -> Result<()> {
        self.start(config, interval)
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            eprintln!("WireGuard DNS shutdown failed: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".native-wg-dns-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn dns_address_selection_is_stable_family_safe_and_deterministic() {
        let addresses = ["[2001:db8::2]:51820", "192.0.2.2:51820", "192.0.2.1:51820"]
            .map(|address| address.parse().unwrap())
            .to_vec();
        assert_eq!(
            select(addresses.clone(), None, 51820, true).unwrap(),
            "192.0.2.1:51820".parse().unwrap()
        );
        assert_eq!(
            select(addresses.clone(), Some(addresses[0]), 51820, true).unwrap(),
            addresses[0]
        );
        assert_eq!(
            select(addresses.clone(), Some(addresses[0]), 51820, false).unwrap(),
            addresses[2]
        );
        for invalid in [
            "[2001:db8::2]:51820",
            "0.0.0.0:51820",
            "224.0.0.1:51820",
            "192.0.2.1:1",
        ] {
            assert!(select(vec![invalid.parse().unwrap()], None, 51820, false).is_err());
        }
    }

    #[test]
    fn dns_cache_refresh_persists_last_good_retains_errors_and_honors_shutdown() {
        let fixture = Fixture::new();
        let path = fixture.0.join("dns.json");
        let mut cache = Cache::new(path.clone()).unwrap();
        cache.set_resolver(Arc::new(|_, port, _| {
            Ok(vec![SocketAddr::new("192.0.2.1".parse().unwrap(), port)])
        }));
        assert_eq!(
            cache.resolve("vpn.example.test:51820", false).unwrap(),
            "192.0.2.1:51820".parse().unwrap()
        );
        let target = Target {
            endpoint: "vpn.example.test:51820".into(),
            ipv6: false,
            peers: vec![],
        };
        let stop = AtomicBool::new(false);
        cache.set_resolver(Arc::new(|_, port, _| {
            Ok(vec![SocketAddr::new("192.0.2.2".parse().unwrap(), port)])
        }));
        let mut updated = None;
        cache
            .refresh(&target, &stop, |address| {
                updated = Some(address);
                Ok(())
            })
            .unwrap();
        assert_eq!(updated, Some("192.0.2.2:51820".parse().unwrap()));
        cache.set_resolver(Arc::new(|_, _, _| Err(anyhow!("synthetic DNS failure"))));
        cache
            .refresh(&target, &stop, |_| {
                panic!("failed resolution must not mutate the kernel")
            })
            .unwrap();
        let entries = cache.entries.lock().unwrap();
        let entry = entries.values().next().unwrap();
        assert!(
            entry
                .error
                .as_ref()
                .unwrap()
                .contains("synthetic DNS failure")
        );
        assert_eq!(entry.resolved_endpoint, updated.unwrap());
        drop(entries);
        let mut reopened = Cache::new(path).unwrap();
        reopened.set_resolver(Arc::new(|_, _, _| Err(anyhow!("offline"))));
        assert_eq!(
            reopened.resolve(&target.endpoint, false).unwrap(),
            updated.unwrap()
        );
        cache.set_resolver(Arc::new(|_, port, _| {
            Ok(vec![SocketAddr::new("192.0.2.3".parse().unwrap(), port)])
        }));
        stop.store(true, Ordering::Release);
        cache
            .refresh(&target, &stop, |_| {
                panic!("shutdown must prevent late mutation")
            })
            .unwrap();
        assert_eq!(
            cache.resolve(&target.endpoint, false).unwrap(),
            updated.unwrap()
        );
        stop.store(false, Ordering::Release);
        cache
            .refresh(&target, &stop, |_| Err(anyhow!("synthetic kernel failure")))
            .unwrap();
        assert_eq!(
            cache.resolve(&target.endpoint, false).unwrap(),
            updated.unwrap()
        );
        assert!(
            cache
                .entries
                .lock()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .error
                .as_ref()
                .unwrap()
                .contains("kernel failure")
        );
    }
}
