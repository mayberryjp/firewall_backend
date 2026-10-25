use crate::private_store::{identifier, private_file, read_private, valid_id, write_new_private};
use anyhow::{Context, Result, ensure};
use netcontrol_core::{DynamicDNSAddressSource, DynamicDNSConfig, Engine};
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use zeroize::Zeroizing;

struct Secrets {
    root: PathBuf,
    _lock: File,
}

impl Secrets {
    fn open(root: &Path) -> Result<Self> {
        crate::identity::secure_parent(root)?;
        if !root.try_exists()? {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(root)?;
        }
        let metadata = fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "invalid Dynamic DNS private directory"
        );
        crate::identity::secure_parent(&root.join("lock"))?;
        let path = root.join("lock");
        let lock = private_file(&path, !path.try_exists()?)?;
        fs2::FileExt::try_lock_exclusive(&lock).context("Dynamic DNS store is already open")?;
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
        })
    }

    fn references(&self) -> Result<BTreeSet<String>> {
        let mut refs = BTreeSet::new();
        for entry in fs::read_dir(&self.root)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(reference) = name.strip_prefix("secret-") {
                self.get(reference)?;
                refs.insert(reference.to_owned());
            }
        }
        ensure!(
            refs.len() <= 256,
            "Dynamic DNS secret store exceeds 256 entries"
        );
        Ok(refs)
    }

    fn get(&self, reference: &str) -> Result<Zeroizing<String>> {
        ensure!(valid_id(reference), "invalid Dynamic DNS secret reference");
        let bytes = Zeroizing::new(read_private(
            &self.root.join(format!("secret-{reference}")),
        )?);
        let secret = Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned());
        validate_secret(&secret)?;
        Ok(secret)
    }

    fn create(&self, secret: &str) -> Result<String> {
        validate_secret(secret)?;
        ensure!(
            self.references()?.len() < 256,
            "Dynamic DNS secret store limit reached (256)"
        );
        let reference = identifier();
        write_new_private(
            &self.root.join(format!("secret-{reference}")),
            secret.as_bytes(),
        )?;
        Ok(reference)
    }
}

pub(crate) fn validate_secret(secret: &str) -> Result<()> {
    ensure!(
        !secret.is_empty() && secret.len() <= 4096 && !secret.contains('\0'),
        "client_secret must be 1..4096 UTF-8 bytes without NUL"
    );
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Native,
    Simulated,
    Unsupported,
}

#[derive(Clone, Serialize)]
struct EntryStatus {
    name: String,
    state: String,
    address: Option<Ipv4Addr>,
    last_checked_at_unix: Option<u64>,
    last_updated_at_unix: Option<u64>,
    error: Option<String>,
}

impl EntryStatus {
    fn new(config: &DynamicDNSConfig) -> Self {
        Self {
            name: config.name.clone(),
            state: if config.enabled {
                "waiting"
            } else {
                "disabled"
            }
            .into(),
            address: None,
            last_checked_at_unix: None,
            last_updated_at_unix: None,
            error: None,
        }
    }
}

pub struct Manager {
    secrets: Mutex<Secrets>,
    status: Mutex<BTreeMap<String, EntryStatus>>,
    engine: Arc<Mutex<Engine>>,
    mode: Mode,
}

impl Manager {
    pub fn open(root: &Path, engine: Arc<Mutex<Engine>>, mode: Mode) -> Result<Arc<Self>> {
        let secrets = Secrets::open(root)?;
        let refs = secrets.references()?;
        let status = {
            let mut engine = engine
                .lock()
                .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
            engine.configure_dynamic_dns(if mode == Mode::Unsupported {
                None
            } else {
                Some(refs)
            });
            engine
                .saved_configuration()
                .dynamic_dns
                .iter()
                .map(|entry| (entry.name.clone(), EntryStatus::new(entry)))
                .collect()
        };
        Ok(Arc::new(Self {
            secrets: Mutex::new(secrets),
            status: Mutex::new(status),
            engine,
            mode,
        }))
    }

    pub fn status(&self) -> Result<Value> {
        let status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("Dynamic DNS status unavailable"))?;
        Ok(json!({"entries":status.values().collect::<Vec<_>>()}))
    }

    pub fn create_secret(&self, engine: &mut Engine, secret: &str) -> Result<String> {
        let secrets = self
            .secrets
            .lock()
            .map_err(|_| anyhow::anyhow!("Dynamic DNS store unavailable"))?;
        let reference = secrets.create(secret)?;
        engine.configure_dynamic_dns(if self.mode == Mode::Unsupported {
            None
        } else {
            Some(secrets.references()?)
        });
        Ok(reference)
    }

    fn configuration(&self) -> Result<Option<Vec<DynamicDNSConfig>>> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?;
        Ok(
            (!engine.configuration_busy())
                .then(|| engine.saved_configuration().dynamic_dns.clone()),
        )
    }

    fn set_status(&self, name: &str, update: impl FnOnce(&mut EntryStatus)) -> Result<()> {
        let mut statuses = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("Dynamic DNS status unavailable"))?;
        if let Some(status) = statuses.get_mut(name) {
            update(status);
        }
        Ok(())
    }

    pub async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) -> Result<()> {
        let result = self.worker(stop).await;
        if let Err(error) = &result {
            tracing::error!(%error, "Dynamic DNS worker stopped");
        }
        result
    }

    async fn worker(&self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut previous = Vec::new();
        let mut due = BTreeMap::<String, Instant>::new();
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = tick.tick() => {}
            }
            if *stop.borrow() {
                break;
            }
            let Some(config) = self.configuration()? else {
                due.clear();
                let mut statuses = self
                    .status
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Dynamic DNS status unavailable"))?;
                for status in statuses.values_mut() {
                    status.state = "paused".into();
                }
                continue;
            };
            if previous != config {
                let mut statuses = self
                    .status
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Dynamic DNS status unavailable"))?;
                statuses.retain(|name, _| config.iter().any(|e| &e.name == name));
                due.retain(|name, _| config.iter().any(|e| &e.name == name));
                for entry in &config {
                    if !previous.contains(entry) {
                        statuses.insert(entry.name.clone(), EntryStatus::new(entry));
                        due.remove(&entry.name);
                    }
                }
                previous = config.clone();
            }
            for entry in &config {
                if !entry.enabled || self.mode != Mode::Native {
                    self.set_status(&entry.name, |s| {
                        s.state = if !entry.enabled {
                            "disabled"
                        } else if self.mode == Mode::Simulated {
                            "simulated"
                        } else {
                            "unavailable"
                        }
                        .into();
                        s.error = (entry.enabled && self.mode == Mode::Unsupported)
                            .then(|| "Dynamic DNS requires Linux host mode".into());
                    })?;
                    continue;
                }
                if due
                    .get(&entry.name)
                    .is_some_and(|time| *time > Instant::now())
                {
                    continue;
                }
                self.set_status(&entry.name, |s| {
                    s.state = "checking".into();
                    s.error = None;
                })?;
                let update = self.update(entry);
                tokio::pin!(update);
                let result = loop {
                    tokio::select! {
                        _ = stop.changed() => return Ok(()),
                        result = &mut update => break Some(result),
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            if self.configuration()?.as_ref() != Some(&config) { break None; }
                        }
                    }
                };
                let Some(result) = result else {
                    break;
                };
                due.insert(
                    entry.name.clone(),
                    Instant::now() + Duration::from_secs(entry.interval_seconds),
                );
                self.set_status(&entry.name, |s| {
                    s.last_checked_at_unix = Some(now());
                    match result {
                        Ok((address, changed)) => {
                            s.state = "current".into();
                            s.address = Some(address);
                            s.error = None;
                            if changed {
                                s.last_updated_at_unix = Some(now());
                            }
                        }
                        Err(error) => {
                            s.state = "error".into();
                            s.error = Some(error.to_string());
                        }
                    }
                })?;
            }
        }
        Ok(())
    }

    async fn update(&self, config: &DynamicDNSConfig) -> Result<(Ipv4Addr, bool)> {
        let source = interface_ipv4(&config.source_interface)?;
        let client = bound_client(config, source)?;
        let address = detect_address(
            &client,
            &config.address_source,
            source,
            "https://api.ipify.org",
        )
        .await?;
        let secret = self
            .secrets
            .lock()
            .map_err(|_| anyhow::anyhow!("Dynamic DNS store unavailable"))?
            .get(&config.secret_ref)
            .map_err(|_| {
                anyhow::anyhow!(
                    "Dynamic DNS secret unavailable; restore private credential storage"
                )
            })?;
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            config.tenant_id
        );
        let record_url = format!(
            "https://management.azure.com{}/A/{}?api-version=2018-05-01",
            config.zone_resource_id, config.record_name
        );
        let changed =
            azure_update(&client, &token_url, &record_url, config, &secret, address).await?;
        Ok((address, changed))
    }
}

async fn detect_address(
    client: &Client,
    mode: &DynamicDNSAddressSource,
    source: Ipv4Addr,
    detector: &str,
) -> Result<Ipv4Addr> {
    let address = match mode {
        DynamicDNSAddressSource::Interface => source,
        DynamicDNSAddressSource::PublicIp => {
            let response = client.get(detector).send().await.map_err(|_| {
                anyhow::anyhow!(
                    "public IPv4 detection failed; check selected interface, routing and TLS"
                )
            })?;
            ensure!(
                response.status().is_success(),
                "public IPv4 detection returned HTTP {}",
                response.status().as_u16()
            );
            let bytes = bounded_body(response, 64).await?;
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .context("public IPv4 detector returned an invalid address")?
        }
    };
    ensure!(
        public_ipv4(address),
        "detected IPv4 address is not publicly routable"
    );
    Ok(address)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

#[cfg(target_os = "linux")]
fn interface_ipv4(name: &str) -> Result<Ipv4Addr> {
    use std::ffi::CStr;
    let mut list = std::ptr::null_mut();
    ensure!(
        unsafe { libc::getifaddrs(&mut list) } == 0,
        "cannot enumerate source interface addresses"
    );
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Addresses(list);
    let mut addresses = BTreeSet::new();
    let mut current = list;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null()
            && unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() == name.as_bytes()
            && entry.ifa_flags & (libc::IFF_UP as u32) != 0
            && !entry.ifa_addr.is_null()
            && unsafe { (*entry.ifa_addr).sa_family } == libc::AF_INET as u16
        {
            let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local() {
                addresses.insert(ip);
            }
        }
        current = entry.ifa_next;
    }
    ensure!(
        addresses.len() == 1,
        "source interface must be up with exactly one usable IPv4 address; no fallback"
    );
    addresses
        .into_iter()
        .next()
        .context("source interface IPv4 address unavailable")
}

#[cfg(not(target_os = "linux"))]
fn interface_ipv4(_: &str) -> Result<Ipv4Addr> {
    anyhow::bail!("Dynamic DNS requires Linux host mode")
}

fn bound_client(config: &DynamicDNSConfig, source: Ipv4Addr) -> Result<Client> {
    let builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .local_address(std::net::IpAddr::V4(source));
    #[cfg(target_os = "linux")]
    let builder = builder.interface(&config.source_interface);
    #[cfg(not(target_os = "linux"))]
    let _ = config;
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("cannot initialize Dynamic DNS HTTPS client"))
}

async fn bounded_body(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("Dynamic DNS response read failed"))?
    {
        ensure!(
            body.len() + chunk.len() <= limit,
            "Dynamic DNS response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn json_body(response: Response) -> Result<Value> {
    let bytes = Zeroizing::new(bounded_body(response, 65536).await?);
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Azure returned invalid JSON"))
}

async fn azure_update(
    client: &Client,
    token_url: &str,
    record_url: &str,
    config: &DynamicDNSConfig,
    secret: &str,
    address: Ipv4Addr,
) -> Result<bool> {
    let response = client
        .post(token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &config.client_id),
            ("client_secret", secret),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Azure authentication connection failed; check interface, routing and TLS"
            )
        })?;
    ensure!(
        response.status().is_success(),
        "Azure authentication HTTP {}; check tenant, client ID and secret expiry",
        response.status().as_u16()
    );
    let mut token = json_body(response).await?;
    let Value::String(token) = token["access_token"].take() else {
        anyhow::bail!("Azure authentication omitted access_token");
    };
    let token = Zeroizing::new(token);
    ensure!(
        !token.is_empty() && token.len() <= 32768,
        "invalid Azure access token"
    );
    let response = client
        .get(record_url)
        .bearer_auth(&*token)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Azure record lookup connection failed"))?;
    let (mut properties, etag) = if response.status() == StatusCode::NOT_FOUND {
        (json!({}), None)
    } else {
        ensure!(
            response.status().is_success(),
            "Azure record lookup HTTP {}; check DNS Zone Contributor permission and zone ID",
            response.status().as_u16()
        );
        let value = json_body(response).await?;
        let etag = value["etag"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("Azure record lookup omitted etag")?
            .to_owned();
        let properties = value["properties"]
            .as_object()
            .context("Azure record lookup omitted properties")?;
        ensure!(
            properties
                .get("targetResource")
                .is_none_or(|v| v.is_null() || v.as_object().is_some_and(|o| o.is_empty())),
            "Azure alias records cannot be managed by Dynamic DNS"
        );
        let records = properties.get("ARecords").and_then(Value::as_array);
        ensure!(
            records.is_none_or(|r| r.len() <= 1),
            "Dynamic DNS refuses to replace a multi-address Azure A record set"
        );
        if records.is_some_and(|r| {
            r.len() == 1 && r[0]["ipv4Address"].as_str() == Some(&address.to_string())
        }) && properties.get("TTL").and_then(Value::as_u64)
            == Some(u64::from(config.ttl_seconds))
        {
            return Ok(false);
        }
        let mut owned = json!({});
        if let Some(metadata) = properties.get("metadata") {
            owned["metadata"] = metadata.clone();
        }
        (owned, Some(etag))
    };
    properties["TTL"] = json!(config.ttl_seconds);
    properties["ARecords"] = json!([{"ipv4Address":address.to_string()}]);
    let request = client
        .put(record_url)
        .bearer_auth(&*token)
        .json(&json!({"properties":properties}));
    let request = if let Some(etag) = etag {
        request.header(reqwest::header::IF_MATCH, etag)
    } else {
        request.header(reqwest::header::IF_NONE_MATCH, "*")
    };
    let response = request.send().await.map_err(|_| {
        anyhow::anyhow!(
            "Azure record update connection failed; outcome unknown, next check will reconcile"
        )
    })?;
    ensure!(
        matches!(response.status(), StatusCode::OK | StatusCode::CREATED),
        "Azure record update HTTP {}; check permissions, throttling or concurrent record changes",
        response.status().as_u16()
    );
    // A successful ARM response must describe the requested record, not merely acknowledge HTTP.
    let result = json_body(response).await?;
    ensure!(
        result["properties"]["TTL"].as_u64() == Some(u64::from(config.ttl_seconds))
            && result["properties"]["ARecords"].as_array().is_some_and(
                |r| r.len() == 1 && r[0]["ipv4Address"].as_str() == Some(&address.to_string())
            ),
        "Azure update response did not confirm the requested A record"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{App, Authentication, Credential};
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::{Request, State},
        response::IntoResponse,
        routing::any,
    };
    use tower::ServiceExt;

    fn entry() -> DynamicDNSConfig {
        serde_json::from_value(json!({
            "name":"azure-wan", "enabled":true, "source_interface":"wan0", "address_source":"public_ip",
            "tenant_id":"11111111-1111-4111-8111-111111111111",
            "client_id":"22222222-2222-4222-8222-222222222222",
            "secret_ref":"0123456789abcdef0123456789abcdef",
            "zone_resource_id":"/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com",
            "record_name":"home","ttl_seconds":300,"interval_seconds":60
        })).unwrap()
    }

    #[tokio::test]
    async fn dynamic_dns_direct_and_nat_detection_fail_closed() {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        assert_eq!(
            detect_address(
                &client,
                &DynamicDNSAddressSource::Interface,
                "8.8.4.4".parse().unwrap(),
                "invalid://not-used"
            )
            .await
            .unwrap(),
            "8.8.4.4".parse::<Ipv4Addr>().unwrap()
        );
        assert!(
            detect_address(
                &client,
                &DynamicDNSAddressSource::Interface,
                "192.168.1.2".parse().unwrap(),
                "invalid://not-used"
            )
            .await
            .is_err()
        );
        for (status, body, valid) in [
            (200, "8.8.4.4\n".to_owned(), true),
            (200, "192.168.1.1".to_owned(), false),
            (200, "2001:db8::1".to_owned(), false),
            (200, "<html>invalid</html>".to_owned(), false),
            (200, "8".repeat(65), false),
            (503, "provider unavailable".to_owned(), false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let router =
                Router::new().route(
                    "/",
                    any(move || async move {
                        (axum::http::StatusCode::from_u16(status).unwrap(), body)
                    }),
                );
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let result = detect_address(
                &client,
                &DynamicDNSAddressSource::PublicIp,
                "192.168.1.2".parse().unwrap(),
                &url,
            )
            .await;
            assert_eq!(result.is_ok(), valid);
            if let Ok(address) = result {
                assert_eq!(address, "8.8.4.4".parse::<Ipv4Addr>().unwrap());
            }
            server.abort();
            let _ = server.await;
        }
        #[cfg(target_os = "linux")]
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = entry();
            config.source_interface = "ddns-missing0".into();
            let client = bound_client(&config, Ipv4Addr::LOCALHOST).unwrap();
            assert!(
                client
                    .get(format!("http://{}", listener.local_addr().unwrap()))
                    .send()
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        }
    }

    struct AzureFixture {
        record: Option<Value>,
        token_status: u16,
        put_status: u16,
        writes: Vec<(Option<String>, Option<String>, Value)>,
        form: String,
    }

    async fn fixture(
        State(state): State<Arc<Mutex<AzureFixture>>>,
        request: Request,
    ) -> axum::response::Response {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 65536).await.unwrap();
        let mut state = state.lock().unwrap();
        let response = if parts.uri.path() == "/token" {
            state.form = String::from_utf8(body.to_vec()).unwrap();
            (
                state.token_status,
                json!({"access_token":"synthetic-access-token","error_description":"synthetic+secret&value"}),
            )
        } else {
            assert_eq!(
                parts.headers["authorization"],
                "Bearer synthetic-access-token"
            );
            if parts.method == "GET" {
                if let Some(record) = &state.record {
                    (200, record.clone())
                } else {
                    (404, json!({}))
                }
            } else {
                assert_eq!(parts.method, "PUT");
                let value: Value = serde_json::from_slice(&body).unwrap();
                state.writes.push((
                    parts
                        .headers
                        .get("if-match")
                        .map(|v| v.to_str().unwrap().to_owned()),
                    parts
                        .headers
                        .get("if-none-match")
                        .map(|v| v.to_str().unwrap().to_owned()),
                    value.clone(),
                ));
                (state.put_status, value)
            }
        };
        (
            axum::http::StatusCode::from_u16(response.0).unwrap(),
            axum::Json(response.1),
        )
            .into_response()
    }

    async fn azure_case(
        record: Option<Value>,
        token_status: u16,
        put_status: u16,
    ) -> (Result<bool>, AzureFixture) {
        let state = Arc::new(Mutex::new(AzureFixture {
            record,
            token_status,
            put_status,
            writes: Vec::new(),
            form: String::new(),
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/token", any(fixture))
            .route("/record", any(fixture))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let result = azure_update(
            &Client::builder().no_proxy().build().unwrap(),
            &format!("{url}/token"),
            &format!("{url}/record"),
            &entry(),
            "synthetic+secret&value",
            Ipv4Addr::new(8, 8, 4, 4),
        )
        .await;
        server.abort();
        let _ = server.await;
        let state = Arc::try_unwrap(state).ok().unwrap().into_inner().unwrap();
        (result, state)
    }

    #[tokio::test]
    async fn dynamic_dns_azure_create_update_cache_and_concurrency() {
        let (result, state) = azure_case(None, 200, 201).await;
        assert!(result.unwrap());
        assert!(
            state
                .form
                .contains("client_secret=synthetic%2Bsecret%26value")
        );
        assert!(
            state
                .form
                .contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default")
        );
        assert_eq!(state.writes[0].0, None);
        assert_eq!(state.writes[0].1.as_deref(), Some("*"));
        assert_eq!(
            state.writes[0].2["properties"]["ARecords"],
            json!([{"ipv4Address":"8.8.4.4"}])
        );
        let record = json!({"etag":"revision-1","properties":{"TTL":30,"ARecords":[{"ipv4Address":"1.1.1.1"}],"metadata":{"owner":"fixture"}}});
        let (result, state) = azure_case(Some(record), 200, 200).await;
        assert!(result.unwrap());
        assert_eq!(state.writes[0].0.as_deref(), Some("revision-1"));
        assert_eq!(
            state.writes[0].2["properties"]["metadata"]["owner"],
            "fixture"
        );
        let record = json!({"etag":"revision-2","properties":{"TTL":300,"ARecords":[{"ipv4Address":"8.8.4.4"}]}});
        let (result, state) = azure_case(Some(record), 200, 200).await;
        assert!(!result.unwrap());
        assert!(state.writes.is_empty());
        let (result, _) = azure_case(None, 200, 412).await;
        assert!(result.unwrap_err().to_string().contains("412"));
    }

    #[tokio::test]
    async fn dynamic_dns_azure_refuses_alias_multi_record_and_redacts_failures() {
        for properties in [
            json!({"TTL":300,"targetResource":{"id":"/synthetic-alias"}}),
            json!({"TTL":300,"ARecords":[{"ipv4Address":"1.1.1.1"},{"ipv4Address":"8.8.8.8"}]}),
        ] {
            let (result, state) = azure_case(
                Some(json!({"etag":"revision","properties":properties})),
                200,
                200,
            )
            .await;
            assert!(result.is_err());
            assert!(state.writes.is_empty());
        }
        let (result, state) = azure_case(None, 401, 200).await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("401"));
        assert!(!error.contains("synthetic"));
        assert!(state.writes.is_empty());
        let (result, _) = azure_case(None, 200, 429).await;
        assert!(result.unwrap_err().to_string().contains("429"));
    }

    #[test]
    fn dynamic_dns_private_secrets_and_public_address_validation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("secrets");
        let store = Secrets::open(&root).unwrap();
        let reference = store.create("synthetic-only").unwrap();
        assert_eq!(&**store.get(&reference).unwrap(), "synthetic-only");
        assert!(Secrets::open(&root).is_err());
        assert!(store.get("../escape").is_err());
        assert!(store.create("").is_err());
        assert!(store.create(&"x".repeat(4097)).is_err());
        assert!(store.create("bad\0secret").is_err());
        drop(store);
        let store = Secrets::open(&root).unwrap();
        assert!(store.references().unwrap().contains(&reference));
        for _ in 1..256 {
            write_new_private(
                &root.join(format!("secret-{}", identifier())),
                b"synthetic-retained-secret",
            )
            .unwrap();
        }
        assert_eq!(store.references().unwrap().len(), 256);
        assert!(store.create("one-too-many").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join(format!("secret-{reference}")))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            std::os::unix::fs::symlink(
                root.join(format!("secret-{reference}")),
                root.join("secret-00000000000000000000000000000000"),
            )
            .unwrap();
            assert!(store.references().is_err());
        }
        for address in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.1.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_ipv4(address.parse().unwrap()), "{address}");
        }
        assert!(public_ipv4("8.8.4.4".parse().unwrap()));
        assert!(interface_ipv4("ddns-missing0").is_err());
    }

    async fn api(
        app: Arc<App>,
        method: &str,
        path: &str,
        body: Value,
        token: &str,
    ) -> (u16, Value) {
        let response = crate::http::router(app)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (
            response.status().as_u16(),
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap())
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn dynamic_dns_api_confirmation_permissions_and_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(
            Engine::open(
                &dir.path().join("state"),
                Box::new(netcontrol_core::Simulator::new()),
            )
            .unwrap(),
        ));
        let manager =
            Manager::open(&dir.path().join("secrets"), engine.clone(), Mode::Simulated).unwrap();
        let mut app = App::new(
            engine,
            Authentication::Scoped(vec![
                Credential {
                    name: "writer".into(),
                    token_sha256: crate::identity::digest("writer-token"),
                    permissions: netcontrol_core::PERMISSIONS
                        .iter()
                        .map(|p| (*p).into())
                        .collect(),
                },
                Credential {
                    name: "reader".into(),
                    token_sha256: crate::identity::digest("reader-token"),
                    permissions: vec!["state.read".into(), "transactions.write".into()],
                },
            ]),
            false,
        );
        App::attach_dynamic_dns(&mut app, manager.clone()).unwrap();
        let upload = "/api/v1/services/dynamic-dns/secrets";
        let status = "/api/v1/services/dynamic-dns/status";
        assert_eq!(
            api(app.clone(), "GET", status, Value::Null, "bad-token")
                .await
                .0,
            401
        );
        assert_eq!(
            api(
                app.clone(),
                "POST",
                upload,
                json!({"client_secret":"synthetic-only"}),
                "reader-token"
            )
            .await
            .0,
            403
        );
        for value in [
            json!({"client_secret":null}),
            json!({"client_secret":""}),
            json!({"client_secret":"x","extra":true}),
        ] {
            assert_eq!(
                api(app.clone(), "POST", upload, value, "writer-token")
                    .await
                    .0,
                400
            );
        }
        assert_eq!(
            api(app.clone(), "GET", upload, Value::Null, "writer-token")
                .await
                .0,
            405
        );
        assert_eq!(
            api(
                app.clone(),
                "GET",
                &format!("{status}?extra=true"),
                Value::Null,
                "reader-token"
            )
            .await
            .0,
            400
        );
        let (code, created) = api(
            app.clone(),
            "POST",
            upload,
            json!({"client_secret":"synthetic-only"}),
            "writer-token",
        )
        .await;
        assert_eq!(code, 201);
        assert!(created.get("client_secret").is_none());
        let mut entry = entry();
        entry.secret_ref = created["secret_ref"].as_str().unwrap().into();
        let config = json!({"interfaces":[{"name":"wan0","kind":"dummy","role":"wan","mtu":1500,"up":true,"addresses":[]}],"dynamic_dns":[entry]});
        assert_eq!(
            api(
                app.clone(),
                "POST",
                "/api/v1/transactions",
                json!({"base_revision":0,"confirm_timeout_seconds":30,"config":config}),
                "reader-token"
            )
            .await
            .0,
            403
        );
        let (code, transaction) = api(
            app.clone(),
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":0,"confirm_timeout_seconds":30,"config":config}),
            "writer-token",
        )
        .await;
        assert_eq!(code, 202, "{transaction}");
        assert!(manager.configuration().unwrap().is_none());
        assert_eq!(
            api(
                app.clone(),
                "POST",
                upload,
                json!({"client_secret":"replacement"}),
                "writer-token"
            )
            .await
            .0,
            409
        );
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(manager.clone().run(receiver));
        assert_eq!(
            api(
                app.clone(),
                "POST",
                &format!(
                    "/api/v1/transactions/{}/confirm",
                    transaction["id"].as_str().unwrap()
                ),
                Value::Null,
                "writer-token"
            )
            .await
            .0,
            200
        );
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if manager.status().unwrap()["entries"][0]["state"] == "simulated" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (_, state) = api(
            app.clone(),
            "GET",
            "/api/v1/state",
            Value::Null,
            "reader-token",
        )
        .await;
        assert!(!state.to_string().contains("synthetic-only"));
        assert_eq!(
            api(app.clone(), "GET", status, Value::Null, "reader-token")
                .await
                .0,
            200
        );
        let mut disabled = state["desired"].clone();
        disabled["dynamic_dns"][0]["enabled"] = json!(false);
        let (code, pending) = api(
            app.clone(),
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":1,"confirm_timeout_seconds":30,"config":disabled}),
            "writer-token",
        )
        .await;
        assert_eq!(code, 202, "{pending}");
        assert!(
            manager
                .engine
                .lock()
                .unwrap()
                .saved_configuration()
                .dynamic_dns[0]
                .enabled
        );
        let transaction_path = format!("/api/v1/transactions/{}", pending["id"].as_str().unwrap());
        assert_eq!(
            api(
                app.clone(),
                "POST",
                &format!("{transaction_path}/rollback"),
                Value::Null,
                "writer-token"
            )
            .await
            .0,
            200
        );
        assert!(manager.configuration().unwrap().unwrap()[0].enabled);
        let (code, pending) = api(
            app.clone(),
            "POST",
            "/api/v1/transactions",
            json!({"base_revision":1,"confirm_timeout_seconds":30,"config":disabled}),
            "writer-token",
        )
        .await;
        assert_eq!(code, 202, "{pending}");
        assert_eq!(
            api(
                app.clone(),
                "POST",
                &format!(
                    "/api/v1/transactions/{}/confirm",
                    pending["id"].as_str().unwrap()
                ),
                Value::Null,
                "writer-token"
            )
            .await
            .0,
            200
        );
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if manager.status().unwrap()["entries"][0]["state"] == "disabled" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
