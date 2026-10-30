use crate::identity::{IdentityError, Store, digest};
use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use netcontrol_core::{Engine, PERMISSIONS};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const COOKIE: &str = "netcontrol_session";
const API_LIMIT: usize = 1 << 20;
const LOGIN_LIMIT: usize = 4096;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub name: String,
    pub token_sha256: String,
    pub permissions: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    schema: u32,
    credentials: Vec<Credential>,
}
pub fn load_credentials(path: &Path) -> Result<Vec<Credential>> {
    crate::identity::secure_parent(path)?;
    let file = std::fs::symlink_metadata(path)?;
    if !file.is_file() || file.file_type().is_symlink() || file.len() > API_LIMIT as u64 {
        bail!("auth file must be a regular file smaller than 1 MiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.mode() & 0o077 != 0 || file.uid() != unsafe { libc::geteuid() } {
            bail!("auth file must be owner-only and owned by the daemon");
        }
    }
    let input: CredentialFile =
        serde_json::from_slice(&std::fs::read(path)?).context("invalid scoped credential file")?;
    if input.schema != 1 || input.credentials.is_empty() || input.credentials.len() > 100 {
        bail!("auth file requires schema 1 and 1..100 credentials");
    }
    let mut names = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for c in &input.credentials {
        if c.name.trim().is_empty()
            || c.name.trim() != c.name
            || c.name.len() > 80
            || c.name.chars().any(char::is_control)
            || !names.insert(c.name.clone())
            || c.token_sha256.len() != 64
            || hex::decode(&c.token_sha256).is_err()
            || !hashes.insert(c.token_sha256.to_lowercase())
            || c.permissions
                .iter()
                .any(|p| !PERMISSIONS.contains(&p.as_str()))
            || c.permissions.iter().collect::<BTreeSet<_>>().len() != c.permissions.len()
        {
            bail!("invalid or duplicate credential name, token hash, or permission");
        }
    }
    Ok(input
        .credentials
        .into_iter()
        .map(|mut c| {
            c.token_sha256.make_ascii_lowercase();
            c
        })
        .collect())
}

pub enum Authentication {
    Device(Mutex<Store>),
    Scoped(Vec<Credential>),
}
pub struct App {
    pub engine: Arc<Mutex<Engine>>,
    pub health: Arc<crate::health::Monitor>,
    auth: Authentication,
    tls: bool,
    attempts: Mutex<(Instant, usize)>,
    updates: Option<crate::updates::Manager>,
    release_checks: Option<crate::updates::ReleaseCheckControl>,
    sando: Option<Arc<crate::sando::Manager>>,
    mqtt: Option<Arc<crate::mqtt::Manager>>,
    dynamic_dns: Option<Arc<crate::dynamic_dns::Manager>>,
    system: Option<Arc<crate::host_system::Manager>>,
    processes: std::collections::BTreeMap<String, Arc<crate::processes::Control>>,
    daemon_restart: Option<tokio::sync::watch::Sender<bool>>,
    dns_slots: tokio::sync::Semaphore,
}
impl App {
    pub fn new(engine: Arc<Mutex<Engine>>, auth: Authentication, tls: bool) -> Arc<Self> {
        Arc::new(Self {
            engine,
            health: Arc::new(crate::health::Monitor::default()),
            auth,
            tls,
            attempts: Mutex::new((Instant::now(), 0)),
            updates: None,
            release_checks: None,
            sando: None,
            mqtt: None,
            dynamic_dns: None,
            system: None,
            processes: Default::default(),
            daemon_restart: None,
            dns_slots: tokio::sync::Semaphore::new(2),
        })
    }
    pub fn attach_processes(
        app: &mut Arc<Self>,
        controls: std::collections::BTreeMap<String, Arc<crate::processes::Control>>,
        daemon: Option<tokio::sync::watch::Sender<bool>>,
    ) -> Result<()> {
        let app = Arc::get_mut(app).context("application is already shared")?;
        app.processes = controls;
        app.daemon_restart = daemon;
        Ok(())
    }
    pub fn with_updates(
        engine: Arc<Mutex<Engine>>,
        auth: Authentication,
        tls: bool,
        updates: crate::updates::Manager,
    ) -> Result<Arc<Self>> {
        engine
            .lock()
            .map_err(|_| anyhow::anyhow!("engine unavailable"))?
            .set_upgrade_maintenance(updates.active()?)?;
        let mut app = Self::new(engine, auth, tls);
        Arc::get_mut(&mut app)
            .context("new application is shared")?
            .updates = Some(updates);
        Ok(app)
    }
    pub fn attach_release_checks(
        app: &mut Arc<Self>,
        control: crate::updates::ReleaseCheckControl,
    ) -> Result<()> {
        Arc::get_mut(app)
            .context("application is already shared")?
            .release_checks = Some(control);
        Ok(())
    }
    pub fn attach_sando(app: &mut Arc<Self>, manager: Arc<crate::sando::Manager>) -> Result<()> {
        let app = Arc::get_mut(app).context("application is already shared")?;
        if let Some(mqtt) = &app.mqtt {
            mqtt.attach_sando(manager.clone())?;
        }
        app.sando = Some(manager);
        Ok(())
    }
    pub fn refresh_upgrade_gate(&self) -> Result<()> {
        if let Some(updates) = &self.updates {
            self.engine
                .lock()
                .map_err(|_| anyhow::anyhow!("engine unavailable"))?
                .set_upgrade_maintenance(updates.active()?)?;
        }
        Ok(())
    }
    pub fn attach_mqtt(app: &mut Arc<Self>, mqtt: Arc<crate::mqtt::Manager>) -> Result<()> {
        let app = Arc::get_mut(app).context("application is already shared")?;
        if let Some(sando) = &app.sando {
            mqtt.attach_sando(sando.clone())?;
        }
        app.health = mqtt.health.clone();
        app.mqtt = Some(mqtt);
        Ok(())
    }
    pub fn refresh_health(&self, watchdog: bool, tasks: &[(&str, bool)]) {
        let runtime = self.engine.try_lock().ok().and_then(|mut engine| {
            let reply = engine.request(
                "GET",
                "/api/v1/runtime",
                "",
                "platform-monitor",
                &["state.read".into()],
                &[],
            );
            (reply.status == 200).then_some(reply.body)
        });
        let mut managers = Vec::new();
        for (name, status) in [
            ("mqtt", self.mqtt.as_ref().map(|manager| manager.status())),
            (
                "dynamic_dns",
                self.dynamic_dns.as_ref().map(|manager| manager.status()),
            ),
            (
                "system",
                self.system.as_ref().map(|manager| manager.status()),
            ),
        ] {
            if let Some(status) = status {
                managers.push((
                    name,
                    status.unwrap_or_else(|_| json!({"state":"unavailable"})),
                ));
            }
        }
        managers.push(("daemon_tasks", json!({"entries":tasks.iter().map(|(name, finished)| json!({"name":name,"state":if *finished {"stopped"} else {"running"}})).collect::<Vec<_>>()})));
        managers.push((
            "managed_processes",
            json!({"entries":self.processes.iter().map(|(name,control)| {
            let mut status=control.status().unwrap_or_else(|error|json!({"state":"error","error":error.to_string()}));
            status["name"]=json!(name);
            status
        }).collect::<Vec<_>>()}),
        ));
        self.health.observe(runtime.as_ref(), &managers, watchdog);
    }
    pub fn attach_dynamic_dns(
        app: &mut Arc<Self>,
        manager: Arc<crate::dynamic_dns::Manager>,
    ) -> Result<()> {
        Arc::get_mut(app)
            .context("application is already shared")?
            .dynamic_dns = Some(manager);
        Ok(())
    }
    pub fn attach_system(
        app: &mut Arc<Self>,
        manager: Arc<crate::host_system::Manager>,
    ) -> Result<()> {
        Arc::get_mut(app)
            .context("application is already shared")?
            .system = Some(manager);
        Ok(())
    }
    pub fn authenticate_api_key(&self, token: &str) -> Result<Option<Credential>> {
        if token.is_empty() {
            return Ok(None);
        }
        match &self.auth {
            Authentication::Device(store) => {
                let store = store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("credential store unavailable"))?;
                store.check_health()?;
                Ok(store.authenticate(token).map(|key| Credential {
                    name: key.name,
                    token_sha256: String::new(),
                    permissions: PERMISSIONS.iter().map(|p| (*p).to_owned()).collect(),
                }))
            }
            Authentication::Scoped(credentials) => {
                let hash = digest(token);
                Ok(credentials
                    .iter()
                    .find(|c| c.token_sha256.as_bytes().ct_eq(hash.as_bytes()).unwrap_u8() == 1)
                    .cloned())
            }
        }
    }
    fn allow_attempt(&self) -> bool {
        let Ok(mut rate) = self.attempts.lock() else {
            return false;
        };
        if rate.0.elapsed() >= Duration::from_secs(60) {
            *rate = (Instant::now(), 0);
        }
        rate.1 += 1;
        rate.1 <= 10
    }
}
pub fn router(app: Arc<App>) -> Router {
    Router::new().fallback(front_door).with_state(app)
}
fn response(status: u16, value: Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&value).unwrap_or_default()))
        .expect("valid response")
}
fn fail(status: u16, message: &str, api: bool) -> Response {
    response(
        status,
        if api {
            json!({"error":message,"transaction":null})
        } else {
            json!({"error":message})
        },
    )
}
fn store_error(error: anyhow::Error) -> Response {
    if let Some(e) = error.downcast_ref::<IdentityError>() {
        fail(e.status, e.message, false)
    } else {
        fail(500, "credential service unavailable", false)
    }
}
fn text(headers: &HeaderMap, key: &str) -> String {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}
fn set(response: &mut Response, key: &'static str, value: &'static str) {
    response
        .headers_mut()
        .insert(key, HeaderValue::from_static(value));
}
fn decode<T: DeserializeOwned>(
    body: &std::result::Result<Vec<u8>, ()>,
) -> std::result::Result<T, &'static str> {
    match body {
        Ok(bytes) => serde_json::from_slice(bytes).map_err(|_| "invalid JSON request body"),
        Err(()) => Err("http: request body too large"),
    }
}
fn session_cookie(token: &str, tls: bool, logout: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/auth/; Max-Age={}; HttpOnly; SameSite=Strict{}",
        if logout {
            0
        } else {
            crate::identity::SESSION_LIFETIME
        },
        if tls { "; Secure" } else { "" }
    )
}
fn read_cookie(headers: &HeaderMap) -> String {
    let prefix = format!("{COOKIE}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|v| v.trim().strip_prefix(prefix.as_str()))
        .unwrap_or("")
        .to_owned()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateKey {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    saved: bool,
}

async fn front_door(State(app): State<Arc<App>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let method = parts.method.to_string();
    let query = parts.uri.query().unwrap_or("").to_owned();
    let api = path.starts_with("/api/v1/");
    let tls = app.tls;
    let headers = parts.headers;
    let preflight = api
        && method == "OPTIONS"
        && !text(&headers, "origin").is_empty()
        && !text(&headers, "access-control-request-method").is_empty();
    let limit = if path == "/auth/setup" || path == "/auth/login" {
        LOGIN_LIMIT
    } else {
        API_LIMIT
    };
    let body = if preflight {
        Ok(Vec::new())
    } else {
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, limit)).await {
            Ok(Ok(bytes)) => Ok(bytes.to_vec()),
            _ => Err(()),
        }
    };
    let mut result =
        tokio::task::spawn_blocking(move || dispatch(&app, &method, &path, &query, &headers, body))
            .await
            .unwrap_or_else(|_| fail(500, "service unavailable", api));
    tracing::info!(
        surface = if api { "networking" } else { "management" },
        status = result.status().as_u16(),
        "HTTP request completed"
    );
    set(&mut result, "cache-control", "no-store");
    set(&mut result, "x-content-type-options", "nosniff");
    set(&mut result, "referrer-policy", "no-referrer");
    set(
        &mut result,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    if tls {
        set(&mut result, "strict-transport-security", "max-age=31536000");
    }
    if api {
        set(&mut result, "access-control-allow-origin", "*");
        set(
            &mut result,
            "access-control-expose-headers",
            "Location, WWW-Authenticate, Retry-After",
        );
        if preflight {
            set(
                &mut result,
                "access-control-allow-methods",
                "GET, POST, DELETE",
            );
            set(
                &mut result,
                "access-control-allow-headers",
                "Authorization, Content-Type",
            );
        }
    }
    result
}
fn dispatch(
    app: &App,
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: std::result::Result<Vec<u8>, ()>,
) -> Response {
    if path.starts_with("/api/") {
        return api(app, method, path, query, headers, body);
    }
    if matches!(path, "/" | "/app.js" | "/style.css") {
        if method != "GET" && method != "HEAD" {
            let mut r = fail(405, "method not allowed", false);
            set(&mut r, "allow", "GET, HEAD");
            return r;
        }
        let (content, mime): (&[u8], &str) = match path {
            "/" => (
                include_bytes!("../assets/index.html"),
                "text/html; charset=utf-8",
            ),
            "/app.js" => (
                include_bytes!("../assets/app.js"),
                "text/javascript; charset=utf-8",
            ),
            _ => (
                include_bytes!("../assets/style.css"),
                "text/css; charset=utf-8",
            ),
        };
        return Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, mime)
            .body(if method == "HEAD" {
                Body::empty()
            } else {
                Body::from(content)
            })
            .expect("valid asset response");
    }
    let Authentication::Device(store) = &app.auth else {
        return fail(404, "endpoint not found", false);
    };
    if !path.starts_with("/auth/") {
        return fail(404, "endpoint not found", false);
    }
    if method != "GET" {
        let origin = format!(
            "{}://{}",
            if app.tls { "https" } else { "http" },
            text(headers, "host")
        );
        if text(headers, "host").is_empty() || text(headers, "origin") != origin {
            return fail(403, "same-origin request required", false);
        }
        let content_type = text(headers, "content-type");
        if !content_type
            .parse::<mime::Mime>()
            .is_ok_and(|mime| mime.essence_str() == "application/json")
        {
            return fail(415, "application/json required", false);
        }
    }
    let token = read_cookie(headers);
    let Ok(mut store) = store.lock() else {
        return fail(500, "credential service unavailable", false);
    };
    if let Err(error) = store.check_health() {
        return store_error(error);
    }
    if path == "/auth/status" && method == "GET" {
        let (exists, complete, username) = store.status();
        let authenticated = store.session(&token).is_ok();
        let stage = if !exists {
            "account"
        } else if !authenticated {
            "login"
        } else if complete {
            "ready"
        } else {
            "keys"
        };
        return response(
            200,
            json!({"stage":stage,"authenticated":authenticated,"configured":complete,"username":if authenticated { username } else { "" }}),
        );
    }
    if matches!(path, "/auth/setup" | "/auth/login") && method == "POST" {
        if !app.allow_attempt() {
            let mut r = fail(
                429,
                "too many sign-in/setup attempts; retry in one minute",
                false,
            );
            set(&mut r, "retry-after", "60");
            return r;
        }
        let input: Login = match decode(&body) {
            Ok(v) => v,
            Err(message) => return fail(400, message, false),
        };
        let result = if path == "/auth/setup" {
            store.setup(&input.username, &input.password)
        } else {
            store.login(&input.username, &input.password)
        };
        return match result {
            Ok(token) => {
                let mut r = response(200, json!({"ok":true}));
                r.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&session_cookie(&token, app.tls, false))
                        .expect("hex cookie"),
                );
                r
            }
            Err(e) => store_error(e),
        };
    }
    if let Err(e) = store.session(&token) {
        return store_error(e);
    }
    match (method, path) {
        ("POST", "/auth/logout") => match store.logout(&token) {
            Ok(()) => {
                let mut r = response(200, json!({"ok":true}));
                r.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&session_cookie("", app.tls, true)).expect("cookie"),
                );
                r
            }
            Err(e) => store_error(e),
        },
        ("POST", "/auth/complete") => {
            match decode::<Complete>(&body) {
                Ok(Complete { saved: true }) => {}
                _ => return fail(400, "confirm that you saved your API key", false),
            }
            match store.complete(&token) {
                Ok(()) => response(200, json!({"ok":true})),
                Err(e) => store_error(e),
            }
        }
        ("GET", "/auth/keys") => match store.keys(&token) {
            Ok(keys) => response(200, json!({"keys":keys})),
            Err(e) => store_error(e),
        },
        ("POST", "/auth/keys") => {
            let input: CreateKey = match decode(&body) {
                Ok(v) => v,
                Err(message) => return fail(400, message, false),
            };
            match store.create_key(&token, &input.name) {
                Ok((key, token)) => response(201, json!({"key":key,"token":token})),
                Err(e) => store_error(e),
            }
        }
        ("DELETE", path) if path.starts_with("/auth/keys/") => {
            match store.delete_key(&token, &path["/auth/keys/".len()..]) {
                Ok(()) => response(200, json!({"ok":true})),
                Err(e) => store_error(e),
            }
        }
        _ => fail(404, "endpoint or method not found", false),
    }
}
fn api(
    app: &App,
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: std::result::Result<Vec<u8>, ()>,
) -> Response {
    if path.starts_with("/api/v1/")
        && method == "OPTIONS"
        && !text(headers, "origin").is_empty()
        && !text(headers, "access-control-request-method").is_empty()
    {
        if !matches!(
            text(headers, "access-control-request-method").as_str(),
            "GET" | "POST" | "DELETE"
        ) {
            return fail(405, "cross-origin method must be GET, POST or DELETE", true);
        }
        for name in text(headers, "access-control-request-headers")
            .split(',')
            .map(str::trim)
        {
            if !name.is_empty()
                && !name.eq_ignore_ascii_case("authorization")
                && !name.eq_ignore_ascii_case("content-type")
            {
                return fail(
                    400,
                    &format!("unsupported cross-origin request header {name:?}"),
                    true,
                );
            }
        }
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .expect("valid response");
    }
    let authorization = text(headers, "authorization");
    let credential = if let Some(token) = authorization.strip_prefix("Bearer ") {
        match app.authenticate_api_key(token) {
            Ok(credential) => credential,
            Err(_) => return fail(503, "credential store unavailable", true),
        }
    } else {
        None
    };
    let Some(credential) = credential else {
        let mut r = fail(401, "valid API key required", true);
        set(&mut r, "www-authenticate", "Bearer");
        return r;
    };
    let body = match body {
        Ok(body) => body,
        Err(()) => return fail(400, "http: request body too large", true),
    };
    if path == "/api/v1/platform/status" {
        if !credential
            .permissions
            .iter()
            .any(|permission| permission == "state.read")
        {
            return fail(403, "insufficient platform status permission", true);
        }
        if method != "GET" {
            return fail(405, "platform status requires GET", true);
        }
        if !query.is_empty() || !body.is_empty() {
            return fail(400, "platform status accepts no query or body", true);
        }
        return response(200, app.health.snapshot());
    }
    if path == "/api/v1/sando" {
        if !credential.permissions.iter().any(|p| p == "state.read") {
            return fail(403, "insufficient Sando read permission", true);
        }
        if method != "GET" {
            return fail(405, "Sando status requires GET", true);
        }
        if !query.is_empty() || !body.is_empty() {
            return fail(400, "Sando status accepts no query or body", true);
        }
        let Some(manager) = &app.sando else {
            return fail(503, "Sando sync is not configured", true);
        };
        return match manager.status() {
            Ok(status) => response(200, status),
            Err(error) => {
                tracing::error!(%error, "could not read Sando status");
                fail(503, "Sando status unavailable", true)
            }
        };
    }
    if path == "/api/v1/system/upgrade/check" {
        if !credential.permissions.iter().any(|p| p == "system.upgrade") {
            return fail(403, "insufficient upgrade permission", true);
        }
        if method != "POST" {
            return fail(405, "release check requires POST", true);
        }
        if !query.is_empty() || !body.is_empty() {
            return fail(400, "release check accepts no query or body", true);
        }
        let Some(control) = &app.release_checks else {
            return fail(503, "release checking is not configured", true);
        };
        return match control.request() {
            Ok(true) => {
                tracing::info!(actor=%credential.name, "software release check requested");
                let mut reply = response(202, json!({"status":"check_requested"}));
                set(&mut reply, "location", "/api/v1/revisions/latest");
                reply
            }
            Ok(false) => fail(409, "release check already queued or running", true),
            Err(error) => {
                tracing::warn!(%error, "could not request software release check");
                fail(503, "release check worker unavailable", true)
            }
        };
    }
    if matches!(
        path,
        "/api/v1/processes/restart" | "/api/v1/diagnostics/dns-lookup"
    ) {
        let restart = path == "/api/v1/processes/restart";
        let permission = if restart {
            "system.restart"
        } else {
            "diagnostics.run"
        };
        if !credential.permissions.iter().any(|p| p == permission) {
            return fail(403, "insufficient operational permission", true);
        }
        if method != "POST" {
            return fail(405, "operational action requires POST", true);
        }
        if !query.is_empty() {
            return fail(400, "operational action accepts no query parameters", true);
        }
        if let Err(error) = app.refresh_upgrade_gate() {
            tracing::error!(%error,"operational upgrade gate unavailable");
            return fail(503, "upgrade state unavailable", true);
        }
        let Ok(mut engine) = app.engine.lock() else {
            return fail(503, "engine unavailable", true);
        };
        if engine.configuration_busy() {
            return fail(
                409,
                "configuration transaction, upgrade or restart is active",
                true,
            );
        }
        if restart {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Restart {
                target: String,
            }
            let Ok(input) = serde_json::from_slice::<Restart>(&body) else {
                return fail(
                    400,
                    "expected JSON object containing only target string",
                    true,
                );
            };
            if input.target.is_empty()
                || input.target.len() > 80
                || !input.target.is_ascii()
                || input.target.chars().any(|c| c.is_control())
            {
                return fail(400, "invalid managed process target", true);
            }
            if input.target == "netcontrold" {
                let Some(signal) = &app.daemon_restart else {
                    return fail(
                        503,
                        "daemon restart requires the supervised native systemd service",
                        true,
                    );
                };
                if signal.is_closed() {
                    return fail(503, "daemon shutdown listener unavailable", true);
                }
                if let Err(error) = engine.begin_restart() {
                    return fail(409, &error.to_string(), true);
                }
                // Receiver lifetime is owned by main until HTTP drain finishes.
                if signal.send(true).is_err() {
                    engine.cancel_restart();
                    return fail(503, "daemon shutdown listener unavailable", true);
                }
                tracing::warn!(actor=%credential.name,"daemon restart requested");
                return response(
                    202,
                    json!({"target":"netcontrold","status":"restart_requested"}),
                );
            }
            if let Some(control) = app.processes.get(&input.target) {
                return match control.request() {
                    Ok(generation) => {
                        tracing::warn!(actor=%credential.name,target=%input.target,"managed task restart requested");
                        response(202, crate::processes::reply(&input.target, generation))
                    }
                    Err(error) => fail(503, &error.to_string(), true),
                };
            }
            if ["mqtt", "dynamic-dns", "system"].contains(&input.target.as_str()) {
                return fail(503, "managed task is unavailable", true);
            }
            let reply = engine.restart_process(&input.target);
            tracing::warn!(actor=%credential.name,target=%input.target,status=reply.status,"native worker restart action completed");
            return response(reply.status, reply.body);
        }
        let Ok(mut input) = serde_json::from_slice::<netcontrol_core::DNSLookupRequest>(&body)
        else {
            return fail(
                400,
                "expected hostname, interface or server, and optional record_type/timeout_ms",
                true,
            );
        };
        if let Err(error) = input.validate() {
            return fail(400, &error.to_string(), true);
        }
        let Ok(_slot) = app.dns_slots.try_acquire() else {
            return fail(429, "DNS diagnostic concurrency limit reached", true);
        };
        let revision = engine.committed_revision();
        let lookup = match engine.prepare_dns_lookup(&input) {
            Ok(lookup) => lookup,
            Err(error) => return fail(503, &error.to_string(), true),
        };
        drop(engine);
        return match lookup() {
            Ok(mut value) => {
                value["revision"] = json!(revision);
                response(200, value)
            }
            Err(error) => {
                tracing::warn!(%error,"DNS diagnostic failed");
                fail(503, &error.to_string(), true)
            }
        };
    }
    let Ok(mut engine) = app.engine.lock() else {
        return fail(503, "engine unavailable", true);
    };
    if let Some(updates) = &app.updates {
        match updates
            .active()
            .and_then(|active| engine.set_upgrade_maintenance(active))
        {
            Ok(()) => (),
            Err(_) => return fail(503, "upgrade state unavailable", true),
        }
    }
    if matches!(
        path,
        "/api/v1/services/dynamic-dns/status" | "/api/v1/services/dynamic-dns/secrets"
    ) {
        let upload = path.ends_with("/secrets");
        let permission = if upload {
            "dynamic_dns.write"
        } else {
            "state.read"
        };
        if !credential.permissions.iter().any(|p| p == permission) {
            return fail(403, "insufficient Dynamic DNS permission", true);
        }
        if method != if upload { "POST" } else { "GET" } {
            return fail(405, "unsupported Dynamic DNS method", true);
        }
        if !query.is_empty() {
            return fail(
                400,
                "Dynamic DNS endpoint accepts no query parameters",
                true,
            );
        }
        let Some(manager) = &app.dynamic_dns else {
            return fail(503, "Dynamic DNS manager unavailable", true);
        };
        if !upload {
            return match manager.status() {
                Ok(status) => response(200, status),
                Err(_) => fail(503, "Dynamic DNS status unavailable", true),
            };
        }
        if engine.configuration_busy() {
            return fail(409, "configuration transaction or upgrade is active", true);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SecretRequest {
            client_secret: String,
        }
        let Ok(input) = serde_json::from_slice::<SecretRequest>(&body) else {
            return fail(400, "expected JSON object with client_secret string", true);
        };
        let secret = zeroize::Zeroizing::new(input.client_secret);
        if let Err(error) = crate::dynamic_dns::validate_secret(&secret) {
            return fail(400, &error.to_string(), true);
        }
        return match manager.create_secret(&mut engine, &secret) {
            Ok(reference) => response(201, json!({"secret_ref":reference})),
            Err(_) => fail(
                503,
                "Dynamic DNS secret could not be stored; check private storage and its 256-secret limit",
                true,
            ),
        };
    }
    if matches!(
        path,
        "/api/v1/services/mqtt/status" | "/api/v1/services/mqtt/passwords"
    ) {
        let password = path.ends_with("/passwords");
        let permission = if password { "mqtt.write" } else { "state.read" };
        if !credential
            .permissions
            .iter()
            .any(|value| value == permission)
        {
            return fail(403, "insufficient MQTT permission", true);
        }
        if method != if password { "POST" } else { "GET" } {
            return fail(405, "unsupported MQTT method", true);
        }
        if !query.is_empty() {
            return fail(400, "MQTT endpoint accepts no query parameters", true);
        }
        let Some(mqtt) = &app.mqtt else {
            return fail(503, "MQTT publisher unavailable", true);
        };
        if !password {
            return match mqtt.status() {
                Ok(status) => response(200, status),
                Err(_) => fail(503, "MQTT status unavailable", true),
            };
        }
        if engine.configuration_busy() {
            return fail(409, "configuration transaction or upgrade is active", true);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PasswordRequest {
            password: String,
        }
        let Ok(input) = serde_json::from_slice::<PasswordRequest>(&body) else {
            return fail(400, "expected JSON object with password string", true);
        };
        let password = zeroize::Zeroizing::new(input.password);
        if password.is_empty() || password.len() > 4096 || password.contains('\0') {
            return fail(
                400,
                "MQTT password must be 1..4096 UTF-8 bytes without NUL",
                true,
            );
        }
        return match mqtt.create_password(&mut engine, &password) {
            Ok(reference) => response(201, json!({"password_ref":reference})),
            Err(_) => fail(
                503,
                "MQTT password could not be stored; check private storage and its 256-password limit",
                true,
            ),
        };
    }
    if matches!(path, "/api/v1/system/status" | "/api/v1/system/timezones") {
        if !credential
            .permissions
            .iter()
            .any(|value| value == "state.read")
        {
            return fail(403, "insufficient system permission", true);
        }
        if method != "GET" {
            return fail(405, "unsupported system method", true);
        }
        if !query.is_empty() {
            return fail(400, "system endpoint accepts no query parameters", true);
        }
        // Zone enumeration reads the filesystem; do not hold the engine for it.
        drop(engine);
        let Some(system) = &app.system else {
            return fail(503, "host system manager unavailable", true);
        };
        return if path.ends_with("/status") {
            match system.status() {
                Ok(status) => response(200, status),
                Err(_) => fail(503, "system status unavailable", true),
            }
        } else {
            response(200, json!({"timezones":system.timezones()}))
        };
    }
    if path == "/api/v1/system/upgrade" {
        let permission = if method == "POST" {
            "system.upgrade"
        } else {
            "state.read"
        };
        if !credential
            .permissions
            .iter()
            .any(|value| value == permission)
        {
            return fail(403, "insufficient upgrade permission", true);
        }
        if !matches!(method, "GET" | "POST") {
            return fail(405, "method not allowed", true);
        }
        if !query.is_empty() {
            return fail(
                400,
                "upgrade endpoint does not accept query parameters",
                true,
            );
        }
        if method == "GET" {
            if !body.is_empty() {
                return fail(400, "upgrade status does not accept a body", true);
            }
            return match &app.updates {
                None => response(
                    200,
                    json!({"enabled":false,"repository":null,"job":null,"last_successful_version":null}),
                ),
                Some(updates) => match updates.job() {
                    Ok(job) => response(
                        200,
                        json!({"enabled":true,"repository":updates.repository(),"last_successful_version":job.as_ref().and_then(|job| job.last_successful_version.clone()),"job":job.map(|job|job.public())}),
                    ),
                    Err(_) => fail(503, "upgrade state unavailable", true),
                },
            };
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Upgrade {
            version: String,
        }
        let input: Upgrade = match serde_json::from_slice(&body) {
            Ok(input) => input,
            Err(_) => return fail(400, "expected an object containing only version", true),
        };
        let version = match netcontrol_package::update::version(&input.version) {
            Ok(version) => version,
            Err(_) => {
                return fail(
                    400,
                    "version must be canonical yyyy.mm.dd.iteration without a v prefix",
                    true,
                );
            }
        };
        let Some(updates) = &app.updates else {
            return fail(503, "self-upgrade is not configured", true);
        };
        let current = match updates.job() {
            Ok(job) => job,
            Err(_) => return fail(503, "upgrade state unavailable", true),
        };
        if version
            <= netcontrol_core::RELEASE_VERSION
                .parse::<netcontrol_core::Version>()
                .expect("invalid compiled release version")
            || current.as_ref().is_some_and(|job| {
                job.active()
                    || job
                        .last_successful_version
                        .as_ref()
                        .is_some_and(|previous| {
                            netcontrol_package::update::version(previous)
                                .is_ok_and(|previous| version <= previous)
                        })
            })
        {
            return fail(
                409,
                "upgrade active or requested version is not newer than the running and last successful versions",
                true,
            );
        }
        if engine.set_upgrade_maintenance(true).is_err() {
            return fail(
                409,
                "upgrade requires no active configuration transaction",
                true,
            );
        }
        return match updates.start(&input.version) {
            Ok(job) => {
                let mut reply = response(202, job.public());
                set(&mut reply, "location", "/api/v1/system/upgrade");
                reply
            }
            Err(_) => {
                if let Ok(false) = updates.active() {
                    let _ = engine.set_upgrade_maintenance(false);
                }
                fail(
                    503,
                    "could not start software upgrade; inspect the service journal",
                    true,
                )
            }
        };
    }
    let reply = engine.request(
        method,
        path,
        query,
        &credential.name,
        &credential.permissions,
        &body,
    );
    let mut value = reply.body;
    if reply.status == 200 && method == "GET" && matches!(path, "/api/v1/state" | "/api/v1/runtime")
    {
        let health = app.health.snapshot();
        value["process_health"] = health["process_health"].clone();
        value["active_alerts"] = health["active_alerts"].clone();
    }
    let mut r = response(reply.status, value);
    if let Some(location) = reply.location {
        if let Ok(value) = HeaderValue::from_str(&location) {
            r.headers_mut().insert(header::LOCATION, value);
        }
    }
    r
}
