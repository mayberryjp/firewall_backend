use crate::{
    Backend, Config, KernelConfig, SoftwareMetadata, Version, kernel_catalog, store::Store,
    valid_interface_name,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

pub const PERMISSIONS: &[&str] = &[
    "state.read",
    "transactions.write",
    "interfaces.write",
    "routes.write",
    "firewall.write",
    "firewall.logs.read",
    "nat.write",
    "wireguard.write",
    "softflowd.write",
    "gateway_monitors.write",
    "ntp.write",
    "mdns.write",
    "udp_broadcast_relay.write",
    "bgp.write",
    "syslog.write",
    "vnstat.write",
    "mqtt.write",
    "system.write",
    "sando.write",
    "dynamic_dns.write",
    "kernel.namespace.write",
    "kernel.host.write",
    "system.upgrade",
    "connections.delete",
    "system.restart",
    "diagnostics.run",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub id: String,
    pub actor: String,
    pub status: String,
    pub base_revision: Version,
    pub committed_revision: Option<Version>,
    pub candidate: Config,
    pub previous: Config,
    pub confirmation_deadline: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub submitted_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub committed_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_from_revision: Option<Version>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    scope: String,
    revision: Version,
    initial_revision: Version,
    desired: Config,
    active_transaction: Option<String>,
    initialized_at: DateTime<Utc>,
    transactions: BTreeMap<String, Transaction>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    base_revision: Version,
    confirm_timeout_seconds: i64,
    config: Config,
    #[serde(default)]
    description: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRequest {
    base_revision: Version,
    confirm_timeout_seconds: i64,
    #[serde(default)]
    description: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearFirewallRequest {
    base_revision: Version,
    confirm_timeout_seconds: i64,
    confirm: bool,
    #[serde(default)]
    description: String,
}
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub location: Option<String>,
}
impl Reply {
    fn value(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            location: None,
        }
    }
}
struct ApiError {
    status: u16,
    error: String,
    transaction: Option<Box<Transaction>>,
}
impl ApiError {
    fn new(status: u16, error: impl ToString) -> Self {
        Self {
            status,
            error: error.to_string(),
            transaction: None,
        }
    }
    fn transaction(mut self, t: Transaction) -> Self {
        self.transaction = Some(Box::new(t));
        self
    }
    fn reply(self) -> Reply {
        Reply::value(
            self.status,
            json!({"error":self.error,"transaction":self.transaction}),
        )
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;
fn service_error(e: impl ToString) -> ApiError {
    ApiError::new(503, e)
}
fn internal_error(e: impl ToString) -> ApiError {
    ApiError::new(500, e)
}
fn annotate_rule_origins(response: &mut Value, config: &Config) -> Result<()> {
    let configured = json!({"firewall": &config.firewall});
    let rules = response["rules"]
        .as_array_mut()
        .context("backend returned invalid firewall counter rules")?;
    for row in rules {
        ensure!(
            row.is_object(),
            "backend returned invalid firewall counter row"
        );
        let path = row
            .get("config_path")
            .context("counter config_path missing")?;
        let (origin, source) = if path.is_null() {
            (json!("system"), Value::Null)
        } else {
            let path = path.as_str().context("invalid counter config_path")?;
            let rule = configured
                .pointer(path)
                .context("counter config_path not found")?;
            if path == "/firewall/allow_all_icmp" || path.ends_with("/policy") {
                (json!("system"), Value::Null)
            } else {
                (
                    rule.get("origin")
                        .context("counter rule origin missing")?
                        .clone(),
                    rule.get("import_source")
                        .context("counter import_source missing")?
                        .clone(),
                )
            }
        };
        row["origin"] = origin;
        row["import_source"] = source;
    }
    Ok(())
}
fn value<T: Serialize>(v: T) -> ApiResult<Value> {
    serde_json::to_value(v).map_err(service_error)
}
fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    if body.len() > 1 << 20 {
        return Err(ApiError::new(400, "request exceeds 1048576 bytes"));
    }
    serde_json::from_slice(body).map_err(|e| ApiError::new(400, format!("invalid JSON: {e}")))
}
fn pointer_token(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}
/// Drops unknown keys from a request value and returns their JSON Pointers; every known field stays fully validated.
fn prune_unknown<T: serde::de::DeserializeOwned>(
    value: &mut Value,
    prefix: &str,
) -> ApiResult<Vec<String>> {
    let mut ignored = Vec::new();
    loop {
        let error = match serde_path_to_error::deserialize::<_, T>(&*value) {
            Ok(_) => return Ok(ignored),
            Err(error) => error,
        };
        let message = error.inner().to_string();
        let mut segments = Vec::new();
        for segment in error.path().iter() {
            match segment {
                serde_path_to_error::Segment::Map { key } => segments.push(key.clone()),
                serde_path_to_error::Segment::Seq { index } => segments.push(index.to_string()),
                _ => segments.clear(),
            }
        }
        let unknown = message.starts_with("unknown field `");
        let Some(key) = segments.pop().filter(|_| unknown) else {
            return Err(ApiError::new(
                400,
                format!("invalid JSON at {prefix}{}: {message}", error.path()),
            ));
        };
        let mut container = &mut *value;
        for segment in &segments {
            let next = match container {
                Value::Object(map) => map.get_mut(segment),
                Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get_mut(i)),
                _ => None,
            };
            container = next.ok_or_else(|| ApiError::new(400, "invalid JSON request"))?;
        }
        let removed = container
            .as_object_mut()
            .is_some_and(|map| map.remove(&key).is_some());
        if !removed || ignored.len() >= 256 {
            return Err(ApiError::new(
                400,
                "invalid JSON request: too many or unremovable unknown fields",
            ));
        }
        let pointer: String = segments
            .iter()
            .chain(std::iter::once(&key))
            .map(|segment| format!("/{}", pointer_token(segment)))
            .collect();
        ignored.push(format!("{prefix}{pointer}"));
    }
}
fn parse_submit(body: &[u8]) -> ApiResult<(SubmitRequest, Vec<String>)> {
    let mut request: Value = parse(body)?;
    let ignored = match request.get_mut("config") {
        Some(config) => prune_unknown::<Config>(config, "/config")?,
        None => Vec::new(),
    };
    let request = serde_json::from_value(request)
        .map_err(|e| ApiError::new(400, format!("invalid JSON: {e}")))?;
    Ok((request, ignored))
}
fn require(permissions: &[String], p: &str) -> ApiResult<()> {
    if permissions.iter().any(|s| s == p) {
        Ok(())
    } else {
        Err(ApiError::new(403, format!("{p} permission required")))
    }
}
fn authorize(permissions: &[String], before: &Config, after: &Config) -> ApiResult<()> {
    let mut a = before.normalized();
    let mut b = after.normalized();
    for (p, different) in [
        ("routes.write", a.routes != b.routes),
        ("routes.write", a.blackhole != b.blackhole),
        ("softflowd.write", a.softflowd != b.softflowd),
        (
            "gateway_monitors.write",
            a.gateway_monitors != b.gateway_monitors,
        ),
        ("ntp.write", a.ntp != b.ntp),
        ("mdns.write", a.mdns != b.mdns),
        (
            "udp_broadcast_relay.write",
            a.udp_broadcast_relay != b.udp_broadcast_relay,
        ),
        ("bgp.write", a.bgp != b.bgp),
        ("syslog.write", a.syslog != b.syslog),
        ("vnstat.write", a.vnstat != b.vnstat),
        ("mqtt.write", a.mqtt != b.mqtt),
        ("system.write", a.system != b.system),
        ("sando.write", a.sando != b.sando),
        ("dynamic_dns.write", a.dynamic_dns != b.dynamic_dns),
        ("kernel.namespace.write", a.ipv6_enabled != b.ipv6_enabled),
        (
            "kernel.namespace.write",
            a.kernel.namespace != b.kernel.namespace,
        ),
        ("kernel.host.write", a.kernel.host != b.kernel.host),
        ("nat.write", a.firewall.nat != b.firewall.nat),
    ] {
        if different {
            require(permissions, p)?;
        }
    }
    a.firewall.nat = Default::default();
    b.firewall.nat = Default::default();
    if a.firewall != b.firewall {
        require(permissions, "firewall.write")?;
    }
    let wa: BTreeMap<_, _> = a
        .interfaces
        .iter_mut()
        .filter_map(|l| l.wireguard.take().map(|w| (l.name.clone(), w)))
        .collect();
    let wb: BTreeMap<_, _> = b
        .interfaces
        .iter_mut()
        .filter_map(|l| l.wireguard.take().map(|w| (l.name.clone(), w)))
        .collect();
    if wa != wb {
        require(permissions, "wireguard.write")?;
    }
    if a.interfaces != b.interfaces || a.dhcp_clients != b.dhcp_clients || a.dns != b.dns {
        require(permissions, "interfaces.write")?;
    }
    Ok(())
}

pub struct Engine {
    store: Store,
    state: State,
    backend: Box<dyn Backend>,
    closed: bool,
    maintenance: bool,
    restarting: bool,
    mqtt_passwords: Option<BTreeSet<String>>,
    dynamic_dns_secrets: Option<BTreeSet<String>>,
    timezone_check: Option<TimezoneCheck>,
    #[cfg(test)]
    now: Option<DateTime<Utc>>,
}

/// Reports whether a syntactically valid timezone exists on the managed host.
pub type TimezoneCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;
impl Engine {
    pub fn open(path: &Path, backend: Box<dyn Backend>) -> Result<Self> {
        Self::open_inner(path, backend, true, true)
    }

    pub fn open_saved(path: &Path, backend: Box<dyn Backend>) -> Result<Self> {
        Self::open_inner(path, backend, false, true)
    }

    pub fn open_for_factory_reset(path: &Path, backend: Box<dyn Backend>) -> Result<Self> {
        Self::open_inner(path, backend, false, false)
    }

    fn open_inner(
        path: &Path,
        mut backend: Box<dyn Backend>,
        initialize: bool,
        reconcile: bool,
    ) -> Result<Self> {
        let store = Store::open(path)?;
        let scope = backend.scope().context("backend scope")?;
        ensure!(!scope.is_empty(), "backend scope must not be empty");
        let state = match store.load::<State>()? {
            Some(mut s) => {
                ensure!(
                    s.scope == scope,
                    "state belongs to a different backend scope"
                );
                validate_state(&s)?;
                if initialize
                    && s.revision == s.initial_revision
                    && s.transactions.is_empty()
                    && s.desired == Config::empty()
                {
                    let initial = backend.initial_configuration()?.normalized();
                    initial.validate()?;
                    s.desired = initial;
                    store
                        .save(&s)
                        .context("save inherited initial configuration")?;
                }
                s
            }
            None => {
                ensure!(
                    initialize,
                    "no saved configuration; initial provisioning is required"
                );
                let initial = backend
                    .initial_configuration()
                    .context("capture initial backend configuration")?
                    .normalized();
                initial
                    .validate()
                    .context("invalid initial backend configuration")?;
                let initialized_at = Utc::now();
                let initial_revision = Version::first(initialized_at.date_naive())?;
                let s = State {
                    scope: scope.clone(),
                    revision: initial_revision,
                    initial_revision,
                    desired: initial,
                    active_transaction: None,
                    initialized_at,
                    transactions: BTreeMap::new(),
                };
                store.save(&s).context("initialize durable journal")?;
                s
            }
        };
        ensure!(
            state.scope == scope,
            "state belongs to scope {:?}, not {:?}",
            state.scope,
            scope
        );
        validate_state(&state)?;
        let mut e = Self {
            store,
            state,
            backend,
            closed: false,
            maintenance: false,
            restarting: false,
            mqtt_passwords: None,
            dynamic_dns_secrets: None,
            timezone_check: None,
            #[cfg(test)]
            now: None,
        };
        if !reconcile {
            ensure!(
                e.state.active_transaction.is_none(),
                "factory reset requires completing the active transaction recovery first"
            );
            return Ok(e);
        }
        if let Some(id) = e.state.active_transaction.clone() {
            let t = e
                .state
                .transactions
                .get(&id)
                .context("missing active transaction")?;
            if t.status != "pending_confirmation" || e.now() >= t.confirmation_deadline {
                // Failure remains durable and blocks new writes; the operator can retry rollback.
                let _ = e.rollback(&id, "startup recovery");
            }
        }
        let expected = e.expected();
        if e.active()
            .is_none_or(|t| t.status == "pending_confirmation")
        {
            e.backend
                .repair(&expected)
                .context("startup runtime reconciliation")?;
        }
        Ok(e)
    }
    fn now(&self) -> DateTime<Utc> {
        #[cfg(test)]
        if let Some(t) = self.now {
            return t;
        }
        Utc::now()
    }
    fn active(&self) -> Option<&Transaction> {
        self.state
            .active_transaction
            .as_ref()
            .and_then(|id| self.state.transactions.get(id))
    }
    fn expected(&self) -> Config {
        self.active()
            .filter(|t| t.status == "pending_confirmation")
            .map(|t| t.candidate.clone())
            .unwrap_or_else(|| self.state.desired.clone())
    }
    fn persist(&mut self, next: State) -> Result<()> {
        if let Err(e) = self.store.save(&next) {
            if e.is::<crate::store::DurabilityError>() {
                self.closed = true;
            }
            return Err(e);
        }
        self.state = next;
        Ok(())
    }
    pub fn tick(&mut self) -> Result<()> {
        if self.closed {
            bail!("engine is shut down");
        }
        if let Some(t) = self.active() {
            if t.status == "pending_confirmation" && self.now() >= t.confirmation_deadline {
                let id = t.id.clone();
                self.rollback(&id, "confirmation timeout")?;
            }
        }
        Ok(())
    }
    /// Leaves pending confirmations durable for deadline-aware restart recovery.
    pub fn shutdown(&mut self) -> Result<()> {
        if !self.closed {
            self.tick()?;
            self.store.save(&self.state)?;
            self.closed = true;
        }
        Ok(())
    }
    pub fn set_upgrade_maintenance(&mut self, enabled: bool) -> Result<()> {
        ensure!(
            !enabled || (!self.closed && self.active().is_none()),
            "upgrade requires a healthy engine with no active transaction"
        );
        self.maintenance = enabled;
        Ok(())
    }
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        query: &str,
        actor: &str,
        permissions: &[String],
        body: &[u8],
    ) -> Reply {
        if self.closed {
            return ApiError::new(503, "engine is shut down").reply();
        }
        match self.route(method, path, query, actor, permissions, body) {
            Ok(r) => r,
            Err(e) => e.reply(),
        }
    }
    fn route(
        &mut self,
        method: &str,
        path: &str,
        query: &str,
        actor: &str,
        permissions: &[String],
        body: &[u8],
    ) -> ApiResult<Reply> {
        if actor.trim().is_empty() {
            return Err(ApiError::new(401, "valid API key required"));
        }
        if self.restarting && method != "GET" {
            return Err(ApiError::new(409, "daemon restart is pending"));
        }
        if self.maintenance && method != "GET" {
            return Err(ApiError::new(
                409,
                "configuration writes are blocked during software upgrade",
            ));
        }
        if path == "/api/v1/firewall/deny-log" {
            require(permissions, "firewall.logs.read")?;
            if method != "GET" {
                return Err(ApiError::new(405, "method not allowed"));
            }
            if !body.is_empty() {
                return Err(ApiError::new(
                    400,
                    "deny-log retrieval does not accept a body",
                ));
            }
            let query = crate::DenyLogQuery::parse(query).map_err(|e| ApiError::new(400, e))?;
            return self
                .backend
                .deny_log(&query)
                .map(|v| Reply::value(200, v))
                .map_err(service_error);
        }
        if path == "/api/v1/connections" || path.starts_with("/api/v1/connections/") {
            if method != "DELETE" {
                return Err(ApiError::new(405, "method not allowed"));
            }
            require(permissions, "connections.delete")?;
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "connection deletion does not accept query parameters",
                ));
            }
            let target = if path == "/api/v1/connections" {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct DeleteAll {
                    confirm: bool,
                }
                if !parse::<DeleteAll>(body)?.confirm {
                    return Err(ApiError::new(
                        400,
                        "deleting all connections requires confirm: true",
                    ));
                }
                None
            } else {
                let value = path.strip_prefix("/api/v1/connections/").unwrap();
                let id: u32 = value.parse().map_err(|_| {
                    ApiError::new(
                        400,
                        "connection ID must be a canonical unsigned 32-bit decimal",
                    )
                })?;
                if id.to_string() != value {
                    return Err(ApiError::new(
                        400,
                        "connection ID must be a canonical unsigned 32-bit decimal",
                    ));
                }
                let selector: crate::ConnectionTarget = parse(body)?;
                selector
                    .validate()
                    .map_err(|error| ApiError::new(400, error))?;
                Some((id, selector))
            };
            if self.active().is_some() {
                return Err(ApiError::new(
                    409,
                    "connection deletion requires no active transaction",
                ));
            }
            let value = self
                .backend
                .delete_connections(target.as_ref().map(|(id, selector)| (*id, selector)))
                .map_err(|error| {
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                    {
                        ApiError::new(
                            404,
                            "connection expired or no longer matches its ID, tuple and zone",
                        )
                    } else {
                        service_error(error)
                    }
                })?;
            return Ok(Reply::value(200, value));
        }
        if path == "/api/v1/firewall/hosts-and-rules" {
            if method != "DELETE" {
                return Err(ApiError::new(405, "method not allowed"));
            }
            require(permissions, "transactions.write")?;
            require(permissions, "firewall.write")?;
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "firewall bulk deletion does not accept query parameters",
                ));
            }
            let request: ClearFirewallRequest = parse(body)?;
            if !request.confirm {
                return Err(ApiError::new(
                    400,
                    "deleting all firewall hosts and forwarding rules requires confirm: true",
                ));
            }
            let mut config = self.state.desired.clone();
            config.firewall.rules.clear();
            if let Some(policies) = &mut config.firewall.policies {
                policies.hosts.clear();
                for interface in &mut policies.interfaces {
                    interface.rules.clear();
                }
            }
            let transaction = self.submit(
                actor,
                SubmitRequest {
                    base_revision: request.base_revision,
                    confirm_timeout_seconds: request.confirm_timeout_seconds,
                    config,
                    description: if request.description.trim().is_empty() {
                        "Clear firewall hosts and forwarding rules".into()
                    } else {
                        request.description
                    },
                },
                None,
            )?;
            return Ok(Reply {
                status: 202,
                location: Some(format!("/api/v1/transactions/{}", transaction.id)),
                body: value(transaction)?,
            });
        }
        if let Some(name) = path
            .strip_prefix("/api/v1/interfaces/")
            .and_then(|rest| rest.strip_suffix("/dhcp/retry"))
        {
            if method != "POST" {
                return Err(ApiError::new(405, "method not allowed"));
            }
            require(permissions, "interfaces.write")?;
            if !valid_interface_name(name) || !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "invalid interface name or query parameters",
                ));
            }
            if !body.is_empty() {
                let request: Value = parse(body)?;
                if !request.as_object().is_some_and(|fields| fields.is_empty()) {
                    return Err(ApiError::new(
                        400,
                        "DHCP retry accepts only an empty object or no body",
                    ));
                }
            }
            if self.active().is_some() {
                return Err(ApiError::new(
                    409,
                    "DHCP retry requires no active transaction",
                ));
            }
            let interface = self
                .state
                .desired
                .interfaces
                .iter()
                .find(|interface| interface.name == name)
                .ok_or_else(|| ApiError::new(404, "interface not found"))?;
            if !interface.up || !self.state.desired.dhcp_clients.contains_key(name) {
                return Err(ApiError::new(
                    409,
                    "interface must be up with DHCP configured",
                ));
            }
            self.backend
                .retry_dhcp(&self.state.desired, name)
                .map_err(|error| {
                    if error.downcast_ref::<crate::BackendDrift>().is_some() {
                        ApiError::new(409, error)
                    } else {
                        service_error(error)
                    }
                })?;
            return Ok(Reply::value(
                202,
                json!({"interface": name, "status": "retrying"}),
            ));
        }
        if method == "GET" {
            require(permissions, "state.read")?;
            if path == "/api/v1/statistics/firewall" && !body.is_empty() {
                return Err(ApiError::new(
                    400,
                    "firewall counters accept no request body",
                ));
            }
            return self.get(path, query).map(|v| Reply::value(200, v));
        }
        if method != "POST" {
            return Err(ApiError::new(405, "method not allowed"));
        }
        if path == "/api/v1/interfaces/discovered" {
            return Err(ApiError::new(405, "interface discovery is read-only"));
        }
        if [
            "/api/v1/services/bgp",
            "/api/v1/services/bgp/status",
            "/api/v1/routes/bgp",
            "/api/v1/routes/bgp/advertised",
        ]
        .contains(&path)
        {
            return Err(ApiError::new(
                405,
                "BGP endpoints are read-only; configure BGP through transactions",
            ));
        }
        if path == "/api/v1/statistics" || path.starts_with("/api/v1/statistics/") {
            return Err(ApiError::new(405, "statistics endpoints are read-only"));
        }
        require(permissions, "transactions.write")?;
        if path == "/api/v1/transactions" {
            let (r, ignored) = parse_submit(body)?;
            self.check_revision(r.base_revision)?;
            if r.config.software != SoftwareMetadata::default()
                && r.config.software != self.state.desired.software
            {
                return Err(ApiError::new(
                    422,
                    "software metadata is daemon-managed; omit it or submit the current value",
                ));
            }
            authorize(permissions, &self.state.desired, &r.config)?;
            let t = self.submit(actor, r, None)?;
            let mut reply_body = value(&t)?;
            reply_body["ignored_fields"] = json!(ignored);
            return Ok(Reply {
                status: 202,
                location: Some(format!("/api/v1/transactions/{}", t.id)),
                body: reply_body,
            });
        }
        if let Some(rest) = path.strip_prefix("/api/v1/revisions/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() != 2 || parts[1] != "restore" {
                return Err(ApiError::new(404, "endpoint not found"));
            }
            require(permissions, "state.read")?;
            let revision = parse_revision(parts[0])?;
            let r: RestoreRequest = parse(body)?;
            let config = self.revision_config(revision)?;
            self.check_revision(r.base_revision)?;
            authorize(permissions, &self.state.desired, &config)?;
            let description = if r.description.trim().is_empty() {
                format!("Restore revision {revision}")
            } else {
                r.description
            };
            let t = self.submit(
                actor,
                SubmitRequest {
                    base_revision: r.base_revision,
                    confirm_timeout_seconds: r.confirm_timeout_seconds,
                    config,
                    description,
                },
                Some(revision),
            )?;
            return Ok(Reply {
                status: 202,
                location: Some(format!("/api/v1/transactions/{}", t.id)),
                body: value(t)?,
            });
        }
        if let Some(rest) = path.strip_prefix("/api/v1/transactions/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() != 2 || !["confirm", "rollback"].contains(&parts[1]) {
                return Err(ApiError::new(404, "endpoint not found"));
            }
            let t = self
                .state
                .transactions
                .get(parts[0])
                .cloned()
                .ok_or_else(|| ApiError::new(404, "transaction not found"))?;
            authorize(permissions, &t.previous, &t.candidate)?;
            let t = if parts[1] == "confirm" {
                self.confirm(&t.id, actor)?
            } else {
                if t.status == "rolled_back" {
                    t
                } else {
                    if self.state.active_transaction.as_deref() != Some(&t.id) {
                        return Err(ApiError::new(409, "configuration conflict").transaction(t));
                    }
                    self.rollback(&t.id, &format!("rollback requested by {actor}"))
                        .map_err(internal_error)?;
                    self.state
                        .transactions
                        .get(&t.id)
                        .cloned()
                        .ok_or_else(|| service_error("transaction disappeared"))?
                }
            };
            return Ok(Reply::value(200, value(t)?));
        }
        if let Some(service) = path
            .strip_prefix("/api/v1/services/")
            .and_then(|p| p.strip_suffix("/reconcile"))
        {
            if ["mdns", "udp-broadcast-relay"].contains(&service)
                && (!query.is_empty() || !body.is_empty())
            {
                return Err(ApiError::new(
                    400,
                    "service repair does not accept query parameters or a body",
                ));
            }
            let permission = match service {
                "mdns" => "mdns.write",
                "udp-broadcast-relay" => "udp_broadcast_relay.write",
                "softflowd" => "softflowd.write",
                "dhcp-relay" => "interfaces.write",
                "gateway-monitoring" => "gateway_monitors.write",
                "ntp" => "ntp.write",
                "syslog" => "syslog.write",
                "vnstat" => "vnstat.write",
                _ => return Err(ApiError::new(404, "endpoint not found")),
            };
            require(permissions, "state.read")?;
            require(permissions, permission)?;
            let expected = self.expected();
            for (p, enabled) in [
                ("mdns.write", expected.mdns.enabled),
                (
                    "udp_broadcast_relay.write",
                    expected.udp_broadcast_relay.enabled,
                ),
                ("bgp.write", expected.bgp.enabled),
                ("ntp.write", expected.ntp.enabled),
                ("syslog.write", expected.syslog.enabled),
                ("vnstat.write", expected.vnstat.enabled),
                (
                    "softflowd.write",
                    expected.softflowd.iter().any(|s| s.enabled),
                ),
                (
                    "gateway_monitors.write",
                    expected.gateway_monitors.iter().any(|s| s.enabled),
                ),
                (
                    "interfaces.write",
                    expected.interfaces.iter().any(|l| l.dhcp_relay.enabled)
                        || !expected.dhcp_clients.is_empty()
                        || !expected.dns.is_empty(),
                ),
            ] {
                if enabled {
                    require(permissions, p)?;
                }
            }
            if self
                .active()
                .is_some_and(|t| t.status != "pending_confirmation")
            {
                return Err(ApiError::new(409, "transaction recovery is incomplete"));
            }
            let observed = self
                .backend
                .observe_for_repair(&expected)
                .map_err(|error| {
                    if error.downcast_ref::<crate::BackendDrift>().is_some() {
                        ApiError::new(409, error)
                    } else {
                        service_error(error)
                    }
                })?;
            if !observed.same_settings(&expected) {
                return Err(ApiError::new(409, "managed state has drifted"));
            }
            let runtime = self.backend.repair(&expected).map_err(internal_error)?;
            return Ok(Reply::value(200, runtime));
        }
        Err(ApiError::new(404, "endpoint not found"))
    }
    fn check_revision(&self, revision: Version) -> ApiResult<()> {
        if revision != self.state.revision {
            return Err(ApiError::new(409, "configuration conflict"));
        }
        Ok(())
    }
    pub fn saved_configuration(&self) -> &Config {
        &self.state.desired
    }

    pub fn committed_revision(&self) -> Version {
        self.state.revision
    }

    pub fn is_initial_configuration(&self) -> bool {
        self.state.revision == self.state.initial_revision && self.state.transactions.is_empty()
    }

    pub fn update_software_metadata(&mut self, metadata: SoftwareMetadata) -> Result<()> {
        ensure!(!self.closed, "engine is shut down");
        metadata.validate()?;
        let mut next = self.state.clone();
        next.desired.software = metadata;
        if next.desired != self.state.desired {
            self.persist(next)?;
        }
        Ok(())
    }

    pub fn configuration_busy(&self) -> bool {
        self.restarting || self.maintenance || self.active().is_some()
    }

    pub fn begin_restart(&mut self) -> Result<()> {
        ensure!(
            !self.closed && !self.configuration_busy(),
            "configuration transaction, upgrade or restart is active"
        );
        self.restarting = true;
        Ok(())
    }
    pub fn cancel_restart(&mut self) {
        self.restarting = false;
    }
    pub fn prepare_dns_lookup(
        &mut self,
        request: &crate::DNSLookupRequest,
    ) -> Result<crate::DNSLookup> {
        ensure!(
            !self.closed && !self.configuration_busy(),
            "configuration transaction, upgrade or restart is active"
        );
        self.backend
            .prepare_dns_lookup(&self.state.desired, request)
    }

    pub fn restart_process(&mut self, target: &str) -> Reply {
        let c = self.saved_configuration();
        let enabled = match target {
            "ntp" => Some(c.ntp.enabled),
            "syslog" => Some(c.syslog.enabled),
            "mdns" => Some(c.mdns.enabled),
            "bgp" => Some(c.bgp.enabled),
            "vnstat" => Some(c.vnstat.enabled),
            "dhcp-relay" => Some(c.interfaces.iter().any(|link| link.dhcp_relay.enabled)),
            "dhcp-gateway-monitors" => Some(
                c.gateway_monitors
                    .iter()
                    .any(|m| m.enabled && m.mode == crate::GatewayMode::Dhcp),
            ),
            "link-diagnostics" => Some(true),
            _ if target.starts_with("udp-broadcast-relay:") => c
                .udp_broadcast_relay
                .instances
                .iter()
                .find(|instance| target == format!("udp-broadcast-relay:{}", instance.id))
                .map(|instance| c.udp_broadcast_relay.enabled && instance.enabled),
            _ if target.starts_with("flow:") => c
                .softflowd
                .iter()
                .find(|f| Some(f.name.as_str()) == target.strip_prefix("flow:"))
                .map(|f| f.enabled),
            _ if target.starts_with("gateway:") => c
                .gateway_monitors
                .iter()
                .find(|m| {
                    Some(m.name.as_str()) == target.strip_prefix("gateway:")
                        && m.mode == crate::GatewayMode::Explicit
                })
                .map(|m| m.enabled),
            _ if target.starts_with("dhcp-client:") => c
                .dhcp_clients
                .get(target.trim_start_matches("dhcp-client:"))
                .map(|_| true),
            _ => None,
        };
        if self.closed {
            return service_error("engine is shut down").reply();
        }
        if self.configuration_busy() {
            return ApiError::new(
                409,
                "configuration transaction, upgrade or restart is active",
            )
            .reply();
        }
        match enabled {
            None => return ApiError::new(404, "managed worker target not found").reply(),
            Some(false) => return ApiError::new(409, "managed worker is disabled").reply(),
            Some(true) => {}
        }
        match self.backend.restart_process(&self.state.desired, target) {
            Ok(status) => Reply::value(
                200,
                json!({"target":target,"status":if status["state"]=="simulated"{"simulated"}else{"restarted"},"worker":status}),
            ),
            Err(error) => service_error(error).reply(),
        }
    }

    pub fn configure_mqtt(&mut self, references: Option<BTreeSet<String>>) {
        self.mqtt_passwords = references;
    }

    pub fn configure_dynamic_dns(&mut self, references: Option<BTreeSet<String>>) {
        self.dynamic_dns_secrets = references;
    }

    /// `None` means this backend cannot manage host settings; managed values are then rejected.
    pub fn configure_system(&mut self, timezone_check: Option<TimezoneCheck>) {
        self.timezone_check = timezone_check;
    }

    pub fn factory_reset(&mut self, config: Config) -> Result<Transaction> {
        ensure!(!self.closed, "engine is shut down");
        let request = SubmitRequest {
            base_revision: self.state.revision,
            confirm_timeout_seconds: 300,
            config,
            description: "Explicit local factory configuration reset".into(),
        };
        let transaction = self
            .submit_inner("local-factory-reset", request, None, true)
            .map_err(|error| anyhow::anyhow!(error.error))?;
        self.confirm(&transaction.id, "local-factory-reset")
            .map_err(|error| anyhow::anyhow!(error.error))
    }

    fn submit(
        &mut self,
        actor: &str,
        r: SubmitRequest,
        restored: Option<Version>,
    ) -> ApiResult<Transaction> {
        self.submit_inner(actor, r, restored, false)
    }

    fn submit_inner(
        &mut self,
        actor: &str,
        mut r: SubmitRequest,
        restored: Option<Version>,
        factory_reset: bool,
    ) -> ApiResult<Transaction> {
        r.config.normalize();
        r.config.software = self.state.desired.software.clone();
        r.description = r.description.trim().into();
        if r.description.len() > 1024 {
            return Err(ApiError::new(422, "description must not exceed 1024 bytes"));
        }
        r.config.validate().map_err(|e| ApiError::new(422, e))?;
        for entry in &r.config.dynamic_dns {
            if !self
                .dynamic_dns_secrets
                .as_ref()
                .is_some_and(|refs| refs.contains(&entry.secret_ref))
            {
                return Err(ApiError::new(
                    422,
                    "Dynamic DNS backend or secret reference is unavailable",
                ));
            }
        }
        if r.config.mqtt.enabled && self.mqtt_passwords.is_none() {
            return Err(ApiError::new(
                422,
                "MQTT streaming is unavailable for this backend",
            ));
        }
        let system = &r.config.system;
        // Only changed host settings are checked, so unrelated edits survive a missing zone database.
        // The cosmetic domain is stored only and needs no host support.
        let desired = &self.state.desired.system;
        if (system.hostname != desired.hostname || system.timezone != desired.timezone)
            && (!system.hostname.is_empty() || !system.timezone.is_empty())
        {
            let Some(check) = &self.timezone_check else {
                return Err(ApiError::new(
                    422,
                    "host system settings are unavailable for this backend",
                ));
            };
            if !system.timezone.is_empty() && !check(&system.timezone) {
                return Err(ApiError::new(
                    422,
                    "timezone is not available on this host; list valid names with GET /api/v1/system/timezones",
                ));
            }
        }
        if !r.config.mqtt.password_ref.is_empty()
            && !self
                .mqtt_passwords
                .as_ref()
                .is_some_and(|references| references.contains(&r.config.mqtt.password_ref))
        {
            return Err(ApiError::new(422, "MQTT password reference is unavailable"));
        }
        if !(10..=300).contains(&r.confirm_timeout_seconds) {
            return Err(ApiError::new(
                422,
                "confirmation timeout must be 10..300 seconds",
            ));
        }
        self.check_revision(r.base_revision)?;
        if self.active().is_some() {
            return Err(ApiError::new(409, "configuration conflict"));
        }
        if !factory_reset {
            let observed = self
                .backend
                .observe(&self.state.desired)
                .map_err(internal_error)?;
            if !observed.same_settings(&self.state.desired) {
                return Err(ApiError::new(409, "managed state has drifted"));
            }
        }
        for before in &self.state.desired.interfaces {
            if let Some(after) = r.config.interfaces.iter().find(|l| l.name == before.name) {
                if before.kind != after.kind
                    || (before.vlan.is_some() && after.vlan.is_some() && before.vlan != after.vlan)
                {
                    return Err(ApiError::new(
                        422,
                        "interface kind and VLAN identity changes require separate confirmed deletion and creation",
                    ));
                }
            }
        }
        let now = self.now();
        let mut id = [0u8; 16];
        rand::thread_rng()
            .try_fill_bytes(&mut id)
            .map_err(internal_error)?;
        let id = hex::encode(id);
        let t = Transaction {
            id: id.clone(),
            actor: actor.into(),
            status: "applying".into(),
            base_revision: r.base_revision,
            committed_revision: None,
            candidate: r.config,
            previous: self.state.desired.clone(),
            confirmation_deadline: now + Duration::seconds(r.confirm_timeout_seconds),
            error: String::new(),
            description: r.description,
            submitted_at: now,
            committed_at: None,
            committed_by: String::new(),
            restored_from_revision: restored,
        };
        let mut next = self.state.clone();
        next.active_transaction = Some(id.clone());
        next.transactions.insert(id.clone(), t.clone());
        self.persist(next)
            .map_err(|e| internal_error(format!("persist intent: {e}")))?;
        let applied = (|| -> Result<()> {
            if factory_reset {
                self.backend.factory_reset(&t.previous, &t.candidate)?;
            } else {
                self.backend.apply(&t.previous, &t.candidate)?;
            }
            let actual = self.backend.observe(&t.candidate)?;
            ensure!(
                actual.same_settings(&t.candidate),
                "post-apply verification mismatch"
            );
            ensure!(
                self.now() < t.confirmation_deadline,
                "confirmation deadline elapsed while applying"
            );
            Ok(())
        })();
        if let Err(e) = applied {
            let recovery = self.rollback(&id, &format!("apply failed: {e:#}"));
            let t = self.state.transactions.get(&id).cloned().unwrap_or(t);
            return Err(internal_error(match recovery {
                Ok(()) => format!("apply failed: {e:#}"),
                Err(r) => format!("apply failed: {e:#}; {r:#}"),
            })
            .transaction(t));
        }
        let mut next = self.state.clone();
        let pending = next
            .transactions
            .get_mut(&id)
            .ok_or_else(|| service_error("missing durable transaction"))?;
        pending.status = "pending_confirmation".into();
        if let Err(e) = self.persist(next) {
            let _ = self.rollback(&id, "could not persist pending confirmation");
            return Err(internal_error(e)
                .transaction(self.state.transactions.get(&id).cloned().unwrap_or(t)));
        }
        self.state
            .transactions
            .get(&id)
            .cloned()
            .ok_or_else(|| service_error("missing pending transaction"))
    }
    fn confirm(&mut self, id: &str, actor: &str) -> ApiResult<Transaction> {
        let t = self
            .state
            .transactions
            .get(id)
            .cloned()
            .ok_or_else(|| ApiError::new(404, "transaction not found"))?;
        if t.status == "committed" {
            return Ok(t);
        }
        if self.state.active_transaction.as_deref() != Some(id)
            || t.status != "pending_confirmation"
        {
            return Err(ApiError::new(409, "configuration conflict").transaction(t));
        }
        if self.now() >= t.confirmation_deadline {
            let _ = self.rollback(id, "confirmation expired");
            return Err(ApiError::new(409, "confirmation expired")
                .transaction(self.state.transactions.get(id).cloned().unwrap_or(t)));
        }
        let observed = self
            .backend
            .observe(&t.candidate)
            .map_err(|e| internal_error(e).transaction(t.clone()))?;
        if !observed.same_settings(&t.candidate) {
            return Err(ApiError::new(409, "candidate drifted before confirmation").transaction(t));
        }
        let committed_at = self.now();
        if committed_at >= t.confirmation_deadline {
            let _ = self.rollback(id, "confirmation expired during verification");
            return Err(ApiError::new(409, "confirmation expired")
                .transaction(self.state.transactions.get(id).cloned().unwrap_or(t)));
        }
        let mut next = self.state.clone();
        next.revision = self
            .state
            .revision
            .next(committed_at.date_naive())
            .map_err(service_error)?;
        next.desired = t.candidate.clone();
        next.desired.software = self.state.desired.software.clone();
        next.active_transaction = None;
        let committed = next
            .transactions
            .get_mut(id)
            .ok_or_else(|| service_error("transaction disappeared"))?;
        committed.status = "committed".into();
        committed.committed_at = Some(committed_at);
        committed.committed_by = actor.into();
        committed.committed_revision = Some(next.revision);
        let result = committed.clone();
        self.persist(next)
            .map_err(|e| internal_error(format!("persist confirmation: {e}")))?;
        Ok(result)
    }
    fn rollback(&mut self, id: &str, reason: &str) -> Result<()> {
        let t = self
            .state
            .transactions
            .get(id)
            .cloned()
            .context("transaction not found")?;
        let mut next = self.state.clone();
        let active = next
            .transactions
            .get_mut(id)
            .context("missing transaction")?;
        active.status = "rolling_back".into();
        active.error = reason.into();
        if let Err(e) = self.persist(next) {
            if let Some(active) = self.state.transactions.get_mut(id) {
                active.status = "recovery_failed".into();
                active.error = format!("{reason}; persist rollback intent: {e}");
            }
            return Err(e.context("persist rollback intent; writes blocked"));
        }
        let result = (|| -> Result<()> {
            self.backend.apply(&t.candidate, &t.previous)?;
            let observed = self.backend.observe(&t.previous)?;
            ensure!(
                observed.same_settings(&t.previous),
                "rollback verification mismatch"
            );
            Ok(())
        })();
        if let Err(e) = result {
            let mut next = self.state.clone();
            if let Some(active) = next.transactions.get_mut(id) {
                active.status = "recovery_failed".into();
                active.error = format!("{reason}; rollback: {e:#}");
            }
            self.persist(next).context("persist failed recovery")?;
            return Err(e.context("rollback failed; writes blocked"));
        }
        let mut next = self.state.clone();
        next.active_transaction = None;
        if let Some(active) = next.transactions.get_mut(id) {
            active.status = "rolled_back".into();
        }
        if let Err(e) = self.persist(next) {
            if let Some(active) = self.state.transactions.get_mut(id) {
                active.status = "recovery_failed".into();
                active.error = format!("{reason}; persist rollback result: {e}");
            }
            return Err(e.context("persist rollback result; writes blocked"));
        }
        Ok(())
    }
    fn revision_config(&self, number: Version) -> ApiResult<Config> {
        if number == self.state.revision {
            return Ok(self.state.desired.clone());
        }
        if number == self.state.initial_revision {
            return Ok(self
                .state
                .transactions
                .values()
                .find(|t| t.status == "committed" && t.base_revision == self.state.initial_revision)
                .map(|t| t.previous.clone())
                .unwrap_or_else(|| self.state.desired.clone()));
        }
        self.state
            .transactions
            .values()
            .find(|t| t.status == "committed" && t.committed_revision == Some(number))
            .map(|t| t.candidate.clone())
            .ok_or_else(|| ApiError::new(404, format!("revision not found: {number}")))
    }
    fn revision_metadata(&self, number: Version) -> ApiResult<Value> {
        if number == self.state.initial_revision {
            return Ok(
                json!({"revision":number,"current":self.state.revision==number,"submitted_at":null,
            "committed_at":self.state.initialized_at,"committed_by":"system","description":"Initial configuration"}),
            );
        }
        let t = self
            .state
            .transactions
            .values()
            .find(|t| t.status == "committed" && t.committed_revision == Some(number))
            .ok_or_else(|| ApiError::new(404, "revision not found"))?;
        let mut v = json!({"revision":number,"current":number==self.state.revision,"transaction_id":t.id,"submitted_at":t.submitted_at,
            "committed_at":t.committed_at,"submitted_by":t.actor,"committed_by":t.committed_by});
        if !t.description.is_empty() {
            v["description"] = json!(t.description);
        }
        if let Some(source) = t.restored_from_revision {
            v["restored_from_revision"] = json!(source);
        }
        Ok(v)
    }
    fn get(&mut self, path: &str, query: &str) -> ApiResult<Value> {
        if path == "/api/v1/interfaces/discovered" {
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "interface discovery does not accept query parameters",
                ));
            }
            return self
                .backend
                .discover_interfaces()
                .map_err(|e| service_error(format!("interface discovery failed: {e}")));
        }
        if path == "/api/v1/transactions" {
            return value(&self.state.transactions);
        }
        if let Some(id) = path.strip_prefix("/api/v1/transactions/") {
            return self
                .state
                .transactions
                .get(id)
                .ok_or_else(|| ApiError::new(404, "transaction not found"))
                .and_then(value);
        }
        if path == "/api/v1/revisions" {
            let (limit, before) = revision_query(query)?;
            let mut result = vec![];
            let mut next = None;
            let mut revisions: Vec<_> = self
                .state
                .transactions
                .values()
                .filter_map(|transaction| transaction.committed_revision)
                .collect();
            revisions.push(self.state.initial_revision);
            revisions.sort_unstable_by(|a, b| b.cmp(a));
            for n in revisions
                .into_iter()
                .filter(|n| before.is_none_or(|b| *n < b))
            {
                if result.len() == limit {
                    next = result.last().map(|v: &Value| v["revision"].clone());
                    break;
                }
                result.push(self.revision_metadata(n)?);
            }
            let mut page = json!({"revisions":result});
            if let Some(n) = next {
                page["next_before_revision"] = json!(n);
            }
            return Ok(page);
        }
        if let Some(n) = path.strip_prefix("/api/v1/revisions/") {
            if n.contains('/') {
                return Err(ApiError::new(404, "endpoint not found"));
            }
            let n = if n == "latest" {
                if !query.is_empty() {
                    return Err(ApiError::new(
                        400,
                        "latest revision does not accept query parameters",
                    ));
                }
                self.state.revision
            } else {
                parse_revision(n)?
            };
            let config = self.revision_config(n)?;
            let mut metadata = self.revision_metadata(n)?;
            metadata["config"] = value(config)?;
            return Ok(metadata);
        }
        if path == "/api/v1/kernel/tunables/catalog" {
            return value(kernel_catalog());
        }
        if path == "/api/v1/kernel/tunables" {
            let expected = self.expected();
            let runtime = self.backend.runtime(&expected).map_err(service_error)?;
            if let Some(kernel) = runtime.get("kernel_tunables") {
                let mut kernel = kernel.clone();
                kernel["desired"] = value(&self.state.desired.kernel)?;
                return Ok(kernel);
            }
            if !expected.kernel.namespace.is_empty() || !expected.kernel.host.is_empty() {
                return Err(service_error(
                    "backend does not expose kernel rollback snapshots",
                ));
            }
            let empty = KernelConfig::default();
            return Ok(
                json!({"desired":self.state.desired.kernel,"configured":expected.kernel,"effective":empty,
                "observed":empty,"captured_original":empty,"drift":false}),
            );
        }
        if path == "/api/v1/statistics" || path.starts_with("/api/v1/statistics/") {
            validate_statistics(path, query)?;
            let config = self.expected();
            let mut response = self.backend.statistics(&config, path, query).map_err(|e| {
                if [
                    "statistics interface not found",
                    "gateway monitor not found",
                ]
                .contains(&e.to_string().as_str())
                {
                    ApiError::new(404, e)
                } else {
                    service_error(e)
                }
            })?;
            if path == "/api/v1/statistics/firewall" {
                if !response.is_object() {
                    return Err(service_error("backend returned invalid firewall counters"));
                }
                annotate_rule_origins(&mut response, &config).map_err(service_error)?;
                response["config_revision"] = value(self.state.revision)?;
                response["transaction_id"] =
                    value(self.active().map(|transaction| &transaction.id))?;
            }
            return Ok(response);
        }
        if [
            "/api/v1/services/bgp",
            "/api/v1/services/bgp/status",
            "/api/v1/routes/bgp",
            "/api/v1/routes/bgp/advertised",
        ]
        .contains(&path)
        {
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "BGP endpoints do not accept query parameters",
                ));
            }
            if path == "/api/v1/services/bgp" {
                return value(&self.state.desired.bgp);
            }
            let mut status = self
                .backend
                .bgp_status(&self.expected())
                .map_err(service_error)?;
            if matches!(path, "/api/v1/routes/bgp" | "/api/v1/routes/bgp/advertised") {
                let routes = if path.ends_with("/advertised") {
                    "advertised_routes"
                } else {
                    "routes"
                };
                return Ok(
                    json!({"source":"bgp","scope":status["scope"],"state":status["state"],"error":status["error"],"routes":status[routes]}),
                );
            }
            let summary = status
                .as_object_mut()
                .ok_or_else(|| service_error("invalid BGP status"))?;
            summary.remove("routes");
            summary.remove("advertised_routes");
            return Ok(status);
        }
        if path == "/api/v1/services/mdns/status" {
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "mDNS status does not accept query parameters",
                ));
            }
            return self
                .backend
                .mdns_status(&self.expected())
                .map_err(service_error);
        }
        let service_status = path
            .strip_prefix("/api/v1/services/")
            .and_then(|s| s.strip_suffix("/status"));
        if service_status == Some("udp-broadcast-relay") && !query.is_empty() {
            return Err(ApiError::new(
                400,
                "UDP relay status does not accept query parameters",
            ));
        }
        if path == "/api/v1/runtime"
            || path == "/api/v1/parent-interfaces"
            || service_status.is_some()
        {
            if service_status.is_some_and(|s| {
                ![
                    "ntp",
                    "mdns",
                    "udp-broadcast-relay",
                    "syslog",
                    "vnstat",
                    "softflowd",
                    "dhcp-relay",
                    "gateway-monitoring",
                ]
                .contains(&s)
            }) {
                return Err(ApiError::new(404, "endpoint not found"));
            }
            let config = self.expected();
            let mut runtime = self.backend.runtime(&config).map_err(service_error)?;
            runtime["capabilities"]["gateway_monitor_modes"] = json!(["explicit", "dhcp"]);
            runtime["capabilities"]["dhcp_gateway_monitor_address_families"] = json!(["ipv4"]);
            let error = runtime.get("error").cloned().unwrap_or(json!(""));
            return match (path, service_status) {
                ("/api/v1/runtime", _) => Ok(runtime),
                ("/api/v1/parent-interfaces", _) => Ok(runtime["parent_interfaces"].clone()),
                (_, Some("softflowd")) => {
                    Ok(json!({"instances":runtime["softflowd"],"error":error}))
                }
                (_, Some("dhcp-relay")) => {
                    Ok(json!({"interfaces":runtime["dhcp_relay"],"error":error}))
                }
                (_, Some("gateway-monitoring")) => {
                    Ok(json!({"monitors":runtime["gateway_monitors"],"error":error}))
                }
                (_, Some(service)) => {
                    let statuses = runtime["appliance_services"]
                        .as_array()
                        .ok_or_else(|| service_error("backend returned invalid service statuses"))?
                        .iter()
                        .filter(|s| s["name"] == service)
                        .cloned()
                        .collect::<Vec<_>>();
                    Ok(json!({"instances":statuses,"error":error}))
                }
                _ => Err(ApiError::new(404, "endpoint not found")),
            };
        }
        if path == "/api/v1/services/udp-broadcast-relay" {
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "UDP relay configuration does not accept query parameters",
                ));
            }
            return value(&self.state.desired.udp_broadcast_relay);
        }
        if path == "/api/v1/services/mdns" {
            if !query.is_empty() {
                return Err(ApiError::new(
                    400,
                    "mDNS configuration does not accept query parameters",
                ));
            }
            return value(&self.state.desired.mdns);
        }
        let known = [
            "/api/v1/state",
            "/api/v1/interfaces",
            "/api/v1/vlans",
            "/api/v1/gateway-monitors",
            "/api/v1/services/softflowd",
            "/api/v1/services/ntp",
            "/api/v1/services/syslog",
            "/api/v1/services/vnstat",
            "/api/v1/routes",
            "/api/v1/firewall/rules",
            "/api/v1/firewall/hosts",
            "/api/v1/firewall/interface-policies",
            "/api/v1/firewall/nat",
            "/api/v1/wireguard",
        ];
        if !known.contains(&path) && !path.starts_with("/api/v1/interfaces/") {
            return Err(ApiError::new(404, "endpoint not found"));
        }
        let expected = self.expected();
        let observed = self
            .backend
            .observe(&expected)
            .map_err(|e| service_error(format!("observation failed: {e}")))?;
        match path {
            "/api/v1/state" => {
                let mut v = json!({"revision":self.state.revision,"desired":self.state.desired,"observed":observed,"drift":observed.normalized()!=expected.normalized()});
                if let Some(t) = self.active() {
                    v["active_transaction"] = value(t)?;
                }
                Ok(v)
            }
            "/api/v1/interfaces" => value(observed.interfaces),
            "/api/v1/vlans" => value(
                observed
                    .interfaces
                    .into_iter()
                    .filter(|l| l.vlan.is_some())
                    .collect::<Vec<_>>(),
            ),
            "/api/v1/wireguard" => value(
                observed
                    .interfaces
                    .into_iter()
                    .filter(|l| l.wireguard.is_some())
                    .collect::<Vec<_>>(),
            ),
            "/api/v1/routes" => value(observed.routes),
            "/api/v1/gateway-monitors" => value(observed.gateway_monitors),
            "/api/v1/services/softflowd" => value(observed.softflowd),
            "/api/v1/services/ntp" => value(observed.ntp),
            "/api/v1/services/syslog" => value(observed.syslog),
            "/api/v1/services/vnstat" => value(observed.vnstat),
            "/api/v1/firewall/rules" => value(observed.firewall),
            "/api/v1/firewall/nat" => value(observed.firewall.nat),
            "/api/v1/firewall/hosts" => value(
                observed
                    .firewall
                    .policies
                    .map(|p| p.hosts)
                    .unwrap_or_default(),
            ),
            "/api/v1/firewall/interface-policies" => value(
                observed
                    .firewall
                    .policies
                    .map(|p| p.interfaces)
                    .unwrap_or_default(),
            ),
            _ => {
                let name = path
                    .strip_prefix("/api/v1/interfaces/")
                    .ok_or_else(|| ApiError::new(404, "endpoint not found"))?;
                value(
                    observed
                        .interfaces
                        .into_iter()
                        .find(|l| l.name == name)
                        .ok_or_else(|| ApiError::new(404, "interface not found"))?,
                )
            }
        }
    }
}

fn parse_revision(s: &str) -> ApiResult<Version> {
    s.parse().map_err(|error| ApiError::new(400, error))
}
fn revision_query(query: &str) -> ApiResult<(usize, Option<Version>)> {
    let mut limit = 50;
    let mut before = None;
    let mut seen = BTreeSet::new();
    if !query.is_empty() {
        for part in query.split('&') {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| ApiError::new(400, "invalid revision query"))?;
            let k = form_decode(k)?;
            let v = form_decode(v)?;
            if v.is_empty() || !seen.insert(k.clone()) {
                return Err(ApiError::new(
                    400,
                    "revision parameters require one nonempty value",
                ));
            }
            match k.as_str() {
                "limit" => {
                    limit = v
                        .parse()
                        .map_err(|_| ApiError::new(400, "revision list limit must be 1..100"))?;
                    if !(1..=100).contains(&limit) {
                        return Err(ApiError::new(400, "revision list limit must be 1..100"));
                    }
                }
                "before_revision" => before = Some(parse_revision(&v)?),
                _ => {
                    return Err(ApiError::new(
                        400,
                        format!("unknown revision query parameter {k:?}"),
                    ));
                }
            }
        }
    }
    Ok((limit, before))
}
fn form_decode(s: &str) -> ApiResult<String> {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| ApiError::new(400, "invalid query escape"))?;
                let text = std::str::from_utf8(hex)
                    .map_err(|_| ApiError::new(400, "invalid query escape"))?;
                let byte = u8::from_str_radix(text, 16)
                    .map_err(|_| ApiError::new(400, "invalid query escape"))?;
                result.push(byte);
                i += 3;
            }
            b'+' => {
                result.push(b' ');
                i += 1;
            }
            byte => {
                result.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(result).map_err(|_| ApiError::new(400, "query must be UTF-8"))
}
fn validate_statistics(path: &str, query: &str) -> ApiResult<()> {
    if path == "/api/v1/statistics/connections" {
        crate::ConnectionQuery::parse(query).map_err(|error| ApiError::new(400, error))?;
        return Ok(());
    }
    if !query.is_empty() {
        return Err(ApiError::new(
            400,
            "statistics endpoints do not accept query parameters",
        ));
    }
    if [
        "/api/v1/statistics",
        "/api/v1/statistics/interfaces",
        "/api/v1/statistics/protocols",
        "/api/v1/statistics/host",
        "/api/v1/statistics/firewall",
        "/api/v1/statistics/link-diagnostics",
        "/api/v1/statistics/gateways",
        "/api/v1/statistics/vnstat",
    ]
    .contains(&path)
    {
        return Ok(());
    }
    if let Some(name) = path.strip_prefix("/api/v1/statistics/interfaces/") {
        if name.is_empty() || name.contains('/') {
            return Err(ApiError::new(404, "statistics endpoint not found"));
        }
        if name.len() > 15
            || [".", ".."].contains(&name)
            || name.contains(['\0', ':', ' ', '\t', '\n', '\r', '\x0b', '\x0c'])
        {
            return Err(ApiError::new(400, "invalid statistics interface"));
        }
        return Ok(());
    }
    if let Some(name) = path.strip_prefix("/api/v1/statistics/gateways/") {
        if name.is_empty() || name.contains('/') {
            return Err(ApiError::new(404, "statistics endpoint not found"));
        }
        if name.len() > 32
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(ApiError::new(400, "invalid statistics monitor"));
        }
        return Ok(());
    }
    Err(ApiError::new(404, "statistics endpoint not found"))
}
#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

pub fn validate_offline_state(payload: &[u8]) -> Result<()> {
    let state: State = serde_json::from_slice(payload).context("invalid converted state")?;
    validate_state(&state)?;
    ensure!(
        state.active_transaction.is_none(),
        "finish or recover the active transaction with the previous binary before conversion"
    );
    Ok(())
}

fn validate_state(s: &State) -> Result<()> {
    s.desired
        .validate()
        .context("invalid desired configuration")?;
    ensure!(
        s.desired == s.desired.normalized(),
        "desired configuration is not normalized"
    );
    let mut records = BTreeMap::new();
    let initial = s
        .transactions
        .values()
        .find(|t| t.status == "committed" && t.base_revision == s.initial_revision)
        .map(|t| t.previous.clone())
        .unwrap_or_else(|| s.desired.clone());
    ensure!(
        s.initial_revision == Version::first(s.initialized_at.date_naive())?,
        "invalid initial revision"
    );
    records.insert(s.initial_revision, initial);
    let mut active = 0;
    for (id, t) in &s.transactions {
        ensure!(
            id == &t.id
                && id.len() == 32
                && id.bytes().all(|c| c.is_ascii_hexdigit())
                && !t.actor.trim().is_empty(),
            "invalid transaction identity"
        );
        ensure!(
            [
                "applying",
                "pending_confirmation",
                "rolling_back",
                "recovery_failed",
                "rolled_back",
                "committed"
            ]
            .contains(&t.status.as_str()),
            "invalid transaction status"
        );
        t.previous.validate()?;
        t.candidate.validate()?;
        ensure!(
            t.previous == t.previous.normalized() && t.candidate == t.candidate.normalized(),
            "transaction configuration is not normalized"
        );
        ensure!(
            t.description.len() <= 1024 && t.description.trim() == t.description,
            "invalid transaction description"
        );
        let timeout = t.confirmation_deadline - t.submitted_at;
        ensure!(
            timeout >= Duration::seconds(10) && timeout <= Duration::seconds(300),
            "invalid transaction deadline"
        );
        ensure!(
            t.submitted_at >= s.initialized_at,
            "transaction predates journal initialization"
        );
        if [
            "applying",
            "pending_confirmation",
            "rolling_back",
            "recovery_failed",
        ]
        .contains(&t.status.as_str())
        {
            active += 1;
            ensure!(
                s.active_transaction.as_deref() == Some(id.as_str())
                    && t.base_revision == s.revision,
                "inconsistent active transaction"
            );
        }

        if t.status == "committed" {
            ensure!(
                t.base_revision < s.revision
                    && t.committed_at
                        .is_some_and(|at| at >= t.submitted_at && at < t.confirmation_deadline)
                    && !t.committed_by.trim().is_empty(),
                "invalid committed transaction metadata"
            );
            ensure!(
                records
                    .insert(
                        t.committed_revision.context("missing committed revision")?,
                        t.candidate.clone()
                    )
                    .is_none(),
                "duplicate committed revision"
            );
        } else {
            ensure!(
                t.committed_at.is_none()
                    && t.committed_by.is_empty()
                    && t.committed_revision.is_none(),
                "noncommitted transaction has commitment metadata"
            );
        }
    }
    ensure!(
        active == usize::from(s.active_transaction.is_some()),
        "invalid active transaction pointer"
    );
    let mut previous = s.initial_revision;
    for (revision, config) in records.iter().skip(1) {
        let transaction = s
            .transactions
            .values()
            .find(|t| t.committed_revision == Some(*revision))
            .context("revision archive is incomplete")?;
        ensure!(
            transaction.base_revision == previous
                && previous.next(
                    transaction
                        .committed_at
                        .context("missing commit timestamp")?
                        .date_naive()
                )? == *revision,
            "revision archive is incomplete"
        );
        ensure!(
            config.same_settings(&transaction.candidate),
            "invalid revision configuration"
        );
        previous = *revision;
    }
    ensure!(previous == s.revision, "revision archive is incomplete");
    ensure!(
        records
            .get(&s.revision)
            .is_some_and(|config| config.same_settings(&s.desired)),
        "current configuration does not match revision archive"
    );
    for t in s.transactions.values() {
        ensure!(
            records
                .get(&t.base_revision)
                .is_some_and(|config| config.same_settings(&t.previous)),
            "transaction previous configuration disagrees with base revision"
        );
        if let Some(from) = t.restored_from_revision {
            ensure!(
                from <= t.base_revision
                    && records
                        .get(&from)
                        .is_some_and(|config| config.same_settings(&t.candidate)),
                "inconsistent restoration provenance"
            );
        }
    }
    Ok(())
}
