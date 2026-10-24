use crate::{Backend, Config, KernelConfig, kernel_catalog, store::Store, valid_interface_name};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const PERMISSIONS: &[&str] = &[
    "state.read",
    "transactions.write",
    "interfaces.write",
    "routes.write",
    "policy.write",
    "firewall.write",
    "nat.write",
    "wireguard.write",
    "softflowd.write",
    "gateway_monitors.write",
    "ntp.write",
    "syslog.write",
    "vnstat.write",
    "kernel.namespace.write",
    "kernel.host.write",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub id: String,
    pub actor: String,
    pub status: String,
    pub base_revision: u64,
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
    pub restored_from_revision: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    scope: String,
    revision: u64,
    desired: Config,
    active_transaction: Option<String>,
    initialized_at: DateTime<Utc>,
    transactions: BTreeMap<String, Transaction>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    #[serde(default)]
    base_revision: u64,
    confirm_timeout_seconds: i64,
    config: Config,
    #[serde(default)]
    description: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRequest {
    #[serde(default)]
    base_revision: u64,
    confirm_timeout_seconds: i64,
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
fn value<T: Serialize>(v: T) -> ApiResult<Value> {
    serde_json::to_value(v).map_err(service_error)
}
fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    if body.len() > 1 << 20 {
        return Err(ApiError::new(400, "request exceeds 1048576 bytes"));
    }
    serde_json::from_slice(body).map_err(|e| ApiError::new(400, format!("invalid JSON: {e}")))
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
        ("policy.write", a.policy_rules != b.policy_rules),
        ("softflowd.write", a.softflowd != b.softflowd),
        (
            "gateway_monitors.write",
            a.gateway_monitors != b.gateway_monitors,
        ),
        ("ntp.write", a.ntp != b.ntp),
        ("syslog.write", a.syslog != b.syslog),
        ("vnstat.write", a.vnstat != b.vnstat),
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
    #[cfg(test)]
    now: Option<DateTime<Utc>>,
}
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
                    && s.revision == 0
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
                let s = State {
                    scope: scope.clone(),
                    revision: 0,
                    desired: initial,
                    active_transaction: None,
                    initialized_at: Utc::now(),
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
            return self.get(path, query).map(|v| Reply::value(200, v));
        }
        if method != "POST" {
            return Err(ApiError::new(405, "method not allowed"));
        }
        if path == "/api/v1/interfaces/discovered" {
            return Err(ApiError::new(405, "interface discovery is read-only"));
        }
        if path == "/api/v1/statistics" || path.starts_with("/api/v1/statistics/") {
            return Err(ApiError::new(405, "statistics endpoints are read-only"));
        }
        require(permissions, "transactions.write")?;
        if path == "/api/v1/transactions" {
            let r: SubmitRequest = parse(body)?;
            self.check_revision(r.base_revision)?;
            authorize(permissions, &self.state.desired, &r.config)?;
            let t = self.submit(actor, r, None)?;
            return Ok(Reply {
                status: 202,
                location: Some(format!("/api/v1/transactions/{}", t.id)),
                body: value(t)?,
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
            let permission = match service {
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
            if observed.normalized() != expected.normalized() {
                return Err(ApiError::new(409, "managed state has drifted"));
            }
            let runtime = self.backend.repair(&expected).map_err(internal_error)?;
            return Ok(Reply::value(200, runtime));
        }
        Err(ApiError::new(404, "endpoint not found"))
    }
    fn check_revision(&self, revision: u64) -> ApiResult<()> {
        if revision != self.state.revision || self.state.revision == u64::MAX {
            return Err(ApiError::new(409, "configuration conflict"));
        }
        Ok(())
    }
    pub fn saved_configuration(&self) -> &Config {
        &self.state.desired
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
        restored: Option<u64>,
    ) -> ApiResult<Transaction> {
        self.submit_inner(actor, r, restored, false)
    }

    fn submit_inner(
        &mut self,
        actor: &str,
        mut r: SubmitRequest,
        restored: Option<u64>,
        factory_reset: bool,
    ) -> ApiResult<Transaction> {
        r.config.normalize();
        r.description = r.description.trim().into();
        if r.description.len() > 1024 {
            return Err(ApiError::new(422, "description must not exceed 1024 bytes"));
        }
        r.config.validate().map_err(|e| ApiError::new(422, e))?;
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
            if observed.normalized() != self.state.desired.normalized() {
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
                actual.normalized() == t.candidate.normalized(),
                "post-apply verification mismatch"
            );
            ensure!(
                self.now() < t.confirmation_deadline,
                "confirmation deadline elapsed while applying"
            );
            Ok(())
        })();
        if let Err(e) = applied {
            let recovery = self.rollback(&id, &format!("apply failed: {e}"));
            let t = self.state.transactions.get(&id).cloned().unwrap_or(t);
            return Err(internal_error(match recovery {
                Ok(()) => format!("apply failed: {e}"),
                Err(r) => format!("apply failed: {e}; {r}"),
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
            || self.state.revision == u64::MAX
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
        if observed.normalized() != t.candidate.normalized() {
            return Err(ApiError::new(409, "candidate drifted before confirmation").transaction(t));
        }
        if self.now() >= t.confirmation_deadline {
            let _ = self.rollback(id, "confirmation expired during verification");
            return Err(ApiError::new(409, "confirmation expired")
                .transaction(self.state.transactions.get(id).cloned().unwrap_or(t)));
        }
        let mut next = self.state.clone();
        next.revision += 1;
        next.desired = t.candidate.clone();
        next.active_transaction = None;
        let committed = next
            .transactions
            .get_mut(id)
            .ok_or_else(|| service_error("transaction disappeared"))?;
        committed.status = "committed".into();
        committed.committed_at = Some(self.now());
        committed.committed_by = actor.into();
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
                observed.normalized() == t.previous.normalized(),
                "rollback verification mismatch"
            );
            Ok(())
        })();
        if let Err(e) = result {
            let mut next = self.state.clone();
            if let Some(active) = next.transactions.get_mut(id) {
                active.status = "recovery_failed".into();
                active.error = format!("{reason}; rollback: {e}");
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
    fn revision_config(&self, number: u64) -> ApiResult<Config> {
        if number > self.state.revision {
            return Err(ApiError::new(404, format!("revision not found: {number}")));
        }
        if number == 0 {
            return Ok(self
                .state
                .transactions
                .values()
                .find(|t| t.status == "committed" && t.base_revision == 0)
                .map(|t| t.previous.clone())
                .unwrap_or_else(|| self.state.desired.clone()));
        }
        self.state
            .transactions
            .values()
            .find(|t| t.status == "committed" && t.base_revision == number - 1)
            .map(|t| t.candidate.clone())
            .ok_or_else(|| service_error("revision archive is incomplete"))
    }
    fn revision_metadata(&self, number: u64) -> ApiResult<Value> {
        if number == 0 {
            return Ok(
                json!({"revision":0,"current":self.state.revision==0,"submitted_at":null,
            "committed_at":self.state.initialized_at,"committed_by":"system","description":"Initial configuration"}),
            );
        }
        let t = self
            .state
            .transactions
            .values()
            .find(|t| t.status == "committed" && t.base_revision == number - 1)
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
            for n in (0..=self.state.revision)
                .rev()
                .filter(|n| before.is_none_or(|b| *n < b))
            {
                if result.len() == limit {
                    next = result.last().and_then(|v: &Value| v["revision"].as_u64());
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
            let n = parse_revision(n)?;
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
            return self.backend.statistics(&config, path, query).map_err(|e| {
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
            });
        }
        let service_status = path
            .strip_prefix("/api/v1/services/")
            .and_then(|s| s.strip_suffix("/status"));
        if path == "/api/v1/runtime"
            || path == "/api/v1/parent-interfaces"
            || service_status.is_some()
        {
            if service_status.is_some_and(|s| {
                ![
                    "ntp",
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
            let runtime = self.backend.runtime(&config).map_err(service_error)?;
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
                        .filter(|s| {
                            s["name"] == service
                                || (service == "vnstat"
                                    && s["name"].as_str().is_some_and(|n| n.starts_with("vnstat-")))
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    Ok(json!({"instances":statuses,"error":error}))
                }
                _ => Err(ApiError::new(404, "endpoint not found")),
            };
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
            "/api/v1/policy-rules",
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
            "/api/v1/policy-rules" => value(observed.policy_rules),
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

fn parse_revision(s: &str) -> ApiResult<u64> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ApiError::new(
            400,
            "revision must be an unsigned 64-bit integer",
        ));
    }
    s.parse()
        .map_err(|_| ApiError::new(400, "revision must be an unsigned 64-bit integer"))
}
fn revision_query(query: &str) -> ApiResult<(usize, Option<u64>)> {
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
        "/api/v1/statistics/gateways",
        "/api/v1/statistics/vnstat",
        "/api/v1/statistics/vnstat/host",
        "/api/v1/statistics/vnstat/managed",
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
        .find(|t| t.status == "committed" && t.base_revision == 0)
        .map(|t| t.previous.clone())
        .unwrap_or_else(|| s.desired.clone());
    records.insert(0, initial);
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
                    .insert(t.base_revision + 1, t.candidate.clone())
                    .is_none(),
                "duplicate committed revision"
            );
        } else {
            ensure!(
                t.committed_at.is_none() && t.committed_by.is_empty(),
                "noncommitted transaction has commitment metadata"
            );
        }
    }
    ensure!(
        active == usize::from(s.active_transaction.is_some()),
        "invalid active transaction pointer"
    );
    ensure!(
        u64::try_from(records.len())?
            == s.revision
                .checked_add(1)
                .context("revision counter overflow")?,
        "revision archive is incomplete"
    );
    ensure!(
        records.get(&s.revision) == Some(&s.desired),
        "current configuration does not match revision archive"
    );
    for t in s.transactions.values() {
        ensure!(
            records.get(&t.base_revision) == Some(&t.previous),
            "transaction previous configuration disagrees with base revision"
        );
        if let Some(from) = t.restored_from_revision {
            ensure!(
                from <= t.base_revision && records.get(&from) == Some(&t.candidate),
                "inconsistent restoration provenance"
            );
        }
    }
    Ok(())
}
