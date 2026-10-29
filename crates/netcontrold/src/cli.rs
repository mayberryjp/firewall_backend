use crate::http::{App, Credential};
use anyhow::{Context, Result, bail, ensure};
use netcontrol_core::{
    Config, Engine, FirewallHost, GatewayMonitor, InterfacePolicy, Peer, SoftflowdConfig,
    valid_interface_name,
};
use serde_json::{Value, json};

pub const LINE_LIMIT: usize = 65_536;
const CANDIDATE_LIMIT: usize = 1 << 20;

const HELP: &str = "\
Netcontrol configuration CLI (Cisco-inspired, not an IOS shell)
  enable / disable                    Change command mode; never grants permissions
  configure terminal                  Edit a private candidate of the committed revision
  show running-config                 Committed configuration, independent of observation
  show candidate-config / compare     Show the private candidate / its changes
  show state / runtime / interfaces / routes / firewall / kernel
  show interfaces discovered          Read-only inventory, including unmanaged host NICs
  show transactions / transaction ID / revisions / revision NUMBER
    show statistics [host|interfaces|protocols|gateways|link-diagnostics|vnstat]
  commit check                        Normalize and validate; no networking changes
  commit confirmed SECONDS [TEXT]     Apply full candidate; 10..300 seconds to confirm
  confirm [ID] / rollback [ID]         Explicit transaction action; last local ID if omitted
  restore revision NUMBER confirmed SECONDS [TEXT]
  reconcile services SERVICE          Explicit repair using stored settings, not a draft
  discard                             Discard only this session's candidate
  end / exit                          Leave mode / close session; never confirms
Configuration commands:
  ipv6 enable|disable                 Global IPv6 policy (default enabled)
  hostname NAME / no hostname         Managed host name; no hostname leaves it unmanaged
  domain NAME / no domain             Cosmetic domain label; never applied to the host or resolver
  timezone ZONE / no timezone         Managed IANA time zone, e.g. UTC or America/New_York
  interface NAME [ethernet|dummy|vlan|wireguard] / no interface NAME
  ip route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
  ipv6 route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
  no ip route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
  firewall policy accept|drop / firewall allow-all-icmp enable|disable
  firewall rule SOURCE|any DESTINATION|any accept|drop / no firewall rule INDEX
  firewall host JSON / firewall interface-policy JSON
  nat masquerade ipv4|ipv6 INTERFACE [SOURCE] / no nat masquerade INDEX
  nat destination-rewrite WAN tcp|udp PORT LAN TARGET_IP / no nat destination-rewrite INDEX
  ntp server HOST / no ntp server HOST / ntp enable|disable
  mdns JSON / no mdns                 Replace/reset native discovery candidate
  show mdns / show mdns status        Committed settings / applied worker
    udp-broadcast-relay JSON            Replace UDP relay candidate
    no udp-broadcast-relay              Reset UDP relay candidate
    show udp-broadcast-relay [status]   Committed settings / applied instances
  bgp JSON / no bgp                   Replace/reset BGP candidate
  show bgp / show bgp status          Committed BGP settings / neighbor status
  show routes bgp                    BGP learned paths and installation status
  syslog server HOST PORT udp|tcp|tls / no syslog server INDEX / syslog enable|disable
  vnstat enable|disable
  exporter JSON / no exporter NAME / gateway-monitor JSON / no gateway-monitor NAME
  kernel host|namespace KEY VALUE / no kernel host|namespace KEY
  set /JSON/pointer JSON               Typed schema edit; array '-' appends
  delete /JSON/pointer                 Delete optional/defaulted field or array element
  load candidate JSON                 Replace private candidate, never live state
Interface mode:
    role wan|lan|unassigned / mtu NUMBER / shutdown / no shutdown
  ip address PREFIX / ipv6 address PREFIX / no ip address PREFIX
  vlan parent NAME / vlan id NUMBER
  wireguard key-ref NAME / wireguard listen-port PORT
  wireguard peer JSON / no wireguard peer PUBLIC_KEY
  dhcp-relay server IPV4 / no dhcp-relay server IPV4 / dhcp-relay enable|disable
All indexes are zero-based. Cross-resource validation happens at commit check/apply.
No shell, files, passwords, private-key contents, or immediate configuration writes.
";

#[derive(Default)]
enum Mode {
    #[default]
    Exec,
    Privileged,
    Config,
    Interface(String),
}

struct Candidate {
    revision: u64,
    original: Value,
    config: Value,
}

#[derive(Default)]
pub struct CliSession {
    mode: Mode,
    candidate: Option<Candidate>,
    last_transaction: Option<String>,
}

pub struct CommandResult {
    pub output: String,
    pub failed: bool,
    pub exit: bool,
}

impl CliSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prompt(&self) -> &'static str {
        match self.mode {
            Mode::Exec => "netcontrol> ",
            Mode::Privileged => "netcontrol# ",
            Mode::Config => "netcontrol(config)# ",
            Mode::Interface(_) => "netcontrol(config-if)# ",
        }
    }

    pub fn execute(&mut self, app: &App, principal: &Credential, line: &str) -> CommandResult {
        match self.command(app, principal, line) {
            Ok((output, exit)) => CommandResult {
                output,
                failed: false,
                exit,
            },
            Err(error) => CommandResult {
                output: format!("% {error:#}\n"),
                failed: true,
                exit: false,
            },
        }
    }

    fn command(&mut self, app: &App, principal: &Credential, line: &str) -> Result<(String, bool)> {
        ensure!(
            line.len() <= LINE_LIMIT,
            "command exceeds {LINE_LIMIT} bytes"
        );
        ensure!(
            !line.chars().any(char::is_control),
            "control characters and multi-line commands are not accepted"
        );
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            return Ok((String::new(), false));
        }
        let words: Vec<_> = line.split_whitespace().collect();
        match words.as_slice() {
            ["help" | "?"] => return Ok((HELP.into(), false)),
            ["enable"] => {
                ensure!(matches!(self.mode, Mode::Exec), "already in enabled mode");
                self.mode = Mode::Privileged;
                return Ok((
                    "Enabled command mode; API-key permissions are unchanged.\n".into(),
                    false,
                ));
            }
            ["disable"] => {
                ensure!(
                    matches!(self.mode, Mode::Privileged),
                    "leave configuration mode first"
                );
                self.mode = Mode::Exec;
                return Ok((String::new(), false));
            }
            ["end"] => {
                self.privileged()?;
                self.mode = Mode::Privileged;
                return Ok((String::new(), false));
            }
            ["exit"] => {
                match self.mode {
                    Mode::Interface(_) => self.mode = Mode::Config,
                    Mode::Config => self.mode = Mode::Privileged,
                    _ => {
                        self.candidate = None;
                        return Ok((
                            "Session candidate discarded. Pending transactions retain their confirmation deadlines.\n".into(),
                            true,
                        ));
                    }
                }
                return Ok((String::new(), false));
            }
            ["configure", "terminal"] => {
                ensure!(
                    matches!(self.mode, Mode::Privileged),
                    "use enable, then configure terminal"
                );
                permission(principal, "transactions.write")?;
                if self.candidate.is_none() {
                    let (revision, config) = running(app, principal)?;
                    self.candidate = Some(Candidate {
                        revision,
                        original: config.clone(),
                        config,
                    });
                }
                self.mode = Mode::Config;
                return Ok((
                    format!(
                        "Private candidate based on revision {}. No live changes until commit confirmed.\n",
                        self.candidate
                            .as_ref()
                            .context("candidate unavailable")?
                            .revision
                    ),
                    false,
                ));
            }
            ["discard"] => {
                self.privileged()?;
                self.candidate = None;
                self.mode = Mode::Privileged;
                return Ok((
                    "Private candidate discarded; live transactions unchanged.\n".into(),
                    false,
                ));
            }
            ["show", ..] => return Ok((self.show(app, principal, &words[1..])?, false)),
            ["compare"] => return Ok((self.compare(principal)?, false)),
            ["commit", "check"] => {
                permission(principal, "state.read")?;
                let config = self.validated()?;
                return Ok((
                    format!(
                        "Candidate is valid (normalized):\n{}\n",
                        pretty(&serde_json::to_value(config)?)?
                    ),
                    false,
                ));
            }
            ["commit", "confirmed", seconds, ..] => {
                self.privileged()?;
                let seconds = timeout(seconds)?;
                let candidate = self
                    .candidate
                    .as_ref()
                    .context("no candidate; use configure terminal")?;
                let body = json!({
                    "base_revision":candidate.revision,
                    "confirm_timeout_seconds":seconds,
                    "description":words[3..].join(" "),
                    "config":self.validated()?
                });
                let result = request(app, principal, "POST", "/api/v1/transactions", "", &body)?;
                self.remember(&result)?;
                self.candidate = None;
                self.mode = Mode::Privileged;
                return Ok((
                    format!(
                        "{}\nProvisional apply only. Confirm transaction {} within {seconds} seconds or it rolls back. Disconnect does not confirm.\n",
                        pretty(&result)?,
                        self.last_transaction
                            .as_deref()
                            .context("missing transaction ID")?
                    ),
                    false,
                ));
            }
            ["confirm" | "rollback", ..] if words.len() <= 2 => {
                self.privileged()?;
                let id = words
                    .get(1)
                    .copied()
                    .or(self.last_transaction.as_deref())
                    .context("transaction ID required; use show transactions")?;
                identifier(id)?;
                let result = request(
                    app,
                    principal,
                    "POST",
                    &format!("/api/v1/transactions/{id}/{}", words[0]),
                    "",
                    &Value::Null,
                )?;
                self.remember(&result)?;
                return Ok((format!("{}\n", pretty(&result)?), false));
            }
            ["restore", "revision", revision, "confirmed", seconds, ..] => {
                self.privileged()?;
                ensure!(
                    self.candidate.is_none(),
                    "discard the private candidate before restoring a revision"
                );
                let revision = unsigned(revision)?;
                let seconds = timeout(seconds)?;
                let (base, _) = running(app, principal)?;
                let result = request(
                    app,
                    principal,
                    "POST",
                    &format!("/api/v1/revisions/{revision}/restore"),
                    "",
                    &json!({
                        "base_revision":base,
                        "confirm_timeout_seconds":seconds,
                        "description":words[5..].join(" ")
                    }),
                )?;
                self.remember(&result)?;
                return Ok((
                    format!(
                        "{}\nProvisional restore; explicit confirm is required within {seconds} seconds.\n",
                        pretty(&result)?
                    ),
                    false,
                ));
            }
            ["reconcile", "services", service] => {
                self.privileged()?;
                ensure!(
                    matches!(
                        *service,
                        "softflowd"
                            | "dhcp-relay"
                            | "gateway-monitoring"
                            | "ntp"
                            | "mdns"
                            | "udp-broadcast-relay"
                            | "syslog"
                            | "vnstat"
                    ),
                    "unknown service"
                );
                return Ok((
                    format!(
                        "{}\n",
                        pretty(&request(
                            app,
                            principal,
                            "POST",
                            &format!("/api/v1/services/{service}/reconcile"),
                            "",
                            &Value::Null
                        )?)?
                    ),
                    false,
                ));
            }
            _ => {}
        }
        if words[0] == "commit" {
            bail!(
                "use commit check or commit confirmed SECONDS, followed by confirm; immediate commit is not supported"
            );
        }
        ensure!(
            matches!(self.mode, Mode::Config | Mode::Interface(_)),
            "unknown command; use ? or configure terminal"
        );
        permission(principal, "transactions.write")?;
        permission(principal, "state.read")?;
        if let Some(json) = command_input(line, "load candidate") {
            let value: Value = serde_json::from_str(json).context("invalid candidate JSON")?;
            self.edit(|config| {
                *config = value;
                Ok(())
            })?;
        } else if let Some(rest) = command_input(line, "set") {
            let (pointer, input) = split_argument(rest)?;
            let value = serde_json::from_str(input).context("set requires a JSON value")?;
            self.edit(|config| pointer_edit(config, pointer, Some(value)))?;
        } else if let ["delete", pointer] = words.as_slice() {
            self.edit(|config| pointer_edit(config, pointer, None))?;
        } else if let Mode::Interface(name) = &self.mode {
            let name = name.clone();
            self.edit(|config| {
                let interface = array(config, "interfaces")?
                    .iter_mut()
                    .find(|i| i["name"].as_str() == Some(&name))
                    .context("selected interface no longer exists; exit interface mode")?;
                edit_interface(interface, line, &words)
            })?;
        } else if let ["interface", name, rest @ ..] = words.as_slice() {
            ensure!(
                rest.len() <= 1,
                "interface NAME [ethernet|dummy|vlan|wireguard]"
            );
            ensure!(valid_interface_name(name), "invalid interface name");
            let kind = rest.first().copied();
            ensure!(
                kind.is_none_or(|k| matches!(k, "ethernet" | "dummy" | "vlan" | "wireguard")),
                "unsupported interface kind"
            );
            self.edit(|config| {
                let interfaces = array(config, "interfaces")?;
                if let Some(existing) = interfaces.iter().find(|i| i["name"] == *name) {
                    ensure!(
                        kind.is_none_or(|k| existing["kind"] == k),
                        "interface kind differs; remove/recreate it explicitly"
                    );
                } else {
                    let kind = kind.unwrap_or("dummy");
                    let mut interface = json!({
                        "name":name,"kind":kind,"role":"lan","mtu":1500,"up":false,
                        "addresses":[],"dhcp_relay":{"enabled":false,"servers":[]}
                    });
                    if kind == "vlan" {
                        interface["vlan"] = json!({"parent":"","id":0});
                    } else if kind == "wireguard" {
                        interface["wireguard"] =
                            json!({"key_ref":"","listen_port":51820,"peers":[]});
                    }
                    interfaces.push(interface);
                }
                Ok(())
            })?;
            self.mode = Mode::Interface((*name).to_owned());
        } else {
            self.edit(|config| edit_global(config, line, &words))?;
        }
        Ok((
            "Candidate updated; live configuration unchanged.\n".into(),
            false,
        ))
    }

    fn privileged(&self) -> Result<()> {
        ensure!(
            !matches!(self.mode, Mode::Exec),
            "use enable first (API-key permissions still apply)"
        );
        Ok(())
    }

    fn edit(&mut self, edit: impl FnOnce(&mut Value) -> Result<()>) -> Result<()> {
        let candidate = self
            .candidate
            .as_mut()
            .context("no candidate; use configure terminal")?;
        let mut changed = candidate.config.clone();
        edit(&mut changed)?;
        let typed: Config =
            serde_json::from_value(changed).context("invalid configuration schema")?;
        let changed = serde_json::to_value(typed)?;
        ensure!(
            serde_json::to_vec(&changed)?.len() <= CANDIDATE_LIMIT,
            "candidate exceeds 1048576 bytes"
        );
        candidate.config = changed;
        Ok(())
    }

    fn validated(&self) -> Result<Config> {
        let candidate = self
            .candidate
            .as_ref()
            .context("no candidate; use configure terminal")?;
        let mut config: Config = serde_json::from_value(candidate.config.clone())?;
        config.normalize();
        config
            .validate()
            .context("candidate validation failed (422)")?;
        Ok(config)
    }

    fn remember(&mut self, result: &Value) -> Result<()> {
        let id = result["id"]
            .as_str()
            .context("engine response missing transaction ID")?;
        identifier(id)?;
        self.last_transaction = Some(id.to_owned());
        Ok(())
    }

    fn compare(&self, principal: &Credential) -> Result<String> {
        permission(principal, "state.read")?;
        let candidate = self.candidate.as_ref().context("no candidate")?;
        let mut changes = Vec::new();
        differences("", &candidate.original, &candidate.config, &mut changes);
        Ok(if changes.is_empty() {
            format!(
                "No candidate changes (base revision {}).\n",
                candidate.revision
            )
        } else {
            format!(
                "Candidate changes from revision {}:\n{}\n",
                candidate.revision,
                changes.join("\n")
            )
        })
    }

    fn show(&self, app: &App, principal: &Credential, words: &[&str]) -> Result<String> {
        if words == ["running-config"] {
            let (revision, config) = running(app, principal)?;
            return Ok(format!(
                "Committed running configuration, revision {revision}:\n{}\n",
                pretty(&config)?
            ));
        }
        if words == ["candidate-config"] {
            permission(principal, "state.read")?;
            let candidate = self.candidate.as_ref().context("no candidate")?;
            return Ok(format!(
                "Private candidate, base revision {}:\n{}\n",
                candidate.revision,
                pretty(&candidate.config)?
            ));
        }
        let path = match words {
            ["state"] => "/api/v1/state".to_owned(),
            ["runtime"] => "/api/v1/runtime".to_owned(),
            ["mdns"] => "/api/v1/services/mdns".to_owned(),
            ["udp-broadcast-relay"] => "/api/v1/services/udp-broadcast-relay".to_owned(),
            ["udp-broadcast-relay", "status"] => {
                "/api/v1/services/udp-broadcast-relay/status".to_owned()
            }
            ["bgp"] => "/api/v1/services/bgp".to_owned(),
            ["bgp", "status"] => "/api/v1/services/bgp/status".to_owned(),
            ["routes", "bgp"] => "/api/v1/routes/bgp".to_owned(),
            ["mdns", "status"] => "/api/v1/services/mdns/status".to_owned(),
            ["interfaces"] => "/api/v1/interfaces".to_owned(),
            ["interfaces", "discovered"] => "/api/v1/interfaces/discovered".to_owned(),
            ["routes"] => "/api/v1/routes".to_owned(),
            ["firewall"] => "/api/v1/firewall/rules".to_owned(),
            ["kernel"] => "/api/v1/kernel/tunables".to_owned(),
            ["transactions"] => "/api/v1/transactions".to_owned(),
            ["transaction", id] => {
                identifier(id)?;
                format!("/api/v1/transactions/{id}")
            }
            ["revisions"] => "/api/v1/revisions".to_owned(),
            ["revision", number] => format!("/api/v1/revisions/{}", unsigned(number)?),
            ["statistics"] => "/api/v1/statistics".to_owned(),
            ["statistics", kind]
                if matches!(
                    *kind,
                    "interfaces"
                        | "host"
                        | "protocols"
                        | "gateways"
                        | "link-diagnostics"
                        | "vnstat"
                ) =>
            {
                format!("/api/v1/statistics/{kind}")
            }
            _ => bail!("unknown show command; use ?"),
        };
        Ok(format!(
            "{}\n",
            pretty(&request(app, principal, "GET", &path, "", &Value::Null)?)?
        ))
    }
}

fn permission(principal: &Credential, permission: &str) -> Result<()> {
    ensure!(
        principal.permissions.iter().any(|p| p == permission),
        "403: {permission} permission required"
    );
    Ok(())
}

fn pretty(value: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

fn call(
    engine: &mut Engine,
    principal: &Credential,
    method: &str,
    path: &str,
    query: &str,
    body: &Value,
) -> Result<Value> {
    let body = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body)?
    };
    let reply = engine.request(
        method,
        path,
        query,
        &principal.name,
        &principal.permissions,
        &body,
    );
    ensure!(
        reply.status < 400,
        "{}: {}",
        reply.status,
        pretty(&reply.body)?
    );
    Ok(reply.body)
}

fn request(
    app: &App,
    principal: &Credential,
    method: &str,
    path: &str,
    query: &str,
    body: &Value,
) -> Result<Value> {
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| anyhow::anyhow!("503: engine unavailable"))?;
    call(&mut engine, principal, method, path, query, body)
}

fn running(app: &App, principal: &Credential) -> Result<(u64, Value)> {
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| anyhow::anyhow!("503: engine unavailable"))?;
    let page = call(
        &mut engine,
        principal,
        "GET",
        "/api/v1/revisions",
        "limit=1",
        &Value::Null,
    )?;
    let revision = page["revisions"][0]["revision"]
        .as_u64()
        .context("invalid revision response")?;
    let detail = call(
        &mut engine,
        principal,
        "GET",
        &format!("/api/v1/revisions/{revision}"),
        "",
        &Value::Null,
    )?;
    let config: Config = serde_json::from_value(detail["config"].clone())
        .context("invalid committed configuration response")?;
    Ok((revision, serde_json::to_value(config)?))
}

fn identifier(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid transaction ID"
    );
    Ok(())
}

fn unsigned(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "unsigned integer required"
    );
    value.parse().context("unsigned integer out of range")
}

fn number(value: &str) -> Result<i64> {
    i64::try_from(unsigned(value)?).context("integer out of range")
}

fn timeout(value: &str) -> Result<i64> {
    let value = number(value)?;
    ensure!(
        (10..=300).contains(&value),
        "confirmation timeout must be 10..300 seconds"
    );
    Ok(value)
}

fn enabled(value: &str) -> Result<bool> {
    match value {
        "enable" => Ok(true),
        "disable" => Ok(false),
        _ => bail!("expected enable or disable"),
    }
}

fn split_argument(input: &str) -> Result<(&str, &str)> {
    let (argument, rest) = input
        .split_once(char::is_whitespace)
        .context("argument and value required")?;
    ensure!(
        !argument.is_empty() && !rest.trim().is_empty(),
        "argument and value required"
    );
    Ok((argument, rest.trim_start()))
}

fn command_input<'a>(line: &'a str, command: &str) -> Option<&'a str> {
    let mut rest = line;
    for expected in command.split_whitespace() {
        let (word, tail) = rest.split_once(char::is_whitespace)?;
        if word != expected {
            return None;
        }
        rest = tail.trim_start();
    }
    Some(rest)
}

fn array<'a>(value: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>> {
    value
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .with_context(|| format!("missing array {field}"))
}

fn push_unique(values: &mut Vec<Value>, value: Value) -> Result<()> {
    ensure!(!values.contains(&value), "entry already exists");
    values.push(value);
    Ok(())
}

fn remove_where(values: &mut Vec<Value>, matches: impl Fn(&Value) -> bool) -> Result<()> {
    let index = values.iter().position(matches).context("entry not found")?;
    values.remove(index);
    Ok(())
}

fn remove_index(values: &mut Vec<Value>, index: &str) -> Result<()> {
    let index = usize::try_from(unsigned(index)?)?;
    ensure!(index < values.len(), "array index out of range");
    values.remove(index);
    Ok(())
}

fn upsert(values: &mut Vec<Value>, value: Value, key: &str) -> Result<()> {
    let identity = value
        .get(key)
        .and_then(Value::as_str)
        .context("entry identity required")?;
    ensure!(!identity.is_empty(), "entry identity required");
    if let Some(existing) = values.iter_mut().find(|v| v[key] == identity) {
        *existing = value;
    } else {
        values.push(value);
    }
    Ok(())
}

fn edit_interface(interface: &mut Value, line: &str, words: &[&str]) -> Result<()> {
    match words {
        ["role", role] if matches!(*role, "wan" | "lan" | "unassigned") => {
            interface["role"] = json!(role)
        }
        ["mtu", value] => interface["mtu"] = json!(number(value)?),
        ["shutdown"] => interface["up"] = json!(false),
        ["no", "shutdown"] => interface["up"] = json!(true),
        ["ip" | "ipv6", "address", prefix] => {
            check_family(words[0], prefix)?;
            push_unique(array(interface, "addresses")?, json!(prefix))?;
        }
        ["no", family @ ("ip" | "ipv6"), "address", prefix] => {
            check_family(family, prefix)?;
            remove_where(array(interface, "addresses")?, |v| v == prefix)?;
        }
        ["vlan", "parent", parent] => {
            ensure!(
                interface["kind"] == "vlan",
                "selected interface is not a VLAN"
            );
            interface["vlan"]["parent"] = json!(parent);
        }
        ["vlan", "id", id] => {
            ensure!(
                interface["kind"] == "vlan",
                "selected interface is not a VLAN"
            );
            interface["vlan"]["id"] = json!(number(id)?);
        }
        ["wireguard", "key-ref", name] => {
            ensure!(
                interface["kind"] == "wireguard",
                "selected interface is not WireGuard"
            );
            interface["wireguard"]["key_ref"] = json!(name);
        }
        ["wireguard", "listen-port", port] => {
            ensure!(
                interface["kind"] == "wireguard",
                "selected interface is not WireGuard"
            );
            interface["wireguard"]["listen_port"] = json!(number(port)?);
        }
        ["wireguard", "peer", ..] => {
            ensure!(
                interface["kind"] == "wireguard",
                "selected interface is not WireGuard"
            );
            let peer: Peer = serde_json::from_str(
                command_input(line, "wireguard peer").context("peer JSON required")?,
            )?;
            upsert(
                array(&mut interface["wireguard"], "peers")?,
                serde_json::to_value(peer)?,
                "public_key",
            )?;
        }
        ["no", "wireguard", "peer", key] => {
            ensure!(
                interface["kind"] == "wireguard",
                "selected interface is not WireGuard"
            );
            remove_where(array(&mut interface["wireguard"], "peers")?, |v| {
                v["public_key"] == *key
            })?;
        }
        ["dhcp-relay", "server", server] => push_unique(
            array(&mut interface["dhcp_relay"], "servers")?,
            json!(server),
        )?,
        ["no", "dhcp-relay", "server", server] => {
            remove_where(array(&mut interface["dhcp_relay"], "servers")?, |v| {
                v == server
            })?
        }
        ["dhcp-relay", state] => interface["dhcp_relay"]["enabled"] = json!(enabled(state)?),
        _ => bail!("unknown interface command; use ? or exit to global configuration"),
    }
    Ok(())
}

fn check_family(family: &str, prefix: &str) -> Result<()> {
    let (address, _) = netcontrol_core::canonical_prefix(prefix, false)?;
    ensure!(
        address.is_ipv4() == (family == "ip"),
        "address family does not match command"
    );
    Ok(())
}

fn edit_global(config: &mut Value, line: &str, words: &[&str]) -> Result<()> {
    match words {
        ["udp-broadcast-relay", ..] => {
            let relay: netcontrol_core::UDPBroadcastRelayConfig = serde_json::from_str(
                command_input(line, "udp-broadcast-relay").context("UDP relay JSON required")?,
            )?;
            config["udp_broadcast_relay"] = serde_json::to_value(relay)?;
        }
        ["no", "udp-broadcast-relay"] => {
            config["udp_broadcast_relay"] =
                serde_json::to_value(netcontrol_core::UDPBroadcastRelayConfig::default())?
        }
        ["bgp", ..] => {
            let bgp: netcontrol_core::BGPConfig =
                serde_json::from_str(command_input(line, "bgp").context("BGP JSON required")?)?;
            config["bgp"] = serde_json::to_value(bgp)?;
        }
        ["no", "bgp"] => {
            config["bgp"] = serde_json::to_value(netcontrol_core::BGPConfig::default())?
        }
        ["mdns", ..] => {
            let mdns: netcontrol_core::MDNSConfig =
                serde_json::from_str(command_input(line, "mdns").context("mDNS JSON required")?)?;
            config["mdns"] = serde_json::to_value(mdns)?;
        }
        ["no", "mdns"] => {
            config["mdns"] = serde_json::to_value(netcontrol_core::MDNSConfig::default())?
        }
        ["ipv6", value @ ("enable" | "disable")] => {
            config["ipv6_enabled"] = json!(*value == "enable");
        }
        [field @ ("hostname" | "domain" | "timezone"), value] => {
            config["system"][*field] = json!(value)
        }
        ["no", field @ ("hostname" | "domain" | "timezone")] => {
            config["system"][*field] = json!("")
        }
        ["no", "interface", name] => {
            remove_where(array(config, "interfaces")?, |v| v["name"] == *name)?
        }
        [
            family @ ("ip" | "ipv6"),
            "route",
            destination,
            interface,
            gateway,
            table,
            metric,
        ]
        | [
            "no",
            family @ ("ip" | "ipv6"),
            "route",
            destination,
            interface,
            gateway,
            table,
            metric,
        ] => {
            check_family(family, destination)?;
            let route = json!({"enabled":true,"destination":destination,"interface":interface,"gateway":if *gateway=="direct" {""} else {gateway},
                "table":number(table)?,"metric":number(metric)?});
            let route =
                serde_json::to_value(serde_json::from_value::<netcontrol_core::Route>(route)?)?;
            if words[0] == "no" {
                remove_where(array(config, "routes")?, |v| {
                    ["destination", "interface", "gateway", "table", "metric"]
                        .iter()
                        .all(|field| v[field] == route[field])
                })?;
            } else {
                push_unique(array(config, "routes")?, route)?;
            }
        }
        ["firewall", "policy", policy] if matches!(*policy, "accept" | "drop") => {
            config["firewall"]["policy"] = json!(policy)
        }
        ["firewall", "allow-all-icmp", state] => {
            config["firewall"]["allow_all_icmp"] = json!(enabled(state)?)
        }
        ["firewall", "rule", source, destination, action]
            if matches!(*action, "accept" | "drop") =>
        {
            array(&mut config["firewall"], "rules")?.push(json!({
                "source":if *source=="any" {""} else {source},
                "destination":if *destination=="any" {""} else {destination},"action":action
            }))
        }
        ["no", "firewall", "rule", index] => {
            remove_index(array(&mut config["firewall"], "rules")?, index)?
        }
        ["nat", "masquerade", family, interface, source @ ..] => {
            ensure!(
                source.len() <= 1,
                "nat masquerade ipv4|ipv6 INTERFACE [SOURCE]"
            );
            push_unique(
                array(&mut config["firewall"]["nat"], "masquerade")?,
                json!({
                    "family":family,"out_interface":interface,"source":source.first().copied().unwrap_or("")
                }),
            )?;
        }
        ["no", "nat", "masquerade", index] => {
            remove_index(array(&mut config["firewall"]["nat"], "masquerade")?, index)?
        }
        [
            "nat",
            "destination-rewrite",
            wan,
            protocol,
            port,
            lan,
            target,
        ] => {
            push_unique(
                array(&mut config["firewall"]["nat"], "destination_rewrite")?,
                json!({"out_interface":wan,"protocol":protocol,"destination_port":number(port)?,
                    "target_interface":lan,"target_address":target}),
            )?;
        }
        ["no", "nat", "destination-rewrite", index] => remove_index(
            array(&mut config["firewall"]["nat"], "destination_rewrite")?,
            index,
        )?,
        ["ntp", "server", host] => push_unique(array(&mut config["ntp"], "servers")?, json!(host))?,
        ["no", "ntp", "server", host] => {
            remove_where(array(&mut config["ntp"], "servers")?, |v| v == host)?
        }
        ["syslog", "server", host, port, transport] => push_unique(
            array(&mut config["syslog"], "servers")?,
            json!({
                "host":host,"port":number(port)?,"transport":transport
            }),
        )?,
        ["no", "syslog", "server", index] => {
            remove_index(array(&mut config["syslog"], "servers")?, index)?
        }
        [service @ ("ntp" | "syslog" | "vnstat"), state] => {
            config[*service]["enabled"] = json!(enabled(state)?)
        }
        ["kernel", scope @ ("host" | "namespace"), key, value] => {
            config["kernel"][*scope][*key] = json!(value)
        }
        ["no", "kernel", scope @ ("host" | "namespace"), key] => {
            ensure!(
                config["kernel"][*scope]
                    .as_object_mut()
                    .context("kernel map required")?
                    .remove(*key)
                    .is_some(),
                "entry not found"
            );
        }
        ["no", resource @ ("exporter" | "gateway-monitor"), name] => remove_where(
            array(
                config,
                if *resource == "exporter" {
                    "softflowd"
                } else {
                    "gateway_monitors"
                },
            )?,
            |v| v["name"] == *name,
        )?,
        _ => {
            if let Some(input) = command_input(line, "exporter") {
                let value: SoftflowdConfig = serde_json::from_str(input)?;
                upsert(
                    array(config, "softflowd")?,
                    serde_json::to_value(value)?,
                    "name",
                )?;
            } else if let Some(input) = command_input(line, "gateway-monitor") {
                let value: GatewayMonitor = serde_json::from_str(input)?;
                upsert(
                    array(config, "gateway_monitors")?,
                    serde_json::to_value(value)?,
                    "name",
                )?;
            } else if let Some(input) = command_input(line, "firewall host") {
                let value: FirewallHost = serde_json::from_str(input)?;
                firewall_policy(config, "hosts", serde_json::to_value(value)?, "id")?;
            } else if let Some(input) = command_input(line, "firewall interface-policy") {
                let value: InterfacePolicy = serde_json::from_str(input)?;
                firewall_policy(
                    config,
                    "interfaces",
                    serde_json::to_value(value)?,
                    "interface",
                )?;
            } else {
                bail!("unknown configuration command; use ?");
            }
        }
    }
    Ok(())
}

fn firewall_policy(config: &mut Value, field: &str, value: Value, key: &str) -> Result<()> {
    if config["firewall"]["policies"].is_null() {
        config["firewall"]["policies"] = json!({"hosts":[],"interfaces":[]});
    }
    upsert(
        array(&mut config["firewall"]["policies"], field)?,
        value,
        key,
    )
}

fn pointer_edit(config: &mut Value, pointer: &str, value: Option<Value>) -> Result<()> {
    let (parent, key) = pointer
        .rsplit_once('/')
        .context("absolute JSON pointer required")?;
    ensure!(!key.is_empty(), "nonempty JSON pointer field required");
    for token in pointer.split('/').skip(1) {
        let mut chars = token.chars();
        while let Some(c) = chars.next() {
            if c == '~' {
                ensure!(
                    matches!(chars.next(), Some('0' | '1')),
                    "invalid JSON pointer escape"
                );
            }
        }
    }
    let key = key.replace("~1", "/").replace("~0", "~");
    let parent = config
        .pointer_mut(parent)
        .context("JSON pointer parent does not exist")?;
    match parent {
        Value::Object(object) => {
            if let Some(value) = value {
                object.insert(key, value);
            } else {
                ensure!(
                    object.remove(&key).is_some(),
                    "JSON pointer field not found"
                );
            }
        }
        Value::Array(array) => {
            if key == "-" {
                array.push(value.context("'-' requires a value to append")?);
            } else {
                ensure!(
                    key == "0" || !key.starts_with('0'),
                    "noncanonical array index"
                );
                let index = usize::try_from(unsigned(&key)?)?;
                ensure!(
                    index < array.len(),
                    "array index out of range; use '-' to append"
                );
                if let Some(value) = value {
                    array[index] = value;
                } else {
                    array.remove(index);
                }
            }
        }
        _ => bail!("JSON pointer parent must be an object or array"),
    }
    Ok(())
}

fn differences(path: &str, before: &Value, after: &Value, output: &mut Vec<String>) {
    if before == after {
        return;
    }
    if let (Some(a), Some(b)) = (before.as_object(), after.as_object()) {
        let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
        for key in keys {
            let pointer = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
            differences(
                &pointer,
                a.get(key).unwrap_or(&Value::Null),
                b.get(key).unwrap_or(&Value::Null),
                output,
            );
        }
    } else {
        output.push(format!("- {path} {before}\n+ {path} {after}"));
    }
}
