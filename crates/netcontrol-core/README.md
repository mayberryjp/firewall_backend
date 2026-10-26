# netcontrol-core

Pure Rust networking/configuration domain, durable transaction engine and
simulator. No shell commands, subprocess daemons, Go implementation or Go state
reader are used. The crate exports the shared `Backend`, `Config`, feature model
types, `Simulator`, `Engine`, `Reply`, `Transaction` and `PERMISSIONS` interfaces.
Backend calls are synchronous; callers must serialize access to `Engine`.

## Current configuration contract

Configuration JSON retains the current networking field names: `ntp`, `syslog`,
`vnstat`, `mdns`, `gateway_monitors`, `interfaces`, `routes`, `firewall`,
`softflowd`, and `kernel`. Every feature configuration has a typed serde model
with `deny_unknown_fields`. Interface `role` is required and must be `wan` or
`lan`. `firewall.allow_all_icmp` defaults to `true` when omitted; explicit JSON
`null` is rejected. Optional arrays/maps normalize to empty arrays/maps; ordering
is canonical except where firewall policy evaluation depends on rule order.

Validation covers canonical numeric addresses/networks/endpoints, interface
identities and MTU, WireGuard keys/ports/peers, VLAN parent cycles and identities,
DHCP relay bindings, managed routes and routing tables, NAT address families,
host/ingress firewall policies and expansion/metadata limits, kernel allowlists
and canonical scalar/vector values, service endpoints/timeouts/limits, and
gateway monitoring address/routing/timing dependencies.

User-configurable source-policy routing is unsupported: `policy_rules` is an
unknown field (dropped and reported when submitted through the API, including
empty arrays/null; rejected when loading saved state), `/api/v1/policy-rules` is absent,
and `policy.write` is not a permission. Native gateway monitors derive internal
host-source rules for explicit monitors; enabled explicit monitors sharing a
source must use the same table. `mode: "dhcp"` requires a DHCP-configured managed
interface and IPv4 target, omits source/gateway/table, and can be saved enabled
before lease acquisition without static addresses/routes. Native runtime follows
only that interface's active lease; waiting/unavailable is Unknown, not Down.
Ordinary destination routing remains available, normally through table 254.

`mdns` always serializes, defaults disabled, and uses the shared
`MDNSConfig`/`MDNSReflection`/`MDNSPublishing` types. It validates managed LAN
allow/deny membership (32 entries/effective links), 64 canonical local
service/subtype/provider filters, effective address families and coherent
publishing options even when disabled. Active reflection needs two eligible
links; publishing alone needs one. Metadata is operationally stripped;
publishing hostname fallback is explicitly derived from `system.hostname`.
Global IPv6 disable suppresses transport/AAAA without changing preferences.
`mdns.write` covers every mDNS edit, including metadata, restores and all
aggregate service-repair entry points when enabled. Reads use `state.read`:
`GET /api/v1/services/mdns` returns committed configuration without observation;
`GET /api/v1/services/mdns/status` returns the applied singleton status envelope.
Both reject query parameters. Bodyless
`POST /api/v1/services/mdns/reconcile` uses existing aggregate repair permissions
and creates no revision; query/body input is rejected. Candidate edits remain
full confirmed transactions. Simulator status says `simulated`, with zero
decimal-string counters and no claimed packets/membership.

## Persistent state and recovery

The state file is a JSON envelope with exactly these fields:

```json
{
  "schema": "netcontrol-rust-state-v1",
  "sha256": "64 lowercase hexadecimal digits",
  "state": {}
}
```

The illustrated empty `state` is not a valid journal; its actual typed payload
contains `scope`, `revision`, `desired`, `active_transaction`, `initialized_at`
and `transactions`. SHA-256 covers the exact JSON bytes of the saved `state`
value. The writer serializes that value once as compact JSON, then hashes and
publishes the same payload. Loading verifies those bytes before decoding current
Rust types, so field ordering/default expansion cannot fabricate corruption.
Changing whitespace within the saved value changes its checksum; envelope
whitespace outside that value is not covered. This detects corruption, not an
attacker able to rewrite the journal and its checksum.

The journal rejects unknown fields, malformed/truncated/empty files, checksum
mismatches, different schemas, scope mismatches, inconsistent active pointers,
invalid configurations, incomplete/duplicate revision histories, inconsistent
base snapshots and restoration provenance. Go journals are not parsed or
converted. Existing data is never silently reset, imported or deleted. An
incompatible file requires explicit operator handling; the old file must be
preserved. Normal loading never converts it. The separately authorized
[offline policy-rule conversion](../../docs/BUILD_AND_INSTALL.md#offline-policy-rule-state-conversion)
can remove only empty retired arrays after checksum/current-model/history
validation, with a preview, explicit confirmation and exact private backup.
It refuses active transactions and non-empty archived rules. This is not an
automatic loader compatibility path or a general migration framework.

A checksum failure is not permission to reset state or recompute its checksum.
Preserve the original file and inspect the failure. A model-dependent checksum
bug could previously reject valid bytes after adding fields such as
`ipv6_enabled`; the corrected loader checks stored bytes without rewriting the
file. It still rejects actual corruption and incompatible current payloads,
without migration, repair fallback or live-network configuration import.

An adjacent `.lock` file uses an exclusive process lock. State/lock paths must
be regular files rather than symbolic links. Publication uses a unique adjacent
pending file, file synchronization and atomic replacement. Unix also synchronizes
the containing directory. Windows uses `MoveFileExW` with replacement and
write-through flags. A directory-sync failure after publication blocks the
engine until restart rather than allowing writes from an uncertain in-memory
revision. The state size limit is 256 MiB; history is not pruned.

Windows publication retries transient access/sharing/lock denials up to eight
atomic attempts over 254 ms, accommodating short-lived scanner/indexer handles.
Permanent failures remain explicit errors and never trigger deletion of the
previous journal. Win32 replacement uses resolved extended-length paths so state
locations exceeding the historical 260-character limit remain supported.

Transaction intent is durable before backend changes. Post-apply observation
must match the normalized candidate; failed application or verification performs
durable rollback intent, backend rollback and verification. Recovery failures
remain active and block new writes. Startup rolls back `applying`,
`rolling_back`, `recovery_failed` and expired `pending_confirmation` records.
Unexpired provisional candidates resume with their original deadline.
Confirmation re-observes state, checks the deadline before and after observation,
and commits configuration/revision/history atomically. Confirmation and rollback
are idempotent in their respective terminal states. Historical restoration is a
new provisional transaction, not an overwrite of revision history.

The exact shared backend interface has no cancellation, preflight or standalone
kernel snapshot methods. Native implementations must bound their synchronous
operations and durably capture/restore kernel originals within their own
`apply` implementation. The engine checks the confirmation deadline after
application but cannot interrupt a backend that hangs. Native ownership,
syscalls, kernel-original persistence and live reconciliation belong to
`netcontrol-native`, not this crate. A backend may expose its full kernel view
as `runtime.kernel_tunables`; without it, nonempty kernel inspection returns an
explicit `503`, never fabricated original values.

## Engine HTTP-domain routing

The engine implements current networking GET routes for state, interfaces and
individual interfaces, VLANs, routes, policy rules, firewall/rules/hosts/
interface-policies/NAT, WireGuard, gateway monitors, service configuration and
status, runtime, parent interfaces, kernel catalog/view, transactions and
individual transactions, revision history/details, and all statistics sections.
POST handles transaction submission, confirmation, rollback, revision restore,
and service reconciliation.

Authentication, request content-type, transport, CORS, headers other than
`Reply.location`, and identity endpoints belong to the daemon. The engine
requires a nonempty actor, `state.read` for reads, `transactions.write` for
writes, and all changed-domain permissions on submit/confirm/rollback/restore.
Restore also requires `state.read`. Service reconciliation requires its domain,
`state.read`, and write permissions for every enabled service that repair can
restart. Authorization compares canonical configurations and separately gates
WireGuard settings, NAT, namespace kernel and host kernel changes.

Successful writes return `202` and a transaction `Location`; confirm/rollback
return `200`. Errors are `{"error":"message","transaction":null}` or contain
the relevant failed transaction snapshot. Malformed JSON/query is `400`;
missing identity `401`; permission failures `403`; absent resources `404`;
unsupported methods `405`; revision/active/drift/deadline conflicts `409`;
domain validation failures `422`; mutation/backend failures `500`; unavailable
observation/runtime/statistics `503`. Statistics are GET-only and reject queries.
Revision lists default to 50 items, accept 1..100 and an exclusive
`before_revision` cursor, and reject unknown/duplicate/empty parameters.

## Simulator runtime/statistics JSON

`runtime` contains `appliance_services`, `gateway_monitors`, `dhcp_relay`,
`parent_interfaces`, `softflowd`, and `kernel_tunables`. No PIDs are invented.

- Appliance entries are `{name,scope,state}` for `ntp`/`host`, `syslog`/`host`,
  `vnstat-host`/`host`, `vnstat-managed`/`managed`.
- Softflowd entries are `{name,state}`.
- DHCP relay entries are `{interface,state}`.
- Enabled entries have `state:"simulated"`; disabled entries use `"disabled"`.
- `parent_interfaces` is empty: external interfaces are not fabricated.
- `kernel_tunables` contains `desired`, `configured`, `effective`, `observed`,
  `captured_original`, and `drift`. Kernel values are simulator fixtures, not
  measured host settings; removal restores those original fixture values.
- Gateway entries contain `name`, `process_state`, `sample_status`,
  `health:"unknown"`, nullable `started_at`, `collected_at`,
  `health_changed_at`, `last_success_at`; zero `sent`, `received`, `lost`,
  `pending`, `variation_pairs`; and nullable `loss_percent`, `rtt_min_ms`,
  `rtt_max_ms`, `rtt_avg_ms`, `rtt_stddev_ms`, `rtt_p50_ms`, `rtt_p95_ms`,
  `rtt_variation_ms`. Enabled process/sample states are `"simulated"`;
  disabled process/sample states are `"disabled"`.

Statistics wrappers are `{sample,interfaces,protocols,gateways}` for all,
`{sample,interfaces}` / `{sample,protocols}` / `{sample,monitors}` by section,
and `{sample,interface}` / `{sample,monitor}` by individual name.
`sample` contains `scope:"simulator"`, RFC3339 `started_at`, `collected_at`,
and `status:"simulated"`. Interface entries contain `name`, `kind`,
`ownership:"managed"`, `mtu`, `admin_up`, `oper_state:"unknown"`,
`status:"simulated"` and `counters:null`. Protocol entries for `snmp`, `netstat`
and `snmp6` contain `name`, `status:"simulated"` and `groups:null`. Missing
individual resources return `404`.

### Persistent traffic history endpoints

`GET /api/v1/statistics/vnstat`, `/api/v1/statistics/vnstat/host`, and
`/api/v1/statistics/vnstat/managed` require `state.read` and reject every nonempty
query with `400`. Unknown scopes, trailing slashes and additional path segments
return `404` before calling a backend. Other methods return `405`.

The engine delegates the three valid routes to the backend without discarding
the response. Native services return:

```text
{
  schema: "netcontrol-services/counters/v1",
  scopes: {
    host?: CounterDatabase,
    managed?: CounterDatabase
  }
}
```

The aggregate endpoint includes both scopes; each scoped endpoint selects only
that scope. Each database contains `schema`, `scope`, `interfaces` and `history`.
Interface rows contain `ifindex`, `boot_id`, `namespace_id`, `last`, `total`,
`resets`, `last_seen` and `present`. History rows contain `collected_at`,
`interface`, `delta` and `reset`. Every `last`/`total`/`delta` counter object
contains decimal-string `rx_bytes`, `tx_bytes`, `rx_packets` and `tx_packets`.
The native backend may additionally identify its enclosing managed scope;
this does not replace the `host`/`managed` database selection.

Disabled collection, unavailable workers and collection/storage errors produce
`503` with the normal `{error,transaction:null}` envelope. A valid but unready
scope does not become `404` or a fabricated successful empty measurement.
The simulator cannot collect persistent traffic: disabled vnstat returns
`503` with `"vnstat is disabled"`; enabled vnstat returns `503` with
`"traffic history unavailable: simulator does not collect traffic counters"`.
Its ordinary simulated network-statistics endpoints remain available.

## Validation

Run `cargo test -p netcontrol-core`,
`cargo clippy -p netcontrol-core --all-targets -- -D warnings`, and
`cargo fmt -p netcontrol-core -- --check`.
The tests cover current example schemas, validation boundaries, permissions,
revision restoration and pagination, WAL failures, corrupt/incompatible state,
locking, drift, deadline/startup recovery, rollback and kernel originals.
Portable tests do not prove Linux kernel/native behavior or process power-loss
durability.
