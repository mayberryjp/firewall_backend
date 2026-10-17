# Netcontrol frontend specification

## 1. Purpose and contract

Build an administrative web application for the Netcontrol isolated-lab network
control plane. Operators must be able to inspect owned networking, prepare a
complete desired configuration, review its effects, provisionally apply it, and
explicitly confirm or roll it back. They must also be able to inspect transaction
recovery, restore committed revisions, and diagnose managed softflowd processes.

This document specifies frontend behavior against the backend in this repository.
Statements marked **Frontend decision** are proposed UI choices, not existing
backend capabilities. Statements marked **Operator prerequisite** require
deployment or host setup outside the application. The backend remains authoritative
for validation, authorization, observation, and transaction outcomes.

### 1.1 Audience and success criteria

- **Operator:** Understand what is committed, what is live, and what is only a draft.
- **Network administrator:** Change multiple related subsystems in one package
  without accidentally deleting unrelated configuration.
- **Recovery operator:** Find an interrupted transaction and safely retry rollback,
  including when full live observation is unavailable.
- **Frontend developer:** Implement the application without inventing missing API
  capabilities or misunderstanding provisional success as a durable commit.

The release is complete when all P0/P1 requirements and the acceptance scenarios
in section 16 pass. P2 items are optional polish.

### 1.2 Scope and limitations

Support:

- Managed dummy, VLAN, and kernel WireGuard interfaces and IP addresses.
- Read-only adopted parent inventory.
- Unicast routes and source-policy routing.
- Ordered forward-chain source/destination accept/drop rules and default policy.
- IPv4/IPv6 masquerading.
- WireGuard key references, peers, endpoints, allowed networks, and keepalive.
- Typed softflowd configuration, runtime inspection, and explicit reconciliation.
- Complete-package transactions, confirmation, rollback, and recovery.
- Committed configuration history, comparison, export, and historical restore.
- Read-only namespace interface counters and IP/TCP/UDP/ICMP protocol statistics,
  including explicit partial/unavailable and simulator states.

Do not present as supported:

- Physical-device provisioning, parent adoption, namespace creation or selection
  through the API, bridges, DHCP, DNS management, or forwarding sysctl management.
- SNAT, DNAT, port forwarding, port/protocol firewall matches, sets, conntrack
  controls, traffic control, device tuning, or hardware offload.
- Private-key upload/generation, key-file listing, package installation, arbitrary
  commands, process identity configuration, or systemd control.
- Server-computed throughput/history, flow records, WireGuard handshake/peer
  telemetry, collector-delivery verification, or real-time server push.
  Client-derived interface rate charts are optional, subject to section 6.1.1.
- User/credential administration, token creation/revocation, permission discovery,
  a tamper-evident audit log, or multi-host coordination.

Label the product **Isolated lab control plane**. Do not market it as a production
host-network manager or describe a package apply as an atomic kernel transaction.

## 2. Product and interaction principles

1. **Committed, live, draft, and provisional are distinct.** Always label them.
2. **One shared draft, one package.** Resource forms stage local edits; only the
   review workflow submits configuration.
3. **Confirmation is explicit.** A `202` response is not a committed revision.
4. **No inferred success.** A timeout, disconnect, closed tab, or expired UI
   countdown cannot establish the server outcome.
5. **Preserve unrelated state.** Start drafts from committed desired configuration,
   not observed state or a partial resource response.
6. **Recovery first.** Transaction status and rollback must remain accessible when
   live observation or a resource page fails.
7. **Truthful health.** Administrative up is not carrier, modeled agreement is not
   connectivity, and process responsiveness is not delivery to a collector.
8. **No automatic configuration writes.** Never auto-confirm, auto-resubmit a
   package, auto-restore, or run an unbounded service restart loop.

## 3. Application structure

### 3.1 Navigation

**Frontend decision:** Use the following application routes. These are browser
routes, not backend endpoints.

| Route | Page |
| --- | --- |
| `/connect` | Credential entry and connection status |
| `/overview` | Summary, safety state, active transaction, runtime health |
| `/interfaces` | All managed interfaces; kind filters for dummy/VLAN/WireGuard |
| `/interfaces/:name` | Interface detail and staged editor |
| `/parents` | Read-only adopted parent inventory |
| `/routes` | Routes |
| `/policy-rules` | Source-policy rules |
| `/firewall` | Forward filter policy and ordered rules |
| `/nat` | Masquerade rules |
| `/wireguard` | WireGuard-focused interface/peer view |
| `/services/softflowd` | Configured instances joined with runtime status |
| `/services/softflowd/:name` | Instance detail and staged editor |
| `/changes` | Shared draft, comparison, import/export, apply review |
| `/transactions` | Transaction history |
| `/transactions/:id` | Transaction details and lifecycle actions |
| `/history` | Committed revision history |
| `/history/:revision` | Historical configuration, comparison, restore |

Deep links must work after browser refresh. Unknown browser routes show an
application 404, not an empty page. Encode resource names/IDs in URLs.

### 3.2 Persistent application shell

- Header: product/lab label, deployment label, committed revision, last successful
  refresh time, connection status, and credential disconnect action.
- Sidebar: navigation above, grouped as Overview, Networking, Services, Changes,
  and History.
- Shared draft indicator: number of changed entities, validation status, and
  **Review changes** action. Count firewall-policy changes separately.
- Global safety banner, visible on every authenticated page:
  - Active pending transaction: ID/link, absolute deadline, remaining time,
    **Confirm** and **Roll back**.
  - Applying/rolling back: operation status and detail link.
  - Recovery failed: persistent critical banner and **Retry rollback**.
  - Drift/observation unavailable: warning, last known timestamp, diagnostic links.
- Toasts supplement persistent state; they must never be the only confirmation or
  recovery interface.

**Frontend decision:** Prioritize the highest-severity safety state when space is
limited, but keep other problems discoverable. Order: recovery failure, uncertain
write outcome, pending confirmation, unavailable/stale state, modeled drift.

### 3.3 Visual and responsive requirements

- Desktop-first administrative UI, usable at 1280px width and above.
- At 768px, collapse navigation and convert wide table detail to drawers/cards;
  horizontal table scrolling is acceptable when headers remain understandable.
- At 375px, the active-transaction banner and its actions remain usable without
  horizontal scrolling. All critical operations remain available.
- Use consistent spacing, typography, input heights, and semantic color tokens.
  Display IPs, prefixes, keys, IDs, and JSON in monospace.
- Neutral = informational, blue = draft/applying, amber = provisional/drift,
  red = failure/destructive, green = verified committed/healthy.
- Never encode state using color alone. Include text and an icon.
- Destructive actions need descriptive labels, not an ambiguous **OK**.

## 4. Connection, credentials, and deployment

### 4.1 Deployment contract

**Operator prerequisite:** Serve the frontend and API through one trusted HTTPS
origin, with `/api/v1` forwarded to Netcontrol. In default device mode the daemon
serves a small embedded onboarding/key-management website at `/`; the broader
networking dashboard specified here still needs a separate frontend. Legacy
`-auth-file` mode serves only the networking API. Neither mode implements CORS.
A Vite/development proxy may provide same-origin networking API paths locally.
Remote device website access should use native TLS; `/auth/` origin and Secure
cookie checks do not trust forwarded headers.

The frontend API base is deployment configuration, not arbitrary user input in
the initial release. Do not send an operator's token to a URL supplied by a query
parameter, imported file, or untrusted content. No external analytics or services
may receive configuration, tokens, keys, or diagnostic payloads.

**Frontend decision:** Default to a relative `/api/v1` base and a deployment-supplied
label/mode (`Linux`, `Simulator`, or `Unknown`). No current API exposes backend
mode, namespace, version, or feature capabilities. Never infer Linux operation
from an empty service list or fabricate a namespace label.

### 4.2 Credential flow

#### Device onboarding and key management (implemented)

Without `-auth-file`, `/` hosts a three-step setup wizard: username/password,
named automatically generated API key(s), then saved-key acknowledgement and
completion. Anyone reaching an unclaimed device can claim it; restrict management
network access until setup completes. Networking API keys do not work before
completion. An interrupted account setup resumes through password sign-in.

Credentials live in an owner-restricted bbolt database, separate from network JSON,
using bcrypt password hashes and SHA-256 hashes of random 256-bit keys. API-key
plaintext is returned only by creation, shown in a one-time dialog, cleared when
hidden, and never persisted in browser storage. Lists show name, creation time,
and a masked suffix (last four characters). Lost-response recovery is removal and
replacement, never fetching plaintext. New keys have all networking permissions.

The device account manages keys using an HttpOnly, SameSite=Strict session cookie
scoped to `/auth/`, Secure with native HTTPS, expiring after 30 minutes. Mutations
require `Content-Type: application/json` and a matching `Origin` header. Sign-out
invalidates the session. Networking API endpoints remain bearer-only; sessions do
not authorize them, and bearer keys cannot manage device credentials.

| Endpoint | Request/response |
| --- | --- |
| `GET /auth/status` | `{stage: "account" \| "login" \| "keys" \| "ready", authenticated: boolean, configured: boolean, username: string}`; username empty unless signed in |
| `POST /auth/setup` | `{username, password}`; claims once and sets session cookie |
| `POST /auth/login` | `{username, password}`; sets session cookie |
| `POST /auth/logout` | `{}`; revokes session and clears cookie |
| `GET /auth/keys` | `{keys: [{id, name, masked, created_at}]}`; signed-in only |
| `POST /auth/keys` | `{name}` -> `201 {key: {id, name, masked, created_at}, token}`; sole plaintext response |
| `DELETE /auth/keys/{id}` | Immediately revokes future requests; already authorized operations continue |
| `POST /auth/complete` | `{saved: true}`; requires session and at least one key |

Auth responses are `no-store`; errors are `{error: string}`. Common failures:
`400` invalid fields, `401` bad/expired session or credentials, `403` origin,
`404` missing key, `409` already claimed/missing initial key, `415` content type,
`429` sign-in/setup rate limit (10 attempts/minute device-wide, `Retry-After: 60`),
`500` credential-store failure. Usernames are 1..64 bytes, passwords 12..72 UTF-8
bytes, key names 1..80 bytes and unique. Names cannot have outer whitespace or
control characters. At most 100 keys and 32 active sessions are allowed.

The account can remove even the last key and generate replacements; no password
reset, remote recovery, API-key expiration, or managed-key permission editor is
provided. `-auth-file` is an explicit alternative, not an automatic migration.

#### Connecting the broader networking dashboard

1. Show a masked bearer-token input and **Connect**.
2. Keep the token in memory only. No token in local/session storage, URLs, logs,
   error trackers, exported files, or service-worker caches.
3. Validate access using authenticated reads. A successful transaction-list read
   establishes read access even if `/state` returns an observation error.
4. On success, load the shell and separately load state, runtime, and relevant
   history. Show independent failures rather than failing the whole application.
5. On `401`, stop background requests and request a credential again. Keep an
   in-memory draft until the operator explicitly discards/disconnects; do not
   silently lose it when a token becomes invalid.
6. Disconnect clears token, cached server data, and draft after an unsaved-change
   warning. If a transaction is pending, explain that disconnecting does not
   confirm, cancel, or reliably trigger immediate rollback.

The device-account session above does not authenticate this networking client.
A dashboard reload requires API-token re-entry. Clearing a browser token does not
revoke it; use device key management (or operator edits/restart in legacy mode).

### 4.3 Authorization

All reads require `state.read`. All POST actions require `transactions.write`.
Configuration changes additionally require permissions for every changed area:

| Change | Additional permission |
| --- | --- |
| Interface/address/VLAN fields | `interfaces.write` |
| WireGuard settings and removal of a WireGuard interface | `wireguard.write` |
| Routes | `routes.write` |
| Source-policy rules | `policy.write` |
| Filter policy/rules | `firewall.write` |
| Masquerading | `nat.write` |
| softflowd configuration | `softflowd.write` |

Creating/removing a WireGuard interface typically needs both interface and
WireGuard permissions. Confirm/rollback requires the permissions for the original
transaction's full previous-to-candidate difference, even for another submitter.
Restore also requires `state.read`. Service reconciliation requires `state.read`
and `softflowd.write` in addition to `transactions.write`.

There is no current-user or permissions endpoint. Do not probe authorization by
issuing writes. Deployment-supplied UI permission hints may disable controls, but
must be labeled advisory; otherwise offer actions and handle `403` explicitly.
Show permission errors near the action, preserve the draft, and explain that
another appropriately authorized operator may need to confirm or recover.

## 5. State and draft model

### 5.1 Definitions

| Name | Meaning and source |
| --- | --- |
| Committed desired | `/state.desired`, associated with `/state.revision` |
| Observed | `/state.observed`, live modeled state at observation time |
| Expected live | Active candidate while pending confirmation; otherwise desired |
| Draft | Local editable clone of desired plus its captured base revision |
| Historical | Immutable configuration from `/revisions/{revision}` |

`drift` compares observed against expected live. A pending candidate differing
from committed desired is normal and does not itself mean drift.

Never automatically copy observed state into the draft to “fix” drift. There is
no general drift-reconciliation endpoint. Recovery may require an operator
outside this UI.

### 5.2 Shared draft lifecycle

- Create the first draft by deep-cloning the latest desired configuration and
  capturing its revision. Reuse the same draft across all editors.
- Every editor uses **Stage changes** / **Cancel**. Stage changes performs no HTTP
  mutation. Existing resource lists default to committed desired, with explicit
  staged previews and an optional observed comparison.
- Editor Cancel discards only un-staged form edits. **Discard draft** discards the
  shared draft after confirmation.
- Display draft changes across pages and warn before navigation that would lose
  un-staged input. Warn on reload/tab close when supported by the browser.
- Keep drafts in memory by default. Provide explicit JSON export so operators can
  save work; warn that topology, peer public keys, and key references are sensitive.
- If the server revision changes, mark the draft stale. Block submission. Offer
  export, comparison against the new desired configuration, and explicit restart
  from latest. Do not auto-rebase or silently overwrite another operator's work.
- If any active transaction exists, block new package submission and historical
  restore. Preserve a pre-existing draft, but mark it unavailable for apply.
- After this client's confirmed transaction, clear the submitted draft only once
  the server outcome is known. If it rolls back, preserve the candidate as an
  editable draft after refreshing the committed baseline and resolving staleness.
- Do not allow ordinary editing of an active transaction candidate. It is a
  submitted snapshot, not a mutable draft.

### 5.3 Comparison and identity

Show additions, modifications, deletions, and ordered-list moves by subsystem:

- Interfaces and softflowd instances: identity by `name`.
- WireGuard peers: identity by public key within an interface.
- Routes: identity by `(table, destination, metric)`.
- Policy rules: identity by priority.
- Filter and masquerade rules: ordered arrays, with frontend-only stable row IDs.
  Never send those row IDs to the backend.
- Interface rename is delete/create, not an API rename operation.

Ignore ordering differences the backend normalizes: interfaces by name, addresses
lexically, peers by public key, allowed IPs lexically, softflowd by name, policy
rules by priority, and routes by the backend's route-key string. Ignore JSON map
key order. Preserve filter and masquerade rule order.

Counts are counts of UI entities, not a prediction of kernel operation count.
Show exact old/new values on expansion and offer read-only JSON comparison.

## 6. Screen requirements

### 6.1 Overview

Show:

- Committed revision, link to history detail, last refresh and freshness.
- Counts of managed interfaces by kind, routes, policy rules, filter rules,
  masquerade rules, and configured/enabled softflowd instances.
- Drift state and comparison link: expected live versus observed.
- Active transaction summary with deadline/actions.
- Parent availability and softflowd runtime summaries.
- Recent transactions and committed revisions.
- Scope/ownership help: owned namespace only; protected parents are not managed
  resources; forwarding and out-of-band access are operator responsibilities.

Do not show fabricated CPU, RAM, traffic, latency, tunnel health, or collector
metrics. A failed observation is **Unknown/unavailable**, not zero resources.

### 6.1.1 Read-only networking statistics

All statistics reads require `state.read` and accept no query parameters:

| GET endpoint | Response |
| --- | --- |
| `/api/v1/statistics` | `{sample, interfaces, protocols}` |
| `/api/v1/statistics/interfaces` | `{sample, interfaces}` |
| `/api/v1/statistics/interfaces/{name}` | `{sample, interface}` |
| `/api/v1/statistics/protocols` | `{sample, protocols}` |

`sample` contains `scope`, `started_at`, `collected_at`, and `status`:
`available`, `partial`, or `simulated`. Treat timestamps as a collection window,
not an atomic kernel snapshot. Display freshness independently of configuration
freshness. An unavailable source/link has its own status and error; missing
counters/groups are null, not zero. Optional counter fields can be absent.

Interface records include `name`, optional `index`, `kind`, `ownership`, `mtu`,
`admin_up`, `oper_state`, optional `mac`, `status`, optional `counter_bits`
(32 or 64), nullable `counters`, and optional `error`. Counter keys cover RX/TX
bytes, packets, errors, drops, and detailed link errors; see
[Networking statistics](README.md#networking-statistics) for the complete scope.
Statistics include unmanaged links and loopback, not just editable resources.
Do not turn their presence into provisioning/edit controls. A changed adopted
parent identity is labeled `adopted_parent_identity_changed`.

Protocol records contain `name` (`snmp`, `netstat`, `snmp6`), `status`, nullable
`groups`, and optional `error`. Groups map kernel group/field names to decimal
strings; IPv6 fields retain full names under `IPv6`. Preserve unknown fields and
do not assume identical groups across kernels. Some values are gauges/constants,
not counters; `Tcp.MaxConn` can be `"-1"`.

**Precision:** All statistics values are quoted decimal strings on the wire,
unlike revision numbers. Keep them as strings or validated `BigInt`; never route
them through `Number` or the revision serializer's unquoted-number encoding.
Use arbitrary-precision deltas before deliberately rounding a displayed rate.

**Frontend decision:** Poll visible statistics every 2-5 seconds, without
overlapping requests. Prefer the combined endpoint when displaying several
sections, pause polling on hidden pages, and back off on errors. Preserve the
last good result with a stale label; do not retain it as a current success.
`404` means the named interface no longer exists; `503` is unavailable collection,
not zero traffic. Protocol-only collection can fail when every source is absent.

Never invent a rate from a first sample, unavailable/simulated counters, a changed
scope/name/index/width, a counter decrease, or nonpositive elapsed time. Use
actual sample elapsed time, not the scheduled poll interval. Reset baselines on
these events; do not attempt to repair ambiguous resets or multiple 32-bit wraps.
Identity hints cannot detect every recreation/reset. Do not calculate rates for
gauges/constants or sum parents/VLANs/veths/loopback into a misleading total.

Keep statistics in separate ephemeral monitoring state. Polling must not dirty,
replace, or rebase a configuration draft, alter pending transactions, or imply
counter history can be restored with a revision. Statistics remain independent
of full configuration observation errors. No per-flow, driver-specific,
host-global softnet/sockstat, WireGuard peer, or streaming API is implied.

### 6.2 Managed interfaces and VLANs

Table columns: name, kind, administrative up/down, MTU, addresses, VLAN parent/ID
when applicable, staged-change indicator, and actions. Filters: text, kind, and
administrative state. Detail views include desired/observed comparison.

Editor fields:

- Name, kind (`dummy`, `wireguard`, `vlan`), MTU, administrative up, address list.
- VLAN: parent selector and VLAN ID.
- WireGuard: embedded settings/peers or link to the same shared WireGuard editor.

Parent selector combines eligible managed dummy/VLAN interfaces in the draft
with available adopted parents. Identify adopted parents as read-only. Do not
offer WireGuard, self, or descendants as parents.

For an existing interface, lock kind; for an existing VLAN, lock parent and ID.
Explain the supported replacement choices: use a new name, or separately apply
and confirm deletion before recreation. A local unsent new interface may still
change these fields.

Deleting an interface opens a dependency review showing child VLANs, routes,
masquerade rules, and capture instances. Do not silently cascade. Require explicit
staging of removals/references and block apply until the full package is valid.
Renames must similarly surface dependencies. Up does not imply carrier/readiness.

### 6.3 Adopted parents

Read-only table: name, kind, index, MAC, MTU, administrative up, available, error.
Fetch through runtime or parent inventory even when full observation fails.
Show absence/error as an actionable diagnostic, not an invitation to recreate.
No add/delete/edit/adopt buttons. Explain that replacement of a parent identity
requires operator attention; changing a parent's MTU/up externally is not itself
owned-configuration drift.

### 6.4 Routes

Table/editor: destination network, optional gateway, managed interface, table,
metric. Family badge derives from destination. Include text/table/interface/family
filters and a delete action.

Gateway omission means a direct route; never substitute `0.0.0.0`. Managed
interface options come from the draft, not adopted parents. Explain reserved
tables and protocol 242 ownership; protocol is not an editable field.

### 6.5 Source-policy routing

Table/editor: priority, canonical source network, lookup table. Sort/display by
ascending numeric priority. Explain that this is source-prefix table lookup,
not arbitrary Linux policy-rule selectors. Multiple rules may use the same table;
only priorities must be unique.

### 6.6 Firewall forwarding

- Default policy selector: Accept or Drop.
- Ordered rule list: position, source or Any, destination or Any, action.
- Add/edit/delete, move up/down, and optional drag reorder with keyboard equivalent.
- Show a catch-all warning when both prefixes are omitted; subsequent filter
  rules can be unreachable. This is a warning, not a backend validation error.
- Require an explicit review acknowledgement for a default drop policy or a
  catch-all drop. Explain that this owns only the `inet netcontrol` forward chain,
  not a full host firewall or the management listener's input policy.

Do not alphabetically sort rules before sending. Do not add port, protocol,
ingress/egress-interface, logging, or stateful-match controls.

### 6.7 NAT masquerading

Ordered table/editor: position, family (`ipv4`/`ipv6`), optional source network or
Any, managed egress interface. Provide move up/down as well as add/edit/delete.

Filter egress choices to draft interfaces with an address of the selected family.
Explain missing options and link to interface editing. Switching family must
revalidate source and egress rather than silently rewriting values.

Show: “Masquerading does not enable forwarding, create routes, or bypass filter
rules.” No static translation or port-forward controls. NAT edits remain separate
from filter edits for review and permissions, but share the same transaction and
owned nftables table.

### 6.8 WireGuard

Show WireGuard interfaces and peers using the same underlying draft as Interfaces.
Fields: key reference, stable listen port, peer public key, optional numeric
endpoint, allowed network list, persistent keepalive seconds.

Show key reference as a name, never a filesystem path. No private-key input,
reveal, upload, download, or browser key generation. Explain immutable operator
key files and retention of old references for recovery/history.

Public keys may be truncated in tables with accessible full-text/copy controls.
Do not label a configured peer connected. No handshake/transfer metrics exist.
Endpoint roaming can create modeled drift; surface it without overwriting the
draft automatically.

### 6.9 softflowd

Table: name, desired enabled, observed enabled, capture interface, collector,
export version, runtime state, PID/start time when supplied, error, staged state.

Editor: name, enabled, capture interface, numeric collector address/port, export
version, sampling rate, maximum flows, snap length, promiscuous capture, optional
single-line capture filter, and optional timeout overrides.

Capture interface options include managed draft interfaces and available adopted
parents. Mark adopted parents protected. Timeout overrides are optional named
entries; absence means executable defaults, not zero.

Display runtime states:

| Value | UI label |
| --- | --- |
| `running` | Running; local responsiveness checked, delivery not verified |
| `disabled` | Disabled |
| `simulated` | Simulated; no real capture process |
| `not_running` | Not running |
| `unhealthy` | Unhealthy |
| `exited` | Exited |
| Unknown future value | Unknown status, retaining raw value |

Missing runtime data means Unknown, not Disabled. Keep top-level runtime error
visible even if individual rows appear healthy.

**Reconcile services** is a separate explicitly confirmed runtime action. It sends
a bodyless POST using stored committed/pending configuration, not the draft.
Explain that it affects managed services collectively, may lose flow caches, does
not replay networking, and creates no revision. Do not suggest per-instance restart
or automatically retry it. Block it during applying/rolling-back/recovery-failed
states; it is allowed by the backend during pending confirmation.

### 6.10 Changes/review

Display captured base revision, latest committed revision, per-subsystem diff,
validation summary, required permission names, description, and confirmation
window. Include explicit deletion counts and default-policy/order changes.

**Frontend decision:** Default confirmation window to 120 seconds; allow integers
10 through 300. This is a UI default, not a server default. Description is optional.

Before **Apply provisionally**, require acknowledgement that:

- The package replaces the complete owned configuration, including deletions.
- Networking can be disrupted and intermediate states are visible.
- The confirmation clock starts before the HTTP response, and confirmation must
  happen before the server deadline.
- Out-of-band access and operator-managed forwarding may be necessary.

Provide JSON import/export:

- Primary format is a complete `Config` object. Optionally accept the repository
  example request wrapper, extracting only `config` after explicitly identifying
  the format. Never reuse its base revision, timeout, or description silently.
- Reject unknown fields, multiple JSON values, invalid types, and incomplete
  top-level configuration sections in the editor. Do not silently drop fields or
  interpret omitted sections as an innocuous merge.
- Import replaces the local draft only after a full diff/deletion preview and
  confirmation. It performs no server write.
- Export config-only JSON; optionally provide a separately labeled current-base
  request export. Export no token or frontend-only metadata.

### 6.11 Transactions

List columns: status, transaction ID, description, actor, submitted time, base
revision, committed time/by, restore source, and deadline where relevant.
The endpoint returns an ID-keyed object, not a paginated array. Sort locally by
known submitted time descending, with deterministic ID tie-breaking; place missing
timestamps in a clearly labeled unknown-date group. Provide client-side filtering
and pagination without pretending there is server-side search.

Detail: status, full raw error/reason, candidate-versus-previous comparison,
timestamps, provenance, deadline, actor/confirmer, links to base/result revisions,
and authorized lifecycle actions. Result revision for a committed transaction is
`base_revision + 1`, not the current server revision.

Keep nonterminal states and errors visible after navigation and reconnect.
There is no backend `failed` terminal status; failed applies normally become
`rolled_back` or `recovery_failed`. A rollback `error` can be a reason rather than
evidence that recovery itself failed. No reliable rollback timestamp or rollback
actor field is supplied; do not invent either.

### 6.12 Committed history and restoration

- Newest revision first, using server pagination and revision-number ordering.
- Columns: revision/current badge, description, submitted/committed dates,
  submitted/committed actors, transaction link, restored-from revision.
- Null dates show **Unknown (legacy record)**. Omitted actor shows **Unknown**.
  Revision 0 may have only initialization date/system attribution.
- Detail loads full configuration; allow comparison against current committed
  desired or another explicitly selected revision, and config-only export.
- **Restore this revision** opens a preview against current desired, collects
  timeout/description, then calls the restore endpoint. Do not create a normal
  transaction by resubmitting the historical config.
- Disable restore when a transaction is active or fresh state is unavailable.
  Warn if there is a local draft; require explicit discard/export before restore.
- Restoration is provisional and follows normal confirmation/recovery. It creates
  a new revision on confirmation, never rewinds numbering or overwrites history.
- Explain that historical keys may be unavailable and current restrictions still
  apply. Restoring revision 0 may remove all owned resources; show the full impact.
- Preserve explicit `restored_from_revision: 0`; never treat it as absent.

## 7. Transaction state machine and reliability

### 7.1 Server states

| Status | Meaning | UI behavior |
| --- | --- | --- |
| `applying` | Intent journaled; reconcile/readback underway | Read-only progress, no percentage estimate |
| `pending_confirmation` | Candidate verified; committed revision unchanged | Countdown, Confirm and Roll back |
| `committed` | Desired revision durably published | Success; refresh desired/history |
| `rolling_back` | Restoring previous configuration | Recovery progress, no new writes |
| `rolled_back` | Previous configuration restoration verified/persisted | Explain reason; revision unchanged |
| `recovery_failed` | Recovery or its persistence failed | Critical banner, Retry rollback; new submissions blocked |

Typical paths:

```text
applying -> pending_confirmation -> committed
applying -> rolling_back -> rolled_back
pending_confirmation -> rolling_back -> rolled_back
rolling_back -> recovery_failed -> rolling_back -> rolled_back
```

A transition can complete before any read returns; do not require every state to
be observed. Engine operations hold a lock, so reads can block behind mutations.
The UI cannot promise independently observable real-time progress.

### 7.2 Apply sequence

1. Validate the complete draft, cross-resource references, and serialized request
   size. Fetch current state and check base revision, no active transaction, and
   no modeled drift. These are UX checks, not a server-side concurrency guarantee.
2. Freeze the submitted snapshot and disable duplicate submission.
3. POST the complete package. Do not reset the draft or show committed success.
4. On `202`, immediately display returned status/deadline and transaction detail.
   Refresh state/runtime; reconcile against the transaction endpoint.
5. On any error containing a transaction object, display that transaction and
   inspect server state before enabling new writes.
6. On unknown outcome, follow section 7.4. Never automatically replay the POST.

### 7.3 Confirmation and rollback

- **Confirm configuration** is available only for a pending candidate with a
  non-expired displayed deadline. Refresh status when stale. Ask the operator to
  acknowledge their connectivity checks; the backend does not test reachability.
- Show the server's absolute UTC deadline, a localized timestamp, and a countdown.
  Use the absolute deadline, not a timer starting at response receipt.
- Browser time is approximate; use an exposed valid HTTP `Date` value as an
  optional skew estimate and disclose uncertainty. Never use the countdown as
  authority. At zero, show **Deadline reached; awaiting server outcome**, stop
  offering Confirm, and continue status reconciliation.
- Do not auto-confirm on navigation, observed agreement, or successful ping.
- **Roll back** explicitly restores previous config. Explain effects and confirm
  the destructive recovery action, without making the dialog obstruct an urgent
  recovery path.
- **Retry rollback** is the recovery action for `recovery_failed`, not Resubmit.
- Confirm is idempotent after commit; rollback is idempotent after rollback. Do
  not use this as justification for generic write retries.
- A `409` on confirmation can mean drift, expiry, or invalid lifecycle state;
  display the error and refresh status rather than declaring success.

### 7.4 Unknown outcome, refresh, and multiple operators

A network error/timeout after a POST means **Outcome unknown**, not Failed safely.
Client abort does not undo durable intent.

If a transaction ID is known, read it directly. Otherwise read `/transactions`
and `/state`, compare the pre-submit transaction ID set/base/candidate/description,
and show any plausible new transaction. These are correlation hints, not
idempotency keys. In multi-operator cases do not assume a similar transaction
belongs to this request. Require operator reconciliation when ambiguous.

Block repeat submission until the outcome is established. Keep the frozen
candidate available for comparison/export. The API has no idempotency-key or
client-request-ID support.

On reconnect or reload after credential entry, fetch transactions independently
of `/state`. Find nonterminal transactions even if observation fails, show their
detail, and expose recovery. Do not assume the absence of a local draft means no
transaction is active. Other tabs/operators may perform lifecycle actions;
poll server state and update controls rather than relying on local ownership.

Restart notes for operator help:

- Applying/rolling-back work is recovered by rollback on daemon restart.
- Unexpired pending confirmation can survive restart; expired pending work rolls
  back on restart. The watchdog cannot run while the daemon/machine is stopped.
- A closed browser is not a rollback mechanism. Graceful daemon shutdown attempts
  rollback, but the UI cannot guarantee immediate recovery during outages.

## 8. Validation contract

Run local validation for immediate feedback; retain server error messages because
preflight/kernel/permissions can still reject a locally valid package. All numeric
fields below are integers. Do not use JavaScript truthiness to validate `0`.

### 8.1 Addresses and prefixes

- Use a tested IP parser; regex alone is insufficient.
- IPv4-mapped IPv6 prefixes are not accepted.
- Prefix spelling must match Go `netip` canonical output, including compressed
  lowercase IPv6. Network fields must have host bits cleared.
- Interface address prefixes retain host bits: `192.0.2.10/24` is valid and must
  not silently become `192.0.2.0/24`.
- For network inputs such as `192.0.2.10/24`, show a correction suggestion
  `192.0.2.0/24` and require acceptance; do not silently widen a selector.
- Interface addresses must satisfy Go's `IsGlobalUnicast` and be unique within
  the interface. Private/documentation unicast addresses are valid; this is not
  equivalent to “publicly routable.”
- No zone identifiers in numeric endpoint/gateway/collector inputs.

### 8.2 Field constraints

| Area | Constraints |
| --- | --- |
| Interface name | `^[a-zA-Z0-9_.-]{1,15}$`; not `lo`, `.`, `..`; unique; cannot collide with protected adopted parent |
| Kind | `dummy`, `wireguard`, `vlan`; existing kind cannot change in place |
| MTU | 1280..65535 |
| VLAN | Required only for VLAN kind; parent valid/known, ID 1..4094; unique parent/ID pair; no cycles, self-parent, or WireGuard parent; child MTU <= parent MTU |
| WireGuard settings | Required only for WireGuard kind; do not send on other kinds |
| Key reference | `^[a-zA-Z0-9_-]{1,64}$`; no path; availability/private file checks are server-side |
| Listen port | 1..65535; stable nonzero port required |
| Peer public key | Base64 decodes to a nonzero 32-byte WireGuard key; unique within interface |
| Endpoint | Optional numeric IP:port, nonzero port, IPv6 bracketed; no DNS, zone, or mapped IPv6 |
| Allowed IPs | Canonical networks; exact duplicates prohibited across all peers on that WireGuard interface; overlaps are not generically forbidden |
| Keepalive | 0..65535 seconds; 0 means disabled |
| Route destination | Canonical network |
| Route gateway | Optional canonical numeric address; same family as destination, no mapped IPv6 or zone |
| Route interface | Must exist in managed draft interfaces |
| Route table | 10000..19999 |
| Route metric | 1..2147483647 |
| Route uniqueness | `(table, destination, metric)` unique, even if device/gateway differs |
| Policy source | Canonical network |
| Policy priority | 10000..19999, unique across policy rules |
| Policy table | 10000..19999; reuse across rules allowed |
| Filter policy/action | Exactly `accept` or `drop` |
| Filter prefixes | Optional canonical source/destination networks; same family when both supplied; both may be empty |
| Masquerade family | Exactly `ipv4` or `ipv6` |
| Masquerade source | Optional canonical network matching explicit family |
| Masquerade egress | Managed draft interface with at least one configured address of matching family |
| Description | Optional, trimmed; maximum 1024 UTF-8 bytes after trimming |
| Confirmation window | 10..300 seconds |

Do not reject duplicates or overlaps the backend permits merely as a frontend
constraint. Warnings about redundant/shadowed rules are acceptable. Do not add
unsupported route-table/port-uniqueness restrictions.

### 8.3 softflowd constraints

| Field | Constraint |
| --- | --- |
| Instance count | At most 16, including disabled entries |
| Name | `^[a-zA-Z0-9_-]{1,32}$`, unique |
| Capture interface | Valid interface name; managed or operator-adopted interface; server preflight remains authoritative |
| Collector | Canonical numeric unicast or loopback IP:port; nonzero port; bracketed IPv6; no zone/mapped IPv6/DNS |
| Export version | 1, 5, 9, or 10; label 10 as IPFIX |
| Sampling rate | 1..1000000; 1 means unsampled |
| Max flows | 1..1000000 |
| Snap length | 64..65535 bytes |
| Capture filter | Optional; at most 4096 UTF-8 bytes; no NUL, CR, or LF |
| Timeout names | Only `general`, `tcp`, `tcp.rst`, `tcp.fin`, `udp`, `icmp`, `maxlife`, `expint` |
| Timeout values | 0..604800 seconds; `general`, when present, must be >= 1 |

Disabled entries still require valid fields. Filter compilation, executable
availability, capture capability, and native integration are preflight/runtime
concerns; the UI cannot certify them locally. There are no server-provided
defaults for mandatory numeric fields; new-record presets must be visibly
identified as frontend presets and never applied silently to existing records.

### 8.4 Error presentation

- Inline field errors plus a linked form summary; focus the summary after failure.
- Cross-resource errors link to every affected editor and the review page.
- Display server `error` as text, not HTML. Preserve its full detail in an
  expandable area; do not depend on parsing English text into stable error codes.
- Unknown validation failures remain visible as form-level errors.
- Do not replace malformed/missing data with a success-shaped empty configuration.

## 9. API integration contract

### 9.1 Common behavior

- All networking `/api/v1` requests: `Authorization: Bearer <token>`.
- JSON-body POST requests: `Content-Type: application/json`.
- Responses are JSON with `Cache-Control: no-store`.
- JSON-body requests have a 1 MiB limit; unknown fields/trailing JSON values fail.
  Measure the complete serialized UTF-8 request, not only the config.
- GET success and lifecycle/reconcile POST success are `200`; submit/restore
  success are `202` with `Location` and a transaction body.
- No PUT/PATCH/DELETE, websocket, SSE, batch-read, dry-run, or validation endpoint.
- Reads can invoke live observation. Fetch `/state` once for aggregate data rather
  than issuing every resource GET on each refresh.
- Resource GETs return observed configuration, not desired/draft data.

### 9.2 Endpoint inventory

Paths below are relative to `/api/v1`.

| Method | Path | Response |
| --- | --- | --- |
| GET | `/state` | `StateView` |
| GET | `/runtime` | `RuntimeState` |
| GET | `/parent-interfaces` | `ParentInterface[]` |
| GET | `/interfaces` | Observed `Interface[]` |
| GET | `/interfaces/{name}` | One observed `Interface` |
| GET | `/vlans` | Observed VLAN `Interface[]` |
| GET | `/wireguard` | Observed WireGuard `Interface[]` |
| GET | `/routes` | Observed `Route[]` |
| GET | `/policy-rules` | Observed `PolicyRule[]` |
| GET | `/firewall/rules` | Entire observed `Firewall`, including policy and NAT |
| GET | `/firewall/nat` | Observed `{ "masquerade": [...] }` |
| GET | `/services/softflowd` | Observed `SoftflowdConfig[]` |
| GET | `/services/softflowd/status` | `{ "instances": SoftflowdStatus[], "error": string }` |
| GET | `/transactions` | `Record<string, Transaction>` |
| GET | `/transactions/{id}` | `Transaction` |
| GET | `/revisions?limit=50&before_revision=N` | `RevisionPage` |
| GET | `/revisions/{revision}` | `Revision` |
| POST | `/transactions` | Complete package request -> `Transaction` |
| POST | `/transactions/{id}/confirm` | No body -> `Transaction` |
| POST | `/transactions/{id}/rollback` | No body -> `Transaction` |
| POST | `/revisions/{revision}/restore` | Restore request -> `Transaction` |
| POST | `/services/softflowd/reconcile` | No body -> `RuntimeState` |

For revision lists, `limit` defaults to 50, accepts 1..100, and
`before_revision` is an exclusive uint64 cursor. Unknown, duplicated, empty, or
malformed parameters return `400`. Use `next_before_revision` verbatim for the
next page; absence means exhausted. Do not calculate cursors from dates.

### 9.3 Request examples

Complete empty package, useful as a schema illustration, **not a safe default**:

```json
{
  "base_revision": 0,
  "confirm_timeout_seconds": 120,
  "description": "Remove all owned configuration",
  "config": {
    "interfaces": [],
    "routes": [],
    "policy_rules": [],
    "firewall": {
      "policy": "accept",
      "rules": [],
      "nat": { "masquerade": [] }
    },
    "softflowd": []
  }
}
```

Historical restore body:

```json
{
  "base_revision": 12,
  "confirm_timeout_seconds": 120,
  "description": "Restore known-good configuration"
}
```

The selected historical revision is in the URL, not the body. An omitted/blank
restore description defaults server-side to `Restore revision N`.

### 9.4 Data shapes

The following TypeScript describes the application-level contract, not a generated
SDK. Optional fields can be absent; timestamp fields explicitly marked nullable
can be null for legacy data.

**Revision precision:** The backend emits uint64 values as JSON numbers. Native
`JSON.parse` can silently round values above `Number.MAX_SAFE_INTEGER`. Use a
lossless JSON boundary: parse revision/cursor values to validated decimal strings
and serialize them back as unquoted integer tokens using a tested lossless
serializer. Ordinary `JSON.stringify` of these application strings is not a valid
request encoding. Do not use an unsafe `number` cast or regex JSON rewriting.
Statistics are the deliberate exception: counter/protocol values already arrive
as quoted decimal strings and must remain quoted; see section 6.1.1.

```ts
type RevisionNumber = string; // Validated decimal uint64 in application state.
type Timestamp = string; // RFC 3339.

interface Config {
  interfaces: ManagedInterface[];
  routes: Route[];
  policy_rules: PolicyRule[];
  firewall: Firewall;
  softflowd: SoftflowdConfig[];
}

interface ManagedInterface {
  name: string;
  kind: "dummy" | "wireguard" | "vlan";
  mtu: number;
  up: boolean;
  addresses: string[];
  vlan?: { parent: string; id: number };
  wireguard?: {
    key_ref: string;
    listen_port: number;
    peers: Peer[];
  };
}

interface Peer {
  public_key: string;
  endpoint?: string;
  allowed_ips: string[];
  persistent_keepalive_seconds: number;
}

interface Route {
  destination: string;
  gateway?: string;
  interface: string;
  table: number;
  metric: number;
}

interface PolicyRule {
  priority: number;
  source: string;
  table: number;
}

interface Firewall {
  policy: "accept" | "drop";
  rules: Array<{ source?: string; destination?: string; action: "accept" | "drop" }>;
  nat: { masquerade: MasqueradeRule[] };
}

interface MasqueradeRule {
  family: "ipv4" | "ipv6";
  source?: string;
  out_interface: string;
}

interface SoftflowdConfig {
  name: string;
  enabled: boolean;
  interface: string;
  collector: string;
  export_version: 1 | 5 | 9 | 10;
  sampling_rate: number;
  max_flows: number;
  snaplen: number;
  promiscuous: boolean;
  capture_filter?: string;
  timeouts: Partial<Record<
    "general" | "tcp" | "tcp.rst" | "tcp.fin" |
    "udp" | "icmp" | "maxlife" | "expint", number
  >>;
}

type TransactionStatus =
  | "applying" | "pending_confirmation" | "committed"
  | "rolling_back" | "rolled_back" | "recovery_failed";

interface Transaction {
  id: string;
  actor: string;
  status: TransactionStatus;
  base_revision: RevisionNumber;
  candidate: Config;
  previous: Config;
  confirmation_deadline: Timestamp;
  error?: string;
  description?: string;
  submitted_at: Timestamp | null;
  committed_at: Timestamp | null;
  committed_by?: string;
  restored_from_revision?: RevisionNumber;
}

interface StateView {
  revision: RevisionNumber;
  desired: Config;
  observed: Config;
  drift: boolean;
  active_transaction?: Transaction;
}

interface ParentInterface {
  name: string;
  kind: string;
  index: number;
  mac: string;
  mtu: number;
  up: boolean;
  available: boolean;
  error?: string;
}

interface SoftflowdStatus {
  name: string;
  state: string;
  pid?: number;
  started_at?: Timestamp;
  error?: string;
}

interface RuntimeState {
  parent_interfaces: ParentInterface[];
  softflowd: SoftflowdStatus[];
  error?: string;
}

interface RevisionMetadata {
  revision: RevisionNumber;
  current: boolean;
  transaction_id?: string;
  submitted_at: Timestamp | null;
  committed_at: Timestamp | null;
  submitted_by?: string;
  committed_by?: string;
  description?: string;
  restored_from_revision?: RevisionNumber;
}

interface Revision extends RevisionMetadata { config: Config }
interface RevisionPage {
  revisions: RevisionMetadata[];
  next_before_revision?: RevisionNumber;
}

interface PackageRequest {
  base_revision: RevisionNumber;
  confirm_timeout_seconds: number;
  config: Config;
  description?: string;
}
type RestoreRequest = Omit<PackageRequest, "config">;
interface ApiError { error: string; transaction: Transaction | null }
```

Decode responses at runtime. Do not cast arbitrary JSON to these types. An
unrecognized transaction status or incompatible configuration schema must produce
a visible compatibility warning and disable unsafe editing/lifecycle assumptions;
retain read-only diagnostics. Live observed links can reflect unexpected kinds
under drift, so do not force unknown observations into an editable supported kind.

The status endpoint's `error` key is always emitted by the current implementation
and may be an empty string; runtime's `error` is omitted when empty. Collection
responses may require normalizing a documented nil collection to an empty list at
the boundary, but malformed or missing required configuration must not become an
invented empty desired configuration.

### 9.5 Error behavior

Backend errors normally have:

```json
{
  "error": "human-readable detail",
  "transaction": null
}
```

| Status | Expected interpretation |
| --- | --- |
| `400` | Invalid JSON/query/path value, unknown request field, oversized body decoding failure |
| `401` | Missing/invalid bearer credential |
| `403` | Missing permission |
| `404` | Endpoint/resource/revision/transaction not found |
| `405` | Unsupported method (`Allow: GET, POST`) |
| `409` | Stale base, active transaction, drift, invalid lifecycle state, or another conflict |
| `415` | JSON-body action lacks `application/json` |
| `422` | Request validation or validation-class preflight failure |
| `500` | Operational/preflight/persistence/apply/recovery failure |
| `503` | Live observation/runtime unavailable |

Do not assume all preflight failures are `422`; some are `500`. An error response
may include a transaction even after changes have occurred. Proxies can also
return non-JSON errors, including `413`/`502`/`504`; show status and a bounded,
sanitized textual diagnostic, then reconcile uncertain writes.

## 10. Refresh, caching, and concurrency

**Frontend decision:**

- On connect and refocus: refresh state and runtime; independently fetch
  transactions to support recovery when state observation fails.
- Normal visible operation: state/runtime every 5 seconds, transaction history
  every 10 seconds when needed for global recovery discovery.
- During a known nonterminal/uncertain transaction: its detail and state every
  1 second after the preceding request completes; runtime every 5 seconds.
- Use single-flight requests per query. Do not queue overlapping polls while a
  backend operation holds the engine lock. A “1-second poll” is not a guarantee
  of one response per second.
- Read request timeout: 80 seconds; write timeout: 90 seconds. These are UI
  tolerances, not server completion guarantees. Surface delayed reads promptly
  while allowing the operation to finish.
- On read transport failure: back off 1, 2, 5, then 10 seconds. Do not retry `401`
  in a loop. Mutations have zero automatic retries.
- Always keep pending deadlines visible, but note that background tabs may throttle
  polling. Refresh immediately on visibility/network restoration.
- Discard older read results after a newer mutation/refetch; abort obsolete reads
  where practical. Never abort a write and describe it as canceled.
- Every dataset has loading/error/last-success/freshness state. Show cached data as
  stale with its timestamp when refreshing fails. Do not allow new apply/restore
  based on stale or unavailable state.
- Confirmation/rollback remain independently accessible through a fresh transaction
  detail even if aggregate observation is unavailable; confirmation can still be
  rejected by server observation checks.
- Revision details are immutable; cache within the authenticated session. Current
  flags and list pagination must refresh after commits.

No service worker/offline mutation queue in the initial release. Offline mode is
read-only last-known information with explicit stale warnings.

## 11. Suggested frontend implementation

**Frontend decision, not a backend requirement:** If no frontend stack already
exists, use React + TypeScript + Vite, a router, a server-state query library,
schema validation, and an accessible component/form library. Prefer the team's
existing equivalents over adding parallel frameworks.

Keep these logical responsibilities separate without over-engineering:

- Authenticated API client: lossless revision encoding, runtime decoding, typed
  HTTP/transport errors, no automatic mutation retries, token redaction.
- Server-state queries: refresh/single-flight/freshness.
- Shared local draft store: captured base, staged configuration, semantic diff,
  cross-resource validation, stale flag.
- Transaction coordinator: mutation status, unknown-outcome handling, lifecycle
  refresh, global recovery banner.
- Reusable resource editors and ordered-list controls.

Use a discriminated interface schema so VLAN/WireGuard fields cannot be sent on
the wrong kind. Keep form values such as empty numeric input separate from valid
request types. Backend JSON keys remain snake_case on the wire.

Do not add invented backend dependencies such as `/me`, `/capabilities`,
`/validate`, or `/metrics` to make the first release work.

## 12. Accessibility and interaction quality

- Target WCAG 2.2 AA.
- All controls have visible labels and associated help/error text.
- Keyboard access for tables, drawers, dialogs, list reordering, and copy actions.
- Dialog focus trap, initial focus, Escape behavior, and restoration to trigger.
- Error summaries link/focus to invalid fields; errors do not rely on color.
- Status changes use appropriately scoped live regions. Do not announce every
  countdown tick; announce meaningful thresholds and expiry.
- Contrast-compliant text/badges/focus indicators; support zoom and reduced motion.
- Long IPs, keys, IDs, and error strings wrap or scroll without breaking layout.
- Time displays include timezone and access to exact UTC value. Null legacy
  timestamps remain unknown.
- Clipboard failures are explicit and offer selectable text.
- Empty, loading, stale, denied, not-found, and incompatible-response states have
  distinct content and recovery actions.

## 13. Safety and privacy requirements

- Render server errors, descriptions, capture filters, and imported JSON as text;
  never inject them as HTML.
- Use deployment CSP and avoid unnecessary third-party scripts/resources.
- Clear sensitive in-memory state on explicit disconnect. Do not cache API traffic
  in a service worker or persist credentials in browser storage.
- Never send Authorization headers to another origin through redirects; treat an
  unexpected API redirect as a deployment error.
- Browser diagnostics may record endpoint templates, status, and duration, but
  not token, full request/response bodies, or configuration by default.
- Download/export is operator initiated and includes a sensitivity notice.
- Explain that rollback restores modeled configuration, not lost packets,
  connections, handshakes, flow caches, exported records, interface indices, or
  other unmodeled/external state.
- Journal history is not a full audit-event API. Show available recorded metadata,
  not an invented complete audit trail.

## 14. Backend gaps and operator dependencies

These do not authorize speculative UI controls or require backend changes for
the initial frontend release.

| Gap/prerequisite | Initial frontend treatment |
| --- | --- |
| No broader dashboard hosting/CORS | Embedded onboarding at `/`; separate same-origin dashboard deployment |
| No networking-key permission discovery | Token entry, advisory deployment hints, handle `403`; `/auth/status` only identifies device-account sessions |
| No backend/namespace/capability endpoint | Deployment labels or Unknown; no guessed capabilities |
| No key inventory/private-key API | Manual validated key reference; operator provisions files |
| No dry-run/diff/validation endpoint | Local validation/diff; server preflight happens during submit |
| No idempotency key | Freeze uncertain writes; reconcile transaction records; never blind retry |
| No event stream/server-side rate history | Bounded polling of statistics and modeled/runtime views |
| No general drift repair | Diagnostic comparison and operator guidance; no “force apply” |
| No history pruning/server transaction pagination | Client pagination; document scaling limitation |
| No persisted rollback actor/time fields | Display reason/raw error, avoid fabricated metadata |
| Revisions/cursors emitted as JSON numbers | Lossless parsing/serialization; statistics values are already decimal strings |
| Linux namespace/parents/forwarding/executable setup | Operator-owned provisioning outside application |

Future enhancements such as capabilities, structured error codes, idempotency
keys, paginated transaction summaries, and explicit server clock can be proposed
separately. The release must remain usable without them.

## 15. Delivery priorities and handoff

### P0: Safety foundation

- Same-origin connectivity, token handling, typed/lossless API boundary.
- Server-state freshness and independent transaction/recovery reads.
- Shared complete draft and semantic comparison.
- Apply/confirm/rollback/unknown-outcome lifecycle and persistent global banner.
- Drift/stale/permission/observation error handling.

### P1: Complete supported product

- All resource editors and read-only parents.
- softflowd runtime/reconciliation.
- Read-only interface/protocol statistics with precision, freshness, and explicit
  unavailable/simulated states; client-derived charts remain optional.
- Transaction history/detail and failed-recovery retry.
- Revision history/detail/comparison/restore, including revision 0.
- Config import/export, responsive critical workflows, accessibility.
- Automated coverage of section 16 and developer deployment/run instructions.

### P2: Optional polish

- Additional table density/filter preferences, richer topology visualization,
  multi-revision comparison ergonomics, and non-blocking redundancy hints.
- No P2 work should introduce unsupported backend claims or delay safety handling.

Frontend deliverables:

1. Application source with dependency lockfile and documented build/run commands.
2. Same-origin development proxy configuration and production hosting guidance.
3. Reusable API/data schemas, resource forms, and transaction lifecycle handling.
4. Automated unit/component/integration tests and critical browser workflows.
5. UI states/design assets for normal, pending, stale, denied, drift, unavailable,
   uncertain, rolled-back, and recovery-failed states.
6. Explicit list of deployment inputs and any unresolved product decisions.

## 16. Acceptance and verification plan

Use the simulator for end-to-end configuration/lifecycle tests, mocked API cases
for deterministic failures and boundary conditions, and an explicitly disposable
Linux namespace for native behavior. Simulator success does not verify Linux
networking or real softflowd delivery.

| ID | Scenario | Required result |
| --- | --- | --- |
| A01 | Missing/invalid credential | `401` shown; no token persistence/logging; no polling loop |
| A02 | Valid read credential, `/state` observation fails | Transaction/runtime diagnostics still usable; state marked unavailable |
| A03 | Stage edits on multiple pages | One shared draft; zero mutation requests until apply |
| A04 | Edit only a route | Submitted package preserves all unrelated subsystems |
| A05 | Submit valid package | `202` shown as pending, not committed; desired revision unchanged |
| A06 | Confirm before deadline | Server reports committed; revision increments once; caches refresh |
| A07 | Do not confirm | UI waits for server rollback result; revision/history unchanged |
| A08 | Manual rollback/repeated lifecycle action | Server outcome respected; no duplicate revision; reason visible |
| A09 | Apply fails, rollback succeeds | `rolled_back` and original error/reason visible; no false commit |
| A10 | Recovery fails | Persistent critical banner; new applies/restores blocked; retry rollback available |
| A11 | Stale base/another operator commits | `409`; draft retained and marked stale; no auto-rebase/resubmit |
| A12 | External modeled drift | Expected-versus-observed comparison; no force/automatic overwrite |
| A13 | Connection drops after intent is durable | Outcome unknown; transaction discovery; no automatic POST retry |
| A14 | Reload/reconnect with pending transaction | Token re-entry then active transaction rediscovery and deadline/actions |
| A15 | Submit latency consumes confirmation window | Remaining time uses original server deadline, not response time |
| A16 | Browser clock skew/background throttling | Absolute deadline shown; fresh server state determines outcome |
| A17 | Permission denied on submit/confirm/rollback | `403` explicit; draft/transaction retained; authorized recovery guidance |
| A18 | Firewall/NAT reorder | Wire payload preserves exact order; diff displays moves |
| A19 | Address versus network input | Host address `/24` retained; non-network selector rejected with suggested correction |
| A20 | IPv6 and numeric endpoints | Canonicalization, brackets, zones, mapped addresses and family checks exercised |
| A21 | VLAN cycles/duplicate identity/MTU mismatch | Linked local errors; invalid package not submitted |
| A22 | Protected parent missing/replaced | Read-only diagnostic retained; no API recreate/edit control |
| A23 | Interface kind or VLAN parent/ID change | Locked for existing interface; replacement workflow explained |
| A24 | Delete referenced interface | Dependency impact visible; no silent cascade; invalid references block apply |
| A25 | Masquerade egress missing family address | Local error; family-correct managed options only |
| A26 | WireGuard field/key/allowed-IP validation | Constraints enforced; no private-key input or unsupported tunnel-health claims |
| A27 | softflowd limits and disabled entries | 16-instance limit, full disabled-entry validation, timeout/filter byte boundaries |
| A28 | Running/unhealthy/exited/simulated service | Correct labels; PID only when supplied; no delivery claim |
| A29 | Reconcile services with unsent draft | Bodyless action uses stored state; draft unchanged; no revision created |
| A30 | Paginate committed history | Correct exclusive cursor, descending revisions, exhausted/empty handling |
| A31 | Legacy metadata | Null timestamps/unknown actors displayed honestly; no guessed dates |
| A32 | Restore older revision including 0 | Restore endpoint used; full impact preview; confirmation creates next revision with provenance |
| A33 | Restore key unavailable/current restriction | Server failure shown; history unmodified; transaction inspected if supplied |
| A34 | Invalid/partial/oversized JSON import | Explicit errors; no silent deletion, truncation, or write |
| A35 | UTF-8 size boundaries | 1024-byte trimmed description, 4096-byte filter, 1 MiB full request limits tested |
| A36 | Revision above JS safe-integer limit | Exact list/detail/cursor/base/provenance round-trip with unquoted JSON integers |
| A37 | Non-JSON proxy failure/incompatible API data | Visible diagnostic; uncertain writes reconciled; no empty-state success fallback |
| A38 | Keyboard/mobile critical workflow | Review, confirm, rollback and recovery usable at 375px and keyboard-only |
| A39 | Another tab/operator completes transaction | UI refreshes lifecycle/desired state without local ownership assumptions |
| A40 | Long operation blocks reads | No overlapping request storm, invented progress, or duplicate mutation |

Test every inclusive numeric bound and at least one value immediately outside
each bound. Test required request shape and exact API paths/methods, not only UI
snapshots. Include an automated assertion that tokens never enter storage, URLs,
exports, or application logs.

## 17. Source references

- [README](README.md): supported scope, deployment, lifecycle and ownership.
- [HTTP routing and authorization](internal/httpapi/api.go): endpoint behavior,
  error statuses, body limits and permission checks.
- [Configuration model and validation](internal/control/config.go): core resources,
  normalization, addresses, routes, policy, filtering and NAT.
- [VLAN/softflowd/runtime models](internal/control/extensions.go): extended fields
  and constraints.
- [Transaction engine](internal/control/engine.go): state machine, confirmation,
  rollback, deadlines and persistence behavior.
- [Runtime reconciliation](internal/control/runtime.go): service-only repair.
- [Revision archive](internal/control/revisions.go): history, metadata and restore.
- [Daemon setup](cmd/netcontrold/main.go): listener, TLS, backend and operator flags.
- [Migration example](examples/migration.json) and
  [VLAN/softflowd example](examples/vlan-softflowd.json): complete request examples.
