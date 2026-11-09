# Netcontrol frontend specification

## 1. Purpose and contract

Build an administrative web application for the Netcontrol host-managed firewall
appliance. Operators must be able to discover host NICs, inspect owned networking, prepare a
complete desired configuration, review its effects, provisionally apply it, and
explicitly confirm or roll it back. They must also be able to inspect transaction
recovery, restore committed revisions, and diagnose native protocol workers.

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
- Unicast routes; source-policy routing is not user-configurable.
- Ordered forward-chain source/destination accept/drop rules and default policy.
- Named IP-based outbound host policies, ingress-interface rule overrides,
  optional managed egress-interface matches, Any/TCP/UDP/ICMP/ICMPv6 protocols,
  TCP/UDP destination ports, and
  automatic established/related return traffic.
- IPv4/IPv6 masquerading.
- Exact-port IPv4/IPv6 destination rewrite of forwarded traffic originally
  routed through a selected WAN to another device on a managed LAN.
- Transactional global IPv6 enable/disable policy, disabled by default.
- WireGuard key references, peers, endpoints, allowed networks, and keepalive.
- Typed softflowd configuration, runtime inspection, and explicit reconciliation.
- Per-interface DHCPv4 relay server lists and enable flags, native Rust relay,
  runtime inspection, and explicit service repair.
- Explicit opt-in host-clock NTP and whole-appliance remote syslog workers,
  using host networking; dual host/managed-namespace native traffic accounting with persistent
  separate databases, all-interface discovery, status and repair.
- Native mDNS/DNS-SD reflection across selected managed LANs, service/provider
  filters, optional appliance publishing, status and repair (section 6.1.7).
- Complete-package transactions, confirmation, rollback, and recovery.
- Committed configuration history, comparison, export, and historical restore.
- Read-only namespace interface counters and IP/TCP/UDP/ICMP protocol statistics,
  including explicit partial/unavailable and simulator states.
- Read-only native conntrack connection snapshots with original/reply tuples,
  protocol state, NAT status and nullable per-direction packet/byte accounting.
- Read-only host NIC discovery and explicit Ethernet static configuration.
- Initial physical-NIC inheritance on supported native host installations,
  in-process DHCPv4 clients and per-interface systemd-resolved configuration.
- Ubuntu import-preserving console LAN/WAN provisioning, explicit factory-reset
  LAN-to-WAN masquerade and
  service-managed host IPv4 forwarding after native policy reconciliation.
- Persisted host-input default policy and managed-ingress rules, with implicit
  loopback and established/related acceptance when input filtering is configured.
- Persisted descriptive display names and notes on configurable resource records,
  separate from technical identities and references.

Do not present as supported:

- Hardware creation, parent adoption, namespace creation or selection
  through the API, bridges, DHCP server management, DHCPv6 clients/relay, DNS
  server management, or forwarding sysctl management. Active NetworkManager
  IPv4 capture is supported only during console host takeover, not as browser
  manager control. Dynamic global IPv6 inheritance is not implemented.
- Static SNAT, general DNAT/port forwarding beyond destination rewrite,
  arbitrary protocol matches/port ranges, sets, conntrack
  controls, traffic control, NIC offload/channel/ring/coalescing tuning, or
  hardware offload. Explicit RPS tuning is documented separately below.
- Private-key upload/generation, key-file listing, package installation, arbitrary
  commands, process identity configuration, or systemd control.
- Calendar-aggregated throughput/history, flow records, collector-delivery
  verification, or real-time server push.
  Client-derived interface rate charts are optional, subject to section 6.1.1.
- Multi-user account administration, API-key permission discovery,
  a tamper-evident audit log, or multi-device coordination. Single-device setup
  and named API-key creation/revocation are provided by the embedded website.

Label the product **Firewall appliance**. Production readiness still requires
Linux packet-path, reboot and recovery acceptance; do not describe a package
apply as an atomic kernel transaction.

### 1.3 Rust request and persistence contract

The backend is a Rust-only workspace. There is no Go executable, state importer,
protocol-daemon wrapper, or compatibility endpoint. Packages use the signed
`.ncpkg` format and native package tool, not APK/abuild.

Request JSON rejects unknown fields in the envelope, but `POST /api/v1/transactions`
drops unknown keys anywhere inside `config` and reports them (see
[Unknown configuration fields](#unknown-configuration-fields)). Non-optional fields, arrays, and maps reject
explicit `null`; omitted defaultable collections become empty. Optional
`wireguard`, `vlan`, and `firewall.policies` may be null/omitted. Measurement
nullability in responses is separate from request validation.

Missing structurally required fields return `400`, rather than being decoded as
zero values and subsequently failing semantic validation. Required fields:

| Object | Required fields |
| --- | --- |
| Transaction submit | `config`, `confirm_timeout_seconds` |
| Revision restore | `confirm_timeout_seconds` |
| Interface | `name`, `kind`, `role`, `mtu`, `up` |
| WireGuard / peer | `key_ref`, `listen_port` / `public_key` |
| VLAN | `parent`, `id` |
| Route | `destination`, `interface`, `table`, `metric` |
| Policy rule | `priority`, `source`, `table` |
| Firewall/host rule | `action` |
| Masquerade rule | `family`, `out_interface` |
| Destination rewrite rule | `out_interface`, `protocol`, `destination_port`, `target_interface`, `target_address` |
| Firewall host | `id`, `name`, `addresses`, `policy` |
| Ingress policy | `interface` |
| Syslog destination | `host`, `port`, `transport` |
| Flow exporter | All configuration fields except `capture_filter`, `timeouts`, `metadata` |
| Gateway monitor | Identity/enabled/interface/target; explicit mode also needs source/gateway/table; timing fields remain defaultable |

`firewall.spoof_block` and `firewall.allow_all_icmp` default to true only when omitted; explicit null is
`400`. An omitted firewall/policy defaults to `"accept"`. Invalid semantic values
still return `422`.

Transaction responses no longer expose `kernel_before` or `kernel_after`;
kernel-original ownership belongs to native persistence. Use the kernel
inspection endpoint. Runtime may include `kernel_tunables` with `desired`,
`configured`, `effective`, `observed`, `captured_original`, and `drift`.
Service repair rejects observed networking drift with `409`. Native observation
errors return `503`; startup reconciliation errors fail startup rather than
advertising a successfully initialized but unreconciled engine.
The repair precheck verifies network/kernel ownership independently of worker
health, so a failed enabled worker does not itself block explicit service repair.
Repair never bypasses networking drift protection.

Network state uses the checksummed `netcontrol-rust-state-v2` envelope with
`schema`, `sha256`, and `state` fields, limited to 256 MiB. The state contains
scope, revision, initial revision, desired configuration, nullable active transaction ID,
initialization timestamp, and transaction map. Incompatible/corrupt data is
rejected without import, deletion, or reset. Revisions retain
`{revisions,next_before_revision?}` and flattened detail metadata plus `config`;
default list limit 50, range 1..100, exclusive date-version string `before_revision`.
Numeric-revision v1 journals are incompatible and refused unchanged; no automatic
conversion or state reset is provided. An explicitly operator-run
[offline date-revision conversion](docs/BUILD_AND_INSTALL.md#offline-date-revision-state-conversion)
is available with private backups and a numeric-to-date revision mapping.
It preserves configuration/history, rejects active or invalid state and does
not add numeric aliases to the API. After conversion, refetch current state and
history; invalidate cached numeric revision IDs/cursors and re-review stale drafts.

Identity and scoped-auth files require their own `schema: 1` JSON roots; these
are not the network-state envelope. A scoped file is
`{"schema":1,"credentials":[{"name":"dashboard","token_sha256":"<64 hex characters>","permissions":["state.read"]}]}`.
It requires 1..100 unique credentials, known nonduplicated permissions, and a
maximum file size of 1 MiB. Empty permissions grant nothing. Unknown fields,
bare credential arrays, and unsupported schemas are rejected. `--auth-file`
and explicit `--credential-db` are mutually exclusive. Scoped-file revocation
requires restart; device-managed key revocation is immediate for future requests.
No old identity, network-state, or vnStat database importer/reset is provided.

CLI options use `--long-options`. External executable, child UID/GID,
runtime-directory, `--backend-log-file`, and `--syslog-ca-file` settings are
removed. The backend audit file is `<services-state-dir>/backend.log`; native syslog
receives journald-forwarded messages via systemd socket activation, and syslog TLS
uses system CA trust. See the [daemon contract](crates/netcontrold/README.md)
and [installation guide](docs/BUILD_AND_INSTALL.md) for current deployment flags.

### Unknown configuration fields

`POST /api/v1/transactions` prunes unknown keys at any depth inside `config`
(objects inside arrays included), then validates what remains exactly as before.
The `202` body is the usual transaction plus an always-present array:

```json
{"id":"0123456789abcdef0123456789abcdef","status":"pending_confirmation","ignored_fields":["/config/future_option","/config/interfaces/0/preferred_new_option"]}
```

(Abbreviated; the real body also carries the full transaction.) Entries are
RFC 6901 JSON Pointers into the submitted request (`~0`/`~1` escaped, zero-based
indexes), in discovery order, at most 256; more fails with `400`. Dropped keys are
absent from `candidate`, saved state, history and the native backend, so
`GET /api/v1/transactions/{id}` does not list them later. An empty array means
nothing was dropped.

Only unknown keys are tolerated. Wrong types, `null` for non-optional fields,
missing required fields, unknown keys in the request envelope
(`base_revision`, `confirm_timeout_seconds`, `description`, `config`), trailing
JSON, oversized bodies and semantic validation failures still return `400`/`422`.
`POST /api/v1/revisions/{revision}/restore` is unchanged and its response has no
`ignored_fields`. Saved journal/history, native ownership, credentials and signed
packages still reject unknown fields.

A dropped key is a silent no-op for the field you meant: a misspelled
`firewall.allow_all_icmp` or an inline secret such as `mqtt.password` is ignored,
not refused. Show `ignored_fields` to the operator after every submit, treat a
nonempty list as a warning, and do not claim a setting was applied unless it
appears in `candidate`.

### 1.4 Descriptive Object Metadata

The following resource objects accept optional `metadata` containing optional
string `display_name` and `description` fields. This is part of the full desired
configuration, not a separate annotation endpoint.

| Resource | Metadata location |
| --- | --- |
| Ethernet, dummy, VLAN, WireGuard interface | `interfaces[].metadata` |
| WireGuard peer | `interfaces[].wireguard.peers[].metadata` |
| DHCP relay | `interfaces[].dhcp_relay.metadata` |
| DHCP client | `dhcp_clients[interface].metadata` |
| DNS settings / domain | `dns[interface].metadata`, `dns[interface].domains[].metadata` |
| Route | `routes[].metadata` |
| Ordered firewall rule / masquerade rule | `firewall.rules[].metadata`, `firewall.nat.masquerade[].metadata` |
| Destination rewrite rule | `firewall.nat.destination_rewrite[].metadata` |
| Firewall host / outbound host rule | `firewall.policies.hosts[].metadata`, `firewall.policies.hosts[].rules[].metadata` |
| Interface policy / rule | `firewall.policies.interfaces[].metadata`, `firewall.policies.interfaces[].rules[].metadata` |
| Input interface policy / rule | `firewall.input.interfaces[].metadata`, `firewall.input.interfaces[].rules[].metadata` |
| NTP / syslog / vnStat settings | `ntp.metadata`, `syslog.metadata`, `vnstat.metadata` |
| mDNS settings | `mdns.metadata` |
| UDP broadcast relay / instance | `udp_broadcast_relay.metadata`, `udp_broadcast_relay.instances[].metadata` |
| Syslog destination | `syslog.servers[].metadata` |
| Flow exporter / gateway monitor | `softflowd[].metadata`, `gateway_monitors[].metadata` |
| Azure Dynamic DNS entry | `dynamic_dns[].metadata` |

VLAN and WireGuard interface labels belong on the containing interface, not on
the nested VLAN tag/key-settings objects. Container objects (`config`, `firewall`,
`nat`, `kernel`, policy collections) and scalar address/server lists do not gain
their own metadata fields.

Valid interface example (technical identity is still `eno1`):

```json
{
  "name": "eno1",
  "kind": "ethernet",
  "role": "wan",
  "mtu": 1500,
  "up": true,
  "metadata": {"display_name": "Internet uplink", "description": "Primary ISP handoff"}
}
```

- Omitted metadata/strings default to empty strings. Empty metadata is omitted
  from serialized responses; a nonempty object serializes both string fields,
  including an empty companion field. `{}` clears both fields in the submitted
  complete configuration. Explicit null, wrong types and unknown metadata fields
  are `400`, not defaults.
- `display_name`: empty or up to 128 Unicode scalar values, no control characters;
  a nonempty whitespace-only value is invalid. `description`: up to 2048 Unicode
  scalar values, with newline/tab allowed but other control characters rejected.
  Semantic violations return `422`. Text is preserved, not lowercased or trimmed.
  Count Unicode scalar values rather than UTF-8 bytes or UTF-16 code units.
- Display names need not be unique. They never rename a kernel link, change VLAN
  identity, peer key, route/policy identity, exporter/monitor name, host ID/name,
  references, worker identity or firewall matching. Existing identifier validation
  remains authoritative.
- Use existing full-package transaction/confirmation/rollback/history/restore
  workflows. Metadata-only edits require `transactions.write` and the same
  resource write permissions as functional changes: `interfaces.write` for
  interface/relay/client/DNS metadata; `wireguard.write` for peer metadata;
  `routes.write`, `nat.write`, `firewall.write`, `ntp.write`,
  `syslog.write`, `vnstat.write`, `mdns.write`, `softflowd.write`, `gateway_monitors.write`
  for the corresponding objects. No new permission or HTTP method/path is added.
- Native operational configuration excludes these annotations. Metadata-only
  applies verify the existing configuration but do not take the native network
  mutation/worker-restart path. Linux Ethernet display names separately update
  descriptive link aliases as described below. Saved state, transaction candidates/previous
  configs and revision details retain annotations. Normal drift checks remain.
  Observed resource metadata is configuration-derived, not evidence that Linux
  or a remote peer reports that display name. Discovery/runtime identifiers
  remain technical; join them with desired configuration for labels.
- Required frontend work: add optional display-name/description controls on all
  listed editors, include metadata in shared drafts/import/export/review/restore,
  and preserve it when changing unrelated fields. Display a friendly label with
  the technical identity still available; selectors submit technical keys, not
  labels. Blank labels fall back to the existing name/ID/prefix/key. Sort/search
  may include labels without changing backend object identity or rule ordering.
  Render all annotation text as text, never raw HTML.

**Linux physical-interface labels:** configured `kind:"ethernet"` interfaces
receive one descriptive `IFLA_IFALIAS`, not a rename or an alternative interface
name. A nonempty `metadata.display_name` becomes `DISPLAY_NAME [ROLE]`, with
uppercase `WAN`, `LAN` or `UNASSIGNED`; an empty display name uses the role alone.
For example, `Internet uplink` with `role:"wan"` produces
`alias Internet uplink [WAN]` under the unchanged `eno1` entry in `ip -d link show`.
It does not produce `WAN@eno1`: `NAME@PARENT` describes link topology, not a label.

Linux permits a single alias of at most 255 UTF-8 bytes. If necessary, only the
display-name prefix is shortened at a UTF-8 character boundary to leave room for
the complete role suffix. Saved text and its existing 128-character validation
remain unchanged. Descriptions do not affect aliases. Unmanaged NICs, configured
VLAN/dummy/WireGuard interfaces and actual interface identifiers are untouched.

Aliases are reapplied on successful native apply/startup repair, including
name/role edits and clearing a display name. Metadata-only updates do not restart
networking/workers or change native network ownership. Original aliases are
durably preserved and restored on unmanagement; interrupted/failed label updates
restore their pre-update aliases with identity checks. Errors use the existing
transaction failure/recovery flow, not a success-shaped fallback. Cosmetic alias
drift alone does not become network drift; configured metadata in API replies
is still not an independent kernel alias observation. There are no new fields,
endpoints, permissions or stricter text limits. Optional frontend work: explain
the combined kernel label and possible display-prefix shortening without
replacing technical keys or shortening the saved name.

### 1.5 Native mDNS implementation status

The [native mDNS / DNS-SD build specification](docs/MDNS_SPEC.md) now has an
unreleased Rust implementation: reflection, service/provider filters, family
controls and optional appliance publishing. The current contract is in section
6.1.7. No Avahi daemon, external process or D-Bus service is used.

General multicast routing, SSDP, media forwarding, automatic service-port
firewall permits and CARP integration remain unsupported. Discovery does not
make a service reachable. Native namespace fixtures are not complete
VLAN/nftables/MLD, device interoperability, load, reboot or appliance acceptance.
The earlier planning item is superseded by
[implementation handoff 2026-10-25-17](docs/frontend-handoffs/2026-10-25.md#2026-10-25-17-native-mdns-implementation).

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
| `/interfaces` | All live interfaces, including read-only loopback; managed Ethernet/dummy/VLAN/WireGuard |
| `/interfaces/:name` | Interface detail and staged editor |
| `/parents` | Read-only adopted parent inventory |
| `/routes` | Routes |
| `/firewall` | Host inventory/outbound policies, ingress overrides, global default, or explicit legacy ordered-rule view |
| `/nat` | Masquerade and destination rewrite rules |
| `/wireguard` | WireGuard-focused interface/peer view |
| `/services/softflowd` | Configured instances joined with runtime status |
| `/services/softflowd/:name` | Instance detail and staged editor |
| `/changes` | Shared draft, comparison, import/export, apply review |
| `/transactions` | Transaction history |
| `/transactions/:id` | Transaction details and lifecycle actions |
| `/history` | Committed revision history |
| `/history/:revision` | Historical configuration, comparison, restore |
| `/settings/sando` | Sando base URL, hourly metadata sync and one-time host/rule imports |

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

Custom signed native package/OpenRC installation and automatic build artifacts are documented in
the [build and installation specification](docs/BUILD_AND_INSTALL.md).
Ubuntu fresh installation downloads the latest published stable GitHub Release
without a CI run ID, GitHub login or manual build. It selects a single canonical
calendar version, verifies the Ubuntu manifest, binary size/SHA-256, amd64 ELF
header and compiled version, and fetches the systemd unit from the same immutable
tag's source over verified HTTPS. Missing/invalid releases, rate limiting or
download failures stop installation; there is no CI-artifact/source fallback.
The installer uses Python 3 for metadata verification only; protocol services
remain in-process Rust. The Ubuntu assets are unsigned; trust rests on HTTPS and
the GitHub repository/account, not an independent publisher signature.
Installation/help text should use `sudo bash install.sh`, not the removed
`--run-id` option. Fresh installation also stops/disables and persistently masks
installed `snapd.service` and `snapd.socket`, including stopping already-masked
units. It verifies inactive/failed active state and persistent `masked` enablement
before appliance provisioning; missing units are skipped and failures abort.
Snap packages/data and separate application units are not removed. Snap
management/installation and refreshes are blocked; operator instructions must
require review of Snap-dependent workloads. It also disables automatic Ubuntu APT
checks, downloads and installs, **including security updates**, by persistently
masking present `apt-daily.timer`, `apt-daily-upgrade.timer`, `apt-daily.service`
and `apt-daily-upgrade.service` and verifying inactive/failed state. Running APT
jobs are never forcibly stopped; verification fails until completion and retry.
Absent units are skipped. The atomic root-owned mode-0644
`/etc/apt/apt.conf.d/99-netcontrol-no-automatic-updates` sets
`APT::Periodic::{Enable,Update-Package-Lists,Download-Upgradeable-Packages,Unattended-Upgrade}`
to `"0"` and `Unattended-Upgrade::InstallOnShutdown` to `"false"`.
Effective `apt-config dump` values must match; conflicting configuration fails.
Manual APT commands and Netcontrol release checks remain available. Operator
instructions must require planned manual OS patching and must not describe
disabled automatic security patching as a security improvement.
This host policy adds no API fields, permissions or web action and does not
change the saved firewall configuration.
Fresh installation and full source `upgrade.sh` deployments also remove standard
Ubuntu MOTD files, generator directories and cached messages, remove active
`pam_motd.so` lines from regular PAM configuration files, and stop/disable and
persistently mask standard MOTD services/timers (including masks for absent units).
Custom content in these targeted locations is deleted. Inspection, unit-control,
PAM-write and removal failures abort deployment; completed host cleanup is not
rolled back with the daemon binary. Authentication modules/credentials, firewall
state, `/etc/issue`, SSH `Banner` settings and embedded configuration SSH greetings
are unchanged. Build-only runs and HTTP/automatic HTTPS self-upgrades do **not**
apply MOTD cleanup. No HTTP methods/paths, schemas, permissions or status codes
change. Update operator installation/source-upgrade help, not API client types;
see [exact cleanup scope](docs/BUILD_AND_INSTALL.md#motd-cleanup) and
[handoff 2026-11-09-01](docs/frontend-handoffs/2026-11-09.md#2026-11-09-01-install-and-source-upgrade-motd-cleanup).
Interactive installs prompt for missing LAN interface and IPv4
host/prefix, suggesting the second physical port and `192.168.0.1/24`.
`--wan` overrides WAN independently; `--lan` and `--lan-address` skip their
individual prompts. Unattended installs require both LAN flags and fail if either
is missing. Invalid interactive answers are prompted again; EOF cancels.
The stable-release download mechanism itself adds no HTTP endpoint,
authentication permission or saved configuration schema.
An initial capture failure can leave an empty journal lock without a saved
journal. Fresh-install retries retain and reuse only a verified root-owned,
mode-0600, empty, singly linked regular lock that is currently unlocked, and
only while both journal and appliance environment are absent. Existing state,
environment and active/unsafe locks still block installation; no files are
deleted to force setup. See the installation guide for operator recovery.
Alpine packages and the bare daemon default to HTTP on `0.0.0.0:8080`.
Ubuntu's fresh appliance installer defaults WAN to the first physical Ethernet
NIC in natural name order (Wi-Fi/virtual NICs excluded). LAN is explicitly
selected through a prompt or flag. It can be a physical Ethernet port or an
existing standard 802.1Q VLAN on another physical port, with ID 1..4094.
Enter its real name, for example `vlan50`, not `vlan50@enp2s0`. Tagged LAN uses
the VLAN for its address, role, input/forwarding rules and NAT subnet; the physical
parent remains up, unassigned and without an untagged LAN address. VLAN-on-WAN,
stacked VLANs and unsupported ownership are rejected. The selected release must
support tagged provisioning; no physical-parent fallback is allowed.
LAN addresses must be canonical usable RFC1918 IPv4 hosts, prefixes 8..30,
entirely within RFC1918 space and not a network/broadcast address. WAN
retains imported static IPv4, routes and DNS; an empty WAN receives DHCPv4.
Provisioning preserves imported supported interfaces/firewall/MTU/routes/DNS
instead of replacing them with factory policy. It sets the chosen WAN/LAN roles,
enables those ports and replaces only the LAN's addresses/DHCP client. It does
not invent LAN allow-all, WAN input denial or NAT; operators must review the
imported rules, including literal subnets affected by the LAN address choice.
The console transaction commits after verification without a connectivity or
WAN-readiness timer, and interrupted provisioning resumes its durable candidate.
Unsupported networking/managers are not restored on connectivity loss.
Explicit factory reset retains its separate factory contract.
The installer starts/enables the service with `--appliance` and binds HTTP to the selected LAN address using
`/etc/netcontrol/appliance.env`; there is no new HTTP provisioning endpoint.
LAN clients need static addressing/gateway; no DHCP/DNS server is provisioned.
Existing installations are not rerun or reset by the installer. A root-only
local `--configure-lan NAME --lan-parent NAME --lan-vlan ID --lan-address CIDR`
command can move an unchanged factory physical LAN to an explicitly identified
VLAN. Customized policy, extra LAN addresses and conflicting existing VLAN
settings are refused. It uses a normal 120-second provisional transaction;
verify tagged connectivity and explicitly confirm through
`--confirm-network-change ID` or the authenticated transaction API/SSH CLI.
Unconfirmed changes roll back. After confirmation the operator must update only
`NETCONTROL_LISTEN` in `/etc/netcontrol/appliance.env` and restart the service;
the HTTP listener is not automatically rebound by network transactions.
Keep console access throughout. See the [CLI guide](docs/CLI.md#correcting-an-initially-untagged-factory-lan).
Ordinary native startup and `upgrade.sh` require a saved journal and apply that
desired configuration; they never initialize desired state from current NIC
settings. Managed-interface drift is reconciled to the saved plan, subject to
native identity, ownership and foreign-resource checks. Live snapshots are used
only for rollback, not as a new desired configuration.

Ubuntu fresh installation and full `upgrade.sh` deployment now load
`nf_conntrack` and enable/persist host `net.netfilter.nf_conntrack_acct=1` and
`net.netfilter.nf_conntrack_checksum=1` before provisioning/daemon replacement.
The installer supplies `procps`/`kmod`; existing upgrade hosts must already have
them. Setup failure aborts before daemon replacement; partially applied host
prerequisites are not rolled back. `--build-only`, factory reset, signed-package
installation and the HTTP read API do not run this setup. Other network
namespaces still need explicit operator configuration. Existing connections
can retain null counters; no table flush, state reset or browser setup action
is added. See [host persistence and limitations](docs/BUILD_AND_INSTALL.md#conntrack-host-prerequisites).

Initial installation and explicit reset share the same clean factory configuration
builder; inherited OS settings are handover/rollback data, not factory defaults.
The operator-only `sudo bash reset.sh` asks for default-No confirmation before
any host checks or changes; `--yes` skips the prompt for unattended use. Blank,
declined/invalid input or EOF cancels. It replaces current networking with factory
WAN/LAN defaults using a locally authorized transaction. This is not an HTTP
endpoint or identity reset. It preserves account/API credentials, key files and
revision history; revision increments rather than returning to zero. Other saved
Ethernet interfaces become unassigned with MTU 1500, up, without configured
addresses/DNS/DHCP; custom virtual interfaces/routes/policies/service settings
are removed from current desired configuration. Wi-Fi association remains with
the supplicant. Factory reset does not wait for WAN DHCP before committing the
LAN recovery configuration. It requires console access, an existing valid saved
configuration and no active core transaction; native recovery intents are not
discarded. It reinstalls the appliance service and LAN HTTP binding, starts and
enables the service, and defaults to `http://192.168.0.1:8080/` afterward.
After backup and before native recovery, reset retires the temporary
`/run/systemd/network/00-00-wifi-recovery.network` override into its private
backup, ending temporary networkd Wi-Fi DHCP ownership. The file is not restored
automatically on failure. Unrelated networkd files and native identity/ownership
checks remain unchanged; reset does not forcibly disable all network managers.
Explicit reset builds its candidate from saved desired configuration without a
pre-reset live-address observation; drifted recovery addresses must not prevent
reset preparation. Post-apply verification, transaction/identity/ownership checks
and rollback remain. Normal observation-backed HTTP state behavior is unchanged.
Frontend/operator guidance must distinguish upgrade, network reset and identity
reset; after reconnect, refetch state/revision and discard or explicitly rebase
stale drafts. Do not restart onboarding or expose a nonexistent HTTP reset API.
Changing the management IP requires operator coordination of that environment
file and service restart; an API interface-address edit alone does not rebind
the listener. The persisted input policy enforces WAN denial; binding alone is
not an ingress ACL. Removing the input policy removes that protection.
Package arguments select native Linux host mode; the bare daemon defaults to simulator development mode.
Package installation must not be presented as proof of native networking readiness.
The embedded website requires no separate frontend build.

Optional Ubuntu OS footprint reduction is a separate console operator workflow:
`sudo bash hardening.sh` previews only; `--apply` stops/disables explicit printing,
mDNS discovery and crash-reporting units and purges only explicit installed
profile packages. Dependency removals outside that list are refused; there is no
autoremove. It also previews, then only with `--apply` stops/disables and
persistently masks installed `snapd.service` and `snapd.socket`, with stopped/
persistent-mask verification. Already-masked Snap units are still stopped;
absent ones are skipped. Snap packages/data are retained, and separate Snap
application units are not explicitly stopped; this is not full app removal.
Snap management and refreshes are blocked. Existing hosts must explicitly run
reviewed hardening to apply this policy; binary/source upgrades alone do not.
It also previews, then applies the same verified automatic-APT policy as fresh
installation, retaining packages/manual APT access and recording prior unit
states and the owned APT fragment (or its absence) for deliberate recovery.
Cached login update notices may remain; arbitrary third-party schedulers and
graphical updaters are outside this Ubuntu APT policy.
Network, Wi-Fi, SSH, time synchronization and build tools are not
targeted. The full footprint/purge profile is not automatically run during
installation/upgrade/reset and adds
no HTTP endpoint, browser action, permissions or schema fields. mDNS discovery
may disappear, so operator instructions should use the appliance IP.
AppArmor remains enabled by default. `--disable-apparmor` explicitly opts out of
that protection, with `--apply`, via a GRUB `apparmor=0` boot drop-in and disabled
service. GRUB is required, packages are retained, and kernel enforcement changes
only after a manual reboot. Do not present the opt-out as a security improvement
or as verified immediately from a service stop. Private state records are not a
full package/configuration rollback. See [scope/recovery](docs/BUILD_AND_INSTALL.md#ubuntu-os-footprint-reduction).

**Operator prerequisite:** Use operator-configured, reachable frontend/API origins.
Direct onboarding is available at `http://<appliance-LAN-IP>:8080/` with no SSH
tunnel or certificate. HTTP is permitted on non-loopback listeners. TLS is
optional and requires both `--tls-cert` and `--tls-key`; providing only one fails
startup. Wildcard IPv4 binding includes WAN interfaces and does not establish a
LAN-only access policy. HTTP sends passwords, session cookies, and API keys
unencrypted; do not describe it as a secure connection.
A same-origin deployment may forward `/api/v1` to Netcontrol; a separate dashboard
origin may call the configured firewall URL directly using API-key authentication.
In default device mode the daemon
serves a small embedded onboarding/key-management website at `/`; the broader
networking dashboard specified here still needs a separate frontend. Scoped
`--auth-file` mode serves only the networking API. Both modes allow all origins
for `/api/v1/` using `Access-Control-Allow-Origin: *`, including error responses.
Preflight `OPTIONS` requests need no authentication and return `204` for `GET`,
`POST` or `DELETE` with `Authorization` and `Content-Type` request headers (case-insensitive
header names). Unsupported preflight methods return `405`; unsupported requested
headers return `400`, with the normal API JSON error shape. Non-preflight
`OPTIONS` requests still require authentication and are not new API operations.
Responses expose `Location`, `WWW-Authenticate`, and `Retry-After`.
Use `credentials: "omit"` and an explicit Authorization Bearer header for cross-origin API
calls; `Access-Control-Allow-Credentials` is not enabled. Actual authentication,
permissions, and device setup completion requirements are unchanged.
A Vite/development proxy may still provide same-origin API paths locally.
`/auth/` and website assets do not enable CORS: onboarding and key management
remain on the device's own origin, with existing cookie/origin protection.
For HTTPS device website access use native TLS; `/auth/` origin and Secure cookie
checks do not trust forwarded headers. HTTP sessions keep HttpOnly and
SameSite=Strict cookies but do not have the Secure attribute. Authentication,
same-origin mutation checks, and API-key requirements remain unchanged.
An HTTPS dashboard may be blocked from calling an HTTP API by mixed-content
rules even with CORS; use a matching deployment/proxy or enable TLS as appropriate.
Allow-all CORS does not bypass TLS/certificate checks, mixed-content blocking,
network reachability, or browser local/private-network access restrictions.
No private-network CORS opt-in is advertised; test the target browser/environment
and use operator-approved permissions or a trusted management proxy as needed.

The frontend API base is deployment configuration, not arbitrary user input in
the initial release. Do not send an operator's API key to a URL supplied by a query
parameter, imported file, or untrusted content. No external analytics or services
may receive configuration, API keys, session tokens, or diagnostic payloads.

**Frontend decision:** Default to a relative `/api/v1` base and a deployment-supplied
label/mode (`Linux`, `Simulator`, or `Unknown`). No current API exposes backend
mode or a general namespace/running-version/capability inventory. Software-upgrade
status (section 4.5) exposes only upgrade configuration and historical success,
not the running software version. Never infer Linux operation from an empty
service list or fabricate a namespace label.

### 4.2 Credential flow

#### Device onboarding and key management (implemented)

**Terminology:** Label the firewall access credential **API key** everywhere in
the UI, help, and user-visible errors, not "bearer token" or "API token".
`Bearer` names the HTTP authorization scheme, not the credential. The existing
`token` key-creation response field and `token_sha256` auth-file field still mean
the API key and its hash; these technical field names are unchanged. Device
session tokens remain distinct from networking API keys.

Without `--auth-file`, `/` hosts a three-step setup wizard: username/password,
named automatically generated API key(s), then saved-key acknowledgement and
completion. Anyone reaching an unclaimed device can claim it; restrict management
network access until setup completes. Networking API keys do not work before
completion. An interrupted account setup resumes through password sign-in.

Credentials live in an owner-restricted Rust credential store, separate from
network state, using Argon2id password hashes and SHA-256 hashes of random
256-bit API keys. Persisted Rust formats are not Go/bbolt import formats; an
incompatible store must fail explicitly, never be reset or silently imported. API-key
plaintext is returned only by creation, shown in a one-time dialog, cleared when
hidden, and never persisted in browser storage. Lists show name, creation time,
and a masked suffix (last four characters). Lost-response recovery is removal and
replacement, never fetching plaintext. New keys have all networking permissions.

The device account manages keys using an HttpOnly, SameSite=Strict session cookie
scoped to `/auth/`, Secure with native HTTPS, expiring after 30 minutes. Mutations
require `Content-Type: application/json` and a matching `Origin` header. Sign-out
invalidates the session. Networking API endpoints require API keys sent using the
Bearer scheme; sessions do not authorize them, and API keys cannot manage device credentials.

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
The 32-session limit returns `409`; duplicate key names/key-count limits return
`400`. Sessions have a fixed, non-sliding 1,800-second lifetime, persisted across
restart. The cookie is `netcontrol_session`, with `Path=/auth/`, `Max-Age=1800`,
HttpOnly and SameSite=Strict; Secure is set only on the actual TLS listener.
Setup/login request bodies are limited to 4,096 bytes; other bodies to 1 MiB.
Unknown fields, missing required fields, null bodies, and trailing JSON return
`400`. Body-read timeout after ten seconds currently also returns the
`400` body-too-large error. After an identity write failure, credential operations
fail closed until restart; API-key lookup returns
`503 {"error":"credential store unavailable","transaction":null}`.

The account can remove even the last key and generate replacements; no password
reset, remote recovery, API-key expiration, or managed-key permission editor is
provided. `--auth-file` is an explicit alternative, not an automatic migration.

#### Connecting the broader networking dashboard

1. Show a masked **API key** input and **Connect**.
2. Keep the API key in memory only. No API key in local/session storage, URLs, logs,
   error trackers, exported files, or service-worker caches.
3. Validate access using authenticated reads. A successful transaction-list read
   establishes read access even if `/state` returns an observation error.
4. On success, load the shell and separately load state, runtime, and relevant
   history. Show independent failures rather than failing the whole application.
5. On `401`, stop background requests and request a credential again. Keep an
   in-memory draft until the operator explicitly discards/disconnects; do not
   silently lose it when an API key becomes invalid.
6. Disconnect clears the API key, cached server data, and draft after an unsaved-change
   warning. If a transaction is pending, explain that disconnecting does not
   confirm, cancel, or reliably trigger immediate rollback.

The device-account session above does not authenticate this networking client.
A dashboard reload requires API-key re-entry. Clearing an API key from the browser does not
revoke it; use device key management (or operator edits/restart in legacy mode).

### 4.3 Authorization

All reads require `state.read`. POST actions require `transactions.write`, except
the per-interface DHCP retry action (`interfaces.write`), MQTT password upload
(`mqtt.write`), Discord webhook upload (`discord.write`) and software upgrade
submission (`system.upgrade`).
Operational restart requires `system.restart`; an on-demand DNS lookup requires
`diagnostics.run`, not `transactions.write` or `state.read`. These permissions
do not grant configuration editing. Paired path-test start/cancel requires
`diagnostics.run`, `interfaces.write` and `firewall.write` together because it
temporarily changes live MTUs and permits test traffic. It does not edit saved
configuration or use `transactions.write`. Device-account
API keys have all permissions,
including upgrade authority when the operator explicitly enables self-upgrade;
scoped credential files must grant `system.upgrade` explicitly.
Firewall deny history has the separate `firewall.logs.read` permission; neither
`state.read` nor `firewall.write` grants traffic-log access. Device-account keys
include it; scoped keys must explicitly grant it.
Configuration changes additionally require permissions for every changed area:

| Change | Additional permission |
| --- | --- |
| Interface/address/VLAN fields, roles, DHCP relay/client settings, resolver maps | `interfaces.write` |
| WireGuard settings and removal of a WireGuard interface | `wireguard.write` |
| Routes | `routes.write` |
| Filter policy/rules | `firewall.write` |
| Masquerading / destination rewrite | `nat.write` |
| softflowd configuration | `softflowd.write` |
| Gateway monitor configuration | `gateway_monitors.write` |
| NTP server/client settings | `ntp.write` |
| mDNS reflection/publishing and metadata | `mdns.write` |
| UDP broadcast/multicast relay and metadata | `udp_broadcast_relay.write` |
| BGP ASN, router ID, timers, neighbors and import policy | `bgp.write` |
| Whole-appliance syslog/remote destinations | `syslog.write` |
| Host plus managed-namespace native traffic accounting | `vnstat.write` |
| MQTT streaming configuration | `mqtt.write` |
| Discord alert configuration and private webhook upload | `discord.write` |
| Host name and time zone (`system`) | `system.write` |
| Sando URL and frontend-reported import state (`sando`) | `sando.write` |
| Azure Dynamic DNS configuration and secret upload | `dynamic_dns.write` |

Creating/removing a WireGuard interface typically needs both interface and
WireGuard permissions. Confirm/rollback requires the permissions for the original
transaction's full previous-to-candidate difference, even for another submitter.
Restore also requires `state.read`. Service reconciliation requires `state.read`
and `transactions.write`, plus `softflowd.write` for the softflowd repair endpoint
or `interfaces.write` for DHCP relay repair, or `gateway_monitors.write` for
gateway monitoring repair. All service repair actions repair all enabled
services: also require `softflowd.write` when any softflowd instance is enabled,
`interfaces.write` when any DHCP relay is enabled or DHCP client/resolver maps
are configured, and `gateway_monitors.write`
when any gateway monitor is enabled. Authorization uses the
current committed/pending configuration under the engine lock, not the draft.

This shared-service permission rule also includes enabled NTP (`ntp.write`),
syslog (`syslog.write`), vnStat (`vnstat.write`), mDNS (`mdns.write`) and enabled
UDP broadcast relay (`udp_broadcast_relay.write`) on all eight service repair
endpoints. Each new endpoint additionally requires its own service write
permission even when disabled. See section 6.1.3 for host-wide effects.

There is no current-user or permissions endpoint. Do not probe authorization by
issuing writes. Deployment-supplied UI permission hints may disable controls, but
must be labeled advisory; otherwise offer actions and handle `403` explicitly.
Show permission errors near the action, preserve the draft, and explain that
another appropriately authorized operator may need to confirm or recover.

### Operational restart and DNS diagnostics

These are implemented, API-key-authenticated, explicit actions, not transactions
or background polling. Both paths accept POST only (`405` otherwise), no query
parameters (`400`), strict JSON objects with no unknown fields, and the normal
`401`/`403` authentication/permission errors. Neither changes desired
configuration or creates a configuration revision. Both reject an active
configuration transaction, recovery, upgrade or daemon restart with `409`.
Preparation/backend unavailability returns `503`. No shell commands, child
processes, arbitrary PID control or request-supplied resolver addresses are used.

#### Restart managed processes

`POST /api/v1/processes/restart`, permission `system.restart`:

```json
{"target":"ntp"}
```

`target` is a nonempty ASCII string, at most 80 characters, without control
characters. Exact supported identifiers:

| Target | Scope and prerequisites |
| --- | --- |
| `ntp`, `syslog`, `mdns` | Selected enabled native service worker |
| `vnstat` | All interfaces in the host namespace; vnStat enabled |
| `dhcp-relay` | Shared relay worker; at least one enabled relay |
| `flow:NAME` | One configured enabled flow exporter |
| `udp-broadcast-relay:ID` | One configured enabled UDP relay instance; global enable required, canonical decimal ID 1..63 |
| `gateway:NAME` | One configured enabled explicit gateway monitor |
| `dhcp-client:INTERFACE` | One configured DHCP client on an up interface |
| `dhcp-gateway-monitors` | Shared DHCP-derived monitor manager; at least one enabled DHCP-mode monitor |
| `link-diagnostics` | Native link diagnostic collector |
| `mqtt`, `dynamic-dns`, `discord`, `system` | Daemon-owned async manager runner; restarting an idle/disabled runner does not enable its configuration |
| `netcontrold` | Entire daemon, including HTTP/SSH; supervised native host-mode systemd/watchdog deployment only |

Unknown/unconfigured targets return `404`; disabled native service targets return
`409`. An unavailable worker/controller or unsupported daemon deployment returns
`503`. Native restart joins the old worker before starting its replacement and
returns `200`, for example:

```json
{"target":"ntp","status":"restarted","worker":{"name":"ntp","state":"running"}}
```

`worker` is the target's existing status snapshot; the example is abbreviated.
Completion means the owned supervisor has been restarted, not that upstream
connectivity, a new DHCP lease, clock synchronization, delivery or measurement
health has been established. A recovering worker can report retry/error status.
Simulator-native targets return `200` with `status:"simulated"` and do no work.
Restart is targeted, not the broad service reconciliation action.

Async manager requests return `202`, for example:

```json
{"target":"mqtt","status":"restart_requested","generation":1}
```

`generation` is an ephemeral monotonically increasing request counter, not a
configuration revision or completion token. Requests received during the same
drain may coalesce into one new attempt. Old attempts drain before replacement.
Unexpected exits/panics remain visible as errors in platform health under
`managed_processes`; the controller stays available for an explicit restart.
These health entries also include `running`, `restarting` and `stopped` states;
ordinary manager status remains independently available.

Daemon restart returns `202 {"target":"netcontrold","status":"restart_requested"}`,
blocks new mutations, drains HTTP/SSH and workers, durably closes the engine,
then exits nonzero. The existing packaged systemd `Restart=on-failure` policy
starts it again after approximately five seconds, plus shutdown/startup time.
Manual, simulator, OpenRC and namespace-lab launches cannot request daemon
restart. HTTP success acknowledges scheduling, not a completed boot; connectivity
can close before the client receives a response. Require confirmation, preserve
drafts, avoid automatic resubmission, and reconnect with bounded backoff.
There is no durable restart-job/status endpoint.

Restart discards the selected worker's ephemeral state/caches/counters;
accounting databases and desired configuration are preserved. DHCP retry may
reacquire a lease and affect connectivity; syslog may miss deliveries while
restarting. Monitor restarts reset sampling baselines. Show these effects before
confirmation and poll the existing target/platform status afterward.

#### Paired path MTU/MSS tests

These are deliberate, short-lived, two-firewall diagnostics, not continuous
monitoring, automatic tuning, an iperf subprocess or a VPN-only feature.
The backend runs tests; the frontend must implement the two-sided start/cancel
workflow. Start on both firewalls within the arming window, with inverse source/
peer addresses and the same random one-time secret and port. No management API
key is exchanged between firewalls.

| Method/path | Permission | Result |
| --- | --- | --- |
| `POST /api/v1/diagnostics/path-tests` | `diagnostics.run` + `interfaces.write` + `firewall.write` | `202` accepted session |
| `GET /api/v1/diagnostics/path-tests` | `state.read` | `200` current/last session status; no body/query |
| `POST /api/v1/diagnostics/path-tests/{id}/cancel` | Same three start grants | `200` cancellation/restoration status; no body/query |

Start is a strict, nonnull JSON object. Synthetic example only; do not reuse its
pairing secret:

```json
{
  "interface": "vlan100",
  "source_address": "192.0.2.1",
  "peer_address": "192.0.2.2",
  "port": 49872,
  "maximum_mtu": 9000,
  "parents": [{"interface": "eno1", "maximum_mtu": 9100}],
  "pairing_secret": "synthetic-pairing-secret-1234567890"
}
```

- `interface`: valid live IP-capable interface, not a kind whitelist. Physical
  Ethernet, VLAN, WireGuard and other tunnels are eligible subject to actual
  kernel/address/routing/ownership checks; no silent egress fallback.
- `source_address`, `peer_address`: distinct unicast IP literals of the same
  family, excluding unspecified, multicast, loopback and limited broadcast.
  IPv6 link-local addresses are explicitly unsupported; use unique-local or
  globally scoped IPv6. Source must belong to the selected interface.
- `port`: integer 1024..65535, default 49872, used for both UDP and TCP. Match it
  on both ends; there is no public persistent diagnostic listener.
- `maximum_mtu`: required integer 1280..65535 bytes, the explicit temporary
  selected-interface ceiling, not a proposed saved configuration value.
  Native preparation rejects unsupported values or lowering a live MTU.
- `parents`: optional array, default empty, maximum eight distinct explicitly
  approved ancestor interfaces, each with valid `interface` and
  `maximum_mtu:1280..65535`. The selected interface cannot repeat here.
  Do not infer consent for other interfaces, automatically raise all uplinks or
  silently guess an ambiguous tunnel underlay.
- `pairing_secret`: required write-only 32..128 non-space printable ASCII
  bytes (`!` through `~`). Generate
  at least 32 cryptographically random bytes and encode as hexadecimal on the
  client; copy to the other firewall over a trusted channel. Timing alone is
  not authentication. Never persist in drafts/history/browser storage, log it,
  put it in a URL or copy it into ordinary firewall configuration.
  Submit over HTTPS or a trusted management channel. Authentication does not
  imply encryption of synthetic diagnostic traffic.

One session per firewall, at most 30 seconds arming and 30 seconds measuring,
with a 90-second overall lifetime budget. Temporary MTU changes affect unrelated
traffic on the same interface/parents: show an explicit disruption warning and
the exact approvals before submitting. State the expected peer/interface/port
and selected maxima on both forms. Do not retry start automatically.

The orchestrator records owned originals before changing live state. Firewall
permissions are temporary, peer/interface/port-scoped, not a blanket policy
disable; kernel expiry limits exposure if the process dies. Restore originals
on normal completion, cancellation or failure, and recover interrupted MTU
changes on daemon startup. A killed daemon cannot execute MTU restoration until
it runs again; do not promise independent kernel expiry of an MTU. Failed
restoration remains an explicit error and blocks conflicting mutations.
Do not overwrite a foreign interface replacement or external state changes.
Kernel permit expiry/removal does not revoke already established conntrack
acceptance. The orchestrator closes test sockets but does not flush unrelated
connections. While cleanup has failed, it retains its socket reservations and
durable intent; process death releases those reservations, so restart/recovery
is still required. Do not describe permit expiry as complete session teardown.
Startup recovery precedes normal native reconciliation; if owned state cannot
be safely restored, startup fails explicitly rather than adopting foreign
changes. Status/cancellation remain available for cleanup failures in a
running daemon, not a promise of API availability after failed startup.

Preparation currently refuses any configured DHCP client or enabled BGP: their
asynchronous address/MTU/route writers prevent stable ownership. Dynamic
WireGuard DNS endpoints also prevent testing their selected/ancestor path or
an unresolved tunnel underlay; demonstrably unrelated dynamic tunnels do not
block a nonencapsulating selected path. Numeric-endpoint tunnels remain
eligible. IPv6 tests require IPv6 enabled in committed configuration. Both the
UDP and TCP source ports must be free; sockets are reserved before any MTU or
firewall changes. These preparation refusals are explicit `503`, not successful
empty measurements; do not suggest disabling live services automatically.

While a test/restoration owns the lease, configuration writes, capability
refresh/save, secret uploads, upgrades, restarts and other mutating actions are
blocked; read-only status and cancellation remain available. No software or
configuration revision is created for a test. No result automatically changes
MTU, TCP MSS or persistent firewall rules.
Firewall-counter and observe/repair reads that cannot safely interpret
temporary rules are explicitly unavailable during the lease. Keep polling
the dedicated status endpoint rather than treating those errors as zero
counters or vanished saved rules.

##### Status and progress

Start, status and cancellation return the native status object
`schema:"netcontrol-path-test-status-v1"`:

| Field | Type and meaning |
| --- | --- |
| `id` | 32 lowercase hexadecimal characters, or null before a session; use this ID, not protocol `session_id`, for cancellation |
| `state` | `idle`, `preparing`, `running`, `restoring`, `completed`, `cancelled`, `failed`, `cleanup_failed`, or `interrupted` |
| `active` | Boolean ownership/busy flag; wait for false before enabling conflicting writes, regardless of measurement outcome |
| `error` | String or null; preserve and display cleanup errors |
| `restoration` | `not_required`, `pending`, `restored`, or `kernel_reset` (recovery after a changed boot) |
| `deadline_unix_ms` | Optional integer UTC Unix milliseconds, present on a newly started session; not a promise of independent MTU restoration |
| `permit_lease_seconds` | Integer 90 |
| `mtu_restores_on_daemon_recovery` | Boolean true |
| `conntrack_cleanup` | String `not_performed` |
| `warnings` | String array; display operational limitations |
| `mtu_changes` | Array of interface snapshot/observation rows described below |
| `progress` | Progress object or null; cleared while restoring |
| `result` | Completed measurement object or null; completion of measurements does not imply successful restoration |

`mtu_changes[]` includes selected/approved links and unapproved ancestry
context, not just changed links. Each row has `interface:string`, `index:integer`,
`kind:string`, `address:integer[]` (raw link-address bytes, possibly empty),
`parent:integer|null` (ifindex), `approved:boolean`, `original_mtu:integer`,
`maximum_mtu:integer`, `observed_mtu:integer|null`, `identity_matches:boolean`
and `restored:boolean`. MTUs are bytes. Do not require MAC addresses or
interpret context rows as operator approvals.

`progress.schema` is `netcontrol-path-test-progress-v1`. Its `phase` is:

- `armed`, with `arm_timeout_seconds:30`;
- `paired`, with integer byte caps `local_cap_bytes`, `peer_cap_bytes`,
  `peer_send_cap_bytes`, `local_receive_cap_bytes`, `tested_cap_bytes`;
- `udp_complete`, with `udp.outbound` and `udp.inbound` evidence below;
- `completed`, with no additional required fields.

The outer state remains `running` during arming/pairing. Progress may be
skipped between polls; do not require observing every phase. Idle has null
`id`, `error`, `progress`, `result`, an empty `mtu_changes` array, false
`active` and `restoration:"not_required"`. Cancellation requests stopping;
its `200` response does not imply synchronous restoration.

##### Measurement result

`result.schema` is `netcontrol-path-test-v1`, with `status:"completed"`,
`interface`, `source_address`, `peer_address` (strings), `port` (integer),
`role:"initiator"|"responder"`, `session_id` (protocol identity string),
`elapsed_ms` (number), `limitations:string[]`,
`peer_report_received:boolean` and `local_report_acknowledged:boolean`.
Authenticated final peer reports may be absent without invalidating local
receive evidence; render missing sender evidence as unavailable.

`limits` distinguishes requested/interface/route/peer ceilings from path
evidence. Integer byte fields are `requested_maximum_mtu_bytes`,
`interface_mtu_bytes`, `initial_route_mtu_bytes`, `local_cap_bytes`,
`peer_cap_bytes`, `local_receive_cap_bytes`, `peer_send_cap_bytes`,
`inbound_tested_cap_bytes`, `tested_cap_bytes`, `ip_udp_overhead_bytes`.
`final_cached_route_mtu_bytes` is integer or null;
`ipv6_minimum_mtu_bytes` is 1280 for IPv6, otherwise null.
`path_mtu_bytes` is deliberately null: finite sampling does not establish a
conclusive path MTU. Integer bounds also include `maximum_probes_per_size`,
`candidate_limit`, `measurement_limit_seconds`, `arm_limit_seconds` and
`lifetime_limit_seconds`. At most 12 packet-size candidates are sampled;
there is no byte-exact boundary search.

`udp.outbound` and `udp.inbound` each contain:

- `largest_verified_ip_size_bytes:integer|null`, `delivery_evidence:string`,
  `rtt_origin:"local"|"peer"`, and `sizes:object[]`.
- Each size row has `ip_size_bytes:integer`, `delivered:integer`,
  `attempted`, `sent`, `ack_timeouts`, `emsgsize`, `send_errors`
  (integers or null), `loss_fraction:number|null` (0..1),
  `mean_rtt_ms:number|null`, and
  `status:"verified"|"local_or_route_limit"|"unknown"`.
- Outbound delivery requires a small authenticated received-size ACK, not an
  equally large echo. Inbound delivery counts authenticated local receives.
  Inbound sender counters and peer RTT are null until an authenticated peer
  report arrives; inbound `ack_timeouts` remains null. Final inbound
  `peer_sender_report` is that report object or null; progress snapshots omit
  this final-report field.

`udp.receive_path_errors` is an object of bounded integer counters keyed by
observed error (`emsgsize`, `connection_refused`, `connection_reset`,
`host_unreachable`, `network_unreachable`, `administratively_prohibited`);
absent keys mean none observed.

`tcp` contains `outbound_trials:object[]`, `inbound_trials:object[]`,
`peer_sender_trials:object[]|null`, `trial_byte_limit:4194304`,
`rate_limit_bytes_per_second:8388608` and `mss_observation:string`.
At most three fresh socket trials run per direction. All trial rows include
integer `trial`, `requested_mss_bytes` and string `status`:

- Outbound `status` is `measured` or `inconclusive`. Fields
  `effective_mss_bytes`, `peer_effective_mss_bytes`, `delivered_bytes`,
  `retransmits` are integers or null; `elapsed_ms`,
  `goodput_bits_per_second`, `kernel_rtt_ms`, `connect_ms`,
  `authentication_rtt_ms` are numbers or null. `delivery_evidence` is a string
  describing the authenticated byte-count/SHA256 receipt, or null without
  evidence. `error:string|null` preserves an inconclusive trial's failure
  reason; measured trials have null errors.
- Inbound `status` is `received`; integer `effective_mss_bytes`,
  `delivered_bytes`, numeric `elapsed_ms`, `goodput_bits_per_second`,
  `kernel_rtt_ms`, null `retransmits`, nullable integer
  `sender_retransmits`/`sender_effective_mss_bytes` and string
  `delivery_evidence` distinguish local receive observations from final
  peer-sender evidence.

`measured_candidates` contains
`largest_verified_outbound_ip_size_bytes:integer|null`,
`best_outbound_mss_trial:object|null` (the measured outbound row with highest
observed goodput), and `automatic_configuration:false`. This short,
rate-limited comparison is not an unrestricted speed test or a recommendation
to apply the highest observed candidate automatically.

Render authenticated bidirectional UDP packet-size evidence and TCP MSS trials,
not an unqualified "ideal MTU." Distinguish total IP packet size from TCP payload
MSS, local/peer/interface/route caps from verified path limits, loss/timeouts from
proof that a size is too large, and requested from observed TCP MSS. Inner
delivery does not prove absence of outer tunnel fragmentation. Brief tests,
ECMP, routing changes, congestion and CPU load limit conclusions.
The test connections terminate on the two firewalls; they do not prove
forwarded-LAN workload performance. MSS trials change only their own sockets,
not the firewall's persistent TCP MSS clamping policy.

Wrong JSON/types/nulls/unknown fields/body/query/ID shape: `400`; invalid request
values: `422`; authentication: `401`/`403`; conflicting test/transaction/
maintenance: `409`; unknown cancellation ID: `404`; unsupported method: `405`;
unavailable native backend or preparation/control failure: `503`. The simulator
does not fabricate successful measurements. Accepted-session failures are
reported in status; preserve restoration errors and poll until the lease is
released before offering new mutations.

#### Timed DNS lookup

`POST /api/v1/diagnostics/dns-lookup`, permission `diagnostics.run`:

```json
{"interface":"wan0","hostname":"google.com","record_type":"A","timeout_ms":2000}
```

To query only a specific resolver (synthetic example):

```json
{"hostname":"example.test","server":"192.0.2.53","record_type":"A","timeout_ms":2000}
```

- Optional `interface`: valid interface name, configured and administratively up
  when supplied. Omitted or null with an explicit `server` uses normal kernel
  routing in the managed namespace without binding to a device. No configured
  interface is required in that mode. With no `server`, `interface` is required
  to select configured/DHCP resolvers; omitting both returns `400`. Empty string
  is invalid, not automatic selection.
- Required `hostname`: ASCII DNS name with labels 1..63 characters, total at most
  253 characters excluding an optional final dot. Alphanumeric/hyphen labels
  must start/end alphanumeric. IP literals, whitespace, empty labels and Unicode
  fail `400`. The normalized result is lowercase without a final dot.
- `record_type`: `"A"` (default) or `"AAAA"` only.
- `timeout_ms`: integer, default `2000`, inclusive range `100..5000`. This is the
  overall network attempt budget, shared among remaining servers; scheduling/
  kernel timeout granularity can extend observed elapsed time slightly.
- Optional `server`: one IPv4 or IPv6 address string, not a hostname, URL or
  IP:port. Omitted or null uses the configured resolver selection below.
  Unspecified, multicast and IPv4 limited-broadcast addresses fail `400`.
  An explicit server is queried exclusively on port 53: no configured/DHCP
  fallback, and no configured DNS servers or DHCP resolver state are required.
  Any supplied interface must still be configured and up. An IPv6 server when global
  IPv6 is disabled returns `503`; A/AAAA selection is independent of transport.
- Without `server`, uses that interface's configured servers first, then
  valid matching DHCP-lease servers unless its DNS override setting suppresses
  DHCP DNS. Duplicate DHCP entries are omitted. IPv6 resolver addresses are
  excluded when global IPv6 is disabled; an AAAA question can still use IPv4.
  Missing/down interface, no effective servers, more than 16 effective servers
  or unavailable resolver state return `503`, not an invented public fallback.
- At most two concurrent lookups per daemon; additional requests return `429`.
  The engine lock is released before network I/O; configuration can proceed
  while the query uses its captured committed configuration/lease snapshot.

Direct native UDP queries target port 53 in the managed namespace and bind
nonloopback resolvers only when an interface is supplied. Otherwise normal
kernel routing selects the path for both UDP and TCP. Loopback resolvers use
loopback routing. Truncated UDP responses retry over native TCP using the remaining
attempt deadline. This bypasses OS hosts/cache lookup, but the selected DNS
server can itself cache answers. No DNSSEC validation or active link diagnosis
is implied.

`200` returns a diagnostic result, including when every attempt fails.
Synthetic successful response:

```json
{"status":"answered","interface":"wan0","hostname":"example.test","record_type":"A","server":"192.0.2.53","transport":"udp","rcode":0,"addresses":["192.0.2.7"],"rtt_ms":12.5,"elapsed_ms":13.2,"error":null,"attempts":[{"server":"192.0.2.53","transport":"udp","rcode":0,"addresses":["192.0.2.7"],"rtt_ms":12.5,"status":"answered","error":null}],"scope":"host:<opaque>","revision":"2026.10.29.8"}
```

`rtt_ms` is a measured numeric DNS request/response time in milliseconds,
including resolver processing, not ICMP RTT. For TCP fallback it excludes TCP
connect time and the earlier UDP exchange. `elapsed_ms` includes all attempts
and fallback setup. `scope` is opaque; `revision` identifies the captured
committed configuration, not necessarily the current revision when returning.
`rcode` is the numeric DNS response code. The first valid response ends the
lookup, including NXDOMAIN, SERVFAIL or REFUSED; nonzero codes return no
addresses and remain measured answers. Only transport/protocol failures try
the next configured server when no explicit `server` was supplied.

Response `interface` is `string | null`: the requested interface when supplied,
otherwise null, including in simulator mode. It is not a discovered egress
interface; do not infer which interface the kernel used from this field.

Failed attempts contain `server`, `status:"failed"`, `rtt_ms:null`, `error`;
successful attempts have the successful answer fields shown above. If all fail,
the top-level result has `status:"failed"`, null `server`, `transport`, `rcode`
and `rtt_ms`, empty `addresses`, and explicit errors in `attempts`. Null is not
zero. Simulator returns `status:"simulated"`, `scope:"simulator"`, null timing/
server/transport/code, empty answers/attempts, and no fabricated RTT. Query-job
or namespace failure outside the diagnostic exchange returns `503`.

Frontend: add a deliberate lookup form with hostname, optional interface/server
IP (at least one required), A/AAAA and bounded timeout, single-flight submission,
result/attempt/error rendering, and
labels distinguishing DNS response codes from transport failures. No continuous
lookup polling or automatic restart on a DNS error.

### 4.4 Transactional SSH configuration CLI

Ubuntu `install.sh` and full `upgrade.sh` enable the daemon's in-process SSH
server by default on `127.0.0.1:2222` (IPv4 localhost only) through
`NETCONTROL_SSH_LISTEN`. LAN/WAN clients cannot connect to this default.
Full upgrades replace the managed wildcard default with loopback; existing
explicit environment-file/CLI overrides remain effective. Operator help must
show local-console SSH, not direct appliance-IP access by default. Manual
invocations remain disabled unless that variable or `--ssh-listen` is supplied;
an explicit flag takes precedence. Optional `--ssh-host-key` defaults to
`<state>.ssh-key`. Build-only upgrades change no service settings. This is not a
second daemon, system shell or HTTP endpoint. The literal SSH username
is `apikey` and its password is the existing API key, with the same permissions,
device setup gate, immediate managed-key revocation and fail-closed identity
health. SSH never makes account passwords authorize networking operations.

Linux host device mode additionally supports browser-free onboarding via the
root-console command `netcontrold --create-api-key NAME`. It communicates only
through a protected local Unix socket (default `/run/netcontrol/control.sock`),
not an HTTP endpoint. On an unclaimed device it interactively obtains the device
username/password and atomically saves a completed account plus a full-permission
key. For an existing account it preserves username/password/keys/sessions, adds
the key and completes pending onboarding; existing pending keys become active.
The key is displayed once on a terminal and thereafter uses normal HTTP/SSH
authorization and website listing/revocation. No shared default password,
account-password SSH authentication, identity schema change or scoped-key
modification is introduced.

Existing `GET /auth/status` can therefore observe configured identity after local
setup, without this browser having a session; render the existing login stage,
not an assumed setup stage. `POST /auth/login`, `GET /auth/keys` and
`DELETE /auth/keys/{id}` retain their current device-session rules and schemas.
No client changes are required; optional onboarding/operator help can explain
the root-console command. Updated daemon deployment is required for the socket.
Non-Linux and `--auth-file` deployments do not support this local operation.
See [console setup](docs/CLI.md#browser-free-local-key-creation).

Each shell stages a private candidate against a captured committed revision.
`commit confirmed 10..300` submits a complete package to the existing engine;
confirmation, rollback, deadlines, revision history and recovery are shared with
HTTP. No immediate commit, per-command live edits, parallel write bypass or
automatic merge exists. Disconnect discards local draft only, never confirms or
cancels an already applied transaction. Either surface can recover a transaction
with appropriate permissions.

Interactive shells require a PTY; SSH exec accepts one command, not a script.
Commands are limited to 65,536 bytes, private candidates to 1 MiB and rendered
output to 4 MiB. Output overflow returns an explicit error and nonzero exec
status instead of partial successful JSON. The command may already have applied
changes; inspect state/transactions before retrying. Ctrl-C cancels input only;
Ctrl-D exits without confirming pending work. Transport/session limits and
terminal behavior are detailed in the [CLI guide](docs/CLI.md#ssh-transport-limits).

HTTP paths, schemas, CORS, authentication and status/error behavior are unchanged.
Treat CLI commits as other-manager writes: keep polling, handle revision/active
transaction conflicts, preserve drafts and uncertain-write recovery. No frontend
client or UI changes are required to use SSH; optional operator help may link
to the [CLI guide](docs/CLI.md). Host management access, key fingerprint trust,
namespace provisioning and exposure are operator responsibilities.
Upgrade preserves saved host-input policy and adds no port permits or WAN
protection: operators must review management reachability. Address overrides
and explicit disable are documented in the
[deployment guide](docs/BUILD_AND_INSTALL.md#optional-configuration-ssh-server).
Host-key or bind failures remain startup errors, not silent SSH disablement.

### 4.5 Ubuntu Self-Upgrade

Ubuntu self-upgrades trust a fixed GitHub repository over verified HTTPS,
without publisher signatures or signing-key setup. A root-owned repository/
optional-token configuration enables installation through `--upgrade-config`
or `NETCONTROL_UPGRADE_CONFIG`; standard install/upgrade scripts now bootstrap
that configuration and service environment automatically, preserving valid
operator settings and existing startup arguments.
It supports only Ubuntu amd64/systemd, Linux host appliance mode. It is not an
OS update, `.ncpkg` installation, factory reset or source build. It consumes
published stable Ubuntu release assets from the configured repository; validation
or local builds alone do not prove publication. SHA-256 detects corruption against the same-source manifest, not
publisher authenticity: compromise of the trusted GitHub repository/account can
provide an accepted replacement. Separate signed `.ncpkg` packages are unchanged.
See [operator setup and artifact contract](docs/BUILD_AND_INSTALL.md#ubuntu-self-upgrade).

| Method/path | Permission | Behavior |
| --- | --- | --- |
| `POST /api/v1/system/upgrade` | `system.upgrade` | Submit a specific GitHub HTTPS release version; returns `202` job and `Location: /api/v1/system/upgrade` |
| `GET /api/v1/system/upgrade` | `state.read` | Read configuration-enabled flag and latest durable job; `200` even when disabled |
| `POST /api/v1/system/upgrade/check` | `system.upgrade` | Request release discovery now, no body/query; `202` with `Location: /api/v1/revisions/latest`; does not install |

POST body is exactly `{"version":"2026.10.29.2"}` (synthetic version). Version is
canonical `yyyy.mm.dd.iteration`, maximum 21 bytes, a real UTC calendar date,
year 0001..9999, zero-padded month/day, iteration 1..4294967295 without leading
zeroes. No `v` prefix, prerelease suffix or build metadata. GitHub tag is `v<version>`. No query parameters,
unknown/duplicate fields, URL/repository/token/key/path, force or downgrade inputs.
GET accepts no body/query. Standard error envelope `{error, transaction: null}`:
`400` invalid input, `401` invalid/missing API key, `403` insufficient permission,
`405` other methods, `409` active job/configuration transaction or version not
newer than the last successful API upgrade, `503` disabled/preparation/state
failure. Errors after acceptance are recorded on the job, not returned by POST.

GET response fields: `enabled: boolean`, `repository: string|null`,
`last_successful_version: string|null`, `job: object|null`. Enabled means operator
configuration is present, not that a release exists or is healthy. Historical
last-successful version is **not** the running software version; manual deploys
can differ. No initial version is inferred. Latest job is overwritten on a new
accepted request; no job-history/cancel endpoint exists.

POST returns a job object with string `id`, `version`, `status`, RFC3339
`created_at`/`updated_at`, nullable string `error` and
`last_successful_version`. GET nests that same shape under `job`. Synthetic example:

```json
{"id":"upgrade_example","version":"2026.10.29.2","status":"queued","created_at":"2026-10-29T00:00:00Z","updated_at":"2026-10-29T00:00:00Z","error":null,"last_successful_version":null}
```

Statuses: `queued`, `downloading`, `installing`, `checking`, `succeeded`,
`failed`, `rolled_back`, `recovery_required`. Only `succeeded`, `failed` and
`rolled_back` are terminal; recovery-required needs local-console intervention
and remains write-blocking. `202` does not promise that the release was found,
integrity checks passed or installation succeeded. A new API upgrade must be newer
than both the running version and last successful API-upgrade version when known;
there is no downgrade override. The running baseline is the embedded public
software version, independently of upgrade receipts and Cargo package versions.

Frontend tasks: explicit privileged-action confirmation showing requested
version/repository and expected management/traffic interruption; strict version
validation; no credential/URL fields or implicit retry. Poll GET without overlap
and back off during disconnection, preserving the accepted job ID. Do not mark
a restart outage as job failure or success; reconnect, compare the latest ID
and status, and report a superseded job rather than confusing it with a new one.
Reads remain available until restart, but new configuration/SSH writes and DHCP
retry return `409` while active; disable those actions and preserve unsaved drafts.
After reconnect, refetch state/revision before allowing draft submission.

The independent helper validates the fixed release/tag, version, target, exact
two required assets, size/digest/ELF and bounded HTTPS downloads. It requires
`netcontrold-ubuntu-amd64` and `netcontrol-ubuntu-amd64.json`, with no signature
asset. The staged executable's `--version` must match the manifest/request.
It preserves the main service arguments and
saved configuration, and attempts previous-binary restoration on install/startup
failure. A required boot recovery unit handles interrupted install/check phases.
It also applies existing conntrack accounting/checksum prerequisites. Browser
code must not claim full state rollback, guaranteed connectivity, atomic host
prerequisites or retroactive conntrack counters. The daemon performs no automatic frontend reload,
release publication, reboot, connection flush, credential reset or compatibility
migration. Actual systemd/power-loss/release/browser acceptance remains
pending; [handoff 2026-10-24-07](docs/frontend-handoffs/2026-10-24.md#2026-10-24-07-signed-ubuntu-self-upgrade)
is Pending frontend review and its version rules are superseded by the
[date-version handoff](docs/frontend-handoffs/2026-10-29.md#2026-10-29-01-date-versions-and-daily-release-checks).
Signing/bootstrap and checking enablement requirements are superseded by
[handoff 2026-10-29-05](docs/frontend-handoffs/2026-10-29.md#2026-10-29-05-automatic-github-https-upgrades),
also Pending frontend review.

### 4.6 Software Version and Daily Release Checks

The saved master configuration contains a daemon-managed `software` object.
Read it from `GET /api/v1/state` at `desired.software`, or
`GET /api/v1/revisions/latest` at `config.software` without requiring healthy
network observation. Existing API-key authentication and `state.read` apply.
The manual check action below reuses `system.upgrade`; no new permission is added.

Synthetic successful check:

```json
{"version":"2026.10.29.1","repository":"example/netcontrol","latest_version":"2026.10.29.2","update_available":true,"last_checked_at":"2026-10-29T22:00:00Z","error":null}
```

`version` is the running binary's embedded public version, always a date-version
string. Software versions now derive from UTC first-parent Git commit dates
and an immutable seed; CI publishes each validated default-branch mainline
commit, including docs-only changes, as a stable version. Clients must not
infer versions from build completion times, assume gap-free iterations or
conflate them with independent configuration revisions. No client field changes.
Source deployments require Git and full history; prebuilt runtime does not.
[Handoff 2026-10-29-06](docs/frontend-handoffs/2026-10-29.md#2026-10-29-06-per-commit-stable-releases)
is Pending frontend review for deployment coordination and optional wording.
`repository`, `latest_version`, `last_checked_at` and `error` are
`string|null`; `update_available` is `boolean|null`. Time is RFC3339 UTC.
`repository:null` means checking is disabled. A configured checker is pending
until its first result (`latest_version`, `update_available`, `last_checked_at`
and `error` all null). A successful check sets `latest_version` and compares
numeric date/iteration components against `version`. An older/equal release
means `update_available:false`, not an available downgrade. A failed check
sets `last_checked_at` and explicit `error`, clearing latest/availability to
null; never render it as "up to date" or keep a stale success badge.

An in-process worker queries GitHub `/releases/latest` at startup and every
24 hours by default, using `mayberryjp/firewall_backend` without any signing
or installation configuration. Configured self-upgrades supply the same trusted
repository and optional server-managed token for discovery. Explicit
`--disable-release-checks` disables automatic/manual checks and produces
`repository:null`; an absent upgrade configuration no longer disables checking.
Discovery is portable and independent of installation's Ubuntu/native constraints.
Only published stable releases with canonical `v<version>` tags qualify.
HTTPS verification is mandatory; redirects are refused, connect timeout is
10 seconds, total request timeout 30 seconds, response limit 1 MiB. No release,
rate limiting, malformed tags and transport/API errors are explicit failed
checks; retry with the manual action below, the next daily check or daemon restart.
The daemon never automatically downloads/installs or publishes. CI publication
is separate and occurs only after each default-branch commit's checks and
artifact verification succeed. Availability is discovery metadata,
not proof that the required binary/manifest assets exist or that installation will succeed.

Results are atomically saved in the master journal without applying networking,
allocating a configuration revision or changing a pending transaction.
Startup resets metadata to the running build and disabled/pending state, then
checks asynchronously. On `POST /api/v1/transactions`, omit `config.software`
or echo its current value; nondefault differing supplied metadata returns `422`.
It is not an editable setting or an authorization bypass. Confirmation and
historical restore retain current software metadata rather than restoring old
binary identity/check results. Historical snapshots may contain historical
metadata; the current revision detail always returns current saved metadata.

#### Check now

`POST /api/v1/system/upgrade/check` requests an immediate asynchronous check of
the same operator-configured repository. Existing API-key authentication and
`system.upgrade` are required; `state.read` alone cannot trigger network work.
Send an **empty body**, with no query parameters. Do not send `{}`, a version,
repository, URL, token or force flag.

Accepted response: HTTP `202`, `Location: /api/v1/revisions/latest`,
`{"status":"check_requested"}`. This acknowledges queuing, not completion,
availability, integrity validation or installation. Read
`GET /api/v1/revisions/latest` (`config.software`) or normal state polling
(`desired.software`) with `state.read` for the resulting metadata.
The old saved result remains visible while checking; no persisted `checking`
flag or job ID is added. A new success/failure updates `last_checked_at` and
the usual fields above. Discovery failures appear in `software.error` with
null latest/availability, not a later HTTP error from the accepted POST.

The standard error envelope is unchanged: `401` invalid/missing authentication,
`403` missing `system.upgrade`, `405` methods other than POST, `400` any nonempty
body/query, `409` a manual or scheduled check already queued/running, `503`
checking explicitly disabled or its worker unavailable. `409` does not queue another
check; show an already-checking message and observe the existing result.
Manual and scheduled requests share one worker and cannot overlap. Requests do
not reset the daily timer, allocate configuration revisions, alter pending
transactions or start an upgrade. Shutdown cancels queued/in-flight checks
without publishing a fabricated result; the next startup checks normally.

Add **Check now** beside software availability, enabled when
`software.repository !== null` and the user has permission. Do not gate it on
`GET /api/v1/system/upgrade.enabled`: that field controls installation only.
Disable repeated clicks during a local request/
poll cycle, show the prior result as stale/checking, and keep fetch/authorization/
worker errors distinct from a successful no-update result. Capture the previous
`last_checked_at`, then poll for a changed result with a bounded local wait.
An unchanged timestamp after a timeout/restart is an uncertain outcome, not
proof that the current version is up to date; allow an explicit retry. The
network timeout is 30 seconds; account for scheduling/persistence overhead.
No install confirmation or update job should appear merely from this action.

Frontend tasks: show running version and separate update availability/error/
pending/disabled states; keep these fields out of editable drafts and omit
`software` on transaction submission. Existing normal state polling observes
new results; do not make reads trigger network checks. Update version forms,
transaction/history/cursor types and comparison as described below.

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

- Interfaces, softflowd instances, and gateway monitors: identity by `name`.
- WireGuard peers: identity by public key within an interface.
- Routes: identity by `(table, destination, metric)`.
- Policy rules: identity by priority.
- Filter, masquerade and destination rewrite rules: ordered arrays, with frontend-only stable row IDs.
  Never send those row IDs to the backend.
- Interface rename is delete/create, not an API rename operation.

Ignore ordering differences the backend normalizes: interfaces by name, addresses
lexically, peers by public key, allowed IPs lexically, softflowd and gateway monitors by name, policy
rules by priority, and routes by the backend's route-key string. Ignore JSON map
key order. Preserve filter, masquerade and destination rewrite rule order.

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

All statistics reads require `state.read`. Only the connection snapshot endpoint
accepts the bounded query parameters documented below; other statistics reads
accept no query parameters:

| GET endpoint | Response |
| --- | --- |
| `/api/v1/statistics` | `{sample, interfaces, protocols, gateways?, link_diagnostics, uptime}` |
| `/api/v1/statistics/interfaces` | `{sample, interfaces}` |
| `/api/v1/statistics/interfaces/{name}` | `{sample, interface}` |
| `/api/v1/statistics/protocols` | `{sample, protocols}` |
| `/api/v1/statistics/connections` | Connection snapshot with filters/paging; `netcontrol-connections/v1` |
| `/api/v1/statistics/firewall` | Live logical-rule match counters; `netcontrol-firewall-counters/v1` |
| `/api/v1/statistics/host` | Host health snapshot; `netcontrol-host-health/v1` (see below) |
| `/api/v1/statistics/link-diagnostics` | Cached native link observations; `netcontrol-link-diagnostics/v1` |
| `/api/v1/statistics/gateways` | `{sample, monitors}` |
| `/api/v1/statistics/gateways/{name}` | `{sample, monitor}` |

`sample` contains `scope`, `started_at`, `collected_at`, and `status`:
`available`, `partial`, or `simulated`. Treat timestamps as a collection window,
not an atomic kernel snapshot. Display freshness independently of configuration
freshness. An unavailable source/link has its own status and error; missing
counters/groups are null, not zero. Optional counter fields can be absent.

The aggregate response includes a required top-level `uptime` object:
`{scope, collected_at, status, data, error}`. Native `scope` is `"host"`:
Linux `/proc/uptime` in the daemon's existing context, **seconds since host
boot**, not daemon runtime or the configured network lab namespace. `collected_at`
is RFC3339 UTC and also closes the aggregate sample's collection window.
Available `data` is `{uptime_seconds, idle_seconds}`, both finite nonnegative
JSON numbers in seconds (fractional values allowed). CPU-summed `idle_seconds`
may exceed uptime. `status: "available"` has `error: null`; a failed read or
invalid kernel value gives `status: "unavailable"`, `data: null`, an explanatory
error string, and aggregate `sample.status: "partial"` while preserving other
statistics. The simulator reports `scope: "simulator"`, `status: "simulated"`,
null `data`/`collected_at` and an explanatory error, never the development host's
uptime. The object is absent from narrower networking statistics endpoints.
No queries, permissions, configuration fields, saved state or reset operations
are added. CLI `show statistics` exposes the same aggregate object.

Interface records include `name`, optional `index`, `kind`, `ownership`, `mtu`,
`admin_up`, `oper_state`, optional `mac`, `status`, optional `counter_bits`
(32 or 64), nullable `counters`, and optional `error`. Counter keys cover RX/TX
bytes, packets, errors, drops, and detailed link errors; see
[Native networking statistics](crates/netcontrol-native/README.md#runtime-statistics-and-limitations)
for the measurement scope.
Statistics include unmanaged links and loopback, not just editable resources.
Do not turn their presence into provisioning/edit controls. A changed adopted
parent identity is labeled `adopted_parent_identity_changed`.

Protocol records contain `name` (`snmp`, `netstat`, `snmp6`), `status`, nullable
`groups`, and optional `error`. Groups map kernel group/field names to decimal
strings; IPv6 fields retain full names under `IPv6`. Preserve unknown fields and
do not assume identical groups across kernels. Some values are gauges/constants,
not counters; `Tcp.MaxConn` can be `"-1"`.

**Precision:** Kernel counter/protocol values are quoted decimal strings on the wire.
Keep them as strings or validated `BigInt`; never route them through `Number`.
Date-version revision strings are a separate type, not kernel counters.
Use arbitrary-precision deltas before deliberately rounding a displayed rate.
Gateway window counts/measurements are bounded JSON numbers, with null for
missing measurements; they must not use the kernel-counter decoder.

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
of full configuration observation errors. Connection state is available only
through the explicit endpoint below; interface/protocol statistics do not imply
driver-specific, host-global softnet/sockstat, WireGuard peer, or streaming APIs.

#### Native link diagnostics

`GET /api/v1/statistics/link-diagnostics` requires API-key Bearer authentication
and `state.read`. GET only (`405` otherwise); query parameters are rejected
(`400`), normal `401`/`403` authorization applies. A readable cache returns `200`
even while starting/unavailable/stale; a cache/scope read failure returns `503`.
No configuration writes, new permission, enabled setting, active probe, or
transaction/confirmation/rollback policy is introduced. CLI:
`show statistics link-diagnostics`. Aggregate statistics embeds the same cache
as `link_diagnostics`, with independent freshness/status; its older `sample`
does not describe the diagnostics sampling interval.

The collector runs continuously in the managed network namespace, including
unmanaged interfaces and loopback. Native Rust uses routing netlink,
`NETLINK_SOCK_DIAG`/`TCP_INFO`, and a kernel-filtered AF_PACKET datagram socket.
No subprocess, third-party collector, eBPF program, BTF, tracefs, or provider
integration is involved. Packet payloads/endpoints are not stored or exported.
Headers are observed before firewall acceptance/checksum validation; observations
do not prove packet acceptance, delivery or application behavior.

Envelope:
- `schema: "netcontrol-link-diagnostics/v1"`, opaque backend `scope`.
- `status: "starting"|"available"|"unavailable"|"stale"|"simulated"`.
- `collected_at: string|null`: UTC RFC3339 last successful collection.
  `age_ms: number|null`: monotonic age of that success (startup age before the
  first success). `interval_seconds: number|null`: actual elapsed sample time,
  null for the first successful sample or after an unavailable interval.
- `error: string|null`, `interfaces`, `queues`, `local_tcp`, `packet_headers`,
  `signals: string[]`, and native `coverage` strings explaining measurement
  boundaries. Failed sources return explicit unavailable status/error, null
  sections and no active signals, not fabricated zeros. A sample older than
  five seconds is stale; retained sections are historical only. Simulator
  returns simulated status, null sections/timing and no signals.

Native collection takes a snapshot approximately once per second (plus collection
cost), independent of HTTP/MQTT poll frequency. Each of four netlink dumps is
bounded by a one-second deadline, 16 MiB and 8192 rows; oversized/interrupted/
truncated/denied/unsupported dumps explicitly fail the sample and reset delta
baselines. The header socket requests a bounded 4 MiB buffer (kernel limits
apply), snapshots at most 256 bytes per packet, processes at most 4096 packets
per receive round, tracks at most 8192 directed flow keys and interface rows,
and expires directions after 120 seconds idle. Shutdown joins the owned thread;
collection errors retry without blocking configuration or restarting the daemon.

`interfaces: object[]|null`: rows have numeric `index`, string `name`,
`errors` (RX+TX errors), `drops` (RX+TX drops), and nullable `errors_delta`,
`drops_delta`. Counters/deltas are exact unsigned decimal strings, not JSON
numbers. First/reset/new-identity deltas are null; indexes/names cannot detect
every recreation. Counts are observations, not unique packet-loss totals.

`queues: object[]|null`: each row has `index: number`, `name: string|null`,
`handle: number`, `parent: number`, `kind: string`, `status:
"available"|"unavailable"`, `queue: object|null`, `drops_delta: string|null`,
`backlog_growth_bytes: string|null` (signed decimal). `queue` contains numeric
`qlen_packets`, `backlog_bytes`, and exact decimal strings `drops`, `requeues`,
`overlimits`. No queue statistics means unavailable, not zero. Identity includes
interface index, handle, parent and kind. Never sum hierarchical qdisc rows;
overlimits do not necessarily mean loss. Backlog is a gauge; growth is the
difference from the previous successful snapshot, not a byte rate or queue
sojourn-time measurement. Counters may reset when qdiscs are replaced.

`local_tcp: object|null` covers **established sockets terminated on this router
only**, not forwarded TCP:
- Numeric `established_sockets`, `compared_sockets`; deltas include only socket
  cookies observed in both successful samples. Short-lived sockets and transient
  events between snapshots can be missed. First samples do not invent deltas.
- `retransmissions_delta: string|null`, numeric nullable
  `retransmissions_per_second`, `retransmissions_per_thousand_segments`
  (denominator is observed outgoing segments, not a physical-loss probability),
  `cwnd_reductions` (sampled reductions, including non-loss causes).
- Exact cumulative decimal strings `observed_retransmissions` and
  `observed_cwnd_reductions`, since collector start across successful comparisons.
  These retain observed events between slower MQTT publications. They survive
  collection errors, reset on daemon restart, and do not recover unobserved
  short-lived sockets or unavailable intervals; they are not kernel boot totals.
- Nullable numeric `cwnd_min_segments`, `cwnd_max_segments`, `rtt_p50_ms`,
  `rtt_p95_ms` (nearest-rank over positive current socket SRTT values, not packet
  latency percentiles), `rtt_variation_max_ms`, `rto_max_ms`,
  `unacked_segments_max`, `lost_segments_max`, `send_queue_max_bytes`,
  `peer_window_min_bytes`. Send-queue bytes are socket queue occupancy, not qdisc
  occupancy. No sockets/usable values yields null extrema, not measured zero.
- Numeric `peer_window_measured_sockets`, nullable numeric
  `peer_zero_window_sockets`; if any socket's kernel TCP_INFO lacks the peer
  window field, the zero-window count is null rather than claiming completeness.
  Peer-window minimum summarizes only measured sockets.

`packet_headers: object|null` covers plaintext **ingress** IPv4/IPv6 TCP ACKs,
including forwarded and locally delivered traffic. Outgoing duplicates are
excluded. Decrypted WireGuard interfaces can expose inner TCP; an encrypted
outer UDP packet cannot. IPv4 options and up to eight supported IPv6 extension
headers are decoded; no fragment reassembly, IPv6 jumbograms or arbitrary
encapsulation decoding. VLAN parent/child/tunnel observations may duplicate a
path; never sum interfaces as unique flows. NAT can create different directed
keys. Only 16-bit raw advertised windows are compared within a direction;
scaling handshakes are not used to invent byte windows or forwarded `cwnd`.

- `status: "available"`, numeric `tracked_directions`, `flow_limit: 8192`.
- Exact cumulative decimal strings `kernel_drops`, `rejected_headers`,
  `untracked_packets`, `capture_gaps`, and boolean `statistics_complete`.
  Any kernel loss, malformed/truncated header, capacity rejection or reopened
  capture makes completeness false until daemon restart. This is completeness
  for the declared capture scope, not all traffic; unsupported protocols/
  fragments are excluded. Dropped samples are not retransmissions.
- `interfaces` rows contain numeric `index`, nullable `name`, exact decimal
  strings `tcp_ack_packets`, `zero_window_observations`,
  `zero_window_transitions`, `window_decreases`, and nullable numeric
  `window_raw_min`, `window_raw_max` (raw 16-bit values). Counts/extrema are since
  collector start while the interface remains observed, not the last second.
  The first observed zero counts as an observation, not a transition; SYN,
  FIN/RST and sequence/ACK reordering do not create tracked window transitions.
  Flow expiry/capacity/loss can miss transitions. A zero window means receiver
  pressure, not physical link congestion. Exact zero-window duration is not
  measured.

`signals` are **evidence indicators**, not confirmed root-cause alarms or daemon
health gates. Current codes: `interface_errors`, `interface_drops`,
`local_egress_drops`, `local_queue_growth`, `local_tcp_retransmissions`,
`local_tcp_cwnd_reductions`, `local_tcp_rtt_rise`, `receiver_window_pressure`.
Counter signals require a positive interval delta; queue growth requires a
positive backlog difference. RTT rise means socket SRTT median exceeds both
twice the previous median and a 20 ms increase; changing socket populations can
also cause it. Receiver pressure means new captured zero-window ACK observations
or a current local socket peer-zero window. Show queue/interface evidence with
the relevant rows and keep local TCP evidence explicitly separate. RTT rise
plus queue growth/drops suggests local congestion; retransmissions alone do not
locate upstream loss. There is no cross-router correlation, exact upstream-hop
diagnosis, packet-loss history, per-destination aggregation or automatic repair.
Existing gateway-probe statistics remain separately available for comparison.

MQTT's existing QoS-1 nonretained `netcontrol/<device_id>/state` payload gains
the same `link_diagnostics` object. Existing interval, permissions, confirmed
settings, availability/LWT, payload bounds and no-backlog behavior are unchanged;
one-second collection is **not** one-second publication. Home Assistant discovery
adds status/signal-count and local TCP rate/window/RTT sensors using the existing
`metric_key("link", resource, field)` encoding (`resource` is `monitor` or
`local_tcp`). Measurements are null unless diagnostic status is available;
unavailable aggregate reads carry an explicit unavailable object. Queue/header
detail remains in the raw object, not thousands of discovery entities.

Frontend tasks: add read-only diagnostic types/cards; poll non-overlapping every
2..5 seconds while visible; gate all measurements by status/freshness, preserve
decimal precision and display capture incompleteness. Keep receiver-pressure,
local-queue and local-socket observations distinct, and render unknown signal
codes generically. Never copy diagnostics into configuration drafts or disable
editing because of them. Deployment requires kernel packet/inet/TCP diagnostics
support, CAP_NET_RAW for capture and appropriate namespace-entry privileges;
Ubuntu install/full source upgrade loads/persists modules. No unprivileged-BPF
sysctl, AppArmor or lockdown weakening. Other package/manual upgrade paths need
operator kernel-module prerequisites; API reads never repair them.

#### Conntrack limits and timeouts

Nine advanced conntrack controls are accepted through the existing
`kernel.host` and `kernel.namespace` string maps. Previously these names were
rejected as unsupported tunables. No new configuration object, write endpoint,
permission, recommended tuning values, or default override is added.

**Native host ownership is mandatory at installation and startup, including
both source and HTTPS upgrades.** Initial console takeover reads all nine
current values into the private capture and initial configuration before
transferring ownership. Saved-host startup first recovers/reconciles saved
configuration, then captures any missing tuning keys and durably commits them
as owned configuration. Existing saved values remain authoritative and are
never replaced with observed drift or a guessed default.

When keys are missing, startup records a verified system transaction
(`actor:"system-conntrack-ownership"`, `status:"committed"`,
`confirmation_deadline:null`) and advances the configuration revision.
Its durable intermediate state is `applying_local`; interrupted application
resumes through existing recovery. The only allowed changes are additions of
missing conntrack keys; credentials, saved tuning and unrelated settings remain
unchanged. This internal host policy is not a frontend auto-confirm action or
a new HTTP endpoint. Complete ownership is idempotent: no repeated capture,
revision or application on subsequent startups.

| Full sysctl key | Scope | Inclusive range | Unit |
|---|---|---|---|
| `net.netfilter.nf_conntrack_max` | host | 1024..16777216 | entries |
| `net.netfilter.nf_conntrack_tcp_timeout_established` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_tcp_timeout_close` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_tcp_timeout_close_wait` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_tcp_timeout_fin_wait` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_tcp_timeout_last_ack` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_tcp_timeout_time_wait` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_udp_timeout` | namespace | 1..604800 | seconds |
| `net.netfilter.nf_conntrack_udp_timeout_stream` | namespace | 1..604800 | seconds |

Values are nonnull canonical decimal **strings**, not JSON numbers. Reject
leading zeros, signs, whitespace, multiple elements, incorrect scope and
out-of-range values. Removing an owned key restores its captured original through
the normal transaction lifecycle, but native host startup reclaims missing
conntrack keys from the then-current values. Removal is not a permanent opt-out
from host ownership. Simulator and explicit lab namespaces do not auto-capture.
Do not silently clamp unsupported current values.
The native preflight validates both requested and captured current values.
Read-only `nf_conntrack_count`, hash-bucket tuning and TCP validation-relaxation
controls (`nf_conntrack_tcp_loose`, `nf_conntrack_tcp_be_liberal`) remain
unsupported as configuration.

`GET /api/v1/kernel/tunables/catalog` (API key, `state.read`) returns the same
array schema with nine additional `kind:"integer"`, `count:1` entries:
`name:string`, `scope:"host"|"namespace"`, `min:number`, `max:number`,
`description:string`. Descriptions include operational warnings. Catalog bounds
are configuration limits, not memory sizing recommendations or effective values.
`GET /api/v1/kernel/tunables` and `GET /api/v1/runtime` expose the keys under the
existing desired/configured/effective/observed/captured-original maps. Empty maps
do not imply the kernel has no defaults. Simulator values are synthetic, not
measurements of the appliance.

Synthetic fragment, not a complete transaction or tuning recommendation:

```json
{"kernel":{"host":{"net.netfilter.nf_conntrack_max":"65536"},"namespace":{"net.netfilter.nf_conntrack_tcp_timeout_established":"432000","net.netfilter.nf_conntrack_udp_timeout":"30"}}}
```

Submit the full current configuration through `POST /api/v1/transactions` with
`base_revision` and `confirm_timeout_seconds` 10..300, then explicitly
`POST /api/v1/transactions/{id}/confirm` or `/rollback`. Mutations, confirmation,
rollback and revision restore require `transactions.write` and
`kernel.host.write` for the entry limit and/or `kernel.namespace.write` for
timeouts, plus permissions for other changed resources. JSON type/null errors
are `400`, semantic validation errors `422`, authentication/permissions
`401`/`403`, stale/busy transactions `409`, native preflight/write/readback
failures use existing `500` transaction errors; observation availability errors
are `503`. Successful submit is provisional `202`, confirm/rollback `200`.
Revision restore uses the existing `POST /api/v1/revisions/{revision}/restore`.

Linux requires loaded conntrack sysctls and writable procfs with the normal
native permissions. The entry limit is **host-global**, including when accessed
through a lab namespace, and uses the existing exclusive host-tunables ownership
gate; lab use requires the explicit host-tuning opt-in. Timeouts are scoped to
the daemon's network namespace. No module loading, hash-table resizing,
connection deletion/flush, sysctl.d file, or TCP validation relaxation occurs.
Missing/unreadable/unwritable/unsupported current keys abort initial capture
or saved-host startup explicitly; there is no partial adoption, empty successful
fallback or state reset. A pending configuration transaction blocks a missing-key
claim rather than being automatically confirmed or overwritten. Saved
configuration and native ownership intents provide restart repair,
exact readback, rollback and original restoration.

Frontend: add an advanced conntrack group driven by catalog scope/bounds, keep
values as strings, distinguish configured from effective/original values, and
explain mandatory host ownership and restart recapture after removal. Refresh
state/revision after an installation or upgrade before submitting a draft; show
captured live values rather than inventing defaults. Warn that higher limits
permit greater memory use; lower limits can reject new connections; short
timeouts can break idle flows or leave late teardown packets untracked.
Do not claim that a valid value is safe for available RAM, that timeout changes
rewrite every existing timer, or that restoring sysctls resurrects expired
connections. Require operator review and independent connectivity checks before
confirmation. Deploy the accepting backend before enabling the controls.

#### Performance diagnostics and RPS tuning

`GET /api/v1/statistics/performance` requires API-key authentication and
`state.read`. No query or body (including `{}`/`null`) is accepted: `400`.
Other methods return `405`, authentication/permission failures `401`/`403`.
Native collection requires current-daemon host mode; explicit lab namespaces,
fatal interface enumeration/identity failures and collection-limit failures
return `503`. Individual missing sources return `200` with explicit partial
evidence, not zero measurements. Responses retain `Cache-Control: no-store`.
Register this read-only route in the API Explorer. It never writes capability
snapshots, configuration, revisions or tuning, and sends no probe traffic.

The envelope is `schema:"netcontrol-performance/v1"`, `sample`, `sections`,
`interfaces`, `configured_rps`, `configured_rfs`, `configured_offloads`, `rfs`,
`tuning_available`, `recommendations`,
`config_revision` and `transaction_id`. The last two identify the committed
calendar revision and nullable provisionally applied transaction. `configured_rps`
reflects that applied configuration, not necessarily committed desired state.
`tuning_available` means native host-tuning ownership is available, not caller
write authorization, per-device hardware support or verified performance benefit.
Native host mode acquires this ownership automatically at daemon startup.
Do not require `--allow-host-tunables`, a daemon restart with changed options or
a permission-enabling refresh before offering supported tuning controls.

`sample` contains:

- `scope:"host"`, opaque `backend_scope`, RFC3339 UTC `started_at`/`collected_at`.
- `status:"available"|"partial"`; `atomic:false`.
- Nullable monotonic `sample_interval_seconds`, measured since the prior
  diagnostics request in this daemon, not a configured poll interval.
- `allowed_cpus_scope:"collector_thread"`: the collector's process/cgroup
  constraints do not scope all host kernel networking.
- `identity_stable`: initial/final boot, online, allowed and isolated CPU
  evidence agrees. Changes/unavailable identity clear all baselines and null
  all source intervals, deltas, rates and CPU percentages. Topology and affinity
  are not final-rechecked; collection is still non-atomic.

`sections` has `boot_id`, `online_cpus`, `allowed_cpus`, `isolated_cpus`,
`topology`, `cpu`, `softirqs`, `softnet`, `interrupts`, `irq_affinity` and
`identity_recheck`. Each uses `{status,data,error}`: status
`available|partial|unavailable`, unavailable data null with explicit string error;
partial data retains nested errors. CPU-list data are numeric ID arrays.
Never turn unavailable evidence into empty lists or zero counts.

- `topology.data:{partial,cpus,numa}`: CPU rows have `cpu_id`,
  evidence-wrapped integer `physical_package_id` and `core_id`, and nullable
  numeric `numa_node_ids[]`. `numa` is evidence-wrapped node/CPU-list data.
- `irq_affinity.data:{partial,rows}`: each row has numeric `irq` and
  `smp_affinity_list`/`effective_affinity_list` evidence wrappers, whose data
  contains `cpu_ids[]`.
- `identity_recheck.data:{partial,stable,checks}`: checks for boot/online/
  allowed/isolated evidence retain `initial`, `final`, `matches` and `error`.

Counter-section data (`cpu`, `softirqs`, `softnet`, `interrupts`) contains
`partial`, `metadata`, nullable `sample_interval_seconds`, `baseline` and `rows`.
Use **each source's interval/baseline**, not the envelope interval. Row `counts`
and nonnull `delta` values are exact unsigned decimal strings; nonnull
`per_second` values are floating-point rates. The entire delta/rate object is
null without a valid baseline. Baselines reset on source failure, boot/CPU/
topology/layout identity change or any counter decrease; no wrap inference.
IRQ action-description or affinity changes reset IRQ baselines too. Baseline
labels include `ready`, `initial_or_source_recovered`,
`topology_or_source_layout_changed`, `counter_reset`, `nonpositive_interval`,
`monotonic_clock_reset`, `identity_unavailable`, `identity_unstable` and
`cpu_identity_unavailable`. Only `ready` permits rates.

| Section | Row identity | Count/delta/rate fields |
| --- | --- | --- |
| `cpu` | `cpu_id` | `user_ticks`, `nice_ticks`, `system_ticks`, `idle_ticks`, `iowait_ticks`, `irq_ticks`, `softirq_ticks`, `steal_ticks`, `guest_ticks`, `guest_nice_ticks`, `total_ticks`, `busy_ticks` |
| `softirqs` | `cpu_id` | `net_rx`, `net_tx` (invocations, not packets) |
| `softnet` | Modern `cpu_id` | `processed`, `dropped`, `time_squeeze` (kernel events, not unique packet-loss totals) |
| `interrupts` | `irq`, `cpu_id`, `description` | `interrupts`; numeric hardware IRQs only |

CPU ticks use USER_HZ units. Total excludes additional guest double-counting;
busy excludes idle/iowait. Nullable `busy_percent`/`softirq_percent` use tick
deltas, with zero-total intervals remaining null. Modern softnet layouts use
hexadecimal column 13 as CPU ID, never row position. Historical 11-column
layouts retain counts with `cpu_id:null`, `row_index` and no deltas/rates;
12-column layouts are unavailable. Metadata documents units/source/coverage.

Collection is on demand, with no background worker or persisted benchmark
history. CPU/IRQ collection is bounded to 32 MiB/sample, 4096 CPUs/IRQs and
65536 IRQ-CPU rows. Interface collection is bounded to 8192 links, 4096 physical/WireGuard
RX queues, 65536 NIC-IRQ associations, and checks its five-second budget between
operations. Source files are bounded; these are not hard preemptive I/O deadlines.

`interfaces[]` has `name`, numeric `index`, `mac`, native `kind`, `up`,
`physical`, `managed`, nullable VLAN `parent_index`/`parent`, nullable
`rx_queues:[{name,rps_cpus,rps_flow_cnt}]`, nullable numeric `irqs[]` and `errors:string[]`.
`rps_flow_cnt` is the current nonnegative integer RFS queue table entry count (null for WireGuard),
not a packet counter. Unreadable queue controls produce explicit interface errors.
Queue masks are observed canonical hexadecimal strings. Kernel WireGuard links
expose their RX RPS masks, with null `rps_flow_cnt` and null physical `irqs`.
Other nonphysical links retain null queue/IRQ evidence. `managed` means a configured
Ethernet or WireGuard record; unmanaged/down links remain visible. VLAN parent references can be
followed to the physical NIC; veth peer indices are not mislabeled as parents.
NIC IRQ association comes from device sysfs, not action-name guessing.

`recommendations[]` contains RPS candidates only for up, managed physical NICs
with exactly one observed RX queue, RPS disabled and no interface-source errors:

- Fields: `kind:"rps"`, `target:"INTERFACE/rx-N"`,
  `status:"trial"|"insufficient_evidence"`, nullable `suggested_mask`,
  nullable `evidence`, string `reason`, `automatic:false`, `tuning_available`.
- A concrete trial requires stable identity, available topology/isolation/
  effective-affinity evidence, and ready CPU/NET_RX/IRQ intervals of 1..30
  seconds aligned within 0.1 seconds. An associated active IRQ CPU must have
  busy >=80%, softirq >=30% and positive NET_RX and NIC IRQ deltas.
- Choose at most two online, allowed, nonisolated idle CPUs (busy <=50%,
  softirq <=10%), outside that NIC's effective IRQ affinity. Require distinct
  physical cores, excluding the busy core's SMT siblings, in the same package
  and NUMA node as the observed busy IRQ CPU. This is IRQ-CPU locality evidence,
  not proof of the NIC's own NUMA placement. Rank by lower busy percentage,
  then CPU ID. Missing/ambiguous evidence returns a null mask with reason.
- Evidence records `irq_cpu`, measured `busy_percent`/`softirq_percent`,
  `cpu_sample_interval_seconds`, `target_cpus[]` and `locality`.
  This is a conservative experiment, not a bottleneck diagnosis or speed claim.
  Never auto-submit, auto-confirm, enable all CPUs or edit IRQ affinity.

Simulator responses use the same envelope with `sample.status:"simulated"`,
scope/backend_scope `simulator`, null timestamps/interval/allowed scope,
`identity_stable:false`, null section data and interfaces, and no recommendations.
They never read host performance or claim operational support.

##### Explicit RPS configuration and lifecycle

New optional `kernel.rps` is a nonnull `Record<string,string>`; omitted/empty
means no owned RPS settings. It is omitted from serialization when empty.
Synthetic fragment only, not a complete transaction or recommended CPU choice:

```json
{"kernel":{"rps":{"eno1/rx-0":"c"}}}
```

`c` selects CPUs 2 and 3. Keys use a managed physical Ethernet or kernel WireGuard
interface and canonical `rx-N` queue index 0..4095, maximum 64 settings.
Masks are lowercase comma-separated hexadecimal 32-bit words, highest word
unpadded, subsequent words exactly eight digits; CPU IDs 0..8191.
No `0x`, whitespace, uppercase or redundant leading zeros. `0` disables RPS.
Every selected CPU must be online at native apply preflight. VLANs, other tunnels,
dummy/veth software links and unsupported/missing queues cannot be tuned.
WireGuard creation and RPS may share one candidate, for example
`{"kernel":{"rps":{"wg0/rx-0":"2"}}}` (synthetic CPU-1 fragment, not a
recommendation or full transaction). Physical-device or kernel WireGuard identity,
actual RX controls and write/readback support are verified natively. New WireGuard
queues are checked after link creation; a missing/unwritable queue fails the
transaction and triggers rollback. WireGuard RPS steers post-decryption RX
processing; it does not select crypto worker CPUs. IRQ-based recommendations
remain physical-only; RFS and NIC offloads remain physical-Ethernet-only.

Use the full `POST /api/v1/transactions` candidate and current `base_revision`,
10..300-second confirmation timeout and explicit confirm/rollback. Changes,
confirmation, rollback and revision restores require `transactions.write`,
`kernel.host.write`, `interfaces.write`, plus permissions for other changes.
Native host mode automatically acquires the exclusive host-tunables lock;
no separate operator opt-in is required. Hardware support and actual kernel
write permissions are still checked. Do not copy native `rps_identity` observations
into editable configuration. No new permission, RPS write endpoint or GET tuning.

Known JSON type/null errors are `400`; invalid masks/keys, limits and unmanaged
or ineligible interface references are `422`; authentication `401`/`403`, stale/busy
transaction `409`, native apply/readback/recovery errors use existing `500`
transaction behavior. Source availability errors on diagnostic reads are `503`
or explicit `200` partial evidence as above. Submit success is provisional
`202`; confirm/rollback `200`. Preserve errors and inspect uncertain outcomes,
never automatically retry mutation.

`GET /api/v1/kernel/tunables` and existing runtime reads expose `rps` in
desired/configured/effective/observed/captured-original maps. Native maps may
also expose daemon-owned `rps_identity:{INTERFACE:{index,mac,boot,wireguard_public_key?}}`.
Physical identities omit the public key; WireGuard has an empty `mac` and its
kernel public key. No private key is exposed or stored in tuning identity. Normal
state/revision reads preserve desired masks. Capture original values/identities
durably before writes, verify exact readback, and restore through native intents
on apply failure/interrupted recovery. Failed recovery retains its intent and
error. Remove an entry to restore its original mask and release queue ownership;
set `0` to explicitly own a disabled setting. Confirmation timeout/restart
rollback restores the previous configuration; reboot reapplies verified saved
settings. Same-boot index plus physical MAC or WireGuard public-key checks reject
arbitrary replacement, even a same-key WireGuard replacement. Controlled creation,
rekey and rollback/reboot recreation verify the configured kernel public key
before rebinding identity, preserving owned original masks. A new device's intent
records deletion on rollback; its initial mask is captured after creation and
saved with successful ownership. Deleting WireGuard drops its nonexistent queue
from writes and releases ownership; rollback recreates the device and previous
requested mask. Missing devices outside controlled recreation,
changed CPU availability or unreadable controls fail explicitly; no automatic
hotplug repair, permissive fallback or external tuning coordination.

Frontend tasks: preserve `kernel.rps` in all full-package drafts/history/imports;
offer explicit mask review/edit/removal only with permissions and prerequisites;
show source errors, first/reset samples and pending transaction identity.
Capture before/after diagnostics under the same load, plus existing interface
throughput, link-diagnostic drops/backlog and gateway RTT/loss. A first sample
alone is insufficient. Verify independent management/VLAN/WireGuard reachability,
and compare CPU distribution, rates, drops and latency before confirming.
Do not label the trial faster without measured improvement. No before/after
records are saved by this endpoint; UI comparison/export is frontend-owned.
RFS and NIC offloads have separate explicit controls below. RPS alone changes
none of them. No RSS/XPS, IRQ, qdisc, flowtable, XDP/AF_XDP or DPDK controls.

##### Explicit RFS and NIC offload configuration

These settings use the existing complete-candidate transaction API and the same
`transactions.write`, `interfaces.write`, `kernel.host.write`, native host mode,
automatic host-mode tuning availability and exclusive host-tunables lock
prerequisites as RPS. No tuning GET or separate enable endpoint is added. Do not enable anything
automatically from a capability snapshot or recommendation.

`kernel.rfs?: {sock_flow_entries:number, queues:Record<string,number>} | null`
is omitted when unmanaged. Omitted/null releases RFS ownership; a present object
requires both fields and rejects unknown fields. Global `sock_flow_entries` and
every queue count must be zero or a power of two up to **1048576**. Maximum 64
queues, with the same managed physical Ethernet `INTERFACE/rx-N` keys as RPS.
The sum of configured queue counts must not exceed the global count.
Positive queue counts additionally require an explicitly configured nonzero RPS
mask on the same queue. Neither RPS nor CPU choices are added implicitly.

RFS steers receive work toward CPUs running local socket consumers; it is not a
generic acceleration switch for forwarded/NAT traffic. The global table affects
other local applications and reallocating tables discards learned flow placement.
Coordinate with other tuning tools; do not concurrently manage the same controls.
Zero explicitly disables/owns a table; removing a queue restores its original
count. Removing the entire RFS object restores the original global and owned
queue tables, then releases ownership. RPS itself remains independent.

`kernel.offloads?: Record<string,Record<string,boolean>>` is nonnull, defaults to
empty/unmanaged, and is omitted when empty. At most 32 managed physical Ethernet
interfaces; each feature map must be nonempty. Keys are exact unprefixed Linux
feature names, not group aliases such as `tso`, `gro` or `ethtool:rx-checksum`.
The configurable allowlist is:

```text
rx-checksum
tx-checksum-ipv4
tx-checksum-ip-generic
tx-checksum-ipv6
tx-scatter-gather
tx-scatter-gather-fraglist
tx-tcp-segmentation
tx-tcp6-segmentation
tx-tcp-ecn-segmentation
tx-tcp-mangleid-segmentation
tx-generic-segmentation
tx-gso-partial
rx-gro
rx-gro-hw
rx-udp-gro-forwarding
rx-lro
rx-vlan-hw-parse
tx-vlan-hw-insert
rx-vlan-stag-hw-parse
tx-vlan-stag-hw-insert
```

`rx-lro:true` is rejected: LRO is not safe to enable on a forwarding firewall.
It can be explicitly disabled; unmanaged original settings are not automatically
changed. Availability is driver-specific: a name on this list is not proof of
support. Native preflight freshly checks feature existence/changeability,
physical identity and controls; fixed or unsupported requested features fail,
even if their active value already matches. Do not automatically enable all
supported features or disable Linux offloads based on another OS's defaults.

Synthetic **configuration fragment, not a complete transaction or recommendation**:

```json
{
  "kernel": {
    "rps": {"eno1/rx-0": "2"},
    "rfs": {"sock_flow_entries": 4096, "queues": {"eno1/rx-0": 1024}},
    "offloads": {"eno1": {"rx-checksum": true, "rx-lro": false}}
  }
}
```

Each boolean requests the exact active and requested feature value. Kernel
dependency changes are not silently accepted: submit a coherent set of dependent
features in the same candidate. The backend captures all feature active and
requested bits, including inactive wishes and features outside the configurable
allowlist, before mutation; unrelated changes and readback mismatches fail and
trigger recovery. Removing a feature restores its original setting while other
features on that interface remain owned. Removing the interface entry restores
the whole captured feature state and releases offload ownership.

Original values/identities and complete pre-operation snapshots participate in
native durable intents, failure recovery, explicit/deadline rollback, restart,
reboot and unmanagement. Interface MAC/same-boot index guards reject replacement.
Failed recovery keeps its intent/error; missing drivers, devices or controls
never produce successful no-ops. Confirmation follows independent connectivity
checks, not a claimed performance improvement.
Complete native snapshots must fit the existing 16 MiB per-file recovery limit;
an oversized intent fails before kernel mutation rather than persisting an
unreadable recovery record.

Existing status behavior: malformed types/unknown fields `400`; invalid counts,
dependencies, references, allowlist or LRO enable `422`; authentication `401/403`;
stale/busy `409`; provisional apply `202`; confirm/rollback `200`; native
preflight/write/readback/recovery failure `500`. Kernel/runtime source failures
remain `503` rather than fabricated values.

`GET /api/v1/kernel/tunables` and `GET /api/v1/runtime` expose the new configured,
effective, observed and captured-original `rfs`/`offloads` maps. Native observations
also include daemon-owned `rfs_identity`, `offload_identity` and
`offload_requested` (full feature-request bits). These fields are not editable
KernelConfig fields and must not enter transaction candidates. Empty optional
native maps may be omitted. `GET /api/v1/state` and revisions retain only desired
configuration, not driver metadata.

Performance diagnostics add `configured_rfs` (object/null),
`configured_offloads` (object) and
`rfs:{status:"ready"|"unavailable"|"simulated",sock_flow_entries:number|null,error:string|null}`.
Global RFS source failure makes the sample partial with an explicit error.
Simulator observations are modeled state, never measured hardware; its RFS
global evidence is simulated/null. Capability inventory remains a separate
timestamped cache; explicit refresh, no automatic refresh polling, is unchanged.

Required frontend tasks: preserve both fields in full-package edits/imports/
history; provide explicit physical-NIC feature controls with support/fixed/error
evidence and dependency review; make LRO disable-only; add global/per-queue RFS
budget and RPS dependency validation. Distinguish disable from restore-original,
desired from active/requested bits, and cached inventory from fresh readback.
Use pending confirmation/error UI and before/after CPU, throughput, drops and
latency comparisons; offload changes affect packet capture/accounting granularity.
There is **no ALTQ, CAKE/FQ-CoDel, HTB, ingress IFB or other shaping implementation**;
all traffic shaping was explicitly deferred.

#### Host health sensors

`GET /api/v1/statistics/host` is a read-only API-key-authenticated `state.read`
operation. No query parameters or configuration fields. It is deliberately
**not** included in `GET /api/v1/statistics`: only the lightweight host `uptime`
object is included there. Poll this endpoint when displaying full host health.
CLI equivalent: `show statistics host`.

It reads procfs/sysfs and calls `statvfs` in the **daemon's** existing process/
mount context, without entering the configured networking lab namespace.
`sample.scope` is `"host"`, not the network statistics' namespace identity.
In a container these are kernel/host-wide or mount/PID-namespace-visible values,
not necessarily container/cgroup limits or a physical appliance inventory.
No cgroup quota normalization, SMART drive-health prediction, external commands,
sensor driver loading, writes, saved history, alarm policy or background sampler.
The simulator never reads the development host: its scope/status are
`"simulator"`/`"simulated"`, boot identity is null, and all section data is null.

Response envelope:

- `schema`: literal `"netcontrol-host-health/v1"`.
- `sample`: `scope`, `boot_id` (Linux boot UUID string; null only in simulator),
  `started_at`, `collected_at` (RFC3339 UTC) and `status`
  (`available`, `partial`, `simulated`). Collection is sequential, not atomic.
- `sections`: the twelve keys below. Each is
  `{status, data, error}`. Status is `available`, `partial` (array has failed
  children), `unavailable`, or `simulated`. An unavailable/simulated section has
  `data: null` and an explanatory error string, not zero. Available sections have
  `error: null`; partial array sections retain usable rows and child errors.
  Missing kernel features, permissions and hot-unplug are explicit failures.
  An empty available sensor array means no matching sensors were enumerated.

| Section | Data and source |
| --- | --- |
| `cpu` | `/proc/stat`: `ticks_per_second` (positive JSON integer from `_SC_CLK_TCK`), `cpus: [{name, ticks}]`, `scheduler` map. CPU names are aggregate `cpu` and `cpuN`. Tick keys: `user`, `nice`, `system`, `idle`, optional `iowait`, `irq`, `softirq`, `steal`, `guest`, `guest_nice`. Scheduler keys when present: `ctxt`, `processes` (cumulative forks), `procs_running`, `procs_blocked` (gauges). |
| `memory` | `/proc/meminfo`: `bytes` map preserving kernel names for all `kB` fields, multiplied by 1024. Required `MemTotal`, `MemFree`, `MemAvailable`, `SwapTotal`, `SwapFree`. `used_bytes = MemTotal - MemAvailable`, `swap_used_bytes = SwapTotal - SwapFree`. Non-byte HugePages counts are omitted. Reclaimable cache is not automatically treated as unavailable memory. |
| `load` | `/proc/loadavg`: finite nonnegative JSON numbers `one`, `five`, `fifteen`; decimal strings `runnable_tasks`, `total_tasks`, `last_pid`. Load is not a percentage; includes uninterruptible tasks. |
| `uptime` | `/proc/uptime`: finite nonnegative JSON numbers `uptime_seconds`, `idle_seconds`; summed CPU idle time can exceed uptime. |
| `vm` | `/proc/vmstat`: available cumulative keys `pgpgin`, `pgpgout` (KiB), `pswpin`, `pswpout` (pages), `pgfault`, `pgmajfault`, `oom_kill` (events). Missing keys are omitted, never invented. |
| `pressure_cpu`, `pressure_memory`, `pressure_io` | Corresponding `/proc/pressure/*`: required `some`, optional `full`; each has JSON numeric `avg10`, `avg60`, `avg300` (0..100 percent stall-time averages over seconds) and decimal-string `total` (cumulative microseconds). Optional kernel PSI support; do not substitute zero when absent. |
| `disks` | `/proc/diskstats`: array `{name, major, minor, counters}`. Major/minor and all counters are decimal strings. Includes disks, partitions and virtual devices, not just managed storage. See fields below. |
| `filesystems` | `/proc/self/mountinfo` and `statvfs`: array `{mount_id, device, mount_point, filesystem, usage}`. Mount ID is a decimal string, device is `major:minor`, other identity fields strings. `usage` is its own `{status,data,error}`. Data: decimal strings `total_bytes`, `free_bytes`, `available_bytes`, `used_bytes`, `total_inodes`, `free_inodes`, `available_inodes`; boolean `read_only`. Used = total minus free; available excludes reserved space. Zero inode totals may mean no inode accounting. |
| `thermal` | `/sys/class/thermal/thermal_zoneN`: array of `{id,status,data,error}`; data `{type, temperature_millicelsius}`. Temperature is a signed JSON integer; negative temperatures are valid. |
| `hwmon` | `/sys/class/hwmon/hwmonN`: temperature and fan input array, `{id,chip,unit,status,data,error}`; unit `millicelsius` or `rpm`, data `{value,label}`. Value is a signed JSON integer (RPM nonnegative), label nullable string. Per-chip enumeration/name failures produce an unavailable row with only `id,status,data,error`. A nonzero/malformed optional kernel `*_fault` marks that sensor unavailable, not healthy. |

Disk `counters`: `reads_completed`, `reads_merged`, `sectors_read`, `read_ms`,
`writes_completed`, `writes_merged`, `sectors_written`, `write_ms`,
`io_in_progress` (gauge), `io_ms`, `weighted_io_ms`; optional kernel groups
`discards_completed`, `discards_merged`, `sectors_discarded`, `discard_ms`,
`flushes_completed`, `flush_ms`. Sector units are always 512 bytes, regardless
of physical sector size. `_ms` fields are cumulative milliseconds.
Do not sum disks and their partitions/device-mapper layers into a host total.

Filesystem collection deliberately includes only local filesystem types:
ext2/3/4, xfs, btrfs, f2fs, jfs, reiserfs, zfs, overlay, tmpfs, ramfs, squashfs,
vfat, exfat and ntfs3. Network, FUSE, autofs and other pseudo/unknown filesystems
are excluded without probing their space. Mounts/bind mounts can duplicate
storage; values describe the currently path-resolved filesystem, not additive
physical capacity. Collection is not a hard-deadline I/O service: local storage
faults or concurrent mount changes can still delay syscalls. Reads are bounded
to 2 MiB per source; directory enumeration and filesystem/sensor lists to 4096
entries. Oversized/malformed sources are explicit errors.

**Frontend tasks:** add host-health client types and a monitoring view for memory/
swap, CPU utilization, load/uptime, PSI, local space/inodes, disk I/O and sensors.
Poll every 2-5 seconds only while visible, without overlaps; back off on errors.
Keep state separate from configuration drafts/revisions. Label scope, freshness,
units, duplicates and partial/missing readings; render kernel labels as text.
Do not infer universal healthy/warning thresholds for hardware or load.

Counters/large gauges are quoted decimal strings: use strings/BigInt and exact
deltas, converting only a bounded display result to Number. CPU busy percentage
requires two valid samples: total ticks = sum user through steal (omit absent
fields), busy = total minus idle minus iowait, percent = 100 * delta busy /
delta total. Never add guest/guest_nice again (already included in user/nice).
Treat iowait-based utilization as approximate. Reset baselines on boot/scope/
device/CPU identity changes, missing data, any contributing counter decrease or
nonpositive elapsed/total delta. First samples show no rates. Use actual uptime
delta for disk/event rates, not the scheduled polling period. Counter resets,
CPU hotplug and device reuse may be ambiguous; never repair them speculatively.
Thermal and hwmon may expose the same physical sensor; do not average or sum.

HTTP `200` carries successful or partial snapshots (even if all sections fail).
`401`/`403` retain normal API-key/permission semantics; query parameters are
`400`, non-GET methods `405`, unknown subpaths `404`. Boot-identity or top-level
collection errors are `503` with the normal `{error,transaction:null}` envelope.
No new privilege/host-service opt-in, persisted state or deployment service:
readable Linux procfs/sysfs and local mount access are required, with a daemon
rebuild. Browser polling/rendering and physical hardware coverage require
frontend/appliance acceptance; portable tests alone are not that evidence.

#### Conntrack connection snapshots

`GET /api/v1/statistics/connections` is an API-key Bearer-authenticated,
`state.read` action. It reads Linux conntrack directly through netfilter netlink
in the daemon's network namespace (host by default, optional lab namespace).
It includes tracked connections involving unmanaged links, loopback, local
services and other firewall owners, not just managed forwarded traffic. Treat
remote/local endpoint visibility as sensitive operational data; do not log or
persist complete snapshots in browser storage or export them automatically.
Collection is independent of configuration observation and protocol-worker
health, and is not included in aggregate `GET /api/v1/statistics` polling.

Query parameters use normal URL encoding. Unknown/duplicate parameters, empty
values, malformed/out-of-range values and queries over 4096 bytes return `400`.
Numbers are canonical unsigned decimal without leading zeroes except `0`.

| Parameter | Type/default and validation |
| --- | --- |
| `limit` | Integer 1..1000, default 100 |
| `offset` | Integer 0..1000000, default 0 |
| `family` | Omit for both; `ipv4` or `ipv6` |
| `protocol` | Omit for all; `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, or numeric IP protocol 0..255 |
| `address` | Canonical IPv4/IPv6 literal, no hostname/CIDR/zone; matches either endpoint in either tuple; must agree with `family` when both supplied |
| `port` | Integer 0..65535; matches either source/destination port in either tuple |
| `zone` | Integer 0..65535; matches the top-level conntrack zone |

Example: `GET /api/v1/statistics/connections?protocol=tcp&port=443&limit=100`.
Filtering is AND across parameters, applied after the namespace-wide dump. It
does not reduce kernel dump cost. A successful native response has:

- `schema`: literal `netcontrol-connections/v1`.
- `sample`: normal `scope`, RFC3339 `started_at`/`collected_at`, and `status`.
  Status is `partial` when any matched connection lacks counters in either
  direction; otherwise `available`. An empty successful snapshot does not prove
  connection accounting is enabled. The window is not an atomic kernel snapshot.
- `summary`: nonnegative integer `total` (all dumped entries), `matched` (after
  filters), `returned` (this page), `accounting_unavailable` (matched entries
  missing either directional counter object). These are counts, not counter
  strings. Accounting-unavailable counts apply to all matches, not only this page.
- `limit`, `offset`: effective numeric values; `next_offset`: integer or `null`.
  Offset beyond available matches returns an empty page and null next offset.
- `connections`: array ordered by zone/available ID and tuple identity. Every
  page is a new live dump; connections can arrive/expire between pages, so pages
  may overlap/skip entries. No retained snapshot, cursor or historical store.

Each connection contains these non-optional fields (nullable where specified):

| Fields | Types and meaning |
| --- | --- |
| `id` | Decimal string or null, kernel conntrack ID; not a durable/global identity |
| `zone` | Integer 0..65535; zero when the kernel omits the default zone |
| `family` | `ipv4` or `ipv6` |
| `protocol`, `protocol_name` | Numeric IP protocol and `tcp`/`udp`/`icmp`/`icmpv6`/`sctp`/`other` |
| `state`, `tcp_state` | State string and nullable numeric TCP conntrack state; raw unknown TCP states are retained with `state: "UNKNOWN"` |
| `status` | Raw unsigned 32-bit kernel conntrack status bitmask |
| `seen_reply`, `assured`, `source_nat`, `destination_nat` | Booleans derived from kernel status, not rule evaluation |
| `mark` | Unsigned 32-bit connection mark; zero when omitted by the kernel |
| `timeout_seconds` | Remaining kernel timeout in seconds, or null |
| `original`, `reply` | Tuple objects in each kernel direction, not frontend-local TX/RX |
| `original_counters`, `reply_counters` | `{packets: string, bytes: string}` or null; exact unsigned decimal strings |

Tuple fields are non-null IP strings `source`, `destination`; nullable integer
`source_port`, `destination_port`, `icmp_id` (0..65535), `icmp_type`, `icmp_code`
(0..255); and nullable tuple `zone` (0..65535). No invented ports for ICMP or
unknown protocols. Original/reply tuples expose NAT translations without
asserting which rule caused them. TCP state strings are `NONE`, `SYN_SENT`,
`SYN_RECV`, `ESTABLISHED`, `FIN_WAIT`, `CLOSE_WAIT`, `LAST_ACK`, `TIME_WAIT`,
`CLOSE`, `LISTEN`, `SYN_SENT2`, or `UNKNOWN`; without a TCP state the coarse status
is `ASSURED`, `SEEN_REPLY`, or `UNREPLIED`. These are conntrack states, not
application connection status or current firewall allow/drop verdicts.

Synthetic example with unavailable kernel accounting:

```json
{
  "schema": "netcontrol-connections/v1",
  "sample": {"scope":"synthetic:namespace","started_at":"2026-10-24T12:00:00Z","collected_at":"2026-10-24T12:00:00.010Z","status":"partial"},
  "summary": {"total":1,"matched":1,"returned":1,"accounting_unavailable":1},
  "limit": 100,
  "offset": 0,
  "next_offset": null,
  "connections": [{
    "id":"42","zone":0,"family":"ipv4","protocol":6,"protocol_name":"tcp",
    "state":"ESTABLISHED","tcp_state":3,"status":22,"seen_reply":true,"assured":true,
    "source_nat":true,"destination_nat":false,"mark":0,"timeout_seconds":120,
    "original":{"source":"192.0.2.10","destination":"198.51.100.20","source_port":40000,"destination_port":443,"icmp_id":null,"icmp_type":null,"icmp_code":null,"zone":null},
    "reply":{"source":"198.51.100.20","destination":"203.0.113.10","source_port":443,"destination_port":50000,"icmp_id":null,"icmp_type":null,"icmp_code":null,"zone":null},
    "original_counters":null,"reply_counters":null
  }]
}
```

Counter values are kernel per-connection accounting, not interface/L2 throughput,
application payload, or cumulative per-rule hits. Null is unavailable, not zero.
Kernel accounting generally requires `net.netfilter.nf_conntrack_acct=1` in the
same namespace when the connection is created; enabling it is an explicit
operator deployment action, is not retroactive for existing entries, and is not
performed by this read API. Ubuntu installation/full upgrade now configure it
automatically as part of that operator workflow (section 4.1); other deployment
paths/namespaces require explicit setup. Null counters and partial samples must
still be supported after installation/upgrade. Never flush connections to obtain counters. Rates require
matching scope, ID/zone and full tuple identity, exact integer deltas and actual
sample time; reset on counter decrease, identity change, disappearance or error.
Do not invent a rate from a first sample, null/simulated counters or a page change.

Kernel dump limits are 100000 entries, 64 MiB received, a five-second receive
collection budget and a 1 MiB maximum datagram. Missing kernel support/modules,
insufficient netfilter privileges, interrupted/malformed/over-limit dumps and
read errors are `503`, not an empty available response. The existing raw
netfilter reader validates kernel sender/sequence and rejects interrupted dumps;
its framing checks also continue to protect native nftables drift inspection.
The kernel read budget does not include all decoding/serialization overhead.
Invalid/missing key is `401`, insufficient permission `403`, unsupported method
`405`, unknown endpoint suffix `404`; errors use `{error, transaction: null}`.

Simulator returns `200` with `sample.status: "simulated"`, an empty array,
`summary.total`, `matched`, `accounting_unavailable` null, `returned: 0`, and null
`next_offset`. It does not fabricate native activity or measured zero totals.

Frontend tasks: add a Connections view with server-side filters,
original/reply/NAT details, state/remaining timeout, directional counters,
freshness and unavailable accounting messages. Poll only while visible, do not
overlap requests, back off on `503`, reset offset on filter change and preserve
drafts. Keep only ephemeral monitoring state. Deletion is a separately authorized
action described below; reads never delete state. Prefer ID plus zone/tuple
identity over array position for row keys.
Existing `GET /api/v1/firewall/rules` and desired firewall configuration remain
the rule-definition sources. Per-rule counters use the separate
[rule accounting endpoint](#firewall-rule-match-counters), not connection sums.
The connection endpoint does not add rule-to-connection attribution, packet logs, guaranteed visibility of rejected
or NOTRACK traffic, historical connections, or automatic policy changes.

#### Connection state deletion

Bearer API keys need the dedicated `connections.delete` permission, not just
`state.read` or firewall write permission. Device-account keys receive all current
permissions; scoped keys need an explicit grant. These are immediate operational
actions, not configuration transactions, and do not change saved configuration,
revisions, ownership, firewall rules or accounting settings. They require Linux
conntrack/netfilter write privileges in the daemon's configured namespace.
Simulator/non-Linux backends return `503`, never simulated destructive success.

`DELETE /api/v1/connections` deletes all conntrack entries in that namespace,
including IPv4/IPv6, all zones, unmanaged/local/other-owner traffic and management
or NAT state. It does not apply the Connections view's filters. The body must be
exactly `{"confirm":true}`; missing/false confirmation is `400`. No item ID means
collection deletion, not an empty request body. A trailing slash, empty item ID
or malformed ID is an error, never a fallback to deleting everything.

`DELETE /api/v1/connections/{id}` targets the snapshot row's ID plus original
tuple, family, protocol and zone. ID must be canonical unsigned 32-bit decimal
(0..4294967295), without signs, leading zeroes, suffixes or additional slashes.
The JSON body has exactly `family` (`"ipv4"`/`"ipv6"`), `protocol` (integer),
`zone` (integer 0..65535) and `original` (tuple object). Synthetic TCP example:

```json
{
  "family": "ipv4",
  "protocol": 6,
  "zone": 0,
  "original": {
    "source": "192.0.2.2",
    "destination": "198.51.100.2",
    "source_port": 50000,
    "destination_port": 443
  }
}
```

Use `/api/v1/connections/123` for a synthetic row with ID `"123"`. Project only
the four named fields from the row; do not submit reply/counters/state/ID as
extra body fields. `original.source`/`destination` must match the chosen IP
family. TCP (6), UDP (17) and SCTP (132) require both ports (integers 0..65535)
and absent/null ICMP fields. ICMP (1, IPv4) or ICMPv6 (58, IPv6) requires
`icmp_id` (0..65535), `icmp_type`/`icmp_code` (0..255), and absent/null ports.
An optional `original.zone` must be null/absent or equal the top-level zone;
direction-specific differing zones and other protocols are not supported for
targeted deletion. No unknown fields or query parameters are accepted. Disable
row deletion if ID or the required identity fields are unavailable/unsupported.
IDs are ephemeral and can be reused; do not retain a selector as durable identity.

Success is `200` with `{"status":"deleted","scope":"<namespace-scope>"}`
for one entry or `{"status":"flushed","scope":"<namespace-scope>"}` for
the collection. There is no deleted-count claim. Kernel acknowledgement is
required; stale/nonmatching ID+tuple+zone returns `404`, never a flush. Other
errors use `{error, transaction: null}`: `400` invalid selector/body/query,
`401` invalid/missing key, `403` missing permission, `405` unsupported method,
`409` active configuration transaction or software-upgrade maintenance, `503`
unsupported backend, kernel/privilege/transport failure. No POST flush alias.

Deleting conntrack state does **not** send TCP RSTs, close application sockets or
guarantee a fresh TCP handshake. Subsequent packets can recreate state immediately
according to kernel/firewall policy, so even an acknowledged flush need not leave
the next snapshot empty. Existing management/NAT traffic can be disrupted. There
is no undo or revision rollback for this operation. On timeout/disconnection or
transport failure, outcome may be unknown or partial; refresh state, do not
automatically retry a destructive request.

Frontend tasks: gate row/all-state delete controls by permission and maintenance
status, require explicit confirmation (stronger warning for whole namespace),
keep the collection action clearly independent of current filters, disable while
pending and refresh after success or uncertain outcomes. Treat `404` as a stale
row and refetch. Preserve configuration drafts and monitoring rate semantics;
never automatically flush to obtain counters or apply a firewall rule change.

### 6.1.2 Gateway health and RTT variation

Native IPv4/IPv6 ICMP monitoring is available, without dpinger. No automatic
failover, configured forwarding-route changes, Prometheus endpoint, or persistent metric history is
implemented. Gateways are independent named resources in `config.gateway_monitors`.
Edit them in the shared draft and submit a complete transaction, never through
service repair. Disabled monitors retain their validated settings.

Editor fields: name, enabled, mode, managed interface, target, and timing/threshold
fields. `mode` is `explicit` (default when omitted) or `dhcp`. Explicit mode also
requires source address, gateway and routing table. Canonical output omits
`mode` for explicit monitors. Do not infer mode/path from WAN/LAN role. Names are unique/case-sensitive,
1..32 `[a-zA-Z0-9_-]` characters, maximum 64 monitors. Numeric addresses must be
canonical and same-family in explicit mode; reject hostnames, zones, mapped IPv6, loopback,
multicast, and unspecified addresses. Source must be configured on an up
managed interface, cannot be link-local or equal the gateway/target. Private/ULA
sources are valid. IPv6 gateway/target can be link-local; interface supplies
the scope. Enabled monitors require a matching enabled explicit route into table 254 or
10000..19999. The backend manages internal source-policy rules for enabled monitor
source addresses only (`/32` IPv4, `/128` IPv6); these are not editable or exposed
as configuration. Enabled monitors sharing a source must use the same routing
table (`422` otherwise). Rules are deduplicated and deterministically assigned
priorities starting at 10000; disabling/removing monitors reconciles their rules
through normal transaction/rollback/recovery. These source matches also affect
other traffic using that exact source address, not just probe packets.
Disabled explicit monitors need not retain network references. Never silently add configured routes
or firewall exceptions. Changing monitors requires `gateway_monitors.write`;
there is no separate policy permission.

**DHCP/Automatic IPv4 mode:** persist `mode: "dhcp"`, the selected managed
interface, target and monitor settings only. The interface must have a
`dhcp_clients` entry, and must be up when the monitor is enabled; this reference
is required even for disabled DHCP monitors. No static address, configured route
or active lease is required to save/confirm an enabled monitor. Omit
`source_address`, `gateway` and `routing_table`: empty strings/zero also normalize
to omission, but nonempty/nonzero explicit fields return `422`. Null/type/unknown
mode errors return `400`. IPv6 targets in DHCP mode return `422`; DHCPv6 is not
supported. Existing explicit IPv4/IPv6 behavior and timing defaults are unchanged.

Synthetic monitor object (inside a complete configuration transaction):

```json
{"name":"wan-health","enabled":true,"mode":"dhcp","interface":"wan1","target":"1.1.1.1"}
```

Never copy a lease's source/gateway/table into the draft, history or export.
The backend resolves only the selected interface's valid, matching DHCPv4 lease.
It chooses the target's longest-prefix lease route, then lowest metric; conflicting
equal-ranked next hops are unavailable. There is no other-interface/default-route
fallback. Same-path renewal, DNS/server/lifetime changes preserve the window;
source/gateway/selected-route changes stop/join and rebind the probe, restarting
warmup. Expiry/removal stops probing; acquisition/reacquisition resumes it
automatically, without a configuration revision. A 100 ms coordinator poll follows
completed lease updates; kernel operations/worker startup add bounded processing
time, so this is not a strict 100 ms end-to-end guarantee.

Native DHCP paths use private IPv4 tables/socket marks 20000..20063 and exact
mark-plus-source-plus-output-interface rules at priorities 9000..9063, tagged protocol 244. A terminal
unreachable route prevents lookup fall-through. These are owned runtime state,
not public routes/rules or automatic WAN failover. Multiple monitors on one
interface, including identical targets, have independent marked paths/windows;
unmarked application traffic is unaffected by these DHCP rules. Foreign entries are not
overwritten; conflicts report unavailable/Unknown. Disable/delete, transaction
rollback, repair/restart and recovery reconcile workers and tagged paths.

Discover support with authenticated `GET /api/v1/runtime` (`state.read`):
`capabilities.gateway_monitor_modes` is `["explicit","dhcp"]`, and
`capabilities.dhcp_gateway_monitor_address_families` is `["ipv4"]`. If these
signals are absent or omit DHCP/IPv4, do not offer DHCP mode or test support with
a write. Capability means schema support, not operator opt-in, privileges or a
current lease. No version endpoint or fallback contract is introduced.

Gateway timing fields use these inclusive bounds (milliseconds except percent):

| Field | Default | Bounds |
| --- | --- | --- |
| `probe_interval_ms` | 1000 | 100..60000 |
| `loss_timeout_ms` | 2000 | 100..60000 |
| `window_ms` | 30000 | 1000..300000 |
| `latency_threshold_ms` | 150 | 1..60000 |
| `loss_threshold_percent` | 20 | 1..100 |
| `rtt_variation_threshold_ms` | 0 | 0..60000 |
| `failure_hold_ms` | 3000 | 100..60000 |
| `recovery_hold_ms` | 5000 | 100..60000 |

Explicit zero or omission selects defaults except zero variation threshold means
disabled. Null/type errors return `400`; invalid normalized bounds return `422`.
Disabled monitors still undergo validation. Loss timeout must be at most ten
probe intervals; window must be at least two loss timeouts and three probe
intervals, and at most 1024 probe intervals.
Display units as milliseconds or percent, not seconds/microseconds. Validate
cross-field timeout/window limits and preserve disabled settings in review,
serialization, revision history, rollback, and restore.

Show three independent status columns:

- `process_state`: native worker lifecycle, not an external process/PID.
- `sample_status`: disabled/simulated/warming_up/available/stale/unavailable/waiting_for_dhcp.
- `health`: unknown/up/degraded/down.

Socket/path failure is unavailable/unknown, **not** gateway down. Do not use
missing/null as zero, draw simulated samples as successful probes, hide errors,
or infer health from the configuration's `enabled`. Full-window warmup precedes
classification. Down means 100% finalized loss; degraded means configured
loss/mean-RTT/optional-variation threshold reached. Worsening must persist for
failure hold, improvement for recovery hold; initial Up also uses recovery hold.
Default window is 30 seconds, failure hold 3 seconds, recovery hold 5 seconds,
degraded thresholds 20% loss / 150 ms average RTT. Explain that rolling-window
effects add to hold time. ICMP reachability is not proof of application health.

Rows always include `mode`, `interface`, `resolved_source_address: string|null`,
`resolved_gateway: string|null`, `resolved_routing_table: number|null`, and
`reason: string|null`. These are runtime values, not editable configuration.
Before/after a valid lease, enabled DHCP monitors report `process_state: "waiting"`,
`sample_status: "waiting_for_dhcp"`, `health: "unknown"`, null resolved values and
reason `"waiting for DHCP lease"`. An active lease with no usable target route,
ambiguous route or probe/path setup failure reports `error`/`unavailable`/Unknown
with a diagnostic reason, not remote Down. Render waiting and unavailable
reasons even when HTTP is `200`; reason text is diagnostic, not an enum.
Resolved gateway is null for a direct DHCP route; resolved source/table remain
present when probing. Disabled rows have null resolved values/reason. Simulator
DHCP rows stay simulated/Unknown with null resolved values and an explanatory
reason; no lease or measured success is fabricated.

Display loss percentage; sent/received/lost/pending window counts; min/max/mean,
population RTT standard deviation, nearest-rank p50/p95; last success and
freshness; and **RTT variation (not one-way/RTP jitter)**:

`mean(abs(RTT[n] - RTT[n-1]))` only over adjacent transmitted probes with replies.

Never bridge losses/pending probes or turn loss into zero RTT. Null variation
with no pairs is normal. `sent = received + lost + pending`; loss excludes
pending from its denominator. Last success may precede the current window.
Do not derive cumulative packet totals or rates from these rolling-window
counts. Histories reset on affected settings/network changes, repair/restart;
configuration revisions do not restore measurements.

Poll cached APIs using the existing 2-5 second, non-overlapping policy.
Collection endpoint returns `monitors: []` when empty. Single-name lookup is
case-sensitive, 404 when absent. All statistics query parameters are rejected.
Individual failed monitors can return HTTP 200 with errors; display them.
Gateway sample envelope is `available`, `partial`, or `simulated`; individual
sample statuses remain authoritative. Per-monitor `collected_at` is cached
measurement time, not the envelope retrieval time. Cached samples become stale
after max(1000 ms, 3 probe intervals); render Unknown and stop live graphing.
Keep last-known data visibly stale rather than current.

Runtime includes `gateway_monitors`; dedicated service status returns
`{monitors, error}`. Render top-level and row errors. Offer explicit repair with
confirmation and all enabled-service permissions; it uses stored settings,
does not apply the draft, and does not create a revision. Health/worker failure
does not mutate configured enabled or create modeled drift by itself.

Operator prerequisite: Linux gateway monitoring and host-service opt-ins
(`--gateway-monitoring` / `NETCONTROL_GATEWAY_MONITORING=true` and, in host
appliance mode, `--allow-host-services` / `NETCONTROL_ALLOW_HOST_SERVICES=true`),
raw ICMP/namespace privileges,
correct routes/rules/return paths, and ICMP/ICMPv6 permission through other
firewalls. The API cannot install packages, grant capabilities, or set that flag.
DHCP mode additionally needs native route/rule/socket-mark administration and
free private table/priority/mark ranges above. Deploy the backend before enabling the new frontend
mode. Use the [explicit dual-stack plus DHCP example](examples/gateway-monitoring.json).
The current install and full upgrade scripts automatically persist both opt-ins
in `netcontrold.service.d/50-netcontrol-appliance-services.conf` using the
environment settings, without replacing customized `ExecStart` arguments.
`--build-only` does not alter service settings. Direct/manual deployments still
need the flags or environment settings; absent settings default to false and
invalid boolean environment values fail startup. These permissions do not enable
disabled services or add monitor configuration. Missing opt-ins reject
enabled monitors before native networking changes; transaction errors remain `500`
with the transaction and rollback outcome, now retaining the underlying error
chain in both `error` and `transaction.error`. Display the full message, not just
the outer native rollback context. Do not automatically retry, disable the monitor,
or add routes to work around an operator prerequisite. See
[operator setup](docs/BUILD_AND_INSTALL.md#enabling-gateway-monitoring-on-an-installed-appliance).

### 6.1.3 Appliance NTP, syslog, and vnStat

Add shared-draft editors for `config.ntp`, `config.syslog`, `config.vnstat`.
All integrations default disabled. Exact server limits, canonical host syntax,
timing, lifecycle semantics, operator prerequisites and warnings are in the
[native protocol service implementation](crates/netcontrol-services).
Use the [complete example](examples/appliance-services.json), replacing synthetic
servers and preserving the actual complete network configuration.

- NTP editor: enabled toggle and 0..8 unique server host/IP strings; enabling
  requires at least one. This disciplines the **whole appliance clock**, not an
  isolated clock, with host networking. Client only, slew-only, no NTP serving
  or NTS. Each correction is bounded to +/-500 ms, with continued polling for
  larger residual offsets. Running is not synchronized. Rollback restores
  settings, not time. No server-consensus/falseticker algorithm is provided.
  Ubuntu fresh installation and full source upgrades now stop/disable and
  persistently mask standard OS NTP clients and one-shot services/timers,
  including absent units, with stopped/persistent-mask verification and remaining
  known-client checks. Failures abort deployment. Saved `ntp.enabled` and
  `ntp.servers` remain unchanged; disabled means no managed network time sync,
  not fallback to timesyncd/chrony. Enabled polls configured servers only, with
  no implicit public pool. Disabling does not restore OS clients. Arbitrarily
  named custom clients/cron launchers require operator removal. Existing hosts
  need the revised full source upgrade; HTTP/automatic binary self-upgrades
  retain existing masks but do not establish them. No API/client-type changes;
  update NTP/operator help for the clock-drift/TLS implications and
  [deployment scope](docs/BUILD_AND_INSTALL.md#ntp-ownership).
  [Handoff 2026-11-09-06](docs/frontend-handoffs/2026-11-09.md#2026-11-09-06-exclusive-os-ntp-ownership)
  is pending frontend review.
- Syslog editor: enabled toggle and 0..8 unique `(host, port, transport)` rows;
  enabling requires at least one. Explicit `udp`/`tcp`/`tls`, integer port
  1..65535, canonical IP or lowercase DNS host. TLS uses verified operator trust;
  no insecure fallback. Warn that UDP/TCP are unencrypted and UDP can lose logs.
  Fan-out receives journald-forwarded host/kernel/daemon stderr messages; backend
  JSON remains message text. Native syslog requires systemd/journald and the
  inherited `netcontrol-syslog` datagram socket at `/run/systemd/journal/syslog`.
  Journald retains `/dev/log`. No direct kernel reader/backend file tail remains,
  avoiding duplicate capture. OpenRC/direct launches cannot enable native syslog.
  The Rust worker does not start/stop a system syslog daemon. Describe its actual
  captured sources and unavailable sources explicitly; do not imply complete
  system/kernel/backend delivery merely because a worker is running.
- vnStat editor: one enabled toggle for **all host interfaces**, not a
  selected-interface list or scope selector; optional nullable UDP collector.
  One worker/database includes unmanaged/loopback and newly created interfaces.
  Inventory, sampling and synchronized history publication occur every 5 seconds.
  Traffic across VLAN/parent/veth/loopback overlaps: never sum it.

Per service in `ntp`, `syslog`, `vnstat`:

| Method | Path | Shape |
|---|---|---|
| GET | `/api/v1/services/{service}` | `NTPConfig`, `SyslogConfig`, or `VNStatConfig` |
| GET | `/api/v1/services/{service}/status` | `{instances: ApplianceServiceStatus[], error: string}` |
| POST | `/api/v1/services/{service}/reconcile` | No body, `RuntimeState`; all enabled services |

`RuntimeState.appliance_services` always contains `ntp`, `syslog`, `vnstat`
and `mdns` rows; service-specific status filters to its instances.
The `mdns` row has the separate typed shape in section 6.1.7.
Render lifecycle state, scope, optional start time, optional active traffic-history
database directory and errors. Native workers use `disabled`, `running`, `error`,
or `stopped`; simulator rows are `simulated`. Preserve unknown states rather than
relabeling them as success. HTTP 200 can contain row errors.
Native service supervisors retry preparation/runtime errors, unexpected exits
and unwind panics automatically with capped 1, 2, 4, 8, 16, 30-second backoff.
An attempt lasting at least 60 seconds resets the delay. Optional recovery fields
on native worker rows (and explicit gateway monitor rows) are `retrying: boolean`,
`restart_count: number` (nonnegative failed/ended attempt count since supervisor
creation), and `last_error: string` (retained after recovery). `state: "error"`
with `retrying: true` is a live recovering supervisor, not a disabled setting.
`started_at` describes the latest ready execution attempt. Current `error` clears
on readiness; fresh NTP sample collection resumes as `warming_up`, not stale
success. Do not treat old sample timestamps/counters as current delivery proof.
Native verification checks applied settings and active owned supervisors, not
service health. Runtime service unavailability alone does not fail configuration
reads, apply/confirmation/rollback, or impose a global editing lock. Structural
validation, opt-ins, missing syslog activation, genuine networking drift,
authorization, persistence and transaction recovery errors remain enforced.
Running proves local worker/namespace/readiness only, **not** synchronized
clock, complete capture, or remote delivery. NTP exposes optional sample
`offset_ms`, `delay_ms`, `requested_slew_ms`, `uncorrected_offset_ms`, `server`,
`collected_at`, `discipline: "slew_only"`, and
`sample_status: "warming_up"|"available"|"unavailable"`. Offsets are signed
milliseconds; delay is nonnegative. Requested slew is bounded to +/-500 ms.
Uncorrected offset is sample offset minus the requested correction, not proof
that the asynchronous adjustment completed. Preserve sample timestamps on stale
samples; no synchronization or remote-delivery acknowledgment is provided.
Missing or invalid NTP samples do not stop the worker, including after three
failed polling rounds. While `state: "running"` and `sample_status: "unavailable"`,
render the row's `error` as a non-blocking time-sync warning, not a failed
configuration read or a global editing lock. Keep configured servers visible
from `GET /api/v1/services/ntp`; an unavailable sample is not an empty server list.
Continue status polling; the next accepted sample clears the warning. Other
configuration reads, staging and confirmation remain available when no genuine
backend error exists. Startup, socket I/O and clock-adjustment failures remain
visible service errors and automatically retry; they are not configuration-health
gates. Existing drift, authorization and transaction recovery guards still apply.
Syslog keeps local capture and reachable destinations running while unavailable
destinations reconnect independently (1..30-second exponential backoff, reset on
successful write). Optional numeric counters `captured_records`,
`forwarded_records`, and `failed_deliveries` count locally captured records,
records successfully written to every destination, and missed per-destination
sends respectively, since the latest execution attempt. `destination_errors`
is an optional `string[]` of active destination warnings, empty after recovery;
the row can be `running` with an `error`. No delivery acknowledgment or replay
of missed records is provided. Render failures as service-local warnings.
Poll visible status at the existing non-overlapping 2-5 second cadence.
Failures do not rewrite desired enabled settings or create drift by themselves.

Stage and review normally; confirmation/rollback/restore requires changed-area
permissions. Repair is explicit, confirmed, revision-free, uses stored settings,
and requires permissions for all enabled services. It never applies a draft.
Preserve drafts on 403/409/422/500; expose validation/runtime errors. Existing
401/403/404/405 and transaction revision/recovery behavior applies.

Operator prerequisites are not API settings: `--allow-host-services` or
`NETCONTROL_ALLOW_HOST_SERVICES=true` (set by current install/full upgrade scripts),
namespace/host capabilities, exclusive host-service ownership, journald forwarding for syslog, trust bundle,
host DNS/routing, and stopping competing clock/logging services. No packages,
arbitrary commands, OpenRC service management, or host-network edits are exposed.
Ubuntu install/full source-upgrade scripts configure `ForwardToSyslog=yes`,
`MaxLevelSyslog=debug`, `ReadKMsg=yes` and `netcontrol-syslog.socket`, and stop/mask
common competing syslog receivers. They preserve journald and its `/dev/log` input.
Build-only and API/package upgrades do not provision this setup. Saved
syslog settings remain unchanged: disabling native syslog stops forwarding, not
local journald capture. The bounded receiver queue may retain messages while
disabled and forward them on enable; overflow/daemon restart may lose them.
Capture/rate limits/forwarding settings determine coverage; a running worker is
not evidence of complete capture or delivery. Enabled native syslog without the
inherited socket fails preflight explicitly (HTTP 500 on transaction apply under
the existing error mapping), before service workers are stopped for that apply.
Malformed activation/socket state can fail daemon startup. Custom receivers
must release `/run/systemd/journal/syslog`; no socket is stolen or unlinked by
the worker. See [deployment and recovery](docs/BUILD_AND_INSTALL.md#host-logging-ownership).
Frontend syslog help and status source labels must describe journald, not direct
`/dev/log`, `/dev/kmsg` or backend-file capture. Do not offer host process-control
actions or automatically retry writes after a failed rollback.
Direct/manual host clock/logging/statistics deployments retain explicit opt-ins
even when native networking uses the host namespace. Host-network management alone does not authorize
clock adjustment or take ownership from competing services.

Settings persist through transactions/revisions/restart; traffic histories survive
graceful stop/repair. Traffic identity includes boot/namespace/interface identity.
No history is automatically deleted. Abrupt
kill can lose unsaved samples and leave ownership requiring operator recovery.
Simulator status is simulated without processes, time changes, or real history.

#### Native traffic history

Authenticated `state.read` GET `/api/v1/statistics/vnstat` returns one host-wide
database. The former `/host` and `/managed` suffixes are removed (`404`).
No query parameters are supported (`400`); unknown suffixes are `404`,
non-GET methods are `405`. Disabled, failed, not-yet-ready or simulator collectors
return `503`, never fabricated measured empty data. No `scopes` wrapper or
opaque native scope decoration remains; `scope` is the literal `"host"`.

```ts
interface TrafficCounts {
  rx_bytes: string; tx_bytes: string; rx_packets: string; tx_packets: string;
}
interface TrafficPeriod { date: string; counts: TrafficCounts }
interface TrafficInterface {
  ifindex: number; boot_id: string; namespace_id: string;
  last: TrafficCounts; total: TrafficCounts;
  day: TrafficPeriod; month: TrafficPeriod;
  resets: number; last_seen: Timestamp; present: boolean;
}
interface TrafficDatabase {
  schema: "netcontrol-services/counters/v2";
  scope: "host";
  interfaces: Record<string, TrafficInterface>;
  history: { collected_at: Timestamp; interface: string; delta: TrafficCounts; reset: boolean }[];
  last_report_date: string | null;
  last_report_error: string | null;
  sent_datagrams: string;
  failed_datagrams: string;
}
```

Counter and datagram strings are unsigned decimal integers; preserve them
losslessly. Day dates are `YYYY-MM-DD`; month dates are `YYYY-MM` in the host's
local calendar. Interface discovery samples every host interface every 5 seconds,
including unmanaged, down, VLAN, tunnel, veth and loopback interfaces. Removed
interfaces remain with `present:false` and are not exported.
The first sample establishes a baseline; it is not previous lifetime usage.
Only the latest 10,000 per-interface history records are retained, while
cumulative totals persist; removed interfaces and reset boundaries remain visible.
Daily/monthly buckets retain the current periods independently of history pruning.
Polling deltas belong to the calendar period in which they are observed; midnight,
restart and reset accounting is approximate. Initial/partially observed days are
not complete historical usage. Do not sum overlapping interfaces.

`vnstat.collector` is null (default: collection only) or a literal IP:port
UDP destination, port 1..65535. No DNS, multicast, unspecified or IPv4 broadcast
destinations; IPv6 destinations require global IPv6 enabled. Validate even when
disabled. Edit only on the owning traffic-accounting service form; preserve
metadata. Transactions require existing `transactions.write` and `vnstat.write`.
At the first sample in local **23:59**, attempt one datagram per present interface:
`hostname.domain|1;interface;YYYY-MM-DD;day_rx;day_tx;day_total;day_rate;YYYY-MM;month_rx;month_tx;month_total;month_rate;total_rx;total_tx;total_bytes\n`.
This is the 15-field human-readable `vnstat --oneline` version-1 layout, with
IEC byte units and decimal bit/s rate units. The prefix uses committed
`system.hostname` and `system.domain`: for example, `firewall` and `example.test`
produce `firewall.example.test|`. An empty domain sends hostname only, without
a trailing dot. When hostname is empty/unmanaged, use the current kernel
hostname; if appending a configured domain, use its first label so an existing
OS suffix is replaced rather than duplicated. No resolver lookup or kernel/NIS
domain is used. Domain/name changes reach the existing worker on the next engine
tick (normally within about a second), only after confirmation, including after
restart with a pending transaction. They do not restart accounting, reset
counters/history or trigger an extra daily report. All interfaces in one attempt
use a single identity snapshot. The final name is limited to 253 characters;
invalid/overlong effective kernel-name/domain combinations produce an explicit
non-blocking `last_report_error`, not a truncated name or hostname-only fallback.
Each interface is its own UDP datagram. The final minute after sampling is omitted
from that day's report; accounting continues normally through midnight. The host
local timezone is used; restart the daemon after host timezone changes to refresh
libc's timezone cache. No backfill when the reporting minute is missed, no durable
delivery queue/acknowledgment, and no fabricated zero fallback for unavailable data.
Genuine observed zero usage is valid. `sent_datagrams` means local socket acceptance,
not delivery. `last_report_error` is a non-blocking reporting warning; collection
continues. Socket/setup failures retry within that minute; per-interface send
failures are counted without blocking other reports. Persisted date suppresses
repeat daily attempts across normal restart; a crash between send and persistence
can duplicate a report. Collector deduplication should use reported name/interface/date;
adding/changing a domain changes that identity and may create a new collector
device. Preserve existing collector history; no backend migration or duplicate
short-name report is provided.
Datagrams are plaintext and unauthenticated, as with the supplied shell reporter;
restrict collector/network access. No implicit firewall permits are installed.

Storage is `traffic-host-v2.json` in the existing service-state directory.
Prior v1 accounting files are retained, not migrated/reset/deleted. If a prior host
v1 file exists without v2, collection reports an explicit operator-archival error;
starting a new baseline requires an explicit operator decision, not an automatic
rewrite. Corrupt/incompatible v2 and unresolved pending snapshots also remain
explicit errors in the accounting worker's retrying status, not daemon-startup
failures or global configuration locks. Disabled accounting does not read these
files. Retired v1 files are never decoded as v2; a retained managed v1 file does
not participate in host-only accounting. Existing statistics unavailability
remains `503`. This is format-compatible output, not vnStat database compatibility.

### Platform Health And Active Alerts

HTTP `GET /api/v1/state` and `GET /api/v1/runtime` include top-level
`process_health` and `active_alerts` alongside their existing fields. These are
ephemeral runtime observations, **not** fields inside `desired`, persisted
configuration, drafts, revisions or transaction candidates. Do not copy them
into configuration submissions. They do not create drift or change revisions.

`GET /api/v1/platform/status` returns only `{process_health, active_alerts}` from
the same cache, independent of the networking engine lock and network
observation. Use it when configuration observation fails or is busy. Existing
API-key authentication and `state.read` are required (`401`/`403`); GET only
(`405`), no query parameters or nonempty body (`400`). Successful reads are
`200`, no-store, including unhealthy/unknown snapshots. Authentication storage
failure can still return `503`; no unauthenticated diagnostics are exposed.
Existing genuine errors from state/runtime reads are not converted into fake
successful configuration reads. Service reconcile responses need not contain
the daemon-enriched fields; the GET responses above do.

The monitor samples approximately every two seconds after completed engine
deadline ticks. `process_health.status` is `healthy`, `degraded`, `unhealthy`
or `unknown`; `healthy` is respectively `true`, `null`, `false` or `null`.
Use `status` to distinguish a known degraded condition from unknown health.
Known component states
`running`/`current` are healthy, `error`/`stopped`/`unavailable`/`reconnecting`
are unhealthy at the component level. Discord's `ready` and `paused` states are
also healthy: the notification worker is operational, not proof that any
particular webhook delivery succeeded. These classifications are specific to
Discord, not other components. A failed component with `retrying:true` produces
aggregate `degraded`, rather than `unhealthy`, unless another non-retrying
component has failed. Dynamic DNS update failures are retrying because the
running manager schedules the next update; a stopped manager is reported
separately. Unknown component states take precedence over degraded; a failed
non-retrying component takes precedence over both. Missing native runtime or a
stale sample still makes the aggregate unknown.
Disabled/simulated/waiting/unmanaged components are not failures;
other unmeasured states make the aggregate unknown. Missing native runtime
makes the aggregate unknown and preserves previously observed native failures
until a successful observation can clear them. This is local execution/status
health, **not** proof of synchronized time, packet forwarding or remote delivery.
A running NTP worker with unavailable samples is healthy with a warning alert.
Disabled/simulated services do not raise sample/capture-statistics alerts merely
because statistics are unmeasured or incomplete. Explicit service errors remain
visible; running services still report unavailable accounting and capture loss.

`collected_at` is RFC3339 UTC or null before observation. `stale` becomes true
after 15 seconds without a completed health collection (monotonic timeout);
aggregate/daemon health becomes unknown, not stale success, and a
`monitor_stale` alert appears. Initial unsampled health is unknown. Optional
`runtime_available` says whether the latest native runtime collection succeeded.
Optional `daemon` reports the real PID, local state/health, sampled uptime in
seconds and whether systemd watchdog configuration was detected. `components`
contains stable IDs, component/resource identifiers, actual source state,
nullable health, retrying flag and last-observed timestamp. Counters/states are
snapshots; a cached running state is not independent proof of ongoing work.

Covered sources: native appliance workers, relay/export/probe workers, DHCP
client errors, MQTT, Dynamic DNS, host hostname/timezone status, and completion
of the three daemon-owned manager tasks. Current errors, unavailable samples,
unhealthy gateway reports and incomplete capture/warnings become alerts; no
new CPU/RAM/temperature thresholds or arbitrary health policy are introduced.

Each active alert has stable `id`, `component`, nullable `resource`,
`severity: warning|error`, machine-readable `code`, sanitized `message`,
`retrying`, `first_seen_at`, `last_seen_at`. UTC timestamps can be null when
unavailable. IDs combine source/resource and condition, not error text; repeated
failures preserve first-seen time. Alerts clear on observed recovery, not on
failed collection. Known codes are `worker_unavailable`, `service_warning`,
`runtime_unavailable`, `monitor_stale`, `health_unavailable`; accept future codes.
Raw backend errors, URLs, credentials and provider responses are not copied
into alert messages. No alert persistence, history/acknowledgment, notification
preferences or dismiss action. Restart begins a new observation history.

Render the aggregate and per-component states, freshness and active alert list;
continue non-overlapping 2..5-second polling. Preserve drafts and configuration
access: health labels and alerts are **observations only**, never write locks,
rollback triggers or reasons to stop healthy workers. Existing authorization,
configuration validation, genuine network drift and durable recovery guards stay.

### 6.1.4 Home Assistant MQTT Streaming

Provide API-managed settings in the shared configuration draft. This is outbound
telemetry, not remote control or individual-probe history. Previously no MQTT
configuration, publisher or password/status API existed. No CLI credentials or
inline `config.mqtt.password` are accepted.

Optional `config.mqtt` normalizes in responses to these defaults:

```json
{"enabled":false,"endpoint":"","username":"","password_ref":"","source_interface":"","interval_seconds":60}
```

| Field | Type and Validation |
| --- | --- |
| `enabled` | Boolean global streaming switch, default false. |
| `endpoint` | String, max 1024 UTF-8 bytes; `mqtt://host[:port]` or `mqtts://host[:port]`, default ports 1883/8883, explicit port 1..65535. Host required, no credentials, non-root path, query or fragment; nonempty values validate even when disabled. IPv6 literals require enabled IPv6. |
| `username` | String, max 256 UTF-8 bytes, no controls; default empty. Empty username/reference supports anonymous authentication. Username with empty reference sends an empty password. |
| `password_ref` | String, empty or exactly 32 lowercase hex characters; a nonempty reference requires username and a locally stored password, even when disabled. Never plaintext. |
| `source_interface` | String, empty or valid Linux interface name; enabled streaming requires an up managed interface of this name. Binding fails closed. Hostname DNS still uses the host resolver, not this binding. |
| `interval_seconds` | Integer seconds, default 60, inclusive 10..3600. |

All fields are non-null. Unknown keys/wrong types/null return `400`; semantic
validation, missing credential references and unsupported enabled namespace mode
return `422`. Changes require `transactions.write` plus new `mqtt.write` and any
other changed-resource grants. Normal transactions, confirmation, rollback,
revisions and restoration carry these settings. Publishing uses confirmed saved
settings only, never an unconfirmed draft.

Exact new endpoints, API-key Bearer authentication, no query parameters:

| Method and Path | Permission | Success |
| --- | --- | --- |
| `POST /api/v1/services/mqtt/passwords` | `mqtt.write` | `201 {"password_ref":"0123456789abcdef0123456789abcdef"}` |
| `GET /api/v1/services/mqtt/status` | `state.read` | `200` status below |

Upload body is strictly `{"password":"synthetic-example-only"}`: 1..4096 UTF-8
bytes, no NUL or additional fields. Password is write-only: no read/list/delete
API, echo or ordinary configuration/history value. Replacement creates a new
immutable reference. Owner-only files are plaintext at rest, not encrypted;
limit 256 passwords, no automatic pruning because revisions retain references.
Uploads during transaction/recovery/maintenance return `409`. Invalid body/query
is `400`, absent/bad key `401`, insufficient grant `403`, wrong method `405`,
unavailable manager/storage or exhausted limit `503`. Use normal API error envelopes.

Synthetic status example:

```json
{"device_id":"0123456789abcdef0123456789abcdef","enabled":true,"state":"reconnecting","error":"MQTT connection reset by peer","last_published_at_unix":1792800000,"connection_attempts":3,"reconnect_count":3,"last_connected_at_unix":1792800000,"last_failure":{"category":"connection_reset","message":"MQTT connection reset by peer","os_error_code":104,"at_unix":1792800060}}
```

`device_id` is a stable private-store identity string. `enabled` reflects confirmed
settings after worker observation; startup may briefly report disabled. `state`
is `disabled`, `connecting`, `running`, `reconnecting`, `error`, `simulated`,
`unavailable` or `stopped`. `error` is a nullable redacted string.
`last_published_at_unix` is nullable integer UTC Unix seconds, updated after broker
acknowledgment of a batch, not Home Assistant ingestion; its last value can remain
after disable/failure. Poll every 5..10 seconds on the settings screen.

Reconnect diagnostics are read-only at `GET /api/v1/services/mqtt/status` with
the same `state.read` permission:

| Field | Type and semantics |
|---|---|
| `connection_attempts` | Nonnegative integer, initially 0; increments immediately before each session attempt, including configuration-driven new sessions. |
| `reconnect_count` | Nonnegative integer, initially 0; increments for each failed session/connection attempt that schedules a retry, including failures before connection. Not a count of successful reconnects. Orderly disable/configuration changes do not increment it. |
| `last_connected_at_unix` | Nullable integer UTC Unix seconds; latest successful broker CONNACK, not proof of an acknowledged telemetry batch. |
| `last_failure` | Nullable object; most recent retry-triggering failure, retained during retries, recovery, disable and managed-worker stop/restart. |
| `last_failure.category` | Nonnullable allowlisted string listed below; machine-readable cause, not arbitrary library text. |
| `last_failure.message` | Nonnullable credential-safe diagnostic string. Render as text. |
| `last_failure.os_error_code` | Nullable signed integer OS error number for a network I/O failure; platform-dependent, not a broker MQTT return code. |
| `last_failure.at_unix` | Nonnullable integer UTC Unix seconds when the failure was observed; not necessarily when physical connectivity was lost. |

Counters saturate at the unsigned 64-bit maximum. Diagnostics are daemon-lifetime
memory, not configuration/history or on-disk state; a daemon process restart
resets counters to 0 and nullable diagnostic fields to null. Retained
`last_failure` is historical, not a current alarm when `state` is `running`.
The current `error` now reports a specific safe reason rather than the previous
generic connection-unavailable message. It remains visible during the next
`connecting` attempt and clears on CONNACK, successful publication, disable or
stop. Collection errors still use the existing `error` state without incrementing
reconnect counters or replacing retry history.

Failure categories:
- Broker response: `authentication`, `authorization`, `client_id`,
  `broker_unavailable`, `protocol`.
- Transport/timeouts: `connection_refused`, `connection_reset`,
  `connection_closed`, `network_timeout`, `network_unreachable`, `network_io`,
  `connection_timeout`, `write_timeout`, `keepalive_timeout`,
  `publication_ack_timeout`.
- Local/TLS/worker: `source_interface`, `permission_denied`, `credentials`,
  `configuration`, `tls_configuration`, `tls`, `tls_certificate`, `packet_size`,
  `discovery_manifest`, `client_channel`, `worker`, `internal`.

The daemon emits one warning per failed attempt with only the same allowlisted
category/message and optional OS code. Neither the status diagnostics nor these
warnings include endpoint URLs, usernames, password references, passwords,
packet bodies, peer-provided text or raw library error chains. DNS/unknown I/O
failures may be grouped as `network_io`; a peer close/reset does not prove an
ACL rejection or duplicate client ID. Broker logs may still be needed to
distinguish those causes. MQTT 3.1.1 does not provide publication-rejection reason
codes: `publication_ack_timeout` identifies the observed missing acknowledgments,
not an asserted ACL or packet-size cause.

Frontend workflow: masked replacement input, never prefilled from the reference;
upload first, save only the reference in the shared draft, then submit
`POST /api/v1/transactions`, confirm via
`POST /api/v1/transactions/{id}/confirm`, or roll back via
`POST /api/v1/transactions/{id}/rollback`. Existing `202` submit, `200` confirm/
rollback and conflict/error behavior remain. New settings also appear in
`GET /api/v1/state`, transaction/revision reads, and
`POST /api/v1/revisions/{revision}/restore`. Clear plaintext after upload and on
error/dismiss; keep it out of logs, exports, URLs and persisted drafts. Discarded
uploads still consume the private-store limit. Show the global toggle and
connection/last-publish status without claiming Home Assistant verified ingestion.
Show the safe current reason and historical last-failure category/time, attempts,
retry count and last broker connection. Keep historical failures visibly separate
from current errors; do not hide them whenever the next attempt starts.

Publisher and deployment contract:

- Linux native host mode only. Simulator reports `simulated` without network I/O;
  namespace lab mode rejects enabled streaming. Host routing/DNS, interface-binding
  privileges, broker reachability and firewall permission are operator prerequisites.
- Persistent MQTT 3.1.1, keepalive 30 seconds, clean session, five-second connection
  timeout and five-second reconnect delay, retried indefinitely while enabled.
  The TCP connection stays open between samples. Outstanding QoS-1 publications
  with no acknowledgement progress for 30 seconds also trigger reconnect and
  fresh discovery/state, not offline sample replay. Existing `reconnecting` status
  and redacted errors apply; no additional frontend controls are required.
  `mqtts` requires system trust and valid
  certificate/hostname; no insecure bypass. Explicit `mqtt` is plaintext. Upload
  passwords over protected HTTPS or a trusted management channel.
- Device discovery at
  `homeassistant/device/netcontrol_<device_id>/config`;
  complete samples at `netcontrol/<device_id>/state`; availability at
  `netcontrol/<device_id>/availability`. QoS 1; discovery/availability retained,
  samples nonretained. Broker ACLs must allow these publications and subscription
  to `homeassistant/status`. Birth `online` refreshes discovery/sample within
  five seconds when idle. LWT is retained `offline`; graceful stop/disable attempts
  offline/disconnect within three seconds. Broken sockets rely on broker LWT.
- Discovery contains shared device/origin/availability metadata, `qos: 1`,
  `state_topic: "netcontrol/<device_id>/state"` and a `components` mapping.
  Each component keeps `platform: "sensor"`, its stable `unique_id`, template,
  units/classes and expiry. Only changed discovery is sent between samples;
  reconnect and Home Assistant birth resend it. Removal publishes a bounded
  device-discovery update containing platform-only entries for removed components,
  followed by the current complete discovery without those entries. The durable
  manifest finalizes only after batch acknowledgments; interrupted removals can
  repeat. Failed enumerations retain prior discovery, not invented measurements.
- Every sample is one complete JSON object containing `collected_at_unix`
  (Unix seconds), all `metrics`, and structured `bgp`, `link_diagnostics`,
  `process_health`, `active_alerts`, `statistics_available` and `telemetry_sources`.
  Their types, exact counter strings, nullability and content are unchanged.
  No shard assembly is needed; no `/state/metrics/*` or `/state/<section>` is
  published. Delivery is QoS 1 and can duplicate. One message carries the full
  sample, but source reads still are not an atomic kernel snapshot.
  Availability `online` is queued after the state message.
  `last_published_at_unix` advances only after the whole batch is acknowledged.
- **Breaking deployment requirement:** update broker ACLs for
  `homeassistant/device/netcontrol_<device_id>/config` and
  `netcontrol/<device_id>/state`, preserving availability and birth access.
  Stop/disable the publisher and have the broker administrator clear each former
  retained `homeassistant/sensor/netcontrol_<device_id>/<component_id>/config`
  with an empty retained publication on that exact topic before enabling device
  discovery; do not publish to wildcards or clear the new device-discovery topic.
  No dual old/new topics,
  automatic broker-state conversion or schema migration. Keep the private store,
  device ID and secret references. Home Assistant rediscovery and entity-registry
  continuity must be verified; unique IDs alone do not prove customization
  preservation across discovery methods.
  Brokers must allow 33,554,432-byte payloads and MQTT packet overhead
  (at least 33,558,528 bytes for a configured packet cap). For Mosquitto, review
  `message_size_limit` and `max_packet_size`; also review broker/subscriber memory
  budgets. Only the daemon outbound packet cap increases; inbound stays 1 MiB.
  Broker acknowledgments alone do not prove Home Assistant ingestion. See
  [handoff 2026-11-06-07](docs/frontend-handoffs/2026-11-06.md#2026-11-06-07-consolidated-mqtt-with-32-mib-payloads).
- Stable name-hashed sensor IDs and durable component-removal manifest.
  Component IDs preserve case and contain 1..128 ASCII letters/digits/underscores;
  reads and writes apply the same validation, with at most 8192 manifest entries
  and a 1 MiB file limit. Generated mixed-case protocol IDs are valid and do not
  require deleting/recreating private state. Entities:
  configuration revision, uptime, version; interface link state and all exported
  64-bit link counters (RX/TX bytes/packets/errors/drops, multicast, collisions,
  RX length/overrun/CRC/frame/FIFO/missed/no-handler/other-host drops, TX aborted/
  carrier/FIFO/heartbeat/window errors and RX/TX compressed packets); gateway
  health/process/sample state, retry/restart counts, start/sample/last success/
  health-change timestamps, variation-pair counts, window sent/received/
  lost/pending/loss percent and RTT min/max/average/stddev/p50/p95/variation.
  These are rolling summaries, not individual probes/cumulative probe totals.
  Counter decimal strings remain lossless; stale/unavailable values are unknown,
  not zero. For sensors with units or a state class, discovery templates render
  null or missing metrics as Home Assistant's `None` sentinel, not the literal
  `unknown` string that numeric sensors reject. The state payload still carries
  JSON null (or omits a retained-source metric); it does not contain fabricated
  zeroes or string sentinels. Text sensors retain their `unknown` fallback.
  Valid zero, fractional/negative readings and exact 64-bit counter strings
  pass through without numeric coercion. Corrected discovery is reannounced
  through the existing startup/reconnect/birth workflow; old per-sensor discovery
  conflicts remain a separate broker-administrator cleanup concern.
  Software version is the embedded public date version, independent
  of Cargo's internal package version. Configuration revision is also a
  date-version string, not a numeric counter.
- Host health sensors, read from the same snapshot as `GET /api/v1/statistics/host`
  on each sample (`state.read`; scope is the daemon's host, not the lab namespace):
  fixed entities `memory_total_bytes`, `memory_available_bytes`, `memory_used_bytes`,
  `swap_total_bytes`, `swap_used_bytes` (B), `load_1m`/`load_5m`/`load_15m`,
  `host_uptime_seconds`, `oom_kills` (cumulative), and PSI 10-second averages
  `pressure_cpu_some`, `pressure_memory_some`/`_full`, `pressure_io_some`/`_full` (%).
  Dynamic entities, one per item, keyed by a hash of the identity: **per CPU core**
  busy percent plus a total (`cpu`), **per thermal zone** temperature (°C), **per
  hwmon temperature/fan sensor** (°C or RPM) and **per local filesystem mount**
  total/used/available bytes. CPU busy percent is computed by the daemon from tick
  deltas between consecutive samples as specified above (guest ticks not
  double-counted); the first sample after (re)connect, a boot change, a counter
  decrease or no elapsed ticks is unknown. Entity names are stable and
  id-based (`thermal_zone0 temperature`, `coretemp hwmon2/temp1`): sensor
  type and label are not shown, rename entities in Home Assistant. Zero fan RPM and
  negative temperatures are real readings; a failed section, sensor or filesystem is
  unknown, never zero. When a whole section cannot be enumerated its existing
  entities are kept (unknown, expiring) rather than removed. Caps: 256 CPU rows,
  64 thermal zones, 128 hwmon sensors, 64 filesystems (first in snapshot order);
  extras are ignored. A host snapshot that fails to read leaves these
  sensors unknown without failing the sample. Additional host metrics:
  - Other exported memory byte gauges (`memoryfield`, up to 128 memory fields
    examined, including free/cache/buffers/slab/dirty/writeback); existing total/
    available/swap-total aliases are not duplicated.
  - `vm_pgpgin`/`vm_pgpgout` (KiB), `vm_pswpin`/`vm_pswpout` (pages),
    `vm_pgfault`/`vm_pgmajfault` (faults), cumulative, alongside `oom_kills`.
  - `scheduler_ctxt` and `scheduler_processes` (cumulative), plus
    `scheduler_procs_running`/`scheduler_procs_blocked` (gauges), and
    `load_runnable_tasks`/`load_total_tasks` (task gauges).
  - `host_idle_seconds` (cumulative CPU idle time across cores, s), filesystem
    `free_bytes`, total/free/available inode gauges and `read_only` state, in
    addition to the existing filesystem total/used/available bytes.
  - All supported PSI categories now include `avg10`/`avg60`/`avg300` (%) and
    cumulative `total` (microseconds), with keys `<section>_<category>_<field>`.
  - Per-disk (`disk`, disk name identity) reads/writes/discards/flushes completed,
    merged reads/writes/discards, sectors read/written/discarded, read/write/
    discard/flush milliseconds, I/O milliseconds and weighted I/O milliseconds
    (cumulative), and `io_in_progress` (gauge). Linux sectors are 512 bytes, not
    device logical-block sizes; MQTT preserves sectors rather than silently
    converting them. Optional kernel fields stay unknown when absent. Cap:
    first 64 disk rows; `disk_statistics_truncated` reports overflow, retaining
    any existing omitted disk entities as unknown rather than removing them.
  - `host_section_<section>_status` preserves available/partial/unavailable/
    simulated section status. Unsupported/read-failed sections are not measured
    zero. Additional memory/disk entities are retained on enumeration failure.
- NetFlow/IPFIX sensors, one set per **configured** `softflowd` instance (enabled or
  not), read from `GET /api/v1/services/softflowd/status` on each sample and keyed
  by a hash of the instance name: `state` (`running`, `stopped`, `disabled`, `error`,
  ...), `statistics_complete` (false once the kernel has dropped any capture
  packet until the worker restarts), `dropped_packets` (kernel capture-socket drops,
  exact decimal string, cumulative since worker start), `active_flows` (gauge),
  `exported_flows`, `excluded_packets`, `filtered_packets` and `malformed_packets`
  (cumulative). Counters reset when the worker restarts. A stopped, disabled or
  just-started worker has no counters and they are unknown, never zero; the
  counters other than drops appear after the first table scan. No entities exist
  while no instance is configured; if the status read fails the existing entities
  are kept (unknown, expiring). Names are `<name> flow dropped packets` etc. Cap:
  64 instances. `running` is local worker health, not collector delivery; see
  [docs/NETFLOW_IPFIX_SPEC.md](docs/NETFLOW_IPFIX_SPEC.md) section 5.
- Additional bounded monitoring families use these discovery/state topic families,
  QoS, expiry and credentials. IDs are `<kind>_<sha256(identity)>_<field>`:
  - **Kernel protocols** (`protocol`, identity `<source>/<group>`): all numeric
    SNMP/netstat/SNMP6 counters, including IPv4/IPv6, TCP/TCP extensions, UDP and
    ICMP/type counters. Exact decimal strings, cumulative; TCP `CurrEstab` is a
    gauge and octet counters use B. Configuration constants (`Forwarding`,
    `DefaultTTL`, `RtoAlgorithm`, `RtoMin`, `RtoMax`, `MaxConn`) are excluded.
    Per-source status has identity `<source>`, field `status`.
  - **Native services** (`service`, identity service name, or
    `udp-broadcast-relay:<instance_id>`): process state, retry/restart metadata,
    start/sample timestamps, sample status where supported and `error_present`
    (presence of a reported current/last error, not an assurance of health).
    NTP exposes discipline and available offset/delay/requested-slew/uncorrected
    offset in ms. Syslog exposes cumulative captured/forwarded/failed-delivery
    counts and a destination-error count, not messages or destination details.
    mDNS/UDP relay expose their supported receive/transmit packet/byte, policy/
    loop/duplicate/hop-limit/queue/oversize/unsupported-record/malformed/
    rate-limit/receive-drop/send-error
    counters and `statistics_complete`. Unsupported receive-loss accounting is
    null/false, not proof of no loss. Worker counters are unknown unless running;
    mDNS/UDP relay additionally require a completed sample. Failed NTP sampling
    masks prior offsets rather than publishing stale good values.
  - **DHCP**: `dhcprelay` identities are interface names, with state/retry/restart/
    start metadata. `dhcpclient` identifies each interface with an observed lease
    or error: `lease_valid`, `error_present`, `acquired_at` (Unix s), `lifetime`,
    `renewal`, `rebinding` (s) and `expires_at_unix` (Unix s). No leased addresses,
    DNS/search-domain values, DHCP packet inventory or error strings are copied.
  - **WireGuard** (`wgpeer`): per-interface `peer_count`; per-peer `rx_bytes`/
    `tx_bytes` (exact cumulative strings) and `last_handshake_unix_seconds`
    (nullable Unix s). Peer identity is `<interface>/<public_key>` before hashing;
    display names use the interface and a short hash. No key material, endpoints
    or allowed-prefix inventories are published.
  - **BGP**: `bgp` identity `bgp` exposes state/health, installed-prefix count,
    connected-prefix count, neighbor count and established-neighbor count.
    `bgppeer` identifies neighbor
    names: state, received/advertised prefix gauges, cumulative rejected-prefix
    count and nullable negotiated hold seconds. Transient/starting failures retain
    prior peer discovery with unknown measurements. The existing raw BGP summary
    remains; route/advertised-route tables are not added.
  - **vnStat**: the existing cached vnStat worker status supplies summaries without
    reading/serializing its persisted history. `traffic` identifies interface
    names: `present`, `last_seen`, cumulative `resets`, `total_rx_bytes`/
    `total_tx_bytes`/`total_rx_packets`/`total_tx_packets`, and matching `day_`/
    `month_` metrics plus `day_date`/`month_date`. Day/month totals are gauges,
    labeled by the worker's local calendar buckets, not running lifetime counters
    or a new MQTT history feed. Absent interfaces or unavailable workers have
    unknown totals. `service` identity `vnstat` also exposes cumulative
    `sent_datagrams`/`failed_datagrams`, `last_report_date` and `error_present`.
    Counters/report state retain the existing worker/persistence/reset semantics;
    sent datagrams do not prove external collector delivery.
  - **Software** (`software`, identity `release`): `latest_version`,
    `update_available` (nullable boolean), `last_checked_at` and `check_state`
    (`disabled|pending|succeeded|error`), from committed daemon-managed software
    metadata. Disabled/pending/failed checks remain unknown, not "up to date".
  - **Sando** (`sando`, identity `sync`): `enabled`, `state`, `last_attempt_at`,
    `last_success_at`, `next_sync_at`, `host_count`, `skipped_hosts`. Read-only
    projection of the current configured source's sync state: no source URL,
    errors, names, icons, classification, scores, addresses or raw hosts. The
    counts describe cached results, not a live network census; last success
    determines freshness. Disabled/failed sync can retain prior counts, while a
    source change hides the old source's results. The normal Sando API and hourly
    synchronization are unchanged.
  - **Firewall aggregate accounting only** (`firewall`, identity `accounting`):
    `generation`, `ruleset_id`, `logical_rule_count`, `rule_match_packets`,
    `rule_match_bytes`, **`dropped_packets` and `dropped_bytes`**. The latter sum
    actual managed input/forward DROP rules and global/host/input default DROP
    policies from `GET /api/v1/statistics/firewall`, classified against the same
    committed configuration captured under the engine lock. Accepts, bypasses,
    generated IPv4 ICMP exceptions and NAT matches are not drops; configured
    ICMP/ICMPv6 DROP rules do contribute. Deny-log rate limits/loss do not affect these
    kernel counters. Packet/byte values are exact decimal strings; counters reset
    on installed generation changes. They do not cover NIC errors, external
    firewall tables, other Linux drop sites or historical generations. Rule-match
    totals sum all accounted rows and can count a packet more than once; they are
    not unique traffic totals. No per-rule sensor, action/path/label inventory or
    raw rule-counter array is published. Unavailable/simulated counters are null.
  - Family limits fail collection explicitly: 1024 protocol counter fields,
    256 appliance-service rows, 256 DHCP relay/client identities, 128 BGP
    neighbors, 128 traffic-history interfaces and 128 WireGuard peers total.
    Existing host/NetFlow caps and the overall payload/entity limits also apply.
- The complete MQTT state payload carries the exact shared `process_health` object
  and `active_alerts` array. Home Assistant sensor metrics/discovery add
  `process_health` (`healthy|degraded|unhealthy|unknown`) and numeric `active_alert_count`.
  Alerts do not change MQTT transport availability: a connected publisher can
  publish unhealthy or unknown platform state. Broker disconnection still uses
  the existing offline last will; it cannot deliver alerts while disconnected.
- `statistics_available: boolean` distinguishes a partial sample when network
  statistics fail. Health/alerts and other available sensors still publish;
  existing interface/gateway entities are preserved to expire/appear unknown,
  not removed or fabricated as zero. A host-sensor failure remains unknown.
- `telemetry_sources` contains read-success booleans `network`, `protocols`,
  `host`, `services`, `bgp`, `firewall`, `sando`, mirrored by
  `source_<name>_readable` sensors. True means the source could be read, not that
  its workers/measurements are healthy or available (simulated/disabled/partial
  section states remain explicit). Independent failures do not suppress other
  available families/health/alerts; existing dynamic entities from failed
  enumerations are kept unknown, while authoritative empty enumerations remove
  obsolete entities. Protocol/BGP reads are independently attempted if aggregate
  network statistics fail. Engine-backed reads share one committed configuration
  lock; source timestamps are still independent, not an atomic kernel snapshot.
- Samples expire after three publication intervals. Active configuration/maintenance
  and unrecoverable collection failures pause samples with offline availability;
  the next successful sample restores availability. No offline backlog or command topics. Limits:
  4096 entities and 32 MiB (33,554,432 serialized UTF-8 bytes) per published
  discovery/state payload. Entity limits include health/source additions and
  merged retained discovery. If a complete discovery, complete state or discovery
  removal exceeds the cap, collection fails explicitly with payload class,
  serialized byte count and limit, not payload contents; no partial sample is
  enqueued and no values are truncated. Source failures/nulls and expiry can still
  cause unknown/unavailable entities; consolidation does not hide them.
  Raw connections, deny records, route tables, Sando inventory, secrets and vnStat
  history records are not added. No MQTT controls or automatic upgrades/sync
  triggers are introduced.
- Back up `<state>.mqtt` with the journal, preserving ownership/owner-only files,
  stable ID, passwords and manifest. Default
  `/var/lib/netcontrol/native-state.json.mqtt`. Never reset missing credentials,
  silently prune revision references or clone to another active appliance.
  Decommissioned Home Assistant entities/retained topics need operator removal.
- Deploy rebuilt daemon/dependencies/system CA trust; no sidecar MQTT process.
  Verify actual Home Assistant ingestion and trusted/untrusted TLS broker behavior
  on deployment; local protocol fixtures do not prove these integrations.

### 6.1.5 Azure Dynamic DNS

Implement an Azure public DNS IPv4 A-record settings screen in the shared
configuration draft. This is a new backend capability, not a pfSense-compatible
wire API. Only Azure public DNS is supported; no AAAA, wildcard, private DNS,
other providers, custom detector URLs, gateway groups or force-update endpoint.

`config.dynamic_dns` is an optional array, default `[]`, maximum 32 entries.
Canonical state/history/transaction responses include the array. Entries have
these **non-null, required** fields (only metadata has a default):

| Field | Type and Validation |
| --- | --- |
| `name` | Unique string, 1..64 ASCII letters/digits/underscore/hyphen; stable UI identity. |
| `enabled` | Boolean; disabling retains configuration and the Azure record. |
| `source_interface` | Valid Linux interface-name string; enabled entries require an up managed interface. |
| `address_source` | `"interface"` (direct public IPv4) or `"public_ip"` (NAT-aware IPv4 from fixed HTTPS ipify endpoint). |
| `tenant_id`, `client_id` | Azure tenant and application/client UUID strings, each 36 characters including hyphens. |
| `secret_ref` | Exactly 32 lowercase hexadecimal characters returned by secret upload; must exist locally even when disabled. No inline secret. |
| `zone_resource_id` | `/subscriptions/{UUID}/resourceGroups/{group}/providers/Microsoft.Network/dnszones/{zone}`; exact segment names, public zone only. Group 1..90 ASCII alphanumerics/`_.-()`, no trailing dot; zone lowercase DNS name with a dot, max 253 bytes, labels 1..63. |
| `record_name` | `@` for apex or lowercase relative DNS name with 1..63-byte alphanumeric/hyphen labels (no leading/trailing hyphen). No wildcard, trailing dot or FQDN equal to/ending with the zone; combined FQDN max 253 bytes. |
| `ttl_seconds` | Integer seconds, inclusive 30..86400. |
| `interval_seconds` | Integer seconds, inclusive 60..86400; no implicit interval/TTL defaults. |
| `metadata` | Optional standard `display_name`/`description` object; defaults empty; section 1.4 limits apply. |

Duplicate target A records are rejected (zone resource ID compared
case-insensitively, relative record name compared exactly), including disabled
entries. Other fields remain validated while disabled; interface existence/up is
required only when enabled. Wrong known types, nulls, missing entry fields and
invalid enum values return `400`; semantic bounds, missing secret references and
unsupported namespace-mode entries return `422`. Ordinary transaction `config`
unknown-field pruning/`ignored_fields` still applies (section 1.3), including
accidental inline `client_secret`; uploads and persisted data remain strict.
Never intentionally send an inline secret in a transaction.

Changes use existing `POST /api/v1/transactions` and
`POST /api/v1/transactions/{id}/confirm` or `/rollback`, with
`transactions.write`, `dynamic_dns.write` and any other changed-resource grants.
Existing `202` submit, `200` confirm/rollback, revision conflicts and restore
permissions remain unchanged. `GET /api/v1/state`, transaction/revision reads and
`POST /api/v1/revisions/{revision}/restore` carry references/settings, not secrets.
Native ownership projections exclude daemon-only Dynamic DNS settings.

New API-key-authenticated endpoints, with no query parameters:

| Method and Path | Permission | Success |
| --- | --- | --- |
| `POST /api/v1/services/dynamic-dns/secrets` | `dynamic_dns.write` | `201 {"secret_ref":"0123456789abcdef0123456789abcdef"}` |
| `GET /api/v1/services/dynamic-dns/status` | `state.read` | `200` status below |

Strict upload body: `{"client_secret":"synthetic-example-only"}`, 1..4096 UTF-8
bytes without NUL, no additional keys. Replace by uploading a new immutable secret
and putting its reference in the shared draft. Invalid body/query `400`, invalid
key `401`, insufficient permission `403`, active transaction/recovery/upgrade
upload `409`, wrong method `405`, unavailable storage/manager or exhausted
256-secret store `503`. Standard API error envelope and CORS apply. There is no
secret read/list/delete API; discarded uploads consume capacity. Clear plaintext
on upload completion/error/dismiss; never log it, export it or persist it in drafts.

Synthetic configuration fragment (not a complete transaction):

```json
{"dynamic_dns":[{"name":"azure-wan","enabled":true,"source_interface":"wan0","address_source":"public_ip","tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","secret_ref":"0123456789abcdef0123456789abcdef","zone_resource_id":"/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com","record_name":"home","ttl_seconds":300,"interval_seconds":60}]}
```

Synthetic status:

```json
{"entries":[{"name":"azure-wan","state":"current","address":"8.8.4.4","last_checked_at_unix":1792890000,"last_updated_at_unix":1792890000,"error":null}]}
```

Entries are sorted by name and represent confirmed settings after worker
observation (brief startup/configuration lag is possible). Join to the draft by
name without treating draft changes as active. `state` is `waiting`, `disabled`,
`paused`, `checking`, `current`, `error`, `simulated` or `unavailable`.
`address` is a nullable IPv4 string, the last successfully reconciled address;
timestamps are nullable integer UTC Unix seconds. `last_checked_at_unix` updates
on success or failure; `last_updated_at_unix` only after a successful Azure PUT
response confirms the requested IP/TTL. A GET finding the record already current
does not advance the update timestamp. Last address/timestamps may survive errors
or pauses; settings replacement resets that entry's status. `error` is a nullable
redacted string with stage/HTTP status, never upstream bodies/credentials/tokens.
`current` means Azure control-plane state, **not** recursive DNS propagation.
Poll every 5..10 seconds only while visible.

Frontend tasks: add types and list/editor with explicit per-entry enable,
interface selector, source-mode choice, tenant/client IDs, zone resource ID,
relative hostname/apex, TTL/interval and metadata; use masked replacement-secret
input. Upload first, save only reference, preserve entries in full-config
transactions/restores, display validation errors and unknown-field warnings.
Show per-entry errors/last-known timestamps, distinguish simulated/paused from
current, warn that disabling/deleting never removes DNS records and rollback
cannot undo external writes. Explain public-IP detection's third-party disclosure,
CGNAT/inbound limitations and DNS TTL/propagation.

Deployment/operator requirements:

- Linux host mode and privileged source-interface binding. Simulator has no
  external I/O; namespace lab mode rejects entries. The selected interface must
  have exactly one usable IPv4 (not loopback/link-local/unspecified), including
  DHCP-acquired addresses. Missing/ambiguous/down interfaces fail explicitly.
  Resulting published addresses must be public, not private, CGNAT, documentation,
  benchmarking, link-local, loopback, multicast or reserved ranges.
- `public_ip` uses `https://api.ipify.org` (64-byte bounded plain IPv4 response).
  Azure authentication uses `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
  with client credentials and `https://management.azure.com/.default` scope.
  ARM uses `{zone_resource_id}/A/{record_name}?api-version=2018-05-01` under
  `https://management.azure.com`. Public Azure cloud only.
- Verified TLS, no insecure bypass, redirects or proxies. All HTTP sockets bind
  the selected interface and IPv4 without another-WAN fallback; host-resolver DNS
  lookups are not interface-bound. Require working host DNS/routing/outbound HTTPS.
  Connect timeout five seconds, each request total timeout 15 seconds, Azure
  bodies bounded at 64 KiB. Checks are serialized and retried no sooner than the
  configured interval after completion; DNS changes are polling-based, not immediate.
- Assign the app service principal DNS Zone Contributor at the public DNS zone
  scope; enter client-secret **value**, not secret ID, and rotate before expiry.
  Records can be absent (created conditionally) or a singleton/empty A record set.
  Alias/multi-address sets are refused. Each check reads Azure, avoids unchanged
  IP/TTL writes, preserves metadata and uses If-Match/If-None-Match. Concurrent
  edits (`412`), throttling (`429`), expired secrets (`401`), permissions (`403`)
  and other failures surface as per-entry errors, then retry next interval.
- Only confirmed settings run; pending transaction/maintenance pauses checks and
  cancels work on the next one-second observation. Shutdown cancels requests and
  joins the worker. An already transmitted Azure PUT can still complete; no
  external DNS rollback, deletion or record restoration is attempted.
- Preserve `<state>.dynamic-dns` alongside journal backups (default
  `/var/lib/netcontrol/native-state.json.dynamic-dns`). Secrets are immutable
  owner-only plaintext files, not encrypted; no pruning while revisions may use
  them. Rebuilt backend and coordinated frontend deployment are required; do not
  reset state/credentials to accommodate the new fields.
- Local fixtures verify protocol and error behavior; live Azure TLS/RBAC, actual
  WAN/DHCP/NAT changes, recursive DNS propagation and appliance reboot remain
  deployment acceptance checks. See [operator setup](README.md#azure-dynamic-dns)
  and [handoff](docs/frontend-handoffs/2026-10-25.md#2026-10-25-01-azure-dynamic-dns).

### 6.1.6 Host name and time zone

`config.system` manages two appliance host settings (host name and time zone) and
stores one display/reporting label (domain). It is part of the shared
configuration draft and is always present in `GET /api/v1/state`, transactions and
revisions:

```ts
interface SystemConfig {
  hostname: string; // "" = unmanaged, else a lowercase RFC 1123 label
  domain: string;   // "" = none, else a lowercase DNS name for display/vnStat, not OS DNS
  timezone: string; // "" = unmanaged, else an IANA zone name
}
```

```json
{"system":{"hostname":"fw-1","domain":"home.example.test","timezone":"America/New_York"}}
```

There is no `metadata` on this object. Send the whole object (all three fields) like
every other section; an omitted `system` means everything is empty.

Validation (`422` on submit; the SSH `commit check` only validates syntax):

- `hostname`: empty, or 1..63 characters of `a-z`, `0-9` and `-`, not starting or
  ending with `-`. Uppercase, dots, underscores and spaces are rejected; the domain
  is a separate field.
- `domain`: empty, or a lowercase DNS name of dot-separated labels (each 1..63 of
  `a-z`, `0-9`, `-`, not starting or ending with `-`), at most 253 characters, no
  trailing dot, and not a bare IP address or all digits. `hostname` plus `.` plus
  `domain` must not exceed 253 characters. A single label such as `lan` is valid.
- `timezone`: empty, or at most 64 characters in at most three `/`-separated parts of
  letters, digits, `_`, `+` and `-` (`UTC`, `America/New_York`, `Etc/GMT+5`). Dots,
  `..`, empty parts and spaces are rejected.
- When the **timezone value changes**, it must also exist in the host's timezone
  database (`422`, "timezone is not available on this host"). Unchanged values are
  not rechecked, so unrelated edits still work if the database later disappears.
- Non-empty `hostname` or `timezone` values are rejected (`422`, "host system settings are unavailable for this
  backend") when the daemon cannot manage the host, such as a namespace lab.
  The simulator accepts any well-formed zone.

Permissions: `transactions.write` plus the new **`system.write`** for any change to
`config.system`. Scoped credential files must list `system.write`; device-account
keys have it automatically.

**When it takes effect.** Like MQTT and Dynamic DNS, `system` is daemon-owned and is
**not** part of the networking apply: it never changes the network, never delays
confirmation, and a rolled-back or unconfirmed transaction never touches the host.
Within about a second of confirmation the daemon applies the saved values. While
a transaction is pending, nothing is applied. The values are enforced: if another
agent changes them, the daemon sets them again (at most every 10 seconds); a failed
apply is retried every 30 seconds. **Clearing a value (empty string) stops managing
it and leaves the host as it is**; it does not restore the previous name or zone.

Host effects:

- `domain`: **display/reporting label.** It is stored and returned with the configuration so the UI
  can show a full name (`hostname.domain`), and supplies the vnStat collector
  report suffix described above. The daemon never applies it to OS settings: no host
  file, kernel domain name, resolver or DNS search domain is changed. It needs no host
  support, is accepted on any backend, and a change to it needs only `system.write`.
  Search domains remain `dns[interface].domains` and `dhcp_clients[].use_domains`.
- `hostname`: the kernel hostname and `/etc/hostname`. The daemon's syslog
  forwarding picks the new name up within a second. `/etc/hosts` is not edited, and
  the per-interface DHCP-client `hostname` is a separate setting.
- `timezone`: `/etc/localtime` becomes a symlink to the zone file, and
  `/etc/timezone` is rewritten only where it already exists. Processes that were
  already running may keep the old zone until restarted. API timestamps stay
  UTC, and NTP and the system clock are unaffected.

Read-only endpoints (`state.read`; no query parameters; `405` for other methods,
`401`/`403` as usual, `503` when the manager is unavailable):

| Method and path | Result |
| --- | --- |
| `GET /api/v1/system/status` | `SystemStatus`, the confirmed settings and what the host reports |
| `GET /api/v1/system/timezones` | `{"timezones":["America/Chicago","UTC",...]}` sorted valid zone names |

```ts
type SystemSettingState =
  | "unmanaged" | "current" | "applying" | "error" | "paused" | "simulated" | "unavailable";
interface SystemSettingStatus {
  configured: string;        // confirmed value, "" when unmanaged
  observed: string | null;   // what the host reports now; null when unknown
  state: SystemSettingState;
  error: string | null;      // set when state is "error" or "unavailable"
}
interface SystemStatus {
  hostname: SystemSettingStatus;
  timezone: SystemSettingStatus;
  last_applied_at_unix: number | null; // last time the daemon changed the host
}
```

```json
{"hostname":{"configured":"fw-1","observed":"fw-1","state":"current","error":null},
 "timezone":{"configured":"America/New_York","observed":"America/New_York","state":"current","error":null},
 "last_applied_at_unix":1792890000}
```

`current` means the host matches; `applying` is a short wait (for example after an
external change, before the daemon sets it again); `paused` means a transaction is
pending or an upgrade is running; `error` carries a message such as a missing
privilege or timezone database and is retried; `simulated` and `unavailable`
(namespace lab or non-Linux) never touch a host. `observed` is the kernel hostname,
or the zone name from `/etc/localtime` (null when it is not a link into the zone
database), and is also reported for unmanaged settings. The simulator returns a
fixed sample zone list; the native list is empty when the host has no timezone
database.

Frontend tasks: add `SystemConfig` and the status types; a hostname field with the
rules above and a timezone selector loaded from `/system/timezones` (disable it with
an explanation when the list is empty); show the status row with `observed`, `state`
and `error`; keep the empty value as an explicit "Unmanaged" choice and explain that
clearing does not revert; note that long-running processes may need a restart
for a new zone; submit through the normal draft, `commit` and confirm flow.

Operator prerequisites: Linux host mode with a daemon that may set the hostname
(root/`CAP_SYS_ADMIN`); the host's timezone database (the `tzdata` package; the daemon
installs nothing); no other hostname or timezone manager (cloud-init, a DHCP
hostname option, or a configuration tool) fighting the daemon. Local fixtures cover
this logic, but the real hostname and time zone behavior on an appliance is a
deployment acceptance check. See the
[handoff](docs/frontend-handoffs/2026-10-25.md#2026-10-25-10-host-name-and-time-zone).

### 6.1.7 Native mDNS / DNS-SD

Provide a **Services > mDNS / Discovery** editor using the shared full-config
draft, not independent immediate saves. The in-process Rust service is disabled
by default. It reflects discovery between eligible links; it is not an Avahi
process, a DNS resolver, SSDP relay, IGMP/MLD router or multicast media proxy.

```ts
interface MDNSConfig {
  enabled: boolean; // false
  metadata?: ObjectMetadata;
  interface_mode: "allow" | "deny"; // allow
  interfaces: string[]; // [], unique, at most 32
  ipv4: boolean; // true
  ipv6: boolean; // true
  reflection: { enabled: boolean; filters: string[] }; // false, []
  publishing: {
    enabled: boolean; // false
    hostname: string; // ""; use configured system.hostname when publishing
    domain: string; // "local."
    addresses: boolean; hinfo: boolean; workstation: boolean;
    browse_domain: boolean; aaaa_on_ipv4: boolean; a_on_ipv6: boolean;
    // All publication flags default false.
  };
}

type MDNSCounterName =
  | "received_packets" | "transmitted_packets" | "received_bytes"
  | "transmitted_bytes" | "malformed_packets" | "hop_limit_drops"
  | "policy_drops" | "duplicate_drops" | "rate_limit_drops"
  | "queue_drops" | "oversize_drops" | "unsupported_record_drops" | "send_errors";

interface MDNSFilterCounters {
  filter: string; // Applied canonical reflection filter, not an array index.
  matched_packets: string; // Exact unsigned decimal string.
  transmitted_packets: string; // Successful per-destination datagram sends.
  last_used_at: Timestamp | null; // Last admitted match; null before any match.
  last_transmitted_at: Timestamp | null; // Null before any successful send.
}

interface MDNSStatus extends Record<MDNSCounterName, string> {
  name: "mdns";
  scope: "managed";
  enabled: boolean;
  state: "disabled" | "simulated" | "running" | "stopped" | "error";
  started_at: Timestamp | null;
  collected_at: Timestamp | null;
  error: string | null;
  effective_interfaces: string[];
  effective_families: ("ipv4" | "ipv6")[];
  reflection_enabled: boolean;
  publishing_enabled: boolean;
  filter_counters: MDNSFilterCounters[];
  receive_drops: string | null;
  statistics_complete: boolean;
  warnings: string[];
  limits: Record<string, number>; // Exact fixed keys/bounds listed below.
}
```

`config.mdns` is always present in serialized configuration. Preserve it,
including metadata and disabled preferences, in drafts/import/export/history.
This feature uses the current transaction unknown-field/`ignored_fields`
contract; do not silently dismiss server warnings.

Membership/validation (`422` semantic errors):

- Eligible links are configured, administratively up `ethernet`/`vlan`
  interfaces with role `lan`. WAN, unassigned, unmanaged, loopback, WireGuard
  and dummy links never participate. Allow entries must be eligible; deny
  entries must identify configured Ethernet/VLAN links (excluding WAN is
  allowed but redundant). Names must be unique and references valid even
  while disabled. Eligibility uses each selected interface's own candidate
  `up`/`role` fields, not live discovery or the VLAN parent's settings.
  Allow-interface `422` errors include those candidate values in their text;
  retain that diagnostic context and do not parse error strings as state.
- Allow mode selects only listed links; empty never means all. Deny mode
  selects eligible links except those listed. Review newly included links when
  other configuration changes expand a deny-mode set.
- Enabled reflection requires 2..32 effective links; publishing alone requires
  1..32. Enabling mDNS requires at least one function and effective family.
  Each enabled family needs a usable local address on each selected link;
  bind/membership/address/ownership failures are explicit apply errors, not
  partial successful membership.
- Global `ipv6_enabled: false` suppresses IPv6 transport and **all local AAAA
  publication**, even AAAA-over-IPv4, while retaining saved mDNS preferences.
  An IPv6-only enabled configuration then fails validation. No packet-family
  translation is performed.
- Filters: empty means all services. At most 64 unique absolute local DNS
  names with a trailing dot, ASCII labels 1..63 bytes, total at most 253 bytes;
  normalize ASCII case. Accept service types such as `_ipp._tcp.local.`,
  DNS-SD subtype names, exact service instances such as
  `_udp._govee-lan._udp.local.`, and provider names such as `printer.local.`.
  An instance filter selects only that instance; `_govee-lan._udp.local.`
  selects all instances of the service. No glob, regex or arbitrary
  instance-name patterns. Editors may accept shorthand such as `_http._tcp`
  or `_http._tcp.local`, but must submit `_http._tcp.local.`; the API still
  requires canonical absolute names. Detect case-insensitive duplicates after
  editor completion (the same service with/without `.local.` is not unique).
  Filtering reconstructs mixed
  messages rather than forwarding an entire packet because one service matches.
- Publishing is separate and off by default. Enabled publishing requires a
  real publication flag. Hostname is a lowercase single hostname label of
  1..63 bytes (letters/digits/hyphens, no edge hyphen) or empty to use valid,
  nonempty configured `system.hostname`; never ambient host state.
  Domain is `local.` or an absolute subdomain, no underscores, at most 253
  bytes; generated host/workstation/enumeration names must also fit.
  Cosmetic `system.domain` never changes mDNS.
- `aaaa_on_ipv4` needs `ipv4` and `addresses`; `a_on_ipv6` needs `ipv6` and
  `addresses`. These flags choose published record types, not cross-family
  reflection. HINFO deliberately exposes Linux/architecture; workstation uses
  the conventional `_workstation._tcp` record/port 9. No SSH/SFTP/default
  management service is advertised.

HTTP methods, all with existing API-key authentication:

| Method / path | Permission / result |
| --- | --- |
| `GET /api/v1/services/mdns` | `state.read`; `200 MDNSConfig`, committed configuration, independent of observation |
| `GET /api/v1/services/mdns/status` | `state.read`; `200 {instances: MDNSStatus[], error: string}`, applied singleton snapshot, including provisional state; remains readable on worker failure |
| `POST /api/v1/services/mdns/reconcile` | `state.read`, `transactions.write`, `mdns.write` and every other enabled-service repair permission; bodyless, `200 RuntimeState`, no new revision |

Reads reject query parameters (`400`); mDNS repair rejects queries and any
nonempty body, including `{}` (`400`). Existing `401`/`403` authentication and
authorization, `409` drift/recovery/maintenance guards, apply failure/rollback
and genuine observation errors remain. Changes/restores require `mdns.write`
in addition to transaction and other changed-area permissions; changing input
rules additionally requires `firewall.write`.

`RuntimeState.appliance_services` includes a heterogeneous `mdns` row; do not
cast it to an NTP sample or discard it as an unknown service. Its status fields:

- `name: "mdns"`, `scope: "managed"`, `enabled: boolean`,
  `state: "disabled" | "simulated" | "running" | "stopped" | "error"`;
  `started_at`, `collected_at`, `error`: string or null.
- `effective_interfaces: string[]`, `effective_families: ("ipv4" | "ipv6")[]`,
  `reflection_enabled`, `publishing_enabled`: booleans.
- Exact unsigned decimal-string counters: `received_packets`,
  `transmitted_packets`, `received_bytes`, `transmitted_bytes`,
  `malformed_packets`, `hop_limit_drops`, `policy_drops`, `duplicate_drops`,
  `rate_limit_drops`, `queue_drops`, `oversize_drops`,
  `unsupported_record_drops`, `send_errors`; `receive_drops` is a decimal
  string or null if kernel loss accounting becomes unavailable.
- Counters reset on worker start. `transmitted_packets` counts successful
  destination sends, not client receipt. `statistics_complete` becomes false
  after known receive/queue/rate/oversize loss or unavailable loss accounting.
  Disabled/simulated rows claim no measured completeness (`statistics_complete:
  false`, `receive_drops: null`) and have empty `warnings`; do not render these
  unmeasured statistics as an unhealthy service.
- `filter_counters` contains one row per **applied** `reflection.filters`
  entry, in applied order, even when disabled or reflection is off; empty
  filters produce `[]` (unfiltered reflection has no invented wildcard row).
  Join by canonical `filter`, never by row index or the committed/draft list.
  `matched_packets` counts each admitted ingress datagram once per contributing
  filter, across questions and all record sections, including learned bounded
  DNS-SD dependencies. It is sampled after policy filtering, before later
  returned-packet/egress suppression; a match need not produce a send.
  Provider/instance browse solicitation and service enumeration count as
  matches, not proof that a matching device exists.
  `transmitted_packets` counts each successfully sent reflected datagram
  containing attributed questions/records, per destination and per fragment;
  unrelated fragments, failed/rate-limited sends and appliance publishing do
  not increment it. Legacy unicast reflection replies count too.
  Overlapping entries may both receive credit; never sum these rows to infer
  the global packet total. Both numbers are saturating `u64` decimal strings.
  `last_used_at` updates on a match; `last_transmitted_at` on a successful send;
  both are UTC RFC3339 strings or null before that event.
  Rows reset to `"0"`/null each worker run, including automatic retry, explicit
  restart and configuration replacement/rollback; they are not persisted.
  Disabled/simulated rows are unmeasured zeroes, not evidence of inactivity.
  Existing `state`, `started_at`, `restart_count`, `collected_at`, error/warnings
  and `statistics_complete` identify lifecycle and sample limitations.
  Poll with the existing 2..5-second single-flight interval; render Matched,
  Forwarded and Last used next to each filter without JavaScript `number`
  conversion, and retain drafts while showing applied/provisional activity.
- Optional `retrying`, `restart_count`, `last_error` have the shared native
  supervisor semantics in section 6.1.3. Link/port/socket failures are visible
  and retry automatically without manual repair or global configuration locks.
  Stale sockets are retired before reopening the configured membership;
  conflicting local UDP/5353 receivers are never ignored or killed.
- `warnings: string[]`: `receive_loss_accounting_unavailable`, `receive_loss`,
  `rate_limit_loss`, `queue_loss`, `oversize_loss` as applicable. Render
  warnings without converting them into a global unhealthy-service lock.
- `limits`: numeric fixed bounds including `interfaces:32`, `payload_bytes:9000`,
  `records:512`, `fingerprints:8192`, `fingerprint_seconds:1`,
  `associations:8192`, `association_seconds:120`, `requesters:1024`,
  `requester_seconds:5`, `packets_per_second:200`, `burst:400`,
  `queue_datagrams:256`, `queue_bytes:2097152`, `egress_payload_bytes:1232`,
  `poll_ms:100`, `shutdown_ms:1000`. These are not editable tuning fields.

Use nonoverlapping 2..5-second polling and preserve drafts on errors. Display
committed versus applied/provisional membership and global IPv6 suppression.
Running means local worker readiness, not verified discovery/delivery. No
remote device inventory, captured TXT, packet dumps or runtime caches are
exported in configuration/history.

Operator prerequisites: Linux native networking and existing host-service
opt-in in host mode; sole local UDP 5353 ownership and one active reflector per
connected domain. No competing daemon is killed or auto-disabled. Restrictive
host-input policy needs explicit ingress UDP destination port 5353 permits;
current input rules cannot narrow that to multicast destinations. The worker
validates destination group/source/hop limit. Normal IPv6 membership/MLD
behavior also needs packet-path acceptance. Reflection changes no firewall,
NAT or forwarding sysctl. Unicast connections to discovered addresses/ports
need separate routing/policy; IPv6 link-local addresses do not become routable.

Protocol boundaries: require IP TTL/hop limit 255; reflected QU questions become
multicast-answer questions, with legacy requester correlation. Support common
DNS-SD records A/NS/CNAME/PTR/HINFO/TXT/AAAA/SRV/DNAME/NSEC; other RR types cause
an explicit counted datagram drop. Output is capped at 1232 payload bytes and
actual MTU; split at RR boundaries/TC continuations, never truncate bytes.
Unfit individual records/question sections drop/count; unfit publisher probe
RRsets reject startup. Route-netlink monitoring starts before socket preparation
and gates receive, maintenance and sends. Required link deletion/replacement,
rename, administrative down or lost/invalid notifications latch an attempt error
and retire its sockets; the supervisor automatically retries preparation.
Identical name/index/address recreation and automatic recovery are covered by
native tests. Valid address changes block stale sockets while refreshing both
families. Snapshot polling is a backstop, not the isolation mechanism; the final
notification check/send remains non-atomic. Provider-only PTR answers require a
learned SRV/provider association; unknown dependencies are not forwarded broadly.

Native veth/namespace tests cover wire reflection and lifecycle but not full
VLAN/nftables/MLD, Apple/Windows/printer/Avahi interoperability, reference-host
10k-packet/s performance, reboot or production acceptance. Do not claim exact
Avahi parity. See [build/acceptance spec](docs/MDNS_SPEC.md) and
[required handoff](docs/frontend-handoffs/2026-10-25.md#2026-10-25-17-native-mdns-implementation).

### Native IPv4 UDP Broadcast Relay

Provide a single **Services > UDP Broadcast Relay** editor using shared staged
configuration and confirmed transactions. This is implemented backend behavior,
not a proposal. Canonical details and prerequisites are in the
[relay contract](docs/UDP_BROADCAST_RELAY_SPEC.md).

```ts
type UDPRelaySource = "original" | "interface_address" | "interface_address_and_port";
interface UDPRelayInstance {
  id: number;
  enabled: boolean;
  port: number;
  interfaces: string[];
  multicast_address: string | null;
  source: UDPRelaySource;
  metadata?: ObjectMetadata;
}
interface UDPBroadcastRelayConfig {
  enabled: boolean;
  instances: UDPRelayInstance[];
  metadata?: ObjectMetadata;
}
interface UDPRelayStatus {
  name: "udp-broadcast-relay";
  instance_id: number;
  scope: "managed";
  enabled: boolean;
  port: number;
  interfaces: string[];
  multicast_address: string | null;
  source: UDPRelaySource;
  state: string;
  started_at: Timestamp | null;
  collected_at: Timestamp | null;
  error?: string | null;
  last_error?: string | null;
  retrying?: boolean;
  restart_count?: number;
  received_packets: string;
  transmitted_packets: string;
  received_bytes: string;
  transmitted_bytes: string;
  policy_drops: string;
  loop_drops: string;
  rate_limit_drops: string;
  send_errors: string;
  last_send_error: string | null;
  last_send_error_at: Timestamp | null;
  receive_drops: string | null;
  statistics_complete: boolean;
  limits: {
    interfaces: 32;
    payload_bytes: 65507;
    packets_per_second: 200;
    burst: 400;
    poll_ms: 100;
    shutdown_ms: 1000;
  };
}
```

`config.udp_broadcast_relay` is always serialized; default disabled/empty. Each
instance requires `id`, `enabled`, `port`, `interfaces`. Defaults are null group
and `original` source. Unknown fields/types are rejected. Validate at most 63
instances; unique IDs 1..63 and unique ports 1..65535 even when disabled; 2..32
distinct configured up Ethernet/VLAN links with IPv4 prefix <=30 or DHCP. Global
enable requires an enabled instance. Do not offer loopback/dummy/WireGuard.
Optional group must be an IPv4 multicast literal. Backend sorts ID/interface
sets. Both metadata fields follow shared limits and are operationally inert.
Enabled listener conflicts with mDNS/5353, DHCP relay/67 and DHCP clients/68
reject configuration; unrelated port owners appear as runtime retry errors.

Edits, confirmation/rollback and restore require `udp_broadcast_relay.write`
plus existing transaction/other-resource permissions. Preserve the section in
all complete-config submissions. Every shared-service reconciliation now needs
this permission when the relay is enabled. The new
`POST /api/v1/services/udp-broadcast-relay/reconcile` requires its own permission
even when disabled, plus `state.read`, `transactions.write` and permissions for
other enabled shared services. It rejects bodies/queries (`400`) and repairs
the whole shared service set under existing conflict/drift guards.

| Read | Response |
| --- | --- |
| `GET /api/v1/services/udp-broadcast-relay` | Committed `UDPBroadcastRelayConfig` |
| `GET /api/v1/services/udp-broadcast-relay/status` | Applied `{instances: UDPRelayStatus[], error: string}` |

Both require `state.read`, reject queries (`400`) and use standard `401`/`403`.
Runtime status includes provisional settings, independently of committed reads.
There is no per-instance CRUD or separate write endpoint. Use existing
`POST /api/v1/processes/restart` with `target: "udp-broadcast-relay:ID"` and
`system.restart` for a selected enabled instance. Missing target is `404`,
disabled/busy is `409`, native success uses the existing `200` restart envelope.

`UDPRelayStatus` is heterogeneous runtime data: `name: "udp-broadcast-relay"`,
numeric `instance_id`, `scope: "managed"`, effective `enabled`, configured
`port/interfaces/multicast_address/source`, `state`, nullable `started_at` and
`collected_at`, optional current `error`, `last_error`, `retrying` and
`restart_count`. Per-instance health resources are `udp-broadcast-relay:ID`;
never key these rows by shared `name` alone. Render eight decimal-string
counters without conversion to JavaScript number: `received_packets`,
`transmitted_packets`, `received_bytes`, `transmitted_bytes`, `policy_drops`,
`loop_drops`, `rate_limit_drops`, `send_errors`. Counts reset per socket attempt;
bytes are payload bytes and successful transmissions count each outgoing link,
not remote delivery. Nullable `last_send_error`/`last_send_error_at` retain send
failures, including MTU errors. `receive_drops: null` and
`statistics_complete: false` mean unknown kernel loss, not zero. This expected
accounting limitation alone does not create an active health alert for UDP
relay instances. Actual worker errors, unavailable samples, degraded health
and explicit warnings retain their normal alert behavior. Process health can
be healthy while a running service reports a warning; it is not proof of
packet delivery. Runtime validators must accept `UDPRelayStatus` as a distinct
`appliance_services` member, not require generic or mDNS-only fields. `limits` has
`interfaces:32`, `payload_bytes:65507`, `packets_per_second:200`, `burst:400`,
`poll_ms:100`, `shutdown_ms:1000`. Do not show simulated rows as live traffic.
For per-entry usage badges, join status `instance_id` to configured `id`, show
Received/Forwarded plus optional payload bytes and drop/error details. UDP
relay does not currently expose a per-instance last-used timestamp:
`collected_at` is the latest sample time, not the last packet time.

Use compact instance rows and one owning editor. Offer Govee (4001,
239.255.255.250) and ECHONET Lite (3610, 224.0.23.0) presets that populate a
draft, allocate an unused ID, retain explicit interface selection and never
auto-enable/push or create firewall rules. Default both to original source.
Support enabled toggles, numeric ID/port inputs, interface multi-selection,
optional group, a named source-mode menu and shared metadata. Show current
worker error/retrying state without disabling valid editing/confirmation.

Operator prerequisites: allow local input UDP to each configured relay port on
participating links; allow routed unicast device traffic separately. Govee
requires LAN Control, IoT-to-controller UDP/4002 replies and controller-to-device
UDP/4003 commands. ECHONET Lite needs UDP/3610 request/reply routing. There is
no automatic related allowance, NAT or response proxy. Rewritten source modes
can break direct replies. Raw output cannot fragment; header+payload must fit
egress MTU (1472 payload with MTU 1500). The fixed per-instance rate bound is
200 admitted packets/s, burst 400. Backend requires Linux/CAP_NET_RAW and
existing host-service opt-in. No IPv6, point-to-point, CARP or SSDP/DIAL proxy
parity. Physical-device, actual VLAN/Wi-Fi and deployment acceptance remains.
See [required frontend handoff](docs/frontend-handoffs/2026-10-28.md#2026-10-28-06-native-udp-broadcast-relay).

### Native IPv4 BGP

Implemented as an in-process Rust BGP-4 worker using native TCP sockets,
netlink routes and WireGuard kernel updates. No FRR/BIRD/Go executable, shell,
supervised process, third-party integration or eBPF prerequisite. This is a
bounded connected-route speaker, not a full Internet routing daemon.

#### Configuration and permissions

Top-level `config.bgp` participates in full configuration transactions,
confirmation, rollback and revision history. Changes require
`transactions.write` plus `bgp.write` and the existing permissions for other
changed areas. Device keys receive the new permission; scoped files must grant
it explicitly. The existing all-enabled-service reconciliation permission rule
also requires `bgp.write` when BGP is enabled.

Synthetic configuration fragment (merge into a complete configuration with the
referenced interface/address and, for WireGuard, peer already configured):

```json
{
  "bgp": {
    "enabled": true,
    "local_asn": 65001,
    "router_id": "10.10.0.1",
    "keepalive_seconds": 30,
    "hold_seconds": 90,
    "max_prefixes": 4096,
    "neighbors": [
      {
        "name": "remote",
        "address": "10.10.0.2",
        "local_address": "10.10.0.1",
        "interface": "wg0",
        "remote_asn": 65002,
        "wireguard_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "accept_default": false
      }
    ]
  }
}
```

Defaults: disabled, ASN `0`, empty router ID, keepalive `30`, hold `90`,
max prefixes `4096`, empty neighbors. ASN/router ID must be supplied together
when configuring an identity or neighbors, including while disabled. Enabled
BGP requires at least one neighbor. Local/remote ASN are uint32, nonzero,
excluding `23456` (AS_TRANS), `65535` and `4294967295`; four-octet ASN negotiation is
supported. Router ID must be nonzero unicast IPv4, distinct from the remote
router ID during session negotiation.

Keepalive is integer seconds, at least 1 and at most one third of hold time.
Hold is integer seconds `3..65535`. These are global configured timers, not
per-neighbor overrides or a BGP "hello" interval. Effective hold is the minimum
of local/remote proposals; remote hold 0 disables the negotiated hold/keepalive
timer. Effective keepalive is the lesser of configured keepalive and one third
of negotiated hold. Handshake timeout is 30 seconds; reconnect attempts are
approximately every 5 seconds. Worker-level failures retry after approximately
one second with explicit status errors.

`max_prefixes` is integer `1..16384`, bounding accepted paths across all
neighbors (alternate paths count separately). Exceeding capacity closes the
affected session and withdraws its routes, not a partial silently accepted
table. Maximum 32 neighbors. Neighbor names follow interface-name shape/length
rules and are unique; IPv4 neighbor addresses must be unique, unicast and
different from their local address.

Each neighbor requires `name`, `address`, `local_address`, `interface`,
`remote_asn`. `local_address` must be a static IPv4 address on a configured up
peering interface. Non-WireGuard peers must be directly connected on that
interface. Non-WireGuard `wireguard_public_key` must be empty (default).
For WireGuard it must identify an enabled peer on the selected interface;
one BGP neighbor per WireGuard peer is supported. That peer's **static**
AllowedIPs must already cover the neighbor address to bootstrap BGP. Operators
also need a connected/static route to the neighbor through the tunnel and a
working underlay route to its WireGuard endpoint. DNS endpoints also require
working underlay DNS; endpoint refresh preserves BGP-owned AllowedIPs.
BGP cannot learn the route
needed to establish its own initial connection.

`accept_default` defaults false per neighbor. True permits receiving `0.0.0.0/0`;
it does not originate a default route or override ownership protections.
Both BGP config and neighbor objects accept the normal descriptive `metadata`
object; metadata is validated and excluded from operational/kernel settings.
Unknown transaction config fields follow the existing ignored-field reporting
contract; incorrect types and invalid supported fields fail validation.

#### Export, import and forwarding behavior

- Both active and passive peering use TCP 179, explicitly bound to the selected
  interface and local IPv4 address. Only configured remote source addresses
  are admitted. Simultaneous connections use router-ID-based collision
  selection. Basic eBGP and iBGP sessions are supported.
- Advertise IPv4 connected prefixes from **all configured administratively up,
  live up interfaces**, including current DHCP IPv4 addresses. Re-read native
  addresses approximately every two seconds and withdraw removed prefixes.
  Prefixes are canonicalized/deduplicated; special unspecified/loopback/
  multicast local addresses are omitted. Export is bounded at 4096 prefixes.
  Configured static routes and BGP-learned routes are not redistributed.
- Receive IPv4 unicast UPDATEs. Reject own-AS loops, eBGP paths whose first AS
  differs from the configured remote AS, default routes without opt-in, invalid
  addresses and paths whose NEXT_HOP is not the neighbor's peering address.
  For iBGP, the other speaker must use next-hop-self for nonlocal paths.
  Rejected prefixes are counted, not retained as accepted path rows.
- Deterministic basic selection: highest iBGP LOCAL_PREF (eBGP uses 100),
  shortest AS sequence, lowest ORIGIN, prefer eBGP over iBGP, then neighbor
  name. MED is exposed but not used in this initial local selection policy.
  No ECMP, route reflection, learned-route transit/export, recursive next-hop
  resolution, IPv6/MP-BGP, route-refresh, graceful restart, AS_SET/confederation
  segments, routing-policy language, BFD, TCP MD5 or TCP-AO. Unsupported or
  malformed protocol inputs close the session with an explicit error.
- Install selected accepted prefixes in Linux main table `254`, metric `200`,
  owned protocol `245`. Non-WireGuard routes use the received next hop on the
  selected interface; WireGuard routes use the tunnel interface. Configured
  static/connected routes with the same prefix take precedence in the BGP
  ownership policy. Other protocols' routes are not removed or overwritten;
  an exact kernel key conflict is an explicit install error. `installed` means
  the route was installed, not that it wins over every other kernel route.
- For a selected WireGuard path, union the prefix into the **referenced peer's**
  effective AllowedIPs unless its own static AllowedIPs already cover it.
  Reject overlap with another configured peer's static AllowedIPs or another
  selected peer's BGP-owned prefixes on the same WireGuard interface; do not
  steal prefixes between peers. These prefixes affect both cryptokey routing
  and which source addresses that peer may send. Trust peers accordingly.
- Withdrawals, disconnect/hold expiry, disable, restart, transaction apply/
  rollback and shutdown remove BGP-owned routes/additions. Preserve static
  AllowedIPs, unrelated routes, desired config and revision IDs. A private
  ownership journal records additions before mutation; startup cleans stale
  owned entries only after native scope/ownership validation, then relearns.
  Learned routes are runtime state, never saved as desired routes/AllowedIPs.
  Reconciliation audits owned entries approximately every two seconds and
  repairs missing additions without replacing foreign route conflicts.
  Changes remove obsolete owned paths before installing replacements; no
  interruption-free failover or graceful restart is promised.

#### API, status, CLI and MQTT

API-key authentication and `state.read`:

| Method and path | Response |
| --- | --- |
| `GET /api/v1/services/bgp` | Committed `BGPConfig` |
| `GET /api/v1/services/bgp/status` | Applied worker/neighbor status, without full learned or advertised route rows |
| `GET /api/v1/routes/bgp` | `{source:"bgp",scope,state,error,routes:[...]}` learned paths |
| `GET /api/v1/routes/bgp/advertised` | Same envelope, per-neighbor advertised routes |

No query parameters (`400`). These paths are read-only (`405` otherwise);
configuration is transactional. Normal `401`/`403`; unavailable scope/backend/
status returns `503`. BGP session/install failures remain readable as status,
not empty success-shaped kernel data. The ordinary `/api/v1/routes` remains
configured static routes; do not infer BGP visibility from that endpoint.

Synthetic learned path envelope:

```json
{"source":"bgp","scope":"linux:<opaque>","state":"running","error":null,"routes":[{"prefix":"198.51.100.0/24","neighbor":"remote","interface":"wg0","next_hop":"10.10.0.2","as_path":[65002],"origin":0,"local_pref":100,"med":0,"selected":true,"installed":true,"reason":null,"source":"bgp"}]}
```

Route fields: canonical IPv4 `prefix`, neighbor name/interface, IPv4
`next_hop`, uint32 ASN array `as_path`, numeric ORIGIN `0..2`, uint32
`local_pref`/`med`, booleans `selected` and `installed`, nullable string reason,
literal `source:"bgp"`. A selected path can have `installed:false` when
reconciliation fails; inspect envelope/status error. Nonselected reasons:
`alternate_path`, `connected_or_static_route`, `wireguard_static_peer_overlap`,
`wireguard_dynamic_peer_overlap`. Policy-rejected NLRI are not listed; inspect
neighbor rejected-prefix counters. Route arrays include alternate accepted
paths and are bounded by configured max prefixes; no pagination/history.

Advertised-route envelope (synthetic):

```json
{"source":"bgp","scope":"linux:<opaque>","state":"running","error":null,"routes":[{"prefix":"203.0.113.0/24","neighbor":"remote","interface":"wg0","next_hop":"10.10.0.1","source":"bgp"}]}
```

Advertised rows have canonical IPv4 `prefix`, configured neighbor-name string,
interface-name string, IPv4 `next_hop` (that neighbor's local session address)
and literal `source:"bgp"`. They come from each established connection's tracked
advertised prefix set, not from `connected_prefixes` or received routes. The
same prefix can have a row for each peer; key rows by neighbor plus prefix.
`routes` is always an array, empty before establishment, when inactive, after
session loss/withdrawal, on worker failure/shutdown/restart, and in the simulator.
No saved config, revision, forwarding or export policy changes are made by reads.
The list tracks UPDATEs queued for the established session, not remote receipt,
acceptance or installation; BGP has no per-prefix acknowledgement. Do not label
the rows as peer-confirmed routes. Local connected networks are the current
export policy, but `connected_prefixes` is not the per-peer advertised inventory.
There is no advertised AS-path/best-path/installed flag in this row schema.

Offer Received/Advertised route views under BGP and filter/group by neighbor
client-side; this endpoint accepts no query parameters, pagination or history.
Use the existing received schema only in Received view and the new row type
in Advertised view. Current session `advertised_prefixes` counts correspond
to that peer's rows in a matching running snapshot; separate requests can race
with session changes. Bulk advertised rows are excluded from the status API,
native runtime summaries, aggregate statistics and MQTT publication.

Worker states: `disabled`, `starting`, `running`, `error`, `stopped`, and
simulator `simulated`. Running worker `health` is `up` only when all sessions
are established and installation succeeded, otherwise `degraded`. A running
process is not proof of established BGP. Active running status includes
`local_asn`, `router_id`, `connected_prefixes` (canonical string array),
`installed_prefixes` (number), `kernel_protocol:245`, `route_metric:200`,
`table:254`, nullable error and `neighbors`.

Neighbor rows include `name`, IPv4 `address`, `interface`, session `state`
(`active`, `open_sent`, `open_confirm`, `established`), numeric
`received_prefixes`, `advertised_prefixes`, cumulative `rejected_prefixes`,
nullable `negotiated_hold_seconds`, nullable IPv4 `remote_router_id` and
nullable last `error`. Counts/reset state are ephemeral and reset on worker
restart; previous session errors clear on a new establishment. Inactive/
starting/error snapshots can omit active-only fields. Simulator reports
`simulated` or `disabled`, no learned routes, null unmeasured counts, and no
real session/forwarding claim. Treat `scope` as opaque.

`runtime.bgp` and an `appliance_services` row named `bgp` expose the same
summary without full route rows. Shared `process_health` and `active_alerts`
observe the worker: running with down neighbors is a service warning, not a
global configuration gate or dead daemon. Aggregate statistics add `bgp`
summary; existing MQTT state publication carries it plus the existing
process-health/alerts. No per-route MQTT flood, new broker integration, or
immediate event delivery is promised.

`POST /api/v1/processes/restart` with `{"target":"bgp"}` uses
`system.restart`, existing transaction/upgrade guards, and native `200`
supervisor restart semantics (`409` disabled). It withdraws/relearns, not an
in-place protocol reset. Simulator restart is explicitly simulated.

CLI: `bgp JSON`, `no bgp` edit the private candidate; `show bgp`,
`show bgp status`, `show routes bgp` use the corresponding read APIs.

Frontend tasks: add a BGP settings form to transactional networking, local/
remote ASN validation, router ID, interface/local-address and WireGuard peer
selectors, timer/prefix bounds, and a clearly warned default-route opt-in.
Add neighbor-state and BGP-specific route tables with AS path, source,
selected/installed/reason/error distinctions; poll status single-flight while
visible and fetch route rows separately. Preserve configured AllowedIPs in
forms; display learned additions as read-only runtime state. Wire the existing
restart confirmation and process-health/MQTT display without disabling unrelated
editing due to peer availability.

Deployment: permit TCP 179 only from configured peers on selected interfaces;
ensure WireGuard underlay UDP, bootstrap addressing/routes and kernel support.
Existing root native service has the socket/netlink privileges; no installer
module/security weakening or helper package is needed. There is no BGP
authentication beyond configured address admission; prefer WireGuard/trusted
links. Real-appliance and interoperability acceptance remain separate from
isolated native tests.

### Sando One-Time Imports

Provide **Settings > Sando** at browser route `/settings/sando` with an API
base-URL form, **Sync enabled** toggle, hourly metadata status, **Import hosts**
and **Import rules** buttons, and separate latest confirmed host/rule import
statistics. One-time imports remain frontend-driven and explicitly reviewed.
Optional hourly synchronization runs in the daemon, fetching only host metadata
into a separate cache. It never automatically edits firewall hosts/rules or copies
complete Sando device objects into the firewall schema.

The always-serialized top-level `config.sando` defaults to:

```json
{"api_url":"","sync_enabled":false,"hosts_import":null,"rules_import":null}
```

```ts
interface SandoConfig {
  api_url: string;
  sync_enabled: boolean;
  hosts_import: SandoImportState | null;
  rules_import: SandoImportState | null;
}
interface SandoImportState {
  source_url: string;
  import_count: number;
  last_import_at: Timestamp;
  status: "succeeded" | "partial";
  imported_count: number;
  skipped_count: number;
}
```

`api_url` is the Sando server base **before** `/api`, e.g.
`http://192.0.2.10:8044`; a reverse-proxy prefix is allowed, e.g.
`https://inventory.example.test/sando`. Append `/api/localhosts` or
`/api/ignorelist/ip/<encoded-IP>` after removing trailing base slashes; do not
discard a configured proxy prefix. Empty means unconfigured. Nonempty URLs and
every record's required `source_url` must be absolute lowercase `http://` or
`https://` URLs of at most 2048 UTF-8 bytes, with a host, no credentials,
query/fragment, whitespace, control characters, backslashes or port zero.
No DNS/HTTP/HTTPS connectivity test occurs on save. `sync_enabled` defaults to
`false`; `null`, strings and numbers are invalid. Enabling without a configured
URL returns `422`. No Sando token/credential field is provided.

Each nullable state records one import kind independently. Non-null records
require every field. `import_count` is the frontend-reported number of
confirmed logical import operations represented by the saved configuration:
integer 1..4294967295. `imported_count` and `skipped_count` are item counts for
the latest import, integers 0..4294967295. Status `succeeded` requires zero
skipped items; an empty successfully reviewed import can have zero imported.
`partial` requires both positive imported and skipped counts. Counts are ordinary
JSON numbers, not quoted counters. `last_import_at` is client-reported RFC3339
time, years 1970..9999; offsets are accepted and serialized in UTC. It is not a
server measurement or an independently verified sync time.

`source_url` records the base used for that latest import. It may differ from
the current `api_url`, so changing/clearing settings does not silently erase or
misattribute prior results. Show the recorded source alongside statistics.
These are versioned configuration snapshots, not an immutable audit log:
the backend validates but does not calculate/verify import counters, timestamps
or source data. Normal historical restoration can restore prior statistics.

#### Persistence, authorization and errors

Read committed settings using `GET /api/v1/revisions/latest` at `config.sando`
without live network observation, or `GET /api/v1/state` at `desired.sando`.
Existing API-key authentication and `state.read` apply. Save URL changes or
import records through the existing complete `POST /api/v1/transactions`
package, followed by `/api/v1/transactions/{id}/confirm`. Preserve the entire
configuration and current string `base_revision`; a partial config is not a
settings PATCH. `transactions.write` plus `sando.write` are required for every
Sando change, including records, clearing, confirmation, rollback and restores.
Imported hosts/rules additionally require `firewall.write`, and any other
changed area retains its existing permission. Sando permission cannot authorize
firewall changes.

`GET /api/v1/sando` supplies daemon sync status/cache as specified below; there
is no one-time import or sync-write endpoint. Existing transaction success
statuses remain submit `202`, confirm/rollback `200`; ordinary error envelope
`{error,transaction}` applies: `401` API authentication, `403` permission,
`400` invalid known JSON types/out-of-range unsigned integers/missing record fields/status enum/timestamp
encoding, `422` invalid URL/count/timestamp range or inconsistent outcome,
`409` stale revision/active transaction/drift, and existing persistence/backend
failures. The ordinary unknown-configuration-field reporting policy still
applies; do not rely on unknown import fields being saved.

Statistics become committed only on confirmation and are atomically saved with
the reviewed host/rule edits. Provisional application, failed confirmation,
rollback and restart recovery retain the previous committed report as
appropriate. Import-only metadata is excluded from native operational
configuration, so it does not restart workers or itself change firewall rules.
The standard full-package safety checks remain. SSH generic `set`/`load candidate`
and show/commit workflows carry the same typed settings and permissions.

Large valid imported rulesets use the same atomic native firewall transaction,
with a per-socket send buffer sized for the complete update. They are not split
into partially applied imports. No import schema, validation limit, permission,
HTTP status or confirmation behavior changes. Resource/kernel failures still
surface as ordinary backend apply errors; a reported restoration of the previous
configuration is not a successful import and must not advance the saved report.

#### Rule-source labels and Sando replacement

Rule acquisition, mapping, review, replacement and ordering remain **frontend
responsibilities**. There is no backend rule-import/merge endpoint, automatic
rule fetch, special preservation guard or background firewall synchronization.
Submit the complete reviewed candidate through ordinary confirmed transactions.
See [rule origins](#firewall-rule-origins) for persisted labels.

Tag each newly imported Sando rule with `origin:"import"` and
`import_source:"sando"` (the provider ID, not an upstream URL). On **Import rules**:

1. Fetch/validate the source and build a reviewable replacement before changing
   the draft. A failed/incomplete acquisition must not be interpreted as an empty
   successful import. Show skipped/invalid items and require explicit review of
   any intentionally partial replacement.
2. Read the current committed configuration/revision. Across rule lists managed
   by this import (including previous target lists with no replacement entries),
   remove **only** rules whose origin is `import` and
   import_source is exactly `sando`. This replaces prior Sando rules even if the
   configured Sando base URL changed. Record the actual URL in `rules_import`.
3. Keep every manual rule and every other provider's imported rules unchanged,
   including their matching fields, action, metadata and source labels. Never
   infer Sando ownership from names, addresses, matching content or host metadata.
   Preserve non-Sando `system`/`inherited` labels too. Do not delete/recreate
   host inventory, defaults, input policy or NAT as a side effect of a forwarding
   rule import.
4. Within each affected existing rule list, keep manual rules first in their
   existing relative order; preserve other retained rules' relative order, then
   append new Sando rules in source order. Do not change the compiler's ingress-
   interface-before-host precedence or move rules between scopes. Show ordering
   and removed/new-rule effects in the review.
5. Commit the complete candidate and updated report together; normal confirmation/
   rollback applies. On revision conflict, rebase/rebuild the review against the
   latest state, never blind-resubmit a stale full package. A reviewed genuinely
   empty source removes only old Sando-owned rules; cancel/failure leaves the
   prior configuration intact.

These are frontend requirements, not backend enforcement: an authorized full
configuration write can still edit/delete any rule. Changing a rule's ownership
label is an explicit reviewed edit, not an automatic consequence of opening an
editor. Hourly Sando metadata refresh still never changes labels or rules.

#### Hourly host-metadata synchronization

Save `sync_enabled` through the same full confirmed transaction as `api_url`.
Only committed settings drive the worker: drafts, provisional changes and rolled
back settings do not start/stop it. Confirmed changes are observed within one
second. When enabled, fetch immediately at daemon startup, enablement or source
URL change, then 3600 seconds after each completed attempt, including failures.
Requests are single-flight. Disabling or changing the source cancels any in-flight
request within one second; obsolete results are discarded even before that poll.
Shutdown cancels in-flight acquisition. No browser, cron or external process
is needed. No independent manual-sync endpoint is added.

The daemon makes an unauthenticated `GET <api_url>/api/localhosts`, preserving
reverse-proxy path prefixes. It never calls Sando's mutating
`POST /api/threatscore`; scores come from inventory. No ignore lists or rules
are fetched. The daemon must reach Sando over the configured trusted network;
browser CORS/mixed-content limits apply only to the separate browser imports.
HTTP and HTTPS are supported, TLS certificates are verified, redirects and
environment proxies are disabled, connect timeout is 5 seconds and request
timeout is 30 seconds. Non-2xx, timeout, invalid JSON/types/metadata, duplicate
IP addresses and size/count violations are explicit sync errors, not empty success.
Responses are bounded to 4 MiB including chunked bodies, inventory to 4096 rows,
and the serialized private cache to 1 MiB. Cache writes are atomic, owner-only
and durable at `<--state path>.sando`; corrupt/unsafe existing caches fail startup
explicitly. Sync results are runtime metadata, not revision history or client-
writable fields in `config.sando`. Existing confirmed import counters do not
change. Empty inventory only clears this cache, never firewall configuration;
upstream may return empty arrays on database errors, so do not infer deletions.

Read `GET /api/v1/sando` with an API key and `state.read`. No query/body is
accepted. It returns `200`, `Cache-Control: no-store`; errors use the ordinary
`{error,transaction}` envelope: `401` invalid key, `403` permission, `405` wrong
method, `400` query/body and `503` unavailable manager/status. Reads never
trigger HTTP acquisition. Synthetic successful response:

```json
{
  "enabled": true,
  "state": "succeeded",
  "sync_interval_seconds": 3600,
  "source_url": "http://192.0.2.10:8044",
  "last_attempt_at": "2026-10-30T04:00:00Z",
  "last_success_at": "2026-10-30T04:00:00Z",
  "next_sync_at": "2026-10-30T05:00:00Z",
  "error": null,
  "skipped_hosts": 0,
  "hosts": [{
    "addresses": ["192.0.2.20", "2001:db8::20"],
    "host_name": "camera.example.test",
    "icon": "camera_icon",
    "classification": "Camera",
    "threat_score": 25
  }]
}
```

- `state`: `disabled | pending | syncing | succeeded | error`; describes
  synchronization, **not firewall application**. Disabled takes precedence.
- Timestamps are nullable RFC3339 UTC. `last_attempt_at` records the latest
  completed attempt, `last_success_at` the latest persisted successful snapshot.
  `next_sync_at` is null before scheduling, while fetching and when disabled.
  `error` is nullable text. Failed refreshes retain prior hosts and success time;
  persistence failure publishes an explicit error without publishing new hosts.
  Cached metadata/status survive restart; enabled startup still refreshes
  immediately. Disabled settings retain cached data without fetching. A
  different configured URL never exposes another source's cache as its results.
- `addresses`: one or two distinct unicast IP strings from `ip_address` and
  `ip6_address`, normalized to canonical spelling. MAC-only/no-address entries
  are omitted and counted in integer `skipped_hosts`. Invalid non-MAC IP strings
  reject the snapshot. Match metadata by exact address, never by display name;
  this does not create firewall identities or change their names/policies.
- `host_name`: nullable string, first nonblank `dhcp_hostname`, `dns_hostname`,
  then `lease_hostname`; maximum 255 UTF-8 bytes.
- `icon`: nullable upstream icon identifier, maximum 128 UTF-8 bytes.
- `classification`: nullable `local_description`, maximum 512 UTF-8 bytes.
  This is Sando's free-text classification description, **not** a new category
  enum inferred from icons, vendor names or tags.
- All three strings reject control characters; empty/whitespace-only strings
  become null. Treat names, descriptions and icons as untrusted display data:
  escape text and map supported icon identifiers, never inject HTML or fetch
  arbitrary icon URLs.
- `threat_score`: nullable integer `-1..100`. Preserve `-1` as Sando's
  **no traffic data** sentinel and `null` as unavailable; neither means zero
  risk. `0..100` are dimensionless upstream scores, not firewall decisions.

Frontend tasks: add the disabled-by-default toggle, require URL before enabling,
explain daemon/network prerequisites, and save through normal confirmation.
Poll the status endpoint while the page is visible (for example every 30
seconds; polling does not initiate sync). Show actual last success/error and
disabled/stale states independently of one-time import reports. Enrich matched
host displays with these metadata fields without overwriting manual firewall
names or policies. No automatic blocks/permits based on scores are implied.
See [handoff 2026-10-29-07](docs/frontend-handoffs/2026-10-29.md#2026-10-29-07-hourly-sando-host-metadata-sync).

#### Frontend acquisition and review

The following upstream routes were verified against
[Sando source revision be3df805](https://github.com/mayberryjp/sando/tree/be3df805adb82606ae7285f885d21b6cf597698e);
they are **Sando routes**, not Netcontrol endpoints:

- `GET /api/localhosts`: array of inventory objects. Known fields include
  `ip_address`, `ip6_address`, `mac_address`, `mac_vendor`, `dhcp_hostname`,
  `dns_hostname`, `lease_hostname`, `local_description`, `icon`, `tags`,
  `os_fingerprint`, `domain_name`, lease/detection flags, timestamps and traffic
  totals. `/api/devices` supplies category names, not the host inventory.
  Keep the complete upstream device object in the browser for display if useful;
  runtime-validate fields before mapping to the existing `FirewallHost`.
  The backend adds no vendor/device-type/raw-device fields in this iteration.
- `GET /api/ignorelist/ip/<encoded-IP>`: active detection-ignore entries matching
  the IP as **either source or destination**, with `id`, `src_ip`, `dst_ip`,
  `dst_port`, `protocol`, `times_seen`, `first_seen`, `last_seen`. This is not an
  authoritative firewall allowlist. Do not equate `whitelisted` device flags
  with unrestricted firewall access.

For one-time imports, fetch entirely from the browser, never sending the
Netcontrol API key to Sando.
The browser must reach the configured source; CORS, HTTPS/mixed-content and
local-network browser policies are operator/frontend prerequisites. Current
Sando documents trusted-network use and missing authentication/TLS protections;
do not expose it publicly. The fixed hourly metadata worker is not an arbitrary
backend proxy for browser import requests.
Upstream database helpers can return empty arrays on errors; an empty fetch is
not proof that existing firewall hosts/rules should be deleted.

1. Save/review the configured URL through the normal full transaction. Disable
   import actions while unconfigured or an operation is in flight.
2. **Import hosts** fetches inventory and stages selected additions/updates:
   validate canonical unicast IPv4/IPv6 addresses, unique stable IDs/names and
   existing host limits. Resolve collisions with an explicit review. Preserve
   unrelated hosts, policies and manual rules. Do not activate discovered devices
   or choose a more permissive default policy merely because they exist in Sando.
3. **Import rules** fetches candidate ignorelist entries for selected hosts.
   Only entries whose source matches the selected host can suggest that host's
   outbound rules. Do not reverse inbound entries into outbound permits. Map
   only explicitly supported TCP/UDP/ICMP/ICMPv6 protocols and literal
   destinations into existing host-policy fields. Ports apply only to TCP/UDP;
   ICMP suggestions must have no ports and a compatible family. Skip/report ambiguous, wildcard or
   unsupported entries rather than broadening them. Do not import universal
   allow rules from suppression settings. Review and deduplicate suggested
   accept rules; preserve manual rules and require explicit policy choices.
4. Stage the appropriate record with the selected source, latest item counts,
   UTC browser time, result status and saved `import_count + 1` (or 1 initially).
   One confirmed logical import increments once, not once per fetch/retry.
   Show local **Fetched/staged; not applied** until successful confirmation;
   committed report panels continue reading committed desired state.
5. Apply the full reviewed draft and explicitly confirm. Handle stale revisions,
   interrupted requests and uncertain writes through existing transaction
   recovery; never blindly resubmit and double-count. Cancelled/failed browser
   fetches, discarded previews and rolled-back imports do not update saved
   reports. Show their error locally while retaining the last confirmed result.
   The separate daemon metadata sync/status does not count as a confirmed import.

### 6.2 Managed interfaces and VLANs

Table columns: name, kind, role (including read-only Loopback), administrative up/down, MTU, addresses, VLAN parent/ID
when applicable, staged-change indicator, and actions. Filters: text, kind, and
administrative state, and role. Detail views include desired/observed comparison.

Editor fields:

- Name, kind (`ethernet`, `dummy`, `wireguard`, `vlan`), required role (`wan`, `lan`, or `unassigned`),
  MTU, administrative up, address list.
- VLAN: parent selector and VLAN ID.
- WireGuard: embedded settings/peers or link to the same shared WireGuard editor.

Show role choices as WAN/LAN/Unassigned but serialize lowercase `wan`/`lan`/`unassigned`. Require an
explicit selection for every managed interface; do not infer from names, routes,
or VLAN parents, or silently assign a default. Omitted, null, empty, uppercase,
and unknown values are invalid (422); non-string JSON values are malformed (400).
Apply validation to all managed kinds and include role edits in review diffs.
Multiple interfaces may share a role; no WAN/LAN count requirement exists.
`loopback` is a reserved discovery-only role, never a choice in any managed
interface editor. Read-only loopbacks always have role `loopback`; their role
cannot be changed to WAN, LAN or Unassigned. Do not extend `ManagedInterface.role`
with this value or submit loopback rows in managed configuration.

Roles are descriptive metadata, not automatic firewall zones or NAT/routing
configuration. Preserve them in client types, full-package payloads, shared
drafts, reads, and revision workflows. Role edits require `interfaces.write`
and `transactions.write`, not `firewall.write`. Linux observed roles come from
the expected configuration, not a kernel-derived observation; do not claim
independent verification of network-facing identity.
Adopted read-only parents remain unchanged and do not have editable roles.
This is a greenfield contract: saved configurations/snapshots without required
roles are invalid; do not add a compatibility fallback or migration.

Parent selector combines eligible managed Ethernet/dummy/VLAN interfaces in the draft
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

#### Host interface discovery and selection

##### Interface capability snapshots

`GET /api/v1/interface-capabilities` requires API-key authentication and
`state.read`. It returns `InterfaceCapabilitySnapshot | null`; null means no
refresh has been performed. This cached-read path never probes hardware or runs
state observation.
`GET /api/v1/interface-capabilities/refresh` requires `state.read` plus
`interfaces.write`, performs one synchronous passive scan of all links in the
backend namespace, and returns the atomically persisted snapshot with 200.
Both paths accept no body (including `{}`) or query parameters (400); wrong
methods return 405, authentication/permissions return 401/403. Fatal scan errors
return 503, persistence errors 500; either preserves the last saved snapshot.
Upgrade/restart guards can return 409 on refresh despite its GET method.
Source failures within a completed
scan return 200 with `inventory.status: "partial"` and explicit `errors`.
Partial snapshots replace prior data; do not merge old evidence into new rows.

**API Explorer integration (required):** the user reports both routes are missing
from the frontend explorer. Register both full paths as separate GET entries:
"Read saved interface capabilities" and "Refresh interface capabilities".
The refresh method changed from POST to GET to support the explorer's GET-only
execution; POST now returns 405, without an alias. Keep existing API-key handling.
The read entry needs `state.read`; refresh additionally needs `interfaces.write`.
Accept no body or query parameters for either entry.

Refresh is intentionally scan-and-save, not a normal read-only GET. Mark its
side effect in the explorer and require explicit user execution. Never include
it in automatic polling, prefetch, automatic retries or "run all GETs".
Responses use `Cache-Control: no-store`; disable client/proxy response caching
and send the actual request on each explicit refresh. Avoid overlapping scans.
Render a never-refreshed read as null, successful/partial snapshots with original
timestamp/scope and errors, and permission/409/500/503 failures without claiming
the old snapshot was refreshed. A successful refresh returns the same
`InterfaceCapabilitySnapshot` type as a non-null cached read.

The snapshot is daemon-owned journal state, not a `Config` field. Never include
it in transactions or expose an inventory editor. Refresh does not advance
configuration revisions, apply changes, enable acceleration, affect ownership
or roll back with configuration transactions. There is no automatic scan at
startup, polling or hotplug. Keep the original UTC timestamp, scope and boot ID
visible: cached current-link values are not live statistics.

Rows include unmanaged/down/virtual/loopback interfaces, kernel index/MAC/kind,
nullable driver/firmware/bus identity, nullable PCI identifiers/NUMA node,
nullable link details, supported/advertised/partner-advertised link modes,
nullable channel limits/counts, queue CPU masks and performance capabilities.
Link speeds are Mbps; duplex is `half`/`full` or null. Down/unknown current speed
is null, never a manufactured negotiated speed. Link-mode lists include media,
autonegotiation, pause and FEC bits as well as speed modes; filter on nonnull
`speed_mbps`/`duplex` for a speed/duplex capability list. Preserve unknown kernel
bit IDs with null names/speeds instead of dropping them.

Capabilities identify RSS, RPS, RFS, accelerated RFS, XPS, XPS RX-queue mapping,
generic/native/hardware XDP, redirect/scatter-gather, AF_XDP copy/zero-copy,
DPDK and `ethtool:<driver-feature-name>` offloads. `support` is
`supported`, `unsupported`, `unknown` or `not_applicable`; nullable `enabled`
means activation could not be observed. Evidence is not operational verification,
performance benefit or proof of hardware offload. DPDK, accelerated RFS, generic
XDP and AF_XDP copy readiness remain unknown pending dedicated validation.
Missing APIs, permissions or driver replies mean unknown with diagnostics,
not unsupported hardware. Do not offer automatic tuning based on these rows.

In optional lab namespaces sysfs identity/queues are explicitly omitted because
the sysfs mount may belong to another namespace; ethtool/netdev queries remain
namespace-local. Simulator rows have `source: "simulator"`,
`status: "simulated"`, null hardware/index/MAC/link/channel measurements and
unknown performance support. Containers observe their namespace, not external
host NICs. See the [design](docs/INTERFACE_CAPABILITIES.md) and required
[frontend handoff](docs/frontend-handoffs/2026-10-31.md#2026-10-31-01-interface-capability-inventory).
The GET-only refresh method and missing explorer registrations are tracked in
[handoff 2026-11-04-02](docs/frontend-handoffs/2026-11-04.md#2026-11-04-02-get-capability-refresh-and-api-explorer-registration).

##### Explicit existing-VLAN adoption

`POST /api/v1/interfaces/adopt-vlan` requires the normal API key plus both
`interfaces.write` and `transactions.write`. It accepts no query parameters.
The strict JSON object has exactly three required, nonnull fields:

```json
{"name":"vlan50","parent":"enp2s0","id":50}
```

`name` and `parent` are distinct interface names, each 1..15 ASCII bytes using
letters, digits, underscore, hyphen or dot; `lo`, `.` and `..` are forbidden.
`id` is an integer 1..4094. The parent must already be managed Ethernet.
This explicitly imports an existing unmanaged VLAN; it does not create one,
assign its LAN role or change its address. Ordinary transactions still reject
implicitly taking ownership of an unmanaged VLAN.

Success is `200 {"revision": <canonical revision string>, "interface": <Interface>}`.
The interface uses the existing `Interface` schema with kind `vlan`, role
`unassigned`, matching parent/ID and preserved supported live settings. Other
saved configuration is preserved. Refresh saved state and the candidate's base
revision before a subsequent normal confirmed transaction. This ownership
operation itself has no confirmation timer: later rollback retains the imported
baseline rather than deleting the operator's original VLAN.

Malformed/unknown/missing fields or query parameters return 400; invalid names,
IDs or managed-parent requirements return 422. Already-managed links, busy or
drifted configuration and conflicting recovery return 409. Native refusal,
unsupported backend/scope or failed handover returns 503; persistence failures
can return 500. Missing/invalid authentication is 401, missing permission is 403
and unsupported methods are 405. Show the server error detail.

Native adoption requires host mode, matching live VLAN identity, supported
static configuration and systemd-networkd/resolved ownership handoff. Its
networkd source must explicitly disable RA (`IPv6AcceptRA=no`); DHCP, static/
DHCP/RA routes other than kernel-connected routes, unsupported networkd settings
and changed capture sources are refused. Lab namespaces are unsupported.
Capture and recovery intent are durable before handover. Interrupted adoption
blocks other configuration writes until explicit recovery/retry or restart;
do not automatically retry, prefetch or poll this mutation.

After capture, explicit ownership recovery checks the VLAN's identity, relinquishes
networkd management and actively reapplies the captured address/MTU/up settings.
Initial host inheritance instead uses the aggressive console-only takeover
contract below; it does not share these narrow later-VLAN capture restrictions.
Startup reasserts networkd exclusions for all still-owned physical interfaces,
including those without an initial-inheritance receipt, then reconciles saved
desired configuration rather than restoring bootstrap addressing. This does
not add an endpoint, discover/claim unrelated links or remove initial capture
restrictions.
Before verifying this baseline, restart recovery initializes committed DHCP
clients and restores valid durable leases, including pending lease intents.
An empty in-memory lease map must not classify a valid leased WAN address as
an unexpected static address. This changes neither the saved configuration nor
address/route validation; arbitrary live addresses are not imported.
External changes to those mutable settings during handover are overwritten on
the selected VLAN, not treated as a requirement for manual reconciliation.
Verification compares address configuration rather than raw kernel creation/
update timestamps or dump ordering. Real identity or post-apply configuration
mismatches remain errors, with recovery intent retained. Other interfaces and
saved appliance configuration are not reset. No request/response fields,
permissions or status codes change.

Required API Explorer/client registration and optional operator UX are tracked
in [handoff 2026-11-06-03](docs/frontend-handoffs/2026-11-06.md#2026-11-06-03-interactive-and-tagged-lan-setup).
The active recovery fix is tracked in
[handoff 2026-11-06-04](docs/frontend-handoffs/2026-11-06.md#2026-11-06-04-active-vlan-ownership-recovery).

##### Live interface selection

`GET /api/v1/interfaces/discovered` requires the normal API key and `state.read`.
It returns `DiscoveredInterface[]`, including unmanaged links and loopback in
the backend's network namespace. Native mode defaults to the daemon's current
host namespace; `--namespace NAME` optionally selects a lab namespace.
In Docker this means the container network, never Windows host adapters.
Simulator inventory describes only simulated links, not real host hardware.
Native host mode requires a persistent `/etc/machine-id` containing 32 hex
characters. Empty/missing/invalid identity fails startup; the daemon does not
silently generate one or reset state. Preserve the state location and machine
identity across restart/reboot; isolated lab scopes remain boot-bound.

Discovery is read-only, does not require successful configured-state observation
or healthy service workers, and does not assign WAN/LAN roles or take NIC ownership.
It classifies actual kernel loopback links using the loopback flag, not a name
such as `lo` or a prefix heuristic.
It rejects query parameters with 400, unsupported POST with 405, missing/invalid
keys with 401 and missing `state.read` with 403. Real read failures return 503,
not an empty success. `GET /api/v1/interfaces` retains its managed-config meaning.

Provide a separate discovered-NIC list with name, kernel index, MAC, kind,
current MTU/up state and addresses. Loopback and unsupported kinds remain visible
but cannot be selected as Ethernet. Existing Ethernet and veth links use the
configuration kind `ethernet`. Explicitly choose role, desired MTU/up state and
static addresses before submitting the full candidate; do not infer WAN/LAN.
Discovery addresses may not satisfy candidate validation, so never blindly copy
them into a transaction.

The main interface overview must also show live inventory, not only the managed
configuration list. Default to **All interfaces**, including down, unmanaged,
loopback and unsupported links; kind/ownership filters must be explicit user
choices, not an implicit supported-kind whitelist. Linux loopback is normally
named `lo`; preserve the actual backend name rather than inventing a `lo0` alias.
Loopback is visible/read-only, not eligible for adoption, deletion or submission
as a configurable Ethernet interface.

Every discovery row includes read-only `role` and `addressing_type` fields:

| Discovered kind | `role` | `addressing_type` | Editing |
|---|---|---|---|
| Actual loopback | `"loopback"` | `"static"` | None; fixed values, regardless of up/down state or active address count. |
| Any other kind, managed or unmanaged | `null` | `null` | Do not infer role or addressing origin from discovery. Join managed settings separately as below. |

Render loopbacks as **Loopback** role and **Static** addressing by default, using
these explicit values. Both are fixed read-only labels, not selectors: no other
role or Static/DHCP/SLAAC/None addressing choice is supported for a loopback.
An empty loopback address list does not change it to DHCP, None or Unassigned.
Other interfaces must never offer the Loopback role; their normal managed-role
choices remain WAN/LAN/Unassigned. A role filter may include Loopback to find
these read-only rows. Null discovery metadata is not the managed `unassigned`
role, disabled addressing, or proof of static/DHCP origin.

Synthetic loopback discovery row:

```json
{
  "name": "lo", "kind": "loopback", "index": 1,
  "mac": "00:00:00:00:00:00", "mtu": 65536, "up": true,
  "addresses": ["127.0.0.1/8", "::1/128"],
  "ownership": "loopback", "role": "loopback", "addressing_type": "static"
}
```

These are inventory fields, not new desired-configuration fields. Full-package
transactions still reject a managed `loopback` kind or a `loopback` role on other
managed kinds with `422`. Adding `dhcp_clients.lo` is also `422` because loopback
cannot be a managed DHCP client. Discovery stays GET-only (`405` for POST); no
loopback role/addressing mutation API is added. Existing unknown-property
projection/`ignored_fields` behavior is unchanged: do not copy a discovered row
or its read-only `addressing_type` into candidate configuration.

Join discovered rows with managed configuration by technical `name`. Display
`DiscoveredInterface.addresses` as **Active addresses**, including DHCP IPv4,
static IPv4, global/link-local IPv6 and loopback addresses. Keep configured static
addresses in a separate field/column or detail section. An empty configured
address list must not render as no active IP when discovery contains one. Do not
discard kernel addresses just because they are absent from desired state or
from Netcontrol's DHCP lease map: an external manager may have assigned them.
Lease records from `GET /api/v1/runtime` enrich matching rows with server/expiry/
errors; they do not replace kernel inventory or prove a recorded address is
currently applied. Discovery alone does not identify DHCP versus static origin.
Never copy these active addresses into configuration drafts.

Fetch inventory independently of managed-state observation and runtime polling.
If those other reads fail, keep successful inventory rows/addresses visible and
mark unavailable configuration/lease details separately. If inventory fails,
show unavailable/stale state rather than an empty successful table. Preserve
missing configured links as clearly absent/read-only diagnostic rows, without
fabricating live addresses from desired state or a cached lease.

Changing host networking may sever API/SSH management. Keep the user's draft,
show the exact removals/additions and provisional deadline, require independent
connectivity verification and never auto-confirm. Ethernet management operates
on an existing NIC, not hardware creation/deletion; show removal as releasing
configuration ownership rather than deleting a physical port.
Initial native host inheritance is separate from discovery. A new journal or an
empty revision-zero journal without transactions inherits supported physical
NICs with `unassigned` roles; existing configurations are not recaptured. A
populated interface list at the initial revision is therefore valid. This is not WAN
detection, a browser-side import or an automatically confirmed user transaction.
Initial physical capture now keeps DHCPv4 from dual-stack networkd DHCP modes
but excludes IPv6 addresses/routes and IPv6 DNS literals; DHCPv6/SLAAC is disabled,
not imported as static configuration. Native reconciliation enforces the disabled
IPv6 default globally, including empty configuration and loopback/unmanaged links.
Opening discovery alone remains read-only. Initial console takeover imports
supported Ethernet/veth, dummy and standard VLAN topology, static IPv4/routes,
DHCPv4 (including unleased clients), networkd/active NetworkManager settings and
representable nftables rules as owned configuration. Unsupported topology is
detached/downed/address-cleared; custom routing, foreign nftables/legacy xtables,
qdiscs, XDP/TCX and known competing managers/processes are disabled. Original OS
files and private capture remain, but there is no connectivity-loss rollback.
Known units are persistently masked/stopped; same-namespace standalone
competitors are terminated with pidfds. Resolved, SSH, Netcontrol and Wi-Fi
authentication remain. Inactive manager profiles/private keys are not translated;
custom launchers/renamed competitors require operator review.
Explicit read-only parents retain link-level settings. Removing a managed
interface from an aggressively adopted host does not hand it back to an OS
manager: unconfigured links remain down/address-cleared, except read-only parents.
Normal confirmed transaction rollback can restore the prior valid managed plan.

`GET /api/v1/runtime` (`state.read`) adds native `host_takeover: null | HostTakeover`.
It is null without a host takeover receipt. The object has `mode: "console"`,
`phase: "captured" | "applying" | "owned" | "failed" | "complete"`, `error: string`
(empty without a recorded error), `connectivity_confirmation_required: false`,
and `items: {resource: string, disposition: "imported" | "disabled", reason: string}[]`.
Items describe the captured plan/decisions, not live reachability. Raw snapshots,
lease secrets and OS configuration contents are never returned. Incomplete/failed
phases must not render as successful takeover; show console correction/retry
guidance. No new mutation endpoint or permission is introduced.

Local provisioning transactions use durable `applying_local` and then
`committed`, with `confirmation_deadline: null`; restart resumes and verifies
the candidate before commitment. The browser must not offer confirmation or a
countdown for these transactions. Normal HTTP/SSH edits still require their
non-null deadline, independent verification and explicit confirmation; ordinary
apply/rollback failure semantics are unchanged.
Verified system conntrack-ownership transactions use the same nullable-deadline
local lifecycle; see [the ownership policy](#conntrack-limits-and-timeouts).

#### DHCPv4 and resolver configuration

Full `Config` payloads and revision snapshots carry optional `dhcp_clients` and
`dns` objects keyed by configured interface name. Omitted maps mean empty;
empty maps may be omitted in responses. Null maps/entries/fields and unknown
fields are rejected. Preserve these maps in drafts, export, revision restoration
and unrelated edits; dropping them disables DHCP or removes resolver settings.

`dhcp_clients[interface]` fields are defaultable: `client_id` is empty (MAC
identity) or hex encoding of 2..255 bytes including the identifier type;
`hostname` is empty or a canonical hostname, max 253 characters; `route_metric`
is integer 0..4294967295, default 0; `use_mtu` is boolean, default false;
`use_domains` is `no` (default), `route`, or `yes`. Clients require a configured
Ethernet interface, no enabled relay on it and no static IPv4 address in its
address list. Static IPv6 may coexist. An administratively down NIC does not run
a client. DHCP-supplied MTU must fit 1280..65535.

`dns[interface]` has default-empty `servers: string[]` (up to 8 unique canonical
IPv4/IPv6 unicast or loopback literals, no zones/ports/TLS names) and
`domains: { name: string, route_only: boolean }[]` (up to 32 unique canonical
domains, with both domain fields required). Routing-only `.` is allowed.
`override_dhcp_dns` is a boolean, **default `true`** (omitted means `true`; null and
non-booleans are rejected), always present in responses. When true and `servers` is
non-empty, DNS servers learned from the interface's DHCP lease are discarded and
only the configured servers are published to systemd-resolved for that interface.
When false, the lease servers are appended after the configured ones. With no
configured servers, the lease servers are always kept (there is nothing to override
them with). The setting does not affect DHCP search domains, which stay controlled by
`dhcp_clients[].use_domains`. Configured servers are published first; the daemon also
resets resolved's remembered current server so a newly configured server is actually
selected. Interfaces adopted from an existing host configuration are imported with
`override_dhcp_dns: false`, preserving their earlier merged behavior.
DNS publication requires native host mode and running systemd-resolved; lab
namespaces cannot change the host resolver. These are client resolver settings,
not a DNS server or a hostname-to-address zone editor.

Both maps require `interfaces.write` plus ordinary transaction permissions.
Shared service-repair POSTs also require `interfaces.write` whenever either map
is configured, in addition to permissions for all enabled services. Structural
errors use 400, semantic schema errors 422, missing permissions 403; existing
transaction conflicts, apply/recovery failures and observation 503 behavior
remain. Configuration changes still use transactions, not standalone DHCP/DNS
configuration endpoints. The runtime-only retry action below is separate.

Native `GET /api/v1/runtime` adds `dhcp_clients: { leases, errors }`. Both are
objects keyed by NIC name. A lease contains the configured `client`, IPv4 CIDR
`address`, IPv4 `server`, `acquired_at` (Unix seconds), `lifetime`, `renewal`,
`rebinding` (seconds), `routes: Route[]`, `dns: string[]`, `domain: string`, and
`mtu: number | null`. Errors are strings keyed by NIC. Missing lease means no
currently recorded lease, not a static fallback or an empty successful renewal.
Native runtime only: simulator does not fabricate real leases; treat an absent
`dhcp_clients` runtime property as unsupported/simulated, not as a native sample.

Managed-interface and route GETs remain desired/verified static configuration;
do not copy runtime/discovery DHCP addresses into their static lists. Show DHCP
mode, active address/expiry/server, dynamic routes and resolver data separately.
Poll runtime using existing cadence and preserve expired/unavailable/error
distinctions. Renewal does not create a new configuration revision. Never
auto-confirm a transaction because a lease exists or the HTTP process is active.

Enabled IPv4 static routes referencing a DHCP-managed interface are
lease-dependent: without a valid matching lease they remain configured but are
suspended in the native route plan. Acquisition/renewal/address replacement
restores missing configured protocol-242 routes after DHCP routes; expiry/NAK
removes the dependent static routes. This does not change `enabled`, revision,
history or a configured literal gateway. Routes with `gateway:"dhcp"` instead
resolve their next hop from that interface's current lease, as specified in
[Routes](#64-routes). An unreachable pinned gateway or an
unowned conflicting route remains an explicit backend/worker error, not a
successful fallback. IPv6 routes and other interfaces are outside this recovery.
Use `dhcp_clients.leases` acquisition/lifetime and `errors` for status; do not
equate an enabled route, a retained expired lease, or a `200` configuration read
with installed/forwarding traffic. No per-static-route installation field or
automatic network-repair API is introduced. Reads do not repair drift.

**Manual DHCPv4 retry:** `POST /api/v1/interfaces/{name}/dhcp/retry` requires an
API-key Bearer token with `interfaces.write`; `transactions.write` and
`state.read` are not required for the action itself. Polling runtime separately
requires `state.read`. Accept no body or exactly an empty JSON object `{}`;
reject query parameters, unknown fields, null, arrays and malformed JSON with
`400`. Names use the configured interface-name syntax (1..15 ASCII bytes;
letters, digits, `_`, `-`, `.`; not `lo`, `.` or `..`). No name aliases or
display names. A synthetic accepted response is:

```json
{"interface":"wan0","status":"retrying"}
```

`202` means the selected replacement worker initialized, not that a lease or
default route was obtained. Native Linux stops/joins only that client's worker
before replacement, starts fresh DHCP discovery without DHCPRELEASE, and keeps
a still-valid lease/address/routes/resolver state until replacement, expiry or
a DHCP rejection. Other DHCP clients and protocol workers are not restarted.
Existing lease-update intents are recovered using the normal committed-lease
rollback path. Stop has a 15-second deadline and startup acknowledgment a
10-second wait; native reads/recovery can add time. A stop timeout retains
ownership and prevents a second client. Do not automatically repeat a timed-out
HTTP request; inspect runtime first. This action does not create a transaction,
change configuration/revision/history, or require confirmation.

Errors: `401` invalid/missing API key; `403` missing permission; `404` valid name
not in committed configuration; `409` any active/recovering transaction,
interface administratively down in committed configuration, DHCP not configured,
native ownership mismatch/identity drift, or pending native configuration
recovery intent; `405` other methods; `503` unsupported backend (including
simulator), native I/O/startup/shutdown failure or engine unavailable. Errors use
the ordinary `{error, transaction}` envelope (`transaction: null`). Worker
health/lease-acquisition failure alone does not prevent attempting retry.

Offer an explicit retry action for configured, up DHCP interfaces using committed
state, not the draft. Disable duplicate clicks while the request is pending;
handle conflicts and errors without clearing drafts. Poll
`GET /api/v1/runtime` at the existing cadence and render
`dhcp_clients.leases[name]` and `dhcp_clients.errors[name]`. A previously valid
lease can remain visible during retry; its mere presence is not proof of a new
acquisition. Compare `acquired_at`/expiry and show an unconfirmed outcome if no
update is observed, rather than claiming success from `202`. No attempt ID,
completion event, forced release, DHCPv6 retry or automatic retry is provided.

Deployment: console takeover requires root network/BPF privileges,
systemd/resolved, trusted persistent state and stable host identity. It supports
unleased DHCPv4 and active NetworkManager capture, disables unsupported
networking and masks competing managers. Read-only parents/lab namespaces are
excluded and actual loopback remains read-only. Wi-Fi authentication stays with
its supplicant. Stopping the daemon does not hand ownership back to OS managers.
Real Ubuntu/systemd interruption, reboot and management acceptance remain
required; isolated Linux tests are not proof of production safety.

Installed Ubuntu appliance mode enables host IPv4 forwarding after native
policy reconciliation on each startup. Initial installation retains imported
supported policy, routes, DNS and WAN addressing and sets explicit LAN addressing
and WAN/LAN roles. Empty WAN uses DHCPv4. Only explicit factory reset selects
DHCPv4 WAN, forward/input drop defaults, LAN allow-all, global IPv4 ICMP acceptance
and LAN-subnet WAN masquerade. Ordinary startup and
upgrades preserve saved `firewall.allow_all_icmp`, including explicit false.
Role edits alone do not regenerate policy.
IPv6 forwarding and non-appliance deployments remain operator responsibilities.
The API deliberately rejects IPv4/IPv6 forwarding sysctls: changing them can
change other kernel device/RA settings that are not currently captured for
transaction rollback. Do not render a supported forwarding toggle or claim
Netcontrol configures every host subsystem.

#### Global IPv6 policy

The complete configuration has a top-level `ipv6_enabled: boolean`. Omission
defaults to `false`; normalized configuration/revision/transaction reads include
it explicitly. `null`, strings and numbers are `400`. Fresh install/factory
configuration disables IPv6. Explicit saved `true` remains enabled; changing a
default does not overwrite that saved choice. Preserve this scalar in every full-package edit,
export/import, compare and historical restore.

Expose an **Enable IPv6** global switch in the candidate editor. Changes use
`POST /api/v1/transactions` followed by the existing confirmation/rollback
workflow, not a new immediate-write endpoint. `transactions.write` plus
`kernel.namespace.write` authorize changing the switch; any accompanying
resource edits require their existing permissions. Reads use `state.read`:
`GET /api/v1/state`, `/api/v1/runtime` and existing revision/transaction routes.
Confirmation and historical restore retain their existing authorization rules.

When false, IPv6 literals/prefixes are invalid across interface addresses,
WireGuard endpoints/allowed IPs, DNS servers, routes, policy rules, firewall
source/destination/host/input references, masquerade, NTP/syslog servers,
gateway monitors and exporter collectors. `ip6`/`icmp6` capture filters are also
invalid. Validation applies even to disabled service records. Remove/replace
conflicts in the same candidate; do not silently delete them when toggling.
Hostnames remain valid and native NTP/syslog resolution uses IPv4 hosts entries,
IPv4 DNS servers and A queries only. Exporters exclude IPv6 regardless of their
otherwise-valid filter/version. Family-neutral firewall rules remain valid.
Conflicting candidates return `422` before any live change.

Native enforcement covers all/default/per-interface Linux `disable_ipv6`
controls in the managed namespace, including unmanaged links, adopted parents
and loopback. `false` means `1`, `true` means `0`; new interfaces inherit the
default. Enabled does not imply configured IPv6 addresses, forwarding, DHCPv6
or router advertisements. Do not expose arbitrary IPv6 sysctls as substitutes.
Normal host deployment controls the appliance host; explicit lab namespace mode
does not disable IPv6 in unrelated namespaces or move the management listener.

`GET /api/v1/runtime` adds:

```json
{"ipv6":{"enabled":false,"status":"measured","disable_ipv6":{"all":"1","default":"1","lo":"1","lan0":"1"},"drift":false}}
```

This is a response fragment with synthetic interface names. `enabled` is the
desired boolean; `status` is `"measured"` natively or `"simulated"` in the
simulator. `disable_ipv6` is a string-to-`"0"|"1"` map of observed controls,
or null for the simulator. `drift` is boolean natively, null when simulated.
Do not label simulated data as verified kernel enforcement. Drift blocks
ordinary writes/confirmation; existing repair/recovery rules still apply.

Warn that disabling interrupts IPv6 traffic and IPv6-only management, including
`::1` dependencies. Require deliberate review, recommend IPv4 management and
independent console access, preserve pending transaction identity across
disconnects and never infer confirmation from a successful apply.
Existing errors remain: missing grants `403`, stale base/active transaction/
maintenance/drift conflicts `409`, native apply/read failures `503` with normal
transaction recovery details where applicable. A failed or unreachable apply
is not a successful disable.

Policy is saved and reconciled on daemon startup, including after reboot. It
does not install bootloader/module blacklists or an OS sysctl.d file and is not
a guarantee of IPv6 absence before daemon startup. Linux IPv6 kernel controls
under `/proc/sys/net/ipv6/conf` must be readable and writable when a change is
needed; absent controls or denied required writes fail explicitly. Same-boot disable/re-enable and rollback preserve unmanaged
IPv6 addresses/routes with elapsed finite lifetimes; managed addresses/routes
come from configuration. Missing/changed captured unmanaged interface identities
fail recovery rather than writing to a replacement. Prior-boot snapshots are
discarded during boot reconciliation; do not promise restoration of old leases
or unmanaged transient addresses after reboot. Coordinate backend deployment
before enabling the switch; no compatibility aliases or state reset.

### 6.2.1 Per-interface DHCPv4 relay

Include an **Enable DHCP relay** boolean and an editable server-address list in
each managed interface editor. Wire field:
`dhcp_relay: { enabled: boolean, servers: string[] }`. Default is disabled with
an empty list; normalized reads include the object. Retain valid server entries
when toggled off. Lists are normalized and every configured server receives
requests; this is not ordered failover.

Servers must be distinct canonical unicast IPv4 literals: no hostnames, ports,
prefixes, IPv6, loopback, link-local, multicast, broadcast, or unspecified IPs.
Validate entries even when disabled. Enabling requires at least one server,
an administratively up Ethernet/dummy/VLAN interface, and a configured unicast IPv4
address. WireGuard cannot be enabled for relay. WAN/LAN role does not restrict
relay or select upstream interfaces.

The first IPv4 address in lexicographically sorted canonical interface prefixes
is the relay address (`giaddr`). Show it in the editor/review when more than one
IPv4 address is present; do not infer a different subnet. Enabled interfaces must
use distinct relay addresses. IPv6 DHCP is not implemented.

Server Offers, ACKs and NAKs with zero BOOTP hops are valid (RFC 2131 table 3).
Relay reply processing does not require the server to echo request hops.
Transaction/client identity, configured upstream, relay-address and on-link
checks remain required; downstream relay chaining remains unsupported.

Linux uses an in-process Rust DHCPv4 relay, not a DNS or DHCP address server.
Simulator status is `simulated`, never actual packet forwarding. Unsupported
configurations must fail explicitly during preflight. Operators supply capabilities,
namespace access, routes, server return paths, DHCP scopes and any permissions
on external firewalls. Native input permissions for the relay itself are
automatic; no manual input rule is required:

- Client: IPv4 UDP source port 68, destination port 67, ingress equal to the
  relay-enabled interface, destination either `255.255.255.255` or its exact
  selected relay address. The worker retains source/on-link/header validation.
- Server: IPv4 UDP source/destination port 67, source equal to one of that
  interface's configured servers and destination equal to its exact selected
  relay address. Return traffic can enter any interface; upstream/transaction
  validation remains in the worker.

These are system-owned derived accepts before configured input rules, including
explicit input drops. Enabling relay deliberately authorizes only this traffic;
disable relay to withdraw these exceptions. They apply in the normal network
transaction and are regenerated for server/address changes, startup repair,
rollback and interrupted-intent recovery. They are not inserted into saved
`firewall.input.interfaces`, interface responses, drafts or exported packages.
Existing manual permissions remain user-owned, and established/related conntrack
acceptance is unchanged; disabling relay does not flush conntrack or remove
manual DHCP permits. No automatic routing/NAT/forwarding changes, IPv6 permissions,
TCP/UDP management access or DHCPv4 client port-68 input exception is added.

`GET /api/v1/statistics/firewall` exposes generated client/server input rows
with `config_path:null`, system origin and null import source, described under
[rule counters](#firewall-rule-match-counters). Use them with worker status
and traces to distinguish arrival, input admission, relay activity and delivery;
an accepted packet does not prove a lease was supplied by the server.

Use interface write permissions and full-package transaction workflows;
confirmation, rollback, restart, and revision restoration preserve settings.
Worker reconfiguration can briefly interrupt enabled interfaces. Show this warning
in review. Disabled server lists still persist.

Read `GET /api/v1/services/dhcp-relay/status` as
`{ interfaces: DHCPRelayStatus[], error: string }`, or use runtime's `dhcp_relay`
array. Join rows by interface name. Show disabled, simulated and native
running/error/stopped states distinctly; preserve errors and
unknown values. Do not show or infer child-process PIDs. Running verifies worker
namespace and owned UDP 67 socket, not server reachability or lease
delivery. Missing runtime data is Unknown, not Disabled.

If an enabled relay/exporter worker fails, native observation returns `503`;
it does not toggle the configured `enabled` field. Preserve desired configuration
and drafts, and use runtime errors for diagnosis. Runtime remains accessible
even when full observation fails.
Offer explicit bodyless `POST /api/v1/services/dhcp-relay/reconcile` using stored
committed/pending settings, not drafts. It repairs all managed services, creates
no revision, does not replay networking, and requires permissions described in
the authorization section. Do not automatically retry it.

### 6.3 Adopted parents

Read-only table: name, kind, index, MAC, MTU, administrative up, available, error.
Fetch through runtime or parent inventory even when full observation fails.
Show absence/error as an actionable diagnostic, not an invitation to recreate.
No add/delete/edit/adopt buttons. Explain that replacement of a parent identity
requires operator attention; changing a parent's MTU/up externally is not itself
owned-configuration drift.

### 6.4 Routes

Table/editor: enabled toggle, destination network, optional gateway, managed
interface, table, metric. Family badge derives from destination. Include
text/table/interface/family/enabled filters and a separate delete action.

Static routes accept `enabled: boolean`; omission defaults to `true` in requests
and saved configurations, including revision records. Canonical responses always
include the boolean. Explicit null or nonboolean values return `400`. New-route
forms should explicitly start with `true`; preserve explicit false rather than
using a truthiness-based default. False retains the complete route and metadata in desired/observed
configuration, drafts, transactions, revision history and exports, but excludes
it from native installation. `/api/v1/routes` includes disabled records; it is not
a raw kernel routing-table dump. DHCP-learned runtime routes do not gain this flag.
Disabling an installed route removes only that owned static route; re-enabling
installs it. Rollback/recovery uses the same route selection. Editing fields of a
disabled route does not install it. Initial host adoption records inherited
static routes with `enabled: true`.

For DHCP-managed interfaces, enabled IPv4 routes may be temporarily suspended
while no valid matching lease exists. Keep the toggle enabled and show a
"waiting for DHCP" distinction using runtime lease/error state; do not silently
disable or remove the configuration. See the DHCP lifecycle contract above.
`GET /api/v1/state`, `/api/v1/routes` and interface reads keep their existing
response shapes and can succeed while these routes are suspended. Other
networking drift and worker failures still produce `503`, not synthetic success.

Disabled routes still require valid canonical prefixes, matching gateway family,
a managed interface, table 254 or 10000..19999, and an integer metric 0..2147483647.
Duplicate `(table, destination, metric)` identities remain invalid across both
states; enabled is not part of identity. IPv6 policy still validates disabled
routes. Enabled explicit gateway monitors require a matching enabled route;
disabling their only matching route without disabling/changing the monitor
returns `422`. DHCP-mode monitors still do not require static routes.

Stage toggles in the shared draft and apply a complete `POST /api/v1/transactions`
package, with normal confirmation/rollback. Changes require `transactions.write`
and `routes.write`, plus permissions for other changed resources. Reads require
`state.read`. There is no per-route enable/disable endpoint or new permission.
Warn about management-connectivity loss before disabling management/default
routes. Saved configuration and revision records that omit the field load with
routes enabled; explicit false remains disabled. This is ordinary field defaulting,
not a file-rewrite utility or reset. Other schema/validation requirements remain
strict. Deploy backend support before offering disabled-route controls.

Gateway omission or `""` means a direct route; never substitute `0.0.0.0`.
Otherwise `gateway` accepts a canonical numeric address or the exact lowercase
string `"dhcp"`. `"dhcp"` requires an IPv4 destination and a DHCPv4 client on the
same managed interface, including for disabled routes. IPv6, blackhole targets,
other spellings and DHCP-less interfaces reject this mode with `422`. Null and
non-string gateways remain `400`. Literal gateways remain pinned; they are
never automatically rewritten to a new site's router.

Synthetic route fragment (requires configured Ethernet `eno1` and
`dhcp_clients.eno1`; keep the operator-selected table and metric):

```json
{"enabled":true,"destination":"203.0.113.10/32","gateway":"dhcp","interface":"eno1","table":254,"metric":10}
```

For `"dhcp"`, the runtime plan selects the lowest-metric IPv4 default route
(`0.0.0.0/0`, table 254) from that interface's valid matching lease. Equal-best
defaults must agree on one numeric unicast gateway. No default, a direct default
without a next hop, an invalid gateway or differing equal-best gateways produces
an explicit worker/backend error; never fall back to another WAN, DHCP server
address, an old pinned gateway or an arbitrary router. DHCP classless routes are
authoritative: if they suppress the Router option and contain no default, this
mode cannot resolve. Specific leased routes do not override the selected default
gateway for configured DHCP-following routes.

Without a valid matching lease, enabled routes remain configured and suspended,
as above. Acquisition, renewal, gateway-only changes and address/site changes
resolve and install the owned protocol-242 routes after DHCP routes. Loss removes
them; failed lease updates restore the previous lease and its resolved routes
through existing recovery intents. Table, metric, destination, interface,
`enabled`, revision and saved `"dhcp"` value do not change with the lease.
Desired/observed configuration reads and revisions retain `"dhcp"`, not the
resolved address. Runtime lease routes remain numeric/direct learned routes;
they are not a list of resolved configured routes. No new status field is added.

Offer a Direct / Static address / DHCP gateway selector and only enable the last
choice for IPv4 routes on draft DHCP-managed Ethernet interfaces. Preserve this
choice across draft edits, exports, disabled routes, history and rollback.
Show waiting/error state using the applied runtime lease/error map, not a
fabricated installed gateway. Keep the existing transaction permissions,
confirmation, `500` apply/recovery errors and `503` observation failures.
Deploy backend support before submitting `"dhcp"`.

For a WireGuard endpoint host route, operators must verify its existing table,
metric and routing policy keep the endpoint on the underlay rather than the
tunnel. This mode does not select a table, add policy rules, alter AllowedIPs or
remove other routes to prevent tunnel recursion. Switching a pinned route is an
explicit configuration transaction; no saved route is automatically converted.

Managed interface options come from the draft, not adopted parents. Explain reserved
tables and protocol 242 ownership; protocol is not an editable field.

#### Blackhole target

Optional top-level `config.blackhole` defines **one** named drop target that any
number of routes may use as their `interface`. It is not a device: no link is
created, and the kernel route is a deviceless `blackhole`, `unreachable` or
`prohibit` route. Absent or empty `name` means not configured. Normalized
responses always include the object:

```json
{"blackhole":{"name":"","action":"blackhole"}}
```

- `name`: string, default empty. When nonempty it must be a valid interface name
  (letters/digits/`.`/`_`/`-`, at most 15 characters) and must not equal a managed
  interface or, natively, an adopted parent. It is the only value besides managed
  interfaces that `routes[].interface` may take.
- `action`: `"blackhole"` (default, silently discards), `"unreachable"` (sender gets
  host unreachable) or `"prohibit"` (sender gets administratively prohibited).
  One action applies to every route that uses the target.
- Optional `metadata` with the usual `display_name`/`description` limits.

A route targeting the blackhole must have an empty `gateway`; table 254 or
10000..19999, positive metric and duplicate-identity rules are unchanged. Routes
are ordinary static routes: `enabled: false` keeps them saved but uninstalled,
and both IPv4 and IPv6 destinations are supported (IPv6 requires `ipv6_enabled`).
Referencing the name while it is empty, unknown or colliding returns `422`; the
name cannot be removed while a route uses it. Unknown keys in the object are
dropped and reported like any other configuration key on submit.

Synthetic example inside a complete candidate:

```json
{"blackhole":{"name":"blackhole0","action":"blackhole"},
 "routes":[{"destination":"198.51.100.0/24","interface":"blackhole0","table":254,"metric":50}]}
```

Behavior to explain to operators: matching traffic is dropped during the routing
decision, before forwarding policy or NAT, including traffic the appliance itself
tries to send to that destination. A longer-prefix or lower-metric route still
wins, so a `0.0.0.0/0` blackhole at a high metric acts as a fail-closed fallback.
Routes in tables 10000..19999 only apply where a routing rule selects that table.
There are no per-route drop counters, so do not display dropped-packet counts.
Changing `action` or the name reconciles only owned routes; renaming with an
unchanged action leaves identical kernel routes and is not drift. Changes
require `transactions.write` and `routes.write`; confirmation/rollback and
restore are unchanged. The firewall, NAT, DHCP, DNS and gateway-monitor
sections still require real managed interfaces and cannot name the blackhole.
The simulator validates but installs nothing.

### 6.5 Source-policy routing

User-configurable source-policy routing is unsupported. Remove its table/editor,
navigation, client type and permission controls. `GET /api/v1/policy-rules`
returns `404`; `policy.write` is not a supported permission. Configuration must
omit `policy_rules` entirely, including empty arrays or null; unknown-field
submissions return `400` rather than being ignored. State, transactions and
revision configurations no longer serialize the field. CLI `policy-rule`,
`no policy-rule` and `show policy-rules` are unsupported.

Normal destination routes remain supported with `routes.write`. Use table 254
(main) for ordinary routing; custom tables remain available for explicitly
configured gateway-monitor paths, with internal rules as described above.
No API import/restore compatibility path or automatic persisted-state migration
is provided; unsupported saved configurations fail explicitly without deleting
or resetting data. The separately authorized operator-only
[offline conversion](docs/BUILD_AND_INSTALL.md#offline-policy-rule-state-conversion)
can remove empty retired fields from validated stopped-service journals/native
metadata with preview, confirmation and private backups. It refuses non-empty
rules (including history), active/recovery state and corruption. There is no HTTP
conversion endpoint, browser repair action or permissive startup fallback.

### 6.6 Firewall forwarding

#### Spoof Block

Provide a global **Spoof Block** toggle bound to `config.firewall.spoof_block`:
a nonnull boolean, **default true** for omitted input, new installations and
factory reset. Preserve explicit false in drafts, full-candidate writes,
history/restore and restart. Changes use existing confirmed transactions with
`transactions.write` and `firewall.write`; wrong types/null return `400`.
There is no per-interface override, extra endpoint, mode selector or uRPF
setting. The normalized Firewall/configuration always exposes the boolean.

`GET /api/v1/firewall/rules` (`state.read`, API-key authentication) returns
`FirewallView`: the existing observed Firewall fields plus a read-only
`system_policies` array. The array currently contains one policy with
`id:"spoof_block"`, `origin:"system"`, `read_only:true`,
`config_path:"/firewall/spoof_block"` and `enabled:boolean`. This is a response
projection, **not configuration**: desired state, runtime configuration,
revision/export payloads and editable interface policies remain unchanged.
Never copy `system_policies` into a transaction candidate; unknown configuration
fields are rejected with `400`. Continue editing only `firewall.spoof_block`
through normal confirmed transactions.

The policy's `chains` array exposes the exact compiled source guard, in
`input`, then `forward` hook order. Each chain has `name` (`input_spoof_block`
or `forward_spoof_block`), `hook`, `priority:-1`, `policy:"accept"` and ordered
`rules`. A chain's accept policy means **continue to later hook chains**, not
final packet authorization. Each rule contains:

- `id:string` (`<chain>:<order>`) and zero-based `order:integer`. These are
  positional identities within this response, not persisted rule identifiers;
  refresh after configuration changes and do not retain selection by position.
- `action:"return"|"drop"`, `counter_id:string` matching a statistics row ID,
  and `config_path:string|null`: `/firewall/spoof_block` for terminal drops,
  otherwise null.
- `matches`: `family:"ipv4"|"ipv6"`, `ingress_interface:string`,
  `source:string|null` and `destination:string|null` (canonical CIDR, null
  means unrestricted), `protocol:"any"|"udp"|"icmpv6"`,
  `source_port:number|null`, `destination_port:number|null` (UDP ports,
  1-65535), `icmp_type:number|null`, `icmp_code:number|null` (0-255),
  and `hop_limit:number|null` (0-255). Null means no constraint, not zero;
  generated ICMPv6 exceptions explicitly match code 0.

All rules are returned, including zero-hit rules, exact DHCP destinations,
each IPv6 exception and both per-interface terminal family drops. Rules use
the same compiler as native enforcement, not a second frontend approximation.
The response describes the observed applied configuration, including a pending
transaction's candidate, and returns to the previous rules after rollback.
Existing observation/backend failures remain explicit `503`; no incomplete
or empty-success substitute is returned for a compilation failure. Existing
authentication, permission and method handling is unchanged.

When disabled, the policy remains present with `enabled:false, chains:[]`.
Enabled with no managed LANs returns `enabled:true, chains:[]`; it does not
imply any installed guard chain. Counter joins are **many-to-one**: terminal
drop counters aggregate all LANs/families per chain, and generated return
counters group matches by interface/category. Never display aggregate counters
as distinct measured per-rule/per-interface hits or sum repeated `counter_id`s.
Render policies/rules as system-owned, non-editable details alongside user
policies; the global toggle remains the only Spoof Block control.

Synthetic shortened response fragment (other Firewall fields and rules omitted):

```json
{
  "spoof_block": true,
  "system_policies": [{
    "id": "spoof_block",
    "origin": "system",
    "read_only": true,
    "config_path": "/firewall/spoof_block",
    "enabled": true,
    "chains": [{
      "name": "input_spoof_block",
      "hook": "input",
      "priority": -1,
      "policy": "accept",
      "rules": [{
        "id": "input_spoof_block:0",
        "order": 0,
        "counter_id": "input_spoof_block:generated/spoof_block/lan0/local",
        "config_path": null,
        "action": "return",
        "matches": {
          "family": "ipv4",
          "ingress_interface": "lan0",
          "source": "192.0.2.0/24",
          "destination": null,
          "protocol": "any",
          "source_port": null,
          "destination_port": null,
          "icmp_type": null,
          "icmp_code": null,
          "hop_limit": null
        }
      }]
    }]
  }]
}
```

Required system-policy rendering is tracked in
[handoff 2026-11-09-09](docs/frontend-handoffs/2026-11-09.md#2026-11-09-09-read-only-spoof-block-system-policy-details).

Enabled enforcement covers IPv4 and IPv6 entering every managed interface with
`role:"lan"` (Ethernet, VLAN, dummy or WireGuard), including configured down
LANs once traffic can enter them. WAN, unassigned/adopted-only links, loopback
and local output are not source-guarded. Each LAN's permitted source prefixes
are its own configured interface addresses truncated to their network prefix,
not host inventory, other LANs, live unmanaged addresses, routes, BGP or
WireGuard `allowed_ips`. Multiple prefixes are a union; duplicate subnets are
deduplicated. A LAN without a source prefix for a family drops ordinary traffic
of that family. Changing addresses/roles updates enforcement transactionally,
including restart, confirmed changes and rollback.

The owned `input_spoof_block` and `forward_spoof_block` filter chains run at
hook priority -1, before the normal priority-0 input/forward chains. Invalid
sources are terminal drops even for established/related packets, global IPv4
ICMP bypass, temporary diagnostic permits and ordinary allow rules. Valid
sources return through this guard's policy and **continue to normal rules**;
they are not automatically authorized. The guard does not alter forwarding,
NAT, conntrack state/timeouts, routes or Linux `rp_filter`.

Exceptions bypass only this source guard and never grant a final accept:

- IPv4 DHCP bootstrap: `0.0.0.0`, UDP source 68/destination 67, addressed to
  `255.255.255.255` or an exact configured IPv4 address on the ingress LAN.
- DHCPv6: `fe80::/10`, UDP source 546/destination 547, addressed to
  `ff02::1:2` or `fe80::/10`.
- ICMPv6 code 0 neighbor discovery: link-local source `fe80::/10`, types
  133/134/135/136, hop limit 255, destination link-local (`fe80::/10`),
  link-scope multicast (`ff02::/16`) or an ingress LAN's configured IPv6 subnet.
- Unspecified IPv6 source `::`: code 0 RS type 133 to `ff02::2`, or DAD NS
  type 135 to solicited-node multicast `ff02::1:ff00:0/104`, hop limit 255.
- MLD: link-local source, types 130/131/132/143, code 0, hop limit 1,
  destination `ff02::/16`; unspecified source is permitted only for reports
  131/143 with those same destination/code/hop constraints.

Keep normal DHCP/IPv6 input permits; otherwise these packets can still be
dropped by later policy. This is not an RA guard or same-subnet device identity
check. It intentionally blocks routed downstream/VPN/relay sources outside the
ingress LAN's own subnets, even when a route exists. Explicitly disable the
global setting when that topology is intended; never silently add routes,
prefixes, exemptions or auto-disable it. A `/0` interface subnet naturally
permits every source of that family and should be shown as ineffective source
restriction. Enabling may immediately interrupt off-subnet active sessions.
This feature does not fix WAN return drops or identify connection state.

Show system-owned terminal drop counters at
`input_spoof_block:/firewall/spoof_block` and
`forward_spoof_block:/firewall/spoof_block`, with config path
`/firewall/spoof_block`, aggregating both families/all LANs. Guard return
counters have null config paths and generated keys
`generated/spoof_block/<interface>/local`, `/bootstrap`, `/ipv6_control`
in each guard chain. Returns are not firewall accepts/drops; summed rule-match
counters can count a packet again in normal rules. Disabled/no-LAN enforcement
has no guard chains/rows. Guard plans are bounded to 20480 rules per chain and
the complete instrumented ruleset to 81920 physical rules; excess native
preflight/apply is an explicit error, not partial enforcement.

Deny history adds `reason:"spoof_block"` with `compiled_rule_index:null`;
its `chain` remains `"input"` or `"forward"`, not the auxiliary chain name.
Normal logging, retention, category selection, permanent tuple deduplication and
Discord eligibility remain unchanged. Do not treat source-guard drops as a new
notification category or automatically allow their source. Refresh ruleset
identity/counter baselines when LAN addresses/roles or this setting change.

Deployment impact: default-on enforcement is a breaking policy change on the
first application/startup of the new compiler; explicit saved false remains
authoritative. Review routed LAN/relay/VPN topology before deployment, using
console/independent operator access and normal confirmed-change recovery.
There is no compatibility window, migration or state reset. Required frontend
work is detailed in [handoff 2026-11-09-08](docs/frontend-handoffs/2026-11-09.md#2026-11-09-08-default-on-lan-spoof-block).

#### Global logging and ICMP

Provide a global **Log firewall drops** toggle bound to
`config.firewall.drop_logging_enabled`. It is a nonnull boolean, enabled by
default for new installations, factory reset and omitted input. Explicit
`false` must survive drafts, full-candidate submissions, restart and revision
restore. Changes require `firewall.write` and `transactions.write` through the
normal confirmed transaction workflow. Null/wrong types return `400`.
This controls all owned input/forward drops, not individual rules or syslog.
Disabling stops capture, not drop verdicts or live rule accounting; retained
history remains readable. See [deny logging](#firewall-deny-log).

Provide a global **Allow all IPv4 ICMP (protocol 1)** toggle bound to
`config.firewall.allow_all_icmp`, with `firewall.write` and `transactions.write`
required to change it. It defaults to `true` when omitted; null returns `400`. Normalized
reads return a boolean. Preserve explicit `false` in full-package submissions,
revision restore, and draft editing; do not use a truthy fallback.

When enabled, an implicit accept exception runs after Spoof Block but before other owned forward rules
in both policy modes, including host/interface drops and the global default.
It also accepts protocol 1 in owned input/output chains. It applies to every
interface in the managed namespace, including loopback, adopted parents, and
future interfaces, without generating editable per-interface policy entries.
It covers all IPv4 ICMP types/codes, not just echo, and does not cover ICMPv6
(protocol 58). Other nftables tables may still drop traffic.

Disabling removes the exception and the owned output chain, not a blanket
ICMP block. The input chain remains if `firewall.input` is configured and its
rules/default continue to apply. Without that policy, the ICMP-only input chain
is removed. Forwarding rules/defaults still apply when disabled.
Show this exception prominently in both policy modes and in the review diff.
Warn that an older client omitting the field re-enables it. Older durable
configurations and historical snapshots without the setting default to enabled;
startup applies the exception even over previous ICMP drops. Explicit `false`
survives upgrades. Unrelated owned-firewall drift fails migration/startup.

The primary policy view pivots around **hosts**, not interfaces. Host inventory:
stable ID, unique display name, one or more explicit IPv4/IPv6 addresses, outbound
default Accept/Drop, and ordered rules. Show hosts as independently editable
devices; do not nest them under an interface. IP-based identity is not
authenticated identity and does not track DHCP/MAC changes automatically.

Rules: destination Any, another host by ID, or a canonical network; protocol Any,
TCP, UDP, ICMP, or ICMPv6; optional explicit destination ports for TCP/UDP; Accept/Drop.
These same five choices apply to host, ingress-interface, management-input and
legacy ordered filter rules. Wire values are omitted/empty string for Any,
`tcp`, `udp`, `icmp`, `icmpv6`; null, aliases, numbers and other names are invalid.
Any matches every IP protocol, not just the four named choices.

ICMP matches IPv4 protocol 1; ICMPv6 matches IPv6 upper-layer protocol 58,
including packets with IPv6 extension headers. These match all types/codes:
no per-type/code selector is implemented. Both forbid destination ports.
ICMPv6 requires `ipv6_enabled: true`, including wildcard rules. Explicit
prefixes must agree with the protocol family. Dual-stack source/destination
hosts expand only compatible address pairs; at least one pair must exist.
Disable/clear port controls for Any/ICMP/ICMPv6 and prevent incompatible family
selections. Warn that blocking ICMPv6 can break neighbor discovery and IPv6
error reporting. The global Allow all IPv4 ICMP exception still precedes IPv4
ICMP drop rules; it does not permit ICMPv6.
Host and interface rules also accept optional `out_interface`: an empty/omitted
string matches any egress; otherwise it must name a managed draft interface
(maximum 15 characters, using the interface-name validation). Null is invalid.
An interface rule with this field requires both the ingress and egress matches.
Preserve this field in drafts, imports, exports, history and full-package writes.
Changing a host address updates all destination-host references in the package.
Deletion must first remove or replace references; never silently broaden them.
Offer add/edit/delete and keyboard-accessible reordering.

A separate **Interface overrides** view configures ordered rules for an ingress
interface (managed draft link or adopted parent). There is no interface default.
Display the effective precedence prominently:

0. Spoof Block drops off-subnet LAN sources; valid/exempt sources fall through.
   If Allow all IPv4 ICMP is enabled, remaining IPv4 protocol 1 is accepted.
1. Established/related traffic is accepted, including existing connections.
2. First matching ingress-interface rule wins, overriding host policy.
3. Otherwise evaluate the source host's ordered rules, then its default.
4. Unknown source hosts use the global default.

The destination host's own outbound policy is not evaluated. Interface allows
override host drops as well as interface drops overriding host allows. Warn about
interface catch-alls that shadow all host policies. Existing connections can
survive a newly applied ordinary rule block until conntrack expires; Spoof Block
still checks their LAN source before established/related acceptance. Explicit
[connection state deletion](#connection-state-deletion) is separately authorized
and never performed automatically by rule changes. `firewall.policies`
host/interface rules apply only to forwarded traffic,
not management input or local device output. `firewall.input` is a separate
host-input policy; the global ICMP exception also covers input/output.
NAT remains separate.

Include explicit **Legacy ordered rules** mode for existing configurations:
source/destination prefixes or Any, the same protocol choices and optional
TCP/UDP destination ports, Accept/Drop, and global default; stateless
after the optional global ICMP exception.
It is selected by absent/null `firewall.policies`. New host/interface mode sends
`policies` and an empty legacy `rules` list; never mix the models. Switching models
must show the full difference and require acknowledgement, not silently translate
or discard rules. Host-only, interface-only, and combined configurations are valid.

Legacy `protocol` and `destination_ports` default to empty/Any and an empty list;
normalized responses omit empty fields. All filter scopes limit ports to 32
unique integers 1..65535; legacy port expansion is limited to 20480 rules.
Each expanded legacy port retains its logical rule's counter identity.
Never sort rules before sending. Host inventory and port lists may be sorted.
Require review acknowledgement for drop defaults and catch-all drops. Provide
managed egress selection, but do not add arbitrary protocol choices, port ranges, per-rule logging controls, or configurable
conntrack controls: these are not implemented.

#### Firewall rule origins

All saved legacy filter, host-policy, ingress-interface, management-input,
masquerade and destination-rewrite rules carry:

```ts
type RuleOrigin = "manual" | "import" | "system" | "inherited";
interface RuleSource {
  origin: RuleOrigin;
  import_source: string | null;
}
```

Both fields are always serialized on rule objects. Request omission defaults
origin to `manual` and import_source to null; explicit null origin and unknown
origin strings return `400`. `origin:"import"` requires a provider ID matching
`[a-z][a-z0-9_-]{0,63}` (1..64 ASCII characters); absent/null/invalid source is
`422`. Other origins require null/omitted import_source (`422` otherwise).
`"sando"` identifies Sando imports; other provider IDs remain distinct.
The existing legacy `source` field remains an IP prefix, **not** provenance.

Synthetic examples (individual rules, not complete transaction requests):

```json
{"source":"192.0.2.0/24","action":"accept","origin":"manual","import_source":null}
```

```json
{"destination":"198.51.100.0/24","action":"drop","origin":"import","import_source":"sando"}
```

Origins are descriptive labels, not permissions, verified upstream identity or
an authorization boundary. `manual` is explicitly maintained policy; `import`
is managed by the named frontend importer; `system` describes rules derived from
settings/built-in behavior; `inherited` describes an inherited presentation.
When displaying a host's effective policy, show ingress-interface rules as
inherited **without changing the original interface rule's saved manual/import
ownership**. Do not persist derived copies or rewrite its origin to inherited
just to render that host view. The backend adds no effective-host-rule endpoint.

Labels are preserved in reads, full-package writes, revisions, restores and
rollback; they use existing firewall/NAT write permissions. They are excluded
from operational matching, ruleset hashes and native identity, like display
metadata. Label-only edits do not change rule evaluation order, auto-delete or
reclassify rules, restart workers or reset live counters. A new counter sample
can reflect updated labels without a new counter generation. Unknown source
ownership must not be inferred automatically; omitted origin simply means manual.

The [counter endpoint](#firewall-rule-match-counters) reports these labels on
configured logical-rule rows. Backend-generated bypass/default/setting rows
are tagged `origin:"system", import_source:null`, including ICMP, global/input/
host defaults and established/loopback acceptance. Interface definition rows
retain their original saved origin; inherited host-view rendering is frontend
work. Deny-log records remain unchanged and do not contain these labels; do not
relabel historical packets using the current draft.

#### Firewall deny log

When `firewall.drop_logging_enabled` is true (the default), native Linux
continuously captures owned input/forwarding **drops**, including
explicit rules, generated host-policy defaults and chain default Drop policies.
Records are runtime telemetry, not firewall configuration: no per-rule log flags in rule
forms, no transactions/revisions on reads/capture, and no records in configuration
exports, aggregate state/statistics or MQTT. Backend audit/syslog remains separate.
Capture does not depend on a browser or request and cannot reconstruct prior
unrecorded traffic. Existing acceptance, ICMP and established/related precedence
is unchanged; accepted packets are not deny records.

Setting `firewall.drop_logging_enabled:false` removes NFLOG expressions from all
owned drop rules/defaults, flushes the pending captured batch, joins the receiver
and releases group 100. Packets still drop and packet/byte counters still count.
Already captured/in-flight records can finish persistence during disable;
traffic after disable completes is not captured, indexed or reconstructed.
Re-enabling starts the receiver before installing logging expressions. Confirm,
rollback, revision restore and startup repair apply the target setting.
Retained history, IDs and lifetime first-seen identities are never cleared.
Discord sending reports unavailable while capture is disabled; re-enabling does
not replay traffic missed during that interval. Capture remains independent of
the separate `discord.enabled` flag.

`GET /api/v1/firewall/deny-log` requires API-key authentication and
**`firewall.logs.read` only** (not `state.read` or write permissions).
It takes no body; other methods return `405`. Query parameters:

| Parameter | Type/default | Validation/meaning |
| --- | --- | --- |
| `limit` | decimal integer, 100 | 1..500 |
| `before_id` | optional decimal ID string | Exclusive positive u64 cursor; use `next_before_id` unchanged |
| `since_ms`, `until_ms` | optional decimal integers | Inclusive Unix UTC milliseconds, 0..253402300799999; since <= until |
| `address` | optional string | Canonical IPv4/IPv6 literal, matches source OR destination |
| `protocol` | optional decimal integer | IP protocol number 0..255; e.g. TCP 6, UDP 17, ICMP 1, ICMPv6 58 |
| `chain` | optional string | Exactly `input` or `forward` |
| `include_broadcast` | boolean string, `false` | Exactly `true` or `false`; include records tagged `ipv4_broadcast` when true |
| `include_tcp_closures` | boolean string, `false` | Exactly `true` or `false`; include records tagged `tcp_finish`, `tcp_reset` or `tcp_ack_only` when true |

Both categories are excluded when their flags are omitted or false. True includes
that category alongside other matching drops; it is not a category-only selector.
Records tagged with both categories require both flags true. Filtering uses saved
tags before page limits/cursor selection, not current interface reclassification.
Filters combine with AND. Query maximum 4096 bytes; unknown/duplicate parameters,
noncanonical numbers (including leading zeros/signs), invalid IPs/ranges and
bodies return `400`. Authentication/permission errors are `401`/`403`.
Simulator, unavailable engine or native scope/read failures return `503`, not an
empty successful simulated log. Errors use the normal `{error, transaction}`
envelope. All replies are `Cache-Control: no-store`.

Synthetic `200` response (not actual appliance traffic):

```json
{
  "records": [{
    "id": "42", "timestamp_ms": 1793336400000,
    "chain": "forward", "reason": "rule", "compiled_rule_index": 2,
    "ruleset_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "source": "192.0.2.2", "destination": "198.51.100.9", "protocol": 17,
    "source_port": 12345, "destination_port": 53,
    "ingress_index": 2, "egress_index": 3, "ingress": "lan0", "egress": "wan0",
    "packet_length": 64,
    "tcp_flags": null, "tcp_payload_length": null, "tags": []
  }],
  "next_before_id": null, "oldest_id": "42", "newest_id": "42",
  "cursor_expired": false,
  "retention": {"max_records": 4096, "max_segment_bytes": 524288, "segments": 8},
  "capture": {
    "status": "capturing", "error": null, "group": 100, "rate_limit_per_second": 100,
    "discarded_records": "0", "malformed_records": "0",
    "overflow_events": "0", "sequence_gaps": "0",
    "counters_scope": "daemon_session", "loss_count_exact": false
  }
}
```

Records are newest **ID** first, independent of clock changes. IDs and loss
counters are decimal strings, not JavaScript numbers. IDs survive normal daemon
restart and are not configuration revisions. `oldest_id`/`newest_id` are global
retention boundaries, unaffected by filters, and null for empty history.
`next_before_id:string|null` is the exclusive cursor for another matching page;
null means no older retained match. New capture does not shift earlier pages.
`cursor_expired:true` means the cursor reached/passed evicted history; render an
explicit retention-gap notice rather than claiming the entire history was read.

Every record serializes all fields. Timestamp is a millisecond integer; source/
destination are canonical IP strings; protocol is an integer. Ports are integers
0..65535 or null for non-port protocols, noninitial fragments or headers outside
the 128-byte capture bound. Interface indexes are positive integers or null;
names are strings or null when unavailable/removed/unrepresentable. Do not
replace a historical null name using the current device at a reused index.
`packet_length` is the IP-header-advertised byte length (IPv4 total length or
IPv6 base payload length plus 40; not Ethernet bytes or a flow total).
No packet payload is persisted or returned.

Every record also includes `tcp_flags:integer|null`, `tcp_payload_length:integer|null`
and required `tags:string[]` (possibly empty). `tcp_flags` is the low eight TCP
control bits, 0..255: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32, ECE=64,
CWR=128; the NS/reserved header bits are not included. Null means non-TCP,
noninitial fragment, or a fixed TCP header unavailable within the advertised IP
length and 128-byte capture bound. Never replace null with zero.
`tcp_payload_length` is the IP-advertised bytes after IP/extension and TCP headers,
not captured bytes, Ethernet bytes or a flow total. It is null without readable
TCP flags or when fragmentation prevents knowing the complete TCP segment size.
TCP options need not fit in the capture to calculate length from the data offset.
An invalid readable TCP data offset increments malformed capture accounting.

Tags describe packet observations, **not confirmed connection state or safety**:

| Tag | Exact meaning |
| --- | --- |
| `tcp_finish` | Readable TCP FIN bit set |
| `tcp_reset` | Readable TCP RST bit set; may indicate refusal/reset, not normal closure |
| `tcp_ack_only` | Flags exactly ACK (16) and known TCP payload length zero; not proof of teardown |
| `tcp_connection_attempt` | SYN set, ACK/FIN/RST clear; not proof a connection was admitted |
| `ipv4_broadcast` | Destination is `255.255.255.255`, an explicit kernel-reported IPv4 broadcast, or the directed broadcast calculated from a live assigned IPv4 address/prefix; prefix length must be <=30 |

Tags are independent and ordered as in the table; a FIN/RST packet can have both
tags and an IPv4 broadcast tag. Broadcast tagging is protocol-independent,
including UDP. IPv6 is never broadcast; multicast is not tagged as broadcast.
Directed broadcasts use explicit broadcast attributes and live address/prefix
metadata, so classification also works when the kernel omits `IFA_BROADCAST`.
They use all live interface address metadata in the managed
network namespace, including dynamic/unmanaged addresses, refreshed at startup
and once per capture worker window (approximately one second). Snapshot timeout/
failure stops capture with an explicit capture error instead of silently using
stale classification. There is no per-packet scan or request-time reclassification.
Tags are saved with the record; subsequent address changes do not rewrite history.
No inference is made for remote/unknown subnet broadcasts. For example,
`10.4.30.255` is broadcast on `10.4.30.0/24`, but not on `10.4.30.0/23`;
`10.4.30.127` can be broadcast on a `/25`. `/31` and `/32` do not add directed
broadcasts. Empty tags mean no recognized observation, not verified unicast/safety.

Add initially-off **Include TCP FIN/RST/ACK-only drops** and
**Include IPv4 broadcast drops** controls mapped to `include_tcp_closures` and
`include_broadcast`. Filtering is server-side. For all categories request, for
example, `GET /api/v1/firewall/deny-log?limit=100&include_broadcast=true&include_tcp_closures=true`.
`tag` and `exclude_tags` are unsupported query parameters and return `400`.
Reset loaded pages and the cursor when either category flag or another backend
filter changes; refetch from the newest page and retain the same selection on
every subsequent page. Discard late responses from an older selection rather
than mixing them with the new results. Use the original `next_before_id`, not a
locally computed cursor. A null cursor means no older retained matching record.
Retained boundary IDs remain global and may identify excluded records.
Describe empty results as no retained matching drops, not no captured traffic.
Unknown TCP flags and ACK packets with unknown/nonzero payload are not excluded
as ACK-only; only the saved `tcp_ack_only` tag qualifies.
Do not call FIN/RST/ACK-only traffic harmless or confirmed closing. Render
readable flag names plus raw bits and independent tag badges.
Filtering does not stop capture, change verdicts, erase records, or suppress
Discord notifications. These request flags are independent of Discord settings.

Deployment contract: private deny-log segments now require **schema 2**, including
required tags and current traffic metadata. Unsupported segments are rejected
unchanged at native startup; no conversion, reset or deletion is performed.
The lifetime first-seen SQLite identity/schema is unchanged. Incompatible queued
alert records fail explicitly without being claimed when delivery is enabled.
Preserve private history/index/configuration and follow the
[operator requirements](docs/BUILD_AND_INSTALL.md#firewall-deny-logging)
before deployment; new frontend controls require the accepting backend.

`reason` is `rule`, `policy` or `spoof_block`; `policy` means a chain default
Drop and `spoof_block` means the LAN source guard. Both have
`compiled_rule_index:null`. A generated host default is a `rule` drop.
Rule indexes are zero-based **compiled** positions (including generated rules),
not user-facing array indexes/stable IDs. Show them only alongside the 64-character
lowercase SHA-256 `ruleset_id` identifying the actual applied operational firewall,
including provisional/rolled-back rulesets. Never attribute old records to the
current draft's rule at the same numeric position.

Capture status is `disabled`, `starting`, `capturing`, `error` or `stopped`; `error` is
nullable text and can also contain the last malformed-record warning while
capture continues. `200` with capture error still exposes retained history, not
healthy current collection. Fatal I/O/capture errors stop collection until
operator repair and daemon restart. Counters reset per daemon session:
`discarded_records` counts valid records exceeding the 100-record/one-second
worker-window persistence cap; `malformed_records` counts rejected messages;
`overflow_events` counts socket ENOBUFS notifications; `sequence_gaps` counts
missing per-group kernel sequence positions. These indicators can overlap and
do not give an exact lost-packet total; do not sum them as such.

History is private persistent rotating storage, at most eight 512-record/512-KiB
segments (4096 records maximum; segment rotation can retain fewer). There is no
guaranteed time horizon, configurable retention or clear endpoint. Normal shutdown
flushes the pending batch; crashes can lose up to the pending one-second batch
and kernel-buffered records. Metadata remains sensitive: do not persist it in
browser storage, analytics or config exports. Retention and capture errors never
clear drafts or change policies.

#### Discord first-seen drop alerts

Optional Discord notification settings are a nonnull top-level
`discord:{enabled:boolean,notify_broadcast:boolean,notify_tcp_closures:boolean,webhook_ref:string}`
object. Omission/default is
`{"enabled":false,"notify_broadcast":false,"notify_tcp_closures":false,"webhook_ref":""}`.
Both category flags are nonnull booleans defaulting to false independently of
global enable. Enabled alerts require an existing private
webhook reference. References are device-local 32-character lowercase hexadecimal
strings; empty means unconfigured. Unknown fields, nulls and wrong types reject
with `400`; invalid/missing references or enabling an unavailable backend reject
with `422`. Changes, confirmation, rollback and revision restore require
`transactions.write` and new **`discord.write`**, plus other changed-resource
permissions. Use the existing full candidate and confirmed transaction workflow.
No webhook URL/token is accepted inside networking configuration or exports.

Create the reference with **`POST /api/v1/services/discord/webhooks`**, API key
and `discord.write`, no query, using a JSON object containing only
`webhook_url:string`. It must be a canonical
`https://discord.com/api/webhooks/ID/TOKEN` URL, maximum 512 bytes, with a
nonzero digit ID of at most 20 characters and a 16..256-character token made
of ASCII letters/digits/underscore/hyphen. Other origins, HTTP, credentials,
explicit ports, escaped path components, query strings and fragments are rejected.
Do not echo the URL in UI validation messages or logs.

Synthetic example only; the token is not an actual credential:

```json
{"webhook_url":"https://discord.com/api/webhooks/123456789012345678/synthetic_test_token_that_is_not_a_real_discord_credential"}
```

Success: **`201 {"webhook_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`** (synthetic
reference; use the actual returned reference). Authentication/permission failures
`401`/`403`; wrong method `405`; invalid JSON/URL/query `400`; active transaction
or upgrade `409`; unavailable manager, private storage failure or the
256-webhook storage limit `503`. The URL is stored only in daemon-owned private
storage with the existing credential-store safety checks. There is no URL read,
delete, test-send or arbitrary webhook endpoint. Uploading does not enable alerts,
send a message or create a configuration revision. Use HTTPS management or the
protected local control path; a webhook URL is a secret bearer credential.

**Identity is exactly `(source IP, destination IP, destination port, numeric IP
protocol)`**. Source port, chain, reason, ingress/egress and ruleset are ignored.
TCP flags, payload length and traffic tags are also ignored for identity.
Messages include raw hexadecimal TCP flags (or `unavailable`) and the
record's traffic tags (or `none`). Deny-log query selection and frontend-only
visibility filters do not suppress alerts.
Absent destination port is distinct from numeric zero. One newly observed tuple
produces one alert entry, not one entry per packet. The native logger maintains a
private, durable SQLite first-seen index independent of the rotating drop table;
seen tuples are never expired by time, rotation, disable/enable or restart.
First observation while globally or categorically disabled still marks the tuple
seen and is not backfilled after enabling. Enabling never sends retained history,
including later packets with different tags for an already-seen tuple.
On first feature startup,
existing retained records seed the index without alerts; pre-feature records
already rotated out cannot be reconstructed.

`notify_broadcast:true` permits first drops tagged `ipv4_broadcast` (limited or
live directed IPv4 broadcast). It does not configure multicast notification.
`notify_tcp_closures:true` permits first drops tagged `tcp_finish`, `tcp_reset`
or `tcp_ack_only`: FIN, RST, and flags exactly ACK with a known zero TCP payload
length. Unknown payload length is not empty ACK-only; SYN or data-bearing ACK
does not fall into this bucket unless independently tagged FIN/RST. These are
packet observations, not proof of a closed connection or harmless traffic.
A record in both categories requires both switches enabled. Other newly seen
drops remain eligible when global alerts and firewall capture are enabled.
The switches change Discord delivery only, not firewall verdicts, log collection,
retention, permanent identity or frontend log visibility.

The index stores exact identities (not probabilistic hashes) and queued first
records. It grows with lifetime distinct tuples and outstanding alerts; there
is no automatic eviction or clear endpoint. Preserve it with private state
backups. Native storage/schema/corruption failures are explicit capture/worker
errors, not permission to reset the index or repeatedly notify old tuples.
The existing 100-record/second capture limit and kernel losses still apply:
uncaptured packets cannot generate notifications. Normal rotating-history
retention/counts do not include the separate lifetime index.

Delivery uses committed settings, pauses during active configuration/upgrade
work, and runs only in the native Linux host backend. Simulator mode reports
simulated/disabled and never posts; unsupported mode cannot be enabled.
Eligible pending alerts survive normal restart; global disabling clears pending
delivery without forgetting identities. Category checks apply at enqueue and
again before delivery using current committed settings; excluded queued records
are discarded without backfill. Category-only changes also cancel in-flight
delivery/retry work. Suppressed records are not delivery attempts and increment
neither `delivered` nor `failed`. A queued record is claimed durably before HTTP delivery
to prevent duplicate posts after uncertain results or crashes. Delivery is
best-effort, **not exactly-once guaranteed**: transport failures, non-rate-limit
HTTP failures, interrupted in-flight requests or configuration changes are not
replayed for the same tuple. HTTP `429` alone permits up to three attempts,
respecting the provider's bounded `retry_after` (0..86400 seconds); malformed or
oversized rate-limit replies stop the worker explicitly. Retry waits and HTTP
requests are cancelled promptly on shutdown or configuration changes. A message
already accepted by Discord cannot be withdrawn by disabling or rollback.

Messages batch at most ten first-seen entries, within Discord's 6000-character
embed budget, with normal polling once per second. Each entry includes configured
firewall identity (`system.hostname.system.domain` when both are set, hostname
alone without a domain, or `Firewall` without a hostname), source/destination
and nullable ports, protocol,
input/forward chain, drop reason, interfaces, drop ID, timestamp in UTC epoch
milliseconds and IP packet length in bytes. Firewall identity is the embed
author name, with title `New firewall drop`, keeping a maximum-length full
hostname within Discord's 256-character author limit.
Source/destination endpoints append a device name in parentheses when an exact
IP match has a nonblank Sando `local_description` (cached as `classification`,
up to 512 bytes). Render the description in Unicode uppercase for Discord only;
stored/API descriptions, IPs/ports and the firewall author name keep their
original case. Only that description is used: no Sando `host_name`,
DNS/DHCP/lease hostname or `firewall.policies.hosts[].name` fallback.
Cached descriptions are used only for the current `sando.api_url`, including
retained cache when sync is disabled or a refresh fails.
Unknown endpoints and missing/null/blank descriptions remain IP/port only.
No reverse DNS, external fetch or guessed
subnet/device match occurs during delivery. For example:
`192.0.2.10:53000 (CAMERA) -> 192.0.2.20:443 (SERVER)`.
Names are reporting metadata, not part of permanent deduplication or evidence
of device identity. Longer entries split into smaller messages within the
6000-character total embed budget after uppercasing, including character
expansion, without truncating names or discarding entries.
Device names are additional metadata exported to Discord.
No packet payload, credentials or
webhook URL are included. `allowed_mentions.parse:[]` prevents notification text
from pinging users/roles. HTTPS certificate verification, fixed provider
validation, no redirects, 5-second connect/10-second total timeouts apply.
No firewall permit, forwarding/NAT or unrelated packet behavior is changed.

**`GET /api/v1/services/discord/status`** requires API key and `state.read`,
no query/body, other methods `405`; authentication/permissions `401`/`403`,
invalid query/body `400`, unavailable manager/status `503`. Response:

```json
{"enabled":false,"notify_broadcast":false,"notify_tcp_closures":false,"state":"disabled","delivered":"0","failed":"0","last_drop_id":null,"error":null,"counters_scope":"daemon_session","deduplication":["source","destination","destination_port","protocol"]}
```

`state` is `starting|disabled|simulated|unavailable|paused|ready|error|stopped`;
`delivered`/`failed` are decimal-string **alert-entry** counts (not message or
packet counts), retained through manager restarts within the daemon session.
`last_drop_id` and `error` are nullable strings. No raw URL is returned.
Delivery failures leave the active worker `ready` with a nonnull `error`, a
failure count and a `service_warning` health alert; a later successful delivery
clears the error. A failed delivery is not proof that the worker stopped and is
not replayed. A malformed or unreadable rate-limit response is a delivery
failure, not a reason to stop the worker. `error` state still indicates a
stopped worker that requires the separately reported manager recovery.
The three notification booleans report the manager's current policy; worker
updates normally occur on its one-second tick. Read saved configuration for
authoritative committed settings and do not overwrite a pending draft from status.
The `discord` manager participates in daemon health/task supervision and
`POST /api/v1/processes/restart {"target":"discord"}` (`system.restart`,
normal `202` scheduling); restarting does not enable it or reset seen identities.

Frontend required work: add a global toggle, independent default-off
**Notify broadcast drops** and **Notify TCP FIN/RST/empty ACK-only drops**
controls, and a password-style webhook URL
input, upload privately then save the returned reference in a full candidate,
clear the raw URL from form state after success and never cache/log it.
Render existing-reference/replace states without trying to fetch the secret.
Recognize `discord.write` in credential controls. Explain permanent deduplication,
no globally/category-disabled history backfill, category overlap requiring both
switches, third-party export of drop metadata and best-effort
delivery. Poll status only as appropriate for the settings/status view; expose
errors and entry counts without suggesting failed tuples will be re-sent.
Deploy the accepting backend first, preserve the private webhook/index stores,
and verify DNS/routes/outbound HTTPS to Discord from the firewall. No automatic
port opening, external program or operator-provided signing key is required.
Register both new routes in the API Explorer.

#### Deny-log viewer requirements

Frontend action: recognize `firewall.logs.read` and distinguish unsupported,
unauthorized, healthy-empty, capture-error, rate-loss and retention-gap states.
A dedicated **Deny log** viewer with refresh, filters and Load older is optional;
if implemented, use this endpoint only while visible/on explicit request rather
than adding traffic records to general polling. Display timestamps with units/
timezone, nullable ports/interfaces, protocol and attribution; never claim an
empty/limited log proves traffic was allowed. It excludes other firewall owners,
route blackholes, qdisc/checksum drops and accepted/established traffic.
Deployment requires NFLOG/nft_log kernel support, exclusive group 100, current
native privileges and private writable storage; no syslog enablement or external
daemon. See [operator requirements](docs/BUILD_AND_INSTALL.md#firewall-deny-logging)
and [handoff 2026-10-29-09](docs/frontend-handoffs/2026-10-29.md#2026-10-29-09-firewall-deny-history).

#### Bulk deletion of firewall hosts and forwarding rules

Optional bulk-action UI: provide a clearly destructive **Delete all firewall
hosts and forwarding rules** action with an explicit scope preview. This is not
a factory reset, a complete firewall reset, or connection-state deletion.

`DELETE /api/v1/firewall/hosts-and-rules` requires an API key with both
`transactions.write` and `firewall.write`, even when already empty. It accepts
no query parameters and requires this JSON body (synthetic revision; use the
current revision from `GET /api/v1/revisions/latest`):

```json
{
  "base_revision": "2026.10.30.1",
  "confirm_timeout_seconds": 30,
  "confirm": true,
  "description": "Clear reviewed firewall hosts and forwarding rules"
}
```

`base_revision` is a canonical calendar-version string; timeout is an integer
10..300 seconds; `confirm` is the required literal boolean `true`. Optional
`description` is trimmed, limited to 1024 UTF-8 bytes and defaults to
`Clear firewall hosts and forwarding rules` if blank. Unknown request fields,
including `config`, are rejected; the server builds a candidate from the current
committed config without replacing unrelated settings.

Exact effect:

- Clear legacy `firewall.rules`.
- Clear `firewall.policies.hosts`, including every host's attached rules/default.
- Clear every `firewall.policies.interfaces[*].rules`. Preserve interface-policy
  entries/metadata and whether `firewall.policies` is present.
- Preserve `firewall.policy`, `firewall.allow_all_icmp`, all
  `firewall.nat.masquerade`/`destination_rewrite`, and all `firewall.input`
  rules/defaults. Preserve interfaces, routing, services, Sando settings/import
  reports/cache and all other configuration.
- Do not flush conntrack or remove other applications' nftables tables.
  Automatically generated ICMP/established rules remain according to the
  unchanged policy mode/settings. This is removal of configured forwarding
  rules, not a promise that the kernel ruleset becomes literally empty.

Success is `202` with the ordinary `Transaction` object and
`Location: /api/v1/transactions/{id}`. The candidate is **already applied
provisionally**, not merely queued. Committed config/revision remain unchanged
until `POST /api/v1/transactions/{id}/confirm` (`200`, normal transaction and
changed-resource permissions). Explicit `/rollback` or confirmation expiry
restores the prior configuration; standard restart recovery, drift checks and
durable intent apply. Confirmation allocates one normal current-day config
revision. History/restore retains the original hosts/rules. Already-empty
configuration still produces a normal pending transaction; it is not an
immediate-success special case.

Errors use `{error,transaction}`: `401` invalid/missing key, `403` either required
permission missing, `405` method other than DELETE, `400` missing/invalid JSON,
unknown fields, noncanonical revision/type, non-true confirmation or query;
`422` invalid timeout/overlong description/candidate validation, `409` stale
revision, active transaction, drift, upgrade/restart guard; ordinary backend/
persistence failures are `500` with a transaction when one was created.
Resolve uncertain writes through transaction/state reads; never blindly retry
with a newer base revision. No automatic confirmation or privilege bypass.

Frontend tasks if adopting this action: show the exact removed/preserved scope and warn that retaining
a global Drop default can stop forwarding, while removing drops under Accept
can broaden access. Keeping input rules does not guarantee remote connectivity.
Require explicit destructive acknowledgement before DELETE, then use the normal
confirmation countdown and rollback controls. Refresh hosts, forwarding rules,
revision/history and pending-transaction views after confirmation/rollback.
Keep Sando discovery metadata distinct from configured firewall hosts; clearing
the firewall must not silently reimport discoveries. Do not label preserved NAT/
input rules as deleted. See
[handoff 2026-10-29-08](docs/frontend-handoffs/2026-10-29.md#2026-10-29-08-bulk-firewall-host-and-forward-rule-deletion).

Per-rule packet/byte match counters use the dedicated endpoint below. Existing
connection accounting cannot be interpreted as cumulative rule hits.

#### Firewall rule match counters

`GET /api/v1/statistics/firewall` requires API-key authentication and `state.read`.
It accepts no nonempty query or request body (`400`). Only GET is supported
(`405`); invalid/missing credentials are `401`, missing permission `403`, and
unknown GET suffixes `404`. Reads do not apply configuration, clear counters,
flush connections, start logging or allocate revisions/transactions.

Native success is `200`, schema `netcontrol-firewall-counters/v1`:

```json
{
  "schema": "netcontrol-firewall-counters/v1",
  "sample": {
    "scope": "example-namespace",
    "status": "available",
    "started_at": "2026-10-30T06:00:00Z",
    "collected_at": "2026-10-30T06:00:00.010Z"
  },
  "config_revision": "2026.10.30.1",
  "transaction_id": null,
  "ruleset_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "generation": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "rules": [{
    "id": "forward:/firewall/policies/hosts/0/rules/0",
    "chain": "forward",
    "config_path": "/firewall/policies/hosts/0/rules/0",
    "origin": "manual",
    "import_source": null,
    "expanded_rules": 4,
    "packets": "9007199254740993",
    "bytes": "576460752303423552"
  }]
}
```

This is a synthetic shortened example, not measured traffic. Native returns
all instrumented logical rows, including measured zeros, ordered by chain/key.
`sample.scope` is opaque; timestamps are UTC RFC3339 and bracket collection,
not an atomic global measurement instant. `ruleset_id` is the lowercase SHA-256
of the applied operational firewall and compiled input plan, including
interface-derived DHCP relay permissions and Spoof Block plans, matching deny-log ruleset identity.
Treat it as opaque; changing LAN addresses/roles or relay settings can change this ID even when saved
firewall JSON is unchanged.
`generation` is a lowercase SHA-256 token incorporating a fresh ruleset-installation
UUID and physical chain/handle set; treat it as opaque, not a software/config version.
`config_revision` is the currently committed canonical calendar revision.
`transaction_id` is the active provisional transaction ID or null. During a
transaction, counters describe its **applied candidate**, not the saved revision;
after confirmation/rollback refresh both metadata and the relevant config.

Each row has a unique `id` (`chain:logical-key`), `chain` string, nullable
`config_path` JSON pointer into that applied normalized configuration, positive
integer `expanded_rules`, and nonnegative decimal-string `packets`/`bytes`.
Each row also has `origin:RuleOrigin` and `import_source:string|null` as specified
under [rule origins](#firewall-rule-origins). Generated/default/setting rows are
system-owned; configured rule rows use the matching applied configuration labels.
Use BigInt/exact integer arithmetic: physical u64 counters are summed as u128,
which can exceed both JavaScript safe integers and u64. There are no
per-second fields, historical totals, unique-connection counts or rule names
in these rows. Resolve names/actions from the matching applied config.

Supported configured paths:

- Forward: `/firewall/rules/{index}`,
  `/firewall/policies/interfaces/{index}/rules/{rule_index}`,
  `/firewall/policies/hosts/{index}/rules/{rule_index}`,
  `/firewall/policies/hosts/{index}/policy`, `/firewall/policy`.
- Input: `/firewall/input/interfaces/{index}/rules/{rule_index}`,
  `/firewall/input/policy`.
- NAT: `/firewall/nat/masquerade/{index}` (`postrouting`) and
  `/firewall/nat/destination_rewrite/{index}` (`destination_rewrite`).
- The IPv4 ICMP exception has `/firewall/allow_all_icmp` in each of
  `forward`, `input` and `output` when enabled. Distinguish these by chain/ID.
- Spoof Block terminal drops have `/firewall/spoof_block` in
  `input_spoof_block` and `forward_spoof_block`. Their generated return rows and
  fallthrough semantics are defined in [Spoof Block](#spoof-block).

Generated keys have `config_path:null`: `generated/forward/established_related`
in host-policy mode, `generated/input/loopback` and
`generated/input/established_related` with configured input,
`generated/input/policy` for the ICMP-only generated input chain, and
`generated/output/policy` for the ICMP output chain. Their IDs still contain
the generated key. Enabled DHCP relays additionally expose
`generated/input/dhcp_relay/<interface>/clients` (two physical rules: limited
broadcast and selected relay address) and
`generated/input/dhcp_relay/<interface>/servers` (one physical rule per configured
server). These accepts precede configured input rules and are present even without
an explicit input configuration. They have system origin and null import source.
Interface names are managed kernel names, not array indexes; refresh the rows
when relay configuration changes. Chains/rules absent from the compiled firewall have no rows.
Empty rule lists still have their instrumented terminal default.

All physical address, destination-host, family and port expansions for one
logical key/chain are summed. A counter increments **after matching**, before
logging/verdict/NAT. Evaluation order and accept/drop precedence are unchanged.
Established/related acceptance in host/input mode, loopback and ICMP bypasses
can prevent later user rules from seeing traffic; those generated/exception
rows count separately. Counters do not retroactively attribute bypass traffic.
NAT evaluates initial packets of new conntrack mappings, not every established
packet. Bytes are nftables packet lengths, not Ethernet/interface/application
throughput; other firewall owners and non-nftables drops are excluded.

Ruleset replacement resets counters on network apply, rollback, startup/service
repair, compiler refresh and reboot. Even unchanged firewall definitions can
reset during other network changes; metadata-only changes may preserve them.
Closing/reopening the native backend alone preserves the kernel generation,
but normal daemon startup runs repair and refreshes it. Nothing is persisted
or restored from configuration history; no reset API is provided.

Before calculating rates, require matching scope, generation, ruleset identity
and row ID, exact nondecreasing values and elapsed collection time. Discard
deltas after change/decrease/error/row disappearance, or on first/simulated
samples. Array indexes are not durable rule IDs. Do not join old samples or
deny-log compiled indices to current rows solely by array position.

Reads verify owned configuration/fingerprint before and after the dump.
Only numeric counter values are excluded from drift fingerprints; identity,
matches, log/verdict expressions, ordering and other attributes remain checked.
Malformed, interrupted, mismatched-generation/layout, unsupported, missing-owned-
firewall, drift or over-limit reads return `503` with `{error, transaction:null}`,
not partial rows or available zeros. Bounds: 81920 physical rules, 64 MiB per
dump, five-second receive budget per dump and 1 MiB maximum datagram; decoding
and the multiple ownership-verification dumps add overhead.

Simulator returns the same schema with `sample.status:"simulated"`,
scope `"simulator"`, UTC timestamps, `generation:null`, `ruleset_id:null`, and
`rules:[]`; config revision/transaction identity still reflect the engine.
This is explicitly unmeasured, not an available empty kernel snapshot.

Frontend action: add the client types/endpoint and replace claims that rule
counters are unavailable. Optional per-rule counter UI should fetch only while
visible/on refresh, avoid overlapping requests, show freshness/reset/error
states, and keep samples out of browser persistence/config exports/general
state polling. No counter form fields or write transaction are needed.
Per-rule counters are not embedded in aggregate statistics, runtime, MQTT or health.
MQTT alone publishes a bounded aggregate summary, including overall managed
firewall dropped packets/bytes and reset identity; see
[MQTT streaming](#614-home-assistant-mqtt-streaming). This does not publish per-rule
rows or replace the on-demand counter API.
Native deployment requires `CONFIG_NF_TABLES` (`nf_tables` or built-in),
alongside the existing NFLOG prerequisites and namespace/net_admin privileges.
Current kernels include counter expressions in `nf_tables`, not a separate
`nft_counter` module. Ubuntu install/full upgrade loads/persists the core
provider; build-only does not.
See [handoff 2026-10-29-10](docs/frontend-handoffs/2026-10-29.md#2026-10-29-10-firewall-rule-match-counters).

### 6.6.1 Host input filtering

`config.firewall.input` is optional/nullable. Omitted/null means no explicit
input filter (apart from the global ICMP exception); normalized reads omit it
when absent. A configured object requires `policy: "accept" | "drop"` and
accepts `interfaces` (omitted defaults to an empty array). Each ingress policy
requires a managed `interface` and ordered `rules` (omitted defaults empty).
Input rules reuse destination prefix, Any/TCP/UDP/ICMP/ICMPv6 protocol, destination-port list
and action from host policy rules; nonempty `out_interface` and
`destination_host` are rejected. Input does not support host identity matches.
Types/null-in-nonnullable-fields/unknown-field errors are 400; invalid policy,
unmanaged ingress, invalid ports/prefixes or forbidden nonempty matches are 422.
Changes require `firewall.write` and `transactions.write`, not a new permission.

Configured-input precedence is global IPv4 ICMP acceptance if enabled, then
implicit loopback acceptance, implicit established/related acceptance, ordered
ingress rules, and finally the input default. Local output is not filtered.
Input and forwarding are distinct views; neither input defaults nor rules
authorize forwarded traffic. Preserve both through full-package edits/history.
The existing policy limits apply: at most 32 unique managed ingress entries,
320 ordered rules each, 32 explicit TCP/UDP destination ports per rule,
320 KiB (327680 bytes) serialized policy metadata and 20480 total native input
entries including established/related, implicit loopback and generated DHCP-relay
permits. Core policy validation counts established/related but not the generated
loopback/relay entries; native compilation enforces the final total. Rule order is semantic; port lists and unique
ingress entries are normalized by sorting.

Explicit factory reset creates input default-drop, LAN allow-all, and WAN
IPv4 UDP destination-port 68 acceptance for DHCP. Loopback and replies remain
implicit. The forwarding policy has a LAN allow-all rule without egress matching,
default-drop for other new traffic, and stateful returns. NAT remains restricted
to LAN-subnet IPv4 traffic exiting WAN. Show the DHCP exception and implicit
rules clearly; deleting the DHCP/LAN allowances can affect reachability/renewal.
Explicit factory reset sets `firewall.allow_all_icmp: true`. Initial provisioning
instead retains supported imported policy; imported existing chains disable
the default implicit ICMP bypass rather than silently widening their policy.
This allows all IPv4 ICMP types/codes on every interface, including WAN, before
input/forwarding drops, and accepts local IPv4 ICMP output. It does not cover
ICMPv6. Show the enabled exception rather than describing WAN as blocking all
new traffic. Ordinary startup/upgrades do not rewrite existing saved values.
Warn before removing the input policy: doing so removes WAN host protection.

### 6.7 NAT

#### Masquerading

Ordered table/editor: position, family (`ipv4`/`ipv6`), optional source network or
Any, managed egress interface. Provide move up/down as well as add/edit/delete.

Filter IPv4 egress choices to draft interfaces with a static IPv4 address or
a configured DHCPv4 client. IPv6 still requires a static IPv6 address.
Explain missing options and link to interface editing. Switching family must
revalidate source and egress rather than silently rewriting values.

Show: “Masquerading does not enable forwarding, create routes, or bypass filter
rules.” No general static translation or port-forward controls. NAT edits remain separate
from filter edits for review and permissions, but share the same transaction and
owned nftables table.

#### Destination rewrite

Expose `firewall.nat.destination_rewrite` as an ordered rule editor titled
**Destination rewrite**. This is destination NAT (DNAT), not 1:1 NAT.
Previously only `masquerade` was available; reads now include both arrays,
including empty `destination_rewrite: []`. Omission defaults to an empty array;
null is invalid. No new endpoint or permission is introduced.

Each rule requires:

| Field | Type and contract |
| --- | --- |
| `out_interface` | Up managed interface with role `wan`; matches the original destination's route before rewriting, not the rewritten packet's outgoing interface. Requires a static address of the target family, or DHCPv4 for an IPv4 target. |
| `protocol` | Exactly `"tcp"` or `"udp"`. Use two rules for both DNS transports. |
| `destination_port` | Integer 1..65535, exactly one port; no ranges, lists, source filters or port translation. |
| `target_interface` | Up managed interface with role `lan`, with a static subnet containing the target. Validation/reference field; ordinary routing still determines how packets reach the target. |
| `target_address` | Canonical unicast IPv4/IPv6 literal, another device on the selected LAN subnet, not any configured firewall address, loopback, link-local, multicast, unspecified, IPv4 subnet network/broadcast or mapped IPv6. Determines the matching original IP family; no cross-family NAT. |
| `metadata` | Optional standard display name/description. Cosmetic edits still require `nat.write`. |

At most 256 rules. Duplicate `(out_interface, protocol, destination_port,
IP family)` matches are rejected, even with different targets. IPv6 rules require
`ipv6_enabled: true`. Interface role/down/address changes and deletions must
resolve dependent rules in the same complete candidate. Target IPs are not
probed and no service reachability is promised.

Synthetic `firewall.nat` fragment for Internet-bound DNS interception:

```json
{
  "masquerade": [],
  "destination_rewrite": [
    {"out_interface":"wan0","protocol":"udp","destination_port":53,
     "target_interface":"lan0","target_address":"192.168.10.53"},
    {"out_interface":"wan0","protocol":"tcp","destination_port":53,
     "target_interface":"lan0","target_address":"192.168.10.53"}
  ]
}
```

Native rules run in prerouting at DNAT priority, before the routing decision and
ordinary forwarding filters. A kernel FIB lookup of the original destination
(including source and packet mark) must resolve through `out_interface`.
LAN-routed destinations, other ports/protocols/families and firewall-originated
Internet traffic are not intercepted. Rules preserve destination port and client
source IP. Conntrack reverses translation on replies, so clients see the original
destination. Matching changes apply to new connections only; existing conntrack
translations survive edits, removal and rollback until expiry or explicit
connection deletion. Do not silently flush connections on configuration changes.

**Required warning:** The target's replies must route back through this firewall.
For clients and target sharing a subnet, direct replies bypass reverse NAT and
usually break the connection. Require operator-arranged routed return paths or
a separate target subnet. There is no automatic source NAT/hairpin masquerade.
Other explicitly configured masquerade rules still apply normally. Do not add a
source-NAT toggle or silently change the source address.
There is no automatic exemption for the target device's own forwarded traffic:
if its upstream DNS queries use the selected WAN and port 53, they are rewritten
too. Configure the resolver's upstream path/transport so it does not match these
rules; otherwise DNS resolution can loop or fail.

**Filtering/routing:** DNAT does not grant access or create routes. Forward rules
see the rewritten destination and actual LAN egress; a rule allowing only WAN
egress may need a separate explicit allow to the local target. Include that filter
change in review; never automatically insert an accept. Global forwarding,
working routes/return paths and nftables inet FIB/NAT kernel support are operator
prerequisites. IPv6 forwarding is not enabled by the installer.

Save via `POST /api/v1/transactions` with `transactions.write` and `nat.write`
(plus permissions for other changes). Confirm/rollback/history restore and
recovery use the existing workflow. Read via `GET /api/v1/firewall/nat`,
`GET /api/v1/firewall/rules` or state/config views, with `state.read`.
Missing/wrongly typed required fields (including port values outside the
unsigned 16-bit range) return `400`; port zero, invalid references,
target subnet/family, duplicate matches or collection limit return `422`;
normal authorization/conflict/drift/native failure statuses remain unchanged.
Structurally typed configuration rejects unknown fields; the transaction endpoint
retains its documented unknown-field pruning and reports `ignored_fields`.
Do not submit unsupported source/range/target-port fields.

Frontend tasks: add client types, add/edit/delete/reorder controls, WAN/LAN role
and family-aware options, exact-port and target validation, separate TCP/UDP DNS
rows, metadata and dependency handling, ordered diff/history rendering, and
prominent source-preserving return-route/new-connections/filtering warnings.
Deploy the backend before enabling the editor; preserve `masquerade` and all
unrelated candidate sections. Validate routed TCP/UDP replies, bypass cases,
default-drop filtering, errors, persistence and rollback on a Linux test router.
Simulator results do not prove packet forwarding.

### 6.8 WireGuard

Show WireGuard interfaces and peers using the same underlying draft as Interfaces.
Fields: key reference, stable listen port, peer public key, optional numeric or DNS
endpoint, allowed network list, persistent keepalive seconds, and a per-peer
`enabled` toggle.

#### DNS peer endpoints

`endpoint` remains an optional nonnullable string: omit/empty for no configured
endpoint, canonical numeric `IPv4:port` / `[IPv6]:port`, or lowercase ASCII
`hostname:port` such as `vpn.example.test:51820`. DNS names use nonempty labels
of 1..63 letters/digits/hyphens, no leading/trailing hyphen, at most 253 bytes,
no trailing dot, whitespace, underscore, URL scheme/path or service-name port.
Single-label host aliases are accepted; use a fully qualified name for DNS
rather than relying on search suffixes. Ports are canonical decimal 1..65535.
Wrong field types/null return `400`; invalid syntax returns `422`.

The backend, not the browser, resolves enabled DNS peers using its existing
bounded native `/etc/hosts` and `/etc/resolv.conf` UDP A/AAAA resolver in the
managed namespace. It supports untruncated replies/CNAMEs, not TCP fallback,
DNS-over-HTTPS or browser DNS. Resolver reachability must not depend on the
tunnel being bootstrapped. First use needs a usable answer; a cold lookup or
cache-persistence failure fails the normal transaction (`500`, with its
transaction/rollback outcome), not a silently empty endpoint.

Automatic refresh runs immediately and then waits 60 seconds between cycles,
plus lookup/processing time; DNS TTL does not change this interval. Retain the
selected address while it is still returned; otherwise select deterministically,
preferring IPv4. Disabled global IPv6 permits only A/IPv4 results and IPv4 DNS
servers. No compatible answers or later lookup/update failures retain the last
successful selection and report an error. Cached successful selections persist
in private native state for restart/rollback, so a resolver outage does not erase
working peer configuration. Disabled peers are neither resolved nor refreshed.

Refresh updates only the endpoint of the existing device/peer identity, not keys,
AllowedIPs (including BGP-owned prefixes), keepalives, revisions or transaction
history. Workers stop/join before link/peer reconfiguration, rollback or removal.
DNS-selected endpoints and authenticated roaming are runtime transport state,
not numeric endpoint drift; explicitly numeric endpoints retain strict drift
checks. Preserve the configured hostname in drafts/desired/observed config;
do not replace it with a runtime IP or resolve it in the frontend.

`GET /api/v1/state` (`state.read`) adds native `runtime.wireguard_dns`:

- `running: boolean`, `refresh_interval_seconds: 60`, `error: string | null`.
  False with no DNS peers is normal; a worker-level error is not successful DNS.
- `peers: []` for no enabled DNS peers; otherwise one row per interface/public-key
  identity with `interface`, `public_key`, configured `endpoint`,
  `ipv6_enabled`, `resolved_endpoint` (numeric socket string),
  `last_attempt_unix_ms`, `last_success_unix_ms` (nonnullable Unix ms numbers),
  and nullable `error`. Selected cache state is not a connectivity guarantee;
  actual roaming endpoints remain under `runtime.wireguard[].peers[].endpoint`.
- Show refresh failures and last success separately from handshake/traffic.
  Keep the configured name visible alongside selected/actual addresses.
  Simulators need not report this native-only measurement; do not fabricate it.

There is no new config flag, interval form, endpoint or permission. Changing the
existing endpoint uses `POST /api/v1/transactions`, normal confirmation/rollback,
`transactions.write` and `wireguard.write` (plus other changed-component
permissions). Deploy the updated backend before enabling hostname entry.

Peers accept `enabled: boolean`; omission defaults to `true` in requests and saved
configurations (including revision records), and canonical responses always include
it. Explicit `null` or non-boolean values return `400`. New-peer forms should start
with `true`; preserve explicit `false` rather than using a truthiness default. A
disabled peer keeps its full settings and metadata in desired configuration, drafts,
transactions, revision history and exports, but is **not installed** on the interface:
its handshake and traffic stop, and re-enabling installs it again with a fresh
handshake. Toggling is an ordinary complete `POST /api/v1/transactions` with normal
confirmation and rollback, requiring `transactions.write` and `wireguard.write`.
There is no per-peer endpoint or new permission. Disabled peers still require a valid,
unique public key and canonical allowed networks (and obey the IPv6 policy), but a
disabled peer may reuse an allowed network that an enabled peer uses, so a spare can
be staged; only enabled peers (and a single peer's own list) must not duplicate.
Native runtime lists only installed peers, so a disabled peer has no runtime row,
handshake or byte counters; do not show stale values for it. Disabling the only
peer that carries management traffic cuts that path, so warn before committing.
Peer identity stays the public key; `enabled` is not part of identity.

Show key reference as a name, never a filesystem path. No private-key input,
reveal, upload, download, or browser key generation. Explain immutable operator
key files and retention of old references for recovery/history.

Public keys may be truncated in tables with accessible full-text/copy controls.
Do not label a configured peer connected. Native runtime diagnostics can include
measured public peer handshake/transfer information; these are optional
observations, not a dedicated peer-statistics API or proof of reachability.
Do not fabricate telemetry when absent or simulated.
Numeric endpoint roaming can create modeled drift; surface it without overwriting
the draft automatically. DNS/omitted endpoints have the dynamic behavior above.

### 6.9 softflowd

The complete implementation reference (capture and flow semantics, wire formats,
expiry rules, runtime fields, prerequisites and non-goals) is
[docs/NETFLOW_IPFIX_SPEC.md](docs/NETFLOW_IPFIX_SPEC.md). This section is the UI
contract; that document is the detailed behavior reference.

Table: name, desired enabled, observed enabled, capture interface, collector,
export version, native worker state/start time when supplied, error, staged state.
Desired enabled is an inline per-row toggle (`softflowd[].enabled`, same pattern as
gateway monitors and static routes) that stages the change in the shared draft; it
never issues a live request and disabled entries remain fully validated and retained.
The create action is labelled **Add export** (not "Add instance"); it opens the editor
with the same fields. No backend change: enable/disable already uses the existing
`softflowd.write` permission and complete configuration transaction.

Editor: name, enabled, capture interface, numeric collector address/port, export
version, sampling rate, maximum flows, snap length, promiscuous capture, optional
capture filter chosen from empty, `ip`, `ip6`, `tcp`, `udp`, `icmp`, `icmp6`,
and optional timeout overrides. Arbitrary BPF expressions are not supported.
Fragments and IPv6 jumbograms are excluded. Versions 1/5 export IPv4;
9/IPFIX support IPv4 and IPv6. Version 1 cannot convey sampling metadata:
show `sampling_metadata: false` without inventing unsampled traffic totals.

Capture interface options include managed draft interfaces and available adopted
parents. Mark adopted parents protected. Timeout overrides are optional named
entries; absence means native worker defaults, not zero.

Display runtime states:

| Value | UI label |
| --- | --- |
| `running` | Running; local responsiveness checked, delivery not verified |
| `disabled` | Disabled |
| `simulated` | Simulated; no real capture process |
| `error` | Worker failed; display error |
| `stopped` | Worker stopped |
| Unknown future value | Unknown status, retaining raw value |

Missing runtime data means Unknown, not Disabled. Keep top-level runtime error
visible even if individual rows appear healthy.

Native AF_PACKET packet drops no longer stop export or fail service verification
by themselves. Runtime/status rows expose `dropped_packets` (exact unsigned decimal
string) and `statistics_complete` (boolean). Enabled native workers initialize
these to `"0"` and `true`; each export-scan poll accumulates socket drops and any
observed loss makes statistics incomplete until worker restart. Shutdown retains
the values. These are socket drops before application filtering/sampling, not a
count of lost flow records. Capture/statistics socket errors and export failures
still produce `state: "error"` and can fail confirmation.

Show an inline warning naming the instance and exact dropped-packet count when
`statistics_complete === false`; explain that flow totals may undercount traffic
while export can continue. Do not convert the decimal counter through JavaScript
`Number`. Absent fields (disabled, simulated or unavailable rows) mean unknown,
not zero/complete. Do not label a running worker as loss-free or delivery-verified.
No automatic retry, reconciliation or transaction replay is warranted by this
warning; the existing unknown-write recovery rules still apply.

**Reconcile services** is a separate explicitly confirmed runtime action. It sends
a bodyless POST using stored committed/pending configuration, not the draft.
Explain that it affects managed services collectively, may lose flow caches, does
not replay networking, and creates no revision. Do not suggest per-instance restart
or automatically retry it. Block it during applying/rolling-back/recovery-failed
states; it is allowed by the backend during pending confirmation.

This includes the shared DHCP relay worker. Require permissions for all enabled
services and warn that repair may briefly interrupt DHCP relay on every enabled
interface, not just softflowd.

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
  request export. Export no API key or frontend-only metadata.
- For a one-request committed configuration download, use
  `GET /api/v1/revisions/latest` and export its complete `config` object. Label
  this **Download committed configuration**: pending-confirmation candidates
  may be temporarily applied but are not included. This is not a full-device
  backup; external secret files, device accounts/API keys and runtime state are
  not included. Keep the sensitivity notice and operator-initiated download.

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
the server-supplied nullable `committed_revision`, populated only after commit;
never compute it from `base_revision` or substitute the latest server revision.

Keep nonterminal states and errors visible after navigation and reconnect.
There is no backend `failed` terminal status; failed applies normally become
`rolled_back` or `recovery_failed`. A rollback `error` can be a reason rather than
evidence that recovery itself failed. No reliable rollback timestamp or rollback
actor field is supplied; do not invent either.

### 6.12 Committed history and restoration

- Newest revision first, using server pagination and numeric date/iteration ordering.
- Columns: revision/current badge, description, submitted/committed dates,
  submitted/committed actors, transaction link, restored-from revision.
- Null dates show **Unknown (legacy record)**. Omitted actor shows **Unknown**.
  The initial date-version revision has only initialization date/system attribution.
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
  apply. Restoring the initial revision may remove all owned resources; show the full impact.
- Preserve `restored_from_revision` exactly; absence means no restore source.

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
- Prefix spelling must match canonical IP prefix output, including compressed
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
| Kind | `ethernet`, `dummy`, `wireguard`, `vlan`; existing kind cannot change in place; Ethernet must already exist |
| MTU | 1280..65535 |
| VLAN | Required only for VLAN kind; parent valid/known, ID 1..4094; unique parent/ID pair; no cycles, self-parent, or WireGuard parent; child MTU <= parent MTU |
| WireGuard settings | Required only for WireGuard kind; do not send on other kinds |
| Key reference | `^[a-zA-Z0-9_-]{1,64}$`; no path; availability/private file checks are server-side |
| Listen port | 1..65535; stable nonzero port required |
| Peer public key | Base64 decodes to a nonzero 32-byte WireGuard key; unique within interface |
| Endpoint | Optional canonical IP:port (IPv6 bracketed) or lowercase DNS hostname:port; canonical decimal port 1..65535; no URL, zone, mapped IPv6, trailing dot or non-DNS label characters |
| Allowed IPs | Canonical networks; exact duplicates prohibited within a peer and across all **enabled** peers on that WireGuard interface (a disabled peer may reuse one); overlaps are not generically forbidden |
| Keepalive | 0..65535 seconds; 0 means disabled |
| Route destination | Canonical network |
| Route gateway | Optional canonical numeric address; same family as destination, no mapped IPv6 or zone |
| Route interface | Must exist in managed draft interfaces |
| Route table | 254 (main) or 10000..19999 |
| Route metric | 0..2147483647; zero preserves the kernel's default static-route priority |
| Route uniqueness | `(table, destination, metric)` unique, even if device/gateway differs |
| Policy source | Canonical network |
| Policy priority | 10000..19999, unique across policy rules |
| Policy table | 254 or 10000..19999; reuse across rules allowed |
| Filter policy/action | Exactly `accept` or `drop` |
| Filter prefixes | Optional canonical source/destination networks; same family when both supplied; both may be empty |
| Host inventory | At most 128; unique ID `^[a-zA-Z0-9_-]{1,64}$`; unique nonblank name <=80 bytes, no outer whitespace/control characters |
| Host addresses/default | 1..16 canonical unicast IPv4/IPv6 addresses, globally unique across hosts; no CIDR, mapped IPv6, zones, loopback or link-local; required accept/drop default |
| Filter protocols | Omitted/empty Any, `tcp`, `udp`, `icmp` (IPv4 only), `icmpv6` (IPv6 only, requires ipv6_enabled); all types/codes; incompatible families rejected |
| Host/interface rules | At most 320 ordered rules per host/interface (also input ingress); the five filter protocol choices; accept/drop |
| Legacy ordered rules | Same protocol/port contract; at most 20480 port-expanded entries; preserve order |
| Policy destination | Omitted = Any; existing `destination_host` ID or canonical `destination` network, mutually exclusive; host rule needs at least one compatible source/destination family |
| Destination ports | Optional <=32 unique integers 1..65535; requires TCP/UDP |
| Interface overrides | <=32 unique valid ingress names, managed in draft or operator-adopted; no interface default/final verdict for unmatched traffic |
| Policy expansion | <=320 KiB (327680 bytes) serialized policy metadata and <=20480 generated forwarding rules, counting stateful and host defaults; backend authoritative |
| Masquerade family | Exactly `ipv4` or `ipv6` |
| Masquerade source | Optional canonical network matching explicit family |
| Masquerade egress | Managed draft interface with an address of matching family, or a DHCPv4 client for IPv4 |
| Destination rewrite | <=256 rules; up managed WAN/LAN, canonical usable LAN target on another device; exact TCP/UDP port 1..65535; unique WAN/protocol/port/family; IPv6 requires global enable |
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
| Sampling rate | 1..1000000; 1 means unsampled; native v5 is limited to 16383 |
| Max flows | 1..1000000 |
| Snap length | 64..65535 bytes |
| Capture filter | Optional; exactly empty, `ip`, `ip6`, `tcp`, `udp`, `icmp`, or `icmp6` |
| Timeout names | Only `general`, `tcp`, `tcp.rst`, `tcp.fin`, `udp`, `icmp`, `maxlife`, `expint` |
| Timeout values | 0..604800 seconds; `general`, when present, must be >= 1 |

Disabled entries still require valid fields. Capture capability and native integration are preflight/runtime
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
- JSON-body requests have a 1 MiB limit; unknown envelope fields/trailing JSON values fail.
  Unknown keys inside a submitted `config` are dropped and listed instead.
  Measure the complete serialized UTF-8 request, not only the config.
- GET success and lifecycle/reconcile POST success are `200`; submit/restore
  success are `202` with `Location` and a transaction body. Submit also returns
  `ignored_fields` (see below).
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
| GET | `/interfaces/discovered` | Read-only `DiscoveredInterface[]`; independent of managed-state observation |
| POST | `/interfaces/adopt-vlan` | Strict `{name,parent,id}`, no query -> `200 {revision,interface}`; `interfaces.write` + `transactions.write`, explicit preserved-baseline ownership handoff |
| GET | `/interface-capabilities` | Persisted `InterfaceCapabilitySnapshot \| null`; `state.read`, no implicit scan |
| GET | `/interface-capabilities/refresh` | No body/query -> `200 InterfaceCapabilitySnapshot`; `state.read` + `interfaces.write`, explicit passive scan and durable save; never auto-run/prefetch/poll |
| GET | `/statistics/performance` | No body/query -> live host CPU/IRQ/softnet, physical/WireGuard RX queues and physical-only RPS trial evidence; `state.read`, no tuning or persisted scan |
| GET | `/kernel/tunables` | Desired/configured/effective/observed/original kernel maps, including explicit RPS masks and native read-only identity evidence |
| GET | `/interfaces/{name}` | One observed `Interface` |
| POST | `/processes/restart` | `{target}` -> targeted worker `200` or manager/daemon scheduling `202`; `system.restart` |
| POST | `/diagnostics/dns-lookup` | Timed configured- or explicit-resolver diagnostic result `200`; `diagnostics.run` |
| POST | `/diagnostics/path-tests` | Arm paired short-lived MTU/MSS test, `202`; `diagnostics.run` + `interfaces.write` + `firewall.write`; temporary MTU/peer-specific firewall lease |
| GET | `/diagnostics/path-tests` | Current/last session and restoration status, `200`; `state.read`, no body/query |
| POST | `/diagnostics/path-tests/{id}/cancel` | Cancel and restore owned temporary state, `200`; same three start permissions, no body/query |
| POST | `/interfaces/{name}/dhcp/retry` | No body or `{}` -> `202 {interface, status: "retrying"}`; `interfaces.write`, runtime only |
| GET | `/vlans` | Observed VLAN `Interface[]` |
| GET | `/wireguard` | Observed WireGuard `Interface[]` |
| GET | `/routes` | Observed `Route[]` |
| GET | `/routes/bgp` | BGP-only learned/selected/installed path rows; not desired static routes |
| GET | `/routes/bgp/advertised` | Exact established-session advertised prefixes per neighbor; not peer acceptance |
| GET | `/services/bgp` | Committed `BGPConfig` |
| GET | `/services/bgp/status` | Applied BGP worker and neighbor summary |
| GET | `/firewall/rules` | Observed `FirewallView`: Firewall fields plus read-only compiled `system_policies` |
| GET | `/firewall/deny-log` | Filtered persistent deny history, capture/loss/retention status; `firewall.logs.read` |
| GET | `/firewall/hosts` | Observed `FirewallHost[]`; empty in legacy mode |
| GET | `/firewall/interface-policies` | Observed ingress `InterfacePolicy[]`; empty in legacy mode |
| GET | `/firewall/nat` | Observed `{ "masquerade": [...], "destination_rewrite": [...] }` |
| GET | `/services/softflowd` | Observed `SoftflowdConfig[]` |
| GET | `/services/softflowd/status` | `{ "instances": SoftflowdStatus[], "error": string }` |
| GET | `/services/dhcp-relay/status` | `{ "interfaces": DHCPRelayStatus[], "error": string }` |
| POST | `/services/discord/webhooks` | Private `{webhook_url}` upload -> `201 {webhook_ref}`; `discord.write` |
| GET | `/services/discord/status` | First-seen alert delivery state/counts, no secret; `state.read` |
| GET | `/gateway-monitors` | Observed `GatewayMonitor[]` metadata |
| GET | `/statistics/gateways` | `{sample, monitors: GatewayMonitorStatistics[]}` |
| GET | `/statistics/gateways/{name}` | `{sample, monitor: GatewayMonitorStatistics}` |
| GET | `/services/gateway-monitoring/status` | `{monitors: GatewayMonitorStatistics[], error: string}` |
| GET | `/transactions` | `Record<string, Transaction>` |
| GET | `/transactions/{id}` | `Transaction` |
| GET | `/revisions?limit=50&before_revision=N` | `RevisionPage` |
| GET | `/revisions/latest` | `Revision`; latest committed configuration, independent of live observation |
| GET | `/revisions/{revision}` | `Revision` |
| POST | `/transactions` | Complete package request -> `Transaction` |
| POST | `/transactions/{id}/confirm` | No body -> `Transaction` |
| POST | `/transactions/{id}/rollback` | No body -> `Transaction` |
| POST | `/revisions/{revision}/restore` | Restore request -> `Transaction` |
| POST | `/services/softflowd/reconcile` | No body -> `RuntimeState` |
| POST | `/services/dhcp-relay/reconcile` | No body -> `RuntimeState`; repairs all managed services |
| POST | `/services/gateway-monitoring/reconcile` | No body -> `RuntimeState`; repairs all managed services |
| GET | `/services/ntp` | Configured `NTPConfig` metadata |
| GET | `/services/syslog` | Configured `SyslogConfig` metadata |
| GET | `/services/vnstat` | Configured `VNStatConfig` metadata |
| GET | `/services/ntp/status` | `{instances: ApplianceServiceStatus[], error}` |
| GET | `/services/syslog/status` | `{instances: ApplianceServiceStatus[], error}` |
| GET | `/services/vnstat/status` | `{instances: ApplianceServiceStatus[], error}`; one host-wide worker |
| GET | `/statistics/vnstat` | `TrafficDatabase`, v2 host-wide calendar accounting |
| POST | `/services/ntp/reconcile` | No body -> `RuntimeState`; all enabled services |
| POST | `/services/syslog/reconcile` | No body -> `RuntimeState`; all enabled services |
| POST | `/services/vnstat/reconcile` | No body -> `RuntimeState`; all enabled services |
| GET | `/services/mdns` | Committed `MDNSConfig`; independent of observation |
| GET | `/services/mdns/status` | `{instances: MDNSStatus[], error: string}`; applied singleton, readable on failure |
| POST | `/services/mdns/reconcile` | No body -> `RuntimeState`; all enabled-service repair permissions; no query/body |

For revision lists, `limit` defaults to 50, accepts 1..100, and
`before_revision` is an exclusive canonical date-version string cursor. Unknown, duplicated, empty, or
malformed parameters return `400`. Use `next_before_revision` verbatim for the
next page; absence means exhausted. Do not calculate cursors from dates.

`GET /api/v1/revisions/latest` requires `state.read` and returns `200` with
exactly the revision detail shape (flattened metadata plus complete
`config`), including the initialization revision before the first commit. It resolves the current
committed revision in one request without live observation or configuration
writes. Pending, rolled-back and failed transactions do not advance the
returned revision; confirming a restore does. No query parameters are accepted
(`400` with the normal JSON error shape). Authentication/permission failures
remain `401`/`403`; archive failures are explicit errors, not empty-config
fallbacks. Existing `Cache-Control: no-store` behavior applies. No attachment
header or config-only response is added; create the JSON download from `config`.

### 9.3 Request examples

Complete empty package, useful as a schema illustration, **not a safe default**:

```json
{
  "base_revision": "2026.10.29.1",
  "confirm_timeout_seconds": 120,
  "description": "Remove all owned configuration",
  "config": {
    "interfaces": [],
    "routes": [],
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
  "base_revision": "2026.10.29.13",
  "confirm_timeout_seconds": 120,
  "description": "Restore known-good configuration"
}
```

The selected historical revision is in the URL, not the body. An omitted/blank
restore description defaults server-side to `Restore revision N`.

### 9.4 Data shapes

The following TypeScript describes the application-level contract, not a generated
SDK. Optional fields can be absent; timestamp fields explicitly marked nullable
can be null when specified by the current response contract.

**Revision format:** All revision/base/restore/result/cursor fields are quoted
canonical `yyyy.mm.dd.iteration` strings on the wire. Use ordinary JSON string
serialization; remove uint64/lossless-number revision encoders. Validate a real
UTC date (year 0001..9999) and iteration 1..4294967295 without leading zeroes.
Compare numeric components, not lexicographic strings (`.10` is newer than `.9`).
Initialization allocates iteration 1; further same-day confirmations increment it,
and the first confirmation on a later UTC day starts at 1. Clock regression or
iteration exhaustion returns an explicit `503`, without committing or losing the
pending rollback path. Copy the exact current revision for `base_revision`;
numeric inputs, missing base revisions and malformed strings return `400`.
Configuration and software iterations are independent. Rollbacks do not advance
configuration versions; confirmed restores create a new revision. History is
not contiguous integer arithmetic. Kernel counters remain decimal strings;
gateway measurements remain ordinary JSON numbers.

```ts
type RevisionNumber = string; // Canonical yyyy.mm.dd.iteration, quoted on the wire.
type Timestamp = string; // RFC 3339.

interface Config {
  software: SoftwareMetadata; // Daemon-managed; omit from write requests.
  sando: SandoConfig; // Settings and frontend-reported confirmed import state.
  ipv6_enabled: boolean;
  ntp: NTPConfig;
  syslog: SyslogConfig;
  vnstat: VNStatConfig;
  mdns: MDNSConfig; // always serialized; see section 6.1.7
  system: SystemConfig; // see section 6.1.6
  discord: DiscordConfig;
  dynamic_dns: DynamicDNSConfig[];
  interfaces: ManagedInterface[];
  dhcp_clients?: Record<string, DHCPClientConfig>;
  dns?: Record<string, DNSConfig>;
  routes: Route[];
  firewall: Firewall;
  softflowd: SoftflowdConfig[];
  gateway_monitors: GatewayMonitor[];
}

interface DiscordConfig {
  enabled: boolean;
  notify_broadcast: boolean;
  notify_tcp_closures: boolean;
  webhook_ref: string; // Device-local reference only; never the webhook URL.
}

interface SoftwareMetadata {
  version: string; // Canonical yyyy.mm.dd.iteration.
  repository: string | null;
  latest_version: string | null;
  update_available: boolean | null;
  last_checked_at: Timestamp | null;
  error: string | null;
}

interface DynamicDNSConfig {
  name: string;
  enabled: boolean;
  source_interface: string;
  address_source: "interface" | "public_ip";
  tenant_id: string;
  client_id: string;
  secret_ref: string;
  zone_resource_id: string;
  record_name: string;
  ttl_seconds: number;
  interval_seconds: number;
  metadata?: { display_name: string; description: string };
}

interface NTPConfig { enabled: boolean; servers: string[] }
interface SyslogServer { host: string; port: number; transport: "udp" | "tcp" | "tls" }
interface SyslogConfig { enabled: boolean; servers: SyslogServer[] }
interface VNStatConfig { enabled: boolean; collector: string | null }
interface ApplianceServiceStatus {
  name: "ntp" | "syslog" | "vnstat";
  scope: "host";
  state: "disabled" | "simulated" | "running" | "error" | "stopped";
  started_at?: Timestamp;
  database_directory?: string;
  schema?: "netcontrol-services/counters/v2";
  interfaces?: Record<string, TrafficInterface>;
  collector?: string | null;
  last_report_date?: string | null;
  last_report_error?: string | null;
  sent_datagrams?: string;
  failed_datagrams?: string;
  source?: "journald"; // syslog worker only
  host_source?: "/run/systemd/journal/syslog"; // syslog worker only
  forwarded_records?: number; // nonnegative integer, per syslog worker start
  captured_records?: number; // syslog locally captured records, per execution attempt
  failed_deliveries?: number; // syslog missed per-destination sends, no replay
  destination_errors?: string[]; // syslog current connection/write warnings
  retrying?: boolean;
  restart_count?: number;
  last_error?: string;
  error?: string;
  sample_status?: "warming_up" | "available" | "unavailable";
  server?: string;
  offset_ms?: number;
  delay_ms?: number;
  requested_slew_ms?: number;
  uncorrected_offset_ms?: number;
  discipline?: "slew_only";
  collected_at?: Timestamp;
}

interface GatewayMonitorSettings {
  name: string;
  enabled: boolean;
  interface: string;
  target: string;
  probe_interval_ms: number;
  loss_timeout_ms: number;
  window_ms: number;
  latency_threshold_ms: number;
  loss_threshold_percent: number;
  rtt_variation_threshold_ms: number;
  failure_hold_ms: number;
  recovery_hold_ms: number;
}

type GatewayMonitor = GatewayMonitorSettings & (
  | { mode?: "explicit"; source_address: string; gateway: string; routing_table: number }
  | { mode: "dhcp"; source_address?: never; gateway?: never; routing_table?: never }
);

interface GatewayMonitorStatistics {
  name: string;
  mode: "explicit" | "dhcp";
  interface: string;
  resolved_source_address: string | null;
  resolved_gateway: string | null;
  resolved_routing_table: number | null;
  reason: string | null;
  process_state: "disabled" | "simulated" | "running" | "error" | "stopped" | "waiting";
  sample_status: "disabled" | "simulated" | "stopped" | "warming_up" | "available" | "unavailable" | "waiting_for_dhcp";
  health: "unknown" | "up" | "degraded" | "down";
  started_at: Timestamp | null;
  collected_at: Timestamp | null;
  health_changed_at: Timestamp | null;
  last_success_at: Timestamp | null;
  sent: number;
  received: number;
  lost: number;
  pending: number;
  variation_pairs: number;
  loss_percent: number | null;
  rtt_min_ms: number | null;
  rtt_max_ms: number | null;
  rtt_avg_ms: number | null;
  rtt_stddev_ms: number | null;
  rtt_p50_ms: number | null;
  rtt_p95_ms: number | null;
  rtt_variation_ms: number | null;
  error?: string;
}

interface DiscoveredInterface {
  name: string;
  kind: string; // Ethernet/veth normalize to "ethernet"; other kinds remain visible.
  index: number | null; // Native kernel index; null for simulated links.
  mac: string | null;
  mtu: number;
  up: boolean;
  addresses: string[];
  ownership: "managed" | "unmanaged" | "loopback";
  role: "loopback" | null; // Fixed for actual loopbacks; otherwise null, join managed settings.
  addressing_type: "static" | null; // Fixed static for loopbacks; otherwise origin is not inferred.
}

interface InterfaceCapabilitySnapshot {
  collected_at: string; // RFC3339 UTC, not a live sample timestamp.
  scope: string;
  inventory: {
    source: "native" | "simulator";
    status: "observed" | "partial" | "simulated";
    kernel_release: string | null;
    boot_id: string | null;
    errors: string[];
    interfaces: InterfaceCapabilities[]; // Sorted by name.
  };
}

interface InterfaceCapabilities {
  name: string;
  index: number | null;
  mac: string | null;
  kind: string; // Native link kind, including veth, loopback and unsupported kinds.
  driver: {
    name: string;
    version: string | null;
    firmware_version: string | null;
    expansion_rom_version: string | null;
    bus_address: string | null;
  } | null;
  hardware: {
    bus: string | null;
    address: string | null;
    vendor_id: string | null;
    device_id: string | null;
    subsystem_vendor_id: string | null;
    subsystem_device_id: string | null;
    revision: string | null; // PCI IDs/revision are hexadecimal strings.
    numa_node: number | null; // Unknown/unassigned (-1 from sysfs) is null.
  } | null;
  link: {
    carrier: boolean | null;
    speed_mbps: number | null;
    duplex: "half" | "full" | null;
    autonegotiation: boolean | null;
    supported_modes: InterfaceLinkMode[];
    advertised_modes: InterfaceLinkMode[];
    partner_advertised_modes: InterfaceLinkMode[];
  } | null;
  channels: {
    max_rx: number;
    max_tx: number;
    max_other: number;
    max_combined: number;
    rx: number;
    tx: number;
    other: number;
    combined: number;
  } | null;
  queues: {
    name: string;
    rps_cpus: string | null;
    rps_flow_count: number | null; // Table entries, not packets.
    xps_cpus: string | null;
    xps_rxqs: string | null; // Hexadecimal RX-queue mask, not CPU mask.
  }[];
  capabilities: {
    name: string;
    support: "supported" | "unsupported" | "unknown" | "not_applicable";
    enabled: boolean | null;
    evidence: string[];
    reason: string | null;
  }[];
  errors: string[];
}

interface InterfaceLinkMode {
  bit: number;
  name: string | null;
  speed_mbps: number | null;
  duplex: "half" | "full" | null;
}

interface ManagedInterface {
  name: string;
  kind: "ethernet" | "dummy" | "wireguard" | "vlan";
  role: "wan" | "lan" | "unassigned";
  mtu: number;
  up: boolean;
  addresses: string[];
  dhcp_relay: { enabled: boolean; servers: string[] };
  vlan?: { parent: string; id: number };
  wireguard?: {
    key_ref: string;
    listen_port: number;
    peers: Peer[];
  };
}

interface Peer {
  enabled?: boolean; // omitted means true in requests; responses always include it
  public_key: string;
  endpoint?: string;
  allowed_ips: string[];
  persistent_keepalive_seconds: number;
}

interface DHCPClientConfig {
  client_id: string;
  hostname: string;
  route_metric: number;
  use_mtu: boolean;
  use_domains: "no" | "route" | "yes";
}

interface DNSConfig {
  servers: string[];
  domains: { name: string; route_only: boolean }[];
  override_dhcp_dns: boolean; // default true; see section 6.2 DNS settings
}

interface DHCPClientRuntime {
  leases: Record<string, {
    client: DHCPClientConfig;
    address: string;
    server: string;
    acquired_at: number; // Unix seconds, not RFC 3339.
    lifetime: number; renewal: number; rebinding: number; // Seconds.
    routes: Route[];
    dns: string[];
    domain: string;
    mtu: number | null;
  }>;
  errors: Record<string, string>;
}

interface Route {
  enabled: boolean;
  destination: string;
  gateway?: string;
  interface: string;
  table: number;
  metric: number;
}

type RuleOrigin = "manual" | "import" | "system" | "inherited";
interface RuleSource {
  origin: RuleOrigin;
  import_source: string | null;
}

type FilterProtocol = "" | "tcp" | "udp" | "icmp" | "icmpv6";

interface Firewall {
  spoof_block: boolean; // Default true when omitted; null is invalid.
  drop_logging_enabled: boolean; // Omitted input defaults to true; null is invalid.
  allow_all_icmp: boolean; // Omitted input defaults to true; null is invalid.
  policy: "accept" | "drop";
  rules: Array<RuleSource & {
    source?: string;
    destination?: string;
    protocol?: FilterProtocol;
    destination_ports?: number[];
    action: "accept" | "drop";
  }>;
  nat: { masquerade: MasqueradeRule[]; destination_rewrite: DestinationRewriteRule[] };
  policies?: { hosts: FirewallHost[]; interfaces: InterfacePolicy[] } | null;
  input?: InputFirewall | null;
}

// GET /firewall/rules only; never submit system_policies as configuration.
interface FirewallView extends Firewall {
  system_policies: SystemFirewallPolicy[];
}

interface SystemFirewallPolicy {
  id: "spoof_block";
  origin: "system";
  read_only: true;
  config_path: "/firewall/spoof_block";
  enabled: boolean;
  chains: Array<{
    name: "input_spoof_block" | "forward_spoof_block";
    hook: "input" | "forward";
    priority: -1;
    policy: "accept";
    rules: Array<{
      id: string;
      order: number;
      counter_id: string;
      config_path: "/firewall/spoof_block" | null;
      action: "return" | "drop";
      matches: {
        family: "ipv4" | "ipv6";
        ingress_interface: string;
        source: string | null;
        destination: string | null;
        protocol: "any" | "udp" | "icmpv6";
        source_port: number | null;
        destination_port: number | null;
        icmp_type: number | null;
        icmp_code: number | null;
        hop_limit: number | null;
      };
    }>;
  }>;
}

interface InputFirewall {
  policy: "accept" | "drop";
  interfaces: Array<{
    interface: string;
    rules: Array<Omit<HostPolicyRule, "out_interface" | "destination_host">>;
  }>;
}

interface FirewallHost {
  id: string;
  name: string;
  addresses: string[];
  policy: "accept" | "drop";
  rules: HostPolicyRule[];
}

interface InterfacePolicy {
  interface: string;
  rules: HostPolicyRule[];
}

interface HostPolicyRule extends RuleSource {
  out_interface?: string;
  destination_host?: string;
  destination?: string;
  protocol?: FilterProtocol;
  destination_ports?: number[];
  action: "accept" | "drop";
}

interface MasqueradeRule extends RuleSource {
  family: "ipv4" | "ipv6";
  source?: string;
  out_interface: string;
}

interface DestinationRewriteRule extends RuleSource {
  metadata?: { display_name?: string; description?: string };
  out_interface: string; // Original WAN, before DNAT.
  protocol: "tcp" | "udp";
  destination_port: number;
  target_interface: string;
  target_address: string;
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
  | "applying" | "applying_local" | "pending_confirmation" | "committed"
  | "rolling_back" | "rolled_back" | "recovery_failed";

interface Transaction {
  id: string;
  actor: string;
  status: TransactionStatus;
  base_revision: RevisionNumber;
  committed_revision: RevisionNumber | null;
  candidate: Config;
  previous: Config;
  confirmation_deadline: Timestamp | null; // Null for local host provisioning or system conntrack ownership.
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
  process_health: ProcessHealth;
  active_alerts: ActiveAlert[];
}

interface ActiveAlert {
  id: string;
  component: string;
  resource: string | null;
  severity: "warning" | "error";
  code: string;
  message: string;
  retrying: boolean;
  first_seen_at: Timestamp | null;
  last_seen_at: Timestamp | null;
}
interface ProcessHealth {
  status: "healthy" | "degraded" | "unhealthy" | "unknown";
  healthy: boolean | null;
  collected_at: Timestamp | null;
  stale: boolean;
  runtime_available?: boolean;
  daemon?: { pid: number; state: "running" | "unknown"; healthy: boolean | null;
    uptime_seconds: number; watchdog_enabled: boolean };
  components: { id: string; component: string; resource: string; state: string;
    healthy: boolean | null; retrying: boolean; collected_at: Timestamp }[];
}
interface PlatformStatus { process_health: ProcessHealth; active_alerts: ActiveAlert[] }

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
  scope?: "managed";
  export_version?: 1 | 5 | 9 | 10;
  address_family?: "ipv4" | "dual";
  fragments?: "excluded";
  capture_filter?: string;
  sampling_rate?: number;
  sampling_metadata?: boolean; // false only for NetFlow v1
  started_at?: Timestamp;
  error?: string;
  dropped_packets?: string; // Exact cumulative AF_PACKET drops since worker start.
  statistics_complete?: boolean; // False remains sticky after an observed drop.
  active_flows?: number; // Present after the first table scan; counters are JSON numbers.
  exported_flows?: number;
  excluded_packets?: number;
  filtered_packets?: number;
  malformed_packets?: number;
}

interface RuntimeState {
  host_takeover?: HostTakeover | null; // Native host takeover only.
  process_health?: ProcessHealth; // Always present on HTTP GET /runtime; absent from some core action responses.
  active_alerts?: ActiveAlert[];
  capabilities: {
    gateway_monitor_modes: ("explicit" | "dhcp")[];
    dhcp_gateway_monitor_address_families: "ipv4"[];
  };
  dhcp_clients?: DHCPClientRuntime;
  appliance_services: (ApplianceServiceStatus | MDNSStatus | UDPRelayStatus)[];
  parent_interfaces: ParentInterface[];
  softflowd: SoftflowdStatus[];
  dhcp_relay: DHCPRelayStatus[];
  gateway_monitors: GatewayMonitorStatistics[];
  error?: string;
}

interface HostTakeover {
  mode: "console";
  phase: "captured" | "applying" | "owned" | "failed" | "complete";
  error: string;
  connectivity_confirmation_required: false;
  items: { resource: string; disposition: "imported" | "disabled"; reason: string }[];
}

interface DHCPRelayStatus {
  interface: string;
  state: string;
  started_at?: Timestamp;
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
  config: Omit<Config, "software">;
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
| `401` | Missing/invalid API key; API error text is `valid API key required` |
| `403` | Missing permission |
| `404` | Endpoint/resource/revision/transaction not found |
| `405` | Unsupported method; CORS preflight advertises `GET, POST, DELETE`, not support for every method on every route |
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
  HTTP/transport errors, no automatic mutation retries, API-key redaction.
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
  not the API key, full request/response bodies, or configuration by default.
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
| No broader dashboard hosting | Embedded onboarding at `/`; separate trusted dashboard, same-origin or API-key-authenticated cross-origin API |
| No networking-key permission discovery | API key entry, advisory deployment hints, handle `403`; `/auth/status` only identifies device-account sessions |
| No backend/namespace/capability endpoint | Deployment labels or Unknown; no guessed capabilities |
| No key inventory/private-key API | Manual validated key reference; operator provisions files |
| No dry-run/diff/validation endpoint | Local validation/diff; server preflight happens during submit |
| No idempotency key | Freeze uncertain writes; reconcile transaction records; never blind retry |
| No event stream/calendar-aggregated rate history | Bounded polling; native per-sample counters/history are available |
| No general drift repair | Diagnostic comparison and operator guidance; no “force apply” |
| No history pruning/server transaction pagination | Client pagination; document scaling limitation |
| No persisted rollback actor/time fields | Display reason/raw error, avoid fabricated metadata |
| Revisions/cursors emitted as JSON numbers | Lossless parsing/serialization; statistics values are already decimal strings |
| Linux namespace/parents/capability setup | Operator-owned; Ubuntu installer provisions IPv4 LAN/WAN forwarding/NAT, not IPv6 |

Future enhancements such as capabilities, structured error codes, idempotency
keys, paginated transaction summaries, and explicit server clock can be proposed
separately. The release must remain usable without them.

## 15. Delivery priorities and handoff

### P0: Safety foundation

- Same-origin connectivity, API-key handling, typed/lossless API boundary.
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
- Revision history/detail/comparison/restore, including the initialization revision.
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
| A01 | Missing/invalid API key | `401` shown; no API-key persistence/logging; no polling loop |
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
| A14 | Reload/reconnect with pending transaction | API-key re-entry then active transaction rediscovery and deadline/actions |
| A15 | Submit latency consumes confirmation window | Remaining time uses original server deadline, not response time |
| A16 | Browser clock skew/background throttling | Absolute deadline shown; fresh server state determines outcome |
| A17 | Permission denied on submit/confirm/rollback | `403` explicit; draft/transaction retained; authorized recovery guidance |
| A18 | Firewall/NAT reorder | Wire payload preserves exact order; diff displays moves |
| A18-host | Host policy and interface override | Interface first-match verdict overrides host; unmatched interface rules fall back to source-host rules/default; destination host's outbound default is ignored |
| A18-state | Stateful policy update | Established/related return traffic remains allowed after applying a new block; UI warns that existing sessions are not terminated |
| A18-address | Host address edit and references | Stable host-ID references follow updated IPv4/IPv6 addresses; duplicate addresses and dangling references are rejected; history/restore retain inventory |
| A18-legacy | Firewall model switch | Absent/null policies preserve stateless legacy behavior; nonempty legacy rules cannot mix with host/interface policies; legacy protocol and TCP/UDP ports survive drafts/history/rollback |
| A18-protocols | Filter protocol choices | Any/TCP/UDP/ICMP/ICMPv6 work in host/interface/input/legacy scopes; ports only TCP/UDP; family and IPv6-enable violations rejected; global IPv4 ICMP exception retains precedence |
| A19 | Address versus network input | Host address `/24` retained; non-network selector rejected with suggested correction |
| A20 | IPv6 and numeric endpoints | Canonicalization, brackets, zones, mapped addresses and family checks exercised |
| A21 | VLAN cycles/duplicate identity/MTU mismatch | Linked local errors; invalid package not submitted |
| A22 | Protected parent missing/replaced | Read-only diagnostic retained; no API recreate/edit control |
| A23 | Interface kind or VLAN parent/ID change | Locked for existing interface; replacement workflow explained |
| A24 | Delete referenced interface | Dependency impact visible; no silent cascade; invalid references block apply |
| A25 | Masquerade egress missing family address/client | Local error unless IPv4 has a DHCPv4 client; IPv6 still requires its family address |
| A26 | WireGuard field/key/allowed-IP validation | Constraints enforced; no private-key input or unsupported tunnel-health claims |
| A27 | softflowd limits and disabled entries | 16-instance limit, full disabled-entry validation, timeout/filter byte boundaries |
| A28 | Running/error/stopped/disabled/simulated worker | Correct labels; no fabricated PID or delivery claim |
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
snapshots. Include an automated assertion that API keys never enter storage, URLs,
exports, or application logs.

## 17. Source references

- [README](README.md): supported scope, deployment, lifecycle and ownership.
- [HTTP routing and authorization](crates/netcontrold): endpoint behavior,
  error statuses, body limits and permission checks.
- [Configuration model and validation](crates/netcontrol-core): core resources,
  normalization, addresses, routes, policy, filtering and NAT.
- [Native protocol workers](crates/netcontrol-services): extended fields
  and constraints.
- [Transaction engine](crates/netcontrol-core): state machine, confirmation,
  rollback, deadlines and persistence behavior.
- [Native networking](crates/netcontrol-native): Linux ownership and reconciliation.
- [Revision archive](crates/netcontrol-core): history, metadata and restore.
- [Daemon setup](crates/netcontrold): listener, TLS, backend and operator flags.
- [Migration example](examples/migration.json) and
  [VLAN/softflowd example](examples/vlan-softflowd.json): complete request examples.
