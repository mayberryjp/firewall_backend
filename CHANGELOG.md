# Changelog

## Unreleased

### Fixed

- Native service failures no longer become global configuration-health gates.
  Owned Rust supervisors retry startup/runtime failures, unexpected exits and
  unwind panics with cancellable 1..30-second exponential backoff. Verification
  checks applied configuration and active supervisors rather than connectivity
  or sample availability. Adds recovery metadata to worker status; mDNS reopens
  sockets automatically after link/port recovery without using stale sockets.
  Syslog reconnects destinations independently, preserves local capture and
  reachable collectors, and reports missed deliveries without promising replay.
  Authorization, configuration validation, ownership, network drift and durable
  recovery guards remain. Recommended bump: minor for additive status fields
  and availability behavior; baseline unknown, Unreleased. Required frontend
  warning/status handling: [handoff 2026-10-27-01](docs/frontend-handoffs/2026-10-27.md#2026-10-27-01-resilient-service-supervision).

- A DNS server added to an interface that already used a DHCP-provided server was listed
  first in systemd-resolved but never used: resolved keeps its previously selected server
  while that server stays in the list. Publishing per-interface DNS now reads the link's
  current list and selected server from resolved and, when they do not match the wanted
  order, clears the link's servers once before setting the list so the first configured
  server is selected. An unreadable resolved state falls back to the previous plain update.
  Lease DNS servers are still appended after configured ones. The D-Bus read path is
  unverified against a real systemd-resolved; the decision logic is unit tested. No API,
  schema or frontend change; recommended bump: patch; baseline unknown.

- Saving a networking-only change (for example adding a DNS server or changing an MTU)
  while an appliance service such as NTP, syslog or vnStat is enabled no longer fails
  with `native service ntp is not healthy ... "state":"stopped"`, followed by a failed
  rollback and blocked writes. The native apply stops all service workers before changing
  interfaces, but the services layer treated an empty worker set as already current when
  the services configuration was unchanged, so nothing restarted them. Workers are now
  restarted unless exactly the expected set is running. NTP also no longer fails to start
  when a server name cannot be resolved (for example DNS or the WAN is down): resolution
  is retried every poll and the row shows `sample_status: "unavailable"` with the error.
  No API or schema change; recommended bump: patch; baseline unknown. Frontend action: none.

- `upgrade.sh`/`install.sh` journald-forwarding setup no longer aborts (and rolls the
  upgrade back) on a second run: once `rsyslog.service` is masked, its `syslog.service`
  alias reports load state `error`. A logger in that state is now accepted only when
  `systemctl is-enabled` reports it `masked`; any other `error` still fails the
  deployment. No API or frontend change; recommended bump: none (unreleased scripts).

- Missing/invalid NTP samples no longer stop the worker after three polling
  rounds and consequently fail unrelated configuration reads and transaction
  observation/confirmation. NTP keeps polling with `sample_status: "unavailable"`
  and a visible row-local warning; the next accepted sample clears it. Startup,
  socket I/O, clock-adjustment errors and transaction recovery guards are
  unchanged. Recommended bump: patch; baseline unknown, Unreleased.
  Required frontend warning/list handling:
  [handoff 2026-10-25-11](docs/frontend-handoffs/2026-10-25.md#2026-10-25-11-non-blocking-ntp-sample-warnings).

- Fixed the signed-package CI build for the static musl target: the NetFlow
  capture `recvmmsg` call passed `MSG_DONTWAIT` as `i32`, but musl's libc binding
  takes `u32` (glibc takes `i32`). The flag is now converted by inference, so both
  libc variants compile. No behavior, API or frontend change. Recommended bump:
  none (build fix for unreleased code).

- Further reduced native NetFlow/IPFIX processing overhead with hash-based flow
  lookups, cached timeout classes, one monotonic timestamp per packet update
  and expiry scan, and bounded batching of capacity/counter-rollover exports
  instead of one UDP send per early-expired flow. Preserves flow limits,
  least-recently-updated eviction, counter rollover, timeout precedence,
  sampling, drop reporting and wire formats. Recommended bump: patch;
  baseline unknown, Unreleased. No API/schema, frontend or deployment change.

- Reduced native NetFlow/IPFIX capture loss by replacing the unconditional
  10 ms receive-loop sleep with readiness polling, batching up to 64 frames per
  receive syscall, and requesting a bounded 4 MiB receive buffer per exporter
  (subject to the host's `net.core.rmem_max`). Queued traffic no longer waits
  between 256-packet processing rounds. Sampling, flow/export formats, sticky
  capture-loss reporting and fatal I/O errors remain unchanged. No API/schema,
  host sysctl or frontend change. Recommended bump: patch; baseline unknown,
  Unreleased. See [capture details](docs/NETFLOW_IPFIX_SPEC.md#packet-drops).

### Changed

- Ubuntu `install.sh` and full `upgrade.sh` now enable the existing in-process
  configuration SSH listener by default on `0.0.0.0:2222` through
  `NETCONTROL_SSH_LISTEN`. Explicit `--ssh-listen` wins; operator environment
  files/drop-ins can override or disable the default. Build-only and bare
  daemon defaults are unchanged. No separate sshd, OS shell, credential change
  or automatic firewall exception. Review saved host-input policy before
  upgrading. Recommended bump: minor; baseline unknown, Unreleased.
  [Operator-help handoff 2026-10-25-16](docs/frontend-handoffs/2026-10-25.md#2026-10-25-16-default-embedded-ssh-for-ubuntu-deployment).

- Documentation only: added the [native mDNS / DNS-SD build specification](docs/MDNS_SPEC.md)
  for an in-process Rust pfSense-Avahi-like discovery service, including reflection,
  filters, optional publishing, protocol/lifecycle gates and frontend/deployment
  coordination. The original proposal alone had no runtime/API effect and
  recommended no bump; it is now superseded by the implementation entry below.

- Native syslog now requires systemd/journald forwarding through the inherited
  `netcontrol-syslog` datagram socket at `/run/systemd/journal/syslog`. Journald
  retains `/dev/log` and kernel/daemon capture; direct `/dev/log`, `/dev/kmsg` and
  backend-file capture are removed to avoid duplicate forwarding. Ubuntu scripts
  configure socket activation/journald and mask competing receivers, never the
  journald dev-log input. Worker repair/rollback reuses systemd's socket; managed
  service stop/restart also stops/restarts the socket. Status adds
  `source: "journald"`, changes `host_source`, removes `backend_source` and
  `kernel_source`. OpenRC/direct native syslog is unsupported; no fallback.
  This supersedes the earlier unreleased takeover design. Recommended bump:
  **major** for breaking deployment/source/status contracts; baseline unknown.
  Required frontend help/status coordination:
  [handoff 2026-10-25-09](docs/frontend-handoffs/2026-10-25.md#2026-10-25-09-journald-only-native-syslog).

- Documentation only: [FRONTEND_SPEC.md](FRONTEND_SPEC.md) section 6.9 now specifies an
  inline per-row enable/disable toggle for NetFlow/IPFIX exports and the **Add export**
  create-action label. No API, schema or runtime change; recommended bump: none.

- Native NetFlow/IPFIX capture continues exporting after AF_PACKET packet drops
  instead of stopping the worker and rejecting confirmation solely for capture
  loss. Runtime/status rows report exact cumulative `dropped_packets` and a sticky
  `statistics_complete: false`; real socket/export failures remain errors.
  Recommended bump: minor for the explicit runtime contract and behavior change;
  baseline unknown, Unreleased. Frontend warning required; see
  [handoff 2026-10-25-05](docs/frontend-handoffs/2026-10-25.md#2026-10-25-05-native-flow-capture-loss-reporting).

- `POST /api/v1/transactions` now drops unknown keys anywhere inside `config`
  instead of returning `400`, and lists each dropped key as an RFC 6901 pointer in
  a new `ignored_fields` array on the `202` response (always present, possibly
  empty). Known fields keep full type/value/semantic validation; the request
  envelope, revision restore, saved journal/history, native ownership, credentials
  and packages still reject unknown fields. Dropped keys never reach the saved
  configuration, transaction record or native backend. This relaxes the
  greenfield strict-contract policy by explicit user request for compatibility
  with newer/older clients; a mistyped security-relevant key is now ignored rather
  than refused, so callers must inspect `ignored_fields`. Inline secrets such as
  `mqtt.password` are dropped like any other unknown key. Recommended bump: minor;
  baseline unknown. Frontend action required; see
  [handoff 2026-10-24-19](docs/frontend-handoffs/2026-10-24.md#2026-10-24-19-unknown-configuration-fields-are-dropped-and-reported).

### Added

- Shared runtime `process_health` and deduplicated `active_alerts` on HTTP state
  and runtime reads, plus authenticated engine-independent
  `GET /api/v1/platform/status`. Health is observational healthy/unhealthy/unknown,
  not a configuration gate; stale/unavailable monitoring does not claim success
  or clear known failures. MQTT publishes the same objects and Home Assistant
  health/alert-count sensors, including partial samples when statistics fail.
  Packaged systemd service and install/full-upgrade drop-in add readiness and a
  progress-driven watchdog: restart failed/wedged daemon, not offline services.
  No persisted config or permission change. Recommended bump: minor; baseline
  unknown, Unreleased. [Frontend handoff 2026-10-27-02](docs/frontend-handoffs/2026-10-27.md#2026-10-27-02-watchdog-process-health-and-active-alerts).

- Native in-process Rust mDNS/DNS-SD reflection, service/provider/subtype
  filtering, optional appliance publishing, allow/deny managed-LAN selection
  and IPv4/IPv6 controls through new always-serialized `config.mdns` (disabled
  by default). Adds `mdns.write`, committed config/status/repair endpoints and
  CLI commands, with existing confirmation/rollback/recovery and all-service
  repair authorization. No Avahi/Go process, D-Bus, general multicast/SSDP/media
  forwarding, automatic firewall exception or SSH/SFTP advertisement.
  Exact-string counters and bounded parsing/rate/memory behavior report
  discovery loss explicitly. Route-netlink gates I/O and latches required-link
  replacement or notification-loss errors until repair. Common RR types only;
  real VLAN/nftables/MLD, device interoperability, load and reboot qualification limits
  are documented in the [implementation spec](docs/MDNS_SPEC.md).
  Recommended bump: minor; baseline unknown, Unreleased.
  [Required frontend handoff 2026-10-25-17](docs/frontend-handoffs/2026-10-25.md#2026-10-25-17-native-mdns-implementation).

- `GET /api/v1/revisions/latest` returns the latest committed revision metadata
  and complete `config` in one request with `state.read`, without requiring
  healthy live observation. Includes revision 0; excludes unconfirmed candidates.
  Query parameters return `400`. Existing numbered revision responses are
  unchanged. Recommended bump: minor (additive endpoint); baseline unknown.
  Optional frontend download integration:
  [handoff 2026-10-25-14](docs/frontend-handoffs/2026-10-25.md#2026-10-25-14-single-request-committed-configuration-download).

- `system.domain`: a cosmetic domain name beside `hostname` and `timezone` (CLI `domain NAME` /
  `no domain`). It is stored and returned only; it is never applied to the host or resolver and
  never becomes a DNS search domain, and it needs no host support or timezone database. Lowercase
  DNS name, at most 253 characters (with the host name); empty by default. Recommended bump:
  minor; baseline unknown. Optional frontend work; see
  [handoff 2026-10-25-13](docs/frontend-handoffs/2026-10-25.md#2026-10-25-13-cosmetic-system-domain).

- `dns[interface].override_dhcp_dns` (boolean, default **true**): when true and the
  interface has at least one configured DNS server, DNS servers learned from its DHCP lease
  are discarded and only the configured servers are published to systemd-resolved. False
  keeps the earlier behavior (configured servers first, then lease servers). Without
  configured servers the lease servers are kept. DHCP search domains are unchanged.
  Interfaces adopted from an existing host configuration are imported with false. The
  default changes behavior for existing entries that have servers. Recommended bump:
  minor; baseline unknown. Frontend action required; see
  [handoff 2026-10-25-12](docs/frontend-handoffs/2026-10-25.md#2026-10-25-12-override-dhcp-dns-servers).

- Host name and time zone settings: `config.system` (`hostname`, `timezone`; empty =
  unmanaged, the default and always present in configuration responses), a new
  `system.write` permission, `GET /api/v1/system/status` and
  `GET /api/v1/system/timezones` (`state.read`), and the CLI commands `hostname`,
  `timezone` and their `no` forms. After confirmation the daemon sets the kernel hostname
  and `/etc/hostname` and links `/etc/localtime` to the zone (Linux host mode, requires
  the host timezone database); values are enforced with retry/backoff, a rolled-back
  transaction never touches the host, and clearing a value does not revert it. The
  section is excluded from the native networking configuration. Native syslog
  forwarding now re-reads the kernel hostname every second so a hostname change takes
  effect without a restart. Changing the Config shape is a breaking addition for
  clients that validate responses strictly. Recommended bump: minor; baseline unknown.
  Frontend action required for the UI; see
  [handoff 2026-10-25-10](docs/frontend-handoffs/2026-10-25.md#2026-10-25-10-host-name-and-time-zone).

- Home Assistant MQTT streaming now also publishes NetFlow/IPFIX (`softflowd`)
  statistics per configured instance: export state, `statistics_complete`, kernel
  capture **`dropped_packets`** (exact decimal string), active flows, exported flows
  and excluded/filtered/malformed packet counters, read from the existing
  `GET /api/v1/services/softflowd/status` rows. Counters are unknown (never zero)
  without a running worker, reset on worker restart, and are absent when no exporter
  is configured; a failed status read keeps the existing entities. No configuration,
  API or permission change. Recommended bump: minor; baseline unknown. Frontend
  action: none required, optional documentation; see
  [handoff 2026-10-25-07](docs/frontend-handoffs/2026-10-25.md#2026-10-25-07-mqtt-netflowipfix-sensors).

- Added the standalone [NetFlow/IPFIX implementation reference](docs/NETFLOW_IPFIX_SPEC.md)
  for the `softflowd` configuration and runtime (written from the code), and completed
  the `SoftflowdStatus` type in the frontend contract with the counters the daemon
  already returns. Documentation only; no behavior, API or schema change.
  Recommended bump: none. Optional frontend action; see
  [handoff 2026-10-25-06](docs/frontend-handoffs/2026-10-25.md#2026-10-25-06-netflowipfix-implementation-reference).

- WireGuard peer `enabled` boolean (default true when omitted in requests and saved
  configuration; null/non-boolean rejected). A disabled peer keeps all settings in
  configuration, history and exports but is not installed on the interface, so its
  traffic and handshake stop; re-enabling installs it again. Toggles use ordinary
  confirmed transactions with `wireguard.write`, rollback and restart recovery.
  Disabled peers are still validated, but may reuse an allowed network that an
  enabled peer uses. Runtime lists installed peers only. Recommended bump: minor;
  baseline unknown. Frontend action required; see
  [handoff 2026-10-25-04](docs/frontend-handoffs/2026-10-25.md#2026-10-25-04-wireguard-peer-enabled-toggle).

- `netcontrold --create-wireguard-key NAME` and `--wireguard-public-key NAME` create
  a WireGuard private key file in `--keys` (default `/etc/netcontrol/keys`) and print
  its public key, with no extra packages. Keys are generated by the daemon's WireGuard
  library, published atomically with mode `0600`, never overwrite an existing file,
  and use the contract's name rule (letters, digits, `_`, `-`, at most 64). The flags
  exit without starting the daemon or touching networking or saved state. See the
  [install guide](docs/BUILD_AND_INSTALL.md#creating-a-wireguard-private-key).
  Recommended bump: minor; baseline unknown. No API, schema or frontend change.

- Home Assistant MQTT streaming now also publishes host health from the existing
  host snapshot: memory/swap, load, host uptime, OOM kills, PSI averages, per-core
  CPU busy percent (computed from tick deltas; unknown on the first sample or
  after a reset), per thermal zone and hwmon temperature/fan sensor, and local
  filesystem total/used/available bytes. Failed readings are unknown, never zero;
  sections that cannot be enumerated keep their existing entities. Entity counts
  are capped per kind. No configuration, API or permission change. Recommended
  bump: minor; baseline unknown. Frontend action: none required, optional
  documentation; see
  [handoff 2026-10-25-03](docs/frontend-handoffs/2026-10-25.md#2026-10-25-03-mqtt-host-health-sensors).

- Azure public DNS IPv4 Dynamic DNS with per-entry WAN interface monitoring or
  NAT-aware HTTPS public-IP detection, service-principal authentication,
  write-only private secret references and authenticated upload/status APIs.
  Confirmed transactional settings only; verified TLS/source binding, conditional
  A-record updates, metadata preservation, explicit errors and no alias/multi-address
  replacement. Simulator performs no network I/O. Recommended bump: minor;
  baseline unknown. Frontend action required; see
  [handoff 2026-10-25-01](docs/frontend-handoffs/2026-10-25.md#2026-10-25-01-azure-dynamic-dns).

- Optional top-level `blackhole` section (`name`, `action` of `blackhole`,
  `unreachable` or `prohibit`, optional metadata) defining one named drop target
  that any number of static routes may use as their `interface`. Native hosts
  install those routes as deviceless kernel blackhole/unreachable/prohibit routes
  (protocol 242, no gateway), verify and reconcile them like other owned routes,
  and keep renames with an unchanged action drift-free. The name must be a valid
  interface name not used by a managed or adopted interface; blackhole routes
  cannot have a gateway; changes require `routes.write`. Absent section means
  not configured; no per-route drop counters. Recommended bump: minor; baseline
  unknown. Frontend action required; see
  [handoff 2026-10-24-20](docs/frontend-handoffs/2026-10-24.md#2026-10-24-20-blackhole-route-target).

- API-managed Home Assistant MQTT discovery/statistics streaming, default disabled,
  with broker, username, write-only password reference, source interface and
  configurable 60-second interval (10..3600 seconds). Persistent Linux host-bound
  MQTT, verified TLS when selected, QoS 1, reconnect, availability/LWT and discovery
  reconciliation; confirmed settings only, simulator makes no connection. Gateway
  summaries, interface counters, revision, uptime and version (unknown for placeholder
  0.0.0). Private credentials/device identity in `<state>.mqtt`; new `mqtt.write`
  and password/status APIs. Recommended bump: minor; baseline unknown. Frontend
  action required; see [handoff 2026-10-24-18](docs/frontend-handoffs/2026-10-24.md#2026-10-24-18-home-assistant-mqtt-statistics).

- Read-only Linux host-health snapshots at `GET /api/v1/statistics/host`
  (`state.read`) and `show statistics host`: CPU ticks/scheduler, memory/swap,
  load/uptime, VM/OOM counters, PSI, disk I/O, local filesystem bytes/inodes,
  thermal-zone and hwmon temperatures/fans. Exact decimal counter strings,
  independent source/sensor errors and explicit simulated/unmeasured responses;
  daemon-visible host scope, no kernel writes, external workers or saved history.
  Recommended bump: minor; baseline unknown. Frontend action required; see
  [handoff 2026-10-24-17](docs/frontend-handoffs/2026-10-24.md#2026-10-24-17-kernel-host-health-sensors).

- Static-route `enabled` boolean, defaulting to true when omitted in requests or
  saved configuration. Explicit false remains disabled; null/nonboolean values
  are rejected. Disabled routes remain validated and
  saved in configuration/history but are excluded from native route plans;
  enabling/disabling uses ordinary confirmed transactions and owned-route
  reconciliation. Explicit gateway monitors require enabled matching routes.
  Initial host adoption and CLI route creation explicitly enable static routes;
  CLI deletion also handles disabled records. Canonical responses include enabled.
  Recommended bump: minor for route enable/disable functionality; baseline unknown.
  Frontend action required; see [handoff 2026-10-24-15](docs/frontend-handoffs/2026-10-24.md#2026-10-24-15-static-route-enabled-state)
  and its [default-enabled correction](docs/frontend-handoffs/2026-10-24.md#2026-10-24-16-static-route-defaults-to-enabled).

- DHCPv4 gateway monitors with explicit `mode: "dhcp"`, selected managed interface
  and target, without pinned lease source/gateway/table or static route prerequisites.
  Enabled monitors save before acquisition and report waiting/Unknown; native
  probes follow selected-interface lease paths, retain windows on identical
  renewals, rebind on changes and stop on expiry without cross-WAN fallback.
  Tagged private routes/rules reconcile on disable/delete/rollback/recovery/restart.
  Adds runtime capability discovery, resolved path/reason fields and IPv4-only
  DHCP mode; existing explicit IPv4/IPv6 monitors remain unchanged. Recommended
  bump: minor; baseline unknown. Frontend action required; see
  [handoff 2026-10-24-12](docs/frontend-handoffs/2026-10-24.md#2026-10-24-12-dhcp-interface-gateway-monitors).

- Explicitly authorized offline `netcontrol-state-convert` for empty retired
  `policy_rules` fields in saved journals/history and native ownership/adoption
  snapshots. Preview by default; locked/current-model/history validation,
  confirmation, durable private originals/staged replacements and manifest before
  per-file atomic publication. Refuses non-empty rules, corruption and active
  recovery; no implicit loader/API migration, reset or live networking change.
  Interrupted multi-file publication requires offline restoration of all originals.
  Recommended bump: minor for the new operator tool; baseline unknown. The
  underlying public source-policy removal remains a major contract change.

- Global persisted `ipv6_enabled` policy (default true on installation/factory
  configuration), using confirmed configuration transactions and
  `kernel.namespace.write`. Native enforcement sets/verifies all/default/
  per-interface Linux IPv6 disable controls, including loopback and future
  links; adds drift/runtime reporting and same-boot address/route recovery.
  Disabled configurations reject IPv6 references; service resolution/export
  becomes IPv4-only. CLI adds `ipv6 enable|disable`. Policy is reapplied on
  daemon startup, not before it; no bootloader/module/sysctl.d changes.
  Recommended bump: minor; baseline unknown. Frontend changes required; see
  [handoff 2026-10-24-09](docs/frontend-handoffs/2026-10-24.md#2026-10-24-09-global-ipv6-policy).

- Explicit `DELETE /api/v1/connections` (confirmed namespace-wide flush) and
  `DELETE /api/v1/connections/{id}` (original tuple/family/protocol/zone plus ID)
  require new `connections.delete`. Malformed/stale targets never become a flush;
  active transactions/upgrades block deletion. Native netfilter ACK validation,
  typed stale-target `404`, DELETE CORS and synthetic isolated-kernel regression;
  no configuration/rule changes, TCP RST or guaranteed new handshake. Simulator
  refuses destructive success. Recommended bump: minor; baseline unknown.
  See [handoff 2026-10-24-08](docs/frontend-handoffs/2026-10-24.md#2026-10-24-08-connection-state-deletion).

- Optional signed Ubuntu amd64 self-upgrade: version-only
  `POST /api/v1/system/upgrade` (`system.upgrade`), read-only latest-job polling,
  pinned operator GitHub repository/Ed25519 key, bounded authenticated HTTPS
  release downloads, independent systemd helper, configuration-write maintenance
  gate, verified previous-binary restoration and required boot recovery.
  Offline `netcontrol-package build-update` creates version-bound release assets;
  nothing is tagged/uploaded/published automatically. Conntrack prerequisites
  are retained; no state reset, arbitrary URLs, downgrade override or implied
  state rollback. Recommended bump: minor; release baseline unknown. Linux
  build/lint/unit/filesystem checks passed, but the full test gate has an existing
  metadata-fixture failure and real systemd/reboot/release acceptance is pending.
  See [handoff 2026-10-24-07](docs/frontend-handoffs/2026-10-24.md#2026-10-24-07-signed-ubuntu-self-upgrade).

- Read-only `GET /api/v1/statistics/connections` conntrack snapshots using
  `state.read`: original/reply NAT tuples, protocol state/status, zone/mark,
  nullable remaining timeout/ID and exact nullable per-direction packet/byte
  counters. Strict family/protocol/address/port/zone filters and bounded live
  paging; no per-rule attribution, writes/flush, history or silent accounting
  enablement. Simulator explicitly reports unmeasured data. Raw netfilter reads
  validate kernel origin and use bounded collection; existing nftables ownership
  checks remain. Recommended bump: minor; baseline unknown. Linux acceptance is
  unverified; see [handoff 2026-10-24-05](docs/frontend-handoffs/2026-10-24.md#2026-10-24-05-read-only-conntrack-connection-statistics).

- Authenticated `POST /api/v1/interfaces/{name}/dhcp/retry` runtime action using
  `interfaces.write`, without changing configuration/revisions or restarting
  other clients. Native retry joins the selected worker before fresh discovery,
  retaining a valid lease until replacement, expiry or rejection; `202` confirms
  worker startup, not lease acquisition. Conflicts block active transactions,
  down/unconfigured interfaces and native ownership/recovery mismatches.
  Recommended bump: minor; baseline unknown. Linux validation remains pending;
  see [handoff 2026-10-24-03](docs/frontend-handoffs/2026-10-24.md#2026-10-24-03-per-interface-dhcpv4-retry).

- Optional descriptive `metadata.display_name`/`metadata.description` on interfaces
  (including VLAN/WireGuard), peers, routes/policies, firewall/NAT records,
  DHCP/DNS settings and service/monitor/exporter records. Bounded Unicode text is
  persisted and authorized through existing transactions/revisions without
  changing identifiers. Native metadata-only edits avoid network mutation and
  worker restarts. Recommended bump: minor; baseline unknown. Frontend types,
  forms and draft preservation are required; see
  [handoff 2026-10-24-02](docs/frontend-handoffs/2026-10-24.md#2026-10-24-02-descriptive-object-metadata).

- Preview-first Ubuntu `hardening.sh` footprint profile for explicit printing,
  mDNS discovery and crash-reporting service/package removal. `--apply` is
  required; dependency removal outside the allowlist and package installations
  are refused, with no autoremove. Optional `--disable-apparmor` schedules a
  GRUB-based protection opt-out on a manual reboot; default preserves AppArmor.
  Includes private pre-change state records and mocked regression coverage.
  Recommended bump: minor for new operator functionality; baseline unknown.
  Live Ubuntu/APT/GRUB/reboot acceptance remains unverified. See
  [handoff 2026-10-24-01](docs/frontend-handoffs/2026-10-24.md#2026-10-24-01-optional-ubuntu-footprint-reduction).

- Explicit Ubuntu `reset.sh` for factory network configuration, with
  optional port/LAN-prefix selection and a reset-capable binary override. Private
  backup precedes a journaled local reset; credentials, keys and revision history
  are retained. Factory LAN is committed without waiting for WAN DHCP. No HTTP
  reset endpoint. Initial installation shares the same clean factory builder.
  See [handoff 2026-10-23-04](docs/frontend-handoffs/2026-10-23.md#2026-10-23-04-saved-configuration-upgrades-and-explicit-factory-reset).

- Fresh Ubuntu appliance provisioning: first/second naturally ordered physical
  Ethernet ports default to DHCPv4 WAN/LAN, with optional paired overrides and
  static LAN `192.168.0.1/24`. LAN allows all input/forwarding; unsolicited WAN
  input and other new forwarded traffic are denied, with loopback/stateful/DHCP
  input exceptions. WAN lease/default-route acquisition is bounded to 30 seconds
  before confirmation, with transaction rollback on failure. LAN-subnet WAN IPv4
  masquerade committed through the transaction engine, LAN-address management
  binding and automatic service start/boot enablement. `--appliance` enables
  host IPv4 forwarding after native policy reconciliation on every startup.
  Host/interface policy rules support optional managed `out_interface` matches;
  IPv4 masquerade accepts DHCP-client WANs without static address copies.
  Recommended bump: major for the changed installer/service deployment contract;
  baseline unknown, no release assigned. Linux build/packet-path acceptance is
  outstanding; no LAN DHCP/DNS server or IPv6 forwarding is provisioned. See
  [handoff 2026-10-23-03](docs/frontend-handoffs/2026-10-23.md#2026-10-23-03-automatic-ports-dhcp-wan-and-input-filtering).
- Optional persisted `firewall.input` default and managed-ingress policies,
  validated with existing host-rule limits and `firewall.write` authorization.
  Input filtering is installed atomically with forwarding/NAT in the owned
  nftables table; removing it explicitly removes that input protection.
- Automatic first-start inheritance of physical NICs for an unused native host
  journal, with `unassigned` roles, networkd per-NIC ownership handover,
  original snapshot/route recovery and explicit unsupported-host errors.
- In-process DHCPv4 clients with durable leases/update intents, dynamic routes,
  resolver publication and runtime lease/error inspection. A vendored Apache-2.0
  mozim correction propagates DHCP NAKs; the existing netlink stack is reused.
  Top-level `dhcp_clients` and `dns` configuration maps use `interfaces.write`,
  including shared repair authorization. No first-party test code added per
  user direction. Linux compilation and runtime acceptance remain outstanding.

### Changed

- Ubuntu fresh installation and full development upgrades now load/persist
  `nf_conntrack`, enable packet/byte accounting and checksum validation, and
  verify live settings before provisioning or replacing the daemon. Installer
  adds `kmod`; existing upgrade hosts need `kmod`/`procps`. Build-only and HTTP
  reads remain non-mutating. Existing flows can retain null counters; no flush,
  reset or arbitrary capacity/timeout tuning. Recommended bump: patch for
  missing appliance accounting prerequisites; baseline unknown. Linux reboot
  acceptance remains pending. See [handoff 2026-10-24-06](docs/frontend-handoffs/2026-10-24.md#2026-10-24-06-conntrack-installation-prerequisites).

- Frontend contract clarification: the interface overview must use live inventory
  for active addresses, show DHCP-assigned IPv4 even when configured static
  addresses are empty, and include loopback/unmanaged/unsupported links by
  default. Backend API/runtime behavior is unchanged; rendering remains pending
  in the separate frontend. Release impact: none for this backend documentation/
  regression change; recommend a frontend patch when implemented. See
  [handoff 2026-10-24-04](docs/frontend-handoffs/2026-10-24.md#2026-10-24-04-live-interface-addresses-and-loopback-visibility).

- Factory reset now prompts for confirmation with `sudo bash reset.sh`; `--yes`
  is optional for unattended use. Blank, declined/invalid input and EOF cancel
  before host checks or changes. Recommended bump: patch for CLI usability;
  baseline unknown, no release assigned.

- Native daemon startup and `upgrade.sh` now require saved configuration and do
  not initialize desired state from live NIC settings. Missing installed services
  are upgrade errors instead of implicit installations. Owned host interfaces are
  reconciled to the saved plan on startup drift; live snapshots remain rollback
  data only. Explicit first-install provisioning remains separate. Recommended
  bump: major for the changed startup/deployment contract; baseline unknown.

- Interface roles accept `unassigned` in addition to `wan`/`lan`. First native
  host startup now takes supported physical NIC IP/DHCP ownership instead of
  always starting empty. Target hosts require networkd/resolved; NetworkManager,
  dynamic global IPv6, bridged/bonded ports, custom policy rules and unsupported
  networkd options are rejected. Recommended bump: major for initial ownership,
  persisted configuration and frontend/deployment contract changes; no approved
  release baseline or release assigned. See the 2026-10-23 journal/handoff.

- Renamed the operator script from `in-place-upgrade.sh` to `upgrade.sh`; use
  `bash upgrade.sh [--build-only]`. Behavior and build-cache location are unchanged.
  Recommended bump: major for the breaking script entry-point rename; no approved
  release baseline.

### Fixed

- DHCP-managed interfaces now reconcile their enabled IPv4 static routes after
  lease acquisition, renewal and address replacement, restoring protocol-242
  routes lost by the kernel. Lease loss suspends those routes without changing
  saved settings; valid acquisition restores them after connected DHCP routes.
  Scoped ownership/conflict checks, readback, lease intents and rollback remain
  enforced. Normal configuration reconciliation also rereads routes after address
  changes instead of trusting a stale presence cache. Recommended bump: patch;
  baseline unknown. Frontend action required for lease-dependent status wording;
  see [handoff 2026-10-25-02](docs/frontend-handoffs/2026-10-25.md#2026-10-25-02-dhcp-dependent-static-route-lifecycle).

- Native startup/reboot ownership comparison now projects recorded configurations
  through the same strict typed operational representation as current candidates.
  Daemon-owned MQTT settings are excluded from native networking/service plans,
  avoiding false durable-ownership mismatches from irrelevant serialized fields
  and native mutations/restarts for MQTT-only edits. Network mismatch/unknown-field
  guards remain; no state reset, adoption bypass or migration. Recommended bump:
  patch; baseline unknown. No API/schema/frontend change.

- Gateway-monitor apply failures now preserve the underlying apply and rollback
  error chains in HTTP errors and durable transaction records. Native service
  configuration/opt-ins are validated before stopping workers or changing
  networking. Host monitoring requires host-service and gateway-probe opt-ins. Added
  [operator setup](docs/BUILD_AND_INSTALL.md#enabling-gateway-monitoring-on-an-installed-appliance).
  Recommended bump: patch; baseline unknown. Optional frontend troubleshooting
  guidance: [handoff 2026-10-24-13](docs/frontend-handoffs/2026-10-24.md#2026-10-24-13-gateway-monitor-prerequisites-and-apply-errors).

- Appliance install/full upgrade now automatically persist host-service and
  gateway-monitoring permissions in a managed systemd environment drop-in,
  preserving custom units/startup arguments. Daemon accepts strict boolean
  `NETCONTROL_ALLOW_HOST_SERVICES` and `NETCONTROL_GATEWAY_MONITORING` equivalents
  of its existing flags; direct-run defaults remain disabled. Setup/reload
  failures abort deployment; build-only remains mutation-free. Installer requires
  current artifacts exposing those settings. Recommended bump: patch for making
  appliance monitoring usable; baseline unknown. Optional deployment guidance:
  [handoff 2026-10-24-14](docs/frontend-handoffs/2026-10-24.md#2026-10-24-14-automatic-appliance-monitoring-permissions).

- CI metadata fixtures distinguish string-valued host records from the kernel
  `host` map, avoiding unsupported metadata injection without relaxing schemas.
  Empty native host startup checks its no-firewall guard before bootstrap,
  preserving verification-only startup and failed-first-transaction rollback.
  DHCP cleanup removes obsolete owned routes before deleting the leased address,
  avoiding stale route deletions after kernel address cleanup (`ESRCH`). Full
  workspace tests and all 17 privileged native/service regressions now pass
  locally. No API/schema/frontend change. Recommended bump: patch; baseline unknown.

- State checksum verification hashes the saved JSON payload before current-model
  decoding, instead of reserializing typed state. Model field ordering/defaults
  (including `ipv6_enabled`) no longer falsely report valid journals as corrupt.
  Writes hash/publish a single serialization; corruption, unknown fields and
  incompatible state still fail without reset, migration or checksum repair.
  Added field-order/default/tamper regressions. No HTTP/frontend contract change.
  Recommended bump: patch; baseline unknown.

- Native DHCP lease application installs direct/connected routes before routes
  through a gateway. Previously canonical route sorting put the default route
  first while the leased address used `NOPREFIXROUTE`, so a fresh lease could
  fail with an unreachable gateway and roll its address back despite a DHCP ACK.
  Added isolated Linux lease application/renewal/removal regression coverage;
  privileged execution now passes, including the cleanup correction above.
  No API/schema change. Recommended
  bump: patch; baseline unknown.

- Local factory reset reads saved desired configuration directly rather than
  calling observation-backed state retrieval, so pre-existing address drift no
  longer blocks reset preparation with a provisioning 503. Post-apply verification,
  rollback, identity/ownership checks and normal API behavior remain unchanged.
  Recommended bump: patch; baseline unknown.

- Factory reset moves the temporary networkd Wi-Fi recovery override into its
  private backup before native handover, so it no longer takes precedence over
  the managed-interface exclusion. Unrelated networkd configuration and normal
  startup checks remain unchanged. Recommended bump: patch; baseline unknown.

- Inherited host startup reasserts networkd ownership exclusions for still-managed
  physical NICs before retained-intent recovery, DHCP startup and resolver writes.
  Prevents resolved `LinkBusy` failures when networkd reclaimed a NIC after reboot
  or console recovery. Identity and conflicting-file checks remain enforced;
  lab/non-inherited configurations and released interfaces are not taken over.
  No state reset, address-drift bypass or API/schema change. Recommended bump:
  patch; aggregate Unreleased remains major. Linux compilation/runtime validation
  remains outstanding.

- Physical-NIC handover publishes non-secret networkd exclusion files as `0644`
  so the unprivileged networkd service can read them; matching prepared-receipt
  files receive the same mode on retry. Failures now report the observed
  administrative state and selected network file. Captured DHCP connected-subnet
  routes retain DHCP protocol 243 and expire with their lease instead of being
  misclassified as static routes. Recommended fix bump: patch; aggregate
  Unreleased remains major. Linux rebuild/runtime verification pending.

- Initial physical-NIC inheritance now accepts Linux's disabled rule-suppression
  sentinel on otherwise standard local/main/default policy rules. Previously it
  misclassified that default netlink metadata as custom routing and aborted
  startup. Active suppression, selectors and custom rules remain rejected; the
  startup error now identifies the offending rule. Recommended fix bump: patch;
  aggregate Unreleased remains major. Linux rebuild/runtime validation pending.

- Incremental deployment failures now print the failed phase/exit code, systemd
  process result and bounded service journal before binary recovery. Diagnostic
  failures do not block restoration. No health-check, state rollback or frontend
  contract change. Recommended fix bump: patch; aggregate Unreleased stays major.

- Fixed native inheritance compilation: imported the missing `bail!` macro,
  exposed route-key decoding only to sibling Linux modules, and compared DHCP
  preferred sources using netlink's IPv4 `RouteAddress` type. Vendored DHCP timer
  and raw-socket registration now use Tokio's `AsyncFd::register` with owned
  descriptors and explicit I/O-error conversion, removing deprecated constructor
  usage. Recommended fix bump: patch; aggregate Unreleased remains major.
  Linux build/runtime verification is still pending.

- Incremental upgrades discover the active service's direct executable from
  systemd rather than requiring `/usr/local/sbin/netcontrold`. Replacement and
  backup now use that installed path; wrappers/ambiguous commands are rejected
  with diagnostic output. Recommended fix bump: patch; no release assigned.

- Native direct IPv6 route creation/observation now uses Linux universe scope
  instead of expecting IPv4 link scope. Fixes apply/rollback failures and the
  privileged integration gate that blocked CI packaging. Unexpected route
  scopes remain rejected. Recommended fix bump: patch; aggregate Unreleased
  remains major, with no approved baseline.

- Documented an Ubuntu amd64 source-install command that installs stable Rust
  through rustup as well as native build dependencies, checks the checkout
  directory, and selects the GNU target explicitly. Documentation only;
  no runtime, signed-package or service-startup changes. Recommended bump: none.

### Added

- Incremental upgrader now installs a missing systemd unit/private directories
  and starts the built daemon, including when no binary exists or the service
  is inactive. Existing units are preserved, unmanaged daemons rejected, and
  failed deployment recovers the previous binary/running state where possible.
  Boot enablement remains operator-controlled. Recommended bump: minor;
  aggregate Unreleased remains major, with no approved baseline.

- Ubuntu amd64 incremental development upgrade script using a persistent Cargo
  cache and debug builds, with build-only mode, staged replacement of the active
  systemd daemon and best-effort previous-binary recovery. No Docker, Git fetch,
  automatic prerequisite installation or state rollback. Recommended bump: minor;
  aggregate Unreleased remains major, with no approved baseline.

- Ubuntu systemd service installed by the source bootstrap, with private state
  directories, native host-mode arguments, journald logging and explicit
  operator-controlled start/boot enablement. Differing existing unit files are
  not overwritten. Recommended feature bump: minor; no release assigned.

- Ubuntu amd64 `install.sh` source bootstrap: installs native build dependencies
  and stable Rust, fetches a selectable GitHub ref and installs the daemon.
  Does not configure networking, start services or change signed packaging.
  Recommended feature bump: minor; no release baseline assigned.

- Read-only `GET /api/v1/interfaces/discovered` and `show interfaces discovered`
  for interface inventory, independent of configured state/worker health.
  Ethernet configuration accepts existing host Ethernet/veth NICs; main routing
  table `254` is supported alongside reserved tables.

- Cisco-inspired configuration CLI over an optional in-process Rust SSH server,
  using existing API keys/permissions, private session candidates, complete-schema
  typed editing and the same confirmed-apply/rollback/revision engine as HTTP.
  Persistent Ed25519 host keys; no system sshd, shell, forwarding or file transfer.
  Recommended feature bump: minor; aggregate Unreleased remains major.

- Rust-only workspace with typed configuration, complete-package transactions,
  durable confirmation/rollback/recovery, committed revisions, a simulator,
  direct Linux networking, embedded onboarding, API keys and optional native TLS.
- In-process Rust DHCPv4 relay, slew-only NTP client, RFC5424 remote syslog,
  persistent host/managed traffic counters and history, NetFlow v1/v5/v9/IPFIX
  export, and ICMPv4/v6 gateway monitoring. Workers use sockets/kernel APIs,
  not supervised protocol daemons.
- Native `netcontrol-package` tooling for Ed25519-signed `.ncpkg` construction,
  verification, ownership-aware installation, durable rollback and interrupted
  install recovery; static musl x86-64/ARM64 package targets and OpenRC assets.
- Rust Linux/Windows CI checks, opt-in privileged Linux integration fixtures,
  and custom-package build jobs. Binary artifact upload requires explicit
  manual opt-in after distribution licensing review; the native backend links
  GPL-3.0-or-later `rustables`, and no project distribution license is assigned.
- `state.read` traffic-history GETs at `/api/v1/statistics/vnstat`,
  `/api/v1/statistics/vnstat/host`, and `/api/v1/statistics/vnstat/managed`,
  with decimal-string counters and explicit unavailable errors.

- Allow-all-origin CORS for bearer-authenticated `/api/v1/` in both authentication
  modes, with unauthenticated GET/POST preflights and browser-visible API errors
  and transaction Location headers. Account/key management remains same-origin;
  cross-origin cookie credentials are not enabled. Recommended feature bump:
  minor; aggregate Unreleased recommendation below remains unchanged.

- Persistent NTP, remote syslog, and traffic-accounting settings with scoped
  permissions, simulated/native status and shared repair APIs. Host-wide
  effects require explicit operator ownership and host-service opt-in.

- Native IPv4/IPv6 ICMP gateway monitors with explicit source/interface/table/
  next-hop checks, rolling loss/RTT/percentiles/consecutive RTT variation,
  configurable warmup/health holds, cached JSON statistics and service repair,
  scoped `gateway_monitors.write` permission, and operator opt-in.
  No dpinger dependency, automatic failover, or Prometheus endpoint.

- Per-interface DHCPv4 relay settings (`dhcp_relay.enabled` and `servers`),
  native relay lifecycle on Linux, operator CLI settings, runtime
  status/repair APIs, simulation, and transaction/revision persistence.
- Required `role` (`wan` or `lan`) on every managed interface, preserved through
  configuration reads, durable state, transaction/revision workflows, and Linux
  observation. Descriptive metadata only; no automatic network policy changes.
- `config.firewall.allow_all_icmp`: default-enabled IPv4 protocol 1 acceptance on
  every interface in the managed namespace, for input, output, and forwarding.
  Supports explicit disabling, existing firewall permissions, transaction
  confirmation/rollback, durable state, and revision restoration.
- Daily change memory and frontend handoff workflow in repository Copilot
  instructions.

### Changed

- CI now runs only on Ubuntu x86-64: removed Windows checks and ARM64 package
  jobs while retaining native integration, systemd/installer validation and
  gated x86-64 package artifacts. CI-only change; recommended bump: none.

- Ubuntu installer now requires `--run-id` and downloads checksum-verified
  prebuilt daemon/unit artifacts from successful manually dispatched GitHub
  Actions builds; source compilation and `--ref` are removed. GitHub Actions
  authentication and an opt-in uploaded artifact are required. Existing CI
  release/publication gates remain unchanged. Recommended bump: major for the
  installer CLI/deployment contract; no approved release baseline assigned.

- Native Linux networking now defaults to the daemon's host network namespace;
  an explicit namespace is optional for isolated labs. Alpine package arguments
  select native host mode; the bare daemon still defaults to the simulator.
  Host-NIC onboarding is explicit rather than automatic takeover. Recommended
  bump: major for native scope, deployment and physical-interface semantics;
  no release baseline or version is assigned.

- Replaced the Go implementation with Rust; there is no wrapper, dual runtime,
  compatibility endpoint or persisted-data importer. Incompatible/corrupt state
  is rejected without deletion or reset. Network state requires the checksummed
  `netcontrol-rust-state-v1` envelope; identity and scoped-auth JSON require
  `schema: 1`. Scoped credentials are an object containing `credentials`, not
  a bare array.
- Configuration JSON rejects unknown fields and explicit nulls for nonoptional
  fields; missing structural fields return 400, semantic errors 422. Transaction
  responses omit `kernel_before`/`kernel_after`. Observation failures return 503;
  service repair rejects networking drift with 409; startup reconciliation
  failures fail startup. Device session-limit conflicts now return 409.
- Native runtime states describe workers (`disabled`, `running`, `error`,
  `stopped`), not child processes; no PIDs are exposed. Flow capture filters
  support only empty/ip/ip6/tcp/udp/icmp/icmp6; fragments are excluded. NTP requests
  only bounded +/-500 ms slews and reports accepted sample/correction metrics,
  never synchronization merely because a worker is running.
- CLI options use conventional `--long-options`. Backend logging uses
  `<services-state-dir>/backend.log`; syslog TLS uses system trust.

- Daemon and Alpine package default to unencrypted HTTP on `0.0.0.0:8080` for
  direct browser onboarding without an SSH tunnel. Non-loopback HTTP is allowed;
  TLS remains optional with a certificate/key pair. Startup warns about plaintext
  credentials. This includes WAN-facing IPv4 interfaces unless externally
  restricted; authentication is unchanged. Recommended bump: major for the
  changed default management exposure.

- All service repair endpoints require `ntp.write`, `syslog.write`, and
  `vnstat.write` respectively when those services are enabled. Host-wide
  service effects require explicit operator ownership and host-service opt-in;
  no automatic takeover of existing clock/logging services is performed.

- Service repair checks permissions for every enabled managed service under the
  engine lock; softflowd-only credentials cannot repair enabled DHCP relays,
  and interface-only credentials cannot repair enabled softflowd instances.
  All repair endpoints also require `gateway_monitors.write` when any gateway
  monitor is enabled.
- Interface configurations and saved snapshots without an explicit valid role
  are rejected. No default role or older-format migration is provided.
- Repository development policy is explicitly greenfield: no backward
  compatibility requirements or compatibility-only migrations/fallbacks unless
  specifically requested. Keep the current backend/frontend contract coordinated.
- Omitted `allow_all_icmp` defaults to enabled in valid current configuration;
  explicit `false` retains rule/default-controlled behavior, and explicit null
  is rejected. This is not an old-state migration.

### Removed

- User-configurable source-policy routing: configuration `policy_rules`
  (including empty/null values), `/api/v1/policy-rules`, `policy.write`, and CLI
  policy-rule/show commands. Normal destination routes remain supported;
  gateway monitors derive internal host-source rules with deterministic priorities,
  rejecting conflicting tables for a shared source. Native apply/drift/rollback/
  restart and private reboot snapshots retain monitor routing. Probe FIB checks
  now request the actual policy-selected table. Recommended bump: major for the
  breaking API/configuration/permission/CLI contract; baseline unknown.
  No migration or state reset. Frontend action required; see
  [handoff 2026-10-24-10](docs/frontend-handoffs/2026-10-24.md#2026-10-24-10-remove-user-configurable-source-policy-routing).

- All Go sources/tests and module manifests, the old Alpine APK/abuild packaging,
  and external dnsmasq/chronyd/syslog-ng/vnstatd/softflowd supervision.
- External executable, child UID/GID and runtime-directory options,
  `--backend-log-file`, and `--syslog-ca-file`. No legacy aliases are provided.

### Fixed

- Standardized firewall access terminology as "API key" in current operator and
  frontend documentation and authentication errors. HTTP Bearer authentication
  and existing JSON/configuration field names are unchanged. Recommended bump:
  patch; aggregate Unreleased recommendation remains unchanged.

- Rust publication handles transient Windows file-sharing conflicts using
  bounded retries and supports extended-length paths. OpenRC package payloads
  retain LF line endings even when built from a CRLF checkout.
- Service-repair prechecks separate networking ownership/drift from worker
  health, so a failed worker can be restarted without bypassing network safety.
- Central flow validation rejects unsupported filters and v5 sampling above
  16383 with 422, including simulator submissions. Package ELF validation rejects
  shared dependencies without interpreters and invalid executable/load segments.

Release recommendation: **major**, for the Rust-only persisted-state, CLI,
service-runtime and packaging contracts as well as changed management exposure.
No release baseline is assigned; Cargo `0.0.0` is development metadata, not an
approved release. Privileged Linux and physical Alpine acceptance remain pending;
cross-compilation does not establish native correctness.
