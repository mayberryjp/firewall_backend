# Changelog

## Unreleased

### Added

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
