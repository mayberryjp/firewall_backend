# Changelog

## Unreleased

### Fixed

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
