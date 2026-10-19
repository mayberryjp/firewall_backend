# Changelog

## Unreleased

### Added

- Allow-all-origin CORS for bearer-authenticated `/api/v1/` in both authentication
  modes, with unauthenticated GET/POST preflights and browser-visible API errors
  and transaction Location headers. Account/key management remains same-origin;
  cross-origin cookie credentials are not enabled. Recommended feature bump:
  minor; aggregate Unreleased recommendation below remains unchanged.

- Persistent NTP, remote syslog, and vnStat settings with scoped permissions,
  simulated/native status and shared repair APIs. Opt-in native supervision
  runs slew-only chronyd and whole-appliance syslog-ng in host networking, plus
  separate host/managed vnstatd instances with retained databases and explicit
  all-interface inventory, including loopback. Added Alpine syntax and native
  vnStat lifecycle/discovery/traffic CI coverage.

- Native IPv4/IPv6 ICMP gateway monitors with explicit source/interface/table/
  next-hop checks, rolling loss/RTT/percentiles/consecutive RTT variation,
  configurable warmup/health holds, cached JSON statistics and service repair,
  scoped `gateway_monitors.write` permission, and operator opt-in.
  No dpinger dependency, automatic failover, or Prometheus endpoint.

- Automatic GitHub Actions checks and Alpine 3.23 APK builds for x86_64/aarch64,
  with OpenRC integration, install smoke checks, development-build provenance,
  ephemeral signing keys, checksums, and a build/installation specification.
- Per-interface DHCPv4 relay settings (`dhcp_relay.enabled` and `servers`),
  managed relay-only dnsmasq lifecycle on Linux, operator CLI settings, runtime
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
- Older saved configurations and snapshots without `allow_all_icmp` now default
  to enabled. Startup migrates owned firewall rules atomically while rejecting
  unrelated firewall drift. This can override previous forwarding ICMP drops;
  explicit `false` retains rule/default-controlled behavior.

### Fixed

- Standardized firewall access terminology as "API key" in current operator and
  frontend documentation and authentication errors. HTTP Bearer authentication
  and existing JSON/configuration field names are unchanged. Recommended bump:
  patch; aggregate Unreleased recommendation remains unchanged.

- Windows CI preserves LF Go source line endings for formatting checks.
  The native vnStat lifecycle test removes its externally created discovery
  interface before transactions, preserving managed-namespace drift protection.

- DHCP relay reconciliation runs independently of the softflowd instance loop;
  relay-only native updates no longer skip service reconciliation.

- DHCP relay initialization no longer depends on configuring softflowd; the
  native lifecycle test explicitly checks independent relay integration.

Release recommendation: **major**, because default behavior broadens accepted
traffic for existing configurations. No release baseline or version is assigned.
