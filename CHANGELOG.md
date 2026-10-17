# Changelog

## Unreleased

### Added

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

- Service repair checks permissions for every enabled managed service under the
  engine lock; softflowd-only credentials cannot repair enabled DHCP relays,
  and interface-only credentials cannot repair enabled softflowd instances.
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

- DHCP relay initialization no longer depends on configuring softflowd; the
  native lifecycle test explicitly checks independent relay integration.

Release recommendation: **major**, because default behavior broadens accepted
traffic for existing configurations. No release baseline or version is assigned.
