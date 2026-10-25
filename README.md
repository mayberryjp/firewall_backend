# Netcontrol

Netcontrol is a Rust network-control daemon with an embedded device setup
website, API-key-authenticated HTTP API, durable configuration transactions,
and a custom signed packaging system.

This is a greenfield **host-managed firewall appliance**. The native Linux
backend controls the machine's networking; an isolated namespace is an optional
lab tool, not an appliance prerequisite. Production readiness still requires
Linux/Alpine runtime, boot/recovery and connectivity acceptance. A running
process or simulator result is not evidence that real networking works.

## Rust-only architecture

| Component | Responsibility |
| --- | --- |
| [netcontrold](crates/netcontrold) | HTTP listener, device account, API keys, sessions, embedded UI |
| [netcontrol-core](crates/netcontrol-core) | Typed configuration, authorization, transactions, rollback, revisions, persistence, simulator |
| [netcontrol-native](crates/netcontrol-native) | Direct Linux host networking, interface discovery and owned configuration |
| [netcontrol-services](crates/netcontrol-services) | Native protocol and statistics workers |
| [netcontrol-package](crates/netcontrol-package) | Signed `.ncpkg` creation, verification, installation and installation recovery |

There is no Go executable, Go wrapper, dual backend, or Go-state migration path.
Protocol services run in Rust rather than supervising dnsmasq, chronyd,
softflowd, syslog-ng, or vnstatd. The operating system's OpenRC service starts
the single daemon; it is not a protocol implementation.

Backward compatibility is not a constraint. Invalid or unsupported
configuration must produce explicit errors rather than permissive defaults or
successful no-op operations. Existing on-device data must never be deleted to
force a new schema to load.

## Build and validate

Use stable Rust. The workspace toolchain file selects rustfmt and clippy;
Cargo.lock pins dependencies. A supported native C toolchain is needed for TLS
cryptography; Linux builds also require libclang and Linux UAPI headers for the
direct nftables bindings. See the [build prerequisites](docs/BUILD_AND_INSTALL.md#build).

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
```

Linux kernel and privileged protocol tests are separate:

```sh
NETCONTROL_INTEGRATION=1 cargo test \
  -p netcontrol-native -p netcontrol-services --locked -- --ignored
```

Run these only on an appropriately privileged, disposable Linux test machine.
Portable Windows tests and Linux cross-compilation do not establish native
runtime correctness. Consult the [change journal](docs/journal/2026-10-19.md)
for actual validation results and known limits of the rewrite.

For fast development on an Ubuntu amd64 firewall, use
[upgrade.sh](upgrade.sh) to build incrementally and restart
the daemon without Docker or waiting for CI. An installed service and saved
configuration are required; upgrades never provision from live interfaces. See the
[setup and recovery limitations](docs/BUILD_AND_INSTALL.md#incremental-ubuntu-development-upgrades).
Ubuntu installation and full upgrades also enable and persist conntrack accounting
and checksum validation; existing flows may retain null counters. See
[conntrack host prerequisites](docs/BUILD_AND_INSTALL.md#conntrack-host-prerequisites).

Optional Ubuntu amd64 self-upgrade uses `POST /api/v1/system/upgrade` with a
specific SemVer version and `GET` on the same path for durable job status.
It is disabled until a trusted release-signing public key and fixed GitHub
repository are configured. See [signed self-upgrades](docs/BUILD_AND_INSTALL.md#signed-ubuntu-self-upgrade)
for bootstrap, artifact publishing, recovery and validation limitations.

For optional Ubuntu OS footprint reduction, start with `sudo bash hardening.sh`
to preview the explicit service/package profile. Nothing changes without
`--apply`. AppArmor remains enabled unless `--disable-apparmor` is explicitly
selected; that protection opt-out requires GRUB and a later manual reboot.
See [scope and recovery](docs/BUILD_AND_INSTALL.md#ubuntu-os-footprint-reduction).

## Start and onboard

For a development simulator:

```sh
cargo run -p netcontrold -- \
  --backend simulator \
  --listen 0.0.0.0:8080 \
  --state state.json \
  --credential-db credentials.json
```

Open `http://<machine-LAN-IP>:8080/` in your browser. No SSH tunnel or TLS
certificate is required by the default HTTP configuration.

1. Create the device account with a username and password.
2. Generate a named **API key** and save the one-time plaintext value.
3. Acknowledge saving the key and finish setup.
4. Configure your API client with the appliance address and API key.

The device account manages keys; it does not authorize networking calls.
The API key authorizes networking calls; it does not manage the account.
`Bearer` is the HTTP authorization scheme, not the user-facing credential name:

```http
Authorization: Bearer <API key>
```

Unclaimed devices can be claimed by anyone able to reach the website.
`0.0.0.0` includes all IPv4 interfaces, including WAN-facing ones. HTTP
transmits passwords, session cookies, and API keys without encryption.
Restrict management reachability appropriately. Optional TLS requires a
certificate and private key together.

On LAN HTTP origins browsers may disable automatic clipboard access; manually
select and copy the API key when needed. The plaintext cannot be recovered
after the one-time dialog closes.

### Cross-origin dashboard access

Networking paths under `/api/v1/` allow all origins, including error responses.
Valid preflight requests allow GET/POST with Authorization and Content-Type.
Actual requests still require an API key and the appropriate permissions.
Use `credentials: "omit"` for cross-origin dashboard calls.

Account and key-management paths under `/auth/` remain same-origin and use
HttpOnly, SameSite=Strict session cookies. HTTP cookies are not Secure; HTTPS
cookies are Secure. CORS does not bypass mixed-content, certificate,
private-network, or network-reachability restrictions.

## Configuration workflow

### Routing scope

User-configurable source-policy routing is unsupported. Omit `policy_rules`
from configuration; even an empty array is rejected. There is no
`/api/v1/policy-rules` endpoint, `policy.write` grant or `policy-rule` CLI command.
Ordinary destination routes remain supported; use table 254 (main) for normal
traffic. Enabled gateway monitors retain backend-managed host-source rules for
their explicit routing tables. Monitors sharing a source must share a table;
these internal rules affect all traffic from that exact source, not only probes.
DHCPv4 monitors instead use `mode: "dhcp"`, interface and target without pinned
source/gateway/table. They follow only that interface's active lease, wait with
Unknown health before acquisition, and never fall back to another WAN. Private
interface-scoped paths are runtime-owned, not editable routes. Explicit IPv4/IPv6
monitors are unchanged. See the [monitor contract](FRONTEND_SPEC.md#612-gateway-health-and-rtt-variation).
Host appliance monitoring requires both `--allow-host-services` and
`--gateway-monitoring`; the shipped unit does not enable them. See
[installed-appliance setup](docs/BUILD_AND_INSTALL.md#enabling-gateway-monitoring-on-an-installed-appliance).
See [the routing contract](FRONTEND_SPEC.md#65-source-policy-routing).

### Global IPv6 policy

The top-level `ipv6_enabled` boolean defaults to `true`, including fresh
installation and factory configuration. Set `"ipv6_enabled": false` in the
complete configuration submitted through the normal confirmed transaction
workflow, or stage `ipv6 disable` in the configuration CLI. Changing it requires
`kernel.namespace.write` as well as `transactions.write`.

On Linux, disabling writes and verifies `net.ipv6.conf.default.disable_ipv6=1`,
`net.ipv6.conf.all.disable_ipv6=1` and every existing interface's `disable_ipv6`,
including loopback and unmanaged links. New interfaces inherit the disabled
default. The scope is the daemon's managed network namespace (the appliance
host in normal installations). Re-enabling sets these controls to `0` before
restoring configured IPv6 networking; it does not enable IPv6 forwarding.

Remove IPv6 addresses, routes, policy/firewall/NAT references, DNS/server
literals, WireGuard endpoints/allowed prefixes, monitors and exporter collectors/
IPv6-only filters from the same candidate before disabling. Conflicts return
validation errors rather than silently dropping configuration. Service hostname
resolution becomes IPv4-only and flow exporters exclude IPv6. Runtime reports
the desired switch and observed controls under `ipv6`; simulator values are
explicitly unmeasured.

IPv6 management sessions will disconnect: apply over IPv4 with independent
console access and explicitly confirm or roll back. Saved policy is reapplied
on daemon startup/reboot; this does not change bootloader arguments, unload IPv6,
or disable it before the daemon starts. Missing kernel controls or required
writes to read-only sysctls fail explicitly. Same-boot rollback/re-enable restores captured unmanaged IPv6
addresses/routes without extending finite lifetimes; stale prior-boot snapshots
are not resurrected. See the [frontend contract](FRONTEND_SPEC.md#global-ipv6-policy).

### Editing configuration

Configuration resources support optional `metadata.display_name` and
`metadata.description`, including Ethernet/VLAN/WireGuard interfaces, peers,
routes, policies, firewall/NAT rules, DHCP/DNS settings and service instances.
These annotations are persisted with the normal transaction/revision workflow;
they never replace technical identifiers or interface references. See the
[metadata contract](FRONTEND_SPEC.md#14-descriptive-object-metadata) and
[labelled VLAN example](examples/vlan-softflowd.json).

Networking changes use a full configuration package, not independent resource
edits:

1. Read desired configuration, revision, runtime, and live observation.
2. Submit a candidate against the current base revision with a confirmation
   timeout.
3. Inspect the provisional live result and verify independent management
   connectivity.
4. Confirm explicitly or roll back. Timeout and interrupted-operation recovery
   must retain the previous valid configuration.

Do not treat `202 Accepted` as a committed revision. An uncertain HTTP write
must be reconciled through transaction reads, not blindly retried.
Interfaces require an explicit `wan`, `lan`, or `unassigned` role; roles do not automatically
rewrite policy. The Ubuntu appliance installer explicitly provisions those roles,
a static LAN address, LAN-to-WAN forwarding, and IPv4 masquerade. Installed
appliance mode enables host IPv4 forwarding after native policy reconciliation
on every startup; changing roles through the API does not regenerate policy.

During explicit first-install provisioning, a new or untouched empty revision-zero
journal captures physical NICs, addresses/routes, MTU, administrative state,
DHCPv4 identity and resolver configuration for handover and rollback. Initial
installation then applies the same clean factory plan as explicit reset: selected
WAN/LAN, other saved Ethernet interfaces unassigned without IP/DHCP configuration.
Netcontrold takes per-NIC IP/DHCP ownership from systemd-networkd; it does not
guess WAN/LAN, reset configured journals, or copy DHCP addresses as static ones.
The installer provisions and starts the appliance. Ordinary native startup and
`upgrade.sh` use the saved configuration; they do not inherit live settings.
Startup reconciles managed interfaces to that saved plan. Temporary recovery
addresses are not saved configuration and can be removed during reconciliation.

Use `sudo bash reset.sh` from a local console and confirm the prompt to replace
current networking with factory WAN/LAN defaults. `--yes` skips confirmation for
unattended use. Optional paired `--wan`/`--lan` overrides select
ports. Reset backs up state and preserves credentials, keys and revision history;
it does not delete journals or reconstruct desired settings from the live NICs.
See [factory reset](docs/BUILD_AND_INSTALL.md#factory-configuration-reset).

This implementation targets systemd-networkd/systemd-resolved hosts. A DHCP NIC
needs an active finite lease for identity/lifetime inheritance. NetworkManager,
bridged/bonded ports, dynamic global IPv6, custom policy routing and unsupported
networkd options fail explicitly. Existing Wi-Fi association remains with its
supplicant. DHCP runs in Rust, with durable leases and owned routes, not a
supervised external client. See the [handover prerequisites and acceptance
limits](docs/BUILD_AND_INSTALL.md#automatic-physical-interface-inheritance).

Discovery remains read-only: `GET /api/v1/interfaces/discovered` inventories live
links, while `GET /api/v1/interfaces` returns managed configuration. DHCP settings
and static DNS are stored in top-level `dhcp_clients` and `dns` maps; active leases
are separate in `GET /api/v1/runtime` under `dhcp_clients`. There is no DNS server.
Routes may target main table `254` or reserved tables `10000..19999`.

The [frontend contract](FRONTEND_SPEC.md) records API fields, endpoints,
permissions and workflow. The Rust rewrite changes persisted implementation and
service lifecycle; see its current implementation notes and handoff before
using historical examples.

## Install on Ubuntu

An Ubuntu amd64 [prebuilt installer](install.sh) downloads verified binaries
from a successful manually dispatched GitHub Actions run. No Rust/compiler
installation is needed on the firewall. GitHub authentication and an approved
artifact-producing workflow run are required; there is no public release yet.
See the [download command and prerequisites](docs/BUILD_AND_INSTALL.md#ubuntu-prebuilt-installation-amd64).
It automatically provisions a fresh appliance:

```sh
sudo bash install.sh --run-id 123456789
```

Use the actual approved workflow run ID. The first physical Ethernet interface
in natural name order (`eno1`, `eno2`, ...; Wi-Fi/virtual links excluded) is WAN;
the second is LAN. Override with both `--wan` and `--lan` when needed. LAN
defaults to `192.168.0.1/24` (`--lan-address` overrides it); WAN is configured
for DHCPv4, not retained as static. The installer waits up to 30 seconds for an
upstream lease/default route and rolls back its transaction on failure.
It enables/starts the service, binds HTTP management to the LAN address,
installs LAN allow-all forwarding and input rules, drops unsolicited inbound
WAN traffic, permits replies and WAN DHCP, and masquerades the LAN subnet on WAN.
Existing appliance state is not reset.
LAN clients currently need static addresses and the appliance as their gateway;
no LAN DHCP or DNS server is installed. IPv6 forwarding is not enabled.
Use console access during provisioning. See the
[service commands](docs/BUILD_AND_INSTALL.md#ubuntu-systemd-service). The GitHub
download command requires the installer to be pushed and the reviewed artifacts
to be built and uploaded first.

## Install on Alpine

Use the [native build and installation guide](docs/BUILD_AND_INSTALL.md).
Packages contain static musl binaries for x86-64 or ARM64, an OpenRC unit, and
operator configuration. Installation uses the Rust package tool, not APK/abuild.
Packages are Ed25519-signed and verified before installation; the installer
has explicit ownership checks and durable rollback information.

The installed package selects native Linux host mode with HTTP on
`0.0.0.0:8080`; the bare daemon's development default remains simulator mode.
The installer does not configure a LAN address, enable the service at boot
or start routing. Discovery does not take ownership of every interface.
Do not delete configuration, credentials or history to work around startup
failures. Preserve console access while changing host management networking.

## Configuration CLI over SSH

The daemon includes a Cisco-inspired CLI and an in-process Rust SSH server.
Enable it explicitly; it does not require or launch a system `sshd`:

```sh
netcontrold --state state.json --credential-db credentials.json \
  --ssh-listen 0.0.0.0:2222
ssh -p 2222 apikey@192.0.2.10
```

Use the literal username `apikey` and your existing **API key** at the password
prompt. Account passwords are not networking credentials. The persistent
Ed25519 host key defaults to `<state>.ssh-key`; preserve it and verify the host
fingerprint. SSH is disabled unless `--ssh-listen` is provided.

Use `enable`, `configure terminal`, interface/global configuration commands,
`compare`, and `commit check`. `commit confirmed 60` applies the private
candidate through the same transaction engine as HTTP; verify connectivity,
then `confirm`. Disconnect never confirms a pending transaction. Revisions,
permissions, rollback, timeout and conflicts are shared with the API.

See the [CLI operator guide](docs/CLI.md) for syntax, JSON-pointer editing of the
complete schema, host keys, authentication, recovery and limitations.

## Current limits and distribution review

The native protocol implementations have explicit boundaries: flow filters are
limited to empty/ip/ip6/tcp/udp/icmp/icmp6 and exclude fragments; NTP is a bounded
slew-only client without NTS or server consensus; syslog has no durable
forwarding queue or automatic reconnect; traffic history is per-sample, not
calendar aggregation. See the [native service contract](crates/netcontrol-services/README.md).
No DHCP/DNS server or DHCPv6 relay is provided.

The native backend links GPL-3.0-or-later `rustables`. No project distribution
license has been assigned. Review combined-work licensing, notices and
corresponding-source obligations before distributing binaries. CI package
upload is disabled by default and requires explicit manual opt-in.

## Change memory and frontend coordination

- [Unreleased changes](CHANGELOG.md)
- [Daily journal](docs/journal/2026-10-19.md)
- [Latest frontend handoff](docs/frontend-handoffs/2026-10-19.md)
- [Rust cutover handoff](docs/frontend-handoffs/2026-10-18.md)
- [Repository development instructions](.github/copilot-instructions.md)

No release baseline is assigned. Cargo workspace version `0.0.0` is only
unassigned development metadata. A build, successful test, or journal entry
does not mean a release was approved, changes were pushed, or a frontend
notification was delivered.
