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
softflowd, syslog-ng, or vnstatd. The operating system's service manager starts
the single daemon; it is not a protocol implementation. Native syslog requires
systemd/journald socket activation; it is unavailable under OpenRC.

Native [IPv4 UDP broadcast/multicast relay](docs/UDP_BROADCAST_RELAY_SPEC.md)
implements the documented pfSense package's selected-interface forwarding,
multicast membership, three source modes and instance-ID echo suppression.
Use the [Govee/ECHONET Lite example](examples/udp-broadcast-relay.json), adapting
its synthetic interfaces, addresses, revision and firewall policy. Govee LAN
Control must be enabled; discovery does not grant routed device access. This
runs inside Netcontrol with automatic reconnect/retry, not an external package.

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
These scripts also configure journald forwarding and a systemd-owned native
syslog receiver at `/run/systemd/journal/syslog`, stopping/masking competing
syslog receivers. Journald keeps `/dev/log`, kernel capture and the local journal.
Review [logging ownership and recovery](docs/BUILD_AND_INSTALL.md#host-logging-ownership);
saved syslog settings are not enabled automatically.

Native Linux mode continuously collects [link diagnostics](FRONTEND_SPEC.md#native-link-diagnostics):
qdisc backlog/drops, interface errors, local TCP RTT/retransmissions/congestion
windows, and bounded plaintext ingress TCP advertised-window observations
(including forwarded traffic). Use `GET /api/v1/statistics/link-diagnostics`,
`show statistics link-diagnostics`, aggregate statistics, or existing MQTT state
publication. Collection is in-process Rust using netlink and filtered AF_PACKET
sockets, not eBPF tools or supervised helpers. Install/full source upgrade loads
and persists the required packet/TCP diagnostics modules. Signals are evidence,
not proof of the failing upstream hop; receiver pressure is not link congestion.

Operational actions run entirely in Rust:
`POST /api/v1/processes/restart` with `{"target":"ntp"}` selectively restarts a
managed worker (`system.restart` permission). Target `netcontrold` schedules a
graceful full restart only under the packaged native systemd/watchdog service;
it never kills arbitrary OS processes.
`POST /api/v1/diagnostics/dns-lookup` with
`{"interface":"wan0","hostname":"google.com","record_type":"A","timeout_ms":2000}`
queries that interface's configured/DHCP DNS servers and returns measured
`rtt_ms`, answers, DNS response code and attempt errors (`diagnostics.run`).
Add `"server":"192.0.2.53"` to query only that IP on port 53, without configured
resolver fallback or changing saved DNS settings. With an explicit server,
omit `interface` to use normal kernel routing, for example
`{"hostname":"example.test","server":"192.0.2.53"}`. No shell lookup or external
helper is used. See the
[complete action contract](FRONTEND_SPEC.md#operational-restart-and-dns-diagnostics)
for targets, limits, statuses, timing and side effects.

Basic native IPv4 BGP runs inside the daemon: configure `bgp` in a full
transaction with local ASN/router ID, interface-bound neighbors and keepalive/
hold timers. It advertises connected prefixes from all configured up interfaces,
installs accepted learned routes, and maintains BGP-owned WireGuard AllowedIPs
for explicitly referenced peers. Default-route import requires opt-in.
Inspect `GET /api/v1/services/bgp/status` or `GET /api/v1/routes/bgp`;
`GET /api/v1/routes/bgp/advertised` lists exact per-neighbor session exports.
CLI inspection uses `show bgp status` or `show routes bgp`; MQTT includes the summary and shared
process health. Static configuration is preserved on withdrawal/session loss.
See the [BGP contract and operator prerequisites](FRONTEND_SPEC.md#native-ipv4-bgp)
for limits, bootstrap routing, privileges, ownership and unsupported features.
A [synthetic BGP-over-WireGuard transaction](examples/bgp.json) illustrates
the current schema; provision keys/underlay and adapt the complete configuration
before applying it.

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

## Destination rewrite

Exact-port destination NAT can redirect forwarded Internet-bound traffic to a
device on a local subnet. Match the original WAN, TCP or UDP and one port using
`firewall.nat.destination_rewrite`; see the
[example](examples/destination-rewrite.json) and
[complete contract](FRONTEND_SPEC.md#destination-rewrite).
For DNS, configure both TCP/53 and UDP/53. The destination port and client IP
are preserved; firewall-originated traffic is excluded. Ordinary forwarding
rules see the rewritten target and still apply.

The target must send replies through this firewall. A target on the client's
own subnet normally replies directly and will not work without an explicitly
arranged routed return path. No automatic source NAT or hairpin masquerade is
added. Configure a separate target subnet if needed. Changes affect new
connections; existing conntrack translations are not automatically deleted.
The target device is not automatically exempt: its own upstream queries must
not use the intercepted WAN/port, or they will be redirected back to it.
Linux nftables inet FIB/NAT support, forwarding and working routes are required.
Edits use normal confirmed transactions and `nat.write`.

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

## Azure Dynamic DNS

The in-process Dynamic DNS client updates **Azure public DNS IPv4 A records**.
It follows the pfSense model of a monitored WAN interface, relative hostname,
Azure application ID/secret, zone resource ID and TTL. Unlike pfSense's generic
username/password labels, the API names the Azure tenant/client fields explicitly.
AAAA records, private DNS zones, wildcard names, other providers, gateway-group
failover and custom detection URLs are not supported.

1. Host/delegate your public zone in Azure DNS. Register a single-tenant Entra
   application; record the tenant ID, application/client ID and **client-secret
   value** (not its secret ID). Assign its service principal **DNS Zone Contributor**
   at the DNS zone scope. Keep track of secret expiry and replace it before expiry.
2. Upload the secret using `POST /api/v1/services/dynamic-dns/secrets`
   (`dynamic_dns.write`), with `{"client_secret":"synthetic-example-only"}`.
   Save the returned `secret_ref`; the secret is never returned.
3. Add an entry to `config.dynamic_dns` in a complete ordinary configuration
   transaction (`transactions.write` plus `dynamic_dns.write`), then confirm it.
   Example below is synthetic: replace IDs/reference/zone/interface.

```json
{"dynamic_dns":[{"name":"azure-wan","enabled":true,"source_interface":"wan0","address_source":"public_ip","tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","secret_ref":"0123456789abcdef0123456789abcdef","zone_resource_id":"/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com","record_name":"home","ttl_seconds":300,"interval_seconds":60}]}
```

`record_name` is relative (`home` or `vpn.home`), **not** `home.example.com`;
use `@` for the zone apex. `address_source: "interface"` uses the selected
interface's public IPv4 directly. `"public_ip"` queries `https://api.ipify.org`
through that interface to detect a NAT-translated public IPv4. Public detection
discloses the egress IP to ipify; CGNAT detection does not make inbound connectivity
possible. The interface must be up with exactly one usable IPv4 address; missing
or ambiguous addresses fail explicitly. Non-public results are refused.

Only confirmed settings activate; active transactions/upgrades pause checks.
Disabling/deleting an entry stops updates but **does not delete the Azure record**.
Configuration rollback cannot undo a completed/in-flight external DNS write.
The client checks Azure every interval, skips unchanged IP/TTL, preserves record
metadata and uses ETag/conditional creation to avoid overwriting concurrent edits.
It refuses alias or multi-address A record sets. Missing records are created.
Errors retry after the configured interval; requests are serialized with bounded
timeouts. DNS TTL/recursive caches still govern when clients observe a change.

Poll `GET /api/v1/services/dynamic-dns/status` (`state.read`) for per-entry state,
last successful address, last check/update Unix seconds and redacted errors.
See the [complete frontend contract](FRONTEND_SPEC.md#615-azure-dynamic-dns).
There is no manual force-update action.

Linux host mode, privileged interface binding, working host DNS/routing and
outbound HTTPS to ipify (public detection only), `login.microsoftonline.com`
and `management.azure.com` are required. All HTTPS certificates/hostnames are
verified; redirects and proxies are disabled. Sockets bind both source IPv4 and
interface without another-WAN fallback; DNS lookups still use the host resolver.
Simulator reports simulated without network I/O; namespace lab mode rejects entries.
Use HTTPS/a trusted management channel for secret upload.

Back up `<state>.dynamic-dns` together with configuration/history (default
`/var/lib/netcontrol/native-state.json.dynamic-dns`). These daemon-owned,
owner-only secret files are **plaintext at rest**, not encrypted. At most 256
immutable secrets are retained, including discarded uploads; no read/delete or
automatic pruning API exists because old revisions may reference them.

References consulted:
[pfSense Dynamic DNS client settings](https://docs.netgate.com/pfsense/en/latest/services/dyndns/client.html),
[pfSense Azure setup walkthrough](https://micoolpaul.com/2022/07/20/configuring-pfsense-dynamic-dns-with-azure-dns/),
[Microsoft client-credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow),
and [Azure DNS record-set REST API](https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01).

## Home Assistant MQTT Statistics

Optional streaming is API-managed. Upload a broker password with
`POST /api/v1/services/mqtt/passwords` (`mqtt.write`), then put the returned
`password_ref` in `config.mqtt` in an ordinary configuration transaction and
confirm it. Changes require `transactions.write` and `mqtt.write`; status uses
`state.read` at `GET /api/v1/services/mqtt/status`. Passwords are never returned
or included in configuration/history. Use HTTPS or a trusted management channel.

Example settings inside a complete candidate configuration (synthetic reference;
replace it with the upload result and select an up managed interface):

```json
{"mqtt":{"enabled":true,"endpoint":"mqtts://broker.example.test:8883","username":"netcontrol","password_ref":"0123456789abcdef0123456789abcdef","source_interface":"lan0","interval_seconds":60}}
```

Default disabled, interval 60 seconds (allowed 10..3600). Only confirmed settings
activate publishing. A persistent source-interface-bound MQTT 3.1.1 connection
publishes Home Assistant device discovery, availability, gateway health/probe-window
summaries, interface counters, configuration revision and daemon uptime, plus host
health: memory/swap, load, uptime, pressure, **per-core CPU busy percent**, **per
temperature/fan sensor** (thermal zones and hwmon) and local filesystem space, and
per-instance NetFlow/IPFIX export state, **dropped capture packets**, active/exported
flows and excluded/filtered/malformed packet counters. The version
sensor is unknown while package metadata remains the unreleased placeholder
`0.0.0`. MQTT is telemetry-only. Linux host mode is required; simulator makes no
connection and namespace lab mode rejects enabled streaming. Binding fails closed;
hostname resolution still uses the host resolver, not the selected interface.
The connection stays open between samples and retries failures every five seconds
while enabled. If outstanding QoS-1 publications make no acknowledgement progress
for 30 seconds, the publisher reconnects and sends fresh discovery/state; it does
not replay an offline sample backlog.

Prefer `mqtts://` (port 8883), with a system-trusted certificate and matching
hostname. Explicit `mqtt://` (1883) sends credentials/data without TLS. Endpoint
URLs must not contain credentials, paths other than `/`, query or fragment.
Broker ACLs must allow retained discovery publication at
`homeassistant/device/netcontrol_<device_id>/config`, publication under
`netcontrol/<device_id>/`, and subscription to `homeassistant/status`. Discovery
and availability are retained; samples are not. QoS 1 can duplicate messages.

Back up `<state>.mqtt` together with the journal (default
`/var/lib/netcontrol/native-state.json.mqtt`). Its daemon-owned private files hold
stable device identity, password references and the discovery manifest. Preserve
ownership/permissions; never clone this identity to another active appliance.
Passwords are plaintext at rest in owner-only files, not encrypted. References
are immutable and retained for revisions; limit 256 passwords. There is no pruning
or deletion API: do not remove files referenced by configuration/history. Missing
or corrupt private state requires operator recovery, not an identity reset.
See the [exact contract](FRONTEND_SPEC.md#614-home-assistant-mqtt-streaming).

## Host name and time zone

`config.system` holds an optional `hostname`, an optional IANA `timezone` and a cosmetic
`domain`; empty means unmanaged (the default). The `domain` is only stored and shown by
clients: it is never applied to the host and never becomes a DNS search domain. Changes use the ordinary confirmed transaction flow
with `transactions.write` plus `system.write`, but the daemon applies them itself
after confirmation, like MQTT: the network is not touched and a rolled-back
transaction never changes the host. Linux host mode sets the kernel hostname and
`/etc/hostname` and replaces `/etc/localtime` with a link to the zone file (the host
must have its timezone database, normally the `tzdata` package; nothing is installed).
Values are enforced, so a change by another agent is set again within seconds, and
failures are retried. Clearing a value stops managing it and does not revert the
host. `/etc/hosts` is not edited, and processes started earlier may keep the old time
zone until restarted. The simulator and namespace lab perform no host changes.

`GET /api/v1/system/status` and `GET /api/v1/system/timezones` (`state.read`) report
the confirmed values, what the host reports and the valid zone names. CLI:
`hostname NAME`, `domain NAME`, `timezone ZONE`, `no hostname`, `no domain`, `no timezone`. DNS resolvers are not
part of this section: use the per-interface `dns` settings. See the
[exact contract](FRONTEND_SPEC.md#616-host-name-and-time-zone).

## Configuration workflow

### Host health

`GET /api/v1/statistics/host` (`state.read`) reads Linux CPU ticks/scheduler,
memory/swap, load/uptime, VM/OOM counters, pressure stalls, disk I/O, local
filesystem space/inodes and thermal/hwmon temperatures/fans in-process.
CLI: `show statistics host`. Missing features/sensor faults are explicit
per-source errors, never zero measurements. Counters are exact decimal strings;
CPU utilization and I/O rates need two samples. No configuration changes,
external sensor programs, drivers, stored history or additional host-service
permission. This uses the daemon-visible host/procfs/mount context, not a
network lab namespace or cgroup limits. Simulator data is unmeasured.
See the [host-health contract](FRONTEND_SPEC.md#host-health-sensors) for fields,
units, filesystem exclusions, rate calculations and frontend requirements.

### Routing scope

User-configurable source-policy routing is unsupported. Omit `policy_rules`
from configuration; it has no effect (a submitted `policy_rules` key is dropped
and reported in `ignored_fields`). There is no
`/api/v1/policy-rules` endpoint, `policy.write` grant or `policy-rule` CLI command.
Ordinary destination routes accept an `enabled` boolean (omission defaults to true); disabled
records stay saved but are not installed. Use table 254 (main) for normal traffic.
An enabled explicit gateway monitor requires a matching enabled route. See the
[route contract](FRONTEND_SPEC.md#64-routes). A single optional `blackhole` section
(`name`, plus `action` of `blackhole`, `unreachable` or `prohibit`) lets any number
of routes use that name as their `interface` to drop matching traffic in the
routing decision; it is a deviceless kernel route, not a link. Saved routes without the field load
as enabled. Enabled gateway monitors retain backend-managed host-source rules for
their explicit routing tables. Monitors sharing a source must share a table;
these internal rules affect all traffic from that exact source, not only probes.
DHCPv4 monitors instead use `mode: "dhcp"`, interface and target without pinned
source/gateway/table. They follow only that interface's active lease, wait with
Unknown health before acquisition, and never fall back to another WAN. Private
interface-scoped paths are runtime-owned, not editable routes. Explicit IPv4/IPv6
monitors are unchanged. See the [monitor contract](FRONTEND_SPEC.md#612-gateway-health-and-rtt-variation).
Host appliance monitoring requires host-service and gateway-probe permission.
The install and upgrade scripts enable both automatically through a managed
systemd environment drop-in, preserving customized startup arguments. See
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

## Native mDNS discovery across LANs

The in-process Rust mDNS/DNS-SD worker reflects discovery across explicitly
selected managed Ethernet/VLAN LAN interfaces, with service/provider filters,
IPv4/IPv6 controls and opt-in appliance publishing. It defaults **disabled**.
No Avahi daemon, external helper, D-Bus service or general multicast router is
used. Enable through the normal full-configuration/confirmed transaction flow;
`mdns.write` is required.

Read committed settings at `GET /api/v1/services/mdns` and applied worker state
at `GET /api/v1/services/mdns/status`. Bodyless
`POST /api/v1/services/mdns/reconcile` uses the existing all-service repair
permissions. Restrictive host-input policy needs explicit UDP 5353 permits;
the worker opens no firewall holes. Discovery does not grant access to a
printer/casting service, make IPv6 link-local addresses routable, or forward
SSDP/media traffic. Use only one active reflector per connected domain.

See the [current frontend contract](FRONTEND_SPEC.md#617-native-mdns--dns-sd),
[build and qualification spec](docs/MDNS_SPEC.md) and
[synthetic example](examples/mdns.json). The example is not a safe replacement
for an existing appliance's complete configuration. Namespace wire tests do
not establish device interoperability, production load or reboot acceptance.

## Configuration CLI over SSH

The daemon includes a Cisco-inspired CLI and an in-process Rust SSH server.
Ubuntu `install.sh` and full `upgrade.sh` runs enable it by default on
`0.0.0.0:2222`; no separate system `sshd` is required or launched. For a manual
daemon invocation, enable it explicitly:

```sh
netcontrold --state state.json --credential-db credentials.json \
  --ssh-listen 0.0.0.0:2222
ssh -p 2222 apikey@192.0.2.10
```

Use the literal username `apikey` and your existing **API key** at the password
prompt. Account passwords are not networking credentials. The persistent
Ed25519 host key defaults to `<state>.ssh-key`; preserve it and verify the host
fingerprint. Manual invocations remain disabled unless `--ssh-listen` or
`NETCONTROL_SSH_LISTEN` is provided; the explicit flag takes precedence.
Review host-input firewall exposure before upgrading: the script does not
add firewall exceptions, and wildcard binding must not expose management to WAN.
See [deployment overrides](docs/BUILD_AND_INSTALL.md#optional-configuration-ssh-server)
for a custom address or explicit disable.

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
