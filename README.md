# Netcontrol

A Go REST control plane for packaged Linux networking migrations. This is an
initial implementation for **isolated labs**, not a production host-networking
manager. The default backend simulates changes without touching the OS.

## Development policy

This is a **greenfield project**: backward compatibility is not a requirement.
Implement the current contract directly; do not add legacy fallbacks, compatibility
layers, or upgrade migrations unless specifically requested. Breaking API,
configuration, and saved-state changes are acceptable. Keep tests, examples, and
the frontend specification synchronized, and reject invalid inputs explicitly.
This does not relax authorization, transaction recovery, or rollback guarantees
for valid current configurations, and does not authorize deleting existing data.
See the [repository instructions](.github/copilot-instructions.md).

## Interface roles

Every managed interface must explicitly declare `"role": "wan"` or
`"role": "lan"` in its configuration, independent of its name and kind:

```json
{
  "name": "edge0",
  "kind": "dummy",
  "role": "wan",
  "mtu": 1500,
  "up": true,
  "addresses": ["192.0.2.2/24"]
}
```

This is one entry in `config.interfaces`, not a full transaction. Both values are
lowercase; omission, null, empty values, and other labels are invalid. There is no
default, name-based inference, migration, or inherited role for VLAN children.
Any supported managed kind (dummy, VLAN, WireGuard) can have either role; there
is no requirement to have exactly one WAN or at least one interface of each role.

Roles are descriptive configuration metadata only. They do not automatically
change routes, firewall rules, NAT, or interface operational settings. They are
preserved in desired/observed API reads, full-package transactions, durable state,
and revision snapshots, including confirmation, rollback, restart, and restore.
Linux observation copies roles from the corresponding expected configuration;
the role is not a kernel-derived property or an independent operational check.
Adopted read-only parents are not managed interfaces and do not acquire this field.

Use the normal full-package transaction workflow; role edits require
`interfaces.write` and `transactions.write`. Invalid role values return HTTP 422;
non-string JSON types return HTTP 400. Saved configurations and historical
transaction snapshots must also satisfy the current role requirement or loading
fails explicitly. No older-format fallback is provided.

## Per-interface DHCPv4 relay

Each managed interface has a `dhcp_relay` configuration:

```json
{
  "enabled": true,
  "servers": ["198.51.100.10", "198.51.100.20"]
}
```

This object belongs inside an interface entry, alongside `name`, `role`, and
`addresses`. It defaults to disabled with an empty server list. Disabled
configurations may retain their server list. All entries must be distinct,
canonical numeric unicast IPv4 addresses, even when disabled: no hostnames,
ports, prefixes, IPv6, loopback, link-local, multicast, or broadcast addresses.
Server order is normalized; requests go to every configured server, not an
ordered failover list.

Enabling requires at least one server and an administratively up dummy or VLAN
interface with a unicast IPv4 address. WireGuard is not supported as a DHCP relay
client-facing interface. Either WAN/LAN role is allowed; roles do not choose
upstream links. The first IPv4 address in lexicographically sorted canonical
interface prefixes is used as the local relay address (`giaddr`); if a link has
multiple IPv4 addresses, ensure that subnet choice is intended. Enabled relay
interfaces must have distinct relay addresses.

The simulator preserves settings and reports `simulated`; it sends no DHCP
packets. The Linux backend manages one **operator-installed dnsmasq** process
for the enabled interfaces in the target network namespace. DNS is disabled
(`--port=0`), no DHCP address ranges are configured, and system dnsmasq config,
hosts, and resolver files are not loaded. This is relay-only, not a DHCP server.
See the complete [DHCP relay example](examples/dhcp-relay.json) and the upstream
[dnsmasq relay documentation](https://dnsmasq.org/docs/dnsmasq-man.html).

### Relay operator setup

Install a dnsmasq build supporting DHCPv4 relay and supply:

```text
-dhcp-relay-binary /usr/sbin/dnsmasq
-dhcp-relay-runtime-dir /run/netcontrol-dhcp-relay
-dhcp-relay-uid <existing non-root service UID>
-dhcp-relay-gid <existing non-root service GID>
```

These flags supplement the normal `-backend linux`, `-namespace`, and any
`-adopt-parents` options. The example uses an operator-adopted `uplink` trunk,
with client VLAN 100 and server VLAN 200. Provision the trunk outside Netcontrol
and adopt it read-only. Servers must have a return route to the client subnet;
the example's connected upstream subnet supplies the outbound path.

The binary must be an absolute, root-owned executable, not group/world-writable,
with no set-ID bits or file capabilities. The runtime root must be dedicated,
root-owned, non-symlink, traversable and not group/world-writable (0711 is
recommended), including traversable ancestors. Use a separate directory from
softflowd. Service UID/GID must identify existing local user/group accounts.
Children start as that non-root identity with only the required ambient
`CAP_NET_BIND_SERVICE`, `CAP_NET_ADMIN`, and `CAP_NET_RAW` capabilities.
The parent needs the documented namespace privileges and permission to inspect
its child's namespace and `/proc/<pid>/fd` socket ownership (which can require
`CAP_SYS_PTRACE` under restricted procfs/ptrace policies).

Do not run another DHCP service on UDP 67 in the same namespace. Configure
upstream reachability, server return routes, and any other firewall's UDP 67/68
permissions explicitly; this feature does not create routes/NAT/firewall
exceptions. DHCPv6 and custom server ports are not implemented.
If integration is absent, enabling is rejected before transaction intent is
written. Invalid daemon configuration, bind/privilege errors, and startup
failures are explicit errors, not successful disabled fallbacks.

### Relay lifecycle and runtime

Settings use normal full-package transactions, `interfaces.write` plus
`transactions.write`, and preserve server lists across confirmation, rollback,
restart, revision reads/restores, and interface deletion/recreation. A changed
server list, selected address, or enabled interface set restarts the shared
relay; changing one interface can briefly interrupt relay service on the others.
Changed/removed instances stop before networking edits and start after routes
and firewall reconciliation. Startup and explicit repair resume the stored
committed/pending configuration, not a client draft.

`GET /api/v1/services/dhcp-relay/status` requires `state.read` and returns
`{"interfaces": [...], "error": ""}`. `/api/v1/runtime` also includes a
`dhcp_relay` array. Each status has `interface`, `state`, optional `pid`,
`started_at`, and `error`. States include disabled, simulated, unavailable,
not_running, running, unhealthy, and exited. Enabled interfaces share one PID.
Running means the supervised process owns its UDP 67 socket in the correct
namespace with the expected PID file, not that an upstream server or client
has successfully exchanged a lease. Process failures also produce configuration
drift; status remains accessible without successful full observation.

`POST /api/v1/services/dhcp-relay/reconcile` takes no body and requires
`state.read`, `transactions.write`, and `interfaces.write`. It repairs all managed
services, so `softflowd.write` is also required if any softflowd instance is
enabled. Conversely, softflowd's repair endpoint requires `interfaces.write`
when a DHCP relay is enabled. These checks use the current committed/pending
configuration under the engine lock. Repair creates no revision and does not
reapply links/routes/firewall. Do not automatically retry a repair.

## Frontend developer handoff

See the [frontend specification](FRONTEND_SPEC.md) for screens, shared-draft and
transaction workflows, API/data contracts, validation, deployment prerequisites,
and acceptance criteria. Proposed UI decisions are distinguished from current
backend capabilities.

## The transaction guarantee

One request submits a complete desired configuration spanning interfaces,
addresses, VLANs, routes, source-policy routing, nftables, WireGuard, typed
softflowd instances, and explicitly configured kernel-network tunables.

**This is coordinated commit with compensating rollback, not a shared atomic
kernel transaction.** Linux does not provide a single commit boundary across
these subsystems. Packets and other observers can see intermediate states.
Dropped traffic, interface indices, handshakes, and connections cannot be rolled
back. Only the owned nftables table update (filtering and masquerading together) is an
atomic native batch.

1. Check `base_revision`, validate the entire candidate, check owned-state drift,
   and preflight the candidate and rollback key references.
2. Serialize API-managed changes within the process. Take an advisory journal
   file lock to reject a second process using the same journal.
3. Persist and sync the intent **before** making kernel changes.
4. Apply/read back explicit kernel tunables and restore released keys to captured
   originals. Stop removed/changed softflowd instances, create/update links in parent-first
   order, configure addresses and WireGuard, reconcile routes and policy
   rules, atomically replace the owned nftables table, then remove obsolete
   links in child-first order. Start/reconfigure softflowd and check its private
   control socket and resume DHCP relay after network reconciliation. Networking
   uses native kernel interfaces; optional softflowd and DHCP relay integrations
   launch operator-installed executables. No shell
   commands are executed by the service.
5. Read back the modeled state. Return `202 pending_confirmation` only if it
   matches the candidate. The committed desired revision is unchanged.
6. Confirm before the deadline to durably publish the desired revision. Otherwise
   restore the previous committed configuration and verify restoration.
7. If apply fails, attempt rollback. If rollback or its persistence fails, expose
   `recovery_failed`, log the error, and block further submissions. An operator can
   explicitly retry rollback.

All transactions require a 10..300 second confirmation window. It starts when
intent is journaled, not when the HTTP response arrives. A failed or disconnected
HTTP request does **not** imply that nothing happened; query the transaction list
and live state before retrying. After intent is durable, client cancellation does
not cancel apply/recovery.

### Restart and failure semantics

- An interrupted `applying` or `rolling_back` transaction is rolled back on
  restart. A `recovery_failed` transaction gets one startup recovery attempt.
- An unexpired pending confirmation survives restart; an expired one rolls back.
- Managed softflowd children are recreated from the committed configuration or
  the unexpired candidate on startup, without replaying unrelated networking.
  Failure to resume a pending candidate triggers rollback. A committed-service
  startup failure is logged and exposed through runtime status; the API remains
  available for diagnosis and explicit service reconciliation.
- A graceful shutdown attempts rollback of any provisional transaction.
- The in-process watchdog cannot run while the daemon or machine is stopped.
  Recovery happens when the service restarts. Native library calls are
  synchronous; the operation context is a cooperative bound, not a hard deadline
  on every kernel operation. Use a supervised service and out-of-band access.
- The journal is bound to its backend and, on Linux, to the pinned namespace's
  device/inode and boot ID. It will not silently apply a journal to a recreated
  namespace or a different backend. Reboot/recreated-namespace recovery requires
  operator intervention; automatic namespace provisioning is not implemented.
- Use a trusted private journal directory on a local Linux filesystem. Writes
  sync the temporary file, rename it, and sync the parent directory. Windows is a
  simulator/development target, not a crash-durability guarantee.
- External tools do not honor the process lock. Drift checks are not a kernel-wide
  compare-and-swap, so exclusive ownership remains a deployment requirement.

## Supported scope and ownership

| Subsystem | Initial contract |
| --- | --- |
| Interfaces | Create/delete `dummy`, kernel `wireguard`, and 802.1Q `vlan` links; name, required WAN/LAN role, MTU, up/down |
| VLAN parents | Operator-adopted physical Ethernet/veth/dummy parents, protected from API deletion and direct reconfiguration; managed dummy/VLAN parents also supported |
| Addresses | Exact global-unicast IPv4/IPv6 prefixes on managed links; host bits retained |
| Routes | Unicast destination/gateway/device/positive metric, tables 10000..19999, protocol 242 |
| Policy routing | Source-prefix table lookup; unique priorities and tables 10000..19999 |
| Firewall | Owned `inet netcontrol` table; legacy ordered source/destination rules or stateful host policies with ingress-interface overrides, TCP/UDP destination ports, and global/host defaults |
| NAT | IPv4/IPv6 masquerading in the same table's `postrouting` NAT chain, with explicit family, optional source network, and required managed egress interface |
| WireGuard | Private-key references, stable listen ports, peers, numeric endpoints, allowed IPs and keepalive |
| softflowd | Typed foreground instances: enable/disable, capture interface/filter, numeric collector, NetFlow/IPFIX version, sampling, max flows, snaplen, promiscuity, and timeouts |
| DHCPv4 relay | Per-interface enable/server list; supervised relay-only dnsmasq on up dummy/VLAN links; runtime inspection and repair |
| Kernel TCP/IP tuning | Allowlisted, validated namespace tunables, plus separately opted-in host-global network tunables; original-value capture, drift checks and transaction recovery |

The Linux backend requires an **explicit, pre-created, initially empty network
namespace** (loopback and explicitly adopted parent links are allowed).
It refuses the current and PID 1 namespaces.
The management HTTP listener remains in the service's original namespace.
The target namespace is pinned for the lifetime of the process.

All non-loopback links in that namespace, **except explicitly adopted parents**,
belong exclusively to this service. Pre-provision and adopt physical/veth parents
before first binding the journal; do not attach unadopted physical devices.
Do not run NetworkManager, systemd-networkd, another
Netcontrol process, or another controller in it. An unexpected link produces
drift and blocks a new transaction. Routes are owned only when both protocol 242
and a reserved table match; policy-rule priorities 10000..19999 and the named inet
table are exclusive reservations. Other routes/rules/nftables tables are not
removed or adopted.

Observation and drift cover modeled properties, not every kernel attribute.
Unsupported owned firewall expressions/chains or policy-rule selectors cause an
explicit observation error rather than an invented successful state. WireGuard
counters and handshakes are not configuration; endpoint roaming *does* change
modeled state and can produce drift. Restoring a deleted WireGuard interface
restores configuration, not its prior sessions.

IPv6 DAD is disabled on configured addresses to keep this isolated-lab adapter
synchronous. Production address readiness/DAD handling is not implemented.
Changing interface kind or a VLAN's parent/ID in place is rejected. Use a new
name, or separately confirm deletion before recreating it. Forwarding sysctls
are not changed.

Physical-device provisioning/moving, bridges, namespaces as API resources, SNAT/DNAT/port forwarding,
arbitrary protocol matches, port ranges, user-defined sets/conntrack controls,
traffic control, device tuning, hardware offload,
distributed coordination, and automatic drift reconciliation are **not**
implemented. The firewall API is deliberately not a full nftables language.
Transaction history is retained in the journal without automatic pruning.

## Build and run

Requires Go 1.24 or later:

```text
go mod download
go build ./cmd/netcontrold
```

### Authentication

Authentication is mandatory for the networking API, including in the simulator.
There are two mutually exclusive startup modes.

#### Device website (default)

Start without `-auth-file`, then open the management listener in a browser:

```text
netcontrold -backend simulator -state state.json
```

Visit `http://127.0.0.1:8080/` for local development. The embedded website needs no
separate frontend build and provides:

1. **Device account:** choose a username and a unique 12..72-byte password.
2. **API keys:** enter a name and generate one or more cryptographically random
   256-bit keys. Save the full key from the one-time dialog. After dismissal or
   refresh, only its name, creation time, and last four characters are displayed.
3. **Finish:** acknowledge saving a key and finish setup. Networking API access is
   disabled until this step completes. Use `Authorization: Bearer <key>` thereafter.

Account creation is atomic: only one visitor can claim the device. **There is no
bootstrap code: anyone who can reach an unclaimed device can claim it.** Restrict
network access until setup completes. If interrupted after account creation, sign
in with that account to resume; an existing account is never overwritten.
Setup does not configure interfaces, routes, or firewall policy.

Subsequent visits offer password sign-in and named key creation/removal. Each key
has full networking API permissions; scoped keys remain available through legacy
mode below. A device-account session cannot call networking endpoints, and API keys
cannot manage credentials. Removing a key blocks subsequent authenticated requests;
it does not cancel work already authorized or pending transactions. The last key
may be removed: the device account can always generate a replacement.

Credentials are held in a separate embedded bbolt database, by default
`<state>.credentials.db`, configurable with `-credential-db`. It is not part of the
network JSON journal, revision history, or configuration exports. Only bcrypt
password hashes (cost 12), SHA-256 hashes of random API keys/session tokens, key
metadata, and session expiry are stored; full API keys cannot be recovered. This is
hash-based secret protection, **not database encryption**. The database uses an
exclusive process lock, synchronous transactions, and owner-only file permissions
on Unix; place it in a trusted private local directory and protect backups.
Windows is a development target: restrict the directory with Windows ACLs; Unix
mode bits do not enforce Windows access control. Never delete/replace a configured
database to work around sign-in problems: an absent database creates an unclaimed
device. There is no remote password reset or account recovery in this version.

Website sessions expire after 30 minutes and sign-out revokes them. They use
HttpOnly, SameSite=Strict cookies (Secure over HTTPS), restricted to `/auth/`.
Mutations require JSON and an exact same-origin `Origin` header. Sign-in and setup
share a device-wide limit of 10 attempts/minute (a busy/untrusted client can
temporarily exhaust it); at most 32 sessions and 100 unique-named keys are allowed.
API keys do not expire automatically. Keys are not saved in browser storage.
If a key-creation response is lost, sign in, remove that named key and create a
replacement; the plaintext cannot be fetched again.

Use the daemon's native TLS listener for remote website access. A proxy must
preserve the external Host and scheme as seen by the daemon (TLS re-encryption for
HTTPS); forwarded headers are not trusted. Do not proxy an HTTPS website to this
plaintext backend: exact-origin checks and Secure-cookie detection require
end-to-end TLS. The website only manages onboarding and keys, not the broader
networking dashboard described in the frontend handoff.

#### Pre-provisioned auth-file mode (legacy, optional)

Supplying `-auth-file auth.json` explicitly selects the existing static-token
behavior and disables the device website/session endpoints. It cannot be combined
with `-credential-db`; no automatic migration of existing tokens is performed.
Generate a strong random bearer token locally, retain the plaintext only on the
client, and place its lowercase SHA-256 hash in a private `auth.json`:

```json
[
  {
    "name": "lab-admin",
    "token_sha256": "<64 hexadecimal characters: SHA-256 of your random token>",
    "permissions": [
      "state.read",
      "transactions.write",
      "interfaces.write",
      "routes.write",
      "policy.write",
      "firewall.write",
      "nat.write",
      "wireguard.write",
      "softflowd.write",
      "kernel.namespace.write",
      "kernel.host.write"
    ]
  }
]
```

For example, generate a token and hash in PowerShell:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$token = [Convert]::ToBase64String($bytes)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token)))).Replace("-", "").ToLowerInvariant()
$sha.Dispose()
# Retain $token securely on the client; put $hash in auth.json.
```

`state.read` allows all modeled configuration reads. Mutations require
`transactions.write` plus the permissions for every changed subsystem.
Confirmation and rollback require the same subsystem permissions as the original
package, even if another principal submitted it. Removing a WireGuard interface
also requires `wireguard.write`. These are administrative permissions within the
owned namespace, not a general host-command capability.

VLAN changes require `interfaces.write`. Softflowd changes require
`softflowd.write`, independently of firewall, NAT, or interface permissions.
Adopting parents, choosing an executable, installing packages, and selecting
process identities are operator-only startup settings, never API inputs.

Kernel tuning requires `kernel.namespace.write` and/or `kernel.host.write` for
the scopes actually changed, plus `transactions.write`. Neither permission
implies the other or grants interface/firewall access. Host writes additionally
require the daemon's operator-only `-allow-host-tunables` flag.

Masquerading changes require `nat.write`, separately from `firewall.write`.
A NAT-only operator can change masquerading without changing filter rules, but
still needs `transactions.write` and must submit a complete package preserving
the other subsystems. Existing credentials do not automatically gain NAT write
permission; add it explicitly where needed.

Tokens are matched using constant-time hash comparisons. Non-loopback listeners
require `-tls-cert` and `-tls-key`; default plaintext loopback access is intended
for local development or a trusted TLS-terminating proxy. Do not forward
unauthenticated remote traffic to the loopback listener.

Structured HTTP audit and transaction lifecycle events go to stderr; authorization
failures are logged, and bearer tokens/private keys are not. Deployments must
collect and protect these logs; this is not a tamper-evident audit store. In legacy
mode credential reload, expiry, and rate limiting are not implemented. Managed
keys are checked against the database on each networking request.

### Simulator (Windows or Linux)

```text
netcontrold -backend simulator -auth-file auth.json -state state.json
```

On PowerShell, use `.\netcontrold.exe`. The simulator resumes its journaled
candidate/desired configuration after restart; it cannot observe a real kernel or
prove kernel behavior.

### Linux native backend

Use a disposable Linux machine with namespace administration privileges, kernel
WireGuard support, nftables inet NAT support (Linux 5.2+), and masquerade/conntrack
kernel support. The network CLI tools below are operator setup only; the
networking adapter does not invoke them:

```sh
sudo ip netns add netcontrol-lab
sudo install -d -m 700 /var/lib/netcontrol /etc/netcontrol/keys
# Generate once; retain old key files while any rollback can reference them.
sudo sh -c 'umask 077; wg genkey > /etc/netcontrol/keys/wg0'
sudo ./netcontrold -backend linux -namespace netcontrol-lab \
  -state /var/lib/netcontrol/state.json \
  -auth-file /etc/netcontrol/auth.json -keys /etc/netcontrol/keys
```

The daemon needs `CAP_SYS_ADMIN` for namespace entry and `CAP_NET_ADMIN` for
networking. This version does not split privilege into a separate helper process.
Do **not** run the whole daemon with `ip netns exec`: its management listener
belongs outside the target namespace.

IP forwarding switches are **operator-managed**, not part of this API or its
rollback contract. If this namespace will route transit traffic, provision the
appropriate switches separately:

```sh
sudo ip netns exec netcontrol-lab sysctl -w net.ipv4.ip_forward=1
# Only when routing IPv6 is intended:
sudo ip netns exec netcontrol-lab sysctl -w net.ipv6.conf.all.forwarding=1
```

Changing IPv4 forwarding can reset other IPv4 host/router defaults; enabling IPv6
forwarding changes router-advertisement behavior. Plan those settings as operator
provisioning, rather than assuming they are side-effect-free boolean changes.
Masquerading does not enable forwarding, install routes, or bypass filtering.

The API accepts **key names**, never private keys or filesystem paths. Key files
must be regular private files with no group/other permission bits. Key references
are confined to the configured key directory. Treat each key file as immutable;
use a new reference for rotation and retain old files for recovery. No private
key material is stored in the journal, response, or audit events.

### VLANs and protected parents

An owned VLAN is an ordinary interface with `"kind": "vlan"` and
`"vlan": {"parent": "uplink", "id": 100}`. IDs are 1..4094, names may contain
dots (Linux's 15-character limit still applies), and only 802.1Q is supported.
Parents may be managed dummy/VLAN links or pre-provisioned, explicitly adopted
Ethernet device/veth/dummy links. Cycles, duplicate parent/ID pairs, WireGuard
parents, and child MTUs greater than the parent's MTU are rejected. Creation
and deletion follow dependencies, not input/name order.

For a disposable veth-backed lab, provision **both** ends before first startup:

```sh
sudo ip netns exec netcontrol-lab ip link add uplink type veth peer name uplink-peer
sudo ip netns exec netcontrol-lab ip link set uplink up
sudo ip netns exec netcontrol-lab ip link set uplink-peer up
# Add this to the native daemon invocation:
# -adopt-parents uplink,uplink-peer
```

Adopted parents are not listed in `config.interfaces`; their addresses, MTU,
administrative up/down state, MAC, and lifecycle remain operator-owned. The API
cannot directly configure, delete, or recreate them. Their name/index/type/MAC
identities are checked before observation and mutation and bound into the
journal scope. Missing/replaced parents fail explicitly rather than being
silently re-adopted. `GET /api/v1/parent-interfaces` reports live availability,
identity, MTU, and administrative state even when full configuration observation
fails. Parent MTU/up changes themselves are not owned-config drift.

Bring parents up and provision connectivity separately. A configured-up child
does not prove its parent has carrier. VLAN operation and explicitly requested
promiscuous capture can affect the parent's kernel receive-filter/promiscuity
reference counts; protection does not mean those kernel-maintained flags never
change.

### Operator-installed softflowd

Softflowd is the first dedicated third-party-package adapter, **not** a generic
package manager or arbitrary-command API. Install a compatible softflowd/libpcap
with the operating system's package manager, disable any conflicting distro
service, and provision a dedicated non-root system UID/GID. Netcontrol does not
install binaries, write a distro's service configuration, or manage systemd.

Enable the integration on the native daemon:

```sh
sudo install -d -m 711 /run/netcontrol-softflowd
sudo ./netcontrold -backend linux -namespace netcontrol-lab \
  -state /var/lib/netcontrol/state.json -auth-file /etc/netcontrol/auth.json \
  -adopt-parents uplink,uplink-peer \
  -softflowd-binary /usr/sbin/softflowd \
  -softflowd-runtime-dir /run/netcontrol-softflowd \
  -softflowd-uid "$(id -u netcontrol-flow)" \
  -softflowd-gid "$(id -g netcontrol-flow)"
```

Create the `netcontrol-flow` account first; paths and account names are examples.
The fixed executable must resolve to a root-owned, regular executable not
writable by group/others, without set-ID bits or file capabilities (the manager
supplies capture capabilities). Treat it as immutable while the service runs;
restart Netcontrol after a package upgrade to re-probe capabilities.
The dedicated runtime directory must be root-owned,
non-symlink, non-writable by group/others, and traversable by the child (0711);
all its ancestors must also be traversable. Its own lock prevents two managers
using the same runtime directory. Instance sockets live in private 0700
directories owned by the child UID. Live/untrusted stale sockets or unexpected
files are refused, never adopted or recursively removed.

For this privileged lab deployment, run the daemon as root with namespace/network
capabilities. The service also needs permission to switch UID/GID, chown private
directories, and pass ambient capture capabilities (including an appropriate
capability bounding set). Reading a different-UID child's namespace through
`/proc` for readiness verification may also require `CAP_SYS_PTRACE`; restrictive
proc mounts or security policies can explicitly prevent readiness.
Children run with the configured non-root UID/GID,
no supplementary groups, a minimal environment, `CAP_NET_RAW`, and additionally
`CAP_NET_ADMIN` only when promiscuous capture is requested. They enter the managed
network namespace and stay foreground. A pinned creator thread and Linux
parent-death signal kill children when the daemon dies. Use a supervisor with
`KillMode=control-group` as additional crash protection. This is not a complete
userspace sandbox or privilege-separated control plane.

The package's `softflowd` array is the durable source of truth; configuration
becomes typed executable arguments, not an editable generated config file.
See [the complete VLAN/softflowd package](examples/vlan-softflowd.json).
That example needs a real VLAN gateway/collector; a standalone veth pair does
not provide either. Its catch-all source-policy lookup lets an unbound exporter
socket select its route; ensure the collector is reachable in the managed
namespace, not merely in the daemon's management namespace.

- Up to 16 uniquely named instances, with managed or adopted capture interfaces.
- `enabled` controls lifecycle; a disabled instance still carries valid settings.
  Omitting an instance from the next complete package stops/removes it.
- `collector` is one canonical numeric IPv4/IPv6 address and nonzero port.
  DNS, multicast collectors, and multiple collectors are not supported.
- `export_version` is 1, 5, 9, or 10 (IPFIX); transport is UDP.
- `sampling_rate` is the periodic sampling denominator (1 means every packet).
  Sampling and `max_flows` must be 1..1000000; `snaplen` is 64..65535 bytes.
- `capture_filter` is a one-line BPF expression up to 4096 bytes. It is passed
  as one argument after `--`, never interpreted as a shell command or flags.
- `timeouts` maps `general`, `tcp`, `tcp.rst`, `tcp.fin`, `udp`, `icmp`,
  `maxlife`, and `expint` to 0..604800 seconds; `general` must be positive.
  Zero values follow the installed softflowd's semantics. Omitted keys retain
  its defaults, so pin the package version when reproducibility matters.
- Required CLI options and export versions are checked against the installed
  binary's bounded, timed help output. BPF compilation and capture permission
  checks occur during startup on the actual interface; failure causes ordinary
  transaction compensation, not a successful-looking disabled service.

Readiness checks the private control socket's PID/UID, the child's network
namespace, and a bounded statistics reply. It proves local process responsiveness,
**not collector delivery or packet capture correctness**. Unexpected exit or
unresponsiveness changes observed `enabled` to false, creates modeled drift,
and appears in `/api/v1/services/softflowd/status`. There is no unbounded restart
loop. Diagnose and explicitly retry:

```text
POST /api/v1/services/softflowd/reconcile
```

This bodyless action requires `state.read`, `transactions.write`, and
`softflowd.write`, plus `interfaces.write` when a DHCP relay is enabled because
it repairs all managed services. It uses the server's current committed/pending configuration,
repairs only managed service processes, never replays networking or accepts new
configuration, and does not create a configuration revision. Unresolved
transaction recovery blocks it. `/api/v1/runtime` and the status endpoint expose
the last startup/reconcile error until successful explicit reconciliation.

Changing settings, removing a service, rollback, restart, or crash may discard
flow caches/counters and unexported records; already exported records cannot be
retracted. Process termination uses TERM with bounded KILL escalation, not a
guaranteed export flush. Configuration rollback does not restore process memory.
Running the simulator reports `simulated`, never a real PID or proof of capture.

### Explicit kernel TCP/IP tuning

Tunables are part of each complete, dated configuration revision, not a second
configuration file or an automatically selected performance profile:

```json
{
  "kernel": {
    "namespace": {
      "net.core.somaxconn": "8192",
      "net.ipv4.tcp_rmem": "4096 131072 16777216",
      "net.ipv4.tcp_congestion_control": "cubic"
    },
    "host": {
      "net.core.netdev_max_backlog": "2000"
    }
  }
}
```

This is a **configuration fragment**: merge it into the full package before
submitting. Values are strings so scalars, vectors and algorithm names have one
consistent JSON shape. Integers must be canonical decimal, vectors use single
spaces and nondecreasing values, and all keys/types/ranges are allowlisted.
The example numbers illustrate syntax, not recommendations for every machine.
The native adapter reads/writes `/proc/sys` directly on namespace-pinned threads,
checks procfs, rejects symlink leaves, performs single bounded writes, and reads
back the exact result. It does not run `sysctl`, edit `/etc/sysctl.conf`, or
silently skip unavailable/read-only parameters. The simulator models values
without changing the OS; its initial values are synthetic fixtures, not detected
Linux defaults.

`GET /api/v1/kernel/tunables/catalog` lists all supported names, scope, kind,
arity, allowed ranges, and explanatory notes. The initial allowlist is:

| Scope | Parameters |
| --- | --- |
| Managed namespace | `net.core.somaxconn`; `net.ipv4.tcp_max_syn_backlog`, `tcp_syncookies`, `tcp_sack`, `tcp_window_scaling`, `tcp_timestamps`, `tcp_moderate_rcvbuf`, `tcp_mtu_probing`, `tcp_slow_start_after_idle`, `tcp_autocorking`, `tcp_no_metrics_save`, `tcp_rmem`, `tcp_wmem`, `ip_local_port_range`, `tcp_congestion_control` |
| Host-global | `net.core.rmem_max`, `wmem_max`, `rmem_default`, `wmem_default`, `netdev_max_backlog`, `netdev_budget`, `netdev_budget_usecs` |

The abbreviated names in each row retain their preceding `net.ipv4.` or
`net.core.` prefix. Most `net.ipv4.tcp_*` knobs also govern TCP over IPv6; they
are not settings for transit forwarding alone. Global core buffer controls
must not be treated as writable namespace-local values on kernels where they
are shared. Availability still depends on the running kernel/build, security
policy and proc mount.

Congestion-control names must be present in that namespace's currently available
algorithm list before a write. Missing algorithms must be provisioned separately;
Netcontrol does not invoke `modprobe`, choose a fallback, or assume BBR is faster
than CUBIC. A module disappearing or a parameter becoming unwritable during a
transaction is an explicit apply/recovery error.

#### Original values, defaults, and removal

- With no `kernel` values, tuning is **opt-in**: untouched keys retain their
  existing OS/operator settings. Legacy journals do not silently enable tuning.
- Before a key's first attempted ownership in a journal, capture its actual
  live value. Persist it in `kernel_baseline` with the transaction intent before
  any writes. These are **captured originals**, not guessed distro/factory
  defaults and not a performance preset.
- Explicit values override the existing value while owned. Each transaction
  also durably records exact pre-change and effective post-change values for
  every affected key, including newly owned and provisionally released keys.
- Omitting an owned key from the next complete package restores its first
  captured original. Confirmation releases ownership. While pending, restoration
  itself is verified and protected by drift checks.
- Rollback restores that transaction's exact pre-change values, not whatever
  happens to be in the original baseline. Thus a failed re-adoption does not
  overwrite a legitimate newer unowned operator setting with an older original.
- Originals remain immutable for the journal's lifetime, including after
  rollback/release. Re-adopting and later releasing a key uses that same original;
  it does not silently recapture a different meaning of "default."
- After release, unrelated transactions do not rewrite historical/unowned keys.
  Restart recovery uses durable snapshots; no in-memory-only undo list is needed.

`GET /api/v1/kernel/tunables` returns `desired`, `configured`, `effective`,
`observed`, `captured_original`, and `drift`. `configured` is the pending candidate
when present. `effective` also includes temporary original-value restorations
when keys are being removed, or the recovery target after a rollback failure.
Only affected/owned keys are observed here; the endpoint does not fabricate
current values for every unowned catalog key. It works independently of full
interface/firewall observation. Full `/state` still includes the explicitly
configured kernel values.

Catalog ranges are API validation bounds, not a guarantee that every kernel
accepts every value. Tighter running-kernel limits, clamping, and write failures
are detected and cause explicit compensation rather than silent adjustment.

All normal protections apply: stale-base checks, fine-grained authorization,
history/restore, timed confirmation, readback, restart recovery, and write
blocking after failed compensation. Changing a sysctl is not a cross-key atomic
operation. Restoring numbers cannot undo packet loss, congestion-window changes,
socket allocations, or effects on an existing connection. Some knobs are
defaults for **new** sockets and do not retune existing ones.

#### Host-global opt-in and ownership

Start the Linux daemon with `-allow-host-tunables` **only** when it is authorized
to administer the entire host's allowlisted network settings. This is a deliberate
exception to namespace isolation: other namespaces, applications, and potentially
the management connection can be affected.

The flag acquires `/run/netcontrol-host-tunables.lock` for the daemon's lifetime.
Its parent and lock file must be trusted/root-owned, and a second cooperating
instance cannot take ownership even with a different journal. All cooperating
instances must share the host's `/run` filesystem; isolated container lock
filesystems are not sufficient. This advisory lock cannot exclude `sysctl`,
systemd-sysctl, tuning agents, or privileged external writers. Disable conflicting
owners and retain out-of-band access.

The flag can be enabled on an existing namespace journal. Once desired state
or an active transaction owns host tunables, startup without the flag is refused
instead of silently abandoning observation/recovery. First confirm a package
that removes/restores those host keys before disabling the flag. Merely keeping
historical host revisions does not require host-write privileges at startup.
Host keys are accessed in the pinned PID-1 network namespace; the ordinary
networking adapter still refuses host-interface/routing management.

Reboot/namespace identity restrictions on journals still apply. Configured sysctls
are not independently installed as boot-time configuration. An in-process watchdog
cannot restore host settings while Netcontrol is stopped; supervise the daemon
and plan recovery accordingly.

#### A conservative mixed-workload base configuration

[kernel-mixed-conservative.json](examples/kernel-mixed-conservative.json) is an
explicit starting point labeled v1, **not an automatically applied profile**.
Copy/merge its `kernel` object into your real package and override selected keys.
Do not submit the whole example over an existing deployment without merging:
its empty interface/service lists intentionally demonstrate complete-package
replacement and would remove those resources.

The example keeps SACK, window scaling, timestamps and receive autotuning enabled;
retains SYN cookies, normal idle slow-start, automatic coalescing and metric
reuse; enables MTU black-hole recovery; and uses a modest listen backlog ceiling.
Many of these are already modern Linux defaults. They are a starting point for
robust mixed workloads, not a claim that changing them improves an already
well-tuned kernel.

It deliberately leaves host-global changes, congestion algorithm, buffer
ceilings, ephemeral port ranges, retry timers, TIME_WAIT behavior, and scheduling
choices **unset**. Do not blindly enlarge queues, disable safety mechanisms, or
shorten connection timers in pursuit of an unqualified "highest performance."
Forwarding sysctls remain operator-managed: IPv4 forwarding changes can reset
other network defaults and need a separate coordinated contract. Per-interface
sysctls, qdisc/tc, NIC offload/RSS, conntrack limits, global TCP memory-page budgets,
module loading and arbitrary sysctl paths are outside this initial allowlist.

For a workload-specific higher-performance revision:

1. Define the objective: throughput, tail latency, CPU efficiency, or connection
   capacity. A larger queue may improve burst absorption while worsening p99
   latency.
2. Measure a baseline with representative connection counts, traffic mix, RTT,
   MTU, packet loss and application behavior. Record goodput, p50/p95/p99 latency,
   retransmissions, socket memory, CPU/softirq utilization and receive drops.
3. Size TCP buffer **ceilings** using bandwidth-delay product and a concurrency/
   RAM budget, not a fixed internet recipe. For example, 10 Gbit/s at 20 ms
   needs about 25 MB of in-flight data for one full-rate flow. Buffer ceilings
   are not reservations, but many busy sockets can still exhaust memory.
4. Change one related group at a time. Raise host backlog/budgets only after
   measured drops or polling exhaustion, and check latency/CPU fairness afterward.
   Test CUBIC versus an available alternative rather than forcing one universally.
5. Keep only reproducible improvements as confirmed revisions, with workload/
   benchmark details in the transaction description. Restore a known-good
   revision if the trade-offs are unacceptable.

Kernel semantics and defaults are documented in the upstream
[IP sysctl reference](https://docs.kernel.org/networking/ip-sysctl.html) and
[network core sysctl reference](https://docs.kernel.org/admin-guide/sysctl/net.html).
There is intentionally no universal "fastest" switch or undocumented preset
expansion hidden in the server.

## Networking statistics

Read-only statistics are collected directly from the managed Linux namespace:
interface metadata and counters through native route Netlink, and protocol
statistics from the namespace's procfs networking files. No `ip`, `ifconfig`,
`netstat`, or other subprocess is used. All four endpoints require `state.read`:

```text
GET /api/v1/statistics
GET /api/v1/statistics/interfaces
GET /api/v1/statistics/interfaces/wan
GET /api/v1/statistics/protocols
```

The combined response has `sample`, `interfaces`, and `protocols`. The interfaces
and protocols endpoints return `sample` plus their respective array; a named
interface returns `sample` and one `interface` object. Empty lists are `[]`.
There are no query parameters, counter-reset operations, or statistics writes.
A nonexistent interface returns `404`, invalid input `400`, unsupported methods
`405`, and collection/parsing failures `503`.

### Interface counters

Unlike configuration reads, statistics include **all links in the managed
namespace**: loopback, managed interfaces, adopted parents, and unmanaged links.
Each record includes name, kernel index, kind, ownership, MTU, administrative
state, operational state, and MAC address when present. Ownership labels include
`managed`, `adopted_parent`, `adopted_parent_identity_changed`, `unmanaged`, and
`loopback`. Diagnostic collection remains usable when configuration observation
fails, including a changed protected-parent identity.

The `counters` object exposes:

- RX/TX packets, bytes, errors, and dropped packets.
- Multicast and collisions.
- RX length, overrun, CRC, frame, FIFO, and missed errors.
- TX aborted, carrier, FIFO, heartbeat, and window errors.
- RX/TX compressed packets.
- Optional `rx_nohandler` and `rx_otherhost_dropped` when supplied by the kernel.

The collector prefers `IFLA_STATS64`, falls back to `IFLA_STATS`, and reports
`counter_bits: 64` or `32` accordingly. A list uses one Netlink dump; a named
interface uses a direct lookup. Interrupted dumps are errors, not complete
samples. Missing counter attributes produce `status: "unavailable"`,
`counters: null`, and an explicit error, not invented zero traffic. Optional
trailing counters are omitted when absent; a reported zero is a real kernel
value, though drivers may not implement every individual event counter.

### Protocol statistics and availability

Protocol records identify their source as `snmp`, `netstat`, or `snmp6`.
`groups` contains the kernel's group/field names, for example
`groups.Tcp.RetransSegs`, `groups.Udp.InDatagrams`, or
`groups.TcpExt.ListenDrops`. IPv6 fields retain their full names under
`groups.IPv6`, for example `Ip6InReceives`. Available groups depend on kernel
configuration. These are not all monotonic counters: fields such as
`Tcp.CurrEstab` are gauges, and `Tcp.MaxConn` may be `"-1"`.

The native collector reads `/proc/thread-self/net/{snmp,netstat,snmp6}` on the
namespace-pinned worker thread. `/proc/net` would incorrectly follow the process
leader's namespace. Missing sources are explicitly `unavailable`, with
`groups: null` and an error. A sample with unavailable sections is `partial`;
a protocol-only request fails if no protocol source is available. Unexpected
I/O errors or malformed data fail explicitly. The simulator reports
`simulated`, null counters/groups, and no invented kernel indices or traffic.

### Precision, sampling, and rates

**All interface counter values and protocol values are JSON decimal strings.**
This preserves full unsigned 64-bit precision for JavaScript clients; parse
counters with `BigInt`, not `Number`. This does not change the existing numeric
revision-number wire format.

`sample` includes `scope`, `started_at`, `collected_at`, and `status`
(`available`, `partial`, or `simulated`). Collection spans a time window, not
an atomic cross-interface/protocol snapshot. Counters are ephemeral: they are not
configuration, drift, revisions, transaction snapshots, or persisted history.
Polling does not change a pending candidate or save the journal.

Clients may derive rates from successive valid samples, accounting for actual
elapsed time and counter width. Discard a baseline on unavailable data, changed
scope/name/index, a counter decrease/reset, or nonpositive elapsed time. Boot,
interface recreation, driver reset, and 32-bit wrap can invalidate deltas;
scope/name/index are useful identity hints, not a perfect generation detector.
Do not sum every interface into a host total: VLANs, parents, veths, and loopback
can count the same traffic more than once.

There is no host-global softnet/sockstat feed, conntrack/per-flow telemetry,
driver-specific ethtool statistics, WireGuard handshake/peer counters,
server-side rate history, streaming, or Prometheus exporter in this feature.

## REST API

Every request requires `Authorization: Bearer <token>`.

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v1/state` | Committed desired revision, live observed configuration, modeled drift, active transaction |
| GET | `/api/v1/interfaces` | Observed owned interfaces |
| GET | `/api/v1/interfaces/{name}` | One observed interface |
| GET | `/api/v1/vlans` | Observed owned VLAN interfaces, including parent/ID |
| GET | `/api/v1/parent-interfaces` | Read-only adopted parent inventory and availability |
| GET | `/api/v1/runtime` | Parent inventory, service runtime health, and last startup/reconcile error |
| GET | `/api/v1/services/softflowd` | Observed instance configurations; desired settings remain in `/state` |
| GET | `/api/v1/services/softflowd/status` | `{"instances": [...], "error": "..."}` with state/PID/start time/error |
| GET | `/api/v1/kernel/tunables/catalog` | Allowlisted names, scope, types, ranges and notes |
| GET | `/api/v1/kernel/tunables` | Explicit desired/configured values, effective targets, readback, captured originals and drift |
| GET | `/api/v1/statistics` | Namespace interface and protocol statistics with collection metadata |
| GET | `/api/v1/statistics/interfaces` | All namespace links, metadata and counters |
| GET | `/api/v1/statistics/interfaces/{name}` | One namespace link's metadata and counters |
| GET | `/api/v1/statistics/protocols` | Namespace IP/TCP/UDP/ICMP and extended kernel statistics |
| GET | `/api/v1/routes` | Observed owned routes |
| GET | `/api/v1/policy-rules` | Observed owned source-policy rules |
| GET | `/api/v1/firewall/rules` | Entire observed firewall: global policy, legacy rules or host/interface policies, and NAT |
| GET | `/api/v1/firewall/hosts` | Observed host inventory with outbound defaults/rules; `[]` in legacy mode |
| GET | `/api/v1/firewall/interface-policies` | Observed ordered ingress-interface override rules; `[]` in legacy mode |
| GET | `/api/v1/firewall/nat` | Observed owned masquerade rules, as `{"masquerade": [...]}` |
| GET | `/api/v1/wireguard` | Observed owned WireGuard interfaces, without private keys |
| GET | `/api/v1/transactions` | Journaled transactions keyed by ID |
| GET | `/api/v1/transactions/{id}` | Transaction status, candidate, previous config, error, confirmation deadline |
| GET | `/api/v1/revisions` | Paginated committed configuration history with dates, actors, descriptions, and restore provenance |
| GET | `/api/v1/revisions/{revision}` | One historical revision's metadata and complete configuration |
| POST | `/api/v1/transactions` | Submit one complete replacement package |
| POST | `/api/v1/transactions/{id}/confirm` | Confirm a verified candidate; idempotent after commit |
| POST | `/api/v1/transactions/{id}/rollback` | Roll back or retry failed recovery; idempotent after rollback |
| POST | `/api/v1/revisions/{revision}/restore` | Apply a historical configuration as a new provisional transaction |
| POST | `/api/v1/services/softflowd/reconcile` | Retry service runtime reconciliation using stored configuration; no body |
| GET | `/api/v1/services/dhcp-relay/status` | Per-interface relay runtime states, shared PID, and errors |
| POST | `/api/v1/services/dhcp-relay/reconcile` | Retry all managed services using stored configuration; no body |

There are deliberately no independent write endpoints for individual subsystems:
all configuration edits travel through the package transaction boundary. The
service-reconcile action repairs runtime only. Omitted resources in
a complete configuration are removed, not merged. Firewall rule order matters.
IP networks must be canonical; address prefixes may retain host bits. The body
limit is 1 MiB; unknown JSON fields and trailing JSON values are rejected.

### Configuration history and restoration

Every confirmed configuration remains available as a numbered revision.
Revision 0 is the initial configuration. Pending, failed, and rolled-back
transactions remain in transaction history, but do not become committed
configuration revisions.

```text
GET /api/v1/revisions?limit=50
GET /api/v1/revisions?limit=50&before_revision=12
GET /api/v1/revisions/7
```

The list returns a `revisions` array of metadata, newest revision number first.
It does not embed full configuration snapshots. Each entry includes:

- `revision` and `current`.
- `submitted_at` and `committed_at`, recorded in UTC.
- `submitted_by`, `committed_by`, and `transaction_id` when available.
- Optional `description` and `restored_from_revision`.

The default page size is 50, with a maximum of 100. When more entries remain,
`next_before_revision` gives the exclusive cursor for the next page.
An exhausted page has no next cursor; an empty page contains `revisions: []`.
Unknown, empty, duplicated, or malformed list parameters return `400`.
Ordering uses revision numbers, not wall-clock timestamps, so a clock adjustment
does not reorder history. For revision 0, `committed_at` records initialization.

The detail endpoint returns those same metadata fields plus `config`, containing
the full historical desired configuration. It does not query the live kernel.
The journal's committed transaction snapshots are the archive; there is no
separately editable copy of historical configuration. Loading a journal with
missing/duplicate committed revisions or inconsistent configurations fails
explicitly instead of presenting incomplete history as complete.

**Older journals remain readable, but their original dates cannot be recovered.**
For history written before timestamps were supported, `submitted_at` and
`committed_at` are `null`; an unknown confirmer is omitted. No dates are invented
from file modification times or confirmation deadlines. New commits record dates
normally without changing older entries.

An ordinary transaction may include a top-level `description` (at most 1024 bytes
after trimming surrounding whitespace), for example `"Migrate office uplink"`.
The submitter and confirmer may be different principals and are recorded
separately.

To restore revision 7 while currently at revision 12:

```text
POST /api/v1/revisions/7/restore
Content-Type: application/json
```

```json
{
  "base_revision": 12,
  "confirm_timeout_seconds": 60,
  "description": "Restore known-good office configuration"
}
```

The server loads revision 7; the client does not resubmit its configuration.
The restore response is `202` with a transaction ID and `Location` header.
Verify the provisional live state, then confirm through the normal
`POST /api/v1/transactions/{id}/confirm` endpoint. Confirmation creates revision
13, carrying `restored_from_revision: 7`. Revisions 7 through 12 are unchanged.
Revision 0 can also be restored; provenance uses the explicit value `0`.
An omitted/blank restore description defaults to `"Restore revision 7"`.

Restoration requires `state.read`, `transactions.write`, and permissions for all
subsystem differences between the current and historical configurations. It
reuses current validation, revision checks, drift checks, preflight, timed
confirmation, and compensating rollback. A stale base or active transaction is
rejected with `409`. Historical WireGuard key files must still be available;
current interface-kind restrictions and other safety checks still apply.
Restoration is not guaranteed to succeed merely because a configuration once
worked. It does not restore connection state, external files, or unmodeled
sysctls, and does not provide cross-subsystem packet-visible atomicity.

If restore fails, expires, or is rolled back, the committed revision and history
remain unchanged. The old transaction `/rollback` action is still for the active
provisional transaction, not for historical restoration. History and dates persist
in the same JSON journal; retain and back up that journal to retain the archive.

### Allow all IPv4 ICMP

Set `config.firewall.allow_all_icmp` in the configuration JSON:

```json
{
  "allow_all_icmp": true,
  "policy": "drop",
  "rules": [],
  "nat": {"masquerade": []}
}
```

This is the `firewall` object inside a complete configuration package, not a
standalone transaction. The setting defaults to `true` when omitted or `null`.
Normalized configurations and firewall reads return an explicit boolean.

When enabled, the backend installs an IPv4 protocol **1** accept exception before
all other owned forwarding rules, in both legacy and host/interface modes. It also
creates owned input and output filter chains containing that exception, with
accept defaults so other local traffic is unchanged. The exception has no
interface/address/type/code restrictions: it covers every interface in the
managed network namespace, including loopback, adopted parents, and interfaces
created later. No per-interface policy entries need to be added.

Setting the flag to `false` removes the forwarding exception and the owned input
and output chains; it does **not** add an ICMP drop rule. Existing forwarding
rules/defaults then decide ICMP behavior. IPv6 ICMP (protocol 58) is unaffected.
Rules in other nftables tables can still drop traffic; this setting does not
override them, configure forwarding sysctls, or change routing/NAT.

**Upgrade behavior:** new namespaces receive the default rules during backend
initialization. Existing durable configurations without this field, including
transaction/rollback snapshots, default to enabled. Startup atomically reconciles
the owned firewall to the expected configuration, enabling the exception even
if earlier forwarding defaults or rules blocked ICMP. Unrelated firewall drift
or invalid owned rules fail startup rather than being overwritten. A pending
transaction's candidate determines the live policy during migration. Explicit
`false` values are preserved; migration completion is persisted and retried on
failure. Historical snapshots that never specified the flag now restore the
enabled default.

Changing this setting requires `firewall.write` plus `transactions.write` and
uses the normal full-package submit/confirm/rollback workflow. Read it through
`GET /api/v1/firewall/rules` or `/api/v1/state`. The hosts/interface-policy reads
continue returning only user-authored entries, not the implicit exception.

### Host-centric and interface firewall policies

Host policies attach to named devices, **not interfaces**. A host has a stable
`id`, a display `name`, explicit IPv4/IPv6 `addresses` (no subnet suffix), an
outbound default `policy`, and ordered `rules`. Moving the host between interfaces
does not change its policy as long as its configured IP address stays the same.
Addresses must be unique across hosts. This is IP matching, not authenticated
device identity: spoofing, DHCP lease changes, MAC discovery, and automatic
address tracking are not handled. Update address assignments transactionally.

Enable the new model by including `config.firewall.policies`:

```json
{
  "policy": "drop",
  "rules": [],
  "policies": {
    "hosts": [
      {
        "id": "laptop",
        "name": "Laptop",
        "addresses": ["192.0.2.10", "2001:db8::10"],
        "policy": "drop",
        "rules": [
          {"protocol": "tcp", "destination_ports": [443], "action": "accept"}
        ]
      }
    ],
    "interfaces": [
      {
        "interface": "lan",
        "rules": [
          {"protocol": "tcp", "destination_ports": [22], "action": "drop"}
        ]
      }
    ]
  },
  "nat": {"masquerade": []}
}
```

This is a fragment of a complete package. The ingress `lan` interface must be in
the package's managed interfaces or explicitly operator-adopted on Linux. Interface
policies are optional and have **no interface default action**; an unmatched
interface rule must fall through to the source host, not override its default.
Host-only, interface-only, and combined policies are supported.

Evaluation order for forwarded traffic:

0. If `allow_all_icmp` is enabled (the default), accept IPv4 protocol 1.
1. Accept **established/related** conntrack traffic, including replies.
2. Evaluate the matching **ingress-interface** rule list in order. The first
   matching rule accepts or drops, overriding any host policy.
3. Identify the **source host** by its exact IP and evaluate its rules in order.
   If none matches, use that host's default.
4. If the source has no host entry, use the global `firewall.policy`.

The destination host's outbound default is **not** consulted. A rule can use
`destination_host` to reference an existing host ID (all its configured addresses),
or `destination` for a canonical IP network, but not both. Omitting both means
any destination. `protocol` is omitted for any protocol, or `tcp`/`udp`.
`destination_ports` is an optional list of 1..65535 ports and requires TCP/UDP;
omitting it matches all ports. Host source/destination pairs only expand within
the same IP family; a rule with no compatible family is rejected.

Both types of rule list are first-match-wins, **not universal deny-wins**. An
interface catch-all fully overrides hosts on that interface; an interface allow
can override a host drop as well as the reverse. Host inventory, IP-address, and
port-list ordering are normalized; rule order is preserved. An empty rule list
is valid. Catch-all rules may intentionally shadow subsequent rules.

**Existing connections survive policy changes and rollback.** The API does not
flush conntrack, and the established/related rule runs before interface blocks.
New blocks govern new connections, not guaranteed termination of active sessions.
Host/interface policies govern forwarding, not the device's input/output
firewall or protection of its management listener. The global ICMP exception
described above also covers input/output. NAT remains separate and still uses an egress
interface. Firewall policy edits, host address/name edits, and interface overrides
require `firewall.write` plus `transactions.write`; NAT and link edits retain
their own permissions.

Limits: 128 hosts, 16 addresses per host, 32 interface policies, 64 ordered rules
per host/interface, 32 unique destination ports per rule, 64 KiB of serialized
policy metadata, and at most 4096 expanded forwarding rules (including the
stateful rule and per-address defaults, excluding the separate global ICMP
exception). Host IDs use
`^[a-zA-Z0-9_-]{1,64}$`; names are unique, nonblank, at most 80 bytes, and have
no outer whitespace or control characters. Hosts require canonical unicast IPs,
not loopback, link-local, multicast, IPv4-mapped IPv6, or zone-qualified addresses.

Omitting `policies` (or setting it to `null`) selects **stateless legacy** `rules`,
after the optional global ICMP exception. A nonempty legacy list cannot be mixed
with `policies`; switching models is an explicit full-package transaction.
History, restoration, confirmation, drift detection, and rollback include the
abstract inventory. On Linux the inventory is chunked into bounded userdata in an
unhooked `policy_metadata` chain; observed forwarding expressions and their order
must exactly match the compiled policy. Metadata alone is not trusted.

Use [examples/host-policies.json](examples/host-policies.json) for a complete
simulator request demonstrating host HTTPS/SSH rules, an ingress SSH block,
an ingress DNS exception, a destination-host reference, and separate masquerading.
Its dummy links are lab scaffolding, not a working physical network.
The read-only `/api/v1/firewall/hosts` and `/api/v1/firewall/interface-policies`
endpoints return the observed lists. All edits still use the complete-package
transaction API; there are no standalone host writes.

### Masquerading

Inside the package's `config.firewall`, add:

```json
{
  "policy": "accept",
  "rules": [],
  "nat": {
    "masquerade": [
      {"family": "ipv4", "source": "10.8.0.0/24", "out_interface": "wan"}
    ]
  }
}
```

This is a **fragment of a complete configuration package**, not a standalone
write endpoint. `family` is required (`ipv4` or `ipv6`); `source` is optional
(omission matches all sources in that family); `out_interface` must name an
interface in the same package with a configured address of that family.
Translation uses the kernel-selected egress address, not a fixed SNAT address.
Order is preserved. The optional `postrouting` base chain runs at source-NAT
priority 100 with an accept policy.

Omitting `nat`, or sending `{"masquerade":[]}`, removes all owned masquerade rules.
Older journals without a NAT field load as an empty masquerade list; existing
filter-only tables remain valid. NAT candidates are journaled, verified, confirmed,
rolled back, and checked for modeled drift just like other configuration.
Observation checks the actual kernel expressions against metadata, not metadata
alone.

**Conntrack is not flushed or restored by the API.** Rule changes and rollback
affect new connections; existing NAT mappings can continue using the previous
translation until they expire. Interface/address removal or other kernel events
can invalidate mappings independently. No API for conntrack management is
provided.

[examples/migration.json](examples/migration.json) spans every initial subsystem.
Its dummy uplink and empty WireGuard peer list demonstrate configuration
orchestration, not a working Internet connection or tunnel. For native use,
provision the `wg0` key reference first. For later submissions, update
`base_revision` using `GET /api/v1/state`.

Example client flow (curl):

```sh
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/state
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data-binary @examples/migration.json http://127.0.0.1:8080/api/v1/transactions
# Verify state and connectivity from an independent management session, then:
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/api/v1/transactions/TRANSACTION_ID/confirm
```

A WireGuard peer has `public_key` (base64), optional numeric `endpoint`
(`192.0.2.1:51820` or `[2001:db8::1]:51820`), `allowed_ips` (canonical networks),
and `persistent_keepalive_seconds` (0..65535). DNS resolution and preshared keys
are not supported.

Submission returns `202` only after live verification. Confirmation returns
`200` after durable publication. JSON errors have `error` and `transaction`
(the latter is null when no transaction exists). Relevant failures: `400`
malformed JSON, `401` authentication, `403` authorization, `409` stale revision /
active transaction / drift / expired confirmation, `415` content type, `422`
invalid configuration, `500` apply/recovery/persistence failure, and `503`
observation failure on read. Failed apply responses include the transaction ID
and rollback status when an intent was journaled. Do not interpret them as
successful commits.

While a candidate is pending, `desired` remains the last committed config and
`observed` reflects the candidate. `drift` compares observation against the
candidate during that period, otherwise against committed desired state.

## Validation

```text
go test ./...
go vet ./...
go test -race ./internal/...
```

Race detection requires a platform-supported C toolchain. Failure-injection tests
exercise partial apply, failed compensation, failed journal writes, timeout and
late confirmation, restart recovery, stale revisions, drift, serialization, and
subsystem authorization.

Native integration must run on Linux with the required capabilities and kernel
modules:

```sh
sudo env NETCONTROL_INTEGRATION=1 go test ./internal/control \
  -run '^TestLinuxIsolatedTransaction$' -count=1 -v
```

This test creates and cleans up its own namespace; it never targets the host
network. It exercises real interfaces, IPv4/IPv6 addresses and routes, policy
rules, nftables, WireGuard, observation, confirmation and compensating rollback.
It also checks IPv4/IPv6 masquerade rule readback, sends IPv4 UDP probes and
inspects conntrack tuples to verify actual translation, nonmatching-source
behavior, preservation of an established mapping across rule edits, and
restoration of translation after rollback.
Run the protected-parent/nested-VLAN lifecycle and compensation test with:

```sh
sudo env NETCONTROL_INTEGRATION=1 go test ./internal/control \
  -run '^TestLinuxVLANProtectedParents$' -count=1 -v
```

An optional real-process test checks readiness, pending-candidate restart,
unexpected exit, explicit repair, configuration rollback, invalid BPF
compensation, and process removal:

```sh
sudo env NETCONTROL_INTEGRATION=1 \
  NETCONTROL_SOFTFLOWD_BINARY=/usr/sbin/softflowd \
  NETCONTROL_SOFTFLOWD_UID="$(id -u netcontrol-flow)" \
  NETCONTROL_SOFTFLOWD_GID="$(id -g netcontrol-flow)" \
  go test ./internal/control -run '^TestLinuxSoftflowdLifecycle$' -count=1 -v
```

DHCP relay lifecycle and packet tests require an installed dnsmasq plus the
non-root account/group described in [Relay operator setup](#relay-operator-setup):

```sh
sudo env NETCONTROL_INTEGRATION=1 \
  NETCONTROL_DHCP_RELAY_BINARY=/usr/sbin/dnsmasq \
  NETCONTROL_DHCP_RELAY_UID="$(id -u netcontrol-relay)" \
  NETCONTROL_DHCP_RELAY_GID="$(id -g netcontrol-relay)" \
  go test ./internal/control -run '^TestLinuxDHCPRelay' -count=1 -v
```

These tests cover process readiness, pending-candidate restart, crash repair,
enable/disable, server changes, interface removal, and rollback. The packet test
creates isolated router/client/server namespaces and VLAN/veth links, checks that
a request reaches both configured servers with the selected relay address, and
verifies an offer returns to the client. They never target the host network.

The ordinary suite skips these integration tests unless explicitly enabled. Cross-compilation alone
does not validate native kernel behavior.

Kernel ownership tests cover capture-before-write, restoration on omission,
released-key noninterference, capture races, partial writes, persistence failures,
timeouts, scoped authorization, history, corrupt snapshots, and restart recovery.
The native namespace-only lifecycle test never writes host-global tunables:

```sh
sudo env NETCONTROL_INTEGRATION=1 go test ./internal/control \
  -run '^TestLinuxKernelNamespaceLifecycle$' -count=1 -v
```

The statistics integration test sends real UDP packets over loopback in a fresh
namespace and checks packet/byte deltas, namespace-specific UDP protocol counts,
single-link lookup, unmanaged-link visibility, and unchanged configuration.
It never changes host-global tunables:

```sh
sudo env NETCONTROL_INTEGRATION=1 go test ./internal/control \
  -run '^TestLinuxNetworkStatisticsPacketsAndNamespaceIsolation$' -count=1 -v
```

Portable tests cover all counter mappings, 32/64-bit decoding, endianness,
precision, protocol parsing/fuzz seeds, missing-data semantics, authorization,
read-only methods, response shapes, and independence from configuration writes.
