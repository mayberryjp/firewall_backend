# Netcontrol

A Go REST control plane for packaged Linux networking migrations. This is an
initial implementation for **isolated labs**, not a production host-networking
manager. The default backend simulates changes without touching the OS.

## The transaction guarantee

One request submits a complete desired configuration spanning interfaces,
addresses, routes, source-policy routing, nftables, and WireGuard.

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
4. Create/update links, addresses and WireGuard, reconcile routes and policy
   rules, atomically replace the owned nftables table, then remove obsolete
   links. No shell commands are executed by the service.
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
| Interfaces | Create/delete `dummy` and kernel `wireguard` links; name, MTU, up/down |
| Addresses | Exact global-unicast IPv4/IPv6 prefixes on managed links; host bits retained |
| Routes | Unicast destination/gateway/device/positive metric, tables 10000..19999, protocol 242 |
| Policy routing | Source-prefix table lookup; unique priorities and tables 10000..19999 |
| Firewall | Owned `inet netcontrol` table, `forward` filter chain, ordered source/destination accept/drop rules and default policy |
| NAT | IPv4/IPv6 masquerading in the same table's `postrouting` NAT chain, with explicit family, optional source network, and required managed egress interface |
| WireGuard | Private-key references, stable listen ports, peers, numeric endpoints, allowed IPs and keepalive |

The Linux backend requires an **explicit, pre-created, initially empty network
namespace** (loopback is allowed). It refuses the current and PID 1 namespaces.
The management HTTP listener remains in the service's original namespace.
The target namespace is pinned for the lifetime of the process.

All non-loopback links in that namespace belong exclusively to this service.
Do not attach physical devices or run NetworkManager, systemd-networkd, another
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
Changing interface kind in place is rejected. Forwarding sysctls are not changed.

Physical-interface adoption, VLANs, bridges, namespaces as API resources, SNAT/DNAT/port forwarding,
ports/protocols/sets/conntrack, traffic control, device tuning, hardware offload,
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

Authentication is mandatory, including in the simulator. Generate a strong random
bearer token locally, retain the plaintext only on the client, and place its
lowercase SHA-256 hash in a private `auth.json`:

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
      "wireguard.write"
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
collect and protect these logs; this is not a tamper-evident audit store. Credential
reload, expiry, and rate limiting are not implemented.

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
kernel support. Only the operator setup uses CLI tools:

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

## REST API

Every request requires `Authorization: Bearer <token>`.

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v1/state` | Committed desired revision, live observed configuration, modeled drift, active transaction |
| GET | `/api/v1/interfaces` | Observed owned interfaces |
| GET | `/api/v1/interfaces/{name}` | One observed interface |
| GET | `/api/v1/routes` | Observed owned routes |
| GET | `/api/v1/policy-rules` | Observed owned source-policy rules |
| GET | `/api/v1/firewall/rules` | Observed owned default policy and ordered rules |
| GET | `/api/v1/firewall/nat` | Observed owned masquerade rules, as `{"masquerade": [...]}` |
| GET | `/api/v1/wireguard` | Observed owned WireGuard interfaces, without private keys |
| GET | `/api/v1/transactions` | Journaled transactions keyed by ID |
| GET | `/api/v1/transactions/{id}` | Transaction status, candidate, previous config, error, confirmation deadline |
| POST | `/api/v1/transactions` | Submit one complete replacement package |
| POST | `/api/v1/transactions/{id}/confirm` | Confirm a verified candidate; idempotent after commit |
| POST | `/api/v1/transactions/{id}/rollback` | Roll back or retry failed recovery; idempotent after rollback |

There are deliberately no independent write endpoints for individual subsystems:
all edits travel through the package transaction boundary. Omitted resources in
a complete configuration are removed, not merged. Firewall rule order matters.
IP networks must be canonical; address prefixes may retain host bits. The body
limit is 1 MiB; unknown JSON fields and trailing JSON values are rejected.

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
The ordinary suite skips it unless explicitly enabled. Cross-compilation alone
does not validate native kernel behavior.
