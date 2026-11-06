# Transactional configuration CLI over SSH

The Rust daemon includes a Cisco-inspired command interpreter and its own
in-process SSH server. It does not launch `sshd`, a login shell, or external
networking commands. This is not an IOS-compatible implementation or a general
operating-system shell.

## Enable and connect

SSH is independent of the HTTP listener. Ubuntu `install.sh` and full
`upgrade.sh` enable the in-process server by default on `0.0.0.0:2222` through
`NETCONTROL_SSH_LISTEN`. A manual daemon invocation remains opt-in:

```sh
netcontrold --backend simulator \
  --state /var/lib/netcontrol/state.json \
  --credential-db /var/lib/netcontrol/credentials.json \
  --ssh-listen 0.0.0.0:2222 \
  --ssh-host-key /var/lib/netcontrol/ssh-host-key
```

For OpenRC, add the two SSH arguments to `netcontrold_args` in
`/etc/conf.d/netcontrold`, preserving the other arguments. No new package payload
or separate SSH service is required. Native mode manages the same host network
namespace as the management listener unless an isolated lab namespace is
explicitly selected. Changing a management NIC can interrupt API/SSH access.

`--ssh-listen` takes precedence over `NETCONTROL_SSH_LISTEN`. Full Ubuntu
upgrades preserve custom startup arguments; `--build-only` changes no service
settings. To override/disable the script-managed default, see
[deployment overrides](BUILD_AND_INSTALL.md#optional-configuration-ssh-server).
The scripts do not create firewall permits: restrict TCP 2222 to trusted
management networks. The fresh appliance input policy already blocks new WAN
connections, but an existing appliance's current policy must be reviewed.

If `--ssh-host-key` is omitted, its path is `<state>.ssh-key`. The daemon creates
an Ed25519 host key once and reuses it. Existing invalid/insecure host-key data
fails startup; it is not overwritten or silently regenerated. Keep this file
private and stable. Check the SSH host fingerprint through an independently
trusted channel before accepting it in your client's known-hosts database.
Changing/deleting it changes device identity; do not bypass host-key warnings.
The daemon logs the public SHA-256 host fingerprint at startup. Host-key files
must be unencrypted OpenSSH Ed25519 private keys, at most 16 KiB. Symlinks,
reparse points and hard links are rejected. On Unix, the key must be daemon-owned
with no group/other permissions; new keys use mode 0600. On Windows, operators
must enforce private ACLs on the key and its parent directory; the daemon does
not independently verify Windows ACL privacy.

Create and save an **API key** using normal website onboarding or the local
console command below, and then:

```sh
ssh -p 2222 apikey@192.0.2.10
```

Use the literal SSH username `apikey`. Enter the existing API key at the SSH
password prompt, not the device-account password. Do not put the key in a command
line or URL. Device keys require completed onboarding; scoped `--auth-file` keys
use their existing permissions. SSH authentication does not grant extra
permissions, and `enable` changes only CLI mode. API-key revocation is checked
again before each command; scoped-file changes still require daemon restart.

SSH encrypts its own connection even if the HTTP listener uses HTTP. It does not
make HTTP key creation secure or restrict an all-interface listener to LAN.
Operators still provide reachable addressing and management access controls.
Enabling SSH does not provision interfaces or forwarding.

### Browser-free local key creation

With the updated daemon running, use a trusted Linux root console:

```sh
sudo netcontrold --create-api-key console
ssh -p 2222 apikey@127.0.0.1
```

On a fresh device, the first command prompts for a device username and a
12..72-byte password twice, without echoing the password. It atomically saves
the account, finishes onboarding and creates a full-permission API key. Save
the displayed key immediately and use it at the SSH password prompt. The device
account password remains for website login; it is not an SSH password.

If an account already exists, its username/password and existing keys/sessions
are preserved, and no account prompt is shown. The command also finishes pending
onboarding: existing pending device keys become usable. Key names must be unique,
nonempty, trimmed, without control characters, and at most 80 bytes; the normal
100-key limit applies. Failed validation changes nothing; uncertain persistence
fails closed and requires daemon restart. Use the normal website key list and
revocation controls for the new key.

This is local root authorization, not a default password or an unauthenticated
HTTP/SSH route. The daemon keeps its credential-store lock; no restart or direct
state-file editing is needed. Plaintext passwords/keys are not persisted or
logged by the daemon. Output requires a terminal: do not redirect it or use
session recording, terminal logging or shell tracing while creating a key.
Lost output cannot be recovered; inspect/revoke that named key before creating
another. Do not blindly retry a timed-out request.

Linux host device mode automatically binds `/run/netcontrol/control.sock`,
independently of HTTP and SSH listeners. Its directory is root-owned mode 0700
and socket mode 0600; both peers must have root UID. The directory's parent must
also be root-owned and not writable by others. The daemon rejects foreign files,
symlinks, insecure paths and active sockets; a verified stale socket after a
crash is replaced. Shutdown finishes accepted identity writes and removes only
its owned socket. Bind failures are startup errors, not silent disablement.

For an explicit socket path, supply `--control-socket /run/netcontrol/custom.sock`
to both the daemon and key command. A manual root simulator/lab launch needs this
explicit flag; native host device mode uses the default automatically. Live local
key creation is Linux-only and unavailable with `--auth-file`, whose externally
managed scoped credentials must not be modified through this command.
The feature requires a daemon built with this support; an older running daemon
has no socket. It does not enable SSH when SSH is disabled, assign network
addresses, or add firewall permits. Use the existing candidate/confirmed
configuration commands after login to set LAN addresses and VLANs.

## Correcting an initially untagged factory LAN

The installer now prompts for an existing physical or VLAN LAN and its IPv4
address. It does not reconfigure already-provisioned devices. If an unchanged
factory installation selected the physical parent instead of the intended VLAN,
use the updated daemon's root-only local command:

```sh
sudo netcontrold --configure-lan vlan50 \
  --lan-parent enp2s0 --lan-vlan 50 --lan-address 192.168.50.1/24
```

This is not a factory reset. It first validates that saved network policy is the
unchanged factory policy with one physical LAN/address and one physical WAN.
Customized policy, extra LAN addresses or conflicting VLAN identity/addresses
are refused; use a deliberately reviewed complete configuration for those cases.
An existing unmanaged VLAN needs an explicit ownership handoff that preserves
its live addressing/MTU and becomes a saved unassigned baseline; an absent VLAN
is created by the subsequent transaction. Ordinary configuration commands still
do not implicitly seize foreign links.

The requested change moves the LAN address/role, input and forwarding rules and
NAT subnet to the VLAN and removes untagged addressing from the parent. It
preserves the physical WAN DHCP configuration. The command displays a transaction
ID and applies provisionally for **120 seconds**. Verify connectivity from the
tagged LAN, then run from the console:

```sh
sudo netcontrold --confirm-network-change TRANSACTION_ID
```

You may also confirm the ID through the existing authenticated SSH CLI/API.
Without confirmation, normal transaction rollback restores the original saved
LAN policy. If the VLAN was explicitly imported first, that imported baseline
remains managed with its original settings; rollback does not delete the
operator's preexisting VLAN. Errors/uncertain outcomes require inspecting
transactions, not resetting state or blindly retrying.

HTTP binding is deployment configuration, separate from the network transaction.
After confirmation, edit only `NETCONTROL_LISTEN` in the root-owned
`/etc/netcontrol/appliance.env` to the new address (for example
`NETCONTROL_LISTEN=192.168.50.1:8080`), preserving its other settings, then:

```sh
sudo systemctl restart netcontrold
```

Do not restart or change the listener environment before confirmation.
Keep local console access throughout; connect the switch port as a tagged trunk.
The usual wildcard SSH listener includes the new address and localhost.
No key/password bypass, DHCP server or new firewall WAN management permit is
introduced. These commands require the updated running Linux device daemon and
its protected local control socket.

## Candidate, apply, and confirmation

BGP uses `bgp JSON` / `no bgp` to replace/reset the private candidate's BGP
object. Commit requires `transactions.write` and `bgp.write`, plus permissions
for other changed areas. `show bgp`, `show bgp status` and `show routes bgp`
require `state.read`; the last lists learned paths independently of configured
static routes. See the [complete BGP contract](../FRONTEND_SPEC.md#native-ipv4-bgp)
for a configuration example, interface/WireGuard selection, timers, default
route opt-in, installation status and limitations.

Every SSH shell has a private in-memory candidate. Entering configuration mode
copies the **committed** configuration and its revision, not observed live state.
Commands edit only that candidate. They never change networking individually.

```text
netcontrol> enable
netcontrol# configure terminal
netcontrol(config)# interface lan0 dummy
netcontrol(config-if)# role lan
netcontrol(config-if)# no shutdown
netcontrol(config-if)# ip address 192.0.2.1/24
netcontrol(config-if)# exit
netcontrol(config)# compare
netcontrol(config)# commit check
netcontrol(config)# commit confirmed 60 Add lab interface
netcontrol# show state
netcontrol# confirm
```

`commit confirmed` submits one complete configuration to the **same Engine**
used by the HTTP API, with the candidate's base revision and a 10..300-second
confirmation timeout. Existing permissions, drift guards, durable intent,
confirmation, rollback, revisions and recovery remain authoritative.

- A successful apply is provisional, not a committed revision.
- Check independent connectivity before `confirm [transaction-id]`.
- `rollback [transaction-id]` requests explicit rollback using the same engine.
- The optional ID defaults to the most recent successful transaction in that
  shell. A new shell must provide the ID, obtained using `show transactions`.
- Disconnect or `exit` from exec/enabled mode discards the local candidate but
  **does not confirm or cancel an already submitted transaction**. Its durable
  confirmation deadline remains. In interface/global configuration mode,
  `exit` moves up one mode and retains the candidate.
- A stale candidate returns revision conflict; it is not silently merged or
  rebased. Inspect the latest running configuration, then explicitly discard and
  start again.
- Errors retain the private candidate. If an apply reports uncertain recovery,
  read its transaction instead of blindly retrying.
- `end` leaves configuration mode without discarding. `discard` removes only the
  local candidate. Neither is rollback of a live transaction.
- Immediate `commit`/`write memory` is not supported: confirmation is explicit,
  and confirmed revisions are already persisted.

This is the API's rollback-aware complete-package transaction, **not** an atomic
whole-kernel update. Interfaces and services can be interrupted during apply.

## Modes and configuration commands

`?` or `help` prints the complete command list. Use full command names; IOS
abbreviations, shell expansion, pipes, semicolon chaining and OS commands are not
provided.

| Mode | Prompt | Purpose |
| --- | --- | --- |
| Exec | `netcontrol>` | Read state and help; `enable` enters enabled mode |
| Enabled | `netcontrol#` | Enter configuration; confirm/rollback/restore/repair |
| Global candidate | `netcontrol(config)#` | Stage shared network/service/kernel fields |
| Interface candidate | `netcontrol(config-if)#` | Stage one interface |

Global editors include:

For an IPv4 route on a DHCP-managed Ethernet interface, use `dhcp` instead of a
literal gateway to follow that interface lease's IPv4 default-route gateway:
`ip route 203.0.113.10/32 eno1 dhcp 254 10`. `direct` remains a no-gateway route;
literal gateways remain pinned. Table/metric stay operator-selected. Missing or
ambiguous lease gateways fail explicitly; no valid lease suspends installation.
Keep WireGuard endpoint-loop prevention in the surrounding underlay routing
policy. See the [complete route contract](../FRONTEND_SPEC.md#64-routes).

```text
interface NAME [ethernet|dummy|vlan|wireguard]
no interface NAME
ipv6 enable|disable
hostname NAME
no hostname
timezone ZONE
no timezone
ip route PREFIX INTERFACE GATEWAY|direct|dhcp TABLE METRIC
ipv6 route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
no ip route PREFIX INTERFACE GATEWAY|direct|dhcp TABLE METRIC
firewall policy accept|drop
firewall allow-all-icmp enable|disable
firewall rule SOURCE|any DESTINATION|any accept|drop
no firewall rule INDEX
firewall host JSON
firewall interface-policy JSON
nat masquerade ipv4|ipv6 INTERFACE [SOURCE]
no nat masquerade INDEX
nat destination-rewrite WAN tcp|udp PORT LAN TARGET_IP
no nat destination-rewrite INDEX
ntp server HOST
no ntp server HOST
ntp enable|disable
syslog server HOST PORT udp|tcp|tls
no syslog server INDEX
syslog enable|disable
vnstat enable|disable
exporter JSON
no exporter NAME
gateway-monitor JSON
no gateway-monitor NAME
kernel host|namespace KEY VALUE
no kernel host|namespace KEY
kernel rps INTERFACE/rx-N MASK
no kernel rps INTERFACE/rx-N
kernel rfs JSON
no kernel rfs
kernel offload INTERFACE FEATURE enable|disable
no kernel offload INTERFACE [FEATURE]
```

`show diagnostics path-test` reads the current/last short-lived paired MTU/MSS
session (`state.read`). Start/cancel is API-managed, not a CLI credential command;
pairing secrets are never accepted as saved configuration or printed by status.
Simulator/unsupported backends report an explicit error, not invented results.
See the [paired-test contract](../FRONTEND_SPEC.md#paired-path-mtumss-tests).

`show statistics performance` reads passive CPU/IRQ/softnet and physical/WireGuard RX-queue
evidence (`state.read`). `kernel rps` stages a canonical lowercase hexadecimal
CPU mask, for example `c` selects CPUs 2 and 3; this is a synthetic example,
not an appliance recommendation. Mask `0` explicitly disables RPS; `no kernel
rps` restores the queue's captured original mask on apply. Changes require
`transactions.write`, `interfaces.write`, `kernel.host.write` and native host mode,
which automatically acquires tuning ownership without an extra launch flag.
Use a managed physical Ethernet parent or kernel WireGuard interface, not a
VLAN or other tunnel. For example, `kernel rps wg0/rx-0 2` selects CPU 1
(synthetic, not a recommendation). WireGuard creation and tuning can share a
candidate; the live kernel must expose a writable RX queue. RFS and NIC offload
targets remain physical-only. `commit check` validates configuration, not live queue/CPU/write
availability. Apply still requires `commit confirmed` and explicit `confirm`
after independent connectivity/performance checks. No IRQ or other tuning is
changed. See the [contract](../FRONTEND_SPEC.md#performance-diagnostics-and-rps-tuning).

`kernel rfs` replaces the candidate's typed global/per-queue RFS object, for
example `kernel rfs {"sock_flow_entries":4096,"queues":{"eno1/rx-0":1024}}`.
This is synthetic, not a recommended appliance setting. Counts are zero or powers
of two up to 1048576; positive queue counts need explicit nonzero candidate RPS
masks, and their sum cannot exceed the global count. `no kernel rfs` restores
captured global/queue originals on apply. RFS is primarily for local applications.

`kernel offload eno1 rx-checksum enable` stages one exact driver feature;
`disable` explicitly owns a false setting. `no kernel offload eno1 rx-checksum`
restores that feature's original setting; omitting FEATURE releases all offload
ownership on that interface. No external ethtool command runs. Missing/fixed
features, incoherent dependencies and unexpected side effects fail explicitly;
LRO cannot be enabled. These commands use the same permissions, automatic
host-mode ownership, confirmed transaction and recovery workflow as RPS.
No offloads or RFS are enabled by merely displaying capabilities. See the
[complete feature/count contract](../FRONTEND_SPEC.md#explicit-rfs-and-nic-offload-configuration).

Route-add commands explicitly stage `enabled: true`. Route deletion matches the
specified path/table/metric regardless of its enabled flag or metadata, so a
disabled route remains deletable. Route enabled toggles use the complete
configuration transaction API; there is no dedicated CLI toggle command.

`ipv6 enable|disable` stages the top-level `ipv6_enabled` policy (default true).
It requires `kernel.namespace.write` when applied, in addition to transaction
permission. Disabling requires removing conflicting IPv6 configuration in the
same candidate; use IPv4 management and independently verify connectivity before
confirmation. It affects loopback/unmanaged interfaces in the managed namespace,
not only addresses configured through the CLI. See the
[global IPv6 contract](../FRONTEND_SPEC.md#global-ipv6-policy).

`hostname NAME`, `domain NAME` and `timezone ZONE` stage `system.hostname`,
`system.domain` and `system.timezone`; the domain is a cosmetic label that is never
applied to the host or used as a search domain;
the `no` forms stage the empty (unmanaged) value, which stops management without
restoring the previous value. They require `system.write` when applied. `commit
check` validates only the syntax (lowercase RFC 1123 label; IANA zone shape); a
timezone that is missing from the host database is rejected when the transaction is
submitted. The daemon applies confirmed values itself after confirmation; see the
[host name and time zone contract](../FRONTEND_SPEC.md#616-host-name-and-time-zone).
There is no `show system`; read `GET /api/v1/system/status` over HTTP.

Source-policy routing is not user-configurable: `policy-rule`, `no policy-rule`
and `show policy-rules` are unsupported. JSON candidate imports must omit
`policy_rules`, even when empty. Ordinary routes remain editable (normally table
254); gateway monitors manage their exact-source lookup rules internally.

Interface editors include:

```text
role wan|lan|unassigned
mtu NUMBER
shutdown
no shutdown
ip address PREFIX
ipv6 address PREFIX
no ip address PREFIX
no ipv6 address PREFIX
vlan parent NAME
vlan id NUMBER
wireguard key-ref NAME
wireguard listen-port PORT
wireguard peer JSON
no wireguard peer PUBLIC_KEY
dhcp-relay server IPV4
no dhcp-relay server IPV4
dhcp-relay enable|disable
```

`wireguard key-ref NAME` names a private key file already stored on the appliance
(it does not take the key itself). Create it with the
[key creation command](BUILD_AND_INSTALL.md#creating-a-wireguard-private-key),
which also prints the public key for the peer.

Peers have an `enabled` flag (default true). A disabled peer stays in the candidate
and saved configuration but is not installed on the interface. Toggle it by
pointer, for example `set /interfaces/0/wireguard/peers/0/enabled false` (back with
`true`), or resend the peer with `"enabled":false` in `wireguard peer JSON`.
Resending a peer without `enabled` makes it enabled again. Check the live result
with `show runtime`: only installed peers appear there.

New candidate entries start as administratively down, role LAN, MTU 1500;
omitted kind is dummy. These are visible CLI creation defaults, not role-based
network policy. Use `show interfaces discovered` before staging
`interface eth0 ethernet` for an existing host NIC. Ethernet entries configure
existing Ethernet/veth links; they do not create or delete hardware.
Explicitly preserve needed management addresses in the candidate; discovery
does not copy them into desired configuration or automatically assign roles.
Separately, the first supported native host startup inherits physical NICs into
an otherwise unused journal with role `unassigned`. That initial baseline is not
repeated by discovery or normal restart. DHCPv4 and resolver settings are
top-level `dhcp_clients`/`dns` maps; use complete-schema JSON editing to change
them, and keep DHCP lease addresses out of static address lists. See the
[current contract](../FRONTEND_SPEC.md#dhcpv4-and-resolver-configuration) and
[host prerequisites](BUILD_AND_INSTALL.md#automatic-physical-interface-inheritance).
New VLAN/WireGuard interfaces require their specific settings before validation.
Changing an existing interface's kind requires explicit removal/recreation or
an explicit typed candidate edit. WireGuard accepts only preprovisioned key-file
references, never private-key contents.

Object editors take one JSON object matching the
[current configuration schema](../FRONTEND_SPEC.md#94-data-shapes). Exporters,
gateway monitors, peers and firewall policies are upserted by their existing
name/public-key/ID/interface identity. Ordered firewall rules append; indexes
are zero-based. Removing an interface does not silently remove dependent routes,
VLANs or monitors: fix dependencies in the candidate before checking/committing.

Fields and bounds use the canonical backend contract, including reserved routing
tables, explicit roles, supported capture filters, and operator host-service/
kernel opt-ins. Semantic cross-resource validation is deferred to `commit check`
and apply so a candidate can be built in several commands.

For host routing, main table `254` is also supported. Forwarding remains an
operator prerequisite: the CLI rejects forwarding sysctls because their
collateral device/RA changes cannot currently be safely rolled back.
Roles do not enable forwarding, acquire DHCP leases or create NAT automatically.

Destination rewrite matches forwarded traffic's original WAN route and one exact
TCP/UDP destination port, replacing only the destination IP with another device
on the selected LAN subnet. Use separate TCP and UDP rules for DNS. For example:
`nat destination-rewrite wan0 udp 53 lan0 192.168.10.53`.
The client IP and destination port remain unchanged; arrange replies through the
firewall (a same-subnet target normally replies directly and breaks reverse NAT).
Firewall-originated traffic is excluded, ordinary filtering still applies to
the rewritten target, and existing conntrack translations persist after edits.
Commands stage the same confirmed transaction and require `nat.write`; see the
[canonical contract](../FRONTEND_SPEC.md#destination-rewrite).

## Complete-schema JSON editing

All configuration surfaces, including nested fields not given a dedicated
shortcut, are available through typed JSON-pointer editing:

```text
set /firewall/policy "drop"
set /ntp/servers/- "time.example.test"
delete /ntp/servers/0
set /kernel/namespace/net.ipv4.tcp_congestion_control "cubic"
set /blackhole {"name":"blackhole0","action":"blackhole"}
ip route 198.51.100.0/24 blackhole0 direct 254 50
load candidate {"firewall":{"allow_all_icmp":true,"policy":"accept"}}
```

Pointers use RFC6901 `~0` and `~1` escapes, zero-based array indexes, and `-` to
append. Parents must exist. `delete` removes an array entry or optional/defaulted
field; deleting a required field fails. Omitted defaulted fields return to current
schema defaults. Unknown fields, nulls for nonoptional fields and wrong types
fail without changing the candidate. There is no file upload or filename
interpretation; `load candidate` takes inline JSON only.

Each command is limited to 65,536 bytes and the candidate to 1 MiB. Large
configurations can be assembled with several pointer edits; there is no multiline
JSON/paste mode. The engine's 1 MiB submit-body limit includes the transaction
envelope and description, so leave space for those when building large candidates.
Running/candidate views are JSON to preserve the exact complete
schema, not an independently lossy IOS configuration format.

## Inspection, recovery, and other managers

```text
show running-config
show candidate-config
compare
show state
show runtime
show udp-broadcast-relay
show udp-broadcast-relay status
show interfaces
show interfaces discovered
show routes
show firewall
show kernel
show statistics
show statistics host
show statistics link-diagnostics
show statistics vnstat
show transactions
show transaction TRANSACTION_ID
show revisions
show revision yyyy.mm.dd.iteration
restore revision yyyy.mm.dd.iteration confirmed 60 DESCRIPTION
reconcile services ntp
reconcile services udp-broadcast-relay
```

UDP relay candidate editing uses `udp-broadcast-relay JSON` and
`no udp-broadcast-relay`, then the normal commit-check/confirmed-commit workflow.
Changes require `udp_broadcast_relay.write` plus transaction and other changed
resource permissions. See the [synthetic Govee/ECHONET example](../examples/udp-broadcast-relay.json)
and [relay contract](UDP_BROADCAST_RELAY_SPEC.md) for schema, firewall and route
prerequisites. Service repair is shared, not a per-instance restart.

`show running-config` reads the committed revision archive without requiring
healthy live observation. `show state`/resource views retain observation errors;
`show interfaces discovered` reads actual namespace inventory independently of
configured-state verification and worker health. In native host mode this
includes unmanaged host NICs; in simulator mode it is simulated inventory only.

Revision arguments and JSON revision fields are canonical UTC
`yyyy.mm.dd.iteration` strings, not incrementing integers. Use an exact ID from
`show revisions`; initial allocation and a new day's first confirmed commit use
iteration 1. Restores create a new revision on confirmation; rollback does not.
Software uses the same format independently. `show running-config` includes
daemon-managed `software` identity/daily-update metadata; it is read-only and
must not be edited or restored as networking settings.
`show runtime`, transaction reads and rollback are separate diagnostics/actions.
Restore creates a new provisional transaction and requires confirmation.
Discard a private candidate before restoring. Service repair acts on stored
committed/pending settings, **not** the private candidate, and requires the same
all-enabled-service permissions as HTTP repair.

HTTP clients and other SSH sessions share the same revision and active-transaction
guard. Either management surface can inspect/confirm/roll back a transaction if
its API key has the necessary permissions. Frontends must retain existing
conflict/polling/uncertain-write behavior; there is no SSH-only configuration
database, automatic merge, notification channel or parallel commit bypass.

The SSH exec facility accepts a single CLI command and returns nonzero status
on failure, for example `ssh -p 2222 apikey@192.0.2.10 'show running-config'`.
Use an interactive shell with a PTY for a multi-command candidate workflow, not
multiline exec requests. Shell requests without a PTY are rejected; use `ssh -t`
when your client does not automatically request one. SSH forwarding,
SFTP/subsystems, environment injection and arbitrary program execution are not
available.

## SSH transport limits

The listener accepts at most 32 simultaneous connections, 60 new connections per
minute and 30 password-authentication attempts per minute globally. Each
connection allows three authentication attempts. Identification and authentication
each have a 15-second deadline. Connections have a five-minute inactivity limit
and a 30-minute absolute lifetime; reconnecting does not confirm a transaction.

Interactive input accepts CR, LF or CRLF terminators and backspace/DEL editing.
Ctrl-C immediately cancels the current input line and reprompts, keeping the
candidate. It does not interrupt an executing command or undo an applied
transaction. Ctrl-D immediately exits, discarding partial input and the private
candidate without confirming or cancelling a pending transaction.
Invalid UTF-8, unsupported control/escape sequences and overlong lines are
rejected through the next terminator, never partially executed. ASCII is echoed;
non-ASCII input is accepted as UTF-8 but not echoed. Output strips terminal
controls and uses CRLF line endings. This is a bounded command terminal, not a
full-screen terminal emulator.

Rendered command output, including CRLF expansion, is limited to 4 MiB.
An oversized response is replaced with an explicit error, not partial JSON or
a success-shaped truncated response. Exec returns status 1; an interactive
shell reprompts. The command may already have completed or applied changes:
inspect state/individual transactions before retrying. Use narrower resource
or individual transaction/revision queries instead of an oversized listing.
