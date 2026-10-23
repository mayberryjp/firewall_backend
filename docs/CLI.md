# Transactional configuration CLI over SSH

The Rust daemon includes a Cisco-inspired command interpreter and its own
in-process SSH server. It does not launch `sshd`, a login shell, or external
networking commands. This is not an IOS-compatible implementation or a general
operating-system shell.

## Enable and connect

SSH is opt-in and independent of the existing HTTP listener:

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

Complete normal website onboarding, create and save an **API key**, and then:

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

## Candidate, apply, and confirmation

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

```text
interface NAME [ethernet|dummy|vlan|wireguard]
no interface NAME
ip route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
ipv6 route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
no ip route PREFIX INTERFACE GATEWAY|direct TABLE METRIC
policy-rule PRIORITY SOURCE TABLE
no policy-rule PRIORITY
firewall policy accept|drop
firewall allow-all-icmp enable|disable
firewall rule SOURCE|any DESTINATION|any accept|drop
no firewall rule INDEX
firewall host JSON
firewall interface-policy JSON
nat masquerade ipv4|ipv6 INTERFACE [SOURCE]
no nat masquerade INDEX
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
```

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

## Complete-schema JSON editing

All configuration surfaces, including nested fields not given a dedicated
shortcut, are available through typed JSON-pointer editing:

```text
set /firewall/policy "drop"
set /ntp/servers/- "time.example.test"
delete /ntp/servers/0
set /kernel/namespace/net.ipv4.tcp_congestion_control "cubic"
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
show interfaces
show interfaces discovered
show routes
show policy-rules
show firewall
show kernel
show statistics
show statistics vnstat/managed
show transactions
show transaction TRANSACTION_ID
show revisions
show revision NUMBER
restore revision NUMBER confirmed 60 DESCRIPTION
reconcile services ntp
```

`show running-config` reads the committed revision archive without requiring
healthy live observation. `show state`/resource views retain observation errors;
`show interfaces discovered` reads actual namespace inventory independently of
configured-state verification and worker health. In native host mode this
includes unmanaged host NICs; in simulator mode it is simulated inventory only.
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
