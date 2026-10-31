# Native Linux backend

This crate implements `netcontrol_core::Backend` through direct Linux syscalls,
routing netlink, WireGuard generic netlink, and atomic nftables netlink batches.
It never invokes `ip`, `nft`, `wg`, Go, a shell, or a service executable.
`wireguard-control` is always explicitly selected with `Backend::Kernel`; its
optional userspace-program backend is never selected.

## Operator requirements

- Linux with network namespace, dummy, VLAN, WireGuard, connection-tracking,
  nftables inet/filter/NAT/masquerade support provisioned by the operator.
- By default the daemon's **current network namespace**, not a forced entry into
  PID 1's namespace. In Docker this means the container namespace; host networking
  must be selected by the operator to manage host links. An optional explicit
  `namespace` selects a pre-created lab namespace: a simple name resolves under
  `/run/netns`; an absolute nsfs mount path is also accepted. Explicit namespace
  symlinks are rejected. This crate neither creates nor deletes namespaces.
- `CAP_NET_ADMIN` for network configuration and nftables. When target and current
  namespaces match, networking workers skip `setns`, so namespace entry alone
  does not require `CAP_SYS_ADMIN`. Entering a different namespace requires
  applicable `setns` capabilities (normally `CAP_SYS_ADMIN` in the relevant user
  namespaces). Service-specific capabilities are additional; blanket
  `--privileged` is not a prerequisite. Host sysctl writes need
  explicit `allow_host_tunables` and exclusive ownership of the trusted
  root-owned `/run/netcontrol-host-tunables.lock`. The normal management listener
  remains outside the managed namespace.
- A dedicated absolute services state directory. Its `native` child is private
  (0700); state files are private (0600), atomically replaced and directory-synced.
  The namespace inode and state directory are advisory-locked exclusively.
- Private WireGuard key files referenced by basename, owned by the daemon user
  with no group/other permission bits. The key directory must be owned by that
  user and not group/other-writable. Keys are opened relative to the directory
  descriptor without following symlinks; key contents are not persisted in state,
  logs, runtime replies, or nftables metadata.

`NativeOptions.namespace` defaults to the empty string (current-daemon host mode).
Other deserialization defaults are keys `/etc/netcontrol/keys`, services state
`/var/lib/netcontrol/services`, no adopted parents, and all host/probe opt-ins
disabled. Unknown option fields are rejected. On non-Linux platforms,
`Native::open` fails explicitly; portable parsing tests do not imply native
networking support.

Linux compilation of the direct nftables dependency `rustables` requires
libclang and Linux UAPI headers at **build time**, not on the deployed appliance.
`rustables` declares `GPL-3.0-or-later`; review the complete dependency licenses
and distribution obligations before distributing a statically linked appliance.
No project release or licensing approval is implied here.

Production defaults enable both the `tls` service feature and `nftables`.
`--no-default-features` exists for source validation on cross-compilation hosts
without the C/header toolchain: TLS requests then fail explicitly and
`Native::open` always fails because nftables is essential. It is **not** a
functional networking build or a permissive firewall fallback.

## Firewall deny logging

The owned namespace-pinned NFLOG receiver reserves group 100 and runs inside
Rust; no ulogd, journal scraper or syslog dependency. Every managed input/forward
drop expression logs before its verdict; terminal log-and-drop rules cover chain
Drop defaults. Accept/ICMP/established precedence remains unchanged. Startup
refreshes the verified firewall compiler output through a durable recovery intent,
without allocating a configuration revision or adopting foreign rules.

The receiver copies at most 128 header bytes and persists only parsed metadata.
Private atomic rotating segments live at `native/deny-log` below services state.
At most 4096 records are retained, with a 100-record/second persistence cap;
overflow, sequence gaps, malformed input and cap discards are exposed explicitly.
Normal stop joins and flushes; abrupt termination can lose the current one-second
batch. Fatal I/O/capture errors stop collection and remain visible alongside
retained history until daemon restart. Invalid/unsafe saved logs fail startup
unchanged rather than silently resetting traffic history.

Require `CONFIG_NF_TABLES`, `CONFIG_NETFILTER_NETLINK_LOG`, `CONFIG_NFT_LOG`, `CAP_NET_ADMIN`,
exclusive group ownership and writable private storage. Standard Ubuntu
install/full-upgrade loads/persists `nf_tables`, `nfnetlink_log` and `nft_log`.
Counter expressions are included in current `nf_tables`, not a separate
`nft_counter` module.
See [deployment details](../../docs/BUILD_AND_INSTALL.md#firewall-deny-logging)
and [API/limitations](../../FRONTEND_SPEC.md#firewall-deny-log).

## Firewall rule counters

All owned physical nft rules include one counter after matching and before
logging/verdict/NAT, with bounded logical-key/install-generation userdata.
`GET /api/v1/statistics/firewall` aggregates address/family/port expansions
into exact decimal-string packet/byte totals for configured rules, defaults,
and generated bypasses. NAT counts initial mapping evaluations, not all flow
traffic. No changes to ordering, accept/drop decisions or connection tracking.

Reads check ownership/config/fingerprint before and after the scoped bounded
netlink dump, validate unique handles, one generation/counter per physical rule
and complete expected multiplicities. Only counter numeric values are zeroed
for drift fingerprinting; other expression bytes, identity and order remain
significant. Unsupported/malformed/drifted data fails explicitly.

The generation combines a fresh per-install UUID and kernel chain/handle set.
Native network apply/rollback, startup/service repair, compiler refresh and
reboot reset counts; simple backend reopen without repair preserves them.
Metadata-only changes can preserve them. Counters are not saved/restored or
included in aggregate statistics/MQTT. Existing native privileges and
`CONFIG_NF_TABLES` suffice; no external collector or new dependency.
See the [canonical API/reset contract](../../FRONTEND_SPEC.md#firewall-rule-match-counters).

## Native IPv4 BGP

The owned `nc-bgp` Rust worker implements bounded BGP-4 peering on interface-
bound TCP/179 with configurable ASN/router ID and keepalive/hold timers.
It advertises connected IPv4 networks from configured up interfaces and installs
selected received paths through netlink (main table, protocol 245, metric 200).
For WireGuard neighbors, an explicit peer key maps learned prefixes to effective
AllowedIPs, preserving static entries and refusing cross-peer prefix overlap.
Disconnect/withdraw/stop removes owned runtime additions. A durable private
ownership journal is recovered only after native namespace/scope validation;
learned state is not desired configuration or a revision.

Runtime status, process health, MQTT summary, restart and BGP-only route APIs
are described in the [canonical contract](../../FRONTEND_SPEC.md#native-ipv4-bgp).
Operators provide bootstrap routes/static AllowedIPs, TCP 179 input permits
and WireGuard underlay reachability. Existing native socket/netlink privileges
are required; no helper daemon, eBPF, installer package or automatic firewall
permit is added. IPv6, transit/learned-route exports, recursive next hops,
AS_SET/confederations, route reflection/refresh, graceful restart, BFD and
TCP authentication are outside this first implementation.

## Native mDNS

Native mDNS is a managed in-process UDP worker, not forwarding or an Avahi
wrapper. Apply stops/joins it before network changes and restores the previous
service set on failed startup. Verification checks its effective operational
configuration and running worker; a network-only apply must restart stopped
workers even when service settings are unchanged. Explicit repair, rollback
and boot reapply use the same lifecycle. Dedicated mDNS status reads the owned
worker snapshot directly, without requiring healthy network observation.
See [protocol and ownership boundaries](../netcontrol-services/README.md#implemented-services-and-boundaries).
No implicit nftables accept is inserted: local UDP destination port 5353 input
on selected LANs and independent unicast service permissions remain operator
responsibilities. Host-input rules currently cannot narrow the permit to only
the mDNS multicast destination; the worker enforces group/source/hop admission.
Actual VLAN, restrictive nftables/IPv6 MLD and appliance/reboot qualification
remain separate from the isolated veth fixtures.

## Global IPv6 policy

The persisted top-level `ipv6_enabled` switch defaults to true. Native startup
and transactional apply enforce `net.ipv6.conf.{all,default}.disable_ipv6` and
all current per-interface controls, including loopback/unmanaged devices, in
the managed namespace. Disabled is `1`; enabled is `0`. New devices inherit the
default. These are namespace controls, not host-global tunable opt-ins, and
cannot be supplied through the arbitrary-tunable allowlist.

IPv6 support and readable procfs controls are required. Required writes need
writable controls; absent controls or denied writes are explicit startup/apply errors. Proc writes
are read back and verified, including per-interface drift. IPv6 is enabled
before restoring configured addresses/routes and disabled after obsolete owned
IPv6 state is reconciled. Services stop/join before changes and restart with
IPv4-only resolution/export when disabled.

Durable native intents capture IPv6 controls and unmanaged address/route state;
same-boot rollback/re-enable restores it with elapsed address/route lifetimes.
Managed networking uses normal configuration reconciliation and Ethernet
snapshots. Changed/missing unmanaged interface identities fail explicitly.
Prior-boot transient snapshots are discarded on boot reconciliation rather than
resurrecting stale leases or writing to reused indexes. The policy is reapplied
when the daemon starts, not before: no sysctl.d file, bootloader change, module
unload, forwarding enablement or cross-namespace enforcement is introduced.

Use IPv4 management plus console access when disabling. See the
[canonical API/runtime contract](../../FRONTEND_SPEC.md#global-ipv6-policy).

## Native link diagnostics

An owned namespace-pinned Rust thread collects routing-netlink qdisc backlog/
drops, interface errors, established TCP socket diagnostics and filtered
AF_PACKET ingress TCP header observations. Runs independently of HTTP polling
and configuration transactions, retries errors, joins on drop, and never starts
helper processes or changes qdiscs/firewall/sysctls. No eBPF dependency.
Expose cached data through `/api/v1/statistics/link-diagnostics` and aggregate
`link_diagnostics`; the existing MQTT publisher includes it and local TCP sensors.
Forwarded TCP has observable advertised windows but no router-owned `cwnd`/RTT.
Receiver pressure is not link congestion; encrypted outer tunnel traffic cannot
expose inner TCP. All counters are ephemeral and capture loss/capacity/gaps are
explicit. Bounds, units, statuses and remaining limitations are in the
[canonical contract](../../FRONTEND_SPEC.md#native-link-diagnostics).
Ubuntu installation/full source upgrade loads/persists packet/TCP diagnostic
modules; [other deployment prerequisites](../../docs/BUILD_AND_INSTALL.md#native-link-diagnostics-prerequisites)
remain operator responsibilities.

## Host health sensors

Host performance sensors are separate from namespace networking statistics:
`GET /api/v1/statistics/host` reads procfs, sysfs and local `statvfs` data in
the daemon context, without entering a lab network namespace or mutating the
kernel. CPU/memory/load/uptime/VM/PSI, disk I/O, space/inodes and temperature/fan
sources fail independently. Collection does not load sensor drivers or probe
network/FUSE mounts. See [the full host-health contract](../../FRONTEND_SPEC.md#host-health-sensors)
for scope, exact decimal counters, bounds, supported filesystems and limitations.

## Conntrack connection snapshots

`GET /api/v1/statistics/connections` reads namespace-wide Linux conntrack state
using `NETLINK_NETFILTER`, not the `conntrack` executable or a supervised helper.
The HTTP API requires `state.read`; the daemon needs kernel conntrack support
and native netfilter read privileges in its configured namespace. Host mode
includes connections involving unmanaged devices and other firewall owners;
lab mode reads only that namespace. It does not require healthy service workers
or a successful configured-state observation, and does not mutate ownership,
firewall rules, connections, sysctls or desired configuration.

Original/reply tuples expose NAT addresses/ports, with protocol/TCP state,
status flags, mark, zone, nullable timeout/ID, and per-direction packet/byte
counts. Counts are exact decimal strings or null when accounting is absent.
This is neither a per-rule counter nor evidence of a current allow/drop verdict.
No rule association, packet capture or history API. Reads never delete state.

Ubuntu installation and full development upgrades load `nf_conntrack`, enable
and persist `net.netfilter.nf_conntrack_acct=1` and
`net.netfilter.nf_conntrack_checksum=1` in the host namespace. Other deployment
paths/namespaces require explicit operator setup before new connections are
created. See [host prerequisites and limitations](../../docs/BUILD_AND_INSTALL.md#conntrack-host-prerequisites).
The endpoint never enables accounting itself and does not retrofit counters onto
existing entries. No conntrack table flush is required or recommended.
Counter bytes are kernel connection accounting, not
application-payload or interface byte totals. See the
[canonical query/schema and frontend contract](../../FRONTEND_SPEC.md#conntrack-connection-snapshots).

Dump collection is capped at five seconds, 64 MiB and 100000 entries; individual
datagrams are capped at 1 MiB. Decode/serialization adds overhead. Filters run
after the full dump, so do not bypass those collection limits. Interrupted,
truncated, unsupported and permission-denied reads fail explicitly. Pagination
is over fresh live snapshots, not a consistent retained cursor. The daemon does
not explicitly load kernel modules, restart services or change accounting
configuration in this read path. Privileged Linux acceptance remains outstanding in this task's
[journal](../../docs/journal/2026-10-24.md#conntrack-connection-statistics-api).

## Conntrack state deletion

`DELETE /api/v1/connections` with exactly `{"confirm":true}` flushes the daemon
namespace's conntrack state. `DELETE /api/v1/connections/{id}` instead requires
the snapshot's family, protocol, zone and original tuple in its JSON body. Both
require `connections.delete`, native netfilter write privileges, no active
configuration transaction and no software-upgrade maintenance. Malformed/empty
item selectors never become a flush; stale ID+tuple+zone is `404`. Simulator and
non-Linux backends explicitly refuse destructive actions. See the
[canonical request/error contract](../../FRONTEND_SPEC.md#connection-state-deletion).

The in-process netfilter transport waits for a kernel acknowledgement and checks
its source, sequence and echoed request header. Target deletion binds original
tuple, family, protocol, ID and zone; supported targets are TCP/UDP/SCTP and
ICMP/ICMPv6 without differing directional zones. Collection deletion is unfiltered
and includes IPv4/IPv6/all zones and local/unmanaged/other-owner traffic in that
namespace. It never changes nftables rules, saved configuration, revisions,
ownership or accounting settings, and does not fabricate a deletion count.

This removes conntrack state, not application sockets: no TCP RST is sent and a
new handshake is not guaranteed. Packets can recreate state immediately; NAT or
management connections may be disrupted. This is irreversible operational work,
not transaction rollback. A timeout/disconnect can leave an unknown or partial
outcome; refresh rather than automatically retry. Do not flush to enable counters.

Portable selector/encoding/ACK tests and the isolated synthetic-UDP namespace
regression passed in Linux Docker. The latter checks stale-ID refusal, exact
deletion preserving another flow, full namespace flush, and unchanged ownership
and nftables fingerprint. It does not prove appliance TCP/NAT/IPv6 or browser
acceptance; see the [journal](../../docs/journal/2026-10-24.md#connection-state-deletion).

## Ownership and reconciliation

Host mode requires a valid stable `/etc/machine-id`. Its scope combines that ID
and the absolute native state location, and is retained across reboots. A private
`host-scope.json` binds that state to the namespace device/inode within each boot;
using it in another namespace in the same boot fails instead of resetting state.
This is not a portable machine/container identity or permission to move state
between namespaces. Explicit lab scopes remain boot/namespace-inode bound.
Adopted parents add a name/index/kind/MAC identity hash to lab scopes.
Every operation rechecks the pinned namespace identity. Parents are pre-created Ethernet,
veth or dummy links; their identity is checked before operations and they are
never configured, addressed, brought up/down, or deleted. Parent MTU/up changes
are reported as runtime information, not adopted configuration.

Managed links include preexisting `ethernet` (kernel device or veth), dummy,
802.1Q VLAN and kernel WireGuard links. Ethernet links must already exist;
the backend never creates/deletes them or changes their MAC. Explicit selection
permits admin up/down, MTU and static IPv4/IPv6 configuration. Before any mutation,
the intent durably stores the selected Ethernet interfaces' current identity,
MTU/up state and lossless kernel address messages; ownership retains the first
original snapshot while the link remains managed. Removal restores that original,
then releases ownership instead of deleting the link. Failed first adoption and
interrupted applies restore the per-operation snapshot even when no ownership
file had yet been saved. Identity checks use name/kind/MAC and, within the same
boot, interface index. Finite address lifetimes age during rollback; expired
addresses are not resurrected, and backward wall-clock changes cause an error
instead of extending a finite lease. External DHCP/network managers must not
race changes to selected interfaces.

Explicit initial provisioning inherits physical NICs into an otherwise unused core
journal with role `unassigned`; it does not recapture configured state. Handover
currently requires networkd/resolved and live finite DHCPv4 leases, preserving
client identity rather than persisting a lease as static configuration. The
private adoption receipt records original NIC snapshots/routes; matching per-NIC
networkd ownership files make those interfaces unmanaged before Netcontrol
starts its in-process clients. Existing OS/supplicant configuration remains.
See [installation prerequisites and acceptance limits](../../docs/BUILD_AND_INSTALL.md#automatic-physical-interface-inheritance).

Ownership exclusions are non-secret root-owned `0644` files so the
`systemd-network` service account can read them. Temporary files remain `0600`
while written, then become `0644` before fsync/publication; matched existing
receipt files receive the same readable mode on retry. This does not relax
private receipt/lease permissions. An unsuccessful ownership check includes the
observed administrative state, selected network file and expected override.

On restart, inherited host interfaces that remain in durable native ownership
have their identities checked and their networkd exclusions reasserted before
interrupted-operation recovery, DHCP startup or resolver publication. Missing
exclusions are recreated; conflicting files still fail explicitly. This prevents
resolved's `LinkBusy` failure after networkd has reclaimed an interface. Explicit
lab configurations and interfaces no longer managed are not handed over through
this restart path. It does not change saved addresses, DHCP settings or roles,
and it does not discard recovery intents.

Ordinary startup reads the core journal without initial inheritance. If an
already-owned host interface differs from the saved desired configuration,
startup reconciles it to that saved configuration after identity and ownership
checks. Live snapshots are captured only for rollback, never promoted to desired
configuration. Transaction observation/drift checks remain strict, and changed
foreign firewall tables, conflicting routes and unsupported kernel state still
fail explicitly. Explicit factory reset uses the same snapshot/intent machinery
to apply a replacement configuration selected by the local operator.

Native committed-configuration comparisons use the current typed operational
projection on both sides, not raw persisted JSON versus newly serialized defaults.
Daemon-owned `mqtt` settings and descriptive metadata do not describe native
network ownership; they remain in the core journal/API but are excluded from
native plans. MQTT-only edits therefore verify without native mutation, intent
publication or native service restarts. Reading ownership does not rewrite its
file. Unknown configuration fields remain rejected and substantive network
differences still fail the startup/reboot ownership guard.

If startup reports `reboot configuration does not match durable native ownership`,
do not delete the core journal, native ownership or recovery intents, reset the
appliance, or adopt its live configuration to bypass the check. Deploy the corrected
daemon through the normal upgrade path. Repeated `IFLA_INET6_CONF` size warnings
are distinct from this fatal comparison; inspect the final startup error if the
failure persists. Appliance-specific configuration/kernel differences still need
diagnosis rather than an automatic overwrite.

Top-level `dhcp_clients` and `dns` maps participate in core transactions and
interface authorization. DHCP addresses and routes are separate live lease
state, guarded by a shared lock during native verify/reconcile. DHCP routes use
protocol 243; static routes remain protocol 242. A lease-update intent protects
address/route/persistence convergence. Renewal, rebind, NAK, expiry, bounded worker
shutdown and restart are implemented using a locally patched Apache-2.0 mozim
engine; its optional second netlink implementation is disabled.

Enabled IPv4 static routes on a DHCP-managed interface depend on its valid,
matching lease. They remain in saved/returned configuration while suspended
without a lease; they are not installed or expected by native verification until
acquisition. Each lease update restores missing configured routes after installing
DHCP connected/gateway routes, with direct static routes before gateway static
routes. Lease loss removes only that interface's configured IPv4 static routes.
IPv6, other interfaces, disabled routes and unowned routes are not repaired by
this path. A pinned static gateway is never rewritten to the DHCP gateway:
an unreachable configured gateway or conflicting route produces an explicit error.
Routes are added without replacement, checked for ownership/conflicts and read
back; the existing lease intent and rollback also cover static restoration.
Route plans are rebuilt from current configuration on startup/recovery and
updated under the lease-state lock during transactions. Normal configuration
reconciliation rereads route presence after interface/address changes, because
the kernel may have removed routes during those operations. Reads remain
read-only and unrelated drift is not automatically overwritten.
Linux namespace tests cover these lifecycle paths, rollback and foreign-route
protection; physical-appliance DHCP/networkd/resolved acceptance remains separate.

Host handover still requires physical-appliance runtime acceptance. Restart handover-selection
regression tests cover owned/released interfaces and the lab/non-inherited
boundary; real networkd/resolved reboot and recovery acceptance remains required.

Removal from desired configuration restores the original NIC snapshot but does
not remove its persistent networkd exclusion or restart an OS DHCP client.
Do not treat deletion, daemon stop or binary rollback as an automatic OS-manager
hand-back. Preserve state and use console-assisted operator recovery.

VLAN dependencies
are created parent-first and removed child-first; identity changes recreate
affected descendants. Every managed link has an explicit `wan`/`lan`/`unassigned` metadata
role. Loopbacks remain read-only discovery, classified using the kernel loopback
flag rather than their name. They always report `role: "loopback"` and
`addressing_type: "static"`; other discovered links report null for both fields,
without inferring their managed role or address origin. Loopback role/kind and
DHCP settings cannot be submitted as managed configuration.
Global addresses are reconciled exactly; unmanaged link-local addresses
are left alone. New IPv6 addresses use NODAD for synchronous isolated-lab
verification. Desired addresses are static; managed DHCP lease addresses are
added only to the effective native view. Production DAD workflows are not
implemented. Existing addresses on unrelated interfaces are not reconciled.

Static configuration routes default to enabled when `enabled` is omitted;
explicitly disabled records stay in core
configuration but are excluded from the operational plan. Toggling reconciles
only owned routes, including rollback/recovery; inherited static routes start
enabled. DHCP runtime routes are unchanged.

The optional `blackhole` section names one deviceless drop target. Routes whose
`interface` equals that name are installed as kernel `blackhole`, `unreachable`
or `prohibit` routes (per its `action`) with no output device, no gateway and
universe scope, still protocol 242 in table 254 or 10000–19999. Verification
maps those route types back to the configured name; IPv6 kernel routes report
the loopback device, which is accepted. A deviceless route whose type no longer
matches the configured action is stale: it is removed and reinstalled, while a
pure rename with the same action leaves the kernel unchanged. A deviceless route
with a gateway or another device is drift. Foreign deviceless routes and initial
adoption are unaffected.

WireGuard peers default to enabled when `enabled` is omitted. A disabled peer stays
in core configuration and history but is excluded from the operational plan, so its
peer is replaced out of the kernel device on the next apply and absent from runtime
statistics; toggling reconciles only that interface's peer set (the device is
verified, then re-applied when it differs), including rollback and restart
recovery. Disabled peers do not count toward allowed-network overlap checks.

Routes use protocol 242 and table 254 (main) or tables 10000–19999. Policy rules
use priorities 10000–19999 and those same target tables. Outside validated
first-start inheritance, unowned kernel/DHCP/
operator routes are ignored, never replaced or explicitly deleted; a conflicting
destination/table/metric is an error before mutation. Owned routes are added
exclusively, not with a replace operation that could overwrite a foreign route.
Unmanaged interfaces are allowed and preserved; a new virtual-interface name
colliding with one is rejected. Unsupported owned route/rule attributes or rule
actions fail explicitly. Selected-link address/admin changes can inherently
alter the kernel's connected or autoconfigured routes on that selected link;
this is not a snapshot/restore facility for another routing/DHCP manager.

The initial handover explicitly retags captured static/DHCP routes and the
DHCP lease's matching kernel connected-subnet route. Keeping that subnet route
in lease state preserves gateway reachability when applying NOPREFIXROUTE.
Other kernel routes are not adopted through this exception.
Both DHCP-protocol routes and the captured matching kernel subnet route transfer
to protocol 243 and use lease-expiry checks; neither becomes a static 242 route.

The initial policy-rule check recognizes only standard local/main/default
priority/table pairs with no selectors or active flags. Linux's `u32::MAX`
suppression values mean disabled suppression and are accepted as default
metadata; active suppression and other attributes remain rejected. A rejection
includes the offending netlink rule and happens before ownership handover.

User-configurable source-policy rules are not supported. Enabled explicit gateway monitors
derive deduplicated `/32` IPv4 or `/128` IPv6 source rules, sorted by numeric source
address with priorities starting at 10000. Monitors sharing a source must share
its table. All traffic with that exact source is subject to the lookup.
Rules remain part of native drift detection, apply/removal, rollback and restart
reconciliation, but are absent from public configuration and API responses.
Private reboot snapshots preserve the observed rule subset in
`_monitor_policy_rules`; that field is rejected by the public configuration model.

DHCPv4 monitors (`mode: "dhcp"`) persist interface/target/settings, never lease
addresses or gateways. The in-process coordinator resolves a valid matching lease
on that interface, using longest destination prefix then metric, with no cross-WAN
fallback. Before a lease, probes wait with Unknown health; unusable paths are
unavailable/Unknown. A changed binding joins the old worker before clearing paths
and starting a new window; identical renewal preserves measurements. Lease updates
and monitor reconciliation share the DHCP state mutex. A 100 ms poll follows
completed lease changes; bounded kernel/worker operations add processing time.

Private tables/socket marks 20000..20063 and mark-plus-source-plus-output-interface
rules with priorities 9000..9063 are tagged protocol 244. Connected routes precede gateway routes; a
terminal unreachable default prevents fall-through. Foreign entries are not
overwritten. Reserved tagged paths are cleaned/rebuilt at configuration/recovery;
disable/delete/rollback/shutdown joins probes before path removal. Marks separate
multiple same-interface monitors, including identical targets, without redirecting
unmarked application traffic. No new public source-policy support, DHCPv6 or WAN failover.

The firewall owns only `inet/netcontrol`. Each update atomically replaces its
table, chains and ordered rules in one batch. It implements ordered forwarding
rules, host/interface policy expansion (4096 compiled-rule limit), established/
related acceptance for host policies, explicit host defaults, IPv4 ICMP acceptance
on input/output/forward when enabled, and IPv4/IPv6 egress masquerade. Interface
rules precede host-specific rules, and per-host defaults follow that host's
ordered rules. There are no implicit role-based policies.

The durable ownership file stores the firewall configuration and a lossless
read-only kernel fingerprint, excluding dynamic handles/use counts but including
chain policies, full expressions and ordering. Sets, objects and flowtables in
the owned table are rejected. An existing table without durable ownership is
never adopted. Fresh host startup with empty desired configuration performs only
verification/discovery and starts no firewall table. The first transaction owns
its table; failed first bootstrap removes it again. Explicit isolated-lab repair
can bootstrap the empty current firewall contract.

Sysctls use a strict per-scope allowlist, canonical bounded values, procfs
verification, and already-loaded congestion algorithms only. Original values are
captured durably before mutation. Removing desired keys restores their captured
values; retained original-value ownership remains drift-checked and is included
in `runtime.kernel_tunables` as `captured_original`. `effective` overlays desired
values on retained originals; `observed` is read from the relevant namespace.
Host-global settings require their explicit flag for observation and recovery
as well as writes.

A synced native intent records scope, before/after configurations, captured
kernel values and previous ownership before any mutation. Failures attempt to
restore the previous network, sysctls and services. An incomplete rollback leaves
the intent on disk and blocks successful recovery; opening the backend retries
that scoped rollback. Core-level rollback retries also accept an already fully
verified target, without relaxing the drift guard or changing unrelated state.
This is rollback-aware reconciliation, **not** an atomic whole-network update.

On a new host boot, startup repair can replay only the exact configuration saved
in durable native ownership. Core can also request a rollback before startup
repair (for example, an expired confirmation): its before configuration must
match durable native ownership, then native restores the requested target
directly without first replaying the expired candidate. Both paths check Ethernet identity, foreign-route
conflicts, existing virtual-link identity and firewall ownership. Current boot
link/address/route/rule/sysctl state is journaled before replay; failures restore
that captured state or retain the intent and fail closed. Absent owned virtual
links and firewall tables can be recreated. Existing conflicting firewall state,
unexpected owned routes/rules, or WireGuard state that cannot be verified are
errors, not an implicit reset/adoption. Same-boot drift is never treated as a
reboot. Reboot/power-loss behavior has not been exercised on Linux hardware.

Service workers are delegated to `netcontrol-services` through the fixed shared
`Services` interface. They are stopped before network edits and started after
convergence; edits can therefore interrupt enabled workers. Worker construction
and calls occur on the host thread, while networking operations use new,
short-lived namespace-pinned threads that restore their original namespace.
Failed enabled workers cause observation errors. Backend event lines are written
to the private services `backend.log`; see the services crate for its own exact
supported protocols and explicit restrictions.
Explicit service repair checks namespace/network/sysctl/firewall ownership
without requiring workers to be healthy, then restarts them. Failed workers
therefore remain repairable without weakening networking drift protection.

## Runtime, statistics and limitations

Destination rewrite uses exact-port prerouting DNAT in the owned inet table,
atomically installed with ordinary filtering and masquerade. A kernel FIB lookup
of the original destination/source/packet mark matches the selected WAN before
DNAT; ordinary routing then selects the local target's path. Requires nftables
inet FIB and NAT support (`nft_fib_inet`, IPv4/IPv6 FIB implementations, NAT/
conntrack), working forwarding and routes. Unsupported kernel expressions fail
the apply explicitly; modules are not loaded by the daemon.
Client IP/port are not changed, no filter accepts are inserted, local output
is excluded, and conntrack handles reverse translation. Targets must reply via
the firewall; same-subnet direct replies bypass reverse NAT. No automatic hairpin
SNAT is provided. Existing connections survive configuration edits/rollback.
See the [contract](../../FRONTEND_SPEC.md#destination-rewrite) and
[configuration example](../../examples/destination-rewrite.json).

- Runtime includes adopted parent availability/identity errors, service status,
  public WireGuard/peer handshake and byte statistics, and actual sysctl state.
  It never exposes private keys or invented process IDs.
- `Backend::discover_interfaces` returns a read-only array of real links:
  `name`, normalized `kind` (`ethernet` for device/veth), `index`, `mac`, `mtu`,
  `up`, all observed IPv4/IPv6 `addresses`, and `ownership`
  (`managed|unmanaged|loopback`). It does not require committed configuration
  verification and remains usable before adoption and when managed state drifts.
- `/api/v1/statistics`, `/api/v1/statistics/interfaces`, and
  `/api/v1/statistics/protocols` read routing-netlink 64-bit link counters and
  namespace-specific `/proc/thread-self/net/{snmp,netstat,snmp6}`. Integer counter
  values are decimal strings, including counters above JavaScript's exact range.
  `/api/v1/statistics/interfaces/<name>` selects a single interface.
  All query parameters are rejected explicitly.
  Link diagnostics and host/connection statistics have dedicated native collectors;
  other statistics paths are delegated to the services crate.
- `/api/v1/statistics/vnstat` delegates to the single host-wide v2 services traffic
  database without a scopes wrapper or managed-scope decoration. `/host` and
  `/managed` suffixes are removed. Per-interface namespace identities, calendar buckets, history,
  and decimal-string counters are preserved. Disabled, unavailable or
  not-yet-collected workers return explicit errors; history is never fabricated.
- Kernel and service drift currently returns an observation **error**, not a
  reconstructed differing `Config`. Core clients must handle the resulting
  unavailable/error response; no success-shaped desired state is returned for
  drift. Automatic firewall/link/route drift repair is deliberately refused;
  service repair operates only after network drift checks.
- WireGuard `listen_port=0` is explicitly rejected. A stable nonzero port is
  required for exact committed/effective comparison. DNS endpoints, userspace
  WireGuard, PSKs and fwmarks are not part of this contract.
- Transactional kernel forwarding toggles, module loading, namespace provisioning,
  unsupported netlink features, protocol-counter rate history,
  and arbitrary statistics query options are not implemented or silently enabled.
  Ubuntu installation now automatically assigns the first/second naturally
  ordered physical Ethernet ports as DHCPv4 WAN/LAN, uses `192.168.0.1/24` on
  LAN, permits all LAN input/forwarding, denies unsolicited WAN input, and
  masquerades LAN-subnet traffic exiting WAN. Explicit port/subnet overrides
  remain available. The persisted `firewall.input` uses the same owned table
  and atomic batch as forwarding/NAT, including loopback/stateful/DHCP exceptions.
  Daemon `--appliance`
  mode enables host IPv4 forwarding after native policy reconciliation on each
  startup. This is a deployment prerequisite, not an API tunable or a
  transactionally rolled-back setting. `ip_forward` can reset IPv4 devconf
  defaults; configure any required per-device hardening after that transition.
  IPv6 forwarding is not enabled; it has additional per-device/RA side effects.
  Named-value sysctl snapshots alone cannot promise safe rollback for these.
- Cross compilation is not evidence of packet forwarding, firewall/NAT
  semantics, host tuning, crash/power loss behavior, or real service
  interoperability. Destination rewrite has passed an isolated router/client/
  target namespace fixture for IPv4 TCP/UDP and IPv6 UDP forwarding, reverse
  translation, filtering, bypass, rollback/reopen and the 256-rule limit.
  See the [actual validation journal](../../docs/journal/2026-10-28.md#destination-rewrite).
  This does not qualify physical appliance connectivity, same-subnet operator
  return paths, reboot/crash recovery or unrelated privileged fixtures.

## Validation

Portable parser, validation, compiler-ordering and serialization tests:

```text
cargo test -p netcontrol-native --lib
cargo clippy -p netcontrol-native --all-targets -- -D warnings
cargo fmt -p netcontrol-native -- --check
```

Validation performed on the Windows development host:

- Portable native tests cover host defaults, Ethernet/VLAN/main-table validation,
  durable snapshot serialization, and existing native contracts.
- Full default-feature `x86_64-unknown-linux-musl` source/test checking and strict
  Clippy passed, including the nftables compiler and privileged test fixtures.
- Linux test executables were cross-linked, not executed. Linux-only key-file
  security tests and the privileged integration fixtures therefore remain
  unexecuted.

Cross-compilation checks, with the Linux C compiler/sysroot, UAPI headers and
libclang configured:

```text
cargo check -p netcontrol-native --target x86_64-unknown-linux-musl --tests
cargo clippy -p netcontrol-native --target x86_64-unknown-linux-musl --all-targets -- -D warnings
cargo test -p netcontrol-native --target x86_64-unknown-linux-musl --no-run
```

Opt-in Linux integration tests are marked `#[ignore]` and deliberately **fail**,
rather than silently skip, if the environment flag, Linux capabilities, mounted
namespace support or required kernel modules are missing:

```text
NETCONTROL_INTEGRATION=1 cargo test -p netcontrol-native -- --ignored
```

Lab tests provision and unmount only uniquely named fixture namespace mounts
under the crate's working directory. The host-mode fixture launches a child test
process and requires it to unshare a fresh network namespace **before** creating
links or opening host-mode `Native`; it never configures the invoking host.
It covers read-only discovery through drift, first-adoption failure, Ethernet
identity/static addresses/MTU/admin state, VLAN parenting, table-254 ownership,
foreign routes/unmanaged link preservation, durable interrupted apply, and a
simulated boot replay and pre-repair expired-candidate rollback (not an actual
machine reboot). Other fixtures cover dummy/VLAN/
WireGuard, addresses, routes, policy rules, firewall/NAT installation, sysctl
capture/removal restoration, restart, unmanaged-interface preservation, read-only
adopted parents, external firewall mutation, and interrupted-intent rollback.
