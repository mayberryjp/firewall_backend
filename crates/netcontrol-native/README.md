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

VLAN dependencies
are created parent-first and removed child-first; identity changes recreate
affected descendants. Every managed link has an explicit `wan`/`lan` metadata
role. Global addresses are reconciled exactly; unmanaged link-local addresses
are left alone. New IPv6 addresses use NODAD for synchronous isolated-lab
verification. Desired addresses are static; production DAD workflows are not
implemented. Existing addresses on unrelated interfaces are not reconciled.

Routes use protocol 242 and table 254 (main) or tables 10000–19999. Policy rules
use priorities 10000–19999 and those same target tables. Unowned kernel/DHCP/
operator routes are ignored, never replaced or explicitly deleted; a conflicting
destination/table/metric is an error before mutation. Owned routes are added
exclusively, not with a replace operation that could overwrite a foreign route.
Unmanaged interfaces are allowed and preserved; a new virtual-interface name
colliding with one is rejected. Unsupported owned route/rule attributes or rule
actions fail explicitly. Selected-link address/admin changes can inherently
alter the kernel's connected or autoconfigured routes on that selected link;
this is not a snapshot/restore facility for another routing/DHCP manager.

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
  Other statistics paths are delegated to the services crate.
- `/api/v1/statistics/vnstat`, `/api/v1/statistics/vnstat/host` and
  `/api/v1/statistics/vnstat/managed` delegate to the live services traffic
  database, preserving `{schema,scopes}` and adding the actual backend `scope`
  identity. Database scope names, per-interface namespace identities, history,
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
- Kernel forwarding toggles, module loading, namespace provisioning,
  unsupported netlink features, protocol-counter rate history,
  and arbitrary statistics query options are not implemented or silently enabled.
  Provision routing forwarding externally where required: `ip_forward` can reset
  IPv4 devconf defaults and IPv6 forwarding has per-device/RA side effects;
  named-value sysctl snapshots alone cannot promise safe rollback for these.
- Privileged Linux integration tests have **not** been executed. Cross compilation is not
  evidence of packet forwarding, firewall/NAT semantics, host tuning, crash/power
  loss behavior, or real service interoperability. In particular, the current
  native tests exercise kernel installation/observation and mutation drift;
  a multi-namespace packet-forwarding/NAT acceptance suite remains necessary.

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
