# Native Linux backend

This crate implements `netcontrol_core::Backend` through direct Linux syscalls,
routing netlink, WireGuard generic netlink, and atomic nftables netlink batches.
It never invokes `ip`, `nft`, `wg`, Go, a shell, or a service executable.
`wireguard-control` is always explicitly selected with `Backend::Kernel`; its
optional userspace-program backend is never selected.

## Operator requirements

- Linux with network namespace, dummy, VLAN, WireGuard, connection-tracking,
  nftables inet/filter/NAT/masquerade support provisioned by the operator.
- A pre-created **isolated** network namespace, explicitly supplied as
  `namespace`. A simple name resolves under `/run/netns`; an absolute path to
  a mounted nsfs network namespace is also accepted. Namespace symlinks,
  the caller's current network namespace, and PID 1's namespace are rejected.
  This crate neither creates nor deletes an operator namespace.
- Namespace-entry/network-administration privileges; host sysctl writes need
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

`NativeOptions` requires `namespace`; all other fields have deserialization
defaults: keys `/etc/netcontrol/keys`, services state
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

Scope identifies the boot ID and pinned namespace device/inode. Adopted parents
add a stable name/index/kind/MAC identity hash. Every operation rechecks that the
named namespace still resolves to that inode. Parents are pre-created Ethernet,
veth or dummy links; their identity is checked before operations and they are
never configured, addressed, brought up/down, or deleted. Parent MTU/up changes
are reported as runtime information, not adopted configuration.

Managed links are dummy, 802.1Q VLAN and kernel WireGuard links. VLAN dependencies
are created parent-first and removed child-first; identity changes recreate
affected descendants. Every managed link has an explicit `wan`/`lan` metadata
role. Global addresses are reconciled exactly; unmanaged link-local addresses
are left alone. New IPv6 addresses use NODAD for synchronous isolated-lab
verification. Address lifetime policy and production DAD workflows are not
implemented.

Routes use protocol 242 and tables 10000–19999. Policy rules use priorities and
tables 10000–19999. Foreign routes in these reserved tables, unsupported owned
route/rule attributes or rule actions, and unexpected non-adopted interfaces
cause explicit drift errors rather than takeover. Only reserved owned routes,
rules and explicitly managed links may be changed.

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
never adopted. An initially empty namespace can bootstrap only the empty current
firewall contract; arbitrary existing networking is not adopted.

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
- Kernel forwarding toggles, module loading, namespace provisioning, physical
  link takeover, unsupported netlink features, protocol-counter rate history,
  and arbitrary statistics query options are not implemented or silently enabled.
  Provision routing forwarding externally where required.
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

- All 15 portable native tests passed; strict Windows Clippy and formatting passed.
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

Tests provision and unmount only uniquely named fixture namespace mounts under
the crate's working directory, never host networking. They cover dummy/VLAN/
WireGuard, addresses, routes, policy rules, firewall/NAT installation, sysctl
capture/removal restoration, restart, unexpected-interface drift, read-only
adopted parents, external firewall mutation, and interrupted-intent rollback.
