# Native Rust build and installation

## Packaging contract

Netcontrol uses its own signed `.ncpkg` format and the Rust
`netcontrol-package` executable. The signed-package installer does not use APK,
abuild, tar extraction, shell-driven installation, or an external package-manager
subprocess. The Ubuntu prebuilt installer below is a separate deployment path.
Alpine Linux remains a deployment target, using static musl executables and
OpenRC to start the single Rust daemon. No dnsmasq, chronyd, softflowd,
syslog-ng, or vnstatd service is installed or supervised.

Supported package targets:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`

Windows is a development/test target, not a native firewall or installation
target. Linux kernel tests require Linux and the appropriate privileges;
portable tests do not establish native networking readiness.

There is no approved release version. Cargo's `0.0.0` workspace value is
unassigned development metadata, not a release baseline. Artifacts are
identified by target, source commit, and content SHA-256.

## Build

Install stable Rust and the native compiler/linker for the selected target.
The native nftables binding dependency also requires libclang and Linux UAPI
headers at build time; Debian/Ubuntu provide `libclang-dev` and `linux-libc-dev`.
These are build dependencies, not supervised protocol programs.
For a native x86-64 Linux build with the musl development tools installed:

```sh
rustup target add x86_64-unknown-linux-musl
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked --target x86_64-unknown-linux-musl \
  -p netcontrold -p netcontrol-package
```

Use an aarch64 Linux host and the aarch64 target for ARM64 builds unless an
appropriate cross-linker is explicitly configured. Merely adding a Rust target
does not install a cross-architecture linker.

## Incremental Ubuntu development upgrades

[upgrade.sh](../upgrade.sh) builds the current checkout on an
Ubuntu amd64 firewall and replaces/restarts an installed `netcontrold.service`.
A missing service is an explicit error; use the fresh installer for provisioning.
Loaded services retain their unit and executable path. The script discovers that path from systemd's
effective `ExecStart` instead of assuming a fixed installation directory.
Exactly one direct, absolute executable named `netcontrold` is required;
wrappers, missing/ambiguous commands and symlink executables are rejected.
The destination may be absent on first installation. Masked/broken services,
conflicting unit files and unmanaged running daemons cause explicit errors.
The detected destination is printed before deployment. It does not use
Docker, wait for CI, fetch code, install prerequisites, overwrite an existing unit,
or explicitly modify credentials/configuration. The daemon loads and applies
its saved desired configuration, not the live NIC configuration. Missing native
journals are errors, not permission to inherit the host during upgrade. Live
snapshots are rollback evidence only; temporary recovery addresses may be removed
when saved configuration is applied. This is a development path,
not a signed-package installation or a substitute for full CI validation.

Install build prerequisites once:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential pkg-config libclang-dev linux-libc-dev util-linux \
  git curl ca-certificates sudo
```

If rustup is not installed, download and review the official installer, then
install Rust as the account that will build the code:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
# Review /tmp/rustup-init.sh before executing it.
sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable
. "$HOME/.cargo/env"
rustup toolchain install stable --profile minimal
rustup target add --toolchain stable x86_64-unknown-linux-gnu
```

Keep a persistent repository checkout on the firewall. Clone it once if needed
(private repositories require separately configured Git authentication):

```sh
git clone https://github.com/mayberryjp/firewall_backend.git
cd firewall_backend
```

For each iteration, update the checkout deliberately, review the changes, and
run the script as that same build account; it requests sudo for service control
and binary installation:

```sh
git pull --ff-only
bash upgrade.sh
```

The script runs `cargo +stable build --locked --target
x86_64-unknown-linux-gnu -p netcontrold` with incremental compilation enabled.
The debug-profile binary avoids release optimization time. Build outputs live
under `target/in-place-upgrade`, and Cargo's downloads remain in the account's
normal Cargo cache. Do not clean these between iterations. The first build is
expensive; dependency/toolchain changes can also trigger larger rebuilds.
Compiler memory/CPU load and the larger debug binary are development trade-offs.
The native GNU binary is built for this Ubuntu host, not a static distribution
artifact. Keep environment/toolchain settings consistent to reuse the cache.

Use `bash upgrade.sh --build-only` to compile and run the binary's
`--help` smoke check without sudo or a service restart. Failed builds/smoke
checks leave the running daemon untouched. A checkout-local lock rejects
concurrent invocations; do not run other installers or upgrades, including
from another checkout, at the same time.

For deployment, the script stages the new binary beside the destination,
saves `<installed-executable>.previous` if a binary exists (overwritten on each deployment),
stops the service, atomically renames the staged binary and starts the service.
It requires the unit to remain active across five one-second checks. Failed
restart/checks or catchable interruption trigger best-effort binary restoration.
Before recovery stops the replacement, the script prints the failed deployment
phase/exit code, systemd result/main-process exit status and the last 60 service
journal lines. Diagnostic-command failures do not prevent restoration. Review
these logs for sensitive runtime details before sharing them. For a failure from
an older script, inspect `journalctl -u netcontrold.service -n 100 --no-pager -o short-iso`
before retrying; the generic recovery message alone does not identify the cause.
A previously active service is restarted; a previously inactive service stays
stopped. With no previous binary, a failed first deployment removes the new
binary. A newly installed unit/directories remain for inspection and retry;
state and credentials are never deleted. Setup failures do not start the daemon.
Boot enablement is unchanged, including on first installation. Restoration
failure is reported explicitly. A power loss or
`SIGKILL` cannot be recovered automatically by shell traps.

Use a local console or the OS's independent SSH service, not netcontrold's
configuration SSH listener, which restarts with the daemon. Expect interruption
to managed networking/workers. The supplied unit runs native host mode, listens
on all interfaces at HTTP port 8080, and uses state/credentials under
`/var/lib/netcontrol`; restrict management access before deployment. If adopting
an existing binary with nonstandard state paths, review the supplied unit first.
Active systemd status is only a startup check:
verify the management API, logs and actual network connectivity afterward.
The new daemon can change persisted state during startup; binary restoration
does not undo those changes or guarantee an older binary can load that state.
Review persisted-contract changes and take protected, consistent backups before
deploying them. No backward-compatibility or automatic state reset is provided.

For manual binary recovery from the local console (state compatibility still
must be checked), set `installed` to the exact destination printed by the script.
The following example uses the repository installer's default destination:

```sh
installed=/usr/local/sbin/netcontrold
sudo systemctl stop netcontrold.service
sudo install -o root -g root -m 0755 "$installed.previous" "$installed"
sudo systemctl start netcontrold.service
sudo journalctl -u netcontrold.service -n 50 --no-pager
```

## Ubuntu prebuilt installation (amd64)

The repository provides [install.sh](../install.sh) for an internet-connected
Ubuntu amd64 systemd host. It installs prebuilt static musl binaries from a
successful, manually dispatched GitHub Actions build, not source code. No
Rust, Cargo, compiler, libclang or build headers are installed on the appliance.

There is no approved release or public release-download channel. After reviewing
distribution licensing, an authorized operator must run the existing Build and
test workflow with `upload_packages: true` on reviewed source containing these
changes. The installer needs that successful run's numeric ID. Uploads remain
disabled by default, including push/PR builds. No workflow is dispatched and no
artifact is published automatically by changing this code.

GitHub Actions artifacts require authentication even for public repositories.
Install/authenticate GitHub CLI for the account performing installation:

```sh
sudo apt-get update && sudo apt-get install --no-install-recommends -y gh curl ca-certificates
sudo gh auth login
```

Use an account with access to the repository's Actions artifacts. Never embed
tokens in download URLs or shell history. Download and inspect the installer
before running it as root. Once these changes are pushed and an approved build
has uploaded its artifacts, run from any directory, replacing `123456789` with
the actual successful workflow run ID:

```sh
curl -fL https://raw.githubusercontent.com/mayberryjp/firewall_backend/main/install.sh -o /tmp/netcontrol-install.sh && sudo bash /tmp/netcontrol-install.sh --run-id 123456789
```

Downloading fully before execution prevents running a partial response. For a
pinned installer replace `main` in its URL with the reviewed source commit.
Public raw access is required for that command; private repositories require
an authenticated download without credentials embedded in the URL.

The installer installs only `ca-certificates`, `gh`, `procps` and `curl` through APT,
checks the successful workflow's repository/path/event/commit, downloads
`netcontrol-ubuntu-amd64-<commit>`, verifies SHA-256 for the exact daemon and
unit files and installs `/usr/local/sbin/netcontrold`. Only `--run-id` is required.
The first physical Ethernet interface in natural name order is WAN and the
second is LAN (`eno1`, `eno2`, ...; `eno2` precedes `eno10`). Loopback, virtual
and Wi-Fi interfaces are excluded. At least two physical Ethernet ports are
required. Both `--wan WAN_NIC --lan LAN_NIC` may override selection; a partial
override is rejected. Selection does not depend on current addresses or the
current default route. Extra ports retain `unassigned` roles.
`--lan-address` defaults to `192.168.0.1/24` and must describe a usable host
inside an RFC1918 subnet with prefix length 8..30, entirely within private
space and not overlapping another interface or active DHCP lease. There is no
source-build fallback or `--ref` option. No checkout is needed.
Checksums detect corruption; authenticity relies on the reviewed source and
authenticated GitHub workflow/artifact channel, not an independently trusted
publisher signature. This is not a signed `.ncpkg` installation.
Artifacts expire after 14 days; missing/expired artifacts or failed/unapproved
workflow kinds cause an error rather than installing a different build.
The workflow's manual upload input is an operator approval gate, not proof that
licensing has been resolved. No release version is inferred from a run ID.
An already running daemon causes an explicit stop-and-retry error; the script
does not stop it for you. It installs the systemd unit and private directories
described below, provisions the appliance and starts/enables it. Existing
appliance journals, journal locks and appliance environment files cause explicit
refusal; they are never removed to force a reinstall. Existing compiler/toolchain
packages from prior source installs are not automatically removed.
The host must be running systemd, not merely have `systemctl` installed.

### Initial appliance provisioning

Use a local console and connect the selected WAN to an upstream network before
installation. Ubuntu must already provide supported networkd/resolved state;
the installer explicitly configures WAN as DHCPv4 even if Ubuntu initially used
a static WAN. A previously inherited DHCP identity is retained when available.
An upstream DHCP server must supply an IPv4 address and default route within
30 seconds after provisional application. NetworkManager and unsupported initial network
settings still fail explicitly; the installer does not convert OS managers.

The install-time root-only daemon invocation uses `--backend linux --appliance
--provision-wan WAN_NIC --provision-lan LAN_NIC --provision-lan-address LAN_CIDR`
with the installed state paths. It captures the initial physical NIC baseline,
then provisionally applies a normal durable configuration transaction. It
waits for WAN DHCP/address/default-route readiness and checks subnet overlap,
then confirms locally without waiting for remote confirmation. Failure attempts
an explicit transaction rollback; rollback errors remain explicit. This local
installer confirmation is deliberate; it is
not independent connectivity verification. The command exits after committing.
Configured roles/firewall, nonzero revisions and active transactions are refused.
Failures can leave durable handover/state evidence; inspect it from the console,
do not delete it or rerun installation as an assumed rollback.

The resulting configuration assigns WAN/LAN roles, replaces the LAN's addresses
with the selected static IPv4 address, removes LAN DHCP-client/DNS/static routes,
clears static WAN addressing/routes/DNS and configures a WAN DHCPv4 client.
The forward default is drop, with an unrestricted LAN-ingress allow-all rule
(no egress restriction), established/related return acceptance and no global
ICMP bypass. LAN-subnet IPv4 traffic exiting WAN is masqueraded. WAN DHCP
addresses/routes remain runtime state, not static copies. Competing default
routes on additional ports are rejected.

An explicit host-input policy defaults to drop for both IP families. It accepts
loopback, established/related replies, all traffic entering LAN, and WAN IPv4
UDP destination port 68 for DHCP. New WAN connections to the appliance,
including system SSH and packets addressed to its LAN IP, are denied. Local
output is unrestricted. These are Netcontrol-owned nftables rules, installed
atomically with forwarding/NAT and persisted in configuration, not a second
UFW ruleset. The policy is editable through configuration transactions;
removing it removes that input protection.

Installation writes root-only `/etc/netcontrol/appliance.env` with
`NETCONTROL_LISTEN=<LAN-IP>:8080`, then enables/starts the systemd service.
Appliance startup reconciles native policy first, then writes and verifies
`net.ipv4.ip_forward=1`. The unit selects this mode on every boot; no separate
sysctl file enables routing before the daemon has reconciled policy. Unprovisioned
LAN/WAN roles fail appliance startup. IPv4 forwarding remains enabled on daemon
stop; the owned kernel firewall/routes remain, while DHCP workers stop. This
is not a fail-closed supervisor or automatic forwarding-drift repair mechanism.
Changing IPv4 forwarding can reset kernel per-interface defaults; apply future
host-hardening settings after that transition. IPv6 forwarding is unchanged.

Installation checks HTTP readiness on the LAN address and IPv4 forwarding; it
does not establish end-to-end forwarding, upstream reachability or reboot safety.
LAN clients need static subnet addresses and the appliance as gateway. No LAN
DHCP server, DNS proxy, IPv6 router advertisements or IPv6 NAT is provisioned.
Complete onboarding from LAN immediately. HTTP is unencrypted; LAN clients are
trusted by the initial allow-all policy. WAN protection is provided by the input
policy, not merely the listener binding. No SSH authentication hardening or
broader OS-hardening/eBPF profile is installed.

For a source build, use `bash upgrade.sh --build-only`, install its binary/unit
as documented below, then run the same one-time provisioning invocation locally
with the full installed state paths before starting the appliance service.
The development upgrader is not a fresh-device provisioner.

### Ubuntu systemd service

The installer installs [netcontrold.service](../packaging/native/netcontrold.service)
at `/etc/systemd/system/netcontrold.service`. It creates root-only directories
`/var/lib/netcontrol`, `/var/lib/netcontrol/services` and `/etc/netcontrol/keys`.
The unit runs as root in native host mode, with private file creation (`0077`),
journald logging, restart on failure and a 60-second shutdown allowance.
It does not isolate the network namespace: native operations must reach the
host networking. The unit selects `--appliance` and the LAN-address management
listener from `/etc/netcontrol/appliance.env` (default `192.168.0.1:8080`).
Host services, API tunables, gateway monitoring and configuration
SSH remain disabled unless explicitly added to `ExecStart`.

Persistent paths match the manual Ubuntu startup command:
`/var/lib/netcontrol/native-state.json`, `/var/lib/netcontrol/credentials.json`
and `/var/lib/netcontrol/services`. Existing files are not deleted, reset or
imported from another state path. If you used different paths, retain them in
a reviewed systemd override before startup; do not accidentally onboard into a
new credential store.

The installed Ubuntu listener is unencrypted HTTP on the provisioned LAN address,
not the WAN address. Bare-daemon and Alpine defaults are separate contracts.
Keep console access and leave Ubuntu's Wi-Fi authentication under its existing
supplicant. Explicit first-install provisioning performs physical NIC inheritance
and ownership handover. Subsequent native host startup requires its saved journal
and applies that known configuration, not current interface settings. Startup can
change connectivity; it is not only an HTTP service start.

```sh
sudo systemctl start netcontrold
sudo systemctl status netcontrold --no-pager
sudo journalctl -u netcontrold -f
```

Complete onboarding at `http://<LAN-IP>:8080/`. The appliance installer already
enables boot startup; for a manual/source installation, enable it after provisioning:

```sh
sudo systemctl enable netcontrold
```

Use `sudo systemctl edit netcontrold` for operator drop-ins. To change arguments,
clear `ExecStart=` and supply the complete replacement command under `[Service]`;
then reload systemd and explicitly restart during a safe maintenance window.
The installer accepts an identical existing unit but refuses differing units
or symlinks rather than overwriting operator changes. Drop-ins are preserved.
The fresh appliance installer starts/enables the service after provisioning;
it is not an existing-appliance upgrade mechanism. If changing the LAN management
IP later, coordinate `/etc/netcontrol/appliance.env` and a service restart from
the console. API address changes do not rewrite the process listener binding.

For a previously installed binary without a unit, no rebuild is needed. After
the unit is pushed to GitHub, run the following only when no unit exists at the
destination (the checks refuse to replace one):

```sh
curl -fL https://raw.githubusercontent.com/mayberryjp/firewall_backend/main/packaging/native/netcontrold.service -o /tmp/netcontrold.service
sudo install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys
test ! -e /etc/systemd/system/netcontrold.service && test ! -L /etc/systemd/system/netcontrold.service && sudo install -m 0644 /tmp/netcontrold.service /etc/systemd/system/netcontrold.service
sudo systemctl daemon-reload
```

Stop any foreground instance using the same state before `systemctl start`.

### From an existing checkout

For an internet-connected Ubuntu amd64 server with `rustup` available through
APT (including Ubuntu 26.04), run the following from a trusted checkout's
repository root, not `/etc/netplan`. The initial check stops the command if the
daemon crate is absent. This installs compiler/linker tools, libclang, Linux
headers, CA roots, and stable Rust with the repository's rustfmt/clippy
components before building with the committed lockfile. Rust is installed for
the invoking user; use the same account throughout the build.

```sh
test -f crates/netcontrold/Cargo.toml && sudo apt-get update && sudo apt-get install -y build-essential pkg-config libclang-dev linux-libc-dev ca-certificates rustup && rustup toolchain install stable --profile minimal --component rustfmt --component clippy && rustup run stable cargo build --release --locked --target x86_64-unknown-linux-gnu -p netcontrold && sudo install -m 0755 target/x86_64-unknown-linux-gnu/release/netcontrold /usr/local/sbin/netcontrold
```

The explicit GNU target uses Ubuntu's native linker and does not require musl
tools. `rustup run stable cargo` does not depend on a shell restart or Cargo's
user-bin directory being on PATH. This is a manual source deployment of the
daemon only, not installation of a signed `.ncpkg`: it does not install the
package tool, OpenRC assets or a systemd unit, start/enable a service, or change
network configuration. The final command replaces any existing binary at
`/usr/local/sbin/netcontrold`; stop an existing daemon before replacing it.
Signed package ownership/recovery guarantees do not apply to this manual path.
Do not use Alpine's OpenRC startup commands on a standard systemd Ubuntu host.
Native startup requirements and management exposure warnings below still apply.

Wi-Fi configured through Netplan/networkd also needs Ubuntu's `wpasupplicant`
package. It is an operating-system connectivity prerequisite, not a Netcontrol
runtime dependency. If Wi-Fi is the only internet connection and the package
is absent, transfer it and its missing dependencies offline before running the
online build command. Netcontrol does not configure Wi-Fi authentication.

## Create a package

The package builder accepts static ELF64 Linux binaries, verifies their
architecture and executable load/entry bounds, and rejects dynamic ELF
interpreters or shared-library dependencies, including dependencies in an ELF
without an interpreter. Static PIE is supported. It includes:

| Installed path | Mode | Purpose |
| --- | --- | --- |
| `/usr/sbin/netcontrold` | 0755 | Rust daemon and embedded website |
| `/usr/sbin/netcontrol-package` | 0755 | Native package tool |
| `/etc/init.d/netcontrold` | 0755 | OpenRC service |
| `/etc/conf.d/netcontrold` | 0644 | Operator-managed daemon arguments |

Example on the build machine:

```sh
tool=target/x86_64-unknown-linux-musl/release/netcontrol-package
umask 077
"$tool" keygen --private-key signing.key --public-key signing.pub
"$tool" build \
  --daemon target/x86_64-unknown-linux-musl/release/netcontrold \
  --installer "$tool" \
  --target x86_64-unknown-linux-musl \
  --signing-key signing.key \
  --output netcontrol-x86_64.ncpkg
"$tool" verify netcontrol-x86_64.ncpkg --public-key signing.pub
```

Key files contain exactly 32 binary bytes, not PEM, JSON, or hexadecimal.
Key generation refuses to overwrite files and creates the private key with
owner-only permissions on Unix. Keep the private key offline/private and never
copy it to deployment artifacts. Establish trust in the public key through a
separate reviewed channel.

The format consists of `NCPKG001`, a little-endian manifest length, a strict
JSON manifest, the explicitly listed payloads, and an Ed25519 signature covering
all preceding bytes. Each manifest entry includes size, mode, and SHA-256.
Package size is limited to 256 MiB; manifest size to 64 KiB. The reader rejects
unsupported formats, targets, paths, permissions, duplicate/unlisted content,
truncation, modified payloads, invalid signatures, and dynamically linked
executables. It does not execute archive-supplied scripts.

## Install on Alpine

Copy the standalone `netcontrol-package` binary, `.ncpkg` file, and reviewed
public key to the Alpine machine. The package tool must match the machine
architecture. Do not treat an untrusted installer as safe merely because it
also receives a trusted signing key.

As root:

```sh
chmod 755 ./netcontrol-package
./netcontrol-package verify netcontrol-x86_64.ncpkg --public-key signing.pub
./netcontrol-package install netcontrol-x86_64.ncpkg --public-key signing.pub
```

Before starting native host mode, ensure `/etc/machine-id` contains a persistent
32-hex-character machine identity. Some minimal Alpine/container installations
do not provision it. On a **new machine with no assigned identity**, provision
one once as root, preserving any existing valid value:

```sh
if [ ! -s /etc/machine-id ]; then
  tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id
  chmod 444 /etc/machine-id
fi
rc-service netcontrold start
rc-service netcontrold status
```

Do not replace an existing identity to work around scope errors. In containers,
preserve the same machine-id file across replacement along with state/services
data. Missing, empty or malformed identity fails startup explicitly.

Installation does not start or enable services automatically. OpenRC must
already be available on the operating system. Package installation does not
configure a LAN address, routing, DHCP, or management firewall access.

The default listener is **HTTP on `0.0.0.0:8080`**, outside the managed network
namespace. Open `http://<machine-LAN-IP>:8080/` directly from your browser.
Create a device account, generate and save an **API key**, and finish setup.
No certificate or SSH tunnel is required.

The wildcard listener includes WAN-facing IPv4 interfaces if reachable.
HTTP sends passwords, session cookies, and API keys without encryption. TLS
remains an explicit optional daemon configuration. Management exposure is an
operator responsibility, not a consequence of configuring an interface as LAN.
An unclaimed device can be claimed by anyone able to reach its website.
Automatic clipboard access may be unavailable on HTTP LAN origins; select and
copy the one-time API key manually if necessary.

The package's OpenRC arguments select native host mode. Startup inventories the
host but does not automatically select NICs or create a usable firewall
configuration. Keep a console available, review the candidate and confirm live
connectivity before enabling unattended startup:

```sh
rc-update add netcontrold default
```

## Native host networking

The native backend manages the network namespace in which the daemon starts:
the appliance host on Alpine, or the container's own network namespace in Docker.
It does not require a separate managed namespace. Root/network-administration
privileges and kernel nftables/link support are required. It never reaches
through an ordinary container to control the Windows or Docker VM host.
Same-namespace native operations require `CAP_NET_ADMIN`; entering a different
lab namespace additionally needs namespace-entry privileges (`CAP_SYS_ADMIN`).
Raw probes/capture and host clock services require their own capabilities and
explicit opt-ins; network-administration access alone does not grant those.

The package supplies native-mode OpenRC arguments. For a manual deployment:

```sh
netcontrold_args="--backend linux \
  --listen 0.0.0.0:8080 \
  --state /var/lib/netcontrol/native-state.json \
  --credential-db /var/lib/netcontrol/credentials.json \
  --keys /etc/netcontrol/keys \
  --services-state-dir /var/lib/netcontrol/services"
```

Use `GET /api/v1/interfaces/discovered` or `show interfaces discovered` to inspect
actual links before making a candidate. Existing Ethernet/veth NICs use
`kind: "ethernet"`; their desired addresses, MTU, up/down state and role must be
explicit. `GET /api/v1/interfaces` remains managed configuration, not discovery.
Discovery itself never brings interfaces up/down or removes addresses.
Use main routing table `254` for ordinary host routes; reserved tables
`10000..19999` remain available for policy routing. Existing foreign routes
are not blanket-deleted. Initial physical-NIC inheritance is the explicit
exception described below; subsequent discovery is not an import operation.
Original and per-operation Ethernet snapshots protect selected static settings.
Changes intrinsic to selected addresses/admin state can affect kernel-connected
or autoconfiguration routes; this is not rollback of another DHCP/routing
manager's state. Stop competing managers on selected ports.

For an isolated lab, `--namespace NAME` explicitly selects an existing namespace;
the daemon does not create it. Use a distinct state/services directory for a
different scope. Simulator state is not native state; incompatible data is
rejected without deletion. Do not run competing interface/address managers on
NICs selected for Netcontrol management. Native DHCPv4 is in-process; DNS
publication uses systemd-resolved in host mode, not an embedded DNS server.

WireGuard private keys must already exist in the private key
directory. Add `--allow-host-tunables`, `--allow-host-services`, or
`--gateway-monitoring` only after reviewing their host-wide effects and
capabilities. Competing clock/logging services must not retain ownership when
the corresponding native workers are enabled. Syslog TLS needs system CA roots.
These opt-ins do not configure networking or enable services by themselves.
Host mode can interrupt the API/SSH connection while applying; use
`commit confirmed`, independent connectivity verification and console access.

See the exact [native ownership/prerequisites](../crates/netcontrol-native/README.md)
and [service restrictions](../crates/netcontrol-services/README.md). On a
disposable Linux host, validate packet forwarding, rollback, management
reachability, DHCP and collector behavior before enabling unattended native
startup. Cross-compilation is not that acceptance test.

## Automatic Physical Interface Inheritance

This unreleased implementation needs Linux build and console-assisted runtime
acceptance before deployment. No runtime acceptance is claimed by local Rust
syntax checks. Build first with `bash upgrade.sh --build-only` on Ubuntu amd64.

Explicit first-install provisioning seeds only a new journal, or an empty revision-zero
journal with no transaction history. Existing configurations are never reset or
recaptured. Lab namespaces and explicitly read-only adopted parents do not
participate. Physical detection requires a sysfs device, excluding loopback,
veth and virtual links. All eligible NICs are imported together, with role
`unassigned`; MTU/up state, supported static addresses/routes, DHCPv4 identity,
route metric and resolver settings are inherited.

Requirements: root, trusted persistent native/core state, stable machine identity,
running systemd-networkd and systemd-resolved. NetworkManager is currently
rejected. Every DHCPv4 NIC needs a live finite lease with its client identifier;
an unplugged/unleased DHCP NIC is an explicit startup error, not a static-address
fallback. Bridged/bonded ports, custom policy rules, active dynamic global IPv6
and unsupported networkd options are rejected before takeover. DHCPv6/SLAAC,
DHCP servers and Wi-Fi association configuration are not imported.

The daemon writes an adoption receipt under the private native state directory
and per-NIC `/etc/systemd/network/00-netcontrol-NAME.network` ownership files.
Those non-secret ownership files are root-owned and mode `0644`, readable by
networkd's unprivileged account. Adoption receipts and lease data remain private.
It reloads/reconfigures networkd through D-Bus and checks that each NIC is
unmanaged before taking ownership. A failed check reports `ADMIN_STATE`, the
selected `NETWORK_FILE` and the expected override path. No manager is globally disabled; original
Netplan/networkd and supplicant files remain. Caught handover failures attempt
snapshot/route restoration and remove only matching ownership files; failed
recovery retains its receipt for diagnosis/retry. Preserve both core and native
state; the ownership files alone are not a backup.

Netcontrold must remain running for lease renewal. Stopping/uninstalling it does
not hand IP ownership back to networkd; finite addresses eventually expire.
Do not revert to an older binary or remove ownership files while this daemon is
running. A console-assisted operator hand-back must stop the daemon, preserve
its state, remove only its matching per-NIC ownership files, and reload/reconfigure
networkd using the retained OS configuration. New leases may change addresses.

Operator acceptance: verify current connectivity and DNS before/after first
start, static and DHCP NICs, renew/rebind/NAK/expiry, daemon restart/reboot,
transaction confirmation/timeout rollback, foreign-route protection and an
interrupted handover. Confirm a second startup does not recapture the host.
Do not run the runtime checks over the sole management connection without a
console. Regression tests now cover saved-only startup and explicit reset;
privileged Linux acceptance remains required.

## Factory Configuration Reset

Use the local console: factory reset may immediately disconnect SSH and change
management addressing. It requires an installed Ubuntu amd64 service and a valid
saved core/native configuration containing the selected ports and native
ownership. It is not an identity reset or a repair tool
for corrupt journals. An active core transaction must be recovered or rolled
back before reset; native recovery intents remain authoritative and are replayed.

```sh
sudo bash reset.sh
```

Confirm with `y` or `yes` when prompted. Empty input, any other answer or EOF
cancels before host checks or changes. Use `--yes` only to skip confirmation for
unattended use. Optional paired `--wan`/`--lan` overrides select specific ports.
Omit both port arguments for the install defaults: first and second naturally
ordered physical Ethernet ports, excluding Wi-Fi/virtual links. LAN defaults to
`192.168.0.1/24`; `--lan-address` can explicitly select another valid private host
prefix. WAN becomes DHCPv4. The factory input/forwarding/NAT policy is the same
as installation. Other saved Ethernet interfaces are up, MTU 1500, unassigned,
without configured IPs, DNS or DHCP clients. VLAN/WireGuard, custom routes,
policy, service settings and tunable overrides are removed from current desired
configuration. Supplicant credentials/association definitions are not rewritten.
Re-enable Wi-Fi DHCP through a subsequent confirmed configuration if required.
Initial installation uses the same clean factory configuration builder; inherited
OS settings serve only as handover/rollback data before the initial transaction.

After confirmation, the script stops the daemon and writes a private backup under
`/var/lib/netcontrol/factory-reset.XXXXXX` before changing configuration. It uses
the installed binary by default, reinstalls the canonical appliance unit/binary,
sets the LAN HTTP environment, and starts/enables the service. Credentials,
API keys, WireGuard/SSH key files and transaction history are retained; the
current configuration is replaced through a locally authorized journaled reset,
not by deleting core/native state. Revision increments normally. Reset commits
once native verification succeeds; it does not wait for a WAN lease/default
route. An unplugged WAN must not undo the factory LAN recovery address.

Before invoking native recovery, reset moves the temporary Wi-Fi recovery file
`/run/systemd/network/00-00-wifi-recovery.network`, when present, into that private
backup as `wifi-recovery.network`. Otherwise its earlier filename can override
Netcontrol's networkd exclusion and prevent handover. Native handover reloads
networkd and reconfigures its owned links before checking that networkd has
relinquished them. This explicitly ends temporary networkd Wi-Fi DHCP ownership;
use the console. Symlink/non-regular recovery files are refused. Unrelated
networkd files are not disabled, and normal startup checks are unchanged.
The recovery file stays in the backup even if reset subsequently fails; restore
it manually only when intentionally returning Wi-Fi to networkd.

To build a reset-capable binary without first restarting a broken service:

```sh
bash upgrade.sh --build-only
sudo bash reset.sh --yes --wan eno1 --lan enp3s0 \
  --binary target/in-place-upgrade/x86_64-unknown-linux-gnu/debug/netcontrold
```

Failed reset applies use existing transaction/native rollback. A failure after
the reset transaction commits (for example, service/environment setup) retains
the committed factory configuration. The script leaves
the daemon stopped on failure and prints the backup location; it does not copy
backup journals over recovery evidence. Do not run reset/upgrade concurrently.
After success, reconnect at `192.168.0.1`, use the retained credentials, and
refetch desired state/revision before submitting any saved frontend draft.

## Optional configuration SSH server

Add `--ssh-listen 0.0.0.0:2222` to `netcontrold_args` to enable the daemon's
native SSH interpreter; add `--ssh-host-key /var/lib/netcontrol/ssh-host-key`
to select a persistent private Ed25519 host-key file explicitly. Otherwise the
key defaults to `<state>.ssh-key`. Keep this key stable and owner-only; invalid
existing data fails startup rather than being regenerated.

Connect with `ssh -p 2222 apikey@<appliance-IP>`, using an existing API key at the
password prompt after completing website onboarding. Scoped auth-file keys work
with their existing permissions. This does not use a device-account password or
spawn a system shell/sshd. SSH listens in the host management namespace and has
independent encrypted transport; optional SSH does not change HTTP defaults.

The CLI stages a private candidate, then applies/explicitly confirms it through
the existing complete-package transaction engine. It does not modify each
network setting immediately. See the [operator guide](CLI.md) for commands,
rollback, host trust, bounds and deployment acceptance. The package format and
four installed paths are unchanged.

## Package ownership and interrupted installation

The installer takes an exclusive lock under `/var/lib/netcontrol-package/`.
It records package ownership in `installed.json`, and writes a synchronized
`transaction.json` containing rollback data before replacing files.

- Existing unowned files or locally modified package files cause explicit
  failure; they are not overwritten.
- Identical package installation is permitted.
- Updates require the installed files to match their recorded checksums.
  Preserve a customized configuration outside the package transaction and
  explicitly review its deployment rather than expecting silent overwrite.
- The installer rejects symlinks in installation paths.
- Failed writes attempt rollback; rollback failure remains an explicit error
  and preserves recovery information.
- Interrupted installations block further installs until explicit recovery:

```sh
netcontrol-package recover
```

Recovery restores only the four package paths and the package receipt. The
installer never deletes/reset network state, account credentials, private
WireGuard keys, traffic history, or other application data. It does not
automatically import previous persisted schemas.

`--root <existing-directory>` installs/recoveries into an alternate filesystem
root for image construction and tests; installation is still Linux-only and
checks the package target against the running machine.

## Automatic builds

[CI](../.github/workflows/build.yml) checks Rust formatting, tests, clippy, and
builds on Ubuntu 24.04 x86-64, and runs privileged Linux integration separately
on the same runner platform. Windows and ARM64 jobs are not run. Successful
checks gate a single `x86_64-unknown-linux-musl` package build on Ubuntu; the
static daemon is also used by the Ubuntu amd64 prebuilt installer. Package
format support for other architectures does not imply CI coverage.
Artifacts contain the package, standalone installer, public key, commit/target
build information, and SHA-256 checksums.
The amd64 job also prepares `netcontrol-ubuntu-amd64-<commit>` with the static
daemon, systemd unit and strict binary-mode SHA-256 manifest. It uses the same
opt-in upload gate and 14-day retention. The Ubuntu bootstrap selects that
artifact by successful workflow run ID rather than installing OpenRC payloads.

CI generates a temporary signing key and retains only its public key. This
verifies consistency but is not a stable publisher identity: trust only
artifacts from a reviewed commit and the expected authenticated workflow.
Checksums alone do not establish authenticity. Package artifact upload is
disabled on push/PR and requires the explicit manual `upload_packages` input.
The native backend links `rustables` under GPL-3.0-or-later. No project
distribution license has been assigned; review combined-work licensing,
corresponding-source and notice obligations before distributing any binaries.
The implementation does not assign a new license on the user's behalf.
No signed package repository,
release, publication, device deployment, or automatic frontend notification
is performed.
