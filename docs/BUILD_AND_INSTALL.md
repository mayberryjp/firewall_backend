# Native Rust build and installation

## Packaging contract

Netcontrol uses its own signed `.ncpkg` format and the Rust
`netcontrol-package` executable. The signed-package installer does not use APK,
abuild, tar extraction, shell-driven installation, or an external package-manager
subprocess. The Ubuntu prebuilt installer below is a separate deployment path.
Alpine Linux remains a deployment target, using static musl executables and
OpenRC to start the single Rust daemon. No dnsmasq, chronyd, softflowd,
syslog-ng, or vnstatd service is installed or supervised.
Native syslog is the exception to OpenRC support: it requires systemd/journald
socket activation. Keep `syslog.enabled=false` on non-systemd deployments.

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
Full installation/upgrade also enables native host services and gateway probes
through the managed systemd environment drop-in described
[below](#enabling-gateway-monitoring-on-an-installed-appliance), without rewriting
the base unit or custom startup arguments. Build-only runs do not change it.
They also [configure journald forwarding](#host-logging-ownership) for native syslog.
Full install/upgrade enables the embedded configuration SSH listener on
`0.0.0.0:2222` through `NETCONTROL_SSH_LISTEN`; no second process or OpenSSH
package is started. Explicit `--ssh-listen` arguments take precedence. Review
current host-input firewall reachability before upgrading; the script does not
open ports or change saved input policy. See
[SSH overrides](#optional-configuration-ssh-server) for custom binding or disable.
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
  git curl ca-certificates sudo procps kmod
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

Full deployment runs the installer's shared conntrack, native link-diagnostics and appliance-service
permission setup, then reloads systemd as root after the build and service-path
check, before staging/replacing/stopping the daemon.
Keep `install.sh` beside `upgrade.sh` from the same reviewed checkout.
`--build-only` performs no conntrack/diagnostics/service setup or host changes. See
[conntrack host prerequisites](#conntrack-host-prerequisites) for persistence,
failure limitations and accounting behavior.

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

### Startup reports a state checksum mismatch

Preserve the saved state and a protected, consistent backup; do not delete it,
recalculate its checksum, run factory reset or import live NIC settings to make
an upgrade start. A bug in the loader verified checksums after decoding into
current Rust types. New fields such as `ipv6_enabled` could therefore change
the bytes being checked and falsely reject an unchanged journal. The corrected
loader verifies the saved JSON payload before typed decoding and does not write
the file during verification. Rebuild from source containing this fix before
retrying the ordinary upgrade. Actual checksum corruption and incompatible
payloads still fail explicitly; this is not automatic state repair/conversion.

Repeated `IFLA_INET6_CONF` warnings about 236 versus 240 bytes come from the
older netlink decoder encountering extra kernel data; they are separate from
the fatal state checksum error. This fix does not upgrade or silence that
dependency. If systemd reports changed units/drop-ins, run
`sudo systemctl daemon-reload` before retrying. Check
`sudo systemctl status netcontrold.service --no-pager` and its journal after
binary recovery; a restoration message alone does not prove service health.

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

## Offline Date-Revision State Conversion

If deployment reports `incompatible state schema "netcontrol-rust-state-v1"`,
the saved journal still uses numeric revisions. The daemon requires date-based
v2 state. IPv6 `IFLA_INET6_CONF` size warnings are separate and do not cause this
schema failure. Do **not** delete configuration or rename the schema string:
transaction bases, committed revisions and restore provenance must also change.

The explicitly authorized `netcontrol-state-convert --date-revisions` operation
converts valid numeric v1 state offline, preserving desired configuration and
every historical transaction/configuration. It uses initialization/commit UTC
dates and the current date-version allocator, mapping numeric revision 0 to the
initial date's iteration 1. Subsequent commits increment on the same UTC day or
start at iteration 1 on a later day. Transaction IDs, actors, statuses and
timestamps remain; base/committed/restore revision references become strings.
The preview and private backup manifest include the exact revision mapping.
No old numeric aliases, normal-startup compatibility path or automatic reset
is introduced. Already-v2 input with this flag is rejected.

Use the reviewed updated checkout on the appliance and a local console or
independent OS SSH. Inspect the effective unit paths first; examples below use
the supplied unit's defaults. Build before stopping, then preview offline:

```sh
bash upgrade.sh --build-only
sudo systemctl stop netcontrold.service
sudo target/in-place-upgrade/x86_64-unknown-linux-gnu/debug/netcontrol-state-convert \
  --state /var/lib/netcontrol/native-state.json \
  --services-state-dir /var/lib/netcontrol/services --date-revisions
```

Preview never writes source data. Review the mapping and affected file paths
privately. A valid preview can then be applied with a **new** private backup
directory (the command prompts for `CONVERT`):

```sh
sudo target/in-place-upgrade/x86_64-unknown-linux-gnu/debug/netcontrol-state-convert \
  --state /var/lib/netcontrol/native-state.json \
  --services-state-dir /var/lib/netcontrol/services --date-revisions \
  --apply --backup-dir /var/lib/netcontrol/date-revisions-backup
bash upgrade.sh
sudo systemctl status netcontrold.service --no-pager
sudo journalctl -u netcontrold.service -n 50 --no-pager
```

Keep the service stopped between conversion and installing the matching new
binary. Do not start the previous binary against converted v2 state. Because
the upgrade starts from a stopped service, a failed deployment leaves the old
installation stopped rather than claiming a working rollback. If replacement
startup fails, stop it, preserve diagnostics, restore **all** originals from the
conversion bundle as described below, and only then start the matching previous
binary. A binary rollback by itself does not roll back this offline conversion.

The shared converter holds journal/native locks, verifies original checksums,
validates all history and current native ownership/adoption, backs up every
affected file before publication and refuses changed sources. It rejects active
transactions/native intents, incomplete history, backward UTC commit dates,
unknown fields, nonempty retired policy rules and scope/config mismatches.
Finish/recover pending work with the previous binary first; do not bypass the
checks or discard history. The same explicit operation can remove **empty**
retired `policy_rules` fields if present; it never removes nonempty rules.
Credentials, host identities, service counters and unrelated files are not reset.
See the [shared backup/publication/recovery details](#offline-policy-rule-state-conversion).

## Offline Policy-Rule State Conversion

The explicitly authorized `netcontrol-state-convert` tool removes retired empty
`policy_rules` arrays from an otherwise valid saved Rust journal and its native
metadata. This is an operator-run exception, not a normal startup/API/import
compatibility path. It does not reset configuration, import live networking,
repair corrupt checksums, stop/start services or change the kernel.

Build the tool from the reviewed current checkout **before** stopping the daemon:

```sh
CARGO_TARGET_DIR=target/in-place-upgrade cargo +stable build --locked \
  --target x86_64-unknown-linux-gnu -p netcontrold --bin netcontrol-state-convert
```

Use a local console or independent OS SSH, never Netcontrol's own SSH listener.
Review the effective unit/state paths, ensure no manual/self-upgrade worker or
other state writer is active, then stop the daemon. These are the supplied
Ubuntu unit's defaults; substitute the effective paths if customized:

```sh
sudo systemctl stop netcontrold.service
sudo target/in-place-upgrade/x86_64-unknown-linux-gnu/debug/netcontrol-state-convert \
  --state /var/lib/netcontrol/native-state.json \
  --services-state-dir /var/lib/netcontrol/services
```

No `--apply` means **preview only**: JSON lists exact snapshot locations, removed
rule counts and affected file paths. It may create adjacent lock files, but does
not change source state or create a backup bundle. Reports can contain transaction
IDs/file paths; keep them private. The main journal's original checksum must be
valid. Inputs and immediate parent directories must be private, owned by the
invoking user (normally root), and free of symlinks; files cannot be hard-linked.
Do not change permissions blindly or share state/backup contents.

Conversion refuses active core transactions, native `intent.json`, incomplete
adoption, scope/configuration mismatches, invalid history/unknown fields, duplicate
JSON keys and **any non-empty `policy_rules` array**, including historical ones.
Do not bypass these checks. Review/decommission current source routing with the
previous binary; non-empty archived rules need a separately reviewed conversion
plan, not history deletion. View filters/normal firewall policy are unrelated.

After reviewing a fully valid empty-rule preview, use a **new** backup directory:

```sh
sudo target/in-place-upgrade/x86_64-unknown-linux-gnu/debug/netcontrol-state-convert \
  --state /var/lib/netcontrol/native-state.json \
  --services-state-dir /var/lib/netcontrol/services \
  --apply --backup-dir /var/lib/netcontrol/policy-removal-backup
```

Type `CONVERT` to confirm; empty/other input cancels. `--apply --yes` is an explicit
unattended confirmation; never put it on an unreviewed command. Without
`--backup-dir`, apply chooses a unique sibling directory beside the main journal.
An existing backup directory is refused rather than reused/overwritten.

The tool holds the normal journal/native locks through confirmation and apply.
It converts only `desired`, every transaction's `previous`/`candidate`, native
`ownership.json`'s `committed_config`, and optional `adoption.json`'s `config` and
`ownership_before.committed_config`. Native operational snapshots are re-encoded
using the current operational model. Other fields, credentials, service counters,
Ethernet/IPv6 recovery evidence and key material are not edited. Transaction IDs,
revision identifiers, statuses, provenance and timestamps remain; archived configuration
payloads are intentionally converted, with exact originals retained in backup.
The separate explicit `--date-revisions` operation described above additionally
rewrites revision identifiers/references; its manifest operation is `date-revisions`.

Before replacing any source file, the private bundle contains `manifest.json`,
numbered `*.original` byte-for-byte backups and `*.converted` replacements, with
SHA-256 values and absolute original paths. Files are 0600 and the bundle 0700;
files and directories are synchronized. Publication uses adjacent staging plus
atomic rename per file, **not an atomic transaction across all files**. A
`completed` marker is written only after all replacements have been synchronized.

If conversion errors/is interrupted or the marker is missing, **do not start the
daemon or rerun upgrade blindly**. Preserve the whole bundle; inspect its manifest
privately and restore **all** numbered originals to their recorded paths with
0600 permissions from the stopped/offline state, then use the matching previous
binary. Never restore only the main journal or recompute hashes to force loading.
Adjacent `.conversion-*` staging files from interruption are not live state; keep
them for inspection. Backups are never automatically deleted. There is no automatic
multi-file rollback or boot recovery in this operator tool.

After successful conversion, keep the bundle and run the ordinary `bash upgrade.sh`
from this fixed checkout. If systemd warns about changed units, first run
`sudo systemctl daemon-reload`. Since the service was stopped, explicitly start it
after deployment with `sudo systemctl start netcontrold.service`, then inspect
status/journal, API data, saved configuration and connectivity. The tool itself
does not deploy a binary or prove appliance startup/network health.

## Native link diagnostics prerequisites

Linux native mode continuously collects qdisc/socket diagnostics and bounded
plaintext TCP headers in Rust; no external collector or eBPF runtime is required.
Ubuntu `install.sh` and full `upgrade.sh` run the shared
`configure_link_diagnostics` before provisioning/replacing the daemon. It loads
`af_packet`, `inet_diag`, `tcp_diag` (built-in implementations are valid) and
persists those names in root-owned mode-0644
`/etc/modules-load.d/netcontrol-link-diagnostics.conf`. Symlink/non-regular
targets are refused; unrelated module files are preserved. Missing modules,
commands or persistence errors abort deployment before daemon replacement.
Already-loaded modules/host prerequisites are not rolled back on later failure.
`--build-only` does not load modules or modify the host.

Kernel requirements are `CONFIG_PACKET`, `CONFIG_INET_DIAG`,
`CONFIG_INET_TCP_DIAG`, routing-netlink qdisc statistics and IPv4/IPv6 socket
diagnostics. The existing root daemon needs CAP_NET_RAW; entering a separate
network namespace also needs appropriate SYS_ADMIN permissions. Restricted
containers/capability overrides must allow the corresponding sockets/setns.
Neither script enables unprivileged BPF, installs BCC/bpftrace/ss/tc collectors,
mounts tracefs/bpffs, or weakens AppArmor/lockdown. No reboot is normally required.
No API or collector-side host sysctl/module mutation is added.

Other deployment paths (signed packages, HTTPS self-updates, OpenRC/manual binaries)
require operator-provided kernel support/modules. Missing support produces an
explicit unavailable diagnostic sample with retries, not a healthy zero, service
crash or configuration-write lock. Verify with authenticated
`GET /api/v1/statistics/link-diagnostics` or
`show statistics link-diagnostics`, and generate real traffic. Runtime collection
is approximately one second; MQTT retains its configured publication interval.
Do not treat lack of TCP sockets on a forwarding router as a missing collector:
local TCP diagnostics and forwarded packet-header coverage are distinct.
See the [canonical measurement/limits contract](../FRONTEND_SPEC.md#native-link-diagnostics).

## Conntrack host prerequisites

The Ubuntu fresh installer and full development upgrade load `nf_conntrack`,
apply and read back these host-network-namespace settings before provisioning
or replacing the daemon, and persist them across boot:

| Setting | Value | Purpose |
| --- | --- | --- |
| `net.netfilter.nf_conntrack_acct` | `1` | Per-direction packet/byte accounting for new connections |
| `net.netfilter.nf_conntrack_checksum` | `1` | Validate incoming checksums during connection tracking |

Root-owned, mode `0644` files are installed at
`/etc/sysctl.d/90-netcontrol-conntrack.conf` (the two settings) and
`/etc/modules-load.d/netcontrol-conntrack.conf` (`nf_conntrack`), so systemd can
load the module before boot-time sysctls. These Netcontrol-owned files are
replaced on each install/full upgrade; symlinks and non-regular destinations
are refused. Unrelated configuration files are not rewritten. Later-sorted
operator sysctl files can override these settings at boot; resolve conflicts
deliberately and check the effective values after reboot.

`kmod` supplies `modprobe`; `procps` supplies `sysctl`. Fresh installation installs
both. Existing installations need both available before a full upgrade; the
upgrade does not install packages. Missing commands/module/kernel support,
failed writes/readback or persistence errors abort before daemon replacement or
fresh provisioning. Host changes are not a multi-file/kernel transaction: a
failed setup can leave already-applied settings or a configuration file, and
later deployment failure does not undo these prerequisites. Inspect the error
and retry after correcting it. Do not unload conntrack or flush connections as
recovery. Saved desired configuration, credentials and revision history are not
reset by this setup.

Accounting is not retroactive. Existing entries can retain null counters until
they expire naturally; generate new traffic to verify counters. It adds
per-connection memory overhead. No table flush or reboot is needed for new
connections to receive accounting after successful setup. Verify on the host:

```sh
sysctl net.netfilter.nf_conntrack_acct net.netfilter.nf_conntrack_checksum
```

The profile leaves table capacity/hash sizing, timeouts, TCP loose/liberal
tracking policy, automatic helpers, event delivery and timestamp extensions
unchanged. Capacity/timeouts require workload and RAM sizing; events/timestamps
are not needed by the current dump-based API. It never enables automatic
helpers or relaxes TCP validation. Other deployment paths and isolated network
namespaces require explicit operator setup in the appropriate namespace; the
read-only connections API never changes these settings itself. No package,
daemon-startup, factory-reset or browser hook is added by this shell setup.

## Ubuntu Self-Upgrade

Optional self-upgrade supports Ubuntu amd64, root-run `netcontrold.service`,
and the Linux host appliance backend only. It downloads a specific GitHub release
from an operator-configured repository; requests cannot supply URLs, repositories,
keys, tokens, installation paths, scripts or force/downgrade flags. This is a
daemon-binary update, not an OS/package update or `.ncpkg`/OpenRC installation.
It does not build source, invoke Git/APT, replace the main service unit, or reset
configuration, credentials, keys or revision history. There is no approved
release baseline or published update channel established by this change.

### Trust and Bootstrap

Ubuntu self-updates use the fixed GitHub repository over verified HTTPS, **without
publisher signatures**. SHA-256 checks consistency with the same-source manifest,
not independent authenticity. Compromise of the trusted GitHub repository/account
can supply an accepted executable. This user-selected trust model does not change
the separate signed `.ncpkg` package format.

Fresh `install.sh` and source `upgrade.sh` runs automatically create or validate
root-owned mode `0600` `/etc/netcontrol/updates.json` and enable
`NETCONTROL_UPGRADE_CONFIG=/etc/netcontrol/updates.json` in the managed service
drop-in. Source upgrades run the staged new daemon's bootstrap **before stopping
the previous service**; bootstrap failure aborts replacement. The helper is:
`netcontrold --configure-updates /etc/netcontrol/updates.json`. It exits without
starting a daemon, fetching releases or changing saved networking. It creates
the following defaults only when the file is absent:

```json
{
  "repository": "mayberryjp/firewall_backend",
  "token_file": null
}
```

For private repositories, `token_file` is an absolute path to a root-owned mode
`0600` file containing a GitHub token with read-only repository release access.
Never include its value in API requests, URLs, documentation or logs. Public
releases need no token. Configuration/token ancestors must be root-owned,
not writable by other users and not symlinks. Do not put them in temporary or
user-writable directories. Unknown configuration fields are rejected.

Existing valid configuration is preserved byte-for-byte, including custom
repository/token paths. Existing invalid, unsafe, symlink or hard-linked files
are rejected, not reset. The current schema contains only `repository` and
optional `token_file`: remove a former `public_key` field explicitly before
deployment; do not delete unrelated key files or change a pending worker's
configuration. Finish/recover active upgrades using their matching binary first.
No signing key, signature asset or key-generation setup is needed.

Manual/custom deployments can set `--upgrade-config PATH` explicitly; a command
line value takes precedence over the service environment. The managed drop-in
does not replace existing unit arguments/state paths. Restart from an independent
OS SSH session/local console. Invalid/unsafe configuration fails startup
explicitly. Without the option/environment, installation stays disabled (but
release discovery works independently). A simulator/lab namespace cannot enable
installation. `--build-only` makes no service/configuration changes. Keep `kmod`
and `procps` installed. Successful API upgrades apply/persist the same conntrack
accounting/checksum prerequisites as the shell paths before binary replacement;
those host prerequisite changes are not rolled back on later failure.

### Release Assets

Public software versions are canonical `yyyy.mm.dd.iteration`: a real UTC date,
zero-padded month/day, and iteration 1..4294967295 without leading zeroes.
The embedded source version is `RELEASE_VERSION` in
[version.rs](../crates/netcontrol-core/src/version.rs); the first assigned build
label is `2026.10.29.1`, not a claim that a release has been published.
Substantive code changes advance that build label once per task. Cargo's
three-part package version is internal, not software identity.
Publication still needs explicit approval. Use the embedded version from the
daemon being published. No prerelease/build suffix or `v` prefix is accepted in
manifests/API bodies; the GitHub tag adds `v` to that exact version.

Build the daemon as a static amd64 Linux musl executable and use the package
tool's offline asset builder on the publishing machine:

```sh
daemon=target/x86_64-unknown-linux-musl/release/netcontrold
version="$("$daemon" --version)"
version="${version#netcontrold }"
netcontrol-package build-update \
  --daemon "$daemon" \
  --version "$version" \
  --output-dir ubuntu-update-assets
```

The output directory must not already exist. The command validates the static
ELF and creates exactly these assets; it does not upload, tag or release:

- `netcontrold-ubuntu-amd64`: executable, maximum 256 MiB.
- `netcontrol-ubuntu-amd64.json`: strict manifest, maximum 4096 bytes, containing
  `schema: 1`, `version`, `target: "ubuntu-amd64-systemd"`, numeric `size` in bytes
  and lowercase hexadecimal `sha256`.

No `.sig` is produced or required. `build-update` has no signing-key argument.
The existing manually gated build workflow prepares these same two assets in
`netcontrol-ubuntu-updates-<commit>`; it does not create a release or publish them.

Upload those two files to the approved, non-draft release in the configured
repository using a separate authorized publication workflow. The daemon uses
GitHub's HTTPS release/asset API, including private-release authentication when
configured. It checks the tag, unique asset names/sizes, manifest version/target,
binary size/digest/ELF, replacement `--help` support for `--upgrade-config` and
exact embedded `--version` match before installation. HTTPS certificate verification stays enabled; credentials
are sensitive headers, not URLs, and are not forwarded to a different redirect
host. Requests have 15-second connect and 300-second per-request total timeouts,
at most five HTTPS redirects and bounded response bodies. No release is
published by enabling this feature.

### Request, Status and Recovery

Use an API key with `system.upgrade` to submit JSON:

```http
POST /api/v1/system/upgrade
Authorization: Bearer <API_KEY>
Content-Type: application/json

{"version":"2026.10.29.2"}
```

`202` acknowledges a durable queued job, not successful verification/installation.
`Location` is `/api/v1/system/upgrade`; poll `GET` there with `state.read`.
The API retains the latest job only. It exposes `last_successful_version`, not
a claim about the currently running binary: manual deployments can change that
binary. The current embedded build version is saved at `desired.software.version`
in API state. Requests at or below either the running version or last successful
API-upgrade version are rejected. There is no force/downgrade/cancel endpoint.
Unknown/duplicate JSON fields, malformed versions or query parameters are `400`;
invalid keys `401`, missing permission `403`, unsupported methods `405`, active
job/transaction or non-newer version `409`, disabled/preparation failure `503`.
Asynchronous errors appear in job status, not a later HTTP error from the POST.

### Daily Release Discovery and Configuration Versions

The daemon checks GitHub's latest published stable release at startup and every
24 hours by default, asynchronously and without installing it. Without installation
configuration it uses `mayberryjp/firewall_backend` anonymously; configured
self-upgrades supply their fixed repository and optional private token.
`--disable-release-checks` explicitly disables scheduled/manual discovery,
not a configured installation manager. No browser-supplied
repository/token/URL is accepted. HTTPS requests refuse redirects, use a 10-second
connect/30-second total timeout and limit JSON to 1 MiB. Tags must be canonical
`vyyyy.mm.dd.iteration`; errors (including no published release or rate limiting)
are logged and saved, not turned into "no update".

To check immediately without restarting or installing anything, use authenticated
`POST /api/v1/system/upgrade/check` with `system.upgrade`, no query and an empty
body. `202 {"status":"check_requested"}` queues work on the same single-flight
worker; `Location: /api/v1/revisions/latest` identifies where to read
`config.software` with `state.read`. The previous result remains until completion.
An already queued/running manual or scheduled check returns `409`; explicitly disabled
or unavailable checking returns `503`. No repository/token/version override is
accepted. The daily timer is unchanged; shutdown cancels outstanding checks.
This action neither downloads assets nor invokes the installation path.

The master configuration's daemon-managed `software` object saves running
`version`, nullable `repository`, `latest_version`, `update_available`,
`last_checked_at` and `error`. Null availability means disabled, pending or failed,
distinguished by repository/time/error; it never means up to date. Metadata is
reset to the running build at startup and atomically refreshed without a
configuration revision or network apply. Upgrades validate binary/manifest integrity
separately. No real release publication/discovery or appliance upgrade is implied
by tests. See [field/UI details](../FRONTEND_SPEC.md#46-software-version-and-daily-release-checks).

Configuration revision IDs independently use the same UTC date format. Initial
configuration and each new UTC day's first confirmation allocate iteration 1;
same-day confirmations increment it. Copy server-issued strings for conflict
checks and history cursors; use `committed_revision` on confirmed transactions
rather than adding one. Backward UTC clock movement blocks confirmation explicitly
but leaves rollback available. Keep the host UTC clock accurate; the configured
display/host timezone does not affect allocation.

Current network journals use `netcontrol-rust-state-v2`. Numeric-revision v1
journals are incompatible, rejected unchanged, and are not converted by the
default policy-rule-removal operation. Use the explicitly authorized
[offline date conversion](#offline-date-revision-state-conversion) before
deploying this state contract over a v1 journal, with private backups; do not
delete/reset data or recompute checksums to force loading. No automatic migration
or compatibility window is provided. Frontend and backend must deploy the new
string-revision contract together.

The original daemon must be the service's `MainPID`, and its effective `ExecStart`
must directly name the current regular root-owned executable. New configuration
transactions/actions, including configuration-SSH writes and DHCP retry, are
blocked with `409` while a job is active; reads and existing protocol workers
continue until restart. No active configuration transaction may be interrupted
by acceptance. Do not run other installers/upgraders concurrently: shell/package
tools do not share this API's maintenance gate.

Private state lives at `/var/lib/netcontrol-updates`: latest `job.json`, copied
helper/configuration, candidate, previous executable and readiness information.
Allow disk/memory for multiple bounded binary copies; staging/backup failure
does not intentionally replace the installed executable. An independent transient
systemd worker verifies/downloads first, applies conntrack prerequisites, durably
backs up the executable, records installation intent, stops the daemon, atomically
replaces the binary beside its existing destination, and starts the same service.
The replacement must report its initialized PID/digest and remain the same active
PID for at least five seconds within the readiness budget. This is startup
readiness, not an independent proof of management-path or packet connectivity.

Before accepting the first job, the API installs/enables
`netcontrol-upgrade-recovery.service` plus the owned
`50-netcontrol-upgrade-recovery.conf` dependency drop-in. Differing existing owned
units/drop-ins are refused; other operator drop-ins and `ExecStart` are preserved.
The recovery helper remains separate from the replaced binary. On boot, recovery
runs before and is required by the daemon. An interrupted pre-install job fails
without binary replacement; interrupted install/check phases restore the
digest-verified previous executable. Recovery failure blocks startup and requires
local-console intervention. On ordinary replacement/readiness failure, the worker
attempts the same binary restoration and restart. A corrupt backup is not installed.

Job statuses: `queued`, `downloading`, `installing`, `checking`, `succeeded`,
`failed`, `rolled_back`, `recovery_required`. Only the first three terminal
outcomes (`succeeded`, `failed`, `rolled_back`) release the maintenance gate;
`recovery_required` does not. Treat API/SSH disconnection during restart as
expected, reconnect and poll the accepted job instead of resubmitting blindly.
Inspect `journalctl -u netcontrol-upgrade-worker.service` and the main/recovery
service journals locally; review them for sensitive details before sharing.

Binary recovery does **not** undo persisted-state changes, guarantee that an
older binary can read newer state, restore network connectivity, or replace
consistent protected backups. Publishers/operators must review the release's
state/deployment contract and test recovery before approving deployment. Never
delete state or flush connections to force an update. Automated systemd restart,
boot/power-loss, authenticated release-download and frontend acceptance still
require a disposable Ubuntu VM; container build/unit/filesystem tests do not
prove these behaviors. See the [current journal](journal/2026-10-29.md#automatic-github-https-updates)
and [original recovery design](journal/2026-10-24.md#signed-ubuntu-self-upgrade).

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

The installer installs only `ca-certificates`, `gh`, `procps`, `kmod` and `curl` through APT,
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
Before provisioning, it applies the persistent
[conntrack host prerequisites](#conntrack-host-prerequisites). The downloaded
installer remains self-contained; no checkout or extra helper download is needed.

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
eBPF profile is installed. The optional OS footprint script is a separate
operator action, not part of installation or upgrade.

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
The unit and managed install/full-source-upgrade drop-in use `Type=notify`,
`NotifyAccess=main`, `WatchdogSec=60s`, `WatchdogSignal=SIGKILL`,
`TimeoutStartSec=180s`, `Restart=on-failure`, `RestartSec=5s`,
`StartLimitIntervalSec=0`, and `LimitCORE=0`. Repeated failures keep retrying
without resetting saved state; invalid configuration/credentials are never
repaired by deletion. Operator drop-ins can override these settings explicitly.
The daemon sends READY only after the HTTP listener binds, heartbeats at half
the systemd-supplied interval after completed engine deadline ticks, and STOPPING
on listener shutdown. A stalled executor/engine progress path stops heartbeats;
systemd can kill/restart a wedged daemon. Ordinary worker errors, offline
upstreams, alerts and unhealthy labels never request a daemon restart.
The watchdog cannot prove every worker is making progress; task completion and
service errors are separately observable. Long engine-blocking operations can
consume the watchdog budget; qualify/tune the timeout for the appliance workload.
Watchdog termination is abrupt, so normal durable transaction recovery is still
required on restart. The 60-second shutdown allowance applies to normal stops.
Manual launches without NOTIFY_SOCKET/WATCHDOG_USEC keep running without a
systemd watchdog. Non-systemd/OpenRC installs retain their service-manager
supervision, not this heartbeat feature. A binary-only update does not install
unit changes; deploy the packaged unit or run the full source upgrade and reload
systemd. Actual PID-1 hang/restart/reboot acceptance remains a deployment check.
It does not isolate the network namespace: native operations must reach the
host networking. The unit selects `--appliance` and the LAN-address management
listener from `/etc/netcontrol/appliance.env` (default `192.168.0.1:8080`).
The bare unit does not enable API tunables. Install/full upgrade writes the
managed service drop-in that enables host-service/gateway opt-ins and embedded
configuration SSH on TCP 2222 without changing `ExecStart`. Actual protocol
workers remain controlled by saved configuration; SSH uses the existing
API-key authentication and device setup gate.

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
directory (see [Creating a WireGuard private key](#creating-a-wireguard-private-key)). Add `--allow-host-tunables`, `--allow-host-services`, or
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

### Creating a WireGuard private key

Private keys are never accepted through the API, the CLI or the dashboard; create
them on the appliance with the installed daemon. No extra packages (such as
`wireguard-tools`) are needed. A WireGuard interface's `key_ref` is the **name of a
file** in the private key directory, not the key itself. Run as root, choosing the
reference (letters, digits, `_` and `-`, at most 64 characters):

```sh
sudo /usr/local/sbin/netcontrold --create-wireguard-key wg-wan
```

It prints only the **public key**; give that to the peer. The private key is
generated by the daemon's own WireGuard library and written once with mode `0600`
into `/etc/netcontrol/keys` (created `0700` if missing). It never overwrites an
existing key, rejects invalid names, and does not start the daemon or touch
networking or saved configuration. If the unit passes a different `--keys`
directory, pass the same one here. To show a public key again later:

```sh
sudo /usr/local/sbin/netcontrold --wireguard-public-key wg-wan
```

These flags need a daemon build that includes them (run `bash upgrade.sh`).

Then reference the name: `wireguard key-ref wg-wan` in the CLI, or
`"key_ref": "wg-wan"` in the interface's `wireguard` object. The daemon reads the
file when applying and verifying and rejects it unless it is a regular file owned by
the daemon user, mode `0600` (no group/other bits), at most 128 bytes, containing a
nonzero base64 32-byte key, inside a directory owned by that user and not group- or
world-writable. Run the command as the user the daemon runs as (root on a standard
installation). To rotate a key, create a new file under a new name and change
`key_ref` in a confirmed transaction rather than editing the file in place. Keys
are not part of the configuration journal or its exports, so back up the key
directory separately and keep the backup private. The WireGuard/SSH key files are
retained by factory reset.

### Host Name and Time Zone Prerequisites

The optional `system.hostname` and `system.timezone` settings are applied by the
daemon on the host after a transaction is confirmed (see the
[contract](../FRONTEND_SPEC.md#616-host-name-and-time-zone)). They need Linux host
mode, a daemon running as root (`CAP_SYS_ADMIN` sets the hostname), and the host's
timezone database at `/usr/share/zoneinfo`, normally the `tzdata` package. The
installer and daemon never install packages. Check it with:

```sh
test -f /usr/share/zoneinfo/UTC && echo "timezone database present"
```

Without the database `GET /api/v1/system/timezones` is empty and a timezone change is
rejected with a clear error. Install `tzdata` with the operating system's package
manager if you want to manage the time zone.

The daemon treats managed values as authoritative and sets them again if they
drift. If another agent also writes the hostname they will fight; on Ubuntu images
that use cloud-init, set `preserve_hostname: true` in a file under
`/etc/cloud/cloud.cfg.d/` before managing the hostname, and do not combine it with a
DHCP-provided hostname. The daemon writes `/etc/hostname` and the kernel name only;
it does not edit `/etc/hosts`. Clearing a managed value leaves the host as it is.

### Enabling Gateway Monitoring on an Installed Appliance

The current `install.sh` and full `upgrade.sh` automatically enable both required
permissions for host appliance gateway monitors, including DHCP mode. They write
the managed file
`/etc/systemd/system/netcontrold.service.d/50-netcontrol-appliance-services.conf`:

```ini
[Unit]
Requires=netcontrol-syslog.socket
After=netcontrol-syslog.socket systemd-journald.service

[Service]
Sockets=netcontrol-syslog.socket
Environment=NETCONTROL_ALLOW_HOST_SERVICES=true
Environment=NETCONTROL_GATEWAY_MONITORING=true
```

The environment variables are equivalent to `--allow-host-services` and
`--gateway-monitoring`. Absent settings default to false; malformed boolean values
fail daemon argument parsing before state is created. The installer rejects
artifacts without these current environment settings in `--help`.
`--appliance` itself does not imply either permission.

The scripts reload systemd before starting the daemon. The upgrade keeps the
existing base unit, executable path, arguments and unrelated drop-ins; only its
managed environment file is replaced atomically. Symlink/non-regular managed
paths are refused. Setup or reload failure aborts before binary deployment.
Like conntrack prerequisites, this managed permission configuration persists
if a subsequent binary deployment fails; binary recovery does not undo it.
Explicit operator environment overrides can still change the effective settings.
`--build-only` does not install the drop-in, reload systemd or restart anything.

### Host Logging Ownership

The Ubuntu [installer](../install.sh) and full [source upgrade](../upgrade.sh)
configure **journald forwarding**, not `/dev/log` takeover:

```text
Applications -> /dev/log -> journald -> /run/systemd/journal/syslog -> Netcontrol
Kernel + daemon stdout/stderr -> journald -------------------------------^
```

Journald keeps `/dev/log`, kernel capture and its local journal even when native
syslog is disabled. Netcontrol neither binds/unlinks `/dev/log`, reads
`/dev/kmsg`, nor tails `backend.log`; this avoids duplicate kernel/backend
forwarding. `backend.log` remains a private daemon audit file. Messages from
journald are wrapped as RFC5424 records with APP-NAME `journald`; original
forwarded headers stay in message text, not structured journal fields.

The scripts atomically publish these root-owned mode `0644` managed files:

- `/etc/systemd/journald.conf.d/90-netcontrol-syslog.conf`:
  `[Journal]`, `ForwardToSyslog=yes`, `MaxLevelSyslog=debug`, `ReadKMsg=yes`.
- `/etc/systemd/system/netcontrol-syslog.socket`: a mode `0600` Unix datagram
  receiver at `/run/systemd/journal/syslog`, `Service=netcontrold.service`,
  `FileDescriptorName=netcontrol-syslog`, `RemoveOnStop=yes`,
  `PartOf=netcontrold.service`. Systemd creates and passes the receiver.
- The appliance service drop-in shown above requires/receives that socket.
  `PartOf` propagates service stop/restart to the socket in the same systemd
  transaction, including source upgrades, API upgrades and factory reset.
  It prevents forwarding traffic from reactivating the daemon during maintenance.
  The socket is not independently enabled or started before initial provisioning.

Unrelated files/custom arguments are preserved; unsafe managed paths are refused.
Configuration publication is atomic per file, not a multi-file transaction.
The scripts reload units, stop/persistently mask installed `rsyslog.service`,
`syslog-ng.service`, `syslog.service`, `syslogd.service`, `busybox-syslogd.service`
and the competing vendor `syslog.socket`. They **start/preserve**
`systemd-journald-dev-log.socket` and restart journald to apply forwarding.
No journald input is masked and no arbitrary process/socket is killed/unlinked.
Custom receivers must release the forwarding path explicitly. Systemd retains
its normal socket creation/error handling; the Rust worker never steals paths.
After stopping known receivers, setup rejects symlinks/non-sockets and checks
`/proc/net/unix` before removing only a stale unbound forwarding socket. Still-bound
custom receivers and failed ownership inspection abort without removing the path.
Neither setup nor the worker removes `/dev/log`.

During source upgrade, files/reload are prepared before stopping Netcontrol;
competing receivers and journald forwarding are configured after it stops and
before binary replacement. Setup/restart failure aborts deployment and uses
existing binary recovery. Managed configuration and masks persist on failure.
Build-only changes none of this. Later operator drop-ins may override the managed
journald settings; verify the effective configuration and end-to-end capture.

Native syslog requires a systemd launch passing exactly one descriptor named
`netcontrol-syslog`, bound to the forwarding path, with matching `LISTEN_PID`.
Bad activation metadata or socket descriptors fail startup explicitly. Without
activation, enabling syslog fails service preflight; other disabled-syslog
deployments remain possible. There is **no direct/OpenRC fallback**. Direct/manual
systemd deployments must provide the equivalent units/journald settings.
Signed API/package upgrades update binaries, not this deployment setup; provision
it before deploying code with enabled native syslog. Use console/independent OS SSH.

Saved syslog stays opt-in: disabled means no native remote forwarding, while
journald still captures locally. The socket queue is bounded, not durable:
messages may be buffered while disabled and forwarded on later enable, or lost
to overflow/rate limits. Daemon stop/restart discards the managed socket queue.
No journal replay/cursor, exact coverage or remote acknowledgment is provided.

Verify `systemctl status netcontrold netcontrol-syslog.socket systemd-journald`
and effective `systemd-analyze cat-config systemd/journald.conf`, then use a
synthetic `logger` message and remote collector to verify capture once per input.
Confirm journald retains the record and repeat after reboot. Returning to an OS
syslog receiver requires stopping Netcontrol/socket first and deliberately
removing/replacing the managed receiver/service dependencies before unmasking
the appropriate original units. Never run competing receivers at the same path.
An already blocked transaction/failed rollback still needs explicit operator
recovery; these scripts do not clear it.

Host-service permission also permits other native services **when enabled in
saved configuration**. It does not turn on NTP/syslog/traffic workers, add
monitors or change firewall/routing configuration by itself. Review saved service
settings and competing host-service ownership before deployment.

For an existing installed appliance, run the current checkout's normal upgrade
from independent OS SSH/console access; no manual unit edit is needed:

```sh
bash upgrade.sh
systemctl show netcontrold -p Environment -p ExecStart --no-pager
systemctl status netcontrold --no-pager
```

Restart interrupts API/embedded SSH sessions; do not deploy during an active
configuration transaction or upgrade. Direct/manual daemon deployments outside
these scripts must supply the two flags or equivalent environment variables.
Verify management connectivity and current state, refresh the draft's base
revision, then resubmit and confirm the monitor change. Do not reset state or
add a static probe route for DHCP mode. Missing opt-ins reject the transaction
before native network mutation; the error is still `500` with rollback status.
The current backend preserves underlying apply/rollback causes in the response
and saved transaction. A historical error containing only
`native apply failed; previous configuration restored` does not identify the
original cause; it cannot be reconstructed from that message alone.

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

Explicit reset constructs factory desired configuration directly from the saved
plan, without reading the observation-backed state API first. Existing live
addresses need not match saved addresses: do not remove the LAN recovery address
to satisfy a pre-reset drift check. Native identity/ownership, active-transaction
and rollback checks remain, and the applied factory configuration is verified
before confirmation. Ordinary state/API observation checks are unchanged.

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

## Ubuntu OS Footprint Reduction

[hardening.sh](../hardening.sh) starts a conservative Ubuntu amd64/systemd
appliance footprint profile. It is not a complete security-hardening baseline.
Default invocation only reads unit/package state and simulates APT removal:

```sh
sudo bash hardening.sh
```

Review the output, take a device snapshot and use a local console to apply:

```sh
sudo bash hardening.sh --apply
```

The service list is `cups.service`, `cups.socket`, `cups.path`,
`cups-browsed.service`, `avahi-daemon.service`, `avahi-daemon.socket`,
`apport.service` and `whoopsie.service`. Loaded matching units are stopped and
disabled; absent or masked units are skipped. This removes printing, mDNS
discovery and crash-reporting functions, so do not use it on a host needing them.
Use the appliance IP instead of relying on its `.local` discovery name.

Only installed packages from this list are requested for purge: `cups`,
`cups-browsed`, `cups-daemon`, `cups-client`, `avahi-daemon`, `avahi-utils`,
`apport`, `apport-gtk`, `whoopsie`, `popularity-contest`, `ubuntu-report`.
Essential/protected packages are refused. The English-language APT simulation
must contain recognized removals and may neither install packages nor remove
anything outside that exact selected list. Desktop/metapackage dependency chains
can therefore cause a refusal; the script does not override that guard. It never
runs autoremove, update, upgrade, cache cleanup or broad wildcard purges.

Networkd/resolved, Wi-Fi supplicants, SSH, time synchronization, security updates,
firmware, kernels, boot tools, logging, cloud-init, NetworkManager, Bluetooth and
the Rust/build/download toolchain are not targeted. No addresses, routes,
firewall rules, Netcontrol journals/credentials/keys or network configuration are
rewritten. No new protocol worker or external service is installed. This initial
profile deliberately does not strip every package or kernel module.

### Optional AppArmor Protection Opt-Out

Disabling AppArmor removes mandatory access-control protection; it is not itself
a security improvement. For the requested opt-out, preview and then apply:

```sh
sudo bash hardening.sh --disable-apparmor
sudo bash hardening.sh --apply --disable-apparmor
```

This requires an existing GRUB installation with `update-grub`, a regular
`/etc/default/grub` and `/boot/grub/grub.cfg`; unsupported boot layouts fail
preflight before any service/package changes. It writes the root-owned `0644`
`/etc/default/grub.d/99-netcontrol-apparmor.cfg` drop-in, appending `apparmor=0`
to `GRUB_CMDLINE_LINUX`, runs `update-grub`, and disables `apparmor.service`
without stopping it. AppArmor packages are retained. Existing kernel enforcement
is not claimed to be disabled until the next boot; no automatic reboot occurs.
Other applications relying on AppArmor confinement lose that protection too.
After a deliberate console-maintenance reboot, inspect `/proc/cmdline` and
`/sys/module/apparmor/parameters/enabled` to verify the actual boot state.

### State Records and Recovery

Apply stores root-only pre-change records under
`/var/lib/netcontrol/os-hardening.XXXXXX`: selected service active/enablement
states, selected package versions, and, for the AppArmor option, its service
state and any previous script drop-in. The state record is not a filesystem
snapshot: package payloads and purged application configuration are not backed
up, and reinstalling packages may require network access. APT maintainer scripts
still run; real-device boot and management continuity require separate testing.

Failures stop subsequent steps but earlier service/package changes may remain.
There is no automatic package rollback. Reinstall only the removed packages you
actually need and restore service enablement/activation according to the records;
do not blindly start every recorded unit. Shared dependencies are left alone.
If GRUB generation fails, the previous drop-in is restored (or a newly created
one removed); generated GRUB output may still need repair. Regenerate/inspect
the boot configuration before rebooting, rather than assuming full boot rollback.

To undo the AppArmor option, restore `apparmor-grub.cfg` from the selected backup
if it exists; otherwise remove only the script's
`/etc/default/grub.d/99-netcontrol-apparmor.cfg`. Run `sudo update-grub`, restore
the prior `apparmor.service` enablement (normally `sudo systemctl enable
apparmor.service`), and reboot manually when console recovery is available.
Verify kernel state afterward; stopping/starting the service alone cannot undo
the `apparmor=0` boot parameter.

Do not run hardening concurrently with install, upgrade, reset or APT/dpkg jobs.
The script serializes its own apply runs, not other package managers. It is not
automatically invoked by any deployment script. Preview and mocked tests do not
prove the live Ubuntu package plan, bootloader or post-reboot connectivity.

## Native mDNS discovery

Native mDNS/DNS-SD is an in-process Rust service, disabled in saved defaults.
No Avahi/D-Bus package, daemon or service-unit activation is required. It works
in the managed Linux namespace and uses the existing host-service opt-in in
host mode (Ubuntu install/full upgrade supplies it).

Configure `mdns` through a full confirmed transaction with `mdns.write`, selecting
up managed Ethernet/VLAN LAN interfaces and the needed address families. Keep
one active reflector per connected discovery domain; resolve other local UDP
5353 responders before enabling. The service rejects conflicting ownership;
it does not kill competitors or change systemd-resolved.

Restrictive host-input policies need explicit ingress UDP destination port
5353 permits. Current rules cannot narrow these permits to the mDNS multicast
destination; the worker validates packet destination/source/hop metadata.
Discovery does not permit unicast service connections or route IPv6 link-local
addresses. No firewall, NAT, IGMP/MLD routing or forwarding sysctl is changed.
OpenRC is supported for this worker independently of syslog's systemd-only
socket activation.

Read committed config at `/api/v1/services/mdns`; read applied lifecycle/loss
warnings at `/api/v1/services/mdns/status`, even after worker failure. Never
confuse local readiness with successful device discovery. Before production,
validate actual VLAN/nftables/IPv6 membership paths, devices, packet rates,
restart/reboot and management connectivity. See the
[contract](../FRONTEND_SPEC.md#617-native-mdns--dns-sd),
[build/qualification spec](MDNS_SPEC.md) and
[synthetic example](../examples/mdns.json), not a ready-to-apply replacement
configuration.

## Optional configuration SSH server

Ubuntu `install.sh` and full `upgrade.sh` now enable the daemon's **in-process**
configuration SSH server by default using
`Environment=NETCONTROL_SSH_LISTEN=0.0.0.0:2222` in the managed
`50-netcontrol-appliance-services.conf` drop-in. This is not a separate SSH
daemon process, system shell, SFTP server or supervised `sshd`.
`upgrade.sh --build-only` does not change this configuration.

For manual/OpenRC deployments, add `--ssh-listen 0.0.0.0:2222` to
`netcontrold_args` to enable the daemon's native SSH interpreter; add
`--ssh-host-key /var/lib/netcontrol/ssh-host-key`
to select a persistent private Ed25519 host-key file explicitly. Otherwise the
key defaults to `<state>.ssh-key`. Keep this key stable and owner-only; invalid
existing data fails startup rather than being regenerated.

To customize the script-managed listener, add a root-owned
`NETCONTROL_SSH_LISTEN=192.0.2.1:2222` line to `/etc/netcontrol/appliance.env`,
substituting a real management address. Environment-file values override the
managed default; explicit `--ssh-listen` arguments override both. Do not edit
the generated `50-netcontrol-appliance-services.conf`, which full upgrades
refresh.

To disable the environment-provided listener, use an operator-owned systemd
drop-in (for example `systemctl edit netcontrold`) containing:

```ini
[Service]
UnsetEnvironment=NETCONTROL_SSH_LISTEN
```

Also remove any explicit `--ssh-listen` argument from your custom `ExecStart`.
An empty or invalid address is an error, not an off switch. Then reload systemd
and restart from an independent OS SSH session/local console; both API and
embedded SSH sessions are interrupted. Operator-owned drop-ins survive full
upgrades. The bare daemon remains off when neither flag nor environment value
is provided.

Review host-input policy before enabling or upgrading: binding to `0.0.0.0`
includes WAN addresses. Fresh provisioning blocks new WAN input, but upgrading
preserves the saved firewall and adds no SSH permit or protective deny. A port
collision or insecure host-key file causes startup failure, not a silent
fallback to disabled SSH. No operating-system SSH service is changed.

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
