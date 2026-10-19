# Native Rust build and installation

## Packaging contract

Netcontrol uses its own signed `.ncpkg` format and the Rust
`netcontrol-package` executable. It does not use APK, abuild, tar extraction,
shell-driven installation, or an external package-manager subprocess.
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
rc-service netcontrold start
rc-service netcontrold status
```

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

Default configuration remains simulator mode: installing or starting the
package does not make it a live host firewall. After reviewing the configuration:

```sh
rc-update add netcontrold default
```

## Enable native networking deliberately

The native backend requires an operator-created isolated network namespace,
kernel networking support, and namespace/network-administration privileges.
The daemon does not create the namespace, configure physical ports, enable
forwarding, or adopt arbitrary existing networking. Its management listener
remains in the host namespace.

After provisioning those prerequisites, stop the simulator and configure
`netcontrold_args` in `/etc/conf.d/netcontrold` using conventional long options:

```sh
netcontrold_args="--backend linux --namespace netcontrol \
  --listen 0.0.0.0:8080 \
  --state /var/lib/netcontrol/native-state.json \
  --credential-db /var/lib/netcontrol/credentials.json \
  --keys /etc/netcontrol/keys \
  --services-state-dir /var/lib/netcontrol/services"
```

`netcontrol` above is an example namespace name, resolved under `/run/netns`,
not a namespace the installer creates. The daemon rejects its own or PID 1's
network namespace and namespace symlinks. Network state is bound to the actual
backend scope: a simulator file is not native state, and a different namespace
is not the same scope. Retain existing files and choose a deliberate separate
state path when changing scope; do not reset incompatible state.

Pre-created parent interfaces require explicit `--adopt-parents`; they remain
read-only. WireGuard private keys must already exist in the private key
directory. Add `--allow-host-tunables`, `--allow-host-services`, or
`--gateway-monitoring` only after reviewing their host-wide effects and
capabilities. Competing clock/logging services must not retain ownership when
the corresponding native workers are enabled. Syslog TLS needs system CA roots.
These opt-ins do not configure networking or enable services by themselves.

See the exact [native ownership/prerequisites](../crates/netcontrol-native/README.md)
and [service restrictions](../crates/netcontrol-services/README.md). On a
disposable Linux host, validate packet forwarding, rollback, management
reachability, DHCP and collector behavior before enabling unattended native
startup. Cross-compilation is not that acceptance test.

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
builds on Linux/Windows, and runs privileged Linux integration separately.
Successful checks gate static musl package builds for x86-64 and ARM64.
Artifacts contain the package, standalone installer, public key, commit/target
build information, and SHA-256 checksums.

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
