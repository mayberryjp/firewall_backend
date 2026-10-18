# Alpine build and installation specification

## Scope

Build `netcontrold` as a lightweight Alpine Linux **APK** for `x86_64` and
`aarch64`, with an OpenRC service. The build baseline is Alpine **3.23**, not an
unversioned `latest` image. Packages contain a stripped, static Go binary and the
embedded onboarding website; no separate Node/frontend build is required.

This remains an isolated-lab networking controller, not a production host
firewall appliance. Packaging does not add host-network management, namespace
provisioning, physical-device setup, or unattended reboot recovery.

## Automatic GitHub builds

[Build workflow](../.github/workflows/build.yml) runs on every push and pull
request, with an additional manual Run workflow entry. No secrets are required.
It does not create releases, tags, commits, or deploy to devices.

The pipeline:

1. Checks Go formatting and module integrity; runs tests, vet, and builds on
   Linux and Windows using the current stable Go toolchain. Linux also runs the
   race detector and packaging shell syntax checks.
2. Runs opt-in kernel and managed-daemon tests as root on a disposable Linux
   runner, with dnsmasq/softflowd and required kernel modules. Tests create their
   own namespaces, never targeting the host namespace.
3. Only after both check jobs succeed, builds native-architecture APKs inside
   Alpine 3.23 containers on x86-64 and ARM64 runners.
4. Runs Alpine Go tests/vet through `abuild`, installs the resulting APK in that
   disposable container, and smoke-tests OpenRC start/restart/stop, management
   HTTP readiness, protected API access, and private directory permissions.
5. Uploads each architecture's artifacts for 14 days:
   - `netcontrol-0_git<TIMESTAMP>-r0.apk`
   - An ephemeral APK signing public key (`*.rsa.pub`).
   - `BUILDINFO.json`: full source commit, commit timestamp, package version,
     architecture, actual Alpine version, and Go toolchain.
   - `SHA256SUMS`: package, public-key, and build-info checksums.

Actions are pinned to commit IDs with read-only repository permissions.
Checkout credentials are not persisted. Both check jobs gate artifact creation;
dependency, test, kernel, signing, or smoke failures fail the build.

### Version and trust policy

`0_git<TIMESTAMP>-r0` is an APK **development identifier**, using the source
commit's Unix timestamp. It is not an assigned SemVer release. Use the full
commit in `BUILDINFO.json` to distinguish builds, including commits sharing a
timestamp. No release baseline has been selected.

Each build generates a temporary signing key and destroys the private key when
the build helper exits. Only its public key is exported. This avoids storing a
signing secret in the repository or requiring a CI secret, but it is **not** a
stable publisher identity. Checksums detect corruption, not malicious replacement.
Trust artifacts only from a reviewed commit and the expected authenticated
repository workflow; pull-request artifacts can contain untrusted code.

A stable signed APK repository, long-lived trusted signing key, release version,
and publication/deployment workflow are separate future decisions. The APK
metadata uses `LicenseRef-Unspecified` because this repository has not declared
a distribution license; this does not grant redistribution rights.

## Install a build artifact

On the GitHub repository's **Actions -> Build and test**, select a successful run
for your reviewed commit and download the artifact matching `apk --print-arch`.
Artifacts are named `netcontrol-alpine3.23-<ARCH>-<FULL_COMMIT>`. Extract the ZIP
before running the following commands.

On an Alpine 3.23 OpenRC host, as root, in the extracted artifact directory:

```sh
apk --print-arch
cat BUILDINFO.json
sha256sum -c SHA256SUMS

# Trust only the key from the reviewed workflow artifact.
install -m 644 ./*.rsa.pub /etc/apk/keys/
apk add ./netcontrol-*.apk

rc-service netcontrold start
rc-service netcontrold status
```

Do not bypass signature verification with `--allow-untrusted`. No public APK
repository is published by this workflow; install the downloaded local file.
The package does **not** automatically start or enable itself.

The default configuration is simulator mode, bound to `127.0.0.1:8080`.
Use the device console, or an existing SSH connection with a local tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 operator@device
```

Open `http://127.0.0.1:8080/`, create the device account, generate/save an API key,
and complete setup. Anyone reaching an unclaimed device can claim it; do not
expose it to an untrusted network. Simulator changes never affect the OS.
Use native TLS before changing the listener to a non-loopback address.

To start the configured service at boot:

```sh
rc-update add netcontrold default
```

### Installed paths

| Path | Purpose |
|------|---------|
| `/usr/sbin/netcontrold` | Static daemon and embedded onboarding website |
| `/etc/init.d/netcontrold` | OpenRC service |
| `/etc/conf.d/netcontrold` | Root-managed `netcontrold_args` |
| `/var/lib/netcontrol/` | Private root-owned state and credentials directory |
| `/var/lib/netcontrol/state.json` | Default simulator journal |
| `/var/lib/netcontrol/credentials.db` | Device identity database, separate from network state |
| `/etc/netcontrol/keys/` | Operator-provisioned private WireGuard keys |
| `/var/log/netcontrold.log` | Root-only structured stdout/stderr log |
| `/run/netcontrold.pid` | OpenRC-owned daemon PID file |

OpenRC allows 90 seconds for graceful termination before a forced kill. The
daemon normally rolls back an active transaction on shutdown. Inspect the log
after failures; OpenRC process status alone is not HTTP or networking readiness.
Operators must rotate/retain logs and protect backups of the journal,
credentials database, and private keys.

## Enable native Linux networking

The service runs as root for namespace/kernel administration. Enabling Linux is
an explicit operator action; no API can choose the namespace or executable.
The kernel must support network namespaces, dummy/VLAN links, nftables,
conntrack/NAT, and WireGuard when used. Containers need suitable namespace/kernel
privileges; an ordinary unprivileged application container is insufficient.

For a **new isolated lab** only, provision an empty namespace before first use:

```sh
apk add iproute2
ip netns add netcontrol-lab
```

Replace `netcontrold_args` in `/etc/conf.d/netcontrold` with:

```sh
netcontrold_args="-backend linux -namespace netcontrol-lab \
  -listen 127.0.0.1:8080 \
  -state /var/lib/netcontrol/linux-state.json \
  -credential-db /var/lib/netcontrol/credentials.db \
  -keys /etc/netcontrol/keys"
```

Then:

```sh
rc-service netcontrold restart
tail -n 50 /var/log/netcontrold.log
```

Use a separate new journal for the first Linux configuration; simulator and
Linux journals cannot be interchanged. The credential database can stay the
same. Provide read-only adopted parents with `-adopt-parents` only after
provisioning them externally. Create WireGuard key files privately as described
in the [README](../README.md).

**Namespace lifetime matters:** journals are bound to boot ID and namespace
identity, not merely the namespace name. Restarting the service in the same
namespace is supported; recreating the namespace or rebooting changes its scope.
This package does not restore that kernel scope or replay configuration into a
new one. Do not delete existing journals or credentials to force startup. A
native boot-time deployment needs an explicitly designed provisioning/recovery
process; this is not implemented by the APK or OpenRC unit.

### Optional appliance NTP, syslog, and vnStat

These explicitly extend ownership beyond the managed namespace: NTP adjusts
the real appliance clock, syslog-ng owns the whole system logger, and vnstatd
tracks host and managed-namespace interfaces in separate databases.
NTP/syslog outbound traffic uses host networking, DNS and routes.

```sh
apk add chrony syslog-ng vnstat ca-certificates
```

Before enabling, explicitly stop competing clock/logging OpenRC services and
prevent them from starting independently at boot. Do not automatically stop
unknown host services. Verify `/dev/log` ownership; existing/stale sockets or
symlinks require explicit operator resolution, not automatic takeover.

Append to existing native arguments in `/etc/conf.d/netcontrold`:

```sh
netcontrold_args="$netcontrold_args -allow-host-services \
  -ntp-binary /usr/sbin/chronyd -syslog-binary /usr/sbin/syslog-ng \
  -vnstatd-binary /usr/sbin/vnstatd -vnstat-binary /usr/bin/vnstat"
```

Restart, then stage service settings through complete API transactions. Keep
the OpenRC backend log redirection to `/var/log/netcontrold.log`, which syslog-ng
tails alongside system/kernel logs. Other launchers must arrange their own
regular backend log source with `-backend-log-file`.

One exclusive host-service owner is allowed. Root needs namespace privileges,
`CAP_SYS_TIME` for NTP and `CAP_SYSLOG` for system/kernel logging. Container
clock privileges can affect the real host. No NTP serving, stepping, NTS, remote
delivery guarantee, or automatic firewall/network provisioning is provided.
Disabling managed syslog stops the whole logger; provision an alternative
before relying on local logging after disabling/rollback.

Default private root-owned mode-0700 directories are `/run/netcontrol-services`
and persistent `/var/lib/netcontrol/services`; they must be separate.
vnStat databases are never automatically deleted. Runtime reports their active
paths. Managed scope changes create a different database; existing native
namespace/journal reboot limits still apply.
See the [full contract and recovery cautions](../README.md#appliance-time-remote-logging-and-vnstat)
and [complete synthetic example](../examples/appliance-services.json).

### Optional native gateway monitoring

Native IPv4/IPv6 ICMP monitoring needs no dpinger package or additional daemon.
After configuring native namespace/journal arguments above, append in
`/etc/conf.d/netcontrold`:

```sh
netcontrold_args="$netcontrold_args -gateway-monitoring"
```

Restart the service, then submit monitors with their explicit source/interface,
route, next hop, and source-policy rule. The root OpenRC service needs
`CAP_NET_RAW` plus its existing namespace/network administration privileges;
restricted/container deployments must supply those capabilities explicitly.
No route, firewall permission, or automatic failover is installed by monitoring.
Verify ICMP/ICMPv6 return paths yourself. Simulator mode never sends probes.

See the [configuration, metrics, and native test instructions](../README.md#native-gateway-monitoring)
and [dual-stack example](../examples/gateway-monitoring.json).
Monitor settings persist, while in-memory metrics reset after restart.
The namespace/reboot limitations above still apply.

### Optional DHCP relay

Install only if needed; neither the daemon nor the APK requires dnsmasq for
simulator/basic networking:

```sh
apk add dnsmasq
addgroup -S netcontrol-relay
adduser -S -D -H -G netcontrol-relay netcontrol-relay
```

In `/etc/conf.d/netcontrold`, resolve the local identity and append flags to the
existing native arguments:

```sh
relay_uid=$(id -u netcontrol-relay) || return 1
relay_gid=$(id -g netcontrol-relay) || return 1
netcontrold_args="$netcontrold_args \
  -dhcp-relay-binary /usr/sbin/dnsmasq \
  -dhcp-relay-runtime-dir /run/netcontrol-dhcp-relay \
  -dhcp-relay-uid $relay_uid -dhcp-relay-gid $relay_gid"
```

Restart the service, then enable relay through normal interface transactions.
Do not enable Alpine's independent dnsmasq service for this integration.
Netcontrol supervises its own relay-only child; no softflowd installation or
configuration is required. Routes, server return paths, and other firewall
permissions remain operator responsibilities. See
[relay setup and constraints](../README.md#relay-operator-setup).
Softflowd is likewise optional and separately operator-configured.

## Build an APK locally on Alpine

Run builds on the target architecture using Alpine 3.23. Root first installs
the tools and creates a build account (omit account creation if it exists):

```sh
apk add alpine-sdk go git
adduser -D builder
addgroup builder abuild
su - builder
```

As that unprivileged user:

```sh
git clone https://github.com/mayberryjp/firewall_backend.git
cd firewall_backend
sh packaging/alpine/build.sh
```

The helper requires a clean, committed checkout and packages **HEAD**, not
uncommitted edits. It does not install dependencies or change a user's existing
abuild signing configuration. It creates isolated temporary keys/configuration,
generates SHA-512 source checksums, runs `abuild`, and writes artifacts to
`dist/`. `OUTDIR=/absolute/empty/directory` can override the output location;
nonempty output directories are rejected to prevent stale artifacts.

The APKBUILD disables cgo and uses the installed Go toolchain (Go 1.24+), with
read-only modules, trimmed paths and stripped build IDs/debug symbols. Race
tests run separately on the Linux CI host with a C toolchain.

For a binary-only development build on Linux:

```sh
go mod download
CGO_ENABLED=0 go build -trimpath -o netcontrold ./cmd/netcontrold
./netcontrold -backend simulator -state ./state.json
```

On Windows, use Go 1.24+ and PowerShell:

```powershell
go mod download
go build -o netcontrold.exe .\cmd\netcontrold
.\netcontrold.exe -backend simulator -state .\state.json
```

Windows does not support the native backend or APK installation.

## Updating and removing a package

Stop the service, back up state/credentials/keys privately, verify the reviewed
replacement artifact and its public key, then use `apk add --upgrade` with that
local APK. Review any `/etc/conf.d/netcontrold.apk-new` before restarting; apk
preserves modified configuration. Do not discard data or use an older contract
as a fallback: this project's greenfield policy still applies.

To disable/remove:

```sh
rc-service netcontrold stop
rc-update del netcontrold default
apk del netcontrol
```

Only remove the runlevel entry if previously added. Package removal does not
purge populated state directories, credentials, operator keys, or logs.
It does not delete namespaces or undo all committed networking configuration.

## Verification status

Locally verified on Windows: full Go tests, vet/build; Linux control-test
compilation and vet; static Linux amd64/arm64 builds; workflow validation with
actionlint; shell syntax checks.

**Not yet executed:** actual Alpine APK creation/installation, OpenRC smoke
tests, Linux privileged integration and race tests. Docker's Linux engine is
unavailable in the current Windows environment. The new CI performs those
checks after these files are committed/pushed and GitHub Actions is enabled;
no remote run has been triggered or reported successful.
