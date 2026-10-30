#!/usr/bin/env bash
set -euo pipefail

configure_conntrack() (
    set -euo pipefail
    local sysctl_directory=${1:-/etc/sysctl.d} modules_directory=${2:-/etc/modules-load.d}
    local sysctl_file="$sysctl_directory/90-netcontrol-conntrack.conf"
    local modules_file="$modules_directory/netcontrol-conntrack.conf"
    local executable path work actual
    for executable in modprobe sysctl install; do
        command -v "$executable" >/dev/null || {
            printf 'Missing %s; install kmod and procps before configuring conntrack.\n' "$executable" >&2
            exit 1
        }
    done
    for path in "$sysctl_file" "$modules_file"; do
        [[ ! -L $path && ( ! -e $path || -f $path ) ]] || {
            printf 'Refusing non-regular conntrack configuration: %s\n' "$path" >&2
            exit 1
        }
    done
    modprobe nf_conntrack || exit 1
    sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_checksum=1 || exit 1
    for path in net.netfilter.nf_conntrack_acct net.netfilter.nf_conntrack_checksum; do
        actual=$(sysctl -n "$path") || exit 1
        [[ $actual == 1 ]] || {
            printf 'Conntrack prerequisite did not take effect: %s\n' "$path" >&2
            exit 1
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    printf 'net.netfilter.nf_conntrack_acct = 1\nnet.netfilter.nf_conntrack_checksum = 1\n' > "$work/sysctl" || exit 1
    printf 'nf_conntrack\n' > "$work/modules" || exit 1
    install -d -m 0755 "$sysctl_directory" "$modules_directory" || exit 1
    install -o root -g root -m 0644 "$work/sysctl" "$sysctl_file" || exit 1
    install -o root -g root -m 0644 "$work/modules" "$modules_file" || exit 1
    printf 'Conntrack accounting and checksum validation enabled and configured for boot. Existing connections may still lack counters.\n'
)

configure_link_diagnostics() (
    set -euo pipefail
    local directory=${1:-/etc/modules-load.d}
    local destination="$directory/netcontrol-link-diagnostics.conf" work module
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
        printf 'Refusing non-regular link diagnostics module configuration: %s\n' "$destination" >&2
        exit 1
    }
    for module in af_packet inet_diag tcp_diag; do
        modprobe "$module" || {
            printf 'Native link diagnostics require kernel CONFIG_PACKET, CONFIG_INET_DIAG and CONFIG_INET_TCP_DIAG (failed: %s).\n' "$module" >&2
            exit 1
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    printf 'af_packet\ninet_diag\ntcp_diag\n' > "$work/modules" || exit 1
    install -d -m 0755 "$directory" || exit 1
    install -o root -g root -m 0644 "$work/modules" "$destination" || exit 1
    printf 'Native link diagnostics kernel modules enabled for boot; no eBPF tools or security sysctl changes required.\n'
)

configure_deny_logging() (
    set -euo pipefail
    local directory=${1:-/etc/modules-load.d}
    local destination="$directory/netcontrol-deny-log.conf" work module
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
        printf 'Refusing non-regular deny-log module configuration: %s\n' "$destination" >&2
        exit 1
    }
    for module in nf_tables nfnetlink_log nft_log; do
        modprobe "$module" || {
            printf 'Firewall telemetry requires CONFIG_NF_TABLES (including counter expressions), CONFIG_NETFILTER_NETLINK_LOG and CONFIG_NFT_LOG (failed: %s).\n' "$module" >&2
            exit 1
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    printf 'nf_tables\nnfnetlink_log\nnft_log\n' > "$work/modules" || exit 1
    install -d -m 0755 "$directory" || exit 1
    install -o root -g root -m 0644 "$work/modules" "$destination" || exit 1
    printf 'Firewall deny-log and rule-accounting kernel modules enabled for boot; telemetry remains separate from configuration.\n'
)

configure_appliance_services() (
    set -euo pipefail
    local directory=${1:-/etc/systemd/system/netcontrold.service.d}
    local destination="$directory/50-netcontrol-appliance-services.conf" staged=''
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
        printf 'Refusing non-regular appliance service configuration: %s\n' "$destination" >&2
        exit 1
    }
    install -d -o root -g root -m 0755 "$directory" || exit 1
    staged=$(mktemp "$directory/.appliance-services.XXXXXX") || exit 1
    trap '[[ -z $staged ]] || rm -f -- "$staged"' EXIT
    printf '[Unit]\nRequires=netcontrol-syslog.socket\nAfter=netcontrol-syslog.socket systemd-journald.service\nStartLimitIntervalSec=0\n\n[Service]\nType=notify\nNotifyAccess=main\nWatchdogSec=60s\nWatchdogSignal=SIGKILL\nTimeoutStartSec=180s\nRestart=on-failure\nRestartSec=5s\nLimitCORE=0\nSockets=netcontrol-syslog.socket\nEnvironment=NETCONTROL_ALLOW_HOST_SERVICES=true\nEnvironment=NETCONTROL_GATEWAY_MONITORING=true\nEnvironment=NETCONTROL_SSH_LISTEN=0.0.0.0:2222\nEnvironment=NETCONTROL_UPGRADE_CONFIG=/etc/netcontrol/updates.json\n' > "$staged" || exit 1
    chmod 0644 "$staged" || exit 1
    mv -fT -- "$staged" "$destination" || exit 1
    printf 'Appliance host services, gateway monitoring and embedded configuration SSH (TCP 2222) enabled for the next daemon start; configured protocol services remain controlled by saved configuration. Restrict management access with the host-input firewall.\n'
)

configure_logging_units() (
    set -euo pipefail
    local root=${1:-/etc} work staged='' relative directory destination
    work=$(mktemp -d) || exit 1
    trap '[[ -z $staged ]] || rm -f -- "$staged"; rm -rf -- "$work"' EXIT
    printf '[Unit]\nDescription=Netcontrol journald syslog receiver\nPartOf=netcontrold.service\n\n[Socket]\nListenDatagram=/run/systemd/journal/syslog\nSocketMode=0600\nService=netcontrold.service\nFileDescriptorName=netcontrol-syslog\nRemoveOnStop=yes\n' > "$work/netcontrol-syslog.socket" || exit 1
    printf '[Journal]\nForwardToSyslog=yes\nMaxLevelSyslog=debug\nReadKMsg=yes\n' > "$work/90-netcontrol-syslog.conf" || exit 1
    for relative in systemd/system/netcontrol-syslog.socket systemd/journald.conf.d/90-netcontrol-syslog.conf; do
        destination="$root/$relative"
        directory=${destination%/*}
        [[ ! -L $root/systemd && ! -L $directory &&
           ( ! -e $directory || -d $directory ) &&
           ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
            printf 'Refusing unsafe logging configuration: %s\n' "$destination" >&2
            exit 1
        }
        install -d -o root -g root -m 0755 "$directory" || exit 1
        staged=$(mktemp "$directory/.netcontrol-logging.XXXXXX") || exit 1
        install -o root -g root -m 0644 "$work/${destination##*/}" "$staged" || exit 1
        mv -fT -- "$staged" "$destination" || exit 1
        staged=''
    done
)

configure_host_logging() (
    set -euo pipefail
    local forwarding_socket=${1:-/run/systemd/journal/syslog} unix_sockets=${2:-/proc/net/unix}
    local unit state status
    printf 'Configuring journald forwarding to native syslog; stopping/masking competing syslog receivers. Journald retains /dev/log.\n'
    for unit in rsyslog.service syslog-ng.service syslog.service syslogd.service busybox-syslogd.service \
        syslog.socket; do
        if ! state=$(systemctl show "$unit" --property=LoadState --value); then
            [[ $state == not-found ]] || {
                printf 'Cannot inspect conflicting logger %s.\n' "$unit" >&2
                exit 1
            }
        fi
        case $state in
            not-found) continue ;;
            loaded|masked) ;;
            error)
                # An alias of an already masked logger (syslog.service -> rsyslog.service) fails to load but cannot run.
                [[ $(systemctl is-enabled "$unit" 2>/dev/null || true) == masked ]] || {
                    printf 'Unsupported logger load state for %s: %s\n' "$unit" "$state" >&2
                    exit 1
                }
                continue ;;
            *) printf 'Unsupported logger load state for %s: %s\n' "$unit" "$state" >&2; exit 1 ;;
        esac
        systemctl mask --now "$unit" || {
            printf 'Cannot stop/mask conflicting logger %s; deployment aborted.\n' "$unit" >&2
            exit 1
        }
        state=$(systemctl show "$unit" --property=ActiveState --value) || exit 1
        [[ $state == inactive || $state == failed ]] || {
            printf 'Conflicting logger %s is still %s; deployment aborted.\n' "$unit" "$state" >&2
            exit 1
        }
    done
    if [[ -L $forwarding_socket || ( -e $forwarding_socket && ! -S $forwarding_socket ) ]]; then
        printf 'Refusing non-socket/symlink syslog forwarding path: %s\n' "$forwarding_socket" >&2
        exit 1
    fi
    if [[ -S $forwarding_socket ]]; then
        if awk -v socket="$forwarding_socket" \
            '$8 == socket { found=1 } END { exit !found }' "$unix_sockets"; then
            printf 'Syslog forwarding socket %s is still bound; stop its owner explicitly. No socket removed.\n' "$forwarding_socket" >&2
            exit 1
        else
            status=$?
            [[ $status -eq 1 ]] || {
                printf 'Cannot inspect syslog socket ownership; no socket removed.\n' >&2
                exit 1
            }
        fi
        rm -- "$forwarding_socket" || exit 1
    fi
    systemctl start systemd-journald-dev-log.socket || {
        printf 'Cannot start journald /dev/log input; deployment aborted.\n' >&2
        exit 1
    }
    systemctl restart systemd-journald.service || {
        printf 'Cannot activate journald syslog forwarding; deployment aborted.\n' >&2
        exit 1
    }
)

check_systemd_unit() {
    local unit=netcontrold.service
    local destination=/etc/systemd/system/netcontrold.service
    if [[ -L $destination ]] || { [[ -e $destination ]] && ! cmp -s "$unit" "$destination"; }; then
        printf 'Existing %s differs from the supplied unit; refusing to overwrite it. Use systemd drop-ins for customization.\n' "$destination" >&2
        return 1
    fi
}

configure_upgrade_settings() {
    "${1:-/usr/local/sbin/netcontrold}" --configure-updates /etc/netcontrol/updates.json
}

install_systemd_service() {
    check_systemd_unit || return 1
    install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys || return 1
    install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service || return 1
    configure_upgrade_settings || return 1
    configure_appliance_services || return 1
    configure_logging_units || return 1
    systemctl daemon-reload || return 1
    configure_host_logging || return 1
}

select_appliance_ports() {
    local wan=${1:-} lan=${2:-} directory=${3:-/sys/class/net} path name
    local -a interfaces=()
    mapfile -t interfaces < <(
        for path in "$directory"/*; do
            name=${path##*/}
            [[ $name != lo && -d $path/device && -r $path/type && $(< "$path/type") == 1 &&
               ! -d $path/wireless && ! -e $path/phy80211 ]] || continue
            printf '%s\n' "$name"
        done | LC_ALL=C sort -V
    )
    if [[ -z $wan && -z $lan ]]; then
        [[ ${#interfaces[@]} -ge 2 ]] || { printf 'At least two physical Ethernet interfaces are required.\n' >&2; return 1; }
        wan=${interfaces[0]}
        lan=${interfaces[1]}
    fi
    [[ -n $wan && -n $lan && $wan != "$lan" && " ${interfaces[*]} " == *" $wan "* &&
       " ${interfaces[*]} " == *" $lan "* ]] || {
        printf 'Provide both --wan and --lan with distinct physical Ethernet ports, or omit both for automatic selection.\n' >&2
        return 1
    }
    printf '%s %s\n' "$wan" "$lan"
}

provision_appliance() {
    local binary=$1 wan=$2 lan=$3 address=$4
    "$binary" --backend linux --appliance \
        --state /var/lib/netcontrol/native-state.json \
        --credential-db /var/lib/netcontrol/credentials.json \
        --keys /etc/netcontrol/keys \
        --services-state-dir /var/lib/netcontrol/services \
        --provision-wan "$wan" --provision-lan "$lan" --provision-lan-address "$address" || return 1
    printf 'NETCONTROL_LISTEN=%s:8080\n' "${address%/*}" |
        install -o root -g root -m 0600 /dev/stdin /etc/netcontrol/appliance.env || return 1
    systemctl daemon-reload || return 1
    systemctl enable --now netcontrold.service || return 1
    curl --noproxy '*' --silent --show-error --fail --retry 15 \
        --retry-connrefused --retry-all-errors --retry-delay 1 --max-time 2 \
        "http://${address%/*}:8080/" >/dev/null || return 1
    [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || {
        printf 'Appliance startup did not enable IPv4 forwarding. Inspect the service journal.\n' >&2
        return 1
    }
}

download_prebuilt() {
    local run_id=$1 destination=$2 commit
    gh auth status || {
        printf 'Authenticate GitHub CLI as the installing user first (sudo gh auth login when installing as root). Actions read access is required.\n' >&2
        return 1
    }
    commit=$(gh api "repos/mayberryjp/firewall_backend/actions/runs/$run_id" --jq 'select(.conclusion == "success" and .path == ".github/workflows/build.yml" and .event == "workflow_dispatch" and .head_repository.full_name == "mayberryjp/firewall_backend") | .head_sha') || return 1
    if [[ ! $commit =~ ^[0-9a-f]{40}$ ]]; then
        printf 'Expected a successful manually dispatched build workflow from the owning repository.\n' >&2
        return 1
    fi
    gh run download "$run_id" --repo mayberryjp/firewall_backend --name "netcontrol-ubuntu-amd64-$commit" --dir "$destination" || return 1
    (
        cd "$destination"
        local file
        for file in netcontrold netcontrold.service SHA256SUMS; do
            [[ -f $file && ! -L $file ]] || return 1
        done
        [[ $(wc -l < SHA256SUMS) -eq 2 ]] || return 1
        grep -Eq '^[0-9a-f]{64} \*netcontrold$' SHA256SUMS || return 1
        grep -Eq '^[0-9a-f]{64} \*netcontrold\.service$' SHA256SUMS || return 1
        sha256sum --check --strict SHA256SUMS
    ) || return 1
    printf 'Verified prebuilt artifacts from source commit %s (workflow run %s).\n' "$commit" "$run_id"
}

main() {
    local run_id='' wan='' lan='' lan_address=192.168.0.1/24 path ports
    if [[ ${1:-} == --help ]]; then
        printf 'Usage: bash install.sh --run-id SUCCESSFUL_BUILD_RUN_ID [--wan WAN_NIC --lan LAN_NIC] [--lan-address 192.168.0.1/24]\nDefaults: first physical Ethernet port (natural name order) is DHCP WAN, second is LAN; LAN allows all traffic, WAN denies unsolicited inbound, LAN-to-WAN traffic is NATed. Provisions LAN-address HTTP management and enables the service at boot. Automatically configures host-service/gateway-monitoring permissions, journald forwarding and native syslog socket activation; stops/masks competing syslog receivers, leaving journald in charge of /dev/log. Saved configuration controls which workers run. Requires console access and networkd/resolved. LAN clients need static addressing; no DHCP server is installed.\n'
        return
    fi
    while [[ $# -gt 0 ]]; do
        [[ $# -ge 2 ]] || { printf 'Missing option value; use --help.\n' >&2; return 1; }
        case $1 in
            --run-id) [[ -z $run_id ]] || return 1; run_id=$2 ;;
            --wan) [[ -z $wan ]] || return 1; wan=$2 ;;
            --lan) [[ -z $lan ]] || return 1; lan=$2 ;;
            --lan-address) lan_address=$2 ;;
            *) printf 'Unknown option: %s. Use --help.\n' "$1" >&2; return 1 ;;
        esac
        shift 2
    done
        if [[ ! $run_id =~ ^[0-9]+$ || ( -n $wan && ! $wan =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ ) ||
            ( -n $lan && ! $lan =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ ) ||
          ! $lan_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        printf 'Specify a run ID, an IPv4 LAN prefix and optionally both --wan/--lan; use --help.\n' >&2
        return 1
    fi
    if [[ $(uname -s) != Linux || ! -r /etc/os-release ]]; then
        printf 'This prebuilt installer requires Ubuntu Linux amd64.\n' >&2
        return 1
    fi
    local ID
    . /etc/os-release
    if [[ ${ID:-} != ubuntu ]] || [[ $(dpkg --print-architecture) != amd64 ]]; then
        printf 'This prebuilt installer requires Ubuntu amd64.\n' >&2
        return 1
    fi
    if [[ $EUID -ne 0 ]]; then
        printf 'Run with sudo bash install.sh (or as root).\n' >&2
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
        printf 'This installer requires Ubuntu running systemd.\n' >&2
        return 1
    fi

    for path in /var/lib/netcontrol/native-state.json /var/lib/netcontrol/native-state.json.lock /etc/netcontrol/appliance.env; do
        [[ ! -e $path && ! -L $path ]] || { printf 'Fresh appliance installation required; refusing existing %s. Do not delete appliance state to reinstall.\n' "$path" >&2; return 1; }
    done
    ports=$(select_appliance_ports "$wan" "$lan") || return 1
    read -r wan lan <<< "$ports"
    printf 'Selected WAN: %s (DHCP); LAN: %s (%s).\n' "$wan" "$lan" "$lan_address"
    systemctl is-active --quiet systemd-networkd.service || return 1
    systemctl is-active --quiet systemd-resolved.service || return 1
    apt-get update
    apt-get install --no-install-recommends -y ca-certificates gh procps kmod curl
    if pgrep -x netcontrold >/dev/null; then
        printf 'Stop the running netcontrold before installing; networking will not be stopped automatically.\n' >&2
        return 1
    fi
    local work cleanup help
    work=$(mktemp -d)
    printf -v cleanup 'rm -rf -- %q' "$work"
    trap "$cleanup" EXIT
    download_prebuilt "$run_id" "$work"
    cd "$work"
    chmod 0755 netcontrold
    help=$(./netcontrold --help) || return 1
    if ! grep -q -- --provision-wan <<< "$help" ||
       ! grep -q NETCONTROL_ALLOW_HOST_SERVICES <<< "$help" ||
       ! grep -q NETCONTROL_GATEWAY_MONITORING <<< "$help" ||
       ! grep -q NETCONTROL_SSH_LISTEN <<< "$help" ||
       ! grep -q NETCONTROL_UPGRADE_CONFIG <<< "$help" ||
       ! grep -q -- --configure-updates <<< "$help"; then
        printf 'Artifact lacks current appliance provisioning/service/SSH environment support. Build the reviewed current source; no older-contract fallback is provided.\n' >&2
        return 1
    fi
    check_systemd_unit
    configure_conntrack || return 1
    configure_link_diagnostics || return 1
    configure_deny_logging || return 1
    install -d -m 0755 /usr/local/sbin
    install -m 0755 netcontrold /usr/local/sbin/netcontrold
    install_systemd_service
    provision_appliance /usr/local/sbin/netcontrold "$wan" "$lan" "$lan_address"
    printf 'Provisioned IPv4 firewall: LAN %s (%s), WAN %s, LAN-to-WAN forwarding and masquerade. Service enabled at boot.\nManagement: http://%s:8080/ (complete onboarding from LAN).\nConfiguration SSH: TCP 2222, username apikey, password is an API key generated after onboarding; no OS shell or separate sshd.\nLAN clients need addresses in this subnet and this appliance as gateway; no DHCP/DNS server was installed.\nLogs: journalctl -u netcontrold -f\n' "$lan" "$lan_address" "$wan" "${lan_address%/*}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi