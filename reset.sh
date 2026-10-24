#!/usr/bin/env bash
set -euo pipefail

reset_repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$reset_repository/install.sh"
source "$reset_repository/upgrade.sh"

confirm_reset() {
    [[ $1 == true ]] && return 0
    local answer
    printf 'Factory reset replaces networking and may disconnect SSH. Use a local console. Credentials and keys are retained.\n' >&2
    if read -r -p 'Restore factory network settings? [y/N] ' answer; then
        case $answer in
            [yY]|[yY][eE][sS]) return 0 ;;
        esac
    fi
    printf 'Factory reset cancelled; nothing changed.\n' >&2
    return 1
}

retire_wifi_recovery() {
    local recovery="$1/00-00-wifi-recovery.network" backup=$2
    [[ -e $recovery || -L $recovery ]] || return 0
    [[ -f $recovery && ! -L $recovery ]] || {
        printf 'Refusing a symlink or non-regular Wi-Fi recovery override: %s\n' "$recovery" >&2
        return 1
    }
    mv -- "$recovery" "$backup/wifi-recovery.network" || return 1
    printf 'Temporary Wi-Fi networkd override moved into reset backup.\n'
}

reset_appliance() {
    local binary=$1 wan=$2 lan=$3 address=$4
    "$binary" --backend linux --appliance --factory-reset \
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
}

main() {
    local confirmed=false wan='' lan='' address=192.168.0.1/24 binary='' installed ports backup path
    if [[ ${1:-} == --help ]]; then
        printf 'Usage: sudo bash reset.sh\nAsks for confirmation before restoring factory networking. Use --yes to skip the prompt for unattended use.\nOptional overrides: [--wan WAN_NIC --lan LAN_NIC] [--lan-address 192.168.0.1/24] [--binary PATH]\nExplicitly replaces saved networking with factory defaults, reinstalls the appliance service and starts/enables it. Default first/second physical Ethernet ports are WAN/LAN. Requires an existing saved configuration and local console access. Preserves credentials, keys and transaction history. No WAN lease is required to finish reset.\n'
        return
    fi
    while [[ $# -gt 0 ]]; do
        case $1 in
            --yes) confirmed=true; shift ;;
            --wan|--lan|--lan-address|--binary)
                [[ $# -ge 2 ]] || { printf 'Missing option value.\n' >&2; return 1; }
                case $1 in
                    --wan) wan=$2 ;;
                    --lan) lan=$2 ;;
                    --lan-address) address=$2 ;;
                    --binary) binary=$2 ;;
                esac
                shift 2 ;;
            *) printf 'Unknown reset option: %s\n' "$1" >&2; return 1 ;;
        esac
    done
    confirm_reset "$confirmed" || return 1
    [[ $EUID -eq 0 && $(uname -s) == Linux && -d /run/systemd/system ]] || {
        printf 'Run reset.sh as root on Ubuntu with systemd.\n' >&2; return 1;
    }
    local ID
    . /etc/os-release
    [[ ${ID:-} == ubuntu && $(dpkg --print-architecture) == amd64 ]] || return 1
    mkdir -p "$reset_repository/target/in-place-upgrade" || return 1
    exec 9>"$reset_repository/target/in-place-upgrade/upgrade.lock"
    flock -n 9 || { printf 'Another upgrade/reset is running from this checkout.\n' >&2; return 1; }
    [[ -f /var/lib/netcontrol/native-state.json && ! -L /var/lib/netcontrol/native-state.json ]] || {
        printf 'No saved configuration; use install.sh for initial provisioning.\n' >&2; return 1;
    }
    [[ $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || return 1
    ports=$(select_appliance_ports "$wan" "$lan") || return 1
    read -r wan lan <<< "$ports"
    installed=$(service_target) || return 1
    binary=${binary:-$installed}
    [[ -f $binary && ! -L $binary ]] || return 1
    binary=$(readlink -f -- "$binary") || return 1
    "$binary" --help | grep -F -- '--factory-reset' >/dev/null || {
        printf 'Binary lacks factory reset support; build the current source with bash upgrade.sh --build-only and pass --binary PATH.\n' >&2; return 1;
    }
    systemctl is-active --quiet systemd-networkd.service || return 1
    systemctl is-active --quiet systemd-resolved.service || return 1
    for path in /usr/local/sbin/netcontrold /etc/systemd/system/netcontrold.service /etc/netcontrol/appliance.env; do
        [[ ! -L $path && ( ! -e $path || -f $path ) ]] || {
            printf 'Refusing a symlink or non-regular reset destination: %s\n' "$path" >&2; return 1;
        }
    done
    printf 'Factory reset: WAN %s (DHCP), LAN %s (%s). Other saved Ethernet interfaces become unassigned without IP/DHCP configuration. Use the local console.\n' "$wan" "$lan" "$address"
    systemctl stop netcontrold.service || return 1
    no_unmanaged_daemon || return 1
    backup=$(mktemp -d /var/lib/netcontrol/factory-reset.XXXXXX) || return 1
    chmod 0700 "$backup" || return 1
    for path in /var/lib/netcontrol/native-state.json /var/lib/netcontrol/services \
        /etc/netcontrol/appliance.env /etc/systemd/system/netcontrold.service; do
        if [[ -e $path ]]; then cp -a -- "$path" "$backup/" || return 1; fi
    done
    cp -a -- "$installed" "$backup/netcontrold" || return 1
    printf 'Private pre-reset backup: %s\n' "$backup"
    retire_wifi_recovery /run/systemd/network "$backup" || return 1
    install -d -m 0755 /usr/local/sbin || return 1
    if [[ $binary != /usr/local/sbin/netcontrold ]]; then
        install -o root -g root -m 0755 -- "$binary" /usr/local/sbin/netcontrold || return 1
    fi
    install -m 0644 "$reset_repository/packaging/native/netcontrold.service" /etc/systemd/system/netcontrold.service || return 1
    if ! reset_appliance /usr/local/sbin/netcontrold "$wan" "$lan" "$address"; then
        systemctl stop netcontrold.service || true
        printf 'Factory reset failed; service left stopped. Preserve the journal/recovery intent and inspect logs. Backup: %s\n' "$backup" >&2
        return 1
    fi
    printf 'Factory configuration applied. Management: http://%s:8080/ . Credentials and keys retained. WAN DHCP continues independently.\n' "${address%/*}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi