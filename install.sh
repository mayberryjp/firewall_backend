#!/usr/bin/env bash
set -euo pipefail

check_systemd_unit() {
    local unit=netcontrold.service
    local destination=/etc/systemd/system/netcontrold.service
    if [[ -L $destination ]] || { [[ -e $destination ]] && ! cmp -s "$unit" "$destination"; }; then
        printf 'Existing %s differs from the supplied unit; refusing to overwrite it. Use systemd drop-ins for customization.\n' "$destination" >&2
        return 1
    fi
}

install_systemd_service() {
    check_systemd_unit || return 1
    install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys
    install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service
    systemctl daemon-reload
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
        printf 'Usage: bash install.sh --run-id SUCCESSFUL_BUILD_RUN_ID [--wan WAN_NIC --lan LAN_NIC] [--lan-address 192.168.0.1/24]\nDefaults: first physical Ethernet port (natural name order) is DHCP WAN, second is LAN; LAN allows all traffic, WAN denies unsolicited inbound, LAN-to-WAN traffic is NATed. Provisions LAN-address HTTP management and enables the service at boot. Requires console access and networkd/resolved. LAN clients need static addressing; no DHCP server is installed.\n'
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
    apt-get install --no-install-recommends -y ca-certificates gh procps curl
    if pgrep -x netcontrold >/dev/null; then
        printf 'Stop the running netcontrold before installing; networking will not be stopped automatically.\n' >&2
        return 1
    fi
    local work cleanup
    work=$(mktemp -d)
    printf -v cleanup 'rm -rf -- %q' "$work"
    trap "$cleanup" EXIT
    download_prebuilt "$run_id" "$work"
    cd "$work"
    chmod 0755 netcontrold
    ./netcontrold --help | grep -- --provision-wan >/dev/null || {
        printf 'Artifact lacks appliance provisioning. Build the reviewed current source; no older-contract fallback is provided.\n' >&2
        return 1
    }
    check_systemd_unit
    install -d -m 0755 /usr/local/sbin
    install -m 0755 netcontrold /usr/local/sbin/netcontrold
    install_systemd_service
    provision_appliance /usr/local/sbin/netcontrold "$wan" "$lan" "$lan_address"
    printf 'Provisioned IPv4 firewall: LAN %s (%s), WAN %s, LAN-to-WAN forwarding and masquerade. Service enabled at boot.\nManagement: http://%s:8080/ (complete onboarding from LAN). LAN clients need addresses in this subnet and this appliance as gateway; no DHCP/DNS server was installed.\nLogs: journalctl -u netcontrold -f\n' "$lan" "$lan_address" "$wan" "${lan_address%/*}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi