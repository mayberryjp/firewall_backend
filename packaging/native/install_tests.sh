#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
source ./install.sh
temporary=$(mktemp -d)
printf -v cleanup 'rm -rf -- %q' "$temporary"
trap "$cleanup" EXIT
scenario=valid

for fresh_scenario in clean unused_lock active_lock nonempty_lock private_mode directory_lock symlink_lock dangling_lock hardlink_lock saved_state empty_state environment state_symlink environment_symlink; do
    fresh_directory="$temporary/fresh-$fresh_scenario"
    mkdir "$fresh_directory"
    fresh_state="$fresh_directory/state.json"
    fresh_environment="$fresh_directory/appliance.env"
    fresh_lock="$fresh_state.lock"
    if [[ $fresh_scenario != clean ]]; then
        : > "$fresh_lock"
        chmod 0600 "$fresh_lock"
    fi
    case $fresh_scenario in
        active_lock) exec {fresh_fd}<>"$fresh_lock"; flock --exclusive "$fresh_fd" ;;
        nonempty_lock) printf 'foreign data\n' > "$fresh_lock" ;;
        private_mode) chmod 0644 "$fresh_lock" ;;
        directory_lock) rm "$fresh_lock"; mkdir "$fresh_lock" ;;
        symlink_lock) mv "$fresh_lock" "$fresh_directory/target"; ln -s target "$fresh_lock" ;;
        dangling_lock) rm "$fresh_lock"; ln -s missing "$fresh_lock" ;;
        hardlink_lock) ln "$fresh_lock" "$fresh_directory/other" ;;
        saved_state) printf 'saved configuration\n' > "$fresh_state" ;;
        empty_state) : > "$fresh_state" ;;
        environment) printf 'NETCONTROL_LISTEN=192.0.2.1:8080\n' > "$fresh_environment" ;;
        state_symlink) ln -s missing "$fresh_state" ;;
        environment_symlink) ln -s missing "$fresh_environment" ;;
    esac
    if [[ $fresh_scenario != clean ]]; then
        fresh_identity=$(stat -c '%d:%i:%s:%a:%h' -- "$fresh_lock")
    fi
    if check_fresh_installation "$fresh_state" "$fresh_environment"; then
        [[ $fresh_scenario == clean || $fresh_scenario == unused_lock ]] || exit 1
    else
        [[ $fresh_scenario != clean && $fresh_scenario != unused_lock ]] || exit 1
    fi
    if [[ $fresh_scenario != clean ]]; then
        [[ $(stat -c '%d:%i:%s:%a:%h' -- "$fresh_lock") == "$fresh_identity" ]]
    fi
    if [[ $fresh_scenario == active_lock ]]; then
        flock --unlock "$fresh_fd"
        exec {fresh_fd}>&-
        check_fresh_installation "$fresh_state" "$fresh_environment"
    fi
done
printf 'Fresh installation retry, active/unsafe lock refusal and saved-state protection tests passed.\n'

for conntrack_scenario in success repeat module_failure write_failure read_failure verify_failure checksum_failure persist_failure symlink_sysctl symlink_modules; do
    conntrack_directory="$temporary/conntrack-$conntrack_scenario"
    mkdir -p "$conntrack_directory/sysctl.d" "$conntrack_directory/modules-load.d"
    printf 'unrelated configuration\n' > "$conntrack_directory/sysctl.d/10-unrelated.conf"
    if [[ $conntrack_scenario == symlink_sysctl ]]; then
        ln -s 10-unrelated.conf "$conntrack_directory/sysctl.d/90-netcontrol-conntrack.conf"
        if [[ ! -L $conntrack_directory/sysctl.d/90-netcontrol-conntrack.conf ]]; then
            printf 'Skipped sysctl symlink refusal: filesystem did not create a symlink.\n'
            continue
        fi
    elif [[ $conntrack_scenario == symlink_modules ]]; then
        ln -s ../sysctl.d/10-unrelated.conf "$conntrack_directory/modules-load.d/netcontrol-conntrack.conf"
        if [[ ! -L $conntrack_directory/modules-load.d/netcontrol-conntrack.conf ]]; then
            printf 'Skipped modules symlink refusal: filesystem did not create a symlink.\n'
            continue
        fi
    fi
    if (
        modprobe() {
            printf 'modprobe %s\n' "$*" >> "$conntrack_directory/commands"
            [[ $* == nf_conntrack ]] || return 1
            [[ $conntrack_scenario != module_failure ]]
        }
        sysctl() {
            printf 'sysctl %s\n' "$*" >> "$conntrack_directory/commands"
            if [[ $1 == -w ]]; then
                [[ $* == '-w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_checksum=1' ]] || return 1
                [[ $conntrack_scenario != write_failure ]]
            elif [[ $conntrack_scenario == verify_failure ||
                ( $conntrack_scenario == checksum_failure && $2 == net.netfilter.nf_conntrack_checksum ) ]]; then
                printf '0\n'
            else
                printf '1\n'
                [[ $conntrack_scenario != read_failure ]]
            fi
        }
        install() {
            [[ $conntrack_scenario != persist_failure ]] || return 1
            local -a arguments=()
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -o|-g) shift 2 ;;
                    *) arguments+=("$1"); shift ;;
                esac
            done
            command install "${arguments[@]}"
        }
        configure_conntrack "$conntrack_directory/sysctl.d" "$conntrack_directory/modules-load.d" || exit 1
        if [[ $conntrack_scenario == repeat ]]; then
            configure_conntrack "$conntrack_directory/sysctl.d" "$conntrack_directory/modules-load.d" || exit 1
        fi
    ); then
        [[ $conntrack_scenario == success || $conntrack_scenario == repeat ]] || exit 1
        [[ $(< "$conntrack_directory/sysctl.d/90-netcontrol-conntrack.conf") == $'net.netfilter.nf_conntrack_acct = 1\nnet.netfilter.nf_conntrack_checksum = 1' ]]
        [[ $(< "$conntrack_directory/modules-load.d/netcontrol-conntrack.conf") == nf_conntrack ]]
        grep -q '^modprobe nf_conntrack$' "$conntrack_directory/commands"
        grep -q '^sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_checksum=1$' "$conntrack_directory/commands"
    else
        [[ $conntrack_scenario != success ]] || exit 1
        [[ ! -f $conntrack_directory/modules-load.d/netcontrol-conntrack.conf || -L $conntrack_directory/modules-load.d/netcontrol-conntrack.conf ]]
        if [[ $conntrack_scenario == symlink_* ]]; then
            [[ ! -e $conntrack_directory/commands ]]
        elif [[ $conntrack_scenario == module_failure ]]; then
            ! grep -q '^sysctl ' "$conntrack_directory/commands"
        fi
    fi
    [[ $(< "$conntrack_directory/sysctl.d/10-unrelated.conf") == 'unrelated configuration' ]]
done
printf 'Conntrack live settings, boot persistence and prerequisite-failure tests passed (mocked kernel commands).\n'

for diagnostics_scenario in success repeat module_failure persist_failure symlink_file; do
    diagnostics_directory="$temporary/link-diagnostics-$diagnostics_scenario"
    mkdir -p "$diagnostics_directory"
    printf 'unrelated\n' > "$diagnostics_directory/other.conf"
    if [[ $diagnostics_scenario == symlink_file ]]; then
        ln -s other.conf "$diagnostics_directory/netcontrol-link-diagnostics.conf"
    fi
    if (
        modprobe() {
            printf '%s\n' "$*" >> "$diagnostics_directory/commands"
            [[ $diagnostics_scenario != module_failure ]]
        }
        install() {
            [[ $diagnostics_scenario != persist_failure ]] || return 1
            local -a arguments=()
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -o|-g) shift 2 ;;
                    *) arguments+=("$1"); shift ;;
                esac
            done
            command install "${arguments[@]}"
        }
        configure_link_diagnostics "$diagnostics_directory" || exit 1
        if [[ $diagnostics_scenario == repeat ]]; then
            configure_link_diagnostics "$diagnostics_directory" || exit 1
        fi
    ); then
        [[ $diagnostics_scenario == success || $diagnostics_scenario == repeat ]] || exit 1
        [[ $(< "$diagnostics_directory/netcontrol-link-diagnostics.conf") == $'af_packet\ninet_diag\ntcp_diag' ]]
        [[ $(head -n 3 "$diagnostics_directory/commands") == $'af_packet\ninet_diag\ntcp_diag' ]]
    else
        [[ $diagnostics_scenario != success && $diagnostics_scenario != repeat ]] || exit 1
        [[ ! -f $diagnostics_directory/netcontrol-link-diagnostics.conf ||
           -L $diagnostics_directory/netcontrol-link-diagnostics.conf ]] || exit 1
    fi
    [[ $(< "$diagnostics_directory/other.conf") == unrelated ]]
done
printf 'Native link diagnostics module setup and failure tests passed (mocked kernel commands).\n'

for deny_scenario in success repeat counter_in_core tables_failure nfnetlink_failure log_failure persist_failure symlink_file; do
    deny_directory="$temporary/deny-log-$deny_scenario"
    mkdir -p "$deny_directory"
    printf 'unrelated\n' > "$deny_directory/other.conf"
    if [[ $deny_scenario == symlink_file ]]; then
        ln -s other.conf "$deny_directory/netcontrol-deny-log.conf"
    else
        printf 'previous modules\n' > "$deny_directory/netcontrol-deny-log.conf"
    fi
    if (
        modprobe() {
            printf '%s\n' "$*" >> "$deny_directory/commands"
            [[ ( $deny_scenario != tables_failure || $1 != nf_tables ) &&
               ( $deny_scenario != nfnetlink_failure || $1 != nfnetlink_log ) &&
               ( $deny_scenario != log_failure || $1 != nft_log ) &&
               ( $deny_scenario != counter_in_core || $1 != nft_counter ) ]]
        }
        install() {
            [[ $deny_scenario != persist_failure ]] || return 1
            local -a arguments=()
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -o|-g) shift 2 ;;
                    *) arguments+=("$1"); shift ;;
                esac
            done
            command install "${arguments[@]}"
        }
        configure_deny_logging "$deny_directory" || exit 1
        if [[ $deny_scenario == repeat ]]; then
            configure_deny_logging "$deny_directory" || exit 1
        fi
    ); then
        [[ $deny_scenario == success || $deny_scenario == repeat || $deny_scenario == counter_in_core ]] || exit 1
        [[ $(< "$deny_directory/netcontrol-deny-log.conf") == $'nf_tables\nnfnetlink_log\nnft_log' ]]
        deny_commands=$'nf_tables\nnfnetlink_log\nnft_log'
        if [[ $deny_scenario == repeat ]]; then
            deny_commands+=$'\nnf_tables\nnfnetlink_log\nnft_log'
        fi
        [[ $(< "$deny_directory/commands") == "$deny_commands" ]]
    else
        [[ $deny_scenario != success && $deny_scenario != repeat && $deny_scenario != counter_in_core ]] || exit 1
        [[ -L $deny_directory/netcontrol-deny-log.conf ||
           $(< "$deny_directory/netcontrol-deny-log.conf") == 'previous modules' ]] || exit 1
    fi
    [[ $(< "$deny_directory/other.conf") == unrelated ]]
done
printf 'Firewall telemetry provider, core counter support and prerequisite/publication failure tests passed (mocked kernel commands).\n'

for service_scenario in success repeat directory_failure chmod_failure publish_failure symlink_file symlink_directory file_directory nonregular_target; do
    service_directory="$temporary/service-opt-ins-$service_scenario"
    mkdir -p "$service_directory/drop-ins"
    printf 'custom unit\n' > "$service_directory/unit"
    printf '[Service]\nEnvironment=CUSTOM_SETTING=preserved\n' > "$service_directory/drop-ins/99-custom.conf"
    service_target="$service_directory/drop-ins/50-netcontrol-appliance-services.conf"
    printf 'previous managed settings\n' > "$service_target"
    case $service_scenario in
        symlink_file)
            rm "$service_target"
            ln -s 99-custom.conf "$service_target" ;;
        symlink_directory)
            mv "$service_directory/drop-ins" "$service_directory/original"
            ln -s original "$service_directory/drop-ins" ;;
        file_directory)
            rm "$service_target"
            rm "$service_directory/drop-ins/99-custom.conf"
            rmdir "$service_directory/drop-ins"
            printf 'not a directory\n' > "$service_directory/drop-ins" ;;
        nonregular_target)
            rm "$service_target"
            mkdir "$service_target" ;;
    esac
    if (
        install() {
            [[ $service_scenario != directory_failure ]] || return 1
            local -a arguments=()
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -o|-g) shift 2 ;;
                    *) arguments+=("$1"); shift ;;
                esac
            done
            command install "${arguments[@]}"
        }
        chmod() { [[ $service_scenario != chmod_failure ]] && command chmod "$@"; }
        mv() { [[ $service_scenario != publish_failure ]] && command mv "$@"; }
        configure_appliance_services "$service_directory/drop-ins" || exit 1
        if [[ $service_scenario == repeat ]]; then
            configure_appliance_services "$service_directory/drop-ins" || exit 1
        fi
    ); then
        [[ $service_scenario == success || $service_scenario == repeat ]] || exit 1
        [[ $(< "$service_target") == $'[Unit]\nRequires=netcontrol-syslog.socket\nAfter=netcontrol-syslog.socket systemd-journald.service\nStartLimitIntervalSec=0\n\n[Service]\nType=notify\nNotifyAccess=main\nWatchdogSec=60s\nWatchdogSignal=SIGKILL\nTimeoutStartSec=180s\nRestart=on-failure\nRestartSec=5s\nLimitCORE=0\nSockets=netcontrol-syslog.socket\nEnvironment=NETCONTROL_ALLOW_HOST_SERVICES=true\nEnvironment=NETCONTROL_GATEWAY_MONITORING=true\nEnvironment=NETCONTROL_SSH_LISTEN=0.0.0.0:2222\nEnvironment=NETCONTROL_UPGRADE_CONFIG=/etc/netcontrol/updates.json' ]]
    else
        [[ $service_scenario != success && $service_scenario != repeat ]] || exit 1
        if [[ $service_scenario == *_failure ]]; then
            [[ $(< "$service_target") == 'previous managed settings' ]]
        fi
    fi
    [[ $(< "$service_directory/unit") == 'custom unit' ]]
    if [[ $service_scenario != file_directory ]]; then
        [[ $(< "$service_directory/drop-ins/99-custom.conf") == $'[Service]\nEnvironment=CUSTOM_SETTING=preserved' ]]
        [[ -z $(find "$service_directory/drop-ins" -name '.appliance-services.*' -print) ]]
    fi
done
printf 'Appliance service opt-ins, repeat setup, custom-setting preservation and publication failure tests passed.\n'

for logging_setup in success repeat symlink_file symlink_directory publish_failure; do
    logging_root="$temporary/logging-setup-$logging_setup"
    mkdir -p "$logging_root/systemd/system" "$logging_root/systemd/journald.conf.d"
    printf 'operator config\n' > "$logging_root/systemd/journald.conf.d/99-operator.conf"
    case $logging_setup in
        symlink_file) ln -s 99-operator.conf "$logging_root/systemd/journald.conf.d/90-netcontrol-syslog.conf" ;;
        symlink_directory)
            mv "$logging_root/systemd/journald.conf.d" "$logging_root/original"
            ln -s ../original "$logging_root/systemd/journald.conf.d" ;;
    esac
    if (
        # Ownership options need root; CI runs these tests unprivileged.
        install() {
            local -a arguments=()
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -o|-g) shift 2 ;;
                    *) arguments+=("$1"); shift ;;
                esac
            done
            command install "${arguments[@]}"
        }
        mv() { [[ $logging_setup != publish_failure ]] && command mv "$@"; }
        configure_logging_units "$logging_root" || exit 1
        if [[ $logging_setup == repeat ]]; then configure_logging_units "$logging_root" || exit 1; fi
    ); then
        [[ $logging_setup == success || $logging_setup == repeat ]] || exit 1
        [[ $(< "$logging_root/systemd/journald.conf.d/90-netcontrol-syslog.conf") == $'[Journal]\nForwardToSyslog=yes\nMaxLevelSyslog=debug\nReadKMsg=yes' ]]
        for directive in PartOf=netcontrold.service ListenDatagram=/run/systemd/journal/syslog SocketMode=0600 Service=netcontrold.service FileDescriptorName=netcontrol-syslog RemoveOnStop=yes; do
            grep -Fxq "$directive" "$logging_root/systemd/system/netcontrol-syslog.socket"
        done
    else
        [[ $logging_setup != success && $logging_setup != repeat ]] || exit 1
    fi
    [[ $(< "$logging_root/systemd/journald.conf.d/99-operator.conf") == 'operator config' ]]
    [[ -z $(find "$logging_root" -name '.netcontrol-logging.*' -print) ]]
done
printf 'Managed journald forwarding and socket-unit persistence, idempotency and safe publication tests passed.\n'

for logging_scenario in stopped repeat missing query_failure mask_failure active_failure still_active unknown_state masked_alias error_enabled input_failure restart_failure regular symlink; do
    logging_directory="$temporary/logging-$logging_scenario"
    mkdir "$logging_directory"
    printf 'preserve\n' > "$logging_directory/operator"
    if [[ $logging_scenario == regular ]]; then
        printf 'not a socket\n' > "$logging_directory/log"
    elif [[ $logging_scenario == symlink ]]; then
        ln -s operator "$logging_directory/log"
    fi
    if (
        systemctl() {
            printf '%s\n' "$*" >> "$logging_directory/commands"
            case $1 in
                show)
                    if [[ $* == *LoadState* ]]; then
                        case $logging_scenario in
                            missing) printf 'not-found\n'; return 4 ;;
                            query_failure) return 1 ;;
                            unknown_state) printf 'error\n' ;;
                            masked_alias) [[ $2 == syslog.service ]] && printf 'error\n' || printf 'loaded\n' ;;
                            error_enabled) printf 'error\n' ;;
                            repeat) printf 'masked\n' ;;
                            *) printf 'loaded\n' ;;
                        esac
                    else
                        case $logging_scenario in
                            active_failure) return 1 ;;
                            still_active) printf 'active\n' ;;
                            *) printf 'inactive\n' ;;
                        esac
                    fi ;;
                mask) [[ $logging_scenario != mask_failure ]] ;;
                is-enabled) [[ $logging_scenario == masked_alias ]] && printf 'masked\n' || { [[ $logging_scenario == error_enabled ]] && printf 'enabled\n'; return 1; } ;;
                start) [[ $* == 'start systemd-journald-dev-log.socket' && $logging_scenario != input_failure ]] ;;
                restart) [[ $* == 'restart systemd-journald.service' && $logging_scenario != restart_failure ]] ;;
                *) return 1 ;;
            esac
        }
        configure_host_logging "$logging_directory/log" "$logging_directory/unix"
    ); then
        case $logging_scenario in stopped|repeat|missing|masked_alias) ;; *) exit 1 ;; esac
        grep -Fxq 'start systemd-journald-dev-log.socket' "$logging_directory/commands"
        grep -Fxq 'restart systemd-journald.service' "$logging_directory/commands"
    else
        case $logging_scenario in stopped|repeat|missing|masked_alias) exit 1 ;; esac
    fi
    ! grep -Eq '^(mask|stop).*systemd-journald' "$logging_directory/commands"
    [[ $(< "$logging_directory/operator") == preserve ]]
    if [[ $logging_scenario == regular || $logging_scenario == symlink ]]; then
        [[ -e $logging_directory/log ]]
        ! grep -q '^restart ' "$logging_directory/commands"
    fi
    if [[ $logging_scenario == masked_alias ]]; then
        grep -Fxq 'mask --now rsyslog.service' "$logging_directory/commands"
        ! grep -Fxq 'mask --now syslog.service' "$logging_directory/commands"
    fi
    if [[ $logging_scenario == stopped || $logging_scenario == repeat ]]; then
        for logging_unit in rsyslog.service syslog-ng.service syslog.service syslogd.service busybox-syslogd.service syslog.socket; do
            grep -Fxq "mask --now $logging_unit" "$logging_directory/commands"
        done
    fi
done
printf 'Competing receiver masking, journald input preservation/restart and failure tests passed (mocked systemd).\n'

ports_fixture="$temporary/ports"
mkdir -p "$ports_fixture"
for port_fixture_name in eno10 eno2 eno1 wlan0 lo tun0; do
    mkdir -p "$ports_fixture/$port_fixture_name"
    printf '1\n' > "$ports_fixture/$port_fixture_name/type"
done
for port_fixture_name in eno10 eno2 eno1 wlan0; do mkdir "$ports_fixture/$port_fixture_name/device"; done
mkdir "$ports_fixture/wlan0/wireless"
[[ $(select_appliance_ports '' '' "$ports_fixture") == 'eno1 eno2' ]]
[[ $(select_appliance_ports eno10 eno1 "$ports_fixture") == 'eno10 eno1' ]]
for port_fixture_pair in 'eno1 eno1' 'eno1 missing' 'wlan0 eno1' 'eno1'; do
    read -r fixture_wan fixture_lan <<< "$port_fixture_pair"
    if select_appliance_ports "$fixture_wan" "$fixture_lan" "$ports_fixture"; then exit 1; fi
done
[[ $(prompt_appliance_lan '' '' '' "$ports_fixture" <<< $'eno10\n10.4.50.1/24') == 'eno1 eno10 10.4.50.1/24' ]]
[[ $(prompt_appliance_lan '' '' '' "$ports_fixture" <<< $'\n') == 'eno1 eno2 192.168.0.1/24' ]]
[[ $(prompt_appliance_lan eno2 '' '' "$ports_fixture" <<< $'\n') == 'eno2 eno1 192.168.0.1/24' ]]
[[ $(prompt_appliance_lan eno1 eno10 '' "$ports_fixture" <<< '10.4.50.1/24') == 'eno1 eno10 10.4.50.1/24' ]]
[[ $(prompt_appliance_lan eno1 '' '10.4.50.1/24' "$ports_fixture" <<< 'eno10') == 'eno1 eno10 10.4.50.1/24' ]]
[[ $(prompt_appliance_lan eno1 '' '' "$ports_fixture" <<< $'missing\neno2\ninvalid\n192.168.0.0/24\n10.4.50.1/24') == 'eno1 eno2 10.4.50.1/24' ]]
if prompt_appliance_lan '' '' '' "$ports_fixture" </dev/null; then exit 1; fi
if prompt_appliance_lan eno1 eno2 '' "$ports_fixture" </dev/null; then exit 1; fi
if prompt_appliance_lan missing '' '' "$ports_fixture" </dev/null 2>"$temporary/invalid-wan"; then exit 1; fi
! grep -q '^LAN interface' "$temporary/invalid-wan"
for address in 10.4.50.1/24 172.16.0.1/12 192.168.0.1/16 10.0.0.1/30; do
    valid_lan_address "$address"
done
for address in 10.4.50.0/24 10.4.50.255/24 192.168.0.1/15 172.16.0.1/11 172.32.0.1/24 8.8.8.8/24 999.1.1.1/24 10.0.0.1/31 010.0.0.1/24 10.0.0.1/08 '10.0.0.1/24 extra'; do
    if valid_lan_address "$address"; then printf 'Invalid LAN address accepted: %s\n' "$address" >&2; exit 1; fi
done
printf 'Interactive LAN selection, address validation, defaults, overrides and cancellation tests passed.\n'
mkdir "$ports_fixture/vlan50" "$ports_fixture/wanvlan" "$ports_fixture/stacked"
printf '1\n' > "$ports_fixture/vlan50/type"
printf '1\n' > "$ports_fixture/wanvlan/type"
printf '1\n' > "$ports_fixture/stacked/type"
vlan_fixture="$temporary/vlans"
printf 'VLAN Dev name | VLAN ID | Interface\nvlan50 | 50 | eno2\nwanvlan | 20 | eno1\nstacked | 51 | vlan50\n' > "$vlan_fixture"
[[ $(lan_vlan_details vlan50 "$vlan_fixture") == 'eno2 50' ]]
[[ $(select_appliance_ports eno1 vlan50 "$ports_fixture" "$vlan_fixture") == 'eno1 vlan50' ]]
[[ $(prompt_appliance_lan eno1 '' '' "$ports_fixture" "$vlan_fixture" <<< $'vlan50\n10.4.50.1/24') == 'eno1 vlan50 10.4.50.1/24' ]]
if select_appliance_ports eno1 wanvlan "$ports_fixture" "$vlan_fixture"; then exit 1; fi
if select_appliance_ports eno1 stacked "$ports_fixture" "$vlan_fixture"; then exit 1; fi
printf 'invalid | 4095 | eno2\n' >> "$vlan_fixture"
if lan_vlan_details invalid "$vlan_fixture"; then exit 1; fi
printf 'vlan50 | 50 | eno2\n' >> "$vlan_fixture"
if lan_vlan_details vlan50 "$vlan_fixture"; then exit 1; fi
printf 'Existing VLAN LAN selection and unsafe topology refusal tests passed.\n'
mkdir "$temporary/one-port"
mv "$ports_fixture/eno1" "$temporary/one-port/"
if select_appliance_ports '' '' "$temporary/one-port"; then exit 1; fi
printf 'Automatic Ethernet port selection and override validation passed.\n'

curl() {
    local url=${!#} output='' limit=''
    [[ $* == *"--proto =https --proto-redir =https --tlsv1.2 --fail --location"* ]] || return 1
    while [[ $# -gt 1 ]]; do
        case $1 in
            --output) output=$2; shift 2 ;;
            --max-filesize) limit=$2; shift 2 ;;
            *) shift ;;
        esac
    done
    printf '%s\n' "$url" >> "$fixture/downloads"
    case $url in
        https://api.github.com/repos/mayberryjp/firewall_backend/releases/latest)
            [[ $limit == 1048576 && $scenario != api_failure && $scenario != no_release ]] || return 1
            cp "$fixture/release.json" "$output" ;;
        https://github.com/mayberryjp/firewall_backend/releases/download/v2026.11.05.2/netcontrol-ubuntu-amd64.json)
            [[ $limit == 4096 && $scenario != missing_manifest ]] || return 1
            cp "$fixture/manifest.json" "$output" ;;
        https://github.com/mayberryjp/firewall_backend/releases/download/v2026.11.05.2/netcontrold-ubuntu-amd64)
            [[ $limit == 268435456 && $scenario != missing_binary ]] || return 1
            cp "$fixture/binary" "$output"
            if [[ $scenario == tampered_binary ]]; then printf x >> "$output"; fi ;;
        https://raw.githubusercontent.com/mayberryjp/firewall_backend/v2026.11.05.2/packaging/native/netcontrold.service)
            [[ $limit == 65536 && $scenario != missing_unit ]] || return 1
            if [[ $scenario == empty_unit ]]; then : > "$output"
            else cp packaging/native/netcontrold.service "$output"; fi ;;
        *) printf 'Unexpected release URL: %s\n' "$url" >&2; return 1 ;;
    esac
}

for scenario in valid api_failure no_release draft prerelease bad_tag invalid_date oversized_iteration \
    missing_asset duplicate_asset foreign_url malformed_metadata missing_manifest missing_binary \
    malformed_manifest duplicate_field unknown_field schema_bool wrong_schema wrong_version wrong_target \
    size_bool short_binary oversized_binary wrong_size bad_digest digest_mismatch tampered_binary \
    wrong_elf wrong_arch oversized_manifest missing_unit empty_unit; do
    fixture="$temporary/release-$scenario"
    mkdir "$fixture"
    python3 - "$fixture" "$scenario" <<'PY'
import hashlib
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
scenario = sys.argv[2]
binary = bytearray(64)
binary[:6] = b"\x7fELF\x02\x01"
binary[18:20] = b"\x3e\x00"
if scenario == "wrong_elf":
    binary[0] = 0
if scenario == "wrong_arch":
    binary[18] = 183
manifest = {"schema": 1, "version": "2026.11.05.2", "target": "ubuntu-amd64-systemd",
            "size": len(binary), "sha256": hashlib.sha256(binary).hexdigest()}
invalid = {
    "unknown_field": ("extra", True), "schema_bool": ("schema", True),
    "wrong_schema": ("schema", 2), "wrong_version": ("version", "2026.11.05.1"),
    "wrong_target": ("target", "other"), "size_bool": ("size", True),
    "short_binary": ("size", 63), "oversized_binary": ("size", 268435457),
    "wrong_size": ("size", 65), "bad_digest": ("sha256", "Z" * 64),
    "digest_mismatch": ("sha256", "0" * 64),
}
if scenario in invalid:
    key, value = invalid[scenario]
    manifest[key] = value
manifest_text = json.dumps(manifest)
if scenario == "duplicate_field":
    manifest_text = '{"schema":1,' + manifest_text[1:]
elif scenario == "malformed_manifest":
    manifest_text = "{"
elif scenario == "oversized_manifest":
    manifest_text += " " * 4096
base = "https://github.com/mayberryjp/firewall_backend/releases/download/v2026.11.05.2/"
release = {"tag_name": "v2026.11.05.2", "draft": False, "prerelease": False,
           "assets": [{"name": name, "browser_download_url": base + name}
                      for name in ("netcontrol-ubuntu-amd64.json", "netcontrold-ubuntu-amd64")]}
if scenario in ("draft", "prerelease"):
    release[scenario] = True
elif scenario == "bad_tag":
    release["tag_name"] = "../bad"
elif scenario == "invalid_date":
    release["tag_name"] = "v2026.02.30.1"
elif scenario == "oversized_iteration":
    release["tag_name"] = "v2026.11.05.4294967296"
elif scenario == "missing_asset":
    release["assets"].pop()
elif scenario == "duplicate_asset":
    release["assets"].append(release["assets"][0])
elif scenario == "foreign_url":
    release["assets"][0]["browser_download_url"] = "https://example.invalid/asset"
(directory / "release.json").write_text("{" if scenario == "malformed_metadata" else json.dumps(release))
(directory / "manifest.json").write_text(manifest_text)
(directory / "binary").write_bytes(binary)
PY
    destination="$temporary/$scenario"
    mkdir "$destination"
    if download_prebuilt "$destination"; then
        [[ $scenario == valid ]] || { printf 'Unexpected success: %s\n' "$scenario" >&2; exit 1; }
        [[ $(< "$destination/release-version") == 2026.11.05.2 ]]
        cmp "$destination/netcontrold.service" packaging/native/netcontrold.service
        [[ $(wc -l < "$fixture/downloads") -eq 4 ]]
    else
        [[ $scenario != valid ]] || { printf 'Valid release rejected\n' >&2; exit 1; }
        [[ ! -e $destination/release-version ]]
        if [[ $scenario != missing_unit && $scenario != empty_unit ]]; then
            ! grep -q raw.githubusercontent.com "$fixture/downloads"
        fi
    fi
done
unset -f curl
for scenario in valid wrong_version version_failure help_failure missing_option missing_takeover vlan_supported vlan_missing_parent vlan_missing_id vlan_unsupported; do
    destination="$temporary/prebuilt-$scenario"
    mkdir "$destination"
    printf '2026.11.05.2\n' > "$destination/release-version"
    cat > "$destination/netcontrold" <<'SH'
#!/usr/bin/env bash
case $1 in
    --version)
        [[ $prebuilt_scenario != version_failure ]] || exit 1
        if [[ $prebuilt_scenario == wrong_version ]]; then printf 'netcontrold 2026.11.05.1\n'
        else printf 'netcontrold 2026.11.05.2\n'; fi ;;
    --help)
        [[ $prebuilt_scenario != help_failure ]] || exit 1
        printf '%s\n' --provision-wan NETCONTROL_ALLOW_HOST_SERVICES NETCONTROL_GATEWAY_MONITORING NETCONTROL_SSH_LISTEN NETCONTROL_UPGRADE_CONFIG
        if [[ $prebuilt_scenario != missing_takeover ]]; then printf '%s\n' console-host-takeover; fi
        if [[ $prebuilt_scenario != missing_option ]]; then printf '%s\n' --configure-updates; fi
        if [[ $prebuilt_scenario == vlan_supported || $prebuilt_scenario == vlan_missing_id ]]; then printf '%s\n' --provision-lan-parent; fi
        if [[ $prebuilt_scenario == vlan_supported || $prebuilt_scenario == vlan_missing_parent ]]; then printf '%s\n' --provision-lan-vlan; fi ;;
    *) exit 1 ;;
esac
SH
    export prebuilt_scenario=$scenario
    selected_lan=''
    if [[ $scenario == vlan_* ]]; then selected_lan=vlan50; fi
    if (lan_vlan_details() { [[ $1 == vlan50 ]]; }; check_prebuilt "$destination" "$selected_lan"); then
        [[ $scenario == valid || $scenario == vlan_supported ]] || exit 1
    else
        [[ $scenario != valid && $scenario != vlan_supported ]] || exit 1
    fi
done
unset prebuilt_scenario
(
    [[ $(main --help) != *--run-id* ]]
    if main --run-id 123; then exit 1; fi
    uname() { printf 'unsupported-test-platform\n'; }
    if output=$(main 2>&1); then exit 1; fi
    [[ $output == *'requires Ubuntu Linux amd64'* ]]
)
printf 'Stable release download, verification, compiled version/options, pinned unit, failure and no-run-ID CLI tests passed.\n'

(
trace=''
check_systemd_unit() { return 0; }
install() { trace="$trace install $*;"; }
systemctl() { trace="$trace systemctl $*;"; }
configure_appliance_services() { trace+=' appliance-services;'; }
configure_logging_units() { trace+=' logging-units;'; }
configure_host_logging() { trace+=' host-logging;'; }
configure_snap() { trace+=' snap;'; }
configure_os_updates() { trace+=' os-updates;'; }
configure_upgrade_settings() { trace+=' upgrade-settings;'; }
install_systemd_service
[[ $trace == ' os-updates; snap;'* ]]
[[ $trace == *'install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys;'* ]]
[[ $trace == *'install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service;'* ]]
[[ $trace == *'systemctl daemon-reload;'* ]]
[[ $trace == *'appliance-services; logging-units; systemctl daemon-reload;'* ]]
[[ $trace == *'systemctl daemon-reload; host-logging;'* ]]
[[ $trace != *'systemctl start'* && $trace != *'systemctl enable'* ]]
trace=''
check_systemd_unit() { return 1; }
if install_systemd_service; then exit 1; fi
[[ -z $trace ]]
for failure_stage in os_updates snap upgrade_settings service_setup logging_units reload logging; do
    trace=''
    check_systemd_unit() { return 0; }
    configure_upgrade_settings() { trace+=' upgrade-settings;'; [[ $failure_stage != upgrade_settings ]]; }
    configure_appliance_services() { trace+=' appliance-services;'; [[ $failure_stage != service_setup ]]; }
    configure_logging_units() { trace+=' logging-units;'; [[ $failure_stage != logging_units ]]; }
    systemctl() { trace+=" systemctl $*;"; [[ $failure_stage != reload ]]; }
    configure_host_logging() { trace+=' host-logging;'; return 1; }
    configure_snap() { trace+=' snap;'; [[ $failure_stage != snap ]]; }
    configure_os_updates() { trace+=' os-updates;'; [[ $failure_stage != os_updates ]]; }
    if install_systemd_service; then exit 1; fi
    if [[ $failure_stage == os_updates ]]; then
        [[ $trace == ' os-updates;' ]]
        continue
    fi
    if [[ $failure_stage == snap ]]; then
        [[ $trace == ' os-updates; snap;' ]]
        continue
    fi
    if [[ $failure_stage == upgrade_settings ]]; then
        [[ $trace != *'appliance-services;'* ]]
        continue
    fi
    [[ $trace == *'appliance-services;'* ]]
    if [[ $failure_stage == service_setup || $failure_stage == logging_units ]]; then
        [[ $trace != *'systemctl daemon-reload;'* ]]
    else
        [[ $trace == *'systemctl daemon-reload;'* ]]
    fi
done
)
printf 'Prebuilt download verification and service-installation tests passed (mocked GitHub/system commands).\n'

for provision_scenario in success tagged_success config_failure env_failure reload_failure start_failure http_failure forwarding_failure; do
    provision_directory="$temporary/provision-$provision_scenario"
    mkdir "$provision_directory"
    selected_lan=lan0
    if [[ $provision_scenario == tagged_success ]]; then selected_lan=vlan50; fi
    if (
        lan_vlan_details() {
            [[ $provision_scenario == tagged_success && $1 == vlan50 ]] || return 1
            printf 'lan0 50\n'
        }
        provision_fixture() {
            printf 'configure %s\n' "$*" >> "$provision_directory/commands"
            [[ $provision_scenario != config_failure ]]
        }
        install() {
            printf 'install %s\n' "$*" >> "$provision_directory/commands"
            command cat > "$provision_directory/environment"
            [[ $provision_scenario != env_failure ]]
        }
        systemctl() {
            printf 'systemctl %s\n' "$*" >> "$provision_directory/commands"
            [[ $provision_scenario != reload_failure || $1 != daemon-reload ]] || return 1
            [[ $provision_scenario != start_failure || $1 != enable ]]
        }
        curl() {
            printf 'curl %s\n' "$*" >> "$provision_directory/commands"
            [[ $provision_scenario != http_failure ]]
        }
        sysctl() {
            if [[ $provision_scenario == forwarding_failure ]]; then printf '0\n'; else printf '1\n'; fi
        }
        provision_appliance provision_fixture wan0 "$selected_lan" 192.168.50.1/24
    ); then
        [[ $provision_scenario == success || $provision_scenario == tagged_success ]] || exit 1
    else
        [[ $provision_scenario != success && $provision_scenario != tagged_success ]] || exit 1
    fi
    grep -q -- "--provision-wan wan0 --provision-lan $selected_lan --provision-lan-address 192.168.50.1/24" "$provision_directory/commands"
    if [[ $provision_scenario == tagged_success ]]; then
        grep -q -- '--provision-lan-parent lan0 --provision-lan-vlan 50' "$provision_directory/commands"
    fi
    if [[ $provision_scenario == config_failure ]]; then
        ! grep -Eq '^(install|systemctl|curl) ' "$provision_directory/commands"
    else
        [[ $(< "$provision_directory/environment") == NETCONTROL_LISTEN=192.168.50.1:8080 ]]
    fi
    if [[ $provision_scenario == env_failure || $provision_scenario == reload_failure ]]; then
        ! grep -q '^systemctl enable' "$provision_directory/commands"
    fi
    if [[ $provision_scenario == success || $provision_scenario == tagged_success ]]; then
        grep -q '^systemctl enable --now netcontrold.service' "$provision_directory/commands"
        grep -q 'http://192.168.50.1:8080/' "$provision_directory/commands"
    fi
done
printf 'Appliance provisioning and prerequisite-failure ordering tests passed (mocked host commands).\n'

source ./upgrade.sh
for executable_path in /usr/local/sbin/netcontrold /usr/sbin/netcontrold /opt/netcontrol/netcontrold; do
    root_command() { printf '{ path=%s ; argv[]=%s --backend linux ; ignore_errors=no ; }\n' "$executable_path" "$executable_path"; }
    [[ $(service_binary) == "$executable_path" ]]
done
for fixture_command_line in '' '{ path=/bin/sh ; argv[]=/bin/sh -c netcontrold ; }' '{ path=netcontrold ; }' '{ path=/usr/sbin/netcontrold-other ; }' '{ path=/usr/sbin/netcontrold ; } { path=/opt/netcontrold ; }'; do
    root_command() { printf '%s\n' "$fixture_command_line"; }
    if service_binary; then printf 'Unsafe ExecStart accepted: %s\n' "$fixture_command_line" >&2; exit 1; fi
done
root_command() { return 1; }
if service_binary; then printf 'Failed systemd query accepted\n' >&2; exit 1; fi
printf 'Service executable discovery tests passed (mocked systemd).\n'

for deployment_scenario in success setup_failure deploy_failure; do
    (
        deployment_trace=''
        root_command() {
            [[ $# -eq 5 && $1 == bash && $2 == -c &&
                $3 == 'source "$1"; configure_conntrack && configure_link_diagnostics && configure_deny_logging && configure_appliance_services && configure_logging_units && systemctl daemon-reload' && $4 == bash && $5 == "$PWD/install.sh" ]] || return 1
            deployment_trace+='setup;'
            [[ $deployment_scenario != setup_failure ]]
        }
        upgrade_binary() {
            [[ $1 == new-binary && $2 == installed-binary && $3 == "$PWD/install.sh" ]] || return 1
            deployment_trace+='deploy;'
            [[ $deployment_scenario != deploy_failure ]]
        }
        if deploy_upgrade new-binary installed-binary "$PWD/install.sh"; then
            [[ $deployment_scenario == success ]] || exit 1
        else
            [[ $deployment_scenario != success ]] || exit 1
        fi
        if [[ $deployment_scenario == setup_failure ]]; then
            [[ $deployment_trace == 'setup;' ]]
        else
            [[ $deployment_trace == 'setup;deploy;' ]]
        fi
    )
done
printf 'Upgrade configures conntrack and appliance services/reloads systemd before replacement; setup failures abort (mocked commands).\n'

cat > "$temporary/setup-fixture.sh" <<'EOF'
configure_conntrack() {
    printf 'conntrack\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != conntrack_failure ]]
}
configure_link_diagnostics() {
    printf 'link-diagnostics\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != diagnostics_failure ]]
}
configure_deny_logging() {
    printf 'deny-log\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != deny_log_failure ]]
}
configure_appliance_services() {
    printf 'services\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != services_failure ]]
}
configure_logging_units() {
    printf 'logging-units\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != logging_units_failure ]]
}
systemctl() {
    [[ $* == daemon-reload ]] || return 1
    printf 'reload\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != reload_failure ]]
}
EOF
for setup_scenario in success conntrack_failure diagnostics_failure deny_log_failure services_failure logging_units_failure reload_failure; do
    (
        export SETUP_SCENARIO=$setup_scenario SETUP_TRACE="$temporary/setup-$setup_scenario.trace"
        root_command() { "$@"; }
        upgrade_binary() { printf 'deploy\n' >> "$SETUP_TRACE"; }
        if deploy_upgrade new-binary installed-binary "$temporary/setup-fixture.sh"; then
            [[ $setup_scenario == success ]] || exit 1
        else
            [[ $setup_scenario != success ]] || exit 1
        fi
        case $setup_scenario in
            success) expected=$'conntrack\nlink-diagnostics\ndeny-log\nservices\nlogging-units\nreload\ndeploy' ;;
            conntrack_failure) expected=conntrack ;;
            diagnostics_failure) expected=$'conntrack\nlink-diagnostics' ;;
            deny_log_failure) expected=$'conntrack\nlink-diagnostics\ndeny-log' ;;
            services_failure) expected=$'conntrack\nlink-diagnostics\ndeny-log\nservices' ;;
            logging_units_failure) expected=$'conntrack\nlink-diagnostics\ndeny-log\nservices\nlogging-units' ;;
            reload_failure) expected=$'conntrack\nlink-diagnostics\ndeny-log\nservices\nlogging-units\nreload' ;;
        esac
        [[ $(< "$SETUP_TRACE") == "$expected" ]]
    )
done
printf 'Upgrade aborts before deployment on conntrack, service setup or systemd reload failure.\n'

for scenario in missing loaded unmanaged conflicting masked install_failure reload_failure; do
    destination="$temporary/setup-$scenario"
    mkdir "$destination"
    if [[ $scenario == conflicting ]]; then printf 'custom unit\n' > "$destination/unit"; fi
    if UPGRADE_TEST_DIRECTORY="$destination" UPGRADE_TEST_SCENARIO="$scenario" bash -c '
        set -euo pipefail
        source ./upgrade.sh
        root_command() {
            printf "%s\n" "$*" >> "$UPGRADE_TEST_DIRECTORY/commands"
            case $1 in
                pgrep) [[ $UPGRADE_TEST_SCENARIO == unmanaged ]] && return 0; return 1 ;;
                install) [[ $UPGRADE_TEST_SCENARIO != install_failure ]] ;;
                systemctl)
                    case $* in
                        *LoadState*)
                            case $UPGRADE_TEST_SCENARIO in
                                loaded) printf "loaded\n" ;;
                                masked) printf "masked\n" ;;
                                *) printf "not-found\n"; return 4 ;;
                            esac ;;
                        *ExecStart*) printf "{ path=/usr/local/sbin/netcontrold ; }\n" ;;
                        *daemon-reload*) [[ $UPGRADE_TEST_SCENARIO != reload_failure ]] ;;
                        *) return 1 ;;
                    esac ;;
                *) return 1 ;;
            esac
        }
        service_target "$PWD" "$UPGRADE_TEST_DIRECTORY/unit"
    '; then
        [[ $scenario == loaded ]] || exit 1
    else
        [[ $scenario != loaded ]] || exit 1
    fi
    ! grep -q '^install ' "$destination/commands"
    if [[ $scenario == conflicting ]]; then [[ $(< "$destination/unit") == 'custom unit' ]]; fi
    ! grep -Eq 'systemctl (start|enable)' "$destination/commands"
done
printf 'Upgrade refuses missing services without provisioning or interface changes (mocked privileged commands).\n'

for scenario in success fail_stage fail_bootstrap fail_logging fail_restart fail_health first_install fail_first_start inactive_existing fail_inactive_start; do
    destination="$temporary/upgrade-$scenario"
    mkdir "$destination"
    printf 'old binary\n' > "$destination/netcontrold"
    if [[ $scenario == first_install || $scenario == fail_first_start ]]; then rm "$destination/netcontrold"; fi
    printf 'new binary\n' > "$destination/new"
    if UPGRADE_TEST_DIRECTORY="$destination" UPGRADE_TEST_SCENARIO="$scenario" bash -c '
        set -euo pipefail
        source ./upgrade.sh
        sleep() { :; }
        root_command() {
            printf "%s\n" "$*" >> "$UPGRADE_TEST_DIRECTORY/commands"
            case $1 in
                "$UPGRADE_TEST_DIRECTORY/"*.upgrade.*)
                    [[ $2 == --configure-updates && $3 == /etc/netcontrol/updates.json &&
                       $UPGRADE_TEST_SCENARIO != fail_bootstrap ]]
                    ;;
                bash)
                    if [[ $3 == '\''source "$1"; configure_host_logging'\'' ]]; then
                        grep -q "^systemctl stop netcontrold.service$" "$UPGRADE_TEST_DIRECTORY/commands" || return 1
                        [[ $UPGRADE_TEST_SCENARIO != fail_logging ]]
                    else
                        [[ $3 == '\''source "$1"; configure_conntrack && configure_link_diagnostics && configure_deny_logging && configure_appliance_services && configure_logging_units && systemctl daemon-reload'\'' ]]
                    fi ;;
                install)
                    [[ $UPGRADE_TEST_SCENARIO != fail_stage ]] || return 1
                    command cp -- "${@: -2}"
                    ;;
                systemctl)
                    case $2 in
                        start)
                            if [[ ! -f $UPGRADE_TEST_DIRECTORY/started ]]; then
                                touch "$UPGRADE_TEST_DIRECTORY/started"
                                [[ $UPGRADE_TEST_SCENARIO != fail_restart ]] || return 1
                                [[ $UPGRADE_TEST_SCENARIO != fail_first_start && $UPGRADE_TEST_SCENARIO != fail_inactive_start ]] || return 1
                            fi
                            ;;
                        is-active)
                            case $UPGRADE_TEST_SCENARIO in
                                first_install|fail_first_start|inactive_existing|fail_inactive_start)
                                    [[ -f $UPGRADE_TEST_DIRECTORY/started ]] || return 1 ;;
                            esac
                            [[ $UPGRADE_TEST_SCENARIO != fail_health || ! -f $UPGRADE_TEST_DIRECTORY/started ]] || return 1
                            ;;
                        show) printf "inactive\n" ;;
                    esac
                    ;;
                pgrep) return 1 ;;
                *) command "$@" ;;
            esac
        }
        deploy_upgrade "$UPGRADE_TEST_DIRECTORY/new" "$UPGRADE_TEST_DIRECTORY/netcontrold" "$PWD/install.sh"
    '; then
        [[ $scenario == success || $scenario == first_install || $scenario == inactive_existing ]] || { printf 'Unexpected upgrade success: %s\n' "$scenario" >&2; exit 1; }
        cmp "$destination/new" "$destination/netcontrold"
    else
        [[ $scenario != success && $scenario != first_install && $scenario != inactive_existing ]] || { printf 'Valid upgrade failed\n' >&2; exit 1; }
        if [[ $scenario == fail_first_start ]]; then
            [[ ! -e $destination/netcontrold ]]
        else
            [[ $(< "$destination/netcontrold") == 'old binary' ]]
        fi
        if [[ $scenario == fail_stage || $scenario == fail_bootstrap ]]; then
            ! grep -q 'systemctl stop' "$destination/commands"
        else
            [[ $(grep -c 'systemctl stop' "$destination/commands") -eq 2 ]]
            if [[ $scenario == fail_first_start || $scenario == fail_inactive_start || $scenario == fail_logging ]]; then
                [[ $(grep -c 'systemctl start' "$destination/commands") -eq 1 ]]
            else
                [[ $(grep -c 'systemctl start' "$destination/commands") -eq 2 ]]
            fi
        fi
    fi
    if [[ $scenario != fail_stage && $scenario != fail_bootstrap && $scenario != first_install && $scenario != fail_first_start ]]; then
        [[ $(< "$destination/netcontrold.previous") == 'old binary' ]]
    fi
    [[ -z $(find "$destination" -name 'netcontrold.upgrade.*' -print) ]]
done
printf 'Incremental upgrade replacement and recovery tests passed (mocked service commands).\n'

(
    source ./reset.sh
    recovery_directory="$temporary/wifi-recovery"
    recovery_backup="$temporary/wifi-recovery-backup"
    mkdir "$recovery_directory" "$recovery_backup"
    retire_wifi_recovery "$recovery_directory" "$recovery_backup"
    printf 'temporary DHCP configuration\n' > "$recovery_directory/00-00-wifi-recovery.network"
    printf 'operator configuration\n' > "$recovery_directory/10-operator.network"
    retire_wifi_recovery "$recovery_directory" "$recovery_backup"
    [[ ! -e $recovery_directory/00-00-wifi-recovery.network ]]
    [[ $(< "$recovery_backup/wifi-recovery.network") == 'temporary DHCP configuration' ]]
    [[ $(< "$recovery_directory/10-operator.network") == 'operator configuration' ]]
    mkdir "$recovery_directory/00-00-wifi-recovery.network"
    if retire_wifi_recovery "$recovery_directory" "$recovery_backup"; then exit 1; fi
    rmdir "$recovery_directory/00-00-wifi-recovery.network"
)

for reset_scenario in success config_failure env_failure reload_failure start_failure http_failure; do
    reset_directory="$temporary/reset-$reset_scenario"
    mkdir "$reset_directory"
    if (
        source ./reset.sh
        reset_fixture() {
            printf 'reset %s\n' "$*" >> "$reset_directory/commands"
            [[ $reset_scenario != config_failure ]]
        }
        install() {
            printf 'environment\n' >> "$reset_directory/commands"
            command cat > "$reset_directory/environment"
            [[ $reset_scenario != env_failure ]]
        }
        systemctl() {
            printf 'systemctl %s\n' "$*" >> "$reset_directory/commands"
            [[ $* != daemon-reload || $reset_scenario != reload_failure ]] || return 1
            [[ $* != 'enable --now netcontrold.service' || $reset_scenario != start_failure ]]
        }
        curl() {
            printf 'http %s\n' "$*" >> "$reset_directory/commands"
            [[ $reset_scenario != http_failure ]]
        }
        reset_appliance reset_fixture eno1 enp3s0 192.168.0.1/24
    ); then
        [[ $reset_scenario == success ]] || exit 1
    else
        [[ $reset_scenario != success ]] || exit 1
    fi
    grep -q -- '--factory-reset' "$reset_directory/commands"
    grep -q -- '--provision-wan eno1 --provision-lan enp3s0 --provision-lan-address 192.168.0.1/24' "$reset_directory/commands"
    case $reset_scenario in
        config_failure) ! grep -Eq '^environment|^systemctl|^http' "$reset_directory/commands" ;;
        env_failure) ! grep -Eq '^systemctl|^http' "$reset_directory/commands" ;;
        reload_failure) ! grep -Eq 'enable --now|^http' "$reset_directory/commands" ;;
        start_failure) ! grep -q '^http' "$reset_directory/commands" ;;
        success) [[ $(< "$reset_directory/environment") == 'NETCONTROL_LISTEN=192.168.0.1:8080' ]] ;;
    esac
done
(
    source ./reset.sh
    uname() { touch "$temporary/unexpected-reset-host-check"; return 1; }
    for answer in '' n no invalid; do
        if confirm_reset false <<< "$answer"; then printf 'Reset accepted a declined confirmation.\n' >&2; exit 1; fi
        if main <<< "$answer"; then printf 'Reset continued without confirmation.\n' >&2; exit 1; fi
    done
    if confirm_reset false </dev/null; then printf 'Reset accepted EOF.\n' >&2; exit 1; fi
    if main </dev/null; then printf 'Reset continued after EOF.\n' >&2; exit 1; fi
    for answer in y Y yes YES Yes; do
        confirm_reset false <<< "$answer" || exit 1
    done
    confirm_reset true </dev/null || exit 1
    if main --unknown; then printf 'Reset accepted unknown options.\n' >&2; exit 1; fi
    [[ ! -e $temporary/unexpected-reset-host-check ]]
)
printf 'Explicit factory reset and prerequisite-failure ordering tests passed (mocked host commands).\n'

(
    source ./hardening.sh
    hardening_check_host() { :; }
    hardening_check_apparmor() { :; }
    hardening_unit_candidates=(cups.service)
    hardening_package_candidates=(cups)
    hardening_test_plan='Purg cups [1.0]'
    hardening_test_protected=false
    systemctl() {
        [[ $1 == show ]] || { printf 'Unexpected service mutation.\n' >&2; return 1; }
        printf 'loaded\n'
    }
    dpkg-query() {
        if [[ $hardening_test_protected == true ]]; then printf 'installed yes\n'; else printf 'installed\n'; fi
    }
    apt-get() {
        [[ $1 == --simulate ]] || { printf 'Unexpected package mutation.\n' >&2; return 1; }
        printf '%s\n' "$hardening_test_plan"
    }
    install() { printf 'Unexpected filesystem mutation.\n' >&2; return 1; }
    preview=$(main)
    [[ $preview == *'Preview only; nothing changed.'* ]]
    preview=$(main --disable-apparmor)
    [[ $preview == *'WARNING: disabling AppArmor'* && $preview == *'Preview only; nothing changed.'* ]]
    hardening_packages=(cups)
    for hardening_test_plan in 'Remv openssh-server [1.0]' 'Purg cups [1.0]
Remv systemd-networkd [1.0]' 'Inst unexpected [1.0]' 'unrecognized plan'; do
        if hardening_check_purge; then printf 'Unsafe hardening plan accepted.\n' >&2; exit 1; fi
    done
    hardening_test_plan='Purg cups:amd64 [1.0]'
    hardening_check_purge
    hardening_test_protected=true
    if hardening_plan; then printf 'Protected package accepted.\n' >&2; exit 1; fi
    if main --unknown; then exit 1; fi
)

for hardening_test_scenario in success simulation_failure service_failure purge_failure; do
    (
        source ./hardening.sh
        hardening_units=(cups.service)
        hardening_packages=(cups)
        hardening_configure_os_updates() { :; }
        hardening_test_backup="$temporary/hardening-$hardening_test_scenario"
        mkdir "$hardening_test_backup"
        systemctl() {
            printf 'service %s\n' "$*" >> "$hardening_test_backup/commands"
            [[ $1 != disable || $hardening_test_scenario != service_failure ]]
        }
        dpkg-query() { printf 'cups\t1.0\n'; }
        apt-get() {
            printf 'apt %s\n' "$*" >> "$hardening_test_backup/commands"
            if [[ $1 == --simulate ]]; then
                [[ $hardening_test_scenario != simulation_failure ]] || return 1
                printf 'Purg cups [1.0]\n'
            else
                [[ $hardening_test_scenario != purge_failure ]]
            fi
        }
        if hardening_apply_plan "$hardening_test_backup" false; then
            [[ $hardening_test_scenario == success ]] || exit 1
        else
            [[ $hardening_test_scenario != success ]] || exit 1
        fi
        case $hardening_test_scenario in
            simulation_failure) ! grep -q '^service' "$hardening_test_backup/commands" ;;
            service_failure) ! grep -q '^apt --assume-yes' "$hardening_test_backup/commands" ;;
            success)
                grep -q '^apt --assume-yes purge -- cups$' "$hardening_test_backup/commands"
                hardening_disable_apparmor() { printf 'apparmor\n' >> "$hardening_test_backup/commands"; }
                ! grep -q '^apparmor$' "$hardening_test_backup/commands"
                hardening_apply_plan "$hardening_test_backup" true
                grep -q '^apparmor$' "$hardening_test_backup/commands" ;;
        esac
    )
done

for hardening_test_scenario in success grub_failure first_grub_failure; do
    (
        source ./hardening.sh
        hardening_test_directory="$temporary/grub-$hardening_test_scenario"
        hardening_test_backup="$temporary/grub-backup-$hardening_test_scenario"
        mkdir "$hardening_test_directory" "$hardening_test_backup"
        if [[ $hardening_test_scenario != first_grub_failure ]]; then
            printf 'previous configuration\n' > "$hardening_test_directory/99-netcontrol-apparmor.cfg"
        fi
        install() {
            if [[ $1 == -d ]]; then return 0; fi
            command cat > "${@: -1}"
        }
        update-grub() { [[ $hardening_test_scenario == success ]]; }
        systemctl() {
            printf '%s\n' "$*" >> "$hardening_test_backup/commands"
            if [[ $1 == show ]]; then printf 'loaded\n'; fi
        }
        if hardening_disable_apparmor "$hardening_test_backup" "$hardening_test_directory"; then
            [[ $hardening_test_scenario == success ]] || exit 1
            grep -Fq 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} apparmor=0"' "$hardening_test_directory/99-netcontrol-apparmor.cfg"
            grep -q '^disable apparmor.service$' "$hardening_test_backup/commands"
            ! grep -Eq -- '--now|stop' "$hardening_test_backup/commands"
        else
            [[ $hardening_test_scenario != success ]] || exit 1
            if [[ $hardening_test_scenario == grub_failure ]]; then
                [[ $(< "$hardening_test_directory/99-netcontrol-apparmor.cfg") == 'previous configuration' ]]
            else
                [[ ! -e $hardening_test_directory/99-netcontrol-apparmor.cfg ]]
            fi
            ! grep -q '^disable' "$hardening_test_backup/commands"
        fi
    )
done
printf 'OS footprint preview, dependency guards, failure ordering and AppArmor boot-option tests passed (mocked host commands).\n'

policy_cases=0
for policy_profile in snap apt; do
  for policy_process in install hardening; do
    for policy_scenario in installed repeat absent missing_unit masked_active runtime_mask query_failure unknown_state disable_failure stop_failure mask_failure verify_failure still_active runtime_only active_job config_override shutdown_override config_query_failure write_failure unsafe_target existing_config; do
        if [[ $policy_profile == snap ]]; then
            case $policy_scenario in active_job|config_override|shutdown_override|config_query_failure|write_failure|unsafe_target|existing_config) continue ;; esac
            policy_units=(snapd.service snapd.socket)
        else
            policy_units=(apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service)
        fi
        policy_cases=$((policy_cases + 1))
        policy_missing_unit=${policy_units[1]}
        policy_directory="$temporary/$policy_profile-$policy_process-$policy_scenario"
        policy_target="$policy_directory/apt/99-netcontrol-no-automatic-updates"
        mkdir -p "$policy_directory/apt"
        : > "$policy_directory/commands"
        if [[ $policy_scenario == existing_config ]]; then
            printf 'APT::Periodic::Enable "1";\n' > "$policy_target"
        elif [[ $policy_scenario == unsafe_target ]]; then
            printf 'keep original\n' > "$policy_directory/original"
            ln -s "$policy_directory/original" "$policy_target"
        fi
        if (
            if [[ $policy_process == hardening ]]; then
                source ./hardening.sh
                hardening_unit_candidates=("${policy_units[@]}")
                hardening_package_candidates=()
                if [[ $policy_profile == snap ]]; then hardening_configure_os_updates() { :; }; fi
                dpkg-query() { printf 'Unexpected package query.\n' >&2; return 1; }
                apt-get() { printf 'Unexpected package mutation.\n' >&2; return 1; }
            fi
            install() {
                if [[ $# -ne 8 || ${1:-} != -d || ${2:-} != -o || ${3:-} != root ||
                      ${4:-} != -g || ${5:-} != root || ${6:-} != -m ||
                      ${7:-} != 0755 || ${8:-} != "$policy_directory/apt" ]]; then
                    printf 'Unexpected APT fixture install command: %s\n' "$*" >&2
                    return 1
                fi
                command install -d -m "$7" -- "$8"
            }
            apt-config() {
                [[ $1 == dump ]] || return 1
                [[ $policy_scenario != config_query_failure ]] || return 1
                if [[ $policy_scenario == config_override ]]; then
                    sed 's/Enable "0"/Enable "1"/' "$policy_target"
                elif [[ $policy_scenario == shutdown_override ]]; then
                    sed 's/InstallOnShutdown "false"/InstallOnShutdown "true"/' "$policy_target"
                else
                    cat "$policy_target"
                fi
            }
            if [[ $policy_scenario == write_failure ]]; then mv() { return 1; }; fi
            systemctl() {
                printf '%s\n' "$*" >> "$policy_directory/commands"
                local operation=$1 unit state active
                shift
                if [[ $operation == show ]]; then
                    unit=$1
                    [[ " ${policy_units[*]} " == *" $unit "* ]] || return 1
                    if [[ $* == *LoadState* ]]; then
                        case $policy_scenario in
                            absent) printf 'not-found\n'; return 4 ;;
                            missing_unit)
                                if [[ $unit == "$policy_missing_unit" ]]; then printf 'not-found\n'; return 4; fi ;;
                            query_failure) return 1 ;;
                            unknown_state) printf 'error\n'; return 0 ;;
                        esac
                        if [[ -e $policy_directory/$unit.masked ||
                              $policy_scenario == masked_active || $policy_scenario == runtime_mask ||
                              $policy_scenario == stop_failure ]]; then
                            printf 'masked\n'
                        else
                            printf 'loaded\n'
                        fi
                        return 0
                    fi
                    if [[ $policy_scenario == verify_failure && -e $policy_directory/$unit.masked ]]; then
                        return 1
                    fi
                    active=active
                    case $unit in
                        apt-daily.service|apt-daily-upgrade.service)
                            if [[ $policy_scenario != active_job ]]; then active=inactive; fi ;;
                    esac
                    if [[ -e $policy_directory/$unit.stopped && $policy_scenario != still_active ]]; then
                        active=inactive
                    fi
                    state=enabled
                    if [[ $policy_scenario == masked_active || $policy_scenario == stop_failure ]]; then
                        state=masked
                    elif [[ $policy_scenario == runtime_mask ]]; then
                        state=masked-runtime
                    fi
                    if [[ -e $policy_directory/$unit.masked ]]; then
                        if [[ $policy_scenario == runtime_only ]]; then state=masked-runtime; else state=masked; fi
                    fi
                    printf 'ActiveState=%s\nUnitFileState=%s\n' "$active" "$state"
                    return 0
                fi
                if [[ $operation == disable ]]; then
                    if [[ $1 == --now ]]; then
                        shift
                        for unit in "$@"; do
                            [[ $unit != apt-daily.service && $unit != apt-daily-upgrade.service ]] || {
                                printf 'APT job would be forcibly stopped.\n' >&2; return 1;
                            }
                        done
                    fi
                fi
                for unit in "$@"; do
                    [[ " ${policy_units[*]} " == *" $unit "* ]] || return 1
                    case $operation in
                        disable)
                            [[ $policy_scenario != disable_failure ]] || return 1
                            case $unit in
                                apt-daily.service|apt-daily-upgrade.service) ;;
                                *) : > "$policy_directory/$unit.stopped" ;;
                            esac ;;
                        stop)
                            [[ $unit != apt-daily.service && $unit != apt-daily-upgrade.service ]] || return 1
                            [[ $policy_scenario != stop_failure ]] || return 1
                            : > "$policy_directory/$unit.stopped" ;;
                        mask)
                            [[ $policy_scenario != mask_failure ]] || return 1
                            : > "$policy_directory/$unit.masked" ;;
                        *) printf 'Unexpected policy command: %s\n' "$operation" >&2; return 1 ;;
                    esac
                done
            }
            if [[ $policy_process == install ]]; then
                if [[ $policy_profile == snap ]]; then
                    configure_snap || exit 1
                    if [[ $policy_scenario == repeat ]]; then configure_snap || exit 1; fi
                else
                    configure_os_updates "$policy_directory/apt" || exit 1
                    if [[ $policy_scenario == repeat ]]; then configure_os_updates "$policy_directory/apt" || exit 1; fi
                fi
            else
                hardening_plan || exit 1
                ! grep -Eq '^(disable|stop|mask) ' "$policy_directory/commands" || exit 1
                [[ ! -e $policy_target || $policy_scenario == existing_config || $policy_scenario == unsafe_target ]] || exit 1
                mkdir "$policy_directory/backup"
                hardening_apply_plan "$policy_directory/backup" false "$policy_directory/apt" || exit 1
                if [[ $policy_scenario == repeat ]]; then
                    hardening_plan || exit 1
                    mkdir "$policy_directory/repeated-backup"
                    hardening_apply_plan "$policy_directory/repeated-backup" false "$policy_directory/apt" || exit 1
                fi
            fi
        ); then
            case $policy_scenario in installed|repeat|absent|missing_unit|masked_active|runtime_mask|existing_config) ;; *) exit 1 ;; esac
            if [[ $policy_scenario == absent ]]; then
                ! grep -Eq '^(disable|stop|mask) ' "$policy_directory/commands"
            else
                for policy_unit in "${policy_units[@]}"; do
                    if [[ $policy_scenario == missing_unit && $policy_unit == "$policy_missing_unit" ]]; then
                        [[ ! -e $policy_directory/$policy_unit.masked ]]
                        continue
                    fi
                    [[ -e $policy_directory/$policy_unit.masked ]]
                    case $policy_unit in
                        apt-daily.service|apt-daily-upgrade.service) expected_active=inactive ;;
                        *) expected_active=active; [[ -e $policy_directory/$policy_unit.stopped ]] ;;
                    esac
                    if [[ $policy_process == hardening ]]; then
                        grep -Fxq "ActiveState=$expected_active" "$policy_directory/backup/$policy_unit.state"
                    fi
                done
            fi
            if [[ $policy_profile == apt ]]; then
                parsed=$(command apt-config -c "$policy_target" dump)
                for key in Enable Update-Package-Lists Download-Upgradeable-Packages Unattended-Upgrade; do
                    grep -Fxq "APT::Periodic::$key \"0\";" "$policy_target"
                    grep -Fxq "APT::Periodic::$key \"0\";" <<< "$parsed"
                done
                [[ $(stat -c '%a' "$policy_target") == 644 ]]
                grep -Fxq 'Unattended-Upgrade::InstallOnShutdown "false";' "$policy_target"
                grep -Fxq 'Unattended-Upgrade::InstallOnShutdown "false";' <<< "$parsed"
                if [[ $policy_process == hardening ]]; then
                    if [[ $policy_scenario == existing_config ]]; then
                        grep -Fxq 'APT::Periodic::Enable "1";' "$policy_directory/backup/apt-periodic.conf"
                        [[ $(< "$policy_directory/backup/apt-periodic.state") == present ]]
                    else
                        [[ $(< "$policy_directory/backup/apt-periodic.state") == absent ]]
                    fi
                fi
            fi
        else
            case $policy_scenario in installed|repeat|absent|missing_unit|masked_active|runtime_mask|existing_config) exit 1 ;; esac
            if [[ $policy_scenario == query_failure || $policy_scenario == unknown_state ]]; then
                ! grep -Eq '^(disable|stop|mask) ' "$policy_directory/commands"
            fi
            if [[ $policy_scenario == disable_failure || $policy_scenario == stop_failure ]]; then
                ! grep -q '^mask ' "$policy_directory/commands"
            fi
            if [[ $policy_scenario == active_job || $policy_scenario == write_failure ]]; then [[ ! -e $policy_target ]]; fi
            if [[ $policy_scenario == unsafe_target ]]; then [[ $(< "$policy_directory/original") == 'keep original' ]]; fi
        fi
        if [[ $policy_profile == apt ]]; then
            ! grep -Eq '^(stop|disable --now).*apt-daily(-upgrade)?\.service' "$policy_directory/commands"
        fi
        [[ -z $(find "$policy_directory/apt" -maxdepth 1 -name '.automatic-updates.*' -print) ]]
    done
  done
done
printf 'Snap/APT install/hardening preview, persistent masks, periodic config, active-job safety, backups and failure tests passed (%s scenarios; mocked systemd, real APT config parser; no package/data removal).\n' "$policy_cases"