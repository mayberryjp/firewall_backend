#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
source ./install.sh
temporary=$(mktemp -d)
printf -v cleanup 'rm -rf -- %q' "$temporary"
trap "$cleanup" EXIT
fixture_commit=0123456789abcdef0123456789abcdef01234567
scenario=valid

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
        [[ $(< "$service_target") == $'[Service]\nEnvironment=NETCONTROL_ALLOW_HOST_SERVICES=true\nEnvironment=NETCONTROL_GATEWAY_MONITORING=true' ]]
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
mkdir "$temporary/one-port"
mv "$ports_fixture/eno1" "$temporary/one-port/"
if select_appliance_ports '' '' "$temporary/one-port"; then exit 1; fi
printf 'Automatic Ethernet port selection and override validation passed.\n'

gh() {
    case $1 in
        auth) [[ $scenario != unauthenticated ]] ;;
        api)
            [[ $scenario != api_failure ]] || return 1
            [[ $scenario != unsuccessful ]] || return 0
            printf '%s\n' "$fixture_commit"
            ;;
        run)
            [[ $scenario != missing_artifact ]] || return 1
            [[ $* == *"netcontrol-ubuntu-amd64-$fixture_commit"* ]] || return 1
            local destination=${!#}
            printf 'synthetic executable fixture\n' > "$destination/netcontrold"
            cp packaging/native/netcontrold.service "$destination/netcontrold.service"
            (cd "$destination" && sha256sum --binary netcontrold netcontrold.service > SHA256SUMS)
            case $scenario in
                tampered_binary) printf 'tampered\n' >> "$destination/netcontrold" ;;
                tampered_unit) printf 'tampered\n' >> "$destination/netcontrold.service" ;;
                incomplete_manifest) head -n 1 "$destination/SHA256SUMS" > "$destination/reduced"; mv "$destination/reduced" "$destination/SHA256SUMS" ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

for scenario in valid unauthenticated api_failure unsuccessful missing_artifact tampered_binary tampered_unit incomplete_manifest; do
    destination="$temporary/$scenario"
    mkdir "$destination"
    if download_prebuilt 123 "$destination"; then
        [[ $scenario == valid ]] || { printf 'Unexpected success: %s\n' "$scenario" >&2; exit 1; }
    else
        [[ $scenario != valid ]] || { printf 'Valid artifact rejected\n' >&2; exit 1; }
    fi
done

(
trace=''
check_systemd_unit() { return 0; }
install() { trace="$trace install $*;"; }
systemctl() { trace="$trace systemctl $*;"; }
configure_appliance_services() { trace+=' appliance-services;'; }
install_systemd_service
[[ $trace == *'install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys;'* ]]
[[ $trace == *'install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service;'* ]]
[[ $trace == *'systemctl daemon-reload;'* ]]
[[ $trace == *'appliance-services; systemctl daemon-reload;'* ]]
[[ $trace != *'systemctl start'* && $trace != *'systemctl enable'* ]]
trace=''
check_systemd_unit() { return 1; }
if install_systemd_service; then exit 1; fi
[[ -z $trace ]]
for failure_stage in service_setup reload; do
    trace=''
    check_systemd_unit() { return 0; }
    configure_appliance_services() { trace+=' appliance-services;'; [[ $failure_stage != service_setup ]]; }
    systemctl() { trace+=" systemctl $*;"; return 1; }
    if install_systemd_service; then exit 1; fi
    [[ $trace == *'appliance-services;'* ]]
    if [[ $failure_stage == service_setup ]]; then
        [[ $trace != *'systemctl daemon-reload;'* ]]
    else
        [[ $trace == *'systemctl daemon-reload;'* ]]
    fi
done
)
printf 'Prebuilt download verification and service-installation tests passed (mocked GitHub/system commands).\n'

for provision_scenario in success config_failure env_failure reload_failure start_failure http_failure forwarding_failure; do
    provision_directory="$temporary/provision-$provision_scenario"
    mkdir "$provision_directory"
    if (
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
        provision_appliance provision_fixture wan0 lan0 192.168.50.1/24
    ); then
        [[ $provision_scenario == success ]] || exit 1
    else
        [[ $provision_scenario != success ]] || exit 1
    fi
    grep -q -- '--provision-wan wan0 --provision-lan lan0 --provision-lan-address 192.168.50.1/24' "$provision_directory/commands"
    if [[ $provision_scenario == config_failure ]]; then
        ! grep -Eq '^(install|systemctl|curl) ' "$provision_directory/commands"
    else
        [[ $(< "$provision_directory/environment") == NETCONTROL_LISTEN=192.168.50.1:8080 ]]
    fi
    if [[ $provision_scenario == env_failure || $provision_scenario == reload_failure ]]; then
        ! grep -q '^systemctl enable' "$provision_directory/commands"
    fi
    if [[ $provision_scenario == success ]]; then
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
                $3 == 'source "$1"; configure_conntrack && configure_appliance_services && systemctl daemon-reload' && $4 == bash && $5 == "$PWD/install.sh" ]] || return 1
            deployment_trace+='setup;'
            [[ $deployment_scenario != setup_failure ]]
        }
        upgrade_binary() {
            [[ $1 == new-binary && $2 == installed-binary ]] || return 1
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
configure_appliance_services() {
    printf 'services\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != services_failure ]]
}
systemctl() {
    [[ $* == daemon-reload ]] || return 1
    printf 'reload\n' >> "$SETUP_TRACE"
    [[ $SETUP_SCENARIO != reload_failure ]]
}
EOF
for setup_scenario in success conntrack_failure services_failure reload_failure; do
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
            success) expected=$'conntrack\nservices\nreload\ndeploy' ;;
            conntrack_failure) expected=conntrack ;;
            services_failure) expected=$'conntrack\nservices' ;;
            reload_failure) expected=$'conntrack\nservices\nreload' ;;
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

for scenario in success fail_stage fail_restart fail_health first_install fail_first_start inactive_existing fail_inactive_start; do
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
                bash) [[ $3 == '\''source "$1"; configure_conntrack && configure_appliance_services && systemctl daemon-reload'\'' ]] ;;
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
        if [[ $scenario == fail_stage ]]; then
            ! grep -q 'systemctl stop' "$destination/commands"
        else
            [[ $(grep -c 'systemctl stop' "$destination/commands") -eq 2 ]]
            if [[ $scenario == fail_first_start || $scenario == fail_inactive_start ]]; then
                [[ $(grep -c 'systemctl start' "$destination/commands") -eq 1 ]]
            else
                [[ $(grep -c 'systemctl start' "$destination/commands") -eq 2 ]]
            fi
        fi
    fi
    if [[ $scenario != fail_stage && $scenario != first_install && $scenario != fail_first_start ]]; then
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