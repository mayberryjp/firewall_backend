#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
source ./install.sh
temporary=$(mktemp -d)
printf -v cleanup 'rm -rf -- %q' "$temporary"
trap "$cleanup" EXIT
fixture_commit=0123456789abcdef0123456789abcdef01234567
scenario=valid

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

trace=''
check_systemd_unit() { return 0; }
install() { trace="$trace install $*;"; }
systemctl() { trace="$trace systemctl $*;"; }
install_systemd_service
[[ $trace == *'install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys;'* ]]
[[ $trace == *'install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service;'* ]]
[[ $trace == *'systemctl daemon-reload;'* ]]
[[ $trace != *'systemctl start'* && $trace != *'systemctl enable'* ]]
trace=''
check_systemd_unit() { return 1; }
if install_systemd_service; then exit 1; fi
[[ -z $trace ]]
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
        [[ $scenario == missing || $scenario == loaded ]] || exit 1
    else
        [[ $scenario != missing && $scenario != loaded ]] || exit 1
    fi
    if [[ $scenario == missing ]]; then
        grep -q 'install -d -m 0700 /var/lib/netcontrol' "$destination/commands"
        grep -q 'install -m 0644 .*netcontrold.service' "$destination/commands"
        grep -q 'systemctl daemon-reload' "$destination/commands"
    elif [[ $scenario == loaded || $scenario == unmanaged || $scenario == conflicting || $scenario == masked ]]; then
        ! grep -q '^install ' "$destination/commands"
    fi
    if [[ $scenario == conflicting ]]; then [[ $(< "$destination/unit") == 'custom unit' ]]; fi
    ! grep -Eq 'systemctl (start|enable)' "$destination/commands"
done
printf 'Missing-service setup and refusal tests passed (mocked privileged commands).\n'

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
        upgrade_binary "$UPGRADE_TEST_DIRECTORY/new" "$UPGRADE_TEST_DIRECTORY/netcontrold"
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