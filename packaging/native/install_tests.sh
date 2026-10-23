#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
source <(sed '$d' install.sh)
temporary=$(mktemp -d)
printf -v cleanup 'rm -rf -- %q' "$temporary"
trap "$cleanup" EXIT
fixture_commit=0123456789abcdef0123456789abcdef01234567
scenario=valid

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

source ./in-place-upgrade.sh
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

for scenario in success fail_stage fail_restart fail_health; do
    destination="$temporary/upgrade-$scenario"
    mkdir "$destination"
    printf 'old binary\n' > "$destination/netcontrold"
    printf 'new binary\n' > "$destination/new"
    if UPGRADE_TEST_DIRECTORY="$destination" UPGRADE_TEST_SCENARIO="$scenario" bash -c '
        set -euo pipefail
        source ./in-place-upgrade.sh
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
                            fi
                            ;;
                        is-active)
                            [[ $UPGRADE_TEST_SCENARIO != fail_health || ! -f $UPGRADE_TEST_DIRECTORY/started ]] || return 1
                            ;;
                    esac
                    ;;
                *) command "$@" ;;
            esac
        }
        upgrade_binary "$UPGRADE_TEST_DIRECTORY/new" "$UPGRADE_TEST_DIRECTORY/netcontrold"
    '; then
        [[ $scenario == success ]] || { printf 'Unexpected upgrade success: %s\n' "$scenario" >&2; exit 1; }
        cmp "$destination/new" "$destination/netcontrold"
    else
        [[ $scenario != success ]] || { printf 'Valid upgrade failed\n' >&2; exit 1; }
        [[ $(< "$destination/netcontrold") == 'old binary' ]]
        if [[ $scenario == fail_stage ]]; then
            ! grep -q 'systemctl stop' "$destination/commands"
        else
            [[ $(grep -c 'systemctl stop' "$destination/commands") -eq 2 ]]
            [[ $(grep -c 'systemctl start' "$destination/commands") -eq 2 ]]
        fi
    fi
    if [[ $scenario != fail_stage ]]; then
        [[ $(< "$destination/netcontrold.previous") == 'old binary' ]]
    fi
    [[ -z $(find "$destination" -name 'netcontrold.upgrade.*' -print) ]]
done
printf 'Incremental upgrade replacement and recovery tests passed (mocked service commands).\n'