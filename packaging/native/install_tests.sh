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