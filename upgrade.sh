#!/usr/bin/env bash
set -euo pipefail

root_command() {
    if [[ $EUID -eq 0 ]]; then "$@"; else sudo -- "$@"; fi
}

no_unmanaged_daemon() {
    if root_command pgrep -x netcontrold >/dev/null; then
        printf 'An unmanaged netcontrold is running; refusing to replace it.\n' >&2
        return 1
    else
        [[ $? -eq 1 ]] || { printf 'Cannot check for unmanaged netcontrold processes.\n' >&2; return 1; }
    fi
}

service_target() {
    local repository=$1 unit=${2:-/etc/systemd/system/netcontrold.service} load_state
    if ! load_state=$(root_command systemctl show netcontrold.service --property=LoadState --value); then
        [[ $load_state == not-found ]] || return 1
    fi
    case $load_state in
        loaded) service_binary ;;
        not-found)
            no_unmanaged_daemon || return 1
            [[ ! -e $unit && ! -L $unit ]] || { printf 'Refusing to overwrite existing service unit: %s\n' "$unit" >&2; return 1; }
            printf 'Installing the missing systemd service and private directories. HTTP listens on all interfaces, port 8080; restrict management access.\n' >&2
            root_command install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys >&2 || return 1
            root_command install -d -m 0755 /usr/local/sbin >&2 || return 1
            root_command install -m 0644 "$repository/packaging/native/netcontrold.service" "$unit" >&2 || return 1
            root_command systemctl daemon-reload >&2 || return 1
            service_binary
            ;;
        *) printf 'Unsupported service load state: %s. No unit overwritten.\n' "$load_state" >&2; return 1 ;;
    esac
}

service_binary() {
    local command_line destination remainder
    local pattern='\{[[:space:]]*path=([^[:space:];]+)[[:space:]]*;'
    command_line=$(root_command systemctl show netcontrold.service --property=ExecStart --value) || {
        printf 'Cannot inspect netcontrold.service ExecStart.\n' >&2
        return 1
    }
    if [[ ! $command_line =~ $pattern ]]; then
        printf 'Expected a direct netcontrold ExecStart; systemd reported: %s\n' "$command_line" >&2
        return 1
    fi
    destination=${BASH_REMATCH[1]}
    remainder=${command_line#*"${BASH_REMATCH[0]}"}
    if [[ $destination != /*/netcontrold || $remainder =~ $pattern ]]; then
        printf 'Expected exactly one absolute netcontrold executable, not a wrapper; systemd reported: %s\n' "$command_line" >&2
        return 1
    fi
    printf '%s\n' "$destination"
}

upgrade_binary() (
    set -euo pipefail
    local binary=$1 destination=$2
    local staged='' backup="$destination.previous" stopped=false committed=false
    local had_binary=false was_active=false active_state
    recover() {
        local status=$?
        trap - EXIT INT TERM HUP
        if [[ $stopped == true && $committed == false ]]; then
            printf 'Deployment interrupted or failed; recovering the previous installation.\n' >&2
            if ! root_command systemctl stop netcontrold.service; then
                printf 'RECOVERY FAILED: cannot stop service; inspect %s from the local console.\n' "$backup" >&2
                exit "$status"
            fi
            if [[ $had_binary == true ]]; then
                root_command cp -p -- "$backup" "$staged" &&
                    root_command mv -fT -- "$staged" "$destination" || {
                    printf 'RECOVERY FAILED. Previous binary: %s; local console intervention required.\n' "$backup" >&2
                    exit "$status"
                }
            else
                root_command rm -f -- "$destination" || exit "$status"
            fi
            if [[ $was_active == true ]]; then
                root_command systemctl start netcontrold.service || printf 'RECOVERY FAILED: previous service could not start.\n' >&2
            fi
            printf 'Previous binary state restored; inspect service logs and connectivity.\n' >&2
        fi
        [[ -z $staged ]] || root_command rm -f -- "$staged"
        exit "$status"
    }
    trap recover EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    [[ ! -L $destination && ( ! -e $destination || -f $destination ) ]] || { printf 'Daemon destination must be a regular file, not a symlink.\n' >&2; exit 1; }
    [[ ! -L $backup && ( ! -e $backup || -f $backup ) ]] || exit 1
    if root_command systemctl is-active --quiet netcontrold.service; then
        was_active=true
    else
        active_state=$(root_command systemctl show netcontrold.service --property=ActiveState --value)
        [[ $active_state == inactive || $active_state == failed ]] || { printf 'Service is transitioning or unavailable: %s\n' "$active_state" >&2; exit 1; }
        no_unmanaged_daemon
    fi
    staged=$(root_command mktemp "${destination}.upgrade.XXXXXX")
    root_command install -o root -g root -m 0755 -- "$binary" "$staged"
    if [[ -f $destination ]]; then
        root_command cp -p -- "$destination" "$backup"
        had_binary=true
    fi
    stopped=true
    root_command systemctl stop netcontrold.service
    root_command mv -fT -- "$staged" "$destination"
    root_command systemctl start netcontrold.service
    local attempt
    for attempt in 1 2 3 4 5; do
        sleep 1
        root_command systemctl is-active --quiet netcontrold.service
    done
    committed=true
    printf 'Deployment completed: %s\nLogs: journalctl -u netcontrold -f\n' "$destination"
    if [[ $had_binary == true ]]; then printf 'Previous binary: %s\n' "$backup"; fi
)

main() {
    if [[ ${1:-} == --help ]]; then
        printf 'Usage: bash upgrade.sh [--build-only]\nIncrementally builds the current checkout on Ubuntu amd64, installs the systemd service if missing, and starts or upgrades netcontrold. No git pull, prerequisite installation or boot enablement.\n'
        return
    fi
    [[ $# -eq 0 || $# -eq 1 && $1 == --build-only ]] || { printf 'Use --help for usage.\n' >&2; return 1; }
    [[ $(uname -s) == Linux && -r /etc/os-release ]] || return 1
    local ID
    . /etc/os-release
    [[ ${ID:-} == ubuntu && $(dpkg --print-architecture) == amd64 ]] || { printf 'Ubuntu amd64 is required.\n' >&2; return 1; }
    local repository binary executable destination
    repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    cd "$repository"
    for executable in cargo rustup flock; do
        command -v "$executable" >/dev/null || { printf 'Missing prerequisite: %s. See docs/BUILD_AND_INSTALL.md.\n' "$executable" >&2; return 1; }
    done
    [[ -f Cargo.lock ]] || { printf 'The committed Cargo.lock is required.\n' >&2; return 1; }
    export CARGO_TARGET_DIR="$repository/target/in-place-upgrade"
    mkdir -p "$CARGO_TARGET_DIR"
    exec 9>"$CARGO_TARGET_DIR/upgrade.lock"
    flock -n 9 || { printf 'Another upgrade is running from this checkout.\n' >&2; return 1; }
    if [[ $# -eq 0 ]]; then
        [[ -d /run/systemd/system ]] || { printf 'A running systemd installation is required.\n' >&2; return 1; }
    fi
    CARGO_INCREMENTAL=1 cargo +stable build --locked --target x86_64-unknown-linux-gnu -p netcontrold
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/debug/netcontrold"
    "$binary" --help >/dev/null
    printf 'Built %s\n' "$binary"
    if [[ $# -eq 0 ]]; then
        destination=$(service_target "$repository") || return 1
        printf 'Service executable: %s\n' "$destination"
        printf 'Restarting the firewall daemon; use a local console or independent OS SSH session.\n'
        upgrade_binary "$binary" "$destination"
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi