#!/usr/bin/env bash
set -euo pipefail

root_command() {
    if [[ $EUID -eq 0 ]]; then "$@"; else sudo -- "$@"; fi
}

upgrade_binary() (
    set -euo pipefail
    local binary=$1 destination=${2:-/usr/local/sbin/netcontrold}
    local staged='' backup="$destination.previous" stopped=false committed=false
    recover() {
        local status=$?
        trap - EXIT INT TERM HUP
        if [[ $stopped == true && $committed == false ]]; then
            printf 'Upgrade interrupted or failed; restoring the previous binary.\n' >&2
            if root_command systemctl stop netcontrold.service &&
                root_command cp -p -- "$backup" "$staged" &&
                root_command mv -fT -- "$staged" "$destination" &&
                root_command systemctl start netcontrold.service; then
                printf 'Previous binary restored; inspect service logs and connectivity.\n' >&2
            else
                printf 'RECOVERY FAILED. Previous binary: %s; local console intervention required.\n' "$backup" >&2
            fi
        fi
        [[ -z $staged ]] || root_command rm -f -- "$staged"
        exit "$status"
    }
    trap recover EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    [[ -f $destination && ! -L $destination ]] || { printf 'Expected an installed regular daemon binary.\n' >&2; exit 1; }
    [[ ! -L $backup && ( ! -e $backup || -f $backup ) ]] || exit 1
    root_command systemctl is-active --quiet netcontrold.service || exit 1
    staged=$(root_command mktemp "${destination}.upgrade.XXXXXX")
    root_command install -o root -g root -m 0755 -- "$binary" "$staged"
    root_command cp -p -- "$destination" "$backup"
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
    printf 'Upgrade completed. Previous binary: %s\nLogs: journalctl -u netcontrold -f\n' "$backup"
)

main() {
    if [[ ${1:-} == --help ]]; then
        printf 'Usage: bash in-place-upgrade.sh [--build-only]\nIncrementally builds the current checkout on Ubuntu amd64, then replaces and restarts the existing netcontrold.service. No git pull, dependency installation or configuration changes.\n'
        return
    fi
    [[ $# -eq 0 || $# -eq 1 && $1 == --build-only ]] || { printf 'Use --help for usage.\n' >&2; return 1; }
    [[ $(uname -s) == Linux && -r /etc/os-release ]] || return 1
    local ID
    . /etc/os-release
    [[ ${ID:-} == ubuntu && $(dpkg --print-architecture) == amd64 ]] || { printf 'Ubuntu amd64 is required.\n' >&2; return 1; }
    local repository binary executable
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
        root_command systemctl show netcontrold.service --property=ExecStart --value |
            grep -Fq 'path=/usr/local/sbin/netcontrold ;' || { printf 'Service must execute /usr/local/sbin/netcontrold.\n' >&2; return 1; }
        root_command systemctl is-active --quiet netcontrold.service || { printf 'The existing service must be active.\n' >&2; return 1; }
    fi
    CARGO_INCREMENTAL=1 cargo +stable build --locked --target x86_64-unknown-linux-gnu -p netcontrold
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/debug/netcontrold"
    "$binary" --help >/dev/null
    printf 'Built %s\n' "$binary"
    if [[ $# -eq 0 ]]; then
        printf 'Restarting the firewall daemon; use a local console or independent OS SSH session.\n'
        upgrade_binary "$binary"
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi