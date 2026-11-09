#!/usr/bin/env bash
set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/install.sh"

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
    local load_state
    if ! load_state=$(root_command systemctl show netcontrold.service --property=LoadState --value); then
        [[ $load_state == not-found ]] || return 1
    fi
    case $load_state in
        loaded) service_binary ;;
        not-found)
            printf 'No installed netcontrold service; use install.sh for initial provisioning. Upgrade does not initialize networking.\n' >&2
            return 1
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
    local binary=$1 destination=$2 installer=$3
    local staged='' backup="$destination.previous" stopped=false committed=false
    local had_binary=false was_active=false active_state phase='prepare replacement'
    recover() {
        local status=$?
        trap - EXIT INT TERM HUP
        if [[ $stopped == true && $committed == false ]]; then
            printf 'Deployment failed during %s (exit %s). Service diagnostics before recovery:\n' "$phase" "$status" >&2
            root_command systemctl show netcontrold.service \
                --property=ActiveState --property=SubState --property=Result \
                --property=ExecMainCode --property=ExecMainStatus >&2 || true
            root_command journalctl -u netcontrold.service --no-pager \
                --lines=60 --output=short-iso >&2 || true
            installer_message warning 'Upgrade failed. Restoring the previous installation.'
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
    installer_step 'Staging the new binary' root_command install -o root -g root -m 0755 -- "$binary" "$staged"
    phase='configure GitHub HTTPS upgrades'
    installer_step 'Configuring release updates' root_command "$staged" --configure-updates /etc/netcontrol/updates.json
    if [[ -f $destination ]]; then
        installer_step 'Saving the previous binary' root_command cp -p -- "$destination" "$backup"
        had_binary=true
    fi
    stopped=true
    phase='stop previous service'
    installer_step 'Stopping Netcontrol' root_command systemctl stop netcontrold.service
    phase='configure journald forwarding'
    installer_step 'Configuring host logging' root_command bash -c 'source "$1"; configure_host_logging' bash "$installer"
    phase='install replacement binary'
    installer_step 'Installing the new binary' root_command mv -fT -- "$staged" "$destination"
    phase='start replacement service'
    installer_step 'Starting Netcontrol' root_command systemctl start netcontrold.service
    phase='check replacement service stability'
    installer_message step 'Checking service stability.'
    local attempt
    for attempt in 1 2 3 4 5; do
        sleep 1
        root_command systemctl is-active --quiet netcontrold.service
    done
    committed=true
    installer_message success 'Upgrade complete.'
    printf 'Installed: %s\nLogs: journalctl -u netcontrold -f\n' "$destination"
    if [[ $had_binary == true ]]; then printf 'Previous binary: %s\n' "$backup"; fi
)

deploy_upgrade() {
    local binary=$1 destination=$2 installer=$3
    installer_message warning 'Use a local console or independent OS SSH session. Restarting may interrupt connectivity.'
    installer_message warning 'Configuration SSH defaults to localhost TCP 2222 only; explicit overrides are kept. Competing syslog receivers will be disabled.'
    installer_message warning 'Startup owns missing conntrack tuning settings using current values; existing saved tuning is kept.'
    installer_message warning 'OS NTP clients will be stopped and masked. Only explicitly enabled Netcontrol NTP will synchronize the clock.'
    installer_message warning 'AppArmor confinement and custom profiles will be removed. GRUB is required; active AppArmor requires manual reboot and upgrade rerun before binary replacement.'
    installer_step 'Configuring kernel modules and system services' root_command bash -c 'source "$1"; configure_apparmor && configure_conntrack && configure_link_diagnostics && configure_deny_logging && configure_motd && configure_ntp && configure_appliance_services && configure_logging_units && systemctl daemon-reload' bash "$installer" || return 1
    upgrade_binary "$binary" "$destination" "$installer"
}

main() {
    if [[ ${1:-} == --help ]]; then
        printf '%s\n' \
            'Usage: bash upgrade.sh [--build-only]' \
            '' \
            'Build the current checkout on Ubuntu amd64 and restart the installed service.' \
            '  --build-only  Build without changing the installed service.' \
            '' \
            'Requires stable Rust and installed build prerequisites; uses sudo for deployment.' \
            'Keeps custom startup arguments and saved networking; startup owns missing conntrack tuning values.' \
            'Enables host services, gateway monitoring, configuration SSH and journald forwarding.' \
            'Disables competing syslog receivers. SSH defaults to localhost TCP 2222 only; explicit overrides are kept.' \
            'Removes MOTD login messages/generators and stops/masks MOTD services.' \
            'Stops/masks OS NTP clients; only explicitly enabled Netcontrol NTP synchronizes the clock.' \
            'Disables AppArmor via GRUB; if active, stops for manual reboot/rerun before binary replacement.' \
            'Purges AppArmor policy/tooling and custom profiles, masks its service and pins out reinstall; required libraries/kernel code remain.' \
            'Use a local console or independent OS SSH session. Review firewall access.' \
            'No provisioning, reset, git pull, prerequisite installation or boot enablement.' \
            '' \
            'Output: color on terminals; NO_COLOR=1 disables it. Failed steps show diagnostics.' \
            'Details: docs/BUILD_AND_INSTALL.md'
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
    for executable in cargo rustup flock git; do
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
    CARGO_INCREMENTAL=1 installer_step 'Building Netcontrol (the first build may take a while)' cargo +stable build --locked --target x86_64-unknown-linux-gnu -p netcontrold
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/debug/netcontrold"
    "$binary" --help >/dev/null
    installer_message success 'Build complete.'
    if [[ $# -eq 0 ]]; then
        destination=$(service_target) || return 1
        installer_message step "Upgrading $destination."
        deploy_upgrade "$binary" "$destination" "$repository/install.sh"
    else
        printf 'Binary: %s\n' "$binary"
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi