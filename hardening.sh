#!/usr/bin/env bash
set -euo pipefail

hardening_unit_candidates=(cups.service cups.socket cups.path cups-browsed.service
    avahi-daemon.service avahi-daemon.socket apport.service whoopsie.service)
hardening_package_candidates=(cups cups-browsed cups-daemon cups-client
    avahi-daemon avahi-utils apport apport-gtk whoopsie popularity-contest ubuntu-report)
hardening_units=()
hardening_packages=()

hardening_check_host() {
    [[ $(uname -s) == Linux && -r /etc/os-release && -d /run/systemd/system ]] || {
        printf 'Requires Ubuntu amd64 with systemd.\n' >&2; return 1;
    }
    local ID
    . /etc/os-release
    [[ ${ID:-} == ubuntu && $(dpkg --print-architecture) == amd64 ]] || return 1
    local executable
    for executable in systemctl dpkg-query apt-get flock; do
        command -v "$executable" >/dev/null || return 1
    done
}

hardening_check_purge() {
    [[ ${#hardening_packages[@]} -gt 0 ]] || return 0
    local simulation operation package remainder removals=0
    simulation=$(LC_ALL=C apt-get --simulate purge -- "${hardening_packages[@]}") || return 1
    printf '%s\n' "$simulation"
    while read -r operation package remainder; do
        case $operation in
            Remv|Purg)
                package=${package%%:*}
                [[ " ${hardening_packages[*]} " == *" $package "* ]] || {
                    printf 'Refusing dependency removal outside the explicit profile: %s\n' "$package" >&2
                    return 1
                }
                removals=$((removals + 1)) ;;
            Inst)
                printf 'Refusing a purge plan that installs packages: %s\n' "$package" >&2
                return 1 ;;
        esac
    done <<< "$simulation"
    [[ $removals -gt 0 ]] || {
        printf 'APT returned no recognized removal plan; refusing to apply.\n' >&2; return 1;
    }
}

hardening_plan() {
    local unit state package information status essential protected
    hardening_units=()
    hardening_packages=()
    for unit in "${hardening_unit_candidates[@]}"; do
        state=$(systemctl show "$unit" --property LoadState --value) || return 1
        case $state in
            loaded) hardening_units+=("$unit") ;;
            not-found|masked) ;;
            *) printf 'Cannot inspect unit %s: %s\n' "$unit" "$state" >&2; return 1 ;;
        esac
    done
    for package in "${hardening_package_candidates[@]}"; do
        information=$(dpkg-query -W -f='${db:Status-Status}\t${Essential}\t${Protected}\n' "$package" 2>/dev/null) || continue
        read -r status essential protected <<< "$information"
        [[ $status == installed ]] || continue
        [[ $essential != yes && $protected != yes ]] || {
            printf 'Refusing an essential/protected package: %s\n' "$package" >&2; return 1;
        }
        hardening_packages+=("$package")
    done
    printf 'Disable/stop units: %s\n' "${hardening_units[*]:-(none)}"
    printf 'Purge installed packages: %s\n' "${hardening_packages[*]:-(none)}"
    hardening_check_purge || return 1
}

hardening_check_apparmor() {
    command -v update-grub >/dev/null || {
        printf 'AppArmor boot disable requires a supported GRUB installation.\n' >&2; return 1;
    }
    [[ -f /etc/default/grub && ! -L /etc/default/grub &&
       -f /boot/grub/grub.cfg && ! -L /boot/grub/grub.cfg &&
       ! -L /etc/default/grub.d && ( ! -e /etc/default/grub.d || -d /etc/default/grub.d ) ]] || return 1
    local target=/etc/default/grub.d/99-netcontrol-apparmor.cfg
    [[ ! -L $target && ( ! -e $target || -f $target ) ]] || return 1
}

hardening_disable_apparmor() {
    local backup=$1 directory=${2:-/etc/default/grub.d} previous=false state
    local target="$directory/99-netcontrol-apparmor.cfg"
    [[ ! -L $directory && ! -L $target && ( ! -e $target || -f $target ) ]] || return 1
    systemctl show apparmor.service --property ActiveState --property UnitFileState > "$backup/apparmor.service.state" || return 1
    install -d -m 0755 "$directory" || return 1
    if [[ -e $target ]]; then
        cp -a -- "$target" "$backup/apparmor-grub.cfg" || return 1
        previous=true
    fi
    printf 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} apparmor=0"\n' |
        install -o root -g root -m 0644 /dev/stdin "$target" || return 1
    if ! update-grub; then
        if [[ $previous == true ]]; then
            cp -a -- "$backup/apparmor-grub.cfg" "$target" || return 1
        else
            rm -- "$target" || return 1
        fi
        printf 'update-grub failed. Drop-in restored; inspect generated GRUB configuration before rebooting.\n' >&2
        return 1
    fi
    state=$(systemctl show apparmor.service --property LoadState --value) || return 1
    case $state in
        loaded) systemctl disable apparmor.service || return 1 ;;
        not-found|masked) ;;
        *) return 1 ;;
    esac
    printf 'AppArmor disable scheduled for next boot. Existing profiles remain active until reboot. No reboot performed.\n'
}

hardening_apply_plan() {
    local backup=$1 disable_apparmor=$2 unit
    hardening_check_purge || return 1
    for unit in "${hardening_units[@]}"; do
        systemctl show "$unit" --property ActiveState --property UnitFileState > "$backup/$unit.state" || return 1
    done
    if [[ ${#hardening_packages[@]} -gt 0 ]]; then
        dpkg-query -W -f='${binary:Package}\t${Version}\n' "${hardening_packages[@]}" > "$backup/packages.tsv" || return 1
    fi
    for unit in "${hardening_units[@]}"; do
        systemctl disable --now "$unit" || return 1
    done
    if [[ ${#hardening_packages[@]} -gt 0 ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get --assume-yes purge -- "${hardening_packages[@]}" || return 1
    fi
    if [[ $disable_apparmor == true ]]; then
        hardening_disable_apparmor "$backup" || return 1
    fi
}

main() {
    local apply=false disable_apparmor=false backup
    while [[ $# -gt 0 ]]; do
        case $1 in
            --apply) apply=true ;;
            --disable-apparmor) disable_apparmor=true ;;
            --help)
                printf 'Usage: sudo bash hardening.sh [--apply] [--disable-apparmor]\nDefault: preview only. --apply stops/disables printing, mDNS discovery and crash-reporting units and purges only explicit installed profile packages. No autoremove. Networking, Wi-Fi, SSH, time sync, security updates, firmware and build tools are preserved.\n--disable-apparmor explicitly opts out of AppArmor protection on the next boot using GRUB; without --apply it only previews that choice. Use a local console and take a device snapshot before applying. No reboot is performed.\n'
                return ;;
            *) printf 'Unknown hardening option: %s\n' "$1" >&2; return 1 ;;
        esac
        shift
    done
    hardening_check_host || return 1
    if [[ $apply == true && $EUID -ne 0 ]]; then
        printf 'Apply requires root.\n' >&2; return 1
    fi
    if [[ $disable_apparmor == true ]]; then
        printf 'WARNING: disabling AppArmor removes mandatory access-control protection; it is not a security improvement. GRUB reboot required.\n'
        hardening_check_apparmor || return 1
    fi
    hardening_plan || return 1
    if [[ $apply != true ]]; then
        printf 'Preview only; nothing changed. Review the plan, then use --apply from a local console.\n'
        return
    fi
    install -d -m 0700 /var/lib/netcontrol || return 1
    exec 9>/var/lib/netcontrol/os-hardening.lock
    flock -n 9 || { printf 'Another hardening run is active.\n' >&2; return 1; }
    backup=$(mktemp -d /var/lib/netcontrol/os-hardening.XXXXXX) || return 1
    chmod 0700 "$backup" || return 1
    printf 'Private pre-change state: %s\n' "$backup"
    if ! hardening_apply_plan "$backup" "$disable_apparmor"; then
        printf 'Hardening stopped on failure; earlier changes may already be applied. No automatic package rollback. Inspect %s before continuing.\n' "$backup" >&2
        return 1
    fi
    printf 'Footprint profile applied. State records: %s. No network configuration changed or reboot performed.\n' "$backup"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi