#!/usr/bin/env bash
set -euo pipefail

hardening_unit_candidates=(cups.service cups.socket cups.path cups-browsed.service
    avahi-daemon.service avahi-daemon.socket apport.service whoopsie.service
    snapd.service snapd.socket apt-daily.timer apt-daily-upgrade.timer
    apt-daily.service apt-daily-upgrade.service)
hardening_package_candidates=(cups cups-browsed cups-daemon cups-client
    avahi-daemon avahi-utils apport apport-gtk whoopsie popularity-contest ubuntu-report)
hardening_units=()
hardening_mask_units=()
hardening_packages=()

hardening_check_host() {
    [[ $(uname -s) == Linux && -r /etc/os-release && -d /run/systemd/system ]] || {
        printf 'Requires Ubuntu amd64 with systemd.\n' >&2; return 1;
    }
    local ID
    . /etc/os-release
    [[ ${ID:-} == ubuntu && $(dpkg --print-architecture) == amd64 ]] || return 1
    local executable
    for executable in systemctl dpkg-query apt-get apt-config flock; do
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
    hardening_mask_units=()
    hardening_packages=()
    for unit in "${hardening_unit_candidates[@]}"; do
        if ! state=$(systemctl show "$unit" --property LoadState --value); then
            [[ $state == not-found ]] || {
                printf 'Cannot inspect unit %s.\n' "$unit" >&2; return 1;
            }
        fi
        case $state in
            loaded) hardening_units+=("$unit") ;;
            not-found|masked) ;;
            *) printf 'Cannot inspect unit %s: %s\n' "$unit" "$state" >&2; return 1 ;;
        esac
        case $unit in
            snapd.service|snapd.socket|apt-daily.timer|apt-daily-upgrade.timer|apt-daily.service|apt-daily-upgrade.service)
                if [[ $state == loaded || $state == masked ]]; then hardening_mask_units+=("$unit"); fi ;;
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
    printf 'Disable units (stop timers/non-APT services, never running APT jobs): %s\n' "${hardening_units[*]:-(none)}"
    printf 'Persistently mask Snap/automatic APT units: %s\n' "${hardening_mask_units[*]:-(none)}"
    printf 'WARNING: disable automatic APT checks, downloads and installation, including security updates; schedule manual patching. Running APT jobs are not interrupted.\n'
    printf 'Write and verify /etc/apt/apt.conf.d/99-netcontrol-no-automatic-updates (APT::Periodic Enable/Update-Package-Lists/Download-Upgradeable-Packages/Unattended-Upgrade = 0; Unattended-Upgrade::InstallOnShutdown = false).\n'
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

hardening_configure_os_updates() (
    set -euo pipefail
    local backup=$1 directory=${2:-/etc/apt/apt.conf.d} staged='' configuration key
    local target="$directory/99-netcontrol-no-automatic-updates"
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $target && ( ! -e $target || -f $target ) ]] || {
        printf 'Refusing non-regular automatic APT configuration: %s\n' "$target" >&2; exit 1;
    }
    if [[ -e $target ]]; then
        cp -a -- "$target" "$backup/apt-periodic.conf" || exit 1
        printf 'present\n' > "$backup/apt-periodic.state" || exit 1
    else
        printf 'absent\n' > "$backup/apt-periodic.state" || exit 1
    fi
    install -d -o root -g root -m 0755 "$directory" || exit 1
    staged=$(mktemp "$directory/.automatic-updates.XXXXXX") || exit 1
    trap '[[ -z $staged ]] || rm -f -- "$staged"' EXIT
    for key in Enable Update-Package-Lists Download-Upgradeable-Packages Unattended-Upgrade; do
        printf 'APT::Periodic::%s "0";\n' "$key"
    done > "$staged" || exit 1
    printf 'Unattended-Upgrade::InstallOnShutdown "false";\n' >> "$staged" || exit 1
    chmod 0644 "$staged" || exit 1
    mv -fT -- "$staged" "$target" || exit 1
    configuration=$(apt-config dump) || exit 1
    for key in Enable Update-Package-Lists Download-Upgradeable-Packages Unattended-Upgrade; do
        grep -Fxq "APT::Periodic::$key \"0\";" <<< "$configuration" || {
            printf 'Effective APT periodic setting %s is not disabled; inspect APT configuration precedence.\n' "$key" >&2; exit 1;
        }
    done
    grep -Fxq 'Unattended-Upgrade::InstallOnShutdown "false";' <<< "$configuration" || {
        printf 'Effective unattended upgrade on shutdown is not disabled; inspect APT configuration precedence.\n' >&2; exit 1;
    }
)

hardening_apply_plan() {
    local backup=$1 disable_apparmor=$2 unit status
    hardening_check_purge || return 1
    for unit in "${hardening_units[@]}" "${hardening_mask_units[@]}"; do
        systemctl show "$unit" --property ActiveState --property UnitFileState > "$backup/$unit.state" || return 1
    done
    if [[ ${#hardening_packages[@]} -gt 0 ]]; then
        dpkg-query -W -f='${binary:Package}\t${Version}\n' "${hardening_packages[@]}" > "$backup/packages.tsv" || return 1
    fi
    for unit in "${hardening_units[@]}"; do
        case $unit in
            apt-daily.service|apt-daily-upgrade.service) systemctl disable "$unit" || return 1 ;;
            *) systemctl disable --now "$unit" || return 1 ;;
        esac
    done
    for unit in "${hardening_mask_units[@]}"; do
        case $unit in
            apt-daily.service|apt-daily-upgrade.service) ;;
            *) systemctl stop "$unit" || return 1 ;;
        esac
        systemctl mask "$unit" || return 1
        status=$(systemctl show "$unit" --property ActiveState --property UnitFileState) || return 1
        if ! grep -Fxq 'UnitFileState=masked' <<< "$status" ||
           ! grep -Eq '^ActiveState=(inactive|failed)$' <<< "$status"; then
            printf 'Unit %s is not stopped and persistently masked.\n' "$unit" >&2
            case $unit in
                apt-daily.service|apt-daily-upgrade.service)
                    printf 'Wait for the running APT job to finish, then retry; APT jobs are never forcibly stopped.\n' >&2 ;;
            esac
            return 1
        fi
    done
    hardening_configure_os_updates "$backup" "${3:-/etc/apt/apt.conf.d}" || return 1
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
                printf 'Usage: sudo bash hardening.sh [--apply] [--disable-apparmor]\nDefault: preview only. --apply stops/disables printing, mDNS discovery and crash-reporting units and purges only explicit installed profile packages. Installed snapd.service and snapd.socket are stopped and persistently masked, including already-masked units; loaded Snap units are also disabled. Absent Snap units are skipped; Snap packages/data and separate Snap application units are retained. Snap installation/management and refreshes are blocked; review Snap-dependent workloads before applying. Automatic APT checks, downloads and installation, INCLUDING SECURITY UPDATES, are disabled using persistent apt-daily/apt-daily-upgrade timer/service masks and APT periodic configuration. Running APT jobs are never forcibly stopped; wait for completion and retry if verification fails. Manual apt-get update/upgrade and Netcontrol release checks remain available. Schedule manual patching. No autoremove. Networking, Wi-Fi, SSH, time sync, firmware and build tools are preserved.\n--disable-apparmor explicitly opts out of AppArmor protection on the next boot using GRUB; without --apply it only previews that choice. Use a local console and take a device snapshot before applying. No reboot is performed.\n'
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