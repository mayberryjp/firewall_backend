#!/usr/bin/env bash
set -euo pipefail

installer_message() {
    local level=$1 message=$2 color='' reset='' label
    case $level in
        step) label='..'; color=$'\033[1;36m' ;;
        success) label=OK; color=$'\033[1;32m' ;;
        warning) label=WARN; color=$'\033[1;33m' ;;
        error) label=FAIL; color=$'\033[1;31m' ;;
    esac
    if [[ -t 2 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
        reset=$'\033[0m'
    else
        color=''
    fi
    printf '%s[%s]%s %s\n' "$color" "$label" "$reset" "$message" >&2
}

installer_step() (
    local label=$1 output
    shift
    installer_message step "$label"
    output=$(mktemp) || {
        installer_message error 'Cannot create a temporary command log.'
        exit 1
    }
    finish_step() {
        local status=$?
        trap - EXIT
        if [[ $status -ne 0 ]]; then
            installer_message error "$label (exit $status)"
            cat -- "$output" >&2
        else
            sed -n '/^\[WARN\] /p' "$output" >&2 || status=$?
        fi
        rm -f -- "$output"
        exit "$status"
    }
    trap finish_step EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    "$@" > "$output" 2>&1
)

configure_conntrack() (
    set -euo pipefail
    local sysctl_directory=${1:-/etc/sysctl.d} modules_directory=${2:-/etc/modules-load.d}
    local sysctl_file="$sysctl_directory/90-netcontrol-conntrack.conf"
    local modules_file="$modules_directory/netcontrol-conntrack.conf"
    local executable path work actual
    for executable in modprobe sysctl install; do
        command -v "$executable" >/dev/null || {
            printf 'Missing %s; install kmod and procps before configuring conntrack.\n' "$executable" >&2
            exit 1
        }
    done
    for path in "$sysctl_file" "$modules_file"; do
        [[ ! -L $path && ( ! -e $path || -f $path ) ]] || {
            printf 'Refusing non-regular conntrack configuration: %s\n' "$path" >&2
            exit 1
        }
    done
    modprobe nf_conntrack || exit 1
    sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_checksum=1 || exit 1
    for path in net.netfilter.nf_conntrack_acct net.netfilter.nf_conntrack_checksum; do
        actual=$(sysctl -n "$path") || exit 1
        [[ $actual == 1 ]] || {
            printf 'Conntrack prerequisite did not take effect: %s\n' "$path" >&2
            exit 1
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    printf 'net.netfilter.nf_conntrack_acct = 1\nnet.netfilter.nf_conntrack_checksum = 1\n' > "$work/sysctl" || exit 1
    printf 'nf_conntrack\n' > "$work/modules" || exit 1
    install -d -m 0755 "$sysctl_directory" "$modules_directory" || exit 1
    install -o root -g root -m 0644 "$work/sysctl" "$sysctl_file" || exit 1
    install -o root -g root -m 0644 "$work/modules" "$modules_file" || exit 1
    installer_message success 'Conntrack accounting and checksum validation enabled.'
)

configure_link_diagnostics() (
    set -euo pipefail
    local directory=${1:-/etc/modules-load.d}
    local destination="$directory/netcontrol-link-diagnostics.conf" work module
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
        printf 'Refusing non-regular link diagnostics module configuration: %s\n' "$destination" >&2
        exit 1
    }
    for module in af_packet inet_diag tcp_diag; do
        modprobe "$module" || {
            printf 'Native link diagnostics require kernel CONFIG_PACKET, CONFIG_INET_DIAG and CONFIG_INET_TCP_DIAG (failed: %s).\n' "$module" >&2
            exit 1
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    printf 'af_packet\ninet_diag\ntcp_diag\n' > "$work/modules" || exit 1
    install -d -m 0755 "$directory" || exit 1
    install -o root -g root -m 0644 "$work/modules" "$destination" || exit 1
    installer_message success 'Link diagnostics modules enabled.'
)

configure_deny_logging() (
    set -euo pipefail
    local directory=${1:-/etc/modules-load.d}
    local destination="$directory/netcontrol-deny-log.conf" work module
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
        printf 'Refusing non-regular deny-log module configuration: %s\n' "$destination" >&2
        exit 1
    }
    for module in nf_tables nfnetlink_log nft_log; do
        modprobe "$module" || {
            printf 'Firewall telemetry requires CONFIG_NF_TABLES (including counter expressions), CONFIG_NETFILTER_NETLINK_LOG and CONFIG_NFT_LOG (failed: %s).\n' "$module" >&2
            exit 1
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    printf 'nf_tables\nnfnetlink_log\nnft_log\n' > "$work/modules" || exit 1
    install -d -m 0755 "$directory" || exit 1
    install -o root -g root -m 0644 "$work/modules" "$destination" || exit 1
    installer_message success 'Firewall telemetry modules enabled.'
)

configure_masked_units() (
    set -euo pipefail
    local label=$1 unit state status canonical
    shift
    local -a loaded=() masked=() present=() jobs=()
    local -A seen=()
    for unit in "$@"; do
        if ! state=$(systemctl show "$unit" --property LoadState --value); then
            [[ $state == not-found ]] || {
                printf 'Cannot inspect %s unit %s.\n' "$label" "$unit" >&2
                exit 1
            }
        fi
        case $state in
            loaded)
                case $unit in
                    apt-daily.service|apt-daily-upgrade.service) jobs+=("$unit") ;;
                    *)
                        if ! canonical=$(systemctl show "$unit" --property Id --value) ||
                           [[ -z $canonical || $canonical == *[[:space:]]* || $canonical == -* ]]; then
                            printf 'Cannot resolve canonical %s unit %s.\n' "$label" "$unit" >&2
                            exit 1
                        fi
                        if [[ ! ${seen[$canonical]+present} ]]; then
                            loaded+=("$canonical")
                            seen[$canonical]=1
                        fi ;;
                esac
                present+=("$unit") ;;
            masked) masked+=("$unit"); present+=("$unit") ;;
            not-found) ;;
            *) printf 'Unsupported %s unit state for %s: %s\n' "$label" "$unit" "$state" >&2; exit 1 ;;
        esac
    done
    if [[ ${#present[@]} -eq 0 ]]; then
        exit 0
    fi
    installer_message step "Disabling $label services."
    if [[ ${#loaded[@]} -gt 0 ]]; then
        # Disabling a unit can remove its aliases before --now tries to stop them.
        systemctl stop "${loaded[@]}" || exit 1
        systemctl disable "${loaded[@]}" || exit 1
    fi
    for unit in "${masked[@]}"; do
        case $unit in
            apt-daily.service|apt-daily-upgrade.service) ;;
            *) systemctl stop "$unit" || exit 1 ;;
        esac
    done
    if [[ ${#jobs[@]} -gt 0 ]]; then systemctl disable "${jobs[@]}" || exit 1; fi
    systemctl mask "${present[@]}" || exit 1
    for unit in "${present[@]}"; do
        status=$(systemctl show "$unit" --property ActiveState --property UnitFileState) || exit 1
        if ! grep -Fxq 'UnitFileState=masked' <<< "$status" ||
           ! grep -Eq '^ActiveState=(inactive|failed)$' <<< "$status"; then
            printf '%s unit %s is not stopped and persistently masked.\n' "$label" "$unit" >&2
            case $unit in
                apt-daily.service|apt-daily-upgrade.service)
                    printf 'Wait for the running APT job to finish, then retry; APT jobs are never forcibly stopped.\n' >&2 ;;
            esac
            exit 1
        fi
    done
)

configure_snap() {
    configure_masked_units Snap snapd.service snapd.socket
}

configure_sysstat_collection() (
    set -euo pipefail
    local unit status
    local -a units=(sysstat-collect.timer sysstat-collect.service)
    configure_masked_units Sysstat "${units[@]}" || exit 1
    systemctl mask "${units[@]}" || exit 1
    for unit in "${units[@]}"; do
        status=$(systemctl show "$unit" --property ActiveState --property UnitFileState) || exit 1
        if ! grep -Fxq 'UnitFileState=masked' <<< "$status" ||
           ! grep -Eq '^ActiveState=(inactive|failed)$' <<< "$status"; then
            printf 'Sysstat unit %s is not stopped and persistently masked.\n' "$unit" >&2
            exit 1
        fi
    done
    installer_message success 'Sysstat activity collection stopped and persistently masked; existing statistics preserved.'
)

configure_apparmor() (
    set -euo pipefail
    local root=${1:-/} path parent work previous=false enabled status active=false
    local grub="$root/etc/default/grub.d/99-netcontrol-apparmor.cfg"
    local generated="$root/boot/grub/grub.cfg"
    [[ $root == /* && -d $root && ! -L $root ]] || {
        printf 'Refusing unsafe AppArmor configuration root: %s\n' "$root" >&2; exit 1;
    }
    for path in update-grub systemctl; do
        command -v "$path" >/dev/null || {
            printf 'AppArmor disablement requires %s and a supported GRUB installation.\n' "$path" >&2; exit 1;
        }
    done
    for path in etc/default/grub.d boot/grub sys/module/apparmor/parameters; do
        parent="$root/$path"
        while [[ $parent != "$root" && $parent != / ]]; do
            [[ ! -L $parent && ( ! -e $parent || -d $parent || $parent == "$root/$path" ) ]] || {
                printf 'Refusing unsafe AppArmor path: %s\n' "$parent" >&2; exit 1;
            }
            parent=$(dirname -- "$parent")
        done
    done
    for path in "$root/etc/default/grub" "$generated"; do
        [[ -f $path && ! -L $path ]] || {
            printf 'AppArmor disablement requires a regular GRUB configuration: %s\n' "$path" >&2; exit 1;
        }
    done
    for path in "$grub"; do
        [[ ! -L $path && ( ! -e $path || -f $path ) ]] || {
            printf 'Refusing non-regular AppArmor configuration: %s\n' "$path" >&2; exit 1;
        }
    done
    work=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$work"' EXIT
    install -d -o root -g root -m 0755 "$root/etc/default/grub.d" || exit 1
    if [[ -e $grub ]]; then
        cp -a -- "$grub" "$work/grub.previous" || exit 1
        previous=true
    fi
    printf 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} apparmor=0"\n' > "$work/grub" || exit 1
    install -o root -g root -m 0644 "$work/grub" "$grub" || exit 1
    if ! update-grub || ! awk '
        $1 ~ /^(linux|linuxefi|linux16)$/ {
            found=1; last=""
            for (i=3; i<=NF; i++) if ($i ~ /^apparmor=/) last=$i
            if (last != "apparmor=0") invalid=1
        }
        END { exit (!found || invalid) }
    ' "$generated"; then
        if [[ $previous == true ]]; then
            cp -a -- "$work/grub.previous" "$grub" || exit 1
        else
            rm -- "$grub" || exit 1
        fi
        printf 'AppArmor GRUB generation/verification failed; drop-in restored. Inspect generated boot configuration before rebooting.\n' >&2
        exit 1
    fi
    if [[ -e $root/sys/module/apparmor/parameters/enabled ]]; then
        enabled=$(cat -- "$root/sys/module/apparmor/parameters/enabled") || exit 1
        case $enabled in
            N|0) ;;
            Y|1) active=true ;;
            *) printf 'Cannot verify running AppArmor state: %s\n' "$enabled" >&2; exit 1 ;;
        esac
    elif [[ -e $root/sys/module/apparmor ]]; then
        printf 'Cannot verify running AppArmor state: enabled parameter is missing.\n' >&2; exit 1
    fi
    if [[ -e $root/sys/kernel/security/lsm ]]; then
        enabled=$(cat -- "$root/sys/kernel/security/lsm") || exit 1
        if [[ ,$enabled, == *,apparmor,* ]]; then
            active=true
        fi
    fi
    configure_masked_units AppArmor apparmor.service || exit 1
    systemctl mask apparmor.service || exit 1
    status=$(systemctl show apparmor.service --property ActiveState --property UnitFileState) || exit 1
    grep -Fxq 'UnitFileState=masked' <<< "$status" &&
        grep -Eq '^ActiveState=(inactive|failed)$' <<< "$status" || {
            printf 'AppArmor service is not stopped and persistently masked.\n' >&2; exit 1;
        }
    installer_message success 'AppArmor disablement configured in GRUB; service persistently masked. All packages, profiles, caches and APT preferences preserved.'
    if [[ $active == true ]]; then
        installer_message warning 'AppArmor is still enabled in the running kernel. Installation/upgrade will continue without rebooting. Please reboot manually from a local console after Netcontrol is installed to apply apparmor=0; you may defer this reboot. Existing kernel confinement may remain active until then. No installer rerun is needed.'
    fi
)

configure_ntp() (
    set -euo pipefail
    local unit status process
    local -a units=(
        systemd-timesyncd.service chrony.service chronyd.service
        ntp.service ntpd.service ntpsec.service openntpd.service busybox-ntpd.service
        ntpdate.service ntpdate.timer ntpdate-debian.service
        sntp.service sntp.timer ntpdig.service ntpdig.timer
    )
    command -v pgrep >/dev/null || {
        printf 'Missing pgrep; install procps before taking ownership of NTP.\n' >&2
        exit 1
    }
    configure_masked_units NTP "${units[@]}" || exit 1
    systemctl mask "${units[@]}" || exit 1
    for unit in "${units[@]}"; do
        status=$(systemctl show "$unit" --property ActiveState --property UnitFileState) || exit 1
        if ! grep -Fxq 'UnitFileState=masked' <<< "$status" ||
           ! grep -Eq '^ActiveState=(inactive|failed)$' <<< "$status"; then
            printf 'NTP unit %s is not stopped and persistently masked.\n' "$unit" >&2
            exit 1
        fi
    done
    # pgrep uses the kernel's 15-character comm name, including truncated timesyncd.
    for process in systemd-timesyn chronyd ntpd ntpsec openntpd ntpdate ntpdate-debian sntp ntpdig; do
        if pgrep -x "$process" >/dev/null; then
            printf 'Competing NTP process %s is still running; disable its custom service, cron job or launcher before retrying.\n' "$process" >&2
            exit 1
        else
            status=$?
            [[ $status -eq 1 ]] || {
                printf 'Cannot inspect competing NTP process %s (pgrep exit %s).\n' "$process" "$status" >&2
                exit 1
            }
        fi
    done
    installer_message success 'OS NTP clients stopped and persistently masked; Netcontrol NTP settings preserved.'
)

configure_motd() (
    set -euo pipefail
    local root=${1:-/} relative path parent configuration staged='' unit status
    local -a units=(motd.service motd-news.service motd-news.timer update-motd.service update-motd.timer)
    [[ $root == /* && -d $root && ! -L $root ]] || {
        printf 'Refusing unsafe MOTD cleanup root: %s\n' "$root" >&2
        exit 1
    }
    root=${root%/}
    local -a targets=(
        etc/motd etc/motd.dynamic etc/motd.d etc/update-motd.d etc/default/motd-news
        run/motd run/motd.dynamic run/motd.d var/cache/motd-news
        usr/lib/motd.d usr/share/motd.d etc/cron.daily/update-motd
    )
    for relative in "${targets[@]}" etc/pam.d; do
        parent=${relative%/*}
        while [[ $parent != . && $parent != "$relative" ]]; do
            path="$root/$parent"
            [[ ! -L $path && ( ! -e $path || -d $path ) ]] || {
                printf 'Refusing unsafe MOTD parent directory: %s\n' "$path" >&2
                exit 1
            }
            relative=$parent
            parent=${relative%/*}
        done
    done
    [[ ! -L $root/etc/pam.d && ( ! -e $root/etc/pam.d || -d $root/etc/pam.d ) ]] || {
        printf 'Refusing unsafe PAM directory: %s/etc/pam.d\n' "$root" >&2
        exit 1
    }
    configure_masked_units MOTD "${units[@]}" || exit 1
    # Mask absent standard units too, so package reinstalls cannot enable them.
    systemctl mask "${units[@]}" || exit 1
    for unit in "${units[@]}"; do
        status=$(systemctl show "$unit" --property UnitFileState --value) || exit 1
        [[ $status == masked ]] || {
            printf 'MOTD unit %s is not persistently masked.\n' "$unit" >&2
            exit 1
        }
    done
    for path in "$root"/etc/pam.d/*; do
        [[ -e $path || -L $path ]] || continue
        [[ -f $path && ! -L $path ]] || {
            printf 'Refusing non-regular PAM configuration: %s\n' "$path" >&2
            exit 1
        }
        if grep -Eq '^[[:space:]]*[^#[:space:]].*[[:space:]/]pam_motd\.so([[:space:]]|$)' "$path"; then
            configuration=$path
            staged=$(mktemp "${configuration}.motd.XXXXXX") || exit 1
            trap '[[ -z $staged ]] || rm -f -- "$staged"' EXIT
            cp -p -- "$configuration" "$staged" || exit 1
            awk '!/^[[:space:]]*#/ && /(^|[[:space:]\/])pam_motd\.so([[:space:]]|$)/ { next } { print }' \
                "$configuration" > "$staged" || exit 1
            mv -fT -- "$staged" "$configuration" || exit 1
            staged=''
        else
            [[ $? -eq 1 ]] || {
                printf 'Cannot inspect PAM MOTD configuration: %s\n' "$path" >&2
                exit 1
            }
        fi
    done
    for relative in "${targets[@]}"; do
        path="$root/$relative"
        rm -rf -- "$path" || exit 1
        [[ ! -e $path && ! -L $path ]] || {
            printf 'MOTD cleanup did not remove %s.\n' "$path" >&2
            exit 1
        }
    done
    installer_message success 'MOTD services, login messages and generators removed.'
)

configure_os_updates() (
    set -euo pipefail
    local directory=${1:-/etc/apt/apt.conf.d} staged='' configuration key
    local target="$directory/99-netcontrol-no-automatic-updates"
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $target && ( ! -e $target || -f $target ) ]] || {
        printf 'Refusing non-regular automatic APT configuration: %s\n' "$target" >&2; exit 1;
    }
    installer_message warning 'Automatic OS updates, including security fixes, will be disabled. Schedule manual patching.'
    configure_masked_units APT apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service || exit 1
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
    installer_message success 'Automatic OS updates disabled.'
)

configure_network_wait() (
    set -euo pipefail
    local unit=systemd-networkd-wait-online.service status
    configure_masked_units Network-online "$unit" || exit 1
    systemctl mask "$unit" || exit 1
    status=$(systemctl show "$unit" --property ActiveState --property UnitFileState) || exit 1
    if ! grep -Fxq 'UnitFileState=masked' <<< "$status" ||
       ! grep -Eq '^ActiveState=(inactive|failed)$' <<< "$status"; then
        printf 'Network-online unit %s is not stopped and persistently masked.\n' "$unit" >&2
        exit 1
    fi
    installer_message success 'Networkd online wait disabled; networking services are unchanged.'
)

configure_appliance_services() (
    set -euo pipefail
    local directory=${1:-/etc/systemd/system/netcontrold.service.d}
    local destination="$directory/50-netcontrol-appliance-services.conf" staged=''
    [[ ! -L $directory && ( ! -e $directory || -d $directory ) &&
       ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
        printf 'Refusing non-regular appliance service configuration: %s\n' "$destination" >&2
        exit 1
    }
    configure_network_wait || exit 1
    install -d -o root -g root -m 0755 "$directory" || exit 1
    staged=$(mktemp "$directory/.appliance-services.XXXXXX") || exit 1
    trap '[[ -z $staged ]] || rm -f -- "$staged"' EXIT
    printf '[Unit]\nRequires=netcontrol-syslog.socket\nAfter=netcontrol-syslog.socket systemd-journald.service\nStartLimitIntervalSec=0\n\n[Service]\nType=notify\nNotifyAccess=main\nWatchdogSec=60s\nWatchdogSignal=SIGKILL\nTimeoutStartSec=180s\nRestart=on-failure\nRestartSec=5s\nLimitCORE=0\nSockets=netcontrol-syslog.socket\nSyslogIdentifier=netcontrold\nEnvironment=NETCONTROL_ALLOW_HOST_SERVICES=true\nEnvironment=NETCONTROL_GATEWAY_MONITORING=true\nEnvironment=NETCONTROL_SSH_LISTEN=127.0.0.1:2222\nEnvironment=NETCONTROL_UPGRADE_CONFIG=/etc/netcontrol/updates.json\n' > "$staged" || exit 1
    chmod 0644 "$staged" || exit 1
    mv -fT -- "$staged" "$destination" || exit 1
    installer_message success 'Host services, gateway monitoring and localhost configuration SSH enabled.'
)

configure_logging_units() (
    set -euo pipefail
    local root=${1:-/etc} work staged='' relative directory destination
    work=$(mktemp -d) || exit 1
    trap '[[ -z $staged ]] || rm -f -- "$staged"; rm -rf -- "$work"' EXIT
    printf '[Unit]\nDescription=Netcontrol journald syslog receiver\nPartOf=netcontrold.service\n\n[Socket]\nListenDatagram=/run/systemd/journal/syslog\nSocketMode=0600\nService=netcontrold.service\nFileDescriptorName=netcontrol-syslog\nRemoveOnStop=yes\n' > "$work/netcontrol-syslog.socket" || exit 1
    printf '[Journal]\nForwardToSyslog=yes\nMaxLevelSyslog=debug\nReadKMsg=yes\nStorage=persistent\nSystemMaxUse=128M\nSystemKeepFree=256M\nRuntimeMaxUse=32M\nMaxRetentionSec=7day\n' > "$work/90-netcontrol-syslog.conf" || exit 1
    for relative in systemd/system/netcontrol-syslog.socket systemd/journald.conf.d/90-netcontrol-syslog.conf; do
        destination="$root/$relative"
        directory=${destination%/*}
        [[ ! -L $root/systemd && ! -L $directory &&
           ( ! -e $directory || -d $directory ) &&
           ! -L $destination && ( ! -e $destination || -f $destination ) ]] || {
            printf 'Refusing unsafe logging configuration: %s\n' "$destination" >&2
            exit 1
        }
        install -d -o root -g root -m 0755 "$directory" || exit 1
        staged=$(mktemp "$directory/.netcontrol-logging.XXXXXX") || exit 1
        install -o root -g root -m 0644 "$work/${destination##*/}" "$staged" || exit 1
        mv -fT -- "$staged" "$destination" || exit 1
        staged=''
    done
)

configure_host_logging() (
    set -euo pipefail
    local forwarding_socket=${1:-/run/systemd/journal/syslog} unix_sockets=${2:-/proc/net/unix}
    local unit state status
    installer_message step 'Configuring host logging.'
    for unit in rsyslog.service syslog-ng.service syslog.service syslogd.service busybox-syslogd.service \
        syslog.socket; do
        if ! state=$(systemctl show "$unit" --property=LoadState --value); then
            [[ $state == not-found ]] || {
                printf 'Cannot inspect conflicting logger %s.\n' "$unit" >&2
                exit 1
            }
        fi
        case $state in
            not-found) continue ;;
            loaded|masked) ;;
            error)
                # An alias of an already masked logger (syslog.service -> rsyslog.service) fails to load but cannot run.
                [[ $(systemctl is-enabled "$unit" 2>/dev/null || true) == masked ]] || {
                    printf 'Unsupported logger load state for %s: %s\n' "$unit" "$state" >&2
                    exit 1
                }
                continue ;;
            *) printf 'Unsupported logger load state for %s: %s\n' "$unit" "$state" >&2; exit 1 ;;
        esac
        systemctl mask --now "$unit" || {
            printf 'Cannot stop/mask conflicting logger %s; deployment aborted.\n' "$unit" >&2
            exit 1
        }
        state=$(systemctl show "$unit" --property=ActiveState --value) || exit 1
        [[ $state == inactive || $state == failed ]] || {
            printf 'Conflicting logger %s is still %s; deployment aborted.\n' "$unit" "$state" >&2
            exit 1
        }
    done
    if [[ -L $forwarding_socket || ( -e $forwarding_socket && ! -S $forwarding_socket ) ]]; then
        printf 'Refusing non-socket/symlink syslog forwarding path: %s\n' "$forwarding_socket" >&2
        exit 1
    fi
    if [[ -S $forwarding_socket ]]; then
        if awk -v socket="$forwarding_socket" \
            '$8 == socket { found=1 } END { exit !found }' "$unix_sockets"; then
            printf 'Syslog forwarding socket %s is still bound; stop its owner explicitly. No socket removed.\n' "$forwarding_socket" >&2
            exit 1
        else
            status=$?
            [[ $status -eq 1 ]] || {
                printf 'Cannot inspect syslog socket ownership; no socket removed.\n' >&2
                exit 1
            }
        fi
        rm -- "$forwarding_socket" || exit 1
    fi
    systemctl start systemd-journald-dev-log.socket || {
        printf 'Cannot start journald /dev/log input; deployment aborted.\n' >&2
        exit 1
    }
    systemctl restart systemd-journald.service || {
        printf 'Cannot activate journald syslog forwarding; deployment aborted.\n' >&2
        exit 1
    }
    journalctl --flush || {
        printf 'Cannot flush persistent host journal; deployment aborted.\n' >&2
        exit 1
    }
)

check_systemd_unit() {
    local unit=netcontrold.service
    local destination=/etc/systemd/system/netcontrold.service
    if [[ -L $destination ]] || { [[ -e $destination ]] && ! cmp -s "$unit" "$destination"; }; then
        printf 'Existing %s differs from the supplied unit; refusing to overwrite it. Use systemd drop-ins for customization.\n' "$destination" >&2
        return 1
    fi
}

configure_upgrade_settings() {
    "${1:-/usr/local/sbin/netcontrold}" --configure-updates /etc/netcontrol/updates.json
}

install_systemd_service() {
    check_systemd_unit || return 1
    configure_os_updates || return 1
    configure_snap || return 1
    configure_motd || return 1
    configure_ntp || return 1
    configure_sysstat_collection || return 1
    install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys || return 1
    install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service || return 1
    configure_upgrade_settings || return 1
    configure_appliance_services || return 1
    configure_logging_units || return 1
    systemctl daemon-reload || return 1
    configure_host_logging || return 1
}

select_appliance_ports() {
    local wan=${1:-} lan=${2:-} directory=${3:-/sys/class/net} vlan_table=${4:-/proc/net/vlan/config} path name
    local -a interfaces=()
    mapfile -t interfaces < <(
        for path in "$directory"/*; do
            name=${path##*/}
            [[ $name != lo && -d $path/device && -r $path/type && $(< "$path/type") == 1 &&
               ! -d $path/wireless && ! -e $path/phy80211 ]] || continue
            printf '%s\n' "$name"
        done | LC_ALL=C sort -V
    )
    if [[ -z $wan && -z $lan ]]; then
        [[ ${#interfaces[@]} -ge 2 ]] || { printf 'At least two physical Ethernet interfaces are required.\n' >&2; return 1; }
        wan=${interfaces[0]}
        lan=${interfaces[1]}
    fi
    local lan_parent=$lan details
    if [[ " ${interfaces[*]} " != *" $lan "* ]]; then
        details=$(lan_vlan_details "$lan" "$vlan_table") || {
            printf 'LAN must be an existing physical Ethernet interface or an existing VLAN on a physical Ethernet parent.\n' >&2
            return 1
        }
        read -r lan_parent _ <<< "$details"
        [[ -d $directory/$lan && -r $directory/$lan/type && $(< "$directory/$lan/type") == 1 ]] || return 1
    fi
    [[ -n $wan && -n $lan && $wan != "$lan" && $wan != "$lan_parent" &&
       " ${interfaces[*]} " == *" $wan "* && " ${interfaces[*]} " == *" $lan_parent "* ]] || {
        printf 'WAN must be a physical Ethernet port distinct from the physical LAN or VLAN parent.\n' >&2
        return 1
    }
    printf '%s %s\n' "$wan" "$lan"
}

lan_vlan_details() {
    local wanted=$1 table=${2:-/proc/net/vlan/config} name id parent rest found='' count=0
    [[ -r $table ]] || return 1
    while IFS='|' read -r name id parent rest; do
        name=${name//[[:space:]]/}
        [[ $name == "$wanted" ]] || continue
        id=${id//[[:space:]]/}
        parent=${parent//[[:space:]]/}
        [[ $id =~ ^[1-9][0-9]{0,3}$ && $parent =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ ]] || return 1
        (( id <= 4094 )) || return 1
        found="$parent $id"
        count=$((count + 1))
    done < "$table"
    [[ $count -eq 1 ]] || return 1
    printf '%s\n' "$found"
}

valid_lan_address() {
    local address=$1 a b c d prefix ip mask network
    [[ $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
    IFS='./' read -r a b c d prefix <<< "$address"
    a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d)); prefix=$((10#$prefix))
    [[ $address == "$a.$b.$c.$d/$prefix" ]] || return 1
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 && prefix >= 8 && prefix <= 30 )) || return 1
    (( (a == 10 && prefix >= 8) ||
       (a == 172 && b >= 16 && b <= 31 && prefix >= 12) ||
       (a == 192 && b == 168 && prefix >= 16) )) || return 1
    ip=$(( (a << 24) | (b << 16) | (c << 8) | d ))
    mask=$(( (0xffffffff << (32 - prefix)) & 0xffffffff ))
    network=$(( ip & mask ))
    (( ip != network && ip != (network | (0xffffffff ^ mask)) ))
}

provision_appliance() {
    local binary=$1 plan=$2 address=$3
    "$binary" --backend linux --appliance \
        --state /var/lib/netcontrol/native-state.json \
        --credential-db /var/lib/netcontrol/credentials.json \
        --keys /etc/netcontrol/keys \
        --services-state-dir /var/lib/netcontrol/services \
        --provision-network "$plan" || return 1
    printf 'NETCONTROL_LISTEN=%s:8080\n' "$address" |
        install -o root -g root -m 0600 /dev/stdin /etc/netcontrol/appliance.env || return 1
    systemctl daemon-reload || return 1
    systemctl enable --now netcontrold.service || return 1
    curl --noproxy '*' --silent --show-error --fail --retry 15 \
        --retry-connrefused --retry-all-errors --retry-delay 1 --max-time 2 \
        "http://$address:8080/" >/dev/null || return 1
    [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || {
        printf 'Appliance startup did not enable IPv4 forwarding. Inspect the service journal.\n' >&2
        return 1
    }
}

prepare_network_plan() {
    local binary=$1 plan=$2 supplied=$3 approved=$4 address answer
    if [[ $supplied == false ]]; then
        "$binary" --plan-network "$plan" || return 1
    fi
    address=$("$binary" --check-network-plan "$plan") || return 1
    if [[ $supplied == true ]]; then
        printf 'Proposed network plan (replaces imported networking/firewall):\n' >&2
        cat -- "$plan" >&2 || return 1
        printf '\nAll LANs are trusted for router access; LAN -> WAN forwarding and IPv4 masquerade only. No DHCP/DNS server.\n' >&2
        if [[ $approved != true ]]; then
            printf 'Apply this plan without connectivity rollback? Type yes: ' >&2
            if ! IFS= read -r answer || [[ $answer != yes ]]; then
                printf '\nInstallation cancelled.\n' >&2
                return 1
            fi
        fi
    fi
    [[ $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        printf 'Daemon returned an invalid management IPv4 address.\n' >&2
        return 1
    }
    printf '%s\n' "$address"
}

download_prebuilt() {
    local destination=$1 version base
    release_download 'https://api.github.com/repos/mayberryjp/firewall_backend/releases/latest' \
        "$destination/release.json" 1048576 || return 1
    version=$(python3 - "$destination/release.json" <<'PY'
import datetime
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    release = json.load(source)
if not isinstance(release, dict):
    sys.exit("Invalid GitHub release response")
tag = release.get("tag_name")
if (release.get("draft") is not False or release.get("prerelease") is not False
        or not isinstance(tag, str)
        or not re.fullmatch(r"v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]{0,9}", tag)):
    sys.exit("Expected a published stable calendar-version release")
version = tag[1:]
year, month, day, iteration = map(int, version.split("."))
datetime.date(year, month, day)
if iteration > 4294967295:
    sys.exit("Release iteration exceeds the supported range")
assets = release.get("assets")
if not isinstance(assets, list):
    sys.exit("Release is missing its Ubuntu assets")
base = f"https://github.com/mayberryjp/firewall_backend/releases/download/{tag}/"
for name in ("netcontrol-ubuntu-amd64.json", "netcontrold-ubuntu-amd64"):
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == name]
    if len(matches) != 1 or matches[0].get("browser_download_url") != base + name:
        sys.exit(f"Release is missing a unique trusted Ubuntu asset: {name}")
print(version)
PY
    ) || { printf 'Cannot select a valid stable Ubuntu release.\n' >&2; return 1; }
    base="https://github.com/mayberryjp/firewall_backend/releases/download/v$version"
    release_download "$base/netcontrol-ubuntu-amd64.json" "$destination/manifest.json" 4096 || return 1
    release_download "$base/netcontrold-ubuntu-amd64" "$destination/netcontrold" 268435456 true || return 1
    python3 - "$destination" "$version" <<'PY' || return 1
import hashlib
import json
import pathlib
import re
import sys

def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate manifest field: {key}")
        result[key] = value
    return result

directory = pathlib.Path(sys.argv[1])
manifest_path = directory / "manifest.json"
binary_path = directory / "netcontrold"
for path in (manifest_path, binary_path):
    if path.is_symlink() or not path.is_file():
        sys.exit("Release downloads must be regular files")
if manifest_path.stat().st_size > 4096:
    sys.exit("Release manifest exceeds 4096 bytes")
manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=unique_fields)
if (not isinstance(manifest, dict)
        or set(manifest) != {"schema", "version", "target", "size", "sha256"}
        or type(manifest["schema"]) is not int or manifest["schema"] != 1
        or manifest["version"] != sys.argv[2]
        or manifest["target"] != "ubuntu-amd64-systemd"
        or type(manifest["size"]) is not int or not 64 <= manifest["size"] <= 268435456
        or not isinstance(manifest["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])):
    sys.exit("Invalid Ubuntu release manifest or release version mismatch")
with binary_path.open("rb") as binary:
    digest = hashlib.sha256()
    header = binary.read(64)
    digest.update(header)
    for chunk in iter(lambda: binary.read(1024 * 1024), b""):
        digest.update(chunk)
if binary_path.stat().st_size != manifest["size"] or digest.hexdigest() != manifest["sha256"]:
    sys.exit("Release binary size or SHA-256 mismatch")
if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
    sys.exit("Release binary must be an amd64 Linux ELF executable")
PY
    release_download \
        "https://raw.githubusercontent.com/mayberryjp/firewall_backend/v$version/packaging/native/netcontrold.service" \
        "$destination/netcontrold.service" 65536 || return 1
    [[ -f $destination/netcontrold.service && -s $destination/netcontrold.service && ! -L $destination/netcontrold.service ]] || {
        printf 'Release systemd unit is empty or not a regular download.\n' >&2
        return 1
    }
    printf '%s\n' "$version" > "$destination/release-version" || return 1
    installer_message success "Verified release v$version."
}

release_download() {
    local url=$1 destination=$2 limit=$3 resume=${4:-false}
    local partial="$destination.part" attempt status http_status size
    local -a continuation=()
    : > "$partial" || return 1
    if [[ $resume == true ]]; then continuation=(--continue-at -); fi
    for attempt in 1 2 3 4 5; do
        if [[ $resume != true ]]; then : > "$partial" || return 1; fi
        if http_status=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location \
            --silent --show-error --connect-timeout 30 --max-time 900 \
            --speed-limit 1024 --speed-time 60 --max-filesize "$limit" \
            "${continuation[@]}" --write-out '%{http_code}' --output "$partial" "$url"); then
            size=$(stat -c %s -- "$partial") || return 1
            if [[ $size -le $limit ]]; then
                mv -f -- "$partial" "$destination" || return 1
                return 0
            fi
            printf 'Release download exceeds %s bytes: %s\n' "$limit" "$url" >&2
            break
        else
            status=$?
        fi
        case $status:$http_status in
            5:*|6:*|7:*|16:*|18:*|28:*|35:*|52:*|55:*|56:*|92:*) ;;
            22:408|22:429|22:500|22:502|22:503|22:504) ;;
            33:*|36:*|22:416)
                [[ $resume == true ]] || break
                installer_message warning 'Release server refused download resume; discarding partial data.'
                : > "$partial" || return 1 ;;
            *) break ;;
        esac
        if [[ $attempt -lt 5 ]]; then
            installer_message warning "Release download attempt $attempt/5 failed (curl $status, HTTP ${http_status:-unknown}); retrying in 5 seconds."
            sleep 5 || return 1
        fi
    done
    rm -f -- "$partial" || return 1
    printf 'Release download failed after %s attempt(s): %s. Check internet/DNS access and stable release availability; rerun the installer when connectivity recovers.\n' "$attempt" "$url" >&2
    return 1
}

check_prebuilt() (
    set -euo pipefail
    cd "$1" || exit 1
    chmod 0755 netcontrold || exit 1
    local actual_version expected_version help
    expected_version=$(< release-version)
    actual_version=$(./netcontrold --version) || exit 1
    if [[ $actual_version != "netcontrold $expected_version" ]]; then
        printf 'Downloaded daemon version does not match the selected release.\n' >&2
        exit 1
    fi
    help=$(./netcontrold --help) || exit 1
    if ! grep -q -- --provision-network <<< "$help" ||
       ! grep -q -- --plan-network <<< "$help" ||
       ! grep -q -- --check-network-plan <<< "$help" ||
       ! grep -q console-host-takeover <<< "$help" ||
       ! grep -q conntrack-tuning-ownership <<< "$help" ||
       ! grep -q NETCONTROL_ALLOW_HOST_SERVICES <<< "$help" ||
       ! grep -q NETCONTROL_GATEWAY_MONITORING <<< "$help" ||
       ! grep -q NETCONTROL_SSH_LISTEN <<< "$help" ||
       ! grep -q NETCONTROL_UPGRADE_CONFIG <<< "$help" ||
       ! grep -q -- --configure-updates <<< "$help"; then
        printf 'Release lacks current appliance provisioning/service/SSH environment support. No older-contract fallback is provided.\n' >&2
        exit 1
    fi
)

check_fresh_installation() {
    local state=$1 environment=$2 lock="$1.lock" path
    for path in "$state" "$environment"; do
        [[ ! -e $path && ! -L $path ]] || {
            printf 'Fresh appliance installation required; refusing existing %s. Do not delete appliance state to reinstall.\n' "$path" >&2
            return 1
        }
    done
    if [[ -e $lock || -L $lock ]]; then
        [[ -f $lock && ! -L $lock ]] &&
            [[ $(stat -c '%u:%a:%h:%s' -- "$lock") == "$EUID:600:1:0" ]] || {
            printf 'Refusing unsafe or nonempty state lock %s; expected an installer-owned mode-0600 empty regular file with one link.\n' "$lock" >&2
            return 1
        }
        command -v flock >/dev/null || {
            printf 'The flock command (util-linux) is required to check an existing state lock safely.\n' >&2
            return 1
        }
        flock --nonblock --exclusive -- "$lock" true || {
            printf 'State lock %s is held by another process or cannot be checked; stop the owning process before retrying.\n' "$lock" >&2
            return 1
        }
    fi
}

main() {
    local network_plan='' management_address supplied=false approved=false
    if [[ ${1:-} == --help ]]; then
        printf '%s\n' \
            'Usage: sudo bash install.sh [--network-plan FILE [--yes]]' \
            '' \
            'Install the latest stable release on a fresh Ubuntu amd64 host.' \
            'Requires root, systemd-networkd, systemd-resolved and a local console.' \
            '' \
            'Walks through every Ethernet port and VLAN: roles, DHCP/static IPv4, WAN gateway/DNS.' \
            'Create VLANs with explicit parent/ID, including shared WAN/LAN trunks.' \
            'Select a private static management LAN; review and confirm before network takeover.' \
            'Exactly one WAN; multiple trusted LANs; IPv6 configured later in the controller.' \
            '  --network-plan FILE  Use a reviewed JSON network plan instead of the wizard' \
            '  --yes                Approve that supplied plan without a confirmation prompt' \
            '' \
            'Unattended installs require --network-plan FILE --yes.' \
            'Replaces imported interface addressing/routes/DNS and firewall with the reviewed plan.' \
            'Allows router access from all LANs, LAN-to-WAN forwarding/NAT; drops unsolicited WAN traffic.' \
            'Disables unsupported settings and competing managers.' \
            'Captures current conntrack tuning values into owned configuration.' \
            'No connectivity rollback. Review the starter firewall policy from the console.' \
            'Disables Snap, competing syslog receivers and automatic OS updates, including security fixes.' \
            'Removes MOTD login messages/generators and stops/masks MOTD services.' \
            'Stops/masks OS NTP clients; Netcontrol NTP remains disabled until explicitly configured.' \
            'Stops/masks the sysstat collection timer and service; preserves existing statistics.' \
            'Schedules AppArmor disablement via GRUB; if active, recommends a manual reboot after installation.' \
            'Installation continues without rebooting; reboot may be deferred and no installer rerun is needed.' \
            'Persistently masks AppArmor service; preserves all packages, profiles, caches and APT preferences.' \
            'Schedule manual OS patching. LAN clients need static addresses; no DHCP/DNS server is installed.' \
            'Enables LAN HTTP setup, localhost configuration SSH on TCP 2222 and startup at boot.' \
            '' \
            'Output: color on terminals; NO_COLOR=1 disables it. Failed steps show diagnostics.' \
            'Details: docs/BUILD_AND_INSTALL.md'
        return
    fi
    while [[ $# -gt 0 ]]; do
        case $1 in
            --network-plan)
                [[ $# -ge 2 && -z $network_plan && -n $2 ]] || { printf 'Specify --network-plan FILE once.\n' >&2; return 1; }
                network_plan=$2; supplied=true; shift 2 ;;
            --yes)
                [[ $approved == false ]] || { printf 'Specify --yes once.\n' >&2; return 1; }
                approved=true; shift ;;
            *) printf 'Unknown option: %s. Use --help.\n' "$1" >&2; return 1 ;;
        esac
    done
    if [[ $approved == true && $supplied == false ]]; then
        printf '%s\n' '--yes requires --network-plan FILE.' >&2
        return 1
    fi
    if [[ $supplied == true ]]; then
        [[ -f $network_plan && ! -L $network_plan ]] || { printf 'Network plan must be a regular, non-symlink file.\n' >&2; return 1; }
        network_plan=$(readlink -f -- "$network_plan") || return 1
    fi
    if [[ $(uname -s) != Linux || ! -r /etc/os-release ]]; then
        printf 'This prebuilt installer requires Ubuntu Linux amd64.\n' >&2
        return 1
    fi
    local ID
    . /etc/os-release
    if [[ ${ID:-} != ubuntu ]] || [[ $(dpkg --print-architecture) != amd64 ]]; then
        printf 'This prebuilt installer requires Ubuntu amd64.\n' >&2
        return 1
    fi
    if [[ $EUID -ne 0 ]]; then
        printf 'Run with sudo bash install.sh (or as root).\n' >&2
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
        printf 'This installer requires Ubuntu running systemd.\n' >&2
        return 1
    fi

    check_fresh_installation /var/lib/netcontrol/native-state.json /etc/netcontrol/appliance.env || return 1
    if [[ ! -t 0 && ( $supplied == false || $approved == false ) ]]; then
        printf 'Noninteractive installation requires --network-plan FILE --yes; use a local terminal for the wizard.\n' >&2
        return 1
    fi
    installer_message warning 'Use a local console. Host networking will be taken over without connectivity rollback.'
    installer_message warning 'Automatic OS updates, including security fixes, and Snap will be disabled. Schedule manual patching.'
    installer_message warning 'Competing syslog receivers will be disabled. Configuration SSH listens on localhost TCP 2222 only by default.'
    installer_message warning 'OS NTP clients will be stopped and masked. Configure Netcontrol NTP explicitly to synchronize the clock.'
    installer_message warning 'AppArmor confinement will be disabled on the next boot; packages and profiles are preserved. GRUB is required. Installation continues without a reboot; reboot manually afterward when convenient.'
    systemctl is-active --quiet systemd-networkd.service || {
        installer_message error 'systemd-networkd must be running.'
        return 1
    }
    systemctl is-active --quiet systemd-resolved.service || {
        installer_message error 'systemd-resolved must be running.'
        return 1
    }
    installer_step 'Refreshing package lists' apt-get update || return 1
    installer_step 'Installing prerequisites' apt-get install --no-install-recommends -y ca-certificates python3 procps kmod curl || return 1
    if pgrep -x netcontrold >/dev/null; then
        printf 'Stop the running netcontrold before installing; networking will not be stopped automatically.\n' >&2
        return 1
    fi
    local work cleanup
    work=$(mktemp -d)
    printf -v cleanup 'rm -rf -- %q' "$work"
    trap "$cleanup" EXIT
    installer_step 'Downloading and verifying the latest release' download_prebuilt "$work" || return 1
    installer_step 'Checking release support' check_prebuilt "$work" || return 1
    installer_message success "Release v$(< "$work/release-version") ready."
    if [[ $supplied == true ]]; then
        install -m 0600 -- "$network_plan" "$work/network-plan.json" || return 1
    fi
    network_plan="$work/network-plan.json"
    management_address=$(prepare_network_plan "$work/netcontrold" "$network_plan" "$supplied" "$approved") || return 1
    installer_step 'Disabling AppArmor' configure_apparmor || return 1
    cd "$work"
    check_systemd_unit || return 1
    installer_step 'Configuring connection tracking' configure_conntrack || return 1
    installer_step 'Enabling link diagnostics' configure_link_diagnostics || return 1
    installer_step 'Enabling firewall telemetry' configure_deny_logging || return 1
    installer_step 'Creating the install directory' install -d -m 0755 /usr/local/sbin || return 1
    installer_step 'Installing netcontrold' install -m 0755 netcontrold /usr/local/sbin/netcontrold || return 1
    installer_step 'Configuring system services' install_systemd_service || return 1
    installer_step 'Taking over networking and starting Netcontrol' provision_appliance /usr/local/sbin/netcontrold "$network_plan" "$management_address" || return 1
    installer_message success 'Installed. Service enabled at boot.'
    printf 'Setup: http://%s:8080/\nSSH: localhost TCP 2222; ssh -p 2222 apikey@127.0.0.1; use an API key created after setup.\nLogs: journalctl -u netcontrold -f\n' "$management_address"
    installer_message warning 'All configured LANs are trusted for router access. LAN clients need addressing, this gateway and DNS; no DHCP/DNS server was installed. Verify WAN connectivity from the console.'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi