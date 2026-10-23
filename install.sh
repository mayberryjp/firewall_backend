#!/usr/bin/env bash
set -euo pipefail

check_systemd_unit() {
    local unit=packaging/native/netcontrold.service
    local destination=/etc/systemd/system/netcontrold.service
    if [[ -L $destination ]] || { [[ -e $destination ]] && ! cmp -s "$unit" "$destination"; }; then
        printf 'Existing %s differs from the supplied unit; refusing to overwrite it. Use systemd drop-ins for customization.\n' "$destination" >&2
        return 1
    fi
}

install_systemd_service() {
    check_systemd_unit || return 1
    install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys
    install -m 0644 packaging/native/netcontrold.service /etc/systemd/system/netcontrold.service
    systemctl daemon-reload
}

main() {
    local ref=main
    if [[ ${1:-} == --help ]]; then
        printf 'Usage: bash install.sh [--ref BRANCH_TAG_OR_COMMIT]\nInstalls netcontrold from trusted GitHub source on Ubuntu amd64; does not start services.\n'
        return
    fi
    if [[ $# -gt 0 ]]; then
        if [[ $# -ne 2 || $1 != --ref || -z $2 || $2 == -* ]]; then
            printf 'Usage: bash install.sh [--ref BRANCH_TAG_OR_COMMIT]\n' >&2
            return 1
        fi
        ref=$2
    fi
    if [[ $(uname -s) != Linux || ! -r /etc/os-release ]]; then
        printf 'This source installer requires Ubuntu Linux amd64.\n' >&2
        return 1
    fi
    local ID
    . /etc/os-release
    if [[ ${ID:-} != ubuntu ]] || [[ $(dpkg --print-architecture) != amd64 ]]; then
        printf 'This source installer requires Ubuntu amd64.\n' >&2
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

    apt-get update
    apt-get install -y build-essential pkg-config libclang-dev linux-libc-dev ca-certificates git procps
    if pgrep -x netcontrold >/dev/null; then
        printf 'Stop the running netcontrold before installing; networking will not be stopped automatically.\n' >&2
        return 1
    fi
    if ! command -v rustup >/dev/null 2>&1; then
        apt-get install -y rustup
    fi
    rustup toolchain install stable --profile minimal --component rustfmt --component clippy

    local work cleanup
    work=$(mktemp -d)
    printf -v cleanup 'rm -rf -- %q' "$work"
    trap "$cleanup" EXIT
    git init -q "$work/source"
    git -C "$work/source" remote add origin https://github.com/mayberryjp/firewall_backend.git
    git -C "$work/source" fetch --depth 1 origin "$ref"
    git -C "$work/source" checkout --detach FETCH_HEAD
    cd "$work/source"
    test -f packaging/native/netcontrold.service
    check_systemd_unit
    printf 'Building source commit: '
    git rev-parse HEAD
    CARGO_TARGET_DIR="$work/target" rustup run stable cargo build --release --locked --target x86_64-unknown-linux-gnu -p netcontrold
    install -d -m 0755 /usr/local/sbin
    install -m 0755 "$work/target/x86_64-unknown-linux-gnu/release/netcontrold" /usr/local/sbin/netcontrold
    install_systemd_service
    printf 'Installed netcontrold and its systemd unit. No services started or enabled; no network configuration changed.\nReview management access, then run: systemctl start netcontrold\nEnable at boot only after testing: systemctl enable netcontrold\nLogs: journalctl -u netcontrold -f\n'
}

main "$@"