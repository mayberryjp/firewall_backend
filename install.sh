#!/usr/bin/env bash
set -euo pipefail

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
    printf 'Building source commit: '
    git rev-parse HEAD
    CARGO_TARGET_DIR="$work/target" rustup run stable cargo build --release --locked --target x86_64-unknown-linux-gnu -p netcontrold
    install -d -m 0755 /usr/local/sbin
    install -m 0755 "$work/target/x86_64-unknown-linux-gnu/release/netcontrold" /usr/local/sbin/netcontrold
    printf 'Installed /usr/local/sbin/netcontrold. No services started or enabled; no network configuration changed.\n'
}

main "$@"