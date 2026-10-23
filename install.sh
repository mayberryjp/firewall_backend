#!/usr/bin/env bash
set -euo pipefail

check_systemd_unit() {
    local unit=netcontrold.service
    local destination=/etc/systemd/system/netcontrold.service
    if [[ -L $destination ]] || { [[ -e $destination ]] && ! cmp -s "$unit" "$destination"; }; then
        printf 'Existing %s differs from the supplied unit; refusing to overwrite it. Use systemd drop-ins for customization.\n' "$destination" >&2
        return 1
    fi
}

install_systemd_service() {
    check_systemd_unit || return 1
    install -d -m 0700 /var/lib/netcontrol /var/lib/netcontrol/services /etc/netcontrol/keys
    install -m 0644 netcontrold.service /etc/systemd/system/netcontrold.service
    systemctl daemon-reload
}

download_prebuilt() {
    local run_id=$1 destination=$2 commit
    gh auth status || {
        printf 'Authenticate GitHub CLI as the installing user first (sudo gh auth login when installing as root). Actions read access is required.\n' >&2
        return 1
    }
    commit=$(gh api "repos/mayberryjp/firewall_backend/actions/runs/$run_id" --jq 'select(.conclusion == "success" and .path == ".github/workflows/build.yml" and .event == "workflow_dispatch" and .head_repository.full_name == "mayberryjp/firewall_backend") | .head_sha') || return 1
    if [[ ! $commit =~ ^[0-9a-f]{40}$ ]]; then
        printf 'Expected a successful manually dispatched build workflow from the owning repository.\n' >&2
        return 1
    fi
    gh run download "$run_id" --repo mayberryjp/firewall_backend --name "netcontrol-ubuntu-amd64-$commit" --dir "$destination" || return 1
    (
        cd "$destination"
        local file
        for file in netcontrold netcontrold.service SHA256SUMS; do
            [[ -f $file && ! -L $file ]] || return 1
        done
        [[ $(wc -l < SHA256SUMS) -eq 2 ]] || return 1
        grep -Eq '^[0-9a-f]{64} \*netcontrold$' SHA256SUMS || return 1
        grep -Eq '^[0-9a-f]{64} \*netcontrold\.service$' SHA256SUMS || return 1
        sha256sum --check --strict SHA256SUMS
    ) || return 1
    printf 'Verified prebuilt artifacts from source commit %s (workflow run %s).\n' "$commit" "$run_id"
}

main() {
    local run_id
    if [[ ${1:-} == --help ]]; then
        printf 'Usage: bash install.sh --run-id SUCCESSFUL_BUILD_RUN_ID\nInstalls verified prebuilt netcontrold artifacts on Ubuntu amd64; requires GitHub CLI authentication and does not start services.\n'
        return
    fi
    if [[ $# -ne 2 || $1 != --run-id || ! $2 =~ ^[0-9]+$ ]]; then
        printf 'Usage: bash install.sh --run-id SUCCESSFUL_BUILD_RUN_ID\n' >&2
        return 1
    fi
    run_id=$2
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

    apt-get update
    apt-get install --no-install-recommends -y ca-certificates gh procps
    if pgrep -x netcontrold >/dev/null; then
        printf 'Stop the running netcontrold before installing; networking will not be stopped automatically.\n' >&2
        return 1
    fi
    local work cleanup
    work=$(mktemp -d)
    printf -v cleanup 'rm -rf -- %q' "$work"
    trap "$cleanup" EXIT
    download_prebuilt "$run_id" "$work"
    cd "$work"
    check_systemd_unit
    install -d -m 0755 /usr/local/sbin
    install -m 0755 netcontrold /usr/local/sbin/netcontrold
    install_systemd_service
    printf 'Installed netcontrold and its systemd unit. No services started or enabled; no network configuration changed.\nReview management access, then run: systemctl start netcontrold\nEnable at boot only after testing: systemctl enable netcontrold\nLogs: journalctl -u netcontrold -f\n'
}

main "$@"