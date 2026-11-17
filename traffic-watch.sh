#!/usr/bin/env bash
set -euo pipefail

declare -A traffic_watch_previous=()
declare -A traffic_watch_queues=()

traffic_watch_error() {
    printf 'ERROR: %s\n' "$*" >&2
    return 1
}

traffic_watch_number() {
    [[ $1 =~ ^(0|[1-9][0-9]*)$ && ${#1} -le 19 ]] &&
        { [[ ${#1} -lt 19 || $1 < 9223372036854775807 || $1 == 9223372036854775807 ]]; }
}

traffic_watch_ifindex() {
    local value
    if ! read -r value < "/sys/class/net/$1/ifindex"; then
        traffic_watch_error "Cannot read interface identity for $1; monitoring stopped."
        return 1
    fi
    printf '%s\n' "$value"
}

traffic_watch_link() {
    local interface=$1 field value
    value=$(traffic_watch_ifindex "$interface") || return 1
    traffic_watch_number "$value" || { traffic_watch_error "Invalid interface identity for $interface."; return 1; }
    printf '%s ' "$value"
    for field in rx_packets rx_dropped rx_errors rx_missed_errors tx_packets tx_dropped tx_errors tx_carrier_errors; do
        local path="/sys/class/net/$interface/statistics/$field"
        if ! read -r value < "$path"; then
            traffic_watch_error "Cannot read $path; monitoring stopped."
            return 1
        fi
        traffic_watch_number "$value" || { traffic_watch_error "Invalid counter in $path."; return 1; }
        printf '%s ' "$value"
    done
    printf '\n'
}

traffic_watch_qdiscs() {
    local output
    if ! output=$(tc -s qdisc show dev "$1"); then
        traffic_watch_error "Cannot read qdisc statistics for $1; monitoring stopped."
        return 1
    fi
    printf '%s\n' "$output" | awk '
        function fail() { failed = 1; exit 1 }
        $1 == "qdisc" {
            if (active) fail()
            active = 1
            kind = $2
            handle = $3
            parent = ""
            drops = ""
            for (i = 4; i <= NF; i++) {
                if ($i == "root") parent = "root"
                if ($i == "parent") parent = $(i + 1)
            }
            if (parent == "") fail()
        }
        active && $1 == "Sent" {
            for (i = 1; i < NF; i++) {
                if ($i == "(dropped") {
                    drops = $(i + 1)
                    sub(/,$/, "", drops)
                }
            }
        }
        active && $1 == "backlog" {
            packets = $3
            sub(/p$/, "", packets)
            if (drops !~ /^[0-9]+$/ || packets !~ /^[0-9]+$/ || $2 == "") fail()
            print kind, handle, parent, drops, $2, packets
            active = 0
            rows++
        }
        END { if (failed || active || !rows) exit 1 }
    '
}

traffic_watch_sample() {
    local interface=$1 role=$2 link queues index final_index old_index baseline=0 reset=0
    local rx_packets rx_drops rx_errors rx_missed tx_packets tx_drops tx_errors tx_carrier
    local -a values deltas
    link=$(traffic_watch_link "$interface") || return 1
    read -r -a values <<< "$link"
    [[ ${#values[@]} == 9 ]] || { traffic_watch_error "Incomplete counters for $interface."; return 1; }
    index=${values[0]}
    if ! queues=$(traffic_watch_qdiscs "$interface"); then
        traffic_watch_error "Unavailable or unsupported qdisc output for $interface; monitoring stopped."
        return 1
    fi
    final_index=$(traffic_watch_ifindex "$interface") || return 1
    [[ $index == "$final_index" ]] || { traffic_watch_error "Interface $interface changed while sampling; restart monitoring."; return 1; }
    old_index=${traffic_watch_previous[$interface:index]:-}
    [[ $old_index == "$index" ]] || baseline=1
    local i previous
    for ((i = 1; i < ${#values[@]}; i++)); do
        previous=${traffic_watch_previous[$interface:$i]:-${values[i]}}
        if ((values[i] < previous)); then reset=1; fi
        deltas[i]=$((values[i] - previous))
        traffic_watch_previous[$interface:$i]=${values[i]}
    done
    traffic_watch_previous[$interface:index]=$index
    if ((baseline || reset)); then
        if ((reset)) && ((!baseline)); then
            printf 'RESET %s %s: counters decreased; new baseline, no loss inferred.\n' "$role" "$interface"
        else
            printf 'BASE  %s %s: baseline saved; existing totals ignored.\n' "$role" "$interface"
        fi
    else
        rx_packets=${deltas[1]} rx_drops=${deltas[2]} rx_errors=${deltas[3]} rx_missed=${deltas[4]}
        tx_packets=${deltas[5]} tx_drops=${deltas[6]} tx_errors=${deltas[7]} tx_carrier=${deltas[8]}
        local status=----
        ((rx_drops == 0 && rx_errors == 0 && rx_missed == 0)) || status='!!!!'
        printf '%s %-3s IN  %-12s packets +%-8s DROPS +%-6s ERRORS +%-6s MISSED +%s\n' "$status" "$role" "$interface" "$rx_packets" "$rx_drops" "$rx_errors" "$rx_missed"
        status=----
        ((tx_drops == 0 && tx_errors == 0 && tx_carrier == 0)) || status='!!!!'
        printf '%s %-3s OUT %-12s packets +%-8s DROPS +%-6s ERRORS +%-6s CARRIER +%s\n' "$status" "$role" "$interface" "$tx_packets" "$tx_drops" "$tx_errors" "$tx_carrier"
    fi

    local kind handle parent drops backlog packets key delta changed=0 queued=0 comparable=0 rebased=0
    local -A current=()
    while read -r kind handle parent drops backlog packets; do
        traffic_watch_number "$drops" && traffic_watch_number "$packets" || {
            traffic_watch_error "Invalid qdisc counters for $interface."
            return 1
        }
        key="$interface:$index:$kind:$handle:$parent"
        current[$key]=$drops
        previous=${traffic_watch_queues[$key]:-}
        if [[ -z $previous ]] || ((baseline || reset || drops < previous)); then
            rebased=$((rebased + 1))
        else
            comparable=$((comparable + 1))
            delta=$((drops - previous))
            if ((delta > 0)); then
                changed=$((changed + 1))
                printf '!!!! %s QDISC DROP +%s [%s handle=%s parent=%s]\n' "$role" "$delta" "$kind" "$handle" "$parent"
            fi
        fi
        if ((packets > 0)) || [[ $backlog != 0b ]]; then
            queued=$((queued + 1))
            printf 'WAIT %s QDISC backlog=%s/%s packets [%s handle=%s parent=%s]\n' "$role" "$backlog" "$packets" "$kind" "$handle" "$parent"
        fi
    done <<< "$queues"
    for key in "${!traffic_watch_queues[@]}"; do
        [[ $key != "$interface:"* ]] || unset 'traffic_watch_queues[$key]'
    done
    for key in "${!current[@]}"; do traffic_watch_queues[$key]=${current[$key]}; done
    printf '     %s qdisc rows: %s comparable, %s new/reset; %s with new drops, %s with backlog.\n' "$role" "$comparable" "$rebased" "$changed" "$queued"
}

traffic_watch_main() {
    if [[ ${1:-} == --help || ${1:-} == -h ]]; then
        printf 'Usage: bash traffic-watch.sh WAN_INTERFACE LAN_INTERFACE [INTERVAL_SECONDS]\n'
        return 0
    fi
    [[ $# -ge 2 && $# -le 3 ]] || {
        traffic_watch_error 'Usage: bash traffic-watch.sh WAN_INTERFACE LAN_INTERFACE [INTERVAL_SECONDS]'
        return 1
    }
    local interface interval=${3:-1} command timestamp
    for interface in "$1" "$2"; do
        [[ $interface =~ ^[a-zA-Z0-9_.:-]{1,15}$ && $interface != . && $interface != .. ]] || {
            traffic_watch_error "Invalid interface name: $interface"
            return 1
        }
    done
    [[ $1 != "$2" ]] || { traffic_watch_error 'WAN and LAN must be different interfaces.'; return 1; }
    [[ $interval =~ ^[1-9][0-9]*$ && ${#interval} -le 2 && $interval -le 60 ]] || {
        traffic_watch_error 'Interval must be an integer from 1 to 60 seconds.'
        return 1
    }
    for command in tc awk sleep date; do
        command -v "$command" >/dev/null || { traffic_watch_error "Missing command: $command"; return 1; }
    done
    export LC_ALL=C
    printf 'Read-only traffic watch: WAN=%s LAN=%s, interval=%ss. Ctrl-C stops.\n' "$1" "$2" "$interval"
    printf 'UPLOAD: LAN IN -> WAN OUT. DOWNLOAD: WAN IN -> LAN OUT.\n'
    printf 'Numbers are NEW since the previous sample, not lifetime totals.\n'
    printf '!!!! = new drops/errors; WAIT = sampled queue backlog, not proof of loss.\n'
    printf 'Qdisc rows are NOT summed: parent/child counters can overlap.\n'
    printf 'No alert does not prove uninterrupted audio; brief queues and upstream loss can be missed.\n'
    while true; do
        timestamp=$(date '+%Y-%m-%d %H:%M:%S %z') || {
            traffic_watch_error 'Cannot read sample time; monitoring stopped.'
            return 1
        }
        printf '\n=== %s ===\n' "$timestamp"
        traffic_watch_sample "$1" WAN || return 1
        traffic_watch_sample "$2" LAN || return 1
        sleep "$interval" || { traffic_watch_error 'Sample wait interrupted; monitoring stopped.'; return 1; }
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    traffic_watch_main "$@"
fi
