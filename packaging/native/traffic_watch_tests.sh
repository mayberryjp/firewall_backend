#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
source ./traffic-watch.sh
temporary=$(mktemp -d)
printf -v cleanup 'rm -rf -- %q' "$temporary"
trap "$cleanup" EXIT

fixture_index=2
counters='2 100 3854 3 0 200 36 0 3'
queue_drops=12
queue_parent=:1
backlog=0b
backlog_packets=0
scenario=valid
traffic_watch_ifindex() { printf '%s\n' "$fixture_index"; }
traffic_watch_link() { printf '%s\n' "$counters"; }
tc() {
    [[ $* == '-s qdisc show dev enp1s0' || $* == '-s qdisc show dev enp2s0' ]] || return 1
    [[ $scenario != failure ]] || { printf 'fixture permission denied\n' >&2; return 1; }
    [[ $scenario != malformed ]] || { printf 'qdisc unexpected output\n'; return 0; }
    printf 'qdisc mq 0: root\n Sent 1000 bytes 100 pkt (dropped %s, overlimits 50 requeues 1)\n backlog 0b 0p requeues 1\n' "$queue_drops"
    printf 'qdisc fq_codel 0: parent %s limit 10240p\n Sent 1000 bytes 100 pkt (dropped %s, overlimits 50 requeues 1)\n backlog %s %sp requeues 1\n' "$queue_parent" "$queue_drops" "$backlog" "$backlog_packets"
}

traffic_watch_sample enp1s0 WAN > "$temporary/baseline"
grep -q 'baseline saved; existing totals ignored' "$temporary/baseline"
! grep -q '^!!!!' "$temporary/baseline"

counters='2 110 3856 4 1 220 39 2 4'
queue_drops=14
backlog=1500b
backlog_packets=1
traffic_watch_sample enp1s0 WAN > "$temporary/changes"
grep -Eq '^!!!! WAN IN .*packets \+10 .*DROPS \+2 .*ERRORS \+1 .*MISSED \+1' "$temporary/changes"
grep -Eq '^!!!! WAN OUT .*packets \+20 .*DROPS \+3 .*ERRORS \+2 .*CARRIER \+1' "$temporary/changes"
[[ $(grep -c 'QDISC DROP +2 ' "$temporary/changes") == 2 ]]
! grep -q 'QDISC DROP +4 ' "$temporary/changes"
grep -q 'backlog=1500b/1 packets' "$temporary/changes"

backlog=0b
backlog_packets=0
traffic_watch_sample enp1s0 WAN > "$temporary/unchanged"
! grep -Eq '^!!!!|^WAIT' "$temporary/unchanged"
grep -q '2 comparable, 0 new/reset; 0 with new drops, 0 with backlog' "$temporary/unchanged"

queue_parent=:2
queue_drops=1
traffic_watch_sample enp1s0 WAN > "$temporary/queue-reset"
grep -q '0 comparable, 2 new/reset' "$temporary/queue-reset"
! grep -q '^!!!!' "$temporary/queue-reset"

counters='2 1 0 0 0 1 0 0 0'
traffic_watch_sample enp1s0 WAN > "$temporary/reset"
grep -q '^RESET WAN enp1s0' "$temporary/reset"
! grep -q '^!!!!' "$temporary/reset"

fixture_index=3
counters='3 1 0 0 0 1 0 0 0'
traffic_watch_sample enp1s0 WAN > "$temporary/replaced"
grep -q '^BASE .*baseline saved' "$temporary/replaced"

fixture_index=4
if traffic_watch_sample enp1s0 WAN > "$temporary/identity" 2>&1; then
    printf 'Expected sampling identity mismatch failure.\n' >&2
    exit 1
fi
grep -q 'changed while sampling' "$temporary/identity"
fixture_index=3

for scenario in failure malformed; do
    if traffic_watch_sample enp1s0 WAN > "$temporary/$scenario" 2>&1; then
        printf 'Expected explicit failure for %s.\n' "$scenario" >&2
        exit 1
    fi
    grep -q '^ERROR:' "$temporary/$scenario"
done

for arguments in 'enp1s0 enp1s0' '../bad enp2s0' 'enp1s0 enp2s0 0' 'enp1s0 enp2s0 61'; do
    read -r -a parameters <<< "$arguments"
    if traffic_watch_main "${parameters[@]}" > "$temporary/arguments" 2>&1; then
        printf 'Expected invalid argument rejection: %s\n' "$arguments" >&2
        exit 1
    fi
    grep -q '^ERROR:' "$temporary/arguments"
done

(
    scenario=valid
    traffic_watch_previous=()
    traffic_watch_queues=()
    counters='3 100 3854 3 0 200 36 0 3'
    queue_drops=12
    samples=0
    sleep() {
        samples=$((samples + 1))
        if ((samples == 2)); then exit 0; fi
        counters='3 110 3856 4 1 220 39 2 4'
        queue_drops=14
    }
    traffic_watch_main enp1s0 enp2s0 1
) > "$temporary/live"
grep -q 'UPLOAD: LAN IN -> WAN OUT' "$temporary/live"
grep -Eq '^!!!! WAN OUT .*DROPS \+3 ' "$temporary/live"
grep -Eq '^!!!! LAN IN .*DROPS \+2 ' "$temporary/live"
[[ $(grep -c '^=== ' "$temporary/live") == 2 ]]
printf 'Traffic watch fixture tests passed.\n'
