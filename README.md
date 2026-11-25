# Netcontrol

Netcontrol is a Rust network-control daemon with an embedded device setup
website, API-key-authenticated HTTP API, durable configuration transactions,
and a custom signed packaging system.

This is a greenfield **host-managed firewall appliance**. The native Linux
backend controls the machine's networking; an isolated namespace is an optional
lab tool, not an appliance prerequisite. Production readiness still requires
Linux/Alpine runtime, boot/recovery and connectivity acceptance. A running
process or simulator result is not evidence that real networking works.

## Rust-only architecture

Native host mode mandatorily owns `kernel.panic=10`: reboot ten seconds after a
kernel panic. Startup overwrites conflicting values, persists
`/etc/sysctl.d/99-netcontrol-panic.conf`, and verifies readback. There is no
dedicated worker or panic-policy process-health row; later external changes
remain until daemon startup or boot reapplies the policy.
Startup takeover failures abort startup. This does not enable panic-on-oops,
panic-on-warning or watchdog-triggered panics. Simulator and lab namespace modes
never claim this host-global setting. See the
[operator contract](docs/BUILD_AND_INSTALL.md#kernel-panic-reboot-ownership).

| Component | Responsibility |
| --- | --- |
| [netcontrold](crates/netcontrold) | HTTP listener, device account, API keys, sessions, embedded UI |
| [netcontrol-core](crates/netcontrol-core) | Typed configuration, authorization, transactions, rollback, revisions, persistence, simulator |
| [netcontrol-native](crates/netcontrol-native) | Direct Linux host networking, interface discovery and owned configuration |
| [netcontrol-services](crates/netcontrol-services) | Native protocol and statistics workers |
| [netcontrol-package](crates/netcontrol-package) | Signed `.ncpkg` creation, verification, installation and installation recovery |

There is no Go executable, Go wrapper, dual backend, or Go-state migration path.
Protocol services run in Rust rather than supervising dnsmasq, chronyd,
softflowd, syslog-ng, or vnstatd. The operating system's service manager starts
the single daemon; it is not a protocol implementation. Native syslog requires
systemd/journald socket activation; it is unavailable under OpenRC.

Native [IPv4 UDP broadcast/multicast relay](docs/UDP_BROADCAST_RELAY_SPEC.md)
implements the documented pfSense package's selected-interface forwarding,
multicast membership, three source modes and instance-ID echo suppression.
Use the [Govee/ECHONET Lite example](examples/udp-broadcast-relay.json), adapting
its synthetic interfaces, addresses, revision and firewall policy. Govee LAN
Control must be enabled; discovery does not grant routed device access. This
runs inside Netcontrol with automatic reconnect/retry, not an external package.

## Persistent log viewing

`GET /api/v1/logs/syslog` reads locally captured journald/socket messages;
`GET /api/v1/logs/netcontrol` reads daemon diagnostics and native backend events.
`GET /api/v1/logs/performance` reads a separate performance-evidence history.
All three require the separate `logs.read` permission and support bounded cursor
polling. Each stream retains four 2 MiB segments under
`<services-state-dir>/logs`, survives daemon restart and reports cursor gaps
when old segments expire. No whole-file download or forwarding replay.

With the host-services opt-in and valid systemd/journald activation, local
socket capture runs even when `syslog.enabled` is false; that setting controls
remote forwarding only. Runtime/MQTT `forwarding_enabled` distinguishes the
forwarding setting from the capture worker's state. Simulator log APIs return
explicit unavailability. Logs can contain sensitive third-party text: restrict
log-reading keys and render text safely. See the
[API contract](FRONTEND_SPEC.md#persistent-log-viewing-apis).

New socket records tagged `netcontrold` by journald are excluded from both local
syslog history and remote forwarding; daemon diagnostics remain in the Netcontrol
view and host journal. Existing history is not rewritten. Routine HTTP completion
events are not emitted. Named process/worker lifecycle, retry and destination
recovery events provide troubleshooting context without request/packet logging.

The performance stream is always available in native mode, without the
host-services opt-in. Existing collectors record newly observed qdisc drops,
separate interface RX/TX errors and drops, RX frame/length errors,
local-router TCP retransmissions, and diagnostic
capture drops (not user-packet loss). Configured explicit and DHCP gateway
monitors record each newly timed-out probe once, plus held health changes
(including recovery, but not initial healthy startup) with measured
loss/latency/RTT variation and configured
thresholds. Collector failures/recovery and gateway worker failures distinguish
missing measurements from clean measurements. No additional poller, probes,
thresholds, configuration changes or automatic tuning are added.
Gateway replies use kernel arrival timestamps and per-monitor socket filters,
so delayed userspace processing does not itself become probe loss or RTT.
Detected local receive overflow/backlog or invalid timing reports unavailable,
not a remote outage; clock steps invalidate the attempt and restart warmup.
RX frame/length errors are subcategories of RX errors, not additional packets
to sum. WireGuard RX frame errors can indicate an incoming AllowedIPs rejection
or an invalid inner packet type; they do not confirm a mismatch or identify a
peer/source address. The same directional counters are available in link
diagnostics; first/reset observations have null deltas.

Records contain UTC observation times, interval/identity/counter evidence, and
gateway probe send times/timeouts; they do not recover exact packet-drop times
or prove the cause of poor audio. Link collection is approximately once a second
plus collection/storage time; gateway timeout observation uses the existing
approximately 100 ms statistics cycle. Healthy samples and ordinary backlog/
overlimits are not logged. Event-only synchronized writes share the existing
bounded log storage, under `<services-state-dir>/logs/performance`: four 2 MiB
segments, retained across restart, not an unlimited archive or retention period.
Busy failure periods can expire history quickly; copy evidence promptly.
See the [performance log contract](FRONTEND_SPEC.md#performance-evidence-log).

`DELETE /api/v1/logs/performance` with `logs.delete` and no body or query
durably purges only retained performance evidence. Collection continues;
new records can appear immediately. Successful purges reset the stream's
cursor identity, including across restart. Read permission does not authorize
deletion. See the [purge contract](FRONTEND_SPEC.md#purging-performance-evidence).

Host-wide traffic accounting uses one Rust worker for every kernel interface,
including unmanaged, VLAN, tunnel, veth and loopback links. Optional
`vnstat.collector` sends one `hostname.domain|vnstat --oneline`-format UDP datagram per
present interface during local 23:59, with daily/monthly/lifetime observed
totals. The prefix uses committed `system.hostname` and `system.domain`;
an empty domain sends hostname only, and an unmanaged hostname uses the kernel
name. Reporting is approximate and best-effort, not a delivery guarantee.
Samples/API history refresh every five seconds; disk checkpoints normally occur
every 60 seconds, with initial/report-date/final clean-shutdown saves. Abrupt
termination can lose uncheckpointed observations; historical interface totals
are preserved without automatic pruning.
See the [traffic contract](FRONTEND_SPEC.md#native-traffic-history) and
[example](examples/appliance-services.json) for configuration and retained-state
requirements; there is no vnStat daemon, cron or netcat dependency.

Backward compatibility is not a constraint. Invalid or unsupported
configuration must produce explicit errors rather than permissive defaults or
successful no-op operations. Existing on-device data must never be deleted to
force a new schema to load.

## Interface capability snapshots

Explicit NIC capability inventory is available separately:
`GET /api/v1/interface-capabilities/refresh` (`state.read` and
`interfaces.write`, no body/query) reads all links once and durably saves the
snapshot. `GET /api/v1/interface-capabilities` (`state.read`) returns it, or
null before the first refresh, without rescanning. Driver/firmware and PCI
identity, supported/advertised speed-duplex modes, queues, steering, XDP and
offload evidence are daemon-owned observations, not editable configuration.
Refresh is an explicit scan-and-save GET for GET-only API explorers, not a
read-only resource: never prefetch, automatically retry, cache or poll it.
Unknown/partial results are explicit; no tuning or device rebinding occurs.
RSS details report the default indirection table and raw hash/transform settings,
not the hash key. Enabled means observed multi-queue distribution with identified
hashing, not simply multiple queues. Physical device IRQs expose effective CPU
affinity and exact cumulative per-CPU interrupt counts; queues map to IRQs only
when exact driver action names establish identity. Unknown mappings stay explicit.
IRQ CPU placement is separate from RPS and does not prove balanced processing.
VLAN RPS reports the observed physical parent's enabled/disabled state with
`inherited_from` naming that parent, including stacked VLANs. Unresolved ancestry
or missing parent measurements remain unknown, never disabled by default.
The VLAN's own queue masks remain raw diagnostics, not its normal receive-path
RPS setting. Configure RPS on the physical parent, not the VLAN.
DPDK readiness requires future PMD-specific validation. See the
[design](docs/INTERFACE_CAPABILITIES.md) and
[frontend contract](FRONTEND_SPEC.md#interface-capability-snapshots).

## Performance diagnostics and safe RPS tuning

For a readable, read-only Linux terminal view of new interface/qdisc drops,
run [traffic-watch.sh](traffic-watch.sh) during the incident (replace the WAN/LAN
names with the actual interfaces):

```sh
bash traffic-watch.sh enp1s0 enp2s0
```

It establishes a baseline, then labels WAN/LAN input/output and reports new
packets, drops, errors, missed receives and carrier errors each second.
`!!!!` highlights new drops/errors; `WAIT` shows sampled queue backlog, which
does not itself prove loss. An optional third argument sets the interval in
whole seconds from 1 to 60. Ctrl-C stops; append `| tee traffic-watch.log` to
retain the timestamped output locally. The script changes no networking settings
and needs Bash plus `tc` (iproute2), awk, date and sleep; root is normally not
required, but network statistics must be readable.

Existing lifetime totals are ignored. Counter decreases, replaced interfaces
and new/replaced qdisc identities establish fresh baselines rather than inventing
negative or huge loss counts. Parent/child qdisc drops are shown separately,
never summed. Missing/unreadable counters or unsupported qdisc output stop with
an explicit error. No alerts does not prove uninterrupted audio: the script does
not identify voice packets, measure upstream/receiver loss or catch every
between-sample queue change. This is a standalone troubleshooting tool, not a
daemon feature or continuous background service.

`GET /api/v1/statistics/performance` (`state.read`, no body/query) collects
passive host CPU, network softirq, softnet, IRQ and interface/queue evidence.
It is separate from cached capability inventory: reads neither save capability
snapshots nor change configuration. Compare successive samples under the same
representative load alongside existing interface rates, queue drops and gateway
latency; a recommendation is a trial candidate, never proof of a speed increase.

Explicit `kernel.rps` entries map managed physical Ethernet or WireGuard RX queues
to canonical Linux CPU masks, for example `{"eno1/rx-0":"c"}` selects CPUs 2 and 3.
This is a synthetic illustration, not a recommended mask for another appliance.
Use complete confirmed configuration transactions with `transactions.write`,
`kernel.host.write` and `interfaces.write`. Native host mode enables tuning
automatically and acquires its exclusive host-tunables lock at startup; no
extra launch flag or permission refresh is required. No IRQ, offload, RSS, RFS or VLAN queue
settings are changed automatically. Zero disables RPS; removing an entry restores
its captured original mask. Native durable intents cover apply failures and
interrupted recovery, and confirmation timeout restores the prior configuration.
WireGuard accepts the same setting, for example `{"wg0/rx-0":"2"}` (CPU 1),
when its kernel RX queue exposes writable RPS controls. Creation and tuning can
share a transaction; rekey, deletion, recreation and reboot preserve safe ownership.
This steers post-decryption RX processing, not WireGuard crypto workers. No
WireGuard IRQ-based mask recommendations are generated; RFS/offloads remain
physical-Ethernet-only.

SSH supports `show statistics performance`, `kernel rps INTERFACE/rx-N MASK`
and `no kernel rps INTERFACE/rx-N` in the normal candidate/confirmed workflow.
See the [contract](FRONTEND_SPEC.md#performance-diagnostics-and-rps-tuning) and
[frontend handoff](docs/frontend-handoffs/2026-11-04.md#2026-11-04-03-performance-diagnostics-and-transactional-rps).
Real hardware connectivity and performance acceptance remain operator work.

## NIC offloads and RFS

Explicit `kernel.offloads` maps managed physical Ethernet names to exact Linux
feature booleans for checksum, scatter/gather, segmentation, GRO and VLAN
offloads. Driver support/changeability is freshly checked; unsafe LRO enabling
is rejected. Full active and requested feature state is captured so coupled or
unrelated changes cannot silently succeed and original settings can be restored.
No external ethtool process is used.

Optional `kernel.rfs` sets the host-global `sock_flow_entries` budget and
per-RX-queue table sizes, with zero/power-of-two validation and explicit nonzero
RPS dependencies. This targets local socket consumers, not generic forwarded
traffic acceleration. Global changes affect other local applications.

Both use automatic host-mode tuning availability with exclusive ownership,
permissions, confirmed transactions, original
capture, exact readback, rollback and recovery as RPS. Nothing is enabled
automatically. Inspect existing kernel/runtime and capability APIs; do not copy
observational identity/requested-bit metadata into editable configuration.
See the [contract](FRONTEND_SPEC.md#explicit-rfs-and-nic-offload-configuration)
and [frontend handoff](docs/frontend-handoffs/2026-11-04.md#2026-11-04-06-nic-offload-controls-and-rfs).
All traffic shaping remains explicitly deferred; no ALTQ/CAKE/FQ-CoDel/HTB or
ingress redirection is installed.

## Live route table

`GET /api/v1/routes/table` (`state.read`, no query/body) reads all IPv4/IPv6
kernel routing tables in the daemon's managed network namespace, including
unmanaged, connected, local, DHCP, BGP, multipath and deviceless routes.
It exposes numeric Linux protocol/type/scope/flags, interface names and indices,
source prefixes, gateways, metrics, cache metadata and raw netlink attributes
for advanced details. It does not change networking, configuration or ownership.
Simulator/unavailable/oversized reads fail explicitly; no partial result.
The existing `/api/v1/routes` remains managed configuration, not this live dump.
See the [live-table contract](FRONTEND_SPEC.md#live-kernel-route-table).

## Read-only loopback interfaces

`GET /api/v1/interfaces/discovered` (`state.read`) includes every live link.
Actual kernel loopback links always report `role: "loopback"` and
`addressing_type: "static"`, including when down or without addresses. Both are
fixed read-only labels; loopbacks cannot be adopted, edited, deleted, assigned
another role or configured for DHCP/SLAAC. Identify them by kernel flags, not
interface-name guesses.

Other discovery rows include null for both fields; join their managed
configuration for roles/addressing settings rather than infer them from active
addresses. Managed role choices remain `wan`, `lan` and `unassigned`; never offer
`loopback` for another interface. No new desired-config address-type field is
added. See the [discovery contract](FRONTEND_SPEC.md#host-interface-discovery-and-selection)
and [frontend handoff](docs/frontend-handoffs/2026-10-30.md#2026-10-30-09-fixed-loopback-role-and-static-addressing).

## WireGuard DNS peers

WireGuard peers accept DNS endpoints such as `vpn.example.test:51820`, as well
as canonical numeric IP endpoints. Use lowercase ASCII hostnames and an explicit
port 1..65535. Structural validation and network restoration never perform DNS
queries. The background worker resolves enabled peers immediately after startup
and refreshes DNS every 60 seconds, retaining a still-advertised address to avoid unnecessary churn.
Global IPv6 disablement restricts resolution to IPv4.

Successful selections persist in private native state for restart/rollback.
Later DNS failures retain the last address and appear in
`GET /api/v1/state` under `runtime.wireguard_dns`. Without a cached address, the
peer is installed with its keys, AllowedIPs and keepalives but awaits DNS;
`resolved_endpoint` and `last_success_unix_ms` are null. A failed first lookup
records an error and retries without aborting configuration apply or startup.
Underlay DNS must eventually work independently of the tunnel for it to connect.
Disabled peers are not resolved.
Updates change only peer endpoints, preserving keys, AllowedIPs/BGP prefixes
and keepalives. Numeric endpoints retain strict drift checks; DNS-selected
addresses and authenticated roaming are dynamic runtime state.
See the [contract](FRONTEND_SPEC.md#dns-peer-endpoints) and synthetic
[BGP-over-WireGuard example](examples/bgp.json); replace its name, addresses
and public key, and provision the private key/underlay before applying.

## Conntrack limits and timeouts

Advanced conntrack tuning uses the existing confirmed kernel transaction
workflow, HTTP catalog and configuration SSH commands. Own
`net.netfilter.nf_conntrack_max` in `kernel.host` (1024..16777216 entries);
own TCP established/close/close-wait/fin-wait/last-ack/time-wait and UDP
unreplied/stream timeouts in `kernel.namespace` (1..604800 seconds).
Native host installation and every saved-host startup (including source/HTTPS
upgrades) own all nine settings. Capture current values for missing keys into
configuration; preserve and reapply existing saved settings, never guess values.
Initial capture is durable before takeover; startup additions use a verified
system transaction and advance the configuration revision once. Missing or
unsupported kernel values fail explicitly. Simulator/lab modes do not auto-own.
Values are canonical decimal strings; no tuning defaults are changed automatically.
Removing a key restores its captured original, with normal persistence,
restart repair, drift detection and rollback, but the next native host startup
captures/reclaims missing conntrack keys. Host limits require
`kernel.host.write`, namespace timeouts `kernel.namespace.write`, and all
mutations use `transactions.write`.

Higher limits permit more memory use, lower limits can block new connections,
and short timeouts can disrupt idle flows or expose late teardown drops.
Applying settings never flushes connections, resizes hash buckets or relaxes TCP
validation. Inspect actual usage and connectivity before confirmation; restoring
a setting cannot recover a flow that already expired.
See the [exact catalog/API contract](FRONTEND_SPEC.md#conntrack-limits-and-timeouts),
[configuration SSH usage](docs/CLI.md#conntrack-controls), and
[frontend handoff](docs/frontend-handoffs/2026-11-08.md#2026-11-08-01-conntrack-controls).

## DHCP relay firewall admission

Enabling per-interface DHCPv4 relay automatically installs system-owned native
input permits: UDP 68 to 67 on that interface, addressed to the limited broadcast
or selected relay IPv4 address, and UDP 67 to 67 from its configured servers to
that relay address. No separate manual input rule is needed. The service permits
precede configured input drops; disabling/removing relay removes only these
derived permits, not manual rules or existing conntrack state.

The same transaction applies addresses, relay settings and firewall permissions;
startup repair and rollback regenerate them. No forwarding/NAT, routes or
management-port access is enabled. Operators still provide reachable servers,
return routes, DHCP scopes and permissions on other firewalls. Inspect generated
`input:generated/input/dhcp_relay/<interface>/clients` and `/servers` rows at
`GET /api/v1/statistics/firewall`, alongside worker status and packet captures.
See the [relay contract](FRONTEND_SPEC.md#621-per-interface-dhcpv4-relay).

Relay diagnostics are also available with `state.read`:
`GET /api/v1/statistics/dhcp-relay` returns per-interface and shared-worker
received/forwarded/rejected/error/expiry counters plus pending tracking entries.
`GET /api/v1/services/dhcp-relay/log` offers a 2048-event in-memory ring with
cursor-based polling (about once per second), optional interface filtering and
explicit overwrite/reset markers. No packet payloads or disk log; daemon
restart clears history. Counters reset per worker attempt, not per API read.
These are forwarding observations, not proof of DHCP lease completion. See the
[diagnostics contract](FRONTEND_SPEC.md#dhcp-relay-diagnostics) and
[frontend handoff](docs/frontend-handoffs/2026-11-11.md#2026-11-11-02-dhcp-relay-diagnostics).

## Bulk firewall clearing

`DELETE /api/v1/firewall/hosts-and-rules` removes all configured firewall hosts,
their attached rules, interface forwarding rules and legacy ordered rules.
It preserves NAT, management-input rules, global policies, ICMP settings and
unrelated configuration, and never flushes existing connection state.
Require `transactions.write` plus `firewall.write`, current `base_revision`,
`confirm: true` and a 10..300-second confirmation timeout. The response is a
normal `202` pending transaction: changes are provisionally applied and must be
explicitly confirmed, otherwise rollback restores the original state. This is
not a factory reset or a literal empty kernel ruleset. Review the
[complete scope and safeguards](FRONTEND_SPEC.md#bulk-deletion-of-firewall-hosts-and-forwarding-rules).
Per-connection accounting and dedicated per-rule match counters are available.

## Firewall filter protocols

Host, ingress-interface, management-input and legacy ordered filter rules
support Any, TCP, UDP, ICMP and ICMPv6. Omit `protocol` (or use `""`) for Any;
otherwise use `tcp`, `udp`, `icmp` or `icmpv6`. Only TCP/UDP accept
`destination_ports`: up to 32 unique individual ports, 1..65535.
ICMP is IPv4-only; ICMPv6 is IPv6-only, requires global IPv6 enablement and
matches through IPv6 extension headers. Both cover all types/codes.
Incompatible families and port combinations are explicit validation errors.
Dual-stack host rules expand only compatible addresses.

The global `allow_all_icmp` IPv4 exception still precedes configured drops;
disable it to enforce IPv4 ICMP drop rules. ICMPv6 has no such exception.
NAT destination rewriting remains TCP/UDP only; no port ranges, arbitrary
numeric protocols or ICMP type/code selectors were added.
See the [filter contract](FRONTEND_SPEC.md#66-firewall-forwarding).

## Kernel reverse-path filtering

`firewall.rpf_mode` selects Linux IPv4 `rp_filter`: **disabled** (default),
**loose**, or **strict**. Strict requires the reverse route through the ingress
interface; loose requires a reverse route through any interface. This is routing
validation, not a LAN-subnet allowlist, and does not protect IPv6.

Netcontrol takes over `all`, `default` and every interface's RPF setting in its
managed namespace, including WAN, LAN, unmanaged/down links and loopback.
Existing values are overwritten without ownership-conflict refusal.
Install/startup/upgrade and reconciliation apply the selected mode; explicitly
saved modes are preserved. New links inherit the owned default.
Strict mode can disrupt asymmetric multi-WAN/VPN traffic: review topology and
retain console access. Changes use confirmed firewall transactions or
`firewall rpf disabled|loose|strict`.

There are no generated spoof-block rules, exceptions or `system_policies`.
The firewall API returns only the mode and ordinary configuration; runtime
reports measured RPF values and drift. RPF drops are not nftables counters,
deny-log events, MQTT firewall-drop totals or Discord notifications. Retained
historical deny records are preserved.
See the [contract](FRONTEND_SPEC.md#kernel-reverse-path-filtering) and
[handoff](docs/frontend-handoffs/2026-11-09.md#2026-11-09-10-kernel-ipv4-reverse-path-filtering).

## Firewall rule accounting

`GET /api/v1/statistics/firewall` (`state.read`, no query/body) reads live
native nftables packet/byte counters. Expanded address/family/port matches are
summed into each configured host, interface, legacy, input or NAT rule. Defaults,
established/related bypass and the IPv4 ICMP exception have separate rows.
Counts are exact decimal strings, not JavaScript numbers or unique connections.
NAT counters measure initial rule evaluation, not established-flow throughput.

Use the returned scope, ruleset identity and generation before calculating
deltas or joining rows to the applied configuration. Applying/rolling back a
network ruleset, startup/service repair or reboot resets counters; metadata-only
changes need not. No persistence/reset endpoint or changes to configuration
exports. Reads preserve ownership and ignore only changing numeric counter
values for drift inspection; drift/unavailable reads are errors, never fake zeros.
Ubuntu install/full upgrade provisions `nf_tables`, which includes counter
expressions on current kernels; there is no separate `nft_counter` requirement.
Other Linux installations must enable `CONFIG_NF_TABLES`. See the
[complete API/reset contract](FRONTEND_SPEC.md#firewall-rule-match-counters).

## Firewall deny history

`firewall.drop_logging_enabled` defaults to `true` on new installations and
factory reset. Set it to `false` using a confirmed configuration transaction
(`transactions.write`, `firewall.write`) or SSH `firewall drop-logging disable`
to stop collection without changing firewall verdicts or rule counters.
History and first-seen identities persist; the log API reports `disabled`.
Re-enable with `true` or `firewall drop-logging enable`. Discord alerts depend
on capture and pause while logging is disabled; missed traffic is not backfilled.

When enabled, native Linux continuously records managed input/forwarding rule and default-policy
drops in a private, persistent rotating log, separate from configuration, revisions,
backend audit logs and syslog. Retrieve retained metadata on demand with
`GET /api/v1/firewall/deny-log?limit=100`, using an API key granted
`firewall.logs.read`. Filter by address, numeric IP protocol, chain and Unix
millisecond time range; page newest-first using `next_before_id`.
Records include nullable TCP flags/payload byte counts and independent traffic
tags. Retrieval excludes IPv4 broadcast and TCP FIN/RST/known empty ACK-only drops
by default. Request `include_broadcast=true` and/or `include_tcp_closures=true`
to include those categories; overlapping records require both flags. Filters apply
server-side before pagination and combine with address/protocol/time/chain selection.
Use both flags to retrieve all categories; keep flags unchanged while paging.
No `tag` or `exclude_tags` query parameters are supported.
Broadcast detection uses limited broadcast
`255.255.255.255` and live kernel-reported subnet broadcasts, not a `.255` guess.
ACK-only does not prove teardown, and no tag changes capture or firewall verdicts.
Current deny segments require schema 2; unsupported history fails startup unchanged.
See the deployment guide before replacing a backend with existing telemetry.

Retention is at most 4096 records in eight bounded segments; collection retains
at most 100 records/second and reports loss/error indicators. This is best-effort
diagnostic history, not a complete security audit or packet capture. Accepted
traffic, other firewall owners and non-firewall drops are excluded.
See the [API contract](FRONTEND_SPEC.md#firewall-deny-log) and
[kernel/storage prerequisites](docs/BUILD_AND_INSTALL.md#firewall-deny-logging).

## Protected-host network experience

Native Linux host mode automatically collects explicitly configured firewall
hosts behind observed, up, managed LAN interfaces. Each canonical IP has its own
ten-second series, retained for one hour in private SQLite storage at
`<services-state-dir>/host-experience/experience.sqlite`. No active probes or
external collector programs are used.

`GET /api/v1/statistics/host-experience/latest` and
`GET /api/v1/statistics/host-experience/history?address=192.0.2.20` require
`state.read` and no body. Latest supports `address`, `interface`, `limit`
1..256 (default 100) and opaque collection-pinned `cursor`; history returns
360 observed/missing ten-second slots. Four reads may run concurrently.

`GET /api/v1/statistics/host-experience/summary` provides a separately labeled
rolling **1-hour observed experience** table, with the same scope/body rules.
Use `address`, `interface`, `limit` 1..256 (default 25) and its own window-pinned
cursor. It pools exact traffic/TCP/DNS counts, source coverage, usable RTT
extrema/variation, experience-state durations and timestamped last rated
experience. Missing evidence remains unknown; no invented hourly score or
averaged p95. DNS and both passive RTT p50/p95 pool retained 32-bin timing
histograms, with explicit sample/slot coverage; these are histogram estimates.
Older history without distributions stays retained but cannot supply timing
percentiles. The backend atomically extends recognized telemetry schema v1 with
the bounded timing table; new coverage fills over the next hour, without backfill.
Connection gauges include both the pinned latest snapshot with
freshness and the one-hour mean over available snapshots, with coverage.
Restart paging on `409` window expiry. See the
[summary contract](docs/PROTECTED_HOST_EXPERIENCE_SPEC.md#821-one-hour-per-ip-summaries).

Return host-perspective packets/bytes/rates, managed policy drops, connection
gauges, observed TCP repeats/window pressure/passive ACK timings, ordinary
UDP/TCP DNS latency/unanswered observations, last seen, interface/VLAN and
cached Sando metadata. Counts are decimal strings; missing evidence stays null.
The explainable score is a Netcontrol heuristic, not UniFi/Wi-Fi telemetry.
Managed drops never penalize it. Capture loss/capacity pressure prevents false
ratings; last seen is traffic observation, not reachability or uptime.

See the [implemented contract and limits](docs/PROTECTED_HOST_EXPERIENCE_SPEC.md)
and [frontend handoff](docs/frontend-handoffs/2026-11-14.md#2026-11-14-04-protected-host-experience-implementation).
Deployment requires owned nftables counter/last-expression sets, NFLOG group 101
with ingress timestamps/sequence/conntrack metadata, AF_PACKET/TPACKET_V2
LAN-egress capture, and owner-only writable storage. Linux does not supply NFLOG
timestamps at postrouting: received transport evidence uses kernel-timestamped
packet-ring frames instead. Connection inventory refreshes before every
ten-second bucket; missing/stale sources still return null, never guessed zero.
The revised main-file budget is 2 GiB plus a bounded 32 MiB WAL; freed pages are
reused, not continually vacuumed. Simulator/lab-namespace mode is unsupported.
Appliance throughput, forwarding latency and NIC/offload acceptance remain
deployment checks; namespace/unit tests do not certify physical performance.

## Discord first-seen drop alerts

Optional `discord.enabled` sends Discord webhook notifications for the first
captured occurrence of exactly `(source IP, destination IP, destination port,
IP protocol)`. Source ports, interfaces and reasons do not create new identities.
A durable native index preserves seen tuples across restarts and drop-log rotation;
there is no time-based expiry. Drops first seen while globally or categorically
disabled are not backfilled.
Existing retained history seeds the index without sending messages.

Independent `discord.notify_broadcast` and `discord.notify_tcp_closures` flags
both default off. The first permits IPv4 broadcast drops; the second permits
FIN, RST and known empty ACK-only drops. A drop in both categories requires both
flags enabled. These observed packet tags do not prove a connection closed or
traffic is harmless. Other newly seen drops remain eligible with global alerts
and capture enabled. Category filters affect notifications only: history and
permanent seen identities are retained. Queued drops are checked against current
settings before delivery; enabling later never replays suppressed tuples.

Upload the secret URL through `POST /api/v1/services/discord/webhooks`
(`discord.write`), then save the returned `webhook_ref` and notification flags
through normal confirmed transactions (`transactions.write`, `discord.write`).
Only canonical HTTPS `discord.com` webhook URLs are accepted. Raw URLs/tokens
are private and never enter configuration exports. Read delivery/errors with
`GET /api/v1/services/discord/status` (`state.read`). Native host mode only;
simulator mode never posts. The worker is supervised and can be restarted with
the existing managed-process action without resetting identities.

`POST /api/v1/services/discord/test` (`discord.write`, no query/body) sends the
firewall name, compiled backend version and committed configuration revision to
the saved webhook, including while automatic alerts are disabled. Native host
mode and an available worker are required; simulator mode never sends.
Only successful Discord acceptance clears the delivery error and failure count;
health warnings recover on the next sample. Preserve delivered-alert counts,
seen identities and notification settings. Failures remain explicit and do not
clear counts. Do not automatically retry test requests or use them to recover a
stopped worker. See the [test contract](FRONTEND_SPEC.md#discord-first-seen-drop-alerts).

Alerts include packet metadata, not payloads, and batch up to ten first-seen
entries with mentions disabled. Identify the firewall as `hostname.domain` when
both are configured, hostname alone without a domain, or `Firewall` without a
hostname. Source/destination endpoints retain IPs/ports and append only Sando
`local_description` labels in uppercase for exact matching IPs from the current
source's cache. This is Discord-only formatting; stored descriptions and the
firewall name retain their case. Missing/null/blank descriptions leave IP/port only: no DNS/DHCP/lease
hostname or configured firewall-host-name fallback. No live lookups are performed.
Long names split messages within Discord's embed limits without truncation.
Device names are additional metadata exported to Discord.
Respect Discord rate limits; delivery remains
best-effort, with no replay after ambiguous failures or interrupted sends.
The permanent identity index grows with distinct traffic; preserve private
state and monitor disk capacity. No firewall rules are automatically opened.
See the [complete contract](FRONTEND_SPEC.md#discord-first-seen-drop-alerts) and
[frontend handoff](docs/frontend-handoffs/2026-11-08.md#2026-11-08-08-discord-notification-category-flags).

## Sando imports

Sando acquisition runs entirely in the daemon; **Test sync** retrieves and maps
policies server-side without applying them. Remove browser host/rule imports.
The backend saves `config.sando`
with an API base URL and separate latest confirmed host/rule import
records, including source, operation/item counts, time and status. Save them
with reviewed firewall changes through normal confirmed transactions
(`sando.write`, plus `firewall.write` for host/rule edits).

Saved firewall/NAT rules expose `origin` (`manual`, `import`, `system`, `inherited`)
and nullable `import_source`; Sando uses `origin:"import", import_source:"sando"`.
The daemon replaces only Sando-owned host rules, preserves manual rules/other
imports and keeps manual-first ordering within each affected list. The backend
stores/validates labels and tags generated counter rows as system. The optional
automatic policy worker below replaces only Sando-owned host rules; ordinary
configuration writes have no special merge guard. Labels do not affect matching or
counter generations. See [rule origins and replacement](FRONTEND_SPEC.md#rule-source-labels-and-sando-replacement).

Optional `sando.sync_enabled` (default `false`, requires `api_url`) enables
daemon-side host metadata acquisition immediately on startup/enablement and
hourly after each completed attempt, even with no browser open. The daemon pulls
host names, icons, classification descriptions and threat scores from Sando's
`GET /api/localhosts`; it never recalculates scores or imports ignore lists.
Read the durable, bounded metadata snapshot and last attempt/success/error using
`GET /api/v1/sando` (`state.read`). Failed refreshes preserve the last successful
snapshot; disabling cancels polling while retaining cached metadata. Host sync automatically adds new canonical unicast firewall hosts with stable
browser-pattern IDs, bounded unique names, policy `drop` and no initial rules.
Existing hosts, addresses, manual names/policies/rules and unrelated settings
remain unchanged; missing inventory never deletes hosts. IPv6 additions require
`ipv6_enabled`; conflicting/ineligible rows are skipped and counted. All valid
additions use one durable apply/verify/immediate confirmation and configuration
revision; unchanged/score-only refreshes create none. Busy/apply failures retain
the prior configuration/cache and retry hourly. Existing host limits apply
atomically, and legacy forwarding rules must first be removed explicitly.
New hosts trigger the independently enabled policy worker immediately.
Metadata remains a separate cache; confirmed browser import reports are untouched.
Both sync toggles and URL changes while either is enabled require `firewall.write`
with normal Sando/transaction authority. Server-to-Sando reachability is required; no credentials, arbitrary
proxy or full device-object storage is added.

Independent `sando.policy_sync_enabled` (default `false`, requires `api_url`)
polls `GET /api/ignorelist` immediately and every five minutes after completion.
It uses `ETag`/`If-None-Match`; `304` does not load or apply a list. A changed
list automatically replaces Sando-owned outbound accept rules on existing
hosts, preserving manual/other-provider rules, inventory and default policies.
Canonical unicast, same-family addresses and supported protocols/ports are
mapped, including browser-compatible explicit `*` destinations/ports and
ICMP zero/wildcard ports. Host permits cover that host's addresses in the
matching family. Unsupported/unmatched/duplicate entries are skipped and counted.
A valid empty list removes old Sando-owned host rules; a nonempty all-invalid
list fails and retains them. Retained rules prevent duplicate permits, manual
rules stay first, and unchanged Sando permits retain saved order despite upstream
query ordering. No wildcard sources or new hosts are inferred. Enabling/disabling, or changing the URL while enabled,
requires `firewall.write` as well as `sando.write` and `transactions.write`.

Effective rule changes use durable apply/verification and automatic confirmation,
advancing the configuration revision once without browser intervention. Failures
retain the validator for retry and use normal rollback/recovery; busy transactions
are not overwritten. Unchanged rules/`304` do not create revisions. Read independent
`policies` status/counts/errors through `GET /api/v1/sando`. Applied configuration
survives restart; policy status/ETag are in memory and startup fetches unconditionally.
One-time import reports remain untouched. Host/score sync need not be enabled.
See the [automatic policy contract](FRONTEND_SPEC.md#automatic-policy-synchronization).

Bodyless `POST /api/v1/sando/policies/preview` uses the committed Sando URL and
the same retrieval/host-rule mapping as automatic policy sync. It requires
`state.read`, `sando.write` and `firewall.write`, but not `transactions.write`.
It returns the full proposed `config`, `base_revision`, source URL/ETag,
imported/skipped counts and `changed`; it never submits a transaction, applies
rules, enables polling, writes import reports or updates worker status/cache.
Either sync flag may remain disabled for already configured hosts. Test sync
does not create hosts: enable host sync and await discovery for new hosts.
The frontend stages the candidate in
**Save / Commit** for explicit review, normal save/confirmation or discard.
Existing unsaved drafts must not be overwritten; a revision change during
retrieval returns `409` and later stale saves use normal conflict handling.
Empty previews show the same Sando-owned-rule removals as automatic
sync, but do not activate them. See [Test sync](FRONTEND_SPEC.md#server-side-test-sync-preview).
The required **Settings > Sando** toggles, status panels and import workflow are specified
in the [frontend contract](FRONTEND_SPEC.md#sando-one-time-imports).

## Build and validate

Use stable Rust. The workspace toolchain file selects rustfmt and clippy;
Cargo.lock pins dependencies. Source builds require Git and a full checkout
(not a shallow clone or source archive) to derive the commit version.
A supported native C toolchain is needed for TLS
cryptography; Linux builds also require libclang and Linux UAPI headers for the
direct nftables bindings. See the [build prerequisites](docs/BUILD_AND_INSTALL.md#build).

The test profile optimizes core code at `opt-level=1` and native code at
`opt-level=2` so bounded read regressions exercise an optimized native decoder
rather than debug-build overhead. Test debug assertions and bounded read deadlines remain enabled:
900 ms normally, with hourly-summary aggregation allowing 900 ms per started
64-host batch (at most 3.6 seconds for 256 hosts). Development and release
build profiles are unchanged.

CI runs the dense 256-host/hourly deadline regression in its own required step
so unrelated parallel tests do not consume its wall-clock read budget. It is
excluded only from the parallel invocation, not from validation; its 3.6-second
deadline, 360-slot/256-host correctness and 4 MiB response assertions remain.
To reproduce CI scheduling locally:

```sh
cargo +stable test --workspace --locked -- --skip experience_store::tests::dense_hourly_page_obeys_read_and_response_bounds
```

```sh
cargo +stable test -p netcontrol-native --lib --locked experience_store::tests::dense_hourly_page_obeys_read_and_response_bounds -- --exact --nocapture --test-threads=1
```

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
```

Linux kernel and privileged protocol tests are separate:

```sh
NETCONTROL_INTEGRATION=1 cargo test \
  -p netcontrol-native -p netcontrol-services --locked -- --ignored --test-threads=1
```

Run these only on an appropriately privileged, disposable Linux test machine.
Run fixtures serially: isolated host-mode fixtures still share the exclusive
host-tunables lock. CI uses the same single-threaded test setting.
CI runs native, protocol-worker and root-only CLI suites on separate disposable
runners, including the ignored sizing/throughput checks; no tests are skipped.
It preserves `CARGO_INCREMENTAL=0` when invoking Cargo under `sudo` to reuse
the precompiled tests. GNU release build/installation checks run independently
of workspace tests/Clippy and the musl package build. Publication requires all
jobs, including every privileged matrix entry, to pass. Each new job/suite has
its own dependency cache; the first run may be cold. Repository rules requiring
individual job names must account for the split GNU/privileged check names.
Portable Windows tests and Linux cross-compilation do not establish native
runtime correctness. Consult the [change journal](docs/journal/2026-10-19.md)
for actual validation results and known limits of the rewrite.

For fast development on an Ubuntu amd64 firewall, use
[upgrade.sh](upgrade.sh) to build incrementally and restart
the daemon without Docker or waiting for CI. An installed service and saved
configuration are required; upgrades never provision from live interfaces. See the
[setup and recovery limitations](docs/BUILD_AND_INSTALL.md#incremental-ubuntu-development-upgrades).
Ubuntu installation and full upgrades also enable and persist conntrack accounting
and checksum validation; existing flows may retain null counters. See
[conntrack host prerequisites](docs/BUILD_AND_INSTALL.md#conntrack-host-prerequisites).
These scripts also configure journald forwarding and a systemd-owned native
syslog receiver at `/run/systemd/journal/syslog`, stopping/masking competing
syslog receivers. Journald keeps `/dev/log`, kernel capture and the local journal.
Review [logging ownership and recovery](docs/BUILD_AND_INSTALL.md#host-logging-ownership);
saved syslog settings are not enabled automatically.
Fresh installation and full source upgrades also remove standard Ubuntu MOTD
files/generators, disable PAM MOTD output and stop/persistently mask MOTD units.
Custom content in the targeted MOTD locations is deleted. Build-only and
HTTP/automatic HTTPS self-upgrades do not apply this cleanup. See
[MOTD cleanup](docs/BUILD_AND_INSTALL.md#motd-cleanup).
These scripts also stop/disable and persistently mask standard OS NTP clients,
including timesyncd, chrony, ntpd and one-shot NTP services/timers. They verify
stopped/persistently masked units and reject remaining known NTP processes.
Netcontrol's saved NTP settings are preserved: with NTP disabled there is no
managed network clock synchronization; enabling it polls only configured servers.
NTP runtime status includes optional `server_time`, the selected server's sampled
reply-transmission UTC, separately from firewall-clock `collected_at` and signed
`offset_ms`. Sampling failure retains the old server time with unavailable sample
status; it is not a live clock or proof that local clock correction completed.
Existing appliances need the revised full source upgrade to establish these masks;
binary-only self-upgrades retain but do not create them. See
[NTP ownership](docs/BUILD_AND_INSTALL.md#ntp-ownership).

Native Linux mode continuously collects [link diagnostics](FRONTEND_SPEC.md#native-link-diagnostics):
qdisc backlog/drops, interface errors, local TCP RTT/retransmissions/congestion
windows, and bounded plaintext ingress TCP advertised-window observations
(including forwarded traffic). Use `GET /api/v1/statistics/link-diagnostics`,
`show statistics link-diagnostics`, aggregate statistics, or existing MQTT state
publication. Collection is in-process Rust using netlink and filtered AF_PACKET
sockets, not eBPF tools or supervised helpers. Install/full source upgrade loads
and persists the required packet/TCP diagnostics modules. Signals are evidence,
not proof of the failing upstream hop; receiver pressure is not link congestion.

Operational actions run entirely in Rust:
`POST /api/v1/processes/restart` with `{"target":"ntp"}` selectively restarts a
managed worker (`system.restart` permission). Target `netcontrold` schedules a
graceful full restart only under the packaged native systemd/watchdog service;
it never kills arbitrary OS processes.
`POST /api/v1/diagnostics/dns-lookup` with
`{"interface":"wan0","hostname":"google.com","record_type":"A","timeout_ms":2000}`
queries that interface's configured/DHCP DNS servers and returns measured
`rtt_ms`, answers, DNS response code and attempt errors (`diagnostics.run`).
Add `"server":"192.0.2.53"` to query only that IP on port 53, without configured
resolver fallback or changing saved DNS settings. With an explicit server,
omit `interface` to use normal kernel routing, for example
`{"hostname":"example.test","server":"192.0.2.53"}`. No shell lookup or external
helper is used. See the
[complete action contract](FRONTEND_SPEC.md#operational-restart-and-dns-diagnostics)
for targets, limits, statuses, timing and side effects.

Paired MTU/MSS diagnostics use explicit
`POST /api/v1/diagnostics/path-tests` on both firewalls: select any suitable
live IP interface, its source address, exact peer IP, a common test port and
a random one-time pairing secret. Supply the selected interface's temporary
maximum MTU and explicitly approve any parent MTU increases. This can disrupt
other traffic; nothing is inferred or saved as a new configuration.
Start/cancel needs `diagnostics.run`, `interfaces.write` and `firewall.write`.
Read progress/results with `GET /api/v1/diagnostics/path-tests` (`state.read`);
cancel with `POST /api/v1/diagnostics/path-tests/{id}/cancel`.
Arming/measurements are bounded; scoped temporary firewall permissions expire
and owned MTUs/rules are restored afterward. Interrupted MTU changes recover
on daemon startup; restoration failures remain explicit and block mutations.
Compare verified packet sizes and measured MSS trials, not a promise of an
ideal MTU or proof of no outer tunnel fragmentation. No iperf/external worker,
automatic tuning or API-key exchange. Preparation currently refuses configured
DHCP clients, enabled BGP and dynamic WireGuard DNS on an unresolved/affected
path; it does not stop these services automatically. Kernel permit expiry does
not revoke established conntrack acceptance, and a killed daemon must restart
to restore MTUs. See the
[paired-test contract](FRONTEND_SPEC.md#paired-path-mtumss-tests).

Basic native IPv4 BGP runs inside the daemon: configure `bgp` in a full
transaction with local ASN/router ID, interface-bound neighbors and keepalive/
hold timers. It advertises connected prefixes from all configured up interfaces,
installs accepted learned routes, and maintains BGP-owned WireGuard AllowedIPs
for explicitly referenced peers. Default-route import requires opt-in.
Each neighbor has `enabled` (default `true`); set `false` in a full transaction
to stop that session and remove its learned routes without deleting saved
settings or static WireGuard AllowedIPs. Disabled neighbors show `disabled`
and do not degrade health; all-disabled BGP is idle with no listeners.
Applying the change currently restarts BGP, briefly reconnecting other enabled
peers too. Disabled saved neighbors still require valid interface/peer settings.
Inspect `GET /api/v1/services/bgp/status` or `GET /api/v1/routes/bgp`;
`GET /api/v1/routes/bgp/advertised` lists exact per-neighbor session exports.
CLI inspection uses `show bgp status` or `show routes bgp`; MQTT includes the summary and shared
process health. Static configuration is preserved on withdrawal/session loss.
See the [BGP contract and operator prerequisites](FRONTEND_SPEC.md#native-ipv4-bgp)
for limits, bootstrap routing, privileges, ownership and unsupported features.
A [synthetic BGP-over-WireGuard transaction](examples/bgp.json) illustrates
the current schema; provision keys/underlay and adapt the complete configuration
before applying it.

For a routed speaker with a separate forwarding host, set each neighbor's
`multihop_ttl` (1..255, default 1) and `allowed_next_hops` (up to 32 gateway
addresses). A nonempty list replaces the implicit peer-only next-hop
policy; an off-link non-WireGuard speaker requires TTL greater than 1 and a
nonempty list. Provide independent bootstrap/return routes and TCP/179 permits.
See the [synthetic routed BGP transaction](examples/bgp-routed.json).
Neighbor status exposes `last_rejection` alongside the rejected-prefix counter.
WireGuard also supports separate session/NEXT_HOP addresses: both must be
covered by the referenced peer's static AllowedIPs, and listed next hops must
not overlap another enabled peer's static AllowedIPs. The
[WireGuard example](examples/bgp.json) includes a separate speaker, authorized
forwarding address and bootstrap route. Learned destinations still use that
peer's tunnel/AllowedIPs, not ARP or recursive gateway resolution.

Optional Ubuntu amd64 self-upgrade uses `POST /api/v1/system/upgrade` with a
specific `yyyy.mm.dd.iteration` version and `GET` on the same path for durable job status.
Installation and source upgrades automatically create/validate private update
settings and enable the fixed GitHub HTTPS repository; no signing key is needed.
Ubuntu self-updates are unsigned: HTTPS/GitHub are trusted, with bounded manifest,
version, ELF, size and SHA-256 checks, not independent publisher authentication.
The separate signed `.ncpkg` format is unchanged.
See [Ubuntu self-upgrades](docs/BUILD_AND_INSTALL.md#ubuntu-self-upgrade)
for bootstrap, artifact publishing, recovery and validation limitations.

Software identity comes from `RELEASE_VERSION` in
[version.rs](crates/netcontrol-core/src/version.rs), generated from Git by
[build.rs](crates/netcontrol-core/build.rs), not Cargo's package version.
Starting with the immutable [seed](crates/netcontrol-core/release-version),
each first-parent commit advances `yyyy.mm.dd.iteration` using its UTC commit
date, including documentation-only commits. No manual version bump is needed.
CI validates every new default-branch mainline commit and publishes its version
tag and two Ubuntu update assets as a stable GitHub Release; PRs and other
branches never publish. See [automatic releases](docs/BUILD_AND_INSTALL.md#automatic-builds-and-releases).
The daemon saves read-only `software` metadata in the master configuration:
running version, configured release repository, latest release, nullable update
availability, last check time and explicit error. It checks the fixed default
`mayberryjp/firewall_backend` repository at startup and every 24 hours even without
installation configuration; configured self-upgrades supply their repository/token.
`--disable-release-checks` explicitly disables discovery and Check now;
no automatic installation occurs. Disabled, pending and failed checks never mean
"up to date". `POST /api/v1/system/upgrade/check`, with `system.upgrade` and an
empty body, requests a check now (`202`); read saved `software` metadata for the
result. An existing queued/running check returns `409`, disabled/unavailable
checking `503`. See the [frontend contract](FRONTEND_SPEC.md#check-now).

Configuration revisions independently use the same UTC date format as JSON strings.
An existing numeric-v1 journal requires the explicit
[offline conversion](docs/BUILD_AND_INSTALL.md#offline-date-revision-state-conversion)
before deploying the date-version daemon; configuration/history are preserved
with private backups rather than discarded.
Initialization and each UTC day's first confirmed commit start at iteration 1;
further commits that day increment it. History, conflict detection and confirmed
restore use the exact server-issued revision; never derive it with arithmetic.
The current journal is `netcontrol-rust-state-v2`. Numeric-revision journals are
incompatible and are refused without deletion, reset or automatic conversion.

For optional Ubuntu OS footprint reduction, start with `sudo bash hardening.sh`
to preview the explicit service/package profile. Nothing changes without
`--apply`. Fresh installation and hardening apply both stop/disable and
persistently mask installed `snapd.service` and `snapd.socket`, verifying that
they are inactive/failed and persistently masked. Absent units are skipped;
Snap packages/data and separate application units are not removed. Snap
management and refreshes are blocked, so review Snap-dependent workloads first.
Fresh installation and hardening also disable Ubuntu's automatic APT checks, downloads and installs,
**including automatic security updates**, with persistent timer/service masks
and verified APT periodic/shutdown settings. Manual `apt-get update`/`upgrade`
and Netcontrol release checks remain available; operators must schedule OS
patching. Running APT jobs are never forcibly stopped; wait for completion and
retry if verification fails. Binary/source upgrades alone do not apply these
host policies; existing hosts can use the reviewed hardening workflow.
Fresh installation and full source upgrades prepare a verified GRUB `apparmor=0`
boot setting and persistently mask its service. Active AppArmor does not block
installation or binary replacement: a visible warning recommends a manual
console reboot afterward, which may be deferred without rerunning the installer.
Existing kernel confinement may remain active until that reboot.
All packages (including Ubuntu metapackages), profiles, caches and APT preferences
are preserved; no AppArmor purge, autoremove or package pin is performed.
This disables confinement protection; it is not
a security improvement or a guarantee against deliberate root overrides.
Build-only, HTTP/automatic binary upgrades, signed packages and reset do not
establish this policy.
The separate hardening workflow still requires explicit `--disable-apparmor`
and retains packages; it does not apply the mandatory deployment verification.
See [AppArmor disablement](docs/BUILD_AND_INSTALL.md#apparmor-disablement).
See [scope and recovery](docs/BUILD_AND_INSTALL.md#ubuntu-os-footprint-reduction).

## Destination rewrite

Exact-port destination NAT can redirect forwarded Internet-bound traffic to a
device on a local subnet. Match the original WAN, TCP or UDP and one port using
`firewall.nat.destination_rewrite`; see the
[example](examples/destination-rewrite.json) and
[complete contract](FRONTEND_SPEC.md#destination-rewrite).
For DNS, configure both TCP/53 and UDP/53. The destination port and client IP
are preserved; firewall-originated traffic is excluded. Ordinary forwarding
rules see the rewritten target and still apply.

The target must send replies through this firewall. A target on the client's
own subnet normally replies directly and will not work without an explicitly
arranged routed return path. No automatic source NAT or hairpin masquerade is
added. Configure a separate target subnet if needed. Changes affect new
connections; existing conntrack translations are not automatically deleted.
The target device is not automatically exempt: its own upstream queries must
not use the intercepted WAN/port, or they will be redirected back to it.
Linux nftables inet FIB/NAT support, forwarding and working routes are required.
Edits use normal confirmed transactions and `nat.write`.

## Start and onboard

For a development simulator:

```sh
cargo run -p netcontrold -- \
  --backend simulator \
  --listen 0.0.0.0:8080 \
  --state state.json \
  --credential-db credentials.json
```

Open `http://<machine-LAN-IP>:8080/` in your browser. No SSH tunnel or TLS
certificate is required by the default HTTP configuration.

1. Create the device account with a username and password.
2. Generate a named **API key** and save the one-time plaintext value.
3. Acknowledge saving the key and finish setup.
4. Configure your API client with the appliance address and API key.

The device account manages keys; it does not authorize networking calls.
The API key authorizes networking calls; it does not manage the account.
`Bearer` is the HTTP authorization scheme, not the user-facing credential name:

```http
Authorization: Bearer <API key>
```

Unclaimed devices can be claimed by anyone able to reach the website.
`0.0.0.0` includes all IPv4 interfaces, including WAN-facing ones. HTTP
transmits passwords, session cookies, and API keys without encryption.
Restrict management reachability appropriately. Optional TLS requires a
certificate and private key together.

On LAN HTTP origins browsers may disable automatic clipboard access; manually
select and copy the API key when needed. The plaintext cannot be recovered
after the one-time dialog closes.

### Cross-origin dashboard access

Networking paths under `/api/v1/` allow all origins, including error responses.
Valid preflight requests allow GET/POST with Authorization and Content-Type.
Actual requests still require an API key and the appropriate permissions.
Use `credentials: "omit"` for cross-origin dashboard calls.

Account and key-management paths under `/auth/` remain same-origin and use
HttpOnly, SameSite=Strict session cookies. HTTP cookies are not Secure; HTTPS
cookies are Secure. CORS does not bypass mixed-content, certificate,
private-network, or network-reachability restrictions.

## Azure Dynamic DNS

The in-process Dynamic DNS client updates **Azure public DNS IPv4 A records**.
It follows the pfSense model of a monitored WAN interface, relative hostname,
Azure application ID/secret, zone resource ID and TTL. Unlike pfSense's generic
username/password labels, the API names the Azure tenant/client fields explicitly.
AAAA records, private DNS zones, wildcard names, other providers, gateway-group
failover and custom detection URLs are not supported.

1. Host/delegate your public zone in Azure DNS. Register a single-tenant Entra
   application; record the tenant ID, application/client ID and **client-secret
   value** (not its secret ID). Assign its service principal **DNS Zone Contributor**
   at the DNS zone scope. Keep track of secret expiry and replace it before expiry.
2. Upload the secret using `POST /api/v1/services/dynamic-dns/secrets`
   (`dynamic_dns.write`), with `{"client_secret":"synthetic-example-only"}`.
   Save the returned `secret_ref`; the secret is never returned.
3. Add an entry to `config.dynamic_dns` in a complete ordinary configuration
   transaction (`transactions.write` plus `dynamic_dns.write`), then confirm it.
   Example below is synthetic: replace IDs/reference/zone/interface.

```json
{"dynamic_dns":[{"name":"azure-wan","enabled":true,"source_interface":"wan0","address_source":"public_ip","tenant_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222","secret_ref":"0123456789abcdef0123456789abcdef","zone_resource_id":"/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/dns-rg/providers/Microsoft.Network/dnszones/example.com","record_name":"home","ttl_seconds":300,"interval_seconds":60}]}
```

`record_name` is relative (`home` or `vpn.home`), **not** `home.example.com`;
use `@` for the zone apex. `address_source: "interface"` uses the selected
interface's public IPv4 directly. `"public_ip"` queries `https://api.ipify.org`
through that interface to detect a NAT-translated public IPv4. Public detection
discloses the egress IP to ipify; CGNAT detection does not make inbound connectivity
possible. The interface must be up with exactly one usable IPv4 address; missing
or ambiguous addresses fail explicitly. Non-public results are refused.

Only confirmed settings activate; active transactions/upgrades pause checks.
Disabling/deleting an entry stops updates but **does not delete the Azure record**.
Configuration rollback cannot undo a completed/in-flight external DNS write.
The client checks Azure every interval, skips unchanged IP/TTL, preserves record
metadata and uses ETag/conditional creation to avoid overwriting concurrent edits.
It refuses alias or multi-address A record sets. Missing records are created.
Errors retry after the configured interval; requests are serialized with bounded
timeouts. DNS TTL/recursive caches still govern when clients observe a change.

Poll `GET /api/v1/services/dynamic-dns/status` (`state.read`) for per-entry state,
last successful address, last check/update Unix seconds and redacted errors.
See the [complete frontend contract](FRONTEND_SPEC.md#615-azure-dynamic-dns).
There is no manual force-update action.

Linux host mode, privileged interface binding, working host DNS/routing and
outbound HTTPS to ipify (public detection only), `login.microsoftonline.com`
and `management.azure.com` are required. All HTTPS certificates/hostnames are
verified; redirects and proxies are disabled. Sockets bind both source IPv4 and
interface without another-WAN fallback; DNS lookups still use the host resolver.
Simulator reports simulated without network I/O; namespace lab mode rejects entries.
Use HTTPS/a trusted management channel for secret upload.

Back up `<state>.dynamic-dns` together with configuration/history (default
`/var/lib/netcontrol/native-state.json.dynamic-dns`). These daemon-owned,
owner-only secret files are **plaintext at rest**, not encrypted. At most 256
immutable secrets are retained, including discarded uploads; no read/delete or
automatic pruning API exists because old revisions may reference them.

References consulted:
[pfSense Dynamic DNS client settings](https://docs.netgate.com/pfsense/en/latest/services/dyndns/client.html),
[pfSense Azure setup walkthrough](https://micoolpaul.com/2022/07/20/configuring-pfsense-dynamic-dns-with-azure-dns/),
[Microsoft client-credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow),
and [Azure DNS record-set REST API](https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01).

## Home Assistant MQTT Statistics

Optional streaming is API-managed. Upload a broker password with
`POST /api/v1/services/mqtt/passwords` (`mqtt.write`), then put the returned
`password_ref` in `config.mqtt` in an ordinary configuration transaction and
confirm it. Changes require `transactions.write` and `mqtt.write`; status uses
`state.read` at `GET /api/v1/services/mqtt/status`. Passwords are never returned
or included in configuration/history. Use HTTPS or a trusted management channel.

Example settings inside a complete candidate configuration (synthetic reference;
replace it with the upload result and select an up managed interface):

```json
{"mqtt":{"enabled":true,"endpoint":"mqtts://broker.example.test:8883","username":"netcontrol","password_ref":"0123456789abcdef0123456789abcdef","source_interface":"lan0","interval_seconds":60}}
```

Default disabled, interval 60 seconds (allowed 10..3600). Only confirmed settings
activate publishing. A persistent source-interface-bound MQTT 3.1.1 connection
publishes Home Assistant device discovery, availability, gateway health/probe-window
summaries, interface counters, configuration revision and daemon uptime, plus host
health: memory/swap, load, uptime, pressure, **per-core CPU busy percent**, **per
temperature/fan sensor** (thermal zones and hwmon) and local filesystem space, and
per-instance NetFlow/IPFIX export state, **dropped capture packets**, active/exported
flows, exported UDP datagrams/payload bytes, sampled observed packets/bytes represented
by sent flow records, export errors and excluded/filtered/malformed packet counters.
The same per-instance totals are available in the
[runtime/status API](docs/NETFLOW_IPFIX_SPEC.md#5-runtime-and-status-api);
they reset on worker restart and do not confirm collector receipt. Coverage also includes
all interface error counters, IP/TCP/UDP/ICMP kernel counters, disk I/O, VM and
scheduler counters, all PSI windows, service/NTP/syslog/mDNS/relay statistics,
DHCP lease summaries, WireGuard peer byte counters/handshakes, BGP neighbor
gauges, vnStat daily/monthly/lifetime and reporting summaries, software release
checks and Sando sync summaries. The version sensor uses the embedded calendar
release version, not Cargo's internal placeholder.

Only NetFlow v5 and IPFIX v10 are supported; v1/v9 are rejected. Both support
configurable `sampling_rate`: 1..1,000,000,
with v5 limited to 16,383, including disabled instances. `1` is unsampled;
N selects every Nth received frame. Raw flow counts are not scaled; collector
full-traffic estimates must account for the interval. Capture exclusions/drops
and UDP delivery loss can still make totals incomplete. Byte-based exports use
`max_message_size` (default 1200 UDP payload bytes, range 132..65,507), bounded
by route PMTU with fragmentation disabled and `EMSGSIZE` re-batching of unsent
records. IPFIX sends separate initial/periodic templates (600 seconds or 20
data datagrams), not templates in every data message. See the
[receiver requirements](docs/IPFIX_RECEIVER_SPEC.md) and
[frontend contract](FRONTEND_SPEC.md#69-softflowd).

**Overall firewall dropped packets and bytes** sum the managed input/forward
DROP rules and default policies, using exact kernel counters rather than sampled
deny logs. These reset with the installed counter generation; unavailable or
simulated measurements are unknown, not zero. Per-rule sensors, raw connection/
route/host inventories, packet logs and traffic-history records are not published.
Aggregate rule-match totals are also available, but are not unique traffic
totals: one packet can match several accepting/bypass/NAT rules.
Source-readability flags distinguish partial samples from healthy zero readings.
Discovery/state remain capped at 4096 entities and 1 MiB each; exceeding limits
fails collection explicitly. The exact contract below specifies family limits.

MQTT is telemetry-only. Linux host mode is required; simulator makes no
connection and namespace lab mode rejects enabled streaming. Binding fails closed;
hostname resolution still uses the host resolver, not the selected interface.
The connection stays open between samples and retries failures every five seconds
while enabled. If outstanding QoS-1 publications make no acknowledgement progress
for 30 seconds, the publisher reconnects and sends fresh discovery/state; it does
not replay an offline sample backlog.

For reconnect debugging, read `GET /api/v1/services/mqtt/status`. It includes a
specific safe `error`, `connection_attempts`, `reconnect_count`,
`last_connected_at_unix`, and retained `last_failure` with `category`, `message`,
`at_unix` and nullable `os_error_code`. Failure history survives retries and
recovery; these in-memory diagnostics reset when the daemon process restarts.
The retry count includes failed initial connections, not just established
connections lost. `last_connected_at_unix` means broker CONNACK; only
`last_published_at_unix` proves acknowledgment of a telemetry batch.
On systemd installations use `journalctl -u netcontrold --since "15 minutes ago"
--no-pager` for matching safe warnings. No credential/endpoint/raw packet text is
logged by these warnings. Correlate close/reset or acknowledgment timeouts with
broker logs; those symptoms alone cannot identify ACL rejection or duplicate IDs.

Prefer `mqtts://` (port 8883), with a system-trusted certificate and matching
hostname. Explicit `mqtt://` (1883) sends credentials/data without TLS. Endpoint
URLs must not contain credentials, paths other than `/`, query or fragment.
Broker ACLs must allow retained discovery publication at
`homeassistant/device/netcontrol_<device_id>/config`, publication under
`netcontrol/<device_id>/#`, and subscription to `homeassistant/status`. Discovery
and availability are retained; samples are not. QoS 1 can duplicate messages.

Discovery is one retained Home Assistant device message with all sensor
`components` and a shared `state_topic`. Each sample is one complete JSON message
at `netcontrol/<device_id>/state`: `collected_at_unix`, all `metrics`, health,
alerts, BGP, link diagnostics and source status. No metric shards or separate
section topics are published. Each discovery/state payload allows up to **32 MiB
(33,554,432 serialized UTF-8 bytes)**; the entity limit remains 4096. Oversized
samples fail explicitly without truncation or partial enqueue.

The broker must accept that payload size and MQTT packet overhead. If configured,
raise broker payload limits to at least 33,554,432 bytes and packet limits to at
least 33,558,528 bytes (32 MiB + 4096); for Mosquitto these are
`message_size_limit` and `max_packet_size`. Review broker/subscriber memory budgets.
The daemon increases its outbound limit, not broker configuration or the 1 MiB
inbound limit. PUBACK proves broker acknowledgment, not Home Assistant ingestion.

This supersedes the split-topic contract. Stop/disable the publisher before
deployment, update ACLs/subscriptions and have the broker administrator clear each
retained `homeassistant/sensor/netcontrol_<device_id>/<component_id>/config`
message with an empty retained payload before enabling device discovery. Publish
to each exact topic, not an MQTT wildcard. Do not clear the new device-discovery
topic. No dual publication or automatic retained-topic conversion is provided.
Device identity, entity unique IDs, saved configuration and secrets are retained.
Home Assistant entity-registry/customization continuity requires deployment
acceptance; it is not guaranteed by preserving unique IDs alone.
Consolidation does not invent unavailable source measurements; null/missing
metrics and expired samples still appear unknown/unavailable as appropriate.

Back up `<state>.mqtt` together with the journal (default
`/var/lib/netcontrol/native-state.json.mqtt`). Its daemon-owned private files hold
stable device identity, password references and the discovery manifest. Preserve
ownership/permissions; never clone this identity to another active appliance.
Discovery component IDs preserve ASCII letter case, including kernel protocol
counter names. Manifest reads and writes share ID/count validation and a 1 MiB
file limit; valid generated mixed-case IDs no longer break subsequent samples
or daemon startup. Do not delete the private store as a reconnect workaround.
Passwords are plaintext at rest in owner-only files, not encrypted. References
are immutable and retained for revisions; limit 256 passwords. There is no pruning
or deletion API: do not remove files referenced by configuration/history. Missing
or corrupt private state requires operator recovery, not an identity reset.
See the [exact contract](FRONTEND_SPEC.md#614-home-assistant-mqtt-streaming).

## Host name and time zone

`config.system` holds an optional `hostname`, an optional IANA `timezone` and a
display/reporting `domain`; empty means unmanaged/no domain (the default). The
`domain` supplies the vnStat collector name suffix and can be shown by clients;
it is never applied to the host and never becomes a DNS search domain. Changes use the ordinary confirmed transaction flow
with `transactions.write` plus `system.write`, but the daemon applies them itself
after confirmation, like MQTT: the network is not touched and a rolled-back
transaction never changes the host. Linux host mode sets the kernel hostname and
`/etc/hostname` and replaces `/etc/localtime` with a link to the zone file (the host
must have its timezone database, normally the `tzdata` package; nothing is installed).
Values are applied and verified at daemon/manager startup and when the confirmed
value changes; failed attempts retry after 30 seconds. Successful settings are
not continuously polled or reclaimed after external changes. Clearing a value
stops managing it and does not revert the
host. `/etc/hosts` is not edited, and processes started earlier may keep the old time
zone until restarted. The simulator and namespace lab perform no host changes.

`GET /api/v1/system/status` and `GET /api/v1/system/timezones` (`state.read`) report
the confirmed values, their last apply-time observations and the valid zone names. CLI:
`hostname NAME`, `domain NAME`, `timezone ZONE`, `no hostname`, `no domain`, `no timezone`. DNS resolvers are not
part of this section: use the per-interface `dns` settings. See the
[exact contract](FRONTEND_SPEC.md#616-host-name-and-time-zone).

## Configuration workflow

### Host health

`GET /api/v1/statistics` (CLI `show statistics`) includes a top-level `uptime`
object with host seconds since boot and summed CPU idle seconds. It uses the
daemon-visible `/proc/uptime`, not process runtime or a lab network namespace.
Source failures mark the aggregate partial with explicit unavailable/null uptime;
the simulator never measures the development host.

`GET /api/v1/statistics/host` (`state.read`) reads Linux CPU ticks/scheduler,
memory/swap, load/uptime, VM/OOM counters, pressure stalls, disk I/O, local
filesystem space/inodes and thermal/hwmon temperatures/fans in-process.
CLI: `show statistics host`. Missing features/sensor faults are explicit
per-source errors, never zero measurements. Counters are exact decimal strings;
CPU utilization and I/O rates need two samples. No configuration changes,
external sensor programs, drivers, stored history or additional host-service
permission. This uses the daemon-visible host/procfs/mount context, not a
network lab namespace or cgroup limits. Simulator data is unmeasured.
See the [host-health contract](FRONTEND_SPEC.md#host-health-sensors) for fields,
units, filesystem exclusions, rate calculations and frontend requirements.

### Routing scope

User-configurable source-policy routing is unsupported. Omit `policy_rules`
from configuration; it has no effect (a submitted `policy_rules` key is dropped
and reported in `ignored_fields`). There is no
`/api/v1/policy-rules` endpoint, `policy.write` grant or `policy-rule` CLI command.
Ordinary destination routes accept an `enabled` boolean (omission defaults to true); disabled
records stay saved but are not installed. Use table 254 (main) for normal traffic.
An enabled explicit gateway monitor requires a matching enabled route. See the
[route contract](FRONTEND_SPEC.md#64-routes). A single optional `blackhole` section
(`name`, plus `action` of `blackhole`, `unreachable` or `prohibit`) lets any number
of routes use that name as their `interface` to drop matching traffic in the
routing decision; it is a deviceless kernel route, not a link. Saved routes without the field load
as enabled. Enabled gateway monitors retain backend-managed host-source rules for
their explicit routing tables. Monitors sharing a source must share a table;
these internal rules affect all traffic from that exact source, not only probes.
DHCPv4 monitors instead use `mode: "dhcp"`, interface and target without pinned
source/gateway/table. They follow only that interface's active lease, wait with
Unknown health before acquisition, and never fall back to another WAN. Private
interface-scoped paths are runtime-owned, not editable routes. Explicit IPv4/IPv6
monitors are unchanged. See the [monitor contract](FRONTEND_SPEC.md#612-gateway-health-and-rtt-variation).
Host appliance monitoring requires host-service and gateway-probe permission.
The install and upgrade scripts enable both automatically through a managed
systemd environment drop-in, preserving customized startup arguments. See
[installed-appliance setup](docs/BUILD_AND_INSTALL.md#enabling-gateway-monitoring-on-an-installed-appliance).
See [the routing contract](FRONTEND_SPEC.md#65-source-policy-routing).

### Global IPv6 policy

The top-level `ipv6_enabled` boolean defaults to `false`, including fresh
installation and factory configuration. Set `"ipv6_enabled": true` in the
complete configuration submitted through the normal confirmed transaction
workflow to enable IPv6, or stage `ipv6 enable` in the configuration CLI. Changing it requires
`kernel.namespace.write` as well as `transactions.write`.

On Linux, disabling writes and verifies `net.ipv6.conf.default.disable_ipv6=1`,
`net.ipv6.conf.all.disable_ipv6=1` and every existing interface's `disable_ipv6`,
including loopback and unmanaged links. New interfaces inherit the disabled
default. The scope is the daemon's managed network namespace (the appliance
host in normal installations). Re-enabling sets these controls to `0` before
restoring configured IPv6 networking; it does not enable IPv6 forwarding.

Remove IPv6 addresses, routes, policy/firewall/NAT references, DNS/server
literals, WireGuard endpoints/allowed prefixes, monitors and exporter collectors/
IPv6-only filters from the same candidate before disabling. Conflicts return
validation errors rather than silently dropping configuration. Service hostname
resolution becomes IPv4-only and flow exporters exclude IPv6. Runtime reports
the desired switch and observed controls under `ipv6`; simulator values are
explicitly unmeasured.

IPv6 management sessions will disconnect: apply over IPv4 with independent
console access and explicitly confirm or roll back. Saved policy is reapplied
on daemon startup/reboot; this does not change bootloader arguments, unload IPv6,
or disable it before the daemon starts. Missing kernel controls or required
writes to read-only sysctls fail explicitly. Same-boot rollback/re-enable restores captured unmanaged IPv6
addresses/routes without extending finite lifetimes; stale prior-boot snapshots
are not resurrected. See the [frontend contract](FRONTEND_SPEC.md#global-ipv6-policy).

### Editing configuration

Configuration resources support optional `metadata.display_name` and
`metadata.description`, including Ethernet/VLAN/WireGuard interfaces, peers,
routes, policies, firewall/NAT rules, DHCP/DNS settings and service instances.
These annotations are persisted with the normal transaction/revision workflow;
they never replace technical identifiers or interface references. See the
[metadata contract](FRONTEND_SPEC.md#14-descriptive-object-metadata) and
[labelled VLAN example](examples/vlan-softflowd.json).

Networking changes use a full configuration package, not independent resource
edits:

1. Read desired configuration, revision, runtime, and live observation.
2. Submit a candidate against the current base revision with a confirmation
   timeout.
3. Inspect the provisional live result and verify independent management
   connectivity.
4. Confirm explicitly or roll back. Timeout and interrupted-operation recovery
   must retain the previous valid configuration.

Do not treat `202 Accepted` as a committed revision. An uncertain HTTP write
must be reconciled through transaction reads, not blindly retried.
Managed interfaces require an explicit `wan`, `lan`, or `unassigned` role; roles do not automatically
rewrite policy. The Ubuntu appliance installer sets those roles and a static
LAN address while retaining imported supported policy. Explicit factory reset
installs factory LAN-to-WAN forwarding/masquerade and enables `firewall.allow_all_icmp`, accepting
all IPv4 ICMP to/from/through the appliance, including WAN, before managed drops.
Ordinary startup and upgrades preserve the saved setting. Installed
appliance mode enables host IPv4 forwarding after native policy reconciliation
on every startup; changing roles through the API does not regenerate policy.

During explicit first-install provisioning, a new or untouched empty revision-zero
journal captures supported interfaces, addresses/routes, MTU, administrative
state, DHCPv4, DNS and firewall policy before mutation. Initial installation
retains that import, disables unsupported networking and masks competing owners.
It uses console-only commitment/recovery, not a connectivity timer. Netcontrold does not
guess WAN/LAN, reset configured journals, or copy DHCP addresses as static ones.
The installer provisions and starts the appliance. Ordinary native startup and
`upgrade.sh` use the saved configuration; they do not inherit live settings.
Startup reconciles managed interfaces to that saved plan. Temporary recovery
addresses are not saved configuration and can be removed during reconciliation.

Use `sudo bash reset.sh` from a local console and confirm the prompt to replace
current networking with factory WAN/LAN defaults. `--yes` skips confirmation for
unattended use. Optional paired `--wan`/`--lan` overrides select
ports. Reset backs up state and preserves credentials, keys and revision history;
it does not delete journals or reconstruct desired settings from the live NICs.
See [factory reset](docs/BUILD_AND_INSTALL.md#factory-configuration-reset).

This implementation requires systemd/systemd-resolved and root network/BPF
administration. DHCP clients can be inherited without a lease, including active
NetworkManager sources. Initial takeover keeps DHCPv4 but excludes IPv6
addresses, routes and DNS servers, and disables IPv6 during startup reconciliation.
It does not turn DHCPv6/SLAAC addresses into static addresses. Bridged/bonded
topology, custom policy routing and unimportable manager features are disabled,
not preserved as external owners. Existing Wi-Fi association remains with its
supplicant. DHCP runs in Rust, with durable leases and owned routes, not a
supervised external client. See the [handover prerequisites and acceptance
limits](docs/BUILD_AND_INSTALL.md#automatic-physical-interface-inheritance).

Discovery remains read-only: `GET /api/v1/interfaces/discovered` inventories live
links, while `GET /api/v1/interfaces` returns managed configuration. DHCP settings
and static DNS are stored in top-level `dhcp_clients` and `dns` maps; active leases
are separate in `GET /api/v1/runtime` under `dhcp_clients`. There is no DNS server.
Routes may target main table `254` or reserved tables `10000..19999`.

The [frontend contract](FRONTEND_SPEC.md) records API fields, endpoints,
permissions and workflow. The Rust rewrite changes persisted implementation and
service lifecycle; see its current implementation notes and handoff before
using historical examples.

## Install on Ubuntu

An Ubuntu amd64 [prebuilt installer](install.sh) downloads verified binaries
from the latest published stable GitHub Release. No Rust/compiler installation,
GitHub login, CI run ID or manual workflow dispatch is needed on the firewall.
Transient downloads retry automatically; the version-pinned binary resumes
within the same installer run, with longer bounded timeouts for slow links.
See the [download command and prerequisites](docs/BUILD_AND_INSTALL.md#ubuntu-prebuilt-installation-amd64).
From a local terminal, it walks through all Ethernet ports and VLANs, WAN/LAN
roles, DHCP/static IPv4, WAN gateway/DNS and the management LAN before takeover:

```sh
curl --proto '=https' --tlsv1.2 -fL https://raw.githubusercontent.com/mayberryjp/firewall_backend/main/install.sh -o /tmp/netcontrol-install.sh
# Inspect the downloaded script before running it as root.
sudo bash /tmp/netcontrol-install.sh
```

The installer selects one stable version, verifies its manifest, binary size,
SHA-256, amd64 ELF header and compiled version, and fetches its systemd unit from
the same release tag. Downloads use verified HTTPS; Ubuntu release assets are
unsigned, unlike `.ncpkg` packages. Missing or invalid releases fail explicitly.
No WAN is selected silently. Review every physical Ethernet port and existing
802.1Q VLAN; create additional VLANs by name, parent and ID (1..4094), including
tagged WAN/LAN on a single shared trunk and nested VLANs. Choose exactly one WAN
and one or more trusted LANs. Each assigned link uses DHCPv4 or static IPv4;
unassigned ports have no IP and can serve as VLAN parents. Static WAN requires
an on-link gateway and DNS servers. Select a private static management LAN,
then review the complete plan and explicitly confirm. EOF or declining cancels.
For unattended use supply `--network-plan FILE --yes`; the old installer
`--wan`/`--lan`/`--lan-address` flags are not accepted. See the
[plan schema and example](docs/BUILD_AND_INSTALL.md#installer-network-plan).
Console-only takeover captures supported host networking for ownership/recovery,
then replaces addressing, routes, DNS and firewall with the reviewed plan.
No lease/connectivity timer gates commitment.
Unsupported topology/routes/policy/firewall/traffic control and known competing
managers are disabled, not left active or used as reasons to refuse discovery.
IPv6 is disabled by default. Private capture and explicit runtime takeover
status support interruption/retry, not automatic connectivity rollback.
The installer enables/starts the service and binds HTTP to the management LAN.
The starter firewall trusts all selected LANs for router access, allows new
forwarding only from LAN to WAN, and masquerades IPv4 on WAN. Unsolicited WAN
input/forwarding is dropped, except DHCP replies; established/related replies
and loopback remain implicit. There is no inter-LAN forwarding allowance or
global ICMP bypass. Explicit factory reset remains separate.
Existing appliance state is not reset.
The packaged systemd service starts without waiting for `network-online.target`.
Installation and full source upgrades persistently mask
`systemd-networkd-wait-online.service` to avoid its boot timeout; this does not
disable networkd itself or guarantee WAN connectivity at startup. See the
[boot-wait operator guidance](docs/BUILD_AND_INSTALL.md#network-online-boot-wait).
LAN clients need their own addressing, DNS and the appliance as their gateway;
no LAN DHCP or DNS server is installed. IPv6 forwarding is not enabled.
Use console access during provisioning. See the
[service commands](docs/BUILD_AND_INSTALL.md#ubuntu-systemd-service). The GitHub
download command uses the installer currently published on `main`; local script
edits are not available there until an authorized push. Initial internet
addressing, gateway and DNS must work before downloading/installing.

## Startup durability and boot diagnostics

Saved timestamps describe observed UTC wall-clock values, not a reliable ordering
of events. Archived rollback records may predate journal initialization, and a
same-day clock correction may put confirmation before submission. Neither
invalidates an otherwise intact journal. Configuration validation, checksums,
ownership, revision chains and rollback invariants remain strict; history is
not re-dated, deleted or reset. Correcting UTC backward does not block editing:
new configuration revisions increment the saved date's iteration until real UTC
passes that date, then start iteration 1 on the newer day. Commit timestamps use
actual corrected UTC; revision dates are a monotonic high-water mark, not proof
of the commit's wall-clock date. Iteration exhaustion still fails explicitly.
Software build versions retain their separate strict Git-history clock checks.

Daily traffic exports also resume at the corrected local 23:59 despite a
future-dated last-report marker, without resetting accounting/history. Re-entering
a date after another clock change can repeat an export; unchanged-date restart
does not. Host-experience timing still quarantines ambiguous pre-correction
samples and temporarily rejects hourly summaries across a clock discontinuity.
It recovers after its rolling-hour discontinuity window, not after waiting for
the formerly incorrect calendar date.

Confirmation is bounded by both the saved UTC deadline and a process-monotonic
timer. Restart reconstructs the remaining budget, capped at the original
10..300 seconds; it cannot recover elapsed monotonic time across a reboot.
Clock corrections do not rewrite the displayed UTC deadline. Server transaction
state, not a browser countdown, is authoritative.

Networking reconciliation detects a same-parent/tag VLAN under a conflicting
name before removing managed routes/rules. It identifies both names and refuses
to rename/delete an unowned link. Resolve actual ownership from console or an
SSH-independent recovery job; never delete the active management VLAN as a
guess. This is not automatic adoption or a promise of interruption-free apply.

Full Ubuntu installation/source upgrade now enables persistent journald storage,
with a 128 MiB disk-use target, 256 MiB keep-free reserve, 32 MiB runtime target
and seven-day retention, and explicitly flushes the current boot. Operator
overrides and disk pressure can limit retention. HTTPS binary-only upgrades do
not install that policy. See [host logging](docs/BUILD_AND_INSTALL.md#host-logging-ownership).
Check retained boots and private host evidence after an incident:

```sh
journalctl --list-boots --no-pager; journalctl -k -b -1 --no-pager; journalctl -u netcontrold -b -1 -n 100 --no-pager
```

If the prior boot is absent, do not infer a crash cause. Check current-boot kernel
messages, firmware-supported `/sys/fs/pstore`, and the separately retained
[daemon/socket history](FRONTEND_SPEC.md#persistent-log-viewing-apis).
Redact sensitive details before sharing. A daemon/watchdog failure, loss of
management forwarding, OOM event and kernel hang need different evidence.
The reported overnight failures are not diagnosed or proven fixed by these
startup changes.

## Install on Alpine

Use the [native build and installation guide](docs/BUILD_AND_INSTALL.md).
Packages contain static musl binaries for x86-64 or ARM64, an OpenRC unit, and
operator configuration. Installation uses the Rust package tool, not APK/abuild.
Packages are Ed25519-signed and verified before installation; the installer
has explicit ownership checks and durable rollback information.

The installed package selects native Linux host mode with HTTP on
`0.0.0.0:8080`; the bare daemon's development default remains simulator mode.
The installer does not configure a LAN address, enable the service at boot
or start routing. Discovery does not take ownership of every interface.
Do not delete configuration, credentials or history to work around startup
failures. Preserve console access while changing host management networking.

## Native mDNS discovery across LANs

The in-process Rust mDNS/DNS-SD worker reflects discovery across explicitly
selected managed Ethernet/VLAN LAN interfaces, with service/provider filters,
IPv4/IPv6 controls and opt-in appliance publishing. It defaults **disabled**.
No Avahi daemon, external helper, D-Bus service or general multicast router is
used. Enable through the normal full-configuration/confirmed transaction flow;
`mdns.write` is required.

Read committed settings at `GET /api/v1/services/mdns` and applied worker state
at `GET /api/v1/services/mdns/status`. Bodyless
`POST /api/v1/services/mdns/reconcile` uses the existing all-service repair
permissions. Restrictive host-input policy needs explicit UDP 5353 permits;
the worker opens no firewall holes. Discovery does not grant access to a
printer/casting service, make IPv6 link-local addresses routable, or forward
SSDP/media traffic. Use only one active reflector per connected domain.

Status includes per-reflection-filter matched/forwarded packet counters and
last-match/last-send timestamps alongside the service totals. Counts are exact
decimal strings, reset on each worker run and do not prove remote delivery;
appliance publishing is excluded. See the
[counter handoff](docs/frontend-handoffs/2026-11-01.md#2026-11-01-01-mdns-and-udp-relay-entry-usage-counters)
for the mDNS shape and existing per-instance UDP relay counters.

See the [current frontend contract](FRONTEND_SPEC.md#617-native-mdns--dns-sd),
[build and qualification spec](docs/MDNS_SPEC.md) and
[synthetic example](examples/mdns.json). The example is not a safe replacement
for an existing appliance's complete configuration. Namespace wire tests do
not establish device interoperability, production load or reboot acceptance.

## Configuration CLI over SSH

The daemon includes a Cisco-inspired CLI and an in-process Rust SSH server.
Ubuntu `install.sh` and full `upgrade.sh` runs enable it by default on
`127.0.0.1:2222` (localhost only); no separate system `sshd` is required or launched. For a manual
daemon invocation, enable it explicitly:

```sh
netcontrold --state state.json --credential-db credentials.json \
  --ssh-listen 127.0.0.1:2222
ssh -p 2222 apikey@127.0.0.1
```

Use the literal username `apikey` and your existing **API key** at the password
prompt. Account passwords are not networking credentials. The persistent
Ed25519 host key defaults to `<state>.ssh-key`; preserve it and verify the host
fingerprint. Manual invocations remain disabled unless `--ssh-listen` or
`NETCONTROL_SSH_LISTEN` is provided; the explicit flag takes precedence.
The managed default is not reachable through LAN/WAN addresses. Full upgrades
replace the managed wildcard default with loopback; build-only upgrades do not.
Explicit operator overrides remain effective and require host-input exposure
review; the script does not add firewall exceptions.
See [deployment overrides](docs/BUILD_AND_INSTALL.md#optional-configuration-ssh-server)
for a custom address or explicit disable.

For browser-free setup on the running Linux host daemon, use a root console:
`sudo netcontrold --create-api-key console`, then
`ssh -p 2222 apikey@127.0.0.1`. A fresh device prompts for a username and hidden
account password; the command saves the account/key and finishes onboarding
atomically. Existing account passwords are preserved. Save the API key displayed
once and use it as the SSH password. This uses a root-only local Unix socket,
not a shared default password; it requires the updated running daemon and a
terminal. See [local key setup](docs/CLI.md#browser-free-local-key-creation)
for pending-onboarding effects, socket requirements and failure handling.

Use `enable`, `configure terminal`, interface/global configuration commands,
`compare`, and `commit check`. `commit confirmed 60` applies the private
candidate through the same transaction engine as HTTP; verify connectivity,
then `confirm`. Disconnect never confirms a pending transaction. Revisions,
permissions, rollback, timeout and conflicts are shared with the API.

See the [CLI operator guide](docs/CLI.md) for syntax, JSON-pointer editing of the
complete schema, host keys, authentication, recovery and limitations.

## Current limits and distribution review

The native protocol implementations have explicit boundaries: flow filters are
limited to empty/ip/ip6/tcp/udp/icmp/icmp6 and exclude fragments; NTP immediately
steps the whole host clock to the lowest-delay valid configured server sample
on startup and every 24 hours after a completed polling round, without a
correction-size cap. Manual Force sync reuses the targeted restart API:
`POST /api/v1/processes/restart` with `{"target":"ntp"}` (`system.restart`).
It triggers an immediate fresh poll and resets the daily wait; inspect
`GET /api/v1/services/ntp/status` for its result, not just the restart response.
Forward/backward jumps affect timestamps and time-based expiry; there is no
NTS or server consensus. Syslog has no durable
forwarding queue or automatic reconnect; traffic history is per-sample, not
calendar aggregation. See the [native service contract](crates/netcontrol-services/README.md).
No DHCP/DNS server or DHCPv6 relay is provided.

The native backend links GPL-3.0-or-later `rustables`. No project distribution
license has been assigned. Review combined-work licensing, notices and
corresponding-source obligations before distributing binaries, including before
pushing the workflow that activates automatic public Ubuntu releases. The user
has authorized automatic Ubuntu update publication; that is not a licensing
review or a new project license. Separate signed development-package and
prebuilt-installer artifact uploads still require manual opt-in.

## Change memory and frontend coordination

- [Unreleased changes](CHANGELOG.md)
- [Daily journal](docs/journal/2026-10-19.md)
- [Latest frontend handoff](docs/frontend-handoffs/2026-10-19.md)
- [Rust cutover handoff](docs/frontend-handoffs/2026-10-18.md)
- [Repository development instructions](.github/copilot-instructions.md)

The commit-version seed is not proof of publication. Cargo workspace version
`0.0.0` remains internal development metadata. Only actual GitHub Releases
establish publication; a local build, test or journal entry does not prove CI
ran, code was pushed, a device was upgraded or a frontend handoff was delivered.
