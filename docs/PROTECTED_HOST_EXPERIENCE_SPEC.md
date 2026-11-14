# Protected-host network experience - implemented contract and acceptance scope

Date: 2026-11-14. **Status: implemented, unreleased.** Collection, typed SQLite
storage, passive analysis/scoring and HTTP APIs are integrated. No frontend UI,
deployment, publication or physical-appliance performance certification is
implied. Measured resource revisions below supersede the original proposal.

The [frontend contract](../FRONTEND_SPEC.md#16-protected-host-network-experience)
defines the client requirements. UniFi's supplied
client table is a presentation reference, not a source of measurement semantics,
assets or a claimed reproduction of its proprietary experience algorithm.

## 1. Goal and agreed scope

Provide a read-only, firewall-observed experience dashboard for **explicitly
configured firewall hosts behind managed LAN interfaces**. Continuously observe
their traffic, finalize one snapshot every **10 seconds**, and retain at most
**one hour** in a private SQLite database. Each configured IP gets its own series,
including separate IPv4 and IPv6 rows belonging to the same configured host.

Confirmed during scoping:

- Eligibility comes from configured firewall hosts (`firewall.policies.hosts`
  in saved core configuration; `/api/v1/firewall/hosts`), not every observed LAN client
  or every Sando inventory entry.
- Public identity is the canonical IP address, **not interface-plus-IP**.
  Derive and return the host's LAN interface, such as `vlan20` or `vlan40`.
- Observe DNS/TCP exchanges passively in the host's traffic through the firewall;
  do not substitute router-local socket statistics or generate diagnostic probes.
- Deliver backend collection, retention, scoring and APIs; frontend table
  and graph implementation is outside this backend work.

### In scope for the complete v1 implementation

- Host-perspective sent/received packet and byte interval counters and rates.
- Managed firewall drops attributable to the host, with direction and coverage.
- Current tracked connection counts.
- Observed TCP repeated data/retransmission evidence, receive-window changes,
  zero-window pressure, passive data/ACK timing and RTT variation.
- Passive ordinary DNS request/response time, response errors and observed
  unanswered requests, including bounded DNS-over-TCP parsing.
- Last observed traffic, current activity state, derived LAN interface.
- Exact-address Sando icon and local description, alongside configured host name.
- Explainable per-snapshot experience level, score, confidence and reason codes.
- A latest table API and a full retained per-IP history API, both authenticated.
- Explicit measurement gaps, unsupported traffic, reset epochs and health errors.

### Not in scope

Active ping/DNS/HTTP tests, Wi-Fi/AP/controller integration, RSSI, radio retries,
channel/technology/PHY rate, vendor inference, device OS/application uptime,
RTP/one-way jitter, application payload logging, TLS decryption, DNS domain
history, browsing history, threat scoring, automatic tuning/blocking, traffic
shaping, MQTT/Home Assistant entities, push/WebSocket delivery, host merging by
MAC/name, or retention beyond an hour. Unobserved same-LAN switched traffic is
not included. No external Go, packet-analysis or collector process is supervised.

## 2. Evidence from the current repository

The implementation reuses these verified mechanisms and respects their limits:

| Current component | Useful mechanism | Boundary requiring new work |
| --- | --- | --- |
| [Firewall host validation](../crates/netcontrol-core/src/model.rs) | At most 128 host objects, 1..16 globally unique canonical unicast addresses each | At most 2048 configured IPs; host objects have no stored interface association |
| [Conntrack decoder](../crates/netcontrol-native/src/conntrack.rs) and [query types](../crates/netcontrol-core/src/connections.rs) | Original/reply tuples, zones, NAT flags, protocol state, nullable directional accounting; bounded full dump | Ten-second snapshots miss expired/short-lived connections and cannot recover their packet/byte totals |
| [Link diagnostics](../crates/netcontrol-native/src/linux/link_monitor.rs) and [TCP parser](../crates/netcontrol-native/src/link_monitor.rs) | Rust packet sockets, kernel filters, bounded receive rounds, header/window tracking, loss reporting and joined shutdown | Local TCP_INFO covers router-terminated sockets only; current packet capture excludes outgoing copies and direct UDP, does not expose per-host timing/retransmission history |
| [Flow worker](../crates/netcontrol-services/src/flow.rs) | IP/VLAN parsing, directed keys, bounded ordered expiry and counters | Optional/sampled exporter instances are not complete host traffic accounting or a dashboard database |
| [Sando manager](../crates/netcontrold/src/sando.rs) | Cached exact-IP icon and `classification` projection, source-match and unavailable semantics | Local description is free text, not a device-type enum; cache lookup must be shared/typed, not another upstream fetch every tick |
| [Deny history store](../crates/netcontrol-native/src/linux/deny_log/store.rs) | Private SQLite ownership, schema and integrity checks | Drop history is bounded/rate-limited, and permanent first-seen deduplication is unsuitable for full drop counts or one-hour retention |
| [DNS lookup worker](../crates/netcontrol-services/src/dns_lookup.rs) | Bounded DNS decoding/validation concepts | Existing API generates a diagnostic query; it is not passive per-client DNS timing |

The [monitoring-efficiency work](journal/2026-11-12.md#bound-monitoring-work-and-batch-traffic-checkpoints)
is an important constraint: do not undo kernel filtering, recreate full-table
cloning/expiry work, write per packet, or duplicate whole-interface capture just
to publish every ten seconds. No cause of the previously reported voice
interruptions was established.

## 3. Eligibility, interface derivation and identity

### 3.1 Membership

Read the committed configured host address set and live managed interfaces with
`role:"lan"`. An address is eligible when it has a unique supported LAN attachment:

1. Prefer validated actual observations on the logical LAN link and an existing
   route/neighbor attachment consistent with that link.
2. For an idle configured address, use a unique directly connected LAN subnet or
   validated on-link route. Do not infer LAN membership from private IP ranges,
   interface-name prefixes or Sando metadata.
3. Exclude WAN, unassigned, unmanaged and firewall-owned addresses. Routed hosts
   beyond another router, nested networks without direct attachment evidence and
   ambiguous/unresolved attachments remain unmapped for v1.

IPv6 uses canonical address matching and on-link evidence, not IPv4-style
subnet/broadcast guesses. Collection follows actual logical VLAN interfaces;
never attribute a tagged host to its physical parent merely because a capture
also exists there.

The product assumes one derived interface per IP. When evidence cannot establish
it, report an unmapped-address diagnostic rather than inventing a network or
merging conflicting observations. This does not add a new interface-qualified API
identity or change existing firewall configuration validation.

### 3.2 Identity and changes

- API identity: canonical `ip_address`; address family is explicit.
- `configured_host_id` and `configured_name` identify the configured host, not
  a physical device inferred from its address.
- `observation_epoch`: opaque string changing on collector restart, interface
  identity replacement, address reassignment to another host, or counter reset.
  Never subtract baselines or correlate TCP/DNS state across epochs.
- An interface move keeps the same IP series; each sample records its actual
  interface, host/configuration identity and epoch so the move is visible.
- Latest lists only currently eligible configured IPs. Retained history for an
  address that was removed is readable until natural expiry; mark its top-level
  `currently_protected:false`. Do not silently transfer its old observations to a
  newly configured host using that IP.
- Host edits/removal stop new collection for affected membership; they do not
  delete retained rows outside the one-hour retention policy.
- During provisional configuration/rollback/recovery, pause affected attribution,
  clear affected transport baselines and record a gap. Do not publish candidate
  metadata as committed. History and unaffected evidence are preserved.

### 3.3 Metadata

Return `configured_name` separately from Sando `host_name`, `icon` and
`classification`. `classification` is the original-case nullable
`local_description`, **not** an inferred category/type. `icon` is a nullable
identifier for the frontend's existing supported icon mapping; unknown/null
icons use a generic frontend icon without changing the API value.

Reuse Sando's exact-IP, current-source cache semantics and string limits:
host name <=255 UTF-8 bytes, icon <=128, classification <=512, no control
characters. No match returns null metadata, not an invented device name/type.
Return `metadata.status:"available"|"unavailable"|"stale"` and nullable
`last_success_at`/`error`. Last successful current-source metadata can enrich
the row during a sync error with explicit stale status; another source's cache
must never appear as current metadata.
Metadata is stale when its current-source sync reports an error or its last
successful snapshot is older than two hours (two normal sync periods); absence
of a successful exact-IP match yields unavailable metadata. These are freshness
rules, not new Sando acquisition/retry behavior.

API table metadata is current at the captured response snapshot. History samples
record host ID/interface/revision/epoch but do not duplicate icon/description
strings every ten seconds or pretend current descriptions are historical.

## 4. Observation and attribution architecture

Kernel-side per-IP counters at logical LAN boundaries feed a filtered, bounded
passive TCP/DNS observer and a separate SQLite writer. A separate bounded
conntrack worker streams one inventory rather than retaining its full payload.
Current code: [observer/lifecycle/API reads](../crates/netcontrol-native/src/linux/experience.rs),
[kernel accounting](../crates/netcontrol-native/src/linux/experience_kernel.rs),
[passive analysis](../crates/netcontrol-native/src/experience_analysis.rs).

### 4.1 Base traffic counters

The owned `inet netcontrol_experience` table uses interface/IP eligibility sets,
dynamic counter/last-expression sets and dedicated accounting chains:

- Sent/upload: eligible host-source traffic arriving on its derived LAN
  interface, before source NAT. Includes attempts later dropped by the firewall.
- Received/download: traffic destined to the host at LAN egress after applicable
  destination/reverse NAT and managed filtering. This is the firewall's attempted
  delivery, not proof the endpoint received it.
- Record all supported IP protocols, including fragments, for basic counters
  even when transport analysis cannot decode them.
- Provide per-IP last-activity timestamps from the same boundary accounting,
  including non-TCP/non-DNS traffic. Kernel `last` expression ages provide
  activity timing; idle counters preserve the prior timestamp instead of
  advancing it with subsequent polls.
  A changed ten-second byte counter cannot justify inventing the exact packet
  timestamp; do not stamp snapshot time as actual `last_seen_at`.
- Count each traversal once per host/direction on the logical LAN boundary.
  Do not also count the WAN, physical VLAN parent, tunnel outer packet or a
  second capture copy. Routed LAN-to-LAN traffic legitimately contributes to
  source sent and destination received; summing host rows is not unique appliance
  traffic.
- Router-local LAN DNS/management exchanges may contribute to basic boundary
  counters; the transport measurement describes the observed client exchange,
  not router-local TCP_INFO. Pure firewall-originated traffic is not assigned
  to a protected host as upload.
- IP-layer counters exclude Ethernet overhead. Offloads can change observed
  packet granularity; expose `packet_unit:"kernel_l3_packet"` and
  `byte_unit:"ip_layer_bytes"`. Do not claim physical wire packets or goodput.

Keep telemetry accounting ownership independent of numeric drift and ordinary
policy rebuilds where safely possible. Changes must preserve firewall verdicts,
NAT, rule order, recovery and rollback. Counters that reset within a bucket
produce null deltas/gap reasons, never a huge subtraction or a guessed zero.
No per-host full conntrack dumps and no per-packet database writes.

### 4.2 Firewall drops

Instrument **managed terminal drop paths** with per-host counter attribution;
reuse kernel rule-generation/accounting patterns. This includes configured
host/interface/input/default-policy drops, not just explicit host-rule hits.
Count a terminal decision once, including established return paths when dropped.
Assign sent attempts to the eligible source and received attempts to the eligible
destination using logical interface and validated NAT/conntrack context.
For an attributable LAN-to-LAN drop, both endpoint perspectives can have a drop
observation; do not sum them as unique dropped packets.

Expose `dropped_sent_packets`, `dropped_received_packets`,
`dropped_unattributed_packets` in collector diagnostics and
`drop_coverage:"managed_nftables_only"`. RPF, NIC/qdisc loss, foreign policies,
upstream loss and packets absent from the firewall are not these drop counters.
Do not derive counts from rate-limited NFLOG history or first-seen records.
Collection must be independent of `firewall.drop_logging_enabled`; existing
history, permissions, category filters and Discord behavior remain unchanged.

**Score rule:** managed policy drops are informational/security evidence and
never lower experience merely because the firewall successfully enforced policy.

### 4.3 Passive TCP/DNS observer

Accepted host traffic is copied through NFLOG group 101 at input/forward and
postrouting hooks, never substituted with router-local TCP_INFO. Generic TCP
capture is 256 bytes; DNS capture is 4608 bytes to retain a 4096-byte message
plus headers. Original conntrack destination IP **and port** restore
client-visible DNS after DNAT, including port 53 rewritten to another port.
Intentionally blocked attempts remain visible in traffic/drop counters but do
not become transport retransmission/unanswered penalties.

- Bind observation to relevant logical LAN links; admit only eligible host
  traffic and the required TCP/ordinary-DNS forms in the kernel filter.
- Observe host ingress and host egress for exchange correlation. The existing
  diagnostics collector's outgoing exclusion stays unchanged for its own scope.
  Share parsing/socket lifecycle primitives where appropriate; do not globally
  widen its filter or double-count parent/child observations.
- New analysis is continuous. A ten-second periodic packet sample is inadequate
  for sequence/ACK correlation, DNS latency, last seen or short-lived activity.
- Use monotonic receive timestamps with bounded capture-delay/loss reporting;
  preserve kernel receive timestamps if available. Egress timestamps describe
  observation at the firewall, not exact physical transmission time.
- Maintain bounded per-flow sequence/ACK and DNS correlation state in memory.
  Parse only necessary transport headers and DNS framing/question fingerprints.
  No raw packets, QNAMEs, DNS answers, remote flow tuples or payloads in SQLite,
  API responses or routine logs. Question fingerprints are transient matching
  material, not persistent browsing history.
- TCP DNS needs bounded stream reassembly, framing, coalesced/segmented messages,
  retransmission handling and pipelined transaction IDs; parsing each TCP packet
  as a complete DNS response is forbidden.
- Malformed/truncated/unsupported fragments, missing handshakes, encrypted DNS,
  capacity eviction, packet loss and capture restarts invalidate relevant
  correlations and expose coverage reasons. They are not network retransmissions,
  zero RTT, DNS timeouts or good experience.

### 4.4 Conntrack

Use one bounded shared direct netfilter dump per ten-second snapshot, not a paged
HTTP loop or 2048 separate queries. Derive per-IP `connections_total`,
`connections_tcp_established` and `connections_unreplied`, counting each kernel
entry once for that host even when both original and reply tuples match.
Include zone and full tuple identity internally; kernel IDs alone are reusable.

NAT/return-direction attribution must preserve the protected private address.
A connection between two protected hosts counts once for each host. Counts are
point-in-time gauges, not sessions started or concurrency throughout the bucket.
No conntrack entry does not mean no traffic or an offline device.
The inventory is streamed on a separate worker, requested roughly two seconds
before close, with the existing 100,000-entry/64 MiB wire-volume guard and a
two-second I/O budget. No full-inventory allocation is retained. Gauges include
nullable `observed_at` (completion) and `measurement_duration_ms`; inventory
iteration is not atomic. A failed, unready, previous-generation or >2500 ms old
result gives null gauges with an explicit error. Capture never waits for it.
Conntrack packet/byte deltas are **not** the primary volume source.

## 5. Ten-second metric contract

Directions are the protected host's
perspective. Count/byte fields use exact unsigned decimal strings or null;
finite latency/rate/percentage fields use JSON numbers or null. No NaN/Infinity,
negative unsigned counts or null-to-zero coercion.

Each sample covers `[start_at,end_at)` with a ten-second scheduled width.
`measured_duration_ms` is the actual monotonic coverage used for rates.
Startup/reset/late/partial intervals expose coverage and do not pretend to be a
complete ten-second observation. `end_at`/other public timestamps are UTC RFC3339;
age/duration calculations use monotonic time. Never interpolate missing data.

### 5.1 Traffic, activity and connections

| Fields | Meaning |
| --- | --- |
| `traffic.sent_packets`, `received_packets` | Interval kernel IP packet observations at the defined LAN boundaries |
| `traffic.sent_bytes`, `received_bytes` | Interval IP-layer byte observations, including headers/repeated data |
| `traffic.sent_bps`, `received_bps` | `bytes * 8 / (measured_duration_ms / 1000)`; null without valid counter continuity/coverage |
| `firewall.dropped_sent_packets`, `dropped_received_packets` | Interval attributable managed drop decisions |
| `connections.total`, `tcp_established`, `unreplied` | Shared inventory gauges near close, decimal strings; actual timing in `observed_at` and `measurement_duration_ms` |
| `last_seen_at` | Most recent attributable host boundary traffic; null before observation, unchanged while idle |
| `activity` | `active` with traffic in the interval; `idle` with complete zero traffic and last seen <=60 seconds old; `not_recently_seen` with older/no observation; `unknown` when traffic observation is unavailable |

Activity is not Wi-Fi association, reachability, operating-system uptime or a
guaranteed online/offline state. A connection existing at close does not advance
last seen. Retained one-hour totals are calculated from retained valid buckets;
they are not lifetime or 24-hour usage and are lower bounds when coverage has gaps.

### 5.2 TCP observations

| Fields | Measurement and limitations |
| --- | --- |
| `tcp.data_packets_sent`, `data_packets_received` | Captured data-bearing TCP observations, not ACK-only/SYN/FIN units or wire segments |
| `tcp.retransmission_observations_sent`, `retransmission_observations_received` | Repeated/overlapping previously observed TCP data sequence ranges in that direction; count a packet once even with multiple overlaps |
| `tcp.retransmission_percent_sent`, `retransmission_percent_received` | Repeat observations / data-packet observations *100; null without an eligible denominator or trustworthy tracking |
| `tcp.window_decreases_host`, `window_decreases_peer` | Ordered advertised-window decreases emitted by the host or remote peer; same tracked connection/direction only |
| `tcp.zero_window_observations_host`, `zero_window_observations_peer` | Captured zero-window advertisements, including repeated ACKs |
| `tcp.zero_window_transitions_host`, `zero_window_transitions_peer` | Ordered transitions from nonzero to zero; first-seen zero is not a transition |
| `tcp.advertised_window_min_bytes_host`, `advertised_window_min_bytes_peer` | Nullable minimum only with complete validated window-scale negotiation; zero is still measurable without scaling |
| `tcp.rtt_remote`, `tcp.rtt_host` | Independent passive timing summaries, defined below |

Do not call packet overlap proof of physical loss. Capture duplication, sequence
wrap, reorder, spurious retransmission, GSO/GRO and state eviction need explicit
handling. Suppress analysis after capture gaps until a defensible fresh baseline;
report incomplete rather than classify discarded capture packets as retransmits.
Sampled receive windows are **not congestion window (`cwnd`)**. Forwarded
sender `cwnd`, RTO and exact zero-window duration are not observable for v1.

Passive TCP timing:

- `rtt_remote`: host-sent data observed entering LAN -> first matching cumulative
  ACK observed returning toward the host. Covers the path beyond the LAN
  observation point, firewall/remote processing and ACK behavior.
- `rtt_host`: data observed toward the host at LAN egress -> matching ACK observed
  arriving from the host. Covers the host-facing path, host processing and
  delayed ACKs. It does not identify a specific AP/radio cause.
- Maintain both directions' sequence intervals; one cumulative ACK produces at
  most one timing observation from an unambiguously tracked newly acknowledged
  range. Do not multiply a single ACK into many statistical samples.
- Apply Karn-style exclusion to acknowledged retransmitted/ambiguous ranges;
  handle delayed/duplicate/SACK ACKs, wraparound and midstream starts. SYN
  handshake time can be a later metric but is not substituted for data/ACK RTT.
- Summary fields: `samples` and `variation_pairs` decimal strings;
  nullable `p50_ms`, `p95_ms`, `min_ms`, `max_ms`, `variation_mean_ms`.
  Percentiles are nearest-rank (`ceil(p*N)`, one-based). Variation is the mean
  absolute difference between consecutive usable RTT observations **within the
  same flow/direction**, pooled by contributing pair count. Never difference RTTs
  from unrelated destinations or bridge expiry/loss/epoch boundaries.

This is passive data/ACK round-trip evidence, not ICMP RTT, one-way latency,
application response time or RTP jitter.

### 5.3 Passive DNS

Observe ordinary DNS on UDP/TCP port 53 on the client-visible LAN leg, whether
forwarded to a resolver or answered by a router-local resolver. Expose the
observed scope; never replace it with a background lookup from the firewall.

- Match host, resolver, protocol/ports, transaction ID and validated question
  fingerprint, with TCP stream identity as applicable.
- Measure request observation -> first matched complete response. Include
  successful answers, NXDOMAIN and other response codes as actual responses;
  NXDOMAIN is not a transport failure. Track SERVFAIL/REFUSED separately.
- A retransmitted/ambiguous request is excluded from timing unless unambiguous
  correlation is established; do not silently choose a convenient start time.
- UDP truncation (`TC=1`) is a measured response and can initiate a separate
  observed TCP retry. Report transport attempts, not an invented combined
  application lookup time without a reliable link.
- Proposed unanswered deadline: **5 seconds** after the observed request.
  Count in the bucket in which the deadline finalizes, not retrospectively in a
  committed older bucket. Unanswered means no response was observed by that
  deadline; it does not prove the client failed at five seconds.
- Do not count pending, incomplete/capacity-evicted or capture-gap requests as
  timeouts. Report exclusions. Response-only observations cannot invent requests.
- A response after a finalized unanswered deadline is a late/excluded
  observation, not a second finalized outcome for that attempt. Keep bounded
  matching/tombstone state long enough to prevent duplicate outcome accounting.
- DoT/DoH/DoQ, custom ports, encrypted tunnels and unsupported reassembly return
  unavailable DNS evidence; UDP port 443 is not observable DNS.

Fields: decimal-string `requests`, `responses`, `unanswered`, `pending_at_close`,
`servfail_responses`, `refused_responses`, `excluded_observations`;
nullable numeric `response_time_p50_ms`, `response_time_p95_ms`,
`response_time_variation_mean_ms`, `unanswered_percent`.
Unanswered percent uses finalized `responses + unanswered`, not currently
pending requests. DNS variation uses consecutive unambiguous responses for the
same host/resolver/transport, without bridging gaps. Label it response-time
variation, not network jitter.

## 6. Explainable experience scoring

**Implemented `algorithm:"netcontrol-passive-v1"`; representative-appliance
calibration remains open.** This is Netcontrol's own diagnostic heuristic, not a UniFi
score or a guaranteed user/application quality assessment.

For each ten-second sample, derive evidence from the **last six contiguous
complete ten-second buckets** up to that sample (maximum 60 seconds). Preserve
the score/reasons as calculated then; reads do not rescore old samples against
new metadata/thresholds. Weight pooled counts by their true denominators and
compute pooled RTT percentiles from bounded in-memory distributions, not an
average of per-bucket p95 values.

Timing distributions use 32 fixed bins with full counts and exact observed
extrema/variation accumulation. Public p50/p95 values and pooled scoring
quantiles are bounded-histogram estimates, not exact retained raw timings.
Busy hosts do not become unrateable merely after 64 timing observations.

Component score bands (boundary belongs to the next worse band):

| Component | Score 100 | Score 85 | Score 60 | Score 25 | Minimum evidence in scoring window |
| --- | --- | --- | --- | --- | --- |
| Sent/received TCP repeat percentage, separately | <0.5% | <2% | <5% | >=5% | >=100 eligible data observations in that direction |
| Passive remote RTT p95 | <50 ms | <150 ms | <300 ms | >=300 ms | >=20 usable ACK timings |
| Passive host RTT p95 | <10 ms | <40 ms | <100 ms | >=100 ms | >=20 usable ACK timings |
| DNS response time p95 | <30 ms | <100 ms | <300 ms | >=300 ms | >=5 usable response timings |
| DNS unanswered fraction | <1% | <5% | <20% | >=20% | >=5 finalized valid attempts |

Overall score is the **minimum eligible component score**, not a weighted mean
that masks one impaired component. Display:

- `excellent`: score >=90.
- `good`: 75..89.
- `fair`: 50..74.
- `poor`: 0..49.
- `unknown`: null score, no defensible rating.

Experience object:

- `score:number|null` in 0..100; `level` as above.
- `status:"rated"|"idle"|"insufficient_data"|"incomplete"|"unavailable"`.
- `confidence:"high"|"limited"|"none"`.
- `basis_seconds:number` in 0..60, `algorithm:string`,
  `components:[{code,score,value,unit,samples}]`, `reasons:string[]`.
- High confidence requires six complete buckets and at least two eligible
  component classes (`tcp_repeats`, `tcp_timing`, `dns`). Fewer complete buckets
  or only one eligible class can be rated with limited confidence.
- Incomplete capture affecting a participating class prevents a normal rating:
  use null score, `status:"incomplete"` and explain the gap. A legitimately
  absent class (for example UDP-only/DoH traffic) is missing evidence, not loss.
- No current-bucket traffic gives null score with `idle` when observation is
  complete; never carry forward last hour's excellent rating as current.
- No eligible components gives null score/`insufficient_data`. Missing metrics,
  zero denominators, startup and stale samples never default to score 100.
- Window pressure, TCP resets, policy drops and RTT variation are explanatory
  advisory reasons in v1, not independent score penalties. Window decreases alone
  are normal flow control; jitter thresholds without a workload baseline would
  overclaim network quality.

Stable reason codes include `tcp_repeats_sent`, `tcp_repeats_received`,
`remote_ack_delay`, `host_ack_delay`, `dns_response_delay`, `dns_unanswered`,
`host_zero_window`, `peer_zero_window`, `managed_policy_drops`,
`insufficient_samples`, `capture_gap`, `tracking_capacity`, `counter_reset`,
`configuration_transition`, `unsupported_dns`, `no_recent_traffic`.
Return contributing values/counts so frontend/operator can explain a label.
A poor host score is not a daemon-health failure or an authorization/write gate.

## 7. SQLite storage, scheduling and retention

Native path: `<services-state-dir>/host-experience/experience.sqlite`.
Keep it separate from configuration/revisions, vnStat history, deny history and
the permanent Discord first-seen index. API reads never initialize/repair storage.

### 7.1 Logical schema

Use a versioned typed schema, not arbitrary packet/JSON blobs:

- Collector runs: epoch/start/end/clock-anchor metadata, retained only while
  referenced by a retained sample.
- Host epochs: IP, configured host ID/name, interface identity/name, configuration
  revision, epoch; no remote connection tuples or Sando text snapshots.
- Buckets: collection ID, scheduled start/end, actual coverage duration,
  source statuses/errors and collector loss/capacity counters.
- Host samples: IP, bucket ID, epoch reference, last seen, activity, nullable
  metric scalars, score/status/confidence/algorithm and bounded reason/component
  records. Unique `(ip_address,bucket_id)`, indexed for IP/time and expiry.

Store canonical IP bytes with family where useful; expose canonical literals.
Counts must round-trip unsigned 64-bit values exactly despite SQLite's signed
INTEGER range: use a validated representation such as canonical decimal TEXT
for counters above signed range. Timestamps/durations are bounded signed
integers internally; rates/latencies must be finite.

### 7.2 Cadence and continuity

- Bucket cadence is ten seconds independently of API clients. Continuous
  observation and one atomic SQLite write batch per completed bucket.
- UTC-aligned bucket labels use a monotonic schedule anchored to wall time.
  Skip missed ticks; never run catch-up observation bursts or synthesize zeros.
- Clock changes create a new epoch/anchor and explicit discontinuity. Use opaque
  bucket ordering/collection IDs rather than wall-clock ordering alone.
- Sample counters together in a bounded collection window; report actual
  measurement skew/duration. A conntrack dump is not an atomic kernel snapshot.
- Commit samples, scoring results and expiry in one writer transaction; latest
  readers see a whole completed collection, never a mix of half-written hosts.
- No engine lock, per-packet lock convoy, synchronous database write or remote
  metadata fetch on the forwarding path. One owned writer and bounded queues.
- Use WAL with bounded busy timeout, explicit persistence errors and checkpoint
  management. `synchronous=FULL`: completed buckets are durable on
  successful commit, subject to filesystem/device guarantees. Do not silently
  use vnStat's different 60-second save policy.

### 7.3 Exactly bounded retention

Normal full coverage is **360 completed ten-second buckets per IP**.
There is no additional live bucket in the latest/history response.

- Never return a bucket whose end is older than one hour at request time;
  at exactly `now - 3600 seconds`, expiry applies. Maximum response is 360
  observations/slots, not 361 inclusive endpoints.
- Writer pruning runs every ten seconds, including paused collection via idle
  maintenance; startup prunes before publishing ready
  state. Read-time filtering applies even if the writer has stopped.
- Monotonic age protects retention while running. After restart use recorded
  clock anchors/UTC evidence; backwards/unknown wall-clock chronology must not
  expose or extend old telemetry indefinitely. Quarantine untrustworthy time
  ranges from reads with explicit status; do not reset/delete the entire DB.
- Prune unreferenced host/run/bucket metadata too. Do not leave an unlimited
  historical IP catalog or old last-seen records outside sample retention.
- Idle eligible hosts still receive a row each bucket with measured zero traffic
  and nullable unavailable transport summaries. Ineligible/removed hosts do not.
- Restart preserves unexpired committed history but resets transport correlations.
  First counter deltas after a reset are null until valid baselines exist.
- Graceful shutdown joins observation/writer workers, finishes only already
  completed buckets, checkpoints and reports final persistence failures.
  Abrupt stop may lose the current unfinished bucket; report restart/gap, not
  guessed observations during downtime.

### 7.4 Resource and privacy budgets

Finalized implementation bounds and measured sizing revisions:

- Eligibility: honor existing maximum 2048 configured addresses, not a new lower
  silent UI/collector limit; maximum 737,280 full-retention host sample rows.
- Analyzer plus all six rolling evidence buckets has a conservative tested
  allocation bound of 76,877,402 bytes (under 80 MiB on the tested x86-64 layout).
  This supersedes the proposed **aggregate** 64 MiB target; it is not an RSS
  measurement or a claim that the rest of the daemon uses no memory.
  TCP flows and pending DNS requests each have an 8192 global / 32 per-host cap.
  Quiet configured hosts do not reserve unused slots; global pressure reclaims
  over-fair-share borrowers with explicit exclusions. Finalized DNS tombstones
  have separate bounded capacity and do not consume pending-request quota.
  Capture buffers, at most two queued completed collections, current/writing
  collections, bounded API responses and SQLite/kernel buffers are additional.
  Whole-appliance CPU/RSS/latency acceptance remains required.
- UDP DNS capture/framed TCP DNS message analysis <=4096 bytes; reject oversized
  analysis explicitly without storing payload. TCP reassembly and partial
  message storage have a separate global memory bound, never 4096 * unbounded
  flows.
- SQLite main-file limit **2 GiB** (`max_page_count=524288`, 4096-byte pages)
  and WAL limit **32 MiB**, including indexes/retained metadata. The 512 MiB
  proposal failed at 229,376 populated samples and was revised, not worked around
  by dropping hosts or shortening history. The full 737,280-row stress fixture
  verifies populated IPv6 metrics, exact usage, expiry and cleanup.
  Reuse freed pages, bounded checkpoints, no hot-path full VACUUM.
- On memory/capture/DB capacity pressure, expose partial/unavailable status and
  counter evidence; do not silently shorten retention, remove configured hosts,
  reduce cadence, block forwarding, or report a successful zero sample.
- DB/directory/WAL/SHM are owner-only, symlink-safe and exclusively owned.
  Integrity/schema failures preserve existing data, expose explicit unavailability
  and do not prevent unrelated configuration control from functioning.
- Native host deployment requires nftables dynamic counter/last-expression
  sets, original-direction conntrack port expressions and NFLOG with timestamps,
  sequence and conntrack metadata. Managed drop accounting is compiled into the
  owned firewall; these capabilities are deployment requirements, not optional
  older-kernel compatibility paths. NFLOG group 101 is reserved separately from
  existing deny-history group 100. No shell collector or active probe is started.
- Retention is logical deletion, not guaranteed secure erasure from filesystem,
  WAL, SSD or backups. Do not claim privacy guarantees beyond this boundary.

## 8. HTTP APIs

**Not present today.** Both use API-key Bearer authentication and `state.read`,
read-only GET, no body, `Cache-Control:no-store`, existing CORS/security headers
and `{error,transaction}` errors. No new log-reading privilege is bypassed:
only aggregated host measurements/metadata are returned, never deny records,
remote flow lists or DNS content.

### 8.1 Latest table

`GET /api/v1/statistics/host-experience/latest`

Allowed optional query parameters:

| Parameter | Validation / behavior |
| --- | --- |
| `address` | One canonical IPv4/IPv6 literal; filters by IP |
| `interface` | One existing managed LAN technical name; exact current attachment filter |
| `limit` | Canonical integer 1..256, default 100 |
| `cursor` | Opaque bounded continuation token <=1024 bytes from this API |

Unknown/duplicate parameters, invalid literals and invalid cursor combinations
are `400`. Unsupported known interface role is `422`. Capture one completed
collection for all pages; cursor binds collection ID and filter values. Stable
sort is address family then numeric address bytes, not textual IP order.
An expired/purged collection cursor returns `409` with an instruction to restart
latest paging; do not silently switch pages to another ten-second tick.

Envelope: `schema:"netcontrol-host-experience/v1"`, `kind:"latest"`,
`collected_at:string|null`, `age_ms:number|null`, `interval_seconds:10`,
`retention_seconds:3600`, `collection_id:string|null`,
`status:"starting"|"available"|"partial"|"stale"|"unavailable"`,
`error:string|null`, `collector` diagnostics, `hosts:HostLatest[]`,
`next_cursor:string|null`.

Each `HostLatest` contains IP/family, configured ID/name,
`currently_protected:true`, current derived interface (name/index/kind/VLAN ID;
VLAN ID nullable for non-VLAN), current metadata, `sample:Sample|null`, and
`retained_usage` with nullable `sent_bytes`/`received_bytes`, coverage seconds
and `complete:boolean`. Retained usage covers the represented IP's retained
epochs and is labeled **1-hour observed usage**, not a stable physical device's
usage if ownership changed.

Before first completed bucket, return `200` starting, eligible metadata rows
with `sample:null`, not fake metrics. No eligible LAN hosts returns `200` with
`hosts:[]` and explicit unmapped/excluded diagnostics. A collector older than
30 seconds is stale. Historical last samples may be shown as stale with actual
age, never recast as live; samples past retention must disappear.

Collector diagnostics contain decimal-string interval `capture_dropped_packets`,
`analysis_exclusions`, `tracking_evictions`, `dropped_unattributed_packets`;
numeric `eligible_addresses`, `unmapped_addresses`, `excluded_addresses`;
`sources:[{name,status,error}]` and `reasons:string[]`. Count fields are null
when their source is unavailable, never guessed zero.

Synthetic starting response showing the metadata wrapper (an observed response
replaces `sample:null` with the shape below; this is not a deployed capture):

```json
{
  "schema":"netcontrol-host-experience/v1","kind":"latest",
  "collected_at":null,"age_ms":null,"interval_seconds":10,
  "retention_seconds":3600,"collection_id":null,"status":"starting","error":null,
  "collector":{
    "capture_dropped_packets":null,"analysis_exclusions":null,
    "tracking_evictions":null,"dropped_unattributed_packets":null,
    "eligible_addresses":1,"unmapped_addresses":0,"excluded_addresses":0,
    "sources":[{"name":"traffic","status":"starting","error":null}],
    "reasons":["insufficient_samples"]
  },
  "hosts":[{
    "ip_address":"192.0.2.20","address_family":"ipv4",
    "configured_host_id":"camera","configured_name":"Front door camera",
    "currently_protected":true,
    "interface":{"name":"vlan20","index":20,"kind":"vlan","vlan_id":20},
    "metadata":{
      "host_name":"camera.example.test","icon":"camera_icon",
      "classification":"Front door camera","status":"available",
      "last_success_at":"2026-11-14T00:00:00Z","error":null
    },
    "sample":null,
    "retained_usage":{
      "sent_bytes":null,"received_bytes":null,"coverage_seconds":0,"complete":false
    }
  }],
  "next_cursor":null
}
```

`address_family` is `ipv4|ipv6`; `interface` may be null when current attachment
became unavailable, with the relevant collector reason. `index`/`vlan_id` are
bounded integers; VLAN ID is 1..4094 or null for a non-VLAN.
`metadata` is always an object with the fields above; its three display strings,
timestamp and error are nullable. `configured_name`/ID are nonnull strings from
the configured or last-retained identity. `retained_usage.coverage_seconds`
counts valid observed duration, at most 3600, and `complete` requires full valid
coverage with no missing/reset intervals.

### 8.2 Full one-hour per-IP history

`GET /api/v1/statistics/host-experience/history?address=192.0.2.20`

Required canonical `address`; no other query parameters, time-window controls,
downsampling options or body in v1. IPv6 example:
`?address=2001%3Adb8%3A20%3A%3A20`. Read at most 360 aligned slots for the retained
one-hour window. No pagination is needed for this per-IP response.

Return common schema/interval/retention/status/diagnostics and:

- `kind:"history"`, `host` current-or-last-retained identity/metadata,
  `currently_protected:boolean`.
- `window:{start_at,end_at}`, `returned_samples:number` in 0..360,
  `expected_slots:360`, `coverage_complete:boolean`, `clock_discontinuity:boolean`.
- `samples` chronological by observation/collection order, with each slot
  `{start_at,end_at,status:"observed"|"missing",sample:Sample|null}`.
  Emit missing slots with null sample during startup/downtime/ineligible periods;
  a slot is not a zero-traffic observation. On clock discontinuity preserve
  observed ordering and explicit gaps/anchors; don't invent a UTC-perfect grid.
  Cap the entire slot array at 360.

Configured eligible IP before collection returns `200` with no observed samples
and missing slots. A removed IP with unexpired history returns that history;
an address neither eligible nor present in retained data returns `404`.
An unmapped configured IP with no retained LAN history also returns `404` and
an explanatory error. Current metadata may be unavailable independently of
historical metrics.

Use `/latest` for the table every ten seconds and `/history` only for a selected
row/graph; do not fetch all hosts' hour histories on every table refresh.

### 8.3 Sample shape and units

Synthetic example of one observed sample; version/epoch/IDs are illustrative,
not evidence of a deployed release:

```json
{
  "ip_address": "192.0.2.20",
  "configured_host_id": "camera",
  "configured_name": "Camera",
  "configuration_revision": "2026.11.14.3",
  "observation_epoch": "synthetic-epoch-1",
  "start_at": "2026-11-14T00:25:00Z",
  "end_at": "2026-11-14T00:25:10Z",
  "measured_duration_ms": 10000,
  "interface": {"name":"vlan20","index":20,"kind":"vlan","vlan_id":20},
  "last_seen_at": "2026-11-14T00:25:09Z",
  "activity": "active",
  "traffic": {
    "status":"available","error":null,"sent_packets":"200","received_packets":"400",
    "sent_bytes":"20000","received_bytes":"500000",
    "sent_bps":16000,"received_bps":400000,
    "packet_unit":"kernel_l3_packet","byte_unit":"ip_layer_bytes"
  },
  "firewall": {
    "status":"available","error":null,"dropped_sent_packets":"2",
    "dropped_received_packets":"0","drop_coverage":"managed_nftables_only"
  },
  "connections": {
    "status":"available","error":null,
    "observed_at":"2026-11-14T00:25:08.100Z","measurement_duration_ms":50,
    "total":"3","tcp_established":"2","unreplied":"1"
  },
  "tcp": {
    "status":"available","error":null,"data_packets_sent":"100","data_packets_received":"300",
    "retransmission_observations_sent":"0","retransmission_observations_received":"0",
    "retransmission_percent_sent":0,"retransmission_percent_received":0,
    "window_decreases_host":"2","window_decreases_peer":"1",
    "zero_window_observations_host":"0","zero_window_observations_peer":"0",
    "zero_window_transitions_host":"0","zero_window_transitions_peer":"0",
    "advertised_window_min_bytes_host":65536,"advertised_window_min_bytes_peer":131072,
    "rtt_remote":{"samples":"20","variation_pairs":"19","p50_ms":15,"p95_ms":25,"min_ms":10,"max_ms":30,"variation_mean_ms":2},
    "rtt_host":{"samples":"20","variation_pairs":"19","p50_ms":2,"p95_ms":4,"min_ms":1,"max_ms":5,"variation_mean_ms":0.5}
  },
  "dns": {
    "status":"available","error":null,"requests":"5","responses":"5","unanswered":"0",
    "pending_at_close":"0","servfail_responses":"0","refused_responses":"0",
    "excluded_observations":"0","response_time_p50_ms":8,
    "response_time_p95_ms":12,"response_time_variation_mean_ms":1,
    "unanswered_percent":0
  },
  "experience": {
    "algorithm":"netcontrol-passive-v1","score":100,"level":"excellent",
    "status":"rated","confidence":"limited","basis_seconds":10,
    "components":[
      {"code":"tcp_repeats_sent","score":100,"value":0,"unit":"percent","samples":"100"},
      {"code":"tcp_repeats_received","score":100,"value":0,"unit":"percent","samples":"300"},
      {"code":"remote_ack_delay","score":100,"value":25,"unit":"ms","samples":"20"},
      {"code":"host_ack_delay","score":100,"value":4,"unit":"ms","samples":"20"},
      {"code":"dns_response_delay","score":100,"value":12,"unit":"ms","samples":"5"},
      {"code":"dns_unanswered","score":100,"value":0,"unit":"percent","samples":"5"}
    ],
    "reasons":["managed_policy_drops"]
  },
  "coverage": {
    "complete":true,"reasons":["managed_policy_drops"],
    "traffic":"kernel_l3_pre_snat_sent_post_filter_received","firewall":"managed_nftables_only",
    "tcp":"accepted_lan_tcp","dns":"accepted_client_visible_udp_tcp_53","connections":"shared_conntrack_snapshot"
  }
}
```

Each source section's `status` is
`available|partial|unavailable|not_observed`, with nullable `error` when relevant.
Unavailable fields are null; measured counts can legitimately be `"0"`.
`not_observed` means no relevant traffic, not unavailable collection.
`coverage.complete` means complete **declared observable scope**, not visibility
into encrypted, offloaded, upstream or same-switch traffic. Return interval
capture loss/analysis exclusions as collector diagnostics and per-source reasons.

### 8.4 Errors and reads during failure

- `401` invalid/missing API key; `403` missing `state.read`; `405` other method.
- `400` body/query/type/canonical-validation errors; `422` invalid interface role.
- `404` unknown/unretained history address; latest filters can return empty rows.
- `409` invalidated latest pagination snapshot.
- `429` four experience reads already active; retry without overlapping polls.
- `503` simulator/unsupported native mode, unavailable manager, unreadable/
  corrupt/unsupported storage. Simulator must not fabricate host traffic.
- With readable committed storage but a failed live source, return `200` with
  partial/stale/unavailable source status and real retained evidence, not a
  success-shaped live fallback. Completely unavailable storage remains `503`.
- Both response bodies have a **4 MiB** hard ceiling; the original 1 MiB latest
  target was too small for 256 fully populated samples even before enrichment.
  SQLite statement/busy deadlines and storage-lock acquisition are bounded to
  one second; four concurrent requests bound response work. Capacity/contention
  returns explicit `503`; hosts/samples are never silently truncated to fit.

## 9. Frontend table and graph handoff

Use the supplied table's client-oriented arrangement, not its unsupported columns:

| Dashboard column | Backend source |
| --- | --- |
| Name / icon | Configured name, nullable exact-IP Sando icon; description as subtitle/tooltip |
| Type / description | `classification` text; generic type display only when unavailable, not an inferred API enum |
| Network / connection | Derived logical LAN interface and optional VLAN ID |
| IP address | Canonical IP; separate rows for separately configured addresses |
| Experience | Level, score, confidence, reasons and observation freshness |
| Activity | Sent + received bps from a valid interval |
| Download / upload | Received / sent bps, host perspective |
| 1-hour usage | Retained received/sent observed bytes and coverage |
| Last seen | Actual last observed traffic timestamp; never label device uptime |
| Connections / drops | Current conntrack gauges and per-bucket managed drop counts |

Selecting a row loads the ten-second one-hour graph. Plot gaps as gaps, not zero;
graph score/level, throughput, managed drops, passive TCP/DNS timing and receiver
pressure with separate units. Show remote-path vs host-path timing distinctly.
Retain original-case descriptions, map icons safely, and render unsupported/
unknown/idle/stale states visibly. No AP, Wi-Fi, radio channel, 24-hour usage or
uptime field is promised by this API.

Required frontend work is **future** and **Pending frontend review**:
[handoff 2026-11-14-03](frontend-handoffs/2026-11-14.md#2026-11-14-03-protected-host-experience-proposal).
Do not wire calls or advertise backend availability until implementation passes
acceptance and an accepting build is deployed.

## 10. Implementation work breakdown and acceptance gates

The worker, metrics, persistence, scoring and APIs below are implemented
together, not a traffic-only intermediate delivery. The
[implementation journal](journal/2026-11-14.md#protected-host-experience-implementation)
records executed validation, resource measurements, corrections and limitations.
Physical NIC/offload/appliance-load acceptance remains distinct and outstanding.

| Phase | Scope / expected components | Depends on | Exit gate |
| --- | --- | --- | --- |
| 0. Feasibility and finalized measurement design | Native Linux kernel counter hooks/set-map support, VLAN/offload/NAT boundaries, filtered bidirectional TCP/DNS capture, worst-case row/CPU/memory sizing | Concurrent code work complete; development authorized | Demonstrate representative traffic attribution and bounded overhead; finalize schema/budgets/threshold caveats without enabling production collection |
| 1. Typed contract, storage and scoring primitives | `netcontrol-core` metric/query types, epoch/retention rules; private SQLite store in native layer; pure score logic | Phase 0 | Focused precision, 360-slot retention, clock/reset, unknown/idle/gap and threshold tests |
| 2. Basic native host observer | Native eligibility/interface resolution, kernel packet/byte/drop accounting, shared conntrack snapshot, ten-second writer/lifecycle | Phase 1 | IPv4/IPv6, VLAN, NAT, LAN-to-LAN, drops independent of logs, short-flow volume, restart/shutdown/rollback acceptance |
| 3. TCP/DNS analysis | Native/passive parser and bounded flow tracking, repeated data, scaling/windows, directional ACK timing/variation, UDP/TCP DNS | Phases 0 and 1; integrate phase 2 buckets | Loss/reorder/wrap/retransmission ambiguity, DNS stream/pipeline/expiry and capacity tests; no fake metrics or payload retention |
| 4. API and metadata integration | `netcontrold` manager/lifecycle, existing Sando typed lookup, latest/history HTTP permissions, coherent paging and diagnostics | Phases 2 and 3 | Exact response fields, status/error cases, source failures, removed/reassigned IPs and concurrent reads |
| 5. Full regression and physical acceptance | Cross-crate checks, privileged namespace fixtures, appliance load/durability; final spec/changelog/handoff | Phase 4 | Performance/resource/correctness acceptance below; backend availability explicitly recorded |

Do not expose phase-2 traffic-only delivery as completed v1: the requested TCP/DNS
measurements and experience must be integrated or a reduced scope must be
explicitly approved. Frontend UI work can proceed from a labeled mock/proposal
but is not backend acceptance.

### Required focused behavior tests

- Exactly 10-second schedule/360-slot upper bound; first/partial/missed buckets;
  expiry on the exact one-hour boundary; idle and removed addresses.
- Two addresses on one host stay independent; configured-only eligibility,
  VLAN derivation, no parent/WAN duplication, interface move/recreation,
  ownership reassignment, NAT/return and routed host-to-host attribution.
- Counter continuity, unsigned values above JavaScript and SQLite signed limits,
  rates using actual duration, resets and transaction/rollback gaps.
- Short-lived connections and fragments counted by base traffic even when
  absent/unsupported in conntrack/transport analysis.
- Every terminal managed drop counted once per endpoint perspective, log capture
  disabled, security drops excluded from score, RPF coverage remains explicit.
- TCP retransmission ambiguity, duplicate capture/reorder/SACK/wrap, missing
  scaling SYNs, zero-window transitions and delayed/cumulative ACK correlation;
  separate remote/host timing and no cross-flow variation.
- DNS UDP/TCP segmentation/coalescing/pipelining, timeout finalization across
  buckets, pending/excluded attempts, NXDOMAIN vs SERVFAIL, truncated UDP/TCP
  fallback, encrypted DNS and bounded reassembly.
- Exact score boundaries/denominators, missing classes, idle/null score,
  capture gaps, limited confidence, no retrospective rescore.
- Atomic full-collection latest pagination across ticks and expiry, chronological
  per-IP history, no more than 360 slots and source-specific errors.
- API authorization/canonical query/body/method checks, simulator `503`, metadata
  source switching/staleness/nulls and safe icon/text semantics.
- SQLite ownership/schema/corruption/disk-full/busy failures preserve existing
  data and unrelated configuration access; restart and clean shutdown join all
  workers, with final write failures explicitly reported.

### Performance and operational acceptance

Use equivalent before/after appliance loads, including a bidirectional bulk
transfer plus real-time voice-like traffic and DNS bursts. Establish the baseline
before enabling this collector; container tests alone are not appliance evidence.

Initial proposed acceptance thresholds under the agreed representative load:
throughput regression <=3%; incremental p95 forwarded latency <=1 ms or <=5%
of baseline (whichever allowance is larger); collector CPU <=5% of one core at
the ordinary appliance workload; no growth beyond documented memory/storage/
queue bounds; zero unexplained packet duplication. Report the actual link rates,
host/flow count and CPU model with results. These are acceptance targets, not
claims that this design already meets them.

At intentional overload, forwarding/configuration must remain responsive,
analysis admission must be fair/bounded, capture/DB losses must be reported and
experience must become incomplete rather than falsely excellent/poor.
Validate worst-case 2048-address retention and high-flow churn separately from
ordinary load. Do not lower coverage/cadence or weaken kernel security silently
to pass benchmarks.

Development will span crates: run smallest focused checks first, then stable
locked workspace tests, strict all-targets Clippy, formatting and build. Privileged
Linux namespace fixtures must establish packet attribution, shutdown, concurrency,
persistence and rollback; physical NIC/offload/runtime acceptance remains required.
No deployment, commit, push, publication or frontend notification is authorized
by this scope.

## 11. Finalized decisions and remaining acceptance

- Independent boundary accounting, accepted-only passive analysis, terminal-drop
  helper instrumentation, streamed conntrack and private scalar SQLite are
  implemented in Rust. Numeric accounting does not weaken policy drift guards.
- Public identity, direction, nullability, scoring and pagination are defined
  above; current metadata does not rewrite retained sample identities.
- Measured storage, analysis-memory and response-bound revisions are explicit
  in sections 7.4/8.4. No silent reduction of 2048 IPs, 360 slots or cadence.
- Remaining operator acceptance: representative throughput/latency/CPU/RSS,
  physical offload/VLAN/NAT topologies and heuristic calibration. Container
  fixtures are not claims about the target appliance or voice quality.
- Frontend table/chart implementation and integration remain required in
  [item 2026-11-14-04](frontend-handoffs/2026-11-14.md#2026-11-14-04-protected-host-experience-implementation),
  Pending frontend review.

**Release impact:** additive read APIs and observed-state data, plus new private
telemetry storage/native capability requirements; next automatic calendar
version. No release seed/package-version edit, compatibility shim, deployment,
commit, tag, publication or frontend notification is part of this work.
