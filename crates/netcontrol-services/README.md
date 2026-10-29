# Native service workers

`netcontrol-services` owns Rust threads and sockets, not child processes. Its
public API accepts complete operational configuration JSON and reuses the core
mDNS types and validation.
Unknown service fields, invalid values, unsupported modes, missing privileges,
conflicting ownership, and incompatible stored records are errors.

## Scope and lifecycle

Construct `Services` on the host-network thread with an absolute, private
`state_directory`. The constructor locks `services-v1.lock` and pins both the
original host namespace and, when configured, the namespace file handle. Each
worker explicitly enters its pinned network namespace; the caller is not moved.
Here "host" means the daemon's original namespace, not PID 1's namespace. With
native host mode, both host and managed workers use that same pinned namespace.
Workers skip `setns` when already there; no `CAP_SYS_ADMIN` is required solely
for same-namespace execution. Other-namespace entry and service-specific
capabilities remain necessary where applicable.
Host clock/logging/traffic collection requires `allow_host_services`; running
managed workers without an isolated namespace requires that same opt-in. ICMP
probing additionally requires `allow_gateway_monitoring`. Namespace switching
requires the applicable Linux namespace capability.

`apply` validates before stopping the current workers and restores the previous
service configuration on a failed start where possible. `repair` deliberately
restarts the requested service set. Workers have bounded socket I/O, cooperative
stops, ten-second stop notifications, and owned joins. They never invent PIDs.
Startup can take up to sixty seconds for bounded DNS/TLS connection attempts.
Each owned worker supervises repeated preparation/execution attempts. Startup
errors, runtime errors, unexpected exits and unwind panics retain an error and
retry after 1, 2, 4, 8, 16, then at most 30 seconds; an attempt lasting at least
60 seconds resets the delay. Stops interrupt backoff and prevent further retries.
Failed attempts release their resources before reopening them. Linux-native
operations are unavailable on other platforms.

Runtime status keeps `appliance_services`, `dhcp_relay`, `softflowd`, and
`gateway_monitors` collections. Rows use `state: disabled|running|error|stopped`,
with real `started_at` and `error` information where applicable. Gateway rows
use the existing `process_state`, `sample_status`, and health/statistics fields.
These are worker states, not external daemon states; there is no `pid` field.
`state: error` with `retrying: true` means the supervisor is alive and recovering,
not that the requested service was disabled. `restart_count` counts failed or
unexpectedly completed attempts since supervisor creation; `last_error` retains
the latest failure after recovery while the current `error` clears on readiness.
Configuration verification checks applied settings and owned active supervisors,
not connectivity, delivery, samples or service health. Runtime unavailability
does not block unrelated reads, apply, confirmation or rollback. Configuration
validation, explicit opt-ins, missing syslog activation, authorization, network
drift and durable transaction recovery safeguards remain enforced.

## Implemented services and boundaries

* **IPv4 UDP broadcast relay:** one supervised managed worker per enabled
  `udp_broadcast_relay.instances[]`, with an exclusive UDP listener, per-link
  multicast memberships and device-bound raw IPv4 egress. Relays broadcasts
  and the optional exact multicast group to selected links except ingress;
  offers original-source and two interface-source modes. Instance IDs mark
  DSCP to suppress echoes; ECN, TTL and UDP payload are preserved. CAP_NET_RAW
  and the normal host-service opt-in apply. No external process, automatic
  firewall/NAT rule, arbitrary-unicast proxy, IPv6 or CARP tracking. Failed
  bindings, missing DHCP addresses and link changes report errors and retry
  independently. Eight string counters report observed payload traffic/drops
  and send errors; kernel receive loss remains unmeasured. Raw IPv4 packets
  must fit the outgoing MTU; send errors retain their latest reason. See
  [contract and device setup](../../docs/UDP_BROADCAST_RELAY_SPEC.md).

* **mDNS/DNS-SD:** one managed singleton, disabled by default, with same-family
  reflection between 2..32 explicitly eligible, up managed Ethernet/VLAN LANs.
  Allow/deny selection never discovers unmanaged links or includes WAN. IPv4
  `224.0.0.251` and IPv6 `ff02::fb` use per-interface, device-bound UDP/5353
  sockets, packet-info/hop-limit admission, local-source egress and hop limit
  255. IPv4 disables `IP_MULTICAST_ALL`; IPv6 sockets are IPv6-only. Host mode
  needs `allow_host_services`; no external daemon, systemd socket activation,
  firewall accepts, forward permits, NAT or family translation is installed.
  Operators must allow local input UDP/5353 on participating links and service
  connectivity separately. Use one reflector per connected reflection domain.
  A namespace-scoped abstract socket locks cooperative ownership and procfs
  inspection rejects existing UDP/5353 receivers, including reusable sockets;
  operators resolve competing receivers themselves.
  A bounded Rust DNS codec decodes compression and reconstructs all sections.
  Supported RRs are A, NS, CNAME, PTR, HINFO, TXT, AAAA, SRV, DNAME and NSEC.
  Other types reject the complete datagram and increment
  `unsupported_record_drops`, never pass through unsafe opaque compression.
  Filtered service/subtype/provider discovery tracks only admitted instance and
  provider dependencies per ingress/family, rebuilds mixed packets, supports
  enumeration, and expires associations within 120 seconds. Filtering is
  unauthenticated discovery policy, not service authorization; provider
  addresses needed by allowed services are necessarily disclosed.
  Reflection clears QU, preserves record TTL/cache-flush/known answers and
  handles TTL-zero goodbyes. Outstanding queries bound direct-unicast admission;
  five-second legacy request mappings reconstruct the original ID/questions,
  clear cache-flush and cap answer TTL to ten seconds.
  Optional publishing probes configured identities before readiness, fails
  visibly on hostname conflict instead of renaming, announces/refreshes and
  responds to queries with known-answer suppression, QU/legacy handling and
  goodbye records. TC known-answer continuations collect for 450 ms.
  Address, opt-in Linux/CPU HINFO, `_workstation._tcp` (conventional port 9)
  and browse-domain records are real publications; SSH/SFTP and arbitrary
  services are not advertised. Explicit hostname or configured system hostname
  is used, never ambient hostname; cosmetic system domain is irrelevant.
  Global IPv6 disable suppresses IPv6 transport and AAAA publication, preserving
  saved preferences. Cross-family flags only select published record types.
  Link/address snapshots are checked every second, not by netlink subscription.
  Address replacement prepares replacement sockets and reprobes publications;
  missing/down/replaced required links stop use of stale sockets rather than
  silently shrinking membership. The supervisor reports the failure and
  automatically reopens resources when the configured links become available.
  Readiness is not proof of network delivery.
  Runtime `appliance_services` includes the singleton `mdns` row. Its counters
  are decimal strings, reset at worker start. Linux `SO_RXQ_OVFL` accounts
  socket receive loss; unavailable accounting, descriptor replacement or
  truncated ancillary data makes `receive_drops: null`. Statistics are
  incomplete after known receive/queue/rate/oversize loss or unavailable
  accounting. Disabled/simulator samples do not claim measured completeness.
  Fixed limits are 9,000 input bytes, 512 questions/RRs, 8,192 transmission
  fingerprints plus a separate bounded ingress-loop guard, 8,192 aggregate
  dependency associations, 1,024 aggregate outstanding requesters, and per
  interface/family ingress/egress buckets of 200 packets/s with burst 400.
  Work is synchronous and batched (maximum 256 datagrams/2 MiB); pending
  publication continuations are also bounded to 2 MiB. Output uses at most
  1,232 bytes, reduced for actual interface MTU. RR-boundary splitting and TC
  query known-answer continuations are supported; a single RR or question
  section that cannot fit is dropped/counted rather than byte-truncated.
  A publisher probe RRset that cannot fit one egress datagram rejects startup
  explicitly, rather than claiming successful partial identity probing.
  Polling waits 10 ms and normal shutdown is tested below one second.
  See [synthetic configuration](../../examples/mdns.json). Isolated privileged
  veth/namespace tests cover actual IPv4/IPv6 source/port/hop/fanout, filtering,
  legacy replies, publishing, ownership, rollback/restart/repair and shutdown:
  `NETCONTROL_INTEGRATION=1 cargo test -p netcontrol-services --locked native_mdns -- --ignored`.
  VLAN-tag/nftables/MLD acceptance, 10,000-packet/s reference-host load,
  device/browser/Avahi interoperability and boot/appliance qualification remain
  separate, unverified acceptance gates. Do not infer them from these fixtures.

* **DHCPv4:** one exclusive UDP/67 socket with receive/send `IP_PKTINFO`,
  supported on explicitly managed up Ethernet, dummy or VLAN interfaces;
  per-interface giaddr, up to 64 upstreams per interface, no downstream relay chaining,
  Ethernet/DHCP header/options/hops validation, transaction ID plus client-MAC
  correlation, trusted upstream/source-port checks, and bounded transaction
  tracking (65,536 entries; 120 seconds). Configured client addresses must be
  on-link unicast, not subnet broadcast/network/relay addresses. Broadcast and
  renewals use source/interface-controlled UDP; initial unicast replies use
  AF_PACKET with the client's Ethernet address and valid IPv4/UDP checksums.
  Requests require UDP/68, replies UDP/67. Requires privileged bind and raw
  packet permission. DHCPv6, chained relays, and option-82 insertion are absent.
* **NTP:** host UDP poll client, one resolved endpoint per configured server,
  sixty-four-second polling and three-second response deadlines. Validates
  server mode, v3/v4, leap, stratum, originate/receive/transmit timestamps,
  round-trip bounds and root distance, including NTP era rollover. Chooses the
  lowest-delay valid sample and uses only Linux `adjtimex(ADJ_OFFSET_SINGLESHOT)`.
  Each requested correction is clamped to +/-500 ms (500,000 microseconds);
  larger valid residual offsets continue polling and slewing rather than
  causing failure. The kernel applies corrections gradually; no clock step
  or immediate synchronization is claimed. Requires CAP_SYS_TIME
  and explicit operator ownership of clock discipline; no automatic takeover
  of another clock manager. Missing/invalid samples remain visibly unavailable
  with a row-local error while the worker keeps running and polling, even after
  three failed rounds. A valid sample clears the warning automatically.
  This condition does not fail configuration observation or confirmation;
  startup, socket I/O and clock-adjustment failures are reported while the
  supervisor automatically retries resource preparation and polling.
  No NTP serving, NTS, drift
  estimator, server consensus/falseticker algorithm, or chrony command API.
* **Syslog:** RFC5424 output over UDP and RFC6587 octet-counted TCP/TLS.
  TLS verifies server identity/IP against system CA roots. The default-enabled
  `tls` Cargo feature uses rustls/ring and needs a C compiler when building its
  cryptographic dependency; builds without this feature reject TLS forwarding
  explicitly, never downgrade it. **Requires systemd/journald** with
  `ForwardToSyslog=yes` and a single inherited datagram descriptor named
  `netcontrol-syslog`, bound to `/run/systemd/journal/syslog`. Validates the
  activation PID/count/name, socket type/address and socket-path identity.
  Missing activation rejects enabled syslog before worker shutdown/apply.
  OpenRC/direct launches cannot enable native syslog; no direct-capture fallback.
  Ubuntu install/full source-upgrade scripts configure the socket/journald and
  stop/mask competing receivers, not journald's `/dev/log` input; see
  [host logging ownership](../../docs/BUILD_AND_INSTALL.md#host-logging-ownership).
  Journald captures host/kernel messages and daemon stdout/stderr. Netcontrol
  only receives forwarded datagrams; it never binds/unlinks `/dev/log`, opens
  `/dev/kmsg`, or tails `backend.log`, avoiding duplicate kernel/backend capture.
  Journald's forwarded message text is wrapped in bounded RFC5424 output with
  APP-NAME `journald`; this is not a journal cursor reader or metadata-preserving
  journal export. A local copy is appended to `syslog-host.log`.
  Messages are bounded to 65,000 bytes. Each remote destination reconnects
  independently with a 1..30-second capped exponential backoff; successful writes
  reset its delay. Connection/write failures retain a row-local warning while
  local capture and other destinations continue. `destination_errors` lists
  current destination failures; `captured_records` counts local records,
  `forwarded_records` counts records written successfully to every destination,
  and `failed_deliveries` counts missed per-destination sends. These numeric
  counters reset when the worker restarts; successful sends do not prove receipt.
  Missed deliveries are not queued or replayed. Socket-path/local I/O failure
  invokes shared worker recovery. Systemd owns socket lifetime; worker repair/rollback
  reuses the inherited receiver and never unlinks it. While disabled/stopped,
  the bounded socket queue may retain messages for later forwarding or overflow;
  daemon stop/restart closes the managed socket and its queue. Journald capture,
  rate limits and forwarding settings determine coverage. No complete delivery,
  acknowledgment, durable forwarding queue/replay or rotation is claimed.
* **Traffic counters:** host and managed workers sample all `/proc/thread-self/net/dev`
  interfaces, including loopback, every five seconds. Captures byte/packet
  baselines, accumulates observed deltas, and records boot/namespace/interface/reset
  boundaries. The first observation is a baseline, not invented earlier
  traffic. A reset adds the new counter value rather than subtracting/wrapping.
  Removed interfaces remain in history. The latest 10,000 per-interface sample
  records are retained; cumulative totals are not truncated. Files
  `traffic-host-v1.json` and `traffic-managed-v1.json` use the independent
  `netcontrol-services/counters/v1` schema. Snapshots use exclusive `.pending`
  creation, fsync, atomic rename and directory fsync; an unresolved `.pending`
  file causes an explicit error and requires operator review. Invalid/incompatible
  records are never deleted, reset, migrated, or interpreted as Go/vnStat data.
  There is no vnStat database/client compatibility or calendar aggregation.
* **NetFlow:** AF_PACKET Ethernet/VLAN capture and NetFlow v1/v5/v9/IPFIX UDP export,
  bounded flow capacity, configured sampling, idle/protocol/flag/maxlife/export
  timeouts, and shutdown flushing. Excludes its collector traffic to avoid
  export feedback. Capture uses nonblocking batches of up to 64 packets per
  `recvmmsg`, with at most 256 packets between maintenance checks. A readiness
  poll waits up to 10 ms only when no capture is ready; queued traffic is drained
  without the former unconditional 10 ms sleep. Each exporter requests a 4 MiB
  socket receive buffer (Linux caps this at `net.core.rmem_max` and doubles the
  accepted value for socket accounting) and uses at most 64 times `snaplen`
  bytes of userspace packet storage. Flow accounting uses a randomly seeded
  hash table with an ordered least-recently-updated index; the configured
  `max_flows` limit is unchanged. Timeout classes are resolved once at startup,
  with one monotonic timestamp per packet update and per expiry scan.
  Capacity/counter-rollover exports are coalesced at the end of each receive
  batch, with at most 64 pending records, rather than sending each early-expired
  flow separately. No host sysctl is changed. Capture and
  export still share a worker; CPU overload, long scans or slow export can
  still cause loss. AF_PACKET capture drops do not stop the worker or export.
  Runtime reports cumulative `dropped_packets` as an exact decimal string and
  `statistics_complete: false` after any observed drop; flow totals may undercount
  traffic. Both reset on worker restart (initially `"0"` and `true`); loss remains
  recorded across later loss-free polls and shutdown. Counters cover socket drops
  before application filtering/sampling and are read at the configured export-scan
  interval. Capture/statistics socket errors and export failures remain fatal.
  Running does not verify collector delivery or loss-free capture.
  Versions 1 and 5 represent IPv4; v9 and IPFIX represent IPv4 and IPv6,
  with template IDs 256/257 refreshed in every export packet, 64-bit counters,
  protocol/ports/flags/TOS/timestamps, and sampling interval/algorithm elements.
  Version 9 sequence counts packets; IPFIX sequence counts data records, and
  IPFIX timestamps are epoch milliseconds. Unsupported families, fragments,
  and IPv6 jumbograms are excluded/flagged in status rather than misparsed.
  Version 1 uses a 16-byte header, 48-byte records, at most 24 records per packet,
  network-byte-order integers, and TCP flags at record offset 40 (v5 uses 37).
  V1 has no sequence or sampling-interval metadata fields: configured capture
  sampling still applies, reported counters describe captured samples and are
  not artificially multiplied; runtime exposes `sampling_metadata: false`.
  Next-hop/interface-index fields remain zero where not measured. `capture_filter`
  accepts exactly empty, `ip`, `ip6`, `tcp`, `udp`, `icmp`, or `icmp6`; other
  expressions are rejected, not silently ignored. Filters run natively after
  bounded protocol parsing; they are not arbitrary BPF programs. Version 5
  sampling is limited to 16,383. No BPF compiler, softflowd control
  socket, or external exporter is used. General idle defaults to 60 seconds,
  maximum life 3,600 seconds, scan/export interval one second; protocol-specific
  idle values fall back to general. Explicit protocol idle/maxlife zero disables
  that timeout; explicit `expint: 0` scans each bounded capture poll.
  For an isolated accounting microbenchmark (not a NIC throughput test), run
  `cargo test -p netcontrol-services --release --locked flow_accounting_throughput
  -- --ignored --nocapture`; it exercises repeated flows and capacity churn,
  verifies packet conservation, and prints elapsed time for one million updates.
* **Gateway monitoring:** native raw ICMPv4/v6, bound source and interface,
  with explicit routing table 254 (main) or 10000–19999;
  the native backend derives internal host-source rules before starting workers.
  Enabled monitors sharing a source must share a table. The service layer
  validates explicit routes without requiring a public policy-rule collection;
  callers remain responsible for operational routing. Route lookups request
  the actual policy-selected table as well as the matching FIB route, with
  effective rtnetlink table/interface/next-hop validation before each probe,
  nonce/id/sequence checks, rolling loss/RTT/stddev/percentiles/consecutive RTT
  variation, warmup, and failure/recovery holds. Missing/late/duplicate replies
  are not successes. No configured-route mutation or automatic failover.
  `mode: "explicit"` is the default. DHCPv4 mode omits pinned source/gateway/table;
  this manager reports waiting/Unknown until the native lease coordinator supplies
  a binding. The coordinator uses public `GatewayProbe` to reuse the same ICMP
  engine and shutdown/snapshot lifecycle without restarting unrelated services.
  DHCP FIB checks include the bound output interface and private per-probe socket
  mark, matching native private rules without collisions between same-WAN monitors.
  Runtime rows expose mode/interface, nullable resolved
  source/gateway/table and waiting/error reason; no lease is copied into settings.

DNS is resolved natively through `/etc/hosts` and bounded UDP A/AAAA requests to
at most two `/etc/resolv.conf` nameservers. It deliberately rejects truncated or
unsuccessful replies and has no TCP-DNS/search-domain/resolver-daemon fallback.
Only the first resolved endpoint is connected; failed endpoints are errors,
not silently substituted configurations.

## Statistics

`statistics(path, query)` accepts no query parameters:

* `/api/v1/statistics/gateways[/<name>]`: existing gateway sample/monitor shape.
* `/api/v1/statistics/vnstat[/host|managed]`: this crate returns
  `{ "schema": "netcontrol-services/counters/v1", "scopes": { ... } }`; the native
  backend adds its opaque string `scope` identity before the HTTP response.
  Scope records include `interfaces` (last/raw/cumulative counters and reset
  identity) and `history` (timestamp/interface/delta/reset). All byte/packet
  counter values are decimal strings, never precision-losing JavaScript numbers.

The `/api/v1` prefix may be omitted for the native adapter's internal dispatch.
The query string must be exactly empty: any nonempty string, including
`scope=host`, `limit=1`, unknown keys, and whitespace, is rejected. Only the base
path and exact `/host` or `/managed` suffix are valid; trailing slashes, extra
segments, and unknown scopes are errors. The HTTP/core adapter maps these
paths/scopes before dispatch; disabled/unready/failed collectors are unavailable
errors, not measured empty databases. Both canonical and internal path forms
are covered by exact-body tests.
Interface/protocol kernel statistics belong to the native network adapter, not
this crate. Syslog forward counts indicate writes, not confirmed remote receipt.
NTP offset/delay metrics describe accepted samples, not a synchronization promise.

### JSON field reference

All timestamps below are RFC3339 UTC strings. Optional properties are omitted
until observed; gateway metrics/time properties instead use explicit `null`.
Service status does not contain authentication/identity records. API
authentication and permissions must be enforced by the caller; operator opt-ins
are not substitutes for user authorization.

Common enabled appliance row:

```json
{
  "name": "ntp",
  "scope": "host",
  "state": "running",
  "started_at": "2026-10-19T05:00:00Z",
  "sample_status": "available",
  "server": "time.example.test",
  "offset_ms": 0.125,
  "delay_ms": 1.5,
  "requested_slew_ms": 0.125,
  "uncorrected_offset_ms": 0.0,
  "discipline": "slew_only",
  "collected_at": "2026-10-19T05:00:01Z"
}
```

* NTP `sample_status`: `warming_up|available|unavailable`; `server` string;
  `offset_ms` signed number, `delay_ms` nonnegative number; optional `error`
  string. `requested_slew_ms` is the signed correction requested from Linux,
  bounded to +/-500; `uncorrected_offset_ms` is the measured sample offset minus
  that requested correction, **not** the current measured clock error or proof
  that the asynchronous adjustment completed. `discipline` is `slew_only`.
  A running worker/available sample does not mean synchronized; large initial
  offsets may require prolonged slewing. A previous successful sample remains labeled with its original
  `collected_at` when a later polling round fails; `sample_status: unavailable`
  and `error` indicate staleness, not a current successful correction.
* Syslog adds `source: "journald"` and
  `host_source: "/run/systemd/journal/syslog"`; the former `backend_source` and
  `kernel_source` fields are removed. `forwarded_records` is a nonnegative
  integer, reset per worker start. It counts complete
  records written to every configured destination, not acknowledgments.
* Each `vnstat-host`/`vnstat-managed` row adds
  `schema: "netcontrol-services/counters/v1"`, `database_directory` path,
  `collected_at`, and an `interfaces` map described below.
* DHCP row: `interface`, `name: "dhcp-relay"`, `scope: "managed"`, `state`,
  `started_at`, optional `error`. All enabled relay interfaces share the
  exclusive socket worker; a worker error affects every enabled relay row.
  Disabled rows contain only `interface` and `state: "disabled"`.
* Exporter row: `name` instance identity, `scope: "managed"`, `state`,
  `started_at`, `export_version: 1|5|9|10`, `address_family: "ipv4"|"dual"`,
  `fragments: "excluded"`, `capture_filter`, `sampling_rate` integer,
  `sampling_metadata` boolean (false only for v1); after collection, nonnegative integer
  `active_flows`, `exported_flows`, `excluded_packets`, `filtered_packets`,
  `malformed_packets`; optional `error`.
* Disabled appliance rows have only `name`, `scope`, `state`; disabled exporter
  rows only `name`, `state`. Enabled-but-stopped rows have the same identity
  properties with `state: "stopped"`.

Gateway row:

```json
{
  "name": "uplink",
  "process_state": "running",
  "sample_status": "warming_up",
  "health": "unknown",
  "started_at": "2026-10-19T05:00:00Z",
  "collected_at": "2026-10-19T05:00:00Z",
  "health_changed_at": null,
  "last_success_at": null,
  "sent": 1,
  "received": 0,
  "lost": 0,
  "pending": 1,
  "variation_pairs": 0,
  "loss_percent": null,
  "rtt_min_ms": null,
  "rtt_max_ms": null,
  "rtt_avg_ms": null,
  "rtt_stddev_ms": null,
  "rtt_p50_ms": null,
  "rtt_p95_ms": null,
  "rtt_variation_ms": null
}
```

`process_state` uses worker states; `sample_status` is
`disabled|stopped|warming_up|available|unavailable`; `health` is
`unknown|up|degraded|down`. Probe counts are integers; loss is a nullable number
in percent; all RTT fields are nullable numbers in milliseconds. Worker errors
force `sample_status: unavailable`, `health: unknown`, and add `error`.

Gateway collection response: `{ "sample": SAMPLE, "gateways": [ROW] }`.
Individual response: `{ "sample": SAMPLE, "monitor": ROW }`.
`SAMPLE` has `scope: "managed"`, `started_at: null`, current `collected_at`,
and `status: "available"|"partial"`; it is partial unless every requested
monitor is available or disabled.

Native traffic HTTP response example (synthetic, `/api/v1/statistics/vnstat/managed`):

```json
{
  "schema": "netcontrol-services/counters/v1",
  "scope": "linux:11111111-1111-4111-8111-111111111111:4:4026533000",
  "scopes": {
    "managed": {
      "schema": "netcontrol-services/counters/v1",
      "scope": "managed",
      "interfaces": {
        "lan0": {
          "ifindex": 3,
          "boot_id": "synthetic-boot-id",
          "namespace_id": "4:4026533000",
          "last": {
            "rx_bytes": "120", "tx_bytes": "100",
            "rx_packets": "2", "tx_packets": "1"
          },
          "total": {
            "rx_bytes": "20", "tx_bytes": "0",
            "rx_packets": "1", "tx_packets": "0"
          },
          "resets": 0,
          "last_seen": "2026-10-19T05:00:00Z",
          "present": true
        }
      },
      "history": [{
        "collected_at": "2026-10-19T05:00:00Z",
        "interface": "lan0",
        "delta": {
          "rx_bytes": "20", "tx_bytes": "0",
          "rx_packets": "1", "tx_packets": "0"
        },
        "reset": false
      }]
    }
  }
}
```

The base `/api/v1/statistics/vnstat` reply has the identical envelope with both
`scopes.host` and `scopes.managed`; each DB has its own corresponding `scope`.
The `/host` reply contains only `scopes.host`. The added top-level `scope` is an
opaque native-backend identity (not `host` or `managed`); store/compare it without
parsing. This crate's direct return value omits only that top-level decoration.
The simulator truthfully returns an unavailable error instead of this measured
native database. The HTTP/core layer requires `state.read`; it returns 400 for
nonempty queries, 404 for invalid scopes/path suffixes, and 503 for disabled,
unready, or failed collectors. No write route or query-based scope selector exists.

Persisted traffic records use **JSON unsigned integer numbers** for the four
counter fields; only public runtime/statistics output converts these to decimal
strings. `ifindex`, `resets`, and probe/record counts remain JSON integers.
File format and public encoding are intentionally distinct. `scope` is exactly
`host|managed`; additional/unknown persisted fields and incompatible schemas
are rejected. Disabled/unready/failed traffic workers produce errors instead of
returning fabricated zero histories. Pending frontend action: replace child
process/PID displays with worker states; optionally expose the new traffic
history route, counter encoding, and reset markers. This is an unreleased
breaking-contract change; recommended release bump is **major**, with no
approved baseline or release assigned.

## Validation

Portable tests: `cargo test -p netcontrol-services`.

On Windows, all 33 portable protocol/lifecycle/persistence tests passed, as did
`cargo clippy -p netcontrol-services --all-targets -- -D warnings`. Linux musl source and ignored-test compilation passed with the default TLS
feature using
`cargo check -p netcontrol-services --target x86_64-unknown-linux-musl --tests`.
The matching strict all-target Clippy check and
`cargo test -p netcontrol-services --target x86_64-unknown-linux-musl --no-run`
also passed, including the rustls/ring provider and linked Linux test executable.
These are cross-compilation/link checks, **not Linux execution**. No-default-
feature source/strict-Clippy/link checks also passed.

Linux privileged checks:
`NETCONTROL_INTEGRATION=1 cargo test -p netcontrol-services -- --ignored`.
These explicitly require namespace/raw-socket privileges and run on isolated
network-namespace threads. They exercise actual IPv4/IPv6 echo sockets,
AF_PACKET/v1/v5/v9/IPFIX UDP export including IPv6, counter persistence/joins, and an NTP UDP fixture
without changing the host clock. They do not establish full production
interoperability, TLS PKI end-to-end behavior, real DHCP client topology,
privileged clock mutation, or whole-host log ownership safety on a target
appliance; those require dedicated Linux deployment checks.
