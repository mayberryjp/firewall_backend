# Native mDNS / DNS-SD build specification

Status: **implemented, Unreleased**, 2026-10-25. This is the build and
qualification specification; the current frontend/API contract is in
[section 6.1.7](../FRONTEND_SPEC.md#617-native-mdns--dns-sd).
Implemented does not mean complete Avahi parity or production qualification.

### Implementation and qualification status

- Typed configuration, scoped authorization, API/CLI, simulator, native worker,
  reflection, service/provider filtering, legacy correlation, local publishing,
  status and transaction recovery are implemented.
- A bounded native Rust codec was selected rather than adding Hickory: support
  is explicit for A/NS/CNAME/PTR/HINFO/TXT/AAAA/SRV/DNAME/NSEC; other RR types
  cause counted datagram drops. There is no external DNS/Avahi library dependency.
  The service crate reuses core mDNS types through a local workspace dependency.
- Same-family sockets are per-interface and bound to their device. Route-netlink
  monitoring starts before snapshots/socket preparation and gates receive,
  maintenance and sends. Required deletion/replacement, rename, administrative
  down or lost/invalid notifications retire the failed attempt's sockets. The
  owned supervisor reports errors and retries preparation automatically with
  capped backoff; configuration verification is not a service-health gate.
  Valid address changes block stale sockets and refresh both families. Snapshot
  polling remains a backstop; the final notification check/send is not atomic.
- Egress payload is at most 1232 bytes, reduced for MTU. RR-boundary splitting
  and TC continuations are implemented; an unfit individual record/question
  section drops/counts. A publisher probe RRset that cannot fit rejects startup.
  Workstation publication uses hostname instance/conventional port 9; no
  SSH/SFTP service is advertised.
- Portable and isolated privileged Linux veth/namespace tests exist. Full
  VLAN/nftables/MLD, cross-device/Avahi interoperability, reference-host load,
  reboot and appliance acceptance remain unverified. Milestones below include
  acceptance requirements that are not yet release evidence.

## 1. Objective and reference scope

Implement the useful pfSense Avahi feature set as in-process Rust workers:
cross-VLAN mDNS/DNS-SD reflection, interface selection, service/host filtering,
IPv4/IPv6 selection and optional appliance information publishing. Do not install,
link to, invoke or supervise Avahi, use its D-Bus service, or introduce a Go
component. Reuse the existing transaction, native ownership and worker systems.

The reference is the pfSense package settings and generated configuration
inspected on 2026-10-25, not every API or capability in upstream Avahi:

| pfSense Avahi capability | Proposed Netcontrol treatment |
| --- | --- |
| Enable/disable; allowed or denied interface list | Supported, with the managed-LAN boundary below |
| Bidirectional reflection among selected interfaces | Supported; one reflection domain per appliance |
| Disable IPv4 or IPv6 | Supported as positive enable flags |
| Allowed service-type or provider-host names | Supported with explicit DNS-name matching semantics |
| Publishing addresses, HINFO, workstation and browse domain | Supported in the publishing milestone, off by default |
| Override publishing hostname/domain | Supported; independent of cosmetic `system.domain` |
| Publish AAAA over IPv4 / A over IPv6 | Supported as record-publishing options, not transport translation |
| Start/stop from CARP VIP ownership | Deferred: Netcontrol has no equivalent CARP ownership contract |
| External default SSH/SFTP service files | Not imported; never advertise an SFTP service that does not exist |
| Arbitrary service-file or D-Bus registrations | Out of scope |

The inspected package disables wide-area DNS-SD and does not expose
`reflect-ipv`. Accordingly, no IPv4-to-IPv6 packet reflection is proposed.
AAAA records in an IPv4 DNS packet are different from translating a packet to
IPv6. SSDP/UPnP, IGMP/MLD multicast routing, multicast media streams and arbitrary
UDP relaying are **not** Avahi reflection and are outside this build.

Discovery does not establish connectivity. Clients still need routes and
explicit firewall permissions to the advertised service address/port. IPv6
link-local addresses are not usable across VLANs; neither NAT nor address
rewriting is part of this service.

### Intentional differences from the reference

- Only configured, administratively up Ethernet/VLAN interfaces with `role: "lan"`
  participate. No unmanaged interfaces, WAN, unassigned roles, WireGuard,
  loopback or host-wide discovery. Dummy interfaces are test-only.
- Empty allow mode never means all host interfaces. Deny mode operates only on
  the eligible managed-LAN universe, not pfSense's potentially unassigned links.
  Adding an eligible interface changes deny-mode membership and must be shown
  in transaction review.
- Reject ambiguous/noncanonical filter patterns rather than guessing glob or
  substring behavior. This is functional filtering parity, not an undocumented
  byte-for-byte clone of Avahi's matching implementation.
- Require IP TTL / IPv6 hop limit 255 for admitted reflected traffic. This is a
  deliberate stricter admission rule than configurations that do not check TTL;
  incompatible senders must be visible through counters, not silently accepted.
- No automatic advertisements of management endpoints; optional publishing
  cannot imply arbitrary command, FTP or SFTP support.
- No exact QU/unicast-preservation claim: upstream Avahi itself documents loss
  of the unicast-reply bit during reflection. The supported behavior is below.

## 2. Configuration contract

Add an always-serialized top-level `config.mdns` object. Defaults are disabled;
no existing configuration starts reflecting or publishing. Use the existing
`ObjectMetadata` type, validation limits and operational stripping.

Synthetic **configuration fragment**, not a complete transaction:

```json
{
  "mdns": {
    "enabled": true,
    "metadata": {
      "display_name": "Trusted and device discovery",
      "description": "Allow printer discovery across selected LANs"
    },
    "interface_mode": "allow",
    "interfaces": ["lan10", "lan20"],
    "ipv4": true,
    "ipv6": false,
    "reflection": {
      "enabled": true,
      "filters": ["_ipp._tcp.local."]
    },
    "publishing": {
      "enabled": false,
      "hostname": "",
      "domain": "local.",
      "addresses": false,
      "hinfo": false,
      "workstation": false,
      "browse_domain": false,
      "aaaa_on_ipv4": false,
      "a_on_ipv6": false
    }
  }
}
```

| Field | Type / default / validation |
| --- | --- |
| `enabled` | Boolean, false |
| `metadata` | Existing metadata object; omitted input uses existing defaults |
| `interface_mode` | `"allow"` or `"deny"`, default `"allow"` |
| `interfaces` | Unique managed interface names, default `[]`, maximum 32; normalized sorted order |
| `ipv4`, `ipv6` | Booleans, each true by default; at least one when enabled |
| `reflection.enabled` | Boolean, false |
| `reflection.filters` | Unique DNS names, default `[]` means all services; maximum 64 entries |
| `publishing.enabled` | Boolean, false; independent of reflection |
| `publishing.hostname` | String, default `""`: use validated configured `system.hostname`; otherwise explicit lowercase single hostname label, 1..63 bytes |
| `publishing.domain` | Canonical DNS name with trailing dot, default `"local."`; allow only `local.` or its subdomains, maximum 253 textual bytes |
| Remaining publishing flags | Booleans, all false |

Rules:

1. Resolve the effective interface set from the full candidate. Enabled
   reflection needs 2..32 eligible links; publishing without reflection needs
   1..32. Enabling the service with neither function is an error.
2. Allow entries must be eligible candidate links. Deny entries must identify
   configured Ethernet/VLAN links; excluding a WAN is permitted but redundant.
   Missing/duplicate names fail. Membership is not inferred from subnet numbers
  or interface naming conventions. Eligibility uses the selected interface's
  own candidate `up`/`role` fields, not observed link state or VLAN parent
  fields. Rejected allow entries include those candidate values in the
  existing `422` error text.
3. `config.ipv6_enabled: false` suppresses operational IPv6 transport and AAAA
   publication while retaining the configured mDNS preferences. Effective IPv6
   is `config.ipv6_enabled && mdns.ipv6`. Require at least one effective family.
   There is no cross-family packet forwarding.
4. Validate disabled objects too: types, field limits, referenced names and
   syntax remain valid. Minimum active-link counts and runtime socket checks
   apply only when enabling the corresponding function.
5. Filter entries are canonical absolute service-type names such as
  `_ipp._tcp.local.`, DNS-SD subtype names, exact service-instance names such
  as `_udp._govee-lan._udp.local.`, or provider host names such as
  `printer.local.`. An instance filter matches only that instance; use
  `_govee-lan._udp.local.` to select every instance of that service.
  DNS comparison is case-insensitive; normalize ASCII case
   and require trailing dots. Validate DNS labels/wire length with the chosen
   DNS codec, allowing underscore service labels. No arbitrary regex/glob,
   instance-label substring matching or non-local names.
6. Publishing hostname fallback must resolve to a nonempty valid configured
   hostname when publishing is enabled; no ambient OS hostname fallback.
   Changing `system.hostname` must therefore update publishing's operational
   input even though `system` is otherwise stripped from native configuration.
   `system.domain` remains cosmetic and must not change mDNS.
7. Reject incoherent publishing combinations: require at least one publication
   flag when publishing is enabled; cross-family flags require their transport
   and `addresses`; IPv6 global policy still wins. HINFO is an explicit
   information-disclosure opt-in. Do not expose raw DNS records or XML input.
8. Core semantic errors return existing `422` JSON errors. Retain the current
   transaction handling of unknown `config` keys and `ignored_fields`; this
   feature must not invent a conflicting unknown-field policy.

Keep this a single bidirectional reflection domain, matching the package model.
Directional policies, multiple domains and per-device authorization are not
part of this target schema.

## 3. Native architecture

### Component ownership

| Component | Build work |
| --- | --- |
| [core model](../crates/netcontrol-core/src/model.rs) | Typed `MDNSConfig` and nested types; defaults, exports, normalization, validation, metadata and effective-family handling |
| [engine](../crates/netcontrol-core/src/engine.rs) | `mdns.write`, changed-area authorization, proposed reads/repair, aggregate repair permission guard |
| [simulator](../crates/netcontrol-core/src/simulator.rs) | Round-trip configuration and explicit simulated status, no fabricated packets |
| [service configuration](../crates/netcontrol-services/src/config.rs) | Strict operational parser, resolved membership and validation |
| [services manager](../crates/netcontrol-services/src/lib.rs) | One `mdns` worker in managed namespace; preflight, expected worker set, start/stop, status and verification |
| [worker lifecycle](../crates/netcontrol-services/src/worker.rs) | Reuse readiness handshake, owned thread, bounded I/O and joined shutdown |
| [native backend](../crates/netcontrol-native/src/linux.rs) | Applied-state input, address/link refresh, worker verification, apply/rollback/boot recovery |
| [firewall planner](../crates/netcontrol-native/src/firewall_plan.rs) and [nftables backend](../crates/netcontrol-native/src/linux/firewall.rs) | Explicit operator input rules and packet-path tests; no implicit forward exceptions |
| [CLI](../crates/netcontrold/src/cli.rs) | Typed candidate editor and inspection; no direct service bypass |
| [frontend contract](../FRONTEND_SPEC.md) | Types, forms, permissions, status, warnings and acceptance once implemented |

Add a portable protocol module and Linux socket implementation within
`netcontrol-services`, preferably `mdns.rs` plus `mdns/linux.rs` once the split
is useful. Do not create a new daemon or crate just for this worker.

The implementation uses a bounded native Rust wire codec rather than the
initial Hickory candidate, with a deliberately restricted RR set as described
above. Compression pointers are decoded before filtering and never copied into
rebuilt packets. Portable tests exercise malformed/compressed packets and
fixed resource limits; native fixtures exercise actual wire exchanges. Further
fuzzing and independent implementation interoperability remain qualification
work. No resolver, desktop discovery daemon or external codec was added.

### Linux sockets and packet path

- UDP 5353; IPv4 multicast `224.0.0.251`, IPv6 multicast `ff02::fb`.
- Create sockets after the worker enters the pinned managed network namespace.
  Use explicit multicast membership per ifindex, IPv6-only IPv6 sockets,
  destination/ingress packet info and received TTL/hop-limit ancillary data.
- Prefer one receive socket per family with explicit egress `sendmsg` interface
  selection; prove Linux membership isolation (`IP_MULTICAST_ALL=0` where
  applicable), reuse/binding and interface scoping in the socket spike. A
  per-interface socket layout is acceptable only if it passes the same tests.
- Send using the egress interface's local address, UDP source port 5353 and
  TTL/hop limit 255. Never spoof the original sender or use AF_PACKET injection
  to bypass the host firewall. IPv6 uses the correct link-local scope.
- Admission requires configured ingress and destination group, valid unicast
  source, expected family/port, hop limit, complete ancillary data and a valid
  bounded DNS packet. Unicast responses are accepted only for an outstanding
  reflected exchange. Never admit unrelated unicast DNS into reflection.
- Existing host services opt-in also gates host-mode mDNS. Namespace mode stays
  in its selected namespace. Native enable on non-Linux fails explicitly.
- Detect conflicting UDP 5353 users during preflight and report a useful error.
  Port binding alone is not exclusive when multicast sockets are reusable:
  inspect namespace socket ownership and define a cooperative-reflector
  ownership check. Do not claim that every competing remote reflector can be
  detected, kill processes, or disable systemd-resolved's mDNS automatically.
- Subscribe to route-netlink before the initial snapshot/socket preparation.
  Required link deletion/replacement, rename or administrative down latches an
  error, including recreation with identical name/index/MAC/address. Malformed,
  truncated or lost notifications fail closed, as do exceeded monitoring bounds:
  64 datagrams per drain, 64 KiB per datagram, 512 messages per datagram and
  8192 deletion tombstones. Receive, maintenance and sends check the monitor.
  Valid address replacement blocks stale sockets while refreshing both families.
  Link failure triggers automatic resource reopening with capped backoff, not
  silent membership shrinkage. Failures stay visible while recovery is pending.
  The last check and send are non-atomic; no mathematical TOCTOU guarantee.

### Reflection semantics

Reflect protocol messages, not arbitrary IP packets:

1. Same-family queries, replies, unsolicited announcements, probes and TTL-zero
   goodbyes can cross to every other effective interface. Never transmit back
   to the ingress link or replay an ingress packet between address families.
2. Preserve DNS record TTLs, cache-flush semantics and known-answer sections.
   IP TTL/hop limit is newly set to 255; it is not a DNS record TTL.
3. Normalize reflected QU questions to multicast-answer questions. Clients
   continue listening on multicast; do not promise preserved unicast preference.
   Handle direct unicast replies to outstanding worker traffic deliberately,
   not as a general-purpose relay.
4. Support legacy queries from ephemeral source ports with a bounded
   requester mapping. Forward discovery as mDNS and reconstruct legacy replies
   to the original link/requester/port, preserving its transaction ID/question
   section, clearing cache-flush bits and limiting answer TTL to 10 seconds.
   Do not key normal mDNS exchanges only by DNS ID (usually zero).
5. Reencode any modified packet with fresh compression offsets. Never remove
   raw byte ranges from compressed DNS. Preserve opaque RR data only where
   the codec can safely reserialize it; reject unsupported name-bearing forms
   explicitly and count them. No success-shaped truncated messages.
6. Bound input to 9000 DNS payload bytes after kernel UDP reassembly. Detect
   receive/control truncation. Emit messages within the chosen egress UDP
   payload/MTU budget; protocol-correct splitting/TC and known-answer
   continuation are acceptance requirements, not arbitrary byte truncation.
   Oversize/unsupported cases are counted and visible; do not promise support
   for every jumbo advertisement before interoperability tests pass.
7. Do not become a caching resolver. Keep only bounded transient state for
   duplicate suppression, outstanding queries and filter dependency tracking.
   Never synthesize stale device advertisements from that state.

### Filtering without collateral leakage

An empty filter list reflects all valid mDNS traffic within the selected domain.
With filters, process every DNS section, not just the first question or record:

- Service types admit matching PTR discovery, instances' SRV/TXT records and
  referenced host A/AAAA/NSEC records needed to use that allowed service.
  Handle subtype queries and `_services._dns-sd._udp.local.` enumeration.
- Provider-host filters admit that host and discovered services whose SRV
  target is the host. They do not mean every host sharing its IP address.
- Exact-instance filters admit the parent service's PTR/ANY browse queries,
  matching PTR replies, the selected instance's SRV/TXT and its referenced
  host records. Service enumeration may expose the parent service type, not
  other instances. Questions never authorize response/known-answer records.
- Build dependency associations per ingress link and family, bounded by RR TTL
  and resource limits. Do not use DNS transaction IDs as service identity.
- Mixed allowed/disallowed packets must be reconstructed with only permitted
  questions, records and dependencies, including additional/authority sections.
  Omit unresolved dependencies until their relationship is established; never
  widen to "allow entire packet" on an unknown association or full cache.
- Apply the same policy to announcements, probes, known answers and goodbyes.
  When a shared address is needed by an allowed service, its hostname/address
  is necessarily disclosed; document that boundary.
- Advertised names/records are unauthenticated and spoofable. This is discovery
  filtering, not an authorization boundary or replacement for forwarding policy.

### Loops, load and resource bounds

Use these initial fixed limits, exposed in status and benchmarked before merge;
do not add a tuning API until measurements justify it:

| Resource | Initial bound |
| --- | --- |
| Effective interfaces | 32 |
| Received DNS payload | 9000 bytes |
| Parsed questions + resource records | 512 per message; bounded compression depth/work |
| Recent transmission fingerprints | 8192 entries, 1-second expiry, bounded replacement |
| Filter associations | 8192 entries; DNS TTL bounded to 120 seconds of tracking |
| Legacy/unicast outstanding requesters | 1024 entries, 5-second expiry |
| Ingress token bucket | Per interface/family: 200 packets/second, burst 400 |
| Egress token bucket | Per interface/family: 200 packets/second, burst 400 |
| Outbound queue | 256 datagrams and at most 2 MiB total per worker |
| Poll/shutdown reaction | At most 100 ms blocking poll; shutdown within 1 second in normal operation |

Fingerprint actual normalized transmitted payload plus family and egress link;
exclude expected local echoes without globally suppressing another VLAN's
independent identical query. Maintain a separate bounded recent-reflection
guard for returned packets and test repeated queries, probes and goodbyes so
the guard does not prevent legitimate retransmission.

These guards and rate limits mitigate loops; they cannot prove a loop-free
topology with independent reflectors rewriting packets. Require **one active
reflector per connected reflection domain**. Drop and count overload rather than
building an unbounded queue, log rate-limited warnings and keep servicing stop
requests. Rate-limit/capture drops alone are not fatal worker health failures.

## 4. Firewall, lifecycle and recovery

### Firewall contract

Reflection is local receive plus local send, not IP forwarding. Existing
forward-chain permits alone do not enable it. With host-input filtering,
operators must allow UDP destination port 5353 on each participating interface.
The current input-rule model can express ingress/UDP/port but cannot narrowly
match only these multicast destination addresses; document that wider local
5353 permit and enforce group/source admission inside the worker.

Do not silently insert an accept rule before an operator's deny policy. A
single full-package transaction may include the mDNS config and input-rule
edits; those firewall edits additionally require `firewall.write`. External
nftables/firewall policies remain operator responsibilities. IPv6 membership
uses normal kernel MLD/ICMPv6 behavior; include membership behavior under
restrictive input policies in integration acceptance.

No automatic LAN-to-device unicast permits, NAT, forwarding sysctl edits,
IGMP proxying or broad multicast permits. Local output restrictions installed
outside Netcontrol may still block emission. Readiness is not end-to-end
delivery verification, even if the socket joins successfully.

### Transaction integration

- Add `mdns.write` to the authoritative permission list and changed-area checks,
  including metadata-only edits. Adding it is not a permission-grant migration.
  Existing keys without it cannot change mDNS.
- Retain full-package submission, base-revision conflict, confirmation deadline,
  durable intent, restore and recovery semantics. Do not expose direct live
  writes or an independent persisted mDNS configuration.
- Include operational mDNS configuration in service comparison and native
  observation. Exclude metadata from drift. Include derived publishing hostname
  and effective interfaces/families so upstream config changes cannot leave a
  stale worker. Clear transient caches on membership/filter changes.
- Extend `expected_workers` / `workers_current` with `mdns`; identical service
  config after network-only apply must still restart a stopped worker.
- Prepare sockets and memberships before reporting ready. On failed startup,
  tear down every partially prepared socket and retry the requested configuration
  with capped backoff. Report a recovering error without claiming readiness.
  Invalid configuration and structural transaction failures still use the
  existing apply/rollback path. Do not turn packet drops or malformed peer
  messages into failed configuration verification.
- Genuine socket, required-interface or worker failure is an explicit service
  error, not a global configuration-health gate. Verification checks requested
  configuration and active owned supervisors, including recovering workers;
  it does not assert network delivery or erase service errors to confirm.
- Stop/join the worker before changing/removing links; prevent send-after-stop.
  Rollback, explicit repair, restart and boot reapply restore configured
  membership, not vanished discovery caches or client sessions.
- Preserve existing service-manager permission behavior: repairs can restart
  all managed services. Every repair entry point must require `mdns.write` when
  mDNS is enabled, and mDNS repair must require other enabled-service permissions.

## 5. HTTP, CLI and runtime surfaces

These paths are implemented in the unreleased backend:

| Method / path | Permission | Proposed behavior |
| --- | --- | --- |
| `GET /api/v1/services/mdns` | `state.read` | Complete committed `MDNSConfig`; independent of live observation |
| `GET /api/v1/services/mdns/status` | `state.read` | Applied worker snapshot, including provisional configuration |
| `POST /api/v1/services/mdns/reconcile` | `state.read`, `transactions.write`, `mdns.write` and existing enabled-service repair permissions | Bodyless existing repair workflow; `200 RuntimeState`; no revision |
| `POST /api/v1/transactions` | `transactions.write`, `state.read`, changed-area permissions | Full config with `mdns`; existing `202` transaction/confirmation flow |

New reads reject query parameters with `400`; the repair rejects nonempty
query/body rather than silently ignoring them. Authentication is the existing
API key (`401`/`403`). Reuse existing `409` conflict/drift/recovery,
`422` validation, apply/repair error and rollback mappings; do not introduce
inconsistent status codes in a new service path.

Add `mdns` to `/api/v1/runtime`, service status aggregation and full config
state/revisions, including `/api/v1/revisions/latest`. History/export contains
configuration, not runtime peer names, query mappings or caches.

Status contract:

- Envelope `{instances: [row], error: string}` with one row for the singleton.
- Row `name: "mdns"`, `scope: "managed"`, `enabled: boolean`,
  `state: "disabled" | "simulated" | "running" | "stopped" | "error"`.
- `started_at: string | null`, `collected_at: string | null`, `error: string | null`.
- `effective_interfaces: string[]`, `effective_families: ("ipv4" | "ipv6")[]`,
  `reflection_enabled: boolean`, `publishing_enabled: boolean`.
- All cumulative counters are exact unsigned decimal **strings**, following
  service counter conventions; reset on worker start:
  `received_packets`, `transmitted_packets` (successful destination sends),
  `received_bytes`, `transmitted_bytes`, `malformed_packets`,
  `hop_limit_drops`, `policy_drops`, `duplicate_drops`, `rate_limit_drops`,
  `queue_drops`, `oversize_drops`, `unsupported_record_drops`,
  `receive_drops` (nullable if kernel cannot report), `send_errors`.
- `statistics_complete: boolean`; false after known receive/queue/rate loss,
  or when receive-loss accounting is unavailable. It is not a delivery metric.
- Bounded warnings with stable reason strings, no captured TXT data, device
  inventories, arbitrary query contents or packet dumps. No process IDs.
  Expose the fixed resource limits alongside counters, not hidden tuning knobs.

Status must remain readable when mDNS itself has failed; do not call the
healthy-managed-network observation path to construct its error row. The
simulator reports `simulated` with no invented traffic or verified membership.

CLI: candidate commands `mdns JSON`, `no mdns` (reset to disabled defaults),
`show mdns`, `show mdns status` and `reconcile services mdns`. Use the same
Engine permission/transaction paths. Existing `show running-config`, candidate
JSON-pointer edits, compare and historical restore preserve the new object.

## 6. Optional publishing milestone

Publishing is a real responder, not periodic blind UDP broadcasts:

- Implement RFC 6762 probing, conflict tie-breaking, announcements, refresh,
  known-answer suppression, QU/legacy response rules and goodbye records.
  Keep publisher and reflector decisions separate to avoid reflecting locally
  published packets back into themselves.
- Publish only the appliance's eligible-interface addresses; never WAN,
  private keys, API keys, version details or discovered remote device addresses.
  Scope link-local addresses correctly; reflection of a link-local address is
  not a claim it is routable. Cross-family record flags only affect local
  publications, not transparent device-record reflection.
- On hostname conflict, stop that publication and show an explicit error/warning;
  do not silently mutate configured identities or rename other devices.
  A failed required publisher must follow service verification rules.
- `workstation` advertises the appliance workstation record, not general
  service-file registration. HINFO reveals only the deliberately selected
  OS/architecture fields. Browse-domain publishing follows RFC 6763.
- The explicit hostname/domain are unrelated to unicast DNS/resolver search
  domains. No public DNS update or wide-area discovery is performed.
- No default SSH advertisement in this target: the custom SSH interface is an
  API-key configuration CLI, not a general shell; SFTP is absent. Adding its
  discovery later needs a separate, accurately named service contract.

Do not expose publishing flags that merely parse but perform no work. A
reflection-only initial implementation must document its smaller schema/API
and reject unsupported publishing requests rather than simulate success.

## 7. Build milestones and acceptance gates

### M0 - protocol/socket feasibility

Prove codec support, UDP 5353 ownership/coexistence, ingress metadata, IPv4 and
IPv6 joins, per-egress source selection, QU normalization, legacy correlation
and multi-interface duplicate suppression in an isolated Linux namespace.
Resolve address-change notifications, MTU splitting and filter associations
with executable fixtures before committing to the final wire engine.

Exit: packet captures and tests show correct scope, source address, source port
and TTL/hop limit; no dependence on an external daemon. Record limitations
before implementing a public schema.

### M1 - core contract and native bidirectional reflection

Add typed config, permission and complete wiring; worker sockets, all-service
reflection, fixed resource limits, runtime status, CLI and transaction recovery.
Default disabled. Test on two and three VLANs and against restrictive host-input
policy. No publishing/filter placeholders accepted.

### M2 - filtered discovery and full reflector qualification

Add service/provider matching, dependency tracking, mixed-packet rebuilding,
enumeration/subtypes, robust multi-packet exchanges and resource exhaustion
tests. Qualify common clients/services on Linux, Windows, Apple devices and
representative printers/casting devices. Casting discovery success must not be
confused with media/control connectivity; SSDP-only devices remain unsupported.

### M3 - opt-in host publishing

Implement the actual responder state machine and publishing controls above.
Only after this milestone claim the target publishing scope. CARP gating,
custom registrations, WAN/point-to-point operation and general multicast remain
excluded, not hidden future work inside a successful response.

### M4 - release/deployment qualification

Cross-crate implementation requires:

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo build --workspace --locked
```

Run focused core/services tests first. Privileged Linux integration follows the
existing opt-in namespace harness; do not use production VLANs as the test lab.

Required automated scenarios:

1. Default disabled, round-trip/full export, normalized metadata, bad names,
   duplicate membership, over-limit input, global IPv6 off and disabled-object
   validation; all permission and historical restore surfaces.
2. Queries and replies in both directions; unsolicited announcements, TTL-zero
   goodbyes, probes/conflicts, known answers, QU, legacy unicast, compressed DNS,
   NSEC, subtypes, service enumeration and mixed allowed/disallowed records.
3. IPv4-only, IPv6-only and dual-stack; verify no family translation, no WAN or
   unselected-interface traffic, no ingress echo and no address spoofing.
4. Loss/malformed/short/truncated/oversize DNS, compression cycles, bad offsets,
   high record counts, wrong hop limit, unknown RRs, unknown associations and
   cache exhaustion. The process survives without widened filtering.
5. Two/three-link fanout, local echo, repeated valid identical queries, remote
   reflector loop fixture, rate/queue limits and exact counter shapes. Under a
   10,000 packet/second synthetic flood, measured egress after the initial burst
   stays within configured buckets, memory plateaus and shutdown is <=1 second
   on the documented reference test host. Specify that host before treating
   timing measurements as release evidence.
6. Linux nftables input drop blocks discovery until the operator adds intended
   local 5353 permits; forward policy is unchanged. Unicast service use still
   requires separate policy. Test IPv6 membership under restrictive input.
7. Network-only apply restarts the worker; interface removal/recreation,
   address replacement, partial bind/join failure, failed apply/rollback,
   pending confirmation, deadline rollback, explicit repair, daemon restart
   and reboot recovery do not leak sockets or detach threads.
8. Status remains usable on genuine worker failure; malformed packets and
   capture/rate loss remain warnings rather than blocking unrelated apply.
9. Publishing tests cover probe conflicts, correct answers/flags/TTL,
   shutdown goodbyes, no sensitive disclosure, disabled options and hostname
   changes; no advertisement of unimplemented services.

Packet captures, emitted DNS fixtures and Linux integration results are
required evidence. A portable parser test, simulator response or successful
socket bind is insufficient to claim interoperability or delivery.

## 8. Frontend and deployment work

Add a **Services > mDNS / Discovery** page with enable, allow/deny interface
selection, family controls, reflection, allowed service/provider names and
advanced publishing. Default publishing and reflection off until explicitly
configured. Explain deny-mode expansion, discovery exposure, firewall
prerequisites, QU limits and the one-reflector rule.

Show configured versus effective interfaces/families; global IPv6 suppression;
applied/provisional versus committed configuration; worker readiness rather than
delivery; drops/incomplete counters; explicit failure/repair. Use standard
nonoverlapping 2..5-second polling and shared draft/apply/confirm workflow.
Preserve config, metadata and disabled flags in import/export/revision restore.

Never auto-open management or discovered service ports. No automatic Avahi
removal; operators resolve competing 5353 ownership before enable. No additional
OS service is installed. Normal native namespace/socket privileges apply;
use existing appliance/host-service opt-in rather than weakening service-unit
hardening. Test OpenRC and systemd lifecycle paths: this service must not inherit
syslog's systemd socket-activation requirement.

The implementation recommends a **minor** release for additive service/config/API
capability (baseline unknown), with any breaking contract changes assessed
explicitly. Nothing here authorizes a version bump, package release or
deployment. The original proposal was documentation-only; implementation
supersedes that availability statement, not the remaining qualification gates.

Open qualification gates: independent codec fuzzing/interoperability,
VLAN/nftables/MLD behavior, full reference-host load and actual deployment/reboot.
Local tests cover cooperative ownership, filter dependencies, MTU/continuations,
identical interface recreation, notification loss and address refresh, but are
not proofs of arbitrary topology, all kernel races or device interoperability.
Exact upstream Avahi parity must not be asserted without comparing behavior fixtures.

## 9. Sources and coordination

Public reference sources inspected 2026-10-25:

- [pfSense Avahi settings](https://github.com/pfsense/FreeBSD-ports/blob/devel/net/pfSense-pkg-Avahi/files/usr/local/www/avahi_settings.php):
  interface modes, filters, publishing and CARP UI.
- [pfSense Avahi configuration generation](https://github.com/pfsense/FreeBSD-ports/blob/devel/net/pfSense-pkg-Avahi/files/usr/local/pkg/avahi/avahi.inc):
  actual daemon settings, disabled wide-area/user publishing and CARP lifecycle.
- [Avahi daemon configuration reference](https://manpages.debian.org/trixie/avahi-daemon/avahi-daemon.conf.5.en.html):
  reflector scope, QU caveat, reflector-loop warning, name filters and
  cross-family behavior.
- [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html) and
  [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html): protocol/responder and
  DNS-SD requirements, not a standard for arbitrary multicast routing.

These are mutable source branches/manuals, not a pinned pfSense release or a
claim that Netcontrol embeds their implementation.

Coordination: [implementation handoff](frontend-handoffs/2026-10-25.md#2026-10-25-17-native-mdns-implementation),
[journal](journal/2026-10-25.md#native-mdns-implementation) and
[canonical contract](../FRONTEND_SPEC.md#617-native-mdns--dns-sd).
