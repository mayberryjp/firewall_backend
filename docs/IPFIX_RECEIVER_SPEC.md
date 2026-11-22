# IPFIX Receiver Requirements for Netcontrol

Audience: collector/receiver developers and operators.
Status: receiver requirements for the **current implemented exporter**;
this document does not claim that a receiver is implemented in this repository
or that third-party collector interoperability has been verified.

The scope is `softflowd[].export_version: 10` only. NetFlow v1/v5/v9 decoding
is not required unless those versions are separately enabled. See the
[exporter specification](NETFLOW_IPFIX_SPEC.md) for appliance configuration,
capture, expiry and runtime APIs.

**MUST** denotes a requirement to receive and correctly interpret this exporter.
**SHOULD** denotes a recommended receiver safeguard or operational practice.
These are requirements for a receiver being built, not new backend features.

## 1. Minimum support

| Area | Receiver requirement |
| --- | --- |
| Protocol | IPFIX version 10, template-based decoding |
| Export transport | UDP; no TCP/SCTP listener or handshake required |
| Outer IP family | IPv4 and/or IPv6 matching the configured collector addresses |
| Record IP family | Decode both IPv4 and IPv6 records, regardless of outer IP family |
| Templates | Template Set 2; templates 256 and 257, each with 13 fields |
| Counters | Exact unsigned 64-bit packet/octet values |
| Timestamps | Unsigned 64-bit Unix epoch milliseconds, not uptime |
| Sampling | Per-record IEs 34 and 35; configurable interval 1..1,000,000, algorithm 1 |
| Flow identity | Directional 5-tuple **plus TOS/traffic class** |
| Reliability | UDP loss, duplication, reordering and exporter restart handling |

**Sampling is configurable for IPFIX and all NetFlow versions.** IPFIX accepts
`sampling_rate: 1..1,000,000`, including disabled instances; `1` is unsampled.
It emits the configured `samplingInterval` and `samplingAlgorithm = 1`.
Raw counts describe sampled observations and are not scaled by the exporter.
The receiver MUST distinguish those counts from any estimated full-traffic
totals. Sampling and transport/capture loss are separate concerns.

Options Templates, Options Data Sets, enterprise-specific IEs, variable-length
fields, TLS/DTLS and SCTP transport are not emitted by this implementation.
A receiver may support them for other exporters, but must not depend on them
for Netcontrol.

## 2. Listener, routing and trust

- The receiver MUST listen on the UDP destination address/port configured in
  `collector`. Port 4739 is a useful choice, not an exporter default.
- For UDP/IPv6, the operator must enable appliance IPv6 and use a bracketed
  numeric endpoint, for example `[2001:db8::50]:4739`. UDP/IPv4 can carry
  IPv6 records too; an IPv4 listener must not reject template 257.
- The receiver MUST accept an ephemeral exporter source port. It MUST NOT
  require source port 4739 or assume that the source port remains stable
  across worker restarts.
- The export source address and route are selected by the appliance kernel.
  The configured capture interface does not force export egress.
- A successful local send is not delivery confirmation. The receiver MUST NOT
  require an acknowledgement exchange; the exporter does not implement one.
- Export is unauthenticated and unencrypted. Operators SHOULD restrict reachable
  listeners to intended exporters and use a trusted network or separately
  managed secure tunnel. Source IP and observation domain are not credentials.

The receiver MUST preserve UDP datagram boundaries and detect truncated
datagrams rather than parsing a truncated buffer as a complete message.
It MUST accept the current maximum **2416-byte UDP payload**; a 1500-byte
application receive limit is insufficient. A general-purpose IPFIX receiver
SHOULD allow larger UDP payloads rather than hard-code this exporter maximum.

IP fragmentation/reassembly belongs to the network stack. Firewall rules,
network MTU and operating-system reassembly limits must permit delivery.
The exporter is not path-MTU-aware; the receiver cannot request smaller batches.
Monitor kernel receive drops and application queue pressure under load.

## 3. Message framing

Each UDP payload contains one IPFIX message. All multibyte integers are
unsigned and big-endian.

| Byte offset | Width | Header field | Interpretation |
| --- | --- | --- | --- |
| 0 | 2 | Version | Exactly 10 |
| 2 | 2 | Message length | Includes the 16-byte header and every set |
| 4 | 4 | Export time | Unix epoch seconds at encoding |
| 8 | 4 | Sequence number | Data-record count before this message, modulo 2^32 |
| 12 | 4 | Observation domain ID | Random per exporter worker execution attempt |

The receiver MUST validate message length against the actual UDP payload.
It MUST walk sets using their declared lengths, not search for template IDs
in arbitrary bytes. Each set starts with a two-byte Set ID and two-byte set
length. Set length includes that four-byte header and any padding.

For current valid exports:

1. Template Set ID **2** appears first and is **116 bytes** including its header.
2. It contains template **256**, then template **257**.
3. Nonempty IPv4 Data Set **256** follows, when IPv4 records exist.
4. Nonempty IPv6 Data Set **257** follows, when IPv6 records exist.
5. There are **1 to 30 data records total** across both families.

The receiver MUST decode using the received template definitions, including
their advertised IE widths, rather than assuming the template ID alone defines
the schema. Identical template refreshes are normal and MUST be accepted.
Both templates are sent even when IPv6 is disabled or only IPv4 data exists;
receiving template 257 alone is not evidence of observed IPv6 traffic.

Sets are padded with zeros to a four-byte boundary. Current data records are
already multiples of four bytes, so their Data Sets need no trailing padding.
Padding, set headers and template definitions MUST NOT become flow records.

## 4. Exact data-record schema

Each template definition has a two-byte template ID, two-byte field count
(13), followed by 13 pairs of two-byte IE ID and two-byte length.
No enterprise bit or enterprise number is present.

Offsets below are relative to the start of a **data record**, not its set.

| Field | IE ID: IPv4 / IPv6 | Width: IPv4 / IPv6 | Offset: IPv4 / IPv6 |
| --- | --- | --- | --- |
| sourceIPv4Address / sourceIPv6Address | 8 / 27 | 4 / 16 | 0 / 0 |
| destinationIPv4Address / destinationIPv6Address | 12 / 28 | 4 / 16 | 4 / 16 |
| sourceTransportPort | 7 | 2 / 2 | 8 / 32 |
| destinationTransportPort | 11 | 2 / 2 | 10 / 34 |
| protocolIdentifier | 4 | 1 / 1 | 12 / 36 |
| ipClassOfService | 5 | 1 / 1 | 13 / 37 |
| tcpControlBits | 6 | 1 / 1 | 14 / 38 |
| packetDeltaCount | 2 | 8 / 8 | 15 / 39 |
| octetDeltaCount | 1 | 8 / 8 | 23 / 47 |
| flowStartMilliseconds | 152 | 8 / 8 | 31 / 55 |
| flowEndMilliseconds | 153 | 8 / 8 | 39 / 63 |
| samplingInterval | 34 | 4 / 4 | 47 / 71 |
| samplingAlgorithm | 35 | 1 / 1 | 51 / 75 |

Template 256 records are **52 bytes**; template 257 records are **76 bytes**.
The receiver MUST support the one-byte encoding of `tcpControlBits`, not
require a two-byte value. Fields are not naturally aligned; decoders MUST NOT
assume aligned machine-word reads.

Example message sizes, excluding UDP/IP/link headers:

| Records | Template set | Data set(s) | Message length |
| --- | --- | --- | --- |
| One IPv4 | 116 | 56 | 188 |
| One IPv6 | 116 | 80 | 212 |
| One IPv4 + one IPv6 | 116 | 56 + 80 | 268 |
| Thirty IPv4 | 116 | 1564 | 1696 |
| Thirty IPv6 | 116 | 2284 | 2416 |

## 5. Template scope, restarts and sequencing

Template state MUST be scoped by the observed UDP transport session plus
observation domain ID and template ID. A practical session key includes source
IP/port and local destination IP/port; do not share one global template cache
keyed only by 256/257 or only by the observation domain.

The receiver MUST process templates in a message before decoding that message's
Data Sets. Both templates accompany every export, so the first received packet
is independently decodable even if earlier packets were lost or a cached
template expired. No template-only keepalive or withdrawal is emitted.
Receiver-managed idle expiry SHOULD bound cached session/template state.

On each worker execution attempt, the exporter starts its sequence at zero
and chooses a random 32-bit observation domain. A restart can also change the
UDP source port and, depending on routing, source address. The receiver MUST
handle the new session/domain without treating it as continuous old sequence
state. Random domains may collide and do not identify an interface or appliance.

For a message with sequence `S` and `R` data records, the next in-order message
in that session/domain has sequence `(S + R) mod 2^32`. Count records from
**both** Data Sets. Do not increment by datagram count, set count or templates.
For example, a message at sequence 100 containing two IPv4 records and one
IPv6 record makes the next expected sequence 103.

Sequence gaps SHOULD produce transport-quality diagnostics, not prevent decoding
otherwise valid messages. UDP can reorder or duplicate messages; a single
mismatch does not prove permanent loss. Deduplication/reorder handling MUST
remain session-scoped and account for wrap/restarts rather than discarding all
messages below the last sequence. Missing records cannot be recovered from
this exporter; there is no retransmission or replay protocol.

## 6. Flow interpretation and aggregation

### Identity and direction

The exporter key is:

`(source IP, destination IP, source port, destination port, protocol, TOS/traffic class)`

The receiver MUST preserve these six components and the exporter/session
provenance. Reverse-direction traffic is a separate unidirectional flow.
Different TOS values are separate flows even when the conventional 5-tuple
matches. An optional bidirectional conversation view is receiver-derived,
not an exporter record.

For TCP/UDP, ports are decoded normally. For ICMP/ICMPv6:

- Source port is zero.
- Destination port is `(type << 8) | code`.
- Decode `type = destinationPort >> 8` and `code = destinationPort & 255`;
  do not label the value as a TCP/UDP service port.

For other protocols, including SCTP (132), both ports are zero. The receiver
MUST NOT infer an SCTP association or real SCTP port-zero endpoint from those
zeros. TCP flags are ORed across sampled packets in the flow; for non-TCP
traffic they are zero.
At rates above 1, flags and first/last times describe selected packets only;
they need not include the actual connection's handshake, FIN/RST or endpoints
in time.

### Counters and sampling

`packetDeltaCount` and `octetDeltaCount` describe sampled observed packets in that
exported record, not lifetime cumulative counters. Octets are layer-3 IP
lengths, excluding Ethernet headers. The receiver MUST preserve exact u64
values; JavaScript `Number` cannot represent every value. Use an exact integer
representation and, if exposing JSON, decimal strings.

`samplingAlgorithm` is always **1** (deterministic), and `samplingInterval`
is the configured **1..1,000,000**. At rate N, every Nth received frame is
selected before parsing/filtering; rate 1 selects every frame. This phase
continues across receive batches and starts afresh on each worker execution.
Non-IP, filtered and collector-directed frames participate in the selection
sequence even though they may not contribute exported records.

The receiver MUST accept these per-record fields without requiring an Options
Template. Preserve raw counts and the interval/algorithm alongside each record.
If estimating full traffic, multiply raw counts by that record's interval using
overflow-safe arithmetic, label the result **estimated**, and never scale twice.
The product of a u64 counter and an interval can exceed u64. Aggregates spanning
different sampling rates must scale each contributing record appropriately;
do not apply the latest interval to all historical records.

For example, 3 packets/132 octets at interval 100 means 3 sampled observed
packets/132 observed layer-3 bytes; a full-traffic estimate is 300 packets/
13,200 bytes. At interval 1, observed and estimated counts coincide without
scaling. Deterministic sampling can be biased and cannot exactly reconstruct
filtered packets, capture drops or missing UDP exports.

Repeated keys can appear as separate record segments after idle/max-life/capacity
expiry or restart. Sum appropriate segments for aggregates; do not subtract
one record's counts from the next as if these were monotonic counters.
Record order is not a stable flow order.

### Time and missing context

IEs 152/153 are Unix epoch **milliseconds**. The exporter reconstructs them at
export from its current system clock and elapsed worker milliseconds; it does
not export hardware arrival timestamps. Preserve raw times and store receiver
arrival time separately. Clock corrections can shift exported timestamps.
Do not treat export time as the end of every flow or clamp unexpected times
silently. Elapsed worker millisecond values wrap at 32 bits; this format is
not a guarantee of accurate reconstructed timing for very long-lived flows.

IPFIX records contain no capture interface name/index, instance name, VLAN,
MAC, next hop, AS number, prefix length, application identity or flow-end reason.
The receiver MUST represent this context as unknown unless separately configured.
Operators SHOULD use distinct collector ports per capture instance when stable
interface attribution is required; observation domains are not stable labels.
Traffic captured on multiple interfaces can be counted more than once.

Fragments, IPv6 jumbograms, non-IP frames, capture-filter exclusions and kernel
capture drops are not recovered in these records. There is no IPFIX field
reporting capture completeness or drop count. UDP sequence continuity therefore
MUST NOT be presented as proof of complete traffic accounting. Appliance runtime
drop statistics are a separate API, not part of this wire protocol.

## 7. Error handling and receiver observability

The receiver MUST reject malformed/truncated messages and invalid set/template
lengths explicitly without turning them into successful zero-valued records.
Do not use a stale template from another session to make a message decodable.
Parsing failure SHOULD identify the sender/session and a bounded diagnostic,
without unrestricted packet payload logging.

The receiver SHOULD expose separate metrics for received datagrams, decoded
records, parse failures, unknown templates, duplicate/reordered messages,
sequence-gap evidence, socket/queue drops and last receipt time. Bound template
caches, queues and processing work so malformed or excessive input cannot
consume unlimited receiver resources.

No packets during an idle period is normal: export is driven by flow expiry,
not a periodic heartbeat. A lack of traffic does not prove exporter failure;
a running exporter or recent message does not prove loss-free capture.

## 8. Receiver acceptance checklist

These are tests required of the receiver; they were **not executed against a
receiver in this documentation task**.

1. Receive IPFIX over UDP/IPv4 and, where deployed, UDP/IPv6 with an arbitrary
   exporter source port. No TCP/SCTP or acknowledgement dependency.
2. Decode template 257/IPv6 records arriving over UDP/IPv4 and IPv4 records
   arriving over UDP/IPv6. Accept both templates with IPv4-only data.
3. Decode one-family and mixed-family messages using all 13 IE widths/offsets,
   including one-byte TCP flags and unaligned 64-bit counters.
4. Verify the five message lengths in section 4, including 2416-byte payloads
   without application truncation; separately verify actual path-MTU delivery.
5. Join mid-stream and decode the first received message using its templates.
   Accept repeated templates without duplicate flow creation.
6. Keep template/sequence state isolated for two senders with the same template
   IDs and domain, and for multiple domains from the same UDP endpoint.
7. Advance sequence by total data records, not messages/templates; test loss,
   reordering, duplicates, wrap from 2^32 to zero and restart at sequence zero
   under a new session/domain.
8. Preserve counters above 2^53 exactly. Test interval 1, 4 and 1,000,000 with
   algorithm 1. At interval 100, retain 3 raw packets and, if requested, show
   300 estimated packets, never 300 observed. Test overflow-safe estimation and
   mixed-rate aggregation. IPFIX rates 0 and 1,000,001 must fail backend
   validation with HTTP 422, including disabled instances.
9. Preserve reverse directions and differing TOS as distinct keys. Decode ICMP
   type/code and represent SCTP ports as unavailable rather than real ports.
10. Decode epoch-millisecond times without confusing seconds or uptime, retain
    receiver arrival time, and surface clock anomalies without silent fixes.
11. Sum repeated-key record segments as deltas, retain provenance and avoid
    claiming capture completeness from sequence continuity.
12. Reject malformed lengths/truncated datagrams visibly; tolerate idle periods
    without requiring nonexistent template-only keepalives.

## References

- [Exporter implementation specification](NETFLOW_IPFIX_SPEC.md)
- [Encoder, capture parser and protocol tests](../crates/netcontrol-services/src/flow.rs)
- [Native capture/export integration fixtures](../crates/netcontrol-services/src/integration.rs)
- [Canonical appliance UI/API contract](../FRONTEND_SPEC.md#69-softflowd)
- [Collector configuration example](../examples/vlan-softflowd.json)
