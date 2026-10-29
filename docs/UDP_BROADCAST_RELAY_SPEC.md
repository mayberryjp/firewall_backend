# Native IPv4 UDP Broadcast Relay

## Reference and scope

The behavior follows the documented [pfSense UDP Broadcast Relay package](https://docs.netgate.com/pfsense/en/latest/packages/udpbroadcastrelay.html):
global/per-instance enable, unique instance ID, destination UDP port, selected
interfaces, optional IPv4 multicast membership and three source-address modes.
The implementation is original in-process Rust, not a bundled or supervised
copy of [upstream udpbroadcastrelay](https://github.com/marjohn56/udpbroadcastrelay).

The relay forwards limited or incoming-subnet directed broadcasts and the
configured multicast group to every selected interface except ingress. It
rewrites broadcasts to the outgoing subnet broadcast, preserves multicast
destinations and UDP payload, and preserves IPv4 TTL (including multicast TTL
1). The source modes are:

| `source` | Outgoing source address | Outgoing source UDP port |
| --- | --- | --- |
| `original` (default) | Original sender | Original sender port |
| `interface_address` | Outgoing interface IPv4 address | Original sender port |
| `interface_address_and_port` | Outgoing interface IPv4 address | Configured destination port |

Instance ID replaces the six DSCP bits (`id << 2`); ECN bits are preserved.
Packets already marked with the same ID are dropped. DSCP is not authentication.
Use one relay per connected discovery domain, avoid cyclic/overlapping relay
paths, and do not strip/remark these DSCP tags between cooperating relays.

This is not a general multicast router or unicast response proxy. No IPv6,
WireGuard/point-to-point relay, CARP master tracking, SSDP/DIAL application
proxy, CIDR allow/block list, arbitrary spoofed-source setting or alternate
TTL-based loop mode is implemented. Application discovery is not device access
authorization. These are explicit scope limits, not claims of every upstream
command-line option or complete pfSense platform parity.

## Configuration

Top-level `config.udp_broadcast_relay` defaults to
`{"enabled":false,"instances":[]}`. See the complete synthetic
[transaction example](../examples/udp-broadcast-relay.json). It replaces the
whole desired configuration, not just this section; merge with current intent
and use the current base revision rather than submitting it unchanged.

- `enabled`: boolean, default false. Enabled requires at least one enabled instance.
- `instances`: array, default empty, maximum 63. IDs and ports are unique even
  for disabled rows. Normalization sorts instances by ID and interfaces by name.
- Each instance requires integer `id` 1..63, boolean `enabled`, integer `port`
  1..65535 and `interfaces` containing 2..32 unique configured interface names.
- Interfaces must be up Ethernet/VLAN links with broadcast-capable static IPv4
  (prefix at most /30) or configured DHCP. Runtime waits/retries until a usable
  DHCP address exists. Loopback, dummy and point-to-point links are not eligible.
- `multicast_address`: IPv4 multicast literal or null; omitted defaults null.
  Null relays broadcasts only. It never means all multicast groups.
- `source`: one table value above, defaults `original`.
- Global and instance `metadata` use the shared optional display-name/description
  contract. Metadata is persisted/authorized but stripped from operational
  comparison, so metadata-only changes do not restart sockets.
- Relay objects reject unknown fields and invalid types. Known listener
  conflicts reject enabled configurations: mDNS/5353, DHCP relay/67 and DHCP
  clients/68. Other port owners are detected at runtime, never terminated.
- There is one wildcard UDP listener per instance and no socket reuse. Even
  otherwise filtered local unicast to that port cannot be shared with another
  local service.

Changes use normal transactions, confirmed activation, history/restore and
rollback. They require `transactions.write` and `udp_broadcast_relay.write`,
plus permissions for other changed resources. Disabled settings are still
validated. No compatibility aliases or migrations are provided.

## Govee and ECHONET Lite

[Govee's official LAN API guide](https://app-h5.govee.com/user-manual/wlan-guide)
requires supported hardware with LAN Control enabled in the Govee Home app.
Relay UDP **4001**, multicast **239.255.255.250**, between the controller and
device networks, using `source: "original"`. A synthetic scan is:

```json
{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}
```

Devices send discovery/status replies to controller UDP **4002**. Subsequent
controller commands go directly to device UDP **4003**. Permit these routed
unicast flows separately; relaying ports 4002/4003 is not a substitute for
normal routing. Rewritten-source modes can direct replies to the firewall;
there is no response proxy to repair that application workflow.

ECHONET Lite IPv4 discovery uses multicast **224.0.23.0**, UDP **3610**, with
normal unicast UDP/3610 request/reply traffic. Select the same two networks and
preserve the original source. See the Consortium's
[ECHONET Lite specification, Part 2](https://echonet.jp/spec_v114_lite_en/).
Controllers/devices may impose their own subnet restrictions; physical-device
interoperability still requires testing. IPv6 ECHONET discovery is not relayed.

## Firewall and deployment prerequisites

The relay never installs implicit input, forwarding, output or NAT permits.

1. Allow host-input UDP to the relay port and relevant group/broadcast on each
   participating ingress link. Existing host-input policy can block discovery;
   an ordinary forwarding rule does not grant access to this local UDP socket.
2. Permit required routed controller/device request and reply flows explicitly.
   A multicast query does not make a unicast device reply an automatically
   established/related connection. Use narrowly scoped controller/device hosts
   and ports, rather than opening the complete IoT network.
3. Ensure each device/controller has a return route through the firewall and
   that host reverse-path/output policy, switches, IGMP snooping and Wi-Fi client
   isolation permit the traffic. Do not mask routing problems with broad SNAT.
4. Linux requires CAP_NET_RAW plus existing network-management permissions;
   native host mode requires the existing `allow_host_services` opt-in. Namespace
   mode pins workers to that namespace. Non-Linux activation is unsupported.

The runtime selects the numerically lowest usable live IPv4 address and its
broadcast on each interface; /31 and /32 aliases are skipped. Prefer a single
IPv4 subnet per participating link. It snapshots link/address changes every
100 ms and checks egress indices before sending; changes retire the attempt and
reopen sockets through the supervisor. This is snapshot/index checking, not the
mDNS worker's route-notification identity-history guarantee.

Receive payloads are bounded to 65507 bytes, but raw `IP_HDRINCL` sends do not
fragment. The IPv4 header plus UDP header plus payload must fit each outgoing
MTU (1472 payload bytes with MTU 1500). Oversized sends increment `send_errors`
and retain `last_send_error`; small discovery traffic remains usable and the
supervisor stays running. There is no queue/backlog/replay or delivery guarantee.

Each instance has a fixed 200 admitted packets/second token bucket, burst 400,
before fanout to at most 31 other links. A receive round processes at most 64
datagrams; polling is 100 ms and shutdown is cooperative. These protective
bounds are deliberate additions, not configurable pfSense settings.

## Operations and status

- `GET /api/v1/services/udp-broadcast-relay`: committed relay config, `state.read`.
- `GET /api/v1/services/udp-broadcast-relay/status`: applied status, including
  provisional transactions, `state.read`; `{instances: [...], error: ""}`.
- Both reads reject query parameters with `400`. Authentication/authorization
  uses the usual `401`/`403`; malformed configuration uses transaction `400`.
- `POST /api/v1/services/udp-broadcast-relay/reconcile`: bodyless/queryless shared
  service repair. Requires `state.read`, `transactions.write`,
  `udp_broadcast_relay.write` and every other enabled shared-service permission.
  It repairs the shared service set, not just one instance; normal conflict and
  drift guards remain. Every shared-service repair now also requires
  `udp_broadcast_relay.write` when the relay is globally enabled.
- `POST /api/v1/processes/restart`, `{"target":"udp-broadcast-relay:1"}`, uses
  `system.restart`. Canonical decimal instance IDs only; missing instance `404`,
  disabled target/active transaction `409`, native restart `200` with the
  existing restart envelope. This does not enable a disabled instance or bump
  the configuration revision.
- CLI: `udp-broadcast-relay JSON`, `no udp-broadcast-relay` in a candidate;
  `show udp-broadcast-relay`, `show udp-broadcast-relay status`, and
  `reconcile services udp-broadcast-relay`.

`RuntimeState.appliance_services` contains one row per configured instance with
`name: "udp-broadcast-relay"`, numeric `instance_id`, `scope: "managed"`, effective
`enabled`, configured port/interfaces/group/source and normal worker state.
Disabled instances have no worker; simulator rows say `simulated`, not measured.
Supervisors use `running|error|stopped`, `retrying`, `restart_count`, `started_at`,
optional current `error` and retained `last_error`. Startup/bind/link failures
retry after 1, 2, 4, 8, 16, then at most 30 seconds; connectivity does not gate
configuration apply/confirmation/rollback. Backoff and sockets stop/join before
replacement. There are no external daemon PIDs.

Eight saturating decimal-string counters reset on each attempt:
`received_packets`, `transmitted_packets`, `received_bytes`, `transmitted_bytes`,
`policy_drops`, `loop_drops`, `rate_limit_drops`, `send_errors`. Byte counts are
UDP payload only; transmissions count successful per-egress sends, not delivery.
`last_send_error` and `last_send_error_at` are nullable retained error details;
`collected_at` is the latest counter sample. `receive_drops: null` and
`statistics_complete: false` explicitly mean kernel receive loss is unmeasured,
not zero. The normal health monitor can therefore emit a statistics warning;
per-instance process resources are `udp-broadcast-relay:ID`, also carried by
existing health/MQTT publication. `limits` publishes the fixed bounds above.

## Acceptance evidence and remaining work

Portable tests cover schema/defaults/normalization, invalid input, metadata,
permissions, API reads, persistence, confirmed rollback, source modes and exact
packet construction. An opt-in privileged native fixture checks Govee-style
multicast discovery/routed replies, ECHONET binary multicast, limited/directed
broadcast, TTL/DSCP, source rewrites, filtered traffic, host-input enforcement,
MTU failure reporting, link/port recovery, restart, prompt worker joins, native
reopen/repair and rollback across isolated veth networks.

```sh
NETCONTROL_INTEGRATION=1 cargo test -p netcontrol-native --locked \
  native_udp_relay -- --ignored --nocapture
```

This is not physical Govee/ECHONET, actual VLAN/switch/Wi-Fi, reboot, sustained
load, pfSense interoperability or production acceptance. Required frontend work
is tracked in [handoff 2026-10-28-06](frontend-handoffs/2026-10-28.md#2026-10-28-06-native-udp-broadcast-relay).