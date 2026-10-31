# Interface capability discovery

## Purpose and safety

Inventory every link in the backend network namespace, including unmanaged,
down, virtual and loopback links. Read NIC/driver identity, PCI identifiers,
link modes, queue topology and performance feature evidence without enabling
anything. This is an observation snapshot, not an optimization recommendation
or proof of throughput. Do not rebind devices, load modules, allocate hugepages,
attach BPF programs, bind AF_XDP queues or change ethtool/sysctl/IRQ settings.

## API and persistence

- `GET /api/v1/interface-capabilities`: API key and `state.read`. Read the last
  persisted snapshot; return JSON `null` before the first refresh. Never scan
  implicitly on GET or startup.
- `POST /api/v1/interface-capabilities/refresh`: API key, `state.read` and
  `interfaces.write`. Perform one synchronous inventory and atomically persist
  it before returning 200. No body or query parameters.
- Both paths reject bodies/query parameters with 400 and unsupported methods
  with 405. Normal authentication errors are 401/403. Fatal discovery errors
  return 503; persistence errors return 500 and retain the prior snapshot.
  Existing upgrade/restart write guards apply to refresh.
- Use a separate collection path so a real interface named `capabilities`
  remains retrievable at `GET /api/v1/interfaces/capabilities`.
- Per-source failures produce a `partial` snapshot with explicit diagnostics,
  never inferred unsupported hardware or an empty success. A successful partial
  refresh replaces the previous snapshot; it is not merged with stale evidence.
- Serialize refreshes with the engine's existing request lock. Retain only the
  latest snapshot in the checksummed, owner-only engine journal, separately
  from editable desired configuration and configuration history. Inventory
  writes do not advance revisions, apply networking or participate in rollback.
- Record UTC collection time, backend scope, kernel release and boot ID.
  Stored observations survive restart but can become stale after reboot,
  hotplug, renaming, firmware/driver/configuration changes. GET returns the
  original timestamp/boot ID; the frontend must not present it as live state.

## Output

The snapshot has `collected_at` (RFC3339 UTC), `scope` and an `inventory` object.
The inventory has `source` (`native` or `simulator`),
`status` (`observed`, `partial`, `simulated`), nullable
`kernel_release`/`boot_id`, `errors` and name-sorted `interfaces`.

Each interface contains `name`, nullable kernel `index`/`mac`, `kind`, nullable
`driver`, `hardware`, `link`, RX/TX `queues`, `capabilities` and `errors`.

- Driver: name, nullable version/firmware/expansion-ROM version and bus address.
- Hardware: nullable bus type, device address, PCI vendor/device/subsystem
  identifiers (hex strings), revision and NUMA node. PCI numeric IDs are the
  authoritative identity; no guessed marketing name or external database.
- Link: nullable carrier, current speed in Mbps, duplex (`half`/`full`),
  autonegotiation enabled; supported, advertised and link-partner advertised
  link-mode lists. Each mode retains its kernel bit index, nullable recognized
  name, speed Mbps and duplex. Non-speed bits and unknown future bits remain
  visible; never manufacture speed/duplex support from current speed.
- Queues: RX/TX names and CPU masks/flow-table sizes, plus a nullable `channels`
  object with ethtool channel maxima and current counts when exposed. CPU masks
  are Linux hexadecimal masks.
- Capabilities: stable feature `name`, `support` (`supported`, `unsupported`,
  `unknown`, `not_applicable`), nullable `enabled`, evidence strings and nullable
  reason. Enabled is unknown unless directly observed; support is never proof
  of availability, activation or operational verification.

Performance inventory includes RSS, RPS, RFS, accelerated RFS, XPS CPU/RX-queue
steering, native/hardware XDP, XDP redirect/multi-buffer, AF_XDP zero-copy,
DPDK and driver-reported ethtool offloads. Preserve individual offload names
and enabled state rather than collapsing them into a vague acceleration flag.

Synthetic interface excerpt (selected fields and capabilities only; not a
measured NIC or a complete response):

```json
{
  "name": "eth0",
  "driver": {
    "name": "example_driver",
    "version": "1.0",
    "firmware_version": "example-firmware",
    "expansion_rom_version": null,
    "bus_address": "0000:01:00.0"
  },
  "link": {
    "carrier": true,
    "speed_mbps": 1000,
    "duplex": "full",
    "autonegotiation": true,
    "supported_modes": [
      {"bit": 4, "name": "1000baseT_Half", "speed_mbps": 1000, "duplex": "half"},
      {"bit": 5, "name": "1000baseT_Full", "speed_mbps": 1000, "duplex": "full"},
      {"bit": 12, "name": "10000baseT_Full", "speed_mbps": 10000, "duplex": "full"}
    ],
    "advertised_modes": [
      {"bit": 5, "name": "1000baseT_Full", "speed_mbps": 1000, "duplex": "full"}
    ],
    "partner_advertised_modes": []
  },
  "capabilities": [
    {
      "name": "rss",
      "support": "supported",
      "enabled": null,
      "evidence": ["ethtool RSS indirection table size: 128"],
      "reason": null
    },
    {
      "name": "dpdk",
      "support": "unknown",
      "enabled": null,
      "evidence": [],
      "reason": "PMD and deployment prerequisites have not been validated"
    }
  ]
}
```

## Linux collection

- Enumerate live links with rtnetlink in the backend namespace.
- Read driver info, modern link settings, channels, RSS indirection-table size
  and feature names/flags using read-only ethtool ioctls on a namespace-local
  socket. Do not add legacy link-settings fallback contracts.
- Query generic-netlink `netdev` XDP feature flags. Missing family/attributes or
  failed queries mean unknown with a reason, not unsupported.
- Read queues and device identity from sysfs only in daemon host mode, verifying
  interface index before accepting sysfs evidence. Optional lab namespaces
  omit sysfs evidence explicitly because the mounted sysfs may describe another
  namespace. Validate link index again after collection to detect replacement.
- RPS/RFS/XPS presence and current masks/table sizes are software evidence.
  RSS requires driver evidence, not simply multiple queues.
- Accelerated RFS and DPDK readiness remain unknown unless a dedicated,
  driver-aware validator is added later. A PCI device or VFIO module alone does
  not prove DPDK PMD compatibility. Generic XDP/AF_XDP copy-mode operational
  readiness also requires later validation; discovery does not probe attachment.
- Bound variable-size kernel replies and socket waits. Malformed replies are
  explicit source failures.
- Simulator rows identify simulated links and unknown capabilities; never read
  host hardware or fabricate measured capability support.

## Acceptance and future work

Test authentication, strict methods/body/query validation, no implicit scans,
partial/error behavior, persistence/restart, failed-write retention and unchanged
desired configuration/revision/rollback. Test kernel reply decoding, unknown
mode bits, down-link sentinels, offload flags and sysfs masks with fixtures.
Run read-only Linux collection against real namespace-local links; physical NIC
and driver diversity require additional operator acceptance.

Future work may add authorized operational verification and explicit tuning
transactions. Those are outside this API and must account for firewall-path
bypass, management connectivity, rollback and CPU/NUMA placement.

Contract impact: additive, Unreleased; next automatic calendar version, no
manual version bump. See [frontend contract](../FRONTEND_SPEC.md) and
[handoff](frontend-handoffs/2026-10-31.md#2026-10-31-01-interface-capability-inventory).
