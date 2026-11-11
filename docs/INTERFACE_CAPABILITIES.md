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
  implicitly on this cached-read path or startup.
- `GET /api/v1/interface-capabilities/refresh`: API key, `state.read` and
  `interfaces.write`. Perform one synchronous inventory and atomically persist
  it before returning 200. No body or query parameters.
- Refresh is deliberately a scan-and-save GET for GET-only API explorers, not
  an ordinary read. Only explicit user execution may trigger it: no automatic
  polling, prefetch, retry, caching or bulk "run all GETs". Responses have
  `Cache-Control: no-store`; repeated explicit GETs each scan and save again.
  POST is unsupported (405); there is no alternate write-method alias.
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
  are Linux hexadecimal masks. Nullable `irqs` and `irq_mapping_reason` describe
  an observed unique hardware IRQ mapping or explain why it is unknown.
- RSS: nullable `rss` contains default `context:0`, nullable RX queue index
  `indirection_table` and raw unsigned-byte `hash_function`/
  `input_transformation` bitmasks. No hash key is serialized. RSS activation
  is true for multiple table targets with recognized active hash bits (1/2/4
  for Toeplitz/XOR/CRC32), false for a table targeting at most one queue, and
  unknown for missing details or unrecognized hashing with multiple targets.
  Support remains driver-table evidence, independent of activation/CPU affinity.
- Interrupts: nullable `interrupts` lists device IRQ numbers, nullable
  descriptions/effective logical CPU IDs and cumulative per-CPU counts
  (`cpu_id`, exact decimal-string `interrupts`), plus errors per IRQ.
  Event IRQs remain visible even without a queue association. Missing sources
  are null independently, never zero. These are interrupt events, not packet
  counts, utilization or post-RPS CPU measurements.
- Capabilities: stable feature `name`, `support` (`supported`, `unsupported`,
  `unknown`, `not_applicable`), nullable `enabled`/`inherited_from`, evidence
  strings and nullable reason. Activation requires observed queue evidence;
  support is never proof of operational verification or performance benefit.

For VLAN RPS, `support`/`enabled` come from the observed physical parent and
`inherited_from` names that source, including stacked VLANs. Render Enabled or
Disabled plus "Inherited from <parent>", not an independent third activation
state. A parent with unknown activation remains `enabled:null` with its source
name. Non-VLAN capabilities and simulator rows use null `inherited_from`.
The VLAN's own `queues[].rps_cpus` stays unchanged as diagnostic evidence:
ordinary tagged receive traffic is steered on the physical device before VLAN
demultiplexing, without a second RPS selection using the VLAN's mask.
At least one enabled parent queue means enabled, not that every queue/flow is
steered. Per-VLAN configuration remains rejected.

Unresolved/missing/cross-namespace ancestry, cycles, more than 32 ancestry links,
missing physical identity or ambiguous software parents (bridge/bond/veth)
produce unknown RPS with null source and explicit row errors/reason. Never
infer disabled or fabricate ancestry. VLAN inheritance affects only RPS;
RSS and device IRQ observations remain direct, not inherited.
Deploy the backend and explicitly refresh the snapshot for new observations;
cached reads retain their timestamp and do not perform implicit scans.

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
      "enabled": true,
      "inherited_from": null,
      "evidence": ["default RSS context targets RX queues {0, 1, 2, 3}; hash function bits: 1"],
      "reason": null
    },
    {
      "name": "dpdk",
      "support": "unknown",
      "enabled": null,
      "inherited_from": null,
      "evidence": [],
      "reason": "PMD and deployment prerequisites have not been validated"
    }
  ]
}
```

## Linux collection

- Enumerate live links with rtnetlink in the backend namespace.
- Read driver info, modern link settings, channels, RSS indirection-table size
  and default-context table/hash/transform settings with a two-phase size/data
  handshake (ETHTOOL_GRSSH), rejecting size races and oversized/truncated replies,
  and feature names/flags using read-only ethtool ioctls on a namespace-local
  socket. Do not add legacy link-settings fallback contracts.
- Query generic-netlink `netdev` XDP feature flags. Missing family/attributes or
  failed queries mean unknown with a reason, not unsupported.
- Read queues and device identity from sysfs only in daemon host mode, verifying
  interface index before accepting sysfs evidence. Optional lab namespaces
  omit sysfs evidence explicitly because the mounted sysfs may describe another
  namespace. Validate link index again after collection to detect replacement.
- Read `/proc/interrupts` once per scan with the performance monitor's shared
  bounded parser (2 MiB, at most 4096 numeric IRQs/65536 IRQ-CPU cells).
  Enumerate at most 4096 device MSI/MSI-X IRQs, or the reported non-MSI IRQ,
  and read effective affinity independently. Do not infer queue identity from
  vector position: require an exact unshared action name `INTERFACE-TxRx-N`,
  `INTERFACE-rx-N`/`INTERFACE-Rx-N`, or `INTERFACE-tx-N`/`INTERFACE-Tx-N`
  and a unique matching IRQ. Unknown/ambiguous mappings produce diagnostics.
  Software/lab/simulator queues have no fabricated physical IRQ evidence.
  Snapshot fields are not atomic live rates; reuse performance statistics for
  live deltas without polling or automatically invoking capability refresh.
- RPS/RFS/XPS presence and current masks/table sizes are software evidence.
  RSS requires driver evidence, not simply multiple queues.
- Resolve VLAN RPS from namespace-local rtnetlink lower-link indices and
  physical sysfs identity. Recheck link kind/identity and VLAN lower-link
  topology after collection; a change fails refresh rather than saving mixed
  ancestry. Preserve raw VLAN queue observations and diagnostics.
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
