# Firewall performance work plan

Updated: 2026-11-04.

This is a resumable roadmap, not an implemented API contract or authorization to
deploy, enable tuning, commit, push or publish. Planned field names/endpoints
must be designed against current code before implementation. The
[frontend specification](../FRONTEND_SPEC.md) remains authoritative.

## Milestones

| Milestone | Status | Outcome |
| --- | --- | --- |
| 1. Diagnostics and transactional RPS | Backend implemented locally, Unreleased; frontend and physical acceptance pending | Identify CPU pressure and support explicitly reviewed, rollback-aware RPS trials |
| 2. Safe NIC offload management and RFS | Backend implemented locally, Unreleased; physical/frontend acceptance pending | Explicit driver feature controls and RFS budgets with confirmed transactions, original capture and recovery |
| 3. WAN smart queue management | Explicitly deferred by user | No ALTQ/CAKE/FQ-CoDel/HTB or ingress shaping is implemented |

No measured appliance speedup has been established. Most important checksum,
segmentation, GRO and VLAN offloads were already enabled in the supplied
inventory; additional controls are primarily for safe tuning and diagnosis.

## 1. Finish diagnostics and RPS acceptance

### Existing backend

- Passive `GET /api/v1/statistics/performance`: CPU, IRQ, softnet, topology,
  physical RX queues and conservative RPS trial evidence.
- Explicit `kernel.rps` masks with permissions, host opt-in, confirmation,
  readback, original-setting capture and durable rollback/recovery.
- SSH inspection and candidate editing; no automatic tuning.

Implementation results and limitations:
[journal](journal/2026-11-04.md#performance-diagnostics-and-transactional-rps).
Current contract:
[performance diagnostics and RPS](../FRONTEND_SPEC.md#performance-diagnostics-and-rps-tuning).
Frontend work:
[handoff 2026-11-04-03](frontend-handoffs/2026-11-04.md#2026-11-04-03-performance-diagnostics-and-transactional-rps),
**Pending frontend review**.

### Remaining acceptance

- [ ] Integrate frontend types, full-package preservation, diagnostics and
  explicit tuning/confirmation UX; do not assume the handoff was delivered.
- [ ] Through an approved deployment, verify real physical NIC queue/CPU
  evidence, permissions and host opt-in.
- [ ] Establish repeatable baseline traffic and acceptance criteria before
  tuning: throughput, CPU distribution, drops/backlog, latency and loss.
- [ ] Run one explicitly reviewed RPS trial; preserve independent management
  access and verify VLAN/WireGuard traffic where used.
- [ ] Exercise physical-setting readback, explicit rollback, deadline rollback,
  restart recovery and original restoration.
- [ ] Compare equivalent before/after loads; retain results and reject tuning
  that fails the agreed performance/connectivity criteria.

Physical acceptance is required before production tuning. Milestone 2 code can
be developed without enabling unverified settings on an appliance.

## 2. Safe NIC offload management and RFS

### Scope

Implemented live inspection and explicit control of driver-supported, changeable
checksum, GRO/GSO, TSO and VLAN offloads. Preserve individual feature names,
support/changeability, enabled state and error evidence. Do not equate feature
availability with a performance benefit.

Also implemented explicit RFS global/per-queue table sizes, with bounded
power-of-two budgets, RPS dependencies, identity checks and native recovery.
RFS targets local socket applications, not a promise of faster forwarding.
Active **and requested** offload bitmaps participate in exact readback and
original restoration. Driver side effects and oversized recovery snapshots fail
explicitly. Automatic host-mode tuning availability does not enable any setting.
See the [current contract](../FRONTEND_SPEC.md#explicit-rfs-and-nic-offload-configuration),
[handoff 2026-11-04-06](frontend-handoffs/2026-11-04.md#2026-11-04-06-nic-offload-controls-and-rfs)
and [journal](journal/2026-11-04.md#nic-offload-controls-and-rfs).
The following implementation checklist is retained as acceptance context, not
authorization to deploy or a claim that physical acceptance is complete.

### Implementation sequence

1. Read the current capability collector, RPS ownership/recovery code,
   configuration model, authorization, simulator, CLI and frontend contract.
   Reuse existing patterns; keep passive inventory separate from tuning.
2. Design a strict typed offload configuration and observation contract.
   Decide the supported feature set and dependency handling from verified
   kernel/driver semantics, not guessed aliases or an "enable all" profile.
3. Implement bounded direct Rust/kernel inspection and writes, with physical
   interface identity checks, automatic host-mode tuning ownership and explicit permissions.
   No external ethtool process or arbitrary command endpoint.
4. Capture original values durably before mutation. Integrate with complete
   confirmed transactions, exact post-write readback, apply failure recovery,
   timeout rollback, restart/reboot and restoration when ownership is released.
5. Account for driver-coupled changes: inspect affected feature state before
   and after writes, preserve unrelated settings, and reject unsupported or
   unachievable combinations explicitly.
6. Wire simulator, API reads, authorization, candidate/history/export handling
   and CLI consistently. Keep observed identity/changeability daemon-owned.
7. Update canonical documentation, examples where useful, changelog, journal
   and a new frontend handoff alongside the implemented contract.

### Acceptance

- [ ] Supported mutable features can be changed and verified; immutable,
  unknown, missing and permission-denied features fail explicitly.
- [ ] Interface replacement, driver side effects, partial writes and readback
  mismatches cannot produce a false success.
- [ ] Original state survives restart and interrupted-operation recovery.
  Removal, explicit rollback and deadline rollback restore the intended state.
- [ ] Existing firewall enforcement, NAT, VLAN/WireGuard traffic, accounting
  and diagnostic interpretation remain correct; document any intentional
  counter/capture semantics affected by segmentation or aggregation.
- [ ] Before/after testing measures throughput, CPU, drops and latency under
  equivalent loads. No speed claim without measured improvement.
- [ ] Run focused tests first, then the required locked stable workspace tests,
  strict Clippy, formatting and build; perform Linux physical-driver acceptance.

Do not enable `rx-all`, `rx-fcs` or every disabled feature as a generic speed
optimization. Most useful offloads may already be enabled.

## 3. Deferred: WAN smart queue management

The user explicitly deferred **all traffic shaping** while requesting offload
and RFS controls. The following is future design context only, not delivered
functionality or authorization to implement/enable it.

Goal: improve latency during uploads/downloads, not promise a higher link rate.

Before implementation, settle the following design using current backend code
and measured WAN behavior:

- Supported CAKE/FQ-CoDel options and required kernel facilities; explicitly
  reject unavailable support instead of silently substituting another policy.
- Upload/download rate units and limits, ingress shaping mechanism if included,
  link overhead handling and CPU cost.
- Ownership of qdiscs and any required virtual links, preservation of foreign
  objects, and interaction with VLANs, WireGuard and other managed networking.
- Transactional apply/readback, confirmation, crash recovery and restoration
  of prior queueing state.
- Frontend forms, permission checks, latency-under-load graphs and clear
  deployment prerequisites.

Use in-process Rust/kernel APIs, not supervised `tc` or other external programs.
Acceptance must compare loaded and unloaded latency, loss, throughput and CPU,
and verify management connectivity and rollback.

## Deferred until evidence justifies them

- Ring-buffer/coalescing controls: first verify driver support and measure
  throughput-versus-latency tradeoffs.
- Hardware accelerated RFS-specific driver controls: software RFS table
  configuration is implemented; no new hardware ntuple/RSS tuning is included.
- RSS/multiqueue controls: current inventory did not establish usable support.
- nftables software flow acceleration: first resolve policy-change, logging,
  counter, accounting and shaping interactions; no silent datapath bypass.
- Native/hardware XDP and AF_XDP zero-copy: reported unsupported in the supplied
  inventory. DPDK readiness remains unverified; do not infer PMD compatibility
  from PCI identity.

## How to resume

1. Read this plan, the latest [journal](journal), current
   [changelog](../CHANGELOG.md), [frontend handoffs](frontend-handoffs) and
   [canonical contract](../FRONTEND_SPEC.md).
2. Check the working tree and preserve unrelated changes. Reconfirm which
   milestones are actually implemented, reviewed, deployed and measured.
3. Finish physical/frontend acceptance for milestones 1 and 2; do not repeat
   delivered controls or treat container tests as physical acceptance.
   Traffic shaping remains deferred unless explicitly requested again.
4. Keep new work under Unreleased and use automatic calendar versioning.
   Planned runtime additions are expected to be additive, but document actual
   contract impact when designed; do not manually bump the release seed.
5. Update this plan's checkboxes/status only with evidence. Deployment, commits,
   pushes, publication and frontend notifications need explicit authorization.
