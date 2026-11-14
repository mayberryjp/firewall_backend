//! Bounded, in-process transport evidence at a client-visible L3 boundary.
use anyhow::{Result, ensure};
use netcontrol_core::experience::{
    Distribution, Dns, MAX_ADDRESSES, SourceStatus, Tcp, TransportEvidence, add_reason,
    rolling_evidence_memory_bound,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

pub const FLOW_LIMIT: usize = 8192;
pub const DNS_LIMIT: usize = 8192;
pub const PER_HOST_FLOW_LIMIT: usize = 32;
pub const PER_HOST_DNS_LIMIT: usize = 32;
pub const DNS_STREAM_LIMIT: usize = 256;
pub const TOMBSTONE_LIMIT: usize = 32768;
pub const PER_HOST_TOMBSTONE_LIMIT: usize = 2048;
const RANGES: usize = 8;
const MESSAGE_LIMIT: usize = 4096;
const STREAM_LIMIT: usize = MESSAGE_LIMIT + 2;
const DNS_DEADLINE: Duration = Duration::from_secs(5);
const TOMBSTONE_LIFETIME: Duration = Duration::from_secs(10);
const FLOW_LIFETIME: Duration = Duration::from_secs(120);
const MAX_NATIVE_REASONS: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct Analysis {
    pub tcp: Tcp,
    pub dns: Dns,
    pub evidence: TransportEvidence,
    pub analysis_exclusions: u64,
    pub tracking_evictions: u64,
    pub capture_dropped_packets: u64,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    peer: IpAddr,
    host_port: u16,
    peer_port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DnsKey {
    flow: FlowKey,
    tcp: bool,
    stream: u64,
    id: u16,
    question: [u8; 32],
}
struct Attempt {
    started: Instant,
    ambiguous: bool,
}
struct Tombstone {
    fingerprint: [u8; 32],
    expires: Instant,
}
struct DnsObservation<'a> {
    flow: &'a FlowKey,
    tcp: bool,
    stream: u64,
    sent: bool,
    at: Instant,
}
#[derive(Default)]
struct Direction {
    reference: Option<(u32, i64)>,
    covered: Vec<(i64, i64)>,
    pending: Vec<Pending>,
    acknowledged: Option<i64>,
    ambiguity_until: Option<i64>,
    previous_rtt: Option<f64>,
    scale: Option<u8>,
    syn_seen: bool,
    syn_sequence: Option<u32>,
    window: Option<(u32, u32, u16)>,
    fin_end: Option<i64>,
    trustworthy: bool,
}
struct Pending {
    start: i64,
    end: i64,
    at: Instant,
    ambiguous: bool,
}
struct Flow {
    directions: [Direction; 2],
    streams: Option<Box<[Stream; 2]>>,
    stream_id: u64,
    seen: Instant,
    fin_seen: [bool; 2],
    handshake_valid: bool,
}
impl Flow {
    fn new(now: Instant, stream_id: u64, dns: bool) -> Self {
        Self {
            directions: [Direction::fresh(), Direction::fresh()],
            streams: dns.then(|| Box::new([Stream::default(), Stream::default()])),
            stream_id,
            seen: now,
            fin_seen: [false; 2],
            handshake_valid: false,
        }
    }
}
#[derive(Default)]
struct Stream {
    next: Option<u32>,
    bytes: Vec<u8>,
    reordered: BTreeMap<u32, Vec<u8>>,
    broken: bool,
    first_at: Option<Instant>,
}
#[derive(Default)]
struct Counters {
    data: [u64; 2],
    repeats: [u64; 2],
    decreases: [u64; 2],
    zero: [u64; 2],
    transitions: [u64; 2],
    minimum: [Option<u64>; 2],
    rtt: [Distribution; 2],
    dns_time: Distribution,
    requests: u64,
    responses: u64,
    unanswered: u64,
    servfail: u64,
    refused: u64,
    excluded: u64,
    dns_excluded: u64,
    capacity: u64,
    capture_dropped: u64,
    tcp_seen: bool,
    dns_seen: bool,
    tcp_partial: bool,
    dns_partial: bool,
    reasons: Vec<String>,
}
impl Counters {
    fn exclude_observations(&mut self, count: u64, dns: bool) {
        self.excluded = self.excluded.saturating_add(count);
        if dns {
            self.dns_excluded = self.dns_excluded.saturating_add(count);
        }
    }
    fn exclude(&mut self, tcp: bool, dns: bool, reason: &str) {
        self.exclude_observations(1, dns);
        self.tcp_partial |= tcp;
        self.dns_partial |= dns;
        if self.reasons.len() < MAX_NATIVE_REASONS {
            add_reason(&mut self.reasons, reason);
        }
    }
    fn capacity(&mut self, tcp: bool, dns: bool) {
        self.capacity = self.capacity.saturating_add(1);
        self.exclude(tcp, dns, "tracking_capacity");
    }
}
#[derive(Default)]
struct Host {
    flows: BTreeMap<FlowKey, Flow>,
    dns: BTreeMap<DnsKey, Attempt>,
    tombstones: VecDeque<Tombstone>,
    // UDP source-port changes do not turn the same resolver into another timing population.
    previous_dns: BTreeMap<(IpAddr, bool, u64), (f64, Instant)>,
    counters: Counters,
    last_observation: Option<Instant>,
    dns_quarantine: Option<(Instant, &'static str)>,
    tcp_quarantine_until: Option<Instant>,
}

#[derive(Default)]
pub struct Analyzer {
    hosts: BTreeMap<IpAddr, Host>,
    flows: usize,
    dns: usize,
    streams: usize,
    tombstones: usize,
    next_stream: u64,
}

/// Conservative owned-allocation budget for the analyzer plus 6 * 2048 rolling
/// evidence slots. Includes allocation rounding, partially filled B-tree nodes,
/// both DNS stream directions and one MiB of packet/merge scratch. Excludes
/// SQLite/kernel buffers and the application's independently bounded API rows.
pub fn working_memory_bound() -> usize {
    use std::mem::size_of;
    const ALLOCATION_OVERHEAD: usize = 32;
    // std BTreeMap uses eleven key/value slots; nonroot nodes have >=5 keys.
    // Uneven borrowed allocation can leave a root in every host plus partially
    // filled nonroot nodes. Do not assume uniform fair-share occupancy.
    let maximum_nodes = MAX_ADDRESSES + FLOW_LIMIT / 5;
    let node = |key: usize, value: usize| 11 * (key + value) + 160;
    let host_map = (MAX_ADDRESSES / 5 + 1) * node(size_of::<IpAddr>(), size_of::<Host>());
    let flow_map = maximum_nodes * node(size_of::<FlowKey>(), size_of::<Flow>());
    let dns_map = maximum_nodes * node(size_of::<DnsKey>(), size_of::<Attempt>());
    let variations = maximum_nodes
        * node(
            size_of::<(IpAddr, bool, u64)>(),
            size_of::<(f64, Instant)>(),
        );
    let ranges = FLOW_LIMIT
        * 2
        * ((RANGES + 1) * size_of::<(i64, i64)>()
            + RANGES * size_of::<Pending>()
            + 2 * ALLOCATION_OVERHEAD);
    let streams = DNS_STREAM_LIMIT
        * (size_of::<[Stream; 2]>()
            + ALLOCATION_OVERHEAD
            + 2 * (8192
                + ALLOCATION_OVERHEAD
                + STREAM_LIMIT
                + 4 * ALLOCATION_OVERHEAD
                + node(size_of::<u32>(), size_of::<Vec<u8>>())));
    let reasons = MAX_ADDRESSES
        * (MAX_NATIVE_REASONS * (size_of::<String>() + 32 + ALLOCATION_OVERHEAD)
            + ALLOCATION_OVERHEAD);
    // VecDeque growth can retain up to twice its live length, plus its initial
    // four-slot allocation per host; finalized state has a separate global cap.
    let tombstones = (2 * TOMBSTONE_LIMIT + 4 * MAX_ADDRESSES) * size_of::<Tombstone>()
        + MAX_ADDRESSES * ALLOCATION_OVERHEAD;
    size_of::<Analyzer>()
        + host_map
        + flow_map
        + dns_map
        + variations
        + ranges
        + streams
        + reasons
        + tombstones
        + rolling_evidence_memory_bound()
        + 1024 * 1024
}

impl Analyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace eligibility, preserving only unchanged addresses. No silent lower host limit.
    pub fn configure<I: IntoIterator<Item = IpAddr>>(&mut self, addresses: I) -> Result<()> {
        let mut eligible = BTreeSet::new();
        for address in addresses {
            eligible.insert(address);
            ensure!(
                eligible.len() <= MAX_ADDRESSES,
                "experience eligibility exceeds 2048 IPs"
            );
        }
        self.hosts.retain(|address, _| eligible.contains(address));
        for address in eligible {
            self.hosts.entry(address).or_default();
        }
        let variation_limit = self.host_limits().1;
        for host in self.hosts.values_mut() {
            while host.previous_dns.len() > variation_limit {
                host.previous_dns.pop_first();
            }
        }
        self.recount();
        Ok(())
    }
    /// Fair shares protected under global pressure, not hard admission caps.
    pub fn host_limits(&self) -> (usize, usize) {
        (
            PER_HOST_FLOW_LIMIT.min(FLOW_LIMIT / self.hosts.len().max(1)),
            PER_HOST_DNS_LIMIT.min(DNS_LIMIT / self.hosts.len().max(1)),
        )
    }
    fn recount(&mut self) {
        self.flows = self.hosts.values().map(|h| h.flows.len()).sum();
        self.dns = self.hosts.values().map(|h| h.dns.len()).sum();
        self.streams = self
            .hosts
            .values()
            .flat_map(|h| h.flows.values())
            .filter(|f| f.streams.is_some())
            .count();
        self.tombstones = self.hosts.values().map(|h| h.tombstones.len()).sum();
    }
    /// Capture gaps discard correlations, not finalized bucket evidence.
    pub fn reset(&mut self) {
        let now = Instant::now();
        for host in self.hosts.values_mut() {
            host.flows.clear();
            host.dns.clear();
            host.tombstones = VecDeque::new();
            host.previous_dns.clear();
            host.counters.exclude(true, true, "capture_gap");
            host.last_observation = None;
            host.dns_quarantine = Some((now + DNS_DEADLINE + TOMBSTONE_LIFETIME, "capture_gap"));
        }
        self.recount();
    }
    pub fn capture_gap(&mut self, dropped_packets: u64) {
        self.reset();
        for host in self.hosts.values_mut() {
            host.counters.capture_dropped = host
                .counters
                .capture_dropped
                .saturating_add(dropped_packets);
        }
    }
    pub fn reset_host(&mut self, address: IpAddr) {
        if let Some(host) = self.hosts.get_mut(&address) {
            host.flows.clear();
            host.dns.clear();
            host.tombstones = VecDeque::new();
            host.previous_dns.clear();
            host.counters
                .exclude(true, true, "configuration_transition");
            host.last_observation = None;
            host.dns_quarantine = Some((
                Instant::now() + DNS_DEADLINE + TOMBSTONE_LIFETIME,
                "configuration_transition",
            ));
        }
        self.recount();
    }
    #[cfg(test)]
    pub fn observe(
        &mut self,
        address: IpAddr,
        sent: bool,
        network_packet: &[u8],
        at: Instant,
    ) -> Result<()> {
        self.observe_translated(address, sent, network_packet, at, None)
    }
    /// Restore the client-visible destination from validated conntrack metadata.
    /// Received LAN packets are already reverse-NATed and never overridden.
    pub fn observe_translated(
        &mut self,
        address: IpAddr,
        sent: bool,
        network_packet: &[u8],
        at: Instant,
        original_destination: Option<(IpAddr, u16)>,
    ) -> Result<()> {
        let Some(slot) = self.hosts.get_mut(&address) else {
            anyhow::bail!("IP is not configured for experience analysis");
        };
        // Keep the membership tree stable on the packet path while donor
        // reclamation borrows other hosts. The empty slot cannot be a donor.
        let mut host = std::mem::take(slot);
        self.flows -= host.flows.len();
        self.dns -= host.dns.len();
        self.tombstones -= host.tombstones.len();
        self.streams -= host
            .flows
            .values()
            .filter(|flow| flow.streams.is_some())
            .count();
        let result = self.observe_host(
            address,
            sent,
            network_packet,
            at,
            &mut host,
            original_destination,
        );
        self.flows += host.flows.len();
        self.dns += host.dns.len();
        self.tombstones += host.tombstones.len();
        self.streams += host
            .flows
            .values()
            .filter(|flow| flow.streams.is_some())
            .count();
        *self.hosts.get_mut(&address).expect("configured host slot") = host;
        result
    }
    fn observe_host(
        &mut self,
        address: IpAddr,
        sent: bool,
        network_packet: &[u8],
        at: Instant,
        host: &mut Host,
        original_destination: Option<(IpAddr, u16)>,
    ) -> Result<()> {
        let decoded = packet(network_packet);
        if host.last_observation.is_some_and(|last| at < last) {
            host.flows.clear();
            host.dns.clear();
            host.tombstones = VecDeque::new();
            host.previous_dns.clear();
            host.dns_quarantine = Some((at + DNS_DEADLINE + TOMBSTONE_LIFETIME, "capture_gap"));
            host.counters.exclude(true, true, "capture_gap");
            self.recount();
            anyhow::bail!("nonmonotonic capture timestamp");
        }
        host.last_observation = Some(at);
        let mut packet = match decoded {
            Ok(Some(packet)) => packet,
            Ok(None) => {
                host.counters.exclude(true, true, "unsupported_transport");
                // Missing fragment/header evidence can conceal a DNS response or ACK.
                host.flows.clear();
                host.dns.clear();
                host.tombstones = VecDeque::new();
                host.previous_dns.clear();
                host.dns_quarantine = Some((at + DNS_DEADLINE + TOMBSTONE_LIFETIME, "capture_gap"));
                self.recount();
                return Ok(());
            }
            Err(error) => {
                host.counters.exclude(true, true, "capture_gap");
                host.flows.clear();
                host.dns.clear();
                host.tombstones = VecDeque::new();
                host.previous_dns.clear();
                host.dns_quarantine = Some((at + DNS_DEADLINE + TOMBSTONE_LIFETIME, "capture_gap"));
                self.recount();
                return Err(error);
            }
        };
        if sent {
            if let Some((destination, port)) = original_destination {
                packet.destination = destination;
                packet.destination_port = port;
            }
        }
        ensure!(
            if sent {
                packet.source == address
            } else {
                packet.destination == address
            },
            "packet does not match host perspective"
        );
        if !matches!(packet.protocol, 6 | 17) {
            return Ok(());
        }
        let key = FlowKey {
            peer: if sent {
                packet.destination
            } else {
                packet.source
            },
            host_port: if sent {
                packet.source_port
            } else {
                packet.destination_port
            },
            peer_port: if sent {
                packet.destination_port
            } else {
                packet.source_port
            },
        };
        if packet.protocol == 17 {
            if key.peer_port != 53 {
                return Ok(());
            }
            expire_dns(host, at, TOMBSTONE_LIMIT.saturating_sub(self.tombstones));
            host.counters.dns_seen = true;
            if packet.payload.len() != packet.data_len || packet.payload.len() > MESSAGE_LIMIT {
                host.counters.exclude(false, true, "unsupported_dns");
                invalidate_dns(host, &key, false, None);
            } else {
                self.dns_message(
                    host,
                    DnsObservation {
                        flow: &key,
                        tcp: false,
                        stream: 0,
                        sent,
                        at,
                    },
                    packet.payload,
                );
            }
            return Ok(());
        }
        let direction = usize::from(!sent);
        host.counters.tcp_seen = true;
        let is_dns = key.peer_port == 53;
        if is_dns {
            expire_dns(host, at, TOMBSTONE_LIMIT.saturating_sub(self.tombstones));
        }
        if !host.flows.contains_key(&key) {
            if host.tcp_quarantine_until.is_some_and(|until| at < until) && !packet.syn {
                host.counters.exclude(true, is_dns, "tracking_capacity");
                return Ok(());
            }
            let global_full = self.flows + host.flows.len() >= FLOW_LIMIT;
            if host.flows.len() >= PER_HOST_FLOW_LIMIT
                || (global_full && !self.reclaim_flow(host.flows.len(), at))
            {
                host.counters.capacity(true, is_dns);
                return Ok(());
            }
            self.next_stream = self.next_stream.wrapping_add(1);
            let local_streams = host
                .flows
                .values()
                .filter(|flow| flow.streams.is_some())
                .count();
            let admit_dns = is_dns && self.streams + local_streams < DNS_STREAM_LIMIT;
            if is_dns && !admit_dns {
                host.counters.capacity(false, true);
            }
            host.flows
                .insert(key.clone(), Flow::new(at, self.next_stream, admit_dns));
        }
        let flow = host.flows.get_mut(&key).expect("admitted flow");
        flow.seen = at;
        let mut replaced_stream = None;
        // A new initial SYN replaces stale tuples without joining stream identities.
        if packet.syn && !packet.ack {
            let old_id = flow.stream_id;
            let duplicate = flow.directions[direction].syn_seen
                && flow.directions[direction]
                    .reference
                    .is_some_and(|(seq, _)| seq == packet.sequence);
            if !duplicate {
                self.next_stream = self.next_stream.wrapping_add(1);
                let dns = flow.streams.is_some();
                *flow = Flow::new(at, self.next_stream, dns);
                replaced_stream = Some(old_id);
            }
        }
        let counters = &mut host.counters;
        if packet.syn {
            flow.directions[direction].syn_seen = true;
            flow.directions[direction].syn_sequence = Some(packet.sequence);
            flow.directions[direction].scale = packet.scale;
            flow.directions[direction].reference = Some((packet.sequence, 0));
            if packet.ack
                && flow.directions[1 - direction]
                    .syn_sequence
                    .is_some_and(|seq| packet.acknowledgment == seq.wrapping_add(1))
            {
                flow.handshake_valid = true;
            }
            if let Some(streams) = &mut flow.streams {
                if streams[direction].next.is_none() {
                    streams[direction].next = Some(packet.sequence.wrapping_add(1));
                }
            }
        }
        observe_window(flow, direction, &packet, counters);
        if packet.ack {
            flow.directions[1 - direction].ack(packet.acknowledgment, at, 1 - direction, counters);
        }
        let mut repeated = false;
        if packet.data_len > 0 {
            counters.data[direction] = counters.data[direction].saturating_add(1);
            repeated = flow.directions[direction].data(
                packet.sequence.wrapping_add(u32::from(packet.syn)),
                packet.data_len,
                at,
                direction,
                counters,
            );
        }
        let stream_id = flow.stream_id;
        let mut messages = Vec::new();
        let mut broken = false;
        if is_dns {
            counters.dns_seen = true;
            if let Some(streams) = &mut flow.streams {
                match streams[direction].feed(
                    packet.sequence.wrapping_add(u32::from(packet.syn)),
                    packet.payload,
                    packet.data_len,
                    at,
                ) {
                    Ok(decoded) => messages = decoded,
                    Err(_) => {
                        counters.exclude(false, true, "unsupported_dns");
                        broken = true;
                    }
                }
            }
        }
        if packet.fin {
            flow.fin_seen[direction] = true;
            let end = packet
                .sequence
                .wrapping_add(u32::from(packet.syn))
                .wrapping_add(packet.data_len as u32)
                .wrapping_add(1);
            flow.directions[direction].fin_end = flow.directions[direction].unwrap(end);
        }
        let close = packet.rst || flow.fin_seen.iter().all(|fin| *fin);
        if let Some(old_id) = replaced_stream {
            invalidate_dns(host, &key, true, Some(old_id));
        }
        if repeated && is_dns && sent {
            for (dns_key, attempt) in &mut host.dns {
                if dns_key.flow == key && dns_key.tcp && dns_key.stream == stream_id {
                    attempt.ambiguous = true;
                    host.counters.exclude_observations(1, true);
                }
            }
            host.previous_dns.remove(&(key.peer, true, stream_id));
        }
        if broken {
            invalidate_dns(host, &key, true, Some(stream_id));
        }
        for (message, _) in messages {
            self.dns_message(
                host,
                DnsObservation {
                    flow: &key,
                    tcp: true,
                    stream: stream_id,
                    sent,
                    at,
                },
                &message,
            );
        }
        // Do not bridge DNS variation across tuple reuse, expiry or close.
        let current_stream = host.flows.get(&key).map(|f| f.stream_id);
        host.dns
            .retain(|k, _| k.flow != key || !k.tcp || Some(k.stream) == current_stream);
        if close {
            invalidate_dns(host, &key, true, current_stream);
            host.flows.remove(&key);
        }
        Ok(())
    }
    fn reclaim_flow(&mut self, requester_count: usize, at: Instant) -> bool {
        let fair = PER_HOST_FLOW_LIMIT.min(FLOW_LIMIT / self.hosts.len().max(1));
        if requester_count >= fair {
            return false;
        }
        let donor = self
            .hosts
            .iter()
            .filter(|(_, host)| host.flows.len() > fair)
            .max_by_key(|(_, host)| host.flows.len())
            .map(|(address, _)| *address);
        let Some(address) = donor else {
            return false;
        };
        let donor = self.hosts.get_mut(&address).expect("selected flow donor");
        let key = donor
            .flows
            .iter()
            .min_by_key(|(_, flow)| flow.seen)
            .map(|(key, _)| key.clone())
            .expect("borrowed flow");
        let removed = donor.flows.remove(&key).expect("selected borrowed flow");
        self.flows -= 1;
        self.streams -= usize::from(removed.streams.is_some());
        let pending_before = donor.dns.len();
        invalidate_dns(donor, &key, true, Some(removed.stream_id));
        quarantine_dns(donor, at, "tracking_capacity");
        self.dns -= pending_before;
        donor.counters.capacity(true, removed.streams.is_some());
        donor.tcp_quarantine_until = Some(at + DNS_DEADLINE + TOMBSTONE_LIFETIME);
        true
    }
    fn reclaim_dns(&mut self, requester_count: usize, at: Instant) -> bool {
        let fair = PER_HOST_DNS_LIMIT.min(DNS_LIMIT / self.hosts.len().max(1));
        if requester_count >= fair {
            return false;
        }
        let donor = self
            .hosts
            .iter()
            .filter(|(_, host)| host.dns.len() > fair)
            .max_by_key(|(_, host)| host.dns.len())
            .map(|(address, _)| *address);
        let Some(address) = donor else {
            return false;
        };
        let donor = self.hosts.get_mut(&address).expect("selected DNS donor");
        self.dns -= donor.dns.len();
        quarantine_dns(donor, at, "tracking_capacity");
        true
    }
    fn dns_message(&mut self, host: &mut Host, observation: DnsObservation<'_>, bytes: &[u8]) {
        let parsed = match dns_header(bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                host.counters.exclude(false, true, "unsupported_dns");
                invalidate_dns(
                    host,
                    observation.flow,
                    observation.tcp,
                    Some(observation.stream),
                );
                return;
            }
        };
        let key = DnsKey {
            flow: observation.flow.clone(),
            tcp: observation.tcp,
            stream: observation.stream,
            id: parsed.id,
            question: parsed.question,
        };
        let blocked = host
            .dns_quarantine
            .is_some_and(|(until, _)| observation.at < until)
            || host.dns.contains_key(&key)
            || tombstone_matches(host, &key, observation.at);
        let needs_slot =
            !parsed.response && observation.sent && !blocked && host.dns.len() < PER_HOST_DNS_LIMIT;
        let admission = self.dns + host.dns.len() < DNS_LIMIT
            || (needs_slot && self.reclaim_dns(host.dns.len(), observation.at));
        let variation_limit = PER_HOST_DNS_LIMIT.min(DNS_LIMIT / self.hosts.len().max(1));
        dns_message(
            host,
            observation,
            parsed,
            admission,
            variation_limit,
            TOMBSTONE_LIMIT.saturating_sub(self.tombstones),
        );
    }

    /// Finalize interval counters; pending exchanges remain until outcome/deadline.
    pub fn finish(&mut self, address: IpAddr, now: Instant) -> Analysis {
        let Some(host) = self.hosts.get_mut(&address) else {
            return Analysis::default();
        };
        let dns_before = host.dns.len();
        let tombstones_before = host.tombstones.len();
        expire_dns(
            host,
            now,
            TOMBSTONE_LIMIT - self.tombstones + tombstones_before,
        );
        let expired: Vec<_> = host
            .flows
            .iter()
            .filter(|(_, flow)| now.saturating_duration_since(flow.seen) >= FLOW_LIFETIME)
            .map(|(key, flow)| (key.clone(), flow.stream_id))
            .collect();
        for (key, stream_id) in expired {
            if let Some(flow) = host.flows.remove(&key) {
                self.flows -= 1;
                self.streams -= usize::from(flow.streams.is_some());
            }
            invalidate_dns(host, &key, true, Some(stream_id));
        }
        let pending = host
            .dns
            .values()
            .filter(|request| !request.ambiguous)
            .count();
        let mut counters = std::mem::take(&mut host.counters);
        let invalid_tcp_timings = counters.rtt.iter().filter(|r| r.overflowed).count();
        counters.exclude_observations(invalid_tcp_timings as u64, false);
        counters.exclude_observations(u64::from(counters.dns_time.overflowed), true);
        let tcp_complete = !counters.tcp_partial && !counters.rtt.iter().any(|r| r.overflowed);
        let dns_complete = !counters.dns_partial && !counters.dns_time.overflowed;
        let mut reasons = counters.reasons.clone();
        if counters.rtt.iter().any(|r| r.overflowed) || counters.dns_time.overflowed {
            add_reason(&mut reasons, "invalid_timing_evidence");
        }
        if counters.zero[0] > 0 {
            add_reason(&mut reasons, "host_zero_window");
        }
        if counters.zero[1] > 0 {
            add_reason(&mut reasons, "peer_zero_window");
        }
        let tcp = if counters.tcp_seen || counters.tcp_partial {
            Tcp {
                status: if tcp_complete {
                    SourceStatus::Available
                } else {
                    SourceStatus::Partial
                },
                error: None,
                data_packets_sent: Some(counters.data[0].into()),
                data_packets_received: Some(counters.data[1].into()),
                retransmission_observations_sent: tcp_complete.then(|| counters.repeats[0].into()),
                retransmission_observations_received: tcp_complete
                    .then(|| counters.repeats[1].into()),
                retransmission_percent_sent: (tcp_complete && counters.data[0] > 0)
                    .then(|| counters.repeats[0] as f64 * 100.0 / counters.data[0] as f64),
                retransmission_percent_received: (tcp_complete && counters.data[1] > 0)
                    .then(|| counters.repeats[1] as f64 * 100.0 / counters.data[1] as f64),
                window_decreases_host: Some(counters.decreases[0].into()),
                window_decreases_peer: Some(counters.decreases[1].into()),
                zero_window_observations_host: Some(counters.zero[0].into()),
                zero_window_observations_peer: Some(counters.zero[1].into()),
                zero_window_transitions_host: Some(counters.transitions[0].into()),
                zero_window_transitions_peer: Some(counters.transitions[1].into()),
                advertised_window_min_bytes_host: counters.minimum[0],
                advertised_window_min_bytes_peer: counters.minimum[1],
                rtt_remote: counters.rtt[0].summary(),
                rtt_host: counters.rtt[1].summary(),
            }
        } else {
            Tcp {
                status: SourceStatus::NotObserved,
                ..Tcp::default()
            }
        };
        let dns = if counters.dns_seen
            || counters.dns_partial
            || pending > 0
            || counters.unanswered > 0
        {
            let summary = counters.dns_time.summary();
            let finalized = counters.responses.saturating_add(counters.unanswered);
            Dns {
                status: if dns_complete {
                    SourceStatus::Available
                } else {
                    SourceStatus::Partial
                },
                error: None,
                requests: Some(counters.requests.into()),
                responses: Some(counters.responses.into()),
                unanswered: Some(counters.unanswered.into()),
                pending_at_close: Some((pending as u64).into()),
                servfail_responses: Some(counters.servfail.into()),
                refused_responses: Some(counters.refused.into()),
                excluded_observations: Some(counters.dns_excluded.into()),
                response_time_p50_ms: summary.p50_ms,
                response_time_p95_ms: summary.p95_ms,
                response_time_variation_mean_ms: summary.variation_mean_ms,
                unanswered_percent: (dns_complete && finalized > 0)
                    .then(|| counters.unanswered as f64 * 100.0 / finalized as f64),
            }
        } else {
            Dns {
                status: SourceStatus::NotObserved,
                ..Dns::default()
            }
        };
        let [remote_rtt, host_rtt] = counters.rtt;
        let result = Analysis {
            tcp,
            dns,
            evidence: TransportEvidence {
                tcp_complete,
                dns_complete,
                data_sent: counters.data[0],
                data_received: counters.data[1],
                repeats_sent: counters.repeats[0],
                repeats_received: counters.repeats[1],
                dns_responses: counters.responses,
                dns_unanswered: counters.unanswered,
                remote_rtt,
                host_rtt,
                dns_time: counters.dns_time,
                reasons: reasons.clone(),
            },
            analysis_exclusions: counters.excluded,
            tracking_evictions: counters.capacity,
            capture_dropped_packets: counters.capture_dropped,
            reasons,
        };
        self.dns = self.dns - dns_before + host.dns.len();
        self.tombstones = self.tombstones - tombstones_before + host.tombstones.len();
        result
    }
}

impl Direction {
    fn fresh() -> Self {
        Self {
            trustworthy: true,
            ..Self::default()
        }
    }
    fn unwrap(&self, sequence: u32) -> Option<i64> {
        let (wire, absolute) = self.reference?;
        let delta = sequence.wrapping_sub(wire);
        if delta == 1 << 31 {
            return None;
        }
        Some(absolute + i64::from(delta as i32))
    }
    fn data(
        &mut self,
        sequence: u32,
        length: usize,
        at: Instant,
        direction: usize,
        counters: &mut Counters,
    ) -> bool {
        if !self.trustworthy {
            counters.exclude(true, false, "tracking_capacity");
            return false;
        }
        if self.reference.is_none() {
            self.reference = Some((sequence, 0));
        }
        let Some(start) = self.unwrap(sequence) else {
            counters.exclude(true, false, "sequence_ambiguity");
            self.trustworthy = false;
            self.pending.clear();
            self.previous_rtt = None;
            return false;
        };
        let end = start + length as i64;
        let overlap = self.covered.iter().any(|(lo, hi)| start < *hi && end > *lo);
        if overlap {
            counters.repeats[direction] = counters.repeats[direction].saturating_add(1);
            for pending in &mut self.pending {
                if start < pending.end && end > pending.start {
                    pending.ambiguous = true;
                }
            }
            if self.acknowledged.is_none_or(|ack| end > ack) {
                self.ambiguity_until =
                    Some(self.ambiguity_until.map_or(end, |limit| limit.max(end)));
            }
            self.previous_rtt = None;
        }
        self.covered.push((start, end));
        self.covered.sort_unstable();
        let mut merged: Vec<(i64, i64)> = Vec::with_capacity(RANGES + 1);
        for &(lo, hi) in &self.covered {
            if let Some(previous) = merged.last_mut().filter(|previous| lo <= previous.1) {
                previous.1 = previous.1.max(hi);
            } else {
                merged.push((lo, hi));
            }
        }
        if merged.len() > RANGES {
            counters.capacity(true, false);
            // Discarding disjoint evidence invalidates future overlap classification.
            self.pending.clear();
            self.previous_rtt = None;
            self.trustworthy = false;
            merged.remove(0);
        }
        self.covered = merged;
        if self.reference.is_none_or(|(_, absolute)| end > absolute) {
            self.reference = Some((sequence.wrapping_add(length as u32), end));
        }
        if !overlap && self.acknowledged.is_none_or(|ack| end > ack) {
            if self.pending.len() >= RANGES {
                let removed = self.pending.remove(0);
                self.ambiguity_until = Some(
                    self.ambiguity_until
                        .map_or(removed.end, |v| v.max(removed.end)),
                );
                self.previous_rtt = None;
                counters.capacity(true, false);
            }
            self.pending.push(Pending {
                start,
                end,
                at,
                ambiguous: false,
            });
            self.pending.sort_by_key(|p| p.end);
        }
        overlap
    }
    fn ack(&mut self, sequence: u32, at: Instant, direction: usize, counters: &mut Counters) {
        if !self.trustworthy {
            return;
        }
        let Some(mut ack) = self.unwrap(sequence) else {
            return;
        };
        if self.acknowledged.is_some_and(|previous| ack <= previous) {
            return;
        }
        let Some(maximum) = self.covered.last().map(|range| range.1) else {
            return;
        };
        if self.fin_end == Some(ack) && ack == maximum + 1 {
            ack = maximum;
        }
        if ack > maximum {
            // An ACK for data absent from capture cannot time whatever remains.
            self.pending.clear();
            self.previous_rtt = None;
            self.acknowledged = Some(ack);
            counters.exclude(true, false, "capture_gap");
            return;
        }
        let newly: Vec<_> = self.pending.iter().filter(|p| p.end <= ack).collect();
        let crossed_gap = if let Some(first) = newly.first() {
            !self
                .covered
                .iter()
                .any(|(lo, hi)| *lo <= first.start && *hi >= ack)
        } else {
            false
        };
        let ambiguous = crossed_gap
            || newly.iter().any(|p| p.ambiguous)
            || self
                .ambiguity_until
                .is_some_and(|limit| self.acknowledged.is_none_or(|old| old < limit));
        if !ambiguous {
            // One cumulative ACK contributes one sample, never one per acknowledged packet.
            if let Some(candidate) = newly.last().filter(|p| at >= p.at) {
                let value = at.duration_since(candidate.at).as_secs_f64() * 1000.0;
                counters.rtt[direction].push(value, self.previous_rtt);
                self.previous_rtt = Some(value);
            }
        } else {
            self.previous_rtt = None;
        }
        self.pending.retain(|p| p.end > ack);
        self.acknowledged = Some(ack);
        if self.ambiguity_until.is_some_and(|limit| ack >= limit) {
            self.ambiguity_until = None;
        }
    }
}

fn newer_or_equal(value: u32, previous: u32) -> bool {
    value.wrapping_sub(previous) < 1 << 31
}
fn observe_window(flow: &mut Flow, direction: usize, packet: &Packet<'_>, counters: &mut Counters) {
    if packet.syn || !packet.ack {
        return;
    }
    let scaling = flow.handshake_valid && flow.directions.iter().all(|d| d.syn_seen);
    let scale = if scaling && flow.directions.iter().all(|d| d.scale.is_some()) {
        flow.directions[direction].scale.unwrap_or(0)
    } else {
        0
    };
    let row = &mut flow.directions[direction];
    counters.zero[direction] += u64::from(packet.window == 0);
    if packet.window == 0 || scaling {
        let bytes = u64::from(packet.window) << scale;
        counters.minimum[direction] =
            Some(counters.minimum[direction].map_or(bytes, |v| v.min(bytes)));
    }
    let ordered = row.window.is_none_or(|(seq, ack, _)| {
        newer_or_equal(packet.sequence, seq) && newer_or_equal(packet.acknowledgment, ack)
    });
    if ordered {
        if let Some((_, _, previous)) = row.window {
            counters.decreases[direction] += u64::from(packet.window < previous);
            counters.transitions[direction] += u64::from(previous > 0 && packet.window == 0);
        }
        row.window = Some((packet.sequence, packet.acknowledgment, packet.window));
    }
}

impl Stream {
    fn break_stream(&mut self) {
        self.broken = true;
        self.bytes.clear();
        self.reordered.clear();
        self.first_at = None;
    }
    fn feed(
        &mut self,
        sequence: u32,
        payload: &[u8],
        full_length: usize,
        at: Instant,
    ) -> Result<Vec<(Vec<u8>, Instant)>> {
        if full_length == 0 {
            return Ok(Vec::new());
        }
        if self.broken || self.next.is_none() || payload.len() != full_length {
            self.break_stream();
            anyhow::bail!("incomplete DNS stream");
        }
        let next = self.next.expect("validated stream baseline");
        let change = sequence.wrapping_sub(next);
        if change == 1 << 31 {
            self.break_stream();
            anyhow::bail!("ambiguous DNS sequence");
        }
        let offset = change as i32;
        let mut sequence = sequence;
        let mut payload = payload;
        if offset < 0 {
            let already = (-(i64::from(offset))) as usize;
            if already >= payload.len() {
                return Ok(Vec::new());
            }
            payload = &payload[already..];
            sequence = next;
        } else if offset > 0 {
            let retained = self.reordered.values().map(Vec::len).sum::<usize>() + self.bytes.len();
            if self
                .reordered
                .get(&sequence)
                .is_some_and(|old| old.as_slice() == payload)
            {
                return Ok(Vec::new());
            }
            // Overlapping reordered payload is ambiguous; never choose arbitrary bytes.
            if self.reordered.iter().any(|(seq, bytes)| {
                let start = seq.wrapping_sub(next) as i32;
                offset < start + bytes.len() as i32 && offset + payload.len() as i32 > start
            }) || self.reordered.len() >= 4
                || retained + payload.len() > STREAM_LIMIT
            {
                self.break_stream();
                anyhow::bail!("DNS stream reassembly limit or ambiguity");
            }
            self.reordered.insert(sequence, payload.to_vec());
            return Ok(Vec::new());
        }
        let overlapping: Vec<_> = self
            .reordered
            .keys()
            .copied()
            .filter(|seq| {
                let start = seq.wrapping_sub(next) as i32;
                start >= 0 && (start as usize) < payload.len()
            })
            .collect();
        for queued in overlapping {
            let bytes = self.reordered.remove(&queued).expect("selected overlap");
            let start = queued.wrapping_sub(next) as usize;
            let overlap = (payload.len() - start).min(bytes.len());
            if payload[start..start + overlap] != bytes[..overlap] {
                self.break_stream();
                anyhow::bail!("conflicting DNS stream overlap");
            }
            if overlap < bytes.len() {
                self.reordered.insert(
                    queued.wrapping_add(overlap as u32),
                    bytes[overlap..].to_vec(),
                );
            }
        }
        let mut messages = Vec::new();
        if let Err(error) = self.append(payload, at, &mut messages) {
            self.break_stream();
            return Err(error);
        }
        self.next = Some(sequence.wrapping_add(payload.len() as u32));
        loop {
            let next = self.next.expect("stream baseline");
            let Some((seq, _)) = self
                .reordered
                .iter()
                .find(|(seq, _)| (**seq).wrapping_sub(next) == 0)
                .map(|(seq, bytes)| (*seq, bytes.len()))
            else {
                break;
            };
            let bytes = self.reordered.remove(&seq).expect("selected segment");
            if let Err(error) = self.append(&bytes, at, &mut messages) {
                self.break_stream();
                return Err(error);
            }
            self.next = Some(seq.wrapping_add(bytes.len() as u32));
        }
        Ok(messages)
    }
    fn append(
        &mut self,
        mut payload: &[u8],
        at: Instant,
        messages: &mut Vec<(Vec<u8>, Instant)>,
    ) -> Result<()> {
        while !payload.is_empty() {
            if self.bytes.is_empty() {
                self.first_at = Some(at);
            }
            let desired = if self.bytes.len() < 2 {
                2
            } else {
                usize::from(u16::from_be_bytes([self.bytes[0], self.bytes[1]])) + 2
            };
            if desired > STREAM_LIMIT || (desired > 2 && desired < 14) {
                self.break_stream();
                anyhow::bail!("unsupported DNS frame length");
            }
            let take = (desired - self.bytes.len()).min(payload.len());
            self.bytes.extend_from_slice(&payload[..take]);
            payload = &payload[take..];
            if self.bytes.len() == desired && desired > 2 {
                ensure!(messages.len() < 256, "too many coalesced DNS frames");
                messages.push((self.bytes[2..].to_vec(), self.first_at.unwrap_or(at)));
                self.bytes.clear();
                self.first_at = None;
            } else if self.bytes.len() == 2 {
                let size = usize::from(u16::from_be_bytes([self.bytes[0], self.bytes[1]]));
                if !(12..=MESSAGE_LIMIT).contains(&size) {
                    self.break_stream();
                    anyhow::bail!("unsupported DNS frame length");
                }
            }
        }
        Ok(())
    }
}

fn invalidate_dns(host: &mut Host, flow: &FlowKey, tcp: bool, stream: Option<u64>) {
    let mut removed = 0u64;
    host.dns.retain(|key, _| {
        let matched =
            key.flow == *flow && key.tcp == tcp && stream.is_none_or(|id| key.stream == id);
        if matched {
            removed += 1;
        }
        !matched
    });
    host.counters.exclude_observations(removed, true);
    host.previous_dns.retain(|(key, transport, id), _| {
        *key != flow.peer || *transport != tcp || !stream.is_none_or(|stream| stream == *id)
    });
}
fn quarantine_dns(host: &mut Host, at: Instant, reason: &'static str) {
    for _ in 0..host.dns.len() {
        host.counters.capacity(false, true);
    }
    host.dns.clear();
    host.previous_dns.clear();
    host.dns_quarantine = Some((at + DNS_DEADLINE + TOMBSTONE_LIFETIME, reason));
}
fn dns_fingerprint(key: &DnsKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    match key.flow.peer {
        IpAddr::V4(address) => {
            hash.update([4]);
            hash.update(address.octets());
        }
        IpAddr::V6(address) => {
            hash.update([6]);
            hash.update(address.octets());
        }
    }
    hash.update(key.flow.host_port.to_be_bytes());
    hash.update(key.flow.peer_port.to_be_bytes());
    hash.update([u8::from(key.tcp)]);
    hash.update(key.stream.to_be_bytes());
    hash.update(key.id.to_be_bytes());
    hash.update(key.question);
    hash.finalize().into()
}
fn tombstone_matches(host: &Host, key: &DnsKey, at: Instant) -> bool {
    let fingerprint = dns_fingerprint(key);
    host.tombstones
        .iter()
        .any(|tombstone| tombstone.expires > at && tombstone.fingerprint == fingerprint)
}
fn remember_dns(
    host: &mut Host,
    key: &DnsKey,
    finalized: Instant,
    now: Instant,
    tombstone_budget: usize,
) -> bool {
    let expires = finalized + TOMBSTONE_LIFETIME;
    if expires <= now {
        return true;
    }
    if host.tombstones.len() >= PER_HOST_TOMBSTONE_LIMIT
        || host.tombstones.len() >= tombstone_budget
    {
        host.counters.capacity(false, true);
        quarantine_dns(host, now, "tracking_capacity");
        return false;
    }
    host.tombstones.push_back(Tombstone {
        fingerprint: dns_fingerprint(key),
        expires,
    });
    true
}
fn expire_dns(host: &mut Host, now: Instant, tombstone_budget: usize) {
    host.tombstones.retain(|tombstone| tombstone.expires > now);
    if host.tombstones.is_empty() {
        host.tombstones = VecDeque::new();
    } else if host.tombstones.len() * 2 < host.tombstones.capacity() {
        host.tombstones.shrink_to_fit();
    }
    let expired: Vec<_> = host
        .dns
        .iter()
        .filter(|(_, attempt)| now.saturating_duration_since(attempt.started) >= DNS_DEADLINE)
        .map(|(key, _)| key.clone())
        .collect();
    for key in expired {
        let Some(attempt) = host.dns.remove(&key) else {
            continue;
        };
        host.previous_dns
            .remove(&(key.flow.peer, key.tcp, key.stream));
        if !attempt.ambiguous {
            host.counters.unanswered = host.counters.unanswered.saturating_add(1);
        }
        remember_dns(
            host,
            &key,
            attempt.started + DNS_DEADLINE,
            now,
            tombstone_budget,
        );
    }
    host.previous_dns
        .retain(|_, (_, at)| now.saturating_duration_since(*at) < FLOW_LIFETIME);
}
fn dns_message(
    host: &mut Host,
    observation: DnsObservation<'_>,
    parsed: DnsHeader,
    global_admission: bool,
    variation_limit: usize,
    tombstone_budget: usize,
) {
    let DnsObservation {
        flow,
        tcp,
        stream,
        sent,
        at,
    } = observation;
    if let Some((until, reason)) = host.dns_quarantine {
        if at < until {
            host.counters.exclude(false, true, reason);
            return;
        }
    }
    host.dns_quarantine = None;
    if parsed.response == sent {
        host.counters
            .exclude(false, true, "dns_direction_ambiguity");
        invalidate_dns(host, flow, tcp, Some(stream));
        return;
    }
    let key = DnsKey {
        flow: flow.clone(),
        tcp,
        stream,
        id: parsed.id,
        question: parsed.question,
    };
    let variation = (flow.peer, tcp, stream);
    if tombstone_matches(host, &key, at) {
        host.counters.exclude_observations(1, true);
        host.previous_dns.remove(&variation);
        return;
    }
    if !parsed.response {
        if let Some(attempt) = host.dns.get_mut(&key) {
            attempt.ambiguous = true;
            host.counters.exclude_observations(1, true);
            host.previous_dns.remove(&variation);
            return;
        }
        // ID reuse with different questions is still ambiguous for a response omitting/mutating questions.
        if host
            .dns
            .keys()
            .any(|k| k.flow == *flow && k.tcp == tcp && k.stream == stream && k.id == parsed.id)
        {
            host.counters.exclude(false, true, "dns_ambiguity");
            return;
        }
        if !global_admission || host.dns.len() >= PER_HOST_DNS_LIMIT {
            host.counters.capacity(false, true);
            host.previous_dns.remove(&variation);
            return;
        }
        host.counters.requests = host.counters.requests.saturating_add(1);
        host.dns.insert(
            key,
            Attempt {
                started: at,
                ambiguous: false,
            },
        );
        return;
    }
    let Some(attempt) = host.dns.remove(&key) else {
        host.counters.exclude_observations(1, true);
        host.previous_dns.remove(&variation);
        return;
    };
    if attempt.ambiguous || at < attempt.started {
        host.counters.exclude_observations(1, true);
        host.previous_dns.remove(&variation);
        remember_dns(host, &key, at, at, tombstone_budget);
        return;
    }
    if at.duration_since(attempt.started) >= DNS_DEADLINE {
        host.counters.unanswered = host.counters.unanswered.saturating_add(1);
        host.counters.exclude_observations(1, true);
        host.previous_dns.remove(&variation);
        remember_dns(
            host,
            &key,
            attempt.started + DNS_DEADLINE,
            at,
            tombstone_budget,
        );
        return;
    }
    host.counters.responses = host.counters.responses.saturating_add(1);
    host.counters.servfail += u64::from(parsed.rcode == 2);
    host.counters.refused += u64::from(parsed.rcode == 5);
    let time = at.duration_since(attempt.started).as_secs_f64() * 1000.0;
    let previous = host.previous_dns.get(&variation).map(|(time, _)| *time);
    host.counters.dns_time.push(time, previous);
    if !remember_dns(host, &key, at, at, tombstone_budget) {
        return;
    }
    if host.previous_dns.len() < variation_limit || host.previous_dns.contains_key(&variation) {
        host.previous_dns.insert(variation, (time, at));
    } else {
        host.counters.capacity(false, true);
    }
}

struct DnsHeader {
    id: u16,
    response: bool,
    rcode: u8,
    question: [u8; 32],
}
fn dns_header(bytes: &[u8]) -> Result<DnsHeader> {
    ensure!(
        (12..=MESSAGE_LIMIT).contains(&bytes.len()),
        "invalid DNS analysis size"
    );
    ensure!(
        bytes[2] & 0x78 == 0 && bytes[3] & 0x40 == 0,
        "unsupported DNS opcode/flags"
    );
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
    ensure!(questions == 1, "DNS requires one validated question");
    let mut position = 12;
    let mut hash = Sha256::new();
    dns_name(bytes, &mut position, Some(&mut hash))?;
    ensure!(position + 4 <= bytes.len(), "truncated DNS question");
    hash.update(&bytes[position..position + 4]);
    position += 4;
    // Validate complete records without retaining names or answers; TC UDP may
    // legally stop after complete question and the records actually present.
    let truncated = bytes[2] & 2 != 0;
    let records = [6, 8, 10]
        .iter()
        .map(|offset| usize::from(u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]])))
        .sum::<usize>();
    ensure!(records <= 512, "DNS record analysis bound");
    for _ in 0..records {
        if truncated && position == bytes.len() {
            break;
        }
        dns_name(bytes, &mut position, None)?;
        ensure!(position + 10 <= bytes.len(), "truncated DNS record header");
        let length = usize::from(u16::from_be_bytes([
            bytes[position + 8],
            bytes[position + 9],
        ]));
        position += 10;
        ensure!(
            position + length <= bytes.len(),
            "truncated DNS record data"
        );
        position += length;
    }
    ensure!(position == bytes.len(), "unparsed DNS trailing bytes");
    Ok(DnsHeader {
        id: u16::from_be_bytes([bytes[0], bytes[1]]),
        response: bytes[2] & 0x80 != 0,
        rcode: bytes[3] & 15,
        question: hash.finalize().into(),
    })
}
fn dns_name(bytes: &[u8], position: &mut usize, mut hash: Option<&mut Sha256>) -> Result<()> {
    let mut cursor = *position;
    let mut end = None;
    let mut expanded = 0usize;
    let mut visited = BTreeSet::new();
    for _ in 0..128 {
        ensure!(
            cursor < bytes.len() && visited.insert(cursor),
            "DNS name loop/truncation"
        );
        let length = bytes[cursor];
        if length & 0xc0 == 0xc0 {
            ensure!(cursor + 1 < bytes.len(), "truncated DNS pointer");
            let target = (usize::from(length & 63) << 8) | usize::from(bytes[cursor + 1]);
            ensure!(
                target < cursor && target >= 12,
                "invalid DNS compression pointer"
            );
            end.get_or_insert(cursor + 2);
            cursor = target;
            continue;
        }
        ensure!(length & 0xc0 == 0 && length <= 63, "invalid DNS label");
        cursor += 1;
        expanded += usize::from(length) + 1;
        ensure!(
            expanded <= 255 && cursor + usize::from(length) <= bytes.len(),
            "invalid DNS name size"
        );
        if let Some(hash) = hash.as_deref_mut() {
            hash.update([length]);
            for byte in &bytes[cursor..cursor + usize::from(length)] {
                hash.update([byte.to_ascii_lowercase()]);
            }
        }
        cursor += usize::from(length);
        if length == 0 {
            *position = end.unwrap_or(cursor);
            return Ok(());
        }
    }
    anyhow::bail!("DNS name complexity bound")
}

struct Packet<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    window: u16,
    scale: Option<u8>,
    payload: &'a [u8],
    data_len: usize,
}
fn packet(bytes: &[u8]) -> Result<Option<Packet<'_>>> {
    ensure!(!bytes.is_empty(), "empty IP capture");
    let (source, destination, mut offset, mut protocol, end, ipv6) = match bytes[0] >> 4 {
        4 => {
            ensure!(bytes.len() >= 20, "short IPv4 header");
            let offset = usize::from(bytes[0] & 15) * 4;
            let end = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            ensure!(
                offset >= 20 && offset <= bytes.len() && offset <= end,
                "invalid IPv4 length"
            );
            if u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0 {
                return Ok(None);
            }
            (
                IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                offset,
                bytes[9],
                end,
                false,
            )
        }
        6 => {
            ensure!(bytes.len() >= 40, "short IPv6 header");
            let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            if length == 0 {
                return Ok(None);
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24])?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40])?)),
                40,
                bytes[6],
                40 + length,
                true,
            )
        }
        _ => return Ok(None),
    };
    if ipv6 {
        for _ in 0..8 {
            if !matches!(protocol, 0 | 43 | 60 | 51) {
                break;
            }
            ensure!(
                offset + 2 <= bytes.len() && offset + 2 <= end,
                "short IPv6 extension"
            );
            let length = if protocol == 51 {
                (usize::from(bytes[offset + 1]) + 2) * 4
            } else {
                (usize::from(bytes[offset + 1]) + 1) * 8
            };
            protocol = bytes[offset];
            offset += length;
            ensure!(
                offset <= bytes.len() && offset <= end,
                "invalid IPv6 extension"
            );
        }
        if matches!(protocol, 44 | 50 | 0 | 43 | 60 | 51) {
            return Ok(None);
        }
    }
    let mut result = Packet {
        source,
        destination,
        protocol,
        source_port: 0,
        destination_port: 0,
        sequence: 0,
        acknowledgment: 0,
        syn: false,
        ack: false,
        fin: false,
        rst: false,
        window: 0,
        scale: None,
        payload: &[],
        data_len: 0,
    };
    if !matches!(protocol, 6 | 17) {
        return Ok(Some(result));
    }
    let minimum = if protocol == 6 { 20 } else { 8 };
    ensure!(
        offset + minimum <= bytes.len() && offset + minimum <= end,
        "short transport header"
    );
    let transport = &bytes[offset..bytes.len().min(end)];
    result.source_port = u16::from_be_bytes([transport[0], transport[1]]);
    result.destination_port = u16::from_be_bytes([transport[2], transport[3]]);
    if protocol == 17 {
        let size = usize::from(u16::from_be_bytes([transport[4], transport[5]]));
        ensure!(size >= 8 && offset + size <= end, "invalid UDP length");
        result.data_len = size - 8;
        result.payload = &transport[8..transport.len().min(size)];
        return Ok(Some(result));
    }
    let size = usize::from(transport[12] >> 4) * 4;
    ensure!(
        size >= 20 && size <= transport.len() && offset + size <= end,
        "invalid TCP header length"
    );
    result.sequence = u32::from_be_bytes(transport[4..8].try_into()?);
    result.acknowledgment = u32::from_be_bytes(transport[8..12].try_into()?);
    result.fin = transport[13] & 1 != 0;
    result.syn = transport[13] & 2 != 0;
    result.rst = transport[13] & 4 != 0;
    result.ack = transport[13] & 16 != 0;
    result.window = u16::from_be_bytes([transport[14], transport[15]]);
    let mut option = 20;
    while option < size {
        match transport[option] {
            0 => break,
            1 => option += 1,
            kind => {
                ensure!(option + 2 <= size, "short TCP option");
                let length = usize::from(transport[option + 1]);
                ensure!(
                    length >= 2 && option + length <= size,
                    "invalid TCP option length"
                );
                if kind == 3 && result.syn {
                    ensure!(
                        length == 3 && result.scale.is_none() && transport[option + 2] <= 14,
                        "invalid TCP window scale"
                    );
                    result.scale = Some(transport[option + 2]);
                }
                option += length;
            }
        }
    }
    result.data_len = end - offset - size;
    result.payload = &transport[size..];
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host_ip() -> IpAddr {
        "192.0.2.20".parse().unwrap()
    }
    fn configured() -> Analyzer {
        let mut analyzer = Analyzer::new();
        analyzer.configure([host_ip()]).unwrap();
        analyzer
    }
    fn ip_packet(sent: bool, protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
        bytes[9] = protocol;
        let (source, destination) = if sent {
            ([192, 0, 2, 20], [198, 51, 100, 53])
        } else {
            ([198, 51, 100, 53], [192, 0, 2, 20])
        };
        bytes[12..16].copy_from_slice(&source);
        bytes[16..20].copy_from_slice(&destination);
        bytes.extend_from_slice(transport);
        bytes
    }
    #[allow(clippy::too_many_arguments)]
    fn tcp(
        sent: bool,
        port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        window: u16,
        scale: Option<u8>,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = if scale.is_some() { 24 } else { 20 };
        let mut bytes = vec![0; length];
        let (source, destination) = if sent {
            (12000u16, port)
        } else {
            (port, 12000u16)
        };
        bytes[..2].copy_from_slice(&source.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination.to_be_bytes());
        bytes[4..8].copy_from_slice(&sequence.to_be_bytes());
        bytes[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
        bytes[12] = ((length / 4) as u8) << 4;
        bytes[13] = flags;
        bytes[14..16].copy_from_slice(&window.to_be_bytes());
        if let Some(scale) = scale {
            bytes[20..24].copy_from_slice(&[3, 3, scale, 0]);
        }
        bytes.extend_from_slice(payload);
        ip_packet(sent, 6, &bytes)
    }
    fn question(id: u16, rcode: Option<u8>) -> Vec<u8> {
        let mut bytes = vec![0; 12];
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        bytes[5] = 1;
        if let Some(rcode) = rcode {
            bytes[2] = 0x80;
            bytes[3] = rcode;
        }
        bytes.extend_from_slice(&[1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
        bytes
    }
    fn udp(sent: bool, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 8];
        let (source, destination) = if sent {
            (12000u16, 53u16)
        } else {
            (53u16, 12000u16)
        };
        bytes[..2].copy_from_slice(&source.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination.to_be_bytes());
        bytes[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        ip_packet(sent, 17, &bytes)
    }
    fn frame(message: &[u8]) -> Vec<u8> {
        let mut bytes = (message.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(message);
        bytes
    }
    fn handshake(analyzer: &mut Analyzer, port: u16, now: Instant) {
        analyzer
            .observe(
                host_ip(),
                true,
                &tcp(true, port, 99, 0, 2, 100, Some(2), &[]),
                now,
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(false, port, 199, 100, 18, 100, Some(3), &[]),
                now,
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                true,
                &tcp(true, port, 100, 200, 16, 100, None, &[]),
                now,
            )
            .unwrap();
    }
    fn redirected_ipv4(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes[16..20].copy_from_slice(&[198, 18, 0, 53]);
        bytes[22..24].copy_from_slice(&6053u16.to_be_bytes());
        bytes
    }
    #[test]
    fn translated_udp_dns_uses_original_destination_ip_and_port_only_when_sent() {
        let now = Instant::now();
        let mut analyzer = configured();
        let logical = ("198.51.100.53".parse().unwrap(), 53);
        let request = redirected_ipv4(udp(true, &question(1, None)));
        analyzer
            .observe_translated(host_ip(), true, &request, now, Some(logical))
            .unwrap();
        analyzer
            .observe_translated(
                host_ip(),
                false,
                &udp(false, &question(1, Some(0))),
                now + Duration::from_millis(12),
                Some(("203.0.113.1".parse().unwrap(), 6053)),
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_millis(20));
        assert_eq!(result.dns.status, SourceStatus::Available);
        assert_eq!(result.dns.requests, Some(1u64.into()));
        assert_eq!(result.dns.responses, Some(1u64.into()));
        assert_eq!(result.dns.response_time_p95_ms, Some(12.0));
        let wire = packet(&request).unwrap().unwrap();
        assert_eq!(wire.destination, "198.18.0.53".parse::<IpAddr>().unwrap());
        assert_eq!(wire.destination_port, 6053);
    }
    #[test]
    fn translated_tcp_dns_restores_stream_identity_through_handshake_and_response() {
        let now = Instant::now();
        let mut analyzer = configured();
        let logical = ("198.51.100.53".parse().unwrap(), 53);
        analyzer
            .observe_translated(
                host_ip(),
                true,
                &redirected_ipv4(tcp(true, 53, 99, 0, 2, 100, Some(2), &[])),
                now,
                Some(logical),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(false, 53, 199, 100, 18, 100, Some(3), &[]),
                now,
            )
            .unwrap();
        analyzer
            .observe_translated(
                host_ip(),
                true,
                &redirected_ipv4(tcp(true, 53, 100, 200, 16, 100, None, &[])),
                now,
                Some(logical),
            )
            .unwrap();
        let request = frame(&question(1, None));
        analyzer
            .observe_translated(
                host_ip(),
                true,
                &redirected_ipv4(tcp(true, 53, 100, 200, 16, 100, None, &request)),
                now + Duration::from_millis(1),
                Some(logical),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(
                    false,
                    53,
                    200,
                    100 + request.len() as u32,
                    16,
                    100,
                    None,
                    &frame(&question(1, Some(3))),
                ),
                now + Duration::from_millis(13),
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_millis(20));
        assert_eq!(result.dns.status, SourceStatus::Available);
        assert_eq!(result.dns.requests, Some(1u64.into()));
        assert_eq!(result.dns.responses, Some(1u64.into()));
        assert_eq!(result.dns.response_time_p95_ms, Some(12.0));
        assert_eq!(result.tcp.rtt_remote.samples, 1u64.into());
        assert_eq!(result.tcp.rtt_remote.p95_ms, Some(12.0));
        assert_eq!(analyzer.hosts[&host_ip()].flows.len(), 1);
    }
    #[test]
    fn sequence_wrap_overlap_and_karn_ambiguity() {
        let now = Instant::now();
        let mut counters = Counters::default();
        let mut direction = Direction::fresh();
        assert!(!direction.data(u32::MAX - 3, 8, now, 0, &mut counters));
        assert!(direction.data(
            u32::MAX - 1,
            4,
            now + Duration::from_millis(5),
            0,
            &mut counters
        ));
        direction.ack(4, now + Duration::from_millis(20), 0, &mut counters);
        assert_eq!(counters.repeats[0], 1);
        assert_eq!(counters.rtt[0].samples, 0);
        assert!(!direction.data(4, 8, now + Duration::from_millis(25), 0, &mut counters));
        direction.ack(12, now + Duration::from_millis(40), 0, &mut counters);
        direction.ack(12, now + Duration::from_millis(50), 0, &mut counters);
        assert_eq!(counters.rtt[0].samples, 1);
        assert_eq!(counters.rtt[0].summary().p95_ms, Some(15.0));
        assert_eq!(counters.rtt[0].variation_pairs, 0);
        assert!(!direction.data(12u32.wrapping_add(1 << 31), 1, now, 0, &mut counters));
        assert!(counters.tcp_partial);
    }
    #[test]
    fn reordered_disjoint_data_is_not_a_repeat_and_one_ack_is_one_sample() {
        let now = Instant::now();
        let mut counters = Counters::default();
        let mut direction = Direction::fresh();
        direction.data(120, 10, now, 0, &mut counters);
        direction.data(100, 20, now + Duration::from_millis(2), 0, &mut counters);
        direction.ack(130, now + Duration::from_millis(20), 0, &mut counters);
        assert_eq!(counters.repeats[0], 0);
        assert_eq!(counters.rtt[0].samples, 1);
        assert_eq!(counters.rtt[0].summary().p95_ms, Some(20.0));
        assert!(!counters.tcp_partial);
        direction.data(130, 10, now + Duration::from_millis(30), 0, &mut counters);
        direction.ack(150, now + Duration::from_millis(40), 0, &mut counters);
        assert!(counters.tcp_partial);
        assert_eq!(counters.rtt[0].samples, 1);
    }
    #[test]
    fn windows_scale_only_after_matching_handshake_and_ignore_reordered_changes() {
        let now = Instant::now();
        let mut analyzer = configured();
        handshake(&mut analyzer, 80, now);
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(false, 80, 200, 100, 16, 90, None, &[]),
                now,
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(false, 80, 201, 100, 16, 0, None, &[]),
                now,
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(false, 80, 200, 100, 16, 80, None, &[]),
                now,
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(false, 80, 202, 100, 16, 0, None, &[]),
                now,
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now);
        assert_eq!(result.tcp.advertised_window_min_bytes_host, Some(400));
        assert_eq!(result.tcp.advertised_window_min_bytes_peer, Some(0));
        assert_eq!(result.tcp.zero_window_transitions_peer, Some(1u64.into()));
        assert_eq!(result.tcp.window_decreases_peer, Some(1u64.into()));
        assert_eq!(result.tcp.zero_window_observations_peer, Some(2u64.into()));
    }
    #[test]
    fn dns_tcp_segmented_framing_pipeline_and_negative_answers() {
        let now = Instant::now();
        let mut analyzer = configured();
        handshake(&mut analyzer, 53, now);
        let mut requests = frame(&question(1, None));
        requests.extend(frame(&question(2, None)));
        analyzer
            .observe(
                host_ip(),
                true,
                &tcp(true, 53, 100, 200, 16, 100, None, &requests[..1]),
                now,
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                true,
                &tcp(true, 53, 101, 200, 16, 100, None, &requests[1..]),
                now + Duration::from_millis(2),
            )
            .unwrap();
        let mut responses = frame(&question(1, Some(3)));
        responses.extend(frame(&question(2, Some(2))));
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(
                    false,
                    53,
                    200,
                    100 + requests.len() as u32,
                    16,
                    100,
                    None,
                    &responses[..13],
                ),
                now + Duration::from_millis(10),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &tcp(
                    false,
                    53,
                    213,
                    100 + requests.len() as u32,
                    16,
                    100,
                    None,
                    &responses[13..],
                ),
                now + Duration::from_millis(22),
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_millis(30));
        assert_eq!(result.dns.requests, Some(2u64.into()));
        assert_eq!(result.dns.responses, Some(2u64.into()));
        assert_eq!(result.dns.servfail_responses, Some(1u64.into()));
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert_eq!(result.evidence.dns_time.samples, 2);
        assert_eq!(result.evidence.dns_time.summary().p95_ms, Some(20.0));
        assert_eq!(result.dns.status, SourceStatus::Available);
        assert!(analyzer.hosts[&host_ip()].flows.values().all(|flow| {
            flow.streams
                .as_ref()
                .unwrap()
                .iter()
                .all(|stream| stream.bytes.is_empty())
        }));
    }
    #[test]
    fn bounded_stream_reorders_frames_and_rejects_overlap_and_oversize() {
        let now = Instant::now();
        let bytes = frame(&question(1, None));
        let mut stream = Stream {
            next: Some(100),
            ..Stream::default()
        };
        assert!(
            stream
                .feed(105, &bytes[5..], bytes.len() - 5, now)
                .unwrap()
                .is_empty()
        );
        let decoded = stream.feed(100, &bytes[..5], 5, now).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, question(1, None));
        assert!(
            stream
                .feed(100, &bytes, bytes.len(), now)
                .unwrap()
                .is_empty()
        );
        let mut stream = Stream {
            next: Some(100),
            ..Stream::default()
        };
        stream.feed(110, &[1; 10], 10, now).unwrap();
        assert!(stream.feed(115, &[2; 10], 10, now).is_err());
        assert!(stream.broken);
        let mut stream = Stream {
            next: Some(100),
            ..Stream::default()
        };
        assert!(stream.feed(100, &[0x20, 0], 2, now).is_err());
    }
    #[test]
    fn dns_deadlines_late_duplicates_and_ambiguity_have_one_or_no_outcome() {
        let now = Instant::now();
        let mut analyzer = configured();
        analyzer
            .observe(host_ip(), true, &udp(true, &question(1, None)), now)
            .unwrap();
        let before = analyzer.finish(host_ip(), now + Duration::from_secs(4));
        assert_eq!(before.dns.pending_at_close, Some(1u64.into()));
        assert_eq!(before.dns.unanswered, Some(0u64.into()));
        let deadline = analyzer.finish(host_ip(), now + Duration::from_secs(5));
        assert_eq!(deadline.dns.unanswered, Some(1u64.into()));
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &question(1, Some(0))),
                now + Duration::from_secs(6),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &question(1, Some(0))),
                now + Duration::from_secs(7),
            )
            .unwrap();
        let after = analyzer.finish(host_ip(), now + Duration::from_secs(8));
        assert_eq!(after.dns.responses, Some(0u64.into()));
        assert_eq!(after.dns.unanswered, Some(0u64.into()));
        assert_eq!(after.evidence.dns_time.samples, 0);
        analyzer
            .observe(
                host_ip(),
                true,
                &udp(true, &question(2, None)),
                now + Duration::from_secs(9),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                true,
                &udp(true, &question(2, None)),
                now + Duration::from_secs(10),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &question(2, Some(3))),
                now + Duration::from_secs(11),
            )
            .unwrap();
        let ambiguous = analyzer.finish(host_ip(), now + Duration::from_secs(15));
        assert_eq!(ambiguous.dns.responses, Some(0u64.into()));
        assert_eq!(ambiguous.dns.unanswered, Some(0u64.into()));
    }
    #[test]
    fn negative_dns_answers_are_responses_and_gap_never_becomes_timeout() {
        let now = Instant::now();
        let mut analyzer = configured();
        analyzer
            .observe(host_ip(), true, &udp(true, &question(1, None)), now)
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &question(1, Some(3))),
                now + Duration::from_millis(12),
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_millis(20));
        assert_eq!(result.dns.responses, Some(1u64.into()));
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert_eq!(result.evidence.dns_time.summary().p95_ms, Some(12.0));
        analyzer
            .observe(
                host_ip(),
                true,
                &udp(true, &question(2, None)),
                now + Duration::from_secs(1),
            )
            .unwrap();
        analyzer.capture_gap(3);
        let result = analyzer.finish(host_ip(), now + Duration::from_secs(10));
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert!(!result.evidence.dns_complete);
        assert_eq!(result.capture_dropped_packets, 3);
        let idle = analyzer.finish(host_ip(), now + Duration::from_secs(20));
        assert_eq!(idle.tcp.status, SourceStatus::NotObserved);
        assert_eq!(idle.dns.status, SourceStatus::NotObserved);
    }
    #[test]
    fn udp_truncation_is_a_response_and_mismatched_questions_have_no_timing() {
        let now = Instant::now();
        let mut analyzer = configured();
        analyzer
            .observe(host_ip(), true, &udp(true, &question(1, None)), now)
            .unwrap();
        let mut mismatch = question(1, Some(0));
        mismatch[13] = b'b';
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &mismatch),
                now + Duration::from_millis(3),
            )
            .unwrap();
        let mut truncated = question(1, Some(0));
        truncated[2] |= 2;
        truncated[7] = 1;
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &truncated),
                now + Duration::from_millis(7),
            )
            .unwrap();
        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &truncated),
                now + Duration::from_millis(8),
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_millis(10));
        assert_eq!(result.dns.responses, Some(1u64.into()));
        assert_eq!(result.evidence.dns_time.samples, 1);
        assert_eq!(result.evidence.dns_time.summary().p95_ms, Some(7.0));
        assert_eq!(result.dns.excluded_observations, Some(2u64.into()));
    }
    #[test]
    fn dns_exclusions_do_not_include_tcp_only_sequence_ambiguity() {
        let now = Instant::now();
        let mut analyzer = configured();
        handshake(&mut analyzer, 443, now);
        for (sent, packet, elapsed) in [
            (true, udp(true, &question(1, None)), 1),
            (false, udp(false, &question(1, Some(0))), 2),
            (true, tcp(true, 443, 100, 200, 16, 100, None, b"a"), 3),
            (
                true,
                tcp(
                    true,
                    443,
                    101u32.wrapping_add(1 << 31),
                    200,
                    16,
                    100,
                    None,
                    b"b",
                ),
                4,
            ),
        ] {
            analyzer
                .observe(
                    host_ip(),
                    sent,
                    &packet,
                    now + Duration::from_millis(elapsed),
                )
                .unwrap();
        }
        let result = analyzer.finish(host_ip(), now + Duration::from_millis(10));
        assert_eq!(result.analysis_exclusions, 1);
        assert_eq!(result.tcp.status, SourceStatus::Partial);
        assert_eq!(result.dns.status, SourceStatus::Available);
        assert_eq!(result.dns.excluded_observations, Some(0u64.into()));
        assert_eq!(result.dns.responses, Some(1u64.into()));
        assert!(result.evidence.dns_complete);

        analyzer
            .observe(
                host_ip(),
                false,
                &udp(false, &question(2, Some(0))),
                now + Duration::from_millis(11),
            )
            .unwrap();
        let next = analyzer.finish(host_ip(), now + Duration::from_millis(20));
        assert_eq!(next.analysis_exclusions, 1);
        assert_eq!(next.dns.excluded_observations, Some(1u64.into()));
        assert_eq!(next.dns.responses, Some(0u64.into()));
    }
    #[test]
    fn dns_exclusions_only_include_dns_timing_overflow() {
        for dns_overflow in [false, true] {
            let now = Instant::now();
            let mut analyzer = configured();
            analyzer
                .observe(host_ip(), true, &udp(true, &question(1, None)), now)
                .unwrap();
            analyzer
                .observe(
                    host_ip(),
                    false,
                    &udp(false, &question(1, Some(0))),
                    now + Duration::from_millis(1),
                )
                .unwrap();
            let counters = &mut analyzer.hosts.get_mut(&host_ip()).unwrap().counters;
            counters.rtt[0].push(f64::NAN, None);
            if dns_overflow {
                counters.dns_time.push(f64::NAN, None);
            }
            let result = analyzer.finish(host_ip(), now + Duration::from_millis(10));
            assert_eq!(result.analysis_exclusions, 1 + u64::from(dns_overflow));
            assert_eq!(
                result.dns.excluded_observations,
                Some(u64::from(dns_overflow).into())
            );
            assert_eq!(result.evidence.dns_complete, !dns_overflow);
        }
    }
    #[test]
    fn truncated_dns_and_missing_tcp_handshake_do_not_invent_latencies() {
        let now = Instant::now();
        let mut analyzer = configured();
        let mut captured = udp(true, &question(1, None));
        captured.truncate(30);
        analyzer.observe(host_ip(), true, &captured, now).unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_secs(10));
        assert_eq!(result.dns.requests, Some(0u64.into()));
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert_eq!(result.dns.status, SourceStatus::Partial);
        let mut analyzer = configured();
        let bytes = frame(&question(1, None));
        analyzer
            .observe(
                host_ip(),
                true,
                &tcp(true, 53, 100, 200, 16, 100, None, &bytes),
                now,
            )
            .unwrap();
        let result = analyzer.finish(host_ip(), now + Duration::from_secs(10));
        assert_eq!(result.dns.requests, Some(0u64.into()));
        assert_eq!(result.dns.status, SourceStatus::Partial);
        assert_eq!(result.tcp.advertised_window_min_bytes_host, None);
    }
    #[test]
    fn capacity_admission_is_fair_and_explicit() {
        let now = Instant::now();
        let mut analyzer = configured();
        for id in 0..=PER_HOST_DNS_LIMIT {
            analyzer
                .observe(host_ip(), true, &udp(true, &question(id as u16, None)), now)
                .unwrap();
        }
        assert_eq!(analyzer.dns, PER_HOST_DNS_LIMIT);
        let result = analyzer.finish(host_ip(), now);
        assert_eq!(result.tracking_evictions, 1);
        assert!(!result.evidence.dns_complete);
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert!(
            analyzer
                .configure(
                    (0..=MAX_ADDRESSES).map(|n| IpAddr::V4(Ipv4Addr::from(0xc000_0000 + n as u32)))
                )
                .is_err()
        );
        assert_eq!(analyzer.hosts.len(), 1);
    }
    #[test]
    fn high_volume_ack_timings_do_not_exhaust_distribution_capacity() {
        let now = Instant::now();
        let mut analyzer = configured();
        handshake(&mut analyzer, 80, now);
        for index in 0..10_000u32 {
            let at = now + Duration::from_micros(u64::from(index) * 500);
            analyzer
                .observe(
                    host_ip(),
                    true,
                    &tcp(true, 80, 100 + index, 200, 16, 100, None, &[1]),
                    at,
                )
                .unwrap();
            analyzer
                .observe(
                    host_ip(),
                    false,
                    &tcp(false, 80, 200, 101 + index, 16, 100, None, &[]),
                    at + Duration::from_micros(200),
                )
                .unwrap();
        }
        let result = analyzer.finish(host_ip(), now + Duration::from_secs(10));
        assert_eq!(result.tcp.status, SourceStatus::Available);
        assert_eq!(result.evidence.remote_rtt.samples, 10_000);
        assert_eq!(result.tracking_evictions, 0);
        assert!(result.evidence.tcp_complete);
    }
    #[test]
    fn borrowed_capacity_is_reclaimed_only_when_all_hosts_need_their_fair_share() {
        let now = Instant::now();
        let mut analyzer = configured();
        for index in 0..PER_HOST_FLOW_LIMIT {
            analyzer
                .observe(
                    host_ip(),
                    true,
                    &tcp(true, 1000 + index as u16, 1, 0, 2, 100, None, &[]),
                    now,
                )
                .unwrap();
            analyzer
                .observe(
                    host_ip(),
                    true,
                    &udp(true, &question(index as u16, None)),
                    now,
                )
                .unwrap();
        }
        let mut addresses = vec![host_ip()];
        addresses.extend(
            (1..MAX_ADDRESSES).map(|index| IpAddr::V4(Ipv4Addr::from(0xc612_0000 + index as u32))),
        );
        analyzer.configure(addresses.clone()).unwrap();
        assert_eq!(analyzer.host_limits(), (4, 4));
        assert_eq!(analyzer.hosts[&host_ip()].flows.len(), 32);
        assert_eq!(analyzer.hosts[&host_ip()].dns.len(), 32);
        for address in &addresses[1..] {
            let IpAddr::V4(address_v4) = address else {
                unreachable!()
            };
            for slot in 0..4u16 {
                let mut bytes = tcp(true, 80 + slot, 1, 0, 2, 100, None, &[]);
                bytes[12..16].copy_from_slice(&address_v4.octets());
                analyzer.observe(*address, true, &bytes, now).unwrap();
                let mut query = udp(true, &question(slot, None));
                query[12..16].copy_from_slice(&address_v4.octets());
                analyzer.observe(*address, true, &query, now).unwrap();
            }
            assert_eq!(analyzer.hosts[address].flows.len(), 4);
            assert_eq!(analyzer.hosts[address].dns.len(), 4);
        }
        for slot in 0..4u16 {
            analyzer
                .observe(
                    host_ip(),
                    true,
                    &udp(true, &question(slot, None)),
                    now + Duration::from_secs(16),
                )
                .unwrap();
        }
        assert_eq!(analyzer.flows, FLOW_LIMIT);
        assert_eq!(analyzer.dns, DNS_LIMIT);
        assert_eq!(analyzer.hosts[&host_ip()].flows.len(), 4);
        assert!(
            analyzer
                .finish(host_ip(), now + Duration::from_secs(16))
                .tracking_evictions
                > 0
        );
    }
    #[test]
    fn inactive_configured_hosts_do_not_reserve_unused_slots() {
        let now = Instant::now();
        let mut analyzer = configured();
        let mut addresses = vec![host_ip()];
        addresses.extend(
            (1..MAX_ADDRESSES).map(|index| IpAddr::V4(Ipv4Addr::from(0xc612_0000 + index as u32))),
        );
        analyzer.configure(addresses).unwrap();
        for index in 0..20u16 {
            analyzer
                .observe(
                    host_ip(),
                    true,
                    &tcp(true, 1000 + index, 1, 0, 2, 100, None, &[]),
                    now,
                )
                .unwrap();
            analyzer
                .observe(host_ip(), true, &udp(true, &question(index, None)), now)
                .unwrap();
        }
        assert_eq!(analyzer.hosts[&host_ip()].flows.len(), 20);
        assert_eq!(analyzer.hosts[&host_ip()].dns.len(), 20);
        assert_eq!(analyzer.finish(host_ip(), now).tracking_evictions, 0);
    }
    #[test]
    fn saturated_dns_borrowers_yield_to_a_new_host_without_fabricating_timeouts() {
        let now = Instant::now();
        let addresses: Vec<_> = (0..MAX_ADDRESSES)
            .map(|index| IpAddr::V4(Ipv4Addr::from(0xc612_0000 + index as u32)))
            .collect();
        let mut analyzer = Analyzer::new();
        analyzer.configure(addresses.clone()).unwrap();
        for address in &addresses[..DNS_LIMIT / PER_HOST_DNS_LIMIT] {
            let IpAddr::V4(address) = address else {
                unreachable!()
            };
            for slot in 0..PER_HOST_DNS_LIMIT {
                let mut bytes = udp(true, &question(slot as u16, None));
                bytes[12..16].copy_from_slice(&address.octets());
                analyzer
                    .observe(IpAddr::V4(*address), true, &bytes, now)
                    .unwrap();
            }
        }
        assert_eq!(analyzer.dns, DNS_LIMIT);
        let newcomer = addresses[DNS_LIMIT / PER_HOST_DNS_LIMIT];
        let IpAddr::V4(address) = newcomer else {
            unreachable!()
        };
        for slot in 0..4u16 {
            let mut bytes = udp(true, &question(slot, None));
            bytes[12..16].copy_from_slice(&address.octets());
            analyzer.observe(newcomer, true, &bytes, now).unwrap();
        }
        assert_eq!(analyzer.hosts[&newcomer].dns.len(), 4);
        let donor = analyzer
            .hosts
            .iter()
            .find(|(_, host)| host.counters.capacity > 0)
            .map(|(address, _)| *address)
            .unwrap();
        let result = analyzer.finish(donor, now + Duration::from_secs(6));
        assert!(result.tracking_evictions > 0);
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert!(!result.evidence.dns_complete);
    }
    #[test]
    fn finalized_responses_do_not_consume_pending_dns_quota() {
        let now = Instant::now();
        let mut analyzer = configured();
        let mut addresses = vec![host_ip()];
        addresses.extend(
            (1..MAX_ADDRESSES).map(|index| IpAddr::V4(Ipv4Addr::from(0xc612_0000 + index as u32))),
        );
        analyzer.configure(addresses).unwrap();
        for index in 0..1000u16 {
            let at = now + Duration::from_millis(u64::from(index) * 10);
            let mut request = question(index, None);
            request[13] = b'a' + (index % 26) as u8;
            let mut response = request.clone();
            response[2] = 0x80;
            analyzer
                .observe(host_ip(), true, &udp(true, &request), at)
                .unwrap();
            analyzer
                .observe(
                    host_ip(),
                    false,
                    &udp(false, &response),
                    at + Duration::from_millis(1),
                )
                .unwrap();
            assert!(analyzer.hosts[&host_ip()].dns.is_empty());
        }
        let result = analyzer.finish(host_ip(), now + Duration::from_secs(10));
        assert_eq!(result.dns.requests, Some(1000u64.into()));
        assert_eq!(result.dns.responses, Some(1000u64.into()));
        assert_eq!(result.dns.unanswered, Some(0u64.into()));
        assert_eq!(result.tracking_evictions, 0);
        assert_eq!(result.evidence.dns_time.samples, 1000);
        assert!(result.evidence.dns_complete);
        assert_eq!(analyzer.hosts[&host_ip()].tombstones.len(), 1000);
        analyzer.finish(host_ip(), now + Duration::from_secs(21));
        assert_eq!(analyzer.hosts[&host_ip()].tombstones.capacity(), 0);
    }
    #[test]
    fn analyzer_and_all_rolling_evidence_fit_the_working_memory_budget() {
        let bound = working_memory_bound();
        assert!(
            bound <= 80 * 1024 * 1024,
            "owned working-memory bound is {bound} bytes"
        );
        eprintln!("analyzer plus six-bucket allocation bound: {bound} bytes");
        assert!(std::mem::size_of::<Distribution>() <= 320);
        let mut distribution = Distribution::default();
        for index in 0..100_000 {
            distribution.push(f64::from(index), None);
        }
        assert_eq!(distribution.samples, 100_000);
        assert!(!distribution.overflowed);
    }
}
