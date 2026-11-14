//! Public, storage-safe protected-host observations and bounded passive scoring.
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;

pub const SCHEMA: &str = "netcontrol-host-experience/v1";
pub const ALGORITHM: &str = "netcontrol-passive-v1";
pub const INTERVAL_SECONDS: u32 = 10;
pub const RETENTION_SECONDS: u32 = 3600;
pub const MAX_ADDRESSES: usize = 2048;
pub const HISTOGRAM_BINS: usize = 32;
pub const MAX_EVIDENCE_REASONS: usize = 4;
pub const MAX_EVIDENCE_EPOCH_BYTES: usize = 128;
/// Left-inclusive timing bins, aligned to every scoring threshold and the DNS deadline.
pub const TIMING_BIN_LOWER_MS: [f64; HISTOGRAM_BINS] = [
    0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 15.0, 20.0, 25.0, 30.0, 35.0, 40.0, 45.0,
    50.0, 60.0, 75.0, 100.0, 125.0, 150.0, 175.0, 200.0, 250.0, 300.0, 400.0, 500.0, 1000.0,
    2500.0, 5000.0,
];

/// Exact unsigned decimal JSON strings, including values above SQLite's i64 range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Count(pub u64);
impl From<u64> for Count {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl Serialize for Count {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value: u64 = text.parse().map_err(serde::de::Error::custom)?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom(
                "count must be canonical unsigned decimal",
            ));
        }
        Ok(Self(value))
    }
}

macro_rules! enumeration {
    ($name:ident, $default:ident, $($variant:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { #[default] $default, $($variant),+ }
    };
}
enumeration!(SourceStatus, Unavailable, Available, Partial, NotObserved);
enumeration!(Activity, Unknown, Active, Idle, NotRecentlySeen);
enumeration!(AddressFamily, Ipv4, Ipv6);
enumeration!(ExperienceLevel, Unknown, Excellent, Good, Fair, Poor);
enumeration!(
    ExperienceStatus,
    Unavailable,
    Rated,
    Idle,
    InsufficientData,
    Incomplete
);
enumeration!(Confidence, None, Limited, High);
enumeration!(MetadataStatus, Unavailable, Available, Stale);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceIdentity {
    pub name: String,
    pub index: u32,
    pub kind: String,
    pub vlan_id: Option<u16>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostIdentity {
    pub ip_address: IpAddr,
    pub address_family: AddressFamily,
    pub configured_host_id: String,
    pub configured_name: String,
    pub currently_protected: bool,
    pub interface: Option<InterfaceIdentity>,
    pub metadata: Metadata,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    pub host_name: Option<String>,
    pub icon: Option<String>,
    pub classification: Option<String>,
    pub status: MetadataStatus,
    pub last_success_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Traffic {
    pub status: SourceStatus,
    pub error: Option<String>,
    pub sent_packets: Option<Count>,
    pub received_packets: Option<Count>,
    pub sent_bytes: Option<Count>,
    pub received_bytes: Option<Count>,
    pub sent_bps: Option<f64>,
    pub received_bps: Option<f64>,
    pub packet_unit: String,
    pub byte_unit: String,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            status: SourceStatus::Unavailable,
            error: None,
            sent_packets: None,
            received_packets: None,
            sent_bytes: None,
            received_bytes: None,
            sent_bps: None,
            received_bps: None,
            packet_unit: "kernel_l3_packet".into(),
            byte_unit: "ip_layer_bytes".into(),
        }
    }
}
impl Traffic {
    pub fn measured(
        sent_packets: u64,
        received_packets: u64,
        sent_bytes: u64,
        received_bytes: u64,
        duration_ms: u64,
    ) -> Self {
        if duration_ms == 0 {
            return Self::default();
        }
        Self {
            status: SourceStatus::Available,
            sent_packets: Some(sent_packets.into()),
            received_packets: Some(received_packets.into()),
            sent_bytes: Some(sent_bytes.into()),
            received_bytes: Some(received_bytes.into()),
            sent_bps: Some(sent_bytes as f64 * 8000.0 / duration_ms as f64),
            received_bps: Some(received_bytes as f64 * 8000.0 / duration_ms as f64),
            ..Self::default()
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Firewall {
    pub status: SourceStatus,
    pub error: Option<String>,
    pub dropped_sent_packets: Option<Count>,
    pub dropped_received_packets: Option<Count>,
    pub drop_coverage: String,
}
impl Default for Firewall {
    fn default() -> Self {
        Self {
            status: SourceStatus::Unavailable,
            error: None,
            dropped_sent_packets: None,
            dropped_received_packets: None,
            drop_coverage: "managed_nftables_only".into(),
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Connections {
    pub status: SourceStatus,
    pub error: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub measurement_duration_ms: Option<u64>,
    pub total: Option<Count>,
    pub tcp_established: Option<Count>,
    pub unreplied: Option<Count>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Timing {
    pub samples: Count,
    pub variation_pairs: Count,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub variation_mean_ms: Option<f64>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Tcp {
    pub status: SourceStatus,
    pub error: Option<String>,
    pub data_packets_sent: Option<Count>,
    pub data_packets_received: Option<Count>,
    pub retransmission_observations_sent: Option<Count>,
    pub retransmission_observations_received: Option<Count>,
    pub retransmission_percent_sent: Option<f64>,
    pub retransmission_percent_received: Option<f64>,
    pub window_decreases_host: Option<Count>,
    pub window_decreases_peer: Option<Count>,
    pub zero_window_observations_host: Option<Count>,
    pub zero_window_observations_peer: Option<Count>,
    pub zero_window_transitions_host: Option<Count>,
    pub zero_window_transitions_peer: Option<Count>,
    pub advertised_window_min_bytes_host: Option<u64>,
    pub advertised_window_min_bytes_peer: Option<u64>,
    pub rtt_remote: Timing,
    pub rtt_host: Timing,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Dns {
    pub status: SourceStatus,
    pub error: Option<String>,
    pub requests: Option<Count>,
    pub responses: Option<Count>,
    pub unanswered: Option<Count>,
    pub pending_at_close: Option<Count>,
    pub servfail_responses: Option<Count>,
    pub refused_responses: Option<Count>,
    pub excluded_observations: Option<Count>,
    pub response_time_p50_ms: Option<f64>,
    pub response_time_p95_ms: Option<f64>,
    pub response_time_variation_mean_ms: Option<f64>,
    pub unanswered_percent: Option<f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Coverage {
    pub complete: bool,
    pub reasons: Vec<String>,
    pub traffic: String,
    pub firewall: String,
    pub tcp: String,
    pub dns: String,
    pub connections: String,
}
impl Default for Coverage {
    fn default() -> Self {
        Self {
            complete: false,
            reasons: Vec::new(),
            traffic: "unavailable".into(),
            firewall: "unavailable".into(),
            tcp: "unavailable".into(),
            dns: "unavailable".into(),
            connections: "unavailable".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Component {
    pub code: String,
    pub score: u8,
    pub value: f64,
    pub unit: String,
    pub samples: Count,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Experience {
    pub algorithm: String,
    pub score: Option<u8>,
    pub level: ExperienceLevel,
    pub status: ExperienceStatus,
    pub confidence: Confidence,
    pub basis_seconds: u32,
    pub components: Vec<Component>,
    pub reasons: Vec<String>,
}
impl Default for Experience {
    fn default() -> Self {
        Self {
            algorithm: ALGORITHM.into(),
            score: None,
            level: ExperienceLevel::Unknown,
            status: ExperienceStatus::Unavailable,
            confidence: Confidence::None,
            basis_seconds: 0,
            components: Vec::new(),
            reasons: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    pub ip_address: IpAddr,
    pub configured_host_id: String,
    pub configured_name: String,
    pub configuration_revision: String,
    pub observation_epoch: String,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub measured_duration_ms: u64,
    pub interface: Option<InterfaceIdentity>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub activity: Activity,
    pub traffic: Traffic,
    pub firewall: Firewall,
    pub connections: Connections,
    pub tcp: Tcp,
    pub dns: Dns,
    pub experience: Experience,
    pub coverage: Coverage,
}
impl Sample {
    pub fn new(
        ip_address: IpAddr,
        configured_host_id: String,
        configuration_revision: String,
        observation_epoch: String,
        start_at: DateTime<Utc>,
        end_at: DateTime<Utc>,
    ) -> Self {
        Self {
            ip_address,
            configured_name: configured_host_id.clone(),
            configured_host_id,
            configuration_revision,
            observation_epoch,
            start_at,
            end_at,
            measured_duration_ms: 0,
            interface: None,
            last_seen_at: None,
            activity: Activity::Unknown,
            traffic: Traffic::default(),
            firewall: Firewall::default(),
            connections: Connections::default(),
            tcp: Tcp::default(),
            dns: Dns::default(),
            experience: Experience::default(),
            coverage: Coverage::default(),
        }
    }
}

/// Transient evidence only: do not persist flow identities, DNS fingerprints or distributions.
///
/// p50/p95 are histogram estimates: the lower edge of the bin containing the
/// nearest-rank observation, clipped to the exact observed minimum. The final
/// bin is [5000 ms, infinity). Exact minima,
/// maxima, observation counts and flow-local variation sums are retained.
/// Volume does not exhaust this fixed-size representation.
#[derive(Clone, Debug, Default)]
pub struct Distribution {
    pub counts: [u64; HISTOGRAM_BINS],
    pub samples: u64,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub variation_sum_ms: f64,
    pub variation_pairs: u64,
    /// Invalid input or arithmetic overflow, never ordinary observation volume.
    pub overflowed: bool,
}
impl Distribution {
    pub fn push(&mut self, value_ms: f64, previous_ms: Option<f64>) {
        if !value_ms.is_finite()
            || value_ms < 0.0
            || previous_ms.is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            self.overflowed = true;
            return;
        }
        let bin = TIMING_BIN_LOWER_MS.partition_point(|edge| *edge <= value_ms) - 1;
        let (Some(samples), Some(count)) =
            (self.samples.checked_add(1), self.counts[bin].checked_add(1))
        else {
            self.overflowed = true;
            return;
        };
        self.samples = samples;
        self.counts[bin] = count;
        self.min_ms = Some(self.min_ms.map_or(value_ms, |value| value.min(value_ms)));
        self.max_ms = Some(self.max_ms.map_or(value_ms, |value| value.max(value_ms)));
        if let Some(previous) = previous_ms {
            let sum = self.variation_sum_ms + (value_ms - previous).abs();
            if !sum.is_finite() {
                self.overflowed = true;
                return;
            }
            self.variation_sum_ms = sum;
            if let Some(pairs) = self.variation_pairs.checked_add(1) {
                self.variation_pairs = pairs;
            } else {
                self.overflowed = true;
            }
        }
    }
    /// Pool by actual sample and contributing pair counts, without creating
    /// variation pairs across flows, buckets or discontinuities.
    pub fn merge(&mut self, other: &Self) {
        if !self.valid() || !other.valid() {
            self.overflowed = true;
            return;
        }
        let (Some(samples), Some(pairs)) = (
            self.samples.checked_add(other.samples),
            self.variation_pairs.checked_add(other.variation_pairs),
        ) else {
            self.overflowed = true;
            return;
        };
        for (target, count) in self.counts.iter_mut().zip(other.counts) {
            if let Some(sum) = target.checked_add(count) {
                *target = sum;
            } else {
                self.overflowed = true;
                return;
            }
        }
        self.samples = samples;
        self.variation_pairs = pairs;
        self.variation_sum_ms += other.variation_sum_ms;
        self.overflowed |= !self.variation_sum_ms.is_finite();
        if let Some(minimum) = other.min_ms {
            self.min_ms = Some(self.min_ms.map_or(minimum, |value| value.min(minimum)));
        }
        if let Some(maximum) = other.max_ms {
            self.max_ms = Some(self.max_ms.map_or(maximum, |value| value.max(maximum)));
        }
    }
    pub fn quantile(&self, percent: u8) -> Option<f64> {
        if !self.valid() || self.samples == 0 || !(1..=100).contains(&percent) {
            return None;
        }
        let rank = (u128::from(self.samples) * u128::from(percent)).div_ceil(100);
        let mut cumulative = 0u128;
        for (bin, count) in self.counts.iter().enumerate() {
            cumulative += u128::from(*count);
            if cumulative >= rank {
                return Some(TIMING_BIN_LOWER_MS[bin].max(self.min_ms.unwrap_or(0.0)));
            }
        }
        None
    }
    pub fn summary(&self) -> Timing {
        if !self.valid() {
            return Timing::default();
        }
        Timing {
            samples: self.samples.into(),
            variation_pairs: self.variation_pairs.into(),
            p50_ms: self.quantile(50),
            p95_ms: self.quantile(95),
            min_ms: self.min_ms,
            max_ms: self.max_ms,
            variation_mean_ms: (self.variation_pairs > 0)
                .then(|| self.variation_sum_ms / self.variation_pairs as f64),
        }
    }
    fn valid(&self) -> bool {
        !self.overflowed
            && self
                .counts
                .iter()
                .map(|count| u128::from(*count))
                .sum::<u128>()
                == u128::from(self.samples)
            && self.variation_sum_ms.is_finite()
            && self.variation_sum_ms >= 0.0
            && self.variation_pairs <= self.samples
            && if self.samples == 0 {
                self.min_ms.is_none() && self.max_ms.is_none()
            } else {
                matches!((self.min_ms, self.max_ms), (Some(min), Some(max))
                    if min.is_finite() && max.is_finite() && min >= 0.0 && max >= min)
            }
    }
}
#[derive(Clone, Debug, Default)]
pub struct TransportEvidence {
    pub tcp_complete: bool,
    pub dns_complete: bool,
    pub data_sent: u64,
    pub data_received: u64,
    pub repeats_sent: u64,
    pub repeats_received: u64,
    pub dns_responses: u64,
    pub dns_unanswered: u64,
    pub remote_rtt: Distribution,
    pub host_rtt: Distribution,
    pub dns_time: Distribution,
    pub reasons: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct EvidenceBucket {
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub observation_epoch: String,
    pub complete: bool,
    pub traffic_available: bool,
    pub active: bool,
    pub transport: TransportEvidence,
    pub reasons: Vec<String>,
}
impl EvidenceBucket {
    pub fn from_sample(sample: &Sample, mut transport: TransportEvidence) -> Self {
        // Rolling evidence must not multiply arbitrary source-error strings by 2048 * 6.
        transport.reasons = transport
            .reasons
            .iter()
            .filter(|reason| reason.len() <= 32)
            .take(MAX_EVIDENCE_REASONS)
            .cloned()
            .collect();
        let valid_epoch = !sample.observation_epoch.is_empty()
            && sample.observation_epoch.len() <= MAX_EVIDENCE_EPOCH_BYTES;
        let mut reasons: Vec<_> = sample
            .coverage
            .reasons
            .iter()
            .filter(|reason| reason.len() <= 32)
            .take(MAX_EVIDENCE_REASONS)
            .cloned()
            .collect();
        if !valid_epoch {
            if reasons.len() == MAX_EVIDENCE_REASONS {
                reasons.pop();
            }
            add_reason(&mut reasons, "invalid_observation_epoch");
        }
        Self {
            start_at: sample.start_at,
            end_at: sample.end_at,
            observation_epoch: if valid_epoch {
                sample.observation_epoch.clone()
            } else {
                String::new()
            },
            complete: sample.coverage.complete && sample.measured_duration_ms > 0 && valid_epoch,
            traffic_available: sample.traffic.status == SourceStatus::Available,
            active: sample.activity == Activity::Active,
            transport,
            reasons,
        }
    }
}
/// Maximum retained bytes for six evidence slots per configured address,
/// including bounded epoch/reason allocations and allocator rounding allowance.
pub fn rolling_evidence_memory_bound() -> usize {
    const ALLOCATION_OVERHEAD: usize = 32;
    let reasons =
        2 * MAX_EVIDENCE_REASONS * (std::mem::size_of::<String>() + 32 + ALLOCATION_OVERHEAD);
    MAX_ADDRESSES
        * 6
        * (std::mem::size_of::<EvidenceBucket>()
            + reasons
            + MAX_EVIDENCE_EPOCH_BYTES
            + 3 * ALLOCATION_OVERHEAD)
}

/// `buckets` is chronological, ending in the current bucket; only the last six are examined.
pub fn score(buckets: &[EvidenceBucket]) -> Experience {
    let mut result = Experience::default();
    let Some(current) = buckets.last() else {
        return result;
    };
    result.reasons = current.reasons.clone();
    for reason in &current.transport.reasons {
        add_reason(&mut result.reasons, reason);
    }
    if !current.traffic_available {
        return result;
    }
    if !current.complete {
        result.status = ExperienceStatus::Incomplete;
        add_reason(&mut result.reasons, "capture_gap");
        return result;
    }
    if !current.active {
        result.status = ExperienceStatus::Idle;
        add_reason(&mut result.reasons, "no_recent_traffic");
        return result;
    }
    let mut window = Vec::with_capacity(6);
    let mut next_start = current.end_at;
    for bucket in buckets.iter().rev().take(6) {
        if !bucket.complete
            || bucket.observation_epoch != current.observation_epoch
            || bucket.end_at != next_start
            || (bucket.end_at - bucket.start_at).num_milliseconds() != 10_000
        {
            break;
        }
        next_start = bucket.start_at;
        window.push(bucket);
    }
    result.basis_seconds = window.len() as u32 * 10;
    if window.is_empty() {
        result.status = ExperienceStatus::Incomplete;
        add_reason(&mut result.reasons, "capture_gap");
        return result;
    }
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut repeats_sent = 0u64;
    let mut repeats_received = 0u64;
    let mut responses = 0u64;
    let mut unanswered = 0u64;
    let mut remote = Distribution::default();
    let mut host = Distribution::default();
    let mut dns = Distribution::default();
    let mut tcp_complete = true;
    let mut dns_complete = true;
    let mut counts_complete = true;
    for bucket in &window {
        let t = &bucket.transport;
        if [&t.remote_rtt, &t.host_rtt, &t.dns_time]
            .iter()
            .any(|distribution| !distribution.valid())
        {
            add_reason(&mut result.reasons, "invalid_timing_evidence");
        }
        tcp_complete &= t.tcp_complete
            && t.remote_rtt.valid()
            && t.host_rtt.valid()
            && t.repeats_sent <= t.data_sent
            && t.repeats_received <= t.data_received;
        dns_complete &= t.dns_complete && t.dns_time.valid();
        for (total, value) in [
            (&mut sent, t.data_sent),
            (&mut received, t.data_received),
            (&mut repeats_sent, t.repeats_sent),
            (&mut repeats_received, t.repeats_received),
            (&mut responses, t.dns_responses),
            (&mut unanswered, t.dns_unanswered),
        ] {
            if let Some(sum) = total.checked_add(value) {
                *total = sum;
            } else {
                counts_complete = false;
            }
        }
        remote.merge(&t.remote_rtt);
        host.merge(&t.host_rtt);
        dns.merge(&t.dns_time);
    }
    tcp_complete &= remote.valid() && host.valid();
    dns_complete &= dns.valid();
    let tcp_participates = sent > 0
        || received > 0
        || remote.samples > 0
        || host.samples > 0
        || remote.overflowed
        || host.overflowed;
    let dns_participates = responses > 0 || unanswered > 0 || dns.samples > 0 || dns.overflowed;
    if !counts_complete || responses.checked_add(unanswered).is_none() {
        result.status = ExperienceStatus::Incomplete;
        add_reason(&mut result.reasons, "counter_overflow");
        return result;
    }
    if (!tcp_complete && tcp_participates) || (!dns_complete && dns_participates) {
        result.status = ExperienceStatus::Incomplete;
        for bucket in &window {
            for reason in &bucket.transport.reasons {
                add_reason(&mut result.reasons, reason);
            }
        }
        add_reason(&mut result.reasons, "capture_gap");
        return result;
    }
    let mut classes = [false; 3];
    for (code, numerator, denominator) in [
        ("tcp_repeats_sent", repeats_sent, sent),
        ("tcp_repeats_received", repeats_received, received),
    ] {
        if denominator >= 100 && tcp_complete {
            component(
                &mut result,
                code,
                numerator as f64 * 100.0 / denominator as f64,
                [0.5, 2.0, 5.0],
                "percent",
                denominator,
            );
            classes[0] = true;
        }
    }
    for (code, distribution, minimum, bands, class, complete) in [
        (
            "remote_ack_delay",
            &remote,
            20,
            [50.0, 150.0, 300.0],
            1,
            tcp_complete,
        ),
        (
            "host_ack_delay",
            &host,
            20,
            [10.0, 40.0, 100.0],
            1,
            tcp_complete,
        ),
        (
            "dns_response_delay",
            &dns,
            5,
            [30.0, 100.0, 300.0],
            2,
            dns_complete,
        ),
    ] {
        if complete && distribution.samples >= minimum {
            component(
                &mut result,
                code,
                distribution.quantile(95).unwrap(),
                bands,
                "ms",
                distribution.samples,
            );
            classes[class] = true;
        }
    }
    let finalized = responses.saturating_add(unanswered);
    if dns_complete && finalized >= 5 {
        component(
            &mut result,
            "dns_unanswered",
            unanswered as f64 * 100.0 / finalized as f64,
            [1.0, 5.0, 20.0],
            "percent",
            finalized,
        );
        classes[2] = true;
    }
    if let Some(value) = result.components.iter().map(|c| c.score).min() {
        result.score = Some(value);
        result.status = ExperienceStatus::Rated;
        result.level = match value {
            90..=100 => ExperienceLevel::Excellent,
            75..=89 => ExperienceLevel::Good,
            50..=74 => ExperienceLevel::Fair,
            _ => ExperienceLevel::Poor,
        };
        result.confidence = if window.len() == 6 && classes.iter().filter(|v| **v).count() >= 2 {
            Confidence::High
        } else {
            Confidence::Limited
        };
    } else {
        result.status = ExperienceStatus::InsufficientData;
        add_reason(&mut result.reasons, "insufficient_samples");
    }
    result
}
fn component(
    result: &mut Experience,
    code: &str,
    value: f64,
    bands: [f64; 3],
    unit: &str,
    samples: u64,
) {
    let score = if value < bands[0] {
        100
    } else if value < bands[1] {
        85
    } else if value < bands[2] {
        60
    } else {
        25
    };
    result.components.push(Component {
        code: code.into(),
        score,
        value,
        unit: unit.into(),
        samples: samples.into(),
    });
    if score < 100 {
        add_reason(&mut result.reasons, code);
    }
}
pub fn add_reason(reasons: &mut Vec<String>, reason: &str) {
    if reasons.len() < 32 && !reasons.iter().any(|r| r == reason) {
        reasons.push(reason.into());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestQuery {
    pub address: Option<IpAddr>,
    pub interface: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LatestParameters {
    address: Option<String>,
    interface: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}
pub fn canonical_address(value: &str) -> Result<IpAddr> {
    let address: IpAddr = value.parse()?;
    ensure!(
        address.to_string() == value,
        "address must be a canonical IP literal"
    );
    Ok(address)
}
impl LatestQuery {
    pub fn parse(query: &str) -> Result<Self> {
        ensure!(query.len() <= 4096, "experience query exceeds 4096 bytes");
        let parameters: LatestParameters = serde_urlencoded::from_str(query)?;
        let address = parameters
            .address
            .as_deref()
            .map(canonical_address)
            .transpose()?;
        let limit = if let Some(value) = parameters.limit {
            let limit: usize = value.parse()?;
            ensure!(
                (1..=256).contains(&limit) && limit.to_string() == value,
                "limit must be canonical integer 1..256"
            );
            limit
        } else {
            100
        };
        if let Some(interface) = &parameters.interface {
            ensure!(
                !interface.is_empty()
                    && interface.len() <= 15
                    && interface
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
                "invalid technical interface name"
            );
        }
        if let Some(cursor) = &parameters.cursor {
            ensure!(
                !cursor.is_empty()
                    && cursor.len() <= 1024
                    && cursor.bytes().all(|b| b.is_ascii_graphic()),
                "invalid cursor"
            );
        }
        // Collection/filter binding is checked by the store which issued the opaque token.
        Ok(Self {
            address,
            interface: parameters.interface,
            limit,
            cursor: parameters.cursor,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryQuery {
    pub address: IpAddr,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryParameters {
    address: String,
}
impl HistoryQuery {
    pub fn parse(query: &str) -> Result<Self> {
        ensure!(query.len() <= 4096, "experience query exceeds 4096 bytes");
        let parameters: HistoryParameters = serde_urlencoded::from_str(query)?;
        Ok(Self {
            address: canonical_address(&parameters.address)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bucket(second: i64) -> EvidenceBucket {
        EvidenceBucket {
            start_at: DateTime::from_timestamp(second, 0).unwrap(),
            end_at: DateTime::from_timestamp(second + 10, 0).unwrap(),
            observation_epoch: "epoch".into(),
            complete: true,
            traffic_available: true,
            active: true,
            transport: TransportEvidence {
                tcp_complete: true,
                dns_complete: true,
                ..TransportEvidence::default()
            },
            reasons: Vec::new(),
        }
    }
    #[test]
    fn counts_and_queries_are_exact_and_strict() {
        let value = Count(u64::MAX);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<Count>(&json).unwrap(), value);
        for invalid in ["0", "\"01\"", "\"-1\""] {
            assert!(serde_json::from_str::<Count>(invalid).is_err());
        }
        for query in [
            "limit=01",
            "limit=257",
            "address=192.0.2.1&address=192.0.2.2",
            "extra=x",
            "address=2001:0db8::1",
        ] {
            assert!(LatestQuery::parse(query).is_err(), "{query}");
        }
        assert!(HistoryQuery::parse("address=192.0.2.1&limit=1").is_err());
    }
    #[test]
    fn idle_gap_and_absence_are_not_excellent() {
        let mut b = bucket(0);
        assert_eq!(
            score(&[b.clone()]).status,
            ExperienceStatus::InsufficientData
        );
        b.transport.data_sent = 100;
        assert_eq!(score(&[b.clone()]).score, Some(100));
        b.active = false;
        assert_eq!(score(&[b.clone()]).status, ExperienceStatus::Idle);
        b.complete = false;
        assert_eq!(score(&[b.clone()]).status, ExperienceStatus::Incomplete);
        b.traffic_available = false;
        assert_eq!(score(&[b]).status, ExperienceStatus::Unavailable);
    }
    #[test]
    fn thresholds_are_pooled_not_averaged_percentiles() {
        let mut a = bucket(0);
        let mut b = bucket(10);
        for _ in 0..20 {
            a.transport.remote_rtt.push(10.0, None);
        }
        b.transport.remote_rtt.push(300.0, None);
        let result = score(&[a, b]);
        assert_eq!(result.components[0].value, 10.0);
        for (repeats, expected) in [(0, 100), (1, 85), (4, 60), (10, 25)] {
            let mut b = bucket(0);
            b.transport.data_sent = 200;
            b.transport.repeats_sent = repeats;
            assert_eq!(score(&[b]).score, Some(expected));
        }
        let mut b = bucket(0);
        b.transport.dns_responses = 4;
        b.transport.dns_unanswered = 1;
        assert_eq!(score(&[b]).score, Some(25));
    }
    #[test]
    fn epochs_break_windows_and_partial_evidence_cannot_rate() {
        let mut a = bucket(0);
        a.transport.data_sent = 100;
        let mut b = bucket(10);
        b.observation_epoch = "replacement".into();
        assert_eq!(score(&[a.clone(), b.clone()]).score, None);
        b.observation_epoch = a.observation_epoch.clone();
        b.transport.tcp_complete = false;
        b.transport.data_sent = 1;
        assert_eq!(score(&[a, b]).status, ExperienceStatus::Incomplete);
    }
    #[test]
    fn timing_thresholds_and_six_bucket_confidence() {
        for (which, thresholds, samples) in [
            (0, [50.0, 150.0, 300.0], 20),
            (1, [10.0, 40.0, 100.0], 20),
            (2, [30.0, 100.0, 300.0], 5),
        ] {
            for (value, expected) in thresholds.into_iter().zip([85, 60, 25]) {
                let mut b = bucket(0);
                let distribution = match which {
                    0 => &mut b.transport.remote_rtt,
                    1 => &mut b.transport.host_rtt,
                    _ => &mut b.transport.dns_time,
                };
                for _ in 0..samples {
                    distribution.push(value, None);
                }
                assert_eq!(score(&[b]).score, Some(expected));
            }
        }
        let mut buckets: Vec<_> = (0..6).map(|index| bucket(index * 10)).collect();
        buckets[5].transport.data_sent = 100;
        for _ in 0..20 {
            buckets[5].transport.remote_rtt.push(1.0, None);
        }
        assert_eq!(score(&buckets).confidence, Confidence::High);
        buckets[2].complete = false;
        let result = score(&buckets);
        assert_eq!(result.basis_seconds, 30);
        assert_eq!(result.confidence, Confidence::Limited);
    }
    #[test]
    fn high_volume_timing_stays_rated_and_invalid_evidence_does_not() {
        let mut b = bucket(0);
        for _ in 0..100_000 {
            b.transport.remote_rtt.push(1.5, Some(1.0));
        }
        assert!(!b.transport.remote_rtt.overflowed);
        assert_eq!(b.transport.remote_rtt.samples, 100_000);
        assert_eq!(
            b.transport.remote_rtt.summary().variation_mean_ms,
            Some(0.5)
        );
        assert_eq!(score(&[b.clone()]).score, Some(100));
        b.transport.remote_rtt.push(f64::NAN, None);
        assert_eq!(score(&[b]).status, ExperienceStatus::Incomplete);
    }
    #[test]
    fn unequal_histograms_pool_all_counts_and_do_not_create_variation_pairs() {
        let mut a = bucket(0);
        let mut b = bucket(10);
        for _ in 0..10_000 {
            a.transport.remote_rtt.push(15.0, Some(10.0));
        }
        for _ in 0..10 {
            b.transport.remote_rtt.push(300.0, None);
        }
        let result = score(&[a.clone(), b.clone()]);
        assert_eq!(result.components[0].value, 15.0);
        assert_eq!(result.components[0].samples, Count(10_010));
        let mut pooled = a.transport.remote_rtt;
        pooled.merge(&b.transport.remote_rtt);
        assert_eq!(pooled.summary().variation_pairs, Count(10_000));
        assert_eq!(pooled.summary().variation_mean_ms, Some(5.0));
        assert_eq!(pooled.summary().max_ms, Some(300.0));
        assert_eq!(pooled.quantile(100), Some(300.0));
    }
    #[test]
    fn full_coverage_with_real_snapshot_skew_is_rated() {
        let mut sample = Sample::new(
            "192.0.2.1".parse().unwrap(),
            "host".into(),
            "2026.11.14.1".into(),
            "epoch".into(),
            DateTime::from_timestamp(0, 0).unwrap(),
            DateTime::from_timestamp(10, 0).unwrap(),
        );
        sample.measured_duration_ms = 10_002;
        sample.coverage.complete = true;
        sample.activity = Activity::Active;
        sample.traffic = Traffic::measured(100, 0, 10_000, 0, 10_002);
        let evidence = TransportEvidence {
            tcp_complete: true,
            dns_complete: true,
            data_sent: 100,
            ..TransportEvidence::default()
        };
        assert_eq!(
            score(&[EvidenceBucket::from_sample(&sample, evidence.clone())]).score,
            Some(100)
        );
        sample.measured_duration_ms = 0;
        assert_eq!(
            score(&[EvidenceBucket::from_sample(&sample, evidence)]).status,
            ExperienceStatus::Incomplete
        );
    }
    #[test]
    fn retained_configured_name_is_required_and_round_trips() {
        let mut sample = Sample::new(
            "192.0.2.1".parse().unwrap(),
            "camera".into(),
            "2026.11.14.1".into(),
            "epoch".into(),
            DateTime::from_timestamp(0, 0).unwrap(),
            DateTime::from_timestamp(10, 0).unwrap(),
        );
        sample.configured_name = "Front door camera".into();
        sample.connections.status = SourceStatus::Available;
        sample.connections.total = Some(1u64.into());
        sample.connections.tcp_established = Some(1u64.into());
        sample.connections.unreplied = Some(0u64.into());
        sample.connections.observed_at = Some(DateTime::from_timestamp(9, 0).unwrap());
        sample.connections.measurement_duration_ms = Some(25);
        let mut encoded = serde_json::to_value(&sample).unwrap();
        let decoded = serde_json::from_value::<Sample>(encoded.clone()).unwrap();
        assert_eq!(decoded.configured_name, "Front door camera");
        assert_eq!(
            decoded.connections.observed_at,
            sample.connections.observed_at
        );
        assert_eq!(decoded.connections.measurement_duration_ms, Some(25));
        encoded.as_object_mut().unwrap().remove("configured_name");
        assert!(serde_json::from_value::<Sample>(encoded).is_err());
    }
}
