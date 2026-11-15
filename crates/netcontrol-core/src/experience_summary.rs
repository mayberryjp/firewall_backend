//! One-hour summaries of retained samples, without reconstructing distributions or scores.
use crate::experience::{
    self, Connections, Count, Experience, ExperienceLevel, ExperienceStatus, InterfaceIdentity,
    Sample, SourceStatus, Timing,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

const HOUR_MS: i64 = 3_600_000;
const SLOT_MS: i64 = 10_000;
const SLOTS: u32 = 360;
const REASON_LIMIT: usize = 32;
const PERCENTILE_REASON: &str = "per_bucket_distributions_not_retained";

fn connection_values(snapshot: &Connections) -> Result<[Count; 3]> {
    let values = [snapshot.total, snapshot.tcp_established, snapshot.unreplied];
    let [Some(total), Some(established), Some(unreplied)] = values else {
        anyhow::bail!("available connection snapshot lacks counts");
    };
    ensure!(
        established.0 <= total.0 && unreplied.0 <= total.0,
        "connection subtype count exceeds total"
    );
    ensure!(
        snapshot.observed_at.is_some(),
        "available connection snapshot lacks timestamp"
    );
    Ok([total, established, unreplied])
}

pub fn connection_snapshot(sample: Option<&Sample>, now_ms: i64) -> Result<Value> {
    let Some(sample) = sample else {
        let mut result = serde_json::to_value(Connections {
            error: Some("no matching connection snapshot in pinned latest collection".into()),
            ..Connections::default()
        })?;
        result["age_ms"] = Value::Null;
        return Ok(result);
    };
    let snapshot = &sample.connections;
    if snapshot.status == SourceStatus::Available {
        connection_values(snapshot)?;
    }
    let age = snapshot
        .observed_at
        .map(|at| {
            now_ms
                .checked_sub(at.timestamp_millis())
                .filter(|age| *age >= 0)
                .ok_or_else(|| anyhow::anyhow!("connection snapshot timestamp is in the future"))
        })
        .transpose()?;
    let mut result = serde_json::to_value(snapshot)?;
    result["age_ms"] = json!(age);
    if snapshot.status == SourceStatus::Available && age.is_some_and(|age| age > 30_000) {
        result["status"] = json!("stale");
    }
    Ok(result)
}

#[derive(Default)]
struct ConnectionAverage {
    sums: [u128; 3],
    observed_slots: u32,
    first_observed_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
}
impl ConnectionAverage {
    fn push(&mut self, sample: &Sample, values: Option<[Count; 3]>) {
        if let Some(values) = values {
            for (sum, value) in self.sums.iter_mut().zip(values) {
                *sum += u128::from(value.0);
            }
            self.observed_slots += 1;
            if let Some(at) = sample.connections.observed_at {
                self.first_observed_at.get_or_insert(at);
                self.last_observed_at = Some(at);
            }
        }
    }
    fn json(&self) -> Value {
        let mean = |sum: u128| {
            (self.observed_slots > 0).then(|| sum as f64 / f64::from(self.observed_slots))
        };
        json!({
            "total": mean(self.sums[0]),
            "tcp_established": mean(self.sums[1]),
            "unreplied": mean(self.sums[2]),
            "observed_slots": self.observed_slots,
            "coverage_seconds": self.observed_slots * 10,
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
        })
    }
}

#[derive(Default)]
struct Total {
    value: u128,
    observed_slots: u32,
    complete_slots: u32,
    measured_duration_ms: u64,
    last_observed_at: Option<DateTime<Utc>>,
}
impl Total {
    fn push(&mut self, value: Option<Count>, sample: &Sample, status: SourceStatus) {
        if let Some(value) = value {
            self.value += u128::from(value.0);
            self.observed_slots += 1;
            self.complete_slots += u32::from(status == SourceStatus::Available);
            self.measured_duration_ms += sample.measured_duration_ms;
            self.last_observed_at = Some(sample.end_at);
        }
    }
    fn json(&self) -> Value {
        json!({
            "total": (self.observed_slots > 0).then(|| self.value.to_string()),
            "observed_slots": self.observed_slots,
            "complete_slots": self.complete_slots,
            "measured_duration_ms": self.measured_duration_ms,
            "last_observed_at": self.last_observed_at,
        })
    }
    fn rate(&self) -> Option<f64> {
        (self.measured_duration_ms > 0)
            .then(|| self.value as f64 * 8000.0 / self.measured_duration_ms as f64)
    }
}

#[derive(Default)]
struct Source {
    available: u32,
    partial: u32,
    not_observed: u32,
    unavailable: u32,
    observed_duration_ms: u64,
    complete_duration_ms: u64,
    last_observed_at: Option<DateTime<Utc>>,
}
impl Source {
    fn push(&mut self, status: SourceStatus, sample: &Sample) {
        match status {
            SourceStatus::Available => self.available += 1,
            SourceStatus::Partial => self.partial += 1,
            SourceStatus::NotObserved => self.not_observed += 1,
            SourceStatus::Unavailable => self.unavailable += 1,
        }
        if matches!(status, SourceStatus::Available | SourceStatus::Partial) {
            self.observed_duration_ms += sample.measured_duration_ms;
            self.last_observed_at = Some(sample.end_at);
        }
        if status == SourceStatus::Available {
            self.complete_duration_ms += sample.measured_duration_ms;
        }
    }
    fn json(&self) -> Value {
        json!({
            "available_slots": self.available,
            "partial_slots": self.partial,
            "not_observed_slots": self.not_observed,
            "unavailable_slots": self.unavailable,
            "observed_slots": self.available + self.partial,
            "complete_slots": self.available,
            "observed_seconds": (self.available + self.partial) * 10,
            "complete_seconds": self.available * 10,
            "observed_duration_ms": self.observed_duration_ms,
            "complete_duration_ms": self.complete_duration_ms,
            "last_observed_at": self.last_observed_at,
        })
    }
}

#[derive(Default)]
struct Ratio {
    numerator: u128,
    denominator: u128,
    observed_slots: u32,
    complete_slots: u32,
    last_observed_at: Option<DateTime<Utc>>,
}
impl Ratio {
    fn push(&mut self, numerator: Count, denominator: u128, sample: &Sample, status: SourceStatus) {
        self.numerator += u128::from(numerator.0);
        self.denominator += denominator;
        self.observed_slots += 1;
        self.complete_slots += u32::from(status == SourceStatus::Available);
        self.last_observed_at = Some(sample.end_at);
    }
    fn json(&self) -> Value {
        json!({
            "numerator": (self.observed_slots > 0).then(|| self.numerator.to_string()),
            "denominator": (self.observed_slots > 0).then(|| self.denominator.to_string()),
            "percent": (self.denominator > 0)
                .then(|| self.numerator as f64 * 100.0 / self.denominator as f64),
            "observed_slots": self.observed_slots,
            "complete_slots": self.complete_slots,
            "last_observed_at": self.last_observed_at,
        })
    }
}

#[derive(Default)]
struct TimingTotal {
    observed_slots: u32,
    complete_slots: u32,
    samples: u128,
    variation_pairs: u128,
    variation_mean_ms: Option<f64>,
    min_ms: Option<f64>,
    max_ms: Option<f64>,
    last_observed_at: Option<DateTime<Utc>>,
}
impl TimingTotal {
    fn push(&mut self, timing: &Timing, sample: &Sample) {
        if !matches!(
            sample.tcp.status,
            SourceStatus::Available | SourceStatus::Partial
        ) {
            return;
        }
        self.observed_slots += 1;
        self.complete_slots += u32::from(sample.tcp.status == SourceStatus::Available);
        self.samples += u128::from(timing.samples.0);
        if let Some(value) = timing.variation_mean_ms {
            let pairs = u128::from(timing.variation_pairs.0);
            self.variation_pairs += pairs;
            let weight = pairs as f64 / self.variation_pairs as f64;
            self.variation_mean_ms = Some(
                self.variation_mean_ms
                    .map_or(value, |mean| mean * (1.0 - weight) + value * weight),
            );
        }
        if let Some(value) = timing.min_ms {
            self.min_ms = Some(self.min_ms.map_or(value, |old| old.min(value)));
        }
        if let Some(value) = timing.max_ms {
            self.max_ms = Some(self.max_ms.map_or(value, |old| old.max(value)));
        }
        if timing.samples.0 > 0 {
            self.last_observed_at = Some(sample.end_at);
        }
    }
    fn json(&self) -> Value {
        json!({
            "samples": (self.observed_slots > 0).then(|| self.samples.to_string()),
            "variation_pairs": (self.observed_slots > 0).then(|| self.variation_pairs.to_string()),
            "variation_mean_ms": self.variation_mean_ms,
            "min_ms": self.min_ms, "max_ms": self.max_ms,
            "p50_ms": null, "p95_ms": null,
            "percentile_unavailable_reason": PERCENTILE_REASON,
            "observed_slots": self.observed_slots, "complete_slots": self.complete_slots,
            "last_observed_at": self.last_observed_at,
        })
    }
}

#[derive(Default)]
struct StatusDuration {
    slots: u32,
}
impl StatusDuration {
    fn json(&self) -> Value {
        json!({"slots": self.slots, "seconds": self.slots * 10})
    }
}

/// Consumes chronological ten-second rows for one IP over a trailing one-hour interval.
pub struct Accumulator {
    start_ms: i64,
    end_ms: i64,
    address: Option<IpAddr>,
    observed_slots: u32,
    complete_slots: u32,
    first_sample_at: Option<DateTime<Utc>>,
    last_sample_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    previous_end_ms: Option<i64>,
    initial_identity: Option<(String, Option<InterfaceIdentity>, String, String)>,
    host_id_changed: bool,
    interface_changed: bool,
    configured_identity_changed: bool,
    previous_epoch: Option<String>,
    epochs: BTreeSet<String>,
    epoch_discontinuities: u32,
    sources: [Source; 5],
    traffic: [Total; 4],
    firewall: [Total; 2],
    tcp: [Total; 4],
    retransmission: [Ratio; 2],
    rtt: [TimingTotal; 2],
    dns: [Total; 6],
    dns_unanswered: Ratio,
    connections: ConnectionAverage,
    pending_at_close: Option<Count>,
    pending_at_close_at: Option<DateTime<Utc>>,
    statuses: [StatusDuration; 5],
    rated_levels: [StatusDuration; 4],
    worst_level: Option<ExperienceLevel>,
    last_rated: Option<(DateTime<Utc>, Experience)>,
    reasons: BTreeMap<String, u32>,
    reasons_truncated: bool,
}
impl Accumulator {
    pub fn new(start_ms: i64, end_ms: i64) -> Result<Self> {
        ensure!(
            start_ms.rem_euclid(SLOT_MS) == 0
                && end_ms.rem_euclid(SLOT_MS) == 0
                && start_ms.checked_add(HOUR_MS) == Some(end_ms),
            "summary interval must be exactly one hour with ten-second UTC-aligned endpoints"
        );
        ensure!(
            DateTime::<Utc>::from_timestamp_millis(start_ms).is_some()
                && DateTime::<Utc>::from_timestamp_millis(end_ms).is_some(),
            "summary timestamps are out of range"
        );
        Ok(Self {
            start_ms,
            end_ms,
            address: None,
            observed_slots: 0,
            complete_slots: 0,
            first_sample_at: None,
            last_sample_at: None,
            last_seen_at: None,
            previous_end_ms: None,
            initial_identity: None,
            host_id_changed: false,
            interface_changed: false,
            configured_identity_changed: false,
            previous_epoch: None,
            epochs: BTreeSet::new(),
            epoch_discontinuities: 0,
            sources: std::array::from_fn(|_| Source::default()),
            traffic: std::array::from_fn(|_| Total::default()),
            firewall: std::array::from_fn(|_| Total::default()),
            tcp: std::array::from_fn(|_| Total::default()),
            retransmission: std::array::from_fn(|_| Ratio::default()),
            rtt: std::array::from_fn(|_| TimingTotal::default()),
            dns: std::array::from_fn(|_| Total::default()),
            dns_unanswered: Ratio::default(),
            connections: ConnectionAverage::default(),
            pending_at_close: None,
            pending_at_close_at: None,
            statuses: std::array::from_fn(|_| StatusDuration::default()),
            rated_levels: std::array::from_fn(|_| StatusDuration::default()),
            worst_level: None,
            last_rated: None,
            reasons: BTreeMap::new(),
            reasons_truncated: false,
        })
    }

    pub fn push(&mut self, sample: &experience::Sample) -> Result<()> {
        let start = sample.start_at.timestamp_millis();
        let end = sample.end_at.timestamp_millis();
        ensure!(self.observed_slots < SLOTS, "summary exceeds 360 samples");
        ensure!(
            start >= self.start_ms
                && end <= self.end_ms
                && start.rem_euclid(SLOT_MS) == 0
                && start.checked_add(SLOT_MS) == Some(end)
                && sample.start_at.timestamp_subsec_nanos() % 1_000_000 == 0
                && sample.end_at.timestamp_subsec_nanos() % 1_000_000 == 0,
            "sample must occupy an aligned ten-second slot within the summary hour"
        );
        ensure!(
            self.previous_end_ms
                .is_none_or(|previous| start >= previous),
            "duplicate, overlapping or nonchronological summary sample"
        );
        ensure!(
            self.address.is_none_or(|ip| ip == sample.ip_address),
            "mixed summary IP addresses"
        );
        validate(sample)?;
        let connections = if sample.connections.status == SourceStatus::Available {
            Some(connection_values(&sample.connections)?)
        } else {
            None
        };

        self.address = Some(sample.ip_address);
        self.observed_slots += 1;
        self.complete_slots += u32::from(sample.coverage.complete);
        self.first_sample_at.get_or_insert(sample.start_at);
        self.last_sample_at = Some(sample.end_at);
        self.previous_end_ms = Some(end);
        self.connections.push(sample, connections);
        if let Some(seen) = sample.last_seen_at {
            self.last_seen_at = Some(self.last_seen_at.map_or(seen, |old| old.max(seen)));
        }
        if let Some(initial) = &self.initial_identity {
            self.host_id_changed |= initial.0 != sample.configured_host_id;
            self.interface_changed |= initial.1 != sample.interface;
            self.configured_identity_changed |=
                initial.2 != sample.configured_name || initial.3 != sample.configuration_revision;
        } else {
            self.initial_identity = Some((
                sample.configured_host_id.clone(),
                sample.interface.clone(),
                sample.configured_name.clone(),
                sample.configuration_revision.clone(),
            ));
        }
        if self.previous_epoch.as_ref() != Some(&sample.observation_epoch) {
            self.epoch_discontinuities += u32::from(self.previous_epoch.is_some());
            self.previous_epoch = Some(sample.observation_epoch.clone());
        }
        if !self.epochs.contains(&sample.observation_epoch) {
            self.epochs.insert(sample.observation_epoch.clone());
        }
        for (source, status) in self.sources.iter_mut().zip([
            sample.traffic.status,
            sample.firewall.status,
            sample.tcp.status,
            sample.dns.status,
            sample.connections.status,
        ]) {
            source.push(status, sample);
        }
        for (total, value) in self.traffic.iter_mut().zip([
            sample.traffic.sent_packets,
            sample.traffic.received_packets,
            sample.traffic.sent_bytes,
            sample.traffic.received_bytes,
        ]) {
            total.push(value, sample, sample.traffic.status);
        }
        for (total, value) in self.firewall.iter_mut().zip([
            sample.firewall.dropped_sent_packets,
            sample.firewall.dropped_received_packets,
        ]) {
            total.push(value, sample, sample.firewall.status);
        }
        for (total, value) in self.tcp.iter_mut().zip([
            sample.tcp.data_packets_sent,
            sample.tcp.data_packets_received,
            sample.tcp.retransmission_observations_sent,
            sample.tcp.retransmission_observations_received,
        ]) {
            total.push(value, sample, sample.tcp.status);
        }
        for (ratio, (data, repeat)) in self.retransmission.iter_mut().zip([
            (
                sample.tcp.data_packets_sent,
                sample.tcp.retransmission_observations_sent,
            ),
            (
                sample.tcp.data_packets_received,
                sample.tcp.retransmission_observations_received,
            ),
        ]) {
            if let (Some(data), Some(repeat)) = (data, repeat) {
                ratio.push(repeat, u128::from(data.0), sample, sample.tcp.status);
            }
        }
        self.rtt[0].push(&sample.tcp.rtt_remote, sample);
        self.rtt[1].push(&sample.tcp.rtt_host, sample);
        for (total, value) in self.dns.iter_mut().zip([
            sample.dns.requests,
            sample.dns.responses,
            sample.dns.unanswered,
            sample.dns.servfail_responses,
            sample.dns.refused_responses,
            sample.dns.excluded_observations,
        ]) {
            total.push(value, sample, sample.dns.status);
        }
        if sample.dns.status == SourceStatus::Available
            && let (Some(responses), Some(unanswered)) =
                (sample.dns.responses, sample.dns.unanswered)
        {
            self.dns_unanswered.push(
                unanswered,
                u128::from(responses.0) + u128::from(unanswered.0),
                sample,
                sample.dns.status,
            );
        }
        if let Some(pending) = sample.dns.pending_at_close {
            self.pending_at_close = Some(pending);
            self.pending_at_close_at = Some(sample.end_at);
        }
        self.statuses[status_index(sample.experience.status)].slots += 1;
        if sample.experience.status == ExperienceStatus::Rated {
            let index = level_index(sample.experience.level);
            self.rated_levels[index].slots += 1;
            if self
                .worst_level
                .is_none_or(|level| index > level_index(level))
            {
                self.worst_level = Some(sample.experience.level);
            }
            if let Some((at, stored)) = self.last_rated.as_mut()
                && *stored == sample.experience
            {
                *at = sample.end_at;
            } else {
                self.last_rated = Some((sample.end_at, sample.experience.clone()));
            }
        }
        let mut reasons = [""; REASON_LIMIT * 2];
        let count = sample.experience.reasons.len() + sample.coverage.reasons.len();
        for (target, reason) in reasons.iter_mut().zip(
            sample
                .experience
                .reasons
                .iter()
                .chain(&sample.coverage.reasons),
        ) {
            *target = reason.as_str();
        }
        let reasons = &mut reasons[..count];
        reasons.sort_unstable();
        for (index, &reason) in reasons.iter().enumerate() {
            if index > 0 && reasons[index - 1] == reason {
                continue;
            }
            if let Some(count) = self.reasons.get_mut(reason) {
                *count += 1;
            } else if self.reasons.len() < REASON_LIMIT {
                self.reasons.insert(reason.to_owned(), 1);
            } else {
                self.reasons_truncated = true;
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<serde_json::Value> {
        let identity_changed =
            self.host_id_changed || self.interface_changed || self.configured_identity_changed;
        let start = DateTime::<Utc>::from_timestamp_millis(self.start_ms)
            .ok_or_else(|| anyhow::anyhow!("invalid summary start"))?;
        let end = DateTime::<Utc>::from_timestamp_millis(self.end_ms)
            .ok_or_else(|| anyhow::anyhow!("invalid summary end"))?;
        let last_rated = self.last_rated.map(|(at, value)| {
            json!({
                "sample_at": at, "experience": value,
                "is_last_observed_slot": self.last_sample_at == Some(at),
            })
        });
        Ok(json!({
            "start_at": start, "end_at": end,
            "expected_slots": SLOTS, "observed_slots": self.observed_slots,
            "complete_slots": self.complete_slots, "observed_seconds": self.observed_slots * 10,
            "coverage_complete": self.complete_slots == SLOTS && !identity_changed
                && self.epoch_discontinuities == 0,
            "first_sample_at": self.first_sample_at, "last_sample_at": self.last_sample_at,
            "last_seen_at": self.last_seen_at, "observation_epochs": self.epochs.len(),
            "epoch_discontinuities": self.epoch_discontinuities,
            "identity_changed": identity_changed,
            "identity_changes": {
                "host_id": self.host_id_changed, "interface": self.interface_changed,
                "configured_identity": self.configured_identity_changed,
            },
            "sources": {
                "traffic": self.sources[0].json(), "firewall": self.sources[1].json(),
                "tcp": self.sources[2].json(), "dns": self.sources[3].json(),
                "connections": self.sources[4].json(),
            },
            "connections": {
                "current": null,
                "average": self.connections.json(),
            },
            "traffic": {
                "sent_packets": self.traffic[0].json(), "received_packets": self.traffic[1].json(),
                "sent_bytes": self.traffic[2].json(), "received_bytes": self.traffic[3].json(),
                "sent_bps": self.traffic[2].rate(), "received_bps": self.traffic[3].rate(),
                "packet_unit": "kernel_l3_packet", "byte_unit": "ip_layer_bytes",
            },
            "firewall": {
                "dropped_sent_packets": self.firewall[0].json(),
                "dropped_received_packets": self.firewall[1].json(),
                "drop_coverage": "managed_nftables_only",
            },
            "tcp": {
                "data_packets_sent": self.tcp[0].json(), "data_packets_received": self.tcp[1].json(),
                "retransmission_observations_sent": self.tcp[2].json(),
                "retransmission_observations_received": self.tcp[3].json(),
                "retransmission_sent": self.retransmission[0].json(),
                "retransmission_received": self.retransmission[1].json(),
                "rtt_remote": self.rtt[0].json(), "rtt_host": self.rtt[1].json(),
            },
            "dns": {
                "requests": self.dns[0].json(), "responses": self.dns[1].json(),
                "unanswered": self.dns[2].json(), "servfail_responses": self.dns[3].json(),
                "refused_responses": self.dns[4].json(), "excluded_observations": self.dns[5].json(),
                "unanswered_ratio": self.dns_unanswered.json(),
                "pending_at_close": self.pending_at_close, "pending_at_close_at": self.pending_at_close_at,
                "pending_at_close_is_last_observed_slot": self.pending_at_close_at.is_some()
                    && self.pending_at_close_at == self.last_sample_at,
                "response_time_p50_ms": null, "response_time_p95_ms": null,
                "response_time_variation_mean_ms": null,
                "timing_unavailable_reason": "per_bucket_distributions_and_variation_weights_not_retained",
            },
            "experience": {
                "rated": self.statuses[0].json(), "idle": self.statuses[1].json(),
                "insufficient_data": self.statuses[2].json(), "incomplete": self.statuses[3].json(),
                "unavailable": self.statuses[4].json(),
                "missing": {"slots": SLOTS - self.observed_slots, "seconds": (SLOTS - self.observed_slots) * 10},
                "rated_levels": {
                    "excellent": self.rated_levels[0].json(), "good": self.rated_levels[1].json(),
                    "fair": self.rated_levels[2].json(), "poor": self.rated_levels[3].json(),
                },
                "worst_rated_level": self.worst_level, "last_rated": last_rated,
                "reason_frequencies": self.reasons, "reason_frequencies_truncated": self.reasons_truncated,
            },
        }))
    }
}

fn status_index(status: ExperienceStatus) -> usize {
    match status {
        ExperienceStatus::Rated => 0,
        ExperienceStatus::Idle => 1,
        ExperienceStatus::InsufficientData => 2,
        ExperienceStatus::Incomplete => 3,
        ExperienceStatus::Unavailable => 4,
    }
}
fn level_index(level: ExperienceLevel) -> usize {
    match level {
        ExperienceLevel::Excellent => 0,
        ExperienceLevel::Good => 1,
        ExperienceLevel::Fair => 2,
        ExperienceLevel::Poor => 3,
        ExperienceLevel::Unknown => 4,
    }
}

fn finite(values: &[Option<f64>]) -> Result<()> {
    ensure!(
        values
            .iter()
            .flatten()
            .all(|value| value.is_finite() && *value >= 0.0),
        "nonfinite or negative summary metric"
    );
    Ok(())
}
fn counts(status: SourceStatus, values: &[Option<Count>]) -> Result<()> {
    match status {
        SourceStatus::Available => ensure!(
            values.iter().all(Option::is_some),
            "available source has missing counters"
        ),
        SourceStatus::NotObserved | SourceStatus::Unavailable => {
            ensure!(
                values.iter().all(Option::is_none),
                "unobserved source has measured counters"
            );
        }
        SourceStatus::Partial => {}
    }
    Ok(())
}
fn validate_timing(timing: &Timing, status: SourceStatus) -> Result<()> {
    finite(&[
        timing.min_ms,
        timing.max_ms,
        timing.p50_ms,
        timing.p95_ms,
        timing.variation_mean_ms,
    ])?;
    ensure!(
        timing.variation_pairs.0 <= timing.samples.0,
        "timing variation pairs exceed samples"
    );
    ensure!(
        (timing.variation_pairs.0 > 0) == timing.variation_mean_ms.is_some(),
        "timing variation count/mean mismatch"
    );
    if timing.samples.0 == 0 {
        ensure!(
            timing.min_ms.is_none()
                && timing.max_ms.is_none()
                && timing.p50_ms.is_none()
                && timing.p95_ms.is_none(),
            "empty timing has measured extrema or percentiles"
        );
    } else {
        ensure!(
            matches!(status, SourceStatus::Available | SourceStatus::Partial),
            "unobserved timing source has samples"
        );
        let (Some(min), Some(max)) = (timing.min_ms, timing.max_ms) else {
            anyhow::bail!("timing samples require exact extrema");
        };
        ensure!(min <= max, "reversed timing extrema");
        ensure!(
            [timing.p50_ms, timing.p95_ms]
                .into_iter()
                .flatten()
                .all(|value| value >= min && value <= max)
                && !matches!((timing.p50_ms, timing.p95_ms), (Some(a), Some(b)) if a > b),
            "timing percentiles outside extrema or reversed"
        );
    }
    Ok(())
}
fn validate(sample: &Sample) -> Result<()> {
    ensure!(
        sample.measured_duration_ms <= 20_000
            && (!sample.coverage.complete || sample.measured_duration_ms > 0),
        "invalid measured duration or complete coverage"
    );
    ensure!(
        !sample.observation_epoch.is_empty()
            && sample.observation_epoch.len() <= experience::MAX_EVIDENCE_EPOCH_BYTES,
        "invalid observation epoch"
    );
    ensure!(
        !sample.configured_host_id.is_empty()
            && sample.configured_host_id.len() <= 255
            && !sample.configured_name.is_empty()
            && sample.configured_name.len() <= 255
            && !sample.configuration_revision.is_empty()
            && sample.configuration_revision.len() <= 64,
        "invalid configured summary identity"
    );
    if let Some(interface) = &sample.interface {
        ensure!(
            !interface.name.is_empty()
                && interface.name.len() <= 15
                && interface.index > 0
                && !interface.kind.is_empty()
                && interface.kind.len() <= 32
                && interface.vlan_id.is_none_or(|id| (1..=4094).contains(&id)),
            "invalid summary interface identity"
        );
    }
    for reasons in [&sample.experience.reasons, &sample.coverage.reasons] {
        ensure!(
            reasons.len() <= REASON_LIMIT
                && reasons
                    .iter()
                    .all(|reason| !reason.is_empty() && reason.len() <= 128)
                && reasons
                    .iter()
                    .enumerate()
                    .all(|(index, reason)| !reasons[..index].contains(reason)),
            "invalid or oversized summary reasons"
        );
    }
    ensure!(
        sample.experience.score.is_none_or(|score| score <= 100)
            && sample.experience.basis_seconds <= 60
            && sample.experience.components.len() <= 16,
        "invalid stored experience"
    );
    ensure!(
        sample.experience.status != ExperienceStatus::Rated
            || (sample.experience.score.is_some()
                && sample.experience.level != ExperienceLevel::Unknown),
        "rated experience requires stored score and level"
    );
    ensure!(
        sample.experience.status == ExperienceStatus::Rated
            || (sample.experience.score.is_none()
                && sample.experience.level == ExperienceLevel::Unknown),
        "unrated experience has a stored score or rated level"
    );
    ensure!(
        sample.experience.components.iter().all(|component| {
            component.value.is_finite()
                && component.value >= 0.0
                && component.score <= 100
                && !component.code.is_empty()
                && component.code.len() <= 64
                && !component.unit.is_empty()
                && component.unit.len() <= 32
        }),
        "invalid stored experience component"
    );
    counts(
        sample.traffic.status,
        &[
            sample.traffic.sent_packets,
            sample.traffic.received_packets,
            sample.traffic.sent_bytes,
            sample.traffic.received_bytes,
        ],
    )?;
    counts(
        sample.firewall.status,
        &[
            sample.firewall.dropped_sent_packets,
            sample.firewall.dropped_received_packets,
        ],
    )?;
    counts(
        sample.tcp.status,
        &[
            sample.tcp.data_packets_sent,
            sample.tcp.data_packets_received,
            sample.tcp.retransmission_observations_sent,
            sample.tcp.retransmission_observations_received,
        ],
    )?;
    if matches!(
        sample.tcp.status,
        SourceStatus::NotObserved | SourceStatus::Unavailable
    ) {
        ensure!(
            [
                sample.tcp.window_decreases_host,
                sample.tcp.window_decreases_peer,
                sample.tcp.zero_window_observations_host,
                sample.tcp.zero_window_observations_peer,
                sample.tcp.zero_window_transitions_host,
                sample.tcp.zero_window_transitions_peer,
            ]
            .iter()
            .all(Option::is_none)
                && sample.tcp.advertised_window_min_bytes_host.is_none()
                && sample.tcp.advertised_window_min_bytes_peer.is_none(),
            "unobserved TCP source has auxiliary counters"
        );
    }
    counts(
        sample.dns.status,
        &[
            sample.dns.requests,
            sample.dns.responses,
            sample.dns.unanswered,
            sample.dns.pending_at_close,
            sample.dns.servfail_responses,
            sample.dns.refused_responses,
            sample.dns.excluded_observations,
        ],
    )?;
    finite(&[
        sample.traffic.sent_bps,
        sample.traffic.received_bps,
        sample.tcp.retransmission_percent_sent,
        sample.tcp.retransmission_percent_received,
        sample.dns.unanswered_percent,
        sample.dns.response_time_p50_ms,
        sample.dns.response_time_p95_ms,
        sample.dns.response_time_variation_mean_ms,
    ])?;
    ensure!(
        sample.traffic.packet_unit == "kernel_l3_packet"
            && sample.traffic.byte_unit == "ip_layer_bytes"
            && sample.firewall.drop_coverage == "managed_nftables_only",
        "unsupported summary counter units"
    );
    for (bytes, rate) in [
        (sample.traffic.sent_bytes, sample.traffic.sent_bps),
        (sample.traffic.received_bytes, sample.traffic.received_bps),
    ] {
        ensure!(
            rate.is_none() || (bytes.is_some() && sample.measured_duration_ms > 0),
            "traffic rate lacks bytes or measured duration"
        );
    }
    if [
        sample.traffic.status,
        sample.firewall.status,
        sample.tcp.status,
        sample.dns.status,
    ]
    .into_iter()
    .any(|status| matches!(status, SourceStatus::Available | SourceStatus::Partial))
    {
        ensure!(
            sample.measured_duration_ms > 0,
            "observed source requires measured duration"
        );
    }
    for (data, repeat, percent) in [
        (
            sample.tcp.data_packets_sent,
            sample.tcp.retransmission_observations_sent,
            sample.tcp.retransmission_percent_sent,
        ),
        (
            sample.tcp.data_packets_received,
            sample.tcp.retransmission_observations_received,
            sample.tcp.retransmission_percent_received,
        ),
    ] {
        ensure!(
            repeat.is_none() || data.is_some(),
            "TCP repeats lack paired data count"
        );
        ensure!(
            !matches!((data, repeat), (Some(data), Some(repeat)) if repeat > data),
            "TCP repeats exceed data count"
        );
        ensure!(
            percent.is_none()
                || matches!((data, repeat), (Some(data), Some(_)) if data.0 > 0)
                    && percent.is_some_and(|percent| percent <= 100.0),
            "TCP percentage lacks valid paired denominator"
        );
    }
    validate_timing(&sample.tcp.rtt_remote, sample.tcp.status)?;
    validate_timing(&sample.tcp.rtt_host, sample.tcp.status)?;
    ensure!(
        sample.dns.unanswered_percent.is_none()
            || sample.dns.status == SourceStatus::Available
                && matches!((sample.dns.responses, sample.dns.unanswered),
                    (Some(responses), Some(unanswered)) if responses.0 > 0 || unanswered.0 > 0)
                && sample
                    .dns
                    .unanswered_percent
                    .is_some_and(|value| value <= 100.0),
        "DNS percentage lacks available paired denominator"
    );
    for count in [sample.dns.servfail_responses, sample.dns.refused_responses] {
        ensure!(
            count.is_none()
                || matches!((count, sample.dns.responses), (Some(count), Some(responses)) if count <= responses),
            "DNS response subtype lacks valid response count"
        );
    }
    ensure!(
        !matches!(
            (sample.dns.servfail_responses, sample.dns.refused_responses, sample.dns.responses),
            (Some(servfail), Some(refused), Some(responses))
                if u128::from(servfail.0) + u128::from(refused.0) > u128::from(responses.0)
        ),
        "DNS response subtype sum exceeds responses"
    );
    if matches!(
        sample.dns.status,
        SourceStatus::NotObserved | SourceStatus::Unavailable
    ) {
        ensure!(
            sample.dns.response_time_p50_ms.is_none()
                && sample.dns.response_time_p95_ms.is_none()
                && sample.dns.response_time_variation_mean_ms.is_none(),
            "unobserved DNS source has measured timing"
        );
    }
    ensure!(
        [
            sample.dns.response_time_p50_ms,
            sample.dns.response_time_p95_ms,
            sample.dns.response_time_variation_mean_ms
        ]
        .iter()
        .all(Option::is_none)
            || sample
                .dns
                .responses
                .is_some_and(|responses| responses.0 > 0),
        "DNS timing lacks observed responses"
    );
    ensure!(
        !matches!((sample.dns.response_time_p50_ms, sample.dns.response_time_p95_ms),
            (Some(p50), Some(p95)) if p50 > p95),
        "reversed DNS timing percentiles"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experience::{Activity, Dns, Tcp, Traffic};

    fn sample(slot: u32) -> Sample {
        let start = DateTime::<Utc>::from_timestamp_millis(i64::from(slot) * SLOT_MS).unwrap();
        let end = DateTime::<Utc>::from_timestamp_millis(i64::from(slot + 1) * SLOT_MS).unwrap();
        let mut sample = Sample::new(
            "192.0.2.1".parse().unwrap(),
            "host".into(),
            "2026.11.14.1".into(),
            "epoch-a".into(),
            start,
            end,
        );
        sample.measured_duration_ms = 10_000;
        sample
    }
    fn tcp(data: u64, repeats: u64) -> Tcp {
        Tcp {
            status: SourceStatus::Available,
            data_packets_sent: Some(data.into()),
            data_packets_received: Some(0.into()),
            retransmission_observations_sent: Some(repeats.into()),
            retransmission_observations_received: Some(0.into()),
            ..Tcp::default()
        }
    }
    fn dns(responses: u64, unanswered: u64, pending: u64) -> Dns {
        Dns {
            status: SourceStatus::Available,
            requests: Some(100.into()),
            responses: Some(responses.into()),
            unanswered: Some(unanswered.into()),
            pending_at_close: Some(pending.into()),
            servfail_responses: Some(0.into()),
            refused_responses: Some(0.into()),
            excluded_observations: Some(0.into()),
            ..Dns::default()
        }
    }

    #[test]
    fn last_seen_preserves_actual_observations_after_nominal_bucket_end() {
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        let mut row = sample(359);
        let seen = row.end_at + chrono::Duration::milliseconds(125);
        row.last_seen_at = Some(seen);
        let mut earlier = sample(358);
        earlier.last_seen_at = Some(seen - chrono::Duration::seconds(10));
        accumulator.push(&earlier).unwrap();
        accumulator.push(&row).unwrap();
        assert_eq!(
            accumulator.finish().unwrap()["last_seen_at"],
            serde_json::to_value(seen).unwrap()
        );
    }

    #[test]
    fn connection_averages_exclude_missing_and_partial_snapshots() {
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        for (slot, (total, status, age)) in [
            (10, SourceStatus::Available, 1000),
            (30, SourceStatus::Available, 1000),
            (1000, SourceStatus::Partial, 1000),
            (1000, SourceStatus::Unavailable, 3000),
        ]
        .into_iter()
        .enumerate()
        {
            let mut row = sample(u32::try_from(slot).unwrap());
            row.connections = Connections {
                status,
                observed_at: Some(row.end_at - chrono::Duration::milliseconds(age)),
                total: Some(Count(total)),
                tcp_established: Some(Count(total / 2)),
                unreplied: Some(Count(0)),
                ..Connections::default()
            };
            accumulator.push(&row).unwrap();
        }
        accumulator.push(&sample(4)).unwrap();
        let result = accumulator.finish().unwrap();
        let average = &result["connections"]["average"];
        assert_eq!(average["total"], 20.0);
        assert_eq!(average["tcp_established"], 10.0);
        assert_eq!(average["unreplied"], 0.0);
        assert_eq!(average["observed_slots"], 2);
        assert_eq!(average["coverage_seconds"], 20);

        let mut empty = Accumulator::new(0, HOUR_MS).unwrap();
        empty.push(&sample(0)).unwrap();
        assert!(empty.finish().unwrap()["connections"]["average"]["total"].is_null());
    }

    #[test]
    fn current_connections_preserve_zero_and_mark_old_snapshots_stale() {
        let mut row = sample(0);
        row.connections = Connections {
            status: SourceStatus::Available,
            observed_at: Some(row.end_at),
            measurement_duration_ms: Some(50),
            total: Some(Count(0)),
            tcp_established: Some(Count(0)),
            unreplied: Some(Count(0)),
            ..Connections::default()
        };
        let current = connection_snapshot(Some(&row), 10_000).unwrap();
        assert_eq!(current["total"], "0");
        assert_eq!(current["status"], "available");
        assert_eq!(current["age_ms"], 0);
        assert_eq!(
            connection_snapshot(Some(&row), 40_001).unwrap()["status"],
            "stale"
        );
        assert!(connection_snapshot(None, 10_000).unwrap()["total"].is_null());
        assert!(connection_snapshot(Some(&row), 9999).is_err());
        let mut average = Accumulator::new(0, HOUR_MS).unwrap();
        average.push(&row).unwrap();
        assert_eq!(
            average.finish().unwrap()["connections"]["average"]["total"],
            0.0
        );
        row.connections.total = None;
        assert!(connection_snapshot(Some(&row), 10_000).is_err());
    }

    #[test]
    fn exact_totals_above_u64_and_measured_duration_rates() {
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        for slot in 0..2 {
            let mut row = sample(slot);
            row.measured_duration_ms = if slot == 0 { 10_000 } else { 20_000 };
            row.traffic = Traffic::measured(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                row.measured_duration_ms,
            );
            accumulator.push(&row).unwrap();
        }
        let result = accumulator.finish().unwrap();
        assert_eq!(
            result["traffic"]["sent_bytes"]["total"],
            "36893488147419103230"
        );
        assert_eq!(
            result["traffic"]["received_packets"]["total"],
            "36893488147419103230"
        );
        assert_eq!(result["observed_seconds"], 20);
        assert_eq!(
            result["traffic"]["sent_bytes"]["measured_duration_ms"],
            30_000
        );
        let rate = result["traffic"]["sent_bps"].as_f64().unwrap();
        assert!((rate / (u64::MAX as f64 * 2.0 * 8000.0 / 30_000.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn pooled_ratios_and_pair_weighted_variation_exclude_missing_denominators() {
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        for (slot, data, repeats, responses, unanswered, pairs, mean) in
            [(0, 100, 10, 9, 1, 1, 100.0), (1, 900, 0, 90, 0, 9, 0.0)]
        {
            let mut row = sample(slot);
            row.tcp = tcp(data, repeats);
            row.tcp.rtt_remote = Timing {
                samples: Count(10),
                variation_pairs: Count(pairs),
                min_ms: Some(0.0),
                max_ms: Some(200.0),
                p50_ms: Some(10.0),
                p95_ms: Some(100.0),
                variation_mean_ms: Some(mean),
            };
            row.dns = dns(responses, unanswered, u64::from(slot + 1));
            accumulator.push(&row).unwrap();
        }
        let mut partial = sample(2);
        partial.tcp.status = SourceStatus::Partial;
        partial.tcp.data_packets_sent = Some(9000.into());
        partial.dns = dns(1000, 1000, 7);
        partial.dns.status = SourceStatus::Partial;
        accumulator.push(&partial).unwrap();
        accumulator.push(&sample(3)).unwrap();
        let result = accumulator.finish().unwrap();
        assert_eq!(result["tcp"]["data_packets_sent"]["total"], "10000");
        assert_eq!(result["tcp"]["retransmission_sent"]["denominator"], "1000");
        assert!(
            (result["tcp"]["retransmission_sent"]["percent"]
                .as_f64()
                .unwrap()
                - 1.0)
                .abs()
                < 1e-12
        );
        assert!(
            (result["tcp"]["rtt_remote"]["variation_mean_ms"]
                .as_f64()
                .unwrap()
                - 10.0)
                .abs()
                < 1e-12
        );
        assert_eq!(result["tcp"]["rtt_remote"]["min_ms"], 0.0);
        assert_eq!(result["tcp"]["rtt_remote"]["max_ms"], 200.0);
        assert!(result["tcp"]["rtt_remote"]["p95_ms"].is_null());
        assert_eq!(result["dns"]["unanswered_ratio"]["denominator"], "100");
        assert!(
            (result["dns"]["unanswered_ratio"]["percent"]
                .as_f64()
                .unwrap()
                - 1.0)
                .abs()
                < 1e-12
        );
        assert_eq!(result["dns"]["pending_at_close"], "7");
        assert_eq!(
            result["dns"]["pending_at_close_is_last_observed_slot"],
            false
        );
        assert!(result["dns"]["response_time_variation_mean_ms"].is_null());
    }

    #[test]
    fn idle_unobserved_partial_and_missing_slots_are_not_zero_measurements() {
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        let mut idle = sample(0);
        idle.activity = Activity::Idle;
        idle.coverage.complete = true;
        idle.experience.status = ExperienceStatus::Idle;
        idle.tcp.status = SourceStatus::NotObserved;
        idle.dns.status = SourceStatus::NotObserved;
        accumulator.push(&idle).unwrap();
        let mut partial = sample(2);
        partial.traffic.status = SourceStatus::Partial;
        partial.traffic.sent_bytes = Some(5.into());
        partial.experience.status = ExperienceStatus::Incomplete;
        accumulator.push(&partial).unwrap();
        let result = accumulator.finish().unwrap();
        assert_eq!(result["observed_slots"], 2);
        assert_eq!(result["complete_slots"], 1);
        assert_eq!(result["coverage_complete"], false);
        assert_eq!(result["experience"]["missing"]["seconds"], 3580);
        assert_eq!(result["experience"]["idle"]["seconds"], 10);
        assert_eq!(result["sources"]["tcp"]["not_observed_slots"], 1);
        assert_eq!(result["sources"]["traffic"]["partial_slots"], 1);
        assert!(result["tcp"]["data_packets_sent"]["total"].is_null());
        assert!(result["dns"]["requests"]["total"].is_null());
        assert_eq!(result["traffic"]["sent_bytes"]["complete_slots"], 0);
        assert_eq!(result["traffic"]["sent_bytes"]["total"], "5");
    }

    #[test]
    fn transitions_invalidate_full_hour_and_last_rated_remains_stored_and_stale() {
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        let mut stable = Accumulator::new(0, HOUR_MS).unwrap();
        for slot in 0..SLOTS {
            let mut row = sample(slot);
            row.coverage.complete = true;
            row.experience.status = ExperienceStatus::Idle;
            stable.push(&row).unwrap();
            if slot == 0 {
                row.experience.status = ExperienceStatus::Rated;
                row.experience.level = ExperienceLevel::Fair;
                row.experience.score = Some(60);
                row.experience.reasons = vec!["tcp_repeats_sent".into()];
                row.coverage.reasons = row.experience.reasons.clone();
            } else {
                row.observation_epoch = "epoch-b".into();
                row.configured_host_id = "another-host".into();
                row.configured_name = "another-name".into();
                row.interface = Some(InterfaceIdentity {
                    name: "eth0".into(),
                    index: 1,
                    kind: "physical".into(),
                    vlan_id: None,
                });
            }
            accumulator.push(&row).unwrap();
        }
        let result = accumulator.finish().unwrap();
        assert_eq!(stable.finish().unwrap()["coverage_complete"], true);
        assert_eq!(result["observed_seconds"], 3600);
        assert_eq!(result["coverage_complete"], false);
        assert_eq!(result["observation_epochs"], 2);
        assert_eq!(result["epoch_discontinuities"], 1);
        assert_eq!(
            result["identity_changes"],
            json!({"host_id": true, "interface": true, "configured_identity": true})
        );
        assert_eq!(
            result["experience"]["last_rated"]["experience"]["score"],
            60
        );
        assert_eq!(
            result["experience"]["last_rated"]["is_last_observed_slot"],
            false
        );
        assert_eq!(
            result["experience"]["last_rated"]["sample_at"],
            "1970-01-01T00:00:10Z"
        );
        assert_eq!(result["experience"]["worst_rated_level"], "fair");
        assert_eq!(
            result["experience"]["reason_frequencies"]["tcp_repeats_sent"],
            1
        );
    }

    #[test]
    fn rejects_invalid_rows_without_mutating_and_rejects_duplicates() {
        assert!(Accumulator::new(1, HOUR_MS + 1).is_err());
        assert!(Accumulator::new(SLOT_MS, HOUR_MS).is_err());
        let mut rolling = Accumulator::new(SLOT_MS, HOUR_MS + SLOT_MS).unwrap();
        assert!(rolling.push(&sample(0)).is_err());
        rolling.push(&sample(1)).unwrap();
        rolling.push(&sample(360)).unwrap();
        let rolling = rolling.finish().unwrap();
        assert_eq!(rolling["observed_slots"], 2);
        assert_eq!(rolling["first_sample_at"], "1970-01-01T00:00:10Z");
        assert_eq!(rolling["last_sample_at"], "1970-01-01T01:00:10Z");
        let mut accumulator = Accumulator::new(0, HOUR_MS).unwrap();
        let mut bad = sample(0);
        bad.tcp = tcp(1, 2);
        assert!(accumulator.push(&bad).is_err());
        bad.tcp = tcp(2, 1);
        bad.tcp.rtt_host.samples = Count(1);
        assert!(accumulator.push(&bad).is_err());
        bad.tcp = Tcp::default();
        bad.traffic.sent_packets = Some(0.into());
        assert!(accumulator.push(&bad).is_err());
        accumulator.push(&sample(0)).unwrap();
        assert!(accumulator.push(&sample(0)).is_err());
        assert!(accumulator.push(&sample(360)).is_err());
        let mut mixed = sample(1);
        mixed.ip_address = "192.0.2.2".parse().unwrap();
        assert!(accumulator.push(&mixed).is_err());
        accumulator.push(&sample(1)).unwrap();
        assert_eq!(accumulator.finish().unwrap()["observed_slots"], 2);
    }
}
