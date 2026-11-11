use anyhow::{Result, anyhow, ensure};
use netcontrol_core::DHCPRelayLogQuery;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) const CAPACITY: usize = 2048;

#[derive(Clone, Copy)]
pub(crate) enum Action {
    Request,
    Reply,
    ToServer,
    ToClient,
    Rejected,
    SendError,
    Expired,
    WorkerStart,
    WorkerError,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Request => "requests_received",
            Self::Reply => "replies_received",
            Self::ToServer => "requests_forwarded",
            Self::ToClient => "replies_forwarded",
            Self::Rejected => "packets_rejected",
            Self::SendError => "send_errors",
            Self::Expired => "transactions_expired",
            Self::WorkerStart => "worker_start",
            Self::WorkerError => "worker_error",
        }
    }
}

#[derive(Default)]
struct Counts {
    values: BTreeMap<&'static str, u64>,
    reasons: BTreeMap<String, u64>,
    pending: usize,
}

impl Counts {
    fn record(&mut self, action: Action, reason: &str) {
        if matches!(action, Action::WorkerStart | Action::WorkerError) {
            return;
        }
        let value = self.values.entry(action.name()).or_default();
        *value = value.saturating_add(1);
        if matches!(action, Action::Rejected) {
            let value = self.reasons.entry(reason.into()).or_default();
            *value = value.saturating_add(1);
        }
    }

    fn value(&self) -> Value {
        let mut result = json!({"pending_transactions":self.pending.to_string(),
            "rejected_by_reason":self.reasons.iter().map(|(k,v)|(k.clone(),json!(v.to_string()))).collect::<serde_json::Map<_,_>>()});
        for action in [
            Action::Request,
            Action::Reply,
            Action::ToServer,
            Action::ToClient,
            Action::Rejected,
            Action::SendError,
            Action::Expired,
        ] {
            result[action.name()] = json!(
                self.values
                    .get(action.name())
                    .copied()
                    .unwrap_or(0)
                    .to_string()
            );
        }
        result
    }
}

struct State {
    epoch: String,
    generation: u64,
    since: Option<String>,
    sequence: u64,
    overwritten: u64,
    events: VecDeque<Value>,
    totals: Counts,
    interfaces: BTreeMap<String, Counts>,
    send_warnings: BTreeMap<(Option<String>, String), Instant>,
}

#[derive(Clone)]
pub(crate) struct Telemetry(Arc<Mutex<State>>);

impl Default for Telemetry {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(State {
            epoch: format!("{:032x}", rand::random::<u128>()),
            generation: 0,
            since: None,
            sequence: 0,
            overwritten: 0,
            events: VecDeque::new(),
            totals: Counts::default(),
            interfaces: BTreeMap::new(),
            send_warnings: BTreeMap::new(),
        })))
    }
}

impl Telemetry {
    pub fn begin(&self, interfaces: impl Iterator<Item = String>) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("DHCP relay telemetry lock poisoned"))?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("DHCP relay generation exhausted"))?;
        state.since = Some(crate::worker::now());
        state.totals = Counts::default();
        state.interfaces = interfaces.map(|name| (name, Counts::default())).collect();
        state.send_warnings.clear();
        Ok(())
    }

    pub fn pending(&self, counts: BTreeMap<String, usize>) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("DHCP relay telemetry lock poisoned"))?;
        state.totals.pending = counts.values().sum();
        for (name, value) in &mut state.interfaces {
            value.pending = counts.get(name).copied().unwrap_or(0);
        }
        Ok(())
    }

    pub fn track(&self, interface: &str, add: bool) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("DHCP relay telemetry lock poisoned"))?;
        let counts = state
            .interfaces
            .get_mut(interface)
            .ok_or_else(|| anyhow!("unknown DHCP relay counter interface"))?;
        if add {
            counts.pending += 1;
            state.totals.pending += 1;
        } else {
            ensure!(counts.pending > 0, "DHCP relay pending counter underflow");
            counts.pending -= 1;
            state.totals.pending -= 1;
        }
        Ok(())
    }

    pub fn record(
        &self,
        interface: Option<&str>,
        action: Action,
        reason: &str,
        packet: &[u8],
        peer: Option<SocketAddr>,
    ) -> Result<()> {
        self.record_detail(interface, action, reason, packet, peer, "")
    }

    pub fn record_detail(
        &self,
        interface: Option<&str>,
        action: Action,
        reason: &str,
        packet: &[u8],
        peer: Option<SocketAddr>,
        detail: &str,
    ) -> Result<()> {
        let metadata = super::dhcp::metadata(packet);
        self.record_metadata(interface, action, reason, metadata.as_ref(), peer, detail)
    }

    pub fn record_metadata(
        &self,
        interface: Option<&str>,
        action: Action,
        reason: &str,
        metadata: Option<&super::dhcp::Metadata>,
        peer: Option<SocketAddr>,
        detail: &str,
    ) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("DHCP relay telemetry lock poisoned"))?;
        state.totals.record(action, reason);
        if let Some(counts) = interface.and_then(|name| state.interfaces.get_mut(name)) {
            counts.record(action, reason);
        }
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("DHCP relay log sequence exhausted"))?;
        let sequence = state.sequence;
        let generation = state.generation;
        let warn = if matches!(action, Action::SendError) {
            let key = (interface.map(str::to_owned), reason.to_owned());
            if state
                .send_warnings
                .get(&key)
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(30))
            {
                state.send_warnings.insert(key, Instant::now());
                true
            } else {
                false
            }
        } else {
            false
        };
        let detail: String = detail.chars().take(512).collect();
        let event = json!({
            "sequence":sequence.to_string(), "generation":generation.to_string(),
            "timestamp":crate::worker::now(), "interface":interface,
            "event":action.name(), "reason":reason.chars().take(512).collect::<String>(), "peer":peer,
            "detail": detail,
            "message_type":metadata.map(|m|m.message_type),
            "transaction_id":metadata.map(|m|&m.transaction_id),
            "client_mac":metadata.map(|m|&m.client_mac),
            "client_address":metadata.map(|m|m.client_address),
            "offered_address":metadata.map(|m|m.offered_address),
            "relay_address":metadata.map(|m|m.relay_address),
            "broadcast":metadata.map(|m|m.broadcast),
            "hops":metadata.map(|m|m.hops),
        });
        if state.events.len() == CAPACITY {
            state.events.pop_front();
            state.overwritten = state.overwritten.saturating_add(1);
        }
        state.events.push_back(event);
        drop(state);
        if warn {
            tracing::warn!(
                interface = interface.unwrap_or("-"),
                peer = ?peer,
                stage = reason,
                error = %detail,
                transaction_id = metadata.map(|m|m.transaction_id.as_str()),
                "DHCP relay send failed; continuing other packets and destinations"
            );
        }
        Ok(())
    }

    pub fn statistics(&self) -> Result<Value> {
        let state = self
            .0
            .lock()
            .map_err(|_| anyhow!("DHCP relay telemetry lock poisoned"))?;
        Ok(json!({
            "epoch":state.epoch, "generation":state.generation.to_string(),
            "counters_since":state.since, "collected_at":crate::worker::now(),
            "totals":state.totals.value(),
            "interfaces":state.interfaces.iter().map(|(name,counts)| json!({"interface":name,"counters":counts.value()})).collect::<Vec<_>>(),
            "log_capacity":CAPACITY,"log_overwritten":state.overwritten.to_string()
        }))
    }

    pub fn log(&self, query: &DHCPRelayLogQuery) -> Result<Value> {
        let state = self
            .0
            .lock()
            .map_err(|_| anyhow!("DHCP relay telemetry lock poisoned"))?;
        let reset = query
            .cursor
            .as_ref()
            .is_some_and(|(epoch, _)| epoch != &state.epoch);
        let after = query
            .cursor
            .as_ref()
            .filter(|_| !reset)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        ensure!(
            after <= state.sequence,
            "DHCP relay cursor is ahead of the log"
        );
        let oldest = state
            .events
            .front()
            .and_then(|event| event["sequence"].as_str())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(state.sequence.saturating_add(1));
        let gap = query.cursor.is_some() && !reset && after < oldest.saturating_sub(1);
        let mut events = Vec::new();
        let mut scanned = after;
        let mut has_more = false;
        for event in &state.events {
            let sequence: u64 = event["sequence"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid relay event sequence"))?
                .parse()?;
            if sequence <= after {
                continue;
            }
            if query
                .interface
                .as_ref()
                .is_some_and(|name| event["interface"] != *name)
            {
                scanned = sequence;
                continue;
            }
            if events.len() == query.limit {
                has_more = true;
                break;
            }
            scanned = sequence;
            events.push(event.clone());
        }
        if !has_more {
            scanned = state.sequence;
        }
        Ok(json!({"epoch":state.epoch,"events":events,
            "next_cursor":format!("{}:{scanned}",state.epoch),
            "reset":reset,"gap":gap,"has_more":has_more,
            "capacity":CAPACITY,"overwritten":state.overwritten.to_string()}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_expiry_details_are_retained_without_logging_payloads() {
        let telemetry = Telemetry::default();
        telemetry.begin(["lan".into()].into_iter()).unwrap();
        let metadata = super::super::dhcp::Metadata {
            message_type: 3,
            transaction_id: "0000002a".into(),
            client_mac: "02:00:00:00:00:01".into(),
            client_address: "192.0.2.20".parse().unwrap(),
            offered_address: "0.0.0.0".parse().unwrap(),
            relay_address: "192.0.2.1".parse().unwrap(),
            broadcast: true,
            hops: 1,
        };
        telemetry
            .record_metadata(
                Some("lan"),
                Action::Expired,
                "tracking_timeout",
                Some(&metadata),
                None,
                &"x".repeat(600),
            )
            .unwrap();
        telemetry
            .record(None, Action::WorkerStart, "", &[], None)
            .unwrap();
        let page = telemetry
            .log(&DHCPRelayLogQuery::parse("").unwrap())
            .unwrap();
        let event = &page["events"][0];
        assert_eq!(event["transaction_id"], "0000002a");
        assert_eq!(event["client_mac"], "02:00:00:00:00:01");
        assert_eq!(event["client_address"], "192.0.2.20");
        assert_eq!(event["offered_address"], "0.0.0.0");
        assert_eq!(event["relay_address"], "192.0.2.1");
        assert_eq!(event["broadcast"], true);
        assert_eq!(event["hops"], 1);
        assert_eq!(event["detail"].as_str().unwrap().len(), 512);
        assert!(event.get("payload").is_none());
        for field in [
            "client_address",
            "offered_address",
            "relay_address",
            "broadcast",
            "hops",
        ] {
            assert!(page["events"][1][field].is_null());
        }
        assert_eq!(page["events"][1]["detail"], "");
    }

    #[test]
    fn send_warning_throttling_does_not_drop_api_events_or_counters() {
        let telemetry = Telemetry::default();
        telemetry.begin(["lan".into()].into_iter()).unwrap();
        let key = (Some("lan".into()), "to_server".into());
        telemetry
            .record_detail(
                Some("lan"),
                Action::SendError,
                "to_server",
                &[],
                None,
                "synthetic route failure",
            )
            .unwrap();
        let first = telemetry.0.lock().unwrap().send_warnings[&key];
        for _ in 0..3 {
            telemetry
                .record_detail(
                    Some("lan"),
                    Action::SendError,
                    "to_server",
                    &[],
                    None,
                    "synthetic route failure",
                )
                .unwrap();
        }
        assert_eq!(telemetry.0.lock().unwrap().send_warnings[&key], first);
        telemetry
            .0
            .lock()
            .unwrap()
            .send_warnings
            .insert(key.clone(), Instant::now() - Duration::from_secs(31));
        telemetry
            .record_detail(
                Some("lan"),
                Action::SendError,
                "to_server",
                &[],
                None,
                "synthetic route failure",
            )
            .unwrap();
        assert!(telemetry.0.lock().unwrap().send_warnings[&key] >= first);
        assert_eq!(
            telemetry.statistics().unwrap()["totals"]["send_errors"],
            "5"
        );
        assert_eq!(
            telemetry
                .log(&DHCPRelayLogQuery::parse("").unwrap())
                .unwrap()["events"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        telemetry.begin(["lan".into()].into_iter()).unwrap();
        assert!(telemetry.0.lock().unwrap().send_warnings.is_empty());
    }

    #[test]
    fn relay_log_is_bounded_and_reports_cursor_gaps_resets_and_filters() {
        let telemetry = Telemetry::default();
        telemetry
            .begin(["lan".into(), "guest".into()].into_iter())
            .unwrap();
        let initial = telemetry
            .log(&DHCPRelayLogQuery::parse("").unwrap())
            .unwrap();
        let epoch = initial["epoch"].as_str().unwrap();
        assert!(
            telemetry
                .log(&DHCPRelayLogQuery::parse(&format!("cursor={epoch}:1")).unwrap())
                .is_err()
        );
        for _ in 0..CAPACITY + 3 {
            telemetry
                .record(Some("lan"), Action::Rejected, "invalid_packet", &[], None)
                .unwrap();
        }
        let first = telemetry
            .log(
                &DHCPRelayLogQuery::parse(&format!(
                    "cursor={}&limit=2",
                    initial["next_cursor"].as_str().unwrap()
                ))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(first["events"].as_array().unwrap().len(), 2);
        assert_eq!(first["gap"], true);
        assert_eq!(first["overwritten"], "3");
        assert_eq!(first["has_more"], true);
        let filtered = telemetry
            .log(&DHCPRelayLogQuery::parse("interface=guest").unwrap())
            .unwrap();
        assert_eq!(filtered["events"], json!([]));
        assert_eq!(filtered["has_more"], false);
        let reset = Telemetry::default()
            .log(
                &DHCPRelayLogQuery::parse(&format!(
                    "cursor={}",
                    first["next_cursor"].as_str().unwrap()
                ))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(reset["reset"], true);
        let stats = telemetry.statistics().unwrap();
        assert_eq!(
            stats["totals"]["packets_rejected"],
            (CAPACITY + 3).to_string()
        );
        telemetry.begin(["lan".into()].into_iter()).unwrap();
        assert_eq!(
            telemetry.statistics().unwrap()["totals"]["packets_rejected"],
            "0"
        );
        assert_eq!(telemetry.statistics().unwrap()["generation"], "2");
        assert_eq!(
            telemetry
                .log(&DHCPRelayLogQuery::parse("").unwrap())
                .unwrap()["events"]
                .as_array()
                .unwrap()
                .len(),
            100
        );
    }

    #[test]
    fn relay_totals_include_unattributed_packets_and_pending_is_a_gauge() {
        let telemetry = Telemetry::default();
        telemetry.begin(["lan".into()].into_iter()).unwrap();
        telemetry
            .record(None, Action::Rejected, "unmatched_reply", &[], None)
            .unwrap();
        telemetry
            .record(Some("lan"), Action::ToServer, "", &[], None)
            .unwrap();
        telemetry
            .pending(BTreeMap::from([("lan".into(), 2)]))
            .unwrap();
        let stats = telemetry.statistics().unwrap();
        assert_eq!(stats["totals"]["packets_rejected"], "1");
        assert_eq!(stats["interfaces"][0]["counters"]["packets_rejected"], "0");
        assert_eq!(stats["totals"]["pending_transactions"], "2");
        assert_eq!(
            stats["interfaces"][0]["counters"]["requests_forwarded"],
            "1"
        );
    }

    #[test]
    fn relay_telemetry_supports_concurrent_polling_and_worker_restart_shutdown() {
        let telemetry = Telemetry::default();
        let factory = telemetry.clone();
        let mut worker =
            crate::worker::Worker::start("relay-test".into(), None, json!({}), move || {
                factory.begin(["lan".into()].into_iter())?;
                let telemetry = factory.clone();
                Ok(Box::new(move |ctx| {
                    telemetry.track("lan", true)?;
                    telemetry.record(Some("lan"), Action::Request, "", &[], None)?;
                    while !ctx.wait(std::time::Duration::from_millis(1)) {
                        telemetry.record(Some("lan"), Action::ToServer, "", &[], None)?;
                    }
                    telemetry.pending(Default::default())?;
                    Ok(())
                }))
            })
            .unwrap();
        let epoch = telemetry.statistics().unwrap()["epoch"].clone();
        for _ in 0..100 {
            let result = telemetry
                .log(&DHCPRelayLogQuery::parse("limit=1").unwrap())
                .unwrap();
            assert!(result["events"].as_array().unwrap().len() <= 1);
        }
        worker.restart().unwrap();
        worker.shutdown().unwrap();
        let stats = telemetry.statistics().unwrap();
        assert_eq!(stats["epoch"], epoch);
        assert_eq!(stats["generation"], "2");
        assert_eq!(stats["totals"]["pending_transactions"], "0");
    }
}
