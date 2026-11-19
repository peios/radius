//! Bounded, caller-authorized diagnostic projections shared by CLI and GXWI.
//! Inputs are eventd query results, never privileged daemon snapshots.
use crate::model::{Stored, Value};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use std::collections::BTreeMap;

/// Registry setting, default, inclusive lower bound, inclusive upper bound.
pub const KNOBS: &[(&str, u32, u32, u32)] = &[
    ("DiagnosticsMaxStages", 32, 4, 256),
    ("DiagnosticsMaxEventBytes", 8192, 1024, 32768),
    ("DiagnosticsEventsPerSecond", 200, 1, 100000),
    ("DiagnosticsSummaryReserve", 50, 1, 100000),
    ("DiagnosticsDropSamples", 8, 0, 1024),
    ("DiagnosticsReportSeconds", 5, 1, 3600),
    ("DiagnosticsLookbackSeconds", 900, 1, 2592000),
    ("DiagnosticsMaxLookbackSeconds", 86400, 1, 2592000),
    ("DiagnosticsMaxRecords", 4096, 16, 65536),
    ("DiagnosticsMaxAttempts", 200, 1, 10000),
    ("DiagnosticsMaxViewBytes", 4194304, 65536, 67108864),
    ("DiagnosticsBackfillSeconds", 60, 1, 86400),
    ("DiagnosticsReconnectSeconds", 3, 1, 300),
    ("DiagnosticsStreamSeconds", 60, 5, 3600),
];
#[derive(Clone, Debug)]
pub struct Settings(BTreeMap<String, u32>);
impl Default for Settings {
    fn default() -> Self {
        Self(KNOBS.iter().map(|(k, v, _, _)| ((*k).into(), *v)).collect())
    }
}
impl Settings {
    pub fn read(stored: &Stored) -> Result<Self, String> {
        let mut result = Self::default();
        for (name, _, min, max) in KNOBS {
            if let Some(value) = stored.settings.get(*name) {
                match value {
                    Value::Number(value) if (min..=max).contains(&value) => {
                        result.0.insert((*name).into(), *value);
                    }
                    _ => return Err(format!("{name}: expected DWORD {min}..{max}")),
                }
            }
        }
        if result.get("LookbackSeconds") > result.get("MaxLookbackSeconds") {
            return Err("diagnostic lookback exceeds maximum".into());
        }
        Ok(result)
    }
    pub fn get(&self, suffix: &str) -> u32 {
        self.0[&format!("Diagnostics{suffix}")]
    }
}

/// Only already-authorized, flattened event fields belong here.
pub type Record = BTreeMap<String, Json>;
pub const ATTEMPT: &str = "object.radiusd.attempt.guid";
pub const OPERATION: &str = "object.authentication.operation.guid";
pub const SEQUENCE: &str = "object.radiusd.progress.sequence";
pub const STAGE: &str = "object.radiusd.progress.stage";
/// Specific observed actions, following PGSS's lifecycle event naming.
pub const STAGE_EVENTS: &[(&str, &str, &str)] = &[
    ("started", "*", "radiusd.exchange.started"),
    ("method", "offered", "radiusd.exchange.method.offered"),
    ("method", "selected", "radiusd.exchange.method.selected"),
    ("tls", "*", "radiusd.exchange.tls.negotiated"),
    (
        "credentials",
        "pending",
        "radiusd.exchange.credential.requested",
    ),
    ("credentials", "*", "radiusd.exchange.credential.verified"),
    ("permissions", "*", "radiusd.exchange.permission.checked"),
    ("assignment", "*", "radiusd.exchange.assignment.evaluated"),
    (
        "accounting",
        "pending",
        "radiusd.exchange.accounting.requested",
    ),
    ("accounting", "*", "radiusd.exchange.accounting.checked"),
    ("protocol", "*", "radiusd.exchange.protocol.checked"),
];
pub fn stage_event(stage: &str, result: &str) -> Option<&'static str> {
    STAGE_EVENTS
        .iter()
        .find(|(s, r, _)| *s == stage && (*r == result || *r == "*"))
        .map(|(_, _, event)| *event)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Bytes,
    Unsigned,
    Bool,
}
pub fn field_type(key: &str) -> Option<FieldType> {
    use FieldType::*;
    Some(match key {
        ATTEMPT | OPERATION | "subject.token.sid" | "object.account.sid" => Bytes,
        STAGE
        | "source.address"
        | "source.radiusd.username"
        | "source.radiusd.station"
        | "object.radiusd.listener"
        | "object.radiusd.canonical-name"
        | "object.radiusd.method"
        | "object.radiusd.last-stage"
        | "object.radiusd.client.configuration-id"
        | "object.radiusd.client.name"
        | "object.radiusd.network.name"
        | "object.radiusd.authentication-profile.name"
        | "object.radiusd.assignment.profile.name"
        | "object.radiusd.assignment.rule.name"
        | "object.radiusd.network.configuration-id"
        | "object.radiusd.authentication-profile.id"
        | "object.radiusd.config.fingerprint"
        | "object.radiusd.config.saved-fingerprint"
        | "object.radiusd.assignment.rule.id"
        | "object.radiusd.assignment.profile.id"
        | "object.radiusd.assignment.fingerprint"
        | "object.radiusd.reply"
        | "object.radiusd.progress.result"
        | "outcome.reason"
        | "outcome.detail" => Text,
        SEQUENCE
        | "object.radiusd.client.id"
        | "object.radiusd.network.id"
        | "object.radiusd.listener-index"
        | "object.radiusd.elapsed-ms"
        | "object.radiusd.retransmissions"
        | "object.radiusd.assignment.vlan"
        | "object.radiusd.drops.count"
        | "object.radiusd.diagnostics.emitted"
        | "object.radiusd.diagnostics.failed"
        | "object.radiusd.diagnostics.suppressed"
        | "object.radiusd.diagnostics.disabled"
        | "object.radiusd.diagnostics.report-seconds" => Unsigned,
        "outcome.success" | "object.radiusd.diagnostics.truncated" => Bool,
        _ => return None,
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn record_digest(record: &Record) -> [u8; 32] {
    ring::digest::digest(
        &ring::digest::SHA256,
        &serde_json::to_vec(record).expect("event fields serialize"),
    )
    .as_ref()
    .try_into()
    .expect("SHA256 length")
}
/// Approximate wall-clock age of a readable event timestamp (Unix nanoseconds).
pub fn age(record: &Record) -> String {
    let Some(time) = record.get("event.time").and_then(Json::as_u64) else {
        return "Time unavailable".into();
    };
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return "Time unavailable".into();
    };
    if u128::from(time) > now.as_nanos() {
        return "Timestamp is in the future".into();
    }
    let seconds =
        ((now.as_nanos() - u128::from(time)) / 1_000_000_000).min(u128::from(u64::MAX)) as u64;
    for (unit, size) in [("days", 86400), ("hours", 3600), ("minutes", 60)] {
        if seconds >= size {
            return format!("{} {unit} ago", seconds / size);
        }
    }
    format!("{seconds} seconds ago")
}
pub fn parse_id(text: &str) -> Option<[u8; 16]> {
    let value: String = text
        .trim_matches(['{', '}'])
        .chars()
        .filter(|c| *c != '-')
        .collect();
    if value.len() != 32 || !value.is_ascii() {
        return None;
    }
    let mut id = [0; 16];
    for (i, v) in id.iter_mut().enumerate() {
        *v = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Filter {
    pub seconds: Option<u32>,
    pub network: Option<String>,
    pub client: Option<String>,
    pub username: Option<String>,
    pub station: Option<String>,
    pub attempt: Option<String>,
}
impl Filter {
    pub fn validate(&self, settings: &Settings) -> Result<(), String> {
        if self
            .seconds
            .is_some_and(|n| n == 0 || n > settings.get("MaxLookbackSeconds"))
        {
            return Err("diagnostic lookback outside configured bounds".into());
        }
        if self
            .attempt
            .as_ref()
            .is_some_and(|id| parse_id(id).is_none())
        {
            return Err("expected a 16-byte attempt identifier".into());
        }
        if [&self.network, &self.client, &self.username, &self.station]
            .into_iter()
            .flatten()
            .any(|s| s.len() > 256)
        {
            return Err("diagnostic filter exceeds 256 bytes".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Attempt {
    pub id: String,
    /// Readable fields only. Missing fields are not filled from configuration.
    pub summary: Record,
    pub stages: Vec<Record>,
    pub outcome_available: bool,
    pub possible_gap: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct View {
    pub attempts: Vec<Attempt>,
    pub drops: Vec<Record>,
    pub collection: Vec<Record>,
    pub uncorrelated: usize,
    pub truncated: bool,
    pub possible_gap: bool,
    pub following: bool,
    pub status: String,
}
impl View {
    /// Filter reconstructed attempts using only fields returned by eventd.
    /// This preserves earlier anonymous stages of a later identified attempt.
    pub fn filtered(mut self, filter: &Filter) -> Self {
        self.attempts.retain(|a| {
            [
                ("object.radiusd.network.configuration-id", &filter.network),
                ("object.radiusd.client.configuration-id", &filter.client),
                ("source.radiusd.username", &filter.username),
                ("source.radiusd.station", &filter.station),
            ]
            .into_iter()
            .all(|(field, wanted)| {
                wanted.as_ref().is_none_or(|wanted| {
                    a.summary.get(field).and_then(Json::as_str) == Some(wanted)
                })
            })
        });
        if let Some(wanted) = &filter.client {
            self.drops.retain(|r| {
                r.get("object.radiusd.client.configuration-id")
                    .and_then(Json::as_str)
                    == Some(wanted)
            });
        }
        self
    }
}

/// A bounded reconstruction of evidence; missing outcomes never become failures.
pub struct Projection {
    records: BTreeMap<String, Record>,
    bytes: usize,
    settings: Settings,
    pub truncated: bool,
    pub possible_gap: bool,
}
impl Projection {
    pub fn new(settings: Settings) -> Self {
        Self {
            records: BTreeMap::new(),
            bytes: 0,
            settings,
            truncated: false,
            possible_gap: false,
        }
    }
    fn key(record: &Record) -> String {
        // Kernel-assigned per-CPU sequence plus boot identity distinguishes
        // otherwise identical reports and supports overlap replay deduplication.
        let header = ["event.boot.guid", "event.cpu", "event.sequence"];
        if header.iter().all(|field| record.contains_key(*field)) {
            let identity: BTreeMap<_, _> = header
                .into_iter()
                .map(|field| (field, &record[field]))
                .collect();
            return serde_json::to_string(&identity).expect("event fields serialize");
        }
        // A stage's sequence is per attempt; include emitter identity so an
        // unrelated emitter cannot be silently merged into the same timeline.
        let mut identity = Map::new();
        for field in [
            "event.boot.guid",
            "emitter.process.guid",
            "event.type",
            ATTEMPT,
            SEQUENCE,
        ] {
            if let Some(value) = record.get(field) {
                identity.insert(field.into(), value.clone());
            }
        }
        if !record.contains_key(ATTEMPT) || !record.contains_key(SEQUENCE) {
            for (k, v) in record {
                identity.insert(k.clone(), v.clone());
            }
        }
        serde_json::to_string(&identity).expect("event fields serialize")
    }
    pub fn insert(&mut self, record: Record) {
        let key = Self::key(&record);
        if self.records.contains_key(&key) {
            return;
        }
        let size = serde_json::to_vec(&record)
            .expect("event fields serialize")
            .len()
            + key.len();
        if size > self.settings.get("MaxViewBytes") as usize {
            self.truncated = true;
            return;
        }
        while !self.records.is_empty()
            && (self.records.len() >= self.settings.get("MaxRecords") as usize
                || self.bytes + size > self.settings.get("MaxViewBytes") as usize)
        {
            // Retain the newest observed event times, not arbitrary map-key order.
            let victim = self
                .records
                .iter()
                .min_by_key(|(_, r)| event_time(r))
                .map(|(k, _)| k.clone())
                .unwrap();
            let old = self.records.remove(&victim).unwrap();
            self.bytes = self
                .bytes
                .saturating_sub(serde_json::to_vec(&old).unwrap().len() + victim.len());
            self.truncated = true;
        }
        self.bytes += size;
        self.records.insert(key, record);
    }
    pub fn view(&self, following: bool, status: impl Into<String>) -> View {
        let mut view = View {
            following,
            status: status.into(),
            truncated: self.truncated,
            possible_gap: self.possible_gap,
            ..Default::default()
        };
        let mut attempts: BTreeMap<String, Vec<Record>> = BTreeMap::new();
        for record in self.records.values() {
            view.truncated |= record
                .get("object.radiusd.diagnostics.truncated")
                .and_then(Json::as_bool)
                == Some(true);
            let kind = record
                .get("event.type")
                .and_then(Json::as_str)
                .unwrap_or("");
            if kind == "radiusd.request.discarded" {
                view.drops.push(record.clone());
            } else if kind == "radiusd.diagnostics.reported" {
                view.collection.push(record.clone());
            } else if let Some(id) = record.get(ATTEMPT).and_then(Json::as_str) {
                let emitter = record
                    .get("emitter.process.guid")
                    .map(Json::to_string)
                    .unwrap_or_default();
                attempts
                    .entry(format!("{emitter}:{id}"))
                    .or_default()
                    .push(record.clone());
            } else if kind.starts_with("radiusd.exchange.") || kind.is_empty() {
                view.uncorrelated += 1;
            }
        }
        for (_, mut records) in attempts {
            records.sort_by_key(|r| r.get(SEQUENCE).and_then(Json::as_u64).unwrap_or(u64::MAX));
            let mut summary = Record::new();
            let mut available = false;
            let mut gap = self.possible_gap;
            let mut expected = 1;
            for record in &records {
                if let Some(n) = record.get(SEQUENCE).and_then(Json::as_u64) {
                    if n != expected {
                        gap = true;
                    }
                    expected = n + 1;
                } else {
                    gap = true;
                }
                available |= record.get("event.type").and_then(Json::as_str)
                    == Some("radiusd.exchange.attempted")
                    && record.contains_key("outcome.success");
                for (k, v) in record {
                    summary.insert(k.clone(), v.clone());
                }
            }
            // A hidden sequence must not let a successful intermediate action
            // overwrite a final rejection. Terminal-only facts come from the
            // terminal record itself, including a still-valid authority link.
            if let Some(terminal) = records
                .iter()
                .filter(|r| {
                    r.get("event.type").and_then(Json::as_str) == Some("radiusd.exchange.attempted")
                })
                .max_by_key(|r| event_time(r))
            {
                for field in [
                    "outcome.success",
                    "outcome.reason",
                    "outcome.detail",
                    "object.radiusd.reply",
                    "object.radiusd.last-stage",
                    "object.radiusd.progress.result",
                    OPERATION,
                ] {
                    summary.remove(field);
                }
                for (key, value) in terminal {
                    summary.insert(key.clone(), value.clone());
                }
                available = terminal
                    .get("outcome.success")
                    .and_then(Json::as_bool)
                    .is_some();
            }
            let id = summary.get(ATTEMPT).and_then(Json::as_str).unwrap().into();
            view.attempts.push(Attempt {
                id,
                summary,
                stages: records,
                outcome_available: available,
                possible_gap: gap,
            });
        }
        view.attempts
            .sort_by_key(|a| std::cmp::Reverse(event_time(&a.summary)));
        if view.attempts.len() > self.settings.get("MaxAttempts") as usize {
            view.attempts
                .truncate(self.settings.get("MaxAttempts") as usize);
            view.truncated = true;
        }
        view.drops.sort_by_key(event_time);
        view.collection.sort_by_key(event_time);
        view
    }
}
fn event_time(r: &Record) -> i64 {
    r.get("event.time").and_then(Json::as_i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hidden_sequences_cannot_turn_a_final_refusal_into_an_accept_or_restore_a_missing_link() {
        let mut p = Projection::new(Settings::default());
        let mut final_record = stage(3, "radiusd.exchange.attempted");
        final_record.remove(SEQUENCE);
        final_record.insert("outcome.success".into(), false.into());
        final_record.insert("outcome.reason".into(), "permission-denied".into());
        p.insert(final_record);
        let mut early = stage(1, "radiusd.exchange.started");
        early.remove(SEQUENCE);
        early.insert("outcome.success".into(), true.into());
        early.insert(OPERATION.into(), hex(&[9; 16]).into());
        p.insert(early);
        let view = p.view(false, "");
        assert!(view.attempts[0].outcome_available);
        assert_eq!(view.attempts[0].summary["outcome.success"], false);
        assert_eq!(
            view.attempts[0].summary["outcome.reason"],
            "permission-denied"
        );
        assert!(!view.attempts[0].summary.contains_key(OPERATION));
        assert!(view.attempts[0].possible_gap);
    }
    #[test]
    fn kernel_sequence_distinguishes_identical_reports_but_deduplicates_replay() {
        let mut p = Projection::new(Settings::default());
        let mut report: Record = [
            ("event.type".into(), "radiusd.request.discarded".into()),
            ("event.boot.guid".into(), hex(&[9; 16]).into()),
            ("event.cpu".into(), 1.into()),
            ("event.sequence".into(), 42.into()),
        ]
        .into();
        p.insert(report.clone());
        p.insert(report.clone());
        report.insert("event.sequence".into(), 43.into());
        p.insert(report);
        assert_eq!(p.view(false, "").drops.len(), 2);
    }
    #[test]
    fn configured_record_and_attempt_bounds_do_not_alter_the_authentication_fingerprint() {
        let mut stored = Stored::default();
        stored
            .settings
            .insert("DiagnosticsMaxRecords".into(), Value::Number(16));
        stored
            .settings
            .insert("DiagnosticsMaxAttempts".into(), Value::Number(2));
        let mut projection = Projection::new(Settings::read(&stored).unwrap());
        for n in 1..100u64 {
            let mut record = stage(1, "radiusd.exchange.progressed");
            record.insert(ATTEMPT.into(), hex(&[n as u8; 16]).into());
            record.insert("event.time".into(), n.into());
            projection.insert(record);
        }
        let view = projection.view(false, "complete");
        assert_eq!(view.attempts.len(), 2);
        assert!(view.truncated);
        assert_eq!(view.attempts[0].id, hex(&[99; 16]));
        let mut changed = stored.clone();
        changed
            .settings
            .insert("DiagnosticsMaxRecords".into(), Value::Number(20));
        assert_ne!(changed.fingerprint(), stored.fingerprint());
        assert_eq!(
            changed.authentication_fingerprint(),
            stored.authentication_fingerprint()
        );
    }
    fn stage(seq: u64, kind: &str) -> Record {
        [
            (ATTEMPT.into(), Json::String(hex(&[7; 16]))),
            (SEQUENCE.into(), seq.into()),
            ("event.type".into(), kind.into()),
        ]
        .into()
    }
    #[test]
    fn replay_deduplicates_and_late_outcomes_complete_without_inventing_fields() {
        let mut p = Projection::new(Settings::default());
        p.insert(stage(1, "radiusd.exchange.progressed"));
        p.insert(stage(1, "radiusd.exchange.progressed"));
        assert_eq!(p.view(true, "following").attempts[0].stages.len(), 1);
        assert!(!p.view(false, "disconnected").attempts[0].outcome_available);
        let mut terminal = stage(3, "radiusd.exchange.attempted");
        terminal.insert("outcome.success".into(), true.into());
        p.insert(terminal);
        assert!(p.view(true, "following").attempts[0].possible_gap);
        p.insert(stage(2, "radiusd.exchange.progressed"));
        let v = p.view(true, "following");
        assert!(v.attempts[0].outcome_available);
        assert!(!v.attempts[0].possible_gap);
        assert!(!v.attempts[0].summary.contains_key("object.account.sid"));
    }
    #[test]
    fn hidden_correlation_fields_do_not_turn_into_synthetic_attempts() {
        let mut p = Projection::new(Settings::default());
        p.insert([("event.type".into(), "radiusd.exchange.progressed".into())].into());
        let v = p.view(false, "complete");
        assert!(v.attempts.is_empty());
        assert_eq!(v.uncorrelated, 1);
    }
}
