//! Best-effort diagnostic emission: bounded work and cardinality, no disk I/O.
use super::{event, Sink, Tier, Writer};
use radius_management::diagnostics::{hex, Record, Settings, ATTEMPT, SEQUENCE, STAGE};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

type DropBucket = (u64, Option<(SocketAddr, Option<String>)>);
pub(super) struct State {
    pub settings: Settings,
    window: Instant,
    ordinary: u32,
    summaries: u32,
    reported: Instant,
    pub emitted: u64,
    pub failed: u64,
    pub suppressed: u64,
    pub disabled: u64,
    drops: BTreeMap<(usize, &'static str), DropBucket>,
    samples: u32,
}
impl Default for State {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            window: Instant::now(),
            ordinary: 0,
            summaries: 0,
            reported: Instant::now() - Duration::from_secs(3600),
            emitted: 0,
            failed: 0,
            suppressed: 0,
            disabled: 0,
            drops: BTreeMap::new(),
            samples: 0,
        }
    }
}
impl State {
    fn admit(&mut self, summary: bool) -> bool {
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.ordinary = 0;
            self.summaries = 0;
        }
        if summary && self.summaries < self.settings.get("SummaryReserve") {
            self.summaries += 1;
            return true;
        }
        if self.ordinary < self.settings.get("EventsPerSecond") {
            self.ordinary += 1;
            return true;
        }
        self.suppressed = self.suppressed.saturating_add(1);
        false
    }
}
fn bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() || text.len() > 136 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}
fn put(root: &mut Map<String, Value>, path: &str, value: Value) {
    if let Some((head, tail)) = path.split_once('.') {
        let child = root
            .entry(head.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = child {
            put(map, tail, value);
        }
    } else {
        root.insert(path.into(), value);
    }
}
fn write(w: &mut Writer, value: &Value, path: &str) {
    match value {
        Value::Object(values) => {
            w.write_map(values.len() as u32);
            for (key, value) in values {
                w.write_str(key);
                write(
                    w,
                    value,
                    &if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    },
                );
            }
        }
        Value::String(value) if path.ends_with(".guid") || path.ends_with(".sid") => {
            if let Some(bytes) = bytes(value) {
                w.write_bin(&bytes);
            } else {
                w.write_str(value);
            }
        }
        Value::String(value) => {
            w.write_str(value);
        }
        Value::Bool(value) => {
            w.write_bool(*value);
        }
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                w.write_uint(value);
            } else {
                w.write_int(value.as_i64().unwrap_or(0));
            }
        }
        _ => {
            w.write_nil();
        }
    }
}
fn encode(record: &Record) -> Option<Vec<u8>> {
    let mut root = Map::new();
    for (key, value) in record {
        put(&mut root, key, value.clone());
    }
    let mut writer = Writer::new();
    write(&mut writer, &Value::Object(root), "");
    writer.to_bytes().ok()
}

impl Sink {
    pub fn configure_diagnostics(&mut self, settings: Settings) {
        self.diagnostics.settings = settings;
    }
    pub(super) fn diagnostic_record(&mut self, kind: &str, record: &Record, summary: bool) {
        if !self.diagnostics.admit(summary) {
            return;
        }
        if !matches!(self.policy.enabled(kind, Tier::Standard), Ok(true)) {
            self.diagnostics.disabled = self.diagnostics.disabled.saturating_add(1);
            return;
        }
        let mut record = record.clone();
        record.insert(
            "subject.token.sid".into(),
            hex(self.actor.as_bytes()).into(),
        );
        if record.iter().any(|(key, value)| {
            use radius_management::diagnostics::{field_type, FieldType::*};
            !match field_type(key) {
                Some(Text) => value.as_str().is_some(),
                Some(Bytes) => value.as_str().and_then(bytes).is_some(),
                Some(Unsigned) => value.as_u64().is_some(),
                Some(Bool) => value.as_bool().is_some(),
                None => false,
            }
        }) {
            self.diagnostics.failed = self.diagnostics.failed.saturating_add(1);
            return;
        }
        let max = self.diagnostics.settings.get("MaxEventBytes") as usize;
        let mut encoded = encode(&record);
        if summary && encoded.as_ref().is_some_and(|v| v.len() > max) {
            record.retain(|key, _| {
                key == ATTEMPT
                    || key == SEQUENCE
                    || key == STAGE
                    || key.starts_with("outcome.")
                    || key == "subject.token.sid"
                    || key == "object.radiusd.client.id"
                    || key == "object.radiusd.network.id"
                    || key == "object.radiusd.method"
                    || key == "object.radiusd.last-stage"
                    || key == "object.radiusd.elapsed-ms"
            });
            record.insert("object.radiusd.diagnostics.truncated".into(), true.into());
            encoded = encode(&record);
        }
        let ok = encoded
            .filter(|v| v.len() <= max)
            .is_some_and(|bytes| event::emit(kind, &bytes).is_ok());
        if ok {
            self.diagnostics.emitted = self.diagnostics.emitted.saturating_add(1);
        } else {
            self.diagnostics.failed = self.diagnostics.failed.saturating_add(1);
            self.warning("a diagnostic event could not be emitted");
        }
    }
    pub(super) fn diagnostic_drop(
        &mut self,
        reason: &'static str,
        listener: usize,
        peer: SocketAddr,
        client: Option<&str>,
    ) {
        // Native listener count and the closed reason vocabulary bound keys.
        if listener >= 64 {
            return;
        }
        let bucket = self
            .diagnostics
            .drops
            .entry((listener, reason))
            .or_insert((0, None));
        bucket.0 = bucket.0.saturating_add(1);
        if self.diagnostics.samples < self.diagnostics.settings.get("DropSamples") {
            bucket.1 = Some((peer, client.map(str::to_owned)));
            self.diagnostics.samples += 1;
        }
    }
    pub fn flush_diagnostics(&mut self) {
        if self.diagnostics.reported.elapsed()
            < Duration::from_secs(u64::from(self.diagnostics.settings.get("ReportSeconds")))
        {
            return;
        }
        self.diagnostics.reported = Instant::now();
        let dropped = std::mem::take(&mut self.diagnostics.drops);
        self.diagnostics.samples = 0;
        for ((listener, reason), (count, sample)) in dropped {
            let mut record: Record = [
                (
                    "object.radiusd.listener-index".into(),
                    (listener as u64).into(),
                ),
                ("object.radiusd.drops.count".into(), count.into()),
                ("outcome.reason".into(), reason.into()),
                ("outcome.success".into(), false.into()),
            ]
            .into();
            if let Some((peer, client)) = sample {
                record.insert("source.address".into(), peer.ip().to_string().into());
                if let Some(client) = client {
                    record.insert(
                        "object.radiusd.client.configuration-id".into(),
                        client.into(),
                    );
                }
            }
            self.diagnostic_record("radiusd.request.discarded", &record, false);
        }
        let record: Record = [
            (
                "object.radiusd.diagnostics.emitted".into(),
                self.diagnostics.emitted.into(),
            ),
            (
                "object.radiusd.diagnostics.failed".into(),
                self.diagnostics.failed.into(),
            ),
            (
                "object.radiusd.diagnostics.suppressed".into(),
                self.diagnostics.suppressed.into(),
            ),
            (
                "object.radiusd.diagnostics.disabled".into(),
                self.diagnostics.disabled.into(),
            ),
            (
                "object.radiusd.diagnostics.report-seconds".into(),
                self.diagnostics.settings.get("ReportSeconds").into(),
            ),
        ]
        .into();
        self.diagnostic_record("radiusd.diagnostics.reported", &record, true);
    }
}
