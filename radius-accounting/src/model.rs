use crate::{
    wire::{Attribute, Request},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation {
    pub client: String,
    pub policy: Option<String>,
    pub source: IpAddr,
    pub received_ms: i64,
    pub effective_ms: i64,
    pub status: u32,
    pub nas: Vec<u8>,
    pub nas_attributes: Vec<Attribute>,
    pub session: Option<Vec<u8>>,
    pub subsystem: Option<Vec<u8>>,
    pub username: Option<Vec<u8>>,
    pub station: Option<Vec<u8>>,
    pub called_station: Option<Vec<u8>>,
    pub classes: Vec<Vec<u8>>,
    pub tunnel: Option<Vec<u8>>,
    pub multi_session: Option<Vec<u8>>,
    pub link_count: Option<u32>,
    pub duration_seconds: Option<u32>,
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub input_packets: Option<u32>,
    pub output_packets: Option<u32>,
    pub terminate_cause: Option<u32>,
    pub event_timestamp: Option<u32>,
    pub packet_digest: Vec<u8>,
    pub semantic_digest: Vec<u8>,
    pub attributes: Vec<Attribute>,
    pub warnings: Vec<String>,
}
fn singleton(attrs: &[Attribute], kind: u8) -> Result<Option<&[u8]>> {
    let mut values = attrs.iter().filter(|a| a.kind == kind);
    let first = values.next();
    if values.next().is_some() {
        return Err(Error::Malformed);
    }
    Ok(first.map(|a| a.value.as_slice()))
}
pub fn integer(attrs: &[Attribute], kind: u8) -> Result<Option<u32>> {
    singleton(attrs, kind)?
        .map(|b| {
            b.try_into()
                .map(u32::from_be_bytes)
                .map_err(|_| Error::Malformed)
        })
        .transpose()
}
impl Observation {
    pub fn new(
        request: &Request,
        client: String,
        source: IpAddr,
        received_ms: i64,
    ) -> Result<Self> {
        Self::with_profile(request, client, source, received_ms, None)
    }
    pub fn with_profile(
        request: &Request,
        client: String,
        source: IpAddr,
        received_ms: i64,
        profile: Option<&crate::profile::Profile>,
    ) -> Result<Self> {
        let attrs = &request.attributes;
        let status = integer(attrs, 40)?.unwrap_or(0);
        let session = singleton(attrs, 44)?
            .filter(|b| !b.is_empty())
            .map(Vec::from);
        let nas_identifier = singleton(attrs, 32)?.filter(|b| !b.is_empty());
        let nas_ip = singleton(attrs, 4)?.filter(|b| b.len() == 4);
        let nas_v6 = singleton(attrs, 95)?.filter(|b| b.len() == 16);
        // A NAS identity is mandatory; actual source is retained separately.
        let (tag, value) = nas_identifier
            .map(|v| (32, v))
            .or_else(|| nas_v6.map(|v| (95, v)))
            .or_else(|| nas_ip.map(|v| (4, v)))
            .unwrap_or((0, &[]));
        let mut nas = if tag == 0 { Vec::new() } else { vec![tag] };
        nas.extend_from_slice(value);
        let event_timestamp = integer(attrs, 55)?;
        let delay = integer(attrs, 41)?.unwrap_or(0);
        let effective_ms = event_timestamp
            .map(|v| i64::from(v) * 1000)
            .unwrap_or_else(|| received_ms.saturating_sub(i64::from(delay) * 1000));
        let mut warnings = Vec::new();
        if event_timestamp.is_none() {
            warnings.push("estimated-event-time".into());
        }
        if effective_ms < 0 || effective_ms > received_ms.saturating_add(300_000) {
            warnings.push("unreliable-event-time".into());
        }
        let mut counter = |low, high| -> Result<Option<u64>> {
            let lo = integer(attrs, low)?;
            let hi = integer(attrs, high)?;
            if lo.is_some() && hi.is_none() {
                warnings.push(format!("counter-{low}-high-word-missing"));
            }
            Ok(lo.map(|v| u64::from(v) | (u64::from(hi.unwrap_or(0)) << 32)))
        };
        let input = counter(42, 52)?;
        let output = counter(43, 53)?;
        let mut result = Self {
            client,
            policy: None,
            source,
            received_ms,
            effective_ms,
            status,
            nas,
            nas_attributes: attrs
                .iter()
                .filter(|a| matches!(a.kind, 4 | 32 | 95))
                .cloned()
                .collect(),
            session,
            subsystem: singleton(attrs, 30)?.map(Vec::from),
            username: singleton(attrs, 1)?.map(Vec::from),
            station: singleton(attrs, 31)?.map(Vec::from),
            called_station: singleton(attrs, 30)?.map(Vec::from),
            classes: attrs
                .iter()
                .filter(|a| a.kind == 25)
                .map(|a| a.value.clone())
                .collect(),
            tunnel: singleton(attrs, 68)?.map(Vec::from),
            multi_session: singleton(attrs, 50)?.map(Vec::from),
            link_count: integer(attrs, 51)?,
            duration_seconds: integer(attrs, 46)?,
            input,
            output,
            input_packets: integer(attrs, 47)?,
            output_packets: integer(attrs, 48)?,
            terminate_cause: integer(attrs, 49)?,
            event_timestamp,
            packet_digest: request.packet_digest(),
            semantic_digest: request.semantic_digest(),
            attributes: attrs
                .iter()
                .filter(|a| !matches!(a.kind, 33 | 80))
                .cloned()
                .collect(),
            warnings,
        };
        if let Some(profile) = profile {
            profile.apply(&mut result)?;
        }
        if result.status == 0
            || result.nas.is_empty()
            || (!result.lifecycle() && result.session.as_ref().is_none_or(|s| s.is_empty()))
        {
            return Err(Error::Malformed);
        }
        Ok(result)
    }
    pub fn has_reliable_time(&self) -> bool {
        self.event_timestamp.is_some()
            && !self.warnings.iter().any(|w| w == "unreliable-event-time")
    }
    pub fn lifecycle(&self) -> bool {
        matches!(self.status, 7 | 8 | 18 | 19)
    }
    pub fn kind(&self) -> &'static str {
        match self.status {
            9..=11 => "tunnel",
            12..=14 => "tunnel-link",
            _ => "session",
        }
    }
    pub fn projection_key(&self) -> Option<Vec<u8>> {
        projection_key(
            self.kind(),
            self.session.as_deref()?,
            self.tunnel.as_deref(),
        )
    }
}
fn projection_key(kind: &str, session: &[u8], tunnel: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut key = Vec::new();
    key.extend_from_slice(&(kind.len() as u32).to_be_bytes());
    key.extend_from_slice(kind.as_bytes());
    if kind != "session" {
        let tunnel = tunnel.filter(|v| !v.is_empty())?;
        key.extend_from_slice(&(tunnel.len() as u32).to_be_bytes());
        key.extend_from_slice(tunnel);
    }
    key.extend_from_slice(session);
    Some(key)
}
pub fn same_station(a: &[u8], b: &[u8]) -> bool {
    fn mac(value: &[u8]) -> Option<Vec<u8>> {
        if value.len() == 6 {
            return Some(value.to_vec());
        }
        let hex: Vec<_> = value
            .iter()
            .copied()
            .filter(|b| !matches!(b, b':' | b'-' | b'.'))
            .collect();
        if hex.len() != 12 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        hex.as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                std::str::from_utf8(p)
                    .ok()
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect()
    }
    a == b || mac(a).zip(mac(b)).is_some_and(|(a, b)| a == b)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub reference: Vec<u8>,
    pub client: String,
    pub policy: String,
    pub sid: String,
    pub name: Option<String>,
    pub groups: Vec<String>,
    pub station: Option<Vec<u8>>,
    pub issued_ms: i64,
    pub expires_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub client: String,
    pub nas: Vec<u8>,
    pub source: IpAddr,
    pub policy: Option<String>,
    pub session: Vec<u8>,
    pub kind: String,
    pub tunnel: Option<Vec<u8>>,
    pub multi_session: Option<Vec<u8>>,
    pub link_count: Option<u32>,
    pub subsystem: Option<Vec<u8>>,
    pub sid: Option<String>,
    pub groups: Vec<String>,
    pub name: Option<String>,
    pub username: Option<Vec<u8>>,
    pub station: Option<Vec<u8>>,
    pub classes: Vec<Vec<u8>>,
    pub nas_attributes: Vec<Attribute>,
    pub state: State,
    pub start_ms: i64,
    pub last_ms: i64,
    pub last_received_ms: i64,
    pub end_ms: Option<i64>,
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub warnings: Vec<String>,
    pub revision: u64,
}
impl Session {
    pub fn projection_key(&self) -> Option<Vec<u8>> {
        projection_key(&self.kind, &self.session, self.tunnel.as_deref())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Active,
    Stale,
    Ended,
    InferredEnded,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub id: String,
    pub session: Option<String>,
    pub disposition: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub batch_ms: u64,
    pub batch_count: usize,
    pub batch_bytes: usize,
    pub queue_count: usize,
    pub max_database_bytes: u64,
    pub retry_horizon_seconds: u64,
    pub observation_retention_seconds: u64,
    pub summary_retention_seconds: u64,
    pub detail_interval_seconds: u64,
    pub stale_seconds: u64,
    pub expire_seconds: u64,
    pub reservation_seconds: u64,
    pub require_ma: bool,
    pub raw_capture: bool,
    pub raw_retention_seconds: u64,
    pub raw_max_bytes: u64,
    pub linked_views: bool,
    pub retain_names: bool,
    pub retain_attributes: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_ms: 1000,
            batch_count: 512,
            batch_bytes: 1 << 20,
            queue_count: 4096,
            max_database_bytes: 1 << 30,
            retry_horizon_seconds: 86400,
            observation_retention_seconds: 7 * 86400,
            summary_retention_seconds: 90 * 86400,
            detail_interval_seconds: 0,
            stale_seconds: 1800,
            expire_seconds: 86400,
            reservation_seconds: 120,
            require_ma: false,
            raw_capture: false,
            raw_retention_seconds: 3600,
            raw_max_bytes: 64 << 20,
            linked_views: false,
            retain_names: true,
            retain_attributes: true,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !(1..=5000).contains(&self.batch_ms)
            || !(1..=10000).contains(&self.batch_count)
            || !(4096..=64 << 20).contains(&self.batch_bytes)
            || !(1..=65536).contains(&self.queue_count)
            || self.batch_count > self.queue_count
            || self.max_database_bytes < 1 << 20
            || self.max_database_bytes > 1 << 50
            || self.retry_horizon_seconds == 0
            || self.retry_horizon_seconds > 30 * 86400
            || self.observation_retention_seconds < self.retry_horizon_seconds
            || self.summary_retention_seconds < self.observation_retention_seconds
            || self.summary_retention_seconds > 10 * 366 * 86400
            || self.stale_seconds < 60
            || self.expire_seconds < self.stale_seconds
            || self.expire_seconds > 10 * 366 * 86400
            || self.detail_interval_seconds > self.summary_retention_seconds
            || !(10..=3600).contains(&self.reservation_seconds)
            || self.raw_retention_seconds > 86400
            || self.raw_max_bytes > self.max_database_bytes / 2
            || (self.raw_capture && (!self.retain_names || !self.retain_attributes))
        {
            return Err(Error::Configuration(
                "invalid accounting bounds or retention dependency".into(),
            ));
        }
        Ok(())
    }
}
