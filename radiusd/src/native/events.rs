use crate::driver::{Event, Output};
mod diagnostics;
use peios::{
    event::{self, EventPolicy, Tier},
    msgpack::Writer,
    security::Sid,
};
use radius_core::Reply;
use std::{
    net::UdpSocket,
    os::{fd::AsFd, unix::net::UnixDatagram},
    time::{Duration, Instant},
};

pub struct Sink {
    diagnostics: diagnostics::State,
    pub sockets: Vec<UdpSocket>,
    pub policy: EventPolicy,
    pub actor: Sid,
    last_warning: Option<Instant>,
    discarded: u64,
    last_discard_report: Instant,
    last_accounting: Instant,
    accounting_health: Option<bool>,
    metrics: Option<UnixDatagram>,
}
impl Sink {
    pub fn new(sockets: Vec<UdpSocket>, actor: Sid) -> peios::Result<Self> {
        Ok(Self {
            diagnostics: diagnostics::State::default(),
            sockets,
            policy: EventPolicy::open()?,
            actor,
            last_warning: None,
            discarded: 0,
            last_discard_report: Instant::now(),
            last_accounting: Instant::now() - Duration::from_secs(10),
            accounting_health: None,
            metrics: None,
        })
    }
    pub fn warning(&mut self, message: &str) {
        if self
            .last_warning
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(5))
        {
            eprintln!("radiusd: {message}");
            self.last_warning = Some(Instant::now());
        }
    }
    pub fn configuration(&mut self, valid: bool) {
        let kind = "radiusd.configuration.loaded";
        if !matches!(self.policy.enabled(kind, Tier::Standard), Ok(true)) {
            return;
        }
        let mut w = Writer::new();
        w.write_map(3)
            .write_str("subject")
            .write_map(1)
            .write_str("token")
            .write_map(1)
            .write_str("sid")
            .write_bin(self.actor.as_bytes());
        w.write_str("config")
            .write_map(1)
            .write_str("root")
            .write_str(crate::config::ROOT);
        w.write_str("outcome")
            .write_map(if valid { 1 } else { 2 })
            .write_str("success")
            .write_bool(valid);
        if !valid {
            w.write_str("reason").write_str("invalid-or-unavailable");
        }
        self.submit(kind, &w);
    }
    /// Operational samples deliberately contain no user, station, NAS, policy,
    /// session, Class or principal labels. Exact usage remains in the ledger.
    pub fn accounting(&mut self, enabled: bool, status: &radius_accounting::worker::Status) {
        if self.last_accounting.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.last_accounting = Instant::now();
        let healthy = !enabled || status.available;
        if self.accounting_health != Some(healthy) {
            self.accounting_health = Some(healthy);
            let kind = "radiusd.accounting.health.changed";
            if matches!(self.policy.enabled(kind, Tier::Standard), Ok(true)) {
                let mut w = Writer::new();
                w.write_map(2)
                    .write_str("subject")
                    .write_map(1)
                    .write_str("token")
                    .write_map(1)
                    .write_str("sid")
                    .write_bin(self.actor.as_bytes());
                w.write_str("outcome")
                    .write_map(1)
                    .write_str("success")
                    .write_bool(healthy);
                self.submit(kind, &w);
            }
        }
        if self.metrics.is_none() {
            self.metrics = (|| -> peios::Result<_> {
                use peios::registry::{Data, Key, KeyAccess, OpenFlags};
                let key = Key::open(
                    None,
                    "Machine\\System\\eventd",
                    KeyAccess::QUERY_VALUE,
                    OpenFlags::empty(),
                )?;
                let value = key.query_value(b"MetricSocketPath", None)?;
                let Data::Sz(path) = Data::decode(value.ty, &value.data) else {
                    return Err(std::io::Error::other("invalid metric socket").into());
                };
                let socket = UnixDatagram::unbound()?;
                socket.set_nonblocking(true)?;
                peios::token::ImpersonationLevel::set_pass_token(socket.as_fd(), true)?;
                socket.connect(path)?;
                Ok(socket)
            })()
            .ok();
        }
        let samples = [
            ("enabled", "gauge", u64::from(enabled)),
            ("available", "gauge", u64::from(status.available)),
            ("committed", "counter", status.committed),
            ("duplicates", "counter", status.duplicate),
            ("failed", "counter", status.failed),
            ("admission_bypasses", "counter", status.admission_bypasses),
            ("batches", "counter", status.batches),
            (
                "commit_milliseconds",
                "gauge",
                status.last_commit_latency_ms,
            ),
        ];
        let mut w = Writer::new();
        w.write_array(samples.len() as u32);
        for (name, kind, value) in samples {
            w.write_map(3)
                .write_str("name")
                .write_str(&format!("radiusd.accounting.{name}"))
                .write_str("type")
                .write_str(kind)
                .write_str("value")
                .write_float(value as f64);
        }
        if let (Some(socket), Ok(bytes)) = (&self.metrics, w.to_bytes()) {
            if socket.send(&bytes).is_err() {
                self.metrics = None;
            }
        }
    }
    fn submit(&mut self, kind: &str, w: &Writer) {
        if w.to_bytes()
            .and_then(|bytes| event::emit(kind, &bytes))
            .is_err()
        {
            self.warning("an operational event could not be emitted");
        }
    }
}
impl Output for Sink {
    fn progress(&mut self, record: &radius_management::diagnostics::Record) {
        use radius_management::diagnostics::{stage_event, STAGE};
        let stage = record
            .get(STAGE)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let result = record
            .get("object.radiusd.progress.result")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if let Some(kind) = stage_event(stage, result) {
            self.diagnostic_record(kind, record, false);
        }
    }
    fn discarded_sample(
        &mut self,
        reason: &'static str,
        listener: usize,
        peer: std::net::SocketAddr,
        client: Option<&str>,
    ) {
        self.diagnostic_drop(reason, listener, peer, client);
        self.discarded();
    }
    fn policy_issue(&mut self, id: &[u8; 16], issue: &str) {
        let attempt = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        self.warning(&format!(
            "assignment refused for attempt {attempt}: {issue}"
        ));
    }
    fn discarded(&mut self) {
        self.discarded = self.discarded.saturating_add(1);
        if self.last_discard_report.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "radiusd: discarded {} unauthenticated, unbound, or invalid datagrams",
                self.discarded
            );
            self.discarded = 0;
            self.last_discard_report = Instant::now();
        }
    }
    fn send(&mut self, listener: usize, reply: &Reply) -> bool {
        self.sockets.get(listener).is_some_and(|socket| {
            socket
                .send_to(&reply.bytes, reply.peer)
                .is_ok_and(|n| n == reply.bytes.len())
        })
    }
    fn event(&mut self, e: Event<'_>) {
        use radius_management::diagnostics::{hex, ATTEMPT};
        let mut record = e.diagnostic;
        record.insert(ATTEMPT.into(), hex(e.id).into());
        record.insert("object.radiusd.client.id".into(), e.client.into());
        record.insert("object.radiusd.network.id".into(), e.network.into());
        if let Some(username) = e.username {
            record.insert("source.radiusd.username".into(), username.into());
        }
        if let Some(name) = e.canonical {
            record.insert("object.radiusd.canonical-name".into(), name.into());
        }
        if let Some(sid) = e.sid {
            record.insert("object.account.sid".into(), hex(sid).into());
        }
        self.diagnostic_record("radiusd.exchange.attempted", &record, true);
    }
}
