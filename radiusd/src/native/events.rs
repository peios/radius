use crate::driver::{Event, Output, Reason};
use peios::{
    event::{self, EventPolicy, Tier},
    msgpack::Writer,
    security::Sid,
};
use radius_core::Reply;
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

pub struct Sink {
    pub sockets: Vec<UdpSocket>,
    pub policy: EventPolicy,
    pub actor: Sid,
    last_warning: Option<Instant>,
    discarded: u64,
    last_discard_report: Instant,
}
impl Sink {
    pub fn new(sockets: Vec<UdpSocket>, actor: Sid) -> peios::Result<Self> {
        Ok(Self {
            sockets,
            policy: EventPolicy::open()?,
            actor,
            last_warning: None,
            discarded: 0,
            last_discard_report: Instant::now(),
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
        let kind = "radiusd.exchange.attempted";
        if !matches!(self.policy.enabled(kind, Tier::Standard), Ok(true)) {
            return;
        }
        let mut w = Writer::new();
        w.write_map(3 + u32::from(e.username.is_some()));
        w.write_str("subject")
            .write_map(1)
            .write_str("token")
            .write_map(1)
            .write_str("sid")
            .write_bin(self.actor.as_bytes());
        if let Some(username) = e.username {
            w.write_str("source")
                .write_map(1)
                .write_str("radiusd")
                .write_map(1)
                .write_str("username")
                .write_str(username);
        }
        w.write_str("object")
            .write_map(1 + u32::from(e.sid.is_some()));
        w.write_str("radiusd")
            .write_map(3 + u32::from(e.canonical.is_some()));
        w.write_str("attempt")
            .write_map(1)
            .write_str("guid")
            .write_bin(e.id);
        w.write_str("client")
            .write_map(1)
            .write_str("id")
            .write_uint(e.client);
        w.write_str("network")
            .write_map(1)
            .write_str("id")
            .write_uint(e.network);
        if let Some(name) = e.canonical {
            w.write_str("canonical-name").write_str(name);
        }
        if let Some(sid) = e.sid {
            w.write_str("account")
                .write_map(1)
                .write_str("sid")
                .write_bin(sid);
        }
        let success = e.reason == Reason::Granted;
        w.write_str("outcome")
            .write_map(if success { 1 } else { 2 })
            .write_str("success")
            .write_bool(success);
        if !success {
            w.write_str("reason").write_str(e.reason.name());
        }
        self.submit(kind, &w);
    }
}
