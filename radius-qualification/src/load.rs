//! Measured component workloads, not native authd or AP capacity claims.
use crate::{
    protocol::{self, Authority, Capture, SyntheticBackend, Tls, TtlsPeer},
    Result, Scratch,
};
use radius_accounting::{
    model::Settings,
    store::Store,
    worker::{self, Handle},
};
use radius_core::Limits;
use radiusd::driver::Driver;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        mpsc::{Receiver, TryRecvError},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Serialize)]
pub struct Options {
    pub requests: usize,
    pub clients: usize,
    pub concurrency: usize,
    pub attempts: usize,
    pub per_client: usize,
    pub queue: usize,
    pub batch: usize,
    pub batch_ms: u64,
    pub allow_overload: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            requests: 2048,
            clients: 16,
            concurrency: 64,
            attempts: 256,
            per_client: 32,
            queue: 4096,
            batch: 512,
            batch_ms: 1000,
            allow_overload: false,
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        if !(1..=200_000).contains(&self.requests)
            || !(1..=256).contains(&self.clients)
            || !(1..=4096).contains(&self.concurrency)
            || !(1..=65536).contains(&self.attempts)
            || !(1..=65536).contains(&self.per_client)
            || !(1..=65536).contains(&self.queue)
            || !(1..=10_000).contains(&self.batch)
            || self.batch > self.queue
            || !(1..=5000).contains(&self.batch_ms)
        {
            return Err("qualification options exceed bounded workload limits".into());
        }
        Ok(())
    }
}
#[derive(Serialize)]
pub struct Latency {
    pub samples: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}
pub fn latency(mut samples: Vec<Duration>) -> Latency {
    samples.sort_unstable();
    let at = |p: usize| {
        samples
            .get((samples.len().saturating_sub(1) * p) / 100)
            .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
    };
    Latency {
        samples: samples.len(),
        p50_ms: at(50),
        p95_ms: at(95),
        p99_ms: at(99),
        max_ms: at(100),
    }
}
#[derive(Serialize)]
pub struct Report {
    pub schema: u32,
    pub workload: &'static str,
    pub options: Options,
    pub elapsed_seconds: f64,
    pub offered: usize,
    pub completed: usize,
    pub rejected: usize,
    pub operations_per_second: f64,
    pub latency: Latency,
    pub max_pending: usize,
    pub recovered: bool,
    pub peak_rss_kib: Option<u64>,
    pub details: serde_json::Value,
}
fn peak_rss() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|s| s.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}
struct Exchange {
    peer: TtlsPeer,
    began: Instant,
    messages: usize,
}

pub fn authentication(options: Options) -> Result<Report> {
    options.validate()?;
    let tls = Tls::new();
    let limits = Limits {
        attempts: options.attempts,
        per_client: options.per_client,
        cached_replies: options.attempts.max(16),
        idle: Duration::from_secs(5),
        overall: Duration::from_secs(10),
        ..Default::default()
    };
    let config = Arc::new(protocol::config(&tls, options.clients, limits));
    let mut driver = Driver::new(config, SyntheticBackend(Authority::Ready))?;
    let mut out = Capture::default();
    let mut peers: BTreeMap<std::net::SocketAddr, Exchange> = BTreeMap::new();
    let mut times = Vec::new();
    let mut completed = 0;
    let mut rejected = 0;
    let mut issued = 0;
    let mut peak = 0;
    let began = Instant::now();
    while issued < options.requests || !peers.is_empty() {
        while issued < options.requests && peers.len() < options.concurrency {
            let address = protocol::address(issued % options.clients, issued);
            let peer = tls.peer();
            let mut packet = peer.initial();
            packet[4..12].copy_from_slice(&(issued as u64).to_be_bytes());
            protocol::resign(&mut packet);
            let started = Instant::now();
            let before = out.replies.len();
            driver.receive(Instant::now(), 0, address, &packet, &mut out);
            issued += 1;
            if out.replies.len() == before {
                rejected += 1;
                continue;
            }
            if peers
                .insert(
                    address,
                    Exchange {
                        peer,
                        began: started,
                        messages: 0,
                    },
                )
                .is_some()
            {
                return Err("synthetic peer collision".into());
            }
            peak = peak.max(peers.len());
        }
        driver.tick(Instant::now(), &mut out);
        // A bounded round-robin slice allows peers to overlap their TLS work.
        let count = out.replies.len();
        for _ in 0..count {
            let (address, reply) = out.replies.pop_front().unwrap();
            let Some(exchange) = peers.get_mut(&address) else {
                return Err("unmatched qualification reply".into());
            };
            exchange.messages += 1;
            if exchange.messages > 256 {
                return Err("unbounded authentication conversation".into());
            }
            if let Some(next) = exchange.peer.respond(&reply)? {
                driver.receive(Instant::now(), 0, address, &next, &mut out);
            } else {
                if reply[0] == 2 {
                    completed += 1;
                    times.push(exchange.began.elapsed());
                } else {
                    rejected += 1;
                }
                peers.remove(&address);
            }
        }
        if peers
            .values()
            .any(|p| p.began.elapsed() > Duration::from_secs(15))
        {
            return Err("authentication workload stalled".into());
        }
        if out.replies.is_empty() && !peers.is_empty() {
            std::thread::yield_now();
        }
    }
    let elapsed = began.elapsed().as_secs_f64();
    let recovery_time = Instant::now() + Duration::from_secs(20);
    driver.tick(recovery_time, &mut out);
    let drained = driver.pending() == 0;
    let mut peer = tls.peer();
    let mut packet = peer.initial();
    packet[4..12].copy_from_slice(&u64::MAX.to_be_bytes());
    protocol::resign(&mut packet);
    let address = protocol::address(0, 0);
    let mut accepted = false;
    for _ in 0..256 {
        driver.receive(recovery_time, 0, address, &packet, &mut out);
        driver.tick(recovery_time, &mut out);
        let Some((_, reply)) = out.replies.pop_front() else {
            break;
        };
        accepted |= reply[0] == 2;
        match peer.respond(&reply)? {
            Some(next) => packet = next,
            None => break,
        }
    }
    let recovered = drained && accepted && driver.pending() == 0;
    if completed + rejected != options.requests
        || !recovered
        || (!options.allow_overload && rejected != 0)
    {
        return Err("authentication workload conservation/admission check failed".into());
    }
    Ok(Report {
        schema: 1,
        workload: "in-process-ttls-pap-production-coordinator-mocked-authority",
        options,
        elapsed_seconds: elapsed,
        offered: issued,
        completed,
        rejected,
        operations_per_second: completed as f64 / elapsed.max(f64::EPSILON),
        latency: latency(times),
        max_pending: peak,
        recovered,
        peak_rss_kib: peak_rss(),
        details: serde_json::json!({"native_authd": false, "udp_transport": false, "policy": "explicit-default-assignment", "certificate": "ephemeral-self-signed", "backend": "fixed-synthetic-credentials", "recovery": "new-successful-conversation-after-drain", "max_pending_unit": "outstanding-synthetic-peers"}),
    })
}

type ReceiptWait = (
    Instant,
    Receiver<radius_accounting::Result<radius_accounting::model::Receipt>>,
);
pub fn accounting(options: Options, parent: &Path) -> Result<Report> {
    options.validate()?;
    let scratch = Scratch::new(parent)?;
    let path = scratch.0.join("ledger.db");
    let settings = Settings {
        enabled: true,
        batch_ms: options.batch_ms,
        batch_count: options.batch,
        queue_count: options.queue,
        max_database_bytes: 128 << 20,
        ..Default::default()
    };
    let ledger = Handle::start(path.clone(), settings.clone())?;
    let began = Instant::now();
    let mut issued = 0;
    let mut rejected = 0;
    let mut times = Vec::new();
    let mut ids = BTreeSet::new();
    let mut pending: Vec<ReceiptWait> = Vec::new();
    let mut peak = 0;
    while issued < options.requests || !pending.is_empty() {
        while issued < options.requests && pending.len() < options.concurrency {
            let started = Instant::now();
            let observation = protocol::observation(issued, options.clients, worker::now_ms());
            match ledger.record(observation, None) {
                Ok(receipt) => pending.push((started, receipt)),
                Err(radius_accounting::Error::Limit) => rejected += 1,
                Err(e) => return Err(e.into()),
            }
            issued += 1;
            peak = peak.max(pending.len());
        }
        let mut i = 0;
        while i < pending.len() {
            match pending[i].1.try_recv() {
                Ok(Ok(receipt)) => {
                    ids.insert(receipt.id);
                    times.push(pending[i].0.elapsed());
                    pending.swap_remove(i);
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(TryRecvError::Disconnected) => {
                    return Err("accounting owner disappeared".into())
                }
                Err(TryRecvError::Empty) => {
                    if pending[i].0.elapsed() > Duration::from_secs(30) {
                        return Err("accounting completion deadline exceeded".into());
                    }
                    i += 1;
                }
            }
        }
        if !pending.is_empty() {
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    let elapsed = began.elapsed().as_secs_f64();
    ledger.stop()?.recv_timeout(Duration::from_secs(5))?;
    let status = ledger.snapshot();
    drop(ledger);
    let reopened = Store::open(&path, settings)?;
    let health = reopened.health()?;
    let completed = times.len();
    let recovered = health.observations as usize == ids.len() && ids.len() == completed;
    if completed + rejected != options.requests
        || !recovered
        || (!options.allow_overload && rejected != 0)
    {
        return Err("accounting receipt/durability check failed".into());
    }
    Ok(Report {
        schema: 1,
        workload: "sqlite-wal-full-batched-owner",
        options,
        elapsed_seconds: elapsed,
        offered: issued,
        completed,
        rejected,
        operations_per_second: completed as f64 / elapsed.max(f64::EPSILON),
        latency: latency(times),
        max_pending: peak,
        recovered,
        peak_rss_kib: peak_rss(),
        details: serde_json::json!({"owner": status, "retained": health, "native_adapter": false, "storage": "temporary-database-on-selected-parent-filesystem", "arrival": "closed-loop-bounded-window", "records": "unique-session-starts", "max_pending_unit": "submitted-receipts-awaiting-collection", "recovery": "all-unique-receipts-retained-after-stop-and-reopen"}),
    })
}
