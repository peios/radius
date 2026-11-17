//! Reproducible host ledger qualification, without network or real identities.
use radius_accounting::{
    model::{Observation, Settings},
    wire::{self, Attribute, Request},
    worker::{self, Handle},
};
use std::{
    collections::VecDeque,
    path::PathBuf,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let directory = PathBuf::from(args.get(1).ok_or("supply a new output directory")?);
    let count: usize = args.get(2).ok_or("supply report count")?.parse()?;
    if !(100..=100000).contains(&count) {
        return Err("count must be 100 through 100000".into());
    }
    std::fs::create_dir(&directory)?;
    let settings = Settings {
        enabled: true,
        batch_ms: 10,
        batch_count: 256,
        ..Default::default()
    };
    let handle = Handle::start(directory.join("ledger.db"), settings.clone())?;
    worker::wait(handle.configure(settings.clone(), vec![])?)?;
    let secret = b"load-fixture-only-secret";
    let stamp = (worker::now_ms() / 1000) as u32;
    let start = Instant::now();
    let mut pending = VecDeque::new();
    let mut latencies = Vec::new();
    for n in 0..count {
        let attrs = [
            Attribute::integer(40, if n < 100 { 1 } else { 3 }),
            Attribute {
                kind: 44,
                value: ((n % 100) as u32).to_be_bytes().to_vec(),
            },
            Attribute {
                kind: 32,
                value: b"load-nas".to_vec(),
            },
            Attribute::integer(55, stamp + (n / 100) as u32),
            Attribute::integer(42, (n / 100) as u32 * 1000),
        ];
        let packet = wire::request(n as u8, &attrs, secret, true)?;
        let parsed = Request::parse(&packet, secret, true)?;
        let observation = Observation::new(
            &parsed,
            "fixture".into(),
            "127.0.0.1".parse()?,
            i64::from(stamp + (n / 100) as u32) * 1000,
        )?;
        loop {
            match handle.record(observation.clone(), None) {
                Ok(rx) => {
                    pending.push_back((Instant::now(), rx));
                    break;
                }
                Err(radius_accounting::Error::Limit) => {
                    if let Some((at, rx)) = pending.pop_front() {
                        worker::wait(rx)?;
                        latencies.push(at.elapsed().as_millis() as u64);
                    } else {
                        std::thread::yield_now();
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    while let Some((at, rx)) = pending.pop_front() {
        worker::wait(rx)?;
        latencies.push(at.elapsed().as_millis() as u64);
    }
    let elapsed = start.elapsed();
    let status = handle.snapshot();
    handle.stop()?.recv_timeout(Duration::from_secs(5))?;
    let store = radius_accounting::store::Store::open(&directory.join("ledger.db"), settings)?;
    let health = store.health()?;
    assert_eq!(health.observations, count as u64);
    assert_eq!(health.sessions, 100);
    latencies.sort_unstable();
    println!(
        "{}",
        serde_json::json!({"reports":count,"sessions":health.sessions,"elapsed_ms":elapsed.as_millis(),"reports_per_second":count as f64/elapsed.as_secs_f64(),"completion_p50_ms":latencies[count/2],"completion_p95_ms":latencies[count*95/100],"completion_p99_ms":latencies[count*99/100],"durable_batches":status.batches,"database_bytes_after_reopen":health.database_bytes,"failed":status.failed,"build":"debug","workload":"100 unresolved sessions, no principal budgets, pipeline through bounded owner"})
    );
    Ok(())
}
