use radius_accounting::{
    model::Settings,
    worker::{self, Handle},
};
use radius_core::Limits;
use radius_qualification::{
    campaign,
    load::{self, Options},
    protocol::{self, Authority, Capture, SyntheticBackend, Tls},
    Scratch,
};
use radiusd::driver::Driver;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    time::{Duration, Instant},
};

#[test]
fn successful_tls_load_accounts_for_every_completion_and_bounds_peers() {
    let report = load::authentication(Options {
        requests: 24,
        clients: 3,
        concurrency: 6,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(report.completed, 24);
    assert_eq!(report.rejected, 0);
    assert_eq!(report.latency.samples, 24);
    assert!(report.max_pending <= 6 && report.recovered);
}

#[test]
fn full_authentication_tables_reject_bursts_and_recover() {
    let report = load::authentication(Options {
        requests: 100,
        clients: 2,
        concurrency: 32,
        attempts: 4,
        per_client: 2,
        allow_overload: true,
        ..Default::default()
    })
    .unwrap();
    assert!(report.completed > 0 && report.rejected > 0);
    assert_eq!(report.completed + report.rejected, 100);
    assert!(report.recovered);
}

#[test]
fn durable_load_receipts_survive_owner_stop_and_reopen() {
    let report = load::accounting(
        Options {
            requests: 48,
            clients: 4,
            concurrency: 16,
            queue: 32,
            batch: 8,
            batch_ms: 2,
            ..Default::default()
        },
        &std::env::temp_dir(),
    )
    .unwrap();
    assert_eq!(report.completed, 48);
    assert_eq!(report.details["retained"]["observations"], 48);
    assert!(report.recovered);
}

#[test]
fn production_coordinator_never_accepts_failed_or_stalled_required_services() {
    let tls = Tls::new();
    for mode in [
        Authority::Failed,
        Authority::Stalled,
        Authority::AccountingFailed,
        Authority::AccountingStalled,
        Authority::Ready,
    ] {
        let mut peer = tls.peer();
        let config = Arc::new(protocol::config(&tls, 1, Limits::default()));
        let mut driver = Driver::new(config, SyntheticBackend(mode)).unwrap();
        // Model an event sink that cannot retain evidence. Admission must still
        // depend on authority/accounting, not whether event delivery succeeded.
        let mut output = Capture {
            lose_events: true,
            ..Default::default()
        };
        let now = Instant::now();
        let mut packet = peer.initial();
        let mut accepted = false;
        for _ in 0..100 {
            driver.receive(now, 0, protocol::address(0, 0), &packet, &mut output);
            driver.tick(now, &mut output);
            let Some((_, reply)) = output.replies.pop_front() else {
                break;
            };
            if reply[0] == 2 {
                accepted = true;
            }
            match peer.respond(&reply).unwrap() {
                Some(next) => packet = next,
                None => break,
            }
        }
        assert_eq!(accepted, matches!(mode, Authority::Ready));
        driver.tick(now + Duration::from_secs(200), &mut output);
        assert_eq!(driver.pending(), 0);
        assert!(output.events.is_empty());
    }
}

#[test]
fn accounting_queue_enforces_its_limit_while_storage_is_unavailable() {
    let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
    let blocked = Arc::new(Barrier::new(2));
    let entered = Arc::new(Barrier::new(2));
    let a = blocked.clone();
    let b = entered.clone();
    let ledger = Handle::start_verified(
        scratch.0.join("ledger.db"),
        Settings {
            queue_count: 4,
            batch_count: 2,
            batch_ms: 1,
            ..Default::default()
        },
        Arc::new(move || {
            b.wait();
            a.wait();
            Ok(())
        }),
    )
    .unwrap();
    entered.wait();
    let mut receipts = Vec::new();
    for i in 0..4 {
        receipts.push(
            ledger
                .record(protocol::observation(i, 1, worker::now_ms()), None)
                .unwrap(),
        );
    }
    assert!(matches!(
        ledger.record(protocol::observation(5, 1, worker::now_ms()), None),
        Err(radius_accounting::Error::Limit)
    ));
    blocked.wait();
    for receipt in receipts {
        worker::wait(receipt).unwrap();
    }
    worker::wait(
        ledger
            .record(protocol::observation(6, 1, worker::now_ms()), None)
            .unwrap(),
    )
    .unwrap();
    ledger
        .stop()
        .unwrap()
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
}

#[test]
fn accounting_owner_recovers_after_its_authority_check_becomes_available() {
    let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
    let available = Arc::new(AtomicBool::new(false));
    let gate = available.clone();
    let ledger = Handle::start_verified(
        scratch.0.join("ledger.db"),
        Settings {
            batch_ms: 1,
            batch_count: 1,
            ..Default::default()
        },
        Arc::new(move || {
            if gate.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(radius_accounting::Error::Configuration(
                    "synthetic-authority-unavailable".into(),
                ))
            }
        }),
    )
    .unwrap();
    assert!(worker::wait(
        ledger
            .record(protocol::observation(0, 1, worker::now_ms()), None)
            .unwrap()
    )
    .is_err());
    assert!(!ledger.snapshot().available);
    available.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ledger.snapshot().available && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ledger.snapshot().available);
    worker::wait(
        ledger
            .record(protocol::observation(1, 1, worker::now_ms()), None)
            .unwrap(),
    )
    .unwrap();
    ledger
        .stop()
        .unwrap()
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
}

#[test]
fn seeded_fuzz_campaigns_replay_on_stable_rust() {
    for input in [
        vec![],
        vec![0; 64],
        (0..=255).collect::<Vec<u8>>(),
        vec![255; 512],
    ] {
        campaign::packets(&input);
        campaign::engine_sequences(&input);
        campaign::driver_sequences(&input);
        campaign::ledger_sequences(&input);
        campaign::control_sequences(&input);
    }
}

#[test]
fn storage_write_sync_full_and_sigkill_failures_preserve_receipts() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_radius-qualify"))
        .arg("failures")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["recovered"], true);
    assert_eq!(report["power_loss"], false);
    assert_eq!(report["cases"].as_array().unwrap().len(), 20);
}
