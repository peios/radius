use radius_accounting::{
    model::*,
    quota::*,
    store::*,
    wire::{self, Attribute, Request},
};
const SECRET: &[u8] = b"accounting-test-only-secret";
const USER: &str = "S-1-5-21-1-2-3-1001";
const GROUP: &str = "S-1-5-21-1-2-3-2001";

#[test]
fn committed_but_unacknowledged_process_exit_recovers_as_a_retry() {
    const CHILD: &str = "RADIUS_ACCOUNTING_CRASH_PATH";
    if let Some(path) = std::env::var_os(CHILD) {
        let mut store = Store::open(std::path::Path::new(&path), Settings::default()).unwrap();
        store
            .record(&[observation(1, b"unacknowledged", 100)])
            .unwrap();
        // Bypass Store/Connection destructors after commit, before a reply.
        std::process::exit(71);
    }
    let directory =
        std::env::temp_dir().join(format!("radius-crash-{}", radius_accounting::id().unwrap()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("ledger.db");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "committed_but_unacknowledged_process_exit_recovers_as_a_retry",
        ])
        .env(CHILD, &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(71));
    let mut store = Store::open(&path, Settings::default()).unwrap();
    let receipt = store
        .record(&[observation(1, b"unacknowledged", 100)])
        .unwrap()
        .remove(0);
    assert!(receipt.disposition.starts_with("duplicate-"));
    assert_eq!(store.health().unwrap().observations, 1);
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn batch_failure_has_no_partial_receipts_or_interpretation() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let good = observation(1, b"atomic", 100);
    let mut invalid = good.clone();
    invalid.status = 9;
    invalid.tunnel = None;
    // A missing tunnel selector is retained as unresolved, not a failed batch.
    // Instead duplicate primary evidence IDs through an invalid Class grant
    // are not needed: use a hard SQLite size failure after a valid first row.
    invalid.semantic_digest = vec![82; 32];
    invalid.attributes = vec![Attribute {
        kind: 26,
        value: vec![1; 2 << 20],
    }];
    let settings = Settings {
        max_database_bytes: 1 << 20,
        raw_max_bytes: 0,
        ..Default::default()
    };
    store.configure(settings).unwrap();
    assert!(store.record(&[good, invalid]).is_err());
    assert_eq!(store.health().unwrap().observations, 0);
    assert_eq!(store.health().unwrap().sessions, 0);
}

#[test]
fn owner_recovers_without_losing_configured_limits() {
    use radius_accounting::worker::{self, Handle};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let directory = std::env::temp_dir().join(format!(
        "radius-worker-{}",
        radius_accounting::id().unwrap()
    ));
    std::fs::create_dir(&directory).unwrap();
    let available = Arc::new(AtomicBool::new(false));
    let check = available.clone();
    let settings = Settings {
        batch_ms: 100,
        ..Default::default()
    };
    let handle = Handle::start_verified(
        directory.join("ledger.db"),
        settings.clone(),
        Arc::new(move || {
            if check.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(std::io::Error::other("injected outage").into())
            }
        }),
    )
    .unwrap();
    assert!(worker::wait(
        handle
            .configure(
                settings,
                vec![budget("closed", USER, Dimension::Concurrent, 0)]
            )
            .unwrap()
    )
    .is_err());
    available.store(true, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !handle.snapshot().available && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(handle.snapshot().available);
    let now = worker::now_ms();
    let mut g = grant(95);
    g.issued_ms = now;
    g.expires_ms = now + 100000;
    assert!(
        matches!(worker::wait(handle.grant(g).unwrap()),Err(radius_accounting::Error::Configuration(e)) if e=="principal allowance exhausted")
    );
    handle
        .stop()
        .unwrap()
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn foreign_and_corrupt_databases_are_refused_without_replacement() {
    let directory = std::env::temp_dir().join(format!(
        "radius-schema-{}",
        radius_accounting::id().unwrap()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("ledger.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('preserve');",
    )
    .unwrap();
    drop(db);
    let before = std::fs::read(&path).unwrap();
    assert!(Store::open(&path, Settings::default()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"not a SQLite database").unwrap();
    assert!(Store::open(&path, Settings::default()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a SQLite database");
    std::fs::remove_dir_all(directory).unwrap();
}
fn attrs(status: u32, session: &[u8], time: u32) -> Vec<Attribute> {
    vec![
        Attribute::integer(40, status),
        Attribute {
            kind: 44,
            value: session.to_vec(),
        },
        Attribute {
            kind: 32,
            value: b"ap-one".to_vec(),
        },
        Attribute::integer(55, time),
    ]
}
fn observation(status: u32, session: &[u8], time: u32) -> Observation {
    let bytes = wire::request(1, &attrs(status, session, time), SECRET, true).unwrap();
    let request = Request::parse(&bytes, SECRET, true).unwrap();
    Observation::new(
        &request,
        "client".into(),
        "192.0.2.1".parse().unwrap(),
        i64::from(time) * 1000,
    )
    .unwrap()
}
fn grant(reference: u8) -> Grant {
    Grant {
        reference: vec![reference; 16],
        client: "client".into(),
        policy: "policy".into(),
        sid: USER.into(),
        name: Some("Jack".into()),
        groups: vec![GROUP.into(), GROUP.into()],
        station: None,
        issued_ms: 0,
        expires_ms: 100_000_000,
    }
}
fn budget(id: &str, principal: &str, dimension: Dimension, max: u64) -> Budget {
    Budget {
        id: id.into(),
        principal: principal.into(),
        policy: None,
        dimension,
        period: Period::Lifetime,
        maximum: max,
        disconnect: true,
    }
}
fn with_identity(mut o: Observation, g: &Grant) -> Observation {
    o.classes = vec![g.reference.clone()];
    o
}

#[test]
fn tunnel_reports_do_not_close_or_charge_the_parent_session() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(91);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[budget("time", USER, Dimension::TotalSessionTime, 999999)])
        .unwrap();
    let parent = store
        .record(&[with_identity(observation(1, b"same", 100), &g)])
        .unwrap()
        .remove(0);
    let mut tunnel = with_identity(observation(9, b"same", 101), &g);
    tunnel.tunnel = Some(b"tunnel-a".to_vec());
    let tunnel_id = store
        .record(&[tunnel.clone()])
        .unwrap()
        .remove(0)
        .session
        .unwrap();
    tunnel.status = 11;
    tunnel.effective_ms = 110000;
    tunnel.received_ms = 110000;
    tunnel.semantic_digest = vec![92; 32];
    store.record(&[tunnel]).unwrap();
    assert_ne!(parent.session.as_ref().unwrap(), &tunnel_id);
    assert_eq!(
        store.session(&tunnel_id).unwrap().unwrap().state,
        State::Ended
    );
    assert_eq!(
        store
            .session(parent.session.as_ref().unwrap())
            .unwrap()
            .unwrap()
            .state,
        State::Active
    );
    assert_eq!(store.balances(&g, 120000).unwrap()[0].used, 20000);
    store.rebuild().unwrap();
    assert_eq!(store.balances(&g, 120000).unwrap()[0].used, 20000);
}

#[test]
fn privacy_flags_remove_names_and_attribute_history_at_ingest() {
    let mut store = Store::memory(Settings {
        retain_names: false,
        retain_attributes: false,
        ..Default::default()
    })
    .unwrap();
    let g = grant(92);
    store.grant(&g, 0).unwrap();
    let mut o = with_identity(observation(1, b"private", 100), &g);
    o.username = Some(b"private-name".to_vec());
    let id = store.record(&[o]).unwrap().remove(0).session.unwrap();
    let row = store.session(&id).unwrap().unwrap();
    assert!(row.name.is_none() && row.username.is_none());
    let history = store.history(&id, 10).unwrap();
    assert!(history[0].username.is_none() && history[0].attributes.is_empty());
    store.rebuild().unwrap();
    assert!(store.session(&id).unwrap().unwrap().name.is_none());
}

#[test]
fn class_order_and_mac_format_do_not_change_verified_identity() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let mut old = grant(93);
    old.station = Some(b"AA:BB:CC:DD:EE:FF".to_vec());
    let mut new = old.clone();
    new.reference = vec![94; 16];
    new.issued_ms = 1000;
    new.groups = vec!["S-1-5-21-1-2-3-3333".into()];
    store.grant(&old, 0).unwrap();
    store.grant(&new, 1000).unwrap();
    let mut o = observation(1, b"class", 100);
    o.station = Some(b"aabb.ccdd.eeff".to_vec());
    o.classes = vec![
        new.reference.clone(),
        old.reference.clone(),
        b"foreign".to_vec(),
    ];
    let id = store.record(&[o]).unwrap().remove(0).session.unwrap();
    let row = store.session(&id).unwrap().unwrap();
    assert_eq!(row.sid.as_deref(), Some(USER));
    assert_eq!(row.groups, new.groups);
}

#[test]
fn class_cannot_rebind_a_report_to_a_different_configured_policy() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(96);
    store.grant(&g, 0).unwrap();
    let mut o = with_identity(observation(1, b"other-policy", 100), &g);
    o.policy = Some("other-policy".into());
    let id = store.record(&[o]).unwrap().remove(0).session.unwrap();
    let row = store.session(&id).unwrap().unwrap();
    assert_eq!(row.policy.as_deref(), Some("other-policy"));
    assert!(row.sid.is_none());
}

#[test]
fn full_database_rolls_back_and_reuses_retained_free_pages() {
    let settings = Settings {
        max_database_bytes: 1 << 20,
        raw_max_bytes: 0,
        retry_horizon_seconds: 1,
        observation_retention_seconds: 2,
        summary_retention_seconds: 3,
        ..Default::default()
    };
    let mut store = Store::memory(settings).unwrap();
    let mut full = false;
    for n in 0..2000u32 {
        let mut o = observation(2, &n.to_be_bytes(), 100);
        o.attributes.push(Attribute {
            kind: 26,
            value: vec![77; 2000],
        });
        if store.record(&[o]).is_err() {
            full = true;
            break;
        }
    }
    assert!(full, "fixture must reach SQLite's hard limit");
    let before = store.health().unwrap().observations;
    assert!(before > 0);
    store.maintain(200000).unwrap();
    assert_eq!(store.health().unwrap().observations, 0);
    store.record(&[observation(1, b"recovered", 200)]).unwrap();
}

#[test]
fn correction_survives_rebuild_without_reopening_session() {
    let mut store = Store::memory(Settings {
        stale_seconds: 60,
        expire_seconds: 120,
        ..Default::default()
    })
    .unwrap();
    let id = store
        .record(&[observation(1, b"correct", 100)])
        .unwrap()
        .remove(0)
        .session
        .unwrap();
    store.maintain(230000).unwrap();
    store
        .correct_end(Correction {
            session: id.clone(),
            actor: USER.into(),
            at_ms: 230000,
            end_ms: 150000,
            note: "observed disconnect".into(),
        })
        .unwrap();
    store.rebuild().unwrap();
    assert_eq!(store.session(&id).unwrap().unwrap().end_ms, Some(150000));
}

#[test]
fn rebuilding_retained_evidence_preserves_ids_usage_and_commands() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(7);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[
            budget("bytes", USER, Dimension::InputBytes, 9999),
            budget("time", GROUP, Dimension::ConnectedTime, 999999),
        ])
        .unwrap();
    let start = store
        .record(&[with_identity(observation(1, b"x", 100), &g)])
        .unwrap()
        .remove(0);
    let mut interim = with_identity(observation(3, b"x", 110), &g);
    interim.input = Some(1234);
    store.record(&[interim]).unwrap();
    store
        .enqueue_disconnect(start.session.as_ref().unwrap(), USER, 110000, "manual")
        .unwrap();
    let before = store.balances(&g, 120000).unwrap();
    let commands = store.commands().unwrap();
    store.rebuild().unwrap();
    store.rebuild().unwrap();
    assert_eq!(before, store.balances(&g, 120000).unwrap());
    assert!(store
        .session(start.session.as_ref().unwrap())
        .unwrap()
        .is_some());
    assert_eq!(commands[0].id, store.commands().unwrap()[0].id);
}
#[test]
fn retention_keeps_lifetime_allowances_after_personal_history_expires() {
    let settings = Settings {
        retry_horizon_seconds: 1,
        observation_retention_seconds: 2,
        summary_retention_seconds: 3,
        raw_max_bytes: 0,
        ..Default::default()
    };
    let mut store = Store::memory(settings).unwrap();
    let g = grant(8);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[
            budget("bytes", USER, Dimension::InputBytes, 9999),
            budget("time", USER, Dimension::TotalSessionTime, 999999),
        ])
        .unwrap();
    let start = store
        .record(&[with_identity(observation(1, b"x", 100), &g)])
        .unwrap()
        .remove(0);
    let mut stop = with_identity(observation(2, b"x", 110), &g);
    stop.input = Some(2345);
    store.record(&[stop]).unwrap();
    let before = store.balances(&g, 120000).unwrap();
    store.maintain(120000).unwrap();
    store.rebuild().unwrap();
    assert!(store
        .session(start.session.as_ref().unwrap())
        .unwrap()
        .is_none());
    assert_eq!(before, store.balances(&g, 120000).unwrap());
}
#[test]
fn rebuild_does_not_reopen_expired_sessions() {
    let mut store = Store::memory(Settings {
        stale_seconds: 60,
        expire_seconds: 120,
        ..Default::default()
    })
    .unwrap();
    let receipt = store
        .record(&[observation(1, b"x", 100)])
        .unwrap()
        .remove(0);
    store.maintain(230000).unwrap();
    store.rebuild().unwrap();
    let row = store
        .session(receipt.session.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(row.state, State::InferredEnded);
    assert_eq!(row.end_ms, Some(220000));
}
#[test]
fn reauthentication_changes_group_time_without_retroactively_changing_history() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let old = grant(9);
    let mut new = grant(10);
    new.groups = vec!["S-1-5-21-1-2-3-2002".into()];
    new.issued_ms = 110000;
    store.grant(&old, 0).unwrap();
    store.grant(&new, 110000).unwrap();
    store
        .replace_budgets(&[
            budget("old", GROUP, Dimension::TotalSessionTime, 999999),
            budget("new", &new.groups[0], Dimension::TotalSessionTime, 999999),
        ])
        .unwrap();
    store
        .record(&[with_identity(observation(1, b"x", 100), &old)])
        .unwrap();
    store
        .record(&[with_identity(observation(3, b"x", 120), &new)])
        .unwrap();
    assert_eq!(store.balances(&old, 130000).unwrap()[0].used, 10000);
    assert_eq!(store.balances(&new, 130000).unwrap()[0].used, 20000);
    let before = store.balances(&new, 130000).unwrap();
    store.rebuild().unwrap();
    assert_eq!(before, store.balances(&new, 130000).unwrap());
}
#[test]
fn counter_regression_never_refunds_or_double_charges() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(11);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[budget("bytes", USER, Dimension::InputBytes, 9999)])
        .unwrap();
    for (status, time, count) in [(1, 100, 100), (3, 110, 25), (3, 120, 120)] {
        let mut o = with_identity(observation(status, b"x", time), &g);
        o.input = Some(count);
        store.record(&[o]).unwrap();
    }
    assert_eq!(store.balances(&g, 130000).unwrap()[0].used, 120);
}
#[test]
fn vendor_mapping_can_supply_missing_session_and_nas_without_executable_code() {
    use radius_accounting::profile::*;
    let p = Profile {
        version: 1,
        name: "example".into(),
        rules: vec![
            Rule {
                key: Key {
                    vendor: 0,
                    kind: 100,
                },
                target: Target::Nas,
                encoding: Encoding::Bytes,
                replace: false,
                mapping: vec![],
            },
            Rule {
                key: Key {
                    vendor: 0,
                    kind: 101,
                },
                target: Target::Session,
                encoding: Encoding::Bytes,
                replace: false,
                mapping: vec![],
            },
        ],
        dictionary: vec![],
    };
    let attrs = vec![
        Attribute::integer(40, 1),
        Attribute {
            kind: 100,
            value: b"nas".to_vec(),
        },
        Attribute {
            kind: 101,
            value: b"session".to_vec(),
        },
    ];
    let request = Request::parse(
        &wire::request(1, &attrs, SECRET, false).unwrap(),
        SECRET,
        false,
    )
    .unwrap();
    assert!(Observation::new(&request, "c".into(), "127.0.0.1".parse().unwrap(), 100000).is_err());
    let mapped = Observation::with_profile(
        &request,
        "c".into(),
        "127.0.0.1".parse().unwrap(),
        100000,
        Some(&p),
    )
    .unwrap();
    assert_eq!(mapped.session.unwrap(), b"session");
    assert_eq!(mapped.nas, b"nas");
}
#[test]
fn quota_disconnect_does_not_fake_a_stop_or_repeat_terminal_commands() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(12);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[budget("time", USER, Dimension::ConnectedTime, 5000)])
        .unwrap();
    let r = store
        .record(&[with_identity(observation(1, b"x", 100), &g)])
        .unwrap()
        .remove(0);
    store.enforce(110000).unwrap();
    let mut commands = store.commands().unwrap();
    assert_eq!(commands.len(), 1);
    let id = commands[0].id.clone();
    commands[0].state = "acknowledged".into();
    store.command_result(&commands[0]).unwrap();
    store.enforce(120000).unwrap();
    assert!(store.commands().unwrap().is_empty());
    assert!(store
        .session(r.session.as_ref().unwrap())
        .unwrap()
        .unwrap()
        .end_ms
        .is_none());
    assert_eq!(
        store
            .enqueue_disconnect(
                r.session.as_ref().unwrap(),
                "radiusd",
                120000,
                "budget:time"
            )
            .unwrap()
            .id,
        id
    );
}

#[test]
fn packet_integrity_padding_and_optional_ma() {
    for ma in [false, true] {
        let bytes = wire::request(233, &attrs(1, b"opaque\0\xff", 100), SECRET, ma).unwrap();
        let request = Request::parse(&bytes, SECRET, ma).unwrap();
        assert_eq!(request.identifier, 233);
        assert!(Request::parse(&bytes, b"wrong", false).is_err());
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[1, 2, 3]);
        assert!(Request::parse(&padded, SECRET, false).is_ok());
        let mut broken = bytes;
        broken[20] ^= 1;
        assert!(Request::parse(&broken, SECRET, false).is_err());
        assert_eq!(request.response(SECRET).unwrap()[0], 5);
    }
    let bytes = wire::request(1, &attrs(1, b"x", 100), SECRET, false).unwrap();
    assert!(Request::parse(&bytes, SECRET, true).is_err());
}
#[test]
fn forbidden_credentials_and_duplicate_singletons_are_not_recorded() {
    let mut a = attrs(1, b"x", 100);
    a.push(Attribute {
        kind: 2,
        value: b"secret".to_vec(),
    });
    assert!(Request::parse(&wire::request(1, &a, SECRET, false).unwrap(), SECRET, false).is_err());
    let mut a = attrs(1, b"x", 100);
    a.push(Attribute::integer(40, 2));
    let request =
        Request::parse(&wire::request(1, &a, SECRET, false).unwrap(), SECRET, false).unwrap();
    assert!(Observation::new(&request, "c".into(), "127.0.0.1".parse().unwrap(), 100_000).is_err());
}
#[test]
fn retry_changes_id_delay_and_authenticator_without_new_usage() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let first = observation(1, b"x", 100);
    let receipt = store.record(&[first]).unwrap().remove(0);
    let mut a = attrs(1, b"x", 100);
    a.push(Attribute::integer(41, 10));
    let request =
        Request::parse(&wire::request(99, &a, SECRET, true).unwrap(), SECRET, true).unwrap();
    let second = Observation::new(
        &request,
        "client".into(),
        "192.0.2.1".parse().unwrap(),
        110_000,
    )
    .unwrap();
    let duplicate = store.record(&[second]).unwrap().remove(0);
    assert_eq!(receipt.id, duplicate.id);
    assert!(duplicate.disposition.starts_with("duplicate"));
    assert_eq!(store.health().unwrap().observations, 1);
}
#[test]
fn fresh_equal_counter_interim_is_not_collapsed() {
    let mut store = Store::memory(Settings::default()).unwrap();
    store.record(&[observation(1, b"x", 100)]).unwrap();
    for t in [110, 120] {
        let mut o = observation(3, b"x", t);
        o.input = Some(0);
        store.record(&[o]).unwrap();
    }
    assert_eq!(store.health().unwrap().observations, 3);
}
#[test]
fn unsigned_counter_totals_survive_full_range_and_duplicate_delivery() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(1);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[budget("data", USER, Dimension::InputBytes, u64::MAX)])
        .unwrap();
    store
        .record(&[with_identity(observation(1, b"x", 100), &g)])
        .unwrap();
    let mut o = with_identity(observation(3, b"x", 110), &g);
    o.input = Some(u64::MAX - 1);
    store.record(&[o.clone()]).unwrap();
    store.record(&[o]).unwrap();
    let b = store.balances(&g, 120_000).unwrap();
    assert_eq!(b[0].used, u64::MAX - 1);
    assert_eq!(b[0].remaining, 1);
}
#[test]
fn overlapping_time_budgets_charge_all_principals_without_adding_allowances() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let g = grant(1);
    store.grant(&g, 0).unwrap();
    store
        .replace_budgets(&[
            budget("sum", USER, Dimension::TotalSessionTime, 5 * 3_600_000),
            budget("union", USER, Dimension::ConnectedTime, 3_600_000),
            budget("group", GROUP, Dimension::TotalSessionTime, 10 * 3_600_000),
        ])
        .unwrap();
    for i in 0..3 {
        let mut o = with_identity(observation(1, &[i], 100), &g);
        o.packet_digest = vec![i];
        o.semantic_digest = vec![i];
        store.record(&[o]).unwrap();
    }
    let b = store.balances(&g, 3_700_000).unwrap();
    assert_eq!(
        b.iter().find(|b| b.budget.id == "sum").unwrap().used,
        3 * 3_600_000
    );
    assert_eq!(
        b.iter().find(|b| b.budget.id == "union").unwrap().used,
        3_600_000
    );
    assert_eq!(
        b.iter().find(|b| b.budget.id == "group").unwrap().used,
        3 * 3_600_000
    );
}
#[test]
fn concurrent_admissions_reserve_the_last_slot_atomically() {
    let mut store = Store::memory(Settings::default()).unwrap();
    store
        .replace_budgets(&[budget("slots", GROUP, Dimension::Concurrent, 1)])
        .unwrap();
    store.grant(&grant(1), 0).unwrap();
    assert!(store.grant(&grant(2), 0).is_err());
    store.grant(&grant(2), 121_000).unwrap();
}
#[test]
fn concurrent_limit_allows_reauthentication_without_reserving_another_slot() {
    let mut store = Store::memory(Settings::default()).unwrap();
    store
        .replace_budgets(&[
            budget("user-slot", USER, Dimension::Concurrent, 1),
            budget("group-slot", GROUP, Dimension::Concurrent, 1),
        ])
        .unwrap();
    let mut first = grant(101);
    first.station = Some(b"AA:BB:CC:DD:EE:FF".to_vec());
    store.grant(&first, 0).unwrap();
    let mut start = with_identity(observation(1, b"reauth", 100), &first);
    start.station = Some(b"aa-bb-cc-dd-ee-ff".to_vec());
    let id = store.record(&[start]).unwrap().remove(0).session.unwrap();

    let mut renewed = first.clone();
    renewed.reference = vec![102; 16];
    renewed.station = Some(b"aabb.ccdd.eeff".to_vec());
    renewed.issued_ms = 110000;
    assert!(store.grant(&renewed, 110000).is_ok());
    assert!(store.grant(&renewed, 110001).is_ok());
    assert!(store
        .balances(&first, 110001)
        .unwrap()
        .iter()
        .all(|b| b.used == 1));
    assert_eq!(store.enforce(110001).unwrap(), 0);

    for (n, change) in ["station", "client", "policy", "sid", "missing", "empty"]
        .into_iter()
        .enumerate()
    {
        let mut other = renewed.clone();
        other.reference = vec![110 + n as u8; 16];
        match change {
            "station" => other.station = Some(b"11:22:33:44:55:66".to_vec()),
            "client" => other.client = "other-client".into(),
            "policy" => other.policy = "other-policy".into(),
            "sid" => other.sid = "S-1-5-21-1-2-3-9999".into(),
            "missing" => other.station = None,
            "empty" => other.station = Some(Vec::new()),
            _ => unreachable!(),
        }
        assert!(store.grant(&other, 110001).is_err(), "{change}");
    }
    let mut update = with_identity(observation(3, b"reauth", 111), &renewed);
    update.station = first.station.clone();
    let updated = store.record(&[update]).unwrap().remove(0);
    assert_eq!(updated.session.as_ref(), Some(&id));
    let mut stop = with_identity(observation(2, b"reauth", 112), &renewed);
    stop.station = first.station.clone();
    store.record(&[stop]).unwrap();
    assert!(store
        .balances(&first, 112001)
        .unwrap()
        .iter()
        .all(|b| b.used == 0));
}

#[test]
fn reauthentication_reserves_new_group_capacity_without_borrowing_a_slot() {
    const NEW_GROUP: &str = "S-1-5-21-1-2-3-3001";
    let mut store = Store::memory(Settings::default()).unwrap();
    let mut first = grant(121);
    first.station = Some(b"AA:BB:CC:DD:EE:FF".to_vec());
    store.grant(&first, 0).unwrap();
    let mut start = with_identity(observation(1, b"member", 100), &first);
    start.station = first.station.clone();
    store.record(&[start]).unwrap();

    let mut other = grant(122);
    other.sid = "S-1-5-21-1-2-3-9999".into();
    other.groups = vec![NEW_GROUP.into()];
    other.station = Some(b"11:22:33:44:55:66".to_vec());
    store.grant(&other, 0).unwrap();
    let mut start = with_identity(observation(1, b"other", 100), &other);
    start.station = other.station.clone();
    store.record(&[start]).unwrap();
    store
        .replace_budgets(&[budget("new-group", NEW_GROUP, Dimension::Concurrent, 1)])
        .unwrap();

    let mut renewed = first.clone();
    renewed.reference = vec![123; 16];
    renewed.groups.push(NEW_GROUP.into());
    renewed.issued_ms = 110000;
    assert!(store.grant(&renewed, 110000).is_err());
    let mut stop = with_identity(observation(2, b"other", 111), &other);
    stop.station = other.station.clone();
    store.record(&[stop]).unwrap();
    store.grant(&renewed, 111000).unwrap();

    let query = Grant {
        reference: Vec::new(),
        ..renewed.clone()
    };
    assert_eq!(store.balances(&query, 111001).unwrap()[0].used, 1);
    other.reference = vec![124; 16];
    other.issued_ms = 111000;
    assert!(store.grant(&other, 111001).is_err());
    let mut update = with_identity(observation(3, b"member", 112), &renewed);
    update.station = first.station;
    store.record(&[update]).unwrap();
    assert_eq!(store.balances(&query, 112001).unwrap()[0].used, 1);
    assert_eq!(store.enforce(112001).unwrap(), 0);
}
#[test]
fn stop_then_old_interim_cannot_reopen_session() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let r = store
        .record(&[observation(1, b"x", 100)])
        .unwrap()
        .remove(0);
    store.record(&[observation(2, b"x", 120)]).unwrap();
    store.record(&[observation(3, b"x", 110)]).unwrap();
    let s = store.session(r.session.as_ref().unwrap()).unwrap().unwrap();
    assert_eq!(s.state, State::Ended);
    assert_eq!(s.end_ms, Some(120_000));
}
#[test]
fn delayed_restart_does_not_close_newer_sessions() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let old = store
        .record(&[observation(1, b"old", 100)])
        .unwrap()
        .remove(0);
    let new = store
        .record(&[observation(1, b"new", 300)])
        .unwrap()
        .remove(0);
    store.record(&[observation(7, b"", 200)]).unwrap();
    assert_eq!(
        store
            .session(old.session.as_ref().unwrap())
            .unwrap()
            .unwrap()
            .state,
        State::InferredEnded
    );
    assert_eq!(
        store
            .session(new.session.as_ref().unwrap())
            .unwrap()
            .unwrap()
            .state,
        State::Active
    );
}
#[test]
fn row_authorization_precedes_pagination_and_revision_is_checked() {
    let mut store = Store::memory(Settings::default()).unwrap();
    for i in 0..5 {
        store.record(&[observation(1, &[i], 100)]).unwrap();
    }
    let filter = Filter {
        limit: 2,
        ..Default::default()
    };
    let page = store.page(&filter, |_| false).unwrap();
    assert!(page.sessions.is_empty());
    assert!(page.next.is_none());
    let page = store.page(&filter, |_| true).unwrap();
    assert_eq!(page.sessions.len(), 2);
    assert!(page.next.is_some());
    store.record(&[observation(1, b"new", 100)]).unwrap();
    assert!(store
        .page(
            &Filter {
                revision: Some(page.revision),
                ..filter
            },
            |_| true
        )
        .is_err());
}
#[test]
fn durable_reopen_and_single_owner() {
    let dir = std::env::temp_dir().join(format!(
        "radius-accounting-test-{}",
        radius_accounting::id().unwrap()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("ledger.db");
    let mut store = Store::open(&path, Settings::default()).unwrap();
    assert!(Store::open(&path, Settings::default()).is_err());
    let r = store
        .record(&[observation(1, b"x", 100)])
        .unwrap()
        .remove(0);
    drop(store);
    let mut store = Store::open(&path, Settings::default()).unwrap();
    assert!(store
        .session(r.session.as_ref().unwrap())
        .unwrap()
        .is_some());
    assert_eq!(
        store.record(&[observation(1, b"x", 100)]).unwrap()[0].id,
        r.id
    );
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn interval_union_is_clipped_and_order_independent() {
    assert_eq!(
        interval_usage([(20, 40), (0, 30), (30, 50), (90, 80)], 10, 45),
        (55, 35)
    );
}
#[test]
fn utc_month_and_week_boundaries() {
    assert_eq!(
        Period::Month.bounds(1_709_208_000_000).unwrap(),
        (1_706_745_600_000, 1_709_251_200_000)
    );
    let (a, b) = Period::Week.bounds(1_709_208_000_000).unwrap();
    assert_eq!(b - a, 7 * 86_400_000);
}
