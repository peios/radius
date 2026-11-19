use super::*;

fn wire_command(store: &mut Store, session: &str, identifier: u8, timestamp: u32) -> Command {
    use radius_accounting::dynamic::*;
    let mut command = store
        .enqueue_dynamic(
            Intent {
                intent_key: String::new(),
                request_id: Some(radius_accounting::id().unwrap()),
                session: session.into(),
                actor: USER.into(),
                reason: "administrator".into(),
                action: Action::Disconnect,
                configuration: "a".repeat(64),
                desired: None,
                fallback: vec![],
            },
            i64::from(timestamp) * 1000,
        )
        .unwrap();
    let attrs = Profile {
        proxy_state_nonce: false,
        ..Default::default()
    }
    .attributes(
        Action::Disconnect,
        command.target.as_ref().unwrap(),
        None,
        i64::from(timestamp) * 1000,
    )
    .unwrap()
    .unwrap();
    command.packet =
        wire::dynamic_request(wire::DISCONNECT_REQUEST, identifier, &attrs, SECRET).unwrap();
    command.port = 3799;
    command.secret_fingerprint = vec![3; 32];
    command.state = "sent".into();
    command.attempts = 1;
    command.first_sent_ms = Some(i64::from(timestamp) * 1000);
    command
}

#[test]
fn durable_wire_allocation_survives_restart_rebuild_and_clock_rollback() {
    let directory = std::env::temp_dir().join(format!(
        "radius-wire-clock-{}",
        radius_accounting::id().unwrap()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("ledger.db");
    let mut store = Store::open(&path, Settings::default()).unwrap();
    let session = store.record(&[observation(1, b"wire-clock", 100)]).unwrap()[0]
        .session
        .clone()
        .unwrap();
    let mut first = wire_command(&mut store, &session, 0, 100);
    store.command_result(&first).unwrap();
    drop(store);
    let mut store = Store::open(&path, Settings::default()).unwrap();
    first.attempts += 1;
    store.command_result(&first).unwrap(); // Exact durable retransmission remains valid.
    let mut changed = first.clone();
    changed.packet[1] = 1;
    assert!(store.command_result(&changed).is_err());
    first.state = "acknowledged".into();
    store.command_result(&first).unwrap();
    store.rebuild().unwrap();
    let mut second = wire_command(&mut store, &session, 0, 101);
    assert!(
        matches!(store.command_result(&second), Err(radius_accounting::Error::Io(e)) if e.kind()==std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(store.commands().unwrap()[0].state, "pending");
    // A different ID cannot make time move backwards.
    let target = second.target.as_ref().unwrap();
    for (identifier, timestamp, allowed) in [(1, 99, false), (1, 101, true)] {
        let attrs = radius_accounting::dynamic::Profile::default()
            .attributes(
                radius_accounting::dynamic::Action::Disconnect,
                target,
                None,
                timestamp * 1000,
            )
            .unwrap()
            .unwrap();
        second.packet =
            wire::dynamic_request(wire::DISCONNECT_REQUEST, identifier, &attrs, SECRET).unwrap();
        let result = store.command_result(&second);
        assert_eq!(result.is_ok(), allowed);
    }
    second.state = "acknowledged".into();
    store.command_result(&second).unwrap();
    // After the configured duplicate window, ID 0 can be used at a new timestamp.
    let third = wire_command(&mut store, &session, 0, 400);
    store.command_result(&third).unwrap();
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn wire_identifier_pool_exhaustion_defers_without_consuming_a_request() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let session = store
        .record(&[observation(1, b"wire-capacity", 100)])
        .unwrap()[0]
        .session
        .clone()
        .unwrap();
    for identifier in 0..=255 {
        let mut command = wire_command(&mut store, &session, identifier, 100);
        store.command_result(&command).unwrap();
        command.state = "acknowledged".into();
        store.command_result(&command).unwrap();
    }
    let mut deferred = wire_command(&mut store, &session, 0, 101);
    assert!(store.command_result(&deferred).is_err());
    let saved = store.commands().unwrap().remove(0);
    assert_eq!(saved.attempts, 0);
    assert!(saved.packet.is_empty());
    assert!(saved.validation_error.unwrap().contains("identifier"));
    // Re-encoding later is still the same durable administrator request.
    let attrs = radius_accounting::dynamic::Profile::default()
        .attributes(
            radius_accounting::dynamic::Action::Disconnect,
            deferred.target.as_ref().unwrap(),
            None,
            400_000,
        )
        .unwrap()
        .unwrap();
    deferred.packet = wire::dynamic_request(wire::DISCONNECT_REQUEST, 0, &attrs, SECRET).unwrap();
    store.command_result(&deferred).unwrap();
}

#[test]
fn schema_two_upgrade_adds_wire_fences_and_preserves_evidence() {
    let directory = std::env::temp_dir().join(format!(
        "radius-wire-upgrade-{}",
        radius_accounting::id().unwrap()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("ledger.db");
    let mut store = Store::open(&path, Settings::default()).unwrap();
    let session = store.record(&[observation(1, b"schema-two", 100)]).unwrap()[0]
        .session
        .clone()
        .unwrap();
    let mut previous = wire_command(&mut store, &session, 0, 100);
    store.command_result(&previous).unwrap();
    previous.state = "acknowledged".into();
    store.command_result(&previous).unwrap();
    drop(store);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "DROP TABLE dynamic_wire_clock; DROP TABLE dynamic_wire_ids; PRAGMA user_version=2;",
    )
    .unwrap();
    drop(db);
    let mut store = Store::open(&path, Settings::default()).unwrap();
    assert_eq!(store.health().unwrap().sessions, 1);
    let first = wire_command(&mut store, &session, 0, 100);
    assert!(store.command_result(&first).is_err());
    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn wire_pairs_are_machine_unique_and_identifier_holds_follow_the_nas_address() {
    let mut store = Store::memory(Settings::default()).unwrap();
    let first = store.record(&[observation(1, b"nas-one", 100)]).unwrap()[0]
        .session
        .clone()
        .unwrap();
    let mut command = wire_command(&mut store, &first, 0, 100);
    store.command_result(&command).unwrap();
    command.state = "acknowledged".into();
    store.command_result(&command).unwrap();
    let mut second_observation = observation(1, b"nas-two", 100);
    second_observation.source = "192.0.2.2".parse().unwrap();
    let second = store.record(&[second_observation]).unwrap()[0]
        .session
        .clone()
        .unwrap();
    let mut other = wire_command(&mut store, &second, 0, 100);
    // Even another AP sharing a secret cannot reuse an identical wire pair.
    assert!(store.command_result(&other).is_err());
    let attrs = radius_accounting::dynamic::Profile::default()
        .attributes(
            radius_accounting::dynamic::Action::Disconnect,
            other.target.as_ref().unwrap(),
            None,
            101_000,
        )
        .unwrap()
        .unwrap();
    other.packet = wire::dynamic_request(wire::DISCONNECT_REQUEST, 0, &attrs, SECRET).unwrap();
    store.command_result(&other).unwrap(); // Its own duplicate window is independent.
    let mut changed_port = wire_command(&mut store, &first, 0, 102);
    changed_port.port = 4799;
    assert!(store.command_result(&changed_port).is_err());
}
