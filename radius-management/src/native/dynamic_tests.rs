//! Real ledger owner and UDP transport, without a host Peios kernel or live NAS.
use super::{
    accounting::{Service, Snapshot},
    dynamic::{reconcile, Authority},
    dynamic_commands::Commands,
};
use crate::{
    dynamic::Evaluation,
    model::{Kind, Record, Stored, Value},
};
use radius_accounting::{
    dynamic::{Action, Authorization, CredentialBinding, Intent, Proof},
    model::{Grant, Observation, Session, Settings},
    wire::{self, Attribute, Request},
    worker::{self, Handle, View},
};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const CLIENT: &str = "11111111-1111-4111-8111-111111111111";
const POLICY: &str = "22222222-2222-4222-8222-222222222222";
const SID: &str = "S-1-5-21-1-2-3-1001";
const SECRET: &[u8] = b"dynamic-test-only-shared-secret";
struct Fixture {
    service: Service,
    session: Session,
    path: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(done) = self.service.ledger.stop() {
            let _ = done.recv_timeout(Duration::from_secs(2));
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn fixture(port: u16) -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "radius-controls-{}",
        radius_accounting::id().unwrap()
    ));
    std::fs::create_dir(&path).unwrap();
    let mut stored = Stored::default();
    stored
        .settings
        .insert("SchemaVersion".into(), Value::Number(crate::model::SCHEMA));
    stored
        .settings
        .insert("AccountingEnabled".into(), Value::Number(1));
    stored.objects.push(Record {
        kind: Kind::Policy,
        id: POLICY.into(),
        values: [
            ("Name".into(), Value::Text("test".into())),
            ("Enabled".into(), Value::Number(1)),
            ("ServiceKind".into(), Value::Text("accounting-only".into())),
        ]
        .into(),
    });
    stored.objects.push(Record {
        kind: Kind::Client,
        id: CLIENT.into(),
        values: [
            ("Name".into(), Value::Text("nas".into())),
            ("Enabled".into(), Value::Number(1)),
            ("Addresses".into(), Value::List(vec!["127.0.0.1/32".into()])),
            ("Policies".into(), Value::List(vec![POLICY.into()])),
            ("SecretFile".into(), Value::Text("/fixture-secret".into())),
            ("DisconnectPort".into(), Value::Number(u32::from(port))),
        ]
        .into(),
    });
    let config = crate::accounting::prepare(&stored).unwrap();
    let settings = Settings {
        enabled: true,
        ..Default::default()
    };
    let now = worker::now_ms();
    let mut store =
        radius_accounting::store::Store::open(&path.join("ledger.db"), settings.clone()).unwrap();
    let g = Grant {
        proof: None,
        reference: vec![5; 16],
        client: CLIENT.into(),
        policy: POLICY.into(),
        sid: SID.into(),
        name: None,
        groups: vec![],
        station: None,
        issued_ms: now - 1000,
        expires_ms: now + 3600000,
    };
    store.grant(&g, now).unwrap();
    store
        .bind_grant(&Proof {
            sequence: 0,
            grant: g.reference.clone(),
            authenticated_ms: g.issued_ms,
            configuration: config.fingerprint.clone(),
            issued: Authorization {
                vlan: Some(10),
                timeout_seconds: 3600,
                attributes: Default::default(),
                configured_timeout_seconds: None,
            },
            configured_timeout_seconds: 3600,
            credentials: vec![CredentialBinding {
                reference: [1; 16],
                revision: [2; 16],
            }],
        })
        .unwrap();
    let attrs = vec![
        Attribute::integer(40, 1),
        Attribute::integer(55, (now / 1000) as u32),
        Attribute {
            kind: 32,
            value: b"fixture-nas".to_vec(),
        },
        Attribute {
            kind: 44,
            value: b"exact-occurrence".to_vec(),
        },
        Attribute {
            kind: 25,
            value: g.reference,
        },
    ];
    let request = Request::parse(
        &wire::request(1, &attrs, SECRET, true).unwrap(),
        SECRET,
        true,
    )
    .unwrap();
    let mut observation =
        Observation::new(&request, CLIENT.into(), "127.0.0.1".parse().unwrap(), now).unwrap();
    observation.policy = Some(POLICY.into());
    let id = store.record(&[observation]).unwrap()[0]
        .session
        .clone()
        .unwrap();
    let session = store.session(&id).unwrap().unwrap();
    drop(store);
    let ledger = Handle::start(path.join("ledger.db"), settings).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !ledger.snapshot().available {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    let snapshot = Snapshot {
        config,
        ledger_ready: true,
        activation_error: None,
        secrets: BTreeMap::from([(CLIENT.into(), Arc::new(Zeroizing::new(SECRET.to_vec())))]),
    };
    let service = Service::fixture(snapshot, ledger);
    service.publish_authority(Some(Authority {
        revision: service.snapshot().unwrap().config.fingerprint.clone(),
        evaluate: Arc::new(|sessions| sessions.iter().map(|_| granted(10, 3)).collect()),
    }));
    Fixture {
        service,
        session,
        path,
    }
}
fn granted(vlan: u16, revision: u8) -> Evaluation {
    Evaluation::Granted {
        desired: Authorization {
            vlan: Some(vlan),
            timeout_seconds: 3600,
            attributes: Default::default(),
            configured_timeout_seconds: None,
        },
        credentials: Some(vec![CredentialBinding {
            reference: [1; 16],
            revision: [revision; 16],
        }]),
    }
}
fn commands(f: &Fixture) -> Vec<radius_accounting::store::Command> {
    worker::wait(
        f.service
            .ledger
            .command_history(f.session.id.clone())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn richer_policy_updates_are_not_reissued_as_allowance_time_decreases() {
    let f = fixture(9);
    let mut snapshot = (*f.service.snapshot().unwrap()).clone();
    snapshot
        .config
        .dynamic
        .policies
        .get_mut(POLICY)
        .unwrap()
        .update_authorization = true;
    let settings: radius_authorization::Settings =
        serde_json::from_value(serde_json::json!({"IdleTimeoutSeconds":120})).unwrap();
    let attributes = settings.compile(Some(10), &Default::default()).unwrap();
    let desired = Authorization {
        vlan: Some(10),
        timeout_seconds: 300,
        configured_timeout_seconds: Some(3600),
        attributes,
    };
    let evaluate = |desired| Evaluation::Granted {
        desired,
        credentials: Some(vec![CredentialBinding {
            reference: [1; 16],
            revision: [2; 16],
        }]),
    };
    reconcile(&f.service, &snapshot, &f.session, evaluate(desired.clone())).unwrap();
    let mut command = commands(&f).remove(0);
    assert_eq!(command.action, Action::UpdateAuthorization);
    command.state = "acknowledged".into();
    worker::wait(f.service.ledger.command_result(command.clone()).unwrap()).unwrap();
    reconcile(&f.service, &snapshot, &f.session, evaluate(desired.clone())).unwrap();
    let before = worker::wait(
        f.service
            .ledger
            .reconciliation(f.session.id.clone())
            .unwrap(),
    )
    .unwrap();
    let mut lower = desired;
    lower.timeout_seconds = 200;
    reconcile(&f.service, &snapshot, &f.session, evaluate(lower)).unwrap();
    let after = worker::wait(
        f.service
            .ledger
            .reconciliation(f.session.id.clone())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(commands(&f).len(), 1);
    assert_eq!(commands(&f)[0].id, command.id);
    assert_eq!(after.intent_epoch, before.intent_epoch);
    // Returning to the originally issued profile still needs an update: the
    // last acknowledged authorization is the actual comparison baseline.
    reconcile(&f.service, &snapshot, &f.session, granted(10, 2)).unwrap();
    assert_eq!(commands(&f).len(), 2);
    assert!(commands(&f)[0]
        .desired
        .as_ref()
        .unwrap()
        .attributes
        .settings
        .0
        .is_empty());
}
#[test]
fn unchanged_effective_policy_and_nt_maintenance_do_not_control_sessions() {
    let f = fixture(3799);
    let mut snapshot = (*f.service.snapshot().unwrap()).clone();
    reconcile(&f.service, &snapshot, &f.session, granted(10, 2)).unwrap();
    snapshot.config.fingerprint = "b".repeat(64); // Observed edit/rename, same result.
    reconcile(&f.service, &snapshot, &f.session, granted(10, 2)).unwrap();
    assert!(commands(&f).is_empty());
    assert_eq!(
        worker::wait(
            f.service
                .ledger
                .reconciliation(f.session.id.clone())
                .unwrap()
        )
        .unwrap()
        .status,
        "current"
    );
}
#[test]
fn vlan_password_and_confirmed_revocation_have_distinct_actions_and_do_not_advance_proof() {
    for (evaluation, expected) in [
        (granted(20, 2), Action::Disconnect),
        (granted(10, 3), Action::Reauthenticate),
        (Evaluation::Disabled, Action::Disconnect),
        (Evaluation::Deleted, Action::Disconnect),
        (Evaluation::Denied, Action::Disconnect),
    ] {
        let f = fixture(3799);
        let snapshot = f.service.snapshot().unwrap();
        reconcile(&f.service, &snapshot, &f.session, evaluation.clone()).unwrap();
        reconcile(&f.service, &snapshot, &f.session, evaluation).unwrap();
        let commands = commands(&f);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].action, expected);
        assert_eq!(commands[0].actor, "radiusd");
        let row = worker::wait(
            f.service
                .ledger
                .session(
                    f.session.id.clone(),
                    View {
                        all: true,
                        ..Default::default()
                    },
                )
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(row.proof, f.session.proof);
    }
}
#[test]
fn outage_keeps_connection_by_default_and_uses_the_persisted_grace_timer() {
    let f = fixture(3799);
    let mut snapshot = (*f.service.snapshot().unwrap()).clone();
    reconcile(
        &f.service,
        &snapshot,
        &f.session,
        Evaluation::Unavailable("offline".into()),
    )
    .unwrap();
    assert!(commands(&f).is_empty());
    let mut state = worker::wait(
        f.service
            .ledger
            .reconciliation(f.session.id.clone())
            .unwrap(),
    )
    .unwrap();
    state.unavailable_since_ms = Some(worker::now_ms() - 2000);
    worker::wait(
        f.service
            .ledger
            .reconciled(f.session.id.clone(), state)
            .unwrap(),
    )
    .unwrap();
    snapshot
        .config
        .dynamic
        .policies
        .get_mut(POLICY)
        .unwrap()
        .unavailable_grace_seconds = Some(1);
    reconcile(
        &f.service,
        &snapshot,
        &f.session,
        Evaluation::Unavailable("still offline".into()),
    )
    .unwrap();
    assert_eq!(commands(&f)[0].action, Action::Disconnect);
    assert_eq!(
        commands(&f)[0].reason,
        "reevaluation-unavailable-grace-expired"
    );
}
#[test]
fn rename_does_not_repeat_terminal_intent_but_confirmed_recovery_starts_a_new_episode() {
    for terminal in ["acknowledged", "uncertain", "rejected", "unsupported"] {
        let f = fixture(3799);
        let mut snapshot = (*f.service.snapshot().unwrap()).clone();
        reconcile(&f.service, &snapshot, &f.session, Evaluation::Disabled).unwrap();
        let mut original = commands(&f).remove(0);
        original.state = terminal.into();
        worker::wait(f.service.ledger.command_result(original.clone()).unwrap()).unwrap();
        snapshot.config.fingerprint = "b".repeat(64);
        reconcile(&f.service, &snapshot, &f.session, Evaluation::Disabled).unwrap();
        assert_eq!(commands(&f).len(), 1, "rename repeated {terminal}");
        // Unknown authority is not evidence of recovery.
        reconcile(
            &f.service,
            &snapshot,
            &f.session,
            Evaluation::Unavailable("offline".into()),
        )
        .unwrap();
        reconcile(&f.service, &snapshot, &f.session, Evaluation::Disabled).unwrap();
        assert_eq!(commands(&f).len(), 1);
        reconcile(&f.service, &snapshot, &f.session, granted(10, 2)).unwrap();
        reconcile(&f.service, &snapshot, &f.session, Evaluation::Disabled).unwrap();
        let history = commands(&f);
        assert_eq!(history.len(), 2);
        assert_ne!(history[0].intent_key, original.intent_key);
    }
}
#[test]
fn missing_credential_metadata_is_unknown_and_cannot_rebind_a_proved_revision() {
    let f = fixture(3799);
    let snapshot = f.service.snapshot().unwrap();
    reconcile(
        &f.service,
        &snapshot,
        &f.session,
        Evaluation::Granted {
            desired: Authorization {
                vlan: Some(10),
                timeout_seconds: 3600,
                attributes: Default::default(),
                configured_timeout_seconds: None,
            },
            credentials: None,
        },
    )
    .unwrap();
    assert!(commands(&f).is_empty());
    assert_eq!(
        worker::wait(
            f.service
                .ledger
                .reconciliation(f.session.id.clone())
                .unwrap()
        )
        .unwrap()
        .status,
        "credential-status-unknown"
    );
}
fn tick_until_packet(
    commands: &mut Commands,
    f: &Fixture,
    socket: &Arc<UdpSocket>,
    nas: &UdpSocket,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buffer = [0; 4096];
    loop {
        commands.tick(
            &f.service,
            &f.service.snapshot().unwrap(),
            std::slice::from_ref(socket),
        );
        if let Ok(n) = nas.recv(&mut buffer) {
            return buffer[..n].to_vec();
        }
        assert!(Instant::now() < deadline, "no command arrived");
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn restart_retransmits_exact_packet_and_wrong_peer_cannot_acknowledge() {
    for proxy_state_nonce in [true, false] {
        restart_wire_mode(proxy_state_nonce);
    }
}
fn restart_wire_mode(proxy_state_nonce: bool) {
    let nas = UdpSocket::bind("127.0.0.1:0").unwrap();
    nas.set_nonblocking(true).unwrap();
    let mut f = fixture(nas.local_addr().unwrap().port());
    let mut configured = (*f.service.snapshot().unwrap()).clone();
    let profile = "66666666-6666-4666-8666-666666666666";
    configured.config.dynamic.profiles.insert(
        profile.into(),
        radius_accounting::dynamic::Profile {
            proxy_state_nonce,
            ..Default::default()
        },
    );
    configured
        .config
        .dynamic
        .clients
        .insert(CLIENT.into(), Some(profile.into()));
    let authority = f.service.authority();
    f.service = Service::fixture(configured, f.service.ledger.clone());
    f.service.publish_authority(authority);
    let snapshot = f.service.snapshot().unwrap();
    worker::wait(
        f.service
            .ledger
            .dynamic(Intent {
                intent_key: String::new(),
                request_id: None,
                session: f.session.id.clone(),
                actor: SID.into(),
                reason: "manual".into(),
                action: Action::Disconnect,
                configuration: snapshot.config.fingerprint.clone(),
                desired: None,
                fallback: vec![],
            })
            .unwrap(),
    )
    .unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let mut first = Commands::new();
    let packet = tick_until_packet(&mut first, &f, &socket, &nas);
    let mut offset = 20;
    let mut has_proxy_state = false;
    while offset < packet.len() {
        has_proxy_state |= packet[offset] == 33;
        offset += packet[offset + 1] as usize;
    }
    assert_eq!(has_proxy_state, proxy_state_nonce);
    assert!(wire::dynamic_timestamp(&packet).is_ok());
    drop(first);
    let mut restarted = Commands::new();
    let retry = tick_until_packet(&mut restarted, &f, &socket, &nas);
    assert_eq!(retry, packet);
    let mut ack = vec![41, packet[1], 0, 20];
    ack.extend_from_slice(&packet[4..20]);
    use md5::{Digest, Md5};
    let mut hash = Md5::new();
    hash.update(&ack);
    hash.update(SECRET);
    ack[4..20].copy_from_slice(&hash.finalize());
    assert!(restarted.response(
        &socket,
        SocketAddr::from(([127, 0, 0, 1], 1)),
        &ack,
        &f.service,
        false
    ));
    assert_eq!(commands(&f)[0].state, "sent");
    assert!(restarted.response(&socket, nas.local_addr().unwrap(), &ack, &f.service, false));
    let deadline = Instant::now() + Duration::from_secs(2);
    while commands(&f)[0].state != "acknowledged" {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn generic_profile_does_not_claim_fresh_authentication_or_silently_disconnect() {
    let f = fixture(3799);
    let snapshot = f.service.snapshot().unwrap();
    reconcile(&f.service, &snapshot, &f.session, granted(10, 3)).unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let mut dispatcher = Commands::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while commands(&f)[0].state != "unsupported" {
        dispatcher.tick(&f.service, &snapshot, std::slice::from_ref(&socket));
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(commands(&f)[0].action, Action::Reauthenticate);
    assert_eq!(commands(&f)[0].attempts, 0);
}

#[test]
fn rich_coa_transmits_the_exact_vendor_setting_and_retains_its_acknowledged_baseline() {
    let nas = UdpSocket::bind("127.0.0.1:0").unwrap();
    nas.set_nonblocking(true).unwrap();
    let mut f = fixture(nas.local_addr().unwrap().port());
    let mut snapshot = (*f.service.snapshot().unwrap()).clone();
    let mut profile = radius_accounting::dynamic::Profile::wispr_rates();
    profile
        .authorization
        .live
        .insert("DownloadBitsPerSecond".into());
    let settings: radius_authorization::Settings =
        serde_json::from_value(serde_json::json!({"DownloadBitsPerSecond":1000})).unwrap();
    let desired = Authorization {
        vlan: Some(10),
        timeout_seconds: 3600,
        configured_timeout_seconds: Some(3600),
        attributes: settings.compile(Some(10), &profile.authorization).unwrap(),
    };
    snapshot
        .config
        .dynamic
        .profiles
        .insert("fixture".into(), profile);
    snapshot
        .config
        .dynamic
        .clients
        .insert(CLIENT.into(), Some("fixture".into()));
    f.service = Service::fixture(snapshot, f.service.ledger.clone());
    let expected = desired.clone();
    f.service.publish_authority(Some(Authority {
        revision: f.service.snapshot().unwrap().config.fingerprint.clone(),
        evaluate: Arc::new(move |sessions| {
            sessions
                .iter()
                .map(|_| Evaluation::Granted {
                    desired: expected.clone(),
                    credentials: None,
                })
                .collect()
        }),
    }));
    worker::wait(
        f.service
            .ledger
            .dynamic(Intent {
                intent_key: String::new(),
                request_id: None,
                session: f.session.id.clone(),
                actor: SID.into(),
                reason: "manual".into(),
                action: Action::UpdateAuthorization,
                configuration: f.service.snapshot().unwrap().config.fingerprint.clone(),
                desired: Some(desired.clone()),
                fallback: vec![],
            })
            .unwrap(),
    )
    .unwrap();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let mut dispatcher = Commands::new();
    let packet = tick_until_packet(&mut dispatcher, &f, &socket, &nas);
    assert_eq!(packet[0], 43);
    let mut at = 20;
    let mut attrs = Vec::new();
    while at < packet.len() {
        let length = usize::from(packet[at + 1]);
        attrs.push((packet[at], packet[at + 2..at + length].to_vec()));
        at += length;
    }
    assert!(attrs.contains(&(44, f.session.session.clone())));
    assert!(attrs.contains(&(26, vec![0, 0, 55, 42, 8, 6, 0, 0, 3, 232])));
    assert!(attrs.contains(&(27, 3600u32.to_be_bytes().to_vec())));
    // Independent response construction authenticates the actual transmitted
    // request; no AP or untrusted external service participates in this test.
    let mut ack = vec![44, packet[1], 0, 20];
    ack.extend_from_slice(&packet[4..20]);
    use md5::{Digest, Md5};
    let mut hash = Md5::new();
    hash.update(&ack);
    hash.update(SECRET);
    ack[4..20].copy_from_slice(&hash.finalize());
    assert!(dispatcher.response(&socket, nas.local_addr().unwrap(), &ack, &f.service, false));
    let deadline = Instant::now() + Duration::from_secs(2);
    while commands(&f)[0].state != "acknowledged" {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    let recorded = commands(&f).remove(0);
    assert_eq!(recorded.desired, Some(desired));
    assert!(recorded.previous.unwrap().attributes.settings.0.is_empty());
}

#[test]
fn queued_revocation_rechecks_recovery_before_transmission() {
    let nas = UdpSocket::bind("127.0.0.1:0").unwrap();
    nas.set_nonblocking(true).unwrap();
    let f = fixture(nas.local_addr().unwrap().port());
    let snapshot = f.service.snapshot().unwrap();
    reconcile(&f.service, &snapshot, &f.session, Evaluation::Disabled).unwrap();
    // The fresh authority callback now reports the recovered account. This
    // models queued intent surviving a restart, rather than trusting an event.
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let mut dispatcher = Commands::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while commands(&f)[0].state != "superseded" {
        dispatcher.tick(&f.service, &snapshot, std::slice::from_ref(&socket));
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut bytes = [0; 4096];
    assert!(nas.recv(&mut bytes).is_err());
    assert_eq!(commands(&f)[0].attempts, 0);
}

#[test]
fn disabling_vlan_disconnect_does_not_implicitly_select_coa_update() {
    let f = fixture(3799);
    let mut snapshot = (*f.service.snapshot().unwrap()).clone();
    snapshot
        .config
        .dynamic
        .policies
        .get_mut(POLICY)
        .unwrap()
        .vlan_disconnect = false;
    reconcile(&f.service, &snapshot, &f.session, granted(20, 2)).unwrap();
    assert!(commands(&f).is_empty());
    snapshot
        .config
        .dynamic
        .policies
        .get_mut(POLICY)
        .unwrap()
        .update_authorization = true;
    reconcile(&f.service, &snapshot, &f.session, granted(20, 2)).unwrap();
    assert_eq!(commands(&f)[0].action, Action::UpdateAuthorization);
}
