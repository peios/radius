//! Disposable guest qualification only; never run against a deployed machine.
use peios_auth::{Field, IdentityKind, Key, fields};
use radius_accounting::{
    dynamic::{Action, Authorization, CredentialBinding, Proof},
    model::Grant,
    store::Store,
    wire::{self, Attribute},
};
use radius_management::{
    accounting::{Filter, Request},
    native::{accounting, registry},
};
use std::{
    net::UdpSocket,
    path::Path,
    time::{Duration, Instant},
};

const POLICY: &str = "22222222-2222-4222-8222-222222222222";
const CLIENT: &str = "11111111-1111-4111-8111-111111111111";
const REFERENCE: &[u8] = b"native-control-verified-grant";
fn record() -> peios_auth::Record {
    let client = peios_auth::Client::new().unwrap();
    let mut op = client
        .lookup(
            Key::Name("dev-radius"),
            IdentityKind::Principal,
            fields::CREDENTIAL_BINDINGS,
        )
        .unwrap();
    op.wait().unwrap();
    let mut result = op.identity().unwrap();
    assert_eq!(result.outcome, 1);
    assert!(result.incomplete_sources.is_empty());
    assert_eq!(result.records.len(), 1);
    result.records.remove(0)
}
fn bindings(record: &peios_auth::Record) -> Vec<CredentialBinding> {
    match record.fields.get(&fields::CREDENTIAL_BINDINGS) {
        Some(Field::CredentialBindings(values)) => values
            .iter()
            .map(|v| CredentialBinding {
                reference: v.reference,
                revision: v.revision,
            })
            .collect(),
        other => panic!("expected disclosed credential metadata, got {other:?}"),
    }
}
fn authenticated() -> peios_auth::Authenticated {
    let client = peios_auth::Client::new().unwrap();
    let mut op = client
        .authenticate(peios_auth::AuthenticateRequest {
            authentication: peios_auth::AuthenticationRequest {
                username: "dev-radius",
                supported_credentials: peios_auth::Capabilities::PASSWORD,
                required_credential_type: Some(1),
                ssh_binding: None,
            },
            groups: true,
            claims: peios_auth::ClaimSelection::AllPermitted,
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline);
        match op.step().unwrap() {
            peios_auth::Progress::Complete => return op.authenticated().unwrap(),
            peios_auth::Progress::Prompt => {
                let round = op.round().unwrap();
                assert_eq!(round.prompts.len(), 1);
                assert_eq!(round.prompts[0].credential_type, 1);
                op.respond(
                    round.id,
                    &[peios_auth::Answer {
                        credential_ref: round.prompts[0].credential_ref,
                        data: b"development-only-password",
                    }],
                )
                .unwrap();
            }
            peios_auth::Progress::Wait => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn seed() {
    let subject = authenticated();
    let credentials = bindings(&subject.identity);
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials, bindings(&record()));
    let sid = peios::security::SidRef::from_bytes(&subject.identity.sid)
        .unwrap()
        .to_string();
    let config = radius_management::accounting::prepare(&registry::read().unwrap()).unwrap();
    let now = radius_accounting::worker::now_ms();
    let mut store = Store::open(
        &Path::new(accounting::DIRECTORY).join("ledger.db"),
        Default::default(),
    )
    .unwrap();
    store
        .grant(
            &Grant {
                proof: None,
                reference: REFERENCE.into(),
                client: CLIENT.into(),
                policy: POLICY.into(),
                sid,
                name: None,
                groups: vec![],
                station: None,
                issued_ms: now,
                expires_ms: now + 3600000,
            },
            now,
        )
        .unwrap();
    store
        .bind_grant(&Proof {
            sequence: 0,
            grant: REFERENCE.into(),
            authenticated_ms: now,
            configuration: config.fingerprint,
            issued: Authorization {
                vlan: Some(20),
                timeout_seconds: 3600,
            },
            configured_timeout_seconds: 3600,
            credentials,
        })
        .unwrap();
    println!("PASS NATIVE CONTROLS: actual authenticated credential binding durably captured");
}
fn session_id() -> String {
    let rows = accounting::query(Request::Sessions {
        filter: Filter {
            active_only: true,
            limit: 100,
            ..Default::default()
        },
    })
    .unwrap();
    rows["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["session"] == serde_json::json!(b"native-control-session".to_vec()))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .into()
}
fn start() {
    let secret = std::fs::read("/mnt/dev/credentials/secret").unwrap();
    let attrs = vec![
        Attribute::integer(40, 1),
        Attribute {
            kind: 32,
            value: b"native-control-nas".into(),
        },
        Attribute {
            kind: 44,
            value: b"native-control-session".into(),
        },
        Attribute {
            kind: 25,
            value: REFERENCE.into(),
        },
        Attribute {
            kind: 30,
            value: b"aa-bb-cc-dd-ee-ff:Home".into(),
        },
    ];
    let packet = wire::request(1, &attrs, &secret, true).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&packet, "127.0.0.1:18130").unwrap();
    let mut buffer = [0; 4096];
    let (n, _) = socket.recv_from(&mut buffer).unwrap();
    assert!(n >= 20);
    assert_eq!(buffer[0], 5);
    let id = session_id();
    let row = accounting::query(Request::Session { id }).unwrap();
    assert!(!row["proof"].is_null());
    assert_eq!(row["proof"]["credentials"].as_array().unwrap().len(), 1);
    println!(
        "PASS NATIVE CONTROLS: authenticated accounting occurrence recognized with original proof"
    );
}
fn control(action: Action, request_id: &str) -> serde_json::Value {
    accounting::query(Request::Control {
        id: session_id(),
        action,
        request_id: request_id.into(),
    })
    .unwrap()
}
fn acknowledge(nas: &UdpSocket, command: &serde_json::Value, code: u8) {
    use md5::{Digest, Md5};
    let secret = std::fs::read("/mnt/dev/credentials/secret").unwrap();
    let mut buffer = [0; 4096];
    let (n, peer) = nas.recv_from(&mut buffer).unwrap();
    let sent = &buffer[..n];
    assert_eq!(sent[0], code);
    assert_eq!(peer, "127.0.0.1:18130".parse().unwrap());
    let mut kinds = Vec::new();
    let mut at = 20;
    while at < n {
        let size = usize::from(sent[at + 1]);
        assert!(size >= 2 && at + size <= n);
        kinds.push(sent[at]);
        at += size;
    }
    assert!(kinds.contains(&32) && kinds.contains(&44) && kinds.contains(&80));
    assert!(!kinds.contains(&1));
    if code == 43 {
        assert!(kinds.contains(&81) && kinds.contains(&27));
    }
    let mut reply = vec![if code == 43 { 44 } else { 41 }, sent[1], 0, 20];
    reply.extend_from_slice(&sent[4..20]);
    let mut hash = Md5::new();
    hash.update(&reply);
    hash.update(&secret);
    reply[4..20].copy_from_slice(&hash.finalize());
    let mut forged = reply.clone();
    forged[4] ^= 1;
    nas.send_to(&forged, peer).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let id = session_id();
    let rows = accounting::query(Request::Commands { id: id.clone() }).unwrap();
    assert!(
        !rows
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == command["id"] && c["state"] == "acknowledged")
    );
    nas.send_to(&reply, peer).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rows = accounting::query(Request::Commands { id: id.clone() }).unwrap();
        if rows
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == command["id"] && c["state"] == "acknowledged")
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    let row = accounting::query(Request::Session { id }).unwrap();
    assert!(row["end_ms"].is_null());
}
fn transport() {
    let nas = UdpSocket::bind("127.0.0.1:3799").unwrap();
    nas.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let command = control(Action::UpdateAuthorization, "native-update");
    acknowledge(&nas, &command, 43);
    let repeat = control(Action::UpdateAuthorization, "native-update");
    assert_eq!(repeat["id"], command["id"]);
    assert_eq!(repeat["state"], "acknowledged");
    let reauth = control(Action::Reauthenticate, "native-reauth");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rows = accounting::query(Request::Commands { id: session_id() }).unwrap();
        if rows
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == reauth["id"] && c["state"] == "unsupported")
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    let disconnect = control(Action::Disconnect, "native-disconnect");
    acknowledge(&nas, &disconnect, 40);
    println!(
        "PASS NATIVE CONTROLS: exact CoA/Disconnect selectors, forged reply rejection, durable ACK, idempotent manual request and honest unsupported reauth"
    );
}
fn automatic(action: Action) {
    let nas = UdpSocket::bind("127.0.0.1:3799").unwrap();
    nas.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let command = loop {
        let rows = accounting::query(Request::Commands { id: session_id() }).unwrap();
        if let Some(command) = rows.as_array().unwrap().iter().find(|c| {
            c["actor"] == "radiusd"
                && (c["state"] == "pending" || c["state"] == "sent")
                && c["action"] == serde_json::to_value(action).unwrap()
        }) {
            break command.clone();
        }
        assert!(Instant::now() < deadline, "no automatic command queued");
        std::thread::sleep(Duration::from_millis(25));
    };
    acknowledge(
        &nas,
        &command,
        if action == Action::Disconnect { 40 } else { 43 },
    );
    println!("PASS NATIVE CONTROLS: automatic {action:?} reached the exact original occurrence");
}
fn scoped(fallback: bool) {
    use peios::{
        security::{IntegrityLevel, Privileges, Sid, WellKnown},
        token::{ImpersonationLevel, LogonType, Session, TokenBuilder, TokenType},
    };
    let id = session_id();
    let user: Sid = if fallback {
        "S-1-5-21-1-2-3-779"
    } else {
        "S-1-5-21-1-2-3-778"
    }
    .parse()
    .unwrap();
    let session = Session::create(
        LogonType::Network,
        "native-controls-authority",
        user.as_ref(),
    )
    .unwrap();
    {
        let token = TokenBuilder::new()
            .user(user.as_ref())
            .add_group(Sid::well_known(WellKnown::Everyone).as_ref(), 6)
            .privileges(Privileges::CHANGE_NOTIFY, Privileges::CHANGE_NOTIFY)
            .token_type(TokenType::Impersonation, ImpersonationLevel::Impersonation)
            .integrity(IntegrityLevel::HIGH)
            .session(session)
            .projected_ids(1000778, 1000778)
            .create()
            .unwrap();
        let _scope = token.impersonate_scoped().unwrap();
        for action in [Action::Reauthenticate, Action::UpdateAuthorization] {
            assert!(
                accounting::query(Request::Control {
                    id: id.clone(),
                    action,
                    request_id: format!("denied-{fallback}-{action:?}")
                })
                .is_err()
            );
        }
        let client = peios_auth::Client::new().unwrap();
        if let Ok(mut op) = client.lookup(
            Key::Name("dev-radius"),
            IdentityKind::Principal,
            fields::CREDENTIAL_BINDINGS,
        ) {
            if op.wait().is_ok() {
                assert!(op.identity().unwrap().records.iter().all(|r| !matches!(
                    r.fields.get(&fields::CREDENTIAL_BINDINGS),
                    Some(Field::CredentialBindings(_))
                )));
            }
        }
        if !fallback {
            assert!(accounting::query(Request::Commands { id }).is_ok());
        }
        drop(_scope);
        drop(token);
    }
    for attempt in 0..200 {
        match Session::destroy_empty(session) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) if e.raw_os_error() == Some(16) && attempt < 199 => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(e) => panic!("session cleanup: {e}"),
        }
    }
    println!(
        "PASS NATIVE CONTROLS: actual caller action/fallback rights and credential metadata denial"
    );
}
fn main() {
    assert_eq!(
        std::env::var("PEIOS_DISPOSABLE_RADIUS_TEST").as_deref(),
        Ok("yes")
    );
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seed") => seed(),
        Some("start") => start(),
        Some("transport") => transport(),
        Some("automatic-disconnect") => automatic(Action::Disconnect),
        Some("automatic-update") => automatic(Action::UpdateAuthorization),
        Some("scoped") => scoped(false),
        Some("fallback") => scoped(true),
        Some("state") => {
            let id = session_id();
            let row = accounting::query(Request::Session { id: id.clone() }).unwrap();
            let commands = accounting::query(Request::Commands { id: id.clone() }).unwrap();
            let state = serde_json::json!({"session":id,"proof":row["proof"],"commands":commands});
            if args[3] == "save" {
                std::fs::write(&args[2], serde_json::to_vec(&state).unwrap()).unwrap();
            } else {
                let before: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
                assert_eq!(
                    state, before,
                    "cold boot changed command history or original proof"
                );
            }
            println!(
                "PASS NATIVE CONTROLS: persisted command history and original proof {}",
                args[3]
            );
        }
        Some("binding") => {
            let current = bindings(&record());
            let file = &args[2];
            match args[3].as_str() {
                "save" => std::fs::write(file, serde_json::to_vec(&current).unwrap()).unwrap(),
                "empty" => assert!(current.is_empty()),
                mode => {
                    let old: Vec<CredentialBinding> =
                        serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
                    assert_eq!(old.len(), 1);
                    assert_eq!(current.len(), 1);
                    assert_eq!(current[0].reference, old[0].reference);
                    if mode == "changed" {
                        assert_ne!(current[0].revision, old[0].revision);
                    } else {
                        assert_eq!(current, old);
                    }
                }
            }
            println!("PASS NATIVE CONTROLS: credential revision {}", args[3]);
        }
        _ => panic!("expected seed/start/transport/scoped/fallback/binding"),
    }
}
