//! Explicitly disposable native qualification; not an administration interface.
use radius_management::{
    accounting::{Filter, Request},
    native::accounting,
};
use std::{net::UdpSocket, path::Path, time::Duration};
const USER: &str = "S-1-5-21-1-2-3-777";
fn main() {
    assert_eq!(
        std::env::var("PEIOS_DISPOSABLE_RADIUS_TEST").as_deref(),
        Ok("yes")
    );
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seed") => {
            let mut store = radius_accounting::store::Store::open(
                &Path::new(accounting::DIRECTORY).join("ledger.db"),
                Default::default(),
            )
            .unwrap();
            let now = radius_accounting::worker::now_ms();
            store
                .grant(
                    &radius_accounting::model::Grant {
                        proof: None,
                        reference: b"accounting-native-grant".to_vec(),
                        client: "11111111-1111-4111-8111-111111111111".into(),
                        policy: "22222222-2222-4222-8222-222222222222".into(),
                        sid: USER.into(),
                        name: Some("Accounting fixture".into()),
                        groups: vec![],
                        station: None,
                        issued_ms: 0,
                        expires_ms: now + 86400000,
                    },
                    now,
                )
                .unwrap();
            println!("PASS NATIVE ACCOUNTING: protected SQLite WAL/FULL ledger and Class grant");
        }
        Some("udp") => {
            let request = std::fs::read(&args[2]).unwrap();
            let expected = std::fs::read(&args[3]).unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(4)))
                .unwrap();
            socket.send_to(&request, "127.0.0.1:18130").unwrap();
            let mut bytes = [0; 4096];
            if expected.is_empty() {
                assert!(socket.recv_from(&mut bytes).is_err());
            } else {
                let (n, peer) = socket
                    .recv_from(&mut bytes)
                    .expect("durable accounting response");
                assert_eq!(peer, "127.0.0.1:18130".parse().unwrap());
                assert_eq!(&bytes[..n], expected);
            }
            println!(
                "PASS NATIVE ACCOUNTING: independent request/response {}",
                args[2]
            );
        }
        Some("authority") => authority(),
        Some("self") => scoped(false),
        Some("delegated") => scoped(true),
        Some("disconnect") => disconnect(),
        _ => panic!("expected seed, udp REQUEST EXPECTED, or authority"),
    }
}
fn disconnect() {
    use md5::{Digest, Md5};
    let secret = b"native-accounting-test-secret";
    let socket = UdpSocket::bind("127.0.0.1:3799").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let page = accounting::query(Request::Sessions {
        filter: Filter {
            limit: 100,
            active_only: true,
            ..Default::default()
        },
    })
    .unwrap();
    let id = page["sessions"].as_array().unwrap().first().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let command = accounting::query(Request::Disconnect { id: id.clone() }).unwrap();
    let mut buf = [0; 4096];
    let (n, peer) = socket.recv_from(&mut buf).unwrap();
    let sent = &buf[..n];
    assert_eq!(sent[0], 40);
    assert_eq!(peer, "127.0.0.1:18130".parse().unwrap());
    let mut signed = sent.to_vec();
    signed[4..20].fill(0);
    let mut h = Md5::new();
    h.update(&signed);
    h.update(secret);
    assert_eq!(h.finalize().as_slice(), &sent[4..20]);
    let mut response = vec![41, sent[1], 0, 20];
    response.extend_from_slice(&sent[4..20]);
    let mut h = Md5::new();
    h.update(&response);
    h.update(secret);
    response[4..20].copy_from_slice(&h.finalize());
    let mut tampered = response.clone();
    tampered[4] ^= 1;
    socket.send_to(&tampered, peer).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let pending = accounting::query(Request::Commands { id: id.clone() }).unwrap();
    assert_ne!(pending[0]["state"], "acknowledged");
    socket.send_to(&response, peer).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
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
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(30));
    }
    let row = accounting::query(Request::Session { id }).unwrap();
    assert!(row["end_ms"].is_null());
    println!("PASS NATIVE ACCOUNTING: independent Disconnect integrity, forged ACK refused, real ACK persisted without false Stop");
}
fn scoped(delegated: bool) {
    use peios::{
        security::{IntegrityLevel, Privileges, Sid, WellKnown},
        token::{ImpersonationLevel, LogonType, Session, TokenBuilder, TokenType},
    };
    let user: Sid = if delegated {
        "S-1-5-21-1-2-3-778"
    } else {
        USER
    }
    .parse()
    .unwrap();
    let session = Session::create(
        LogonType::Network,
        "accounting-scoped-qualification",
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
            .projected_ids(1000777, 1000777)
            .create()
            .unwrap();
        let _scope = token.impersonate_scoped().unwrap();
        assert!(accounting::query(Request::Status).is_err());
        let rows = accounting::query(Request::Sessions {
            filter: Filter {
                limit: 100,
                ..Default::default()
            },
        })
        .unwrap();
        let rows = rows["sessions"].as_array().unwrap();
        assert_eq!(rows.len(), if delegated { 2 } else { 1 });
        let own = rows.iter().find(|r| r["sid"] == USER).unwrap();
        let id = own["id"].as_str().unwrap().to_owned();
        assert!(accounting::query(Request::History {
            id: id.clone(),
            limit: 20
        })
        .is_ok());
        assert!(accounting::query(Request::Disconnect { id }).is_err());
        assert!(accounting::query(Request::Usage {
            principal: USER.into(),
            policy: "22222222-2222-4222-8222-222222222222".into()
        })
        .is_ok());
        if delegated {
            assert!(accounting::query(Request::Usage {
                principal: USER.into(),
                policy: "*".into()
            })
            .is_err());
            let filtered = accounting::query(Request::Sessions {
                filter: Filter {
                    limit: 100,
                    policy: Some("22222222-2222-4222-8222-222222222222".into()),
                    principal: Some(USER.into()),
                    ..Default::default()
                },
            })
            .unwrap();
            assert_eq!(filtered["sessions"].as_array().unwrap().len(), 1);
        } else {
            assert!(accounting::query(Request::Usage {
                principal: "S-1-5-21-1-2-3-778".into(),
                policy: "*".into()
            })
            .is_err());
        }
        assert!(std::fs::read(format!("{}/ledger.db", accounting::DIRECTORY)).is_err());
    }
    for _ in 0..200 {
        match Session::destroy_empty(session) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) if e.raw_os_error() == Some(16) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("session cleanup: {e}"),
        }
    }
    println!("PASS NATIVE ACCOUNTING: {} actual token, scoped rows/history/usage, denied disconnect and raw file",if delegated{"delegated"}else{"self-service"});
}
fn authority() {
    use peios::{
        security::{IntegrityLevel, Privileges, Sid, WellKnown},
        token::{ImpersonationLevel, LogonType, Session, TokenBuilder, TokenType},
    };
    let user: Sid = USER.parse().unwrap();
    let admin = Sid::well_known(WellKnown::Administrators);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let session = Session::create(
        LogonType::Network,
        "accounting-qualification",
        user.as_ref(),
    )
    .unwrap();
    for enabled in [true, false] {
        let token = TokenBuilder::new()
            .user(user.as_ref())
            .add_group(admin.as_ref(), if enabled { 14 } else { 16 })
            .add_group(everyone.as_ref(), 6)
            .privileges(Privileges::CHANGE_NOTIFY, Privileges::CHANGE_NOTIFY)
            .token_type(TokenType::Impersonation, ImpersonationLevel::Impersonation)
            .integrity(IntegrityLevel::HIGH)
            .session(session)
            .projected_ids(1000777, 1000777)
            .create()
            .unwrap();
        let _scope = token.impersonate_scoped().unwrap();
        let status = accounting::query(Request::Status);
        let rows = accounting::query(Request::Sessions {
            filter: Filter {
                limit: 100,
                ..Default::default()
            },
        });
        if enabled {
            assert!(status.is_ok());
            assert!(rows.unwrap()["sessions"].as_array().unwrap().len() >= 2);
        } else {
            assert!(status.is_err());
            assert!(rows.unwrap()["sessions"].as_array().unwrap().is_empty());
        }
        assert!(
            std::fs::read(format!("{}/ledger.db", accounting::DIRECTORY)).is_ok() == enabled,
            "directory traversal privilege must not bypass the file's DACL"
        );
    }
    for _ in 0..200 {
        match Session::destroy_empty(session) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) if e.raw_os_error() == Some(16) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("session cleanup: {e}"),
        }
    }
    println!("PASS NATIVE ACCOUNTING: actual peer token, enabled versus deny-only administrator, private database");
}
