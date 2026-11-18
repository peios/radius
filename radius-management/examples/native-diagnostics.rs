//! Caller and field-permission qualification in an explicitly disposable guest.
use peios::{
    registry::{CreateFlags, Key, KeyAccess, ValueType},
    security::{sddl, IntegrityLevel, Privileges, Sid, WellKnown},
    token::{ImpersonationLevel, LogonType, Session, TokenBuilder, TokenType},
};
use radius_management::{
    diagnostics::{Filter, OPERATION},
    native::{diagnostics, registry},
};
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

const USER: &str = "S-1-5-21-1-2-3-779";
const POLICY: &str = "Machine\\System\\eventd\\Security\\Events\\radiusd";
const HIDDEN: &[(&str, &str)] = &[
    (
        "source.radiusd.username",
        "d2f3b806-f1d6-527b-8501-009fe4f57bb5",
    ),
    ("object.account.sid", "0ab84ccf-ca5f-51ab-aaf4-003b2c7a0cfb"),
    (
        "object.radiusd.canonical-name",
        "ccddcbc3-8e68-512d-92ac-9596fc8a33de",
    ),
    (OPERATION, "c6d619b7-8908-50c5-a18d-0344789eb400"),
];

fn main() {
    assert_eq!(
        std::env::var("PEIOS_DISPOSABLE_RADIUS_TEST").as_deref(),
        Ok("yes")
    );
    if std::env::args().nth(1).as_deref() == Some("primary") {
        let monitor = diagnostics::Monitor::start(Filter::default()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(7);
        loop {
            let view = monitor.snapshot();
            assert!(
                view.attempts.is_empty(),
                "ordinary process inherited SYSTEM query rights"
            );
            if view.following {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "primary live reader failed: {}",
                view.status
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        println!("PASS RADIUS DIAGNOSTICS: ordinary primary-token process live query");
        return;
    }
    // Read genuine daemon attempts, not fixture-emitted substitutes.
    let filter = Filter::default();
    let view = diagnostics::read(&filter).expect("SYSTEM diagnostic history");
    let accepted = view
        .attempts
        .iter()
        .find(|a| {
            a.outcome_available
                && a.summary
                    .get("outcome.success")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
        })
        .expect("an actual accepted attempt");
    let operation = accepted
        .summary
        .get(OPERATION)
        .and_then(serde_json::Value::as_str)
        .expect("authority-issued correlation");
    let authority = diagnostics::authority(operation).expect("linked authority query");
    assert!(
        !authority.is_empty(),
        "no exact linked authd operation event"
    );
    assert!(authority
        .iter()
        .all(|r| r.get(OPERATION).and_then(serde_json::Value::as_str) == Some(operation)));
    println!("PASS RADIUS DIAGNOSTICS: genuine attempt history and exact authd correlation");

    let user: Sid = USER.parse().unwrap();
    let session = Session::create(
        LogonType::Network,
        "radius-diagnostic-qualification",
        user.as_ref(),
    )
    .unwrap();
    let token = TokenBuilder::new()
        .user(user.as_ref())
        .add_group(Sid::well_known(WellKnown::Everyone).as_ref(), 6)
        .add_group(Sid::well_known(WellKnown::AuthenticatedUsers).as_ref(), 6)
        .privileges(Privileges::CHANGE_NOTIFY, Privileges::CHANGE_NOTIFY)
        .token_type(TokenType::Impersonation, ImpersonationLevel::Impersonation)
        .integrity(IntegrityLevel::HIGH)
        .session(session)
        .projected_ids(1000779, 1000779)
        .create()
        .unwrap();
    {
        let _scope = token.impersonate_scoped().unwrap();
        assert!(
            registry::read().is_err(),
            "fixture unexpectedly grants configuration read"
        );
        assert!(diagnostics::read(&filter)
            .expect("authorized empty query")
            .attempts
            .is_empty());
        assert!(
            matches!(diagnostics::Monitor::start(filter.clone()), Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied),
            "impersonating hosts must not launch a primary-token worker"
        );
    }
    let primary = token
        .duplicate(
            peios::token::TokenAccess::ASSIGN_PRIMARY,
            TokenType::Primary,
            ImpersonationLevel::Impersonation,
        )
        .unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.arg("primary");
    // SAFETY: after fork this closure only invokes the token-install syscall;
    // it does not allocate or lock, and the owned handle remains live.
    unsafe {
        command.pre_exec(move || Ok(primary.install()?));
    }
    assert!(command.status().unwrap().success());
    drop(command);
    println!("PASS RADIUS DIAGNOSTICS: impersonated worker escalation refused");
    // These UUIDv5 field IDs use eventd's documented field namespace and PCDS
    // mapping. Deny personal fields, while granting ordinary attempt evidence.
    let denied: String = HIDDEN
        .iter()
        .map(|(_, guid)| format!("(OD;;0x1;{guid};;{USER})"))
        .collect();
    let descriptor = sddl::parse(&format!(
        "O:SYG:SYD:P{denied}(A;;0x1;;;{USER})(A;;0x1;;;SY)"
    ))
    .unwrap();
    let (key, _) = Key::create(
        None,
        POLICY,
        KeyAccess::SET_VALUE | KeyAccess::QUERY_VALUE,
        CreateFlags::default(),
        None,
        None,
    )
    .unwrap();
    // Refuse to overwrite someone else's fixture policy.
    assert!(key.query_value(b"", None).is_err());
    key.set_value(b"", ValueType::BINARY, descriptor.as_bytes())
        .call()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    {
        let _scope = token.impersonate_scoped().unwrap();
        let view = diagnostics::read(&filter).expect("delegated field-filtered history");
        assert!(
            !view.attempts.is_empty(),
            "delegated event read was not honored"
        );
        assert!(
            registry::read().is_err(),
            "event rights granted unrelated configuration rights"
        );
        for record in view.attempts.iter().flat_map(|a| &a.stages) {
            for (field, _) in HIDDEN {
                assert!(!record.contains_key(*field), "hidden {field} leaked");
            }
        }
        let filtered = diagnostics::read(&Filter {
            username: Some("dev-radius".into()),
            ..filter.clone()
        })
        .unwrap();
        assert!(
            filtered.attempts.is_empty(),
            "hidden username was reconstructed"
        );
    }
    key.delete_value(b"", None, None).unwrap();
    drop(token);
    for attempt in 0..200 {
        match Session::destroy_empty(session) {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) if e.raw_os_error() == Some(16) && attempt < 199 => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(e) => panic!("qualification session cleanup: {e}"),
        }
    }
    println!(
        "PASS RADIUS DIAGNOSTICS: delegated fields, personal-field denial and no reconstruction"
    );
}
