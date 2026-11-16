//! Only run as SYSTEM inside a disposable qualification guest.
use peios::{
    security::{IntegrityLevel, Privileges, Sid, WellKnown},
    token::{ImpersonationLevel, LogonType, Session, TokenBuilder, TokenType},
};
use radius_management::{
    model::{Value, Values, ROOT},
    native::{control, credentials, registry},
};
fn main() {
    assert_eq!(
        std::env::var("PEIOS_DISPOSABLE_RADIUS_TEST").as_deref(),
        Ok("yes")
    );
    let user: Sid = "S-1-5-21-1-2-3-777".parse().unwrap();
    let admin = Sid::well_known(WellKnown::Administrators);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let session =
        Session::create(LogonType::Network, "radius-qualification", user.as_ref()).unwrap();
    for enabled in [true, false] {
        // Match authd's enabled, owner-eligible Administrators group: default,
        // enabled and owner = 14. Deny-only = 16. Both tokens have identical
        // user and Unix projections; group attributes decide access.
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
        let query = control::query();
        if enabled {
            assert!(
                query.is_ok(),
                "enabled administrator could not query status: {query:?}"
            );
            if std::env::var("PEIOS_ADMIN_WRITABLE_FIXTURE").as_deref() == Ok("yes") {
                registry::write(
                    &format!("{ROOT}\\Settings"),
                    &Values::from([("IdleTimeoutSeconds".into(), Value::Number(30))]),
                    false,
                )
                .expect("enabled administrator must edit the initialized configuration");
                let mut staged = credentials::Staged::default();
                let path = staged
                    .write(b"administrator-secret-probe")
                    .expect("enabled administrator must stage a protected secret");
                assert_eq!(
                    &*credentials::material(&path, true, 1024).unwrap(),
                    b"administrator-secret-probe"
                );
                // Uncommitted staging removes this fixture file on scope exit.
            }
        } else {
            assert_eq!(
                query.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                registry::write(
                    &format!("{ROOT}\\Settings"),
                    &Values::from([("MaxVerifications".into(), Value::Number(32))]),
                    false
                )
                .unwrap_err()
                .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                credentials::material("/var/state/radius/secrets/secret", true, 1024)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }
    // Socket peer-token references may retire after the final userspace close.
    for attempt in 0..200 {
        match Session::destroy_empty(session) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) if error.raw_os_error() == Some(16) && attempt < 199 => {
                std::thread::sleep(std::time::Duration::from_millis(25))
            }
            Err(error) => panic!("qualification session cleanup: {error}"),
        }
    }
    println!("PASS RADIUS ADMIN: real peer token, deny-only group, Registry and secret authority");
}
