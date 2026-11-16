#![cfg(feature = "native")]
use peios::security::{sddl, Sid};
use peios_auth::{
    fields, Authenticated, Capabilities, Claim, ClaimCoverage, ClaimValue, Field, Record, Reference,
};
use radiusd::{config::Network, driver::Reason, native::authentication::evaluate};
use std::collections::BTreeMap;

const USER: &str = "S-1-5-21-1-2-3-1000";
const GROUP: &str = "S-1-5-21-1-2-3-1001";
fn subject() -> Authenticated {
    Authenticated {
        mschapv2_authenticator_response: None,
        identity: Record {
            sid: USER.parse::<Sid>().unwrap().as_bytes().to_vec(),
            name: "local\\jack".into(),
            kind: 1,
            fields: BTreeMap::from([
                (
                    fields::GROUPS,
                    Field::References(vec![Reference {
                        sid: GROUP.parse::<Sid>().unwrap().as_bytes().to_vec(),
                        name: "household".into(),
                        unix_id: 1,
                    }]),
                ),
                (
                    fields::CLAIMS,
                    Field::Claims(vec![Claim {
                        name: "Department".into(),
                        flags: 0,
                        value_type: 3,
                        values: vec![ClaimValue::Text("Engineering".into())],
                    }]),
                ),
            ]),
        },
        verified_credentials: Capabilities::PASSWORD,
        absent_claims: Vec::new(),
        claim_coverage: ClaimCoverage::Complete,
    }
}
fn check(subject: &Authenticated, text: &str) -> Result<(), Reason> {
    evaluate(
        subject,
        "qualification",
        &Network {
            methods: vec![radius_core::Method::TtlsPap],
            ssid: b"Qualification".to_vec(),
            security: sddl::parse(&format!("O:SYG:SY{text}"))
                .unwrap()
                .as_bytes()
                .to_vec(),
            reauthenticate_seconds: 3600,
        },
    )
}
#[test]
#[ignore = "requires a disposable Peios guest"]
fn native_group_and_typed_claims_use_the_supplied_subject() {
    let mut s = subject();
    let sd = format!("D:(XA;;0x1;;;{GROUP};(@User.Department == \"Engineering\"))");
    assert_eq!(check(&s, &sd), Ok(()));
    s.identity
        .fields
        .insert(fields::GROUPS, Field::References(Vec::new()));
    assert_eq!(check(&s, &sd), Err(Reason::Policy));
}
#[test]
#[ignore = "requires a disposable Peios guest"]
fn hidden_claim_is_unknown_and_cannot_satisfy_a_negative_condition() {
    let mut s = subject();
    let sd = format!("D:(XA;;0x1;;;{GROUP};(!Exists @User.Secret))");
    assert_eq!(check(&s, &sd), Ok(()));
    s.claim_coverage = ClaimCoverage::Filtered;
    assert_eq!(check(&s, &sd), Err(Reason::MissingContext));
    s.absent_claims.push("Secret".into());
    assert_eq!(check(&s, &sd), Ok(()));
}
#[test]
#[ignore = "requires a disposable Peios guest"]
fn missing_local_device_context_never_grants() {
    let s = subject();
    let sd = format!("D:(XA;;0x1;;;{GROUP};(Exists @Device.Managed))");
    assert_eq!(check(&s, &sd), Err(Reason::MissingContext));
}

#[test]
#[ignore = "requires SYSTEM with enabled SeAuditPrivilege in a disposable Peios guest"]
fn audited_network_check_uses_the_actual_caller() {
    let sd = format!("D:(A;;0x1;;;{GROUP})S:(AU;SA;0x1;;;{USER})");
    assert_eq!(check(&subject(), &sd), Ok(()));
}
