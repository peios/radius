use radius_policy::*;
use serde_json::json;
use std::collections::BTreeMap;
const A: &str = "11111111-1111-4111-8111-111111111111";
const B: &str = "22222222-2222-4222-8222-222222222222";
fn profiles() -> Vec<Profile> {
    vec![
        Profile {
            id: A.into(),
            name: "Staff".into(),
            enabled: true,
            vlan: Some(10),
            settings: Default::default(),
        },
        Profile {
            id: B.into(),
            name: "Default".into(),
            enabled: true,
            vlan: None,
            settings: Default::default(),
        },
    ]
}
fn rule(name: &str, action: &str) -> RuleInput {
    RuleInput {
        name: name.into(),
        values: BTreeMap::from([("Actions".into(), json!([action]))]),
        children: vec![],
    }
}
fn assign(name: &str, profile: &str) -> RuleInput {
    rule(name, &format!("ASSIGN({profile})"))
}
fn policy(rules: &[RuleInput]) -> Policy {
    Policy::compile(rules, &profiles()).unwrap()
}
#[test]
fn backstop_and_explicit_default() {
    assert!(policy(&[]).assignment(&Facts::new()).is_err());
    let result = policy(&[assign("default", B)])
        .assignment(&Facts::new())
        .unwrap();
    assert_eq!(result.vlan, None);
    assert_eq!(result.profile, B);
}
#[test]
fn exceptions_shadow_and_abstention_uses_speakers_priority() {
    let mut root = assign("root", A);
    root.values.insert("Priority".into(), json!(5));
    let mut child = rule("child", "NULL");
    child.values.insert("Priority".into(), json!(99));
    root.children.push(child);
    let out = policy(&[root, assign("other", B)])
        .explain(&Facts::new())
        .unwrap();
    assert_eq!(out.assignment.unwrap().profile, A);
    assert_eq!(out.winner.as_deref(), Some("root"));
    assert_eq!(out.candidates[0].priority, 5);
    assert!(out.rules[0].steps.contains(&"ancestor-fallback".into()));
}
#[test]
fn tied_different_profiles_refuse_in_both_orders() {
    for roots in [
        vec![assign("a", A), assign("b", B)],
        vec![assign("b", B), assign("a", A)],
    ] {
        let out = policy(&roots).explain(&Facts::new()).unwrap();
        assert_eq!(out.outcome, "conflicting-profiles");
        assert!(out.assignment.is_none());
    }
}
#[test]
fn agreeing_profiles_are_not_conflicts_and_reject_wins_ties() {
    assert!(policy(&[assign("a", A), assign("b", A)])
        .assignment(&Facts::new())
        .is_ok());
    assert!(policy(&[assign("a", A), rule("b", "REJECT")])
        .assignment(&Facts::new())
        .is_err());
    let mut high = assign("high", A);
    high.values.insert("Priority".into(), json!(1));
    assert!(policy(&[high, rule("low", "REJECT")])
        .assignment(&Facts::new())
        .is_ok());
}
#[test]
fn disabled_parent_hides_child_and_profile_disable_refuses() {
    let mut root = rule("root", "NULL");
    root.values.insert("Enabled".into(), json!(0));
    root.children.push(assign("child", A));
    assert!(policy(&[root]).assignment(&Facts::new()).is_err());
    let mut p = profiles();
    p[0].enabled = false;
    assert!(Policy::compile(&[assign("root", A)], &p)
        .unwrap()
        .assignment(&Facts::new())
        .is_err());
}
#[test]
fn group_any_of_and_conditions_are_conjunctive() {
    let mut root = assign("staff", A);
    root.values.insert(
        "Subject.Group.Equal".into(),
        json!(["S-1-5-32-544", "S-1-5-32-545"]),
    );
    root.values
        .insert("Request.SSID.Equal".into(), json!("Home"));
    let p = policy(&[root]);
    let mut f = Facts::from([(
        "Subject.Group".into(),
        vec![Scalar::Sid("S-1-5-32-545".into())],
    )]);
    assert!(p.assignment(&f).is_err());
    f.insert("Request.SSID".into(), vec![Scalar::String("Home".into())]);
    assert!(p.assignment(&f).is_ok());
}
#[test]
fn claim_types_are_exact_and_full_unsigned_range_survives() {
    for (ty, pattern, value) in [
        ("Int64", json!(i64::MIN), Scalar::Int64(i64::MIN)),
        ("Uint64", json!(u64::MAX), Scalar::Uint64(u64::MAX)),
        ("Boolean", json!(true), Scalar::Boolean(true)),
        ("String", json!("1"), Scalar::String("1".into())),
        (
            "Sid",
            json!("S-1-5-32-544"),
            Scalar::Sid("S-1-5-32-544".into()),
        ),
        ("Octet", json!("00ff"), Scalar::Octet(vec![0, 255])),
    ] {
        let mut r = assign("typed", A);
        r.values
            .insert(format!("Subject.Claim.test.{ty}.Equal"), pattern);
        let p = policy(&[r]);
        assert!(p
            .assignment(&Facts::from([("Subject.Claim.test".into(), vec![value])]))
            .is_ok());
        assert!(p
            .assignment(&Facts::from([(
                "Subject.Claim.test".into(),
                vec![Scalar::Uint64(1)]
            )]))
            .is_err());
    }
}
#[test]
fn missing_claim_does_not_become_false_but_presence_is_explicit() {
    let mut r = assign("false", A);
    r.values
        .insert("Subject.Claim.x.Boolean.Equal".into(), json!(false));
    let p = policy(&[r]);
    assert!(p.assignment(&Facts::new()).is_err());
    assert!(p
        .assignment(&Facts::from([(
            "Subject.Claim.x".into(),
            vec![Scalar::Boolean(false)]
        )]))
        .is_ok());
    let mut r = assign("absent", A);
    r.values
        .insert("Subject.Claim.x.Boolean.Present".into(), json!(0));
    let p = policy(&[r]);
    assert!(p.assignment(&Facts::new()).is_err());
    let mut complete = Facts::new();
    complete.claim_coverage = ClaimCoverage::Complete;
    assert!(p.assignment(&complete).is_ok());
    let mut partial = Facts::new();
    partial.absent_claims.insert("X".into());
    assert!(p.assignment(&partial).is_ok());
    complete.unknown_claims.insert("x".into());
    assert!(p.assignment(&complete).is_err());
}

#[test]
fn claim_names_follow_authd_unicode_equivalence_without_value_folding() {
    let mut r = assign("team", A);
    r.values
        .insert("Subject.Claim.équipe.String.Equal".into(), json!("Team"));
    let p = policy(&[r]);
    let facts = Facts::from([(
        "Subject.Claim.ÉQUIPE".into(),
        vec![Scalar::String("Team".into())],
    )]);
    assert!(p.assignment(&facts).is_ok());
    let facts = Facts::from([(
        "Subject.Claim.Équipe".into(),
        vec![Scalar::String("team".into())],
    )]);
    assert!(p.assignment(&facts).is_err());
    assert!(serde_json::from_value::<Facts>(
        json!({"values":{"Subject.Claim.Équipe":[],"Subject.Claim.équipe":[]}})
    )
    .is_err());
}

#[test]
fn contradictory_claim_knowledge_is_refused_instead_of_guessing() {
    let mut facts = Facts::from([("Subject.Claim.x".into(), vec![Scalar::Boolean(true)])]);
    facts.absent_claims.insert("X".into());
    assert!(validate_facts(&facts).is_err());
}
#[test]
fn unknown_facts_operators_references_and_malformed_patterns_are_errors() {
    for (key, value) in [
        ("Something.Equal", json!("x")),
        ("Subject.User.Regex", json!(".*")),
        ("Subject.Claim.x.Boolean.GreaterThan", json!(1)),
        ("Client.Address.Equal", json!("bad")),
        ("Subject.Group.Equal", json!([])),
        ("Priority", json!(u64::MAX)),
    ] {
        let mut r = assign("invalid", A);
        r.values.insert(key.into(), value);
        assert!(Policy::compile(&[r], &profiles()).is_err(), "{key}");
    }
    assert!(Policy::compile(&[assign("missing", "no-such-profile")], &profiles()).is_err());
}
#[test]
fn explanations_contain_outcomes_without_claim_values() {
    let mut r = assign("staff", A);
    r.values.insert(
        "Subject.Claim.private.String.Equal".into(),
        json!("sensitive"),
    );
    let p = policy(&[r]);
    let f = Facts::from([(
        "Subject.Claim.private".into(),
        vec![Scalar::String("sensitive".into())],
    )]);
    let out = p.explain(&f).unwrap();
    assert!(out.hypothetical);
    assert!(!serde_json::to_string(&out).unwrap().contains("sensitive"));
}
#[test]
fn vlan_validation_and_profile_renames_preserve_assignment() {
    for v in [0, 4095, u16::MAX] {
        let mut p = profiles();
        p[0].vlan = Some(v);
        assert!(Policy::compile(&[], &p).is_err());
    }
    let mut p = profiles();
    p[0].name = "Renamed".into();
    assert_eq!(
        Policy::compile(&[assign("root", A)], &p)
            .unwrap()
            .assignment(&Facts::new())
            .unwrap()
            .profile,
        A
    );
}
#[test]
fn address_and_station_use_shared_pnp_patterns() {
    let mut r = assign("lan", A);
    r.values
        .insert("Client.Address.Equal".into(), json!("10.10.0.0/16"));
    r.values
        .insert("Request.Station.Equal".into(), json!("aa:bb:cc:dd:ee:ff"));
    let f = Facts::from([
        (
            "Client.Address".into(),
            vec![Scalar::Address("10.10.1.2".parse().unwrap())],
        ),
        (
            "Request.Station".into(),
            vec![Scalar::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])],
        ),
    ]);
    assert!(policy(&[r]).assignment(&f).is_ok());
}
