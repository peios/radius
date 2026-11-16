use radius_management::model::{new_id, valid_id, Kind, Record, Stored, Value, Values};
const CLIENT: &str = "11111111-1111-4111-8111-111111111111";
const POLICY: &str = "22222222-2222-4222-8222-222222222222";
const PROFILE: &str = "33333333-3333-4333-8333-333333333333";
const IDENTITY: &str = "44444444-4444-4444-8444-444444444444";
fn record(kind: Kind, id: &str, fields: &[(&str, Value)]) -> Record {
    let mut r = Record {
        kind,
        id: id.into(),
        values: Values::from([("Name".into(), Value::Text(format!("{kind:?}")))]),
    };
    if kind != Kind::Identity {
        r.values.insert("Enabled".into(), Value::Number(1));
    }
    r.values
        .extend(fields.iter().map(|(n, v)| (n.to_string(), v.clone())));
    r
}
fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn list(s: &[&str]) -> Value {
    Value::List(s.iter().map(|s| s.to_string()).collect())
}
fn setup() -> Stored {
    Stored {
        settings: Values::from([("SchemaVersion".into(), Value::Number(2))]),
        issues: vec![],
        objects: vec![
            record(
                Kind::Client,
                CLIENT,
                &[
                    ("Addresses", list(&["192.0.2.0/24"])),
                    ("SecretFile", text("/var/state/radius/secret")),
                    ("Policies", list(&[POLICY])),
                ],
            ),
            record(
                Kind::Policy,
                POLICY,
                &[
                    ("SSID", text("Home")),
                    ("ConnectSecurity", text("O:SYD:(A;;0x1;;;AU)")),
                    ("AuthenticationProfile", text(PROFILE)),
                    ("ReauthenticateSeconds", Value::Number(3600)),
                ],
            ),
            record(
                Kind::Profile,
                PROFILE,
                &[
                    (
                        "AuthenticationMethods",
                        list(&["peap-mschapv2", "ttls-pap"]),
                    ),
                    ("ServerIdentity", text(IDENTITY)),
                ],
            ),
            record(
                Kind::Identity,
                IDENTITY,
                &[
                    ("CertificateFiles", list(&["/var/state/radius/server.der"])),
                    ("PrivateKeyFile", text("/var/state/radius/key.der")),
                ],
            ),
        ],
    }
}
#[test]
fn display_renames_preserve_references_and_authentication_identity() {
    let mut stored = setup();
    assert!(stored.validate().is_empty());
    let before = stored.authentication_fingerprint();
    let saved = stored.fingerprint();
    stored.objects[1]
        .values
        .insert("Name".into(), text("Household"));
    assert_eq!(
        stored.resolve(Kind::Policy, "Household").unwrap().id,
        POLICY
    );
    assert_eq!(stored.dependents(Kind::Policy, POLICY).len(), 1);
    assert!(stored.validate().is_empty());
    assert_eq!(before, stored.authentication_fingerprint());
    assert_ne!(saved, stored.fingerprint());
}
#[test]
fn deleted_and_recreated_objects_do_not_satisfy_old_references() {
    let mut stored = setup();
    stored.objects[1].id = new_id().unwrap();
    let issues = stored.validate();
    assert!(issues
        .iter()
        .any(|i| i.object == CLIENT && i.message.contains(POLICY)));
    assert_eq!(stored.objects[0].list("Policies").unwrap(), &[POLICY]);
}
#[test]
fn disabled_is_valid_and_does_not_hide_broken_references() {
    let mut stored = setup();
    for r in &mut stored.objects {
        if r.kind != Kind::Identity {
            r.values.insert("Enabled".into(), Value::Number(0));
        }
    }
    assert!(stored.validate().is_empty());
    stored.objects.retain(|r| r.kind != Kind::Profile);
    assert!(stored
        .validate()
        .iter()
        .any(|i| i.object == POLICY && i.message.contains(PROFILE)));
}
#[test]
fn duplicate_labels_require_a_guid() {
    let mut stored = setup();
    let mut copy = stored.objects[1].clone();
    copy.id = new_id().unwrap();
    stored.objects.push(copy);
    assert!(stored
        .resolve(Kind::Policy, "Policy")
        .unwrap_err()
        .contains("ambiguous"));
    assert_eq!(stored.resolve(Kind::Policy, POLICY).unwrap().id, POLICY);
}
#[test]
fn invalid_values_remain_inspectable_for_repair() {
    let mut stored = setup();
    stored.objects[0]
        .values
        .insert("Addresses".into(), Value::Number(42));
    let data = serde_json::to_string(&stored).unwrap();
    let copy: Stored = serde_json::from_str(&data).unwrap();
    assert_eq!(copy.objects[0].number("Addresses"), Some(42));
    assert!(copy.validate().iter().any(|i| i.field == "Addresses"));
}
#[test]
fn method_lists_are_explicit_and_ordered() {
    let mut stored = setup();
    let before = stored.authentication_fingerprint();
    stored.objects[2].values.insert(
        "AuthenticationMethods".into(),
        list(&["ttls-pap", "peap-mschapv2"]),
    );
    assert!(stored.validate().is_empty());
    assert_ne!(before, stored.authentication_fingerprint());
    for methods in [&["ttls-pap", "ttls-pap"][..], &["unknown"][..], &[][..]] {
        stored.objects[2]
            .values
            .insert("AuthenticationMethods".into(), list(methods));
        assert!(!stored.validate().is_empty());
    }
}
#[test]
fn identifiers_are_canonical_random_v4_and_safe_registry_leaves() {
    let a = new_id().unwrap();
    let b = new_id().unwrap();
    assert_ne!(a, b);
    assert!(valid_id(&a));
    for id in [
        "",
        "../Settings",
        "22222222-2222-1222-8222-222222222222",
        "22222222-2222-4222-2222-222222222222",
        "22222222-2222-4222-8222-22222222222G",
    ] {
        assert!(!valid_id(id));
    }
}
