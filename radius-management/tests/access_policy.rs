use radius_management::{
    access_policy,
    model::{Kind, Record, Stored, Value, Values, SCHEMA},
};
const POLICY: &str = "11111111-1111-4111-8111-111111111111";
const PROFILE: &str = "22222222-2222-4222-8222-222222222222";
const ROOT: &str = "33333333-3333-4333-8333-333333333333";
const CHILD: &str = "44444444-4444-4444-8444-444444444444";
fn record(kind: Kind, id: &str) -> Record {
    let mut r = Record::new(kind, "Test").unwrap();
    r.id = id.into();
    r
}
fn fixture() -> Stored {
    let policy = record(Kind::Policy, POLICY);
    let profile = record(Kind::AccessProfile, PROFILE);
    let mut root = record(Kind::Rule, ROOT);
    root.values
        .insert("Policy".into(), Value::Text(POLICY.into()));
    root.values.insert("Priority".into(), Value::Number(5));
    root.values
        .insert("Actions".into(), Value::Text(format!("ASSIGN({PROFILE})")));
    let mut child = record(Kind::Rule, CHILD);
    child
        .values
        .insert("Policy".into(), Value::Text(POLICY.into()));
    child
        .values
        .insert("Parent".into(), Value::Text(ROOT.into()));
    Stored {
        settings: Values::from([("SchemaVersion".into(), Value::Number(SCHEMA))]),
        objects: vec![policy, profile, root, child],
        issues: vec![],
    }
}
#[test]
fn accounting_accepts_implicit_enabled_rules_but_rejects_malformed_flags() {
    let mut stored = fixture();
    let root = stored.objects.iter_mut().find(|r| r.id == ROOT).unwrap();
    root.values.remove("Enabled");
    assert!(radius_management::accounting::prepare(&stored).is_ok());
    let root = stored.objects.iter_mut().find(|r| r.id == ROOT).unwrap();
    root.values
        .insert("Enabled".into(), Value::Text("yes".into()));
    assert!(radius_management::accounting::prepare(&stored).is_err());
    let root = stored.objects.iter_mut().find(|r| r.id == ROOT).unwrap();
    root.values.insert("Enabled".into(), Value::Number(2));
    assert!(radius_management::accounting::prepare(&stored).is_err());
}
#[test]
fn nested_registry_paths_and_parent_fallback_use_the_same_compilation() {
    let stored = fixture();
    let child = stored.get(Kind::Rule, CHILD).unwrap();
    assert_eq!(
        child.path(),
        format!("Machine\\Software\\Radius\\AccessPolicies\\{POLICY}\\Rules\\{ROOT}\\{CHILD}")
    );
    let policy = access_policy::compile(&stored, POLICY).unwrap();
    let result = policy.explain(&radius_policy::Facts::new()).unwrap();
    assert_eq!(result.assignment.unwrap().profile, PROFILE);
    assert_eq!(result.winner.as_deref(), Some(ROOT));
    assert_eq!(result.candidates[0].priority, 5);
}
#[test]
fn shared_profile_references_are_visible_even_for_scalar_actions() {
    let stored = fixture();
    let uses = stored.dependents(Kind::AccessProfile, PROFILE);
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].id, ROOT);
    assert_eq!(stored.dependents(Kind::Rule, ROOT)[0].id, CHILD);
}
#[test]
fn broken_parent_and_missing_profile_are_refused() {
    let mut stored = fixture();
    stored
        .objects
        .iter_mut()
        .find(|r| r.id == CHILD)
        .unwrap()
        .values
        .insert("Parent".into(), Value::Text(PROFILE.into()));
    assert!(access_policy::compile(&stored, POLICY).is_err());
    let mut stored = fixture();
    stored.objects.retain(|r| r.kind != Kind::AccessProfile);
    assert!(access_policy::compile(&stored, POLICY).is_err());
}
#[test]
fn no_rules_is_a_valid_forest_with_a_refusing_backstop() {
    let mut stored = fixture();
    stored.objects.retain(|r| r.kind != Kind::Rule);
    assert!(access_policy::compile(&stored, POLICY)
        .unwrap()
        .assignment(&radius_policy::Facts::new())
        .is_err());
}
#[test]
fn unknown_profile_fields_and_bad_vlan_types_cannot_silently_remove_isolation() {
    for (name, value) in [
        ("VlanId", Value::Text("20".into())),
        ("VlanID", Value::Number(20)),
        ("VlanId", Value::Number(0)),
        ("VlanId", Value::Number(4095)),
    ] {
        let mut profile = record(Kind::AccessProfile, PROFILE);
        profile.values.insert(name.into(), value);
        assert!(access_policy::profile(&profile).is_err());
    }
}
#[test]
fn policy_scope_isolation_prevents_cross_network_parentage() {
    let mut stored = fixture();
    let mut other = record(Kind::Policy, "55555555-5555-4555-8555-555555555555");
    other
        .values
        .insert("SSID".into(), Value::Text("Other".into()));
    stored.objects.push(other.clone());
    stored
        .objects
        .iter_mut()
        .find(|r| r.id == CHILD)
        .unwrap()
        .values
        .insert("Policy".into(), Value::Text(other.id.clone()));
    assert!(access_policy::compile(&stored, &other.id).is_err());
}
