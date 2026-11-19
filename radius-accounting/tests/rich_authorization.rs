use radius_accounting::{
    dynamic::{Action, Authorization, Profile, Target},
    wire::Attribute,
};
use serde_json::json;
fn value(settings: serde_json::Value, mappings: &radius_authorization::Mappings) -> Authorization {
    let settings: radius_authorization::Settings = serde_json::from_value(settings).unwrap();
    Authorization {
        vlan: Some(20),
        timeout_seconds: 60,
        configured_timeout_seconds: Some(300),
        attributes: settings.compile(Some(20), mappings).unwrap(),
    }
}
fn target() -> Target {
    Target {
        source: "192.0.2.1".parse().unwrap(),
        nas: vec![Attribute {
            kind: 32,
            value: b"synthetic-nas".to_vec(),
        }],
        session: b"exact-session".to_vec(),
        station: None,
    }
}
#[test]
fn live_updates_require_capabilities_and_keep_exact_session_selectors() {
    let old = value(json!({"IdleTimeoutSeconds":120}), &Default::default());
    let desired = value(json!({"IdleTimeoutSeconds":60}), &Default::default());
    let mut profile = Profile::default();
    assert!(profile
        .attributes_with_previous(
            Action::UpdateAuthorization,
            &target(),
            Some(&desired),
            Some(&old),
            1_800_000_000_000
        )
        .unwrap()
        .is_none());
    profile
        .authorization
        .live
        .insert("IdleTimeoutSeconds".into());
    let attrs = profile
        .attributes_with_previous(
            Action::UpdateAuthorization,
            &target(),
            Some(&desired),
            Some(&old),
            1_800_000_000_000,
        )
        .unwrap()
        .unwrap();
    assert!(attrs
        .iter()
        .any(|a| a.kind == 44 && a.value == b"exact-session"));
    assert!(attrs
        .iter()
        .any(|a| a.kind == 28 && a.value == 60u32.to_be_bytes()));
    assert!(attrs
        .iter()
        .any(|a| a.kind == 29 && a.value == 1u32.to_be_bytes()));
}
#[test]
fn allowance_changes_do_not_change_the_policy_identity() {
    let mut old = value(json!({"IdleTimeoutSeconds":120}), &Default::default());
    let mut desired = old.clone();
    desired.timeout_seconds = 30;
    assert!(desired.same_policy(&old));
    desired.configured_timeout_seconds = Some(100);
    assert!(!desired.same_policy(&old));
    old.timeout_seconds = 301;
    assert!(old.validate().is_err());
}
#[test]
fn removal_requires_reset_and_termination_action_can_return_to_reauthentication() {
    let old = value(
        json!({"SessionTimeoutSeconds":60,"IdleTimeoutSeconds":120}),
        &Default::default(),
    );
    let desired = value(json!({}), &Default::default());
    let mut profile = Profile::default();
    profile
        .authorization
        .live
        .insert("IdleTimeoutSeconds".into());
    assert!(profile
        .attributes_with_previous(
            Action::UpdateAuthorization,
            &target(),
            Some(&desired),
            Some(&old),
            1_800_000_000_000
        )
        .unwrap()
        .is_none());
    profile.authorization.clear.insert(
        "IdleTimeoutSeconds".into(),
        vec![radius_authorization::Attribute {
            kind: 28,
            value: 0u32.to_be_bytes().to_vec(),
        }],
    );
    let attrs = profile
        .attributes_with_previous(
            Action::UpdateAuthorization,
            &target(),
            Some(&desired),
            Some(&old),
            1_800_000_000_000,
        )
        .unwrap()
        .unwrap();
    assert!(attrs
        .iter()
        .any(|a| a.kind == 28 && a.value == 0u32.to_be_bytes()));
    assert!(attrs
        .iter()
        .any(|a| a.kind == 29 && a.value == 1u32.to_be_bytes()));
}

#[test]
fn custom_recipes_cannot_claim_a_timer_they_did_not_send() {
    use radius_accounting::dynamic::Value;
    let old = value(json!({}), &Default::default());
    let desired = value(json!({"SessionTimeoutSeconds":60}), &Default::default());
    let mut profile = Profile::default();
    let recipe = profile
        .recipes
        .iter_mut()
        .find(|r| r.action == Action::UpdateAuthorization)
        .unwrap();
    recipe
        .attributes
        .iter_mut()
        .find(|a| a.kind == 27)
        .unwrap()
        .value = Value::Integer(999);
    assert!(profile
        .attributes_with_previous(
            Action::UpdateAuthorization,
            &target(),
            Some(&desired),
            Some(&old),
            1_800_000_000_000
        )
        .unwrap()
        .is_none());
    let recipe = profile
        .recipes
        .iter_mut()
        .find(|r| r.action == Action::UpdateAuthorization)
        .unwrap();
    recipe
        .attributes
        .iter_mut()
        .find(|a| a.kind == 27)
        .unwrap()
        .value = Value::Timeout;
    recipe
        .attributes
        .push(radius_accounting::dynamic::Encoding {
            kind: 29,
            vendor: None,
            value: Value::Integer(1),
        });
    assert!(profile
        .attributes_with_previous(
            Action::UpdateAuthorization,
            &target(),
            Some(&desired),
            Some(&old),
            1_800_000_000_000
        )
        .unwrap()
        .is_none());
}

#[test]
fn legacy_proof_json_defaults_to_no_rich_settings() {
    let old: Authorization =
        serde_json::from_value(json!({"vlan":20,"timeout_seconds":60})).unwrap();
    old.validate().unwrap();
    assert_eq!(old.attributes, Default::default());
    assert_eq!(old.configured_timeout_seconds, None);
}
