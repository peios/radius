use radius_accounting::{
    dynamic::{Action, NasSelector, Profile, Target},
    wire::Attribute,
};

fn target() -> Target {
    Target {
        source: "192.0.2.10".parse().unwrap(),
        nas: vec![
            Attribute {
                kind: 4,
                value: vec![192, 0, 2, 10],
            },
            Attribute {
                kind: 32,
                value: b"ap".to_vec(),
            },
        ],
        session: b"exact-occurrence".to_vec(),
        station: Some(b"00-11-22-33-44-55".to_vec()),
    }
}

#[test]
fn identifier_only_profile_keeps_exact_session_and_station() {
    let profile = Profile {
        nas_selectors: vec![NasSelector::Identifier],
        ..Default::default()
    };
    let attrs = profile
        .attributes(Action::Disconnect, &target(), None, 1_000)
        .unwrap()
        .unwrap();
    assert!(!attrs.iter().any(|a| a.kind == 4));
    for kind in [32, 44, 31, 55] {
        assert_eq!(attrs.iter().filter(|a| a.kind == kind).count(), 1);
    }
    assert_eq!(
        attrs.iter().find(|a| a.kind == 44).unwrap().value,
        b"exact-occurrence"
    );
    // Selection is a wire recipe; immutable targeting evidence is unchanged.
    assert_eq!(target().nas.len(), 2);
}

#[test]
fn nas_selection_cannot_remove_all_target_scope_or_accept_missing_session() {
    let profile = Profile {
        nas_selectors: vec![NasSelector::Ipv6Address],
        ..Default::default()
    };
    assert!(profile
        .attributes(Action::Disconnect, &target(), None, 1_000)
        .is_err());
    let mut missing = target();
    missing.session.clear();
    assert!(Profile::default()
        .attributes(Action::Disconnect, &missing, None, 1_000)
        .is_err());
}

#[test]
fn legacy_profile_defaults_and_invalid_selector_definitions() {
    let mut value = serde_json::to_value(Profile::default()).unwrap();
    value.as_object_mut().unwrap().remove("nas_selectors");
    let profile = Profile::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    let attrs = profile
        .attributes(Action::Disconnect, &target(), None, 1_000)
        .unwrap()
        .unwrap();
    assert!(attrs.iter().any(|a| a.kind == 4));
    assert!(attrs.iter().any(|a| a.kind == 32));
    for invalid in [
        serde_json::json!([]),
        serde_json::json!(["identifier", "identifier"]),
        serde_json::json!(["username"]),
    ] {
        value["nas_selectors"] = invalid;
        assert!(Profile::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
