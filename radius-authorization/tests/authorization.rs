use radius_authorization::*;
use serde_json::json;

fn settings(value: serde_json::Value) -> Settings {
    let value: Settings = serde_json::from_value(value).unwrap();
    value.validate().unwrap();
    value
}
fn wispr() -> Mappings {
    serde_json::from_value(json!({"settings":{
        "UploadBitsPerSecond":[{"target":{"vendor":14122,"attribute":7},"format":"integer32"}],
        "DownloadBitsPerSecond":[{"target":{"vendor":14122,"attribute":8},"format":"integer32"}]
    },"live":["UploadBitsPerSecond","DownloadBitsPerSecond"]}))
    .unwrap()
}

#[test]
fn standard_families_have_independent_wire_vectors() {
    let value = settings(json!({
        "IdleTimeoutSeconds":120,"IngressFiltering":true,
        "TaggedVlans":["20"],"UntaggedVlans":["30"],
        "UserPriorityTable":"01234567","FilterIds":["guest","limited"],
        "FilterRules":["permit in 6 from any to 192.0.2.0/24 443"],
        "FramedIpv4Address":"192.0.2.9","FramedIpv4Netmask":"255.255.255.0",
        "Ipv4Routes":["198.51.100.0/24 192.0.2.1 1"],
        "FramedIpv6Address":"2001:db8::9","FramedIpv6Prefix":"2001:db8:1::/64",
        "DelegatedIpv6Prefix":"2001:db8:100::/56","DelegatedIpv6Pool":"customer",
        "Ipv6DnsServers":["2001:db8::53"],"Ipv6Routes":["2001:db8:2::/64 2001:db8::1 2"],
        "Mtu":1500,"AccountingInterimSeconds":60,"ManagementProtocol":2,"ServiceType":18,
        "ManagementTransportProtection":1,"ManagementPolicyId":"operators",
        "ManagementPrivilegeLevel":5,"ServiceLabel":"Guest network"
    }));
    let reply = value.compile(None, &Mappings::default()).unwrap();
    let find = |kind| {
        reply
            .attributes
            .iter()
            .find(|a| a.kind == kind)
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(find(28), [0, 0, 0, 120]);
    assert_eq!(find(56), [0x31, 0, 0, 20]);
    assert_eq!(
        reply
            .attributes
            .iter()
            .filter(|a| a.kind == 56)
            .nth(1)
            .unwrap()
            .value,
        [0x32, 0, 0, 30]
    );
    assert_eq!(find(57), [0, 0, 0, 1]);
    assert_eq!(find(59), [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(find(8), [192, 0, 2, 9]);
    assert_eq!(find(97), [0, 64, 0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0]);
    assert_eq!(find(123), [0, 56, 0x20, 1, 0x0d, 0xb8, 1, 0, 0]);
    assert_eq!(find(171), b"customer");
    assert_eq!(find(136), [0, 0, 0, 5]);
    assert_eq!(reply.attributes.iter().filter(|a| a.kind == 11).count(), 2);
    assert!(!reply.encoded.contains_key("ServiceLabel"));
    assert_eq!(
        serde_json::from_slice::<Compiled>(&serde_json::to_vec(&reply).unwrap()).unwrap(),
        reply
    );
}

#[test]
fn named_vlan_and_non_vlan_tunnels_use_distinct_standard_encodings() {
    let named = settings(json!({"VlanName":"Guests"}))
        .compile(None, &Mappings::default())
        .unwrap();
    assert_eq!(
        named.attributes,
        vec![Attribute {
            kind: 58,
            value: b"\x32Guests".to_vec()
        }]
    );
    assert!(named
        .settings
        .compile(Some(20), &Mappings::default())
        .is_err());
    let tunnel=settings(json!({"TunnelType":3,"TunnelMediumType":1,"TunnelClientEndpoint":"192.0.2.1","TunnelServerEndpoint":"192.0.2.2","TunnelPreference":1,"TunnelAssignmentId":"vpn"})).compile(None,&Mappings::default()).unwrap();
    assert_eq!(tunnel.encoded["TunnelType"][0].value, [0, 0, 0, 3]);
    assert_eq!(tunnel.encoded["TunnelPreference"][0].value, [0, 0, 0, 1]);
}

#[test]
fn vendor_rates_are_exact_and_do_not_truncate() {
    let value =
        settings(json!({"DownloadBitsPerSecond":10_000_000,"UploadBitsPerSecond":2_000_000}));
    assert!(value.compile(None, &Mappings::default()).is_err());
    let reply = value.compile(None, &wispr()).unwrap();
    assert_eq!(
        reply.encoded["DownloadBitsPerSecond"][0].value,
        [0, 0, 55, 42, 8, 6, 0, 152, 150, 128]
    );
    assert!(settings(json!({"DownloadBitsPerSecond":10_000_000_000u64}))
        .compile(None, &wispr())
        .is_err());
    let mut mapping = wispr();
    mapping.settings.get_mut("DownloadBitsPerSecond").unwrap()[0].divisor = 1000;
    assert!(settings(json!({"DownloadBitsPerSecond":10_000_001}))
        .compile(None, &mapping)
        .is_err());
}

#[test]
fn unsupported_or_conflicting_encodings_cannot_silently_drop_settings() {
    let mut mapping = wispr();
    mapping
        .settings
        .insert("DownloadBitsPerSecond".into(), vec![]);
    assert!(settings(json!({"DownloadBitsPerSecond":100}))
        .compile(None, &mapping)
        .is_err());
    mapping = wispr();
    mapping.settings.insert(
        "UploadBitsPerSecond".into(),
        mapping.settings["DownloadBitsPerSecond"].clone(),
    );
    assert!(
        settings(json!({"UploadBitsPerSecond":100,"DownloadBitsPerSecond":100}))
            .compile(None, &mapping)
            .is_err()
    );
    for target in [1, 2, 24, 25, 33, 44, 79, 80] {
        let mapping: Mappings = serde_json::from_value(
            json!({"settings":{"AccessRole":[{"target":{"attribute":target},"format":"text"}]}}),
        )
        .unwrap();
        assert!(mapping.validate().is_err());
    }
    let mapping:Mappings=serde_json::from_value(json!({"settings":{"AccessRole":[{"target":{"vendor":311,"attribute":16},"format":"text"}]}})).unwrap();
    assert!(mapping.validate().is_err());
}

#[test]
fn live_removal_needs_a_qualified_reset_of_the_previous_exact_attribute() {
    let mut mapping = wispr();
    let before = settings(json!({"DownloadBitsPerSecond":100}))
        .compile(None, &mapping)
        .unwrap();
    let after = Settings::default().compile(None, &mapping).unwrap();
    assert!(mapping.updates(&before, &after).is_err());
    let mut reset = before.attributes[0].clone();
    reset.value[6..].copy_from_slice(&0u32.to_be_bytes());
    mapping
        .clear
        .insert("DownloadBitsPerSecond".into(), vec![reset.clone()]);
    assert_eq!(mapping.updates(&before, &after).unwrap(), vec![reset]);
    mapping.live.clear();
    assert!(mapping.updates(&before, &after).is_err());
}

#[test]
fn a_changed_mapping_does_not_reinterpret_the_old_reset_target() {
    let mut mapping = wispr();
    let before = settings(json!({"DownloadBitsPerSecond":100}))
        .compile(None, &mapping)
        .unwrap();
    mapping.settings.get_mut("DownloadBitsPerSecond").unwrap()[0]
        .target
        .attribute = 9;
    let after = Settings::default().compile(None, &mapping).unwrap();
    let mut wrong = before.attributes[0].clone();
    wrong.value[4] = 9;
    mapping
        .clear
        .insert("DownloadBitsPerSecond".into(), vec![wrong]);
    assert!(mapping.updates(&before, &after).is_err());
}

#[test]
fn timers_do_not_extend_network_policy_and_actions_are_explicit() {
    assert_eq!(Settings::default().timer(3600), (3600, false));
    assert_eq!(
        settings(json!({"ReauthenticateSeconds":600})).timer(3600),
        (600, false)
    );
    assert_eq!(
        settings(json!({"ReauthenticateSeconds":7200})).timer(3600),
        (3600, false)
    );
    assert_eq!(
        settings(json!({"SessionTimeoutSeconds":300})).timer(3600),
        (300, true)
    );
    assert_eq!(
        settings(json!({"SessionTimeoutSeconds":300,"SessionExpiryAction":"reauthenticate"}))
            .timer(3600),
        (300, false)
    );
}

#[test]
fn malformed_settings_fail_before_wire_encoding() {
    for invalid in [
        json!({"IdleTimeoutSeconds":0}),
        json!({"IdleTimeoutSeconds":"10"}),
        json!({"DownloadBitsPerSecond":100,"MinimumDownloadBitsPerSecond":200}),
        json!({"TaggedVlans":["0"]}),
        json!({"TaggedVlans":["20","20"]}),
        json!({"TaggedVlans":["020"]}),
        json!({"TaggedVlans":["20"],"UntaggedVlans":["20"]}),
        json!({"TaggedVlanNames":["Staff"],"UntaggedVlanNames":["Staff"]}),
        json!({"FramedIpv6Prefix":"2001:db8::1/64"}),
        json!({"FramedIpv6Prefix":"::/129"}),
        json!({"FramedIpv4Address":"bad"}),
        json!({"FramedIpv4Netmask":"255.0.255.0"}),
        json!({"AccountingInterimSeconds":1}),
        json!({"FilterRules":["run arbitrary code"]}),
        json!({"Ipv4Routes":["192.0.2.1/24 192.0.2.1"]}),
        json!({"ReauthenticateSeconds":10,"SessionTimeoutSeconds":20}),
        json!({"TunnelType":3}),
        json!({"State":"forged"}),
        json!({"ServiceType":17}),
        json!({"SessionExpiryAction":"disconnect"}),
    ] {
        let value: Settings = serde_json::from_value(invalid.clone()).unwrap();
        assert!(value.validate().is_err(), "{invalid}");
    }
    assert!(settings(json!({"TaggedVlans":["20"]}))
        .compile(Some(20), &Default::default())
        .is_err());
}

#[test]
fn all_setting_groups_are_bounded_by_the_complete_reply_budget() {
    let mut value = Settings::default();
    value.0.insert(
        "FilterIds".into(),
        Value::List((0..32).map(|n| format!("{n:0240}")).collect()),
    );
    assert!(value.compile(None, &Mappings::default()).is_err());
    let mut compiled = settings(json!({"FilterIds":["guest"]}))
        .compile(None, &Mappings::default())
        .unwrap();
    compiled.attributes[0].value = b"different".to_vec();
    assert!(compiled.validate().is_err());
}

#[test]
fn text_vendor_encodings_preserve_units_affixes_and_types() {
    let mappings:Mappings=serde_json::from_value(json!({"settings":{
        "DownloadBitsPerSecond":[{"target":{"vendor":12345,"attribute":1},"format":"decimal-text","divisor":1000,"prefix":"rate=","suffix":"k"}],
        "ClientIsolation":[{"target":{"vendor":12345,"attribute":2},"format":"boolean-integer"}],
        "Extension.example.role":[{"target":{"vendor":12345,"attribute":3},"format":"text","prefix":"role="}]
    }})).unwrap();
    let reply=settings(json!({"DownloadBitsPerSecond":10_000_000,"ClientIsolation":true,"Extension.example.role":"guest"})).compile(None,&mappings).unwrap();
    assert_eq!(
        &reply.encoded["DownloadBitsPerSecond"][0].value[6..],
        b"rate=10000k"
    );
    assert_eq!(
        &reply.encoded["ClientIsolation"][0].value[6..],
        &[0, 0, 0, 1]
    );
    assert_eq!(
        &reply.encoded["Extension.example.role"][0].value[6..],
        b"role=guest"
    );
    assert!(settings(json!({"DownloadBitsPerSecond":10_000_001}))
        .compile(None, &mappings)
        .is_err());
}

#[test]
fn deserialized_proofs_cannot_drop_a_required_setting_or_carry_a_noncanonical_prefix() {
    let mut reply = settings(json!({"IdleTimeoutSeconds":120}))
        .compile(None, &Default::default())
        .unwrap();
    reply.encoded.clear();
    reply.attributes.clear();
    assert!(reply.validate().is_err());
    assert!(Attribute {
        kind: 97,
        value: vec![0, 1, 0x81]
    }
    .validate()
    .is_err());
    assert!(Attribute {
        kind: 97,
        value: vec![0, 1, 0x80]
    }
    .validate()
    .is_ok());
    // Calling the lower-level mapping entry point still validates before
    // arithmetic such as decoding the eight priority digits.
    let invalid: Settings =
        serde_json::from_value(json!({"UserPriorityTable":"!!!!!!!!"})).unwrap();
    assert!(Mappings::default().compile(&invalid, None).is_err());
}

#[test]
fn membership_updates_preserve_an_unchanged_companion_attribute_family() {
    let mut mappings = Mappings::default();
    mappings.live.insert("TaggedVlans".into());
    let old = settings(json!({"TaggedVlans":["20"],"UntaggedVlans":["30"]}))
        .compile(None, &mappings)
        .unwrap();
    let new = settings(json!({"TaggedVlans":["40"],"UntaggedVlans":["30"]}))
        .compile(None, &mappings)
        .unwrap();
    let attrs = mappings.updates(&old, &new).unwrap();
    assert_eq!(
        attrs,
        vec![
            Attribute {
                kind: 56,
                value: vec![0x31, 0, 0, 40]
            },
            Attribute {
                kind: 56,
                value: vec![0x32, 0, 0, 30]
            }
        ]
    );
}
