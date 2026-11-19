//! Bounded shared entrypoints for coverage-guided fuzzing and corpus replay.
use crate::protocol::{self, Authority, Capture, SyntheticBackend, Tls, SECRET};
use radius_accounting::{
    model::Observation,
    wire::{self, Attribute},
};
use radius_core::{Admission, Client, Engine, Limits, Method, Outcome};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

fn tls() -> &'static Tls {
    static TLS: OnceLock<Tls> = OnceLock::new();
    TLS.get_or_init(Tls::new)
}

/// Exercise both raw datagrams and structured, correctly authenticated frames.
/// Re-signing synthetic frames avoids spending the entire campaign at MAC checks.
pub fn packets(data: &[u8]) {
    if data.len() > 8192 {
        return;
    }
    let _ = radius_core::wire::Request::parse(data, SECRET);
    let _ = wire::Request::parse(data, SECRET, false);
    let _ = wire::Request::parse(data, SECRET, true);
    let sent = wire::dynamic_request(
        43,
        1,
        &[
            Attribute::integer(55, 1),
            Attribute {
                kind: 32,
                value: b"synthetic-nas".to_vec(),
            },
            Attribute {
                kind: 44,
                value: b"synthetic-session".to_vec(),
            },
        ],
        SECRET,
    )
    .unwrap();
    let _ = wire::dynamic_result(data, &sent, SECRET, true);
    let _ = radius_accounting::profile::Profile::parse(data);
    let _ = radius_accounting::dynamic::Profile::parse(data);
    let mut attrs = Vec::new();
    let mut at = 0;
    while at + 2 <= data.len() && attrs.len() < 32 {
        let size = (data[at + 1] as usize).min(96).min(data.len() - at - 2);
        attrs.push(Attribute {
            kind: data[at],
            value: data[at + 2..at + 2 + size].to_vec(),
        });
        at += 2 + size;
    }
    let dynamic_attrs: Vec<_> = attrs.iter().map(|a| (a.kind, a.value.clone())).collect();
    for code in [44, 45] {
        let reply = protocol::dynamic_reply(&sent, code, &dynamic_attrs, true);
        let _ = wire::dynamic_result(&reply, &sent, SECRET, true);
        let valid = protocol::dynamic_reply(&sent, code, &[], true);
        assert_eq!(
            wire::dynamic_result(&valid, &sent, SECRET, true).unwrap(),
            (code == 44, None)
        );
        assert!(wire::dynamic_result(&valid, &sent, b"wrong-secret", true).is_err());
    }
    for ma in [false, true] {
        if let Ok(packet) = wire::request(1, &attrs, SECRET, ma) {
            if let Ok(parsed) = wire::Request::parse(&packet, SECRET, ma) {
                assert_eq!(parsed.canonical, packet);
                assert!(parsed.response(SECRET).unwrap().len() <= wire::MAX_PACKET);
                let _ = Observation::new(
                    &parsed,
                    "synthetic".into(),
                    protocol::address(0, 0).ip(),
                    1_800_000_000_000,
                );
                let mut changed = packet.clone();
                changed[4] ^= 1;
                assert!(wire::Request::parse(&changed, SECRET, ma).is_err());
            }
        }
    }
    let mut packet = protocol::request(1, 0, None, 1, data.get(..data.len().min(512)).unwrap());
    if let Some(&value) = data.first() {
        let offset = 20 + usize::from(value) % (packet.len() - 20);
        packet[offset] ^= data.get(1).copied().unwrap_or(255);
    }
    protocol::resign(&mut packet);
    let _ = radius_core::wire::Request::parse(&packet, SECRET);
}

pub fn engine_sequences(data: &[u8]) {
    if data.len() > 4096 {
        return;
    }
    let mut engine = Engine::new(
        tls().server.clone(),
        Limits {
            attempts: 8,
            per_client: 2,
            cached_replies: 16,
            idle: Duration::from_millis(100),
            overall: Duration::from_secs(1),
            frame_payload: 128,
            ..Default::default()
        },
    )
    .unwrap();
    let mut now = Instant::now();
    let mut state = None;
    let mut eap_id = 0;
    let mut typ = 21;
    let mut previous = protocol::request(1, 0, None, 1, b"anonymous");
    let script = std::iter::once(&[0u8, 0, 0, 0][..]).chain(data.chunks(32).take(128));
    for (i, chunk) in script.enumerate() {
        let command = chunk[0] % 8;
        let client_id = usize::from(chunk.get(1).copied().unwrap_or(0) % 4);
        let mut binding = protocol::binding(client_id);
        let policy = u64::from(chunk.get(2).copied().unwrap_or(0) % 2);
        now += Duration::from_millis(u64::from(chunk.get(3).copied().unwrap_or(0)));
        let packet = match command {
            0 => protocol::request(i as u8, 0, None, 1, b"anonymous"),
            1 => previous.clone(),
            2 | 3 => protocol::request(i as u8, eap_id, state, typ, &chunk[1..]),
            4 => {
                engine.expire(now);
                continue;
            }
            5 => {
                engine.retain_bindings(|b| b.client != client_id as u64);
                continue;
            }
            6 => {
                if let Some(id) = state {
                    if let Ok(reply) = engine.finish(
                        now,
                        id,
                        Client {
                            binding,
                            secret: SECRET,
                            policy_generation: policy,
                        },
                        Admission::BackendFailure,
                    ) {
                        assert_ne!(reply.bytes[0], 2);
                    }
                }
                continue;
            }
            _ => {
                binding.trust_generation += 1;
                protocol::request(i as u8, eap_id, state, typ, &chunk[1..])
            }
        };
        let methods = if chunk.get(4).copied().unwrap_or(0) & 1 == 0 {
            [Method::TtlsPap, Method::PeapMschapv2]
        } else {
            [Method::PeapMschapv2, Method::TtlsPap]
        };
        let outcome = engine.receive_with_methods(
            now,
            protocol::address(client_id, 0),
            Client {
                binding: binding.clone(),
                secret: SECRET,
                policy_generation: policy,
            },
            &packet,
            &methods,
        );
        match outcome {
            Ok(Outcome::Reply(reply)) => {
                assert_ne!(reply.bytes[0], 2, "no successful admission was supplied");
                let (eap, s) = protocol::decoded(&reply.bytes);
                state = s.or(state);
                if eap.len() >= 5 {
                    eap_id = eap[1];
                    typ = eap[4];
                }
            }
            Ok(Outcome::Verify(v)) => {
                if let Ok(reply) = engine.finish(
                    now,
                    v.id(),
                    Client {
                        binding,
                        secret: SECRET,
                        policy_generation: policy,
                    },
                    Admission::Denied,
                ) {
                    assert_ne!(reply.bytes[0], 2);
                }
            }
            _ => {}
        }
        previous = packet;
        assert!(engine.active_attempts() <= 8);
    }
    engine.expire(now + Duration::from_secs(2));
    assert_eq!(engine.active_attempts(), 0);
}

/// Reach real TLS/PAP and the production coordinator before injecting outages,
/// restarts, malformed continuations, replays and clock advances.
pub fn driver_sequences(data: &[u8]) {
    if data.len() > 2048 {
        return;
    }
    let mode = match data.first().copied().unwrap_or(0) % 4 {
        0 => Authority::Failed,
        1 => Authority::Stalled,
        2 => Authority::AccountingFailed,
        _ => Authority::AccountingStalled,
    };
    let config = std::sync::Arc::new(protocol::config(
        tls(),
        1,
        Limits {
            idle: Duration::from_millis(500),
            overall: Duration::from_secs(1),
            attempts: 4,
            per_client: 4,
            ..Default::default()
        },
    ));
    let mut driver = radiusd::driver::Driver::new(config.clone(), SyntheticBackend(mode)).unwrap();
    let mut peer = tls().peer();
    let mut out = Capture {
        lose_events: data.get(1).copied().unwrap_or(0) & 1 != 0,
        ..Default::default()
    };
    let mut now = Instant::now();
    let mut packet = peer.initial();
    let mut used = 0;
    for step in 0..64 {
        if step > 2 {
            let action = data.get(used + 2).copied().unwrap_or(0);
            used += 1;
            match action % 16 {
                1 => {
                    packet.extend_from_slice(&[0; 3]);
                } // Legal datagram padding.
                2 if packet.len() > 38 => {
                    packet[38] ^= action;
                } // Integrity failure.
                3 => {
                    driver.pause();
                }
                4 => {
                    driver.activate(config.clone()).unwrap();
                }
                5 => {
                    now += Duration::from_millis(600);
                }
                6 => {
                    driver = radiusd::driver::Driver::new(config.clone(), SyntheticBackend(mode))
                        .unwrap();
                }
                _ => {}
            }
        }
        driver.receive(now, 0, protocol::address(0, 0), &packet, &mut out);
        driver.tick(now, &mut out);
        let Some((_, reply)) = out.replies.pop_front() else {
            break;
        };
        assert_ne!(
            reply[0], 2,
            "authority or required accounting never approved"
        );
        match peer.respond(&reply) {
            Ok(Some(next)) => packet = next,
            _ => break,
        }
        assert!(driver.pending() <= 4);
    }
    driver.tick(now + Duration::from_secs(2), &mut out);
    assert_eq!(driver.pending(), 0);
    for (_, reply) in out.replies {
        assert_ne!(reply[0], 2);
    }
}

/// Reordered, duplicated and delayed reports must never invent an authenticated
/// subject. Rebuilding is checked against the pre-rebuild projection.
pub fn ledger_sequences(data: &[u8]) {
    use radius_accounting::{
        model::Settings,
        store::{Filter, Store},
    };
    if data.len() > 1024 {
        return;
    }
    let mut store = Store::memory(Settings::default()).unwrap();
    let mut previous = protocol::observation(0, 1, 1_800_000_000_000);
    for (i, chunk) in data.chunks(8).take(64).enumerate() {
        let action = chunk[0] % 6;
        if action == 1 {
            let before = store.health().unwrap().observations;
            let receipt = store.record(&[previous.clone()]).unwrap().remove(0);
            let after = store.health().unwrap().observations;
            let repeated = store.record(&[previous.clone()]).unwrap().remove(0);
            assert_eq!(receipt.id, repeated.id);
            assert_eq!(store.health().unwrap().observations, after);
            assert!(after == before || after == before + 1);
        } else if action == 2 {
            let mut before = store
                .page(
                    &Filter {
                        limit: 100,
                        ..Default::default()
                    },
                    |_| true,
                )
                .unwrap();
            store.rebuild().unwrap();
            let mut after = store
                .page(
                    &Filter {
                        limit: 100,
                        ..Default::default()
                    },
                    |_| true,
                )
                .unwrap();
            // Rebuild intentionally advances the projection revision. All
            // retained session values, including identity and counters, agree.
            for session in before.sessions.iter_mut().chain(after.sessions.iter_mut()) {
                session.revision = 0;
            }
            assert_eq!(
                serde_json::to_value(before.sessions).unwrap(),
                serde_json::to_value(after.sessions).unwrap()
            );
        } else if action == 3 {
            store.maintain(1_800_000_500_000).unwrap();
        } else {
            let session = chunk.get(1).copied().unwrap_or(0) % 4;
            let status = [1, 2, 3][usize::from(chunk.get(2).copied().unwrap_or(0) % 3)];
            let seconds = u32::from(chunk.get(3).copied().unwrap_or(0));
            let attrs = [
                Attribute {
                    kind: 32,
                    value: b"synthetic-nas".to_vec(),
                },
                Attribute {
                    kind: 44,
                    value: vec![session],
                },
                Attribute::integer(40, status),
                Attribute::integer(46, seconds),
                Attribute::integer(55, 1_800_000_000 + seconds),
                Attribute::integer(42, u32::from(chunk.get(4).copied().unwrap_or(0)) * 4096),
            ];
            let bytes = wire::request(i as u8, &attrs, SECRET, true).unwrap();
            let request = wire::Request::parse(&bytes, SECRET, true).unwrap();
            previous = Observation::new(
                &request,
                "synthetic".into(),
                protocol::address(0, 0).ip(),
                1_800_000_500_000,
            )
            .unwrap();
            store.record(&[previous.clone()]).unwrap();
        }
        let page = store
            .page(
                &Filter {
                    limit: 100,
                    ..Default::default()
                },
                |_| true,
            )
            .unwrap();
        for session in page.sessions {
            assert!(session.sid.is_none());
        }
        assert!(store.health().unwrap().observations <= 65);
    }
}

/// Durable CoA/Disconnect intents retain exact targets and idempotency across
/// result updates, duplicates, rebuild and later accounting evidence.
pub fn control_sequences(data: &[u8]) {
    use radius_accounting::{
        dynamic::{Action, Authorization, Intent},
        model::Settings,
        store::{Filter, Store},
    };
    if data.len() > 1024 {
        return;
    }
    let mut store = Store::memory(Settings::default()).unwrap();
    store
        .record(&[protocol::observation(0, 1, 1_800_000_000_000)])
        .unwrap();
    let session = store
        .page(
            &Filter {
                limit: 10,
                ..Default::default()
            },
            |_| true,
        )
        .unwrap()
        .sessions
        .remove(0);
    let target = radius_accounting::dynamic::Target::from_session(&session).unwrap();
    let mut last = None;
    for (i, bytes) in data.chunks(8).take(64).enumerate() {
        match bytes[0] % 5 {
            0 | 1 => {
                let action = [
                    Action::Disconnect,
                    Action::Reauthenticate,
                    Action::UpdateAuthorization,
                ][usize::from(bytes.get(1).copied().unwrap_or(0) % 3)];
                let intent = Intent {
                    intent_key: format!("synthetic-{}", bytes.get(2).copied().unwrap_or(0) % 4),
                    request_id: Some(format!(
                        "request-{}",
                        bytes.get(3).copied().unwrap_or(0) % 8
                    )),
                    session: session.id.clone(),
                    actor: "synthetic-operator".into(),
                    reason: "qualification".into(),
                    action,
                    configuration: "0".repeat(64),
                    desired: Some(Authorization {
                        vlan: Some(1 + u16::from(bytes.get(4).copied().unwrap_or(0))),
                        timeout_seconds: 60,
                    }),
                    fallback: if action != Action::Disconnect {
                        vec![Action::Disconnect]
                    } else {
                        vec![]
                    },
                };
                if let Ok(command) =
                    store.enqueue_dynamic(intent.clone(), 1_800_000_000_000 + i as i64)
                {
                    assert_eq!(command.target.as_ref(), Some(&target));
                    let repeated = store
                        .enqueue_dynamic(intent, 1_800_000_000_000 + i as i64)
                        .unwrap();
                    assert_eq!(command.id, repeated.id);
                    assert_eq!(command.requested_action, repeated.requested_action);
                    last = Some(command);
                }
            }
            2 => {
                if let Some(mut command) = last.clone() {
                    command.state = ["sent", "ack", "nak", "uncertain", "superseded"]
                        [usize::from(bytes.get(1).copied().unwrap_or(0) % 5)]
                    .into();
                    command.attempts = u32::from(bytes.get(2).copied().unwrap_or(0));
                    let _ = store.command_result(&command);
                    let mut forged = command;
                    forged.actor = "different-operator".into();
                    assert!(store.command_result(&forged).is_err());
                }
            }
            3 => {
                store.rebuild().unwrap();
            }
            _ => {
                store
                    .record(&[protocol::observation(0, 1, 1_800_000_000_000)])
                    .unwrap();
            }
        }
        for command in store.command_history(&session.id).unwrap() {
            assert_eq!(command.session, session.id);
            assert_eq!(command.target.as_ref(), Some(&target));
        }
        assert_eq!(store.health().unwrap().observations, 1);
    }
}
