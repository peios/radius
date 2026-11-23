use crate::*;
use hmac::{Hmac, Mac};
use md5::Md5;
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore,
};
use std::{
    io::{Cursor, Write},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

const SECRET: &[u8] = b"test-radius-secret-at-least-16";

#[test]
fn complete_authorization_is_signed_and_only_available_on_accept() {
    use md5::Digest;
    let settings: radius_authorization::Settings = serde_settings();
    let compiled = settings.compile(None, &Default::default()).unwrap();
    let request_auth = [42; 16];
    let reply = crate::wire::response_with_authorization(
        7,
        &request_auth,
        SECRET,
        2,
        &[3, 1, 0, 4],
        None,
        None,
        Some(60),
        None,
        None,
        Some(&compiled),
    )
    .unwrap();
    let mut attrs = Vec::new();
    let mut at = 20;
    while at < reply.len() {
        let length = reply[at + 1] as usize;
        attrs.push((reply[at], reply[at + 2..at + length].to_vec()));
        at += length;
    }
    assert!(attrs.contains(&(28, 120u32.to_be_bytes().to_vec())));
    assert!(attrs.contains(&(11, b"guest".to_vec())));
    assert!(attrs.contains(&(29, 0u32.to_be_bytes().to_vec())));
    let mut signed = reply.clone();
    signed[4..20].copy_from_slice(&request_auth);
    let ma = signed[22..38].to_vec();
    signed[22..38].fill(0);
    let mut mac = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    mac.update(&signed);
    assert_eq!(ma, mac.finalize().into_bytes().as_slice());
    signed[22..38].copy_from_slice(&ma);
    let mut digest = Md5::new();
    Digest::update(&mut digest, &signed);
    Digest::update(&mut digest, SECRET);
    assert_eq!(&reply[4..20], digest.finalize().as_slice());
    for code in [3, 11] {
        assert!(crate::wire::response_with_authorization(
            7,
            &request_auth,
            SECRET,
            code,
            &[4, 1, 0, 4],
            None,
            None,
            None,
            None,
            None,
            Some(&compiled)
        )
        .is_err());
    }
    fn serde_settings() -> radius_authorization::Settings {
        use radius_authorization::{Settings, Value};
        Settings(std::collections::BTreeMap::from([
            ("IdleTimeoutSeconds".into(), Value::Number(120)),
            ("FilterIds".into(), Value::List(vec!["guest".into()])),
            ("SessionTimeoutSeconds".into(), Value::Number(60)),
        ]))
    }
}

#[test]
fn vlan_assignment_is_atomic_tagged_consistently_and_integrity_protected() {
    use md5::Digest;
    let request_auth = [42; 16];
    let reply = crate::wire::response_with_policy(
        7,
        &request_auth,
        SECRET,
        2,
        &[3, 1, 0, 4],
        None,
        None,
        Some(60),
        Some(b"reference"),
        Some(4094),
    )
    .unwrap();
    let mut attributes = Vec::new();
    let mut pos = 20;
    while pos < reply.len() {
        let len = reply[pos + 1] as usize;
        attributes.push((reply[pos], reply[pos + 2..pos + len].to_vec()));
        pos += len;
    }
    assert_eq!(
        attributes
            .iter()
            .filter(|(k, _)| matches!(*k, 64 | 65 | 81))
            .cloned()
            .collect::<Vec<_>>(),
        vec![
            (64, vec![0, 0, 0, 13]),
            (65, vec![0, 0, 0, 6]),
            (81, b"\x004094".to_vec())
        ]
    );
    let mut signed = reply.clone();
    signed[4..20].copy_from_slice(&request_auth);
    let expected_ma = signed[22..38].to_vec();
    signed[22..38].fill(0);
    let mut mac = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    mac.update(&signed);
    assert_eq!(expected_ma, mac.finalize().into_bytes().as_slice());
    signed[22..38].copy_from_slice(&expected_ma);
    let mut digest = Md5::new();
    Digest::update(&mut digest, &signed);
    Digest::update(&mut digest, SECRET);
    assert_eq!(&reply[4..20], digest.finalize().as_slice());
    for code in [3, 11] {
        assert!(crate::wire::response_with_policy(
            7,
            &request_auth,
            SECRET,
            code,
            &[4, 1, 0, 4],
            None,
            None,
            None,
            None,
            Some(10)
        )
        .is_err());
    }
    for vlan in [0, 4095] {
        assert!(crate::wire::response_with_policy(
            7,
            &request_auth,
            SECRET,
            2,
            &[3, 1, 0, 4],
            None,
            None,
            None,
            None,
            Some(vlan)
        )
        .is_err());
    }
    let reply = crate::wire::response_with_policy(
        7,
        &request_auth,
        SECRET,
        2,
        &[3, 1, 0, 4],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let mut pos = 20;
    while pos < reply.len() {
        assert!(!matches!(reply[pos], 64 | 65 | 81));
        pos += reply[pos + 1] as usize;
    }
}

fn attr(packet: &mut Vec<u8>, kind: u8, value: &[u8]) {
    packet.extend_from_slice(&[kind, (value.len() + 2) as u8]);
    packet.extend_from_slice(value);
}
fn sign(mut packet: Vec<u8>) -> Vec<u8> {
    let length = packet.len() as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[22..38].fill(0);
    let mut mac = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    mac.update(&packet);
    packet[22..38].copy_from_slice(&mac.finalize().into_bytes());
    packet
}
fn request(radius_id: u8, eap_id: u8, state: Option<[u8; 16]>, typ: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![1, radius_id, 0, 0];
    packet.extend_from_slice(&[radius_id; 16]);
    attr(&mut packet, 80, &[0; 16]);
    let mut eap = vec![2, eap_id];
    eap.extend_from_slice(&((data.len() + 5) as u16).to_be_bytes());
    eap.push(typ);
    eap.extend_from_slice(data);
    for chunk in eap.chunks(253) {
        attr(&mut packet, 79, chunk);
    }
    if let Some(state) = state {
        attr(&mut packet, 24, &state);
    }
    sign(packet)
}
fn identity(id: u8) -> Vec<u8> {
    request(id, 0, None, 1, b"anonymous")
}
fn decoded(reply: &[u8]) -> (Vec<u8>, Option<[u8; 16]>) {
    let mut eap = Vec::new();
    let mut state = None;
    let mut offset = 20;
    while offset < reply.len() {
        let size = usize::from(reply[offset + 1]);
        let data = &reply[offset + 2..offset + size];
        match reply[offset] {
            79 => eap.extend_from_slice(data),
            24 => state = Some(data.try_into().unwrap()),
            _ => {}
        }
        offset += size;
    }
    (eap, state)
}
fn setup(limits: Limits) -> (Engine, ClientConnection) {
    let (engine, config) = setup_config(limits);
    (
        engine,
        ClientConnection::new(config, ServerName::try_from("radius.test").unwrap()).unwrap(),
    )
}
fn setup_config(limits: Limits) -> (Engine, Arc<ClientConfig>) {
    let certified = rcgen::generate_simple_self_signed(vec!["radius.test".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let server = server_config(vec![cert.clone()], key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    (Engine::new(server, limits).unwrap(), Arc::new(client))
}
fn peer() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}
fn binding() -> Binding {
    Binding {
        client: 1,
        trust_generation: 1,
        network: 1,
        source: peer().ip(),
    }
}
fn client(binding: Binding) -> Client<'static> {
    Client {
        binding,
        secret: SECRET,
        policy_generation: 1,
    }
}
fn reply(outcome: Outcome) -> Vec<u8> {
    match outcome {
        Outcome::Reply(reply) => reply.bytes,
        _ => panic!("expected reply"),
    }
}

#[test]
fn rejects_tampering_duplicates_and_malformed_attributes() {
    let packet = identity(1);
    assert!(wire::Request::parse(&packet, SECRET).is_ok());
    let mut padded = packet.clone();
    padded.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        wire::Request::parse(&padded, SECRET).unwrap().canonical,
        packet
    );
    for size in 0..packet.len() {
        assert!(wire::Request::parse(&packet[..size], SECRET).is_err());
    }
    let mut corrupt = packet.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        wire::Request::parse(&corrupt, SECRET),
        Err(Error::Integrity)
    ));
    let mut duplicate = packet.clone();
    attr(&mut duplicate, 80, &[0; 16]);
    assert!(matches!(
        wire::Request::parse(&sign(duplicate), SECRET),
        Err(Error::Malformed)
    ));
    let mut malformed = packet;
    malformed.extend_from_slice(&[24, 0]);
    assert!(matches!(
        wire::Request::parse(&sign(malformed), SECRET),
        Err(Error::Malformed)
    ));
}

#[test]
fn arbitrary_truncations_and_attribute_lengths_do_not_panic() {
    let packet = identity(1);
    for offset in 20..packet.len() {
        for value in 0..=255 {
            let mut changed = packet.clone();
            changed[offset] = value;
            let _ = wire::Request::parse(&changed, SECRET);
        }
    }
}

fn avp(out: &mut Vec<u8>, code: u32, data: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&[0x40, 0, 0, (data.len() + 8) as u8]);
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

#[test]
fn pap_stream_boundaries_duplicates_and_required_attributes() {
    let mut message = Vec::new();
    avp(&mut message, 1, b"jack");
    avp(&mut message, 2, b"test-password\0\0\0");
    for length in 0..message.len() {
        assert!(pap::credentials(&message[..length]).unwrap().is_none());
    }
    let credentials = pap::credentials(&message).unwrap().unwrap();
    assert_eq!(credentials.username, b"jack");
    let crate::Credential::Password(password) = &credentials.proof else {
        panic!("expected PAP");
    };
    assert_eq!(&**password, b"test-password");
    assert!(!format!("{credentials:?}").contains("test-password"));
    let mut duplicate = message.clone();
    avp(&mut duplicate, 1, b"admin");
    assert!(matches!(
        pap::credentials(&duplicate),
        Err(Error::Malformed)
    ));
    let mut unknown = message;
    avp(&mut unknown, 999, b"required");
    assert!(matches!(pap::credentials(&unknown), Err(Error::Protocol)));
}

#[test]
fn retransmission_is_exact_and_does_not_allocate_another_attempt() {
    let (mut engine, _) = setup(Limits::default());
    let now = Instant::now();
    let packet = identity(1);
    let first = reply(
        engine
            .receive(now, peer(), client(binding()), &packet)
            .unwrap(),
    );
    let second = reply(
        engine
            .receive(now, peer(), client(binding()), &packet)
            .unwrap(),
    );
    assert_eq!(first, second);
    assert_eq!(engine.active_attempts(), 1);
}

#[test]
fn per_client_and_global_attempt_limits_are_enforced() {
    let (mut engine, _) = setup(Limits {
        attempts: 2,
        per_client: 1,
        ..Limits::default()
    });
    let now = Instant::now();
    engine
        .receive(now, peer(), client(binding()), &identity(1))
        .unwrap();
    assert!(matches!(
        engine.receive(now, peer(), client(binding()), &identity(2)),
        Err(Error::Limit)
    ));
    let mut other = binding();
    other.client = 2;
    engine
        .receive(now, peer(), client(other), &identity(3))
        .unwrap();
    let mut third = binding();
    third.client = 3;
    assert!(matches!(
        engine.receive(now, peer(), client(third), &identity(4)),
        Err(Error::Limit)
    ));
}

#[test]
fn continuation_cannot_move_to_a_different_client_network_or_address() {
    let (mut engine, _) = setup(Limits::default());
    let now = Instant::now();
    let first = reply(
        engine
            .receive(now, peer(), client(binding()), &identity(1))
            .unwrap(),
    );
    let (eap, state) = decoded(&first);
    let continuation = request(2, eap[1], state, 21, &[0]);
    for change in 0..3 {
        let (mut engine, _) = setup(Limits::default());
        let first = reply(
            engine
                .receive(now, peer(), client(binding()), &identity(1))
                .unwrap(),
        );
        let (eap, state) = decoded(&first);
        let continuation = request(2, eap[1], state, 21, &[0]);
        let mut wrong = binding();
        match change {
            0 => wrong.client += 1,
            1 => wrong.network += 1,
            _ => wrong.trust_generation += 1,
        }
        assert!(matches!(
            engine.receive(now, peer(), client(wrong), &continuation),
            Err(Error::Binding)
        ));
        assert_eq!(engine.active_attempts(), if change == 0 { 1 } else { 0 });
    }
    let different: SocketAddr = "127.0.0.2:12345".parse().unwrap();
    let mut wrong = binding();
    wrong.source = different.ip();
    assert!(matches!(
        engine.receive(now, different, client(wrong), &continuation),
        Err(Error::Binding)
    ));
    assert_eq!(engine.active_attempts(), 1);
    assert!(matches!(
        engine.receive(now, peer(), client(binding()), &continuation),
        Ok(Outcome::Reply(_))
    ));
}

#[test]
fn overall_deadline_cannot_be_extended_by_progress() {
    let (mut engine, _) = setup(Limits {
        idle: Duration::from_secs(2),
        overall: Duration::from_secs(3),
        ..Limits::default()
    });
    let now = Instant::now();
    let mut response = reply(
        engine
            .receive(now, peer(), client(binding()), &identity(1))
            .unwrap(),
    );
    for second in 1..=2 {
        let (eap, state) = decoded(&response);
        response = reply(
            engine
                .receive(
                    now + Duration::from_secs(second),
                    peer(),
                    client(binding()),
                    &request(second as u8 + 1, eap[1], state, 21, &[0]),
                )
                .unwrap(),
        );
    }
    engine.expire(now + Duration::from_secs(3));
    assert_eq!(engine.active_attempts(), 0);
}

#[test]
fn idle_attempts_expire_without_incoming_packets() {
    let (mut engine, _) = setup(Limits::default());
    let now = Instant::now();
    engine
        .receive(now, peer(), client(binding()), &identity(1))
        .unwrap();
    engine.expire(now + Duration::from_secs(30));
    assert_eq!(engine.active_attempts(), 0);
}

fn pending() -> (Engine, Verification, Vec<u8>, Instant) {
    let (mut engine, mut tls_client) = setup(Limits {
        frame_payload: 128,
        ..Limits::default()
    });
    let now = Instant::now();
    let mut output = reply(
        engine
            .receive(now, peer(), client(binding()), &identity(1))
            .unwrap(),
    );
    let mut server_bytes = Vec::new();
    let mut app_sent = false;
    for radius_id in 2..=200 {
        let (eap, state) = decoded(&output);
        assert_eq!(eap[0], 1);
        let flags = eap[5];
        let payload = if flags & 0x80 != 0 {
            &eap[10..]
        } else {
            &eap[6..]
        };
        server_bytes.extend_from_slice(payload);
        let mut send = vec![0];
        if flags & 0x40 == 0 {
            let mut cursor = Cursor::new(std::mem::take(&mut server_bytes));
            while cursor.position() < cursor.get_ref().len() as u64 {
                tls_client.read_tls(&mut cursor).unwrap();
                tls_client.process_new_packets().unwrap();
            }
            if !tls_client.is_handshaking() && !app_sent {
                let mut avps = Vec::new();
                avp(&mut avps, 1, b"jack");
                avp(&mut avps, 2, b"password");
                tls_client.writer().write_all(&avps).unwrap();
                app_sent = true;
            }
            while tls_client.wants_write() {
                tls_client.write_tls(&mut send).unwrap();
            }
        }
        let packet = request(radius_id, eap[1], state, 21, &send);
        match engine
            .receive(now, peer(), client(binding()), &packet)
            .unwrap()
        {
            Outcome::Reply(reply) => output = reply.bytes,
            Outcome::Verify(verification) => return (engine, verification, packet, now),
            Outcome::Drop => panic!("unexpected drop"),
            Outcome::Mschapv2Response { .. } => panic!("unexpected MSCHAPv2 proof"),
        }
    }
    panic!("exchange did not finish");
}

#[test]
fn peap_negotiates_and_completes_only_after_tunneled_confirmation() {
    let (mut engine, tls_client) = setup(Limits {
        frame_payload: 128,
        ..Limits::default()
    });
    peap_exchange(&mut engine, tls_client, Instant::now(), Admission::Granted);
}

fn peap_exchange(
    engine: &mut Engine,
    mut tls_client: ClientConnection,
    now: Instant,
    final_admission: Admission,
) {
    use std::io::Read;
    let methods = [Method::PeapMschapv2, Method::TtlsPap];
    let mut output = reply(
        engine
            .receive_with_methods(now, peer(), client(binding()), &identity(1), &methods)
            .unwrap(),
    );
    let mut server_bytes = Vec::new();
    let mut id = None;
    let mut backend_called = false;
    let mut proof_seen = false;
    for radius_id in 2..=200 {
        let (eap, state) = decoded(&output);
        assert_eq!(output[0], 11);
        assert_eq!(eap[4], 25);
        let flags = eap[5];
        server_bytes.extend_from_slice(if flags & 0x80 != 0 {
            &eap[10..]
        } else {
            &eap[6..]
        });
        let mut send = vec![0];
        if flags & 0x40 == 0 {
            let mut cursor = Cursor::new(std::mem::take(&mut server_bytes));
            while cursor.position() < cursor.get_ref().len() as u64 {
                tls_client.read_tls(&mut cursor).unwrap();
                tls_client.process_new_packets().unwrap();
            }
            let mut plaintext = Vec::new();
            let mut scratch = [0; 4096];
            loop {
                match tls_client.reader().read(&mut scratch) {
                    Ok(0) => break,
                    Ok(n) => plaintext.extend_from_slice(&scratch[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("{e}"),
                }
            }
            let answer = match plaintext.first() {
                None => Vec::new(),
                Some(1) if plaintext.len() == 1 => b"\x01User".to_vec(),
                Some(26) if plaintext[1] == 1 => {
                    assert_eq!(&plaintext[6..22], &[7; 16]);
                    let mut answer = vec![26, 2, plaintext[2], 0, 58, 49];
                    answer.extend_from_slice(&[1; 16]);
                    answer.extend_from_slice(&[0; 8]);
                    answer.extend_from_slice(&[2; 24]);
                    answer.push(0);
                    answer.extend_from_slice(b"User");
                    answer
                }
                Some(26) if plaintext[1] == 3 => {
                    assert!(proof_seen);
                    assert_eq!(
                        &plaintext[5..],
                        b"S=ABABABABABABABABABABABABABABABABABABABAB"
                    );
                    vec![26, 3]
                }
                Some(1) if plaintext.len() == 11 && plaintext[4] == 33 => {
                    assert!(engine.has_attempt(&id.unwrap()));
                    plaintext[0] = 2;
                    plaintext
                }
                _ => panic!("unexpected inner exchange"),
            };
            if !answer.is_empty() {
                tls_client.writer().write_all(&answer).unwrap();
            }
            while tls_client.wants_write() {
                tls_client.write_tls(&mut send).unwrap();
            }
        }
        let packet = request(radius_id, eap[1], state, 25, &send);
        match engine
            .receive_with_methods(now, peer(), client(binding()), &packet, &methods)
            .unwrap()
        {
            Outcome::Reply(reply) => output = reply.bytes,
            Outcome::Verify(verification) => {
                assert!(!backend_called);
                backend_called = true;
                assert_eq!(verification.credentials.username, b"User");
                assert!(matches!(
                    verification.credentials.proof,
                    Credential::Mschapv2
                ));
                id = Some(verification.id());
                output = engine
                    .mschapv2_challenge(now, id.unwrap(), [7; 16])
                    .unwrap()
                    .bytes;
            }
            Outcome::Mschapv2Response {
                id: current,
                response,
            } => {
                assert_eq!(Some(current), id);
                assert_eq!(&response[..16], &[1; 16]);
                assert_eq!(&response[16..], &[2; 24]);
                proof_seen = true;
                output = engine
                    .finish_with_protocol(
                        now,
                        current,
                        client(binding()),
                        Admission::Granted,
                        Some(3600),
                        Some([0xab; 20]),
                    )
                    .unwrap()
                    .bytes;
                assert_eq!(output[0], 11);
            }
            Outcome::Drop => {
                let terminal = engine
                    .finish_with_protocol(
                        now,
                        id.unwrap(),
                        client(binding()),
                        final_admission,
                        Some(3600),
                        Some([0xab; 20]),
                    )
                    .unwrap();
                let granted = final_admission == Admission::Granted;
                assert_eq!(terminal.bytes[0], if granted { 2 } else { 3 });
                assert_eq!(decoded(&terminal.bytes).0[0], if granted { 3 } else { 4 });
                if !granted {
                    let mut offset = 20;
                    while offset < terminal.bytes.len() {
                        assert_ne!(
                            terminal.bytes[offset], 26,
                            "denied reply contained key attributes"
                        );
                        offset += usize::from(terminal.bytes[offset + 1]);
                    }
                }
                assert_eq!(engine.active_attempts(), 0);
                assert!(backend_called && proof_seen);
                return;
            }
        }
    }
    panic!("PEAP did not finish");
}

#[test]
fn repeated_peap_exchanges_release_state_and_recheck_final_admission() {
    let (mut engine, config) = setup_config(Limits {
        attempts: 1,
        per_client: 1,
        cached_replies: 4,
        frame_payload: 128,
        ..Limits::default()
    });
    let now = Instant::now();
    for cycle in 0..96 {
        let client =
            ClientConnection::new(config.clone(), ServerName::try_from("radius.test").unwrap())
                .unwrap();
        let admission = match cycle % 3 {
            0 => Admission::Granted,
            1 => Admission::Denied,
            _ => Admission::BackendFailure,
        };
        // Reuse packet identifiers after the reply cache has expired, without sleeping.
        peap_exchange(
            &mut engine,
            client,
            now + Duration::from_secs(cycle * 16),
            admission,
        );
        assert_eq!(engine.active_attempts(), 0);
    }
}

#[test]
fn repeated_abandoned_peap_attempts_stay_bounded_and_expire() {
    let (mut engine, _) = setup_config(Limits {
        attempts: 8,
        per_client: 8,
        cached_replies: 4,
        ..Limits::default()
    });
    let now = Instant::now();
    for cycle in 0..128 {
        let now = now + Duration::from_secs(cycle * 32);
        engine.expire(now);
        assert_eq!(engine.active_attempts(), 0);
        for id in 1..=8 {
            assert!(matches!(
                engine
                    .receive_with_methods(
                        now,
                        peer(),
                        client(binding()),
                        &identity(id),
                        &[Method::PeapMschapv2],
                    )
                    .unwrap(),
                Outcome::Reply(_)
            ));
            assert_eq!(engine.active_attempts(), usize::from(id));
        }
        assert!(matches!(
            engine.receive_with_methods(
                now,
                peer(),
                client(binding()),
                &identity(9),
                &[Method::PeapMschapv2],
            ),
            Err(Error::Limit)
        ));
    }
    engine.expire(now + Duration::from_secs(128 * 32));
    assert_eq!(engine.active_attempts(), 0);
}

#[test]
fn nak_chooses_only_an_allowed_untried_method() {
    let methods = [Method::PeapMschapv2, Method::TtlsPap];
    let (mut engine, _) = setup(Limits::default());
    let now = Instant::now();
    let initial = reply(
        engine
            .receive_with_methods(now, peer(), client(binding()), &identity(1), &methods)
            .unwrap(),
    );
    let (eap, state) = decoded(&initial);
    assert_eq!(eap[4], 25);
    let switched = reply(
        engine
            .receive_with_methods(
                now,
                peer(),
                client(binding()),
                &request(2, eap[1], state, 3, &[21]),
                &methods,
            )
            .unwrap(),
    );
    let (eap, state) = decoded(&switched);
    assert_eq!(eap[4], 21);
    let rejected = reply(
        engine
            .receive_with_methods(
                now,
                peer(),
                client(binding()),
                &request(3, eap[1], state, 3, &[25]),
                &methods,
            )
            .unwrap(),
    );
    assert_eq!(rejected[0], 3);
}

#[test]
fn peap_fragment_lengths_may_repeat_but_cannot_change() {
    for change in [false, true] {
        let (mut engine, mut peer_tls) = setup(Limits::default());
        let now = Instant::now();
        let methods = [Method::PeapMschapv2];
        let start = reply(
            engine
                .receive_with_methods(now, peer(), client(binding()), &identity(1), &methods)
                .unwrap(),
        );
        let (eap, state) = decoded(&start);
        let mut hello = Vec::new();
        peer_tls.write_tls(&mut hello).unwrap();
        assert!(hello.len() > 128);
        let mut fragment = vec![0xc0];
        fragment.extend_from_slice(&(hello.len() as u32).to_be_bytes());
        fragment.extend_from_slice(&hello[..128]);
        let ack = reply(
            engine
                .receive_with_methods(
                    now,
                    peer(),
                    client(binding()),
                    &request(2, eap[1], state, 25, &fragment),
                    &methods,
                )
                .unwrap(),
        );
        let (eap, state) = decoded(&ack);
        assert_eq!(&eap[5..], &[0]);
        let mut fragment = vec![0x80];
        fragment.extend_from_slice(&(hello.len() as u32 + u32::from(change)).to_be_bytes());
        fragment.extend_from_slice(&hello[128..]);
        let response = reply(
            engine
                .receive_with_methods(
                    now,
                    peer(),
                    client(binding()),
                    &request(3, eap[1], state, 25, &fragment),
                    &methods,
                )
                .unwrap(),
        );
        assert_eq!(response[0], if change { 3 } else { 11 });
    }
}

#[test]
fn admission_is_explicit_one_shot_and_pending_duplicates_do_not_repeat_authentication() {
    let (mut engine, verification, packet, now) = pending();
    assert_eq!(verification.credentials.username, b"jack");
    assert!(matches!(
        engine
            .receive(now, peer(), client(binding()), &packet)
            .unwrap(),
        Outcome::Drop
    ));
    let accepted = engine
        .finish(
            now,
            verification.id(),
            client(binding()),
            Admission::Granted,
        )
        .unwrap();
    assert_eq!(accepted.bytes[0], 2);
    assert_eq!(decoded(&accepted.bytes).0[0], 3);
    assert!(matches!(
        engine.finish(
            now,
            verification.id(),
            client(binding()),
            Admission::Granted
        ),
        Err(Error::UnknownAttempt)
    ));
    assert_eq!(
        reply(
            engine
                .receive(now, peer(), client(binding()), &packet)
                .unwrap()
        ),
        accepted.bytes
    );
}

#[test]
fn denial_and_backend_failure_never_deliver_keys() {
    for decision in [Admission::Denied, Admission::BackendFailure] {
        let (mut engine, verification, _, now) = pending();
        let denied = engine
            .finish(now, verification.id(), client(binding()), decision)
            .unwrap();
        assert_eq!(denied.bytes[0], 3);
        assert_eq!(
            decoded(&denied.bytes).0,
            [4, decoded(&denied.bytes).0[1], 0, 4]
        );
        // Reject consists only of MA and EAP; no key-bearing VSA.
        assert_eq!(denied.bytes.len(), 44);
    }
}

#[test]
fn expired_or_rebound_backend_results_cannot_grant_access() {
    let (mut engine, verification, _, now) = pending();
    assert!(matches!(
        engine.finish(
            now + Duration::from_secs(121),
            verification.id(),
            client(binding()),
            Admission::Granted
        ),
        Err(Error::UnknownAttempt)
    ));
    let (mut engine, verification, _, now) = pending();
    let mut changed = binding();
    changed.trust_generation += 1;
    assert!(matches!(
        engine.finish(now, verification.id(), client(changed), Admission::Granted),
        Err(Error::Binding)
    ));
}

#[test]
fn a_verified_result_cannot_be_manufactured_from_an_initial_identity() {
    let (mut engine, _) = setup(Limits::default());
    let now = Instant::now();
    let first = reply(
        engine
            .receive(now, peer(), client(binding()), &identity(1))
            .unwrap(),
    );
    assert!(matches!(
        engine.finish(
            now,
            decoded(&first).1.unwrap(),
            client(binding()),
            Admission::Granted
        ),
        Err(Error::Protocol)
    ));
}

#[test]
fn final_reply_cache_uses_the_policy_generation_that_made_the_decision() {
    let (mut engine, verification, packet, now) = pending();
    let mut current = client(binding());
    current.policy_generation = 2;
    let accepted = engine
        .finish(now, verification.id(), current, Admission::Granted)
        .unwrap();
    let mut current = client(binding());
    current.policy_generation = 2;
    assert_eq!(
        reply(engine.receive(now, peer(), current, &packet).unwrap()),
        accepted.bytes
    );
    assert!(matches!(
        engine.receive(now, peer(), client(binding()), &packet),
        Err(Error::UnknownAttempt)
    ));
}

#[test]
fn secret_rotation_is_detected_even_if_the_adapter_reuses_the_generation() {
    let (mut engine, verification, _, now) = pending();
    let current = Client {
        secret: b"different-radius-shared-secret",
        ..client(binding())
    };
    assert!(matches!(
        engine.finish(now, verification.id(), current, Admission::Granted),
        Err(Error::Binding)
    ));
}

#[test]
fn limit_updates_preserve_existing_deadlines_and_validate_before_applying() {
    let now = Instant::now();
    let (mut engine, _) = setup(Limits {
        idle: Duration::from_secs(4),
        overall: Duration::from_secs(10),
        ..Limits::default()
    });
    engine
        .receive(now, peer(), client(binding()), &identity(1))
        .unwrap();
    assert!(engine
        .update_limits(Limits {
            idle: Duration::ZERO,
            ..Limits::default()
        })
        .is_err());
    engine
        .update_limits(Limits {
            idle: Duration::from_secs(1),
            ..Limits::default()
        })
        .unwrap();
    engine
        .receive(
            now + Duration::from_secs(1),
            peer(),
            client(binding()),
            &identity(2),
        )
        .unwrap();
    engine.expire(now + Duration::from_secs(2));
    assert_eq!(engine.active_attempts(), 1);
    engine.expire(now + Duration::from_secs(4));
    assert_eq!(engine.active_attempts(), 0);
}

#[test]
fn oversized_tls_fragments_are_rejected_and_release_the_attempt() {
    let now = Instant::now();
    let (mut engine, _) = setup(Limits::default());
    let initial = reply(
        engine
            .receive(now, peer(), client(binding()), &identity(1))
            .unwrap(),
    );
    let (eap, state) = decoded(&initial);
    let mut frame = vec![0xc0];
    frame.extend_from_slice(&65537u32.to_be_bytes());
    frame.push(1);
    let rejected = reply(
        engine
            .receive(
                now,
                peer(),
                client(binding()),
                &request(2, eap[1], state, 21, &frame),
            )
            .unwrap(),
    );
    assert_eq!(rejected[0], 3);
    assert_eq!(engine.active_attempts(), 0);
}

#[test]
fn a_tls_configuration_with_early_tickets_is_rejected() {
    let certified = rcgen::generate_simple_self_signed(vec!["radius.test".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let mut config = server_config(vec![certified.cert.der().clone()], key).unwrap();
    Arc::get_mut(&mut config).unwrap().send_tls13_tickets = 2;
    assert!(matches!(
        Engine::new(config, Limits::default()),
        Err(Error::Configuration)
    ));
}

#[test]
fn a_policy_edit_does_not_break_an_unanswered_challenge_retransmission() {
    let (mut engine, _) = setup(Limits::default());
    let now = Instant::now();
    let packet = identity(1);
    let first = reply(
        engine
            .receive(now, peer(), client(binding()), &packet)
            .unwrap(),
    );
    let mut updated = client(binding());
    updated.policy_generation = 2;
    let replay = reply(engine.receive(now, peer(), updated, &packet).unwrap());
    assert_eq!(first, replay);
    assert_eq!(engine.active_attempts(), 1);
}
