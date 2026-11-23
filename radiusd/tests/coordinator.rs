use hmac::{Hmac, Mac};
use md5::Md5;
use radius_core::{Limits, Reply, Verification};
use radiusd::{
    config::{Client, Config, Network, Prefix},
    driver::{AdmissionContext, AdmissionExtras, Backend, Driver, Event, Output, Progress, Reason},
};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore,
};
use std::{
    cell::Cell,
    collections::{BTreeMap, VecDeque},
    io::{Cursor, Write},
    net::SocketAddr,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const SECRET: &[u8] = b"fixture-radius-secret-32-bytes!!!";
type AccountingState = (Rc<Cell<bool>>, Rc<Cell<usize>>, Option<Reason>);

struct Fake {
    calls: Rc<Cell<usize>>,
    ready: Rc<Cell<bool>>,
    drops: Rc<Cell<usize>>,
    accounting: Option<AccountingState>,
}
struct Work {
    ready: Rc<Cell<bool>>,
    drops: Rc<Cell<usize>>,
}
impl Drop for Work {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl Backend for Fake {
    type Work = Work;
    type Subject = ();
    fn operation_guid(&self, _: &Work) -> Option<[u8; 16]> {
        Some([17; 16])
    }
    fn begin(&mut self, v: Verification) -> Result<Work, Reason> {
        let radius_core::Credential::Password(password) = &v.credentials.proof else {
            panic!("expected PAP");
        };
        assert_eq!(&**password, b"password");
        self.calls.set(self.calls.get() + 1);
        Ok(Work {
            ready: self.ready.clone(),
            drops: self.drops.clone(),
        })
    }
    fn step(&mut self, w: &mut Work) -> Progress<()> {
        if w.ready.get() {
            Progress::Complete(())
        } else {
            Progress::Waiting
        }
    }
    fn admission(&mut self, _: &(), network_id: &str, network: &Network) -> Result<(), Reason> {
        assert!(!network_id.is_empty());
        if network.security == [1] {
            Ok(())
        } else {
            Err(Reason::Policy)
        }
    }
    fn identity<'a>(&self, _: &'a ()) -> (&'a str, &'a [u8]) {
        ("canonical-jack", b"test-sid")
    }
    fn accounting(
        &mut self,
        _: &(),
        context: AdmissionContext<'_>,
    ) -> Result<Option<AdmissionExtras>, Reason> {
        let Some((ready, calls, denied)) = &self.accounting else {
            return Ok(Some(AdmissionExtras::default()));
        };
        assert_eq!(context.client_id, "aps");
        assert_eq!(context.network_id, "home");
        calls.set(calls.get() + 1);
        if !ready.get() {
            return Ok(None);
        }
        if let Some(reason) = denied {
            return Err(*reason);
        }
        Ok(Some(AdmissionExtras {
            class: Some(b"durably-committed-reference".to_vec()),
            timeout_seconds: Some(123),
        }))
    }
}
#[derive(Default)]
struct Out {
    progress: Vec<radius_management::diagnostics::Record>,
    diagnostic: Vec<radius_management::diagnostics::Record>,
    replies: VecDeque<Vec<u8>>,
    events: Vec<(Reason, Option<String>, Option<String>)>,
    deliver: bool,
}
impl Output for Out {
    fn progress(&mut self, record: &radius_management::diagnostics::Record) {
        self.progress.push(record.clone());
    }
    fn send(&mut self, _: usize, r: &Reply) -> bool {
        self.replies.push_back(r.bytes.clone());
        self.deliver
    }
    fn event(&mut self, e: Event<'_>) {
        self.diagnostic.push(e.diagnostic);
        self.events.push((
            e.reason,
            e.username.map(str::to_owned),
            e.canonical.map(str::to_owned),
        ));
    }
}
type Setup = (
    Config,
    ClientConnection,
    Fake,
    Rc<Cell<usize>>,
    Rc<Cell<bool>>,
    Rc<Cell<usize>>,
);
fn setup() -> Setup {
    setup_peers().0
}
fn setup_peers() -> (Setup, ClientConnection) {
    let certified = rcgen::generate_simple_self_signed(vec!["radius.test".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let tls = radius_core::server_config(vec![cert.clone()], key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let client = Arc::new(client);
    let second =
        ClientConnection::new(client.clone(), ServerName::try_from("radius.test").unwrap())
            .unwrap();
    let tls_client =
        ClientConnection::new(client, ServerName::try_from("radius.test").unwrap()).unwrap();
    let config = Config {
        labels: Default::default(),
        diagnostics: Default::default(),
        saved_fingerprint: String::new(),
        listeners: vec!["127.0.0.1:1812".parse().unwrap()],
        limits: Limits {
            frame_payload: 128,
            ..Default::default()
        },
        verifications: 1,
        clients: BTreeMap::from([(
            "aps".into(),
            Client {
                name: "aps".into(),
                enabled: true,
                addresses: vec![Prefix::parse("127.0.0.0/8").unwrap()],
                secret: Zeroizing::new(SECRET.to_vec()),
                networks: vec!["home".into()],
                authorization: Default::default(),
            },
        )]),
        networks: BTreeMap::from([(
            "home".into(),
            Network {
                authentication_profile: None,
                access: access_policy(),
                enabled: true,
                tls: None,
                tls_tag: [0; 32],
                methods: vec![radius_core::Method::TtlsPap],
                ssid: b"Home".to_vec(),
                security: vec![1],
                reauthenticate_seconds: 3600,
            },
        )]),
        tls,
        fingerprint: [1; 32],
    };
    let calls = Rc::new(Cell::new(0));
    let ready = Rc::new(Cell::new(true));
    let drops = Rc::new(Cell::new(0));
    let backend = Fake {
        calls: calls.clone(),
        ready: ready.clone(),
        drops: drops.clone(),
        accounting: None,
    };
    ((config, tls_client, backend, calls, ready, drops), second)
}
fn attr(packet: &mut Vec<u8>, kind: u8, value: &[u8]) {
    packet.extend_from_slice(&[kind, (value.len() + 2) as u8]);
    packet.extend_from_slice(value);
}
fn request(
    id: u8,
    eap_id: u8,
    state: Option<[u8; 16]>,
    typ: u8,
    data: &[u8],
    called: Option<&[u8]>,
) -> Vec<u8> {
    let mut packet = vec![1, id, 0, 0];
    packet.extend_from_slice(&[id; 16]);
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
    if let Some(called) = called {
        attr(&mut packet, 30, called);
    }
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    let mut h = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    h.update(&packet);
    packet[22..38].copy_from_slice(&h.finalize().into_bytes());
    packet
}
fn decode(reply: &[u8]) -> (Vec<u8>, Option<[u8; 16]>) {
    let mut eap = Vec::new();
    let mut state = None;
    let mut offset = 20;
    while offset < reply.len() {
        let len = reply[offset + 1] as usize;
        let value = &reply[offset + 2..offset + len];
        match reply[offset] {
            79 => eap.extend_from_slice(value),
            24 => state = Some(value.try_into().unwrap()),
            _ => {}
        }
        offset += len;
    }
    (eap, state)
}
fn peer() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}
fn pending(
    driver: &mut Driver<Fake>,
    tls: ClientConnection,
    out: &mut Out,
    now: Instant,
) -> Vec<u8> {
    pending_outer(driver, tls, out, now, b"anonymous")
}
fn pending_outer(
    driver: &mut Driver<Fake>,
    mut tls: ClientConnection,
    out: &mut Out,
    now: Instant,
    outer: &[u8],
) -> Vec<u8> {
    driver.receive(
        now,
        0,
        peer(),
        &request(1, 0, None, 1, outer, Some(b"aa-bb-cc-dd-ee-ff:Home")),
        out,
    );
    let mut server = Vec::new();
    let mut sent = false;
    for id in 2..200 {
        let reply = out.replies.pop_front().expect("challenge missing");
        let (eap, state) = decode(&reply);
        let flags = eap[5];
        server.extend_from_slice(if flags & 0x80 != 0 {
            &eap[10..]
        } else {
            &eap[6..]
        });
        let mut send = vec![0];
        if flags & 0x40 == 0 {
            let mut cursor = Cursor::new(std::mem::take(&mut server));
            while cursor.position() < cursor.get_ref().len() as u64 {
                tls.read_tls(&mut cursor).unwrap();
                tls.process_new_packets().unwrap();
            }
            if !tls.is_handshaking() && !sent {
                let mut avps = Vec::new();
                for (code, value) in [(1u32, b"jack".as_slice()), (2u32, b"password".as_slice())] {
                    avps.extend_from_slice(&code.to_be_bytes());
                    avps.extend_from_slice(&[0, 0, 0, (8 + value.len()) as u8]);
                    avps.extend_from_slice(value);
                    while avps.len() % 4 != 0 {
                        avps.push(0);
                    }
                }
                tls.writer().write_all(&avps).unwrap();
                sent = true;
            }
            while tls.wants_write() {
                tls.write_tls(&mut send).unwrap();
            }
        }
        // Continuations may omit Called-Station-Id; the authenticated State
        // continues the original client/network binding.
        let packet = request(id, eap[1], state, 21, &send, None);
        driver.receive(now, 0, peer(), &packet, out);
        if out.replies.is_empty() {
            assert!(sent);
            return packet;
        }
    }
    panic!("TTLS exchange did not reach backend");
}

#[test]
fn accounting_completion_gates_accept_and_cached_class_is_exact() {
    let (config, tls, mut backend, _, _, _) = setup();
    let committed = Rc::new(Cell::new(false));
    let calls = Rc::new(Cell::new(0));
    backend.accounting = Some((committed.clone(), calls.clone(), None));
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    let last = pending(&mut d, tls, &mut out, now);
    d.tick(now, &mut out);
    assert!(out.replies.is_empty() && out.events.is_empty());
    let milestones = out.progress.len();
    for _ in 0..50 {
        d.tick(now, &mut out);
    }
    assert_eq!(
        out.progress.len(),
        milestones,
        "polling the same pending operation adds no milestones"
    );
    committed.set(true);
    d.tick(now, &mut out);
    let reply = out.replies.pop_front().unwrap();
    assert_eq!(reply[0], 2);
    let summary = out.diagnostic.last().unwrap();
    assert_eq!(summary["outcome.success"], true);
    assert_eq!(
        summary["object.authentication.operation.guid"],
        radius_management::diagnostics::hex(&[17; 16])
    );
    let records = serde_json::to_string(&out.progress).unwrap();
    assert_eq!(
        out.progress
            .iter()
            .filter(|record| record
                .get("object.radiusd.progress.stage")
                .and_then(serde_json::Value::as_str)
                == Some("method")
                && record
                    .get("object.radiusd.progress.result")
                    .and_then(serde_json::Value::as_str)
                    == Some("selected"))
            .count(),
        1,
        "the offered method becomes selected after the client's response"
    );
    assert!(!records.contains("password"));
    assert!(!records.contains(std::str::from_utf8(SECRET).unwrap()));
    let mut pos = 20;
    let mut class = None;
    let mut timeout = None;
    while pos < reply.len() {
        let n = reply[pos + 1] as usize;
        if reply[pos] == 25 {
            class = Some(reply[pos + 2..pos + n].to_vec());
        }
        if reply[pos] == 27 {
            timeout = Some(u32::from_be_bytes(
                reply[pos + 2..pos + n].try_into().unwrap(),
            ));
        }
        pos += n;
    }
    assert_eq!(
        class.as_deref(),
        Some(b"durably-committed-reference".as_slice())
    );
    assert_eq!(timeout, Some(123));
    let before = calls.get();
    d.receive(now, 0, peer(), &last, &mut out);
    assert_eq!(out.replies.pop_front().unwrap(), reply);
    assert_eq!(calls.get(), before);
}

#[test]
fn retransmitting_the_initial_request_does_not_restart_its_diagnostic_timeline() {
    let (config, _, backend, _, _, _) = setup();
    let mut driver = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let packet = request(1, 0, None, 1, b"anonymous", Some(b"aa-bb-cc-dd-ee-ff:Home"));
    let now = Instant::now();
    driver.receive(now, 0, peer(), &packet, &mut out);
    let first = out.replies.pop_front().unwrap();
    let count = out.progress.len();
    driver.receive(now, 0, peer(), &packet, &mut out);
    assert_eq!(out.replies.pop_front().unwrap(), first);
    assert_eq!(out.progress.len(), count);
    driver.tick(now + Duration::from_secs(31), &mut out);
    assert_eq!(
        out.diagnostic.last().unwrap()["object.radiusd.retransmissions"],
        1
    );
}
#[test]
fn exhausted_accounting_allowance_cannot_emit_accept_or_class() {
    let (config, tls, mut backend, _, _, _) = setup();
    backend.accounting = Some((
        Rc::new(Cell::new(true)),
        Rc::new(Cell::new(0)),
        Some(Reason::Quota),
    ));
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    d.tick(now, &mut out);
    let reply = out.replies.pop_front().unwrap();
    assert_eq!(reply[0], 3);
    let mut pos = 20;
    while pos < reply.len() {
        assert_ne!(reply[pos], 25);
        pos += reply[pos + 1] as usize;
    }
    assert_eq!(out.events[0].0, Reason::Quota);
}
#[test]
fn completed_exchange_replays_identically_without_verifying_or_logging_twice() {
    let (config, tls, backend, calls, _, _) = setup();
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    let last = pending(&mut d, tls, &mut out, now);
    assert_eq!(calls.get(), 1);
    d.receive(now, 0, peer(), &last, &mut out);
    assert!(out.replies.is_empty());
    d.tick(now, &mut out);
    let reply = out.replies.pop_front().unwrap();
    assert_eq!(reply[0], 2);
    assert_eq!(
        out.events,
        [(
            Reason::Granted,
            Some("jack".into()),
            Some("canonical-jack".into())
        )]
    );
    d.receive(now, 0, peer(), &last, &mut out);
    assert_eq!(out.replies.pop_front().unwrap(), reply);
    assert_eq!(calls.get(), 1);
    assert_eq!(out.events.len(), 1);
    let mut offset = 20;
    let mut timeout = None;
    let mut action = None;
    while offset < reply.len() {
        let size = reply[offset + 1] as usize;
        let v = &reply[offset + 2..offset + size];
        match reply[offset] {
            27 => timeout = Some(u32::from_be_bytes(v.try_into().unwrap())),
            29 => action = Some(u32::from_be_bytes(v.try_into().unwrap())),
            _ => {}
        }
        offset += size;
    }
    assert_eq!(timeout, Some(3600));
    assert_eq!(action, Some(1));
}
#[test]
fn pending_reload_holds_verified_result_and_uses_replacement_policy() {
    let (config, tls, backend, _, _, _) = setup();
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    d.pause();
    d.tick(now, &mut out);
    assert!(out.replies.is_empty());
    assert!(out.events.is_empty());
    let mut config = setup().0; // renewal retains the old TLS attempt
    config.networks.get_mut("home").unwrap().security = vec![0];
    config.fingerprint = [2; 32];
    d.activate(Arc::new(config)).unwrap();
    d.tick(now, &mut out);
    let reply = out.replies.pop_front().unwrap();
    assert_eq!(reply[0], 3);
    assert_eq!(out.events[0].0, Reason::Policy);
    assert!(!reply.windows(2).any(|w| w == [27, 6]));
}
#[test]
fn paused_service_does_not_replay_a_cached_accept() {
    let (config, tls, backend, _, _, _) = setup();
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    let last = pending(&mut d, tls, &mut out, now);
    d.tick(now, &mut out);
    out.replies.clear();
    d.pause();
    d.receive(now, 0, peer(), &last, &mut out);
    assert!(out.replies.is_empty());
}
#[test]
fn changed_policy_does_not_replay_a_previously_cached_accept() {
    let (config, tls, backend, _, _, _) = setup();
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    let last = pending(&mut d, tls, &mut out, now);
    d.tick(now, &mut out);
    assert_eq!(out.replies.pop_front().unwrap()[0], 2);
    let mut next = setup().0;
    next.networks.get_mut("home").unwrap().security = vec![0];
    next.fingerprint = [2; 32];
    d.activate(Arc::new(next)).unwrap();
    d.receive(now, 0, peer(), &last, &mut out);
    assert!(out.replies.is_empty());
    assert_eq!(out.events.len(), 1);
}
#[test]
fn ssid_change_cancels_a_verified_attempt() {
    let (config, tls, backend, _, _, _) = setup();
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    d.pause();
    d.tick(now, &mut out);
    let mut next = setup().0;
    next.networks.get_mut("home").unwrap().ssid = b"Renamed".to_vec();
    d.activate(Arc::new(next)).unwrap();
    d.tick(now, &mut out);
    assert!(out.replies.is_empty());
    assert_eq!(
        out.events[0],
        (
            Reason::Binding,
            Some("jack".into()),
            Some("canonical-jack".into())
        )
    );
}
#[test]
fn verification_limit_rejects_without_starting_another_backend() {
    let ((config, tls, backend, calls, ready, _), second) = setup_peers();
    ready.set(false);
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    pending_outer(&mut d, second, &mut out, now, b"second-anonymous");
    d.tick(now, &mut out);
    assert_eq!(calls.get(), 1);
    assert_eq!(d.pending(), 1);
    assert_eq!(out.replies.pop_front().unwrap()[0], 3);
    assert_eq!(out.events[0].0, Reason::Busy);
}
#[test]
fn backend_expiry_cancels_work_and_never_admits_late_results() {
    let (config, tls, backend, _, ready, drops) = setup();
    ready.set(false);
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    d.tick(now + Duration::from_secs(31), &mut out);
    assert_eq!(drops.get(), 1);
    ready.set(true);
    d.tick(now + Duration::from_secs(32), &mut out);
    assert!(out.replies.is_empty());
    assert_eq!(out.events[0].0, Reason::Timeout);
}
#[test]
fn rotated_secret_invalidates_pending_backend_and_cached_binding() {
    let (config, tls, backend, _, ready, drops) = setup();
    ready.set(false);
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    let mut next = setup().0;
    next.clients.get_mut("aps").unwrap().secret =
        Zeroizing::new(b"replacement-secret-at-least-16".to_vec());
    d.activate(Arc::new(next)).unwrap();
    d.tick(now, &mut out);
    assert_eq!(drops.get(), 1);
    assert_eq!(out.events[0].0, Reason::Binding);
    assert!(out.replies.is_empty());
}
#[test]
fn network_selection_is_explicit_and_integrity_checked() {
    let (config, _, backend, calls, _, _) = setup();
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    for called in [
        None,
        Some(b"aa-bb-cc-dd-ee-ff:home".as_slice()),
        Some(b"aa-bb-cc-dd-ee-ff:Other".as_slice()),
    ] {
        d.receive(
            now,
            0,
            peer(),
            &request(1, 0, None, 1, b"anonymous", called),
            &mut out,
        );
    }
    let mut forged = request(1, 0, None, 1, b"anonymous", Some(b"aa-bb-cc-dd-ee-ff:Home"));
    forged[25] ^= 1;
    d.receive(now, 0, peer(), &forged, &mut out);
    assert!(out.replies.is_empty());
    assert_eq!(d.pending(), 0);
    assert_eq!(calls.get(), 0);
}
#[test]
fn most_specific_client_wins_and_bad_secret_has_no_fallback() {
    let (mut config, _, backend, _, _, _) = setup();
    config.clients.insert(
        "one".into(),
        Client {
            name: "one".into(),
            enabled: true,
            addresses: vec![Prefix::parse("127.0.0.1").unwrap()],
            secret: Zeroizing::new(b"other-secret-at-least-16".to_vec()),
            networks: vec!["home".into()],
            authorization: Default::default(),
        },
    );
    assert_eq!(config.client(peer().ip()).unwrap().name, "one");
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out::default();
    d.receive(
        Instant::now(),
        0,
        peer(),
        &request(1, 0, None, 1, b"anonymous", Some(b"aa-bb-cc-dd-ee-ff:Home")),
        &mut out,
    );
    assert!(out.replies.is_empty());
}
#[test]
fn conflicting_client_prefix_or_network_ssid_is_rejected() {
    let (mut config, _, _, _, _, _) = setup();
    config.clients.insert(
        "other".into(),
        Client {
            name: "other".into(),
            enabled: true,
            addresses: vec![Prefix::parse("127.0.0.0/8").unwrap()],
            secret: Zeroizing::new(SECRET.to_vec()),
            networks: vec!["home".into()],
            authorization: Default::default(),
        },
    );
    assert!(config.validate().is_err());
    config.clients.remove("other");
    config.networks.insert(
        "alias".into(),
        Network {
            authentication_profile: None,
            access: access_policy(),
            enabled: true,
            tls: None,
            tls_tag: [0; 32],
            methods: vec![radius_core::Method::TtlsPap],
            ssid: b"Home".to_vec(),
            security: vec![1],
            reauthenticate_seconds: 3600,
        },
    );
    config
        .clients
        .get_mut("aps")
        .unwrap()
        .networks
        .push("alias".into());
    assert!(config.validate().is_err());
}

#[test]
fn disabled_specific_client_cannot_fall_back_to_an_enabled_prefix() {
    let (mut config, _, backend, calls, _, _) = setup();
    config.clients.insert(
        "disabled".into(),
        Client {
            name: "disabled".into(),
            enabled: false,
            addresses: vec![Prefix::parse("127.0.0.1").unwrap()],
            secret: Zeroizing::new(Vec::new()),
            networks: vec!["home".into()],
            authorization: Default::default(),
        },
    );
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out::default();
    d.receive(
        Instant::now(),
        0,
        peer(),
        &request(1, 0, None, 1, b"anonymous", Some(b"aa-bb-cc-dd-ee-ff:Home")),
        &mut out,
    );
    assert!(out.replies.is_empty());
    assert_eq!(calls.get(), 0);
    assert_eq!(d.pending(), 0);
}

#[test]
fn a_disabled_policy_denies_its_requests_without_invalidating_configuration() {
    let (mut config, _, backend, calls, _, _) = setup();
    config.networks.get_mut("home").unwrap().enabled = false;
    assert!(config.validate().is_ok());
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out::default();
    d.receive(
        Instant::now(),
        0,
        peer(),
        &request(1, 0, None, 1, b"anonymous", Some(b"aa-bb-cc-dd-ee-ff:Home")),
        &mut out,
    );
    assert!(out.replies.is_empty());
    assert_eq!(calls.get(), 0);
}

#[test]
fn disabling_an_object_cancels_pending_work_and_cannot_admit_late_results() {
    for client in [true, false] {
        let (config, tls, backend, _, ready, drops) = setup();
        ready.set(false);
        let mut d = Driver::new(Arc::new(config), backend).unwrap();
        let mut out = Out {
            deliver: true,
            ..Default::default()
        };
        let now = Instant::now();
        pending(&mut d, tls, &mut out, now);
        let mut next = setup().0;
        if client {
            next.clients.get_mut("aps").unwrap().enabled = false;
        } else {
            next.networks.get_mut("home").unwrap().enabled = false;
        }
        d.activate(Arc::new(next)).unwrap();
        ready.set(true);
        d.tick(now, &mut out);
        assert!(out.replies.is_empty());
        assert_eq!(drops.get(), 1);
        assert_eq!(out.events[0].0, Reason::Binding);
    }
}

#[test]
fn the_selected_policy_uses_its_own_server_certificate() {
    let (mut config, _, backend, calls, _, _) = setup();
    let (other, tls, _, _, _, _) = setup();
    config.networks.get_mut("home").unwrap().tls = Some(other.tls.clone());
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    d.tick(now, &mut out);
    assert_eq!(calls.get(), 1);
    assert_eq!(out.replies.pop_front().unwrap()[0], 2);
}

#[test]
fn changing_server_identity_cancels_an_in_progress_conversation() {
    let (config, tls, backend, _, ready, drops) = setup();
    ready.set(false);
    let mut d = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut d, tls, &mut out, now);
    let mut next = setup().0;
    next.networks.get_mut("home").unwrap().tls_tag = [7; 32];
    d.activate(Arc::new(next)).unwrap();
    ready.set(true);
    d.tick(now, &mut out);
    assert_eq!(drops.get(), 1);
    assert!(out.replies.is_empty());
    assert_eq!(out.events[0].0, Reason::Binding);
}

fn access_policy() -> std::sync::Arc<radius_policy::Policy> {
    let profile = radius_policy::Profile {
        id: "11111111-1111-4111-8111-111111111111".into(),
        name: "Default".into(),
        enabled: true,
        vlan: None,
        settings: Default::default(),
    };
    let rule = radius_policy::RuleInput {
        name: "default".into(),
        values: std::collections::BTreeMap::from([(
            "Actions".into(),
            serde_json::json!([format!("ASSIGN({})", profile.id)]),
        )]),
        children: vec![],
    };
    std::sync::Arc::new(radius_policy::Policy::compile(&[rule], &[profile]).unwrap())
}

#[test]
fn vlan_assignment_survives_signed_reply_retransmission_without_extra_accounting() {
    let (mut config, tls, mut backend, _, _, _) = setup();
    let profile = radius_policy::Profile {
        id: "11111111-1111-4111-8111-111111111111".into(),
        name: "Staff".into(),
        enabled: true,
        vlan: Some(20),
        settings: Default::default(),
    };
    let rule = radius_policy::RuleInput {
        name: "default".into(),
        values: BTreeMap::from([(
            "Actions".into(),
            serde_json::json!([format!("ASSIGN({})", profile.id)]),
        )]),
        children: vec![],
    };
    config.networks.get_mut("home").unwrap().access =
        Arc::new(radius_policy::Policy::compile(&[rule], &[profile]).unwrap());
    let accounting_calls = Rc::new(Cell::new(0));
    backend.accounting = Some((Rc::new(Cell::new(true)), accounting_calls.clone(), None));
    let mut driver = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    let last = pending(&mut driver, tls, &mut out, now);
    driver.tick(now, &mut out);
    let reply = out.replies.pop_front().unwrap();
    assert_eq!(reply[0], 2);
    let mut pos = 20;
    let mut group = None;
    while pos < reply.len() {
        let len = reply[pos + 1] as usize;
        if reply[pos] == 81 {
            group = Some(reply[pos + 2..pos + len].to_vec());
        }
        pos += len;
    }
    assert_eq!(group, Some(b"\x0020".to_vec()));
    assert_eq!(accounting_calls.get(), 1);
    driver.receive(now, 0, peer(), &last, &mut out);
    assert_eq!(out.replies.pop_front().unwrap(), reply);
    assert_eq!(accounting_calls.get(), 1);
}

#[test]
fn profile_conflict_refuses_before_accounting_reservation() {
    let (mut config, tls, mut backend, _, _, _) = setup();
    let profiles = [
        radius_policy::Profile {
            id: "11111111-1111-4111-8111-111111111111".into(),
            name: "A".into(),
            enabled: true,
            vlan: Some(10),
            settings: Default::default(),
        },
        radius_policy::Profile {
            id: "22222222-2222-4222-8222-222222222222".into(),
            name: "B".into(),
            enabled: true,
            vlan: Some(20),
            settings: Default::default(),
        },
    ];
    let rules = profiles
        .iter()
        .map(|p| radius_policy::RuleInput {
            name: p.name.clone(),
            values: BTreeMap::from([(
                "Actions".into(),
                serde_json::json!([format!("ASSIGN({})", p.id)]),
            )]),
            children: vec![],
        })
        .collect::<Vec<_>>();
    config.networks.get_mut("home").unwrap().access =
        Arc::new(radius_policy::Policy::compile(&rules, &profiles).unwrap());
    let accounting_calls = Rc::new(Cell::new(0));
    backend.accounting = Some((Rc::new(Cell::new(true)), accounting_calls.clone(), None));
    let mut driver = Driver::new(Arc::new(config), backend).unwrap();
    let mut out = Out {
        deliver: true,
        ..Default::default()
    };
    let now = Instant::now();
    pending(&mut driver, tls, &mut out, now);
    driver.tick(now, &mut out);
    let reply = out.replies.pop_front().unwrap();
    assert_eq!(reply[0], 3);
    assert_eq!(accounting_calls.get(), 0);
    let mut pos = 20;
    while pos < reply.len() {
        assert!(!matches!(reply[pos], 25 | 26 | 64 | 65 | 81));
        pos += reply[pos + 1] as usize;
    }
}

#[test]
fn complete_profile_is_cached_and_missing_equipment_mapping_refuses_before_accounting() {
    for supported in [true, false] {
        let (mut config, tls, mut backend, _, _, _) = setup();
        let profile=radius_policy::Profile{
            id:"11111111-1111-4111-8111-111111111111".into(),name:"Guest".into(),enabled:true,vlan:Some(20),
            settings:serde_json::from_value(serde_json::json!({"DownloadBitsPerSecond":10_000_000,"IdleTimeoutSeconds":120,"FilterIds":["guest"],"SessionTimeoutSeconds":60})).unwrap(),
        };
        let rule = radius_policy::RuleInput {
            name: "default".into(),
            values: BTreeMap::from([(
                "Actions".into(),
                serde_json::json!([format!("ASSIGN({})", profile.id)]),
            )]),
            children: vec![],
        };
        config.networks.get_mut("home").unwrap().access =
            Arc::new(radius_policy::Policy::compile(&[rule], &[profile]).unwrap());
        if supported {
            config.clients.get_mut("aps").unwrap().authorization=serde_json::from_value(serde_json::json!({"settings":{"DownloadBitsPerSecond":[{"target":{"vendor":14122,"attribute":8},"format":"integer32"}]}})).unwrap();
        }
        let calls = Rc::new(Cell::new(0));
        backend.accounting = Some((Rc::new(Cell::new(true)), calls.clone(), None));
        let mut driver = Driver::new(Arc::new(config), backend).unwrap();
        let mut out = Out {
            deliver: true,
            ..Default::default()
        };
        let now = Instant::now();
        let last = pending(&mut driver, tls, &mut out, now);
        driver.tick(now, &mut out);
        let reply = out.replies.pop_front().unwrap();
        assert_eq!(reply[0], if supported { 2 } else { 3 });
        assert_eq!(calls.get(), usize::from(supported));
        let mut attributes = Vec::new();
        let mut at = 20;
        while at < reply.len() {
            let length = reply[at + 1] as usize;
            attributes.push((reply[at], reply[at + 2..at + length].to_vec()));
            at += length;
        }
        if supported {
            assert!(attributes.contains(&(27, 60u32.to_be_bytes().to_vec())));
            assert!(attributes.contains(&(29, 0u32.to_be_bytes().to_vec())));
            assert!(attributes.contains(&(28, 120u32.to_be_bytes().to_vec())));
            assert!(attributes.contains(&(11, b"guest".to_vec())));
            assert!(attributes.contains(&(26, vec![0, 0, 55, 42, 8, 6, 0, 152, 150, 128])));
        } else {
            assert!(!attributes
                .iter()
                .any(|(kind, _)| matches!(kind, 11 | 25..=29 | 64 | 65 | 81)));
        }
        driver.receive(now, 0, peer(), &last, &mut out);
        assert_eq!(out.replies.pop_front().unwrap(), reply);
        assert_eq!(calls.get(), usize::from(supported));
    }
}
