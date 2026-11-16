use hmac::{Hmac, Mac};
use md5::Md5;
use radius_core::{Limits, Reply, Verification};
use radiusd::{
    config::{Client, Config, Network, Prefix},
    driver::{Backend, Driver, Event, Output, Progress, Reason},
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

struct Fake {
    calls: Rc<Cell<usize>>,
    ready: Rc<Cell<bool>>,
    drops: Rc<Cell<usize>>,
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
    fn admission(&mut self, _: &(), security: &[u8]) -> Result<(), Reason> {
        if security == [1] {
            Ok(())
        } else {
            Err(Reason::Policy)
        }
    }
    fn identity<'a>(&self, _: &'a ()) -> (&'a str, &'a [u8]) {
        ("canonical-jack", b"test-sid")
    }
}
#[derive(Default)]
struct Out {
    replies: VecDeque<Vec<u8>>,
    events: Vec<(Reason, Option<String>, Option<String>)>,
    deliver: bool,
}
impl Output for Out {
    fn send(&mut self, _: usize, r: &Reply) -> bool {
        self.replies.push_back(r.bytes.clone());
        self.deliver
    }
    fn event(&mut self, e: Event<'_>) {
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
                addresses: vec![Prefix::parse("127.0.0.0/8").unwrap()],
                secret: Zeroizing::new(SECRET.to_vec()),
                networks: vec!["home".into()],
            },
        )]),
        networks: BTreeMap::from([(
            "home".into(),
            Network {
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
            addresses: vec![Prefix::parse("127.0.0.1").unwrap()],
            secret: Zeroizing::new(b"other-secret-at-least-16".to_vec()),
            networks: vec!["home".into()],
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
            addresses: vec![Prefix::parse("127.0.0.0/8").unwrap()],
            secret: Zeroizing::new(SECRET.to_vec()),
            networks: vec!["home".into()],
        },
    );
    assert!(config.validate().is_err());
    config.clients.remove("other");
    config.networks.insert(
        "alias".into(),
        Network {
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
