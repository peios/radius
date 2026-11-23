//! Synthetic credentials and certificates are generated locally and never logged.
use crate::Result;
use hmac::{Hmac, Mac};
use md5::Md5;
use radius_accounting::{
    model::Observation,
    wire::{self, Attribute},
};
use radius_core::{Binding, Limits};
use radiusd::{
    config::{Client, Config, Network, Prefix},
    driver::{AdmissionContext, AdmissionExtras, Backend, Event, Output, Progress, Reason},
};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{Cursor, Write},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use zeroize::Zeroizing;

pub const SECRET: &[u8] = b"synthetic-radius-qualification-secret";
pub const PASSWORD: &[u8] = b"synthetic-password";

/// Independent synthetic dynamic-authorization reply encoder. Structured fuzz
/// inputs reach authenticated ACK/NAK semantics instead of stopping at the MAC.
pub fn dynamic_reply(sent: &[u8], code: u8, attrs: &[(u8, Vec<u8>)], ma: bool) -> Vec<u8> {
    use md5::Digest;
    let mut bytes = vec![code, sent[1], 0, 0];
    bytes.extend_from_slice(&sent[4..20]);
    for (kind, value) in attrs {
        bytes.extend_from_slice(&[*kind, (value.len() + 2) as u8]);
        bytes.extend_from_slice(value);
    }
    if ma {
        bytes.extend_from_slice(&[80, 18]);
        bytes.extend_from_slice(&[0; 16]);
    }
    let len = (bytes.len() as u16).to_be_bytes();
    bytes[2..4].copy_from_slice(&len);
    if ma {
        let mut mac = <Hmac<Md5> as Mac>::new_from_slice(SECRET).unwrap();
        Mac::update(&mut mac, &bytes);
        let at = bytes.len() - 16;
        bytes[at..].copy_from_slice(&mac.finalize().into_bytes());
    }
    let mut hash = Md5::new();
    Digest::update(&mut hash, &bytes);
    Digest::update(&mut hash, SECRET);
    bytes[4..20].copy_from_slice(&hash.finalize());
    bytes
}

pub struct Tls {
    pub server: Arc<ServerConfig>,
    pub client: Arc<ClientConfig>,
}
impl Tls {
    pub fn new() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["radius.test".into()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let server = radius_core::server_config(vec![cert.clone()], key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        Self {
            server,
            client: Arc::new(client),
        }
    }
    pub fn peer(&self) -> TtlsPeer {
        TtlsPeer {
            tls: ClientConnection::new(
                self.client.clone(),
                ServerName::try_from("radius.test").unwrap(),
            )
            .unwrap(),
            server: Vec::new(),
            sent: false,
            id: 1,
        }
    }
}
impl Default for Tls {
    fn default() -> Self {
        Self::new()
    }
}

pub fn address(client: usize, device: usize) -> SocketAddr {
    (
        Ipv4Addr::new(127, 1, (client / 250) as u8, (client % 250 + 1) as u8),
        10000 + (device % 50000) as u16,
    )
        .into()
}
pub fn binding(client: usize) -> Binding {
    Binding {
        client: client as u64,
        network: 1,
        trust_generation: 1,
        source: address(client, 0).ip(),
    }
}
pub fn attribute(packet: &mut Vec<u8>, kind: u8, value: &[u8]) {
    assert!(value.len() <= 253);
    packet.extend_from_slice(&[kind, (value.len() + 2) as u8]);
    packet.extend_from_slice(value);
}
pub fn request(id: u8, eap_id: u8, state: Option<[u8; 16]>, typ: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![1, id, 0, 0];
    packet.extend_from_slice(&[id; 16]);
    attribute(&mut packet, 80, &[0; 16]);
    let mut eap = vec![2, eap_id];
    eap.extend_from_slice(&((data.len() + 5) as u16).to_be_bytes());
    eap.push(typ);
    eap.extend_from_slice(data);
    for chunk in eap.chunks(253) {
        attribute(&mut packet, 79, chunk);
    }
    if let Some(state) = state {
        attribute(&mut packet, 24, &state);
    }
    attribute(&mut packet, 30, b"00-00-00-00-00-01:Qualification");
    resign(&mut packet);
    packet
}
pub fn resign(packet: &mut [u8]) {
    if packet.len() < 38 || packet.len() > u16::MAX as usize {
        return;
    }
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[22..38].fill(0);
    let mut h = Hmac::<Md5>::new_from_slice(SECRET).unwrap();
    h.update(packet);
    packet[22..38].copy_from_slice(&h.finalize().into_bytes());
}
pub fn decoded(reply: &[u8]) -> (Vec<u8>, Option<[u8; 16]>) {
    assert!((20..=4096).contains(&reply.len()));
    assert_eq!(
        u16::from_be_bytes([reply[2], reply[3]]) as usize,
        reply.len()
    );
    let mut eap = Vec::new();
    let mut state = None;
    let mut offset = 20;
    while offset < reply.len() {
        assert!(offset + 2 <= reply.len());
        let len = reply[offset + 1] as usize;
        assert!(len >= 2 && offset + len <= reply.len());
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

pub struct TtlsPeer {
    tls: ClientConnection,
    server: Vec<u8>,
    sent: bool,
    id: u8,
}
impl TtlsPeer {
    pub fn initial(&self) -> Vec<u8> {
        request(1, 0, None, 1, b"anonymous")
    }
    /// None is terminal. Only the real engine's challenge is used as State.
    pub fn respond(&mut self, reply: &[u8]) -> Result<Option<Vec<u8>>> {
        let (eap, state) = decoded(reply);
        if matches!(reply[0], 2 | 3) {
            return Ok(None);
        }
        if reply[0] != 11 || eap.len() < 6 || eap[4] != 21 {
            return Err("invalid TTLS challenge".into());
        }
        let flags = eap[5];
        let offset = if flags & 0x80 != 0 { 10 } else { 6 };
        if eap.len() < offset {
            return Err("truncated TTLS challenge".into());
        }
        self.server.extend_from_slice(&eap[offset..]);
        let mut send = vec![0];
        if flags & 0x40 == 0 {
            let mut cursor = Cursor::new(std::mem::take(&mut self.server));
            while cursor.position() < cursor.get_ref().len() as u64 {
                self.tls.read_tls(&mut cursor)?;
                self.tls.process_new_packets()?;
            }
            if !self.tls.is_handshaking() && !self.sent {
                let mut avps = Vec::new();
                for (code, value) in [(1u32, b"synthetic-user".as_slice()), (2, PASSWORD)] {
                    avps.extend_from_slice(&code.to_be_bytes());
                    avps.extend_from_slice(&[0x40, 0, 0, (8 + value.len()) as u8]);
                    avps.extend_from_slice(value);
                    avps.resize(avps.len().next_multiple_of(4), 0);
                }
                self.tls.writer().write_all(&avps)?;
                self.sent = true;
            }
            while self.tls.wants_write() {
                self.tls.write_tls(&mut send)?;
            }
        }
        self.id = self.id.wrapping_add(1);
        Ok(Some(request(self.id, eap[1], state, 21, &send)))
    }
}

pub fn config(tls: &Tls, clients: usize, limits: Limits) -> Config {
    let verifications = limits.attempts;
    let profile = radius_policy::Profile {
        id: "11111111-1111-4111-8111-111111111111".into(),
        name: "Synthetic".into(),
        enabled: true,
        vlan: None,
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
    Config {
        labels: Default::default(),
        diagnostics: Default::default(),
        saved_fingerprint: "synthetic".into(),
        listeners: vec!["127.0.0.1:1812".parse().unwrap()],
        limits,
        verifications,
        clients: (0..clients)
            .map(|i| {
                let name = format!("synthetic-ap-{i}");
                (
                    name.clone(),
                    Client {
                        name,
                        enabled: true,
                        addresses: vec![Prefix::parse(&address(i, 0).ip().to_string()).unwrap()],
                        secret: Zeroizing::new(SECRET.to_vec()),
                        networks: vec!["synthetic-network".into()],
                        authorization: Default::default(),
                    },
                )
            })
            .collect(),
        networks: BTreeMap::from([(
            "synthetic-network".into(),
            Network {
                authentication_profile: None,
                access: Arc::new(radius_policy::Policy::compile(&[rule], &[profile]).unwrap()),
                enabled: true,
                tls: None,
                tls_tag: [0; 32],
                methods: vec![radius_core::Method::TtlsPap],
                ssid: b"Qualification".to_vec(),
                security: vec![1],
                reauthenticate_seconds: 3600,
            },
        )]),
        tls: tls.server.clone(),
        fingerprint: [1; 32],
    }
}

#[derive(Clone, Copy)]
pub enum Authority {
    Ready,
    Failed,
    Stalled,
    AccountingFailed,
    AccountingStalled,
}
pub struct SyntheticBackend(pub Authority);
impl Backend for SyntheticBackend {
    type Work = ();
    type Subject = ();
    fn begin(&mut self, v: radius_core::Verification) -> std::result::Result<(), Reason> {
        if matches!(self.0, Authority::Failed) {
            return Err(Reason::Backend);
        }
        match &v.credentials.proof {
            radius_core::Credential::Password(p)
                if p.as_slice() == PASSWORD && v.credentials.username == b"synthetic-user" =>
            {
                Ok(())
            }
            _ => Err(Reason::Credentials),
        }
    }
    fn step(&mut self, _: &mut ()) -> Progress<()> {
        if matches!(self.0, Authority::Stalled) {
            Progress::Waiting
        } else {
            Progress::Complete(())
        }
    }
    fn admission(&mut self, _: &(), _: &str, _: &Network) -> std::result::Result<(), Reason> {
        Ok(())
    }
    fn identity<'a>(&self, _: &'a ()) -> (&'a str, &'a [u8]) {
        ("synthetic-user", b"synthetic-sid")
    }
    fn accounting(
        &mut self,
        _: &(),
        _: AdmissionContext<'_>,
    ) -> std::result::Result<Option<AdmissionExtras>, Reason> {
        match self.0 {
            Authority::AccountingFailed => Err(Reason::Accounting),
            Authority::AccountingStalled => Ok(None),
            _ => Ok(Some(AdmissionExtras::default())),
        }
    }
}
#[derive(Default)]
pub struct Capture {
    pub replies: VecDeque<(SocketAddr, Vec<u8>)>,
    pub events: Vec<Reason>,
    pub discarded: usize,
    pub lose_events: bool,
}
impl Output for Capture {
    fn send(&mut self, _: usize, reply: &radius_core::Reply) -> bool {
        self.replies.push_back((reply.peer, reply.bytes.clone()));
        true
    }
    fn event(&mut self, e: Event<'_>) {
        if !self.lose_events {
            self.events.push(e.reason);
        }
    }
    fn discarded(&mut self) {
        self.discarded += 1;
    }
}

pub fn observation(sequence: usize, clients: usize, now_ms: i64) -> Observation {
    let attrs = [
        Attribute {
            kind: 32,
            value: format!("synthetic-nas-{}", sequence % clients).into_bytes(),
        },
        Attribute {
            kind: 44,
            value: format!("synthetic-session-{sequence}").into_bytes(),
        },
        Attribute::integer(40, 1),
        Attribute::integer(55, (now_ms / 1000) as u32),
    ];
    let packet = wire::request(sequence as u8, &attrs, SECRET, true).unwrap();
    let request = wire::Request::parse(&packet, SECRET, true).unwrap();
    Observation::new(
        &request,
        format!("synthetic-client-{}", sequence % clients),
        address(sequence % clients, 0).ip(),
        now_ms,
    )
    .unwrap()
}
