use super::{credentials::material, registry};
use crate::{
    model::{Issue, Kind, Stored, Value, ROOT},
    runtime::{Client, Config, Network, Prefix},
};
use peios::{
    registry::{Key, KeyAccess, NotifyFilter, OpenFlags},
    security::{sddl, SecurityDescriptor},
};
use ring::digest::{Context, SHA256};
use std::{
    collections::BTreeMap,
    io,
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn invalid(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s.into())
}
fn number(s: &Stored, name: &str, default: u32) -> io::Result<u32> {
    match s.settings.get(name) {
        None => Ok(default),
        Some(Value::Number(n)) => Ok(*n),
        _ => Err(invalid(format!("Settings.{name}: expected REG_DWORD"))),
    }
}
fn stamp(hash: &mut Context, b: &[u8]) {
    hash.update(&(b.len() as u64).to_be_bytes());
    hash.update(b);
}
pub fn descriptor(v: &Value) -> io::Result<SecurityDescriptor> {
    let sd = match v {
        Value::Text(s) => sddl::parse(s),
        Value::Bytes(b) => SecurityDescriptor::from_validated_bytes(b.clone()),
        _ => return Err(invalid("expected SDDL or binary SD")),
    }
    .map_err(io::Error::from)?;
    if sd.view().map_err(io::Error::from)?.owner().is_none() {
        return Err(invalid("ConnectSecurity requires an owner"));
    }
    Ok(sd)
}
pub fn prepare(stored: &Stored) -> io::Result<Config> {
    if let Some(first) = stored.validate().first() {
        return Err(invalid(format!(
            "{} {}: {}",
            first.object, first.field, first.message
        )));
    }
    let listeners = match stored.settings.get("Listen") {
        Some(Value::List(v)) => v
            .iter()
            .map(|s| s.parse().map_err(|_| invalid("invalid listener address")))
            .collect::<io::Result<Vec<_>>>()?,
        _ => return Err(invalid("Settings.Listen: expected listener list")),
    };
    let limits = radius_core::Limits {
        idle: Duration::from_secs(u64::from(number(stored, "IdleTimeoutSeconds", 30)?)),
        overall: Duration::from_secs(u64::from(number(stored, "OverallTimeoutSeconds", 120)?)),
        cache_lifetime: Duration::from_secs(u64::from(number(stored, "ReplyCacheSeconds", 15)?)),
        attempts: number(stored, "MaxAttempts", 256)? as usize,
        per_client: number(stored, "MaxAttemptsPerClient", 32)? as usize,
        cached_replies: number(stored, "MaxCachedReplies", 1024)? as usize,
        frame_payload: number(stored, "FragmentBytes", 1000)? as usize,
    };
    let verifications = number(stored, "MaxVerifications", 32)? as usize;
    let saved_fingerprint = stored.fingerprint();
    let mut hash = Context::new(&SHA256);
    stamp(&mut hash, stored.authentication_fingerprint().as_bytes());
    // An empty resolver allows an unconfigured daemon to serve local status but
    // cannot authenticate TLS. Disable resumption as for configured identities.
    let mut empty = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid("TLS versions unavailable"))?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    empty.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    empty.send_tls13_tickets = 0;
    empty.max_tls13_tickets = 0;
    let mut identities = BTreeMap::new();
    for r in stored.objects.iter().filter(|r| r.kind == Kind::Identity) {
        let mut identity_hash = Context::new(&SHA256);
        let mut chain = Vec::new();
        for path in r.list("CertificateFiles").unwrap() {
            let bytes = material(path, false, 65536)
                .map_err(|e| invalid(format!("{} CertificateFiles: {e}", r.id)))?;
            stamp(&mut hash, &bytes);
            stamp(&mut identity_hash, &bytes);
            chain.push(rustls::pki_types::CertificateDer::from(bytes.to_vec()));
        }
        let key = material(r.text("PrivateKeyFile").unwrap(), true, 65536)
            .map_err(|e| invalid(format!("{} PrivateKeyFile: {e}", r.id)))?;
        stamp(&mut hash, &key);
        let key = rustls::pki_types::PrivateKeyDer::try_from(key.to_vec())
            .map_err(|_| invalid(format!("{}: invalid DER private key", r.id)))?;
        let tls = radius_core::server_config(chain, key)
            .map_err(|_| invalid(format!("{}: certificate and key do not match", r.id)))?;
        let tag: [u8; 32] = identity_hash.finish().as_ref().try_into().unwrap();
        identities.insert(r.id.clone(), (tls, tag));
    }
    let mut networks = BTreeMap::new();
    for r in stored
        .objects
        .iter()
        .filter(|r| r.kind == Kind::Policy && r.text("ServiceKind") != Some("accounting-only"))
    {
        let profile = stored
            .get(Kind::Profile, r.text("AuthenticationProfile").unwrap())
            .unwrap();
        let (tls, tls_tag) = identities
            .get(profile.text("ServerIdentity").unwrap())
            .unwrap();
        let methods = profile
            .list("AuthenticationMethods")
            .unwrap()
            .iter()
            .map(|s| radius_core::Method::parse(s).unwrap())
            .collect();
        let security = descriptor(r.values.get("ConnectSecurity").unwrap())
            .map_err(|e| invalid(format!("{} ConnectSecurity: {e}", r.id)))?;
        networks.insert(
            r.id.clone(),
            Network {
                access: Arc::new(crate::access_policy::compile(stored, &r.id).map_err(invalid)?),
                enabled: r.enabled() && profile.enabled(),
                tls: Some(tls.clone()),
                tls_tag: *tls_tag,
                methods,
                ssid: r.text("SSID").unwrap().as_bytes().to_vec(),
                security: security.as_bytes().to_vec(),
                reauthenticate_seconds: r.number("ReauthenticateSeconds").unwrap(),
            },
        );
    }
    let mut clients = BTreeMap::new();
    for r in stored.objects.iter().filter(|r| r.kind == Kind::Client) {
        let secret = if r.enabled() {
            material(r.text("SecretFile").unwrap(), true, 1024)
                .map_err(|e| invalid(format!("{} SecretFile: {e}", r.id)))?
        } else {
            Zeroizing::new(Vec::new())
        };
        stamp(&mut hash, &secret);
        clients.insert(
            r.id.clone(),
            Client {
                name: r.id.clone(),
                enabled: r.enabled(),
                secret,
                addresses: r
                    .list("Addresses")
                    .unwrap()
                    .iter()
                    .map(|s| Prefix::parse(s).map_err(invalid))
                    .collect::<io::Result<_>>()?,
                networks: r
                    .list("Policies")
                    .unwrap()
                    .iter()
                    .filter(|id| networks.contains_key(*id))
                    .cloned()
                    .collect(),
            },
        );
    }
    let tls = identities
        .values()
        .next()
        .map(|(tls, _)| tls.clone())
        .unwrap_or_else(|| Arc::new(empty));
    let config = Config {
        saved_fingerprint,
        listeners,
        limits,
        verifications,
        clients,
        networks,
        tls,
        fingerprint: hash.finish().as_ref().try_into().unwrap(),
    };
    config.validate().map_err(invalid)?;
    Ok(config)
}
pub fn load() -> io::Result<Config> {
    prepare(&registry::read()?)
}
pub enum Update {
    Pending,
    Valid(Arc<Config>),
    Invalid {
        saved: Option<String>,
        issues: Vec<Issue>,
    },
}
pub fn watch() -> Receiver<Update> {
    let (tx, rx) = mpsc::sync_channel(2);
    thread::spawn(move || worker(tx));
    rx
}
fn worker(tx: SyncSender<Update>) {
    let mut watch: Option<Key> = None;
    let mut fingerprint = None;
    let mut saved_fingerprint = None;
    let mut last_check = Instant::now() - Duration::from_secs(3);
    let mut buffer = [0; 8192];
    loop {
        if watch.is_none() {
            watch = Key::open(None, ROOT, KeyAccess::NOTIFY, OpenFlags::empty())
                .ok()
                .and_then(|key| {
                    key.notify(NotifyFilter::ALL, true).ok()?;
                    key.set_nonblocking(true).ok()?;
                    Some(key)
                });
            fingerprint = None;
        }
        let changed = match watch.as_ref().map(|k| k.read_watch_events(&mut buffer)) {
            Some(Ok(v)) => !v.is_empty(),
            Some(Err(_)) => {
                watch = None;
                true
            }
            None => true,
        };
        if changed || last_check.elapsed() >= Duration::from_secs(1) {
            if changed && tx.send(Update::Pending).is_err() {
                return;
            }
            let stored = registry::read();
            let saved = stored.as_ref().ok().map(Stored::fingerprint);
            let next = stored
                .as_ref()
                .map_err(|e| invalid(e.to_string()))
                .and_then(prepare);
            match next {
                Ok(config) if watch.is_some() => {
                    if changed
                        || fingerprint != Some(config.fingerprint)
                        || saved_fingerprint.as_ref() != Some(&config.saved_fingerprint)
                    {
                        if !changed && tx.send(Update::Pending).is_err() {
                            return;
                        }
                        fingerprint = Some(config.fingerprint);
                        saved_fingerprint = Some(config.saved_fingerprint.clone());
                        if tx.send(Update::Valid(Arc::new(config))).is_err() {
                            return;
                        }
                    }
                }
                result => {
                    watch = None;
                    fingerprint = None;
                    let mut issues = stored
                        .as_ref()
                        .ok()
                        .map(Stored::validate)
                        .unwrap_or_default();
                    if issues.is_empty() {
                        issues.push(Issue {
                            object: "Configuration".into(),
                            field: String::new(),
                            message: result
                                .err()
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| "Registry watch unavailable".into()),
                        });
                    }
                    if tx.send(Update::Invalid { saved, issues }).is_err() {
                        return;
                    }
                }
            }
            last_check = Instant::now();
        }
        thread::sleep(Duration::from_millis(50));
    }
}
