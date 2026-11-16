use crate::config::{Client, Config, Network, Prefix, ROOT};
use peios::{
    file::{fd_get_sd, SecInfo},
    registry::{Key, KeyAccess, NotifyFilter, OpenFlags, RegValue, Transaction, ValueType},
    security::{sddl, AceType, Control, Sid, WellKnown},
};
use ring::digest::{Context, SHA256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, Read},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
struct ConfigKey<'a> {
    key: Key,
    transaction: &'a Transaction,
}

fn open<'a>(
    parent: Option<&ConfigKey<'a>>,
    name: &str,
    transaction: &'a Transaction,
) -> io::Result<ConfigKey<'a>> {
    Key::open_transacted(
        parent.map(|parent| &parent.key),
        name,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
        Some(transaction),
    )
    .map(|key| ConfigKey { key, transaction })
    .map_err(Into::into)
}
fn value(key: &ConfigKey<'_>, name: &str) -> io::Result<Option<RegValue>> {
    match key.key.query_value(name.as_bytes(), Some(key.transaction)) {
        Ok(value) if value.data.len() <= 65536 => Ok(Some(value)),
        Ok(_) => Err(invalid("registry value too large")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn required(key: &ConfigKey<'_>, name: &str) -> io::Result<RegValue> {
    value(key, name)?.ok_or_else(|| invalid("required registry value missing"))
}
fn text(value: &RegValue) -> io::Result<String> {
    if value.ty != ValueType::SZ {
        return Err(invalid("expected REG_SZ"));
    }
    let bytes = value.data.strip_suffix(&[0]).unwrap_or(&value.data);
    if bytes.contains(&0) {
        return Err(invalid("embedded zero in registry text"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| invalid("registry text is not UTF-8"))
}
fn string(key: &ConfigKey<'_>, name: &str) -> io::Result<String> {
    text(&required(key, name)?)
}
fn strings(key: &ConfigKey<'_>, name: &str) -> io::Result<Vec<String>> {
    let value = required(key, name)?;
    if value.ty != ValueType::MULTI_SZ || !value.data.ends_with(&[0, 0]) {
        return Err(invalid("expected terminated REG_MULTI_SZ"));
    }
    let data = &value.data[..value.data.len() - 2];
    let mut result = Vec::new();
    if data.is_empty() {
        return Ok(result);
    }
    for entry in data.split(|b| *b == 0) {
        if entry.is_empty() {
            return Err(invalid("empty registry list entry"));
        }
        if result.len() >= 256 {
            return Err(invalid("registry list too long"));
        }
        result.push(
            String::from_utf8(entry.to_vec()).map_err(|_| invalid("registry list is not UTF-8"))?,
        );
    }
    Ok(result)
}
fn number(key: &ConfigKey<'_>, name: &str, default: u32) -> io::Result<u32> {
    match value(key, name)? {
        None => Ok(default),
        Some(value) if value.ty == ValueType::DWORD && value.data.len() == 4 => {
            Ok(u32::from_le_bytes(value.data.try_into().unwrap()))
        }
        _ => Err(invalid("expected REG_DWORD")),
    }
}
fn children(key: &ConfigKey<'_>) -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    for entry in key.key.subkeys(Some(key.transaction)) {
        if result.len() >= 256 {
            return Err(invalid("too many registry records"));
        }
        let name = String::from_utf8(entry.map_err(io::Error::from)?.name)
            .map_err(|_| invalid("invalid registry record name"))?;
        if !crate::config::valid_name(&name) {
            return Err(invalid("invalid record identifier"));
        }
        result.push(name);
    }
    Ok(result)
}

/// Native file-policy verification is intentionally conservative for this
/// milestone: private, regular, singly linked, administrator-owned files with
/// plain grants only to SYSTEM, Administrators and the radiusd service SID.
/// A mode-bit check is not evidence of KACS protection.
fn material(path: &str, secret: bool, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("credential path must be absolute"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() == 0 || before.len() > max as u64 {
        return Err(invalid("invalid credential file"));
    }
    let sd = fd_get_sd(file.as_fd(), SecInfo::OWNER | SecInfo::DACL).map_err(io::Error::from)?;
    let view = sd.view().map_err(io::Error::from)?;
    let system = Sid::well_known(WellKnown::System);
    let admins = Sid::well_known(WellKnown::Administrators);
    let service: Sid = crate::config::SERVICE_SID
        .parse()
        .map_err(io::Error::from)?;
    if view.owner() != Some(system.as_ref()) && view.owner() != Some(admins.as_ref()) {
        return Err(invalid("credential owner is not trusted"));
    }
    let dacl = view
        .dacl()
        .ok_or_else(|| invalid("credential file has an unrestricted DACL"))?;
    for ace in dacl.iter() {
        if ace.ace_type() == AceType::AccessDenied {
            continue;
        }
        if ace.ace_type() != AceType::AccessAllowed {
            return Err(invalid("unsupported credential file grant"));
        }
        let trusted = ace
            .sid()
            .is_some_and(|sid| sid == system.as_ref() || sid == admins.as_ref());
        let service_read = ace.sid() == Some(service.as_ref());
        // Public certificates may be read, but only trusted principals may
        // modify them or their security. Generic bits are treated conservatively.
        let read_only = ace.mask() & !(0xa0000000 | 0x001200a9) == 0;
        if !trusted && (!read_only || (secret && !service_read)) {
            return Err(invalid("credential file grants excessive access"));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > max
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mtime() != after.mtime()
    {
        return Err(invalid("credential changed during read"));
    }
    Ok(bytes)
}

struct PreparedClient {
    addresses: Vec<Prefix>,
    secret_file: String,
    networks: Vec<String>,
}

struct Prepared {
    listeners: Vec<std::net::SocketAddr>,
    limits: radius_core::Limits,
    verifications: usize,
    certificate_files: Vec<String>,
    private_key_file: String,
    clients: BTreeMap<String, PreparedClient>,
    networks: BTreeMap<String, Network>,
    hash: Context,
}

fn stamp(hash: &mut Context, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// Copy Registry-owned configuration in one bounded snapshot. Returning this
/// description closes the transaction before any credential file is opened.
fn read_registry() -> io::Result<Prepared> {
    let transaction = Transaction::begin_read_only().map_err(io::Error::from)?;
    let root = open(None, ROOT, &transaction)?;
    let settings = open(Some(&root), "Settings", &transaction)?;
    let tls = open(Some(&root), "TLS", &transaction)?;
    let networks_key = open(Some(&root), "Networks", &transaction)?;
    let clients_key = open(Some(&root), "Clients", &transaction)?;
    let listeners = strings(&settings, "Listen")?
        .iter()
        .map(|s| s.parse().map_err(|_| invalid("invalid listener address")))
        .collect::<io::Result<Vec<_>>>()?;
    let limits = radius_core::Limits {
        idle: Duration::from_secs(u64::from(number(&settings, "IdleTimeoutSeconds", 30)?)),
        overall: Duration::from_secs(u64::from(number(&settings, "OverallTimeoutSeconds", 120)?)),
        cache_lifetime: Duration::from_secs(u64::from(number(&settings, "ReplyCacheSeconds", 15)?)),
        attempts: number(&settings, "MaxAttempts", 256)? as usize,
        per_client: number(&settings, "MaxAttemptsPerClient", 32)? as usize,
        cached_replies: number(&settings, "MaxCachedReplies", 1024)? as usize,
        frame_payload: number(&settings, "FragmentBytes", 1000)? as usize,
    };
    let verifications = number(&settings, "MaxVerifications", 32)? as usize;
    let mut hash = Context::new(&SHA256);
    stamp(
        &mut hash,
        format!("{listeners:?}{limits:?}{verifications}").as_bytes(),
    );
    let certificate_files = strings(&tls, "CertificateFiles")?;
    let private_key_file = string(&tls, "PrivateKeyFile")?;
    if certificate_files.is_empty() || certificate_files.len() > 16 {
        return Err(invalid("invalid certificate chain length"));
    }
    let mut networks = BTreeMap::new();
    for name in children(&networks_key)? {
        let key = open(Some(&networks_key), &name, &transaction)?;
        let ssid = string(&key, "SSID")?.into_bytes();
        let security = required(&key, "ConnectSecurity")?;
        let security = match security.ty {
            ValueType::SZ => sddl::parse(&text(&security)?).map_err(io::Error::from)?,
            ValueType::BINARY => {
                peios::security::SecurityDescriptor::from_validated_bytes(security.data)
                    .map_err(io::Error::from)?
            }
            _ => return Err(invalid("ConnectSecurity must be SDDL or binary SD")),
        };
        if security.view().map_err(io::Error::from)?.owner().is_none() {
            return Err(invalid("ConnectSecurity requires an owner"));
        }
        // Missing descriptors are rejected above; a deliberately supplied
        // absent DACL keeps KACS grant-all semantics rather than being rewritten.
        let _ = security
            .view()
            .map_err(io::Error::from)?
            .control()
            .contains(Control::DACL_PRESENT);
        let reauthenticate_seconds = number(&key, "ReauthenticateSeconds", 3600)?;
        let methods = match value(&key, "AuthenticationMethods")? {
            None => vec![radius_core::Method::TtlsPap],
            Some(_) => strings(&key, "AuthenticationMethods")?
                .iter()
                .map(|name| {
                    radius_core::Method::parse(name)
                        .ok_or_else(|| invalid("unknown authentication method"))
                })
                .collect::<io::Result<Vec<_>>>()?,
        };
        stamp(&mut hash, name.as_bytes());
        stamp(&mut hash, &ssid);
        stamp(&mut hash, security.as_bytes());
        stamp(&mut hash, &reauthenticate_seconds.to_be_bytes());
        for method in &methods {
            stamp(&mut hash, method.name().as_bytes());
        }
        networks.insert(
            name,
            Network {
                methods,
                ssid,
                security: security.as_bytes().to_vec(),
                reauthenticate_seconds,
            },
        );
    }
    let mut clients = BTreeMap::new();
    for name in children(&clients_key)? {
        let key = open(Some(&clients_key), &name, &transaction)?;
        let sources = strings(&key, "Addresses")?;
        let addresses = sources
            .iter()
            .map(|s| Prefix::parse(s).map_err(invalid))
            .collect::<io::Result<Vec<_>>>()?;
        let secret_file = string(&key, "SecretFile")?;
        let allowed = strings(&key, "Networks")?;
        stamp(&mut hash, name.as_bytes());
        for source in &sources {
            stamp(&mut hash, source.as_bytes());
        }
        for network in &allowed {
            stamp(&mut hash, network.as_bytes());
        }
        clients.insert(
            name.clone(),
            PreparedClient {
                addresses,
                secret_file,
                networks: allowed,
            },
        );
    }
    Ok(Prepared {
        listeners,
        limits,
        verifications,
        clients,
        networks,
        certificate_files,
        private_key_file,
        hash,
    })
}

pub fn load() -> io::Result<Config> {
    let Prepared {
        listeners,
        limits,
        verifications,
        clients: prepared_clients,
        networks,
        certificate_files,
        private_key_file,
        mut hash,
    } = read_registry()?;
    let mut certificates = Vec::new();
    for path in certificate_files {
        let bytes = material(&path, false, 65536)?;
        stamp(&mut hash, &bytes);
        certificates.push(rustls::pki_types::CertificateDer::from(bytes.to_vec()));
    }
    let key = material(&private_key_file, true, 65536)?;
    stamp(&mut hash, &key);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key.to_vec())
        .map_err(|_| invalid("private key is not DER"))?;
    let tls = radius_core::server_config(certificates, key)
        .map_err(|_| invalid("invalid certificate/key pair"))?;
    let mut clients = BTreeMap::new();
    for (name, client) in prepared_clients {
        let secret = material(&client.secret_file, true, 1024)?;
        stamp(&mut hash, name.as_bytes());
        stamp(&mut hash, &secret);
        clients.insert(
            name.clone(),
            Client {
                name,
                addresses: client.addresses,
                secret,
                networks: client.networks,
            },
        );
    }
    let config = Config {
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

pub enum Update {
    Pending,
    Valid(Arc<Config>),
    Invalid,
}
/// Own all blocking Registry/file I/O on a bounded configuration worker. The
/// packet loop never waits for Registry or filesystem progress. Channel capacity
/// bounds queued snapshots; credential copies are released when superseded.
pub fn watch() -> Receiver<Update> {
    let (tx, rx) = mpsc::sync_channel(2);
    thread::spawn(move || worker(tx));
    rx
}
fn worker(tx: SyncSender<Update>) {
    let mut watch: Option<Key> = None;
    let mut fingerprint = None;
    let mut last_check = Instant::now() - Duration::from_secs(3);
    let mut buffer = [0u8; 8192];
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
        let change = watch.as_ref().map(|key| key.read_watch_events(&mut buffer));
        let changed = match change {
            Some(Ok(events)) => !events.is_empty(),
            Some(Err(_)) => {
                watch = None;
                true
            }
            None => true,
        };
        // Periodic validation also observes removal/protection changes of
        // referenced files. This is best effort, not a transactional snapshot.
        if changed || last_check.elapsed() >= Duration::from_secs(1) {
            if changed && tx.send(Update::Pending).is_err() {
                return;
            }
            let next = load();
            if watch.is_none() || next.is_err() {
                // Reopen the watch after an unreadable/deleted root. A watch
                // on an old key must not be treated as watching its replacement.
                watch = None;
                fingerprint = None;
                if tx.send(Update::Invalid).is_err() {
                    return;
                }
            } else if let Ok(config) = next {
                if changed || fingerprint != Some(config.fingerprint) {
                    if !changed && tx.send(Update::Pending).is_err() {
                        return;
                    }
                    fingerprint = Some(config.fingerprint);
                    if tx.send(Update::Valid(Arc::new(config))).is_err() {
                        return;
                    }
                }
            }
            last_check = Instant::now();
        }
        thread::sleep(Duration::from_millis(50));
    }
}
