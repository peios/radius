//! Accounting authority, independent of EAP configuration and TLS material.
use crate::{accounting::*, model::Value, runtime::SERVICE_SID};
use peios::{
    access::AccessCheck,
    security::{AccessMask, GenericMapping},
    token::Token,
};
use radius_accounting::{
    model::{Observation, Session},
    store::Annotation,
    wire,
    worker::{self, Handle, View},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{SocketAddr, UdpSocket},
    os::{
        fd::AsFd,
        unix::{
            fs::FileTypeExt,
            net::{UnixListener, UnixStream},
        },
    },
    sync::{Arc, RwLock, mpsc},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

pub const DIRECTORY: &str = "/var/state/radius/accounting";
/// Explicit administrative provisioning, preserving an existing namespace SD.
pub fn provision_metrics() -> io::Result<()> {
    use peios::registry::{Data, Key, KeyAccess, OpenFlags, Transaction};
    let tx = Transaction::begin().map_err(err)?;
    let key = Key::open_transacted(
        None,
        "Machine\\System\\eventd\\Security\\Metrics",
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        OpenFlags::empty(),
        Some(&tx),
    )
    .map_err(err)?;
    match key.query_value(b"radiusd.accounting", Some(&tx)) {
        Ok(_) => return Ok(()),
        Err(e) => {
            let error: io::Error = e.into();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
    }
    let sd = peios::security::sddl::parse(&format!(
        "O:SYG:SYD:P(A;;0x9;;;SY)(A;;0x9;;;BA)(A;;0x8;;;{SERVICE_SID})"
    ))
    .map_err(err)?;
    let data = Data::Binary(sd.as_bytes().to_vec());
    key.set_value(b"radiusd.accounting", data.ty(), &data.encode())
        .in_txn(&tx)
        .call()
        .map_err(err)?;
    tx.commit().map_err(err)
}
#[derive(Clone)]
pub struct Snapshot {
    pub config: Configuration,
    pub ledger_ready: bool,
    pub activation_error: Option<String>,
    pub secrets: BTreeMap<String, Arc<Zeroizing<Vec<u8>>>>,
}
#[derive(Clone)]
pub struct Service {
    pub ledger: Handle,
    state: Arc<RwLock<Option<Arc<Snapshot>>>>,
    error: Arc<RwLock<Option<String>>>,
    queue_count: usize,
    authority: Arc<RwLock<Option<super::dynamic::Authority>>>,
    hint: Arc<AtomicU64>,
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
#[derive(Debug)]
struct ControlFailure {
    code: &'static str,
    message: &'static str,
}
impl std::fmt::Display for ControlFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for ControlFailure {}
fn control_failure(code: &'static str, message: &'static str) -> io::Error {
    io::Error::other(ControlFailure { code, message })
}
pub fn verify_directory() -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(DIRECTORY)?;
    verify_private(&directory)?;
    for name in [
        "ledger.db",
        "ledger.db-wal",
        "ledger.db-shm",
        "ledger.db.owner",
    ] {
        let path = std::path::Path::new(DIRECTORY).join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && meta.nlink() == 1 => {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?;
                if file.metadata()?.nlink() != 1 {
                    return Err(err("unsafe accounting file links"));
                }
                verify_private(&file)?;
            }
            Ok(_) => return Err(err("unsafe accounting file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn verify_private(file: &std::fs::File) -> io::Result<()> {
    use peios::{
        file::SecInfo,
        security::{AceType, Sid},
    };
    let sd = peios::file::fd_get_sd(file.as_fd(), SecInfo::OWNER | SecInfo::DACL).map_err(err)?;
    let v = sd.view().map_err(err)?;
    let trusted = [
        "S-1-5-18".parse::<Sid>().map_err(err)?,
        "S-1-5-32-544".parse().map_err(err)?,
        SERVICE_SID.parse().map_err(err)?,
    ];
    if !trusted.iter().any(|s| v.owner() == Some(s.as_ref())) {
        return Err(err("untrusted accounting directory owner"));
    }
    let acl = v
        .dacl()
        .ok_or_else(|| err("accounting directory needs a DACL"))?;
    for ace in acl.iter() {
        if ace.ace_type() == AceType::AccessDenied {
            continue;
        }
        if ace.ace_type() != AceType::AccessAllowed
            || !trusted.iter().any(|s| ace.sid() == Some(s.as_ref()))
        {
            return Err(err("accounting directory is not private"));
        }
    }
    Ok(())
}
/// Explicit administrative provisioning; never relax an existing directory.
pub fn provision_directory() -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    super::credentials::provision_directory()?;
    match std::fs::symlink_metadata(DIRECTORY) {
        Ok(_) => return verify_directory(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::DirBuilder::new().mode(0o700).create(DIRECTORY)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(DIRECTORY)?;
    let sd=peios::security::sddl::parse(&format!("O:{SERVICE_SID}G:{SERVICE_SID}D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;{SERVICE_SID})")).map_err(err)?;
    peios::file::fd_set_sd(file.as_fd(), peios::file::SecInfo::DACL, &sd).map_err(err)?;
    verify_directory()
}
impl Service {
    #[cfg(test)]
    pub(super) fn fixture(snapshot: Snapshot, ledger: Handle) -> Self {
        Self {
            queue_count: snapshot.config.settings.queue_count,
            ledger,
            state: Arc::new(RwLock::new(Some(Arc::new(snapshot)))),
            error: Arc::new(RwLock::new(None)),
            authority: Arc::new(RwLock::new(None)),
            hint: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn start() -> io::Result<Self> {
        let initial = super::registry::read()
            .ok()
            .and_then(|s| prepare(&s).ok())
            .map(|s| s.settings)
            .unwrap_or_default();
        let service = Self {
            queue_count: initial.queue_count,
            authority: Arc::new(RwLock::new(None)),
            hint: Arc::new(AtomicU64::new(0)),
            ledger: Handle::start_verified(
                std::path::Path::new(DIRECTORY).join("ledger.db"),
                initial,
                Arc::new(|| verify_directory().map_err(Into::into)),
            )
            .map_err(err)?,
            state: Arc::new(RwLock::new(None)),
            error: Arc::new(RwLock::new(None)),
        };
        serve(service.clone())?;
        super::dynamic::start(service.clone())?;
        let (tx, updates) = mpsc::sync_channel(1);
        let watcher = service.clone();
        thread::Builder::new()
            .name("radius-accounting-config".into())
            .spawn(move || {
                loop {
                    if tx.send(watcher.load()).is_err() {
                        return;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            })?;
        let worker = service.clone();
        thread::Builder::new()
            .name("radius-accounting-udp".into())
            .spawn(move || worker.run(updates))?;
        Ok(service)
    }
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.state.read().ok()?.clone()
    }
    pub fn publish_authority(&self, authority: Option<super::dynamic::Authority>) {
        if let Ok(mut active) = self.authority.write() {
            *active = authority;
        }
    }
    pub fn authority(&self) -> Option<super::dynamic::Authority> {
        self.authority.read().ok()?.clone()
    }
    pub(super) fn hint(&self) -> u64 {
        self.hint.load(Ordering::Relaxed)
    }
    pub(super) fn changed(&self) {
        self.hint.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn transmit(
        &self,
        command: &radius_accounting::store::Command,
        socket: &UdpSocket,
        peer: SocketAddr,
    ) -> io::Result<usize> {
        // Keep activation and secret replacement fenced through this one
        // nonblocking send; a checked clone alone could become stale.
        let authority = self
            .authority
            .read()
            .map_err(|_| err("authority lock unavailable"))?;
        let state = self
            .state
            .read()
            .map_err(|_| err("configuration lock unavailable"))?;
        let snapshot = state
            .as_ref()
            .ok_or_else(|| err("configuration unavailable"))?;
        if authority
            .as_ref()
            .is_none_or(|a| a.revision != command.configuration)
            || snapshot.config.fingerprint != command.configuration
        {
            return Err(err("configuration superseded"));
        }
        let target = command
            .target
            .as_ref()
            .ok_or_else(|| err("target missing"))?;
        if target.source != peer.ip() || command.port != peer.port() {
            return Err(err("target changed"));
        }
        let client = snapshot
            .config
            .peers
            .values()
            .flat_map(|client| {
                client
                    .addresses
                    .iter()
                    .filter(|p| p.contains(target.source))
                    .map(move |p| (p.bits, client))
            })
            .max_by_key(|(bits, _)| *bits)
            .map(|(_, client)| client)
            .filter(|client| client.enabled && client.disconnect_port == peer.port())
            .ok_or_else(|| err("client changed"))?;
        let same_secret = snapshot.secrets.get(&client.id).is_some_and(|s| {
            ring::digest::digest(&ring::digest::SHA256, s.as_slice()).as_ref()
                == command.secret_fingerprint
        });
        if !same_secret {
            return Err(err("client secret changed"));
        }
        socket.send_to(&command.packet, peer)
    }
    fn load(&self) -> io::Result<Snapshot> {
        let config = prepare(&super::registry::read()?).map_err(err)?;
        super::configuration::descriptor(&config.security)?;
        for p in config.policies.values() {
            super::configuration::descriptor(&p.accounting_security)?;
        }
        let mut secrets = BTreeMap::new();
        for peer in config.peers.values().filter(|p| p.enabled) {
            let secret = super::credentials::material(&peer.secret_file, true, 1024)?;
            if secret.len() < 16 {
                return Err(err("accounting secret is too short"));
            }
            secrets.insert(peer.id.clone(), Arc::new(secret));
        }
        Ok(Snapshot {
            config,
            secrets,
            ledger_ready: false,
            activation_error: None,
        })
    }
    fn run(&self, updates: mpsc::Receiver<io::Result<Snapshot>>) {
        struct Pending {
            socket: Arc<UdpSocket>,
            peer: SocketAddr,
            bytes: Vec<u8>,
            result: worker::Completion<radius_accounting::model::Receipt>,
        }
        let mut sockets: Vec<Arc<UdpSocket>> = Vec::new();
        let mut pending: Vec<Pending> = Vec::new();
        let mut fingerprint = Vec::new();
        let mut configuring: Option<worker::Completion<()>> = None;
        let mut bytes = [0u8; 65536];
        let mut disconnects = super::dynamic_commands::Commands::new();
        loop {
            if let Ok(loaded) = updates.try_recv() {
                let loaded = loaded.and_then(|mut next| {
                    if next.config.settings.queue_count != self.queue_count {
                        return Err(err("AccountingQueueCount changes require a daemon restart"));
                    }
                    let previous = self.snapshot();
                    let previous_ready = previous.as_ref().is_some_and(|s| s.ledger_ready);
                    let mut stamp = next.config.fingerprint.as_bytes().to_vec();
                    for secret in next.secrets.values() {
                        stamp.extend_from_slice(
                            ring::digest::digest(&ring::digest::SHA256, secret.as_slice()).as_ref(),
                        );
                    }
                    if stamp != fingerprint || (!previous_ready && configuring.is_none()) {
                        let mut new_sockets = Vec::new();
                        if next.config.settings.enabled {
                            for address in &next.config.listeners {
                                if let Some(socket) = sockets
                                    .iter()
                                    .find(|s| s.local_addr().ok() == Some(*address))
                                {
                                    new_sockets.push(socket.clone());
                                    continue;
                                }
                                let bound = (|| -> io::Result<UdpSocket> {
                                    let socket = socket2::Socket::new(
                                        if address.is_ipv4() {
                                            socket2::Domain::IPV4
                                        } else {
                                            socket2::Domain::IPV6
                                        },
                                        socket2::Type::DGRAM,
                                        Some(socket2::Protocol::UDP),
                                    )?;
                                    if address.is_ipv6() {
                                        socket.set_only_v6(true)?;
                                    }
                                    socket.set_nonblocking(true)?;
                                    socket.bind(&(*address).into())?;
                                    Ok(socket.into())
                                })();
                                match bound {
                                    Ok(socket) => new_sockets.push(Arc::new(socket)),
                                    Err(e) => {
                                        next.activation_error =
                                            Some(format!("accounting listener unavailable: {e}"));
                                        new_sockets.clear();
                                        break;
                                    }
                                }
                            }
                        }
                        // Keep valid outage policy available even when the
                        // ledger cannot open. Unchecked quotas never grant.
                        let configured = self
                            .ledger
                            .configure(next.config.settings.clone(), next.config.budgets.clone());
                        match configured {
                            Ok(rx) => configuring = Some(rx),
                            Err(e) => {
                                configuring = None;
                                next.activation_error.get_or_insert_with(|| e.to_string());
                            }
                        }
                        next.ledger_ready = !next.config.settings.enabled;
                        sockets = new_sockets;
                        fingerprint = stamp;
                    } else {
                        next.ledger_ready = previous_ready;
                        next.activation_error = previous.and_then(|s| s.activation_error.clone());
                    }
                    Ok(Arc::new(next))
                });
                match loaded {
                    Ok(snapshot) => {
                        let activation_error = snapshot.activation_error.clone();
                        if let Ok(mut state) = self.state.write() {
                            *state = Some(snapshot);
                        }
                        if let Ok(mut e) = self.error.write() {
                            *e = activation_error;
                        }
                    }
                    Err(e) => {
                        configuring = None;
                        fingerprint.clear();
                        sockets.clear();
                        if let Ok(mut state) = self.state.write() {
                            *state = None;
                        }
                        if let Ok(mut error) = self.error.write() {
                            *error = Some(e.to_string());
                        }
                    }
                }
            }
            if let Some(result) = configuring.as_ref().and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                    radius_accounting::Error::Configuration("accounting owner stopped".into()),
                )),
                Err(mpsc::TryRecvError::Empty) => None,
            }) {
                configuring = None;
                if let Some(previous) = self.snapshot() {
                    let mut next = (*previous).clone();
                    if let Err(e) = result {
                        next.activation_error.get_or_insert_with(|| e.to_string());
                    }
                    next.ledger_ready =
                        !next.config.settings.enabled || next.activation_error.is_none();
                    if let Ok(mut error) = self.error.write() {
                        *error = next.activation_error.clone();
                    }
                    if let Ok(mut state) = self.state.write() {
                        *state = Some(Arc::new(next));
                    }
                }
            }
            let mut index = 0;
            while index < pending.len() {
                match pending[index].result.try_recv() {
                    Ok(Ok(_)) => {
                        let done = pending.swap_remove(index);
                        let _ = done.socket.send_to(&done.bytes, done.peer);
                    }
                    Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                        pending.swap_remove(index);
                    }
                    Err(mpsc::TryRecvError::Empty) => index += 1,
                }
            }
            if let Some(snapshot) = self.snapshot() {
                if snapshot.ledger_ready {
                    disconnects.tick(self, &snapshot, &sockets);
                }
                for socket in &sockets {
                    for _ in 0..32 {
                        let (length, source) = match socket.recv_from(&mut bytes) {
                            Ok(v) => v,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        };
                        if disconnects.response(
                            socket,
                            source,
                            &bytes[..length],
                            self,
                            snapshot.config.dynamic.settings.require_response_ma,
                        ) {
                            continue;
                        }
                        if !snapshot.ledger_ready {
                            continue;
                        }
                        if pending.len() >= snapshot.config.settings.queue_count {
                            continue;
                        }
                        let selected = snapshot
                            .config
                            .peers
                            .values()
                            .flat_map(|p| {
                                p.addresses
                                    .iter()
                                    .filter(move |a| a.contains(source.ip()))
                                    .map(move |a| (a.bits, p))
                            })
                            .max_by_key(|(bits, _)| *bits)
                            .map(|(_, p)| p);
                        let Some(peer) = selected.filter(|p| p.enabled) else {
                            continue;
                        };
                        let Some(secret) = snapshot.secrets.get(&peer.id) else {
                            continue;
                        };
                        let parsed = (|| -> radius_accounting::Result<_> {
                            let request = wire::Request::parse(
                                &bytes[..length],
                                secret.as_slice(),
                                snapshot.config.settings.require_ma,
                            )?;
                            let mut observation = Observation::with_profile(
                                &request,
                                peer.id.clone(),
                                source.ip(),
                                worker::now_ms(),
                                peer.profile
                                    .as_ref()
                                    .and_then(|p| snapshot.config.profiles.get(p)),
                            )?;
                            let candidates: Vec<_> = peer
                                .policies
                                .iter()
                                .filter(|id| {
                                    snapshot.config.policies.get(*id).is_some_and(|policy| {
                                        policy.enabled
                                            && match (&policy.ssid, &observation.called_station) {
                                                (Some(ssid), Some(called)) => {
                                                    crate::runtime::called_ssid(called)
                                                        .is_some_and(|v| v == ssid.as_slice())
                                                }
                                                (None, _) => true,
                                                _ => false,
                                            }
                                    })
                                })
                                .collect();
                            if candidates.len() == 1 {
                                observation.policy = Some(candidates[0].clone());
                            }
                            let reply = request.response(secret.as_slice())?;
                            let raw = snapshot
                                .config
                                .settings
                                .raw_capture
                                .then(|| request.canonical.clone());
                            let result = self.ledger.record(observation, raw)?;
                            Ok((reply, result))
                        })();
                        if let Ok((reply, result)) = parsed {
                            pending.push(Pending {
                                socket: socket.clone(),
                                peer: source,
                                bytes: reply,
                                result,
                            });
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn permitted(token: &Token, sd: &Value, right: u32) -> bool {
    super::configuration::descriptor(sd).ok().is_some_and(|sd| {
        AccessCheck::new(
            &sd,
            AccessMask::from_bits_retain(right),
            GenericMapping::new(
                READ | PERSONAL | USAGE,
                DISCONNECT | CORRECT | REAUTHENTICATE | UPDATE_AUTHORIZATION,
                READ,
                ALL,
            ),
        )
        .token(token.as_fd())
        .check()
        .is_ok_and(|r| r.allowed)
    })
}
fn view(token: &Token, s: &Snapshot, right: u32) -> View {
    View {
        all: permitted(token, &s.config.security, right),
        policies: s
            .config
            .policies
            .iter()
            .filter(|(_, p)| permitted(token, &p.accounting_security, right))
            .map(|(id, _)| id.clone())
            .collect(),
        own_sid: if s.config.self_service
            && right & (DISCONNECT | CORRECT | RAW | REAUTHENTICATE | UPDATE_AUTHORIZATION) == 0
        {
            token.user().ok().map(|s| s.to_string())
        } else {
            None
        },
    }
}
fn allowed(token: &Token, s: &Snapshot, row: &Session, right: u32) -> bool {
    view(token, s, right).allows(row)
}
fn redact(row: &mut Session, personal: bool, usage: bool) {
    if !personal {
        row.sid = None;
        row.proof = None;
        row.groups.clear();
        row.name = None;
        row.username = None;
        row.station = None;
        row.classes.clear();
        row.nas_attributes.clear();
        row.nas.clear();
        row.session.clear();
        row.tunnel = None;
        row.multi_session = None;
        row.subsystem = None;
        row.source = "0.0.0.0".parse().unwrap();
    }
    if !usage {
        row.input = None;
        row.output = None;
        row.link_count = None;
    }
}
fn controls(token: &Token, snapshot: &Snapshot, row: &Session) -> serde_json::Value {
    use radius_accounting::dynamic::{Action, Target};
    let profile = snapshot.config.dynamic.profile(&row.client);
    let ready = Target::from_session(row).is_ok();
    let can = |action| {
        let fallback = row
            .policy
            .as_ref()
            .and_then(|p| snapshot.config.dynamic.policies.get(p))
            .map(|p| super::dynamic::fallback_after(action, &p.fallback))
            .unwrap_or_default();
        ready
            && allowed(token, snapshot, row, READ | crate::dynamic::right(action))
            && fallback
                .iter()
                .all(|a| allowed(token, snapshot, row, READ | crate::dynamic::right(*a)))
            && std::iter::once(action)
                .chain(fallback)
                .any(|a| profile.recipes.iter().any(|r| r.action == a))
    };
    serde_json::json!({"disconnect":can(Action::Disconnect),"reauthenticate":can(Action::Reauthenticate),"update-authorization":can(Action::UpdateAuthorization),"profile":profile.name})
}
fn command_view(
    mut command: radius_accounting::store::Command,
    personal: bool,
) -> io::Result<serde_json::Value> {
    command.packet.clear();
    command.secret_fingerprint.clear();
    if !personal {
        command.target = None;
        command.proof.clear();
    }
    let mut value = serde_json::to_value(command).map_err(err)?;
    if let Some(value) = value.as_object_mut() {
        value.remove("packet");
        value.remove("secret_fingerprint");
    }
    Ok(value)
}
fn answer(service: &Service, token: &Token, request: Request) -> io::Result<serde_json::Value> {
    if matches!(request, Request::Status) {
        let security = super::registry::read()
            .ok()
            .and_then(|s| s.settings.get("AccountingSecurity").cloned())
            .unwrap_or_else(|| Value::Text(DEFAULT_SECURITY.into()));
        if !permitted(token, &security, READ) {
            return Err(err("accounting status denied"));
        }
        let snapshot = service.snapshot();
        return Ok(
            serde_json::json!({"version":1,"enabled":snapshot.as_ref().is_some_and(|s|s.config.settings.enabled),"ledger":service.ledger.snapshot(),"configuration_error":service.error.read().ok().and_then(|e|e.clone()),"session_controls":snapshot.as_ref().map(|s|&s.config.dynamic.settings),"controls_active":snapshot.as_ref().is_some_and(|s|service.authority().is_some_and(|a|a.revision==s.config.fingerprint))}),
        );
    }
    let s = service
        .snapshot()
        .ok_or_else(|| err("accounting configuration unavailable"))?;
    let read = view(token, &s, READ);
    let actor = token.user().map_err(err)?.to_string();
    let row = |id: &str, right: u32| -> io::Result<Session> {
        let session = worker::wait(
            service
                .ledger
                .session(id.into(), read.clone())
                .map_err(err)?,
        )
        .map_err(err)?
        .ok_or_else(|| err("session unavailable"))?;
        if !allowed(token, &s, &session, READ | right) {
            return Err(err("session unavailable"));
        }
        Ok(session)
    };
    Ok(match request {
        Request::Status => {
            if !permitted(token, &s.config.security, READ) {
                return Err(err("accounting status denied"));
            }
            serde_json::json!({"version":1,"enabled":s.config.settings.enabled,"ledger":service.ledger.snapshot(),"configuration_error":service.error.read().ok().and_then(|e|e.clone()),"session_controls":s.config.dynamic.settings,"controls_active":service.authority().is_some_and(|a|a.revision==s.config.fingerprint)})
        }
        Request::Sessions { filter } => {
            if filter.principal.as_ref().is_some_and(|principal| {
                !(permitted(token, &s.config.security, READ | PERSONAL)
                    || filter
                        .policy
                        .as_ref()
                        .and_then(|id| s.config.policies.get(id))
                        .is_some_and(|p| permitted(token, &p.accounting_security, READ | PERSONAL))
                    || (s.config.self_service && principal == &actor))
            }) {
                return Err(err("principal filter denied"));
            }
            let mut page =
                worker::wait(service.ledger.page(filter, read).map_err(err)?).map_err(err)?;
            let capabilities: Vec<_> = page
                .sessions
                .iter()
                .map(|row| controls(token, &s, row))
                .collect();
            for row in &mut page.sessions {
                let personal = allowed(token, &s, row, READ | PERSONAL);
                let usage = allowed(token, &s, row, READ | USAGE);
                redact(row, personal, usage);
            }
            let mut page = serde_json::to_value(page).map_err(err)?;
            if let Some(rows) = page["sessions"].as_array_mut() {
                for (row, capability) in rows.iter_mut().zip(capabilities) {
                    row["controls"] = capability;
                }
            }
            page
        }
        Request::Session { id } => {
            let mut r = row(&id, 0)?;
            let capability = controls(token, &s, &r);
            let issued = r.proof.as_ref().map(|p| p.issued.clone());
            let personal = allowed(token, &s, &r, READ | PERSONAL);
            let usage = allowed(token, &s, &r, READ | USAGE);
            redact(&mut r, personal, usage);
            let mut value = serde_json::to_value(r).map_err(err)?;
            value["controls"] = capability;
            value["issued"] = serde_json::to_value(issued).map_err(err)?;
            value
        }
        Request::History { id, limit } => {
            let r = row(&id, PERSONAL | USAGE)?;
            let raw = allowed(token, &s, &r, READ | PERSONAL | USAGE | RAW);
            let mut history = worker::wait(service.ledger.history(r.id, limit, read).map_err(err)?)
                .map_err(err)?;
            if !raw {
                for observation in &mut history {
                    observation.attributes.clear();
                }
            }
            serde_json::to_value(history).map_err(err)?
        }
        Request::Usage { principal, policy } => {
            principal.parse::<peios::security::Sid>().map_err(err)?;
            let global = permitted(token, &s.config.security, READ | PERSONAL | USAGE);
            let delegated =
                s.config.policies.get(&policy).is_some_and(|p| {
                    permitted(token, &p.accounting_security, READ | PERSONAL | USAGE)
                });
            if !(global || delegated || (s.config.self_service && principal == actor)) {
                return Err(err("usage query denied"));
            }
            let mut balances = worker::wait(
                service
                    .ledger
                    .balances(usage_subject(&principal, &policy))
                    .map_err(err)?,
            )
            .map_err(err)?;
            if !global && delegated {
                balances.retain(|b| b.budget.policy.as_ref() == Some(&policy));
            }
            serde_json::to_value(balances).map_err(err)?
        }
        Request::Disconnect { id } => {
            let session = row(&id, DISCONNECT)?;
            command_view(
                worker::wait(
                    service
                        .ledger
                        .disconnect(id, actor, "administrator".into())
                        .map_err(err)?,
                )
                .map_err(err)?,
                allowed(token, &s, &session, READ | PERSONAL),
            )?
        }
        Request::Commands { id } => {
            row(&id, PERSONAL)?;
            serde_json::Value::Array(
                worker::wait(service.ledger.command_history(id).map_err(err)?)
                    .map_err(err)?
                    .into_iter()
                    .map(|c| command_view(c, true))
                    .collect::<io::Result<Vec<_>>>()?,
            )
        }
        Request::Reconciliation { id } => {
            row(&id, PERSONAL)?;
            serde_json::to_value(
                worker::wait(service.ledger.reconciliation(id).map_err(err)?).map_err(err)?,
            )
            .map_err(err)?
        }
        Request::Control {
            id,
            action,
            request_id,
        } => {
            use crate::{dynamic::Evaluation, native::dynamic::fallback_after};
            use radius_accounting::dynamic::{Action, Intent};
            let session = row(&id, crate::dynamic::right(action))?;
            if let Some(command) = worker::wait(
                service
                    .ledger
                    .command_request(actor.clone(), request_id.clone())
                    .map_err(err)?,
            )
            .map_err(err)?
            {
                if command.session != id || command.requested_action != action {
                    return Err(control_failure(
                        "request-conflict",
                        "The request ID already names a different operation.",
                    ));
                }
                return command_view(command, allowed(token, &s, &session, READ | PERSONAL));
            }
            radius_accounting::dynamic::Target::from_session(&session).map_err(|_| {
                control_failure(
                    "unmanageable",
                    "Precise NAS and session selectors are required.",
                )
            })?;
            let policy = session
                .policy
                .as_ref()
                .and_then(|p| s.config.dynamic.policies.get(p))
                .ok_or_else(|| {
                    control_failure(
                        "configuration-unavailable",
                        "Session policy is unavailable.",
                    )
                })?;
            let fallback = fallback_after(action, &policy.fallback);
            for next in &fallback {
                if !allowed(token, &s, &session, READ | crate::dynamic::right(*next)) {
                    return Err(control_failure(
                        "permission-denied",
                        "Permission for a configured fallback action is required.",
                    ));
                }
            }
            let authority = service
                .authority()
                .filter(|a| a.revision == s.config.fingerprint)
                .ok_or_else(|| {
                    control_failure(
                        "configuration-unavailable",
                        "Active authentication configuration is unavailable.",
                    )
                })?;
            let desired = match (authority.evaluate)(std::slice::from_ref(&session))
                .into_iter()
                .next()
            {
                Some(Evaluation::Granted { desired, .. }) => Some(desired),
                Some(Evaluation::Denied | Evaluation::Disabled | Evaluation::Deleted)
                    if action == Action::Disconnect =>
                {
                    None
                }
                Some(Evaluation::Unavailable(_)) if action == Action::Disconnect => None,
                Some(Evaluation::Unavailable(_)) if action == Action::Reauthenticate => {
                    Some(radius_accounting::dynamic::Authorization {
                        vlan: None,
                        timeout_seconds: 1,
                    })
                }
                Some(Evaluation::Unavailable(_)) | None => {
                    return Err(control_failure(
                        "authority-unavailable",
                        "Fresh identity evaluation is unavailable; no authorization update was issued.",
                    ));
                }
                _ => {
                    return Err(control_failure(
                        "access-denied",
                        "Current policy does not permit an authorization update.",
                    ));
                }
            };
            if service
                .authority()
                .is_none_or(|a| a.revision != authority.revision)
            {
                return Err(control_failure(
                    "superseded",
                    "Configuration changed; inspect the current state before retrying.",
                ));
            }
            command_view(
                worker::wait(
                    service
                        .ledger
                        .dynamic(Intent {
                            intent_key: String::new(),
                            request_id: Some(request_id),
                            session: id,
                            actor,
                            reason: "administrator".into(),
                            action,
                            configuration: authority.revision,
                            desired,
                            fallback,
                        })
                        .map_err(err)?,
                )
                .map_err(err)?,
                allowed(token, &s, &session, READ | PERSONAL),
            )?
        }
        Request::Annotate { id, note } => {
            row(&id, CORRECT)?;
            worker::wait(
                service
                    .ledger
                    .annotate(Annotation {
                        session: id,
                        actor,
                        at_ms: worker::now_ms(),
                        note,
                    })
                    .map_err(err)?,
            )
            .map_err(err)?;
            serde_json::json!({"recorded":true})
        }
        Request::Rebuild => {
            if !permitted(token, &s.config.security, READ | CORRECT) {
                return Err(err("rebuild denied"));
            }
            worker::wait(service.ledger.rebuild(actor).map_err(err)?).map_err(err)?;
            serde_json::json!({"rebuilt":true})
        }
        Request::CorrectEnd { id, end_ms, note } => {
            row(&id, CORRECT)?;
            worker::wait(
                service
                    .ledger
                    .correct(radius_accounting::store::Correction {
                        session: id,
                        actor,
                        at_ms: worker::now_ms(),
                        end_ms,
                        note,
                    })
                    .map_err(err)?,
            )
            .map_err(err)?;
            serde_json::json!({"corrected":true})
        }
        Request::Related { id } => {
            if !s.config.settings.linked_views {
                return Err(err("linked views are disabled"));
            }
            let r = row(&id, PERSONAL)?;
            let principal = r.sid.ok_or_else(|| err("unverified session identity"))?;
            let filter = Filter {
                principal: Some(principal),
                limit: 100,
                ..Default::default()
            };
            let mut page = worker::wait(
                service
                    .ledger
                    .page(filter, view(token, &s, READ | PERSONAL))
                    .map_err(err)?,
            )
            .map_err(err)?;
            for r in &mut page.sessions {
                let usage = allowed(token, &s, r, READ | USAGE);
                redact(r, true, usage);
            }
            serde_json::to_value(page).map_err(err)?
        }
    })
}
fn receive(stream: &mut UnixStream, max: usize) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > max {
        return Err(err("accounting message too large"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn send(stream: &mut UnixStream, bytes: &[u8], max: usize) -> io::Result<()> {
    if bytes.len() > max {
        return Err(err("accounting message too large"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}
fn serve(service: Service) -> io::Result<()> {
    let path = std::path::Path::new(SOCKET);
    super::control::protect(path.parent().unwrap(), true)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(err("accounting endpoint is not a socket")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    super::control::protect(path, false)?;
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let result = (|| {
                let token = Token::open_peer(stream.as_fd()).map_err(err)?;
                let bytes = receive(&mut stream, MAX_REQUEST)?;
                answer(
                    &service,
                    &token,
                    serde_json::from_slice(&bytes).map_err(err)?,
                )
            })();
            let envelope = match result {
                Ok(value) => serde_json::json!({"ok":value}),
                Err(error) => match error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<ControlFailure>())
                {
                    Some(error) => serde_json::json!({"error":error.message,"code":error.code}),
                    None => serde_json::json!({"error":"accounting request unavailable or denied"}),
                },
            };
            if let Ok(bytes) = serde_json::to_vec(&envelope) {
                let _ = send(&mut stream, &bytes, MAX_RESPONSE);
            }
        }
    });
    Ok(())
}
pub fn query(mut request: Request) -> io::Result<serde_json::Value> {
    if let Request::Control { request_id, .. } = &mut request {
        if request_id.is_empty() {
            *request_id = crate::model::new_id().map_err(err)?;
        }
    }
    let mut stream = UnixStream::connect(SOCKET)?;
    stream.set_read_timeout(Some(Duration::from_secs(6)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let token = Token::open_peer(stream.as_fd()).map_err(err)?;
    if token.user().map_err(err)? != SERVICE_SID.parse::<peios::security::Sid>().map_err(err)? {
        return Err(err("accounting endpoint is not radiusd"));
    }
    send(
        &mut stream,
        &serde_json::to_vec(&request).map_err(err)?,
        MAX_REQUEST,
    )?;
    let reply: serde_json::Value =
        serde_json::from_slice(&receive(&mut stream, MAX_RESPONSE)?).map_err(err)?;
    reply.get("ok").cloned().ok_or_else(|| {
        err(reply
            .get("error")
            .and_then(|v| v.as_str())
            .map(|s| s.chars().take(512).collect::<String>())
            .unwrap_or_else(|| "accounting request unavailable or denied".into()))
    })
}
