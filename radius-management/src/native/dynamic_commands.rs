//! Bounded durable RFC 5176 commands; ACK never establishes DHCP or fresh proof.
use super::{
    accounting::{Service, Snapshot},
    dynamic::Authority,
};
use crate::dynamic::Evaluation;
use radius_accounting::{
    dynamic::{self, Action, Target},
    model::{Session, State},
    store::{Command, CommandStep},
    wire::{self, Attribute},
    worker::{self, Completion, View},
};
use std::sync::mpsc;
use std::{
    collections::BTreeMap,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

struct Flight {
    command: Command,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    secret: Arc<Zeroizing<Vec<u8>>>,
    sent: Instant,
    committed: Option<Completion<()>>,
    checking: Option<Completion<Option<Session>>>,
    revalidate: bool,
}
enum Disposition {
    Ready,
    Defer,
    Cancel,
}
type Validated = Vec<(Command, Session, Disposition)>;
pub(super) struct Commands {
    flights: BTreeMap<u8, Flight>,
    query: Option<Completion<Vec<(Command, Session)>>>,
    validation: Option<Completion<Validated>>,
    last: Instant,
    next: u8,
}
impl Commands {
    pub fn new() -> Self {
        Self {
            flights: BTreeMap::new(),
            query: None,
            validation: None,
            last: Instant::now() - Duration::from_secs(2),
            next: 0,
        }
    }
    pub fn response(
        &mut self,
        socket: &UdpSocket,
        source: SocketAddr,
        packet: &[u8],
        service: &Service,
        require_ma: bool,
    ) -> bool {
        if packet.len() < 20 || !matches!(packet[0], 41 | 42 | 44 | 45) {
            return false;
        }
        let Some(f) = self.flights.get_mut(&packet[1]) else {
            return true;
        };
        if f.peer != source
            || f.socket.local_addr().ok() != socket.local_addr().ok()
            || f.command.state != "sent"
        {
            return true;
        }
        if let Ok((ack, cause)) =
            wire::dynamic_result(packet, &f.command.packet, f.secret.as_slice(), require_ma)
        {
            f.command.state = if ack { "acknowledged" } else { "rejected" }.into();
            f.command.error_cause = cause;
            if !ack && dynamic::explicitly_unsupported(cause) && !f.command.fallback.is_empty() {
                f.command.history.push(CommandStep {
                    action: f.command.action,
                    state: "rejected".into(),
                    attempts: f.command.attempts,
                    at_ms: worker::now_ms(),
                    first_sent_ms: f.command.first_sent_ms,
                    error_cause: cause,
                });
                f.command.action = f.command.fallback.remove(0);
                f.command.state = "pending".into();
                f.command.attempts = 0;
                f.command.first_sent_ms = None;
                f.command.error_cause = None;
                f.command.packet.clear();
            }
            f.checking = None;
            f.committed = service.ledger.command_result(f.command.clone()).ok();
        }
        true
    }
    pub fn tick(&mut self, service: &Service, snapshot: &Snapshot, sockets: &[Arc<UdpSocket>]) {
        let ledger = &service.ledger;
        let settings = &snapshot.config.dynamic.settings;
        let authority = service.authority();
        self.flights.retain(|_, f| {
            if let Some(commit) = &f.committed {
                match commit.try_recv() {
                    Ok(Ok(())) if f.command.state != "sent" => return false,
                    Ok(Ok(())) => {
                        f.committed = None;
                        f.checking = ledger
                            .session(
                                f.command.session.clone(),
                                View {
                                    all: true,
                                    ..Default::default()
                                },
                            )
                            .ok();
                    }
                    Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
                    Err(_) => {}
                }
            } else if let Some(check) = &f.checking {
                match check.try_recv() {
                    Ok(Ok(Some(session))) => {
                        f.checking = None;
                        if current(&f.command, &session, authority.as_ref(), snapshot).is_ok() {
                            if service.transmit(&f.command, &f.socket, f.peer).is_err() {
                                f.command.validation_error =
                                    Some("transmission unavailable or superseded".into());
                            }
                            f.sent = Instant::now();
                        } else {
                            f.command.state = "uncertain".into();
                            f.committed = ledger.command_result(f.command.clone()).ok();
                        }
                    }
                    Ok(_) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        f.checking = None;
                        f.command.state = "uncertain".into();
                        f.committed = ledger.command_result(f.command.clone()).ok();
                    }
                    Err(_) => {}
                }
            } else if f.command.state != "sent" {
                f.committed = ledger.command_result(f.command.clone()).ok();
            } else if f.revalidate {
                // Keep accepting replies during the fresh identity read.
            } else if f.sent.elapsed()
                >= Duration::from_secs(
                    u64::from(settings.retry_seconds) * (1u64 << f.command.attempts.min(3)),
                )
            {
                if f.command.attempts >= settings.retries {
                    f.command.state = "uncertain".into();
                } else {
                    f.revalidate = true;
                }
                if !f.revalidate {
                    f.committed = ledger.command_result(f.command.clone()).ok();
                }
            }
            true
        });
        if self.validation.is_none() {
            if let Some(query) = &self.query {
                match query.try_recv() {
                    Ok(Ok(rows)) => {
                        self.query = None;
                        if let Some(authority) = authority.clone() {
                            let rows: Vec<_> = rows
                                .into_iter()
                                .filter(|(c, _)| {
                                    !self
                                        .flights
                                        .values()
                                        .any(|f| f.command.id == c.id && !f.revalidate)
                                })
                                .take(settings.max_in_flight)
                                .collect();
                            if rows.is_empty() {
                                return;
                            }
                            let config = snapshot.config.clone();
                            let ledger = ledger.clone();
                            let (tx, rx) = mpsc::sync_channel(1);
                            if std::thread::Builder::new()
                                .name("radius-command-validation".into())
                                .spawn(move || {
                                    let sessions: Vec<_> =
                                        rows.iter().map(|(_, s)| s.clone()).collect();
                                    let results = (authority.evaluate)(&sessions);
                                    let validated = rows
                                        .into_iter()
                                        .zip(results)
                                        .map(|((mut c, s), e)| {
                                            let result = validate(&mut c, &s, e, &config, &ledger);
                                            (c, s, result)
                                        })
                                        .collect();
                                    let _ = tx.send(Ok(validated));
                                })
                                .is_ok()
                            {
                                self.validation = Some(rx);
                            }
                        }
                    }
                    Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.query = None
                    }
                    Err(_) => {}
                }
            }
        }
        if let Some(query) = &self.validation {
            match query.try_recv() {
                Ok(Ok(rows)) => {
                    self.validation = None;
                    for (mut command, session, disposition) in rows {
                        if let Some(id) = self
                            .flights
                            .iter()
                            .find(|(_, f)| f.command.id == command.id)
                            .map(|(id, _)| *id)
                        {
                            if !self.flights[&id].revalidate
                                || self.flights[&id].command.state != "sent"
                            {
                                continue;
                            }
                            self.flights.remove(&id);
                        }
                        match disposition {
                            Disposition::Defer => {
                                command.validation_error =
                                    Some("identity reevaluation unavailable".into());
                                command.not_before_ms =
                                    worker::now_ms() + i64::from(settings.interval_seconds) * 1000;
                                let _ = ledger.command_result(command);
                                continue;
                            }
                            Disposition::Cancel => {
                                command.state = if command.attempts == 0 {
                                    "superseded"
                                } else {
                                    "uncertain"
                                }
                                .into();
                                let _ = ledger.command_result(command);
                                continue;
                            }
                            Disposition::Ready => {
                                command.validation_error = None;
                                command.not_before_ms = 0;
                            }
                        }
                        if self.flights.len() >= settings.max_in_flight {
                            break;
                        }
                        if self.flights.values().any(|f| f.command.id == command.id) {
                            continue;
                        }
                        if command.configuration.is_empty() && command.attempts == 0 {
                            command.configuration = snapshot.config.fingerprint.clone();
                            command.target = Target::from_session(&session).ok();
                            command.proof = session
                                .proof
                                .as_ref()
                                .map(|p| p.grant.clone())
                                .unwrap_or_default();
                        }
                        if let Err(reason) =
                            current(&command, &session, authority.as_ref(), snapshot)
                        {
                            command.state = if command.attempts == 0 {
                                reason
                            } else {
                                "uncertain"
                            }
                            .into();
                            let _ = ledger.command_result(command);
                            continue;
                        }
                        let Some(peer) = snapshot.config.peers.get(&session.client) else {
                            continue;
                        };
                        let Some(secret) = snapshot.secrets.get(&peer.id) else {
                            continue;
                        };
                        let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_slice())
                            .as_ref()
                            .to_vec();
                        if command.attempts != 0
                            && (command.packet.len() < 20
                                || command.secret_fingerprint != digest
                                || command.port != peer.disconnect_port)
                        {
                            command.state = "uncertain".into();
                            let _ = ledger.command_result(command);
                            continue;
                        }
                        let Some(socket) = sockets.iter().find(|s| {
                            s.local_addr()
                                .is_ok_and(|a| a.is_ipv4() == session.source.is_ipv4())
                        }) else {
                            continue;
                        };
                        let id = if command.packet.len() >= 20 {
                            let id = command.packet[1];
                            if self.flights.contains_key(&id) {
                                continue;
                            }
                            id
                        } else {
                            let Some(id) = (0..=255).find_map(|_| {
                                let id = self.next;
                                self.next = self.next.wrapping_add(1);
                                (!self.flights.contains_key(&id)).then_some(id)
                            }) else {
                                break;
                            };
                            prepare(
                                &mut command,
                                &snapshot.config.dynamic.profile(&session.client),
                                id,
                                secret.as_slice(),
                            );
                            id
                        };
                        if command.packet.is_empty() {
                            if command.state == "pending" {
                                command.state = "invalid-request".into();
                            }
                            let _ = ledger.command_result(command);
                            continue;
                        }
                        command.secret_fingerprint = digest;
                        command.port = peer.disconnect_port;
                        command.state = "sent".into();
                        command.first_sent_ms.get_or_insert(worker::now_ms());
                        command.attempts = command.attempts.saturating_add(1);
                        if command.attempts > settings.retries {
                            command.state = "uncertain".into();
                            let _ = ledger.command_result(command);
                            continue;
                        }
                        let Ok(committed) = ledger.command_result(command.clone()) else {
                            continue;
                        };
                        self.flights.insert(
                            id,
                            Flight {
                                command,
                                socket: socket.clone(),
                                peer: SocketAddr::new(session.source, peer.disconnect_port),
                                secret: secret.clone(),
                                sent: Instant::now(),
                                committed: Some(committed),
                                checking: None,
                                revalidate: false,
                            },
                        );
                    }
                }
                Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.validation = None
                }
                Err(_) => {}
            }
        }
        if self.query.is_none()
            && self.validation.is_none()
            && self.last.elapsed() >= Duration::from_millis(250)
        {
            self.query = ledger.dispatch().ok();
            self.last = Instant::now();
        }
    }
}
fn validate(
    command: &mut Command,
    session: &Session,
    evaluation: Evaluation,
    config: &crate::accounting::Configuration,
    ledger: &worker::Handle,
) -> Disposition {
    if command.attempts != 0
        && worker::now_ms().saturating_sub(command.first_sent_ms.unwrap_or(command.created_ms))
            > i64::from(config.dynamic.settings.command_lifetime_seconds) * 1000
    {
        return Disposition::Cancel;
    }
    if command.actor != "radiusd" {
        return match (command.action, evaluation) {
            (Action::Disconnect | Action::Reauthenticate, _) => Disposition::Ready,
            (Action::UpdateAuthorization, Evaluation::Granted { desired, .. }) => {
                if command.attempts == 0 {
                    command.desired = Some(desired);
                    Disposition::Ready
                } else if command
                    .desired
                    .as_ref()
                    .is_some_and(|d| d.vlan == desired.vlan)
                {
                    Disposition::Ready
                } else {
                    Disposition::Cancel
                }
            }
            (_, Evaluation::Unavailable(_)) => Disposition::Defer,
            _ => Disposition::Cancel,
        };
    }
    if let Some(budget) = command.reason.strip_prefix("budget:") {
        let Some(budget) = config
            .budgets
            .iter()
            .find(|b| b.id == budget && b.disconnect)
        else {
            return Disposition::Cancel;
        };
        let subject = crate::accounting::usage_subject(
            &budget.principal,
            session.policy.as_deref().unwrap_or_default(),
        );
        return match ledger.balances(subject).and_then(worker::wait) {
            Ok(balances)
                if balances.iter().any(|b| {
                    b.budget.id == budget.id
                        && if b.budget.dimension == radius_accounting::quota::Dimension::Concurrent
                        {
                            b.used > b.budget.maximum
                        } else {
                            b.exhausted()
                        }
                }) =>
            {
                Disposition::Ready
            }
            Ok(_) => Disposition::Cancel,
            Err(_) => Disposition::Defer,
        };
    }
    let Some(policy) = session
        .policy
        .as_ref()
        .and_then(|p| config.dynamic.policies.get(p))
    else {
        return Disposition::Cancel;
    };
    if command.reason == "reevaluation-unavailable-grace-expired" {
        return match evaluation {
            Evaluation::Unavailable(_) if policy.unavailable_grace_seconds.is_some() => {
                Disposition::Ready
            }
            _ => Disposition::Cancel,
        };
    }
    match evaluation {
        Evaluation::Unavailable(_) => Disposition::Defer,
        Evaluation::Denied | Evaluation::Disabled | Evaluation::Deleted => {
            if command.reason == "access-revoked" && policy.revoke_access {
                Disposition::Ready
            } else {
                Disposition::Cancel
            }
        }
        Evaluation::Granted {
            desired,
            credentials,
        } => {
            let Some(proof) = &session.proof else {
                return Disposition::Cancel;
            };
            let relevant = if command.reason.starts_with("vlan-changed:") {
                policy.vlan_disconnect && desired.vlan != proof.issued.vlan
            } else if command.reason.starts_with("credential-changed:") {
                if credentials.is_none() {
                    return Disposition::Defer;
                }
                policy.password_reauthenticate
                    && !proof.credentials.is_empty()
                    && proof
                        .credentials
                        .iter()
                        .any(|p| !credentials.as_ref().expect("checked").contains(p))
            } else if command.reason == "authorization-changed" {
                policy.update_authorization
                    && (desired.vlan != proof.issued.vlan
                        || config
                            .policies
                            .get(session.policy.as_deref().unwrap_or_default())
                            .is_some_and(|p| {
                                p.reauthenticate_seconds != proof.configured_timeout_seconds
                            }))
            } else {
                false
            };
            if !relevant {
                return Disposition::Cancel;
            }
            if command.attempts == 0 {
                command.desired = Some(desired);
                Disposition::Ready
            } else if command
                .desired
                .as_ref()
                .is_some_and(|d| d.vlan == desired.vlan)
            {
                Disposition::Ready
            } else {
                Disposition::Cancel
            }
        }
    }
}
fn prepare(command: &mut Command, profile: &dynamic::Profile, id: u8, secret: &[u8]) {
    let Some(target) = command.target.as_ref() else {
        command.state = "invalid-selector".into();
        return;
    };
    loop {
        match profile.attributes(
            command.action,
            target,
            command.desired.as_ref(),
            worker::now_ms(),
        ) {
            Ok(Some(mut attrs)) => {
                // Opaque nonsecret entropy prevents identical authenticators
                // if a packet Identifier is reused in the same second.
                let Ok(nonce) = radius_accounting::id() else {
                    return;
                };
                attrs.push(Attribute {
                    kind: 33,
                    value: nonce.into_bytes(),
                });
                if let Ok(packet) = wire::dynamic_request(
                    if command.action == Action::Disconnect {
                        wire::DISCONNECT_REQUEST
                    } else {
                        wire::COA_REQUEST
                    },
                    id,
                    &attrs,
                    secret,
                ) {
                    command.packet = packet;
                }
                return;
            }
            Ok(None) if !command.fallback.is_empty() => {
                command.history.push(CommandStep {
                    action: command.action,
                    state: "unsupported".into(),
                    attempts: 0,
                    at_ms: worker::now_ms(),
                    first_sent_ms: None,
                    error_cause: None,
                });
                command.action = command.fallback.remove(0);
            }
            Ok(None) => {
                command.state = "unsupported".into();
                return;
            }
            Err(_) => {
                command.state = "invalid-selector".into();
                return;
            }
        }
    }
}
fn current(
    command: &Command,
    session: &Session,
    authority: Option<&Authority>,
    snapshot: &Snapshot,
) -> Result<(), &'static str> {
    if session.end_ms.is_some() || matches!(session.state, State::Ended | State::InferredEnded) {
        return Err("session-ended");
    }
    if authority.is_none_or(|a| {
        a.revision != command.configuration || a.revision != snapshot.config.fingerprint
    }) {
        return Err("superseded");
    }
    if command.proof
        != session
            .proof
            .as_ref()
            .map(|p| p.grant.clone())
            .unwrap_or_default()
        || Target::from_session(session).ok().as_ref() != command.target.as_ref()
    {
        return Err("superseded");
    }
    let peer = snapshot
        .config
        .peers
        .get(&session.client)
        .filter(|p| p.enabled && p.addresses.iter().any(|a| a.contains(session.source)))
        .ok_or("client-unavailable")?;
    let selected = snapshot
        .config
        .peers
        .values()
        .flat_map(|p| {
            p.addresses
                .iter()
                .filter(|a| a.contains(session.source))
                .map(move |a| (a.bits, &p.id))
        })
        .max_by_key(|(bits, _)| *bits);
    if selected.is_none_or(|(_, id)| id != &session.client)
        || !peer
            .policies
            .iter()
            .any(|id| session.policy.as_ref() == Some(id))
    {
        return Err("client-changed");
    }
    Ok(())
}
