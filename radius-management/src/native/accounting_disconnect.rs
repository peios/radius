//! Bounded, durable Disconnect requests. An ACK never substitutes for Stop.
use super::accounting::Snapshot;
use radius_accounting::{
    model::{Session, State},
    store::Command,
    wire::{self, Attribute},
    worker::{self, Completion, Handle},
};
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
    packet: Vec<u8>,
    sent: Instant,
    committed: Option<Completion<()>>,
}
pub(super) struct Disconnects {
    flights: BTreeMap<u8, Flight>,
    query: Option<Completion<Vec<(Command, Session)>>>,
    last: Instant,
    next: u8,
}
impl Disconnects {
    pub fn new() -> Self {
        Self {
            flights: BTreeMap::new(),
            query: None,
            last: Instant::now() - Duration::from_secs(2),
            next: 0,
        }
    }
    pub fn response(
        &mut self,
        socket: &UdpSocket,
        source: SocketAddr,
        packet: &[u8],
        ledger: &Handle,
    ) -> bool {
        if packet.len() < 20 || !matches!(packet[0], 41 | 42) {
            return false;
        }
        let Some(f) = self.flights.get_mut(&packet[1]) else {
            return true;
        };
        if f.peer != source || f.socket.local_addr().ok() != socket.local_addr().ok() {
            return true;
        }
        if let Ok((ack, cause)) = wire::disconnect_result(packet, &f.packet, f.secret.as_slice()) {
            f.command.state = if ack { "acknowledged" } else { "rejected" }.into();
            f.command.error_cause = cause;
            f.committed = ledger.command_result(f.command.clone()).ok();
        }
        true
    }
    pub fn tick(&mut self, ledger: &Handle, snapshot: &Snapshot, sockets: &[Arc<UdpSocket>]) {
        self.flights.retain(|_, f| {
            if f.command.state == "sent"
                && f.committed.is_none()
                && f.command.attempts >= 4
                && f.sent.elapsed() >= Duration::from_secs(4)
            {
                f.command.state = "uncertain".into();
            }
            if let Some(commit) = &f.committed {
                match commit.try_recv() {
                    Ok(Ok(())) => {
                        if f.command.state != "sent" {
                            return false;
                        }
                        let _ = f.socket.send_to(&f.packet, f.peer);
                        f.sent = Instant::now();
                        f.committed = None;
                    }
                    Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
                    Err(_) => {}
                }
            } else if f.command.state != "sent" {
                f.committed = ledger.command_result(f.command.clone()).ok();
            } else if f.sent.elapsed() >= Duration::from_secs(1u64 << f.command.attempts.min(2)) {
                let mut retry = f.command.clone();
                retry.attempts += 1;
                if let Ok(committed) = ledger.command_result(retry.clone()) {
                    f.command = retry;
                    f.committed = Some(committed);
                }
            }
            true
        });
        if let Some(query) = &self.query {
            match query.try_recv() {
                Ok(Ok(rows)) => {
                    self.query = None;
                    for (mut command, session) in rows {
                        if self.flights.len() >= 128 {
                            break;
                        }
                        if self.flights.values().any(|f| f.command.id == command.id) {
                            continue;
                        }
                        if session.end_ms.is_some()
                            || matches!(session.state, State::Ended | State::InferredEnded)
                        {
                            command.state = "session-ended".into();
                            let _ = ledger.command_result(command);
                            continue;
                        }
                        let Some(peer) = snapshot.config.peers.get(&session.client).filter(|p| {
                            p.enabled && p.addresses.iter().any(|a| a.contains(session.source))
                        }) else {
                            command.state = "client-unavailable".into();
                            let _ = ledger.command_result(command);
                            continue;
                        };
                        // Preserve prefix masking even if configuration changed since Start.
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
                        if selected.is_none_or(|(_, id)| id != &session.client) {
                            command.state = "client-changed".into();
                            let _ = ledger.command_result(command);
                            continue;
                        }
                        let Some(secret) = snapshot.secrets.get(&peer.id) else {
                            continue;
                        };
                        let Some(socket) = sockets.iter().find(|s| {
                            s.local_addr()
                                .is_ok_and(|a| a.is_ipv4() == session.source.is_ipv4())
                        }) else {
                            continue;
                        };
                        let identifier = (0..=255).find_map(|_| {
                            let id = self.next;
                            self.next = self.next.wrapping_add(1);
                            (!self.flights.contains_key(&id)).then_some(id)
                        });
                        let Some(id) = identifier else { break };
                        let mut attrs = session.nas_attributes.clone();
                        attrs.push(Attribute {
                            kind: 44,
                            value: session.session,
                        });
                        if let Some(station) = session.station {
                            attrs.push(Attribute {
                                kind: 31,
                                value: station,
                            });
                        }
                        attrs.push(Attribute::integer(
                            55,
                            (worker::now_ms() / 1000).max(0).min(u32::MAX as i64) as u32,
                        ));
                        let Ok(packet) = wire::disconnect(id, &attrs, secret.as_slice()) else {
                            command.state = "invalid-selector".into();
                            let _ = ledger.command_result(command);
                            continue;
                        };
                        command.state = "sent".into();
                        command.attempts = command.attempts.saturating_add(1);
                        if command.attempts > 4 {
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
                                packet,
                                sent: Instant::now(),
                                committed: Some(committed),
                            },
                        );
                    }
                }
                Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => self.query = None,
                Err(_) => {}
            }
        }
        if self.query.is_none() && self.last.elapsed() >= Duration::from_secs(1) {
            self.query = ledger.dispatch().ok();
            self.last = Instant::now();
        }
    }
}
