//! Nonblocking integration coordinator. Backend operations and supplied-subject
//! decisions are adapter-owned; no username lookup reconstructs an identity.
use crate::config::{called_ssid, Config};
use radius_core::{Admission, Binding, Client, Engine, Outcome, Reply, Verification};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Granted,
    Credentials,
    Policy,
    MissingContext,
    Backend,
    Busy,
    Timeout,
    Binding,
    Protocol,
    Undelivered,
}
impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Credentials => "authentication-failed",
            Self::Policy => "permission-denied",
            Self::MissingContext => "missing-context",
            Self::Backend => "authority-unavailable",
            Self::Busy => "conversation-limit",
            Self::Timeout => "timed-out",
            Self::Binding => "binding-changed",
            Self::Protocol => "protocol-error",
            Self::Undelivered => "undelivered",
        }
    }
}
pub enum Progress<S> {
    Waiting,
    Complete(S),
    Failed(Reason),
}
pub trait Backend {
    type Work;
    type Subject;
    fn begin(&mut self, verification: Verification) -> Result<Self::Work, Reason>;
    /// Must make bounded, nonblocking progress. Drop cancels unfinished work.
    fn step(&mut self, work: &mut Self::Work) -> Progress<Self::Subject>;
    fn admission(&mut self, subject: &Self::Subject, security: &[u8]) -> Result<(), Reason>;
    fn identity<'a>(&self, subject: &'a Self::Subject) -> (&'a str, &'a [u8]);
}
pub struct Event<'a> {
    pub id: &'a [u8; 16],
    pub client: u64,
    pub network: u64,
    pub username: Option<&'a str>,
    pub canonical: Option<&'a str>,
    pub sid: Option<&'a [u8]>,
    pub reason: Reason,
}
pub trait Output {
    /// Submission to UDP is a delivery boundary, not proof the AP admitted Wi-Fi.
    fn send(&mut self, listener: usize, reply: &Reply) -> bool;
    fn event(&mut self, event: Event<'_>);
    fn discarded(&mut self) {}
}
struct Attempt<W, S> {
    listener: usize,
    binding: Binding,
    username: Option<String>,
    work: Option<W>,
    result: Option<Result<S, Reason>>,
    cancelled: bool,
}
pub struct Driver<B: Backend> {
    engine: Engine,
    config: Arc<Config>,
    ready: bool,
    attempts: HashMap<[u8; 16], Attempt<B::Work, B::Subject>>,
    completed: HashMap<[u8; 16], (Binding, Instant)>,
    backend: B,
}
impl<B: Backend> Driver<B> {
    pub fn new(config: Arc<Config>, backend: B) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            engine: Engine::new(config.tls.clone(), config.limits.clone())
                .map_err(|_| "invalid engine")?,
            config,
            ready: true,
            attempts: HashMap::new(),
            completed: HashMap::new(),
            backend,
        })
    }
    pub fn pause(&mut self) {
        self.ready = false;
    }
    pub fn activate(&mut self, config: Arc<Config>) -> Result<(), &'static str> {
        config.validate()?;
        self.engine
            .update_limits(config.limits.clone())
            .map_err(|_| "invalid limits")?;
        self.engine
            .update_tls(config.tls.clone())
            .map_err(|_| "invalid TLS")?;
        let same_listeners = config.listeners == self.config.listeners;
        for attempt in self.attempts.values_mut() {
            if !same_listeners || config.bound(&attempt.binding).is_none() {
                attempt.cancelled = true;
            }
        }
        self.engine
            .retain_bindings(|binding| same_listeners && config.bound(binding).is_some());
        self.completed
            .retain(|_, (binding, _)| same_listeners && config.bound(binding).is_some());
        self.config = config;
        self.ready = true;
        Ok(())
    }
    pub fn receive(
        &mut self,
        now: Instant,
        listener: usize,
        peer: SocketAddr,
        bytes: &[u8],
        output: &mut impl Output,
    ) {
        let Some(client) = self.config.client(peer.ip()) else {
            return output.discarded();
        };
        // Verify integrity before interpreting any AP-supplied network name.
        let Ok(request) = radius_core::wire::Request::parse(bytes, &client.secret) else {
            return output.discarded();
        };
        let selected = if let Some(id) = request.state {
            let bound = self
                .attempts
                .get(&id)
                .map(|a| &a.binding)
                .or_else(|| self.completed.get(&id).map(|(binding, _)| binding));
            let Some(bound) = bound else {
                return output.discarded();
            };
            let Some((current, name, network)) = self.config.bound(bound) else {
                return output.discarded();
            };
            if current.name != client.name {
                return output.discarded();
            }
            if let Some(called) = request.called_station {
                if called_ssid(called) != Some(network.ssid.as_slice()) {
                    return output.discarded();
                }
            }
            (name, network)
        } else {
            if !self.ready {
                return;
            }
            let Some(ssid) = request.called_station.and_then(called_ssid) else {
                return output.discarded();
            };
            let Some(network) = self.config.network(client, ssid) else {
                return output.discarded();
            };
            network
        };
        let binding = self.config.binding(client, selected.0, peer.ip());
        let policy = u64::from_be_bytes(self.config.fingerprint[..8].try_into().unwrap());
        let context = Client {
            binding: binding.clone(),
            secret: &client.secret,
            policy_generation: policy,
        };
        match self.engine.receive(now, peer, context, bytes) {
            Ok(Outcome::Reply(reply)) => {
                // A pending reload must not replay an old Access-Accept.
                if reply.bytes[0] == 2 && !self.ready {
                    return;
                }
                if let Some(id) = reply_state(&reply.bytes) {
                    if self.engine.has_attempt(&id) {
                        self.attempts.entry(id).or_insert(Attempt {
                            listener,
                            binding,
                            username: None,
                            work: None,
                            result: None,
                            cancelled: false,
                        });
                    }
                }
                let delivered = output.send(listener, &reply);
                if reply.bytes[0] == 3 {
                    if let Some(id) = request.state {
                        if let Some(attempt) = self.attempts.remove(&id) {
                            emit(
                                &mut self.backend,
                                &id,
                                &attempt,
                                attempt.result.as_ref().and_then(|r| r.as_ref().ok()),
                                if delivered {
                                    Reason::Protocol
                                } else {
                                    Reason::Undelivered
                                },
                                output,
                            );
                        }
                    }
                }
            }
            Ok(Outcome::Verify(verification)) => {
                let id = verification.id();
                let active = self.attempts.values().filter(|a| a.work.is_some()).count();
                if let Some(attempt) = self.attempts.get_mut(&id) {
                    attempt.username = std::str::from_utf8(&verification.credentials.username)
                        .ok()
                        .map(str::to_owned);
                    if active >= self.config.verifications {
                        attempt.result = Some(Err(Reason::Busy));
                    } else {
                        match self.backend.begin(verification) {
                            Ok(work) => attempt.work = Some(work),
                            Err(reason) => attempt.result = Some(Err(reason)),
                        }
                    }
                }
            }
            _ => output.discarded(),
        }
    }
    pub fn tick(&mut self, now: Instant, output: &mut impl Output) {
        self.engine.expire(now);
        self.completed.retain(|_, (_, deadline)| now < *deadline);
        let ids: Vec<_> = self.attempts.keys().copied().collect();
        for id in ids {
            let mut attempt = self.attempts.remove(&id).unwrap();
            if !self.engine.has_attempt(&id) {
                emit(
                    &mut self.backend,
                    &id,
                    &attempt,
                    attempt.result.as_ref().and_then(|r| r.as_ref().ok()),
                    if !attempt.cancelled && self.config.bound(&attempt.binding).is_some() {
                        Reason::Timeout
                    } else {
                        Reason::Binding
                    },
                    output,
                );
                continue;
            }
            if let Some(work) = attempt.work.as_mut() {
                match self.backend.step(work) {
                    Progress::Waiting => {}
                    Progress::Complete(subject) => {
                        attempt.work = None;
                        attempt.result = Some(Ok(subject));
                    }
                    Progress::Failed(reason) => {
                        attempt.work = None;
                        attempt.result = Some(Err(reason));
                    }
                }
            }
            if !self.ready || attempt.result.is_none() {
                self.attempts.insert(id, attempt);
                continue;
            }
            let result = attempt.result.take().unwrap();
            let Some((client, _, network)) = self.config.bound(&attempt.binding) else {
                continue;
            };
            let reason = match &result {
                Ok(subject) => self
                    .backend
                    .admission(subject, &network.security)
                    .err()
                    .unwrap_or(Reason::Granted),
                Err(reason) => *reason,
            };
            let context = Client {
                binding: attempt.binding.clone(),
                secret: &client.secret,
                policy_generation: u64::from_be_bytes(
                    self.config.fingerprint[..8].try_into().unwrap(),
                ),
            };
            let reply = self.engine.finish_with_reauthentication(
                now,
                id,
                context,
                if reason == Reason::Granted {
                    Admission::Granted
                } else if matches!(reason, Reason::Backend | Reason::Busy) {
                    Admission::BackendFailure
                } else {
                    Admission::Denied
                },
                Some(network.reauthenticate_seconds),
            );
            if self.completed.len() >= self.config.limits.cached_replies {
                if let Some(oldest) = self
                    .completed
                    .iter()
                    .min_by_key(|(_, (_, deadline))| *deadline)
                    .map(|(id, _)| *id)
                {
                    self.completed.remove(&oldest);
                }
            }
            self.completed.insert(
                id,
                (
                    attempt.binding.clone(),
                    now + self.config.limits.cache_lifetime,
                ),
            );
            let reason = match reply {
                Ok(reply) if output.send(attempt.listener, &reply) => reason,
                _ => Reason::Undelivered,
            };
            emit(
                &mut self.backend,
                &id,
                &attempt,
                result.as_ref().ok(),
                reason,
                output,
            );
        }
    }
    pub fn pending(&self) -> usize {
        self.attempts.len()
    }
}
fn emit<B: Backend>(
    backend: &mut B,
    id: &[u8; 16],
    attempt: &Attempt<B::Work, B::Subject>,
    subject: Option<&B::Subject>,
    reason: Reason,
    output: &mut impl Output,
) {
    let identity = subject.map(|s| backend.identity(s));
    output.event(Event {
        id,
        client: attempt.binding.client,
        network: attempt.binding.network,
        username: attempt.username.as_deref(),
        canonical: identity.map(|(name, _)| name),
        sid: identity.map(|(_, sid)| sid),
        reason,
    });
}
fn reply_state(bytes: &[u8]) -> Option<[u8; 16]> {
    let mut offset = 20;
    while offset + 2 <= bytes.len() {
        let size = usize::from(bytes[offset + 1]);
        if size < 2 || offset + size > bytes.len() {
            return None;
        }
        if bytes[offset] == 24 && size == 18 {
            return bytes[offset + 2..offset + size].try_into().ok();
        }
        offset += size;
    }
    None
}
