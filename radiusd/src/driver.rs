//! Nonblocking integration coordinator. Backend operations and supplied-subject
//! decisions are adapter-owned; no username lookup reconstructs an identity.
use crate::config::{called_ssid, Config, Network};
use radius_core::{Admission, Binding, Client, Engine, Outcome, Reply, Verification};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Granted,
    Credentials,
    Policy,
    MissingContext,
    Backend,
    KernelUnsupported,
    AccessCheck,
    Busy,
    Timeout,
    Binding,
    Protocol,
    Undelivered,
    Quota,
    Accounting,
}
impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Credentials => "authentication-failed",
            Self::Policy => "permission-denied",
            Self::MissingContext => "missing-context",
            Self::Backend => "authority-unavailable",
            Self::KernelUnsupported => "kernel-api-unavailable",
            Self::AccessCheck => "access-check-error",
            Self::Busy => "conversation-limit",
            Self::Timeout => "timed-out",
            Self::Binding => "binding-changed",
            Self::Protocol => "protocol-error",
            Self::Undelivered => "undelivered",
            Self::Quota => "allowance-exhausted",
            Self::Accounting => "accounting-unavailable",
        }
    }
}
pub enum Progress<S> {
    Waiting,
    Mschapv2Challenge([u8; 16]),
    Complete(S),
    Failed(Reason),
}
pub struct AdmissionContext<'a> {
    pub vlan: Option<u16>,
    pub authorization: &'a radius_authorization::Compiled,
    pub configured_timeout_seconds: u32,
    pub id: [u8; 16],
    pub client_id: &'a str,
    pub network_id: &'a str,
    pub network: &'a Network,
    pub station: Option<&'a [u8]>,
    pub saved_fingerprint: &'a str,
}
#[derive(Default)]
pub struct AdmissionExtras {
    pub class: Option<Vec<u8>>,
    pub timeout_seconds: Option<u32>,
}
pub trait Backend {
    type Work;
    type Subject;
    fn begin(&mut self, verification: Verification) -> Result<Self::Work, Reason>;
    /// Must make bounded, nonblocking progress. Drop cancels unfinished work.
    fn step(&mut self, work: &mut Self::Work) -> Progress<Self::Subject>;
    fn operation_guid(&self, _work: &Self::Work) -> Option<[u8; 16]> {
        None
    }
    fn mschapv2_response(
        &mut self,
        _work: &mut Self::Work,
        _response: &[u8; 40],
    ) -> Result<(), Reason> {
        Err(Reason::Credentials)
    }
    fn mschapv2_success(&self, _subject: &Self::Subject) -> Option<[u8; 20]> {
        None
    }
    fn admission(
        &mut self,
        subject: &Self::Subject,
        network_id: &str,
        network: &Network,
    ) -> Result<(), Reason>;
    fn identity<'a>(&self, subject: &'a Self::Subject) -> (&'a str, &'a [u8]);
    /// Authority-disclosed identity only; the driver adds verified client and
    /// asserted request context separately.
    fn policy_facts(&self, _subject: &Self::Subject) -> Result<radius_policy::Facts, Reason> {
        Ok(radius_policy::Facts::new())
    }
    /// None means pending background accounting work, never implicit success.
    fn accounting(
        &mut self,
        _subject: &Self::Subject,
        _context: AdmissionContext<'_>,
    ) -> Result<Option<AdmissionExtras>, Reason> {
        Ok(Some(AdmissionExtras::default()))
    }
    fn completed(&mut self, _id: &[u8; 16]) {}
}
pub struct Event<'a> {
    pub diagnostic: radius_management::diagnostics::Record,
    pub id: &'a [u8; 16],
    pub client: u64,
    pub network: u64,
    pub username: Option<&'a str>,
    pub canonical: Option<&'a str>,
    pub sid: Option<&'a [u8]>,
    pub reason: Reason,
}
pub trait Output {
    fn progress(&mut self, _record: &radius_management::diagnostics::Record) {}
    fn discarded_sample(
        &mut self,
        _reason: &'static str,
        _listener: usize,
        _peer: SocketAddr,
        _client: Option<&str>,
    ) {
        self.discarded();
    }
    /// Operational diagnostics containing rule paths, never supplied facts.
    fn policy_issue(&mut self, _id: &[u8; 16], _issue: &str) {}
    /// Submission to UDP is a delivery boundary, not proof the AP admitted Wi-Fi.
    fn send(&mut self, listener: usize, reply: &Reply) -> bool;
    fn event(&mut self, event: Event<'_>);
    fn discarded(&mut self) {}
}
struct Attempt<W, S> {
    trace: crate::diagnostics::Trace,
    challenge: Option<[u8; 16]>,
    listener: usize,
    binding: Binding,
    username: Option<String>,
    work: Option<W>,
    result: Option<Result<S, Reason>>,
    cancelled: bool,
    station: Option<Vec<u8>>,
    authorised: Option<([u8; 32], Result<(), Reason>)>,
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
            return output.discarded_sample("unknown-client", listener, peer, None);
        };
        // A disabled, most-specific client must not fall back to a wider range.
        if !client.enabled {
            return output.discarded_sample("disabled-client", listener, peer, Some(&client.name));
        }
        // Verify integrity before interpreting any AP-supplied network name.
        let request = match radius_core::wire::Request::parse(bytes, &client.secret) {
            Ok(request) => request,
            Err(error) => {
                return output.discarded_sample(
                    if error == radius_core::Error::Integrity {
                        "integrity-failed"
                    } else {
                        "malformed-request"
                    },
                    listener,
                    peer,
                    Some(&client.name),
                );
            }
        };
        let selected = if let Some(id) = request.state {
            let bound = self
                .attempts
                .get(&id)
                .map(|a| &a.binding)
                .or_else(|| self.completed.get(&id).map(|(binding, _)| binding));
            let Some(bound) = bound else {
                return output.discarded_sample(
                    "unknown-state",
                    listener,
                    peer,
                    Some(&client.name),
                );
            };
            let Some((current, name, network)) = self.config.bound(bound) else {
                return output.discarded_sample(
                    "stale-binding",
                    listener,
                    peer,
                    Some(&client.name),
                );
            };
            if current.name != client.name {
                return output.discarded_sample(
                    "client-mismatch",
                    listener,
                    peer,
                    Some(&client.name),
                );
            }
            if let Some(called) = request.called_station {
                if called_ssid(called) != Some(network.ssid.as_slice()) {
                    return output.discarded_sample(
                        "network-mismatch",
                        listener,
                        peer,
                        Some(&client.name),
                    );
                }
            }
            (name, network)
        } else {
            if !self.ready {
                output.discarded_sample(
                    "configuration-unavailable",
                    listener,
                    peer,
                    Some(&client.name),
                );
                return;
            }
            let Some(ssid) = request.called_station.and_then(called_ssid) else {
                return output.discarded_sample(
                    "missing-network",
                    listener,
                    peer,
                    Some(&client.name),
                );
            };
            let Some(network) = self.config.network(client, ssid) else {
                return output.discarded_sample(
                    "network-not-permitted",
                    listener,
                    peer,
                    Some(&client.name),
                );
            };
            network
        };
        if !selected.1.enabled {
            return output.discarded_sample("disabled-network", listener, peer, Some(&client.name));
        }
        if let Some(tls) = &selected.1.tls {
            if self.engine.update_tls(tls.clone()).is_err() {
                return output.discarded_sample(
                    "tls-configuration",
                    listener,
                    peer,
                    Some(&client.name),
                );
            }
        }
        let binding = self.config.binding(client, selected.0, peer.ip());
        let policy = u64::from_be_bytes(self.config.fingerprint[..8].try_into().unwrap());
        let context = Client {
            binding: binding.clone(),
            secret: &client.secret,
            policy_generation: policy,
        };
        let outcome =
            self.engine
                .receive_with_methods(now, peer, context, bytes, &selected.1.methods);
        if let Some(id) = request.state {
            if let Some(a) = self.attempts.get_mut(&id) {
                if let Some((method, tls, repeated, selected)) =
                    self.engine.diagnostic_progress(&id)
                {
                    let changed = a.trace.method != method.name();
                    a.trace.method = method.name();
                    if selected {
                        a.trace.stage("method", "selected", output);
                    } else if changed {
                        a.trace.stage("method", "offered", output);
                    }
                    a.trace.set("object.radiusd.retransmissions", repeated);
                    if tls && !a.trace.tls_ready {
                        a.trace.tls_ready = true;
                        a.trace.stage("tls", "established", output);
                    }
                }
            }
        }
        if let Some((id, error)) = self.engine.take_terminal_failure() {
            if let Some(a) = self.attempts.get_mut(&id) {
                a.trace.failure = Some(if error == radius_core::Error::Tls {
                    "tls-failed"
                } else {
                    "protocol-failed"
                });
                a.trace.set(
                    "outcome.reason",
                    if error == radius_core::Error::Tls {
                        "tls-failed"
                    } else {
                        "protocol-failed"
                    },
                );
                a.trace.stage(
                    if error == radius_core::Error::Tls {
                        "tls"
                    } else {
                        "protocol"
                    },
                    "failed",
                    output,
                );
            }
        }
        match outcome {
            Ok(Outcome::Reply(reply)) => {
                // A pending reload must not replay an old Access-Accept.
                if reply.bytes[0] == 2 && !self.ready {
                    return;
                }
                if let Some(id) = reply_state(&reply.bytes) {
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        self.attempts.entry(id)
                    {
                        if self.engine.has_attempt(&id) {
                            entry.insert(Attempt {
                                trace: {
                                    let mut trace = crate::diagnostics::Trace::new(
                                        crate::diagnostics::Context {
                                            id: &id,
                                            peer,
                                            listener: self.config.listeners.get(listener).copied(),
                                            client: &client.name,
                                            network: selected.0,
                                            policy: selected.1,
                                            config: &self.config,
                                            now,
                                        },
                                    );
                                    if let Some(station) =
                                        request.station.and_then(radius_policy::station_mac)
                                    {
                                        trace.set(
                                            "source.radiusd.station",
                                            station
                                                .iter()
                                                .map(|b| format!("{b:02x}"))
                                                .collect::<Vec<_>>()
                                                .join(":"),
                                        );
                                    }
                                    trace.stage("started", "observed", output);
                                    trace.stage("method", "offered", output);
                                    trace
                                },
                                challenge: None,
                                listener,
                                binding,
                                username: None,
                                work: None,
                                result: None,
                                cancelled: false,
                                station: request.station.map(Vec::from),
                                authorised: None,
                            });
                        }
                    }
                }
                if let Some(id) = reply_state(&reply.bytes) {
                    if let (Some(attempt), Some((_, _, repeated, _))) = (
                        self.attempts.get_mut(&id),
                        self.engine.diagnostic_progress(&id),
                    ) {
                        attempt
                            .trace
                            .set("object.radiusd.retransmissions", repeated);
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
                    if let Some(name) = &attempt.username {
                        attempt.trace.set("source.radiusd.username", name.clone());
                    }
                    attempt.trace.stage("credentials", "pending", output);
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
            Ok(Outcome::Mschapv2Response { id, response }) => {
                if let Some(attempt) = self.attempts.get_mut(&id) {
                    let result = attempt
                        .work
                        .as_mut()
                        .ok_or(Reason::Credentials)
                        .and_then(|work| self.backend.mschapv2_response(work, &response));
                    if let Err(reason) = result {
                        attempt.work = None;
                        attempt.result = Some(Err(reason));
                    }
                }
            }
            Ok(Outcome::Drop) => {}
            Err(error) => output.discarded_sample(
                match error {
                    radius_core::Error::Limit => "conversation-limit",
                    radius_core::Error::Binding => "binding-mismatch",
                    _ => "protocol-rejected",
                },
                listener,
                peer,
                Some(&client.name),
            ),
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
                let progress = self.backend.step(work);
                attempt.trace.authority(self.backend.operation_guid(work));
                match progress {
                    Progress::Waiting => {}
                    Progress::Mschapv2Challenge(challenge) => {
                        attempt.challenge = Some(challenge);
                    }
                    Progress::Complete(subject) => {
                        let (name, sid) = self.backend.identity(&subject);
                        attempt.trace.set("object.radiusd.canonical-name", name);
                        attempt.trace.set(
                            "object.account.sid",
                            radius_management::diagnostics::hex(sid),
                        );
                        attempt.trace.stage("credentials", "verified", output);
                        attempt.work = None;
                        attempt.result = Some(Ok(subject));
                    }
                    Progress::Failed(reason) => {
                        attempt.trace.set("outcome.reason", reason.name());
                        attempt.trace.stage("credentials", "failed", output);
                        attempt.work = None;
                        attempt.result = Some(Err(reason));
                    }
                }
            }
            if self.ready {
                if let Some(challenge) = attempt.challenge.take() {
                    match self.engine.mschapv2_challenge(now, id, challenge) {
                        Ok(reply) if output.send(attempt.listener, &reply) => {}
                        _ => {
                            // Exact retransmission may still deliver a cached
                            // challenge. Keep the fixed conversation deadlines.
                        }
                    }
                }
            }
            if !self.ready || attempt.result.is_none() || !self.engine.pending_reply(&id) {
                self.attempts.insert(id, attempt);
                continue;
            }
            let result = attempt.result.take().unwrap();
            let Some((client, network_id, network)) = self.config.bound(&attempt.binding) else {
                continue;
            };
            let mut reason = match &result {
                Ok(subject) => {
                    if attempt
                        .authorised
                        .as_ref()
                        .is_none_or(|(generation, _)| *generation != self.config.fingerprint)
                    {
                        attempt.authorised = Some((
                            self.config.fingerprint,
                            self.backend.admission(subject, network_id, network),
                        ));
                    }
                    attempt
                        .authorised
                        .as_ref()
                        .unwrap()
                        .1
                        .err()
                        .unwrap_or(Reason::Granted)
                }
                Err(reason) => *reason,
            };
            let mut extras = AdmissionExtras::default();
            let mut vlan = None;
            let mut authorization = radius_authorization::Compiled::default();
            let mut configured_timeout_seconds = network.reauthenticate_seconds;
            attempt.trace.set(
                "object.radiusd.config.fingerprint",
                radius_management::diagnostics::hex(&self.config.fingerprint),
            );
            attempt.trace.set(
                "object.radiusd.config.saved-fingerprint",
                self.config.saved_fingerprint.clone(),
            );
            if result.is_ok() {
                if reason != Reason::Granted {
                    attempt.trace.set("outcome.reason", reason.name());
                }
                attempt.trace.stage(
                    "permissions",
                    if reason == Reason::Granted {
                        "granted"
                    } else {
                        "refused"
                    },
                    output,
                );
            }
            if reason == Reason::Granted {
                for key in [
                    "object.radiusd.assignment.profile.id",
                    "object.radiusd.assignment.rule.id",
                    "object.radiusd.assignment.profile.name",
                    "object.radiusd.assignment.rule.name",
                    "object.radiusd.assignment.vlan",
                    "object.radiusd.assignment.fingerprint",
                ] {
                    attempt.trace.fields.remove(key);
                }
                let assignment = self
                    .backend
                    .policy_facts(result.as_ref().unwrap())
                    .and_then(|mut facts| {
                        use radius_policy::Scalar;
                        facts.insert(
                            "Client.Id".into(),
                            vec![Scalar::String(client.name.clone())],
                        );
                        facts.insert(
                            "Client.Address".into(),
                            vec![Scalar::Address(attempt.binding.source)],
                        );
                        facts.insert(
                            "Request.SSID".into(),
                            vec![Scalar::String(
                                String::from_utf8(network.ssid.clone())
                                    .map_err(|_| Reason::MissingContext)?,
                            )],
                        );
                        if let Some(station) = attempt
                            .station
                            .as_deref()
                            .and_then(radius_policy::station_mac)
                        {
                            facts.insert("Request.Station".into(), vec![Scalar::Mac(station)]);
                        }
                        network
                            .access
                            .assignment_with_rule(&facts)
                            .map_err(|issue| {
                                attempt.trace.set(
                                    "outcome.detail",
                                    issue.chars().take(256).collect::<String>(),
                                );
                                attempt.trace.set("outcome.reason", Reason::Policy.name());
                                output.policy_issue(&id, &issue);
                                Reason::Policy
                            })
                    });
                match assignment {
                    Ok((value, rule)) => {
                        match value.settings.compile(value.vlan, &client.authorization) {
                            Ok(compiled) => {
                                configured_timeout_seconds =
                                    value.settings.timer(network.reauthenticate_seconds).0;
                                authorization = compiled;
                            }
                            Err(issue) => {
                                attempt.trace.set(
                                    "outcome.detail",
                                    issue.chars().take(256).collect::<String>(),
                                );
                                attempt.trace.set("outcome.reason", Reason::Policy.name());
                                output.policy_issue(&id, &issue);
                                reason = Reason::Policy;
                            }
                        }
                        if reason == Reason::Granted {
                            let material = serde_json::to_value((value.vlan, &authorization))
                                .expect("validated authorization serializes");
                            let record = radius_management::diagnostics::Record::from([(
                                "authorization".into(),
                                material,
                            )]);
                            attempt.trace.set(
                                "object.radiusd.assignment.fingerprint",
                                radius_management::diagnostics::hex(
                                    &radius_management::diagnostics::record_digest(&record),
                                ),
                            );
                        }
                        vlan = value.vlan;
                        if let Some(label) = self
                            .config
                            .labels
                            .get(&format!("AccessProfiles/{}", value.profile))
                        {
                            attempt
                                .trace
                                .set("object.radiusd.assignment.profile.name", label.clone());
                        }
                        attempt
                            .trace
                            .set("object.radiusd.assignment.profile.id", value.profile);
                        if let Some(rule) = rule {
                            if let Some(label) = self.config.labels.get(&format!("Rules/{rule}")) {
                                attempt
                                    .trace
                                    .set("object.radiusd.assignment.rule.name", label.clone());
                            }
                            attempt.trace.set("object.radiusd.assignment.rule.id", rule);
                        }
                        if let Some(vlan) = vlan {
                            attempt
                                .trace
                                .set("object.radiusd.assignment.vlan", u64::from(vlan));
                        }
                        attempt.trace.stage(
                            "assignment",
                            if reason == Reason::Granted {
                                "granted"
                            } else {
                                "refused"
                            },
                            output,
                        );
                    }
                    Err(error) => {
                        reason = error;
                        attempt.trace.set("outcome.reason", error.name());
                        attempt.trace.stage("assignment", "refused", output);
                    }
                }
            }
            if reason == Reason::Granted && self.engine.final_admission(&id) {
                attempt.trace.stage("accounting", "pending", output);
                match self.backend.accounting(
                    result.as_ref().unwrap(),
                    AdmissionContext {
                        vlan,
                        authorization: &authorization,
                        configured_timeout_seconds,
                        id,
                        client_id: &client.name,
                        network_id,
                        network,
                        station: attempt.station.as_deref(),
                        saved_fingerprint: &self.config.saved_fingerprint,
                    },
                ) {
                    Ok(Some(value)) => {
                        extras = value;
                        attempt.trace.stage("accounting", "granted", output);
                    }
                    Ok(None) => {
                        attempt.result = Some(result);
                        self.attempts.insert(id, attempt);
                        continue;
                    }
                    Err(error) => {
                        reason = error;
                        attempt.trace.set("outcome.reason", error.name());
                        attempt.trace.stage("accounting", "refused", output);
                    }
                }
            }
            let context = Client {
                binding: attempt.binding.clone(),
                secret: &client.secret,
                policy_generation: u64::from_be_bytes(
                    self.config.fingerprint[..8].try_into().unwrap(),
                ),
            };
            let reply = self.engine.finish_with_authorization(
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
                Some(
                    extras
                        .timeout_seconds
                        .map_or(configured_timeout_seconds, |v| {
                            v.min(configured_timeout_seconds)
                        }),
                ),
                result
                    .as_ref()
                    .ok()
                    .and_then(|subject| self.backend.mschapv2_success(subject)),
                extras.class.as_deref(),
                vlan,
                Some(&authorization),
            );
            if self.engine.has_attempt(&id) {
                if let Ok(reply) = reply {
                    output.send(attempt.listener, &reply);
                }
                attempt.result = Some(result);
                self.attempts.insert(id, attempt);
                continue;
            }
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
        diagnostic: attempt.trace.terminal(reason),
        id,
        client: attempt.binding.client,
        network: attempt.binding.network,
        username: attempt.username.as_deref(),
        canonical: identity.map(|(name, _)| name),
        sid: identity.map(|(_, sid)| sid),
        reason,
    });
    backend.completed(id);
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
