use crate::{
    ttls::{Step, Tunnel},
    wire, Error,
};
use ring::digest;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Context established by the transport/configuration adapter, never from
/// client-asserted NAS-IP-Address. Changes to trust invalidate old attempts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Binding {
    pub client: u64,
    pub trust_generation: u64,
    pub network: u64,
    pub source: IpAddr,
}

/// The adapter supplies the currently selected trusted client's secret.
pub struct Client<'a> {
    pub binding: Binding,
    pub secret: &'a [u8],
    /// Cache isolation when admission policy changes. This is not a grant.
    pub policy_generation: u64,
}

/// Limits apply to every attempt and include attempts awaiting a backend reply.
#[derive(Debug, Clone)]
pub struct Limits {
    pub idle: Duration,
    pub overall: Duration,
    pub cache_lifetime: Duration,
    pub attempts: usize,
    pub per_client: usize,
    pub cached_replies: usize,
    pub frame_payload: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(30),
            overall: Duration::from_secs(120),
            cache_lifetime: Duration::from_secs(15),
            attempts: 256,
            per_client: 32,
            cached_replies: 1024,
            frame_payload: 1000,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if self.idle.is_zero()
            || self.overall.is_zero()
            || self.cache_lifetime.is_zero()
            || self.attempts == 0
            || self.per_client == 0
            || self.cached_replies == 0
            || !(64..=3000).contains(&self.frame_payload)
            || self.idle > Duration::from_secs(3600)
            || self.overall > Duration::from_secs(3600)
            || self.cache_lifetime > Duration::from_secs(3600)
            || self.attempts > 65536
            || self.per_client > 65536
            || self.cached_replies > 65536
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Password bytes are erased on drop. Debug formatting never exposes either
/// field. A production adapter owns any additional credential-conversation state.
pub struct Credentials {
    pub username: Vec<u8>,
    pub password: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials([redacted])")
    }
}

/// One-shot credential/admission continuation. The caller retains the complete
/// verified subject on this attempt and returns a decision through `finish`.
pub struct Verification {
    id: [u8; 16],
    pub credentials: Credentials,
    pub binding: Binding,
}
impl Verification {
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Granted,
    Denied,
    BackendFailure,
}

pub struct Reply {
    pub peer: SocketAddr,
    pub bytes: Vec<u8>,
}
pub enum Outcome {
    Reply(Reply),
    Verify(Verification),
    Drop,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    peer: SocketAddr,
    binding: Binding,
    policy: u64,
    hash: [u8; 32],
}
struct Cached {
    key: CacheKey,
    expires: Instant,
    bytes: Vec<u8>,
}
struct Pending {
    key: CacheKey,
    radius_id: u8,
    request_auth: [u8; 16],
    eap_id: u8,
    secret: Zeroizing<Vec<u8>>,
}
struct Attempt {
    binding: Binding,
    secret_tag: [u8; 32],
    station: Option<Vec<u8>>,
    started: Instant,
    touched: Instant,
    idle: Duration,
    overall: Duration,
    expected_eap_id: u8,
    tunnel: Tunnel,
    pending: Option<Pending>,
}
impl Attempt {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= self.overall
            || now.saturating_duration_since(self.touched) >= self.idle
    }
}

/// A caller-owned, single-threaded state machine. It performs no blocking I/O.
/// A stalled backend can leave an attempt pending only until its fixed deadlines.
pub struct Engine {
    tls: Arc<rustls::ServerConfig>,
    limits: Limits,
    attempts: HashMap<[u8; 16], Attempt>,
    cache: VecDeque<Cached>,
}
impl Engine {
    pub fn new(tls: Arc<rustls::ServerConfig>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        // Do not accept generic TLS defaults that can resume before inner auth.
        if tls.send_tls13_tickets != 0
            || tls.max_tls13_tickets != 0
            || tls.max_early_data_size != 0
            || tls.ticketer.enabled()
            || tls.session_storage.can_cache()
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            tls,
            limits,
            attempts: HashMap::new(),
            cache: VecDeque::new(),
        })
    }

    /// Apply limits to future attempts. Existing attempts retain their original
    /// deadlines. Lower allocation limits do not evict in-progress exchanges.
    pub fn update_limits(&mut self, limits: Limits) -> Result<(), Error> {
        limits.validate()?;
        while self.cache.len() > limits.cached_replies {
            self.cache.pop_front();
        }
        self.limits = limits;
        Ok(())
    }

    /// Reap bounded tables even when no packets arrive. The driver should call
    /// this periodically; every receive/finish also calls it.
    pub fn expire(&mut self, now: Instant) {
        self.attempts.retain(|_, a| !a.expired(now));
        self.cache.retain(|c| now < c.expires);
    }
    pub fn active_attempts(&self) -> usize {
        self.attempts.len()
    }

    /// Replace the certificate for future attempts; existing TLS conversations
    /// retain their original configuration. Apply only a fully validated config.
    pub fn update_tls(&mut self, tls: Arc<rustls::ServerConfig>) -> Result<(), Error> {
        Self::new(tls.clone(), self.limits.clone())?;
        self.tls = tls;
        Ok(())
    }

    pub fn has_attempt(&self, id: &[u8; 16]) -> bool {
        self.attempts.contains_key(id)
    }

    /// Invalidate both conversations and cached terminal/challenge replies when
    /// the driver removes a trusted client/network binding.
    pub fn retain_bindings(&mut self, mut valid: impl FnMut(&Binding) -> bool) {
        self.attempts.retain(|_, attempt| valid(&attempt.binding));
        self.cache.retain(|reply| valid(&reply.key.binding));
    }

    /// Parse/integrity errors are returned to the driver for redacted counters;
    /// the driver silently discards those packets rather than answering them.
    pub fn receive(
        &mut self,
        now: Instant,
        peer: SocketAddr,
        client: Client<'_>,
        bytes: &[u8],
    ) -> Result<Outcome, Error> {
        self.expire(now);
        if peer.ip() != client.binding.source
            || client.secret.len() < 16
            || client.secret.len() > 1024
        {
            return Err(Error::Binding);
        }
        let request = wire::Request::parse(bytes, client.secret)?;
        let secret_tag: [u8; 32] = digest::digest(&digest::SHA256, client.secret)
            .as_ref()
            .try_into()
            .map_err(|_| Error::Binding)?;
        let key = CacheKey {
            peer,
            binding: client.binding.clone(),
            policy: client.policy_generation,
            hash: digest::digest(&digest::SHA256, request.canonical)
                .as_ref()
                .try_into()
                .map_err(|_| Error::Malformed)?,
        };
        if let Some(cached) = self.cache.iter().find(|c| {
            c.key.peer == key.peer && c.key.binding == key.binding && c.key.hash == key.hash
                // A challenge grants nothing. Preserve its exact retransmission
                // across policy edits; only terminal decisions require matching
                // the admission generation. Final admission still uses current policy.
                && (c.key.policy == key.policy || c.bytes.first() == Some(&11))
        }) {
            return Ok(Outcome::Reply(Reply {
                peer,
                bytes: cached.bytes.clone(),
            }));
        }
        let eap = &request.eap;
        if eap[0] != 2 || eap.len() < 5 {
            return Err(Error::Protocol);
        }
        if eap[4] == 1 {
            if request.state.is_some() {
                return Err(Error::Protocol);
            }
            if self.attempts.len() >= self.limits.attempts
                || self
                    .attempts
                    .values()
                    .filter(|a| a.binding.client == client.binding.client)
                    .count()
                    >= self.limits.per_client
            {
                return Err(Error::Limit);
            }
            if eap.len() > 258 {
                return Err(Error::Limit);
            }
            let mut id = wire::random()?;
            for _ in 0..4 {
                if !self.attempts.contains_key(&id) {
                    break;
                }
                id = wire::random()?;
            }
            if self.attempts.contains_key(&id) {
                return Err(Error::Random);
            }
            let next = eap[1].wrapping_add(1);
            let reply = wire::response(
                request.identifier,
                &request.authenticator,
                client.secret,
                11,
                &wire::eap_request(next, &[0x20])?,
                Some(id),
                None,
            )?;
            self.attempts.insert(
                id,
                Attempt {
                    binding: client.binding,
                    secret_tag,
                    station: request.station.map(<[u8]>::to_vec),
                    started: now,
                    touched: now,
                    idle: self.limits.idle,
                    overall: self.limits.overall,
                    expected_eap_id: next,
                    tunnel: Tunnel::new(self.tls.clone(), self.limits.frame_payload)?,
                    pending: None,
                },
            );
            self.remember(now, key, reply.clone());
            return Ok(Outcome::Reply(Reply { peer, bytes: reply }));
        }
        let id = request.state.ok_or(Error::Protocol)?;
        let mut attempt = self.attempts.remove(&id).ok_or(Error::UnknownAttempt)?;
        if attempt.binding != client.binding
            || attempt.station.as_deref() != request.station
            || !bool::from(attempt.secret_tag.ct_eq(&secret_tag))
        {
            // A foreign source/client cannot cancel another party's attempt.
            // For the same client and address, a changed trust definition or
            // network is an invalidation, not a context switch or resumable pause.
            if attempt.binding.client != client.binding.client
                || attempt.binding.source != client.binding.source
                || attempt.station.as_deref() != request.station
            {
                self.attempts.insert(id, attempt);
            }
            return Err(Error::Binding);
        }
        if attempt.pending.is_some() || eap[1] != attempt.expected_eap_id {
            self.attempts.insert(id, attempt);
            return Ok(Outcome::Drop);
        }
        attempt.touched = now;
        let step = if eap[4] == 21 {
            attempt.tunnel.step(&eap[5..])
        } else {
            Err(Error::Protocol)
        };
        match step {
            Ok(Step::Verify(credentials)) => {
                attempt.pending = Some(Pending {
                    key,
                    radius_id: request.identifier,
                    request_auth: request.authenticator,
                    eap_id: eap[1],
                    secret: Zeroizing::new(client.secret.to_vec()),
                });
                let binding = attempt.binding.clone();
                self.attempts.insert(id, attempt);
                Ok(Outcome::Verify(Verification {
                    id,
                    credentials,
                    binding,
                }))
            }
            Ok(Step::Send(data)) => {
                let next = eap[1].wrapping_add(1);
                attempt.expected_eap_id = next;
                let reply = wire::response(
                    request.identifier,
                    &request.authenticator,
                    client.secret,
                    11,
                    &wire::eap_request(next, &data)?,
                    Some(id),
                    None,
                )?;
                self.attempts.insert(id, attempt);
                self.remember(now, key, reply.clone());
                Ok(Outcome::Reply(Reply { peer, bytes: reply }))
            }
            Err(_) => {
                let reply = wire::response(
                    request.identifier,
                    &request.authenticator,
                    client.secret,
                    3,
                    &wire::eap_terminal(eap[1], false),
                    None,
                    None,
                )?;
                self.remember(now, key, reply.clone());
                Ok(Outcome::Reply(Reply { peer, bytes: reply }))
            }
        }
    }

    /// Complete an actual pending verification once. `Granted` means the
    /// integration has both verified the credential and checked current policy.
    /// This method rechecks time and trust/network binding, never mints a token.
    pub fn finish(
        &mut self,
        now: Instant,
        id: [u8; 16],
        current: Client<'_>,
        admission: Admission,
    ) -> Result<Reply, Error> {
        self.finish_with_reauthentication(now, id, current, admission, None)
    }

    /// Session attributes are included before response integrity and caching.
    /// Only an explicit successful admission may request AP reauthentication.
    pub fn finish_with_reauthentication(
        &mut self,
        now: Instant,
        id: [u8; 16],
        current: Client<'_>,
        admission: Admission,
        reauthenticate_seconds: Option<u32>,
    ) -> Result<Reply, Error> {
        if reauthenticate_seconds == Some(0) {
            return Err(Error::Configuration);
        }
        self.expire(now);
        let mut attempt = self.attempts.remove(&id).ok_or(Error::UnknownAttempt)?;
        let secret_tag: [u8; 32] = digest::digest(&digest::SHA256, current.secret)
            .as_ref()
            .try_into()
            .map_err(|_| Error::Binding)?;
        if attempt.binding != current.binding || !bool::from(attempt.secret_tag.ct_eq(&secret_tag))
        {
            return Err(Error::Binding);
        }
        let mut pending = attempt.pending.take().ok_or(Error::Protocol)?;
        pending.key.policy = current.policy_generation;
        let granted = admission == Admission::Granted;
        let msk = if granted {
            Some(attempt.tunnel.msk()?)
        } else {
            None
        };
        let bytes = wire::response_with_reauthentication(
            pending.radius_id,
            &pending.request_auth,
            &pending.secret,
            if granted { 2 } else { 3 },
            &wire::eap_terminal(pending.eap_id, granted),
            None,
            msk.as_ref().map(|m| m.as_slice()),
            if granted {
                reauthenticate_seconds
            } else {
                None
            },
        )?;
        let peer = pending.key.peer;
        self.remember(now, pending.key, bytes.clone());
        Ok(Reply { peer, bytes })
    }

    fn remember(&mut self, now: Instant, key: CacheKey, bytes: Vec<u8>) {
        if self.cache.len() >= self.limits.cached_replies {
            self.cache.pop_front();
        }
        self.cache.push_back(Cached {
            key,
            bytes,
            expires: now + self.limits.cache_lifetime,
        });
    }
}
