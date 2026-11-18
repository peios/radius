//! Bounded, credential-free milestones for an active conversation.
use crate::{
    config::{Config, Network},
    driver::Output,
};
use radius_management::diagnostics::{hex, Record, Settings, ATTEMPT, OPERATION, SEQUENCE, STAGE};
use serde_json::Value;
use std::{net::SocketAddr, time::Instant};

pub(crate) struct Trace {
    pub(crate) fields: Record,
    pub(crate) last: &'static str,
    pub(crate) failure: Option<&'static str>,
    pub(crate) tls_ready: bool,
    pub(crate) method: &'static str,
    started: Instant,
    sequence: u64,
    emitted: u32,
    settings: Settings,
    seen: std::collections::BTreeMap<&'static str, (String, String, String)>,
}
pub(crate) struct Context<'a> {
    pub id: &'a [u8; 16],
    pub peer: SocketAddr,
    pub listener: Option<SocketAddr>,
    pub client: &'a str,
    pub network: &'a str,
    pub policy: &'a Network,
    pub config: &'a Config,
    pub now: Instant,
}
impl Trace {
    pub(crate) fn new(context: Context<'_>) -> Self {
        let Context {
            id,
            peer,
            listener,
            client,
            network,
            policy: n,
            config: c,
            now,
        } = context;
        let mut fields = Record::new();
        for (key, value) in [
            (ATTEMPT, hex(id)),
            ("source.address", peer.ip().to_string()),
            ("object.radiusd.client.configuration-id", client.into()),
            ("object.radiusd.network.configuration-id", network.into()),
            ("object.radiusd.config.fingerprint", hex(&c.fingerprint)),
            (
                "object.radiusd.config.saved-fingerprint",
                c.saved_fingerprint.clone(),
            ),
        ] {
            fields.insert(key.into(), value.into());
        }
        if let Some(listener) = listener {
            fields.insert(
                "object.radiusd.listener".into(),
                listener.to_string().into(),
            );
        }
        if let Some(profile) = &n.authentication_profile {
            fields.insert(
                "object.radiusd.authentication-profile.id".into(),
                profile.clone().into(),
            );
        }
        for (collection, id, field) in [
            ("Clients", Some(client), "object.radiusd.client.name"),
            (
                "AccessPolicies",
                Some(network),
                "object.radiusd.network.name",
            ),
            (
                "AuthenticationProfiles",
                n.authentication_profile.as_deref(),
                "object.radiusd.authentication-profile.name",
            ),
        ] {
            if let Some(label) = id.and_then(|id| c.labels.get(&format!("{collection}/{id}"))) {
                fields.insert(field.into(), label.clone().into());
            }
        }
        Self {
            fields,
            last: "started",
            failure: None,
            tls_ready: false,
            method: n.methods[0].name(),
            started: now,
            sequence: 0,
            emitted: 0,
            settings: c.diagnostics.clone(),
            seen: Default::default(),
        }
    }
    pub(crate) fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.fields.insert(key.into(), value.into());
    }
    pub(crate) fn authority(&mut self, id: Option<[u8; 16]>) {
        if let Some(id) = id {
            self.set(OPERATION, hex(&id));
        } else {
            self.fields.remove(OPERATION);
        }
    }
    pub(crate) fn stage(&mut self, stage: &'static str, result: &str, output: &mut impl Output) {
        let fingerprint = self
            .fields
            .get("object.radiusd.config.fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let key = (result.to_owned(), fingerprint, self.method.to_owned());
        if self.seen.get(stage) == Some(&key) {
            return;
        }
        self.seen.insert(stage, key);
        self.last = stage;
        self.sequence = self.sequence.saturating_add(1);
        self.set(STAGE, stage);
        self.set(SEQUENCE, self.sequence);
        self.set("object.radiusd.progress.result", result);
        let success = !matches!(result, "failed" | "refused");
        self.set("outcome.success", success);
        if success {
            self.fields.remove("outcome.reason");
            self.fields.remove("outcome.detail");
        }
        self.set("object.radiusd.method", self.method);
        self.set(
            "object.radiusd.elapsed-ms",
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        );
        if self.emitted < self.settings.get("MaxStages") {
            self.emitted += 1;
            output.progress(&self.fields);
        } else {
            self.set("object.radiusd.diagnostics.truncated", true);
        }
    }
    pub(crate) fn terminal(&self, reason: crate::driver::Reason) -> Record {
        use crate::driver::Reason;
        let mut fields = self.fields.clone();
        fields.insert(SEQUENCE.into(), (self.sequence + 1).into());
        fields.insert(STAGE.into(), "completed".into());
        fields.insert("object.radiusd.last-stage".into(), self.last.into());
        fields.insert("object.radiusd.method".into(), self.method.into());
        fields.insert(
            "object.radiusd.elapsed-ms".into(),
            (self.started.elapsed().as_millis().min(u64::MAX as u128) as u64).into(),
        );
        if let Some(reason) = self.failure {
            fields.insert("outcome.reason".into(), reason.into());
        }
        fields.insert("outcome.success".into(), (reason == Reason::Granted).into());
        fields.insert(
            "object.radiusd.progress.result".into(),
            reason.name().into(),
        );
        fields.insert(
            "object.radiusd.reply".into(),
            match reason {
                Reason::Granted => "accept-submitted",
                Reason::Undelivered => "send-failed",
                Reason::Timeout | Reason::Binding => "none",
                _ => "reject-submitted",
            }
            .into(),
        );
        if reason != Reason::Granted && !(reason == Reason::Protocol && self.failure.is_some()) {
            fields.insert("outcome.reason".into(), reason.name().into());
        }
        fields
    }
}
