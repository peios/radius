//! Persist an opaque accounting reference and reserve limits before acceptance.
use super::authentication::{Auth, Work};
use crate::{
    config::Network,
    driver::{AdmissionContext, AdmissionExtras, Backend, Progress, Reason},
};
use peios::security::SidRef;
use peios_auth::{fields, Authenticated, Field};
use radius_accounting::{
    model::Grant,
    quota::{Balance, Dimension},
    worker::{now_ms, Completion},
};
use radius_core::Verification;
use radius_management::native::accounting::Service;
use std::{collections::HashMap, sync::mpsc::TryRecvError};

struct Pending {
    fingerprint: String,
    class: Vec<u8>,
    result: Completion<Vec<Balance>>,
}
pub struct AccountingAuth {
    auth: Auth,
    service: Service,
    pending: HashMap<[u8; 16], Pending>,
}
impl AccountingAuth {
    pub fn new(service: Service) -> Self {
        Self {
            auth: Auth,
            service,
            pending: HashMap::new(),
        }
    }
}
impl Backend for AccountingAuth {
    type Work = Work;
    type Subject = Authenticated;
    fn begin(&mut self, v: Verification) -> Result<Work, Reason> {
        self.auth.begin(v)
    }
    fn step(&mut self, w: &mut Work) -> Progress<Authenticated> {
        self.auth.step(w)
    }
    fn mschapv2_response(&mut self, w: &mut Work, r: &[u8; 40]) -> Result<(), Reason> {
        self.auth.mschapv2_response(w, r)
    }
    fn mschapv2_success(&self, s: &Authenticated) -> Option<[u8; 20]> {
        self.auth.mschapv2_success(s)
    }
    fn admission(&mut self, s: &Authenticated, id: &str, n: &Network) -> Result<(), Reason> {
        self.auth.admission(s, id, n)
    }
    fn identity<'a>(&self, s: &'a Authenticated) -> (&'a str, &'a [u8]) {
        self.auth.identity(s)
    }
    fn policy_facts(&self, s: &Authenticated) -> Result<radius_policy::Facts, Reason> {
        self.auth.policy_facts(s)
    }
    fn completed(&mut self, id: &[u8; 16]) {
        self.pending.remove(id);
    }
    fn accounting(
        &mut self,
        s: &Authenticated,
        c: AdmissionContext<'_>,
    ) -> Result<Option<AdmissionExtras>, Reason> {
        let snapshot = self.service.snapshot().ok_or(Reason::Accounting)?;
        if snapshot.config.fingerprint != c.saved_fingerprint {
            return Ok(None);
        }
        let policy = snapshot
            .config
            .policies
            .get(c.network_id)
            .ok_or(Reason::Accounting)?;
        let sid = SidRef::from_bytes(&s.identity.sid)
            .ok_or(Reason::MissingContext)?
            .to_string();
        let Some(Field::References(groups)) = s.identity.fields.get(&fields::GROUPS) else {
            return Err(Reason::MissingContext);
        };
        let groups = groups
            .iter()
            .map(|g| {
                SidRef::from_bytes(&g.sid)
                    .map(|s| s.to_string())
                    .ok_or(Reason::MissingContext)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let limited = snapshot.config.budgets.iter().any(|b| {
            (b.principal == sid || groups.contains(&b.principal))
                && b.policy.as_ref().is_none_or(|p| p == c.network_id)
        });
        let allow_outage = policy.allow_unavailable || (!policy.required && !limited);
        if !snapshot.config.settings.enabled {
            return if policy.required || limited {
                Err(Reason::Accounting)
            } else {
                Ok(Some(AdmissionExtras::default()))
            };
        }
        if !snapshot.ledger_ready || !self.service.ledger.snapshot().available {
            return if allow_outage {
                self.service.ledger.bypass();
                Ok(Some(AdmissionExtras::default()))
            } else {
                Err(Reason::Accounting)
            };
        }
        if self
            .pending
            .get(&c.id)
            .is_some_and(|p| p.fingerprint != snapshot.config.fingerprint)
        {
            self.pending.remove(&c.id);
        }
        if !self.pending.contains_key(&c.id) {
            let now = now_ms();
            let class = format!(
                "ra1:{}",
                radius_accounting::id().map_err(|_| Reason::Accounting)?
            )
            .into_bytes();
            let grant = Grant {
                reference: class.clone(),
                client: c.client_id.into(),
                policy: c.network_id.into(),
                sid,
                name: Some(s.identity.name.clone()),
                groups,
                station: c.station.map(Vec::from),
                issued_ms: now,
                expires_ms: now.saturating_add(
                    (snapshot.config.settings.summary_retention_seconds * 1000) as i64,
                ),
            };
            match self.service.ledger.grant(grant) {
                Ok(result) => {
                    self.pending.insert(
                        c.id,
                        Pending {
                            fingerprint: snapshot.config.fingerprint.clone(),
                            class,
                            result,
                        },
                    );
                }
                Err(_) => {
                    return if allow_outage {
                        self.service.ledger.bypass();
                        Ok(Some(AdmissionExtras::default()))
                    } else {
                        Err(Reason::Accounting)
                    }
                }
            }
        }
        let pending = self.pending.get(&c.id).unwrap();
        match pending.result.try_recv() {
            Err(TryRecvError::Empty) => Ok(None),
            Ok(Ok(balances)) => {
                let timeout = balances
                    .iter()
                    .filter(|b| {
                        matches!(
                            b.budget.dimension,
                            Dimension::TotalSessionTime | Dimension::ConnectedTime
                        )
                    })
                    .map(|b| (b.remaining / 1000).max(1).min(u32::MAX as u64) as u32)
                    .min();
                Ok(Some(AdmissionExtras {
                    class: Some(pending.class.clone()),
                    timeout_seconds: timeout,
                }))
            }
            Ok(Err(radius_accounting::Error::Configuration(message)))
                if message == "principal allowance exhausted" =>
            {
                Err(Reason::Quota)
            }
            _ => {
                if allow_outage {
                    self.service.ledger.bypass();
                    Ok(Some(AdmissionExtras::default()))
                } else {
                    Err(Reason::Accounting)
                }
            }
        }
    }
}
