//! Fresh SID-based policy reads. These lookups never authenticate or advance proof.
use super::authentication::{evaluate_record, policy_facts_record};
use crate::{config::Config, driver::Reason};
use peios::security::Sid;
use peios_auth::{ClaimCoverage, Field, IdentityKind, Key, Record, fields};
use radius_accounting::{
    dynamic::{Authorization, CredentialBinding},
    model::Session,
};
use radius_management::{
    dynamic::Evaluation,
    native::{accounting::Service, dynamic::Authority},
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

enum Current {
    Found(Record),
    Deleted,
    Unavailable,
}
fn lookup(sid: &str, timeout: u32) -> Current {
    let Ok(sid) = sid.parse::<Sid>() else {
        return Current::Unavailable;
    };
    let result = (|| {
        let client = peios_auth::Client::with_options(peios_auth::Options {
            reply_timeout_ms: u64::from(timeout),
            ..Default::default()
        })
        .ok()?;
        let mut operation = client
            .lookup(
                Key::Sid(sid.as_ref().as_bytes()),
                IdentityKind::Principal,
                fields::ENABLED | fields::GROUPS | fields::CLAIMS | fields::CREDENTIAL_BINDINGS,
            )
            .ok()?;
        operation.wait().ok()?;
        operation.identity().ok()
    })();
    match result {
        Some(mut identity)
            if identity.outcome == 1
                && identity.records.len() == 1
                && identity.incomplete_sources.is_empty() =>
        {
            let record = identity.records.remove(0);
            if record.sid != sid.as_ref().as_bytes() || record.kind != 1 {
                Current::Unavailable
            } else {
                Current::Found(record)
            }
        }
        Some(identity) if identity.outcome == 2 && identity.incomplete_sources.is_empty() => {
            Current::Deleted
        }
        _ => Current::Unavailable,
    }
}
pub fn publish(service: &Service, config: Arc<Config>) {
    let revision = config.saved_fingerprint.clone();
    let Some(snapshot) = service
        .snapshot()
        .filter(|s| s.config.fingerprint == revision)
    else {
        // The accounting watcher may still be activating this revision. The
        // main loop calls publish again once both independently prepared views
        // agree, never from merely saved Registry data.
        return;
    };
    let timeout = snapshot.config.dynamic.settings.identity_timeout_ms;
    let budget = snapshot.config.dynamic.settings.budget_ms;
    let ledger = service.ledger.clone();
    service.publish_authority(Some(Authority {
        revision,
        evaluate: Arc::new(move |sessions| {
            let began = Instant::now();
            let mut current = BTreeMap::new();
            let mut results = Vec::with_capacity(sessions.len());
            for session in sessions {
                if !results.is_empty()
                    && began.elapsed() >= Duration::from_millis(u64::from(budget))
                {
                    break;
                }
                let Some(sid) = &session.sid else {
                    results.push(Evaluation::Unavailable("verified SID unavailable".into()));
                    continue;
                };
                let record = current
                    .entry(sid.clone())
                    .or_insert_with(|| lookup(sid, timeout));
                let mut evaluation = match record {
                    Current::Deleted => Evaluation::Deleted,
                    Current::Unavailable => {
                        Evaluation::Unavailable("identity authority unavailable".into())
                    }
                    Current::Found(record) => evaluate(&config, session, record),
                };
                if let Evaluation::Granted { desired, .. } = &mut evaluation {
                    // CoA cannot extend a connection past current shared time
                    // allowances. Use current group facts, never historical quota
                    // attribution, without rewriting the accounting history.
                    let mut subject = crate::native::dynamic::usage_subject(session, record);
                    subject.reference = session
                        .proof
                        .as_ref()
                        .map(|p| p.grant.clone())
                        .unwrap_or_default();
                    match ledger
                        .balances(subject)
                        .and_then(radius_accounting::worker::wait)
                    {
                        Ok(balances) => {
                            for balance in balances.iter().filter(|b| {
                                matches!(
                                    b.budget.dimension,
                                    radius_accounting::quota::Dimension::TotalSessionTime
                                        | radius_accounting::quota::Dimension::ConnectedTime
                                )
                            }) {
                                desired.timeout_seconds = desired
                                    .timeout_seconds
                                    .min((balance.remaining / 1000).clamp(1, u64::from(u32::MAX))
                                        as u32);
                            }
                        }
                        Err(_) => {
                            evaluation =
                                Evaluation::Unavailable("current allowance unavailable".into())
                        }
                    }
                }
                results.push(evaluation);
            }
            results
        }),
    }));
}
fn evaluate(config: &Config, session: &Session, record: &mut Record) -> Evaluation {
    let unavailable = || Evaluation::Unavailable("identity or policy context unavailable".into());
    match record.fields.get(&fields::ENABLED) {
        Some(Field::Number(0)) => return Evaluation::Disabled,
        Some(Field::Number(1)) => {}
        _ => return unavailable(),
    }
    let Some(client) = config
        .client(session.source)
        .filter(|c| c.enabled && c.name == session.client)
    else {
        return Evaluation::Denied;
    };
    let Some((policy, network)) = session
        .policy
        .as_ref()
        .and_then(|id| config.networks.get(id).map(|n| (id, n)))
        .filter(|(id, n)| n.enabled && client.networks.contains(id))
    else {
        return Evaluation::Denied;
    };
    let coverage = if matches!(record.fields.get(&fields::CLAIMS), Some(Field::Claims(_))) {
        ClaimCoverage::Complete
    } else {
        ClaimCoverage::Filtered
    };
    // Withheld values cannot establish absence. Filtered coverage preserves
    // that unknown even for policies whose decision needs no such claim.
    let missing_claims = !matches!(record.fields.get(&fields::CLAIMS), Some(Field::Claims(_)));
    if missing_claims {
        record.fields.insert(fields::CLAIMS, Field::Claims(vec![]));
    }
    let result = (|| {
        evaluate_record(record, coverage, &[], policy, network, false)?;
        let mut facts = policy_facts_record(record, coverage, &[])?;
        use radius_policy::Scalar;
        facts.insert(
            "Client.Id".into(),
            vec![Scalar::String(client.name.clone())],
        );
        facts.insert(
            "Client.Address".into(),
            vec![Scalar::Address(session.source)],
        );
        facts.insert(
            "Request.SSID".into(),
            vec![Scalar::String(
                String::from_utf8(network.ssid.clone()).map_err(|_| Reason::MissingContext)?,
            )],
        );
        if let Some(mac) = session
            .station
            .as_deref()
            .and_then(radius_policy::station_mac)
        {
            facts.insert("Request.Station".into(), vec![Scalar::Mac(mac)]);
        }
        let explanation = network
            .access
            .explain(&facts)
            .map_err(|_| Reason::MissingContext)?;
        let assignment = match explanation.assignment {
            Some(value) => value,
            None if matches!(
                explanation.outcome.as_str(),
                "rejected" | "profile-disabled"
            ) && explanation.winner.is_some() =>
            {
                return Err(Reason::Policy);
            }
            None if explanation.outcome == "backstop"
                && coverage == ClaimCoverage::Complete
                && facts.unknown_claims.is_empty() =>
            {
                return Err(Reason::Policy);
            }
            None => return Err(Reason::MissingContext),
        };
        let credentials = match record.fields.get(&fields::CREDENTIAL_BINDINGS) {
            Some(Field::CredentialBindings(bindings)) => Some(
                bindings
                    .iter()
                    .map(|b| CredentialBinding {
                        reference: b.reference,
                        revision: b.revision,
                    })
                    .collect(),
            ),
            _ => None,
        };
        Ok(Evaluation::Granted {
            desired: Authorization {
                vlan: assignment.vlan,
                timeout_seconds: network.reauthenticate_seconds,
            },
            credentials,
        })
    })();
    if missing_claims {
        record.fields.remove(&fields::CLAIMS);
    }
    match result {
        Ok(v) => v,
        Err(Reason::Policy) => Evaluation::Denied,
        Err(_) => unavailable(),
    }
}
fn usage_subject(session: &Session, current: &Current) -> radius_accounting::model::Grant {
    let mut grant = radius_management::accounting::usage_subject(
        session.sid.as_deref().unwrap_or_default(),
        session.policy.as_deref().unwrap_or_default(),
    );
    if let Current::Found(record) = current {
        if let Some(Field::References(groups)) = record.fields.get(&fields::GROUPS) {
            grant.groups = groups
                .iter()
                .filter_map(|g| peios::security::SidRef::from_bytes(&g.sid).map(|s| s.to_string()))
                .collect();
        }
    }
    grant
}
