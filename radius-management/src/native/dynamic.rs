//! Reconciliation is deliberately outside the EAP and UDP packet loops.
use super::accounting::{Service, Snapshot};
use crate::dynamic::Evaluation;
use radius_accounting::{
    dynamic::{Action, Intent, Reconciliation},
    model::Session,
    store::Filter,
    worker::{self, View},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub type Evaluator = dyn Fn(&[Session]) -> Vec<Evaluation> + Send + Sync;
#[derive(Clone)]
pub struct Authority {
    pub revision: String,
    pub evaluate: Arc<Evaluator>,
}
pub fn start(service: Service) -> std::io::Result<()> {
    let hints = service.clone();
    std::thread::Builder::new()
        .name("radius-identity-hints".into())
        .spawn(move || {
            let mut previous = None;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                if !hints.snapshot().is_some_and(|s| {
                    s.config.dynamic.settings.enabled && s.config.dynamic.settings.event_hints
                }) {
                    continue;
                }
                // Reads use the ordinary service token. Omission or failure does
                // not establish that an account changed or ceased to exist.
                if let Ok(Some(stamp)) = super::diagnostics::identity_change_hint() {
                    if previous != Some(stamp) {
                        previous = Some(stamp);
                        hints.changed();
                    }
                }
            }
        })?;
    std::thread::Builder::new()
        .name("radius-session-control".into())
        .spawn(move || {
            let mut revision = String::new();
            let mut after = None;
            let mut next = Instant::now();
            let mut hint = service.hint();
            loop {
                std::thread::sleep(Duration::from_millis(100));
                let Some(snapshot) = service.snapshot() else {
                    continue;
                };
                let Some(authority) = service.authority() else {
                    continue;
                };
                let settings = &snapshot.config.dynamic.settings;
                if !settings.enabled
                    || !snapshot.ledger_ready
                    || !service.ledger.snapshot().available
                    || authority.revision != snapshot.config.fingerprint
                {
                    continue;
                }
                if revision != authority.revision {
                    revision = authority.revision.clone();
                    hint = service.hint();
                    after = None;
                    next = Instant::now();
                }
                if hint != service.hint() {
                    hint = service.hint();
                    next = Instant::now();
                }
                if Instant::now() < next {
                    continue;
                }
                let began = Instant::now();
                let page = service
                    .ledger
                    .page(
                        Filter {
                            after: after.clone(),
                            active_only: true,
                            limit: settings.batch_size,
                            ..Default::default()
                        },
                        View {
                            all: true,
                            ..Default::default()
                        },
                    )
                    .and_then(worker::wait);
                let Ok(page) = page else {
                    next = Instant::now() + Duration::from_secs(1);
                    continue;
                };
                let results = (authority.evaluate)(&page.sessions);
                for (session, evaluation) in page.sessions.iter().zip(results) {
                    if service.authority().is_none_or(|a| a.revision != revision) {
                        break;
                    }
                    if let Err(error) = reconcile(&service, &snapshot, session, evaluation) {
                        eprintln!("radiusd: session reconciliation deferred: {error}");
                    }
                    after = Some(session.id.clone());
                    if began.elapsed() >= Duration::from_millis(u64::from(settings.budget_ms)) {
                        break;
                    }
                }
                if (after == page.sessions.last().map(|s| s.id.clone()) && page.next.is_none())
                    || page.sessions.is_empty()
                {
                    after = None;
                    next =
                        Instant::now() + Duration::from_secs(u64::from(settings.interval_seconds));
                }
            }
        })?;
    Ok(())
}
pub(super) fn reconcile(
    service: &Service,
    snapshot: &Snapshot,
    session: &Session,
    evaluation: Evaluation,
) -> radius_accounting::Result<()> {
    let now = worker::now_ms();
    let Some(policy) = session
        .policy
        .as_ref()
        .and_then(|p| snapshot.config.dynamic.policies.get(p))
    else {
        return Ok(());
    };
    let mut state = worker::wait(service.ledger.reconciliation(session.id.clone())?)?;
    if state.proof
        != session
            .proof
            .as_ref()
            .map(|p| p.grant.clone())
            .unwrap_or_default()
    {
        state = Reconciliation::default();
    }
    state.proof = session
        .proof
        .as_ref()
        .map(|p| p.grant.clone())
        .unwrap_or_default();
    state.configuration = snapshot.config.fingerprint.clone();
    state.checked_ms = now;
    state.observed = session.observed.clone();
    state.requested = worker::wait(service.ledger.command_history(session.id.clone())?)?
        .into_iter()
        .find(|c| {
            c.state == "acknowledged"
                && c.action == Action::UpdateAuthorization
                && c.proof == state.proof
        })
        .and_then(|c| c.desired);
    let mut selected = None;
    let mut reason = String::new();
    let authoritative = !matches!(evaluation, Evaluation::Unavailable(_));
    match evaluation {
        Evaluation::Unavailable(error) => {
            let since = *state.unavailable_since_ms.get_or_insert(now);
            state.status = format!("pending: {}", error.chars().take(200).collect::<String>());
            state.desired = None;
            if policy
                .unavailable_grace_seconds
                .is_some_and(|s| now.saturating_sub(since) >= i64::from(s) * 1000)
            {
                selected = Some(Action::Disconnect);
                reason = "reevaluation-unavailable-grace-expired".into();
            }
        }
        Evaluation::Denied | Evaluation::Disabled | Evaluation::Deleted => {
            state.unavailable_since_ms = None;
            state.desired = None;
            state.status = "access-revoked".into();
            if policy.revoke_access {
                selected = Some(Action::Disconnect);
                reason = "access-revoked".into();
            }
        }
        Evaluation::Granted {
            desired,
            credentials,
        } => {
            state.unavailable_since_ms = None;
            state.desired = Some(desired.clone());
            state.status = "current".into();
            if let Some(proof) = &session.proof {
                let changed = credentials
                    .as_ref()
                    .filter(|_| !proof.credentials.is_empty())
                    .is_some_and(|current| {
                        proof
                            .credentials
                            .iter()
                            .any(|proved| !current.contains(proved))
                    });
                if changed && policy.password_reauthenticate {
                    selected = Some(Action::Reauthenticate);
                    // Stable identity revision, independent of missed events.
                    let mut bindings = credentials.clone().unwrap_or_default();
                    bindings.sort_by_key(|b| (b.reference, b.revision));
                    let bytes = serde_json::to_vec(&bindings)?;
                    reason = format!(
                        "credential-changed:{}",
                        radius_accounting::hex(
                            ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()
                        )
                    );
                } else if policy.password_reauthenticate
                    && (proof.credentials.is_empty() || credentials.is_none())
                {
                    state.status = "credential-status-unknown".into();
                }
                if desired.vlan != proof.issued.vlan && policy.vlan_disconnect {
                    selected = Some(Action::Disconnect);
                    reason = format!("vlan-changed:{:?}", desired.vlan);
                } else if selected.is_none()
                    && policy.update_authorization
                    && (desired.vlan != proof.issued.vlan
                        || snapshot
                            .config
                            .policies
                            .get(session.policy.as_deref().unwrap_or_default())
                            .is_some_and(|p| {
                                p.reauthenticate_seconds != proof.configured_timeout_seconds
                            }))
                    && state.requested.as_ref() != Some(&desired)
                {
                    selected = Some(Action::UpdateAuthorization);
                    reason = "authorization-changed".into();
                }
            } else {
                state.status = "authorization-baseline-unknown".into();
            }
        }
    }
    if session.sid.is_none() || radius_accounting::dynamic::Target::from_session(session).is_err() {
        selected = None;
        state.status = "unmanageable: missing verified identity or precise selectors".into();
    }
    if selected.is_some() || authoritative {
        let signature = if let Some(action) = selected {
            let profile = snapshot.config.dynamic.profile(&session.client);
            let fallback = fallback_after(action, &policy.fallback);
            let mut actions = vec![action];
            actions.extend(&fallback);
            let recipes: Vec<_> = actions
                .iter()
                .map(|a| profile.recipes.iter().find(|r| r.action == *a))
                .collect();
            let update = actions.contains(&Action::UpdateAuthorization);
            let configured_timeout = update.then(|| {
                snapshot
                    .config
                    .policies
                    .get(session.policy.as_deref().unwrap_or_default())
                    .map(|p| p.reauthenticate_seconds)
            });
            let vlan = update.then(|| state.desired.as_ref().and_then(|d| d.vlan));
            let clear = update.then_some(&profile.clear_vlan);
            let bytes = serde_json::to_vec(&(
                action,
                &reason,
                &fallback,
                recipes,
                profile.station_selector,
                profile.require_station,
                vlan,
                configured_timeout,
                clear,
            ))?;
            radius_accounting::hex(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref())
        } else {
            String::new()
        };
        if signature != state.intent_signature {
            state.intent_epoch = state
                .intent_epoch
                .checked_add(1)
                .ok_or(radius_accounting::Error::Limit)?;
            state.intent_signature = signature;
        }
    }
    if let Some(action) = selected {
        let fallback = fallback_after(action, &policy.fallback);
        let command = worker::wait(service.ledger.dynamic(Intent {
            intent_key: format!("{}:{}", state.intent_epoch, state.intent_signature),
            request_id: None,
            session: session.id.clone(),
            actor: "radiusd".into(),
            reason,
            action,
            configuration: snapshot.config.fingerprint.clone(),
            desired: state.desired.clone(),
            fallback,
        })?)?;
        state.status = format!("{:?}: {}", command.action, command.state);
    }
    worker::wait(service.ledger.reconciled(session.id.clone(), state)?)?;
    Ok(())
}
pub fn fallback_after(action: Action, configured: &[Action]) -> Vec<Action> {
    configured
        .iter()
        .copied()
        .filter(|next| match action {
            Action::UpdateAuthorization => *next != action,
            Action::Reauthenticate => *next == Action::Disconnect,
            Action::Disconnect => false,
        })
        .collect()
}
