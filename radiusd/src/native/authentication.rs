use crate::{
    config::{CONNECT, Network},
    driver::{Backend, Progress, Reason},
};
use peios::{
    access::{
        AccessCheck, AuditContext, AuditValue, ClaimCoverage, SubjectAccessDecision, SubjectGroup,
        SuppliedClaims, SuppliedSubject,
    },
    security::{AccessMask, GenericMapping, SecurityDescriptor, Sid, SidRef},
    token::{Claim, ClaimAttr, ClaimValues},
};
use peios_auth::{
    Answer, AuthenticateRequest, Authenticated, AuthenticationRequest, Capabilities,
    ClaimSelection, ClaimValue, Field, Operation, fields,
};
use radius_core::{Credential, Verification};
use zeroize::Zeroizing;

pub struct Auth;
pub struct Work {
    operation: Operation,
    password: Option<Zeroizing<Vec<u8>>>,
    mschapv2: bool,
    challenge_round: Option<(u64, u32)>,
    answered: bool,
}
impl Drop for Work {
    fn drop(&mut self) {
        self.operation.cancel();
    }
}

impl Backend for Auth {
    type Work = Work;
    type Subject = Authenticated;
    fn operation_guid(&self, work: &Work) -> Option<[u8; 16]> {
        work.operation.operation_guid()
    }
    fn begin(&mut self, verification: Verification) -> Result<Work, Reason> {
        let username = std::str::from_utf8(&verification.credentials.username)
            .map_err(|_| Reason::Credentials)?;
        if username.contains('\0') {
            return Err(Reason::Credentials);
        }
        let client = peios_auth::Client::new().map_err(|_| Reason::Backend)?;
        let (password, mschapv2, capabilities, kind) = match verification.credentials.proof {
            Credential::Password(password) => (Some(password), false, Capabilities::PASSWORD, 1),
            Credential::Mschapv2 => (None, true, Capabilities::MSCHAPV2, 3),
        };
        let operation = client
            .authenticate(AuthenticateRequest {
                authentication: AuthenticationRequest {
                    username,
                    supported_credentials: capabilities,
                    required_credential_type: Some(kind),
                    ssh_binding: None,
                },
                groups: true,
                claims: ClaimSelection::AllPermitted,
            })
            .map_err(|_| Reason::Backend)?;
        Ok(Work {
            operation,
            password,
            mschapv2,
            challenge_round: None,
            answered: false,
        })
    }
    fn step(&mut self, work: &mut Work) -> Progress<Authenticated> {
        if work.challenge_round.is_some() {
            return Progress::Waiting;
        }
        // One bounded transition per driver tick, regardless of peer behavior.
        match work.operation.step() {
            Ok(peios_auth::Progress::Wait) => Progress::Waiting,
            Ok(peios_auth::Progress::Prompt) => {
                if work.mschapv2 {
                    let challenge = (|| {
                        let round = work.operation.round().map_err(|_| Reason::Backend)?;
                        if round.prompts.len() != 1 || work.answered {
                            return Err(Reason::Credentials);
                        }
                        let prompt = &round.prompts[0];
                        if prompt.credential_type != 3 {
                            return Err(Reason::Credentials);
                        }
                        let challenge: [u8; 16] = prompt
                            .parameters
                            .as_slice()
                            .try_into()
                            .map_err(|_| Reason::Credentials)?;
                        work.challenge_round = Some((round.id, prompt.credential_ref));
                        Ok(challenge)
                    })();
                    return match challenge {
                        Ok(challenge) => Progress::Mschapv2Challenge(challenge),
                        Err(reason) => Progress::Failed(reason),
                    };
                }
                let answer = (|| {
                    let round = work.operation.round().map_err(|_| Reason::Backend)?;
                    if round.prompts.len() != 1 {
                        return Err(Reason::Credentials);
                    }
                    let prompt = &round.prompts[0];
                    if prompt.credential_type != 1
                        || !prompt.secret
                        || !prompt.parameters.is_empty()
                    {
                        return Err(Reason::Credentials);
                    }
                    let password = work.password.take().ok_or(Reason::Credentials)?;
                    work.answered = true;
                    // libauth copies answers to its bounded outgoing buffer in
                    // respond; this retained password is erased on every exit.
                    work.operation
                        .respond(
                            round.id,
                            &[Answer {
                                credential_ref: prompt.credential_ref,
                                data: &password,
                            }],
                        )
                        .map_err(|_| Reason::Backend)
                })();
                match answer {
                    Ok(()) => Progress::Waiting,
                    Err(reason) => Progress::Failed(reason),
                }
            }
            Ok(peios_auth::Progress::Complete) => match work.operation.authenticated() {
                Ok(subject)
                    if subject.verified_credentials.0
                        == if work.mschapv2 {
                            Capabilities::MSCHAPV2.0
                        } else {
                            Capabilities::PASSWORD.0
                        }
                        && subject.mschapv2_authenticator_response.is_some() == work.mschapv2
                        && work.answered =>
                {
                    Progress::Complete(subject)
                }
                _ => Progress::Failed(Reason::Credentials),
            },
            Err(error) => Progress::Failed(authentication_failure(&error)),
        }
    }
    fn mschapv2_response(&mut self, work: &mut Work, response: &[u8; 40]) -> Result<(), Reason> {
        let (round, credential_ref) = work.challenge_round.take().ok_or(Reason::Credentials)?;
        if !work.mschapv2 || work.answered {
            return Err(Reason::Credentials);
        }
        work.answered = true;
        work.operation
            .respond(
                round,
                &[Answer {
                    credential_ref,
                    data: response,
                }],
            )
            .map_err(|_| Reason::Backend)
    }
    fn mschapv2_success(&self, subject: &Authenticated) -> Option<[u8; 20]> {
        subject.mschapv2_authenticator_response
    }
    fn admission(
        &mut self,
        identity: &Authenticated,
        network_id: &str,
        network: &Network,
    ) -> Result<(), Reason> {
        evaluate(identity, network_id, network)
    }
    fn identity<'a>(&self, subject: &'a Authenticated) -> (&'a str, &'a [u8]) {
        (&subject.identity.name, &subject.identity.sid)
    }
    fn policy_facts(&self, subject: &Authenticated) -> Result<radius_policy::Facts, Reason> {
        policy_facts(subject)
    }
}

fn authentication_failure(error: &peios_auth::Error) -> Reason {
    // peios/auth.h: category 6 is PGSS_DENIAL; category 1 is UNAVAILABLE.
    // PGSS AuthenticationFailed (4) includes unknown accounts and bad proofs;
    // AccountRestricted (6) uses the same public label to avoid distinguishing
    // account state. Other denials and client failures describe the authority
    // path, not a bad credential. Never classify from its free-form message.
    match (error.category, error.code) {
        (6, 4 | 6) => Reason::Credentials,
        _ => Reason::Backend,
    }
}

fn policy_facts(identity: &Authenticated) -> Result<radius_policy::Facts, Reason> {
    policy_facts_record(
        &identity.identity,
        identity.claim_coverage,
        &identity.absent_claims,
    )
}
pub(super) fn policy_facts_record(
    identity: &peios_auth::Record,
    coverage: peios_auth::ClaimCoverage,
    absent: &[String],
) -> Result<radius_policy::Facts, Reason> {
    use radius_policy::{Facts, Scalar};
    let sid = |b: &[u8]| {
        SidRef::from_bytes(b)
            .map(|s| Scalar::Sid(s.to_string()))
            .ok_or(Reason::MissingContext)
    };
    let mut facts = Facts::new();
    facts.claim_coverage = match coverage {
        peios_auth::ClaimCoverage::Complete => radius_policy::ClaimCoverage::Complete,
        peios_auth::ClaimCoverage::Filtered => radius_policy::ClaimCoverage::Filtered,
        _ => return Err(Reason::MissingContext),
    };
    facts.absent_claims = absent
        .iter()
        .map(|n| radius_policy::claim_name(n))
        .collect();
    facts.insert("Subject.User".into(), vec![sid(&identity.sid)?]);
    facts.insert(
        "Subject.Name".into(),
        vec![Scalar::String(identity.name.clone())],
    );
    let Some(Field::References(groups)) = identity.fields.get(&fields::GROUPS) else {
        return Err(Reason::MissingContext);
    };
    facts.insert(
        "Subject.Group".into(),
        groups
            .iter()
            .map(|g| sid(&g.sid))
            .collect::<Result<_, _>>()?,
    );
    let Some(Field::Claims(claims)) = identity.fields.get(&fields::CLAIMS) else {
        return Err(Reason::MissingContext);
    };
    for raw in claims {
        let claim = convert_claim(raw)?;
        // Like PNP's enabled-group facts, assignment facts must never turn
        // disabled or deny-only authority data into grant-eligible values.
        if claim
            .flags
            .intersects(ClaimAttr::DISABLED | ClaimAttr::USE_FOR_DENY_ONLY)
        {
            facts
                .unknown_claims
                .insert(radius_policy::claim_name(&claim.name));
            continue;
        }
        let values = match claim.values {
            ClaimValues::Int64(v) => v.into_iter().map(Scalar::Int64).collect(),
            ClaimValues::Uint64(v) => v.into_iter().map(Scalar::Uint64).collect(),
            ClaimValues::Boolean(v) => v.into_iter().map(Scalar::Boolean).collect(),
            ClaimValues::String(v) => v.into_iter().map(Scalar::String).collect(),
            ClaimValues::Sid(v) => v.into_iter().map(|s| Scalar::Sid(s.to_string())).collect(),
            ClaimValues::Octet(v) => v.into_iter().map(Scalar::Octet).collect(),
        };
        if facts
            .insert(format!("Subject.Claim.{}", claim.name), values)
            .is_some()
        {
            return Err(Reason::MissingContext);
        }
    }
    Ok(facts)
}

pub fn evaluate(
    identity: &Authenticated,
    network_id: &str,
    network: &Network,
) -> Result<(), Reason> {
    evaluate_record(
        &identity.identity,
        identity.claim_coverage,
        &identity.absent_claims,
        network_id,
        network,
        true,
    )
}
pub(super) fn evaluate_record(
    identity: &peios_auth::Record,
    coverage: peios_auth::ClaimCoverage,
    absent_claims: &[String],
    network_id: &str,
    network: &Network,
    audit: bool,
) -> Result<(), Reason> {
    let sd = SecurityDescriptor::from_validated_bytes(network.security.clone())
        .map_err(|_| Reason::Policy)?;
    let user = SidRef::from_bytes(&identity.sid).ok_or(Reason::MissingContext)?;
    let Some(Field::References(memberships)) = identity.fields.get(&fields::GROUPS) else {
        return Err(Reason::MissingContext);
    };
    let groups = memberships
        .iter()
        .map(|group| {
            Ok(SubjectGroup {
                sid: SidRef::from_bytes(&group.sid).ok_or(Reason::MissingContext)?,
                attributes: 4,
            })
        })
        .collect::<Result<Vec<_>, Reason>>()?;
    let Some(Field::Claims(claims)) = identity.fields.get(&fields::CLAIMS) else {
        return Err(Reason::MissingContext);
    };
    let claims = claims
        .iter()
        .map(convert_claim)
        .collect::<Result<Vec<_>, _>>()?;
    let coverage = match coverage {
        peios_auth::ClaimCoverage::Complete => ClaimCoverage::Complete,
        peios_auth::ClaimCoverage::Filtered => ClaimCoverage::Partial,
        _ => return Err(Reason::MissingContext),
    };
    let absent: Vec<_> = absent_claims.iter().map(String::as_str).collect();
    let subject = SuppliedSubject {
        user: Some(user),
        groups: Some(&groups),
        user_claims: Some(SuppliedClaims {
            values: &claims,
            absent: &absent,
            coverage,
        }),
        ..Default::default()
    };
    let mapping = GenericMapping::new(CONNECT, 0, CONNECT, CONNECT);
    // This display label never selects policy; binding uses the original bytes.
    let ssid = String::from_utf8_lossy(&network.ssid);
    let context = AuditContext::new(
        "network",
        &[("id", network_id.into()), ("ssid", AuditValue::Str(&ssid))],
    )
    .map_err(|_| Reason::AccessCheck)?;
    match AccessCheck::new(&sd, AccessMask::from_bits_retain(CONNECT), mapping)
        .audit_context(&context)
        .subject_no_audit(!audit)
        .check_subject(&subject)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EOPNOTSUPP) => Reason::KernelUnsupported,
            _ => Reason::AccessCheck,
        })? {
        SubjectAccessDecision::Granted { .. } => Ok(()),
        SubjectAccessDecision::Denied { .. } => Err(Reason::Policy),
        SubjectAccessDecision::MissingContext { .. } => Err(Reason::MissingContext),
    }
}
fn convert_claim(claim: &peios_auth::Claim) -> Result<Claim, Reason> {
    let bad = || Reason::MissingContext;
    let values = match claim.value_type {
        1 => ClaimValues::Int64(
            claim
                .values
                .iter()
                .map(|v| match v {
                    ClaimValue::Signed(v) => Ok(*v),
                    _ => Err(bad()),
                })
                .collect::<Result<_, _>>()?,
        ),
        2 => ClaimValues::Uint64(
            claim
                .values
                .iter()
                .map(|v| match v {
                    ClaimValue::Unsigned(v) => Ok(*v),
                    _ => Err(bad()),
                })
                .collect::<Result<_, _>>()?,
        ),
        3 => ClaimValues::String(
            claim
                .values
                .iter()
                .map(|v| match v {
                    ClaimValue::Text(v) => Ok(v.clone()),
                    _ => Err(bad()),
                })
                .collect::<Result<_, _>>()?,
        ),
        5 => ClaimValues::Sid(
            claim
                .values
                .iter()
                .map(|v| match v {
                    ClaimValue::Bytes(v) => {
                        SidRef::from_bytes(v).map(Sid::from_ref).ok_or_else(bad)
                    }
                    _ => Err(bad()),
                })
                .collect::<Result<_, _>>()?,
        ),
        6 => ClaimValues::Boolean(
            claim
                .values
                .iter()
                .map(|v| match v {
                    ClaimValue::Boolean(v) => Ok(*v),
                    _ => Err(bad()),
                })
                .collect::<Result<_, _>>()?,
        ),
        16 => ClaimValues::Octet(
            claim
                .values
                .iter()
                .map(|v| match v {
                    ClaimValue::Bytes(v) => Ok(v.clone()),
                    _ => Err(bad()),
                })
                .collect::<Result<_, _>>()?,
        ),
        _ => return Err(bad()),
    };
    Ok(Claim {
        name: claim.name.clone(),
        flags: ClaimAttr::from_bits_retain(claim.flags),
        values,
    })
}

#[cfg(test)]
mod authentication_failure_tests {
    use super::*;

    fn error(category: u32, code: u32) -> peios_auth::Error {
        peios_auth::Error {
            category,
            code,
            outcome_unknown: false,
            message: "authentication failed".into(),
        }
    }

    #[test]
    fn credential_and_account_denials_share_the_generic_failure_label() {
        for code in [4, 6] {
            let reason = authentication_failure(&error(6, code));
            assert_eq!(reason, Reason::Credentials);
            assert_eq!(reason.name(), "authentication-failed");
        }
    }

    #[test]
    fn other_pgss_denials_are_authority_failures() {
        for code in [0, 1, 2, 3, 5, 7, 8, 9, 10, 11, u32::MAX] {
            assert_eq!(authentication_failure(&error(6, code)), Reason::Backend);
        }
    }

    #[test]
    fn client_failures_cannot_be_mistaken_for_pgss_denials() {
        for category in [0, 1, 2, 3, 4, 5, 7, u32::MAX] {
            for code in [0, 4, 6, 7, u32::MAX] {
                let reason = authentication_failure(&error(category, code));
                assert_eq!(reason, Reason::Backend);
                assert_eq!(reason.name(), "authority-unavailable");
            }
        }
    }
}
