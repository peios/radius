use crate::{
    config::{Network, CONNECT},
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
    fields, Answer, AuthenticateRequest, Authenticated, AuthenticationRequest, Capabilities,
    ClaimSelection, ClaimValue, Field, Operation,
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
            Err(error) => Progress::Failed(if error.category == 1 {
                Reason::Credentials
            } else {
                Reason::Backend
            }),
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
}

pub fn evaluate(
    identity: &Authenticated,
    network_id: &str,
    network: &Network,
) -> Result<(), Reason> {
    let sd = SecurityDescriptor::from_validated_bytes(network.security.clone())
        .map_err(|_| Reason::Policy)?;
    let user = SidRef::from_bytes(&identity.identity.sid).ok_or(Reason::MissingContext)?;
    let Some(Field::References(memberships)) = identity.identity.fields.get(&fields::GROUPS) else {
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
    let Some(Field::Claims(claims)) = identity.identity.fields.get(&fields::CLAIMS) else {
        return Err(Reason::MissingContext);
    };
    let claims = claims
        .iter()
        .map(convert_claim)
        .collect::<Result<Vec<_>, _>>()?;
    let coverage = match identity.claim_coverage {
        peios_auth::ClaimCoverage::Complete => ClaimCoverage::Complete,
        peios_auth::ClaimCoverage::Filtered => ClaimCoverage::Partial,
        _ => return Err(Reason::MissingContext),
    };
    let absent: Vec<_> = identity.absent_claims.iter().map(String::as_str).collect();
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
