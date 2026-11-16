//! PEAPv0 inner framing (MS-PEAP 3.1.5.6) and EAP-MSCHAPv2.
//! Cryptographic credential verification belongs to the caller's authority.
use crate::{Credential, Credentials, Error};

#[derive(PartialEq, Eq)]
enum Phase {
    Start,
    Identity,
    Challenge,
    Response,
    Verified,
    SuccessAck,
    ResultAck,
    Complete,
}
pub(crate) struct Peap {
    phase: Phase,
    username: Vec<u8>,
    mschap_id: u8,
    result_id: u8,
}
pub(crate) enum Inner {
    Send(Vec<u8>),
    Verify(Credentials),
    Response([u8; 40]),
    Complete,
    More,
}
impl Peap {
    pub fn new() -> Self {
        Self {
            phase: Phase::Start,
            username: Vec::new(),
            mschap_id: 1,
            result_id: 1,
        }
    }
    pub fn complete(&self) -> bool {
        self.phase == Phase::Complete
    }
    pub fn process(&mut self, bytes: &[u8]) -> Result<Inner, Error> {
        match self.phase {
            Phase::Start if bytes.is_empty() => {
                self.phase = Phase::Identity;
                Ok(Inner::Send(vec![1]))
            }
            Phase::Identity => {
                if bytes.is_empty() {
                    return Ok(Inner::More);
                }
                if bytes == [1] {
                    return Ok(Inner::More);
                }
                if bytes[0] != 1 || bytes.len() < 2 || bytes.len() > 257 || bytes[1..].contains(&0)
                {
                    return Err(Error::Protocol);
                }
                self.username = bytes[1..].to_vec();
                self.phase = Phase::Challenge;
                Ok(Inner::Verify(Credentials {
                    username: self.username.clone(),
                    proof: Credential::Mschapv2,
                }))
            }
            Phase::Response => {
                if bytes.len() < 5 {
                    return Ok(Inner::More);
                }
                let size = usize::from(u16::from_be_bytes([bytes[3], bytes[4]])) + 1;
                if size > 311 {
                    return Err(Error::Limit);
                }
                if bytes.len() < size {
                    return Ok(Inner::More);
                }
                if bytes.len() != size
                    || bytes.len() < 56
                    || bytes[..3] != [26, 2, self.mschap_id]
                    || bytes[5] != 49
                    || bytes[22..30] != [0; 8]
                    || bytes[54] != 0
                    || bytes[55..] != self.username
                {
                    return Err(Error::Protocol);
                }
                let mut response = [0; 40];
                response[..16].copy_from_slice(&bytes[6..22]);
                response[16..].copy_from_slice(&bytes[30..54]);
                self.phase = Phase::Verified;
                Ok(Inner::Response(response))
            }
            Phase::SuccessAck => {
                if bytes.len() < 2 {
                    return Ok(Inner::More);
                }
                if bytes != [26, 3] {
                    return Err(Error::Protocol);
                }
                self.phase = Phase::ResultAck;
                Ok(Inner::Send(vec![
                    1,
                    self.result_id,
                    0,
                    11,
                    33,
                    0x80,
                    3,
                    0,
                    2,
                    0,
                    1,
                ]))
            }
            Phase::ResultAck => {
                if bytes.len() < 11 {
                    return Ok(Inner::More);
                }
                if bytes != [2, self.result_id, 0, 11, 33, 0x80, 3, 0, 2, 0, 1] {
                    return Err(Error::Protocol);
                }
                self.phase = Phase::Complete;
                Ok(Inner::Complete)
            }
            _ if bytes.is_empty() => Ok(Inner::More),
            _ => Err(Error::Protocol),
        }
    }
    pub fn challenge(&mut self, challenge: [u8; 16]) -> Result<Vec<u8>, Error> {
        if self.phase != Phase::Challenge {
            return Err(Error::Protocol);
        }
        let mut bytes = vec![26, 1, self.mschap_id, 0, 28, 16];
        bytes.extend_from_slice(&challenge);
        bytes.extend_from_slice(b"radiusd");
        self.phase = Phase::Response;
        Ok(bytes)
    }
    pub fn success(&mut self, success: [u8; 20]) -> Result<Vec<u8>, Error> {
        if self.phase != Phase::Verified {
            return Err(Error::Protocol);
        }
        let mut bytes = vec![26, 3, self.mschap_id, 0, 46, b'S', b'='];
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for byte in success {
            bytes.extend_from_slice(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
        }
        self.phase = Phase::SuccessAck;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_identity_switches_and_requires_both_success_acknowledgements() {
        let mut peap = Peap::new();
        assert!(matches!(peap.process(&[]).unwrap(), Inner::Send(_)));
        assert!(matches!(
            peap.process(b"\x01User").unwrap(),
            Inner::Verify(_)
        ));
        assert!(peap.success([0; 20]).is_err());
        assert_eq!(&peap.challenge([7; 16]).unwrap()[6..22], &[7; 16]);
        let mut proof = vec![26, 2, 1, 0, 58, 49];
        proof.extend_from_slice(&[1; 16]);
        proof.extend_from_slice(&[0; 8]);
        proof.extend_from_slice(&[2; 24]);
        proof.push(0);
        proof.extend_from_slice(b"User");
        let mut wrong_name = proof.clone();
        wrong_name[55] = b'u';
        assert!(peap.process(&wrong_name).is_err());
        assert!(matches!(peap.process(&proof).unwrap(), Inner::Response(_)));
        let success = peap.success([0xab; 20]).unwrap();
        assert_eq!(&success[5..], b"S=ABABABABABABABABABABABABABABABABABABABAB");
        assert!(!peap.complete());
        assert!(matches!(peap.process(&[26, 3]).unwrap(), Inner::Send(_)));
        let mut denied = [2, 1, 0, 11, 33, 0x80, 3, 0, 2, 0, 2];
        assert!(peap.process(&denied).is_err());
        denied[10] = 1;
        assert!(matches!(peap.process(&denied).unwrap(), Inner::Complete));
        assert!(peap.complete());
        assert!(peap.process(&proof).is_err());
    }
}
