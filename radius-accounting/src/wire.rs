//! RFC 2866 accounting integrity. Legacy MD5 is confined to the wire contract.
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub const MAX_PACKET: usize = 4096;
pub const ACCOUNTING_REQUEST: u8 = 4;
pub const ACCOUNTING_RESPONSE: u8 = 5;
pub const DISCONNECT_REQUEST: u8 = 40;
pub const DISCONNECT_ACK: u8 = 41;
pub const DISCONNECT_NAK: u8 = 42;
type HmacMd5 = Hmac<Md5>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribute {
    pub kind: u8,
    pub value: Vec<u8>,
}
impl Attribute {
    pub fn integer(kind: u8, value: u32) -> Self {
        Self {
            kind,
            value: value.to_be_bytes().to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct Request {
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<Attribute>,
    pub canonical: Vec<u8>,
    pub message_authenticator: bool,
}
impl Request {
    pub fn parse(bytes: &[u8], secret: &[u8], require_ma: bool) -> Result<Self> {
        let (bytes, attributes, ma) = frame(bytes, ACCOUNTING_REQUEST)?;
        if attributes
            .iter()
            .any(|a| matches!(a.kind, 2 | 3 | 18 | 24 | 69 | 70 | 79 | 84))
        {
            return Err(Error::Credentials);
        }
        // Microsoft authentication proofs and MPPE keys are not accounting
        // attributes. Refuse them rather than retaining opaque credential data.
        for a in attributes
            .iter()
            .filter(|a| a.kind == 26 && a.value.len() >= 4 && a.value[..4] == 311u32.to_be_bytes())
        {
            let mut at = 4;
            while at < a.value.len() {
                if at + 2 > a.value.len() {
                    return Err(Error::Malformed);
                }
                let length = a.value[at + 1] as usize;
                if length < 2 || at + length > a.value.len() {
                    return Err(Error::Malformed);
                }
                if matches!(a.value[at],1..=6|11|12|16|17|25..=28) {
                    return Err(Error::Credentials);
                }
                at += length;
            }
        }
        let expected = request_hash(bytes, secret);
        if !bool::from(expected.ct_eq(&bytes[4..20])) {
            return Err(Error::Integrity);
        }
        if require_ma && ma.is_none() {
            return Err(Error::Integrity);
        }
        if let Some(offset) = ma {
            // Accounting MA is calculated with a zero Request Authenticator,
            // before calculating the final Request Authenticator containing MA.
            let mut signed = bytes.to_vec();
            signed[4..20].fill(0);
            signed[offset..offset + 16].fill(0);
            verify_mac(&signed, secret, &bytes[offset..offset + 16])?;
        }
        Ok(Self {
            identifier: bytes[1],
            authenticator: bytes[4..20].try_into().map_err(|_| Error::Malformed)?,
            attributes,
            canonical: bytes.to_vec(),
            message_authenticator: ma.is_some(),
        })
    }
    pub fn response(&self, secret: &[u8]) -> Result<Vec<u8>> {
        let attributes: Vec<_> = self
            .attributes
            .iter()
            .filter(|a| a.kind == 33)
            .cloned()
            .collect();
        response(
            ACCOUNTING_RESPONSE,
            self.identifier,
            &self.authenticator,
            &attributes,
            secret,
            self.message_authenticator,
        )
    }
    /// Exact packet receipt; authenticated client scope is added by the ledger.
    pub fn packet_digest(&self) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, &self.canonical)
            .as_ref()
            .to_vec()
    }
    /// Protocol retransmissions may change ID, authenticator, Delay and MA.
    /// All other bytes, including fresh counters/timestamps, remain significant.
    pub fn semantic_digest(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for a in &self.attributes {
            if !matches!(a.kind, 41 | 80 | 33) {
                data.push(a.kind);
                data.extend_from_slice(&(a.value.len() as u32).to_be_bytes());
                data.extend_from_slice(&a.value);
            }
        }
        ring::digest::digest(&ring::digest::SHA256, &data)
            .as_ref()
            .to_vec()
    }
}

type Frame<'a> = (&'a [u8], Vec<Attribute>, Option<usize>);
fn frame(bytes: &[u8], code: u8) -> Result<Frame<'_>> {
    if bytes.len() < 20 || bytes[0] != code {
        return Err(Error::Malformed);
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if !(20..=MAX_PACKET).contains(&length) || length > bytes.len() {
        return Err(Error::Malformed);
    }
    let bytes = &bytes[..length];
    let mut attrs = Vec::new();
    let mut ma = None;
    let mut at = 20;
    while at < length {
        if at + 2 > length {
            return Err(Error::Malformed);
        }
        let size = bytes[at + 1] as usize;
        if size < 2 || at + size > length {
            return Err(Error::Malformed);
        }
        let kind = bytes[at];
        if kind == 80 && (size != 18 || ma.replace(at + 2).is_some()) {
            return Err(Error::Malformed);
        }
        attrs.push(Attribute {
            kind,
            value: bytes[at + 2..at + size].to_vec(),
        });
        at += size;
    }
    Ok((bytes, attrs, ma))
}
fn request_hash(bytes: &[u8], secret: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    Digest::update(&mut h, &bytes[..4]);
    Digest::update(&mut h, [0; 16]);
    Digest::update(&mut h, &bytes[20..]);
    Digest::update(&mut h, secret);
    h.finalize().into()
}
fn verify_mac(bytes: &[u8], secret: &[u8], expected: &[u8]) -> Result<()> {
    let mut mac = HmacMd5::new_from_slice(secret).map_err(|_| Error::Integrity)?;
    mac.update(bytes);
    mac.verify_slice(expected).map_err(|_| Error::Integrity)
}
fn encode(
    code: u8,
    identifier: u8,
    auth: &[u8; 16],
    attrs: &[Attribute],
    ma: bool,
) -> Result<(Vec<u8>, Option<usize>)> {
    let mut out = vec![code, identifier, 0, 0];
    out.extend_from_slice(auth);
    let mut ma_offset = None;
    for a in attrs {
        if a.kind == 80 || a.value.len() > 253 || out.len() + a.value.len() + 2 > MAX_PACKET {
            return Err(Error::Limit);
        }
        out.extend_from_slice(&[a.kind, (a.value.len() + 2) as u8]);
        out.extend_from_slice(&a.value);
    }
    if ma {
        if out.len() + 18 > MAX_PACKET {
            return Err(Error::Limit);
        }
        out.extend_from_slice(&[80, 18]);
        ma_offset = Some(out.len());
        out.extend_from_slice(&[0; 16]);
    }
    let length = (out.len() as u16).to_be_bytes();
    out[2..4].copy_from_slice(&length);
    Ok((out, ma_offset))
}
/// Useful for independent callers and fixtures, not an acceptance shortcut.
pub fn request(identifier: u8, attrs: &[Attribute], secret: &[u8], ma: bool) -> Result<Vec<u8>> {
    let (mut out, offset) = encode(ACCOUNTING_REQUEST, identifier, &[0; 16], attrs, ma)?;
    if let Some(offset) = offset {
        put_mac(&mut out, offset, secret)?;
    }
    let hash = request_hash(&out, secret);
    out[4..20].copy_from_slice(&hash);
    Ok(out)
}
fn put_mac(bytes: &mut [u8], offset: usize, secret: &[u8]) -> Result<()> {
    let mut h = HmacMd5::new_from_slice(secret).map_err(|_| Error::Integrity)?;
    h.update(bytes);
    bytes[offset..offset + 16].copy_from_slice(&h.finalize().into_bytes());
    Ok(())
}
fn response(
    code: u8,
    identifier: u8,
    request_auth: &[u8; 16],
    attrs: &[Attribute],
    secret: &[u8],
    ma: bool,
) -> Result<Vec<u8>> {
    let (mut bytes, offset) = encode(code, identifier, request_auth, attrs, ma)?;
    if let Some(offset) = offset {
        put_mac(&mut bytes, offset, secret)?;
    }
    let mut h = Md5::new();
    Digest::update(&mut h, &bytes);
    Digest::update(&mut h, secret);
    bytes[4..20].copy_from_slice(&h.finalize());
    Ok(bytes)
}

/// RFC 5176 Disconnect: NAS-address/session selectors are adapter-validated.
/// No username-only or wildcard targeting is allowed by this encoder.
pub fn disconnect(identifier: u8, attrs: &[Attribute], secret: &[u8]) -> Result<Vec<u8>> {
    if !attrs.iter().any(|a| a.kind == 44 && !a.value.is_empty())
        || !attrs.iter().any(|a| matches!(a.kind, 4 | 32 | 95))
        || attrs
            .iter()
            .any(|a| matches!(a.kind, 2 | 3 | 18 | 24 | 79 | 80))
    {
        return Err(Error::Configuration(
            "Disconnect requires NAS and session selectors".into(),
        ));
    }
    let (mut bytes, _) = encode(DISCONNECT_REQUEST, identifier, &[0; 16], attrs, false)?;
    let hash = request_hash(&bytes, secret);
    bytes[4..20].copy_from_slice(&hash);
    Ok(bytes)
}
pub fn disconnect_result(bytes: &[u8], sent: &[u8], secret: &[u8]) -> Result<(bool, Option<u32>)> {
    if sent.len() < 20 || !matches!(bytes.first(), Some(&DISCONNECT_ACK) | Some(&DISCONNECT_NAK)) {
        return Err(Error::Malformed);
    }
    let (bytes, attrs, ma) = frame(bytes, bytes[0])?;
    if bytes[1] != sent[1] {
        return Err(Error::Integrity);
    }
    let mut signed = bytes.to_vec();
    signed[4..20].copy_from_slice(&sent[4..20]);
    let mut h = Md5::new();
    Digest::update(&mut h, &signed);
    Digest::update(&mut h, secret);
    if !bool::from(<[u8; 16]>::from(h.finalize()).ct_eq(&bytes[4..20])) {
        return Err(Error::Integrity);
    }
    if let Some(offset) = ma {
        signed[offset..offset + 16].fill(0);
        verify_mac(&signed, secret, &bytes[offset..offset + 16])?;
    }
    let errors: Vec<_> = attrs.iter().filter(|a| a.kind == 101).collect();
    let cause = match errors.as_slice() {
        [] => None,
        [a] if a.value.len() == 4 => Some(u32::from_be_bytes(a.value[..].try_into().unwrap())),
        _ => return Err(Error::Malformed),
    };
    Ok((bytes[0] == DISCONNECT_ACK, cause))
}
