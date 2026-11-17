//! RFC 2865/3579 packet integrity and RFC 2548 key wrapping.
//!
//! MD5 is used only where the legacy RADIUS wire protocol requires it. TLS and
//! its key derivation are delegated to Rustls. No custom cryptographic primitive
//! is implemented here.
use crate::Error;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

type HmacMd5 = Hmac<Md5>;
pub const MAX_PACKET: usize = 4096;

/// An integrity-checked Access-Request. Fields borrow the original datagram.
pub struct Request<'a> {
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub state: Option<[u8; 16]>,
    pub station: Option<&'a [u8]>,
    pub called_station: Option<&'a [u8]>,
    pub eap: Vec<u8>,
    pub canonical: &'a [u8],
}

impl<'a> Request<'a> {
    /// Ignore datagram padding beyond the declared RADIUS length, as RFC 2865
    /// requires. Reject duplicate singletons and require exactly one valid MA.
    pub fn parse(bytes: &'a [u8], secret: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 20 || bytes[0] != 1 {
            return Err(Error::Malformed);
        }
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if !(20..=MAX_PACKET).contains(&len) || bytes.len() < len {
            return Err(Error::Malformed);
        }
        let bytes = &bytes[..len];
        let mut state = None;
        let mut station = None;
        let mut called_station = None;
        let mut ma = None;
        let mut eap = Vec::new();
        let mut eap_ended = false;
        let mut offset = 20;
        while offset < len {
            if offset + 2 > len {
                return Err(Error::Malformed);
            }
            let kind = bytes[offset];
            let size = usize::from(bytes[offset + 1]);
            if size < 2 || offset + size > len {
                return Err(Error::Malformed);
            }
            let value = &bytes[offset + 2..offset + size];
            if kind != 79 && !eap.is_empty() {
                eap_ended = true;
            }
            match kind {
                24 => {
                    if state.is_some() || value.len() != 16 {
                        return Err(Error::Malformed);
                    }
                    state = Some(value.try_into().map_err(|_| Error::Malformed)?);
                }
                30 => {
                    if called_station.replace(value).is_some() || value.is_empty() {
                        return Err(Error::Malformed);
                    }
                }
                31 => {
                    if station.replace(value).is_some() || value.is_empty() {
                        return Err(Error::Malformed);
                    }
                }
                79 => {
                    if eap_ended || value.is_empty() {
                        return Err(Error::Malformed);
                    }
                    eap.extend_from_slice(value);
                }
                80 => {
                    if ma.replace(offset + 2).is_some() || value.len() != 16 {
                        return Err(Error::Malformed);
                    }
                }
                // Proxying and outer password methods are outside this slice.
                2 | 3 | 33 => return Err(Error::Protocol),
                _ => {}
            }
            offset += size;
        }
        let ma = ma.ok_or(Error::Integrity)?;
        let mut signed = bytes.to_vec();
        signed[ma..ma + 16].fill(0);
        let mut verifier = HmacMd5::new_from_slice(secret).map_err(|_| Error::Integrity)?;
        verifier.update(&signed);
        verifier
            .verify_slice(&bytes[ma..ma + 16])
            .map_err(|_| Error::Integrity)?;
        if eap.len() < 4 || usize::from(u16::from_be_bytes([eap[2], eap[3]])) != eap.len() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            identifier: bytes[1],
            authenticator: bytes[4..20].try_into().map_err(|_| Error::Malformed)?,
            state,
            station,
            called_station,
            eap,
            canonical: bytes,
        })
    }
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| Error::Random)?;
    Ok(out)
}

fn attribute(out: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), Error> {
    if value.len() > 253 || out.len() + value.len() + 2 > MAX_PACKET {
        return Err(Error::Limit);
    }
    out.extend_from_slice(&[kind, (value.len() + 2) as u8]);
    out.extend_from_slice(value);
    Ok(())
}

fn wrapped_key(secret: &[u8], request_auth: &[u8; 16], salt: [u8; 2], key: &[u8]) -> Vec<u8> {
    let mut plaintext = Zeroizing::new(vec![0; (key.len() + 1).next_multiple_of(16)]);
    plaintext[0] = key.len() as u8;
    plaintext[1..1 + key.len()].copy_from_slice(key);
    let mut encrypted = Vec::with_capacity(2 + plaintext.len());
    encrypted.extend_from_slice(&salt);
    let mut previous = Vec::from(request_auth.as_slice());
    previous.extend_from_slice(&salt);
    for block in plaintext.chunks(16) {
        let mut hash = Md5::new();
        Digest::update(&mut hash, secret);
        Digest::update(&mut hash, &previous);
        let mask = Zeroizing::new(<[u8; 16]>::from(hash.finalize()));
        previous = block.iter().zip(mask.iter()).map(|(p, m)| p ^ m).collect();
        encrypted.extend_from_slice(&previous);
    }
    encrypted
}

/// Build an authenticated reply. The response MA is calculated with the request
/// authenticator in the header, then the Response Authenticator includes that MA.
pub(crate) fn response(
    request_id: u8,
    request_auth: &[u8; 16],
    secret: &[u8],
    code: u8,
    eap: &[u8],
    state: Option<[u8; 16]>,
    msk: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    response_with_reauthentication(
        request_id,
        request_auth,
        secret,
        code,
        eap,
        state,
        msk,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn response_with_reauthentication(
    request_id: u8,
    request_auth: &[u8; 16],
    secret: &[u8],
    code: u8,
    eap: &[u8],
    state: Option<[u8; 16]>,
    msk: Option<&[u8]>,
    reauthenticate_seconds: Option<u32>,
) -> Result<Vec<u8>, Error> {
    response_with_class(
        request_id,
        request_auth,
        secret,
        code,
        eap,
        state,
        msk,
        reauthenticate_seconds,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn response_with_class(
    request_id: u8,
    request_auth: &[u8; 16],
    secret: &[u8],
    code: u8,
    eap: &[u8],
    state: Option<[u8; 16]>,
    msk: Option<&[u8]>,
    reauthenticate_seconds: Option<u32>,
    class: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![code, request_id, 0, 0];
    out.extend_from_slice(request_auth);
    // First attribute: strict MA, including for Reject and Challenge.
    attribute(&mut out, 80, &[0; 16])?;
    for chunk in eap.chunks(253) {
        attribute(&mut out, 79, chunk)?;
    }
    if let Some(state) = state {
        attribute(&mut out, 24, &state)?;
    }
    if let Some(class) = class {
        if code != 2 || class.is_empty() {
            return Err(Error::Configuration);
        }
        attribute(&mut out, 25, class)?;
    }
    if let Some(seconds) = reauthenticate_seconds {
        if code != 2 || seconds == 0 {
            return Err(Error::Configuration);
        }
        attribute(&mut out, 27, &seconds.to_be_bytes())?;
        attribute(&mut out, 29, &1u32.to_be_bytes())?;
    }
    if let Some(msk) = msk {
        if code != 2 || msk.len() != 64 {
            return Err(Error::Protocol);
        }
        let mut salts = random::<4>()?;
        salts[0] |= 0x80;
        salts[2] |= 0x80;
        if salts[..2] == salts[2..] {
            salts[3] ^= 1;
        }
        for (kind, key, salt) in [
            (17, &msk[..32], [salts[0], salts[1]]),
            (16, &msk[32..], [salts[2], salts[3]]),
        ] {
            let encrypted = wrapped_key(secret, request_auth, salt, key);
            let mut value = Vec::from(311u32.to_be_bytes());
            value.extend_from_slice(&[kind, (encrypted.len() + 2) as u8]);
            value.extend_from_slice(&encrypted);
            attribute(&mut out, 26, &value)?;
        }
    }
    let len = u16::try_from(out.len()).map_err(|_| Error::Limit)?;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    let mut mac = HmacMd5::new_from_slice(secret).map_err(|_| Error::Integrity)?;
    mac.update(&out);
    out[22..38].copy_from_slice(&mac.finalize().into_bytes());
    let mut hash = Md5::new();
    Digest::update(&mut hash, &out);
    Digest::update(&mut hash, secret);
    out[4..20].copy_from_slice(&hash.finalize());
    Ok(out)
}

pub(crate) fn eap_request_type(id: u8, kind: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u16::try_from(data.len() + 5).map_err(|_| Error::Limit)?;
    let mut packet = vec![1, id];
    packet.extend_from_slice(&len.to_be_bytes());
    packet.push(kind);
    packet.extend_from_slice(data);
    Ok(packet)
}

pub(crate) fn eap_terminal(id: u8, success: bool) -> [u8; 4] {
    [if success { 3 } else { 4 }, id, 0, 4]
}
