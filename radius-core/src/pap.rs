use crate::{Credentials, Error};
use zeroize::Zeroizing;

/// Parse a complete PAP AVP sequence. Incomplete TLS-stream input is retained
/// by the caller, independently of TLS record and EAP fragment boundaries.
pub(crate) fn credentials(bytes: &[u8]) -> Result<Option<Credentials>, Error> {
    let mut offset = 0;
    let mut username = None;
    let mut password = None;
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            return Ok(None);
        }
        let header = &bytes[offset..];
        let code = u32::from_be_bytes(header[..4].try_into().map_err(|_| Error::Malformed)?);
        let vendor = header[4] & 0x80 != 0;
        let required = header[4] & 0x40 != 0;
        let len = u32::from_be_bytes([0, header[5], header[6], header[7]]) as usize;
        let header_len = if vendor { 12 } else { 8 };
        if len < header_len || len > 4096 {
            return Err(Error::Malformed);
        }
        let padded = len.next_multiple_of(4);
        if header.len() < padded {
            return Ok(None);
        }
        let data = &header[header_len..len];
        match (vendor, code) {
            (false, 1) => {
                if username.replace(data).is_some() || data.is_empty() || data.len() > 253 {
                    return Err(Error::Malformed);
                }
            }
            (false, 2) => {
                if password.replace(data).is_some() || data.len() > 1024 {
                    return Err(Error::Malformed);
                }
            }
            _ if required => return Err(Error::Protocol),
            _ => {}
        }
        offset += padded;
    }
    let (Some(username), Some(password)) = (username, password) else {
        return Ok(None);
    };
    let end = password.iter().rposition(|b| *b != 0).map_or(0, |n| n + 1);
    Ok(Some(Credentials {
        username: username.to_vec(),
        password: Zeroizing::new(password[..end].to_vec()),
    }))
}
