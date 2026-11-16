use crate::{pap, Credentials, Error};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig, ServerConnection,
};
use std::{
    io::{Cursor, Read},
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_TLS: usize = 65536;
const MAX_PLAINTEXT: usize = 4096;

/// Construct a server-authenticated TLS configuration for full TTLS/PAP
/// exchanges. No client certificate, resumption or early data is enabled.
pub fn server_config(
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| Error::Configuration)?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|_| Error::Configuration)?;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

pub(crate) enum Step {
    Send(Vec<u8>),
    Verify(Credentials),
}

pub(crate) struct Tunnel {
    tls: ServerConnection,
    incoming: Vec<u8>,
    expected: Option<usize>,
    outgoing: Vec<u8>,
    offset: usize,
    plaintext: Zeroizing<Vec<u8>>,
    mtu: usize,
}

impl Tunnel {
    pub(crate) fn new(config: Arc<ServerConfig>, mtu: usize) -> Result<Self, Error> {
        let mut tls = ServerConnection::new(config).map_err(|_| Error::Tls)?;
        tls.set_buffer_limit(Some(MAX_TLS));
        Ok(Self {
            tls,
            incoming: Vec::new(),
            expected: None,
            outgoing: Vec::new(),
            offset: 0,
            plaintext: Zeroizing::new(Vec::new()),
            mtu,
        })
    }

    pub(crate) fn step(&mut self, data: &[u8]) -> Result<Step, Error> {
        let (&flags, tail) = data.split_first().ok_or(Error::Malformed)?;
        // TTLSv0 only. A peer cannot send a server Start frame.
        if flags & 0x3f != 0 {
            return Err(Error::Protocol);
        }
        if !self.outgoing.is_empty() {
            if flags != 0 || !tail.is_empty() {
                return Err(Error::Protocol);
            }
            return Ok(Step::Send(self.next_fragment()));
        }
        let (length, payload) = if flags & 0x80 != 0 {
            if tail.len() < 4 || self.expected.is_some() {
                return Err(Error::Malformed);
            }
            let len =
                u32::from_be_bytes(tail[..4].try_into().map_err(|_| Error::Malformed)?) as usize;
            if len == 0 || len > MAX_TLS {
                return Err(Error::Limit);
            }
            (Some(len), &tail[4..])
        } else {
            (None, tail)
        };
        let more = flags & 0x40 != 0;
        if more && length.is_none() && self.expected.is_none() {
            return Err(Error::Protocol);
        }
        if more && payload.is_empty() {
            return Err(Error::Protocol);
        }
        if let Some(len) = length {
            self.expected = Some(len);
        }
        if self.incoming.len() + payload.len() > MAX_TLS {
            return Err(Error::Limit);
        }
        self.incoming.extend_from_slice(payload);
        if let Some(len) = self.expected {
            if self.incoming.len() > len || (more && self.incoming.len() >= len) {
                return Err(Error::Malformed);
            }
            if !more && self.incoming.len() != len {
                return Err(Error::Malformed);
            }
        }
        if more {
            return Ok(Step::Send(vec![0]));
        }
        if !self.incoming.is_empty() {
            let incoming = std::mem::take(&mut self.incoming);
            self.expected = None;
            let mut cursor = Cursor::new(incoming);
            while cursor.position() < cursor.get_ref().len() as u64 {
                let n = self.tls.read_tls(&mut cursor).map_err(|_| Error::Tls)?;
                if n == 0 {
                    return Err(Error::Tls);
                }
                self.tls.process_new_packets().map_err(|_| Error::Tls)?;
            }
        }
        if !self.tls.is_handshaking() {
            let mut scratch = Zeroizing::new([0u8; 4096]);
            loop {
                match self.tls.reader().read(scratch.as_mut()) {
                    Ok(0) => return Err(Error::Protocol),
                    Ok(n) => {
                        if self.plaintext.len() + n > MAX_PLAINTEXT {
                            return Err(Error::Limit);
                        }
                        self.plaintext.extend_from_slice(&scratch[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err(Error::Tls),
                }
            }
        }
        while self.tls.wants_write() {
            self.tls
                .write_tls(&mut self.outgoing)
                .map_err(|_| Error::Tls)?;
            if self.outgoing.len() > MAX_TLS {
                return Err(Error::Limit);
            }
        }
        if !self.outgoing.is_empty() {
            return Ok(Step::Send(self.next_fragment()));
        }
        if !self.tls.is_handshaking() && !self.plaintext.is_empty() {
            if let Some(credentials) = pap::credentials(&self.plaintext)? {
                self.plaintext.zeroize();
                return Ok(Step::Verify(credentials));
            }
        }
        Ok(Step::Send(vec![0]))
    }

    fn next_fragment(&mut self) -> Vec<u8> {
        let first = self.offset == 0;
        let count = (self.outgoing.len() - self.offset).min(self.mtu);
        let more = self.offset + count < self.outgoing.len();
        let mut frame = vec![if more { 0x40 } else { 0 }];
        if first && more {
            frame[0] |= 0x80;
            frame.extend_from_slice(&(self.outgoing.len() as u32).to_be_bytes());
        }
        frame.extend_from_slice(&self.outgoing[self.offset..self.offset + count]);
        self.offset += count;
        if !more {
            self.outgoing.clear();
            self.offset = 0;
        }
        frame
    }

    pub(crate) fn msk(&self) -> Result<Zeroizing<[u8; 64]>, Error> {
        if self.tls.is_handshaking() {
            return Err(Error::Protocol);
        }
        let (label, context): (&[u8], Option<&[u8]>) = match self.tls.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_2) => (b"ttls keying material", None),
            Some(rustls::ProtocolVersion::TLSv1_3) => {
                (b"EXPORTER_EAP_TLS_Key_Material", Some(&[21]))
            }
            _ => return Err(Error::Protocol),
        };
        let keys = self
            .tls
            .export_keying_material(Zeroizing::new([0u8; 128]), label, context)
            .map_err(|_| Error::Tls)?;
        let mut msk = Zeroizing::new([0; 64]);
        msk.copy_from_slice(&keys[..64]);
        Ok(msk)
    }
}
