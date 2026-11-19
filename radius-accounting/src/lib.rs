//! Accounting evidence, deterministic interpretation and transactional storage.
//!
//! Peios authority and sockets belong to the native adapter. Protocol parsing
//! cannot create verified subjects; only a previously persisted local grant can.
#![forbid(unsafe_code)]

pub mod dynamic;
pub mod model;
pub mod profile;
pub mod quota;
pub mod store;
pub mod wire;
pub mod worker;

#[derive(Debug)]
pub enum Error {
    Malformed,
    Integrity,
    Credentials,
    Limit,
    Configuration(String),
    Storage(rusqlite::Error),
    Io(std::io::Error),
    Encoding(serde_json::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(message) => write!(f, "accounting configuration: {message}"),
            Self::Storage(rusqlite::Error::SqliteFailure(code, _)) => write!(
                f,
                "accounting storage operation failed ({:?}/{})",
                code.code, code.extended_code
            ),
            Self::Storage(_) => f.write_str("accounting storage operation failed"),
            Self::Io(e) => write!(f, "accounting I/O: {}", e.kind()),
            Self::Encoding(_) => f.write_str("invalid accounting data encoding"),
            other => write!(f, "accounting error: {other:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Encoding(value)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn id() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Limit)?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex = hex(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
