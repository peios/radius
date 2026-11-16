//! Portable RADIUS authentication and EAP-TTLS/PAP protocol core.
//!
//! The caller supplies an authenticated-client/network binding for each packet,
//! monotonic time, and an explicit admission result after verifying credentials.
//! This crate has no registry, account database, OS token or socket authority.
#![forbid(unsafe_code)]

mod engine;
mod pap;
mod peap;
mod ttls;
pub mod wire;

pub use engine::{
    Admission, Binding, Client, Credential, Credentials, Engine, Limits, Method, Outcome, Reply,
    Verification,
};
pub use ttls::server_config;

/// Failures never contain credentials or packet contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Integrity,
    Protocol,
    Limit,
    Expired,
    Binding,
    UnknownAttempt,
    Random,
    Tls,
    Configuration,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RADIUS protocol error: {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
