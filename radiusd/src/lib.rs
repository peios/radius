//! Peios RADIUS integration. Portable configuration/scheduling rules are tested
//! without native services; production authentication uses the public libauth API.
pub mod config;
pub mod driver;
#[cfg(feature = "native")]
pub mod native;
