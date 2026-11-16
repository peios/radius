//! Bounded local status protocol. No credentials or subject claims cross it.
use crate::model::Issue;
use serde::{Deserialize, Serialize};
pub const SOCKET: &str = "/run/radiusd/control.sock";
pub const REQUEST: &[u8] = b"RADIUS-STATUS 1\n";
pub const MAX_REPLY: usize = 256 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub version: u32,
    pub state: String,
    pub saved_fingerprint: Option<String>,
    pub effective_fingerprint: Option<String>,
    pub issues: Vec<Issue>,
    pub listeners: Vec<String>,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            version: 1,
            state: "starting".into(),
            saved_fingerprint: None,
            effective_fingerprint: None,
            issues: Vec::new(),
            listeners: Vec::new(),
        }
    }
}
