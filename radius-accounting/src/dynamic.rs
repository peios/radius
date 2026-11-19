//! Declarative dynamic authorization and durable evidence, never AP identity.
use crate::{model::Session, wire::Attribute, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    #[default]
    Disconnect,
    Reauthenticate,
    UpdateAuthorization,
}

/// Values actually emitted by this server. None VLAN explicitly means no
/// RADIUS override; absence of this entire record means unknown legacy state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub vlan: Option<u16>,
    pub timeout_seconds: u32,
}
impl Authorization {
    pub fn validate(&self) -> Result<()> {
        if self.vlan.is_some_and(|v| !(1..=4094).contains(&v)) || self.timeout_seconds == 0 {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    pub reference: [u8; 16],
    pub revision: [u8; 16],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    /// Ledger commit order, independent of wall-clock collisions or rollback.
    pub sequence: u64,
    pub grant: Vec<u8>,
    pub authenticated_ms: i64,
    pub configuration: String,
    pub issued: Authorization,
    pub configured_timeout_seconds: u32,
    pub credentials: Vec<CredentialBinding>,
}
impl Proof {
    pub fn validate(&self) -> Result<()> {
        self.issued.validate()?;
        if self.grant.is_empty()
            || self.grant.len() > 253
            || self.configuration.len() != 64
            || !self.configuration.bytes().all(|b| b.is_ascii_hexdigit())
            || self.authenticated_ms < 0
            || self.configured_timeout_seconds == 0
            || self.credentials.len() > 64
            || self.credentials.iter().enumerate().any(|(i, c)| {
                c.reference == [0; 16]
                    || c.revision == [0; 16]
                    || self.credentials[..i]
                        .iter()
                        .any(|old| old.reference == c.reference)
            })
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// Exact occurrence selectors captured before transmission. Never use a name
/// or broaden an incomplete target to all sessions on a NAS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub source: std::net::IpAddr,
    pub nas: Vec<Attribute>,
    pub session: Vec<u8>,
    pub station: Option<Vec<u8>>,
}
impl Target {
    pub fn from_session(session: &Session) -> Result<Self> {
        if session.kind != "session" || session.end_ms.is_some() {
            return Err(Error::Configuration("session is not controllable".into()));
        }
        let target = Self {
            source: session.source,
            nas: session.nas_attributes.clone(),
            session: session.session.clone(),
            station: session.station.clone(),
        };
        target.attributes(true)?;
        Ok(target)
    }
    pub fn attributes(&self, station: bool) -> Result<Vec<Attribute>> {
        let mut seen = std::collections::BTreeSet::new();
        if self.session.is_empty()
            || self.session.len() > 253
            || self.nas.is_empty()
            || self.nas.len() > 3
            || self.source.is_unspecified()
            || self.source.is_multicast()
            || self.nas.iter().any(|a| {
                !seen.insert(a.kind)
                    || match a.kind {
                        4 => a.value.len() != 4,
                        95 => a.value.len() != 16,
                        32 => a.value.is_empty() || a.value.len() > 253,
                        _ => true,
                    }
            })
            || self
                .station
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 253)
        {
            return Err(Error::Configuration(
                "incomplete or ambiguous session selectors".into(),
            ));
        }
        let mut attributes = self.nas.clone();
        attributes.push(Attribute {
            kind: 44,
            value: self.session.clone(),
        });
        if station {
            if let Some(value) = &self.station {
                attributes.push(Attribute {
                    kind: 31,
                    value: value.clone(),
                });
            }
        }
        Ok(attributes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    tag = "value",
    content = "data",
    deny_unknown_fields
)]
pub enum Value {
    Integer(u32),
    Text(String),
    VlanDecimal,
    Timeout,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encoding {
    pub kind: u8,
    #[serde(default)]
    pub vendor: Option<u32>,
    pub value: Value,
}
impl Encoding {
    fn validate(&self) -> Result<()> {
        // No credentials, selectors, protocol state or integrity attributes can
        // be injected by a profile. Vendor attributes remain bounded data.
        if self.kind == 0
            || self.vendor == Some(0)
            || (self.vendor == Some(311)
                && matches!(self.kind, 1..=6 | 11 | 12 | 16 | 17 | 25..=28))
            || (self.vendor.is_none() && !matches!(self.kind, 6 | 27 | 28 | 29 | 64 | 65 | 81))
            || (self.vendor.is_none()
                && !matches!(
                    (self.kind, &self.value),
                    (6 | 64 | 65, Value::Integer(_))
                        | (27..=29, Value::Integer(_) | Value::Timeout)
                        | (81, Value::Text(_) | Value::VlanDecimal)
                ))
            || matches!(&self.value, Value::Text(v) if v.is_empty() || v.len() > 240 || v.contains('\0'))
        {
            return Err(Error::Configuration(
                "invalid dynamic attribute encoding".into(),
            ));
        }
        Ok(())
    }
    fn encode(&self, desired: &Authorization) -> Result<Option<Attribute>> {
        self.validate()?;
        let mut value = match &self.value {
            Value::Integer(v) => v.to_be_bytes().to_vec(),
            Value::Text(v) => v.as_bytes().to_vec(),
            Value::VlanDecimal => {
                let Some(vlan) = desired.vlan else {
                    return Ok(None);
                };
                vlan.to_string().into_bytes()
            }
            Value::Timeout => desired.timeout_seconds.to_be_bytes().to_vec(),
        };
        if self.vendor.is_none() && self.kind == 81 {
            value.insert(0, 0);
        }
        Ok(Some(if let Some(vendor) = self.vendor {
            let mut bytes = vendor.to_be_bytes().to_vec();
            bytes.push(self.kind);
            bytes.push((value.len() + 2) as u8);
            bytes.extend(value);
            Attribute {
                kind: 26,
                value: bytes,
            }
        } else {
            Attribute {
                kind: self.kind,
                value,
            }
        }))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub action: Action,
    /// Administrator declaration after device qualification. RFC 5176
    /// Authorize-Only alone cannot establish fresh proof.
    #[serde(default)]
    pub fresh_proof: bool,
    #[serde(default)]
    pub attributes: Vec<Encoding>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub name: String,
    #[serde(default = "yes")]
    pub station_selector: bool,
    #[serde(default)]
    pub require_station: bool,
    /// Which recorded NAS selectors to transmit. At least one must be present
    /// on the exact target; the session selector is never optional.
    #[serde(default = "all_nas_selectors")]
    pub nas_selectors: Vec<NasSelector>,
    /// Clearing a VLAN override has no universal standard CoA encoding.
    #[serde(default)]
    pub clear_vlan: Vec<Encoding>,
    pub recipes: Vec<Recipe>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NasSelector {
    IpAddress,
    Identifier,
    Ipv6Address,
}
impl NasSelector {
    fn kind(self) -> u8 {
        match self {
            Self::IpAddress => 4,
            Self::Identifier => 32,
            Self::Ipv6Address => 95,
        }
    }
}
fn all_nas_selectors() -> Vec<NasSelector> {
    vec![
        NasSelector::IpAddress,
        NasSelector::Identifier,
        NasSelector::Ipv6Address,
    ]
}
fn yes() -> bool {
    true
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            name: "RFC 5176".into(),
            station_selector: true,
            require_station: false,
            nas_selectors: all_nas_selectors(),
            clear_vlan: vec![],
            recipes: vec![
                Recipe {
                    action: Action::Disconnect,
                    fresh_proof: false,
                    attributes: vec![],
                },
                Recipe {
                    action: Action::UpdateAuthorization,
                    fresh_proof: false,
                    attributes: vec![
                        Encoding {
                            kind: 64,
                            vendor: None,
                            value: Value::Integer(13),
                        },
                        Encoding {
                            kind: 65,
                            vendor: None,
                            value: Value::Integer(6),
                        },
                        Encoding {
                            kind: 81,
                            vendor: None,
                            value: Value::VlanDecimal,
                        },
                        Encoding {
                            kind: 27,
                            vendor: None,
                            value: Value::Timeout,
                        },
                    ],
                },
            ],
        }
    }
}
impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65536 {
            return Err(Error::Limit);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.name.is_empty()
            || self.name.len() > 128
            || self.recipes.is_empty()
            || self.recipes.len() > 3
            || self.clear_vlan.len() > 16
            || (self.require_station && !self.station_selector)
            || self.nas_selectors.is_empty()
            || self.nas_selectors.len() > 3
            || self
                .nas_selectors
                .iter()
                .enumerate()
                .any(|(i, selector)| self.nas_selectors[..i].contains(selector))
        {
            return Err(Error::Configuration(
                "invalid dynamic profile bounds".into(),
            ));
        }
        for (i, recipe) in self.recipes.iter().enumerate() {
            if self.recipes[..i].iter().any(|r| r.action == recipe.action)
                || recipe.attributes.len() > 16
                || (recipe.action == Action::Disconnect
                    && (!recipe.attributes.is_empty() || recipe.fresh_proof))
                || (recipe.action == Action::Reauthenticate
                    && (!recipe.fresh_proof || recipe.attributes.is_empty()))
                || recipe
                    .attributes
                    .iter()
                    .any(|a| a.vendor.is_none() && a.kind == 6 && a.value == Value::Integer(17))
            {
                return Err(Error::Configuration(
                    "ambiguous dynamic profile capability".into(),
                ));
            }
            for attr in &recipe.attributes {
                attr.validate()?;
            }
            let mut keys = std::collections::BTreeSet::new();
            if recipe
                .attributes
                .iter()
                .any(|a| !keys.insert((a.vendor, a.kind)))
            {
                return Err(Error::Configuration(
                    "duplicate dynamic attribute encoding".into(),
                ));
            }
            if recipe.action == Action::Reauthenticate
                && recipe.attributes.iter().any(|a| {
                    matches!(a.value, Value::VlanDecimal)
                        || (a.vendor.is_none() && matches!(a.kind, 64 | 65 | 81))
                })
            {
                return Err(Error::Configuration(
                    "reauthentication cannot assign a VLAN".into(),
                ));
            }
        }
        for attr in &self.clear_vlan {
            attr.validate()?;
            if matches!(attr.value, Value::VlanDecimal | Value::Timeout) {
                return Err(Error::Configuration(
                    "VLAN reset requires an explicit device encoding".into(),
                ));
            }
        }
        let mut keys = std::collections::BTreeSet::new();
        if self
            .clear_vlan
            .iter()
            .any(|a| !keys.insert((a.vendor, a.kind)))
            || self
                .recipes
                .iter()
                .filter(|r| r.action == Action::UpdateAuthorization)
                .any(|r| {
                    r.attributes
                        .iter()
                        .filter(|a| a.vendor.is_some() || !matches!(a.kind, 64 | 65 | 81))
                        .any(|a| keys.contains(&(a.vendor, a.kind)))
                })
        {
            return Err(Error::Configuration("ambiguous VLAN reset encoding".into()));
        }
        Ok(())
    }
    pub fn attributes(
        &self,
        action: Action,
        target: &Target,
        desired: Option<&Authorization>,
        now: i64,
    ) -> Result<Option<Vec<Attribute>>> {
        self.validate()?;
        let Some(recipe) = self.recipes.iter().find(|r| r.action == action) else {
            return Ok(None);
        };
        if self.require_station && target.station.is_none() {
            return Err(Error::Configuration(
                "profile requires a station selector".into(),
            ));
        }
        let mut attrs = target.attributes(self.station_selector)?;
        attrs.retain(|a| {
            !matches!(a.kind, 4 | 32 | 95) || self.nas_selectors.iter().any(|s| s.kind() == a.kind)
        });
        if !attrs.iter().any(|a| matches!(a.kind, 4 | 32 | 95)) {
            return Err(Error::Configuration(
                "profile has no recorded NAS selector".into(),
            ));
        }
        if action != Action::Disconnect {
            let desired = desired.ok_or(Error::Malformed)?;
            desired.validate()?;
            if action == Action::UpdateAuthorization
                && desired.vlan.is_none()
                && self.clear_vlan.is_empty()
            {
                return Ok(None);
            }
            for encoding in &recipe.attributes {
                if action == Action::UpdateAuthorization
                    && desired.vlan.is_none()
                    && encoding.vendor.is_none()
                    && matches!(encoding.kind, 64 | 65 | 81)
                {
                    continue;
                }
                if let Some(attr) = encoding.encode(desired)? {
                    attrs.push(attr);
                }
            }
            if action == Action::UpdateAuthorization && desired.vlan.is_none() {
                for encoding in &self.clear_vlan {
                    if let Some(attr) = encoding.encode(desired)? {
                        attrs.push(attr);
                    }
                }
            }
        }
        attrs.push(Attribute::integer(
            55,
            (now / 1000).clamp(0, i64::from(u32::MAX)) as u32,
        ));
        Ok(Some(attrs))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Reconciliation {
    pub intent_signature: String,
    pub intent_epoch: u64,
    pub configuration: String,
    pub proof: Vec<u8>,
    pub checked_ms: i64,
    pub unavailable_since_ms: Option<i64>,
    pub status: String,
    pub desired: Option<Authorization>,
    /// Last accepted update is retained independently of issued and observed.
    pub requested: Option<Authorization>,
    pub observed: Option<Observed>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub vlan: Option<u16>,
    pub timeout_seconds: Option<u32>,
    pub reported_ms: i64,
}
impl Observed {
    pub fn from_attributes(attrs: &[Attribute], now: i64) -> Option<Self> {
        let vlans: Vec<_> = attrs.iter().filter(|a| a.kind == 81).collect();
        let vlan = if let [value] = vlans.as_slice() {
            let bytes = value.value.as_slice();
            let bytes = if bytes.first().is_some_and(|b| *b <= 31) {
                &bytes[1..]
            } else {
                bytes
            };
            std::str::from_utf8(bytes)
                .ok()
                .filter(|s| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|v| (1..=4094).contains(v))
        } else {
            None
        };
        let timeout_seconds = crate::model::integer(attrs, 27)
            .ok()
            .flatten()
            .filter(|v| *v != 0);
        (vlan.is_some() || timeout_seconds.is_some()).then_some(Self {
            vlan,
            timeout_seconds,
            reported_ms: now,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Enforcement {
    pub update_authorization: bool,
    pub vlan_disconnect: bool,
    pub revoke_access: bool,
    pub password_reauthenticate: bool,
    pub unavailable_grace_seconds: Option<u32>,
    pub fallback: Vec<Action>,
}
impl Default for Enforcement {
    fn default() -> Self {
        Self {
            update_authorization: false,
            vlan_disconnect: true,
            revoke_access: true,
            password_reauthenticate: true,
            unavailable_grace_seconds: None,
            fallback: vec![],
        }
    }
}
impl Enforcement {
    pub fn validate(&self) -> Result<()> {
        if self.fallback.len() > 2
            || self
                .fallback
                .iter()
                .enumerate()
                .any(|(i, a)| *a == Action::UpdateAuthorization || self.fallback[..i].contains(a))
            || self.fallback.windows(2).any(|a| a[0] == Action::Disconnect)
            || self
                .unavailable_grace_seconds
                .is_some_and(|v| v == 0 || v > 30 * 86400)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

pub fn explicitly_unsupported(cause: Option<u32>) -> bool {
    matches!(cause, Some(401 | 405 | 406))
}

#[derive(Clone, Debug)]
pub struct Intent {
    pub intent_key: String,
    pub request_id: Option<String>,
    pub session: String,
    pub actor: String,
    pub reason: String,
    pub action: Action,
    pub configuration: String,
    pub desired: Option<Authorization>,
    pub fallback: Vec<Action>,
}
