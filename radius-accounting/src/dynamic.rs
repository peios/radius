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
    #[serde(default)]
    pub attributes: radius_authorization::Compiled,
    /// The policy cap before current allowance balances shorten this reply.
    #[serde(default)]
    pub configured_timeout_seconds: Option<u32>,
}
impl Authorization {
    pub fn same_policy(&self, other: &Self) -> bool {
        self.vlan == other.vlan
            && self.attributes == other.attributes
            && self
                .configured_timeout_seconds
                .unwrap_or(self.timeout_seconds)
                == other
                    .configured_timeout_seconds
                    .unwrap_or(other.timeout_seconds)
    }
    pub fn validate(&self) -> Result<()> {
        self.attributes.validate().map_err(Error::Configuration)?;
        if self.vlan.is_some_and(|v| !(1..=4094).contains(&v))
            || self.timeout_seconds == 0
            || self
                .configured_timeout_seconds
                .is_some_and(|v| v == 0 || self.timeout_seconds > v)
        {
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
    /// Last acknowledged update for this proof, or its original issued state.
    /// Legacy issued records kept the configured cap in the enclosing proof.
    pub fn baseline(&self, acknowledged: Option<&Authorization>) -> Authorization {
        let mut baseline = acknowledged.unwrap_or(&self.issued).clone();
        if acknowledged.is_none() && baseline.configured_timeout_seconds.is_none() {
            baseline.configured_timeout_seconds = Some(self.configured_timeout_seconds);
        }
        baseline
    }
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
    /// Some NAS implementations reject Proxy-State in dynamic requests.
    /// Durable identifier reservations remain mandatory in either mode.
    #[serde(default = "yes")]
    pub proxy_state_nonce: bool,
    #[serde(default = "identifier_window")]
    pub identifier_reuse_seconds: u32,
    /// Clearing a VLAN override has no universal standard CoA encoding.
    #[serde(default)]
    pub clear_vlan: Vec<Encoding>,
    /// Shared admission/CoA mapping for typed access-profile settings.
    #[serde(default)]
    pub authorization: radius_authorization::Mappings,
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
pub fn identifier_window() -> u32 {
    300
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            name: "RFC 5176".into(),
            station_selector: true,
            require_station: false,
            nas_selectors: all_nas_selectors(),
            proxy_state_nonce: true,
            identifier_reuse_seconds: identifier_window(),
            clear_vlan: vec![],
            authorization: Default::default(),
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
    pub fn wispr_rates() -> Self {
        Self {
            name: "RFC 5176 with WISPr admission rates".into(),
            authorization: radius_authorization::Mappings::wispr_rates(),
            ..Self::default()
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65536 {
            return Err(Error::Limit);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.authorization
            .validate()
            .map_err(Error::Configuration)?;
        if self.version != 1
            || self.name.is_empty()
            || self.name.len() > 128
            || self.recipes.is_empty()
            || self.recipes.len() > 3
            || self.clear_vlan.len() > 16
            || !(1..=86400).contains(&self.identifier_reuse_seconds)
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
        self.attributes_with_previous(action, target, desired, None, now)
    }
    pub fn attributes_with_previous(
        &self,
        action: Action,
        target: &Target,
        desired: Option<&Authorization>,
        previous: Option<&Authorization>,
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
                && previous.is_none_or(|p| p.vlan.is_some())
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
            if action == Action::UpdateAuthorization {
                let empty = radius_authorization::Compiled::default();
                let old = previous.map(|p| &p.attributes).unwrap_or(&empty);
                let extra = match self.authorization.updates(old, &desired.attributes) {
                    Ok(a) => a,
                    Err(_) => return Ok(None),
                };
                let occupied: std::collections::BTreeSet<_> = attrs
                    .iter()
                    .map(|a| {
                        radius_authorization::Attribute {
                            kind: a.kind,
                            value: a.value.clone(),
                        }
                        .key()
                    })
                    .collect();
                for value in extra {
                    let key = value.key();
                    if occupied.contains(&key) {
                        return Ok(None);
                    }
                    attrs.push(Attribute {
                        kind: value.kind,
                        value: value.value,
                    });
                }
                let disconnect = desired.attributes.settings.timer(desired.timeout_seconds).1;
                let action = u32::from(!disconnect);
                if attrs.iter().filter(|a| a.kind == 27).count() != 1
                    || attrs.iter().any(|a| {
                        (a.kind == 27 && a.value != desired.timeout_seconds.to_be_bytes())
                            || (a.kind == 29 && a.value != action.to_be_bytes())
                    })
                {
                    // A custom recipe must express the authorization retained
                    // in its proof; an ACK cannot validate a different timer.
                    return Ok(None);
                }
                if !attrs.iter().any(|a| a.kind == 29) {
                    attrs.push(Attribute::integer(29, action));
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
