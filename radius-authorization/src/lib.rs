//! Typed network-service settings and bounded, declarative equipment encodings.
//! This library neither authenticates principals nor allocates network resources.
#![forbid(unsafe_code)]

mod encoding;
mod settings;
pub use encoding::{Attribute, Encoding, Format, Mappings, Target};
pub use settings::{spec, Kind, Settings, Spec, Value, FIELDS};
pub type Result<T> = std::result::Result<T, String>;

pub const MAX_ATTRIBUTES: usize = 96;
pub const MAX_BYTES: usize = 2400;

/// A complete compiled reply. Serialize this alongside the logical decision so
/// equipment mapping changes are observable even when profile values agree.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Compiled {
    pub settings: Settings,
    pub attributes: Vec<Attribute>,
    pub encoded: std::collections::BTreeMap<String, Vec<Attribute>>,
}
impl Compiled {
    pub fn validate(&self) -> Result<()> {
        self.settings.validate()?;
        if self.settings.0.keys().any(|name| {
            !matches!(
                name.as_str(),
                "SessionTimeoutSeconds"
                    | "SessionExpiryAction"
                    | "ReauthenticateSeconds"
                    | "ServiceLabel"
            ) && !self.encoded.contains_key(name)
        }) || self.encoded.values().any(Vec::is_empty)
        {
            return Err("authorization setting has no attributed encoding".into());
        }
        if self
            .encoded
            .keys()
            .any(|k| !self.settings.0.contains_key(k))
            || self.encoded.values().flatten().ne(self.attributes.iter())
        {
            return Err("authorization encoding attribution does not match the reply".into());
        }
        validate_attributes(&self.attributes)
    }
}

pub fn validate_attributes(attributes: &[Attribute]) -> Result<()> {
    if attributes.len() > MAX_ATTRIBUTES
        || attributes.iter().map(|a| a.value.len() + 2).sum::<usize>() > MAX_BYTES
    {
        return Err("authorization attributes exceed reply budget".into());
    }
    for attribute in attributes {
        attribute.validate()?;
    }
    Ok(())
}
