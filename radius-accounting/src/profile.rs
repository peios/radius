//! Bounded declarative vendor profiles, not executable plugins.
use crate::{model::Observation, wire::Attribute, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub vendor: u32,
    pub kind: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    Nas,
    Session,
    Subsystem,
    Username,
    Station,
    CalledStation,
    Input,
    Output,
    Status,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    Bytes,
    BigEndian32,
    BigEndian64,
    Decimal,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub key: Key,
    pub target: Target,
    pub encoding: Encoding,
    #[serde(default)]
    pub replace: bool,
    #[serde(default)]
    pub mapping: Vec<(u64, u64)>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dictionary {
    pub key: Key,
    pub name: String,
    pub encoding: Encoding,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub dictionary: Vec<Dictionary>,
}
impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65536 {
            return Err(Error::Limit);
        }
        let profile: Self = serde_json::from_slice(bytes)?;
        profile.validate()?;
        Ok(profile)
    }
    pub fn validate(&self) -> Result<()> {
        let mut targets = BTreeSet::new();
        if self.version != 1
            || self.name.is_empty()
            || self.name.len() > 128
            || self.rules.len() > 32
            || self.dictionary.len() > 128
        {
            return Err(Error::Configuration("profile bounds/version".into()));
        }
        for rule in &self.rules {
            if !targets.insert(format!("{:?}", rule.target))
                || rule.mapping.len() > 64
                || rule.key.kind == 0
                || (matches!(rule.target, Target::Status | Target::Input | Target::Output)
                    && rule.encoding == Encoding::Bytes)
                || (rule.encoding == Encoding::Bytes && !rule.mapping.is_empty())
                || rule
                    .mapping
                    .iter()
                    .map(|(from, _)| from)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != rule.mapping.len()
            {
                return Err(Error::Configuration(
                    "invalid or duplicate profile target".into(),
                ));
            }
        }
        let mut keys = BTreeSet::new();
        for entry in &self.dictionary {
            if entry.name.is_empty()
                || entry.name.len() > 128
                || entry.key.kind == 0
                || !keys.insert((entry.key.vendor, entry.key.kind))
            {
                return Err(Error::Configuration("invalid dictionary entry".into()));
            }
        }
        Ok(())
    }
    pub fn apply(&self, observation: &mut Observation) -> Result<()> {
        self.validate()?;
        for rule in &self.rules {
            let Some(value) = extract(&observation.attributes, &rule.key)? else {
                continue;
            };
            let mut numeric = match rule.encoding {
                Encoding::Bytes => None,
                Encoding::BigEndian32 => {
                    value.try_into().ok().map(u32::from_be_bytes).map(u64::from)
                }
                Encoding::BigEndian64 => value.try_into().ok().map(u64::from_be_bytes),
                Encoding::Decimal => std::str::from_utf8(value)
                    .ok()
                    .filter(|s| s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|s| s.parse().ok()),
            };
            if rule.encoding != Encoding::Bytes && numeric.is_none() {
                observation.warnings.push("invalid-vendor-value".into());
                continue;
            }
            if let Some(number) = numeric {
                if let Some((_, replacement)) =
                    rule.mapping.iter().find(|(from, _)| *from == number)
                {
                    numeric = Some(*replacement);
                }
            }
            let byte_value = || {
                if rule.encoding == Encoding::Bytes {
                    value.to_vec()
                } else {
                    numeric.unwrap().to_be_bytes().to_vec()
                }
            };
            match rule.target {
                Target::Nas if rule.replace || observation.nas.is_empty() => {
                    observation.nas = byte_value();
                }
                Target::Session if rule.replace || observation.session.is_none() => {
                    observation.session = Some(byte_value())
                }
                Target::Subsystem if rule.replace || observation.subsystem.is_none() => {
                    observation.subsystem = Some(byte_value())
                }
                Target::Username if rule.replace || observation.username.is_none() => {
                    observation.username = Some(byte_value())
                }
                Target::Station if rule.replace || observation.station.is_none() => {
                    observation.station = Some(byte_value())
                }
                Target::CalledStation if rule.replace || observation.called_station.is_none() => {
                    observation.called_station = Some(byte_value())
                }
                Target::Input if rule.replace || observation.input.is_none() => {
                    observation.input = numeric
                }
                Target::Output if rule.replace || observation.output.is_none() => {
                    observation.output = numeric
                }
                Target::Status if rule.replace || observation.status == 0 => {
                    observation.status = u32::try_from(numeric.ok_or(Error::Malformed)?)
                        .map_err(|_| Error::Malformed)?
                }
                _ => {}
            }
        }
        Ok(())
    }
}
pub fn extract<'a>(attrs: &'a [Attribute], key: &Key) -> Result<Option<&'a [u8]>> {
    let mut found = None;
    for a in attrs {
        if key.vendor == 0 {
            if a.kind == key.kind && found.replace(a.value.as_slice()).is_some() {
                return Err(Error::Malformed);
            }
        } else if a.kind == 26 && a.value.len() >= 4 && a.value[..4] == key.vendor.to_be_bytes() {
            let mut at = 4;
            while at < a.value.len() {
                if at + 2 > a.value.len() {
                    return Err(Error::Malformed);
                }
                let len = a.value[at + 1] as usize;
                if len < 2 || at + len > a.value.len() {
                    return Err(Error::Malformed);
                }
                if a.value[at] == key.kind && found.replace(&a.value[at + 2..at + len]).is_some() {
                    return Err(Error::Malformed);
                }
                at += len;
            }
        }
    }
    Ok(found)
}
