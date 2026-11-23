use crate::{
    settings::{prefix, spec, Value},
    Compiled, Result, Settings,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribute {
    pub kind: u8,
    pub value: Vec<u8>,
}
impl Attribute {
    pub fn validate(&self) -> Result<()> {
        if self.value.is_empty() || self.value.len() > 253 {
            return Err("invalid authorization attribute size".into());
        }
        if self.kind == 26 {
            if self.value.len() < 6 || self.value[5] as usize + 4 != self.value.len() {
                return Err("invalid vendor attribute framing".into());
            }
            Target {
                vendor: Some(u32::from_be_bytes(self.value[..4].try_into().unwrap())),
                attribute: self.value[4],
            }
            .validate()?;
        } else {
            Target {
                vendor: None,
                attribute: self.kind,
            }
            .validate()?;
            if matches!(self.kind,6..=10|12|27..=29|56|57|64|65|83|85|133|134|136)
                && self.value.len() != 4
            {
                return Err("integer authorization attribute requires four bytes".into());
            }
            if matches!(self.kind, 168 | 169) && self.value.len() != 16 {
                return Err("IPv6 authorization address requires sixteen bytes".into());
            }
            if self.kind == 56
                && (self.value.len() != 4
                    || !matches!(self.value[0], 0x31 | 0x32)
                    || !(1..=4094).contains(
                        &(u32::from_be_bytes(self.value[..4].try_into().unwrap()) & 0x00ff_ffff),
                    ))
            {
                return Err("invalid egress VLAN attribute".into());
            }
            if self.kind == 58 && (self.value.len() < 2 || !matches!(self.value[0], 0x31 | 0x32)) {
                return Err("invalid egress VLAN name attribute".into());
            }
            if self.kind == 59 && (self.value.len() != 8 || self.value.iter().any(|v| *v > 7)) {
                return Err("invalid priority table attribute".into());
            }
            if matches!(self.kind, 97 | 123)
                && (self.value.len() < 2
                    || self.value[0] != 0
                    || self.value[1] > 128
                    || self.value.len() != 2 + usize::from(self.value[1]).div_ceil(8))
            {
                return Err("invalid IPv6 prefix attribute".into());
            }
            if matches!(self.kind, 97 | 123)
                && !self.value[1].is_multiple_of(8)
                && self
                    .value
                    .last()
                    .is_some_and(|b| *b & ((1u8 << (8 - self.value[1] % 8)) - 1) != 0)
            {
                return Err("IPv6 prefix attribute has host bits".into());
            }
        }
        Ok(())
    }
    pub fn key(&self) -> Target {
        if self.kind == 26 && self.value.len() >= 6 {
            Target {
                vendor: Some(u32::from_be_bytes(self.value[..4].try_into().unwrap())),
                attribute: self.value[4],
            }
        } else {
            Target {
                vendor: None,
                attribute: self.kind,
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    #[serde(default)]
    pub vendor: Option<u32>,
    pub attribute: u8,
}
impl Target {
    fn validate(&self) -> Result<()> {
        if self.attribute == 0
            || self.vendor == Some(0)
            || (self.vendor == Some(311) && matches!(self.attribute,1..=6|11|12|16|17|25..=28))
            || (self.vendor.is_none()
                && !matches!(self.attribute,6..=13|22|27..=29|56..=59|64..=67|81..=83|85|88|92|96..=100|123|133..=136|168..=171))
        {
            return Err(
                "authorization mapping targets a protected or unsupported attribute".into(),
            );
        }
        Ok(())
    }
    fn wrap(&self, value: Vec<u8>) -> Result<Attribute> {
        self.validate()?;
        let out = if let Some(vendor) = self.vendor {
            if value.is_empty() || value.len() > 247 {
                return Err("vendor value exceeds bounds".into());
            }
            let mut bytes = vendor.to_be_bytes().to_vec();
            bytes.extend([self.attribute, (value.len() + 2) as u8]);
            bytes.extend(value);
            Attribute {
                kind: 26,
                value: bytes,
            }
        } else {
            Attribute {
                kind: self.attribute,
                value,
            }
        };
        out.validate()?;
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Integer32,
    Integer64,
    Text,
    BooleanInteger,
    Ipv4,
    Ipv6,
    Ipv6Prefix,
    DecimalText,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encoding {
    pub target: Target,
    pub format: Format,
    /// Exact conversion only: a value that is not representable is refused.
    #[serde(default = "one")]
    pub divisor: u64,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub suffix: String,
}
fn one() -> u64 {
    1
}
impl Encoding {
    fn validate(&self) -> Result<()> {
        self.target.validate()?;
        if self.divisor == 0
            || (self.divisor != 1
                && !matches!(
                    self.format,
                    Format::Integer32 | Format::Integer64 | Format::DecimalText
                ))
        {
            return Err("invalid mapping conversion".into());
        }
        if self.prefix.len() + self.suffix.len() > 128
            || self
                .prefix
                .chars()
                .chain(self.suffix.chars())
                .any(char::is_control)
            || ((!self.prefix.is_empty() || !self.suffix.is_empty())
                && !matches!(self.format, Format::Text | Format::DecimalText))
        {
            return Err("invalid text mapping affix".into());
        }
        if self.target.vendor.is_none() {
            let valid = match self.target.attribute {
                6 | 7 | 10 | 12 | 13 | 27..=29 | 56 | 57 | 64 | 65 | 83 | 85 | 133 | 134 | 136 => {
                    self.format == Format::Integer32
                }
                8 | 9 => self.format == Format::Ipv4,
                168 | 169 => self.format == Format::Ipv6,
                97 | 123 => self.format == Format::Ipv6Prefix,
                11 | 22 | 58 | 66 | 67 | 81 | 82 | 88 | 92 | 99 | 100 | 135 | 171 => {
                    self.format == Format::Text
                }
                _ => false,
            };
            if !valid {
                return Err("mapping format does not match the standard attribute type".into());
            }
        }
        if self.target.vendor.is_none() && matches!(self.target.attribute, 27 | 29 | 64 | 65 | 81) {
            return Err("timer and VLAN attributes are owned by the authorization encoder".into());
        }
        Ok(())
    }
    fn encode(&self, value: &Value) -> Result<Vec<Attribute>> {
        self.validate()?;
        let items: Vec<Value> = match value {
            Value::List(v) => v.iter().cloned().map(Value::Text).collect(),
            v => vec![v.clone()],
        };
        items.iter().map(|item| {
            let bytes=match (self.format,item) {
                (Format::Integer32,Value::Number(n)) if n%self.divisor==0 => u32::try_from(n/self.divisor).map_err(|_|"setting exceeds equipment's 32-bit range")?.to_be_bytes().to_vec(),
                (Format::Integer64,Value::Number(n)) if n%self.divisor==0 => (n/self.divisor).to_be_bytes().to_vec(),
                (Format::Text,Value::Text(s))=>s.as_bytes().to_vec(),
                (Format::DecimalText,Value::Number(n)) if n%self.divisor==0 => (n/self.divisor).to_string().into_bytes(),
                (Format::BooleanInteger,Value::Boolean(v))=>u32::from(*v).to_be_bytes().to_vec(),
                (Format::Ipv4,Value::Text(s))=>s.parse::<Ipv4Addr>().map_err(|_|"invalid IPv4 address")?.octets().to_vec(),
                (Format::Ipv6,Value::Text(s))=>s.parse::<Ipv6Addr>().map_err(|_|"invalid IPv6 address")?.octets().to_vec(),
                (Format::Ipv6Prefix,Value::Text(s))=>{let (ip,bits)=prefix(s)?;let mut bytes=vec![0,bits];bytes.extend_from_slice(&ip.octets()[..usize::from(bits).div_ceil(8)]);bytes},
                _=>return Err("setting type or exact unit conversion is incompatible with equipment mapping".into()),
            };let mut wrapped=self.prefix.as_bytes().to_vec();wrapped.extend(bytes);wrapped.extend_from_slice(self.suffix.as_bytes());self.target.wrap(wrapped)
        }).collect()
    }
}

/// Optional overrides for named, logical settings. Empty entries explicitly
/// mark unsupported settings; missing entries use only a defined standard.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mappings {
    pub settings: BTreeMap<String, Vec<Encoding>>,
    /// Settings qualified for live updates, independently of admission support.
    pub live: BTreeSet<String>,
    /// Explicit device reset values for a setting removed by live CoA.
    pub clear: BTreeMap<String, Vec<Attribute>>,
}
impl Mappings {
    /// Published WISPr admission encodings. Live support is deliberately empty
    /// until the operator qualifies the receiving equipment's CoA behavior.
    pub fn wispr_rates() -> Self {
        let mut mappings = Self::default();
        for (name, attribute) in [("UploadBitsPerSecond", 7), ("DownloadBitsPerSecond", 8)] {
            mappings.settings.insert(
                name.into(),
                vec![Encoding {
                    target: Target {
                        vendor: Some(14122),
                        attribute,
                    },
                    format: Format::Integer32,
                    divisor: 1,
                    prefix: String::new(),
                    suffix: String::new(),
                }],
            );
        }
        mappings
    }
    pub fn validate(&self) -> Result<()> {
        if self.settings.len() > 80 || self.clear.len() > 80 {
            return Err("too many equipment mappings".into());
        }
        for (name, encodings) in &self.settings {
            if (spec(name).is_none() && !name.starts_with("Extension."))
                || (!encodings.is_empty()
                    && matches!(
                        name.as_str(),
                        "SessionTimeoutSeconds"
                            | "SessionExpiryAction"
                            | "ReauthenticateSeconds"
                            | "VlanName"
                            | "TaggedVlans"
                            | "UntaggedVlans"
                            | "TaggedVlanNames"
                            | "UntaggedVlanNames"
                            | "TunnelType"
                            | "TunnelMediumType"
                            | "TunnelPreference"
                            | "UserPriorityTable"
                            | "IngressFiltering"
                    ))
                || encodings.len() > 8
            {
                return Err(format!("invalid equipment setting mapping {name}"));
            }
            for encoding in encodings {
                encoding.validate()?;
                if name.starts_with("Extension.") && encoding.target.vendor.is_none() {
                    return Err("extensions require a vendor namespace".into());
                }
            }
        }
        for (name, attributes) in &self.clear {
            if spec(name).is_none() && !name.starts_with("Extension.") {
                return Err("unknown equipment reset setting".into());
            }
            crate::validate_attributes(attributes)?;
            if attributes.is_empty() {
                return Err("setting reset requires explicit wire attributes".into());
            }
        }
        if self.live.len() > 80
            || self
                .live
                .iter()
                .any(|n| spec(n).is_none() && !n.starts_with("Extension."))
        {
            return Err("unknown live-update capability".into());
        }
        Ok(())
    }
    pub fn compile(&self, settings: &Settings, vlan: Option<u16>) -> Result<Compiled> {
        settings.validate()?;
        self.validate()?;
        if vlan.is_some()
            && settings
                .0
                .keys()
                .any(|k| k == "VlanName" || k.starts_with("Tunnel"))
        {
            return Err("VLAN ID and another tunnel assignment conflict".into());
        }
        if let (Some(vlan), Some(Value::List(tagged))) = (vlan, settings.0.get("TaggedVlans")) {
            if tagged.contains(&vlan.to_string()) {
                return Err("the untagged VLAN assignment cannot be a tagged membership".into());
            }
        }
        let mut attributes = Vec::new();
        let mut groups = BTreeMap::new();
        let mut owners: BTreeMap<Target, &str> = BTreeMap::new();
        for (name, value) in &settings.0 {
            if self.settings.get(name).is_some_and(Vec::is_empty) {
                return Err(format!("equipment does not support {name}"));
            }
            if matches!(
                name.as_str(),
                "ReauthenticateSeconds" | "SessionTimeoutSeconds" | "SessionExpiryAction"
            ) || (name == "ServiceLabel" && !self.settings.contains_key(name))
            {
                continue;
            }
            let encoded = if let Some(encodings) = self.settings.get(name) {
                if encodings.is_empty() {
                    return Err(format!("equipment does not support {name}"));
                }
                encodings
                    .iter()
                    .map(|encoding| encoding.encode(value))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .flatten()
                    .collect()
            } else {
                standard(name, value)?
            };
            groups.insert(name.clone(), encoded.clone());
            for attribute in encoded {
                let key = attribute.key();
                if let Some(prior) = owners.insert(key, name) {
                    if prior != name
                        && !matches!(
                            (prior, name.as_str()),
                            ("TaggedVlans", "UntaggedVlans")
                                | ("UntaggedVlans", "TaggedVlans")
                                | ("TaggedVlanNames", "UntaggedVlanNames")
                                | ("UntaggedVlanNames", "TaggedVlanNames")
                        )
                    {
                        return Err(format!("{prior} and {name} encode the same attribute"));
                    }
                }
                attributes.push(attribute);
            }
        }
        let out = Compiled {
            settings: settings.clone(),
            attributes,
            encoded: groups,
        };
        out.validate()?;
        Ok(out)
    }
    /// CoA removal is never inferred from omission. Refuse the update unless
    /// the device declares how the previous setting is reset.
    pub fn updates(&self, previous: &Compiled, desired: &Compiled) -> Result<Vec<Attribute>> {
        previous.validate()?;
        desired.validate()?;
        self.validate()?;
        let mut attributes = Vec::new();
        let changed: BTreeSet<_> = previous
            .settings
            .0
            .keys()
            .chain(desired.settings.0.keys())
            .filter(|name| {
                previous.settings.0.get(*name) != desired.settings.0.get(*name)
                    || previous.encoded.get(*name) != desired.encoded.get(*name)
            })
            .collect();
        for name in changed.iter().copied() {
            if !matches!(
                name.as_str(),
                "SessionTimeoutSeconds" | "SessionExpiryAction" | "ReauthenticateSeconds"
            ) && (previous.encoded.contains_key(name) || desired.encoded.contains_key(name))
                && !self.live.contains(name)
            {
                return Err(format!(
                    "equipment has no qualified live-update support for {name}"
                ));
            }
            if let Some(encoded) = desired.encoded.get(name) {
                if encoded.iter().any(|a| matches!(a.kind, 133 | 134)) {
                    return Err(
                        "management protocol and transport changes require fresh authentication"
                            .into(),
                    );
                }
                if let Some(old) = previous.encoded.get(name) {
                    if old
                        .iter()
                        .any(|a| !encoded.iter().any(|new| new.key() == a.key()))
                    {
                        return Err(
                            "live mapping identity changed; fresh authentication required".into(),
                        );
                    }
                }
                attributes.extend(encoded.clone());
            }
        }
        // VLAN membership families share one attribute identity. A receiver
        // replaces its complete list, so preserve the unchanged companion.
        let changed_targets: BTreeSet<_> = attributes.iter().map(Attribute::key).collect();
        for (name, encoded) in &desired.encoded {
            if !changed.contains(name) && encoded.iter().any(|a| changed_targets.contains(&a.key()))
            {
                attributes.extend(encoded.clone());
            }
        }
        for name in previous
            .settings
            .0
            .keys()
            .filter(|n| !desired.settings.0.contains_key(*n))
        {
            if matches!(
                name.as_str(),
                "SessionTimeoutSeconds" | "SessionExpiryAction" | "ReauthenticateSeconds"
            ) {
                continue;
            }
            if !previous.encoded.contains_key(name) {
                continue;
            }
            let resets = self
                .clear
                .get(name)
                .ok_or_else(|| format!("equipment has no reset encoding for {name}"))?;
            let prior = previous
                .encoded
                .get(name)
                .ok_or("previous setting encoding is unknown")?;
            if resets.iter().any(|a| {
                matches!(a.kind, 133 | 134)
                    || !prior.iter().any(|p| p.key() == a.key())
                    || desired.attributes.iter().any(|d| d.key() == a.key())
            }) {
                return Err("reset targets another active setting".into());
            }
            attributes.extend(resets.clone());
        }
        crate::validate_attributes(&attributes)?;
        Ok(attributes)
    }
}
fn standard(name: &str, value: &Value) -> Result<Vec<Attribute>> {
    let spec = spec(name).ok_or_else(|| format!("equipment mapping required for {name}"))?;
    let kind = spec
        .attribute
        .ok_or_else(|| format!("equipment mapping required for {name}"))?;
    let wrap = |bytes: Vec<u8>| {
        Target {
            vendor: None,
            attribute: kind,
        }
        .wrap(bytes)
    };
    match (name, value) {
        ("TaggedVlans" | "UntaggedVlans", Value::List(v)) => v
            .iter()
            .map(|v| {
                let id = v.parse::<u32>().map_err(|_| "invalid VLAN")?;
                wrap(
                    (id | if name == "TaggedVlans" {
                        0x3100_0000
                    } else {
                        0x3200_0000
                    })
                    .to_be_bytes()
                    .to_vec(),
                )
            })
            .collect(),
        ("IngressFiltering", Value::Boolean(v)) => Ok(vec![wrap(
            if *v { 1u32 } else { 2u32 }.to_be_bytes().to_vec(),
        )?]),
        ("VlanName", Value::Text(v)) => {
            let mut name = vec![0x32];
            name.extend_from_slice(v.as_bytes());
            Ok(vec![wrap(name)?])
        }
        ("TaggedVlanNames" | "UntaggedVlanNames", Value::List(v)) => v
            .iter()
            .map(|v| {
                let mut name = vec![if spec.name == "TaggedVlanNames" {
                    0x31
                } else {
                    0x32
                }];
                name.extend_from_slice(v.as_bytes());
                wrap(name)
            })
            .collect(),
        ("UserPriorityTable", Value::Text(v)) => {
            Ok(vec![wrap(v.bytes().map(|b| b - b'0').collect())?])
        }
        (
            "TunnelClientEndpoint" | "TunnelServerEndpoint" | "TunnelAssignmentId",
            Value::Text(v),
        ) => {
            let mut tagged = vec![0];
            tagged.extend_from_slice(v.as_bytes());
            Ok(vec![wrap(tagged)?])
        }
        _ => {
            let format = if matches!(kind, 8 | 9) {
                Format::Ipv4
            } else if matches!(kind, 168 | 169) {
                Format::Ipv6
            } else if matches!(kind, 97 | 123) {
                Format::Ipv6Prefix
            } else if matches!(value, Value::Number(_)) {
                Format::Integer32
            } else {
                Format::Text
            };
            // The fixed standard encoder owns these fields; user overrides do
            // not gain permission to redirect them.
            if matches!(kind, 64 | 65 | 83) {
                let Value::Number(v) = value else {
                    return Err("tunnel integer required".into());
                };
                if *v > 0x00ff_ffff {
                    return Err("tunnel value exceeds 24-bit range".into());
                }
                return Ok(vec![wrap((*v as u32).to_be_bytes().to_vec())?]);
            }
            Encoding {
                target: Target {
                    vendor: None,
                    attribute: kind,
                },
                format,
                divisor: 1,
                prefix: String::new(),
                suffix: String::new(),
            }
            .encode(value)
        }
    }
}
