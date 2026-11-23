use crate::{Compiled, Mappings, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Number,
    Text,
    List,
    Boolean,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Spec {
    pub name: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub kind: Kind,
    pub attribute: Option<u8>,
}
macro_rules! fields {
    ($($group:literal { $($name:literal, $label:literal, $kind:ident, $attribute:expr;)* })*) => {
        pub const FIELDS: &[Spec] = &[$($(Spec {name:$name,label:$label,group:$group,kind:Kind::$kind,attribute:$attribute},)*)*];
    }
}
fields! {
    "Connection" {
        "ReauthenticateSeconds", "Reauthenticate After (seconds)", Number, Some(27);
        "SessionTimeoutSeconds", "Session Timeout (seconds)", Number, Some(27);
        "SessionExpiryAction", "Session Expiry Action", Text, Some(29);
        "IdleTimeoutSeconds", "Idle Timeout (seconds)", Number, Some(28);
    }
    "Bandwidth and Priority" {
        "DownloadBitsPerSecond", "Download Limit (bits/second)", Number, None;
        "UploadBitsPerSecond", "Upload Limit (bits/second)", Number, None;
        "DownloadBurstBytes", "Download Burst (bytes)", Number, None;
        "UploadBurstBytes", "Upload Burst (bytes)", Number, None;
        "MinimumDownloadBitsPerSecond", "Minimum Download Rate (bits/second)", Number, None;
        "MinimumUploadBitsPerSecond", "Minimum Upload Rate (bits/second)", Number, None;
        "ServiceClass", "Service Class", Text, None;
        "Priority", "Traffic Priority", Number, None;
        "UserPriorityTable", "802.1p Priority Map", Text, Some(59);
    }
    "Segmentation and Traffic" {
        "VlanName", "VLAN Name", Text, Some(58);
        "TaggedVlanNames", "Tagged VLAN Names", List, Some(58);
        "UntaggedVlanNames", "Untagged VLAN Names", List, Some(58);
        "TaggedVlans", "Tagged VLAN IDs", List, Some(56);
        "UntaggedVlans", "Untagged VLAN IDs", List, Some(56);
        "IngressFiltering", "Ingress Filtering", Boolean, Some(57);
        "AccessRole", "Access Role", Text, None;
        "FilterIds", "Named Filters", List, Some(11);
        "FilterRules", "NAS Filter Rules", List, Some(92);
        "ClientIsolation", "Client Isolation", Boolean, None;
    }
    "Addressing and Routing" {
        "FramedIpv4Address", "IPv4 Address", Text, Some(8);
        "FramedIpv4Netmask", "IPv4 Netmask", Text, Some(9);
        "Ipv4Pool", "IPv4 Address Pool", Text, Some(88);
        "Ipv4Routes", "IPv4 Routes", List, Some(22);
        "FramedIpv6Address", "IPv6 Address", Text, Some(168);
        "FramedIpv6Prefix", "IPv6 Prefix", Text, Some(97);
        "DelegatedIpv6Prefix", "Delegated IPv6 Prefix", Text, Some(123);
        "Ipv6Pool", "IPv6 Address Pool", Text, Some(100);
        "DelegatedIpv6Pool", "Delegated IPv6 Pool", Text, Some(171);
        "Ipv6Routes", "IPv6 Routes", List, Some(99);
        "Ipv4DnsServers", "IPv4 DNS Servers", List, None;
        "Ipv6DnsServers", "IPv6 DNS Servers", List, Some(169);
        "Mtu", "MTU (bytes)", Number, Some(12);
    }
    "Tunnels and Service" {
        "ServiceType", "RADIUS Service Type", Number, Some(6);
        "FramedProtocol", "Framed Protocol", Number, Some(7);
        "TunnelType", "Tunnel Type", Number, Some(64);
        "TunnelMediumType", "Tunnel Medium Type", Number, Some(65);
        "TunnelClientEndpoint", "Tunnel Client Endpoint", Text, Some(66);
        "TunnelServerEndpoint", "Tunnel Server Endpoint", Text, Some(67);
        "TunnelAssignmentId", "Tunnel Assignment ID", Text, Some(82);
        "TunnelPreference", "Tunnel Preference", Number, Some(83);
    }
    "Accounting" {
        "AccountingInterimSeconds", "Accounting Update Interval (seconds)", Number, Some(85);
        "ServiceLabel", "Reporting Service Label", Text, None;
    }
    "Device Administration" {
        "ManagementProtocol", "Management Protocol", Number, Some(133);
        "ManagementTransportProtection", "Management Transport Protection", Number, Some(134);
        "ManagementPolicyId", "Management Policy ID", Text, Some(135);
        "ManagementPrivilegeLevel", "Management Privilege Level", Number, Some(136);
    }
}
pub fn spec(name: &str) -> Option<&'static Spec> {
    FIELDS.iter().find(|f| f.name == name)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Number(u64),
    Boolean(bool),
    Text(String),
    List(Vec<String>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Settings(pub BTreeMap<String, Value>);
impl Settings {
    pub fn number(&self, name: &str) -> Option<u64> {
        match self.0.get(name) {
            Some(Value::Number(v)) => Some(*v),
            _ => None,
        }
    }
    pub fn text(&self, name: &str) -> Option<&str> {
        match self.0.get(name) {
            Some(Value::Text(v)) => Some(v),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.0.len() > 80 {
            return Err("too many authorization settings".into());
        }
        for (name, value) in &self.0 {
            let spec = spec(name);
            if spec.is_none()
                && !(name.starts_with("Extension.")
                    && name.len() <= 96
                    && name[10..]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                    && name.len() > 10)
            {
                return Err(format!("unknown authorization setting {name}"));
            }
            let kind = match value {
                Value::Number(_) => Kind::Number,
                Value::Boolean(_) => Kind::Boolean,
                Value::Text(_) => Kind::Text,
                Value::List(_) => Kind::List,
            };
            if spec.is_some_and(|s| s.kind != kind) {
                return Err(format!("wrong type for {name}"));
            }
            if let Value::Number(v) = value {
                if (*v == 0 && !matches!(name.as_str(), "Priority" | "ManagementPrivilegeLevel"))
                    || (*v > u32::MAX as u64
                        && !name.ends_with("BitsPerSecond")
                        && !name.ends_with("BurstBytes")
                        && !name.starts_with("Extension."))
                {
                    return Err(format!("{name} exceeds its range"));
                }
                if (name == "Mtu" && !(64..=65535).contains(v))
                    || (name == "AccountingInterimSeconds" && *v < 60)
                    || (name == "Priority" && *v > 7)
                    || (name == "TunnelType" && *v > 0x00ff_ffff)
                    || (matches!(name.as_str(), "TunnelMediumType" | "TunnelPreference")
                        && *v > 0x00ff_ffff)
                    || (name == "ManagementTransportProtection" && *v > 3)
                {
                    return Err(format!("invalid {name}"));
                }
            }
            let strings: Vec<&str> = match value {
                Value::Text(v) => vec![v],
                Value::List(v) => {
                    if v.is_empty() || v.len() > 32 {
                        return Err(format!("invalid list length for {name}"));
                    }
                    if v.iter().collect::<std::collections::BTreeSet<_>>().len() != v.len() {
                        return Err(format!("duplicate {name} values"));
                    }
                    v.iter().map(String::as_str).collect()
                }
                _ => vec![],
            };
            for s in strings {
                if s.is_empty() || s.len() > 240 || s.chars().any(char::is_control) {
                    return Err(format!("invalid text for {name}"));
                }
                match name.as_str() {
                    "SessionExpiryAction" if !matches!(s, "disconnect" | "reauthenticate") => {
                        return Err("invalid session expiry action".into())
                    }
                    "FramedIpv4Address" | "FramedIpv4Netmask" | "Ipv4DnsServers" => {
                        let address = s
                            .parse::<Ipv4Addr>()
                            .map_err(|_| format!("invalid {name}"))?;
                        let inverted = !u32::from(address);
                        if name == "FramedIpv4Netmask" && inverted & inverted.wrapping_add(1) != 0 {
                            return Err("IPv4 netmask must be contiguous".into());
                        }
                    }
                    "FramedIpv6Address" | "Ipv6DnsServers" => {
                        s.parse::<Ipv6Addr>()
                            .map_err(|_| format!("invalid {name}"))?;
                    }
                    "FramedIpv6Prefix" | "DelegatedIpv6Prefix" => {
                        prefix(s)?;
                    }
                    "TaggedVlans" | "UntaggedVlans" => {
                        if s.parse::<u16>()
                            .ok()
                            .filter(|v| (1..=4094).contains(v) && v.to_string() == s)
                            .is_none()
                        {
                            return Err("VLAN must be 1 through 4094".into());
                        }
                    }
                    "UserPriorityTable"
                        if s.len() != 8 || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) =>
                    {
                        return Err("priority map requires eight digits 0 through 7".into())
                    }
                    "Ipv4Routes" => route(s, false)?,
                    "Ipv6Routes" => route(s, true)?,
                    "FilterRules" => filter(s)?,
                    _ => {}
                }
            }
        }
        for direction in ["Upload", "Download"] {
            if self
                .number(&format!("Minimum{direction}BitsPerSecond"))
                .zip(self.number(&format!("{direction}BitsPerSecond")))
                .is_some_and(|(minimum, maximum)| minimum > maximum)
            {
                return Err("minimum rate exceeds maximum rate".into());
            }
        }
        if self.0.contains_key("SessionExpiryAction")
            && !self.0.contains_key("SessionTimeoutSeconds")
        {
            return Err("expiry action requires a session timeout".into());
        }
        if self.0.contains_key("SessionTimeoutSeconds")
            && self.0.contains_key("ReauthenticateSeconds")
        {
            return Err("one RADIUS timer cannot request both expiry actions; choose SessionTimeoutSeconds or ReauthenticateSeconds".into());
        }
        if self.0.contains_key("FramedIpv4Address") && self.0.contains_key("Ipv4Pool") {
            return Err("choose an IPv4 address or pool".into());
        }
        if self.0.contains_key("FramedIpv6Address") && self.0.contains_key("Ipv6Pool") {
            return Err("choose an IPv6 address or pool".into());
        }
        if self.0.contains_key("VlanName")
            && (self.0.contains_key("TaggedVlanNames") || self.0.contains_key("UntaggedVlanNames"))
        {
            return Err("choose a single VLAN name or explicit memberships".into());
        }
        for (tagged, untagged) in [
            ("TaggedVlans", "UntaggedVlans"),
            ("TaggedVlanNames", "UntaggedVlanNames"),
        ] {
            if let (Some(Value::List(a)), Some(Value::List(b))) =
                (self.0.get(tagged), self.0.get(untagged))
            {
                if a.iter().any(|v| b.contains(v)) {
                    return Err("a VLAN cannot be both tagged and untagged".into());
                }
            }
        }
        if self.0.keys().any(|k| k.starts_with("Tunnel"))
            && !(self.0.contains_key("TunnelType") && self.0.contains_key("TunnelMediumType"))
        {
            return Err("tunnel settings require type and medium".into());
        }
        if self.number("ServiceType") == Some(17) {
            return Err("Authorize-Only is not an access-profile service".into());
        }
        if self.0.keys().any(|k| k.starts_with("Management"))
            && !matches!(self.number("ServiceType"), Some(6 | 7 | 18))
        {
            return Err("management settings require a management ServiceType".into());
        }
        if self.0.contains_key("ManagementProtocol") && self.number("ServiceType") != Some(18) {
            return Err("ManagementProtocol requires Framed-Management ServiceType 18".into());
        }
        Ok(())
    }
    /// A profile timer can shorten the network cap; allowance policy can shorten
    /// it again. The action is explicit so an expiry never accidentally renews.
    pub fn timer(&self, network_seconds: u32) -> (u32, bool) {
        let seconds = self
            .number("SessionTimeoutSeconds")
            .or_else(|| self.number("ReauthenticateSeconds"))
            .unwrap_or(network_seconds as u64)
            .min(network_seconds as u64) as u32;
        (
            seconds,
            self.0.contains_key("SessionTimeoutSeconds")
                && self.text("SessionExpiryAction").unwrap_or("disconnect") == "disconnect",
        )
    }
    pub fn compile(&self, vlan: Option<u16>, mappings: &Mappings) -> Result<Compiled> {
        self.validate()?;
        mappings.compile(self, vlan)
    }
}

fn route(value: &str, ipv6: bool) -> Result<()> {
    let parts: Vec<_> = value.split_whitespace().collect();
    if !(2..=3).contains(&parts.len()) {
        return Err("route requires destination, gateway and optional metric".into());
    }
    if ipv6 {
        prefix(parts[0])?;
        parts[1]
            .parse::<Ipv6Addr>()
            .map_err(|_| "invalid IPv6 route gateway")?;
    } else {
        ipv4_prefix(parts[0])?;
        parts[1]
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid IPv4 route gateway")?;
    }
    if parts.get(2).is_some_and(|p| p.parse::<u32>().is_err()) {
        return Err("invalid route metric".into());
    }
    Ok(())
}
fn ipv4_prefix(value: &str) -> Result<()> {
    let (address, bits) = value.split_once('/').unwrap_or((value, "32"));
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| "invalid IPv4 prefix")?;
    let bits = bits
        .parse::<u8>()
        .map_err(|_| "invalid IPv4 prefix length")?;
    if bits > 32 || (bits < 32 && u32::from(address) & (u32::MAX >> bits) != 0) {
        return Err("IPv4 prefix is not canonical".into());
    }
    Ok(())
}
fn filter(value: &str) -> Result<()> {
    let words: Vec<_> = value.split_whitespace().collect();
    if words.len() < 7
        || !matches!(words[0], "permit" | "deny")
        || !matches!(words[1], "in" | "out")
        || !(words[2] == "ip" || words[2].parse::<u8>().is_ok())
        || words[3] != "from"
    {
        return Err("invalid NAS-Filter-Rule header".into());
    }
    fn address(value: &str) -> Result<()> {
        let value = value.strip_prefix('!').unwrap_or(value);
        if matches!(value, "any" | "assigned") {
            return Ok(());
        }
        if value.contains(':') {
            prefix(value).map(|_| ()).or_else(|_| {
                value
                    .parse::<Ipv6Addr>()
                    .map(|_| ())
                    .map_err(|_| "invalid filter address".into())
            })
        } else {
            ipv4_prefix(value)
        }
    }
    fn ports(value: &str) -> Result<()> {
        for range in value.split(',') {
            let (a, b) = range.split_once('-').unwrap_or((range, range));
            let a = a.parse::<u16>().map_err(|_| "invalid filter port")?;
            let b = b.parse::<u16>().map_err(|_| "invalid filter port")?;
            if a > b {
                return Err("reversed filter port range".into());
            }
        }
        Ok(())
    }
    address(words[4])?;
    let mut at = 5;
    if words.get(at) != Some(&"to") {
        ports(words[at])?;
        at += 1;
    }
    if words.get(at) != Some(&"to") {
        return Err("filter requires destination".into());
    }
    at += 1;
    address(words.get(at).ok_or("filter destination missing")?)?;
    at += 1;
    if let Some(word) = words.get(at) {
        if word.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
            ports(word)?;
            at += 1;
        }
    }
    while at < words.len() {
        if matches!(words[at], "frag" | "established" | "setup") {
            at += 1;
            continue;
        }
        if matches!(
            words[at],
            "tcpflags" | "ipoptions" | "tcpoptions" | "icmptypes"
        ) {
            let option = words.get(at + 1).ok_or("filter option requires a value")?;
            if !option
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'!' | b'-'))
            {
                return Err("invalid filter option".into());
            }
            at += 2;
            continue;
        }
        return Err("unsupported NAS filter option".into());
    }
    Ok(())
}

pub(crate) fn prefix(value: &str) -> Result<(Ipv6Addr, u8)> {
    let (address, bits) = value.split_once('/').ok_or("IPv6 prefix needs a length")?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| "invalid IPv6 prefix")?;
    let bits = bits
        .parse::<u8>()
        .map_err(|_| "invalid IPv6 prefix length")?;
    if bits > 128 || (bits < 128 && u128::from(address) & (u128::MAX >> bits) != 0) {
        return Err("IPv6 prefix is not canonical".into());
    }
    Ok((address, bits))
}
