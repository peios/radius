use radius_core::{Binding, Limits};
use ring::digest::{digest, SHA256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use zeroize::Zeroizing;

pub const ROOT: &str = "Machine\\Software\\Radius";
pub const CONNECT: u32 = 1;
/// Fixed virtual account of the service named radiusd, derived by authd/peinit's
/// existing service-SID rule. Native qualification checks peinit's actual token.
pub const SERVICE_SID: &str = "S-1-5-80-1653768611-2164381495-1902105107-3452022516-881820819";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub address: IpAddr,
    pub bits: u8,
}
impl Prefix {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (ip, bits) = text
            .split_once('/')
            .map_or((text, None), |(a, b)| (a, Some(b)));
        let address: IpAddr = ip.parse().map_err(|_| "invalid client address")?;
        if matches!(address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
            return Err("mapped IPv6 client selectors are not supported");
        }
        let max = if address.is_ipv4() { 32 } else { 128 };
        let bits = bits.map_or(Ok(max), |s| {
            s.parse::<u8>().map_err(|_| "invalid client prefix")
        })?;
        if bits > max {
            return Err("invalid client prefix");
        }
        let prefix = Self { address, bits };
        if !prefix.canonical() {
            return Err("client prefix has host bits set");
        }
        Ok(prefix)
    }
    fn canonical(&self) -> bool {
        if matches!(self.address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
            return false;
        }
        if self.bits > if self.address.is_ipv4() { 32 } else { 128 } {
            return false;
        }
        match self.address {
            IpAddr::V4(ip) => self.bits == 32 || u32::from(ip) & (u32::MAX >> self.bits) == 0,
            IpAddr::V6(ip) => self.bits == 128 || u128::from(ip) & (u128::MAX >> self.bits) == 0,
        }
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.bits == 0 || (u32::from(a) ^ u32::from(b)) >> (32 - self.bits) == 0
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.bits == 0 || (u128::from(a) ^ u128::from(b)) >> (128 - self.bits) == 0
            }
            _ => false,
        }
    }
}

pub struct Client {
    pub name: String,
    pub addresses: Vec<Prefix>,
    pub secret: Zeroizing<Vec<u8>>,
    pub networks: Vec<String>,
}
pub struct Network {
    pub ssid: Vec<u8>,
    /// Validated native self-relative SD; never a replacement ACL language.
    pub security: Vec<u8>,
    pub reauthenticate_seconds: u32,
}
pub struct Config {
    pub listeners: Vec<SocketAddr>,
    pub limits: Limits,
    pub verifications: usize,
    pub clients: BTreeMap<String, Client>,
    pub networks: BTreeMap<String, Network>,
    pub tls: Arc<rustls::ServerConfig>,
    /// Configuration fingerprint including referenced file contents; not a
    /// Registry snapshot/generation guarantee. It only detects observed changes.
    pub fingerprint: [u8; 32],
}

pub fn identity(name: &str) -> u64 {
    u64::from_be_bytes(
        digest(&SHA256, name.as_bytes()).as_ref()[..8]
            .try_into()
            .unwrap(),
    )
}
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.listeners.is_empty()
            || self.listeners.len() > 16
            || self.clients.is_empty()
            || self.clients.len() > 256
            || self.networks.is_empty()
            || self.networks.len() > 256
            || self.verifications == 0
            || self.verifications > self.limits.attempts
        {
            return Err("invalid configuration bounds");
        }
        if self.listeners.iter().any(|a| {
            a.port() == 0 || matches!(a.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
        }) || self.listeners.iter().collect::<BTreeSet<_>>().len() != self.listeners.len()
        {
            return Err("invalid listener");
        }
        radius_core::Engine::new(self.tls.clone(), self.limits.clone())
            .map_err(|_| "invalid conversation limits or TLS policy")?;
        let mut ids = BTreeSet::new();
        for name in self.clients.keys().chain(self.networks.keys()) {
            if !valid_name(name) {
                return Err("invalid record name");
            }
        }
        for name in self.clients.keys() {
            if !ids.insert(identity(name)) {
                return Err("client identity collision");
            }
        }
        ids.clear();
        for (name, network) in &self.networks {
            if !ids.insert(identity(name))
                || network.ssid.is_empty()
                || network.ssid.len() > 32
                || network.security.is_empty()
                || network.security.len() > 65536
                || network.reauthenticate_seconds == 0
            {
                return Err("invalid network");
            }
        }
        let mut prefixes = BTreeSet::new();
        for (name, client) in &self.clients {
            if name != &client.name
                || client.addresses.is_empty()
                || client.addresses.len() > 256
                || !(16..=1024).contains(&client.secret.len())
                || client.networks.is_empty()
                || client.networks.len() > 256
            {
                return Err("invalid client");
            }
            for prefix in &client.addresses {
                if !prefix.canonical() || !prefixes.insert((prefix.address, prefix.bits)) {
                    return Err("duplicate client prefix");
                }
            }
            let mut ssids = BTreeSet::new();
            for name in &client.networks {
                let network = self.networks.get(name).ok_or("unknown allowed network")?;
                if !ssids.insert(&network.ssid) {
                    return Err("ambiguous allowed network");
                }
            }
        }
        Ok(())
    }
    pub fn client(&self, source: IpAddr) -> Option<&Client> {
        self.clients
            .values()
            .flat_map(|client| {
                client
                    .addresses
                    .iter()
                    .filter(move |p| p.contains(source))
                    .map(move |p| (p.bits, client))
            })
            .max_by_key(|(bits, _)| *bits)
            .map(|(_, client)| client)
    }
    pub fn network<'a>(&'a self, client: &Client, ssid: &[u8]) -> Option<(&'a str, &'a Network)> {
        client.networks.iter().find_map(|name| {
            self.networks
                .get_key_value(name)
                .filter(|(_, n)| n.ssid == ssid)
                .map(|(name, n)| (name.as_str(), n))
        })
    }
    pub fn binding(&self, client: &Client, network: &str, source: IpAddr) -> Binding {
        let mut material = Zeroizing::new(Vec::new());
        material.extend_from_slice(&client.secret);
        // A renamed SSID is a different network binding, even when its
        // administrator-facing record name stays the same.
        if let Some(network) = self.networks.get(network) {
            material.extend_from_slice(&(network.ssid.len() as u32).to_be_bytes());
            material.extend_from_slice(&network.ssid);
        }
        for prefix in &client.addresses {
            material.extend_from_slice(format!("{}/{},", prefix.address, prefix.bits).as_bytes());
        }
        // Allowed-network additions/removals are checked explicitly against the
        // retained network; unrelated permission edits do not cancel an attempt.
        Binding {
            client: identity(&client.name),
            network: identity(network),
            source,
            trust_generation: u64::from_be_bytes(
                digest(&SHA256, &material).as_ref()[..8].try_into().unwrap(),
            ),
        }
    }
    pub fn bound(&self, binding: &Binding) -> Option<(&Client, &str, &Network)> {
        let client = self.client(binding.source)?;
        let (name, network) = client.networks.iter().find_map(|name| {
            self.networks
                .get_key_value(name)
                .filter(|(name, _)| identity(name) == binding.network)
        })?;
        (self.binding(client, name, binding.source) == *binding).then_some((
            client,
            name.as_str(),
            network,
        ))
    }
}

/// Accept fixed-size MAC syntax, then preserve the complete SSID suffix,
/// including colons/spaces/case. No split-on-last-colon or Unicode folding.
pub fn called_ssid(called: &[u8]) -> Option<&[u8]> {
    if !(19..=50).contains(&called.len()) || called[17] != b':' {
        return None;
    }
    let separator = called[2];
    if !matches!(separator, b':' | b'-') {
        return None;
    }
    for (index, byte) in called[..17].iter().enumerate() {
        if index % 3 == 2 {
            if *byte != separator {
                return None;
            }
        } else if !byte.is_ascii_hexdigit() {
            return None;
        }
    }
    Some(&called[18..])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefixes_are_canonical_and_family_specific() {
        for text in ["192.0.2.0/24", "0.0.0.0/0", "2001:db8::/32", "::/0", "::1"] {
            assert!(Prefix::parse(text).is_ok());
        }
        for text in [
            "192.0.2.1/24",
            "::ffff:192.0.2.1",
            "::/129",
            "x",
            "1.2.3.4/-1",
        ] {
            assert!(Prefix::parse(text).is_err());
        }
        assert!(Prefix::parse("192.0.2.0/24")
            .unwrap()
            .contains("192.0.2.4".parse().unwrap()));
        assert!(!Prefix::parse("192.0.2.0/24")
            .unwrap()
            .contains("::1".parse().unwrap()));
    }
    #[test]
    fn ssid_is_exact_and_mac_is_validated() {
        assert_eq!(
            called_ssid(b"aa-bb-cc-dd-ee-ff:Home:guest "),
            Some(&b"Home:guest "[..])
        );
        assert_eq!(called_ssid(b"aa:bb:cc:dd:ee:ff:Home"), Some(&b"Home"[..]));
        for value in [
            b"Home".as_slice(),
            b"zz-bb-cc-dd-ee-ff:Home",
            b"aa-bb-cc-dd-ee-ff:",
            b"aa:bb-cc-dd-ee-ff:Home",
        ] {
            assert!(called_ssid(value).is_none());
        }
    }
}
