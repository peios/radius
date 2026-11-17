//! Stored configuration, including incomplete records that need repairing.
use ring::{
    digest::{digest, SHA256},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ROOT: &str = "Machine\\Software\\Radius";
pub const SCHEMA: u32 = 3;
pub const MAX_OBJECTS: usize = 256;
pub const MAX_VALUE_BYTES: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Client,
    Policy,
    Profile,
    Identity,
    Quota,
    AccountingProfile,
    AccessProfile,
    Rule,
}
impl Kind {
    pub const ALL: [Self; 8] = [
        Self::Client,
        Self::Policy,
        Self::Profile,
        Self::Identity,
        Self::Quota,
        Self::AccountingProfile,
        Self::AccessProfile,
        Self::Rule,
    ];
    pub fn collection(self) -> &'static str {
        match self {
            Self::Client => "Clients",
            Self::Policy => "AccessPolicies",
            Self::Profile => "AuthenticationProfiles",
            Self::Identity => "ServerIdentities",
            Self::Quota => "Quotas",
            Self::AccountingProfile => "AccountingProfiles",
            Self::AccessProfile => "AccessProfiles",
            Self::Rule => "Rules",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Self::Client),
            "policy" => Some(Self::Policy),
            "profile" => Some(Self::Profile),
            "identity" => Some(Self::Identity),
            "quota" => Some(Self::Quota),
            "accounting-profile" => Some(Self::AccountingProfile),
            "access-profile" => Some(Self::AccessProfile),
            "rule" => Some(Self::Rule),
            _ => None,
        }
    }
    pub fn fields(self) -> &'static [(&'static str, Field)] {
        use Field::*;
        match self {
            Self::Client => &[
                ("Addresses", List),
                ("SecretFile", Text),
                ("Policies", List),
                ("AccountingProfile", Text),
                ("DisconnectPort", Number),
            ],
            Self::Policy => &[
                ("SSID", Text),
                ("ConnectSecurity", Descriptor),
                ("AuthenticationProfile", Text),
                ("ReauthenticateSeconds", Number),
                ("ServiceKind", Text),
                ("AccountingRequired", Number),
                ("OnAccountingUnavailable", Text),
                ("AccountingSecurity", Descriptor),
            ],
            Self::Profile => &[("AuthenticationMethods", List), ("ServerIdentity", Text)],
            Self::Identity => &[("CertificateFiles", List), ("PrivateKeyFile", Text)],
            Self::Quota => &[
                ("Principal", Text),
                ("Policy", Text),
                ("Dimension", Text),
                ("Period", Text),
                ("Maximum", Text),
                ("Disconnect", Number),
            ],
            Self::AccountingProfile => &[("Definition", Text)],
            Self::AccessProfile => &[("VlanId", Number)],
            Self::Rule => &[
                ("Policy", Text),
                ("Parent", Text),
                ("Priority", Text),
                ("Actions", List),
            ],
        }
    }
    pub fn field(self, name: &str) -> Option<Field> {
        if self == Self::Rule && radius_policy::condition_key(name).is_ok() {
            return Some(if name.ends_with(".Present") {
                Field::Number
            } else if name.ends_with(".Equal") {
                Field::List
            } else {
                Field::Text
            });
        }
        match name {
            "Name" => Some(Field::Text),
            "Enabled" if self != Self::Identity => Some(Field::Number),
            "AccountingRequired" if self == Self::Policy => Some(Field::Number),
            "OnAccountingUnavailable" | "ServiceKind" if self == Self::Policy => Some(Field::Text),
            "AccountingSecurity" if self == Self::Policy => Some(Field::Descriptor),
            "AccountingProfile" if self == Self::Client => Some(Field::Text),
            "DisconnectPort" if self == Self::Client => Some(Field::Number),
            _ => self
                .fields()
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, t)| *t),
        }
    }
    pub fn optional(self, name: &str) -> bool {
        matches!(
            (self, name),
            (Self::AccessProfile, "VlanId")
                | (Self::Rule, "Parent" | "Priority" | "Actions")
                | (Self::Client, "AccountingProfile" | "DisconnectPort")
                | (
                    Self::Policy,
                    "ServiceKind"
                        | "AccountingRequired"
                        | "OnAccountingUnavailable"
                        | "AccountingSecurity"
                )
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Text,
    List,
    Number,
    Descriptor,
}

/// Registry values are preserved even when a known field has the wrong type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Value {
    Text(String),
    List(Vec<String>),
    Number(u32),
    Bytes(Vec<u8>),
    Raw { ty: u32, bytes: Vec<u8> },
}
pub type Values = BTreeMap<String, Value>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub kind: Kind,
    pub id: String,
    pub values: Values,
}
impl Record {
    pub fn new(kind: Kind, name: &str) -> Result<Self, String> {
        let mut record = Self {
            kind,
            id: new_id()?,
            values: BTreeMap::from([("Name".into(), Value::Text(name.into()))]),
        };
        if kind != Kind::Identity {
            record.values.insert("Enabled".into(), Value::Number(1));
        }
        if kind == Kind::Policy {
            record
                .values
                .insert("ReauthenticateSeconds".into(), Value::Number(3600));
        }
        if kind == Kind::Quota {
            record.values.extend([
                ("Policy".into(), Value::Text("*".into())),
                ("Period".into(), Value::Text("lifetime".into())),
                ("Disconnect".into(), Value::Number(1)),
            ]);
        }
        if kind == Kind::Rule {
            record
                .values
                .insert("Parent".into(), Value::Text(String::new()));
            record
                .values
                .insert("Actions".into(), Value::List(vec!["NULL".into()]));
        }
        Ok(record)
    }
    pub fn path(&self) -> String {
        if self.kind == Kind::Rule {
            let parent = self.text("Parent").unwrap_or_default().replace('/', "\\");
            let suffix = if parent.is_empty() {
                self.id.clone()
            } else {
                format!("{parent}\\{}", self.id)
            };
            return format!(
                "{ROOT}\\AccessPolicies\\{}\\Rules\\{suffix}",
                self.text("Policy").unwrap_or_default()
            );
        }
        format!("{ROOT}\\{}\\{}", self.kind.collection(), self.id)
    }
    pub fn name(&self) -> &str {
        self.text("Name").unwrap_or(&self.id)
    }
    pub fn text(&self, field: &str) -> Option<&str> {
        match self.values.get(field) {
            Some(Value::Text(v)) => Some(v),
            _ => None,
        }
    }
    pub fn list(&self, field: &str) -> Option<&[String]> {
        match self.values.get(field) {
            Some(Value::List(v)) => Some(v),
            _ => None,
        }
    }
    pub fn number(&self, field: &str) -> Option<u32> {
        match self.values.get(field) {
            Some(Value::Number(v)) => Some(*v),
            _ => None,
        }
    }
    pub fn enabled(&self) -> bool {
        self.kind == Kind::Identity
            || self.number("Enabled") == Some(1)
            || (self.kind == Kind::Rule && !self.values.contains_key("Enabled"))
    }
    pub fn references(&self) -> Vec<(Kind, &str)> {
        match self.kind {
            Kind::Client => {
                let mut references: Vec<_> = self
                    .list("Policies")
                    .unwrap_or_default()
                    .iter()
                    .map(|id| (Kind::Policy, id.as_str()))
                    .collect();
                if let Some(id) = self.text("AccountingProfile").filter(|id| !id.is_empty()) {
                    references.push((Kind::AccountingProfile, id));
                }
                references
            }
            Kind::Policy if self.text("ServiceKind") == Some("accounting-only") => Vec::new(),
            Kind::Policy => self
                .text("AuthenticationProfile")
                .map(|id| vec![(Kind::Profile, id)])
                .unwrap_or_default(),
            Kind::Profile => self
                .text("ServerIdentity")
                .map(|id| vec![(Kind::Identity, id)])
                .unwrap_or_default(),
            Kind::Identity | Kind::AccountingProfile | Kind::AccessProfile => Vec::new(),
            Kind::Rule => {
                let mut refs = Vec::new();
                if let Some(id) = self.text("Policy") {
                    refs.push((Kind::Policy, id));
                }
                if let Some(parent) = self.text("Parent").filter(|p| !p.is_empty()) {
                    refs.push((Kind::Rule, parent.rsplit('/').next().unwrap()));
                }
                for action in self.actions() {
                    let a = action.trim();
                    if a.get(..7)
                        .is_some_and(|s| s.eq_ignore_ascii_case("ASSIGN("))
                        && a.ends_with(')')
                    {
                        refs.push((Kind::AccessProfile, a[7..a.len() - 1].trim()));
                    }
                }
                refs
            }
            Kind::Quota => self
                .text("Policy")
                .filter(|id| *id != "*")
                .map(|id| vec![(Kind::Policy, id)])
                .unwrap_or_default(),
        }
    }
    pub fn actions(&self) -> Vec<&str> {
        match self.values.get("Actions") {
            Some(Value::List(v)) => v.iter().map(String::as_str).collect(),
            Some(Value::Text(v)) => vec![v.as_str()],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub object: String,
    pub field: String,
    pub message: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub settings: Values,
    pub objects: Vec<Record>,
    pub issues: Vec<Issue>,
}
impl Stored {
    pub fn get(&self, kind: Kind, id: &str) -> Option<&Record> {
        self.objects.iter().find(|r| r.kind == kind && r.id == id)
    }
    pub fn resolve(&self, kind: Kind, selector: &str) -> Result<&Record, String> {
        if let Some(r) = self.get(kind, selector) {
            return Ok(r);
        }
        let matches: Vec<_> = self
            .objects
            .iter()
            .filter(|r| r.kind == kind && r.name() == selector)
            .collect();
        match matches.as_slice() {
            [r] => Ok(r),
            [] => Err(format!("{} {selector:?} was not found", kind.collection())),
            _ => Err(format!("{selector:?} is ambiguous; use its GUID")),
        }
    }
    pub fn dependents(&self, kind: Kind, id: &str) -> Vec<&Record> {
        self.objects
            .iter()
            .filter(|r| r.references().contains(&(kind, id)))
            .collect()
    }
    /// Public data only: never include file contents or private-key material.
    pub fn fingerprint(&self) -> String {
        let bytes = serde_json::to_vec(&(self.settings.clone(), &self.objects))
            .expect("stored model serializes");
        digest(&SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    pub fn authentication_fingerprint(&self) -> String {
        let mut copy = self.clone();
        for record in &mut copy.objects {
            record.values.remove("Name");
        }
        copy.fingerprint()
    }
    pub fn validate(&self) -> Vec<Issue> {
        let mut out = self.issues.clone();
        let mut issue = |object: &str, field: &str, message: &str| {
            out.push(Issue {
                object: object.into(),
                field: field.into(),
                message: message.into(),
            })
        };
        if self.settings.get("SchemaVersion") != Some(&Value::Number(SCHEMA)) {
            issue("Settings", "SchemaVersion", "expected schema version 3");
        }
        for kind in Kind::ALL {
            if self.objects.iter().filter(|r| r.kind == kind).count()
                > if kind == Kind::Rule {
                    radius_policy::MAX_RULES
                } else {
                    MAX_OBJECTS
                }
            {
                issue(kind.collection(), "", "too many objects");
            }
        }
        for r in &self.objects {
            if !valid_id(&r.id) {
                issue(&r.id, "Id", "expected a canonical UUIDv4");
            }
            if !(r.kind == Kind::Rule && !r.values.contains_key("Name"))
                && !r.text("Name").is_some_and(|s| {
                    !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
                })
            {
                issue(
                    &r.id,
                    "Name",
                    "expected a nonempty display name of at most 256 bytes",
                );
            }
            if r.kind != Kind::Identity
                && !(r.kind == Kind::Rule && !r.values.contains_key("Enabled"))
                && !matches!(r.number("Enabled"), Some(0 | 1))
            {
                issue(&r.id, "Enabled", "expected 0 or 1");
            }
            for (field, ty) in r.kind.fields() {
                if r.kind.optional(field)
                    && r.values
                        .get(*field)
                        .is_none_or(|v| matches!(v,Value::Text(t)if t.is_empty()))
                {
                    continue;
                }
                if r.kind == Kind::Policy
                    && r.text("ServiceKind") == Some("accounting-only")
                    && matches!(
                        *field,
                        "SSID"
                            | "ConnectSecurity"
                            | "AuthenticationProfile"
                            | "ReauthenticateSeconds"
                    )
                {
                    continue;
                }
                let valid = match (ty, r.values.get(*field)) {
                    (_, Some(Value::Number(_))) if r.kind == Kind::Rule && *field == "Priority" => {
                        true
                    }
                    (_, Some(Value::Text(s))) if r.kind == Kind::Rule && *field == "Actions" => {
                        !s.is_empty()
                    }
                    (Field::Text, Some(Value::Text(s))) => !s.is_empty() && !s.contains('\0'),
                    (Field::List, Some(Value::List(v))) => {
                        !v.is_empty()
                            && v.len() <= 256
                            && v.iter().all(|s| !s.is_empty() && !s.contains('\0'))
                            && v.iter().collect::<BTreeSet<_>>().len() == v.len()
                    }
                    (Field::Number, Some(Value::Number(n)))
                        if matches!(*field, "Disconnect" | "AccountingRequired") =>
                    {
                        *n <= 1
                    }
                    (Field::Number, Some(Value::Number(n))) => *n > 0,
                    (Field::Descriptor, Some(Value::Text(s))) => !s.is_empty(),
                    (Field::Descriptor, Some(Value::Bytes(b))) => {
                        !b.is_empty() && b.len() <= MAX_VALUE_BYTES
                    }
                    _ => false,
                };
                if !valid {
                    issue(&r.id, field, "missing or invalid field");
                }
            }
            for (kind, id) in r.references() {
                if self.get(kind, id).is_none() {
                    issue(
                        &r.id,
                        "References",
                        &format!("missing {} {id}", kind.collection()),
                    );
                }
            }
            if r.kind == Kind::Client {
                for address in r.list("Addresses").unwrap_or_default() {
                    if crate::runtime::Prefix::parse(address).is_err() {
                        issue(
                            &r.id,
                            "Addresses",
                            "expected a canonical IP address or prefix",
                        );
                    }
                }
                if let Some(Value::Text(path)) = r.values.get("SecretFile") {
                    if !absolute(path) {
                        issue(&r.id, "SecretFile", "expected an absolute path");
                    }
                }
            }
            if r.kind == Kind::Policy && r.text("SSID").is_some_and(|s| s.len() > 32) {
                issue(&r.id, "SSID", "SSID exceeds 32 bytes");
            }
            if r.kind == Kind::Profile {
                let methods = r.list("AuthenticationMethods").unwrap_or_default();
                if methods.len() > 2
                    || methods
                        .iter()
                        .any(|m| radius_core::Method::parse(m).is_none())
                {
                    issue(
                        &r.id,
                        "AuthenticationMethods",
                        "unsupported or duplicate authentication methods",
                    );
                }
            }
            if r.kind == Kind::Quota {
                if let Err(e) = crate::accounting::quota(r) {
                    issue(&r.id, "Quota", &e);
                }
            }
            if r.kind == Kind::Rule {
                if let Err(e) = crate::access_policy::validate_scope(r, self) {
                    issue(&r.id, "Parent", &e);
                }
            }
            if r.kind == Kind::AccessProfile {
                if let Err(e) = crate::access_policy::profile(r) {
                    issue(&r.id, "VlanId", &e);
                }
            }
            if r.kind == Kind::AccountingProfile {
                if let Some(definition) = r.text("Definition") {
                    if let Err(e) =
                        radius_accounting::profile::Profile::parse(definition.as_bytes())
                    {
                        issue(&r.id, "Definition", &e.to_string());
                    }
                }
            }
            if r.kind == Kind::Identity {
                for path in r
                    .list("CertificateFiles")
                    .unwrap_or_default()
                    .iter()
                    .map(String::as_str)
                    .chain(r.text("PrivateKeyFile"))
                {
                    if !absolute(path) {
                        issue(&r.id, "Files", "expected absolute credential paths");
                    }
                }
                if r.list("CertificateFiles").is_some_and(|v| v.len() > 16) {
                    issue(
                        &r.id,
                        "CertificateFiles",
                        "certificate chain exceeds 16 files",
                    );
                }
            }
        }
        for policy in self
            .objects
            .iter()
            .filter(|r| r.kind == Kind::Policy && r.text("ServiceKind") != Some("accounting-only"))
        {
            if let Err(e) = crate::access_policy::compile(self, &policy.id) {
                out.push(Issue {
                    object: policy.id.clone(),
                    field: "Rules".into(),
                    message: e,
                });
            }
        }
        out
    }
}
pub fn absolute(s: &str) -> bool {
    std::path::Path::new(s).is_absolute()
        && !std::path::Path::new(s).components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}
pub fn valid_id(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && s.as_bytes()[14] == b'4'
        && matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}
pub fn new_id() -> Result<String, String> {
    let mut b = [0u8; 16];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "random source unavailable")?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let hex: String = b.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
