//! Accounting configuration and bounded local control messages.
use crate::{
    model::{Kind, Stored, Value},
    runtime::Prefix,
};
pub use radius_accounting::store::Filter;
use radius_accounting::{
    model::{Grant, Settings},
    profile::Profile,
    quota::{Budget, Dimension, Period},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr};

pub const SOCKET: &str = "/run/radiusd/accounting.sock";
pub const MAX_REQUEST: usize = 64 * 1024;
pub const MAX_RESPONSE: usize = 512 * 1024;
pub const READ: u32 = 1;
pub const PERSONAL: u32 = 2;
pub const USAGE: u32 = 4;
pub const DISCONNECT: u32 = 8;
pub const CORRECT: u32 = 16;
pub const RAW: u32 = 32;
pub const REAUTHENTICATE: u32 = 64;
pub const UPDATE_AUTHORIZATION: u32 = 128;
pub const ALL: u32 = 255;
pub const DEFAULT_SECURITY: &str = "O:SYG:SYD:(A;;0xff;;;SY)(A;;0xff;;;BA)";
/// Registry name, portable name, boolean. Values larger than DWORD use exact decimal REG_SZ.
pub const KNOBS: &[(&str, &str, bool)] = &[
    ("AccountingBatchMilliseconds", "batch_ms", false),
    ("AccountingBatchCount", "batch_count", false),
    ("AccountingBatchBytes", "batch_bytes", false),
    ("AccountingQueueCount", "queue_count", false),
    ("AccountingMaxDatabaseBytes", "max_database_bytes", false),
    (
        "AccountingRetryHorizonSeconds",
        "retry_horizon_seconds",
        false,
    ),
    (
        "AccountingObservationRetentionSeconds",
        "observation_retention_seconds",
        false,
    ),
    (
        "AccountingSummaryRetentionSeconds",
        "summary_retention_seconds",
        false,
    ),
    (
        "AccountingDetailIntervalSeconds",
        "detail_interval_seconds",
        false,
    ),
    ("AccountingStaleSeconds", "stale_seconds", false),
    ("AccountingExpireSeconds", "expire_seconds", false),
    ("AccountingReservationSeconds", "reservation_seconds", false),
    ("AccountingRequireMessageAuthenticator", "require_ma", true),
    ("AccountingRawCapture", "raw_capture", true),
    (
        "AccountingRawRetentionSeconds",
        "raw_retention_seconds",
        false,
    ),
    ("AccountingRawMaxBytes", "raw_max_bytes", false),
    ("AccountingLinkedViews", "linked_views", true),
    ("AccountingRetainNames", "retain_names", true),
    ("AccountingRetainAttributes", "retain_attributes", true),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Status,
    Sessions {
        filter: Filter,
    },
    Session {
        id: String,
    },
    History {
        id: String,
        limit: usize,
    },
    Related {
        id: String,
    },
    Usage {
        principal: String,
        policy: String,
    },
    Disconnect {
        id: String,
    },
    Control {
        #[serde(default)]
        request_id: String,
        id: String,
        action: radius_accounting::dynamic::Action,
    },
    Reconciliation {
        id: String,
    },
    Commands {
        id: String,
    },
    Annotate {
        id: String,
        note: String,
    },
    CorrectEnd {
        id: String,
        end_ms: i64,
        note: String,
    },
    Rebuild,
}

#[derive(Clone)]
pub struct Peer {
    pub id: String,
    pub enabled: bool,
    pub addresses: Vec<Prefix>,
    pub secret_file: String,
    pub policies: Vec<String>,
    pub profile: Option<String>,
    pub disconnect_port: u16,
}
#[derive(Clone)]
pub struct Policy {
    pub reauthenticate_seconds: u32,
    pub enabled: bool,
    pub ssid: Option<Vec<u8>>,
    pub required: bool,
    pub allow_unavailable: bool,
    pub accounting_security: Value,
}
#[derive(Clone)]
pub struct Configuration {
    pub dynamic: crate::dynamic::Configuration,
    pub settings: Settings,
    pub listeners: Vec<SocketAddr>,
    pub peers: BTreeMap<String, Peer>,
    pub policies: BTreeMap<String, Policy>,
    pub budgets: Vec<Budget>,
    pub profiles: BTreeMap<String, Profile>,
    pub security: Value,
    pub self_service: bool,
    pub fingerprint: String,
}
fn fail(message: impl Into<String>) -> String {
    message.into()
}
pub fn prepare(s: &Stored) -> Result<Configuration, String> {
    if s.settings.get("SchemaVersion") != Some(&Value::Number(crate::model::SCHEMA)) {
        return Err(fail("unsupported Registry schema"));
    }
    for r in &s.objects {
        if !crate::model::valid_id(&r.id) {
            return Err(fail("invalid accounting object GUID"));
        }
        if r.kind != Kind::Identity
            && !(r.kind == Kind::Rule && !r.values.contains_key("Enabled"))
            && !matches!(r.number("Enabled"), Some(0 | 1))
        {
            return Err(fail(format!("{} has invalid Enabled", r.id)));
        }
    }
    let mut settings = match s.settings.get("AccountingSettings") {
        None => Settings::default(),
        Some(Value::Text(text)) => {
            serde_json::from_str(text).map_err(|_| fail("invalid AccountingSettings JSON"))?
        }
        _ => return Err(fail("AccountingSettings requires REG_SZ")),
    };
    let mut encoded = serde_json::to_value(&settings).map_err(|e| e.to_string())?;
    for (registry, field, boolean) in KNOBS {
        if let Some(value) = s.settings.get(*registry) {
            let n = match value {
                Value::Number(n) => u64::from(*n),
                Value::Text(n) => n
                    .parse::<u64>()
                    .map_err(|_| fail(format!("invalid {registry}")))?,
                _ => return Err(fail(format!("invalid {registry}"))),
            };
            if *boolean && n > 1 {
                return Err(fail(format!("{registry} requires 0 or 1")));
            }
            encoded[*field] = if *boolean {
                serde_json::Value::Bool(n == 1)
            } else {
                serde_json::json!(n)
            };
        }
    }
    settings =
        serde_json::from_value(encoded).map_err(|_| fail("accounting settings exceed bounds"))?;
    settings.enabled = match s.settings.get("AccountingEnabled") {
        None => false,
        Some(Value::Number(0)) => false,
        Some(Value::Number(1)) => true,
        _ => return Err(fail("AccountingEnabled requires 0 or 1")),
    };
    settings.validate().map_err(|e| e.to_string())?;
    let listeners = match s.settings.get("AccountingListen") {
        None => vec!["0.0.0.0:1813".parse().unwrap()],
        Some(Value::List(v)) => v
            .iter()
            .map(|s| s.parse().map_err(|_| fail("invalid accounting listener")))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(fail("AccountingListen requires REG_MULTI_SZ")),
    };
    if listeners.is_empty()
        || listeners.len() > 16
        || listeners.iter().any(|a: &SocketAddr| a.port() == 0)
    {
        return Err(fail("invalid accounting listener bounds"));
    }
    for (index, a) in listeners.iter().enumerate() {
        if a.ip().to_canonical() != a.ip()
            || listeners[..index].iter().any(|b| {
                a.port() == b.port()
                    && a.is_ipv4() == b.is_ipv4()
                    && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
            })
        {
            return Err(fail("overlapping or IPv4-mapped accounting listeners"));
        }
    }
    let security = s
        .settings
        .get("AccountingSecurity")
        .cloned()
        .unwrap_or_else(|| Value::Text(DEFAULT_SECURITY.into()));
    let self_service = match s.settings.get("AccountingSelfService") {
        None | Some(Value::Number(0)) => false,
        Some(Value::Number(1)) => true,
        _ => return Err(fail("invalid AccountingSelfService")),
    };
    let mut profiles = BTreeMap::new();
    for r in s
        .objects
        .iter()
        .filter(|r| r.kind == Kind::AccountingProfile && r.enabled())
    {
        let definition = r
            .text("Definition")
            .ok_or_else(|| fail("missing accounting profile Definition"))?;
        profiles.insert(
            r.id.clone(),
            Profile::parse(definition.as_bytes()).map_err(|e| e.to_string())?,
        );
    }
    let mut policies = BTreeMap::new();
    for r in s.objects.iter().filter(|r| r.kind == Kind::Policy) {
        if r.text("ServiceKind")
            .is_some_and(|v| !matches!(v, "" | "wifi" | "accounting-only"))
        {
            return Err(fail("invalid ServiceKind"));
        }
        let flag = |field: &str| -> Result<bool, String> {
            match r.values.get(field) {
                None | Some(Value::Number(0)) => Ok(false),
                Some(Value::Number(1)) => Ok(true),
                _ => Err(fail(format!("invalid {field}"))),
            }
        };
        let allow = match r.text("OnAccountingUnavailable") {
            None | Some("" | "deny-new") => false,
            Some("allow-new") => true,
            _ => {
                return Err(fail(
                    "OnAccountingUnavailable expects deny-new or allow-new",
                ));
            }
        };
        policies.insert(
            r.id.clone(),
            Policy {
                reauthenticate_seconds: r.number("ReauthenticateSeconds").unwrap_or(3600),
                enabled: r.enabled(),
                ssid: r.text("SSID").map(|v| v.as_bytes().to_vec()),
                required: flag("AccountingRequired")?,
                allow_unavailable: allow,
                accounting_security: r
                    .values
                    .get("AccountingSecurity")
                    .filter(|v| !matches!(v,Value::Text(t)if t.is_empty()))
                    .cloned()
                    .unwrap_or_else(|| security.clone()),
            },
        );
    }
    let mut peers = BTreeMap::new();
    let mut prefixes = std::collections::BTreeSet::new();
    for r in s.objects.iter().filter(|r| r.kind == Kind::Client) {
        let addresses = r
            .list("Addresses")
            .ok_or_else(|| fail("missing client Addresses"))?
            .iter()
            .map(|v| Prefix::parse(v).map_err(fail))
            .collect::<Result<Vec<_>, _>>()?;
        if addresses.is_empty() || addresses.len() > 256 {
            return Err(fail("invalid client address count"));
        }
        for p in &addresses {
            if !prefixes.insert((p.address, p.bits)) {
                return Err(fail("duplicate client prefix"));
            }
        }
        let allowed = r
            .list("Policies")
            .ok_or_else(|| fail("missing client Policies"))?
            .to_vec();
        if allowed.is_empty() || allowed.iter().any(|p| !policies.contains_key(p)) {
            return Err(fail("unknown client policy"));
        }
        let profile = r
            .text("AccountingProfile")
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if profile
            .as_ref()
            .is_some_and(|id| !profiles.contains_key(id))
        {
            return Err(fail("unknown or disabled accounting profile"));
        }
        let port = match r.values.get("DisconnectPort") {
            None => 3799,
            Some(Value::Number(port)) => *port,
            _ => return Err(fail("DisconnectPort requires REG_DWORD")),
        };
        if !(1..=65535).contains(&port) {
            return Err(fail("invalid DisconnectPort"));
        }
        peers.insert(
            r.id.clone(),
            Peer {
                id: r.id.clone(),
                enabled: r.enabled(),
                addresses,
                secret_file: r
                    .text("SecretFile")
                    .ok_or_else(|| fail("missing client SecretFile"))?
                    .into(),
                policies: allowed,
                profile,
                disconnect_port: port as u16,
            },
        );
    }
    let mut budgets = Vec::new();
    for r in s
        .objects
        .iter()
        .filter(|r| r.kind == Kind::Quota && r.enabled())
    {
        let b = quota(r)?;
        if b.policy
            .as_ref()
            .is_some_and(|scope| !policies.contains_key(scope))
        {
            return Err(fail("unknown quota policy"));
        }
        budgets.push(b);
    }
    if budgets.len() > 256 || profiles.len() > 256 || peers.len() > 256 || policies.len() > 256 {
        return Err(fail("too many accounting objects"));
    }
    Ok(Configuration {
        dynamic: crate::dynamic::prepare(s)?,
        settings,
        listeners,
        peers,
        policies,
        budgets,
        profiles,
        security,
        self_service,
        fingerprint: s.fingerprint(),
    })
}
pub fn usage_subject(principal: &str, policy: &str) -> Grant {
    Grant {
        proof: None,
        reference: Vec::new(),
        client: String::new(),
        policy: policy.into(),
        sid: principal.into(),
        name: None,
        groups: Vec::new(),
        station: None,
        issued_ms: 0,
        expires_ms: i64::MAX,
    }
}
pub fn quota(r: &crate::model::Record) -> Result<Budget, String> {
    let dimension = match r.text("Dimension") {
        Some("input-bytes") => Dimension::InputBytes,
        Some("output-bytes") => Dimension::OutputBytes,
        Some("total-bytes") => Dimension::TotalBytes,
        Some("total-session-time") => Dimension::TotalSessionTime,
        Some("connected-time") => Dimension::ConnectedTime,
        Some("concurrent") => Dimension::Concurrent,
        _ => return Err(fail("unsupported quota Dimension")),
    };
    let period = match r.text("Period") {
        Some("lifetime") => Period::Lifetime,
        Some("day") => Period::Day,
        Some("week") => Period::Week,
        Some("month") => Period::Month,
        _ => return Err(fail("unsupported quota Period")),
    };
    let scope = r
        .text("Policy")
        .ok_or_else(|| fail("missing quota Policy"))?;
    let maximum = r
        .text("Maximum")
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| fail("Maximum requires exact unsigned decimal"))?;
    let disconnect = match r.values.get("Disconnect") {
        None | Some(Value::Number(1)) => true,
        Some(Value::Number(0)) => false,
        _ => return Err(fail("Disconnect requires 0 or 1")),
    };
    let b = Budget {
        id: r.id.clone(),
        principal: r
            .text("Principal")
            .ok_or_else(|| fail("missing quota Principal"))?
            .into(),
        policy: (scope != "*").then(|| scope.into()),
        dimension,
        period,
        maximum,
        disconnect,
    };
    b.validate().map_err(|e| e.to_string())?;
    Ok(b)
}
