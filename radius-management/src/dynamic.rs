//! Shared configuration and authority adapter for dynamic session controls.
use crate::model::{Kind, Stored, Value};
use radius_accounting::dynamic::{Action, Authorization, CredentialBinding, Enforcement, Profile};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Registry name, JSON path, boolean. Zero grace means keep connections.
pub const KNOBS: &[(&str, &[&str], bool)] = &[
    (
        "DynamicAuthorizationUpdateAutomatically",
        &["defaults", "update_authorization"],
        true,
    ),
    ("DynamicAuthorizationEnabled", &["enabled"], true),
    ("DynamicAuthorizationEventHints", &["event_hints"], true),
    (
        "DynamicAuthorizationCommandLifetimeSeconds",
        &["command_lifetime_seconds"],
        false,
    ),
    (
        "DynamicAuthorizationIntervalSeconds",
        &["interval_seconds"],
        false,
    ),
    ("DynamicAuthorizationBatchSize", &["batch_size"], false),
    (
        "DynamicAuthorizationBudgetMilliseconds",
        &["budget_ms"],
        false,
    ),
    (
        "DynamicAuthorizationIdentityTimeoutMilliseconds",
        &["identity_timeout_ms"],
        false,
    ),
    ("DynamicAuthorizationRetryCount", &["retries"], false),
    (
        "DynamicAuthorizationRetrySeconds",
        &["retry_seconds"],
        false,
    ),
    ("DynamicAuthorizationMaxInFlight", &["max_in_flight"], false),
    (
        "DynamicAuthorizationRequireResponseAuthenticator",
        &["require_response_ma"],
        true,
    ),
    (
        "DynamicAuthorizationDisconnectOnVlanChange",
        &["defaults", "vlan_disconnect"],
        true,
    ),
    (
        "DynamicAuthorizationRevokeAccess",
        &["defaults", "revoke_access"],
        true,
    ),
    (
        "DynamicAuthorizationReauthenticateOnPasswordChange",
        &["defaults", "password_reauthenticate"],
        true,
    ),
    (
        "DynamicAuthorizationUnavailableGraceSeconds",
        &["defaults", "unavailable_grace_seconds"],
        false,
    ),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub event_hints: bool,
    pub command_lifetime_seconds: u32,
    pub interval_seconds: u32,
    pub batch_size: usize,
    pub budget_ms: u32,
    pub identity_timeout_ms: u32,
    pub retries: u32,
    pub retry_seconds: u32,
    pub max_in_flight: usize,
    pub require_response_ma: bool,
    pub defaults: Enforcement,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            event_hints: true,
            command_lifetime_seconds: 60,
            interval_seconds: 30,
            batch_size: 128,
            budget_ms: 1000,
            identity_timeout_ms: 500,
            retries: 4,
            retry_seconds: 1,
            max_in_flight: 64,
            require_response_ma: false,
            defaults: Enforcement::default(),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=86400).contains(&self.interval_seconds)
            || !(10..=300).contains(&self.command_lifetime_seconds)
            || !(1..=200).contains(&self.batch_size)
            || !(10..=10000).contains(&self.budget_ms)
            || !(10..=10000).contains(&self.identity_timeout_ms)
            || !(1..=8).contains(&self.retries)
            || !(1..=60).contains(&self.retry_seconds)
            || !(1..=128).contains(&self.max_in_flight)
        {
            return Err("dynamic authorization settings exceed bounds".into());
        }
        self.defaults.validate().map_err(|e| e.to_string())
    }
}
#[derive(Clone)]
pub struct Configuration {
    pub settings: Settings,
    pub policies: BTreeMap<String, Enforcement>,
    pub profiles: BTreeMap<String, Profile>,
    pub clients: BTreeMap<String, Option<String>>,
}
pub fn prepare(stored: &Stored) -> Result<Configuration, String> {
    let mut settings: Settings = match stored.settings.get("DynamicAuthorizationSettings") {
        None => Settings::default(),
        Some(Value::Text(v)) => serde_json::from_str(v)
            .map_err(|e| format!("invalid DynamicAuthorizationSettings: {e}"))?,
        _ => return Err("DynamicAuthorizationSettings requires REG_SZ JSON".into()),
    };
    let mut encoded = serde_json::to_value(&settings).map_err(|e| e.to_string())?;
    for (name, path, boolean) in KNOBS {
        let Some(value) = stored.settings.get(*name) else {
            continue;
        };
        let Value::Number(number) = value else {
            return Err(format!("{name} requires REG_DWORD"));
        };
        if *boolean && *number > 1 {
            return Err(format!("{name} requires 0 or 1"));
        }
        let mut target = &mut encoded;
        for part in *path {
            target = &mut target[*part];
        }
        *target = if *boolean {
            serde_json::Value::Bool(*number == 1)
        } else if *name == "DynamicAuthorizationUnavailableGraceSeconds" && *number == 0 {
            serde_json::Value::Null
        } else {
            serde_json::json!(number)
        };
    }
    settings = serde_json::from_value(encoded).map_err(|e| e.to_string())?;
    if let Some(value) = stored.settings.get("DynamicAuthorizationFallback") {
        let Value::List(actions) = value else {
            return Err("DynamicAuthorizationFallback requires REG_MULTI_SZ".into());
        };
        settings.defaults.fallback = actions
            .iter()
            .map(|a| {
                serde_json::from_value(serde_json::Value::String(a.clone()))
                    .map_err(|_| "invalid dynamic fallback action".to_string())
            })
            .collect::<Result<_, _>>()?;
    }
    // Unconfigured authentication-only installations have no automatic session
    // inventory. Explicitly enabling automation without it is an error.
    if stored.settings.get("AccountingEnabled") != Some(&Value::Number(1)) {
        if (stored.settings.contains_key("DynamicAuthorizationSettings")
            || KNOBS
                .iter()
                .any(|(name, _, _)| stored.settings.contains_key(*name)))
            && settings.enabled
        {
            return Err("automatic session controls require accounting".into());
        }
        settings.enabled = false;
    }
    settings.validate()?;
    let mut profiles = BTreeMap::new();
    for r in stored
        .objects
        .iter()
        .filter(|r| r.kind == Kind::DynamicProfile && r.enabled())
    {
        let definition = r
            .text("Definition")
            .ok_or("missing dynamic profile Definition")?;
        profiles.insert(
            r.id.clone(),
            Profile::parse(definition.as_bytes()).map_err(|e| e.to_string())?,
        );
    }
    let mut policies = BTreeMap::new();
    for r in stored.objects.iter().filter(|r| r.kind == Kind::Policy) {
        let policy = match r.values.get("SessionControl") {
            None | Some(Value::Text(_)) if r.text("SessionControl").is_none_or(str::is_empty) => {
                settings.defaults.clone()
            }
            Some(Value::Text(v)) => {
                let patch: serde_json::Value =
                    serde_json::from_str(v).map_err(|_| "invalid SessionControl JSON")?;
                let Some(patch) = patch.as_object() else {
                    return Err("SessionControl must be a JSON object".into());
                };
                let mut base =
                    serde_json::to_value(&settings.defaults).map_err(|e| e.to_string())?;
                for (k, v) in patch {
                    base[k] = v.clone();
                }
                serde_json::from_value(base).map_err(|e| format!("invalid SessionControl: {e}"))?
            }
            _ => return Err("SessionControl requires REG_SZ JSON".into()),
        };
        policy.validate().map_err(|e| e.to_string())?;
        policies.insert(r.id.clone(), policy);
    }
    let mut clients = BTreeMap::new();
    for r in stored.objects.iter().filter(|r| r.kind == Kind::Client) {
        let profile = match r.values.get("DynamicAuthorizationProfile") {
            None => None,
            Some(Value::Text(v)) if v.is_empty() => None,
            Some(Value::Text(v)) if profiles.contains_key(v) => Some(v.clone()),
            _ => return Err("unknown or disabled DynamicAuthorizationProfile".into()),
        };
        clients.insert(r.id.clone(), profile);
    }
    Ok(Configuration {
        settings,
        policies,
        profiles,
        clients,
    })
}
impl Configuration {
    pub fn profile(&self, client: &str) -> Profile {
        self.clients
            .get(client)
            .and_then(|id| id.as_ref())
            .and_then(|id| self.profiles.get(id))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub enum Evaluation {
    Granted {
        desired: Authorization,
        credentials: Option<Vec<CredentialBinding>>,
    },
    Denied,
    Disabled,
    Deleted,
    Unavailable(String),
}
pub fn right(action: Action) -> u32 {
    match action {
        Action::Disconnect => crate::accounting::DISCONNECT,
        Action::Reauthenticate => crate::accounting::REAUTHENTICATE,
        Action::UpdateAuthorization => crate::accounting::UPDATE_AUTHORIZATION,
    }
}
