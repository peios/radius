//! Forms over the shared Registry controls; no second settings authority.
use super::*;
const FLAGS: &[(&str, &str)] = &[
    ("update_authorization", "Update Authorization Automatically"),
    ("vlan_disconnect", "Disconnect on VLAN Change"),
    ("revoke_access", "Disconnect on Access Revocation"),
    (
        "password_reauthenticate",
        "Reauthenticate on Password Change",
    ),
];
fn action_label(value: &serde_json::Value) -> &'static str {
    match value.as_str() {
        Some("disconnect") => "Disconnect",
        Some("reauthenticate") => "Fresh Authentication",
        Some("update-authorization") => "Update Authorization",
        _ => "Session Control",
    }
}
fn outcome_label(value: &str) -> &str {
    match value {
        "pending" => "Queued",
        "sent" => "Waiting for Device",
        "acknowledged" => "Accepted by Device",
        "rejected" => "Refused by Device",
        "unsupported" => "Unsupported Capability",
        "uncertain" => "Outcome Unknown",
        "superseded" => "Superseded",
        "current" => "Access Is Current",
        "access-revoked" => "Access Revoked",
        "credential-status-unknown" => "Credential Status Unknown",
        "authorization-baseline-unknown" => "Original Authorization Unknown",
        _ => value,
    }
}
fn authorization(value: &serde_json::Value, observed: bool) -> String {
    if value.is_null() {
        return "Unknown or unavailable".into();
    }
    let vlan = value["vlan"]
        .as_u64()
        .map(|v| format!("VLAN {v}"))
        .unwrap_or_else(|| {
            if observed {
                "VLAN not reported".into()
            } else {
                "No VLAN override".into()
            }
        });
    match value["timeout_seconds"].as_u64() {
        Some(seconds) => format!("{vlan} · Session timeout {seconds} seconds"),
        None => vlan,
    }
}
pub(super) fn evidence(detail: &serde_json::Value) -> String {
    let mut rows = String::new();
    for (label, value, observed) in [
        (
            "Issued at Authentication",
            &detail["session"]["issued"],
            false,
        ),
        (
            "Desired Access",
            &detail["reconciliation"]["desired"],
            false,
        ),
        ("Device Report", &detail["session"]["observed"], true),
    ] {
        rows.push_str(&settings::row(
            label,
            "",
            &escape(&authorization(value, observed)),
        ));
    }
    let status = detail["reconciliation"]["status"]
        .as_str()
        .unwrap_or("Unknown or unavailable");
    rows.push_str(&settings::row(
        "Reevaluation",
        "",
        &escape(outcome_label(status)),
    ));
    rows.push_str(&settings::note("Device acceptance, reconnection, fresh authentication, and address renewal are separate outcomes."));
    if let Some(commands) = detail["commands"].as_array() {
        if commands.is_empty() {
            rows.push_str(&settings::row(
                "Session Commands",
                "No commands recorded.",
                "",
            ));
        }
        for command in commands {
            let label = format!(
                "{} · {}",
                action_label(&command["action"]),
                outcome_label(command["state"].as_str().unwrap_or("Unknown"))
            );
            let reason = command["reason"].as_str().unwrap_or_default();
            let description = if reason.starts_with("vlan-changed:") {
                "VLAN assignment changed"
            } else if reason.starts_with("credential-changed:") {
                "Credential replaced or no longer eligible"
            } else {
                match reason {
                    "access-revoked" => "Current access revoked",
                    "authorization-changed" => "Authorization changed",
                    "reevaluation-unavailable-grace-expired" => {
                        "Identity unavailable beyond the configured grace period"
                    }
                    "administrator" => "Manually requested",
                    _ => "Policy enforcement",
                }
            };
            let mut detail = format!(
                "{description} · {} transmission attempts",
                command["attempts"].as_u64().unwrap_or(0)
            );
            if command["requested_action"] != command["action"] {
                detail.push_str(&format!(
                    " · Fallback from {}",
                    action_label(&command["requested_action"])
                ));
            }
            if let Some(cause) = command["error_cause"].as_u64() {
                detail.push_str(&format!(" · Device error {cause}"));
            }
            if let Some(error) = command["validation_error"].as_str() {
                detail.push_str(&format!(" · {error}"));
            }
            rows.push_str(&settings::row(&label, &detail, ""));
        }
    } else {
        rows.push_str(&settings::row(
            "Session Commands",
            "Unavailable or not permitted.",
            "",
        ));
    }
    rows
}
fn fallback_options(inherit: bool) -> Vec<(String, String)> {
    let mut values = vec![];
    if inherit {
        values.push(("inherit".into(), "Use Global Default".into()));
    }
    values.extend(
        [
            ("", "Report Failure"),
            ("disconnect", "Disconnect"),
            ("reauthenticate", "Reauthenticate"),
            (
                "reauthenticate,disconnect",
                "Reauthenticate, then Disconnect",
            ),
        ]
        .map(|(a, b)| (a.into(), b.into())),
    );
    values
}
pub(super) fn fill_policy(record: &Record, fields: &mut Fields) {
    let value: serde_json::Value = record
        .text("SessionControl")
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    for (key, _) in FLAGS {
        fields.set(
            &format!("control-{key}"),
            match value[*key].as_bool() {
                Some(true) => "1",
                Some(false) => "0",
                None => "inherit",
            },
        );
    }
    fields.set(
        "control-outage",
        if value.get("unavailable_grace_seconds").is_none() {
            "inherit"
        } else if value["unavailable_grace_seconds"].is_null() {
            "keep"
        } else {
            "disconnect"
        },
    );
    fields.set(
        "control-grace",
        &value["unavailable_grace_seconds"]
            .as_u64()
            .unwrap_or(300)
            .to_string(),
    );
    fields.set(
        "control-fallback",
        &value
            .get("fallback")
            .map(|v| {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_else(|| "inherit".into()),
    );
}
pub(super) fn policy_form(enabled: bool) -> String {
    let mut rows = String::new();
    for (key, label) in FLAGS {
        rows.push_str(&settings::row(
            label,
            "Applies to precisely identified sessions after successful activation.",
            &settings::select(
                &format!("control-{key}"),
                label,
                &[
                    ("inherit".into(), "Use Global Default".into()),
                    ("1".into(), "Enabled".into()),
                    ("0".into(), "Disabled".into()),
                ],
                enabled,
            ),
        ));
    }
    rows.push_str(&settings::row(
        "Authority Unavailable",
        "Keeping the connection is the global default. The grace timer survives restarts.",
        &settings::select(
            "control-outage",
            "Authority Unavailable",
            &[
                ("inherit".into(), "Use Global Default".into()),
                ("keep".into(), "Keep Connection and Retry".into()),
                ("disconnect".into(), "Disconnect after Grace Period".into()),
            ],
            enabled,
        ),
    ));
    rows.push_str(&settings::row(
        "Grace Period (seconds)",
        "Used only when disconnecting after an authority outage.",
        &text("control-grace", "Grace Period", "number", enabled),
    ));
    rows.push_str(&settings::row("Unsupported Action Fallback","Only explicit unsupported capabilities permit fallback; every manual action needs permission. Silence remains uncertain.",&settings::select("control-fallback","Fallback",&fallback_options(true),enabled)));
    rows
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(super) fn policy_value(record: &Record, fields: &Fields) -> io::Result<Value> {
    let mut value = match record.text("SessionControl").filter(|s| !s.is_empty()) {
        Some(v) => serde_json::from_str::<serde_json::Value>(v)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        None => serde_json::json!({}),
    };
    let Some(object) = value.as_object_mut() else {
        return Err(invalid(
            "SessionControl must be an object; repair it through the CLI",
        ));
    };
    for (key, _) in FLAGS {
        match fields.get(&format!("control-{key}")) {
            "inherit" => {
                object.remove(*key);
            }
            "1" => {
                object.insert((*key).into(), true.into());
            }
            "0" => {
                object.insert((*key).into(), false.into());
            }
            _ => return Err(invalid("Invalid control selection")),
        }
    }
    match fields.get("control-outage") {
        "inherit" => {
            object.remove("unavailable_grace_seconds");
        }
        "keep" => {
            object.insert("unavailable_grace_seconds".into(), serde_json::Value::Null);
        }
        "disconnect" => {
            let seconds = fields
                .get("control-grace")
                .parse::<u32>()
                .map_err(|_| invalid("Grace period requires seconds"))?;
            object.insert("unavailable_grace_seconds".into(), seconds.into());
        }
        _ => return Err(invalid("Invalid outage selection")),
    }
    if fields.get("control-fallback") == "inherit" {
        object.remove("fallback");
    } else {
        object.insert(
            "fallback".into(),
            fields
                .get("control-fallback")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| serde_json::Value::String(s.into()))
                .collect(),
        );
    }
    Ok(Value::Text(value.to_string()))
}
pub(super) fn fill_global(stored: &Result<Stored, String>, fields: &mut Fields) {
    let config = stored
        .as_ref()
        .ok()
        .and_then(|s| radius_management::dynamic::prepare(s).ok());
    let value = serde_json::to_value(
        config
            .as_ref()
            .map(|c| c.settings.clone())
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    for (name, path, boolean) in radius_management::dynamic::KNOBS {
        let mut v = &value;
        for part in *path {
            v = &v[*part];
        }
        fields.set(
            name,
            &if *boolean {
                if v.as_bool() == Some(true) {
                    "1".into()
                } else {
                    "0".into()
                }
            } else {
                v.as_u64().unwrap_or(0).to_string()
            },
        );
    }
    fields.set(
        "DynamicAuthorizationFallback",
        &config
            .map(|c| {
                c.settings
                    .defaults
                    .fallback
                    .iter()
                    .map(|a| match a {
                        radius_accounting::dynamic::Action::Disconnect => "disconnect",
                        radius_accounting::dynamic::Action::Reauthenticate => "reauthenticate",
                        radius_accounting::dynamic::Action::UpdateAuthorization => {
                            "update-authorization"
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default(),
    );
}
fn label(name: &str) -> &str {
    match name {
        "DynamicAuthorizationUpdateAutomatically" => "Update Authorization Automatically",
        "DynamicAuthorizationEnabled" => "Automatic Session Controls",
        "DynamicAuthorizationEventHints" => "Use Account Change Event Hints",
        "DynamicAuthorizationCommandLifetimeSeconds" => "Transmitted Command Lifetime (seconds)",
        "DynamicAuthorizationIntervalSeconds" => "Reconciliation Interval (seconds)",
        "DynamicAuthorizationBatchSize" => "Sessions per Batch",
        "DynamicAuthorizationBudgetMilliseconds" => "Work Budget (milliseconds)",
        "DynamicAuthorizationIdentityTimeoutMilliseconds" => "Identity Read Timeout (milliseconds)",
        "DynamicAuthorizationRetryCount" => "Maximum Transmission Attempts",
        "DynamicAuthorizationRetrySeconds" => "Retry Backoff (seconds)",
        "DynamicAuthorizationMaxInFlight" => "Concurrent Commands",
        "DynamicAuthorizationRequireResponseAuthenticator" => {
            "Require Response Message-Authenticator"
        }
        "DynamicAuthorizationDisconnectOnVlanChange" => "Disconnect on VLAN Change",
        "DynamicAuthorizationRevokeAccess" => "Disconnect on Access Revocation",
        "DynamicAuthorizationReauthenticateOnPasswordChange" => "Reauthenticate on Password Change",
        "DynamicAuthorizationUnavailableGraceSeconds" => {
            "Authority Outage Grace (seconds; 0 keeps connection)"
        }
        _ => name,
    }
}
pub(super) fn global_form(enabled: bool) -> String {
    let mut rows = String::new();
    for (name, _, boolean) in radius_management::dynamic::KNOBS {
        let title = label(name);
        let control = if *boolean {
            settings::select(
                name,
                title,
                &[
                    ("1".into(), "Enabled".into()),
                    ("0".into(), "Disabled".into()),
                ],
                enabled,
            )
        } else {
            text(name, title, "number", enabled)
        };
        rows.push_str(&settings::row(title, "", &control));
    }
    rows.push_str(&settings::row(
        "Unsupported Action Fallback",
        "The default reports failure without escalation.",
        &settings::select(
            "DynamicAuthorizationFallback",
            "Fallback",
            &fallback_options(false),
            enabled,
        ),
    ));
    format!(
        r#"<form fx-submit="session-control-settings">{}{}</form>"#,
        settings::group(
            "Session Controls",
            &rows,
            "Automatic controls require accounting. Fresh authentication needs a qualified device profile or an explicitly configured Disconnect fallback. Access Policies provide per-policy overrides."
        ),
        settings::submit("Save Session Controls", Button::Primary, enabled)
    )
}
pub(super) fn global_value(fields: &Fields) -> io::Result<Values> {
    let mut values = Values::new();
    for (name, _, _) in radius_management::dynamic::KNOBS {
        values.insert(
            (*name).into(),
            operations::parse_setting(name, fields.get(name))?,
        );
    }
    values.insert(
        "DynamicAuthorizationFallback".into(),
        operations::parse_setting(
            "DynamicAuthorizationFallback",
            fields.get("DynamicAuthorizationFallback"),
        )?,
    );
    Ok(values)
}
