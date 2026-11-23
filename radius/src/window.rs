//! GXWI forms over the same local management operations as the CLI.
use gxwi::settings::{self, Glyph, Kind as Button, Nav, Section, Tile, Width};
use gxwi::{escape, App, Facts, Fields, Live, Surface, Value as EventValue};
use radius_management::{
    model::{Field, Kind, Record, Stored, Value, Values},
    native::{configuration, credentials, operations, registry, service},
};
use std::{
    io,
    sync::{Arc, Weak},
    time::Duration,
};
use zeroize::Zeroizing;

gxwi::icon!(b"dev.peios.radius");
mod diagnostics;
mod session_control;
type Action = Box<dyn FnOnce() -> io::Result<Outcome> + Send>;
fn usage_history_graph(history: &[serde_json::Value]) -> String {
    let mut points: Vec<_> = history
        .iter()
        .filter(|v| v["effective_ms"].as_i64().is_some())
        .collect();
    points.sort_by_key(|v| v["effective_ms"].as_i64());
    if points.len() < 2 {
        return settings::row(
            "Usage History",
            "At least two retained reports are needed for a graph.",
            "",
        );
    }
    let start = points[0]["effective_ms"].as_i64().unwrap();
    let end = points.last().unwrap()["effective_ms"].as_i64().unwrap();
    let maximum = points
        .iter()
        .flat_map(|p| [p["input"].as_u64(), p["output"].as_u64()])
        .flatten()
        .max()
        .unwrap_or(0)
        .max(1);
    let series = |key: &str| {
        points
            .iter()
            .filter_map(|p| {
                let value = p[key].as_u64()?;
                let at = p["effective_ms"].as_i64()?;
                Some(format!(
                    "{:.2},{:.2}",
                    10.0 + (at.saturating_sub(start) as f64)
                        / (end.saturating_sub(start).max(1) as f64)
                        * 580.0,
                    150.0 - (value as f64) / (maximum as f64) * 140.0
                ))
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    format!(
        "<figure><svg viewBox=\"0 0 600 160\" role=\"img\" aria-label=\"Cumulative received bytes (solid) and sent bytes (dashed) across retained reports\"><polyline fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" points=\"{}\"/><polyline fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-dasharray=\"6 4\" points=\"{}\"/></svg><figcaption>Cumulative bytes: received (solid), sent (dashed). Missing reports and counter resets can leave gaps. Scale: 0 to {maximum} bytes.</figcaption></figure>",
        series("input"),
        series("output")
    )
}
enum Outcome {
    Saved(Record),
    Done(String),
    Revealed(Zeroizing<String>),
    Inspected(String),
    Accounting(serde_json::Value),
    AccountingView(&'static str, serde_json::Value),
    Explained(serde_json::Value),
    Diagnostics(radius_management::diagnostics::View),
    DiagnosticMonitor(radius_management::native::diagnostics::Monitor),
    DiagnosticAuthority(Vec<radius_management::diagnostics::Record>),
}
struct Pending {
    description: String,
    action: Action,
}
struct Window {
    diagnostics: radius_management::diagnostics::View,
    diagnostic_monitor: Option<radius_management::native::diagnostics::Monitor>,
    diagnostic_selected: Option<String>,
    diagnostic_authority: Option<Result<Vec<radius_management::diagnostics::Record>, String>>,
    surface: Weak<Surface<Self>>,
    section: &'static str,
    stored: Result<Stored, String>,
    overview: serde_json::Value,
    accounting: serde_json::Value,
    edit: Option<Record>,
    creating: bool,
    writable: bool,
    busy: bool,
    pending: Option<Pending>,
    said: Option<Result<String, String>>,
    secret: Option<Zeroizing<String>>,
    inspection: Option<String>,
    sd_editor: Option<gxwi_sd_editor::Editor>,
    condition_count: usize,
    explain_claim_count: usize,
    explanation: Option<serde_json::Value>,
}
fn rule_conditions(record: &Record) -> Vec<(&str, &Value)> {
    if record.kind != Kind::Rule {
        return Vec::new();
    }
    record
        .values
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "Name" | "Enabled" | "Priority" | "Actions" | "Policy" | "Parent"
            )
        })
        .map(|(k, v)| (k.as_str(), v))
        .collect()
}
fn explanation_facts(fields: &Fields, claim_count: usize) -> io::Result<radius_policy::Facts> {
    use radius_policy::{Facts, Scalar};
    let bad = |s| io::Error::new(io::ErrorKind::InvalidInput, s);
    let mut facts = Facts::new();
    facts.claim_coverage = if fields.get("explain-coverage") == "complete" {
        radius_policy::ClaimCoverage::Complete
    } else {
        radius_policy::ClaimCoverage::Filtered
    };
    facts.absent_claims = fields
        .get("explain-absent")
        .lines()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    for (field, key) in [
        ("explain-user", "Subject.User"),
        ("explain-groups", "Subject.Group"),
        ("explain-name", "Subject.Name"),
        ("explain-client", "Client.Id"),
        ("explain-address", "Client.Address"),
        ("explain-ssid", "Request.SSID"),
        ("explain-station", "Request.Station"),
    ] {
        let text = fields.get(field);
        if text.is_empty() {
            continue;
        }
        let values = text
            .lines()
            .map(|s| match key {
                "Subject.User" | "Subject.Group" => Ok(Scalar::Sid(s.into())),
                "Client.Address" => s
                    .parse()
                    .map(Scalar::Address)
                    .map_err(|_| bad("Invalid client address.")),
                "Request.Station" => radius_policy::station_mac(s.as_bytes())
                    .map(Scalar::Mac)
                    .ok_or_else(|| bad("Invalid station MAC.")),
                _ => Ok(Scalar::String(s.into())),
            })
            .collect::<io::Result<_>>()?;
        facts.insert(key.into(), values);
    }
    for i in 0..claim_count {
        let name = fields.get(&format!("explain-claim-name-{i}"));
        if !name.is_empty() {
            let values = fields
                .get(&format!("explain-claim-values-{i}"))
                .lines()
                .map(|s| match fields.get(&format!("explain-claim-type-{i}")) {
                    "" | "String" => Ok(Scalar::String(s.into())),
                    "Sid" => Ok(Scalar::Sid(s.into())),
                    "Int64" => s
                        .parse()
                        .map(Scalar::Int64)
                        .map_err(|_| bad("Invalid signed claim value.")),
                    "Uint64" => s
                        .parse()
                        .map(Scalar::Uint64)
                        .map_err(|_| bad("Invalid unsigned claim value.")),
                    "Boolean" => s
                        .parse()
                        .map(Scalar::Boolean)
                        .map_err(|_| bad("Boolean values must be true or false.")),
                    "Octet" => {
                        if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err(bad("Invalid hexadecimal octets."));
                        }
                        Ok(Scalar::Octet(
                            (0..s.len())
                                .step_by(2)
                                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                                .collect(),
                        ))
                    }
                    _ => Err(bad("Choose a claim type.")),
                })
                .collect::<io::Result<_>>()?;
            if facts
                .insert(format!("Subject.Claim.{name}"), values)
                .is_some()
            {
                return Err(bad("Duplicate claim name."));
            }
        }
    }
    radius_policy::validate_facts(&facts)
        .map_err(|_| bad("Invalid or oversized hypothetical facts."))?;
    Ok(facts)
}
impl Window {
    fn explain_page(&self) -> String {
        let mut policies = vec![(String::new(), "Choose policy…".into())];
        let mut clients = vec![(String::new(), "Not supplied".into())];
        if let Ok(stored) = &self.stored {
            policies.extend(
                stored
                    .objects
                    .iter()
                    .filter(|r| r.kind == Kind::Policy)
                    .map(|r| (r.id.clone(), r.name().into())),
            );
            clients.extend(
                stored
                    .objects
                    .iter()
                    .filter(|r| r.kind == Kind::Client)
                    .map(|r| (r.id.clone(), r.name().into())),
            );
        }
        let may = !self.busy;
        let knowledge = settings::row(
            "Claim Knowledge",
            "Unknown omitted claims cannot satisfy an absence condition.",
            &settings::select(
                "explain-coverage",
                "Claim Knowledge",
                &[
                    (
                        "filtered".into(),
                        "Only supplied values and known absences".into(),
                    ),
                    (
                        "complete".into(),
                        "Complete set: omitted claims are absent".into(),
                    ),
                ],
                may,
            ),
        );
        let mut rows = settings::row(
            "Access Policy",
            "Evaluates saved configuration; check Overview separately for activation.",
            &settings::select("explain-policy", "Access Policy", &policies, may),
        );
        rows.push_str(&knowledge);
        rows.push_str(&settings::row(
            "Known Absent Claims",
            "Optional names, one per line. These are hypothetical assertions.",
            &list("explain-absent", "Known Absent Claims", may),
        ));
        for (field, label, multi) in [
            ("explain-user", "User SID", false),
            ("explain-groups", "Group SIDs (one per line)", true),
            ("explain-name", "Canonical Username", false),
            ("explain-address", "Client Source Address", false),
            ("explain-ssid", "Reported SSID", false),
            ("explain-station", "Reported Station MAC", false),
        ] {
            rows.push_str(&settings::row(
                label,
                "Blank means this fact is not supplied.",
                &if multi {
                    list(field, label, may)
                } else {
                    text(field, label, "text", may)
                },
            ));
        }
        rows.push_str(&settings::row(
            "Verified Client (hypothetical)",
            "A supplied example, not proof that this client sent a request.",
            &settings::select("explain-client", "Client", &clients, may),
        ));
        for i in 0..self.explain_claim_count {
            rows.push_str(&settings::row(
                &format!("Claim {}", i + 1),
                "Optional hypothetical claim.",
                &text(
                    &format!("explain-claim-name-{i}"),
                    "Claim Name",
                    "text",
                    may,
                ),
            ));
            rows.push_str(&settings::row(
                "Claim Type",
                "Values retain their declared type.",
                &settings::select(
                    &format!("explain-claim-type-{i}"),
                    "Claim Type",
                    &["String", "Int64", "Uint64", "Boolean", "Sid", "Octet"]
                        .map(|s| (s.into(), s.into())),
                    may,
                ),
            ));
            rows.push_str(&settings::row(
                "Claim Values",
                "One value per line. Octet values use hexadecimal.",
                &format!(
                    "{}{}",
                    list(&format!("explain-claim-values-{i}"), "Claim Values", may),
                    settings::button(
                        "Remove Claim",
                        "explain-claim-remove",
                        &[("index", &i.to_string())],
                        Button::Plain,
                        may
                    )
                ),
            ));
        }
        rows.push_str(&settings::row(
            "Claims",
            "Supply only the facts you want to test.",
            &settings::button(
                "Add Claim",
                "explain-claim-add",
                &[],
                Button::Plain,
                may && self.explain_claim_count < 64,
            ),
        ));
        let mut page = format!(
            "<form fx-submit=\"explain-run\">{}{}</form>",
            settings::group("Hypothetical Facts", &rows, ""),
            settings::actions(&settings::submit("Explain", Button::Primary, may))
        );
        if let Some(result) = &self.explanation {
            let e = &result["explanation"];
            let mut rows = settings::fact(
                "Outcome",
                e["outcome"].as_str().unwrap_or("unavailable"),
                false,
            );
            rows.push_str(&settings::fact(
                "Configuration Fingerprint",
                result["fingerprint"].as_str().unwrap_or_default(),
                true,
            ));
            rows.push_str(&settings::row("Scope","Hypothetical assignment only. Credentials, Connect permissions and accounting allowances were not checked.",""));
            if let Some(values) = e["assignment"]["settings"].as_object() {
                for (name, value) in values {
                    let title = radius_authorization::spec(name)
                        .map_or_else(|| label(name), |spec| spec.label);
                    rows.push_str(&settings::row(title,"Selected profile setting; equipment enforcement is not checked by Explain.",&escape(&value.to_string())));
                }
            }
            if let Some(state) = result["authorization_plan"]["state"].as_str() {
                rows.push_str(&settings::row(
                    "Equipment Encoding",
                    result["authorization_plan"]["error"].as_str().unwrap_or(
                        "A hypothetical encoding check does not establish equipment enforcement.",
                    ),
                    &escape(state),
                ));
            }
            if let Some(candidates) = e["candidates"].as_array() {
                for c in candidates {
                    let rule = c["rule"].as_str().unwrap_or_default();
                    let profile = c["profile"].as_str();
                    let target = profile
                        .and_then(|id| {
                            self.stored
                                .as_ref()
                                .ok()
                                .and_then(|s| s.get(Kind::AccessProfile, id))
                        })
                        .map(|p| p.name())
                        .or(profile)
                        .unwrap_or("REJECT");
                    rows.push_str(&settings::row(
                        rule,
                        &format!("Priority {} → {target}", c["priority"]),
                        "",
                    ));
                }
            }
            if let Some(traces) = e["rules"].as_array() {
                for r in traces {
                    let matched = r["matched"].as_bool() == Some(true);
                    let steps = r["steps"]
                        .as_array()
                        .map(|v| {
                            v.iter()
                                .filter_map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    rows.push_str(&settings::row(
                        r["rule"].as_str().unwrap_or_default(),
                        &format!(
                            "{} · {steps}",
                            if matched { "Matched" } else { "Did not match" }
                        ),
                        "",
                    ));
                    if let Some(conditions) = r["conditions"].as_array() {
                        for c in conditions {
                            rows.push_str(&settings::fact(
                                c["condition"].as_str().unwrap_or_default(),
                                if c["matched"].as_bool() == Some(true) {
                                    "Matched"
                                } else {
                                    "Did not match"
                                },
                                false,
                            ));
                        }
                    }
                }
            }
            page.push_str(&settings::group("Explanation", &rows, ""));
        }
        page
    }
}
const SECTIONS: [(&str, &str, Glyph); 13] = [
    ("overview", "Overview", Glyph::Server),
    ("diagnostics", "Diagnostics", Glyph::Server),
    ("client", "Clients", Glyph::Globe),
    ("policy", "Access Policies", Glyph::Shield),
    ("profile", "Authentication Profiles", Glyph::Key),
    ("identity", "Server Identities", Glyph::Certificate),
    ("accounting", "Accounting", Glyph::Server),
    ("quota", "Allowances", Glyph::Shield),
    ("accounting-profile", "Accounting Profiles", Glyph::Globe),
    ("dynamic-profile", "Session Control Profiles", Glyph::Globe),
    ("access-profile", "Access Profiles", Glyph::Globe),
    ("rule", "Assignment Rules", Glyph::Shield),
    ("explain", "Explain Policy", Glyph::Shield),
];
fn section_tile(section: &str) -> Tile {
    match section {
        "diagnostics" => Tile::Blue,
        "overview" => Tile::Blue,
        "client" => Tile::Teal,
        "policy" => Tile::Violet,
        "profile" => Tile::Orange,
        "identity" => Tile::Green,
        "access-profile" => Tile::Teal,
        "rule" | "explain" => Tile::Violet,
        _ => Tile::Slate,
    }
}
fn section_about(section: &str) -> &'static str {
    match section {
        "diagnostics" => {
            "Recorded authentication progress and outcomes, subject to your event permissions."
        }
        "client" => "Devices that send authentication requests to this server.",
        "policy" => "Who may connect, and which authentication profile each network uses.",
        "profile" => "Reusable authentication methods and server identities.",
        "identity" => "Certificates this server presents when devices connect.",
        "accounting" => "Recorded sessions, usage and accounting health on this machine.",
        "quota" => {
            "Independent limits for users and groups. Every applicable allowance must permit access."
        }
        "accounting-profile" => {
            "Declarative mappings for accounting attributes reported by network devices."
        }
        "dynamic-profile" => {
            "Reusable device capabilities and encodings for precise session controls."
        }
        "access-profile" => "Reusable network access settings selected by policy rules.",
        "rule" => "PNP-style rules and nested exceptions selecting one complete access profile.",
        "explain" => {
            "Test saved assignment rules with hypothetical facts. This does not authenticate anyone or grant access."
        }
        _ => "RADIUS authentication and admission on this machine.",
    }
}
fn listeners(stored: &Result<Stored, String>) -> String {
    stored
        .as_ref()
        .ok()
        .and_then(|s| s.settings.get("Listen"))
        .map(field_text)
        .unwrap_or_default()
}
fn read() -> Result<Stored, String> {
    registry::read().map_err(|e| e.to_string())
}
fn overview() -> serde_json::Value {
    crate::cli::run(&[]).unwrap_or_else(|e| serde_json::json!({"error":e.to_string()}))
}
fn field_text(value: &Value) -> String {
    match value {
        Value::Text(v) => v.clone(),
        Value::List(v) => v.join("\n"),
        Value::Number(n) => n.to_string(),
        Value::Bytes(b) => peios::security::sddl::format(b).unwrap_or_default(),
        Value::Raw { .. } => String::new(),
    }
}
fn fill(record: &Record, fields: &mut Fields) {
    if record.kind == Kind::Policy {
        session_control::fill_policy(record, fields);
    }
    if record.kind == Kind::Rule {
        for (i, (key, value)) in rule_conditions(record).into_iter().enumerate() {
            let (fact, operator) = key.rsplit_once('.').unwrap_or((key, "Equal"));
            fields.set(&format!("rule-fact-{i}"), fact);
            fields.set(&format!("rule-op-{i}"), operator);
            fields.set(&format!("rule-values-{i}"), &field_text(value));
        }
        let actions = record.actions();
        let reject = actions.iter().any(|s| s.eq_ignore_ascii_case("REJECT"));
        let assigned = actions.iter().find_map(|s| {
            let s = s.trim();
            (s.get(..7)
                .is_some_and(|s| s.eq_ignore_ascii_case("ASSIGN("))
                && s.ends_with(')'))
            .then(|| s[7..s.len() - 1].trim())
        });
        fields.set(
            "rule-action",
            if reject {
                "REJECT"
            } else if assigned.is_some() {
                "ASSIGN"
            } else {
                "NULL"
            },
        );
        fields.set("rule-profile", assigned.unwrap_or_default());
    }
    fields.set("Name", record.name());
    fields.set("Enabled", if record.enabled() { "1" } else { "0" });
    fields.set("shared-secret", "");
    for (name, _) in record.kind.fields() {
        fields.set(
            name,
            &record.values.get(*name).map(field_text).unwrap_or_default(),
        );
    }
    for (name, default) in [
        ("DisconnectPort", "3799"),
        ("AccountingRequired", "0"),
        ("ServiceKind", "wifi"),
        ("OnAccountingUnavailable", "deny-new"),
    ] {
        if record.kind.optional(name) && !record.values.contains_key(name) {
            fields.set(name, default);
        }
    }
    if let Some(methods) = record.list("AuthenticationMethods") {
        fields.set("AuthenticationMethods", &methods.join(","));
    }
    for id in record.list("Policies").unwrap_or_default() {
        fields.set(&format!("allow-{id}"), "on");
    }
    if record.kind == Kind::Identity {
        fields.set("CertificateFiles", "");
        fields.set("PrivateKeyFile", "");
    }
}
fn text(name: &str, label: &str, kind: &str, enabled: bool) -> String {
    settings::text(
        name,
        label,
        kind,
        Width::Wide,
        enabled,
        r#"autocomplete="off""#,
    )
}
fn list(name: &str, label: &str, enabled: bool) -> String {
    format!(
        r#"<textarea class="st-input" name="{}" rows="3" aria-label="{}"{}></textarea>"#,
        escape(name),
        escape(label),
        if enabled { "" } else { " disabled" }
    )
}
fn label(field: &str) -> &str {
    match field {
        "Name" => "Name",
        "Enabled" => "Enabled",
        "Addresses" => "Source Addresses",
        "Policies" => "Allowed Access Policies",
        "SSID" => "SSID",
        "AuthenticationProfile" => "Authentication Profile",
        "ReauthenticateSeconds" => "Reauthenticate After (seconds)",
        "AuthenticationMethods" => "Authentication Methods",
        "ServerIdentity" => "Server Identity",
        "CertificateFiles" => "Certificate Files",
        "PrivateKeyFile" => "Private Key File",
        "Principal" => "Principal SID",
        "Policy" => "Policy GUID (* for all)",
        "Maximum" => "Maximum (bytes, milliseconds or sessions)",
        "OnAccountingUnavailable" => "If Accounting Is Unavailable",
        "AccountingRequired" => "Require Accounting (0 or 1)",
        "DisconnectPort" => "Disconnect Port",
        "AccountingProfile" => "Accounting Profile",
        "DynamicAuthorizationProfile" => "Session Control Profile",
        "SessionControl" => "Automatic Session Controls",
        "AccountingSecurity" => "Accounting Permissions (blank to inherit)",
        "ServiceKind" => "Service Kind",
        "Definition" => "Profile Definition (JSON)",
        "VlanId" => "VLAN ID (blank for no override)",
        "Parent" => "Parent Rule (blank for a root rule)",
        "Priority" => "Priority (blank to inherit)",
        _ => radius_authorization::spec(field).map_or(field, |s| s.label),
    }
}
fn reference(field: &str) -> Option<Kind> {
    match field {
        "AuthenticationProfile" => Some(Kind::Profile),
        "ServerIdentity" => Some(Kind::Identity),
        "AccountingProfile" => Some(Kind::AccountingProfile),
        "DynamicAuthorizationProfile" => Some(Kind::DynamicProfile),
        _ => None,
    }
}

fn authorization_form(enabled: bool) -> String {
    use radius_authorization::Kind;
    let mut output = String::new();
    let mut group = "";
    let mut rows = String::new();
    for spec in radius_authorization::FIELDS {
        if group != spec.group {
            if !rows.is_empty() {
                output.push_str(&settings::group(group, &rows, ""));
                rows.clear();
            }
            group = spec.group;
        }
        let control = if spec.name == "SessionExpiryAction" {
            settings::select(
                spec.name,
                spec.label,
                &[
                    ("".into(), "Disconnect (default for session timeout)".into()),
                    ("disconnect".into(), "Disconnect".into()),
                    ("reauthenticate".into(), "Reauthenticate".into()),
                ],
                enabled,
            )
        } else if spec.kind == Kind::Boolean {
            settings::select(
                spec.name,
                spec.label,
                &[
                    ("".into(), "Use equipment default".into()),
                    ("1".into(), "Enabled".into()),
                    ("0".into(), "Disabled".into()),
                ],
                enabled,
            )
        } else if spec.kind == Kind::List {
            list(spec.name, spec.label, enabled)
        } else {
            text(spec.name, spec.label, "text", enabled)
        };
        let about=match spec.name {
            "DownloadBitsPerSecond"|"UploadBitsPerSecond"=>"Per connection, from the connected device's perspective. Blank applies no RADIUS override.",
            "SessionTimeoutSeconds"=>"Time until the selected expiry action. Network and principal limits may shorten it. Choose this or a reauthentication interval.",
            "ReauthenticateSeconds"=>"A profile may shorten the network's reauthentication interval. Leave blank to use the network setting.",
            "FilterIds"=>"Names of filters already installed on the equipment, one per line.",
            "FilterRules"=>"NAS-Filter-Rule syntax, one complete supported rule per line.",
            "Ipv4Pool"|"Ipv6Pool"|"DelegatedIpv6Pool"=>"A pool name understood by the gateway; RADIUS does not allocate leases.",
            _=>"Optional. Equipment must support the standard attribute or have an explicit mapping. Blank applies no override.",
        };
        rows.push_str(&settings::row(spec.label, about, &control));
    }
    if !rows.is_empty() {
        output.push_str(&settings::group(group, &rows, ""));
    }
    output
}
fn affected(stored: &Stored, record: &Record) -> String {
    let uses = stored.dependents(record.kind, &record.id);
    if uses.is_empty() {
        "No configuration objects reference this object.".into()
    } else {
        format!(
            "Used by: {}.",
            uses.iter()
                .map(|r| {
                    if r.kind == Kind::Rule {
                        let policy = stored
                            .get(Kind::Policy, r.text("Policy").unwrap_or_default())
                            .map(|p| p.name())
                            .unwrap_or("Missing policy");
                        format!("{policy} / {}", r.name())
                    } else {
                        r.name().to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}
impl Window {
    fn heard(&mut self, stored: Result<Stored, String>, fields: &mut Fields) {
        // Follow external changes only while the field still holds the saved value.
        // Polling and unrelated actions must not replace an administrator's draft.
        if fields.get("listeners") == listeners(&self.stored) {
            fields.set("listeners", &listeners(&stored));
        }
        self.stored = stored;
    }
    fn section_summary(&self, section: &str) -> String {
        if section == "diagnostics" {
            return format!("{} attempts", self.diagnostics.attempts.len());
        }
        if section == "overview" {
            return match self.overview["daemon"].as_str() {
                Some("active") => "Running".into(),
                Some("stopped") => "Stopped".into(),
                Some("invalid") => "Configuration needs attention".into(),
                _ => "Status unavailable".into(),
            };
        }
        match (&self.stored, Kind::parse(section)) {
            (Ok(stored), Some(kind)) => {
                let count = stored.objects.iter().filter(|r| r.kind == kind).count();
                format!("{count} configured")
            }
            _ => "Unavailable".into(),
        }
    }
    fn launch(&mut self, action: Action) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.said = None;
        self.secret = None;
        self.inspection = None;
        let surface = self.surface.clone();
        std::thread::spawn(move || {
            let result = action().map_err(|e| e.to_string());
            let stored = read();
            let overview = overview();
            if let Some(surface) = surface.upgrade() {
                surface.update(move |w, fields| {
                    w.busy = false;
                    w.heard(stored, fields);
                    w.overview = overview;
                    match result {
                        Ok(Outcome::Saved(record)) => {
                            fill(&record, fields);
                            w.edit = Some(record);
                            w.creating = false;
                            w.said =
                                Some(Ok("Saved. Check Overview for activation status.".into()));
                        }
                        Ok(Outcome::Done(message)) => {
                            w.edit = None;
                            w.said = Some(Ok(message));
                        }
                        Ok(Outcome::Revealed(secret)) => {
                            w.secret = Some(secret);
                        }
                        Ok(Outcome::Inspected(info)) => {
                            w.inspection = Some(info);
                        }
                        Ok(Outcome::Accounting(snapshot)) => w.accounting = snapshot,
                        Ok(Outcome::AccountingView(key, snapshot)) => {
                            if !w.accounting.is_object() {
                                w.accounting = serde_json::json!({});
                            }
                            w.accounting[key] = snapshot;
                        }
                        Ok(Outcome::Explained(result)) => w.explanation = Some(result),
                        Ok(Outcome::Diagnostics(view)) => w.diagnostics = view,
                        Ok(Outcome::DiagnosticMonitor(monitor)) => {
                            w.diagnostics = monitor.snapshot();
                            w.diagnostic_monitor = Some(monitor);
                        }
                        Ok(Outcome::DiagnosticAuthority(records)) => {
                            w.diagnostic_authority = Some(Ok(records))
                        }
                        Err(error) => w.said = Some(Err(error)),
                    }
                    fields.set("shared-secret", "");
                });
            }
        });
    }
    fn request(&mut self, description: String, action: Action) {
        self.pending = Some(Pending {
            description,
            action,
        });
        self.said = None;
    }
    fn begin_edit(&mut self, record: Record, creating: bool, fields: &mut Fields) {
        self.condition_count = rule_conditions(&record).len();
        if let Ok(stored) = &self.stored {
            for r in stored.objects.iter().filter(|r| r.kind == Kind::Policy) {
                fields.set(&format!("allow-{}", r.id), "");
            }
        }
        if let Some(previous) = &self.edit {
            for id in previous.list("Policies").unwrap_or_default() {
                fields.set(&format!("allow-{id}"), "");
            }
        }
        fill(&record, fields);
        self.writable = creating || registry::may_write(&record);
        self.edit = Some(record);
        self.creating = creating;
        self.secret = None;
        self.inspection = None;
        self.pending = None;
        self.said = None;
    }
    fn form(&self, record: &Record) -> String {
        let may = !self.busy && self.writable;
        let mut rows = settings::row(
            "Name",
            "A display label; references use the permanent GUID.",
            &text("Name", "Name", "text", may),
        );
        if !self.creating {
            rows.push_str(&settings::fact("GUID", &record.id, true));
        }
        if record.kind != Kind::Identity {
            rows.push_str(&settings::row("Enabled","Disabled objects deny affected authentication. Established sessions follow the configured automatic session controls.",&settings::select("Enabled","Enabled",&[("1".into(),"Enabled".into()),("0".into(),"Disabled".into())],may)));
        }
        for (field, ty) in record.kind.fields() {
            if record.kind == Kind::AccessProfile && radius_authorization::spec(field).is_some() {
                continue;
            }
            if *field == "SessionControl" {
                rows.push_str(&session_control::policy_form(may));
                continue;
            }
            if matches!(*field, "SecretFile" | "ConnectSecurity") {
                continue;
            }
            if record.kind == Kind::Rule && *field == "Actions" {
                continue;
            }
            if record.kind == Kind::Rule && matches!(*field, "Policy" | "Parent") {
                let mut options = vec![(
                    String::new(),
                    if *field == "Parent" {
                        "No parent (root rule)".into()
                    } else {
                        "Choose policy…".into()
                    },
                )];
                if let Ok(stored) = &self.stored {
                    if *field == "Policy" {
                        options.extend(
                            stored
                                .objects
                                .iter()
                                .filter(|r| {
                                    r.kind == Kind::Policy
                                        && r.text("ServiceKind") != Some("accounting-only")
                                })
                                .map(|r| (r.id.clone(), r.name().into())),
                        );
                    } else {
                        options.extend(
                            stored
                                .objects
                                .iter()
                                .filter(|r| r.kind == Kind::Rule && r.id != record.id)
                                .map(|r| {
                                    let parent = r.text("Parent").unwrap_or_default();
                                    let path = if parent.is_empty() {
                                        r.id.clone()
                                    } else {
                                        format!("{parent}/{}", r.id)
                                    };
                                    let policy = stored
                                        .get(Kind::Policy, r.text("Policy").unwrap_or_default())
                                        .map(|p| p.name())
                                        .unwrap_or("Missing policy");
                                    (path, format!("{policy} / {}", r.name()))
                                }),
                        );
                    }
                }
                rows.push_str(&settings::row(
                    label(field),
                    "A rule stays under its original policy and parent after creation.",
                    &settings::select(field, label(field), &options, may && self.creating),
                ));
                continue;
            }
            let control = if let Some(kind) = reference(field) {
                let mut options = vec![(String::new(), "Choose…".into())];
                if let Ok(stored) = &self.stored {
                    for r in stored.objects.iter().filter(|r| r.kind == kind) {
                        options.push((r.id.clone(), r.name().into()));
                    }
                }
                if let Some(id) = record.text(field) {
                    if !options.iter().any(|(v, _)| v == id) {
                        options.push((id.into(), format!("Missing: {id}")));
                    }
                }
                settings::select(field, label(field), &options, may)
            } else if *field == "Policies" {
                let mut options = String::new();
                if let Ok(stored) = &self.stored {
                    for r in stored.objects.iter().filter(|r| r.kind == Kind::Policy) {
                        options.push_str(&format!(
                            r#"<label><input type="checkbox" name="allow-{}"{}>{}</label> "#,
                            escape(&r.id),
                            if may { "" } else { " disabled" },
                            escape(r.name())
                        ));
                    }
                }
                for id in record.list("Policies").unwrap_or_default() {
                    if !self
                        .stored
                        .as_ref()
                        .is_ok_and(|s| s.get(Kind::Policy, id).is_some())
                    {
                        options.push_str(&format!(r#"<label><input type="checkbox" name="allow-{}"{}>Missing: {}</label> "#,escape(id),if may{""}else{" disabled"},escape(id)));
                    }
                }
                options.push_str(r#"<input type="hidden" name="Policies">"#);
                format!(r#"<div class="radius-choices">{options}</div>"#)
            } else if *field == "AuthenticationMethods" {
                settings::select(
                    field,
                    "Authentication Methods",
                    &[
                        (
                            "peap-mschapv2,ttls-pap".into(),
                            "PEAP/MSCHAPv2, then TTLS/PAP".into(),
                        ),
                        (
                            "ttls-pap,peap-mschapv2".into(),
                            "TTLS/PAP, then PEAP/MSCHAPv2".into(),
                        ),
                        ("ttls-pap".into(), "TTLS/PAP only".into()),
                        ("peap-mschapv2".into(), "PEAP/MSCHAPv2 only".into()),
                    ],
                    may,
                )
            } else if matches!(*field, "Definition" | "Extensions") || *ty == Field::List {
                list(field, label(field), may)
            } else {
                text(field, label(field), "text", may)
            };
            let about = match *field {
                "Addresses" => "One IP address or canonical CIDR prefix per line.",
                "Policies" => "Only these policies may be selected by this client.",
                "CertificateFiles" => {
                    "Import PEM or DER files from this Peios machine, one path per line. Leave blank to keep the current certificate."
                }
                "PrivateKeyFile" => {
                    "Import the matching PEM or DER private key; the key is stored in a protected file."
                }
                _ => "",
            };
            rows.push_str(&settings::row(label(field), about, &control));
        }
        if record.kind == Kind::Rule {
            rows.push_str(&settings::row(
                "Action",
                "NULL uses the nearest parent action. REJECT wins equal-priority ties.",
                &settings::select(
                    "rule-action",
                    "Action",
                    &[
                        ("ASSIGN".into(), "Assign access profile".into()),
                        ("REJECT".into(), "Reject".into()),
                        ("NULL".into(), "Abstain (NULL)".into()),
                    ],
                    may,
                ),
            ));
            let mut profiles = vec![(String::new(), "Choose a profile…".into())];
            if let Ok(stored) = &self.stored {
                profiles.extend(
                    stored
                        .objects
                        .iter()
                        .filter(|r| r.kind == Kind::AccessProfile)
                        .map(|r| (r.id.clone(), r.name().into())),
                );
            }
            rows.push_str(&settings::row(
                "Access Profile",
                "Used by the Assign action.",
                &settings::select("rule-profile", "Access Profile", &profiles, may),
            ));
            for i in 0..self.condition_count {
                let controls = format!(
                    "{}{}{}{}",
                    text(&format!("rule-fact-{i}"), "Fact", "text", may),
                    settings::select(
                        &format!("rule-op-{i}"),
                        "Operator",
                        &[
                            ("Equal".into(), "Equals any listed value".into()),
                            ("Present".into(), "Present (1) or absent (0)".into()),
                            ("GreaterThan".into(), "Greater than".into()),
                            ("LessThan".into(), "Less than".into())
                        ],
                        may
                    ),
                    list(&format!("rule-values-{i}"), "Values (one per line)", may),
                    settings::button(
                        "Remove",
                        "condition-remove",
                        &[("index", &i.to_string())],
                        Button::Plain,
                        may
                    )
                );
                rows.push_str(&settings::row(&format!("Condition {}",i+1),"All conditions must match. Claim facts use Subject.Claim.name.Type; types include String, Int64, Uint64, Boolean, Sid and Octet.",&controls));
            }
            rows.push_str(&settings::row(
                "Conditions",
                "A rule with no conditions matches its whole parent region.",
                &settings::button(
                    "Add Condition",
                    "condition-add",
                    &[],
                    Button::Plain,
                    may && self.condition_count < radius_policy::MAX_CONDITIONS,
                ),
            ));
        }
        if record.kind == Kind::Client {
            rows.push_str(&settings::row("Shared Secret",if self.creating{"Leave blank to generate a secret. Reveal it after saving to configure the RADIUS client."}else{"Leave blank to keep the current secret. Replacement requires updating the corresponding RADIUS client."},&text("shared-secret","Shared Secret","password",may)));
        }
        if record.kind == Kind::DynamicProfile && self.creating {
            rows.push_str(&settings::row("WISPr Rate Mapping","Load the published upload/download attribute mappings into this draft. This does not establish equipment enforcement or enable live rate updates.",&settings::button("Use WISPr Template","equipment-wispr-template",&[],Button::Plain,may)));
        }
        let mut controls = settings::submit(
            if self.creating { "Create" } else { "Save" },
            Button::Primary,
            may,
        );
        controls.push_str(&settings::button(
            "Cancel",
            "close",
            &[],
            Button::Plain,
            !self.busy,
        ));
        let mut page = format!(
            r#"<form class="radius-record" fx-submit="save">{}{}{}</form>"#,
            settings::group("Configuration", &rows, ""),
            if record.kind == Kind::AccessProfile {
                authorization_form(may)
            } else {
                String::new()
            },
            settings::actions(&controls)
        );
        let mut permissions = String::new();
        if record.kind == Kind::Policy {
            permissions.push_str(&settings::row(
                "Connect Permissions",
                "Who may gain access through this policy. New policies initially permit no one.",
                &settings::button(
                    "Edit…",
                    "connect-permissions",
                    &[],
                    Button::Plain,
                    !self.busy,
                ),
            ));
        }
        if !self.creating {
            permissions.push_str(&settings::row(
                "Management Permissions",
                "Who may inspect or change this configuration object.",
                &settings::button(
                    "Edit…",
                    "management-permissions",
                    &[],
                    Button::Plain,
                    !self.busy,
                ),
            ));
        }
        page.push_str(&settings::group("Permissions", &permissions, ""));
        if !self.creating {
            let mut controls = String::new();
            if record.kind == Kind::Rule {
                controls.push_str(&settings::button(
                    "Add Exception…",
                    "rule-child",
                    &[],
                    Button::Plain,
                    may,
                ));
            }
            if record.kind == Kind::Client {
                controls.push_str(&settings::button(
                    if self.secret.is_some() {
                        "Hide Secret"
                    } else {
                        "Reveal Secret"
                    },
                    "reveal",
                    &[],
                    Button::Plain,
                    !self.busy,
                ));
                controls.push_str(&settings::button(
                    "Generate New Secret",
                    "generate",
                    &[],
                    Button::Plain,
                    may,
                ));
            }
            if record.kind == Kind::Identity {
                controls.push_str(&settings::button(
                    "Inspect Certificates",
                    "inspect",
                    &[],
                    Button::Plain,
                    !self.busy,
                ));
            }
            controls.push_str(&settings::button(
                "Delete…",
                "delete",
                &[],
                Button::Danger,
                may,
            ));
            page.push_str(&settings::group(
                "Actions",
                &settings::more(settings::More::Form, &settings::actions(&controls)),
                "",
            ));
        }
        if let Some(secret) = &self.secret {
            page.push_str(&settings::group(
                "Shared Secret",
                &settings::more(
                    settings::More::Form,
                    &format!(
                        "<p>Select and copy this value:</p><code>{}</code>",
                        escape(secret)
                    ),
                ),
                "",
            ));
        }
        if let Some(info) = &self.inspection {
            page.push_str(&settings::group(
                "Certificates",
                &settings::more(
                    settings::More::Form,
                    &format!("<pre>{}</pre>", escape(info)),
                ),
                "",
            ));
        }
        page
    }
    fn overview_page(&self) -> String {
        let mut rows = String::new();
        let daemon = self.overview["daemon"].as_str().unwrap_or("unknown");
        let (status, tone) = match daemon {
            "active" => ("Running", settings::Tone::Good),
            "invalid" => ("Needs attention", settings::Tone::Bad),
            "stopped" => ("Stopped", settings::Tone::Plain),
            _ => ("Unavailable", settings::Tone::Warn),
        };
        rows.push_str(&settings::row(
            "RADIUS Server",
            "Handles new authentication requests.",
            &settings::pill(status, tone),
        ));
        rows.push_str(&settings::fact(
            "Service",
            self.overview["service"]["state"]
                .as_str()
                .unwrap_or("Unavailable or not permitted"),
            false,
        ));
        rows.push_str(&settings::row(
            "Start at Boot",
            "Start the server automatically when this machine starts.",
            &match self.overview["start_at_boot"].as_bool() {
                Some(on) => settings::button(
                    if on {
                        "Disable at Boot"
                    } else {
                        "Enable at Boot"
                    },
                    "boot",
                    &[("on", if on { "0" } else { "1" })],
                    Button::Plain,
                    !self.busy,
                ),
                None => settings::value("Unavailable or not permitted", false),
            },
        ));
        let same = self.overview["saved_fingerprint"].is_string()
            && self.overview["saved_fingerprint"]
                == self.overview["runtime"]["effective_fingerprint"]
            && self.overview["runtime"]["state"] == "active";
        rows.push_str(&settings::fact(
            "Saved Configuration",
            if same {
                "Active"
            } else {
                "Not confirmed active"
            },
            false,
        ));
        let mut controls = String::new();
        for (action, title) in [
            ("start", "Start"),
            ("stop", "Stop…"),
            ("restart", "Restart…"),
        ] {
            controls.push_str(&settings::button(
                title,
                "service",
                &[("action", action)],
                Button::Plain,
                !self.busy,
            ));
        }
        rows.push_str(&settings::more(
            settings::More::Form,
            &settings::actions(&controls),
        ));
        let mut page = settings::group("Service", &rows, "");
        if self.overview["configuration_error_code"] == "not-found" {
            page.push_str(&settings::group(
                "Configuration",
                &settings::row(
                    "Initialize Configuration",
                    "Create an empty configuration. No client will be admitted until configured.",
                    &settings::button(
                        "Initialize…",
                        "initialize",
                        &[],
                        Button::Primary,
                        !self.busy,
                    ),
                ),
                "",
            ));
        }
        if let Ok(stored) = &self.stored {
            let mut issues = stored.validate();
            if let Some(runtime) = self.overview["runtime"]["issues"].as_array() {
                for issue in runtime {
                    issues.push(radius_management::model::Issue {
                        object: issue["object"].as_str().unwrap_or_default().into(),
                        field: issue["field"].as_str().unwrap_or_default().into(),
                        message: issue["message"].as_str().unwrap_or_default().into(),
                    });
                }
            }
            for issue in issues {
                page.push_str(&settings::banner(&format!(
                    "{} {}: {}",
                    issue.object, issue.field, issue.message
                )));
            }
        }
        for field in ["configuration_error", "runtime_error"] {
            if let Some(error) = self.overview[field].as_str() {
                page.push_str(&settings::note(error));
            }
        }
        let listen = listeners(&self.stored);
        let settings_form = format!(
            r#"<form fx-submit="listeners">{}</form>"#,
            settings::group(
                "Listeners",
                &format!(
                    "{}{}",
                    settings::row(
                        "Listen Addresses",
                        "Local IP addresses and UDP ports, one per line.",
                        &list("listeners", "Listen Addresses", !self.busy)
                    ),
                    settings::more(
                        settings::More::Form,
                        &settings::actions(&settings::submit("Save", Button::Primary, !self.busy))
                    )
                ),
                &settings::note(&format!("Currently saved: {listen}"))
            )
        );
        page.push_str(&settings_form);
        page
    }
    fn accounting_page(&self) -> String {
        let mut controls = settings::button(
            "Refresh Sessions",
            "accounting-refresh",
            &[],
            Button::Primary,
            !self.busy,
        );
        controls.push_str(&settings::button(
            "Health",
            "accounting-health",
            &[],
            Button::Plain,
            !self.busy,
        ));
        let mut page = settings::group(
            "Sessions",
            &settings::row(
                "Recorded Sessions",
                "Reports can arrive late or out of order; inferred states are labelled.",
                &controls,
            ),
            "",
        );
        if let Some(error) = self.accounting.get("error").and_then(|v| v.as_str()) {
            page.push_str(&settings::banner(error));
        }
        if let Some(rows) = self.accounting["sessions"].as_array() {
            let mut body = String::new();
            for row in rows {
                let id = row["id"].as_str().unwrap_or("");
                let name = row["name"]
                    .as_str()
                    .or_else(|| row["sid"].as_str())
                    .unwrap_or("Unresolved or protected identity");
                let mut actions = settings::button(
                    "Details",
                    "accounting-session",
                    &[("id", id)],
                    Button::Plain,
                    !self.busy,
                );
                actions.push_str(&settings::button(
                    "Disconnect…",
                    "accounting-disconnect",
                    &[("id", id)],
                    Button::Danger,
                    !self.busy && row["controls"]["disconnect"] == true,
                ));
                for (label, action) in [
                    ("Reauthenticate…", "reauthenticate"),
                    ("Update Access…", "update-authorization"),
                ] {
                    actions.push_str(&settings::button(
                        label,
                        "accounting-control",
                        &[("id", id), ("action", action)],
                        Button::Plain,
                        !self.busy && row["controls"][action] == true,
                    ));
                }
                actions.push_str(&settings::button(
                    "Reevaluation",
                    "accounting-reconciliation",
                    &[("id", id)],
                    Button::Plain,
                    !self.busy,
                ));
                body.push_str(&settings::row(
                    name,
                    &format!("{} · {}", id, row["state"].as_str().unwrap_or("unknown")),
                    &actions,
                ));
            }
            page.push_str(&settings::group("Session History", &body, ""));
            if let (Some(after), Some(revision)) = (
                self.accounting["next"].as_str(),
                self.accounting["revision"].as_u64(),
            ) {
                page.push_str(&settings::button(
                    "Next Page",
                    "accounting-next",
                    &[("after", after), ("revision", &revision.to_string())],
                    Button::Plain,
                    !self.busy,
                ));
            }
        }
        if let Some(health) = self.accounting.get("health") {
            let ledger = &health["ledger"];
            let mut body = settings::row(
                "Ledger",
                if ledger["available"] == true {
                    "Available"
                } else {
                    "Unavailable"
                },
                "",
            );
            for (key, label) in [
                ("committed", "Committed Reports"),
                ("duplicate", "Duplicate Reports"),
                ("failed", "Failed Reports"),
                ("admission_bypasses", "Admission Bypasses"),
                ("last_commit_latency_ms", "Last Commit (milliseconds)"),
            ] {
                body.push_str(&settings::row(label, "", &escape(&ledger[key].to_string())));
            }
            if let Some(error) = health["configuration_error"]
                .as_str()
                .or_else(|| ledger["last_error"].as_str())
            {
                body.push_str(&settings::banner(error));
            }
            page.push_str(&settings::group("Accounting Health", &body, ""));
        }
        if let Some(detail) = self.accounting.get("detail") {
            let row = &detail["session"];
            let mut body = String::new();
            for (key, label) in [
                ("id", "Session"),
                ("name", "Account"),
                ("sid", "Verified Principal"),
                ("state", "State"),
                ("kind", "Service Report"),
                ("input", "Received Bytes"),
                ("output", "Sent Bytes"),
            ] {
                if !row[key].is_null() {
                    body.push_str(&settings::row(
                        label,
                        "",
                        &escape(
                            &row[key]
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| row[key].to_string()),
                        ),
                    ));
                }
            }
            if let Some(warnings) = row["warnings"].as_array() {
                for warning in warnings.iter().filter_map(|v| v.as_str()) {
                    body.push_str(&settings::banner(warning));
                }
            }
            if let Some(history) = detail["history"].as_array() {
                body.push_str(&usage_history_graph(history));
            }
            body.push_str(&session_control::evidence(detail));
            page.push_str(&settings::group("Session Details", &body, ""));
        }
        if let Some(balances) = self.accounting.get("usage").and_then(|v| v.as_array()) {
            let mut body = String::new();
            for b in balances {
                let used = b["used"].as_u64().unwrap_or(0);
                let max = b["budget"]["maximum"].as_u64().unwrap_or(0);
                let percent = if max == 0 {
                    100
                } else {
                    ((used as u128) * 100 / (max as u128)).min(100) as u64
                };
                let label = b["budget"]["dimension"].as_str().unwrap_or("Usage");
                let unit = if label.ends_with("time") {
                    "milliseconds"
                } else if label == "concurrent" {
                    "sessions"
                } else {
                    "bytes"
                };
                let description = format!(
                    "{used} of {max} {unit} · {}{}",
                    b["budget"]["period"].as_str().unwrap_or(""),
                    if b["uncertain"] == true {
                        " · uncertain evidence"
                    } else {
                        ""
                    }
                );
                body.push_str(&settings::row(label,&description,&format!("<progress max=\"100\" value=\"{percent}\" aria-label=\"{}\">{percent}%</progress>",escape(label))));
            }
            page.push_str(&settings::group(
                "Principal Allowances",
                &body,
                "Every applicable allowance is consumed independently.",
            ));
        }
        page.push_str(&format!(
            r#"<form fx-submit="accounting-usage">{}{}</form>"#,
            settings::group(
                "Usage",
                &format!(
                    "{}{}",
                    settings::row(
                        "Principal SID",
                        "Usage belongs to a user or group principal.",
                        &text("usage-principal", "Principal SID", "text", !self.busy)
                    ),
                    settings::row(
                        "Policy GUID",
                        "Use * for allowances shared across policies.",
                        &text("usage-policy", "Policy GUID", "text", !self.busy)
                    )
                ),
                ""
            ),
            settings::submit("Show Usage", Button::Plain, !self.busy)
        ));
        page.push_str(&format!(r#"<form fx-submit="accounting-settings">{}{}</form>"#,settings::group("Accounting Settings",&format!("{}{}{}",settings::row("Enabled","The private ledger directory and UDP port permission must be provisioned before activation.",&settings::select("accounting-enabled","Enabled",&[("0".into(),"Disabled".into()),("1".into(),"Enabled".into())],!self.busy)),settings::row("Listen Addresses","Comma-separated UDP socket addresses.",&text("accounting-listen","Listen Addresses","text",!self.busy)),settings::row("Advanced Setting","Registry setting name and value; the CLI uses the same validator.",&format!("{}{}",text("accounting-setting","Setting Name","text",!self.busy),text("accounting-value","Setting Value","text",!self.busy)))),""),settings::submit("Save Settings",Button::Primary,!self.busy)));
        page.push_str(&session_control::global_form(!self.busy));
        page
    }
    fn permissions(&mut self, connect: bool) {
        let Some(record) = self.edit.clone() else {
            return;
        };
        let surface = self.surface.clone();
        let result = if !connect {
            gxwi_sd_editor::registry::key(
                &record.path(),
                record.name(),
                "You may not change this object's management permissions.",
            )
            .and_then(|(request, mut apply)| {
                gxwi_sd_editor::open(&request, move |sd, parts| apply(sd, parts), || {})
                    .map_err(|e| e.to_string())
            })
        } else {
            (|| {
                let sd = configuration::descriptor(
                    record
                        .values
                        .get("ConnectSecurity")
                        .ok_or_else(|| "Missing ConnectSecurity".to_owned())?,
                )
                .map_err(|e| e.to_string())?;
                let creating = self.creating;
                let may = creating || registry::may_write(&record);
                let request = gxwi_sd_editor::Request {
                    object: gxwi_sd_editor::Object {
                        name: record.name().into(),
                        kind: "RADIUS access policy".into(),
                        ..Default::default()
                    },
                    sd: sd.as_bytes().to_vec(),
                    read: None,
                    rights: vec![gxwi_sd_editor::Right {
                        name: "Connect".into(),
                        mask: 1,
                        general: true,
                    }],
                    generic: gxwi_sd_editor::Generic {
                        read: 1,
                        write: 0,
                        execute: 1,
                        all: 1,
                    },
                    can: gxwi_sd_editor::Can {
                        dacl: may,
                        owner: may,
                        audit: may,
                        ..Default::default()
                    },
                };
                gxwi_sd_editor::open(
                    &request,
                    move |edited, parts| {
                        if creating {
                            let Some(surface) = surface.upgrade() else {
                                return Err("Window closed".into());
                            };
                            let result = surface.look(|w, _, _| {
                                let current = w.edit.as_ref().ok_or("No policy being edited")?;
                                if !w.creating
                                    || current.kind != Kind::Policy
                                    || current.id != record.id
                                {
                                    return Err("The policy being edited has changed".into());
                                }
                                gxwi_sd_editor::splice(
                                    configuration::descriptor(
                                        current
                                            .values
                                            .get("ConnectSecurity")
                                            .ok_or("Missing ConnectSecurity")?,
                                    )
                                    .map_err(|e| e.to_string())?
                                    .as_bytes(),
                                    edited,
                                    parts,
                                )
                            });
                            let bytes = result?;
                            surface.update(|w, _| {
                                if let Some(r) = &mut w.edit {
                                    if w.creating && r.kind == Kind::Policy && r.id == record.id {
                                        r.values
                                            .insert("ConnectSecurity".into(), Value::Bytes(bytes));
                                    }
                                }
                            });
                            Ok(())
                        } else {
                            let stored = registry::read().map_err(|e| e.to_string())?;
                            let current = stored
                                .get(Kind::Policy, &record.id)
                                .ok_or("Policy no longer exists")?;
                            let current_sd = configuration::descriptor(
                                current
                                    .values
                                    .get("ConnectSecurity")
                                    .ok_or("Missing ConnectSecurity")?,
                            )
                            .map_err(|e| e.to_string())?;
                            let bytes =
                                gxwi_sd_editor::splice(current_sd.as_bytes(), edited, parts)?;
                            operations::save(
                                current,
                                &Values::from([("ConnectSecurity".into(), Value::Bytes(bytes))]),
                                false,
                            )
                            .map_err(|e| e.to_string())?;
                            Ok(())
                        }
                    },
                    || {},
                )
                .map_err(|e| e.to_string())
            })()
        };
        match result {
            Ok(editor) => self.sd_editor = Some(editor),
            Err(e) => self.said = Some(Err(e)),
        }
    }
}
impl Live for Window {
    fn render(&self, _: &Facts) -> String {
        let nav: Vec<_> = SECTIONS
            .iter()
            .map(|(id, title, glyph)| {
                Nav::Section(Section {
                    id,
                    title,
                    now: self.section_summary(id),
                    glyph: *glyph,
                    tile: section_tile(id),
                })
            })
            .collect();
        let title = SECTIONS
            .iter()
            .find(|(id, _, _)| *id == self.section)
            .unwrap();
        let mut page = settings::head(
            title.2,
            section_tile(self.section),
            title.1,
            section_about(self.section),
        );
        if let Some(pending) = &self.pending {
            page.push_str(&settings::group(
                "Confirm Change",
                &settings::more(
                    settings::More::Asking,
                    &format!(
                        "<p>{}</p>{}",
                        escape(&pending.description),
                        settings::actions(&format!(
                            "{}{}",
                            settings::button("Cancel", "cancel", &[], Button::Plain, true),
                            settings::button("Confirm", "confirm", &[], Button::Danger, !self.busy)
                        ))
                    ),
                ),
                "",
            ));
        }
        if self.section != "diagnostics" {
            if let Err(error) = &self.stored {
                page.push_str(&settings::banner(error));
            }
        }
        if self.section == "overview" {
            page.push_str(&self.overview_page());
        } else if self.section == "diagnostics" {
            page.push_str(&self.diagnostics_page());
        } else if self.section == "accounting" {
            page.push_str(&self.accounting_page());
        } else if self.section == "explain" {
            page.push_str(&self.explain_page());
        } else if let Some(record) = &self.edit {
            page.push_str(&self.form(record));
        } else if let Some(kind) = Kind::parse(self.section) {
            let mut rows = settings::row(
                "Add Configuration",
                "Create a new object in this section.",
                &settings::button("Create…", "create", &[], Button::Primary, !self.busy),
            );
            if let Ok(stored) = &self.stored {
                for r in stored.objects.iter().filter(|r| r.kind == kind) {
                    rows.push_str(&settings::row(
                        r.name(),
                        &format!(
                            "{} · {}",
                            r.id,
                            if r.enabled() { "Enabled" } else { "Disabled" }
                        ),
                        &settings::button(
                            "Edit…",
                            "edit",
                            &[("id", &r.id)],
                            Button::Plain,
                            !self.busy,
                        ),
                    ));
                }
                page.push_str(&settings::group("Configured Objects", &rows, ""));
            }
        }
        settings::window(
            &nav,
            self.section,
            &page,
            &settings::status(
                self.said.as_ref(),
                if self.busy {
                    "Working…"
                } else {
                    "Saved configuration and active configuration are shown separately"
                },
            ),
        )
    }
    fn input(&mut self, name: &str, fields: &mut Fields) {
        if self.busy {
            return;
        }
        if name.starts_with("explain-") {
            self.explanation = None;
        }
        if let Some(id) = name.strip_prefix("allow-") {
            let mut ids: Vec<String> = fields.get("Policies").lines().map(str::to_owned).collect();
            ids.retain(|v| v != id);
            if fields.get(name) == "on" {
                ids.push(id.to_owned());
            }
            fields.set("Policies", &ids.join("\n"));
        }
    }
    fn event(&mut self, name: &str, value: &EventValue, fields: &mut Fields) {
        if self.busy {
            return;
        }
        match name {
            "diagnostics-follow"=>{match self.diagnostic_filter(fields){
                Ok(filter)=>self.launch(Box::new(move||radius_management::native::diagnostics::Monitor::start(filter).map(Outcome::DiagnosticMonitor))),
                Err(error)=>self.said=Some(Err(error.to_string())),
            }},
            "diagnostics-refresh"=>{match self.diagnostic_filter(fields){
                Ok(filter)=>{self.diagnostic_monitor=None;self.launch(Box::new(move||radius_management::native::diagnostics::read(&filter).map(Outcome::Diagnostics)));},
                Err(error)=>self.said=Some(Err(error.to_string())),
            }},
            "diagnostics-stop"=>{self.diagnostic_monitor=None;self.diagnostics.following=false;self.diagnostics.status="Following stopped".into();},
            "diagnostics-select"=>{if let Some(id)=value.get("id").and_then(|v|v.as_str()){
                self.diagnostic_selected=Some(id.into());self.diagnostic_authority=None;
            }},
            "diagnostics-authority"=>{
                let id=self.diagnostics.attempts.iter().find(|a|Some(&a.id)==self.diagnostic_selected.as_ref())
                    .and_then(|a|a.summary.get(radius_management::diagnostics::OPERATION)).and_then(serde_json::Value::as_str).map(str::to_owned);
                if let Some(id)=id{self.launch(Box::new(move||radius_management::native::diagnostics::authority(&id).map(Outcome::DiagnosticAuthority)));}
            },
            "diagnostics-current"=>{
                let section = match value.get("section").and_then(|v|v.as_str()) {
                    Some("client")=>Some("client"), Some("policy")=>Some("policy"),
                    Some("profile")=>Some("profile"), Some("access-profile")=>Some("access-profile"),
                    Some("rule")=>Some("rule"), _=>None,
                };
                if let (Some(section),Some(id),Ok(stored))=(section,value.get("id").and_then(|v|v.as_str()),&self.stored){
                    if let Some(record)=Kind::parse(section).and_then(|kind|stored.get(kind,id)).cloned(){
                        self.section=section;self.begin_edit(record,false,fields);
                    }
                }
            },
            "rule-child"=>{
                if let Some(parent)=self.edit.clone().filter(|r|r.kind==Kind::Rule&&!self.creating&&self.writable) {
                    match Record::new(Kind::Rule,"") {
                        Ok(mut record)=>{
                            record.values.insert("Policy".into(),Value::Text(parent.text("Policy").unwrap_or_default().into()));
                            let path=parent.text("Parent").unwrap_or_default();
                            record.values.insert("Parent".into(),Value::Text(if path.is_empty(){parent.id}else{format!("{path}/{}",parent.id)}));
                            self.begin_edit(record,true,fields);
                        },Err(e)=>self.said=Some(Err(e)),
                    }
                }
            },
            "explain-claim-add"=>{if self.explain_claim_count<64 {
                let i=self.explain_claim_count;self.explain_claim_count+=1;self.explanation=None;
                fields.set(&format!("explain-claim-name-{i}"),"");fields.set(&format!("explain-claim-type-{i}"),"String");fields.set(&format!("explain-claim-values-{i}"),"");
            }},
            "explain-claim-remove"=>{
                if let Some(i)=value.get("index").and_then(|v|v.as_str()).and_then(|v|v.parse::<usize>().ok()).filter(|i|*i<self.explain_claim_count) {
                    for j in i..self.explain_claim_count-1 {for suffix in ["name","type","values"] {
                        let value=fields.get(&format!("explain-claim-{suffix}-{}",j+1)).to_owned();fields.set(&format!("explain-claim-{suffix}-{j}"),&value);
                    }}self.explain_claim_count-=1;self.explanation=None;
                }
            },
            "condition-add"=>{
                if self.edit.as_ref().is_some_and(|r|r.kind==Kind::Rule)&&self.writable&&self.condition_count<radius_policy::MAX_CONDITIONS {
                    let i=self.condition_count;self.condition_count+=1;
                    fields.set(&format!("rule-fact-{i}"),"Subject.Group");fields.set(&format!("rule-op-{i}"),"Equal");fields.set(&format!("rule-values-{i}"),"");
                }
            },
            "condition-remove"=>{
                if let Some(i)=value.get("index").and_then(|v|v.as_str()).and_then(|v|v.parse::<usize>().ok()).filter(|i|*i<self.condition_count) {
                    for j in i..self.condition_count-1 {for suffix in ["fact","op","values"] {
                        let text=fields.get(&format!("rule-{suffix}-{}",j+1)).to_owned();fields.set(&format!("rule-{suffix}-{j}"),&text);
                    }}self.condition_count-=1;
                }
            },
            "explain-run"=>{
                match explanation_facts(fields,self.explain_claim_count) {
                    Ok(facts)=>{let policy=fields.get("explain-policy").to_owned();self.launch(Box::new(move||operations::explain(&policy,&facts).map(Outcome::Explained)));},
                    Err(e)=>self.said=Some(Err(e.to_string())),
                }
            },
            "accounting-refresh"=>self.launch(Box::new(||Ok(Outcome::Accounting(radius_management::native::accounting::query(radius_management::accounting::Request::Sessions{filter:crate::cli::radius_accounting_filter(None)})?)))),
            "accounting-next"=>{if let (Some(after),Some(revision))=(value.get("after").and_then(|v|v.as_str()),value.get("revision").and_then(|v|v.as_str()).and_then(|v|v.parse().ok())) {
                let mut filter=crate::cli::radius_accounting_filter(None);filter.after=Some(after.into());filter.revision=Some(revision);
                self.launch(Box::new(move||Ok(Outcome::Accounting(radius_management::native::accounting::query(radius_management::accounting::Request::Sessions{filter})?))));
            }},
            "accounting-health"=>self.launch(Box::new(||Ok(Outcome::AccountingView("health",radius_management::native::accounting::query(radius_management::accounting::Request::Status)?)))),
            "accounting-session"=>{if let Some(id)=value.get("id").and_then(|v|v.as_str()){let id=id.to_owned();self.launch(Box::new(move||{
                use radius_management::{accounting::Request as R,native::accounting::query};
                let session=query(R::Session{id:id.clone()})?;
                let history=query(R::History{id:id.clone(),limit:200}).ok();
                let reconciliation=query(R::Reconciliation{id:id.clone()}).ok();
                let commands=query(R::Commands{id}).ok();
                Ok(Outcome::AccountingView("detail",serde_json::json!({"session":session,"history":history,"reconciliation":reconciliation,"commands":commands})))
            }));}},
            "accounting-disconnect"=>{if let Some(id)=value.get("id").and_then(|v|v.as_str()){let id=id.to_owned();self.request("Ask the network device to disconnect this session? Acknowledgement does not confirm the session has ended.".into(),Box::new(move||{radius_management::native::accounting::query(radius_management::accounting::Request::Control{request_id:String::new(),id,action:radius_accounting::dynamic::Action::Disconnect})?;Ok(Outcome::Done("Disconnect queued. Refresh accounting to observe the result.".into()))}));}},
            "accounting-control" => {
                if let (Some(id), Some(action)) = (value.get("id").and_then(|v|v.as_str()), value.get("action").and_then(|v|v.as_str())) {
                    let action = match action { "reauthenticate" => radius_accounting::dynamic::Action::Reauthenticate, "update-authorization" => radius_accounting::dynamic::Action::UpdateAuthorization, _ => return };
                    let id = id.to_owned();
                    self.request("Send this session control request? Any configured fallback requires its own permission and may disconnect the device. Acceptance does not confirm fresh authentication or address renewal.".into(), Box::new(move || {
                        let command = radius_management::native::accounting::query(radius_management::accounting::Request::Control { request_id:String::new(), id, action })?;
                        Ok(Outcome::Inspected(serde_json::to_string_pretty(&command).unwrap_or_default()))
                    }));
                }
            },
            "accounting-reconciliation" => {
                if let Some(id) = value.get("id").and_then(|v|v.as_str()) {
                    let id = id.to_owned();
                    self.launch(Box::new(move || {
                        let result = radius_management::native::accounting::query(radius_management::accounting::Request::Reconciliation { id })?;
                        Ok(Outcome::Inspected(serde_json::to_string_pretty(&result).unwrap_or_default()))
                    }));
                }
            },
            "accounting-usage"=>{let principal=fields.get("usage-principal").to_owned();let policy=fields.get("usage-policy").to_owned();self.launch(Box::new(move||Ok(Outcome::AccountingView("usage",radius_management::native::accounting::query(radius_management::accounting::Request::Usage{principal,policy})?))));},
            "accounting-settings"=>{let mut patch=Values::new();for (field,name) in [("accounting-enabled","AccountingEnabled"),("accounting-listen","AccountingListen")]{match operations::parse_setting(name,fields.get(field)){Ok(v)=>{patch.insert(name.into(),v);},Err(e)=>{self.said=Some(Err(e.to_string()));return;}}}let name=fields.get("accounting-setting");if !name.is_empty(){if !name.starts_with("Accounting"){self.said=Some(Err("Choose an accounting setting.".into()));return;}match operations::parse_setting(name,fields.get("accounting-value")){Ok(v)=>{patch.insert(name.into(),v);},Err(e)=>{self.said=Some(Err(e.to_string()));return;}}}self.launch(Box::new(move||{operations::save_settings(&patch)?;Ok(Outcome::Done("Accounting settings saved; activation is checked separately.".into()))}));},
            "session-control-settings" => {
                match session_control::global_value(fields) {
                    Ok(patch) => self.launch(Box::new(move || { operations::save_settings(&patch)?; Ok(Outcome::Done("Session controls saved; check activation status.".into())) })),
                    Err(error) => self.said = Some(Err(error.to_string())),
                }
            },
            "initialize"=>self.request("Create the initial RADIUS configuration? Existing configuration will not be overwritten.".into(),Box::new(||{operations::initialize()?;Ok(Outcome::Done("Configuration initialized.".into()))})),
            "section" => {
                if let Some(section) = value
                    .get("section")
                    .and_then(|v| v.as_str())
                    .and_then(|id| SECTIONS.iter().find(|(s, _, _)| *s == id))
                {
                    self.section = section.0;
                    self.edit = None;
                    self.pending = None;
                    self.secret = None;
                    self.inspection = None;
                    fields.set("shared-secret", "");
                    if section.0=="accounting"{
                        session_control::fill_global(&self.stored, fields);
                        fields.set("usage-policy","*");
                        let settings=self.stored.as_ref().ok().map(|s|&s.settings);
                        fields.set("accounting-enabled",if settings.and_then(|v|v.get("AccountingEnabled"))==Some(&Value::Number(1)){"1"}else{"0"});
                        fields.set("accounting-listen",&settings.and_then(|v|v.get("AccountingListen")).map(|v|field_text(v).replace('\n',",")).unwrap_or_else(||"0.0.0.0:1813".into()));
                    }
                }
            }
            "create" => {
                if let Some(kind) = Kind::parse(self.section) {
                    match Record::new(kind, "") {
                        Ok(mut record) => {
                            if kind == Kind::Policy {
                                record.values.insert(
                                    "ConnectSecurity".into(),
                                    Value::Text("O:BAG:BAD:P".into()),
                                );
                            }
                            if kind == Kind::Profile {
                                record.values.insert(
                                    "AuthenticationMethods".into(),
                                    Value::List(vec!["peap-mschapv2".into(), "ttls-pap".into()]),
                                );
                            }
                            self.begin_edit(record, true, fields);
                        }
                        Err(e) => self.said = Some(Err(e)),
                    }
                }
            }
            "edit" => {
                if let (Some(kind), Some(id), Ok(stored)) = (
                    Kind::parse(self.section),
                    value.get("id").and_then(|v| v.as_str()),
                    &self.stored,
                ) {
                    if let Some(record) = stored.get(kind, id).cloned() {
                        self.begin_edit(record, false, fields);
                    }
                }
            }
            "equipment-wispr-template"=>{
                if self.creating && self.edit.as_ref().is_some_and(|r|r.kind==Kind::DynamicProfile) {
                    fields.set("Definition",&serde_json::to_string_pretty(&radius_accounting::dynamic::Profile::wispr_rates()).expect("equipment template serializes"));
                }
            },
            "close" => {
                self.edit = None;
                self.pending = None;
                self.secret = None;
                self.inspection = None;
                fields.set("shared-secret", "");
            }
            "cancel" => self.pending = None,
            "confirm" => {
                if let Some(p) = self.pending.take() {
                    self.launch(p.action);
                }
            }
            "connect-permissions" => self.permissions(true),
            "management-permissions" => self.permissions(false),
            "service" => {
                if let Some(action) = value
                    .get("action")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                {
                    let start = action == "start";
                    let description=format!("{action} radiusd? Authentication will be interrupted. Established access may continue until reauthentication is required.");
                    let work: Action = Box::new(move || {
                        service::command(&action)?;
                        Ok(Outcome::Done(format!("Service action submitted: {action}")))
                    });
                    if start {
                        self.launch(work);
                    } else {
                        self.request(description, work);
                    }
                }
            }
            "boot" => {
                let on = value.get("on").and_then(|v| v.as_str()) == Some("1");
                self.launch(Box::new(move || {
                    service::start_at_boot(on)?;
                    Ok(Outcome::Done("Boot startup setting saved.".into()))
                }));
            }
            "listeners" => {
                let addresses: Vec<_> = fields
                    .get("listeners")
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                self.launch(Box::new(move || {
                    operations::save_settings(&Values::from([
                        ("Listen".into(), Value::List(addresses)),
                    ]))?;
                    Ok(Outcome::Done("Saved; check activation status.".into()))
                }));
            }
            "save" => {
                let Some(record) = self.edit.clone() else {
                    return;
                };
                let creating = self.creating;
                let mut patch = Values::new();
                let mut remove=Vec::new();
                patch.insert("Name".into(), Value::Text(fields.get("Name").to_owned()));
                if record.kind != Kind::Identity {
                    patch.insert(
                        "Enabled".into(),
                        Value::Number(if fields.get("Enabled") == "1" { 1 } else { 0 }),
                    );
                }
                let mut import = false;
                for (field, ty) in record.kind.fields() {
                    if *field == "SessionControl" {
                        match session_control::policy_value(&record, fields) { Ok(value) => { patch.insert((*field).into(), value); }, Err(error) => { self.said = Some(Err(error.to_string())); return; } }
                        continue;
                    }
                    if matches!(*field, "SecretFile" | "ConnectSecurity") {
                        continue;
                    }
                    if record.kind==Kind::Rule && (matches!(*field,"Actions") || (!creating&&matches!(*field,"Policy"|"Parent"))) {continue;}
                    let text = fields.get(field);
                    if record.kind==Kind::AccessProfile && record.kind.optional(field) && text.is_empty(){if record.values.contains_key(*field){remove.push((*field).into());}continue;}
                    if text.is_empty()&&record.kind.optional(field)&&matches!(*field,"VlanId"|"Priority") {
                        if record.values.contains_key(*field){remove.push((*field).into());}continue;
                    }
                    if text.is_empty()&&record.kind.optional(field)&&*ty==Field::Number{continue;}
                    if record.kind == Kind::Identity && !creating && text.is_empty() {
                        continue;
                    }
                    if record.kind == Kind::Identity {
                        import = true;
                    }
                    let value = match ty {
                        Field::List => Value::List(
                            text.split(if *field=="AuthenticationMethods" {','} else {'\n'})
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_owned)
                                .collect(),
                        ),
                        Field::Number => match text.parse() {
                            Ok(n) => Value::Number(n),
                            Err(_) => {
                                self.said = Some(Err(format!("{} must be a number", label(field))));
                                return;
                            }
                        },
                        _ => Value::Text(text.to_owned()),
                    };
                    patch.insert((*field).into(), value);
                }
                if record.kind==Kind::Rule {
                    let action=match fields.get("rule-action") {
                        "ASSIGN"=>format!("ASSIGN({})",fields.get("rule-profile")),"REJECT"=>"REJECT".into(),_=>"NULL".into(),
                    };patch.insert("Actions".into(),Value::List(vec![action]));
                    for i in 0..self.condition_count {
                        let key=format!("{}.{}",fields.get(&format!("rule-fact-{i}")).trim(),fields.get(&format!("rule-op-{i}")));
                        let text=fields.get(&format!("rule-values-{i}"));
                        let value=if key.ends_with(".Equal") {Value::List(text.lines().map(str::to_owned).collect())}
                            else {match operations::parse_field(Kind::Rule,&key,text) {Ok(v)=>v,Err(e)=>{self.said=Some(Err(e.to_string()));return;}}};
                        if patch.insert(key,value).is_some(){self.said=Some(Err("Duplicate condition; put alternatives in one condition.".into()));return;}
                    }
                    for (key,_) in rule_conditions(&record) {if !patch.contains_key(key){remove.push(key.into());}}
                }
                let secret = Zeroizing::new(fields.get("shared-secret").as_bytes().to_vec());
                fields.set("shared-secret", "");
                let needs_confirmation = !creating
                    && ((record.kind == Kind::Profile
                        && patch.get("Enabled") == Some(&Value::Number(0)))
                        || (record.kind == Kind::Identity && import));
                let description = self
                    .stored
                    .as_ref()
                    .ok()
                    .map(|s| affected(s, &record))
                    .unwrap_or_default();
                let work: Action = Box::new(move || {
                    let secret = (!secret.is_empty()).then_some(secret.as_slice());
                    if record.kind==Kind::Rule || record.kind==Kind::AccessProfile {
                        operations::save_edit(&record,&patch,&remove,creating).map(Outcome::Saved)
                    }else{operations::submit(&record, &mut patch, creating, secret, import).map(Outcome::Saved)}
                });
                if needs_confirmation {
                    self.request(format!("Apply this change? {description}"), work);
                } else {
                    self.launch(work);
                }
            }
            "delete" => {
                if let Some(record) = self.edit.clone() {
                    let description = format!(
                        "Delete {}? {}",
                        record.name(),
                        self.stored
                            .as_ref()
                            .ok()
                            .map(|s| affected(s, &record))
                            .unwrap_or_default()
                    );
                    self.request(
                        description,
                        Box::new(move || {
                            registry::remove(&record)?;
                            Ok(Outcome::Done("Deleted; check activation status.".into()))
                        }),
                    );
                }
            }
            "generate" => {
                if let Some(record) = self.edit.clone() {
                    self.request("Replace this client's shared secret? Update the corresponding RADIUS client after saving.".into(),Box::new(move||{credentials::replace_secret(&record,&credentials::generated_secret()?)?;Ok(Outcome::Saved(record))}));
                }
            }
            "reveal" => {
                if self.secret.take().is_none() {
                    if let Some(record) = self.edit.clone() {
                        self.launch(Box::new(move || {
                            let path = record
                                .text("SecretFile")
                                .ok_or_else(|| io::Error::other("Secret not configured"))?;
                            let bytes = credentials::material(path, true, 1024)?;
                            let secret = String::from_utf8(bytes.to_vec()).map_err(|_| {
                                io::Error::other("Secret is binary; use the CLI to read it")
                            })?;
                            Ok(Outcome::Revealed(Zeroizing::new(secret)))
                        }));
                    }
                }
            }
            "inspect" => {
                if let Some(record) = self.edit.clone() {
                    self.launch(Box::new(move || {
                        Ok(Outcome::Inspected(
                            serde_json::to_string_pretty(&credentials::inspect(&record)?)
                                .map_err(io::Error::other)?,
                        ))
                    }));
                }
            }
            _ => {}
        }
    }
}
pub fn open() -> i32 {
    let mut app = match App::connect() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("radius: cannot open GXWI: {e}");
            return 1;
        }
    };
    settings::stylesheet(&mut app);
    app.stylesheet("/radius.css", include_str!("window.css"));
    let surface = app.live(
        "RADIUS",
        Window {
            diagnostics: Default::default(),
            diagnostic_monitor: None,
            diagnostic_selected: None,
            diagnostic_authority: None,
            surface: Weak::new(),
            section: "overview",
            stored: read(),
            overview: overview(),
            accounting: serde_json::Value::Null,
            edit: None,
            creating: false,
            writable: false,
            busy: false,
            pending: None,
            said: None,
            secret: None,
            inspection: None,
            sd_editor: None,
            condition_count: 0,
            explain_claim_count: 1,
            explanation: None,
        },
    );
    let weak = Arc::downgrade(&surface);
    surface.update(|w, fields| {
        w.surface = weak.clone();
        fields.set("listeners", &listeners(&w.stored));
    });
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(3));
        let Some(surface) = weak.upgrade() else {
            return;
        };
        let stored = read();
        let overview = overview();
        surface.update(|w, fields| {
            if let Some(monitor) = &w.diagnostic_monitor {
                w.diagnostics = monitor.snapshot();
            }
            if !w.busy {
                w.heard(stored, fields);
                w.overview = overview;
            }
        });
    });
    match app.run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("radius: GXWI: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hypothetical_claims_keep_types_and_completeness_explicit() {
        let mut fields = Fields::default();
        fields.set("explain-claim-name-0", "Équipe");
        fields.set("explain-claim-type-0", "String");
        fields.set("explain-claim-values-0", "Engineering");
        fields.set("explain-claim-name-1", "Limit");
        fields.set("explain-claim-type-1", "Uint64");
        fields.set("explain-claim-values-1", "18446744073709551615");
        let facts = explanation_facts(&fields, 2).unwrap();
        assert_eq!(facts.claim_coverage, radius_policy::ClaimCoverage::Filtered);
        assert_eq!(
            facts["Subject.Claim.équipe"],
            vec![radius_policy::Scalar::String("Engineering".into())]
        );
        assert_eq!(
            facts["Subject.Claim.Limit"],
            vec![radius_policy::Scalar::Uint64(u64::MAX)]
        );
        fields.set("explain-claim-name-1", "équipe");
        assert!(explanation_facts(&fields, 2).is_err());
    }
    #[test]
    fn adding_an_exception_preserves_policy_and_real_parent_path() {
        let mut w = window();
        let mut fields = Fields::default();
        let mut rule = Record::new(Kind::Rule, "Default").unwrap();
        rule.values.insert(
            "Policy".into(),
            Value::Text("11111111-1111-4111-8111-111111111111".into()),
        );
        let parent = rule.id.clone();
        w.edit = Some(rule);
        w.creating = false;
        w.event("rule-child", &serde_json::json!({}), &mut fields);
        let child = w.edit.as_ref().unwrap();
        assert!(w.creating);
        assert_eq!(child.text("Parent"), Some(parent.as_str()));
        assert_eq!(
            child.text("Policy"),
            Some("11111111-1111-4111-8111-111111111111")
        );
    }
    #[test]
    fn explanation_view_escapes_rule_names_and_marks_simulation() {
        let mut w = window();
        w.explanation = Some(
            serde_json::json!({"configuration":"saved","fingerprint":"test","explanation":{
            "outcome":"conflicting-profiles","candidates":[{"rule":"<script>unsafe()</script>","profile":null,"priority":0}],"rules":[]}}),
        );
        let page = w.explain_page();
        assert!(!page.contains("<script>unsafe()"));
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("Hypothetical"));
        assert!(page.contains("were not checked"));
        let mut fields = Fields::default();
        w.input("explain-user", &mut fields);
        assert!(w.explanation.is_none());
    }
    pub(super) fn window() -> Window {
        Window {
            diagnostics: Default::default(),
            diagnostic_monitor: None,
            diagnostic_selected: None,
            diagnostic_authority: None,
            surface: Weak::new(),
            section: "overview",
            stored: Ok(Stored::default()),
            overview: serde_json::json!({"daemon":"invalid","service":{"state":"Active"},"start_at_boot":true,"runtime":{"issues":[{"object":"policy-guid","field":"References","message":"missing profile-guid"}]}}),
            accounting: serde_json::Value::Null,
            edit: None,
            creating: false,
            writable: true,
            busy: false,
            pending: None,
            said: None,
            secret: None,
            inspection: None,
            sd_editor: None,
            condition_count: 0,
            explain_claim_count: 1,
            explanation: None,
        }
    }
    fn policy() -> Record {
        let mut r = Record::new(Kind::Policy, "Household").unwrap();
        r.values
            .insert("ConnectSecurity".into(), Value::Text("O:BAG:BAD:P".into()));
        r
    }
    #[test]
    fn listener_refresh_follows_saved_changes_without_overwriting_a_draft() {
        let mut w = window();
        w.stored
            .as_mut()
            .unwrap()
            .settings
            .insert("Listen".into(), Value::List(vec!["127.0.0.1:1812".into()]));
        let mut fields = Fields::default();
        fields.set("listeners", &listeners(&w.stored));
        assert_eq!(fields.get("listeners"), "127.0.0.1:1812");
        let mut changed = w.stored.clone();
        changed
            .as_mut()
            .unwrap()
            .settings
            .insert("Listen".into(), Value::List(vec!["0.0.0.0:1812".into()]));
        w.heard(changed, &mut fields);
        assert_eq!(fields.get("listeners"), "0.0.0.0:1812");
        fields.set("listeners", "192.0.2.1:1812");
        let mut changed_again = w.stored.clone();
        changed_again
            .as_mut()
            .unwrap()
            .settings
            .insert("Listen".into(), Value::List(vec!["127.0.0.1:18120".into()]));
        w.heard(changed_again, &mut fields);
        assert_eq!(fields.get("listeners"), "192.0.2.1:1812");
        assert_eq!(listeners(&w.stored), "127.0.0.1:18120");
    }
    #[test]
    fn all_five_areas_render_and_invalid_configuration_remains_visible() {
        let mut w = window();
        let fields = Fields::default();
        for (section, _, _) in SECTIONS {
            w.section = section;
            if let Some(kind) = Kind::parse(section) {
                w.edit = Some(if kind == Kind::Policy {
                    policy()
                } else {
                    Record::new(kind, "Example").unwrap()
                });
                w.creating = true;
            }
            let html = w.render(&Facts {
                views: 2,
                fields: &fields,
            });
            for (_, title, _) in SECTIONS {
                assert!(html.contains(title));
            }
            assert!(!html.contains("UniFi"));
            assert!(!html.contains("Disconnect Sessions"));
            if section == "overview" {
                assert!(html.contains("missing profile-guid"));
                assert!(html.contains("Not confirmed active"));
            }
            if let Ok(directory) = std::env::var("RADIUS_RENDER_DIRECTORY") {
                std::fs::create_dir_all(&directory).unwrap();
                let document = format!(
                    "<!doctype html><html><head><meta name=viewport content=\"width=device-width,initial-scale=1\"><style>{}</style></head><body>{html}</body></html>",
                    settings::STYLE
                );
                std::fs::write(
                    std::path::Path::new(&directory).join(format!("{section}.html")),
                    document,
                )
                .unwrap();
            }
        }
    }
    #[test]
    fn permission_actions_have_distinct_meanings() {
        let mut w = window();
        w.section = "policy";
        w.edit = Some(policy());
        let html = w.render(&Facts {
            views: 1,
            fields: &Fields::default(),
        });
        assert!(html.contains("Connect Permissions"));
        assert!(html.contains("Management Permissions"));
        assert!(html.contains("connect-permissions"));
        assert!(html.contains("management-permissions"));
    }
    #[test]
    fn broken_client_references_can_be_removed_with_the_same_controls() {
        let id = "22222222-2222-4222-8222-222222222222";
        let mut r = Record::new(Kind::Client, "APs").unwrap();
        r.values
            .insert("Policies".into(), Value::List(vec![id.into()]));
        let mut fields = Fields::default();
        fill(&r, &mut fields);
        let mut w = window();
        w.section = "client";
        w.edit = Some(r);
        let html = w.render(&Facts {
            views: 1,
            fields: &fields,
        });
        assert!(html.contains(&format!("Missing: {id}")));
        fields.set(&format!("allow-{id}"), "");
        w.input(&format!("allow-{id}"), &mut fields);
        assert_eq!(fields.get("Policies"), "");
    }
    #[test]
    fn method_order_survives_editing_and_names_are_escaped() {
        let mut r = Record::new(Kind::Profile, "<script>unexpected()</script>").unwrap();
        r.values.insert(
            "AuthenticationMethods".into(),
            Value::List(vec!["ttls-pap".into(), "peap-mschapv2".into()]),
        );
        let mut fields = Fields::default();
        fill(&r, &mut fields);
        assert_eq!(
            fields.get("AuthenticationMethods"),
            "ttls-pap,peap-mschapv2"
        );
        let mut w = window();
        w.section = "profile";
        w.stored.as_mut().unwrap().objects.push(r);
        let html = w.render(&Facts {
            views: 1,
            fields: &fields,
        });
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
    #[test]
    fn accounting_views_escape_identity_and_keep_unsigned_usage_exact() {
        let mut w = window();
        w.section = "accounting";
        w.accounting = serde_json::json!({
            "sessions":[{"id":"fixture","name":"<script>identity</script>","state":"stale"}],
            "usage":[{"used":u64::MAX,"budget":{"maximum":u64::MAX,"dimension":"total-bytes","period":"lifetime"},"uncertain":true}],
            "detail":{"session":{"id":"fixture","state":"stale"},"history":[{"effective_ms":1000,"input":0,"output":0},{"effective_ms":2000,"input":u64::MAX,"output":10}]}
        });
        let html = w.accounting_page();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("18446744073709551615"));
        assert!(
            html.contains("uncertain evidence")
                && html.contains("<progress")
                && html.contains("<svg")
        );
    }
    #[test]
    fn ordinary_client_pages_do_not_reveal_secret_values() {
        let mut w = window();
        w.section = "client";
        w.edit = Some(Record::new(Kind::Client, "APs").unwrap());
        let html = w.render(&Facts {
            views: 1,
            fields: &Fields::default(),
        });
        assert!(html.contains("Reveal Secret"));
        assert!(!html.contains("Select and copy this value"));
        assert!(html.contains("type=\"password\""));
    }

    #[test]
    fn rich_profile_fields_share_metadata_and_preserve_rule_priority_label() {
        let html = authorization_form(true);
        for field in radius_authorization::FIELDS {
            assert!(html.contains(field.name), "missing {}", field.name);
            assert!(html.contains(field.group), "missing {}", field.group);
        }
        assert!(html.contains("bits/second"));
        assert!(html.contains("Use equipment default"));
        assert!(html.contains("SessionExpiryAction"));
        assert!(label("Priority").contains("inherit"));
        let mut w = window();
        w.explanation = Some(
            serde_json::json!({"explanation":{"assignment":{"settings":{"Priority":0}},"outcome":"assigned","rules":[]}}),
        );
        assert!(w.explain_page().contains("Traffic Priority"));
        w.section = "dynamic-profile";
        w.edit = Some(Record::new(Kind::DynamicProfile, "Example").unwrap());
        w.creating = true;
        let html = w.render(&Facts {
            views: 1,
            fields: &Fields::default(),
        });
        assert!(html.contains("WISPr"));
    }
}
