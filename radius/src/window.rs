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
type Action = Box<dyn FnOnce() -> io::Result<Outcome> + Send>;
enum Outcome {
    Saved(Record),
    Done(String),
    Revealed(Zeroizing<String>),
    Inspected(String),
}
struct Pending {
    description: String,
    action: Action,
}
struct Window {
    surface: Weak<Surface<Self>>,
    section: &'static str,
    stored: Result<Stored, String>,
    overview: serde_json::Value,
    edit: Option<Record>,
    creating: bool,
    writable: bool,
    busy: bool,
    pending: Option<Pending>,
    said: Option<Result<String, String>>,
    secret: Option<Zeroizing<String>>,
    inspection: Option<String>,
    sd_editor: Option<gxwi_sd_editor::Editor>,
}
const SECTIONS: [(&str, &str, Glyph); 5] = [
    ("overview", "Overview", Glyph::Server),
    ("client", "Clients", Glyph::Globe),
    ("policy", "Access Policies", Glyph::Shield),
    ("profile", "Authentication Profiles", Glyph::Key),
    ("identity", "Server Identities", Glyph::Certificate),
];
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
    fields.set("Name", record.name());
    fields.set("Enabled", if record.enabled() { "1" } else { "0" });
    fields.set("shared-secret", "");
    for (name, _) in record.kind.fields() {
        fields.set(
            name,
            &record.values.get(*name).map(field_text).unwrap_or_default(),
        );
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
        _ => field,
    }
}
fn reference(field: &str) -> Option<Kind> {
    match field {
        "AuthenticationProfile" => Some(Kind::Profile),
        "ServerIdentity" => Some(Kind::Identity),
        _ => None,
    }
}
fn affected(stored: &Stored, record: &Record) -> String {
    let uses = stored.dependents(record.kind, &record.id);
    if uses.is_empty() {
        "No configuration objects reference this object.".into()
    } else {
        format!(
            "Used by: {}.",
            uses.iter().map(|r| r.name()).collect::<Vec<_>>().join(", ")
        )
    }
}
impl Window {
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
                    w.stored = stored;
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
            rows.push_str(&settings::row("Enabled","Disabled objects deny affected authentication; established access is not immediately disconnected.",&settings::select("Enabled","Enabled",&[("1".into(),"Enabled".into()),("0".into(),"Disabled".into())],may)));
        }
        for (field, ty) in record.kind.fields() {
            if matches!(*field, "SecretFile" | "ConnectSecurity") {
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
                options
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
            } else if *ty == Field::List {
                list(field, label(field), may)
            } else {
                text(field, label(field), "text", may)
            };
            let about=match *field{"Addresses"=>"One IP address or canonical CIDR prefix per line.","Policies"=>"Only these policies may be selected by this client.","CertificateFiles"=>"Import PEM or DER files from this Peios machine, one path per line. Leave blank to keep the current certificate.","PrivateKeyFile"=>"Import the matching PEM or DER private key; the key is stored in a protected file.",_=>""};
            rows.push_str(&settings::row(label(field), about, &control));
        }
        if record.kind == Kind::Client {
            rows.push_str(&settings::row("Shared Secret",if self.creating{"Leave blank to generate a secret. Reveal it after saving to configure the RADIUS client."}else{"Leave blank to keep the current secret. Replacement requires updating the corresponding RADIUS client."},&text("shared-secret","Shared Secret","password",may)));
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
            r#"<form fx-submit="save">{}{}</form>"#,
            settings::group("Configuration", &rows, ""),
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
                &settings::actions(&controls),
                "",
            ));
        }
        if let Some(secret) = &self.secret {
            page.push_str(&settings::group(
                "Shared Secret",
                &format!(
                    "<p>Select and copy this value:</p><code>{}</code>",
                    escape(secret)
                ),
                "",
            ));
        }
        if let Some(info) = &self.inspection {
            page.push_str(&settings::group(
                "Certificates",
                &format!("<pre>{}</pre>", escape(info)),
                "",
            ));
        }
        page
    }
    fn overview_page(&self) -> String {
        let mut rows = String::new();
        rows.push_str(&settings::fact(
            "Daemon",
            self.overview["daemon"].as_str().unwrap_or("Unknown"),
            false,
        ));
        rows.push_str(&settings::fact(
            "Service",
            self.overview["service"]["state"]
                .as_str()
                .unwrap_or("Unavailable or not permitted"),
            false,
        ));
        rows.push_str(&settings::fact(
            "Start at Boot",
            match self.overview["start_at_boot"].as_bool() {
                Some(true) => "Yes",
                Some(false) => "No",
                None => "Unavailable or not permitted",
            },
            false,
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
        controls.push_str(&settings::button(
            "Enable at Boot",
            "boot",
            &[("on", "1")],
            Button::Plain,
            !self.busy,
        ));
        controls.push_str(&settings::button(
            "Disable at Boot",
            "boot",
            &[("on", "0")],
            Button::Plain,
            !self.busy,
        ));
        rows.push_str(&settings::actions(&controls));
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
        let listen = self
            .stored
            .as_ref()
            .ok()
            .and_then(|s| s.settings.get("Listen"))
            .map(field_text)
            .unwrap_or_default();
        let settings_form = format!(
            r#"<form fx-submit="listeners">{}{}{}</form>"#,
            settings::row(
                "Listen Addresses",
                "Local IP addresses and UDP ports, one per line.",
                &list("listeners", "Listen Addresses", !self.busy)
            ),
            settings::submit("Save", Button::Primary, !self.busy),
            settings::note(&format!("Currently saved: {listen}"))
        );
        page.push_str(&settings::group("Listeners", &settings_form, ""));
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
                    now: String::new(),
                    glyph: *glyph,
                    tile: Tile::Slate,
                })
            })
            .collect();
        let title = SECTIONS
            .iter()
            .find(|(id, _, _)| *id == self.section)
            .unwrap();
        let mut page = settings::head(
            title.2,
            Tile::Slate,
            title.1,
            "RADIUS authentication and admission on this machine.",
        );
        if let Some(pending) = &self.pending {
            page.push_str(&settings::group(
                "Confirm Change",
                &format!(
                    "<p>{}</p>{}",
                    escape(&pending.description),
                    settings::actions(&format!(
                        "{}{}",
                        settings::button("Cancel", "cancel", &[], Button::Plain, true),
                        settings::button("Confirm", "confirm", &[], Button::Danger, !self.busy)
                    ))
                ),
                "",
            ));
        }
        if let Err(error) = &self.stored {
            page.push_str(&settings::banner(error));
        }
        if self.section == "overview" {
            page.push_str(&self.overview_page());
        } else if let Some(record) = &self.edit {
            page.push_str(&self.form(record));
        } else if let Some(kind) = Kind::parse(self.section) {
            page.push_str(&settings::actions(&settings::button(
                "Create…",
                "create",
                &[],
                Button::Primary,
                !self.busy,
            )));
            if let Ok(stored) = &self.stored {
                let mut rows = String::new();
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
                patch.insert("Name".into(), Value::Text(fields.get("Name").to_owned()));
                if record.kind != Kind::Identity {
                    patch.insert(
                        "Enabled".into(),
                        Value::Number(if fields.get("Enabled") == "1" { 1 } else { 0 }),
                    );
                }
                let mut import = false;
                for (field, ty) in record.kind.fields() {
                    if matches!(*field, "SecretFile" | "ConnectSecurity") {
                        continue;
                    }
                    let text = fields.get(field);
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
                    operations::submit(&record, &mut patch, creating, secret, import)
                        .map(Outcome::Saved)
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
    app.stylesheet(
        "/radius.css",
        ".st pre{white-space:pre-wrap;overflow-wrap:anywhere}.st code{overflow-wrap:anywhere}",
    );
    let surface = app.live(
        "RADIUS",
        Window {
            surface: Weak::new(),
            section: "overview",
            stored: read(),
            overview: overview(),
            edit: None,
            creating: false,
            writable: false,
            busy: false,
            pending: None,
            said: None,
            secret: None,
            inspection: None,
            sd_editor: None,
        },
    );
    let weak = Arc::downgrade(&surface);
    surface.update(|w, _| w.surface = weak.clone());
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(3));
        let Some(surface) = weak.upgrade() else {
            return;
        };
        let stored = read();
        let overview = overview();
        surface.update(|w, _| {
            if !w.busy {
                w.stored = stored;
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
    fn window() -> Window {
        Window {
            surface: Weak::new(),
            section: "overview",
            stored: Ok(Stored::default()),
            overview: serde_json::json!({"daemon":"invalid","service":{"state":"Active"},"start_at_boot":true,"runtime":{"issues":[{"object":"policy-guid","field":"References","message":"missing profile-guid"}]}}),
            edit: None,
            creating: false,
            writable: true,
            busy: false,
            pending: None,
            said: None,
            secret: None,
            inspection: None,
            sd_editor: None,
        }
    }
    fn policy() -> Record {
        let mut r = Record::new(Kind::Policy, "Household").unwrap();
        r.values
            .insert("ConnectSecurity".into(), Value::Text("O:BAG:BAD:P".into()));
        r
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
                let document=format!("<!doctype html><html><head><meta name=viewport content=\"width=device-width,initial-scale=1\"><style>{}</style></head><body>{html}</body></html>",settings::STYLE);
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
}
