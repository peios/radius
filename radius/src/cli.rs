#[cfg(feature = "native")]
use radius_management::model::{Kind, Values};
use std::io;
fn terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}
#[cfg(test)]
mod diagnostic_terminal_tests {
    #[test]
    fn a_supplied_name_cannot_inject_terminal_controls() {
        let rendered = super::terminal_text("Zoë\u{1b}[31m\nforged row");
        assert!(rendered.starts_with("Zoë"));
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\n'));
    }
}
pub const HELP: &str = "\
usage: radius [--json] [command]

  status                         service, saved and effective configuration
  diagnostics list|follow [--since SECONDS] [--network GUID] [--client GUID]
    filters: --username SUPPLIED-NAME --station aa:bb:cc:dd:ee:ff
  diagnostics show ATTEMPT-ID [--since SECONDS]
  diagnostics drops|status [--since SECONDS]
  config show | check | init      inspect, validate, or initialize configuration
  config set NAME=VALUE ...       change global settings
  accounting init                provision the private accounting ledger directory
  accounting telemetry-init      provision the service metric namespace, preserving policy
  accounting status | sessions [POLICY-GUID]
    sessions options: --after GUID --revision N --limit N --principal SID --active
  accounting session|history|disconnect|reauthenticate|update SESSION-GUID
  accounting reconciliation SESSION-GUID
  accounting disconnect|reauthenticate|update SESSION-GUID --request-id ID
  accounting related|commands SESSION-GUID
  accounting usage SID [POLICY-GUID]
  accounting annotate SESSION-GUID NOTE
  accounting correct-end SESSION-GUID UNIX-MILLISECONDS NOTE --confirm
  accounting rebuild --confirm   rebuild retained evidence without sending actions
  client|policy|profile|identity|quota|accounting-profile|dynamic-profile|access-profile|rule list
  KIND show NAME-OR-GUID
  KIND create NAME [--set FIELD=VALUE] ...
  KIND set NAME-OR-GUID [--set FIELD=VALUE] ...
  KIND unset NAME-OR-GUID FIELD ...  remove optional settings or rule conditions
  policy explain NAME-OR-GUID --facts PATH  explain saved policy with hypothetical typed JSON facts
  KIND delete NAME-OR-GUID
  KIND enable|disable NAME-OR-GUID  (clients, policies and profiles)
  KIND permissions NAME-OR-GUID connect|management [SDDL]
  client secret NAME-OR-GUID show|generate|set [--stdin|--file PATH]
  identity inspect NAME-OR-GUID    certificate names, issuer, expiry, fingerprint
  identity import NAME-OR-GUID --set CertificateFiles=PATH,... --set PrivateKeyFile=PATH
  service start|stop|restart
  service boot on|off
  --window                       open the GXWI interface

Lists use comma-separated values. References use GUIDs. Secrets are hidden in
ordinary output. Secret set without an input option prompts without echo.
Saving configuration does not imply that radiusd activated it. Service stop or
restart interrupts authentication; established access may last until reauthentication.
";
fn usage(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s.into())
}
#[cfg(feature = "native")]
pub(crate) fn radius_accounting_filter(
    policy: Option<String>,
) -> radius_management::accounting::Filter {
    radius_management::accounting::Filter {
        policy,
        limit: 100,
        ..Default::default()
    }
}
#[derive(Debug)]
pub struct CheckIssues(pub Vec<radius_management::model::Issue>);
impl std::fmt::Display for CheckIssues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, issue) in self.0.iter().enumerate() {
            if index > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{} {}: {}", issue.object, issue.field, issue.message)?;
        }
        Ok(())
    }
}
impl std::error::Error for CheckIssues {}
#[cfg(feature = "native")]
fn fields(kind: Kind, args: &[String]) -> io::Result<Values> {
    use radius_management::native::operations::parse_field;
    let mut values = Values::new();
    let mut i = 0;
    while i < args.len() {
        let arg = if args[i] == "--set" {
            i += 1;
            args.get(i)
                .ok_or_else(|| usage("--set requires FIELD=VALUE"))?
        } else {
            &args[i]
        };
        let (name, value) = arg
            .split_once('=')
            .ok_or_else(|| usage("expected FIELD=VALUE"))?;
        if values
            .insert(name.into(), parse_field(kind, name, value)?)
            .is_some()
        {
            return Err(usage(format!("duplicate field {name}")));
        }
        i += 1;
    }
    Ok(values)
}
#[cfg(feature = "native")]
pub fn run(args: &[String]) -> io::Result<serde_json::Value> {
    use radius_management::{
        model::Value,
        native::{configuration, control, credentials, operations, registry, service},
    };
    use serde_json::json;
    let words: Vec<_> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["diagnostics", command, rest @ ..] => {
            use radius_management::{diagnostics::OPERATION, native::diagnostics};
            let (filter, kind) = if *command == "show" {
                let (id, options) = rest
                    .split_first()
                    .ok_or_else(|| usage("show requires an attempt identifier"))?;
                let mut filter = diagnostic_filter(options)?;
                filter.attempt = Some((*id).into());
                (filter, "show")
            } else {
                (diagnostic_filter(rest)?, *command)
            };
            if !matches!(kind, "list" | "show" | "drops" | "status") {
                return Err(usage(
                    "expected diagnostics list, show, follow, drops or status",
                ));
            }
            let view = diagnostics::read(&filter)?;
            let result = match kind {
                "drops" => {
                    json!({"status":view.status,"drops":view.drops,"truncated":view.truncated})
                }
                "status" => {
                    json!({"eventd_query":"available","collection":view.collection,"status":view.status,"truncated":view.truncated})
                }
                "show" => {
                    let mut linked = Vec::new();
                    let mut errors = Vec::new();
                    for a in &view.attempts {
                        if let Some(id) =
                            a.summary.get(OPERATION).and_then(serde_json::Value::as_str)
                        {
                            match diagnostics::authority(id) {
                                Ok(rows) => linked.extend(rows),
                                Err(error) => errors.push(error.to_string()),
                            }
                        }
                    }
                    json!({"diagnostics":view,"authority_events":linked,"authority_errors":errors})
                }
                _ => serde_json::to_value(view).map_err(io::Error::other)?,
            };
            Ok(result)
        }
        ["policy", "explain", selector, "--facts", path] => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1_048_577)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 1_048_576 {
                return Err(usage("hypothetical facts exceed 1 MiB"));
            }
            let facts =
                serde_json::from_slice(&bytes).map_err(|_| usage("invalid typed facts JSON"))?;
            operations::explain(selector, &facts)
        }
        ["accounting", "init"] => {
            radius_management::native::accounting::provision_directory()?;
            Ok(json!({"provisioned":true}))
        }
        ["accounting", "telemetry-init"] => {
            radius_management::native::accounting::provision_metrics()?;
            Ok(json!({"provisioned":true}))
        }
        ["accounting", rest @ ..] => {
            use radius_management::accounting::Request as R;
            let request = match *rest {
                ["status"] => R::Status,
                ["sessions", ref options @ ..] => {
                    let mut filter = radius_accounting_filter(None);
                    let mut i = 0;
                    while i < options.len() {
                        match options[i] {
                            "--active" => filter.active_only = true,
                            flag @ ("--after" | "--revision" | "--limit" | "--principal") => {
                                i += 1;
                                let value = options
                                    .get(i)
                                    .ok_or_else(|| usage("missing sessions option value"))?;
                                match flag {
                                    "--after" => filter.after = Some((*value).into()),
                                    "--principal" => filter.principal = Some((*value).into()),
                                    "--revision" => {
                                        filter.revision = Some(
                                            value.parse().map_err(|_| usage("invalid revision"))?,
                                        )
                                    }
                                    _ => {
                                        filter.limit =
                                            value.parse().map_err(|_| usage("invalid limit"))?
                                    }
                                }
                            }
                            policy if !policy.starts_with('-') && filter.policy.is_none() => {
                                filter.policy = Some(policy.into())
                            }
                            _ => return Err(usage("invalid sessions option")),
                        }
                        i += 1;
                    }
                    if filter.after.is_some() && filter.revision.is_none() {
                        return Err(usage("--after requires --revision from the previous page"));
                    }
                    R::Sessions { filter }
                }
                ["session", id] => R::Session { id: id.into() },
                ["history", id] => R::History {
                    id: id.into(),
                    limit: 100,
                },
                ["usage", principal] => R::Usage {
                    principal: principal.into(),
                    policy: "*".into(),
                },
                ["related", id] => R::Related { id: id.into() },
                ["commands", id] => R::Commands { id: id.into() },
                ["correct-end", id, end, note, "--confirm"] => R::CorrectEnd {
                    id: id.into(),
                    end_ms: end
                        .parse()
                        .map_err(|_| usage("end time requires Unix milliseconds"))?,
                    note: note.into(),
                },
                ["usage", principal, policy] => R::Usage {
                    principal: principal.into(),
                    policy: policy.into(),
                },
                ["disconnect", id] => R::Control {
                    request_id: String::new(),
                    id: id.into(),
                    action: radius_accounting::dynamic::Action::Disconnect,
                },
                ["reauthenticate", id] => R::Control {
                    request_id: String::new(),
                    id: id.into(),
                    action: radius_accounting::dynamic::Action::Reauthenticate,
                },
                ["update", id] => R::Control {
                    request_id: String::new(),
                    id: id.into(),
                    action: radius_accounting::dynamic::Action::UpdateAuthorization,
                },
                ["reconciliation", id] => R::Reconciliation { id: id.into() },
                [
                    action @ ("disconnect" | "reauthenticate" | "update"),
                    id,
                    "--request-id",
                    request_id,
                ] => R::Control {
                    request_id: request_id.into(),
                    id: id.into(),
                    action: match action {
                        "disconnect" => radius_accounting::dynamic::Action::Disconnect,
                        "reauthenticate" => radius_accounting::dynamic::Action::Reauthenticate,
                        _ => radius_accounting::dynamic::Action::UpdateAuthorization,
                    },
                },
                ["annotate", id, note] => R::Annotate {
                    id: id.into(),
                    note: note.into(),
                },
                ["rebuild", "--confirm"] => R::Rebuild,
                _ => return Err(usage("invalid accounting command; run radius --help")),
            };
            radius_management::native::accounting::query(request)
        }
        [] | ["status"] => {
            let saved = registry::read();
            let live = control::query();
            let service = service::status();
            // A stopped daemon and an unavailable status endpoint are distinct.
            let endpoint = match &live {
                Ok(s) => s.state.clone(),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => "permission-denied".into(),
                Err(_) => {
                    if service
                        .as_ref()
                        .ok()
                        .and_then(|s| s["state"].as_str())
                        .is_some_and(|s| matches!(s, "Inactive" | "Failed"))
                    {
                        "stopped".into()
                    } else {
                        "unreachable".into()
                    }
                }
            };
            Ok(
                json!({"daemon":endpoint,"service":service.ok(),"start_at_boot":service::starts_at_boot().ok(),
                "saved_fingerprint":saved.as_ref().ok().map(|s|s.fingerprint()),"saved_issues":saved.as_ref().ok().map(|s|s.validate()),
                "configuration_error_code":saved.as_ref().err().map(|e|match e.kind(){io::ErrorKind::NotFound=>"not-found",io::ErrorKind::PermissionDenied=>"permission-denied",_=>"failed"}),
                "configuration_error":saved.err().map(|e|e.to_string()),"runtime":live.as_ref().ok(),"runtime_error":live.err().map(|e|e.to_string())}),
            )
        }
        ["config", "show"] => Ok(json!(registry::read()?)),
        ["config", "check"] => {
            let issues = operations::configuration_check(&registry::read()?);
            if !issues.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    CheckIssues(issues),
                ));
            }
            Ok(json!({"valid":true,"activation":"not checked"}))
        }
        ["config", "init"] => {
            operations::initialize()?;
            Ok(json!({"saved":true,"activation":"not checked"}))
        }
        ["config", "set", rest @ ..] if !rest.is_empty() => {
            let mut patch = Values::new();
            for item in rest {
                let (name, value) = item
                    .split_once('=')
                    .ok_or_else(|| usage("expected NAME=VALUE"))?;
                let v = operations::parse_setting(name, value)?;
                patch.insert(name.into(), v);
            }
            operations::save_settings(&patch)?;
            Ok(json!({"saved":true,"activation":"pending"}))
        }
        ["service", "boot", on] if matches!(*on, "on" | "off") => {
            service::start_at_boot(*on == "on")?;
            Ok(json!({"saved":true,"start_at_boot":*on=="on"}))
        }
        ["service", action] => {
            service::command(action)?;
            Ok(json!({"submitted":true,"action":action}))
        }
        ["client", "secret", selector, action, rest @ ..] => {
            use std::io::Write;
            let stored = registry::read()?;
            let record = stored.resolve(Kind::Client, selector).map_err(usage)?;
            match *action {
                "show" if rest.is_empty() => {
                    let path = record
                        .text("SecretFile")
                        .ok_or_else(|| usage("missing SecretFile"))?;
                    let secret = credentials::material(path, true, 1024)?;
                    io::stdout().lock().write_all(&secret)?;
                    Ok(json!(null))
                }
                "generate" if rest.is_empty() => {
                    credentials::replace_secret(record, &credentials::generated_secret()?)?;
                    Ok(
                        json!({"saved":true,"notice":"Update the shared secret on the corresponding RADIUS client."}),
                    )
                }
                "set" => {
                    let secret = read_secret(rest)?;
                    credentials::replace_secret(record, &secret)?;
                    Ok(
                        json!({"saved":true,"notice":"Update the shared secret on the corresponding RADIUS client."}),
                    )
                }
                _ => Err(usage("expected secret show, generate, or set")),
            }
        }
        [kind, action, rest @ ..] => {
            let kind =
                Kind::parse(kind).ok_or_else(|| usage("unknown object kind; run radius --help"))?;
            let stored = registry::read()?;
            match (*action, rest) {
                ("list", []) => Ok(json!(
                    stored
                        .objects
                        .iter()
                        .filter(|r| r.kind == kind)
                        .collect::<Vec<_>>()
                )),
                ("create", [name, args @ ..]) => {
                    let record = operations::create(
                        kind,
                        name,
                        fields(
                            kind,
                            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        )?,
                    )?;
                    Ok(json!({"saved":true,"object":record,"activation":"pending"}))
                }
                (action, [selector, args @ ..]) => {
                    let record = stored.resolve(kind, selector).map_err(usage)?;
                    match (action, args) {
                        ("show", []) => Ok(json!(record)),
                        ("inspect", []) if kind == Kind::Identity => {
                            Ok(json!(credentials::inspect(record)?))
                        }
                        ("delete", []) => {
                            registry::remove(record)?;
                            Ok(json!({"saved":true,"deleted":record.id,"activation":"pending"}))
                        }
                        ("enable" | "disable", []) if kind != Kind::Identity => {
                            let enabled = action == "enable";
                            operations::save(
                                record,
                                &Values::from([(
                                    "Enabled".into(),
                                    Value::Number(u32::from(enabled)),
                                )]),
                                false,
                            )?;
                            Ok(
                                json!({"saved":true,"enabled":enabled,"affected":stored.dependents(kind,&record.id),"activation":"pending"}),
                            )
                        }
                        ("set", args) => {
                            let record = operations::save(
                                record,
                                &fields(
                                    kind,
                                    &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                                )?,
                                false,
                            )?;
                            Ok(json!({"saved":true,"object":record,"activation":"pending"}))
                        }
                        ("unset", args) if !args.is_empty() => {
                            let remove = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
                            let record =
                                operations::save_edit(record, &Values::new(), &remove, false)?;
                            Ok(json!({"saved":true,"object":record,"activation":"pending"}))
                        }
                        ("import", args) if kind == Kind::Identity => {
                            let v = fields(
                                kind,
                                &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                            )?;
                            let chain = match v.get("CertificateFiles") {
                                Some(Value::List(v)) => v.clone(),
                                _ => return Err(usage("CertificateFiles is required")),
                            };
                            let key = match v.get("PrivateKeyFile") {
                                Some(Value::Text(v)) => v.clone(),
                                _ => return Err(usage("PrivateKeyFile is required")),
                            };
                            let mut staged = credentials::Staged::default();
                            let patch = credentials::identity_values(&mut staged, &chain, &key)?;
                            operations::save(record, &patch, false)?;
                            staged.committed();
                            Ok(
                                json!({"saved":true,"affected":stored.dependents(kind,&record.id),"activation":"pending"}),
                            )
                        }
                        ("permissions", [which]) => {
                            let sd = match *which {
                                "management" => registry::management_sd(record)?,
                                "connect" if kind == Kind::Policy => configuration::descriptor(
                                    record
                                        .values
                                        .get("ConnectSecurity")
                                        .ok_or_else(|| usage("missing ConnectSecurity"))?,
                                )?,
                                _ => return Err(usage("expected connect or management")),
                            };
                            Ok(
                                json!({"sddl":peios::security::sddl::format(sd.as_bytes()).map_err(io::Error::from)?}),
                            )
                        }
                        ("permissions", [which, sddl]) => {
                            let sd = peios::security::sddl::parse(sddl).map_err(io::Error::from)?;
                            match *which {
                                "management" => registry::set_management_sd(
                                    record,
                                    &sd,
                                    peios::registry::SecInfo::OWNER
                                        | peios::registry::SecInfo::GROUP
                                        | peios::registry::SecInfo::DACL,
                                )?,
                                "connect" if kind == Kind::Policy => {
                                    operations::save(
                                        record,
                                        &Values::from([(
                                            "ConnectSecurity".into(),
                                            Value::Bytes(sd.as_bytes().to_vec()),
                                        )]),
                                        false,
                                    )?;
                                }
                                _ => return Err(usage("expected connect or management")),
                            }
                            Ok(json!({"saved":true}))
                        }
                        _ => Err(usage("unknown object operation; run radius --help")),
                    }
                }
                _ => Err(usage("missing object selector or operation")),
            }
        }
        _ => Err(usage("unknown command; run radius --help")),
    }
}

#[cfg(feature = "native")]
pub(crate) fn diagnostic_filter(
    args: &[&str],
) -> io::Result<radius_management::diagnostics::Filter> {
    use radius_management::diagnostics::Filter;
    let mut filter = Filter::default();
    let mut words = args.iter();
    while let Some(flag) = words.next() {
        let value = words
            .next()
            .ok_or_else(|| usage("diagnostic option needs a value"))?;
        match *flag {
            "--since" => {
                filter.seconds = Some(
                    value
                        .parse()
                        .map_err(|_| usage("--since requires seconds"))?,
                )
            }
            "--network" => filter.network = Some((*value).into()),
            "--client" => filter.client = Some((*value).into()),
            "--username" => filter.username = Some((*value).into()),
            "--station" => filter.station = Some((*value).into()),
            _ => return Err(usage("unknown diagnostics option")),
        }
    }
    Ok(filter)
}

#[cfg(feature = "native")]
pub fn follow_diagnostics(args: &[String], json: bool) -> io::Result<()> {
    use radius_management::native::diagnostics::Monitor;
    use std::{collections::BTreeSet, io::Write, time::Duration};
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    let monitor = Monitor::start(diagnostic_filter(&args)?)?;
    let mut seen = BTreeSet::new();
    let mut status = String::new();
    loop {
        let view = monitor.snapshot();
        let next = format!("{}:{}:{}", view.status, view.possible_gap, view.truncated);
        if next != status {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"kind":"status","message":view.status,"following":view.following,"possible_gap":view.possible_gap,"truncated":view.truncated})
                );
            } else {
                println!(
                    "{}{}{}",
                    terminal_text(&view.status),
                    if view.possible_gap {
                        "; possible gap"
                    } else {
                        ""
                    },
                    if view.truncated {
                        "; results limited"
                    } else {
                        ""
                    }
                );
            }
            status = next;
        }
        let mut current = BTreeSet::new();
        for attempt in view.attempts.iter().rev() {
            for record in &attempt.stages {
                let key = radius_management::diagnostics::record_digest(record);
                current.insert(key);
                if seen.contains(&key) {
                    continue;
                }
                if json {
                    println!("{}", serde_json::json!({"kind":"event","record":record}));
                } else {
                    let text = |key| {
                        record
                            .get(key)
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("unavailable")
                    };
                    println!(
                        "{}  {}  {}",
                        attempt.id,
                        terminal_text(text("object.radiusd.progress.stage")),
                        terminal_text(text("object.radiusd.progress.result"))
                    );
                }
            }
        }
        seen = current;
        io::stdout().flush()?;
        std::thread::sleep(Duration::from_millis(500));
    }
}
#[cfg(not(feature = "native"))]
pub fn run(_: &[String]) -> io::Result<serde_json::Value> {
    Err(usage("build with the native feature to administer Peios"))
}

#[cfg(feature = "native")]
fn read_secret(args: &[&str]) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::{Read, Write};
    if let ["--file", path] = args {
        return radius_management::native::credentials::read_input(path, 1024);
    }
    if !args.is_empty() && args != ["--stdin"] {
        return Err(usage("expected --stdin or --file PATH"));
    }
    struct Restore(Option<libc::termios>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(old) = self.0 {
                unsafe {
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &old);
                }
            }
        }
    }
    let mut restore = Restore(None);
    if args.is_empty() {
        let mut old = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr initializes old on success; the stdin descriptor is live.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, old.as_mut_ptr()) } != 0 {
            return Err(usage("a terminal is required; use --stdin for automation"));
        }
        let old = unsafe { old.assume_init() };
        let mut hidden = old;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error());
        }
        restore.0 = Some(old);
        eprint!("Shared secret: ");
        io::stderr().flush()?;
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut input = io::stdin().lock();
    for _ in 0..1025 {
        let mut b = [0];
        if input.read(&mut b)? == 0 || b[0] == b'\n' {
            break;
        }
        bytes.push(b[0]);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if restore.0.is_some() {
        eprintln!();
    }
    Ok(bytes)
}
pub fn print_human(value: &serde_json::Value) {
    if value.is_null() {
        return;
    }
    if let Some(attempts) = value.get("attempts").and_then(serde_json::Value::as_array) {
        println!(
            "{}",
            terminal_text(value["status"].as_str().unwrap_or("Diagnostic results"))
        );
        if value["truncated"] == true {
            println!("Results limited by configured bounds.");
        }
        if value["possible_gap"] == true {
            println!("Collection may contain gaps.");
        }
        for attempt in attempts {
            let summary = &attempt["summary"];
            let outcome = if attempt["outcome_available"] != true {
                "outcome unavailable"
            } else if summary["outcome.success"] == true {
                "Accept submitted"
            } else {
                summary["outcome.reason"].as_str().unwrap_or("unsuccessful")
            };
            println!(
                "{}  {}  {}  {}",
                attempt["id"].as_str().unwrap_or("unavailable"),
                summary["object.radiusd.method"]
                    .as_str()
                    .unwrap_or("method unavailable"),
                terminal_text(outcome),
                summary["source.radiusd.username"]
                    .as_str()
                    .map(|s| format!("supplied username: {}", terminal_text(s)))
                    .unwrap_or_default()
            );
        }
        if attempts.is_empty() {
            println!("No matching readable attempts in the returned window.");
        }
        return;
    }
    if let Some(daemon) = value["daemon"].as_str() {
        println!("Daemon             {daemon}");
        println!(
            "Service            {}",
            value["service"]["state"]
                .as_str()
                .unwrap_or("unavailable or not permitted")
        );
        println!(
            "Start at boot      {}",
            match value["start_at_boot"].as_bool() {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unavailable or not permitted",
            }
        );
        let active = value["runtime"]["state"] == "active"
            && value["saved_fingerprint"].is_string()
            && value["saved_fingerprint"] == value["runtime"]["effective_fingerprint"];
        println!(
            "Saved configuration {}",
            if active {
                "active"
            } else {
                "not confirmed active"
            }
        );
        for key in ["configuration_error", "runtime_error"] {
            if let Some(message) = value[key].as_str() {
                println!("{message}");
            }
        }
        if let Some(issues) = value["runtime"]["issues"].as_array() {
            for issue in issues {
                println!(
                    "{} {}: {}",
                    issue["object"].as_str().unwrap_or_default(),
                    issue["field"].as_str().unwrap_or_default(),
                    issue["message"].as_str().unwrap_or_default()
                );
            }
        }
    } else if value["saved"] == true {
        if let Some(name) = value["object"]["values"]["Name"]["value"].as_str() {
            println!(
                "Saved {name} ({})",
                value["object"]["id"].as_str().unwrap_or_default()
            );
        } else {
            println!("Saved.");
        }
        if value["activation"] == "pending" {
            println!("Activation pending; use radius status to check.");
        }
        if let Some(notice) = value["notice"].as_str() {
            println!("{notice}");
        }
        if let Some(affected) = value["affected"].as_array() {
            for object in affected {
                println!(
                    "Used by: {} ({})",
                    object["values"]["Name"]["value"]
                        .as_str()
                        .unwrap_or_default(),
                    object["id"].as_str().unwrap_or_default()
                );
            }
        }
    } else if let Some(list) = value.as_array() {
        for record in list {
            if let (Some(id), Some(name)) = (
                record["id"].as_str(),
                record["values"]["Name"]["value"].as_str(),
            ) {
                println!("{id}  {name}");
            } else {
                println!("{}", serde_json::to_string_pretty(record).unwrap());
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(value).unwrap());
    }
}
