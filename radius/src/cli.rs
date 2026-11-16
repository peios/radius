#[cfg(feature = "native")]
use radius_management::model::{Kind, Values};
use std::io;
pub const HELP: &str = "\
usage: radius [--json] [command]

  status                         service, saved and effective configuration
  config show | check | init      inspect, validate, or initialize configuration
  config set NAME=VALUE ...       change global settings
  client|policy|profile|identity list
  KIND show NAME-OR-GUID
  KIND create NAME [--set FIELD=VALUE] ...
  KIND set NAME-OR-GUID [--set FIELD=VALUE] ...
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
                ("list", []) => Ok(json!(stored
                    .objects
                    .iter()
                    .filter(|r| r.kind == kind)
                    .collect::<Vec<_>>())),
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
