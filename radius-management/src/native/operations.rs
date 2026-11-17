//! Shared edits used by both frontends. Registry checks the actual caller.
use super::{credentials, registry};
use crate::model::{Field, Kind, Record, Stored, Value, Values, ROOT, SCHEMA};
use peios::registry::{CreateFlags, Data, Key, KeyAccess, OpenFlags, Transaction};
use std::io;

pub fn initialize() -> io::Result<()> {
    let software = Key::open(
        None,
        "Machine\\Software",
        KeyAccess::CREATE_SUB_KEY,
        OpenFlags::empty(),
    )
    .map_err(io::Error::from)?;
    // Never overwrite an existing deployment or change its permissions.
    match Key::open(None, ROOT, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "RADIUS configuration already exists",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    credentials::provision_directory()?;
    let tx = Transaction::begin().map_err(io::Error::from)?;
    let sd = peios::security::sddl::parse(&format!(
        "O:BAG:BAD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GR;;;{})",
        crate::runtime::SERVICE_SID
    ))
    .map_err(io::Error::from)?;
    let (root, disposition) = Key::create(
        Some(&software),
        "Radius",
        KeyAccess::ALL_ACCESS,
        CreateFlags::empty(),
        None,
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    if disposition != peios::registry::Disposition::CreatedNew {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "RADIUS configuration already exists",
        ));
    }
    root.set_security(
        peios::registry::SecInfo::OWNER
            | peios::registry::SecInfo::GROUP
            | peios::registry::SecInfo::DACL,
        &sd,
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    let (settings, _) = Key::create(
        Some(&root),
        "Settings",
        KeyAccess::SET_VALUE,
        CreateFlags::empty(),
        None,
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    for (name, value) in [
        ("SchemaVersion", Data::Dword(SCHEMA)),
        ("Listen", Data::MultiSz(vec!["0.0.0.0:1812".into()])),
    ] {
        settings
            .set_value(name.as_bytes(), value.ty(), &value.encode())
            .in_txn(&tx)
            .call()
            .map_err(io::Error::from)?;
    }
    for kind in Kind::ALL {
        if kind == Kind::Rule {
            continue;
        }
        Key::create(
            Some(&root),
            kind.collection(),
            KeyAccess::CREATE_SUB_KEY,
            CreateFlags::empty(),
            None,
            Some(&tx),
        )
        .map_err(io::Error::from)?;
    }
    tx.commit().map_err(Into::into)
}
pub fn parse_field(kind: Kind, name: &str, value: &str) -> io::Result<Value> {
    match kind.field(name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("unknown field {name}"))
    })? {
        Field::Text | Field::Descriptor => Ok(Value::Text(value.into())),
        Field::List => Ok(Value::List(value.split(',').map(str::to_owned).collect())),
        Field::Number => value.parse().map(Value::Number).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}: expected an unsigned number"),
            )
        }),
    }
}

pub fn parse_setting(name: &str, text: &str) -> io::Result<Value> {
    if crate::accounting::KNOBS.iter().any(|(n, _, _)| *n == name) {
        return text
            .parse::<u64>()
            .map(|n| {
                if let Ok(n) = u32::try_from(n) {
                    Value::Number(n)
                } else {
                    Value::Text(n.to_string())
                }
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected exact unsigned decimal",
                )
            });
    }
    match name {
        "Listen" | "AccountingListen" => {
            Ok(Value::List(text.split(',').map(str::to_owned).collect()))
        }
        "StatusSecurity" | "AccountingSecurity" | "AccountingSettings" => {
            Ok(Value::Text(text.into()))
        }
        "AccountingEnabled" | "AccountingSelfService" => text
            .parse()
            .map(Value::Number)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "expected 0 or 1")),
        "IdleTimeoutSeconds"
        | "OverallTimeoutSeconds"
        | "ReplyCacheSeconds"
        | "MaxAttempts"
        | "MaxAttemptsPerClient"
        | "MaxCachedReplies"
        | "FragmentBytes"
        | "MaxVerifications" => text
            .parse()
            .map(Value::Number)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "expected a number")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown global setting",
        )),
    }
}

/// Validate settings through the daemon's own preparation path, independently
/// of unrelated broken records. This performs no credential-file reads.
pub fn save_settings(patch: &Values) -> io::Result<()> {
    for (name, value) in patch {
        // Check that this is a supported, editable setting.
        if !crate::accounting::KNOBS.iter().any(|(n, _, _)| *n == name) {
            parse_setting(
                name,
                if matches!(value, Value::Number(_)) {
                    "1"
                } else {
                    ""
                },
            )?;
        }
        if name == "StatusSecurity" || name == "AccountingSecurity" {
            super::configuration::descriptor(value)?;
        }
    }
    let mut candidate = registry::read()?;
    candidate.settings.extend(patch.clone());
    if patch.keys().any(|name| name.starts_with("Accounting")) {
        crate::accounting::prepare(&candidate).map_err(io::Error::other)?;
    }
    if patch.keys().any(|name| !name.starts_with("Accounting")) {
        candidate.objects.clear();
        super::configuration::prepare(&candidate)?;
    }
    registry::write(&format!("{ROOT}\\Settings"), patch, false)
}
/// Validate edited fields and their references, while keeping unrelated broken
/// objects available for repair. Edits do not claim successful daemon activation.
pub fn save(record: &Record, patch: &Values, creating: bool) -> io::Result<Record> {
    save_edit(record, patch, &[], creating)
}
pub fn save_edit(
    record: &Record,
    patch: &Values,
    remove: &[String],
    creating: bool,
) -> io::Result<Record> {
    for name in patch.keys() {
        if record.kind.field(name).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown field {name}"),
            ));
        }
    }
    let mut next = record.clone();
    next.values.extend(patch.clone());
    for name in remove {
        if !(record.kind.optional(name)
            || (record.kind == Kind::Rule
                && record.values.contains_key(name)
                && !matches!(
                    name.as_str(),
                    "Name" | "Enabled" | "Priority" | "Actions" | "Policy" | "Parent"
                )))
            || matches!(name.as_str(), "Policy" | "Parent")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cannot unset {name}"),
            ));
        }
        next.values.remove(name);
    }
    if record.kind == Kind::Rule
        && !creating
        && ["Policy", "Parent"]
            .iter()
            .any(|k| next.values.get(*k) != record.values.get(*k))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "moving a rule requires creating it at the new parent",
        ));
    }
    let mut stored = registry::read()?;
    stored
        .objects
        .retain(|r| r.kind != next.kind || r.id != next.id);
    stored.objects.push(next.clone());
    let issues: Vec<_> = stored
        .validate()
        .into_iter()
        .filter(|i| {
            i.object == next.id
                || (next.kind == Kind::Rule && Some(i.object.as_str()) == next.text("Policy"))
        })
        .collect();
    if !issues.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            issues
                .iter()
                .map(|i| format!("{}: {}", i.field, i.message))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    if let Some(value) = patch.get("ConnectSecurity") {
        super::configuration::descriptor(value)?;
    }
    if creating {
        registry::write(&next.path(), &next.values, true)?;
    } else {
        registry::write_edit(&next.path(), patch, remove, false)?;
    }
    Ok(next)
}

/// Evaluates saved policy using hypothetical caller-supplied facts. Reading
/// every referenced Registry key uses the real caller's access rights.
pub fn explain(selector: &str, facts: &radius_policy::Facts) -> io::Result<serde_json::Value> {
    let stored = registry::read()?;
    let policy = stored
        .resolve(Kind::Policy, selector)
        .map_err(io::Error::other)?;
    let compiled = crate::access_policy::compile(&stored, &policy.id).map_err(io::Error::other)?;
    let explanation = compiled.explain(facts).map_err(io::Error::other)?;
    Ok(
        serde_json::json!({"configuration":"saved","fingerprint":stored.fingerprint(),"policy":policy.id,
        "full_admission_checked":false,"explanation":explanation}),
    )
}
/// Create with generated shared-secret material unless an existing protected
/// file reference was explicitly supplied. The generated secret is not returned
/// in ordinary output; reveal is a separate authorized operation.
pub fn create(kind: Kind, name: &str, mut values: Values) -> io::Result<Record> {
    let record = Record::new(kind, name).map_err(io::Error::other)?;
    submit(&record, &mut values, true, None, kind == Kind::Identity)
}
/// Forms and CLI share the same staging and Registry publication boundary.
pub fn submit(
    record: &Record,
    values: &mut Values,
    creating: bool,
    secret: Option<&[u8]>,
    import_identity: bool,
) -> io::Result<Record> {
    let kind = record.kind;
    let mut staged = credentials::Staged::default();
    if kind == Kind::Identity && import_identity {
        let chain = match values.get("CertificateFiles") {
            Some(Value::List(v)) => v.clone(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CertificateFiles is required",
                ))
            }
        };
        let key = match values.get("PrivateKeyFile") {
            Some(Value::Text(v)) => v.clone(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PrivateKeyFile is required",
                ))
            }
        };
        values.extend(credentials::identity_values(&mut staged, &chain, &key)?);
    }
    if let Some(secret) = secret {
        if kind != Kind::Client || !(16..=1024).contains(&secret.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client secrets must contain 16 to 1024 bytes",
            ));
        }
        values.insert("SecretFile".into(), Value::Text(staged.write(secret)?));
    } else if creating && kind == Kind::Client && !values.contains_key("SecretFile") {
        let secret = credentials::generated_secret()?;
        let path = staged.write(&secret)?;
        values.insert("SecretFile".into(), Value::Text(path));
    }
    let result = save(record, values, creating)?;
    staged.committed();
    Ok(result)
}
pub fn configuration_check(stored: &Stored) -> Vec<crate::model::Issue> {
    let mut issues = stored.validate();
    if let Err(e) = crate::accounting::prepare(stored) {
        issues.push(crate::model::Issue {
            object: "Accounting".into(),
            field: String::new(),
            message: e,
        });
    }
    if issues.is_empty() {
        if let Err(e) = super::configuration::prepare(stored) {
            issues.push(crate::model::Issue {
                object: "Configuration".into(),
                field: String::new(),
                message: e.to_string(),
            });
        }
    }
    issues
}
