//! One-off explicit migration for the sole development deployment. Run with
//! --apply after stopping radiusd. Does not change credentials or descriptors.
use peios::registry::{CreateFlags, Data, Disposition, Key, KeyAccess, OpenFlags, Transaction};
use radius_management::{
    model::{Kind, Record, Value, ROOT},
    native::registry,
};
use std::io;
fn invalid(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s.into())
}
fn main() -> io::Result<()> {
    let apply = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [arg] if arg == "--apply" => true,
        _ => return Err(invalid("usage: migrate-policy-v3 [--apply]")),
    };
    let mut stored = registry::read()?;
    if stored.settings.get("SchemaVersion") != Some(&Value::Number(2)) {
        return Err(invalid("requires schema 2; no changes made"));
    }
    if stored
        .objects
        .iter()
        .any(|r| matches!(r.kind, Kind::AccessProfile | Kind::Rule))
    {
        return Err(invalid(
            "existing assignment objects require manual review; no changes made",
        ));
    }
    let mut profile =
        Record::new(Kind::AccessProfile, "Default (no VLAN override)").map_err(invalid)?;
    // Keep this generated identity explicit in the plan printed below.
    profile.values.remove("VlanId");
    let mut created = vec![profile.clone()];
    for policy in stored
        .objects
        .iter()
        .filter(|r| r.kind == Kind::Policy && r.text("ServiceKind") != Some("accounting-only"))
    {
        let mut rule = Record::new(Kind::Rule, "Default").map_err(invalid)?;
        rule.values
            .insert("Policy".into(), Value::Text(policy.id.clone()));
        rule.values.insert(
            "Actions".into(),
            Value::List(vec![format!("ASSIGN({})", profile.id)]),
        );
        created.push(rule);
    }
    stored.objects.extend(created.clone());
    stored
        .settings
        .insert("SchemaVersion".into(), Value::Number(3));
    let issues = stored.validate();
    if !issues.is_empty() {
        return Err(invalid(format!("candidate invalid: {issues:?}")));
    }
    println!(
        "{}",
        serde_json::json!({"apply":apply,"schema":3,"created":created,"vlan_override":false})
    );
    if !apply {
        return Ok(());
    }
    let tx = Transaction::begin().map_err(io::Error::from)?;
    let settings = Key::open_transacted(
        None,
        &format!("{ROOT}\\Settings"),
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        OpenFlags::empty(),
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    let version = settings
        .query_value(b"SchemaVersion", Some(&tx))
        .map_err(io::Error::from)?;
    if !matches!(Data::decode(version.ty, &version.data), Data::Dword(2)) {
        return Err(invalid("schema changed during migration"));
    }
    let (_, disposition) = Key::create(
        None,
        &format!("{ROOT}\\AccessProfiles"),
        KeyAccess::CREATE_SUB_KEY,
        CreateFlags::empty(),
        None,
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    if disposition != Disposition::CreatedNew {
        return Err(invalid(
            "AccessProfiles already exists; refusing to merge a concurrent edit",
        ));
    }
    for record in &created {
        if record.kind == Kind::Rule {
            let path = format!(
                "{ROOT}\\AccessPolicies\\{}\\Rules",
                record.text("Policy").unwrap()
            );
            let (_, disposition) = Key::create(
                None,
                &path,
                KeyAccess::CREATE_SUB_KEY,
                CreateFlags::empty(),
                None,
                Some(&tx),
            )
            .map_err(io::Error::from)?;
            if disposition != Disposition::CreatedNew {
                return Err(invalid(
                    "Rules already exists; refusing to merge a concurrent edit",
                ));
            }
        }
        let (key, disposition) = Key::create(
            None,
            &record.path(),
            KeyAccess::SET_VALUE,
            CreateFlags::empty(),
            None,
            Some(&tx),
        )
        .map_err(io::Error::from)?;
        if disposition != Disposition::CreatedNew {
            return Err(invalid("generated object already exists"));
        }
        for (name, value) in &record.values {
            if matches!(name.as_str(), "Policy" | "Parent") {
                continue;
            }
            let value = match value {
                Value::Text(v) => Data::Sz(v.clone()),
                Value::List(v) => Data::MultiSz(v.clone()),
                Value::Number(v) => Data::Dword(*v),
                _ => return Err(invalid("unexpected generated value")),
            };
            key.set_value(name.as_bytes(), value.ty(), &value.encode())
                .in_txn(&tx)
                .call()
                .map_err(io::Error::from)?;
        }
    }
    let version = Data::Dword(3);
    settings
        .set_value(b"SchemaVersion", version.ty(), &version.encode())
        .in_txn(&tx)
        .call()
        .map_err(io::Error::from)?;
    tx.commit().map_err(io::Error::from)?;
    println!("Schema 3 and explicit defaults committed atomically.");
    Ok(())
}
