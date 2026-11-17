use crate::model::{Kind, Record, Stored, Value, Values, MAX_OBJECTS, MAX_VALUE_BYTES, ROOT};
use peios::registry::{CreateFlags, Data, Key, KeyAccess, OpenFlags, SecInfo, Transaction};
use std::io;

fn open(path: &str, transaction: &Transaction) -> io::Result<Key> {
    Key::open_transacted(
        None,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
        Some(transaction),
    )
    .map_err(Into::into)
}
fn values(key: &Key, transaction: &Transaction) -> io::Result<Values> {
    let mut out = Values::new();
    for value in key.values(Some(transaction)) {
        let v = value.map_err(io::Error::from)?;
        if out.len() >= 64 || v.data.len() > MAX_VALUE_BYTES {
            return Err(io::Error::other("Registry record exceeds limits"));
        }
        let name = String::from_utf8(v.name)
            .map_err(|_| io::Error::other("Registry value name is not UTF-8"))?;
        let data = match Data::decode(v.ty, &v.data) {
            Data::Sz(v) => Value::Text(v),
            Data::MultiSz(v) => Value::List(v),
            Data::Dword(v) => Value::Number(v),
            Data::Binary(v) => Value::Bytes(v),
            _ => Value::Raw {
                ty: v.ty.0,
                bytes: v.data,
            },
        };
        out.insert(name, data);
    }
    Ok(out)
}
/// One short read-only Registry snapshot; no credential-file I/O inside it.
pub fn read() -> io::Result<Stored> {
    let mut retries = 3;
    loop {
        match read_once() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && retries > 0 => {
                // A concurrent writer can prevent acquiring a snapshot. Drop
                // the entire attempted view before retrying; never combine
                // records from different snapshots or retry a mutation here.
                retries -= 1;
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            result => return result,
        }
    }
}
fn read_once() -> io::Result<Stored> {
    let transaction = Transaction::begin_read_only().map_err(io::Error::from)?;
    let mut stored = Stored {
        settings: values(
            &open(&format!("{ROOT}\\Settings"), &transaction)?,
            &transaction,
        )?,
        ..Default::default()
    };
    for kind in Kind::ALL {
        if kind == Kind::Rule {
            continue;
        }
        let path = format!("{ROOT}\\{}", kind.collection());
        let parent = match open(&path, &transaction) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in parent.subkeys(Some(&transaction)) {
            if stored.objects.iter().filter(|r| r.kind == kind).count() >= MAX_OBJECTS {
                return Err(io::Error::other("too many configuration objects"));
            }
            let entry = entry.map_err(io::Error::from)?;
            let id = String::from_utf8(entry.name)
                .map_err(|_| io::Error::other("Registry record name is not UTF-8"))?;
            stored.objects.push(Record {
                kind,
                id: id.clone(),
                values: values(&open(&format!("{path}\\{id}"), &transaction)?, &transaction)?,
            });
        }
    }
    let policies: Vec<_> = stored
        .objects
        .iter()
        .filter(|r| r.kind == Kind::Policy)
        .map(|r| r.id.clone())
        .collect();
    for policy in policies {
        let path = format!("{ROOT}\\AccessPolicies\\{policy}\\Rules");
        match open(&path, &transaction) {
            Ok(key) => read_rules(&key, &path, &policy, "", 0, &transaction, &mut stored)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    stored.objects.sort_by_key(|a| a.path());
    Ok(stored)
}
fn read_rules(
    key: &Key,
    path: &str,
    policy: &str,
    parent: &str,
    depth: usize,
    tx: &Transaction,
    stored: &mut Stored,
) -> io::Result<()> {
    for entry in key.subkeys(Some(tx)) {
        if depth > radius_policy::MAX_DEPTH {
            return Err(io::Error::other("rule depth exceeds limits"));
        }
        if stored
            .objects
            .iter()
            .filter(|r| r.kind == Kind::Rule)
            .count()
            >= radius_policy::MAX_RULES
        {
            return Err(io::Error::other("too many rules"));
        }
        let entry = entry.map_err(io::Error::from)?;
        let id =
            String::from_utf8(entry.name).map_err(|_| io::Error::other("rule key is not UTF-8"))?;
        if !crate::model::valid_id(&id) {
            return Err(io::Error::other("rule key must be a canonical GUID"));
        }
        if stored
            .objects
            .iter()
            .any(|r| r.kind == Kind::Rule && r.id == id)
        {
            return Err(io::Error::other("duplicate rule GUID"));
        }
        let child_path = format!("{path}\\{id}");
        let child = open(&child_path, tx)?;
        let mut data = values(&child, tx)?;
        let prior: usize = stored
            .objects
            .iter()
            .filter(|r| r.kind == Kind::Rule)
            .map(|r| crate::access_policy::value_bytes(&r.values))
            .sum();
        if prior + crate::access_policy::value_bytes(&data) > radius_policy::MAX_POLICY_BYTES {
            return Err(io::Error::other("rule values exceed byte limit"));
        }
        if data.contains_key("Policy") || data.contains_key("Parent") {
            return Err(io::Error::other(
                "Policy and Parent are derived rule metadata, not stored values",
            ));
        }
        data.insert("Policy".into(), Value::Text(policy.into()));
        data.insert("Parent".into(), Value::Text(parent.into()));
        stored.objects.push(Record {
            kind: Kind::Rule,
            id: id.clone(),
            values: data,
        });
        let nested = if parent.is_empty() {
            id
        } else {
            format!("{parent}/{id}")
        };
        read_rules(&child, &child_path, policy, &nested, depth + 1, tx, stored)?;
    }
    Ok(())
}
fn encoded(value: &Value) -> io::Result<Data> {
    Ok(match value {
        Value::Text(v) => Data::Sz(v.clone()),
        Value::List(v) => Data::MultiSz(v.clone()),
        Value::Number(v) => Data::Dword(*v),
        Value::Bytes(v) => Data::Binary(v.clone()),
        Value::Raw { .. } => {
            return Err(io::Error::other("unsupported Registry type is read-only"))
        }
    })
}
/// Set only supplied fields, preserving other values and the key's descriptor.
pub fn write(path: &str, values: &Values, creating: bool) -> io::Result<()> {
    write_edit(path, values, &[], creating)
}
pub fn write_edit(
    path: &str,
    values: &Values,
    remove: &[String],
    creating: bool,
) -> io::Result<()> {
    let tx = Transaction::begin().map_err(io::Error::from)?;
    let access = KeyAccess::SET_VALUE
        | KeyAccess::QUERY_VALUE
        | if creating {
            KeyAccess::CREATE_SUB_KEY
        } else {
            KeyAccess::empty()
        };
    let rule = path.contains("\\Rules\\");
    if creating && rule {
        let (policy, _) = path.split_once("\\Rules\\").unwrap();
        Key::create(
            None,
            &format!("{policy}\\Rules"),
            KeyAccess::CREATE_SUB_KEY,
            CreateFlags::empty(),
            None,
            Some(&tx),
        )
        .map_err(io::Error::from)?;
    }
    let key = if creating {
        let (key, created) = Key::create(None, path, access, CreateFlags::empty(), None, Some(&tx))
            .map_err(io::Error::from)?;
        if created != peios::registry::Disposition::CreatedNew {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "object already exists",
            ));
        }
        key
    } else {
        Key::open_transacted(None, path, access, OpenFlags::empty(), Some(&tx))
            .map_err(io::Error::from)?
    };
    for (name, value) in values {
        if rule && matches!(name.as_str(), "Policy" | "Parent") {
            continue;
        }
        let data = encoded(value)?;
        key.set_value(name.as_bytes(), data.ty(), &data.encode())
            .in_txn(&tx)
            .call()
            .map_err(io::Error::from)?;
    }
    for name in remove {
        key.delete_value(name.as_bytes(), None, Some(&tx))
            .map_err(io::Error::from)?;
    }
    tx.commit().map_err(Into::into)
}
pub fn remove(record: &Record) -> io::Result<()> {
    let current = read()?;
    let uses = current.dependents(record.kind, &record.id);
    if !uses.is_empty() {
        return Err(io::Error::other(format!(
            "still referenced by {}",
            uses.iter()
                .map(|r| format!("{} ({})", r.name(), r.id))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let tx = Transaction::begin().map_err(io::Error::from)?;
    let key = Key::open_transacted(
        None,
        &record.path(),
        KeyAccess::DELETE,
        OpenFlags::empty(),
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    if record.kind == Kind::Policy {
        // Removing the last rule leaves its structural container behind.
        // Delete only an empty container, in the same transaction as its
        // policy. Unexpected or concurrently created children must survive.
        match Key::open_transacted(
            None,
            &format!("{}\\Rules", record.path()),
            KeyAccess::DELETE,
            OpenFlags::empty(),
            Some(&tx),
        ) {
            Ok(rules) => rules.delete_key(None, Some(&tx)).map_err(io::Error::from)?,
            Err(error) => {
                let error = io::Error::from(error);
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error);
                }
            }
        }
    }
    key.delete_key(None, Some(&tx)).map_err(io::Error::from)?;
    tx.commit().map_err(Into::into)
}
pub fn management_sd(record: &Record) -> io::Result<peios::security::SecurityDescriptor> {
    Key::open(
        None,
        &record.path(),
        KeyAccess::READ_CONTROL,
        OpenFlags::empty(),
    )
    .map_err(io::Error::from)?
    .get_security(SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL)
    .map_err(Into::into)
}
pub fn set_management_sd(
    record: &Record,
    sd: &peios::security::SecurityDescriptor,
    parts: SecInfo,
) -> io::Result<()> {
    let mut access = KeyAccess::empty();
    if parts.intersects(SecInfo::OWNER | SecInfo::GROUP | SecInfo::LABEL) {
        access |= KeyAccess::WRITE_OWNER;
    }
    if parts.contains(SecInfo::DACL) {
        access |= KeyAccess::WRITE_DAC;
    }
    if parts.contains(SecInfo::SACL) {
        access |= KeyAccess::ACCESS_SYSTEM_SECURITY;
    }
    Key::open(None, &record.path(), access, OpenFlags::empty())
        .map_err(io::Error::from)?
        .set_security(parts, sd, None)
        .map_err(Into::into)
}
pub fn may_write(record: &Record) -> bool {
    Key::open(
        None,
        &record.path(),
        KeyAccess::SET_VALUE,
        OpenFlags::empty(),
    )
    .is_ok()
}
