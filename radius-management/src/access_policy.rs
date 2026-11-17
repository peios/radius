//! Shared configuration projection for native admission and policy explanation.
use crate::model::{Kind, Record, Stored, Value};
use radius_policy::{Policy, Profile, RuleInput};
use std::collections::{BTreeMap, BTreeSet};

pub fn value_bytes(values: &crate::model::Values) -> usize {
    values
        .iter()
        .map(|(k, v)| {
            k.len()
                + match v {
                    Value::Text(s) => s.len(),
                    Value::List(v) => v.iter().map(String::len).sum(),
                    Value::Number(_) => 4,
                    Value::Bytes(v) | Value::Raw { bytes: v, .. } => v.len(),
                }
        })
        .sum()
}

pub fn profile(record: &Record) -> Result<Profile, String> {
    if record
        .values
        .keys()
        .any(|k| !matches!(k.as_str(), "Name" | "Enabled" | "VlanId"))
    {
        return Err("unknown access profile field".into());
    }
    let vlan = match record.values.get("VlanId") {
        None => None,
        Some(Value::Number(n)) => Some(u16::try_from(*n).map_err(|_| "VLAN exceeds range")?),
        _ => return Err("VlanId must be a DWORD or absent".into()),
    };
    let profile = Profile {
        id: record.id.clone(),
        name: record.name().into(),
        enabled: record.enabled(),
        vlan,
    };
    profile.validate()?;
    Ok(profile)
}
pub fn validate_scope(rule: &Record, stored: &Stored) -> Result<(), String> {
    let policy = rule
        .text("Policy")
        .ok_or("rule requires its owning policy")?;
    if !crate::model::valid_id(policy) || stored.get(Kind::Policy, policy).is_none() {
        return Err("unknown owning policy".into());
    }
    let path = rule.text("Parent").unwrap_or_default();
    if !path.is_empty() {
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() > radius_policy::MAX_DEPTH
            || parts
                .iter()
                .any(|s| !crate::model::valid_id(s) || *s == rule.id)
        {
            return Err("invalid parent rule path".into());
        }
        let parent = stored
            .get(Kind::Rule, parts[parts.len() - 1])
            .ok_or("parent rule not found")?;
        if parent.text("Policy") != Some(policy)
            || parent.text("Parent").unwrap_or_default() != parts[..parts.len() - 1].join("/")
        {
            return Err("parent belongs to a different policy or path".into());
        }
    }
    Ok(())
}
pub fn inputs(stored: &Stored, policy: &str) -> Result<Vec<RuleInput>, String> {
    let records: Vec<_> = stored
        .objects
        .iter()
        .filter(|r| r.kind == Kind::Rule && r.text("Policy") == Some(policy))
        .collect();
    if records.len() > radius_policy::MAX_RULES {
        return Err("too many rules".into());
    }
    let mut ids = BTreeSet::new();
    let mut bytes = 0;
    for r in &records {
        bytes += value_bytes(&r.values);
        if bytes > radius_policy::MAX_POLICY_BYTES {
            return Err("rule values exceed byte limit".into());
        }
        if !ids.insert(&r.id) {
            return Err("duplicate rule GUID".into());
        }
        validate_scope(r, stored)?;
    }
    fn tree(records: &[&Record], parent: &str, depth: usize) -> Result<Vec<RuleInput>, String> {
        if depth > radius_policy::MAX_DEPTH {
            return Err("rule depth exceeds limit".into());
        }
        let mut out = Vec::new();
        for record in records
            .iter()
            .filter(|r| r.text("Parent").unwrap_or_default() == parent)
        {
            let mut values = BTreeMap::new();
            for (k, v) in &record.values {
                if matches!(k.as_str(), "Policy" | "Parent") {
                    continue;
                }
                let v = match v {
                    Value::Text(v) => serde_json::json!(v),
                    Value::List(v) => serde_json::json!(v),
                    Value::Number(v) => serde_json::json!(v),
                    _ => {
                        return Err(format!(
                            "{} {k}: unsupported Registry value type",
                            record.id
                        ))
                    }
                };
                values.insert(k.clone(), v);
            }
            let path = if parent.is_empty() {
                record.id.clone()
            } else {
                format!("{parent}/{}", record.id)
            };
            let children = if depth == radius_policy::MAX_DEPTH {
                if records.iter().any(|r| r.text("Parent") == Some(&path)) {
                    return Err("rule depth exceeds limit".into());
                }
                Vec::new()
            } else {
                tree(records, &path, depth + 1)?
            };
            out.push(RuleInput {
                name: record.id.clone(),
                values,
                children,
            });
        }
        Ok(out)
    }
    tree(&records, "", 0)
}
pub fn compile(stored: &Stored, policy: &str) -> Result<Policy, String> {
    let profiles = stored
        .objects
        .iter()
        .filter(|r| r.kind == Kind::AccessProfile)
        .map(profile)
        .collect::<Result<Vec<_>, _>>()?;
    Policy::compile(&inputs(stored, policy)?, &profiles)
}
