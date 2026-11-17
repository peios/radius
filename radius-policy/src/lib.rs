//! RADIUS policy adapter for the shared PNP evaluator. No I/O, credentials,
//! token creation, accounting reservations or packet transmission.
use pnp_core::{
    machinery::{self, Domain, Node, Step},
    pkm_alloc::AllocError,
    CondOp, FactFamily, RegValue, Sid,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const MAX_RULES: usize = 1024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_CONDITIONS: usize = 64;
pub const MAX_ALTERNATIVES: usize = 256;
pub const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

/// Values retain their authority-supplied type. No cross-type comparisons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Scalar {
    Int64(i64),
    Uint64(u64),
    Boolean(bool),
    String(String),
    Sid(String),
    Octet(Vec<u8>),
    Address(IpAddr),
    Mac([u8; 6]),
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimCoverage {
    Complete,
    #[default]
    Filtered,
}

/// Identity knowledge, not just values: a withheld claim cannot prove absence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    #[serde(default, deserialize_with = "deserialize_values")]
    values: BTreeMap<String, Vec<Scalar>>,
    #[serde(default)]
    pub claim_coverage: ClaimCoverage,
    #[serde(default)]
    pub absent_claims: BTreeSet<String>,
    #[serde(default)]
    pub unknown_claims: BTreeSet<String>,
}
pub fn claim_name(name: &str) -> String {
    pnp_core::claim_name::canonical_chars(name).collect()
}
fn fact_name(key: &str) -> String {
    key.strip_prefix("Subject.Claim.").map_or_else(
        || key.into(),
        |name| format!("Subject.Claim.{}", claim_name(name)),
    )
}
fn deserialize_values<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<Scalar>>, D::Error> {
    let input = BTreeMap::<String, Vec<Scalar>>::deserialize(deserializer)?;
    let mut out = BTreeMap::new();
    for (key, value) in input {
        if out.insert(fact_name(&key), value).is_some() {
            return Err(serde::de::Error::custom("equivalent duplicate fact names"));
        }
    }
    Ok(out)
}
impl Facts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, key: String, values: Vec<Scalar>) -> Option<Vec<Scalar>> {
        self.values.insert(fact_name(&key), values)
    }
    pub fn get(&self, key: &str) -> Option<&Vec<Scalar>> {
        self.values.get(&fact_name(key))
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    fn presence(&self, key: &str) -> Option<bool> {
        if self.contains_key(key) {
            return Some(true);
        }
        if let Some(name) = key.strip_prefix("Subject.Claim.") {
            if self
                .unknown_claims
                .iter()
                .any(|n| pnp_core::claim_name::names_equal(n, name))
            {
                return None;
            }
            if self.claim_coverage == ClaimCoverage::Complete
                || self
                    .absent_claims
                    .iter()
                    .any(|n| pnp_core::claim_name::names_equal(n, name))
            {
                Some(false)
            } else {
                None
            }
        } else {
            Some(false)
        }
    }
}
impl<const N: usize> From<[(String, Vec<Scalar>); N]> for Facts {
    fn from(values: [(String, Vec<Scalar>); N]) -> Self {
        let mut facts = Self::new();
        for (key, value) in values {
            facts.insert(key, value);
        }
        facts
    }
}
impl std::ops::Index<&str> for Facts {
    type Output = Vec<Scalar>;
    fn index(&self, key: &str) -> &Self::Output {
        self.get(key).expect("fact exists")
    }
}
impl<'a> IntoIterator for &'a Facts {
    type Item = (&'a String, &'a Vec<Scalar>);
    type IntoIter = std::collections::btree_map::Iter<'a, String, Vec<Scalar>>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

/// Normalize common AP station formatting; this remains asserted context.
pub fn station_mac(bytes: &[u8]) -> Option<[u8; 6]> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.len() != 17 {
        return None;
    }
    let separator = s.as_bytes()[2];
    if !matches!(separator, b':' | b'-') {
        return None;
    }
    let parts = s.split(separator as char).collect::<Vec<_>>();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub vlan: Option<u16>,
}
impl Profile {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_guid(&self.id)
            || self.name.trim().is_empty()
            || self.name.len() > 256
            || self.name.chars().any(char::is_control)
        {
            return Err("invalid access profile identity".into());
        }
        if self.vlan.is_some_and(|v| !(1..=4094).contains(&v)) {
            return Err("VLAN must be 1 through 4094, or unset".into());
        }
        Ok(())
    }
}
pub fn valid_guid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && s.as_bytes()[14] == b'4'
        && matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

/// Registry-shaped rule input. Children are nested exception keys, as in PNP.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleInput {
    pub name: String,
    #[serde(default)]
    pub values: BTreeMap<String, Value>,
    #[serde(default)]
    pub children: Vec<RuleInput>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Assign(usize),
    Reject,
}
struct Rule {
    name: String,
    path: String,
    enabled: bool,
    priority: i64,
    conditions: Vec<Condition>,
    decision: Option<Decision>,
    children: Vec<Rule>,
}
impl Node for Rule {
    fn name(&self) -> &str {
        &self.name
    }
    fn priority(&self) -> i64 {
        self.priority
    }
    fn children(&self) -> &[Self] {
        &self.children
    }
    fn has_direct_verdict(&self) -> bool {
        self.decision.is_some()
    }
}

#[derive(Debug)]
enum Comparison {
    Pnp(CondOp),
    Unsigned {
        operator: String,
        patterns: Vec<(u64, u64)>,
    },
    Boolean(Vec<bool>),
    Octet(Vec<Vec<u8>>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Primitive(FactFamily),
    Uint64,
    Boolean,
    Octet,
}
struct Condition {
    key: String,
    fact: String,
    comparison: Comparison,
}

/// Known fact vocabulary. Claim keys carry an explicit native type suffix:
/// Subject.Claim.department.String.Equal; dots in the claim name are preserved.
fn fact(key: &str) -> Result<(String, Family), String> {
    let primitive = match key {
        "Subject.User" | "Subject.Group" => Some(FactFamily::Sid),
        "Subject.Name" | "Client.Id" | "Request.SSID" => Some(FactFamily::Str),
        "Client.Address" => Some(FactFamily::Addr),
        "Request.Station" => Some(FactFamily::Mac),
        _ => None,
    };
    if let Some(f) = primitive {
        return Ok((key.into(), Family::Primitive(f)));
    }
    if let Some(rest) = key.strip_prefix("Subject.Claim.") {
        let (name, ty) = rest
            .rsplit_once('.')
            .ok_or("claim requires its native type suffix")?;
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err("invalid claim name".into());
        }
        let family = match ty {
            "Int64" => Family::Primitive(FactFamily::Int),
            "Uint64" => Family::Uint64,
            "String" => Family::Primitive(FactFamily::Str),
            "Sid" => Family::Primitive(FactFamily::Sid),
            "Boolean" => Family::Boolean,
            "Octet" => Family::Octet,
            _ => return Err("unknown claim type".into()),
        };
        return Ok((format!("Subject.Claim.{name}"), family));
    }
    Err(format!("unknown fact {key}"))
}
pub fn condition_key(key: &str) -> Result<(), String> {
    let (name, op) = key
        .rsplit_once('.')
        .ok_or("condition requires an operator")?;
    let (_, family) = fact(name)?;
    if op == "Present"
        || op == "Equal"
        || (matches!(family, Family::Primitive(FactFamily::Int) | Family::Uint64)
            && matches!(op, "GreaterThan" | "LessThan"))
    {
        Ok(())
    } else {
        Err(format!("unsupported operator {op} for {name}"))
    }
}
fn elements(value: &Value) -> Result<Vec<&Value>, String> {
    let values = match value {
        Value::Array(v) => v.iter().collect(),
        v => vec![v],
    };
    if values.is_empty()
        || values.len() > MAX_ALTERNATIVES
        || values
            .iter()
            .any(|v| matches!(v, Value::Array(_) | Value::Object(_) | Value::Null))
    {
        return Err("expected a nonempty bounded scalar/list pattern".into());
    }
    Ok(values)
}
fn reg_value(value: &Value) -> Result<RegValue, String> {
    match value {
        Value::String(s) if s.len() <= 65536 && !s.contains('\0') => {
            Ok(RegValue::Str(s.clone().into()))
        }
        Value::Number(n) => n
            .as_i64()
            .map(RegValue::Int)
            .ok_or("expected signed 64-bit integer".into()),
        Value::Array(v) if !v.is_empty() && v.len() <= MAX_ALTERNATIVES => Ok(RegValue::List(
            v.iter()
                .map(reg_value)
                .collect::<Result<Vec<_>, _>>()?
                .into(),
        )),
        _ => Err("expected a PNP scalar or list".into()),
    }
}
fn unsigned(v: &Value) -> Result<u64, String> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .ok_or("expected unsigned 64-bit decimal".into())
}
fn octets(v: &Value) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or("expected hexadecimal octet string")?;
    if s.len() > 65536 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected even-length hexadecimal octet string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
impl Condition {
    fn compile(key: &str, value: &Value) -> Result<Self, String> {
        condition_key(key)?;
        let (name, op) = key.rsplit_once('.').unwrap();
        let (fact, family) = fact(name)?;
        let comparison = if op == "Present" {
            Comparison::Pnp(
                pnp_core::ingest::parse_comparison(FactFamily::Str, op, &reg_value(value)?)
                    .map_err(|e| format!("{e:?}"))?,
            )
        } else {
            match family {
                Family::Primitive(f) => Comparison::Pnp(
                    pnp_core::ingest::parse_comparison(f, op, &reg_value(value)?)
                        .map_err(|e| format!("{e:?}"))?,
                ),
                Family::Uint64 => {
                    let mut patterns = Vec::new();
                    for v in elements(value)? {
                        let pair = if op == "Equal" {
                            if let Some((a, b)) = v.as_str().and_then(|s| s.split_once('-')) {
                                let a = a.parse::<u64>().map_err(|e| e.to_string())?;
                                let b = b.parse::<u64>().map_err(|e| e.to_string())?;
                                if a > b {
                                    return Err("inverted unsigned range".into());
                                }
                                (a, b)
                            } else {
                                let n = unsigned(v)?;
                                (n, n)
                            }
                        } else {
                            let n = unsigned(v)?;
                            (n, n)
                        };
                        patterns.push(pair);
                    }
                    if op != "Equal" && patterns.len() != 1 {
                        return Err("numeric threshold requires one value".into());
                    }
                    Comparison::Unsigned {
                        operator: op.into(),
                        patterns,
                    }
                }
                Family::Boolean => Comparison::Boolean(
                    elements(value)?
                        .into_iter()
                        .map(|v| match v {
                            Value::Bool(b) => Ok(*b),
                            Value::String(s) if s == "true" => Ok(true),
                            Value::String(s) if s == "false" => Ok(false),
                            _ => Err("expected true or false".into()),
                        })
                        .collect::<Result<_, String>>()?,
                ),
                Family::Octet => Comparison::Octet(
                    elements(value)?
                        .into_iter()
                        .map(octets)
                        .collect::<Result<_, _>>()?,
                ),
            }
        };
        Ok(Self {
            key: key.into(),
            fact,
            comparison,
        })
    }
    fn matches(&self, facts: &Facts) -> bool {
        let values = facts.get(&self.fact);
        if let Comparison::Pnp(CondOp::Present(want)) = &self.comparison {
            return facts
                .presence(&self.fact)
                .is_some_and(|present| present == *want);
        }
        values.is_some_and(|v| v.iter().any(|v| self.matches_value(v)))
    }
    fn matches_value(&self, value: &Scalar) -> bool {
        // The primitive parser does not imply conversion of authority values.
        match (&self.comparison, value) {
            (Comparison::Pnp(CondOp::EqualInt(p)), Scalar::Int64(v)) => {
                p.iter().any(|p| p.matches(*v))
            }
            (Comparison::Pnp(CondOp::Gt(p)), Scalar::Int64(v)) => v > p,
            (Comparison::Pnp(CondOp::Lt(p)), Scalar::Int64(v)) => v < p,
            (Comparison::Pnp(CondOp::EqualStr(p)), Scalar::String(v)) => {
                p.iter().any(|p| p.as_str() == v)
            }
            (Comparison::Pnp(CondOp::EqualSid(p)), Scalar::Sid(v)) => {
                Sid::parse_str(v).is_some_and(|v| p.iter().any(|p| *p == v))
            }
            (Comparison::Pnp(CondOp::EqualAddr(p)), Scalar::Address(v)) => {
                p.iter().any(|p| p.matches(*v))
            }
            (Comparison::Pnp(CondOp::EqualMac(p)), Scalar::Mac(v)) => p.iter().any(|p| p == v),
            (Comparison::Unsigned { operator, patterns }, Scalar::Uint64(v)) => {
                match operator.as_str() {
                    "Equal" => patterns.iter().any(|(a, b)| v >= a && v <= b),
                    "GreaterThan" => *v > patterns[0].0,
                    "LessThan" => *v < patterns[0].0,
                    _ => false,
                }
            }
            (Comparison::Boolean(p), Scalar::Boolean(v)) => p.contains(v),
            (Comparison::Octet(p), Scalar::Octet(v)) => p.contains(v),
            _ => false,
        }
    }
}

pub struct Policy {
    roots: Vec<Rule>,
    profiles: Vec<Profile>,
}
impl Policy {
    pub fn compile(inputs: &[RuleInput], profiles: &[Profile]) -> Result<Self, String> {
        if profiles.len() > 256 {
            return Err("too many access profiles".into());
        }
        let mut ids = BTreeSet::new();
        for profile in profiles {
            profile.validate()?;
            if !ids.insert(&profile.id) {
                return Err("duplicate access profile".into());
            }
        }
        let mut count = 0;
        let mut bytes = 0;
        let roots = compile_nodes(inputs, profiles, 0, "", 0, &mut count, &mut bytes)?;
        Ok(Self {
            roots,
            profiles: profiles.to_vec(),
        })
    }
    pub fn explain(&self, facts: &Facts) -> Result<Explanation, String> {
        self.evaluate(facts, true)
    }
    pub fn assignment(&self, facts: &Facts) -> Result<Assignment, String> {
        let out = self.evaluate(facts, false)?;
        if let Some(assignment) = out.assignment {
            return Ok(assignment);
        }
        if out.outcome == "conflicting-profiles" {
            if let Some(first) = out
                .candidates
                .iter()
                .find(|c| Some(&c.rule) == out.winner.as_ref())
            {
                if let Some(other) = out
                    .candidates
                    .iter()
                    .find(|c| c.priority == first.priority && c.profile != first.profile)
                {
                    return Err(format!(
                        "conflicting-profiles: {} and {}",
                        first.rule, other.rule
                    ));
                }
            }
        }
        Err(format!(
            "{}: {}",
            out.outcome,
            out.winner.as_deref().unwrap_or("backstop")
        ))
    }
    fn evaluate(&self, facts: &Facts, trace: bool) -> Result<Explanation, String> {
        validate_facts(facts)?;
        let mut domain = Evaluator {
            facts,
            trace,
            rules: Vec::new(),
        };
        let selected = machinery::evaluate(&self.roots, &mut domain)
            .map_err(|_| "policy allocation failed")?;
        let mut outcome = if selected.winner.is_none() {
            "backstop"
        } else {
            "rejected"
        };
        let mut assignment = None;
        if selected.conflict {
            outcome = "conflicting-profiles";
        } else if let Some(w) = selected.winner {
            if let Decision::Assign(index) = selected.candidates[w].verdict {
                let p = &self.profiles[index];
                if p.enabled {
                    outcome = "assigned";
                    assignment = Some(Assignment {
                        profile: p.id.clone(),
                        vlan: p.vlan,
                    });
                } else {
                    outcome = "profile-disabled";
                }
            }
        }
        let winner = selected
            .winner
            .map(|i| selected.candidates[i].rule.as_str().to_owned());
        let candidates = selected
            .candidates
            .iter()
            .map(|c| Candidate {
                rule: c.rule.as_str().into(),
                priority: c.priority,
                profile: match c.verdict {
                    Decision::Assign(i) => Some(self.profiles[i].id.clone()),
                    Decision::Reject => None,
                },
            })
            .collect();
        Ok(Explanation {
            hypothetical: trace,
            outcome: outcome.into(),
            assignment,
            winner,
            candidates,
            rules: domain.rules,
        })
    }
}
fn compile_nodes(
    inputs: &[RuleInput],
    profiles: &[Profile],
    priority: i64,
    parent: &str,
    depth: usize,
    count: &mut usize,
    bytes: &mut usize,
) -> Result<Vec<Rule>, String> {
    if depth > MAX_DEPTH && !inputs.is_empty() {
        return Err("rule depth exceeds limit".into());
    }
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for input in inputs {
        *bytes += input.name.len();
        for (key, value) in &input.values {
            let scalar_bytes = |v: &Value| -> Result<usize, String> {
                match v {
                    Value::String(s) => Ok(s.len()),
                    Value::Number(_) | Value::Bool(_) => Ok(32),
                    _ => Err("expected scalar rule value".into()),
                }
            };
            *bytes += key.len()
                + match value {
                    Value::Array(v) if v.len() <= MAX_ALTERNATIVES => v
                        .iter()
                        .try_fold(0, |n, v| scalar_bytes(v).map(|m| n + m))?,
                    v => scalar_bytes(v)?,
                };
            if *bytes > MAX_POLICY_BYTES {
                return Err("policy values exceed byte limit".into());
            }
        }
        *count += 1;
        if *count > MAX_RULES {
            return Err("too many rules".into());
        }
        if input.name.is_empty()
            || input.name.len() > 64
            || input
                .name
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
            || !names.insert(&input.name)
        {
            return Err("invalid or duplicate rule name".into());
        }
        if input.values.len() > MAX_CONDITIONS + 4 {
            return Err("too many rule values".into());
        }
        let path = if parent.is_empty() {
            input.name.clone()
        } else {
            format!("{parent}/{}", input.name)
        };
        let enabled = match input.values.get("Enabled") {
            None => true,
            Some(v) if v.as_u64() == Some(1) => true,
            Some(v) if v.as_u64() == Some(0) => false,
            _ => return Err(format!("{path}: Enabled must be 0 or 1")),
        };
        let priority = match input.values.get("Priority") {
            None => priority,
            Some(v) => v
                .as_i64()
                .or_else(|| v.as_str().and_then(|v| v.parse().ok()))
                .ok_or_else(|| format!("{path}: invalid signed Priority"))?,
        };
        let mut decision = None;
        let mut assigned = None;
        if let Some(actions) = input.values.get("Actions") {
            for action in elements(actions)? {
                let action = action.as_str().ok_or("action must be text")?.trim();
                let next = if action.eq_ignore_ascii_case("NULL") {
                    continue;
                } else if action.eq_ignore_ascii_case("REJECT") {
                    Decision::Reject
                } else if action
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("ASSIGN("))
                    && action.ends_with(')')
                {
                    let id = action[7..action.len() - 1].trim();
                    let i = profiles
                        .iter()
                        .position(|p| p.id == id)
                        .ok_or_else(|| format!("{path}: unknown access profile {id}"))?;
                    Decision::Assign(i)
                } else {
                    return Err(format!("{path}: unsupported action"));
                };
                if let Decision::Assign(index) = next {
                    if assigned.is_some_and(|other| other != index) {
                        return Err(format!("{path}: multiple assignments in one rule"));
                    }
                    assigned = Some(index);
                }
                match (decision, next) {
                    (Some(Decision::Reject), _) | (_, Decision::Reject) => {
                        decision = Some(Decision::Reject)
                    }
                    _ => decision = Some(next),
                }
            }
        }
        let mut conditions = Vec::new();
        for (key, value) in &input.values {
            if matches!(key.as_str(), "Enabled" | "Priority" | "Actions" | "Name") {
                continue;
            }
            if key.len() > 512 {
                return Err(format!("{path}: condition name too long"));
            }
            conditions
                .push(Condition::compile(key, value).map_err(|e| format!("{path} {key}: {e}"))?);
        }
        if conditions.len() > MAX_CONDITIONS {
            return Err(format!("{path}: too many conditions"));
        }
        let children = compile_nodes(
            &input.children,
            profiles,
            priority,
            &path,
            depth + 1,
            count,
            bytes,
        )?;
        out.push(Rule {
            name: input.name.clone(),
            path,
            enabled,
            priority,
            conditions,
            decision,
            children,
        });
    }
    Ok(out)
}

/// Bounds hypothetical input and validates typed identity values before use.
pub fn validate_facts(facts: &Facts) -> Result<(), String> {
    if facts.len() > 1024 {
        return Err("too many supplied facts".into());
    }
    let mut bytes = 0usize;
    if facts.absent_claims.len() > 1024 || facts.unknown_claims.len() > 1024 {
        return Err("too many claim-knowledge entries".into());
    }
    let mut absent = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    for (input, out) in [
        (&facts.absent_claims, &mut absent),
        (&facts.unknown_claims, &mut unknown),
    ] {
        for name in input {
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err("invalid claim-knowledge name".into());
            }
            bytes += name.len();
            if !out.insert(claim_name(name)) {
                return Err("duplicate claim-knowledge name".into());
            }
        }
    }
    if absent.iter().any(|name| unknown.contains(name)) {
        return Err("claim cannot be both absent and unknown".into());
    }
    for (key, values) in facts {
        if let Some(name) = key.strip_prefix("Subject.Claim.") {
            if name.is_empty()
                || name.len() > 256
                || name.chars().any(char::is_control)
                || absent.contains(&claim_name(name))
                || unknown.contains(&claim_name(name))
            {
                return Err("invalid or contradictory claim facts".into());
            }
        } else {
            fact(key)?;
        }
        bytes += key.len();
        if key.len() > 512 || values.len() > 1024 {
            return Err("supplied fact exceeds bounds".into());
        }
        for v in values {
            bytes += match v {
                Scalar::String(s) | Scalar::Sid(s) => s.len(),
                Scalar::Octet(v) => v.len(),
                _ => 32,
            };
            if bytes > MAX_POLICY_BYTES {
                return Err("supplied facts exceed byte limit".into());
            }
            match v {
                Scalar::String(s) if s.len() > 65536 => {
                    return Err("supplied string exceeds bounds".into())
                }
                Scalar::Octet(s) if s.len() > 65536 => {
                    return Err("supplied octet array exceeds bounds".into())
                }
                Scalar::Sid(s) if Sid::parse_str(s).is_none() => {
                    return Err("invalid supplied SID".into())
                }
                _ => {}
            }
        }
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub profile: String,
    pub vlan: Option<u16>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConditionTrace {
    pub condition: String,
    pub matched: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleTrace {
    pub rule: String,
    pub matched: bool,
    pub conditions: Vec<ConditionTrace>,
    pub steps: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub rule: String,
    pub priority: i64,
    pub profile: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Explanation {
    pub hypothetical: bool,
    pub outcome: String,
    pub assignment: Option<Assignment>,
    pub winner: Option<String>,
    pub candidates: Vec<Candidate>,
    pub rules: Vec<RuleTrace>,
}
struct Evaluator<'a> {
    facts: &'a Facts,
    trace: bool,
    rules: Vec<RuleTrace>,
}
impl Domain<Rule> for Evaluator<'_> {
    type Verdict = Decision;
    fn matches(&mut self, rule: &Rule) -> bool {
        let mut conditions = Vec::new();
        let mut matched = rule.enabled;
        if matched {
            for condition in &rule.conditions {
                let answer = condition.matches(self.facts);
                if self.trace {
                    conditions.push(ConditionTrace {
                        condition: condition.key.clone(),
                        matched: answer,
                    });
                }
                if !answer {
                    matched = false;
                    break;
                }
            }
        }
        if self.trace {
            self.rules.push(RuleTrace {
                rule: rule.path.clone(),
                matched,
                conditions,
                steps: Vec::new(),
            });
        }
        matched
    }
    fn resolve(&mut self, rule: &Rule, _path: &str) -> Result<Option<Decision>, AllocError> {
        Ok(rule.decision)
    }
    fn strictness(&self, decision: Decision) -> u8 {
        match decision {
            Decision::Assign(_) => 0,
            Decision::Reject => 1,
        }
    }
    fn observe(&mut self, _rule: &Rule, path: &str, step: Step) -> Result<(), AllocError> {
        if self.trace {
            if let Some(trace) = self.rules.iter_mut().find(|t| t.rule == path) {
                trace.steps.push(
                    match step {
                        Step::Shadowed => "shadowed",
                        Step::Triggered => "triggered",
                        Step::Fallback => "ancestor-fallback",
                    }
                    .into(),
                );
            }
        }
        Ok(())
    }
}
