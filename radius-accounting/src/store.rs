//! One owner commits accounting facts, interpretation and budget evidence.
use crate::{
    model::{Grant, Observation, Receipt, Session, Settings, State},
    quota::{interval_usage, Balance, Budget, Dimension},
    Error, Result,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    path::Path,
    time::Duration,
};

const SCHEMA: i64 = 4;
const APPLICATION: i64 = 0x52414441;
type PriorReceipt = (String, Option<String>, String, i64, Vec<u8>);

pub struct Store {
    connection: Connection,
    settings: Settings,
    _owner: Option<File>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub revision: u64,
    pub sessions: u64,
    pub observations: u64,
    pub unresolved: u64,
    pub database_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Annotation {
    pub session: String,
    pub actor: String,
    pub at_ms: i64,
    pub note: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandStep {
    pub action: crate::dynamic::Action,
    pub state: String,
    pub attempts: u32,
    pub at_ms: i64,
    pub first_sent_ms: Option<i64>,
    pub error_cause: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Command {
    #[serde(default)]
    pub previous: Option<crate::dynamic::Authorization>,
    #[serde(default)]
    pub intent_key: String,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub requested_action: crate::dynamic::Action,
    #[serde(default)]
    pub first_sent_ms: Option<i64>,
    #[serde(default)]
    pub not_before_ms: i64,
    #[serde(default)]
    pub validation_error: Option<String>,
    #[serde(default)]
    pub action: crate::dynamic::Action,
    #[serde(default)]
    pub fallback: Vec<crate::dynamic::Action>,
    #[serde(default)]
    pub configuration: String,
    #[serde(default)]
    pub proof: Vec<u8>,
    #[serde(default)]
    pub target: Option<crate::dynamic::Target>,
    #[serde(default)]
    pub desired: Option<crate::dynamic::Authorization>,
    #[serde(default)]
    pub packet: Vec<u8>,
    #[serde(default)]
    pub secret_fingerprint: Vec<u8>,
    #[serde(default)]
    pub port: u16,
    #[serde(default = "crate::dynamic::identifier_window")]
    pub identifier_reuse_seconds: u32,
    #[serde(default)]
    pub history: Vec<CommandStep>,
    pub id: String,
    pub session: String,
    pub actor: String,
    pub created_ms: i64,
    pub state: String,
    pub attempts: u32,
    pub reason: String,
    #[serde(default)]
    pub error_cause: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Correction {
    pub session: String,
    pub actor: String,
    pub at_ms: i64,
    pub end_ms: i64,
    pub note: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Page {
    pub revision: u64,
    pub sessions: Vec<Session>,
    pub next: Option<String>,
}
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub after: Option<String>,
    pub policy: Option<String>,
    pub principal: Option<String>,
    pub active_only: bool,
    pub limit: usize,
    pub revision: Option<u64>,
}

impl Store {
    pub fn open(path: &Path, settings: Settings) -> Result<Self> {
        settings.validate()?;
        // The native adapter provisions and verifies a private directory first.
        // Refuse links here as defence in depth; never chmod an arbitrary tree.
        let parent = path.parent().ok_or(Error::Malformed)?;
        if !parent.is_dir() || std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
            return Err(Error::Configuration(
                "ledger needs a protected real directory".into(),
            ));
        }
        let sidecar = |suffix: &str| {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            std::path::PathBuf::from(p)
        };
        for p in [
            path.to_path_buf(),
            sidecar("-wal"),
            sidecar("-shm"),
            sidecar(".owner"),
        ] {
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(Error::Configuration("unsafe ledger file".into()));
                }
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar(".owner"))?;
        lock.try_lock().map_err(|_| {
            Error::Configuration("ledger already has an owner or locking is unavailable".into())
        })?;
        let connection = Connection::open(path)?;
        let mut store = Self {
            connection,
            settings,
            _owner: Some(lock),
        };
        store.initialize()?;
        Ok(store)
    }
    pub fn memory(settings: Settings) -> Result<Self> {
        settings.validate()?;
        let mut store = Self {
            connection: Connection::open_in_memory()?,
            settings,
            _owner: None,
        };
        store.initialize()?;
        Ok(store)
    }
    fn initialize(&mut self) -> Result<()> {
        self.connection.busy_timeout(Duration::from_millis(250))?;
        let app: i64 = self
            .connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if (app != 0 && app != APPLICATION) || !matches!(version, 0 | 1 | 2 | 3 | SCHEMA) {
            return Err(Error::Configuration(
                "foreign or unsupported ledger schema".into(),
            ));
        }
        if app == 0 {
            let tables = self.connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| unsigned(r, 0),
            )?;
            if tables != 0 {
                return Err(Error::Configuration(
                    "refusing to adopt another database".into(),
                ));
            }
        }
        self.connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL);
          INSERT OR IGNORE INTO meta VALUES(1,0);
          CREATE TABLE IF NOT EXISTS grants (reference BLOB PRIMARY KEY, client TEXT NOT NULL, expires INTEGER NOT NULL, data BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, client TEXT NOT NULL, nas BLOB NOT NULL, wire BLOB NOT NULL, policy TEXT, start INTEGER NOT NULL, last INTEGER NOT NULL, ended INTEGER, data BLOB NOT NULL);
          CREATE INDEX IF NOT EXISTS session_match ON sessions(client,nas,wire,start);
          CREATE INDEX IF NOT EXISTS session_policy ON sessions(policy,id);
          CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, client TEXT NOT NULL, semantic BLOB NOT NULL, exact BLOB NOT NULL, received INTEGER NOT NULL, effective INTEGER NOT NULL, session TEXT, disposition TEXT NOT NULL, data BLOB NOT NULL, projection BLOB);
          CREATE INDEX IF NOT EXISTS observation_retry ON observations(client,semantic,received DESC);
          CREATE INDEX IF NOT EXISTS observation_session ON observations(session,effective);
          CREATE TABLE IF NOT EXISTS boundaries (client TEXT NOT NULL, nas BLOB NOT NULL, subsystem BLOB NOT NULL, at INTEGER NOT NULL, id TEXT PRIMARY KEY, reliable INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS checkpoints (session TEXT PRIMARY KEY, projection BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS usage (id TEXT PRIMARY KEY, session TEXT NOT NULL, at INTEGER NOT NULL, input BLOB NOT NULL, output BLOB NOT NULL, principals BLOB NOT NULL, policy TEXT, uncertain INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS usage_period ON usage(at);
          CREATE TABLE IF NOT EXISTS intervals (id TEXT PRIMARY KEY, session TEXT NOT NULL, start INTEGER NOT NULL, ended INTEGER, principals BLOB NOT NULL, policy TEXT, uncertain INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS interval_period ON intervals(start,ended);
          CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, expires INTEGER NOT NULL, data BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS budgets (id TEXT PRIMARY KEY, data BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY, session TEXT NOT NULL, state TEXT NOT NULL, data BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS annotations (id TEXT PRIMARY KEY, session TEXT NOT NULL, data BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS capture (id TEXT PRIMARY KEY, at INTEGER NOT NULL, packet BLOB NOT NULL);")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS maintenance (id INTEGER PRIMARY KEY CHECK(id=1),at INTEGER NOT NULL); INSERT OR IGNORE INTO maintenance VALUES(1,0);")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS corrections(id TEXT PRIMARY KEY,session TEXT NOT NULL,data BLOB NOT NULL);")?;
        // Version 2 adds independent live reevaluation state. Historical JSON
        // records decode without proof; never infer a baseline during upgrade.
        tx.execute_batch("CREATE TABLE IF NOT EXISTS reconciliations(session TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,data BLOB NOT NULL);")?;
        // Version 3 retains wire allocation independently of command/session
        // retention and projection rebuilds. Never rewind it on a clock step.
        tx.execute_batch("CREATE TABLE IF NOT EXISTS dynamic_wire_clock(scope TEXT PRIMARY KEY,slot INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS dynamic_wire_ids(scope TEXT NOT NULL,identifier INTEGER NOT NULL,at INTEGER NOT NULL,PRIMARY KEY(scope,identifier));")?;
        if version < 3 {
            let commands: Vec<Command> = read_json(&tx, "SELECT data FROM commands")?;
            for command in commands {
                let (Some(target), Ok(timestamp)) = (
                    command.target.as_ref(),
                    crate::wire::dynamic_timestamp(&command.packet),
                ) else {
                    continue;
                };
                if command.port == 0 {
                    continue;
                }
                let scope = target.source.to_string();
                let identifier = i64::from(command.packet[1]);
                let at = i64::from(timestamp);
                tx.execute("INSERT INTO dynamic_wire_clock VALUES('machine',?) ON CONFLICT(scope) DO UPDATE SET slot=max(slot,excluded.slot)",params![at*256+identifier])?;
                tx.execute("INSERT INTO dynamic_wire_ids VALUES(?,?,?) ON CONFLICT(scope,identifier) DO UPDATE SET at=max(at,excluded.at)",params![scope,identifier,at])?;
            }
        }
        if version < 2 {
            tx.execute_batch("DROP INDEX IF EXISTS one_pending_disconnect;")?;
        }
        tx.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS one_pending_control ON commands(session) WHERE state IN ('pending','sent');")?;
        tx.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS control_request ON commands(json_extract(CAST(data AS TEXT),'$.actor'),json_extract(CAST(data AS TEXT),'$.request_id')) WHERE json_extract(CAST(data AS TEXT),'$.request_id') IS NOT NULL;")?;
        tx.execute_batch("CREATE INDEX IF NOT EXISTS control_intent ON commands(session,json_extract(CAST(data AS TEXT),'$.actor'),json_extract(CAST(data AS TEXT),'$.intent_key'));")?;
        tx.execute_batch("CREATE INDEX IF NOT EXISTS control_authorization ON commands(session,state,json_extract(CAST(data AS TEXT),'$.action'),json_extract(CAST(data AS TEXT),'$.proof'));")?;
        tx.execute_batch(&format!(
            "PRAGMA application_id={APPLICATION}; PRAGMA user_version={SCHEMA};"
        ))?;
        tx.commit()?;
        let check: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(Error::Configuration("ledger integrity check failed".into()));
        }
        self.storage_limits(&self.settings)?;
        Ok(())
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }
    pub fn configure(&mut self, settings: Settings) -> Result<()> {
        settings.validate()?;
        self.storage_limits(&settings)?;
        self.settings = settings;
        Ok(())
    }
    pub fn revision(&self) -> Result<u64> {
        Ok(self
            .connection
            .query_row("SELECT revision FROM meta WHERE id=1", [], |r| {
                unsigned(r, 0)
            })?)
    }
    fn storage_limits(&self, settings: &Settings) -> Result<()> {
        let size: u64 = self
            .connection
            .query_row("PRAGMA page_size", [], |r| unsigned(r, 0))?;
        // SQLite enforces growth within each transaction, including a batch
        // that crosses the configured boundary. Free pages remain reusable.
        let pages = settings.max_database_bytes / size;
        self.connection
            .pragma_update(None, "max_page_count", pages as i64)?;
        self.connection
            .execute_batch("PRAGMA wal_autocheckpoint=128; PRAGMA journal_size_limit=1048576;")?;
        Ok(())
    }
    pub fn capacity(&self) -> Result<()> {
        live_capacity(&self.connection, self.settings.max_database_bytes)
    }
    fn database_bytes(&self) -> Result<u64> {
        let pages = self
            .connection
            .query_row("PRAGMA page_count", [], |r| unsigned(r, 0))?;
        let size = self
            .connection
            .query_row("PRAGMA page_size", [], |r| unsigned(r, 0))?;
        let wal = self
            .connection
            .path()
            .and_then(|p| std::fs::metadata(format!("{p}-wal")).ok())
            .map_or(0, |m| m.len());
        Ok(pages.saturating_mul(size).saturating_add(wal))
    }
    pub fn health(&self) -> Result<Health> {
        Ok(Health {
            revision: self.revision()?,
            sessions: self
                .connection
                .query_row("SELECT count(*) FROM sessions", [], |r| unsigned(r, 0))?,
            observations: self.connection.query_row(
                "SELECT count(*) FROM observations",
                [],
                |r| unsigned(r, 0),
            )?,
            unresolved: self.connection.query_row(
                "SELECT count(*) FROM observations WHERE disposition='unresolved'",
                [],
                |r| unsigned(r, 0),
            )?,
            database_bytes: self.database_bytes()?,
        })
    }
    /// Nothing is returned until the entire batch's FULL-sync commit succeeds.
    pub fn record(&mut self, observations: &[Observation]) -> Result<Vec<Receipt>> {
        self.capacity()?;
        if observations.is_empty() || observations.len() > self.settings.batch_count {
            return Err(Error::Limit);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = advance(&tx)?;
        let mut receipts = Vec::with_capacity(observations.len());
        for observation in observations {
            let mut normalized = observation.clone();
            if !self.settings.retain_names {
                normalized.username = None;
                normalized.attributes.retain(|a| a.kind != 1);
            }
            if !self.settings.retain_attributes {
                normalized.attributes.clear();
            }
            receipts.push(apply(&tx, &normalized, &self.settings, revision)?);
        }
        live_capacity(&tx, self.settings.max_database_bytes)?;
        tx.commit()?;
        Ok(receipts)
    }
    pub fn grant(&mut self, grant: &Grant, now: i64) -> Result<Vec<Balance>> {
        let mut canonical = grant.clone();
        canonical.groups.sort();
        canonical.groups.dedup();
        if !self.settings.retain_names {
            canonical.name = None;
        }
        let grant = &canonical;
        if let Some(proof) = &grant.proof {
            proof.validate()?;
            if proof.grant != grant.reference || proof.authenticated_ms != grant.issued_ms {
                return Err(Error::Malformed);
            }
        }
        self.capacity()?;
        if grant.reference.is_empty()
            || grant.reference.len() > 253
            || grant.sid.len() > 192
            || grant.groups.len() > 1024
            || grant.client.is_empty()
            || grant.policy.is_empty()
            || grant.issued_ms > now
            || grant.expires_ms <= now
        {
            return Err(Error::Malformed);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM grants WHERE reference=?",
                [&grant.reference],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            let existing: Grant = serde_json::from_slice(&bytes)?;
            if existing != *grant {
                return Err(Error::Integrity);
            }
            return balances(&tx, grant, now, Some(&grant.reference), true);
        }
        tx.execute("DELETE FROM reservations WHERE expires<=?", [now])?;
        let balances = balances(&tx, grant, now, None, true)?;
        if balances.iter().any(Balance::exhausted) {
            return Err(Error::Configuration("principal allowance exhausted".into()));
        }
        tx.execute(
            "INSERT INTO grants VALUES(?,?,?,?)",
            params![
                grant.reference,
                grant.client,
                grant.expires_ms,
                serde_json::to_vec(grant)?
            ],
        )?;
        tx.execute(
            "INSERT INTO reservations VALUES(?,?,?)",
            params![
                crate::hex(&grant.reference),
                now.saturating_add((self.settings.reservation_seconds * 1000) as i64),
                serde_json::to_vec(grant)?
            ],
        )?;
        advance(&tx)?;
        live_capacity(&tx, self.settings.max_database_bytes)?;
        tx.commit()?;
        Ok(balances)
    }
    pub fn replace_budgets(&mut self, budgets: &[Budget]) -> Result<()> {
        if budgets.len() > 256 {
            return Err(Error::Limit);
        }
        let mut ids = BTreeSet::new();
        for b in budgets {
            b.validate()?;
            if !ids.insert(&b.id) {
                return Err(Error::Malformed);
            }
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM budgets", [])?;
        for b in budgets {
            tx.execute(
                "INSERT INTO budgets VALUES(?,?)",
                params![b.id, serde_json::to_vec(b)?],
            )?;
        }
        advance(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn balances(&self, grant: &Grant, now: i64) -> Result<Vec<Balance>> {
        balances(&self.connection, grant, now, None, false)
    }
    /// Complete the reservation with precisely the authorization about to be
    /// emitted. The caller waits for this commit before issuing Class.
    pub fn bind_grant(&mut self, proof: &crate::dynamic::Proof) -> Result<()> {
        proof.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let data: Vec<u8> = tx.query_row(
            "SELECT data FROM grants WHERE reference=?",
            [&proof.grant],
            |r| r.get(0),
        )?;
        let mut grant: Grant = serde_json::from_slice(&data)?;
        let mut proof = proof.clone();
        if let Some(existing) = &grant.proof {
            proof.sequence = existing.sequence;
            if existing != &proof {
                return Err(Error::Integrity);
            }
            return Ok(());
        }
        if grant.issued_ms != proof.authenticated_ms {
            return Err(Error::Integrity);
        }
        proof.sequence = advance(&tx)?;
        grant.proof = Some(proof.clone());
        tx.execute(
            "UPDATE grants SET data=? WHERE reference=?",
            params![serde_json::to_vec(&grant)?, proof.grant],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn session(&self, id: &str) -> Result<Option<Session>> {
        self.connection
            .query_row("SELECT data FROM sessions WHERE id=?", [id], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?
            .map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .transpose()
    }
    /// Authorisation is applied before limit/count/cursor, never to an already
    /// paginated result. Revision-bound cursors refuse a mixed moving view.
    pub fn page(&self, filter: &Filter, mut allowed: impl FnMut(&Session) -> bool) -> Result<Page> {
        let revision = self.revision()?;
        if filter.revision.is_some_and(|r| r != revision) {
            return Err(Error::Configuration(
                "session view changed; restart pagination".into(),
            ));
        }
        if !(1..=200).contains(&filter.limit) {
            return Err(Error::Limit);
        }
        let mut stmt = self.connection.prepare(
            "SELECT data FROM sessions WHERE id>? AND (? IS NULL OR policy=?) ORDER BY id",
        )?;
        let mut rows = stmt.query(params![
            filter.after.as_deref().unwrap_or(""),
            filter.policy,
            filter.policy
        ])?;
        let mut result = Vec::new();
        let mut scanned = 0;
        let mut next = None;
        while let Some(row) = rows.next()? {
            scanned += 1;
            if scanned > 100_000 {
                return Err(Error::Limit);
            }
            let s: Session = serde_json::from_slice(&row.get::<_, Vec<u8>>(0)?)?;
            if filter.active_only && matches!(s.state, State::Ended | State::InferredEnded) {
                continue;
            }
            if filter
                .principal
                .as_ref()
                .is_some_and(|p| s.sid.as_ref() != Some(p) && !s.groups.contains(p))
                || !allowed(&s)
            {
                continue;
            }
            if result.len() == filter.limit {
                next = result.last().map(|s: &Session| s.id.clone());
                break;
            }
            result.push(s);
        }
        Ok(Page {
            revision,
            sessions: result,
            next,
        })
    }
    pub fn annotate(&mut self, annotation: Annotation) -> Result<()> {
        if annotation.note.is_empty()
            || annotation.note.len() > 4096
            || annotation.actor.len() > 192
            || self.session(&annotation.session)?.is_none()
        {
            return Err(Error::Malformed);
        }
        self.connection.execute(
            "INSERT INTO annotations VALUES(?,?,?)",
            params![
                crate::id()?,
                annotation.session,
                serde_json::to_vec(&annotation)?
            ],
        )?;
        Ok(())
    }
    pub fn correct_end(&mut self, c: Correction) -> Result<()> {
        let mut s = self.session(&c.session)?.ok_or(Error::Malformed)?;
        if !matches!(s.state, State::Stale | State::InferredEnded)
            || c.end_ms < s.last_ms
            || c.end_ms > c.at_ms
            || s.end_ms.is_some_and(|end| c.end_ms > end)
            || c.end_ms
                > s.last_received_ms
                    .saturating_add((self.settings.expire_seconds * 1000) as i64)
            || c.note.is_empty()
            || c.note.len() > 4096
            || c.actor.is_empty()
            || c.actor.len() > 192
        {
            return Err(Error::Malformed);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        s.revision = advance(&tx)?;
        s.state = State::InferredEnded;
        s.end_ms = Some(c.end_ms);
        s.warnings.push("administrator-correction".into());
        tx.execute(
            "INSERT INTO corrections VALUES(?,?,?)",
            params![crate::id()?, s.id, serde_json::to_vec(&c)?],
        )?;
        tx.execute("UPDATE intervals SET ended=max(start,min(coalesce(ended,?),?)),uncertain=1 WHERE session=?",params![c.end_ms,c.end_ms,s.id])?;
        save_session(&tx, &s)?;
        tx.commit()?;
        Ok(())
    }
    pub fn enqueue_disconnect(
        &mut self,
        session: &str,
        actor: &str,
        now: i64,
        reason: &str,
    ) -> Result<Command> {
        let s = self.session(session)?.ok_or(Error::Malformed)?;
        if s.session.is_empty()
            || s.kind != "session"
            || s.nas_attributes.is_empty()
            || matches!(s.state, State::Ended | State::InferredEnded)
            || actor.len() > 192
            || reason.len() > 256
        {
            return Err(Error::Malformed);
        }
        let existing: Option<Vec<u8>>=self.connection.query_row("SELECT data FROM commands WHERE session=? AND (state IN ('pending','sent','uncertain') OR (json_extract(CAST(data AS TEXT),'$.actor')='radiusd' AND json_extract(CAST(data AS TEXT),'$.reason')=?)) LIMIT 1",params![session,reason],|r|r.get(0)).optional()?;
        if let Some(b) = existing {
            return Ok(serde_json::from_slice(&b)?);
        }
        let command = Command {
            previous: None,
            intent_key: String::new(),
            request_id: None,
            requested_action: crate::dynamic::Action::Disconnect,
            first_sent_ms: None,
            not_before_ms: 0,
            validation_error: None,
            action: crate::dynamic::Action::Disconnect,
            fallback: vec![],
            configuration: String::new(),
            proof: s
                .proof
                .as_ref()
                .map(|p| p.grant.clone())
                .unwrap_or_default(),
            target: Some(crate::dynamic::Target::from_session(&s)?),
            desired: None,
            packet: vec![],
            secret_fingerprint: vec![],
            port: 0,
            identifier_reuse_seconds: crate::dynamic::identifier_window(),
            history: vec![],
            id: crate::id()?,
            session: session.into(),
            actor: actor.into(),
            created_ms: now,
            state: "pending".into(),
            attempts: 0,
            reason: reason.into(),
            error_cause: None,
        };
        self.connection.execute(
            "INSERT INTO commands VALUES(?,?,?,?)",
            params![
                command.id,
                command.session,
                command.state,
                serde_json::to_vec(&command)?
            ],
        )?;
        Ok(command)
    }
    pub fn commands(&self) -> Result<Vec<Command>> {
        read_json(
            &self.connection,
            &format!(
                "SELECT data FROM commands WHERE state IN ('pending','sent') AND coalesce(json_extract(CAST(data AS TEXT),'$.not_before_ms'),0)<={} ORDER BY id LIMIT 128",
                crate::worker::now_ms()
            ),
        )
    }
    pub fn enqueue_dynamic(&mut self, intent: crate::dynamic::Intent, now: i64) -> Result<Command> {
        use crate::dynamic::Action;
        let crate::dynamic::Intent {
            intent_key,
            request_id,
            session,
            actor,
            reason,
            action,
            configuration,
            desired,
            fallback,
        } = intent;
        let rank = |action| match action {
            Action::UpdateAuthorization => 0,
            Action::Reauthenticate => 1,
            Action::Disconnect => 2,
        };
        let mut previous = rank(action);
        for next in &fallback {
            if rank(*next) <= previous {
                return Err(Error::Malformed);
            }
            previous = rank(*next);
        }
        if let Some(request) = &request_id {
            if request.is_empty() || request.len() > 128 {
                return Err(Error::Malformed);
            }
            let data:Option<Vec<u8>>=self.connection.query_row("SELECT data FROM commands WHERE json_extract(CAST(data AS TEXT),'$.actor')=? AND json_extract(CAST(data AS TEXT),'$.request_id')=?",params![actor,request],|r|r.get(0)).optional()?;
            if let Some(data) = data {
                let command: Command = serde_json::from_slice(&data)?;
                if command.session != session || command.requested_action != action {
                    return Err(Error::Integrity);
                }
                return Ok(command);
            }
        }
        let session = session.as_str();
        let actor = actor.as_str();
        let reason = reason.as_str();
        let configuration = configuration.as_str();
        if configuration.len() != 64
            || intent_key.len() > 128
            || fallback.len() > 2
            || reason.len() > 256
            || actor.is_empty()
            || actor.len() > 192
        {
            return Err(Error::Malformed);
        }
        if action != Action::Disconnect {
            desired.as_ref().ok_or(Error::Malformed)?.validate()?;
        }
        let s = self.session(session)?.ok_or(Error::Malformed)?;
        let target = crate::dynamic::Target::from_session(&s)?;
        if actor == "radiusd" {
            // Deduplication must outlive the bounded history presentation page.
            let proof = serde_json::to_string(
                &s.proof
                    .as_ref()
                    .map(|p| p.grant.clone())
                    .unwrap_or_default(),
            )?;
            let action_json = serde_json::to_value(action)?;
            let data: Option<Vec<u8>> = self.connection.query_row(
                "SELECT data FROM commands WHERE session=? AND json_extract(CAST(data AS TEXT),'$.actor')=? AND coalesce(json_extract(CAST(data AS TEXT),'$.intent_key'),'')=? AND coalesce(json_extract(CAST(data AS TEXT),'$.requested_action'),'disconnect')=? AND json_extract(CAST(data AS TEXT),'$.reason')=? AND json_extract(CAST(data AS TEXT),'$.proof')=? AND state!='superseded' AND (json_extract(CAST(data AS TEXT),'$.configuration')=? OR state!='pending' OR json_extract(CAST(data AS TEXT),'$.attempts')!=0) ORDER BY rowid DESC LIMIT 1",
                params![session, actor, intent_key, action_json.as_str().ok_or(Error::Malformed)?, reason, proof, configuration], |r|r.get(0)).optional()?;
            if let Some(data) = data {
                return Ok(serde_json::from_slice(&data)?);
            }
        }
        let pending: Vec<Command> = self
            .command_history(session)?
            .into_iter()
            .filter(|c| matches!(c.state.as_str(), "pending" | "sent"))
            .collect();
        for mut c in pending {
            if actor != "radiusd" {
                return Err(Error::Configuration(
                    "a session control is already queued".into(),
                ));
            }
            if c.state == "sent" || c.attempts != 0 {
                return Ok(c);
            }
            c.state = "superseded".into();
            self.command_result(&c)?;
        }
        let command = Command {
            previous: None,
            intent_key,
            request_id,
            requested_action: action,
            first_sent_ms: None,
            not_before_ms: 0,
            validation_error: None,
            id: crate::id()?,
            session: session.into(),
            actor: actor.into(),
            created_ms: now,
            state: "pending".into(),
            attempts: 0,
            reason: reason.into(),
            error_cause: None,
            action,
            fallback,
            configuration: configuration.into(),
            proof: s
                .proof
                .as_ref()
                .map(|p| p.grant.clone())
                .unwrap_or_default(),
            target: Some(target),
            desired,
            packet: vec![],
            secret_fingerprint: vec![],
            port: 0,
            identifier_reuse_seconds: crate::dynamic::identifier_window(),
            history: vec![],
        };
        self.connection.execute(
            "INSERT INTO commands VALUES(?,?,?,?)",
            params![
                command.id,
                session,
                command.state,
                serde_json::to_vec(&command)?
            ],
        )?;
        Ok(command)
    }
    pub fn command_request(&self, actor: &str, request: &str) -> Result<Option<Command>> {
        if actor.len() > 192 || request.is_empty() || request.len() > 128 {
            return Err(Error::Malformed);
        }
        let data:Option<Vec<u8>>=self.connection.query_row("SELECT data FROM commands WHERE json_extract(CAST(data AS TEXT),'$.actor')=? AND json_extract(CAST(data AS TEXT),'$.request_id')=?",params![actor,request],|r|r.get(0)).optional()?;
        data.map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .transpose()
    }
    pub fn reconciliation(&self, session: &str) -> Result<crate::dynamic::Reconciliation> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT data FROM reconciliations WHERE session=?",
                [session],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .unwrap_or_else(|| Ok(Default::default()))
    }
    pub fn reconciled(
        &mut self,
        session: &str,
        state: &crate::dynamic::Reconciliation,
    ) -> Result<()> {
        if state.status.len() > 256 || state.configuration.len() > 64 {
            return Err(Error::Malformed);
        }
        // Stable observations do not need another full fsync every scan.
        // checked_ms is the last durably recorded evaluation, not a heartbeat.
        let mut existing = self.reconciliation(session)?;
        existing.checked_ms = state.checked_ms;
        if existing == *state {
            return Ok(());
        }
        self.connection.execute("INSERT INTO reconciliations VALUES(?,?) ON CONFLICT(session) DO UPDATE SET data=excluded.data", params![session, serde_json::to_vec(state)?])?;
        Ok(())
    }
    /// Select independently of the bounded presentation history. Hundreds of
    /// later rejected requests must not erase the last acknowledged baseline.
    pub fn acknowledged_authorization(
        &self,
        session: &str,
        proof: &[u8],
    ) -> Result<Option<crate::dynamic::Authorization>> {
        let data:Option<Vec<u8>>=self.connection.query_row(
            "SELECT data FROM commands WHERE session=? AND state='acknowledged' AND json_extract(CAST(data AS TEXT),'$.action')='update-authorization' AND json_extract(CAST(data AS TEXT),'$.proof')=? ORDER BY rowid DESC LIMIT 1",
            params![session,serde_json::to_string(proof)?],|r|r.get(0)).optional()?;
        data.map(|bytes| {
            serde_json::from_slice::<Command>(&bytes)
                .map(|c| c.desired)
                .map_err(Into::into)
        })
        .transpose()
        .map(Option::flatten)
    }
    pub fn command_history(&self, session: &str) -> Result<Vec<Command>> {
        let mut stmt = self
            .connection
            .prepare("SELECT data FROM commands WHERE session=? ORDER BY rowid DESC LIMIT 200")?;
        let rows = stmt
            .query_map([session], |r| r.get::<_, Vec<u8>>(0))?
            .map(|r| serde_json::from_slice(&r?).map_err(Into::into))
            .collect();
        rows
    }
    pub fn command_result(&mut self, command: &Command) -> Result<()> {
        let stored: Vec<u8> = self.connection.query_row(
            "SELECT data FROM commands WHERE id=?",
            [&command.id],
            |r| r.get(0),
        )?;
        let current: Command = serde_json::from_slice(&stored)?;
        if current.previous.is_some() && current.previous != command.previous {
            return Err(Error::Integrity);
        }
        if let Some(previous) = &command.previous {
            previous.validate()?;
        }
        if !matches!(current.state.as_str(), "pending" | "sent")
            || current.intent_key != command.intent_key
            || current.request_id != command.request_id
            || current.requested_action != command.requested_action
            || current.session != command.session
            || current.actor != command.actor
            || current.created_ms != command.created_ms
            || current.reason != command.reason
        {
            return Err(Error::Integrity);
        }
        if command.state == "sent" {
            let session = self.session(&command.session)?.ok_or(Error::Malformed)?;
            if session.end_ms.is_some()
                || command.proof
                    != session
                        .proof
                        .as_ref()
                        .map(|p| p.grant.clone())
                        .unwrap_or_default()
                || crate::dynamic::Target::from_session(&session).ok().as_ref()
                    != command.target.as_ref()
            {
                return Err(Error::Integrity);
            }
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if command.state == "sent" {
            if !(1..=86400).contains(&command.identifier_reuse_seconds) {
                return Err(Error::Malformed);
            }
            let timestamp = i64::from(crate::wire::dynamic_timestamp(&command.packet)?);
            if current.state == "sent" {
                // A retransmission reuses the exact durable request, including
                // its first-send time and key/destination fence.
                if current.packet != command.packet
                    || current.first_sent_ms != command.first_sent_ms
                    || current.secret_fingerprint != command.secret_fingerprint
                    || current.port != command.port
                    || current.identifier_reuse_seconds != command.identifier_reuse_seconds
                {
                    return Err(Error::Integrity);
                }
            } else {
                let target = command.target.as_ref().ok_or(Error::Malformed)?;
                let scope = target.source.to_string();
                let id = i64::from(command.packet[1]);
                let slot = timestamp * 256 + id;
                let prior: Option<i64> = tx
                    .query_row(
                        "SELECT slot FROM dynamic_wire_clock WHERE scope='machine'",
                        [],
                        |r| r.get(0),
                    )
                    .optional()?;
                let used: Option<i64> = tx
                    .query_row(
                        "SELECT at FROM dynamic_wire_ids WHERE scope=? AND identifier=?",
                        params![scope, id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if prior.is_some_and(|old| slot <= old)
                    || used.is_some_and(|old| {
                        timestamp < old + i64::from(command.identifier_reuse_seconds)
                    })
                {
                    let mut deferred = current.clone();
                    deferred.validation_error =
                        Some("waiting for a fresh RADIUS identifier or clock recovery".into());
                    tx.execute(
                        "UPDATE commands SET data=? WHERE id=?",
                        params![serde_json::to_vec(&deferred)?, deferred.id],
                    )?;
                    tx.commit()?;
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "dynamic identifier reserved",
                    )));
                }
                tx.execute("INSERT INTO dynamic_wire_clock VALUES('machine',?) ON CONFLICT(scope) DO UPDATE SET slot=excluded.slot",params![slot])?;
                tx.execute("INSERT INTO dynamic_wire_ids VALUES(?,?,?) ON CONFLICT(scope,identifier) DO UPDATE SET at=excluded.at",params![scope,id,timestamp])?;
            }
        }
        tx.execute(
            "UPDATE commands SET state=?,data=? WHERE id=?",
            params![command.state, serde_json::to_vec(command)?, command.id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn maintain(&mut self, now: i64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = advance(&tx)?;
        tx.execute("UPDATE maintenance SET at=max(at,?) WHERE id=1", [now])?;
        let sessions: Vec<Session> =
            read_json(&tx, "SELECT data FROM sessions WHERE ended IS NULL")?;
        for mut s in sessions {
            let age = now.saturating_sub(s.last_received_ms);
            if age >= (self.settings.expire_seconds * 1000) as i64 {
                s.state = State::InferredEnded;
                s.end_ms = Some(
                    s.last_received_ms
                        .saturating_add((self.settings.expire_seconds * 1000) as i64),
                );
                s.warnings.push("inferred-expiration".into());
                tx.execute(
                    "UPDATE intervals SET ended=?,uncertain=1 WHERE session=? AND ended IS NULL",
                    params![s.end_ms, s.id],
                )?;
            } else if age >= (self.settings.stale_seconds * 1000) as i64 && s.state == State::Active
            {
                s.state = State::Stale;
            } else {
                continue;
            }
            s.revision = revision;
            save_session(&tx, &s)?;
        }
        tx.execute("DELETE FROM reservations WHERE expires<=?", [now])?;
        let cutoff =
            now.saturating_sub((self.settings.observation_retention_seconds * 1000) as i64);
        // Bound maintenance so packet commits continue between chunks.
        let expired: Vec<(String, Option<String>, Option<Vec<u8>>)> = {
            let mut stmt=tx.prepare("SELECT id,session,projection FROM observations WHERE received<? ORDER BY rowid LIMIT 512")?;
            let rows = stmt
                .query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<_, _>>()?;
            rows
        };
        for (id, session, projection) in expired {
            if let (Some(session), Some(projection)) = (session, projection) {
                tx.execute("INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(session) DO UPDATE SET projection=excluded.projection",params![session,projection])?;
            }
            tx.execute("DELETE FROM observations WHERE id=?", [id])?;
        }
        let raw_cutoff = now.saturating_sub((self.settings.raw_retention_seconds * 1000) as i64);
        tx.execute("DELETE FROM capture WHERE at<?", [raw_cutoff])?;
        let summary_cutoff =
            now.saturating_sub((self.settings.summary_retention_seconds * 1000) as i64);
        // Quota evidence is retained separately from personal session history.
        // It cannot be discarded while a lifetime allowance may still use it.
        tx.execute(
            "DELETE FROM checkpoints WHERE session IN (SELECT id FROM sessions WHERE ended<?)",
            [summary_cutoff],
        )?;
        tx.execute(
            "DELETE FROM annotations WHERE session IN (SELECT id FROM sessions WHERE ended<?)",
            [summary_cutoff],
        )?;
        tx.execute(
            "DELETE FROM commands WHERE session IN (SELECT id FROM sessions WHERE ended<?)",
            [summary_cutoff],
        )?;
        tx.execute(
            "DELETE FROM observations WHERE session IN (SELECT id FROM sessions WHERE ended<?)",
            [summary_cutoff],
        )?;
        tx.execute("DELETE FROM sessions WHERE ended<?", [summary_cutoff])?;
        tx.execute(
            "DELETE FROM corrections WHERE session NOT IN (SELECT id FROM sessions)",
            [],
        )?;
        tx.execute("DELETE FROM grants WHERE expires<? AND NOT EXISTS(SELECT 1 FROM reservations WHERE id=lower(hex(grants.reference)))",[cutoff])?;
        compact_usage(&tx, cutoff)?;
        tx.commit()?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
        Ok(())
    }
    /// Rebuild retained interpretations from checkpoint anchors plus original
    /// observations, preserving occurrence IDs and all external action records.
    /// A rebuild never enqueues Disconnect or republishes accounting events.
    pub fn rebuild(&mut self) -> Result<()> {
        self.rebuild_as("internal", 0)
    }
    pub fn rebuild_as(&mut self, actor: &str, at_ms: i64) -> Result<()> {
        if actor.is_empty() || actor.len() > 192 {
            return Err(Error::Malformed);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = advance(&tx)?;
        let anchors: Vec<Session> =
            read_json(&tx, "SELECT projection FROM checkpoints ORDER BY session")?;
        let reevaluations: Vec<(String, Vec<u8>)> = {
            let mut query = tx.prepare("SELECT session,data FROM reconciliations")?;
            let rows = query.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        tx.execute(
            "INSERT INTO annotations VALUES(?,?,?)",
            params![
                crate::id()?,
                "*",
                serde_json::to_vec(&Annotation {
                    session: "*".into(),
                    actor: actor.into(),
                    at_ms,
                    note: format!("rebuild revision {revision}")
                })?
            ],
        )?;
        let evidence: Vec<(String, Observation)> = {
            let mut stmt = tx.prepare("SELECT id,data FROM observations ORDER BY rowid")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            let mut values = Vec::new();
            for row in rows {
                let (id, data) = row?;
                if values.len() >= 100_000 {
                    return Err(Error::Limit);
                }
                values.push((id, serde_json::from_slice(&data)?));
            }
            values
        };
        tx.execute("DELETE FROM sessions", [])?;
        tx.execute(
            "DELETE FROM usage WHERE id IN (SELECT id FROM observations)",
            [],
        )?;
        for mut s in anchors {
            s.revision = revision;
            save_session(&tx, &s)?;
            if s.kind == "session" {
                tx.execute(
                    "INSERT OR IGNORE INTO intervals VALUES(?,?,?,?,?,?,?)",
                    params![
                        s.id,
                        s.id,
                        s.start_ms,
                        s.end_ms,
                        serde_json::to_vec(&principals(&s))?,
                        s.policy,
                        i32::from(!s.warnings.is_empty())
                    ],
                )?;
            }
        }
        for (id, o) in evidence {
            let mut session = None;
            let disposition = if !within_window(&o, &self.settings) {
                "outside-retained-time-window".into()
            } else if o.lifecycle() {
                lifecycle(&tx, &o, &id, revision)?
            } else if !matches!(o.status, 1 | 2 | 3 | 9 | 10 | 11 | 12 | 13 | 14) {
                "unsupported-status".into()
            } else {
                match interpret(&tx, &o, &self.settings, revision, &id, true) {
                    Ok(Some(s)) => {
                        session = Some(s.id);
                        "recorded".into()
                    }
                    Ok(None) | Err(Error::Integrity) => "unresolved".into(),
                    Err(e) => return Err(e),
                }
            };
            let projection: Option<Vec<u8>> = if let Some(s) = &session {
                tx.query_row("SELECT data FROM sessions WHERE id=?", [s], |r| r.get(0))
                    .optional()?
            } else {
                None
            };
            tx.execute(
                "UPDATE observations SET session=?,disposition=?,projection=? WHERE id=?",
                params![session, disposition, projection, id],
            )?;
        }
        for (session, data) in reevaluations {
            tx.execute("INSERT INTO reconciliations SELECT ?,? WHERE EXISTS(SELECT 1 FROM sessions WHERE id=?)", params![session, data, session])?;
        }
        let now: i64 = tx.query_row("SELECT at FROM maintenance WHERE id=1", [], |r| r.get(0))?;
        let active: Vec<Session> = read_json(&tx, "SELECT data FROM sessions WHERE ended IS NULL")?;
        for mut s in active {
            if now.saturating_sub(s.last_received_ms)
                >= (self.settings.expire_seconds * 1000) as i64
            {
                s.state = State::InferredEnded;
                s.end_ms = Some(
                    s.last_received_ms
                        .saturating_add((self.settings.expire_seconds * 1000) as i64),
                );
                if !s.warnings.iter().any(|w| w == "inferred-expiration") {
                    s.warnings.push("inferred-expiration".into());
                }
                tx.execute(
                    "UPDATE intervals SET ended=?,uncertain=1 WHERE session=? AND ended IS NULL",
                    params![s.end_ms, s.id],
                )?;
                save_session(&tx, &s)?;
            } else if now.saturating_sub(s.last_received_ms)
                >= (self.settings.stale_seconds * 1000) as i64
            {
                s.state = State::Stale;
                save_session(&tx, &s)?;
            }
        }
        let corrections: Vec<Correction> =
            read_json(&tx, "SELECT data FROM corrections ORDER BY rowid")?;
        for c in corrections {
            let data: Option<Vec<u8>> = tx
                .query_row("SELECT data FROM sessions WHERE id=?", [&c.session], |r| {
                    r.get(0)
                })
                .optional()?;
            if let Some(data) = data {
                let mut s: Session = serde_json::from_slice(&data)?;
                s.end_ms = Some(c.end_ms);
                s.state = State::InferredEnded;
                if !s.warnings.iter().any(|w| w == "administrator-correction") {
                    s.warnings.push("administrator-correction".into());
                }
                save_session(&tx, &s)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn history(&self, session: &str, limit: usize) -> Result<Vec<Observation>> {
        if !(1..=200).contains(&limit) {
            return Err(Error::Limit);
        }
        let mut stmt=self.connection.prepare("SELECT data FROM observations WHERE session=? ORDER BY effective DESC,rowid DESC LIMIT ?")?;
        let rows = stmt.query_map(params![session, limit as i64], |r| r.get::<_, Vec<u8>>(0))?;
        let observations: Vec<Observation> = rows
            .map(|r| serde_json::from_slice(&r?).map_err(Into::into))
            .collect::<Result<_>>()?;
        let mut buckets = BTreeSet::new();
        let width = (self.settings.detail_interval_seconds * 1000).min(i64::MAX as u64) as i64;
        Ok(observations
            .into_iter()
            .filter(|o| {
                width == 0 || o.status != 3 || buckets.insert(o.effective_ms.div_euclid(width))
            })
            .collect())
    }
    pub fn enforce(&mut self, now: i64) -> Result<usize> {
        let sessions: Vec<Session> = read_json(
            &self.connection,
            "SELECT data FROM sessions WHERE ended IS NULL ORDER BY id",
        )?;
        let budgets: Vec<Budget> =
            read_json(&self.connection, "SELECT data FROM budgets ORDER BY id")?;
        let mut commands = 0;
        for budget in budgets.into_iter().filter(|b| b.disconnect) {
            let grant = Grant {
                proof: None,
                reference: Vec::new(),
                client: String::new(),
                policy: budget.policy.clone().unwrap_or_default(),
                sid: budget.principal.clone(),
                name: None,
                groups: Vec::new(),
                station: None,
                issued_ms: 0,
                expires_ms: now.saturating_add(1),
            };
            for b in self
                .balances(&grant, now)?
                .into_iter()
                .filter(|b| b.budget.id == budget.id)
            {
                let exceeded = if b.budget.dimension == Dimension::Concurrent {
                    b.used > b.budget.maximum
                } else {
                    b.exhausted()
                };
                if exceeded && b.budget.disconnect {
                    for s in sessions.iter().filter(|s| s.kind == "session") {
                        if (budget.policy.is_none() || s.policy == budget.policy)
                            && (s.sid.as_ref() == Some(&budget.principal)
                                || s.groups.contains(&budget.principal))
                        {
                            self.enqueue_disconnect(
                                &s.id,
                                "radiusd",
                                now,
                                &format!("budget:{}", b.budget.id),
                            )?;
                            commands += 1;
                        }
                    }
                }
            }
        }
        Ok(commands)
    }
    pub fn capture(&mut self, id: &str, now: i64, packet: &[u8]) -> Result<()> {
        if !self.settings.raw_capture {
            return Ok(());
        }
        let used = self.connection.query_row(
            "SELECT coalesce(sum(length(packet)),0) FROM capture",
            [],
            |r| unsigned(r, 0),
        )?;
        if used.saturating_add(packet.len() as u64) > self.settings.raw_max_bytes {
            return Err(Error::Limit);
        }
        self.connection.execute(
            "INSERT INTO capture VALUES(?,?,?)",
            params![id, now, packet],
        )?;
        Ok(())
    }
}
fn unsigned(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}
/// Fold expired per-report byte deltas into exact UTC-day quota evidence. The
/// detailed observation must already have been pruned, so replay cannot charge
/// the same delta both from a rollup and its source observation.
fn compact_usage(tx: &Transaction<'_>, cutoff: i64) -> Result<()> {
    type Delta = (String, i64, Vec<u8>, Vec<u8>, Vec<u8>, Option<String>, bool);
    let values: Vec<Delta> = {
        let mut stmt=tx.prepare("SELECT id,at,input,output,principals,policy,uncertain FROM usage WHERE at<? AND id NOT LIKE 'aggregate:%' AND NOT EXISTS(SELECT 1 FROM observations o WHERE o.id=usage.id) ORDER BY at,id LIMIT 512")?;
        let values = stmt
            .query_map([cutoff], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        values
    };
    for (id, at, input, output, principals, policy, uncertain) in values {
        let day = at.div_euclid(86_400_000) * 86_400_000;
        let key = serde_json::to_vec(&(day, &principals, &policy))?;
        let key = format!(
            "aggregate:{}",
            crate::hex(ring::digest::digest(&ring::digest::SHA256, &key).as_ref())
        );
        let old: Option<(Vec<u8>, Vec<u8>, bool)> = tx
            .query_row(
                "SELECT input,output,uncertain FROM usage WHERE id=?",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let decode = |b: Vec<u8>| -> Result<u64> {
            Ok(u64::from_be_bytes(
                b.try_into().map_err(|_| Error::Malformed)?,
            ))
        };
        let (old_input, old_output, was_uncertain) = if let Some((i, o, u)) = old {
            (decode(i)?, decode(o)?, u)
        } else {
            (0, 0, false)
        };
        let i = old_input.saturating_add(decode(input)?);
        let o = old_output.saturating_add(decode(output)?);
        tx.execute(
            "INSERT OR REPLACE INTO usage VALUES(?,?,?,?,?,?,?,?)",
            params![
                key,
                "",
                day,
                i.to_be_bytes().as_slice(),
                o.to_be_bytes().as_slice(),
                principals,
                policy,
                uncertain || was_uncertain
            ],
        )?;
        tx.execute("DELETE FROM usage WHERE id=?", [id])?;
    }
    Ok(())
}
fn live_capacity(connection: &Connection, maximum: u64) -> Result<()> {
    let pages: u64 = connection.query_row("PRAGMA page_count", [], |r| unsigned(r, 0))?;
    let free: u64 = connection.query_row("PRAGMA freelist_count", [], |r| unsigned(r, 0))?;
    let size: u64 = connection.query_row("PRAGMA page_size", [], |r| unsigned(r, 0))?;
    if pages.saturating_sub(free).saturating_mul(size) >= maximum {
        return Err(Error::Limit);
    }
    Ok(())
}
fn advance(tx: &Transaction<'_>) -> Result<u64> {
    tx.execute("UPDATE meta SET revision=revision+1 WHERE id=1", [])?;
    Ok(
        tx.query_row("SELECT revision FROM meta WHERE id=1", [], |r| {
            unsigned(r, 0)
        })?,
    )
}
fn read_json<T: serde::de::DeserializeOwned>(c: &Connection, sql: &str) -> Result<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
    rows.map(|r| serde_json::from_slice(&r?).map_err(Into::into))
        .collect()
}
fn save_session(tx: &Transaction<'_>, s: &Session) -> Result<()> {
    tx.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,start=excluded.start,last=excluded.last,ended=excluded.ended,data=excluded.data",params![s.id,s.client,s.nas,s.projection_key().ok_or(Error::Malformed)?,s.policy,s.start_ms,s.last_ms,s.end_ms,serde_json::to_vec(s)?])?;
    Ok(())
}
fn principals(s: &Session) -> Vec<String> {
    let mut values: BTreeSet<_> = s.groups.iter().cloned().collect();
    if let Some(sid) = &s.sid {
        values.insert(sid.clone());
    }
    values.into_iter().collect()
}
fn recognised_grant(tx: &Transaction<'_>, o: &Observation) -> Result<Option<Grant>> {
    let mut found: Option<Grant> = None;
    for class in &o.classes {
        let data: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM grants WHERE reference=? AND client=?",
                params![class, o.client],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(data) = data {
            let grant: Grant = serde_json::from_slice(&data)?;
            if o.policy
                .as_ref()
                .is_some_and(|policy| policy != &grant.policy)
            {
                continue;
            }
            if grant.issued_ms > o.received_ms.saturating_add(300_000)
                || grant.expires_ms < o.effective_ms
            {
                continue;
            }
            if grant
                .station
                .as_ref()
                .zip(o.station.as_ref())
                .is_some_and(|(a, b)| !crate::model::same_station(a, b))
            {
                continue;
            }
            if found
                .as_ref()
                .is_some_and(|g| g.sid != grant.sid || g.policy != grant.policy)
            {
                return Err(Error::Integrity);
            }
            if found
                .as_ref()
                .is_some_and(|g| g.issued_ms == grant.issued_ms && g.groups != grant.groups)
            {
                return Err(Error::Integrity);
            }
            if found.as_ref().is_none_or(|g| {
                (
                    grant.proof.as_ref().map_or(0, |p| p.sequence),
                    grant.issued_ms,
                ) >= (g.proof.as_ref().map_or(0, |p| p.sequence), g.issued_ms)
            }) {
                found = Some(grant);
            }
        }
    }
    Ok(found)
}
fn apply(
    tx: &Transaction<'_>,
    o: &Observation,
    settings: &Settings,
    revision: u64,
) -> Result<Receipt> {
    let horizon = o
        .received_ms
        .saturating_sub((settings.retry_horizon_seconds * 1000) as i64);
    let prior:Option<PriorReceipt>=tx.query_row("SELECT id,session,disposition,effective,data FROM observations WHERE client=? AND semantic=? AND received>=? ORDER BY received DESC LIMIT 1",params![o.client,o.semantic_digest,horizon],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    if let Some((id, session, disposition, effective, data)) = prior {
        let old: Observation = serde_json::from_slice(&data)?;
        if o.has_reliable_time()
            || o.duration_seconds.is_some()
            || o.effective_ms.abs_diff(effective) <= 2000
        {
            // Same authenticated attributes and consistent original occurrence.
            // Retransmit time must not keep a dead session alive.
            if old.nas == o.nas {
                return Ok(Receipt {
                    id,
                    session,
                    disposition: format!("duplicate-{disposition}"),
                    revision,
                });
            }
        }
    }
    let id = crate::id()?;
    let mut session = None;
    let disposition = if !within_window(o, settings) {
        "outside-retained-time-window".into()
    } else if o.lifecycle() {
        lifecycle(tx, o, &id, revision)?
    } else if !matches!(o.status, 1 | 2 | 3 | 9 | 10 | 11 | 12 | 13 | 14) {
        "unsupported-status".into()
    } else {
        match interpret(tx, o, settings, revision, &id, false) {
            Ok(Some(s)) => {
                session = Some(s.id);
                "recorded".into()
            }
            Ok(None) | Err(Error::Integrity) => "unresolved".into(),
            Err(e) => return Err(e),
        }
    };
    let projection: Option<Vec<u8>> = if let Some(session) = &session {
        tx.query_row("SELECT data FROM sessions WHERE id=?", [session], |r| {
            r.get(0)
        })
        .optional()?
    } else {
        None
    };
    tx.execute(
        "INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)",
        params![
            id,
            o.client,
            o.semantic_digest,
            o.packet_digest,
            o.received_ms,
            o.effective_ms,
            session,
            disposition,
            serde_json::to_vec(o)?,
            projection
        ],
    )?;
    Ok(Receipt {
        id,
        session,
        disposition,
        revision,
    })
}
fn within_window(o: &Observation, s: &Settings) -> bool {
    o.effective_ms
        >= o.received_ms
            .saturating_sub((s.summary_retention_seconds * 1000) as i64)
        && !o.warnings.iter().any(|w| w == "unreliable-event-time")
}
fn lifecycle(tx: &Transaction<'_>, o: &Observation, id: &str, revision: u64) -> Result<String> {
    let subsystem = if matches!(o.status, 18 | 19) {
        let Some(s) = &o.subsystem else {
            return Ok("unresolved".into());
        };
        s.clone()
    } else {
        Vec::new()
    };
    tx.execute(
        "INSERT OR IGNORE INTO boundaries VALUES(?,?,?,?,?,?)",
        params![
            o.client,
            o.nas,
            subsystem,
            o.effective_ms,
            id,
            i32::from(o.has_reliable_time())
        ],
    )?;
    if !o.has_reliable_time() {
        return Ok("boundary-time-uncertain".into());
    }
    let mut stmt=tx.prepare("SELECT data FROM sessions WHERE client=? AND nas=? AND ended IS NULL AND start<=? AND last<=?")?;
    let sessions = stmt
        .query_map(
            params![o.client, o.nas, o.effective_ms, o.effective_ms],
            |r| r.get::<_, Vec<u8>>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for data in sessions {
        let mut s: Session = serde_json::from_slice(&data)?;
        if !subsystem.is_empty() && s.subsystem.as_ref() != Some(&subsystem) {
            continue;
        }
        s.state = State::InferredEnded;
        s.end_ms = Some(o.effective_ms);
        s.revision = revision;
        s.warnings.push("nas-lifecycle-boundary".into());
        save_session(tx, &s)?;
        tx.execute(
            "UPDATE intervals SET ended=?,uncertain=1 WHERE session=? AND ended IS NULL",
            params![s.end_ms, s.id],
        )?;
    }
    Ok("lifecycle".into())
}
fn interpret(
    tx: &Transaction<'_>,
    o: &Observation,
    _settings: &Settings,
    revision: u64,
    observation_id: &str,
    replay: bool,
) -> Result<Option<Session>> {
    let Some(wire) = o.projection_key() else {
        return Ok(None);
    };
    let grant = recognised_grant(tx, o)?;
    let policy = grant
        .as_ref()
        .map(|g| g.policy.clone())
        .or_else(|| o.policy.clone());
    let estimated_start = o
        .duration_seconds
        .map(|v| o.effective_ms.saturating_sub(i64::from(v) * 1000));
    let mut stmt=tx.prepare("SELECT data FROM sessions WHERE client=? AND nas=? AND wire=? ORDER BY start DESC LIMIT 65")?;
    let data = stmt
        .query_map(params![o.client, o.nas, wire], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if data.len() > 64 {
        return Ok(None);
    }
    let sessions: Vec<Session> = data
        .iter()
        .map(|d| serde_json::from_slice(d))
        .collect::<std::result::Result<_, _>>()?;
    let candidates: Vec<_> = sessions
        .iter()
        .filter(|s| {
            if s.station
                .as_ref()
                .zip(o.station.as_ref())
                .is_some_and(|(a, b)| !crate::model::same_station(a, b))
            {
                return false;
            }
            if policy.is_some() && s.policy.is_some() && policy != s.policy {
                return false;
            }
            if let Some(g) = &grant {
                if s.sid.as_ref().is_some_and(|sid| sid != &g.sid) {
                    return false;
                }
            }
            if let Some(start) = estimated_start {
                if s.start_ms.abs_diff(start) > 5000
                    && !s.warnings.iter().any(|w| w == "missing-start")
                {
                    return false;
                }
            }
            if let Some(end) = s.end_ms {
                if o.effective_ms > end.saturating_add(5000) {
                    return false;
                }
            }
            let missing = s.warnings.iter().any(|w| w == "missing-start");
            if o.has_reliable_time() && o.effective_ms < s.start_ms.saturating_sub(5000) && !missing
            {
                return false;
            }
            if matches!(o.status, 1 | 9 | 12)
                && s.start_ms.abs_diff(o.effective_ms) > 5000
                && !missing
            {
                return false;
            }
            true
        })
        .collect();
    if candidates.len() > 1 {
        return Ok(None);
    }
    let is_stop = matches!(o.status, 2 | 10 | 11 | 13 | 14);
    let fresh = candidates.is_empty();
    if fresh && !sessions.is_empty() && !matches!(o.status, 1 | 9 | 12) && estimated_start.is_none()
    {
        return Ok(None);
    }
    let mut s = if let Some(s) = candidates.first() {
        (*s).clone()
    } else {
        let start = estimated_start.unwrap_or(o.effective_ms).max(0);
        let mut warnings = o.warnings.clone();
        if !matches!(o.status, 1 | 9 | 12) {
            warnings.push("missing-start".into());
        }
        Session {
            observed: crate::dynamic::Observed::from_attributes(&o.attributes, o.effective_ms),
            proof: grant.as_ref().and_then(|g| g.proof.clone()),
            id: observation_id.into(),
            client: o.client.clone(),
            nas: o.nas.clone(),
            source: o.source,
            policy: policy.clone(),
            session: o.session.clone().ok_or(Error::Malformed)?,
            kind: o.kind().into(),
            tunnel: o.tunnel.clone(),
            multi_session: o.multi_session.clone(),
            link_count: o.link_count,
            subsystem: o.subsystem.clone(),
            sid: grant.as_ref().map(|g| g.sid.clone()),
            groups: grant.as_ref().map(|g| g.groups.clone()).unwrap_or_default(),
            name: grant.as_ref().and_then(|g| g.name.clone()),
            username: o.username.clone(),
            station: o.station.clone(),
            classes: o.classes.clone(),
            nas_attributes: o.nas_attributes.clone(),
            state: State::Active,
            start_ms: start,
            last_ms: start,
            last_received_ms: o.received_ms,
            end_ms: None,
            input: None,
            output: None,
            warnings,
            revision,
        }
    };
    // Validate identity before making any writes. An unresolved observation may
    // be recorded, but must not leave a partial usage mutation behind.
    if grant
        .as_ref()
        .is_some_and(|g| s.sid.as_ref() != Some(&g.sid))
    {
        return Err(Error::Integrity);
    }
    if fresh {
        let boundary:Option<i64>=tx.query_row("SELECT max(at) FROM boundaries WHERE client=? AND nas=? AND reliable=1 AND (length(subsystem)=0 OR subsystem=?) AND at>=?",params![o.client,o.nas,o.subsystem.as_deref().unwrap_or_default(),s.start_ms],|r|r.get(0))?;
        if let Some(at) = boundary {
            if o.effective_ms > at {
                return Ok(None);
            }
            s.end_ms = Some(at);
            s.state = State::InferredEnded;
            s.warnings.push("nas-lifecycle-boundary".into());
        }
    }
    if matches!(o.status, 1 | 9 | 12)
        && s.warnings.iter().any(|w| w == "missing-start")
        && o.effective_ms <= s.last_ms
    {
        s.start_ms = s.start_ms.min(o.effective_ms);
        s.warnings.retain(|w| w != "missing-start");
        if !replay {
            tx.execute(
                "UPDATE intervals SET start=? WHERE id=?",
                params![s.start_ms, s.id],
            )?;
        }
    }
    // Late evidence cannot reopen an ended occurrence or regress a counter.
    let latest = o.effective_ms >= s.last_ms;
    if latest {
        if let Some(observed) =
            crate::dynamic::Observed::from_attributes(&o.attributes, o.effective_ms)
        {
            s.observed = Some(observed);
        }
        if let Some(g) = &grant {
            if s.groups != g.groups && !fresh && s.kind == "session" {
                let edge = g.issued_ms.max(s.last_ms).min(o.effective_ms);
                if !replay {
                    tx.execute("UPDATE intervals SET ended=?,uncertain=1 WHERE session=? AND ended IS NULL",params![edge,s.id])?;
                    let mut p: BTreeSet<_> = g.groups.iter().cloned().collect();
                    p.insert(g.sid.clone());
                    tx.execute(
                        "INSERT OR IGNORE INTO intervals VALUES(?,?,?,?,?,?,?)",
                        params![
                            format!("{observation_id}:membership"),
                            s.id,
                            edge,
                            s.end_ms,
                            serde_json::to_vec(&p)?,
                            s.policy,
                            true
                        ],
                    )?;
                }
                s.groups = g.groups.clone();
                s.warnings
                    .push("membership-changed-at-reauthentication".into());
            }
        }
    }
    if latest {
        let p = principals(&s);
        let delta = |old: Option<u64>, new: Option<u64>| -> (u64, bool) {
            match (old, new) {
                (Some(a), Some(b)) if b >= a => (b - a, false),
                (None, Some(b)) => (b, false),
                (Some(_), Some(_)) => (0, true),
                _ => (0, false),
            }
        };
        let (input, reset_in) = delta(s.input, o.input);
        let (output, reset_out) = delta(s.output, o.output);
        let uncertain = reset_in
            || reset_out
            || !o.warnings.is_empty()
            || s.last_ms.div_euclid(86_400_000) != o.effective_ms.div_euclid(86_400_000);
        if reset_in || reset_out {
            s.warnings.push("counter-reset-or-wrap-unknown".into());
        }
        if s.kind == "session" {
            tx.execute(
                "INSERT OR REPLACE INTO usage VALUES(?,?,?,?,?,?,?,?)",
                params![
                    observation_id,
                    s.id,
                    o.effective_ms,
                    input.to_be_bytes().as_slice(),
                    output.to_be_bytes().as_slice(),
                    serde_json::to_vec(&p)?,
                    s.policy,
                    i32::from(uncertain)
                ],
            )?;
        }
        s.input = match (s.input, o.input) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => b.or(a),
        };
        s.output = match (s.output, o.output) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => b.or(a),
        };
        s.last_ms = o.effective_ms;
        s.last_received_ms = o.received_ms;
        if s.end_ms.is_none() {
            s.state = State::Active;
        }
    }
    if let Some(g) = grant {
        if latest
            && g.proof
                .as_ref()
                .is_some_and(|p| s.proof.as_ref().is_none_or(|old| p.sequence > old.sequence))
        {
            s.proof = g.proof.clone();
        }
        if s.sid.is_none() && fresh {
            s.sid = Some(g.sid.clone());
            s.groups = g.groups.clone();
            s.name = g.name.clone();
        }
        if s.sid.as_ref() != Some(&g.sid) {
            return Err(Error::Integrity);
        }
        for class in &o.classes {
            if !s.classes.contains(class) {
                s.classes.push(class.clone());
            }
        }
        tx.execute(
            "DELETE FROM reservations WHERE id=?",
            [crate::hex(&g.reference)],
        )?;
    }
    if fresh && !replay && s.kind == "session" {
        tx.execute(
            "INSERT INTO intervals VALUES(?,?,?,?,?,?,?)",
            params![
                s.id,
                s.id,
                s.start_ms,
                if is_stop {
                    Some(o.effective_ms)
                } else {
                    s.end_ms
                },
                serde_json::to_vec(&principals(&s))?,
                s.policy,
                i32::from(!s.warnings.is_empty())
            ],
        )?;
    }
    if is_stop {
        let end = s
            .end_ms
            .map_or(o.effective_ms, |end| end.min(o.effective_ms))
            .max(s.start_ms);
        s.end_ms = Some(end);
        s.state = State::Ended;
        if !replay {
            tx.execute("UPDATE intervals SET ended=CASE WHEN ended IS NULL THEN ? ELSE min(ended,?) END WHERE session=?",params![end,end,s.id])?;
        }
    }
    s.warnings.sort();
    s.warnings.dedup();
    s.warnings.truncate(32);
    s.classes.truncate(64);
    s.revision = revision;
    save_session(tx, &s)?;
    Ok(Some(s))
}

fn same_active_connection(grant: &Grant, session: &Session) -> bool {
    session.kind == "session"
        && session.end_ms.is_none()
        && session.sid.as_ref() == Some(&grant.sid)
        && session.client == grant.client
        && session.policy.as_ref() == Some(&grant.policy)
        && grant
            .station
            .as_deref()
            .zip(session.station.as_deref())
            .is_some_and(|(a, b)| {
                !a.is_empty() && !b.is_empty() && crate::model::same_station(a, b)
            })
}
fn session_has_principal(session: &Session, principal: &str) -> bool {
    session.sid.as_deref() == Some(principal) || session.groups.iter().any(|g| g == principal)
}
fn balances(
    c: &Connection,
    grant: &Grant,
    now: i64,
    exclude: Option<&[u8]>,
    admission: bool,
) -> Result<Vec<Balance>> {
    let budgets: Vec<Budget> = read_json(c, "SELECT data FROM budgets ORDER BY id")?;
    let mut result = Vec::new();
    let principals: BTreeSet<_> = grant
        .groups
        .iter()
        .chain(std::iter::once(&grant.sid))
        .collect();
    for budget in budgets {
        if !principals.contains(&budget.principal)
            || budget.policy.as_ref().is_some_and(|p| p != &grant.policy)
        {
            continue;
        }
        let (from, until) = budget.period.bounds(now)?;
        let mut uncertain = false;
        let used = match budget.dimension {
            Dimension::Concurrent => {
                let mut count = 0u64;
                let mut reused = false;
                let sessions: Vec<Session> =
                    read_json(c, "SELECT data FROM sessions WHERE ended IS NULL")?;
                for s in sessions.iter().filter(|s| s.kind == "session") {
                    if (budget.policy.is_none() || s.policy == budget.policy)
                        && session_has_principal(s, &budget.principal)
                    {
                        // Reauthentication occupies its existing slot, rather
                        // than asking for an additional concurrent connection.
                        // Credit at most one verified, same-scope station.
                        if admission && !reused && same_active_connection(grant, s) {
                            reused = true;
                            continue;
                        }
                        count = count.saturating_add(1);
                        uncertain |= s.state == State::Stale;
                    }
                }
                let reservations: Vec<Grant> = read_json(c, "SELECT data FROM reservations")?;
                for g in reservations {
                    if Some(g.reference.as_slice()) == exclude || g.reference == grant.reference {
                        continue;
                    }
                    let live: bool = c.query_row(
                        "SELECT count(*)>0 FROM reservations WHERE id=? AND expires>?",
                        params![crate::hex(&g.reference), now],
                        |r| r.get(0),
                    )?;
                    if live
                        && (budget.policy.is_none() || budget.policy.as_ref() == Some(&g.policy))
                        && (g.sid == budget.principal || g.groups.contains(&budget.principal))
                    {
                        // Keep the durable reservation for newly acquired
                        // groups, but do not charge a reauthentication twice
                        // for principals already represented by its session.
                        if sessions.iter().any(|s| {
                            same_active_connection(&g, s)
                                && session_has_principal(s, &budget.principal)
                        }) {
                            continue;
                        }
                        count = count.saturating_add(1);
                    }
                }
                count
            }
            Dimension::TotalSessionTime | Dimension::ConnectedTime => {
                let mut stmt=c.prepare("SELECT start,ended,principals,policy,uncertain FROM intervals WHERE start<? AND (ended IS NULL OR ended>?)")?;
                let rows = stmt.query_map(params![until, from], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, bool>(4)?,
                    ))
                })?;
                let mut intervals = Vec::new();
                for row in rows {
                    let (a, b, p, policy, u) = row?;
                    let p: Vec<String> = serde_json::from_slice(&p)?;
                    if p.contains(&budget.principal)
                        && (budget.policy.is_none() || budget.policy == policy)
                    {
                        intervals.push((a, b.unwrap_or(now).min(now)));
                        uncertain |= u;
                    }
                }
                let (sum, union) = interval_usage(intervals, from, until.min(now));
                if budget.dimension == Dimension::TotalSessionTime {
                    sum
                } else {
                    union
                }
            }
            _ => {
                let mut stmt=c.prepare("SELECT input,output,principals,policy,uncertain FROM usage WHERE at>=? AND at<?")?;
                let rows = stmt.query_map(params![from, until], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, bool>(4)?,
                    ))
                })?;
                let mut total = 0u64;
                for row in rows {
                    let (i, o, p, policy, u) = row?;
                    let p: Vec<String> = serde_json::from_slice(&p)?;
                    if !p.contains(&budget.principal)
                        || (budget.policy.is_some() && budget.policy != policy)
                    {
                        continue;
                    }
                    let i = u64::from_be_bytes(i.try_into().map_err(|_| Error::Malformed)?);
                    let o = u64::from_be_bytes(o.try_into().map_err(|_| Error::Malformed)?);
                    let amount = match budget.dimension {
                        Dimension::InputBytes => i,
                        Dimension::OutputBytes => o,
                        _ => i.saturating_add(o),
                    };
                    total = total.saturating_add(amount);
                    uncertain |= u;
                }
                total
            }
        };
        result.push(Balance {
            remaining: budget.maximum.saturating_sub(used),
            budget,
            used,
            uncertain,
            period_start_ms: from,
            period_end_ms: until,
        });
    }
    Ok(result)
}
