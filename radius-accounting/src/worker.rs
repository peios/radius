//! Bounded database owner. Packet loops only enqueue and poll completions.
use crate::{
    model::{Grant, Observation, Receipt, Session, Settings},
    quota::{Balance, Budget},
    store::{Annotation, Command, Correction, Filter, Health, Page, Store},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub type Completion<T> = Receiver<Result<T>>;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub available: bool,
    pub committed: u64,
    pub duplicate: u64,
    pub failed: u64,
    pub admission_bypasses: u64,
    pub batches: u64,
    pub last_commit_ms: Option<i64>,
    pub last_batch_records: usize,
    pub last_commit_latency_ms: u64,
    pub health: Option<Health>,
    pub last_error: Option<String>,
}
#[derive(Clone, Default)]
pub struct View {
    pub policies: BTreeSet<String>,
    pub all: bool,
    pub own_sid: Option<String>,
}
impl View {
    pub fn allows(&self, s: &Session) -> bool {
        self.all
            || s.policy.as_ref().is_some_and(|p| self.policies.contains(p))
            || self
                .own_sid
                .as_ref()
                .is_some_and(|sid| s.sid.as_ref() == Some(sid))
    }
}
enum Work {
    Record(
        Box<Observation>,
        Option<Vec<u8>>,
        Instant,
        SyncSender<Result<Receipt>>,
    ),
    Grant(Grant, SyncSender<Result<Vec<Balance>>>),
    Bind(crate::dynamic::Proof, SyncSender<Result<()>>),
    Configure(Settings, Vec<Budget>, SyncSender<Result<()>>),
    Page(Filter, View, SyncSender<Result<Page>>),
    Session(String, View, SyncSender<Result<Option<Session>>>),
    History(String, usize, View, SyncSender<Result<Vec<Observation>>>),
    Balances(Grant, SyncSender<Result<Vec<Balance>>>),
    Annotate(Annotation, SyncSender<Result<()>>),
    Correct(Correction, SyncSender<Result<()>>),
    Disconnect(String, String, String, SyncSender<Result<Command>>),
    Dynamic(crate::dynamic::Intent, SyncSender<Result<Command>>),
    Reconciliation(String, SyncSender<Result<crate::dynamic::Reconciliation>>),
    Reconciled(
        String,
        crate::dynamic::Reconciliation,
        SyncSender<Result<()>>,
    ),
    Commands(SyncSender<Result<Vec<Command>>>),
    CommandHistory(String, SyncSender<Result<Vec<Command>>>),
    AcknowledgedAuthorization(
        String,
        Vec<u8>,
        SyncSender<Result<Option<crate::dynamic::Authorization>>>,
    ),
    CommandRequest(String, String, SyncSender<Result<Option<Command>>>),
    Dispatch(SyncSender<Result<Vec<(Command, Session)>>>),
    CommandResult(Box<Command>, SyncSender<Result<()>>),
    Rebuild(String, SyncSender<Result<()>>),
    Stop(SyncSender<()>),
}
#[derive(Clone)]
pub struct Handle {
    tx: SyncSender<Work>,
    pub status: Arc<Mutex<Status>>,
}
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
impl Handle {
    pub fn start(path: PathBuf, settings: Settings) -> Result<Self> {
        Self::start_verified(path, settings, Arc::new(|| Ok(())))
    }
    pub fn start_verified(
        path: PathBuf,
        settings: Settings,
        verify: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Self> {
        settings.validate()?;
        let (tx, rx) = mpsc::sync_channel(settings.queue_count);
        let status = Arc::new(Mutex::new(Status::default()));
        let state = status.clone();
        thread::Builder::new()
            .name("radius-accounting".into())
            .spawn(move || run(path, settings, rx, state, verify))?;
        Ok(Self { tx, status })
    }
    fn submit<T>(
        &self,
        build: impl FnOnce(SyncSender<Result<T>>) -> Work,
    ) -> Result<Completion<T>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx.try_send(build(tx)).map_err(|e| match e {
            TrySendError::Full(_) => Error::Limit,
            TrySendError::Disconnected(_) => {
                Error::Configuration("accounting owner stopped".into())
            }
        })?;
        Ok(rx)
    }
    pub fn record(&self, o: Observation, raw: Option<Vec<u8>>) -> Result<Completion<Receipt>> {
        self.submit(|tx| Work::Record(Box::new(o), raw, Instant::now(), tx))
    }
    pub fn grant(&self, g: Grant) -> Result<Completion<Vec<Balance>>> {
        self.submit(|tx| Work::Grant(g, tx))
    }
    pub fn bind_grant(&self, proof: crate::dynamic::Proof) -> Result<Completion<()>> {
        self.submit(|tx| Work::Bind(proof, tx))
    }
    pub fn configure(&self, s: Settings, b: Vec<Budget>) -> Result<Completion<()>> {
        s.validate()?;
        for budget in &b {
            budget.validate()?;
        }
        self.submit(|tx| Work::Configure(s, b, tx))
    }
    pub fn page(&self, f: Filter, v: View) -> Result<Completion<Page>> {
        self.submit(|tx| Work::Page(f, v, tx))
    }
    pub fn session(&self, id: String, v: View) -> Result<Completion<Option<Session>>> {
        self.submit(|tx| Work::Session(id, v, tx))
    }
    pub fn balances(&self, g: Grant) -> Result<Completion<Vec<Balance>>> {
        self.submit(|tx| Work::Balances(g, tx))
    }
    pub fn history(
        &self,
        id: String,
        limit: usize,
        view: View,
    ) -> Result<Completion<Vec<Observation>>> {
        self.submit(|tx| Work::History(id, limit, view, tx))
    }
    pub fn annotate(&self, a: Annotation) -> Result<Completion<()>> {
        self.submit(|tx| Work::Annotate(a, tx))
    }
    pub fn disconnect(
        &self,
        id: String,
        actor: String,
        reason: String,
    ) -> Result<Completion<Command>> {
        self.submit(|tx| Work::Disconnect(id, actor, reason, tx))
    }
    pub fn commands(&self) -> Result<Completion<Vec<Command>>> {
        self.submit(Work::Commands)
    }
    pub fn dynamic(&self, intent: crate::dynamic::Intent) -> Result<Completion<Command>> {
        self.submit(|tx| Work::Dynamic(intent, tx))
    }
    pub fn reconciliation(&self, id: String) -> Result<Completion<crate::dynamic::Reconciliation>> {
        self.submit(|tx| Work::Reconciliation(id, tx))
    }
    pub fn reconciled(
        &self,
        id: String,
        state: crate::dynamic::Reconciliation,
    ) -> Result<Completion<()>> {
        self.submit(|tx| Work::Reconciled(id, state, tx))
    }
    pub fn command_history(&self, session: String) -> Result<Completion<Vec<Command>>> {
        self.submit(|tx| Work::CommandHistory(session, tx))
    }
    pub fn acknowledged_authorization(
        &self,
        session: String,
        proof: Vec<u8>,
    ) -> Result<Completion<Option<crate::dynamic::Authorization>>> {
        self.submit(|tx| Work::AcknowledgedAuthorization(session, proof, tx))
    }
    pub fn command_request(
        &self,
        actor: String,
        request: String,
    ) -> Result<Completion<Option<Command>>> {
        self.submit(|tx| Work::CommandRequest(actor, request, tx))
    }
    pub fn dispatch(&self) -> Result<Completion<Vec<(Command, Session)>>> {
        self.submit(Work::Dispatch)
    }
    pub fn command_result(&self, c: Command) -> Result<Completion<()>> {
        self.submit(|tx| Work::CommandResult(Box::new(c), tx))
    }
    pub fn rebuild(&self, actor: String) -> Result<Completion<()>> {
        self.submit(|tx| Work::Rebuild(actor, tx))
    }
    pub fn correct(&self, c: Correction) -> Result<Completion<()>> {
        self.submit(|tx| Work::Correct(c, tx))
    }
    pub fn snapshot(&self) -> Status {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }
    pub fn bypass(&self) {
        if let Ok(mut s) = self.status.lock() {
            s.admission_bypasses = s.admission_bypasses.saturating_add(1);
        }
    }
    pub fn stop(&self) -> Result<Receiver<()>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx.try_send(Work::Stop(tx)).map_err(|_| Error::Limit)?;
        Ok(rx)
    }
}
pub fn wait<T>(rx: Completion<T>) -> Result<T> {
    rx.recv_timeout(Duration::from_secs(5)).map_err(|_| {
        Error::Configuration("accounting operation timed out; outcome may be unknown".into())
    })?
}
fn unavailable<T>(tx: SyncSender<Result<T>>) {
    let _ = tx.try_send(Err(Error::Configuration(
        "accounting ledger unavailable".into(),
    )));
}
fn run(
    path: PathBuf,
    mut settings: Settings,
    rx: Receiver<Work>,
    status: Arc<Mutex<Status>>,
    verify: Arc<dyn Fn() -> Result<()> + Send + Sync>,
) {
    let opened = verify().and_then(|_| Store::open(&path, settings.clone()));
    if let Ok(mut state) = status.lock() {
        state.available = opened.is_ok();
        state.last_error = opened.as_ref().err().map(ToString::to_string);
    }
    let mut store = opened.ok();
    let mut budgets = Vec::new();
    let mut pending = None;
    let mut last_maintenance = Instant::now();
    let mut last_open = Instant::now();
    loop {
        if store.is_none() && last_open.elapsed() >= Duration::from_secs(2) {
            let opened = verify()
                .and_then(|_| Store::open(&path, settings.clone()))
                .and_then(|mut s| {
                    s.replace_budgets(&budgets)?;
                    Ok(s)
                });
            last_open = Instant::now();
            if let Ok(mut state) = status.lock() {
                state.available = opened.is_ok();
                state.last_error = opened.as_ref().err().map(ToString::to_string);
            }
            store = opened.ok();
        }
        let work = match pending.take() {
            Some(work) => Some(work),
            None => match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(w) => Some(w),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(_) => return,
            },
        };
        if let Some(Work::Stop(tx)) = work {
            drop(store);
            let _ = tx.try_send(());
            return;
        }
        if let Some(work) = work {
            if let Work::Record(o, raw, first, reply) = work {
                let mut batch_bytes = serde_json::to_vec(&o).map_or(usize::MAX, |b| b.len());
                if batch_bytes > settings.batch_bytes {
                    let _ = reply.try_send(Err(Error::Limit));
                    continue;
                }
                let mut batch = vec![(o, raw, reply)];
                while batch.len() < settings.batch_count {
                    let remaining =
                        Duration::from_millis(settings.batch_ms).saturating_sub(first.elapsed());
                    match rx.recv_timeout(remaining) {
                        Ok(Work::Record(o, raw, queued, reply)) => {
                            let bytes = serde_json::to_vec(&o).map_or(usize::MAX, |b| b.len());
                            if bytes > settings.batch_bytes.saturating_sub(batch_bytes) {
                                pending = Some(Work::Record(o, raw, queued, reply));
                                break;
                            }
                            batch_bytes += bytes;
                            batch.push((o, raw, reply));
                        }
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let n = batch.len();
                let observations: Vec<_> = batch.iter().map(|(o, _, _)| (**o).clone()).collect();
                let commit_started = Instant::now();
                let result = store
                    .as_mut()
                    .ok_or_else(|| Error::Configuration("accounting unavailable".into()))
                    .and_then(|s| s.record(&observations));
                let mut duplicates = 0;
                let success = result.is_ok();
                match result {
                    Ok(receipts) => {
                        for ((o, raw, reply), receipt) in batch.into_iter().zip(receipts) {
                            if receipt.disposition.starts_with("duplicate-") {
                                duplicates += 1;
                            }
                            if let (Some(bytes), Some(store)) = (raw, store.as_mut()) {
                                let _ = store.capture(&receipt.id, o.received_ms, &bytes);
                            }
                            let _ = reply.try_send(Ok(receipt));
                        }
                    }
                    Err(error) => {
                        if let Ok(mut s) = status.lock() {
                            s.last_error = Some(error.to_string());
                        }
                        if matches!(error, Error::Storage(_) | Error::Io(_)) {
                            store = None;
                            last_open = Instant::now();
                        }
                        for (_, _, reply) in batch {
                            unavailable(reply);
                        }
                    }
                }
                if let Ok(mut s) = status.lock() {
                    s.batches = s.batches.saturating_add(1);
                    s.last_batch_records = n;
                    s.last_commit_latency_ms =
                        commit_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                    if success {
                        s.last_error = None;
                        s.committed = s.committed.saturating_add(n as u64);
                        s.duplicate = s.duplicate.saturating_add(duplicates);
                        s.last_commit_ms = Some(now_ms());
                    } else {
                        s.failed = s.failed.saturating_add(n as u64);
                    }
                    s.available = success;
                }
            } else if let Some(s) = store.as_mut() {
                match work {
                    Work::Grant(g, tx) => {
                        let result = s.grant(&g, now_ms());
                        if let Err(e @ (Error::Storage(_) | Error::Io(_) | Error::Limit)) = &result
                        {
                            if let Ok(mut state) = status.lock() {
                                state.available = false;
                                state.last_error = Some(e.to_string());
                            }
                        }
                        let _ = tx.try_send(result);
                    }
                    Work::Bind(proof, tx) => {
                        let _ = tx.try_send(s.bind_grant(&proof));
                    }
                    Work::Configure(config, b, tx) => {
                        let result = if config.queue_count != settings.queue_count {
                            Err(Error::Configuration(
                                "queue_count changes require a daemon restart".into(),
                            ))
                        } else {
                            s.replace_budgets(&b)
                                .and_then(|_| s.configure(config.clone()))
                        };
                        if result.is_ok() {
                            settings = config;
                            budgets = b;
                        }
                        let _ = tx.try_send(result);
                    }
                    Work::Page(f, v, tx) => {
                        let _ = tx.try_send(s.page(&f, |s| v.allows(s)));
                    }
                    Work::Session(id, v, tx) => {
                        let result = s.session(&id).map(|s| s.filter(|s| v.allows(s)));
                        let _ = tx.try_send(result);
                    }
                    Work::History(id, limit, v, tx) => {
                        let result = s.session(&id).and_then(|row| {
                            if row.as_ref().is_some_and(|row| v.allows(row)) {
                                s.history(&id, limit)
                            } else {
                                Err(Error::Configuration("session unavailable".into()))
                            }
                        });
                        let _ = tx.try_send(result);
                    }
                    Work::Balances(g, tx) => {
                        let _ = tx.try_send(s.balances(&g, now_ms()));
                    }
                    Work::Annotate(a, tx) => {
                        let _ = tx.try_send(s.annotate(a));
                    }
                    Work::Correct(c, tx) => {
                        let _ = tx.try_send(s.correct_end(c));
                    }
                    Work::Disconnect(id, actor, reason, tx) => {
                        let _ = tx.try_send(s.enqueue_disconnect(&id, &actor, now_ms(), &reason));
                    }
                    Work::Dynamic(intent, tx) => {
                        let _ = tx.try_send(s.enqueue_dynamic(intent, now_ms()));
                    }
                    Work::Reconciliation(id, tx) => {
                        let _ = tx.try_send(s.reconciliation(&id));
                    }
                    Work::Reconciled(id, state, tx) => {
                        let _ = tx.try_send(s.reconciled(&id, &state));
                    }
                    Work::Commands(tx) => {
                        let _ = tx.try_send(s.commands());
                    }
                    Work::CommandHistory(id, tx) => {
                        let _ = tx.try_send(s.command_history(&id));
                    }
                    Work::AcknowledgedAuthorization(id, proof, tx) => {
                        let _ = tx.try_send(s.acknowledged_authorization(&id, &proof));
                    }
                    Work::CommandRequest(actor, request, tx) => {
                        let _ = tx.try_send(s.command_request(&actor, &request));
                    }
                    Work::Dispatch(tx) => {
                        let result = s
                            .commands()
                            .and_then(|commands| {
                                commands
                                    .into_iter()
                                    .map(|c| {
                                        s.session(&c.session).map(|row| row.map(|row| (c, row)))
                                    })
                                    .collect::<Result<Vec<_>>>()
                            })
                            .map(|rows| rows.into_iter().flatten().collect());
                        let _ = tx.try_send(result);
                    }
                    Work::CommandResult(c, tx) => {
                        let _ = tx.try_send(s.command_result(&c));
                    }
                    Work::Rebuild(actor, tx) => {
                        let _ = tx.try_send(s.rebuild_as(&actor, now_ms()));
                    }
                    Work::Record(..) | Work::Stop(..) => unreachable!(),
                }
            } else {
                match work {
                    Work::Grant(_, tx) | Work::Balances(_, tx) => unavailable(tx),
                    Work::Configure(config, b, tx) => {
                        if config.queue_count == settings.queue_count {
                            settings = config;
                            budgets = b;
                        }
                        unavailable(tx);
                    }
                    Work::Page(_, _, tx) => unavailable(tx),
                    Work::Session(_, _, tx) => unavailable(tx),
                    Work::History(_, _, _, tx) => unavailable(tx),
                    Work::Annotate(_, tx)
                    | Work::Bind(_, tx)
                    | Work::Reconciled(_, _, tx)
                    | Work::CommandResult(_, tx)
                    | Work::Rebuild(_, tx)
                    | Work::Correct(_, tx) => unavailable(tx),
                    Work::Disconnect(_, _, _, tx) => unavailable(tx),
                    Work::Dynamic(_, tx) => unavailable(tx),
                    Work::Reconciliation(_, tx) => unavailable(tx),
                    Work::Commands(tx) => unavailable(tx),
                    Work::CommandHistory(_, tx) => unavailable(tx),
                    Work::AcknowledgedAuthorization(_, _, tx) => unavailable(tx),
                    Work::CommandRequest(_, _, tx) => unavailable(tx),
                    Work::Dispatch(tx) => unavailable(tx),
                    Work::Record(..) | Work::Stop(..) => unreachable!(),
                }
            }
        }
        if last_maintenance.elapsed() >= Duration::from_secs(5) {
            if let Some(s) = store.as_mut() {
                let result = s
                    .maintain(now_ms())
                    .and_then(|_| {
                        if settings.enabled {
                            s.enforce(now_ms()).map(|_| ())
                        } else {
                            Ok(())
                        }
                    })
                    .and_then(|_| s.capacity());
                if let Ok(mut state) = status.lock() {
                    state.available = result.is_ok();
                    state.last_error = result.as_ref().err().map(ToString::to_string);
                    state.health = s.health().ok();
                }
            }
            last_maintenance = Instant::now();
        }
    }
}
