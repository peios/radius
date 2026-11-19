//! Read eventd as the real caller; never proxy a privileged RADIUS snapshot.
use crate::diagnostics::{
    self as model, Filter, Projection, Record, Settings, View, ATTEMPT, OPERATION,
};
use eventd_client::{
    text,
    wire::{Connection, Response},
    Value,
};
use peios::registry::{Data, Key, KeyAccess, OpenFlags};
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const FIELDS: &[&str] = &[
    "event.time",
    "event.type",
    "event.boot.guid",
    "event.cpu",
    "event.sequence",
    "emitter.class",
    "emitter.token.guid",
    "emitter.true-token.guid",
    "emitter.process.guid",
    "source.token.sid",
    "subject.token.sid",
    ATTEMPT,
    OPERATION,
    "object.radiusd.progress.sequence",
    "object.radiusd.progress.stage",
    "object.radiusd.progress.result",
    "object.radiusd.last-stage",
    "object.radiusd.method",
    "object.radiusd.elapsed-ms",
    "object.radiusd.retransmissions",
    "object.radiusd.listener",
    "object.radiusd.listener-index",
    "source.address",
    "source.radiusd.username",
    "source.radiusd.station",
    "object.account.sid",
    "object.radiusd.canonical-name",
    "object.radiusd.client.configuration-id",
    "object.radiusd.client.name",
    "object.radiusd.network.name",
    "object.radiusd.authentication-profile.name",
    "object.radiusd.assignment.profile.name",
    "object.radiusd.assignment.rule.name",
    "object.radiusd.network.configuration-id",
    "object.radiusd.authentication-profile.id",
    "object.radiusd.config.fingerprint",
    "object.radiusd.config.saved-fingerprint",
    "object.radiusd.assignment.rule.id",
    "object.radiusd.assignment.profile.id",
    "object.radiusd.assignment.fingerprint",
    "object.radiusd.assignment.vlan",
    "outcome.detail",
    "object.radiusd.reply",
    "outcome.success",
    "outcome.reason",
    "object.radiusd.diagnostics.truncated",
    "object.radiusd.drops.count",
    "object.radiusd.diagnostics.emitted",
    "object.radiusd.diagnostics.failed",
    "object.radiusd.diagnostics.suppressed",
    "object.radiusd.diagnostics.disabled",
    "object.radiusd.diagnostics.report-seconds",
];
fn bad(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s.into())
}
fn query_error(s: impl ToString) -> io::Error {
    io::Error::other(s.to_string())
}
pub fn settings() -> Settings {
    // Event access does not require configuration-read permission. Missing or
    // unreadable settings use conservative client bounds, not another identity.
    let read = (|| -> io::Result<_> {
        let key = Key::open(
            None,
            &format!("{}\\Settings", crate::model::ROOT),
            KeyAccess::QUERY_VALUE,
            OpenFlags::empty(),
        )?;
        let mut stored = crate::model::Stored::default();
        for (name, _, _, _) in model::KNOBS {
            if let Ok(value) = key.query_value(name.as_bytes(), None) {
                if let Data::Dword(value) = Data::decode(value.ty, &value.data) {
                    stored
                        .settings
                        .insert((*name).into(), crate::model::Value::Number(value));
                }
            }
        }
        Settings::read(&stored).map_err(bad)
    })();
    read.unwrap_or_default()
}
fn socket_path() -> PathBuf {
    (|| -> Option<_> {
        let key = Key::open(
            None,
            "Machine\\System\\eventd",
            KeyAccess::QUERY_VALUE,
            OpenFlags::empty(),
        )
        .ok()?;
        let value = key.query_value(b"QuerySocketPath", None).ok()?;
        match Data::decode(value.ty, &value.data) {
            Data::Sz(path) => Some(PathBuf::from(path)),
            _ => None,
        }
    })()
    .unwrap_or_else(|| eventd_client::DEFAULT_SOCKET.into())
}
fn query(filter: &Filter, settings: &Settings, stream: bool) -> io::Result<String> {
    filter.validate(settings).map_err(bad)?;
    let mut q = format!(
        "EVENTS radiusd.* SINCE {}s ago TAKE {} SELECT {}",
        filter.seconds.unwrap_or(settings.get("LookbackSeconds")),
        settings.get("MaxRecords"),
        FIELDS.join(", ")
    );
    let mut predicates = Vec::new();
    // Personal filters apply after authorized records have been grouped into
    // attempts; applying username per event would hide anonymous TLS stages.
    if let Some(id) = &filter.attempt {
        predicates.push(format!(
            "{ATTEMPT} == {}",
            text::binary(&model::parse_id(id).ok_or_else(|| bad("invalid attempt identifier"))?)
        ));
    }
    if !predicates.is_empty() {
        q.push_str(&format!(" WHERE {}", predicates.join(" AND ")));
    }
    if stream {
        q.push_str(" STREAM");
    }
    Ok(q)
}

struct DeadlineSocket {
    socket: UnixStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "diagnostic query deadline expired",
            ))
        } else {
            Ok(remaining)
        }
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(self.remaining()?.min(Duration::from_secs(5))))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
fn connect(settings: &Settings, seconds: u32) -> io::Result<Connection<DeadlineSocket>> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    if let Err(error) = socket.connect(&socket2::SockAddr::unix(socket_path())?) {
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "eventd connection timed out",
                ));
            }
            let mut fd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: poll borrows one live pollfd and this socket remains owned.
            let result = unsafe {
                libc::poll(
                    &mut fd,
                    1,
                    remaining.as_millis().min(i32::MAX as u128).max(1) as i32,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result > 0 {
                if let Some(error) = socket.take_error()? {
                    return Err(error);
                }
                break;
            }
        }
    }
    socket.set_nonblocking(false)?;
    Ok(Connection::bounded(
        DeadlineSocket {
            socket: socket.into(),
            deadline: Instant::now() + Duration::from_secs(u64::from(seconds)),
        },
        settings.get("MaxViewBytes") as usize,
    ))
}
/// Hint only: every actual control decision uses a fresh authoritative read.
/// Query complete results under radiusd's ordinary event permissions.
pub(super) fn identity_change_hint() -> io::Result<Option<[u8; 32]>> {
    let stored = crate::model::Stored {
        settings: [(
            "DiagnosticsMaxViewBytes".into(),
            crate::model::Value::Number(65536),
        )]
        .into(),
        ..Default::default()
    };
    let settings = Settings::read(&stored).map_err(bad)?;
    let mut connection = connect(&settings, 1)?;
    let types = [
        "lpsd.credential.changed",
        "lpsd.account.created",
        "lpsd.account.deleted",
        "lpsd.account.modified",
        "lpsd.group.deleted",
        "lpsd.group.member.added",
        "lpsd.group.member.removed",
    ];
    let filter = types
        .iter()
        .map(|name| format!("event.type == {}", text::string(name)))
        .collect::<Vec<_>>()
        .join(" OR ");
    connection.send_query(&format!("EVENTS lpsd.* SINCE 2s ago TAKE 1 WHERE {filter} SELECT event.time, event.boot.guid, event.cpu, event.sequence, event.type")).map_err(query_error)?;
    let mut fingerprint = None;
    loop {
        match connection.next_response().map_err(query_error)? {
            Response::Records(records) if records.len() <= 1 && fingerprint.is_none() => {
                if !records.is_empty() {
                    fingerprint = Some(
                        ring::digest::digest(
                            &ring::digest::SHA256,
                            format!("{records:?}").as_bytes(),
                        )
                        .as_ref()
                        .try_into()
                        .map_err(query_error)?,
                    );
                }
            }
            Response::End => return Ok(fingerprint),
            _ => return Err(query_error("identity hint unavailable")),
        }
    }
}
fn convert(record: eventd_client::Record) -> Record {
    record
        .into_iter()
        .filter_map(|(key, value)| {
            if !FIELDS.contains(&key.as_str()) {
                return None;
            }
            let value = match value {
                Value::String(s) if s.len() <= 4096 => serde_json::Value::String(s),
                Value::Binary(b) if b.len() <= 256 => serde_json::Value::String(model::hex(&b)),
                Value::Bool(v) => v.into(),
                Value::Signed(v) => v.into(),
                Value::Unsigned(v) => v.into(),
                _ => return None,
            };
            Some((key, value))
        })
        .collect()
}

pub fn read(filter: &Filter) -> io::Result<View> {
    let settings = settings();
    let mut connection = connect(&settings, 5)?;
    finite(&mut connection, filter, &settings)
}
fn finite<S: Read + Write>(
    connection: &mut Connection<S>,
    filter: &Filter,
    settings: &Settings,
) -> io::Result<View> {
    connection
        .send_query(&query(filter, settings, false)?)
        .map_err(query_error)?;
    let mut projection = Projection::new(settings.clone());
    let mut count = 0usize;
    loop {
        match connection.next_response().map_err(query_error)? {
            Response::Records(records) => {
                for record in records {
                    count += 1;
                    projection.insert(convert(record));
                }
            }
            Response::End => {
                projection.truncated |= count >= settings.get("MaxRecords") as usize;
                return Ok(projection
                    .view(
                        false,
                        "Query complete; absence of records is not proof of no activity",
                    )
                    .filtered(filter));
            }
            Response::Error(message) => return Err(query_error(message)),
            Response::Watch => return Err(query_error("unexpected streaming query response")),
        }
    }
}

/// Read only exact authd operation links visible in a diagnostic attempt.
pub fn authority(operation: &str) -> io::Result<Vec<Record>> {
    let id = model::parse_id(operation).ok_or_else(|| bad("invalid authd operation identifier"))?;
    let settings = settings();
    let mut connection = connect(&settings, 5)?;
    let sid = crate::runtime::SERVICE_SID
        .parse::<peios::security::Sid>()
        .map_err(query_error)?;
    let q = format!(
        "EVENTS authd.authentication.attempted SINCE {}s ago TAKE 32 WHERE {OPERATION} == {} AND source.token.sid == {} SELECT {}",
        settings.get("MaxLookbackSeconds"),
        text::binary(&id),
        text::binary(sid.as_bytes()),
        FIELDS.join(", ")
    );
    connection.send_query(&q).map_err(query_error)?;
    let mut result = Vec::new();
    loop {
        match connection.next_response().map_err(query_error)? {
            Response::Records(records) => {
                if result.len() + records.len() > 32 {
                    return Err(query_error("authority result exceeds bound"));
                }
                result.extend(records.into_iter().map(convert));
            }
            Response::End => return Ok(result),
            Response::Error(message) => return Err(query_error(message)),
            Response::Watch => return Err(query_error("unexpected streaming authority result")),
        }
    }
}

struct State {
    projection: Projection,
    following: bool,
    status: String,
}
/// A reconnect snapshot remains private until eventd confirms its Watch boundary.
/// Publishing replaces prior evidence rather than merging fields that may no
/// longer be readable under the caller's current permissions.
struct StreamSnapshot {
    initial: Projection,
    count: usize,
    live: bool,
    settings: Settings,
    gap: bool,
}
impl StreamSnapshot {
    fn new(settings: &Settings, gap: bool) -> Self {
        let mut initial = Projection::new(settings.clone());
        initial.possible_gap = gap;
        Self {
            initial,
            count: 0,
            live: false,
            settings: settings.clone(),
            gap,
        }
    }
    fn consume(&mut self, response: Response, state: &Mutex<State>) -> io::Result<()> {
        match response {
            Response::Records(records) => {
                if self.live {
                    let mut state = state
                        .lock()
                        .map_err(|_| query_error("diagnostic state unavailable"))?;
                    for record in records {
                        state.projection.insert(convert(record));
                    }
                } else {
                    self.count = self.count.saturating_add(records.len());
                    for record in records {
                        self.initial.insert(convert(record));
                    }
                }
                Ok(())
            }
            Response::Watch if !self.live => {
                self.initial.truncated |= self.count >= self.settings.get("MaxRecords") as usize;
                let mut state = state
                    .lock()
                    .map_err(|_| query_error("diagnostic state unavailable"))?;
                state.projection =
                    std::mem::replace(&mut self.initial, Projection::new(self.settings.clone()));
                state.following = true;
                state.status = if self.gap {
                    "Following; a previous interruption may have left gaps"
                } else {
                    "Following events collected by eventd"
                }
                .into();
                self.live = true;
                Ok(())
            }
            Response::Error(message) => Err(query_error(message)),
            _ => Err(query_error("event stream ended unexpectedly")),
        }
    }
}
pub struct Monitor {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    socket: Arc<Mutex<Option<UnixStream>>>,
    filter: Filter,
}
impl Monitor {
    pub fn start(filter: Filter) -> io::Result<Self> {
        use peios::token::{Token, TokenAccess};
        // CLONE_THREAD deliberately restores the process primary identity.
        // Normal callers need no token-duplication/impersonation rights. Refuse
        // an impersonated host rather than silently using its primary token.
        // Such callers can use synchronous history queries on their own thread.
        let caller = Token::open_self(false, TokenAccess::QUERY)?.guid()?;
        let primary = Token::open_self(true, TokenAccess::QUERY)?.guid()?;
        if caller != primary {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Live diagnostics require the caller's own process; use a finite history query while impersonating",
            ));
        }
        let settings = settings();
        filter.validate(&settings).map_err(bad)?;
        let state = Arc::new(Mutex::new(State {
            projection: Projection::new(settings.clone()),
            following: false,
            status: "Connecting to eventd".into(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(None));
        let monitor = Self {
            state: state.clone(),
            stop: stop.clone(),
            socket: socket.clone(),
            filter: filter.clone(),
        };
        thread::spawn(move || {
            let mut gap = false;
            while !stop.load(Ordering::Relaxed) {
                if Token::open_self(false, TokenAccess::QUERY)
                    .and_then(|t| t.guid())
                    .ok()
                    != Some(caller)
                {
                    if let Ok(mut state) = state.lock() {
                        state.following = false;
                        state.status =
                            "Diagnostic caller identity changed; start another query".into();
                        state.projection.possible_gap = true;
                    }
                    return;
                }
                let mut connection = match connect(&settings, settings.get("StreamSeconds")) {
                    Ok(c) => c,
                    Err(error) => {
                        if let Ok(mut state) = state.lock() {
                            state.following = false;
                            state.status = format!("Disconnected: {error}");
                            state.projection.possible_gap = true;
                        }
                        gap = true;
                        for _ in 0..settings.get("ReconnectSeconds") * 10 {
                            if stop.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                };
                if let Ok(mut active) = socket.lock() {
                    *active = connection.stream().socket.try_clone().ok();
                }
                let mut snapshot = StreamSnapshot::new(&settings, gap);
                let started = Instant::now();
                let mut renewed = filter.clone();
                if gap {
                    renewed.seconds = Some(
                        renewed
                            .seconds
                            .unwrap_or(settings.get("LookbackSeconds"))
                            .max(settings.get("BackfillSeconds"))
                            .min(settings.get("MaxLookbackSeconds")),
                    );
                }
                let result = (|| -> io::Result<()> {
                    connection
                        .send_query(&query(&renewed, &settings, true)?)
                        .map_err(query_error)?;
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        if started.elapsed()
                            >= Duration::from_secs(u64::from(settings.get("StreamSeconds")))
                        {
                            return Err(query_error("Refreshing event stream; possible gap"));
                        }
                        snapshot
                            .consume(connection.next_response().map_err(query_error)?, &state)?;
                    }
                })();
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                gap = true;
                if let Ok(mut state) = state.lock() {
                    state.following = false;
                    state.projection.possible_gap = true;
                    state.status = format!(
                        "Disconnected: {}",
                        result
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "stream ended".into())
                    );
                }
                if let Ok(mut active) = socket.lock() {
                    *active = None;
                }
                for _ in 0..settings.get("ReconnectSeconds") * 10 {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
        Ok(monitor)
    }
    pub fn snapshot(&self) -> View {
        self.state
            .lock()
            .map(|s| {
                s.projection
                    .view(s.following, &s.status)
                    .filtered(&self.filter)
            })
            .unwrap_or_else(|_| View {
                status: "Diagnostic reader unavailable".into(),
                possible_gap: true,
                ..Default::default()
            })
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(active) = self.socket.lock() {
            if let Some(socket) = active.as_ref() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(sequence: u64, username: Option<&str>) -> eventd_client::Record {
        let mut record: eventd_client::Record = [
            (
                "event.type".into(),
                Value::String("radiusd.exchange.started".into()),
            ),
            (ATTEMPT.into(), Value::Binary(vec![7; 16])),
            (model::SEQUENCE.into(), Value::Unsigned(sequence)),
        ]
        .into();
        if let Some(username) = username {
            record.insert(
                "source.radiusd.username".into(),
                Value::String(username.into()),
            );
        }
        record
    }
    #[test]
    fn reconnect_publishes_only_complete_authorized_snapshots_and_deduplicates_overlap() {
        let settings = Settings::default();
        let state = Mutex::new(State {
            projection: Projection::new(settings.clone()),
            following: false,
            status: String::new(),
        });
        let mut stream = StreamSnapshot::new(&settings, false);
        stream
            .consume(Response::Records(vec![evidence(1, Some("jack"))]), &state)
            .unwrap();
        assert!(state
            .lock()
            .unwrap()
            .projection
            .view(false, "")
            .attempts
            .is_empty());
        stream.consume(Response::Watch, &state).unwrap();
        stream
            .consume(Response::Records(vec![evidence(1, Some("jack"))]), &state)
            .unwrap();
        assert_eq!(
            state.lock().unwrap().projection.view(true, "").attempts[0]
                .stages
                .len(),
            1
        );
        assert!(stream.consume(Response::End, &state).is_err());

        let mut failed = StreamSnapshot::new(&settings, true);
        failed
            .consume(
                Response::Records(vec![evidence(2, Some("partial"))]),
                &state,
            )
            .unwrap();
        assert!(failed
            .consume(Response::Error("not authorized".into()), &state)
            .is_err());
        assert_eq!(
            state.lock().unwrap().projection.view(false, "").attempts[0].summary
                ["source.radiusd.username"],
            "jack"
        );

        let mut reconnect = StreamSnapshot::new(&settings, true);
        reconnect
            .consume(Response::Records(vec![evidence(1, None)]), &state)
            .unwrap();
        reconnect.consume(Response::Watch, &state).unwrap();
        let view = state.lock().unwrap().projection.view(true, "");
        assert!(!view.attempts[0]
            .summary
            .contains_key("source.radiusd.username"));
        assert!(view.possible_gap);
        assert!(!view.attempts[0].outcome_available);
        assert!(reconnect.consume(Response::Watch, &state).is_err());
    }
    struct ReplyIo(std::io::Cursor<Vec<u8>>);
    impl Read for ReplyIo {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.0.read(out)
        }
    }
    impl Write for ReplyIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn frame(writer: peios::msgpack::Writer) -> Vec<u8> {
        let bytes = writer.to_bytes().unwrap();
        let mut result = (bytes.len() as u32).to_le_bytes().to_vec();
        result.extend(bytes);
        result
    }
    #[test]
    fn a_finite_query_discards_initial_records_if_the_server_later_fails() {
        for fails in [false, true] {
            let mut record = peios::msgpack::Writer::new();
            record
                .write_map(2)
                .write_str("status")
                .write_str("ok")
                .write_str("records")
                .write_array(1)
                .write_map(4)
                .write_str("event.type")
                .write_str("radiusd.exchange.progressed")
                .write_str(ATTEMPT)
                .write_bin(&[7; 16])
                .write_str(model::SEQUENCE)
                .write_uint(1)
                .write_str(model::STAGE)
                .write_str("tls");
            let mut end = peios::msgpack::Writer::new();
            if fails {
                end.write_map(2)
                    .write_str("status")
                    .write_str("error")
                    .write_str("error")
                    .write_str("storage unavailable");
            } else {
                end.write_map(1).write_str("status").write_str("end");
            }
            let mut bytes = frame(record);
            bytes.extend(frame(end));
            let mut connection = Connection::bounded(ReplyIo(std::io::Cursor::new(bytes)), 65536);
            let result = finite(&mut connection, &Filter::default(), &Settings::default());
            if fails {
                assert!(result.is_err());
            } else {
                let view = result.unwrap();
                assert_eq!(view.attempts.len(), 1);
                assert!(!view.attempts[0].outcome_available);
            }
        }
    }
    #[test]
    fn supplied_filter_text_remains_one_literal_and_does_not_widen_the_query() {
        let filter = Filter {
            username: Some("jack\" OR outcome.success == true".into()),
            ..Default::default()
        };
        let q = query(&filter, &Settings::default(), false).unwrap();
        assert!(!q.contains("jack"));
        assert!(q.contains("TAKE 4096"));
    }
    #[test]
    fn conversion_does_not_import_claim_snapshots_or_unknown_payload_fields() {
        let record = convert(
            [
                ("secret".into(), Value::String("never retained".into())),
                ("outcome.success".into(), Value::Bool(true)),
            ]
            .into(),
        );
        assert_eq!(record.len(), 1);
    }
}
