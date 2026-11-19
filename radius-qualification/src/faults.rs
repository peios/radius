//! SQLite VFS fault injection lives only in this developer subprocess, never in
//! production Store. Original VFS methods are preserved for every open file.
use radius_accounting::{model::Settings, store::Store};
use radius_qualification::{protocol, Result, Scratch};
use rusqlite::ffi;
use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void},
    io::{BufRead, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicIsize, AtomicPtr, AtomicUsize, Ordering},
        mpsc, Mutex,
    },
    time::{Duration, Instant},
};

static ORIGINAL: AtomicPtr<ffi::sqlite3_vfs> = AtomicPtr::new(std::ptr::null_mut());
// Addresses, not references: SQLite owns files, and each shim table is freed on
// xClose. The mutex is released before calling back into the original VFS.
static FILES: Mutex<BTreeMap<usize, (usize, usize)>> = Mutex::new(BTreeMap::new());
static MODE: AtomicUsize = AtomicUsize::new(0);
static LEFT: AtomicIsize = AtomicIsize::new(-1);
static TRIGGERED: AtomicUsize = AtomicUsize::new(0);

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn original(file: *mut ffi::sqlite3_file) -> *const ffi::sqlite3_io_methods {
    FILES.lock().unwrap().get(&(file as usize)).unwrap().0 as *const _
}
fn trip(sync: bool) -> bool {
    let mode = MODE.load(Ordering::SeqCst);
    if mode == 0 || ((mode == 2 || mode == 4) != sync) {
        return false;
    }
    if LEFT.fetch_sub(1, Ordering::SeqCst) != 0 {
        return false;
    }
    TRIGGERED.fetch_add(1, Ordering::SeqCst);
    if mode == 4 {
        println!("CRASH-POINT");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        } // Parent SIGKILLs this child with a deadline.
    }
    true
}
unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    data: *const c_void,
    len: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    if trip(false) {
        return if MODE.load(Ordering::SeqCst) == 3 {
            ffi::SQLITE_FULL
        } else {
            ffi::SQLITE_IOERR_WRITE
        };
    }
    // SAFETY: xOpen recorded this file's valid original method table. SQLite
    // supplies exactly the original callback's pointer, length and offset.
    unsafe { ((*original(file)).xWrite.unwrap())(file, data, len, offset) }
}
unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    if trip(true) {
        return ffi::SQLITE_IOERR_FSYNC;
    }
    // SAFETY: same file/method lifetime as write; no mutex crosses the callback.
    unsafe { ((*original(file)).xSync.unwrap())(file, flags) }
}
unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    let (methods, shim) = FILES.lock().unwrap().remove(&(file as usize)).unwrap();
    let methods = methods as *const ffi::sqlite3_io_methods;
    // SAFETY: restore the original table before its owner closes the file, then
    // free our separately allocated copy exactly once. No file memory is freed.
    unsafe {
        (*file).pMethods = methods;
        let result = ((*methods).xClose.unwrap())(file);
        drop(Box::from_raw(shim as *mut ffi::sqlite3_io_methods));
        result
    }
}
unsafe extern "C" fn open(
    _: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let base = ORIGINAL.load(Ordering::SeqCst);
    // SAFETY: the process-lifetime default VFS allocated SQLite's file buffer;
    // its xOpen initializes the original table before we copy its callbacks.
    unsafe {
        let result = ((*base).xOpen.unwrap())(base, name, file, flags, out);
        if result == ffi::SQLITE_OK {
            let methods = (*file).pMethods;
            let mut shim = Box::new(std::ptr::read(methods));
            shim.xWrite = Some(write);
            shim.xSync = Some(sync);
            shim.xClose = Some(close);
            let shim = Box::into_raw(shim);
            FILES
                .lock()
                .unwrap()
                .insert(file as usize, (methods as usize, shim as usize));
            (*file).pMethods = shim;
        }
        result
    }
}
fn install() -> Result<()> {
    // SAFETY: called once before opening a database in a dedicated single-case
    // child. Original VFS and registered copy live until process exit. SQLite
    // still allocates the exact default VFS file size; we replace only methods.
    unsafe {
        let base = ffi::sqlite3_vfs_find(std::ptr::null());
        if base.is_null() {
            return Err("no SQLite VFS".into());
        }
        ORIGINAL.store(base, Ordering::SeqCst);
        let mut shim = Box::new(std::ptr::read(base));
        shim.zName = c"radius-qualification-only".as_ptr();
        shim.pNext = std::ptr::null_mut();
        shim.xOpen = Some(open);
        if ffi::sqlite3_vfs_register(Box::into_raw(shim), 1) != ffi::SQLITE_OK {
            return Err("cannot install fault fixture".into());
        }
    }
    Ok(())
}

pub fn child(parent: &Path, kind: &str, point: usize) -> Result<()> {
    if !matches!(kind, "write" | "sync" | "full" | "crash" | "post-commit") || point > 8 {
        return Err("invalid internal storage case".into());
    }
    // Never open an existing database supplied on the command line.
    let path = parent.join(format!("{kind}-{point}"));
    std::fs::create_dir(&path)?;
    install()?;
    let settings = Settings::default();
    let database = path.join("ledger.db");
    let mut store = Store::open(&database, settings.clone())?;
    store.record(&[protocol::observation(0, 1, 1_800_000_000_000)])?;
    if kind == "post-commit" {
        store.record(&[protocol::observation(1, 1, 1_800_000_001_000)])?;
        println!("CRASH-POINT");
        std::io::stdout().flush()?;
        loop {
            std::thread::park();
        }
    }
    let mode = match kind {
        "write" => 1,
        "sync" => 2,
        "full" => 3,
        "crash" => 4,
        _ => return Err("unknown fault".into()),
    };
    MODE.store(mode, Ordering::SeqCst);
    LEFT.store(point as isize, Ordering::SeqCst);
    let batch: Vec<_> = (1..=8)
        .map(|i| protocol::observation(i, 1, 1_800_000_001_000))
        .collect();
    let acknowledged = store.record(&batch).is_ok();
    MODE.store(0, Ordering::SeqCst);
    let fired = TRIGGERED.load(Ordering::SeqCst);
    drop(store);
    let mut reopened = Store::open(&database, settings)?;
    let before = reopened.health()?.observations;
    if !matches!(before, 1 | 9) || (acknowledged && before != 9) {
        return Err("partial transaction or acknowledged receipt lost".into());
    }
    reopened.record(&batch)?;
    if reopened.health()?.observations != 9 {
        return Err("retry duplicated or lost accounting records".into());
    }
    drop(reopened);
    integrity(&database)?;
    if fired != 0 && acknowledged {
        return Err("injected write/sync failure was acknowledged".into());
    }
    println!(
        "{}",
        serde_json::json!({"fault": kind, "point": point, "triggered": fired, "acknowledged": acknowledged, "recovered": true})
    );
    Ok(())
}
fn integrity(path: &Path) -> Result<()> {
    let connection = rusqlite::Connection::open(path)?;
    let checked: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if checked != "ok" {
        return Err("database integrity check failed".into());
    }
    let foreign: i64 =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })?;
    if foreign != 0 {
        return Err("database foreign key check failed".into());
    }
    Ok(())
}
pub fn run(parent: &Path) -> Result<serde_json::Value> {
    let scratch = Scratch::new(parent)?;
    let executable = std::env::current_exe()?;
    let mut cases = Vec::new();
    for (kind, points) in [
        ("write", 8),
        ("sync", 2),
        ("full", 8),
        ("crash", 1),
        ("post-commit", 1),
    ] {
        let mut triggered = 0;
        for point in 0..points {
            let mut child = ChildGuard(
                Command::new(&executable)
                    .args([
                        "internal-storage-child",
                        scratch.0.to_str().ok_or("scratch encoding")?,
                        kind,
                        &point.to_string(),
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?,
            );
            let stdout = child.0.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut case = None;
            let mut killed = false;
            while Instant::now() < deadline {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok(line)) if line == "CRASH-POINT" => {
                        child.0.kill()?;
                        killed = true;
                        triggered += 1;
                        break;
                    }
                    Ok(Ok(line)) => {
                        case = Some(serde_json::from_str::<serde_json::Value>(&line)?);
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            while child.0.try_wait()?.is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            if child.0.try_wait()?.is_none() {
                child.0.kill()?;
                if !killed {
                    let _ = child.0.wait();
                    return Err(format!("storage fault child timed out: {kind}/{point}").into());
                }
            }
            let status = child.0.wait()?;
            let mut stderr = String::new();
            child.0.stderr.take().unwrap().read_to_string(&mut stderr)?;
            reader.join().map_err(|_| "fault output reader failed")?;
            if killed {
                let database = scratch.0.join(format!("{kind}-{point}/ledger.db"));
                let mut store = Store::open(&database, Settings::default())?;
                let before = store.health()?.observations;
                let expected = if kind == "post-commit" { 2 } else { 9 };
                if kind == "post-commit" && before != 2 {
                    return Err("committed record lost after SIGKILL".into());
                }
                if kind == "crash" && !matches!(before, 1 | 9) {
                    return Err("partial crash transaction".into());
                }
                let batch: Vec<_> = (1..expected)
                    .map(|i| protocol::observation(i as usize, 1, 1_800_000_001_000))
                    .collect();
                store.record(&batch)?;
                if store.health()?.observations != expected {
                    return Err("crash retry was not idempotent".into());
                }
                drop(store);
                integrity(&database)?;
                cases.push(serde_json::json!({"fault": kind, "point": point, "killed": true, "recovered": true}));
            } else {
                if !status.success() {
                    return Err(format!("storage fault child failed: {stderr}").into());
                }
                let case = case.ok_or("missing fault result")?;
                triggered += case["triggered"].as_u64().unwrap_or(0) as usize;
                cases.push(case);
            }
        }
        if triggered == 0 {
            return Err(format!("{kind} fault did not reach its injection point").into());
        }
    }
    Ok(
        serde_json::json!({"schema": 1, "cases": cases, "power_loss": false, "injection": "child-process-SQLite-VFS-and-parent-SIGKILL", "recovered": true}),
    )
}
