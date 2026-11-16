//! Local read-only status, authorized with the kernel-attested peer token.
use crate::{
    model::{Value, ROOT},
    runtime::SERVICE_SID,
    status::{Status, MAX_REPLY, REQUEST, SOCKET},
};
use peios::{
    access::AccessCheck,
    security::{sddl, AccessMask, GenericMapping},
    token::Token,
};
use std::{
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::{
            fs::FileTypeExt,
            net::{UnixListener, UnixStream},
        },
    },
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

fn query_allowed(stream: &UnixStream) -> bool {
    let configured = (|| -> io::Result<_> {
        use peios::registry::{Data, Key, KeyAccess, OpenFlags};
        let key = match Key::open(
            None,
            &format!("{ROOT}\\Settings"),
            KeyAccess::QUERY_VALUE,
            OpenFlags::empty(),
        ) {
            Ok(key) => key,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return sddl::parse("O:SYG:SYD:(A;;0x1;;;SY)(A;;0x1;;;BA)").map_err(Into::into)
            }
            Err(error) => return Err(error.into()),
        };
        match key.query_value(b"StatusSecurity", None) {
            Ok(v) => match Data::decode(v.ty, &v.data) {
                Data::Sz(v) => super::configuration::descriptor(&Value::Text(v)),
                Data::Binary(v) => super::configuration::descriptor(&Value::Bytes(v)),
                _ => Err(io::Error::other("invalid StatusSecurity")),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                sddl::parse("O:SYG:SYD:(A;;0x1;;;SY)(A;;0x1;;;BA)").map_err(Into::into)
            }
            Err(e) => Err(e.into()),
        }
    })();
    let Ok(sd) = configured else {
        return false;
    };
    let Ok(token) = Token::open_peer(stream.as_fd()) else {
        return false;
    };
    AccessCheck::new(
        &sd,
        AccessMask::from_bits_retain(1),
        GenericMapping::new(1, 0, 0, 1),
    )
    .token(token.as_fd())
    .check()
    .is_ok_and(|r| r.allowed)
}
fn protect(path: &std::path::Path, directory: bool) -> io::Result<()> {
    // The runtime directory stays service-owned. Other callers can traverse it
    // to connect; status authorization is a separate real-token access check.
    let rights = if directory { "GX" } else { "GRGWGX" };
    let sd=sddl::parse(&format!("O:{SERVICE_SID}G:{SERVICE_SID}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{SERVICE_SID})(A;;{rights};;;WD)")).map_err(io::Error::from)?;
    peios::file::set_sd(None, path, peios::file::SecInfo::DACL, &sd, 0).map_err(Into::into)
}
pub fn serve(status: Arc<Mutex<Status>>) -> io::Result<()> {
    let path = std::path::Path::new(SOCKET);
    let directory = path.parent().unwrap();
    // peinit provisions RuntimeDirectories=radiusd under the service identity.
    protect(directory, true)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(io::Error::other("status endpoint is not a socket")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    protect(path, false)?;
    // One bounded worker; slow management clients cannot block authentication
    // or cause unbounded threads. Kernel backlog bounds queued connections.
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let mut request = vec![0; REQUEST.len()];
            if stream.read_exact(&mut request).is_err()
                || request != REQUEST
                || !query_allowed(&stream)
            {
                continue;
            }
            let snapshot = match status.lock() {
                Ok(v) => v.clone(),
                Err(_) => continue,
            };
            if let Ok(bytes) = serde_json::to_vec(&snapshot) {
                if bytes.len() <= MAX_REPLY {
                    let _ = stream.write_all(&bytes);
                }
            }
        }
    });
    Ok(())
}
pub fn query() -> io::Result<Status> {
    let mut stream = UnixStream::connect(SOCKET)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot connect to radiusd status: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let peer = Token::open_peer(stream.as_fd()).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot identify radiusd status peer: {e}"),
        )
    })?;
    if peer.user().map_err(io::Error::from)?
        != SERVICE_SID
            .parse::<peios::security::Sid>()
            .map_err(io::Error::from)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "status endpoint is not radiusd",
        ));
    }
    stream.write_all(REQUEST)?;
    let mut bytes = Vec::new();
    stream.take(MAX_REPLY as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "radiusd did not authorize the status query",
        ));
    }
    if bytes.len() > MAX_REPLY {
        return Err(io::Error::other("status reply exceeds limits"));
    }
    let status: Status = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if status.version != 1 {
        return Err(io::Error::other("unsupported status protocol version"));
    }
    Ok(status)
}
