use peios::{
    security::Sid,
    token::{Token, TokenAccess},
};
use radiusd::{
    driver::Driver,
    native::{
        accounting::AccountingAuth,
        configuration::{watch, Update},
        events::Sink,
    },
};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn sockets(addresses: &[SocketAddr], old: &[UdpSocket]) -> io::Result<Vec<UdpSocket>> {
    addresses
        .iter()
        .map(|address| {
            if let Some(socket) = old
                .iter()
                .find(|socket| socket.local_addr().ok() == Some(*address))
            {
                return socket.try_clone();
            }
            let domain = if address.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            if address.is_ipv6() {
                socket.set_only_v6(true)?;
            }
            socket.set_nonblocking(true)?;
            socket.bind(&(*address).into())?;
            Ok(socket.into())
        })
        .collect()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().len() != 1 {
        return Err("radiusd takes configuration from the Registry".into());
    }
    let actor = Token::open_self(false, TokenAccess::QUERY)?.user()?;
    if actor != radiusd::config::SERVICE_SID.parse::<Sid>()? {
        return Err("radiusd requires its distinct Identity=Service account".into());
    }
    let updates = watch();
    let mut sink = Sink::new(Vec::new(), actor)?;
    let accounting = radius_management::native::accounting::Service::start()?;
    let mut driver: Option<Driver<AccountingAuth>> = None;
    let status = Arc::new(Mutex::new(radius_management::status::Status::default()));
    radius_management::native::control::serve(status.clone())?;
    // Readiness means the local status service is ready. Invalid configuration
    // remains diagnosable and repairable while no authentication is admitted.
    ready()?;
    let mut announced = None;
    let mut bytes = [0u8; 65536];
    loop {
        let accounting_snapshot = accounting.snapshot();
        let mut accounting_status = accounting.ledger.snapshot();
        accounting_status.available &= accounting_snapshot.as_ref().is_some_and(|s| s.ledger_ready);
        sink.accounting(
            accounting_snapshot.is_none_or(|s| s.config.settings.enabled),
            &accounting_status,
        );
        for _ in 0..4 {
            match updates.try_recv() {
                Ok(Update::Pending) => {
                    if let Some(d) = driver.as_mut() {
                        d.pause();
                    }
                    if let Ok(mut s) = status.lock() {
                        s.state = "validating".into();
                    }
                }
                Ok(Update::Invalid { saved, issues }) => {
                    if let Some(d) = driver.as_mut() {
                        d.pause();
                    }
                    if let Ok(mut s) = status.lock() {
                        s.state = "invalid".into();
                        s.saved_fingerprint = saved;
                        s.issues = issues;
                    }
                    if announced != Some(false) {
                        sink.configuration(false);
                        announced = Some(false);
                    }
                }
                Ok(Update::Valid(config)) => {
                    let activated = sockets(&config.listeners, &sink.sockets).and_then(|sockets| {
                        if let Some(d) = driver.as_mut() {
                            d.activate(config.clone()).map_err(io::Error::other)?;
                        } else {
                            driver = Some(
                                Driver::new(
                                    config.clone(),
                                    AccountingAuth::new(accounting.clone()),
                                )
                                .map_err(io::Error::other)?,
                            );
                        }
                        Ok(sockets)
                    });
                    match activated {
                        Ok(sockets) => {
                            sink.sockets = sockets;
                            if let Ok(mut s) = status.lock() {
                                s.state = "active".into();
                                s.saved_fingerprint = Some(config.saved_fingerprint.clone());
                                s.effective_fingerprint = Some(config.saved_fingerprint.clone());
                                s.listeners =
                                    config.listeners.iter().map(ToString::to_string).collect();
                                s.issues.clear();
                            }
                            sink.configuration(true);
                            announced = Some(true);
                        }
                        Err(error) => {
                            if let Some(d) = driver.as_mut() {
                                d.pause();
                            }
                            if let Ok(mut s) = status.lock() {
                                s.state = "invalid".into();
                                s.saved_fingerprint = Some(config.saved_fingerprint.clone());
                                s.issues = vec![radius_management::model::Issue {
                                    object: "Settings".into(),
                                    field: "Listen".into(),
                                    message: format!("cannot activate configuration: {error}"),
                                }];
                            }
                            if announced != Some(false) {
                                sink.configuration(false);
                                announced = Some(false);
                            }
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("configuration worker stopped".into())
                }
            }
        }
        if let Some(driver) = driver.as_mut() {
            let now = Instant::now();
            for listener in 0..sink.sockets.len() {
                for _ in 0..32 {
                    match sink.sockets[listener].recv_from(&mut bytes) {
                        Ok((size, peer)) => {
                            driver.receive(now, listener, peer, &bytes[..size], &mut sink)
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            sink.warning("UDP receive failed");
                            break;
                        }
                    }
                }
            }
            driver.tick(Instant::now(), &mut sink);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn ready() -> io::Result<()> {
    use std::os::unix::net::UnixDatagram;
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        let socket = UnixDatagram::unbound()?;
        socket.connect(std::path::Path::new(&path))?;
        socket.send(b"READY=1")?;
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("radiusd: {error}");
        std::process::exit(1);
    }
}
