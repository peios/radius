use peios::{
    security::Sid,
    token::{Token, TokenAccess},
};
use radiusd::{
    driver::Driver,
    native::{
        authentication::Auth,
        configuration::{watch, Update},
        events::Sink,
    },
};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
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
        return Err("radiusd takes its configuration from the Registry; no credential CLI arguments are accepted".into());
    }
    let actor = Token::open_self(false, TokenAccess::QUERY)
        .map_err(|error| format!("cannot query service token: {error}"))?
        .user()
        .map_err(|error| format!("cannot read service identity: {error}"))?;
    if actor != radiusd::config::SERVICE_SID.parse::<Sid>()? {
        return Err("radiusd requires its distinct Identity=Service account".into());
    }
    let updates = watch();
    let config = match updates.recv()? {
        Update::Pending => match updates.recv()? {
            Update::Valid(config) => config,
            _ => return Err("invalid initial RADIUS configuration".into()),
        },
        Update::Valid(config) => config,
        _ => return Err("invalid initial RADIUS configuration".into()),
    };
    let bound = sockets(&config.listeners, &[])
        .map_err(|error| format!("cannot open configured listeners: {error}"))?;
    let mut sink = Sink::new(bound, actor)?;
    let mut driver = Driver::new(config.clone(), Auth).map_err(io::Error::other)?;
    let mut active = config;
    sink.configuration(true);
    // Peinit's normal service-manager notification interface.
    ready().map_err(|error| format!("cannot notify service readiness: {error}"))?;
    let mut valid = true;
    let mut bytes = [0u8; 65536];
    loop {
        // A bounded channel keeps configuration and key material bounded.
        for _ in 0..4 {
            match updates.try_recv() {
                Ok(Update::Pending) => driver.pause(),
                Ok(Update::Invalid) => {
                    driver.pause();
                    if valid {
                        sink.configuration(false);
                        valid = false;
                    }
                }
                Ok(Update::Valid(config)) => match sockets(&config.listeners, &sink.sockets) {
                    Ok(sockets) => {
                        driver
                            .activate(Arc::clone(&config))
                            .map_err(io::Error::other)?;
                        sink.sockets = sockets;
                        active = config;
                        valid = true;
                        sink.configuration(true);
                    }
                    Err(_) => {
                        driver.pause();
                        valid = false;
                        sink.configuration(false);
                        sink.warning("configured listener could not be bound");
                    }
                },
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("configuration worker stopped".into())
                }
            }
        }
        let now = Instant::now();
        for listener in 0..sink.sockets.len() {
            // Fairness: a flooding socket cannot prevent expiry/backend work.
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
        // Native libauth step is nonblocking. This bounds readiness latency
        // without a thread or blocking wait per password verification.
        std::thread::sleep(Duration::from_millis(5));
        let _ = &active;
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
