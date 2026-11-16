//! Explicit, loopback-only protocol qualification harness. No production account
//! backend or service installation is supplied by this executable.
#![forbid(unsafe_code)]
use radius_core::{server_config, Admission, Binding, Client, Engine, Limits, Outcome};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    env, fs,
    io::{self, Write},
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("radius-test-server: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut address: SocketAddr = "127.0.0.1:0".parse()?;
    let mut certificates = Vec::new();
    let mut private_key = None;
    let mut secret = None;
    let mut password = None;
    let mut username = None;
    let mut deny = false;
    let mut limits = Limits::default();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--deny" {
            deny = true;
            continue;
        }
        if arg == "--help" {
            println!(
                "Usage: radius-test-server --cert CERT.der [--cert CHAIN.der ...] --key KEY.der\n\
                --secret-file FILE --password-file FILE --user USER [--listen LOOPBACK:PORT]\n\
                [--deny] [--frame-payload BYTES] [--idle-ms MS] [--overall-ms MS]\n\
                Test fixture only. Production daemon radiusd is not implemented yet.\n\
                Secret/password files contain exact bytes, without a trailing newline."
            );
            return Ok(());
        }
        let value = args.next().ok_or("option needs a value")?;
        match arg.as_str() {
            "--listen" => address = value.parse()?,
            "--cert" => certificates.push(CertificateDer::from(fs::read(value)?)),
            "--key" => {
                private_key = Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(
                    value,
                )?)))
            }
            "--secret-file" => secret = Some(Zeroizing::new(fs::read(value)?)),
            "--password-file" => password = Some(Zeroizing::new(fs::read(value)?)),
            "--user" => username = Some(value.into_bytes()),
            "--frame-payload" => limits.frame_payload = value.parse()?,
            "--idle-ms" => limits.idle = Duration::from_millis(value.parse()?),
            "--overall-ms" => limits.overall = Duration::from_millis(value.parse()?),
            _ => return Err("unknown option (see --help)".into()),
        }
    }
    if !address.ip().is_loopback() {
        return Err("test harness requires a loopback address".into());
    }
    let secret = secret.ok_or("--secret-file is required")?;
    if !(16..=1024).contains(&secret.len()) {
        return Err("secret must have 16 to 1024 bytes".into());
    }
    let password = password.ok_or("--password-file is required")?;
    let username = username.ok_or("--user is required")?;
    let config = server_config(certificates, private_key.ok_or("--key is required")?)?;
    let mut engine = Engine::new(config, limits)?;
    let socket = UdpSocket::bind(address)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    println!("LISTEN={}", socket.local_addr()?);
    io::stdout().flush()?;
    let mut buffer = [0u8; 65536];
    loop {
        let (n, peer) = match socket.recv_from(&mut buffer) {
            Ok(packet) => packet,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                engine.expire(Instant::now());
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let binding = Binding {
            client: 1,
            trust_generation: 1,
            network: 1,
            source: peer.ip(),
        };
        let client = Client {
            binding: binding.clone(),
            secret: &secret,
            policy_generation: 1,
        };
        let outcome = engine.receive(Instant::now(), peer, client, &buffer[..n]);
        let reply = match outcome {
            Ok(Outcome::Reply(reply)) => Some(reply),
            Ok(Outcome::Verify(verification)) => {
                // This fixture does not emulate authd. Production integration
                // retains the full verified subject on this exact attempt.
                let credential_ok = bool::from(
                    verification
                        .credentials
                        .password
                        .as_slice()
                        .ct_eq(password.as_slice()),
                ) & bool::from(
                    verification
                        .credentials
                        .username
                        .as_slice()
                        .ct_eq(&username),
                );
                let decision = if credential_ok && !deny {
                    Admission::Granted
                } else {
                    Admission::Denied
                };
                let id = verification.id();
                drop(verification);
                engine
                    .finish(
                        Instant::now(),
                        id,
                        Client {
                            binding,
                            secret: &secret,
                            policy_generation: 1,
                        },
                        decision,
                    )
                    .ok()
            }
            Ok(Outcome::Drop) | Err(_) => None,
        };
        if let Some(reply) = reply {
            socket.send_to(&reply.bytes, reply.peer)?;
        }
    }
}
