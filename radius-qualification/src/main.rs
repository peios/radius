//! Developer entrypoint. Every workload is bounded and uses synthetic identities.
mod faults;
use radius_qualification::{
    load::{self, Options},
    Result,
};
use std::io::Read;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("radius-qualify: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return Err("expected auth, accounting, failures, or replay (see --help)".into());
    };
    if mode == "internal-storage-child" {
        let parent = PathBuf::from(args.next().ok_or("missing scratch parent")?);
        let kind = args.next().ok_or("missing fault kind")?;
        let point: usize = args.next().ok_or("missing fault point")?.parse()?;
        return faults::child(&parent, &kind, point);
    }
    if matches!(mode.as_str(), "--help" | "help") {
        println!("Usage: radius-qualify auth|accounting [--requests N] [--clients N]\n  [--concurrency N] [--attempts N] [--per-client N] [--queue N]\n  [--batch N] [--batch-ms N] [--allow-overload] [--scratch-parent DIR]\nradius-qualify failures [--scratch-parent DIR]\nradius-qualify replay packets|engine_sequences|driver_sequences|ledger_sequences|control_sequences FILE...\n\nSynthetic component qualification only. No native services or external sockets.\nResults are JSON; databases are created exclusively and removed on completion.");
        return Ok(());
    }
    if mode == "replay" {
        let target = args.next().ok_or("missing replay target")?;
        let limit = match target.as_str() {
            "packets" => 8192,
            "engine_sequences" => 4096,
            "driver_sequences" => 2048,
            "ledger_sequences" => 1024,
            "control_sequences" => 1024,
            _ => return Err("unknown replay target".into()),
        };
        let mut count = 0;
        for file in args {
            let mut data = Vec::new();
            std::fs::File::open(file)?
                .take(limit + 1)
                .read_to_end(&mut data)?;
            if data.len() as u64 > limit {
                return Err("replay input exceeds target limit".into());
            }
            match target.as_str() {
                "packets" => radius_qualification::campaign::packets(&data),
                "engine_sequences" => radius_qualification::campaign::engine_sequences(&data),
                "driver_sequences" => radius_qualification::campaign::driver_sequences(&data),
                "ledger_sequences" => radius_qualification::campaign::ledger_sequences(&data),
                "control_sequences" => radius_qualification::campaign::control_sequences(&data),
                _ => return Err("unknown replay target".into()),
            }
            count += 1;
        }
        if count == 0 {
            return Err("no replay inputs supplied".into());
        }
        println!(
            "{}",
            serde_json::json!({"target": target, "replayed": count})
        );
        return Ok(());
    }
    let mut options = Options::default();
    let mut parent = std::env::temp_dir();
    while let Some(arg) = args.next() {
        if arg == "--allow-overload" {
            options.allow_overload = true;
            continue;
        }
        let value = args.next().ok_or("option requires a value")?;
        match arg.as_str() {
            "--requests" => options.requests = value.parse()?,
            "--clients" => options.clients = value.parse()?,
            "--concurrency" => options.concurrency = value.parse()?,
            "--attempts" => options.attempts = value.parse()?,
            "--per-client" => options.per_client = value.parse()?,
            "--queue" => options.queue = value.parse()?,
            "--batch" => options.batch = value.parse()?,
            "--batch-ms" => options.batch_ms = value.parse()?,
            "--scratch-parent" => parent = value.into(),
            _ => return Err("unknown qualification option".into()),
        }
    }
    match mode.as_str() {
        "auth" => println!(
            "{}",
            serde_json::to_string(&load::authentication(options)?)?
        ),
        "accounting" => println!(
            "{}",
            serde_json::to_string(&load::accounting(options, &parent)?)?
        ),
        "failures" => println!("{}", faults::run(&parent)?),
        _ => return Err("unknown qualification workload".into()),
    }
    Ok(())
}
