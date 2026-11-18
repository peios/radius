//! One local RADIUS administration program, terminal commands or --window.
mod cli;
#[cfg(feature = "window")]
mod window;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--window"] {
        #[cfg(feature = "window")]
        std::process::exit(window::open());
        #[cfg(not(feature = "window"))]
        {
            eprintln!("radius: this build does not include GXWI; build with the window feature");
            std::process::exit(1);
        }
    }
    let json = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--json");
    if args.iter().any(|s| matches!(s.as_str(), "--help" | "-h")) || args == ["help"] {
        print!("{}", cli::HELP);
        return;
    }
    let result = if args.first().map(String::as_str) == Some("diagnostics")
        && args.get(1).map(String::as_str) == Some("follow")
    {
        #[cfg(feature = "native")]
        {
            cli::follow_diagnostics(&args[2..], json).map(|()| serde_json::Value::Null)
        }
        #[cfg(not(feature = "native"))]
        {
            cli::run(&args)
        }
    } else if json
        && matches!(
            args.iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            ["client", "secret", _, "show"]
        )
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secret show writes raw bytes; omit --json",
        ))
    } else {
        cli::run(&args)
    };
    match result {
        Ok(value) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&value).expect("structured result serializes")
                );
            } else {
                cli::print_human(&value);
            }
        }
        Err(error) => {
            let (code, tag) = match error.kind() {
                std::io::ErrorKind::InvalidInput => (64, "invalid-argument"),
                std::io::ErrorKind::PermissionDenied => (3, "permission-denied"),
                std::io::ErrorKind::NotFound => (4, "not-found"),
                std::io::ErrorKind::InvalidData => (5, "invalid-configuration"),
                _ => (1, "failed"),
            };
            if json {
                eprintln!(
                    "{}",
                    serde_json::json!({"error":{"code":tag,"message":error.to_string(),"issues":error.get_ref().and_then(|e|e.downcast_ref::<cli::CheckIssues>()).map(|e|&e.0)}})
                );
            } else {
                eprintln!("radius: {error}");
            }
            std::process::exit(code);
        }
    }
}
