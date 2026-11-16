//! Service authority remains peinit's, independently of configuration access.
use crate::model::{Value, Values};
use peinit::client::{Command, ControlClient};
use std::io;
const KEY: &str = "Machine\\System\\Services\\radiusd";
pub fn status() -> io::Result<serde_json::Value> {
    let mut client = ControlClient::connect_default().map_err(io::Error::other)?;
    let state = client.status_of("radiusd").map_err(io::Error::other)?;
    Ok(serde_json::json!({"state":format!("{:?}",state.summary.state),"granted":state.granted}))
}
pub fn command(action: &str) -> io::Result<()> {
    let cmd = match action {
        "start" => Command::Start,
        "stop" => Command::Stop,
        "restart" => Command::Restart,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown service action",
            ))
        }
    };
    let mut client = ControlClient::connect_default().map_err(io::Error::other)?;
    client.command(cmd, "radiusd").map_err(io::Error::other)?;
    Ok(())
}
pub fn start_at_boot(on: bool) -> io::Result<()> {
    let (_, triggers) = boot_configuration()?;
    let mut patch = Values::from([("Triggers".into(), Value::List(boot_triggers(triggers, on)))]);
    if on {
        patch.insert("Disabled".into(), Value::Number(0));
    }
    super::registry::write(KEY, &patch, false)
}
pub fn starts_at_boot() -> io::Result<bool> {
    let (disabled, triggers) = boot_configuration()?;
    Ok(!disabled && triggers.iter().any(|s| is_boot(s)))
}
fn is_boot(trigger: &str) -> bool {
    matches!(trigger, "boot" | "boot:settled")
}
fn boot_triggers(mut triggers: Vec<String>, on: bool) -> Vec<String> {
    if on {
        if !triggers.iter().any(|s| is_boot(s)) {
            triggers.push("boot:settled".into());
        }
    } else {
        triggers.retain(|s| !is_boot(s));
    }
    triggers
}
fn boot_configuration() -> io::Result<(bool, Vec<String>)> {
    use peios::registry::{Data, Key, KeyAccess, OpenFlags, Transaction};
    let tx = Transaction::begin_read_only().map_err(io::Error::from)?;
    let key = Key::open_transacted(
        None,
        KEY,
        KeyAccess::QUERY_VALUE,
        OpenFlags::empty(),
        Some(&tx),
    )
    .map_err(io::Error::from)?;
    let disabled = match key.query_value(b"Disabled", Some(&tx)) {
        Ok(v) => match Data::decode(v.ty, &v.data) {
            Data::Dword(n) => n != 0,
            _ => return Err(io::Error::other("invalid service Disabled value")),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let triggers = match key.query_value(b"Triggers", Some(&tx)) {
        Ok(v) => match Data::decode(v.ty, &v.data) {
            Data::MultiSz(v) if v.len() <= 64 && v.iter().all(|s| s.len() <= 1024) => v,
            _ => return Err(io::Error::other("invalid service Triggers value")),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    Ok((disabled, triggers))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_preference_preserves_non_boot_triggers_and_avoids_duplicates() {
        let original = vec!["timer:nightly".into(), "boot".into(), "boot:settled".into()];
        assert_eq!(boot_triggers(original.clone(), true), original);
        let off = boot_triggers(original, false);
        assert_eq!(off, vec!["timer:nightly"]);
        let on = boot_triggers(off, true);
        assert_eq!(on, vec!["timer:nightly", "boot:settled"]);
        assert_eq!(boot_triggers(on.clone(), true), on);
    }
}
