//! Disposable-guest operational event validation, run as the fixture admin.
use peios::{
    event::EventReader,
    msgpack::{Reader, Type},
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Debug)]
enum Value {
    Text(String),
    Bytes(Vec<u8>),
    Number(u64),
    Bool(bool),
}
fn fields(reader: &mut Reader<'_>, prefix: &str, result: &mut BTreeMap<String, Value>) {
    for _ in 0..reader.read_map().expect("payload map") {
        let key = reader.read_str().expect("field name");
        let key = if prefix.is_empty() {
            key.into()
        } else {
            format!("{prefix}.{key}")
        };
        if reader.peek() == Some(Type::Map) {
            fields(reader, &key, result);
            continue;
        }
        let value = match reader.peek() {
            Some(Type::Str) => Value::Text(reader.read_str().unwrap().into()),
            Some(Type::Bin) => Value::Bytes(reader.read_bin().unwrap().to_vec()),
            Some(Type::Bool) => Value::Bool(reader.read_bool().unwrap()),
            _ => Value::Number(reader.read_uint().expect("field type")),
        };
        assert!(result.insert(key, value).is_none(), "duplicate field");
    }
}
fn main() {
    assert_eq!(
        std::env::var("PEIOS_DISPOSABLE_RADIUS_TEST").as_deref(),
        Ok("yes")
    );
    let mut readers: Vec<_> = (0..2)
        .map(|cpu| EventReader::open(cpu).expect("two fixture CPU rings"))
        .collect();
    std::fs::write("/run/radiusd/events.ready", b"ready").unwrap();
    let start = Instant::now();
    let (mut accepted, mut denied, mut configs) = (0, 0, 0);
    loop {
        for reader in &mut readers {
            for _ in 0..4096 {
                let Some(event) = reader.next().expect("event read") else {
                    break;
                };
                if !event.event_type.starts_with("radiusd.") {
                    continue;
                }
                let mut cursor = Reader::new(&event.payload);
                let mut data = BTreeMap::new();
                fields(&mut cursor, "", &mut data);
                assert_eq!(cursor.remaining(), 0);
                let Some(Value::Bytes(actor)) = data.remove("subject.token.sid") else {
                    panic!("actor missing")
                };
                assert_eq!(
                    actor,
                    radiusd::config::SERVICE_SID
                        .parse::<peios::security::Sid>()
                        .unwrap()
                        .as_bytes()
                );
                let Some(Value::Bool(success)) = data.remove("outcome.success") else {
                    panic!("outcome missing")
                };
                if !success {
                    let Some(Value::Text(reason)) = data.remove("outcome.reason") else {
                        panic!("reason missing")
                    };
                    assert!(!reason.is_empty());
                }
                match event.event_type.as_str() {
                    "radiusd.configuration.loaded" => {
                        assert!(
                            matches!(data.remove("config.root"), Some(Value::Text(root)) if root == radiusd::config::ROOT)
                        );
                        configs += 1;
                    }
                    "radiusd.exchange.attempted" => {
                        assert!(
                            matches!(data.remove("object.radiusd.attempt.guid"), Some(Value::Bytes(id)) if id.len() == 16)
                        );
                        for key in ["object.radiusd.client.id", "object.radiusd.network.id"] {
                            assert!(matches!(data.remove(key), Some(Value::Number(id)) if id != 0));
                        }
                        let supplied = data.remove("source.radiusd.username");
                        let canonical = data.remove("object.radiusd.canonical-name");
                        let sid = data.remove("object.account.sid");
                        assert_eq!(canonical.is_some(), sid.is_some());
                        if let Some(Value::Text(name)) = canonical {
                            assert!(!name.is_empty());
                        }
                        if let Some(Value::Bytes(sid)) = sid {
                            assert!(peios::security::SidRef::from_bytes(&sid).is_some());
                        }
                        if success {
                            assert!(matches!(supplied, Some(Value::Text(_))));
                            accepted += 1;
                        } else {
                            denied += 1;
                        }
                    }
                    _ => panic!("uncatalogued radiusd event"),
                }
                // A closed set of typed fields also prevents accidental claim,
                // packet, password, secret or key material being added silently.
                assert!(data.is_empty(), "unexpected payload fields");
            }
        }
        if std::path::Path::new("/run/radiusd/qualification.done").exists() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(240),
            "qualification timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(accepted > 0 && denied > 0 && configs > 0);
    assert!(readers.iter().all(|r| r.lost() == 0), "event ring overflow");
    println!("PASS NATIVE RADIUS: operational events ({accepted} success, {denied} failure, {configs} configuration)");
}
