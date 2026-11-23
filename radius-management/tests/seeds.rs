//! The Registry seeds the radius package installs, in registry.d: the
//! service definition, its policy record and its port reservations.
use radius_management::runtime::SERVICE_SID;
use serde_json::Value as Json;

fn seed(name: &str) -> Vec<Json> {
    let path = format!("{}/../registry.d/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let seed: Json = serde_json::from_str(&text).unwrap();
    seed["keys"].as_array().unwrap().clone()
}

fn values(keys: &[Json], path: &str) -> Vec<Json> {
    let key = keys
        .iter()
        .find(|key| key["path"] == path)
        .unwrap_or_else(|| panic!("no key {path}"));
    key["values"].as_array().unwrap().clone()
}

fn value<'a>(values: &'a [Json], name: &str) -> Option<&'a Json> {
    values
        .iter()
        .find(|value| value["name"] == name)
        .map(|value| &value["data"])
}

#[test]
fn the_service_starts_at_no_time_until_turned_on() {
    let service = values(
        &seed("radiusd-service.reg"),
        "Machine\\System\\Services\\radiusd",
    );
    assert_eq!(value(&service, "Triggers"), None);
    assert_eq!(value(&service, "Identity").unwrap(), "Service");
    assert_eq!(value(&service, "ImagePath").unwrap(), "/usr/sbin/radiusd");
}

#[test]
fn the_policy_grants_the_service_what_it_keeps_and_may_authenticate() {
    let service = values(
        &seed("radiusd-service.reg"),
        "Machine\\System\\Services\\radiusd",
    );
    let policy = values(
        &seed("radiusd-policy.reg"),
        &format!("Machine\\Generic\\Authn\\Policy\\{SERVICE_SID}"),
    );
    assert_eq!(
        value(&policy, "Privileges"),
        value(&service, "RequiredPrivileges")
    );
    assert_eq!(
        value(&policy, "Capabilities").unwrap(),
        &serde_json::json!(["peios.auth.authenticate"])
    );
}

#[cfg(feature = "native")]
#[test]
fn the_ports_are_reserved_for_the_service() {
    let ports = values(
        &seed("radiusd-port.reg"),
        "Machine\\System\\Network\\TcpIp\\PortReservations",
    );
    let names: Vec<&str> = ports.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["udp:1812", "udp:1813"]);
    // PORT_BIND and READ_CONTROL, for SYSTEM and the service.
    let expected = peios::security::sddl::parse(&format!(
        "O:SYG:SYD:(A;;0x20001;;;SY)(A;;0x20001;;;{SERVICE_SID})"
    ))
    .unwrap();
    for port in &ports {
        let hex = port["data"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(
            peios::security::sddl::format(&bytes).unwrap(),
            peios::security::sddl::format(expected.as_bytes()).unwrap(),
            "{}",
            port["name"]
        );
    }
}
