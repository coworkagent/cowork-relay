use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=vendor");
    let digests: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&fs::read("vendor/digests.json")?)?;
    if digests.len() != 4 {
        return Err("Invalid protocol manifest".into());
    }
    for (path, expected) in digests {
        if !path.starts_with("vendor/")
            || path.contains("..")
            || format!("{:x}", Sha256::digest(fs::read(path)?)) != expected
        {
            return Err("Protocol archive or extracted contract digest mismatch".into());
        }
    }
    let schema: Value = serde_json::from_slice(&fs::read("vendor/relay/control.schema.json")?)?;
    let protocol = schema["$defs"]["protocol"]["const"]
        .as_str()
        .ok_or("Missing relay protocol")?;
    let mut generated = format!("pub const PROTOCOL: &str = {protocol:?};\n");
    let websocket_protocol = schema["$defs"]["websocketProtocol"]["const"]
        .as_str()
        .ok_or("Missing WebSocket protocol")?;
    generated.push_str(&format!(
        "pub const WEBSOCKET_PROTOCOL: &str = {websocket_protocol:?};\n"
    ));
    for (constant, def) in [
        ("FRAME_LIMIT", "frameLimit"),
        ("CONTROL_LIMIT", "controlLimit"),
        ("TICKET_SECONDS", "ticketSeconds"),
    ] {
        let value = schema["$defs"][def]["const"]
            .as_u64()
            .ok_or("Missing relay limit")?;
        generated.push_str(&format!("pub const {constant}: usize = {value};\n"));
    }
    let config: Value = serde_json::from_slice(&fs::read("vendor/relay/config.schema.json")?)?;
    let status_path = config["$defs"]["registrationStatusPath"]["const"]
        .as_str()
        .ok_or("Missing status path")?;
    generated.push_str(&format!(
        "pub const REGISTRATION_STATUS_PATH: &str = {status_path:?};\n"
    ));
    fs::write(
        Path::new(&std::env::var("OUT_DIR")?).join("relay_constants.rs"),
        generated,
    )?;
    Ok(())
}
