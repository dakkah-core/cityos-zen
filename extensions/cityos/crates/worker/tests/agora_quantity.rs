use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(bytes: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--agora-quantity-stdio")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("stdin")?.write_all(bytes)?;
    Ok(child.wait_with_output()?)
}
fn request() -> Value {
    json!({"kind":"agora-cart-quantity","profile":"cityos.zen.agora-cart-quantity.v1",
        "items":[{"sku":"a","quantity":2}],
        "rule":{"ruleId":"r","revisionDigest":format!("sha256:{}", "a".repeat(64)),
            "ruleType":"max_quantity","status":"active","targetSku":null,"maxQuantity":1}})
}
#[test]
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn worker_returns_calculation_and_no_authorization() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&serde_json::to_vec(&request())?)?;
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(response["matchingQuantity"], 2);
    assert_eq!(response["withinLimit"], false);
    assert!(response.get("receipt").is_none());
    assert!(response.get("authorized").is_none());
    Ok(())
}

#[test]
#[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
fn valid_request_fails_closed_without_the_linux_isolation_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&serde_json::to_vec(&request())?)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn worker_failure_never_emits_a_result() -> Result<(), Box<dyn std::error::Error>> {
    let mut invalid = request();
    invalid["rule"]["maxQuantity"] = Value::Null;
    for bytes in [
        b"{invalid".to_vec(),
        serde_json::to_vec(&invalid)?,
        b"[]".to_vec(),
    ] {
        let output = run(&bytes)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    Ok(())
}
