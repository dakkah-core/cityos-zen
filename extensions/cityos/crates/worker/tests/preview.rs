use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const SOURCE: &str = include_str!("../../../corpus/cart-quantity-preview.json");

fn run(input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    run_mode("--preview-stdio", input)
}

fn run_mode(mode: &str, input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg(mode)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(input)?;
    Ok(child.wait_with_output()?)
}

#[cfg(target_os = "linux")]
#[test]
fn supervised_preview_is_bounded_and_non_authoritative() -> Result<(), Box<dyn std::error::Error>> {
    let request = json!({"kind":"preview", "source":SOURCE,
        "facts":{"quantity":1,"maxQuantity":2,"authorized":true}});
    let result = run_mode("--supervised-preview-stdio", &serde_json::to_vec(&request)?)?;
    assert!(result.status.success());
    let body: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(body["kind"], "preview");
    assert_eq!(body["allowed"], true);
    assert!(body.get("signedDecision").is_none());
    assert!(body.get("decisionId").is_none());

    let rejected = run_mode("--supervised-preview-stdio", b"invalid secret-value")?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("secret-value"));

    let authority = json!({"kind":"authority", "source":SOURCE,
        "facts":{"quantity":1,"maxQuantity":2,"authorized":true}});
    let rejected = run_mode(
        "--supervised-preview-stdio",
        &serde_json::to_vec(&authority)?,
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn supervised_preview_is_unavailable_on_other_platforms() -> Result<(), Box<dyn std::error::Error>>
{
    let result = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--supervised-preview-stdio")
        .output()?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn supervised_preview_times_out_when_input_never_closes() -> Result<(), Box<dyn std::error::Error>>
{
    let child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--supervised-preview-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Retain the write end while waiting, so the evaluator cannot observe EOF.
    let mut child = child;
    let input = child.stdin.take().ok_or("missing stdin")?;
    let result = child.wait_with_output()?;
    drop(input);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[test]
fn explicit_preview_round_trips_without_receipt_or_authority()
-> Result<(), Box<dyn std::error::Error>> {
    for (quantity, authorized, expected) in [(1, true, true), (3, true, false), (1, false, false)] {
        let request = json!({"kind":"preview", "source":SOURCE,
            "facts":{"quantity":quantity,"maxQuantity":2,"authorized":authorized}});
        let result = run(&serde_json::to_vec(&request)?)?;
        assert!(result.status.success());
        let body: Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(body["kind"], "preview");
        assert_eq!(body["allowed"], expected);
        assert!(body.get("signedDecision").is_none());
        assert!(body.get("decisionId").is_none());
    }
    Ok(())
}

#[test]
fn invalid_or_ambiguous_preview_fails_without_output() -> Result<(), Box<dyn std::error::Error>> {
    let invalid = [
        br#"{"kind":"preview","kind":"preview","source":"secret-value","facts":{}}"#.to_vec(),
        serde_json::to_vec(&json!({"kind":"authority", "source":SOURCE,
            "facts":{"quantity":1,"maxQuantity":2,"authorized":true}}))?,
        vec![b'x'; 131_073],
    ];
    for request in invalid {
        let result = run(&request)?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-value"));
    }
    Ok(())
}
