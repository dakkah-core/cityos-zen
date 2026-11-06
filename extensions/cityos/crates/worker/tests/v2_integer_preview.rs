use std::io::Write;
use std::process::{Command, Output, Stdio};
use serde_json::{json, Value};

fn source() -> String {
    json!({"types":[{"typeRef":"bool","kind":"boolean"},
        {"typeRef":"quantity","kind":"quantity","unitRef":"cityos:unit:item","minimum":0,"maximum":1000},
        {"typeRef":"input","kind":"record","fields":[{"name":"quantity","typeRef":"quantity"}]}],
        "behavior":{"schemaVersion":"cityos.behavior-definition.v2","behaviorId":"fixture.max-quantity",
            "version":"1.0.0","ownerRef":"core.agora","kind":"decision","implementation":"generated",
            "requiredCapabilities":[],"inputTypeRef":"input","resultTypeRef":"bool","locals":[],
            "expression":{"nodeId":"limit","typeRef":"bool","kind":"op","operator":"lte","args":[
                {"nodeId":"quantity","typeRef":"quantity","kind":"ref","source":"input","path":["quantity"]},
                {"nodeId":"max","typeRef":"quantity","kind":"literal","value":5}]}}}).to_string()
}

fn run(bytes: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--v2-integer-preview-stdio").env_clear().stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    child.stdin.take().ok_or("missing stdin")?.write_all(bytes)?;
    Ok(child.wait_with_output()?)
}

#[test]
fn preview_is_a_bounded_calculation_not_a_receipt() -> Result<(), Box<dyn std::error::Error>> {
    for (quantity, expected) in [(5, true), (6, false)] {
        let request = json!({"kind":"v2-integer-preview",
            "profile":"cityos.zen.v2-safe-integer-comparison-preview.v1", "source":source(),
            "input":json!({"quantity":quantity}).to_string()});
        let output = run(&serde_json::to_vec(&request)?)?;
        assert!(output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["result"], expected);
        assert_eq!(result["profile"], request["profile"]);
        assert_eq!(result["sourceSha256"].as_str().map(str::len), Some(64));
        assert!(result.get("decisionId").is_none());
        assert!(result.get("receipt").is_none());
    }
    Ok(())
}

#[test]
fn preview_rejects_duplicate_or_malformed_facts_without_output() -> Result<(), Box<dyn std::error::Error>> {
    for input in [r#"{"quantity":1,"quantity":2}"#, r#"{"quantity":1.5}"#, r#"{"quantity":1001}"#] {
        let request = json!({"kind":"v2-integer-preview",
            "profile":"cityos.zen.v2-safe-integer-comparison-preview.v1", "source":source(), "input":input});
        let output = run(&serde_json::to_vec(&request)?)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    // Serde struct visitors otherwise accept positional arrays.
    let positional = json!(["v2-integer-preview", "cityos.zen.v2-safe-integer-comparison-preview.v1",
        source(), r#"{"quantity":1}"#]);
    let output = run(&serde_json::to_vec(&positional)?)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}
