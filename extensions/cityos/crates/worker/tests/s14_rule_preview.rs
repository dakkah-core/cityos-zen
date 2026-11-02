use std::io::Write;
use std::process::{Command, Output, Stdio};

use cityos_zen_contracts::S14_CONSENT_SOURCE_SHA256;
use serde_json::{json, Value};

const PROFILE: &str = "cityos.zen.s14-rule-decision.v1";
const SELECTOR_SHA256: &str = "88cfb7768c726e482a8d6c3de5a0f16b27cb01f911e207433760b6a8b2ea61c7";
fn request() -> Value {
    json!({
        "kind":"s14-rule-preview", "profile":PROFILE,
        "context":{"action":"approve","purpose":"operations","resourceType":"permit",
            "subjectRef":"person:1","tenantId":"tenant-a","cellId":"sa-1"},
        "rules":[{"ruleId":"first","effect":"allow","requiresConsent":false,"reasonCode":"OK"}],
        "consent":{"granted":false,"expiresAtMillis":null}, "nowMillis":0
    })
}
fn run(input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--s14-rule-preview-stdio")
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
fn evaluate(input: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let output = run(&serde_json::to_vec(input)?)?;
    assert!(output.status.success(), "{:?}", output.stderr);
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn returns_rule_phase_with_both_document_identities() -> Result<(), Box<dyn std::error::Error>> {
    let value = evaluate(&request())?;
    assert_eq!(value["kind"], "s14-rule-preview");
    assert_eq!(value["profile"], PROFILE);
    assert_eq!(value["effect"], "allow");
    assert_eq!(value["reasonCode"], "OK");
    assert_eq!(value["matchedRuleIds"], json!(["first"]));
    assert!(value["explicitDenyReason"].is_null());
    assert_eq!(value["consentSourceSha256"], S14_CONSENT_SOURCE_SHA256);
    assert_eq!(
        value["selectorDocumentSha256"],
        cityos_zen_runtime::s14_decision::selector_document_sha256()?
    );
    assert_eq!(value["selectorDocumentSha256"], SELECTOR_SHA256);
    Ok(())
}

#[test]
fn preserves_deny_order_and_consent_precedence() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = request();
    value["rules"] = json!([
        {"ruleId":"allow","effect":"allow","requiresConsent":false,"reasonCode":"YES"},
        {"ruleId":"deny","effect":"deny","requiresConsent":false,"reasonCode":"NO"},
        {"ruleId":"allow","effect":"allow","requiresConsent":true,"reasonCode":"LATER"}
    ]);
    let decision = evaluate(&value)?;
    assert_eq!(decision["reasonCode"], "CONSENT_NOT_GRANTED");
    assert_eq!(
        decision["matchedRuleIds"],
        json!(["allow", "deny", "allow"])
    );
    value["consent"]["granted"] = true.into();
    let decision = evaluate(&value)?;
    assert_eq!(decision["effect"], "deny");
    assert_eq!(decision["reasonCode"], "EXPLICIT_DENY");
    assert_eq!(decision["matchedRuleIds"], json!(["deny"]));
    assert_eq!(decision["explicitDenyReason"], "NO");
    Ok(())
}

#[test]
fn invalid_or_ambiguous_input_never_produces_a_decision() -> Result<(), Box<dyn std::error::Error>>
{
    let valid = serde_json::to_string(&request())?;
    let invalid = [
        valid.replacen("\"kind\":", "\"kind\":\"s14-rule-preview\",\"kind\":", 1),
        valid.replacen(
            "\"action\":\"approve\"",
            "\"action\":\"approve\",\"action\":\"approve\"",
            1,
        ),
        valid
            .replacen("\"rules\":[{", "\"rules\":[[{", 1)
            .replacen("}],\"", "}]],\"", 1),
        valid.replace(PROFILE, "unknown"),
        valid.replacen("\"effect\":\"allow\"", "\"effect\":\"other\"", 1),
        valid.replacen("\"nowMillis\":0", "\"nowMillis\":8640000000000001", 1),
        format!("{} {{}}", valid),
    ];
    for input in invalid {
        let output = run(input.as_bytes())?;
        assert!(!output.status.success(), "{input}");
        assert!(output.stdout.is_empty());
    }
    let mut value = request();
    value["rules"][0]["ruleId"] = "x".repeat(4097).into();
    let output = run(&serde_json::to_vec(&value)?)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}
