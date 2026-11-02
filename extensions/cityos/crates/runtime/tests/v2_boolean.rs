use cityos_zen_admission::v2_boolean::admit;
use cityos_zen_runtime::v2_boolean::evaluate;
use serde_json::{json, Value};

// Extracted from the synthetic V2 guard fixture in
// packages/cityos-compiler/tests/unit/business-command-decision-guards.test.ts.
// The inspected CMS Git blob was f7925b74bac0a4e606356759dc37dc4c7898832c.
// These independent expected values are not a live differential test.
const SOURCE: &[u8] = include_bytes!("../../../corpus/v2-boolean-transition.json");

#[test]
fn fixture_analysis_has_complete_dependencies() -> Result<(), Box<dyn std::error::Error>> {
    use zen_engine::policy::{PolicyDocument, PolicyWorkspace};
    let document: PolicyDocument = serde_json::from_value(json!({"imports":[], "blocks":[
        {"id":"v2-model", "type":"dataModel", "props":{"data":{"name":"facts", "properties":[
            {"id":"f0","name":"f0","type":"number","array":false,"optional":false},
            {"id":"f1","name":"f1","type":"number","array":false,"optional":false}
        ]}}},
        {"id":"v2-result", "type":"expression", "props":{"data":{"key":"facts.result", "value":"((facts.f0 == 0) and (facts.f1 == 1))"}}}
    ]}))?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy("v2-boolean", document);
    let diagnostics = workspace.all_diagnostics();
    let goal = workspace.dependencies_scoped("facts.result", Some("v2-boolean"));
    assert!(
        diagnostics.iter().all(|item| item.code
            == zen_engine::policy::DiagnosticCode::RedundantParentheses
            && item.severity == zen_engine::policy::Severity::Hint),
        "synthetic fixture diagnostics: {diagnostics:?}"
    );
    assert!(!goal.unresolved, "synthetic fixture dependencies: {goal:?}");
    assert_eq!(
        goal.deps.len(),
        2,
        "synthetic fixture dependencies: {goal:?}"
    );
    Ok(())
}

#[test]
fn transition_corpus_covers_all_valid_pairs() -> Result<(), Box<dyn std::error::Error>> {
    let policy = admit(SOURCE)?;
    for from in ["draft", "issued", "accepted"] {
        for to in ["draft", "issued", "accepted"] {
            let facts = serde_json::to_vec(&json!({"from":from,"to":to}))?;
            assert_eq!(
                evaluate(&policy, &facts)?,
                from == "draft" && to == "issued"
            );
        }
    }
    Ok(())
}

#[test]
fn closed_input_and_original_bytes_are_checked() -> Result<(), Box<dyn std::error::Error>> {
    let policy = admit(SOURCE)?;
    for input in [
        r#"{"from":"draft"}"#,
        r#"{"from":"draft","to":"issued","extra":true}"#,
        r#"{"from":"unknown","to":"issued"}"#,
        r#"{"from":true,"to":"issued"}"#,
        r#"{"from":"draft","from":"issued","to":"issued"}"#,
        "null",
    ] {
        assert!(evaluate(&policy, input.as_bytes()).is_err(), "{input}");
    }
    let text = std::str::from_utf8(SOURCE)?;
    let duplicate = text.replacen("\"types\":", "\"types\":[],\"types\":", 1);
    assert!(admit(duplicate.as_bytes()).is_err());
    assert!(admit(&[0xff]).is_err());
    Ok(())
}

#[test]
fn invalid_encoded_enum_and_extra_fields_cannot_satisfy_inequality(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut source: Value = serde_json::from_slice(SOURCE)?;
    source["behavior"]["expression"]["args"][0]["operator"] = "neq".into();
    let policy = admit(&serde_json::to_vec(&source)?)?;
    assert!(evaluate(&policy, br#"{"from":99,"to":"issued","extra":true}"#).is_err());
    assert!(evaluate(&policy, br#"{"facts":{"f0":99,"f1":1,"extra":true}}"#).is_err());
    Ok(())
}

#[test]
fn unsupported_and_invalid_v2_do_not_lower() -> Result<(), Box<dyn std::error::Error>> {
    let original: Value = serde_json::from_slice(SOURCE)?;
    let mut variants = Vec::new();
    let mut v = original.clone();
    v["behavior"]["expression"]["operator"] = "add".into();
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["expression"]["args"][0]["args"][0]["source"] = "local".into();
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["expression"]["args"][0]["args"][0]["typeRef"] = "bool".into();
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["expression"]["args"][0]["args"][1]["value"] = "unknown".into();
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["expression"]["args"][1]["nodeId"] = "from-draft".into();
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["table"] = json!({});
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["locals"] = json!([{}]);
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["expression"]["extra"] = json!(true);
    variants.push(v);
    let mut v = original.clone();
    v["types"][1]["values"] = json!(["draft", "draft"]);
    variants.push(v);
    let mut v = original.clone();
    v["types"][1]["values"] = json!([]);
    variants.push(v);
    let mut v = original.clone();
    v["types"][2]["fields"][1]["name"] = "from".into();
    variants.push(v);
    let mut v = original.clone();
    v["types"][2]["fields"][0] = json!(["from", "state"]);
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["requiredCapabilities"] = json!(["fixture:issue", "fixture:issue"]);
    variants.push(v);
    let mut v = original.clone();
    v["behavior"]["expression"]["args"][0]["args"]
        .as_array_mut()
        .ok_or("args")?
        .pop();
    variants.push(v);
    for variant in variants {
        assert!(admit(&serde_json::to_vec(&variant)?).is_err(), "{variant}");
    }
    Ok(())
}

#[test]
fn enum_identity_and_escaped_values_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let mut source: Value = serde_json::from_slice(SOURCE)?;
    let unusual = "\" or true or \"\u{2028}😀";
    source["types"][1]["values"] = json!(["draft", unusual, "accepted"]);
    source["behavior"]["expression"]["args"][1]["args"][1]["value"] = unusual.into();
    let policy = admit(&serde_json::to_vec(&source)?)?;
    assert!(evaluate(
        &policy,
        &serde_json::to_vec(&json!({"from":"draft","to":unusual}))?
    )?);
    assert!(!evaluate(
        &policy,
        &serde_json::to_vec(&json!({"from":"draft","to":"accepted"}))?
    )?);
    source["types"]
        .as_array_mut()
        .ok_or("types")?
        .push(json!({"typeRef":"other","kind":"enum","values":["draft"]}));
    source["behavior"]["expression"]["args"][0]["args"][1]["typeRef"] = "other".into();
    assert!(admit(&serde_json::to_vec(&source)?).is_err());
    Ok(())
}

#[test]
fn boolean_operators_and_typed_equality_are_evaluated() -> Result<(), Box<dyn std::error::Error>> {
    let mut source: Value = serde_json::from_slice(SOURCE)?;
    source["types"] = json!([
        {"typeRef":"bool","kind":"boolean"},
        {"typeRef":"input","kind":"record","fields":[{"name":"a","typeRef":"bool"},{"name":"b","typeRef":"bool"}]}
    ]);
    source["behavior"]["inputTypeRef"] = "input".into();
    source["behavior"]["expression"] = json!({"nodeId":"or","typeRef":"bool","kind":"op","operator":"or","args":[
        {"nodeId":"not","typeRef":"bool","kind":"op","operator":"not","args":[{"nodeId":"a","typeRef":"bool","kind":"ref","source":"input","path":["a"]}]},
        {"nodeId":"neq","typeRef":"bool","kind":"op","operator":"neq","args":[
            {"nodeId":"b","typeRef":"bool","kind":"ref","source":"input","path":["b"]},
            {"nodeId":"true","typeRef":"bool","kind":"literal","value":true}]}
    ]});
    let policy = admit(&serde_json::to_vec(&source)?)?;
    for a in [false, true] {
        for b in [false, true] {
            assert_eq!(
                evaluate(&policy, &serde_json::to_vec(&json!({"a":a,"b":b}))?)?,
                !a || !b
            );
        }
    }
    Ok(())
}

#[test]
fn boolean_literal_still_requires_complete_valid_input() -> Result<(), Box<dyn std::error::Error>> {
    let mut source: Value = serde_json::from_slice(SOURCE)?;
    source["behavior"]["expression"] =
        json!({"nodeId":"constant","typeRef":"bool","kind":"literal","value":true});
    let policy = admit(&serde_json::to_vec(&source)?)?;
    assert!(evaluate(&policy, br#"{"from":"draft","to":"issued"}"#)?);
    assert!(evaluate(&policy, br#"{"from":"draft"}"#).is_err());
    Ok(())
}
