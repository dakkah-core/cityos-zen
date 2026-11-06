//! Synthetic comparison witnesses. This profile has not been qualified for
//! authoritative decisions or connected to an owner operation.
use cityos_zen_admission::v2_boolean::{admit, admit_integer_preview, BOOLEAN_PREVIEW_PROFILE, INTEGER_PREVIEW_PROFILE};
use cityos_zen_runtime::v2_boolean::evaluate;
use serde_json::{json, Value};

const SAFE: i64 = 9_007_199_254_740_991;

fn source(operator: &str) -> Value {
    json!({
        "types": [
            {"typeRef":"bool","kind":"boolean"},
            {"typeRef":"count","kind":"integer","minimum":-SAFE,"maximum":SAFE},
            {"typeRef":"input","kind":"record","fields":[
                {"name":"quantity","typeRef":"count"}, {"name":"limit","typeRef":"count"}
            ]}
        ],
        "behavior": {
            "schemaVersion":"cityos.behavior-definition.v2", "behaviorId":"fixture.quantity",
            "version":"1.0.0", "ownerRef":"core.agora", "kind":"decision",
            "implementation":"generated", "requiredCapabilities":[], "inputTypeRef":"input",
            "resultTypeRef":"bool", "locals":[],
            "expression":{"nodeId":"compare","typeRef":"bool","kind":"op","operator":operator,"args":[
                {"nodeId":"quantity","typeRef":"count","kind":"ref","source":"input","path":["quantity"]},
                {"nodeId":"limit","typeRef":"count","kind":"ref","source":"input","path":["limit"]}
            ]}
        }
    })
}

#[test]
fn comparisons_preserve_exact_safe_integer_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    for operator in ["eq", "neq", "lt", "lte", "gt", "gte"] {
        let bytes = serde_json::to_vec(&source(operator))?;
        assert!(admit(&bytes).is_err(), "legacy profile must remain unchanged");
        let policy = admit_integer_preview(&bytes)?;
        assert_eq!(policy.profile(), INTEGER_PREVIEW_PROFILE);
        for (a, b) in [(-SAFE, -SAFE), (-SAFE, SAFE), (-1, 0), (0, 0), (1, 0), (SAFE, SAFE - 1), (SAFE, SAFE)] {
            let expected = match operator {
                "eq" => a == b, "neq" => a != b, "lt" => a < b,
                "lte" => a <= b, "gt" => a > b, "gte" => a >= b, _ => unreachable!(),
            };
            let input = serde_json::to_vec(&json!({"quantity":a,"limit":b}))?;
            assert_eq!(evaluate(&policy, &input)?, expected, "{operator} {a} {b}");
        }
    }
    let legacy = admit(include_bytes!("../../../corpus/v2-boolean-transition.json"))?;
    assert_eq!(legacy.profile(), BOOLEAN_PREVIEW_PROFILE);
    Ok(())
}

#[test]
fn integer_profile_rejects_invalid_bounds_values_and_unsupported_operators() -> Result<(), Box<dyn std::error::Error>> {
    let mut invalid = source("lte");
    for (min, max) in [(1, 0), (-SAFE - 1, SAFE), (-SAFE, SAFE + 1)] {
        invalid["types"][1]["minimum"] = json!(min);
        invalid["types"][1]["maximum"] = json!(max);
        assert!(admit_integer_preview(&serde_json::to_vec(&invalid)?).is_err());
    }
    for operator in ["add", "multiply", "divide-exact"] {
        assert!(admit_integer_preview(&serde_json::to_vec(&source(operator))?).is_err());
    }
    let policy = admit_integer_preview(&serde_json::to_vec(&source("lte"))?)?;
    for input in [
        r#"{"quantity":9007199254740992,"limit":1}"#,
        r#"{"quantity":1.0,"limit":1}"#,
        r#"{"quantity":1e0,"limit":1}"#,
        r#"{"quantity":-0,"limit":1}"#,
        r#"{"quantity":1,"quantity":2,"limit":1}"#,
        r#"{"quantity":1}"#,
        r#"{"quantity":1,"limit":1,"extra":true}"#,
    ] {
        assert!(evaluate(&policy, input.as_bytes()).is_err(), "{input}");
    }
    let mut bounded = source("lte");
    bounded["types"][1]["minimum"] = json!(0);
    bounded["types"][1]["maximum"] = json!(10);
    let policy = admit_integer_preview(&serde_json::to_vec(&bounded)?)?;
    assert!(evaluate(&policy, br#"{"quantity":11,"limit":10}"#).is_err());
    assert!(evaluate(&policy, br#"{"quantity":-1,"limit":10}"#).is_err());
    Ok(())
}

#[test]
fn ordered_comparison_requires_matching_integer_types() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = source("lte");
    value["types"].as_array_mut().ok_or("types")?.push(json!({"typeRef":"other","kind":"integer","minimum":0,"maximum":10}));
    value["types"][2]["fields"][1]["typeRef"] = json!("other");
    value["behavior"]["expression"]["args"][1]["typeRef"] = json!("other");
    assert!(admit_integer_preview(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn integer_literals_obey_the_same_declared_range_as_owner_facts() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = source("lte");
    value["types"][1]["minimum"] = json!(0);
    value["types"][1]["maximum"] = json!(10);
    value["behavior"]["expression"]["args"][1] =
        json!({"nodeId":"limit","typeRef":"count","kind":"literal","value":10});
    let policy = admit_integer_preview(&serde_json::to_vec(&value)?)?;
    assert!(evaluate(&policy, br#"{"quantity":10,"limit":0}"#)?);
    assert!(evaluate(&policy, br#"{"quantity":10,"limit":11}"#).is_err());
    value["behavior"]["expression"]["args"][1]["value"] = json!(11);
    assert!(admit_integer_preview(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn quantities_retain_the_declared_unit_and_type_identity() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = source("lte");
    value["types"][1] = json!({"typeRef":"count","kind":"quantity","unitRef":"cityos:unit:item",
        "minimum":0,"maximum":1000});
    let policy = admit_integer_preview(&serde_json::to_vec(&value)?)?;
    assert!(evaluate(&policy, br#"{"quantity":1,"limit":2}"#)?);
    let mut no_unit = value.clone();
    no_unit["types"][1].as_object_mut().ok_or("type")?.remove("unitRef");
    assert!(admit_integer_preview(&serde_json::to_vec(&no_unit)?).is_err());
    value["types"].as_array_mut().ok_or("types")?.push(json!({"typeRef":"weight","kind":"quantity",
        "unitRef":"cityos:unit:kg","minimum":0,"maximum":1000}));
    value["types"][2]["fields"][1]["typeRef"] = json!("weight");
    value["behavior"]["expression"]["args"][1]["typeRef"] = json!("weight");
    assert!(admit_integer_preview(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
