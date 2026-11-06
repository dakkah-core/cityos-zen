use cityos_zen_contracts::agora_quantity::{KIND, PROFILE, MAX_ITEMS, MAX_REQUEST_BYTES};
use cityos_zen_runtime::agora_quantity::evaluate;
use serde_json::{json, Value};

const SAFE: u64 = 9_007_199_254_740_991;

fn request() -> Value {
    json!({"kind":KIND,"profile":PROFILE,
        "items":[{"sku":"a","quantity":2},{"sku":"b","quantity":9},{"sku":"a","quantity":3}],
        "rule":{"ruleId":"limit-a","revisionDigest":format!("sha256:{}", "a".repeat(64)),
            "ruleType":"max_quantity","status":"active","targetSku":"a","maxQuantity":5}})
}
fn run(value: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(evaluate(&serde_json::to_vec(value)?)?)?)
}

#[test]
fn selected_and_global_rules_compare_exact_matching_quantities() -> Result<(), Box<dyn std::error::Error>> {
    let mut q = request();
    let a = run(&q)?;
    assert_eq!(a["matchingQuantity"], 5);
    assert_eq!(a["withinLimit"], true);
    assert_eq!(a["ruleId"], "limit-a");
    assert_eq!(a["revisionDigest"], q["rule"]["revisionDigest"]);
    assert_eq!(a["sourceSha256"].as_str().map(str::len), Some(64));
    q["rule"]["maxQuantity"] = json!(4);
    assert_eq!(run(&q)?["withinLimit"], false);
    q["rule"]["targetSku"] = Value::Null;
    q["rule"]["maxQuantity"] = json!(14);
    assert_eq!(run(&q)?["matchingQuantity"], 14);
    assert_eq!(run(&q)?["withinLimit"], true);
    q["rule"]["targetSku"] = json!("absent");
    q["rule"]["maxQuantity"] = json!(0);
    assert_eq!(run(&q)?["matchingQuantity"], 0);
    assert_eq!(run(&q)?["withinLimit"], true);
    q["rule"]["targetSku"] = json!("a");
    assert_eq!(run(&q)?["withinLimit"], false);
    q["items"] = json!([]);
    q["rule"]["maxQuantity"] = json!(0);
    assert_eq!(run(&q)?["matchingQuantity"], 0);
    assert_eq!(run(&q)?["withinLimit"], true);
    Ok(())
}

#[test]
fn exact_safe_boundary_and_total_overflow_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut q = request();
    q["items"] = json!([{ "sku":"a", "quantity":SAFE }]);
    q["rule"]["maxQuantity"] = json!(SAFE);
    assert_eq!(run(&q)?["withinLimit"], true);
    q["rule"]["maxQuantity"] = json!(SAFE - 1);
    assert_eq!(run(&q)?["withinLimit"], false);
    q["items"] = json!([{ "sku":"a", "quantity":SAFE }, { "sku":"b", "quantity":1 }]);
    assert!(run(&q).is_err(), "even nonmatching quantities overflow the whole cart");
    q["items"] = json!([{ "sku":"a", "quantity":SAFE + 1 }]);
    assert!(run(&q).is_err());
    q["items"] = json!([{ "sku":"a", "quantity":1 }]);
    q["rule"]["maxQuantity"] = json!(SAFE + 1);
    assert!(run(&q).is_err());
    Ok(())
}

#[test]
fn invalid_rule_candidate_and_bounded_inputs_fail() -> Result<(), Box<dyn std::error::Error>> {
    let base = request();
    let mut bad = Vec::new();
    for (field, value) in [("status", json!("inactive")), ("ruleType", json!("sku_block")),
        ("targetSku", json!(" a")), ("targetSku", json!("a\u{7f}")), ("ruleId", json!("")),
        ("revisionDigest", json!("sha256:unverified")), ("maxQuantity", Value::Null)] {
        let mut q = base.clone(); q["rule"][field] = value; bad.push(q);
    }
    let mut missing = base.clone(); missing["rule"].as_object_mut().ok_or("rule")?.remove("targetSku"); bad.push(missing);
    for items in [json!([{ "sku":"a", "quantity":0 }]),
        json!([{ "sku":"a", "quantity":-1 }]), json!([{ "sku":"a", "quantity":1.0 }]),
        json!([{ "sku":"a", "quantity":null }]), json!([{ "sku":"\u{feff}a", "quantity":1 }]),
        json!([["a", 1]]), json!(vec![json!({"sku":"a","quantity":1}); MAX_ITEMS + 1])] {
        let mut q = base.clone(); q["items"] = items; bad.push(q);
    }
    for q in bad { assert!(run(&q).is_err(), "accepted {q}"); }
    assert!(evaluate(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn malformed_duplicate_unknown_and_lossy_json_are_rejected() {
    let base = request().to_string();
    for bytes in [base.replacen("\"quantity\":2", "\"quantity\":2,\"quantity\":3", 1),
        base.replacen("\"quantity\":2", "\"quantity\":2e0", 1),
        base.replacen("\"quantity\":2", "\"quantity\":-0", 1),
        base.replacen("\"sku\":\"a\"", "\"sku\":\"a\",\"extra\":true", 1),
        base.replacen("\"kind\":", "\"unknown\":true,\"kind\":", 1),
        format!("{base} true"), "[]".into()] {
        assert!(evaluate(bytes.as_bytes()).is_err(), "accepted {bytes}");
    }
}
