use cityos_zen_admission::sod::{admit_profile, MAX_APPROVERS, MAX_IDENTITY_BYTES};
use cityos_zen_runtime::sod::{evaluate, PROFILE};
use serde_json::{json, Value};

const CASES: &[u8] = include_bytes!("../../../corpus/tryton-sod-source-cases.json");

#[test]
fn source_linked_owner_semantics_cases_match_the_admitted_zen_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let corpus: Value = serde_json::from_slice(CASES)?;
    assert_eq!(corpus["schemaVersion"], "cityos.zen.tryton-sod-source-cases.v1");
    assert_eq!(corpus["authority"], "source-derived extension regression corpus; not an owner-approved policy contract");
    assert_eq!(corpus["source"]["repository"], "cityos-core-tryton");
    assert_eq!(corpus["source"]["path"], "packages/tryton-sod-policy/src/index.ts");
    assert_eq!(corpus["source"]["commit"], "2c2a03d2222a9ce055b2dfa41c86057bc20fa988");
    assert_eq!(corpus["source"]["blob"], "6f0e8bff93ffbf4dda9bcde00b7076749c67df94");
    assert_eq!(corpus["source"]["sha256"], "63513ff2875be9372ec460f1a4b48ef11ad24538dca62b979a7ddd70ad3a08a4");

    let profile = admit_profile()?;
    let cases = corpus["cases"].as_array().ok_or("cases must be an array")?;
    assert_eq!(cases.len(), 16, "source-linked semantic case set changed");
    for case in cases {
        let id = case["id"].as_str().ok_or("case id missing")?;
        let input = serde_json::to_vec(&case["input"])?;
        let result = evaluate(&profile, &input);
        assert!(result.is_ok(), "case {id}: {result:?}");
        let outcome = result?;
        assert_eq!(
            outcome.conditions_satisfied,
            case["conditionsSatisfied"].as_bool().ok_or("expected result missing")?,
            "case {id}"
        );
        assert_eq!(outcome.profile, PROFILE);
        assert_eq!(outcome.source_sha256.as_str(), profile.source_sha256());
    }
    Ok(())
}

#[test]
fn malformed_or_incomplete_sod_facts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let profile = admit_profile()?;
    for malformed in [
        br#"{}"#.as_slice(),
        br#"{"command":{"actor":{"subject":"person:a"}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"approved"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api"}},"evidence":{"approverSubjects":[],"finalDecision":"approved"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api"}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[]}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api","delegatedHumanSubject":null}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"approved"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api","unknown":true}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"approved"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api"}},"realm":{"financialProfileId":"F6"},"evidence":{"approverSubjects":[],"finalDecision":"approved"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api"}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"unknown"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api"}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"approved"},"extra":true}"#,
        br#"{"command":{"actor":{"subject":"person:a","subject":"person:b","workloadId":"api"}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"approved"}}"#,
        br#"{"command":{"actor":{"subject":"person:a","workloadId":"api"}},"realm":{"financialProfileId":"F3"},"evidence":{"approverSubjects":[],"finalDecision":"approved"}} trailing"#,
    ] {
        assert!(
            evaluate(&profile, malformed).is_err(),
            "accepted malformed facts: {}",
            String::from_utf8_lossy(malformed)
        );
    }
    Ok(())
}

#[test]
fn bounded_fact_limits_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let profile = admit_profile()?;
    let identity = "x".repeat(MAX_IDENTITY_BYTES + 1);
    let too_long = json!({
        "command":{"actor":{"subject":identity,"workloadId":"finance-api"}},
        "realm":{"financialProfileId":"F3"},
        "evidence":{"approverSubjects":[],"finalDecision":"approved"}
    });
    assert!(evaluate(&profile, &serde_json::to_vec(&too_long)?).is_err());

    let approvers = (0..=MAX_APPROVERS)
        .map(|index| format!("person:reviewer-{index}"))
        .collect::<Vec<_>>();
    let too_many = json!({
        "command":{"actor":{"subject":"person:requester","workloadId":"finance-api"}},
        "realm":{"financialProfileId":"F4"},
        "evidence":{"approverSubjects":approvers,"finalDecision":"approved"}
    });
    assert!(evaluate(&profile, &serde_json::to_vec(&too_many)?).is_err());

    let oversized = vec![b' '; cityos_zen_contracts::MAX_DOCUMENT_BYTES + 1];
    assert!(evaluate(&profile, &oversized).is_err());
    Ok(())
}

#[test]
fn empty_and_whitespace_required_actor_identities_are_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = admit_profile()?;
    for subject in ["", "   "] {
        let facts = json!({
            "command":{"actor":{"subject":subject,"workloadId":"finance-api"}},
            "realm":{"financialProfileId":"F3"},
            "evidence":{"approverSubjects":["person:reviewer"],"finalDecision":"approved"}
        });
        assert!(evaluate(&profile, &serde_json::to_vec(&facts)?).is_err());
    }
    Ok(())
}
