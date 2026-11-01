use cityos_zen_contracts::PolicyError;
use cityos_zen_runtime::s14_consent::{evaluate, Consent, ConsentFacts, ConsentGatePreview};
use serde_json::Value;

const NOW: i64 = 1_788_220_860_000;
const LATER: i64 = 1_788_220_920_000;
const MAX_DATE: i64 = 8_640_000_000_000_000;

#[test]
fn consent_gate_matches_characterized_s14_cases() -> Result<(), Box<dyn std::error::Error>> {
    let corpus: Value =
        serde_json::from_slice(include_bytes!("../../../corpus/s14-decision-baseline.json"))?;
    assert_eq!(
        corpus["baseInput"]["currentTime"],
        "2026-09-01T00:01:00.000Z"
    );
    let cases = corpus["cases"].as_array().ok_or("missing cases")?;
    let mut checked = 0;
    for id in [
        "consent-check-precedes-deny",
        "consent-missing",
        "consent-granted",
        "consent-revoked",
        "consent-expiry-boundary",
    ] {
        let case = cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or("missing case")?;
        let rules = case["override"]["snapshot"]["rules"]
            .as_array()
            .ok_or("missing rules")?;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["requiresConsent"], true);
        let consent_value = &case["override"]["request"]["consent"];
        let consent = match consent_value["status"].as_str() {
            Some("granted") => {
                let expiry = match consent_value["expiresAt"].as_str() {
                    Some("2026-09-01T00:01:00.000Z") => Some(NOW),
                    Some("2026-09-01T00:02:00.000Z") => Some(LATER),
                    None => None,
                    _ => return Err("unsupported corpus expiry".into()),
                };
                Consent::Granted {
                    expires_at_millis: expiry,
                }
            }
            None | Some("revoked") => Consent::MissingOrNotGranted,
            _ => return Err("unsupported corpus status".into()),
        };
        let expected = if case["expected"]["reasonCodes"][0] == "CONSENT_NOT_GRANTED" {
            ConsentGatePreview::ConsentNotGranted
        } else {
            assert_eq!(case["expected"]["effect"], "allow");
            ConsentGatePreview::Satisfied
        };
        assert_eq!(
            evaluate(&ConsentFacts {
                required: true,
                consent,
                now_millis: NOW
            })?,
            expected,
            "{id}"
        );
        checked += 1;
    }
    assert_eq!(checked, 5);
    Ok(())
}

#[test]
fn consent_gate_handles_optional_and_expiry_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    for (required, consent, now_millis, expected) in [
        (
            false,
            Consent::MissingOrNotGranted,
            10,
            ConsentGatePreview::Satisfied,
        ),
        (
            true,
            Consent::MissingOrNotGranted,
            10,
            ConsentGatePreview::ConsentNotGranted,
        ),
        (
            true,
            Consent::Granted {
                expires_at_millis: None,
            },
            10,
            ConsentGatePreview::Satisfied,
        ),
        (
            true,
            Consent::Granted {
                expires_at_millis: Some(11),
            },
            10,
            ConsentGatePreview::Satisfied,
        ),
        (
            true,
            Consent::Granted {
                expires_at_millis: Some(10),
            },
            10,
            ConsentGatePreview::ConsentNotGranted,
        ),
        (
            true,
            Consent::Granted {
                expires_at_millis: Some(9),
            },
            10,
            ConsentGatePreview::ConsentNotGranted,
        ),
        (
            false,
            Consent::Granted {
                expires_at_millis: Some(9),
            },
            10,
            ConsentGatePreview::Satisfied,
        ),
        (
            true,
            Consent::Granted {
                expires_at_millis: Some(-1),
            },
            -2,
            ConsentGatePreview::Satisfied,
        ),
        (
            true,
            Consent::Granted {
                expires_at_millis: Some(MAX_DATE),
            },
            MAX_DATE,
            ConsentGatePreview::ConsentNotGranted,
        ),
    ] {
        let facts = ConsentFacts {
            required,
            consent,
            now_millis,
        };
        assert_eq!(evaluate(&facts)?, expected);
        assert_eq!(evaluate(&facts)?, expected, "repeated evaluation changed");
    }
    Ok(())
}

#[test]
fn rejects_out_of_range_instants_even_when_consent_is_optional() {
    for facts in [
        ConsentFacts {
            required: false,
            consent: Consent::MissingOrNotGranted,
            now_millis: MAX_DATE + 1,
        },
        ConsentFacts {
            required: false,
            consent: Consent::MissingOrNotGranted,
            now_millis: -MAX_DATE - 1,
        },
        ConsentFacts {
            required: false,
            consent: Consent::Granted {
                expires_at_millis: Some(MAX_DATE + 1),
            },
            now_millis: 0,
        },
        ConsentFacts {
            required: true,
            consent: Consent::Granted {
                expires_at_millis: Some(-MAX_DATE - 1),
            },
            now_millis: 0,
        },
    ] {
        assert_eq!(evaluate(&facts), Err(PolicyError::InvalidInput));
    }
}

#[test]
fn rule_matching_drives_consent_gate_from_source_corpus() -> Result<(), Box<dyn std::error::Error>>
{
    use cityos_zen_runtime::s14_consent::{evaluate_for_request, MatchContext, Rule};

    let corpus: Value =
        serde_json::from_slice(include_bytes!("../../../corpus/s14-decision-baseline.json"))?;
    let cases = corpus["cases"].as_array().ok_or("missing cases")?;
    let context = MatchContext {
        action: "approve",
        purpose: "operations",
        resource_type: "permit",
        subject_ref: "person:1",
        tenant_id: "tenant-a",
        cell_id: "sa-1",
    };
    for id in [
        "consent-unmatched-tenant",
        "consent-matching-rule-among-others",
        "consent-unmatched-action",
        "consent-empty-selector-is-wildcard",
        "consent-unknown-status",
    ] {
        let case = cases.iter().find(|c| c["id"] == id).ok_or("missing case")?;
        let rules = case["override"]["snapshot"]["rules"]
            .as_array()
            .ok_or("missing rules")?;
        let rules: Vec<Rule<'_>> = rules
            .iter()
            .map(|r| Rule {
                action: r["action"].as_str(),
                purpose: r["purpose"].as_str(),
                resource_type: r["resourceType"].as_str(),
                subject_ref: r["subjectRef"].as_str(),
                tenant_id: r["tenantId"].as_str(),
                cell_id: r["cellId"].as_str(),
                requires_consent: r["requiresConsent"].as_bool().unwrap_or(false),
            })
            .collect();
        let expected = if case["expected"]["reasonCodes"][0] == "CONSENT_NOT_GRANTED" {
            ConsentGatePreview::ConsentNotGranted
        } else {
            assert_eq!(case["expected"]["effect"], "allow");
            ConsentGatePreview::Satisfied
        };
        assert_eq!(
            evaluate_for_request(&context, &rules, Consent::MissingOrNotGranted, NOW)?,
            expected,
            "{id}"
        );
    }
    Ok(())
}

#[test]
fn every_s14_selector_is_conjunctive_and_empty_is_wildcard(
) -> Result<(), Box<dyn std::error::Error>> {
    use cityos_zen_runtime::s14_consent::{evaluate_for_request, MatchContext, Rule};
    let request = MatchContext {
        action: "approve",
        purpose: "operations",
        resource_type: "permit",
        subject_ref: "person:1",
        tenant_id: "tenant-a",
        cell_id: "sa-1",
    };
    let matching = Rule {
        action: Some("approve"),
        purpose: Some("operations"),
        resource_type: Some("permit"),
        subject_ref: Some("person:1"),
        tenant_id: Some("tenant-a"),
        cell_id: Some("sa-1"),
        requires_consent: true,
    };
    assert_eq!(
        evaluate_for_request(&request, &[matching], Consent::MissingOrNotGranted, NOW)?,
        ConsentGatePreview::ConsentNotGranted
    );
    for rule in [
        Rule {
            action: Some("other"),
            ..matching
        },
        Rule {
            purpose: Some("other"),
            ..matching
        },
        Rule {
            resource_type: Some("other"),
            ..matching
        },
        Rule {
            subject_ref: Some("other"),
            ..matching
        },
        Rule {
            tenant_id: Some("other"),
            ..matching
        },
        Rule {
            cell_id: Some("other"),
            ..matching
        },
    ] {
        assert_eq!(
            evaluate_for_request(&request, &[rule], Consent::MissingOrNotGranted, NOW)?,
            ConsentGatePreview::Satisfied
        );
    }
    let wildcard = Rule {
        action: Some(""),
        purpose: Some(""),
        resource_type: Some(""),
        subject_ref: Some(""),
        tenant_id: Some(""),
        cell_id: Some(""),
        requires_consent: true,
    };
    assert_eq!(
        evaluate_for_request(&request, &[wildcard], Consent::MissingOrNotGranted, NOW)?,
        ConsentGatePreview::ConsentNotGranted
    );
    Ok(())
}
