use cityos_zen_runtime::s14_decision::{
    evaluate, Consent, Effect, Error, Input, MatchContext, Rule, MAX_DATE_MILLIS, MAX_INPUT_BYTES,
    MAX_RULES, MAX_STRING_BYTES,
};
use serde_json::Value;

fn context() -> MatchContext<'static> {
    MatchContext {
        action: "approve",
        purpose: "operations",
        resource_type: "permit",
        subject_ref: "person:1",
        tenant_id: "tenant-a",
        cell_id: "sa-1",
    }
}
fn rule(id: &'static str, effect: Effect) -> Rule<'static> {
    Rule {
        rule_id: id,
        effect,
        action: None,
        purpose: None,
        resource_type: None,
        subject_ref: None,
        tenant_id: None,
        cell_id: None,
        requires_consent: false,
        reason_code: id,
    }
}
fn run<'a>(
    rules: &'a [Rule<'a>],
    consent: Consent,
    now_millis: i64,
) -> Result<cityos_zen_runtime::s14_decision::Decision, Error> {
    evaluate(&Input {
        context: context(),
        rules,
        consent,
        now_millis,
    })
}

#[test]
fn selector_conjunction_empty_wildcards_and_untrusted_strings() -> Result<(), Error> {
    let all = Rule {
        action: Some("approve"),
        purpose: Some("operations"),
        resource_type: Some("permit"),
        subject_ref: Some("person:1"),
        tenant_id: Some("tenant-a"),
        cell_id: Some("sa-1"),
        ..rule("all", Effect::Allow)
    };
    assert_eq!(run(&[all], Consent::Absent, 0)?.reason_code, "all");
    let mismatches = [
        Rule {
            action: Some("other"),
            ..all
        },
        Rule {
            purpose: Some("other"),
            ..all
        },
        Rule {
            resource_type: Some("other"),
            ..all
        },
        Rule {
            subject_ref: Some("other"),
            ..all
        },
        Rule {
            tenant_id: Some("other"),
            ..all
        },
        Rule {
            cell_id: Some("other"),
            ..all
        },
        Rule {
            action: Some("\" or true or \""),
            ..all
        },
    ];
    for candidate in mismatches {
        assert_eq!(
            run(&[candidate], Consent::Absent, 0)?.reason_code,
            "NO_MATCHING_ALLOW"
        );
    }
    let empty = Rule {
        action: Some(""),
        purpose: Some(""),
        resource_type: Some(""),
        subject_ref: Some(""),
        tenant_id: Some(""),
        cell_id: Some(""),
        ..all
    };
    assert_eq!(run(&[empty], Consent::Absent, 0)?.effect, Effect::Allow);
    assert_eq!(
        run(&[rule("missing", Effect::Allow)], Consent::Absent, 0)?.effect,
        Effect::Allow
    );
    Ok(())
}

#[test]
fn ordered_combination_and_consent_precedence() -> Result<(), Error> {
    let rules = [
        rule("a1", Effect::Allow),
        rule("d1", Effect::Deny),
        rule("d2", Effect::Deny),
        rule("a2", Effect::Allow),
    ];
    let decision = run(&rules, Consent::Absent, 0)?;
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.reason_code, "EXPLICIT_DENY");
    assert_eq!(decision.matched_rule_ids, ["d1"]);
    assert_eq!(decision.explicit_deny_reason.as_deref(), Some("d1"));
    let allows = [rules[0], rules[3]];
    assert_eq!(run(&allows, Consent::Absent, 0)?.matched_rule_ids, ["a1"]);
    assert_eq!(
        run(&[], Consent::Absent, 0)?.reason_code,
        "NO_MATCHING_ALLOW"
    );
    let consent_rules = [
        rules[0],
        rules[1],
        Rule {
            rule_id: "a1",
            requires_consent: true,
            ..rules[3]
        },
        Rule {
            tenant_id: Some("other"),
            requires_consent: true,
            ..rules[2]
        },
    ];
    let missing = run(&consent_rules, Consent::Absent, 0)?;
    assert_eq!(missing.reason_code, "CONSENT_NOT_GRANTED");
    assert_eq!(missing.matched_rule_ids, ["a1", "d1", "a1"]);
    assert_eq!(
        run(
            &consent_rules,
            Consent::Present {
                granted: true,
                expires_at_millis: Some(0)
            },
            0
        )?
        .reason_code,
        "CONSENT_NOT_GRANTED"
    );
    assert_eq!(
        run(
            &consent_rules,
            Consent::Present {
                granted: true,
                expires_at_millis: Some(1)
            },
            0
        )?
        .reason_code,
        "EXPLICIT_DENY"
    );
    assert_eq!(
        run(
            &consent_rules,
            Consent::Present {
                granted: true,
                expires_at_millis: None
            },
            0
        )?
        .matched_rule_ids,
        ["d1"]
    );
    Ok(())
}

#[test]
fn profile_rejects_bounds_as_errors_not_decisions() {
    let one = [rule("a", Effect::Allow)];
    assert_eq!(
        run(&one, Consent::Absent, MAX_DATE_MILLIS + 1),
        Err(Error::InvalidTime)
    );
    assert_eq!(
        run(
            &one,
            Consent::Present {
                granted: true,
                expires_at_millis: Some(-MAX_DATE_MILLIS - 1)
            },
            0
        ),
        Err(Error::InvalidTime)
    );
    assert_eq!(
        run(
            &one,
            Consent::Present {
                granted: false,
                expires_at_millis: Some(MAX_DATE_MILLIS + 1)
            },
            0,
        ),
        Err(Error::InvalidTime)
    );
    let many = vec![one[0]; MAX_RULES + 1];
    assert_eq!(run(&many, Consent::Absent, 0), Err(Error::InputTooLarge));
    let long = "x".repeat(MAX_STRING_BYTES + 1);
    let big = [Rule {
        rule_id: &long,
        ..one[0]
    }];
    assert_eq!(run(&big, Consent::Absent, 0), Err(Error::InputTooLarge));
    let text = "x".repeat(MAX_STRING_BYTES);
    let mut total = Vec::new();
    for _ in 0..(MAX_INPUT_BYTES / MAX_STRING_BYTES + 1) {
        total.push(Rule {
            rule_id: &text,
            ..one[0]
        });
    }
    assert_eq!(run(&total, Consent::Absent, 0), Err(Error::InputTooLarge));
}

#[test]
fn finite_time_endpoints_are_supported() -> Result<(), Error> {
    let rules = [Rule {
        requires_consent: true,
        ..rule("allowed", Effect::Allow)
    }];
    for now in [-MAX_DATE_MILLIS, MAX_DATE_MILLIS] {
        let actual = run(
            &rules,
            Consent::Present {
                granted: true,
                expires_at_millis: None,
            },
            now,
        )?;
        assert_eq!(actual.effect, Effect::Allow);
    }
    let boundary = run(
        &rules,
        Consent::Present {
            granted: true,
            expires_at_millis: Some(MAX_DATE_MILLIS),
        },
        MAX_DATE_MILLIS,
    )?;
    assert_eq!(boundary.reason_code, "CONSENT_NOT_GRANTED");
    Ok(())
}

fn merge(base: &mut Value, overlay: &Value) {
    if let (Some(base), Some(overlay)) = (base.as_object_mut(), overlay.as_object()) {
        for (key, value) in overlay {
            if let Some(existing) = base.get_mut(key) {
                if existing.is_object() && value.is_object() {
                    merge(existing, value);
                    continue;
                }
            }
            base.insert(key.clone(), value.clone());
        }
    }
}

// Only already-characterized rule-phase cases are normalized here. This is not
// a Date.parse implementation and intentionally refuses every unknown instant.
fn fixture_time(value: &str) -> Result<i64, &'static str> {
    match value {
        "2026-09-01T00:01:00.000Z" => Ok(1_788_220_860_000),
        "2026-09-01T00:02:00.000Z" => Ok(1_788_220_920_000),
        _ => Err("unsupported fixture timestamp"),
    }
}

fn required_string(value: &Value) -> Result<&str, &'static str> {
    value.as_str().ok_or("missing string")
}

#[test]
fn existing_synthetic_corpus_rule_phase() -> Result<(), Box<dyn std::error::Error>> {
    let corpus: Value =
        serde_json::from_slice(include_bytes!("../../../corpus/s14-decision-baseline.json"))?;
    let cases = corpus["cases"].as_array().ok_or("missing cases")?;
    let ids = [
        "explicit-allow",
        "no-matching-allow",
        "explicit-deny-wins",
        "tenant-rule-mismatch",
        "tenant-rule-match",
        "consent-check-precedes-deny",
        "consent-missing",
        "consent-granted",
        "consent-revoked",
        "consent-expiry-boundary",
        "consent-unmatched-tenant",
        "consent-matching-rule-among-others",
        "consent-unmatched-action",
        "consent-empty-selector-is-wildcard",
        "consent-unknown-status",
        "first-deny-wins-across-earlier-allow",
        "first-allow-wins-in-input-order",
        "later-matching-consent-precedes-earlier-deny",
        "granted-consent-exposes-earliest-deny",
        "unmatched-consent-rule-does-not-gate-deny",
        "all-six-selectors-match",
        "one-of-six-selectors-mismatch",
        "consent-failure-retains-duplicate-rule-ids",
        "effective-boundary-is-inclusive",
        "action-selector-mismatch",
        "purpose-selector-mismatch",
        "resource-type-selector-mismatch",
        "subject-selector-mismatch",
    ];
    // These outcomes are decided before the rule phase or require legacy
    // Date.parse behavior that this normalized-time API does not implement.
    let excluded = [
        "legacy-invalid-consent-expiry",
        "stale-policy",
        "not-yet-effective",
        "expiry-boundary",
        "missing-subject",
        "invalid-clock",
        "policy-expiry-precedes-consent",
    ];
    for case in cases {
        let id = required_string(&case["id"])?;
        assert!(
            ids.contains(&id) ^ excluded.contains(&id),
            "unclassified or duplicate classification: {id}"
        );
    }
    for id in ids {
        let case = cases
            .iter()
            .find(|case| case["id"] == id)
            .ok_or("missing case")?;
        let mut value = corpus["baseInput"].clone();
        merge(&mut value, &case["override"]);
        let request = &value["request"];
        let context = MatchContext {
            action: required_string(&request["action"])?,
            purpose: required_string(&request["purpose"])?,
            resource_type: required_string(&request["resource"]["resourceType"])?,
            subject_ref: required_string(&request["subject"]["subjectRef"])?,
            tenant_id: required_string(&request["subject"]["tenantId"])?,
            cell_id: required_string(&request["subject"]["cellId"])?,
        };
        let mut rules = Vec::new();
        for r in value["snapshot"]["rules"]
            .as_array()
            .ok_or("missing rules")?
        {
            rules.push(Rule {
                rule_id: required_string(&r["ruleId"])?,
                effect: match required_string(&r["effect"])? {
                    "allow" => Effect::Allow,
                    "deny" => Effect::Deny,
                    _ => return Err("unsupported effect".into()),
                },
                action: r["action"].as_str(),
                purpose: r["purpose"].as_str(),
                resource_type: r["resourceType"].as_str(),
                subject_ref: r["subjectRef"].as_str(),
                tenant_id: r["tenantId"].as_str(),
                cell_id: r["cellId"].as_str(),
                requires_consent: r["requiresConsent"].as_bool().unwrap_or(false),
                reason_code: required_string(&r["reasonCode"])?,
            });
        }
        let consent_value = &request["consent"];
        let expiry = consent_value["expiresAt"]
            .as_str()
            .map(fixture_time)
            .transpose()?;
        let consent = if consent_value["status"] == "granted" {
            Consent::Present {
                granted: true,
                expires_at_millis: expiry,
            }
        } else if !consent_value.is_null() {
            Consent::Present {
                granted: false,
                expires_at_millis: expiry,
            }
        } else {
            Consent::Absent
        };
        let decision = evaluate(&Input {
            context,
            rules: &rules,
            consent,
            now_millis: fixture_time(required_string(&value["currentTime"])?)?,
        })?;
        let expected = &case["expected"];
        assert_eq!(
            match decision.effect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
            },
            expected["effect"],
            "{id}"
        );
        assert_eq!(
            serde_json::json!([decision.reason_code]),
            expected["reasonCodes"],
            "{id}"
        );
        assert_eq!(
            serde_json::json!(decision.matched_rule_ids),
            expected["matchedRuleIds"],
            "{id}"
        );
        if expected["reasonCodes"][0] == "EXPLICIT_DENY" {
            assert_eq!(
                decision.explicit_deny_reason.as_deref(),
                case["expectedIssues"][0]["message"].as_str(),
                "{id}: selected deny issue message"
            );
        } else {
            assert_eq!(decision.explicit_deny_reason, None, "{id}");
        }
    }
    assert!(fixture_time("not-a-date").is_err());
    assert!(fixture_time("invalid").is_err());
    Ok(())
}
