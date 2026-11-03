//! Bounded, non-authoritative transport for the normalized S14 rule phase.
//! It does not authenticate inputs, perform earlier S14 checks, issue receipts,
//! or provide process isolation. Errors never produce a decision.
use std::io::{self, Read, Write};

use cityos_zen_contracts::{PolicyError, S14_CONSENT_SOURCE_SHA256};
use cityos_zen_runtime::{
    s14_consent,
    s14_decision::{self, Consent, Effect, Input, MatchContext, Rule},
};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const KIND: &str = "s14-rule-preview";
const MAX_BYTES: u64 = 131_072;
pub(crate) const MAX_OUTPUT_BYTES: usize = 131_072;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckedResponse {
    kind: String,
    profile: String,
    selector_document_sha256: String,
    consent_source_sha256: String,
    effect: RuleEffect,
    reason_code: String,
    matched_rule_ids: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    explicit_deny_reason: Option<String>,
}

fn required_option<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(d)
}

/// Validate the complete, untrusted child response before forwarding any bytes.
pub(crate) fn validate_response(bytes: &[u8]) -> Result<(), PolicyError> {
    if bytes.len() > MAX_OUTPUT_BYTES
        || bytes.iter().copied().find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n')) != Some(b'{')
    {
        return Err(PolicyError::Evaluation);
    }
    let response: CheckedResponse = serde_json::from_slice(bytes).map_err(|_| PolicyError::Evaluation)?;
    if response.kind != KIND || response.profile != s14_decision::PROFILE
        || response.selector_document_sha256 != s14_decision::selector_document_sha256()?
        || response.consent_source_sha256 != S14_CONSENT_SOURCE_SHA256
        || response.reason_code.len() > s14_decision::MAX_STRING_BYTES
        || response.matched_rule_ids.len() > s14_decision::MAX_RULES
        || response.matched_rule_ids.iter().any(|id| id.len() > s14_decision::MAX_STRING_BYTES)
        || response.explicit_deny_reason.as_ref().is_some_and(|s| s.len() > s14_decision::MAX_STRING_BYTES)
    {
        return Err(PolicyError::Evaluation);
    }
    let shape_ok = match response.effect {
        RuleEffect::Allow => response.explicit_deny_reason.is_none() && response.matched_rule_ids.len() == 1,
        RuleEffect::Deny => match response.reason_code.as_str() {
            "EXPLICIT_DENY" => response.explicit_deny_reason.is_some() && response.matched_rule_ids.len() == 1,
            "CONSENT_NOT_GRANTED" => response.explicit_deny_reason.is_none() && !response.matched_rule_ids.is_empty(),
            "NO_MATCHING_ALLOW" => response.explicit_deny_reason.is_none() && response.matched_rule_ids.is_empty(),
            _ => false,
        },
    };
    if shape_ok { Ok(()) } else { Err(PolicyError::Evaluation) }
}

// Derived serde structs accept positional sequences by default. Require maps
// at every structured level without first decoding to a lossy JSON Value.
struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(Visitor(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Request {
    kind: String,
    profile: String,
    context: Object<Context>,
    rules: Vec<Object<RuleInput>>,
    consent: Object<ConsentInput>,
    now_millis: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Context {
    action: String,
    purpose: String,
    resource_type: String,
    subject_ref: String,
    tenant_id: String,
    cell_id: String,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RuleEffect {
    Allow,
    Deny,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuleInput {
    rule_id: String,
    effect: RuleEffect,
    action: Option<String>,
    purpose: Option<String>,
    resource_type: Option<String>,
    subject_ref: Option<String>,
    tenant_id: Option<String>,
    cell_id: Option<String>,
    requires_consent: bool,
    reason_code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConsentInput {
    granted: bool,
    expires_at_millis: Option<i64>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    kind: &'static str,
    profile: &'static str,
    selector_document_sha256: String,
    consent_source_sha256: String,
    effect: &'static str,
    reason_code: String,
    matched_rule_ids: Vec<String>,
    explicit_deny_reason: Option<String>,
}

pub fn preview() -> Result<(), PolicyError> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    let Object(request): Object<Request> =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::InvalidInput)?;
    if request.kind != KIND || request.profile != s14_decision::PROFILE {
        return Err(PolicyError::InvalidInput);
    }
    let c = &request.context.0;
    let rules: Vec<_> = request
        .rules
        .iter()
        .map(|Object(r)| Rule {
            rule_id: &r.rule_id,
            effect: match r.effect {
                RuleEffect::Allow => Effect::Allow,
                RuleEffect::Deny => Effect::Deny,
            },
            action: r.action.as_deref(),
            purpose: r.purpose.as_deref(),
            resource_type: r.resource_type.as_deref(),
            subject_ref: r.subject_ref.as_deref(),
            tenant_id: r.tenant_id.as_deref(),
            cell_id: r.cell_id.as_deref(),
            requires_consent: r.requires_consent,
            reason_code: &r.reason_code,
        })
        .collect();
    let consent = &request.consent.0;
    let decision = s14_decision::evaluate(&Input {
        context: MatchContext {
            action: &c.action,
            purpose: &c.purpose,
            resource_type: &c.resource_type,
            subject_ref: &c.subject_ref,
            tenant_id: &c.tenant_id,
            cell_id: &c.cell_id,
        },
        rules: &rules,
        consent: Consent::Present {
            granted: consent.granted,
            expires_at_millis: consent.expires_at_millis,
        },
        now_millis: request.now_millis,
    })
    .map_err(|_| PolicyError::Evaluation)?;
    let consent_source_sha256 = s14_consent::admitted_source_sha256()?;
    if consent_source_sha256 != S14_CONSENT_SOURCE_SHA256 {
        return Err(PolicyError::Evaluation);
    }
    let response = Response {
        kind: KIND,
        profile: s14_decision::PROFILE,
        selector_document_sha256: s14_decision::selector_document_sha256()?,
        consent_source_sha256,
        effect: match decision.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        },
        reason_code: decision.reason_code,
        matched_rule_ids: decision.matched_rule_ids,
        explicit_deny_reason: decision.explicit_deny_reason,
    };
    // Serialize before writing anything so oversized output never becomes a
    // partial successful response. A failed write remains a process error.
    let output = serde_json::to_vec(&response).map_err(|_| PolicyError::Evaluation)?;
    if output.len() + 1 > MAX_OUTPUT_BYTES {
        return Err(PolicyError::Evaluation);
    }
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&output)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| PolicyError::Evaluation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn supervisor_response_requires_exact_unambiguous_identity_and_shape() -> Result<(), Box<dyn std::error::Error>> {
        let valid = json!({
            "kind": KIND, "profile": s14_decision::PROFILE,
            "selectorDocumentSha256": s14_decision::selector_document_sha256()?,
            "consentSourceSha256": S14_CONSENT_SOURCE_SHA256,
            "effect": "deny", "reasonCode": "EXPLICIT_DENY",
            "matchedRuleIds": ["rule-1"], "explicitDenyReason": "NO"
        });
        let bytes = serde_json::to_vec(&valid)?;
        assert!(validate_response(&bytes).is_ok());
        let text = String::from_utf8(bytes)?;
        let mut invalid = vec![
            text.replacen("\"kind\":", "\"kind\":\"s14-rule-preview\",\"kind\":", 1),
            text.replace(s14_decision::PROFILE, "wrong-profile"),
            text.replace(S14_CONSENT_SOURCE_SHA256, &"0".repeat(64)),
            text.replace(&s14_decision::selector_document_sha256()?, &"0".repeat(64)),
            text.replacen("\"effect\":\"deny\"", "\"effect\":\"other\"", 1),
            format!("{text} {{}}"),
            format!("[{text}]") ,
        ];
        let mut bad = valid.clone();
        if let Some(object) = bad.as_object_mut() { object.remove("explicitDenyReason"); }
        invalid.push(serde_json::to_string(&bad)?);
        bad = valid.clone();
        bad["extra"] = json!(true);
        invalid.push(serde_json::to_string(&bad)?);
        bad = valid.clone();
        bad["explicitDenyReason"] = json!(null);
        invalid.push(serde_json::to_string(&bad)?);
        bad = valid.clone();
        bad["matchedRuleIds"] = json!(vec!["id"; s14_decision::MAX_RULES + 1]);
        invalid.push(serde_json::to_string(&bad)?);
        bad = valid;
        bad["matchedRuleIds"] = json!(["x".repeat(s14_decision::MAX_STRING_BYTES + 1)]);
        invalid.push(serde_json::to_string(&bad)?);
        for value in invalid { assert!(validate_response(value.as_bytes()).is_err(), "{value}"); }
        Ok(())
    }
}
