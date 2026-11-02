//! Deterministic S14 rule-phase calculation over supplied, normalized facts.
//!
//! The caller must first perform S14's time, required-context, version and
//! policy-window checks, and obtain the complete ordered snapshot and trusted
//! facts from its own boundaries. Every supplied timestamp, including a
//! non-granted consent's expiry, must be validated before normalization. This
//! API accepts only finite integer ECMAScript time values; it deliberately does
//! not parse dates or implement legacy `Date.parse` behavior. Parsing errors
//! must not be converted into an absent expiry or a denial.
//!
//! Zen evaluates the fixed six-selector predicate for each rule and the fixed
//! consent predicate. The host collects matched indexes in source order, then
//! applies consent across all matches, first deny, first allow and default deny.
//! This ordered reduction is explicit because selecting just the first match in
//! a decision table would change S14 semantics. Results are calculations, not
//! authenticated facts, authorization, receipts, or activation authority.
use std::sync::Arc;

use cityos_zen_admission::s14_rules::{admit_fixed, ENTRY, GOAL};
use cityos_zen_contracts::PolicyError;
use serde_json::{json, Value};
use zen_engine::policy::{EvaluateRequest, PolicyWorkspace};

use crate::s14_consent::{self, ConsentFacts, ConsentGatePreview};

pub const PROFILE: &str = "cityos.zen.s14-rule-decision.v1";
pub const MAX_RULES: usize = 1024;
pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_DATE_MILLIS: i64 = 8_640_000_000_000_000;

/// Identify the fixed admitted selector document, not the worker binary.
pub fn selector_document_sha256() -> Result<String, PolicyError> {
    Ok(admit_fixed()?.document_sha256().to_owned())
}

/// Selector facts supplied by the caller; fields are compared exactly.
#[derive(Clone, Copy, Debug)]
pub struct MatchContext<'a> {
    pub action: &'a str,
    pub purpose: &'a str,
    pub resource_type: &'a str,
    pub subject_ref: &'a str,
    pub tenant_id: &'a str,
    pub cell_id: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// A present non-granted consent still carries its normalized expiry so that
/// the same bounds check applies to every supplied numeric timestamp.
#[derive(Clone, Copy, Debug)]
pub enum Consent {
    Absent,
    Present {
        granted: bool,
        expires_at_millis: Option<i64>,
    },
}

/// `None` and `Some("")` are wildcards; nonempty selectors compare exactly.
#[derive(Clone, Copy, Debug)]
pub struct Rule<'a> {
    pub rule_id: &'a str,
    pub effect: Effect,
    pub action: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub resource_type: Option<&'a str>,
    pub subject_ref: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
    pub cell_id: Option<&'a str>,
    pub requires_consent: bool,
    pub reason_code: &'a str,
}

/// `consent` may only be formed after validating every supplied expiry.
#[derive(Clone, Copy, Debug)]
pub struct Input<'a> {
    pub context: MatchContext<'a>,
    pub rules: &'a [Rule<'a>],
    pub consent: Consent,
    pub now_millis: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    pub reason_code: String,
    pub matched_rule_ids: Vec<String>,
    /// For `EXPLICIT_DENY`, CMS uses the selected rule's reason as issue text.
    pub explicit_deny_reason: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InputTooLarge,
    InvalidTime,
    Zen(PolicyError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("S14 rule input exceeds the profile bounds"),
            Self::InvalidTime => f.write_str("S14 time is outside the finite ECMAScript range"),
            Self::Zen(error) => write!(f, "Zen S14 evaluation failed: {error}"),
        }
    }
}
impl std::error::Error for Error {}

impl From<PolicyError> for Error {
    fn from(value: PolicyError) -> Self {
        Self::Zen(value)
    }
}

fn check_bounds(input: &Input<'_>) -> Result<(), Error> {
    if input.rules.len() > MAX_RULES {
        return Err(Error::InputTooLarge);
    }
    if !(-MAX_DATE_MILLIS..=MAX_DATE_MILLIS).contains(&input.now_millis) {
        return Err(Error::InvalidTime);
    }
    if let Consent::Present {
        expires_at_millis: Some(expiry),
        ..
    } = input.consent
    {
        if !(-MAX_DATE_MILLIS..=MAX_DATE_MILLIS).contains(&expiry) {
            return Err(Error::InvalidTime);
        }
    }
    let mut bytes = 0usize;
    let mut add = |s: &str| -> Result<(), Error> {
        if s.len() > MAX_STRING_BYTES {
            return Err(Error::InputTooLarge);
        }
        bytes = bytes.checked_add(s.len()).ok_or(Error::InputTooLarge)?;
        if bytes > MAX_INPUT_BYTES {
            return Err(Error::InputTooLarge);
        }
        Ok(())
    };
    let context = input.context;
    for s in [
        context.action,
        context.purpose,
        context.resource_type,
        context.subject_ref,
        context.tenant_id,
        context.cell_id,
    ] {
        add(s)?;
    }
    for rule in input.rules {
        add(rule.rule_id)?;
        add(rule.reason_code)?;
        for s in [
            rule.action,
            rule.purpose,
            rule.resource_type,
            rule.subject_ref,
            rule.tenant_id,
            rule.cell_id,
        ]
        .into_iter()
        .flatten()
        {
            add(s)?;
        }
    }
    Ok(())
}

/// Evaluate the complete rule phase; unsupported input and Zen errors are errors.
pub fn evaluate(input: &Input<'_>) -> Result<Decision, Error> {
    check_bounds(input)?;
    let admitted = admit_fixed()?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy(ENTRY, admitted.document().clone());
    let c = input.context;
    let mut matching = Vec::new();
    for rule in input.rules {
        let result = workspace.evaluate(&EvaluateRequest {
            policy_path: Arc::from(ENTRY),
            input: json!({"rule": {
                "action": rule.action.unwrap_or(""), "actualAction": c.action,
                "purpose": rule.purpose.unwrap_or(""), "actualPurpose": c.purpose,
                "resourceType": rule.resource_type.unwrap_or(""), "actualResourceType": c.resource_type,
                "subjectRef": rule.subject_ref.unwrap_or(""), "actualSubjectRef": c.subject_ref,
                "tenantId": rule.tenant_id.unwrap_or(""), "actualTenantId": c.tenant_id,
                "cellId": rule.cell_id.unwrap_or(""), "actualCellId": c.cell_id
            }}).into(),
            goals: vec![Arc::from(GOAL)], trace: false,
        }).map_err(|_| Error::Zen(PolicyError::Evaluation))?;
        let output: Value = result.output.into();
        match output.pointer("/rule/matches").and_then(Value::as_bool) {
            Some(true) => matching.push(rule),
            Some(false) => {}
            None => return Err(Error::Zen(PolicyError::Evaluation)),
        }
    }
    let normalized_consent = match input.consent {
        Consent::Present {
            granted: true,
            expires_at_millis,
        } => s14_consent::Consent::Granted { expires_at_millis },
        Consent::Absent | Consent::Present { granted: false, .. } => {
            s14_consent::Consent::MissingOrNotGranted
        }
    };
    let consent = s14_consent::evaluate(&ConsentFacts {
        required: matching.iter().any(|rule| rule.requires_consent),
        consent: normalized_consent,
        now_millis: input.now_millis,
    })?;
    if consent == ConsentGatePreview::ConsentNotGranted {
        return Ok(Decision {
            effect: Effect::Deny,
            reason_code: "CONSENT_NOT_GRANTED".into(),
            matched_rule_ids: matching
                .iter()
                .map(|rule| rule.rule_id.to_owned())
                .collect(),
            explicit_deny_reason: None,
        });
    }
    if let Some(rule) = matching.iter().find(|rule| rule.effect == Effect::Deny) {
        return Ok(Decision {
            effect: Effect::Deny,
            reason_code: "EXPLICIT_DENY".into(),
            matched_rule_ids: vec![rule.rule_id.to_owned()],
            explicit_deny_reason: Some(rule.reason_code.to_owned()),
        });
    }
    if let Some(rule) = matching.iter().find(|rule| rule.effect == Effect::Allow) {
        return Ok(Decision {
            effect: Effect::Allow,
            reason_code: rule.reason_code.to_owned(),
            matched_rule_ids: vec![rule.rule_id.to_owned()],
            explicit_deny_reason: None,
        });
    }
    Ok(Decision {
        effect: Effect::Deny,
        reason_code: "NO_MATCHING_ALLOW".into(),
        matched_rule_ids: matching
            .iter()
            .map(|rule| rule.rule_id.to_owned())
            .collect(),
        explicit_deny_reason: None,
    })
}
