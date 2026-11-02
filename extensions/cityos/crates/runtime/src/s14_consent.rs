//! Fixed S14 consent-gate preview over caller-supplied, normalized facts.
//!
//! This does not select matching rules, parse timestamps, validate provenance,
//! issue a receipt, or authorize an operation. The caller must only use this
//! after the S14 resolver's earlier checks and rule matching have succeeded.
//! The characterized source and cases are recorded in the S14 baseline corpus.

use std::sync::Arc;

use cityos_zen_admission::s14_consent::admit_fixed;
use cityos_zen_contracts::PolicyError;
use serde_json::{json, Value};
use zen_engine::policy::{EvaluateRequest, PolicyWorkspace};

const SOURCE: &[u8] = include_bytes!("../../../corpus/s14-consent-preview.json");
// ECMAScript Date's finite time-value range; all integers in this range are
// exactly representable by a JavaScript Number and by Zen's JSON input.
const MAX_DATE_MILLIS: i64 = 8_640_000_000_000_000;

/// Admit the embedded preview and return the SHA-256 of its original bytes.
/// This identifies only this source-local preview, not a qualified policy.
pub fn admitted_source_sha256() -> Result<String, PolicyError> {
    Ok(admit_fixed(SOURCE)?.source_sha256().to_owned())
}

/// Normalized consent state. All supplied expiry strings must first be validated,
/// even for non-granted consent. Invalid or unsupported dates must return an
/// error upstream; they must never be converted to `None` or discarded here.
/// `None` means the expiry was absent, not that parsing failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    MissingOrNotGranted,
    Granted { expires_at_millis: Option<i64> },
}

/// These facts are supplied by the caller and have no verified provenance here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentFacts {
    /// Whether any *matching* S14 rule requires consent.
    pub required: bool,
    pub consent: Consent,
    pub now_millis: i64,
}

/// Only the consent gate's outcome; `Satisfied` is not an authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentGatePreview {
    Satisfied,
    ConsentNotGranted,
}

/// Caller-supplied request fields used by S14 rule matching; not verified facts.
#[derive(Clone, Copy, Debug)]
pub struct MatchContext<'a> {
    pub action: &'a str,
    pub purpose: &'a str,
    pub resource_type: &'a str,
    pub subject_ref: &'a str,
    pub tenant_id: &'a str,
    pub cell_id: &'a str,
}

/// The S14 selectors and consent flag of one caller-supplied policy rule.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rule<'a> {
    pub action: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub resource_type: Option<&'a str>,
    pub subject_ref: Option<&'a str>,
    pub tenant_id: Option<&'a str>,
    pub cell_id: Option<&'a str>,
    pub requires_consent: bool,
}

impl Rule<'_> {
    fn matches(&self, request: &MatchContext<'_>) -> bool {
        fn matches_selector(selector: Option<&str>, value: &str) -> bool {
            selector.is_none_or(|selector| selector.is_empty() || selector == value)
        }
        matches_selector(self.action, request.action)
            && matches_selector(self.purpose, request.purpose)
            && matches_selector(self.resource_type, request.resource_type)
            && matches_selector(self.subject_ref, request.subject_ref)
            && matches_selector(self.tenant_id, request.tenant_id)
            && matches_selector(self.cell_id, request.cell_id)
    }
}

/// Preview the consent gate using S14's matching-rule semantics.
///
/// The caller must supply the complete snapshot rules and request fields, valid
/// normalized times, and perform S14's earlier checks. This does not verify any
/// facts, evaluate deny/allow rules, issue receipts, or authorize operations.
pub fn evaluate_for_request(
    request: &MatchContext<'_>,
    rules: &[Rule<'_>],
    consent: Consent,
    now_millis: i64,
) -> Result<ConsentGatePreview, PolicyError> {
    evaluate(&ConsentFacts {
        required: rules
            .iter()
            .any(|rule| rule.requires_consent && rule.matches(request)),
        consent,
        now_millis,
    })
}

/// Evaluate the fixed, source-local consent expression through Zen's public API.
/// Invalid timestamp values and Zen failures return an error, never a decision.
pub fn evaluate(facts: &ConsentFacts) -> Result<ConsentGatePreview, PolicyError> {
    let (granted, expires_at) = match facts.consent {
        Consent::MissingOrNotGranted => (false, None),
        Consent::Granted { expires_at_millis } => (true, expires_at_millis),
    };
    if !(-MAX_DATE_MILLIS..=MAX_DATE_MILLIS).contains(&facts.now_millis)
        || expires_at.is_some_and(|time| !(-MAX_DATE_MILLIS..=MAX_DATE_MILLIS).contains(&time))
    {
        return Err(PolicyError::InvalidInput);
    }

    let admitted = admit_fixed(SOURCE)?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy("s14-consent", admitted.document().clone());
    let evaluation = workspace
        .evaluate(&EvaluateRequest {
            policy_path: Arc::from("s14-consent"),
            input: json!({"consent": {
                "required": facts.required,
                "granted": granted,
                "hasExpiry": expires_at.is_some(),
                "now": facts.now_millis,
                "expiresAt": expires_at.unwrap_or(0)
            }})
            .into(),
            goals: vec![Arc::from("consent.satisfied")],
            trace: false,
        })
        .map_err(|_| PolicyError::Evaluation)?;
    let output: Value = evaluation.output.into();
    match output
        .get("consent")
        .and_then(|consent| consent.get("satisfied"))
        .and_then(Value::as_bool)
    {
        Some(true) => Ok(ConsentGatePreview::Satisfied),
        Some(false) => Ok(ConsentGatePreview::ConsentNotGranted),
        None => Err(PolicyError::Evaluation),
    }
}
