//! Non-authoritative, in-process preview. Authoritative worker isolation is not installed.
use std::sync::Arc;

use cityos_zen_admission::AdmittedPreview;
use cityos_zen_contracts::{PolicyError, PreviewFacts, PreviewResult, PROFILE};
use serde_json::{json, Value};
use zen_engine::policy::{EvaluateRequest, PolicyWorkspace};

pub mod s14_consent;
pub mod v2_boolean;

pub fn evaluate_preview(
    policy: &AdmittedPreview,
    facts: &PreviewFacts,
) -> Result<PreviewResult, PolicyError> {
    facts.validate()?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy("cart", policy.document().clone());
    let evaluation = workspace
        .evaluate(&EvaluateRequest {
            policy_path: Arc::from("cart"),
            input: json!({"cart":{"quantity": facts.quantity, "maxQuantity": facts.max_quantity,
            "authorized": facts.authorized}})
            .into(),
            goals: vec![Arc::from("cart.allowed")],
            trace: false,
        })
        .map_err(|_| PolicyError::Evaluation)?;
    let output: Value = evaluation.output.into();
    let allowed = output
        .get("cart")
        .and_then(|cart| cart.get("allowed"))
        .and_then(Value::as_bool)
        .ok_or(PolicyError::Evaluation)?;
    Ok(PreviewResult {
        allowed,
        source_sha256: policy.source_sha256().to_owned(),
        profile: PROFILE,
    })
}
