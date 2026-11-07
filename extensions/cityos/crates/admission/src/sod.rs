//! Bounded, source-derived Tryton SoD evaluation profile.
//!
//! This is a local semantic projection of the current Tryton owner code. It is
//! not an approved policy contract or an authority boundary. Tryton remains the
//! semantic and final business owner; the result does not verify evidence,
//! authorize a command, issue a receipt, activate policy, or cause an effect.
use std::collections::BTreeSet;

use super::{json_nesting_within_limit, v2_boolean, Unique};
use cityos_zen_contracts::{PolicyError, MAX_DOCUMENT_BYTES};
use serde::Deserialize;
use serde_json::{json, Value};

pub const PROFILE: &str = "cityos.zen.tryton-sod-source-preview.v1";
pub const MAX_APPROVERS: usize = 1_024;
pub const MAX_IDENTITY_BYTES: usize = 4_096;

const PROFILE_SOURCE: &[u8] = include_bytes!("../../../corpus/tryton-sod-source-profile.json");

/// The only constructible value admits the checked-in source-derived profile.
/// Its inner V2 behavior remains private so callers cannot substitute a policy.
pub struct AdmittedSodProfile {
    inner: v2_boolean::AdmittedV2Boolean,
}

impl AdmittedSodProfile {
    pub fn source_sha256(&self) -> &str {
        self.inner.source_sha256()
    }

    /// Calculate the source predicates from a closed, caller-supplied projection.
    /// An affirmative result is not verified evidence or financial authority.
    pub fn evaluate(&self, input: &[u8]) -> Result<SodEvaluation, PolicyError> {
        let facts = decode_input(input)?;
        let normalized = facts.normalized()?;
        let normalized_json =
            serde_json::to_vec(&normalized).map_err(|_| PolicyError::InvalidInput)?;
        let conditions_satisfied = self.inner.evaluate(&normalized_json)?;
        Ok(SodEvaluation {
            conditions_satisfied,
            source_sha256: self.source_sha256().to_owned(),
            profile: PROFILE,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodEvaluation {
    /// The bounded predicates evaluated to true; this is not an authorization.
    pub conditions_satisfied: bool,
    pub source_sha256: String,
    pub profile: &'static str,
}

/// Admit the checked-in profile with the existing typed V2 Boolean profile.
///
/// The fixture is deliberately source-local and is not registered as an
/// approved Tryton or CityOS policy contract.
pub fn admit_profile() -> Result<AdmittedSodProfile, PolicyError> {
    Ok(AdmittedSodProfile {
        inner: v2_boolean::admit(PROFILE_SOURCE)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    command: Command,
    realm: Realm,
    evidence: ApprovalEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    actor: Actor,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Actor {
    subject: String,
    workload_id: String,
    #[serde(default, deserialize_with = "deserialize_present_string")]
    delegated_human_subject: Option<String>,
}

fn deserialize_present_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Realm {
    financial_profile_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalEvidence {
    approver_subjects: Vec<String>,
    final_decision: FinalDecision,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FinalDecision {
    Approved,
    Rejected,
    Pending,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedFacts {
    realm_controller_command: bool,
    ai_subject: bool,
    ai_workload: bool,
    final_approved: bool,
    self_approval: bool,
    requires_two_approvers: bool,
    has_two_distinct_approvers: bool,
}

impl Input {
    fn normalized(mut self) -> Result<NormalizedFacts, PolicyError> {
        if self.evidence.approver_subjects.len() > MAX_APPROVERS
            || !matches!(
                self.realm.financial_profile_id.as_str(),
                "F0" | "F1" | "F2" | "F3" | "F4" | "F5"
            )
        {
            return Err(PolicyError::InvalidInput);
        }

        // The owner contracts parse command actor identities through the
        // requiredTextSchema (trim + nonempty); preserve that input boundary.
        self.command.actor.subject = required_identity(self.command.actor.subject)?;
        self.command.actor.workload_id = required_identity(self.command.actor.workload_id)?;
        if let Some(delegated) = self.command.actor.delegated_human_subject.take() {
            self.command.actor.delegated_human_subject = Some(required_identity(delegated)?);
        }
        if self
            .evidence
            .approver_subjects
            .iter()
            .any(|subject| subject.is_empty() || subject.len() > MAX_IDENTITY_BYTES)
        {
            return Err(PolicyError::InvalidInput);
        }

        let actor = self.command.actor;
        let evidence = self.evidence;
        let self_approval = evidence.approver_subjects.iter().any(|approver| {
            approver == &actor.subject
                || approver == &actor.workload_id
                || actor
                    .delegated_human_subject
                    .as_ref()
                    .is_some_and(|delegated| approver == delegated)
        });
        let distinct_approvers: BTreeSet<&str> = evidence
            .approver_subjects
            .iter()
            .map(String::as_str)
            .collect();

        Ok(NormalizedFacts {
            realm_controller_command: actor.workload_id == "tryton-realm-controller",
            ai_subject: actor.subject.starts_with("ai:"),
            ai_workload: actor.workload_id.starts_with("ai-"),
            final_approved: matches!(evidence.final_decision, FinalDecision::Approved),
            self_approval,
            requires_two_approvers: matches!(self.realm.financial_profile_id.as_str(), "F4" | "F5"),
            has_two_distinct_approvers: distinct_approvers.len() >= 2,
        })
    }
}

fn required_identity(value: String) -> Result<String, PolicyError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    Ok(value.to_owned())
}

fn decode_input(source: &[u8]) -> Result<Input, PolicyError> {
    if source.len() > MAX_DOCUMENT_BYTES || !json_nesting_within_limit(source) {
        return Err(PolicyError::InvalidInput);
    }
    let mut decoder = serde_json::Deserializer::from_slice(source);
    let Unique(value) =
        Unique::deserialize(&mut decoder).map_err(|_| PolicyError::InvalidInput)?;
    decoder.end().map_err(|_| PolicyError::InvalidInput)?;
    let root = value.as_object().ok_or(PolicyError::InvalidInput)?;
    for key in ["command", "realm", "evidence"] {
        if !root.get(key).is_some_and(Value::is_object) {
            return Err(PolicyError::InvalidInput);
        }
    }
    let command = root.get("command").and_then(Value::as_object).ok_or(PolicyError::InvalidInput)?;
    if !command.get("actor").is_some_and(Value::is_object) {
        return Err(PolicyError::InvalidInput);
    }
    if !root
        .get("evidence")
        .and_then(Value::as_object)
        .and_then(|evidence| evidence.get("approverSubjects"))
        .is_some_and(Value::is_array)
    {
        return Err(PolicyError::InvalidInput);
    }
    serde_json::from_value(value).map_err(|_| PolicyError::InvalidInput)
}

#[cfg(test)]
mod profile_shape_tests {
    use super::*;

    #[test]
    fn profile_admits_through_the_existing_boolean_v2_api() -> Result<(), PolicyError> {
        let profile = admit_profile()?;
        assert_eq!(profile.inner.profile(), v2_boolean::BOOLEAN_PREVIEW_PROFILE);
        assert_eq!(profile.source_sha256().len(), 64);
        Ok(())
    }
}
