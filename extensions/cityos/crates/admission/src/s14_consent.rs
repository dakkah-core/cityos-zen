//! Admission for one fixed, non-authoritative S14 consent preview document.
//!
//! The digest identifies source bytes, not a qualified policy or build.
use super::{json_nesting_within_limit, Unique};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use cityos_zen_contracts::{PolicyError, MAX_DOCUMENT_BYTES, S14_CONSENT_SOURCE_SHA256};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use zen_engine::loader::{DecisionLoader, LoaderError, LoaderResponse};
use zen_engine::model::DecisionContent;
use zen_engine::policy::{DependencyNode, PolicyDocument, PolicyWorkspace};
use zen_engine::DecisionEngine;

const ENTRY: &str = "s14-consent";
const GOAL: &str = "consent.satisfied";
const WRITER: &str = "s14-consent-gate";
const EXPRESSION: &str = "consent.required == false or (consent.granted and (consent.hasExpiry == false or consent.now < consent.expiresAt))";

/// An admitted copy of the single fixed preview document and its original digest.
/// Only this module can construct it; it carries no authorization or qualification.
#[derive(Clone)]
pub struct AdmittedS14Consent {
    document: PolicyDocument,
    source_sha256: String,
}

impl AdmittedS14Consent {
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

/// Admit only the original bytes of the fixed S14 consent preview.
/// No arbitrary policy source or general Zen profile is admitted by this API.
pub fn admit_fixed(source: &[u8]) -> Result<AdmittedS14Consent, PolicyError> {
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err(PolicyError::InvalidSource);
    }
    let digest = format!("{:x}", Sha256::digest(source));
    if digest != S14_CONSENT_SOURCE_SHA256 {
        return Err(PolicyError::InvalidSource);
    }
    // Verify the original bytes before Zen's deserialization can discard details.
    let document = decode_and_validate(source)?;
    analyze_and_compile(&document)?;
    Ok(AdmittedS14Consent { document, source_sha256: digest })
}

fn decode_and_validate(source: &[u8]) -> Result<PolicyDocument, PolicyError> {
    if source.len() > MAX_DOCUMENT_BYTES || !json_nesting_within_limit(source) {
        return Err(PolicyError::InvalidSource);
    }
    let mut decoder = serde_json::Deserializer::from_slice(source);
    let Unique(value) = Unique::deserialize(&mut decoder).map_err(|_| PolicyError::InvalidSource)?;
    decoder.end().map_err(|_| PolicyError::InvalidSource)?;

    // The complete shape and expression are independent of Zen's permissive
    // BlockDoc decoder, which can otherwise silently ignore unknown blocks.
    let expected = json!({
        "imports": [],
        "blocks": [
            {"id":"s14-consent-model", "type":"dataModel", "props":{"data":{
                "name":"consent", "properties":[
                    {"id":"required","name":"required","type":"boolean","array":false,"optional":false},
                    {"id":"granted","name":"granted","type":"boolean","array":false,"optional":false},
                    {"id":"has-expiry","name":"hasExpiry","type":"boolean","array":false,"optional":false},
                    {"id":"now","name":"now","type":"number","array":false,"optional":false},
                    {"id":"expires-at","name":"expiresAt","type":"number","array":false,"optional":false}
                ]
            }}},
            {"id":WRITER,"type":"expression","props":{"data":{"key":GOAL,"value":EXPRESSION}}}
        ]
    });
    if value != expected {
        return Err(PolicyError::Unsupported);
    }
    // This fixed expression, rather than arbitrary parsed input, is the entire
    // expression profile; compilation failure is never interpreted as success.
    zen_expression::compile_expression(EXPRESSION).map_err(|_| PolicyError::Compile)?;
    serde_json::from_value(value).map_err(|_| PolicyError::InvalidSource)
}

fn validate_goal(goal: &DependencyNode) -> Result<(), PolicyError> {
    let writer = goal.written_by.as_ref().ok_or(PolicyError::Analysis)?;
    if goal.property.as_ref() != GOAL || goal.unresolved
        || writer.policy_path.as_ref() != ENTRY || writer.block_id.as_ref() != WRITER
    {
        return Err(PolicyError::Analysis);
    }
    // Enumerated independently from the engine's analysis and document parser.
    let expected = BTreeSet::from([
        "consent.required", "consent.granted", "consent.hasExpiry",
        "consent.now", "consent.expiresAt",
    ]);
    let mut actual = BTreeSet::new();
    for dependency in &goal.deps {
        if dependency.unresolved || dependency.written_by.is_some()
            || !dependency.deps.is_empty() || !actual.insert(dependency.property.as_ref())
        {
            return Err(PolicyError::Analysis);
        }
    }
    if actual != expected {
        return Err(PolicyError::Analysis);
    }
    Ok(())
}

#[derive(Debug)]
struct FixedLoader {
    content: Arc<DecisionContent>,
    entry_reads: AtomicUsize,
    unexpected_reads: AtomicUsize,
    dynamic_reads: AtomicUsize,
}

impl DecisionLoader for FixedLoader {
    fn load<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = LoaderResponse> + 'a + Send>> {
        self.dynamic_reads.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Err(LoaderError::NotFound(key.to_owned())) })
    }

    fn keys(&self) -> Option<Vec<Arc<str>>> {
        Some(vec![Arc::from(ENTRY)])
    }

    fn load_sync(&self, key: &str) -> Option<LoaderResponse> {
        Some(if key == ENTRY {
            self.entry_reads.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::clone(&self.content))
        } else {
            self.unexpected_reads.fetch_add(1, Ordering::Relaxed);
            Err(LoaderError::NotFound(key.to_owned()))
        })
    }
}

fn analyze_and_compile(document: &PolicyDocument) -> Result<(), PolicyError> {
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy(ENTRY, document.clone());
    if !workspace.all_diagnostics().is_empty() || !workspace.document_uses(ENTRY).is_empty() {
        return Err(PolicyError::Analysis);
    }
    validate_goal(&workspace.dependencies_scoped(GOAL, Some(ENTRY)))?;

    let loader = Arc::new(FixedLoader {
        content: Arc::new(DecisionContent::Policy(Arc::new(document.clone()).into())),
        entry_reads: AtomicUsize::new(0),
        unexpected_reads: AtomicUsize::new(0),
        dynamic_reads: AtomicUsize::new(0),
    });
    let engine = DecisionEngine::default().with_loader(loader.clone());
    if !engine.compile().is_empty()
        || loader.entry_reads.load(Ordering::Relaxed) == 0
        || loader.unexpected_reads.load(Ordering::Relaxed) != 0
        || loader.dynamic_reads.load(Ordering::Relaxed) != 0
    {
        return Err(PolicyError::Compile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SOURCE: &[u8] = include_bytes!("../../../corpus/s14-consent-preview.json");

    #[test]
    fn exact_source_is_admitted_and_any_byte_change_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(S14_CONSENT_SOURCE_SHA256, "70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543");
        let admitted = admit_fixed(SOURCE)?;
        assert_eq!(admitted.source_sha256(), S14_CONSENT_SOURCE_SHA256);
        let mut changed = SOURCE.to_vec();
        changed.push(b' ');
        assert!(matches!(admit_fixed(&changed), Err(PolicyError::InvalidSource)));
        Ok(())
    }

    #[test]
    fn original_byte_decoder_rejects_ambiguity_and_unsupported_content() -> Result<(), Box<dyn std::error::Error>> {
        let source = std::str::from_utf8(SOURCE)?;
        let duplicate = source.replace("\"imports\": []", "\"imports\": [], \"imports\": []");
        assert_ne!(duplicate, source);
        assert!(matches!(decode_and_validate(duplicate.as_bytes()), Err(PolicyError::InvalidSource)));
        let nested_duplicate = source.replace("\"key\":\"consent.satisfied\"", "\"key\":\"consent.satisfied\",\"key\":\"consent.satisfied\"");
        assert_ne!(nested_duplicate, source);
        assert!(matches!(decode_and_validate(nested_duplicate.as_bytes()), Err(PolicyError::InvalidSource)));
        for candidate in [
            source.replace("\"imports\": []", "\"imports\": [\"external\"]"),
            source.replace("\"type\": \"dataModel\"", "\"type\": \"unknownBlock\""),
            source.replace(EXPRESSION, "true"),
        ] {
            assert_ne!(candidate, source);
            assert!(matches!(decode_and_validate(candidate.as_bytes()), Err(PolicyError::Unsupported)));
            assert!(admit_fixed(candidate.as_bytes()).is_err());
        }
        assert!(matches!(decode_and_validate(&vec![b' '; MAX_DOCUMENT_BYTES + 1]), Err(PolicyError::InvalidSource)));
        assert!(matches!(decode_and_validate(&[0xff]), Err(PolicyError::InvalidSource)));
        let deep = format!("{}null{}", "[".repeat(33), "]".repeat(33));
        assert!(matches!(decode_and_validate(deep.as_bytes()), Err(PolicyError::InvalidSource)));
        Ok(())
    }

    #[test]
    fn incomplete_or_ambiguous_goal_analysis_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let document = decode_and_validate(SOURCE)?;
        let mut workspace = PolicyWorkspace::new();
        workspace.set_policy(ENTRY, document);
        let goal = workspace.dependencies_scoped(GOAL, Some(ENTRY));
        validate_goal(&goal)?;
        let mut missing = goal.clone();
        missing.deps.pop();
        assert_eq!(validate_goal(&missing), Err(PolicyError::Analysis));
        let mut unresolved = goal.clone();
        unresolved.unresolved = true;
        assert_eq!(validate_goal(&unresolved), Err(PolicyError::Analysis));
        let mut unresolved_input = goal.clone();
        unresolved_input.deps[0].unresolved = true;
        assert_eq!(validate_goal(&unresolved_input), Err(PolicyError::Analysis));
        let mut duplicate = goal.clone();
        duplicate.deps.push(duplicate.deps[0].clone());
        assert_eq!(validate_goal(&duplicate), Err(PolicyError::Analysis));
        let mut wrong_writer = goal.clone();
        wrong_writer.written_by.as_mut().ok_or("missing writer")?.block_id = Arc::from("other");
        assert_eq!(validate_goal(&wrong_writer), Err(PolicyError::Analysis));
        let mut computed = goal.clone();
        computed.deps[0].written_by = goal.written_by.clone();
        assert_eq!(validate_goal(&computed), Err(PolicyError::Analysis));
        let mut missing_writer = goal.clone();
        missing_writer.written_by = None;
        assert_eq!(validate_goal(&missing_writer), Err(PolicyError::Analysis));
        let mut nested = goal.clone();
        nested.deps[0].deps.push(goal.deps[1].clone());
        assert_eq!(validate_goal(&nested), Err(PolicyError::Analysis));
        Ok(())
    }

    #[test]
    fn invalid_zen_analysis_cannot_be_admitted() -> Result<(), Box<dyn std::error::Error>> {
        let mut value: Value = serde_json::from_slice(SOURCE)?;
        value["blocks"][1]["props"]["data"]["value"] = "nonexistentVar + 1".into();
        let document: PolicyDocument = serde_json::from_value(value)?;
        let mut workspace = PolicyWorkspace::new();
        workspace.set_policy(ENTRY, document.clone());
        assert!(!workspace.all_diagnostics().is_empty());
        assert_eq!(analyze_and_compile(&document), Err(PolicyError::Analysis));
        Ok(())
    }
}
