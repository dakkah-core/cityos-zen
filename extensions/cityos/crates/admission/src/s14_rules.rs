//! Admission of the fixed S14 selector predicate. No caller supplies source.
//!
//! Rule and request strings are evaluation data, never expression text. The
//! admitted document has no imports, dynamic loaders, or caller-defined blocks.
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use cityos_zen_contracts::PolicyError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zen_engine::loader::{DecisionLoader, LoaderError, LoaderResponse};
use zen_engine::model::DecisionContent;
use zen_engine::policy::{DiagnosticCode, PolicyDocument, PolicyWorkspace, Severity};
use zen_engine::DecisionEngine;

pub const ENTRY: &str = "s14-rules-v1";
pub const GOAL: &str = "rule.matches";
const WRITER: &str = "s14-rule-match";
const EXPRESSION: &str = concat!(
    "(rule.action == \"\" or rule.action == rule.actualAction) and ",
    "(rule.purpose == \"\" or rule.purpose == rule.actualPurpose) and ",
    "(rule.resourceType == \"\" or rule.resourceType == rule.actualResourceType) and ",
    "(rule.subjectRef == \"\" or rule.subjectRef == rule.actualSubjectRef) and ",
    "(rule.tenantId == \"\" or rule.tenantId == rule.actualTenantId) and ",
    "(rule.cellId == \"\" or rule.cellId == rule.actualCellId)"
);
const FIELDS: [&str; 12] = [
    "action",
    "actualAction",
    "purpose",
    "actualPurpose",
    "resourceType",
    "actualResourceType",
    "subjectRef",
    "actualSubjectRef",
    "tenantId",
    "actualTenantId",
    "cellId",
    "actualCellId",
];

/// This capability can only contain the fixed document constructed here.
#[derive(Clone)]
pub struct AdmittedS14Rules {
    document: PolicyDocument,
    document_sha256: String,
}

impl AdmittedS14Rules {
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }

    /// Digest of the serialized fixed document, not the worker artifact.
    pub fn document_sha256(&self) -> &str {
        &self.document_sha256
    }
}

fn fixed_document() -> Result<PolicyDocument, PolicyError> {
    let properties: Vec<Value> = FIELDS
        .iter()
        .map(|name| {
            json!({
                "id": name, "name": name, "type": "string", "array": false, "optional": false
            })
        })
        .collect();
    // Both the model and expression are constructed exclusively from constants.
    serde_json::from_value(json!({"imports": [], "blocks": [
        {"id":"s14-rule-model", "type":"dataModel", "props":{"data":{
            "name":"rule", "properties":properties
        }}},
        {"id":WRITER, "type":"expression", "props":{"data":{
            "key":GOAL, "value":EXPRESSION
        }}}
    ]}))
    .map_err(|_| PolicyError::InvalidSource)
}

#[derive(Debug)]
struct FixedLoader {
    content: Arc<DecisionContent>,
    entry_reads: AtomicUsize,
    other_reads: AtomicUsize,
}

impl DecisionLoader for FixedLoader {
    fn load<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = LoaderResponse> + 'a + Send>> {
        self.other_reads.fetch_add(1, Ordering::Relaxed);
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
            self.other_reads.fetch_add(1, Ordering::Relaxed);
            Err(LoaderError::NotFound(key.to_owned()))
        })
    }
}

/// Construct, analyze and compile the sole admitted selector profile.
pub fn admit_fixed() -> Result<AdmittedS14Rules, PolicyError> {
    zen_expression::compile_expression(EXPRESSION).map_err(|_| PolicyError::Compile)?;
    let document = fixed_document()?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy(ENTRY, document.clone());
    // Grouping parentheses are required to make the intended conjunction
    // obvious. Permit only that specific hint on this fixed writer.
    if !workspace.document_uses(ENTRY).is_empty()
        || workspace.all_diagnostics().iter().any(|d| {
            d.code != DiagnosticCode::RedundantParentheses
                || d.severity != Severity::Hint
                || d.location.policy_path.as_ref() != ENTRY
                || d.location.block_id.as_deref() != Some(WRITER)
        })
    {
        return Err(PolicyError::Analysis);
    }
    let goal = workspace.dependencies_scoped(GOAL, Some(ENTRY));
    let writer = goal.written_by.as_ref().ok_or(PolicyError::Analysis)?;
    if goal.property.as_ref() != GOAL
        || goal.unresolved
        || writer.policy_path.as_ref() != ENTRY
        || writer.block_id.as_ref() != WRITER
    {
        return Err(PolicyError::Analysis);
    }
    let expected: BTreeSet<String> = FIELDS.iter().map(|field| format!("rule.{field}")).collect();
    let mut actual = BTreeSet::new();
    for dependency in &goal.deps {
        if dependency.unresolved
            || dependency.written_by.is_some()
            || !dependency.deps.is_empty()
            || !actual.insert(dependency.property.to_string())
        {
            return Err(PolicyError::Analysis);
        }
    }
    if actual != expected {
        return Err(PolicyError::Analysis);
    }
    let loader = Arc::new(FixedLoader {
        content: Arc::new(DecisionContent::Policy(Arc::new(document.clone()).into())),
        entry_reads: AtomicUsize::new(0),
        other_reads: AtomicUsize::new(0),
    });
    let engine = DecisionEngine::default().with_loader(loader.clone());
    if !engine.compile().is_empty()
        || loader.entry_reads.load(Ordering::Relaxed) == 0
        || loader.other_reads.load(Ordering::Relaxed) != 0
    {
        return Err(PolicyError::Compile);
    }
    let bytes = serde_json::to_vec(&document).map_err(|_| PolicyError::InvalidSource)?;
    let document_sha256 = format!("{:x}", Sha256::digest(bytes));
    Ok(AdmittedS14Rules {
        document,
        document_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_profile_is_admitted_and_has_only_the_expected_model_and_writer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let admitted = admit_fixed()?;
        let value = serde_json::to_value(admitted.document())?;
        assert_eq!(value["imports"], json!([]));
        let blocks = value["blocks"].as_array().ok_or("missing blocks")?;
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["id"], "s14-rule-model");
        assert_eq!(blocks[1]["id"], WRITER);
        assert_eq!(blocks[1]["props"]["data"]["key"], GOAL);
        assert_eq!(blocks[1]["props"]["data"]["value"], EXPRESSION);
        Ok(())
    }
}
