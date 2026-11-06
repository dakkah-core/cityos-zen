//! Restricted V2 Boolean/enum and exact integer/quantity previews only.
//!
//! The input is an extracted `{types, behavior}` pair, not a CityOS policy
//! publication. No policy selection, provenance, or authorization is implied.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use cityos_zen_contracts::{PolicyError, MAX_DOCUMENT_BYTES};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zen_engine::loader::{DecisionLoader, LoaderError, LoaderResponse};
use zen_engine::model::DecisionContent;
use zen_engine::policy::{
    Diagnostic, DiagnosticCode, EvaluateRequest, PolicyDocument, PolicyWorkspace, Severity,
};
use zen_engine::DecisionEngine;

use super::{json_nesting_within_limit, Unique};

const ENTRY: &str = "v2-boolean";
const GOAL: &str = "facts.result";
const WRITER: &str = "v2-result";
pub const BOOLEAN_PREVIEW_PROFILE: &str = "cityos.zen.v2-boolean-preview.v1";
pub const INTEGER_PREVIEW_PROFILE: &str = "cityos.zen.v2-safe-integer-comparison-preview.v1";

// Parentheses are deliberately emitted by the lowering to preserve grouping.
// Accept only Zen's corresponding hint on our generated expression; every
// other diagnostic, including a warning or error with that code, is fatal.
fn diagnostics_acceptable(diagnostics: &[Diagnostic]) -> bool {
    diagnostics.iter().all(|item| {
        item.code == DiagnosticCode::RedundantParentheses
            && item.severity == Severity::Hint
            && item.location.policy_path.as_ref() == ENTRY
            && item.location.block_id.as_deref() == Some(WRITER)
    })
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use zen_engine::policy::DiagnosticLocation;

    fn location(policy: &str, block: &str) -> DiagnosticLocation {
        DiagnosticLocation::expression(
            Arc::from(policy),
            Arc::from(block),
            Arc::from("value"),
            None,
        )
    }

    #[test]
    fn only_generated_parentheses_hints_are_nonfatal() {
        let expected = Diagnostic::hint(
            DiagnosticCode::RedundantParentheses,
            location(ENTRY, WRITER),
            "fixture",
        );
        assert!(diagnostics_acceptable(&[]));
        assert!(diagnostics_acceptable(&[expected]));
        for diagnostic in [
            Diagnostic::warning(
                DiagnosticCode::RedundantParentheses,
                location(ENTRY, WRITER),
                "fixture",
            ),
            Diagnostic::error(
                DiagnosticCode::RedundantParentheses,
                location(ENTRY, WRITER),
                "fixture",
            ),
            Diagnostic::hint(
                DiagnosticCode::ParseError,
                location(ENTRY, WRITER),
                "fixture",
            ),
            Diagnostic::hint(
                DiagnosticCode::RedundantParentheses,
                location("other", WRITER),
                "fixture",
            ),
            Diagnostic::hint(
                DiagnosticCode::RedundantParentheses,
                location(ENTRY, "other"),
                "fixture",
            ),
        ] {
            assert!(!diagnostics_acceptable(&[diagnostic]));
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    types: Vec<Type>,
    behavior: Behavior,
}

#[derive(Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Type {
    Boolean {
        type_ref: String,
    },
    Enum {
        type_ref: String,
        values: Vec<String>,
    },
    Integer {
        type_ref: String,
        minimum: i64,
        maximum: i64,
    },
    Quantity {
        type_ref: String,
        unit_ref: String,
        minimum: i64,
        maximum: i64,
    },
    Record {
        type_ref: String,
        fields: Vec<Field>,
    },
}

impl Type {
    fn name(&self) -> &str {
        match self {
            Self::Boolean { type_ref }
            | Self::Enum { type_ref, .. }
            | Self::Integer { type_ref, .. }
            | Self::Quantity { type_ref, .. }
            | Self::Record { type_ref, .. } => type_ref,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Field {
    name: String,
    type_ref: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Behavior {
    schema_version: String,
    behavior_id: String,
    version: String,
    owner_ref: String,
    kind: String,
    implementation: String,
    required_capabilities: Vec<String>,
    input_type_ref: String,
    result_type_ref: String,
    locals: Vec<Value>,
    expression: Expr,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Expr {
    Literal {
        node_id: String,
        type_ref: String,
        value: Value,
    },
    Ref {
        node_id: String,
        type_ref: String,
        source: String,
        path: Vec<String>,
    },
    Op {
        node_id: String,
        type_ref: String,
        operator: String,
        args: Vec<Expr>,
    },
}

fn valid_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
        && !s.contains("://")
}
fn valid_field(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && (s.as_bytes()[0].is_ascii_alphabetic() || s.as_bytes()[0] == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !["__proto__", "prototype", "constructor"].contains(&s)
}
fn semver(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}
fn decode(source: &[u8]) -> Result<Value, PolicyError> {
    if source.len() > MAX_DOCUMENT_BYTES || !json_nesting_within_limit(source) {
        return Err(PolicyError::InvalidSource);
    }
    let mut decoder = serde_json::Deserializer::from_slice(source);
    let Unique(value) =
        Unique::deserialize(&mut decoder).map_err(|_| PolicyError::InvalidSource)?;
    decoder.end().map_err(|_| PolicyError::InvalidSource)?;
    Ok(value)
}

/// An admitted, immutable lowering. The digest identifies input bytes only.
/// The underlying document and encoded input stay private so evaluation cannot
/// bypass closed input validation through this capability.
///
/// ```compile_fail
/// use cityos_zen_admission::v2_boolean::AdmittedV2Boolean;
/// fn bypass(policy: &AdmittedV2Boolean) { let _ = policy.document(); }
/// ```
#[derive(Clone)]
pub struct AdmittedV2Boolean {
    document: PolicyDocument,
    fields: Vec<Field>,
    types: BTreeMap<String, Type>,
    source_sha256: String,
    profile: &'static str,
}
impl AdmittedV2Boolean {
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// Identifies the admission semantics, not qualification or authority.
    pub fn profile(&self) -> &'static str {
        self.profile
    }

    /// Validate the entire closed V2 input before encoding finite enum values.
    fn encode_input(&self, source: &[u8]) -> Result<Value, PolicyError> {
        let value = decode(source).map_err(|_| PolicyError::InvalidInput)?;
        let input = value.as_object().ok_or(PolicyError::InvalidInput)?;
        if input.len() != self.fields.len() {
            return Err(PolicyError::InvalidInput);
        }
        let mut facts = Map::new();
        for (i, field) in self.fields.iter().enumerate() {
            let value = input.get(&field.name).ok_or(PolicyError::InvalidInput)?;
            let encoded = encode_scalar(
                self.types
                    .get(&field.type_ref)
                    .ok_or(PolicyError::InvalidInput)?,
                value,
            )
            .ok_or(PolicyError::InvalidInput)?;
            facts.insert(format!("f{i}"), encoded);
        }
        Ok(json!({"facts": facts}))
    }

    /// Calculate only after validation. This result does not grant authority.
    pub fn evaluate(&self, source: &[u8]) -> Result<bool, PolicyError> {
        let input = self.encode_input(source)?;
        let mut workspace = PolicyWorkspace::new();
        workspace.set_policy(ENTRY, self.document.clone());
        let evaluation = workspace
            .evaluate(&EvaluateRequest {
                policy_path: Arc::from(ENTRY),
                input: input.into(),
                goals: vec![Arc::from(GOAL)],
                trace: false,
            })
            .map_err(|_| PolicyError::Evaluation)?;
        let output: Value = evaluation.output.into();
        output
            .get("facts")
            .and_then(|v| v.get("result"))
            .and_then(Value::as_bool)
            .ok_or(PolicyError::Evaluation)
    }
}

fn encode_scalar(ty: &Type, value: &Value) -> Option<Value> {
    match ty {
        Type::Boolean { .. } => value.as_bool().map(Value::Bool),
        Type::Enum { values, .. } => values
            .iter()
            .position(|v| Some(v.as_str()) == value.as_str())
            .map(|n| json!(n)),
        Type::Integer { minimum, maximum, .. } | Type::Quantity { minimum, maximum, .. } => value.as_i64()
            .filter(|n| (*minimum..=*maximum).contains(n))
            .map(|n| json!(n)),
        Type::Record { .. } => None,
    }
}

struct Lower<'a> {
    types: &'a BTreeMap<String, Type>,
    fields: &'a [Field],
    nodes: BTreeSet<String>,
    reads: BTreeSet<String>,
}
impl Lower<'_> {
    fn expression(&mut self, expr: &Expr, depth: usize) -> Result<(String, String), PolicyError> {
        if depth > 16 || self.nodes.len() >= 128 {
            return Err(PolicyError::Unsupported);
        }
        let (id, type_ref) = match expr {
            Expr::Literal {
                node_id, type_ref, ..
            }
            | Expr::Ref {
                node_id, type_ref, ..
            }
            | Expr::Op {
                node_id, type_ref, ..
            } => (node_id, type_ref),
        };
        if !valid_ref(id) || !self.nodes.insert(id.clone()) {
            return Err(PolicyError::Unsupported);
        }
        let ty = self.types.get(type_ref).ok_or(PolicyError::Unsupported)?;
        let text = match expr {
            Expr::Literal { value, .. } => encode_scalar(ty, value)
                .ok_or(PolicyError::Unsupported)?
                .to_string(),
            Expr::Ref { source, path, .. } => {
                if source != "input" || path.len() != 1 {
                    return Err(PolicyError::Unsupported);
                }
                let (index, field) = self
                    .fields
                    .iter()
                    .enumerate()
                    .find(|(_, f)| f.name == path[0])
                    .ok_or(PolicyError::Unsupported)?;
                if field.type_ref != *type_ref {
                    return Err(PolicyError::Unsupported);
                }
                let name = format!("facts.f{index}");
                self.reads.insert(name.clone());
                name
            }
            Expr::Op { operator, args, .. } => {
                if !matches!(ty, Type::Boolean { .. }) {
                    return Err(PolicyError::Unsupported);
                }
                let arity = if operator == "not" { 1 } else { 2 };
                if args.len() != arity {
                    return Err(PolicyError::Unsupported);
                }
                let mut children = Vec::new();
                for arg in args {
                    children.push(self.expression(arg, depth + 1)?);
                }
                let bool_child =
                    |i: usize| matches!(self.types.get(&children[i].0), Some(Type::Boolean { .. }));
                match operator.as_str() {
                    "not" if bool_child(0) => format!("(not {})", children[0].1),
                    "and" | "or" if bool_child(0) && bool_child(1) => {
                        format!("({} {} {})", children[0].1, operator, children[1].1)
                    }
                    "eq" | "neq" if children[0].0 == children[1].0 => format!(
                        "({} {} {})",
                        children[0].1,
                        if operator == "eq" { "==" } else { "!=" },
                        children[1].1
                    ),
                    "lt" | "lte" | "gt" | "gte"
                        if children[0].0 == children[1].0
                            && matches!(self.types.get(&children[0].0), Some(Type::Integer { .. } | Type::Quantity { .. })) => {
                        let op = match operator.as_str() {
                            "lt" => "<", "lte" => "<=", "gt" => ">", "gte" => ">=",
                            _ => return Err(PolicyError::Unsupported),
                        };
                        format!("({} {} {})", children[0].1, op, children[1].1)
                    }
                    _ => return Err(PolicyError::Unsupported),
                }
            }
        };
        Ok((type_ref.clone(), text))
    }
}

#[derive(Debug)]
struct Loader {
    content: Arc<DecisionContent>,
    entry: AtomicUsize,
    other: AtomicUsize,
}
impl DecisionLoader for Loader {
    fn keys(&self) -> Option<Vec<Arc<str>>> {
        Some(vec![Arc::from(ENTRY)])
    }
    fn load_sync(&self, key: &str) -> Option<LoaderResponse> {
        Some(if key == ENTRY {
            self.entry.fetch_add(1, Ordering::Relaxed);
            Ok(self.content.clone())
        } else {
            self.other.fetch_add(1, Ordering::Relaxed);
            Err(LoaderError::NotFound(key.to_owned()))
        })
    }
    fn load<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = LoaderResponse> + Send + 'a>> {
        self.other.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Err(LoaderError::NotFound(key.to_owned())) })
    }
}

/// Admit only flat Boolean/finite-enum V2 expressions; all other V2 features fail.
pub fn admit(source: &[u8]) -> Result<AdmittedV2Boolean, PolicyError> {
    admit_profile(source, false)
}

/// Admit finite safe-integer and unit-identified quantity comparisons. This is
/// a distinct preview profile; it does not admit arithmetic or coercion.
pub fn admit_integer_preview(source: &[u8]) -> Result<AdmittedV2Boolean, PolicyError> {
    admit_profile(source, true)
}

fn admit_profile(source: &[u8], integer_profile: bool) -> Result<AdmittedV2Boolean, PolicyError> {
    let value = decode(source)?;
    // Serde struct visitors can accept positional sequences. V2 requires
    // objects, including nested record fields, at every struct boundary.
    let root = value.as_object().ok_or(PolicyError::Unsupported)?;
    let declared = root
        .get("types")
        .and_then(Value::as_array)
        .ok_or(PolicyError::Unsupported)?;
    if !root.get("behavior").is_some_and(Value::is_object)
        || declared.iter().any(|ty| {
            let Some(ty) = ty.as_object() else {
                return true;
            };
            ty.get("kind").and_then(Value::as_str) == Some("record")
                && !ty
                    .get("fields")
                    .and_then(Value::as_array)
                    .is_some_and(|fields| fields.iter().all(Value::is_object))
        })
    {
        return Err(PolicyError::Unsupported);
    }
    let parsed: Source = serde_json::from_value(value).map_err(|_| PolicyError::Unsupported)?;
    if parsed.types.len() > 256 {
        return Err(PolicyError::Unsupported);
    }
    let mut types = BTreeMap::new();
    for ty in parsed.types {
        if !valid_ref(ty.name()) {
            return Err(PolicyError::Unsupported);
        }
        match &ty {
            Type::Integer { minimum, maximum, .. } | Type::Quantity { minimum, maximum, .. } => {
                const SAFE: i64 = 9_007_199_254_740_991;
                if !integer_profile || *minimum < -SAFE || *maximum > SAFE || minimum > maximum
                    || matches!(&ty, Type::Quantity { unit_ref, .. } if !valid_ref(unit_ref)) {
                    return Err(PolicyError::Unsupported);
                }
            }
            Type::Enum { values, .. } => {
                let unique: BTreeSet<_> = values.iter().collect();
                if values.is_empty()
                    || values.len() > 256
                    || unique.len() != values.len()
                    || values
                        .iter()
                        .any(|v| v.is_empty() || v.encode_utf16().count() > 128)
                {
                    return Err(PolicyError::Unsupported);
                }
            }
            Type::Record { fields, .. } => {
                let unique: BTreeSet<_> = fields.iter().map(|f| &f.name).collect();
                if fields.len() > 256
                    || unique.len() != fields.len()
                    || fields
                        .iter()
                        .any(|f| !valid_field(&f.name) || !valid_ref(&f.type_ref))
                {
                    return Err(PolicyError::Unsupported);
                }
            }
            _ => {}
        }
        if types.insert(ty.name().to_owned(), ty).is_some() {
            return Err(PolicyError::Unsupported);
        }
    }
    let b = parsed.behavior;
    let caps: BTreeSet<_> = b.required_capabilities.iter().collect();
    if b.schema_version != "cityos.behavior-definition.v2"
        || !valid_ref(&b.behavior_id)
        || !semver(&b.version)
        || !valid_ref(&b.owner_ref)
        || b.kind != "decision"
        || b.implementation != "generated"
        || !b.locals.is_empty()
        || b.required_capabilities.len() > 256
        || caps.len() != b.required_capabilities.len()
        || b.required_capabilities.iter().any(|s| !valid_ref(s))
    {
        return Err(PolicyError::Unsupported);
    }
    // Reject unrelated nested/invalid types as well: this profile's whole type graph is flat.
    for ty in types.values() {
        if let Type::Record { fields, .. } = ty {
            if fields.iter().any(|f| {
                !matches!(
                    types.get(&f.type_ref),
                    Some(Type::Boolean { .. } | Type::Enum { .. } | Type::Integer { .. } | Type::Quantity { .. })
                )
            }) {
                return Err(PolicyError::Unsupported);
            }
        }
    }
    let fields = match types.get(&b.input_type_ref) {
        Some(Type::Record { fields, .. }) => fields.clone(),
        _ => return Err(PolicyError::Unsupported),
    };
    if !matches!(types.get(&b.result_type_ref), Some(Type::Boolean { .. })) {
        return Err(PolicyError::Unsupported);
    }
    let mut lower = Lower {
        types: &types,
        fields: &fields,
        nodes: BTreeSet::new(),
        reads: BTreeSet::new(),
    };
    let (result_type, expression) = lower.expression(&b.expression, 0)?;
    if result_type != b.result_type_ref {
        return Err(PolicyError::Unsupported);
    }
    zen_expression::compile_expression(&expression).map_err(|_| PolicyError::Compile)?;
    let properties: Vec<_> = fields.iter().enumerate().map(|(i, f)| json!({
        "id":format!("f{i}"), "name":format!("f{i}"),
        "type":if matches!(types.get(&f.type_ref), Some(Type::Boolean { .. })) {"boolean"} else {"number"},
        "array":false, "optional":false
    })).collect();
    let document: PolicyDocument = serde_json::from_value(json!({"imports":[], "blocks":[
        {"id":"v2-model", "type":"dataModel", "props":{"data":{"name":"facts", "properties":properties}}},
        {"id":WRITER, "type":"expression", "props":{"data":{"key":GOAL, "value":expression}}}
    ]})).map_err(|_| PolicyError::Compile)?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy(ENTRY, document.clone());
    if !diagnostics_acceptable(&workspace.all_diagnostics())
        || !workspace.document_uses(ENTRY).is_empty()
    {
        return Err(PolicyError::Analysis);
    }
    let goal = workspace.dependencies_scoped(GOAL, Some(ENTRY));
    let writer = goal.written_by.as_ref().ok_or(PolicyError::Analysis)?;
    if goal.unresolved
        || goal.property.as_ref() != GOAL
        || writer.policy_path.as_ref() != ENTRY
        || writer.block_id.as_ref() != WRITER
    {
        return Err(PolicyError::Analysis);
    }
    let mut reads = BTreeSet::new();
    for dep in &goal.deps {
        if dep.unresolved
            || dep.written_by.is_some()
            || !dep.deps.is_empty()
            || !reads.insert(dep.property.to_string())
        {
            return Err(PolicyError::Analysis);
        }
    }
    if reads != lower.reads {
        return Err(PolicyError::Analysis);
    }
    let loader = Arc::new(Loader {
        content: Arc::new(DecisionContent::Policy(Arc::new(document.clone()).into())),
        entry: AtomicUsize::new(0),
        other: AtomicUsize::new(0),
    });
    if !DecisionEngine::default()
        .with_loader(loader.clone())
        .compile()
        .is_empty()
        || loader.entry.load(Ordering::Relaxed) == 0
        || loader.other.load(Ordering::Relaxed) != 0
    {
        return Err(PolicyError::Compile);
    }
    Ok(AdmittedV2Boolean {
        document,
        fields,
        types,
        source_sha256: format!("{:x}", Sha256::digest(source)),
        profile: if integer_profile { INTEGER_PREVIEW_PROFILE } else { BOOLEAN_PREVIEW_PROFILE },
    })
}
