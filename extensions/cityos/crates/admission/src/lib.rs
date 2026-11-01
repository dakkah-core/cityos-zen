//! A deliberately narrow, source-local preview profile. Not an authority boundary.
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use bumpalo::Bump;
use cityos_zen_contracts::{PolicyError, MAX_DOCUMENT_BYTES, MAX_SAFE_INTEGER};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};
use zen_engine::loader::{DecisionLoader, LoaderError, LoaderResponse};
use zen_engine::model::DecisionContent;
use zen_engine::policy::{DependencyNode, PolicyDocument, PolicyWorkspace};
use zen_engine::DecisionEngine;
use zen_expression::lexer::{ComparisonOperator, Lexer, LogicalOperator, Operator, TokenKind};
use zen_expression::parser::{Node, Parser};

// Bound parser work before constructing or traversing an expression AST.
const MAX_EXPRESSION_TOKENS: usize = 128;
// The fixed preview document is shallow; bound recursive JSON deserialization
// before the deserializer constructs values from unsupported input.
const MAX_JSON_NESTING: usize = 32;

/// Only this crate can construct an admitted preview document.
#[derive(Clone)]
pub struct AdmittedPreview {
    document: PolicyDocument,
    source_sha256: String,
}

impl AdmittedPreview {
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

/// The first profile admits exactly one entry and no imports or live fallback.
#[derive(Debug)]
struct ImmutableLoader {
    content: Arc<DecisionContent>,
    entry_reads: AtomicUsize,
    unexpected_reads: AtomicUsize,
    dynamic_reads: AtomicUsize,
}

impl ImmutableLoader {
    fn compiled_expected_entry_only(&self) -> bool {
        self.entry_reads.load(Ordering::Relaxed) > 0
            && self.unexpected_reads.load(Ordering::Relaxed) == 0
            && self.dynamic_reads.load(Ordering::Relaxed) == 0
    }
}

impl DecisionLoader for ImmutableLoader {
    fn load<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = LoaderResponse> + 'a + Send>> {
        self.dynamic_reads.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Err(LoaderError::NotFound(key.to_owned())) })
    }

    fn keys(&self) -> Option<Vec<Arc<str>>> {
        Some(vec![Arc::from("cart")])
    }

    fn load_sync(&self, key: &str) -> Option<LoaderResponse> {
        Some(if key == "cart" {
            self.entry_reads.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::clone(&self.content))
        } else {
            self.unexpected_reads.fetch_add(1, Ordering::Relaxed);
            Err(LoaderError::NotFound(key.to_owned()))
        })
    }
}

// Deserialize before Value creation so duplicate keys and imprecise numbers cannot disappear.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value with unique keys and safe integer numbers")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Unique, E> {
                if value.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Unique(Value::Number(Number::from(value))))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Unique, E> {
                if value > MAX_SAFE_INTEGER {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Unique(Value::Number(Number::from(value))))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Unique, E> {
                Err(E::custom("fractional and exponent numbers are unsupported"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(value)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Boolean,
    Integer,
}

fn expression_type(
    node: &Node<'_>,
    depth: usize,
    reads: &mut BTreeSet<&'static str>,
) -> Result<Ty, PolicyError> {
    if depth > 32 {
        return Err(PolicyError::Unsupported);
    }
    match node {
        Node::Bool(_) => Ok(Ty::Boolean),
        Node::Number(value) => {
            let text = value.to_string();
            let n = text.parse::<i64>().map_err(|_| PolicyError::Unsupported)?;
            if n.unsigned_abs() > MAX_SAFE_INTEGER {
                return Err(PolicyError::Unsupported);
            }
            Ok(Ty::Integer)
        }
        Node::Parenthesized(inner) => expression_type(inner, depth + 1, reads),
        Node::Member { node, property } => match (&**node, &**property) {
            (Node::Identifier("cart"), Node::String("quantity")) => {
                reads.insert("cart.quantity");
                Ok(Ty::Integer)
            }
            (Node::Identifier("cart"), Node::String("maxQuantity")) => {
                reads.insert("cart.maxQuantity");
                Ok(Ty::Integer)
            }
            (Node::Identifier("cart"), Node::String("authorized")) => {
                reads.insert("cart.authorized");
                Ok(Ty::Boolean)
            }
            _ => Err(PolicyError::Unsupported),
        },
        Node::Unary {
            node,
            operator: Operator::Logical(LogicalOperator::Not),
        } if expression_type(node, depth + 1, reads)? == Ty::Boolean => Ok(Ty::Boolean),
        Node::Binary {
            left,
            right,
            operator,
        } => {
            let left = expression_type(left, depth + 1, reads)?;
            let right = expression_type(right, depth + 1, reads)?;
            match operator {
                Operator::Logical(LogicalOperator::And | LogicalOperator::Or)
                    if left == Ty::Boolean && right == Ty::Boolean =>
                {
                    Ok(Ty::Boolean)
                }
                Operator::Comparison(ComparisonOperator::Equal | ComparisonOperator::NotEqual)
                    if left == right =>
                {
                    Ok(Ty::Boolean)
                }
                Operator::Comparison(
                    ComparisonOperator::LessThan
                    | ComparisonOperator::LessThanOrEqual
                    | ComparisonOperator::GreaterThan
                    | ComparisonOperator::GreaterThanOrEqual,
                ) if left == Ty::Integer && right == Ty::Integer => Ok(Ty::Boolean),
                _ => Err(PolicyError::Unsupported),
            }
        }
        _ => Err(PolicyError::Unsupported),
    }
}

fn validate_expression(source: &str) -> Result<BTreeSet<&'static str>, PolicyError> {
    // Templates are outside this profile. Reject their delimiter before Zen's
    // lexer, which recursively scans nested template interpolations before the
    // token budget can be checked.
    if source.is_empty() || source.len() > 4096 || source.as_bytes().contains(&b'`') {
        return Err(PolicyError::Unsupported);
    }
    let bump = Bump::new();
    let mut lexer = Lexer::new();
    let tokens = lexer
        .tokenize(&bump, source)
        .map_err(|_| PolicyError::Unsupported)?;
    if tokens.len() > MAX_EXPRESSION_TOKENS {
        return Err(PolicyError::Unsupported);
    }
    if tokens.iter().any(|token| {
        token.kind == TokenKind::Number
            && (!token.value.chars().all(|c| c.is_ascii_digit())
                || (token.value.len() > 1 && token.value.starts_with('0')))
    }) {
        return Err(PolicyError::Unsupported);
    }
    let parser = Parser::try_new(&tokens, &bump)
        .map_err(|_| PolicyError::Unsupported)?
        .standard();
    let parsed = parser.parse();
    parsed.error().map_err(|_| PolicyError::Unsupported)?;
    let mut reads = BTreeSet::new();
    if expression_type(parsed.root, 0, &mut reads)? != Ty::Boolean {
        return Err(PolicyError::Unsupported);
    }
    zen_expression::compile_expression(source).map_err(|_| PolicyError::Compile)?;
    Ok(reads)
}

// Check Zen's own goal analysis against the independently restricted expression AST.
// A missing writer, unresolved path, additional computed rule, or incomplete read
// set cannot serve as evidence of a closed deterministic preview.
fn validate_goal_closure(
    goal: &DependencyNode,
    expected_reads: &BTreeSet<&str>,
) -> Result<(), PolicyError> {
    let writer = goal.written_by.as_ref().ok_or(PolicyError::Analysis)?;
    if goal.property.as_ref() != "cart.allowed"
        || goal.unresolved
        || writer.policy_path.as_ref() != "cart"
        || writer.block_id.as_ref() != "cart-decision"
    {
        return Err(PolicyError::Analysis);
    }
    let mut actual_reads = BTreeSet::new();
    for dependency in &goal.deps {
        if dependency.unresolved
            || dependency.written_by.is_some()
            || !dependency.deps.is_empty()
            || !actual_reads.insert(dependency.property.as_ref())
        {
            return Err(PolicyError::Analysis);
        }
    }
    if &actual_reads != expected_reads {
        return Err(PolicyError::Analysis);
    }
    Ok(())
}

fn json_nesting_within_limit(source: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in source {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_NESTING {
                        return false;
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    true
}

/// Admit a single fixed-shape policy document for synthetic cart previews.
/// No imports, computed fact acquisition or authorizing receipt are supported.
pub fn admit(source: &[u8]) -> Result<AdmittedPreview, PolicyError> {
    if source.len() > MAX_DOCUMENT_BYTES || !json_nesting_within_limit(source) {
        return Err(PolicyError::InvalidSource);
    }
    let mut decoder = serde_json::Deserializer::from_slice(source);
    let Unique(value) =
        Unique::deserialize(&mut decoder).map_err(|_| PolicyError::InvalidSource)?;
    decoder.end().map_err(|_| PolicyError::InvalidSource)?;
    let root = value.as_object().ok_or(PolicyError::InvalidSource)?;
    if root.keys().any(|key| key != "blocks" && key != "imports") {
        return Err(PolicyError::Unsupported);
    }
    if let Some(imports) = root.get("imports") {
        if imports
            .as_array()
            .filter(|items| items.is_empty())
            .is_none()
        {
            return Err(PolicyError::Unsupported);
        }
    }
    let blocks = root
        .get("blocks")
        .and_then(Value::as_array)
        .ok_or(PolicyError::InvalidSource)?;
    if blocks.len() != 2 {
        return Err(PolicyError::Unsupported);
    }
    let expected_model = json!({"id":"cart-model", "type":"dataModel", "props":{"data":{
    "name":"cart", "properties":[
        {"id":"quantity", "name":"quantity", "type":"number", "array":false, "optional":false},
        {"id":"max", "name":"maxQuantity", "type":"number", "array":false, "optional":false},
        {"id":"authorized", "name":"authorized", "type":"boolean", "array":false, "optional":false}
    ]}}});
    if blocks[0] != expected_model {
        return Err(PolicyError::Unsupported);
    }
    let expression = blocks[1].as_object().ok_or(PolicyError::Unsupported)?;
    if expression
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["id", "props", "type"])
        || expression.get("id").and_then(Value::as_str) != Some("cart-decision")
        || expression.get("type").and_then(Value::as_str) != Some("expression")
    {
        return Err(PolicyError::Unsupported);
    }
    let props = expression
        .get("props")
        .and_then(Value::as_object)
        .ok_or(PolicyError::Unsupported)?;
    if props.len() != 1 {
        return Err(PolicyError::Unsupported);
    }
    let data = props
        .get("data")
        .and_then(Value::as_object)
        .ok_or(PolicyError::Unsupported)?;
    if data.len() != 2 || data.get("key").and_then(Value::as_str) != Some("cart.allowed") {
        return Err(PolicyError::Unsupported);
    }
    let expected_reads = validate_expression(
        data.get("value")
            .and_then(Value::as_str)
            .ok_or(PolicyError::Unsupported)?,
    )?;
    let document: PolicyDocument =
        serde_json::from_value(value).map_err(|_| PolicyError::InvalidSource)?;
    let mut workspace = PolicyWorkspace::new();
    workspace.set_policy("cart", document.clone());
    if !workspace.all_diagnostics().is_empty() || !workspace.document_uses("cart").is_empty() {
        return Err(PolicyError::Analysis);
    }
    validate_goal_closure(
        &workspace.dependencies_scoped("cart.allowed", Some("cart")),
        &expected_reads,
    )?;
    let loader = Arc::new(ImmutableLoader {
        content: Arc::new(DecisionContent::Policy(Arc::new(document.clone()).into())),
        entry_reads: AtomicUsize::new(0),
        unexpected_reads: AtomicUsize::new(0),
        dynamic_reads: AtomicUsize::new(0),
    });
    let engine = DecisionEngine::default().with_loader(loader.clone());
    if !engine.compile().is_empty() || !loader.compiled_expected_entry_only() {
        return Err(PolicyError::Compile);
    }
    Ok(AdmittedPreview {
        document,
        source_sha256: format!("{:x}", Sha256::digest(source)),
    })
}

#[cfg(test)]
mod compile_evidence_tests {
    use super::*;

    fn loader() -> Result<ImmutableLoader, Box<dyn std::error::Error>> {
        let document: PolicyDocument =
            serde_json::from_slice(include_bytes!("../../../corpus/cart-quantity-preview.json"))?;
        Ok(ImmutableLoader {
            content: Arc::new(DecisionContent::Policy(Arc::new(document).into())),
            entry_reads: AtomicUsize::new(0),
            unexpected_reads: AtomicUsize::new(0),
            dynamic_reads: AtomicUsize::new(0),
        })
    }

    #[test]
    fn compile_evidence_requires_the_expected_entry() -> Result<(), Box<dyn std::error::Error>> {
        let loader = loader()?;
        assert!(!loader.compiled_expected_entry_only());
        assert!(matches!(loader.load_sync("other"), Some(Err(_))));
        assert!(!loader.compiled_expected_entry_only());
        Ok(())
    }

    #[test]
    fn compile_evidence_rejects_an_unexpected_lookup_even_after_entry_read(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let loader = loader()?;
        assert!(matches!(loader.load_sync("cart"), Some(Ok(_))));
        assert!(loader.compiled_expected_entry_only());
        assert!(matches!(loader.load_sync("other"), Some(Err(_))));
        assert!(!loader.compiled_expected_entry_only());
        Ok(())
    }

    #[test]
    fn compile_evidence_rejects_dynamic_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let loader = loader()?;
        assert!(matches!(loader.load_sync("cart"), Some(Ok(_))));
        drop(loader.load("cart"));
        assert!(!loader.compiled_expected_entry_only());
        Ok(())
    }

    #[test]
    fn preview_document_still_compiles() -> Result<(), Box<dyn std::error::Error>> {
        admit(include_bytes!("../../../corpus/cart-quantity-preview.json"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn immutable_loader_enumerates_and_never_falls_back() -> Result<(), Box<dyn std::error::Error>>
    {
        let document: PolicyDocument =
            serde_json::from_slice(include_bytes!("../../../corpus/cart-quantity-preview.json"))?;
        let loader = ImmutableLoader {
            content: Arc::new(DecisionContent::Policy(Arc::new(document).into())),
            entry_reads: AtomicUsize::new(0),
            unexpected_reads: AtomicUsize::new(0),
            dynamic_reads: AtomicUsize::new(0),
        };
        assert_eq!(loader.keys(), Some(vec![Arc::from("cart")]));
        assert!(matches!(loader.load_sync("cart"), Some(Ok(_))));
        assert!(matches!(
            loader.load_sync("other"),
            Some(Err(LoaderError::NotFound(_)))
        ));
        let mut future = loader.load("cart");
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(LoaderError::NotFound(_)))
        ));
        assert_eq!(loader.dynamic_reads.load(Ordering::Relaxed), 1);
        Ok(())
    }
}

#[cfg(test)]
mod expression_budget_tests {
    use super::*;

    fn balanced_expression(levels: usize) -> String {
        if levels == 0 {
            "true".to_owned()
        } else {
            let inner = balanced_expression(levels - 1);
            format!("({inner} or {inner})")
        }
    }

    #[test]
    fn token_budget_rejects_wide_expressions_before_parsing() {
        // Both trees are well below the existing AST depth limit; only the
        // larger one exceeds the token budget.
        assert!(validate_expression(&balanced_expression(4)).is_ok());
        assert_eq!(
            validate_expression(&balanced_expression(6)),
            Err(PolicyError::Unsupported)
        );
    }

    #[test]
    fn token_budget_rejects_deep_unary_and_parenthesized_inputs() {
        let unary = format!("{}true", "not ".repeat(MAX_EXPRESSION_TOKENS));
        let parentheses = format!(
            "{}true{}",
            "(".repeat(MAX_EXPRESSION_TOKENS),
            ")".repeat(MAX_EXPRESSION_TOKENS)
        );
        for source in [unary, parentheses] {
            assert_eq!(validate_expression(&source), Err(PolicyError::Unsupported));
        }
    }
}

#[cfg(test)]
mod closure_tests {
    use super::*;

    #[test]
    fn goal_closure_rejects_incomplete_or_ambiguous_analysis(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document: PolicyDocument =
            serde_json::from_slice(include_bytes!("../../../corpus/cart-quantity-preview.json"))?;
        let mut workspace = PolicyWorkspace::new();
        workspace.set_policy("cart", document);
        let goal = workspace.dependencies_scoped("cart.allowed", Some("cart"));
        let expected = BTreeSet::from(["cart.authorized", "cart.maxQuantity", "cart.quantity"]);
        validate_goal_closure(&goal, &expected)?;

        let mut missing = goal.clone();
        missing.deps.pop();
        assert_eq!(
            validate_goal_closure(&missing, &expected),
            Err(PolicyError::Analysis)
        );

        let mut unresolved = goal.clone();
        unresolved.deps[0].unresolved = true;
        assert_eq!(
            validate_goal_closure(&unresolved, &expected),
            Err(PolicyError::Analysis)
        );

        let mut extra = goal.clone();
        let mut unexpected = extra.deps[0].clone();
        unexpected.property = Arc::from("cart.secret");
        extra.deps.push(unexpected);
        assert_eq!(
            validate_goal_closure(&extra, &expected),
            Err(PolicyError::Analysis)
        );

        let mut duplicate = goal.clone();
        duplicate.deps.push(duplicate.deps[0].clone());
        assert_eq!(
            validate_goal_closure(&duplicate, &expected),
            Err(PolicyError::Analysis)
        );

        let mut wrong_writer = goal.clone();
        wrong_writer
            .written_by
            .as_mut()
            .ok_or("missing writer")?
            .policy_path = Arc::from("other");
        assert_eq!(
            validate_goal_closure(&wrong_writer, &expected),
            Err(PolicyError::Analysis)
        );

        let mut no_writer = goal.clone();
        no_writer.written_by = None;
        assert_eq!(
            validate_goal_closure(&no_writer, &expected),
            Err(PolicyError::Analysis)
        );

        let mut nested = goal.clone();
        nested.deps[0].deps.push(goal.deps[1].clone());
        assert_eq!(
            validate_goal_closure(&nested, &expected),
            Err(PolicyError::Analysis)
        );

        let mut computed_input = goal.clone();
        computed_input.deps[0].written_by = goal.written_by.clone();
        assert_eq!(
            validate_goal_closure(&computed_input, &expected),
            Err(PolicyError::Analysis)
        );
        Ok(())
    }
}
