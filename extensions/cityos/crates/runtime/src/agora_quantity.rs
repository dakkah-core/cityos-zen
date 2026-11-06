//! Fixed, bounded quantity calculation over caller-supplied candidate and rule data.
//! The caller owns selection, authentication, completeness and transaction custody.
use cityos_zen_admission::v2_boolean::admit_integer_preview;
use cityos_zen_contracts::{PolicyError, MAX_SAFE_INTEGER};
use cityos_zen_contracts::agora_quantity::{Object, Request, Response, EXECUTION_PROFILE, KIND, PROFILE, MAX_ITEMS, MAX_REQUEST_BYTES};
use serde_json::json;

const SOURCE: &[u8] = include_bytes!("../../../corpus/agora-quantity-v1.json");

fn js_space(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
        | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
fn valid_text(s: &str) -> bool {
    !s.is_empty() && s.encode_utf16().count() <= 256 && s.trim_matches(js_space) == s
        && !s.chars().any(|c| c <= '\u{001f}' || c == '\u{007f}')
}
fn valid_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|v| v.len() == 64
        && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Decode one closed request and evaluate a fixed admitted Zen comparison.
/// A successful return proves only the calculation over these supplied bytes.
pub fn evaluate(request_bytes: &[u8]) -> Result<Response, PolicyError> {
    if request_bytes.len() > MAX_REQUEST_BYTES { return Err(PolicyError::InvalidInput); }
    let Object(request): Object<Request> = serde_json::from_slice(request_bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    let rule = request.rule.0;
    if request.kind != KIND || request.profile != PROFILE
        || request.items.len() > MAX_ITEMS || !valid_text(&rule.rule_id)
        || !valid_digest(&rule.revision_digest) || rule.rule_type != "max_quantity"
        || rule.status != "active" || rule.max_quantity > MAX_SAFE_INTEGER
        || rule.target_sku.as_deref().is_some_and(|s| !valid_text(s)) {
        return Err(PolicyError::InvalidInput);
    }
    let mut total = 0_u64;
    let mut matching = 0_u64;
    for Object(item) in request.items {
        if !valid_text(&item.sku) || item.quantity == 0 || item.quantity > MAX_SAFE_INTEGER {
            return Err(PolicyError::InvalidInput);
        }
        total = total.checked_add(item.quantity).filter(|v| *v <= MAX_SAFE_INTEGER)
            .ok_or(PolicyError::InvalidInput)?;
        if rule.target_sku.as_ref().is_none_or(|sku| *sku == item.sku) {
            matching = matching.checked_add(item.quantity).filter(|v| *v <= MAX_SAFE_INTEGER)
                .ok_or(PolicyError::InvalidInput)?;
        }
    }
    let policy = admit_integer_preview(SOURCE)?;
    let input = serde_json::to_vec(&json!({"quantity":matching,"limit":rule.max_quantity}))
        .map_err(|_| PolicyError::Evaluation)?;
    let within_limit = policy.evaluate(&input)?;
    Ok(Response { kind: KIND, profile: PROFILE, execution_profile: EXECUTION_PROFILE.id,
        source_sha256: policy.source_sha256().to_owned(),
        rule_id: rule.rule_id, revision_digest: rule.revision_digest,
        matching_quantity: matching, max_quantity: rule.max_quantity, within_limit })
}
