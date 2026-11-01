//! Source-local preview contracts. These types do not grant policy authority.
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "cityos.zen.cart-quantity-preview.v1";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_DOCUMENT_BYTES: usize = 65_536;

/// Caller-supplied test values, not verified owner facts.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreviewFacts {
    pub quantity: u64,
    pub max_quantity: u64,
    pub authorized: bool,
}

impl PreviewFacts {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.quantity > MAX_SAFE_INTEGER || self.max_quantity > MAX_SAFE_INTEGER {
            return Err(PolicyError::InvalidInput);
        }
        Ok(())
    }
}

/// A non-authoritative result; deliberately carries no receipt or approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewResult {
    pub allowed: bool,
    pub source_sha256: String,
    pub profile: &'static str,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("invalid source")]
    InvalidSource,
    #[error("unsupported policy content")]
    Unsupported,
    #[error("invalid input")]
    InvalidInput,
    #[error("analysis incomplete or failed")]
    Analysis,
    #[error("compilation failed")]
    Compile,
    #[error("evaluation failed or returned a non-boolean result")]
    Evaluation,
}
