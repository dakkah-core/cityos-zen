//! Source-local preview contracts. These types do not grant policy authority.
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "cityos.zen.cart-quantity-preview.v1";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_DOCUMENT_BYTES: usize = 65_536;

/// Fixed, non-authoritative S14 consent-gate transport identity.
pub const S14_CONSENT_PREVIEW_PROFILE: &str = "cityos.zen.s14-consent-preview.v1";
pub const S14_CONSENT_PREVIEW_KIND: &str = "s14-consent-preview";
pub const S14_CONSENT_SOURCE_SHA256: &str =
    "70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543";

/// Normalized caller-supplied state; no consent record is verified here.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum S14ConsentPreviewState {
    MissingOrNotGranted,
    Granted {
        #[serde(rename = "expiresAtMillis")]
        expires_at_millis: Option<i64>,
    },
}

/// The caller must first validate every supplied expiry and perform S14's
/// earlier checks. An absent expiry must never represent a parse failure.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct S14ConsentPreviewFacts {
    pub required: bool,
    pub consent: S14ConsentPreviewState,
    pub now_millis: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct S14ConsentPreviewRequest {
    pub kind: String,
    pub profile: String,
    pub facts: S14ConsentPreviewFacts,
}

/// A gate result only; neither variant is a policy decision or receipt.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum S14ConsentPreviewOutcome {
    Satisfied,
    ConsentNotGranted,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct S14ConsentPreviewResponse {
    pub kind: String,
    pub profile: String,
    pub outcome: S14ConsentPreviewOutcome,
    #[serde(rename = "sourceSha256")]
    pub source_sha256: String,
}

fn s14_source_sha256<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let digest = String::deserialize(deserializer)?;
    if digest != S14_CONSENT_SOURCE_SHA256 {
        return Err(serde::de::Error::custom("invalid S14 consent source identity"));
    }
    Ok(digest)
}

// Serde's derived struct visitors also accept sequences. Require a map before
// delegating to the derived visitors without first parsing JSON into a Value.
macro_rules! deserialize_object_only {
    ($type:ty, $remote:ident) => {
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct ObjectVisitor;

                impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
                    type Value = $type;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        formatter.write_str("an object")
                    }

                    fn visit_map<M: serde::de::MapAccess<'de>>(
                        self,
                        map: M,
                    ) -> Result<Self::Value, M::Error> {
                        $remote::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    }
                }

                deserializer.deserialize_map(ObjectVisitor)
            }
        }
    };
}

impl<'de> Deserialize<'de> for S14ConsentPreviewState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StateVisitor;
        impl<'de> serde::de::Visitor<'de> for StateVisitor {
            type Value = S14ConsentPreviewState;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a consent state object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                use serde::de::Error;
                let mut state: Option<String> = None;
                // The outer Option records presence; the inner Option records JSON null.
                let mut expiry: Option<Option<i64>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "state" => {
                            if state.is_some() { return Err(M::Error::duplicate_field("state")); }
                            state = Some(map.next_value()?);
                        }
                        "expiresAtMillis" => {
                            if expiry.is_some() { return Err(M::Error::duplicate_field("expiresAtMillis")); }
                            expiry = Some(map.next_value()?);
                        }
                        _ => return Err(M::Error::unknown_field(&key, &["state", "expiresAtMillis"])),
                    }
                }
                match state.as_deref().ok_or_else(|| M::Error::missing_field("state"))? {
                    "missing-or-not-granted" if expiry.is_none() => Ok(S14ConsentPreviewState::MissingOrNotGranted),
                    "missing-or-not-granted" => Err(M::Error::custom("expiry is not allowed for this state")),
                    "granted" => Ok(S14ConsentPreviewState::Granted {
                        expires_at_millis: expiry.ok_or_else(|| M::Error::missing_field("expiresAtMillis"))?,
                    }),
                    other => Err(M::Error::unknown_variant(other, &["missing-or-not-granted", "granted"])),
                }
            }
        }
        deserializer.deserialize_map(StateVisitor)
    }
}

#[derive(Deserialize)]
#[serde(
    remote = "S14ConsentPreviewFacts",
    deny_unknown_fields,
    rename_all = "camelCase"
)]
struct S14ConsentPreviewFactsDef {
    required: bool,
    consent: S14ConsentPreviewState,
    now_millis: i64,
}
deserialize_object_only!(S14ConsentPreviewFacts, S14ConsentPreviewFactsDef);

#[derive(Deserialize)]
#[serde(remote = "S14ConsentPreviewRequest", deny_unknown_fields)]
struct S14ConsentPreviewRequestDef {
    kind: String,
    profile: String,
    facts: S14ConsentPreviewFacts,
}
deserialize_object_only!(S14ConsentPreviewRequest, S14ConsentPreviewRequestDef);

#[derive(Deserialize)]
#[serde(remote = "S14ConsentPreviewResponse", deny_unknown_fields)]
struct S14ConsentPreviewResponseDef {
    kind: String,
    profile: String,
    outcome: S14ConsentPreviewOutcome,
    #[serde(rename = "sourceSha256", deserialize_with = "s14_source_sha256")]
    source_sha256: String,
}
deserialize_object_only!(S14ConsentPreviewResponse, S14ConsentPreviewResponseDef);

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
