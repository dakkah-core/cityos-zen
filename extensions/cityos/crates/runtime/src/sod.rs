//! Pure calculation for the bounded, source-derived Tryton SoD profile.
//! This result is not verified evidence, authorization, a receipt, or a business effect.
use cityos_zen_admission::sod::{AdmittedSodProfile, SodEvaluation};
use cityos_zen_contracts::PolicyError;

pub use cityos_zen_admission::sod::{admit_profile, PROFILE};

pub fn evaluate(
    profile: &AdmittedSodProfile,
    input_json: &[u8],
) -> Result<SodEvaluation, PolicyError> {
    profile.evaluate(input_json)
}
