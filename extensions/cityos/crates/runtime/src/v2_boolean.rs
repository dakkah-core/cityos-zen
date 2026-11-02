//! Pure, non-authoritative V2 Boolean/enum preview through Zen's public API.
use cityos_zen_admission::v2_boolean::AdmittedV2Boolean;
use cityos_zen_contracts::PolicyError;

/// The Boolean is a calculation over caller-supplied facts, not authorization.
pub fn evaluate(policy: &AdmittedV2Boolean, input_json: &[u8]) -> Result<bool, PolicyError> {
    policy.evaluate(input_json)
}
