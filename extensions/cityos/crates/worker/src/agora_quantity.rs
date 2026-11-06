//! Single-request transport. This does not provide a deadline or isolation.
use std::io::{self, Read, Write};
use cityos_zen_contracts::PolicyError;
use cityos_zen_contracts::agora_quantity::MAX_REQUEST_BYTES;
use cityos_zen_runtime::agora_quantity::evaluate;

pub(crate) fn evaluate_stdio() -> Result<(), PolicyError> {
    let mut bytes = Vec::new();
    io::stdin().lock().take(MAX_REQUEST_BYTES as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    let result = evaluate(&bytes)?;
    let mut output = serde_json::to_vec(&result).map_err(|_| PolicyError::Evaluation)?;
    output.push(b'\n');
    io::stdout().lock().write_all(&output).map_err(|_| PolicyError::Evaluation)
}
