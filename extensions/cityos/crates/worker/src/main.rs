//! Local preview transport. This process is not an isolated policy authority.
use std::io::{self, Read, Write};
use std::process::ExitCode;

use cityos_zen_contracts::{PolicyError, PreviewFacts, MAX_DOCUMENT_BYTES};
use serde::Deserialize;
use serde_json::json;

#[cfg(target_os = "linux")]
mod supervisor;

const MAX_REQUEST_BYTES: u64 = (MAX_DOCUMENT_BYTES as u64) * 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    kind: String,
    source: String,
    facts: PreviewFacts,
}

fn preview() -> Result<(), PolicyError> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    let request: PreviewRequest =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::InvalidInput)?;
    if request.kind != "preview" || request.source.len() > MAX_DOCUMENT_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    let policy = cityos_zen_admission::admit(request.source.as_bytes())?;
    let result = cityos_zen_runtime::evaluate_preview(&policy, &request.facts)?;
    let response = json!({
        "kind": "preview",
        "allowed": result.allowed,
        "sourceSha256": result.source_sha256,
        "profile": result.profile,
    });
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|_| PolicyError::Evaluation)?;
    stdout
        .write_all(b"\n")
        .map_err(|_| PolicyError::Evaluation)?;
    Ok(())
}

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments.next();
    if arguments.next().is_some() {
        eprintln!("cityos-zen-worker: authoritative isolation profile unavailable");
        return ExitCode::FAILURE;
    }
    let result = match mode.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("--preview-stdio") => preview(),
        #[cfg(target_os = "linux")]
        Some("--supervised-preview-stdio") => supervisor::preview(),
        _ => {
            eprintln!("cityos-zen-worker: authoritative isolation profile unavailable");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            // Do not echo policy source, facts, or dependency errors to a caller.
            eprintln!("cityos-zen-worker: preview unavailable");
            ExitCode::FAILURE
        }
    }
}
