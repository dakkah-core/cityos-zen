//! Local preview transport. This process is not an isolated policy authority.
use std::io::{self, Read, Write};
use std::process::ExitCode;

use cityos_zen_contracts::{
    agora_quantity::Object, PolicyError, PreviewFacts, S14ConsentPreviewOutcome,
    S14ConsentPreviewRequest,
    S14ConsentPreviewResponse, S14ConsentPreviewState, MAX_DOCUMENT_BYTES,
    S14_CONSENT_PREVIEW_KIND, S14_CONSENT_PREVIEW_PROFILE, S14_CONSENT_SOURCE_SHA256,
};
use cityos_zen_runtime::s14_consent::{self, Consent, ConsentFacts, ConsentGatePreview};
use serde::Deserialize;
use serde_json::json;

mod s14_rule_preview;
mod agora_quantity;
mod json_object;

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod cgroup_cleanup;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod cgroup_limits;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod inherited_fds;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod network;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod resource_limits;
#[cfg(all(target_os = "linux", not(target_env = "uclibc"), any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
mod process_sandbox;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod registered_sandbox;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod stdio;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod supervisor;

const MAX_REQUEST_BYTES: u64 = (MAX_DOCUMENT_BYTES as u64) * 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    kind: String,
    source: String,
    facts: Object<PreviewFacts>,
}

/// The source and input remain strings until each loss-aware decoder runs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2IntegerPreviewRequest {
    kind: String,
    profile: String,
    source: String,
    input: String,
}

fn v2_integer_preview() -> Result<(), PolicyError> {
    let mut bytes = Vec::new();
    io::stdin().lock().take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES
        || bytes.iter().copied().find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n')) != Some(b'{') {
        return Err(PolicyError::InvalidInput);
    }
    let Object(request): Object<V2IntegerPreviewRequest> = serde_json::from_slice(&bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    if request.kind != "v2-integer-preview"
        || request.profile != cityos_zen_admission::v2_boolean::INTEGER_PREVIEW_PROFILE
        || request.source.len() > MAX_DOCUMENT_BYTES || request.input.len() > MAX_DOCUMENT_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    let policy = cityos_zen_admission::v2_boolean::admit_integer_preview(request.source.as_bytes())?;
    let result = cityos_zen_runtime::v2_boolean::evaluate(&policy, request.input.as_bytes())?;
    let response = json!({"kind":"v2-integer-preview", "profile":policy.profile(),
        "sourceSha256":policy.source_sha256(), "result":result});
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|_| PolicyError::Evaluation)?;
    stdout.write_all(b"\n").map_err(|_| PolicyError::Evaluation)
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
    let Object(request): Object<PreviewRequest> =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::InvalidInput)?;
    if request.kind != "preview" || request.source.len() > MAX_DOCUMENT_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    let policy = cityos_zen_admission::admit(request.source.as_bytes())?;
    let result = cityos_zen_runtime::evaluate_preview(&policy, &request.facts.0)?;
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

fn s14_consent_preview() -> Result<(), PolicyError> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyError::InvalidInput)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(PolicyError::InvalidInput);
    }
    let request: S14ConsentPreviewRequest =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::InvalidInput)?;
    if request.kind != S14_CONSENT_PREVIEW_KIND || request.profile != S14_CONSENT_PREVIEW_PROFILE {
        return Err(PolicyError::InvalidInput);
    }
    let consent = match request.facts.consent {
        S14ConsentPreviewState::MissingOrNotGranted => Consent::MissingOrNotGranted,
        S14ConsentPreviewState::Granted { expires_at_millis } => {
            Consent::Granted { expires_at_millis }
        }
    };
    let outcome = match s14_consent::evaluate(&ConsentFacts {
        required: request.facts.required,
        consent,
        now_millis: request.facts.now_millis,
    })? {
        ConsentGatePreview::Satisfied => S14ConsentPreviewOutcome::Satisfied,
        ConsentGatePreview::ConsentNotGranted => S14ConsentPreviewOutcome::ConsentNotGranted,
    };
    let source_sha256 = s14_consent::admitted_source_sha256()?;
    if source_sha256 != S14_CONSENT_SOURCE_SHA256 {
        return Err(PolicyError::Evaluation);
    }
    let response = S14ConsentPreviewResponse {
        kind: S14_CONSENT_PREVIEW_KIND.into(),
        profile: S14_CONSENT_PREVIEW_PROFILE.into(),
        outcome,
        source_sha256,
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|_| PolicyError::Evaluation)?;
    stdout.write_all(b"\n").map_err(|_| PolicyError::Evaluation)
}

fn s14_identity() -> Result<(), PolicyError> {
    let identity = json!({
        "ruleProfile": cityos_zen_runtime::s14_decision::PROFILE,
        "sandboxProfile": "cityos.zen.s14.sandbox-resources.v1",
        "selectorSha256": cityos_zen_runtime::s14_decision::selector_document_sha256()?,
    });
    serde_json::to_writer(io::stdout().lock(), &identity).map_err(|_| PolicyError::Evaluation)
}

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments.next();
    let bounded_s14 = matches!(mode.as_deref().and_then(std::ffi::OsStr::to_str),
        Some("--agora-quantity-stdio" | "--restricted-agora-quantity-stdio"
            | "--supervised-s14-consent-preview-stdio" | "--restricted-s14-consent-preview-stdio"
            | "--supervised-s14-rule-preview-stdio"
            | "--restricted-s14-rule-preview-stdio" | "--sandboxed-s14-rule-stdio"
            | "--s14-host-bootstrap-stdio" | "--s14-host-launcher-stdio"));
    if arguments.next().is_some() {
        if !bounded_s14 {
            eprintln!("cityos-zen-worker: authoritative isolation profile unavailable");
        }
        return ExitCode::FAILURE;
    }
    // This mode never writes an error to inherited stderr: it may be a full
    // blocking pipe, including when the mode is unavailable on this platform.
    if bounded_s14 {
        #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
        return if match mode.as_deref().and_then(std::ffi::OsStr::to_str) {
            Some("--agora-quantity-stdio") => supervisor::agora_quantity(),
            Some("--restricted-agora-quantity-stdio") => supervisor::restricted_agora_quantity(),
            Some("--supervised-s14-consent-preview-stdio") => supervisor::s14_consent_preview(),
            Some("--restricted-s14-consent-preview-stdio") => supervisor::restricted_s14_consent_preview(),
            Some("--supervised-s14-rule-preview-stdio") => supervisor::s14_rule_preview(),
            Some("--restricted-s14-rule-preview-stdio") => supervisor::restricted_s14_rule_preview(),
            Some("--s14-host-bootstrap-stdio") => cityos_zen_worker::host_bootstrap(),
            Some("--s14-host-launcher-stdio") => cityos_zen_worker::host_launcher_stdio(),
            _ => Err(PolicyError::Evaluation),
        }.is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
        #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
        return ExitCode::FAILURE;
    }
    let result = match mode.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("--s14-worker-identity-stdio") => s14_identity(),
        Some("--preview-stdio") => preview(),
        Some("--v2-integer-preview-stdio") => v2_integer_preview(),
        Some("--s14-consent-preview-stdio") => s14_consent_preview(),
        Some("--s14-rule-preview-stdio") => s14_rule_preview::preview(),
        #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
        Some("--supervised-preview-stdio") => supervisor::preview(),
        #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
        Some("--restricted-preview-stdio") => supervisor::restricted_preview(),
        #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
        #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
        Some("--experimental-network-preview-stdio") => supervisor::experimental_network_preview(),
        #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
        Some("--experimental-network-child-stdio") => supervisor::experimental_network_child(),
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
