use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let script = root.join("scripts/upstream/integration.py");
    let python = if cfg!(windows) { "python" } else { "python3" };
    match Command::new(python)
        // The boundary checker must not import caller-supplied PYTHONPATH or
        // user-site startup code before it can inspect the candidate.
        .arg("-I")
        .arg(script)
        .args(std::env::args_os().skip(1))
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) | Err(_) => ExitCode::FAILURE,
    }
}
