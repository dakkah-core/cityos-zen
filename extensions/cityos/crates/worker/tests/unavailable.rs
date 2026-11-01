use std::process::Command;

#[test]
fn unqualified_worker_returns_no_authorization() -> Result<(), Box<dyn std::error::Error>> {
    let result = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker")).output()?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}
