use std::process::Command;

#[test]
fn unqualified_worker_returns_no_authorization() -> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        vec![],
        vec!["--authoritative-stdio"],
        vec!["--sandboxed-s14-rule-stdio"],
        vec!["--preview-stdio", "--authoritative-stdio"],
        vec!["--v2-integer-preview-stdio", "--authoritative-stdio"],
        vec!["--supervised-preview-stdio", "--authoritative-stdio"],
        vec!["--supervised-s14-rule-preview-stdio", "--authoritative-stdio"],
        vec!["--restricted-s14-rule-preview-stdio", "--authoritative-stdio"],
        vec!["--experimental-network-preview-stdio", "--authoritative-stdio"],
        vec!["--experimental-network-child-stdio", "--authoritative-stdio"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
            .args(arguments)
            .output()?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
    Ok(())
}
