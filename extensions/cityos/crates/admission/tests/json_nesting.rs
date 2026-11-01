use cityos_zen_admission::admit;
use cityos_zen_contracts::PolicyError;

#[test]
fn rejects_deep_json_without_exhausting_the_stack() -> Result<(), Box<dyn std::error::Error>> {
    const PROBE: &str = "CITYOS_ZEN_JSON_STACK_PROBE";
    if std::env::var_os(PROBE).is_some() {
        let source = format!("{}null{}", "[".repeat(120), "]".repeat(120));
        let rejected = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || matches!(admit(source.as_bytes()), Err(PolicyError::InvalidSource)))?
            .join()
            .map_err(|_| "admission thread panicked")?;
        assert!(rejected);
        return Ok(());
    }

    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "rejects_deep_json_without_exhausting_the_stack"])
        .env(PROBE, "1")
        .output()?;
    assert!(
        output.status.success(),
        "deep JSON probe failed: {output:?}"
    );
    Ok(())
}

#[test]
fn nesting_guard_ignores_quoted_brackets_and_escaped_quotes(
) -> Result<(), Box<dyn std::error::Error>> {
    let text = format!("escaped quote: \" {}{}", "[".repeat(100), "]".repeat(100));
    let source = serde_json::to_vec(&serde_json::json!({ "unexpected": text }))?;
    assert!(matches!(admit(&source), Err(PolicyError::Unsupported)));
    assert!(admit(include_bytes!("../../../corpus/cart-quantity-preview.json")).is_ok());
    Ok(())
}
