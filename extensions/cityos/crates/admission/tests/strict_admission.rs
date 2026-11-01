use cityos_zen_admission::admit;
use cityos_zen_contracts::{PolicyError, MAX_DOCUMENT_BYTES};
use serde_json::Value;

const SOURCE: &[u8] = include_bytes!("../../../corpus/cart-quantity-preview.json");

fn with_expression(expression: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut source: Value = serde_json::from_slice(SOURCE)?;
    source["blocks"][1]["props"]["data"]["value"] = expression.into();
    Ok(serde_json::to_vec(&source)?)
}

#[test]
fn admits_closed_deterministic_expressions() -> Result<(), Box<dyn std::error::Error>> {
    for expression in [
        "cart.authorized and cart.quantity <= cart.maxQuantity",
        "cart.quantity > 0",
        "cart.authorized == false",
        "true",
    ] {
        assert!(admit(&with_expression(expression)?).is_ok(), "{expression}");
    }
    Ok(())
}

#[test]
fn rejects_unclosed_or_non_deterministic_expressions() -> Result<(), Box<dyn std::error::Error>> {
    for expression in [
        "cart.secret == 1",
        "other.quantity > 0",
        "cart[other.field] > 0",
        "random() > 0",
        "cart.quantity + 1 > 0",
        "cart.quantity > 9007199254740992",
        "cart.quantity > 1.0",
        "cart.quantity > 1e2",
        "cart.quantity > 0 true",
        "cart.quantity",
    ] {
        assert!(admit(&with_expression(expression)?).is_err(), "{expression}");
    }
    Ok(())
}

#[test]
fn rejects_deeply_nested_templates_before_lexing() -> Result<(), Box<dyn std::error::Error>> {
    const PROBE: &str = "CITYOS_ZEN_TEMPLATE_STACK_PROBE";
    if std::env::var_os(PROBE).is_some() {
        // Each interpolation makes Zen's lexer recursively scan another template.
        // The source stays under the expression byte limit.
        let expression = format!("{}true{}", "`${".repeat(750), "}`".repeat(750));
        assert!(expression.len() < 4096);
        let source = with_expression(&expression)?;
        let rejected = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || matches!(admit(&source), Err(PolicyError::Unsupported)))?
            .join()
            .map_err(|_| "admission thread panicked")?;
        assert!(rejected);
        return Ok(());
    }

    // A stack overflow aborts a process, so isolate the pre-fix failure from
    // the rest of the test suite.
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "rejects_deeply_nested_templates_before_lexing"])
        .env(PROBE, "1")
        .output()?;
    assert!(output.status.success(), "nested template probe failed");
    assert!(admit(&with_expression(
        "cart.authorized and cart.quantity <= cart.maxQuantity"
    )?)
    .is_ok());
    Ok(())
}

#[test]
fn rejects_ambiguous_json_and_external_documents() -> Result<(), Box<dyn std::error::Error>> {
    let source = std::str::from_utf8(SOURCE)?;
    let candidates = [
        source.replace("\"imports\": []", "\"imports\": [\"external\"]"),
        source.replace("\"imports\": []", "\"imports\": [], \"imports\": []"),
        source.replace(
            "\"key\":\"cart.allowed\"",
            "\"key\":\"cart.allowed\",\"key\":\"cart.allowed\"",
        ),
        format!("{source} null"),
    ];
    for candidate in candidates {
        assert!(admit(candidate.as_bytes()).is_err(), "{candidate}");
    }
    assert!(matches!(
        admit(&vec![b' '; MAX_DOCUMENT_BYTES + 1]),
        Err(PolicyError::InvalidSource)
    ));
    assert!(matches!(admit(&[0xff]), Err(PolicyError::InvalidSource)));
    Ok(())
}
