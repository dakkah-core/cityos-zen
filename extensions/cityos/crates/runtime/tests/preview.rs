use cityos_zen_admission::admit;
use cityos_zen_contracts::{PolicyError, PreviewFacts, MAX_SAFE_INTEGER};
use cityos_zen_runtime::evaluate_preview;

const SOURCE: &[u8] = include_bytes!("../../../corpus/cart-quantity-preview.json");

#[test]
fn synthetic_cart_quantity_preview_returns_boolean_and_source_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = admit(SOURCE)?;
    for (quantity, max_quantity, authorized, expected) in [
        (2, 3, true, true),
        (3, 3, true, true),
        (4, 3, true, false),
        (0, 3, false, false),
        (MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, true, true),
    ] {
        let result = evaluate_preview(
            &policy,
            &PreviewFacts {
                quantity,
                max_quantity,
                authorized,
            },
        )?;
        assert_eq!(result.allowed, expected);
        assert_eq!(result.source_sha256.len(), 64);
    }
    Ok(())
}

#[test]
fn rejects_unsafe_input() -> Result<(), Box<dyn std::error::Error>> {
    let policy = admit(SOURCE)?;
    assert_eq!(
        evaluate_preview(
            &policy,
            &PreviewFacts {
                quantity: MAX_SAFE_INTEGER + 1,
                max_quantity: 1,
                authorized: true,
            }
        ),
        Err(PolicyError::InvalidInput)
    );
    Ok(())
}

#[test]
fn rejects_unknown_or_ambiguous_content_before_zen_decoding(
) -> Result<(), Box<dyn std::error::Error>> {
    let source = std::str::from_utf8(SOURCE)?;
    for candidate in [
        source.replace("\"expression\"", "\"unknownExecutable\""),
        source.replace("\"imports\": []", "\"imports\": [\"external\"]"),
        source.replace("\"imports\": []", "\"imports\": [], \"imports\": []"),
        source.replace("cart.quantity <= cart.maxQuantity", "random() > 0"),
        source.replace("cart.quantity <= cart.maxQuantity", "cart.quantity / 0 > 1"),
        source.replace("cart.quantity <= cart.maxQuantity", "cart.secret == 1"),
        source.replace(
            "cart.quantity <= cart.maxQuantity",
            "cart.quantity < 9007199254740992",
        ),
        source.replace("cart.quantity <= cart.maxQuantity", "cart.quantity < 1.1"),
        source.replace("cart.quantity <= cart.maxQuantity", "cart.quantity < 1e2"),
    ] {
        assert!(
            admit(candidate.as_bytes()).is_err(),
            "unexpectedly admitted {candidate}"
        );
    }
    assert!(admit(br#"{"nodes":[],"edges":[]}"#).is_err());
    assert!(admit(&[0xff]).is_err());
    Ok(())
}

#[test]
fn preview_matches_the_characterized_agora_quantity_cases() -> Result<(), Box<dyn std::error::Error>>
{
    let corpus: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../corpus/agora-cart-baseline.json"))?;
    let policy = admit(SOURCE)?;
    let cases = corpus["cases"].as_array().ok_or("missing cases")?;
    let rule = &corpus["ruleTemplates"]["maximum"];
    let target = rule["targetSku"].as_str().ok_or("missing sku")?;
    let maximum = rule["maxQuantity"].as_u64().ok_or("missing maximum")?;
    let mut checked = 0;
    for case in cases {
        let id = case["id"].as_str().ok_or("missing id")?;
        if id != "maximum-target-sku" && id != "maximum-other-sku" {
            continue;
        }
        let items = case["body"]["items"].as_array().ok_or("missing items")?;
        let quantity = items
            .iter()
            .filter(|item| item["sku"].as_str() == Some(target))
            .try_fold(0_u64, |sum, item| {
                sum.checked_add(item["quantity"].as_u64()?)
            })
            .ok_or("invalid quantity")?;
        let expected = case["expected"]["allowed"]
            .as_bool()
            .ok_or("missing expected decision")?;
        let result = evaluate_preview(
            &policy,
            &PreviewFacts {
                quantity,
                max_quantity: maximum,
                authorized: true,
            },
        )?;
        assert_eq!(result.allowed, expected, "{id}");
        checked += 1;
    }
    assert_eq!(
        checked, 2,
        "the characterized owner cases must not be skipped"
    );
    Ok(())
}
