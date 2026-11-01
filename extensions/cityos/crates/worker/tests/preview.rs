use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

const SOURCE: &str = include_str!("../../../corpus/cart-quantity-preview.json");

fn run(input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    run_mode("--preview-stdio", input)
}

fn run_mode(mode: &str, input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg(mode)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(input)?;
    Ok(child.wait_with_output()?)
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_preview_is_bounded_and_non_authoritative() -> Result<(), Box<dyn std::error::Error>> {
    let request = json!({"kind":"preview", "source":SOURCE,
        "facts":{"quantity":1,"maxQuantity":2,"authorized":true}});
    let result = run_mode("--supervised-preview-stdio", &serde_json::to_vec(&request)?)?;
    assert!(result.status.success());
    let body: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(body["kind"], "preview");
    assert_eq!(body["allowed"], true);
    assert!(body.get("signedDecision").is_none());
    assert!(body.get("decisionId").is_none());

    let rejected = run_mode("--supervised-preview-stdio", b"invalid secret-value")?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("secret-value"));

    let authority = json!({"kind":"authority", "source":SOURCE,
        "facts":{"quantity":1,"maxQuantity":2,"authorized":true}});
    let rejected = run_mode(
        "--supervised-preview-stdio",
        &serde_json::to_vec(&authority)?,
    )?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn experimental_network_preview_is_isolated_or_unavailable(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--experimental-network-preview-stdio")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = supervisor.stdin.take().ok_or("missing stdin")?;
    let parent_namespace = std::fs::read_link("/proc/thread-self/ns/net")?;
    let children = format!("/proc/{0}/task/{0}/children", supervisor.id());
    let deadline = Instant::now() + Duration::from_secs(3);
    let isolated = loop {
        if let Ok(pids) = std::fs::read_to_string(&children) {
            if pids.split_whitespace().any(|pid| {
                std::fs::read_link(format!("/proc/{pid}/ns/net"))
                    .is_ok_and(|child_namespace| child_namespace != parent_namespace)
            }) {
                break true;
            }
        }
        if supervisor.try_wait()?.is_some() || Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if isolated {
        let request = json!({"kind":"preview", "source":SOURCE,
            "facts":{"quantity":1,"maxQuantity":2,"authorized":true}});
        input.write_all(&serde_json::to_vec(&request)?)?;
    }
    drop(input);
    let result = supervisor.wait_with_output()?;
    if isolated {
        assert!(result.status.success());
        let body: Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(body["kind"], "preview");
        assert_eq!(body["allowed"], true);
        assert!(body.get("signedDecision").is_none());
    } else {
        assert!(!result.status.success(), "experimental preview ran without namespace evidence");
        assert!(result.stdout.is_empty());
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
#[test]
fn supervised_preview_is_unavailable_on_unsupported_platforms(
) -> Result<(), Box<dyn std::error::Error>> {
    for mode in [
        "--supervised-preview-stdio",
        "--restricted-preview-stdio",
        "--experimental-network-preview-stdio",
        "--experimental-network-child-stdio",
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
            .arg(mode)
            .output()?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_preview_times_out_when_input_never_closes() -> Result<(), Box<dyn std::error::Error>>
{
    let child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--supervised-preview-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Retain the write end while waiting, so the evaluator cannot observe EOF.
    let mut child = child;
    let input = child.stdin.take().ok_or("missing stdin")?;
    let result = child.wait_with_output()?;
    drop(input);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_evaluator_sets_no_new_privileges_before_reading_input(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--supervised-preview-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Retain stdin so the evaluator stays alive while its kernel state is read.
    let input = supervisor.stdin.take().ok_or("missing stdin")?;
    let children = format!("/proc/{0}/task/{0}/children", supervisor.id());
    let deadline = Instant::now() + Duration::from_secs(3);
    let observed = loop {
        if let Ok(pids) = std::fs::read_to_string(&children) {
            let found = pids.split_whitespace().any(|pid| {
                std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|status| {
                    status.lines().any(|line| {
                        line.strip_prefix("NoNewPrivs:")
                            .is_some_and(|value| value.trim() == "1")
                    })
                })
            });
            if found {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(input);
    let result = supervisor.wait_with_output()?;
    assert!(observed, "supervised evaluator never reported NoNewPrivs=1");
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn restricted_evaluator_installs_limits_before_reading_input(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--restricted-preview-stdio")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = child.stdin.take().ok_or("missing stdin")?;
    let path = format!("/proc/{}/limits", child.id());
    let expected = [
        ("Max address space", 512_u64 * 1024 * 1024),
        ("Max cpu time", 3),
        ("Max open files", 32),
        ("Max file size", 0),
        ("Max core file size", 0),
    ];
    let deadline = Instant::now() + Duration::from_secs(3);
    let observed = loop {
        if let Ok(limits) = std::fs::read_to_string(&path) {
            if expected.iter().all(|(name, cap)| {
                limits.lines().any(|line| {
                    line.strip_prefix(*name).is_some_and(|values| {
                        let mut values = values.split_whitespace();
                        let soft = values.next().and_then(|value| value.parse::<u64>().ok());
                        let hard = values.next().and_then(|value| value.parse::<u64>().ok());
                        matches!((soft, hard), (Some(soft), Some(hard)) if soft == hard && hard <= *cap)
                    })
                })
            }) {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(input);
    let result = child.wait_with_output()?;
    assert!(observed, "restricted evaluator did not install all resource limits");
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[test]
fn explicit_preview_round_trips_without_receipt_or_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    for (quantity, authorized, expected) in [(1, true, true), (3, true, false), (1, false, false)] {
        let request = json!({"kind":"preview", "source":SOURCE,
            "facts":{"quantity":quantity,"maxQuantity":2,"authorized":authorized}});
        let result = run(&serde_json::to_vec(&request)?)?;
        assert!(result.status.success());
        let body: Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(body["kind"], "preview");
        assert_eq!(body["allowed"], expected);
        assert!(body.get("signedDecision").is_none());
        assert!(body.get("decisionId").is_none());
    }
    Ok(())
}

#[test]
fn invalid_or_ambiguous_preview_fails_without_output() -> Result<(), Box<dyn std::error::Error>> {
    let invalid = [
        br#"{"kind":"preview","kind":"preview","source":"secret-value","facts":{}}"#.to_vec(),
        serde_json::to_vec(&json!({"kind":"authority", "source":SOURCE,
            "facts":{"quantity":1,"maxQuantity":2,"authorized":true}}))?,
        vec![b'x'; 131_073],
    ];
    for request in invalid {
        let result = run(&request)?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-value"));
    }
    Ok(())
}
