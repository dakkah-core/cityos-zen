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
    assert!(!rejected.stderr.is_empty());
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
fn supervised_cart_and_available_experimental_preview_preserve_regular_file_output(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Seek, SeekFrom};
    use std::time::{SystemTime, UNIX_EPOCH};

    let request = serde_json::to_vec(&json!({"kind":"preview", "source":SOURCE,
        "facts":{"quantity":1,"maxQuantity":2,"authorized":true}}))?;
    let expected = run_mode("--preview-stdio", &request)?;
    assert!(expected.status.success());
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    for (index, mode) in ["--supervised-preview-stdio", "--experimental-network-preview-stdio"].into_iter().enumerate() {
        let path = std::env::temp_dir().join(format!("zen-cart-output-{}-{nonce}-{index}", std::process::id()));
        let mut file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
            .arg(mode)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::from(file.try_clone()?))
            .stderr(Stdio::piped())
            .spawn()?;
        let input_result = child.stdin.take().ok_or("missing stdin")?.write_all(&request);
        let result = child.wait_with_output()?;
        file.seek(SeekFrom::Start(0))?;
        let mut output = Vec::new();
        file.read_to_end(&mut output)?;
        drop(file);
        std::fs::remove_file(path)?;
        if mode == "--experimental-network-preview-stdio" && !result.status.success() {
            // Namespace setup is optional in this environment; unavailable is
            // permitted, but a successful run must use the regular file.
            assert!(output.is_empty());
        } else {
            input_result?;
            assert!(result.status.success(), "{mode}: {:?}", result.stderr);
            assert_eq!(output, expected.stdout, "{mode}");
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_s14_output_preserves_pipe_flags_and_response_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::unistd::pipe;

    let consent = serde_json::to_vec(&json!({
        "kind":"s14-consent-preview", "profile":"cityos.zen.s14-consent-preview.v1",
        "facts":{"required":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":10}
    }))?;

    for (mode, direct_mode, request) in [
        ("--supervised-s14-consent-preview-stdio", "--s14-consent-preview-stdio", consent),
    ] {
        let expected = run_mode(direct_mode, &request)?;
        assert!(expected.status.success());
        for scenario in ["success", "nonblocking", "partial", "full", "disconnected"] {
            let (read_fd, write_fd) = pipe()?;
            let mut reader = Some(File::from(read_fd));
            let mut writer = File::from(write_fd);
            let mut flags = fcntl(writer.as_raw_fd(), FcntlArg::F_GETFL)?;
            if scenario == "nonblocking" {
                fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK))?;
                flags = fcntl(writer.as_raw_fd(), FcntlArg::F_GETFL)?;
            }
            let mut fill = Vec::new();
            if scenario == "full" || scenario == "partial" {
                let original = OFlag::from_bits_retain(flags);
                fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(original | OFlag::O_NONBLOCK))?;
                loop {
                    match writer.write(&[b'x'; 4096]) {
                        Ok(0) => return Err("zero-length pipe fill".into()),
                        Ok(n) => fill.extend(std::iter::repeat(b'x').take(n)),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        other => return Err(format!("could not fill pipe: {other:?}").into()),
                    }
                }
                fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(original))?;
                assert!(!fill.is_empty());
                if scenario == "partial" {
                    // If capacity is only one page, this environment cannot
                    // produce a partially full pipe with a whole page free.
                    if fill.len() <= 4096 {
                        continue;
                    }
                    let mut drained = [0u8; 4096];
                    reader.as_mut().ok_or("missing reader")?.read_exact(&mut drained)?;
                    fill.drain(..drained.len());
                }
            }
            if scenario == "disconnected" {
                drop(reader.take());
            }

            let mut supervisor = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
                .arg(mode)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::from(writer.try_clone()?))
                .stderr(Stdio::null())
                .spawn()?;
            let children = format!("/proc/{0}/task/{0}/children", supervisor.id());
            // Keep input open until the evaluator is observed, so the cleanup
            // assertion cannot accidentally pass without creating a child.
            let observe_until = Instant::now() + Duration::from_secs(3);
            let observed = loop {
                if std::fs::read_to_string(&children)
                    .is_ok_and(|pids| !pids.trim().is_empty())
                {
                    break true;
                }
                if supervisor.try_wait()?.is_some() || Instant::now() >= observe_until {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if !observed {
                let _ = supervisor.kill();
                let _ = supervisor.wait();
                return Err(format!("{mode} {scenario}: evaluator not observed").into());
            }
            let write_result = supervisor.stdin.take().ok_or("missing stdin")?.write_all(&request);
            if let Err(error) = write_result {
                let _ = supervisor.kill();
                let _ = supervisor.wait();
                return Err(error.into());
            }

            // On a full pipe, inspect the still-live supervisor while it waits
            // for output space: its evaluator must already have been reaped.
            if scenario == "full" {
                let cleanup_until = Instant::now() + Duration::from_secs(3);
                let reaped = loop {
                    if std::fs::read_to_string(&children)
                        .is_ok_and(|pids| pids.trim().is_empty())
                    {
                        break true;
                    }
                    if supervisor.try_wait()?.is_some() || Instant::now() >= cleanup_until {
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                if !reaped {
                    let _ = supervisor.kill();
                    let _ = supervisor.wait();
                    return Err(format!("{mode}: evaluator was not reaped before forwarding").into());
                }
            }

            let wait_until = Instant::now() + Duration::from_secs(7);
            let status = loop {
                if let Some(status) = supervisor.try_wait()? {
                    break status;
                }
                if Instant::now() >= wait_until {
                    let _ = supervisor.kill();
                    let _ = supervisor.wait();
                    return Err(format!("{mode} {scenario}: supervisor blocked").into());
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let success = matches!(scenario, "success" | "nonblocking" | "partial");
            assert_eq!(status.success(), success, "{mode} {scenario}");
            if !success {
                assert_eq!(status.code(), Some(1), "{mode} {scenario}: abnormal termination");
            }
            assert_eq!(fcntl(writer.as_raw_fd(), FcntlArg::F_GETFL)?, flags);
            drop(writer);
            if let Some(mut reader) = reader {
                let mut output = Vec::new();
                reader.read_to_end(&mut output)?;
                if success {
                    fill.extend_from_slice(&expected.stdout);
                    assert_eq!(output, fill, "{mode} {scenario}");
                } else {
                    assert_eq!(output, fill, "{mode}: partial response on timeout");
                }
            }
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn restricted_evaluators_close_inherited_descriptors_before_reading_input(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let marker = std::env::temp_dir().join(format!("zen-inherited-{}-{nonce}", std::process::id()));
    let marker_file = std::fs::OpenOptions::new().write(true).create_new(true).open(&marker)?;
    drop(marker_file);
    let marker = std::fs::canonicalize(marker)?;
    let request = serde_json::to_vec(&json!({"kind":"preview", "source":SOURCE,
        "facts":{"quantity":1,"maxQuantity":2,"authorized":true}}))?;

    // The shell deliberately opens fd 9 without close-on-exec. The unrestricted
    // preview is a positive control proving that the launcher passes it through.
    for mode in ["--preview-stdio", "--restricted-preview-stdio", "--supervised-preview-stdio"] {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec 9<\"$1\"; exec \"$2\" \"$3\"")
            .arg("test")
            .arg(&marker)
            .arg(env!("CARGO_BIN_EXE_cityos-zen-worker"))
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("missing stdin")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let observed = loop {
            let evaluator = if mode == "--supervised-preview-stdio" {
                let path = format!("/proc/{0}/task/{0}/children", child.id());
                std::fs::read_to_string(path).ok().and_then(|pids| {
                    pids.split_whitespace().next().and_then(|pid| pid.parse::<u32>().ok())
                })
            } else {
                Some(child.id())
            };
            if let Some(pid) = evaluator {
                let fd_dir = format!("/proc/{pid}/fd");
                let targets = std::fs::read_dir(fd_dir).and_then(|entries| {
                    entries.map(|entry| std::fs::read_link(entry?.path())).collect::<std::io::Result<Vec<_>>>()
                });
                if mode == "--preview-stdio" && targets.as_ref().is_ok_and(|targets| targets.contains(&marker)) {
                    break true;
                }
                if mode != "--preview-stdio" {
                    let ready = std::fs::read_to_string(format!("/proc/{pid}/status"))
                        .is_ok_and(|status| status.lines().any(|line| {
                            line.strip_prefix("NoNewPrivs:").is_some_and(|value| value.trim() == "1")
                        }));
                    if ready && targets.as_ref().is_ok_and(|targets| !targets.contains(&marker)) {
                        break true;
                    }
                }
            }
            if child.try_wait()?.is_some() || Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        input.write_all(&request)?;
        drop(input);
        let result = child.wait_with_output()?;
        assert!(observed, "descriptor state was not observed for {mode}");
        assert!(result.status.success(), "preview failed for {mode}");
        let body: Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(body["allowed"], true);
    }
    std::fs::remove_file(marker)?;
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
        serde_json::to_vec(&json!(["preview", SOURCE,
            {"quantity":1,"maxQuantity":2,"authorized":true}]))?,
        serde_json::to_vec(&json!({"kind":"preview", "source":SOURCE,
            "facts":[1,2,true]}))?,
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
