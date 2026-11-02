use std::io::Write;
use std::process::{Command, Output, Stdio};

use cityos_zen_contracts::{
    S14ConsentPreviewFacts, S14ConsentPreviewRequest, S14ConsentPreviewResponse,
    S14ConsentPreviewState, S14_CONSENT_SOURCE_SHA256,
};
use serde_json::{json, Value};

const KIND: &str = "s14-consent-preview";
const PROFILE: &str = "cityos.zen.s14-consent-preview.v1";
const MAX_DATE: i64 = 8_640_000_000_000_000;

fn request(required: bool, consent: Value, now: i64) -> Value {
    json!({
        "kind": KIND,
        "profile": PROFILE,
        "facts": {"required": required, "consent": consent, "nowMillis": now}
    })
}

fn run(mode: &str, input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg(mode)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("missing stdin")?.write_all(input)?;
    Ok(child.wait_with_output()?)
}

fn assert_cases(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    for (required, consent, now, expected) in [
        (true, json!({"state":"missing-or-not-granted"}), 10, "consent-not-granted"),
        (false, json!({"state":"missing-or-not-granted"}), 10, "satisfied"),
        (true, json!({"state":"granted","expiresAtMillis":null}), 10, "satisfied"),
        (true, json!({"state":"granted","expiresAtMillis":11}), 10, "satisfied"),
        (true, json!({"state":"granted","expiresAtMillis":10}), 10, "consent-not-granted"),
        (true, json!({"state":"granted","expiresAtMillis":9}), 10, "consent-not-granted"),
        (true, json!({"state":"granted","expiresAtMillis":MAX_DATE}), MAX_DATE - 1, "satisfied"),
        (true, json!({"state":"granted","expiresAtMillis":-MAX_DATE + 1}), -MAX_DATE, "satisfied"),
    ] {
        let output = run(mode, &serde_json::to_vec(&request(required, consent, now))?)?;
        assert!(output.status.success(), "{mode}: {:?}", output.stderr);
        let response: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(response, json!({"kind":KIND,"profile":PROFILE,"outcome":expected,"sourceSha256":S14_CONSENT_SOURCE_SHA256}));
    }
    Ok(())
}

#[test]
fn consent_preview_returns_only_the_typed_gate_outcome() -> Result<(), Box<dyn std::error::Error>> {
    assert_cases("--s14-consent-preview-stdio")
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_consent_preview_returns_the_same_gate_outcomes() -> Result<(), Box<dyn std::error::Error>> {
    assert_cases("--supervised-s14-consent-preview-stdio")
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_s14_errors_do_not_block_on_full_stdout_and_stderr(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::unistd::pipe;

    fn full_pipe(byte: u8) -> Result<(File, File, Vec<u8>), Box<dyn std::error::Error>> {
        let (read_fd, write_fd) = pipe()?;
        let reader = File::from(read_fd);
        let mut writer = File::from(write_fd);
        let flags = OFlag::from_bits_retain(fcntl(writer.as_raw_fd(), FcntlArg::F_GETFL)?);
        fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        let mut contents = Vec::new();
        loop {
            match writer.write(&[byte; 4096]) {
                Ok(0) => return Err("zero-length pipe fill".into()),
                Ok(n) => contents.extend(std::iter::repeat(byte).take(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
        assert!(!contents.is_empty());
        Ok((reader, writer, contents))
    }

    let valid = serde_json::to_vec(&request(true, json!({"state":"missing-or-not-granted"}), 10))?;
    for scenario in ["blocked-output", "invalid-input", "extra-argument"] {
        let (mut stdout_reader, stdout_writer, stdout_fill) = full_pipe(b'o')?;
        let (mut stderr_reader, stderr_writer, stderr_fill) = full_pipe(b'e')?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"));
        command.arg("--supervised-s14-consent-preview-stdio");
        if scenario == "extra-argument" {
            command.arg("extra");
        }
        let mut child = command.env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::from(stdout_writer.try_clone()?))
            .stderr(Stdio::from(stderr_writer.try_clone()?))
            .spawn()?;
        if scenario == "extra-argument" {
            drop(child.stdin.take());
        } else {
            let input = if scenario == "invalid-input" { b"invalid".as_slice() } else { &valid };
            if let Err(error) = child.stdin.take().ok_or("missing stdin")?.write_all(input) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        }
        let until = Instant::now() + Duration::from_secs(7);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{scenario}: worker blocked on output").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(1), "{scenario}");
        drop(stdout_writer);
        drop(stderr_writer);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        stdout_reader.read_to_end(&mut stdout)?;
        stderr_reader.read_to_end(&mut stderr)?;
        assert_eq!(stdout, stdout_fill, "{scenario}: stdout changed");
        assert_eq!(stderr, stderr_fill, "{scenario}: stderr changed");
    }
    Ok(())
}

fn assert_rejections(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
    let facts = json!({"required":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0});
    let cases = [
        serde_json::to_vec(&json!({"kind":"preview","profile":PROFILE,"facts":facts}))?,
        serde_json::to_vec(&json!({"kind":KIND,"profile":"wrong","facts":facts}))?,
        serde_json::to_vec(&json!({"kind":KIND,"profile":PROFILE,"facts":facts,"receipt":{}}))?,
        serde_json::to_vec(&json!({"kind":"preview","source":"{}","facts":{"quantity":1,"maxQuantity":2,"authorized":true}}))?,
        serde_json::to_vec(&request(true, json!({"state":"revoked"}), 0))?,
        serde_json::to_vec(&request(true, json!({"state":"granted"}), 0))?,
        serde_json::to_vec(&request(true, json!({"state":"missing-or-not-granted","expiresAtMillis":0}), 0))?,
        serde_json::to_vec(&request(true, json!({"state":"missing-or-not-granted","expiresAtMillis":null}), 0))?,
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"expiresAtMillis":null,"state":"missing-or-not-granted"},"nowMillis":0}}"#.to_vec(),
        serde_json::to_vec(&request(true, json!({"state":"granted","expiresAtMillis":"secret-value"}), 0))?,
        serde_json::to_vec(&request(true, json!({"state":"granted","expiresAtMillis":1.5}), 0))?,
        serde_json::to_vec(&request(true, json!({"state":"granted","expiresAtMillis":MAX_DATE + 1}), 0))?,
        serde_json::to_vec(&request(false, json!({"state":"missing-or-not-granted"}), -MAX_DATE - 1))?,
        br#"["s14-consent-preview","cityos.zen.s14-consent-preview.v1",{"required":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0}]"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":[true,{"state":"missing-or-not-granted"},0]}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":["granted",null],"nowMillis":0}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"requ\u0069red":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"state":"missing-or-not-granted","state":"missing-or-not-granted"},"nowMillis":0}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"state":"granted","expiresAtMillis":1,"expiresAtMillis":2},"nowMillis":0}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"expiresAtMillis":1,"expiresAtMillis":2,"state":"granted"},"nowMillis":0}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0,"extra":true}}"#.to_vec(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"state":"granted","expiresAtMillis":null,"extra":true},"nowMillis":0}}"#.to_vec(),
        vec![b'x'; 131_073],
    ];
    for (index, input) in cases.into_iter().enumerate() {
        let output = run(mode, &input)?;
        assert!(!output.status.success(), "{mode} accepted invalid input case {index}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-value"));
    }
    Ok(())
}

#[test]
fn escaped_json_key_is_decoded_before_duplicate_detection() -> Result<(), Box<dyn std::error::Error>> {
    let escaped = br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"requ\u0069red":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0}}"#;
    let duplicate = br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"requ\u0069red":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0}}"#;

    let decoded: Value = serde_json::from_slice(escaped)?;
    assert_eq!(decoded["facts"]["required"], true);
    assert!(serde_json::from_slice::<S14ConsentPreviewRequest>(escaped).is_ok());
    assert!(serde_json::from_slice::<S14ConsentPreviewRequest>(duplicate).is_err());
    Ok(())
}

#[test]
fn consent_contract_types_require_objects_and_reject_duplicate_keys() {
    let request = br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","facts":{"required":true,"consent":{"expiresAtMillis":null,"state":"granted"},"nowMillis":0}}"#;
    assert!(serde_json::from_slice::<S14ConsentPreviewRequest>(request).is_ok());
    assert!(serde_json::from_slice::<S14ConsentPreviewRequest>(br#"["s14-consent-preview","cityos.zen.s14-consent-preview.v1",{"required":true,"consent":{"state":"missing-or-not-granted"},"nowMillis":0}]"#).is_err());
    assert!(serde_json::from_slice::<S14ConsentPreviewFacts>(br#"[true,{"state":"missing-or-not-granted"},0]"#).is_err());
    assert!(serde_json::from_slice::<S14ConsentPreviewState>(br#"["granted",null]"#).is_err());

    let response = br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543"}"#;
    assert!(serde_json::from_slice::<S14ConsentPreviewResponse>(response).is_ok());
    for invalid in [
        br#"["s14-consent-preview","cityos.zen.s14-consent-preview.v1","satisfied","70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543"]"#.as_slice(),
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied"}"#,
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"wrong"}"#,
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"70815B2280ADE5C5C813DC38F16767BDA5C1B91514AE3C425B5B9F1A76761543"}"#,
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543","sourceSha256":"70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543"}"#,
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","outcome":"satisfied","sourceSha256":"70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543"}"#,
        br#"{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"70815b2280ade5c5c813dc38f16767bda5c1b91514ae3c425b5b9f1a76761543","extra":true}"#,
    ] {
        assert!(serde_json::from_slice::<S14ConsentPreviewResponse>(invalid).is_err());
    }
}

#[test]
fn consent_preview_rejects_invalid_and_cart_requests() -> Result<(), Box<dyn std::error::Error>> {
    assert_rejections("--s14-consent-preview-stdio")?;
    let input = serde_json::to_vec(&request(true, json!({"state":"missing-or-not-granted"}), 0))?;
    let output = run("--preview-stdio", &input)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn supervised_consent_rejects_invalid_input_and_times_out_without_eof() -> Result<(), Box<dyn std::error::Error>> {
    assert_rejections("--supervised-s14-consent-preview-stdio")?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_cityos-zen-worker"))
        .arg("--supervised-s14-consent-preview-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = child.stdin.take().ok_or("missing stdin")?;
    let output = child.wait_with_output()?;
    drop(input);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
#[test]
fn supervised_consent_is_unavailable_on_unsupported_platforms() -> Result<(), Box<dyn std::error::Error>> {
    for mode in ["--supervised-s14-consent-preview-stdio", "--restricted-s14-consent-preview-stdio"] {
        let output = run(mode, b"")?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    Ok(())
}
