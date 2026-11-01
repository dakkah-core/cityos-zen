//! Linux process supervision for synthetic previews only. This is not a sandbox.
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use cityos_zen_contracts::{PROFILE, PolicyError};
use serde::Deserialize;

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: u64 = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviewResponse {
    kind: String,
    allowed: bool,
    source_sha256: String,
    profile: String,
}

// The caller supplies only a fixed executable and argument in production.
// Input is inherited so the same deadline covers a caller that never closes it.
fn supervise(command: &mut Command, deadline: Duration) -> Result<Vec<u8>, ()> {
    let started = Instant::now();
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut bytes);
        let _ = sender.send(result.map(|_| bytes));
    });

    let mut output = None;
    let mut status = None;
    loop {
        if started.elapsed() >= deadline {
            break;
        }
        if output.is_none() {
            match receiver.try_recv() {
                Ok(Ok(bytes)) if bytes.len() as u64 <= MAX_RESPONSE_BYTES => output = Some(bytes),
                Ok(_) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit)) if exit.success() => status = Some(exit),
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
        }
        if status.is_some() && output.is_some() {
            return output.ok_or(());
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_sub(started.elapsed())));
    }
    // A killed or failed child can never contribute even a partial response.
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Err(())
}

pub(crate) fn preview() -> Result<(), PolicyError> {
    let executable = std::env::current_exe().map_err(|_| PolicyError::Evaluation)?;
    let mut command = Command::new(executable);
    command
        .arg("--preview-stdio")
        .env_clear()
        .stdin(Stdio::inherit());
    let bytes = supervise(&mut command, DEADLINE).map_err(|_| PolicyError::Evaluation)?;
    let response: PreviewResponse =
        serde_json::from_slice(&bytes).map_err(|_| PolicyError::Evaluation)?;
    if response.kind != "preview"
        || response.profile != PROFILE
        || response.source_sha256.len() != 64
        || !response
            .source_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(PolicyError::Evaluation);
    }
    // Check the typed result before forwarding the child's original non-authoritative response.
    let _ = response.allowed;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&bytes)
        .map_err(|_| PolicyError::Evaluation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_discards_failed_and_oversized_child_output() {
        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "printf partial; exit 1"]);
        assert!(supervise(&mut failed, Duration::from_secs(2)).is_err());

        let mut flood = Command::new("/bin/sh");
        flood.args(["-c", "while :; do printf 0123456789; done"]);
        assert!(supervise(&mut flood, Duration::from_secs(2)).is_err());
    }

    #[test]
    fn supervisor_stops_a_child_that_exceeds_its_deadline() {
        let mut slow = Command::new("/bin/sleep");
        slow.arg("10");
        assert!(supervise(&mut slow, Duration::from_millis(100)).is_err());
    }
}
