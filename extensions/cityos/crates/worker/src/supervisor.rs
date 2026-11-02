//! Linux process supervision for synthetic previews only. This is not a sandbox.
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use cityos_zen_contracts::{
    PolicyError, S14ConsentPreviewResponse, PROFILE, S14_CONSENT_PREVIEW_KIND,
    S14_CONSENT_PREVIEW_PROFILE, S14_CONSENT_SOURCE_SHA256,
};
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::prctl::{get_no_new_privs, set_no_new_privs};
use nix::sys::signal::{killpg, Signal};
use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use serde::Deserialize;

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: u64 = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const REAP_GRACE: Duration = Duration::from_millis(100);

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviewResponse {
    kind: String,
    allowed: bool,
    source_sha256: String,
    profile: String,
}

// Observe without reaping: the child PID must stay reserved until after killpg,
// or a reused process-group ID could target an unrelated process.
fn child_status(pid: Pid) -> Result<WaitStatus, ()> {
    loop {
        match waitid(
            Id::Pid(pid),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        ) {
            Err(Errno::EINTR) => continue,
            result => return result.map_err(|_| ()),
        }
    }
}

// A descendant can leave the group; this is cleanup, not containment. Only the
// direct child is ours to reap. Another child-reaper in this process would
// invalidate the PID reservation and is incompatible with this supervisor.
fn cleanup(mut child: Child, pid: Pid) -> Result<(), ()> {
    let status = child_status(pid)?;
    let exited = !matches!(status, WaitStatus::StillAlive);
    let signalled = match killpg(pid, Signal::SIGKILL) {
        Ok(()) => true,
        Err(Errno::ESRCH) if exited => true,
        Err(_) => false,
    };
    // A successful group signal does not prove it reached the direct child:
    // the child can join another process group while descendants remain here.
    // Its PID is still reserved, so also signal the direct child before reaping.
    let direct_stopped = exited
        || child.kill().is_ok()
        || child_status(pid).is_ok_and(|status| !matches!(status, WaitStatus::StillAlive));
    if exited {
        child.wait().map_err(|_| ())?;
    } else {
        // Reap promptly in the normal case before the short-lived supervisor
        // process exits; this grace period also bounds the synchronous wait.
        let started = Instant::now();
        while started.elapsed() < REAP_GRACE {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return if signalled && direct_stopped {
                        Ok(())
                    } else {
                        Err(())
                    }
                }
                Ok(None) => {
                    thread::sleep(POLL_INTERVAL.min(REAP_GRACE.saturating_sub(started.elapsed())))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            }
        }
        // A task stuck in uninterruptible kernel sleep may not exit promptly,
        // even after SIGKILL. A background reaper can only run for as long as
        // the supervisor process remains alive.
        thread::Builder::new()
            .name("preview-child-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            })
            .map_err(|_| ())?;
    }
    if signalled && direct_stopped {
        Ok(())
    } else {
        Err(())
    }
}

// Input is inherited so the same deadline covers a caller that never closes it.
#[cfg(test)]
fn supervise(command: &mut Command, deadline: Duration) -> Result<Vec<u8>, ()> {
    supervise_from(command, Instant::now(), deadline)
}

fn supervise_from(command: &mut Command, started: Instant, deadline: Duration) -> Result<Vec<u8>, ()> {
    let mut child = command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let pid = match i32::try_from(child.id()) {
        Ok(pid) if pid > 0 => Pid::from_raw(pid),
        _ => {
            let _ = child.kill();
            let _ = thread::Builder::new().spawn(move || {
                let _ = child.wait();
            });
            return Err(());
        }
    };
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or(())?;
        let flags =
            OFlag::from_bits_retain(fcntl(stdout.as_raw_fd(), FcntlArg::F_GETFL).map_err(|_| ())?);
        fcntl(
            stdout.as_raw_fd(),
            FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
        )
        .map_err(|_| ())?;
        let mut output = Vec::new();
        let mut eof = false;
        let mut buffer = [0u8; 4096];
        loop {
            if started.elapsed() >= deadline {
                return Err(());
            }
            if !eof {
                match stdout.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        output.extend_from_slice(&buffer[..n]);
                        if output.len() as u64 > MAX_RESPONSE_BYTES {
                            return Err(());
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(()),
                }
            }
            match child_status(pid)? {
                WaitStatus::Exited(_, 0) if eof => return Ok(output),
                WaitStatus::Exited(_, 0) | WaitStatus::StillAlive => {}
                _ => return Err(()),
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_sub(started.elapsed())));
        }
    })();
    // Also signal the group after success, before releasing the child's PID.
    // Never return partial output or a result if cleanup could not be initiated.
    cleanup(child, pid)?;
    result
}

pub(crate) fn preview() -> Result<(), PolicyError> {
    supervised_preview("--restricted-preview-stdio", ResponseProfile::Cart)
}

pub(crate) fn s14_consent_preview() -> Result<(), PolicyError> {
    supervised_preview(
        "--restricted-s14-consent-preview-stdio",
        ResponseProfile::S14Consent,
    )
}

/// Experimental namespace setup, not a credential boundary or sandbox.
pub(crate) fn experimental_network_preview() -> Result<(), PolicyError> {
    supervised_preview("--experimental-network-child-stdio", ResponseProfile::Cart)
}

#[derive(Clone, Copy)]
enum ResponseProfile {
    Cart,
    S14Consent,
}

fn validate_response(bytes: &[u8], profile: ResponseProfile) -> Result<(), PolicyError> {
    match profile {
        ResponseProfile::Cart => {
            let response: PreviewResponse =
                serde_json::from_slice(bytes).map_err(|_| PolicyError::Evaluation)?;
            if response.kind != "preview"
                || response.profile != PROFILE
                || response.source_sha256.len() != 64
                || !response.source_sha256.bytes().all(|b| {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                })
            {
                return Err(PolicyError::Evaluation);
            }
            let _ = response.allowed;
        }
        ResponseProfile::S14Consent => {
            let response: S14ConsentPreviewResponse =
                serde_json::from_slice(bytes).map_err(|_| PolicyError::Evaluation)?;
            if response.kind != S14_CONSENT_PREVIEW_KIND
                || response.profile != S14_CONSENT_PREVIEW_PROFILE
                || response.source_sha256 != S14_CONSENT_SOURCE_SHA256
            {
                return Err(PolicyError::Evaluation);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn supervised_response(
    command: &mut Command,
    deadline: Duration,
    profile: ResponseProfile,
) -> Result<Vec<u8>, PolicyError> {
    supervised_response_from(command, Instant::now(), deadline, profile)
}

fn supervised_response_from(
    command: &mut Command,
    started: Instant,
    deadline: Duration,
    profile: ResponseProfile,
) -> Result<Vec<u8>, PolicyError> {
    let bytes = supervise_from(command, started, deadline).map_err(|_| PolicyError::Evaluation)?;
    validate_response(&bytes, profile)?;
    Ok(bytes)
}

// S14 output requires an anonymous Linux pipe with a stable, write-only fd and
// a trusted, accessible procfs that permits reopening the pipe for writing.
// Reopening the procfs fd creates a separate open file description, so
// O_NONBLOCK never changes the caller's flags. Do
// not extend this to regular files: O_NONBLOCK does not bound their writes.
// TTYs, sockets, named FIFOs, an O_DIRECT writer fd and unavailable procfs
// fail closed. As elsewhere in this supervisor, the process must not
// concurrently replace the fd or change its flags; other pipe writers can
// write independently. Syscall scheduling/kernel stalls are not time-bounded.
// Linux guarantees nonblocking writes of at most PIPE_BUF (4096) are atomic:
// either the whole response is delivered or no response bytes are delivered.
fn forward_pipe(fd: RawFd, bytes: &[u8], started: Instant, deadline: Duration) -> Result<(), ()> {
    if bytes.is_empty() || bytes.len() > 4096 || started.elapsed() >= deadline {
        return Err(());
    }
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|_| ())?;
    if flags & nix::libc::O_ACCMODE != nix::libc::O_WRONLY
        || flags & nix::libc::O_DIRECT != 0
    {
        return Err(());
    }
    let path = format!("/proc/self/fd/{fd}");
    let target = std::fs::read_link(&path).map_err(|_| ())?;
    if !target.to_str().is_some_and(|name| name.starts_with("pipe:[") && name.ends_with(']')) {
        return Err(());
    }
    let original = std::fs::metadata(&path).map_err(|_| ())?;
    if !original.file_type().is_fifo() {
        return Err(());
    }
    let mut pipe = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| ())?;
    let reopened = pipe.metadata().map_err(|_| ())?;
    if !reopened.file_type().is_fifo()
        || original.dev() != reopened.dev()
        || original.ino() != reopened.ino()
    {
        return Err(());
    }
    loop {
        if started.elapsed() >= deadline {
            return Err(());
        }
        match pipe.write(bytes) {
            Ok(n) if n == bytes.len() => return Ok(()),
            // A short write is not expected under the Linux PIPE_BUF contract.
            Ok(_) => return Err(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL.min(deadline.saturating_sub(started.elapsed())));
            }
            Err(_) => return Err(()),
        }
    }
}

fn supervised_forward(
    command: &mut Command,
    deadline: Duration,
    profile: ResponseProfile,
    output_fd: RawFd,
) -> Result<(), PolicyError> {
    let started = Instant::now();
    let bytes = supervised_response_from(command, started, deadline, profile)?;
    // Cleanup and validation finish before forwarding. The same time budget
    // covers collection, cleanup, validation and the nonblocking write.
    forward_pipe(output_fd, &bytes, started, deadline).map_err(|_| PolicyError::Evaluation)
}

fn supervised_preview(child_mode: &str, profile: ResponseProfile) -> Result<(), PolicyError> {
    let executable = std::env::current_exe().map_err(|_| PolicyError::Evaluation)?;
    let mut command = Command::new(executable);
    command
        .arg(child_mode)
        .env_clear()
        .stdin(Stdio::inherit());
    match profile {
        ResponseProfile::S14Consent => {
            supervised_forward(&mut command, DEADLINE, profile, io::stdout().as_raw_fd())
        }
        ResponseProfile::Cart => {
            // Preserve the legacy cart and experimental destination behavior.
            let bytes = supervised_response_from(&mut command, Instant::now(), DEADLINE, profile)?;
            io::stdout().lock().write_all(&bytes).map_err(|_| PolicyError::Evaluation)
        }
    }
}

/// Install the privilege ceiling and resource limits before reading input.
/// This preview is not an authority, credential boundary, or sandbox.
pub(crate) fn restricted_preview() -> Result<(), PolicyError> {
    restricted(crate::preview)
}

pub(crate) fn restricted_s14_consent_preview() -> Result<(), PolicyError> {
    restricted(crate::s14_consent_preview)
}

fn restricted(preview: impl FnOnce() -> Result<(), PolicyError>) -> Result<(), PolicyError> {
    crate::inherited_fds::close_and_verify()?;
    require_no_new_privs(
        || set_no_new_privs().map_err(|_| ()),
        || get_no_new_privs().map_err(|_| ()),
    )?;
    crate::resource_limits::install()?;
    preview()
}

// Namespace setup must finish successfully before any preview input is read.
fn network_then_preview(
    isolate: impl FnOnce() -> Result<(), PolicyError>,
    preview: impl FnOnce() -> Result<(), PolicyError>,
) -> Result<(), PolicyError> {
    isolate()?;
    preview()
}

pub(crate) fn experimental_network_child() -> Result<(), PolicyError> {
    // A new network namespace does not revoke already-open sockets.
    crate::inherited_fds::close_and_verify()?;
    network_then_preview(crate::network::isolate, restricted_preview)
}

fn require_no_new_privs(
    set: impl FnOnce() -> Result<(), ()>,
    read: impl FnOnce() -> Result<bool, ()>,
) -> Result<(), PolicyError> {
    set().map_err(|_| PolicyError::Evaluation)?;
    if read().map_err(|_| PolicyError::Evaluation)? {
        Ok(())
    } else {
        Err(PolicyError::Evaluation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn forwarding_rejects_regular_files_without_changing_them(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("zen-forward-{}-{nonce}", std::process::id()));
        let file = fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        let flags = fcntl(file.as_raw_fd(), FcntlArg::F_GETFL)?;
        let result = forward_pipe(file.as_raw_fd(), b"response", Instant::now(), Duration::from_secs(1));
        let final_flags = fcntl(file.as_raw_fd(), FcntlArg::F_GETFL)?;
        let size = file.metadata()?.len();
        drop(file);
        fs::remove_file(path)?;
        assert!(result.is_err());
        assert_eq!(final_flags, flags);
        assert_eq!(size, 0);
        Ok(())
    }

    // This probe runs in a subprocess whose stdin is a full, write-only pipe.
    // Using fd 0 avoids changing any process-wide inherited descriptor flags.
    #[test]
    fn delayed_s14_forward_probe() -> Result<(), Box<dyn std::error::Error>> {
        let Some(marker) = std::env::var_os("CITYOS_ZEN_DELAYED_FORWARD_MARKER") else {
            return Ok(());
        };
        let response = format!(r#"{{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"{S14_CONSENT_SOURCE_SHA256}"}}"#);
        let mut child = Command::new("/bin/sh");
        child.args(["-c", "sleep 2; printf ready > \"$2\"; printf '%s' \"$1\"", "test", &response]);
        child.arg(marker).stdin(Stdio::null());
        let started = Instant::now();
        let result = supervised_forward(&mut child, Duration::from_secs(3), ResponseProfile::S14Consent, 0);
        let elapsed = started.elapsed();
        assert!(result.is_err());
        assert!(elapsed >= Duration::from_millis(2700), "failed before waiting for output: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(4200), "output got a fresh deadline: {elapsed:?}");
        Ok(())
    }

    #[test]
    fn delayed_child_and_blocked_output_share_deadline() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use nix::unistd::pipe;

        let (reader_fd, writer_fd) = pipe()?;
        let _reader = File::from(reader_fd);
        let mut writer = File::from(writer_fd);
        let flags = OFlag::from_bits_retain(fcntl(writer.as_raw_fd(), FcntlArg::F_GETFL)?);
        fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        loop {
            match writer.write(&[b'x'; 4096]) {
                Ok(0) => return Err("zero-length pipe fill".into()),
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        fcntl(writer.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let marker = std::env::temp_dir().join(format!("zen-delayed-{}-{nonce}", std::process::id()));
        let mut probe = Command::new(std::env::current_exe()?)
            .args(["--exact", "supervisor::tests::delayed_s14_forward_probe", "--nocapture"])
            .env("CITYOS_ZEN_DELAYED_FORWARD_MARKER", &marker)
            .stdin(Stdio::from(writer))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let until = Instant::now() + Duration::from_secs(6);
        let status = loop {
            if let Some(status) = probe.try_wait()? {
                break status;
            }
            if Instant::now() >= until {
                let _ = probe.kill();
                let _ = probe.wait();
                let _ = fs::remove_file(&marker);
                return Err("delayed forwarding probe blocked".into());
            }
            thread::sleep(POLL_INTERVAL);
        };
        let marker_contents = fs::read(&marker);
        let _ = fs::remove_file(marker);
        assert!(status.success(), "delayed forwarding probe failed");
        assert_eq!(marker_contents?.as_slice(), b"ready");
        Ok(())
    }

    #[test]
    fn experimental_network_failure_never_runs_preview() {
        let preview_called = std::cell::Cell::new(false);
        let result = network_then_preview(
            || Err(PolicyError::Evaluation),
            || {
                preview_called.set(true);
                Ok(())
            },
        );
        assert_eq!(result, Err(PolicyError::Evaluation));
        assert!(!preview_called.get());
    }

    #[test]
    fn privilege_ceiling_fails_closed() {
        let read_called = std::cell::Cell::new(false);
        assert!(require_no_new_privs(
            || Err(()),
            || {
                read_called.set(true);
                Ok(true)
            }
        )
        .is_err());
        assert!(!read_called.get());
        assert!(require_no_new_privs(|| Ok(()), || Err(())).is_err());
        assert!(require_no_new_privs(|| Ok(()), || Ok(false)).is_err());
        assert!(require_no_new_privs(|| Ok(()), || Ok(true)).is_ok());
    }

    #[test]
    fn consent_response_validation_rejects_wrong_or_ambiguous_results() {
        let valid = format!(r#"{{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"{S14_CONSENT_SOURCE_SHA256}"}}"#);
        assert!(validate_response(valid.as_bytes(), ResponseProfile::S14Consent).is_ok());
        assert!(validate_response(valid.as_bytes(), ResponseProfile::Cart).is_err());
        for invalid in [
            valid.replace("s14-consent-preview\",", "preview\","),
            valid.replace("cityos.zen.s14-consent-preview.v1", "other"),
            valid.replace("satisfied", "allow"),
            valid.replace("\"outcome\":\"satisfied\"", "\"outcome\":\"satisfied\",\"receipt\":{}"),
            valid.replace("\"outcome\":\"satisfied\"", "\"outcome\":\"satisfied\",\"outcome\":\"consent-not-granted\""),
            valid.replace(&format!(",\"sourceSha256\":\"{S14_CONSENT_SOURCE_SHA256}\""), ""),
            valid.replace(S14_CONSENT_SOURCE_SHA256, &"0".repeat(64)),
            format!(r#"["s14-consent-preview","cityos.zen.s14-consent-preview.v1","satisfied","{S14_CONSENT_SOURCE_SHA256}"]"#),
            "{".to_owned(),
        ] {
            assert!(validate_response(invalid.as_bytes(), ResponseProfile::S14Consent).is_err());
        }
    }

    #[test]
    fn cart_response_still_accepts_the_existing_sequence_representation() {
        let response = format!(
            "[\"preview\",true,\"{}\",\"{}\"]",
            "a".repeat(64),
            PROFILE,
        );
        assert!(validate_response(response.as_bytes(), ResponseProfile::Cart).is_ok());
    }

    #[test]
    fn consent_supervisor_preserves_original_response_bytes() -> Result<(), PolicyError> {
        let response = format!(" {{ \"outcome\":\"satisfied\", \"sourceSha256\":\"{S14_CONSENT_SOURCE_SHA256}\", \"profile\":\"cityos.zen.s14-consent-preview.v1\", \"kind\":\"s14-consent-preview\" }} \n");
        let mut child = Command::new("/bin/sh");
        child.args(["-c", "printf '%s' \"$1\"", "test", &response]);
        let output = supervised_response(&mut child, Duration::from_secs(2), ResponseProfile::S14Consent)?;
        assert_eq!(output.as_slice(), response.as_bytes());
        Ok(())
    }

    #[test]
    fn consent_supervisor_discards_valid_output_on_failure_or_timeout() {
        let valid = format!(r#"{{"kind":"s14-consent-preview","profile":"cityos.zen.s14-consent-preview.v1","outcome":"satisfied","sourceSha256":"{S14_CONSENT_SOURCE_SHA256}"}}"#);
        let wrong = valid.replace("cityos.zen.s14-consent-preview.v1", "wrong");
        let mut wrong_profile = Command::new("/bin/sh");
        wrong_profile.args(["-c", "printf '%s' \"$1\"", "test", &wrong]);
        assert!(supervised_response(
            &mut wrong_profile,
            Duration::from_secs(2),
            ResponseProfile::S14Consent,
        )
        .is_err());

        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "printf '%s' \"$1\"; exit 1", "test", &valid]);
        assert!(supervised_response(
            &mut failed,
            Duration::from_secs(2),
            ResponseProfile::S14Consent,
        )
        .is_err());

        let mut slow = Command::new("/bin/sh");
        slow.args(["-c", "printf '%s' \"$1\"; exec sleep 10", "test", &valid]);
        assert!(supervised_response(
            &mut slow,
            Duration::from_millis(100),
            ResponseProfile::S14Consent,
        )
        .is_err());
    }

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

    // Executed only by the regression below, in a separate process group.
    #[test]
    fn moved_child_probe() -> Result<(), Box<dyn std::error::Error>> {
        let Some(base) = std::env::var_os("CITYOS_ZEN_MOVED_CHILD_PROBE") else {
            return Ok(());
        };
        let base = std::path::PathBuf::from(base);
        let target_group: i32 = std::env::var("CITYOS_ZEN_PARENT_GROUP")?.parse()?;
        // Keep the original group alive after the direct child leaves it.
        let _keeper = Command::new("/bin/sleep")
            .arg("10")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(target_group))?;
        fs::write(base.with_extension("ready"), b"ready")?;
        thread::sleep(Duration::from_secs(4));
        fs::write(base.with_extension("survived"), b"survived")?;
        Ok(())
    }

    #[test]
    fn supervisor_stops_direct_child_after_it_changes_groups(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let base = std::env::temp_dir().join(format!("zen-moved-{}-{nonce}", std::process::id()));
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--exact")
            .arg("supervisor::tests::moved_child_probe")
            .arg("--nocapture")
            .env("CITYOS_ZEN_MOVED_CHILD_PROBE", &base)
            .env(
                "CITYOS_ZEN_PARENT_GROUP",
                nix::unistd::getpgrp().as_raw().to_string(),
            );
        assert!(supervise(&mut command, Duration::from_secs(2)).is_err());
        let ready = base.with_extension("ready");
        let survived = base.with_extension("survived");
        // Allow the probe's delayed marker to expose a direct child that escaped.
        thread::sleep(Duration::from_secs(4));
        let moved = ready.exists();
        let escaped = survived.exists();
        let _ = fs::remove_file(ready);
        let _ = fs::remove_file(survived);
        assert!(moved, "probe never changed process groups");
        assert!(!escaped, "direct child survived process-group cleanup");
        Ok(())
    }

    #[test]
    fn supervisor_kills_group_after_timeout_failure_and_success(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let base = std::env::temp_dir().join(format!("zen-worker-{}-{nonce}", std::process::id()));
        let cases = [
            // A live direct child and descendant both keep stdout open.
            (
                "(sleep 3; printf survived > \"$1\") & printf '%s' \"$$\" > \"$2\"; wait",
                false,
            ),
            // The leader exits before its descendant releases stdout.
            (
                "(sleep 3; printf survived > \"$1\") & printf '%s' \"$$\" > \"$2\"; exit 0",
                false,
            ),
            // Closed stdout must not let a successful leader leave a descendant behind.
            (
                "(sleep 3; printf survived > \"$1\") >/dev/null 2>&1 & printf '%s' \"$$\" > \"$2\"; printf ok",
                true,
            ),
            (
                "(sleep 3; printf survived > \"$1\") >/dev/null 2>&1 & printf '%s' \"$$\" > \"$2\"; exit 1",
                false,
            ),
        ];
        let mut paths = Vec::new();
        for (index, (script, expect_success)) in cases.into_iter().enumerate() {
            let marker = base.with_extension(format!("{index}.marker"));
            let ready = base.with_extension(format!("{index}.ready"));
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(script)
                .arg("test")
                .arg(&marker)
                .arg(&ready);
            let result = supervise(&mut command, Duration::from_millis(500));
            assert_eq!(result.is_ok(), expect_success);
            if expect_success {
                assert_eq!(result.as_deref(), Ok(&b"ok"[..]));
            }
            let pid = Pid::from_raw(fs::read_to_string(&ready)?.parse()?);
            let reap_deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match waitid(
                    Id::Pid(pid),
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                ) {
                    Err(Errno::ECHILD) => break,
                    _ if Instant::now() < reap_deadline => thread::sleep(POLL_INTERVAL),
                    other => panic!("direct child was not reaped: {other:?}"),
                }
            }
            paths.push((marker, ready));
        }
        // Each descendant would write this marker if it survived cleanup.
        thread::sleep(Duration::from_secs(4));
        for (marker, ready) in paths {
            let survived = marker.exists();
            let _ = fs::remove_file(&marker);
            fs::remove_file(ready)?;
            assert!(!survived, "a process-group descendant survived");
        }
        Ok(())
    }
}
