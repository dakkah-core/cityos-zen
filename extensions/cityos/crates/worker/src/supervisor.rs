//! Linux process supervision for synthetic previews only. This is not a sandbox.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use cityos_zen_contracts::{PolicyError, PROFILE};
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
fn supervise(command: &mut Command, deadline: Duration) -> Result<Vec<u8>, ()> {
    let started = Instant::now();
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
    supervised_preview("--restricted-preview-stdio")
}

/// Experimental namespace setup, not a credential boundary or sandbox.
pub(crate) fn experimental_network_preview() -> Result<(), PolicyError> {
    supervised_preview("--experimental-network-child-stdio")
}

fn supervised_preview(child_mode: &str) -> Result<(), PolicyError> {
    let executable = std::env::current_exe().map_err(|_| PolicyError::Evaluation)?;
    let mut command = Command::new(executable);
    command
        .arg(child_mode)
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

/// Install the privilege ceiling and resource limits before reading input.
/// This preview is not an authority, credential boundary, or sandbox.
pub(crate) fn restricted_preview() -> Result<(), PolicyError> {
    crate::inherited_fds::close_and_verify()?;
    require_no_new_privs(
        || set_no_new_privs().map_err(|_| ()),
        || get_no_new_privs().map_err(|_| ()),
    )?;
    crate::resource_limits::install()?;
    crate::preview()
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
