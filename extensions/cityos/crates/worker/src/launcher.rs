//! One-shot, registered-cgroup host supervisor for the S14 evaluator.
//! Host registration and exclusive cgroup custody are external prerequisites.
use std::{fs::File, io::{self, IoSlice, Read, Write}, mem::MaybeUninit,
    os::{fd::{AsFd, AsRawFd, OwnedFd}, unix::{net::UnixStream, process::CommandExt}},
    process::{Child, Command, Stdio}, sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}}, thread, time::{Duration, Instant}};
use cityos_zen_contracts::PolicyError;
use nix::{errno::Errno, fcntl::{fcntl, FcntlArg, OFlag}, sys::{signal::{killpg, Signal}, wait::{waitid, Id, WaitPidFlag, WaitStatus}}, unistd::{pipe2, Pid}};
use rustix::net::{send, sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use crate::{bootstrap, registered_sandbox::RegisteredCgroup, s14_rule_preview, verified_artifact::VerifiedArtifact};

const INTERVAL: Duration = Duration::from_millis(5);
const REAP_GRACE: Duration = Duration::from_millis(100);

/// Single-use launcher. The caller must have registered this exact exclusive
/// cgroup and artifact out of band and keep an external recovery owner alive.
/// No other code may reap this launcher's child: PID reservation is required
/// until after cgroup placement and process-group cleanup.
pub struct TrustedLauncher { resources: RegisteredCgroup, artifact: VerifiedArtifact }

impl TrustedLauncher {
    /// Capture a host-opened registered artifact as a sealed executable. The
    /// caller still authenticates the registration and owns cgroup custody.
    pub fn capture_file(resources: crate::RegisteredResources, artifact: File,
        expected_artifact_sha256: &str, expected_selector_sha256: &str) -> Result<Self, PolicyError> {
        Self::capture_verified(resources, VerifiedArtifact::from_file(artifact, expected_artifact_sha256)?, expected_selector_sha256)
    }

    pub fn capture(resources: crate::RegisteredResources, artifact: OwnedFd,
        expected_artifact_sha256: &str, expected_selector_sha256: &str) -> Result<Self, PolicyError> {
        Self::capture_verified(resources, VerifiedArtifact::capture(artifact, expected_artifact_sha256)?, expected_selector_sha256)
    }

    fn capture_verified(resources: crate::RegisteredResources, artifact: VerifiedArtifact,
        expected_selector_sha256: &str) -> Result<Self, PolicyError> {
        if expected_selector_sha256.len() != 64
            || !expected_selector_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || cityos_zen_runtime::s14_decision::selector_document_sha256()? != expected_selector_sha256
        { return Err(PolicyError::Evaluation); }
        Ok(Self { resources: resources.0, artifact })
    }

    /// Run one complete request. A result is returned only after a successful
    /// child exit, EOF, cgroup kill/empty observation, direct-child reaping,
    /// output validation, a final limit readback, and the shared deadline.
    pub fn execute(mut self, request: &[u8]) -> Result<Vec<u8>, PolicyError> {
        let profile = self.resources.profile();
        if request.len() > profile.request_limit() { return Err(PolicyError::InvalidInput); }
        let started = Instant::now();
        let deadline = profile.deadline();
        self.resources.recheck().map_err(|_| PolicyError::Evaluation)?;
        let (host, child_socket) = UnixStream::pair().map_err(|_| PolicyError::Evaluation)?;
        host.set_nonblocking(true).map_err(|_| PolicyError::Evaluation)?;
        let child = Command::new(self.artifact.exec_path())
            .arg("--s14-host-bootstrap-stdio").env_clear().process_group(0)
            .stdin(Stdio::from(OwnedFd::from(child_socket)))
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| PolicyError::Evaluation)?;
        let mut guard = Guard { child: Some(child), resources: self.resources, cleaned: false,
            cancelled: Arc::new(AtomicBool::new(false)), writer: None };
        let result = (|| {
            let pid = guard.child.as_ref().ok_or(PolicyError::Evaluation)?.id();
            guard.resources.place_bootstrap(pid).map_err(|_| PolicyError::Evaluation)?;
            if started.elapsed() >= deadline { return Err(PolicyError::Evaluation); }
            let directory = guard.resources.evaluator_directory().map_err(|_| PolicyError::Evaluation)?;
            let (input, output) = pipe2(OFlag::O_CLOEXEC).map_err(|_| PolicyError::Evaluation)?;
            let descriptors = [directory.as_fd(), input.as_fd()];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) { return Err(PolicyError::Evaluation); }
            let token = [bootstrap::token()];
            let slices = [IoSlice::new(&token)];
            loop {
                if started.elapsed() >= deadline { return Err(PolicyError::Evaluation); }
                match sendmsg(&host, &slices, &mut ancillary, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                    Ok(1) => break,
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => thread::sleep(INTERVAL),
                    _ => return Err(PolicyError::Evaluation),
                }
            }
            drop(ancillary);
            drop(input);
            drop(directory);
            let frame = bootstrap::encode(profile.clone())?;
            write_deadline(&host, &frame, started, deadline)?;
            drop(host);
            let writer = File::from(output);
            let writer_fd = writer.as_raw_fd();
            let flags = OFlag::from_bits_retain(fcntl(writer_fd, FcntlArg::F_GETFL).map_err(|_| PolicyError::Evaluation)?);
            fcntl(writer_fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(|_| PolicyError::Evaluation)?;
            let data = request.to_vec();
            let cancelled = guard.cancelled.clone();
            let (written_tx, written_rx) = mpsc::sync_channel(1);
            guard.writer = Some(thread::Builder::new().name("s14-input-writer".into()).spawn(move || {
                let result = write_input(writer, &data, started, deadline, &cancelled);
                let _ = written_tx.send(result);
            }).map_err(|_| PolicyError::Evaluation)?);
            let child = guard.child.as_mut().ok_or(PolicyError::Evaluation)?;
            let mut stdout = child.stdout.take().ok_or(PolicyError::Evaluation)?;
            let flags = OFlag::from_bits_retain(fcntl(stdout.as_raw_fd(), FcntlArg::F_GETFL).map_err(|_| PolicyError::Evaluation)?);
            fcntl(stdout.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(|_| PolicyError::Evaluation)?;
            let mut written = false;
            let mut bytes = Vec::new();
            let mut eof = false;
            loop {
                if started.elapsed() >= deadline { return Err(PolicyError::Evaluation); }
                if !written {
                    match written_rx.try_recv() {
                        Ok(Ok(())) => written = true,
                        Err(mpsc::TryRecvError::Empty) => {},
                        _ => return Err(PolicyError::Evaluation),
                    }
                }
                if !eof {
                    let mut chunk = [0u8; 4096];
                    match stdout.read(&mut chunk) {
                        Ok(0) => eof = true,
                        Ok(n) => {
                            if bytes.len().checked_add(n).is_none_or(|size| size > profile.response_limit()) {
                                return Err(PolicyError::Evaluation);
                            }
                            bytes.extend_from_slice(&chunk[..n]);
                        }
                        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {},
                        Err(_) => return Err(PolicyError::Evaluation),
                    }
                }
                match observe(child.id())? {
                    WaitStatus::Exited(_, 0) if eof && written => break,
                    WaitStatus::Exited(_, 0) | WaitStatus::StillAlive => {},
                    _ => return Err(PolicyError::Evaluation),
                }
                thread::sleep(INTERVAL.min(deadline.saturating_sub(started.elapsed())));
            }
            s14_rule_preview::validate_response(&bytes)?;
            Ok(bytes)
        })();
        finish(&mut guard, result, |guard| guard.resources.verify_limits(),
            |guard| guard.cleanup(), started, deadline)
    }
}

// Clean up before the final readback so an error or timeout does not delay
// termination. The snapshot cannot prove continuous control enforcement.
fn finish<T>(guard: &mut T, result: Result<Vec<u8>, PolicyError>,
    verify: impl FnOnce(&mut T) -> Result<(), ()>,
    cleanup: impl FnOnce(&mut T) -> Result<(), PolicyError>,
    started: Instant, deadline: Duration) -> Result<Vec<u8>, PolicyError> {
    let cleaned = cleanup(guard);
    if cleaned.is_err() { return Err(PolicyError::Evaluation); }
    let limits = verify(guard);
    if limits.is_err() || started.elapsed() >= deadline {
        return Err(PolicyError::Evaluation);
    }
    result
}

fn write_deadline(socket: &UnixStream, bytes: &[u8], started: Instant, deadline: Duration) -> Result<(), PolicyError> {
    let mut sent = 0;
    while sent < bytes.len() {
        if started.elapsed() >= deadline { return Err(PolicyError::Evaluation); }
        match send(socket, &bytes[sent..], SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(0) => return Err(PolicyError::Evaluation),
            Ok(n) => sent += n,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => thread::sleep(INTERVAL),
            Err(_) => return Err(PolicyError::Evaluation),
        }
    }
    Ok(())
}

fn write_input(mut pipe: File, bytes: &[u8], started: Instant, deadline: Duration,
    cancelled: &AtomicBool) -> Result<(), PolicyError> {
    // A broken anonymous pipe sends SIGPIPE. Block it only in this dedicated
    // thread; its pending signal is discarded when the thread exits.
    let mut signals = nix::sys::signal::SigSet::empty();
    signals.add(Signal::SIGPIPE);
    signals.thread_block().map_err(|_| PolicyError::Evaluation)?;
    let mut sent = 0;
    while sent < bytes.len() {
        if cancelled.load(Ordering::Acquire) || started.elapsed() >= deadline { return Err(PolicyError::Evaluation); }
        match pipe.write(&bytes[sent..]) {
            Ok(0) => return Err(PolicyError::Evaluation),
            Ok(n) => sent += n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => thread::sleep(INTERVAL),
            Err(_) => return Err(PolicyError::Evaluation),
        }
    }
    Ok(())
}

fn observe(id: u32) -> Result<WaitStatus, PolicyError> {
    let pid = i32::try_from(id).map_err(|_| PolicyError::Evaluation)?;
    loop {
        match waitid(Id::Pid(Pid::from_raw(pid)), WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT) {
            Err(Errno::EINTR) => continue,
            result => return result.map_err(|_| PolicyError::Evaluation),
        }
    }
}

struct Guard { child: Option<Child>, resources: RegisteredCgroup, cleaned: bool,
    cancelled: Arc<AtomicBool>, writer: Option<thread::JoinHandle<()>> }
impl Guard {
    fn cleanup(&mut self) -> Result<(), PolicyError> {
        if self.cleaned { return Err(PolicyError::Evaluation); }
        self.cleaned = true;
        self.cancelled.store(true, Ordering::Release);
        let writer_ok = self.writer.take().is_none_or(|writer| writer.join().is_ok());
        let Some(mut child) = self.child.take() else { return Err(PolicyError::Evaluation) };
        // Keep the PID reserved until after group signalling, preventing reuse.
        let status = observe(child.id());
        let group = i32::try_from(child.id()).ok().map(Pid::from_raw);
        let group_ok = match (group, status.as_ref()) {
            (Some(pid), Ok(state)) => match killpg(pid, Signal::SIGKILL) {
                Ok(()) => true,
                Err(Errno::ESRCH) if !matches!(state, WaitStatus::StillAlive) => true,
                _ => false,
            },
            _ => false,
        };
        let direct_ok = match status.as_ref() {
            Ok(WaitStatus::StillAlive) => child.kill().is_ok()
                || observe(child.id()).is_ok_and(|state| !matches!(state, WaitStatus::StillAlive)),
            Ok(_) => true,
            // A lost child cannot safely be signalled by a possibly reused PID.
            Err(_) => false,
        };
        let cgroup_ok = self.resources.cleanup().is_ok();
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return if writer_ok && group_ok && direct_ok && cgroup_ok { Ok(()) } else { Err(PolicyError::Evaluation) },
                Ok(None) if start.elapsed() < REAP_GRACE => thread::sleep(INTERVAL),
                Err(e) if e.kind() == io::ErrorKind::Interrupted && start.elapsed() < REAP_GRACE => {},
                _ => {
                    // The outside host must recover if this supervisor dies or
                    // if an uninterruptible child cannot be reaped promptly.
                    let _ = thread::Builder::new().name("s14-child-reaper".into()).spawn(move || { let _ = child.wait(); });
                    return Err(PolicyError::Evaluation);
                }
            }
        }
    }
}
impl Drop for Guard { fn drop(&mut self) { if !self.cleaned { let _ = self.cleanup(); } } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_limit_failure_withholds_output_but_still_cleans_up() {
        struct Fixture { limits_ok: bool, cleanup_ok: bool, steps: Vec<&'static str> }
        for (limits_ok, cleanup_ok, expired, success) in [
            (true, true, false, true), (false, true, false, false),
            (true, false, false, false), (true, true, true, false),
        ] {
            let mut fixture = Fixture { limits_ok, cleanup_ok, steps: Vec::new() };
            let deadline = if expired { Duration::ZERO } else { Duration::from_secs(10) };
            let result = finish(&mut fixture, Ok(b"response".to_vec()), |state| {
                state.steps.push("readback");
                if state.limits_ok { Ok(()) } else { Err(()) }
            }, |state| {
                state.steps.push("cleanup");
                if state.cleanup_ok { Ok(()) } else { Err(PolicyError::Evaluation) }
            }, Instant::now(), deadline);
            if cleanup_ok { assert_eq!(fixture.steps, ["cleanup", "readback"]); }
            else { assert_eq!(fixture.steps, ["cleanup"]); }
            assert_eq!(result.is_ok(), success);
            if success { assert_eq!(result.ok().as_deref(), Some(&b"response"[..])); }
        }
    }

    #[test]
    fn broken_input_pipe_is_an_error_without_sigpipe_termination() -> Result<(), Box<dyn std::error::Error>> {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
        drop(reader);
        let result = thread::spawn(move || {
            write_input(File::from(writer), b"request", Instant::now(), Duration::from_secs(1), &AtomicBool::new(false))
        }).join().map_err(|_| "writer panicked")?;
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn closed_control_socket_is_an_error_without_sigpipe_termination() -> Result<(), Box<dyn std::error::Error>> {
        let (host, child) = UnixStream::pair()?;
        host.set_nonblocking(true)?;
        drop(child);
        assert!(write_deadline(&host, b"profile", Instant::now(), Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn cancelled_writer_does_not_write() -> Result<(), Box<dyn std::error::Error>> {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
        let result = thread::spawn(move || {
            write_input(File::from(writer), b"request", Instant::now(), Duration::from_secs(1), &AtomicBool::new(true))
        }).join().map_err(|_| "writer panicked")?;
        assert!(result.is_err());
        let mut bytes = Vec::new();
        File::from(reader).read_to_end(&mut bytes)?;
        assert!(bytes.is_empty());
        Ok(())
    }
}
