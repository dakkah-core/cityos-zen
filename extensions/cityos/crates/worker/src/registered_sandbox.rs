//! Preparation for host-registered S14 sandbox resources.
//!
//! This module supplies a confined evaluator entry but is not a launcher.
//! Cgroup snapshots cannot prove prior placement or exclusive custody. The
//! external host must provide those guarantees and cleanup; successful
//! readback is not authority or qualification.

use std::{fs::File, io::Read, os::fd::{AsFd, OwnedFd}, thread, time::{Duration, Instant}};

use crate::cgroup_cleanup::{kill_and_observe_empty, linux::LinuxCgroupCleanup};
use crate::cgroup_limits::{AggregateLimits, linux::LinuxCgroupLimits};
use nix::sys::statfs::{fstatfs, CGROUP2_SUPER_MAGIC};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};

/// Identifies the schema and semantics of host-supplied values, not an
/// approval, a registered profile, or evidence of a deployed configuration.
pub(crate) const PROFILE_V1: &str = "cityos.zen.s14.sandbox-resources.v1";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileV1 {
    limits: AggregateLimits,
    max_request_bytes: usize,
    max_response_bytes: usize,
    deadline: Duration,
    cleanup_deadline: Duration,
    cleanup_polls: usize,
}

impl ProfileV1 {
    pub(crate) fn revalidate(self) -> Result<Self, ()> {
        Self::new(PROFILE_V1, self.limits.revalidate().map_err(|_| ())?, self.max_request_bytes,
            self.max_response_bytes, self.deadline, self.cleanup_deadline, self.cleanup_polls)
    }
    /// All values are explicitly supplied by the host. The fixed ceilings here
    /// bound this source-local protocol; they do not choose production limits.
    pub(crate) fn new(
        version: &str, limits: AggregateLimits, max_request_bytes: usize, max_response_bytes: usize,
        deadline: Duration, cleanup_deadline: Duration, cleanup_polls: usize,
    ) -> Result<Self, ()> {
        if version != PROFILE_V1 || !(1..=131_072).contains(&max_request_bytes)
            || !(1..=131_072).contains(&max_response_bytes)
            || deadline.is_zero() || deadline > Duration::from_secs(30)
            || cleanup_deadline.is_zero() || cleanup_deadline > Duration::from_secs(5)
            || !(1..=64).contains(&cleanup_polls)
        { return Err(()); }
        Ok(Self { limits, max_request_bytes, max_response_bytes, deadline, cleanup_deadline, cleanup_polls })
    }

    pub(crate) fn version(&self) -> &'static str { PROFILE_V1 }
    pub(crate) fn request_limit(&self) -> usize { self.max_request_bytes }
    pub(crate) fn response_limit(&self) -> usize { self.max_response_bytes }
    pub(crate) fn deadline(&self) -> Duration { self.deadline }
}

/// A host-owned, pre-opened cgroup v2 directory and its expected controls.
/// The host must establish registration, exact identity, exclusive custody,
/// no migration or control changes, and external recovery on supervisor death.
/// Constructing this object establishes none of those facts.
pub(crate) struct RegisteredCgroup {
    directory: OwnedFd,
    limits: LinuxCgroupLimits,
    cleanup: LinuxCgroupCleanup,
    profile: ProfileV1,
}

impl RegisteredCgroup {
    pub(crate) fn capture(directory: OwnedFd, profile: ProfileV1) -> Result<Self, ()> {
        if !rustix::io::fcntl_getfd(&directory).map_err(|_| ())?.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(());
        }
        // Duplicating this actual descriptor binds both adapters to the same
        // inode; no request-provided path or second independently chosen target.
        let limits_directory = directory.try_clone().map_err(|_| ())?;
        let cleanup_directory = directory.try_clone().map_err(|_| ())?;
        let mut limits = LinuxCgroupLimits::new(limits_directory).map_err(|_| ())?;
        let mut cleanup = LinuxCgroupCleanup::new(cleanup_directory)?;
        limits.verify(&profile.limits).map_err(|_| ())?;
        if !cleanup.initially_empty()? { return Err(()); }
        Ok(Self { directory, limits, cleanup, profile })
    }

    pub(crate) fn evaluator_directory(&self) -> Result<OwnedFd, ()> {
        self.directory.try_clone().map_err(|_| ())
    }

    pub(crate) fn profile(&self) -> ProfileV1 { self.profile.clone() }

    /// The child is a verified bootstrap blocked on the private control socket.
    /// The host must retain exclusive custody and prevent migration throughout.
    pub(crate) fn place_bootstrap(&mut self, pid: u32) -> Result<(), ()> {
        use std::io::Write;
        if pid == 0 || !self.profile.limits.is_single_task() { return Err(()); }
        self.recheck()?;
        let fd = fs::openat2(&self.directory, "cgroup.procs",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(), ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV)
            .map_err(|_| ())?;
        let stat = fs::fstat(&fd).map_err(|_| ())?;
        let anchor = fs::fstat(&self.directory).map_err(|_| ())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_dev != anchor.st_dev
            || fstatfs(&fd).map_err(|_| ())?.filesystem_type() != CGROUP2_SUPER_MAGIC
            || !rustix::io::fcntl_getfd(&fd).map_err(|_| ())?.contains(rustix::io::FdFlags::CLOEXEC)
        { return Err(()); }
        let text = format!("{pid}\n");
        // Treat partial or interrupted writes as uncertain; cleanup is required.
        if File::from(fd).write(text.as_bytes()).map_err(|_| ())? != text.len() { return Err(()); }
        self.limits.verify(&self.profile.limits).map_err(|_| ())?;
        let procs = read_control(&self.directory, "cgroup.procs")?;
        let tasks = read_control(&self.directory, "pids.current")?;
        if !only_current_task(&procs, &tasks, pid) { return Err(()); }
        Ok(())
    }

    /// Recheck the snapshots immediately before an external launcher starts.
    /// This is not a launch gate: a future launcher must establish atomic
    /// membership, actual filesystem/network isolation, and continuous custody.
    pub(crate) fn recheck(&mut self) -> Result<(), ()> {
        self.limits.verify(&self.profile.limits).map_err(|_| ())?;
        if !self.cleanup.initially_empty()? { return Err(()); }
        Ok(())
    }

    /// Read the same host-selected aggregate limits after evaluation. These
    /// sequential snapshots cannot prove continuous enforcement or custody.
    pub(crate) fn verify_limits(&mut self) -> Result<(), ()> {
        self.limits.verify(&self.profile.limits).map_err(|_| ())
    }

    /// Explicitly request recursive cleanup on the registered subtree. A
    /// successful result is only an observed empty snapshot after cgroup.kill;
    /// child reaping and recovery if this process dies remain external duties.
    pub(crate) fn cleanup(&mut self) -> Result<(), ()> {
        let start = Instant::now();
        let deadline = self.profile.cleanup_deadline;
        kill_and_observe_empty(&mut self.cleanup, self.profile.cleanup_polls, || {
            if start.elapsed() >= deadline { return Err(()); }
            thread::sleep(Duration::from_millis(10).min(deadline.saturating_sub(start.elapsed())));
            if start.elapsed() >= deadline { Err(()) } else { Ok(()) }
        }).map_err(|_| ())?;
        if start.elapsed() >= deadline { return Err(()); }
        Ok(())
    }
}

// Fixed, descriptor-relative cgroup files only. Never fall back to a path or a
// weaker resolver if openat2 or cgroup2 verification is unavailable.
fn read_control(directory: &impl AsFd, name: &'static str) -> Result<Vec<u8>, ()> {
    if !matches!(name, "cgroup.procs" | "pids.current") { return Err(()); }
    let anchor = fs::fstat(directory).map_err(|_| ())?;
    let fd = fs::openat2(directory, name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(), ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV)
        .map_err(|_| ())?;
    let stat = fs::fstat(&fd).map_err(|_| ())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_dev != anchor.st_dev
        || fstatfs(&fd).map_err(|_| ())?.filesystem_type() != CGROUP2_SUPER_MAGIC
        || !rustix::io::fcntl_getfd(&fd).map_err(|_| ())?.contains(rustix::io::FdFlags::CLOEXEC)
    { return Err(()); }
    let mut bytes = Vec::new();
    File::from(fd).take(65).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 64 { return Err(()); }
    Ok(bytes)
}

fn only_current_task(procs: &[u8], tasks: &[u8], pid: u32) -> bool {
    pid != 0 && procs == format!("{pid}\n").as_bytes() && tasks == b"1\n"
}

/// Verify this evaluator is already the sole task of a host-supplied cgroup.
/// The external owner must have placed it there before release, must keep the
/// cgroup exclusive, and must own deadline, kill, and wait on every outcome.
/// These readbacks do not authenticate or replace that owner.
pub(crate) fn verify_evaluator_cgroup(directory: OwnedFd, profile: &ProfileV1) -> Result<(), ()> {
    if !profile.limits.is_single_task()
        || !rustix::io::fcntl_getfd(&directory).map_err(|_| ())?.contains(rustix::io::FdFlags::CLOEXEC)
    { return Err(()); }
    let duplicate = directory.try_clone().map_err(|_| ())?;
    let mut limits = LinuxCgroupLimits::new(duplicate).map_err(|_| ())?;
    limits.verify(&profile.limits).map_err(|_| ())?;
    let procs = read_control(&directory, "cgroup.procs")?;
    let tasks = read_control(&directory, "pids.current")?;
    if !only_current_task(&procs, &tasks, std::process::id()) { return Err(()); }
    // The FD is consumed here; callers must also close all inherited aliases
    // before granting evaluator input. The host retains its own cleanup FD.
    Ok(())
}

/// Actual evaluator entry for a trusted external host which has already placed
/// this dedicated process in the supplied registered cgroup before release.
/// It must be called only in a fresh, single-threaded process. The host must
/// enforce the profile deadline, reap the evaluator, and retain exclusive
/// control and recovery of the cgroup. This function cannot prove those host
/// duties and is not exposed through the unauthenticated CLI.
pub(crate) fn execute_in_registered_cgroup(directory: OwnedFd, profile: ProfileV1)
    -> Result<(), cityos_zen_contracts::PolicyError> {
    use cityos_zen_contracts::PolicyError;
    use std::os::fd::AsRawFd;
    if std::env::vars_os().next().is_some() { return Err(PolicyError::Evaluation); }
    crate::stdio::require_anonymous_pipe(std::io::stdin().as_raw_fd(), nix::libc::O_RDONLY)?;
    crate::stdio::require_anonymous_pipe(std::io::stdout().as_raw_fd(), nix::libc::O_WRONLY)?;
    verify_evaluator_cgroup(directory, &profile).map_err(|_| PolicyError::Evaluation)?;
    match nix::unistd::close(2) {
        Ok(()) | Err(nix::errno::Errno::EBADF) => {},
        Err(_) => return Err(PolicyError::Evaluation),
    }
    crate::inherited_fds::close_and_verify()?;
    nix::sys::prctl::set_no_new_privs().map_err(|_| PolicyError::Evaluation)?;
    if !nix::sys::prctl::get_no_new_privs().map_err(|_| PolicyError::Evaluation)? {
        return Err(PolicyError::Evaluation);
    }
    crate::resource_limits::install()?;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    {
        crate::process_sandbox::install()?;
        crate::s14_rule_preview::preview_bounded(profile.request_limit(), profile.response_limit())
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    { Err(PolicyError::Evaluation) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn limits() -> Result<AggregateLimits, Box<dyn std::error::Error>> {
        AggregateLimits::new(50_000, 100_000, 1_048_576, 0, 16).map_err(|_| "invalid limits".into())
    }

    #[test]
    fn versioned_limits_reject_unbounded_or_missing_values() -> Result<(), Box<dyn std::error::Error>> {
        let make = |request, response, deadline, cleanup, polls| {
            ProfileV1::new(PROFILE_V1, limits().map_err(|_| ())?, request, response, deadline, cleanup, polls)
        };
        let profile = make(4096, 8192, Duration::from_secs(1), Duration::from_millis(100), 4)
            .map_err(|_| "profile rejected")?;
        assert_eq!(profile.version(), PROFILE_V1);
        assert_eq!(profile.request_limit(), 4096);
        assert_eq!(profile.response_limit(), 8192);
        assert_eq!(profile.deadline(), Duration::from_secs(1));
        assert!(ProfileV1::new("unknown", limits()?, 1, 1, Duration::from_secs(1),
            Duration::from_secs(1), 1).is_err());
        for (request, response, deadline, cleanup, polls) in [
            (0, 1, Duration::from_secs(1), Duration::from_secs(1), 1),
            (1, 131_073, Duration::from_secs(1), Duration::from_secs(1), 1),
            (1, 1, Duration::ZERO, Duration::from_secs(1), 1),
            (1, 1, Duration::from_secs(31), Duration::from_secs(1), 1),
            (1, 1, Duration::from_secs(1), Duration::ZERO, 1),
            (1, 1, Duration::from_secs(1), Duration::from_secs(6), 1),
            (1, 1, Duration::from_secs(1), Duration::from_secs(1), 0),
            (1, 1, Duration::from_secs(1), Duration::from_secs(1), 65),
        ] { assert!(make(request, response, deadline, cleanup, polls).is_err()); }
        Ok(())
    }

    #[test]
    fn ordinary_directory_is_not_registered_cgroup() -> Result<(), Box<dyn std::error::Error>> {
        let dir: OwnedFd = File::open(std::env::temp_dir())?.into();
        let profile = ProfileV1::new(PROFILE_V1, limits()?, 1, 1, Duration::from_secs(1), Duration::from_secs(1), 1)
            .map_err(|_| "invalid fixture profile")?;
        assert!(RegisteredCgroup::capture(dir, profile).is_err());
        Ok(())
    }

    #[test]
    fn membership_requires_exact_pid_and_one_task() {
        assert!(only_current_task(b"123\n", b"1\n", 123));
        for (pids, tasks, pid) in [
            (&b"123\n124\n"[..], &b"1\n"[..], 123),
            (&b"123"[..], &b"1\n"[..], 123),
            (&b"123\n"[..], &b"2\n"[..], 123),
            (&b"0123\n"[..], &b"1\n"[..], 123),
            (&b"0\n"[..], &b"1\n"[..], 0),
        ] { assert!(!only_current_task(pids, tasks, pid)); }
    }
}
