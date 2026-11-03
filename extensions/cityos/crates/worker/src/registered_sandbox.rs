//! Preparation for host-registered S14 sandbox resources.
//!
//! This module is deliberately not a launcher. A cgroup snapshot cannot prove
//! that a process was placed before it executed, that its subtree is exclusive,
//! or that filesystem and network isolation are in force. Do not release a
//! worker or interpret successful readback as authority or qualification.

use std::{os::fd::OwnedFd, thread, time::{Duration, Instant}};

use crate::cgroup_cleanup::{kill_and_observe_empty, linux::LinuxCgroupCleanup};
use crate::cgroup_limits::{AggregateLimits, linux::LinuxCgroupLimits};

/// Identifies the schema and semantics of host-supplied values, not an
/// approval, a registered profile, or evidence of a deployed configuration.
pub(crate) const PROFILE_V1: &str = "cityos.zen.s14.sandbox-resources.v1";

pub(crate) struct ProfileV1 {
    limits: AggregateLimits,
    max_request_bytes: usize,
    max_response_bytes: usize,
    deadline: Duration,
    cleanup_deadline: Duration,
    cleanup_polls: usize,
}

impl ProfileV1 {
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
    limits: LinuxCgroupLimits,
    cleanup: LinuxCgroupCleanup,
    profile: ProfileV1,
}

impl RegisteredCgroup {
    pub(crate) fn capture(directory: OwnedFd, profile: ProfileV1) -> Result<Self, ()> {
        // Duplicating this actual descriptor binds both adapters to the same
        // inode; no request-provided path or second independently chosen target.
        let limits_directory = directory.try_clone().map_err(|_| ())?;
        let mut limits = LinuxCgroupLimits::new(limits_directory).map_err(|_| ())?;
        let mut cleanup = LinuxCgroupCleanup::new(directory)?;
        limits.verify(&profile.limits).map_err(|_| ())?;
        if !cleanup.initially_empty()? { return Err(()); }
        Ok(Self { limits, cleanup, profile })
    }

    /// Recheck the snapshots immediately before an external launcher starts.
    /// This is not a launch gate: a future launcher must establish atomic
    /// membership, actual filesystem/network isolation, and continuous custody.
    pub(crate) fn recheck(&mut self) -> Result<(), ()> {
        self.limits.verify(&self.profile.limits).map_err(|_| ())?;
        if !self.cleanup.initially_empty()? { return Err(()); }
        Ok(())
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
}
