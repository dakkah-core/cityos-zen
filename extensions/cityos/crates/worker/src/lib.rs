//! Host-facing entry for a confined S14 evaluator process.
//!
//! This API is a computation boundary, not a receipt, authorization, host
//! registration, or qualification. The external host owns placement before
//! evaluation, cgroup custody, deadline, output validation, kill and reaping.

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod bootstrap;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod cgroup_cleanup;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod cgroup_limits;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod inherited_fds;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod json_object;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod launcher;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod registered_launcher_stdio;
#[cfg(all(target_os = "linux", not(target_env = "uclibc"), any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
mod process_sandbox;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod registered_sandbox;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod resource_limits;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod s14_rule_preview;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod stdio;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
mod verified_artifact;

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
pub use launcher::TrustedLauncher;

/// Internal evaluator bootstrap. Input must be the host's private control
/// socket; no actor, facts, or sandbox resource are accepted from an envelope.
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
pub fn host_bootstrap() -> Result<(), cityos_zen_contracts::PolicyError> { bootstrap::run() }

/// Private one-shot launcher protocol. Only an authenticated host may supply
/// the control frame and own the exclusive cgroup and artifact registrations.
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
pub fn host_launcher_stdio() -> Result<(), cityos_zen_contracts::PolicyError> {
    registered_launcher_stdio::run()
}

/// Profile parameters come from the trusted host's registered configuration,
/// never from the evaluated request. These values alone confer no authority.
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[derive(Clone)]
pub struct RegisteredProfile(registered_sandbox::ProfileV1);

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
impl RegisteredProfile {
    pub const VERSION: &'static str = registered_sandbox::PROFILE_V1;

    pub fn request_limit(&self) -> usize { self.0.request_limit() }
    pub fn response_limit(&self) -> usize { self.0.response_limit() }
    pub fn deadline(&self) -> std::time::Duration { self.0.deadline() }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: &str, cpu_quota_usec: u64, cpu_period_usec: u64,
        memory_bytes: u64, swap_bytes: u64, tasks: u64,
        max_request_bytes: usize, max_response_bytes: usize,
        deadline: std::time::Duration, cleanup_deadline: std::time::Duration, cleanup_polls: usize,
    ) -> Result<Self, cityos_zen_contracts::PolicyError> {
        use cityos_zen_contracts::PolicyError;
        let limits = cgroup_limits::AggregateLimits::new(cpu_quota_usec, cpu_period_usec, memory_bytes, swap_bytes, tasks)
            .map_err(|_| PolicyError::InvalidInput)?;
        if !limits.is_single_task() { return Err(PolicyError::InvalidInput); }
        registered_sandbox::ProfileV1::new(version, limits, max_request_bytes, max_response_bytes,
            deadline, cleanup_deadline, cleanup_polls).map(Self).map_err(|_| PolicyError::InvalidInput)
    }

    /// Enter irreversible confinement and evaluate exactly one request.
    ///
    /// The host passes a pre-opened cgroup-v2 directory for this very process,
    /// places it there before granting input, ensures that no other actor can
    /// alter or migrate that subtree, and independently enforces the deadline,
    /// cgroup cleanup and child reaping, including if this process dies. It must
    /// also supply an empty environment, dedicated non-root uid/gid, no
    /// supplementary groups, and isolated anonymous stdin/stdout pipes. This
    /// method verifies current membership, single-task and limit snapshots,
    /// closes inherited descriptors, drops capabilities, and fails closed if
    /// Landlock or seccomp cannot enforce the evaluator restrictions.
    ///
    /// Call only in a fresh dedicated process. It irreversibly restricts that
    /// process even when a later step returns an error. The caller must check
    /// process exit and complete response bytes before use. The default CLI
    /// does not accept a request-supplied cgroup or claim host registration.
    pub fn execute(self, cgroup: std::os::fd::OwnedFd) -> Result<(), cityos_zen_contracts::PolicyError> {
        registered_sandbox::execute_in_registered_cgroup(cgroup, self.0)
    }
}

/// Host-side cgroup handle. Creating it checks filesystem type, control
/// readbacks, and an initially empty snapshot; it cannot establish registration
/// or exclusive custody. Keep it outside the evaluator's cgroup.
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
pub struct RegisteredResources(registered_sandbox::RegisteredCgroup);

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
impl RegisteredResources {
    pub fn capture(directory: std::os::fd::OwnedFd, profile: RegisteredProfile)
        -> Result<Self, cityos_zen_contracts::PolicyError> {
        registered_sandbox::RegisteredCgroup::capture(directory, profile.0)
            .map(Self).map_err(|_| cityos_zen_contracts::PolicyError::Evaluation)
    }

    pub fn recheck(&mut self) -> Result<(), cityos_zen_contracts::PolicyError> {
        self.0.recheck().map_err(|_| cityos_zen_contracts::PolicyError::Evaluation)
    }

    /// Duplicate the same cgroup directory for delivery over a trusted host
    /// boundary. The host must keep it out of the untrusted request.
    pub fn evaluator_directory(&self) -> Result<std::os::fd::OwnedFd, cityos_zen_contracts::PolicyError> {
        self.0.evaluator_directory().map_err(|_| cityos_zen_contracts::PolicyError::Evaluation)
    }

    /// Kill and observe this exact exclusive subtree empty. The host must also
    /// reap its child and provide recovery if the host itself is terminated.
    pub fn cleanup(&mut self) -> Result<(), cityos_zen_contracts::PolicyError> {
        self.0.cleanup().map_err(|_| cityos_zen_contracts::PolicyError::Evaluation)
    }
}

/// Validate untrusted worker output only after a successful child exit and EOF.
/// A valid response is still a calculation over caller-supplied facts.
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
pub fn validate_rule_response(bytes: &[u8]) -> Result<(), cityos_zen_contracts::PolicyError> {
    s14_rule_preview::validate_response(bytes)
}

#[cfg(all(test, target_os = "linux", not(target_env = "uclibc")))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn host_profile_requires_single_task_and_exact_version() {
        let make = |version, tasks| RegisteredProfile::new(version, 50_000, 100_000,
            1_048_576, 0, tasks, 8192, 16384, Duration::from_secs(1), Duration::from_secs(1), 4);
        assert!(make(RegisteredProfile::VERSION, 1).is_ok());
        assert!(make(RegisteredProfile::VERSION, 0).is_err());
        assert!(make(RegisteredProfile::VERSION, 2).is_err());
        assert!(make("unregistered-version", 1).is_err());
    }

    #[test]
    fn host_resources_reject_ordinary_filesystem() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::fs::File::open(std::env::temp_dir())?.into();
        let profile = RegisteredProfile::new(RegisteredProfile::VERSION, 50_000, 100_000,
            1_048_576, 0, 1, 8192, 16384, Duration::from_secs(1), Duration::from_secs(1), 4)?;
        assert!(RegisteredResources::capture(dir, profile).is_err());
        Ok(())
    }
}
