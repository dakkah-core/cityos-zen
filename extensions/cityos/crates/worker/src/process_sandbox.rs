//! Irreversible evaluator restrictions. This is not a launcher or cgroup proof.
//!
//! Call only in a dedicated single-threaded child, after its trusted launcher
//! has placed it in the intended cgroup and closed all non-stdio descriptors.
//! Unsupported kernels and incomplete enforcement return an error.

use cityos_zen_contracts::PolicyError;
use landlock::{Access, AccessFs, ABI, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};
use nix::libc;
use rustix::thread::{capabilities, clear_ambient_capability_set, set_capabilities, CapabilitySet, CapabilitySets};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

// Only syscalls required by the in-memory evaluator and pipe I/O are admitted.
// In particular there is no open, socket, connect, clone, exec, setns, mount,
// pidfd_getfd, io_uring, ptrace, or process-memory access. An unknown syscall
// fails with EPERM. This list is deliberately versioned with the profile and
// may need revision based on real target-specific execution evidence.
const ALLOWED_V1: &[i64] = &[
    libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev, libc::SYS_close,
    libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_mremap,
    libc::SYS_madvise, libc::SYS_brk, libc::SYS_futex, libc::SYS_clock_gettime,
    libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack, libc::SYS_sched_yield, libc::SYS_getpid, libc::SYS_gettid,
    libc::SYS_getrandom, libc::SYS_restart_syscall, libc::SYS_exit, libc::SYS_exit_group,
];

fn syscall_filter() -> Result<BpfProgram, PolicyError> {
    let arch = std::env::consts::ARCH.try_into().map_err(|_| PolicyError::Evaluation)?;
    let rules = ALLOWED_V1.iter().copied().map(|number| (number, Vec::new())).collect();
    let filter = SeccompFilter::new(rules, SeccompAction::Errno(libc::EPERM as u32), SeccompAction::Allow, arch)
        .map_err(|_| PolicyError::Evaluation)?;
    filter.try_into().map_err(|_| PolicyError::Evaluation)
}

fn remove_capabilities() -> Result<(), PolicyError> {
    // Host must choose a dedicated unprivileged identity and clear groups;
    // retaining a saved privileged identity is never acceptable.
    let uid = nix::unistd::getresuid().map_err(|_| PolicyError::Evaluation)?;
    let gid = nix::unistd::getresgid().map_err(|_| PolicyError::Evaluation)?;
    if uid.real.as_raw() == 0 || uid.real != uid.effective || uid.real != uid.saved
        || gid.real.as_raw() == 0 || gid.real != gid.effective || gid.real != gid.saved
        || !nix::unistd::getgroups().map_err(|_| PolicyError::Evaluation)?.is_empty()
    { return Err(PolicyError::Evaluation); }
    clear_ambient_capability_set().map_err(|_| PolicyError::Evaluation)?;
    let empty = CapabilitySets {
        effective: CapabilitySet::empty(), permitted: CapabilitySet::empty(), inheritable: CapabilitySet::empty(),
    };
    set_capabilities(None, empty).map_err(|_| PolicyError::Evaluation)?;
    if capabilities(None).map_err(|_| PolicyError::Evaluation)? != empty {
        return Err(PolicyError::Evaluation);
    }
    Ok(())
}

/// Install all restrictions before consuming evaluator input. This does not
/// establish host identity, cgroup membership, external cleanup, or provenance.
pub(crate) fn install() -> Result<(), PolicyError> {
    // Landlock and seccomp apply to the calling thread. No existing sibling
    // thread may remain unrestricted; the final seccomp filter forbids clone.
    let mut threads = std::fs::read_dir("/proc/self/task").map_err(|_| PolicyError::Evaluation)?;
    if threads.next().transpose().map_err(|_| PolicyError::Evaluation)?.is_none()
        || threads.next().transpose().map_err(|_| PolicyError::Evaluation)?.is_some()
    { return Err(PolicyError::Evaluation); }
    drop(threads);
    let filter = syscall_filter()?;
    remove_capabilities()?;
    install_filters(&filter)
}

fn install_filters(filter: &BpfProgram) -> Result<(), PolicyError> {
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3)).map_err(|_| PolicyError::Evaluation)?
        .create().map_err(|_| PolicyError::Evaluation)?
        .restrict_self().map_err(|_| PolicyError::Evaluation)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(PolicyError::Evaluation);
    }
    seccompiler::apply_filter(filter).map_err(|_| PolicyError::Evaluation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::net::{UnixListener, UnixStream}, process::Command, time::{SystemTime, UNIX_EPOCH}};

    #[test]
    fn allowlist_excludes_filesystem_network_and_process_escape() {
        for syscall in [libc::SYS_openat, libc::SYS_socket, libc::SYS_socketpair,
            libc::SYS_connect, libc::SYS_clone, libc::SYS_execve, libc::SYS_setns,
            libc::SYS_mount, libc::SYS_ptrace, libc::SYS_io_uring_setup] {
            assert!(!ALLOWED_V1.contains(&syscall));
        }
        assert!(syscall_filter().is_ok());
    }

    // Executed in a separate test process. The harness has other threads, so
    // this probe only asserts restrictions on the calling thread; production
    // additionally requires the whole evaluator to be single-threaded.
    #[test]
    fn filter_probe() -> Result<(), Box<dyn std::error::Error>> {
        let Some(file) = std::env::var_os("CITYOS_SANDBOX_PROBE_FILE") else { return Ok(()); };
        let file = std::path::PathBuf::from(file);
        let socket = std::path::PathBuf::from(std::env::var_os("CITYOS_SANDBOX_PROBE_SOCKET").ok_or("missing socket")?);
        let filter = syscall_filter()?;
        if install_filters(&filter).is_err() {
            println!("cityos-sandbox-unavailable");
            return Ok(());
        }
        assert!(fs::read(file).is_err());
        assert!(UnixStream::connect(socket).is_err());
        assert!(Command::new("/bin/true").spawn().is_err());
        println!("cityos-sandbox-enforced");
        Ok(())
    }

    #[test]
    fn filter_denies_credential_file_unix_socket_and_spawn_or_is_unavailable()
        -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("zen-sandbox-{}-{nonce}", std::process::id()));
        fs::create_dir(&dir)?;
        let file = dir.join("credential");
        let socket = dir.join("socket");
        fs::write(&file, b"synthetic")?;
        let listener = UnixListener::bind(&socket)?;
        // Establish that the paths are accessible without the sandbox.
        assert_eq!(fs::read(&file)?, b"synthetic");
        let _connection = UnixStream::connect(&socket)?;
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", "process_sandbox::tests::filter_probe", "--nocapture"])
            .env_clear().env("CITYOS_SANDBOX_PROBE_FILE", &file)
            .env("CITYOS_SANDBOX_PROBE_SOCKET", &socket).output()?;
        drop(listener);
        fs::remove_file(&socket)?;
        fs::remove_file(&file)?;
        fs::remove_dir(&dir)?;
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains("cityos-sandbox-enforced") || stdout.contains("cityos-sandbox-unavailable"));
        Ok(())
    }
}
