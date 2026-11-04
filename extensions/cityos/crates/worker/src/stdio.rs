//! Descriptor checks shared by the registered evaluator and supervisor.
use cityos_zen_contracts::PolicyError;
use nix::fcntl::{fcntl, FcntlArg};
use std::{os::fd::RawFd, os::unix::fs::FileTypeExt};

pub(crate) fn require_anonymous_pipe(fd: RawFd, access: i32) -> Result<(), PolicyError> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|_| PolicyError::Evaluation)?;
    if flags & nix::libc::O_ACCMODE != access || flags & nix::libc::O_DIRECT != 0 {
        return Err(PolicyError::Evaluation);
    }
    let path = format!("/proc/self/fd/{fd}");
    let target = std::fs::read_link(&path).map_err(|_| PolicyError::Evaluation)?;
    if !target.to_str().is_some_and(|name| name.starts_with("pipe:[") && name.ends_with(']')) {
        return Err(PolicyError::Evaluation);
    }
    if !std::fs::metadata(&path).map_err(|_| PolicyError::Evaluation)?.file_type().is_fifo() {
        return Err(PolicyError::Evaluation);
    }
    Ok(())
}
