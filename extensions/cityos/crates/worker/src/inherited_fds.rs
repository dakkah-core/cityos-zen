//! Remove inherited non-stdio descriptors before a restricted preview.
//!
//! This is a startup hygiene measure, not a credential or filesystem boundary.
//! The caller must be single-threaded: another thread opening descriptors while
//! this runs would invalidate the enumeration and verification.
use cityos_zen_contracts::PolicyError;
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg};
use nix::unistd::close;
use std::os::fd::RawFd;

fn descriptors() -> Result<Vec<RawFd>, PolicyError> {
    let mut fds = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|_| PolicyError::Evaluation)? {
        let entry = entry.map_err(|_| PolicyError::Evaluation)?;
        let name = entry.file_name();
        let fd = name
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            .ok_or(PolicyError::Evaluation)?;
        if fd >= 3 {
            fds.push(fd);
        }
    }
    // The read_dir handle is now closed; its own descriptor may be in fds.
    Ok(fds)
}

pub(crate) fn close_and_verify() -> Result<(), PolicyError> {
    close_and_verify_with(descriptors, close, |fd| {
        fcntl(fd, FcntlArg::F_GETFD).map(|_| ())
    })
}

fn close_and_verify_with(
    mut list: impl FnMut() -> Result<Vec<RawFd>, PolicyError>,
    mut close_fd: impl FnMut(RawFd) -> Result<(), Errno>,
    mut check_fd: impl FnMut(RawFd) -> Result<(), Errno>,
) -> Result<(), PolicyError> {
    for fd in list()? {
        match close_fd(fd) {
            Ok(()) | Err(Errno::EBADF) => {}
            Err(_) => return Err(PolicyError::Evaluation),
        }
    }
    for fd in list()? {
        match check_fd(fd) {
            Err(Errno::EBADF) => {}
            // A live descriptor, or an unexpected verification failure, fails closed.
            _ => return Err(PolicyError::Evaluation),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn descriptor_cleanup_fails_closed_on_enumeration_close_and_verification_errors() {
        let closed = Cell::new(false);
        assert!(
            close_and_verify_with(
                || Err(PolicyError::Evaluation),
                |_| {
                    closed.set(true);
                    Ok(())
                },
                |_| Err(Errno::EBADF),
            )
            .is_err()
        );
        assert!(!closed.get());
        assert!(
            close_and_verify_with(|| Ok(vec![9]), |_| Err(Errno::EIO), |_| Err(Errno::EBADF))
                .is_err()
        );
        assert!(close_and_verify_with(|| Ok(vec![9]), |_| Ok(()), |_| Ok(())).is_err());
        assert!(close_and_verify_with(|| Ok(vec![9]), |_| Ok(()), |_| Err(Errno::EIO)).is_err());
        assert!(
            close_and_verify_with(|| Ok(vec![9]), |_| Err(Errno::EBADF), |_| Err(Errno::EBADF))
                .is_ok()
        );
        let reads = Cell::new(0);
        assert!(close_and_verify_with(
            || {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    Ok(vec![9])
                } else {
                    Err(PolicyError::Evaluation)
                }
            },
            |_| Ok(()),
            |_| Err(Errno::EBADF),
        ).is_err());
    }
}
