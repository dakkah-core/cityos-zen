//! Unconnected cgroup v2 cleanup protocol for a future Linux supervisor.
//!
//! This module neither creates nor joins a cgroup, starts a process, nor grants
//! authority. Its Linux adapter requires an independently trusted, pre-opened,
//! exclusively controlled cgroup v2 directory. The caller must keep untrusted
//! tasks from migrating out or changing its controls. `populated 0` is a snapshot,
//! not proof that a task was contained throughout its execution. No result may
//! be forwarded by a caller when cleanup fails.
//!
//! The polling count and read size are bounded, not the duration of backend
//! calls, the caller-supplied wait, or kernel scheduling. Callers must choose
//! the wait policy and separately reap children. No automatic cleanup is attempted on
//! drop: failures must be handled by the owner of the cgroup.

const MAX_EVENTS_BYTES: usize = 4096;
const MAX_POLLS: usize = 64;

/// Operations on one already established, exclusively controlled cgroup v2
/// subtree. `kill_all` must write `1` to its `cgroup.kill`; `read_events` must
/// read its complete `cgroup.events` into the buffer, rejecting truncation.
/// Errors, including unsupported controls, must not be translated to success.
pub(crate) trait CgroupCleanupIo {
    fn kill_all(&mut self) -> Result<(), ()>;
    fn read_events(&mut self, buffer: &mut [u8]) -> Result<usize, ()>;
}

/// A descriptor-anchored backend, not a qualified isolation profile.
///
/// The caller owns cgroup selection and must independently establish that the
/// supplied descriptor names the intended exclusive subtree, not the host root
/// or another workload. Filesystem type alone cannot establish that trust.
/// The caller must also prevent migration out, admission of unrelated tasks,
/// hostile mount namespace changes, and concurrent control mutations throughout
/// the workload and cleanup. Keep an external owner able to recover if the
/// supervisor dies. This adapter supplies none of those guarantees.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::CgroupCleanupIo;
    use nix::sys::statfs::{CGROUP2_SUPER_MAGIC, fstatfs};
    use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsFd, OwnedFd};

    #[derive(Clone, Copy)]
    enum Control {
        Kill,
        Events,
    }

    // The only names accepted here are single, fixed kernel control names.
    // No fallback is permitted if openat2 or any resolve flag is unavailable.
    fn open_control(dir: &impl AsFd, control: Control) -> Result<OwnedFd, ()> {
        let (name, access) = match control {
            Control::Kill => ("cgroup.kill", OFlags::WRONLY),
            Control::Events => ("cgroup.events", OFlags::RDONLY),
        };
        fs::openat2(
            dir,
            name,
            access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| ())
    }

    fn is_cgroup2(fd: &impl AsFd) -> Result<bool, ()> {
        Ok(fstatfs(fd).map_err(|_| ())?.filesystem_type() == CGROUP2_SUPER_MAGIC)
    }

    fn close_on_exec(fd: &impl AsFd) -> Result<bool, ()> {
        Ok(rustix::io::fcntl_getfd(fd)
            .map_err(|_| ())?
            .contains(rustix::io::FdFlags::CLOEXEC))
    }

    pub(crate) struct LinuxCgroupCleanup {
        // Keep the independently supplied directory alive for the whole use.
        _directory: OwnedFd,
        kill: File,
        events: File,
        kill_attempted: bool,
        kill_succeeded: bool,
    }

    impl LinuxCgroupCleanup {
        /// Consumes a close-on-exec, independently trusted directory descriptor.
        /// This verifies filesystem/type, not identity or custody of aliases.
        pub(crate) fn new(directory: OwnedFd) -> Result<Self, ()> {
            let dir_stat = fs::fstat(&directory).map_err(|_| ())?;
            if FileType::from_raw_mode(dir_stat.st_mode) != FileType::Directory
                || !is_cgroup2(&directory)?
                || !close_on_exec(&directory)?
            {
                return Err(());
            }
            let kill = open_control(&directory, Control::Kill)?;
            let events = open_control(&directory, Control::Events)?;
            for control in [&kill, &events] {
                let stat = fs::fstat(control).map_err(|_| ())?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || stat.st_dev != dir_stat.st_dev
                    || !is_cgroup2(control)?
                    || !close_on_exec(control)?
                {
                    return Err(());
                }
            }
            Ok(Self {
                _directory: directory,
                kill: File::from(kill),
                events: File::from(events),
                kill_attempted: false,
                kill_succeeded: false,
            })
        }
    }

    impl CgroupCleanupIo for LinuxCgroupCleanup {
        fn kill_all(&mut self) -> Result<(), ()> {
            if self.kill_attempted {
                return Err(());
            }
            // Even an interrupted or partial write is not safe to retry as if
            // no effect had occurred. The cgroup owner must handle failure.
            self.kill_attempted = true;
            if self.kill.write(b"1").map_err(|_| ())? != 1 {
                return Err(());
            }
            self.kill_succeeded = true;
            Ok(())
        }

        fn read_events(&mut self, buffer: &mut [u8]) -> Result<usize, ()> {
            if !self.kill_succeeded || buffer.is_empty() {
                return Err(());
            }
            self.events.seek(SeekFrom::Start(0)).map_err(|_| ())?;
            let mut used = 0;
            loop {
                // Reject an exactly full buffer too: EOF was not observed.
                if used == buffer.len() {
                    return Err(());
                }
                let read = self.events.read(&mut buffer[used..]).map_err(|_| ())?;
                if read == 0 {
                    return Ok(used);
                }
                used += read;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        #[test]
        fn distinguishes_inheritable_descriptors() -> Result<(), Box<dyn std::error::Error>> {
            let directory = File::open(std::env::temp_dir())?;
            assert!(close_on_exec(&directory).map_err(|_| "read flags failed")?);
            rustix::io::fcntl_setfd(&directory, rustix::io::FdFlags::empty())?;
            let inheritable = close_on_exec(&directory).map_err(|_| "read flags failed")?;
            rustix::io::fcntl_setfd(&directory, rustix::io::FdFlags::CLOEXEC)?;
            assert!(!inheritable);
            assert!(close_on_exec(&directory).map_err(|_| "read flags failed")?);
            Ok(())
        }

        #[test]
        fn fixed_control_open_rejects_symlinks() -> Result<(), Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir()
                .join(format!("cityos-cgroup-open-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&path)?;
            let events = path.join("cgroup.events");
            let target = path.join("target");
            std::fs::write(&events, b"populated 0\n")?;
            std::fs::write(&target, b"populated 0\n")?;
            let dir = File::open(&path)?;
            // This must work so an unsupported openat2 cannot make the
            // subsequent symlink rejection look like a passing check.
            let regular_opened = open_control(&dir, Control::Events).is_ok();
            std::fs::remove_file(&events)?;
            symlink(&target, &events)?;
            let symlink_rejected = open_control(&dir, Control::Events).is_err();
            std::fs::remove_file(&events)?;
            std::fs::remove_file(&target)?;
            std::fs::remove_dir(&path)?;
            assert!(regular_opened, "openat2 unavailable for regular control");
            assert!(symlink_rejected, "control symlink was followed");
            Ok(())
        }

        #[test]
        fn adapter_reads_are_bounded_and_require_one_successful_kill()
        -> Result<(), Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir()
                .join(format!("cityos-cgroup-io-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&path)?;
            let kill_path = path.join("cgroup.kill");
            let events_path = path.join("cgroup.events");
            std::fs::write(&kill_path, b"")?;
            std::fs::write(&events_path, b"populated 1\n")?;
            // This constructs the I/O object directly with ordinary test
            // files; it does not exercise or bypass the production constructor.
            let mut io = LinuxCgroupCleanup {
                _directory: File::open(&path)?.into(),
                kill: std::fs::OpenOptions::new().write(true).open(&kill_path)?,
                events: File::open(&events_path)?,
                kill_attempted: false,
                kill_succeeded: false,
            };
            let mut bytes = [0u8; 64];
            assert!(io.read_events(&mut bytes).is_err());
            assert!(io.kill_all().is_ok());
            assert!(io.kill_all().is_err());
            let count = io
                .read_events(&mut bytes)
                .map_err(|_| "events read failed")?;
            assert_eq!(&bytes[..count], b"populated 1\n");
            std::fs::write(&events_path, b"populated 0\n")?;
            let count = io
                .read_events(&mut bytes)
                .map_err(|_| "events reread failed")?;
            assert_eq!(&bytes[..count], b"populated 0\n");
            assert!(io.read_events(&mut [0u8; 12]).is_err());
            drop(io);
            std::fs::remove_file(&kill_path)?;
            std::fs::remove_file(&events_path)?;
            std::fs::remove_dir(&path)?;
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CleanupError {
    InvalidPollLimit,
    KillFailed,
    ReadFailed,
    WaitFailed,
    InvalidEvents,
    StillPopulated,
}

/// Request a recursive kill once, then make at most `poll_limit` observations.
/// Success only records that the adapter observed `populated 0` after the kill.
/// The caller-supplied wait runs between populated observations, never after the
/// final observation. A failed wait is a cleanup failure; it must not be ignored.
pub(crate) fn kill_and_observe_empty(
    io: &mut impl CgroupCleanupIo,
    poll_limit: usize,
    mut wait: impl FnMut() -> Result<(), ()>,
) -> Result<(), CleanupError> {
    if !(1..=MAX_POLLS).contains(&poll_limit) {
        return Err(CleanupError::InvalidPollLimit);
    }
    io.kill_all().map_err(|_| CleanupError::KillFailed)?;
    let mut buffer = [0u8; MAX_EVENTS_BYTES];
    for observation in 0..poll_limit {
        let len = io
            .read_events(&mut buffer)
            .map_err(|_| CleanupError::ReadFailed)?;
        // A full buffer is ambiguous even if an adapter fails to detect
        // truncation. Reject it rather than parse a potentially partial record.
        if len == 0 || len >= buffer.len() {
            return Err(CleanupError::InvalidEvents);
        }
        if !populated(&buffer[..len])? {
            return Ok(());
        }
        if observation + 1 < poll_limit {
            wait().map_err(|_| CleanupError::WaitFailed)?;
        }
    }
    Err(CleanupError::StillPopulated)
}

fn populated(bytes: &[u8]) -> Result<bool, CleanupError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CleanupError::InvalidEvents)?;
    // A final newline prevents accepting a truncated final field as complete.
    if !text.ends_with('\n') {
        return Err(CleanupError::InvalidEvents);
    }
    let mut found = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next().ok_or(CleanupError::InvalidEvents)?;
        let value = fields.next().ok_or(CleanupError::InvalidEvents)?;
        if fields.next().is_some()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(CleanupError::InvalidEvents);
        }
        if key == "populated" {
            if found.is_some() {
                return Err(CleanupError::InvalidEvents);
            }
            found = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err(CleanupError::InvalidEvents),
            });
        }
    }
    found.ok_or(CleanupError::InvalidEvents)
}
