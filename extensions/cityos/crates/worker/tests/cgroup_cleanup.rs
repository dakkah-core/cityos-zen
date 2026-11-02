//! Source-local protocol tests; these do not kill a real Linux cgroup.
#[path = "../src/cgroup_cleanup.rs"]
mod cgroup_cleanup;

use cgroup_cleanup::{CgroupCleanupIo, CleanupError, kill_and_observe_empty};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Default)]
struct FakeCgroup {
    kill_fails: bool,
    kills: usize,
    reads: usize,
    events: VecDeque<Result<Vec<u8>, ()>>,
    trace: Rc<RefCell<Vec<&'static str>>>,
}

impl CgroupCleanupIo for FakeCgroup {
    fn kill_all(&mut self) -> Result<(), ()> {
        self.trace.borrow_mut().push("kill");
        self.kills += 1;
        if self.kill_fails { Err(()) } else { Ok(()) }
    }

    fn read_events(&mut self, buffer: &mut [u8]) -> Result<usize, ()> {
        self.trace.borrow_mut().push("read");
        self.reads += 1;
        let bytes = self.events.pop_front().ok_or(())??;
        if bytes.len() > buffer.len() {
            return Err(());
        }
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

fn fake(events: &[&[u8]]) -> FakeCgroup {
    FakeCgroup {
        events: events.iter().map(|event| Ok(event.to_vec())).collect(),
        ..FakeCgroup::default()
    }
}

fn observe(io: &mut FakeCgroup, limit: usize) -> Result<(), CleanupError> {
    kill_and_observe_empty(io, limit, || Ok(()))
}

#[test]
fn kills_once_then_requires_an_empty_subtree() {
    let mut io = fake(&[b"populated 1\nfrozen 0\n", b"populated 0\nfrozen 0\n"]);
    assert_eq!(observe(&mut io, 2), Ok(()));
    assert_eq!((io.kills, io.reads), (1, 2));

    let mut busy = fake(&[b"populated 1\n", b"populated 1\n"]);
    assert_eq!(observe(&mut busy, 2), Err(CleanupError::StillPopulated));
    assert_eq!((busy.kills, busy.reads), (1, 2));
}

#[test]
fn waits_only_between_busy_observations_and_fails_closed() {
    let mut io = fake(&[b"populated 1\n", b"populated 1\n", b"populated 0\n"]);
    let trace = Rc::clone(&io.trace);
    assert_eq!(
        kill_and_observe_empty(&mut io, 3, || {
            trace.borrow_mut().push("wait");
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(
        *io.trace.borrow(),
        ["kill", "read", "wait", "read", "wait", "read"]
    );

    let mut immediate = fake(&[b"populated 0\n"]);
    assert_eq!(
        kill_and_observe_empty(&mut immediate, 3, || Err(())),
        Ok(())
    );
    assert_eq!(*immediate.trace.borrow(), ["kill", "read"]);

    let mut exhausted = fake(&[b"populated 1\n", b"populated 1\n"]);
    let trace = Rc::clone(&exhausted.trace);
    assert_eq!(
        kill_and_observe_empty(&mut exhausted, 2, || {
            trace.borrow_mut().push("wait");
            Ok(())
        }),
        Err(CleanupError::StillPopulated)
    );
    assert_eq!(*exhausted.trace.borrow(), ["kill", "read", "wait", "read"]);

    let mut failed = fake(&[b"populated 1\n", b"populated 0\n"]);
    assert_eq!(
        kill_and_observe_empty(&mut failed, 2, || Err(())),
        Err(CleanupError::WaitFailed)
    );
    assert_eq!((failed.kills, failed.reads), (1, 1));
}

#[test]
fn invalid_bounds_and_io_failures_never_report_success() {
    for limit in [0, 65, usize::MAX] {
        let mut io = FakeCgroup::default();
        assert_eq!(observe(&mut io, limit), Err(CleanupError::InvalidPollLimit));
        assert_eq!((io.kills, io.reads), (0, 0));
    }
    let mut failed_kill = FakeCgroup {
        kill_fails: true,
        ..FakeCgroup::default()
    };
    assert_eq!(observe(&mut failed_kill, 1), Err(CleanupError::KillFailed));
    assert_eq!(failed_kill.reads, 0);
    let mut failed_read = FakeCgroup::default();
    assert_eq!(observe(&mut failed_read, 1), Err(CleanupError::ReadFailed));
}

#[test]
fn malformed_or_ambiguous_events_fail_closed() {
    let full = vec![b'x'; 4096];
    for event in [
        &b""[..],
        &b"populated 0"[..],
        &b"frozen 0\n"[..],
        &b"populated 0\npopulated 1\n"[..],
        &b"populated 2\n"[..],
        &b"populated 00\n"[..],
        &b"populated 0 extra\n"[..],
        &b"populated 0\ninvalid\n"[..],
        &b"populated 0\n\xff\n"[..],
        full.as_slice(),
    ] {
        let mut io = fake(&[event]);
        assert_eq!(observe(&mut io, 1), Err(CleanupError::InvalidEvents));
    }
}

#[test]
fn unknown_well_formed_kernel_fields_are_accepted() {
    let mut io = fake(&[b"populated 0\nfrozen 0\nfuture_field 12\n"]);
    assert_eq!(observe(&mut io, 1), Ok(()));
}

#[cfg(target_os = "linux")]
#[test]
fn adapter_rejects_non_cgroup_directories_and_regular_files()
-> Result<(), Box<dyn std::error::Error>> {
    use cgroup_cleanup::linux::LinuxCgroupCleanup;
    use std::fs::File;
    use std::os::fd::OwnedFd;

    // These paths only supply negative test fixtures, never cgroup authority.
    let ordinary_directory: OwnedFd = File::open(std::env::temp_dir())?.into();
    assert!(LinuxCgroupCleanup::new(ordinary_directory).is_err());
    let executable: OwnedFd = File::open(std::env::current_exe()?)?.into();
    assert!(LinuxCgroupCleanup::new(executable).is_err());
    Ok(())
}
