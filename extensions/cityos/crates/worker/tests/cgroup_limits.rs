//! Readback checks and negative fixtures; no real cgroup is controlled or qualified.
#[path = "../src/cgroup_limits.rs"]
mod cgroup_limits;

use cgroup_limits::{AggregateLimits, LimitError};

fn limits() -> AggregateLimits {
    AggregateLimits::new(50_000, 100_000, 1_048_576, 0, 16).unwrap()
}

#[test]
fn only_finite_explicit_configuration_is_accepted() {
    for values in [
        (999, 100_000, 1, 0, 1),
        (1_000, 999, 1, 0, 1),
        (1_000, 1_000_001, 1, 0, 1),
        (1_000, 1_000, 0, 0, 1),
        (1_000, 1_000, 1, 0, 0),
    ] {
        assert_eq!(
            AggregateLimits::new(values.0, values.1, values.2, values.3, values.4),
            Err(LimitError::InvalidConfiguration)
        );
    }
    assert!(AggregateLimits::new(1_000, 1_000, 1, 0, 1).is_ok());
    assert!(AggregateLimits::new(1_000, 1_000_000, 1, 1, 1).is_ok());
}

#[test]
fn complete_matching_readbacks_are_required_for_every_control() {
    let expected = limits();
    let cpu = &b"50000 100000\n"[..];
    let memory = &b"1048576\n"[..];
    let swap = &b"0\n"[..];
    let pids = &b"16\n"[..];
    assert_eq!(expected.verify_readback(cpu, memory, swap, pids), Ok(()));
    for (actual_cpu, actual_memory, actual_swap, actual_pids, name) in [
        (&b"50001 100000\n"[..], memory, swap, pids, "cpu.max"),
        (&b"50000 99999\n"[..], memory, swap, pids, "cpu.max"),
        (cpu, &b"1048577\n"[..], swap, pids, "memory.max"),
        (cpu, memory, &b"1\n"[..], pids, "memory.swap.max"),
        (cpu, memory, swap, &b"17\n"[..], "pids.max"),
    ] {
        assert_eq!(
            expected.verify_readback(actual_cpu, actual_memory, actual_swap, actual_pids),
            Err(LimitError::Mismatch(name))
        );
    }
}

#[test]
fn malformed_truncated_unlimited_and_overflowing_readbacks_fail_closed() {
    let expected = limits();
    let mut full = vec![b'0'; 128];
    full[127] = b'\n';
    for bad in [
        &b""[..],
        &b"16"[..],
        &b"max\n"[..],
        &b"-1\n"[..],
        &b"16\n0\n"[..],
        &b"16 0\n"[..],
        &b"16\t\n"[..],
        &b"18446744073709551616\n"[..],
        &b"\xff\n"[..],
        full.as_slice(),
    ] {
        assert_eq!(
            expected.verify_readback(b"50000 100000\n", b"1048576\n", b"0\n", bad),
            Err(LimitError::InvalidReadback("pids.max"))
        );
    }
    for bad in [
        &b"max 100000\n"[..],
        &b"50000\n"[..],
        &b"50000 100000 1\n"[..],
    ] {
        assert_eq!(
            expected.verify_readback(bad, b"1048576\n", b"0\n", b"16\n"),
            Err(LimitError::InvalidReadback("cpu.max"))
        );
    }
    assert_eq!(
        expected.verify_readback(b"50000 100000\n", b"max\n", b"0\n", b"16\n"),
        Err(LimitError::InvalidReadback("memory.max"))
    );
    assert_eq!(
        expected.verify_readback(b"50000 100000\n", b"1048576\n", b"max\n", b"16\n"),
        Err(LimitError::InvalidReadback("memory.swap.max"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn adapter_rejects_non_cgroup_directory_and_regular_file() -> Result<(), Box<dyn std::error::Error>>
{
    use cgroup_limits::linux::{LinuxCgroupLimits, ReadbackError};
    use std::fs::File;
    use std::os::fd::OwnedFd;

    // Ordinary filesystem paths are negative fixtures, not cgroup authority.
    let directory: OwnedFd = File::open(std::env::temp_dir())?.into();
    assert!(matches!(
        LinuxCgroupLimits::new(directory),
        Err(ReadbackError::InvalidDirectory)
    ));
    let regular: OwnedFd = File::open(std::env::current_exe()?)?.into();
    assert!(matches!(
        LinuxCgroupLimits::new(regular),
        Err(ReadbackError::InvalidDirectory)
    ));
    Ok(())
}
