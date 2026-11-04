//! Unconnected, source-local cgroup v2 aggregate limit readback checks.
//!
//! This is not a launcher or a startup permission. The Linux readback adapter
//! does not establish descriptor identity, exclusive control, task membership,
//! or continuing enforcement. Its caller must supply an independently trusted
//! cgroup descriptor; do not accept workload-supplied bytes or descriptors as
//! evidence. An `Ok` only compares sequential snapshots.
//!
//! `cpu.max` is a bandwidth limit, not a total CPU-time or wall-clock budget.
//! Memory and swap are separately limited; pids counts tasks, including threads.
//! Parent cgroups can impose tighter limits, and configuration must also address
//! other host resources. No policy values or production profile are chosen here.

const MAX_CONTROL_BYTES: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LimitError {
    InvalidConfiguration,
    InvalidReadback(&'static str),
    Mismatch(&'static str),
}

/// Explicit finite limits expected on one cgroup subtree. These values must
/// come from a separately authorized profile, not from the evaluated workload.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AggregateLimits {
    cpu_quota_usec: u64,
    cpu_period_usec: u64,
    memory_bytes: u64,
    swap_bytes: u64,
    tasks: u64,
}

impl AggregateLimits {
    pub(crate) fn is_single_task(&self) -> bool { self.tasks == 1 }
    pub(crate) fn revalidate(self) -> Result<Self, LimitError> {
        Self::new(self.cpu_quota_usec, self.cpu_period_usec, self.memory_bytes, self.swap_bytes, self.tasks)
    }
    pub(crate) fn new(
        cpu_quota_usec: u64,
        cpu_period_usec: u64,
        memory_bytes: u64,
        swap_bytes: u64,
        tasks: u64,
    ) -> Result<Self, LimitError> {
        // cgroup v2 CPU bandwidth permits periods from 1ms to 1s and a
        // finite quota of at least 1ms. Swap zero is a useful finite ceiling.
        if cpu_quota_usec < 1_000
            || !(1_000..=1_000_000).contains(&cpu_period_usec)
            || memory_bytes == 0
            || tasks == 0
        {
            return Err(LimitError::InvalidConfiguration);
        }
        Ok(Self {
            cpu_quota_usec,
            cpu_period_usec,
            memory_bytes,
            swap_bytes,
            tasks,
        })
    }

    /// Compare four complete, independently obtained readbacks with the exact
    /// expected limits. Missing, truncated, unlimited, malformed, overflowing,
    /// or different values fail. Even success must not release a startup gate:
    /// all other containment prerequisites and continuous custody are external.
    pub(crate) fn verify_readback(
        &self,
        cpu_max: &[u8],
        memory_max: &[u8],
        swap_max: &[u8],
        pids_max: &[u8],
    ) -> Result<(), LimitError> {
        let cpu = parse_control::<2>("cpu.max", cpu_max)?;
        if cpu != [self.cpu_quota_usec, self.cpu_period_usec] {
            return Err(LimitError::Mismatch("cpu.max"));
        }
        for (name, bytes, expected) in [
            ("memory.max", memory_max, self.memory_bytes),
            ("memory.swap.max", swap_max, self.swap_bytes),
            ("pids.max", pids_max, self.tasks),
        ] {
            if parse_control::<1>(name, bytes)? != [expected] {
                return Err(LimitError::Mismatch(name));
            }
        }
        Ok(())
    }
}

fn parse_control<const N: usize>(name: &'static str, bytes: &[u8]) -> Result<[u64; N], LimitError> {
    let invalid = || LimitError::InvalidReadback(name);
    if bytes.is_empty() || bytes.len() >= MAX_CONTROL_BYTES || !bytes.ends_with(b"\n") {
        return Err(invalid());
    }
    let line = &bytes[..bytes.len() - 1];
    // Kernel controls are single-line ASCII values. Reject extra lines and
    // non-space separators instead of treating partial/foreign data as valid.
    if line
        .iter()
        .any(|byte| !byte.is_ascii_digit() && *byte != b' ')
    {
        return Err(invalid());
    }
    let mut fields = line
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty());
    let mut result = [0; N];
    for value in &mut result {
        let field = fields.next().ok_or_else(invalid)?;
        *value = field
            .iter()
            .try_fold(0u64, |number, byte| {
                number.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
            })
            .ok_or_else(invalid)?;
    }
    if fields.next().is_some() {
        return Err(invalid());
    }
    Ok(result)
}

/// Read-only, descriptor-anchored cgroup v2 control snapshots.
///
/// The caller must independently establish that the supplied directory names
/// the intended cgroup, not a host root or another workload, and preserve its
/// exclusive custody and control throughout use. It must prevent migration,
/// concurrent limit changes, and hostile mount namespace changes. It must also
/// prevent the supplied directory FD or its aliases from reaching the worker
/// (including via exec). The four reads are sequential, not atomic. This adapter
/// checks none of those duties, does not gate startup, and does not limit kernel
/// call or scheduling time.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::{AggregateLimits, LimitError, MAX_CONTROL_BYTES};
    use nix::sys::statfs::{fstatfs, CGROUP2_SUPER_MAGIC};
    use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsFd, OwnedFd};

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum ReadbackError {
        InvalidDirectory,
        OpenControl(&'static str),
        InvalidControl(&'static str),
        ReadControl(&'static str),
        Limits(LimitError),
    }

    #[derive(Clone, Copy)]
    enum Control {
        Cpu,
        Memory,
        Swap,
        Pids,
    }

    impl Control {
        fn name(self) -> &'static str {
            match self {
                Self::Cpu => "cpu.max",
                Self::Memory => "memory.max",
                Self::Swap => "memory.swap.max",
                Self::Pids => "pids.max",
            }
        }
    }

    // Fixed single-component names only. NO_XDEV also rejects bind-mount
    // crossings; no weaker open fallback is allowed on unsupported kernels.
    fn open_control(dir: &impl AsFd, control: Control) -> Result<OwnedFd, ()> {
        fs::openat2(
            dir,
            control.name(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
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

    fn read_complete(file: &mut File) -> Result<([u8; MAX_CONTROL_BYTES], usize), ()> {
        file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
        let mut buffer = [0; MAX_CONTROL_BYTES];
        let mut used = 0;
        loop {
            // Require EOF within the buffer. Even an exactly full read is
            // ambiguous and fails rather than accepting truncated data.
            if used == buffer.len() {
                return Err(());
            }
            let count = file.read(&mut buffer[used..]).map_err(|_| ())?;
            if count == 0 {
                return Ok((buffer, used));
            }
            used += count;
        }
    }

    pub(crate) struct LinuxCgroupLimits {
        // Retain the independently trusted anchor for the adapter's lifetime.
        _directory: OwnedFd,
        cpu: File,
        memory: File,
        swap: File,
        pids: File,
    }

    impl LinuxCgroupLimits {
        /// Consumes a trusted, close-on-exec directory descriptor; accepts no
        /// path. Filesystem/type checks cannot prove identity or custody of aliases.
        pub(crate) fn new(directory: OwnedFd) -> Result<Self, ReadbackError> {
            let dir_stat = fs::fstat(&directory).map_err(|_| ReadbackError::InvalidDirectory)?;
            if FileType::from_raw_mode(dir_stat.st_mode) != FileType::Directory
                || !is_cgroup2(&directory).map_err(|_| ReadbackError::InvalidDirectory)?
                || !close_on_exec(&directory).map_err(|_| ReadbackError::InvalidDirectory)?
            {
                return Err(ReadbackError::InvalidDirectory);
            }
            let open_verified = |control: Control| -> Result<File, ReadbackError> {
                let name = control.name();
                let fd = open_control(&directory, control)
                    .map_err(|_| ReadbackError::OpenControl(name))?;
                let stat = fs::fstat(&fd).map_err(|_| ReadbackError::InvalidControl(name))?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || stat.st_dev != dir_stat.st_dev
                    || !is_cgroup2(&fd).map_err(|_| ReadbackError::InvalidControl(name))?
                    || !close_on_exec(&fd).map_err(|_| ReadbackError::InvalidControl(name))?
                {
                    return Err(ReadbackError::InvalidControl(name));
                }
                Ok(File::from(fd))
            };
            let cpu = open_verified(Control::Cpu)?;
            let memory = open_verified(Control::Memory)?;
            let swap = open_verified(Control::Swap)?;
            let pids = open_verified(Control::Pids)?;
            Ok(Self {
                _directory: directory,
                cpu,
                memory,
                swap,
                pids,
            })
        }

        /// Compare sequential, complete readbacks from the retained FDs.
        /// Success is neither startup authorization nor proof of containment.
        pub(crate) fn verify(&mut self, expected: &AggregateLimits) -> Result<(), ReadbackError> {
            let (cpu, cpu_len) = read_complete(&mut self.cpu)
                .map_err(|_| ReadbackError::ReadControl(Control::Cpu.name()))?;
            let (memory, memory_len) = read_complete(&mut self.memory)
                .map_err(|_| ReadbackError::ReadControl(Control::Memory.name()))?;
            let (swap, swap_len) = read_complete(&mut self.swap)
                .map_err(|_| ReadbackError::ReadControl(Control::Swap.name()))?;
            let (pids, pids_len) = read_complete(&mut self.pids)
                .map_err(|_| ReadbackError::ReadControl(Control::Pids.name()))?;
            expected
                .verify_readback(
                    &cpu[..cpu_len],
                    &memory[..memory_len],
                    &swap[..swap_len],
                    &pids[..pids_len],
                )
                .map_err(ReadbackError::Limits)
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
        fn fixed_control_opens_reject_symlinks() -> Result<(), Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir()
                .join(format!("cityos-limits-open-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&path)?;
            let dir = File::open(&path)?;
            let target = path.join("target");
            std::fs::write(&target, b"1\n")?;
            for control in [Control::Cpu, Control::Memory, Control::Swap, Control::Pids] {
                let entry = path.join(control.name());
                std::fs::write(&entry, b"1\n")?;
                // Prove openat2 works before testing rejection; unsupported
                // kernels must not make a symlink-only check pass vacuously.
                assert!(open_control(&dir, control).is_ok(), "regular open failed");
                std::fs::remove_file(&entry)?;
                symlink(&target, &entry)?;
                assert!(open_control(&dir, control).is_err(), "symlink followed");
                std::fs::remove_file(&entry)?;
            }
            std::fs::remove_file(&target)?;
            std::fs::remove_dir(&path)?;
            Ok(())
        }

        #[test]
        fn complete_reads_seek_and_reject_full_or_larger_buffers(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir()
                .join(format!("cityos-limits-read-{}-{nonce}", std::process::id()));
            std::fs::write(&path, b"16\n")?;
            let mut file = File::open(&path)?;
            for _ in 0..2 {
                let (bytes, len) = read_complete(&mut file).map_err(|_| "read failed")?;
                assert_eq!(&bytes[..len], b"16\n");
            }
            std::fs::write(&path, vec![b'0'; MAX_CONTROL_BYTES - 1])?;
            assert_eq!(
                read_complete(&mut file).map_err(|_| "read failed")?.1,
                MAX_CONTROL_BYTES - 1
            );
            for size in [MAX_CONTROL_BYTES, MAX_CONTROL_BYTES + 1] {
                std::fs::write(&path, vec![b'0'; size])?;
                assert!(read_complete(&mut file).is_err());
            }
            drop(file);
            std::fs::remove_file(&path)?;
            Ok(())
        }

        #[test]
        fn adapter_uses_complete_readbacks_for_exact_comparison(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "cityos-limits-check-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path)?;
            for (name, bytes) in [
                ("cpu.max", &b"50000 100000\n"[..]),
                ("memory.max", &b"1048576\n"[..]),
                ("memory.swap.max", &b"0\n"[..]),
                ("pids.max", &b"16\n"[..]),
            ] {
                std::fs::write(path.join(name), bytes)?;
            }
            // Deliberately construct only this test object from ordinary files;
            // this does not exercise or alter the production constructor.
            let mut adapter = LinuxCgroupLimits {
                _directory: File::open(&path)?.into(),
                cpu: File::open(path.join("cpu.max"))?,
                memory: File::open(path.join("memory.max"))?,
                swap: File::open(path.join("memory.swap.max"))?,
                pids: File::open(path.join("pids.max"))?,
            };
            let expected = AggregateLimits::new(50_000, 100_000, 1_048_576, 0, 16)
                .map_err(|_| "invalid fixture")?;
            assert_eq!(adapter.verify(&expected), Ok(()));
            std::fs::write(path.join("pids.max"), b"17\n")?;
            assert_eq!(
                adapter.verify(&expected),
                Err(ReadbackError::Limits(LimitError::Mismatch("pids.max")))
            );
            std::fs::write(path.join("memory.swap.max"), b"max\n")?;
            assert_eq!(
                adapter.verify(&expected),
                Err(ReadbackError::Limits(LimitError::InvalidReadback(
                    "memory.swap.max"
                )))
            );
            std::fs::write(path.join("cpu.max"), vec![b'0'; MAX_CONTROL_BYTES])?;
            assert_eq!(
                adapter.verify(&expected),
                Err(ReadbackError::ReadControl("cpu.max"))
            );
            drop(adapter);
            for name in ["cpu.max", "memory.max", "memory.swap.max", "pids.max"] {
                std::fs::remove_file(path.join(name))?;
            }
            std::fs::remove_dir(&path)?;
            Ok(())
        }
    }
}
