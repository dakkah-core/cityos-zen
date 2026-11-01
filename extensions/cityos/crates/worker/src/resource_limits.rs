//! Per-process resource ceilings for non-authoritative Linux previews.
//!
//! Limits apply after the evaluator has started, not to the supervisor or to
//! aggregate descendants. They are inherited but are not a security sandbox.
use cityos_zen_contracts::PolicyError;
use nix::sys::resource::{getrlimit, rlim_t, setrlimit, Resource};

const ADDRESS_SPACE_BYTES: rlim_t = 512 * 1024 * 1024;
const CPU_SECONDS: rlim_t = 3;
const OPEN_FILES: rlim_t = 32;

fn lower_and_verify(
    cap: rlim_t,
    mut get: impl FnMut() -> Result<(rlim_t, rlim_t), ()>,
    set: impl FnOnce(rlim_t, rlim_t) -> Result<(), ()>,
) -> Result<(), PolicyError> {
    let (soft, hard) = get().map_err(|_| PolicyError::Evaluation)?;
    // Never relax an inherited limit, even when only its soft limit is tighter.
    let limit = soft.min(hard).min(cap);
    set(limit, limit).map_err(|_| PolicyError::Evaluation)?;
    let actual = get().map_err(|_| PolicyError::Evaluation)?;
    if actual != (limit, limit) {
        return Err(PolicyError::Evaluation);
    }
    Ok(())
}

pub(crate) fn install() -> Result<(), PolicyError> {
    for (resource, cap) in [
        (Resource::RLIMIT_AS, ADDRESS_SPACE_BYTES),
        (Resource::RLIMIT_CPU, CPU_SECONDS),
        (Resource::RLIMIT_NOFILE, OPEN_FILES),
        (Resource::RLIMIT_FSIZE, 0),
        (Resource::RLIMIT_CORE, 0),
    ] {
        lower_and_verify(
            cap,
            || getrlimit(resource).map_err(|_| ()),
            |soft, hard| setrlimit(resource, soft, hard).map_err(|_| ()),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::process::Command;

    #[test]
    fn limit_setup_fails_closed_and_never_relaxes_inherited_limits(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let calls = Cell::new(0);
        assert_eq!(
            lower_and_verify(10, || Err(()), |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            }),
            Err(PolicyError::Evaluation)
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            lower_and_verify(10, || Ok((20, 30)), |_, _| Err(())),
            Err(PolicyError::Evaluation)
        );
        let reads = Cell::new(0);
        assert_eq!(
            lower_and_verify(
                10,
                || {
                    reads.set(reads.get() + 1);
                    if reads.get() == 1 {
                        Ok((20, 30))
                    } else {
                        Err(())
                    }
                },
                |_, _| Ok(()),
            ),
            Err(PolicyError::Evaluation)
        );
        assert_eq!(
            lower_and_verify(10, || Ok((20, 30)), |_, _| Ok(())),
            Err(PolicyError::Evaluation)
        );
        let observed = Cell::new((5, 20));
        lower_and_verify(10, || Ok(observed.get()), |soft, hard| {
            observed.set((soft, hard));
            Ok(())
        })?;
        assert_eq!(observed.get(), (5, 5));
        Ok(())
    }

    // This probe is spawned separately so irreversible hard limits never affect
    // the parent test runner. The large allocation only reserves virtual space.
    #[test]
    fn resource_limit_child_probe() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("CITYOS_ZEN_LIMIT_PROBE").as_deref() != Some(std::ffi::OsStr::new("1")) {
            return Ok(());
        }
        install()?;
        let mut allocation = Vec::<u8>::new();
        assert!(allocation.try_reserve_exact(1024 * 1024 * 1024).is_err());
        for (resource, cap) in [
            (Resource::RLIMIT_AS, ADDRESS_SPACE_BYTES),
            (Resource::RLIMIT_CPU, CPU_SECONDS),
            (Resource::RLIMIT_NOFILE, OPEN_FILES),
            (Resource::RLIMIT_FSIZE, 0),
            (Resource::RLIMIT_CORE, 0),
        ] {
            let (soft, hard) = getrlimit(resource)?;
            assert!(soft <= cap && hard <= cap && soft == hard);
        }
        println!("cityos-limit-probe-complete");
        Ok(())
    }

    #[test]
    fn kernel_limits_are_applied_in_a_separate_process() -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("resource_limits::tests::resource_limit_child_probe")
            .arg("--nocapture")
            .env("CITYOS_ZEN_LIMIT_PROBE", "1")
            .output()?;
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("cityos-limit-probe-complete"));
        Ok(())
    }
}
