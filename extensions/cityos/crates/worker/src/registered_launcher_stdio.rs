//! One request from the trusted S14 host. Control values are not policy facts.
use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path}, time::Duration};
use cityos_zen_contracts::PolicyError;
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use serde::Deserialize;
use crate::json_object::Object;
use crate::{RegisteredProfile, RegisteredResources, TrustedLauncher};

const MAX_CONTROL: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Control {
    artifact_path: String,
    artifact_sha256: String,
    selector_sha256: String,
    cgroup_path: String,
    cgroup_device: u64,
    cgroup_inode: u64,
    profile: Object<Profile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Profile {
    version: String,
    cpu_quota_usec: u64,
    cpu_period_usec: u64,
    memory_bytes: u64,
    swap_bytes: u64,
    tasks: u64,
    max_request_bytes: usize,
    max_response_bytes: usize,
    deadline_ms: u64,
    cleanup_deadline_ms: u64,
    cleanup_polls: usize,
}

fn path(value: &str) -> Result<&Path, PolicyError> {
    let path = Path::new(value);
    if value.len() > 4096 || !path.is_absolute()
        || path.components().any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    { return Err(PolicyError::InvalidInput); }
    Ok(path)
}

// Resolve from an opened root in one kernel operation. O_NOFOLLOW alone only
// protects the final component; an intermediate symlink could redirect either
// registration. Do not fall back when openat2 or its resolution flags fail.
// The host still owns mount-namespace integrity and resource custody.
fn open_registered(value: &str, directory: bool) -> Result<File, PolicyError> {
    let relative = path(value)?.strip_prefix("/").map_err(|_| PolicyError::InvalidInput)?;
    if relative.as_os_str().is_empty() { return Err(PolicyError::InvalidInput); }
    let root = OpenOptions::new().read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open("/").map_err(|_| PolicyError::Evaluation)?;
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    if directory { flags |= OFlags::DIRECTORY; }
    let fd = fs::openat2(&root, relative, flags, Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS)
        .map_err(|_| PolicyError::Evaluation)?;
    Ok(File::from(fd))
}

fn read_frame(input: &mut impl Read, limit: usize) -> Result<Vec<u8>, PolicyError> {
    let mut length = [0; 4];
    input.read_exact(&mut length).map_err(|_| PolicyError::InvalidInput)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > limit { return Err(PolicyError::InvalidInput); }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes).map_err(|_| PolicyError::InvalidInput)?;
    Ok(bytes)
}

pub(crate) fn run() -> Result<(), PolicyError> {
    if std::env::vars_os().next().is_some() { return Err(PolicyError::Evaluation); }
    let mut input = io::stdin().lock();
    let control = decode_control(&read_frame(&mut input, MAX_CONTROL)?)?;
    let p = control.profile.0;
    let profile = RegisteredProfile::new(&p.version, p.cpu_quota_usec, p.cpu_period_usec,
        p.memory_bytes, p.swap_bytes, p.tasks, p.max_request_bytes, p.max_response_bytes,
        Duration::from_millis(p.deadline_ms), Duration::from_millis(p.cleanup_deadline_ms), p.cleanup_polls)?;
    let request = read_frame(&mut input, profile.request_limit())?;
    let mut trailing = [0; 1];
    if input.read(&mut trailing).map_err(|_| PolicyError::InvalidInput)? != 0 { return Err(PolicyError::InvalidInput); }
    drop(input);
    let directory = open_registered(&control.cgroup_path, true)?;
    let identity = directory.metadata().map_err(|_| PolicyError::Evaluation)?;
    if identity.dev() != control.cgroup_device || identity.ino() != control.cgroup_inode {
        return Err(PolicyError::Evaluation);
    }
    let artifact = open_registered(&control.artifact_path, false)?;
    let resources = RegisteredResources::capture(directory.into(), profile)?;
    let response = TrustedLauncher::capture_file(resources, artifact, &control.artifact_sha256, &control.selector_sha256)?
        .execute(&request)?;
    io::stdout().lock().write_all(&response).map_err(|_| PolicyError::Evaluation)
}

fn decode_control(bytes: &[u8]) -> Result<Control, PolicyError> {
    let Object(control): Object<Control> =
        serde_json::from_slice(bytes).map_err(|_| PolicyError::InvalidInput)?;
    Ok(control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::symlink, time::{SystemTime, UNIX_EPOCH}};

    #[test]
    fn host_frames_require_a_complete_nonempty_bounded_payload() {
        assert_eq!(read_frame(&mut &b"\0\0\0\x03abc"[..], 3).ok(), Some(b"abc".to_vec()));
        assert!(read_frame(&mut &b"\0\0\0\x04abc"[..], 4).is_err());
        assert!(read_frame(&mut &b"\0\0\0\x04abcd"[..], 3).is_err());
        assert!(read_frame(&mut &b"\0\0\0\0"[..], 3).is_err());
    }

    #[test]
    fn launcher_control_and_nested_profile_require_objects() -> Result<(), Box<dyn std::error::Error>> {
        let valid = serde_json::json!({
            "artifactPath":"/run/artifact",
            "artifactSha256":"a",
            "selectorSha256":"b",
            "cgroupPath":"/sys/fs/cgroup/worker",
            "cgroupDevice":1,
            "cgroupInode":2,
            "profile":{
                "version":"profile-v1",
                "cpuQuotaUsec":1000,
                "cpuPeriodUsec":1000,
                "memoryBytes":1024,
                "swapBytes":0,
                "tasks":1,
                "maxRequestBytes":1,
                "maxResponseBytes":1,
                "deadlineMs":1,
                "cleanupDeadlineMs":1,
                "cleanupPolls":1
            }
        });
        assert!(decode_control(&serde_json::to_vec(&valid)?).is_ok());
        assert!(decode_control(b"[]").is_err());
        let mut array_profile = valid;
        array_profile["profile"] = serde_json::json!([]);
        assert!(decode_control(&serde_json::to_vec(&array_profile)?).is_err());
        Ok(())
    }

    #[test]
    fn host_paths_reject_relative_and_parent_components() {
        assert!(path("/run/cityos/worker").is_ok());
        assert!(path("../worker").is_err());
        assert!(path("/run/../worker").is_err());
        assert!(path("").is_err());
    }

    #[test]
    fn registered_paths_reject_symlinks_in_every_component() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let base = std::fs::canonicalize(std::env::temp_dir())?
            .join(format!("cityos-registered-path-{}-{nonce}", std::process::id()));
        let real = base.join("real");
        std::fs::create_dir_all(&real)?;
        std::fs::create_dir(real.join("cgroup"))?;
        std::fs::write(real.join("artifact"), b"fixture")?;
        symlink(&real, base.join("alias"))?;
        symlink(real.join("artifact"), base.join("artifact-link"))?;
        let to_str = |path: &Path| -> Result<String, Box<dyn std::error::Error>> {
            Ok(path.to_str().ok_or("non-UTF-8 test path")?.to_owned())
        };

        // Establish openat2 support first, so unsupported kernels cannot make
        // the rejection checks pass without exercising successful resolution.
        assert!(open_registered(&to_str(&real)?, true).is_ok());
        assert!(open_registered(&to_str(&real.join("artifact"))?, false).is_ok());
        assert!(open_registered(&to_str(&real.join("cgroup"))?, true).is_ok());
        assert!(open_registered(&to_str(&base.join("alias"))?, true).is_err());
        assert!(open_registered(&to_str(&base.join("alias/cgroup"))?, true).is_err());
        assert!(open_registered(&to_str(&base.join("alias/artifact"))?, false).is_err());
        assert!(open_registered(&to_str(&base.join("artifact-link"))?, false).is_err());
        assert!(open_registered("/", true).is_err());

        std::fs::remove_file(base.join("artifact-link"))?;
        std::fs::remove_file(base.join("alias"))?;
        std::fs::remove_file(real.join("artifact"))?;
        std::fs::remove_dir(real.join("cgroup"))?;
        std::fs::remove_dir(real)?;
        std::fs::remove_dir(base)?;
        Ok(())
    }
}
