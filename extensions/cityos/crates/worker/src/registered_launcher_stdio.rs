//! One request from the trusted S14 host. Control values are not policy facts.
use std::{fs::OpenOptions, io::{self, Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path}, time::Duration};
use cityos_zen_contracts::PolicyError;
use serde::Deserialize;
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
    profile: Profile,
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
    let control: Control = serde_json::from_slice(&read_frame(&mut input, MAX_CONTROL)?)
        .map_err(|_| PolicyError::InvalidInput)?;
    let p = control.profile;
    let profile = RegisteredProfile::new(&p.version, p.cpu_quota_usec, p.cpu_period_usec,
        p.memory_bytes, p.swap_bytes, p.tasks, p.max_request_bytes, p.max_response_bytes,
        Duration::from_millis(p.deadline_ms), Duration::from_millis(p.cleanup_deadline_ms), p.cleanup_polls)?;
    let request = read_frame(&mut input, profile.request_limit())?;
    let mut trailing = [0; 1];
    if input.read(&mut trailing).map_err(|_| PolicyError::InvalidInput)? != 0 { return Err(PolicyError::InvalidInput); }
    drop(input);
    let directory = OpenOptions::new().read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path(&control.cgroup_path)?).map_err(|_| PolicyError::Evaluation)?;
    let identity = directory.metadata().map_err(|_| PolicyError::Evaluation)?;
    if identity.dev() != control.cgroup_device || identity.ino() != control.cgroup_inode {
        return Err(PolicyError::Evaluation);
    }
    let artifact = OpenOptions::new().read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path(&control.artifact_path)?).map_err(|_| PolicyError::Evaluation)?;
    let resources = RegisteredResources::capture(directory.into(), profile)?;
    let response = TrustedLauncher::capture_file(resources, artifact, &control.artifact_sha256, &control.selector_sha256)?
        .execute(&request)?;
    io::stdout().lock().write_all(&response).map_err(|_| PolicyError::Evaluation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_frames_require_a_complete_nonempty_bounded_payload() {
        assert_eq!(read_frame(&mut &b"\0\0\0\x03abc"[..], 3).ok(), Some(b"abc".to_vec()));
        assert!(read_frame(&mut &b"\0\0\0\x04abc"[..], 4).is_err());
        assert!(read_frame(&mut &b"\0\0\0\x04abcd"[..], 3).is_err());
        assert!(read_frame(&mut &b"\0\0\0\0"[..], 3).is_err());
    }

    #[test]
    fn host_paths_reject_relative_and_parent_components() {
        assert!(path("/run/cityos/worker").is_ok());
        assert!(path("../worker").is_err());
        assert!(path("/run/../worker").is_err());
        assert!(path("").is_err());
    }
}
