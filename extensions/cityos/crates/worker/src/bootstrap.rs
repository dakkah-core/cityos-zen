//! Private host-to-evaluator handoff over a connected Unix socket.
use std::{io::{self, IoSliceMut, Read}, mem::MaybeUninit, os::fd::{AsFd, AsRawFd, OwnedFd}};
use cityos_zen_contracts::PolicyError;
use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
use crate::registered_sandbox::{ProfileV1, PROFILE_V1};

const MAX_FRAME: usize = 4096;
const TOKEN: u8 = 0x71;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame { version: String, profile: ProfileV1 }

pub(crate) fn encode(profile: ProfileV1) -> Result<Vec<u8>, PolicyError> {
    let bytes = serde_json::to_vec(&Frame { version: PROFILE_V1.into(), profile })
        .map_err(|_| PolicyError::Evaluation)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME { return Err(PolicyError::Evaluation); }
    let mut framed = Vec::with_capacity(bytes.len() + 4);
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&bytes);
    Ok(framed)
}

/// The process starts with no request data. The launcher first places it in
/// the exact cgroup, then sends two FDs and the registered profile on fd 0.
pub(crate) fn run() -> Result<(), PolicyError> {
    if std::env::vars_os().next().is_some() { return Err(PolicyError::Evaluation); }
    let stdin = io::stdin();
    let (cgroup, input, profile) = receive(stdin.lock(), &stdin)?;
    // dup2 replaces and closes the control socket. Both received descriptors
    // were marked CLOEXEC by the kernel; execute closes all aliases again.
    nix::unistd::dup2(input.as_raw_fd(), 0).map_err(|_| PolicyError::Evaluation)?;
    drop(input);
    crate::registered_sandbox::execute_in_registered_cgroup(cgroup, profile)
}

fn receive(mut socket: impl Read, fd: &impl AsFd) -> Result<(OwnedFd, OwnedFd, ProfileV1), PolicyError> {
    let mut byte = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(fd, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
        .map_err(|_| PolicyError::Evaluation)?;
    if msg.bytes != 1 || msg.flags.contains(ReturnFlags::CTRUNC) || byte[0] != TOKEN {
        return Err(PolicyError::Evaluation);
    }
    let mut descriptors: Vec<OwnedFd> = Vec::new();
    for message in control.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(fds) => descriptors.extend(fds),
            _ => return Err(PolicyError::Evaluation),
        }
    }
    if descriptors.len() != 2 { return Err(PolicyError::Evaluation); }
    let mut length = [0u8; 4];
    socket.read_exact(&mut length).map_err(|_| PolicyError::Evaluation)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME { return Err(PolicyError::Evaluation); }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).map_err(|_| PolicyError::Evaluation)?;
    let profile = decode(&bytes)?;
    let input = descriptors.pop().ok_or(PolicyError::Evaluation)?;
    let cgroup = descriptors.pop().ok_or(PolicyError::Evaluation)?;
    Ok((cgroup, input, profile))
}

pub(crate) fn token() -> u8 { TOKEN }

fn decode(bytes: &[u8]) -> Result<ProfileV1, PolicyError> {
    let frame: Frame = serde_json::from_slice(bytes).map_err(|_| PolicyError::Evaluation)?;
    if frame.version != PROFILE_V1 { return Err(PolicyError::Evaluation); }
    frame.profile.revalidate().map_err(|_| PolicyError::Evaluation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup_limits::AggregateLimits;
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::{fs::File, io::{IoSlice, Write}, os::unix::net::UnixStream};
    use std::time::Duration;
    #[test]
    fn framed_profile_requires_version_bounds_and_unambiguous_fields() -> Result<(), Box<dyn std::error::Error>> {
        let limits = AggregateLimits::new(50_000, 100_000, 1024, 0, 1).map_err(|_| "limits")?;
        let profile = ProfileV1::new(PROFILE_V1, limits, 256, 512, Duration::from_secs(1), Duration::from_secs(1), 4)
            .map_err(|_| "profile")?;
        let encoded = encode(profile)?;
        assert_eq!(u32::from_be_bytes(encoded[..4].try_into()?) as usize, encoded.len() - 4);
        let text = std::str::from_utf8(&encoded[4..])?;
        assert!(decode(text.as_bytes()).is_ok());
        assert!(decode(text.replace(PROFILE_V1, "other").as_bytes()).is_err());
        assert!(decode(text.replacen("\"version\":", "\"version\":\"bad\",\"version\":", 1).as_bytes()).is_err());
        assert!(decode(format!("{text}{{}}").as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn receives_exactly_two_close_on_exec_descriptors_and_profile() -> Result<(), Box<dyn std::error::Error>> {
        let limits = AggregateLimits::new(50_000, 100_000, 1024, 0, 1).map_err(|_| "limits")?;
        let profile = ProfileV1::new(PROFILE_V1, limits, 256, 512, Duration::from_secs(1), Duration::from_secs(1), 4)
            .map_err(|_| "profile")?;
        let (mut host, child) = UnixStream::pair()?;
        let directory = File::open(std::env::temp_dir())?;
        let (input, _output) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let fds = [directory.as_fd(), input.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
        assert_eq!(sendmsg(&host, &[IoSlice::new(&[TOKEN])], &mut ancillary, SendFlags::NOSIGNAL)?, 1);
        host.write_all(&encode(profile)?)?;
        let mut reader = child.try_clone()?;
        let (directory, input, profile) = receive(&mut reader, &child)?;
        assert_eq!(profile.request_limit(), 256);
        for fd in [&directory, &input] {
            assert!(rustix::io::fcntl_getfd(fd)?.contains(rustix::io::FdFlags::CLOEXEC));
        }
        Ok(())
    }
}
