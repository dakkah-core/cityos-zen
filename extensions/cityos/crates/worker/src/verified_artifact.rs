//! Immutable executable identity for the host-selected sandbox bootstrap.
use std::{fs::File, io::{Read, Seek, SeekFrom}, os::fd::{AsRawFd, OwnedFd}, os::unix::fs::FileTypeExt};
use cityos_zen_contracts::PolicyError;
use nix::fcntl::{fcntl, FcntlArg, SealFlag};
use sha2::{Digest, Sha256};
use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};

const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) struct VerifiedArtifact { file: File }

fn integer(bytes: &[u8]) -> Option<u64> {
    let mut out = 0u64;
    for (i, byte) in bytes.iter().enumerate() { out |= u64::from(*byte) << (i * 8); }
    Some(out)
}

fn static_elf(file: &mut File, size: u64) -> Result<(), PolicyError> {
    let mut header = [0u8; 64];
    file.seek(SeekFrom::Start(0)).map_err(|_| PolicyError::Evaluation)?;
    file.read_exact(&mut header).map_err(|_| PolicyError::Evaluation)?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(PolicyError::Evaluation);
    }
    let file_type = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let supported_machine = if cfg!(target_arch = "x86_64") { 62 }
        else if cfg!(target_arch = "aarch64") { 183 }
        else if cfg!(target_arch = "riscv64") { 243 }
        else { return Err(PolicyError::Evaluation); };
    if !matches!(file_type, 2 | 3) || machine != supported_machine {
        return Err(PolicyError::Evaluation);
    }
    let offset = integer(&header[32..40]).ok_or(PolicyError::Evaluation)?;
    let entry = integer(&header[54..56]).ok_or(PolicyError::Evaluation)?;
    let count = integer(&header[56..58]).ok_or(PolicyError::Evaluation)?;
    if entry < 56 || entry > 1024 || count == 0 || count > 1024
        || offset.checked_add(entry.checked_mul(count).ok_or(PolicyError::Evaluation)?)
            .is_none_or(|end| end > size)
    { return Err(PolicyError::Evaluation); }
    let mut loadable = false;
    for index in 0..count {
        file.seek(SeekFrom::Start(offset + entry * index)).map_err(|_| PolicyError::Evaluation)?;
        let mut kind = [0; 4];
        file.read_exact(&mut kind).map_err(|_| PolicyError::Evaluation)?;
        match u32::from_le_bytes(kind) {
            1 => loadable = true, // PT_LOAD
            3 => return Err(PolicyError::Evaluation), // PT_INTERP
            _ => {},
        }
    }
    if loadable { Ok(()) } else { Err(PolicyError::Evaluation) }
}

impl VerifiedArtifact {
    /// Copy an opened registered artifact into an immutable executable. The
    /// digest check is against the sealed copy, so a concurrent modification of
    /// the source cannot change the bytes subsequently executed.
    pub(crate) fn from_file(mut source: File, expected: &str) -> Result<Self, PolicyError> {
        let metadata = source.metadata().map_err(|_| PolicyError::Evaluation)?;
        if !metadata.file_type().is_file() || metadata.len() < 64 || metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(PolicyError::Evaluation);
        }
        source.seek(SeekFrom::Start(0)).map_err(|_| PolicyError::Evaluation)?;
        let fd = memfd_create("cityos-s14-evaluator", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
            .map_err(|_| PolicyError::Evaluation)?;
        let mut copy = File::from(fd);
        let copied = std::io::copy(&mut source.take(MAX_ARTIFACT_BYTES + 1), &mut copy)
            .map_err(|_| PolicyError::Evaluation)?;
        if copied != metadata.len() || copied > MAX_ARTIFACT_BYTES {
            return Err(PolicyError::Evaluation);
        }
        fcntl_add_seals(&copy, SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK)
            .map_err(|_| PolicyError::Evaluation)?;
        Self::capture(copy.into(), expected)
    }

    /// The expected digest is supplied by the registered host, never the request.
    /// A sealed regular ELF object is executed by its retained descriptor.
    pub(crate) fn capture(fd: OwnedFd, expected: &str) -> Result<Self, PolicyError> {
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(PolicyError::Evaluation);
        }
        let file = File::from(fd);
        let fd_flags = fcntl(file.as_raw_fd(), FcntlArg::F_GETFD).map_err(|_| PolicyError::Evaluation)?;
        if fd_flags & nix::libc::FD_CLOEXEC == 0 { return Err(PolicyError::Evaluation); }
        let meta = file.metadata().map_err(|_| PolicyError::Evaluation)?;
        if !meta.file_type().is_file() || meta.file_type().is_socket() || meta.len() < 64 || meta.len() > MAX_ARTIFACT_BYTES {
            return Err(PolicyError::Evaluation);
        }
        let seals = SealFlag::from_bits_retain(fcntl(file.as_raw_fd(), FcntlArg::F_GET_SEALS).map_err(|_| PolicyError::Evaluation)?);
        let required = SealFlag::F_SEAL_SEAL | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_WRITE;
        if !seals.contains(required) { return Err(PolicyError::Evaluation); }
        let mut reader = file.try_clone().map_err(|_| PolicyError::Evaluation)?;
        static_elf(&mut reader, meta.len())?;
        reader.seek(SeekFrom::Start(0)).map_err(|_| PolicyError::Evaluation)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut buffer).map_err(|_| PolicyError::Evaluation)?;
            if n == 0 { break; }
            digest.update(&buffer[..n]);
        }
        if format!("{:x}", digest.finalize()) != expected { return Err(PolicyError::Evaluation); }
        Ok(Self { file })
    }

    pub(crate) fn exec_path(&self) -> String { format!("/proc/self/fd/{}", self.file.as_raw_fd()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn elf(interpreter: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 120];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        let machine = if cfg!(target_arch = "x86_64") { 62u16 }
            else if cfg!(target_arch = "aarch64") { 183u16 } else { 243u16 };
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&(if interpreter { 3u32 } else { 1u32 }).to_le_bytes());
        bytes
    }
    fn sealed(bytes: &[u8]) -> Result<OwnedFd, Box<dyn std::error::Error>> {
        let fd = memfd_create("cityos-test", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        fcntl_add_seals(&file, SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK)?;
        Ok(file.into())
    }
    #[test]
    fn exact_sealed_static_artifact_is_required() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = elf(false);
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert!(VerifiedArtifact::capture(sealed(&bytes)?, &digest).is_ok());
        assert!(VerifiedArtifact::capture(sealed(&bytes)?, &"0".repeat(64)).is_err());
        let dynamic = elf(true);
        let digest = format!("{:x}", Sha256::digest(&dynamic));
        assert!(VerifiedArtifact::capture(sealed(&dynamic)?, &digest).is_err());
        let fd = memfd_create("unsealed", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
        let mut file = File::from(fd);
        file.write_all(&bytes)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert!(VerifiedArtifact::capture(file.into(), &digest).is_err());
        Ok(())
    }

    #[test]
    fn registered_file_is_copied_and_checked_before_execution() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = elf(false);
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let source = memfd_create("source", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
        let mut source = File::from(source);
        source.write_all(&bytes)?;
        let captured = VerifiedArtifact::from_file(source.try_clone()?, &digest)?;
        source.seek(SeekFrom::Start(0))?;
        source.write_all(&[0; 4])?;
        // Mutating the source cannot alter the sealed executable.
        assert!(VerifiedArtifact::capture(captured.file.into(), &digest).is_ok());
        assert!(VerifiedArtifact::from_file(source, &digest).is_err());
        Ok(())
    }
}
