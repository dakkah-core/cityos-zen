use std::path::Path;
use std::process::Command;

use cityos_zen_contracts::S14_CONSENT_SOURCE_SHA256;
use sha2::{Digest, Sha256};

const SOURCE_PATH: &str = "extensions/cityos/corpus/s14-consent-preview.json";

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .current_dir(repo)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!("git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(output.stdout)
}

#[test]
fn fixed_source_has_lf_checkout_and_exact_pinned_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let attributes = git(&repo, &["check-attr", "-z", "text", "eol", "--", SOURCE_PATH])?;
    let fields: Vec<&[u8]> = attributes.split(|byte| *byte == 0).collect();
    assert_eq!(fields, vec![
        SOURCE_PATH.as_bytes(), b"text", b"set",
        SOURCE_PATH.as_bytes(), b"eol", b"lf", b"",
    ]);

    // cat-file reads the index blob without applying checkout or clean filters.
    // Hash raw bytes, not Git's normalized worktree representation.
    let blob = git(&repo, &["cat-file", "blob", &format!(":{SOURCE_PATH}")])?;
    let worktree = std::fs::read(repo.join(SOURCE_PATH))?;
    assert_eq!(format!("{:x}", Sha256::digest(&blob)), S14_CONSENT_SOURCE_SHA256, "index blob digest");
    assert_eq!(format!("{:x}", Sha256::digest(&worktree)), S14_CONSENT_SOURCE_SHA256, "worktree byte digest");
    assert_eq!(worktree, blob, "worktree bytes differ from the pinned index blob");
    assert!(!worktree.contains(&b'\r'), "fixed source must have LF line endings");
    Ok(())
}
