#!/usr/bin/env python3
"""Emit source/artifact coordinates for the S14 registration owner.

This produces a candidate only. It does not register, qualify, or activate an
artifact and does not establish that a binary was built from this checkout.
Run after building a Linux worker from a clean, committed fork checkout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[3]
EXTENSION = ROOT / "extensions" / "cityos"


def command(*args: str) -> bytes:
    return subprocess.check_output(args, cwd=ROOT)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_sha256(revision: str) -> str:
    digest = hashlib.sha256()
    process = subprocess.Popen(["git", "archive", "--format=tar", revision], cwd=ROOT, stdout=subprocess.PIPE)
    assert process.stdout is not None
    while chunk := process.stdout.read(1024 * 1024):
        digest.update(chunk)
    if process.wait() != 0:
        raise RuntimeError("git archive failed")
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cms", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--launcher", type=Path)
    args = parser.parse_args()
    if command("git", "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("fork checkout must be clean; a commit cannot identify dirty source")
    revision = command("git", "rev-parse", "HEAD").decode("ascii").strip()
    registry = json.loads((ROOT / "config/upstream/integration.json").read_text(encoding="utf-8"))
    projection = tomllib.loads((EXTENSION / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]
    canonical = tomllib.loads((args.cms / "rust/rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]
    if projection != canonical:
        raise RuntimeError("fork and CMS Rust toolchain projections differ")
    artifact = args.artifact.resolve(strict=True)
    launcher = (args.launcher or artifact).resolve(strict=True)
    identity = json.loads(subprocess.check_output([str(artifact), "--s14-worker-identity-stdio"], timeout=30))
    authority = json.loads((args.cms / "config/shared-platform/authority/shared-operational-authority.source.json").read_text(encoding="utf-8"))
    services = [service for system in authority["systems"] for service in system.get("services", [])
                if service.get("name") == "shared-policy-service"]
    if len(services) != 1:
        raise RuntimeError("canonical S14 service is missing or ambiguous")
    output = {
        "schemaVersion": "cityos.zen.s14-source-candidate.v1",
        "forkRepository": registry["fork"]["repository"],
        "forkRevision": revision,
        "sourceArchiveSha256": source_sha256(revision),
        "rustToolchain": canonical,
        "evaluatorSha256": file_sha256(artifact),
        "launcherSha256": file_sha256(launcher),
        "ruleProfile": identity["ruleProfile"],
        "sandboxProfile": identity["sandboxProfile"],
        "selectorSha256": identity["selectorSha256"],
        "hostCarrier": services[0]["executableHostCarrier"],
        "artifactSourceProvenance": "unverified",
        "qualificationRef": None,
    }
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
