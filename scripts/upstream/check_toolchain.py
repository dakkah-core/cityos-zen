#!/usr/bin/env python3
"""Compare the fork projection with the checked-in CMS Rust toolchain owner."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tomllib

SOURCE = "rust/rust-toolchain.toml"


def read_toolchain(path):
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    if set(document) != {"toolchain"} or not isinstance(document["toolchain"], dict):
        raise ValueError(f"invalid toolchain document: {path}")
    return document["toolchain"]


def compare(source, projection):
    if read_toolchain(source) != read_toolchain(projection):
        raise ValueError("fork toolchain differs from the CMS owner")


def git(cms, *args):
    result = subprocess.run(["git", "-C", str(cms), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError(result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cms", type=Path, required=True)
    parser.add_argument("--projection", type=Path, default=Path(__file__).resolve().parents[2] / "extensions/cityos/rust-toolchain.toml")
    args = parser.parse_args()
    try:
        cms = args.cms.resolve(strict=True)
        root = Path(git(cms, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve(strict=True)
        if root != cms:
            raise ValueError("--cms must name the repository root")
        if git(cms, "status", "--porcelain=v1", "--", SOURCE):
            raise ValueError("CMS toolchain source has uncommitted changes")
        source = cms / SOURCE
        compare(source, args.projection)
        commit = git(cms, "rev-parse", "HEAD").decode("ascii").strip()
        blob = git(cms, "show", f"HEAD:{SOURCE}")
        print(f"toolchain projection matches CMS commit {commit}; source sha256={hashlib.sha256(blob).hexdigest()}")
        print("Toolchain parity is source evidence, not a completed build or consumer qualification.")
        return 0
    except (OSError, ValueError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        print(f"toolchain parity: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
