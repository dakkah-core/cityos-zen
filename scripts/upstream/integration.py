#!/usr/bin/env python3
"""Source-boundary checks for the CityOS Zen fork; not a qualification receipt."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

BOOTSTRAP = "ec108e8069d9eb3154e1856310cc1e8b6bcf4276"
SCHEMA = "cityos.zen-upstream-integration.v1"
UPSTREAM = "https://github.com/gorules/zen.git"
FORK = "https://github.com/dakkah-core/cityos-zen.git"
MANIFEST = "config/upstream/integration.json"
REQUIRED = frozenset({"source-boundary", "core-tests", "semantic-conformance", "isolation-limits", "artifact-consumers", "cityos-owner-host"})
OWNED = frozenset({"extensions/cityos", "config/upstream", "scripts/upstream", "scripts/corpus", "docs/cityos"})
RELEASE_CONTROLS = frozenset({".github/workflows/rust.yaml", ".github/workflows/node.yaml", ".github/workflows/python.yaml", ".github/workflows/go.yaml", ".github/workflows/uniffi.yaml", ".github/workflows/beta-release.yaml", ".github/workflows/release-please.yaml", ".github/workflows/benchmark.yaml"})
CONTROLS = frozenset({MANIFEST, "scripts/upstream/integration.py", "scripts/upstream/check_toolchain.py", "scripts/upstream/test_integration.py", ".github/workflows/cityos-qualification.yaml", ".github/workflows/cityos-extension-tests.yaml", "extensions/cityos/rust-toolchain.toml"}) | RELEASE_CONTROLS
UPSTREAM_REF = "refs/remotes/upstream/master"
SHA = re.compile(r"^[0-9a-f]{40}$")


class BoundaryError(Exception):
    pass


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise BoundaryError(f"git {args[0]} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def text(root: Path, *args: str) -> str:
    return git(root, *args).decode("utf-8", "strict").strip()


def safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and value == str(path) and all(part not in (".", "..", "") for part in value.split("/"))


def in_dir(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory + "/")


def tree(root: Path, revision: str) -> dict[str, tuple[str, str, str]]:
    result = {}
    for entry in git(root, "ls-tree", "-r", "-z", "--full-tree", revision).split(b"\0"):
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split(" ")
        path = raw_path.decode("utf-8", "strict")
        if not safe_path(path):
            raise BoundaryError(f"unsafe tree path: {path!r}")
        result[path] = (mode, kind, oid)
    return result


def show(root: Path, revision: str, path: str) -> bytes:
    return git(root, "show", f"{revision}:{path}")


def parse_manifest(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BoundaryError(f"duplicate manifest key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise BoundaryError(f"invalid manifest: {exc}") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != SCHEMA:
        raise BoundaryError("invalid integration schema")
    upstream, fork = value.get("upstream", {}), value.get("fork", {})
    if not isinstance(upstream, dict) or upstream.get("repository") != UPSTREAM or upstream.get("branch") != "master" or not SHA.fullmatch(str(upstream.get("commit", ""))):
        raise BoundaryError("unexpected upstream identity or commit")
    if not isinstance(fork, dict) or fork != {"repository": FORK, "branch": "master", "baselineCommit": BOOTSTRAP}:
        raise BoundaryError("unexpected fork identity or baseline")
    for field, minimum in (("ownedDirectories", OWNED), ("protectedControls", CONTROLS), ("requiredChecks", REQUIRED)):
        entries = value.get(field)
        if not isinstance(entries, list) or not all(isinstance(x, str) for x in entries) or len(entries) != len(set(entries)) or not minimum.issubset(entries):
            raise BoundaryError(f"missing or duplicate {field}")
        if field != "requiredChecks" and not all(safe_path(x) for x in entries):
            raise BoundaryError(f"unsafe {field} path")
    changes = value.get("changes")
    if not isinstance(changes, list):
        raise BoundaryError("missing change ledger")
    ids, paths = set(), set()
    for entry in changes:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) and entry[k].strip() for k in ("id", "purpose", "invariant", "upstreamBase", "status", "retirement")):
            raise BoundaryError("incomplete change ledger entry")
        if entry["id"] in ids or not SHA.fullmatch(entry["upstreamBase"]) or entry["status"] != "active":
            raise BoundaryError("invalid change identifier, upstream base or status")
        ids.add(entry["id"])
        for field in ("paths", "tests"):
            items = entry.get(field)
            if not isinstance(items, list) or not items or not all(safe_path(item) for item in items):
                raise BoundaryError(f"invalid ledger {field}")
        for path in entry["paths"]:
            if path in paths:
                raise BoundaryError(f"duplicate declared path: {path}")
            paths.add(path)
    return value


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode not in (0, 1):
        raise BoundaryError("unable to establish ancestry")
    return result.returncode == 0


def changed(left: dict, right: dict) -> set[str]:
    return {name for name in left.keys() | right.keys() if left.get(name) != right.get(name)}


def review_worktree(root: Path, manifest: dict) -> list[str]:
    """Inspect local changes for early feedback; this is not trusted qualification."""
    errors = []
    dirty = set(git(root, "diff", "--name-only", "--no-renames", "-z", "HEAD").decode("utf-8").split("\0"))
    dirty.update(git(root, "ls-files", "--others", "--exclude-standard", "-z").decode("utf-8").split("\0"))
    dirty.discard("")
    declared = {path for entry in manifest["changes"] for path in entry["paths"]}
    for path in sorted(dirty):
        if not safe_path(path):
            errors.append(f"unsafe changed path: {path!r}")
            continue
        owned = any(in_dir(path, directory) for directory in manifest["ownedDirectories"])
        if not owned and path not in declared:
            errors.append(f"undeclared upstream modification: {path}")
        target = root / path
        if target.is_symlink():
            errors.append(f"unsafe protected file type or mode: {path}")
        elif target.exists() and not target.resolve().is_relative_to(root):
            errors.append(f"changed path escapes repository: {path}")
        if path.startswith("extensions/cityos/") and path.endswith(".rs") and target.is_file():
            source = target.read_text(encoding="utf-8")
            if re.search(r"\binclude\s*!\s*\(|#\s*\[\s*path\s*=|(?:\.\./)+core/[^\"\s]*/src/", source):
                errors.append(f"extension uses a forbidden private-source mechanism: {path}")
    for entry in manifest["changes"]:
        for path in entry["tests"]:
            if not (root / path).is_file():
                errors.append(f"missing invariant test: {path}")
    return errors


def check(root: Path, base: str, candidate: str, bootstrap: bool = False, check_remotes: bool = True) -> list[str]:
    errors = []
    if not SHA.fullmatch(base) or not SHA.fullmatch(candidate):
        raise BoundaryError("base and candidate must be exact full commit hashes")
    if check_remotes:
        for name, expected in (("origin", FORK), ("upstream", UPSTREAM)):
            if text(root, "remote", "get-url", name).removesuffix(".git") != expected.removesuffix(".git"):
                errors.append(f"unexpected {name} remote")
    base_tree, candidate_tree = tree(root, base), tree(root, candidate)
    if not is_ancestor(root, base, candidate):
        errors.append("trusted base is not an ancestor of candidate")
    if MANIFEST not in candidate_tree:
        raise BoundaryError("candidate manifest missing")
    manifest = parse_manifest(show(root, candidate, MANIFEST))
    if MANIFEST in base_tree:
        trusted = parse_manifest(show(root, base, MANIFEST))
        if set(trusted["ownedDirectories"]) != set(manifest["ownedDirectories"]):
            errors.append("candidate changed trusted ownership boundaries")
        for name in ("ownedDirectories", "protectedControls", "requiredChecks"):
            if not set(trusted[name]).issubset(manifest[name]):
                errors.append(f"candidate weakened trusted {name}")
        candidate_changes = {entry["id"]: entry for entry in manifest["changes"]}
        for entry in trusted["changes"]:
            if candidate_changes.get(entry["id"]) != entry:
                errors.append(f"candidate changed or removed trusted invariant: {entry['id']}")
        for path in trusted["protectedControls"]:
            if path != MANIFEST and base_tree.get(path) != candidate_tree.get(path):
                errors.append(f"trusted control changed: {path}")
        trusted_upstream = tree(root, trusted["upstream"]["commit"])
        trusted_changes = {path for entry in trusted["changes"] for path in entry["paths"]}
        for path in sorted(changed(trusted_upstream, base_tree)):
            if not any(in_dir(path, directory) for directory in trusted["ownedDirectories"]) and path not in trusted_changes:
                errors.append(f"trusted base contains undeclared upstream modification: {path}")
        for path in trusted["protectedControls"]:
            mode, kind, _ = base_tree.get(path, ("", "", ""))
            if kind != "blob" or mode not in ("100644", "100755"):
                errors.append(f"trusted control missing or unsafe: {path}")
        previous_upstream = trusted["upstream"]["commit"]
    elif bootstrap and base == BOOTSTRAP:
        previous_upstream = BOOTSTRAP
        if set(manifest["ownedDirectories"]) != OWNED:
            errors.append("bootstrap changed the reviewed ownership boundaries")
    else:
        raise BoundaryError("trusted base has no controls; bootstrap is permitted only from the recorded original commit")
    upstream = manifest["upstream"]["commit"]
    try:
        observed_upstream = text(root, "rev-parse", "--verify", f"{UPSTREAM_REF}^{{commit}}")
        if not SHA.fullmatch(observed_upstream) or not is_ancestor(root, upstream, observed_upstream):
            errors.append("selected upstream is not reachable from the fetched upstream branch")
    except BoundaryError:
        errors.append("fetched upstream branch is unavailable")
    if not is_ancestor(root, previous_upstream, base):
        errors.append("trusted upstream is not an ancestor of trusted base")
    if not is_ancestor(root, previous_upstream, upstream):
        errors.append("proposed upstream does not descend from trusted upstream")
    if not is_ancestor(root, upstream, candidate):
        errors.append("selected upstream is not integrated into candidate")
    upstream_tree = tree(root, upstream)
    old_tree = tree(root, previous_upstream)
    owned = manifest["ownedDirectories"]
    upstream_delta = changed(old_tree, upstream_tree)
    for path in sorted(upstream_delta):
        if any(in_dir(path, directory) for directory in owned):
            errors.append(f"upstream collision with CityOS-owned path: {path}")
    # A proposal's own ledger cannot authorize changes to upstream-owned code.
    # Additional paths need a separate control transition evaluated by the
    # previous trusted checker and reviewers.
    declaration_source = trusted if MANIFEST in base_tree else manifest
    declared = {path for entry in declaration_source["changes"] for path in entry["paths"]}
    for path in sorted(changed(upstream_tree, candidate_tree)):
        if not any(in_dir(path, directory) for directory in owned) and path not in declared:
            errors.append(f"undeclared upstream modification: {path}")
    for path, (mode, kind, _) in candidate_tree.items():
        if any(in_dir(path, directory) for directory in owned) or path in manifest["protectedControls"] or path in declared:
            if kind != "blob" or mode not in ("100644", "100755"):
                errors.append(f"unsafe protected file type or mode: {path}")
        if path.startswith("extensions/cityos/") and path.endswith(".rs") and kind == "blob":
            source = show(root, candidate, path).decode("utf-8", "strict")
            if re.search(r"\binclude\s*!\s*\(|#\s*\[\s*path\s*=|(?:\.\./)+core/[^\"\s]*/src/", source):
                errors.append(f"extension uses a forbidden private-source mechanism: {path}")
    for entry in manifest["changes"]:
        for path in entry["tests"]:
            if path not in candidate_tree:
                errors.append(f"missing invariant test: {path}")
    if upstream != previous_upstream:
        for path in sorted(changed(base_tree, candidate_tree)):
            if any(in_dir(path, directory) for directory in owned) and path not in declared and path != MANIFEST:
                errors.append(f"upstream integration changed owned path without declaration: {path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--base", required=True, help="previously trusted full CityOS commit")
    parser.add_argument("--candidate", required=True, help="full candidate commit")
    parser.add_argument("--bootstrap", action="store_true", help="allow initial review from the recorded upstream baseline")
    parser.add_argument("--working-tree", action="store_true", help="review the initial uncommitted bootstrap; never qualifies an artifact")
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        if args.working_tree:
            if not args.bootstrap or args.base != BOOTSTRAP or args.candidate != BOOTSTRAP or text(root, "rev-parse", "HEAD") != BOOTSTRAP:
                raise BoundaryError("working-tree review is limited to the recorded initial bootstrap")
            manifest = parse_manifest((root / MANIFEST).read_bytes())
            if set(manifest["ownedDirectories"]) != OWNED or manifest["upstream"]["commit"] != BOOTSTRAP:
                raise BoundaryError("unexpected bootstrap ownership or upstream")
            for name, expected in (("origin", FORK), ("upstream", UPSTREAM)):
                if text(root, "remote", "get-url", name).removesuffix(".git") != expected.removesuffix(".git"):
                    raise BoundaryError(f"unexpected {name} remote")
            errors = review_worktree(root, manifest)
        else:
            errors = check(root, args.base, args.candidate, args.bootstrap)
            if text(root, "rev-parse", "HEAD") == args.candidate and git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
                errors.append("candidate checkout is dirty")
    except (BoundaryError, OSError, UnicodeError, ValueError) as exc:
        print(f"source-boundary: {exc}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"source-boundary: {error}", file=sys.stderr)
    if errors:
        return 1
    print("source-boundary passed; uncommitted review is provisional and is not artifact qualification or activation evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
