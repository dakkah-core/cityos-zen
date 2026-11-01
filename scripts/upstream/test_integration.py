import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cityos_zen_boundary", ROOT / "scripts/upstream/integration.py")
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)
toolchain_spec = importlib.util.spec_from_file_location("cityos_zen_toolchain", ROOT / "scripts/upstream/check_toolchain.py")
toolchain = importlib.util.module_from_spec(toolchain_spec)
toolchain_spec.loader.exec_module(toolchain)


class GitFixture:
    def __init__(self, directory):
        self.root = Path(directory)
        self.run("init", "-q")
        self.write("core/original.txt", "upstream\n")
        self.add("core/original.txt")
        self.commit("upstream")
        self.upstream = self.rev()
        self.run("update-ref", boundary.UPSTREAM_REF, self.upstream)
        manifest = json.loads((ROOT / boundary.MANIFEST).read_text(encoding="utf-8"))
        manifest["upstream"]["commit"] = self.upstream
        self.write(boundary.MANIFEST, json.dumps(manifest))
        for path in boundary.CONTROLS - {boundary.MANIFEST}:
            self.write(path, "trusted control\n")
        self.write("extensions/cityos/feature.rs", "original\n")
        for path in [boundary.MANIFEST, *(boundary.CONTROLS - {boundary.MANIFEST}), "extensions/cityos/feature.rs"]:
            self.add(path)
        self.commit("CityOS controls")
        self.base = self.rev()

    def run(self, *args):
        result = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, check=False)
        if result.returncode:
            raise AssertionError(result.stderr.decode("utf-8", "replace"))
        return result.stdout.decode("utf-8").strip()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def add(self, name):
        self.run("add", "--", name)

    def commit(self, message):
        self.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-q", "-m", message)

    def rev(self):
        return self.run("rev-parse", "HEAD")

    def check(self):
        return boundary.check(self.root, self.base, self.rev(), check_remotes=False)


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = GitFixture(self.temp.name)

    def test_clean_extension_change_is_allowed(self):
        self.repo.write("extensions/cityos/feature.rs", "updated\n")
        self.repo.add("extensions/cityos/feature.rs")
        self.repo.commit("extension")
        self.assertEqual(self.repo.check(), [])

    def test_undeclared_core_edit_is_rejected(self):
        self.repo.write("core/original.txt", "changed\n")
        self.repo.add("core/original.txt")
        self.repo.commit("core")
        self.assertTrue(any("undeclared upstream modification" in error for error in self.repo.check()))

    def test_uncommitted_source_review_detects_untracked_core_change(self):
        self.repo.write("core/undeclared.rs", "change\n")
        manifest = boundary.parse_manifest((self.repo.root / boundary.MANIFEST).read_bytes())
        errors = boundary.review_worktree(self.repo.root, manifest)
        self.assertTrue(any("undeclared upstream modification" in error for error in errors))

    def test_candidate_cannot_weaken_trusted_manifest(self):
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["requiredChecks"].remove("semantic-conformance")
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.add(boundary.MANIFEST)
        self.repo.commit("remove required check")
        with self.assertRaises(boundary.BoundaryError):
            self.repo.check()

    def test_candidate_cannot_reclassify_upstream_as_owned(self):
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["ownedDirectories"].append("core")
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.write("core/original.txt", "unreviewed core change\n")
        self.repo.add(boundary.MANIFEST)
        self.repo.add("core/original.txt")
        self.repo.commit("hide upstream change")
        self.assertTrue(any("ownership boundaries" in error for error in self.repo.check()))

    def test_candidate_cannot_self_declare_a_new_core_patch(self):
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["changes"].append({"id":"candidate-patch", "purpose":"hide an edit", "invariant":"none",
            "paths":["core/original.txt"], "tests":["scripts/upstream/test_integration.py"],
            "upstreamBase":self.repo.upstream, "status":"active", "retirement":"never"})
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.write("core/original.txt", "unreviewed core change\n")
        self.repo.add(boundary.MANIFEST)
        self.repo.add("core/original.txt")
        self.repo.commit("self declare core patch")
        self.assertTrue(any("undeclared upstream modification" in error for error in self.repo.check()))

    def test_private_source_inclusion_is_rejected(self):
        self.repo.write("extensions/cityos/feature.rs", 'include!("../../core/engine/src/lib.rs");\n')
        self.repo.add("extensions/cityos/feature.rs")
        self.repo.commit("private source")
        self.assertTrue(any("private-source" in error for error in self.repo.check()))

    def test_candidate_cannot_change_trusted_checker(self):
        self.repo.write("scripts/upstream/integration.py", "pass\n")
        self.repo.add("scripts/upstream/integration.py")
        self.repo.commit("weaken checker")
        self.assertTrue(any("trusted control changed" in error for error in self.repo.check()))

    def test_cannot_remove_a_trusted_patch_invariant(self):
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["changes"][0]["invariant"] = "weaker"
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.add(boundary.MANIFEST)
        self.repo.commit("weaken invariant")
        self.assertTrue(any("trusted invariant" in error for error in self.repo.check()))

    def test_missing_upstream_ancestry_is_rejected(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        for path in [boundary.MANIFEST, *(boundary.CONTROLS - {boundary.MANIFEST}), "extensions/cityos/feature.rs"]:
            self.repo.write(path, self.repo.run("show", f"{self.repo.base}:{path}") + "\n")
            self.repo.add(path)
        self.repo.commit("alternate")
        alternate = self.repo.rev()
        errors = boundary.check(self.repo.root, self.repo.base, alternate, check_remotes=False)
        self.assertTrue(any("trusted base is not an ancestor" in error for error in errors))

    def test_unmerged_upstream_commit_is_rejected(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("core/new.rs", "upstream\n")
        self.repo.add("core/new.rs")
        self.repo.commit("new upstream")
        incoming = self.repo.rev()
        self.repo.run("update-ref", boundary.UPSTREAM_REF, incoming)
        self.repo.run("checkout", "--detach", self.repo.base)
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["upstream"]["commit"] = incoming
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.add(boundary.MANIFEST)
        self.repo.commit("record unmerged upstream")
        self.assertTrue(any("not integrated into candidate" in error for error in self.repo.check()))

    def test_fork_commit_cannot_be_presented_as_upstream(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("core/original.txt", "not actually from upstream\n")
        self.repo.add("core/original.txt")
        self.repo.commit("fake upstream")
        forged = self.repo.rev()
        self.repo.run("checkout", "--detach", self.repo.base)
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-m", "merge fake", forged)
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["upstream"]["commit"] = forged
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.add(boundary.MANIFEST)
        self.repo.commit("record fake")
        self.assertTrue(any("not reachable from the fetched upstream branch" in error for error in self.repo.check()))

    def test_incoming_upstream_owned_path_collision_is_rejected(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("extensions/cityos/upstream.rs", "upstream collision\n")
        self.repo.add("extensions/cityos/upstream.rs")
        self.repo.commit("upstream collision")
        incoming = self.repo.rev()
        self.repo.run("update-ref", boundary.UPSTREAM_REF, incoming)
        self.repo.run("checkout", "--detach", self.repo.base)
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-m", "merge incoming", incoming)
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["upstream"]["commit"] = incoming
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.add(boundary.MANIFEST)
        self.repo.commit("record incoming")
        self.assertTrue(any("upstream collision" in error for error in self.repo.check()))

    def test_unrecorded_upstream_merge_cannot_hide_owned_collision(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("extensions/cityos/feature.rs", "upstream collision\n")
        self.repo.add("extensions/cityos/feature.rs")
        self.repo.commit("upstream collision")
        incoming = self.repo.rev()
        self.repo.run("update-ref", boundary.UPSTREAM_REF, incoming)
        self.repo.run("checkout", "--detach", self.repo.base)
        # Keep the CityOS tree while retaining the upstream commit as a parent.
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-s", "ours", "-m", "hide incoming", incoming)
        errors = self.repo.check()
        self.assertTrue(any("unrecorded upstream ancestry" in error and incoming in error for error in errors), errors)

    def test_unrecorded_side_branch_is_rejected_without_requiring_latest_upstream(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("core/selected.rs", "selected\n")
        self.repo.add("core/selected.rs")
        self.repo.commit("selected upstream")
        selected = self.repo.rev()
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("core/side.rs", "side\n")
        self.repo.add("core/side.rs")
        self.repo.commit("upstream side branch")
        side = self.repo.rev()
        self.repo.run("checkout", "--detach", selected)
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-m", "upstream merge", side)
        self.repo.run("update-ref", boundary.UPSTREAM_REF, self.repo.rev())

        self.repo.run("checkout", "--detach", self.repo.base)
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-m", "merge selected", selected)
        path = self.repo.root / boundary.MANIFEST
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["upstream"]["commit"] = selected
        self.repo.write(boundary.MANIFEST, json.dumps(manifest))
        self.repo.add(boundary.MANIFEST)
        self.repo.commit("record selected upstream")
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-q", "-m", "CityOS-only commit")
        self.assertEqual(self.repo.check(), [])

        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-s", "ours", "-m", "hide side branch", side)
        errors = self.repo.check()
        self.assertTrue(any("unrecorded upstream ancestry" in error and side in error for error in errors), errors)

    def test_upstream_ancestry_already_in_trusted_base_is_not_new(self):
        self.repo.run("checkout", "--detach", self.repo.upstream)
        self.repo.write("extensions/cityos/upstream.rs", "already integrated\n")
        self.repo.add("extensions/cityos/upstream.rs")
        self.repo.commit("upstream before trusted base")
        incoming = self.repo.rev()
        self.repo.run("update-ref", boundary.UPSTREAM_REF, incoming)
        self.repo.run("checkout", "--detach", self.repo.base)
        self.repo.run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "merge", "--no-ff", "-s", "ours", "-m", "prior integration", incoming)
        self.repo.base = self.repo.rev()
        self.repo.write("extensions/cityos/feature.rs", "CityOS-only update\n")
        self.repo.add("extensions/cityos/feature.rs")
        self.repo.commit("CityOS-only update")
        self.assertEqual(self.repo.check(), [])

    def test_owned_symlink_mode_is_rejected(self):
        blob = self.repo.run("hash-object", "-w", "core/original.txt")
        self.repo.run("update-index", "--add", "--cacheinfo", "120000", blob, "extensions/cityos/link")
        self.repo.commit("symlink")
        self.assertTrue(any("unsafe protected file type" in error for error in self.repo.check()))

    def test_declared_workflow_symlink_mode_is_rejected(self):
        blob = self.repo.run("hash-object", "-w", "core/original.txt")
        self.repo.run("update-index", "--add", "--cacheinfo", "120000", blob, ".github/workflows/rust.yaml")
        self.repo.commit("workflow symlink")
        self.assertTrue(any("unsafe protected file type" in error for error in self.repo.check()))

    def test_release_condition_cannot_be_weakened_by_a_tautology(self):
        self.repo.write(".github/workflows/rust.yaml", "if: github.repository == 'gorules/zen' || true\n")
        self.repo.add(".github/workflows/rust.yaml")
        self.repo.commit("weaken release guard")
        self.assertTrue(any("trusted control changed" in error for error in self.repo.check()))

    def test_paths_reject_traversal_and_prefix_confusion(self):
        for path in ("../other", "/absolute", "a/../b", "a//b", "a\\b", "C:/x"):
            self.assertFalse(boundary.safe_path(path), path)
        self.assertFalse(boundary.in_dir("extensions/cityos-other/a", "extensions/cityos"))

    def test_toolchain_projection_requires_exact_owner_settings(self):
        source = self.repo.root / "owner.toml"
        projection = self.repo.root / "projection.toml"
        source.write_text('[toolchain]\nchannel="1.98.1"\ntargets=["linux"]\n', encoding="utf-8")
        projection.write_text('# projected\n[toolchain]\nchannel="1.98.1"\ntargets=["linux"]\n', encoding="utf-8")
        toolchain.compare(source, projection)
        projection.write_text('[toolchain]\nchannel="1.99.0"\ntargets=["linux"]\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            toolchain.compare(source, projection)

    def test_inherited_release_jobs_restrict_repository(self):
        tagged = "github.repository == 'gorules/zen' && github.ref_type == 'tag'"
        checks = {
            "rust.yaml": {"release":tagged}, "node.yaml": {"release":tagged}, "python.yaml": {"release":tagged},
            "go.yaml": {"release":"github.repository == 'gorules/zen' && (github.ref_type == 'tag' || github.event_name == 'workflow_dispatch')"},
            "uniffi.yaml": dict.fromkeys(["release-java-kotlin", "release-csharp", "release-ios", "release-android"],tagged),
            "beta-release.yaml": {"beta":"github.repository == 'gorules/zen' && startsWith(github.ref, 'refs/heads/release/')"},
            "release-please.yaml": {"release-please":"github.repository == 'gorules/zen'"},
            "benchmark.yaml": {"publish":"github.repository == 'gorules/zen'"},
        }
        for name, jobs in checks.items():
            source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            for job, expected in jobs.items():
                with self.subTest(workflow=name, job=job):
                    match = re.search(rf"(?ms)^  {re.escape(job)}:\s*\n(.*?)(?=^  \S|\Z)", source)
                    self.assertIsNotNone(match)
                    block = match.group(1)
                    condition = re.search(r"(?m)^    if: (.+)$", block)
                    self.assertIsNotNone(condition)
                    self.assertEqual(condition.group(1).strip('"'), expected)

    def test_trusted_source_check_does_not_run_candidate_tests_on_pull_request_target(self):
        source = (ROOT / ".github/workflows/cityos-qualification.yaml").read_text(encoding="utf-8")
        self.assertIn("  pull_request_target:\n", source)
        self.assertIn('git show "$BASE:scripts/upstream/integration.py"', source)
        self.assertIn('python "$RUNNER_TEMP/cityos-trusted-boundary.py"', source)
        self.assertIn('[ "$GITHUB_EVENT_NAME" = push ]', source)
        self.assertNotIn("unittest discover", source)

    def test_build_workflows_do_not_use_private_cache_credentials(self):
        for name in ("rust.yaml", "node.yaml", "go.yaml", "uniffi.yaml"):
            with self.subTest(workflow=name):
                source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                self.assertNotIn("secrets.SCCACHE_", source)
                self.assertIn("sccache: 'false'", source)
        rust = (ROOT / ".github/workflows/rust.yaml").read_text(encoding="utf-8")
        self.assertNotIn("id-token: write", rust)
        uniffi = (ROOT / ".github/workflows/uniffi.yaml").read_text(encoding="utf-8")
        self.assertEqual(uniffi.count("id-token: write"), 1)
        node = (ROOT / ".github/workflows/node.yaml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read\n", node)
        self.assertEqual(node.count("id-token: write"), 1)
        go = (ROOT / ".github/workflows/go.yaml").read_text(encoding="utf-8")
        self.assertEqual(go.count("\npermissions:"), 1)
        self.assertNotIn("permissions: write-all", go)


if __name__ == "__main__":
    unittest.main()
