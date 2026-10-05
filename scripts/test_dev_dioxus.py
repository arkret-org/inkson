"""Regression coverage for automatic SDK repair and dependency rebuilds."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import dev_dioxus as dev


class RegistryRepairTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.registry = self.root / "artifacts" / "registry" / "contract-registry.json"
        self.registry.parent.mkdir(parents=True)
        self.registry.write_bytes(b'{"version": "v1"}\n')
        self.generated = self.root / "event_kinds.rs"
        for name, value in (
            ("SPEC_REGISTRY", self.registry),
            ("SDK_EVENT_KINDS", self.generated),
            ("WORKSPACE_ROOT", self.root),
            ("PROJECT_ROOT", self.root),
        ):
            patcher = patch.object(dev, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.write_digest("0" * 64)

    def write_digest(self, digest):
        self.generated.write_text(
            f'pub const EVENT_KIND_REGISTRY_SHA256: &str = "{digest}";\n',
            encoding="utf-8",
        )

    def synchronize(self, command, cwd):
        self.assertEqual(cwd, self.root)
        self.assertEqual(command[0], "pwsh")
        self.assertIn(str(self.root / "arkret-rust-sdk" / "tools" / "sync-spec.ps1"), command)
        self.assertEqual(command[-2:], ["-ArtifactsDir", str(self.registry.parent.parent)])
        self.write_digest(hashlib.sha256(self.registry.read_bytes()).hexdigest())
        return "Synchronized all SDK spec-derived surfaces\n"

    def test_stale_missing_and_malformed_generated_sources_are_repaired(self):
        for state in ("stale", "missing", "malformed"):
            with self.subTest(state=state):
                if state == "stale":
                    self.write_digest("0" * 64)
                elif state == "missing":
                    self.generated.unlink()
                else:
                    self.generated.write_text("// incomplete generation\n", encoding="utf-8")
                with patch.object(dev.shutil, "which", return_value="pwsh"), patch.object(
                    dev, "run_captured", side_effect=self.synchronize
                ) as run:
                    dev.ensure_registry_alignment()
                    run.assert_called_once()
                dev.require_registry_alignment()

    def test_aligned_sources_do_not_run_generator(self):
        self.write_digest(hashlib.sha256(self.registry.read_bytes()).hexdigest())
        with patch.object(dev, "run_captured") as run:
            dev.ensure_registry_alignment()
        run.assert_not_called()

    def test_success_exit_without_alignment_is_rejected(self):
        with patch.object(dev.shutil, "which", return_value="pwsh"), patch.object(
            dev, "run_captured", return_value=""
        ):
            with self.assertRaisesRegex(RuntimeError, "generated sources are stale"):
                dev.ensure_registry_alignment()

    def test_generator_failure_preserves_diagnostics(self):
        with patch.object(dev.shutil, "which", return_value="pwsh"), patch.object(
            dev, "run_captured", side_effect=RuntimeError("codegen failed: invalid artifact")
        ):
            with self.assertRaisesRegex(RuntimeError, "invalid artifact"):
                dev.ensure_registry_alignment()

    def test_missing_spec_does_not_invoke_generator(self):
        self.registry.unlink()
        with patch.object(dev, "run_captured") as run:
            with self.assertRaises(FileNotFoundError):
                dev.ensure_registry_alignment()
        run.assert_not_called()

    def test_check_is_read_only_when_stale(self):
        with patch.object(dev, "parse_args", return_value=Mock(check=True)), patch.object(
            dev, "run_captured"
        ) as run:
            self.assertEqual(dev.main(), 1)
        run.assert_not_called()

    def test_web_start_repairs_registry_before_launching_dioxus(self):
        metadata = {
            "packages": [{"name": "inkson", "manifest_path": str(self.root / "Cargo.toml")}],
            "target_directory": str(self.root / "target"),
        }

        def launch(command, cwd):
            dev.require_registry_alignment()
            self.assertEqual(command, ["dx", "serve", "--platform", "web", "--port", "8080"])
            self.assertEqual(cwd, self.root)
            return Mock(wait=Mock(return_value=0), poll=Mock(return_value=0))

        with patch.object(dev, "parse_args", return_value=Mock(check=False, platform="web", port=8080)), patch.object(
            dev.shutil, "which", return_value="pwsh"
        ), patch.object(dev, "run_captured", side_effect=self.synchronize), patch.object(
            dev, "cargo_metadata", return_value=metadata
        ), patch.object(dev, "local_dependency_roots", return_value=[]), patch.object(
            dev.threading, "Thread"
        ), patch.object(dev.subprocess, "Popen", side_effect=launch) as process:
            self.assertEqual(dev.main(), 0)
        process.assert_called_once()


class DependencyWatchTests(unittest.TestCase):
    def test_repair_requests_one_rebuild_and_failure_withholds_it(self):
        for failure in (None, RuntimeError("generation failed")):
            with self.subTest(failure=failure):
                stop = Mock()
                stop.wait.side_effect = [False, False, False, True]
                stamp = Mock()
                before = {Path("spec.json"): (1, 1)}
                changed = {Path("spec.json"): (2, 1)}
                repaired = {**changed, Path("generated.rs"): (3, 1)}
                snapshots = [before, changed, changed, repaired, repaired]
                if failure:
                    snapshots = [before, changed, changed, changed]
                with patch.object(dev, "watched_files", side_effect=snapshots), patch.object(
                    dev.time, "monotonic", side_effect=[0.0, 3.0]
                ), patch.object(dev, "ensure_registry_alignment", side_effect=failure) as repair, patch.object(
                    dev, "REBUILD_STAMP", stamp
                ):
                    dev.dependency_watch_loop([], set(), stop)
                repair.assert_called_once()
                if failure:
                    stamp.write_text.assert_not_called()
                else:
                    stamp.write_text.assert_called_once()


if __name__ == "__main__":
    unittest.main()
