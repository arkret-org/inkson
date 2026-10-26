"""Regression coverage for automatic SDK repair and dependency rebuilds."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import sdk_registry as dev


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


if __name__ == "__main__":
    unittest.main()
