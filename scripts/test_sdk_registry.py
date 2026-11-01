"""Regression coverage for automatic SDK repair and dependency rebuilds."""

import hashlib
from pathlib import Path
import tempfile
import subprocess
import threading
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



class GitSourceInventoryTests(unittest.TestCase):
    def test_git_enumeration_preserves_normative_ignored_artifacts_and_new_assets(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();cache=root/'odd-output';cache.mkdir()
            names=['src/lib.rs','theme.css','host.js','styles.list','new module.rs','spec/artifacts/registry.json','odd-output/nested/generated.rs']
            for rel in names:
                p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('source')
            # An ignored proof artifact is absent from Git's combined inventory.
            ignored=root/'artifacts/proof.json';ignored.parent.mkdir();ignored.write_text('{}')
            payload=('\0'.join(names)+'\0').encode()
            with patch.object(dev,'SPEC_REGISTRY',root/'missing.json'),patch.object(dev.subprocess,'run',return_value=Mock(stdout=payload)) as run:
                before=dev.watched_files([root],{cache})
                self.assertEqual(set(before),{root/rel for rel in names if not rel.startswith('odd-output/')})
                ignored.write_text('{"changed":true}');self.assertEqual(dev.watched_files([root],{cache}),before)
                (root/'new module.rs').unlink();self.assertNotIn(root/'new module.rs',dev.watched_files([root],{cache}))
            self.assertEqual(run.call_args.args[0],['git','-C',str(root),'ls-files','-z','--cached','--others','--exclude-standard'])
            self.assertEqual(run.call_args.kwargs['timeout'],2)

    def test_git_errors_and_two_second_timeout_are_not_hidden(self):
        for error in (subprocess.CalledProcessError(128,['git']),subprocess.TimeoutExpired('git',2)):
            with patch.object(dev.subprocess,'run',side_effect=error) as run:
                with self.assertRaises(type(error)):dev.watched_files([Path('D:/owned-source')],set())
            self.assertEqual(run.call_args.kwargs['timeout'],2)

    def test_stopped_scan_does_not_start_git(self):
        stop=threading.Event();stop.set()
        with tempfile.TemporaryDirectory() as name,patch.object(dev.subprocess,'run') as run,patch.object(dev,'SPEC_REGISTRY',Path(name)/'missing'):
            self.assertEqual(dev.watched_files([Path(name)],set(),stop),{})
        run.assert_not_called()

    def test_non_utf8_unrelated_filename_does_not_break_source_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);source=root/'source.rs';source.write_text('source')
            with patch.object(dev,'SPEC_REGISTRY',root/'missing'),patch.object(dev.subprocess,'run',return_value=Mock(stdout=b'non-utf8-\xff.tmp\0source.rs\0')):
                self.assertEqual(set(dev.watched_files([root],set())),{source})

if __name__ == "__main__":
    unittest.main()
