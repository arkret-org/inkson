import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import ui_dependencies


class UiDependencyTests(unittest.TestCase):
    def test_cargo_metadata_decodes_utf8_on_every_platform(self):
        with patch.object(ui_dependencies.subprocess, "check_output", return_value='{"packages":[]}') as output:
            metadata = ui_dependencies.cargo_metadata(Path("inkson"), {})

        self.assertEqual(metadata, {"packages": []})
        self.assertEqual(output.call_args.kwargs["encoding"], "utf-8")

    def test_release_graph_rejects_git_or_incorrect_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text("", encoding="utf-8")
            packages = [{"name": name, "version": version,
                         "source": ui_dependencies.REGISTRY, "manifest_path": str(manifest)}
                        for name, version in ui_dependencies.EXPECTED.items()]
            self.assertEqual(set(ui_dependencies.ui_packages({"packages": packages})), {"glory", "sapid"})
            packages[0]["source"] = "git+https://github.com/glory-rs/glory.git?branch=main#" + "a" * 40
            with self.assertRaises(RuntimeError):
                ui_dependencies.ui_packages({"packages": packages})
            packages[0]["source"] = ui_dependencies.REGISTRY
            packages[0]["version"] = "0.6.1"
            with self.assertRaises(RuntimeError):
                ui_dependencies.ui_packages({"packages": packages})


if __name__ == "__main__":
    unittest.main()
