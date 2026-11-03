import unittest
from pathlib import Path
from unittest.mock import patch

import ui_dependencies


class UiDependencyTests(unittest.TestCase):
    def test_cargo_metadata_decodes_utf8_on_every_platform(self):
        with patch.object(ui_dependencies.subprocess, "check_output", return_value='{"packages":[]}') as output:
            metadata = ui_dependencies.cargo_metadata(Path("inkson"), {})

        self.assertEqual(metadata, {"packages": []})
        self.assertEqual(output.call_args.kwargs["encoding"], "utf-8")


if __name__ == "__main__":
    unittest.main()
