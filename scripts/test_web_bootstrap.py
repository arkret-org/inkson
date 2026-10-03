import unittest
from pathlib import Path
import tempfile

from web_bootstrap import BOOTSTRAP_MARKER, normalize_web_bootstrap, single_bootstrap


PREFIX = "let wasm;\nexport { initSync, __wbg_init as default };\n"
BLOCK = BOOTSTRAP_MARKER + '\n\n// Actually perform the load\n__wbg_init({module_or_path: "/./wasm/inkson_bg.wasm"}).then((wasm) => {\n  globalThis.__dx_mainWasm = wasm;\n});\n'


class WebBootstrapTests(unittest.TestCase):
    def test_cached_build_repetition_retains_one_start_and_the_glue(self):
        for repetitions in (2, 3):
            repaired = single_bootstrap(PREFIX + BLOCK * repetitions)
            self.assertTrue(repaired.startswith(PREFIX))
            self.assertEqual(repaired.count("__wbg_init({module_or_path:"), 1)
            self.assertEqual(single_bootstrap(repaired), repaired)

    def test_single_bootstrap_is_byte_stable(self):
        self.assertEqual(single_bootstrap(PREFIX + BLOCK), PREFIX + BLOCK)

    def test_conflicting_modules_are_rejected(self):
        with self.assertRaises(RuntimeError):
            single_bootstrap(PREFIX + BLOCK + BLOCK.replace("inkson_bg", "other_bg"))

    def test_unrecognized_or_extra_initialization_is_rejected(self):
        for source in (PREFIX, BLOCK + '\n__wbg_init({module_or_path: "extra"});'):
            with self.assertRaises(RuntimeError):
                single_bootstrap(source)

    def test_artifact_repair_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inkson.js"
            path.write_text(PREFIX + BLOCK * 2, encoding="utf-8")
            self.assertTrue(normalize_web_bootstrap(path))
            self.assertFalse(normalize_web_bootstrap(path))


if __name__ == "__main__":
    unittest.main()
