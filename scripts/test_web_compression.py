import gzip
from pathlib import Path
import tempfile
import unittest

from web_compression import precompress_assets


class WebCompressionTests(unittest.TestCase):
    def test_resources_round_trip_deterministically_without_freezing_html_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets" / "pkg"
            assets.mkdir(parents=True)
            sources = {
                assets / "inkson_bg.wasm": b"\x00asm" + b"wasm bytecode" * 1000,
                root / "bootstrap.js": b"export const answer = 42;\n" * 100,
                root / "app.css": b".app { color: white; }\n" * 100,
                root / "ui-build-info.json": b'{"source": "release"}' * 100,
                root / "index.html": b"<head><title>Inkson</title></head>" * 100,
            }
            for path, content in sources.items():
                path.write_bytes(content)
            precompress_assets(root)
            for path, content in sources.items():
                self.assertEqual(path.read_bytes(), content)
                compressed = path.with_name(path.name + ".gz")
                if path.suffix == ".html":
                    self.assertFalse(compressed.exists())
                    continue
                first = compressed.read_bytes()
                self.assertEqual(gzip.decompress(first), content)
                self.assertLess(len(first), len(content))
                self.assertEqual(first[4:8], b"\x00\x00\x00\x00")
                precompress_assets(root)
                self.assertEqual(compressed.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
