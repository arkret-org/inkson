"""Regression tests for canonical mock transport metadata and route ownership."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import check_mock_operation_inventory as gate


class MockInventoryTests(unittest.TestCase):
    def test_generated_transport_contracts_preserve_frames_binary_and_headers(self):
        operations = {row["operation_id"]: row for row in gate.generate()["operations"]}
        stream = operations["ak.self.account.stream.subscribe.v1"]["responses"]
        self.assertEqual(stream["200"]["content"]["application/x-ndjson"]["schema_ref"], "schemas/account-subscribe-frame.schema.json")
        self.assertEqual(stream["409"]["schema_combination"], "anyOf")
        self.assertEqual(len(stream["409"]["schema_alternatives"]), 2)
        blob = operations["ak.self.blob.resource.get.v1"]["responses"]["200"]
        self.assertTrue(blob["content"]["application/octet-stream"]["binary"])
        locator = operations["ak.self.invite_locator.command.issue.v1"]["responses"]["200"]
        self.assertEqual(locator["headers"]["cache-control"]["schema"]["const"], "private, no-store")
        self.assertEqual(operations["ak.edge.push.command.unregister_device.v1"]["responses"]["204"]["content"], {})

    def test_guard_cannot_be_removed_or_raw_route_aliased(self):
        original = gate.MOCK_SOURCES[0].read_text(encoding="utf-8")
        for mutation in [original.replace("const route = guardMockRoute(rawRoute);", "const route = rawRoute;"),
                         original + "\nconst leakedRoute = rawRoute;\n"]:
            with self.subTest(mutation=mutation[-80:]), tempfile.TemporaryDirectory() as scratch:
                path = Path(scratch) / "mock.ts"
                path.write_text(mutation, encoding="utf-8", newline="\n")
                with patch.object(gate, "MOCK_SOURCES", (path,)):
                    with self.assertRaisesRegex(ValueError, "guarded route"):
                        gate.check_response_guard()


if __name__ == "__main__":
    unittest.main()
