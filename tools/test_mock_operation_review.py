"""Tooling unit tests for exact scope, semantic drift and false coverage claims."""
import copy
import sys
import unittest
from unittest.mock import patch

import check_mock_operation_review as gate


class ReviewGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(gate.ROOT / "arkret-spec/tools"))
        import check_operation_closure_locks as closure
        cls.closure = closure
        catalog = gate.read(closure.CONTRACT)
        cls.contracts = closure.operation_closures(catalog)

    def setUp(self):
        self.document = gate.read(gate.REVIEW)
        guard = patch.object(self.closure, "operation_closures", return_value=self.contracts)
        guard.start()
        self.addCleanup(guard.stop)

    def test_current_bindings_need_no_revision_or_copied_contract_members(self):
        gate.verify_contract_bindings(self.document)

    def test_logout_mock_probe_preserves_its_native_authority_obligation(self):
        identifier = "ak.gate.account.command.logout.v1"
        row = next(row for row in self.document["operations"] if row["operation_id"] == identifier)
        self.assertIn(identifier, gate.implemented_ids())
        self.assertEqual(row["verification_need"], "native_authority")
        self.assertIsNone(row["mock_test"])
        gate.verify_contract_bindings(self.document)
        row["mock_test"] = {"file": "tests/contract/remaining-operations.spec.ts",
                            "name": f"remaining valid request and response contract: {identifier}"}
        with self.assertRaises(AssertionError):
            gate.verify_contract_bindings(self.document)

    def test_summary_counts_native_logout_even_while_its_mock_probe_remains(self):
        self.assertIn("ak.gate.account.command.logout.v1", gate.implemented_ids())
        # Isolate arithmetic only; these stubs grant no native evidence credit.
        with patch.object(gate, "verify_contract_bindings"), \
             patch.object(gate, "read", return_value={}), \
             patch.object(gate, "native_digest", return_value="fixture-digest"), \
             patch.object(gate, "validate_native") as producer:
            result = gate.validate(self.document)
        producer.assert_called_once_with({}, {}, "fixture-digest")
        self.assertEqual(result, {"operations": 135, "mock_behavior": 29,
                                  "native_fixture_replay": 14, "uncovered": 92})

    def test_missing_operation(self):
        self.document["operations"].pop()
        with self.assertRaisesRegex(AssertionError, "operation set drift"):
            gate.verify_contract_bindings(self.document)

    def test_duplicate_operation(self):
        self.document["operations"][-1] = copy.deepcopy(self.document["operations"][0])
        with self.assertRaisesRegex(AssertionError, "duplicate"):
            gate.verify_contract_bindings(self.document)

    def test_stale_review_digest(self):
        self.document["operations"][0]["contract_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(AssertionError, "contract changed"):
            gate.verify_contract_bindings(self.document)

    def test_schema_or_error_closure_change_requires_review(self):
        contracts = copy.deepcopy(self.contracts)
        identifier = self.document["operations"][0]["operation_id"]
        next(row for row in contracts if row["operation_id"] == identifier)["sha256"] = "sha256:" + "0" * 64
        with patch.object(self.closure, "operation_closures", return_value=contracts):
            with self.assertRaisesRegex(AssertionError, "contract changed"):
                gate.verify_contract_bindings(self.document)

    def test_source_cannot_certify_native_execution(self):
        self.document["operations"][0]["native_authority_contract"] = "covered"
        with self.assertRaises(AssertionError):
            gate.verify_contract_bindings(self.document)

    def test_missing_mock_cannot_claim_success(self):
        row = next(row for row in self.document["operations"] if row["verification_need"] == "native_authority")
        row["verification_need"] = "mock_behavior"
        with self.assertRaises(AssertionError):
            gate.verify_contract_bindings(self.document)

    def test_redundant_scope_and_revision_are_rejected(self):
        for field in ("scope", "version", "classification_is_not_coverage"):
            with self.subTest(field=field):
                document = {**self.document, field: "unused"}
                with self.assertRaisesRegex(AssertionError, "root fields"):
                    gate.verify_contract_bindings(document)

    def test_binding_success_cannot_bypass_native_evidence(self):
        with patch.object(gate, "validate_native", side_effect=AssertionError("native producer not accepted")):
            with self.assertRaisesRegex(AssertionError, "native producer not accepted"):
                gate.validate(self.document)


if __name__ == "__main__":
    unittest.main()
