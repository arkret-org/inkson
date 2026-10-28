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
