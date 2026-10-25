"""Regression tests against false coverage and stale normative review evidence."""
import copy
import unittest
from check_mock_operation_review import REVIEW, read, validate

class ReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.document = read(REVIEW)
    def test_current_review(self):
        self.assertEqual(validate(self.document)["operations"], 140)
    def test_missing_operation(self):
        self.document["operations"].pop()
        with self.assertRaises(AssertionError): validate(self.document)
    def test_duplicate_operation(self):
        self.document["operations"][-1] = copy.deepcopy(self.document["operations"][0])
        with self.assertRaises(AssertionError): validate(self.document)
    def test_stale_canonical_contract(self):
        self.document["operations"][0]["spec_operation_sha256"] = "0" * 64
        with self.assertRaises(AssertionError): validate(self.document)
    def test_stale_error_mapping(self):
        self.document["operations"][0]["error_mapping_sha256"] = "0" * 64
        with self.assertRaises(AssertionError): validate(self.document)
    def test_error_surface_cannot_drift(self):
        self.document["operations"][0]["operation_specific_errors"] = ["invented_error"]
        with self.assertRaises(AssertionError): validate(self.document)
    def test_source_cannot_certify_native_execution(self):
        self.document["operations"][0]["native_authority_contract"] = "covered"
        with self.assertRaises(AssertionError): validate(self.document)
    def test_missing_mock_cannot_claim_success(self):
        row = next(row for row in self.document["operations"] if row["mock_implementation"] == "missing")
        row["mock_implementation"] = "implemented"
        row["verification_need"] = "mock_behavior"
        with self.assertRaises(AssertionError): validate(self.document)
    def test_classification_is_not_coverage(self):
        self.document["classification_is_not_coverage"] = False
        with self.assertRaises(AssertionError): validate(self.document)

if __name__ == "__main__": unittest.main()
