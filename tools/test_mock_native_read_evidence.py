"""Regress missing, empty, substituted and stale native fixture claims."""
import copy
import unittest
from check_native_read_evidence import FIXTURE, MANIFEST, digest, read, validate

class NativeReadEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.corpus = read(FIXTURE)
        self.manifest = read(MANIFEST)
    def test_complete_actual_corpus(self):
        self.assertEqual(validate(self.corpus, self.manifest, digest(FIXTURE))["native_read_operations"], 14)
    def test_missing_operation_is_not_coverage(self):
        self.corpus["operations"].pop()
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_duplicate_operation_is_not_coverage(self):
        self.corpus["operations"][-1] = copy.deepcopy(self.corpus["operations"][0])
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_empty_response_is_not_native_evidence(self):
        self.corpus["operations"][0]["response_body"] = {}
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_missing_originals_is_not_native_evidence(self):
        self.corpus["operations"][0]["accepted_originals"] = {}
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_unexecuted_producer_cannot_certify_fixture(self):
        self.manifest["native_result"]["passed"] = 0
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_changed_corpus_must_be_reproduced(self):
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest, "0" * 64)
    def test_stale_producer_source_must_be_reproduced(self):
        path = next(iter(self.manifest["source_sha256"]))
        self.manifest["source_sha256"][path] = "0" * 64
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_placeholder_positive_user_lookup_is_forbidden(self):
        row = next(row for row in self.corpus["operations"] if row["operation_id"] == "ak.edge.applet.third_party_users.read.list.v1")
        row["response_body"] = {"exists": False}
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)
    def test_capture_cannot_extend_a_signed_expiry(self):
        row = next(row for row in self.corpus["operations"] if row["operation_id"] == "ak.open.identity.read.resolution.v1")
        row["verified_at"] = "2099-01-01T00:00:00Z"
        with self.assertRaises(AssertionError): validate(self.corpus, self.manifest)

if __name__ == "__main__": unittest.main()
