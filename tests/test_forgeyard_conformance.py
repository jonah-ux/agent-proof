import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.interop import normalize_envelope, verify_interop
from agent_proof.ledger import ProofError


CORPUS = Path(__file__).parents[1] / "conformance" / "forgeyard-ai-work-evidence-v1.json"


class ForgeyardConformanceTests(unittest.TestCase):
    def setUp(self):
        self.corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(self.corpus["contract"], "ai-work-evidence/v1")

    def test_public_cases_are_consumed_with_status_preserved(self):
        expected = {
            "observed": (True, True, "success"),
            "failed": (False, True, "failure"),
            "unknown": (None, False, None),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case in self.corpus["cases"]:
                if not case["valid"]:
                    continue
                source = root / f"{case['name']}.json"
                source.write_text(json.dumps(case["payload"], sort_keys=True), encoding="utf-8")
                normalized = normalize_envelope(source, artifact_root=root)
                status = normalized["projection"]["status"]
                ok, observed, outcome = expected[case["status"]]
                self.assertEqual(status["shared"], case["status"])
                self.assertEqual(status["ok"], ok)
                self.assertEqual(status["observed"], observed)
                self.assertEqual(status["outcome"], outcome)
                if case["status"] == "unknown":
                    self.assertEqual(normalized["unknowns"], ["outcome_unknown"])
                else:
                    self.assertEqual(normalized["unknowns"], [])
                verified = verify_interop(normalized, artifact_root=root, require_input=True)
                self.assertTrue(verified["ok"], verified)
                self.assertEqual(verified["source_state"], "verified")

    def test_invalid_public_cases_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case in self.corpus["cases"]:
                if case["valid"]:
                    continue
                source = root / f"{case['name']}.json"
                source.write_text(json.dumps(case["payload"], sort_keys=True), encoding="utf-8")
                with self.subTest(case=case["name"]):
                    with self.assertRaises(ProofError):
                        normalize_envelope(source, artifact_root=root)


if __name__ == "__main__":
    unittest.main()
