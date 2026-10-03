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

    def test_upstream_manifest_pin_matches_current_forgeyard_owner(self):
        self.assertEqual(
            self.corpus["upstream"],
            "https://github.com/jonah-ux/forgeyard/blob/d6feb5b0ec0f7ccb4fb7f56939e8513972b0855d/conformance/manifest.json",
        )
        self.assertEqual(
            self.corpus["upstream_commit"],
            "d6feb5b0ec0f7ccb4fb7f56939e8513972b0855d",
        )
        self.assertEqual(
            self.corpus["upstream_manifest_sha256"],
            "6fe5fc6c5993f161111110971927b07e7db4b7d9f01eac352afd173ce31e7924",
        )

    def test_fixture_cases_match_the_owner_manifest_shape(self):
        expected = {
            "valid-observed": (True, "observed"),
            "status-unknown": (True, "unknown"),
            "status-failed": (True, "failed"),
            "unknown-version": (False, None),
            "unsafe-artifact": (False, None),
            "bad-hash": (False, None),
            "malformed": (False, None),
        }
        self.assertEqual(
            {case["name"]: (case["valid"], case.get("status")) for case in self.corpus["cases"]},
            expected,
        )

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
