import copy
import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.cli import main
from agent_proof.interop import (
    INTEROP_SCHEMA,
    normalize_envelope,
    verify_interop,
)
from agent_proof.ledger import ProofError, digest_json, load_json
from agent_proof.ledger import collect_ledger, verify_document


class InteroperabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def test_normalization_is_redacted_deterministic_and_source_bound(self):
        source = self._write(
            "evaluation.json",
            {
                "schema": "agent-eval/v1",
                "run_id": "private-run-id",
                "candidate_id": "candidate-alpha",
                "ok": True,
                "observed": True,
                "partial": False,
                "timed_out": False,
                "exit_code": 0,
                "duration_ms": 42,
                "item_count": 3,
                "trial_count": 1,
                "secret": "must-not-cross-boundary",
            },
        )
        normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(normalized["schema"], INTEROP_SCHEMA)
        self.assertEqual(normalized["source"]["path"], "evaluation.json")
        self.assertEqual(normalized["projection"]["status"]["outcome"], "success")
        self.assertEqual(normalized["projection"]["metrics"], {"duration_ms": 42, "item_count": 3, "trial_count": 1})
        encoded = json.dumps(normalized, sort_keys=True)
        self.assertNotIn("private-run-id", encoded)
        self.assertNotIn("must-not-cross-boundary", encoded)
        self.assertEqual(normalized["interop_sha256"], digest_json({k: v for k, v in normalized.items() if k != "interop_sha256"}))
        second = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(normalized, second)
        result = verify_interop(normalized, artifact_root=self.root, require_input=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["source_state"], "verified")
        self.assertEqual(result["unknowns"], [])

    def test_all_portfolio_adapters_preserve_unknown_fields(self):
        fixtures = {
            "agent-policy/v1": "policy",
            "agent-sandbox/v1": "sandbox",
            "agent-eval/v1": "evaluation",
            "agent-trace/v1": "trace",
            "context-pack/v1": "context",
            "agent-resume/v1": "resume",
        }
        for index, (schema, stem) in enumerate(fixtures.items()):
            source = self._write(f"{stem}.json", {"schema": schema, "ok": index % 2 == 0})
            normalized = normalize_envelope(source, artifact_root=self.root)
            self.assertEqual(normalized["source"]["schema"], schema)
            self.assertIn("observed_not_declared", normalized["unknowns"])
            self.assertIn("partial_not_declared", normalized["unknowns"])
            self.assertEqual(verify_interop(normalized)["source_state"], "unbound")

    def test_source_tamper_and_projection_tamper_fail_closed(self):
        source = self._write(
            "sandbox.json",
            {
                "schema": "agent-sandbox/v1",
                "receipt_id": "receipt-1",
                "ok": True,
                "observed": True,
                "partial": False,
                "exit_code": 0,
            },
        )
        normalized = normalize_envelope(source, artifact_root=self.root)
        source.write_text(source.read_text(encoding="utf-8").replace('"ok": true', '"ok": false'), encoding="utf-8")
        tampered_source = verify_interop(normalized, artifact_root=self.root, require_input=True)
        self.assertFalse(tampered_source["ok"], tampered_source)
        self.assertEqual(tampered_source["source_state"], "invalid")

        restored = self._write(
            "sandbox.json",
            {
                "schema": "agent-sandbox/v1",
                "receipt_id": "receipt-1",
                "ok": True,
                "observed": True,
                "partial": False,
                "exit_code": 0,
            },
        )
        self.assertEqual(restored, source)
        projection_tampered = copy.deepcopy(normalized)
        projection_tampered["projection"]["status"]["ok"] = False
        result = verify_interop(projection_tampered, artifact_root=self.root, require_input=True)
        self.assertFalse(result["ok"], result)
        self.assertTrue(any("interop_sha256" in error for error in result["errors"]))

    def test_require_input_distinguishes_integrity_from_provenance_binding(self):
        source = self._write("trace.json", {"schema": "agent-trace/v1", "ok": True})
        normalized = normalize_envelope(source, artifact_root=self.root)
        unbound = verify_interop(normalized)
        self.assertTrue(unbound["ok"], unbound)
        self.assertEqual(unbound["source_state"], "unbound")
        self.assertIn("source_not_bound", unbound["unknowns"])
        required = verify_interop(normalized, require_input=True)
        self.assertFalse(required["ok"], required)

    def test_cli_normalize_and_verify_interop(self):
        source = self._write(
            "context.json",
            {"schema": "context-pack/v1", "pack_id": "pack-1", "ok": True, "observed": True, "partial": False, "file_count": 2},
        )

    def test_normalized_envelope_can_enter_the_proof_ledger(self):
        source = self._write(
            "sandbox.json",
            {"schema": "agent-sandbox/v1", "receipt_id": "receipt-1", "ok": True, "observed": True, "partial": False},
        )
        normalized_path = self.root / "sandbox.interop.json"
        normalized_path.write_text(
            json.dumps(normalize_envelope(source, artifact_root=self.root), sort_keys=True),
            encoding="utf-8",
        )
        ledger, schemas = collect_ledger([normalized_path], run_id="interop-run", artifact_root=self.root)
        self.assertEqual(schemas, [INTEROP_SCHEMA])
        self.assertTrue(verify_document(ledger, artifact_root=self.root)["ok"])
        self.assertTrue(ledger["records"][0]["result"]["observed"])

        normalized_path.write_text(normalized_path.read_text(encoding="utf-8").replace('"ok": true', '"ok": false'), encoding="utf-8")
        with self.assertRaises(ProofError):
            collect_ledger([normalized_path], run_id="interop-run", artifact_root=self.root)
        output = self.root / "interop.json"
        self.assertEqual(main(["normalize", str(source), "--artifact-root", str(self.root), "--out", str(output)]), 0)
        self.assertEqual(
            main(["verify-interop", str(output), "--artifact-root", str(self.root), "--require-input"]),
            0,
        )

    def test_symlink_source_is_refused(self):
        source = self._write("trace.json", {"schema": "agent-trace/v1", "ok": True})
        link = self.root / "linked.json"
        link.symlink_to(source)
        with self.assertRaises(ProofError):
            normalize_envelope(link, artifact_root=self.root)


if __name__ == "__main__":
    unittest.main()
