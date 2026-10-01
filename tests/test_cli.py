import copy
import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.cli import main
from agent_proof.ledger import (
    ProofError,
    append_record,
    build_record,
    export_bundle,
    make_ledger,
    merge_run,
    record_digest,
    verify_document,
    verification_output,
)


class ProofLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "artifact.txt").write_text("known bytes\n", encoding="utf-8")
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema": "agent-policy/v1", "decision": "allow"}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def spec(self, *, run_id="run-1", commit="0123456789abcdef0123456789abcdef01234567", observed=True):
        return {
            "run_id": run_id,
            "actor": "test",
            "recorded_at": "2026-10-01T00:00:00Z",
            "repository": {"url": "https://example.invalid/repo", "branch": "main", "commit": commit},
            "operation": {"argv": ["printf", "hello"], "cwd": "/tmp/test", "environment": {"TOKEN": "must-not-leak"}},
            "result": {"exit_code": 0, "duration_ms": 2, "stdout": "hello", "stderr": "", "observed": observed},
            "sources": ["policy.json"],
            "artifacts": [{"path": "artifact.txt", "label": "fixture"}],
        }

    def test_record_hash_redacts_output_and_environment(self):
        record = build_record(self.spec(), artifact_root=self.root)
        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn("must-not-leak", encoded)
        self.assertNotIn('"stdout": "hello"', encoded)
        self.assertEqual(record["record_sha256"], record_digest(record))
        self.assertEqual(verify_document(record, artifact_root=self.root)["ok"], True)

    def test_chain_and_merge_preserve_observation(self):
        ledger = make_ledger("run-1")
        ledger = append_record(ledger, build_record(self.spec(), artifact_root=self.root), artifact_root=self.root)
        ledger = append_record(ledger, build_record(self.spec(), artifact_root=self.root), artifact_root=self.root)
        self.assertEqual(verify_document(ledger, artifact_root=self.root)["record_count"], 2)
        self.assertEqual(ledger["records"][1]["prev_sha256"], ledger["records"][0]["record_sha256"])
        run = merge_run(ledger, artifact_root=self.root)
        result = verify_document(run, artifact_root=self.root)
        self.assertTrue(result["ok"])
        self.assertTrue(result["observed"])

    def test_tampered_artifact_and_chain_are_refused(self):
        record = build_record(self.spec(), artifact_root=self.root)
        ledger = append_record(make_ledger("run-1"), record, artifact_root=self.root)
        self.assertTrue(verify_document(ledger, artifact_root=self.root)["ok"])
        (self.root / "artifact.txt").write_text("changed\n", encoding="utf-8")
        tampered_artifact = verify_document(ledger, artifact_root=self.root)
        self.assertFalse(tampered_artifact["ok"])
        broken = copy.deepcopy(ledger)
        broken["records"][0]["prev_sha256"] = "0" * 64
        broken["ledger_sha256"] = __import__("agent_proof.ledger", fromlist=["ledger_digest"]).ledger_digest(broken)
        self.assertFalse(verify_document(broken, artifact_root=self.root)["ok"])

    def test_tampered_source_envelope_is_refused(self):
        record = build_record(self.spec(), artifact_root=self.root)
        ledger = append_record(make_ledger("run-1"), record, artifact_root=self.root)
        self.policy.write_text(json.dumps({"schema": "agent-policy/v1", "decision": "deny"}), encoding="utf-8")
        result = verify_document(ledger, artifact_root=self.root)
        self.assertFalse(result["ok"])
        self.assertIn("sources[0] digest or size mismatch", " ".join(result["errors"]))

    def test_symlinked_artifact_is_refused(self):
        link = self.root / "linked.txt"
        link.symlink_to(self.root / "artifact.txt")
        spec = self.spec()
        spec["artifacts"] = [{"path": "linked.txt"}]
        with self.assertRaises(ProofError):
            build_record(spec, artifact_root=self.root)

    def test_cross_repository_append_is_refused(self):
        first = build_record(self.spec(), artifact_root=self.root)
        other = build_record(self.spec(commit="abcdef0123456789abcdef0123456789abcdef01"), artifact_root=self.root)
        ledger = append_record(make_ledger("run-1"), first, artifact_root=self.root)
        with self.assertRaises(ProofError):
            append_record(ledger, other, artifact_root=self.root)

    def test_require_observed_distinguishes_integrity_from_outcome(self):
        record = build_record(self.spec(observed=False), artifact_root=self.root)
        result = verify_document(record, artifact_root=self.root)
        self.assertTrue(result["ok"])
        self.assertFalse(verification_output(result, require_observed=True)["ok"])

    def test_export_is_deterministic_and_contains_manifest(self):
        record = build_record(self.spec(), artifact_root=self.root)
        ledger = append_record(make_ledger("run-1"), record, artifact_root=self.root)
        run = merge_run(ledger, artifact_root=self.root)
        first = export_bundle(run, verify_document(run, artifact_root=self.root), self.root / "one.tar.gz", artifact_root=self.root)
        second = export_bundle(run, verify_document(run, artifact_root=self.root), self.root / "two.tar.gz", artifact_root=self.root)
        self.assertEqual(first["sha256"], second["sha256"])
        import tarfile
        with tarfile.open(self.root / "one.tar.gz", "r:gz") as archive:
            self.assertIn("manifest.json", archive.getnames())
            manifest = json.load(archive.extractfile("manifest.json"))
        self.assertEqual(manifest["schema"], "agent-proof/export/v2")

    def test_cli_capture_and_verify(self):
        path = self.root / "capture.json"
        self.assertEqual(main(["capture", "source", "--out", str(path)]), 0)
        self.assertEqual(main(["verify", str(path)]), 0)
        self.assertEqual(main(["verify", str(path), "--require-observed"]), 1)


if __name__ == "__main__":
    unittest.main()
