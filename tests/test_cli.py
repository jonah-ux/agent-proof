import copy
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from agent_proof.cli import main
from agent_proof.ledger import (
    ProofError,
    append_record,
    build_record,
    collect_ledger,
    digest_json,
    export_bundle,
    make_ledger,
    merge_run,
    record_digest,
    verify_document,
    verify_bundle,
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

    def _make_bundle(self):
        record = build_record(self.spec(), artifact_root=self.root)
        ledger = append_record(make_ledger("run-1"), record, artifact_root=self.root)
        run = merge_run(ledger, artifact_root=self.root)
        bundle = self.root.parent / f"{self.root.name}-bundle.tar.gz"
        export_bundle(run, verify_document(run, artifact_root=self.root), bundle, artifact_root=self.root)
        return bundle, run

    def _rewrite_bundle(self, source, target, mutate):
        with tarfile.open(source, "r:gz") as archive:
            members = []
            for member in archive.getmembers():
                payload = archive.extractfile(member).read() if member.isfile() else None
                members.append((member, payload))
        with tarfile.open(target, "w:gz") as archive:
            for member, payload in members:
                payload = mutate(member.name, payload)
                if payload is None:
                    archive.addfile(member)
                    continue
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    def test_bundle_verifies_without_original_artifact_root(self):
        bundle, _ = self._make_bundle()
        shutil.rmtree(self.root)
        result = verify_bundle(bundle, require_observed=True, require_artifacts=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["kind"], "bundle")
        bundle.unlink()

    def test_bundle_document_tamper_is_refused_even_when_manifest_is_rewritten(self):
        bundle, run = self._make_bundle()
        tampered = self.root.parent / f"{self.root.name}-tampered.tar.gz"

        def mutate(name, payload):
            if name != "proof/document.json":
                return payload
            document = json.loads(payload)
            document["run_sha256"] = "0" * 64
            tampered_doc = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
            return tampered_doc

        self._rewrite_bundle(bundle, tampered, mutate)
        # Even if an attacker rewrites the manifest input digest, the embedded run hash still fails.
        manifest_tampered = self.root.parent / f"{self.root.name}-tampered-manifest.tar.gz"
        with tarfile.open(tampered, "r:gz") as archive:
            members = []
            document = None
            for member in archive.getmembers():
                payload = archive.extractfile(member).read() if member.isfile() else None
                if member.name == "proof/document.json":
                    document = json.loads(payload)
                members.append((member, payload))
        with tarfile.open(manifest_tampered, "w:gz") as archive:
            for member, payload in members:
                if member.name == "manifest.json":
                    manifest = json.loads(payload)
                    manifest["input_sha256"] = digest_json(document)
                    document_payload = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
                    for entry in manifest["entries"]:
                        if entry.get("archive_path") == "proof/document.json":
                            entry["size"] = len(document_payload)
                            entry["sha256"] = __import__("hashlib").sha256(document_payload).hexdigest()
                    payload = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
                if payload is not None:
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
        result = verify_bundle(manifest_tampered)
        self.assertFalse(result["ok"], result)
        self.assertTrue(any("run_sha256" in error or "record" in error for error in result["errors"]))
        bundle.unlink()
        tampered.unlink()
        manifest_tampered.unlink()

    def test_bundle_invalid_utf8_is_refused_as_structured_error(self):
        bundle, _ = self._make_bundle()
        invalid = self.root.parent / f"{self.root.name}-invalid-utf8.tar.gz"

        def mutate(name, payload):
            if name == "manifest.json":
                return b"\xff\xfe"
            return payload

        self._rewrite_bundle(bundle, invalid, mutate)
        result = verify_bundle(invalid)
        self.assertFalse(result["ok"], result)
        self.assertTrue(any("bundle JSON is invalid" in error for error in result["errors"]))
        bundle.unlink()
        invalid.unlink()

    def test_bundle_path_traversal_and_symlink_are_refused(self):
        traversal = self.root.parent / f"{self.root.name}-traversal.tar.gz"
        with tarfile.open(traversal, "w:gz") as archive:
            info = tarfile.TarInfo("../evil")
            payload = b"bad"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        self.assertFalse(verify_bundle(traversal)["ok"])
        symlink = self.root.parent / f"{self.root.name}-symlink.tar.gz"
        with tarfile.open(symlink, "w:gz") as archive:
            info = tarfile.TarInfo("manifest.json")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            archive.addfile(info)
        self.assertFalse(verify_bundle(symlink)["ok"])
        traversal.unlink()
        symlink.unlink()

    def test_collect_known_envelopes_in_deterministic_order(self):
        sandbox = self.root / "sandbox.json"
        evaluation = self.root / "evaluation.json"
        sandbox.write_text(json.dumps({"schema": "agent-sandbox/v1", "ok": True, "backend": "fallback"}), encoding="utf-8")
        evaluation.write_text(json.dumps({"schema": "agent-eval/v1", "ok": True, "exit_code": 0}), encoding="utf-8")
        ledger, schemas = collect_ledger([evaluation, sandbox], run_id="collect-run", artifact_root=self.root)
        self.assertEqual(schemas, ["agent-eval/v1", "agent-sandbox/v1"])
        checked = verify_document(ledger, artifact_root=self.root)
        self.assertTrue(checked["ok"], checked)
        self.assertEqual([record["sources"][0]["path"] for record in ledger["records"]], ["evaluation.json", "sandbox.json"])
        unknown = self.root / "unknown.json"
        unknown.write_text(json.dumps({"schema": "unknown/v9"}), encoding="utf-8")
        with self.assertRaises(ProofError):
            collect_ledger([unknown], run_id="collect-run", artifact_root=self.root)

    def test_cli_verify_bundle(self):
        bundle, _ = self._make_bundle()
        self.assertEqual(main(["verify-bundle", str(bundle), "--require-observed", "--require-artifacts"]), 0)
        bundle.unlink()

    def test_cli_capture_and_verify(self):
        path = self.root / "capture.json"
        self.assertEqual(main(["capture", "source", "--out", str(path)]), 0)
        self.assertEqual(main(["verify", str(path)]), 0)
        self.assertEqual(main(["verify", str(path), "--require-observed"]), 1)


if __name__ == "__main__":
    unittest.main()
