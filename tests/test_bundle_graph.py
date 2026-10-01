import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from agent_proof.cli import main
from agent_proof.ledger import (
    append_record,
    build_record,
    digest_json,
    export_bundle,
    make_ledger,
    merge_run,
    verify_bundle,
    verify_document,
)


class BundleGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "fixtures"
        self.root.mkdir()
        (self.root / "artifact.txt").write_text("known bytes\n", encoding="utf-8")
        (self.root / "policy.json").write_text(
            json.dumps({"schema": "agent-policy/v1", "decision": "allow"}),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def _run(self):
        spec = {
            "run_id": "bundle-graph-run",
            "actor": "test",
            "recorded_at": "2026-10-01T00:00:00Z",
            "repository": {
                "url": "https://example.invalid/repo",
                "branch": "main",
                "commit": "0123456789abcdef0123456789abcdef01234567",
            },
            "operation": {"argv": ["printf", "hello"], "cwd": "/tmp/test"},
            "result": {
                "exit_code": 0,
                "duration_ms": 2,
                "stdout": "hello",
                "stderr": "",
                "observed": True,
            },
            "sources": ["policy.json"],
            "artifacts": [{"path": "artifact.txt", "label": "fixture"}],
        }
        record = build_record(spec, artifact_root=self.root)
        ledger = append_record(make_ledger("bundle-graph-run"), record, artifact_root=self.root)
        return merge_run(ledger, artifact_root=self.root)

    def _make_bundle(self):
        run = self._run()
        bundle = Path(self.temp.name) / "proof.tar.gz"
        exported = export_bundle(
            run,
            verify_document(run, artifact_root=self.root),
            bundle,
            artifact_root=self.root,
        )
        return bundle, run, exported

    @staticmethod
    def _rewrite_bundle(source: Path, target: Path, mutate):
        with tarfile.open(source, "r:gz") as archive:
            members = []
            for member in archive.getmembers():
                payload = archive.extractfile(member).read() if member.isfile() else None
                members.append((member, payload))
        with tarfile.open(target, "w:gz") as archive:
            for member, payload in members:
                payload = mutate(member.name, payload)
                if payload is None:
                    if member.name == "proof/graph.json":
                        continue
                    if member.isfile() and member.size:
                        raise AssertionError(f"mutation removed required payload: {member.name}")
                    archive.addfile(member)
                    continue
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    def test_export_embeds_graph_and_deleted_root_readback_binds_it(self):
        bundle, _, exported = self._make_bundle()
        with tarfile.open(bundle, "r:gz") as archive:
            names = archive.getnames()
            manifest = json.load(archive.extractfile("manifest.json"))
            graph = json.load(archive.extractfile("proof/graph.json"))
        self.assertIn("proof/graph.json", names)
        self.assertEqual(exported["graph_state"], "embedded")
        self.assertEqual(manifest["graph_schema"], "agent-proof/graph/v1")
        self.assertEqual(manifest["graph_sha256"], graph["graph_sha256"])
        self.assertEqual(exported["graph_sha256"], graph["graph_sha256"])

        shutil.rmtree(self.root)
        result = verify_bundle(bundle, require_observed=True, require_artifacts=True, require_graph=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["graph_state"], "verified")
        self.assertEqual(result["graph_sha256"], graph["graph_sha256"])
        self.assertEqual(
            main(["verify-bundle", str(bundle), "--require-observed", "--require-artifacts", "--require-graph"]),
            0,
        )

    def test_graph_tamper_is_refused_even_when_manifest_digests_are_rewritten(self):
        bundle, _, _ = self._make_bundle()
        tampered = Path(self.temp.name) / "tampered-graph.tar.gz"

        def mutate(name, payload):
            if name == "proof/graph.json":
                graph = json.loads(payload)
                graph["run_id"] = "attacker-controlled"
                unsigned = dict(graph)
                unsigned.pop("graph_sha256", None)
                graph["graph_sha256"] = digest_json(unsigned)
                return json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
            if name == "manifest.json":
                manifest = json.loads(payload)
                graph = json.loads(
                    next(
                        payload
                        for member, payload in self._members(bundle)
                        if member.name == "proof/graph.json"
                    )
                )
                graph["run_id"] = "attacker-controlled"
                unsigned = dict(graph)
                unsigned.pop("graph_sha256", None)
                graph["graph_sha256"] = digest_json(unsigned)
                graph_payload = json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
                manifest["graph_sha256"] = graph["graph_sha256"]
                for entry in manifest["entries"]:
                    if entry["archive_path"] == "proof/graph.json":
                        entry["size"] = len(graph_payload)
                        entry["sha256"] = __import__("hashlib").sha256(graph_payload).hexdigest()
                return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
            return payload

        self._rewrite_bundle(bundle, tampered, mutate)
        result = verify_bundle(tampered, require_graph=True)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["graph_state"], "invalid")
        self.assertTrue(any("graph:" in error for error in result["errors"]), result)

    @staticmethod
    def _members(bundle: Path):
        with tarfile.open(bundle, "r:gz") as archive:
            for member in archive.getmembers():
                yield member, archive.extractfile(member).read() if member.isfile() else None

    def test_legacy_v2_bundle_without_graph_remains_readable_but_gate_refuses(self):
        bundle, _, _ = self._make_bundle()
        legacy = Path(self.temp.name) / "legacy.tar.gz"

        def mutate(name, payload):
            if name == "proof/graph.json":
                return None
            if name == "manifest.json":
                manifest = json.loads(payload)
                manifest.pop("graph_schema", None)
                manifest.pop("graph_sha256", None)
                manifest["entries"] = [entry for entry in manifest["entries"] if entry["archive_path"] != "proof/graph.json"]
                return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
            return payload

        self._rewrite_bundle(bundle, legacy, mutate)
        self.assertTrue(verify_bundle(legacy)["ok"])
        self.assertEqual(verify_bundle(legacy)["graph_state"], "absent")
        gated = verify_bundle(legacy, require_graph=True)
        self.assertFalse(gated["ok"])
        self.assertIn("provenance graph is required", gated["errors"])


if __name__ == "__main__":
    unittest.main()
