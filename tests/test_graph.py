import copy
import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.cli import main
from agent_proof.graph import graph_document, verify_graph
from agent_proof.ledger import ProofError, append_record, build_record, digest_json, make_ledger, merge_run, write_json


class ProvenanceGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "artifact.txt").write_text("known bytes\n", encoding="utf-8")
        (self.root / "policy.json").write_text(json.dumps({"schema": "agent-policy/v1", "decision": "allow"}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def _spec(self, *, observed=True):
        return {
            "run_id": "graph-run",
            "actor": "test",
            "recorded_at": "2026-10-01T00:00:00Z",
            "repository": {"url": "https://example.invalid/repo", "branch": "main", "commit": "0123456789abcdef0123456789abcdef01234567"},
            "operation": {"argv": ["printf", "hello"], "cwd": "/tmp/test"},
            "result": {"exit_code": 0, "duration_ms": 2, "stdout": "hello", "stderr": "", "observed": observed},
            "sources": ["policy.json"],
            "artifacts": [{"path": "artifact.txt", "label": "fixture"}],
        }

    def _run(self, *, observed=True):
        first = build_record(self._spec(observed=observed), artifact_root=self.root)
        ledger = append_record(make_ledger("graph-run"), first, artifact_root=self.root)
        second = build_record(self._spec(observed=observed), artifact_root=self.root)
        ledger = append_record(ledger, second, artifact_root=self.root)
        return merge_run(ledger, artifact_root=self.root)

    def test_graph_is_deterministic_and_deduplicates_blobs(self):
        run = self._run()
        first = graph_document(run, artifact_root=self.root, require_observed=True, require_artifacts=True)
        second = graph_document(run, artifact_root=self.root, require_observed=True, require_artifacts=True)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "agent-proof/graph/v1")
        self.assertEqual(first["graph_sha256"], second["graph_sha256"])
        blobs = [node for node in first["nodes"] if node["kind"] == "evidence"]
        self.assertEqual(len(blobs), 2)
        self.assertEqual(sorted(node["roles"] for node in blobs), [["artifact"], ["source"]])
        self.assertEqual(first["node_count"], len(first["nodes"]))
        self.assertEqual(first["edge_count"], len(first["edges"]))

    def test_graph_can_be_verified_bound_or_unbound(self):
        run = self._run()
        graph = graph_document(run, artifact_root=self.root, require_observed=True, require_artifacts=True)
        unbound = verify_graph(graph)
        self.assertTrue(unbound["ok"], unbound)
        self.assertFalse(unbound["bound_input"])
        self.assertIn("input_not_bound", unbound["unknowns"])
        bound = verify_graph(
            graph,
            document=run,
            artifact_root=self.root,
            require_input=True,
            require_observed=True,
            require_artifacts=True,
        )
        self.assertTrue(bound["ok"], bound)
        self.assertTrue(bound["bound_input"])
        self.assertEqual(bound["input_state"], "bound")
        self.assertFalse(verify_graph(graph, require_observed=True)["ok"])
        self.assertFalse(verify_graph(graph, require_artifacts=True)["ok"])

    def test_tampered_graph_and_unknown_endpoints_are_refused(self):
        graph = graph_document(self._run(), artifact_root=self.root)
        tampered = copy.deepcopy(graph)
        tampered["edges"].append({"from": "record:" + "0" * 64, "to": "blob:" + "0" * 64, "kind": "produces", "role": "artifact", "path": "evil"})
        result = verify_graph(tampered)
        self.assertFalse(result["ok"])
        self.assertTrue(any("unknown" in error for error in result["errors"]))

        broken_hash = copy.deepcopy(graph)
        broken_hash["run_id"] = "changed"
        self.assertFalse(verify_graph(broken_hash)["ok"])

    def test_relation_direction_prefix_and_path_contracts_are_refused(self):
        graph = graph_document(self._run(), artifact_root=self.root)

        spoofed = copy.deepcopy(graph)
        contains = next(edge for edge in spoofed["edges"] if edge["kind"] == "contains")
        record_id = next(node["id"] for node in spoofed["nodes"] if node["kind"] == "record")
        contains["from"] = record_id
        spoofed["graph_sha256"] = digest_json({key: value for key, value in spoofed.items() if key != "graph_sha256"})
        spoofed_result = verify_graph(spoofed)
        self.assertFalse(spoofed_result["ok"])
        self.assertTrue(any("relation direction" in error for error in spoofed_result["errors"]))

        malformed = copy.deepcopy(graph)
        supports = next(edge for edge in malformed["edges"] if edge["kind"] == "supports")
        supports["role"] = "artifact"
        supports["path"] = "../escape"
        malformed["graph_sha256"] = digest_json({key: value for key, value in malformed.items() if key != "graph_sha256"})
        malformed_result = verify_graph(malformed)
        self.assertFalse(malformed_result["ok"])
        self.assertTrue(any("relation direction" in error or "path" in error for error in malformed_result["errors"]))

        wrong_prefix = copy.deepcopy(graph)
        container = next(node for node in wrong_prefix["nodes"] if node["id"].startswith("container:"))
        container["id"] = container["id"].replace("container:", "record:", 1)
        wrong_prefix["graph_sha256"] = digest_json({key: value for key, value in wrong_prefix.items() if key != "graph_sha256"})
        self.assertFalse(verify_graph(wrong_prefix)["ok"])

    def test_same_blob_roles_do_not_create_a_graph_cycle(self):
        spec = self._spec()
        spec["sources"] = ["policy.json"]
        spec["artifacts"] = [{"path": "policy.json", "label": "same-bytes"}]
        record = build_record(spec, artifact_root=self.root)
        ledger = append_record(make_ledger("graph-run"), record, artifact_root=self.root)
        graph = graph_document(merge_run(ledger, artifact_root=self.root), artifact_root=self.root)
        blob = next(node for node in graph["nodes"] if node["kind"] == "evidence")
        self.assertEqual(blob["roles"], ["artifact", "source"])
        self.assertTrue(verify_graph(graph)["ok"])

    def test_standalone_previous_link_is_refused(self):
        spec = self._spec()
        spec["prev_sha256"] = "0" * 64
        record = build_record(spec, artifact_root=self.root)
        with self.assertRaises(ProofError):
            graph_document(record, artifact_root=self.root)

    def test_require_gates_and_unsupported_inputs_refuse(self):
        with self.assertRaises(ProofError):
            graph_document(self._run(observed=False), artifact_root=self.root, require_observed=True)
        with self.assertRaises(ProofError):
            graph_document({"schema": "agent-proof/v1", "sha256": "0" * 64})
        with self.assertRaises(ProofError):
            graph_document({"schema": "agent-proof/collect/v2", "ledger": {}})

    def test_cli_graph_and_bound_readback(self):
        run = self._run()
        source = self.root / "run.json"
        graph = self.root / "run.graph.json"
        write_json(source, run)
        self.assertEqual(main(["graph", str(source), "--artifact-root", str(self.root), "--require-observed", "--require-artifacts", "--out", str(graph)]), 0)
        self.assertEqual(
            main([
                "verify-graph",
                str(graph),
                "--input",
                str(source),
                "--artifact-root",
                str(self.root),
                "--require-input",
                "--require-observed",
                "--require-artifacts",
            ]),
            0,
        )


if __name__ == "__main__":
    unittest.main()
