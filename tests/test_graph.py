import copy
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_proof.cli import main
from agent_proof.graph import graph_document, verify_graph
from agent_proof.ledger import ProofError, append_record, build_record, digest_json, export_bundle, ledger_digest, make_ledger, merge_run, record_digest, run_digest, verify_bundle, verify_document, write_json


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

    def test_standalone_record_graph_and_portable_bundle_round_trip(self):
        for observed in (True, False):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "fixtures"
                root.mkdir()
                (root / "artifact.txt").write_text("known bytes\n", encoding="utf-8")
                spec = self._spec(observed=observed)
                spec["sources"] = []
                record = build_record(spec, artifact_root=root)
                graph = graph_document(record, artifact_root=root, require_artifacts=True)
                self.assertIs(verify_graph(graph)["ok"], True)
                bound = verify_graph(graph, document=record, artifact_root=root, require_input=True, require_artifacts=True)
                self.assertIs(bound["ok"], True, bound)
                self.assertEqual(bound["input_state"], "bound")
                bundle = Path(directory) / "standalone.tar.gz"
                export_bundle(record, verify_document(record, artifact_root=root), bundle, artifact_root=root)
                shutil.rmtree(root)
                self.assertFalse(root.exists())
                result = verify_bundle(bundle, require_artifacts=True, require_graph=True)
                self.assertIs(result["ok"], True, result)
                self.assertEqual(result["graph_state"], "verified")
                self.assertIs(result["observed"], observed)

    def test_standalone_record_node_sequence_remains_required(self):
        record = build_record(self._spec(), artifact_root=self.root)
        graph = graph_document(record, artifact_root=self.root)
        for sequence in (None, 0, "1", True):
            with self.subTest(sequence=sequence):
                malformed = copy.deepcopy(graph)
                node = next(node for node in malformed["nodes"] if node["id"].startswith("record:"))
                if sequence is None:
                    node.pop("sequence")
                else:
                    node["sequence"] = sequence
                malformed["graph_sha256"] = digest_json({key: value for key, value in malformed.items() if key != "graph_sha256"})
                result = verify_graph(malformed)
                self.assertIs(result["ok"], False, result)
                self.assertTrue(any("record sequence is invalid" in error for error in result["errors"]), result)

        malformed_edge = copy.deepcopy(graph)
        edge = next(edge for edge in malformed_edge["edges"] if edge["kind"] == "contains")
        edge["sequence"] = True
        malformed_edge["graph_sha256"] = digest_json({key: value for key, value in malformed_edge.items() if key != "graph_sha256"})
        result = verify_graph(malformed_edge)
        self.assertIs(result["ok"], False, result)
        self.assertTrue(any("sequence is invalid" in error for error in result["errors"]), result)

    def test_require_gates_and_unsupported_inputs_refuse(self):
        with self.assertRaises(ProofError):
            graph_document(self._run(observed=False), artifact_root=self.root, require_observed=True)
        with self.assertRaises(ProofError):
            graph_document({"schema": "agent-proof/v1", "sha256": "0" * 64})
        with self.assertRaises(ProofError):
            graph_document({"schema": "agent-proof/collect/v2", "ledger": {}})

    def test_graph_field_shapes_return_structured_refusals(self):
        baseline = graph_document(self._run(), artifact_root=self.root)
        mutations = (
            ("input_schema", []),
            ("input_schema", {}),
            ("source_state", []),
            ("artifact_state", {}),
            ("unknowns", None),
            ("unknowns", 1),
            ("unknowns", {"fixture": "value"}),
            ("unknowns", [{}]),
            ("repository", []),
            ("repository", {"extra": "synthetic-sensitive-marker"}),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                malformed = copy.deepcopy(baseline)
                malformed[field] = value
                malformed["graph_sha256"] = digest_json({
                    key: item for key, item in malformed.items()
                    if key != "graph_sha256"
                })
                result = verify_graph(malformed)
                self.assertIs(result["ok"], False, result)
                self.assertTrue(result["errors"], result)
                json.dumps(result)

    def test_node_and_edge_shapes_do_not_escape_verification(self):
        baseline = graph_document(self._run(), artifact_root=self.root)
        mutations = (
            ("node", "kind", []),
            ("node", "kind", {}),
            ("evidence", "paths", None),
            ("evidence", "roles", 1),
            ("evidence", "schemas", None),
            ("edge", "from", []),
            ("edge", "from", {}),
            ("edge", "to", []),
            ("edge", "to", {}),
            ("edge", "kind", []),
            ("edge", "kind", {}),
            ("continues", "sequence", "2"),
            ("continues", "sequence", {}),
        )
        for category, field, value in mutations:
            with self.subTest(category=category, field=field, value=value):
                malformed = copy.deepcopy(baseline)
                if category == "node":
                    target = malformed["nodes"][0]
                elif category == "evidence":
                    target = next(
                        node for node in malformed["nodes"]
                        if node["kind"] == "evidence"
                    )
                elif category == "continues":
                    target = next(
                        edge for edge in malformed["edges"]
                        if edge["kind"] == "continues"
                    )
                else:
                    target = malformed["edges"][0]
                target[field] = value
                malformed["graph_sha256"] = digest_json({
                    key: item for key, item in malformed.items()
                    if key != "graph_sha256"
                })
                result = verify_graph(malformed)
                self.assertIs(result["ok"], False, result)
                self.assertTrue(result["errors"], result)
                json.dumps(result)

    def test_graph_counts_require_json_integers(self):
        baseline = graph_document(self._run(), artifact_root=self.root)
        for field in ("node_count", "edge_count"):
            for value in (float(baseline[field]), True, False):
                with self.subTest(field=field, value=value):
                    malformed = copy.deepcopy(baseline)
                    malformed[field] = value
                    malformed["graph_sha256"] = digest_json({
                        key: item for key, item in malformed.items()
                        if key != "graph_sha256"
                    })
                    result = verify_graph(malformed)
                    self.assertIs(result["ok"], False, result)
                    self.assertIn(f"{field} must be an integer", result["errors"])

    def test_record_node_fields_are_checked_without_source_binding(self):
        baseline = graph_document(self._run(), artifact_root=self.root)
        mutations = (
            ("observed", []), ("partial", {}), ("prev_sha256", {}),
            ("run_id", []), ("run_id", "other-run"), ("unknowns", None),
            ("unknowns", [{}]), ("unknowns", ["z", "a"]),
            ("unknowns", ["a", "a"]), ("unexpected", {}),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                malformed = copy.deepcopy(baseline)
                node = next(item for item in malformed["nodes"] if item["id"].startswith("record:"))
                node[field] = value
                malformed["graph_sha256"] = digest_json({
                    key: item for key, item in malformed.items()
                    if key != "graph_sha256"
                })
                result = verify_graph(malformed)
                self.assertIs(result["ok"], False, result)
                self.assertIs(result["bound_input"], False)
                self.assertTrue(result["errors"], result)

    def test_graph_builder_normalizes_repeated_record_unknowns(self):
        record = build_record(self._spec(), artifact_root=self.root)
        record["result"]["unknowns"] = ["z", "a", "a"]
        record["record_sha256"] = record_digest(record)
        graph = graph_document(record, artifact_root=self.root)
        node = next(item for item in graph["nodes"] if item["id"].startswith("record:"))
        self.assertEqual(node["unknowns"], ["a", "z"])
        self.assertIs(verify_graph(graph)["ok"], True)

    def test_graph_builder_rejects_non_string_schema(self):
        for schema in (None, [], {}, True):
            with self.subTest(schema=schema):
                with self.assertRaises(ProofError):
                    graph_document({"schema": schema})

    def test_malformed_source_records_are_refused_by_graph_api_and_cli(self):
        baseline = build_record(self._spec(), artifact_root=self.root)
        mutations = [("unknowns", value) for value in (None, 1, True, {}, "abc", [1], [{}])]
        mutations.extend(("sequence", value) for value in (True, 1.0))
        mutations.extend(("run_id", value) for value in (None, [], ""))
        mutations.extend((field, value) for field in ("observed", "partial") for value in (None, [], {}))
        mutations.append(("repository", []))
        source = self.root / "malformed.record.json"
        output = self.root / "refused.graph.json"
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                record = copy.deepcopy(baseline)
                if field in {"unknowns", "observed", "partial"}:
                    record["result"][field] = value
                    error = (
                        "result.unknowns must be a list of strings" if field == "unknowns"
                        else f"result.{field} must be boolean"
                    )
                elif field == "sequence":
                    record[field] = value
                    error = "sequence is missing or invalid"
                elif field == "run_id":
                    record[field] = value
                    error = "run_id is missing or malformed"
                else:
                    record[field] = value
                    error = "repository must be an object"
                record["record_sha256"] = record_digest(record)
                with self.assertRaisesRegex(ProofError, error):
                    graph_document(record, artifact_root=self.root)
                write_json(source, record)
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = main([
                        "graph", str(source), "--artifact-root", str(self.root),
                        "--out", str(output),
                    ])
                self.assertEqual(exit_code, 2)
                report = json.loads(stdout.getvalue())
                self.assertEqual(report["schema"], "agent-proof/error/v2")
                self.assertIs(report["ok"], False)
                self.assertIn(error, report["error"])
                self.assertFalse(output.exists())

    def test_graph_builder_refuses_resealed_embedded_run_identity_mismatch(self):
        record = build_record(self._spec(), artifact_root=self.root)
        ledger = append_record(make_ledger("graph-run"), record, artifact_root=self.root)
        run = merge_run(ledger, artifact_root=self.root)
        for document, hash_field, hash_function in (
            (ledger, "ledger_sha256", ledger_digest),
            (run, "run_sha256", run_digest),
        ):
            with self.subTest(schema=document["schema"]):
                malformed = copy.deepcopy(document)
                embedded = malformed["records"][0]
                embedded["run_id"] = "other-run"
                embedded["record_sha256"] = record_digest(embedded)
                if "record_hashes" in malformed:
                    malformed["record_hashes"] = [embedded["record_sha256"]]
                malformed[hash_field] = hash_function(malformed)
                result = verify_document(malformed, artifact_root=self.root)
                self.assertIs(result["ok"], False, result)
                self.assertIn("record 1: run_id differs from ledger", result["errors"])
                with self.assertRaisesRegex(ProofError, "run_id differs from ledger"):
                    graph_document(malformed, artifact_root=self.root)
                path = self.root / "mismatched.json"
                write_json(path, malformed)
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = main(["graph", str(path), "--artifact-root", str(self.root)])
                self.assertEqual(exit_code, 2)
                self.assertIn("run_id differs from ledger", json.loads(stdout.getvalue())["error"])

    def test_empty_ledger_run_identity_is_still_required(self):
        for run_id in (None, "", [], {}):
            with self.subTest(run_id=run_id):
                ledger = make_ledger("graph-run")
                ledger["run_id"] = run_id
                ledger["ledger_sha256"] = ledger_digest(ledger)
                result = verify_document(ledger)
                self.assertIs(result["ok"], False, result)
                self.assertIn("run_id is missing or malformed", result["errors"])

    def test_cli_malformed_graph_returns_one_json_refusal(self):
        malformed = graph_document(self._run(), artifact_root=self.root)
        malformed["unknowns"] = None
        malformed["graph_sha256"] = digest_json({
            key: item for key, item in malformed.items()
            if key != "graph_sha256"
        })
        path = self.root / "malformed.graph.json"
        write_json(path, malformed)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["verify-graph", str(path)])
        self.assertEqual(exit_code, 1)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["schema"], "agent-proof/graph-verify/v1")
        self.assertIs(report["ok"], False)
        self.assertIn("unknowns must be a list of strings", report["errors"])

    def test_invalid_graph_schema_does_not_echo_input_value(self):
        malformed = graph_document(self._run(), artifact_root=self.root)
        malformed["schema"] = "synthetic-sensitive-marker"
        result = verify_graph(malformed)
        self.assertIs(result["ok"], False)
        self.assertNotIn("synthetic-sensitive-marker", json.dumps(result))

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
