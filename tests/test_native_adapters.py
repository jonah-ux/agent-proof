import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_proof.interop import normalize_envelope, normalize_payload, verify_interop
from agent_proof.ledger import digest_bytes, digest_json


class NativeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _fixture(self, name: str) -> dict:
        corpus = Path(__file__).parents[1] / "conformance" / "native-receipts.json"
        return json.loads(corpus.read_text(encoding="utf-8"))["payloads"][name]

    def test_producer_derived_native_receipts_are_source_bound(self):
        for name in ("sandbox", "mcp", "trace_inspect", "trace_query", "worktree"):
            with self.subTest(producer=name):
                payload = self._fixture(name)
                source = self._write(f"native-{name}.json", payload)
                normalized = normalize_envelope(source, artifact_root=self.root)
                result = verify_interop(normalized, artifact_root=self.root, require_input=True)
                self.assertIs(result["ok"], True, result)
                self.assertEqual(result["source_state"], "verified")
                self.assertIsNone(normalized["projection"]["status"]["observed"])
                self.assertIn("observed_not_declared", normalized["unknowns"])

    def test_native_integer_limits_accept_boundary_and_omit_overflow(self):
        for schema, field in (("agent-sandbox/v2", "duration_ms"),
                              ("agent-trace/inspect/v1", "events"),
                              ("agent-trace/query/v1", "matched")):
            for value in (9007199254740991, 9007199254740992, 10 ** 1000, -1, True):
                with self.subTest(schema=schema, value=value):
                    source = self._write("counter.json", {"schema": schema, field: value})
                    normalized = normalize_envelope(source, artifact_root=self.root)
                    if type(value) is int and 0 <= value <= 9007199254740991:
                        self.assertEqual(normalized["projection"]["metrics"][field], value)
                    else:
                        self.assertNotIn(field, normalized["projection"]["metrics"])
                        self.assertIn(f"{field}_malformed", normalized["unknowns"])

    def test_unbound_verifier_refuses_resealed_native_metric_overflow(self):
        source = self._write("counter.json", {"schema": "agent-trace/query/v1", "matched": 1})
        normalized = normalize_envelope(source, artifact_root=self.root)
        normalized["projection"]["metrics"]["matched"] = 9007199254740992
        normalized["interop_sha256"] = digest_json({k: v for k, v in normalized.items() if k != "interop_sha256"})
        result = verify_interop(normalized)
        self.assertIs(result["ok"], False)
        self.assertIn("projection.metrics is malformed", result["errors"])

    def test_legacy_metric_range_is_preserved(self):
        source = self._write("legacy.json", {"schema": "agent-trace/v1", "event_count": 9007199254740992})
        normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(normalized["projection"]["metrics"]["event_count"], 9007199254740992)
        self.assertIs(verify_interop(normalized, artifact_root=self.root, require_input=True)["ok"], True)

    def test_native_sandbox_preserves_signed_signal_exit_without_inferring_observation(self):
        payload = self._fixture("sandbox")
        payload.update(ok=False, exit_code=-15)
        source = self._write("signal.json", payload)
        normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(normalized["projection"]["status"]["exit_code"], -15)
        self.assertEqual(normalized["projection"]["status"]["outcome"], "failure")
        self.assertIsNone(normalized["projection"]["status"]["observed"])
        self.assertIs(verify_interop(normalized, artifact_root=self.root, require_input=True)["ok"], True)

    def test_mcp_fingerprint_requires_a_declared_sha256_digest(self):
        for value in (self._fixture("mcp")["fingerprint"], "x" * 65, "0" * 63, "A" * 64, 1, None):
            with self.subTest(fingerprint=value):
                source = self._write("mcp.json", {"schema": "mcp-doctor/v1", "fingerprint": value})
                normalized = normalize_envelope(source, artifact_root=self.root)
                self.assertEqual(normalized["projection"]["identity"], {})
                if value == self._fixture("mcp")["fingerprint"]:
                    self.assertEqual(normalized["projection"]["digests"], {"fingerprint": value})
                else:
                    self.assertEqual(normalized["projection"]["digests"], {})
                    self.assertIn("fingerprint_malformed", normalized["unknowns"])

    def test_relative_source_name_is_retained_while_owner_payload_paths_are_omitted(self):
        payload = self._fixture("sandbox")
        source = self._write("neutral-source.json", payload)
        normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(normalized["source"]["path"], "neutral-source.json")
        encoded = json.dumps(normalized, sort_keys=True)
        for field in ("root", "cwd", "stdout", "command"):
            self.assertNotIn(json.dumps(payload[field]), encoded)

    def test_normalization_binds_projection_and_digest_to_one_capture(self):
        original = {"schema": "agent-sandbox/v2", "ok": True, "exit_code": 0}
        replacement = {**original, "exit_code": 1}
        source = self._write("changing.json", original)
        original_bytes = source.read_bytes()
        read_bytes = Path.read_bytes
        read_text = Path.read_text
        reads = []
        replaced = False

        def replace_once(path):
            nonlocal replaced
            if path == source and not replaced:
                source.write_text(json.dumps(replacement), encoding="utf-8")
                replaced = True

        def replace_after_capture(path):
            raw = read_bytes(path)
            if path == source:
                reads.append(raw)
            replace_once(path)
            return raw

        def replace_after_text_read(path, *args, **kwargs):
            text = read_text(path, *args, **kwargs)
            replace_once(path)
            return text

        with patch.object(Path, "read_bytes", replace_after_capture), patch.object(Path, "read_text", replace_after_text_read):
            normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(len(reads), 1)
        self.assertEqual(normalized["source"]["size"], len(original_bytes))
        self.assertEqual(normalized["source"]["sha256"], digest_bytes(original_bytes))
        self.assertEqual(normalized["projection"]["status"]["exit_code"], 0)
        self.assertIs(verify_interop(normalized, artifact_root=self.root, require_input=True)["ok"], False)

    def test_bound_verification_refuses_a_projection_digest_hybrid(self):
        original = {"schema": "agent-sandbox/v2", "ok": True, "exit_code": 0}
        replacement = {**original, "exit_code": 1}
        source = self._write("changing.json", original)
        replacement_bytes = json.dumps(replacement).encode("utf-8")
        hybrid = normalize_payload(original, source_path=source.name,
                                   source_size=len(replacement_bytes),
                                   source_sha256=digest_bytes(replacement_bytes))
        read_text = Path.read_text
        read_bytes = Path.read_bytes
        replaced = False
        byte_reads = []

        def replace_once(path):
            nonlocal replaced
            if path == source and not replaced:
                source.write_bytes(replacement_bytes)
                replaced = True

        def replace_after_text_read(path, *args, **kwargs):
            text = read_text(path, *args, **kwargs)
            replace_once(path)
            return text

        def replace_after_byte_read(path):
            raw = read_bytes(path)
            if path == source:
                byte_reads.append(raw)
            replace_once(path)
            return raw

        with patch.object(Path, "read_text", replace_after_text_read), patch.object(Path, "read_bytes", replace_after_byte_read):
            result = verify_interop(hybrid, artifact_root=self.root, require_input=True)
        self.assertIs(replaced, True)
        self.assertEqual(len(byte_reads), 1)
        self.assertIs(result["ok"], False)
        self.assertEqual(result["source_state"], "invalid")

    def test_sandbox_v2_preserves_receipt_digests_without_paths_or_output(self):
        source = self._write(
            "sandbox.json",
            {
                "schema": "agent-sandbox/v2",
                "version": "0.2.0",
                "ok": True,
                "exit_code": 0,
                "backend": "fallback",
                "enforced": False,
                "timed_out": False,
                "duration_ms": 4,
                "command": ["printf", "synthetic"],
                "command_sha256": "a" * 64,
                "cwd": "/private/worktree",
                "root": "/private/root",
                "stdout": "private output",
                "stderr": "",
                "stdout_sha256": "b" * 64,
                "stderr_sha256": "c" * 64,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "receipt_sha256": "d" * 64,
            },
        )
        normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertEqual(normalized["adapter"]["kind"], "sandbox")
        self.assertEqual(normalized["projection"]["metrics"], {"duration_ms": 4})
        self.assertEqual(set(normalized["projection"]["digests"]), {"command_sha256", "stdout_sha256", "stderr_sha256", "receipt_sha256"})
        encoded = json.dumps(normalized, sort_keys=True)
        self.assertNotIn("private output", encoded)
        self.assertNotIn("/private/worktree", encoded)
        self.assertNotIn("/private/root", encoded)
        self.assertNotIn(json.dumps(["printf", "synthetic"]), encoded)
        self.assertTrue(verify_interop(normalized, artifact_root=self.root, require_input=True)["ok"])

    def test_trace_inspect_and_query_keep_integrity_metadata_bounded(self):
        inspect = self._write(
            "inspect.json",
            {
                "schema": "agent-trace/inspect/v1",
                "events": 2,
                "source_lines": 2,
                "blank_lines": 0,
                "redactions": 1,
                "types": {"tool": 2},
                "raw_sha256": "e" * 64,
                "redacted_sha256": "f" * 64,
            },
        )
        query = self._write(
            "query.json",
            {
                "schema": "agent-trace/query/v1",
                "matched": 1,
                "events": [{"type": "tool", "authorization": "private-token"}],
            },
        )
        inspect_projection = normalize_envelope(inspect, artifact_root=self.root)["projection"]
        query_normalized = normalize_envelope(query, artifact_root=self.root)
        self.assertEqual(inspect_projection["metrics"], {"blank_lines": 0, "events": 2, "redactions": 1, "source_lines": 2})
        self.assertEqual(set(inspect_projection["digests"]), {"raw_sha256", "redacted_sha256"})
        self.assertNotIn("private-token", json.dumps(query_normalized))
        self.assertNotIn("events", query_normalized["projection"])

    def test_mcp_and_worktree_results_keep_owner_output_out_of_projection(self):
        mcp = self._write(
            "mcp.json",
            {
                "schema": "mcp-doctor/v1",
                "version": "0.3.0",
                "strict": False,
                "ok": True,
                "findings": [{"code": "MCP003", "message": "private detail"}],
                "counts": {"tools": 1},
                "fingerprint": "1" * 64,
                "baseline": None,
            },
        )
        worktree = self._write(
            "worktree.json",
            {
                "schema": "worktree-conservator.result/v1",
                "command": "scan",
                "ok": True,
                "data": {"private_path": "/private/repo"},
                "warnings": [],
                "errors": [],
            },
        )
        mcp_normalized = normalize_envelope(mcp, artifact_root=self.root)
        worktree_normalized = normalize_envelope(worktree, artifact_root=self.root)
        self.assertEqual(mcp_normalized["adapter"]["kind"], "mcp-diagnostics")
        self.assertEqual(worktree_normalized["adapter"]["kind"], "worktree")
        self.assertNotIn("private detail", json.dumps(mcp_normalized))
        self.assertNotIn("/private/repo", json.dumps(worktree_normalized))

    def test_native_adapter_malformed_digest_stays_explicitly_unknown(self):
        source = self._write(
            "inspect-bad.json",
            {
                "schema": "agent-trace/inspect/v1",
                "events": 1,
                "raw_sha256": "not-a-digest",
                "redacted_sha256": "0" * 64,
            },
        )
        normalized = normalize_envelope(source, artifact_root=self.root)
        self.assertIn("raw_sha256_malformed", normalized["unknowns"])
        self.assertNotIn("raw_sha256", normalized["projection"].get("digests", {}))


if __name__ == "__main__":
    unittest.main()
