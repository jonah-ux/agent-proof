import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.interop import normalize_envelope, verify_interop


class NativeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_sandbox_v2_preserves_receipt_digests_without_paths_or_output(self):
        source = self._write(
            "sandbox.json",
            {
                "schema": "agent-sandbox/v2",
                "version": 2,
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
                "version": 1,
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
