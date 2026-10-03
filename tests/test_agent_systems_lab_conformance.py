import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.interop import normalize_envelope, verify_interop
from agent_proof.ledger import ProofError


def source_payload(schema: str, index: int) -> dict:
    if schema == "sourcemark/check/v1":
        return {
            "schema": schema,
            "state": "ok",
            "counts": {
                "total": 1,
                "passing": 1,
                "failing": 0,
                "unknown": 0,
                "observations": 1,
                "timed_out": 0,
            },
            "policy_sha256": "sha256:" + "a" * 64,
            "session_sha256": "sha256:" + "b" * 64,
        }
    payload = {
        "schema": schema,
        "run_id": f"synthetic-run-{index}",
        "ok": True,
        "observed": True,
        "partial": False,
        "timed_out": False,
        "exit_code": 0,
    }
    identity = {
        "agent-policy/v1": {"policy_id": f"policy-{index}"},
        "agent-sandbox/v1": {"receipt_id": f"receipt-{index}"},
        "agent-eval/v1": {"evaluation_id": f"eval-{index}", "candidate_id": f"candidate-{index}", "duration_ms": 5, "item_count": 1, "trial_count": 1},
        "agent-trace/v1": {"trace_id": f"trace-{index}", "duration_ms": 5, "event_count": 1, "span_count": 1},
        "context-pack/v1": {"pack_id": f"pack-{index}", "source_count": 1, "file_count": 1, "byte_count": 10},
        "agent-resume/v1": {"resume_id": f"resume-{index}", "checkpoint_id": f"checkpoint-{index}", "duration_ms": 5, "step_count": 1},
        "context-integrity/v1": {"person_id": "private-person", "project_id": "private-project", "citation_count": 1},
    }[schema]
    payload.update(identity)
    payload["answer"] = "private answer must not cross the boundary"
    return payload


class AgentSystemsLabConformanceTests(unittest.TestCase):
    def test_public_manifest_matches_all_reviewed_adapters(self):
        manifest = json.loads((Path(__file__).parents[1] / "conformance" / "agent-systems-lab.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "agent-proof-lab-conformance/v1")
        self.assertEqual({item["schema"] for item in manifest["adapters"]}, {
            "agent-policy/v1", "agent-sandbox/v1", "agent-eval/v1", "agent-trace/v1", "context-pack/v1", "agent-resume/v1", "context-integrity/v1", "sourcemark/check/v1"
        })

    def test_every_manifest_adapter_normalizes_without_leaking_private_values(self):
        manifest = json.loads((Path(__file__).parents[1] / "conformance" / "agent-systems-lab.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, item in enumerate(manifest["adapters"], start=1):
                source = root / f"source-{index}.json"
                source.write_text(json.dumps(source_payload(item["schema"], index)), encoding="utf-8")
                normalized = normalize_envelope(source, artifact_root=root)
                self.assertEqual(normalized["adapter"]["kind"], item["kind"])
                self.assertNotIn("private answer", json.dumps(normalized))
                self.assertTrue(verify_interop(normalized, artifact_root=root, require_input=True)["ok"])

    def test_unknown_schema_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "unknown.json"
            source.write_text(json.dumps({"schema": "unknown/v1", "ok": True}), encoding="utf-8")
            with self.assertRaises(ProofError):
                normalize_envelope(source, artifact_root=root)
