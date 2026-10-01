"""Run a synthetic policy -> sandbox -> evaluation -> proof workflow."""

from __future__ import annotations

import json
import io
from pathlib import Path
import shutil
import tarfile
import tempfile

from agent_proof.ledger import (
    append_record,
    build_record,
    export_bundle,
    make_ledger,
    merge_run,
    render_markdown,
    verification_output,
    verify_bundle,
    verify_document,
    write_json,
)
from agent_proof.graph import graph_document, verify_graph


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="agent-proof-demo-") as directory:
        root = Path(directory) / "fixtures"
        root.mkdir()
        sources = root / "sources"
        sources.mkdir()
        artifact = root / "result.txt"
        artifact.write_text("synthetic result: policy allowed, command completed\n", encoding="utf-8")

        write_json(
            sources / "policy.json",
            {"schema": "agent-policy/v1", "decision": "allow", "allowed": True, "reason": "fixture rule"},
        )
        write_json(
            sources / "sandbox.json",
            {"schema": "agent-sandbox/v1", "ok": True, "backend": "fallback", "enforced": False, "exit_code": 0},
        )
        write_json(
            sources / "eval.json",
            {"schema": "agent-eval/v1", "ok": True, "exit_code": 0, "expected_exit": 0},
        )
        spec = {
            "run_id": "demo-run",
            "actor": "synthetic-fixture",
            "recorded_at": "2026-10-01T00:00:00Z",
            "repository": {"url": "https://example.invalid/demo", "branch": "main", "commit": "0123456789abcdef0123456789abcdef01234567"},
            "operation": {"argv": ["printf", "synthetic"], "cwd": "/tmp/agent-proof-demo", "environment": {"MODE": "demo"}},
            "result": {"exit_code": 0, "duration_ms": 3, "stdout": "synthetic", "stderr": "", "observed": True},
            "sources": ["sources/policy.json", "sources/sandbox.json", "sources/eval.json"],
            "artifacts": [{"path": "result.txt", "label": "command result"}],
            "notes": ["All inputs are synthetic; no local transcript or credential is read."],
        }
        first = build_record(spec, artifact_root=root)
        second_spec = dict(spec)
        second_spec["sequence"] = 1
        second_spec["operation"] = {"argv": ["agent-eval", "fixture.json"], "cwd": spec["operation"]["cwd"], "environment": {"MODE": "demo"}}
        second_spec["result"] = {"exit_code": 0, "duration_ms": 4, "stdout": "score=1.0", "stderr": "", "observed": True}
        second = build_record(second_spec, artifact_root=root)

        ledger = make_ledger("demo-run")
        ledger = append_record(ledger, first, artifact_root=root)
        ledger = append_record(ledger, second, artifact_root=root)
        run = merge_run(ledger, artifact_root=root)
        before = verify_document(run, artifact_root=root)

        original = artifact.read_text(encoding="utf-8")
        artifact.write_text("tampered\n", encoding="utf-8")
        tampered = verify_document(run, artifact_root=root)
        artifact.write_text(original, encoding="utf-8")
        after = verify_document(run, artifact_root=root)
        graph = graph_document(run, artifact_root=root, require_observed=True, require_artifacts=True)
        graph_bound = verify_graph(
            graph,
            document=run,
            artifact_root=root,
            require_input=True,
            require_observed=True,
            require_artifacts=True,
        )
        bundle_path = Path(directory) / "agent-proof-demo.tar.gz"
        bundle = export_bundle(run, after, bundle_path, artifact_root=root)
        shutil.rmtree(root)
        bundle_verified = verify_bundle(bundle_path, require_observed=True, require_artifacts=True)
        tampered_bundle_path = Path(directory) / "agent-proof-demo-tampered.tar.gz"
        with tarfile.open(bundle_path, "r:gz") as archive, tarfile.open(tampered_bundle_path, "w:gz") as tampered_archive:
            for member in archive.getmembers():
                payload = archive.extractfile(member).read() if member.isfile() else None
                if member.name.startswith("artifacts/"):
                    payload = b"tampered artifact\n"
                if payload is None:
                    tampered_archive.addfile(member)
                else:
                    member.size = len(payload)
                    tampered_archive.addfile(member, io.BytesIO(payload))
        bundle_tampered = verify_bundle(tampered_bundle_path)
        graph_unbound = verify_graph(graph)
        graph_tampered = dict(graph)
        graph_tampered["run_id"] = "tampered"
        graph_tampered_result = verify_graph(graph_tampered)

        output = {
            "schema": "agent-proof/demo/v2",
            "ok": before["ok"] and after["ok"] and not tampered["ok"] and bundle_verified["ok"] and not bundle_tampered["ok"],
            "record_count": after["record_count"],
            "observed": after["observed"],
            "verified": after["ok"],
            "tamper_refused": not tampered["ok"],
            "bundle_verified": bundle_verified["ok"],
            "bundle_tamper_refused": not bundle_tampered["ok"],
            "graph_verified": graph_bound["ok"],
            "graph_unbound_verified": graph_unbound["ok"],
            "graph_tamper_refused": not graph_tampered_result["ok"],
            "graph_node_count": graph["node_count"],
            "graph_edge_count": graph["edge_count"],
            "bundle_sha256": bundle["sha256"],
            "markdown_preview": render_markdown(run, verification_output(after)).splitlines()[:6],
        }
        print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
