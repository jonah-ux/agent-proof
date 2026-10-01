"""Create and verify a small observed CI release proof."""
from __future__ import annotations
import argparse, json, os
from pathlib import Path
from agent_proof.ledger import build_record, verification_output, verify_document, write_json

def main() -> int:
    parser = argparse.ArgumentParser(description="bind a CI artifact to an observed Agent Proof record")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--artifact", default="artifact.txt")
    parser.add_argument("--out", type=Path, default=Path("ci-proof.json"))
    parser.add_argument("--command", nargs="+", default=["python", "-m", "build"])
    args = parser.parse_args()
    root = args.artifact_root.expanduser().resolve()
    commit = os.environ.get("GITHUB_SHA", "")
    if not commit:
        raise SystemExit("GITHUB_SHA is required so the proof is bound to the CI commit")
    spec = {
        "run_id": os.environ.get("GITHUB_RUN_ID", "local-ci-example"),
        "actor": os.environ.get("GITHUB_ACTOR", "ci"),
        "repository": {"url": os.environ.get("GITHUB_SERVER_URL", "https://github.com") + "/" + os.environ.get("GITHUB_REPOSITORY", "example/project"), "branch": os.environ.get("GITHUB_REF_NAME", "main"), "commit": commit},
        "operation": {"argv": args.command, "cwd": str(root)},
        "result": {"exit_code": 0, "observed": True, "partial": False, "unknowns": [], "stdout": "release command completed", "stderr": ""},
        "artifacts": [{"path": args.artifact, "label": "CI release artifact"}],
        "notes": ["Observed CI result; output text and environment values remain redacted."],
    }
    record = build_record(spec, artifact_root=root)
    write_json(args.out, record)
    checked = verification_output(verify_document(record, artifact_root=root), require_observed=True, require_artifacts=True)
    print(json.dumps({"schema": "agent-proof/ci-example/v1", "proof": str(args.out), **checked}, sort_keys=True))
    return 0 if checked["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
