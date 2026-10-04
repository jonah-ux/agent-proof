#!/usr/bin/env python3
"""Exercise compatibility through an installed CLI outside its source checkout."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
from importlib.metadata import version

import agent_proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    expected = tomllib.loads((root / "pyproject.toml").read_text())["project"][
        "version"
    ]
    module = Path(agent_proof.__file__).resolve()
    assert module.is_relative_to(Path(sys.prefix).resolve()), (
        "module is not installed in this environment"
    )
    assert agent_proof.__version__ == version("agent_proof") == expected, (
        "package version mismatch"
    )
    assert not Path.cwd().resolve().is_relative_to(root), (
        "run this check outside the source checkout"
    )
    entrypoint = Path(sys.prefix) / "bin/agent-proof"
    assert entrypoint.is_file(), "installed console entry point is unavailable"

    def invoke(arguments, expected_exit=0):
        result = subprocess.run(
            [str(entrypoint), *arguments],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == expected_exit, "installed CLI exit mismatch"
        return json.loads(result.stdout)

    v1_path = root / "conformance/compatibility-v1.json"
    v2_path = root / "conformance/compatibility-v2.json"
    owners = root / "conformance/owners"
    charter = json.loads(v2_path.read_bytes())
    v1 = invoke(["compatibility", "--manifest", str(v1_path)])
    v2 = invoke(["compatibility", "--schema", "v2", "--manifest", str(v2_path)])
    assert v1["ok"] and v2["ok"], "charter refusal"
    assert "manifest" in v1, "historical v1 report field is absent"
    assert (
        v1["manifest_sha256"]
        == charter["compatibility_v1_reference"]["manifest_sha256"]
    )
    arguments = [
        "compatibility-artifacts",
        "--manifest",
        str(v2_path),
        "--artifact-root",
        str(owners),
    ]
    for participant in charter["participants"]:
        owner = participant["owner"]
        arguments.extend(["--source", owner + "=" + owner + ".json"])
    content = invoke(arguments)
    assert content["ok"] and content["complete"], "participant content refusal"
    assert len(content["participants"]) == 13
    assert all(row["validation"] == "owner-json" for row in content["participants"])
    assert (
        content["execution"] == "not_attempted"
        and content["remote_state"] == "not_contacted"
    )

    with tempfile.TemporaryDirectory(prefix="installed-compatibility-") as temporary:
        directory = Path(temporary)

        def peer_for(owner):
            participant = next(
                row for row in charter["participants"] if row["owner"] == owner
            )
            versions = sorted(
                {
                    int(schema.rpartition("/v")[2])
                    for schema in participant["native_schemas"]
                    if schema.rpartition("/v")[0] == "agent-sandbox"
                }
            )
            return {
                "schema": "agent-systems-lab/capabilities/v1",
                "contract_version": 1,
                "capabilities": [],
                "native_protocols": [
                    {"id": "agent-sandbox", "supported_versions": versions}
                ],
            }

        producer, consumer = peer_for("agent-sandbox-run"), peer_for("agent-proof")
        for name, value in (
            ("producer", producer),
            ("consumer", consumer),
            ("registry", charter["capability_registry"]),
        ):
            (directory / (name + ".json")).write_text(json.dumps(value))
        negotiate = [
            "negotiate",
            "--kind",
            "native",
            "--producer",
            str(directory / "producer.json"),
            "--consumer",
            str(directory / "consumer.json"),
            "--registry",
            str(directory / "registry.json"),
        ]
        native = invoke(negotiate)
        assert native["ok"] and native["results"][0]["selected_version"] == 2
        consumer["native_protocols"][0]["supported_versions"] = [1]
        (directory / "consumer.json").write_text(json.dumps(consumer))
        refusal = invoke(negotiate, 2)
        assert not refusal["ok"] and refusal["results"][0]["selected_version"] is None
        assert refusal["results"][0]["errors"][0]["code"] == "unsupported_version"

    print(
        json.dumps(
            {
                "schema": "agent-proof/installed-compatibility/v1",
                "ok": True,
                "version": expected,
                "module_from_environment": True,
                "console_entrypoint": True,
                "v1_manifest_sha256": v1["manifest_sha256"],
                "v2_manifest_sha256": v2["manifest_sha256"],
                "content_validated_owners": len(content["participants"]),
                "native_selected_version": 2,
                "disjoint_native_refused": True,
                "execution": "not_attempted",
                "scope": "installed declaration validation and negotiation; no sibling runtime invocation",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
