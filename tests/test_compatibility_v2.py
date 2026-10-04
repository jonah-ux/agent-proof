"""Pinned declarations, semantic tampering, and version-negotiation regressions."""

import copy
import hashlib
import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from agent_proof import compatibility as contract
from agent_proof import cli


ROOT = Path(__file__).parents[1]
CHARTER = ROOT / "conformance/compatibility-v2.json"
OWNERS = ROOT / "conformance/owners"
CHARTER_DIGEST = "a58483a156facc7cfe321ebad42ec86223276ae5ff5121042b06ab0f9372a46b"


def declaration(field="capabilities", identifier="lifecycle.approval", versions=None):
    value = {
        "schema": contract.CAPABILITY_DECLARATION_SCHEMA,
        "contract_version": 1,
        "capabilities": [],
        "native_protocols": [],
    }
    value[field] = [{"id": identifier, "supported_versions": versions or [1]}]
    return value


class NativeDeclarationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(CHARTER.read_bytes())
        self.sources = {
            entry["owner"]: OWNERS / (entry["owner"] + ".json")
            for entry in self.manifest["participants"]
        }

    def test_reviewed_snapshot_and_every_public_byte_pin(self):
        self.assertEqual(contract.manifest_digest(self.manifest), CHARTER_DIGEST)
        self.assertEqual(len(self.sources), 13)
        for entry in self.manifest["participants"]:
            with self.subTest(owner=entry["owner"]):
                raw = self.sources[entry["owner"]].read_bytes()
                self.assertEqual(
                    hashlib.sha256(raw).hexdigest(),
                    entry["conformance_artifact"]["sha256"],
                )
        report = contract.validate_participant_artifacts(
            CHARTER, self.sources, artifact_root=OWNERS
        )
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["complete"])
        self.assertEqual(report["execution"], "not_attempted")
        self.assertEqual(report["remote_state"], "not_contacted")
        self.assertEqual(len(report["participants"]), 13)
        self.assertTrue(
            all(row["validation"] == "owner-json" for row in report["participants"])
        )
        self.assertTrue(
            all(
                row.get("capability_versions", "not_declared") == "not_declared"
                for row in report["participants"]
            )
        )

    def test_json_declarations_require_source_field_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            charter = Path(temporary) / "charter.json"
            for index, participant in enumerate(self.manifest["participants"]):
                for replacement in ("omitted", None, []):
                    with self.subTest(owner=participant["owner"], value=replacement):
                        manifest = copy.deepcopy(self.manifest)
                        artifact = manifest["participants"][index][
                            "conformance_artifact"
                        ]
                        if replacement == "omitted":
                            del artifact["source_fields"]
                        else:
                            artifact["source_fields"] = replacement
                        errors = contract.validate_manifest_v2(manifest)
                        self.assertIn("source_unbound", {row["code"] for row in errors})
                        charter.write_text(json.dumps(manifest))
                        report = contract.validate_participant_artifacts(
                            charter, self.sources, artifact_root=OWNERS
                        )
                        self.assertFalse(report["ok"], report)
                        self.assertFalse(report["complete"])
                        self.assertEqual(report["participants"], [])
                        self.assertIn(
                            "source_unbound", {row["code"] for row in report["errors"]}
                        )

    def test_rehashed_native_and_capability_mutations_refuse_only_the_changed_owner(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for owner, source in self.sources.items():
                shutil.copyfile(source, directory / (owner + ".json"))
            selected = {owner: directory / (owner + ".json") for owner in self.sources}
            charter = directory / "charter.json"
            for entry in self.manifest["participants"]:
                owner = entry["owner"]
                document = json.loads(self.sources[owner].read_bytes())
                changes = [
                    ("owner", lambda value: value.__setitem__("owner", "wrong-owner")),
                    (
                        "schema",
                        lambda value: value.__setitem__("schema", "wrong-owner/v1"),
                    ),
                ]
                if "repository" in document:
                    changes.append(
                        (
                            "repository",
                            lambda value: value.__setitem__(
                                "repository", "https://github.com/jonah-ux/wrong-owner"
                            ),
                        )
                    )
                for field in ("native_schema", "receipt_schema", "inspect_schema"):
                    if field in document:
                        changes.append(
                            (
                                field,
                                lambda value, field=field: value.__setitem__(
                                    field, "agent-sandbox/v99"
                                ),
                            )
                        )
                for index in range(len(document.get("native_schemas", []))):
                    changes.append(
                        (
                            "native_schemas:" + str(index),
                            lambda value, index=index: value[
                                "native_schemas"
                            ].__setitem__(index, "agent-sandbox/v99"),
                        )
                    )
                for field in ("adapters", "consumer_contracts"):
                    for index in range(len(document.get(field, []))):
                        changes.append(
                            (
                                field + ":" + str(index),
                                lambda value, field=field, index=index: value[field][
                                    index
                                ].__setitem__("schema", "agent-sandbox/v99"),
                            )
                        )
                for index in range(len(document.get("capabilities", []))):
                    changes.append(
                        (
                            "capabilities:" + str(index),
                            lambda value, index=index: value[
                                "capabilities"
                            ].__setitem__(index, "vendor.unknown"),
                        )
                    )
                for capability in document.get("capability_protocols", {}):
                    changes.append(
                        (
                            "mapping:" + capability,
                            lambda value, capability=capability: value[
                                "capability_protocols"
                            ].__setitem__(capability, ["agent-sandbox/v99"]),
                        )
                    )
                for name, change in changes:
                    with self.subTest(owner=owner, field=name):
                        mutated = copy.deepcopy(document)
                        change(mutated)
                        raw = json.dumps(mutated).encode()
                        selected[owner].write_bytes(raw)
                        manifest = copy.deepcopy(self.manifest)
                        target = next(
                            row
                            for row in manifest["participants"]
                            if row["owner"] == owner
                        )
                        target["conformance_artifact"]["sha256"] = hashlib.sha256(
                            raw
                        ).hexdigest()
                        charter.write_text(json.dumps(manifest))
                        self.assertEqual(contract.validate_manifest_v2(manifest), [])
                        report = contract.validate_participant_artifacts(
                            charter, selected, artifact_root=directory
                        )
                        self.assertFalse(report["ok"])
                        states = {
                            row["owner"]: row["state"] for row in report["participants"]
                        }
                        self.assertEqual(states.pop(owner), "refused")
                        self.assertTrue(
                            all(state == "verified" for state in states.values())
                        )
                        self.assertNotIn(
                            "digest_mismatch",
                            {error["code"] for error in report["errors"]},
                        )
                        selected[owner].write_bytes(self.sources[owner].read_bytes())

    def test_registry_native_versions_and_source_provenance_are_enforced(self):
        native = next(
            row
            for row in self.manifest["capability_registry"]["native_protocols"]
            if row["id"] == "agent-sandbox"
        )
        self.assertEqual(native["supported_versions"], [1, 2])
        native["supported_versions"] = [1]
        self.assertIn(
            "unknown_version",
            {error["code"] for error in contract.validate_manifest_v2(self.manifest)},
        )
        manifest = json.loads(CHARTER.read_bytes())
        manifest["participants"][0]["conformance_artifact"]["source_fields"][0][
            "schema"
        ] = "agent-sandbox/v1"
        self.assertIn(
            "source_unbound",
            {error["code"] for error in contract.validate_manifest_v2(manifest)},
        )

    def test_byte_only_manifest_cannot_claim_complete_content(self):
        for entry in self.manifest["participants"]:
            entry["conformance_artifact"].update(
                format="bytes", document_schema=None, owner_contract=None
            )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "charter.json"
            path.write_text(json.dumps(self.manifest))
            report = contract.validate_participant_artifacts(
                path, self.sources, artifact_root=OWNERS
            )
        self.assertFalse(report["ok"])
        self.assertFalse(report["complete"])
        self.assertIn(
            "content_unvalidated", {error["code"] for error in report["errors"]}
        )

    def test_unknown_source_selection_refuses_instead_of_being_ignored(self):
        self.sources["wrong-owner"] = OWNERS / "agent-proof.json"
        result = contract.validate_participant_artifacts(
            CHARTER, self.sources, artifact_root=OWNERS
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"][0]["code"], "source_unbound")

    def test_v2_reports_are_independent_of_the_local_source_root(self):
        first = contract.validate_participant_artifacts(
            CHARTER, self.sources, artifact_root=OWNERS
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            shutil.copyfile(CHARTER, directory / "charter.json")
            for owner, path in self.sources.items():
                shutil.copyfile(path, directory / (owner + ".json"))
            sources = {owner: directory / (owner + ".json") for owner in self.sources}
            second = contract.validate_participant_artifacts(
                directory / "charter.json", sources, artifact_root=directory
            )
        self.assertEqual(first, second)


class VersionNegotiationTests(unittest.TestCase):
    def test_highest_common_native_version_and_disjoint_refusal(self):
        producer = declaration("native_protocols", "agent-sandbox", [1, 2])
        consumer = copy.deepcopy(producer)
        result = contract.negotiate_native_protocols(producer, consumer, producer)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["results"][0]["selected_version"], 2)
        producer["native_protocols"][0]["supported_versions"] = [1]
        consumer["native_protocols"][0]["supported_versions"] = [2]
        result = contract.negotiate_native_protocols(
            producer, consumer, declaration("native_protocols", "agent-sandbox", [1, 2])
        )
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["results"][0]["errors"][0]["code"], "unsupported_version"
        )

    def test_capability_registry_and_every_supplied_peer_constraint(self):
        producer, consumer = declaration(), declaration()
        producer["capability_registry"] = declaration()
        consumer["capability_registry"] = declaration()
        self.assertTrue(contract.negotiate_capabilities(producer, consumer)["ok"])
        consumer["capability_registry"]["capabilities"] = []
        result = contract.negotiate_capabilities(producer, consumer, declaration())
        self.assertFalse(result["ok"])
        self.assertIsNone(result["results"][0]["selected_version"])

    def test_unversioned_names_are_declarations_not_version_support(self):
        registry = declaration()
        registry["capabilities"][0]["supported_versions"] = []
        result = contract.negotiate_capabilities(declaration(), declaration(), registry)
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["results"][0]["errors"][0]["code"], "unsupported_version"
        )

    def test_malformed_and_unknown_declarations_never_select_a_version(self):
        cases = []
        for versions in ([True], [0], [2], [1, 1], [2, 1]):
            peer = declaration()
            peer["capabilities"][0]["supported_versions"] = versions
            cases.append(peer)
        for bad in (None, [], "wrong"):
            cases.append(bad)
        peer = declaration(identifier="vendor/unknown")
        cases.append(peer)
        peer = declaration()
        peer["capabilities"].append(copy.deepcopy(peer["capabilities"][0]))
        cases.append(peer)
        peer = declaration()
        peer["capabilities"][0]["native_protocols"] = [{}]
        cases.append(peer)
        for peer in cases:
            with self.subTest(peer=peer):
                result = contract.negotiate_capabilities(
                    peer, declaration(), declaration()
                )
                self.assertFalse(result["ok"])
                self.assertEqual(result["results"], [])
                self.assertTrue(
                    all(
                        error["code"] in contract.V2_REFUSAL_CODES
                        for error in result["errors"]
                    )
                )
        self.assertFalse(
            contract.negotiate_capability("vendor/unknown", [99], [99])["ok"]
        )
        self.assertFalse(
            contract.negotiate_capability("agent-sandbox", [1, 99], [1])["ok"]
        )


class CompatibilityCLITests(unittest.TestCase):
    def invoke(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                code = cli.main(arguments)
            except SystemExit as failure:
                code = failure.code
        return code, output.getvalue(), errors.getvalue()

    def test_complete_v2_charter_and_native_negotiation_cli(self):
        code, output, errors = self.invoke(
            ["compatibility", "--schema", "v2", "--manifest", str(CHARTER)]
        )
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)["ok"])
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            peer = declaration("native_protocols", "agent-sandbox", [1, 2])
            (directory / "peer.json").write_text(json.dumps(peer))
            code, output, errors = self.invoke(
                [
                    "negotiate",
                    "--kind",
                    "native",
                    "--producer",
                    str(directory / "peer.json"),
                    "--consumer",
                    str(directory / "peer.json"),
                    "--registry",
                    str(directory / "peer.json"),
                ]
            )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["results"][0]["selected_version"], 2)

    def test_invalid_flags_do_not_echo_caller_paths(self):
        for arguments in (
            [
                "compatibility-artifacts",
                "--manifest",
                "/caller/private/charter",
                "--max-bytes",
                "/caller/private/number",
            ],
            [
                "compatibility",
                "--manifest",
                "/caller/private/charter",
                "--unknown",
                "/caller/private/value",
            ],
        ):
            with self.subTest(arguments=arguments):
                code, output, errors = self.invoke(arguments)
                self.assertEqual(code, 2)
                self.assertFalse(json.loads(output)["ok"])
                self.assertNotIn("/caller/private", output + errors)
                self.assertEqual(errors, "")

    def test_malformed_negotiation_json_and_missing_inputs_have_stable_json_refusals(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "private-input.json"
            for raw, expected_code in (
                (b"\xff", "invalid_utf8"),
                (b"[]", "malformed_manifest"),
                (b'{"a":1,"a":2}', "duplicate_json_key"),
            ):
                path.write_bytes(raw)
                code, output, errors = self.invoke(
                    ["negotiate", "--producer", str(path), "--consumer", str(path)]
                )
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output)["errors"][0]["code"], expected_code)
                self.assertNotIn(str(directory), output + errors)
            code, output, errors = self.invoke(
                [
                    "negotiate",
                    "--producer",
                    str(directory / "missing"),
                    "--consumer",
                    str(path),
                ]
            )
            self.assertEqual(code, 2)
            self.assertEqual(
                json.loads(output)["errors"][0]["code"], "manifest_unavailable"
            )
            self.assertNotIn(str(directory), output + errors)


if __name__ == "__main__":
    unittest.main()
