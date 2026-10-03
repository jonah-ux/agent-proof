import json
from pathlib import Path
import tempfile
import unittest

from agent_proof.compatibility import (
    COMPATIBILITY_SCHEMA,
    check_manifest,
    manifest_digest,
    validate_manifest,
)
from agent_proof.interop import ADAPTERS


ROOT = Path(__file__).parents[1]
MANIFEST_PATH = ROOT / "conformance" / "compatibility-v1.json"


class CompatibilityManifestTests(unittest.TestCase):
    def test_declared_adapter_fields_match_the_runtime_registry(self):
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual({item["schema"] for item in payload["adapters"]}, set(ADAPTERS))
        for item in payload["adapters"]:
            with self.subTest(schema=item["schema"]):
                adapter = ADAPTERS[item["schema"]]
                self.assertEqual(item["kind"], adapter["kind"])
                for field in ("identity", "metrics", "digests"):
                    self.assertEqual(item.get(field, []), list(adapter.get(field, ())))

    def test_public_manifest_is_valid_and_digest_is_stable(self):
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], COMPATIBILITY_SCHEMA)
        self.assertEqual(len(payload["adapters"]), 23)
        self.assertEqual(validate_manifest(payload), [])
        report = check_manifest(MANIFEST_PATH)
        self.assertTrue(report["ok"])
        reordered = {key: payload[key] for key in reversed(list(payload))}
        self.assertEqual(manifest_digest(payload), manifest_digest(reordered))

    def test_unknown_version_and_extra_field_fail_closed(self):
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        payload["contract_version"] = 2
        payload["surprise"] = True
        codes = {error["code"] for error in validate_manifest(payload)}
        self.assertIn("unknown_version", codes)
        self.assertIn("malformed_manifest", codes)

    def test_duplicate_refusal_code_is_reported(self):
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        payload["refusal_codes"].append(dict(payload["refusal_codes"][0]))
        codes = {error["code"] for error in validate_manifest(payload)}
        self.assertIn("duplicate_identifier", codes)

    def test_redaction_and_unsafe_boundary_changes_fail_closed(self):
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        payload["redaction"]["raw_payloads"] = True
        payload["participants"][0]["repository"] = "/private/repo"
        codes = {error["code"] for error in validate_manifest(payload)}
        self.assertIn("redaction_violation", codes)
        self.assertIn("malformed_manifest", codes)

    def test_cli_report_is_json_and_nonzero_for_malformed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("[]", encoding="utf-8")
            report = check_manifest(path)
            self.assertFalse(report["ok"])
            self.assertEqual(report["errors"][0]["code"], "malformed_manifest")


if __name__ == "__main__":
    unittest.main()
