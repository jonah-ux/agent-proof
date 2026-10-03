"""Validation for the Agent Systems Lab compatibility charter.

The compatibility manifest is deliberately data-only.  Agent Proof owns this
checker because it already owns the reviewed adapter registry, while each
specialist repository remains authoritative for its native schema and refusal
semantics.  The checker validates the charter itself; it does not fetch sibling
repositories or reinterpret their native payloads.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


COMPATIBILITY_SCHEMA = "agent-systems-lab/compatibility/v1"
SUPPORTED_CONTRACT_VERSION = 1
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_IDENTIFIER = re.compile(IDENTIFIER_PATTERN)
_REFUSAL_CODE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

STATUS_VOCABULARY = (
    "blocked",
    "failed",
    "observed",
    "partial",
    "unknown",
    "unavailable",
    "verified",
)

REQUIRED_REFUSAL_CODES = {
    "digest_mismatch",
    "duplicate_identifier",
    "malformed_manifest",
    "redaction_violation",
    "source_unbound",
    "stale_source_identity",
    "unsafe_path",
    "unknown_version",
    "unsupported_schema",
    "unsupported_status",
}

_TOP_LEVEL_FIELDS = {
    "schema",
    "contract_version",
    "authority",
    "repository",
    "canonicalization",
    "identifiers",
    "statuses",
    "refusal_codes",
    "redaction",
    "owner_codes",
    "participants",
    "adapters",
}


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Return the charter's deterministic JSON representation."""

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def manifest_digest(payload: dict[str, Any]) -> str:
    """Return the SHA-256 digest of a manifest without adding a self-hash."""

    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    """Read a JSON object from *path* and reject non-object roots."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed compatibility manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("malformed compatibility manifest: root must be an object")
    return payload


def _error(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def validate_manifest(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Return stable, machine-readable charter violations.

    The returned list is sorted by refusal code and detail so a caller can
    compare reports across runtimes.  Native owner codes remain in their own
    repositories; this list only covers cross-repository charter failures.
    """

    errors: list[dict[str, str]] = []
    unknown = sorted(set(payload) - _TOP_LEVEL_FIELDS)
    if unknown:
        errors.append(_error("malformed_manifest", f"unknown top-level fields: {', '.join(unknown)}"))

    if payload.get("schema") != COMPATIBILITY_SCHEMA:
        errors.append(_error("unsupported_schema", "schema must be agent-systems-lab/compatibility/v1"))
    if payload.get("contract_version") != SUPPORTED_CONTRACT_VERSION:
        errors.append(_error("unknown_version", "contract_version must be 1"))

    authority = payload.get("authority")
    if not isinstance(authority, str) or not _IDENTIFIER.fullmatch(authority):
        errors.append(_error("malformed_manifest", "authority must be a bounded identifier"))
    repository = payload.get("repository")
    if not isinstance(repository, str) or not repository.startswith("https://"):
        errors.append(_error("malformed_manifest", "repository must be an HTTPS URL"))

    canonicalization = payload.get("canonicalization")
    if canonicalization != {
        "encoding": "utf-8",
        "json": "sorted-keys-compact",
        "allow_nan": False,
    }:
        errors.append(_error("malformed_manifest", "canonicalization does not match the charter"))

    identifiers = payload.get("identifiers")
    if identifiers != {"pattern": IDENTIFIER_PATTERN, "max_length": 128}:
        errors.append(_error("malformed_manifest", "identifiers does not match the charter"))

    statuses = payload.get("statuses")
    if statuses != list(STATUS_VOCABULARY):
        errors.append(_error("unsupported_status", "statuses must equal the ordered charter vocabulary"))

    redaction = payload.get("redaction")
    expected_redaction = {
        "raw_payloads": False,
        "secrets": False,
        "private_paths": False,
        "provider_credentials": False,
    }
    if redaction != expected_redaction:
        errors.append(_error("redaction_violation", "redaction must deny raw payloads, secrets, private paths, and provider credentials"))

    if payload.get("owner_codes") != {
        "mode": "preserve-verbatim",
        "fields": ["owner_status", "owner_code"],
        "unknown_policy": "do-not-infer",
    }:
        errors.append(_error("malformed_manifest", "owner_codes must preserve native status and code fields verbatim"))

    refusal_codes = payload.get("refusal_codes")
    seen_codes: set[str] = set()
    if not isinstance(refusal_codes, list):
        errors.append(_error("malformed_manifest", "refusal_codes must be a list"))
    else:
        actual_codes: set[str] = set()
        for entry in refusal_codes:
            if not isinstance(entry, dict) or set(entry) != {"code", "class", "meaning"}:
                errors.append(_error("malformed_manifest", "each refusal code must contain code, class, and meaning"))
                continue
            code = entry.get("code")
            if not isinstance(code, str) or not _REFUSAL_CODE.fullmatch(code):
                errors.append(_error("malformed_manifest", "refusal code has an invalid format"))
                continue
            if code in seen_codes:
                errors.append(_error("duplicate_identifier", f"duplicate refusal code: {code}"))
            seen_codes.add(code)
            actual_codes.add(code)
            if not isinstance(entry.get("class"), str) or not _IDENTIFIER.fullmatch(entry["class"]):
                errors.append(_error("malformed_manifest", f"refusal class is invalid for {code}"))
            if not isinstance(entry.get("meaning"), str) or not entry["meaning"].strip():
                errors.append(_error("malformed_manifest", f"refusal meaning is empty for {code}"))
        if refusal_codes != sorted(refusal_codes, key=lambda item: item.get("code", "") if isinstance(item, dict) else ""):
            errors.append(_error("malformed_manifest", "refusal_codes must be sorted by code"))
        missing_codes = sorted(REQUIRED_REFUSAL_CODES - actual_codes)
        if missing_codes:
            errors.append(_error("malformed_manifest", f"required refusal codes are missing: {', '.join(missing_codes)}"))

    participants = payload.get("participants")
    if not isinstance(participants, list) or not participants:
        errors.append(_error("malformed_manifest", "participants must be a non-empty list"))
    else:
        participant_ids: set[str] = set()
        for entry in participants:
            required = {"owner", "repository", "native_schemas", "conformance_artifact"}
            if not isinstance(entry, dict) or set(entry) != required:
                errors.append(_error("malformed_manifest", "each participant must contain owner, repository, native_schemas, and conformance_artifact"))
                continue
            owner = entry.get("owner")
            if not isinstance(owner, str) or not _IDENTIFIER.fullmatch(owner):
                errors.append(_error("malformed_manifest", "participant owner is invalid"))
            elif owner in participant_ids:
                errors.append(_error("duplicate_identifier", f"duplicate participant owner: {owner}"))
            else:
                participant_ids.add(owner)
            if not isinstance(entry.get("repository"), str) or not entry["repository"].startswith("https://"):
                errors.append(_error("malformed_manifest", f"participant repository is invalid for {owner}"))
            schemas = entry.get("native_schemas")
            if not isinstance(schemas, list) or not schemas or any(not isinstance(schema, str) or not _IDENTIFIER.fullmatch(schema.replace("/", "_")) for schema in schemas):
                errors.append(_error("malformed_manifest", f"native_schemas is invalid for {owner}"))
            artifact = entry.get("conformance_artifact")
            if not isinstance(artifact, dict) or set(artifact) != {"url", "revision", "sha256"}:
                errors.append(_error("malformed_manifest", f"conformance_artifact is invalid for {owner}"))
            elif (
                not isinstance(artifact["url"], str)
                or not artifact["url"].startswith("https://")
                or not isinstance(artifact["revision"], str)
                or not re.fullmatch(r"[0-9a-f]{40}", artifact["revision"])
                or artifact["revision"] not in artifact["url"]
                or not isinstance(artifact["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
            ):
                errors.append(_error("stale_source_identity", f"conformance_artifact must use an immutable revision and SHA-256 for {owner}"))
        if participants != sorted(participants, key=lambda item: item.get("owner", "") if isinstance(item, dict) else ""):
            errors.append(_error("malformed_manifest", "participants must be sorted by owner"))

    adapters = payload.get("adapters")
    if not isinstance(adapters, list) or not adapters:
        errors.append(_error("malformed_manifest", "adapters must be a non-empty list"))
    else:
        adapter_ids: set[str] = set()
        for entry in adapters:
            required = {"schema", "kind", "identity", "metrics", "source"}
            if not isinstance(entry, dict) or set(entry) != required:
                errors.append(_error("malformed_manifest", "each adapter must contain schema, kind, identity, metrics, and source"))
                continue
            schema = entry.get("schema")
            if not isinstance(schema, str) or not schema or schema in adapter_ids:
                errors.append(_error("duplicate_identifier" if schema in adapter_ids else "malformed_manifest", f"adapter schema is invalid or duplicated: {schema}"))
            else:
                adapter_ids.add(schema)
            if not isinstance(entry.get("kind"), str) or not _IDENTIFIER.fullmatch(entry["kind"]):
                errors.append(_error("malformed_manifest", f"adapter kind is invalid for {schema}"))
            for field in ("identity", "metrics"):
                values = entry.get(field)
                if not isinstance(values, list) or any(not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) for value in values):
                    errors.append(_error("malformed_manifest", f"adapter {field} is invalid for {schema}"))
            if entry.get("source") != "src/agent_proof/interop.py:ADAPTERS":
                errors.append(_error("malformed_manifest", f"adapter source is not the reviewed registry for {schema}"))
        if adapters != sorted(adapters, key=lambda item: item.get("schema", "") if isinstance(item, dict) else ""):
            errors.append(_error("malformed_manifest", "adapters must be sorted by schema"))

    return sorted(errors, key=lambda item: (item["code"], item["detail"]))


def check_manifest(path: Path) -> dict[str, Any]:
    """Return a deterministic checker report for a manifest path."""

    try:
        payload = load_manifest(path)
        errors = validate_manifest(payload)
        digest = manifest_digest(payload)
    except ValueError as exc:
        payload = None
        errors = [_error("malformed_manifest", str(exc))]
        digest = None
    return {
        "schema": "agent-systems-lab/compatibility-check/v1",
        "manifest": str(path),
        "manifest_sha256": digest,
        "ok": not errors,
        "errors": errors,
    }
