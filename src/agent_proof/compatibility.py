"""Validation for the Agent Systems Lab compatibility charter.

The compatibility manifest is deliberately data-only.  Agent Proof owns this
checker because it already owns the reviewed adapter registry, while each
specialist repository remains authoritative for its native schema and refusal
semantics.  The checker validates the charter itself; it does not fetch sibling
repositories or reinterpret their native payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import stat
from typing import Any, Mapping
from urllib.parse import urlsplit


COMPATIBILITY_SCHEMA = "agent-systems-lab/compatibility/v1"
SUPPORTED_CONTRACT_VERSION = 1
COMPATIBILITY_V2_SCHEMA = "agent-systems-lab/compatibility/v2"
SUPPORTED_CONTRACT_VERSION_V2 = 2
ARTIFACT_REPORT_SCHEMA = "agent-systems-lab/compatibility-artifacts/v1"
NEGOTIATION_REPORT_SCHEMA = "agent-systems-lab/negotiation/v1"
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_IDENTIFIER = re.compile(IDENTIFIER_PATTERN)
_REFUSAL_CODE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
CAPABILITY_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,63}(?:/[a-z0-9][a-z0-9._-]{0,63})+$"
_CAPABILITY_IDENTIFIER = re.compile(CAPABILITY_IDENTIFIER_PATTERN)
_GITHUB_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# The registry is deliberately limited to protocols owned by this package.
# Native sibling capabilities are accepted only when a v2 manifest explicitly
# declares them in its own registry; this module never guesses them from a
# package version, deployment, or native schema name.
BUILTIN_CAPABILITY_VERSIONS = {
    "agent-systems-lab/compatibility-artifacts": (1,),
    "agent-systems-lab/native-protocol-negotiation": (1,),
}

TIMESTAMP_RULES = {
    "authority": "native-producer",
    "format": "rfc3339",
    "rewrite": "forbidden",
    "observation_inference": "forbidden",
}

DEFAULT_MANIFEST_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_ARTIFACT_TOTAL_MAX_BYTES = 256 * 1024 * 1024

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

_V2_TOP_LEVEL_FIELDS = {
    "schema",
    "contract_version",
    "state",
    "authority",
    "repository",
    "canonicalization",
    "timestamps",
    "capability_registry",
    "participants",
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


class CompatibilityInputError(ValueError):
    """A stable, path-free compatibility input failure."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


class _DuplicateJSONKey(ValueError):
    """Internal marker for a duplicate JSON object member."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _strict_json(data: bytes | str) -> Any:
    """Decode JSON without parser differentials or duplicate object keys."""

    try:
        return json.loads(
            data,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJSONKey:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed JSON") from exc


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise CompatibilityInputError("invalid_budget", "byte budget is invalid")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise CompatibilityInputError("manifest_unavailable", "compatibility manifest is unavailable")
        if before.st_size > max_bytes:
            raise CompatibilityInputError("manifest_too_large", "compatibility manifest exceeds byte budget")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if before.st_ino != after.st_ino or before.st_dev != after.st_dev or before.st_size != after.st_size:
            raise CompatibilityInputError("manifest_changed_during_read", "compatibility manifest changed during read")
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise CompatibilityInputError("manifest_too_large", "compatibility manifest exceeds byte budget")
        return data
    except CompatibilityInputError:
        raise
    except OSError as exc:
        raise CompatibilityInputError("manifest_unavailable", "compatibility manifest is unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def load_manifest(path: Path, *, max_bytes: int = DEFAULT_MANIFEST_MAX_BYTES) -> dict[str, Any]:
    """Read a bounded, strict JSON object from *path*.

    The path is an input handle, not evidence.  It is intentionally omitted
    from all reports so the same bytes produce the same diagnostics in any
    checkout or cache root.
    """

    try:
        payload = _strict_json(_read_bounded(path, max_bytes))
    except _DuplicateJSONKey as exc:
        raise CompatibilityInputError("duplicate_json_key", "compatibility manifest contains a duplicate JSON key") from exc
    except CompatibilityInputError:
        raise
    except ValueError as exc:
        raise CompatibilityInputError("malformed_manifest", "malformed compatibility manifest") from exc
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
    if type(payload.get("contract_version")) is not int or payload.get("contract_version") != SUPPORTED_CONTRACT_VERSION:
        errors.append(_error("unknown_version", "contract_version must be the integer 1"))

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
            if not isinstance(entry, dict) or not required.issubset(entry) or set(entry) - (required | {"digests"}):
                errors.append(_error("malformed_manifest", "each adapter must contain schema, kind, identity, metrics, source, and optional digests"))
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
            if "digests" in entry:
                values = entry["digests"]
                if not isinstance(values, list) or any(not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) for value in values):
                    errors.append(_error("malformed_manifest", f"adapter digests is invalid for {schema}"))
            if entry.get("source") != "src/agent_proof/interop.py:ADAPTERS":
                errors.append(_error("malformed_manifest", f"adapter source is not the reviewed registry for {schema}"))
        if adapters != sorted(adapters, key=lambda item: item.get("schema", "") if isinstance(item, dict) else ""):
            errors.append(_error("malformed_manifest", "adapters must be sorted by schema"))

    errors.extend(_validate_v1_artifact_bindings(payload))
    return sorted(errors, key=lambda item: (item["code"], item["detail"]))


def check_manifest(path: Path) -> dict[str, Any]:
    """Return a deterministic checker report for a manifest path."""

    try:
        payload = load_manifest(path)
        errors = validate_manifest(payload)
        digest = manifest_digest(payload)
    except CompatibilityInputError as exc:
        errors = [_error(exc.code, str(exc))]
        digest = None
    except ValueError:
        errors = [_error("malformed_manifest", "malformed compatibility manifest")]
        digest = None
    return {
        "schema": "agent-systems-lab/compatibility-check/v1",
        "manifest_sha256": digest,
        "ok": not errors,
        "errors": errors,
    }


def check_manifest_v1_with_bindings(path: Path) -> dict[str, Any]:
    """Opt-in v1 structural check plus canonical participant URL binding."""

    result = check_manifest(path)
    if not result["ok"]:
        return result
    try:
        payload = load_manifest(path)
    except CompatibilityInputError as exc:
        return {**result, "ok": False, "errors": [_error(exc.code, str(exc))]}
    binding_errors = _validate_v1_artifact_bindings(payload)
    return {**result, "ok": not binding_errors, "errors": binding_errors}


CAPABILITY_DECLARATION_SCHEMA = "agent-systems-lab/capabilities/v1"
_DECLARATION_FIELDS = {"schema", "contract_version", "capabilities", "native_protocols"}
_DECLARATION_ENTRY_FIELDS = {"id", "supported_versions"}


def _github_repository(value: Any) -> tuple[str, str] | None:
    """Return canonical GitHub owner/repository parts, or ``None``."""

    if not isinstance(value, str) or not value or any(char in value for char in ("%", "\\", "\x00")):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or parsed.path.count("/") != 2
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
    ):
        return None
    owner, repository = parsed.path[1:].split("/")
    if not _GITHUB_NAME.fullmatch(owner) or not _GITHUB_NAME.fullmatch(repository) or repository.endswith(".git"):
        return None
    return owner, repository


def _github_artifact(value: Any, repository: str, revision: str) -> bool:
    repo_parts = _github_repository(repository)
    if repo_parts is None or not isinstance(value, str) or any(char in value for char in ("%", "\\", "\x00")):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment:
        return False
    parts = parsed.path.split("/")
    if len(parts) < 6 or parts[0] != "" or parts[1:4] != [repo_parts[0], repo_parts[1], "blob"]:
        return False
    if parts[4] != revision or not _COMMIT.fullmatch(parts[4]):
        return False
    relative = parts[5:]
    if not relative or any(not component or component in {".", ".."} for component in relative):
        return False
    return True


def _validate_participant_bindings(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """Validate immutable GitHub identity without contacting GitHub."""

    errors: list[dict[str, str]] = []
    participants = payload.get("participants")
    if not isinstance(participants, list):
        return errors
    for entry in participants:
        if not isinstance(entry, dict):
            continue
        repository = entry.get("repository")
        artifact = entry.get("conformance_artifact")
        if not isinstance(repository, str) or _github_repository(repository) is None:
            errors.append(_error("noncanonical_github_ref", "participant repository must be a canonical GitHub HTTPS URL"))
            continue
        if not isinstance(artifact, dict):
            continue
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not _COMMIT.fullmatch(revision):
            errors.append(_error("unknown_version", "artifact revision must be a 40-character lowercase commit"))
            continue
        if not _github_artifact(artifact.get("url"), repository, revision):
            errors.append(_error("owner_repository_mismatch", "artifact URL is not bound to the participant repository"))
    return errors


def _validate_v1_artifact_bindings(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """Validate v1 URL identity only when v1 bytes are explicitly checked."""

    errors: list[dict[str, str]] = []
    participants = payload.get("participants")
    if not isinstance(participants, list):
        return errors
    for entry in participants:
        if not isinstance(entry, dict):
            continue
        repository = entry.get("repository")
        artifact = entry.get("conformance_artifact")
        if not isinstance(repository, str) or _github_repository(repository) is None:
            errors.append(_error("noncanonical_github_ref", "participant repository must be a canonical GitHub HTTPS URL"))
            continue
        if not isinstance(artifact, dict):
            continue
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not _COMMIT.fullmatch(revision):
            errors.append(_error("unknown_version", "artifact revision must be a 40-character lowercase commit"))
            continue
        if not _github_artifact(artifact.get("url"), repository, revision):
            errors.append(_error("owner_repository_mismatch", "artifact URL is not bound to the participant repository"))
    return errors


def _version_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(type(version) is int and version > 0 for version in value)
        and value == sorted(set(value))
    )


def _validate_declaration(registry: Any) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if not isinstance(registry, dict) or set(registry) != _DECLARATION_FIELDS:
        return [_error("unsupported_schema", "capability declaration must use the reviewed declaration shape")]
    if registry.get("schema") != CAPABILITY_DECLARATION_SCHEMA:
        errors.append(_error("unsupported_schema", "capability declaration schema is unsupported"))
    if type(registry.get("contract_version")) is not int or registry.get("contract_version") != 1:
        errors.append(_error("unknown_version", "capability declaration contract_version must be the integer 1"))
    seen: set[str] = set()
    for field in ("capabilities", "native_protocols"):
        entries = registry.get(field)
        if not isinstance(entries, list):
            errors.append(_error("malformed_manifest", "capability declarations must be lists"))
            continue
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != _DECLARATION_ENTRY_FIELDS:
                errors.append(_error("malformed_manifest", "capability entries must contain id and supported_versions"))
                continue
            identifier = entry.get("id")
            if not isinstance(identifier, str) or not _CAPABILITY_IDENTIFIER.fullmatch(identifier):
                errors.append(_error("unsupported_schema", "capability identifier is unsupported"))
                continue
            if identifier in seen:
                errors.append(_error("duplicate_identifier", "capability identifier is declared more than once"))
            seen.add(identifier)
            versions = entry.get("supported_versions")
            if not _version_list(versions):
                errors.append(_error("malformed_version", "supported_versions must be sorted unique positive integers"))
                continue
            known = BUILTIN_CAPABILITY_VERSIONS.get(identifier)
            if known is not None and any(version not in known for version in versions):
                errors.append(_error("unknown_version", "capability declares a version not supported by this checker"))
        if entries != sorted(entries, key=lambda item: item.get("id", "") if isinstance(item, dict) else ""):
            errors.append(_error("malformed_manifest", "capability declarations must be sorted by identifier"))
    return errors


def validate_manifest_v2(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """Validate the additive v2 compatibility manifest shape.

    v2 is intentionally separate from :func:`validate_manifest`: v1 remains
    readable under its closed schema and does not acquire v2 meaning.
    """

    errors: list[dict[str, str]] = []
    if not isinstance(payload, dict):
        return [_error("malformed_manifest", "compatibility v2 root must be an object")]
    unknown = sorted(set(payload) - _V2_TOP_LEVEL_FIELDS)
    if unknown:
        errors.append(_error("malformed_manifest", "compatibility v2 contains unknown top-level fields"))
    if payload.get("schema") != COMPATIBILITY_V2_SCHEMA:
        errors.append(_error("unsupported_schema", "schema must be agent-systems-lab/compatibility/v2"))
    if type(payload.get("contract_version")) is not int or payload.get("contract_version") != SUPPORTED_CONTRACT_VERSION_V2:
        errors.append(_error("unknown_version", "contract_version must be the integer 2"))
    if payload.get("state") not in {"draft", "complete"}:
        errors.append(_error("malformed_manifest", "state must be draft or complete"))
    if not isinstance(payload.get("authority"), str) or not _IDENTIFIER.fullmatch(payload.get("authority", "")):
        errors.append(_error("malformed_manifest", "authority must be a bounded identifier"))
    if _github_repository(payload.get("repository")) is None:
        errors.append(_error("noncanonical_github_ref", "repository must be a canonical GitHub HTTPS URL"))
    if payload.get("canonicalization") != {
        "encoding": "utf-8",
        "json": "sorted-keys-compact",
        "allow_nan": False,
    }:
        errors.append(_error("malformed_manifest", "canonicalization does not match the compatibility contract"))
    if payload.get("timestamps") != TIMESTAMP_RULES:
        errors.append(_error("malformed_manifest", "timestamp authority and rewrite rules are required"))
    errors.extend(_validate_declaration(payload.get("capability_registry")))

    participants = payload.get("participants")
    if not isinstance(participants, list) or not participants:
        errors.append(_error("malformed_manifest", "participants must be a non-empty list"))
        return sorted(errors, key=lambda item: (item["code"], item["detail"]))
    owners: set[str] = set()
    for entry in participants:
        if not isinstance(entry, dict) or set(entry) != {"owner", "repository", "conformance_artifact"}:
            errors.append(_error("malformed_manifest", "each v2 participant must contain owner, repository, and conformance_artifact"))
            continue
        owner = entry.get("owner")
        if not isinstance(owner, str) or not _IDENTIFIER.fullmatch(owner):
            errors.append(_error("malformed_manifest", "participant owner is invalid"))
        elif owner in owners:
            errors.append(_error("duplicate_identifier", "participant owner is declared more than once"))
        owners.add(owner if isinstance(owner, str) else "")
        repository = entry.get("repository")
        if _github_repository(repository) is None:
            errors.append(_error("noncanonical_github_ref", "participant repository is not canonical"))
        artifact = entry.get("conformance_artifact")
        required_artifact = {"url", "revision", "sha256", "format", "document_schema", "owner_contract"}
        if not isinstance(artifact, dict) or set(artifact) != required_artifact:
            errors.append(_error("malformed_manifest", "v2 artifacts must declare format, document schema, and owner contract"))
            continue
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not _COMMIT.fullmatch(revision):
            errors.append(_error("unknown_version", "artifact revision must be a 40-character lowercase commit"))
        if not isinstance(artifact.get("sha256"), str) or not _SHA256.fullmatch(artifact.get("sha256", "")):
            errors.append(_error("malformed_manifest", "artifact sha256 must be lowercase SHA-256"))
        if _github_repository(repository) is not None and isinstance(revision, str) and _COMMIT.fullmatch(revision):
            if not _github_artifact(artifact.get("url"), repository, revision):
                errors.append(_error("owner_repository_mismatch", "artifact URL is not bound to the participant repository"))
        fmt = artifact.get("format")
        if fmt not in {"bytes", "json"}:
            errors.append(_error("unsupported_schema", "artifact format must be bytes or json"))
        document_schema = artifact.get("document_schema")
        if fmt == "json" and (not isinstance(document_schema, str) or not _CAPABILITY_IDENTIFIER.fullmatch(document_schema)):
            errors.append(_error("unsupported_schema", "JSON artifacts must declare a document schema"))
        if fmt == "bytes" and document_schema is not None:
            errors.append(_error("malformed_manifest", "byte artifacts cannot declare a document schema"))
        contract = artifact.get("owner_contract")
        expected_contract = {"owner_field", "repository_field", "schema_field"}
        if fmt == "json" and (
            not isinstance(contract, dict)
            or set(contract) != expected_contract
            or any(not isinstance(contract[field], str) or not _IDENTIFIER.fullmatch(contract[field]) for field in expected_contract)
        ):
            errors.append(_error("malformed_manifest", "JSON artifacts must declare owner, repository, and schema fields"))
        if fmt == "bytes" and contract is not None:
            errors.append(_error("malformed_manifest", "byte artifacts cannot declare an owner contract"))
    if participants != sorted(participants, key=lambda item: item.get("owner", "") if isinstance(item, dict) else ""):
        errors.append(_error("malformed_manifest", "participants must be sorted by owner"))
    return sorted(errors, key=lambda item: (item["code"], item["detail"]))


def check_manifest_v2(path: Path) -> dict[str, Any]:
    """Check an additive v2 manifest without exposing its input path."""

    try:
        payload = load_manifest(path)
    except CompatibilityInputError as exc:
        return {
            "schema": "agent-systems-lab/compatibility-check/v2",
            "manifest_sha256": None,
            "ok": False,
            "state": "unknown",
            "errors": [_error(exc.code, str(exc))],
        }
    except ValueError:
        return {
            "schema": "agent-systems-lab/compatibility-check/v2",
            "manifest_sha256": None,
            "ok": False,
            "state": "unknown",
            "errors": [_error("malformed_manifest", "malformed compatibility manifest")],
        }
    errors = validate_manifest_v2(payload)
    return {
        "schema": "agent-systems-lab/compatibility-check/v2",
        "manifest_sha256": manifest_digest(payload),
        "ok": not errors,
        "state": payload.get("state", "unknown"),
        "errors": errors,
    }


def _stable_path_error(code: str) -> dict[str, str]:
    return _error(code, code.replace("_", " "))


@dataclass(frozen=True)
class ArtifactSource:
    """A caller-selected local artifact; no URL or cache discovery occurs."""

    path: Path
    cache_ref: str | None = None


def negotiate_capability(
    capability: str,
    producer_versions: Any,
    consumer_versions: Any,
) -> dict[str, Any]:
    """Choose the highest declared mutually supported protocol version."""

    errors: list[dict[str, str]] = []
    if not isinstance(capability, str) or not _CAPABILITY_IDENTIFIER.fullmatch(capability):
        errors.append(_error("unsupported_schema", "capability identifier is unsupported"))
    if not _version_list(producer_versions) or not _version_list(consumer_versions):
        errors.append(_error("malformed_version", "producer and consumer versions must be sorted unique positive integers"))
    if errors:
        return {"schema": NEGOTIATION_REPORT_SCHEMA, "ok": False, "capability": None, "selected_version": None, "errors": sorted(errors, key=lambda item: (item["code"], item["detail"]))}
    shared = sorted(set(producer_versions).intersection(consumer_versions), reverse=True)
    if not shared:
        return {"schema": NEGOTIATION_REPORT_SCHEMA, "ok": False, "capability": capability, "selected_version": None, "errors": [_error("unsupported_version", "producer and consumer have no mutually supported version")]}
    return {"schema": NEGOTIATION_REPORT_SCHEMA, "ok": True, "capability": capability, "selected_version": shared[0], "errors": []}


def negotiate_capabilities(producer: Mapping[str, Any], consumer: Mapping[str, Any]) -> dict[str, Any]:
    """Negotiate only explicitly declared capability entries."""

    errors: list[dict[str, str]] = []
    if producer.get("schema") != CAPABILITY_DECLARATION_SCHEMA or consumer.get("schema") != CAPABILITY_DECLARATION_SCHEMA:
        errors.append(_error("unsupported_schema", "producer and consumer declarations use an unsupported schema"))
    if type(producer.get("contract_version")) is not int or type(consumer.get("contract_version")) is not int:
        errors.append(_error("unknown_version", "declaration contract_version must be an integer"))
    producer_entries = producer.get("capabilities") if isinstance(producer.get("capabilities"), list) else []
    consumer_entries = consumer.get("capabilities") if isinstance(consumer.get("capabilities"), list) else []
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or entry.get("id") in pmap:
            errors.append(_error("malformed_manifest", "capability declarations contain malformed or duplicate entries"))
        else:
            pmap[entry["id"]] = entry.get("supported_versions")
    results: list[dict[str, Any]] = []
    for capability in sorted(set(pmap).intersection(cmap)):
        results.append(negotiate_capability(capability, pmap[capability], cmap[capability]))
    if errors:
        return {"schema": NEGOTIATION_REPORT_SCHEMA, "ok": False, "results": results, "errors": sorted(errors, key=lambda item: (item["code"], item["detail"]))}
    return {"schema": NEGOTIATION_REPORT_SCHEMA, "ok": bool(results) and all(item["ok"] for item in results), "results": results, "errors": [] if results else [_error("unsupported_version", "no mutually declared capability exists")]}


def _safe_relative_path(path: Path) -> bool:
    if path.is_absolute() or "\x00" in str(path) or "\\" in str(path):
        return False
    return all(part not in {"", ".", ".."} for part in path.parts)


def _open_regular_no_follow(root: Path, relative: Path) -> tuple[int, os.stat_result] | None:
    if not _safe_relative_path(relative):
        return None
    try:
        root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    fd = root_fd
    try:
        parts = relative.parts
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            if index < len(parts) - 1:
                flags |= getattr(os, "O_DIRECTORY", 0)
            next_fd = os.open(part, flags, dir_fd=fd)
            if fd != root_fd:
                os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            return None
        return fd, info
    except OSError:
        if fd != root_fd:
            os.close(fd)
        return None
    finally:
        os.close(root_fd)


def _read_artifact(root: Path, relative: Path, max_bytes: int) -> tuple[bytes | None, str | None]:
    if type(max_bytes) is not int or max_bytes <= 0:
        return None, "invalid_budget"
    opened = _open_regular_no_follow(root, relative)
    if opened is None:
        return None, "artifact_missing"
    fd, before = opened
    try:
        if before.st_size > max_bytes:
            return None, "artifact_too_large"
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if before.st_ino != after.st_ino or before.st_dev != after.st_dev or before.st_size != after.st_size:
            return None, "artifact_changed_during_read"
        data = b"".join(chunks)
        if len(data) > max_bytes:
            return None, "artifact_too_large"
        return data, None
    except OSError:
        return None, "artifact_unavailable"
    finally:
        os.close(fd)


def _owner_contract_matches(payload: Any, owner: str, repository: str, schema: str, contract: Mapping[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    return (
        payload.get(contract["owner_field"]) == owner
        and payload.get(contract["repository_field"]) == repository
        and payload.get(contract["schema_field"]) == schema
    )


def validate_participant_artifacts(
    manifest_path: Path,
    sources: Mapping[str, ArtifactSource | Path],
    *,
    artifact_root: Path | None = None,
    max_bytes: int = DEFAULT_ARTIFACT_MAX_BYTES,
    max_total_bytes: int = DEFAULT_ARTIFACT_TOTAL_MAX_BYTES,
) -> dict[str, Any]:
    """Validate caller-selected v2 participant bytes entirely offline.

    Structural validation is completed before any participant source is opened.
    ``sources`` is keyed by owner and is never expanded by scanning a cache.
    """

    try:
        payload = load_manifest(manifest_path)
    except CompatibilityInputError as exc:
        return {"schema": ARTIFACT_REPORT_SCHEMA, "ok": False, "complete": False, "remote_state": "not_contacted", "execution": "not_attempted", "manifest_sha256": None, "participants": [], "errors": [_error(exc.code, str(exc))]}
    except ValueError:
        return {"schema": ARTIFACT_REPORT_SCHEMA, "ok": False, "complete": False, "remote_state": "not_contacted", "execution": "not_attempted", "manifest_sha256": None, "participants": [], "errors": [_error("malformed_manifest", "malformed compatibility manifest")]}
    structural = validate_manifest_v2(payload)
    digest = manifest_digest(payload)
    participants = payload.get("participants")
    if structural or payload.get("state") != "complete":
        if payload.get("state") == "draft":
            structural.append(_error("manifest_incomplete", "compatibility v2 manifest is explicitly incomplete"))
        return {"schema": ARTIFACT_REPORT_SCHEMA, "ok": False, "complete": False, "remote_state": "not_contacted", "execution": "not_attempted", "manifest_sha256": digest, "participants": [], "errors": sorted(structural, key=lambda item: (item["code"], item["detail"]))}
    reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total = 0
    for entry in participants:
        owner = entry["owner"]
        artifact = entry["conformance_artifact"]
        source = sources.get(owner)
        report: dict[str, Any] = {"owner": owner, "state": "not_checked", "format": artifact["format"]}
        if source is None:
            report["state"] = "unavailable"
            report["error"] = "artifact_not_provided"
            errors.append(_stable_path_error("artifact_not_provided"))
            reports.append(report)
            continue
        selected = source if isinstance(source, ArtifactSource) else ArtifactSource(Path(source))
        if selected.cache_ref is not None and selected.cache_ref != artifact["url"]:
            report["state"] = "refused"
            report["error"] = "cache_key_mismatch"
            errors.append(_stable_path_error("cache_key_mismatch"))
            reports.append(report)
            continue
        local = Path(selected.path)
        if artifact_root is not None:
            try:
                local = local.relative_to(artifact_root)
            except ValueError:
                report["state"] = "refused"
                report["error"] = "unsafe_path"
                errors.append(_stable_path_error("unsafe_path"))
                reports.append(report)
                continue
            root = artifact_root
        else:
            root, local = local.parent, Path(local.name)
        data, failure = _read_artifact(root, local, max_bytes)
        if failure:
            report["state"] = "refused" if failure in {"unsafe_path", "artifact_too_large"} else "unavailable"
            report["error"] = failure
            errors.append(_stable_path_error(failure))
            reports.append(report)
            continue
        assert data is not None
        total += len(data)
        if total > max_total_bytes:
            report["state"] = "refused"
            report["error"] = "total_artifact_budget_exceeded"
            errors.append(_stable_path_error("total_artifact_budget_exceeded"))
            reports.append(report)
            continue
        actual = hashlib.sha256(data).hexdigest()
        report["sha256"] = actual
        if not hmac.compare_digest(actual, artifact["sha256"]):
            report["state"] = "refused"
            report["error"] = "digest_mismatch"
            errors.append(_stable_path_error("digest_mismatch"))
            reports.append(report)
            continue
        if artifact["format"] == "json":
            try:
                decoded = data.decode("utf-8")
                document = _strict_json(decoded)
            except (_DuplicateJSONKey, ValueError, UnicodeError):
                report["state"] = "refused"
                report["error"] = "invalid_json"
                errors.append(_stable_path_error("invalid_json"))
                reports.append(report)
                continue
            repository = entry["repository"]
            repo_parts = _github_repository(repository)
            expected_schema = artifact["document_schema"]
            contract = artifact["owner_contract"]
            if repo_parts is None or not _owner_contract_matches(document, owner, repository, expected_schema, contract):
                report["state"] = "refused"
                report["error"] = "owner_contract_mismatch"
                errors.append(_stable_path_error("owner_contract_mismatch"))
                reports.append(report)
                continue
        report["state"] = "verified"
        reports.append(report)
    reports.sort(key=lambda item: item["owner"])
    return {"schema": ARTIFACT_REPORT_SCHEMA, "ok": not errors and all(item["state"] == "verified" for item in reports), "complete": True, "remote_state": "not_contacted", "execution": "not_attempted", "manifest_sha256": digest, "participants": reports, "errors": sorted(errors, key=lambda item: (item["code"], item["detail"]))}
