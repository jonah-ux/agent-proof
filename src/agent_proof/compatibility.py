"""Validation for the Agent Systems Lab compatibility charter.

The compatibility manifest is deliberately data-only.  Agent Proof owns this
checker because it already owns the reviewed adapter registry, while each
specialist repository remains authoritative for its native schema and refusal
semantics.  The checker validates the charter itself; it does not fetch sibling
repositories or reinterpret their native payloads.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import math
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
CAPABILITY_IDENTIFIER_PATTERN = (
    r"^[a-z0-9][a-z0-9._-]{0,63}(?:/[a-z0-9][a-z0-9._-]{0,63})*$"
)
_CAPABILITY_IDENTIFIER = re.compile(CAPABILITY_IDENTIFIER_PATTERN)
_GITHUB_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# The registry is deliberately limited to reviewed, canonical identifiers.
# Package semver, deployment versions, and native schema names are not protocol
# versions.  A caller may negotiate only an identifier present here and in the
# checked-in v2 registry; this prevents a syntactically valid vendor/foo value
# from becoming platform support by assertion alone.
SUPPORTED_CAPABILITY_VERSIONS = {
    "agent-systems-lab/compatibility-artifacts": (1,),
    "agent-systems-lab/native-protocol-negotiation": (1,),
    "evaluation.refusals": (1,),
    "lifecycle.approval": (1,),
    "lifecycle.receipt": (1,),
    "provenance.packet": (1,),
    "review.compose": (1,),
    "review.verify": (1,),
    "trace.export": (1,),
    "trace.import": (1,),
    "work.evidence": (1,),
}

SUPPORTED_NATIVE_PROTOCOL_VERSIONS = {
    "agent-policy": (1,),
    "agent-policy/receipt": (1,),
    "agent-proof": (1,),
    "agent-proof/interop": (1,),
    "agent-proof-lab-conformance": (1,),
    "agent-eval": (1,),
    "agent-sandbox": (1, 2),
    "agent-trace": (1,),
    "agent-trace/inspect": (1,),
    "agent-trace/query": (1,),
    "context-pack": (1,),
    "agent-resume": (1,),
    "context-integrity": (1,),
    "ai-work-evidence": (1,),
    "atlas-receipt": (1,),
    "chatlens-trace-envelope": (1,),
    "forgeyard-compose": (1,),
    "forgeyard-evidence-receipt": (1,),
    "forgeyard-provenance-packet-verify": (1,),
    "forgeyard-provenance-packet": (1,),
    "forgeyard-record-verify": (1,),
    "forgeyard-review-packet": (1,),
    "forgeyard-runtime-evaluation": (1,),
    "mcp-doctor": (1,),
    "slipstream/query": (1,),
    "slipstream/inspect": (1,),
    "slipstream/manifest": (1,),
    "slipstream/verify": (1,),
    "sourcemark/check": (1,),
    "worktree-conservator.result": (1,),
}

# Kept as a compatibility alias for callers that imported the provisional
# name before v2 was documented.
BUILTIN_CAPABILITY_VERSIONS = SUPPORTED_CAPABILITY_VERSIONS

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
    "refusal_codes",
    "capability_registry",
    "compatibility_v1_reference",
    "participants",
}

V2_REFUSAL_CODES = (
    "artifact_changed_during_read",
    "artifact_missing",
    "artifact_not_provided",
    "artifact_too_large",
    "artifact_unavailable",
    "cache_key_mismatch",
    "capability_declaration_mismatch",
    "content_unvalidated",
    "digest_mismatch",
    "duplicate_identifier",
    "duplicate_json_key",
    "invalid_budget",
    "invalid_json",
    "invalid_utf8",
    "json_too_deep",
    "malformed_manifest",
    "malformed_version",
    "manifest_changed_during_read",
    "manifest_incomplete",
    "manifest_too_large",
    "manifest_unavailable",
    "numeric_overflow",
    "non_finite_number",
    "native_schema_mismatch",
    "noncanonical_github_ref",
    "owner_contract_mismatch",
    "owner_repository_mismatch",
    "source_unbound",
    "stale_source_identity",
    "total_artifact_budget_exceeded",
    "unsafe_path",
    "unknown_version",
    "unsupported_schema",
    "unsupported_version",
)


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


class _NonFiniteJSONNumber(ValueError):
    """Internal marker for a non-finite JSON number."""


class _NumericOverflow(ValueError):
    """Internal marker for an integer outside the bounded JSON domain."""


class _JSONTooDeep(ValueError):
    """Internal marker for a JSON document exceeding the nesting budget."""


_MAX_JSON_INTEGER_DIGITS = 128
_MAX_JSON_DEPTH = 128


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise _NonFiniteJSONNumber("non-finite JSON number")


def _strict_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _NonFiniteJSONNumber("non-finite JSON number")
    return parsed


def _strict_int(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > _MAX_JSON_INTEGER_DIGITS:
        raise _NumericOverflow("JSON integer exceeds the bounded numeric domain")
    return int(value)


def _check_json_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            raise _JSONTooDeep("JSON nesting exceeds the bounded depth")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _strict_json(data: bytes | str) -> Any:
    """Decode JSON without parser differentials or duplicate object keys."""

    try:
        result = json.loads(
            data,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
            parse_float=_strict_float,
            parse_int=_strict_int,
        )
        _check_json_depth(result)
        return result
    except _DuplicateJSONKey:
        raise
    except (_NonFiniteJSONNumber, _NumericOverflow, _JSONTooDeep):
        raise
    except UnicodeError:
        raise
    except RecursionError as exc:
        raise _JSONTooDeep("JSON nesting exceeds the bounded depth") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed JSON") from exc


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise CompatibilityInputError("invalid_budget", "byte budget is invalid")
    fd = None
    try:
        if not isinstance(path, (str, os.PathLike)):
            raise CompatibilityInputError(
                "manifest_unavailable", "manifest handle is unavailable"
            )
        if "\x00" in os.fspath(path):
            raise CompatibilityInputError("unsafe_path", "manifest path is unsafe")
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise CompatibilityInputError(
                "unsafe_path", "manifest must be a regular file"
            )
        if before.st_size > max_bytes:
            raise CompatibilityInputError(
                "manifest_too_large", "compatibility manifest exceeds byte budget"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after):
            raise CompatibilityInputError(
                "manifest_changed_during_read",
                "compatibility manifest changed during read",
            )
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise CompatibilityInputError(
                "manifest_too_large", "compatibility manifest exceeds byte budget"
            )
        return data
    except CompatibilityInputError:
        raise
    except (TypeError, ValueError) as exc:
        raise CompatibilityInputError(
            "unsafe_path", "manifest handle is invalid"
        ) from exc
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENXIO}:
            raise CompatibilityInputError(
                "unsafe_path", "manifest path is unsafe"
            ) from exc
        raise CompatibilityInputError(
            "manifest_unavailable", "compatibility manifest is unavailable"
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)


def load_manifest(
    path: Path, *, max_bytes: int = DEFAULT_MANIFEST_MAX_BYTES
) -> dict[str, Any]:
    """Read a bounded, strict JSON object from *path*.

    The path is an input handle, not evidence.  It is intentionally omitted
    from all reports so the same bytes produce the same diagnostics in any
    checkout or cache root.
    """

    try:
        payload = _strict_json(_read_bounded(path, max_bytes))
    except _DuplicateJSONKey as exc:
        raise CompatibilityInputError(
            "duplicate_json_key", "compatibility manifest contains a duplicate JSON key"
        ) from exc
    except CompatibilityInputError:
        raise
    except _NonFiniteJSONNumber as exc:
        raise CompatibilityInputError(
            "non_finite_number", "compatibility manifest contains a non-finite number"
        ) from exc
    except _NumericOverflow as exc:
        raise CompatibilityInputError(
            "numeric_overflow", "compatibility manifest contains an oversized number"
        ) from exc
    except _JSONTooDeep as exc:
        raise CompatibilityInputError(
            "json_too_deep", "compatibility manifest exceeds the JSON depth budget"
        ) from exc
    except UnicodeError as exc:
        raise CompatibilityInputError(
            "invalid_utf8", "compatibility manifest is not valid UTF-8"
        ) from exc
    except ValueError as exc:
        raise CompatibilityInputError(
            "malformed_manifest", "malformed compatibility manifest"
        ) from exc
    if not isinstance(payload, dict):
        raise CompatibilityInputError(
            "malformed_manifest", "malformed compatibility manifest"
        )
    return payload


def _error(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _unique_errors(errors: list[dict[str, str]]) -> list[dict[str, str]]:
    unique = {(item["code"], item["detail"]) for item in errors}
    return [{"code": code, "detail": detail} for code, detail in sorted(unique)]


def validate_manifest(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Return stable, machine-readable charter violations.

    The returned list is sorted by refusal code and detail so a caller can
    compare reports across runtimes.  Native owner codes remain in their own
    repositories; this list only covers cross-repository charter failures.
    """

    if not isinstance(payload, dict):
        return [
            _error("malformed_manifest", "compatibility manifest must be an object")
        ]
    errors: list[dict[str, str]] = []
    unknown = sorted(set(payload) - _TOP_LEVEL_FIELDS)
    if unknown:
        errors.append(
            _error(
                "malformed_manifest", f"unknown top-level fields: {', '.join(unknown)}"
            )
        )

    if payload.get("schema") != COMPATIBILITY_SCHEMA:
        errors.append(
            _error(
                "unsupported_schema",
                "schema must be agent-systems-lab/compatibility/v1",
            )
        )
    if payload.get("contract_version") != SUPPORTED_CONTRACT_VERSION:
        errors.append(_error("unknown_version", "contract_version must be 1"))

    authority = payload.get("authority")
    if not isinstance(authority, str) or not _IDENTIFIER.fullmatch(authority):
        errors.append(
            _error("malformed_manifest", "authority must be a bounded identifier")
        )
    repository = payload.get("repository")
    if not isinstance(repository, str) or not repository.startswith("https://"):
        errors.append(_error("malformed_manifest", "repository must be an HTTPS URL"))

    canonicalization = payload.get("canonicalization")
    if canonicalization != {
        "encoding": "utf-8",
        "json": "sorted-keys-compact",
        "allow_nan": False,
    }:
        errors.append(
            _error("malformed_manifest", "canonicalization does not match the charter")
        )

    identifiers = payload.get("identifiers")
    if identifiers != {"pattern": IDENTIFIER_PATTERN, "max_length": 128}:
        errors.append(
            _error("malformed_manifest", "identifiers does not match the charter")
        )

    statuses = payload.get("statuses")
    if statuses != list(STATUS_VOCABULARY):
        errors.append(
            _error(
                "unsupported_status",
                "statuses must equal the ordered charter vocabulary",
            )
        )

    redaction = payload.get("redaction")
    expected_redaction = {
        "raw_payloads": False,
        "secrets": False,
        "private_paths": False,
        "provider_credentials": False,
    }
    if redaction != expected_redaction:
        errors.append(
            _error(
                "redaction_violation",
                "redaction must deny raw payloads, secrets, private paths, and provider credentials",
            )
        )

    if payload.get("owner_codes") != {
        "mode": "preserve-verbatim",
        "fields": ["owner_status", "owner_code"],
        "unknown_policy": "do-not-infer",
    }:
        errors.append(
            _error(
                "malformed_manifest",
                "owner_codes must preserve native status and code fields verbatim",
            )
        )

    refusal_codes = payload.get("refusal_codes")
    seen_codes: set[str] = set()
    if not isinstance(refusal_codes, list):
        errors.append(_error("malformed_manifest", "refusal_codes must be a list"))
    else:
        actual_codes: set[str] = set()
        for entry in refusal_codes:
            if not isinstance(entry, dict) or set(entry) != {
                "code",
                "class",
                "meaning",
            }:
                errors.append(
                    _error(
                        "malformed_manifest",
                        "each refusal code must contain code, class, and meaning",
                    )
                )
                continue
            code = entry.get("code")
            if not isinstance(code, str) or not _REFUSAL_CODE.fullmatch(code):
                errors.append(
                    _error("malformed_manifest", "refusal code has an invalid format")
                )
                continue
            if code in seen_codes:
                errors.append(
                    _error("duplicate_identifier", f"duplicate refusal code: {code}")
                )
            seen_codes.add(code)
            actual_codes.add(code)
            if not isinstance(entry.get("class"), str) or not _IDENTIFIER.fullmatch(
                entry["class"]
            ):
                errors.append(
                    _error("malformed_manifest", f"refusal class is invalid for {code}")
                )
            if (
                not isinstance(entry.get("meaning"), str)
                or not entry["meaning"].strip()
            ):
                errors.append(
                    _error("malformed_manifest", f"refusal meaning is empty for {code}")
                )
        if refusal_codes != sorted(
            refusal_codes,
            key=lambda item: item.get("code", "") if isinstance(item, dict) else "",
        ):
            errors.append(
                _error("malformed_manifest", "refusal_codes must be sorted by code")
            )
        missing_codes = sorted(REQUIRED_REFUSAL_CODES - actual_codes)
        if missing_codes:
            errors.append(
                _error(
                    "malformed_manifest",
                    f"required refusal codes are missing: {', '.join(missing_codes)}",
                )
            )

    participants = payload.get("participants")
    if not isinstance(participants, list) or not participants:
        errors.append(
            _error("malformed_manifest", "participants must be a non-empty list")
        )
    else:
        participant_ids: set[str] = set()
        for entry in participants:
            required = {"owner", "repository", "native_schemas", "conformance_artifact"}
            if not isinstance(entry, dict) or set(entry) != required:
                errors.append(
                    _error(
                        "malformed_manifest",
                        "each participant must contain owner, repository, native_schemas, and conformance_artifact",
                    )
                )
                continue
            owner = entry.get("owner")
            if not isinstance(owner, str) or not _IDENTIFIER.fullmatch(owner):
                errors.append(
                    _error("malformed_manifest", "participant owner is invalid")
                )
            elif owner in participant_ids:
                errors.append(
                    _error(
                        "duplicate_identifier", f"duplicate participant owner: {owner}"
                    )
                )
            else:
                participant_ids.add(owner)
            if not isinstance(entry.get("repository"), str) or not entry[
                "repository"
            ].startswith("https://"):
                errors.append(
                    _error(
                        "malformed_manifest",
                        f"participant repository is invalid for {owner}",
                    )
                )
            schemas = entry.get("native_schemas")
            if (
                not isinstance(schemas, list)
                or not schemas
                or any(
                    not isinstance(schema, str)
                    or not _IDENTIFIER.fullmatch(schema.replace("/", "_"))
                    for schema in schemas
                )
            ):
                errors.append(
                    _error(
                        "malformed_manifest", f"native_schemas is invalid for {owner}"
                    )
                )
            artifact = entry.get("conformance_artifact")
            if not isinstance(artifact, dict) or set(artifact) != {
                "url",
                "revision",
                "sha256",
            }:
                errors.append(
                    _error(
                        "malformed_manifest",
                        f"conformance_artifact is invalid for {owner}",
                    )
                )
            elif (
                not isinstance(artifact["url"], str)
                or not artifact["url"].startswith("https://")
                or not isinstance(artifact["revision"], str)
                or not re.fullmatch(r"[0-9a-f]{40}", artifact["revision"])
                or artifact["revision"] not in artifact["url"]
                or not isinstance(artifact["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
            ):
                errors.append(
                    _error(
                        "stale_source_identity",
                        f"conformance_artifact must use an immutable revision and SHA-256 for {owner}",
                    )
                )
        if participants != sorted(
            participants,
            key=lambda item: item.get("owner", "") if isinstance(item, dict) else "",
        ):
            errors.append(
                _error("malformed_manifest", "participants must be sorted by owner")
            )

    adapters = payload.get("adapters")
    if not isinstance(adapters, list) or not adapters:
        errors.append(_error("malformed_manifest", "adapters must be a non-empty list"))
    else:
        adapter_ids: set[str] = set()
        for entry in adapters:
            required = {"schema", "kind", "identity", "metrics", "source"}
            if (
                not isinstance(entry, dict)
                or not required.issubset(entry)
                or set(entry) - (required | {"digests"})
            ):
                errors.append(
                    _error(
                        "malformed_manifest",
                        "each adapter must contain schema, kind, identity, metrics, source, and optional digests",
                    )
                )
                continue
            schema = entry.get("schema")
            if not isinstance(schema, str) or not schema or schema in adapter_ids:
                errors.append(
                    _error(
                        "duplicate_identifier"
                        if schema in adapter_ids
                        else "malformed_manifest",
                        f"adapter schema is invalid or duplicated: {schema}",
                    )
                )
            else:
                adapter_ids.add(schema)
            if not isinstance(entry.get("kind"), str) or not _IDENTIFIER.fullmatch(
                entry["kind"]
            ):
                errors.append(
                    _error(
                        "malformed_manifest", f"adapter kind is invalid for {schema}"
                    )
                )
            for field in ("identity", "metrics"):
                values = entry.get(field)
                if not isinstance(values, list) or any(
                    not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
                    for value in values
                ):
                    errors.append(
                        _error(
                            "malformed_manifest",
                            f"adapter {field} is invalid for {schema}",
                        )
                    )
            if "digests" in entry:
                values = entry["digests"]
                if not isinstance(values, list) or any(
                    not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
                    for value in values
                ):
                    errors.append(
                        _error(
                            "malformed_manifest",
                            f"adapter digests is invalid for {schema}",
                        )
                    )
            if entry.get("source") != "src/agent_proof/interop.py:ADAPTERS":
                errors.append(
                    _error(
                        "malformed_manifest",
                        f"adapter source is not the reviewed registry for {schema}",
                    )
                )
        if adapters != sorted(
            adapters,
            key=lambda item: item.get("schema", "") if isinstance(item, dict) else "",
        ):
            errors.append(
                _error("malformed_manifest", "adapters must be sorted by schema")
            )

    return _unique_errors(errors)


def check_manifest(path: Path) -> dict[str, Any]:
    """Return the path-bearing compatibility/v1 report shape."""

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
        "manifest": str(path),
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
# Frozen reference metadata, tied to the v1 digest checked below. This is not
# a runtime discovery list: v2 cannot silently change that reviewed owner set.
_V1_REFERENCE_OWNERS = frozenset(
    {
        "agent-policy",
        "agent-proof",
        "agent-resume",
        "agent-sandbox-run",
        "agent-trace-lite",
        "atlas-agent-runtime",
        "chatlens",
        "context-integrity-lab",
        "forgeyard",
        "mcp-doctor",
        "slipstream",
        "sourcemark",
        "worktree-conservator",
    }
)
_DECLARATION_FIELDS = {"schema", "contract_version", "capabilities", "native_protocols"}
_DECLARATION_ENTRY_FIELDS = {"id", "supported_versions"}


def _github_repository(value: Any) -> tuple[str, str] | None:
    """Return canonical GitHub owner/repository parts, or ``None``."""

    if (
        not isinstance(value, str)
        or not value
        or any(char in value for char in ("%", "\\", "\x00"))
    ):
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
    if (
        not _GITHUB_NAME.fullmatch(owner)
        or not _GITHUB_NAME.fullmatch(repository)
        or repository.endswith(".git")
    ):
        return None
    return owner, repository


def _github_artifact(value: Any, repository: str, revision: str) -> bool:
    repo_parts = _github_repository(repository)
    if (
        repo_parts is None
        or not isinstance(value, str)
        or any(char in value for char in ("%", "\\", "\x00"))
    ):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
    ):
        return False
    parts = parsed.path.split("/")
    if (
        len(parts) < 6
        or parts[0] != ""
        or parts[1:4] != [repo_parts[0], repo_parts[1], "blob"]
    ):
        return False
    if parts[4] != revision or not _COMMIT.fullmatch(parts[4]):
        return False
    relative = parts[5:]
    if not relative or any(
        not component or component in {".", ".."} for component in relative
    ):
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
            errors.append(
                _error(
                    "noncanonical_github_ref",
                    "participant repository must be a canonical GitHub HTTPS URL",
                )
            )
            continue
        if not isinstance(artifact, dict):
            continue
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not _COMMIT.fullmatch(revision):
            errors.append(
                _error(
                    "unknown_version",
                    "artifact revision must be a 40-character lowercase commit",
                )
            )
            continue
        if not _github_artifact(artifact.get("url"), repository, revision):
            errors.append(
                _error(
                    "owner_repository_mismatch",
                    "artifact URL is not bound to the participant repository",
                )
            )
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
            errors.append(
                _error(
                    "noncanonical_github_ref",
                    "participant repository must be a canonical GitHub HTTPS URL",
                )
            )
            continue
        if not isinstance(artifact, dict):
            continue
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not _COMMIT.fullmatch(revision):
            errors.append(
                _error(
                    "unknown_version",
                    "artifact revision must be a 40-character lowercase commit",
                )
            )
            continue
        if not _github_artifact(artifact.get("url"), repository, revision):
            errors.append(
                _error(
                    "owner_repository_mismatch",
                    "artifact URL is not bound to the participant repository",
                )
            )
    return errors


def _version_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(type(version) is int and version > 0 for version in value)
        and value == sorted(set(value))
    )


def _protocol_parts(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str) or len(value) > 256:
        return None
    match = re.fullmatch(r"(.+)/v([1-9][0-9]{0,5})", value)
    if match is None or not _CAPABILITY_IDENTIFIER.fullmatch(match.group(1)):
        return None
    return match.group(1), int(match.group(2))


def _native_protocol_errors(value: Any, registry: Any = None) -> list[dict[str, str]]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) for item in value)
    ):
        return [
            _error(
                "unsupported_schema", "native protocols must be a nonempty string list"
            )
        ]
    if len(value) != len(set(value)):
        return [
            _error("duplicate_identifier", "native protocol is declared more than once")
        ]
    admitted = None
    if registry is not None:
        entries = (
            registry.get("native_protocols", []) if isinstance(registry, dict) else []
        )
        admitted = (
            {
                entry["id"]: entry["supported_versions"]
                for entry in entries
                if isinstance(entry, dict)
                and isinstance(entry.get("id"), str)
                and _version_list(entry.get("supported_versions"))
            }
            if isinstance(entries, list)
            else {}
        )
    errors = []
    for item in value:
        parts = _protocol_parts(item)
        if parts is None or parts[0] not in SUPPORTED_NATIVE_PROTOCOL_VERSIONS:
            errors.append(
                _error("unsupported_schema", "native protocol family is not reviewed")
            )
        elif parts[1] not in SUPPORTED_NATIVE_PROTOCOL_VERSIONS[parts[0]]:
            errors.append(
                _error("unknown_version", "native protocol version is not reviewed")
            )
        elif admitted is not None and parts[0] not in admitted:
            errors.append(
                _error(
                    "unsupported_schema",
                    "native protocol is absent from the manifest registry",
                )
            )
        elif admitted is not None and parts[1] not in admitted[parts[0]]:
            errors.append(
                _error(
                    "unknown_version",
                    "native protocol version is absent from the manifest registry",
                )
            )
    return _unique_errors(errors)


def _validate_declaration(
    registry: Any, *, allow_unversioned: bool = False
) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if not isinstance(registry, dict) or set(registry) != _DECLARATION_FIELDS:
        return [
            _error(
                "unsupported_schema",
                "capability declaration must use the reviewed declaration shape",
            )
        ]
    if registry.get("schema") != CAPABILITY_DECLARATION_SCHEMA:
        errors.append(
            _error("unsupported_schema", "capability declaration schema is unsupported")
        )
    if (
        type(registry.get("contract_version")) is not int
        or registry.get("contract_version") != 1
    ):
        errors.append(
            _error(
                "unknown_version",
                "capability declaration contract_version must be the integer 1",
            )
        )
    seen_by_field: dict[str, set[str]] = {
        "capabilities": set(),
        "native_protocols": set(),
    }
    for field in ("capabilities", "native_protocols"):
        entries = registry.get(field)
        if not isinstance(entries, list):
            errors.append(
                _error("malformed_manifest", "capability declarations must be lists")
            )
            continue
        for entry in entries:
            allowed_fields = _DECLARATION_ENTRY_FIELDS | (
                {"native_protocols"} if field == "capabilities" else set()
            )
            if (
                not isinstance(entry, dict)
                or not _DECLARATION_ENTRY_FIELDS.issubset(entry)
                or set(entry) - allowed_fields
            ):
                errors.append(
                    _error(
                        "malformed_manifest",
                        "capability entries must contain id and supported_versions",
                    )
                )
                continue
            identifier = entry.get("id")
            if not isinstance(identifier, str) or not _CAPABILITY_IDENTIFIER.fullmatch(
                identifier
            ):
                errors.append(
                    _error("unsupported_schema", "capability identifier is unsupported")
                )
                continue
            if identifier in seen_by_field[field]:
                errors.append(
                    _error(
                        "duplicate_identifier",
                        "capability identifier is declared more than once",
                    )
                )
            seen_by_field[field].add(identifier)
            versions = entry.get("supported_versions")
            unversioned = (
                allow_unversioned and field == "capabilities" and versions == []
            )
            if not unversioned and not _version_list(versions):
                errors.append(
                    _error(
                        "malformed_version",
                        "supported_versions must be sorted unique positive integers",
                    )
                )
                continue
            registry_versions = (
                SUPPORTED_CAPABILITY_VERSIONS
                if field == "capabilities"
                else SUPPORTED_NATIVE_PROTOCOL_VERSIONS
            )
            known = registry_versions.get(identifier, ())
            if not known:
                errors.append(
                    _error(
                        "unsupported_schema",
                        "capability identifier is absent from the reviewed registry",
                    )
                )
            elif any(version not in known for version in versions):
                errors.append(
                    _error(
                        "unknown_version",
                        "capability declares a version not supported by this checker",
                    )
                )
            if field == "capabilities" and "native_protocols" in entry:
                errors.extend(_native_protocol_errors(entry["native_protocols"]))
        if entries != sorted(
            entries,
            key=lambda item: item.get("id", "")
            if isinstance(item, dict) and isinstance(item.get("id"), str)
            else "",
        ):
            errors.append(
                _error(
                    "malformed_manifest",
                    "capability declarations must be sorted by identifier",
                )
            )
    return errors


def validate_manifest_v2(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """Validate the additive v2 compatibility manifest shape.

    v2 is intentionally separate from :func:`validate_manifest`: v1 remains
    readable under its closed schema and does not acquire v2 meaning.
    """

    errors: list[dict[str, str]] = []
    if not isinstance(payload, dict):
        return [_error("malformed_manifest", "compatibility v2 root must be an object")]
    unknown = set(payload) - _V2_TOP_LEVEL_FIELDS
    if unknown:
        errors.append(
            _error(
                "malformed_manifest",
                "compatibility v2 contains unknown top-level fields",
            )
        )
    if payload.get("schema") != COMPATIBILITY_V2_SCHEMA:
        errors.append(
            _error(
                "unsupported_schema",
                "schema must be agent-systems-lab/compatibility/v2",
            )
        )
    if (
        type(payload.get("contract_version")) is not int
        or payload.get("contract_version") != SUPPORTED_CONTRACT_VERSION_V2
    ):
        errors.append(
            _error("unknown_version", "contract_version must be the integer 2")
        )
    state = payload.get("state")
    if not isinstance(state, str) or state not in {"draft", "complete"}:
        errors.append(_error("malformed_manifest", "state must be draft or complete"))
    if not isinstance(payload.get("authority"), str) or not _IDENTIFIER.fullmatch(
        payload.get("authority", "")
    ):
        errors.append(
            _error("malformed_manifest", "authority must be a bounded identifier")
        )
    if _github_repository(payload.get("repository")) is None:
        errors.append(
            _error(
                "noncanonical_github_ref",
                "repository must be a canonical GitHub HTTPS URL",
            )
        )
    if payload.get("canonicalization") != {
        "encoding": "utf-8",
        "json": "sorted-keys-compact",
        "allow_nan": False,
    }:
        errors.append(
            _error(
                "malformed_manifest",
                "canonicalization does not match the compatibility contract",
            )
        )
    if payload.get("timestamps") != TIMESTAMP_RULES:
        errors.append(
            _error(
                "malformed_manifest",
                "timestamp authority and rewrite rules are required",
            )
        )
    refusal_codes = payload.get("refusal_codes")
    if refusal_codes != list(V2_REFUSAL_CODES):
        errors.append(
            _error(
                "malformed_manifest",
                "refusal_codes must equal the ordered v2 vocabulary",
            )
        )
    errors.extend(
        _validate_declaration(
            payload.get("capability_registry"), allow_unversioned=True
        )
    )

    reference = payload.get("compatibility_v1_reference")
    if reference != {
        "schema": COMPATIBILITY_SCHEMA,
        "manifest_sha256": "4e91ef19b1d4dddb2da41b9065f3a3979df960f5b061308d68bc281ec1ee79ec",
        "participant_count": len(_V1_REFERENCE_OWNERS),
    }:
        errors.append(
            _error(
                "stale_source_identity",
                "v2 must bind the reviewed compatibility/v1 participant set",
            )
        )

    participants = payload.get("participants")
    if not isinstance(participants, list) or not participants:
        errors.append(
            _error("malformed_manifest", "participants must be a non-empty list")
        )
        return _unique_errors(errors)
    owners: set[str] = set()
    for entry in participants:
        participant_fields = {
            "owner",
            "repository",
            "native_schemas",
            "conformance_artifact",
        }
        if (
            not isinstance(entry, dict)
            or not participant_fields.issubset(entry)
            or set(entry)
            - (
                participant_fields
                | {"role", "declared_capabilities", "capability_protocols"}
            )
        ):
            errors.append(
                _error(
                    "malformed_manifest",
                    "each v2 participant must contain owner, repository, and conformance_artifact",
                )
            )
            continue
        owner = entry.get("owner")
        if not isinstance(owner, str) or not _IDENTIFIER.fullmatch(owner):
            errors.append(_error("malformed_manifest", "participant owner is invalid"))
        elif owner in owners:
            errors.append(
                _error(
                    "duplicate_identifier",
                    "participant owner is declared more than once",
                )
            )
        owners.add(owner if isinstance(owner, str) else "")
        repository = entry.get("repository")
        if _github_repository(repository) is None:
            errors.append(
                _error(
                    "noncanonical_github_ref", "participant repository is not canonical"
                )
            )
        native_schemas = entry.get("native_schemas")
        native_schemas_valid = (
            isinstance(native_schemas, list)
            and bool(native_schemas)
            and all(
                isinstance(schema, str) and _CAPABILITY_IDENTIFIER.fullmatch(schema)
                for schema in native_schemas
            )
            and len(native_schemas) == len(set(native_schemas))
        )
        if not native_schemas_valid:
            errors.append(
                _error(
                    "unsupported_schema",
                    "participant native_schemas must be canonical and unique",
                )
            )
        else:
            errors.extend(
                _native_protocol_errors(
                    native_schemas, payload.get("capability_registry")
                )
            )
        if "declared_capabilities" in entry and not _validate_owner_capabilities(
            entry["declared_capabilities"], payload.get("capability_registry")
        ):
            errors.append(
                _error(
                    "capability_declaration_mismatch",
                    "participant capability names are not registered",
                )
            )
        if "capability_protocols" in entry and not _owner_protocol_mapping_valid(
            entry["capability_protocols"], entry, payload.get("capability_registry")
        ):
            errors.append(
                _error(
                    "capability_declaration_mismatch",
                    "participant capability mapping is not bound to its native schemas",
                )
            )
        role = entry.get("role", "unknown")
        if not isinstance(role, str) or role not in {
            "producer",
            "consumer",
            "mixed",
            "unknown",
        }:
            errors.append(
                _error(
                    "malformed_manifest",
                    "participant role must preserve producer, consumer, mixed, or unknown",
                )
            )
        artifact = entry.get("conformance_artifact")
        required_artifact = {
            "url",
            "revision",
            "sha256",
            "format",
            "document_schema",
            "owner_contract",
        }
        optional_artifact = {"role", "provenance", "source_fields"}
        if (
            not isinstance(artifact, dict)
            or not required_artifact.issubset(artifact)
            or set(artifact) - (required_artifact | optional_artifact)
        ):
            errors.append(
                _error(
                    "malformed_manifest",
                    "v2 artifacts must declare format, document schema, and owner contract",
                )
            )
            continue
        if artifact.get("format") == "json" and not _artifact_format_valid(artifact):
            errors.append(
                _error(
                    "content_unvalidated",
                    "JSON artifact must bind at least one reviewed native or handoff field",
                )
            )
        revision = artifact.get("revision")
        if not isinstance(revision, str) or not _COMMIT.fullmatch(revision):
            errors.append(
                _error(
                    "unknown_version",
                    "artifact revision must be a 40-character lowercase commit",
                )
            )
        if not isinstance(artifact.get("sha256"), str) or not _SHA256.fullmatch(
            artifact.get("sha256", "")
        ):
            errors.append(
                _error(
                    "malformed_manifest", "artifact sha256 must be lowercase SHA-256"
                )
            )
        if (
            _github_repository(repository) is not None
            and isinstance(revision, str)
            and _COMMIT.fullmatch(revision)
        ):
            if not _github_artifact(artifact.get("url"), repository, revision):
                errors.append(
                    _error(
                        "owner_repository_mismatch",
                        "artifact URL is not bound to the participant repository",
                    )
                )
        fmt = artifact.get("format")
        if not isinstance(fmt, str) or fmt not in {"bytes", "json", "pending"}:
            errors.append(
                _error(
                    "unsupported_schema",
                    "artifact format must be bytes, json, or pending",
                )
            )
        document_schema = artifact.get("document_schema")
        if fmt == "json" and (
            not isinstance(document_schema, str)
            or not _CAPABILITY_IDENTIFIER.fullmatch(document_schema)
        ):
            errors.append(
                _error(
                    "unsupported_schema",
                    "JSON artifacts must declare a document schema",
                )
            )
        if fmt == "bytes" and document_schema is not None:
            errors.append(
                _error(
                    "malformed_manifest",
                    "byte artifacts cannot declare a document schema",
                )
            )
        if fmt == "pending" and (document_schema is not None or state != "draft"):
            errors.append(
                _error(
                    "malformed_manifest",
                    "pending artifacts are allowed only in an explicitly draft manifest",
                )
            )
        contract = artifact.get("owner_contract")
        expected_contract = {"owner_field", "schema_field"}
        optional_contract = {
            "repository_field",
            "native_schema_selectors",
            "native_schemas_field",
            "capabilities_field",
            "capability_protocols_field",
            "handoff_field",
        }
        if fmt == "json" and (
            not isinstance(contract, dict)
            or not expected_contract.issubset(contract)
            or "repository_field" not in contract
            or set(contract) - (expected_contract | optional_contract)
            or any(
                not isinstance(contract[field], str)
                or not _IDENTIFIER.fullmatch(contract[field])
                for field in expected_contract
            )
        ):
            errors.append(
                _error(
                    "malformed_manifest",
                    "JSON artifacts must declare owner, repository, and schema fields",
                )
            )
        if fmt == "json" and isinstance(contract, dict):
            if (
                "repository_field" in contract
                and contract["repository_field"] is not None
                and (
                    not isinstance(contract["repository_field"], str)
                    or not _IDENTIFIER.fullmatch(contract["repository_field"])
                )
            ):
                errors.append(
                    _error(
                        "malformed_manifest",
                        "JSON artifact repository binding must be a field or null when omitted by the owner",
                    )
                )
            for field in (
                "native_schemas_field",
                "capabilities_field",
                "capability_protocols_field",
                "handoff_field",
            ):
                if field in contract and (
                    not isinstance(contract[field], str)
                    or not _IDENTIFIER.fullmatch(contract[field])
                ):
                    errors.append(
                        _error(
                            "malformed_manifest",
                            "JSON artifact field bindings must be bounded identifiers",
                        )
                    )
            selectors = contract.get("native_schema_selectors")
            if selectors is not None and (
                not isinstance(selectors, list)
                or not selectors
                or any(
                    not isinstance(selector, dict)
                    or not isinstance(selector.get("kind"), str)
                    or selector.get("kind") not in {"field", "list_field"}
                    or set(selector)
                    != (
                        {"kind", "field"}
                        if selector.get("kind") == "field"
                        else {"kind", "field", "item_field"}
                    )
                    or any(
                        not isinstance(selector.get(key), str)
                        or not _IDENTIFIER.fullmatch(selector[key])
                        for key in ("field", "item_field")
                        if key in selector
                    )
                    for selector in selectors
                )
            ):
                errors.append(
                    _error(
                        "malformed_manifest",
                        "native schema selectors must use the reviewed field/list-field forms",
                    )
                )
            if (
                "capabilities_field" in contract
                and "declared_capabilities" not in entry
            ):
                errors.append(
                    _error(
                        "source_unbound",
                        "capability selector requires explicit declaration facts",
                    )
                )
            if (
                "capability_protocols_field" in contract
                and "capability_protocols" not in entry
            ):
                errors.append(
                    _error(
                        "source_unbound",
                        "capability mapping selector requires explicit protocol facts",
                    )
                )
        if (fmt == "json" or "source_fields" in artifact) and not _source_fields_valid(
            artifact.get("source_fields"), native_schemas
        ):
            errors.append(
                _error(
                    "source_unbound",
                    "source-field provenance is not bound to native declarations",
                )
            )
        if fmt == "bytes" and contract is not None:
            errors.append(
                _error(
                    "malformed_manifest",
                    "byte artifacts cannot declare an owner contract",
                )
            )
        if fmt == "pending" and contract is not None:
            errors.append(
                _error(
                    "malformed_manifest",
                    "pending artifacts cannot claim an owner contract",
                )
            )
    if len(participants) != len(_V1_REFERENCE_OWNERS) or owners != _V1_REFERENCE_OWNERS:
        errors.append(
            _error(
                "stale_source_identity",
                "v2 participants must preserve the frozen compatibility/v1 owner identities",
            )
        )
    if participants != sorted(
        participants,
        key=lambda item: item.get("owner", "")
        if isinstance(item, dict) and isinstance(item.get("owner"), str)
        else "",
    ):
        errors.append(
            _error("malformed_manifest", "participants must be sorted by owner")
        )
    return _unique_errors(errors)


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
            "errors": [
                _error("malformed_manifest", "malformed compatibility manifest")
            ],
        }
    errors = validate_manifest_v2(payload)
    errors = _unique_errors(errors)
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


def _artifact_format_valid(artifact: Mapping[str, Any]) -> bool:
    fmt = artifact.get("format")
    if fmt != "json":
        return False
    contract = artifact.get("owner_contract")
    return isinstance(contract, Mapping) and bool(
        contract.get("native_schema_selectors") or contract.get("native_schemas_field")
    )


def negotiate_capability(
    capability: str,
    producer_versions: Any,
    consumer_versions: Any,
    *,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Negotiate one capability through the same explicit registry constraints."""

    def peer(versions: Any) -> dict[str, Any]:
        return {
            "schema": CAPABILITY_DECLARATION_SCHEMA,
            "contract_version": 1,
            "capabilities": [{"id": capability, "supported_versions": versions}],
            "native_protocols": [],
        }

    report = negotiate_capabilities(
        peer(producer_versions), peer(consumer_versions), registry
    )
    if report["results"]:
        return report["results"][0]
    return {
        "schema": NEGOTIATION_REPORT_SCHEMA,
        "ok": False,
        "capability": None,
        "selected_version": None,
        "errors": report["errors"],
    }


def negotiate_capabilities(
    producer: Mapping[str, Any],
    consumer: Mapping[str, Any],
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Intersect explicit peer capability versions and every registry constraint."""
    return _negotiate_declarations(producer, consumer, registry, "capabilities")


def negotiate_native_protocols(
    producer: Mapping[str, Any],
    consumer: Mapping[str, Any],
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Negotiate declared native schema versions, separately from capabilities."""
    return _negotiate_declarations(producer, consumer, registry, "native_protocols")


def _negotiate_declarations(
    producer: Any,
    consumer: Any,
    registry: Any,
    field: str,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    registries = [] if registry is None else [registry]
    peers = []
    for peer in (producer, consumer):
        if not isinstance(peer, Mapping):
            errors.append(
                _error("malformed_manifest", "peer declaration must be an object")
            )
            continue
        if set(peer) - (_DECLARATION_FIELDS | {"capability_registry"}):
            errors.append(
                _error("malformed_manifest", "peer declaration has unknown fields")
            )
        declaration = {key: peer[key] for key in _DECLARATION_FIELDS if key in peer}
        errors.extend(_validate_declaration(declaration))
        peers.append(declaration)
        if "capability_registry" in peer:
            registries.append(peer["capability_registry"])
    if not registries:
        errors.append(
            _error("malformed_manifest", "an explicit reviewed registry is required")
        )
    registries = [
        dict(candidate) if isinstance(candidate, Mapping) else candidate
        for candidate in registries
    ]
    for candidate in registries:
        errors.extend(_validate_declaration(candidate, allow_unversioned=True))
    if errors:
        return {
            "schema": NEGOTIATION_REPORT_SCHEMA,
            "kind": field,
            "ok": False,
            "results": [],
            "errors": _unique_errors(errors),
        }
    pmap, cmap = (
        {entry["id"]: set(entry["supported_versions"]) for entry in peer[field]}
        for peer in peers
    )
    constraints = [
        {entry["id"]: set(entry["supported_versions"]) for entry in candidate[field]}
        for candidate in registries
    ]
    results = []
    for identifier in sorted(pmap.keys() & cmap.keys()):
        common = pmap[identifier] & cmap[identifier]
        missing = any(identifier not in admitted for admitted in constraints)
        for admitted in constraints:
            common &= admitted.get(identifier, set())
        code = "unsupported_schema" if missing else "unsupported_version"
        results.append(
            {
                "schema": NEGOTIATION_REPORT_SCHEMA,
                "capability": identifier,
                "ok": bool(common),
                "selected_version": max(common) if common else None,
                "errors": []
                if common
                else [_error(code, "no jointly admitted version exists")],
            }
        )
    return {
        "schema": NEGOTIATION_REPORT_SCHEMA,
        "kind": field,
        "ok": bool(results) and all(result["ok"] for result in results),
        "results": results,
        "errors": []
        if results
        else [_error("unsupported_version", "no shared declaration exists")],
    }


def _safe_relative_path(path: Path) -> bool:
    if not path.parts or path.is_absolute() or "\x00" in str(path) or "\\" in str(path):
        return False
    return all(part not in {"", ".", ".."} for part in path.parts)


def _open_regular_no_follow(
    root: Path, relative: Path
) -> tuple[int, os.stat_result] | None:
    if not _safe_relative_path(relative):
        return None
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    if not no_follow or not directory or not nonblocking:
        raise CompatibilityInputError("unsafe_path", "safe file opening is unavailable")
    root_fd = directory_fd = file_fd = None
    try:
        root_fd = os.open(root, os.O_RDONLY | directory | no_follow)
        directory_fd = root_fd
        for part in relative.parts[:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | directory | no_follow, dir_fd=directory_fd
            )
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        # Nonblocking prevents a FIFO from waiting for a writer before fstat.
        file_fd = os.open(
            relative.parts[-1],
            os.O_RDONLY | no_follow | nonblocking,
            dir_fd=directory_fd,
        )
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise CompatibilityInputError(
                "unsafe_path", "artifact must be a regular file"
            )
        result = file_fd, info
        file_fd = None  # Transfer this descriptor to the reader exactly once.
        return result
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None
        code = (
            "unsafe_path"
            if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENXIO}
            else "artifact_unavailable"
        )
        raise CompatibilityInputError(code, code.replace("_", " ")) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd is not None:
            os.close(root_fd)


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Detect in-read mutation without treating file times as observation evidence."""
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@dataclass
class _ArtifactReadBudget:
    """Remaining aggregate capacity, charged even when a read later refuses."""

    remaining: int


def _read_artifact(
    root: Path,
    relative: Path,
    max_bytes: int,
    *,
    total_budget: _ArtifactReadBudget | None = None,
) -> tuple[bytes | None, str | None]:
    if type(max_bytes) is not int or max_bytes <= 0:
        return None, "invalid_budget"
    if not _safe_relative_path(relative):
        return None, "unsafe_path"
    try:
        opened = _open_regular_no_follow(root, relative)
    except CompatibilityInputError as exc:
        return None, exc.code
    if opened is None:
        return None, "artifact_missing"
    fd, before = opened
    try:
        if before.st_size > max_bytes:
            return None, "artifact_too_large"
        if total_budget is not None and before.st_size > total_budget.remaining:
            return None, "total_artifact_budget_exceeded"
        chunks: list[bytes] = []
        remaining = (
            max_bytes
            if total_budget is None
            else min(max_bytes, total_budget.remaining)
        )
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            if total_budget is not None:
                total_budget.remaining -= len(chunk)
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after):
            return None, "artifact_changed_during_read"
        data = b"".join(chunks)
        if len(data) > max_bytes:
            return None, "artifact_too_large"
        return data, None
    except OSError:
        return None, "artifact_unavailable"
    finally:
        os.close(fd)


def _owner_contract_matches(
    payload: Any, owner: str, repository: str, schema: str, contract: Mapping[str, Any]
) -> bool:
    if not isinstance(payload, dict):
        return False
    if (
        payload.get(contract["owner_field"]) != owner
        or payload.get(contract["schema_field"]) != schema
    ):
        return False
    repository_field = contract.get("repository_field")
    if "repository" in payload and repository_field != "repository":
        return False
    return repository_field is None or payload.get(repository_field) == repository


def _declared_schema_values(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _select_declared_values(document: Any, selectors: Any) -> list[str] | None:
    if not isinstance(document, dict) or not isinstance(selectors, list):
        return None
    values: list[str] = []
    for selector in selectors:
        if not isinstance(selector, dict):
            return None
        kind = selector.get("kind")
        field = selector.get("field")
        if kind == "field":
            selected = _declared_schema_values(document.get(field))
            if selected is None:
                return None
            values.extend(selected)
        elif kind == "list_field":
            entries = document.get(field)
            item_field = selector.get("item_field")
            if not isinstance(entries, list) or not isinstance(item_field, str):
                return None
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(
                    entry.get(item_field), str
                ):
                    return None
                values.append(entry[item_field])
        else:
            return None
    return values


def _source_fields_valid(facts: Any, native_schemas: Any) -> bool:
    return (
        isinstance(facts, list)
        and bool(facts)
        and all(
            isinstance(fact, dict)
            and set(fact) == {"field", "role", "schema"}
            and isinstance(fact["field"], str)
            and 0 < len(fact["field"]) <= 256
            and isinstance(fact["role"], str)
            and fact["role"] in {"declared_boundary", "declared_input"}
            and _protocol_parts(fact["schema"]) is not None
            for fact in facts
        )
        and [fact["schema"] for fact in facts] == native_schemas
    )


def _source_fields_from_document(
    document: dict[str, Any], contract: Mapping[str, Any]
) -> list[dict[str, str]]:
    selectors = contract.get("native_schema_selectors")
    if selectors is None:
        selectors = [{"kind": "field", "field": contract["native_schemas_field"]}]
    facts = []
    for selector in selectors:
        values = _select_declared_values(document, [selector])
        if values is None:
            return []
        field = selector["field"]
        role = "declared_boundary"
        if selector["kind"] == "list_field":
            if field in {"adapters", "consumer_contracts"}:
                role = "declared_input"
            field += "[]." + selector["item_field"]
        facts.extend(
            {"field": field, "role": role, "schema": value} for value in values
        )
    return facts


def _validate_owner_native_declaration(
    document: Any, entry: Mapping[str, Any], contract: Mapping[str, Any]
) -> bool:
    expected = entry.get("native_schemas")
    selectors = contract.get("native_schema_selectors")
    if selectors is not None:
        actual = _select_declared_values(document, selectors)
    else:
        field = contract.get("native_schemas_field")
        actual = (
            _declared_schema_values(document.get(field))
            if isinstance(document, dict) and isinstance(field, str)
            else None
        )
    return actual == expected


def _validate_owner_handoff(document: Any, contract: Mapping[str, Any]) -> bool:
    field = contract.get("handoff_field")
    if field is None:
        return True
    value = document.get(field) if isinstance(document, dict) else None
    return (
        isinstance(value, dict)
        and value.get("owner") == "agent-proof"
        and value.get("schema") == "agent-proof/interop/v1"
        and isinstance(value.get("manifest_url"), str)
        and isinstance(value.get("revision"), str)
        and _COMMIT.fullmatch(value["revision"]) is not None
    )


def _validate_owner_capabilities(value: Any, registry: Any) -> bool:
    """Require owner-declared capabilities to be in the checked-in registry."""

    if not isinstance(value, list) or any(
        not isinstance(item, str) or not _CAPABILITY_IDENTIFIER.fullmatch(item)
        for item in value
    ):
        return False
    if not isinstance(registry, dict):
        return False
    declared = registry.get("capabilities")
    if not isinstance(declared, list):
        return False
    known = {
        item.get("id")
        for item in declared
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    return len(value) == len(set(value)) and set(value).issubset(known)


def _owner_protocol_mapping_valid(
    value: Any, entry: Mapping[str, Any], registry: Any
) -> bool:
    """Validate native schema bindings without manufacturing capability versions."""
    capabilities = entry.get("declared_capabilities")
    native = entry.get("native_schemas")
    if (
        not isinstance(value, dict)
        or not value
        or not _validate_owner_capabilities(capabilities, registry)
        or not isinstance(native, list)
        or any(not isinstance(item, str) for item in native)
        or set(value) != set(capabilities)
    ):
        return False
    for protocols in value.values():
        if _native_protocol_errors(protocols, registry) or not set(protocols).issubset(
            native
        ):
            return False
    return True


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

    if (
        type(max_bytes) is not int
        or max_bytes <= 0
        or type(max_total_bytes) is not int
        or max_total_bytes <= 0
    ):
        return {
            "schema": ARTIFACT_REPORT_SCHEMA,
            "ok": False,
            "complete": False,
            "remote_state": "not_contacted",
            "execution": "not_attempted",
            "manifest_sha256": None,
            "participants": [],
            "errors": [_stable_path_error("invalid_budget")],
        }
    try:
        payload = load_manifest(manifest_path)
    except CompatibilityInputError as exc:
        return {
            "schema": ARTIFACT_REPORT_SCHEMA,
            "ok": False,
            "complete": False,
            "remote_state": "not_contacted",
            "execution": "not_attempted",
            "manifest_sha256": None,
            "participants": [],
            "errors": [_error(exc.code, str(exc))],
        }
    except ValueError:
        return {
            "schema": ARTIFACT_REPORT_SCHEMA,
            "ok": False,
            "complete": False,
            "remote_state": "not_contacted",
            "execution": "not_attempted",
            "manifest_sha256": None,
            "participants": [],
            "errors": [
                _error("malformed_manifest", "malformed compatibility manifest")
            ],
        }
    structural = validate_manifest_v2(payload)
    digest = manifest_digest(payload)
    participants = payload.get("participants")
    if structural or payload.get("state") != "complete":
        if payload.get("state") == "draft":
            structural.append(
                _error(
                    "manifest_incomplete",
                    "compatibility v2 manifest is explicitly incomplete",
                )
            )
        return {
            "schema": ARTIFACT_REPORT_SCHEMA,
            "ok": False,
            "complete": False,
            "remote_state": "not_contacted",
            "execution": "not_attempted",
            "manifest_sha256": digest,
            "participants": [],
            "errors": _unique_errors(structural),
        }
    if not isinstance(sources, Mapping) or set(sources) - {
        entry["owner"] for entry in participants
    }:
        return {
            "schema": ARTIFACT_REPORT_SCHEMA,
            "ok": False,
            "complete": False,
            "remote_state": "not_contacted",
            "execution": "not_attempted",
            "manifest_sha256": digest,
            "participants": [],
            "errors": [_stable_path_error("source_unbound")],
        }
    reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total_budget = _ArtifactReadBudget(max_total_bytes)
    aggregate_exhausted = False
    for entry in participants:
        owner = entry["owner"]
        artifact = entry["conformance_artifact"]
        source = sources.get(owner)
        report: dict[str, Any] = {
            "owner": owner,
            "state": "not_checked",
            "format": artifact["format"],
        }
        if source is None:
            report["state"] = "unavailable"
            report["error"] = "artifact_not_provided"
            errors.append(_stable_path_error("artifact_not_provided"))
            reports.append(report)
            continue
        if aggregate_exhausted or total_budget.remaining <= 0:
            report["state"] = "refused"
            report["error"] = "total_artifact_budget_exceeded"
            errors.append(_stable_path_error("total_artifact_budget_exceeded"))
            reports.append(report)
            continue
        try:
            selected = (
                source
                if isinstance(source, ArtifactSource)
                else ArtifactSource(Path(source))
            )
            local = Path(selected.path)
            root = Path(artifact_root) if artifact_root is not None else local.parent
        except (TypeError, ValueError):
            report["state"] = "refused"
            report["error"] = "unsafe_path"
            errors.append(_stable_path_error("unsafe_path"))
            reports.append(report)
            continue
        if selected.cache_ref is not None and selected.cache_ref != artifact["url"]:
            report["state"] = "refused"
            report["error"] = "cache_key_mismatch"
            errors.append(_stable_path_error("cache_key_mismatch"))
            reports.append(report)
            continue
        if artifact_root is not None:
            if local.is_absolute():
                try:
                    local = local.relative_to(root)
                except ValueError:
                    report["state"] = "refused"
                    report["error"] = "unsafe_path"
                    errors.append(_stable_path_error("unsafe_path"))
                    reports.append(report)
                    continue
            if not _safe_relative_path(local):
                report["state"] = "refused"
                report["error"] = "unsafe_path"
                errors.append(_stable_path_error("unsafe_path"))
                reports.append(report)
                continue
        else:
            local = Path(local.name)
        data, failure = _read_artifact(
            root, local, max_bytes, total_budget=total_budget
        )
        if failure:
            if failure == "total_artifact_budget_exceeded":
                aggregate_exhausted = True
            report["state"] = (
                "refused"
                if failure
                in {
                    "unsafe_path",
                    "artifact_too_large",
                    "total_artifact_budget_exceeded",
                }
                else "unavailable"
            )
            report["error"] = failure
            errors.append(_stable_path_error(failure))
            reports.append(report)
            continue
        assert data is not None
        actual = hashlib.sha256(data).hexdigest()
        report["sha256"] = actual
        if not hmac.compare_digest(actual, artifact["sha256"]):
            report["state"] = "refused"
            report["error"] = "digest_mismatch"
            errors.append(_stable_path_error("digest_mismatch"))
            reports.append(report)
            continue
        if artifact["format"] == "bytes":
            report["state"] = "unknown"
            report["validation"] = "byte-only"
            report["error"] = "content_unvalidated"
            errors.append(_stable_path_error("content_unvalidated"))
            reports.append(report)
            continue
        report["validation"] = "owner-json"
        if artifact["format"] == "json":
            try:
                decoded = data.decode("utf-8")
                document = _strict_json(decoded)
            except _DuplicateJSONKey:
                report["state"] = "refused"
                report["error"] = "duplicate_json_key"
                errors.append(_stable_path_error("duplicate_json_key"))
                reports.append(report)
                continue
            except _NonFiniteJSONNumber:
                report["state"] = "refused"
                report["error"] = "non_finite_number"
                errors.append(_stable_path_error("non_finite_number"))
                reports.append(report)
                continue
            except _NumericOverflow:
                report["state"] = "refused"
                report["error"] = "numeric_overflow"
                errors.append(_stable_path_error("numeric_overflow"))
                reports.append(report)
                continue
            except _JSONTooDeep:
                report["state"] = "refused"
                report["error"] = "json_too_deep"
                errors.append(_stable_path_error("json_too_deep"))
                reports.append(report)
                continue
            except UnicodeError:
                report["state"] = "refused"
                report["error"] = "invalid_utf8"
                errors.append(_stable_path_error("invalid_utf8"))
                reports.append(report)
                continue
            except ValueError:
                report["state"] = "refused"
                report["error"] = "invalid_json"
                errors.append(_stable_path_error("invalid_json"))
                reports.append(report)
                continue
            repository = entry["repository"]
            expected_schema = artifact["document_schema"]
            contract = artifact["owner_contract"]
            if not _owner_contract_matches(
                document, owner, repository, expected_schema, contract
            ):
                report["state"] = "refused"
                report["error"] = "owner_contract_mismatch"
                errors.append(_stable_path_error("owner_contract_mismatch"))
                reports.append(report)
                continue
            if not _validate_owner_native_declaration(document, entry, contract):
                report["state"] = "refused"
                report["error"] = "native_schema_mismatch"
                errors.append(_stable_path_error("native_schema_mismatch"))
                reports.append(report)
                continue
            if (
                _source_fields_from_document(document, contract)
                != artifact["source_fields"]
            ):
                report["state"] = "refused"
                report["error"] = "source_unbound"
                errors.append(_stable_path_error("source_unbound"))
                reports.append(report)
                continue
            if not _validate_owner_handoff(document, contract):
                report["state"] = "refused"
                report["error"] = "owner_contract_mismatch"
                errors.append(_stable_path_error("owner_contract_mismatch"))
                reports.append(report)
                continue
            capabilities_field = contract.get("capabilities_field")
            if capabilities_field is not None and (
                not _validate_owner_capabilities(
                    document.get(capabilities_field), payload.get("capability_registry")
                )
                or document.get(capabilities_field)
                != entry.get("declared_capabilities")
            ):
                report["state"] = "refused"
                report["error"] = "capability_declaration_mismatch"
                errors.append(_stable_path_error("capability_declaration_mismatch"))
                reports.append(report)
                continue
            capability_protocols_field = contract.get("capability_protocols_field")
            if capability_protocols_field is not None:
                protocols = document.get(capability_protocols_field)
                if protocols != entry.get(
                    "capability_protocols"
                ) or not _owner_protocol_mapping_valid(
                    protocols, entry, payload.get("capability_registry")
                ):
                    report["state"] = "refused"
                    report["error"] = "capability_declaration_mismatch"
                    errors.append(_stable_path_error("capability_declaration_mismatch"))
                    reports.append(report)
                    continue
        if "declared_capabilities" in entry:
            report["capability_versions"] = "not_declared"
        report["state"] = "verified"
        reports.append(report)
    reports.sort(key=lambda item: item["owner"])
    complete = not errors and all(item["state"] == "verified" for item in reports)
    return {
        "schema": ARTIFACT_REPORT_SCHEMA,
        "ok": complete,
        "complete": complete,
        "remote_state": "not_contacted",
        "execution": "not_attempted",
        "manifest_sha256": digest,
        "participants": reports,
        "errors": _unique_errors(errors),
    }
