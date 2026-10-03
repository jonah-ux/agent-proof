"""Redacted interoperability envelopes for sibling evidence tools.

The sibling projects in Jonah's portfolio intentionally expose different JSON
contracts.  This module gives them one small, loss-aware handoff format without
pretending that a field which was not emitted by a source is known.  Raw source
values remain outside the normalized envelope; only allowlisted scalar signals,
field-presence information, and content digests cross the boundary.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re
from typing import Any

from .ledger import (
    ProofError,
    _HEX64,
    _rooted_file,
    _safe_relative,
    digest_bytes,
    digest_json,
    load_json,
)


INTEROP_SCHEMA = "agent-proof/interop/v1"
INTEROP_VERIFY_SCHEMA = "agent-proof/interop-verify/v1"
FORGEYARD_EVIDENCE_SCHEMA = "ai-work-evidence/v1"

_FORGEYARD_STATUSES = frozenset({"observed", "verified", "failed", "unknown"})
_FORGEYARD_SOURCES = frozenset({"atlas", "chatlens", "forgeyard"})
_FORGEYARD_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FORGEYARD_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_FORGEYARD_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# The registry is deliberately explicit.  A generic JSON file is not evidence
# from a known sibling until its schema has a reviewed adapter here.
ADAPTERS: dict[str, dict[str, Any]] = {
    "agent-policy/v1": {
        "kind": "policy",
        "identity": ("run_id", "policy_id"),
        "metrics": (),
    },
    "agent-sandbox/v1": {
        "kind": "sandbox",
        "identity": ("run_id", "receipt_id"),
        "metrics": ("duration_ms",),
    },
    "agent-sandbox/v2": {
        "kind": "sandbox",
        "identity": (),
        "metrics": ("duration_ms",),
        "digests": ("command_sha256", "stdout_sha256", "stderr_sha256", "receipt_sha256"),
    },
    "agent-eval/v1": {
        "kind": "evaluation",
        "identity": ("run_id", "evaluation_id", "candidate_id"),
        "metrics": ("duration_ms", "item_count", "trial_count"),
    },
    "agent-trace/v1": {
        "kind": "trace",
        "identity": ("run_id", "trace_id"),
        "metrics": ("duration_ms", "event_count", "span_count"),
    },
    "agent-trace/inspect/v1": {
        "kind": "trace-inspect",
        "identity": (),
        "metrics": ("events", "source_lines", "blank_lines", "redactions"),
        "digests": ("raw_sha256", "redacted_sha256"),
    },
    "agent-trace/query/v1": {
        "kind": "trace-query",
        "identity": (),
        "metrics": ("matched",),
    },
    "context-pack/v1": {
        "kind": "context",
        "identity": ("run_id", "pack_id"),
        "metrics": ("source_count", "file_count", "byte_count"),
    },
    "agent-resume/v1": {
        "kind": "resume",
        "identity": ("run_id", "resume_id", "checkpoint_id"),
        "metrics": ("duration_ms", "step_count"),
    },
    "context-integrity/v1": {
        "kind": "context-integrity",
        "identity": ("person_id", "project_id"),
        "metrics": ("citation_count",),
    },
    "mcp-doctor/v1": {
        "kind": "mcp-diagnostics",
        "identity": ("fingerprint",),
        "metrics": (),
    },
    "worktree-conservator.result/v1": {
        "kind": "worktree",
        "identity": ("command",),
        "metrics": (),
    },
    FORGEYARD_EVIDENCE_SCHEMA: {
        "kind": "shared-evidence",
        "identity": ("evidence_id", "source"),
        "metrics": (),
    },
    "agent-proof/v1": {
        "kind": "legacy-proof",
        "identity": ("run_id",),
        "metrics": (),
    },
    "agent-proof/record/v2": {
        "kind": "proof-record",
        "identity": ("run_id",),
        "metrics": ("duration_ms",),
    },
    "agent-proof/ledger/v2": {
        "kind": "proof-ledger",
        "identity": ("run_id",),
        "metrics": ("record_count",),
    },
    "agent-proof/run/v2": {
        "kind": "proof-run",
        "identity": ("run_id",),
        "metrics": ("duration_ms", "record_count"),
    },
    INTEROP_SCHEMA: {
        "kind": "normalized-proof",
        "identity": ("run_id",),
        "metrics": ("record_count",),
    },
}

_STATUS_FIELDS = ("ok", "observed", "partial", "timed_out")


def _validate_forgeyard_evidence(payload: dict[str, Any]) -> None:
    """Validate the public Forgeyard handoff before redaction.

    Forgeyard remains the reference validator for this contract.  Agent Proof
    repeats the small boundary shape here so an untrusted source cannot enter
    the native interop projection with an unsupported version, unsafe path, or
    malformed digest.
    """

    allowed = {
        "schema", "evidence_id", "source", "source_version", "created_at",
        "subject", "summary", "artifacts", "provenance", "status",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ProofError(f"Forgeyard evidence contains unknown fields: {sorted(unknown)}")
    required = allowed - {"artifacts", "provenance"}
    missing = sorted(field for field in required if field not in payload)
    if missing:
        raise ProofError(f"Forgeyard evidence is missing required fields: {', '.join(missing)}")
    if payload.get("schema") != FORGEYARD_EVIDENCE_SCHEMA:
        raise ProofError("unsupported Forgeyard evidence schema")
    evidence_id = payload.get("evidence_id")
    if not isinstance(evidence_id, str) or not _FORGEYARD_EVIDENCE_ID.fullmatch(evidence_id):
        raise ProofError("Forgeyard evidence_id has an invalid format")
    if payload.get("source") not in _FORGEYARD_SOURCES:
        raise ProofError("Forgeyard evidence source is not supported")
    for field in ("source_version", "subject", "summary"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise ProofError(f"Forgeyard evidence {field} must be a bounded non-empty string")
    created_at = payload.get("created_at")
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise ProofError("Forgeyard evidence created_at must be an RFC 3339 UTC timestamp")
    try:
        datetime.fromisoformat(created_at[:-1] + "+00:00")
    except ValueError as exc:
        raise ProofError("Forgeyard evidence created_at must be an RFC 3339 UTC timestamp") from exc
    if payload.get("status") not in _FORGEYARD_STATUSES:
        raise ProofError("Forgeyard evidence status is invalid")
    artifacts = payload.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ProofError("Forgeyard evidence artifacts must be a list")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"name", "size", "sha256"}:
            raise ProofError("Forgeyard artifact must contain only name, size, and sha256")
        name = artifact.get("name")
        if (
            not isinstance(name, str)
            or not _FORGEYARD_ARTIFACT_NAME.fullmatch(name)
            or ".." in name
            or name.startswith("/")
            or "\\" in name
        ):
            raise ProofError("Forgeyard artifact name must be repository-relative")
        if name in seen:
            raise ProofError(f"duplicate Forgeyard artifact name: {name}")
        seen.add(name)
        size = artifact.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ProofError("Forgeyard artifact size must be a non-negative integer")
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not _FORGEYARD_SHA256.fullmatch(digest):
            raise ProofError("Forgeyard artifact sha256 must be lowercase hexadecimal")
    provenance = payload.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ProofError("Forgeyard evidence provenance must be an object")
    for key, value in provenance.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, bool, type(None))):
            raise ProofError("Forgeyard provenance values must be scalar")
        if key.endswith("_sha256") and (not isinstance(value, str) or not _FORGEYARD_SHA256.fullmatch(value)):
            raise ProofError(f"Forgeyard provenance hash is invalid: {key}")


def _source_relative(path: Path, root: Path) -> str:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = root.expanduser().resolve() / candidate
    if candidate.is_symlink():
        raise ProofError(f"interop input may not be a symlink: {path}")
    try:
        relative = candidate.resolve().relative_to(root.expanduser().resolve())
    except ValueError as exc:
        raise ProofError(f"interop input is outside the artifact root: {path}") from exc
    return _safe_relative(relative.as_posix(), "interop source path")


def _state(payload: dict[str, Any], key: str, unknowns: list[str]) -> bool | None:
    if key not in payload:
        unknowns.append(f"{key}_not_declared")
        return None
    value = payload[key]
    if not isinstance(value, bool):
        unknowns.append(f"{key}_malformed")
        return None
    return value


def _optional_int(payload: dict[str, Any], key: str, unknowns: list[str]) -> int | None:
    if key not in payload:
        unknowns.append(f"{key}_not_declared")
        return None
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        unknowns.append(f"{key}_malformed")
        return None
    return value


def _identity(payload: dict[str, Any], fields: tuple[str, ...], unknowns: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for field in fields:
        if field not in payload:
            continue
        value = payload[field]
        if isinstance(value, str) and value:
            result[f"{field}_sha256"] = digest_bytes(value.encode("utf-8"))
        else:
            unknowns.append(f"{field}_malformed")
    return result


def _digests(payload: dict[str, Any], fields: tuple[str, ...], unknowns: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for field in fields:
        if field not in payload:
            unknowns.append(f"{field}_not_declared")
            continue
        value = payload[field]
        if isinstance(value, str) and _HEX64.fullmatch(value):
            result[field] = value
        else:
            unknowns.append(f"{field}_malformed")
    return result


def _projection(payload: dict[str, Any], adapter: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Project allowlisted, non-secret values while recording omissions."""

    if adapter["kind"] == "shared-evidence":
        _validate_forgeyard_evidence(payload)
        shared_status = payload["status"]
        status_to_ok: dict[str, bool | None] = {
            "observed": True,
            "verified": True,
            "failed": False,
            "unknown": None,
        }
        status_to_outcome: dict[str, str | None] = {
            "observed": "success",
            "verified": "success",
            "failed": "failure",
            "unknown": None,
        }
        artifacts = [
            {"name": item["name"], "size": item["size"], "sha256": item["sha256"]}
            for item in payload.get("artifacts", [])
        ]
        unknowns = ["outcome_unknown"] if shared_status == "unknown" else []
        return {
            "status": {
                "shared": shared_status,
                "ok": status_to_ok[shared_status],
                "observed": shared_status != "unknown",
                "partial": None,
                "timed_out": None,
                "outcome": status_to_outcome[shared_status],
                "exit_code": None,
            },
            "identity": _identity(payload, adapter["identity"], unknowns),
            "metrics": {},
            "artifacts": artifacts,
            "declared_fields": [
                "artifacts", "evidence_id", "source", "status",
            ],
        }, _unique(unknowns)

    unknowns: list[str] = []
    status = {field: _state(payload, field, unknowns) for field in _STATUS_FIELDS}
    # ``outcome`` is only a restatement of an explicit boolean ``ok``.  It is
    # never inferred from an exit code, timeout, or a truthy arbitrary field.
    outcome = None if status["ok"] is None else ("success" if status["ok"] else "failure")
    exit_code = _optional_int(payload, "exit_code", unknowns)
    metrics: dict[str, int] = {}
    for key in adapter["metrics"]:
        if key not in payload:
            unknowns.append(f"{key}_not_declared")
            continue
        value = payload[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            unknowns.append(f"{key}_malformed")
            continue
        metrics[key] = value
    digests = _digests(payload, adapter.get("digests", ()), unknowns)
    known_fields = sorted(
        set(field for field in _STATUS_FIELDS if field in payload)
        | set(field for field in ("exit_code",) if field in payload)
        | set(field for field in adapter["metrics"] if field in payload)
        | set(field for field in adapter["identity"] if field in payload)
        | set(field for field in adapter.get("digests", ()) if field in payload)
    )
    return {
        "status": {
            "ok": status["ok"],
            "observed": status["observed"],
            "partial": status["partial"],
            "timed_out": status["timed_out"],
            "outcome": outcome,
            "exit_code": exit_code,
        },
        "identity": _identity(payload, adapter["identity"], unknowns),
        "metrics": metrics,
        "declared_fields": known_fields,
        **({"digests": digests} if adapter.get("digests") else {}),
    }, _unique(unknowns)


def _unique(values: list[str]) -> list[str]:
    return sorted(set(values))


def normalize_payload(
    payload: dict[str, Any],
    *,
    source_path: str,
    source_size: int,
    source_sha256: str,
) -> dict[str, Any]:
    """Normalize a loaded sibling payload into ``interop/v1``."""

    if not isinstance(payload, dict):
        raise ProofError("interop source must be a JSON object")
    source_schema = payload.get("schema")
    if source_schema not in ADAPTERS:
        raise ProofError(f"unsupported interop source schema: {source_schema!r}")
    if source_schema == INTEROP_SCHEMA:
        raise ProofError("interop/v1 cannot be normalized again")
    adapter = ADAPTERS[source_schema]
    projection, unknowns = _projection(payload, adapter)
    normalized: dict[str, Any] = {
        "schema": INTEROP_SCHEMA,
        "source": {
            "path": _safe_relative(source_path, "interop source path"),
            "schema": source_schema,
            "size": source_size,
            "sha256": source_sha256,
        },
        "adapter": {
            "kind": adapter["kind"],
            "name": source_schema,
            "version": "1",
        },
        "projection": projection,
        "unknowns": unknowns,
        "notes": [
            "Allowlisted scalar projection only; raw source values remain external.",
            "Missing source fields remain explicit unknowns.",
        ],
    }
    normalized["interop_sha256"] = digest_json(normalized)
    return normalized


def normalize_envelope(path: Path, *, artifact_root: Path) -> dict[str, Any]:
    """Read and normalize one known sibling envelope under ``artifact_root``."""

    root = artifact_root.expanduser().resolve()
    relative = _source_relative(path, root)
    target = _rooted_file(root, relative, "interop input")
    payload = load_json(target)
    return normalize_payload(
        payload,
        source_path=relative,
        source_size=target.stat().st_size,
        source_sha256=digest_bytes(target.read_bytes()),
    )


def _unsigned(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result.pop("interop_sha256", None)
    return result


def _shape_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != INTEROP_SCHEMA:
        errors.append(f"unsupported interop schema: {document.get('schema')!r}")
    source = document.get("source")
    if not isinstance(source, dict):
        errors.append("source must be an object")
    else:
        try:
            _safe_relative(source.get("path"), "source.path")
        except ProofError as exc:
            errors.append(str(exc))
        if not isinstance(source.get("schema"), str) or source.get("schema") not in ADAPTERS or source.get("schema") == INTEROP_SCHEMA:
            errors.append("source.schema is unsupported")
        if not isinstance(source.get("size"), int) or isinstance(source.get("size"), bool) or source.get("size", -1) < 0:
            errors.append("source.size is invalid")
        if not isinstance(source.get("sha256"), str) or not _HEX64.fullmatch(source.get("sha256", "")):
            errors.append("source.sha256 is malformed")
    adapter = document.get("adapter")
    if not isinstance(adapter, dict):
        errors.append("adapter must be an object")
    else:
        for key in ("kind", "name", "version"):
            if not isinstance(adapter.get(key), str) or not adapter[key]:
                errors.append(f"adapter.{key} is missing")
        if isinstance(source, dict) and isinstance(source.get("schema"), str) and isinstance(adapter.get("name"), str):
            expected = ADAPTERS.get(source["schema"])
            if expected is not None:
                if adapter.get("name") != source["schema"]:
                    errors.append("adapter.name does not match source.schema")
                if adapter.get("kind") != expected["kind"]:
                    errors.append("adapter.kind does not match source schema")
                if adapter.get("version") != "1":
                    errors.append("adapter.version is unsupported")
    projection = document.get("projection")
    if not isinstance(projection, dict):
        errors.append("projection must be an object")
    else:
        source_schema = source.get("schema") if isinstance(source, dict) else None
        status = projection.get("status")
        if not isinstance(status, dict):
            errors.append("projection.status must be an object")
        else:
            for key in ("ok", "observed", "partial", "timed_out"):
                if status.get(key) is not None and not isinstance(status.get(key), bool):
                    errors.append(f"projection.status.{key} must be boolean or null")
            if status.get("outcome") not in {None, "success", "failure"}:
                errors.append("projection.status.outcome is invalid")
            if status.get("ok") is None and status.get("outcome") is not None:
                errors.append("projection.status.outcome requires an explicit ok field")
            if status.get("ok") is True and status.get("outcome") != "success":
                errors.append("projection.status.outcome disagrees with ok")
            if status.get("ok") is False and status.get("outcome") != "failure":
                errors.append("projection.status.outcome disagrees with ok")
            if status.get("exit_code") is not None and (not isinstance(status.get("exit_code"), int) or isinstance(status.get("exit_code"), bool) or status.get("exit_code") < 0):
                errors.append("projection.status.exit_code is invalid")
            if source_schema == FORGEYARD_EVIDENCE_SCHEMA:
                shared = status.get("shared")
                expected_ok = {
                    "observed": True,
                    "verified": True,
                    "failed": False,
                    "unknown": None,
                }
                expected_outcome = {
                    "observed": "success",
                    "verified": "success",
                    "failed": "failure",
                    "unknown": None,
                }
                if shared not in _FORGEYARD_STATUSES:
                    errors.append("projection.status.shared is invalid")
                elif status.get("ok") != expected_ok[shared] or status.get("outcome") != expected_outcome[shared]:
                    errors.append("projection.status does not preserve Forgeyard status")
                if not isinstance(status.get("observed"), bool):
                    errors.append("projection.status.observed must be boolean")
                if status.get("partial") is not None or status.get("timed_out") is not None or status.get("exit_code") is not None:
                    errors.append("Forgeyard projection status cannot invent execution fields")
        identity = projection.get("identity")
        if not isinstance(identity, dict) or any(not isinstance(key, str) or not key.endswith("_sha256") or not isinstance(value, str) or not _HEX64.fullmatch(value) for key, value in (identity.items() if isinstance(identity, dict) else [])):
            errors.append("projection.identity is malformed")
        if isinstance(source, dict) and isinstance(source.get("schema"), str) and isinstance(identity, dict):
            allowed_identity = {f"{field}_sha256" for field in ADAPTERS.get(source["schema"], {}).get("identity", ())}
            if set(identity) - allowed_identity:
                errors.append("projection.identity contains an unsupported field")
        metrics = projection.get("metrics")
        if not isinstance(metrics, dict) or any(not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool) or value < 0 for key, value in (metrics.items() if isinstance(metrics, dict) else [])):
            errors.append("projection.metrics is malformed")
        if isinstance(source, dict) and isinstance(source.get("schema"), str) and isinstance(metrics, dict):
            allowed_metrics = set(ADAPTERS.get(source["schema"], {}).get("metrics", ()))
            if set(metrics) - allowed_metrics:
                errors.append("projection.metrics contains an unsupported field")
        digests = projection.get("digests")
        if digests is not None:
            if not isinstance(digests, dict) or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not _HEX64.fullmatch(value)
                for key, value in (digests.items() if isinstance(digests, dict) else [])
            ):
                errors.append("projection.digests is malformed")
            if isinstance(source, dict) and isinstance(source.get("schema"), str) and isinstance(digests, dict):
                allowed_digests = set(ADAPTERS.get(source["schema"], {}).get("digests", ()))
                if set(digests) - allowed_digests:
                    errors.append("projection.digests contains an unsupported field")
        fields = projection.get("declared_fields")
        if not isinstance(fields, list) or fields != sorted(set(fields)) or any(not isinstance(item, str) for item in fields):
            errors.append("projection.declared_fields is malformed")
        if isinstance(source, dict) and isinstance(source.get("schema"), str) and isinstance(fields, list):
            adapter = ADAPTERS.get(source["schema"], {})
            allowed_fields = set(_STATUS_FIELDS) | {"exit_code"} | set(adapter.get("identity", ())) | set(adapter.get("metrics", ()))
            allowed_fields |= set(adapter.get("digests", ()))
            if source["schema"] == FORGEYARD_EVIDENCE_SCHEMA:
                allowed_fields |= {"artifacts", "status"}
            if set(fields) - allowed_fields:
                errors.append("projection.declared_fields contains an unsupported field")
        if source_schema == FORGEYARD_EVIDENCE_SCHEMA:
            artifacts = projection.get("artifacts")
            if not isinstance(artifacts, list):
                errors.append("projection.artifacts must be a list")
            else:
                seen: set[str] = set()
                for artifact in artifacts:
                    if not isinstance(artifact, dict) or set(artifact) != {"name", "size", "sha256"}:
                        errors.append("projection.artifact is malformed")
                        continue
                    name = artifact.get("name")
                    if (
                        not isinstance(name, str)
                        or not _FORGEYARD_ARTIFACT_NAME.fullmatch(name)
                        or ".." in name
                        or name.startswith("/")
                        or "\\" in name
                    ):
                        errors.append("projection.artifact name is unsafe")
                    elif name in seen:
                        errors.append("projection.artifacts contains a duplicate name")
                    seen.add(name)
                    size = artifact.get("size")
                    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                        errors.append("projection.artifact size is invalid")
                    if not isinstance(artifact.get("sha256"), str) or not _FORGEYARD_SHA256.fullmatch(artifact.get("sha256", "")):
                        errors.append("projection.artifact sha256 is malformed")
    unknowns = document.get("unknowns")
    if not isinstance(unknowns, list) or unknowns != sorted(set(unknowns)) or any(not isinstance(item, str) or not item for item in unknowns):
        errors.append("unknowns must be sorted unique strings")
    notes = document.get("notes")
    if not isinstance(notes, list) or any(not isinstance(item, str) for item in notes):
        errors.append("notes must be a list of strings")
    return errors


def verify_interop(
    document: dict[str, Any],
    *,
    artifact_root: Path | None = None,
    source_path: Path | None = None,
    require_input: bool = False,
) -> dict[str, Any]:
    """Verify an interop envelope, optionally against its source bytes."""

    shape_errors = _shape_errors(document) if isinstance(document, dict) else ["interop document must be an object"]
    errors = list(shape_errors)
    supplied = document.get("interop_sha256") if isinstance(document, dict) else None
    hash_valid = False
    if not isinstance(supplied, str) or not _HEX64.fullmatch(supplied):
        errors.append("interop_sha256 is missing or malformed")
    elif supplied != digest_json(_unsigned(document)):
        errors.append("interop_sha256 does not match canonical content")
    else:
        hash_valid = True

    source_state = "unbound"
    bound_path = source_path
    if bound_path is None and artifact_root is not None and isinstance(document, dict) and isinstance(document.get("source"), dict):
        relative = document["source"].get("path")
        if isinstance(relative, str):
            bound_path = Path(relative)
    if bound_path is not None:
        if artifact_root is None:
            errors.append("artifact root is required for source-bound interop verification")
            source_state = "invalid"
        else:
            try:
                root = artifact_root.expanduser().resolve()
                candidate = bound_path.expanduser()
                if not candidate.is_absolute():
                    candidate = root / candidate
                relative = _source_relative(candidate, root)
                target = _rooted_file(root, relative, "interop source")
                source_payload = load_json(target)
                source_entry = document.get("source", {})
                if relative != source_entry.get("path"):
                    errors.append("source path does not match normalized envelope")
                if target.stat().st_size != source_entry.get("size") or digest_bytes(target.read_bytes()) != source_entry.get("sha256"):
                    errors.append(f"source digest or size mismatch: {relative}")
                regenerated = normalize_payload(
                    source_payload,
                    source_path=relative,
                    source_size=target.stat().st_size,
                    source_sha256=digest_bytes(target.read_bytes()),
                )
                if _unsigned(regenerated) != _unsigned(document):
                    errors.append("normalized projection does not match source")
                source_state = "verified" if not errors else "invalid"
            except ProofError as exc:
                errors.append(str(exc))
                source_state = "invalid"
    if source_state == "unbound" and require_input:
        errors.append("source-bound interop verification is required")
    unknowns = list(document.get("unknowns", [])) if isinstance(document, dict) and isinstance(document.get("unknowns"), list) else []
    if source_state == "unbound" and "source_not_bound" not in unknowns:
        unknowns.append("source_not_bound")
    unknowns = _unique(unknowns)
    return {
        "schema": INTEROP_VERIFY_SCHEMA,
        "ok": not errors,
        "integrity": not shape_errors and hash_valid,
        "source_state": source_state,
        "source_sha256": document.get("source", {}).get("sha256") if isinstance(document, dict) and isinstance(document.get("source"), dict) else None,
        "interop_sha256": supplied if isinstance(supplied, str) else None,
        "unknowns": unknowns,
        "errors": sorted(set(errors)),
    }
