"""Redacted interoperability envelopes for sibling evidence tools.

The sibling projects in Jonah's portfolio intentionally expose different JSON
contracts.  This module gives them one small, loss-aware handoff format without
pretending that a field which was not emitted by a source is known.  Raw source
values remain outside the normalized envelope; only allowlisted scalar signals,
field-presence information, and content digests cross the boundary.
"""

from __future__ import annotations

from pathlib import Path
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


def _projection(payload: dict[str, Any], adapter: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Project allowlisted, non-secret values while recording omissions."""

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
    known_fields = sorted(
        set(field for field in _STATUS_FIELDS if field in payload)
        | set(field for field in ("exit_code",) if field in payload)
        | set(field for field in adapter["metrics"] if field in payload)
        | set(field for field in adapter["identity"] if field in payload)
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
        fields = projection.get("declared_fields")
        if not isinstance(fields, list) or fields != sorted(set(fields)) or any(not isinstance(item, str) for item in fields):
            errors.append("projection.declared_fields is malformed")
        if isinstance(source, dict) and isinstance(source.get("schema"), str) and isinstance(fields, list):
            adapter = ADAPTERS.get(source["schema"], {})
            allowed_fields = set(_STATUS_FIELDS) | {"exit_code"} | set(adapter.get("identity", ())) | set(adapter.get("metrics", ()))
            if set(fields) - allowed_fields:
                errors.append("projection.declared_fields contains an unsupported field")
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
