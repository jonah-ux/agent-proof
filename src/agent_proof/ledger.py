"""Hash-linked evidence records for Agent Proof.

The module deliberately keeps the evidence model independent of sibling tools.  A
caller can hand it the JSON output from a policy, sandbox, evaluation, trace, or
resume tool, and Agent Proof records the file's schema and digest without treating
historical input as an instruction.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
from typing import Any, Iterable


RECORD_SCHEMA = "agent-proof/record/v2"
LEDGER_SCHEMA = "agent-proof/ledger/v2"
RUN_SCHEMA = "agent-proof/run/v2"
VERIFY_SCHEMA = "agent-proof/verify/v2"
EXPORT_SCHEMA = "agent-proof/export/v2"
COLLECT_SCHEMA = "agent-proof/collect/v2"
BUNDLE_VERIFY_SCHEMA = "agent-proof/bundle-verify/v1"
LEGACY_SCHEMA = "agent-proof/v1"
GRAPH_ARCHIVE_PATH = "proof/graph.json"

COLLECTABLE_SCHEMAS = {
    "agent-policy/v1": "policy decision",
    "agent-sandbox/v1": "sandbox receipt",
    "agent-eval/v1": "evaluation result",
    "agent-trace/v1": "trace summary",
    "context-pack/v1": "context pack",
    "agent-resume/v1": "continuation record",
    "context-integrity/v1": "context integrity admission",
    "ai-work-evidence/v1": "Forgeyard shared evidence",
    "agent-proof/v1": "legacy proof envelope",
    RECORD_SCHEMA: "proof record",
    LEDGER_SCHEMA: "proof ledger",
    RUN_SCHEMA: "proof run",
    "agent-proof/interop/v1": "normalized interoperability envelope",
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-fA-F]{7,64}$")


class ProofError(ValueError):
    """A user-correctable evidence or input refusal."""


def canonical_bytes(value: Any) -> bytes:
    """Serialize JSON in the one form used for every digest."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProofError(f"value is not canonical JSON: {exc}") from exc


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
    except OSError as exc:
        raise ProofError(f"cannot read evidence file {path}: {exc}") from exc
    return hasher.hexdigest()


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _as_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProofError(f"{label} must be an object")
    return value


def _as_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ProofError(f"{label} must be a non-empty string")
    return value


def _as_string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProofError(f"{label} must be a list of strings")
    return list(value)


def _unique_strings(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def _safe_relative(value: Any, label: str) -> str:
    text = _as_string(value, label)
    path = Path(text)
    if path.is_absolute() or text in {".", ".."} or ".." in path.parts:
        raise ProofError(f"{label} must be a relative path without '..'")
    if any(part == "" for part in path.parts):
        raise ProofError(f"{label} contains an empty path component")
    return path.as_posix()


def _rooted_file(root: Path | None, relative: str, label: str) -> Path:
    if root is None:
        raise ProofError(f"--artifact-root is required to verify {label}")
    root = root.expanduser().resolve()
    candidate = root
    for part in Path(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ProofError(f"{label} may not traverse a symlink: {relative}")
    target = candidate.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ProofError(f"{label} escapes the artifact root") from exc
    if target.is_symlink() or not target.is_file():
        raise ProofError(f"{label} is missing or is not a regular file: {relative}")
    return target


def _file_entry(item: Any, root: Path | None, label: str, *, load_json_schema: bool = False) -> dict[str, Any]:
    if isinstance(item, str):
        item = {"path": item}
    item = _as_mapping(item, label)
    relative = _safe_relative(item.get("path"), f"{label}.path")
    target = _rooted_file(root, relative, label)
    size = target.stat().st_size
    entry: dict[str, Any] = {
        "label": str(item.get("label", Path(relative).name)),
        "path": relative,
        "size": size,
        "sha256": digest_file(target),
    }
    if load_json_schema:
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProofError(f"{label} is not readable JSON: {relative}: {exc}") from exc
        if isinstance(payload, dict):
            schema = payload.get("schema")
            if isinstance(schema, str):
                entry["schema"] = schema
    return entry


def _hash_text(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ProofError(f"{label} must be a string")
    encoded = value.encode("utf-8")
    return {"bytes": len(encoded), "sha256": digest_bytes(encoded)}


def _hash_environment(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ProofError("operation.environment must be an object")
    entries = []
    for key in sorted(value):
        if not isinstance(key, str) or not key:
            raise ProofError("operation.environment keys must be non-empty strings")
        raw = value[key]
        if not isinstance(raw, str):
            raise ProofError(f"operation.environment[{key!r}] must be a string")
        entries.append({"key": key, "value_sha256": digest_bytes(raw.encode("utf-8"))})
    return entries


def _repository(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    value = _as_mapping(value, "repository")
    result: dict[str, str] = {}
    for key in ("url", "branch", "commit"):
        if value.get(key) is not None:
            result[key] = _as_string(value[key], f"repository.{key}")
    if "commit" in result and not _COMMIT.fullmatch(result["commit"]):
        raise ProofError("repository.commit must be a Git commit SHA")
    return result


def _verify_repository(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("repository must be an object")
        return
    try:
        if _repository(value) != value:
            errors.append("repository contains unsupported or noncanonical fields")
    except ProofError:
        errors.append("repository fields are malformed")


def _record_without_digest(record: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(record)
    unsigned.pop("record_sha256", None)
    return unsigned


def record_digest(record: dict[str, Any]) -> str:
    return digest_json(_record_without_digest(record))


def ledger_digest(ledger: dict[str, Any]) -> str:
    unsigned = dict(ledger)
    unsigned.pop("ledger_sha256", None)
    return digest_json(unsigned)


def run_digest(run: dict[str, Any]) -> str:
    unsigned = dict(run)
    unsigned.pop("run_sha256", None)
    return digest_json(unsigned)


def build_record(spec: dict[str, Any] | None = None, *, artifact_root: Path | None = None) -> dict[str, Any]:
    """Build a redacted, self-hashing v2 record from a JSON specification."""

    spec = _as_mapping(spec or {}, "record spec")
    run_id = _as_string(spec.get("run_id", "standalone"), "run_id")
    actor = _as_string(spec.get("actor", "unknown"), "actor")
    recorded_at = _as_string(spec.get("recorded_at", utc_now()), "recorded_at")

    operation = _as_mapping(spec.get("operation", {}), "operation")
    argv = _as_string_list(operation.get("argv", []), "operation.argv")
    cwd = operation.get("cwd")
    if cwd is not None:
        cwd = _as_string(cwd, "operation.cwd", allow_empty=True)

    result = _as_mapping(spec.get("result", {}), "result")
    exit_code = result.get("exit_code")
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        raise ProofError("result.exit_code must be an integer or null")
    duration_ms = result.get("duration_ms")
    if duration_ms is not None and (not isinstance(duration_ms, int) or duration_ms < 0):
        raise ProofError("result.duration_ms must be a non-negative integer or null")
    unknowns = _unique_strings(_as_string_list(result.get("unknowns", []), "result.unknowns"))
    observed = result.get("observed", False)
    partial = result.get("partial", False)
    if not isinstance(observed, bool) or not isinstance(partial, bool):
        raise ProofError("result.observed and result.partial must be booleans")

    sources = [_file_entry(item, artifact_root, "source", load_json_schema=True) for item in spec.get("sources", [])]
    artifacts = [_file_entry(item, artifact_root, "artifact") for item in spec.get("artifacts", [])]
    notes = _as_string_list(spec.get("notes", []), "notes")
    if len(notes) > 64:
        raise ProofError("notes may contain at most 64 entries")

    record: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "run_id": run_id,
        "sequence": int(spec.get("sequence", 1)),
        "prev_sha256": spec.get("prev_sha256"),
        "recorded_at": recorded_at,
        "actor": actor,
        "repository": _repository(spec.get("repository")),
        "operation": {
            "argv": argv,
            "cwd": cwd,
            "environment": _hash_environment(operation.get("environment", operation.get("env"))),
        },
        "result": {
            "exit_code": exit_code,
            "timed_out": bool(result.get("timed_out", False)),
            "duration_ms": duration_ms,
            "stdout": _hash_text(result.get("stdout", ""), "result.stdout"),
            "stderr": _hash_text(result.get("stderr", ""), "result.stderr"),
            "observed": observed,
            "partial": partial,
            "unknowns": unknowns,
        },
        "sources": sources,
        "artifacts": artifacts,
        "notes": notes,
    }
    if not isinstance(record["sequence"], int) or record["sequence"] < 1:
        raise ProofError("sequence must be a positive integer")
    if record["prev_sha256"] is not None and not isinstance(record["prev_sha256"], str):
        raise ProofError("prev_sha256 must be a 64-character digest or null")
    if isinstance(record["prev_sha256"], str) and not _HEX64.fullmatch(record["prev_sha256"]):
        raise ProofError("prev_sha256 must be a 64-character lowercase digest")
    record["record_sha256"] = record_digest(record)
    return record


def _relative_input(path: Path, artifact_root: Path) -> str:
    try:
        relative = path.expanduser().resolve().relative_to(artifact_root.expanduser().resolve())
    except ValueError as exc:
        raise ProofError(f"collect input is outside the artifact root: {path}") from exc
    return _safe_relative(relative.as_posix(), "collect input")


def _source_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract only explicit result fields; never infer success from arbitrary content."""

    observed = payload.get("observed") is True
    partial = payload.get("partial") is True
    unknowns: list[str] = []
    if "observed" not in payload:
        unknowns.append("source_observation_not_explicit")
    if payload.get("ok") is False:
        unknowns.append("source_reported_failure")
    if payload.get("partial") is True:
        unknowns.append("source_reported_partial")
    coverage = payload.get("coverage")
    if isinstance(coverage, dict) and coverage.get("status") not in (None, "complete"):
        partial = True
        unknowns.append("source_coverage_partial")
    if payload.get("schema") == "agent-proof/interop/v1":
        # A normalized envelope is itself a reviewed source contract.  Reuse
        # only its explicit nested status and carry its loss-aware unknowns;
        # arbitrary nested keys are never interpreted by collect.
        projection = payload.get("projection")
        status = projection.get("status") if isinstance(projection, dict) else None
        if isinstance(status, dict):
            if isinstance(status.get("observed"), bool):
                observed = status["observed"]
            else:
                unknowns.append("interop_observation_unknown")
            if isinstance(status.get("partial"), bool):
                partial = partial or status["partial"]
            else:
                unknowns.append("interop_partial_unknown")
            if status.get("ok") is False:
                unknowns.append("source_reported_failure")
        declared_unknowns = payload.get("unknowns")
        if isinstance(declared_unknowns, list):
            unknowns.extend(item for item in declared_unknowns if isinstance(item, str))
    exit_code = payload.get("exit_code") if isinstance(payload.get("exit_code"), int) else None
    duration_ms = payload.get("duration_ms") if isinstance(payload.get("duration_ms"), int) else None
    return {
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": "",
        "stderr": "",
        "observed": observed,
        "partial": partial,
        "unknowns": _unique_strings(unknowns),
    }


def collect_ledger(
    inputs: Iterable[Path],
    *,
    run_id: str,
    actor: str = "agent-proof-collect",
    artifact_root: Path,
    repository: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Collect known sibling envelopes into a deterministic verified ledger.

    Inputs are sorted by their root-relative path. Their bytes stay outside the ledger;
    each record binds one source file by size, digest, and recognized schema. Unknown
    schemas, duplicate paths, symlinks, malformed JSON, and root escapes refuse the
    complete collection instead of producing a partial ledger that looks complete.
    """

    root = artifact_root.expanduser().resolve()
    paths = list(inputs)
    if not paths:
        raise ProofError("collect requires at least one --input")
    relative_paths = [_relative_input(path, root) for path in paths]
    if len(set(relative_paths)) != len(relative_paths):
        raise ProofError("collect inputs contain duplicate relative paths")
    ordered = sorted(relative_paths)
    ledger = make_ledger(run_id)
    collected_schemas: list[str] = []
    for relative in ordered:
        target = _rooted_file(root, relative, "collect input")
        payload = load_json(target)
        schema = payload.get("schema")
        if schema not in COLLECTABLE_SCHEMAS:
            raise ProofError(f"unsupported collect input schema for {relative}: {schema!r}")
        if schema == "agent-proof/interop/v1":
            from .interop import verify_interop

            interop_result = verify_interop(payload, artifact_root=root, require_input=True)
            if not interop_result["ok"]:
                raise ProofError("invalid normalized interoperability input: " + "; ".join(interop_result["errors"]))
        collected_schemas.append(schema)
        spec = {
            "run_id": run_id,
            "actor": actor,
            "repository": repository or {},
            "operation": {"argv": ["agent-proof", "collect", relative]},
            "result": _source_result(payload),
            "sources": [{"path": relative, "label": COLLECTABLE_SCHEMAS[schema]}],
            "notes": [f"Ingested {schema} as evidence input; source bytes remain external."],
        }
        record = build_record(spec, artifact_root=root)
        ledger = append_record(ledger, record, artifact_root=root)
    return ledger, collected_schemas


def _verify_file_entries(entries: Any, artifact_root: Path | None, label: str, errors: list[str]) -> str:
    if not isinstance(entries, list):
        errors.append(f"{label} must be a list")
        return "invalid"
    if artifact_root is None and entries:
        return "unverified"
    for index, entry in enumerate(entries):
        try:
            entry = _as_mapping(entry, f"{label}[{index}]")
            relative = _safe_relative(entry.get("path"), f"{label}[{index}].path")
            target = _rooted_file(artifact_root, relative, f"{label}[{index}]")
            actual_size = target.stat().st_size
            actual_digest = digest_file(target)
            if actual_size != entry.get("size") or actual_digest != entry.get("sha256"):
                errors.append(f"{label}[{index}] digest or size mismatch: {relative}")
            if "schema" in entry:
                try:
                    payload = json.loads(target.read_text(encoding="utf-8"))
                    if not isinstance(payload, dict) or payload.get("schema") != entry["schema"]:
                        errors.append(f"{label}[{index}] schema mismatch: {relative}")
                except (OSError, UnicodeError, json.JSONDecodeError):
                    errors.append(f"{label}[{index}] is not readable JSON: {relative}")
        except ProofError as exc:
            errors.append(str(exc))
    return "verified" if not errors else "invalid"


def verify_record(record: dict[str, Any], *, artifact_root: Path | None = None) -> dict[str, Any]:
    errors: list[str] = []
    if record.get("schema") != RECORD_SCHEMA:
        errors.append(f"unsupported record schema: {record.get('schema')!r}")
    supplied = record.get("record_sha256")
    if not isinstance(supplied, str) or not _HEX64.fullmatch(supplied):
        errors.append("record_sha256 is missing or malformed")
    elif supplied != record_digest(record):
        errors.append("record_sha256 does not match canonical record content")
    if type(record.get("sequence")) is not int or record["sequence"] < 1:
        errors.append("sequence is missing or invalid")
    if not isinstance(record.get("run_id"), str) or not record["run_id"]:
        errors.append("run_id is missing or malformed")
    _verify_repository(record.get("repository", {}), errors)
    previous = record.get("prev_sha256")
    if previous is not None and (not isinstance(previous, str) or not _HEX64.fullmatch(previous)):
        errors.append("prev_sha256 is missing or malformed")
    result = record.get("result")
    if not isinstance(result, dict):
        errors.append("result is missing")
        result = {}
    observed = result.get("observed") is True
    partial = result.get("partial") is True
    for field in ("observed", "partial"):
        if not isinstance(result.get(field), bool):
            errors.append(f"result.{field} must be boolean")
    raw_unknowns = result.get("unknowns", [])
    if not isinstance(raw_unknowns, list) or not all(isinstance(item, str) for item in raw_unknowns):
        errors.append("result.unknowns must be a list of strings")
        raw_unknowns = []
    unknowns = _unique_strings(raw_unknowns)
    artifact_state = _verify_file_entries(record.get("artifacts", []), artifact_root, "artifacts", errors)
    source_state = _verify_file_entries(record.get("sources", []), artifact_root, "sources", errors)
    return {
        "ok": not errors,
        "kind": "record",
        "record_count": 1,
        "observed": observed,
        "partial": partial,
        "unknowns": unknowns,
        "artifact_state": artifact_state,
        "source_state": source_state,
        "record_hashes": [supplied] if isinstance(supplied, str) else [],
        "errors": errors,
    }


def _repository_key(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def make_ledger(run_id: str) -> dict[str, Any]:
    ledger = {"schema": LEDGER_SCHEMA, "run_id": _as_string(run_id, "run_id"), "repository": {}, "records": []}
    ledger["ledger_sha256"] = ledger_digest(ledger)
    return ledger


def append_record(ledger: dict[str, Any], record: dict[str, Any], *, artifact_root: Path | None = None) -> dict[str, Any]:
    if ledger.get("schema") != LEDGER_SCHEMA:
        raise ProofError("ledger has an unsupported schema")
    current = verify_ledger(ledger, artifact_root=artifact_root)
    if not current["ok"]:
        raise ProofError("cannot append to an invalid ledger: " + "; ".join(current["errors"]))
    standalone = verify_record(record, artifact_root=artifact_root)
    if not standalone["ok"]:
        raise ProofError("cannot append an invalid record: " + "; ".join(standalone["errors"]))
    if record.get("run_id") != ledger.get("run_id"):
        raise ProofError("record run_id does not match the ledger")
    records = list(ledger.get("records", []))
    repository = ledger.get("repository", {})
    if not records:
        repository = dict(record.get("repository", {}))
    elif _repository_key(repository) != _repository_key(record.get("repository", {})):
        raise ProofError("repository identity changed within the ledger")
    candidate = dict(record)
    candidate["sequence"] = len(records) + 1
    candidate["prev_sha256"] = records[-1]["record_sha256"] if records else None
    candidate["record_sha256"] = record_digest(candidate)
    records.append(candidate)
    updated = {"schema": LEDGER_SCHEMA, "run_id": ledger["run_id"], "repository": repository, "records": records}
    updated["ledger_sha256"] = ledger_digest(updated)
    return updated


def verify_ledger(ledger: dict[str, Any], *, artifact_root: Path | None = None) -> dict[str, Any]:
    errors: list[str] = []
    _verify_repository(ledger.get("repository", {}), errors)
    if ledger.get("schema") != LEDGER_SCHEMA:
        errors.append(f"unsupported ledger schema: {ledger.get('schema')!r}")
    supplied = ledger.get("ledger_sha256")
    if not isinstance(supplied, str) or not _HEX64.fullmatch(supplied):
        errors.append("ledger_sha256 is missing or malformed")
    elif supplied != ledger_digest(ledger):
        errors.append("ledger_sha256 does not match canonical ledger content")
    records = ledger.get("records")
    if not isinstance(records, list):
        errors.append("records must be a list")
        records = []
    previous_hash: str | None = None
    repository_key = _repository_key(ledger.get("repository", {}))
    observed = True
    partial = False
    unknowns: set[str] = set()
    artifact_state = "verified"
    source_state = "verified"
    hashes: list[str] = []
    for expected_sequence, record in enumerate(records, 1):
        if not isinstance(record, dict):
            errors.append(f"records[{expected_sequence - 1}] is not an object")
            continue
        result = verify_record(record, artifact_root=artifact_root)
        errors.extend(f"record {expected_sequence}: {error}" for error in result["errors"])
        if record.get("sequence") != expected_sequence:
            errors.append(f"record {expected_sequence}: sequence is not contiguous")
        if record.get("prev_sha256") != previous_hash:
            errors.append(f"record {expected_sequence}: chain link does not match previous record")
        if _repository_key(record.get("repository", {})) != repository_key:
            errors.append(f"record {expected_sequence}: repository identity differs from ledger")
        previous_hash = record.get("record_sha256") if isinstance(record.get("record_sha256"), str) else None
        if isinstance(previous_hash, str):
            hashes.append(previous_hash)
        observed = observed and result["observed"]
        partial = partial or result["partial"]
        unknowns.update(result["unknowns"])
        if result["artifact_state"] != "verified":
            artifact_state = result["artifact_state"]
        if result["source_state"] != "verified":
            source_state = result["source_state"]
    if not records:
        observed = False
    return {
        "ok": not errors,
        "kind": "ledger",
        "record_count": len(records),
        "observed": observed,
        "partial": partial,
        "unknowns": sorted(unknowns),
        "artifact_state": artifact_state,
        "source_state": source_state,
        "record_hashes": hashes,
        "errors": errors,
    }


def merge_run(ledger: dict[str, Any], *, artifact_root: Path | None = None) -> dict[str, Any]:
    verification = verify_ledger(ledger, artifact_root=artifact_root)
    if not verification["ok"]:
        raise ProofError("cannot merge an invalid ledger: " + "; ".join(verification["errors"]))
    run = {
        "schema": RUN_SCHEMA,
        "run_id": ledger["run_id"],
        "repository": ledger.get("repository", {}),
        "records": ledger.get("records", []),
        "record_hashes": verification["record_hashes"],
        "record_count": verification["record_count"],
        "observed": verification["observed"],
        "partial": verification["partial"],
        "unknowns": verification["unknowns"],
        "merged_at": utc_now(),
    }
    run["run_sha256"] = run_digest(run)
    return run


def verify_run(run: dict[str, Any], *, artifact_root: Path | None = None) -> dict[str, Any]:
    errors: list[str] = []
    if run.get("schema") != RUN_SCHEMA:
        errors.append(f"unsupported run schema: {run.get('schema')!r}")
    supplied = run.get("run_sha256")
    if not isinstance(supplied, str) or not _HEX64.fullmatch(supplied):
        errors.append("run_sha256 is missing or malformed")
    elif supplied != run_digest(run):
        errors.append("run_sha256 does not match canonical run content")
    ledger = {
        "schema": LEDGER_SCHEMA,
        "run_id": run.get("run_id"),
        "repository": run.get("repository", {}),
        "records": run.get("records", []),
    }
    ledger["ledger_sha256"] = ledger_digest(ledger)
    verification = verify_ledger(ledger, artifact_root=artifact_root)
    errors.extend(verification["errors"])
    if run.get("record_hashes") != verification["record_hashes"]:
        errors.append("run record_hashes do not match embedded records")
    for key in ("record_count", "observed", "partial", "unknowns"):
        if run.get(key) != verification[key]:
            errors.append(f"run {key} summary does not match embedded records")
    return {
        "ok": not errors,
        "kind": "run",
        "record_count": verification["record_count"],
        "observed": verification["observed"],
        "partial": verification["partial"],
        "unknowns": verification["unknowns"],
        "artifact_state": verification["artifact_state"],
        "source_state": verification["source_state"],
        "record_hashes": verification["record_hashes"],
        "errors": errors,
    }


def verify_document(document: dict[str, Any], *, artifact_root: Path | None = None) -> dict[str, Any]:
    schema = document.get("schema")
    if schema == RECORD_SCHEMA:
        return verify_record(document, artifact_root=artifact_root)
    if schema == LEDGER_SCHEMA:
        return verify_ledger(document, artifact_root=artifact_root)
    if schema == RUN_SCHEMA:
        return verify_run(document, artifact_root=artifact_root)
    if schema == LEGACY_SCHEMA:
        supplied = document.get("sha256")
        unsigned = dict(document)
        unsigned.pop("sha256", None)
        errors = []
        if not isinstance(supplied, str) or supplied != digest_json(unsigned):
            errors.append("legacy sha256 does not match canonical content")
        return {
            "ok": not errors,
            "kind": "legacy",
            "record_count": 1,
            "observed": document.get("observed") is True,
            "partial": False,
            "unknowns": ["legacy_v1_no_artifact_model"],
            "artifact_state": "unverified",
            "source_state": "unverified",
            "record_hashes": [supplied] if isinstance(supplied, str) else [],
            "errors": errors,
        }
    return {
        "ok": False,
        "kind": "unknown",
        "record_count": 0,
        "observed": False,
        "partial": True,
        "unknowns": [],
        "artifact_state": "unknown",
        "source_state": "unknown",
        "record_hashes": [],
        "errors": [f"unsupported evidence schema: {schema!r}"],
    }


def verification_output(result: dict[str, Any], *, require_observed: bool = False, require_artifacts: bool = False) -> dict[str, Any]:
    errors = list(result["errors"])
    if require_observed and not result["observed"]:
        errors.append("observed result is required")
    if require_artifacts and result["artifact_state"] != "verified":
        errors.append("artifact verification is required")
    return {
        "schema": VERIFY_SCHEMA,
        "ok": not errors,
        "integrity": result["ok"],
        "kind": result["kind"],
        "record_count": result["record_count"],
        "observed": result["observed"],
        "partial": result["partial"],
        "unknowns": result["unknowns"],
        "artifact_state": result["artifact_state"],
        "source_state": result["source_state"],
        "record_hashes": result["record_hashes"],
        "errors": errors,
    }


def render_markdown(document: dict[str, Any], verification: dict[str, Any]) -> str:
    title = "Agent Proof Run" if document.get("schema") == RUN_SCHEMA else "Agent Proof Ledger"
    lines = [
        f"# {title}",
        "",
        f"- Schema: `{document.get('schema', 'unknown')}`",
        f"- Run: `{document.get('run_id', 'unknown')}`",
        f"- Integrity: **{'valid' if verification['ok'] else 'refused'}**",
        f"- Observed: **{'yes' if verification['observed'] else 'no'}**",
        f"- Partial: **{'yes' if verification['partial'] else 'no'}**",
        f"- Records: `{verification['record_count']}`",
        "",
        "## Records",
        "",
        "| Sequence | Record | Observed | Partial | Unknowns |",
        "| ---: | --- | :---: | :---: | --- |",
    ]
    records = document.get("records", [])
    if document.get("schema") == RECORD_SCHEMA:
        records = [document]
    for record in records:
        result = record.get("result", {})
        unknowns = ", ".join(result.get("unknowns", [])) or "—"
        lines.append(
            f"| {record.get('sequence', '?')} | `{record.get('record_sha256', 'missing')}` | "
            f"{'yes' if result.get('observed') else 'no'} | {'yes' if result.get('partial') else 'no'} | {unknowns} |"
        )
    if verification["unknowns"]:
        lines.extend(["", "## Unknowns", "", *[f"- {item}" for item in verification["unknowns"]]])
    if verification["errors"]:
        lines.extend(["", "## Verification errors", "", *[f"- {item}" for item in verification["errors"]]])
    lines.append("")
    return "\n".join(lines)


def _tar_bytes(name: str, payload: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def export_bundle(
    document: dict[str, Any],
    verification: dict[str, Any],
    output: Path,
    *,
    artifact_root: Path | None = None,
    require_observed: bool = False,
    require_artifacts: bool = False,
    require_graph: bool = False,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    if not verification["ok"]:
        raise ProofError("cannot export invalid evidence: " + "; ".join(verification["errors"]))
    gated = verification_output(
        verification,
        require_observed=require_observed,
        require_artifacts=require_artifacts,
    )
    if not gated["ok"]:
        raise ProofError("cannot export evidence that does not satisfy publication gates: " + "; ".join(gated["errors"]))
    if max_bytes is not None and max_bytes <= 0:
        raise ProofError("max_bytes must be positive when provided")
    graph_supported = document.get("schema") in {RECORD_SCHEMA, LEDGER_SCHEMA, RUN_SCHEMA}
    if require_graph and not graph_supported:
        raise ProofError("provenance graph is unavailable for this evidence schema")
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in document.get("records", [document] if document.get("schema") == RECORD_SCHEMA else []):
        for category in ("sources", "artifacts"):
            for item in record.get(category, []):
                key = (category, item["path"])
                if key not in seen:
                    seen.add(key)
                    entries.append({"category": category, **item})
    manifest = {
        "schema": EXPORT_SCHEMA,
        "input_schema": document.get("schema"),
        "input_sha256": digest_json(document),
        "entries": [],
    }
    proof_payload = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    manifest["entries"].append({"archive_path": "proof/document.json", "size": len(proof_payload), "sha256": digest_bytes(proof_payload)})
    graph_payload: bytes | None = None
    graph_sha256: str | None = None
    if document.get("schema") in {RECORD_SCHEMA, LEDGER_SCHEMA, RUN_SCHEMA}:
        # Import lazily: graph.py intentionally depends on the ledger verifier.
        from .graph import graph_document

        graph = graph_document(
            document,
            artifact_root=artifact_root,
            require_artifacts=verification.get("artifact_state") == "verified",
        )
        graph_payload = json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        graph_sha256 = graph["graph_sha256"]
        manifest["graph_schema"] = graph["schema"]
        manifest["graph_sha256"] = graph_sha256
        manifest["entries"].append({"archive_path": GRAPH_ARCHIVE_PATH, "size": len(graph_payload), "sha256": digest_bytes(graph_payload)})
    if require_graph and graph_payload is None:
        raise ProofError("provenance graph is required for export")
    artifact_payloads: list[tuple[str, bytes]] = []
    for index, item in enumerate(entries, 1):
        target = _rooted_file(artifact_root, item["path"], item["category"])
        payload = target.read_bytes()
        archive_path = f"{item['category']}/{index:04d}-{Path(item['path']).name}"
        artifact_payloads.append((archive_path, payload))
        manifest["entries"].append({"archive_path": archive_path, "source_path": item["path"], "size": len(payload), "sha256": digest_bytes(payload)})
    manifest_payload = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    projected_bytes = len(manifest_payload) + len(proof_payload) + sum(len(payload) for _path, payload in artifact_payloads)
    if graph_payload is not None:
        projected_bytes += len(graph_payload)
    if max_bytes is not None and projected_bytes > max_bytes:
        raise ProofError(f"projected bundle payload exceeds max_bytes: {projected_bytes} > {max_bytes}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                archive.addfile(_tar_bytes("manifest.json", manifest_payload), io.BytesIO(manifest_payload))
                archive.addfile(_tar_bytes("proof/document.json", proof_payload), io.BytesIO(proof_payload))
                if graph_payload is not None:
                    archive.addfile(_tar_bytes(GRAPH_ARCHIVE_PATH, graph_payload), io.BytesIO(graph_payload))
                for archive_path, payload in artifact_payloads:
                    archive.addfile(_tar_bytes(archive_path, payload), io.BytesIO(payload))
    return {
        "schema": EXPORT_SCHEMA,
        "ok": True,
        "path": str(output),
        "entries": manifest["entries"],
        "graph_state": "embedded" if graph_payload is not None else "absent",
        "graph_sha256": graph_sha256,
        "sha256": digest_file(output),
    }


def _safe_archive_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProofError(f"{label} must be a non-empty POSIX archive path")
    if value.startswith("/"):
        raise ProofError(f"{label} must not be absolute")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ProofError(f"{label} contains an unsafe path component")
    return "/".join(parts)


def _bundle_failure(path: Path, errors: list[str], *, bundle_sha256: str | None = None) -> dict[str, Any]:
    return {
        "schema": BUNDLE_VERIFY_SCHEMA,
        "ok": False,
        "integrity": False,
        "path": str(path),
        "bundle_sha256": bundle_sha256,
        "manifest_sha256": None,
        "document_sha256": None,
        "graph_sha256": None,
        "graph_state": "unknown",
        "kind": "bundle",
        "record_count": 0,
        "observed": False,
        "partial": True,
        "unknowns": [],
        "artifact_state": "unknown",
        "source_state": "unknown",
        "record_hashes": [],
        "errors": errors,
    }


def verify_bundle(
    bundle: Path,
    *,
    require_observed: bool = False,
    require_artifacts: bool = False,
    require_graph: bool = False,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Verify an exported bundle without access to its original artifact root."""

    bundle = bundle.expanduser()
    try:
        bundle_sha256 = digest_file(bundle)
    except ProofError as exc:
        return _bundle_failure(bundle, [str(exc)])
    if max_bytes <= 0:
        return _bundle_failure(bundle, ["max_bytes must be positive"], bundle_sha256=bundle_sha256)

    payloads: dict[str, bytes] = {}
    errors: list[str] = []
    total_bytes = 0
    try:
        with tarfile.open(bundle, mode="r:gz") as archive:
            for member in archive.getmembers():
                try:
                    name = _safe_archive_name(member.name, "archive member")
                except ProofError as exc:
                    errors.append(str(exc))
                    continue
                if name in payloads:
                    errors.append(f"duplicate archive member: {name}")
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    errors.append(f"archive member is not a regular file: {name}")
                    continue
                if member.size < 0 or member.size > max_bytes:
                    errors.append(f"archive member exceeds size limit: {name}")
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    errors.append(f"archive member has no readable payload: {name}")
                    continue
                payload = extracted.read(max_bytes + 1)
                if len(payload) != member.size or len(payload) > max_bytes:
                    errors.append(f"archive member size mismatch: {name}")
                    continue
                total_bytes += len(payload)
                if total_bytes > max_bytes:
                    errors.append("archive total exceeds size limit")
                    break
                payloads[name] = payload
    except (OSError, tarfile.TarError, EOFError) as exc:
        return _bundle_failure(bundle, [f"cannot read gzip/tar bundle: {exc}"], bundle_sha256=bundle_sha256)
    if errors:
        return _bundle_failure(bundle, sorted(errors), bundle_sha256=bundle_sha256)
    if "manifest.json" not in payloads or "proof/document.json" not in payloads:
        missing = [name for name in ("manifest.json", "proof/document.json") if name not in payloads]
        return _bundle_failure(bundle, [f"missing required bundle member: {name}" for name in missing], bundle_sha256=bundle_sha256)

    manifest_payload = payloads["manifest.json"]
    document_payload = payloads["proof/document.json"]
    manifest_sha256 = digest_bytes(manifest_payload)
    document_sha256 = digest_bytes(document_payload)
    try:
        manifest = _as_mapping(json.loads(manifest_payload.decode("utf-8")), "manifest")
        document = _as_mapping(json.loads(document_payload.decode("utf-8")), "proof/document.json")
    except (UnicodeError, json.JSONDecodeError, ProofError) as exc:
        return _bundle_failure(bundle, [f"bundle JSON is invalid: {exc}"], bundle_sha256=bundle_sha256) | {
            "manifest_sha256": manifest_sha256,
            "document_sha256": document_sha256,
        }

    if manifest.get("schema") != EXPORT_SCHEMA:
        errors.append(f"unsupported export schema: {manifest.get('schema')!r}")
    if manifest.get("input_schema") != document.get("schema"):
        errors.append("manifest input_schema does not match proof document")
    if manifest.get("input_sha256") != digest_json(document):
        errors.append("manifest input_sha256 does not match proof document")
    declared_graph_sha256 = manifest.get("graph_sha256")
    declared_graph_schema = manifest.get("graph_schema")
    graph_declared = declared_graph_sha256 is not None or declared_graph_schema is not None
    if graph_declared:
        if not isinstance(declared_graph_sha256, str) or not _HEX64.fullmatch(declared_graph_sha256):
            errors.append("manifest graph_sha256 is missing or malformed")
        if not isinstance(declared_graph_schema, str) or not declared_graph_schema:
            errors.append("manifest graph_schema is missing or malformed")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        errors.append("manifest entries must be a list")
        entries = []
    listed: set[str] = set()
    materialized: list[tuple[str, str, bytes]] = []
    graph_payload: bytes | None = None
    for index, raw_entry in enumerate(entries):
        try:
            entry = _as_mapping(raw_entry, f"manifest.entries[{index}]")
            archive_path = _safe_archive_name(entry.get("archive_path"), f"manifest.entries[{index}].archive_path")
            if archive_path in listed:
                raise ProofError(f"duplicate manifest archive path: {archive_path}")
            listed.add(archive_path)
            if archive_path not in payloads:
                raise ProofError(f"manifest entry is missing from archive: {archive_path}")
            payload = payloads[archive_path]
            if entry.get("size") != len(payload) or entry.get("sha256") != digest_bytes(payload):
                raise ProofError(f"manifest digest mismatch: {archive_path}")
            if archive_path == "proof/document.json":
                if entry.get("size") != len(document_payload):
                    raise ProofError("manifest proof/document.json size mismatch")
                continue
            if archive_path == GRAPH_ARCHIVE_PATH:
                if entry.get("source_path") is not None:
                    raise ProofError("manifest graph entry may not carry source_path")
                graph_payload = payload
                continue
            source_path = entry.get("source_path")
            category = archive_path.split("/", 1)[0] if "/" in archive_path else ""
            if category not in {"sources", "artifacts"} or source_path is None:
                raise ProofError(f"manifest entry lacks a valid source category/path: {archive_path}")
            relative = _safe_relative(source_path, f"manifest.entries[{index}].source_path")
            materialized.append((category, relative, payload))
        except ProofError as exc:
            errors.append(str(exc))
    allowed = {"manifest.json"} | listed
    extra = sorted(set(payloads) - allowed)
    if extra:
        errors.extend(f"archive member is not listed in manifest: {name}" for name in extra)
    if "proof/document.json" not in listed:
        errors.append("manifest does not list proof/document.json")
    if graph_declared and GRAPH_ARCHIVE_PATH not in listed:
        errors.append("manifest graph_sha256 is declared but proof/graph.json is not listed")
    if not graph_declared and GRAPH_ARCHIVE_PATH in listed:
        errors.append("proof/graph.json is present without manifest graph_sha256")
    if require_graph and not graph_declared:
        errors.append("provenance graph is required")
    if errors:
        return _bundle_failure(bundle, sorted(errors), bundle_sha256=bundle_sha256) | {
            "manifest_sha256": manifest_sha256,
            "document_sha256": document_sha256,
        }

    graph_object: dict[str, Any] | None = None
    graph_state = "absent"
    if graph_payload is not None:
        graph_state = "invalid"
        try:
            graph_object = _as_mapping(json.loads(graph_payload.decode("utf-8")), GRAPH_ARCHIVE_PATH)
            if graph_object.get("schema") != declared_graph_schema:
                raise ProofError("manifest graph_schema does not match proof/graph.json")
            if graph_object.get("graph_sha256") != declared_graph_sha256:
                raise ProofError("manifest graph_sha256 does not match proof/graph.json")
            graph_state = "loaded"
        except (UnicodeError, json.JSONDecodeError, ProofError) as exc:
            errors.append(f"bundle graph JSON is invalid: {exc}")
    if errors:
        return _bundle_failure(bundle, sorted(errors), bundle_sha256=bundle_sha256) | {
            "manifest_sha256": manifest_sha256,
            "document_sha256": document_sha256,
            "graph_sha256": declared_graph_sha256 if isinstance(declared_graph_sha256, str) else None,
            "graph_state": graph_state,
        }

    try:
        with tempfile.TemporaryDirectory(prefix="agent-proof-bundle-") as temp_dir:
            root = Path(temp_dir)
            seen_paths: set[str] = set()
            for category, relative, payload in materialized:
                if relative in seen_paths:
                    raise ProofError(f"duplicate materialized source path: {relative}")
                seen_paths.add(relative)
                target = _rooted_target_for_write(root, relative, category)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            result = verify_document(document, artifact_root=root)
            graph_result: dict[str, Any] | None = None
            if graph_object is not None:
                from .graph import verify_graph

                graph_result = verify_graph(
                    graph_object,
                    document=document,
                    artifact_root=root,
                    require_input=True,
                    require_observed=require_observed,
                    require_artifacts=require_artifacts,
                )
    except (OSError, ProofError) as exc:
        return _bundle_failure(bundle, [str(exc)], bundle_sha256=bundle_sha256) | {
            "manifest_sha256": manifest_sha256,
            "document_sha256": document_sha256,
            "graph_sha256": declared_graph_sha256 if isinstance(declared_graph_sha256, str) else None,
            "graph_state": "invalid",
        }

    final_errors = list(result["errors"])
    if require_observed and not result["observed"]:
        final_errors.append("observed result is required")
    if require_artifacts and result["artifact_state"] != "verified":
        final_errors.append("artifact verification is required")
    if graph_result is not None:
        graph_state = "verified" if graph_result["ok"] else "invalid"
        final_errors.extend(f"graph: {error}" for error in graph_result["errors"])
    return {
        "schema": BUNDLE_VERIFY_SCHEMA,
        "ok": not final_errors,
        "integrity": result["ok"],
        "path": str(bundle),
        "bundle_sha256": bundle_sha256,
        "manifest_sha256": manifest_sha256,
        "document_sha256": document_sha256,
        "graph_sha256": declared_graph_sha256 if isinstance(declared_graph_sha256, str) else None,
        "graph_state": graph_state,
        "kind": "bundle",
        "record_count": result["record_count"],
        "observed": result["observed"],
        "partial": result["partial"],
        "unknowns": result["unknowns"],
        "artifact_state": result["artifact_state"],
        "source_state": result["source_state"],
        "record_hashes": result["record_hashes"],
        "errors": sorted(final_errors),
    }


def _rooted_target_for_write(root: Path, relative: str, label: str) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ProofError(f"{label} path escapes bundle root: {relative}") from exc
    return target


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"cannot read JSON {path}: {exc}") from exc
    return _as_mapping(value, str(path))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ProofError(f"cannot write JSON {path}: {exc}") from exc
