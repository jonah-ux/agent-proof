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
from typing import Any, Iterable


RECORD_SCHEMA = "agent-proof/record/v2"
LEDGER_SCHEMA = "agent-proof/ledger/v2"
RUN_SCHEMA = "agent-proof/run/v2"
VERIFY_SCHEMA = "agent-proof/verify/v2"
EXPORT_SCHEMA = "agent-proof/export/v2"
LEGACY_SCHEMA = "agent-proof/v1"

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
    if not isinstance(record.get("sequence"), int) or record.get("sequence", 0) < 1:
        errors.append("sequence is missing or invalid")
    previous = record.get("prev_sha256")
    if previous is not None and (not isinstance(previous, str) or not _HEX64.fullmatch(previous)):
        errors.append("prev_sha256 is missing or malformed")
    result = record.get("result")
    if not isinstance(result, dict):
        errors.append("result is missing")
        result = {}
    observed = result.get("observed") is True
    partial = result.get("partial") is True
    unknowns = _unique_strings(result.get("unknowns", []) if isinstance(result.get("unknowns"), list) else [])
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


def export_bundle(document: dict[str, Any], verification: dict[str, Any], output: Path, *, artifact_root: Path | None = None) -> dict[str, Any]:
    if not verification["ok"]:
        raise ProofError("cannot export invalid evidence: " + "; ".join(verification["errors"]))
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
    output.parent.mkdir(parents=True, exist_ok=True)
    proof_payload = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    manifest["entries"].append({"archive_path": "proof/document.json", "size": len(proof_payload), "sha256": digest_bytes(proof_payload)})
    artifact_payloads: list[tuple[str, bytes]] = []
    for index, item in enumerate(entries, 1):
        target = _rooted_file(artifact_root, item["path"], item["category"])
        payload = target.read_bytes()
        archive_path = f"{item['category']}/{index:04d}-{Path(item['path']).name}"
        artifact_payloads.append((archive_path, payload))
        manifest["entries"].append({"archive_path": archive_path, "source_path": item["path"], "size": len(payload), "sha256": digest_bytes(payload)})
    manifest_payload = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    with output.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                archive.addfile(_tar_bytes("manifest.json", manifest_payload), io.BytesIO(manifest_payload))
                archive.addfile(_tar_bytes("proof/document.json", proof_payload), io.BytesIO(proof_payload))
                for archive_path, payload in artifact_payloads:
                    archive.addfile(_tar_bytes(archive_path, payload), io.BytesIO(payload))
    return {"schema": EXPORT_SCHEMA, "ok": True, "path": str(output), "entries": manifest["entries"], "sha256": digest_file(output)}


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
