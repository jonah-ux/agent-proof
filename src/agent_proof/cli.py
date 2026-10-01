"""Command-line interface for Agent Proof."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import __version__
from .ledger import (
    ProofError,
    append_record,
    build_record,
    digest_json,
    export_bundle,
    load_json,
    make_ledger,
    merge_run,
    render_markdown,
    verification_output,
    verify_bundle,
    verify_document,
    write_json,
)


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _spec(path: Path | None) -> dict[str, Any]:
    return load_json(path) if path else {}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="agent-proof",
        description="Create, chain, verify, render, and export tamper-evident agent evidence.",
    )
    root.add_argument("--version", action="version", version=f"agent-proof {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    capture = commands.add_parser("capture", help="write the legacy v1 empty capture record")
    capture.add_argument("path", nargs="?", help="optional source label")
    capture.add_argument("--out", default="proof.json")
    capture.add_argument("--run-id", default="capture")
    capture.add_argument("--actor", default="unknown")

    record = commands.add_parser("record", help="build a redacted self-hashing record from a JSON spec")
    record.add_argument("spec", nargs="?", help="JSON specification; omitted for an honest empty record")
    record.add_argument("--out", default="record.json")
    record.add_argument("--artifact-root", help="root for relative source and artifact paths")

    append = commands.add_parser("append", help="append a verified record to a hash-linked ledger")
    append.add_argument("--ledger", required=True)
    append.add_argument("--record", required=True)
    append.add_argument("--artifact-root")

    merge = commands.add_parser("merge", help="merge a verified ledger into a self-contained run proof")
    merge.add_argument("--ledger", required=True)
    merge.add_argument("--out", default="run-proof.json")
    merge.add_argument("--artifact-root")

    verify = commands.add_parser("verify", help="recompute hashes, chain links, and optional file digests")
    verify.add_argument("path")
    verify.add_argument("--artifact-root")
    verify.add_argument("--require-observed", action="store_true")
    verify.add_argument("--require-artifacts", action="store_true")

    show = commands.add_parser("show", help="print an evidence document in stable pretty JSON")
    show.add_argument("path")

    render = commands.add_parser("render", help="render a ledger or run proof as deterministic Markdown")
    render.add_argument("path")
    render.add_argument("--out")
    render.add_argument("--artifact-root")

    export = commands.add_parser("export", help="export a verified proof and its files as a deterministic tarball")
    export.add_argument("path")
    export.add_argument("--out", required=True)
    export.add_argument("--artifact-root")

    collect = commands.add_parser("collect", help="collect known sibling envelopes into a verified ledger")
    collect.add_argument("--input", action="append", required=True, help="relative or absolute JSON envelope path; repeatable")
    collect.add_argument("--run-id", required=True)
    collect.add_argument("--actor", default="agent-proof-collect")
    collect.add_argument("--artifact-root", required=True)
    collect.add_argument("--out", default="ledger.json")

    bundle_verify = commands.add_parser("verify-bundle", help="verify an exported bundle without its original artifact root")
    bundle_verify.add_argument("path")
    bundle_verify.add_argument("--require-observed", action="store_true")
    bundle_verify.add_argument("--require-artifacts", action="store_true")
    bundle_verify.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)

    return root


def _capture(args: argparse.Namespace) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": "agent-proof/v1",
        "observed": False,
        "commands": [],
        "artifacts": [],
        "notes": ["Capture records evidence; it does not claim a user-visible result."],
    }
    if args.path:
        record["source"] = str(Path(args.path).expanduser().resolve())
    record["sha256"] = digest_json(record)
    write_json(_path(args.out), record)
    return record


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "capture":
            _print(_capture(args))
            return 0

        if args.command == "record":
            root = _path(args.artifact_root) if args.artifact_root else None
            record = build_record(_spec(_path(args.spec) if args.spec else None), artifact_root=root)
            write_json(_path(args.out), record)
            _print(record)
            return 0

        if args.command == "append":
            ledger_path = _path(args.ledger)
            record_path = _path(args.record)
            root = _path(args.artifact_root) if args.artifact_root else None
            record = load_json(record_path)
            ledger = load_json(ledger_path) if ledger_path.exists() else make_ledger(record.get("run_id", "run"))
            updated = append_record(ledger, record, artifact_root=root)
            write_json(ledger_path, updated)
            _print(updated)
            return 0

        if args.command == "merge":
            root = _path(args.artifact_root) if args.artifact_root else None
            run = merge_run(load_json(_path(args.ledger)), artifact_root=root)
            write_json(_path(args.out), run)
            _print(run)
            return 0

        if args.command == "verify":
            root = _path(args.artifact_root) if args.artifact_root else None
            result = verify_document(load_json(_path(args.path)), artifact_root=root)
            output = verification_output(result, require_observed=args.require_observed, require_artifacts=args.require_artifacts)
            _print(output)
            return 0 if output["ok"] else 1

        if args.command == "show":
            _print(load_json(_path(args.path)))
            return 0

        if args.command == "render":
            document = load_json(_path(args.path))
            root = _path(args.artifact_root) if args.artifact_root else None
            result = verify_document(document, artifact_root=root)
            markdown = render_markdown(document, verification_output(result))
            if args.out:
                output = _path(args.out)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(markdown, encoding="utf-8")
                _print({"schema": "agent-proof/render/v2", "ok": True, "path": str(output)})
            else:
                print(markdown, end="")
            return 0 if result["ok"] else 1

        if args.command == "export":
            document = load_json(_path(args.path))
            root = _path(args.artifact_root) if args.artifact_root else None
            result = verify_document(document, artifact_root=root)
            output = export_bundle(document, result, _path(args.out), artifact_root=root)
            _print(output)
            return 0

        if args.command == "collect":
            from .ledger import collect_ledger

            root = _path(args.artifact_root)
            ledger, schemas = collect_ledger(
                [_path(path) for path in args.input],
                run_id=args.run_id,
                actor=args.actor,
                artifact_root=root,
            )
            write_json(_path(args.out), ledger)
            _print({"schema": "agent-proof/collect/v2", "ok": True, "ledger": ledger, "input_count": len(schemas), "schemas": schemas})
            return 0

        if args.command == "verify-bundle":
            result = verify_bundle(
                _path(args.path),
                require_observed=args.require_observed,
                require_artifacts=args.require_artifacts,
                max_bytes=args.max_bytes,
            )
            _print(result)
            return 0 if result["ok"] else 1

        raise ProofError(f"unsupported command: {args.command}")
    except (ProofError, OSError, json.JSONDecodeError) as exc:
        _print({"schema": "agent-proof/error/v2", "ok": False, "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
