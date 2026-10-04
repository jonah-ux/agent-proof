"""Command-line interface for Agent Proof."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from . import __version__
from .compatibility import (
    ArtifactSource,
    CompatibilityInputError,
    check_manifest,
    check_manifest_v2,
    load_manifest,
    negotiate_capabilities,
    negotiate_native_protocols,
    validate_participant_artifacts,
)
from .graph import graph_document, verify_graph
from .interop import normalize_envelope, verify_interop
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


_COMPATIBILITY_COMMANDS = {"compatibility", "compatibility-artifacts", "negotiate"}


class _ArgumentParser(argparse.ArgumentParser):
    """Keep compatibility argument refusals JSON and free of caller paths."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._path_free = self.prog.split()[-1] in _COMPATIBILITY_COMMANDS

    def parse_args(self, args=None, namespace=None):
        values = list(args) if args is not None else sys.argv[1:]
        self._path_free = self._path_free or bool(
            values and values[0] in _COMPATIBILITY_COMMANDS
        )
        return super().parse_args(values, namespace)

    def error(self, message):
        if self._path_free:
            _print(
                {
                    "schema": "agent-systems-lab/compatibility-error/v2",
                    "ok": False,
                    "errors": [
                        {
                            "code": "malformed_manifest",
                            "detail": "command arguments are malformed",
                        }
                    ],
                }
            )
            self.exit(2)
        super().error(message)


def parser() -> argparse.ArgumentParser:
    root = _ArgumentParser(
        prog="agent-proof",
        description="Create, chain, verify, render, and export tamper-evident agent evidence.",
    )
    root.add_argument(
        "--version", action="version", version=f"agent-proof {__version__}"
    )
    commands = root.add_subparsers(dest="command", required=True)

    capture = commands.add_parser(
        "capture", help="write the legacy v1 empty capture record"
    )
    capture.add_argument("path", nargs="?", help="optional source label")
    capture.add_argument("--out", default="proof.json")
    capture.add_argument("--run-id", default="capture")
    capture.add_argument("--actor", default="unknown")

    record = commands.add_parser(
        "record", help="build a redacted self-hashing record from a JSON spec"
    )
    record.add_argument(
        "spec", nargs="?", help="JSON specification; omitted for an honest empty record"
    )
    record.add_argument("--out", default="record.json")
    record.add_argument(
        "--artifact-root", help="root for relative source and artifact paths"
    )

    append = commands.add_parser(
        "append", help="append a verified record to a hash-linked ledger"
    )
    append.add_argument("--ledger", required=True)
    append.add_argument("--record", required=True)
    append.add_argument("--artifact-root")

    merge = commands.add_parser(
        "merge", help="merge a verified ledger into a self-contained run proof"
    )
    merge.add_argument("--ledger", required=True)
    merge.add_argument("--out", default="run-proof.json")
    merge.add_argument("--artifact-root")

    verify = commands.add_parser(
        "verify", help="recompute hashes, chain links, and optional file digests"
    )
    verify.add_argument("path")
    verify.add_argument("--artifact-root")
    verify.add_argument("--require-observed", action="store_true")
    verify.add_argument("--require-artifacts", action="store_true")

    show = commands.add_parser(
        "show", help="print an evidence document in stable pretty JSON"
    )
    show.add_argument("path")

    render = commands.add_parser(
        "render", help="render a ledger or run proof as deterministic Markdown"
    )
    render.add_argument("path")
    render.add_argument("--out")
    render.add_argument("--artifact-root")

    export = commands.add_parser(
        "export",
        help="export a verified proof and its files as a deterministic tarball",
    )
    export.add_argument("path")
    export.add_argument("--out", required=True)
    export.add_argument("--artifact-root")
    export.add_argument("--require-observed", action="store_true")
    export.add_argument("--require-artifacts", action="store_true")
    export.add_argument("--require-graph", action="store_true")
    export.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="optional uncompressed bundle payload limit; use 67108864 for the verify-bundle default",
    )

    collect = commands.add_parser(
        "collect", help="collect known sibling envelopes into a verified ledger"
    )
    collect.add_argument(
        "--input",
        action="append",
        required=True,
        help="relative or absolute JSON envelope path; repeatable",
    )
    collect.add_argument("--run-id", required=True)
    collect.add_argument("--actor", default="agent-proof-collect")
    collect.add_argument("--artifact-root", required=True)
    collect.add_argument("--out", default="ledger.json")

    normalize = commands.add_parser(
        "normalize",
        help="normalize one known sibling envelope into a redacted interoperability contract",
    )
    normalize.add_argument("input", help="sibling JSON envelope")
    normalize.add_argument("--artifact-root", required=True)
    normalize.add_argument("--out", default="interop.json")

    interop_verify = commands.add_parser(
        "verify-interop",
        help="verify a normalized envelope, optionally against its source file",
    )
    interop_verify.add_argument("path", help="agent-proof/interop/v1 JSON envelope")
    interop_verify.add_argument(
        "--input",
        help="source sibling JSON envelope; defaults to the declared source path",
    )
    interop_verify.add_argument("--artifact-root")
    interop_verify.add_argument("--require-input", action="store_true")

    bundle_verify = commands.add_parser(
        "verify-bundle",
        help="verify an exported bundle without its original artifact root",
    )
    bundle_verify.add_argument("path")
    bundle_verify.add_argument("--require-observed", action="store_true")
    bundle_verify.add_argument("--require-artifacts", action="store_true")
    bundle_verify.add_argument("--require-graph", action="store_true")
    bundle_verify.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)

    graph = commands.add_parser(
        "graph", help="derive a deterministic provenance graph from a proof document"
    )
    graph.add_argument("path")
    graph.add_argument("--artifact-root")
    graph.add_argument("--require-observed", action="store_true")
    graph.add_argument("--require-artifacts", action="store_true")
    graph.add_argument("--out")

    graph_verify = commands.add_parser(
        "verify-graph", help="verify a provenance graph, optionally against its source"
    )
    graph_verify.add_argument("path")
    graph_verify.add_argument("--input")
    graph_verify.add_argument("--artifact-root")
    graph_verify.add_argument("--require-input", action="store_true")
    graph_verify.add_argument("--require-observed", action="store_true")
    graph_verify.add_argument("--require-artifacts", action="store_true")

    compatibility = commands.add_parser(
        "compatibility",
        help="validate the Agent Systems Lab compatibility charter",
    )
    compatibility.add_argument(
        "--manifest",
        default="conformance/compatibility-v1.json",
        help="path to an Agent Systems Lab compatibility manifest",
    )
    compatibility.add_argument("--schema", choices=("v1", "v2"), default="v1")
    compatibility.add_argument(
        "--json",
        action="store_true",
        help="emit the machine-readable report (the default)",
    )

    artifacts = commands.add_parser(
        "compatibility-artifacts",
        help="validate explicitly selected local participant artifact bytes offline",
    )
    artifacts.add_argument(
        "--manifest", required=True, help="path to a complete compatibility/v2 manifest"
    )
    artifacts.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="OWNER=PATH",
        help="caller-selected local artifact; repeat once per participant",
    )
    artifacts.add_argument(
        "--cache-ref", action="append", default=[], metavar="OWNER=URL"
    )
    artifacts.add_argument("--artifact-root")
    artifacts.add_argument("--max-bytes", type=int, default=None)
    artifacts.add_argument("--max-total-bytes", type=int, default=None)

    negotiate = commands.add_parser(
        "negotiate",
        help="negotiate explicitly declared producer and consumer capability versions",
    )
    negotiate.add_argument(
        "--producer", required=True, help="producer capability declaration JSON"
    )
    negotiate.add_argument(
        "--consumer", required=True, help="consumer capability declaration JSON"
    )
    negotiate.add_argument("--registry", help="explicit capability registry JSON")
    negotiate.add_argument(
        "--kind", choices=("capability", "native"), default="capability"
    )

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
            record = build_record(
                _spec(_path(args.spec) if args.spec else None), artifact_root=root
            )
            write_json(_path(args.out), record)
            _print(record)
            return 0

        if args.command == "append":
            ledger_path = _path(args.ledger)
            record_path = _path(args.record)
            root = _path(args.artifact_root) if args.artifact_root else None
            record = load_json(record_path)
            ledger = (
                load_json(ledger_path)
                if ledger_path.exists()
                else make_ledger(record.get("run_id", "run"))
            )
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
            output = verification_output(
                result,
                require_observed=args.require_observed,
                require_artifacts=args.require_artifacts,
            )
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
                _print(
                    {"schema": "agent-proof/render/v2", "ok": True, "path": str(output)}
                )
            else:
                print(markdown, end="")
            return 0 if result["ok"] else 1

        if args.command == "export":
            document = load_json(_path(args.path))
            root = _path(args.artifact_root) if args.artifact_root else None
            result = verify_document(document, artifact_root=root)
            output = export_bundle(
                document,
                result,
                _path(args.out),
                artifact_root=root,
                require_observed=args.require_observed,
                require_artifacts=args.require_artifacts,
                require_graph=args.require_graph,
                max_bytes=args.max_bytes,
            )
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
            _print(
                {
                    "schema": "agent-proof/collect/v2",
                    "ok": True,
                    "ledger": ledger,
                    "input_count": len(schemas),
                    "schemas": schemas,
                }
            )
            return 0

        if args.command == "normalize":
            normalized = normalize_envelope(
                _path(args.input), artifact_root=_path(args.artifact_root)
            )
            write_json(_path(args.out), normalized)
            _print(normalized)
            return 0

        if args.command == "verify-interop":
            normalized = load_json(_path(args.path))
            root = _path(args.artifact_root) if args.artifact_root else None
            source = _path(args.input) if args.input else None
            result = verify_interop(
                normalized,
                artifact_root=root,
                source_path=source,
                require_input=args.require_input,
            )
            _print(result)
            return 0 if result["ok"] else 1

        if args.command == "verify-bundle":
            result = verify_bundle(
                _path(args.path),
                require_observed=args.require_observed,
                require_artifacts=args.require_artifacts,
                require_graph=args.require_graph,
                max_bytes=args.max_bytes,
            )
            _print(result)
            return 0 if result["ok"] else 1

        if args.command == "graph":
            document = load_json(_path(args.path))
            root = _path(args.artifact_root) if args.artifact_root else None
            graph = graph_document(
                document,
                artifact_root=root,
                require_observed=args.require_observed,
                require_artifacts=args.require_artifacts,
            )
            if args.out:
                output = _path(args.out)
                write_json(output, graph)
                _print(
                    {
                        "schema": graph["schema"],
                        "ok": True,
                        "path": str(output),
                        "graph_sha256": graph["graph_sha256"],
                        "node_count": graph["node_count"],
                        "edge_count": graph["edge_count"],
                    }
                )
            else:
                _print(graph)
            return 0

        if args.command == "verify-graph":
            graph = load_json(_path(args.path))
            source = load_json(_path(args.input)) if args.input else None
            root = _path(args.artifact_root) if args.artifact_root else None
            result = verify_graph(
                graph,
                document=source,
                artifact_root=root,
                require_input=args.require_input,
                require_observed=args.require_observed,
                require_artifacts=args.require_artifacts,
            )
            _print(result)
            return 0 if result["ok"] else 1

        if args.command == "compatibility":
            result = (
                check_manifest_v2(_path(args.manifest))
                if args.schema == "v2"
                else check_manifest(_path(args.manifest))
            )
            _print(result)
            return 0 if result["ok"] else 2

        if args.command == "compatibility-artifacts":
            sources: dict[str, ArtifactSource] = {}
            for declaration in args.source:
                if "=" not in declaration:
                    raise ProofError("source selector is malformed")
                owner, selected = declaration.split("=", 1)
                if not owner or not selected or owner in sources:
                    raise ProofError("source selector is malformed")
                sources[owner] = ArtifactSource(_path(selected))
            cache_refs: dict[str, str] = {}
            for declaration in args.cache_ref:
                if "=" not in declaration:
                    raise ProofError("cache selector is malformed")
                owner, reference = declaration.split("=", 1)
                if not owner or not reference or owner in cache_refs:
                    raise ProofError("cache selector is malformed")
                cache_refs[owner] = reference
            sources = {
                owner: ArtifactSource(source.path, cache_refs.get(owner))
                for owner, source in sources.items()
            }
            if set(cache_refs) - set(sources):
                raise ProofError("cache selector has no selected source")
            result = validate_participant_artifacts(
                _path(args.manifest),
                sources,
                artifact_root=_path(args.artifact_root) if args.artifact_root else None,
                **({"max_bytes": args.max_bytes} if args.max_bytes is not None else {}),
                **(
                    {"max_total_bytes": args.max_total_bytes}
                    if args.max_total_bytes is not None
                    else {}
                ),
            )
            _print(result)
            return 0 if result["ok"] else 2

        if args.command == "negotiate":
            negotiate = (
                negotiate_native_protocols
                if args.kind == "native"
                else negotiate_capabilities
            )
            result = negotiate(
                load_manifest(_path(args.producer)),
                load_manifest(_path(args.consumer)),
                load_manifest(_path(args.registry)) if args.registry else None,
            )
            _print(result)
            return 0 if result["ok"] else 2

        raise ProofError(f"unsupported command: {args.command}")
    except CompatibilityInputError as exc:
        _print(
            {
                "schema": "agent-systems-lab/compatibility-error/v2",
                "ok": False,
                "errors": [{"code": exc.code, "detail": str(exc)}],
            }
        )
        return 2
    except (ProofError, OSError, json.JSONDecodeError) as exc:
        if args.command in {"compatibility", "compatibility-artifacts", "negotiate"}:
            _print(
                {
                    "schema": "agent-systems-lab/compatibility-error/v2",
                    "ok": False,
                    "errors": [
                        {
                            "code": "malformed_manifest",
                            "detail": "compatibility input is malformed",
                        }
                    ],
                }
            )
            return 2
        _print({"schema": "agent-proof/error/v2", "ok": False, "error": str(exc)})
        return 2
    except (RuntimeError, TypeError, ValueError):
        if args.command in _COMPATIBILITY_COMMANDS:
            _print(
                {
                    "schema": "agent-systems-lab/compatibility-error/v2",
                    "ok": False,
                    "errors": [
                        {
                            "code": "malformed_manifest",
                            "detail": "compatibility input is malformed",
                        }
                    ],
                }
            )
            return 2
        raise


if __name__ == "__main__":
    raise SystemExit(main())
