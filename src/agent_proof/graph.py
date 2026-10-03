"""Deterministic provenance graphs derived from Agent Proof v2 documents.

The graph is a read-only view over a record, ledger, or merged run.  It keeps
the v2 hashes as input claims and gives them a separate graph hash; it never
rewrites or replaces the evidence document's own integrity model.
"""

from __future__ import annotations

from typing import Any

from .ledger import (
    LEDGER_SCHEMA,
    RECORD_SCHEMA,
    RUN_SCHEMA,
    ProofError,
    _HEX64,
    _safe_relative,
    digest_json,
    verify_document,
)


GRAPH_SCHEMA = "agent-proof/graph/v1"
GRAPH_VERIFY_SCHEMA = "agent-proof/graph-verify/v1"
SUPPORTED_INPUT_SCHEMAS = {RECORD_SCHEMA, LEDGER_SCHEMA, RUN_SCHEMA}


def _records(document: dict[str, Any]) -> list[dict[str, Any]]:
    schema = document.get("schema")
    if schema == RECORD_SCHEMA:
        return [document]
    records = document.get("records")
    if schema in {LEDGER_SCHEMA, RUN_SCHEMA} and isinstance(records, list) and all(isinstance(item, dict) for item in records):
        return list(records)
    raise ProofError(f"graph input must use record/v2, ledger/v2, or run/v2; got {schema!r}")


def _claim_hash(document: dict[str, Any]) -> str:
    schema = document.get("schema")
    key = {
        RECORD_SCHEMA: "record_sha256",
        LEDGER_SCHEMA: "ledger_sha256",
        RUN_SCHEMA: "run_sha256",
    }[schema]
    value = document.get(key)
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProofError(f"graph input is missing a valid {key}")
    return value


def _file_digest(item: Any, label: str) -> str:
    if not isinstance(item, dict):
        raise ProofError(f"{label} entry must be an object")
    value = item.get("sha256")
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProofError(f"{label}.sha256 must be a 64-character lowercase digest")
    return value


def _add_blob(nodes: dict[str, dict[str, Any]], item: dict[str, Any], *, role: str, label: str) -> str:
    digest = _file_digest(item, label)
    node_id = f"blob:{digest}"
    node = nodes.setdefault(node_id, {"id": node_id, "kind": "evidence", "sha256": digest, "roles": [], "paths": [], "schemas": []})
    if role not in node["roles"]:
        node["roles"].append(role)
    path = _safe_relative(item.get("path"), f"{label}.path")
    if path not in node["paths"]:
        node["paths"].append(path)
    schema = item.get("schema")
    if isinstance(schema, str) and schema not in node["schemas"]:
        node["schemas"].append(schema)
    node["roles"].sort()
    node["paths"].sort()
    node["schemas"].sort()
    return node_id


def _edge_key(edge: dict[str, Any]) -> str:
    try:
        return digest_json(edge)
    except ProofError:
        return repr(edge)


def graph_document(
    document: dict[str, Any],
    *,
    artifact_root: Any = None,
    require_observed: bool = False,
    require_artifacts: bool = False,
) -> dict[str, Any]:
    """Derive a stable graph from a verified v2 record, ledger, or run."""

    if not isinstance(document, dict) or document.get("schema") not in SUPPORTED_INPUT_SCHEMAS:
        schema = document.get("schema") if isinstance(document, dict) else None
        raise ProofError(f"graph input must use record/v2, ledger/v2, or run/v2; got {schema!r}")
    verification = verify_document(document, artifact_root=artifact_root)
    errors = list(verification["errors"])
    if require_observed and not verification["observed"]:
        errors.append("observed result is required")
    if require_artifacts and verification["artifact_state"] != "verified":
        errors.append("artifact verification is required")
    if errors:
        raise ProofError("cannot derive graph from invalid evidence: " + "; ".join(sorted(set(errors))))

    document_schema = document["schema"]
    claim_hash = _claim_hash(document)
    run_id = document.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ProofError("graph input run_id must be a non-empty string")
    container_kind = {RECORD_SCHEMA: "record", LEDGER_SCHEMA: "ledger", RUN_SCHEMA: "run"}[document_schema]
    container_id = f"container:{claim_hash}"
    nodes: dict[str, dict[str, Any]] = {
        container_id: {
            "id": container_id,
            "kind": container_kind,
            "sha256": claim_hash,
            "run_id": run_id,
        }
    }
    records = _records(document)
    record_ids: dict[str, str] = {}
    for index, record in enumerate(records, 1):
        record_hash = record.get("record_sha256")
        if not isinstance(record_hash, str) or not _HEX64.fullmatch(record_hash):
            raise ProofError(f"records[{index - 1}] is missing a valid record_sha256")
        record_id = f"record:{record_hash}"
        if record_hash in record_ids:
            raise ProofError(f"duplicate record hash in graph input: {record_hash}")
        record_ids[record_hash] = record_id
        result = record.get("result") if isinstance(record.get("result"), dict) else {}
        nodes[record_id] = {
            "id": record_id,
            "kind": "record",
            "sha256": record_hash,
            "sequence": record.get("sequence", index),
            "prev_sha256": record.get("prev_sha256"),
            "run_id": record.get("run_id", run_id),
            "observed": result.get("observed") is True,
            "partial": result.get("partial") is True,
            "unknowns": sorted(item for item in result.get("unknowns", []) if isinstance(item, str)),
        }

    edges: list[dict[str, Any]] = []
    for index, record in enumerate(records, 1):
        record_id = record_ids[record["record_sha256"]]
        sequence = record.get("sequence", index)
        edges.append({"from": container_id, "to": record_id, "kind": "contains", "sequence": sequence})
        previous = record.get("prev_sha256")
        if isinstance(previous, str) and previous in record_ids:
            edges.append({"from": record_ids[previous], "to": record_id, "kind": "continues", "sequence": sequence})
        elif previous is not None:
            raise ProofError(f"record {index} prev_sha256 does not identify an earlier record")
        for category, role, edge_kind in (("sources", "source", "supports"), ("artifacts", "artifact", "produces")):
            entries = record.get(category, [])
            if not isinstance(entries, list):
                raise ProofError(f"records[{index - 1}].{category} must be a list")
            for item_index, item in enumerate(entries):
                blob_id = _add_blob(nodes, item, role=role, label=f"records[{index - 1}].{category}[{item_index}]")
                edge = {"from": blob_id if role == "source" else record_id, "to": record_id if role == "source" else blob_id, "kind": edge_kind, "role": role, "path": _safe_relative(item.get("path"), f"records[{index - 1}].{category}[{item_index}].path")}
                if role == "source" and isinstance(item.get("schema"), str):
                    edge["schema"] = item["schema"]
                edges.append(edge)

    graph: dict[str, Any] = {
        "schema": GRAPH_SCHEMA,
        "input_schema": document_schema,
        "input_sha256": digest_json(document),
        "input_claim_sha256": claim_hash,
        "run_id": run_id,
        "repository": document.get("repository", {}),
        "observed": verification["observed"],
        "partial": verification["partial"],
        "unknowns": sorted(set(verification["unknowns"])),
        "source_state": verification["source_state"],
        "artifact_state": verification["artifact_state"],
        "nodes": sorted(nodes.values(), key=lambda node: (node["kind"], node["id"])),
        "edges": sorted(edges, key=_edge_key),
    }
    graph["node_count"] = len(graph["nodes"])
    graph["edge_count"] = len(graph["edges"])
    graph["graph_sha256"] = digest_json(graph)
    return graph


def _has_cycle(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> bool:
    adjacency: dict[str, list[str]] = {node["id"]: [] for node in nodes if isinstance(node, dict) and isinstance(node.get("id"), str)}
    for edge in edges:
        if isinstance(edge, dict) and edge.get("kind") in {"contains", "continues"} and edge.get("from") in adjacency and edge.get("to") in adjacency:
            adjacency[edge["from"]].append(edge["to"])
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> bool:
        if node_id in visiting:
            return True
        if node_id in visited:
            return False
        visiting.add(node_id)
        if any(visit(child) for child in adjacency[node_id]):
            return True
        visiting.remove(node_id)
        visited.add(node_id)
        return False

    return any(visit(node_id) for node_id in adjacency)


def verify_graph(
    graph: dict[str, Any],
    *,
    document: dict[str, Any] | None = None,
    artifact_root: Any = None,
    require_input: bool = False,
    require_observed: bool = False,
    require_artifacts: bool = False,
) -> dict[str, Any]:
    """Verify graph structure, and optionally bind it to the source document."""

    errors: list[str] = []
    bound_input = document is not None
    if not isinstance(graph, dict):
        errors.append("graph must be an object")
        graph = {}
    if graph.get("schema") != GRAPH_SCHEMA:
        errors.append(f"unsupported graph schema: {graph.get('schema')!r}")
    if graph.get("input_schema") not in SUPPORTED_INPUT_SCHEMAS:
        errors.append("input_schema is unsupported")
    for key in ("input_sha256", "input_claim_sha256"):
        if not isinstance(graph.get(key), str) or not _HEX64.fullmatch(graph[key]):
            errors.append(f"{key} is missing or malformed")
    if not isinstance(graph.get("run_id"), str) or not graph["run_id"]:
        errors.append("run_id is missing or malformed")
    if graph.get("source_state") not in {"verified", "unverified", "invalid", "unknown"}:
        errors.append("source_state is invalid")
    if graph.get("artifact_state") not in {"verified", "unverified", "invalid", "unknown"}:
        errors.append("artifact_state is invalid")
    if not isinstance(graph.get("observed"), bool):
        errors.append("observed must be boolean")
    if not isinstance(graph.get("partial"), bool):
        errors.append("partial must be boolean")
    if not isinstance(graph.get("unknowns"), list) or any(not isinstance(item, str) for item in graph.get("unknowns", [])):
        errors.append("unknowns must be a list of strings")
    supplied_hash = graph.get("graph_sha256")
    unsigned = {key: value for key, value in graph.items() if key != "graph_sha256"}
    if not isinstance(supplied_hash, str) or not _HEX64.fullmatch(supplied_hash):
        errors.append("graph_sha256 is missing or malformed")
    else:
        try:
            if supplied_hash != digest_json(unsigned):
                errors.append("graph_sha256 does not match canonical graph content")
        except ProofError as exc:
            errors.append(f"graph canonicalization failed: {exc}")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        errors.append("nodes must be a list")
        nodes = []
    node_ids: set[str] = set()
    nodes_by_id: dict[str, dict[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
            errors.append(f"nodes[{index}] is missing a non-empty id")
            continue
        if node["id"] in node_ids:
            errors.append(f"duplicate graph node: {node['id']}")
        node_ids.add(node["id"])
        nodes_by_id[node["id"]] = node
        kind = node.get("kind")
        if kind not in {"run", "ledger", "record", "evidence"}:
            errors.append(f"nodes[{index}] has an unsupported kind")
        digest = node.get("sha256")
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            errors.append(f"nodes[{index}] is missing a valid sha256")
        elif not node["id"].endswith(digest):
            errors.append(f"nodes[{index}] id does not end with its sha256")
        node_id = node.get("id") if isinstance(node.get("id"), str) else ""
        if node_id.startswith("container:"):
            if kind not in {"run", "ledger", "record"}:
                errors.append(f"nodes[{index}] container id has an invalid kind")
        elif node_id.startswith("record:"):
            if kind != "record":
                errors.append(f"nodes[{index}] record id has an invalid kind")
        elif node_id.startswith("blob:"):
            if kind != "evidence":
                errors.append(f"nodes[{index}] blob id has an invalid kind")
        else:
            errors.append(f"nodes[{index}] id prefix is invalid")
        if isinstance(digest, str):
            expected_id_prefix = "blob" if kind == "evidence" else "container" if node_id.startswith("container:") else "record"
            if node_id != f"{expected_id_prefix}:{digest}":
                errors.append(f"nodes[{index}] id does not exactly match its kind and sha256")
        # A standalone record container has kind "record" but no chain sequence.
        if node_id.startswith("record:") and (not isinstance(node.get("sequence"), int) or node.get("sequence", 0) < 1):
            errors.append(f"nodes[{index}] record sequence is invalid")
        if kind == "evidence":
            if not isinstance(node.get("roles"), list) or not node["roles"] or any(not isinstance(item, str) for item in node["roles"]):
                errors.append(f"nodes[{index}] evidence roles are missing")
            if not isinstance(node.get("paths"), list) or not node["paths"] or any(not isinstance(item, str) for item in node["paths"]):
                errors.append(f"nodes[{index}] evidence paths are missing")
            if isinstance(node.get("roles"), list) and all(isinstance(item, str) for item in node["roles"]) and node["roles"] != sorted(set(node["roles"])):
                errors.append(f"nodes[{index}] evidence roles are not sorted and unique")
            if isinstance(node.get("paths"), list) and all(isinstance(item, str) for item in node["paths"]) and node["paths"] != sorted(set(node["paths"])):
                errors.append(f"nodes[{index}] evidence paths are not sorted and unique")
            if not isinstance(node.get("schemas", []), list) or any(not isinstance(item, str) for item in node.get("schemas", [])):
                errors.append(f"nodes[{index}] evidence schemas are malformed")
            if isinstance(node.get("schemas"), list) and all(isinstance(item, str) for item in node["schemas"]) and node["schemas"] != sorted(set(node["schemas"])):
                errors.append(f"nodes[{index}] evidence schemas are not sorted and unique")
            if isinstance(node.get("roles"), list) and any(role not in {"source", "artifact"} for role in node["roles"] if isinstance(role, str)):
                errors.append(f"nodes[{index}] evidence role is unsupported")
            for path in node.get("paths", []) if isinstance(node.get("paths"), list) else []:
                try:
                    _safe_relative(path, f"nodes[{index}].paths")
                except ProofError as exc:
                    errors.append(str(exc))
    edges = graph.get("edges")
    if not isinstance(edges, list):
        errors.append("edges must be a list")
        edges = []
    edge_keys: set[str] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] is not an object")
            continue
        for key in ("from", "to", "kind"):
            if not isinstance(edge.get(key), str) or not edge[key]:
                errors.append(f"edges[{index}] is missing {key}")
        if edge.get("from") not in node_ids:
            errors.append(f"edges[{index}] references an unknown from node")
        if edge.get("to") not in node_ids:
            errors.append(f"edges[{index}] references an unknown to node")
        source = nodes_by_id.get(edge.get("from"))
        target = nodes_by_id.get(edge.get("to"))
        kind = edge.get("kind")
        if source is not None and target is not None:
            valid_relation = (
                (kind == "contains" and isinstance(edge.get("from"), str) and edge["from"].startswith("container:") and source.get("kind") in {"run", "ledger", "record"} and target.get("kind") == "record")
                or (kind == "continues" and source.get("kind") == "record" and target.get("kind") == "record")
                or (kind == "supports" and source.get("kind") == "evidence" and target.get("kind") == "record" and edge.get("role") == "source")
                or (kind == "produces" and source.get("kind") == "record" and target.get("kind") == "evidence" and edge.get("role") == "artifact")
            )
            if not valid_relation:
                errors.append(f"edges[{index}] has an invalid relation direction or role")
        allowed_keys = {
            "contains": {"from", "to", "kind", "sequence"},
            "continues": {"from", "to", "kind", "sequence"},
            "supports": {"from", "to", "kind", "role", "path", "schema"},
            "produces": {"from", "to", "kind", "role", "path"},
        }.get(kind)
        if allowed_keys is None:
            errors.append(f"edges[{index}] has an unsupported kind")
        elif set(edge) - allowed_keys:
            errors.append(f"edges[{index}] contains unsupported fields")
        if kind in {"contains", "continues"} and (not isinstance(edge.get("sequence"), int) or edge.get("sequence", 0) < 1):
            errors.append(f"edges[{index}] sequence is invalid")
        if kind in {"supports", "produces"} and (not isinstance(edge.get("path"), str) or not edge["path"]):
            errors.append(f"edges[{index}] path is missing")

        if kind in {"supports", "produces"} and isinstance(edge.get("path"), str):
            try:
                _safe_relative(edge["path"], f"edges[{index}].path")
            except ProofError as exc:
                errors.append(str(exc))
        if kind == "supports" and edge.get("schema") is not None and not isinstance(edge.get("schema"), str):
            errors.append(f"edges[{index}] source schema is malformed")
        if kind == "produces" and "schema" in edge:
            errors.append(f"edges[{index}] artifact relation may not carry a schema")
        if kind in {"contains", "continues"} and target is not None and isinstance(edge.get("sequence"), int):
            if target.get("sequence") != edge["sequence"]:
                errors.append(f"edges[{index}] sequence does not match target record")
        if kind == "continues" and source is not None and target is not None and isinstance(source.get("sequence"), int) and source.get("sequence") >= edge.get("sequence", 0):
            errors.append(f"edges[{index}] continues edge does not move forward")
        if kind == "continues" and source is not None and target is not None and target.get("prev_sha256") != source.get("sha256"):
            errors.append(f"edges[{index}] continues edge does not match target prev_sha256")
        if kind == "supports" and source is not None and edge.get("path") not in source.get("paths", []):
            errors.append(f"edges[{index}] source path is not present on the evidence node")
        if kind == "supports" and source is not None and edge.get("role") not in source.get("roles", []):
            errors.append(f"edges[{index}] source role is not present on the evidence node")
        if kind == "supports" and source is not None and edge.get("schema") is not None and edge.get("schema") not in source.get("schemas", []):
            errors.append(f"edges[{index}] source schema is not present on the evidence node")
        if kind == "produces" and source is not None and edge.get("path") not in nodes_by_id.get(edge.get("to"), {}).get("paths", []):
            errors.append(f"edges[{index}] artifact path is not present on the evidence node")
        if kind == "produces" and target is not None and edge.get("role") not in target.get("roles", []):
            errors.append(f"edges[{index}] artifact role is not present on the evidence node")
        key = _edge_key(edge)
        if key in edge_keys:
            errors.append(f"duplicate graph edge: {key}")
        edge_keys.add(key)
    if graph.get("node_count") != len(nodes):
        errors.append("node_count does not match nodes")
    if graph.get("edge_count") != len(edges):
        errors.append("edge_count does not match edges")
    containers = [node for node in nodes if isinstance(node, dict) and isinstance(node.get("id"), str) and node["id"].startswith("container:")]
    if len(containers) != 1:
        errors.append("graph must contain exactly one container node")
    elif containers[0].get("sha256") != graph.get("input_claim_sha256"):
        errors.append("container sha256 does not match input_claim_sha256")
    elif containers[0].get("kind") != {RECORD_SCHEMA: "record", LEDGER_SCHEMA: "ledger", RUN_SCHEMA: "run"}.get(graph.get("input_schema")):
        errors.append("container kind does not match input_schema")
    if nodes != sorted(nodes, key=lambda node: (str(node.get("kind", "")), str(node.get("id", ""))) if isinstance(node, dict) else ("", "")):
        errors.append("nodes are not in canonical order")
    if edges != sorted(edges, key=_edge_key):
        errors.append("edges are not in canonical order")
    if _has_cycle(nodes, edges):
        errors.append("graph contains a cycle")

    unknowns = sorted(set(item for item in graph.get("unknowns", []) if isinstance(item, str)))
    input_state = "unbound"
    structural_ok = not errors
    if not bound_input:
        unknowns = sorted(set(unknowns + ["input_not_bound"]))
        if require_input or require_observed or require_artifacts:
            errors.append("source input is required")
    else:
        try:
            expected = graph_document(
                document,
                artifact_root=artifact_root,
                require_observed=require_observed,
                require_artifacts=require_artifacts,
            )
            if expected["graph_sha256"] != supplied_hash:
                errors.append("graph does not match the bound source document")
            input_state = "bound"
        except ProofError as exc:
            errors.append(str(exc))
            input_state = "invalid"
    if require_observed and bound_input and not graph.get("observed"):
        errors.append("observed result is required")
    if require_artifacts and bound_input and graph.get("artifact_state") != "verified":
        errors.append("artifact verification is required")
    return {
        "schema": GRAPH_VERIFY_SCHEMA,
        "ok": not errors,
        "integrity": structural_ok,
        "bound_input": bound_input,
        "input_state": input_state,
        "graph_sha256": supplied_hash if isinstance(supplied_hash, str) else None,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "unknowns": unknowns,
        "errors": sorted(set(errors)),
    }
