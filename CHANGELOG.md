# Changelog

## Unreleased

- Added redacted provenance graph embedding to deterministic `export/v2` bundles.
- Added source-bound bundle graph readback and the explicit `--require-graph` gate,
  while keeping older bundles readable without the gate.
- Added `agent-proof/interop/v1` normalization for policy, sandbox, evaluation, trace,
  context-pack, resume, and proof envelopes, with allowlisted projections, explicit unknowns,
  source-byte binding, and fail-closed `verify-interop` readback.

## 0.3.0 - 2026-10-02

- Added a reviewed `context-integrity/v1` interoperability adapter and collectable schema,
  preserving scoped identity as digests, citation counts as bounded metrics, and answer text
  outside the normalized envelope.

## 0.2.0 - 2026-10-01

- Added redacted `agent-proof/record/v2` evidence records with canonical hashes,
  repository identity, command metadata, output digests, and explicit unknowns.
- Added append-only hash-linked ledgers and self-contained run proofs.
- Added independent verification for record, ledger, and run hashes, chain links,
  source envelopes, and referenced artifact bytes.
- Added portable `verify-bundle` readback that validates gzip/tar safety, manifest
  digests, and proof integrity after the original artifact root is removed.
- Added deterministic `collect` for known policy, sandbox, evaluation, trace,
  context, resume, and proof envelopes without storing their raw values.
- Added deterministic provenance graphs with separate graph hashes, typed
  container/record/evidence nodes, source-bound readback, and unbound-state gates.
- Added deterministic Markdown rendering and tarball export.
- Added a synthetic policy → sandbox → evaluation → proof workflow demo.

## 0.1.0 - 2026-09-30

Initial focused release with a stable CLI contract and synthetic demo.
