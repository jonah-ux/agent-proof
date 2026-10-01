# Changelog

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
