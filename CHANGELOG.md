# Changelog

## 0.4.2 - 2026-10-03

- Return structured graph refusals for malformed JSON field shapes before set/dictionary
  lookups, relation checks, cycle inspection, or unknown-state collection.
- Require actual JSON integers for graph node/edge counts and guard chain-sequence comparisons.
- Refuse malformed record unknowns, Boolean sequences, and missing run identities in the native
  record verifier before graph derivation; check record-node claims during unbound graph readback.
- Reject unsupported node fields and normalize record unknowns to sorted unique strings.
- Check native record observation/partial Boolean fields and canonical repository identity
  before derivation; refuse malformed repository fields during unbound graph verification.
- Keep invalid schema values out of graph diagnostics; valid graph hashing and source binding
  retain the existing contract.
- Cover the malformed-field API and CLI paths in the graph regression suite used by source,
  installed wheel, and installed source-distribution CI consumers.

## 0.4.1 - 2026-10-03

- Correct graph verification for standalone `record/v2` inputs: the record container has
  no chain sequence, while actual record nodes still require a positive sequence.
- Refuse JSON booleans as record-node or chain-edge sequence integers.
- Cover observed and unobserved standalone graph readback and portable bundle verification
  after the original artifact root is removed.
- Run the graph regressions against installed wheel and source consumers in CI and before
  publication. Existing 0.4.0 tags and assets retain their original bytes.

## 0.4.0 - 2026-10-03

- Add native Sandbox v2, Trace inspect/query, MCP Doctor, and Worktree Conservator adapters,
  with bounded counters, signed Sandbox signal exits, and validated declared digests.
- Bind interop projections and source verification to one captured byte buffer.
- Include the compatibility charter and producer-derived native fixtures in source archives;
  exercise native adapters against installed wheel and source consumers.
- Publish the existing Forgeyard shared-evidence adapter and Agent Systems Lab conformance
  corpus alongside the native adapter release.
- Require source tests, installed native adapter checks, matching package/version readback,
  and asserted bundle/graph/interop demo results before automated publication.

## Unreleased — Forgeyard shared evidence consumer

- Add a native `ai-work-evidence/v1` interop adapter and pinned seven-case consumer corpus.
- Preserve shared evidence status and unknown semantics while refusing malformed or unsafe input.

## Unreleased — Agent Systems Lab conformance corpus

- Add a synthetic adapter inventory and conformance tests for policy, sandbox, evaluation, trace,
  context-pack, resume, and context-integrity envelopes.

## 0.3.1 - 2026-10-02

- Reissued the context-integrity interoperability release through the annotated-tag workflow.
- Kept the installed CLI version, package metadata, and release identity aligned.

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
- Aligned the installed `agent-proof --version` entry point with the 0.3.0 package release.

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
