# Architecture

Agent Proof has one deliberately small data path:

```text
JSON operation spec
        |
        v
  record canonicalizer  ---> record_sha256
        |
        v
  append-only ledger     ---> ledger_sha256
        |
        v
  merged run proof      ---> run_sha256
        |
        +--> deterministic export bundle
        |          |
        |          +--> independent bundle readback
        |
        +--> redacted provenance graph
                   |
                   +--> optional source-bound verification
```

## Ownership boundaries

- **Record construction** (`build_record`) validates the operation contract, hashes output and environment values, and binds source and artifact metadata to an explicit artifact root. It never embeds raw command output.
- **Ledger and run verification** (`verify_record`, `verify_ledger`, `verify_run`, `verify_document`) recompute canonical hashes, sequence links, repository identity, and file digests. These functions decide byte integrity; they do not infer that a user-visible outcome occurred.
- **Bundle export and readback** (`export_bundle`, `verify_bundle`) own the archive boundary. Export writes normalized tar metadata. Readback validates member names and types, size limits, manifest coverage, digests, and only then materializes a private temporary artifact root for the normal verifier.
- **Graph derivation and verification** (`graph_document`, `verify_graph`) expose relationships between the proof container, records, source blobs, and artifacts. Graph verification can run unbound or bind back to the original proof document.
- **CLI orchestration** (`cli.py`) translates arguments into these domain operations and emits stable JSON. It does not implement a second verification path.

The large verification functions are intentionally orchestration-heavy because each one represents a trust boundary with ordered refusal checks. Future extraction should preserve those boundaries and stable error contracts; splitting by line count alone would make the security review harder.

## Invariants

1. Canonical JSON and domain-specific digests are deterministic across runs.
2. A valid hash proves byte identity for the checked inputs, not authorship, deployment, adoption, or a user-visible result.
3. Unknown, partial, or unobserved outcomes remain explicit.
4. Archive members must be regular files with safe relative names and bounded sizes.
5. Source and artifact paths are relative to an explicit root and cannot traverse symlinks.
6. Bundle verification must work after the original checkout and artifact root are gone.
7. A graph is a derived, redacted view; it cannot silently replace the proof it claims to describe.

## Failure model

Malformed JSON, invalid UTF-8, unsupported schemas, stale hashes, changed repository identity, broken chain links, missing files, symlinks, traversal names, duplicate members, oversized payloads, and source-bound mismatches fail closed with structured errors. A refusal is evidence that the requested proof could not be established; it is not evidence that the underlying operation succeeded or failed.

## Non-goals

Agent Proof does not sign artifacts, attest to a provider, enforce process isolation, inspect private transcripts, prove deployment, or claim a user-visible result without an explicit observed result in the input record.
