# Agent Proof v2 schema notes

Agent Proof keeps the record body canonical before adding its digest. Every JSON hash uses
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)` encoded
as UTF-8. The exact canonicalization is part of the public contract because a proof is useful only
when an independent reader can recompute it.

## Record

`agent-proof/record/v2` has these sections:

- `run_id`, `sequence`, `prev_sha256`, `recorded_at`, and `actor` identify the chain position.
- `repository` binds the operation to an optional URL, branch, and commit.
- `operation.argv` and `operation.cwd` describe the invocation. `operation.environment` stores
  names plus value digests; it never stores environment values.
- `result` stores exit status, timeout, duration, stdout/stderr byte counts and digests, and the
  explicit `observed`, `partial`, and `unknowns` state.
- `sources` names sibling JSON envelopes by relative path, size, digest, and detected schema.
- `artifacts` names other files by relative path, size, and digest.
- `notes` is bounded human context. It is not an authorization channel.
- `record_sha256` is the digest of the complete record without that field.

## Chain

`agent-proof/ledger/v2` stores one repository identity and an ordered `records` array. The first
record has `sequence: 1` and `prev_sha256: null`. Every later record has the next integer sequence
and the preceding record's `record_sha256`. The ledger digest covers the schema, run identity,
repository, and complete records array.

Appending always verifies the existing ledger first. A changed repository identity, broken link,
invalid record, missing file, or changed source/artifact refuses the append.

## Run proof

`agent-proof/run/v2` embeds the full chain so a verifier does not need a mutable ledger file. It
repeats the record hashes, count, observation state, partial state, and union of unknowns. The
verifier recomputes those summaries from the embedded records and refuses a disagreement.

## Evidence boundary

The hash proves the bytes that were checked. It does not prove who created them, that a command was
safe, that a deployment occurred, or that a user saw the result. `observed: true` is a caller claim
that must be supported by the sibling evidence and workflow that produced the record. If that
evidence is partial or unknown, the record says so and the merged run remains correspondingly
unobserved or partial.

## Export bundles and independent readback

`export_bundle` writes `agent-proof/export/v2` as a deterministic gzip/tar. The archive contains
`manifest.json`, `proof/document.json`, and source/artifact bytes. Manifest entries identify the
archive path, source-relative path where applicable, byte size, and SHA-256. The current export
contract infers the source category from the `sources/` or `artifacts/` archive prefix; it does not
add a second category field to the manifest.

`verify-bundle` reads the archive without trusting tar extraction. It rejects absolute paths, `..`
components, backslashes, duplicate names, symlinks, hard links, devices, FIFOs, unlisted members,
and size-limit violations. It checks the manifest's document schema and canonical `input_sha256`,
then materializes only declared files into a temporary root and calls the existing v2 verifier.
The temporary root is removed before the result is returned. The bundle digest, manifest digest,
and document digest remain visible in `agent-proof/bundle-verify/v1`.

`collect` is a schema-aware adapter for known sibling outputs. It creates one record per input in
relative-path order and stores source digests rather than raw envelope values. It never infers
observation from a generic `ok` field: missing explicit observation becomes an `unknowns` entry.

## Provenance graph

`agent-proof/graph/v1` is a derived, deterministic view over one `record/v2`, `ledger/v2`, or
`run/v2` document. The graph records the input document digest and its self-hash as separate
claims, then emits sorted nodes and edges:

- one `container:<sha256>` node for the input record, ledger, or run;
- `record:<sha256>` nodes with sequence, predecessor, observation, and unknown state;
- deduplicated `blob:<sha256>` evidence nodes with sorted source/artifact roles, relative paths,
  and source schemas;
- `contains`, `continues`, `supports`, and `produces` edges with fixed directions and roles.

The graph does not copy command output, environment values, or operation working directories. It
has its own `graph_sha256`; changing a graph does not rewrite a v2 proof hash. A source-bound
`verify-graph --input` run re-derives the graph and compares the complete representation. An
unbound readback checks only the graph structure and marks `input_not_bound` as an unknown; the
`--require-input`, `--require-observed`, and `--require-artifacts` gates require a source-bound
readback.
