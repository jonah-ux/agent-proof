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
