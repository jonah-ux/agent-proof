# Agent Systems Lab compatibility/v1

`agent-systems-lab/compatibility/v1` is the additive umbrella charter for
Jonah-UX's public Agent Systems Lab. Agent Proof owns the charter checker and
reviewed adapter registry because it already owns source-bound normalization and
digest semantics. The specialist repositories remain authoritative for their
native records, tests, refusal reasons, and release cadence.

## What the charter does

The manifest at [`conformance/compatibility-v1.json`](../../conformance/compatibility-v1.json)
defines the public participants, native schema names, immutable conformance
revisions and SHA-256 pins, canonical JSON and SHA-256 rules, bounded
cross-repository statuses, redaction boundary, stable umbrella refusal classes,
and the reviewed Agent Proof adapter set. It is intentionally a small
compatibility index, not a runtime dependency graph.

The checker is dependency-free and reads only the checked-in manifest:

```console
python3 scripts/check_compatibility.py --json

# The same checker is available through the installed Agent Proof CLI when a
# source-level manifest is supplied explicitly.
agent-proof compatibility --manifest conformance/compatibility-v1.json
```

The report contains a canonical manifest SHA-256. A clean report proves that the
charter's own bytes satisfy the structural contract; it does not prove that every
participant is deployed together, that a source is fresh, or that an outcome was
observed.

The current Agent Proof wheel does not include the repository-level `conformance/`
tree, so installed callers must pass an explicit manifest path. The command
returns exit `0` for a valid charter and exit `2` for a malformed or invalid
charter; it never fetches sibling repositories or private configuration.

## Version and identity rules

- The exact charter schema is `agent-systems-lab/compatibility/v1`.
- `contract_version` is `1`; an unknown version refuses with `unknown_version`.
- Identifiers are bounded to 128 characters and the manifest's explicit ASCII
  pattern. Native repositories may impose stricter local rules.
- Canonical JSON is UTF-8, sorted-key, compact JSON with `allow_nan=false`.
- Digests are lowercase SHA-256 over canonical bytes. A digest binds bytes; it
  does not establish authorship, authorization, deployment, adoption, or a
  user-visible result.

## Status and refusal boundary

The umbrella vocabulary keeps `observed`, `verified`, `failed`, `unknown`,
`partial`, `unavailable`, and `blocked` distinct. Native owner codes remain
unchanged and may be carried alongside an umbrella refusal; this charter never
renames MCP Doctor, Worktree Conservator, Context Integrity, or other owner
reasons. The manifest makes that rule machine-readable with `owner_status` and
`owner_code` fields and a `do-not-infer` policy for missing values.

The umbrella codes cover only cross-repository failures: unsupported schema or
version, malformed or duplicated identifiers, digest/source binding failures,
unsafe paths, unsupported statuses, and redaction violations. They do not claim
to replace native policy, sandbox, lifecycle, retrieval, or diagnostic logic.

## Privacy and ownership boundary

The compatibility manifest carries schema names, public repository URLs,
conformance artifact URLs, bounded labels, and adapter field names. It carries no
raw prompts, transcript text, customer data, credentials, provider tokens,
private filesystem paths, or employer operating policy. Any future projection
must add a fixture and refusal test before it is listed here.

The current owner list is a source-level compatibility surface. Each conformance
artifact is pinned to a public immutable commit and content digest, so a future
revision cannot silently change what the charter reviewed. The pins are evidence
of source identity, not an adoption claim, deployment claim, or assertion that
all repositories are released as one product.
