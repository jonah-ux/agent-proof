# Agent Systems Lab conformance corpus

`agent-systems-lab.json` is the public adapter inventory for the Agent Proof interoperability
layer. The fixtures are generated in tests from synthetic payloads, then normalized through the
same source-bound adapter registry used by the CLI.

The corpus is intentionally loss-aware: identity values become digests, unlisted fields remain
outside the normalized projection, and malformed or unknown schemas fail closed. A successful
normalization proves an integrity-bound projection, not deployment or a user-visible outcome.

The Forgeyard consumer corpus in [`forgeyard-ai-work-evidence-v1.json`](forgeyard-ai-work-evidence-v1.json)
pins the public `ai-work-evidence/v1` cases at Forgeyard commit
[`d6feb5b0ec0f7ccb4fb7f56939e8513972b0855d`](https://github.com/jonah-ux/forgeyard/tree/d6feb5b0ec0f7ccb4fb7f56939e8513972b0855d).
The pinned `conformance/manifest.json` has SHA-256
`6fe5fc6c5993f161111110971927b07e7db4b7d9f01eac352afd173ce31e7924`.
Tests assert the commit, manifest digest, and complete seven-case shape before exercising
source-bound normalization and verification. Refresh this pin when Forgeyard changes its
owner manifest; the native policy and sandbox schemas remain owned by their respective projects.
Agent Proof consumes the contract through its native interop adapter, preserving `observed`,
`verified`, `failed`, and `unknown` status values while refusing unsupported versions, unsafe
artifact names, malformed hashes, and malformed documents.
