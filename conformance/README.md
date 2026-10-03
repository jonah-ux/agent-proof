# Agent Systems Lab conformance corpus

`agent-systems-lab.json` is the public adapter inventory for the Agent Proof interoperability
layer. The fixtures are generated in tests from synthetic payloads, then normalized through the
same source-bound adapter registry used by the CLI.

The corpus is intentionally loss-aware: identity values become digests, unlisted fields remain
outside the normalized projection, and malformed or unknown schemas fail closed. A successful
normalization proves an integrity-bound projection, not deployment or a user-visible outcome.

The Forgeyard consumer corpus in [`forgeyard-ai-work-evidence-v1.json`](forgeyard-ai-work-evidence-v1.json)
pins the public `ai-work-evidence/v1` cases at Forgeyard commit
[`157ccbabc4c622848de2a1c0547bbc6ad5863a69`](https://github.com/jonah-ux/forgeyard/tree/157ccbabc4c622848de2a1c0547bbc6ad5863a69).
Agent Proof consumes the contract through its native interop adapter, preserving `observed`,
`verified`, `failed`, and `unknown` status values while refusing unsupported versions, unsafe
artifact names, malformed hashes, and malformed documents.
