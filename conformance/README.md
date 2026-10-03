# Agent Systems Lab conformance corpus

`agent-systems-lab.json` is the public adapter inventory for the Agent Proof interoperability
layer. The fixtures are generated in tests from synthetic payloads, then normalized through the
same source-bound adapter registry used by the CLI.

The corpus is intentionally loss-aware: identity values become digests, unlisted fields remain
outside the normalized projection, and malformed or unknown schemas fail closed. A successful
normalization proves an integrity-bound projection, not deployment or a user-visible outcome.
