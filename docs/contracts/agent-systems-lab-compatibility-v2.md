# Offline compatibility declarations, version 2

The additive `agent-systems-lab/compatibility/v2` charter is an offline index of
thirteen independently maintained public declarations. Agent Proof validates
their exact bytes, identity fields and selected native schema/capability facts.
It does not import sibling runtimes, fetch URLs, execute their tools, or turn a
declaration into an observed runtime outcome.

The reviewed source snapshot is [compatibility-v2.json](../../conformance/compatibility-v2.json).
Every declaration links to an immutable GitHub commit and has a SHA-256 byte
pin. The local copies in [conformance/owners](../../conformance/owners) preserve
those public bytes; each producer remains authoritative for its own schema.

## Read the charter and the declarations

From the source checkout:

```sh
agent-proof compatibility --schema v2 --manifest conformance/compatibility-v2.json
```

The charter check validates its structure and registry bindings. It does not
open any participant files. To validate all declared files, explicitly select
each owner once with `compatibility-artifacts --source OWNER=PATH` and an
`--artifact-root`. No cache directory is scanned and no URL is downloaded. An
optional `--cache-ref OWNER=URL` must exactly match the charter's artifact URL.
Extra owners, missing selections and unbound cache references refuse.

The same calls are available to installed wheel and source-distribution
consumers. The wheel contains the checker, while source-level charter and
fixtures are supplied through explicit paths. The source distribution includes
the `conformance` resources. Running from the original checkout is not an
installation proof; distribution checks must run outside it and verify the
module comes from the environment's installed package.

## What the reader checks

All thirteen entries use JSON content validation. Each entry binds `owner` and
`schema`; a source with its own `repository` field must match it. A source
without that field binds the repository through the immutable artifact URL,
revision and digest instead of receiving an invented repository property.
Every JSON owner contract declares `repository_field` explicitly. It is null
only when the source omits the repository field. A declared source repository
cannot be disabled by omitting, nulling or remapping its selector.

The reader uses two closed selector forms: `field` reads a string or string
list, and `list_field` reads one named string field from a list of objects.
These cover scalar `native_schema`/`receipt_schema`/`inspect_schema`, native
schema lists, and Agent Proof's adapter and consumer registries. There is no
executable JSONPath, expression evaluator or generic object traversal.

Native schema strings retain their `/vN` suffix. Registry identifiers use the
base family, with explicit admitted integer versions. The reader checks both
the reviewed implementation's admission set and this charter's native
registry. Sandbox v2 is declared by the current producer and accepted by Agent
Proof's current input registry; the older v1 source snapshot stays frozen.

Every JSON artifact requires a nonempty `source_fields` projection recording
the selected source field, schema and declaration role. Missing, null or empty
provenance refuses. The reader reconstructs that projection from the actual
JSON and checks it.
`declared_input` describes adapter/consumer input declarations;
`declared_boundary` preserves other native schema facts without guessing that
the tool ran or produced a particular artifact. Participant roles may remain
`unknown` when the declaration does not establish a stronger role.

Capability names and capability versions are different facts. Native owner
documents that list operation names without capability versions remain
declaration-only: their registry entry has `supported_versions: []`, and their
content report says `capability_versions: not_declared`. Package semver, native
schema suffixes and case names do not create capability-version support.
Forgeyard's `capability_protocols` maps operation names to native schema strings,
not integer capability versions. Those mappings must exactly match the pinned
declaration and stay within that owner's registered native schemas.

## Version negotiation

Peer files use `agent-systems-lab/capabilities/v1` with integer
`contract_version: 1`, `capabilities` and `native_protocols` arrays. Every entry
has a canonical `id` and sorted unique positive integer `supported_versions`.
Boolean values, unsupported families/versions, duplicates, unknown fields and
malformed declarations refuse before any version is selected.

```sh
agent-proof negotiate --kind native \
  --producer producer.json --consumer consumer.json --registry registry.json
```

`--kind capability` is the default. The API exposes `negotiate_capabilities`
and `negotiate_native_protocols` separately. A reviewed registry is required;
it may be passed explicitly or supplied as `capability_registry` in a peer
declaration. Every supplied registry is validated and contributes a constraint.
An explicit registry cannot override a peer's narrower inline registry.
The single-capability `negotiate_capability` convenience API requires the same
explicit registry and delegates to `negotiate_capabilities`; its built-in
identifier catalog cannot establish support without that constraint. Native
schema families use `negotiate_native_protocols`.

For each shared identifier, the result selects the highest version admitted
by both peers and every supplied registry. Missing identifiers and disjoint or
unversioned sets refuse. This proves agreement between explicit declarations,
not live runtime compatibility, authentication or adoption. In particular, the
charter's unversioned operation names cannot be copied into a successful
capability negotiation merely because their native schema has version 1.

## Input boundaries and report meaning

Manifests have a 4 MiB default byte budget; selected artifacts have a 64 MiB
per-file and 256 MiB aggregate budget. Smaller caller budgets are allowed.
The aggregate limit bounds bytes actually read, including reads that later
refuse. A file that cannot fit the remaining capacity refuses before reading,
and later participants are refused without opening after aggregate exhaustion.
Duplicate JSON keys, non-finite or oversized numbers, invalid UTF-8, non-object
manifests and nesting beyond 128 levels refuse. JSON errors never include raw
payloads or local paths in v2 reports.

Artifact paths stay inside the caller's explicit root. The POSIX reader rejects
traversal, symlinks, directories, named pipes and other non-regular targets;
missing files have a distinct refusal. Nonblocking opening prevents a named
pipe from waiting for a writer before its type is inspected. Each descriptor
has one owner and is closed once. File identity, size and modification/change
times detect changes during a read; those times are never evidence that a
native task was observed. Regular filesystem I/O is still subject to the
caller's filesystem and process-level deadlines.

The versioned refusal vocabulary is the charter's ordered `refusal_codes` list.
Errors are deterministic and deduplicated. CLI success returns exit 0; refusal
returns exit 2. Compatibility argument/input errors also emit path-free JSON.
Help and the existing non-compatibility CLI retain their normal interfaces.

Artifact reports use `agent-systems-lab/compatibility-artifacts/v1`.
`ok` and `complete` are true only when every selected participant's required
content checks pass. A `bytes` entry can prove its digest but reports
`content_unvalidated`, with both flags false; it cannot stand in for the full
JSON declaration gate. Reports always say `remote_state: not_contacted` and
`execution: not_attempted`. Native invocation evidence belongs to each owner.

## Version 1 inheritance and limits

The v1 charter is frozen at canonical digest
`4e91ef19b1d4dddb2da41b9065f3a3979df960f5b061308d68bc281ec1ee79ec`, with thirteen
participants. V2 binds that reference rather than rewriting its historical
artifact pins, statuses, redaction policy or adapter contracts.
The v2 participant count and owner identities must match the frozen reference;
dropping, adding or substituting an owner refuses even when new source bytes
have matching recomputed hashes. Expanding the set requires a new reviewed
reference contract. This identity check does not authenticate arbitrary pins.
V1 valid
acceptance and its `manifest` report field remain available. V2 diagnostics
are path-independent; the historical v1 report field is intentionally a caller
path and must be considered before sharing a v1 report.

Native producers retain timestamp authority; rewriting timestamps or inferring
observations from cache/file times is forbidden. The declaration validator
does not reinterpret native event payloads or enforce every domain-specific
rule of a sibling tool. Exact byte/content checks do not prove GitHub authorship,
external URL availability, reproducible builds, security certification,
deployment, outside review or production readiness. Immutable source links,
native conformance, hosted CI and fresh consumer evidence remain separate gates.
