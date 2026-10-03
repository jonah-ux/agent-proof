# Release provenance

Agent Proof publishes prerelease wheels and source archives from annotated `vMAJOR.MINOR.PATCH`
tags. The release workflow checks that the annotated tag resolves to the checked-out commit,
builds both distributions, writes `dist/SHA256SUMS`, and runs isolated wheel and source-archive
consumers before publishing the prerelease.

The public audit script checks for these workflow markers and can compare a supplied distribution
directory with its checksum manifest:

```sh
python3 scripts/audit_public_surface.py --json
python3 scripts/audit_public_surface.py --dist-dir dist --json
```

The receipt is a source and artifact integrity aid. It does not claim a reproducible build across
machines, a security certification, deployment, adoption, or production readiness.
