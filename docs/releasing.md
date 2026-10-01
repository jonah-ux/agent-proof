# Releasing

Run the full test suite, build wheel and sdist, install both in fresh environments, run the
policy → sandbox → evaluation → proof demo, verify its tamper refusal, create an annotated tag
through the approved repository route, publish wheel/source/checksum assets, then verify a fresh
download. The demo must also report `bundle_verified: true`, `bundle_tamper_refused: true`,
`graph_verified: true`, `graph_tamper_refused: true`, and `bundle_graph_verified: true` after
deleting its original fixture root.

## Automated prerelease path

The reviewed `.github/workflows/release.yml` runs only for an annotated semantic-version tag such as
`v0.2.0` (or the repository's current version). It builds the wheel and source archive, writes
`SHA256SUMS`, installs both distributions as fresh consumers, and creates a GitHub prerelease with
those assets. A normal push to `main` does not publish anything. Keep the release deliberate:
complete the checks above, review the exact commit, then push the approved tag through the
repository's governed route and verify the downloaded assets and checksums. A release is not
independently proven until a fresh consumer can run `agent-proof verify-bundle --require-graph`
against a bundle whose original artifact root is absent, receive `graph_state: "verified"`, and
perform a source-bound `agent-proof verify-graph` readback.

## Installed consumer gate

The CI workflow also installs the built wheel and source archive into separate fresh environments and runs the installed `agent-proof` entry point. The local equivalent is:

```bash
python3 -m venv /tmp/agent-proof-wheel
/tmp/agent-proof-wheel/bin/python -m pip install --no-deps dist/agent_proof-*.whl
/tmp/agent-proof-wheel/bin/agent-proof --version
/tmp/agent-proof-wheel/bin/agent-proof capture --out /tmp/agent-proof-wheel-capture.json

python3 -m venv /tmp/agent-proof-sdist
/tmp/agent-proof-sdist/bin/python -m pip install --no-deps dist/agent_proof-*.tar.gz
/tmp/agent-proof-sdist/bin/agent-proof --version
/tmp/agent-proof-sdist/bin/agent-proof capture --out /tmp/agent-proof-sdist-capture.json
```

This checks the distributed artifacts rather than only the source checkout. It still does not prove authorship, deployment, adoption, or a user-visible outcome without an explicit observed record.
