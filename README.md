# Agent Proof

![evidence bundle builder workflow](docs/header.svg)

**Capture what ran, what changed, and what was actually observed.**

[![CI](https://github.com/jonah-ux/agent-proof/actions/workflows/ci.yml/badge.svg)](https://github.com/jonah-ux/agent-proof/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Agent Proof creates a small JSON evidence envelope for work that needs a clear boundary between
“a command ran” and “the intended result was observed.” The file is easy to archive, inspect, and
pass to another agent.

## Try it in 30 seconds

```bash
python -m pip install git+https://github.com/jonah-ux/agent-proof.git@main
python demos/demo.py
```

Capture an envelope, then verify it:

```bash
agent-proof capture --out proof.json
agent-proof verify proof.json
```

The `agent-proof/v1` record includes a hash, commands, artifacts, notes, and an explicit
`observed` field. A captured envelope stays unverified until a real observed result is recorded.

## Development

```bash
python -m unittest discover -s tests
python -m build --sdist --wheel
python demos/demo.py
```

This tool records evidence; it does not infer deployment, installation, or user-visible success.

MIT licensed.
