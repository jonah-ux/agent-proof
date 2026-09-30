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

## See it work

The first envelope is deliberately honest: it records evidence without claiming a user-visible result.

```json
{"schema":"agent-proof/v1","observed":false,"commands":[],"artifacts":[],"notes":["Capture records evidence; it does not claim a user-visible result."],"sha256":"e21fe6e647a7e4f650a9660d57f5452a6a57f6e82aece4ec2feddc13eacac881"}
```

## Related tools

Use [Agent Eval Kit](https://github.com/jonah-ux/agent-eval-kit) for repeatable checks, [Agent Resume](https://github.com/jonah-ux/agent-resume) for continuation records, and [Worktree Conservator](https://github.com/jonah-ux/worktree-conservator) when the evidence concerns workspace lifecycle.

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
