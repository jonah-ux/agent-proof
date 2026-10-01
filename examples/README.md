# Integration examples

`ci_release_proof.py` binds a release artifact to the exact GitHub commit and emits an observed, verifiable proof without storing command output or environment values.

```bash
GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 \
GITHUB_REPOSITORY=example/project \
PYTHONPATH=src python3 examples/ci_release_proof.py \
  --artifact-root examples --artifact ci-artifact.txt --out /tmp/ci-proof.json
```

The example is disposable and local. A production workflow should pass its real artifact root and CI-provided commit/run variables.
