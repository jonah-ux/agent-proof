# Releasing

Run the full test suite, build wheel and sdist, install both in fresh environments, run the
policy → sandbox → evaluation → proof demo, verify its tamper refusal, create an annotated tag
through the approved repository route, publish wheel/source/checksum assets, then verify a fresh
download.

## Automated prerelease path

The reviewed `.github/workflows/release.yml` runs only for an annotated semantic-version tag such as
`v0.2.0` (or the repository's current version). It builds the wheel and source archive, writes
`SHA256SUMS`, installs both distributions as fresh consumers, and creates a GitHub prerelease with
those assets. A normal push to `main` does not publish anything. Keep the release deliberate:
complete the checks above, review the exact commit, then push the approved tag through the
repository's governed route and verify the downloaded assets and checksums.
