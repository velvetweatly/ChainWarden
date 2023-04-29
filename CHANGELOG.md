# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and this project uses semantic versioning.

## [Unreleased]

### Added

- CI job runs the audit against the bundled sample PKI with `--as-of` so the
  expected failure exit code is pinned to a fixed date.

## [0.6.0] - 2026-09-02

### Added

- `--format json` output mode: the report renderer can now emit one JSON object
  per finding, which makes the auditor safe to pipe into alerting pipelines.
