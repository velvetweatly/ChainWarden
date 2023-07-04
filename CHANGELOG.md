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
- `--key-size-min` and `--days-before-expiry` overrides on the `audit`
  subcommand so policy thresholds can be tuned per fleet without editing code.
- `expiry` subcommand now accepts a `--bundle` flag for reading concatenated
  bundles directly instead of scanning a directory.

### Fixed

- Chain builder now prefers the longest matching candidate chain when multiple
  issuers share a common name, instead of stopping at the first match.

## [0.5.0] - 2025-11-18

### Added

- Expiry cliff detection: when a configurable share of certificates in one
  directory expire inside the same window, a single `EXPIRY_CLIFF` finding is
  reported for the group instead of hundreds of individual lines.
- `--group-by` on `audit` to cluster findings by issuer, by day of expiry, or
  by key size for triage.

### Changed

- Finding severities are now sorted in output: ERROR lines first, then WARN,
  then INFO, regardless of scan order.

## [0.4.0] - 2024-06-21

### Added

- Extended key usage and basic constraints sanity checks for CA certificates:
  path length violations, missing key usage bits, and leaf certificates that
  assert CA rights.
- `--chain` flag on `audit` prints the resolved trust chain next to each
  finding so an operator can see which anchor a chain actually resolves to.

### Changed

- `certmodel` now records the subject alternative names and the SHA256
  fingerprint for every parsed certificate; both are exposed in the report.

## [0.3.0] - 2023-08-09

### Added

- Name based chain assembly with self signed root detection and loop guarding
  (`chainbuild.py`). Chains are built by matching issuer names to subject
  names and walking upward until a self signed anchor or a loop is found.
- `chain` subcommand that prints each resolved chain, its depth, and the
  anchor fingerprint.

