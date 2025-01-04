<div align="center">

<img src="docs/assets/logo.svg" width="300"
     alt="A three block certificate chain, root then intermediate then leaf, linked left to right, beside the wordmark ChainWarden" />

# ChainWarden

*Audits a fleet of X.509 and TLS certificates offline: expiry, weak keys, weak
signatures, and name-based chain structure.*

[Install](#install) &nbsp;&middot;&nbsp;
[Commands](#commands) &nbsp;&middot;&nbsp;
[Output format](#output-format) &nbsp;&middot;&nbsp;
[Limitations](#what-chainwarden-does-not-verify)

</div>

---

## The expiry cliff problem

A certificate outage rarely announces itself. It arrives at 02:00 on a public
holiday when the one person who remembered the renewal has left the company,
and the first symptom is a support queue rather than an alert. The certificate
did not fail. It did exactly what it was told to do, on the date printed inside
it, and nobody was reading that date.

The harder version of the same problem is the cliff. When a batch of
certificates is issued together, from one automation run or one migration, they
tend to share a validity window and therefore expire together. You do not get
one outage, you get a wall of them inside a few days, and each renewal competes
with the others for the same tired operator.

ChainWarden exists to read those dates for you, ahead of time, from the
certificates you already have on disk. Point it at a directory of PEM files or a
concatenated bundle. It splits and decodes the PEM blocks, walks the DER to
reach the fields that matter, builds candidate trust chains by matching issuer
names to subject names, and reports expiry problems, weak signature algorithms,
weak RSA keys, chain path building failures, and basic constraint or key usage
mistakes.

Two properties make it dependable in a pipeline:

- It uses the Python standard library only. There is no network access anywhere
  in the code: no sockets, no HTTP, no DNS, no shelling out to network tools.
  What you audit is exactly the bytes on disk.
- It never reads the wall clock. You give it a reference date with `--as-of`,
  and it echoes that date in every output header, so a run on your laptop today
  and a run in CI next week produce identical output from identical input.

## Install

Install from the project root. This exposes a `chainwarden` command on your
path:

```
pip install .
```

You can also run it straight from a checkout without installing, which is how
every command in this document was run:

```
python -m chainwarden <subcommand> ...
```

The only requirement is Python 3.11 or newer, declared in `pyproject.toml`.
There are no third party dependencies to resolve.

## Commands

ChainWarden has four subcommands. The top level help lists them:

```
$ python -m chainwarden --help
usage: chainwarden [-h] {audit,chain,expiry,version} ...

Offline X.509 and TLS certificate fleet auditor.

positional arguments:
  {audit,chain,expiry,version}
    audit               run policy checks and print findings
    chain               build and print trust chains
    expiry              list certificates by expiry
    version             print the version and exit

options:
  -h, --help            show this help message and exit
```

| Subcommand | What it does                                       | Needs `--as-of` |
|------------|----------------------------------------------------|-----------------|
| `audit`    | Run every check and print findings                 | Yes             |
| `chain`    | Build and print candidate trust chains             | No              |
| `expiry`   | List certificates ordered by expiry                | Yes             |
| `version`  | Print the version and exit                         | No              |

A path argument may be a single PEM file that holds one or many CERTIFICATE
blocks, or a directory. When it is a directory, every `*.pem`, `*.crt`, and
`*.cer` file inside is read, non recursively. Files are visited in sorted order
and blocks in file order, and duplicate certificates (same SHA256 fingerprint)
are kept once, so the output is deterministic.

The `audit` subcommand takes four tuning flags beyond the input paths:

```
$ python -m chainwarden audit --help
usage: chainwarden audit [-h] --as-of YYYY-MM-DD
                         [--expiry-warn-days EXPIRY_WARN_DAYS]
                         [--cliff-window-days CLIFF_WINDOW_DAYS]
                         [--cliff-count CLIFF_COUNT]
                         paths [paths ...]

positional arguments:
  paths                 PEM files or directories of PEM certificates

options:
  -h, --help            show this help message and exit
  --as-of YYYY-MM-DD    reference date for expiry checks
  --expiry-warn-days EXPIRY_WARN_DAYS
  --cliff-window-days CLIFF_WINDOW_DAYS
  --cliff-count CLIFF_COUNT
```

The defaults are 90 days for the expiring soon warning, a 30 day window for the
cliff grouping, and a minimum of 3 certificates to call a window a cliff.

## A worked audit

This section follows one certificate, `leaf-weak.pem` in the samples, from the
PEM text on disk to the two findings it produces. The other samples travel the
same path.

The file starts as base64 wrapped in markers:

```
-----BEGIN CERTIFICATE-----
MIIC... (trimmed)
-----END CERTIFICATE-----
```

`pemread.certificate_ders` splits the buffer on the BEGIN and END lines, keeps
only blocks labelled `CERTIFICATE`, and base64 decodes the body to raw DER
bytes. Any other label, such as a `PRIVATE KEY` block in a mixed bundle, is
skipped rather than treated as an error.

`certmodel.parse_certificate` then walks that DER with the tag-length-value
reader in `der.py`. It descends the outer `Certificate` SEQUENCE into the
`TBSCertificate`, reads past the optional version tag, and pulls out the serial,
the issuer and subject names, the two validity times, and the
`SubjectPublicKeyInfo`. For this leaf the public key algorithm OID is
`1.2.840.113549.1.1.1` (rsaEncryption), so the parser reads the RSA modulus
INTEGER and measures its bit length: 1024. The signature algorithm OID on the
outer certificate is `1.2.840.113549.1.1.5`, which the name table renders as
`sha1WithRSAEncryption`.

Two policy checks in `policy.py` now have targets. `check_weak_key` sees the
1024 bit modulus is below the 2048 bit minimum and emits an ERROR with code
`WEAK_KEY`. `check_weak_signature` looks up the signature OID in the weak set,
finds the SHA1 reason, and emits an ERROR with code `WEAK_SIG`. Running the
audit over the bundle confirms both, verbatim:

```
$ python -m chainwarden audit samples/bundle.pem --as-of 2026-09-02
# ChainWarden audit as of 2026-09-02
ERROR EXPIRED          C=US, O=ChainWarden Test PKI, CN=expired.example.test :: expired 823 days ago on 2024-06-01
ERROR WEAK_KEY         C=US, O=ChainWarden Test PKI, CN=weak.example.test :: RSA key size 1024 bits is below the 2048 bit minimum
ERROR WEAK_SIG         C=US, O=ChainWarden Test PKI, CN=weak.example.test :: weak signature algorithm sha1WithRSAEncryption (SHA1 based signature)
WARN  EXPIRING_SOON    C=US, O=ChainWarden Test PKI, CN=soon.example.test :: expires in 29 days on 2026-10-01
# 4 findings: 3 ERROR, 1 WARN
```

The two `weak.example.test` lines are the end of the journey for `leaf-weak.pem`.
The `EXPIRED` and `EXPIRING_SOON` lines come from two other leaves that took the
same path with different data.

The `chain` subcommand walks the same parsed certificates upward instead. It
takes each leaf and repeatedly finds a certificate whose subject equals the
current issuer, until it reaches a self signed root or runs out of candidates.
For the weak leaf that path is three deep and complete:

```
$ python -m chainwarden chain samples/bundle.pem
chain good.example.test depth=3 complete
[leaf] good.example.test exp 2027-01-01 rsaEncryption/2048 sha256WithRSAEncryption
  [ca] ChainWarden Test Intermediate CA exp 2032-01-01 rsaEncryption/2048 sha256WithRSAEncryption
    [root] ChainWarden Test Root CA exp 2034-01-01 rsaEncryption/2048 sha256WithRSAEncryption
chain soon.example.test depth=3 complete
[leaf] soon.example.test exp 2026-10-01 rsaEncryption/2048 sha256WithRSAEncryption
  [ca] ChainWarden Test Intermediate CA exp 2032-01-01 rsaEncryption/2048 sha256WithRSAEncryption
    [root] ChainWarden Test Root CA exp 2034-01-01 rsaEncryption/2048 sha256WithRSAEncryption
chain expired.example.test depth=3 complete
