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
[leaf] expired.example.test exp 2024-06-01 rsaEncryption/2048 sha256WithRSAEncryption
  [ca] ChainWarden Test Intermediate CA exp 2032-01-01 rsaEncryption/2048 sha256WithRSAEncryption
    [root] ChainWarden Test Root CA exp 2034-01-01 rsaEncryption/2048 sha256WithRSAEncryption
chain weak.example.test depth=3 complete
[leaf] weak.example.test exp 2028-01-01 rsaEncryption/1024 sha1WithRSAEncryption
  [ca] ChainWarden Test Intermediate CA exp 2032-01-01 rsaEncryption/2048 sha256WithRSAEncryption
    [root] ChainWarden Test Root CA exp 2034-01-01 rsaEncryption/2048 sha256WithRSAEncryption
```

The four chains above are drawn in the diagram below. Every common name and
expiry date in the diagram is the same text the CLI printed.

![Four leaf certificates, good soon expired and weak, each chaining through one shared intermediate CA to one shared self signed root, three levels deep](docs/assets/chain-depth.svg)

## What each check means

Each finding has a severity, a stable code, the subject it concerns, and a
message. The table below is the catalogue. Codes come from the `Finding`
objects constructed in `policy.py`.

| Check id           | Severity | What triggers it                                                                 | What to do                                                                 |
|--------------------|----------|----------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| `EXPIRED`          | ERROR    | `not_after` is earlier than `--as-of`                                            | Renew or remove the certificate now, it is already invalid                 |
| `NOT_YET_VALID`    | WARN     | `not_before` is later than `--as-of`                                             | Check the clock and the issuance date, deploy only after the start date    |
| `EXPIRING_SOON`    | WARN     | `not_after` is within `--expiry-warn-days` of `--as-of` (default 90)             | Schedule renewal before the printed date                                   |
| `WEAK_SIG`         | ERROR    | Signature algorithm is an MD5 or SHA1 based OID                                   | Reissue with a SHA256 or stronger signature                                |
| `WEAK_KEY`         | ERROR    | RSA modulus is below 2048 bits                                                    | Reissue with a 2048 bit or larger RSA key                                  |
| `LEAF_CERTSIGN`    | ERROR    | Basic constraints say not a CA, but key usage asserts `keyCertSign`              | Reissue without `keyCertSign`, a leaf must not sign certificates           |
| `CA_NO_CERTSIGN`   | WARN     | Basic constraints say CA, but key usage omits `keyCertSign`                      | Add `keyCertSign` to the CA, or it cannot issue                            |
| `BC_NOT_CRITICAL`  | WARN     | Basic constraints CA:TRUE is present but not marked critical                     | Reissue with basic constraints marked critical, per RFC 5280               |
| `CHAIN_INCOMPLETE` | ERROR    | A leaf never reaches a self signed root present in the pool                      | Add the missing issuer or root PEM to the input, then re-run              |
| `PATHLEN_EXCEEDED` | ERROR    | More certificates appear below a CA than its `pathlen` constraint allows         | Shorten the chain or reissue the CA with a larger `pathlen`                |
| `EXPIRY_CLIFF`     | WARN     | `--cliff-count` or more certificates expire inside one `--cliff-window-days`     | Stagger the renewals so they do not all fall due together                  |

The sample bundle does not trigger a cliff at the default 30 day window, because
the leaf expiries are spread across years. Widening the window to 1400 days
groups all four leaves into one bucket and the check fires:

```
$ python -m chainwarden audit samples/bundle.pem --as-of 2026-09-02 --cliff-window-days 1400 --cliff-count 3
# ChainWarden audit as of 2026-09-02
ERROR EXPIRED          C=US, O=ChainWarden Test PKI, CN=expired.example.test :: expired 823 days ago on 2024-06-01
ERROR WEAK_KEY         C=US, O=ChainWarden Test PKI, CN=weak.example.test :: RSA key size 1024 bits is below the 2048 bit minimum
ERROR WEAK_SIG         C=US, O=ChainWarden Test PKI, CN=weak.example.test :: weak signature algorithm sha1WithRSAEncryption (SHA1 based signature)
WARN  EXPIRING_SOON    C=US, O=ChainWarden Test PKI, CN=soon.example.test :: expires in 29 days on 2026-10-01
WARN  EXPIRY_CLIFF     (fleet) :: 4 certificates expire between 2024-06-01 and 2028-01-01, within a 1400 day window
```

The cliff buckets are anchored at the earliest `not_after` in the pool and use
fixed width windows, so the grouping does not depend on `--as-of`. This is a
deliberate simplification, discussed under design decisions below.

## Output format

Output is line oriented and rendered by `report.py`. Every subcommand prints one
record per line so two runs can be diffed cleanly in git.

The `audit` output opens with a header line, then one line per finding sorted by
severity then code then subject, then a summary line. Each finding line has four
fields:

| Field    | Column     | Width      | Source                          | Example                                        |
|----------|------------|------------|---------------------------------|------------------------------------------------|
| Severity | 1          | 5, left    | `Finding.severity`              | `ERROR`                                        |
| Code     | 2          | 16, left   | `Finding.code`                  | `WEAK_KEY`                                      |
| Subject  | 3          | to `::`    | `Finding.subject` (full RDN)    | `C=US, O=ChainWarden Test PKI, CN=weak...`     |
| Message  | after `::` | rest       | `Finding.message`               | `RSA key size 1024 bits is below the 2048...`  |

When there are no findings the body is a single `OK  no findings` line. The
summary counts findings by severity in the fixed order ERROR, WARN, INFO.

The `expiry` output opens with a header, then one line per certificate sorted by
`not_after` then common name. Each line carries the expiry date, the remaining
days as a signed right aligned integer with a `d` suffix, a state word, and the
common name:

```
$ python -m chainwarden expiry samples/bundle.pem --as-of 2026-09-02
# expiry sorted by notAfter, as of 2026-09-02
2024-06-01   -823d EXPIRED expired.example.test
2026-10-01     29d valid   soon.example.test
2027-01-01    121d valid   good.example.test
2028-01-01    486d valid   weak.example.test
2032-01-01   1947d valid   ChainWarden Test Intermediate CA
2034-01-01   2678d valid   ChainWarden Test Root CA
```

The `chain` output prints, per leaf, a header line reading
`chain <cn> depth=<n> <complete|incomplete>`, then one indented line per
certificate from leaf to anchor. Each certificate line names its role (`leaf`,
`ca`, or `root`), the common name, the expiry date, the public key algorithm
with the RSA size appended when known, and the signature algorithm.

## Exit codes

The exit code is the machine readable summary. It lets a CI job or a shell
script react without parsing the text.

| Code | Meaning              | Which subcommands                                        |
|------|----------------------|----------------------------------------------------------|
| 0    | Clean                | `audit` with no findings; `chain` when all chains complete; `expiry` when nothing is expired; `version` always |
| 1    | Findings present     | `audit` with one or more findings; `chain` with an incomplete chain; `expiry` when at least one certificate is expired |
| 2    | Usage error          | Any subcommand: a path not found, malformed PEM, bad DER, or a certificate that fails to parse |

Confirmed from the runs above: the audit over the sample bundle prints findings
and exits 1, and pointing `chain` at a missing directory exits 2:

```
$ python -m chainwarden chain no_such_dir_xyz
error: path not found: no_such_dir_xyz
$ echo $LASTEXITCODE
2
```

## The test PKI in samples

The `samples/` directory holds a real test PKI generated with OpenSSL 3.6.1 on
the machine that built the project. These are test vectors, not production
certificates. Every private key was discarded after signing, so nothing here can
impersonate anything. Subject names use the reserved `.test` label and the
organisation is literally `ChainWarden Test PKI`.

| File               | Role         | Key      | Signature               | notAfter   |
|--------------------|--------------|----------|-------------------------|------------|
| `root.pem`         | root CA      | RSA 2048 | sha256WithRSAEncryption | 2034-01-01 |
| `intermediate.pem` | intermediate | RSA 2048 | sha256WithRSAEncryption | 2032-01-01 |
| `leaf-good.pem`    | leaf         | RSA 2048 | sha256WithRSAEncryption | 2027-01-01 |
| `leaf-soon.pem`    | leaf         | RSA 2048 | sha256WithRSAEncryption | 2026-10-01 |
| `leaf-expired.pem` | leaf         | RSA 2048 | sha256WithRSAEncryption | 2024-06-01 |
| `leaf-weak.pem`    | leaf         | RSA 1024 | sha1WithRSAEncryption   | 2028-01-01 |
| `bundle.pem`       | all six of the above concatenated, in the order listed             |

The validity dates are pinned with OpenSSL's `-not_before` and `-not_after`
flags rather than `-days`, and serial numbers are fixed with `-set_serial`, so
regenerating the PKI produces the same dates and serials on any machine. The
public keys, and therefore the SHA256 fingerprints, differ on each run because
fresh keypairs are generated. The exact commands live in `samples/gen_pki.sh`;
`samples/README.md` narrates them. To regenerate, with OpenSSL on the path:

```
sh samples/gen_pki.sh
```

`leaf-expired.pem` is already past its `notAfter`, and `leaf-weak.pem` carries
both a 1024 bit RSA key and a SHA1 signature, so the weak key and weak signature
checks each have a dedicated target. The root and intermediate are ordinary
healthy CA certificates, and the intermediate carries `pathlen:0`.

## What ChainWarden does not verify

This tool is deliberately narrow. Read this section as a contract about what a
clean run does and does not tell you.

- It does not verify signatures. Chain building is by name matching only: the
  issuer name of one certificate is compared, as a string, to the subject name
  of another. Name-based chain building is not signature verification. The tool
  does not check that the issuer's private key actually signed the certificate,
  and it does not consult authority or subject key identifiers. A certificate
  that claims an issuer it was never signed by will still be linked into a
  chain. Treat the chain output as a structural map, not proof of trust.
- It does not check revocation. There is no CRL handling and no OCSP handling,
  by design, because both require network access and this tool makes none. A
  certificate revoked by its issuer this morning will still be reported as valid
  if its dates and structure are fine.
- It does not validate name constraints, policy constraints, or the full set of
  RFC 5280 path validation rules. It covers basic constraints, key usage,
  extended key usage parsing, and path length only.
- The DER reader targets the specific fields listed above. It measures RSA key
  sizes but does not size elliptic curve or Ed25519 keys, so weak key detection
  applies to RSA only.
- Expiry cliff bucketing is anchored at the earliest expiry in the pool and uses
  fixed width windows. It groups nearby expiries, it does not cluster them
  adaptively, so two certificates one day apart can land in different buckets if
  they straddle a window boundary.

## Design decisions

The two decisions most likely to surprise a reader are the hand-rolled DER
reader and the name-based chain builder. Both were deliberate.

**A hand-rolled DER walker instead of a dependency.** The obvious alternative
was to depend on `cryptography` or `pyOpenSSL` and let a mature library parse
the certificates. That would have given signature verification for free, which
this tool does not attempt. The reason not to is the constraint that shaped the
whole project: standard library only, no network, no build step for a C
extension. A pure Python tag-length-value reader that reaches exactly the fields
in the audit is small, auditable in one sitting, and installs anywhere Python
3.11 runs with nothing to compile. The cost is real and stated plainly in the
limitations: no signature checking, and RSA is the only key type sized. The
reader in `der.py` is intentionally strict, rejecting the indefinite length
encodings that DER forbids anyway, so malformed input fails loudly rather than
parsing into nonsense.

**Name-based chaining as an acceptable first cut.** Proper path building matches
the authority key identifier of a certificate to the subject key identifier of
its issuer, and then verifies the signature. ChainWarden matches issuer name to
subject name and stops there. This is weaker, and the README says so in three
places. It was accepted as a first cut because the tool's primary job is
lifecycle auditing, expiry and weak crypto, not trust decisions, and for that
job a structural map of which certificate claims to be issued by which is enough
to tell an operator whether a root is missing from their bundle. Building the
name index and walking it is a few lines in `chainbuild.py`, it is deterministic
because ties are broken by fingerprint, and it is loop guarded by tracking
visited fingerprints. Adding real signature verification would mean adding a
crypto dependency, which reopens the decision above. The honest split is:
structure now, cryptography later, and never pretend the first is the second.

A smaller decision worth noting: the reference date is a required argument, not
a default of "today". Reading the wall clock would make output depend on when it
ran, which breaks reproducible diffs and makes a test suite awkward. Requiring
`--as-of` and echoing it in the header keeps every run pinned to a date the
reader can see.

## Repository layout

```
ChainWarden/
  README.md                  this document
  CHANGELOG.md               notable changes, Keep a Changelog format
  LICENSE                    MIT licence text
  pyproject.toml             package metadata, entry point, Python 3.11+
  .gitignore                 ignores build and cache artefacts
  .github/workflows/ci.yml   runs the tests and audits the sample bundle
  docs/assets/
    logo.svg                 wordmark: a three block certificate chain
    chain-depth.svg          the sample chains, names and dates from the CLI
  samples/
    gen_pki.sh               regenerates the test PKI with pinned dates
    openssl.cnf              two line minimal config the OpenSSL build needs
    root.pem                 self signed test root CA
    intermediate.pem         test intermediate CA, pathlen:0
    leaf-good.pem            healthy RSA 2048 SHA256 leaf
    leaf-soon.pem            leaf expiring soon relative to the sample date
    leaf-expired.pem         leaf already past notAfter
    leaf-weak.pem            RSA 1024, SHA1 signature, the weak target
    bundle.pem               all six certificates concatenated
    README.md                explains the fixtures and how they were built
  src/chainwarden/
    __init__.py              package marker and version string
    __main__.py              enables python -m chainwarden
    cli.py                   argument parsing, file gathering, dispatch
    pemread.py               PEM block splitter and base64 decoder
    der.py                   tag-length-value DER reader
    certmodel.py             Certificate model, parsed from DER
    chainbuild.py            name-based chain assembly
    policy.py                the checks and their severities
    report.py                line oriented rendering
  tests/
    test_der.py              DER reader unit tests
    test_pemread.py          PEM splitting and label filtering tests
    test_certmodel.py        certificate parsing against the samples
    test_chain_policy.py     chain building and policy checks
    test_cli.py              end to end CLI behaviour and exit codes
```

## Glossary of X.509 terms

| Term                | Meaning as used here                                                                 |
|---------------------|--------------------------------------------------------------------------------------|
| X.509               | The certificate format this tool parses, defined by RFC 5280 and ITU-T X.509         |
| DER                 | Distinguished Encoding Rules, the binary encoding of a certificate's ASN.1 structure |
| PEM                 | Base64 of the DER wrapped in `-----BEGIN CERTIFICATE-----` markers                   |
| TLV                 | Tag-length-value, the triple the DER reader walks                                    |
| OID                 | Object identifier, a dotted-number name for an algorithm or attribute                |
| RDN                 | Relative distinguished name, one component of a subject or issuer name such as `CN=` |
| Subject             | The entity a certificate identifies                                                  |
| Issuer              | The entity whose key signed the certificate; its name links a certificate upward     |
| Leaf                | An end entity certificate, not a CA, at the bottom of a chain                        |
| CA                  | Certificate authority, a certificate allowed to sign other certificates              |
| Root                | A self signed CA at the top of a chain, where subject equals issuer                  |
| Basic constraints   | The extension that marks a certificate as a CA and may cap chain depth with `pathlen`|
| Key usage           | The extension listing allowed operations, such as `keyCertSign`                      |
| `notBefore`/`notAfter` | The start and end of a certificate's validity window                              |
| Fingerprint         | The SHA256 hash of the DER bytes, used here to de-duplicate and break ties           |

## Verification

Run the test suite with the standard library runner. No third party test tools
are needed:

```
python -m unittest discover -s tests -v
```

In this session the suite reported 36 tests passing:

```
Ran 36 tests in 0.027s

OK
```

The 36 tests are spread across five files: `test_der.py` covers the length and
OID decoding edge cases including rejection of indefinite lengths;
`test_pemread.py` covers block splitting, label filtering, and malformed input;
`test_certmodel.py` parses the real sample certificates and asserts their fields;
`test_chain_policy.py` checks leaf detection, chain completeness, the individual
policy checks, cliff detection at wide and narrow windows, and deterministic
output; `test_cli.py` drives the four subcommands end to end and asserts the
exit codes. The CI workflow in `.github/workflows/ci.yml` runs the same command
and then audits the sample bundle, treating exit code 1 as expected because the
sample bundle contains known findings.

## Roadmap

No dates are promised. In rough order of value:

- Optional signature verification behind a flag, which would require an added
  crypto dependency and a clear boundary so the standard library only path stays
  the default.
- Sizing for elliptic curve and Ed25519 keys so weak key detection is not RSA
  only.
- Authority and subject key identifier matching to disambiguate chains where two
  certificates share a subject name.
- Adaptive expiry clustering, so nearby expiries are grouped by proximity rather
  than fixed window boundaries.
- A JSON output mode alongside the line oriented text, for callers that would
  rather parse than diff.

## License

MIT. See [`LICENSE`](LICENSE).


