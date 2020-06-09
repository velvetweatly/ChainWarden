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

