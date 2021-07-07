"""Command line interface for chainwarden.

Subcommands:
  audit    run all policy checks and print findings
  chain    build and print candidate trust chains
  expiry   list certificates ordered by expiry
  version  print the version

Input is one or more paths. A path may be a directory (every *.pem, *.crt and
*.cer file inside is read, non recursively) or a single PEM file that may hold
one or many CERTIFICATE blocks.

The reference date is supplied with --as-of YYYY-MM-DD. It is required for the
audit and expiry subcommands so output never depends on the wall clock, which
keeps runs reproducible. The date is echoed in the output header.

Exit codes: 0 clean, 1 findings present, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date, datetime
from pathlib import Path

from . import __version__, report
from .certmodel import CertParseError, Certificate, parse_certificate
from .chainbuild import build_all_chains
from .der import DERError
from .pemread import PEMError, certificate_ders

_CERT_SUFFIXES = {".pem", ".crt", ".cer"}


def _parse_as_of(text: str) -> date:
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--as-of must be YYYY-MM-DD, got {text!r}"
        )


def _gather_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.is_file() and child.suffix.lower() in _CERT_SUFFIXES:
                    files.append(child)
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(f"path not found: {raw}")
    return files


def _load_certificates(paths: list[str]) -> list[Certificate]:
    """Load and parse every certificate found under the given paths.

    Files are visited in sorted order and blocks in file order, so the returned
    list is deterministic. Duplicate certificates (same fingerprint) are kept
    once, first occurrence wins."""
    certs: list[Certificate] = []
    seen: set[str] = set()
    for path in _gather_files(paths):
        text = path.read_text(encoding="utf-8", errors="replace")
        for der_bytes in certificate_ders(text):
            cert = parse_certificate(der_bytes, source=str(path))
            if cert.fingerprint_sha256 in seen:
                continue
            seen.add(cert.fingerprint_sha256)
            certs.append(cert)
    return certs


def _add_input_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "paths",
        nargs="+",
        help="PEM files or directories of PEM certificates",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chainwarden",
        description="Offline X.509 and TLS certificate fleet auditor.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="run policy checks and print findings")
    _add_input_args(p_audit)
    p_audit.add_argument(
        "--as-of", type=_parse_as_of, required=True, metavar="YYYY-MM-DD",
        help="reference date for expiry checks",
    )
    p_audit.add_argument("--expiry-warn-days", type=int, default=90)
    p_audit.add_argument("--cliff-window-days", type=int, default=30)
    p_audit.add_argument("--cliff-count", type=int, default=3)

    p_chain = sub.add_parser("chain", help="build and print trust chains")
    _add_input_args(p_chain)

    p_expiry = sub.add_parser("expiry", help="list certificates by expiry")
    _add_input_args(p_expiry)
    p_expiry.add_argument(
        "--as-of", type=_parse_as_of, required=True, metavar="YYYY-MM-DD",
        help="reference date for the remaining days column",
    )

    sub.add_parser("version", help="print the version and exit")
    return parser


def _cmd_audit(args: argparse.Namespace) -> int:
    from .policy import AuditConfig, run_audit

    certs = _load_certificates(args.paths)
    chains = build_all_chains(certs)
    config = AuditConfig(
