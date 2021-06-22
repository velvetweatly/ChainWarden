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

