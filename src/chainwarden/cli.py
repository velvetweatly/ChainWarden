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
