"""Policy checks and their severities.

All checks are pure functions of the parsed certificates and an explicit
reference date (as_of). There is no wall-clock read here, so identical input
plus identical as_of produce identical findings. The CLI records the as_of
date in its output header.

Severity ordering, high to low: ERROR, WARN, INFO.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone

from .certmodel import Certificate
from .chainbuild import Chain

SEVERITY_ORDER = {"ERROR": 0, "WARN": 1, "INFO": 2}

# Signature algorithm OIDs considered weak (broken or deprecated hashes).
WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "MD5 based signature",
    "1.2.840.113549.1.1.5": "SHA1 based signature",
    "1.2.840.10045.4.1": "SHA1 based ECDSA signature",
