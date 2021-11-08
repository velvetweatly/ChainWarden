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
}

# RSA modulus sizes below this are flagged.
MIN_RSA_BITS = 2048

# Default window, in days, used to group expiry dates into a cliff.
DEFAULT_CLIFF_WINDOW_DAYS = 30
# Number of certificates expiring within one window to call it a cliff.
DEFAULT_CLIFF_COUNT = 3
# Warn when a certificate expires within this many days of as_of.
DEFAULT_EXPIRY_WARN_DAYS = 90


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    subject: str
    message: str

    def sort_key(self) -> tuple:
        return (SEVERITY_ORDER[self.severity], self.code, self.subject)


def _as_datetime(as_of: date) -> datetime:
    return datetime(as_of.year, as_of.month, as_of.day, tzinfo=timezone.utc)


def check_weak_signature(cert: Certificate) -> list[Finding]:
    findings = []
    reason = WEAK_SIG_OIDS.get(cert.sig_alg_oid)
    if reason:
        findings.append(
            Finding(
                "ERROR",
                "WEAK_SIG",
                cert.subject,
                f"weak signature algorithm {cert.sig_alg_name} ({reason})",
            )
        )
    return findings


def check_weak_key(cert: Certificate) -> list[Finding]:
    findings = []
    if cert.rsa_modulus_bits is not None and cert.rsa_modulus_bits < MIN_RSA_BITS:
        findings.append(
            Finding(
                "ERROR",
                "WEAK_KEY",
                cert.subject,
                f"RSA key size {cert.rsa_modulus_bits} bits is below the "
                f"{MIN_RSA_BITS} bit minimum",
            )
        )
    return findings


def check_validity(cert: Certificate, as_of: date, warn_days: int) -> list[Finding]:
    findings = []
    now = _as_datetime(as_of)
    if cert.not_after < now:
        days = (now - cert.not_after).days
        findings.append(
            Finding(
                "ERROR",
                "EXPIRED",
                cert.subject,
                f"expired {days} days ago on "
                f"{cert.not_after.date().isoformat()}",
