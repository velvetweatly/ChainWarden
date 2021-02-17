"""The Certificate model and the code that fills it from DER.

Structure walked (RFC 5280 section 4.1):

    Certificate ::= SEQUENCE {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING }

    TBSCertificate ::= SEQUENCE {
        version         [0] EXPLICIT INTEGER DEFAULT v1,
        serialNumber        INTEGER,
        signature           AlgorithmIdentifier,
        issuer              Name,
        validity            Validity,
        subject             Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        ... extensions [3] EXPLICIT Extensions OPTIONAL }

We do not verify signatures. This tool inspects structure and policy, it is not
a validating path builder in the cryptographic sense, and it says so.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import der
from .der import TLV

# OID tables. Kept small and explicit so the report can name algorithms.
SIG_ALG_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
}

PUBKEY_ALG_NAMES = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.101.112": "Ed25519",
}

# Attribute type OIDs for RDN components we render.
ATTR_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}

# Extension OIDs.
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_KEY_USAGE = "2.5.29.15"
EXT_EXT_KEY_USAGE = "2.5.29.37"
EXT_SUBJECT_ALT_NAME = "2.5.29.17"

# Key usage bit names in order (RFC 5280 section 4.2.1.3).
KEY_USAGE_BITS = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
]


class CertParseError(ValueError):
    """Raised when a DER buffer does not parse as an X.509 certificate."""


@dataclass(frozen=True)
class BasicConstraints:
    present: bool = False
    critical: bool = False
    ca: bool = False
    path_len: int | None = None


@dataclass
