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
