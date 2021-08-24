"""Chain assembly by issuer to subject name matching.

This is name based path building, not cryptographic verification. Given a pool
of parsed certificates, for each leaf (a certificate that is not an issuer of
any other certificate and is not self signed) we walk upward: repeatedly find a
certificate whose subject equals the current certificate's issuer, until we
reach a self signed certificate (a root) or run out of candidates.

Ambiguity is possible when two certificates share a subject name. We record the
first match in deterministic order and flag nothing here; policy decides
severity. Loops are guarded by tracking visited fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass

from .certmodel import Certificate


