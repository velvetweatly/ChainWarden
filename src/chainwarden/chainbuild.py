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


@dataclass
class Chain:
    """An assembled chain from a leaf up toward a root.

    certs[0] is the leaf. The last element is either a self signed root or the
    highest certificate we could reach. complete is True only when the last
    element is self signed (a root anchor present in the pool)."""

    certs: list[Certificate]

    @property
    def leaf(self) -> Certificate:
        return self.certs[0]

    @property
    def anchor(self) -> Certificate:
        return self.certs[-1]

    @property
    def complete(self) -> bool:
        return self.anchor.is_self_issued

