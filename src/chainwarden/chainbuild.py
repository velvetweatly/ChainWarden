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

    @property
    def depth(self) -> int:
        return len(self.certs)


def _subject_index(certs: list[Certificate]) -> dict[str, list[Certificate]]:
    index: dict[str, list[Certificate]] = {}
    for cert in certs:
        index.setdefault(cert.subject, []).append(cert)
    return index


def find_leaves(certs: list[Certificate]) -> list[Certificate]:
    """Leaves are certificates that no other certificate is issued by, that is
    their subject is not the issuer of anything else, and that are not self
    signed. Order follows the input order for determinism."""
    issued_subjects = set()
    for cert in certs:
        for other in certs:
            if other is cert:
                continue
            if other.issuer == cert.subject and not cert.is_self_issued:
                issued_subjects.add(cert.subject)
                break
    leaves = []
    for cert in certs:
        if cert.is_self_issued:
            continue
        if cert.subject not in issued_subjects:
            leaves.append(cert)
    return leaves


def build_chain(leaf: Certificate, certs: list[Certificate]) -> Chain:
    """Walk from leaf upward by matching issuer to a subject in the pool."""
    index = _subject_index(certs)
    chain = [leaf]
    visited = {leaf.fingerprint_sha256}
    current = leaf
    while not current.is_self_issued:
        candidates = index.get(current.issuer, [])
        # Deterministic pick: lowest fingerprint that is not already visited.
        nxt = None
        for cand in sorted(candidates, key=lambda c: c.fingerprint_sha256):
            if cand.fingerprint_sha256 not in visited:
                nxt = cand
                break
        if nxt is None:
            break
        chain.append(nxt)
        visited.add(nxt.fingerprint_sha256)
        current = nxt
    return Chain(certs=chain)


def build_all_chains(certs: list[Certificate]) -> list[Chain]:
    """Build one chain per detected leaf, in input order."""
