"""Line oriented rendering. Every function returns a list of text lines so the
CLI can join them and callers can diff them cleanly."""

from __future__ import annotations

from datetime import date

from .certmodel import Certificate
from .chainbuild import Chain
from .policy import Finding


def render_findings(findings: list[Finding], as_of: date) -> list[str]:
    lines = [f"# chainwarden audit as of {as_of.isoformat()}"]
    if not findings:
        lines.append("OK  no findings")
        return lines
    for f in findings:
        lines.append(f"{f.severity:<5} {f.code:<16} {f.subject} :: {f.message}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in ("ERROR", "WARN", "INFO") if s in counts)
    lines.append(f"# {len(findings)} findings: {summary}")
    return lines


def render_chain(chain: Chain) -> list[str]:
    lines = []
    status = "complete" if chain.complete else "incomplete"
    lines.append(f"chain {chain.leaf.common_name} depth={chain.depth} {status}")
    for i, cert in enumerate(chain.certs):
        indent = "  " * i
        role = "root" if cert.is_self_issued else ("leaf" if i == 0 else "ca")
        lines.append(
            f"{indent}[{role}] {cert.common_name} "
            f"exp {cert.not_after.date().isoformat()} "
            f"{cert.pubkey_alg_name}"
            + (f"/{cert.rsa_modulus_bits}" if cert.rsa_modulus_bits else "")
            + f" {cert.sig_alg_name}"
        )
    return lines


def render_all_chains(chains: list[Chain]) -> list[str]:
    lines: list[str] = []
    for chain in chains:
        lines.extend(render_chain(chain))
    return lines


def render_expiry(certs: list[Certificate], as_of: date) -> list[str]:
    lines = [f"# expiry sorted by notAfter, as of {as_of.isoformat()}"]
    for cert in sorted(certs, key=lambda c: (c.not_after, c.common_name)):
        remaining = (cert.not_after.date() - as_of).days
        state = "EXPIRED" if remaining < 0 else "valid"
        lines.append(
            f"{cert.not_after.date().isoformat()} "
            f"{remaining:>6}d {state:<7} {cert.common_name}"
        )
    return lines
