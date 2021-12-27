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
