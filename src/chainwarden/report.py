"""Line oriented rendering. Every function returns a list of text lines so the
CLI can join them and callers can diff them cleanly."""

from __future__ import annotations

from datetime import date

from .certmodel import Certificate
from .chainbuild import Chain
from .policy import Finding


def render_findings(findings: list[Finding], as_of: date) -> list[str]:
