#!/usr/bin/env python3
"""ChainWarden quality gate.

Standard library only. Run from the project root:

    python scripts/verify.py

Exit code is 0 when every check passes and 1 when any check fails. One line is
printed per check, followed by a summary line. The checks encode the lessons in
_standards/LESSONS.md that can be verified mechanically:

  1. Every .svg under docs/assets/ parses as XML.
  2. No .svg contains feGaussianBlur, feDropShadow, or feTurbulence.
  3. No XML comment in any .svg contains the illegal `--` sequence.
  4. No tracked text file contains the em dash character U+2014 or its numeric
     or named HTML entity forms.
  5. README.md contains no pandoc style image attribute block.
  6. README.md contains none of the banned marketing terms.
  7. Every .svg under docs/assets/ carries a viewBox, role="img", a <title>,
     and a <desc>.
  8. No two text labels sharing a baseline in any .svg overlap.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"

# File suffixes treated as tracked text for the em dash sweep.
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".svg", ".yml", ".yaml", ".toml", ".cfg", ".ini",
    ".cff", ".sh", ".editorconfig", ".gitattributes", ".gitignore", ".pem",
    ".cnf", "",
}

# Directories that never hold tracked source we author.
SKIP_DIRS = {
    "__pycache__", ".git", ".venv", "build", "dist", ".mypy_cache",
    ".pytest_cache",
}

BANNED_FILTERS = ("feGaussianBlur", "feDropShadow", "feTurbulence")

# Marketing words that lesson 6 bans from the README.
BANNED_MARKETING = [
    "blazing", "blazingly", "cutting-edge", "cutting edge", "state-of-the-art",
    "state of the art", "world-class", "world class", "revolutionary",
    "game-changing", "game changing", "seamless", "seamlessly", "effortless",
    "effortlessly", "lightning-fast", "lightning fast", "supercharge",
    "supercharged", "next-generation", "next generation", "best-in-class",
    "unparalleled", "unrivaled", "unrivalled", "turnkey", "synergy",
    "leverage the power", "one-stop", "robust and scalable",
]

# Built from parts so this file does not match its own em dash sweep. The three
# forms are the literal character U+2014, the numeric entity, and the named
# entity.
EM_DASH_FORMS = (
    "\u2014",
    "&#" + "8212;",
    "&" + "mdash;",
)

# Rough advance widths in em units. Sans and mono per the standard.
WIDTH_SANS = 0.58
WIDTH_MONO = 0.60


def _iter_svgs() -> list[Path]:
    if not ASSETS.is_dir():
        return []
    return sorted(ASSETS.rglob("*.svg"))


def _iter_text_files() -> list[Path]:
    out: list[Path] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        name = path.name
        suffix = path.suffix.lower()
        if suffix in TEXT_SUFFIXES or name in TEXT_SUFFIXES:
            out.append(path)
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def check_svg_parses() -> tuple[bool, str]:
    failures = []
    for svg in _iter_svgs():
        try:
            ET.parse(svg)
        except ET.ParseError as exc:
            failures.append(f"{svg.name}: {exc}")
    if failures:
        return False, "svg parses as XML: " + "; ".join(failures)
    return True, f"svg parses as XML: {len(_iter_svgs())} files ok"


def check_no_banned_filters() -> tuple[bool, str]:
    failures = []
    for svg in _iter_svgs():
        text = svg.read_text(encoding="utf-8")
        for banned in BANNED_FILTERS:
            if banned in text:
                failures.append(f"{svg.name}: {banned}")
    if failures:
        return False, "no banned svg filters: " + "; ".join(failures)
    return True, "no banned svg filters: none found"


def check_no_double_hyphen_in_comments() -> tuple[bool, str]:
    failures = []
    comment_re = re.compile(r"<!--(.*?)-->", re.DOTALL)
    for svg in _iter_svgs():
        text = svg.read_text(encoding="utf-8")
        for body in comment_re.findall(text):
            if "--" in body:
                failures.append(svg.name)
                break
    if failures:
        return False, "no '--' in svg comments: " + "; ".join(failures)
    return True, "no '--' in svg comments: clean"


def check_no_em_dash() -> tuple[bool, str]:
    failures = []
    for path in _iter_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for form in EM_DASH_FORMS:
            if form in text:
                rel = path.relative_to(ROOT).as_posix()
                failures.append(f"{rel}:{form!r}")
    if failures:
        return False, "no em dash forms: " + "; ".join(failures)
    return True, "no em dash forms: clean"


def check_readme_no_pandoc_attr() -> tuple[bool, str]:
    readme = ROOT / "README.md"
    if not readme.is_file():
        return True, "readme pandoc image attr: no README.md"
    text = readme.read_text(encoding="utf-8")
    # Match `){` then width or height before the closing brace.
    pattern = re.compile(r"\)\{[^}]*(?:width|height)[^}]*\}")
    if pattern.search(text):
        return False, "readme pandoc image attr: found `){...width...}` block"
    return True, "readme pandoc image attr: none"


def check_readme_no_marketing() -> tuple[bool, str]:
    readme = ROOT / "README.md"
    if not readme.is_file():
        return True, "readme marketing terms: no README.md"
    text = readme.read_text(encoding="utf-8").lower()
    hits = [term for term in BANNED_MARKETING if term in text]
    if hits:
        return False, "readme marketing terms: " + ", ".join(hits)
    return True, "readme marketing terms: none"


def check_svg_accessibility() -> tuple[bool, str]:
    failures = []
    for svg in _iter_svgs():
        try:
            root = ET.parse(svg).getroot()
        except ET.ParseError:
            failures.append(f"{svg.name}: unparseable")
            continue
        missing = []
        if root.get("viewBox") is None:
            missing.append("viewBox")
        if root.get("role") != "img":
            missing.append('role="img"')
        tags = {_local(el.tag) for el in root.iter()}
        if "title" not in tags:
            missing.append("<title>")
        if "desc" not in tags:
            missing.append("<desc>")
        if missing:
            failures.append(f"{svg.name}: missing {', '.join(missing)}")
    if failures:
        return False, "svg accessibility: " + "; ".join(failures)
    return True, f"svg accessibility: {len(_iter_svgs())} files ok"


def _text_content(el: ET.Element) -> str:
    """Full visible text of a <text> element including tspan children."""
    parts = []
    if el.text:
        parts.append(el.text)
    for child in el:
        if child.text:
            parts.append(child.text)
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def _est_width(text: str, font_size: float, family: str) -> float:
    per_em = WIDTH_MONO if "mono" in (family or "").lower() else WIDTH_SANS
    return len(text) * per_em * font_size


def check_no_label_overlap() -> tuple[bool, str]:
    failures = []
    for svg in _iter_svgs():
        try:
            root = ET.parse(svg).getroot()
        except ET.ParseError:
            continue
        rows: dict[int, list[tuple[float, float, str]]] = {}
        for el in root.iter():
            if _local(el.tag) != "text":
                continue
            content = _text_content(el).strip()
            if not content:
                continue
            try:
                x = float(el.get("x", "0"))
                y = float(el.get("y", "0"))
                font_size = float(el.get("font-size", "16"))
            except ValueError:
                continue
            family = el.get("font-family", "")
            anchor = el.get("text-anchor", "start")
            width = _est_width(content, font_size, family)
            if anchor == "middle":
                left = x - width / 2
            elif anchor == "end":
                left = x - width
            else:
                left = x
            right = left + width
            rows.setdefault(round(y), []).append((left, right, content))
        for baseline, spans in rows.items():
            spans.sort(key=lambda s: s[0])
            for i in range(1, len(spans)):
                prev_left, prev_right, prev_text = spans[i - 1]
                left, right, text = spans[i]
                if left < prev_right - 0.01:
                    failures.append(
                        f"{svg.name} y={baseline}: "
                        f"{prev_text!r} overlaps {text!r}"
                    )
    if failures:
        return False, "no label overlap: " + "; ".join(failures)
    return True, "no label overlap: clean"


CHECKS = [
    check_svg_parses,
    check_no_banned_filters,
    check_no_double_hyphen_in_comments,
    check_no_em_dash,
    check_readme_no_pandoc_attr,
    check_readme_no_marketing,
    check_svg_accessibility,
    check_no_label_overlap,
]


def main() -> int:
    failures = 0
    for check in CHECKS:
        ok, message = check()
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"[{status}] {message}")
    print(f"verify: {len(CHECKS)} checks, {failures} failures")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())


# draft note 48
