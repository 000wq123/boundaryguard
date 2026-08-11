"""Invisible-Unicode security primitives.

Detect, explain, and optionally remove Unicode characters that can be
abused for deception:

* **Bidi formatting controls** (LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI) —
  the attack surface of *Trojan Source* (CVE-2021-42574, arXiv:2111.00169).
  These make source code render in a different order from its logical
  token order, so a human reviewer can approve code that does something
  other than what it looks like.

* **Bidi marks** (LRM/RLM) — harmless on their own and *required* for
  correct rendering of mixed left-to-right/right-to-left text, but they
  are invisible and frequently abused for obfuscation in logs, prompts,
  and provenance strings.

* **Zero-width characters** (ZWSP, ZWNJ, ZWJ, BOM) — invisible to humans,
  meaningful to machines. They can break string comparisons, hide text
  from reviewers, and smuggle content past filters and LLM tooling.

The module provides detection (find + explain) and sanitization
(remove) primitives under two policies:

* ``"security"`` (default) — strip every character in the above sets.
  Safe default for identifiers, provenance keys, hashes, and anything
  that will be compared, logged, or machine-parsed.

* ``"preserve_rtl"`` — keep the characters required for legitimate
  multilingual text (LRM, RLM, ZWNJ, ZWJ) while still removing the
  dangerous bidi *formatting* controls and ZWSP/BOM. Use for
  human-facing text in Arabic, Hebrew, Persian, and Urdu.

Everything here is standard-library only (no dependencies).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# ── Character tables ────────────────────────────────────────────────────
# codepoint -> (short name, full name, category)

BIDI_FORMAT = {
    0x202A: ("LRE", "LEFT-TO-RIGHT EMBEDDING", "bidi_format"),
    0x202B: ("RLE", "RIGHT-TO-LEFT EMBEDDING", "bidi_format"),
    0x202C: ("PDF", "POP DIRECTIONAL FORMATTING", "bidi_format"),
    0x202D: ("LRO", "LEFT-TO-RIGHT OVERRIDE", "bidi_format"),
    0x202E: ("RLO", "RIGHT-TO-LEFT OVERRIDE", "bidi_format"),
    0x2066: ("LRI", "LEFT-TO-RIGHT ISOLATE", "bidi_format"),
    0x2067: ("RLI", "RIGHT-TO-LEFT ISOLATE", "bidi_format"),
    0x2068: ("FSI", "FIRST STRONG ISOLATE", "bidi_format"),
    0x2069: ("PDI", "POP DIRECTIONAL ISOLATE", "bidi_format"),
}

BIDI_MARK = {
    0x200E: ("LRM", "LEFT-TO-RIGHT MARK", "bidi_mark"),
    0x200F: ("RLM", "RIGHT-TO-LEFT MARK", "bidi_mark"),
}

ZERO_WIDTH = {
    0x200B: ("ZWSP", "ZERO WIDTH SPACE", "zero_width"),
    0x200C: ("ZWNJ", "ZERO WIDTH NON-JOINER", "zero_width"),
    0x200D: ("ZWJ", "ZERO WIDTH JOINER", "zero_width"),
    0xFEFF: ("BOM", "ZERO WIDTH NO-BREAK SPACE", "zero_width"),
}

# Characters preserved under the "preserve_rtl" policy: required for
# legitimate Arabic/Hebrew/Persian/Urdu text rendering and script joining.
_PRESERVE_RTL = {0x200E, 0x200F, 0x200C, 0x200D}

# C0 control characters except the common whitespace \t \n \r.
_C0_EXCEPT_WS = frozenset(chr(c) for c in range(0x20) if c not in (0x09, 0x0A, 0x0D))

_ALL_HAZARDS = {**BIDI_FORMAT, **BIDI_MARK, **ZERO_WIDTH}

# ── Data model ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Hazard:
    """A single invisible-Unicode hazard found in a string.

    Attributes:
        codepoint: Unicode code point (int) of the offending character.
        short: Short label, e.g. ``"RLO"``.
        name: Full Unicode name, e.g. ``"RIGHT-TO-LEFT OVERRIDE"``.
        category: One of ``"bidi_format"``, ``"bidi_mark"``, ``"zero_width"``.
        offset: Character offset in the scanned string.
        escaped: Human-readable escape, e.g. ``"U+202E"``.
    """

    codepoint: int
    short: str
    name: str
    category: str
    offset: int
    escaped: str


@dataclass(frozen=True)
class FileHazard:
    """A hazard with file/line/column context (from :func:`scan_file`)."""

    hazard: Hazard
    path: str
    line: int  # 1-based
    column: int  # 1-based


# ── Detection ──────────────────────────────────────────────────────────


def _lookup(ch: str) -> Optional[Tuple[str, str, str]]:
    cp = ord(ch)
    entry = _ALL_HAZARDS.get(cp)
    if entry is not None:
        return entry
    if ch in _C0_EXCEPT_WS:
        name = f"CONTROL-{cp:04X}"
        return ("C0", name, "control")
    return None


def find_suspicious(text: str, policy: str = "security") -> List[Hazard]:
    """Return every suspicious character in *text* as a list of :class:`Hazard`.

    *policy* is either ``"security"`` (default, flags everything) or
    ``"preserve_rtl"`` (ignores LRM/RLM/ZWNJ/ZWJ, which are legitimate
    for multilingual text, but still flags bidi formatting controls,
    ZWSP, BOM, and C0 control characters).
    """
    if not text:
        return []
    hazards: List[Hazard] = []
    for offset, ch in enumerate(text):
        entry = _lookup(ch)
        if entry is None:
            continue
        short, name, category = entry
        if policy == "preserve_rtl" and category in ("bidi_mark", "zero_width"):
            cp = ord(ch)
            if cp in _PRESERVE_RTL:
                continue
        hazards.append(
            Hazard(
                codepoint=ord(ch),
                short=short,
                name=name,
                category=category,
                offset=offset,
                escaped=f"U+{ord(ch):04X}",
            )
        )
    return hazards


def contains_bidi_controls(text: str) -> bool:
    """True if *text* contains any bidi formatting control or mark."""
    return any(ord(ch) in BIDI_FORMAT or ord(ch) in BIDI_MARK for ch in text)


def contains_zero_width(text: str) -> bool:
    """True if *text* contains any zero-width character."""
    return any(ord(ch) in ZERO_WIDTH for ch in text)


def explain_character(ch: str) -> str:
    """Return a human-readable explanation for one character.

    For a known hazard this is ``"U+202E RIGHT-TO-LEFT OVERRIDE (RLO)"``.
    For unknown characters it returns ``"U+0041 LATIN CAPITAL LETTER A"``
    style output, so the function is safe to call on any input.
    """
    if not ch:
        return "(empty string)"
    cp = ord(ch)
    entry = _lookup(ch)
    if entry is not None:
        short, name, category = entry
        return f"U+{cp:04X} {name} ({short}) [{category}]"
    import unicodedata

    name = unicodedata.name(ch, f"<control U+{cp:04X}>")
    return f"U+{cp:04X} {name}"


# ── Sanitization ───────────────────────────────────────────────────────


def sanitize(text: str, policy: str = "security") -> str:
    """Remove suspicious characters from *text* under the given *policy*.

    With ``"security"`` (default) every bidi control, bidi mark,
    zero-width character, and non-whitespace C0 control is removed.
    With ``"preserve_rtl"`` LRM/RLM/ZWNJ/ZWJ are kept so legitimate
    multilingual text still renders correctly.
    """
    if not text:
        return text
    if policy == "preserve_rtl":
        kept: List[str] = []
        for ch in text:
            cp = ord(ch)
            if cp in _PRESERVE_RTL:
                kept.append(ch)
            elif _lookup(ch) is None:
                kept.append(ch)
        return "".join(kept)
    return "".join(ch for ch in text if _lookup(ch) is None)


# ── File scanning ──────────────────────────────────────────────────────

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".tox", ".mypy_cache", ".pytest_cache", ".hg", ".svn", "unsloth_compiled_cache"}


def scan_file(path: Path, policy: str = "security") -> List[FileHazard]:
    """Scan a single text file, returning hazards with line/column context.

    Files that cannot be decoded as UTF-8 are skipped (returned empty).
    """
    try:
        data = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    results: List[FileHazard] = []
    for line_no, line in enumerate(data.splitlines(), start=1):
        for hazard in find_suspicious(line, policy=policy):
            results.append(
                FileHazard(
                    hazard=hazard,
                    path=str(path),
                    line=line_no,
                    column=hazard.offset + 1,
                )
            )
    return results


def scan_path(path: Path, policy: str = "security", recursive: bool = False) -> List[FileHazard]:
    """Scan a file or directory tree.

    When *path* is a directory and *recursive* is True the directory is
    walked (skipping VCS, virtualenv, and cache directories).
    """
    if path.is_file():
        return scan_file(path, policy=policy)
    results: List[FileHazard] = []
    if not recursive:
        for child in sorted(path.iterdir()):
            if child.is_file():
                results.extend(scan_file(child, policy=policy))
        return results
    for root, dirs, files in path.walk():
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in sorted(files):
            results.extend(scan_file(Path(root) / name, policy=policy))
    return results


def scan_texts(texts: Iterable[str], policy: str = "security") -> List[Hazard]:
    """Convenience: scan an iterable of strings, returning flat hazards."""
    out: List[Hazard] = []
    for text in texts:
        out.extend(find_suspicious(text, policy=policy))
    return out
