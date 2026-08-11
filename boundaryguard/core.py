"""Invisible-Unicode security primitives.

Detect, explain, and optionally remove Unicode characters that can be
abused for deception:

* **Bidi formatting controls** (LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI,
  and the deprecated ISS/ASS/IAFS/AFS/NDS/NODS) — the attack surface of
  *Trojan Source* (CVE-2021-42574, arXiv:2111.00169). These make source
  code render in a different order from its logical token order, so a
  human reviewer can approve code that does something other than what it
  looks like.

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

Fail-closed scanning
--------------------
``scan_file`` / ``scan_path_iter`` never silently report a file as
clean when it could not actually be examined. Files that cannot be
decoded as UTF-8, cannot be read, or are special files (FIFOs, sockets,
devices) are reported through the ``on_skip`` callback, and callers are
expected to treat skipped files as "could not verify" rather than
"verified clean". The CLI exits with an error code when anything was
skipped.
"""

from __future__ import annotations

import codecs
import errno
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional, Tuple

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
    # Deprecated bidi controls (Unicode 6.3+): still invisible to humans
    # and able to reorder rendering in older display stacks.
    0x206A: ("ISS", "INHIBIT SYMMETRIC SWAPPING", "bidi_format"),
    0x206B: ("ASS", "ACTIVATE SYMMETRIC SWAPPING", "bidi_format"),
    0x206C: ("IAFS", "INHIBIT ARABIC FORM SHAPING", "bidi_format"),
    0x206D: ("AFS", "ACTIVATE ARABIC FORM SHAPING", "bidi_format"),
    0x206E: ("NDS", "NATIONAL DIGIT SHAPES", "bidi_format"),
    0x206F: ("NODS", "NOMINAL DIGIT SHAPES", "bidi_format"),
}

BIDI_MARK = {
    0x200E: ("LRM", "LEFT-TO-RIGHT MARK", "bidi_mark"),
    0x200F: ("RLM", "RIGHT-TO-LEFT MARK", "bidi_mark"),
}

ZERO_WIDTH = {
    0x200B: ("ZWSP", "ZERO WIDTH SPACE", "zero_width"),
    0x200C: ("ZWNJ", "ZERO WIDTH NON-JOINER", "zero_width"),
    0x200D: ("ZWJ", "ZERO WIDTH JOINER", "zero_width"),
    # U+2060 WORD JOINER: zero-width, machine-significant (breaks string
    # comparisons and tokenization exactly like ZWSP) and has no
    # legitimate rendering role in source, logs, or prompts.
    0x2060: ("WJ", "WORD JOINER", "zero_width"),
    0xFEFF: ("BOM", "ZERO WIDTH NO-BREAK SPACE", "zero_width"),
}

# Characters preserved under the "preserve_rtl" policy: required for
# legitimate Arabic/Hebrew/Persian/Urdu text rendering and script joining.
_PRESERVE_RTL = {0x200E, 0x200F, 0x200C, 0x200D}

# C0 control characters except the common whitespace \t \n \r.
_C0_EXCEPT_WS = frozenset(chr(c) for c in range(0x20) if c not in (0x09, 0x0A, 0x0D))

_ALL_HAZARDS = {**BIDI_FORMAT, **BIDI_MARK, **ZERO_WIDTH}

# Valid policy names. Anything else raises ValueError — an invalid policy
# must never silently fall back to a different security level.
POLICIES = ("security", "preserve_rtl")


class UndecodableFileError(ValueError):
    """Raised when a file cannot be decoded as UTF-8.

    Deliberately *not* caught by default in ``scan_file``: a file that
    cannot be read is a scan failure, not a clean result.
    """


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


# ── Validation ─────────────────────────────────────────────────────────


def _validate_policy(policy: str) -> None:
    if policy not in POLICIES:
        raise ValueError(
            f"invalid policy {policy!r}; expected one of {POLICIES}"
        )


def _require_text(text: object) -> str:
    if not isinstance(text, str):
        raise TypeError(f"expected str, got {type(text).__name__}")
    return text


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


def find_suspicious(
    text: str,
    policy: str = "security",
    limit: Optional[int] = None,
) -> List[Hazard]:
    """Return every suspicious character in *text* as a list of :class:`Hazard`.

    *policy* is either ``"security"`` (default, flags everything) or
    ``"preserve_rtl"`` (ignores LRM/RLM/ZWNJ/ZWJ, which are legitimate
    for multilingual text, but still flags bidi formatting controls,
    ZWSP, BOM, and C0 control characters).

    Any other *policy* value raises :class:`ValueError` — an invalid
    policy never silently falls back to another security level.

    *limit* (optional) stops scanning after *limit* hazards, bounding
    memory for adversarial inputs. Returns at most *limit* hazards.

    Raises:
        TypeError: If *text* is not a ``str``.
        ValueError: If *policy* is not one of :data:`POLICIES`.
    """
    text = _require_text(text)
    _validate_policy(policy)
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
        if limit is not None and len(hazards) >= limit:
            break
    return hazards


def contains_bidi_controls(text: str) -> bool:
    """True if *text* contains any bidi formatting control or mark."""
    text = _require_text(text)
    return any((cp := ord(ch)) in BIDI_FORMAT or cp in BIDI_MARK for ch in text)


def contains_zero_width(text: str) -> bool:
    """True if *text* contains any zero-width character."""
    text = _require_text(text)
    return any(ord(ch) in ZERO_WIDTH for ch in text)


def explain_character(ch: str) -> str:
    """Return a human-readable explanation for one character.

    For a known hazard this is ``"U+202E RIGHT-TO-LEFT OVERRIDE (RLO)"``.
    For unknown characters it returns ``"U+0041 LATIN CAPITAL LETTER A"``
    style output, so the function is safe to call on any single character.

    Raises:
        TypeError: If *ch* is not a ``str``.
        ValueError: If *ch* is not exactly one character.
    """
    ch = _require_text(ch)
    if len(ch) != 1:
        raise ValueError(
            f"expected exactly one character, got {len(ch)}"
        )
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

    Raises:
        TypeError: If *text* is not a ``str``.
        ValueError: If *policy* is not one of :data:`POLICIES`.
    """
    text = _require_text(text)
    _validate_policy(policy)
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

_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}

# Files are scanned in bounded-size chunks (never read whole into memory),
# so a multi-gigabyte file cannot exhaust RAM. Lines are split on the
# universal line terminators (\n, \r, \r\n) — matching how compilers and
# editors count lines for source code.
_CHUNK = 1 << 20  # 1 MiB

_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")

# One regex over every detectable hazard character: bidi controls, marks,
# zero-width characters, and non-whitespace C0 controls.
_HAZARD_RE = re.compile(
    "[" + "".join(
        re.escape(chr(cp))
        for cp in sorted(set(_ALL_HAZARDS) | {ord(c) for c in _C0_EXCEPT_WS})
    ) + "]"
)


# Callback signature: called with (path, reason) for every skipped file.
SkipCallback = Callable[[str, str], None]


def _open_fd(path: Path, follow: bool) -> int:
    """Open *path* for reading, returning the raw file descriptor.

    ``O_NONBLOCK`` is set so opening a FIFO never blocks waiting for a
    writer (the caller rejects non-regular files by ``fstat``). When
    *follow* is False, ``O_NOFOLLOW`` is added where the platform supports
    it: a symlink that races in between enumeration and open fails with
    ``ELOOP`` instead of being followed (closing the TOCTOU window).
    """
    flags = os.O_RDONLY | os.O_NONBLOCK
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(str(path), flags)


def _iter_hazard_chars(
    fh: object,
    policy: str,
    on_decode_error: Callable[[str], None],
) -> Iterator[Tuple[int, int, str]]:
    """Stream *fh* (an open binary file) yielding ``(line, col, char)``.

    Memory stays bounded: input is read in :data:`_CHUNK`-sized pieces and
    decoded incrementally (so multibyte characters split across chunk
    boundaries are handled correctly). Invalid UTF-8 calls
    *on_decode_error(reason)* and stops. Only characters that match
    *policy* are yielded.
    """
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    pending_r = False
    line = 1
    col = 1
    while True:
        raw = fh.read(_CHUNK)  # type: ignore[attr-defined]
        if not raw:
            break
        try:
            text = decoder.decode(raw)
        except UnicodeDecodeError as exc:
            on_decode_error(f"not valid UTF-8 ({exc.reason})")
            return
        if pending_r:
            # A lone \r at the end of the previous chunk may join a \n in
            # this one; only treat it as a break once the next char is seen.
            text = "\r" + text
            pending_r = False
        if text.endswith("\r"):
            pending_r = True
            text = text[:-1]
        if not text:
            continue
        breaks = [(m.start(), m.end()) for m in _LINE_BREAK_RE.finditer(text)]
        bi = 0
        line_start = 0
        for m in _HAZARD_RE.finditer(text):
            off = m.start()
            while bi < len(breaks) and breaks[bi][0] < off:
                line += 1
                col = 1
                line_start = breaks[bi][1]
                bi += 1
            ch = m.group(0)
            entry = _lookup(ch)
            if entry is None:
                continue
            short, name, category = entry
            if (
                policy == "preserve_rtl"
                and category in ("bidi_mark", "zero_width")
                and ord(ch) in _PRESERVE_RTL
            ):
                continue
            yield (line, col + (off - line_start), ch)
        for _, end in breaks[bi:]:
            line += 1
            col = 1
            line_start = end
        col += len(text) - line_start
    # A truncated multibyte sequence at EOF is also invalid UTF-8.
    try:
        decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        on_decode_error(f"not valid UTF-8 ({exc.reason})")


def _make_file_hazard(path: Path, line: int, column: int, ch: str) -> FileHazard:
    short, name, category = _lookup(ch)
    return FileHazard(
        hazard=Hazard(
            codepoint=ord(ch),
            short=short,
            name=name,
            category=category,
            offset=column - 1,
            escaped=f"U+{ord(ch):04X}",
        ),
        path=str(path),
        line=line,
        column=column,
    )


def scan_file(
    path: Path,
    policy: str = "security",
    limit: Optional[int] = None,
) -> List[FileHazard]:
    """Scan a single UTF-8 text file, returning hazards with line/column.

    The file is streamed in bounded-size chunks, so scanning does not load
    the whole file into memory. A symlink given directly is followed (the
    caller named it explicitly); tree scans never follow symlinks.

    Raises:
        ValueError: If *policy* is invalid, or *path* is not a regular file.
        UndecodableFileError: If the file is not valid UTF-8 (fail-closed:
            an unreadable file is never reported as clean).
        OSError: If the file cannot be read (missing, permissions).
    """
    _validate_policy(policy)
    fd = _open_fd(path, follow=True)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"not a regular file: {path}")
        results: List[FileHazard] = []
        decode_failed: List[str] = []

        def on_decode_error(reason: str) -> None:
            decode_failed.append(reason)

        for line, column, ch in _iter_hazard_chars(fh, policy, on_decode_error):
            results.append(_make_file_hazard(path, line, column, ch))
            if limit is not None and len(results) >= limit:
                break
        if decode_failed:
            raise UndecodableFileError(
                f"cannot decode {path} as UTF-8 ({decode_failed[0]})"
            )
        return results


def _scan_single(
    path: Path,
    policy: str,
    limit: Optional[int],
    on_skip: Optional[SkipCallback],
    follow: bool = True,
) -> Iterator[FileHazard]:
    """Stream one file, skipping (never reporting clean) unexaminable files.

    With *follow* False (tree walks), a symlink is refused at open time via
    ``O_NOFOLLOW`` — if one races in after enumeration it is silently
    skipped, closing the TOCTOU window.
    """
    try:
        fd = _open_fd(path, follow)
    except OSError as exc:
        if not follow and exc.errno == errno.ELOOP:
            return  # symlink raced in after enumeration: silently skip
        if on_skip is not None:
            on_skip(str(path), f"cannot read ({exc.strerror or exc})")
        return
    count = 0
    try:
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                if on_skip is not None:
                    on_skip(str(path), "not a regular file (FIFO/socket/device)")
                return

            def on_decode_error(reason: str) -> None:
                if on_skip is not None:
                    on_skip(str(path), reason)

            for line, column, ch in _iter_hazard_chars(fh, policy, on_decode_error):
                yield _make_file_hazard(path, line, column, ch)
                count += 1
                if limit is not None and count >= limit:
                    return
    except OSError as exc:
        if on_skip is not None:
            on_skip(str(path), f"cannot read ({exc.strerror or exc})")


def scan_path_iter(
    path: Path,
    policy: str = "security",
    recursive: bool = False,
    limit: Optional[int] = None,
    on_skip: Optional[SkipCallback] = None,
) -> Iterator[FileHazard]:
    """Yield hazards from a file or directory tree (streaming).

    Unlike :func:`scan_path`, this is a generator: hazards are yielded as
    they are found, so memory stays bounded even for trees with millions
    of findings.

    Files that cannot be examined (non-UTF-8, unreadable, special files)
    are *not* silently treated as clean — they are reported via
    *on_skip(path, reason)*. If *on_skip* is ``None`` they are skipped
    silently (streaming callers should pass a collector).

    Raises:
        OSError: If *path* does not exist or is not a readable directory
            (so a mistyped path fails loudly instead of yielding nothing).
    """
    _validate_policy(policy)
    p = Path(path)
    if p.is_file():
        yield from _scan_single(p, policy, limit, on_skip)
        return
    if not p.is_dir():
        if p.exists():
            raise OSError(
                f"cannot scan {p}: not a regular file or directory "
                "(FIFO/socket/device)"
            )
        raise OSError(f"cannot scan {p}: no such directory")
    if not recursive:
        try:
            children = sorted(p.iterdir())
        except OSError as exc:
            raise OSError(f"cannot list directory {p}: {exc}") from exc
        for child in children:
            if child.is_symlink():
                continue  # never follow symlinks outside the scan root
            yield from _scan_single(child, policy, limit, on_skip, follow=False)
        return

    def _on_walk_error(exc: OSError) -> None:
        if on_skip is not None:
            on_skip(str(getattr(exc, "filename", "?")), "cannot read directory")

    for root, dirs, files in os.walk(p, followlinks=False, onerror=_on_walk_error):
        dirs[:] = [
            d
            for d in dirs
            if d not in _SKIP_DIRS and not (Path(root) / d).is_symlink()
        ]
        for name in sorted(files):
            fp = Path(root) / name
            if fp.is_symlink():
                continue
            yield from _scan_single(fp, policy, limit, on_skip, follow=False)


def scan_path(
    path: Path,
    policy: str = "security",
    recursive: bool = False,
    limit: Optional[int] = None,
    on_skip: Optional[SkipCallback] = None,
) -> List[FileHazard]:
    """Scan a file or directory tree, returning the full list of hazards.

    Convenience wrapper around :func:`scan_path_iter` for callers that
    want the complete result in memory. For large or adversarial inputs
    prefer the streaming iterator.

    Fail-closed note: files that cannot be examined (non-UTF-8,
    unreadable, special files) are **not** reported as clean — they are
    dropped from the result. Pass *on_skip* to observe them; without it
    they are skipped silently, so callers that need a verified-clean
    answer should always provide an *on_skip* callback and treat any skip
    as "could not verify".

    Raises:
        OSError: If *path* does not exist or is not a readable directory.
    """
    return list(
        scan_path_iter(
            path, policy=policy, recursive=recursive, limit=limit, on_skip=on_skip
        )
    )


def scan_texts(
    texts: Iterable[str],
    policy: str = "security",
) -> List[Hazard]:
    """Convenience: scan an iterable of strings, returning flat hazards.

    Raises:
        ValueError: If *policy* is invalid.
    """
    _validate_policy(policy)
    out: List[Hazard] = []
    for text in texts:
        out.extend(find_suspicious(text, policy=policy))
    return out
