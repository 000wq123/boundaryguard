"""Command-line interface for boundaryguard.

Subcommands:

* ``scan``      — scan a file or directory (optionally recursive), print
                  every hazard with file:line:column and an escaped
                  rendering, exit 1 if anything was found.
* ``check``     — like scan, but quiet: only prints a one-line summary.
                  Exit 0 = clean, 1 = hazards found, 2 = error.
* ``inspect``   — explain the characters in a string argument.
* ``sanitize``  — remove hazards from a file (in place or to a new file),
                  written atomically and never through a symlink.

Exit codes are CI-friendly: 0 clean, 1 findings, 2 usage/IO error.

Fail-closed: files that could not be examined (non-UTF-8, unreadable,
FIFOs, sockets, devices) are reported to stderr and force exit code 2 —
a file that cannot be scanned is never silently reported as clean.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from . import __version__
from .core import (
    _ALL_HAZARDS,
    Hazard,
    UndecodableFileError,
    explain_character,
    find_suspicious,
    sanitize,
    scan_path_iter,
)

_POLICIES = ("security", "preserve_rtl")

# How many skipped files to list in the warning (count is always shown).
_MAX_SKIP_DETAIL = 10

# Line/paragraph separators can forge lines in terminal output.
_LINE_FORGERY = (0x2028, 0x2029)


def _render(hazard: Hazard) -> str:
    """Render one hazard as a visible escaped string."""
    return f"\\u{hazard.codepoint:04X}"


def _display(text: str) -> str:
    """Render a possibly-untrusted string safely for terminal output.

    Control characters (C0, DEL, C1), line/paragraph separators, and the
    invisible-Unicode hazards themselves (bidi controls, marks, zero-width
    characters) are replaced with visible ``\\uXXXX`` escapes. Without
    this, a malicious repository can control the terminal through its
    filenames: a newline can forge an ``OK: clean`` verdict or a fake
    finding, and ANSI/OSC sequences or bidi reordering can corrupt or
    lie inside the report.
    """
    out: List[str] = []
    for ch in text:
        cp = ord(ch)
        if (
            cp < 0x20
            or 0x7F <= cp <= 0x9F
            or cp in _LINE_FORGERY
            or cp in _ALL_HAZARDS
        ):
            out.append(f"\\u{cp:04X}")
        else:
            out.append(ch)
    return "".join(out)


def _print_hazard_file(path: str, line: int, column: int, hazard: Hazard) -> None:
    print(
        f"{_display(path)}:{line}:{column}  "
        f"{hazard.escaped} {hazard.name} ({hazard.short}) "
        f"[{hazard.category}]  render={_render(hazard)!r}"
    )


def _report_skips(info: Dict[str, object]) -> None:
    """Print a fail-closed warning listing files that could not be examined."""
    count = int(info["skip_count"])
    skipped = list(info["skipped"])
    print(
        f"warning: {count} file(s) could not be scanned "
        f"(non-UTF-8, unreadable, or special files) — result is incomplete.",
        file=sys.stderr,
    )
    for path, reason in skipped:
        print(f"  skipped {_display(path)}: {_display(reason)}", file=sys.stderr)


def _stream_scan(args: argparse.Namespace, info: Dict[str, object]) -> Iterator[object]:
    """Yield :class:`FileHazard` from a scan, collecting skip events into *info*.

    Never raises on a missing path — instead ``info["error"]`` is set and
    the caller returns exit code 2. Skipped files are counted in
    ``info["skip_count"]`` with the first few listed in ``info["skipped"]``.
    """

    def on_skip(path: str, reason: str) -> None:
        info["skip_count"] = int(info["skip_count"]) + 1
        if len(info["skipped"]) < _MAX_SKIP_DETAIL:
            info["skipped"].append((path, reason))

    if not args.path:
        info["error"] = "empty path"
        return
    try:
        iterator = scan_path_iter(
            Path(args.path),
            policy=args.policy,
            recursive=args.recursive,
            on_skip=on_skip,
        )
        for fh in iterator:
            yield fh
    except OSError as exc:
        info["error"] = str(exc)


def _scan_exit_code(info: Dict[str, object], findings: int) -> int:
    """Fail-closed exit code: any unexamined file dominates the result."""
    if info.get("error"):
        return 2
    if info["skip_count"]:
        _report_skips(info)
        return 2
    return 1 if findings else 0


def cmd_scan(args: argparse.Namespace) -> int:
    info: Dict[str, object] = {"skip_count": 0, "skipped": [], "error": None}
    findings = 0
    for fh in _stream_scan(args, info):
        _print_hazard_file(fh.path, fh.line, fh.column, fh.hazard)
        findings += 1
    if info.get("error"):
        print(f"error: {info['error']}", file=sys.stderr)
        return 2
    if findings:
        print(
            f"\n{findings} invisible-Unicode hazard(s) found "
            f"(policy={args.policy}).",
            file=sys.stderr,
        )
        return _scan_exit_code(info, findings)
    if info["skip_count"]:
        _report_skips(info)
        return 2
    print(f"OK: no invisible-Unicode hazards found in {args.path} (policy={args.policy}).")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    info: Dict[str, object] = {"skip_count": 0, "skipped": [], "error": None}
    findings = 0
    first = None
    for fh in _stream_scan(args, info):
        if findings == 0:
            first = fh
        findings += 1
    if info.get("error"):
        print(f"error: {info['error']}", file=sys.stderr)
        return 2
    if findings:
        print(
            f"{findings} hazard(s) found in {args.path} "
            f"(policy={args.policy}). First: "
            f"{first.hazard.escaped} {first.hazard.name} "
            f"at {_display(first.path)}:{first.line}:{first.column}"
        )
        return _scan_exit_code(info, findings)
    if info["skip_count"]:
        _report_skips(info)
        return 2
    print(f"OK: {args.path} clean (policy={args.policy}).")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    text = " ".join(args.text) if args.text else ""
    found = find_suspicious(text, policy=args.policy)
    for hazard in found:
        print(f"offset={hazard.offset}  {hazard.escaped} {hazard.name} ({hazard.short})")
    if not found:
        print(f"no hazards found in {len(text)} character(s) (policy={args.policy}).")
    return 1 if found else 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if src.is_symlink():
        print(
            f"error: refusing to sanitize symlink {src} "
            f"(it would modify the symlink target)",
            file=sys.stderr,
        )
        return 2
    if not src.exists():
        print(f"error: cannot read {src}: no such file", file=sys.stderr)
        return 2
    try:
        raw = src.read_text(encoding="utf-8")
    except (UnicodeDecodeError, UndecodableFileError):
        print(f"error: {src} is not valid UTF-8; nothing written", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read {src}: {exc}", file=sys.stderr)
        return 2
    clean = sanitize(raw, policy=args.policy)
    out = Path(args.output) if args.output else src
    if out.is_symlink():
        print(
            f"error: refusing to write through symlink {out} "
            f"(it would overwrite the symlink target)",
            file=sys.stderr,
        )
        return 2
    # "In place" means the same file (same path or same inode); anything
    # else is a new output file. samefile can raise OSError on some
    # filesystems even when both paths exist, so treat that as "not in
    # place" rather than crashing.
    in_place = out == src
    if not in_place:
        try:
            in_place = out.exists() and os.path.samefile(src, out)
        except OSError:
            in_place = False
    # Atomic write: temp file in the same directory, then rename. A failed
    # or interrupted write can never leave a partially rewritten file.
    tmp_path: Optional[str] = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=str(out.parent if str(out.parent) else Path(".")),
            prefix=".boundaryguard-",
            suffix=".tmp",
        )
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(clean)
        if in_place:
            # Preserve the original file's permissions for in-place edits.
            os.chmod(tmp_path, stat.S_IMODE(src.stat().st_mode))
        else:
            # New output file: respect the umask like a normal open would
            # (mkstemp defaults to 0600, which is unexpectedly private).
            # os.umask() is the only way to read the umask; the read-back
            # restores it immediately, so the process-global change is
            # transient and safe for this single-threaded CLI.
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp_path, 0o666 & ~umask)
        os.replace(tmp_path, out)
    except OSError as exc:
        print(f"error: cannot write {out}: {exc}", file=sys.stderr)
        return 2
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    removed = len(raw) - len(clean)
    print(
        f"wrote {out} ({removed} hazard character(s) removed, "
        f"policy={args.policy})."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boundaryguard",
        description=(
            "Detect and remove invisible Unicode security hazards "
            "(Trojan Source / CVE-2021-42574 class)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"boundaryguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a file or directory (prints file:line:col)")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("-r", "--recursive", action="store_true", help="walk directories recursively")
    p_scan.add_argument("--policy", choices=_POLICIES, default="security", help="scan policy")
    p_scan.set_defaults(func=cmd_scan)

    p_check = sub.add_parser("check", help="CI-friendly: exit 0 clean, 1 findings, 2 error")
    p_check.add_argument("path", help="file or directory to check")
    p_check.add_argument("-r", "--recursive", action="store_true", help="walk directories recursively")
    p_check.add_argument("--policy", choices=_POLICIES, default="security", help="scan policy")
    p_check.set_defaults(func=cmd_check)

    p_inspect = sub.add_parser("inspect", help="explain characters in a string")
    p_inspect.add_argument("text", nargs="+", help="text to inspect")
    p_inspect.add_argument("--policy", choices=_POLICIES, default="security", help="scan policy")
    p_inspect.set_defaults(func=cmd_inspect)

    p_sanitize = sub.add_parser("sanitize", help="remove hazards from a file (atomic)")
    p_sanitize.add_argument("input", help="input file (UTF-8)")
    p_sanitize.add_argument("-o", "--output", help="output file; defaults to in-place")
    p_sanitize.add_argument("--policy", choices=_POLICIES, default="security", help="sanitize policy")
    p_sanitize.set_defaults(func=cmd_sanitize)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    # Die quietly on SIGPIPE (e.g. `boundaryguard scan big | head`), like
    # standard Unix tools, instead of printing a BrokenPipeError traceback.
    try:
        import signal

        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass  # non-POSIX platform or not the main thread
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # Avoid a secondary BrokenPipeError when the interpreter flushes
        # stdout at shutdown (matters on platforms without SIGPIPE).
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return 141


if __name__ == "__main__":
    sys.exit(main())
