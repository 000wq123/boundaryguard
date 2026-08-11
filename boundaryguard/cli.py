"""Command-line interface for boundaryguard.

Subcommands:

* ``scan``      — scan a file or directory (optionally recursive), print
                  every hazard with file:line:column and an escaped
                  rendering, exit 1 if anything was found.
* ``check``     — like scan, but quiet: only prints a one-line summary.
                  Exit 0 = clean, 1 = hazards found, 2 = error.
* ``inspect``   — explain the characters in a string argument.
* ``sanitize``  — remove hazards from a file (in place or to a new file).

Exit codes are CI-friendly: 0 clean, 1 findings, 2 usage/IO error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import (
    Hazard,
    explain_character,
    find_suspicious,
    sanitize,
    scan_path,
)

_POLICIES = ("security", "preserve_rtl")


def _render(hazard: Hazard) -> str:
    """Render one hazard as a visible escaped string."""
    return f"\\u{hazard.codepoint:04X}"


def _print_hazard_file(path: str, line: int, column: int, hazard: Hazard) -> None:
    print(
        f"{path}:{line}:{column}  "
        f"{hazard.escaped} {hazard.name} ({hazard.short}) "
        f"[{hazard.category}]  render={_render(hazard)!r}"
    )


def cmd_scan(args: argparse.Namespace) -> int:
    findings = scan_path(Path(args.path), policy=args.policy, recursive=args.recursive)
    for fh in findings:
        _print_hazard_file(fh.path, fh.line, fh.column, fh.hazard)
    if findings:
        print(
            f"\n{len(findings)} invisible-Unicode hazard(s) found "
            f"(policy={args.policy}).",
            file=sys.stderr,
        )
        return 1
    print(f"OK: no invisible-Unicode hazards found in {args.path} (policy={args.policy}).")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    findings = scan_path(Path(args.path), policy=args.policy, recursive=args.recursive)
    if findings:
        print(
            f"{len(findings)} hazard(s) found in {args.path} "
            f"(policy={args.policy}). First: "
            f"{findings[0].hazard.escaped} {findings[0].hazard.name} "
            f"at {findings[0].path}:{findings[0].line}:{findings[0].column}"
        )
        return 1
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
    try:
        raw = src.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {src}: {exc}", file=sys.stderr)
        return 2
    clean = sanitize(raw, policy=args.policy)
    if args.output:
        out = Path(args.output)
    else:
        out = src
    try:
        out.write_text(clean, encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write {out}: {exc}", file=sys.stderr)
        return 2
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

    p_check = sub.add_parser("check", help="CI-friendly: exit 0 clean, 1 findings")
    p_check.add_argument("path", help="file or directory to check")
    p_check.add_argument("-r", "--recursive", action="store_true", help="walk directories recursively")
    p_check.add_argument("--policy", choices=_POLICIES, default="security", help="scan policy")
    p_check.set_defaults(func=cmd_check)

    p_inspect = sub.add_parser("inspect", help="explain characters in a string")
    p_inspect.add_argument("text", nargs="+", help="text to inspect")
    p_inspect.add_argument("--policy", choices=_POLICIES, default="security", help="scan policy")
    p_inspect.set_defaults(func=cmd_inspect)

    p_sanitize = sub.add_parser("sanitize", help="remove hazards from a file")
    p_sanitize.add_argument("input", help="input file (UTF-8)")
    p_sanitize.add_argument("-o", "--output", help="output file; defaults to in-place")
    p_sanitize.add_argument("--policy", choices=_POLICIES, default="security", help="sanitize policy")
    p_sanitize.set_defaults(func=cmd_sanitize)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
