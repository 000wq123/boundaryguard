#!/usr/bin/env python3
"""Mutation-test the security guards in boundaryguard.

Each "mutant" below surgically removes or inverts one security guard in a
*sandboxed copy* of the source tree (the real tree is never touched), then
runs the full pytest suite against the mutated copy. The suite must fail
for every mutant: if it passes, that guard has no test coverage and a
future change could silently drop it without CI noticing.

Why a manual mutant set instead of mutmut?
    - Deterministic and fast (~22s): every mutant is a single logical
      guard removal, and each run exercises the whole suite once.
    - Targeted: every mutant here maps to a real security guarantee
      (fail-closed decoding, symlink refusal, terminal escaping, ...)
      rather than hundreds of whole-codebase mutations, most of which are
      uninteresting for a security gate.
    - Zero dependencies beyond pytest (matches the project's zero-dep
      ethos); no install step, no network, no flaky timeouts.

How kills are judged
--------------------
Before any mutant runs, the pristine sandbox is tested once as a control:
if the unmutated suite does not pass in the sandbox, the entire run is
invalid and aborts — the gate can never report "all killed" without first
proving the base suite is green in the same environment.

Per mutant, pytest's exit code decides the status:

* ``KILLED``    — exit 1: tests ran and assertions failed (a genuine kill).
* ``SURVIVED``  — exit 0: the suite passed with the guard removed (gap).
* ``ERRORED``   — any other non-zero exit (2/3/4/5, no test summary):
                  tests could not run, so nothing was demonstrated. Treated
                  as a failure of the gate, never as a kill.
* ``HUNG``      — the per-mutant timeout fired; the guard removal made the
                  suite hang (e.g. a FIFO opened and read forever). Also a
                  failure: the guard was load-bearing and the suite cannot
                  even fail on it.

Known non-mutants (guards deliberately NOT in this set):
    - Atomic sanitize writes (``os.replace``): not deterministically
      testable in a unit suite without fault injection; covered by the
      crash-consistency audit (SIGKILL at every stage, 0 corruptions).
    - The os.walk ``onerror`` callback (unreadable directories): a chmod
      000 test is unreliable when run as root; documented in README.
    - The TOCTOU layer alone (``O_NOFOLLOW`` without the enumeration
      checks): probabilistic by nature, so it is only killable when
      combined with the symlink-refusal mutant (M6).

Exit codes:
    0  — every mutant was killed by the suite (control passed)
    1  — a mutant survived, errored, or hung; or the control failed

Usage:
    python scripts/mutation_test.py           # run the full set
    python scripts/mutation_test.py M3 M7     # run a subset by id
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]

# Each mutant gets this long to run the whole suite. A timeout means the
# mutation made the suite hang — which is itself a failure: the guard was
# load-bearing and the suite cannot even fail on it.
MUTANT_TIMEOUT = float(os.environ.get("BG_MUTANT_TIMEOUT", "180"))

# Items copied into each sandbox so mutants can never touch the real tree.
_COPY_ITEMS = ("boundaryguard", "tests", "pyproject.toml")
_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", ".pytest_cache", "*.egg-info", ".coverage"
)

# ── The mutant set ──────────────────────────────────────────────────────
# Each entry removes/inverts one security guard. ``replacements`` is a
# list of (old, new) exact string pairs; every ``old`` must appear exactly
# once in the current source, so a refactor that rewrites a guard's code
# fails this runner loudly instead of silently mutating the wrong place.

MUTANTS: List[Dict[str, object]] = [
    {
        "id": "M1",
        "path": "boundaryguard/core.py",
        "guard": "hazard detection must not be disabled",
        "replacements": [
            ("    entry = _ALL_HAZARDS.get(cp)\n", "    entry = None\n"),
        ],
        "killed_by": "every detection test (RLI/RLO/ZWSP/BOM/WJ/deprecated bidi)",
    },
    {
        "id": "M2",
        "path": "boundaryguard/core.py",
        "guard": "invalid policies must raise (never silently fall back to security)",
        "replacements": [
            (
                "def _validate_policy(policy: str) -> None:\n"
                "    if policy not in POLICIES:\n"
                "        raise ValueError(\n"
                '            f"invalid policy {policy!r}; expected one of {POLICIES}"\n'
                "        )\n",
                "def _validate_policy(policy: str) -> None:\n    return\n",
            ),
        ],
        "killed_by": "test_invalid_policy_raises_everywhere",
    },
    {
        "id": "M3",
        "path": "boundaryguard/core.py",
        "guard": "preserve_rtl must keep LRM/RLM/ZWNJ/ZWJ (legitimate RTL text)",
        "replacements": [
            ("_PRESERVE_RTL = {0x061C, 0x200E, 0x200F, 0x200C, 0x200D}\n", "_PRESERVE_RTL = set()\n"),
        ],
        "killed_by": "test_preserve_rtl_keeps_legitimate_marks, "
        "test_find_suspicious_preserve_rtl_ignores_legitimate_marks, "
        "test_preserve_rtl_keeps_alm",
    },
    {
        "id": "M4",
        "path": "boundaryguard/core.py",
        "guard": "fail-closed decoding: non-UTF-8 files must never become clean",
        "replacements": [
            # scan_file: decode error must still raise UndecodableFileError.
            (
                "        def on_decode_error(reason: str) -> None:\n"
                "            decode_failed.append(reason)\n",
                "        def on_decode_error(reason: str) -> None:\n            return\n",
            ),
            # _scan_single: decode error must still report via on_skip.
            (
                "            def on_decode_error(reason: str) -> None:\n"
                "                if on_skip is not None:\n"
                "                    on_skip(str(path), reason)\n",
                "            def on_decode_error(reason: str) -> None:\n                return\n",
            ),
        ],
        "killed_by": "test_scan_file_fails_closed_on_binary/utf16, "
        "test_scan_path_iter_reports_skips_fail_closed, "
        "test_check_non_utf8_exit_two_fail_closed",
    },
    {
        "id": "M5",
        "path": "boundaryguard/core.py",
        "guard": "special files (FIFO/socket/device) must be rejected, never read",
        "replacements": [
            # scan_file: FIFO must raise ValueError, not be read.
            (
                "        if not stat.S_ISREG(st.st_mode):\n"
                '            raise ValueError(f"not a regular file: {path}")\n',
                "        if stat.S_ISREG(st.st_mode):\n"
                '            raise ValueError(f"not a regular file: {path}")\n',
            ),
            # _scan_single: FIFO must be reported via on_skip.
            (
                "            if not stat.S_ISREG(st.st_mode):\n"
                "                if on_skip is not None:\n"
                '                    on_skip(str(path), "not a regular file (FIFO/socket/device)")\n'
                "                return\n",
                "            if stat.S_ISREG(st.st_mode):\n"
                "                if on_skip is not None:\n"
                '                    on_skip(str(path), "not a regular file (FIFO/socket/device)")\n'
                "                return\n",
            ),
        ],
        "killed_by": "test_scan_file_raises_on_special_file, "
        "test_scan_path_iter_skips_fifo, test_check_recursive_fifo_exit_two_no_hang",
    },
    {
        "id": "M6",
        "path": "boundaryguard/core.py",
        "guard": "tree scans must never follow symlinks out of the scan root",
        "replacements": [
            # Non-recursive walk: drop the enumeration check.
            (
                "            if child.is_symlink():\n"
                "                continue  # never follow symlinks outside the scan root\n"
                "            yield from _scan_single(child, policy, limit, on_skip, follow=False)\n",
                "            yield from _scan_single(child, policy, limit, on_skip, follow=False)\n",
            ),
            # Recursive walk: drop the per-file enumeration check.
            (
                "            if fp.is_symlink():\n"
                "                continue\n"
                "            yield from _scan_single(fp, policy, limit, on_skip, follow=False)\n",
                "            yield from _scan_single(fp, policy, limit, on_skip, follow=False)\n",
            ),
            # Open-time layer: without O_NOFOLLOW the enumeration checks
            # are the only thing left (and races are no longer closed).
            (
                '        flags |= getattr(os, "O_NOFOLLOW", 0)\n',
                "        pass\n",
            ),
        ],
        "killed_by": "test_scan_path_skips_symlinked_files + "
        "test_scan_path_nonrecursive_skips_symlinked_files",
    },
    {
        "id": "M7",
        "path": "boundaryguard/cli.py",
        "guard": "exit code: unexamined files must force exit 2, never a clean 0",
        "replacements": [
            (
                "    if info[\"skip_count\"]:\n"
                "        _report_skips(info)\n"
                "        return 2\n"
                "    return 1 if findings else 0\n",
                "    if info[\"skip_count\"]:\n"
                "        _report_skips(info)\n"
                "        return 1 if findings else 0\n",
            ),
        ],
        "killed_by": "test_check_non_utf8_exit_two_fail_closed, "
        "test_check_recursive_fifo_exit_two_no_hang, "
        "test_check_findings_and_skips_exit_two",
    },
    {
        "id": "M8",
        "path": "boundaryguard/cli.py",
        "guard": "terminal-safe output: untrusted paths must be escaped",
        "replacements": [
            (
                "        if (\n"
                "            cp < 0x20\n"
                "            or 0x7F <= cp <= 0x9F\n",
                "        if False and (\n"
                "            cp < 0x20\n"
                "            or 0x7F <= cp <= 0x9F\n",
            ),
        ],
        "killed_by": "all TestTerminalInjection tests",
    },
    {
        "id": "M9",
        "path": "boundaryguard/cli.py",
        "guard": "sanitize must refuse symlinked input and output",
        "replacements": [
            ("    if src.is_symlink():\n", "    if False and src.is_symlink():\n"),
            ("    if out.is_symlink():\n", "    if False and out.is_symlink():\n"),
        ],
        "killed_by": "test_sanitize_refuses_symlink_input + "
        "test_sanitize_refuses_symlink_output",
    },
    {
        "id": "M10",
        "path": "boundaryguard/core.py",
        "guard": "non-string input must raise TypeError (API contract)",
        "replacements": [
            (
                "def _require_text(text: object) -> str:\n"
                "    if not isinstance(text, str):\n"
                '        raise TypeError(f"expected str, got {type(text).__name__}")\n'
                "    return text\n",
                "def _require_text(text: object) -> str:\n    return text  # type: ignore[return-value]\n",
            ),
        ],
        "killed_by": "test_non_string_input_raises_typeerror",
    },
    {
        "id": "M11",
        "path": "boundaryguard/core.py",
        "guard": "limit must bound result size (memory DoS guard)",
        "replacements": [
            (
                "        if limit is not None and len(hazards) >= limit:\n"
                "            break\n",
                "        pass\n",
            ),
        ],
        "killed_by": "test_limit_bounds_results, "
        "test_scan_path_iter_limit_bounds_memory",
    },
    {
        "id": "M12",
        "path": "boundaryguard/core.py",
        "guard": "character tables: U+2060 WORD JOINER must be detected",
        "replacements": [
            ('    0x2060: ("WJ", "WORD JOINER", "zero_width"),\n', ""),
        ],
        "killed_by": "test_word_joiner_detected",
    },
    {
        "id": "M13",
        "path": "boundaryguard/core.py",
        "guard": "recursive scans must skip VCS/venv/build directories",
        "replacements": [
            (
                "            if d not in _SKIP_DIRS and not (Path(root) / d).is_symlink()\n",
                "            if not (Path(root) / d).is_symlink()\n",
            ),
        ],
        "killed_by": "test_scan_path_recursive_skips_git",
    },
    {
        "id": "M14",
        "path": "boundaryguard/cli.py",
        "guard": "empty path must fail loudly, not silently scan the CWD",
        "replacements": [
            (
                "    if not args.path:\n"
                '        info["error"] = "empty path"\n'
                "        return\n",
                "    pass\n",
            ),
        ],
        "killed_by": "test_check_empty_path_exit_two",
    },
    {
        "id": "M15",
        "path": "boundaryguard/core.py",
        "guard": "character tables: U+061C ARABIC LETTER MARK (a Bidi_Control) must be detected",
        "replacements": [
            ('    0x061C: ("ALM", "ARABIC LETTER MARK", "bidi_mark"),\n', ""),
        ],
        "killed_by": "test_alm_is_bidi_control_detected, "
        "test_scan_file_flags_alm, test_preserve_rtl_keeps_alm",
    },
]


# ── Runner ──────────────────────────────────────────────────────────────


def _apply_mutation(source: str, replacements: List[Tuple[str, str]]) -> str:
    """Apply (old, new) pairs, requiring each anchor to be unique."""
    for old, new in replacements:
        if old not in source:
            raise AssertionError(
                f"mutation anchor not found in source:\n{old!r}\n"
                "(the guard's code was probably refactored — update "
                "scripts/mutation_test.py)"
            )
        if source.count(old) != 1:
            raise AssertionError(
                f"mutation anchor is not unique ({source.count(old)} hits):\n{old!r}\n"
                "(update the anchor in scripts/mutation_test.py)"
            )
        source = source.replace(old, new, 1)
    return source


def _run_in_sandbox(mut: Optional[Dict[str, object]]) -> Tuple[int, str]:
    """Copy the source+tests into a temp dir, optionally mutate, run pytest.

    ``cwd`` and ``PYTHONPATH`` both point at the sandbox so every test —
    including the subprocess-based CLI tests — imports the *mutated*
    package, never an installed or editable copy. ``mut=None`` runs the
    pristine copy (the control).
    """
    with tempfile.TemporaryDirectory(prefix="bg-mutation-") as td:
        sandbox = Path(td)
        for name in _COPY_ITEMS:
            src = ROOT / name
            dst = sandbox / name
            if src.is_dir():
                shutil.copytree(src, dst, ignore=_IGNORE)
            else:
                shutil.copy2(src, dst)
        if mut is not None:
            target = sandbox / str(mut["path"])
            text = target.read_text(encoding="utf-8")
            text = _apply_mutation(text, list(mut["replacements"]))  # type: ignore[arg-type]
            target.write_text(text, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(sandbox) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            # No -q here: the copied pyproject.toml already adds it via
            # addopts, and two -q flags (quiet-quiet) suppress pytest's
            # "N passed" summary line, which the control uses to verify
            # the expected test count actually ran.
            [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"],
            cwd=sandbox,
            env=env,
            capture_output=True,
            text=True,
            timeout=MUTANT_TIMEOUT,
        )
        return proc.returncode, proc.stdout + proc.stderr


def _check_pytest_available() -> None:
    """Abort before mutating anything if pytest is not installed."""
    proc = subprocess.run(
        [sys.executable, "-c", "import pytest"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.exit(
            "error: pytest is required to run the mutation suite.\n"
            "Install it with: pip install -e .[dev]"
        )


def _status_for(returncode: int) -> str:
    """Map a pytest exit code to a status.

    Only exit 1 (tests ran and failed) is a genuine kill. Exit 0 is a
    survival. Anything else (2/3/4/5: collection, usage, or internal
    errors) means the tests could not run, so nothing was demonstrated.
    """
    if returncode == 0:
        return "SURVIVED"
    if returncode == 1:
        return "KILLED"
    return "ERRORED"


def main(argv: List[str]) -> int:
    _check_pytest_available()
    subset = set(argv[1:])
    print("Mutation testing: boundaryguard security guards")
    print("=" * 56)

    # Control run: the pristine sandbox must pass, or the run is invalid.
    print("  control: verifying the pristine suite passes in the sandbox...")
    control_rc, control_out = _run_in_sandbox(None)
    if control_rc != 0:
        print("  control FAILED — the mutation run is invalid (broken sandbox/base suite).")
        for line in control_out.strip().splitlines()[-8:]:
            print(f"    | {line}")
        return 1
    m = re.search(r"(\d+) passed", control_out)
    print(f"  control passed ({m.group(1)} tests)." if m else "  control passed.")

    results: List[Tuple[Dict[str, object], str, float, str]] = []
    for mut in MUTANTS:
        if subset and mut["id"] not in subset:
            continue
        start = time.monotonic()
        try:
            returncode, output = _run_in_sandbox(mut)
            status = _status_for(returncode)
        except subprocess.TimeoutExpired as exc:
            status = "HUNG"
            output = getattr(exc, "output", "") or ""
        elapsed = time.monotonic() - start
        results.append((mut, status, elapsed, output))
        print(f"  {mut['id']:<4} {status:<9} {elapsed:5.1f}s  {mut['guard']}")

    killed = sum(1 for _, s, _, _ in results if s == "KILLED")
    failed = [(m_, s, out) for m_, s, _, out in results if s != "KILLED"]
    print("=" * 56)
    if not failed:
        print(
            f"{killed}/{len(results)} mutants killed. "
            "All security guards are covered by tests."
        )
        return 0
    print(
        f"{killed}/{len(results)} killed, {len(failed)} NOT killed — "
        "the suite is not protecting:"
    )
    for mut, status, output in failed:
        print(f"\n  {mut['id']} {status}: {mut['guard']}")
        print(f"    expected killed by: {mut['killed_by']}")
        if status == "HUNG":
            print("    the suite hung after this guard was removed (timeout).")
        tail = output.strip().splitlines()[-8:]
        for line in tail:
            print(f"    | {line}")
    print(
        "\nAdd a regression test that fails when this guard is removed, "
        "then re-run this script."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
