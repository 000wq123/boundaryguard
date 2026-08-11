# boundaryguard

**Detect, explain, and remove invisible Unicode security hazards from source code, logs, configuration, provenance strings, and AI inputs.**

[![CI](https://github.com/000wq123/boundaryguard/actions/workflows/ci.yml/badge.svg)](https://github.com/000wq123/boundaryguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)

**Zero dependencies. Pure standard library. CI-friendly exit codes.**

---

## Why this exists

In 2021, researchers (Boucher & Anderson, *[Trojan Source: Invisible Vulnerabilities](https://arxiv.org/abs/2111.00169)*) demonstrated that **Unicode bidirectional control characters** let attackers write source code that *renders* in a different order from its logical token order — so a human reviewer can approve code that does something entirely different from what it appears to do. The attack was assigned **CVE-2021-42574** and affects every major language: Python, JavaScript, C/C++, Java, Rust, Go, SQL, Bash, and more.

The same invisible characters — bidi controls, bidi marks, zero-width spaces, and C0 controls — are routinely abused beyond source code:

- **Prompt injection** — smuggling invisible instructions into text that an LLM will process.
- **String-comparison bypasses** — `"admin\u200b"` vs `"admin"`.
- **Log & provenance poisoning** — invisible characters that corrupt hashes, keys, and audit trails.
- **Filter evasion** — hiding disallowed content in plain sight.

**boundaryguard** is a focused, dependency-free tool for the detection and removal of this character class. It was extracted from the adversarial hardening of a production verification system — where a security audit found invisible-character bugs in provenance and metadata handling — and is shipped with a test corpus of published attack samples.

> ⚠️ **Scope:** boundaryguard detects and removes *invisible-character obfuscation*. It is not a general-purpose SAST scanner, and it does not claim to be a complete defense against all prompt injection or all supply-chain attacks. It removes one well-defined attack class — thoroughly.

---

## Install

```bash
pip install boundaryguard
```

Python 3.9+. No runtime dependencies.

---

## CLI

```bash
# Scan a file or directory
boundaryguard scan path/to/file.py
boundaryguard scan --recursive .

# CI-friendly check (exit 0 clean, exit 1 findings, exit 2 error)
boundaryguard check --recursive .

# Explain characters in a string
boundaryguard inspect "hello\u202e"

# Sanitize a file (in place, or to a new file)
boundaryguard sanitize input.txt -o clean.txt
boundaryguard sanitize config.json --policy preserve_rtl
```

### Example

```bash
$ boundaryguard scan suspicious.py
suspicious.py:4:14  U+202E RIGHT-TO-LEFT OVERRIDE (RLO) [bidi_format]  render='\u202e'

1 invisible-Unicode hazard(s) found (policy=security).
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — every requested file was examined and nothing was found |
| `1` | Hazards found |
| `2` | Usage or I/O error — **or files could not be examined** (see below) |

Drop `boundaryguard check --recursive .` into your CI and never merge invisible code again.

### Security behavior

- **Missing paths fail loudly** — `check` on a nonexistent path exits `2`, never a false "clean".
- **Symlinks are never followed** during tree scans, so a repo can't pull in content from outside its root via a symlinked file or directory. The check is race-proof where the OS allows: tree scans open with `O_NOFOLLOW` (Linux/macOS/BSD), so a file swapped to a symlink *between* enumeration and read fails with `ELOOP` and is skipped rather than followed.
- **Streaming input, bounded memory** — files are scanned in 1 MiB chunks with an incremental UTF-8 decoder; a multi-gigabyte file uses a few MiB of RAM, not its own size. Lines are split on `\n`/`\r`/`\r\n` (matching how compilers and editors count lines); exotic Unicode separators (e.g. U+2028) are scanned as ordinary characters.
- **Terminal-safe output** — filenames are attacker-controlled, so any path printed by the CLI (findings, first-finding lines, skip warnings) has control characters (C0/C1, DEL), line/paragraph separators, and bidi/zero-width hazards rendered as visible `\uXXXX` escapes. A repo can no longer forge an `OK: clean` verdict or fake finding with a newline, inject ANSI/OSC sequences, or bidi-reorder its own path in your report.
- **Atomic sanitize** — `sanitize` writes to a temp file in the same directory and renames it into place; a failed or interrupted write can never leave a partially rewritten file. In-place edits preserve the original file's permissions. (As with `sed -i`, the replacement is a fresh inode, so ownership and hard links are not preserved — the file ends up owned by the current user.)
- **Fail-closed scanning** — a file that *cannot be examined* is never reported clean. Files that aren't valid UTF-8 (e.g. UTF-16, binary), can't be read (permissions), or are special files (FIFOs, sockets, devices) are listed on stderr and force exit code `2` with a warning like:

  ```
  warning: 2 file(s) could not be scanned (non-UTF-8, unreadable, or special files) — result is incomplete.
  ```

  If your tree legitimately contains binary files, exclude them (e.g. scan `src/` only) rather than letting an unexamined file silently pass.
- **Streaming scans** — `scan`/`check` stream findings as they are found, so memory stays bounded even on adversarial trees with millions of hazards.
- **Sanitize refuses symlinks** — `sanitize` on a symlinked input (or `-o` pointing at a symlink) exits `2` rather than silently modifying the symlink's target.

---

## Python API

```python
from boundaryguard import (
    find_suspicious,
    explain_character,
    sanitize,
    contains_bidi_controls,
    contains_zero_width,
    scan_path,
    scan_path_iter,
)

text = "user: \u202e admin"

# Detect
for hazard in find_suspicious(text):
    print(hazard.escaped, hazard.name)   # U+202E RIGHT-TO-LEFT OVERRIDE

# Explain any character
print(explain_character("\u202e"))       # U+202E RIGHT-TO-LEFT OVERRIDE (RLO) [bidi_format]

# Sanitize
print(repr(sanitize(text)))              # 'user:  admin'

# File scanning with line/column
for fh in scan_path("src", recursive=True):
    print(fh.path, fh.line, fh.column, fh.hazard.name)

# Streaming scan with fail-closed skip reporting (bounded memory)
skipped = []
for fh in scan_path_iter("src", recursive=True, on_skip=lambda p, r: skipped.append((p, r))):
    print(fh.path, fh.line, fh.column, fh.hazard.name)
if skipped:
    print(f"{len(skipped)} file(s) could not be scanned: {skipped}")
```

**Fail-closed API:** `scan_file` raises `UndecodableFileError` for non-UTF-8
input and `OSError` for unreadable files — a file that cannot be decoded is
never reported clean. `scan_path_iter` reports unexaminable files through
its `on_skip(path, reason)` callback. Invalid policies raise `ValueError`
(never a silent fallback), and non-string input raises `TypeError`.
`scan_path_iter` is a generator (streaming); `scan_path` is a convenience
wrapper that returns the complete list in memory.

---

## Policies

Unicode bidi and zero-width characters aren't inherently malicious — they're required for legitimate multilingual text. boundaryguard ships two policies so you can be strict where it matters and permissive where it doesn't.

| Policy | Bidi formatting controls | Bidi marks (LRM/RLM) | ZWSP / BOM | ZWNJ / ZWJ | C0 controls |
|--------|------------------------|---------------------|------------|------------|-------------|
| `security` (default) | strip | strip | strip | strip | strip |
| `preserve_rtl` | strip | **keep** | strip | **keep** | strip |

- **`security`** — for identifiers, provenance keys, hashes, and anything machine-parsed or compared. Strict is safe.
- **`preserve_rtl`** — for human-facing text in Arabic, Hebrew, Persian, and Urdu, where LRM/RLM and ZWNJ/ZWJ are needed for correct rendering. The dangerous formatting controls are still removed.

---

## What it detects

| Category | Characters | Why it matters |
|----------|-----------|----------------|
| `bidi_format` | LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI, and the deprecated ISS/ASS/IAFS/AFS/NDS/NODS (U+202A–U+202E, U+2066–U+206F) | **Trojan Source (CVE-2021-42574)** — text renders in a different order from its logical order |
| `bidi_mark` | LRM, RLM (U+200E–U+200F) | Invisible; abused for obfuscation, legitimate for RTL text |
| `zero_width` | ZWSP, ZWNJ, ZWJ, WORD JOINER, BOM (U+200B–U+200D, U+2060, U+FEFF) | Invisible to humans, meaningful to machines; break comparisons and hide content |
| `control` | C0 controls except `\t\n\r` | Non-printing bytes that corrupt logs, terminals, and parsers |

---

## Test corpus

`tests/fixtures/` contains **published-style attack samples** based on the Trojan Source paper, including:

- `trojan_comment.py` — comment-out attack using RLI/PDI isolates
- `trojan_string.py` — RLO string-spoof variant
- `trojan_early_return.py` — LRE/PDF early-return variant
- `legitimate_rtl.txt` — legitimate Arabic text that must pass under `preserve_rtl`

The CI pipeline runs the full suite on Python 3.9–3.12 **and** self-scans the library source with `boundaryguard check` (dogfooding).

---

## Roadmap

- [x] Detection + sanitization with `security` / `preserve_rtl` policies
- [x] CLI (`scan` / `check` / `inspect` / `sanitize`) with CI exit codes
- [x] Trojan Source test corpus (CVE-2021-42574)
- [x] Fail-closed scanning (non-UTF-8 / unreadable / special files never report clean)
- [x] Streaming `scan_path_iter` (bounded memory on adversarial trees)
- [x] Streaming file input (1 MiB chunks; multi-GB files use bounded RAM)
- [x] Terminal-safe output (untrusted paths rendered with visible escapes)
- [x] Race-proof tree scans (`O_NOFOLLOW` where available)
- [ ] JSON / SARIF output for CI integrations
- [ ] **Path-component scanning** — flag invisible-Unicode in *filenames* themselves (e.g. `auth\u202Eyp.exe`). Deliberately out of scope for now: the CLI already renders such names safely, and GitHub/other surfaces have their own handling; needs a distinct finding type and CI-semantics decision.
- [ ] Windows CI coverage — junctions/reparse points and reserved names are not exercised by the (Linux) test matrix; `O_NOFOLLOW` is unavailable on Windows so tree scans there fall back to check-then-open.
- [ ] macOS CI coverage — APFS normalization-insensitivity means NFC/NFD-equivalent names can't coexist on disk, so no double-scan is possible; worth verifying on real hardware.
- [ ] `safe_fs` — path-confinement primitives (path-traversal hardening) as a second module

---

## License

MIT. Contributions welcome — open an issue or pull request.
