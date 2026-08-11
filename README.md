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
| `0` | No hazards found |
| `1` | Hazards found |
| `2` | Usage or I/O error |

Drop `boundaryguard check --recursive .` into your CI and never merge invisible code again.

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
```

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
| `bidi_format` | LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI (U+202A–U+202E, U+2066–U+2069) | **Trojan Source (CVE-2021-42574)** — text renders in a different order from its logical order |
| `bidi_mark` | LRM, RLM (U+200E–U+200F) | Invisible; abused for obfuscation, legitimate for RTL text |
| `zero_width` | ZWSP, ZWNJ, ZWJ, BOM (U+200B–U+200D, U+FEFF) | Invisible to humans, meaningful to machines; break comparisons and hide content |
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
- [ ] JSON / SARIF output for CI integrations
- [ ] Recursive repository scanning performance pass
- [ ] `safe_fs` — path-confinement primitives (path-traversal hardening) as a second module
- [ ] Windows/macOS CI coverage

---

## License

MIT. Contributions welcome — open an issue or pull request.
