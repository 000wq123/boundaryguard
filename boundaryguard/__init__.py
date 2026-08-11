"""boundaryguard — detect and remove invisible Unicode security hazards.

A zero-dependency CLI and Python library for finding and stripping the
Unicode characters behind *Trojan Source* (CVE-2021-42574) and related
invisible-injection attacks: bidi formatting controls, bidi marks,
zero-width characters, and C0 control characters.

Extracted from the adversarial hardening of a production system, and
shipped with a test corpus of published attack samples.

Usage:
    boundaryguard scan --recursive .
    boundaryguard inspect "hello\u202e"
    boundaryguard sanitize input.txt -o clean.txt
    boundaryguard check file.py   # CI-friendly, exit code 1 on findings
"""

from .core import (
    FileHazard,
    Hazard,
    contains_bidi_controls,
    contains_zero_width,
    explain_character,
    find_suspicious,
    sanitize,
    scan_file,
    scan_path,
    scan_texts,
)

__version__ = "0.1.0"

__all__ = [
    "FileHazard",
    "Hazard",
    "contains_bidi_controls",
    "contains_zero_width",
    "explain_character",
    "find_suspicious",
    "sanitize",
    "scan_file",
    "scan_path",
    "scan_texts",
    "__version__",
]
