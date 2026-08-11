"""Unit tests for boundaryguard.core."""

from pathlib import Path

import pytest

from boundaryguard import (
    contains_bidi_controls,
    contains_zero_width,
    explain_character,
    find_suspicious,
    sanitize,
    scan_file,
    scan_path,
)

RLI = "\u2067"  # RIGHT-TO-LEFT ISOLATE
PDI = "\u2069"  # POP DIRECTIONAL ISOLATE
RLO = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
LRM = "\u200e"  # LEFT-TO-RIGHT MARK
RLM = "\u200f"  # RIGHT-TO-LEFT MARK
ZWSP = "\u200b"  # ZERO WIDTH SPACE
ZWNJ = "\u200c"
ZWJ = "\u200d"
BOM = "\ufeff"


class TestFindSuspicious:
    def test_clean_text(self):
        assert find_suspicious("hello world, plain ASCII!") == []

    def test_detects_bidi_isolate(self):
        hazards = find_suspicious(f"if True:  # {RLI} if False: {PDI}")
        shorts = [h.short for h in hazards]
        assert shorts == ["RLI", "PDI"]

    def test_detects_rlo(self):
        hazards = find_suspicious(f"password = \"{RLO}admin\"")
        assert hazards[0].short == "RLO"
        assert hazards[0].escaped == "U+202E"
        assert hazards[0].name == "RIGHT-TO-LEFT OVERRIDE"
        assert hazards[0].category == "bidi_format"

    def test_zero_width_detected(self):
        assert any(h.short == "ZWSP" for h in find_suspicious(f"admin{ZWSP}"))
        assert any(h.short == "BOM" for h in find_suspicious(f"{BOM}"))

    def test_offsets_are_character_indexed(self):
        hazards = find_suspicious(f"ab{RLO}cd")
        assert hazards[0].offset == 2

    def test_empty_string(self):
        assert find_suspicious("") == []


class TestPolicies:
    def test_security_strips_rtl_marks(self):
        # LRM/RLM are invisible and stripped under the strict policy.
        assert find_suspicious(f"a{LRM}b") != []
        assert sanitize(f"a{LRM}b") == "ab"

    def test_preserve_rtl_keeps_legitimate_marks(self):
        # Arabic/Hebrew text legitimately uses LRM/RLM + ZWNJ/ZWJ.
        arabic = "\u0645\u0631\u062d\u0628\u0627"  # مرحبا
        text = f"{arabic}{RLM} {ZWNJ} ok"
        assert sanitize(text, policy="preserve_rtl") == text

    def test_preserve_rtl_still_removes_formatting(self):
        text = f"ok{RLO}bad"
        clean = sanitize(text, policy="preserve_rtl")
        assert RLO not in clean
        assert clean == "okbad"

    def test_preserve_rtl_removes_zwsp(self):
        assert sanitize(f"a{ZWSP}b", policy="preserve_rtl") == "ab"


class TestSanitize:
    def test_strips_all_by_default(self):
        text = f"{RLI}hello{PDI}{ZWSP}{BOM}"
        assert sanitize(text) == "hello"

    def test_keeps_plain_text(self):
        assert sanitize("plain text 123") == "plain text 123"

    def test_keeps_newlines_tabs(self):
        assert sanitize("a\nb\tc") == "a\nb\tc"

    def test_strips_control_chars(self):
        assert sanitize("a\x00b\x1fc") == "abc"


class TestBooleanHelpers:
    def test_contains_bidi_controls(self):
        assert contains_bidi_controls(f"x{RLO}y")
        assert contains_bidi_controls(f"{LRM}")
        assert not contains_bidi_controls("plain")

    def test_contains_zero_width(self):
        assert contains_zero_width(f"a{ZWSP}")
        assert not contains_zero_width("plain")


class TestExplain:
    def test_explains_rlo(self):
        assert "RIGHT-TO-LEFT OVERRIDE" in explain_character(RLO)
        assert "U+202E" in explain_character(RLO)

    def test_explains_plain_ascii(self):
        assert "LATIN CAPITAL LETTER A" in explain_character("A")

    def test_explain_empty(self):
        assert "(empty" in explain_character("")


class TestFileScanning:
    def test_scan_file_finds_line_and_column(self, tmp_path: Path):
        f = tmp_path / "evil.py"
        f.write_text(f"x = 1\nflag = \"{RLO}on\"\n", encoding="utf-8")
        results = scan_file(f)
        assert len(results) == 1
        fh = results[0]
        assert fh.line == 2
        assert fh.column == 9  # flag = " → column 8 is the quote, RLO at 9
        assert fh.hazard.short == "RLO"

    def test_scan_file_skips_binary(self, tmp_path: Path):
        f = tmp_path / "blob.bin"
        f.write_bytes(b"\x00\xff\xfe\x01\x00")
        assert scan_file(f) == []

    def test_scan_path_directory_nonrecursive(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(f"x = '{RLO}'", encoding="utf-8")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.py").write_text(f"y = '{RLO}'", encoding="utf-8")
        found = scan_path(tmp_path, recursive=False)
        assert len(found) == 1
        assert "a.py" in found[0].path

    def test_scan_path_recursive_skips_git(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(f"x = '{RLO}'", encoding="utf-8")
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config").write_text(f"evil = '{RLO}'", encoding="utf-8")
        found = scan_path(tmp_path, recursive=True)
        assert len(found) == 1
        assert ".git" not in found[0].path
