"""Unit tests for boundaryguard.core."""

from pathlib import Path

import pytest

from boundaryguard import (
    POLICIES,
    UndecodableFileError,
    contains_bidi_controls,
    contains_zero_width,
    explain_character,
    find_suspicious,
    sanitize,
    scan_file,
    scan_path,
    scan_path_iter,
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

    def test_limit_bounds_results(self):
        hazards = find_suspicious(f"{RLO}{RLO}{RLO}{RLO}{RLO}", limit=3)
        assert len(hazards) == 3
        hazards = find_suspicious(f"{RLO}{RLO}", limit=5)
        assert len(hazards) == 2

    def test_word_joiner_detected(self):
        # U+2060 WORD JOINER is zero-width and machine-significant: it
        # breaks string comparisons exactly like ZWSP.
        hazards = find_suspicious("admin\u2060")
        assert len(hazards) == 1
        assert hazards[0].short == "WJ"
        assert hazards[0].category == "zero_width"
        assert sanitize("admin\u2060") == "admin"

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

    def test_find_suspicious_preserve_rtl_ignores_legitimate_marks(self):
        # Regression: find_suspicious with preserve_rtl must not flag the
        # marks/joiners that are legitimate for RTL text.
        text = f"a{LRM}b{RLM}c{ZWNJ}d{ZWJ}e"
        assert find_suspicious(text, policy="preserve_rtl") == []
        # …but still flags the dangerous formatting controls.
        assert find_suspicious(f"x{RLO}y", policy="preserve_rtl") != []

    def test_preserve_rtl_keeps_alm(self):
        # U+061C ARABIC LETTER MARK is the Arabic bidi mark; preserve_rtl
        # must keep it exactly like LRM/RLM.
        text = "\u0645\u0631\u062d\u0628\u0627\u061c"  # مرحبا + ALM
        assert sanitize(text, policy="preserve_rtl") == text
        assert find_suspicious(text, policy="preserve_rtl") == []


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

    def test_explain_wrong_length_raises(self):
        # The docstring promises single-character input only; anything
        # else must fail loudly, not silently return a wrong answer.
        with pytest.raises(ValueError):
            explain_character("")
        with pytest.raises(ValueError):
            explain_character("ab")
        with pytest.raises(TypeError):
            explain_character(None)


class TestApiContract:
    def test_invalid_policy_raises_everywhere(self):
        # An invalid policy must never silently fall back to "security".
        for pol in ["banana", "", None, "SECURITY", "garbage", 42]:
            with pytest.raises(ValueError):
                find_suspicious(f"a{RLO}b", policy=pol)
            with pytest.raises(ValueError):
                sanitize(f"a{RLO}b", policy=pol)
        assert POLICIES == ("security", "preserve_rtl")

    def test_non_string_input_raises_typeerror(self):
        with pytest.raises(TypeError):
            find_suspicious(None)
        with pytest.raises(TypeError):
            find_suspicious(b"bytes")
        with pytest.raises(TypeError):
            sanitize(None)
        with pytest.raises(TypeError):
            sanitize(123)
        with pytest.raises(TypeError):
            contains_bidi_controls(1)

    def test_deprecated_bidi_controls_detected(self):
        # U+206A ISS (deprecated but still able to reorder older displays).
        hazards = find_suspicious("\u206a")
        assert len(hazards) == 1
        assert hazards[0].category == "bidi_format"
        assert hazards[0].short == "ISS"

    def test_alm_is_bidi_control_detected(self):
        # U+061C ARABIC LETTER MARK is one of the 13 characters with
        # Bidi_Control=Yes (category Cf, bidi class AL) — every bidi
        # control must be flagged. Regression: ALM was the only gap in the
        # Bidi_Control set.
        hazards = find_suspicious("a\u061cb")
        assert len(hazards) == 1
        assert hazards[0].short == "ALM"
        assert hazards[0].category == "bidi_mark"
        assert sanitize("a\u061cb") == "ab"
        assert contains_bidi_controls("\u061c")

    def test_get_type_hints_works_on_all_public_functions(self):
        import typing

        from boundaryguard import core

        for name in ("find_suspicious", "sanitize", "scan_file", "scan_path_iter"):
            typing.get_type_hints(getattr(core, name))


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

    def test_scan_file_fails_closed_on_binary(self, tmp_path: Path):
        # A file that cannot be decoded must NOT be reported clean.
        f = tmp_path / "blob.bin"
        f.write_bytes(b"\x00\xff\xfe\x01\x00")
        with pytest.raises(UndecodableFileError):
            scan_file(f)

    def test_scan_file_fails_closed_on_utf16(self, tmp_path: Path):
        # A UTF-16 file containing a real RLO is a genuine hazard; it must
        # raise, not silently become "clean".
        f = tmp_path / "evil16.txt"
        f.write_bytes(b"\xff\xfe" + "HELLO\u202eSECRET".encode("utf-16-le"))
        with pytest.raises(UndecodableFileError):
            scan_file(f)

    def test_scan_file_flags_alm(self, tmp_path: Path):
        # U+061C in file content is a bidi control and must be reported
        # with correct line/column through the streaming scanner.
        f = tmp_path / "arabic.py"
        f.write_text("x = 'a\u061cb'\n", encoding="utf-8")
        results = scan_file(f)
        assert len(results) == 1
        assert results[0].hazard.short == "ALM"
        assert results[0].line == 1
        assert results[0].column == 7

    def test_scan_file_raises_on_special_file(self, tmp_path: Path):
        # Run in a thread with a timeout so that a regression which opens
        # the FIFO (blocking forever on a read) fails this test instead of
        # hanging the whole suite.
        import os
        import threading

        fifo = tmp_path / "pipe"
        try:
            os.mkfifo(fifo)
        except (AttributeError, OSError):
            pytest.skip("mkfifo not available")
        result = {}

        def target():
            try:
                scan_file(fifo)
                result["value"] = "no-raise"
            except ValueError as exc:
                result["value"] = f"ValueError: {exc}"

        t = threading.Thread(target=target)
        t.start()
        t.join(timeout=5)
        assert not t.is_alive(), "scan_file blocked on the FIFO (hang regression!)"
        assert str(result.get("value")).startswith("ValueError")

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

    def test_scan_path_missing_dir_raises_oserror(self, tmp_path: Path):
        # A mistyped path must fail loudly, not silently report "clean".
        with pytest.raises(OSError):
            scan_path(tmp_path / "does-not-exist", recursive=True)
        with pytest.raises(OSError):
            scan_path(tmp_path / "does-not-exist", recursive=False)

    def test_scan_path_iter_reports_skips_fail_closed(self, tmp_path: Path):
        # Non-UTF-8 files are reported via on_skip, never silently clean.
        f = tmp_path / "evil16.txt"
        f.write_bytes(b"\xff\xfe" + "A\u202eB".encode("utf-16-le"))
        skips = []
        found = list(
            scan_path_iter(tmp_path, recursive=True, on_skip=lambda p, r: skips.append((p, r)))
        )
        assert found == []
        assert len(skips) == 1
        assert "evil16.txt" in skips[0][0]
        assert "UTF-8" in skips[0][1]

    def test_scan_path_iter_skips_fifo(self, tmp_path: Path):
        # A FIFO must be reported via on_skip, never hang the scan.
        import os

        try:
            os.mkfifo(tmp_path / "pipe")
        except (AttributeError, OSError):
            pytest.skip("mkfifo not available")
        skips = []
        list(
            scan_path_iter(tmp_path, recursive=True, on_skip=lambda p, r: skips.append((p, r)))
        )
        assert len(skips) == 1
        assert "pipe" in skips[0][0]

    def test_scan_path_iter_missing_path_raises(self, tmp_path: Path):
        with pytest.raises(OSError):
            list(scan_path_iter(tmp_path / "nope", recursive=True))

    def test_scan_path_iter_limit_bounds_memory(self, tmp_path: Path):
        f = tmp_path / "many.txt"
        f.write_text(f"{RLO}" * 10000, encoding="utf-8")
        found = list(scan_path_iter(tmp_path, recursive=True, limit=50))
        assert len(found) == 50

    def test_streaming_giant_single_line(self, tmp_path: Path):
        # A line larger than the 1 MiB scan chunk must still be scanned
        # with exact line/column (input is streamed, not read whole).
        f = tmp_path / "giant.txt"
        f.write_text("a" * (2 * 1024 * 1024) + f"{RLO}end", encoding="utf-8")
        results = scan_file(f)
        assert len(results) == 1
        assert results[0].line == 1
        assert results[0].column == 2 * 1024 * 1024 + 1

    def test_streaming_crlf_and_cr(self, tmp_path: Path):
        f = tmp_path / "mixed.txt"
        f.write_text(f"a\r\n{RLO}b\r{RLO}c\n{RLO}", encoding="utf-8")
        results = scan_file(f)
        assert [(r.line, r.column) for r in results] == [(2, 1), (3, 1), (4, 1)]

    def test_scan_path_reports_skips_via_callback(self, tmp_path: Path):
        # scan_path must not silently fail open: skips are observable.
        f = tmp_path / "evil16.txt"
        f.write_bytes(b"\xff\xfe" + f"A{RLO}B".encode("utf-16-le"))
        skips = []
        found = scan_path(
            tmp_path, recursive=True, on_skip=lambda p, r: skips.append((p, r))
        )
        assert found == []
        assert len(skips) == 1
        assert "evil16.txt" in skips[0][0]

    def test_scan_path_skips_symlinked_files(self, tmp_path: Path):
        # A symlink inside the tree must not pull in content from outside.
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.py"
        secret.write_text(f"evil = '{RLO}'", encoding="utf-8")
        repo = tmp_path / "repo"
        repo.mkdir()
        link = repo / "innocent.py"
        try:
            link.symlink_to(secret)
        except OSError:
            pytest.skip("symlinks not permitted on this platform")
        found = scan_path(repo, recursive=True)
        assert found == []
        assert not any("secret" in f.path for f in found)

    def test_scan_path_nonrecursive_skips_symlinked_files(self, tmp_path: Path):
        # Same guarantee for the non-recursive walk (regression for a
        # mutation-survival gap: only the recursive path was tested).
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.py"
        secret.write_text(f"evil = '{RLO}'", encoding="utf-8")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "ok.py").write_text("fine", encoding="utf-8")
        link = repo / "innocent.py"
        try:
            link.symlink_to(secret)
        except OSError:
            pytest.skip("symlinks not permitted on this platform")
        found = scan_path(repo, recursive=False)
        assert found == []
        assert not any("secret" in f.path for f in found)
