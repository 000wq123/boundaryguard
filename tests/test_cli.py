"""CLI tests for boundaryguard (subprocess level)."""

import subprocess
import sys
from pathlib import Path

RLO = "\u202e"
RLI = "\u2067"
PDI = "\u2069"
ZWSP = "\u200b"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "boundaryguard", *args],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )


class TestInspect:
    def test_inspect_finds_rlo(self):
        r = run_cli("inspect", f"hello{RLO}")
        assert r.returncode == 1
        assert "U+202E" in r.stdout
        assert "RIGHT-TO-LEFT OVERRIDE" in r.stdout

    def test_inspect_clean(self):
        r = run_cli("inspect", "hello world")
        assert r.returncode == 0
        assert "no hazards" in r.stdout


class TestScan:
    def test_scan_file_reports_path_line_col(self, tmp_path: Path):
        f = tmp_path / "sample.py"
        f.write_text(f"a = 1\nb = '{RLI} {PDI}'\n", encoding="utf-8")
        r = run_cli("scan", str(f))
        assert r.returncode == 1
        assert "sample.py:2:" in r.stdout
        assert "RLI" in r.stdout
        assert "PDI" in r.stdout

    def test_scan_clean_exit_zero(self, tmp_path: Path):
        f = tmp_path / "clean.py"
        f.write_text("print('safe')\n", encoding="utf-8")
        r = run_cli("scan", str(f))
        assert r.returncode == 0
        assert "OK" in r.stdout


class TestCheck:
    def test_check_dirty_exit_one(self, tmp_path: Path):
        f = tmp_path / "dirty.txt"
        f.write_text(f"token = '{RLO}'", encoding="utf-8")
        r = run_cli("check", str(f))
        assert r.returncode == 1
        assert "hazard" in r.stdout.lower()

    def test_check_clean_exit_zero(self, tmp_path: Path):
        f = tmp_path / "clean.txt"
        f.write_text("nothing here", encoding="utf-8")
        r = run_cli("check", str(f))
        assert r.returncode == 0

    def test_check_missing_path_exit_two_both_modes(self):
        # A nonexistent path must NOT falsely report clean (exit 0).
        r1 = run_cli("check", "/definitely/does/not/exist")
        assert r1.returncode == 2
        r2 = run_cli("check", "--recursive", "/definitely/does/not/exist")
        assert r2.returncode == 2


class TestSanitize:
    def test_sanitize_to_output(self, tmp_path: Path):
        src = tmp_path / "in.txt"
        out = tmp_path / "out.txt"
        src.write_text(f"abc{RLO}def", encoding="utf-8")
        r = run_cli("sanitize", str(src), "-o", str(out))
        assert r.returncode == 0
        assert out.read_text(encoding="utf-8") == "abcdef"

    def test_sanitize_in_place(self, tmp_path: Path):
        src = tmp_path / "in.txt"
        src.write_text(f"a{ZWSP}", encoding="utf-8")
        run_cli("sanitize", str(src))
        assert src.read_text(encoding="utf-8") == "a"
