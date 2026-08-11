"""CLI tests for boundaryguard (subprocess level)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

RLO = "\u202e"
RLI = "\u2067"
PDI = "\u2069"
ZWSP = "\u200b"

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "boundaryguard", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=timeout,
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

    def test_check_empty_path_exit_two(self):
        # "" must not silently resolve to Path(".") and scan the CWD.
        r = run_cli("check", "")
        assert r.returncode == 2
        assert "empty path" in r.stderr

    def test_check_non_utf8_exit_two_fail_closed(self, tmp_path: Path):
        # A UTF-16 file with a real RLO is a hazard; "could not scan" must
        # never become exit 0 "clean".
        f = tmp_path / "evil16.txt"
        f.write_bytes(b"\xff\xfe" + f"HELLO{RLO}SECRET".encode("utf-16-le"))
        r = run_cli("check", str(f))
        assert r.returncode == 2
        assert "could not be scanned" in r.stderr

    def test_check_recursive_fifo_exit_two_no_hang(self, tmp_path: Path):
        # A FIFO in the tree must not hang the scanner; it must be reported
        # and force exit 2 (fail-closed).
        try:
            os.mkfifo(tmp_path / "pipe")
        except (AttributeError, OSError):
            pytest.skip("mkfifo not available")
        (tmp_path / "clean.py").write_text("print(1)\n", encoding="utf-8")
        r = run_cli("check", "--recursive", str(tmp_path), timeout=10)
        assert r.returncode == 2
        assert "could not be scanned" in r.stderr


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

    def test_sanitize_in_place_preserves_permissions(self, tmp_path: Path):
        src = tmp_path / "in.txt"
        src.write_text(f"a{RLO}b", encoding="utf-8")
        src.chmod(0o640)
        run_cli("sanitize", str(src))
        assert src.read_text(encoding="utf-8") == "ab"
        assert (src.stat().st_mode & 0o777) == 0o640

    def test_sanitize_samefile_output_is_in_place(self, tmp_path: Path):
        # `-o` spelled as a different path to the same inode is still an
        # in-place edit: permissions must be preserved, not reset.
        src = tmp_path / "in.txt"
        src.write_text(f"a{RLO}b", encoding="utf-8")
        src.chmod(0o640)
        r = run_cli("sanitize", str(src), "-o", str(src.resolve()))
        assert r.returncode == 0
        assert src.read_text(encoding="utf-8") == "ab"
        assert (src.stat().st_mode & 0o777) == 0o640

    def test_sanitize_refuses_symlink_input(self, tmp_path: Path):
        # In-place sanitize of a symlink would modify the target outside
        # the intended location — refuse instead.
        target = tmp_path / "target.txt"
        target.write_text(f"secret{RLO}content", encoding="utf-8")
        link = tmp_path / "evil_link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("symlinks not permitted on this platform")
        r = run_cli("sanitize", str(link))
        assert r.returncode == 2
        assert "symlink" in r.stderr
        assert target.read_text(encoding="utf-8") == f"secret{RLO}content"  # untouched

    def test_sanitize_refuses_symlink_output(self, tmp_path: Path):
        src = tmp_path / "in.txt"
        src.write_text(f"a{RLO}b", encoding="utf-8")
        target = tmp_path / "victim.txt"
        target.write_text("do not touch", encoding="utf-8")
        out_link = tmp_path / "out.txt"
        try:
            out_link.symlink_to(target)
        except OSError:
            pytest.skip("symlinks not permitted on this platform")
        r = run_cli("sanitize", str(src), "-o", str(out_link))
        assert r.returncode == 2
        assert "symlink" in r.stderr
        assert target.read_text(encoding="utf-8") == "do not touch"

    def test_sanitize_non_utf8_nothing_written(self, tmp_path: Path):
        src = tmp_path / "evil16.txt"
        src.write_bytes(b"\xff\xfe" + f"A{RLO}B".encode("utf-16-le"))
        out = tmp_path / "out.txt"
        r = run_cli("sanitize", str(src), "-o", str(out))
        assert r.returncode == 2
        assert not out.exists()  # nothing partially written


class TestFailClosedPrecedence:
    def test_check_findings_and_skips_exit_two(self, tmp_path: Path):
        # Hazards found AND a file that could not be scanned -> exit 2
        # (fail-closed: the result is incomplete, so it is not a clean pass
        # and not a plain "findings" verdict either).
        dirty = tmp_path / "dirty.py"
        dirty.write_text(f"x = '{RLO}'\n", encoding="utf-8")
        nonutf8 = tmp_path / "evil16.txt"
        nonutf8.write_bytes(b"\xff\xfe" + f"A{RLO}B".encode("utf-16-le"))
        r = run_cli("check", "--recursive", str(tmp_path))
        assert r.returncode == 2
        assert "could not be scanned" in r.stderr
        assert "hazard" in r.stdout.lower()

    def test_sanitize_output_respects_umask(self, tmp_path: Path):
        # New output files must be umask-respecting (not mkstemp's 0600).
        import os

        src = tmp_path / "in.txt"
        src.write_text(f"a{RLO}b", encoding="utf-8")
        out = tmp_path / "out.txt"
        old_umask = os.umask(0o022)
        try:
            r = run_cli("sanitize", str(src), "-o", str(out))
        finally:
            os.umask(old_umask)
        assert r.returncode == 0
        assert (out.stat().st_mode & 0o777) == 0o644


class TestBrokenPipe:
    def test_scan_broken_pipe_no_traceback(self, tmp_path: Path):
        # `boundaryguard scan | head -1` must die quietly, not traceback.
        f = tmp_path / "many.py"
        f.write_text("".join(f"x = '{RLO}'\n" for _ in range(500)), encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, "-m", "boundaryguard", "scan", str(f)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO_ROOT,
        )
        assert proc.stdout is not None
        proc.stdout.readline()  # read one line, then close the pipe
        proc.stdout.close()
        proc.wait(timeout=15)
        err = proc.stderr.read() if proc.stderr else ""
        assert "Traceback" not in err
        assert "BrokenPipeError" not in err
