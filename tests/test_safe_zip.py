import io
import stat
import zipfile

import pytest

from devsecops_agent.safe_zip import Limits, UnsafeArchiveError, extract_zip


def make_zip(entries, compress=zipfile.ZIP_STORED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for name, content in entries:
            z.writestr(name, content)
    return buf.getvalue()


def test_extracts_text_and_binary():
    data = make_zip([("app.py", "print('hi')\n"), ("logo.bin", b"\x00\x01\x02")])
    project = extract_zip(data)
    assert project.text_files == {"app.py": "print('hi')\n"}
    assert project.binary_files == {"logo.bin": b"\x00\x01\x02"}
    assert project.skipped == []


@pytest.mark.parametrize(
    "name", ["../evil.py", "a/../../evil.py", "/etc/passwd", "C:/x.py", "..\\evil.py"]
)
def test_rejects_traversal_and_absolute_paths(name):
    with pytest.raises(UnsafeArchiveError):
        extract_zip(make_zip([(name, "x")]))


def test_skips_symlinks():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ok.py", "x = 1\n")
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
    project = extract_zip(buf.getvalue())
    assert "link" not in project.text_files
    assert [s.path for s in project.skipped] == ["link"]
    assert project.skipped[0].reason == "symlink"


def test_rejects_non_zip():
    with pytest.raises(UnsafeArchiveError):
        extract_zip(b"this is not a zip")


def test_rejects_too_many_entries():
    data = make_zip([(f"f{i}.txt", "x") for i in range(5)])
    with pytest.raises(UnsafeArchiveError):
        extract_zip(data, Limits(max_entries=3))


def test_rejects_oversize_archive():
    with pytest.raises(UnsafeArchiveError):
        extract_zip(make_zip([("a.txt", "x" * 100)]), Limits(max_archive_bytes=10))


def test_rejects_total_size_exceeded():
    data = make_zip([("a.txt", "x" * 600), ("b.txt", "y" * 600)])
    with pytest.raises(UnsafeArchiveError):
        extract_zip(data, Limits(max_total_bytes=1000))


def test_rejects_zip_bomb_ratio():
    data = make_zip(
        [("zeros.txt", b"\x00" * (5 * 1024 * 1024))], compress=zipfile.ZIP_DEFLATED
    )
    with pytest.raises(UnsafeArchiveError):
        extract_zip(data)


def test_skips_oversize_file():
    data = make_zip([("big.txt", "x" * 50), ("small.txt", "y")])
    project = extract_zip(data, Limits(max_file_bytes=10))
    assert list(project.text_files) == ["small.txt"]
    assert project.skipped[0].path == "big.txt"


def test_skips_vcs_and_dependency_dirs():
    data = make_zip([(".git/config", "x"), ("node_modules/a/b.js", "x"), ("main.py", "x")])
    project = extract_zip(data)
    assert list(project.text_files) == ["main.py"]
    assert {s.path for s in project.skipped} == {".git/config", "node_modules/a/b.js"}


def test_strips_single_common_root():
    data = make_zip([("repo-main/app.py", "a"), ("repo-main/src/b.py", "b")])
    project = extract_zip(data)
    assert set(project.text_files) == {"app.py", "src/b.py"}
    assert project.stripped_root == "repo-main"


def test_keeps_root_when_multiple_top_level_entries():
    data = make_zip([("a/x.py", "a"), ("b/y.py", "b")])
    project = extract_zip(data)
    assert set(project.text_files) == {"a/x.py", "b/y.py"}
    assert project.stripped_root == ""


def test_non_utf8_treated_as_binary():
    data = make_zip([("latin.txt", b"caf\xe9")])
    project = extract_zip(data)
    assert "latin.txt" in project.binary_files
    assert project.text_files == {}
