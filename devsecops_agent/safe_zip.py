"""Stage 1: safe intake of untrusted ZIP archives.

The archive is read entirely in memory. Nothing is written to disk and nothing
is ever executed, so path traversal cannot escape anywhere. Names are still
validated because they are reused when the corrected project is exported.

Fatal problems (malicious or abusive archives) raise UnsafeArchiveError.
Individually unsuitable entries (symlinks, encrypted or oversize files,
VCS/dependency directories, duplicates) are skipped and recorded in
`skipped`. Skipped entries are NOT present in the exported corrected ZIP.
"""
from __future__ import annotations

import io
import re
import stat
import zipfile
from dataclasses import dataclass, field


class UnsafeArchiveError(ValueError):
    """The archive is invalid or violates a safety limit and was rejected."""


@dataclass(frozen=True)
class Limits:
    max_archive_bytes: int = 25 * 1024 * 1024
    max_entries: int = 3000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 50 * 1024 * 1024
    max_ratio: int = 100
    ratio_min_bytes: int = 1024 * 1024


DEFAULT_LIMITS = Limits()

SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
)
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class SkippedEntry:
    path: str
    reason: str


@dataclass
class ExtractedProject:
    text_files: dict[str, str] = field(default_factory=dict)
    binary_files: dict[str, bytes] = field(default_factory=dict)
    skipped: list[SkippedEntry] = field(default_factory=list)
    stripped_root: str = ""


def _normalize(name: str) -> str:
    """Return a clean relative POSIX path or raise UnsafeArchiveError."""
    if "\x00" in name:
        raise UnsafeArchiveError("Rejected: entry name contains a NUL byte.")
    p = name.replace("\\", "/")
    if p.startswith("/") or _DRIVE.match(p):
        raise UnsafeArchiveError(f"Rejected: absolute path in archive ({name!r}).")
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if any(s == ".." for s in parts):
        raise UnsafeArchiveError(f"Rejected: path traversal in archive ({name!r}).")
    return "/".join(parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def extract_zip(
    data: bytes, limits: Limits = DEFAULT_LIMITS, strip_root: bool = True
) -> ExtractedProject:
    if len(data) > limits.max_archive_bytes:
        raise UnsafeArchiveError("Rejected: archive exceeds the size limit.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsafeArchiveError("Rejected: not a valid ZIP file.") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_entries:
            raise UnsafeArchiveError("Rejected: too many entries in archive.")

        # Pass 1: validate every name (fatal on traversal/absolute paths).
        entries: list[tuple[zipfile.ZipInfo, str]] = []
        for info in infos:
            norm = _normalize(info.filename)
            if info.is_dir() or not norm:
                continue
            entries.append((info, norm))

        stripped = ""
        if strip_root and entries:
            firsts = {n.split("/")[0] for _, n in entries}
            if len(firsts) == 1 and all("/" in n for _, n in entries):
                stripped = firsts.pop()
                entries = [(i, n[len(stripped) + 1 :]) for i, n in entries]

        project = ExtractedProject(stripped_root=stripped)
        seen: set[str] = set()
        total_read = 0

        # Pass 2: size/ratio checks and bounded reads.
        for info, path in entries:
            if path in seen:
                project.skipped.append(SkippedEntry(path, "duplicate entry"))
                continue
            seen.add(path)

            if any(part in SKIP_DIRS for part in path.split("/")):
                project.skipped.append(
                    SkippedEntry(path, "VCS or dependency directory")
                )
                continue
            if _is_symlink(info):
                project.skipped.append(SkippedEntry(path, "symlink"))
                continue
            if info.flag_bits & 0x1:
                project.skipped.append(SkippedEntry(path, "encrypted entry"))
                continue
            if (
                info.file_size >= limits.ratio_min_bytes
                and info.compress_size > 0
                and info.file_size / info.compress_size > limits.max_ratio
            ):
                raise UnsafeArchiveError(
                    "Rejected: suspicious compression ratio (possible ZIP bomb)."
                )
            if info.file_size > limits.max_file_bytes:
                project.skipped.append(SkippedEntry(path, "file too large"))
                continue

            with zf.open(info) as fh:
                content = fh.read(limits.max_file_bytes + 1)
            total_read += len(content)
            if total_read > limits.max_total_bytes:
                raise UnsafeArchiveError(
                    "Rejected: total uncompressed size exceeds the limit."
                )
            if len(content) > limits.max_file_bytes:
                project.skipped.append(
                    SkippedEntry(path, "file too large (header understated size)")
                )
                continue

            if b"\x00" in content[:8192]:
                project.binary_files[path] = content
                continue
            try:
                project.text_files[path] = content.decode("utf-8")
            except UnicodeDecodeError:
                project.binary_files[path] = content

    return project
