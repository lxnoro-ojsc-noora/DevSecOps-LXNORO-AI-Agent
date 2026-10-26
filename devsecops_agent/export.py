"""Stage 5: corrected-project ZIP export and change summaries."""
from __future__ import annotations

import difflib
import io
import zipfile

FIXED_DATE = (2026, 1, 1, 0, 0, 0)


def build_zip(text_files: dict[str, str], binary_files: dict[str, bytes]) -> bytes:
    """Zip corrected text files plus untouched binaries. Entries skipped at intake are absent."""
    entries = {path: content.encode("utf-8") for path, content in text_files.items()}
    entries.update(binary_files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(entries):
            info = zipfile.ZipInfo(path, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, entries[path])
    return buf.getvalue()


def changed_files(original: dict[str, str], corrected: dict[str, str]) -> dict[str, str]:
    return {p: c for p, c in corrected.items() if original.get(p) != c}


def diff_summary(original: dict[str, str], corrected: dict[str, str]) -> list[tuple[str, str]]:
    out = []
    for path in sorted(changed_files(original, corrected)):
        old = original.get(path, "").split("\n")
        new = corrected[path].split("\n")
        out.append((path, "\n".join(difflib.unified_diff(old, new, f"a/{path}", f"b/{path}", lineterm="", n=2))))
    return out
