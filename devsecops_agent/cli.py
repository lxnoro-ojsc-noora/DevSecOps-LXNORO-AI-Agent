"""Command-line scan of a directory with the deterministic scanner (static; nothing executed)."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .models import count_by_severity
from .safe_zip import SKIP_DIRS
from .scanners import scan_project

MAX_FILE_BYTES = 2 * 1024 * 1024


def collect(root: str, excludes: list[str]) -> dict[str, str]:
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                continue
            if any(rel == e or rel.startswith(e.rstrip("/") + "/") for e in excludes):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
                if b"\x00" in data[:8192]:
                    continue
                files[rel] = data.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
    return files


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Static security scan (nothing is executed).")
    parser.add_argument("path")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--out")
    parser.add_argument("--fail-on-high", action="store_true")
    args = parser.parse_args(argv)
    scan = scan_project(collect(args.path, args.exclude))
    counts = count_by_severity(scan.findings)
    summary = {
        "scanned_at": scan.scanned_at,
        "files_scanned": scan.files_scanned,
        "counts": counts,
        "checks": [{"name": c.name, "status": c.status} for c in scan.checks],
        "findings": [
            {"rule": f.rule_id, "severity": f.severity, "location": f"{f.path}:{f.line}", "evidence": f.evidence}
            for f in scan.findings
        ],
    }
    text = json.dumps(summary, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(f"files={scan.files_scanned} findings={len(scan.findings)} " + " ".join(f"{k}={v}" for k, v in counts.items()))
    if args.fail_on_high and (counts["critical"] or counts["high"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
