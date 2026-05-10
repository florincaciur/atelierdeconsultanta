#!/usr/bin/env python3
"""Find and repair Romanian mojibake in site text files.

The script is intentionally conservative: it edits only known mojibake
fragments or fragments that can be decoded cleanly from Windows-1252 back to
UTF-8. It also ensures HTML files contain a UTF-8 charset meta tag.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


TEXT_EXTENSIONS = {
    ".html",
    ".htm",
    ".md",
    ".txt",
    ".json",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".css",
    ".xml",
}

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "vendor",
}

BROKEN_MAP = {
    "\u00c4\u0192": "\u0103",
    "\u00c4\u201a": "\u0102",
    "\u00c3\u00a2": "\u00e2",
    "\u00c3\u201a": "\u00c2",
    "\u00c3\u00ae": "\u00ee",
    "\u00c3\u017d": "\u00ce",
    "\u00c8\u2122": "\u0219",
    "\u00c8\u02dc": "\u0218",
    "\u00c8\u203a": "\u021b",
    "\u00c8\u0161": "\u021a",
    "\u00c5\u0178": "\u0219",
    "\u00c5\u017e": "\u0218",
    "\u00c5\u00a3": "\u021b",
    "\u00c5\u00a2": "\u021a",
    "\u00e2\u20ac\u201c": "\u2013",
    "\u00e2\u20ac\u201d": "\u2014",
    "\u00e2\u20ac\u017e": "\u201e",
    "\u00e2\u20ac\u0153": "\u201c",
    "\u00e2\u20ac\u0165": "\u201d",
    "\u00e2\u20ac\u02dc": "\u2018",
    "\u00e2\u20ac\u2122": "\u2019",
    "\u00e2\u20ac\u00a6": "\u2026",
    "\u00e2\u2020\u2019": "\u2192",
    "\u00c2\u00a0": " ",
}

SUSPICIOUS_RE = re.compile(
    "|".join(
        [
            r"\u00c4",
            r"\u00c8",
            r"\u00c3",
            r"\u00c5",
            r"\u00e2\u20ac",
            r"\u00e2\u2020",
            r"\u00c2",
        ]
    )
)

AUTO_FRAGMENT_RE = re.compile(
    r"(?:"
    r"[\u00c3\u00c4\u00c5\u00c8]["
    r"\u00a0-\u00ff\u0100-\u017f\u0192\u02dc\u201a-\u201e"
    r"\u2020-\u2026\u2039-\u203a\u20ac\u2122"
    r"]"
    r"|"
    r"\u00e2["
    r"\u0080-\u00ff\u0100-\u017f\u02dc\u201a-\u201e"
    r"\u2020-\u2026\u20ac\u2122"
    r"]{1,2}"
    r")+"
)

RESIDUAL_NBSP_RE = re.compile(r"(?<=\S)\u00c2(?=\s)")
RESIDUAL_BEFORE_PUNCT_RE = re.compile(r"\u00c2(?=[,.;:!?])")
META_CHARSET_RE = re.compile(
    r"<meta\b[^>]*\bcharset\s*=\s*['\"]?\s*utf-8\b[^>]*>",
    re.IGNORECASE,
)
HEAD_OPEN_RE = re.compile(r"<head\b[^>]*>", re.IGNORECASE)


@dataclass
class FileResult:
    path: Path
    changed: bool = False
    mojibake_changed: bool = False
    meta_added: bool = False
    examples: list[tuple[str, str]] = field(default_factory=list)


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        yield path


def read_text(path: Path) -> str | None:
    data = path.read_bytes()
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("cp1252")
        except UnicodeDecodeError:
            return None


def preserve_newline_write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="")


def decode_mojibake_fragment(match: re.Match[str]) -> str:
    fragment = match.group(0)
    try:
        fixed = fragment.encode("cp1252").decode("utf-8")
    except UnicodeError:
        return fragment
    if fixed == fragment:
        return fragment
    if SUSPICIOUS_RE.search(fixed):
        return fragment
    return fixed


def repair_mojibake(text: str) -> str:
    fixed = text
    for _ in range(3):
        previous = fixed
        for broken, replacement in BROKEN_MAP.items():
            fixed = fixed.replace(broken, replacement)
        fixed = AUTO_FRAGMENT_RE.sub(decode_mojibake_fragment, fixed)
        for broken, replacement in BROKEN_MAP.items():
            fixed = fixed.replace(broken, replacement)
        fixed = RESIDUAL_NBSP_RE.sub("", fixed)
        fixed = RESIDUAL_BEFORE_PUNCT_RE.sub("", fixed)
        if fixed == previous:
            break
    return fixed


def ensure_meta_charset(text: str, path: Path) -> tuple[str, bool]:
    if path.suffix.lower() not in {".html", ".htm"}:
        return text, False
    if META_CHARSET_RE.search(text):
        return text, False
    match = HEAD_OPEN_RE.search(text)
    if not match:
        return text, False
    newline = "\r\n" if "\r\n" in text else "\n"
    insert = f"{newline}  <meta charset=\"UTF-8\">"
    return text[: match.end()] + insert + text[match.end() :], True


def changed_line_examples(before: str, after: str, limit: int = 4) -> list[tuple[str, str]]:
    examples: list[tuple[str, str]] = []
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        removed = " ".join(line.strip() for line in before_lines[i1:i2]).strip()
        added = " ".join(line.strip() for line in after_lines[j1:j2]).strip()
        if not removed and not added:
            continue
        examples.append((removed[:220], added[:220]))
        if len(examples) >= limit:
            break
    return examples


def process_file(path: Path) -> FileResult | None:
    original = read_text(path)
    if original is None:
        return None

    repaired = repair_mojibake(original)
    repaired, meta_added = ensure_meta_charset(repaired, path)

    changed = repaired != original
    return FileResult(
        path=path,
        changed=changed,
        mojibake_changed=repair_mojibake(original) != original,
        meta_added=meta_added,
        examples=changed_line_examples(original, repaired) if changed else [],
    )


def suspicious_lines(root: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in iter_text_files(root):
        text = read_text(path)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix()
        for line_no, line in enumerate(text.splitlines(), start=1):
            if SUSPICIOUS_RE.search(line):
                findings.append(
                    {
                        "file": rel,
                        "line": line_no,
                        "text": line.strip()[:240],
                    }
                )
    return findings


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Repair Romanian mojibake in site text files."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write repaired files. Without this flag, the script runs dry-run only.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON summary.",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root to scan. Defaults to the current directory.",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    files = sorted(iter_text_files(root))
    results = [result for path in files if (result := process_file(path)) is not None]
    changed = [result for result in results if result.changed]

    if args.apply:
        for result in changed:
            text = read_text(result.path)
            if text is None:
                continue
            repaired = repair_mojibake(text)
            repaired, _ = ensure_meta_charset(repaired, result.path)
            preserve_newline_write(result.path, repaired)

    summary = {
        "mode": "apply" if args.apply else "dry-run",
        "scanned_files": len(results),
        "changed_files": len(changed),
        "files": [
            {
                "file": result.path.relative_to(root).as_posix(),
                "mojibake_changed": result.mojibake_changed,
                "meta_added": result.meta_added,
                "examples": result.examples,
            }
            for result in changed
        ],
        "remaining_suspicious": suspicious_lines(root) if args.apply else [],
    }

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    print(f"Mode: {summary['mode']}")
    print(f"Scanned text files: {summary['scanned_files']}")
    print(f"Files that would change: {summary['changed_files']}")
    for item in summary["files"]:
        flags = []
        if item["mojibake_changed"]:
            flags.append("mojibake")
        if item["meta_added"]:
            flags.append("meta charset")
        print(f"- {item['file']} ({', '.join(flags)})")
        for before, after in item["examples"]:
            print(f"  before: {before}")
            print(f"  after:  {after}")

    if args.apply:
        print(f"Remaining suspicious lines: {len(summary['remaining_suspicious'])}")
        for finding in summary["remaining_suspicious"][:50]:
            print(f"- {finding['file']}:{finding['line']}: {finding['text']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
