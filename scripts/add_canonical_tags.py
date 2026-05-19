import os
import re
import sys


BASE_URL = "https://atelierdeconsultanta.ro"
DEFAULT_RELATIVE_TARGET = os.path.join("atelierdeconsultanta", "atelierdeconsultanta")
SKIPPED_DIRS = {".git", ".wrangler", "dist", "node_modules"}

CANONICAL_MAP = {
    "dr14.html": f"{BASE_URL}/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html",
    "autoconsum-publici.html": f"{BASE_URL}/autoconsum-public-fotovoltaice-institutii-publice.html",
}

HEAD_RE = re.compile(r"<head\b[^>]*>([\s\S]*?)</head>", re.IGNORECASE)
CANONICAL_RE = re.compile(
    r"<link\b(?=[^>]*\brel\s*=\s*([\"'])canonical\1)[^>]*>",
    re.IGNORECASE,
)


def normalize_relpath(path):
    return path.replace(os.sep, "/")


def resolve_target_dir():
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])

    requested_default = os.path.abspath(DEFAULT_RELATIVE_TARGET)
    if os.path.isdir(requested_default):
        return requested_default

    return os.getcwd()


def canonical_url(file_path, target_dir):
    rel_path = normalize_relpath(os.path.relpath(file_path, target_dir))
    basename = os.path.basename(file_path)

    if rel_path in CANONICAL_MAP:
        return CANONICAL_MAP[rel_path]
    if basename in CANONICAL_MAP:
        return CANONICAL_MAP[basename]

    if rel_path.lower() == "index.html":
        return f"{BASE_URL}/"

    if rel_path.lower().endswith("/index.html"):
        return f"{BASE_URL}/{rel_path[:-len('/index.html')]}/"

    if rel_path.lower().endswith(".html"):
        return f"{BASE_URL}/{rel_path[:-len('.html')]}/"

    return f"{BASE_URL}/{rel_path}/"


def is_browser_saved_artifact(html):
    return "<!-- saved from url=" in html[:2048].lower()


def has_head_canonical(html):
    head_match = HEAD_RE.search(html)
    if not head_match:
        return False
    return CANONICAL_RE.search(head_match.group(1)) is not None


def insert_canonical(html, canon):
    closing_head_re = re.compile(r"(\r?\n)([ \t]*)</head>", re.IGNORECASE)

    def replacement(match):
        newline = match.group(1)
        closing_indent = match.group(2)
        tag_indent = closing_indent or "  "
        return (
            f'{newline}{tag_indent}<link rel="canonical" href="{canon}" />'
            f"{newline}{closing_indent}</head>"
        )

    updated, count = closing_head_re.subn(replacement, html, count=1)
    return updated if count else None


def process_file(file_path, target_dir):
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        html = handle.read()

    if is_browser_saved_artifact(html):
        return "saved-artifact"
    if has_head_canonical(html):
        return "existing"
    if not HEAD_RE.search(html):
        return "missing-head"

    canon = canonical_url(file_path, target_dir)
    updated = insert_canonical(html, canon)
    if updated is None:
        return "missing-head"

    with open(file_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(updated)

    rel_path = os.path.relpath(file_path, target_dir)
    print(f"Added canonical to {rel_path}: {canon}")
    return "updated"


def walk_html_files(target_dir):
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [
            dirname
            for dirname in dirs
            if dirname not in SKIPPED_DIRS and not dirname.endswith("_files")
        ]

        for filename in files:
            if filename.lower().endswith(".html"):
                yield os.path.join(root, filename)


def main():
    target_dir = resolve_target_dir()
    if not os.path.isdir(target_dir):
        print(f"Folderul nu există sau nu este director: {target_dir}", file=sys.stderr)
        return 1

    counts = {
        "updated": 0,
        "existing": 0,
        "missing-head": 0,
        "saved-artifact": 0,
    }

    for file_path in walk_html_files(target_dir):
        status = process_file(file_path, target_dir)
        counts[status] += 1

    if counts["updated"] == 0:
        print("Nu au fost adăugate taguri canonical noi.")

    print(
        "Rezumat: "
        f"{counts['updated']} modificate, "
        f"{counts['existing']} aveau deja canonical în <head>, "
        f"{counts['missing-head']} fără <head>, "
        f"{counts['saved-artifact']} fișiere salvate din browser ignorate."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
