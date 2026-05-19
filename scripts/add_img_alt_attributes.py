import html
import os
import re
import sys
from urllib.parse import unquote, urlparse


DEFAULT_RELATIVE_TARGET = os.path.join("atelierdeconsultanta", "atelierdeconsultanta")
SKIPPED_DIRS = {".git", ".wrangler", "dist", "node_modules"}
MAX_ALT_LENGTH = 125
ACRONYMS = {
    "adr",
    "afir",
    "dr",
    "gdpr",
    "imm",
    "pnrr",
    "por",
    "soc",
}
GENERIC_NAMES = {
    "foto",
    "image",
    "img",
    "imagine",
    "photo",
    "picture",
    "placeholder",
    "untitled",
}

IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE | re.DOTALL)
ALT_RE = re.compile(r"\salt\s*=", re.IGNORECASE)
SRC_RE = re.compile(
    r"\ssrc\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'=<>]+))",
    re.IGNORECASE,
)


def resolve_target_dir():
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])

    requested_default = os.path.abspath(DEFAULT_RELATIVE_TARGET)
    if os.path.isdir(requested_default):
        return requested_default

    return os.getcwd()


def is_browser_saved_artifact(content):
    return "<!-- saved from url=" in content[:2048].lower()


def should_ignore_src(src):
    parsed_path = unquote(urlparse(src).path).replace("\\", "/").lower()
    filename = os.path.basename(parsed_path)
    extension = os.path.splitext(filename)[1]

    return extension == ".svg" or "/icons/" in f"/{parsed_path}"


def clean_alt_part(value):
    value = re.sub(r"[@_ -]?(?:1x|2x|3x)$", "", value, flags=re.IGNORECASE)
    value = re.sub(r"[-_](?:\d{2,5}x\d{2,5}|\d{2,5})$", "", value)
    value = re.sub(r"[-_]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def format_alt_text(value):
    if not value:
        return value

    words = value.strip().split()
    formatted = []
    for index, word in enumerate(words):
        normalized = word.lower()
        if normalized in ACRONYMS:
            formatted.append(normalized.upper())
        elif index == 0:
            formatted.append(normalized.capitalize())
        else:
            formatted.append(normalized)

    return " ".join(formatted)


def trim_alt(value):
    if len(value) <= MAX_ALT_LENGTH:
        return value

    trimmed = value[:MAX_ALT_LENGTH].rstrip()
    last_space = trimmed.rfind(" ")
    if last_space >= MAX_ALT_LENGTH * 0.7:
        trimmed = trimmed[:last_space].rstrip()
    return trimmed


def generate_alt(src):
    parsed_path = unquote(urlparse(src).path)
    filename = os.path.basename(parsed_path)
    name, _extension = os.path.splitext(filename)
    cleaned_name = clean_alt_part(name)

    if cleaned_name.lower() in GENERIC_NAMES:
        return ""

    description = format_alt_text(cleaned_name)

    if not description:
        return ""

    return trim_alt(description)


def add_alt_to_tag(tag, alt_text):
    escaped_alt = html.escape(alt_text, quote=True)
    insert = f' alt="{escaped_alt}"'

    if re.search(r"\s*/>$", tag):
        return re.sub(r"\s*/>$", f"{insert} />", tag, count=1)

    return re.sub(r">$", f"{insert}>", tag, count=1)


def process_html(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()

    if is_browser_saved_artifact(content):
        return 0

    modified = 0

    def replace_img(match):
        nonlocal modified

        tag = match.group(0)
        if ALT_RE.search(tag):
            return tag

        src_match = SRC_RE.search(tag)
        if not src_match:
            return tag

        src = src_match.group(1) or src_match.group(2) or src_match.group(3) or ""
        if should_ignore_src(src):
            return tag

        alt_text = generate_alt(src)
        if not alt_text:
            return tag

        modified += 1
        return add_alt_to_tag(tag, alt_text)

    updated = IMG_RE.sub(replace_img, content)
    if modified:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(updated)

    return modified


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

    total = 0
    touched_files = 0

    for file_path in walk_html_files(target_dir):
        modified = process_html(file_path)
        if modified:
            touched_files += 1
            total += modified
            print(f"{os.path.relpath(file_path, target_dir)}: {modified} imagini actualizate")

    print(f"Total imagini actualizate: {total} în {touched_files} fișiere")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
