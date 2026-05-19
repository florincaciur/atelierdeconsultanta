import os
import re
import sys
from bs4 import BeautifulSoup


DEFAULT_RELATIVE_TARGET = os.path.join("atelierdeconsultanta", "atelierdeconsultanta")
SKIPPED_DIRS = {".git", ".wrangler", "dist", "node_modules"}
SKIPPED_SLUGS = {
    "404",
    "admin",
    "gdpr",
    "politica-de-confidentialitate",
    "termeni-si-conditii",
}

HUB_LINKS = {
    "fonduri-europene": ("/fonduri-europene/", "Fonduri europene"),
    "consultanta-fonduri-europene": (
        "/consultanta-fonduri-europene/",
        "Consultanță fonduri europene",
    ),
    "calendar-fonduri-europene": (
        "/calendar-fonduri-europene/",
        "Calendar fonduri europene",
    ),
    "consultanta-pnrr-digitalizare": (
        "/consultanta-pnrr-digitalizare/",
        "Consultanță PNRR și digitalizare",
    ),
    "start-up-nation": ("/start-up-nation/", "Start-Up Nation"),
}


def resolve_target_dir():
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])

    requested_default = os.path.abspath(DEFAULT_RELATIVE_TARGET)
    if os.path.isdir(requested_default):
        return requested_default

    return os.getcwd()


def normalize_relpath(path):
    return path.replace(os.sep, "/")


def is_browser_saved_artifact(content):
    return "<!-- saved from url=" in content[:2048].lower()


def is_noindex(soup):
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        http_equiv = (meta.get("http-equiv") or "").lower()
        content = (meta.get("content") or "").lower()
        if name in {"robots", "googlebot"} or http_equiv == "x-robots-tag":
            if "noindex" in {part.strip() for part in content.split(",")}:
                return True
    return False


def page_slug(file_path, target_dir, soup):
    canonical = soup.find(
        "link",
        rel=lambda value: value
        and "canonical" in (" ".join(value) if isinstance(value, list) else value).lower(),
    )
    href = canonical.get("href") if canonical else ""
    if href:
        path_part = re.sub(r"^https?://[^/]+", "", href).split("#", 1)[0].split("?", 1)[0]
        path_part = path_part.strip("/")
        if path_part.endswith(".html"):
            path_part = path_part[:-5]
        if path_part:
            return path_part

    rel_path = normalize_relpath(os.path.relpath(file_path, target_dir))
    lower = rel_path.lower()
    if lower == "index.html":
        return ""
    if lower.endswith("/index.html"):
        return rel_path[:-len("/index.html")]
    if lower.endswith(".html"):
        return rel_path[:-len(".html")]
    return rel_path


def should_link(current_slug, key):
    return not current_slug.startswith(key)


def related_links_html(current_slug):
    items = []
    for key, (href, text) in HUB_LINKS.items():
        if should_link(current_slug, key):
            items.append(f'    <li><a href="{href}">{text}</a></li>')

    if len(items) < 3:
        return ""

    return (
        "\n"
        '  <section class="vezi-si-section" aria-labelledby="vezi-si-title">\n'
        '    <h2 id="vezi-si-title">Vezi și</h2>\n'
        '    <ul class="vezi-si">\n'
        + "\n".join(items[:5])
        + "\n"
        "    </ul>\n"
        "  </section>\n"
    )


def insert_before_target(content, section_html):
    targets = [
        re.compile(r"(\r?\n)([ \t]*)</main>", re.IGNORECASE),
        re.compile(r"(\r?\n)([ \t]*)<footer\b", re.IGNORECASE),
        re.compile(r"(\r?\n)([ \t]*)</body>", re.IGNORECASE),
    ]

    for pattern in targets:
        match = pattern.search(content)
        if match:
            newline, indent = match.group(1), match.group(2)
            section = section_html.replace("\n", newline)
            return content[:match.start()] + section + content[match.start():]

    return None


def add_links(file_path, target_dir):
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()

    if is_browser_saved_artifact(content):
        return 0

    soup = BeautifulSoup(content, "html.parser")
    if not soup.find("body") or is_noindex(soup) or soup.select_one("ul.vezi-si"):
        return 0

    current_slug = page_slug(file_path, target_dir, soup)
    if current_slug in SKIPPED_SLUGS:
        return 0

    section_html = related_links_html(current_slug)
    if not section_html:
        return 0

    updated = insert_before_target(content, section_html)
    if updated is None:
        return 0

    with open(file_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(updated)

    return len(BeautifulSoup(section_html, "html.parser").select("ul.vezi-si a"))


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

    changed = []
    for file_path in walk_html_files(target_dir):
        added = add_links(file_path, target_dir)
        if added:
            changed.append((os.path.relpath(file_path, target_dir), added))

    for rel_path, added in changed:
        print(f"{rel_path}: adăugate {added} linkuri interne")

    print(f"Total fișiere modificate: {len(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
