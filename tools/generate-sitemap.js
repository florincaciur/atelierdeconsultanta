const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const TODAY = new Date();
const TODAY_ISO = TODAY.toISOString().slice(0, 10);
const {
  SITE,
  canonicalUrl,
  normalizeCanonicalPath
} = require("./schema-helpers");

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "dist",
  "node_modules",
  "reports",
]);

const DRAFT_PATH_PATTERN = /(^|\/)(?:draft|drafts|_draft|_drafts)(?:\/|$)/i;
const ALTERNATE_CANONICAL_PATHS = new Set([
  "/blog?post=blog-1",
]);

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function isDraftPath(filePath) {
  const relativePath = toPosix(path.relative(ROOT, filePath));
  const basename = path.posix.basename(relativePath).toLowerCase();
  return DRAFT_PATH_PATTERN.test(relativePath) || basename.startsWith("draft-") || basename.endsWith(".draft.html");
}

function walkHtml(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkHtml(fullPath, files);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html") && !isDraftPath(fullPath)) {
      files.push(fullPath);
    }
  }
  return files;
}

function hasNoindexOrRedirect(html) {
  return (
    /<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*\bnoindex\b/i.test(html) ||
    /<meta[^>]+http-equiv=["']refresh["']/i.test(html)
  );
}

function containsDynamicToken(value) {
  return value.includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_-]*/.test(value);
}

function patternToRegex(pattern) {
  const escaped = String(pattern)
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/(^|\/):[A-Za-z][A-Za-z0-9_]*/g, (match) => `${match.startsWith("/") ? "/" : ""}[^/]+`);
  return new RegExp(`^${escaped}$`);
}

function parseRedirectRules() {
  if (!fs.existsSync(REDIRECTS_PATH)) return [];
  return fs.readFileSync(REDIRECTS_PATH, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [source, destination, status = "302"] = line.split(/\s+/);
      return { source, destination, status };
    })
    .filter((rule) => /^3\d\d$/.test(rule.status))
    .map((rule) => ({
      ...rule,
      dynamic: containsDynamicToken(rule.source),
      regex: containsDynamicToken(rule.source) ? patternToRegex(rule.source) : null
    }));
}

function isRedirectSource(pathname, redirectRules) {
  return redirectRules.some((rule) => (
    rule.dynamic ? rule.regex.test(pathname) : rule.source === pathname
  ));
}

function extractCanonical(html) {
  const linkMatches = html.matchAll(/<link\b[^>]*>/gi);
  for (const match of linkMatches) {
    const tag = match[0];
    if (!/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i);
    if (href) return href[1].trim();
  }
  return null;
}

function isInternalCanonical(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin === SITE && !parsed.search && !parsed.hash && canonicalUrl(parsed.pathname) === url;
  } catch {
    return false;
  }
}

function canonicalRouteForFile(filePath) {
  const relativePath = toPosix(path.relative(ROOT, filePath));
  if (relativePath === "index.html") return "/";
  if (relativePath.endsWith("/index.html")) return `/${relativePath.replace(/\/index\.html$/i, "")}`;
  if (relativePath.endsWith(".html")) return `/${relativePath.replace(/\.html$/i, "")}`;
  return "";
}

function isAlternateCanonicalPath(pathname) {
  const clean = pathname === "/" ? "/" : pathname.replace(/\/+$/g, "");
  return ALTERNATE_CANONICAL_PATHS.has(clean);
}

function priority(url) {
  const pathname = new URL(url).pathname;
  if (pathname === "/") return 0;
  const primary = [
    "/consultanta-fonduri-europene",
    "/fonduri-europene",
    "/dr12-afir",
    "/dr14",
    "/start-up-nation-2026",
    "/digitalizare-imm",
    "/e-move",
    "/pro-infra",
    "/programul-tranzitie-justa",
    "/programul-tranzitie-justa-intrebari-documente",
    "/investitii-modernizarea-microintreprinderilor-apel-2",
    "/pocidif-21",
    "/apeluri-gal",
  ];
  const authority = [
    "/despre-faber",
    "/metodologie-verificare-eligibilitate",
    "/surse-oficiale-fonduri-europene",
    "/glosar-fonduri-europene",
    "/studii-de-caz-fonduri-europene",
    "/blog",
  ];
  if (primary.includes(pathname)) return 1;
  if (authority.includes(pathname)) return 2;
  if (pathname.includes("/intrebari/")) return 5;
  if (pathname.includes("/fonduri-europene-caen/")) return 6;
  return 4;
}

function parseSitemapLastmods(xml) {
  const lastmods = new Map();
  const pattern = /<url>\s*<loc>([^<]+)<\/loc>\s*<lastmod>([^<]+)<\/lastmod>\s*<\/url>/g;
  for (const match of xml.matchAll(pattern)) {
    lastmods.set(match[1].trim(), match[2].trim());
  }
  return lastmods;
}

function committedSitemapLastmods() {
  try {
    return parseSitemapLastmods(cp.execFileSync("git", ["show", "HEAD:sitemap.xml"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }));
  } catch {
    if (!fs.existsSync(SITEMAP_PATH)) return new Map();
    return parseSitemapLastmods(fs.readFileSync(SITEMAP_PATH, "utf8"));
  }
}

function dirtyTrackedFiles() {
  try {
    return new Set(
      cp.execFileSync("git", ["status", "--short", "--untracked-files=no"], {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      })
        .split(/\r?\n/)
        .map((line) => line.slice(3).trim().replace(/^"|"$/g, ""))
        .filter(Boolean)
        .map((file) => file.replace(/\\/g, "/"))
    );
  } catch {
    return new Set();
  }
}

function gitLastmodForFile(filePath) {
  try {
    const value = cp.execFileSync("git", ["log", "-1", "--format=%cs", "--", toPosix(path.relative(ROOT, filePath))], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return value || TODAY_ISO;
  } catch {
    const mtime = fs.statSync(filePath).mtime;
    const safeDate = mtime > TODAY ? TODAY : mtime;
    return safeDate.toISOString().slice(0, 10);
  }
}

function lastmodForFile(filePath, url, previousLastmods, dirtyFiles) {
  const relativePath = toPosix(path.relative(ROOT, filePath));
  if (!dirtyFiles.has(relativePath) && previousLastmods.has(url)) {
    return previousLastmods.get(url);
  }
  if (dirtyFiles.has(relativePath)) return TODAY_ISO;
  const mtime = fs.statSync(filePath).mtime;
  const safeDate = mtime > TODAY ? TODAY : mtime;
  const gitDate = gitLastmodForFile(filePath);
  return gitDate > TODAY_ISO ? safeDate.toISOString().slice(0, 10) : gitDate;
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function generate() {
  const urls = new Map();
  const previousLastmods = committedSitemapLastmods();
  const dirtyFiles = dirtyTrackedFiles();
  const redirectRules = parseRedirectRules();
  for (const filePath of walkHtml(ROOT)) {
    const html = fs.readFileSync(filePath, "utf8");
    if (hasNoindexOrRedirect(html)) continue;
    const canonical = extractCanonical(html);
    if (!canonical || !isInternalCanonical(canonical)) continue;
    const parsed = new URL(canonical);
    const canonicalPath = normalizeCanonicalPath(parsed.pathname);
    const normalized = canonicalUrl(canonicalPath);
    if (isAlternateCanonicalPath(canonicalPath)) continue;
    if (isRedirectSource(canonicalPath, redirectRules)) continue;
    if (canonicalPath !== canonicalRouteForFile(filePath)) continue;
    urls.set(normalized, {
      file: toPosix(path.relative(ROOT, filePath)),
      lastmod: lastmodForFile(filePath, normalized, previousLastmods, dirtyFiles),
    });
  }

  const orderedUrls = [...urls.keys()].sort((a, b) => {
    const priorityDelta = priority(a) - priority(b);
    if (priorityDelta !== 0) return priorityDelta;
    return a.localeCompare(b);
  });

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${orderedUrls.map((url) => `  <url>\n    <loc>${escapeXml(url)}</loc>\n    <lastmod>${escapeXml(urls.get(url).lastmod)}</lastmod>\n  </url>`).join("\n")}
</urlset>
`;

  fs.writeFileSync(SITEMAP_PATH, xml, "utf8");
  console.log(`Generated sitemap.xml with ${orderedUrls.length} canonical URLs.`);
}

generate();
