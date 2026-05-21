const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const TODAY = new Date("2026-05-21T12:00:00Z");

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "dist",
  "node_modules",
  "reports",
]);

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function walkHtml(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkHtml(fullPath, files);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) {
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
    return parsed.origin === SITE && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
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

function lastmodForFile(filePath) {
  const mtime = fs.statSync(filePath).mtime;
  const safeDate = mtime > TODAY ? TODAY : mtime;
  return safeDate.toISOString().slice(0, 10);
}

function generate() {
  const urls = new Map();
  for (const filePath of walkHtml(ROOT)) {
    const html = fs.readFileSync(filePath, "utf8");
    if (hasNoindexOrRedirect(html)) continue;
    const canonical = extractCanonical(html);
    if (!canonical || !isInternalCanonical(canonical)) continue;
    const parsed = new URL(canonical);
    const normalized = parsed.pathname === "/" ? `${SITE}/` : canonical.replace(/\/$/, "");
    urls.set(normalized, {
      file: toPosix(path.relative(ROOT, filePath)),
      lastmod: lastmodForFile(filePath),
    });
  }

  const orderedUrls = [...urls.keys()].sort((a, b) => {
    const priorityDelta = priority(a) - priority(b);
    if (priorityDelta !== 0) return priorityDelta;
    return a.localeCompare(b);
  });

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${orderedUrls.map((url) => `  <url>\n    <loc>${url}</loc>\n    <lastmod>${urls.get(url).lastmod}</lastmod>\n  </url>`).join("\n")}
</urlset>
`;

  fs.writeFileSync(SITEMAP_PATH, xml, "utf8");
  console.log(`Generated sitemap.xml with ${orderedUrls.length} canonical URLs.`);
}

generate();
