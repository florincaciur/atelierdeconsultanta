#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");

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

function fail(message, details = []) {
  console.error(message);
  for (const detail of details.slice(0, 20)) console.error(`- ${detail}`);
  if (details.length > 20) console.error(`- ...and ${details.length - 20} more`);
  process.exit(1);
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

function extractCanonical(html) {
  const linkMatches = html.matchAll(/<link\b[^>]*>/gi);
  for (const match of linkMatches) {
    const tag = match[0];
    if (!/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i);
    if (href) return href[1].trim();
  }
  return "";
}

function isInternalCanonical(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin === SITE && !parsed.search && !parsed.hash && !parsed.pathname.endsWith("/index.html") && !parsed.pathname.endsWith(".html");
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

function normalizeUrl(url) {
  const parsed = new URL(url);
  return parsed.pathname === "/" ? `${SITE}/` : `${SITE}${parsed.pathname.replace(/\/$/, "")}`;
}

function sitemapUrls() {
  if (!fs.existsSync(SITEMAP_PATH)) fail("sitemap.xml is missing.");
  const xml = fs.readFileSync(SITEMAP_PATH, "utf8");
  const urls = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
  if (!urls.length) fail("sitemap.xml has no <loc> entries.");
  return urls;
}

function expectedUrls() {
  const urls = new Set();
  for (const filePath of walkHtml(ROOT)) {
    const html = fs.readFileSync(filePath, "utf8");
    if (hasNoindexOrRedirect(html)) continue;
    const canonical = extractCanonical(html);
    if (!canonical || !isInternalCanonical(canonical)) continue;
    const normalized = normalizeUrl(canonical);
    const canonicalPath = new URL(normalized).pathname;
    if (isAlternateCanonicalPath(canonicalPath)) continue;
    if (canonicalPath !== canonicalRouteForFile(filePath)) continue;
    urls.add(normalized);
  }
  return urls;
}

const actualList = sitemapUrls();
const actual = new Set(actualList);
const expected = expectedUrls();

const duplicates = actualList.filter((url, index) => actualList.indexOf(url) !== index);
if (duplicates.length) fail("sitemap.xml contains duplicate URLs.", duplicates);

const invalidUrls = actualList.filter((url) => !isInternalCanonical(url));
if (invalidUrls.length) fail("sitemap.xml contains invalid canonical URLs.", invalidUrls);

const missing = [...expected].filter((url) => !actual.has(url)).sort();
const extra = [...actual].filter((url) => !expected.has(url)).sort();
if (missing.length || extra.length) {
  fail("sitemap.xml does not match indexable canonical HTML pages.", [
    ...missing.map((url) => `missing: ${url}`),
    ...extra.map((url) => `extra: ${url}`),
  ]);
}

console.log(`Verified sitemap.xml with ${actual.size} canonical URLs.`);
