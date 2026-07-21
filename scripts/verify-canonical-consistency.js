#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { sitemapUrls: readSitemapUrls } = require("../tools/sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";

function read(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

function sitemapUrls() {
  return readSitemapUrls(ROOT);
}

function routeForUrl(url) {
  const pathname = new URL(url).pathname;
  return pathname === "/" ? "" : decodeURIComponent(pathname.replace(/^\/+|\/+$/g, ""));
}

function htmlForUrl(url) {
  const route = routeForUrl(url);
  const candidates = route
    ? [`${route}/index.html`, `${route}.html`]
    : ["index.html"];
  return candidates.find((file) => fs.existsSync(path.join(ROOT, file))) || null;
}

function tagValues(html, tagName, attribute, expected) {
  const values = [];
  const tagPattern = new RegExp(`<${tagName}\\b[^>]*>`, "gi");
  for (const match of html.matchAll(tagPattern)) {
    const tag = match[0];
    const attr = tag.match(new RegExp(`\\b${attribute}=["']([^"']+)["']`, "i"));
    if (!attr || !expected(attr[1])) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i);
    const content = tag.match(/\bcontent=["']([^"']+)["']/i);
    values.push((href?.[1] || content?.[1] || "").trim());
  }
  return values;
}

function canonicalValues(html) {
  return tagValues(html, "link", "rel", (value) => value.toLowerCase().split(/\s+/).includes("canonical"));
}

function ogUrlValues(html) {
  return tagValues(html, "meta", "property", (value) => value.toLowerCase() === "og:url");
}

function parseRedirectSources() {
  const sources = new Set();
  if (!fs.existsSync(path.join(ROOT, "_redirects"))) return sources;
  for (const raw of read("_redirects").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [source, , status = "302"] = line.split(/\s+/);
    if (/^3\d\d$/.test(status) && !source.includes(":") && !source.includes("*")) {
      sources.add(source === "/" ? "/" : source.replace(/\/+$/, ""));
    }
  }
  return sources;
}

const errors = [];
const urls = sitemapUrls();
const sitemapSet = new Set(urls);
const redirectSources = parseRedirectSources();

for (const url of urls) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    errors.push(`${url}: URL invalid în sitemap`);
    continue;
  }
  if (parsed.protocol !== "https:" || parsed.hostname !== "atelierdeconsultanta.ro" || parsed.search || parsed.hash) {
    errors.push(`${url}: URL-ul din sitemap nu este canonical HTTPS curat`);
  }
  const file = htmlForUrl(url);
  if (!file) {
    errors.push(`${url}: nu există fișier HTML (destinație 404 locală)`);
    continue;
  }
  const html = read(file);
  if (/\bnoindex\b/i.test((html.match(/<meta[^>]+name=["']robots["'][^>]*>/i) || [""])[0])) {
    errors.push(`${url}: pagina din sitemap este noindex`);
  }
  const canonicals = canonicalValues(html);
  if (canonicals.length !== 1) {
    errors.push(`${url}: canonicale găsite ${canonicals.length}, necesar exact 1`);
    continue;
  }
  const canonical = canonicals[0];
  let canonicalUrl;
  try {
    canonicalUrl = new URL(canonical);
  } catch {
    errors.push(`${url}: canonical invalid: ${canonical}`);
    continue;
  }
  if (canonicalUrl.protocol !== "https:" || canonicalUrl.hostname !== "atelierdeconsultanta.ro") {
    errors.push(`${url}: canonicalul trebuie să fie HTTPS pe atelierdeconsultanta.ro`);
  }
  if (canonical !== url) errors.push(`${url}: canonical diferit: ${canonical}`);
  if (!sitemapSet.has(canonical)) errors.push(`${url}: canonicalul nu există în sitemap`);
  if (!htmlForUrl(canonical)) errors.push(`${url}: canonicalul indică o destinație locală inexistentă`);
  const canonicalPath = canonicalUrl.pathname === "/" ? "/" : canonicalUrl.pathname.replace(/\/+$/, "");
  if (redirectSources.has(canonicalPath)) errors.push(`${url}: canonicalul este sursă de redirect`);
  const ogUrls = ogUrlValues(html);
  if (ogUrls.length !== 1) errors.push(`${url}: og:url găsite ${ogUrls.length}, necesar exact 1`);
  else if (ogUrls[0] !== canonical) errors.push(`${url}: og:url diferă de canonical (${ogUrls[0]})`);
}

if (errors.length) {
  console.error(`Canonical consistency failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Canonical consistency PASS: ${urls.length} indexable pages.`);
