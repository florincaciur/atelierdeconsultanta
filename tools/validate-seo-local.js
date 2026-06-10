#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const IMPORTANT_REDIRECTS = new Map([
  ["/calculator-so-afir", "/calculator-soc"],
  ["/dr12-afir-tineri-fermieri", "/dr12-afir"],
  ["/startup-nation-2026-conditii", "/start-up-nation-2026-conditii"],
  ["/dr12-afir.html", "/dr12-afir"]
]);
const IMPORTANT_CANONICAL_ROUTES = [
  "/fonduri-europene-bucuresti",
  "/consultanta-fonduri-europene-bucuresti",
  "/consultanta-fonduri-europene",
  "/fonduri-europene",
  "/pnrr",
  "/afir",
  "/consultanta-afir",
  "/cat-costa-consultanta-fonduri-europene",
  "/cum-alegi-consultant-fonduri-europene",
  "/pro-infra",
  "/intrebari/ce-documente-sunt-necesare-pentru-dr12",
  "/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene",
  "/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm",
  "/fonduri-europene-caen/0111-culturi-cereale",
  "/fonduri-europene-caen/4321-instalatii-electrice",
  "/fonduri-europene-caen/5610-restaurante",
  "/fonduri-europene-caen/6201-dezvoltare-software"
];

function read(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function parseRedirects() {
  return read("_redirects")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [from, to, status = "301"] = line.split(/\s+/);
      return { from, to, status: Number(status) };
    });
}

function parseSitemap() {
  return [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
}

function parseHeaders() {
  const rules = [];
  let current = null;
  for (const line of read("_headers").split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      current = { pattern: line.trim(), headers: {} };
      rules.push(current);
      continue;
    }
    if (!current) continue;
    const [name, ...rest] = line.trim().split(":");
    current.headers[name.toLowerCase()] = rest.join(":").trim();
  }
  return rules;
}

function sourceFilesForPathname(pathname) {
  if (pathname === "/") return ["index.html"];
  const clean = pathname.replace(/^\/+/, "");
  return [`${clean}.html`, `${clean}/index.html`].filter((file) => fs.existsSync(path.join(ROOT, file)));
}

function extractCanonical(html) {
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0];
    if (!/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) continue;
    return (tag.match(/\bhref=["']([^"']+)["']/i) || [])[1] || "";
  }
  return "";
}

function extractRobots(html) {
  for (const match of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = match[0];
    if (!/\bname=["']robots["']/i.test(tag)) continue;
    return (tag.match(/\bcontent=["']([^"']+)["']/i) || [])[1] || "";
  }
  return "";
}

function normalizePath(raw) {
  try {
    const url = new URL(raw, SITE);
    return url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/g, "");
  } catch {
    return "";
  }
}

function redirectFor(pathname, redirects) {
  return redirects.find((redirect) => redirect.from === pathname);
}

function traceRedirect(pathname, redirects) {
  const chain = [];
  let current = pathname;
  const seen = new Set();
  for (let i = 0; i < 8; i += 1) {
    if (seen.has(current)) return { chain, loop: true, final: current };
    seen.add(current);
    const redirect = redirectFor(current, redirects);
    if (!redirect) return { chain, loop: false, final: current };
    chain.push(redirect);
    current = normalizePath(redirect.to);
  }
  return { chain, loop: true, final: current };
}

function walkHtml(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if ([".git", "node_modules", "dist", "reports"].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkHtml(full, files);
    else if (entry.isFile() && entry.name.endsWith(".html")) files.push(toPosix(path.relative(ROOT, full)));
  }
  return files;
}

function internalLinks(file, html) {
  const links = [];
  for (const match of html.matchAll(/\b(?:href|action)=["']([^"']+)["']/gi)) {
    const value = match[1].replace(/&amp;/g, "&");
    if (/^(?:mailto:|tel:|sms:|javascript:|data:|blob:|#)/i.test(value)) continue;
    try {
      const url = new URL(value, SITE);
      if (url.hostname !== "atelierdeconsultanta.ro") continue;
      links.push({ file, value, pathname: url.pathname, search: url.search });
    } catch {
      // Ignore malformed external snippets; other audits cover HTML validity.
    }
  }
  return links;
}

const problems = [];
const redirects = parseRedirects();
const headers = parseHeaders();
const redirectSources = new Set(redirects.filter((item) => item.status >= 300 && item.status < 400).map((item) => item.from));
const sitemapUrls = parseSitemap();
const sitemapSet = new Set(sitemapUrls);

for (const url of sitemapUrls) {
  const parsed = new URL(url);
  if (parsed.origin !== SITE) problems.push(`Non-canonical host in sitemap: ${url}`);
  if (parsed.search || parsed.hash) problems.push(`Query/hash in sitemap: ${url}`);
  if (parsed.pathname !== "/" && parsed.pathname.endsWith("/")) problems.push(`Trailing slash in sitemap: ${url}`);
  if (parsed.pathname.endsWith(".html")) problems.push(`HTML route in sitemap: ${url}`);
  if (redirectSources.has(parsed.pathname)) problems.push(`Redirected URL in sitemap: ${url}`);

  const sources = sourceFilesForPathname(parsed.pathname);
  const matching = sources.find((file) => {
    const html = read(file);
    return extractCanonical(html) === url && !/\bnoindex\b/i.test(extractRobots(html));
  });
  if (!matching) {
    problems.push(`No indexable self-canonical source for sitemap URL: ${url}`);
    continue;
  }

  const html = read(matching);
  const canonicalPath = normalizePath(extractCanonical(html));
  if (redirectSources.has(canonicalPath)) problems.push(`Canonical points to redirect: ${matching} -> ${canonicalPath}`);
}

for (const [from, expected] of IMPORTANT_REDIRECTS) {
  const result = traceRedirect(from, redirects);
  if (result.loop) problems.push(`Redirect loop for ${from}`);
  if (!result.chain.length) problems.push(`Missing important redirect: ${from}`);
  if (result.chain[0] && result.chain[0].status !== 301) problems.push(`Important redirect is not 301: ${from}`);
  if (result.final !== expected) problems.push(`Redirect chain not direct to final: ${from} -> ${result.final}, expected ${expected}`);
}

for (const route of IMPORTANT_CANONICAL_ROUTES) {
  const url = `${SITE}${route}`;
  const sources = sourceFilesForPathname(route);
  if (redirectSources.has(route)) problems.push(`Important canonical route is configured as redirect: ${route}`);
  if (!sitemapSet.has(url)) problems.push(`Important canonical route missing from sitemap: ${url}`);
  const matching = sources.find((file) => {
    const html = read(file);
    return extractCanonical(html) === url && !/\bnoindex\b/i.test(extractRobots(html));
  });
  if (!matching) problems.push(`Important canonical route is not self-canonical indexable HTML: ${route}`);
}

if (sitemapUrls.some((url) => /official-guides\.json/i.test(url))) {
  problems.push("official-guides.json must not appear in sitemap.");
}
const officialGuideHeaders = headers.find((rule) => rule.pattern === "/official-guides.json");
if (!officialGuideHeaders) {
  problems.push("Missing _headers rule for /official-guides.json.");
} else {
  const robots = officialGuideHeaders.headers["x-robots-tag"] || "";
  const contentType = officialGuideHeaders.headers["content-type"] || "";
  if (!/\bnoindex\b/i.test(robots) || !/\bfollow\b/i.test(robots)) {
    problems.push("/official-guides.json must send X-Robots-Tag: noindex, follow.");
  }
  if (!/^application\/json\b/i.test(contentType)) {
    problems.push("/official-guides.json must declare application/json Content-Type in _headers.");
  }
}
JSON.parse(read("official-guides.json"));

const allLinks = walkHtml(ROOT).flatMap((file) => internalLinks(file, read(file)));
for (const link of allLinks) {
  if (/^http:\/\/(?:www\.)?atelierdeconsultanta\.ro/i.test(link.value)) {
    problems.push(`Internal HTTP link: ${link.file} -> ${link.value}`);
  }
  if (link.search && /(?:^|[?&])s=|post=blog-\d+/i.test(link.search)) {
    problems.push(`Internal query link: ${link.file} -> ${link.value}`);
  }
  if (link.pathname.endsWith(".html")) {
    problems.push(`Internal .html link: ${link.file} -> ${link.value}`);
  }
  if (redirectSources.has(link.pathname)) {
    problems.push(`Internal link to redirected route: ${link.file} -> ${link.value}`);
  }
}

const structuredDataText = walkHtml(ROOT).map(read).join("\n");
if (/SearchAction/i.test(structuredDataText)) problems.push("SearchAction remains in public HTML.");

if (problems.length) {
  for (const problem of problems) console.error(`ERROR ${problem}`);
  process.exitCode = 1;
} else {
  console.log(`SEO local validation passed for ${sitemapUrls.length} sitemap URLs and ${allLinks.length} internal links.`);
}
