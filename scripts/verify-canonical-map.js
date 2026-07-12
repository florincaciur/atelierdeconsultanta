#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const HEADERS_PATH = path.join(ROOT, "_headers");
const REPORT_PATH = path.join(ROOT, "reports", "canonical-map.csv");
const EXCLUDED_DIRS = new Set([".git", ".github", ".wrangler", "admin", "archive", "dist", "node_modules", "reports", "tests"]);
const LEGACY_ROUTES = Object.freeze([
  "/fonduri-europene-herambursabile-2026",
  "/start-up-nation",
  "/consultanta-start-up-nation",
  "/studii-de-caz",
  "/dr14-afir-ferme-mici"
]);
const DR12_SUPPORT_ROUTE = "/dr-12-afir-instalarea-tinerilor-fermieri";
const DR12_SUPPORT_INTENT = "DR12 AFIR și instalarea tinerilor fermieri: diferențe";

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function containsDynamicToken(value) {
  return String(value).includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_]*/.test(String(value));
}

function compileRedirectPattern(pattern) {
  const names = [];
  const escaped = String(pattern)
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/:([A-Za-z][A-Za-z0-9_]*)/g, (_, name) => {
      names.push(name);
      return "([^/]+)";
    });
  return { regex: new RegExp(`^${escaped}$`), names };
}

function parseRedirects() {
  return read("_redirects")
    .split(/\r?\n/)
    .map((line, index) => ({ raw: line.trim(), line: index + 1 }))
    .filter((entry) => entry.raw && !entry.raw.startsWith("#"))
    .map((entry) => {
      const [source, destination, status = "302"] = entry.raw.split(/\s+/);
      const dynamic = containsDynamicToken(source);
      return {
        ...entry,
        source,
        destination,
        status: Number(status),
        dynamic,
        compiled: dynamic ? compileRedirectPattern(source) : null
      };
    });
}

function destinationPath(value) {
  try {
    const url = new URL(value, SITE);
    if (url.origin !== SITE) return "";
    return url.pathname || "/";
  } catch {
    return "";
  }
}

function redirectFor(pathname, redirects) {
  for (const rule of redirects) {
    if (!rule.dynamic) {
      if (rule.source === pathname) return { ...rule, resolvedDestination: rule.destination };
      continue;
    }
    const match = pathname.match(rule.compiled.regex);
    if (!match) continue;
    let resolvedDestination = rule.destination;
    rule.compiled.names.forEach((name, index) => {
      resolvedDestination = resolvedDestination.replace(new RegExp(`:${name}\\b`, "g"), match[index + 1]);
    });
    return { ...rule, resolvedDestination };
  }
  return null;
}

function traceRedirect(pathname, redirects, maxHops = 12) {
  const chain = [];
  const seen = new Set();
  let current = pathname;
  for (let hop = 0; hop < maxHops; hop += 1) {
    if (seen.has(current)) return { chain, finalPath: current, loop: true };
    seen.add(current);
    const rule = redirectFor(current, redirects);
    if (!rule) return { chain, finalPath: current, loop: false };
    chain.push(rule);
    const next = destinationPath(rule.resolvedDestination);
    if (!next) return { chain, finalPath: "", loop: false, external: true };
    current = next;
  }
  return { chain, finalPath: current, loop: true };
}

function sitemapUrls() {
  return [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
}

function walkHtml(directory = ROOT, files = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && EXCLUDED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) walkHtml(fullPath, files);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) files.push(fullPath);
  }
  return files;
}

function extractCanonical(html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  return $('link[rel~="canonical"]').first().attr("href") || "";
}

function extractRobots(html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  return $('meta[name="robots" i]').first().attr("content") || "";
}

function hasMetaRefresh(html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  return $('meta[http-equiv="refresh" i]').length > 0;
}

function canonicalSourceFiles(pathname) {
  if (pathname === "/") return ["index.html"];
  const clean = pathname.replace(/^\/+|\/+$/g, "");
  return [`${clean}.html`, `${clean}/index.html`].filter((file) => fs.existsSync(path.join(ROOT, file)));
}

function parseHeaders() {
  if (!fs.existsSync(HEADERS_PATH)) return [];
  const rules = [];
  let current = null;
  for (const line of fs.readFileSync(HEADERS_PATH, "utf8").split(/\r?\n/)) {
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

function headerPatternMatches(pattern, pathname) {
  const escaped = String(pattern).replace(/[|\\{}()[\]^$+?.]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(pathname);
}

function hasNoindexHeader(pathname, headerRules) {
  return headerRules.some((rule) => headerPatternMatches(rule.pattern, pathname) && /\bnoindex\b/i.test(rule.headers["x-robots-tag"] || ""));
}

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function internalLinks(files = walkHtml()) {
  const links = [];
  for (const filePath of files) {
    const relativeFile = toPosix(path.relative(ROOT, filePath));
    const $ = cheerio.load(fs.readFileSync(filePath, "utf8"), { decodeEntities: false });
    $("a[href], area[href], form[action]").each((_, element) => {
      const raw = $(element).attr("href") || $(element).attr("action") || "";
      if (!raw || /^(?:#|mailto:|tel:|sms:|javascript:|data:|blob:)/i.test(raw)) return;
      try {
        const url = new URL(raw, SITE);
        if (url.origin !== SITE) return;
        links.push({ file: relativeFile, raw, pathname: url.pathname });
      } catch {
        // Other integrity checks report malformed URLs.
      }
    });
  }
  return links;
}

function verifyDr12Support(sitemapSet, problems) {
  const supportFile = path.join(ROOT, "dr-12-afir-instalarea-tinerilor-fermieri.html");
  const mainFile = path.join(ROOT, "dr12-afir", "index.html");
  if (!fs.existsSync(supportFile) || !fs.existsSync(mainFile)) {
    problems.push("DR12 support or main source file is missing");
    return;
  }
  const supportHtml = fs.readFileSync(supportFile, "utf8");
  const mainHtml = fs.readFileSync(mainFile, "utf8");
  const support = cheerio.load(supportHtml, { decodeEntities: false });
  const main = cheerio.load(mainHtml, { decodeEntities: false });
  const supportTitle = normalizeText(support("title").first().text());
  const supportH1 = normalizeText(support("h1").first().text());
  const supportIntro = normalizeText(support("main p").first().text());
  const mainTitle = normalizeText(main("title").first().text());
  const mainH1 = normalizeText(main("h1").first().text());
  const mainIntro = normalizeText(main("main p").first().text());
  if (supportTitle !== DR12_SUPPORT_INTENT || supportH1 !== DR12_SUPPORT_INTENT) {
    problems.push(`DR12 support title and H1 must equal: ${DR12_SUPPORT_INTENT}`);
  }
  if (supportTitle === mainTitle || supportH1 === mainH1 || supportIntro === mainIntro) {
    problems.push("DR12 support article duplicates the main page title, H1 or introduction");
  }
  if (extractCanonical(supportHtml) !== `${SITE}${DR12_SUPPORT_ROUTE}`) problems.push("DR12 support article is not self-canonical");
  if (!sitemapSet.has(`${SITE}${DR12_SUPPORT_ROUTE}`)) problems.push("Distinct DR12 support article is missing from sitemap");
}

function localCanonicalAudit() {
  const problems = [];
  const redirects = parseRedirects();
  const urls = sitemapUrls();
  const sitemapSet = new Set(urls);
  const headerRules = parseHeaders();
  if (urls.length !== sitemapSet.size) problems.push("Duplicate URLs exist in sitemap.xml");

  for (const value of urls) {
    let url;
    try {
      url = new URL(value);
    } catch {
      problems.push(`Invalid sitemap URL: ${value}`);
      continue;
    }
    if (url.origin !== SITE) problems.push(`Noncanonical sitemap host: ${value}`);
    if (url.search || url.hash) problems.push(`Query or hash in sitemap: ${value}`);
    if (url.pathname !== "/" && (url.pathname.endsWith("/") || url.pathname.endsWith(".html"))) problems.push(`Noncanonical sitemap path: ${value}`);
    if (redirectFor(url.pathname, redirects)) problems.push(`Redirect source in sitemap: ${value}`);
    if (hasNoindexHeader(url.pathname, headerRules)) problems.push(`Noindex header applies to sitemap URL: ${value}`);

    const sources = canonicalSourceFiles(url.pathname);
    const validSources = sources.filter((file) => {
      const html = read(file);
      return extractCanonical(html) === value && !/\bnoindex\b/i.test(extractRobots(html)) && !hasMetaRefresh(html);
    });
    if (!validSources.length) problems.push(`No indexable self-canonical HTML source for sitemap URL: ${value}`);
  }

  for (const route of LEGACY_ROUTES) {
    if (sitemapSet.has(`${SITE}${route}`)) problems.push(`Legacy route remains in sitemap: ${route}`);
  }
  const llms = read("llms.txt");
  if (llms.includes(`${SITE}/dr14-afir-ferme-mici`) || /(^|\s)\/dr14-afir-ferme-mici(?:\s|$)/m.test(llms)) {
    problems.push("/dr14-afir-ferme-mici remains in llms.txt");
  }
  const config = JSON.parse(read("config/seo-programs.json"));
  const retiredDr14 = (config.pages || []).find((page) => page.slug === "dr14-afir-ferme-mici");
  if (!retiredDr14 || retiredDr14.redirectTo !== "/dr14") problems.push("Program generator does not retire /dr14-afir-ferme-mici to /dr14");
  const blog = JSON.parse(read("blog.json"));
  if ((blog.posts || []).some((post) => post.slug === "dr14-afir-ferme-mici" && post.published !== false)) {
    problems.push("Retired DR14 alias remains published in blog.json");
  }
  if (read("feed.xml").includes(`${SITE}/dr14-afir-ferme-mici`)) problems.push("Retired DR14 alias remains in feed.xml");

  const htmlFiles = walkHtml();
  for (const filePath of htmlFiles) {
    const html = fs.readFileSync(filePath, "utf8");
    const canonical = extractCanonical(html);
    if (!canonical) continue;
    try {
      const url = new URL(canonical, SITE);
      if (url.origin === SITE && redirectFor(url.pathname, redirects)) {
        problems.push(`Canonical points to redirect: ${toPosix(path.relative(ROOT, filePath))} -> ${url.pathname}`);
      }
    } catch {
      problems.push(`Malformed canonical: ${toPosix(path.relative(ROOT, filePath))} -> ${canonical}`);
    }
  }

  const links = internalLinks(htmlFiles);
  const redirectLinks = links.filter((link) => redirectFor(link.pathname, redirects));
  for (const link of redirectLinks) problems.push(`Internal link points to redirect: ${link.file} -> ${link.raw}`);
  verifyDr12Support(sitemapSet, problems);
  return { problems, redirects, urls, sitemapSet, links, redirectLinks };
}

async function liveCanonicalAudit(urls) {
  const problems = [];
  let cursor = 0;
  async function worker() {
    while (cursor < urls.length) {
      const url = urls[cursor++];
      try {
        const response = await fetch(url, {
          redirect: "manual",
          headers: { "user-agent": "FABER canonical verification/1.0" }
        });
        const html = await response.text();
        if (response.status !== 200) {
          problems.push(`Live sitemap URL is not 200: ${url} -> ${response.status} ${response.headers.get("location") || ""}`.trim());
          continue;
        }
        const canonical = extractCanonical(html);
        if (canonical !== url) problems.push(`Live canonical mismatch: ${url} -> ${canonical || "missing"}`);
        const robots = `${extractRobots(html)},${response.headers.get("x-robots-tag") || ""}`;
        if (/\bnoindex\b/i.test(robots)) problems.push(`Live sitemap URL is noindex: ${url}`);
      } catch (error) {
        problems.push(`Live request failed: ${url} -> ${error.message}`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(8, urls.length) }, () => worker()));
  return problems;
}

function csvCell(value) {
  const string = String(value == null ? "" : value);
  return /[",\r\n]/.test(string) ? `"${string.replace(/"/g, '""')}"` : string;
}

function reportReason(source) {
  if (source.includes("dr12")) return "Consolidare DR12 cerută de auditul GSC";
  if (source.includes("dr14")) return "Consolidare DR14 cerută de auditul GSC";
  if (source.includes("por-adr-nord-est")) return "Normalizare URL legacy POR ADR Nord-Est";
  if (source.includes("afir-autoconsum-agroalimentar")) return "Normalizare URL legacy AFIR Autoconsum";
  if (LEGACY_ROUTES.some((route) => source === route || source.startsWith(`${route}/`) || source.startsWith(`${route}.`))) return "Folder legacy consolidat către pagina echivalentă";
  return containsDynamicToken(source) ? "Regulă globală de normalizare URL" : "Alias legacy consolidat";
}

function writeCanonicalReport(state) {
  const internalCounts = new Map();
  for (const link of state.links) internalCounts.set(link.pathname, (internalCounts.get(link.pathname) || 0) + 1);
  const rows = [["source_path", "canonical_path", "http_status", "action", "in_sitemap", "indexability", "internal_links_to_source", "reason"]];
  for (const url of state.urls) {
    const pathname = new URL(url).pathname;
    rows.push([pathname, pathname, 200, "keep", "yes", "index, follow", internalCounts.get(pathname) || 0, pathname === DR12_SUPPORT_ROUTE ? "Articol suport DR12 distinct" : "URL self-canonical din sitemap"]);
  }
  for (const rule of state.redirects) {
    const target = rule.dynamic ? rule.destination : destinationPath(rule.destination);
    rows.push([rule.source, target, rule.status, rule.dynamic ? "normalize" : "redirect", "no", "not applicable", internalCounts.get(rule.source) || 0, reportReason(rule.source)]);
  }
  rows.sort((a, b) => a === rows[0] ? -1 : b === rows[0] ? 1 : String(a[0]).localeCompare(String(b[0])));
  const csv = `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, csv, "utf8");
  return rows.length - 1;
}

async function main() {
  const state = localCanonicalAudit();
  if (process.argv.includes("--live")) state.problems.push(...await liveCanonicalAudit(state.urls));
  let reportRows = 0;
  if (process.argv.includes("--write-report")) reportRows = writeCanonicalReport(state);
  if (state.problems.length) {
    console.error(`Canonical map verification failed (${state.problems.length}):`);
    for (const problem of state.problems) console.error(`- ${problem}`);
    process.exit(1);
  }
  console.log(`Canonical map PASS: ${state.urls.length} sitemap URLs, 0 redirects, 0 noindex, 0 canonical mismatches, 0 internal links to redirects.`);
  if (reportRows) console.log(`Wrote reports/canonical-map.csv with ${reportRows} rows.`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    process.exit(1);
  });
}

module.exports = {
  LEGACY_ROUTES,
  ROOT,
  SITE,
  destinationPath,
  internalLinks,
  localCanonicalAudit,
  parseRedirects,
  redirectFor,
  sitemapUrls,
  traceRedirect,
  walkHtml
};
