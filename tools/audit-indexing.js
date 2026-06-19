#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const HOSTS = new Set(["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"]);
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const HEADERS_PATH = path.join(ROOT, "_headers");
const REPORT_PATH = path.join(ROOT, "reports", "indexing-audit.json");
const SKIP_SCHEMES = /^(?:mailto|tel|sms|javascript|data|blob|whatsapp):/i;
const NON_PAGE_EXTENSIONS = new Set([
  ".avif",
  ".css",
  ".gif",
  ".ico",
  ".jpeg",
  ".jpg",
  ".js",
  ".json",
  ".map",
  ".pdf",
  ".png",
  ".svg",
  ".txt",
  ".webmanifest",
  ".webp",
  ".xlsx",
  ".xml",
]);

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function readIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
}

function matchesPattern(pattern, pathname) {
  if (pattern === pathname) return true;
  if (!pattern.includes("*")) return false;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(pathname);
}

function parseRedirects() {
  return readIfExists(REDIRECTS_PATH)
    .split(/\r?\n/)
    .map((line, index) => ({ line: index + 1, raw: line.trim() }))
    .filter((entry) => entry.raw && !entry.raw.startsWith("#"))
    .map((entry) => {
      const [from, to, status = "301"] = entry.raw.split(/\s+/);
      return { ...entry, from, to, status: Number(status) || 301 };
    });
}

function parseHeaders() {
  const rules = [];
  let current = null;

  for (const line of readIfExists(HEADERS_PATH).split(/\r?\n/)) {
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

const REDIRECTS = parseRedirects();
const HEADER_RULES = parseHeaders();

function headersFor(pathname) {
  const headers = {};
  for (const rule of HEADER_RULES) {
    if (matchesPattern(rule.pattern, pathname)) Object.assign(headers, rule.headers);
  }
  return headers;
}

function fileForPath(pathname) {
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  const candidates = [];
  if (!clean) {
    candidates.push("index.html");
  } else if (pathname.endsWith("/")) {
    candidates.push(path.posix.join(clean, "index.html"));
  } else if (path.posix.extname(clean)) {
    candidates.push(clean);
  } else {
    candidates.push(path.posix.join(clean, "index.html"), `${clean}.html`);
  }
  return candidates.find((candidate) => fs.existsSync(path.join(ROOT, candidate))) || "";
}

function normalizeAbsoluteUrl(rawUrl) {
  const parsed = new URL(rawUrl, SITE);
  parsed.protocol = "https:";
  parsed.hostname = "atelierdeconsultanta.ro";
  parsed.hash = "";
  parsed.search = "";
  if (parsed.pathname !== "/") parsed.pathname = parsed.pathname.replace(/\/+$/g, "");
  return parsed.href;
}

function hasRedirect(chain) {
  return chain.some((step) => Number(step.status) >= 300 && Number(step.status) < 400);
}

function trace(rawUrl) {
  const chain = [];
  let current = new URL(rawUrl, SITE);
  const seen = new Set();

  for (let index = 0; index < 12; index += 1) {
    const key = current.href;
    if (seen.has(key)) {
      chain.push({ url: current.href, status: "LOOP" });
      break;
    }
    seen.add(key);

    if (current.protocol === "http:") {
      const next = new URL(current.href);
      next.protocol = "https:";
      chain.push({ url: current.href, status: 301, to: next.href, source: "protocol" });
      current = next;
      continue;
    }

    const redirect = REDIRECTS.find((rule) => matchesPattern(rule.from, current.pathname));
    if (redirect) {
      const next = new URL(redirect.to, SITE);
      chain.push({
        url: current.href,
        status: redirect.status,
        to: next.href,
        source: `_redirects:${redirect.line}`,
      });
      current = next;
      continue;
    }

    const file = fileForPath(current.pathname);
    chain.push({
      url: current.href,
      status: file ? 200 : 404,
      file,
    });
    break;
  }

  return chain;
}

function finalStep(chain) {
  return chain[chain.length - 1] || { status: 0, url: "" };
}

function htmlForFile(file) {
  return file ? readIfExists(path.join(ROOT, file)) : "";
}

function extractCanonical($) {
  return $('link[rel="canonical" i]').first().attr("href") || "";
}

function extractRobots($, pathname) {
  const meta = $('meta[name="robots" i]').first().attr("content") || "";
  const googlebot = $('meta[name="googlebot" i]').first().attr("content") || "";
  const header = headersFor(pathname)["x-robots-tag"] || "";
  return [meta, googlebot, header].filter(Boolean).join("; ");
}

function pageDataForFinal(final) {
  const pathname = final.url ? new URL(final.url).pathname : "";
  const html = htmlForFile(final.file);
  const $ = cheerio.load(html, { decodeEntities: false });
  return {
    file: final.file || "",
    pathname,
    html,
    $,
    canonical: extractCanonical($),
    robots: extractRobots($, pathname),
    title: $("title").first().text().replace(/\s+/g, " ").trim(),
    description: $('meta[name="description" i]').first().attr("content") || "",
    h1: $("h1").toArray().map((element) => $(element).text().replace(/\s+/g, " ").trim()),
  };
}

function parseSitemapUrls() {
  const xml = readIfExists(SITEMAP_PATH);
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
}

function addIssue(issues, type, message, details = {}) {
  issues.push({ type, message, ...details });
}

function isCleanCanonicalUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.origin !== SITE) return false;
    if (parsed.search || parsed.hash) return false;
    if (parsed.pathname !== "/" && parsed.pathname.endsWith("/")) return false;
    if (parsed.pathname.endsWith(".html") || parsed.pathname.endsWith("/index.html")) return false;
    return true;
  } catch {
    return false;
  }
}

function validateSitemapUrl(url, sitemapSet, issues, pageRecords) {
  if (!isCleanCanonicalUrl(url)) {
    addIssue(issues, "sitemap-url-format", "Sitemap URL is not a clean canonical URL.", { url });
    return;
  }

  const chain = trace(url);
  const final = finalStep(chain);
  const redirected = hasRedirect(chain);
  const data = pageDataForFinal(final);
  const normalizedFinal = final.url ? normalizeAbsoluteUrl(final.url) : "";

  if (redirected) {
    addIssue(issues, "sitemap-redirect", "Sitemap URL redirects; sitemap must contain only final 200 URLs.", { url, chain });
  }
  if (final.status !== 200) {
    addIssue(issues, "sitemap-status", "Sitemap URL does not return HTTP 200.", { url, chain });
    return;
  }
  if (/\bnoindex\b/i.test(data.robots)) {
    addIssue(issues, "sitemap-noindex", "Sitemap URL is noindex via meta robots or X-Robots-Tag.", {
      url,
      file: data.file,
      robots: data.robots,
    });
  }
  if (!data.canonical) {
    addIssue(issues, "missing-canonical", "Sitemap URL has no canonical tag.", { url, file: data.file });
  } else if (normalizeAbsoluteUrl(data.canonical) !== url || normalizedFinal !== url) {
    addIssue(issues, "canonical-not-self", "Sitemap URL canonical is not self-referencing.", {
      url,
      file: data.file,
      canonical: data.canonical,
    });
  }

  if (data.canonical) {
    const canonicalChain = trace(data.canonical);
    const canonicalFinal = finalStep(canonicalChain);
    const canonicalData = pageDataForFinal(canonicalFinal);
    if (hasRedirect(canonicalChain) || canonicalFinal.status !== 200 || /\bnoindex\b/i.test(canonicalData.robots)) {
      addIssue(issues, "canonical-target-invalid", "Canonical target redirects, is missing, or is noindex.", {
        url,
        canonical: data.canonical,
        chain: canonicalChain,
        robots: canonicalData.robots,
      });
    }
    if (!sitemapSet.has(normalizeAbsoluteUrl(data.canonical))) {
      addIssue(issues, "canonical-not-in-sitemap", "Canonical target is indexable but not present in sitemap.", {
        url,
        canonical: data.canonical,
      });
    }
  }

  if (!data.title) addIssue(issues, "missing-title", "Sitemap URL has no title.", { url, file: data.file });
  if (!data.description) addIssue(issues, "missing-description", "Sitemap URL has no meta description.", { url, file: data.file });
  if (data.h1.length !== 1) addIssue(issues, "h1-count", "Sitemap URL must have exactly one H1.", { url, file: data.file, h1: data.h1 });
  data.$('script[type="application/ld+json"]').each((index, element) => {
    const json = data.$(element).contents().text().trim();
    if (!json) return;
    try {
      JSON.parse(json);
    } catch (error) {
      addIssue(issues, "json-ld-invalid", "JSON-LD block cannot be parsed.", {
        url,
        file: data.file,
        scriptIndex: index,
        error: error.message,
      });
    }
  });

  pageRecords.push({
    url,
    file: data.file,
    title: data.title,
    description: data.description,
    h1: data.h1[0] || "",
    canonical: data.canonical,
  });
}

function validateOfficialGuidesResource(sitemapSet, issues) {
  const resourceUrl = `${SITE}/official-guides.json`;
  const chain = trace(resourceUrl);
  const final = finalStep(chain);
  const headers = headersFor("/official-guides.json");
  const robots = headers["x-robots-tag"] || "";
  const contentType = headers["content-type"] || "";

  if (sitemapSet.has(resourceUrl)) {
    addIssue(issues, "technical-resource-in-sitemap", "official-guides.json must not be listed in sitemap.", {
      url: resourceUrl,
    });
  }
  if (hasRedirect(chain) || final.status !== 200 || final.file !== "official-guides.json") {
    addIssue(issues, "official-guides-status", "official-guides.json must stay available as a direct 200 JSON resource.", {
      url: resourceUrl,
      chain,
    });
  }
  if (!/\bnoindex\b/i.test(robots) || !/\bnofollow\b/i.test(robots)) {
    addIssue(issues, "official-guides-robots", "official-guides.json must send X-Robots-Tag: noindex, nofollow.", {
      url: resourceUrl,
      robots,
    });
  }
  if (!/^application\/json\b/i.test(contentType)) {
    addIssue(issues, "official-guides-content-type", "official-guides.json must declare application/json Content-Type in _headers.", {
      url: resourceUrl,
      contentType,
    });
  }
  try {
    JSON.parse(readIfExists(path.join(ROOT, "official-guides.json")));
  } catch (error) {
    addIssue(issues, "official-guides-json", "official-guides.json is not valid JSON.", {
      url: resourceUrl,
      error: error.message,
    });
  }
}

function duplicateValues(records, key) {
  const seen = new Map();
  const duplicates = [];
  for (const record of records) {
    const value = String(record[key] || "").trim().toLowerCase();
    if (!value) continue;
    if (!seen.has(value)) {
      seen.set(value, record.url);
    } else {
      duplicates.push({ value: record[key], firstUrl: seen.get(value), secondUrl: record.url });
    }
  }
  return duplicates;
}

function isPageLikePath(pathname) {
  const ext = path.posix.extname(pathname).toLowerCase();
  return !ext || !NON_PAGE_EXTENSIONS.has(ext);
}

function normalizeInternalLink(rawValue, sourceUrl) {
  const value = String(rawValue || "").replace(/&amp;/g, "&").trim();
  if (!value || value === "#" || SKIP_SCHEMES.test(value)) return null;
  if (value.includes("${") || value.includes("{{")) return null;

  let parsed;
  try {
    parsed = new URL(value, sourceUrl);
  } catch {
    return null;
  }

  if (!/^https?:$/i.test(parsed.protocol)) return null;
  if (!HOSTS.has(parsed.hostname)) return null;
  if (!isPageLikePath(parsed.pathname)) return null;
  return { value, parsed };
}

function idsForHtml(html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const ids = new Set();
  $('[id], a[name]').each((_, element) => {
    const id = $(element).attr("id") || $(element).attr("name");
    if (id) ids.add(id);
  });
  return ids;
}

function validateInternalLinks(sitemapSet, issues, pageRecords) {
  const byUrl = new Map(pageRecords.map((record) => [record.url, record]));

  for (const record of pageRecords) {
    const html = htmlForFile(record.file);
    const $ = cheerio.load(html, { decodeEntities: false });
    const links = [];

    $("a[href], area[href]").each((_, element) => {
      links.push({ attr: "href", value: $(element).attr("href") || "" });
    });
    $("form[action]").each((_, element) => {
      links.push({ attr: "action", value: $(element).attr("action") || "" });
    });

    for (const link of links) {
      const normalized = normalizeInternalLink(link.value, record.url);
      if (!normalized) continue;

      const { value, parsed } = normalized;
      const cleanUrl = normalizeAbsoluteUrl(parsed.href);
      const cleanPathname = new URL(cleanUrl).pathname;

      if (parsed.search) {
        addIssue(issues, "internal-query", "Internal page link uses query parameters instead of a clean canonical URL.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
        });
      }
      if (parsed.pathname.endsWith("/") && parsed.pathname !== "/") {
        addIssue(issues, "internal-trailing-slash", "Internal page link uses trailing slash variant.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
        });
      }
      if (parsed.pathname.endsWith(".html") || parsed.pathname.endsWith("/index.html")) {
        addIssue(issues, "internal-html-variant", "Internal page link uses .html or /index.html variant.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
        });
      }

      const chain = trace(cleanUrl);
      const final = finalStep(chain);
      const data = pageDataForFinal(final);
      const finalClean = final.url ? normalizeAbsoluteUrl(final.url) : "";

      if (hasRedirect(chain)) {
        addIssue(issues, "internal-redirect", "Internal page link points to a redirected URL.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
          chain,
        });
      }
      if (final.status !== 200) {
        addIssue(issues, "internal-status", "Internal page link does not resolve to HTTP 200.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
          chain,
        });
        continue;
      }
      if (/\bnoindex\b/i.test(data.robots)) {
        addIssue(issues, "internal-noindex", "Internal page link points to a noindex URL.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
          robots: data.robots,
        });
      }
      if (!data.canonical || normalizeAbsoluteUrl(data.canonical) !== finalClean) {
        addIssue(issues, "internal-noncanonical-target", "Internal page link target is not self-canonical.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
          target: finalClean,
          canonical: data.canonical,
        });
      }
      if (cleanUrl !== finalClean || cleanPathname !== new URL(finalClean).pathname) {
        addIssue(issues, "internal-not-final", "Internal page link does not use the final canonical URL.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
          expected: finalClean,
        });
      }
      if (!sitemapSet.has(finalClean) && !/\bnoindex\b/i.test(data.robots)) {
        addIssue(issues, "internal-target-not-in-sitemap", "Internal link points to an indexable page missing from sitemap.", {
          sourceUrl: record.url,
          sourceFile: record.file,
          value,
          target: finalClean,
        });
      }
      if (parsed.hash) {
        const targetRecord = byUrl.get(finalClean);
        const targetHtml = targetRecord ? htmlForFile(targetRecord.file) : data.html;
        const ids = idsForHtml(targetHtml);
        const id = decodeURIComponent(parsed.hash.slice(1));
        if (id && !ids.has(id)) {
          addIssue(issues, "internal-missing-anchor", "Internal link points to a missing anchor.", {
            sourceUrl: record.url,
            sourceFile: record.file,
            value,
            target: finalClean,
            id,
          });
        }
      }
    }
  }
}

function main() {
  const issues = [];
  const pageRecords = [];
  const sitemapUrls = parseSitemapUrls();
  const sitemapSet = new Set(sitemapUrls);

  if (!sitemapUrls.length) addIssue(issues, "sitemap-empty", "sitemap.xml has no URLs.");
  for (const url of sitemapUrls) {
    if (sitemapUrls.indexOf(url) !== sitemapUrls.lastIndexOf(url)) {
      addIssue(issues, "sitemap-duplicate", "Sitemap contains duplicate URL.", { url });
    }
  }

  for (const url of sitemapUrls) validateSitemapUrl(url, sitemapSet, issues, pageRecords);

  for (const key of ["title", "description", "h1"]) {
    for (const duplicate of duplicateValues(pageRecords, key)) {
      addIssue(issues, `duplicate-${key}`, `Sitemap pages have duplicate ${key}.`, duplicate);
    }
  }

  validateInternalLinks(sitemapSet, issues, pageRecords);
  validateOfficialGuidesResource(sitemapSet, issues);

  const report = {
    generatedAt: new Date().toISOString(),
    sitemapUrlCount: sitemapUrls.length,
    checkedPageCount: pageRecords.length,
    issueCount: issues.length,
    issues,
    canonicalUrls: sitemapUrls,
  };

  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  console.log(`Indexing audit checked ${pageRecords.length} sitemap URLs and internal links from canonical pages.`);
  console.log(`Report written to ${toPosix(path.relative(ROOT, REPORT_PATH))}.`);
  if (issues.length) {
    console.error(`Indexing audit failed with ${issues.length} issue(s).`);
    for (const issue of issues.slice(0, 30)) {
      console.error(`- [${issue.type}] ${issue.message} ${issue.url || issue.value || ""}`.trim());
    }
    if (issues.length > 30) console.error(`- ...and ${issues.length - 30} more`);
    process.exit(1);
  }
  console.log("Indexing audit passed.");
}

main();
