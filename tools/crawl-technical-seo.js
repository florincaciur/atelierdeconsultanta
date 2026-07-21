#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const CANONICAL_ORIGIN = "https://atelierdeconsultanta.ro";
const CANONICAL_HOST = "atelierdeconsultanta.ro";
const USER_AGENT = "FABER-Technical-SEO-Crawl/1.0";
const MAX_REDIRECT_HOPS = 5;
const PAGE_LIMIT = Number(process.argv.find((argument) => argument.startsWith("--max-pages="))?.split("=")[1] || 500);
const LABEL = (process.argv.find((argument) => argument.startsWith("--label="))?.split("=")[1] || "before").replace(/[^a-z0-9_-]/giu, "-");
const ORIGIN = (process.argv.find((argument) => argument.startsWith("--origin="))?.split("=")[1] || CANONICAL_ORIGIN).replace(/\/+$/u, "");
const OUTPUT_JSON = path.join(ROOT, "reports", `technical-seo-crawl-${LABEL}.json`);
const OUTPUT_CSV = path.join(ROOT, "reports", `technical-seo-crawl-${LABEL}.csv`);
const OUTPUT_MD = path.join(ROOT, "reports", `technical-seo-crawl-${LABEL}.md`);
const SKIP_SCHEMES = /^(?:mailto|tel|sms|javascript|data|blob|whatsapp):/iu;
const ASSET_EXTENSIONS = /\.(?:avif|css|gif|ico|jpe?g|js|map|pdf|png|svg|webmanifest|webp|woff2?|ttf|xlsx?)(?:$|[?#])/iu;

const fetchCache = new Map();
const issues = [];

function issue(type, severity, url, evidence, fix, acceptance, approval = false) {
  const key = [type, url, evidence].join("|");
  if (issues.some((item) => item._key === key)) return;
  issues.push({ type, severity, url, evidence, fix, acceptance, approvalRequired: approval, _key: key });
}

function cleanInternalUrl(value, base) {
  const raw = String(value || "").replace(/&amp;/gu, "&").trim();
  if (!raw || raw.startsWith("#") || SKIP_SCHEMES.test(raw) || raw.includes("{{") || raw.includes("${")) return null;
  try {
    const parsed = new URL(raw, base);
    if (!/^https?:$/iu.test(parsed.protocol)) return null;
    if (![CANONICAL_HOST, `www.${CANONICAL_HOST}`].includes(parsed.hostname)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function canonicalLogicalUrl(url) {
  const parsed = new URL(url);
  parsed.protocol = "https:";
  parsed.hostname = CANONICAL_HOST;
  parsed.port = "";
  parsed.hash = "";
  return parsed.toString();
}

function requestUrl(logicalUrl) {
  const logical = new URL(logicalUrl);
  const origin = new URL(ORIGIN);
  if (ORIGIN === CANONICAL_ORIGIN || logical.hostname !== CANONICAL_HOST || logical.protocol !== "https:") return logical.toString();
  logical.protocol = origin.protocol;
  logical.hostname = origin.hostname;
  logical.port = origin.port;
  return logical.toString();
}

async function fetchOnce(logicalUrl) {
  const key = logicalUrl;
  if (fetchCache.has(key)) return fetchCache.get(key);
  const promise = (async () => {
    try {
      const response = await fetch(requestUrl(logicalUrl), {
        redirect: "manual",
        headers: { "user-agent": USER_AGENT, accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5" },
      });
      const body = await response.text();
      return {
        requestedUrl: logicalUrl,
        status: response.status,
        location: response.headers.get("location") || "",
        contentType: response.headers.get("content-type") || "",
        xRobots: response.headers.get("x-robots-tag") || "",
        body,
      };
    } catch (error) {
      return { requestedUrl: logicalUrl, status: 0, location: "", contentType: "", xRobots: "", body: "", error: error.message };
    }
  })();
  fetchCache.set(key, promise);
  return promise;
}

async function trace(inputUrl) {
  const chain = [];
  const seen = new Set();
  let current = inputUrl;
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop += 1) {
    if (seen.has(current)) return { chain, loop: true, tooMany: false, final: chain.at(-1) };
    seen.add(current);
    const step = await fetchOnce(current);
    chain.push(step);
    if (step.status < 300 || step.status >= 400 || !step.location) return { chain, loop: false, tooMany: false, final: step };
    current = new URL(step.location, current).toString();
  }
  return { chain, loop: false, tooMany: true, final: chain.at(-1) };
}

function parseSitemapXml(xml) {
  const pageEntries = [];
  for (const match of String(xml).matchAll(/<url>\s*([\s\S]*?)<\/url>/giu)) {
    const loc = match[1].match(/<loc>\s*([^<]+)\s*<\/loc>/iu)?.[1]?.trim();
    const lastmod = match[1].match(/<lastmod>\s*([^<]+)\s*<\/lastmod>/iu)?.[1]?.trim() || null;
    if (loc) pageEntries.push({ url: loc.replace(/&amp;/gu, "&"), lastmod });
  }
  const children = [...String(xml).matchAll(/<sitemap>\s*([\s\S]*?)<\/sitemap>/giu)]
    .map((match) => match[1].match(/<loc>\s*([^<]+)\s*<\/loc>/iu)?.[1]?.trim())
    .filter(Boolean);
  return { pageEntries, children };
}

async function liveSitemapEntries(entryUrl = `${CANONICAL_ORIGIN}/sitemap.xml`, visited = new Set()) {
  if (visited.has(entryUrl)) {
    issue("sitemap-index-loop", "critical", entryUrl, "Sitemap index references itself.", "Remove the circular reference.", "Every sitemap document is visited once.");
    return [];
  }
  visited.add(entryUrl);
  const result = await trace(entryUrl);
  if (result.chain.length !== 1 || result.final.status !== 200) {
    issue("sitemap-document-status", "critical", entryUrl, `Chain: ${result.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> ")}`, "Serve the sitemap document directly with HTTP 200.", "The sitemap document returns 200 without redirect.");
    return [];
  }
  const parsed = parseSitemapXml(result.final.body);
  const entries = [...parsed.pageEntries];
  for (const child of parsed.children) entries.push(...await liveSitemapEntries(child, visited));
  return entries;
}

function explicitHistoricalUrls() {
  const values = new Set();
  const redirectsPath = path.join(ROOT, "_redirects");
  if (fs.existsSync(redirectsPath)) {
    for (const rawLine of fs.readFileSync(redirectsPath, "utf8").split(/\r?\n/u)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const [source] = line.split(/\s+/u);
      if (!source || /[*:]/u.test(source)) continue;
      values.add(new URL(source, CANONICAL_ORIGIN).toString());
    }
  }
  const candidatesPath = path.join(ROOT, "config", "url-consolidation-candidates.json");
  if (fs.existsSync(candidatesPath)) {
    const data = JSON.parse(fs.readFileSync(candidatesPath, "utf8"));
    for (const row of data.rows || []) if (row.url) values.add(new URL(row.url, CANONICAL_ORIGIN).toString());
  }
  const gscPath = path.join(ROOT, "reports", "gsc-page-opportunities.csv");
  if (fs.existsSync(gscPath)) {
    for (const match of fs.readFileSync(gscPath, "utf8").matchAll(/https?:\/\/(?:www\.)?atelierdeconsultanta\.ro[^",\r\n]*/giu)) {
      try { values.add(new URL(match[0]).toString()); } catch { /* Invalid export row; ignored here. */ }
    }
  }
  return [...values];
}

function htmlSignals(record) {
  const $ = cheerio.load(record.body, { decodeEntities: false });
  const canonicals = $("link[rel~='canonical']").map((_, element) => $(element).attr("href") || "").get().filter(Boolean);
  const title = $("title").first().text().replace(/\s+/gu, " ").trim();
  const descriptions = $("meta[name='description' i]").map((_, element) => $(element).attr("content") || "").get().filter(Boolean);
  const h1 = $("h1").map((_, element) => $(element).text().replace(/\s+/gu, " ").trim()).get().filter(Boolean);
  const metaRobots = $("meta[name='robots' i]").first().attr("content") || "";
  const text = $("main").text().replace(/\s+/gu, " ").trim();
  const links = [];
  $("a[href], area[href], form[action]").each((_, element) => {
    const attribute = element.tagName === "form" ? "action" : "href";
    const value = $(element).attr(attribute) || "";
    const parsed = cleanInternalUrl(value, record.finalUrl);
    if (parsed) links.push({ raw: value, url: parsed.toString(), kind: element.tagName === "form" ? "form" : "link" });
  });
  const assets = [];
  $("script[src], img[src], source[src], link[href]").each((_, element) => {
    const value = $(element).attr("src") || $(element).attr("href") || "";
    const parsed = cleanInternalUrl(value, record.finalUrl);
    if (parsed && ASSET_EXTENSIONS.test(parsed.pathname)) assets.push(parsed.toString());
  });
  $("source[srcset], img[srcset]").each((_, element) => {
    for (const item of String($(element).attr("srcset") || "").split(",")) {
      const parsed = cleanInternalUrl(item.trim().split(/\s+/u)[0], record.finalUrl);
      if (parsed) assets.push(parsed.toString());
    }
  });
  const structuredUrls = [];
  $("script[type='application/ld+json']").each((index, element) => {
    try {
      const data = JSON.parse($(element).contents().text());
      (function walk(value) {
        if (typeof value === "string" && /^https?:\/\//iu.test(value)) {
          const parsed = cleanInternalUrl(value, record.finalUrl);
          if (parsed) structuredUrls.push(parsed.toString());
        } else if (Array.isArray(value)) value.forEach(walk);
        else if (value && typeof value === "object") Object.values(value).forEach(walk);
      })(data);
    } catch (error) {
      issue("structured-data-invalid", "high", record.finalUrl, `JSON-LD block ${index + 1}: ${error.message}`, "Correct the JSON-LD syntax.", "Every JSON-LD block parses successfully.");
    }
  });
  return { $, canonicals, title, descriptions, h1, metaRobots, text, links, assets: [...new Set(assets)], structuredUrls: [...new Set(structuredUrls)] };
}

function looksLikeSoft404(signals) {
  const combined = `${signals.title} ${signals.h1.join(" ")} ${signals.text.slice(0, 500)}`.toLowerCase();
  return /(?:404|pagina (?:nu |in)?existent|pagina nu a fost g[aă]sit[aă]|page not found)/iu.test(combined);
}

async function crawlPages(seedUrls, sitemapSet) {
  const pending = [...new Set(seedUrls)];
  const queued = new Set(pending);
  const pageRecords = new Map();
  const rawResults = new Map();
  const linkEdges = [];
  const assets = new Set();

  while (pending.length && rawResults.size < PAGE_LIMIT) {
    const batch = pending.splice(0, 8);
    const results = await Promise.all(batch.map(async (url) => ({ inputUrl: url, traced: await trace(url) })));
    for (const { inputUrl, traced } of results) {
      rawResults.set(inputUrl, traced);
      if (traced.loop || traced.tooMany) {
        issue("redirect-loop-or-chain-limit", "critical", inputUrl, traced.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> "), "Replace the chain with one direct permanent redirect or retain a true 404/410.", "The URL reaches its final response in at most one hop.");
        continue;
      }
      if (traced.chain.length > 2) {
        issue("redirect-chain", "high", inputUrl, traced.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> "), "Point the source directly to the final canonical target.", "The source has exactly one redirect hop.");
      }
      const final = traced.final;
      const isHtml = /text\/html|application\/xhtml\+xml/iu.test(final.contentType) || /^\s*<!doctype html|^\s*<html/iu.test(final.body);
      if (final.status >= 500 || final.status === 0) {
        issue("server-error", "critical", inputUrl, final.error || `HTTP ${final.status}`, "Restore a stable response and investigate hosting/runtime logs.", "The final response is below 500.");
      }
      if (!isHtml || final.status !== 200) continue;
      const finalUrl = final.requestedUrl;
      if (pageRecords.has(finalUrl)) continue;
      const record = { inputUrl, finalUrl, status: final.status, body: final.body, contentType: final.contentType, xRobots: final.xRobots };
      const signals = htmlSignals(record);
      Object.assign(record, signals);
      pageRecords.set(finalUrl, record);

      if (looksLikeSoft404(signals)) issue("soft-404", "high", finalUrl, `HTTP 200 with title/H1: ${signals.title} / ${signals.h1.join(" | ")}`, "Return a true 404/410 or restore substantive content.", "Missing content returns 404/410; valid content no longer resembles an error page.");
      if (!signals.canonicals.length) issue("canonical-missing", "high", finalUrl, "No rel=canonical found.", "Add one absolute self-canonical URL.", "Exactly one canonical points to the final 200 URL.");
      if (signals.canonicals.length > 1) issue("canonical-multiple", "high", finalUrl, signals.canonicals.join(" | "), "Keep exactly one canonical declaration.", "Exactly one canonical remains.");
      if (signals.descriptions.length > 1) issue("meta-description-multiple", "medium", finalUrl, `${signals.descriptions.length} meta descriptions`, "Keep one page-specific meta description.", "Exactly one meta description remains.");
      if (signals.h1.length !== 1) issue("h1-count", "medium", finalUrl, `${signals.h1.length} H1 elements`, "Keep one descriptive H1.", "Exactly one visible H1 remains.");
      if (/\bnoindex\b/iu.test(signals.metaRobots) !== /\bnoindex\b/iu.test(final.xRobots) && signals.metaRobots && final.xRobots) {
        issue("robots-conflict", "high", finalUrl, `meta=${signals.metaRobots}; X-Robots-Tag=${final.xRobots}`, "Align meta robots and X-Robots-Tag.", "Both channels express the same indexability.");
      }
      for (const link of signals.links) {
        const logicalTarget = canonicalLogicalUrl(link.url);
        linkEdges.push({ source: finalUrl, target: logicalTarget, raw: link.raw, kind: link.kind });
        if (link.kind === "link" && new URL(link.url).search) {
          issue("internal-link-query", "medium", finalUrl, link.raw, "Link directly to the clean canonical URL unless the parameter has a required functional purpose.", "Editorial page links do not create crawlable parameter variants.");
        }
        if (link.kind === "link" && !ASSET_EXTENSIONS.test(new URL(logicalTarget).pathname) && !queued.has(logicalTarget) && rawResults.size + pending.length < PAGE_LIMIT) {
          queued.add(logicalTarget);
          pending.push(logicalTarget);
        }
      }
      signals.assets.forEach((asset) => assets.add(asset));
    }
  }
  if (pending.length) issue("crawl-limit", "high", `${CANONICAL_ORIGIN}/`, `${pending.length} URLs remained after limit ${PAGE_LIMIT}.`, "Raise the crawl limit or reduce crawl traps.", "The queue is empty before the configured limit.");
  return { pageRecords, rawResults, linkEdges, assets };
}

async function validatePageSignals(crawl, sitemapEntries) {
  const sitemapSet = new Set(sitemapEntries.map((entry) => entry.url));
  for (const entry of sitemapEntries) {
    const traced = crawl.rawResults.get(entry.url) || await trace(entry.url);
    if (traced.chain.length !== 1 || traced.final.status !== 200) {
      issue("sitemap-url-status", "critical", entry.url, traced.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> "), "Remove non-200/redirected URLs from sitemap and list only the final canonical URL.", "The sitemap URL returns 200 without redirects.");
      continue;
    }
    const record = crawl.pageRecords.get(traced.final.requestedUrl);
    if (!record) continue;
    const robots = `${record.metaRobots} ${record.xRobots}`;
    if (/\bnoindex\b/iu.test(robots)) issue("sitemap-url-noindex", "critical", entry.url, robots.trim(), "Remove the URL from sitemap until it becomes deliberately indexable.", "No sitemap URL is noindex.");
    if (record.canonicals.length !== 1 || record.canonicals[0] !== entry.url) {
      issue("sitemap-url-not-self-canonical", "critical", entry.url, `canonical=${record.canonicals.join(" | ") || "missing"}`, "Align the sitemap URL and the single self-canonical.", "The sitemap URL has one canonical equal to itself.");
    }
  }

  for (const record of crawl.pageRecords.values()) {
    const canonical = record.canonicals[0];
    if (canonical) {
      const target = await trace(canonical);
      if (target.chain.length !== 1 || target.final.status !== 200) {
        issue("canonical-target-invalid", "critical", record.finalUrl, `canonical ${canonical}: ${target.chain.map((step) => step.status).join(" -> ")}`, "Point canonical directly to a 200 indexable target.", "Canonical target returns 200 with no redirect.");
      }
    }
    for (const structuredUrl of record.structuredUrls) {
      const target = await trace(structuredUrl);
      if (target.chain.length > 1 || target.final.status !== 200 || /\.html(?:$|[?#])/iu.test(structuredUrl) || new URL(structuredUrl).hostname !== CANONICAL_HOST) {
        issue("structured-data-old-url", "high", record.finalUrl, `${structuredUrl}: ${target.chain.map((step) => step.status).join(" -> ")}`, "Replace structured-data URLs with the final HTTPS canonical URL.", "Every internal JSON-LD URL is final, 200 and canonical-host.");
      }
    }
  }

  for (const edge of crawl.linkEdges) {
    if (edge.kind === "form" && new URL(edge.target).pathname.startsWith("/api/")) continue;
    const target = crawl.rawResults.get(edge.target) || await trace(edge.target);
    if (target.loop || target.tooMany) issue("internal-link-loop", "critical", edge.source, `${edge.raw} loops`, "Update the internal link to a valid final URL.", "The link reaches a 200 page in zero hops.");
    else if (target.chain.length > 1) issue("internal-link-redirect", "high", edge.source, `${edge.raw}: ${target.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> ")}`, "Update the internal href to the final canonical URL.", "The internal link returns 200 without redirect.");
    else if (target.final.status >= 400) issue("internal-link-error", "critical", edge.source, `${edge.raw}: HTTP ${target.final.status}`, "Correct or remove the broken internal link.", "The internal link returns 200.");
  }

  for (const assetUrl of crawl.assets) {
    const target = await trace(assetUrl);
    if (target.final.status >= 400 || target.final.status === 0) issue("missing-resource", "high", assetUrl, `HTTP ${target.final.status || target.final.error}`, "Restore the resource or update every reference.", "The resource returns 200.");
    else if (target.chain.length > 1) issue("resource-redirect", "medium", assetUrl, target.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> "), "Reference the final asset URL directly.", "The asset returns 200 without redirect.");
  }

  const indexableRecords = [...crawl.pageRecords.values()].filter((record) => record.canonicals.length === 1 && !/\bnoindex\b/iu.test(`${record.metaRobots} ${record.xRobots}`));
  for (const record of indexableRecords) {
    const canonical = record.canonicals[0];
    if (canonical.startsWith(`${CANONICAL_ORIGIN}/`) && !sitemapSet.has(canonical)) {
      issue("indexable-canonical-absent-sitemap", "high", canonical, `Discovered from ${record.inputUrl}`, "Add the important canonical page to the appropriate sitemap or explicitly noindex/consolidate it after approval.", "Every intended indexable canonical page is in sitemap.", true);
    }
  }
}

function validateDuplicatesAndGraph(crawl, sitemapEntries) {
  for (const field of ["title", "h1", "description"]) {
    const seen = new Map();
    for (const record of crawl.pageRecords.values()) {
      if (/\bnoindex\b/iu.test(`${record.metaRobots} ${record.xRobots}`)) continue;
      if (record.canonicals.length !== 1 || canonicalLogicalUrl(record.finalUrl) !== record.canonicals[0]) continue;
      const value = field === "title" ? record.title : field === "h1" ? record.h1[0] : record.descriptions[0];
      const normalized = String(value || "").replace(/\s+/gu, " ").trim().toLowerCase();
      if (!normalized) continue;
      if (seen.has(normalized) && seen.get(normalized) !== record.finalUrl) {
        issue(`duplicate-${field}`, "medium", record.finalUrl, `${value} | first: ${seen.get(normalized)}`, `Differentiate the ${field} according to the page's unique intent.`, `No two indexable canonical pages share this ${field}.`, true);
      } else seen.set(normalized, record.finalUrl);
    }
  }

  const adjacency = new Map();
  for (const edge of crawl.linkEdges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, new Set());
    adjacency.get(edge.source).add(edge.target);
  }
  const home = `${CANONICAL_ORIGIN}/`;
  const depth = new Map([[home, 0]]);
  const queue = [home];
  while (queue.length) {
    const current = queue.shift();
    for (const target of adjacency.get(current) || []) {
      if (depth.has(target)) continue;
      depth.set(target, depth.get(current) + 1);
      queue.push(target);
    }
  }
  for (const entry of sitemapEntries) {
    if (!depth.has(entry.url)) issue("orphan-page", "high", entry.url, "No crawlable internal path from homepage.", "Add a relevant contextual/navigation link or remove the URL from the intended index set.", "The URL is reachable from homepage through crawlable links.", true);
    else if (depth.get(entry.url) > 3) issue("click-depth", "medium", entry.url, `Depth ${depth.get(entry.url)}`, "Add a relevant internal route that reduces click depth.", "Important canonical URL depth is at most 3.");
  }
  return depth;
}

async function validateVariants(sitemapEntries) {
  const variants = [];
  for (const entry of sitemapEntries) {
    const url = new URL(entry.url);
    const pathName = url.pathname;
    variants.push({ type: "http", url: `http://${CANONICAL_HOST}${pathName}`, expected: entry.url });
    variants.push({ type: "www", url: `https://www.${CANONICAL_HOST}${pathName}`, expected: entry.url });
    if (pathName !== "/") {
      variants.push({ type: "trailing-slash", url: `${CANONICAL_ORIGIN}${pathName}/`, expected: entry.url });
      if (!path.posix.extname(pathName)) variants.push({ type: "html", url: `${CANONICAL_ORIGIN}${pathName}.html`, expected: entry.url });
    }
  }
  for (let offset = 0; offset < variants.length; offset += 12) {
    const batch = variants.slice(offset, offset + 12);
    const results = await Promise.all(batch.map(async (variant) => ({ variant, traced: await trace(variant.url) })));
    for (const { variant, traced } of results) {
      const finalUrl = traced.final?.requestedUrl || "";
      if (traced.loop || traced.tooMany || traced.chain.length !== 2 || traced.chain[0].status !== 301 || finalUrl !== variant.expected || traced.final.status !== 200) {
        issue("url-variant-not-one-hop", variant.type === "www" ? "critical" : "high", variant.url, `${traced.chain.map((step) => `${step.status} ${step.requestedUrl}`).join(" -> ")}; expected 301 -> 200 ${variant.expected}`, "Configure one direct 301 to the canonical HTTPS/non-www/no-slash/no-.html URL.", "Variant resolves in one 301 hop to the final 200 canonical URL.");
      }
    }
  }
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
}

function writeReports(summary) {
  fs.mkdirSync(path.dirname(OUTPUT_JSON), { recursive: true });
  const cleanIssues = issues.map(({ _key, ...item }) => item);
  fs.writeFileSync(OUTPUT_JSON, `${JSON.stringify({ ...summary, issues: cleanIssues }, null, 2)}\n`, "utf8");
  const rows = [["type", "severity", "url", "evidence", "fix", "acceptance_test", "approval_required"]];
  for (const item of cleanIssues) rows.push([item.type, item.severity, item.url, item.evidence, item.fix, item.acceptance, item.approvalRequired ? "yes" : "no"]);
  fs.writeFileSync(OUTPUT_CSV, `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`, "utf8");
  const severityCounts = ["critical", "high", "medium", "low"].map((severity) => [severity, cleanIssues.filter((item) => item.severity === severity).length]);
  const markdown = `# Crawl tehnic SEO - ${LABEL}\n\n` +
    `- Origin verificat: ${ORIGIN}\n- Generat: ${summary.generatedAt}\n- URL-uri sitemap: ${summary.sitemapUrlCount}\n- Pagini HTML procesate: ${summary.htmlPageCount}\n- URL-uri istorice testate: ${summary.historicalUrlCount}\n- Resurse interne testate: ${summary.assetCount}\n- Probleme: ${cleanIssues.length}\n` +
    severityCounts.map(([severity, count]) => `- ${severity}: ${count}`).join("\n") +
    `\n\n| Severitate | Tip | URL | Dovada | Fix | Test de acceptare | Aprobare |\n|---|---|---|---|---|---|---|\n` +
    cleanIssues.map((item) => `| ${item.severity} | ${item.type} | ${item.url} | ${item.evidence.replace(/\|/gu, "\\|")} | ${item.fix.replace(/\|/gu, "\\|")} | ${item.acceptance.replace(/\|/gu, "\\|")} | ${item.approvalRequired ? "DA" : "NU"} |`).join("\n") + `\n`;
  fs.writeFileSync(OUTPUT_MD, markdown, "utf8");
}

async function main() {
  const generatedAt = new Date().toISOString();
  const sitemapEntries = await liveSitemapEntries(`${CANONICAL_ORIGIN}/sitemap.xml`);
  const sitemapSet = new Set(sitemapEntries.map((entry) => entry.url));
  const historical = explicitHistoricalUrls();
  const seeds = [`${CANONICAL_ORIGIN}/`, ...sitemapSet, ...historical];
  const crawl = await crawlPages(seeds, sitemapSet);
  await validatePageSignals(crawl, sitemapEntries);
  const depth = validateDuplicatesAndGraph(crawl, sitemapEntries);
  await validateVariants(sitemapEntries);
  const summary = {
    generatedAt,
    origin: ORIGIN,
    sitemapUrlCount: sitemapEntries.length,
    htmlPageCount: crawl.pageRecords.size,
    historicalUrlCount: historical.length,
    assetCount: crawl.assets.size,
    fetchedUrlCount: fetchCache.size,
    reachableSitemapUrlCount: sitemapEntries.filter((entry) => depth.has(entry.url)).length,
    issueCount: issues.length,
  };
  issues.sort((a, b) => ["critical", "high", "medium", "low"].indexOf(a.severity) - ["critical", "high", "medium", "low"].indexOf(b.severity) || a.type.localeCompare(b.type) || a.url.localeCompare(b.url));
  writeReports(summary);
  console.log(`Technical crawl ${LABEL}: ${summary.sitemapUrlCount} sitemap URLs, ${summary.htmlPageCount} HTML pages, ${summary.assetCount} assets, ${summary.issueCount} issues.`);
  console.log(`Reports: ${path.relative(ROOT, OUTPUT_MD)}, ${path.relative(ROOT, OUTPUT_CSV)}, ${path.relative(ROOT, OUTPUT_JSON)}`);
  if (process.argv.includes("--fail-on-critical") && issues.some((item) => item.severity === "critical")) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
