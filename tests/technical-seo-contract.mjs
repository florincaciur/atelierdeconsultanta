#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { handleRequest } from "../cloudflare/domain-seo-redirects.mjs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "https://atelierdeconsultanta.ro";
const { auditSiteLinks } = require("../tools/audit-site-links");
const { collectSiteState } = require("../tools/generate-sitemap");
const { validateLocal } = require("../tools/verify-sitemap");

const sitemapValidation = validateLocal();
assert.deepEqual(sitemapValidation.errors, [], `sitemap contract errors:\n${sitemapValidation.errors.join("\n")}`);

const linkAudit = auditSiteLinks();
assert.deepEqual(linkAudit.issues, [], `local link errors:\n${linkAudit.issues.map((issue) => `${issue.type}: ${issue.sourceFile} -> ${issue.value}`).join("\n")}`);

const state = collectSiteState();
const entryByPath = new Map(state.entries.map((entry) => [new URL(entry.url).pathname, entry]));
const adjacency = new Map();
const uniqueFields = {
  title: new Map(),
  h1: new Map(),
  description: new Map()
};
for (const entry of state.entries) {
  const $ = cheerio.load(fs.readFileSync(path.join(ROOT, entry.sourceFile), "utf8"), { decodeEntities: false });
  const fieldValues = {
    title: $("title").first().text().trim(),
    h1: $("h1").first().text().replace(/\s+/gu, " ").trim(),
    description: $('meta[name="description"]').first().attr("content")?.trim() || ""
  };
  for (const [field, value] of Object.entries(fieldValues)) {
    assert(value, `${entry.route} must have a non-empty ${field}`);
    const routes = uniqueFields[field].get(value) || [];
    routes.push(entry.route);
    uniqueFields[field].set(value, routes);
  }
  const targets = new Set();
  $("a[href]").each((_, element) => {
    try {
      const url = new URL($(element).attr("href"), entry.url);
      const targetPath = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/u, "");
      if (url.origin === SITE && entryByPath.has(targetPath)) targets.add(targetPath);
    } catch {
      // Malformed URLs are reported by the link audit above.
    }
  });
  adjacency.set(entry.route, targets);
}

const depth = new Map([["/", 0]]);
const queue = ["/"];
while (queue.length) {
  const source = queue.shift();
  for (const target of adjacency.get(source) || []) {
    if (depth.has(target)) continue;
    depth.set(target, depth.get(source) + 1);
    queue.push(target);
  }
}
const orphans = [...entryByPath.keys()].filter((route) => !depth.has(route));
const deepPages = [...depth.entries()].filter(([, value]) => value > 3);
assert.deepEqual(orphans, [], `indexable orphan pages: ${orphans.join(", ")}`);
assert.deepEqual(deepPages, [], `canonical pages deeper than 3 clicks: ${JSON.stringify(deepPages)}`);
for (const [field, values] of Object.entries(uniqueFields)) {
  const duplicates = [...values.entries()].filter(([, routes]) => routes.length > 1);
  assert.deepEqual(duplicates, [], `duplicate ${field} values: ${JSON.stringify(duplicates)}`);
}

const workerConfig = JSON.parse(fs.readFileSync(path.join(ROOT, "wrangler.redirects.jsonc"), "utf8"));
const routePatterns = new Set(workerConfig.routes.map((route) => route.pattern));
assert(routePatterns.has("atelierdeconsultanta.ro/*"), "domain worker must cover apex host");
assert(routePatterns.has("www.atelierdeconsultanta.ro/*"), "domain worker must cover www host");

const wwwResponse = await handleRequest(new Request("https://www.atelierdeconsultanta.ro/ghiduri?utm_source=qa"), async () => {
  throw new Error("www redirect must not reach origin");
});
assert.equal(wwwResponse.status, 301);
assert.equal(wwwResponse.headers.get("location"), `${SITE}/ghiduri?utm_source=qa`);

const missingResponse = await handleRequest(new Request(`${SITE}/url-istoric-fara-destinatie-confirmata`), async () => new Response("Not found", {
  status: 404,
  headers: { "content-type": "text/html; charset=utf-8" },
}));
assert.equal(missingResponse.status, 404, "unknown historical URLs must remain true 404 instead of redirecting to homepage");
assert.equal(missingResponse.headers.get("location"), null, "404 must not have a redirect Location header");

const beforeReport = JSON.parse(fs.readFileSync(path.join(ROOT, "reports", "technical-seo-crawl-before.json"), "utf8"));
assert.equal(beforeReport.sitemapUrlCount, 102, "live before-crawl must preserve the observed 102 URL baseline");
assert(beforeReport.issues.some((issue) => issue.type === "url-variant-not-one-hop" && issue.url === "https://www.atelierdeconsultanta.ro/"), "before-crawl must retain evidence for the www host defect");

console.log(`Technical SEO contract passed: ${state.entries.length} canonical URLs, 0 orphans, 0 local broken/redirected links.`);
