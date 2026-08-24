#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "https://atelierdeconsultanta.ro";
const { buildInventory, validateInventory } = require("../tools/generate-route-inventory");
const { localCanonicalAudit, parseRedirects, traceRedirect, walkHtml } = require("../scripts/verify-canonical-map");

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function cleanPath(value) {
  const parsed = new URL(value, SITE);
  return parsed.pathname === "/" ? "/" : parsed.pathname.replace(/\/+$/u, "");
}

function routeForHtml(file) {
  const relative = toPosix(path.relative(ROOT, file));
  if (relative === "index.html") return "/";
  if (relative.endsWith("/index.html")) return `/${relative.slice(0, -"/index.html".length)}`;
  return `/${relative}`;
}

const inventory = buildInventory();
assert.deepEqual(validateInventory(inventory), [], "inventarul stabil de rute trebuie să rămână valid");
assert.equal(inventory.routes.length, 105, "schimbarea inventarului canonical necesită review explicit");

const canonicalUrls = inventory.routes.map((route) => route.canonicalUrl);
const canonicalSet = new Set(canonicalUrls);
assert.equal(canonicalSet.size, canonicalUrls.length, "canonical public duplicat");
assert.equal(new Set(inventory.routes.map((route) => route.route)).size, inventory.routes.length, "rută publică duplicată");

for (const route of inventory.routes) {
  const parsed = new URL(route.canonicalUrl);
  assert.equal(parsed.origin, SITE, `${route.route}: canonical host/protocol invalid`);
  assert.equal(parsed.port, "", `${route.route}: canonical port explicit`);
  assert.equal(parsed.search, "", `${route.route}: canonical cu query string`);
  assert.equal(parsed.hash, "", `${route.route}: canonical cu fragment`);
  if (parsed.pathname !== "/") {
    assert.doesNotMatch(parsed.pathname, /(?:\/$|\.html$|\/index\.html$)/iu, `${route.route}: formă canonical necurată`);
  }
  const source = path.join(ROOT, route.sourceFile);
  assert.ok(fs.existsSync(source), `${route.route}: sursa canonical lipsește`);
  const $ = cheerio.load(fs.readFileSync(source, "utf8"), { decodeEntities: false });
  assert.equal($("link[rel~='canonical']").length, 1, `${route.route}: trebuie exact un canonical`);
  assert.equal($("link[rel~='canonical']").attr("href"), route.canonicalUrl, `${route.route}: canonical neself`);
  assert.equal($("meta[property='og:url']").length, 1, `${route.route}: trebuie exact un og:url`);
  assert.equal($("meta[property='og:url']").attr("content"), route.canonicalUrl, `${route.route}: og:url diferă de canonical`);
  assert.doesNotMatch($("meta[name='robots']").attr("content") || "", /\bnoindex\b/iu, `${route.route}: noindex accidental`);
}

const redirects = parseRedirects();
const exactRedirects = redirects.filter((rule) => !rule.dynamic);
assert.equal(new Set(exactRedirects.map((rule) => rule.source)).size, exactRedirects.length, "sursă de redirect exact duplicată");
for (const rule of exactRedirects) {
  const trace = traceRedirect(rule.source, redirects);
  assert.equal(trace.loop, false, `${rule.source}: redirect loop`);
  assert.equal(trace.chain.length, 1, `${rule.source}: redirectul trebuie să fie direct`);
  const targetUrl = new URL(trace.finalPath, SITE);
  assert.equal(targetUrl.origin, SITE, `${rule.source}: redirect extern neaprobat`);
  assert.ok(canonicalSet.has(`${SITE}${cleanPath(targetUrl.href)}`), `${rule.source}: destinația 301 nu este o rută canonical 200`);
  assert.equal(canonicalSet.has(`${SITE}${cleanPath(rule.source)}`), false, `${rule.source}: sursa 301 apare în setul indexabil`);
}

const registry = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8"));
const retiredRoutes = new Set((registry.pages || []).filter((page) => page.redirectTo).map((page) => `/${page.slug}`));
for (const page of registry.pages || []) {
  const source = `/${page.slug}`;
  const trace = traceRedirect(source, redirects);
  if (!trace.chain.length) continue;
  assert.equal(page.redirectTo, trace.finalPath, `${source}: definiția generatorului nu declară destinația 301`);
}

for (const file of walkHtml()) {
  const relative = toPosix(path.relative(ROOT, file));
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const canonicals = $("link[rel~='canonical']").map((_, element) => $(element).attr("href")).get();
  for (const canonical of canonicals) {
    const parsed = new URL(canonical);
    assert.equal(parsed.origin, SITE, `${relative}: canonical host/protocol invalid`);
    assert.equal(parsed.search, "", `${relative}: canonical cu query string`);
    assert.equal(parsed.hash, "", `${relative}: canonical cu fragment`);
    assert.equal(traceRedirect(cleanPath(canonical), redirects).chain.length, 0, `${relative}: canonical către redirect`);
  }

  const route = routeForHtml(file);
  const trace = traceRedirect(route, redirects);
  if (!trace.chain.length) continue;
  const logicalRoute = route.replace(/(?:\/index\.html|\.html|\/)$/iu, "") || "/";
  if (!retiredRoutes.has(logicalRoute)) continue;
  const declaredTarget = registry.pages.find((page) => `/${page.slug}` === logicalRoute).redirectTo;
  const expected = `${SITE}${declaredTarget}`;
  assert.equal(canonicals.length, 1, `${relative}: artefactul redirect trebuie să aibă un singur canonical`);
  assert.equal(canonicals[0], expected, `${relative}: canonicalul artefactului nu indică destinația declarată`);
  assert.match($("meta[name='robots']").attr("content") || "", /\bnoindex\b/iu, `${relative}: definiție retrasă fără noindex defensiv`);
  const ogUrl = $("meta[property='og:url']").attr("content");
  if (ogUrl) assert.equal(ogUrl, expected, `${relative}: og:url al artefactului diferă de destinația 301`);
  const refresh = $("meta[http-equiv='refresh']").attr("content");
  if (refresh) assert.match(refresh, new RegExp(`url=${declaredTarget.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}$`, "u"), `${relative}: meta refresh nu merge direct la canonical`);
  for (const match of html.matchAll(/window\.location\.replace\(["']([^"']+)["']\)/giu)) {
    assert.equal(match[1], declaredTarget, `${relative}: fallback JS nu merge direct la canonical`);
  }
}

assert.deepEqual(localCanonicalAudit().problems, [], "auditul canonical complet trebuie să fie curat");

console.log(`Canonical policy contract PASS: ${inventory.routes.length} indexable routes, ${exactRedirects.length} direct redirects, apex HTTPS and zero redirect canonicals.`);
