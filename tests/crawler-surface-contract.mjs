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
const { collectSiteState } = require("../tools/generate-sitemap");
const { buildInventory } = require("../tools/generate-route-inventory");
const { sitemapUrls } = require("../tools/sitemap-utils");
const { headerRuleMatchesPath, parseHeaders, parseRobots } = require("../tools/crawler-policy");
const { isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const { syncLlmsText } = require("../tools/sync-program-factual-governance");

const headers = parseHeaders(fs.readFileSync(path.join(ROOT, "_headers"), "utf8"));
const robots = parseRobots(fs.readFileSync(path.join(ROOT, "robots.txt"), "utf8"));
const state = collectSiteState();
const publicRoutes = buildInventory().routes;
const sitemap = new Set(sitemapUrls(ROOT));
const entryByUrl = new Map(state.entries.map((entry) => [entry.url, entry]));
const programs = loadProgramConfig().programs;

function xRobotsFor(pathname) {
  return headers
    .filter((rule) => headerRuleMatchesPath(rule.pattern, pathname))
    .flatMap((rule) => rule.headers)
    .filter((header) => /^x-robots-tag:/iu.test(header))
    .map((header) => header.replace(/^x-robots-tag:\s*/iu, "").trim().toLowerCase());
}

assert.deepEqual(robots.sitemaps, [`${SITE}/sitemap.xml`], "robots.txt trebuie să indice o singură dată sitemap-ul canonical");
const wildcard = robots.groups.find((group) => group.agents.includes("*"));
assert(wildcard, "robots.txt trebuie să aibă un grup wildcard");
assert(wildcard.rules.some((rule) => rule.directive === "allow" && rule.value === "/"), "grupul wildcard trebuie să permită suprafața publică");
assert(wildcard.rules.some((rule) => rule.directive === "disallow" && rule.value === "/api"), "endpointurile tehnice trebuie protejate");
assert.equal(wildcard.rules.some((rule) => rule.directive === "disallow" && /\.(?:css|js)(?:$|\?)/iu.test(rule.value)), false, "robots.txt nu poate bloca CSS sau JS");

for (const entry of publicRoutes) {
  const pathname = new URL(entry.canonicalUrl).pathname;
  const html = fs.readFileSync(path.join(ROOT, entry.sourceFile), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const metaRobots = $("meta[name='robots']").attr("content") || "index, follow";
  assert.doesNotMatch(metaRobots, /\bnoindex\b/iu, `${entry.route}: inventarul public indexabil nu poate avea meta noindex`);
  for (const directive of xRobotsFor(pathname)) {
    assert.doesNotMatch(directive, /\bnoindex\b/iu, `${entry.route}: X-Robots-Tag contrazice pagina publică indexabilă`);
  }
}

for (const url of sitemap) {
  const entry = entryByUrl.get(url);
  assert(entry, `${url}: URL-ul sitemap trebuie să aibă o sursă locală 200/indexabilă`);
  const html = fs.readFileSync(path.join(ROOT, entry.sourceFile), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  assert.equal($("link[rel~='canonical']").attr("href"), url, `${url}: canonicalul local trebuie să fie self`);
  assert.doesNotMatch($("meta[name='robots']").attr("content") || "", /\bnoindex\b/iu, `${url}: sitemap-ul nu poate conține noindex`);
}

const redirectSources = fs.readFileSync(path.join(ROOT, "_redirects"), "utf8")
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => line.split(/\s+/u))
  .filter(([source, , status = "302"]) => /^3\d\d$/u.test(status) && !/[*:]/u.test(source))
  .map(([source]) => source);
for (const source of redirectSources) {
  for (const directive of xRobotsFor(source)) {
    assert.doesNotMatch(directive, /(?:^|[,\s])index(?:[,\s]|$)/iu, `${source}: un redirect nu trebuie să declare X-Robots-Tag index`);
  }
}

for (const pathname of ["/404", "/404.html"]) {
  const directives = xRobotsFor(pathname).join(", ");
  assert.match(directives, /\bnoindex\b/iu, `${pathname}: lipsește X-Robots-Tag noindex`);
  assert.match(directives, /\bfollow\b/iu, `${pathname}: linkurile utile trebuie să rămână follow`);
  assert.doesNotMatch(directives, /\bnofollow\b/iu, `${pathname}: X-Robots-Tag contrazice meta robots`);
}

const expectedLlmsDate = programs
  .filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget)
  .reduce((latest, program) => program.verifiedAt > latest ? program.verifiedAt : latest, "0000-00-00");
const llmsSource = fs.readFileSync(path.join(ROOT, "llms.txt"), "utf8");
const resyncedLlms = syncLlmsText(llmsSource.replace(/^Ultima actualizare:.*$/mu, "Ultima actualizare: 2000-01-01"), programs);
assert.match(resyncedLlms, new RegExp(`^Ultima actualizare: ${expectedLlmsDate}$`, "mu"), "sincronizarea llms trebuie să derive data din registry");

console.log(`Crawler surface contract PASS: ${sitemap.size} sitemap URLs, ${publicRoutes.length} public indexable routes, ${redirectSources.length} redirects without index headers.`);
