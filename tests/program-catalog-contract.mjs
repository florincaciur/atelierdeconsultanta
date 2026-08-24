#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const CATALOG_ROUTE = "/fonduri-europene";
const CATALOG_FILE = path.join(ROOT, "fonduri-europene", "index.html");
const { catalogPrograms, loadProgramConfig } = require("../tools/program-factual-governance");
const { fileForRoute, hasType, parseJsonLd } = require("../tools/structured-data-utils");
const familyConfig = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-family-hubs.json"), "utf8"));
const programs = loadProgramConfig().programs;
const expected = catalogPrograms(programs);
const expectedById = new Map(expected.map((program) => [program.id, program]));
const familyByRoute = new Map(familyConfig.hubs.map((hub) => [hub.route, hub]));
const html = fs.readFileSync(CATALOG_FILE, "utf8");
const $ = cheerio.load(html, { decodeEntities: false });

assert.equal($("h1").length, 1, "catalogul trebuie să aibă un singur H1");
assert.ok($("main").text().trim().split(/\s+/u).length >= 500, "catalogul nu poate fi thin content");
assert.equal(new URL($("link[rel='canonical']").attr("href"), SITE).pathname, CATALOG_ROUTE, "canonical catalog greșit");
assert.match($("meta[name='robots']").attr("content") || "", /index/iu, "catalogul trebuie indexat");
assert.doesNotMatch($("meta[name='robots']").attr("content") || "", /noindex/iu, "catalog noindex accidental");
const title = $("head > title").text().trim();
const description = $("meta[name='description']").attr("content") || "";
assert.ok(title.length >= 30 && title.length <= 70, "title catalog invalid");
assert.ok(description.length >= 100 && description.length <= 170, "description catalog invalidă");
assert.equal($("meta[property='og:title']").attr("content"), title);
assert.equal($("meta[property='og:description']").attr("content"), description);
assert.equal(new URL($("meta[property='og:url']").attr("content"), SITE).pathname, CATALOG_ROUTE);
const jsonLd = parseJsonLd($);
assert.ok(jsonLd.length && jsonLd.every((block) => !block.error), "JSON-LD catalog invalid");
assert.ok(jsonLd.flatMap((block) => block.nodes).some((node) => hasType(node, "BreadcrumbList")), "BreadcrumbList catalog lipsește");
assert.equal($("nav.breadcrumb[aria-label='Breadcrumb']").length, 1, "breadcrumb vizibil catalog lipsește");

const cards = $("[data-program-catalog-entry]");
const ids = cards.map((_, card) => $(card).attr("data-program-id")).get();
const slugs = cards.map((_, card) => $(card).attr("data-program-slug")).get();
const links = cards.map((_, card) => $(card).attr("href")).get();
assert.equal(cards.length, expected.length, "fiecare program catalogEnabled trebuie să apară exact o dată");
assert.equal(Number($("[data-program-catalog-count]").text()), expected.length, "count-ul catalogului nu este derivat");
assert.deepEqual(ids, expected.map((program) => program.id), "ordinea sau selecția catalogului diferă de registry");
assert.equal(new Set(ids).size, ids.length, "ID duplicat în catalog");
assert.equal(new Set(slugs).size, slugs.length, "slug duplicat în catalog");
assert.equal(new Set(links).size, links.length, "canonical link duplicat în catalog");

cards.each((_, card) => {
  const node = $(card);
  const program = expectedById.get(node.attr("data-program-id"));
  assert.ok(program, `catalog orphan ${node.attr("data-program-id")}`);
  const family = familyByRoute.get(program.discovery.parentHub);
  assert.ok(family, `${program.slug}: family route invalid`);
  assert.equal(node.attr("data-program-slug"), program.slug);
  assert.equal(node.attr("data-family-id"), family.id);
  assert.equal(node.attr("data-program-status"), program.status);
  assert.equal(node.attr("data-status-label"), program.statusLabel);
  assert.equal(node.attr("data-verified-at"), program.verifiedAt);
  assert.equal(node.attr("data-source-url"), program.sourceUrl);
  assert.equal(node.attr("href"), program.pageUrl);
  assert.equal(node.find("small").text().trim(), program.statusLabel);
  assert.ok(fs.existsSync(fileForRoute(ROOT, program.pageUrl)), `${program.slug}: canonical route missing`);
});

for (const hub of familyConfig.hubs) {
  assert.equal($("#familii-programe a").filter((_, link) => $(link).attr("href") === hub.route).length, 1, `${hub.route}: family link missing from catalog`);
}

const familyIds = familyConfig.hubs.flatMap((hub) => {
  const family = cheerio.load(fs.readFileSync(fileForRoute(ROOT, hub.route), "utf8"), { decodeEntities: false });
  return family("[data-program-card]").map((_, card) => family(card).attr("data-program-id")).get();
});
assert.equal(familyIds.length, expected.length, "family union count differs from catalog");
assert.deepEqual(new Set(familyIds), new Set(ids), "family union contains missing or orphan programs");

const generator = fs.readFileSync(path.join(ROOT, "tools", "sync-editorial-clusters.js"), "utf8");
assert.doesNotMatch(generator, /FEATURED_FUNDING_SLUGS/u, "catalogul nu poate folosi o listă paralelă de slug-uri");
assert.match(generator, /catalogPrograms\(PROGRAM_REGISTRY\)/u, "catalogul trebuie derivat prin selecția comună din registry");

const browserDocument = cheerio.load(html, { decodeEntities: false });
browserDocument("link[rel='stylesheet'][href^='/assets/']").each((_, link) => {
  const href = browserDocument(link).attr("href").split("?")[0];
  const file = path.join(ROOT, href.replace(/^\//u, ""));
  if (fs.existsSync(file)) browserDocument(link).replaceWith(`<style>${fs.readFileSync(file, "utf8")}</style>`);
});
browserDocument("script, link[href^='http'], link[href^='//']").remove();
const browser = await chromium.launch({ headless: true });
try {
  for (const width of [320, 1366]) {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    const consoleErrors = [];
    page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
    await page.route("http://catalog.test/**", (route) => route.request().resourceType() === "document"
      ? route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: browserDocument.html() })
      : route.abort());
    await page.goto(`http://catalog.test${CATALOG_ROUTE}`, { waitUntil: "domcontentloaded" });
    assert.equal(await page.locator("[data-program-catalog-entry]:visible").count(), expected.length, `${width}px: catalog entries missing`);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
    assert.ok(overflow <= 1, `${width}px: horizontal overflow ${overflow}`);
    const first = page.locator("[data-program-catalog-entry]").first();
    assert.ok((await first.boundingBox()).height >= 44, `${width}px: catalog target smaller than 44px`);
    await first.focus();
    assert.equal(await first.evaluate((element) => element === document.activeElement), true, `${width}px: catalog link not focusable`);
    assert.deepEqual(consoleErrors, [], `${width}px: console errors`);
    await page.close();
  }
} finally {
  await browser.close();
}

console.log(`Program catalog contract PASS: ${expected.length} unique registry entries across ${familyConfig.hubs.length} families.`);
