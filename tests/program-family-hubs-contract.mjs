#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "https://atelierdeconsultanta.ro";
const EXPECTED_HUB_ROUTES = [
  "/afir",
  "/fonduri-regionale",
  "/fonduri-europene-digitalizare",
  "/finantari-panouri-fotovoltaice",
  "/fonduri-europene-imm"
];
const { catalogPrograms, hasOfficialSource, isPublicProgram, loadProgramConfig, statusStatement } = require("../tools/program-factual-governance");
const { fileForRoute, hasType, parseJsonLd } = require("../tools/structured-data-utils");
const hubConfig = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-family-hubs.json"), "utf8"));
const navigation = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "main-navigation.json"), "utf8"));
const { programs } = loadProgramConfig();
const catalog = catalogPrograms(programs);
const catalogIds = new Set(catalog.map((program) => program.id));
const homepage = cheerio.load(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"), { decodeEntities: false });
const hubDocuments = new Map();
const hubTitles = new Set();
const hubDescriptions = new Set();
const hubIntros = new Set();

const proInfra = programs.find((program) => program.slug === "pro-infra");
assert(proInfra, "PRO INFRA must exist in the program registry");
assert.equal(proInfra.family, "energie", "PRO INFRA is a national energy-efficiency program, not a regional program");
assert.equal(proInfra.discovery.parentHub, "/finantari-panouri-fotovoltaice", "PRO INFRA must be assigned to the Energy hub");
assert.deepEqual(proInfra.discovery.regions, ["national"], "PRO INFRA coverage must remain explicitly national");

function routeFile(route) {
  return path.join(ROOT, route.replace(/^\//u, ""), "index.html");
}

function wordCount(value) {
  return String(value || "").trim().split(/\s+/u).filter(Boolean).length;
}

function programsForHub(route) {
  return catalog
    .filter((program) => program.discovery.parentHub === route)
    .sort((left, right) => (left.presentation?.order ?? 999) - (right.presentation?.order ?? 999) || left.name.localeCompare(right.name, "ro"));
}

assert.deepEqual(hubConfig.hubs.map((hub) => hub.route), EXPECTED_HUB_ROUTES, "the five approved canonical routes must be reused");
assert.equal(hubConfig.urlConvention.decision, "reuse_existing_canonical_routes", "URL convention must preserve canonical routes");
assert.equal(hubConfig.urlConvention.approvalRequiredForNewRoutes, true, "new routes must remain behind SEO approval");
const menuHubs = navigation.primaryDestinations.find((item) => item.id === "programe").items.map((item) => item.href);
assert.deepEqual(menuHubs, EXPECTED_HUB_ROUTES, "navigation and family hub architecture must use the same routes");

for (const hub of hubConfig.hubs) {
  assert.ok(fs.existsSync(routeFile(hub.route)), `${hub.route}: canonical HTML is missing`);
  const $ = cheerio.load(fs.readFileSync(routeFile(hub.route), "utf8"), { decodeEntities: false });
  hubDocuments.set(hub.route, $);
  const title = $("head > title").text().trim();
  const description = $("meta[name='description']").attr("content") || "";
  assert.ok(title.length >= 30 && title.length <= 70, `${hub.route}: title invalid`);
  assert.ok(description.length >= 100 && description.length <= 170, `${hub.route}: meta description invalidă`);
  assert.equal($("meta[property='og:title']").attr("content"), title, `${hub.route}: OG title diferă`);
  assert.equal($("meta[property='og:description']").attr("content"), description, `${hub.route}: OG description diferă`);
  assert.equal(new URL($("meta[property='og:url']").attr("content"), SITE).pathname, hub.route, `${hub.route}: OG URL greșit`);
  assert.equal(new URL($("link[rel='canonical']").attr("href"), SITE).pathname, hub.route, `${hub.route}: canonical must remain self-referential`);
  assert.match($("meta[name='robots']").attr("content") || "", /index/iu, `${hub.route}: hub must remain indexable`);
  assert.doesNotMatch($("meta[name='robots']").attr("content") || "", /noindex/iu, `${hub.route}: noindex accidental`);
  const jsonLd = parseJsonLd($);
  assert.ok(jsonLd.length && jsonLd.every((block) => !block.error), `${hub.route}: JSON-LD invalid`);
  assert.ok(jsonLd.flatMap((block) => block.nodes).some((node) => hasType(node, "BreadcrumbList")), `${hub.route}: BreadcrumbList lipsește`);
  assert.equal($("nav.breadcrumb[aria-label='Breadcrumb']").length, 1, `${hub.route}: breadcrumb vizibil lipsește`);
  assert.equal($("h1").length, 1, `${hub.route}: exactly one H1 is required`);
  assert.equal($("h1").first().text().trim(), hub.h1, `${hub.route}: H1 must come from hub config`);
  assert.equal($("header.hero > p").first().text().trim(), hub.intro, `${hub.route}: introduction must come from hub config`);
  assert.equal($("main[data-program-family-hub]").attr("data-program-family-hub"), hub.id, `${hub.route}: family ID invalid`);
  assert.ok(wordCount(hub.intro) >= 50 && wordCount(hub.intro) <= 80, `${hub.route}: introduction must contain 50–80 words`);
  assert.ok(wordCount($("main").text()) >= 400, `${hub.route}: family page is thin`);
  assert.ok(hub.faqs.length >= 5 && hub.faqs.length <= 8, `${hub.route}: FAQ count must be 5–8`);
  assert.equal($(".program-family-faq details").length, hub.faqs.length, `${hub.route}: visible FAQ count must match config`);
  assert.equal($("[data-program-hub-filters] select").length, 4, `${hub.route}: four registry filters are required`);
  assert.deepEqual(
    $("[data-program-hub-filters] select").map((_, element) => $(element).attr("name")).get(),
    ["solicitant", "regiune", "investitie", "status"],
    `${hub.route}: shareable filter parameter names changed`
  );
  assert.equal($("[data-program-results-status]").attr("aria-live"), "polite", `${hub.route}: results must be announced politely`);
  assert.equal($("[data-program-hub-filters]").is("form"), false, `${hub.route}: filters must not behave as a crawlable GET form`);
  assert.equal($("a[href*='?solicitant='], a[href*='?regiune='], a[href*='?investitie='], a[href*='?status=']").length, 0, `${hub.route}: no indexable filter links are allowed`);
  assert.equal($(".program-family-how #program-family-how-title").text().trim(), "Cum alegi", `${hub.route}: how-to section is missing`);
  assert.equal($(".program-family-related a").length, hub.relatedLinks.length, `${hub.route}: relevant resources must match config`);
  for (const link of hub.relatedLinks) assert.ok(fs.existsSync(fileForRoute(ROOT, link.href)), `${hub.route}: internal link inexistent ${link.href}`);
  assert.ok($("a[href='/verificare-eligibilitate-fonduri-europene']").length >= 1, `${hub.route}: project verification CTA is missing`);
  const expectedFamilyPrograms = programsForHub(hub.route);
  const renderedFamilyIds = $("[data-program-card]").map((_, card) => $(card).attr("data-program-id")).get();
  assert.deepEqual(renderedFamilyIds, expectedFamilyPrograms.map((program) => program.id), `${hub.route}: lista nu este derivată din registry`);
  assert.match($("[data-program-results-status]").text(), new RegExp(`^${expectedFamilyPrograms.length} `), `${hub.route}: count nederivat`);
  hubTitles.add(title);
  hubDescriptions.add(description);
  hubIntros.add(hub.intro);
}

assert.equal(hubTitles.size, hubConfig.hubs.length, "family titles must be distinct");
assert.equal(hubDescriptions.size, hubConfig.hubs.length, "family meta descriptions must be distinct");
assert.equal(hubIntros.size, hubConfig.hubs.length, "family introductions must be distinct");

assert.equal(hubDocuments.get("/fonduri-regionale")("[data-program-card][data-program-id='pro-infra']").length, 0, "PRO INFRA must not appear in the Regional / ADR hub");
assert.equal(hubDocuments.get("/finantari-panouri-fotovoltaice")("[data-program-card][data-program-id='pro-infra'] .program-family-card__scope").text().includes("Național"), true, "PRO INFRA must be visibly labeled as national in the Energy hub");

const hubRoutes = new Set(EXPECTED_HUB_ROUTES);
for (const [dictionaryName, dictionary] of Object.entries(hubConfig.filters)) {
  assert.ok(Object.keys(dictionary).length > 0, `${dictionaryName}: controlled dictionary is empty`);
}

for (const program of programs) {
  const discovery = program.discovery;
  assert.ok(discovery && hubRoutes.has(discovery.parentHub), `${program.slug}: exactly one valid parent hub is required`);
  for (const [field, dictionaryName] of [["applicantTypes", "applicantTypes"], ["regions", "regions"], ["investmentTypes", "investmentTypes"]]) {
    assert.ok(Array.isArray(discovery[field]) && discovery[field].length, `${program.slug}: ${field} is empty`);
    for (const value of discovery[field]) assert.ok(hubConfig.filters[dictionaryName][value], `${program.slug}: uncontrolled ${field} value ${value}`);
  }

  const $hub = hubDocuments.get(discovery.parentHub);
  const card = $hub(`[data-program-card][data-program-id='${program.id}']`);
  const shouldList = catalogIds.has(program.id);
  assert.equal(card.length, shouldList ? 1 : 0, `${program.slug}: public card visibility contradicts publication state`);
  for (const [route, document] of hubDocuments) {
    if (route !== discovery.parentHub) assert.equal(document(`[data-program-card][data-program-id='${program.id}']`).length, 0, `${program.slug}: duplicate in ${route}`);
  }
  if (!shouldList) continue;
  assert.ok(hasOfficialSource(program), `${program.slug}: a listed card requires complete official provenance`);
  assert.equal(card.attr("data-program-status"), program.status, `${program.slug}: status differs from registry`);
  assert.equal(card.attr("data-status-label"), program.statusLabel, `${program.slug}: status label differs from registry`);
  assert.equal(card.attr("data-verified-at"), program.verifiedAt, `${program.slug}: verification date differs from registry`);
  assert.equal(card.attr("data-source-url"), program.sourceUrl, `${program.slug}: source URL differs from registry`);
  assert.ok(card.text().includes(statusStatement(program)), `${program.slug}: complete status statement is missing`);
  assert.doesNotMatch(card.find(".program-family-card__status strong").text().trim(), /\.\.$/u, `${program.slug}: status statement has duplicate terminal punctuation`);
  assert.ok(card.find("time").attr("datetime") === program.verifiedAt, `${program.slug}: machine-readable verification date is missing`);
  assert.ok(card.find("p").toArray().some((node) => $hub(node).text().includes("Beneficiar:")), `${program.slug}: beneficiary field is missing`);
  assert.ok(card.text().includes(program.cardSummary), `${program.slug}: registry summary is missing`);
  assert.equal(card.find(`a.btn[href='${program.pageUrl}']`).text().trim(), "Vezi condițiile", `${program.slug}: canonical CTA is missing`);
  assert.equal(card.find(`a[href='${program.sourceUrl}']`).length, 1, `${program.slug}: official source link is missing`);
}

const allFamilyCards = [...hubDocuments.values()].flatMap(($hub) => $hub("[data-program-card]").toArray().map((card) => ({
  id: $hub(card).attr("data-program-id"),
  href: $hub(card).find("a.btn").attr("href")
})));
assert.equal(allFamilyCards.length, catalog.length, "reuniunea family hubs diferă de catalog");
assert.equal(new Set(allFamilyCards.map((card) => card.id)).size, catalog.length, "un program apare în mai multe familii");
assert.equal(new Set(allFamilyCards.map((card) => card.href)).size, catalog.length, "un canonical link apare în mai multe familii");
assert.deepEqual(new Set(allFamilyCards.map((card) => card.id)), new Set(catalog.map((program) => program.id)), "catalog orphan sau program lipsă din familii");

for (const pending of programs.filter((program) => !isPublicProgram(program))) {
  for (const $hub of hubDocuments.values()) assert.equal($hub(`[data-program-id='${pending.id}']`).length, 0, `${pending.slug}: pending program leaked into a public hub`);
}

// Click-depth contract: homepage -> family hub -> public program (maximum two navigational clicks).
for (const hub of hubConfig.hubs) assert.ok(homepage(`a[href='${hub.route}']`).length, `${hub.route}: homepage must link directly to every family hub`);
for (const program of programs.filter((item) => isPublicProgram(item) && item.discovery.listed !== false)) {
  const depth = hubDocuments.get(program.discovery.parentHub)(`a[href='${program.pageUrl}']`).length ? 2 : Number.POSITIVE_INFINITY;
  assert.ok(depth <= 3, `${program.slug}: public program exceeds three clicks from homepage`);
}

const behavior = fs.readFileSync(path.join(ROOT, "assets", "program-family-hubs.js"), "utf8");
const stylesheet = fs.readFileSync(path.join(ROOT, "assets", "program-family-hubs.css"), "utf8");
assert.match(behavior, /history\.replaceState/u, "filters must keep a shareable URL without navigation");
assert.doesNotMatch(behavior, /innerHTML\s*=/u, "filter behavior must not rebuild factual card HTML locally");

const energyRoute = "/finantari-panouri-fotovoltaice";
const energyHtml = fs.readFileSync(routeFile(energyRoute), "utf8")
  .replace(/<link[^>]+program-family-hubs\.css[^>]*>/iu, `<style>${stylesheet}</style>`)
  .replace(/<script[^>]+program-family-hubs\.js[^>]*><\/script>/iu, `<script>${behavior}</script>`);
const energyPrograms = programs.filter((program) => program.discovery.parentHub === energyRoute && isPublicProgram(program) && program.discovery.listed !== false);
const chosenStatus = energyPrograms[0].status;
const expectedStatusCount = energyPrograms.filter((program) => program.status === chosenStatus).length;
const browser = await chromium.launch({ headless: true });

try {
  for (const width of [320, 768, 1366]) {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    await page.route("http://atelier.test/**", (route) => {
      if (route.request().resourceType() === "document") route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: energyHtml });
      else route.abort();
    });
    await page.goto(`http://atelier.test${energyRoute}?utm_source=qa&status=${chosenStatus}`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction((status) => document.querySelector("select[name='status']")?.value === status, chosenStatus);
    assert.equal(await page.locator("[data-program-card]:visible").count(), expectedStatusCount, `${width}px: query-string status filter failed`);
    assert.match(await page.locator("[data-program-results-status]").textContent(), new RegExp(`^${expectedStatusCount} `), `${width}px: live result count is wrong`);
    assert.equal(new URL(page.url()).searchParams.get("utm_source"), "qa", `${width}px: existing attribution parameter was lost`);
    assert.equal(new URL(page.url()).searchParams.get("status"), chosenStatus, `${width}px: status filter is not shareable`);

    await page.locator("[data-program-filters-reset]").click();
    await page.waitForFunction((count) => document.querySelectorAll("[data-program-card]:not([hidden])").length === count, energyPrograms.length);
    assert.equal(await page.locator("[data-program-card]:visible").count(), energyPrograms.length, `${width}px: reset must restore all cards`);
    assert.equal(new URL(page.url()).searchParams.has("status"), false, `${width}px: reset must remove filter query`);
    assert.equal(new URL(page.url()).searchParams.get("utm_source"), "qa", `${width}px: reset must preserve attribution query`);

    const targets = await page.locator(".program-family-filter select, .program-family-filters__reset").evaluateAll((elements) => elements.map((element) => element.getBoundingClientRect().height));
    assert.ok(targets.every((height) => height >= 44), `${width}px: filter targets must be at least 44 CSS px high`);
    const overflow = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
    assert.ok(overflow.content <= overflow.viewport + 1, `${width}px: horizontal overflow ${overflow.content}/${overflow.viewport}`);
    await page.close();
  }
} finally {
  await browser.close();
}

console.log(`Program family hubs contract passed: ${hubConfig.hubs.length} hubs, ${programs.length} assigned programs and accessible shareable filters.`);
