import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const { isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const { fileForRoute, parseJsonLd, sitemapRoutes, typesOf } = require("../tools/structured-data-utils");
const SITE = "https://atelierdeconsultanta.ro";

function pageFile(route) {
  const file = fileForRoute(ROOT, route);
  if (fs.existsSync(file)) return file;
  throw new Error(`Lipsește pagina canonică ${route}`);
}

function loadPage(route) {
  return cheerio.load(fs.readFileSync(pageFile(route), "utf8"), { decodeEntities: false });
}

function clean(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function meta($, selector, attribute = "content") {
  return clean($(selector).first().attr(attribute));
}

function assertShareMetadata(route, $) {
  const required = [
    "meta[property='og:title']",
    "meta[property='og:description']",
    "meta[property='og:image']",
    "meta[property='og:image:alt']",
    "meta[name='twitter:title']",
    "meta[name='twitter:description']",
    "meta[name='twitter:image']",
    "meta[name='twitter:image:alt']",
  ];
  for (const selector of required) assert.equal($(selector).length, 1, `${route}: lipsește ${selector}`);
}

function assertUniqueH2(route, $) {
  const headings = $("h2").map((_, node) => clean($(node).text()).toLocaleLowerCase("ro-RO")).get();
  const duplicates = [...new Set(headings.filter((heading, index) => headings.indexOf(heading) !== index))];
  assert.deepEqual(duplicates, [], `${route}: H2 duplicate: ${duplicates.join(", ")}`);
}

function normalizedUrl(value) {
  return new URL(value, SITE).href.replace(/\/$/u, "");
}

function jsonLdValues(value) {
  if (Array.isArray(value)) return value.flatMap(jsonLdValues);
  if (!value || typeof value !== "object") return [];
  return [value, ...Object.values(value).flatMap(jsonLdValues)];
}

const { programs } = loadProgramConfig();
const publicPrograms = programs.filter((program) => isPublicProgram(program) && program.indexable !== false);
const sitemap = new Set(sitemapRoutes(ROOT));
const programSitemapRoutes = sitemapRoutes(ROOT, "sitemap-programs.xml");
const forbiddenWatermark = /(?:generated\s+(?:by|with)\s+ai|ai[- ]generated|creat(?:ă|a|e)\s+de\s+chatgpt|generat(?:ă|a|e)\s+cu\s+ai|\bchatgpt\b|\bopenai\b)/iu;

assert(publicPrograms.length > 0, "registrul trebuie să conțină programe publice indexabile");
assert(programSitemapRoutes.length > 0, "sitemap-programs.xml trebuie să conțină rute");

for (const route of programSitemapRoutes) {
  const $ = loadPage(route);
  const title = clean($("head > title").first().text());
  const description = meta($, "meta[name='description']");
  assert.ok(title.length > 20 && title.length <= 65, `${route}: title neoptimizat (${title.length})`);
  assert.ok(description.length >= 70 && description.length <= 160, `${route}: descriere neoptimizată (${description.length})`);
  assert.equal($("h1").length, 1, `${route}: trebuie un singur H1`);
  assert.equal(normalizedUrl(meta($, "link[rel='canonical']", "href")), normalizedUrl(route), `${route}: canonical greșit`);
  assert.doesNotMatch(meta($, "meta[name='robots']"), /\b(?:noindex|nofollow)\b/iu, `${route}: robots restricționează indexarea sau urmărirea linkurilor`);
  const directAnswer = clean($("[data-aeo-primary-answer],[data-aeo-direct-answer],[data-answer-readiness-direct]").first().text());
  assert(directAnswer.length >= 100 && directAnswer.length <= 900, `${route}: răspunsul direct AEO/GEO are ${directAnswer.length} caractere`);
  assert.ok($("main a[href^='https://']").length > 0, `${route}: lipsește o sursă externă verificabilă în main`);
  assert.equal($("[data-long-form-toc],.long-form-toc,[data-toc-rail],.toc-rail").length, 0, `${route}: Cuprins/rail nu este permis`);
  assert.doesNotMatch(clean($("main").text()), /(?:^|\s)Cuprins(?:\s|$)/iu, `${route}: textul Cuprins nu este permis`);
  assert.doesNotMatch($.html(), forbiddenWatermark, `${route}: urmă textuală de generare AI`);
  assertShareMetadata(route, $);
  const blocks = parseJsonLd($);
  assert.equal(blocks.some((block) => block.error), false, `${route}: JSON-LD invalid`);
  const types = new Set(blocks.flatMap((block) => block.nodes).flatMap(typesOf));
  assert(types.has("WebPage"), `${route}: schema WebPage lipsește`);
  if (/^\/dr-(?:12|14)-afir-/u.test(route)) assert(types.has("Article"), `${route}: schema Article lipsește`);
  assert(types.has("FAQPage"), `${route}: schema FAQPage lipsește`);
}

for (const program of publicPrograms) {
  const route = program.pageUrl;
  const $ = loadPage(route);
  const title = clean($("head > title").first().text());
  const description = meta($, "meta[name='description']");
  assert.ok(title.length > 20 && title.length <= 65, `${route}: title neoptimizat (${title.length})`);
  assert.ok(description.length >= 70 && description.length <= 160, `${route}: descriere neoptimizată (${description.length})`);
  assert.equal($("h1").length, 1, `${route}: trebuie un singur H1`);
  assert.equal(sitemap.has(route), true, `${route}: programul public indexabil lipsește din sitemap`);
  assert.equal(normalizedUrl(meta($, "link[rel='canonical']", "href")), normalizedUrl(route), `${route}: canonical greșit`);
  assert.doesNotMatch(meta($, "meta[name='robots']"), /\b(?:noindex|nofollow)\b/iu, `${route}: robots restricționează indexarea sau urmărirea linkurilor`);
  const officialLinks = $("main a[href^='https://']").map((_, node) => normalizedUrl($(node).attr("href"))).get();
  assert.equal(officialLinks.includes(normalizedUrl(program.sourceUrl)), true, `${route}: sursa oficială primară nu este vizibilă în main`);
  const directAnswer = clean($("[data-aeo-primary-answer],[data-aeo-direct-answer],[data-answer-readiness-direct]").first().text());
  assert(directAnswer.length >= 100 && directAnswer.length <= 900, `${route}: răspunsul direct AEO/GEO are ${directAnswer.length} caractere`);
  assert.equal($("[data-verified-at]").filter((_, node) => $(node).attr("data-verified-at") === program.verifiedAt).length > 0, true, `${route}: data verificării nu este vizibilă`);
  assert.doesNotMatch($.html(), forbiddenWatermark, `${route}: urmă textuală de generare AI`);
  assertShareMetadata(route, $);

  const blocks = parseJsonLd($);
  assert.equal(blocks.some((block) => block.error), false, `${route}: JSON-LD invalid`);
  const nodes = blocks.flatMap((block) => block.nodes);
  const types = new Set(nodes.flatMap(typesOf));
  assert(types.has("WebPage"), `${route}: schema WebPage lipsește`);
  assert(types.has("FinancialIncentive"), `${route}: schema FinancialIncentive lipsește`);
  const values = nodes.flatMap(jsonLdValues);
  assert(values.some((value) => normalizedUrl(value.url || value["@id"] || SITE) === normalizedUrl(program.sourceUrl)), `${route}: JSON-LD nu citează sursa oficială primară`);
  assert(values.some((value) => value.dateModified === program.lastMeaningfulUpdate), `${route}: dateModified nu corespunde ultimei actualizări semnificative`);
}

for (const route of ["/gal-afir", "/femeia-antreprenor-2026", "/calculator-soc", "/dr12-afir", "/dr14", "/investitii-modernizarea-microintreprinderilor-apel-2"]) {
  const $ = loadPage(route);
  const title = clean($("head > title").first().text());
  const description = meta($, "meta[name='description']");
  assert.ok(title.length > 20 && title.length <= 65, `${route}: title neoptimizat (${title.length})`);
  assert.ok(description.length >= 70 && description.length <= 160, `${route}: descriere neoptimizată (${description.length})`);
  assert.equal($("h1").length, 1, `${route}: trebuie un singur H1`);
  assert.ok($("a[href^='https://']").length > 0, `${route}: lipsește o sursă externă verificabilă`);
  assertShareMetadata(route, $);
}

{
  const route = "/gal-afir";
  const $ = loadPage(route);
  assert.match(clean($("head > title").first().text()), /GAL AFIR 2026/iu);
  assert.match(clean($("h1").text()), /GAL AFIR \/ DR-36/iu);
  assert.equal($("a[href^='https://gal.afir.ro']").length > 0, true, `${route}: lipsește platforma oficială AFIR GAL`);
  assert.equal($("h2").filter((_, node) => /exemplu numeric de cofinanțare/iu.test(clean($(node).text()))).length, 0, `${route}: exemplul generic de cofinanțare nu este permis`);
  assertUniqueH2(route, $);
}

{
  const route = "/femeia-antreprenor-2026";
  const $ = loadPage(route);
  const text = clean($("main").text());
  assert.match(clean($("head > title").first().text()), /Femeia Antreprenor 2026/iu);
  assert.match(clean($("h1").text()), /Femeia Antreprenor 2026/iu);
  assert.match(text, /nu (?:există|are încă) o procedură/iu, `${route}: trebuie delimitată ediția 2026 neconfirmată`);
  assert.equal($("h2").filter((_, node) => /exemplu numeric de cofinanțare/iu.test(clean($(node).text()))).length, 0, `${route}: exemplul generic de cofinanțare nu este permis`);
}

{
  const route = "/calculator-soc";
  const $ = loadPage(route);
  const jsonLd = $("script[type='application/ld+json']").map((_, node) => $(node).text()).get().join("\n");
  assert.match(clean($("h1").text()), /Calculator SO(?:\/SOC)? .*AFIR/iu);
  assert.match(jsonLd, /WebApplication/u, `${route}: lipsește schema WebApplication`);
  assert.ok($("[data-aeo-direct-answer]").length >= 2, `${route}: sunt necesare răspunsuri directe reutilizabile`);
}

console.log(`AI citation readiness contract: PASS (${programSitemapRoutes.length} rute din sitemap-ul de programe, ${publicPrograms.length} programe publice indexabile + verificări prioritare și calculator).`);
