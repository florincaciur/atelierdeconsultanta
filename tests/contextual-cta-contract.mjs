import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { contactHref, loadConfig } = require("../tools/sync-contextual-ctas");
const { validateContactPayload } = await import("../cloudflare/domain-seo-redirects.mjs");
const config = loadConfig();

assert.equal(config.pages.length, 6);
for (const page of config.pages) {
  const html = fs.readFileSync(path.join(ROOT, page.file), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const primary = $("[data-contextual-hero-cta]");
  assert.equal(primary.length, 1, `${page.route}: CTA contextual principal lipsă sau duplicat`);
  assert.equal(primary.text().trim(), page.primary, `${page.route}: copy principal divergent`);
  assert.equal(primary.attr("href"), contactHref(page), `${page.route}: context URL divergent`);
  assert.equal(primary.attr("data-analytics-event"), "cta_click");
  assert.equal(primary.attr("data-analytics-cta-view"), "true");
  assert.equal($("[data-sticky-cta]").length, 1, `${page.route}: sticky CTA lipsă`);
  assert.notEqual($("[data-sticky-cta]").attr("hidden"), undefined, `${page.route}: sticky CTA trebuie ascuns inițial`);
  assert.equal($("link[href^='/assets/contextual-cta.css']").length, 1);
  assert.equal($("script[src^='/assets/contextual-cta.js']").length, 1);
  const url = new URL(primary.attr("href"), "https://atelierdeconsultanta.ro");
  const context = new URLSearchParams(url.hash.slice(1));
  assert.equal(url.search, "");
  assert.deepEqual([...context.keys()].sort(), page.programSlug ? ["program_slug", "source_page"] : ["source_page"]);
  assert.equal(context.get("source_page"), page.route);
  if (page.programSlug) assert.equal(context.get("program_slug"), page.programSlug);
}

const contact = cheerio.load(fs.readFileSync(path.join(ROOT, "contact", "index.html"), "utf8"));
for (const name of ["source_page", "calculator_so_result"]) {
  assert.equal(contact(`#contact-triage-form input[name='${name}']`).length, 1, `formular: ${name} lipsește`);
}

const good = validateContactPayload({
  schema_version: "1.0.0",
  applicant_type: "societate",
  location: "Iași",
  investment: "Utilaje agricole",
  email: "qa@example.com",
  privacy_notice_acknowledged: true,
  program_slug: "dr12-afir",
  source_page: "/dr12-afir",
  calculator_so_result: "12345"
}, Date.now());
assert.equal(good.valid, true, good.errors.map((item) => item.code).join(", "));
assert.equal(good.payload.source_page, "/dr12-afir");
assert.equal(good.payload.calculator_so_result, "12345");

const bad = validateContactPayload({
  schema_version: "1.0.0",
  applicant_type: "societate",
  location: "Iași",
  investment: "Utilaje agricole",
  email: "qa@example.com",
  privacy_notice_acknowledged: true,
  source_page: "https://example.com/private?email=x",
  calculator_so_result: "12x"
}, Date.now());
assert.equal(bad.valid, false);
assert(bad.errors.some((item) => item.field === "source_page"));
assert(bad.errors.some((item) => item.field === "calculator_so_result"));

const client = fs.readFileSync(path.join(ROOT, "assets", "contextual-cta.js"), "utf8");
assert(client.includes("IntersectionObserver") && client.includes("dataset.soValue"), "sticky CTA sau rezultatul SO nu sunt sincronizate");
assert(!/email|phone|name=/iu.test(client), "assetul CTA nu trebuie să citească PII");

console.log(`Contextual CTA contract PASS: ${config.pages.length} suprafețe, context validat, sticky mobil și rezultat SO non-PII.`);
