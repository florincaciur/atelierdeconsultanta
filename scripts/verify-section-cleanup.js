#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const HOME_PATH = path.join(ROOT, "index.html");
const errors = [];

function fail(message) {
  errors.push(message);
}

function normalize(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function comparisonKey(value) {
  return normalize(value).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function canonicalPath(value) {
  try {
    const url = new URL(value, "https://atelierdeconsultanta.ro");
    return url.pathname.replace(/\.html$/i, "").replace(/\/$/, "") || "/";
  } catch {
    return "";
  }
}

function findJsonLdNodes(value, output = []) {
  if (!value || typeof value !== "object") return output;
  if (value["@type"] === "FAQPage" || (Array.isArray(value["@type"]) && value["@type"].includes("FAQPage"))) {
    output.push(value);
  }
  if (Array.isArray(value)) {
    for (const item of value) findJsonLdNodes(item, output);
  } else {
    for (const item of Object.values(value)) findJsonLdNodes(item, output);
  }
  return output;
}

const homeHtml = fs.readFileSync(HOME_PATH, "utf8");
const $ = cheerio.load(homeHtml);

const removedHeadings = [
  "Ce trebuie verificat",
  "Servicii pentru pregătirea proiectului",
  "Programe și surse de finanțare"
];
const currentHeadings = new Set($("h1,h2,h3,h4,h5,h6").map((_, node) => normalize($(node).text())).get());
for (const heading of removedHeadings) {
  if (currentHeadings.has(heading)) fail(`Homepage still contains removed heading: ${heading}`);
}

const toggle = $("#homepage-faq-toggle");
const extra = $("#homepage-faq-extra");
if (toggle.length !== 1) fail(`Expected one #homepage-faq-toggle; found ${toggle.length}`);
if (extra.length !== 1) fail(`Expected one #homepage-faq-extra; found ${extra.length}`);
if (toggle.attr("aria-expanded") !== "false") fail("FAQ toggle must start with aria-expanded=false");
if (toggle.attr("aria-controls") !== "homepage-faq-extra") fail("FAQ toggle aria-controls is incorrect");
if (!extra.is("[hidden]")) fail("#homepage-faq-extra must have the hidden attribute initially");
if (normalize(toggle.text()) !== "Vezi toate resursele utile") fail("FAQ toggle has the wrong initial label");

const expectedFaqs = [
  "Ce face FABER pentru un proiect cu fonduri europene?",
  "Pot primi o concluzie dacă nu știu programul potrivit?",
  "De ce nu promite FABER finanțare garantată?",
  "Cum se face analiza eligibilității?",
  "Cât durează procesul?",
  "Ce servicii include colaborarea?"
];
const visibleFaqItems = $("#homepage-faq > .homepage-faq-grid > .homepage-faq-item");
const visibleQuestions = visibleFaqItems.map((_, node) => normalize($(node).find("h3").first().text())).get();
if (visibleFaqItems.length !== 6) fail(`Expected six visible homepage FAQ cards; found ${visibleFaqItems.length}`);
if (JSON.stringify(visibleQuestions) !== JSON.stringify(expectedFaqs)) {
  fail(`Visible FAQ order/content differs: ${visibleQuestions.join(" | ")}`);
}
visibleFaqItems.each((_, node) => {
  if ($(node).closest("#homepage-faq-extra").length) fail("A visible FAQ card is inside the hidden wrapper");
  if (!normalize($(node).find("p").text())) fail("A visible FAQ card has no answer");
});

const resourcesHeading = extra.find("h2").filter((_, node) => normalize($(node).text()) === "Resurse utile");
if (resourcesHeading.length !== 1) fail(`Expected Resurse utile heading inside hidden wrapper; found ${resourcesHeading.length}`);
const resourceGrid = extra.find(".see-also-grid");
if (resourceGrid.length !== 1) fail(`Expected one resource grid inside hidden wrapper; found ${resourceGrid.length}`);
if (resourceGrid.find("a[href]").length === 0) fail("Resource links are not present statically in HTML");

const footer = $("footer#footer");
if (footer.length !== 1) fail(`Expected one homepage footer; found ${footer.length}`);
if (footer.closest("#homepage-faq-extra").length) fail("Footer must remain outside the hidden wrapper");

const ids = new Map();
$("[id]").each((_, node) => {
  const id = $(node).attr("id");
  ids.set(id, (ids.get(id) || 0) + 1);
});
for (const [id, count] of ids) {
  if (count > 1) fail(`Duplicate homepage id: ${id} (${count})`);
}

$("a").each((_, node) => {
  const href = $(node).attr("href");
  if (href == null || href.trim() === "") fail(`Empty homepage link: ${normalize($(node).text()) || "[no text]"}`);
});

const faqSchemas = [];
$("script[type='application/ld+json']").each((index, node) => {
  try {
    findJsonLdNodes(JSON.parse($(node).html()), faqSchemas);
  } catch (error) {
    fail(`Invalid homepage JSON-LD script ${index + 1}: ${error.message}`);
  }
});
if (faqSchemas.length === 0) fail("Homepage FAQPage JSON-LD is missing");
const schemaQuestions = new Map(
  faqSchemas.flatMap((schema) => (schema.mainEntity || []).map((item) => {
    const question = normalize(item && item.name);
    return [comparisonKey(question), question];
  }))
);
for (const question of expectedFaqs) {
  if (!schemaQuestions.has(comparisonKey(question))) fail(`Visible FAQ is missing from FAQPage schema: ${question}`);
}
for (const [key, question] of schemaQuestions) {
  if (!$("#homepage-faq h3").filter((_, node) => comparisonKey($(node).text()) === key).length) {
    fail(`FAQPage schema question is absent from homepage HTML: ${question}`);
  }
}

const explicitProgramSlugs = [
  "por-adr-nord-est",
  "fonduri-regionale",
  "dr12-afir",
  "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "gal-afir",
  "e-move",
  "pocidif-21",
  "pro-infra",
  "start-up-nation-2026",
  "programul-tranzitie-justa",
  "investitii-modernizarea-microintreprinderilor-apel-2",
  "apeluri-gal"
];
const programSlugs = new Set(explicitProgramSlugs);
const banners = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));
for (const banner of banners) {
  const route = canonicalPath(banner.ctaLink);
  if (route && route !== "/") programSlugs.add(route.slice(1));
}

const forbiddenCardTitles = ["Solicitant", "Investiție", "Punctaj", "Ghid"];
for (const slug of [...programSlugs].sort()) {
  const file = path.join(ROOT, slug, "index.html");
  if (!fs.existsSync(file)) continue;
  const pageHtml = fs.readFileSync(file, "utf8");
  const page = cheerio.load(pageHtml);
  page("section,aside,article,div").each((_, node) => {
    const element = page(node);
    const label = normalize(element.find("h1,h2,h3,h4,h5,h6,.audit-design-summary__label").first().text()).toUpperCase();
    const cardTitles = new Set(element.find("strong").map((__, strong) => normalize(page(strong).text())).get());
    if (label === "PE SCURT" && forbiddenCardTitles.every((title) => cardTitles.has(title))) {
      fail(`${path.relative(ROOT, file)} still contains the four-card PE SCURT section`);
    }
  });
}

const generator = fs.readFileSync(path.join(ROOT, "tools", "apply-design-profiles.js"), "utf8");
if (/function\s+(?:renderSummary|addSummary)\b|audit-design-summary__grid/.test(generator)) {
  fail("tools/apply-design-profiles.js can still regenerate the PE SCURT summary block");
}

if (errors.length) {
  console.error("SECTION CLEANUP VERIFICATION: FAIL");
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log("SECTION CLEANUP VERIFICATION: PASS");
console.log(` - homepage headings removed: ${removedHeadings.length}`);
console.log(` - visible FAQ cards: ${visibleFaqItems.length}`);
console.log(` - static resource links: ${resourceGrid.find("a[href]").length}`);
console.log(` - program routes checked: ${programSlugs.size}`);
console.log(" - FAQPage JSON-LD matches visible homepage questions");
