#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC_ROOT = process.argv.includes("--dist") ? path.join(ROOT, "dist") : ROOT;
const { findPublicHtmlFiles } = require("../tools/sync-global-header");
const governance = JSON.parse(fs.readFileSync(path.join(ROOT, "config/about-faber-governance.json"), "utf8"));
const seo = JSON.parse(fs.readFileSync(path.join(ROOT, "config/seo-programs.json"), "utf8"));

function readPublic(relativePath) {
  return fs.readFileSync(path.join(PUBLIC_ROOT, ...relativePath.split("/")), "utf8");
}

function routeFile(route) {
  const slug = route.replace(/^\//u, "");
  const candidates = [`${slug}/index.html`, `${slug}.html`];
  const match = candidates.find((relativePath) => fs.existsSync(path.join(PUBLIC_ROOT, ...relativePath.split("/"))));
  assert(match, `${route}: lipsește forma HTML publică.`);
  return match;
}

function normalizedText($, selector = "main") {
  return $(selector).text().replace(/\s+/gu, " ").trim();
}

function assertEditorialDate($, label, expectedDate) {
  assert.equal($("meta[property='article:modified_time']").attr("content"), expectedDate, `${label}: article:modified_time trebuie să urmeze data auditului trust.`);
  const visibleDate = $("dt")
    .filter((_, element) => $(element).text().trim() === "Ultima actualizare")
    .next("dd")
    .find("time")
    .attr("datetime");
  assert.equal(visibleDate, expectedDate, `${label}: data editorială vizibilă trebuie să urmeze data auditului trust.`);
}

function schemaHasForbiddenEvidence(value) {
  if (Array.isArray(value)) return value.some(schemaHasForbiddenEvidence);
  if (!value || typeof value !== "object") return false;
  for (const [key, entry] of Object.entries(value)) {
    if (["review", "reviews", "aggregateRating"].includes(key)) return true;
    if (key === "@type" && (Array.isArray(entry) ? entry : [entry]).some((type) => ["Review", "AggregateRating"].includes(type))) return true;
    if (schemaHasForbiddenEvidence(entry)) return true;
  }
  return false;
}

const policy = governance.trustEvidencePolicy;
assert(policy, "Lipsește trustEvidencePolicy din guvernanța About.");
assert.equal(policy.publicCaseStudies, 0, "Nu există studii de caz aprobate pentru publicare.");
assert.equal(policy.publicTestimonials, 0, "Nu există testimoniale aprobate pentru publicare.");
assert.equal(policy.reviewSchemaAllowed, false, "Review schema trebuie să rămână blocată fără dovezi.");
assert.match(policy.reviewedAt, /^\d{4}-\d{2}-\d{2}$/u, "Data auditului trust trebuie să fie ISO.");

const pendingById = new Map(governance.pendingValidations.map((item) => [item.id, item]));
for (const id of ["case_studies_and_results", "testimonials"]) {
  const item = pendingById.get(id);
  assert(item, `${id}: lipsește din pendingValidations.`);
  assert.equal(item.status, "DE_VALIDAT_UMAN", `${id}: trebuie să rămână la validare umană.`);
  assert.equal(item.publicationState, "blocked", `${id}: publicarea trebuie blocată.`);
}
for (const required of ["beneficiarul poate fi publicat", "sector", "program", "serviciu FABER", "investiție", "etapă", "rezultat verificabil", "valoare publicabilă", "locație publicabilă", "permisiune pentru nume și logo"]) {
  assert(pendingById.get("case_studies_and_results").required.includes(required), `Case study: lipsește câmpul „${required}”.`);
}
for (const required of ["text aprobat", "autor", "funcție", "companie", "permisiune de publicare"]) {
  assert(pendingById.get("testimonials").required.includes(required), `Testimonial: lipsește câmpul „${required}”.`);
}

for (const slug of ["studii-de-caz", "portofoliu", "testimoniale"]) {
  const page = seo.pages.find((item) => item.slug === slug);
  assert(page, `${slug}: lipsește din registrul de pagini.`);
  assert.equal(page.approvedItemsCount, 0, `${slug}: registrul nu poate declara elemente aprobate.`);
  assert.equal(page.redirectTo, "/studii-de-caz-fonduri-europene", `${slug}: consolidarea canonicală trebuie păstrată.`);
}

const methodology = cheerio.load(readPublic(routeFile("/metodologie-verificare-eligibilitate")));
assert.equal(methodology("#metodologie-editoriala").length, 1, "Metodologia editorială publică lipsește sau este duplicată.");
assertEditorialDate(methodology, "Metodologie editorială", policy.reviewedAt);
const methodologyText = normalizedText(methodology, "#metodologie-editoriala");
for (const required of [
  "Prioritatea surselor",
  "Anunțat",
  "Consultare publică / ghid consultativ",
  "Ghid final publicat",
  "Schemă aprobată",
  "Apel deschis",
  "Status neconfirmat",
  "verifiedAt este data la care informația a fost reverificată efectiv",
  "Cum corectăm o eroare",
  "Responsabilitate editorială",
  "nu înlocuiește ghidul"
]) {
  assert(methodologyText.includes(required), `Metodologie editorială: lipsește „${required}”.`);
}
assert.equal(methodology("h1").length, 1, "Metodologia trebuie să păstreze un singur H1.");

const cases = cheerio.load(readPublic(routeFile("/studii-de-caz-fonduri-europene")));
assert.equal(cases("#politica-dovezi").length, 1, "Politica dovezilor lipsește sau este duplicată.");
assertEditorialDate(cases, "Studii de caz", policy.reviewedAt);
assert.equal(cases("[data-publication-state='methodology-only']").attr("data-approved-case-count"), "0", "Pagina trebuie să declare zero cazuri aprobate.");
assert.equal(cases("[data-publication-state='methodology-only']").attr("data-approved-testimonial-count"), "0", "Pagina trebuie să declare zero testimoniale aprobate.");
assert.equal(cases("h1").length, 1, "Pagina de studii de caz trebuie să păstreze un singur H1.");
assert.equal(cases("link[rel='canonical']").attr("href"), "https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene", "Canonicalul studiilor de caz s-a schimbat.");
const casesText = normalizedText(cases);
for (const required of [
  "nu publică încă niciun studiu de caz drept rezultat real verificat al unui client și niciun testimonial",
  "metodologie și un model de analiză",
  "Când poate deveni public un studiu de caz",
  "analiză preliminară, eligibilitate, pregătire, depunere, clarificări, contractare, implementare sau finalizare",
  "Testimoniale și review schema",
  "mai puține dovezi reale sunt preferabile unui volum artificial"
]) {
  assert(casesText.includes(required), `Politica dovezilor: lipsește „${required}”.`);
}
assert.equal(cases("[data-case-study='published'], [data-testimonial='published']").length, 0, "Nu poate exista o dovadă publicată cât timp registrul declară zero aprobări.");

const publicFiles = findPublicHtmlFiles(PUBLIC_ROOT);
assert(publicFiles.length >= 100, "Auditul schema trebuie să acopere întregul site public.");
for (const relativePath of publicFiles) {
  const $ = cheerio.load(readPublic(relativePath));
  $("script[type='application/ld+json']").each((_, script) => {
    const parsed = JSON.parse($(script).html());
    assert(!schemaHasForbiddenEvidence(parsed), `${relativePath}: Review/AggregateRating nejustificat în JSON-LD.`);
  });
}

console.log(`Trust evidence contract PASS (${process.argv.includes("--dist") ? "dist" : "source"}): metodologie, zero cazuri/testimoniale și ${publicFiles.length} fișiere JSON-LD validate.`);
