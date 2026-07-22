#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(ROOT, "despre-faber", "index.html"), "utf8");
const identity = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "legal-identity.json"), "utf8"));
const governance = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "about-faber-governance.json"), "utf8"));
const $ = cheerio.load(html);
const errors = [];

function assert(condition, message) {
  if (!condition) errors.push(message);
}

function text(selector) {
  return $(selector).first().text().replace(/\s+/gu, " ").trim();
}

assert(text("h1") === "Consultanță prudentă înainte de dosar", "H1-ul P1.16 nu este exact");
assert(text(".hero > p").includes("Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar."), "poziționarea obligatorie lipsește din hero");
assert($(".hero a.btn-primary").first().text().trim() === "Vezi dacă proiectul merită pregătit", "CTA-ul principal din hero este incorect");
assert($(".about-final-cta a.btn-primary").text().trim() === "Vezi dacă proiectul merită pregătit", "CTA-ul contextual final este incorect");
assert($(".about-final-cta a.btn-primary").attr("href")?.includes("source_page=%2Fdespre-faber"), "CTA-ul nu păstrează contextul paginii");

const requiredHeadings = [
  "Cine este operatorul FABER",
  "Cine lucrează la proiect",
  "De la triere la implementare",
  "Ce nu promite FABER",
  "Ce considerăm dovadă publicabilă",
  "Formulări care cer confirmare oficială"
];
const headings = $("h2").map((_, element) => $(element).text().replace(/\s+/gu, " ").trim()).get();
for (const heading of requiredHeadings) assert(headings.includes(heading), `lipsește secțiunea: ${heading}`);

const methodLabels = $(".about-method-flow strong").map((_, element) => $(element).text().trim()).get();
assert(JSON.stringify(methodLabels) === JSON.stringify(["Triere", "Documente", "Punctaj", "Dosar", "Clarificări și implementare"]), "metoda în cinci pași este divergentă");

assert($("[data-canonical-legal-identity='approved']").length === 1, "operatorul canonic lipsește sau este duplicat");
assert(html.indexOf("CANONICAL_LEGAL_IDENTITY_START") < html.indexOf("about-team-title"), "operatorul trebuie afișat înaintea echipei");
const operatorText = text("[data-canonical-legal-identity='approved']");
for (const field of ["legalName", "taxIdentifier", "tradeRegisterNumber", "registeredOffice", "publicWorkplaceAddress", "personalDataController"]) {
  const value = identity.fields?.[field]?.approvedValue;
  assert(value && operatorText.includes(value), `operatorul nu folosește valoarea aprobată pentru ${field}`);
}
for (const value of [identity.fields?.publicEmail?.approvedValue, ...(identity.approvedContactChannels?.additionalPhones || [])]) {
  if (value) assert(html.includes(String(value)), `datele canonice de contact nu includ ${value}`);
}

assert($(".about-team img").length === 0, "a fost publicată o fotografie de echipă neverificată");
assert($(".about-team a[href*='linkedin.com']").length === 0, "a fost publicat un LinkedIn neverificat");
assert($("script[type='application/ld+json']").toArray().every((element) => !$(element).html().includes('"@type":"Person"') && !$(element).html().includes('"@type": "Person"')), "datele structurate conțin o persoană neverificată");
assert(!html.includes(governance.humanReviewToken), "placeholderul DE_VALIDAT_UMAN a ajuns în HTML-ul public");

const visible = $("body").text().replace(/\s+/gu, " ");
assert(visible.includes("nu afirmă în prezent o afiliere sau o listare instituțională"), "lipsa listării confirmate nu este explicată transparent");
assert(visible.includes("listată în nomenclatorul orientativ AFIR"), "formularea condiționată pentru nomenclatorul AFIR lipsește");
assert(visible.includes("Nu promitem aprobarea"), "limita privind aprobarea lipsește");
assert(visible.includes("Nu echivalăm o listare cu o acreditare"), "limita privind acreditarea AFIR lipsește");
assert(visible.includes("nu înseamnă acreditare din partea AFIR"), "clarificarea despre nomenclatorul AFIR lipsește");
assert(!/garantăm (?:aprobarea|succesul)/iu.test(visible), "pagina conține o promisiune de rezultat");
assert(!/rat[ăe] de succes\s*[:–-]?\s*\d/iu.test(visible), "pagina publică o rată de succes neverificată");
assert($("a[href='/metodologie-verificare-eligibilitate']").length > 0, "linkul spre metodologie lipsește");
assert($("a[href='/studii-de-caz-fonduri-europene']").length > 0, "linkul spre studiile de caz lipsește");
assert($("a[href='/contact']").length > 0 || $("a[href^='/contact?']").length > 0, "linkul spre Contact lipsește");
assert($("link[href='/assets/about-faber.css?v=20260722-1']").length === 1, "stylesheet-ul paginii lipsește sau este duplicat");

for (const validation of governance.pendingValidations || []) {
  assert(validation.status === governance.humanReviewToken, `${validation.id}: status invalid`);
  assert(validation.publicationState === "blocked", `${validation.id}: publicarea nu este blocată`);
}

if (errors.length) {
  console.error(`About FABER contract FAILED (${errors.length}):`);
  errors.forEach((error) => console.error(`- ${error}`));
  process.exit(1);
}

console.log("About FABER contract PASS: identitate canonică, metodă, limite, dovezi și CTA validate; datele umane neverificate rămân private.");
