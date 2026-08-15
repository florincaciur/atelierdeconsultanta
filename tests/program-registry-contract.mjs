#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const {
  PROGRAM_STATUSES,
  fundingSummary,
  isPublicProgram,
  loadProgramConfig,
  validateProgram
} = require("../tools/program-factual-governance");
const { latestVerifiedProgram } = require("../tools/sync-homepage-hero");
const { fileForRoute } = require("../tools/structured-data-utils");

const { programs, publicPrograms } = loadProgramConfig();
const bySlug = new Map(programs.map((program) => [program.slug, program]));
const header = cheerio.load(fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8"), { decodeEntities: false });
const homepage = cheerio.load(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"), { decodeEntities: false });
const banners = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));

function factsFromElement($, element) {
  return {
    slug: $(element).attr("data-program-id"),
    status: $(element).attr("data-program-status"),
    statusLabel: $(element).attr("data-status-label"),
    verifiedAt: $(element).attr("data-verified-at"),
    sourceUrl: $(element).attr("data-source-url")
  };
}

function expectedFacts(program) {
  return {
    slug: program.slug,
    status: program.status,
    statusLabel: program.statusLabel,
    verifiedAt: program.verifiedAt,
    sourceUrl: program.sourceUrl
  };
}

function assertFacts(program, actual, surface) {
  assert.deepEqual(actual, expectedFacts(program), `${program.slug}: contradicție pe suprafața ${surface}`);
}

function jsonLdNodes($) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    const value = JSON.parse($(script).text());
    nodes.push(...(Array.isArray(value?.["@graph"]) ? value["@graph"] : [value]));
  });
  return nodes;
}

function propertyMap(node) {
  return new Map((node?.additionalProperty || []).map((item) => [item.name, String(item.value ?? "")]));
}

for (const status of [
  "apel_deschis",
  "ghid_aprobat_nedeschis",
  "consultare_publica",
  "calendar_estimativ",
  "apel_inchis",
  "arhivat"
]) assert(PROGRAM_STATUSES.includes(status), `Lipsește statusul controlat ${status}`);
assert.equal(PROGRAM_STATUSES.length, 6, "Taxonomia de status nu poate primi valori editoriale locale");

for (const element of header("[data-program-id]").toArray()) {
  const slug = header(element).attr("data-program-id");
  const program = bySlug.get(slug);
  assert(program && isPublicProgram(program), `Meniul publică un program absent sau neverificat: ${slug}`);
  assertFacts(program, factsFromElement(header, element), "meniu");
}

for (const element of homepage("[data-program-id][data-program-status]").toArray()) {
  const slug = homepage(element).attr("data-program-id");
  const program = bySlug.get(slug);
  assert(program && isPublicProgram(program), `Homepage publică un program absent sau neverificat: ${slug}`);
  assertFacts(program, factsFromElement(homepage, element), "homepage/card");
}

for (const banner of banners) {
  const program = bySlug.get(banner.programId);
  assert(program && isPublicProgram(program), `Caruselul publică un program absent sau neverificat: ${banner.programId}`);
  assert.deepEqual(
    {
      status: banner.programStatus,
      statusLabel: banner.statusLabel,
      verifiedAt: banner.verifiedAt,
      sourceUrl: banner.sourceUrl,
      fundingSummary: banner.fundingSummary
    },
    {
      status: program.status,
      statusLabel: program.statusLabel,
      verifiedAt: program.verifiedAt,
      sourceUrl: program.sourceUrl,
      fundingSummary: fundingSummary(program) || null
    },
    `${program.slug}: contradicție în carusel`
  );
}

for (const program of publicPrograms) {
  const file = fileForRoute(ROOT, program.pageUrl);
  assert(fs.existsSync(file), `${program.slug}: lipsește pagina canonică`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assertFacts(program, factsFromElement($, $("body").get(0)), "pagina programului");
  assert.equal($("body").attr("data-publication-state"), "public", `${program.slug}: publicationState greșit pe pagină`);
  const factual = $(".program-factual-status[data-program-id]").first();
  assert(factual.length, `${program.slug}: lipsește componenta factuală vizibilă`);
  assertFacts(program, factsFromElement($, factual.get(0)), "componenta factuală");
  assert.equal(factual.find("a[data-analytics-event='source_document_click']").attr("href"), program.sourceUrl, `${program.slug}: link oficial diferit`);
  assert.equal(factual.find("time").first().attr("datetime"), program.verifiedAt, `${program.slug}: data vizibilă diferă`);
  const expectedFunding = fundingSummary(program);
  assert.equal(Boolean(factual.find("[data-program-funding]").length), Boolean(expectedFunding), `${program.slug}: grantSummary/cofinancingSummary este afișat incorect`);
  if (expectedFunding) assert.equal(factual.find("[data-program-funding]").text().trim(), expectedFunding, `${program.slug}: rezumat financiar diferit`);

  const programNode = jsonLdNodes($).find((node) => String(node?.["@id"] || "") === `https://atelierdeconsultanta.ro${program.pageUrl}#funding-program`);
  assert(programNode, `${program.slug}: lipsește programul din JSON-LD`);
  const properties = propertyMap(programNode);
  assert.equal(programNode.name, program.name, `${program.slug}: nume JSON-LD diferit`);
  assert.equal(programNode.sameAs, program.sourceUrl, `${program.slug}: sursă JSON-LD diferită`);
  assert.equal(properties.get("status"), program.status, `${program.slug}: status JSON-LD diferit`);
  assert.equal(properties.get("statusLabel"), program.statusLabel, `${program.slug}: statusLabel JSON-LD diferit`);
  assert.equal(properties.get("verifiedAt"), program.verifiedAt, `${program.slug}: verifiedAt JSON-LD diferit`);
  assert.equal(properties.has("grantSummary"), program.grantSummary !== null, `${program.slug}: grantSummary JSON-LD publicat incorect`);
  assert.equal(properties.has("cofinancingSummary"), program.cofinancingSummary !== null, `${program.slug}: cofinancingSummary JSON-LD publicat incorect`);

  const menuElements = header(`[data-program-id='${program.slug}']`).toArray();
  for (const element of menuElements) assertFacts(program, factsFromElement(header, element), "meniu desktop/mobil");
  if (program.presentation?.carousel) assert(banners.some((banner) => banner.programId === program.slug), `${program.slug}: lipsește din caruselul configurat`);
}

const latestHomepageProgram = latestVerifiedProgram(publicPrograms);
const latestHomepageNode = homepage("[data-homepage-hero-latest-program]");
assert.equal(latestHomepageNode.length, 1, "homepage: trebuie un singur program verificat recent în hero");
assertFacts(latestHomepageProgram, factsFromElement(homepage, latestHomepageNode.get(0)), "homepage hero compact");

for (const program of programs.filter((item) => !isPublicProgram(item))) {
  assert.equal(header(`[data-program-id='${program.slug}']`).length, 0, `${program.slug}: pending_validation apare în meniu`);
  assert.equal(homepage(`[data-program-id='${program.slug}']`).length, 0, `${program.slug}: pending_validation apare pe homepage`);
  assert(!banners.some((banner) => banner.programId === program.slug), `${program.slug}: pending_validation apare în carusel`);
  const file = fileForRoute(ROOT, program.pageUrl);
  if (!fs.existsSync(file)) continue;
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assert.equal($("body").attr("data-publication-state"), "pending_validation", `${program.slug}: pagina pending nu este marcată`);
  assert.match($("meta[name='robots']").attr("content") || "", /noindex/iu, `${program.slug}: pagina pending este indexabilă`);
  assert.equal($(`[data-program-id='${program.slug}'][data-program-status]`).length, 0, `${program.slug}: pagina pending publică status factual`);
  assert.equal($("main [data-program-funding]").length, 0, `${program.slug}: pagina pending publică valori factuale`);
  assert(!jsonLdNodes($).some((node) => String(node?.["@id"] || "").endsWith("#funding-program")), `${program.slug}: pagina pending publică JSON-LD factual`);
}

const canonical = publicPrograms[0];
assert.throws(
  () => assertFacts(canonical, { ...expectedFacts(canonical), status: "apel_inchis" }, "fixture contradictoriu"),
  /contradicție/,
  "Testul trebuie să eșueze când o suprafață contrazice registrul"
);
const missingSourceVersion = structuredClone(canonical);
missingSourceVersion.sourceVersion = "";
assert(validateProgram(missingSourceVersion).some((error) => /sourceVersion|sursă oficială/iu.test(error)), "Publicarea fără sourceVersion trebuie respinsă");
const invalidStatus = structuredClone(canonical);
invalidStatus.status = "activ";
assert(validateProgram(invalidStatus).some((error) => /status invalid/iu.test(error)), "Un status editorial local trebuie respins");
const numericWithoutSource = structuredClone(publicPrograms.find((program) => program.grantSummary) || canonical);
numericWithoutSource.sourceUrl = "DE_VALIDAT_UMAN";
assert(validateProgram(numericWithoutSource).some((error) => /sursă oficială|numerice/iu.test(error)), "Valorile numerice fără sursă oficială trebuie respinse");
const archivedEvergreen = structuredClone(canonical);
archivedEvergreen.status = "arhivat";
archivedEvergreen.archivedNoindexDecision = "noindex";
archivedEvergreen.evergreenValue = true;
assert(validateProgram(archivedEvergreen).some((error) => /evergreen/iu.test(error)), "noindex pentru arhivă cu valoare evergreen trebuie respins");

console.log(`Contract registru: ${programs.length} programe verificate pe meniu, homepage, carduri, pagini și JSON-LD.`);
