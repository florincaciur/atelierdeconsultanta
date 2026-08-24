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
  CANONICAL_PROGRAM_STATUSES,
  PROGRAM_STATUSES,
  cofinancingSummaryText,
  fundingSummary,
  grantSummaryText,
  isPublicProgram,
  loadProgramConfig,
  validateProgram,
  validateProgramRelationships
} = require("../tools/program-factual-governance");
const { registrySurfaceErrors } = require("../tools/validate-program-registry");
const { incentiveStatusForProgram } = require("../tools/schema-helpers");
const { latestVerifiedProgram } = require("../tools/sync-homepage-hero");
const { fileForRoute } = require("../tools/structured-data-utils");

const { programs, publicPrograms } = loadProgramConfig();
const byId = new Map(programs.map((program) => [program.id, program]));
const header = cheerio.load(fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8"), { decodeEntities: false });
const homepage = cheerio.load(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"), { decodeEntities: false });
const banners = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));

assert.equal(new Set(programs.map((program) => program.id)).size, programs.length, "ID-urile stabile trebuie să fie unice");
assert.equal(new Set(programs.map((program) => program.slug)).size, programs.length, "Slugurile trebuie să fie unice");
assert.equal(new Set(programs.map((program) => program.pageUrl)).size, programs.length, "Canonicalele programelor trebuie să fie unice");
assert.deepEqual(registrySurfaceErrors(programs), [], "Registry/pagini/bannere trebuie reconciliate");

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
    slug: program.id,
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
  const program = byId.get(slug);
  assert(program && isPublicProgram(program), `Meniul publică un program absent sau neverificat: ${slug}`);
  assertFacts(program, factsFromElement(header, element), "meniu");
}

for (const element of homepage("[data-program-id][data-program-status]").toArray()) {
  const slug = homepage(element).attr("data-program-id");
  const program = byId.get(slug);
  assert(program && isPublicProgram(program), `Homepage publică un program absent sau neverificat: ${slug}`);
  assertFacts(program, factsFromElement(homepage, element), "homepage/card");
}

for (const banner of banners) {
  const program = byId.get(banner.programId);
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
  assert.equal($("[data-aeo-program-summary] [data-answer-field='verifiedAt'] time").first().attr("datetime"), program.verifiedAt, `${program.slug}: data vizibilă diferă`);
  const summary = $("[data-aeo-program-summary]").first();
  assert(summary.length, `${program.slug}: lipsește rezumatul semantic answer-first`);
  const expectedGrant = grantSummaryText(program);
  const expectedContribution = cofinancingSummaryText(program);
  assert.equal(Boolean(summary.find("[data-program-grant]").length), Boolean(expectedGrant), `${program.slug}: grantSummary este afișat incorect`);
  assert.equal(Boolean(summary.find("[data-program-contribution]").length), Boolean(expectedContribution), `${program.slug}: cofinancingSummary este afișat incorect`);
  if (expectedGrant) assert(summary.find("[data-program-grant]").text().includes(expectedGrant), `${program.slug}: grantSummary diferă`);
  if (expectedContribution) assert(summary.find("[data-program-contribution]").text().includes(expectedContribution), `${program.slug}: cofinancingSummary diferă`);

  const programNode = jsonLdNodes($).find((node) => String(node?.["@id"] || "") === `https://atelierdeconsultanta.ro${program.pageUrl}#funding-program`);
  assert(programNode, `${program.slug}: lipsește programul din JSON-LD`);
  assert.equal(programNode["@type"], "FinancialIncentive", `${program.slug}: programul trebuie să folosească tipul oficial FinancialIncentive`);
  assert.equal(programNode.name, program.name, `${program.slug}: nume JSON-LD diferit`);
  assert.equal(programNode.description, program.statusLabel, `${program.slug}: statusLabel JSON-LD diferit`);
  assert.equal(programNode.subjectOf?.url, program.sourceUrl, `${program.slug}: sursă JSON-LD diferită`);
  assert.equal(programNode.provider?.name, program.sourceName, `${program.slug}: autoritate JSON-LD diferită`);
  assert.equal(programNode.incentiveStatus, incentiveStatusForProgram(program), `${program.slug}: status Schema.org diferit`);
  assert.equal(programNode.validFrom, program.applicationStart || undefined, `${program.slug}: applicationStart JSON-LD diferit`);
  assert.equal(programNode.validThrough, program.applicationEnd || undefined, `${program.slug}: applicationEnd JSON-LD diferit`);
  assert.equal(programNode.sameAs, undefined, `${program.slug}: sursa documentară nu poate fi sameAs`);
  assert.equal(programNode.additionalProperty, undefined, `${program.slug}: programul nu poate publica proprietăți Schema.org neacceptate`);

  const menuElements = header(`[data-program-id='${program.id}']`).toArray();
  for (const element of menuElements) assertFacts(program, factsFromElement(header, element), "meniu desktop/mobil");
  if (program.presentation?.carousel) assert(banners.some((banner) => banner.programId === program.id), `${program.slug}: lipsește din caruselul configurat`);
}

const latestHomepageProgram = latestVerifiedProgram(publicPrograms);
const latestHomepageNode = homepage("[data-homepage-hero-latest-program]");
assert.equal(latestHomepageNode.length, 1, "homepage: trebuie un singur program verificat recent în hero");
assertFacts(latestHomepageProgram, factsFromElement(homepage, latestHomepageNode.get(0)), "homepage hero compact");

for (const program of programs.filter((item) => !isPublicProgram(item))) {
  assert.equal(header(`[data-program-id='${program.id}']`).length, 0, `${program.slug}: pending_validation apare în meniu`);
  assert.equal(homepage(`[data-program-id='${program.id}']`).length, 0, `${program.slug}: pending_validation apare pe homepage`);
  assert(!banners.some((banner) => banner.programId === program.id), `${program.slug}: pending_validation apare în carusel`);
  const file = fileForRoute(ROOT, program.pageUrl);
  if (!fs.existsSync(file)) continue;
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assert.equal($("body").attr("data-publication-state"), "pending_validation", `${program.slug}: pagina pending nu este marcată`);
  assert.match($("meta[name='robots']").attr("content") || "", /noindex/iu, `${program.slug}: pagina pending este indexabilă`);
  assert.equal($(`[data-program-id='${program.id}'][data-program-status]`).length, 0, `${program.slug}: pagina pending publică status factual`);
  assert.equal($("main [data-program-grant], main [data-program-contribution]").length, 0, `${program.slug}: pagina pending publică valori factuale`);
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
const invalidCanonicalStatus = structuredClone(canonical);
invalidCanonicalStatus.canonicalStatus = "ACTIVE";
assert(validateProgram(invalidCanonicalStatus).some((error) => /canonicalStatus invalid/iu.test(error)), "Un status canonic din afara taxonomiei trebuie respins");
assert.equal(CANONICAL_PROGRAM_STATUSES.length, 13, "Taxonomia canonică trebuie să aibă exact 13 stări");
const openWithoutSessionEvidence = structuredClone(programs.find((program) => program.canonicalStatus === "OPEN"));
openWithoutSessionEvidence.officialSources.roles.sessionAnnouncement = [];
assert(validateProgram(openWithoutSessionEvidence).some((error) => /OPEN.*dovadă.*sesiune/iu.test(error)), "OPEN fără dovadă de sesiune trebuie respins");
const malformedSourceReference = structuredClone(canonical);
malformedSourceReference.officialSources.roles.programPage = [{ ref: "program" }];
assert(validateProgram(malformedSourceReference).some((error) => /officialSources.*programPage.*ref.*label/iu.test(error)), "O referință oficială fără label trebuie respinsă");
const missingRelatedId = structuredClone(programs);
missingRelatedId[0].relatedProgramIds = ["program-inexistent"];
assert(validateProgramRelationships(missingRelatedId).some((error) => /relatedProgramIds.*inexistent/iu.test(error)), "Un relatedProgramId inexistent trebuie respins");
const duplicateCanonical = structuredClone(programs);
duplicateCanonical[1].pageUrl = duplicateCanonical[0].pageUrl;
assert(validateProgramRelationships(duplicateCanonical).some((error) => /pageUrl duplicat/iu.test(error)), "Un canonical duplicat trebuie respins");
const registryWithoutPage = structuredClone(programs);
registryWithoutPage.find((program) => program.indexable).pageUrl = "/program-fara-pagina";
assert(registrySurfaceErrors(registryWithoutPage).some((error) => /fără pagină canonical/iu.test(error)), "Un program indexabil fără pagină trebuie respins");
const pageWithoutRegistry = programs.filter((program) => program.id !== "dr12-afir");
assert(registrySurfaceErrors(pageWithoutRegistry).some((error) => /pagină de program fără înregistrare validă/iu.test(error)), "O pagină de program fără registry trebuie respinsă");
const numericWithoutSource = structuredClone(publicPrograms.find((program) => program.grantSummary) || canonical);
numericWithoutSource.sourceUrl = "DE_VALIDAT_UMAN";
assert(validateProgram(numericWithoutSource).some((error) => /sursă oficială|numerice/iu.test(error)), "Valorile numerice fără sursă oficială trebuie respinse");
const archivedEvergreen = structuredClone(canonical);
archivedEvergreen.status = "arhivat";
archivedEvergreen.archivedNoindexDecision = "noindex";
archivedEvergreen.evergreenValue = true;
assert(validateProgram(archivedEvergreen).some((error) => /evergreen/iu.test(error)), "noindex pentru arhivă cu valoare evergreen trebuie respins");

console.log(`Contract registru: ${programs.length} programe verificate pe meniu, homepage, carduri, pagini și JSON-LD.`);
