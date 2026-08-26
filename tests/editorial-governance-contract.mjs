#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const HUMAN_REVIEW = "DE_VALIDAT_UMAN";
const TODAY = new Date().toISOString().slice(0, 10);
const ELIGIBLE_SCHEMA_TYPES = new Set([
  "WebPage",
  "CollectionPage",
  "Article",
  "BlogPosting",
  "TechArticle",
  "HowTo",
  "SoftwareApplication",
  "GovernmentService"
]);
const {
  REQUIRED_RECORD_FIELDS,
  daysBetween,
  isCompleteRecord,
  isIsoDate,
  loadEditorialGovernance,
  reviewExpired,
  validateGovernance
} = require("../tools/editorial-governance");
const { filesForRoute, syncPageHtml } = require("../tools/sync-editorial-governance");
const {
  generate,
  lastmodForFile
} = require("../tools/generate-sitemap");
const { sitemapLastmods } = require("../tools/sitemap-utils");

const { config, programs, records } = loadEditorialGovernance();
const programById = new Map(programs.map((program) => [program.id, program]));
const recordByRoute = new Map(records.map((record) => [record.route, record]));

function schemaNodes($) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    const value = JSON.parse($(script).text());
    nodes.push(...(Array.isArray(value?.["@graph"]) ? value["@graph"] : Array.isArray(value) ? value : [value]));
  });
  return nodes;
}

function eligibleNode(node) {
  const types = Array.isArray(node?.["@type"]) ? node["@type"] : [node?.["@type"]];
  return types.some((type) => ELIGIBLE_SCHEMA_TYPES.has(type));
}

for (const program of programs) {
  assert(recordByRoute.has(program.pageUrl), `${program.slug}: pagina canonică nu are guvernanță editorială`);
}

for (const record of records) {
  for (const field of REQUIRED_RECORD_FIELDS) {
    assert(Object.hasOwn(record, field), `${record.route}: lipsește câmpul editorial ${field}`);
  }
  const candidates = filesForRoute(record.route).filter((file) => fs.existsSync(file));
  assert(candidates.length, `${record.route}: nu există fișier HTML pentru ruta guvernată`);
  const file = candidates.find((candidate) => candidate.endsWith(`${path.sep}index.html`)) || candidates[0];
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const body = $("body");
  const section = $("[data-editorial-record]").filter((_, element) => element.tagName === "section").first();

  assert.equal(body.attr("data-editorial-record"), record.id, `${record.route}: body indică altă înregistrare editorială`);
  assert.equal(body.attr("data-governance-state"), record.governanceState, `${record.route}: stare editorială diferită în HTML`);
  assert(section.length, `${record.route}: lipsește componenta editorială vizibilă`);

  const structuredNodes = schemaNodes($);
  const nodeById = new Map();
  const indexNode = (value) => {
    if (Array.isArray(value)) return value.forEach(indexNode);
    if (!value || typeof value !== "object") return;
    if (value["@id"]) nodeById.set(value["@id"], value);
    Object.values(value).forEach(indexNode);
  };
  indexNode(structuredNodes);
  const eligible = structuredNodes.filter(eligibleNode);
  if (isCompleteRecord(record)) {
    assert.equal(body.attr("data-editorial-verified-at"), record.verifiedAt, `${record.route}: verifiedAt diferă în HTML`);
    assert.equal(body.attr("data-date-modified"), record.lastMeaningfulUpdate, `${record.route}: dateModified diferă în HTML`);
    assert.equal(body.attr("data-date-published"), isIsoDate(record.datePublished) ? record.datePublished : undefined, `${record.route}: datePublished diferă în HTML`);
    assert.equal(body.attr("data-official-source-updated-at"), isIsoDate(record.officialSourceUpdatedAt) ? record.officialSourceUpdatedAt : undefined, `${record.route}: officialSourceUpdatedAt diferă în HTML`);
    assert.equal(body.attr("data-next-review-at"), undefined, `${record.route}: nextReviewAt intern a fost expus în HTML`);
    assert.equal(body.attr("data-last-meaningful-update"), undefined, `${record.route}: atributul editorial legacy nu a fost eliminat`);
    assert(section.text().includes(`Verificat la ${record.verifiedAt}`), `${record.route}: lipsește data vizibilă de verificare`);
    assert(section.text().includes(`Actualizat editorial la ${record.lastMeaningfulUpdate}`), `${record.route}: lipsește dateModified vizibil`);
    assert(section.text().includes("Publisher: FABER – Atelier de Consultanță"), `${record.route}: publisherul real nu este vizibil`);
    assert(!section.text().includes(record.reviewer), `${record.route}: reviewerul fără profil confirmat a fost publicat`);
    assert(!section.text().includes(record.reviewerRole), `${record.route}: rolul reviewerului fără confirmare a fost publicat`);
    assert.equal(section.text().includes(`Publicat la ${record.datePublished}`), isIsoDate(record.datePublished), `${record.route}: vizibilitatea datePublished este incorectă`);
    assert.equal(section.text().includes(`Sursa oficială a fost actualizată la ${record.officialSourceUpdatedAt}`), isIsoDate(record.officialSourceUpdatedAt), `${record.route}: vizibilitatea officialSourceUpdatedAt este incorectă`);
    assert(!section.text().includes(record.nextReviewAt), `${record.route}: nextReviewAt intern apare în conținutul public`);
    assert.equal(section.find("a[data-analytics-event='source_document_click']").attr("href"), record.officialSourceUrl, `${record.route}: sursa vizibilă diferă`);
    assert(section.find("details.editorial-governance__changelog").length, `${record.route}: lipsește linkul/istoricul «Vezi modificările»`);
    assert(eligible.length, `${record.route}: pagina publică nu are un nod JSON-LD editorial eligibil`);
    for (const node of eligible) {
      assert.equal(node.dateModified, record.lastMeaningfulUpdate, `${record.route}: dateModified nu provine din lastMeaningfulUpdate`);
      assert.equal(node.datePublished, isIsoDate(record.datePublished) ? record.datePublished : undefined, `${record.route}: datePublished nu provine exclusiv din registrul editorial`);
      assert(Array.isArray(node.citation) && node.citation.some((citation) => {
        const resolved = citation?.["@id"] ? nodeById.get(citation["@id"]) : citation;
        return resolved?.url === record.officialSourceUrl;
      }), `${record.route}: sursa oficială lipsește din JSON-LD`);
      const officialCitation = node.citation.map((citation) => citation?.["@id"] ? nodeById.get(citation["@id"]) : citation)
        .find((citation) => citation?.url === record.officialSourceUrl);
      assert.equal(officialCitation?.dateModified, isIsoDate(record.officialSourceUpdatedAt) ? record.officialSourceUpdatedAt : undefined, `${record.route}: officialSourceUpdatedAt a fost confundat în schema sursei`);
      if (record.attributionType === "person") {
        assert.equal(record.personalNameConsent, true, `${record.route}: atribuirea Person necesită acord`);
        assert.equal(node.author?.["@type"], "Person", `${record.route}: autorul nominal trebuie publicat ca Person`);
        assert.equal(node.author?.url, record.authorProfileUrl, `${record.route}: profilul autorului diferă`);
      } else {
        assert.equal(node.author, undefined, `${record.route}: autor organizațional duplicat/neidentificabil în JSON-LD`);
        assert.equal(node.reviewedBy, undefined, `${record.route}: reviewer organizațional nu trebuie transformat într-o persoană fictivă`);
      }
    }
  } else {
    assert.equal(body.attr("data-editorial-verified-at"), undefined, `${record.route}: o dată neverificată a fost expusă în HTML`);
    assert.equal(body.attr("data-next-review-at"), undefined, `${record.route}: un termen neverificat a fost expus în HTML`);
    assert.equal(body.attr("data-date-published"), undefined, `${record.route}: datePublished neverificat a fost expus în HTML`);
    assert.equal(body.attr("data-date-modified"), undefined, `${record.route}: dateModified neverificat a fost expus în HTML`);
    assert.equal(body.attr("data-official-source-updated-at"), undefined, `${record.route}: officialSourceUpdatedAt neverificat a fost expus în HTML`);
    assert.equal(body.attr("data-last-meaningful-update"), undefined, `${record.route}: o actualizare neverificată a fost expusă în HTML`);
    assert(!section.text().includes(HUMAN_REVIEW), `${record.route}: tokenul intern a fost afișat utilizatorului`);
    assert(!section.text().includes("Verificat la"), `${record.route}: pagina incompletă pretinde o verificare publică`);
    for (const node of eligible) {
      assert.equal(node.dateModified, undefined, `${record.route}: dateModified neverificat a rămas în JSON-LD`);
      assert.equal(node.datePublished, undefined, `${record.route}: datePublished neverificat a rămas în JSON-LD`);
      assert.equal(node.author, undefined, `${record.route}: autor neverificat a rămas în JSON-LD`);
      assert.equal(node.reviewedBy, undefined, `${record.route}: reviewer neverificat a rămas în JSON-LD`);
    }
  }

  if (record.attributionType === "person" && record.governanceState === "public") {
    assert.equal(record.personalNameConsent, true, `${record.route}: nume personal publicat fără acord`);
  }
  if (isIsoDate(record.verifiedAt) && isIsoDate(record.nextReviewAt)) {
    const maximum = programById.get(record.programId)?.status === "apel_deschis"
      ? config.policy.openCallReviewDays
      : record.contentType === "program"
        ? config.policy.programReviewDays
        : config.policy.evergreenReviewDays;
    assert(daysBetween(record.verifiedAt, record.nextReviewAt) <= maximum, `${record.route}: termenul de reverificare depășește ${maximum} zile`);
  }
}

const openPrograms = programs.filter((program) => program.status === "apel_deschis");
assert(openPrograms.length, "Fixture: trebuie să existe cel puțin un apel deschis pentru politica de prospețime");
for (const program of openPrograms) {
  const record = recordByRoute.get(program.pageUrl);
  assert(record && isCompleteRecord(record), `${program.slug}: apelul deschis nu are guvernanță publicabilă`);
  assert(isIsoDate(record.verifiedAt), `${program.slug}: verifiedAt invalid pentru apelul deschis`);
  assert(isIsoDate(record.nextReviewAt), `${program.slug}: nextReviewAt invalid pentru apelul deschis`);
  assert(daysBetween(record.verifiedAt, record.nextReviewAt) <= config.policy.openCallReviewDays, `${program.slug}: politica de reverificare depășește ${config.policy.openCallReviewDays} zile`);
  assert(!reviewExpired(record, TODAY), `${program.slug}: apelul deschis are verificarea expirată`);
}

const complete = records.find(isCompleteRecord);
assert(complete, "Fixture: registrul trebuie să conțină cel puțin o pagină publică completă");

const missingSourceConfig = structuredClone(config);
const missingSource = missingSourceConfig.records.find((record) => record.id === complete.id);
missingSource.officialSourceUrl = HUMAN_REVIEW;
assert(
  validateGovernance(missingSourceConfig, programs, TODAY).some((error) => /sursă|publică necesită/iu.test(error)),
  "Validarea trebuie să respingă o pagină publică fără sursă oficială"
);

const personalNameConfig = structuredClone(config);
const personalName = personalNameConfig.records.find((record) => record.id === complete.id);
personalName.attributionType = "person";
personalName.personalNameConsent = false;
assert(
  validateGovernance(personalNameConfig, programs, TODAY).some((error) => /nume personal|personalNameConsent/iu.test(error)),
  "Validarea trebuie să respingă un nume personal fără acord"
);

const publicationOrderConfig = structuredClone(config);
const publicationOrderRecord = publicationOrderConfig.records.find((record) => isCompleteRecord(record));
publicationOrderRecord.datePublished = "2099-01-01";
assert(
  validateGovernance(publicationOrderConfig, programs, TODAY).some((error) => /datePublished nu poate fi după dateModified/iu.test(error)),
  "Validarea trebuie să separe data publicării de modificarea editorială"
);

const sourceDateConfig = structuredClone(config);
const sourceDateRecord = sourceDateConfig.records.find((record) => isCompleteRecord(record) && !record.programId);
assert(sourceDateRecord, "Fixture: este necesară o pagină publică fără program pentru testul sursei");
sourceDateRecord.officialSourceUpdatedAt = "2099-01-01";
assert(
  validateGovernance(sourceDateConfig, programs, TODAY).some((error) => /officialSourceUpdatedAt nu poate fi după verifiedAt/iu.test(error)),
  "Validarea trebuie să separe actualizarea sursei de reverificare"
);

const expiredConfig = structuredClone(config);
const expired = expiredConfig.records.find((record) => record.programId);
assert(expired, "Fixture: trebuie să existe cel puțin o pagină de program guvernată");
expired.nextReviewAt = "2026-08-17";
assert(reviewExpired(expired, TODAY), "Fixture: revizuirea simulată trebuie să fie expirată");
const changedPrograms = structuredClone(programs);
const changedProgram = changedPrograms.find((program) => program.id === expired.programId);
changedProgram.status = changedProgram.status === "apel_inchis" ? "calendar_estimativ" : "apel_inchis";
assert(
  validateGovernance(expiredConfig, changedPrograms, TODAY).some((error) => /reînnoită înaintea schimbării|revizuirea trebuie/iu.test(error)),
  "Schimbarea statusului după expirare trebuie blocată până la reverificare"
);

const staleOpenConfig = structuredClone(config);
const openProgram = programs.find((program) => program.status === "apel_deschis");
const staleOpen = staleOpenConfig.records.find((record) => record.programId === openProgram.id);
const yesterday = new Date(`${TODAY}T00:00:00Z`);
yesterday.setUTCDate(yesterday.getUTCDate() - 1);
staleOpen.nextReviewAt = yesterday.toISOString().slice(0, 10);
assert(
  validateGovernance(staleOpenConfig, programs, TODAY).some((error) => /apel deschis nu poate rămâne public/iu.test(error)),
  "Un apel deschis nu poate depăși termenul intern de reverificare"
);

const sampleFile = filesForRoute(complete.route).find((file) => fs.existsSync(file));
const sampleUrl = `https://atelierdeconsultanta.ro${complete.route}`;
const sampleSource = fs.readFileSync(sampleFile, "utf8");
const firstEditorialBuild = syncPageHtml(sampleSource, complete);
const secondEditorialBuild = syncPageHtml(firstEditorialBuild, complete);
assert.equal(secondEditorialBuild, firstEditorialBuild, "Un build repetat nu trebuie să modifice metadatele editoriale");
for (const node of schemaNodes(cheerio.load(secondEditorialBuild, { decodeEntities: false })).filter(eligibleNode)) {
  assert.equal(node.dateModified, complete.lastMeaningfulUpdate, "Timestamp-ul buildului nu poate deveni dateModified");
}
assert.equal(
  lastmodForFile(sampleFile, sampleUrl, new Map([[sampleUrl, "2020-01-02"]]), new Map()),
  null,
  "O modificare de fișier/build nu trebuie să schimbe lastmod păstrat"
);
assert.equal(
  lastmodForFile(sampleFile, sampleUrl, new Map([[sampleUrl, "2020-01-02"]]), new Map([[sampleUrl, "2021-03-04"]])),
  "2021-03-04",
  "lastMeaningfulUpdate trebuie să aibă prioritate în sitemap"
);

generate();
const sitemapAfterFirstBuild = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
generate();
const sitemapAfterSecondBuild = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
assert.equal(sitemapAfterSecondBuild, sitemapAfterFirstBuild, "Un build global repetat nu trebuie să modifice lastmod");
const generatedLastmods = sitemapLastmods(ROOT);
for (const record of records.filter((item) => isCompleteRecord(item)
  && !programById.get(item.programId)?.discovery?.redirectTarget)) {
  assert.equal(
    generatedLastmods.get(`https://atelierdeconsultanta.ro${record.route}`),
    record.lastMeaningfulUpdate,
    `${record.route}: sitemap lastmod nu provine din lastMeaningfulUpdate`
  );
}

const admin = fs.readFileSync(path.join(ROOT, "admin", "index.html"), "utf8");
for (const filter of ["missing_source", "expired_review", "missing_reviewer", "program_page_contradiction"]) {
  assert(admin.includes(`value="${filter}"`), `CMS: lipsește filtrul ${filter}`);
}
assert(admin.includes("Revizuire obligatorie înainte de schimbarea statusului"), "CMS: lipsește avertismentul pentru status expirat");
assert(fs.existsSync(path.join(ROOT, "reports", "editorial-governance-expiry.md")), "Lipsește raportul de expirare Markdown");
assert(fs.existsSync(path.join(ROOT, "reports", "editorial-governance-expiry.csv")), "Lipsește raportul de expirare CSV");
assert(fs.existsSync(path.join(ROOT, "docs", "procedura-guvernanta-editoriala.md")), "Lipsește procedura editorială");

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const browserErrors = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));
  await page.goto(`file:///${path.join(ROOT, "admin", "index.html").replace(/\\/gu, "/")}`);
  await page.evaluate(() => window.switchPanel("programe", document.querySelector("[data-panel='programe']")));
  assert.equal(await page.locator("#editorialGovernanceGrid article").count(), records.length, "CMS: dashboardul nu afișează toate paginile guvernate");
  await page.selectOption("#editorialGovernanceFilter", "expired_review");
  assert.equal(
    await page.locator("#editorialGovernanceGrid article").count(),
    records.filter((record) => reviewExpired(record, TODAY)).length,
    "CMS: filtrul de verificări expirate este incorect"
  );
  assert.deepEqual(browserErrors, [], `CMS: erori JavaScript în dashboard: ${browserErrors.join("; ")}`);
} finally {
  await browser.close();
}

console.log(`Contract editorial: ${records.length} pagini, ${records.filter(isCompleteRecord).length} publice și ${records.filter((record) => reviewExpired(record, TODAY)).length} revizuiri expirate verificate.`);
