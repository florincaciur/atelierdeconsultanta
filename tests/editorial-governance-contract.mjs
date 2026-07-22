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
const { filesForRoute } = require("../tools/sync-editorial-governance");
const {
  generate,
  lastmodForFile
} = require("../tools/generate-sitemap");
const { sitemapLastmods } = require("../tools/sitemap-utils");

const { config, programs, records } = loadEditorialGovernance();
const programById = new Map(programs.map((program) => [program.slug, program]));
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

  const eligible = schemaNodes($).filter(eligibleNode);
  if (isCompleteRecord(record)) {
    assert.equal(body.attr("data-editorial-verified-at"), record.verifiedAt, `${record.route}: verifiedAt diferă în HTML`);
    assert.equal(body.attr("data-next-review-at"), record.nextReviewAt, `${record.route}: nextReviewAt diferă în HTML`);
    assert.equal(body.attr("data-last-meaningful-update"), record.lastMeaningfulUpdate, `${record.route}: lastMeaningfulUpdate diferă în HTML`);
    assert(section.text().includes(`Verificat la ${record.verifiedAt}`), `${record.route}: lipsește data vizibilă de verificare`);
    assert(section.text().includes(record.reviewer), `${record.route}: lipsește reviewerul vizibil`);
    assert(section.text().includes(record.reviewerRole), `${record.route}: lipsește rolul reviewerului`);
    assert.equal(section.find("a[data-analytics-event='source_document_click']").attr("href"), record.officialSourceUrl, `${record.route}: sursa vizibilă diferă`);
    assert(section.find("details.editorial-governance__changelog").length, `${record.route}: lipsește linkul/istoricul «Vezi modificările»`);
    assert(eligible.length, `${record.route}: pagina publică nu are un nod JSON-LD editorial eligibil`);
    for (const node of eligible) {
      assert.equal(node.dateModified, record.lastMeaningfulUpdate, `${record.route}: dateModified nu provine din lastMeaningfulUpdate`);
      assert(Array.isArray(node.citation) && node.citation.some((citation) => citation.url === record.officialSourceUrl), `${record.route}: sursa oficială lipsește din JSON-LD`);
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
    assert.equal(body.attr("data-last-meaningful-update"), undefined, `${record.route}: o actualizare neverificată a fost expusă în HTML`);
    assert(!section.text().includes(HUMAN_REVIEW), `${record.route}: tokenul intern a fost afișat utilizatorului`);
    assert(!section.text().includes("Verificat la"), `${record.route}: pagina incompletă pretinde o verificare publică`);
    for (const node of eligible) {
      assert.equal(node.dateModified, undefined, `${record.route}: dateModified neverificat a rămas în JSON-LD`);
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

const expired = records.find((record) => record.programId && reviewExpired(record, TODAY));
assert(expired, "Fixture: raportul trebuie să conțină cel puțin o revizuire de program expirată");
const changedPrograms = structuredClone(programs);
const changedProgram = changedPrograms.find((program) => program.slug === expired.programId);
changedProgram.status = changedProgram.status === "apel_inchis" ? "calendar_estimativ" : "apel_inchis";
assert(
  validateGovernance(config, changedPrograms, TODAY).some((error) => /reînnoită înaintea schimbării|revizuirea trebuie/iu.test(error)),
  "Schimbarea statusului după expirare trebuie blocată până la reverificare"
);

const sampleFile = filesForRoute(complete.route).find((file) => fs.existsSync(file));
const sampleUrl = `https://atelierdeconsultanta.ro${complete.route}`;
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
for (const record of records.filter(isCompleteRecord)) {
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
